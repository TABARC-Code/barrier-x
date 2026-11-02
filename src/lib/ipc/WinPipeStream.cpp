/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "WinPipeStream.h"
#ifdef _WIN32
#include "ipc/Ipc.h"
#include "base/IEventQueue.h"
#include "base/Log.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
using namespace barrier::localipc;

WinPipeStream::WinPipeStream(Handle pipe, IEventQueue* events,
                            std::shared_ptr<Peer> peer, std::string input) :
    pipe_(std::move(pipe)), stop_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
    events_(events), peer_(std::move(peer)), input_(std::move(input))
{
    if (!pipe_ || !stop_) { throw std::runtime_error("local service stream failed"); }
}
WinPipeStream::~WinPipeStream() { close(); }
void WinPipeStream::start()
{
    reader_ = std::thread([this] { inputLoop(); });
    try { writer_ = std::thread([this] { outputLoop(); }); }
    catch (...) { close(); throw; }
    if (getSize()) { events_->addEvent(Event(events_->forIStream().inputReady(), this)); }
}
std::function<bool()> WinPipeStream::authorisation(unsigned char type) const
{
    auto peer = peer_;
    const auto operation = type == kIpcCommand ? Operation::Command :
                           type == kIpcLogLine ? Operation::Log :
                           type == kIpcShutdown ? Operation::Shutdown : Operation::Hello;
    return [peer, operation] { return peer && peer->allows(operation); };
}
void WinPipeStream::close()
{
    closed_.store(true);
    if (peer_) { peer_->connected.store(false); }
    SetEvent(stop_.get());
    changed_.notify_all();
    if (reader_.joinable()) { reader_.join(); }
    if (writer_.joinable()) { writer_.join(); }
}
void WinPipeStream::fail(Event::Type type)
{
    if (!closed_.exchange(true)) {
        if (peer_) { peer_->connected.store(false); }
        SetEvent(stop_.get());
        changed_.notify_all();
        events_->addEvent(Event(type, this));
    }
}
UInt32 WinPipeStream::getSize() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<UInt32>(input_.size());
}
UInt32 WinPipeStream::read(void* buffer, UInt32 size)
{
    std::lock_guard<std::mutex> lock(mutex_);
    const auto count = std::min<std::size_t>(size, input_.size());
    if (buffer) { std::memcpy(buffer, input_.data(), count); }
    input_.erase(0, count);
    changed_.notify_all();
    return static_cast<UInt32>(count);
}
void WinPipeStream::write(const void* buffer, UInt32 size)
{
    if (!size) { return; }
    bool rejected = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_.load()) { return; }
        rejected = size > limit - queued_;
        if (!rejected) {
            const auto* bytes = static_cast<const char*>(buffer);
            output_.emplace_back(bytes, bytes + size);
            queued_ += size;
            changed_.notify_all();
        }
    }
    if (rejected) { fail(events_->forIStream().outputError()); }
}
void WinPipeStream::flush()
{
    std::unique_lock<std::mutex> lock(mutex_);
    changed_.wait(lock, [this] { return closed_.load() || queued_ == 0; });
}
void WinPipeStream::inputLoop()
{
    try {
        while (!closed_.load()) {
            char bytes[4096];
            DWORD wanted;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                changed_.wait(lock, [this] { return closed_.load() || input_.size() < limit; });
                if (closed_.load()) { return; }
                wanted = static_cast<DWORD>(std::min<std::size_t>(sizeof(bytes), limit - input_.size()));
            }
            auto count = transfer(pipe_.get(), bytes, wanted, false, stop_.get(), INFINITE);
            if (!count) { break; }
            bool notify;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                notify = input_.empty();
                input_.append(bytes, count);
            }
            if (notify) { events_->addEvent(Event(events_->forIStream().inputReady(), this)); }
        }
    }
    catch (...) { }
    fail(events_->forIStream().inputShutdown());
}
void WinPipeStream::outputLoop()
{
    try {
        while (!closed_.load()) {
            std::vector<char> bytes;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                changed_.wait(lock, [this] { return closed_.load() || !output_.empty(); });
                if (closed_.load()) { return; }
                bytes = std::move(output_.front());
                output_.pop_front();
            }
            DWORD offset = 0;
            while (offset < bytes.size()) {
                auto count = transfer(pipe_.get(), bytes.data() + offset,
                                      DWORD(bytes.size()) - offset, true, stop_.get());
                if (!count) { throw std::runtime_error("local service write failed"); }
                offset += count;
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                queued_ -= bytes.size();
            }
            changed_.notify_all();
        }
    }
    catch (...) { fail(events_->forIStream().outputError()); }
}
WinPipeListener::WinPipeListener(IEventQueue* events, bool service) :
    events_(events), policy_(std::make_shared<Policy>(service)),
    stop_(CreateEventW(nullptr, TRUE, FALSE, nullptr))
{
    if (!stop_) { throw std::runtime_error("local service listener failed"); }
}
WinPipeListener::~WinPipeListener()
{
    SetEvent(stop_.get());
    if (thread_.joinable()) { thread_.join(); }
}
void WinPipeListener::listen()
{
    listener_ = std::make_unique<Listener>(service_pipe, policy_);
    thread_ = std::thread([this] {
        while (WaitForSingleObject(stop_.get(), 0) == WAIT_TIMEOUT) {
            try {
                auto accepted = listener_->accept(stop_.get());
                if (!accepted.pipe) { return; }
                auto stream = std::make_unique<WinPipeStream>(std::move(accepted.pipe), events_,
                    std::move(accepted.peer), std::string(accepted.greeting.data(), accepted.greeting.size()));
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (pending_.size() >= 16) { continue; }
                    pending_.push_back(std::move(stream));
                }
                events_->addEvent(Event(events_->forIListenSocket().connecting(), this));
            }
            catch (...) {
                // I omit credentials and payloads from a rejected connection.
                LOG((CLOG_WARN "local service connection rejected"));
            }
        }
    });
}
std::unique_ptr<WinPipeStream> WinPipeListener::accept()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (pending_.empty()) { return {}; }
    auto result = std::move(pending_.front());
    pending_.pop_front();
    return result;
}
#endif
