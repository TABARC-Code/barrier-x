/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#pragma once
#ifdef _WIN32
#include "ipc/WinLocalPipe.h"
#include "io/IStream.h"
#include <condition_variable>
#include <deque>
#include <thread>
#include <vector>

class WinPipeStream : public barrier::IStream {
public:
    WinPipeStream(barrier::localipc::Handle pipe, IEventQueue* events,
                  std::shared_ptr<barrier::localipc::Peer> peer = {}, std::string input = {});
    ~WinPipeStream() override;
    void start();
    std::function<bool()> authorisation(unsigned char type) const;
    void close() override;
    UInt32 read(void*, UInt32) override;
    void write(const void*, UInt32) override;
    void flush() override;
    void shutdownInput() override { close(); }
    void shutdownOutput() override { close(); }
    void* getEventTarget() const override { return const_cast<WinPipeStream*>(this); }
    bool isReady() const override { return getSize() != 0; }
    UInt32 getSize() const override;
private:
    void inputLoop();
    void outputLoop();
    void fail(Event::Type type);
    barrier::localipc::Handle pipe_, stop_;
    IEventQueue* events_;
    std::shared_ptr<barrier::localipc::Peer> peer_;
    std::atomic<bool> closed_{false};
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::string input_;
    std::deque<std::vector<char>> output_;
    std::size_t queued_ = 0;
    std::thread reader_, writer_;
    static constexpr std::size_t limit = 1024 * 1024 + 8;
};

class WinPipeListener {
public:
    WinPipeListener(IEventQueue* events, bool service);
    ~WinPipeListener();
    void listen();
    std::unique_ptr<WinPipeStream> accept();
    void child(HANDLE process) { policy_->child(process); }
private:
    IEventQueue* events_;
    std::shared_ptr<barrier::localipc::Policy> policy_;
    barrier::localipc::Handle stop_;
    std::unique_ptr<barrier::localipc::Listener> listener_;
    std::thread thread_;
    std::mutex mutex_;
    std::deque<std::unique_ptr<WinPipeStream>> pending_;
};
#endif
