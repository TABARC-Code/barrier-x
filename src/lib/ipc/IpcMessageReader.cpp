/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE.
 */
#include "ipc/IpcMessageReader.h"
#include "io/IStream.h"
#include <algorithm>
#include <cstring>

constexpr std::size_t IpcMessageReader::command_limit;
constexpr std::size_t IpcMessageReader::log_limit;

std::unique_ptr<IpcMessage> IpcMessageReader::read(barrier::IStream& stream)
{
    if (failed_) {
        throw IpcProtocolError();
    }
    auto reject = [this] {
        failed_ = true;
        buffer_.clear();
        throw IpcProtocolError();
    };
    for (;;) {
        while (buffer_.size() < expected_) {
            unsigned char chunk[4096];
            auto wanted = static_cast<UInt32>(std::min(expected_ - buffer_.size(), sizeof(chunk)));
            UInt32 count = stream.read(chunk, wanted);
            if (count == 0) {
                return {};
            }
            if (count > wanted) {
                reject();
            }
            buffer_.insert(buffer_.end(), chunk, chunk + count);
        }

        bool hello = std::memcmp(buffer_.data(), "IHEL", 4) == 0;
        bool command = std::memcmp(buffer_.data(), "ICMD", 4) == 0;
        bool log = std::memcmp(buffer_.data(), "ILOG", 4) == 0;
        bool shutdown = std::memcmp(buffer_.data(), "ISDN", 4) == 0;
        if (direction_ == Direction::FromClient ? !(hello || command) : !(log || shutdown)) {
            reject();
        }
        if (expected_ == 4 && !shutdown) {
            expected_ = hello ? 5 : 8;
            continue;
        }
        if (expected_ == 8) {
            UInt32 length = (UInt32(buffer_[4]) << 24) | (UInt32(buffer_[5]) << 16) |
                            (UInt32(buffer_[6]) << 8) | UInt32(buffer_[7]);
            // Check before reserving storage or adding framing bytes. A length
            // field is a request from the peer, not an allocation instruction.
            if (length > (command ? command_limit : log_limit)) {
                reject();
            }
            expected_ = 8 + std::size_t(length) + (command ? 1 : 0);
            if (buffer_.size() < expected_) {
                continue;
            }
        }

        std::unique_ptr<IpcMessage> message;
        if (hello) {
            if (buffer_[4] != kIpcClientGui && buffer_[4] != kIpcClientNode) {
                reject();
            }
            message = std::make_unique<IpcHelloMessage>(static_cast<EIpcClientType>(buffer_[4]));
        }
        else if (command) {
            std::string text(buffer_.begin() + 8, buffer_.end() - 1);
            if (buffer_.back() > 1 || text.find('\0') != std::string::npos) {
                reject();
            }
            message = std::make_unique<IpcCommandMessage>(text, buffer_.back() != 0);
        }
        else if (log) {
            message = std::make_unique<IpcLogLineMessage>(
                        std::string(buffer_.begin() + 8, buffer_.end()));
        }
        else {
            message = std::make_unique<IpcShutdownMessage>();
        }
        buffer_.clear();
        expected_ = 4;
        return message;
    }
}
