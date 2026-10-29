/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE.
 */
#pragma once

#include "ipc/IpcMessage.h"
#include <memory>
#include <stdexcept>
#include <vector>

namespace barrier { class IStream; }

class IpcProtocolError : public std::runtime_error {
public:
    IpcProtocolError() : std::runtime_error("invalid IPC frame") { }
};

class IpcMessageReader {
public:
    enum class Direction { FromClient, FromServer };
    explicit IpcMessageReader(Direction direction) : direction_(direction) { }

    // An empty result means more bytes are needed, not a malformed message.
    // The caller closes the connection on IpcProtocolError; no resynchronisation.
    std::unique_ptr<IpcMessage> read(barrier::IStream& stream);

    static constexpr std::size_t command_limit = 64 * 1024;
    static constexpr std::size_t log_limit = 1024 * 1024;

private:
    Direction direction_;
    std::vector<unsigned char> buffer_;
    std::size_t expected_ = 4;
    bool failed_ = false;
};
