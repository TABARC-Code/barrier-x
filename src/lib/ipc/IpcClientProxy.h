/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2012 Nick Bolton
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "ipc/IpcMessageReader.h"

#include "ipc/Ipc.h"
#include "arch/IArchMultithread.h"
#include "base/EventTypes.h"
#include "base/Event.h"

#include <mutex>
#include <atomic>
#include <functional>

namespace barrier { class IStream; }
class IpcMessage;
class IpcCommandMessage;
class IpcHelloMessage;
class IEventQueue;

class IpcClientProxy {
    friend class IpcServer;

public:
    IpcClientProxy(barrier::IStream& stream, IEventQueue* events,
                   std::function<std::function<bool()>(unsigned char)> authoriser = {});
    virtual ~IpcClientProxy();

private:
    void                send(const IpcMessage& message);
    void                handleData(const Event&, void*);
    void                handleDisconnect(const Event&, void*);
    void                handleWriteError(const Event&, void*);
    void                disconnect();

private:
    barrier::IStream&    m_stream;
    std::atomic<EIpcClientType> m_clientType;
    std::atomic<bool> m_disconnecting;
    std::mutex m_readMutex;
    std::mutex m_writeMutex;
    IEventQueue*        m_events;
    std::function<std::function<bool()>(unsigned char)> authoriser_;
    IpcMessageReader reader_{IpcMessageReader::Direction::FromClient};
};
