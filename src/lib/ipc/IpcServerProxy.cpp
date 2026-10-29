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

#include "ipc/IpcServerProxy.h"

#include "ipc/IpcMessage.h"
#include "ipc/Ipc.h"
#include "barrier/ProtocolUtil.h"
#include "io/IStream.h"
#include "base/TMethodEventJob.h"
#include "base/Log.h"

//
// IpcServerProxy
//

IpcServerProxy::IpcServerProxy(barrier::IStream& stream, IEventQueue* events) :
    m_stream(stream),
    m_events(events)
{
    m_events->adoptHandler(m_events->forIStream().inputReady(),
        stream.getEventTarget(),
        new TMethodEventJob<IpcServerProxy>(
        this, &IpcServerProxy::handleData));
}

IpcServerProxy::~IpcServerProxy()
{
    m_events->removeHandler(m_events->forIStream().inputReady(),
        m_stream.getEventTarget());
}

void
IpcServerProxy::handleData(const Event&, void*)
{
    if (m_disconnecting) {
        return;
    }
    try {
        while (auto message = reader_.read(m_stream)) {
            Event event(m_events->forIpcServerProxy().messageReceived(), this,
                        nullptr, Event::kDontFreeData);
            event.setDataObject(message.get());
            m_events->addEvent(event);
            message.release();
        }
    }
    catch (const IpcProtocolError&) {
        // No payload in diagnostics: commands and log lines can contain secrets.
        LOG((CLOG_ERR "invalid ipc frame"));
        disconnect();
    }
}

void
IpcServerProxy::send(const IpcMessage& message)
{
    LOG((CLOG_DEBUG4 "ipc write: %d", message.type()));

    switch (message.type()) {
    case kIpcHello: {
        const IpcHelloMessage& hm = static_cast<const IpcHelloMessage&>(message);
        ProtocolUtil::writef(&m_stream, kIpcMsgHello, hm.clientType());
        break;
    }

    case kIpcCommand: {
        const IpcCommandMessage& cm = static_cast<const IpcCommandMessage&>(message);
        std::string command = cm.command();
        ProtocolUtil::writef(&m_stream, kIpcMsgCommand, &command, cm.elevate() ? 1 : 0);
        break;
    }

    default:
        LOG((CLOG_ERR "ipc message not supported: %d", message.type()));
        break;
    }
}

void
IpcServerProxy::disconnect()
{
    if (m_disconnecting) {
        return;
    }
    LOG((CLOG_DEBUG "ipc disconnect, closing stream"));
    m_disconnecting = true;
    m_stream.close();
}
