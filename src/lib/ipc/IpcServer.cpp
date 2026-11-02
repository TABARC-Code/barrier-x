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

#include "ipc/IpcServer.h"
#ifdef _WIN32
#include "ipc/WinPipeStream.h"
#endif

#include "ipc/Ipc.h"
#include "ipc/IpcClientProxy.h"
#include "ipc/IpcMessage.h"
#include "net/IDataSocket.h"
#include "io/IStream.h"
#include "base/IEventQueue.h"
#include "base/TMethodEventJob.h"
#include "base/Event.h"
#include "base/Log.h"

//
// IpcServer
//

IpcServer::IpcServer(IEventQueue* events, SocketMultiplexer* socketMultiplexer) :
    m_mock(false),
    m_events(events),
    m_socketMultiplexer(socketMultiplexer),
    m_socket(nullptr),
    m_address(NetworkAddress(IPC_HOST, IPC_PORT))
{
#ifdef _WIN32
    pipe_ = std::make_shared<WinPipeListener>(m_events, true);
#endif
    init();
}

#ifdef _WIN32
IpcServer::IpcServer(IEventQueue* events, SocketMultiplexer* multiplexer, bool service) :
    m_mock(false), m_events(events), m_socketMultiplexer(multiplexer), m_socket(nullptr),
    m_address(NetworkAddress(IPC_HOST, IPC_PORT)),
    pipe_(std::make_shared<WinPipeListener>(events, service))
{
    init();
}
void IpcServer::childProcess(void* handle) { if (pipe_) { pipe_->child(handle); } }
#endif

IpcServer::IpcServer(IEventQueue* events, SocketMultiplexer* socketMultiplexer, int port) :
    m_mock(false),
    m_events(events),
    m_socketMultiplexer(socketMultiplexer),
    m_socket(nullptr),
    m_address(NetworkAddress(IPC_HOST, port))
{
    init();
}

void
IpcServer::init()
{
#ifdef _WIN32
    if (pipe_) {
        m_events->adoptHandler(m_events->forIListenSocket().connecting(), pipe_.get(),
            new TMethodEventJob<IpcServer>(this, &IpcServer::handleClientConnecting));
        return;
    }
#endif
    // I retain TCP for the explicit-port harness; the Windows service uses a pipe.
    m_socket = new TCPListenSocket(m_events, m_socketMultiplexer, IArchNetwork::kINET);

    m_address.resolve();

    m_events->adoptHandler(
        m_events->forIListenSocket().connecting(), m_socket,
        new TMethodEventJob<IpcServer>(
        this, &IpcServer::handleClientConnecting));
}

IpcServer::~IpcServer()
{
    if (m_mock) {
        return;
    }

#ifdef _WIN32
    if (pipe_) {
        m_events->removeHandler(m_events->forIListenSocket().connecting(), pipe_.get());
        pipe_.reset();
    }
#endif
    if (m_socket != nullptr) { delete m_socket; }

    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        ClientList::iterator it;
        for (it = m_clients.begin(); it != m_clients.end(); it++) {
            deleteClient(*it);
        }
        m_clients.clear();
    }

    m_events->removeHandler(m_events->forIListenSocket().connecting(), m_socket);
}

void
IpcServer::listen()
{
#ifdef _WIN32
    if (pipe_) { pipe_->listen(); return; }
#endif
    m_socket->bind(m_address);
}

void
IpcServer::handleClientConnecting(const Event&, void*)
{
    barrier::IStream* stream = nullptr;
#ifdef _WIN32
    if (pipe_) { stream = pipe_->accept().release(); }
    else
#endif
    { stream = m_socket->accept(); }
    if (stream == NULL) {
        return;
    }

    LOG((CLOG_DEBUG "accepted ipc client connection"));

    IpcClientProxy* proxy = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
#ifdef _WIN32
        if (pipe_) {
            auto* native = static_cast<WinPipeStream*>(stream);
            proxy = new IpcClientProxy(*stream, m_events,
                [native](unsigned char type) { return native->authorisation(type); });
        }
        else
#endif
        { proxy = new IpcClientProxy(*stream, m_events); }
        m_clients.push_back(proxy);
    }

    m_events->adoptHandler(
        m_events->forIpcClientProxy().disconnected(), proxy,
        new TMethodEventJob<IpcServer>(
        this, &IpcServer::handleClientDisconnected));

    m_events->adoptHandler(
        m_events->forIpcClientProxy().messageReceived(), proxy,
        new TMethodEventJob<IpcServer>(
        this, &IpcServer::handleMessageReceived));

#ifdef _WIN32
    if (pipe_) { static_cast<WinPipeStream*>(stream)->start(); }
#endif
    m_events->addEvent(Event(
        m_events->forIpcServer().clientConnected(), this, proxy, Event::kDontFreeData));
}

void
IpcServer::handleClientDisconnected(const Event& e, void*)
{
    IpcClientProxy* proxy = static_cast<IpcClientProxy*>(e.getTarget());

    std::lock_guard<std::mutex> lock(m_clientsMutex);
    m_clients.remove(proxy);
    deleteClient(proxy);

    LOG((CLOG_DEBUG "ipc client proxy removed, connected=%d", m_clients.size()));
}

void
IpcServer::handleMessageReceived(const Event& e, void*)
{
    Event event(m_events->forIpcServer().messageReceived(), this);
    event.setDataObject(e.getDataObject());
    m_events->addEvent(event);
}

void
IpcServer::deleteClient(IpcClientProxy* proxy)
{
    m_events->removeHandler(m_events->forIpcClientProxy().messageReceived(), proxy);
    m_events->removeHandler(m_events->forIpcClientProxy().disconnected(), proxy);
    delete proxy;
}

bool
IpcServer::hasClients(EIpcClientType clientType) const
{
    std::lock_guard<std::mutex> lock(m_clientsMutex);

    if (m_clients.empty()) {
        return false;
    }

    ClientList::const_iterator it;
    for (it = m_clients.begin(); it != m_clients.end(); it++) {
        // at least one client is alive and type matches, there are clients.
        IpcClientProxy* p = *it;
        if (!p->m_disconnecting.load() && p->m_clientType.load() == clientType) {
            return true;
        }
    }

    // all clients must be disconnecting, no active clients.
    return false;
}

void
IpcServer::send(const IpcMessage& message, EIpcClientType filterType)
{
    std::lock_guard<std::mutex> lock(m_clientsMutex);

    ClientList::iterator it;
    for (it = m_clients.begin(); it != m_clients.end(); it++) {
        IpcClientProxy* proxy = *it;
        if (proxy->m_clientType.load() == filterType) {
            proxy->send(message);
        }
    }
}
