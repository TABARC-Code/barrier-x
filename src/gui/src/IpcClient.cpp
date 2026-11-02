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

#include "IpcClient.h"
#include <QTcpSocket>
#ifdef Q_OS_WIN
#include "../../lib/ipc/WinLocalPipe.h"
#endif
#include <QHostAddress>
#include <iostream>
#include <QTimer>
#include "IpcReader.h"
#include "Ipc.h"
#include <QDataStream>
#include <stdexcept>

IpcClient::IpcClient(quint16 port) :
m_Port(port),
m_Enabled(false)
{
#ifdef Q_OS_WIN
    if (port == IPC_PORT) {
        m_Local = new QLocalSocket(this);
        m_Socket = m_Local;
        connect(m_Local, SIGNAL(error(QLocalSocket::LocalSocketError)), this, SLOT(localError(QLocalSocket::LocalSocketError)));
        connect(m_Local, &QLocalSocket::disconnected, this, [this] { m_Verified = false; });
        m_Reader = new IpcReader(m_Local);
    }
    else
#endif
    {
        // I retain explicit TCP ports for the portable socket harness.
        m_Tcp = new QTcpSocket(this);
        m_Socket = m_Tcp;
        connect(m_Tcp, SIGNAL(connected()), this, SLOT(connected()));
        connect(m_Tcp, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(error(QAbstractSocket::SocketError)));
        m_Reader = new IpcReader(m_Tcp);
    }
    connect(m_Reader, &IpcReader::protocolError, this, &IpcClient::errorMessage);
    connect(m_Reader, SIGNAL(readLogLine(const QString&)), this, SLOT(handleReadLogLine(const QString&)));
}

IpcClient::~IpcClient()
{
}

void IpcClient::connected()
{
    sendHello();
    infoMessage("connection established");
}

void IpcClient::connectToHost()
{
    m_Enabled = true;

    infoMessage("connecting to service...");
#ifdef Q_OS_WIN
    if (m_Local) {
        m_Verified = false;
        m_Reader->stop();
        m_Local->abort();
        try {
            auto pipe = barrier::localipc::connectService();
            if (!m_Local->setSocketDescriptor(reinterpret_cast<qintptr>(pipe.get()))) {
                throw std::runtime_error("local service descriptor rejected");
            }
            pipe.release();
            m_Verified = true;
            m_Reader->start();
            connected();
        }
        catch (...) {
            emit errorMessage(tr("Service unavailable or service identity check failed."));
            QTimer::singleShot(1000, this, SLOT(retryConnect()));
        }
        return;
    }
#endif
    m_Reader->start();
    m_Tcp->connectToHost(QHostAddress(QHostAddress::LocalHost), m_Port);
}

void IpcClient::disconnectFromHost()
{
    m_Enabled = false;
    infoMessage("service disconnect");
    m_Reader->stop();
    m_Verified = false;
    m_Socket->close();
}

void IpcClient::error(QAbstractSocket::SocketError error)
{
    QString text;
    switch (error) {
        case 0: text = "connection refused"; break;
        case 1: text = "remote host closed"; break;
        default: text = QString("code=%1").arg(error); break;
    }

    errorMessage(QString("ipc connection error, %1").arg(text));

    QTimer::singleShot(1000, this, SLOT(retryConnect()));
}

void IpcClient::localError(QLocalSocket::LocalSocketError)
{
    m_Verified = false;
    emit errorMessage(tr("Local service connection lost or access refused."));
    QTimer::singleShot(1000, this, SLOT(retryConnect()));
}

void IpcClient::retryConnect()
{
    if (m_Enabled && !m_Socket->isOpen()) {
        connectToHost();
    }
}

void IpcClient::sendHello()
{
    QDataStream stream(m_Socket);
    stream.writeRawData(kIpcMsgHello, 4);

    char typeBuf[1];
    typeBuf[0] = kIpcClientGui;
    stream.writeRawData(typeBuf, 1);
}

void IpcClient::sendCommand(const QString& command, ElevateMode const elevate)
{
#ifdef Q_OS_WIN
    if (m_Local && (!m_Verified || !barrier::localipc::elevatedAdministrator())) {
        emit errorMessage(tr("Administrator approval is required to change the service command. Restart the interface as administrator."));
        return;
    }
#endif
    QDataStream stream(m_Socket);

    stream.writeRawData(kIpcMsgCommand, 4);

    std::string stdStringCommand = command.toStdString();
    const char* charCommand = stdStringCommand.c_str();
    int length = (int)strlen(charCommand);

    char lenBuf[4];
    intToBytes(length, lenBuf, 4);
    stream.writeRawData(lenBuf, 4);
    stream.writeRawData(charCommand, length);

    char elevateBuf[1];
    // Refer to enum ElevateMode documentation for why this flag is mapped this way
    elevateBuf[0] = (elevate == ElevateAlways) ? 1 : 0;
    stream.writeRawData(elevateBuf, 1);
}

void IpcClient::handleReadLogLine(const QString& text)
{
    readLogLine(text);
}

// TODO: qt must have a built in way of converting int to bytes.
void IpcClient::intToBytes(int value, char *buffer, int size)
{
    if (size == 1) {
        buffer[0] = value & 0xff;
    }
    else if (size == 2) {
        buffer[0] = (value >> 8) & 0xff;
        buffer[1] = value & 0xff;
    }
    else if (size == 4) {
        buffer[0] = (value >> 24) & 0xff;
        buffer[1] = (value >> 16) & 0xff;
        buffer[2] = (value >> 8) & 0xff;
        buffer[3] = value & 0xff;
    }
    else {
        // TODO: other sizes, if needed.
    }
}
