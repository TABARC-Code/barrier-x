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

#include "IpcReader.h"
#include "Ipc.h"

#include <QTcpSocket>
#include <QPointer>
#include <QTimer>
#include <QtEndian>
#include <cstring>

constexpr int IpcReader::maximumLogBytes;

IpcReader::IpcReader(QTcpSocket* socket) :
    QObject(socket), m_Socket(socket)
{
    // Bound Qt's pending input as well as our frame. Backpressure beats an
    // enthusiastic allocation on behalf of an untrusted length field.
    m_Socket->setReadBufferSize(maximumLogBytes + 8);
    connect(m_Socket, &QTcpSocket::connected, this, &IpcReader::connectionOpened);
    connect(m_Socket, &QTcpSocket::disconnected, this, &IpcReader::connectionClosed);
}

void IpcReader::start()
{
    if (m_Started) { return; }
    m_Started = true;
    connect(m_Socket, &QTcpSocket::readyRead, this, &IpcReader::read, Qt::UniqueConnection);
    read();
}

void IpcReader::stop()
{
    m_Started = false;
    disconnect(m_Socket, &QTcpSocket::readyRead, this, &IpcReader::read);
    resetFrame();
}

void IpcReader::resetFrame()
{
    m_Buffer.clear();
    m_ExpectedBytes = 4;
}

void IpcReader::connectionOpened()
{
    resetFrame();
    m_Failed = false;
}

void IpcReader::connectionClosed()
{
    const bool incomplete = m_Started && !m_Failed && !m_Buffer.isEmpty();
    resetFrame();
    if (incomplete) {
        m_Failed = true;
        emit protocolError(tr("Incomplete service message."));
    }
}

void IpcReader::rejectFrame()
{
    m_Failed = true;
    resetFrame();
    QPointer<IpcReader> alive(this);
    m_Socket->abort();
    if (alive) {
        // Report the category, never the received command or log contents.
        emit protocolError(tr("Invalid service message."));
    }
}

void IpcReader::read()
{
    if (!m_Started || m_Failed || m_Reading) { return; }
    m_Reading = true;
    QPointer<IpcReader> alive(this);
    readAvailable();
    if (alive) { m_Reading = false; }
}

void IpcReader::readAvailable()
{
    int delivered = 0;
    while (m_Started && !m_Failed && m_Socket->bytesAvailable() > 0) {
        if (m_Buffer.size() < m_ExpectedBytes) {
            const auto chunk = m_Socket->read(qMin(m_ExpectedBytes - m_Buffer.size(), 4096));
            if (chunk.isEmpty()) { return; }
            m_Buffer.append(chunk);
            if (m_Buffer.size() < m_ExpectedBytes) { continue; }
        }
        if (m_ExpectedBytes == 4) {
            if (std::memcmp(m_Buffer.constData(), kIpcMsgLogLine, 4) != 0) {
                rejectFrame();
                return;
            }
            m_ExpectedBytes = 8;
            continue;
        }
        if (m_ExpectedBytes == 8) {
            const quint32 length = qFromBigEndian<quint32>(
                        reinterpret_cast<const uchar*>(m_Buffer.constData() + 4));
            if (length > quint32(maximumLogBytes)) {
                rejectFrame();
                return;
            }
            m_ExpectedBytes = 8 + int(length);
            if (m_Buffer.size() < m_ExpectedBytes) { continue; }
        }
        const QString line = QString::fromUtf8(m_Buffer.constData() + 8, m_ExpectedBytes - 8);
        resetFrame();
        QPointer<IpcReader> alive(this);
        emit readLogLine(line);
        if (!alive || !m_Started || m_Failed) { return; }
        // A burst of valid logs must still leave time to use the interface.
        // FUTURE(BX-006): bound retained log-window history separately.
        if (++delivered == 64 && m_Socket->bytesAvailable() > 0) {
            QTimer::singleShot(0, this, SLOT(read()));
            return;
        }
    }
}
