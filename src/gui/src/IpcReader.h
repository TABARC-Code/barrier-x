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

#include <QObject>
#include <QByteArray>
#include <QIODevice>
#include <functional>

class QTcpSocket;
class QLocalSocket;

class IpcReader : public QObject
{
    Q_OBJECT

public:
    explicit IpcReader(QTcpSocket* socket);
    explicit IpcReader(QLocalSocket* socket);
    void start();
    void stop();
    static constexpr int maximumLogBytes = 1024 * 1024;

signals:
    void readLogLine(const QString& text);
    void protocolError(const QString& text);

private slots:
    void read();
    void connectionOpened();
    void connectionClosed();

private:
    void readAvailable();
    void resetFrame();
    void rejectFrame();

    void initialise();
    QIODevice* m_Socket;
    std::function<void()> m_Abort;
    QByteArray m_Buffer;
    int m_ExpectedBytes = 4;
    bool m_Started = false;
    bool m_Failed = false;
    bool m_Reading = false;
};
