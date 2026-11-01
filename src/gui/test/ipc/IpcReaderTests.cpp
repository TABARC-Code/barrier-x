/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE.
 */
#include "IpcReader.h"
#include "IpcClient.h"
#include <QtTest>
#include <QTcpServer>
#include <QTcpSocket>
#include <QtEndian>
#include <QSignalSpy>

class IpcReaderTests : public QObject {
    Q_OBJECT
private:
    QTcpServer server;
    QTcpSocket socket;
    QTcpSocket* peer = nullptr;
    IpcReader* reader = nullptr;

    static QByteArray header(quint32 size)
    {
        QByteArray bytes("ILOG", 4);
        bytes.resize(8);
        qToBigEndian<quint32>(size, reinterpret_cast<uchar*>(bytes.data() + 4));
        return bytes;
    }
    static QByteArray frame(const QByteArray& payload)
    { return header(quint32(payload.size())) + payload; }
    void send(const QByteArray& bytes)
    {
        QCOMPARE(peer->write(bytes), qint64(bytes.size()));
        peer->flush();
    }
private slots:
    void init()
    {
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));
        socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
        QTRY_VERIFY(server.hasPendingConnections());
        QTRY_COMPARE(socket.state(), QAbstractSocket::ConnectedState);
        peer = server.nextPendingConnection();
        QVERIFY(peer);
        reader = new IpcReader(&socket);
        reader->start();
    }
    void cleanup()
    {
        delete reader;
        reader = nullptr;
        socket.abort();
        delete peer;
        peer = nullptr;
        server.close();
    }
    void fragmentedMessageDoesNotBlockEvents()
    {
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        send("IL");
        bool tick = false;
        QTimer::singleShot(0, [&tick] { tick = true; });
        QTRY_VERIFY(tick);
        QCOMPARE(logs.count(), 0);
        send(frame("ready").mid(2));
        QTRY_COMPARE(logs.count(), 1);
        QCOMPARE(logs[0][0].toString(), QString("ready"));
    }
    void everySplit_data()
    {
        QTest::addColumn<int>("split");
        const auto bytes = frame(QByteArray("caf\xc3\xa9 \xc2\xa3"));
        for (int i = 0; i < bytes.size(); ++i) {
            QTest::newRow(qPrintable(QString::number(i))) << i;
        }
    }
    void everySplit()
    {
        QFETCH(int, split);
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        const QByteArray payload("caf\xc3\xa9 \xc2\xa3");
        const auto bytes = frame(payload);
        if (split) { send(bytes.left(split)); }
        QTest::qWait(1);
        QCOMPARE(logs.count(), 0);
        send(bytes.mid(split));
        QTRY_COMPARE(logs.count(), 1);
        QCOMPARE(logs[0][0].toString(), QString::fromUtf8(payload));
    }
    void coalescedAndEmptyLogs()
    {
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        send(frame("one") + frame("") + frame("three"));
        QTRY_COMPARE(logs.count(), 3);
        QCOMPARE(logs[0][0].toString(), QString("one"));
        QCOMPARE(logs[1][0].toString(), QString());
        QCOMPARE(logs[2][0].toString(), QString("three"));
    }
    void lengthBoundaries_data()
    {
        QTest::addColumn<quint32>("length");
        QTest::addColumn<bool>("accepted");
        QTest::newRow("empty") << quint32(0) << true;
        QTest::newRow("limit") << quint32(IpcReader::maximumLogBytes) << true;
        QTest::newRow("limit-plus-one") << quint32(IpcReader::maximumLogBytes + 1) << false;
        QTest::newRow("signed-max") << quint32(0x7fffffff) << false;
        QTest::newRow("high-bit") << quint32(0x80000000) << false;
        QTest::newRow("unsigned-max") << quint32(0xffffffff) << false;
    }
    void lengthBoundaries()
    {
        QFETCH(quint32, length);
        QFETCH(bool, accepted);
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        QSignalSpy errors(reader, &IpcReader::protocolError);
        send(header(length) + (accepted ? QByteArray(int(length), 'x') : QByteArray()));
        if (accepted) {
            QTRY_COMPARE(logs.count(), 1);
            QCOMPARE(logs[0][0].toString().size(), int(length));
            QCOMPARE(errors.count(), 0);
        }
        else {
            QTRY_COMPARE(errors.count(), 1);
            QTRY_COMPARE(socket.state(), QAbstractSocket::UnconnectedState);
            QCOMPARE(logs.count(), 0);
        }
    }
    void invalidHeaders_data()
    {
        QTest::addColumn<QByteArray>("code");
        for (const char* code : {"NOPE", "ICMD", "IHEL", "ISDN"}) {
            QTest::newRow(code) << QByteArray(code);
        }
    }
    void invalidHeaders()
    {
        QFETCH(QByteArray, code);
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        QSignalSpy errors(reader, &IpcReader::protocolError);
        send(code + frame("must not be delivered"));
        QTRY_COMPARE(errors.count(), 1);
        QTRY_COMPARE(socket.state(), QAbstractSocket::UnconnectedState);
        QCOMPARE(logs.count(), 0);
        QCOMPARE(errors[0][0].toString(), QString("Invalid service message."));
    }
    void truncatedMessageIsDiscarded()
    {
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        QSignalSpy errors(reader, &IpcReader::protocolError);
        send(frame("partial").left(10));
        peer->disconnectFromHost();
        QTRY_COMPARE(socket.state(), QAbstractSocket::UnconnectedState);
        QTRY_COMPARE(errors.count(), 1);
        QCOMPARE(logs.count(), 0);
    }
    void reconnectClearsPartialState()
    {
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        QSignalSpy errors(reader, &IpcReader::protocolError);
        send("ILO");
        peer->disconnectFromHost();
        QTRY_COMPARE(socket.state(), QAbstractSocket::UnconnectedState);
        QTRY_COMPARE(errors.count(), 1);
        delete peer;
        peer = nullptr;
        socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
        QTRY_VERIFY(server.hasPendingConnections());
        QTRY_COMPARE(socket.state(), QAbstractSocket::ConnectedState);
        peer = server.nextPendingConnection();
        send(frame("fresh connection"));
        QTRY_COMPARE(logs.count(), 1);
        QCOMPARE(logs[0][0].toString(), QString("fresh connection"));
        QCOMPARE(errors.count(), 1);
    }
    void startStopAndRepeatedStart()
    {
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        reader->stop();
        const auto bytes = frame("buffered");
        send(bytes);
        QTRY_COMPARE(socket.bytesAvailable(), qint64(bytes.size()));
        QCOMPARE(logs.count(), 0);
        reader->start();
        QTRY_COMPARE(logs.count(), 1);
        reader->start();
        send(frame("once"));
        QTRY_COMPARE(logs.count(), 2);
    }
    void burstYieldsAfterSixtyFourFrames()
    {
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        reader->stop();
        QByteArray bytes;
        for (int i = 0; i < 200; ++i) { bytes += frame(""); }
        send(bytes);
        QTRY_COMPARE(socket.bytesAvailable(), qint64(bytes.size()));
        reader->start();
        QCOMPARE(logs.count(), 64);
        QTRY_COMPARE(logs.count(), 200);
    }
    void signalHandlerCanStopReading()
    {
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        connect(reader, &IpcReader::readLogLine, this, [this] { reader->stop(); });
        send(frame("first") + frame("second"));
        QTRY_COMPARE(logs.count(), 1);
        QTest::qWait(10);
        QCOMPARE(logs.count(), 1);
        reader->start();
        QTRY_COMPARE(logs.count(), 2);
    }
    void signalHandlerCanDestroyReader()
    {
        connect(reader, &IpcReader::readLogLine, this, [this] {
            delete reader;
            reader = nullptr;
        });
        send(frame("first") + frame("second"));
        QTRY_VERIFY(reader == nullptr);
    }
    void signalHandlerCanReenterRead()
    {
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        connect(reader, &IpcReader::readLogLine, this, [this] {
            QVERIFY(QMetaObject::invokeMethod(reader, "read", Qt::DirectConnection));
        });
        send(frame("first") + frame("second"));
        QTRY_COMPARE(logs.count(), 2);
    }
    void invalidFrameStopsFollowingLogs()
    {
        QSignalSpy logs(reader, &IpcReader::readLogLine);
        QSignalSpy errors(reader, &IpcReader::protocolError);
        send(frame("first") + "NOPE" + frame("ignored"));
        QTRY_COMPARE(errors.count(), 1);
        QCOMPARE(logs.count(), 1);
        QCOMPARE(logs[0][0].toString(), QString("first"));
    }
    void clientRestartsAndRelaysProtocolErrors()
    {
        IpcClient client(server.serverPort());
        QSignalSpy logs(&client, &IpcClient::readLogLine);
        QSignalSpy errors(&client, &IpcClient::errorMessage);
        client.connectToHost();
        QTRY_VERIFY(server.hasPendingConnections());
        auto* servicePeer = server.nextPendingConnection();
        servicePeer->write(frame("first"));
        servicePeer->flush();
        QTRY_COMPARE(logs.count(), 1);
        client.disconnectFromHost();
        QTRY_COMPARE(servicePeer->state(), QAbstractSocket::UnconnectedState);
        delete servicePeer;
        client.retryConnect();
        QTest::qWait(10);
        QVERIFY(!server.hasPendingConnections());
        client.connectToHost();
        QTRY_VERIFY(server.hasPendingConnections());
        servicePeer = server.nextPendingConnection();
        servicePeer->write(frame("second"));
        servicePeer->flush();
        QTRY_COMPARE(logs.count(), 2);
        servicePeer->write("NOPE", 4);
        servicePeer->flush();
        QTRY_VERIFY(!errors.isEmpty());
        bool protocolReported = false;
        for (const auto& error : errors) {
            protocolReported |= error[0].toString() == "Invalid service message.";
        }
        QVERIFY(protocolReported);
        client.disconnectFromHost();
        delete servicePeer;
    }
};

QTEST_GUILESS_MAIN(IpcReaderTests)
#include "IpcReaderTests.moc"
