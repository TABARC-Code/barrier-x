/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE.
 */
#include "ipc/IpcMessageReader.h"
#include "ipc/IpcClientProxy.h"
#include "ipc/IpcServerProxy.h"
#include "base/EventQueue.h"
#include "io/IStream.h"
#include "test/global/gtest.h"
#include <algorithm>
#include <cstring>

namespace {
class BufferStream : public barrier::IStream {
public:
    std::string input, output;
    std::size_t offset = 0;
    bool closed = false;
    void close() override { closed = true; }
    UInt32 read(void* buffer, UInt32 size) override
    {
        auto count = std::min<std::size_t>(size, input.size() - offset);
        if (buffer) { std::memcpy(buffer, input.data() + offset, count); }
        offset += count;
        return static_cast<UInt32>(count);
    }
    void write(const void* data, UInt32 size) override
    { output.append(static_cast<const char*>(data), size); }
    void flush() override { }
    void shutdownInput() override { }
    void shutdownOutput() override { }
    void* getEventTarget() const override { return const_cast<BufferStream*>(this); }
    bool isReady() const override { return offset < input.size(); }
    UInt32 getSize() const override { return static_cast<UInt32>(input.size() - offset); }
};
std::string frame(const char* code, const std::string& payload, int flag = -1)
{
    std::string result(code, 4);
    auto size = static_cast<UInt32>(payload.size());
    for (int shift : {24, 16, 8, 0}) { result += char((size >> shift) & 255); }
    result += payload;
    if (flag >= 0) { result += char(flag); }
    return result;
}
class CapturedEvents : public EventQueue {
public:
    std::vector<std::unique_ptr<IpcMessage>> messages;
    int disconnects = 0;
    void addEvent(const Event& event) override
    {
        if (event.getDataObject()) {
            messages.emplace_back(static_cast<IpcMessage*>(event.getDataObject()));
        }
        else { ++disconnects; }
    }
};
}

TEST(IpcMessageReaderTests, CommandSurvivesEverySplit)
{
    auto bytes = frame("ICMD", "barrierc --name desktop", 1);
    for (std::size_t split = 0; split < bytes.size(); ++split) {
        IpcMessageReader reader(IpcMessageReader::Direction::FromClient);
        BufferStream stream;
        stream.input = bytes.substr(0, split);
        EXPECT_EQ(nullptr, reader.read(stream));
        stream.input += bytes.substr(split);
        auto message = reader.read(stream);
        ASSERT_NE(nullptr, message);
        auto& command = static_cast<IpcCommandMessage&>(*message);
        EXPECT_EQ("barrierc --name desktop", command.command());
        EXPECT_TRUE(command.elevate());
        EXPECT_EQ(nullptr, reader.read(stream));
    }
}

TEST(IpcMessageReaderTests, LogSurvivesEverySplit)
{
    auto bytes = frame("ILOG", "connection ready\n");
    for (std::size_t split = 0; split < bytes.size(); ++split) {
        IpcMessageReader reader(IpcMessageReader::Direction::FromServer);
        BufferStream stream;
        stream.input = bytes.substr(0, split);
        EXPECT_EQ(nullptr, reader.read(stream));
        stream.input += bytes.substr(split);
        auto message = reader.read(stream);
        ASSERT_NE(nullptr, message);
        EXPECT_EQ("connection ready\n", static_cast<IpcLogLineMessage&>(*message).logLine());
    }
}

TEST(IpcMessageReaderTests, HelloArrivesOneByteAtATime)
{
    IpcMessageReader reader(IpcMessageReader::Direction::FromClient);
    BufferStream stream;
    std::string hello("IHEL\x01", 5);
    for (std::size_t i = 0; i < 4; ++i) {
        stream.input += hello[i];
        EXPECT_EQ(nullptr, reader.read(stream));
    }
    stream.input += hello[4];
    auto message = reader.read(stream);
    ASSERT_NE(nullptr, message);
    EXPECT_EQ(kIpcClientGui, static_cast<IpcHelloMessage&>(*message).clientType());
}

TEST(IpcMessageReaderTests, ReadsCoalescedMessagesSeparately)
{
    IpcMessageReader reader(IpcMessageReader::Direction::FromServer);
    BufferStream stream;
    stream.input = frame("ILOG", "") + "ISDN" + frame("ILOG", "next");
    ASSERT_EQ(kIpcLogLine, reader.read(stream)->type());
    ASSERT_EQ(kIpcShutdown, reader.read(stream)->type());
    ASSERT_EQ(kIpcLogLine, reader.read(stream)->type());
    EXPECT_EQ(nullptr, reader.read(stream));
}

TEST(IpcMessageReaderTests, RejectsOversizedLengthsBeforeReadingPayload)
{
    for (bool command : {false, true}) {
        IpcMessageReader reader(command ? IpcMessageReader::Direction::FromClient :
                                         IpcMessageReader::Direction::FromServer);
        BufferStream stream;
        stream.input = std::string(command ? "ICMD" : "ILOG") + std::string(4, char(255));
        EXPECT_THROW(reader.read(stream), IpcProtocolError);
        EXPECT_EQ(8u, stream.offset);
        EXPECT_THROW(reader.read(stream), IpcProtocolError);
    }
}

TEST(IpcMessageReaderTests, EnforcesExactCommandAndLogLimits)
{
    for (bool command : {false, true}) {
        auto limit = command ? IpcMessageReader::command_limit : IpcMessageReader::log_limit;
        for (bool oversized : {false, true}) {
            IpcMessageReader reader(command ? IpcMessageReader::Direction::FromClient :
                                             IpcMessageReader::Direction::FromServer);
            BufferStream stream;
            stream.input = frame(command ? "ICMD" : "ILOG",
                                 std::string(limit + (oversized ? 1 : 0), 'x'), command ? 0 : -1);
            if (oversized) { EXPECT_THROW(reader.read(stream), IpcProtocolError); }
            else { EXPECT_NE(nullptr, reader.read(stream)); }
        }
    }
}

TEST(IpcMessageReaderTests, RejectsUnknownAndWrongDirectionCodes)
{
    for (bool client : {false, true}) {
        for (const char* code : {"NOPE", client ? "ILOG" : "ICMD"}) {
            IpcMessageReader reader(client ? IpcMessageReader::Direction::FromClient :
                                            IpcMessageReader::Direction::FromServer);
            BufferStream stream;
            stream.input = code;
            EXPECT_THROW(reader.read(stream), IpcProtocolError);
        }
    }
}

TEST(IpcMessageReaderTests, RejectsInvalidHelloAndElevation)
{
    for (const auto& bytes : {std::string("IHEL\xff", 5), frame("ICMD", "test", 2),
                              frame("ICMD", std::string("bad\0command", 11), 0)}) {
        IpcMessageReader reader(IpcMessageReader::Direction::FromClient);
        BufferStream stream;
        stream.input = bytes;
        EXPECT_THROW(reader.read(stream), IpcProtocolError);
    }
}

TEST(IpcMessageReaderTests, EmptyCommandAndFalseElevationArePreserved)
{
    IpcMessageReader reader(IpcMessageReader::Direction::FromClient);
    BufferStream stream;
    stream.input = frame("ICMD", "", 0);
    auto message = reader.read(stream);
    ASSERT_NE(nullptr, message);
    EXPECT_TRUE(static_cast<IpcCommandMessage&>(*message).command().empty());
    EXPECT_FALSE(static_cast<IpcCommandMessage&>(*message).elevate());
}

TEST(IpcProxyTests, ClientProxyWaitsForCompleteCommand)
{
    CapturedEvents events;
    auto* stream = new BufferStream;
    IpcClientProxy proxy(*stream, &events);
    auto bytes = frame("ICMD", "test", 0);
    stream->input = bytes.substr(0, 10);
    events.dispatchEvent(Event(events.forIStream().inputReady(), stream));
    EXPECT_TRUE(events.messages.empty());
    stream->input += bytes.substr(10);
    events.dispatchEvent(Event(events.forIStream().inputReady(), stream));
    ASSERT_EQ(1u, events.messages.size());
    EXPECT_EQ("test", static_cast<IpcCommandMessage&>(*events.messages[0]).command());
}

TEST(IpcProxyTests, ClientProxyStopsOnInvalidFrameWithoutNullMessage)
{
    CapturedEvents events;
    auto* stream = new BufferStream;
    IpcClientProxy proxy(*stream, &events);
    stream->input = "NOPE" + frame("ICMD", "ignored", 0);
    events.dispatchEvent(Event(events.forIStream().inputReady(), stream));
    EXPECT_TRUE(stream->closed);
    EXPECT_EQ(4u, stream->offset);
    EXPECT_EQ(1, events.disconnects);
    EXPECT_TRUE(events.messages.empty());
    events.dispatchEvent(Event(events.forIStream().inputReady(), stream));
    EXPECT_EQ(1, events.disconnects);
}

TEST(IpcProxyTests, ServerProxyWaitsAndStopsAfterInvalidFrame)
{
    CapturedEvents events;
    BufferStream stream;
    IpcServerProxy proxy(stream, &events);
    stream.input = "IL";
    events.dispatchEvent(Event(events.forIStream().inputReady(), &stream));
    EXPECT_TRUE(events.messages.empty());
    stream.input += frame("ILOG", "test").substr(2) + "NOPEISDN";
    events.dispatchEvent(Event(events.forIStream().inputReady(), &stream));
    ASSERT_EQ(1u, events.messages.size());
    EXPECT_EQ("test", static_cast<IpcLogLineMessage&>(*events.messages[0]).logLine());
    EXPECT_TRUE(stream.closed);
    EXPECT_EQ(stream.input.size() - 4, stream.offset);
}

class IpcCommandEncodingTests : public ::testing::Test {
protected:
    void send(IpcServerProxy& proxy, bool elevate)
    {
        proxy.send(IpcCommandMessage("test", elevate));
    }
};

TEST_F(IpcCommandEncodingTests, EncodesBothElevationFlags)
{
    for (bool elevate : {false, true}) {
        CapturedEvents events;
        BufferStream stream;
        IpcServerProxy proxy(stream, &events);
        send(proxy, elevate);
        EXPECT_EQ(frame("ICMD", "test", elevate ? 1 : 0), stream.output);
    }
}
