/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2026 barrier-x contributors
 *
 * This package is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License found in LICENSE.
 * This package is distributed WITHOUT ANY WARRANTY; see LICENSE for details.
 */

#include "base/EventQueue.h"
#include "base/EventTypes.h"
#include "test/global/gtest.h"

#include <array>
#include <atomic>
#include <thread>
#include <vector>

// Exercise every lazy provider so leak checking covers queue teardown, rather
// than relying on whichever event types a socket test happens to request.
TEST(EventQueueTests, OwnsAndReusesEveryEventTypeProvider)
{
    for (int cycle = 0; cycle < 3; ++cycle) {
        EventQueue events;
#define CHECK_PROVIDER(type) \
        EXPECT_EQ(&events.for##type(), &events.for##type())
        CHECK_PROVIDER(Client);
        CHECK_PROVIDER(IStream);
        CHECK_PROVIDER(IpcClient);
        CHECK_PROVIDER(IpcClientProxy);
        CHECK_PROVIDER(IpcServer);
        CHECK_PROVIDER(IpcServerProxy);
        CHECK_PROVIDER(IDataSocket);
        CHECK_PROVIDER(IListenSocket);
        CHECK_PROVIDER(ISocket);
        CHECK_PROVIDER(OSXScreen);
        CHECK_PROVIDER(ClientListener);
        CHECK_PROVIDER(ClientProxy);
        CHECK_PROVIDER(ClientProxyUnknown);
        CHECK_PROVIDER(Server);
        CHECK_PROVIDER(ServerApp);
        CHECK_PROVIDER(IKeyState);
        CHECK_PROVIDER(IPrimaryScreen);
        CHECK_PROVIDER(IScreen);
        CHECK_PROVIDER(Clipboard);
        CHECK_PROVIDER(File);
#undef CHECK_PROVIDER
    }
}

TEST(EventQueueTests, ConcurrentProviderCreationReturnsOneInstance)
{
    EventQueue events;
    std::atomic<bool> start{false};
    std::array<IStreamEvents*, 8> providers{};
    std::vector<std::thread> callers;
    for (std::size_t index = 0; index < providers.size(); ++index) {
        callers.emplace_back([&, index] {
            while (!start.load()) {
                std::this_thread::yield();
            }
            providers[index] = &events.forIStream();
            providers[index]->inputShutdown();
        });
    }
    start.store(true);
    for (auto& caller : callers) {
        caller.join();
    }
    for (auto* provider : providers) {
        EXPECT_EQ(&events.forIStream(), provider);
    }
}
