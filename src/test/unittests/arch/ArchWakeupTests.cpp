/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2026 barrier-x contributors
 *
 * This package is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License found in LICENSE.
 * This package is distributed WITHOUT ANY WARRANTY; see LICENSE for details.
 */

#if SYSAPI_UNIX
#include "arch/Arch.h"
#include "arch/XArch.h"
#include "test/global/gtest.h"

#include <atomic>
#include <cerrno>
#include <fcntl.h>

#if defined(BARRIER_TEST_WRAP_POLL) && HAVE_POLL
#include <poll.h>
namespace {
thread_local bool cancel_next_poll = false;
}

extern "C" int __real_poll(struct pollfd*, nfds_t, int);
extern "C" int __wrap_poll(struct pollfd* descriptors, nfds_t count, int timeout)
{
    if (cancel_next_poll) {
        cancel_next_poll = false;
        ArchThread current = ARCH->newCurrentThread();
        ARCH->cancelThread(current);
        ARCH->closeThread(current);
        errno = EINTR;
        return -1;
    }
    return __real_poll(descriptors, count, timeout);
}

TEST(ArchWakeupTests, InterruptedPollPropagatesCancellation)
{
    std::atomic<bool> cancelled{false};
    ArchSocket socket = ARCH->newSocket(IArchNetwork::kINET, IArchNetwork::kSTREAM);
    ArchThread worker = ARCH->newThread([socket, &cancelled]() {
        IArchNetwork::PollEntry entry{};
        entry.m_socket = socket;
        entry.m_events = IArchNetwork::kPOLLIN;
        cancel_next_poll = true;
        try {
            ARCH->pollSocket(&entry, 1, -1);
        }
        catch (XThreadCancel&) {
            cancelled.store(true);
            throw;
        }
    });
    ASSERT_NE(nullptr, worker);
    EXPECT_TRUE(ARCH->wait(worker, 5));
    ARCH->closeThread(worker);
    ARCH->closeSocket(socket);
    EXPECT_TRUE(cancelled.load());
}
#endif

TEST(ArchWakeupTests, PipeBelongsToTargetAndClosesWithThread)
{
    auto* threads = ArchMultithreadPosix::getInstance();
    ArchThread current = ARCH->newCurrentThread();
    void* original = threads->getNetworkDataForThread(current);
    std::atomic<bool> finished{false};
    ArchThread worker = ARCH->newThread([&finished]() {
        while (!finished.load()) {
            ARCH->sleep(0.001);
        }
    });
    ASSERT_NE(nullptr, worker);
    ARCH->unblockPollSocket(worker);
    auto* pipe = static_cast<int*>(threads->getNetworkDataForThread(worker));
    EXPECT_NE(nullptr, pipe);
    EXPECT_EQ(original, threads->getNetworkDataForThread(current));

    int read_end = pipe ? pipe[0] : -1;
    int write_end = pipe ? pipe[1] : -1;
    if (pipe) {
        EXPECT_NE(0, fcntl(read_end, F_GETFL) & O_NONBLOCK);
        EXPECT_NE(0, fcntl(write_end, F_GETFL) & O_NONBLOCK);
        EXPECT_NE(0, fcntl(read_end, F_GETFD) & FD_CLOEXEC);
        EXPECT_NE(0, fcntl(write_end, F_GETFD) & FD_CLOEXEC);
        for (int wake = 0; wake < 10000; ++wake) {
            ARCH->unblockPollSocket(worker);
        }
        EXPECT_EQ(pipe, threads->getNetworkDataForThread(worker));
    }
    finished.store(true);
    EXPECT_TRUE(ARCH->wait(worker, 5));
    ARCH->closeThread(worker);
    ARCH->closeThread(current);
    if (pipe) {
        errno = 0;
        EXPECT_EQ(-1, fcntl(read_end, F_GETFD));
        EXPECT_EQ(EBADF, errno);
        errno = 0;
        EXPECT_EQ(-1, fcntl(write_end, F_GETFD));
        EXPECT_EQ(EBADF, errno);
    }
}
#endif
