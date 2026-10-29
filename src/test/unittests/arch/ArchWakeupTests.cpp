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
#include "test/global/gtest.h"

#include <atomic>
#include <cerrno>
#include <fcntl.h>

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
