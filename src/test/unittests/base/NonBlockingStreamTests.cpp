/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2026 barrier-x contributors
 *
 * This package is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License found in LICENSE.
 * This package is distributed WITHOUT ANY WARRANTY; see LICENSE for details.
 */

#if SYSAPI_UNIX
#include "base/NonBlockingStream.h"
#include "test/global/gtest.h"

#include <fcntl.h>
#include <unistd.h>

class NonBlockingStreamTests : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_EQ(0, pipe(descriptors)); }
    void TearDown() override
    {
        for (int fd : descriptors) {
            if (fd != -1) {
                close(fd);
            }
        }
    }
    int descriptors[2] = {-1, -1};
};

TEST_F(NonBlockingStreamTests, EmptyPipeDoesNotBlock)
{
    NonBlockingStream input(descriptors[0]);
    char value = 'x';
    EXPECT_FALSE(input.try_read_char(value));
    EXPECT_EQ('x', value);
}

TEST_F(NonBlockingStreamTests, EndOfFileDoesNotAbort)
{
    NonBlockingStream input(descriptors[0]);
    close(descriptors[1]);
    descriptors[1] = -1;
    char value = 'x';
    EXPECT_FALSE(input.try_read_char(value));
}

TEST_F(NonBlockingStreamTests, ReadsAvailableCharacter)
{
    NonBlockingStream input(descriptors[0]);
    ASSERT_EQ(1, write(descriptors[1], "z", 1));
    char value = 0;
    EXPECT_TRUE(input.try_read_char(value));
    EXPECT_EQ('z', value);
}

TEST_F(NonBlockingStreamTests, RestoresOriginalFlags)
{
    int original = fcntl(descriptors[0], F_GETFL);
    ASSERT_NE(-1, original);
    {
        NonBlockingStream input(descriptors[0]);
        EXPECT_NE(0, fcntl(descriptors[0], F_GETFL) & O_NONBLOCK);
    }
    EXPECT_EQ(original, fcntl(descriptors[0], F_GETFL));
}

TEST_F(NonBlockingStreamTests, InvalidDescriptorIsInactive)
{
    NonBlockingStream input(-1);
    char value = 'x';
    EXPECT_FALSE(input.try_read_char(value));
}
#endif
