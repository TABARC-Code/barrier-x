/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "test/global/gtest.h"
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#if SYSAPI_WIN32
TEST(OpenSslRuntimeTests, WindowsLoadsSupportedCryptoRuntime)
{
    // I check loaded libcrypto too. Finding new headers doesn't replace an old DLL.
    const auto version = OpenSSL_version_num();
    EXPECT_EQ(0x30500000UL, version & 0xfff00000UL);
    EXPECT_GE(version, 0x30500090UL);
}
#endif
