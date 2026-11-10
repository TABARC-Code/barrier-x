/*
    barrier -- mouse and keyboard sharing utility
    Copyright (C) Barrier contributors

    This package is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    found in the file LICENSE that should have accompanied this file.

    This package is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "net/FingerprintDatabase.h"
#include "test/global/gtest.h"
#include <fstream>
#include <stdexcept>
#include <openssl/rand.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace barrier {

TEST(FingerprintDatabase, parse_db_line)
{
    ASSERT_FALSE(FingerprintDatabase::parse_db_line("").valid());
    ASSERT_FALSE(FingerprintDatabase::parse_db_line("abcd").valid());
    ASSERT_FALSE(FingerprintDatabase::parse_db_line("v1:algo:something").valid());
    ASSERT_FALSE(FingerprintDatabase::parse_db_line("v2:algo:something").valid());
    ASSERT_FALSE(FingerprintDatabase::parse_db_line("v2:algo:01020304abc").valid());
    ASSERT_FALSE(FingerprintDatabase::parse_db_line("v2:algo:01020304ZZ").valid());
    ASSERT_EQ(FingerprintDatabase::parse_db_line("v2:algo:01020304ab"),
              (FingerprintData{"algo", {1, 2, 3, 4, 0xab}}));
}

TEST(FingerprintDatabase, read)
{
    std::istringstream stream;
    stream.str(R"(
v2:algo1:01020304ab
v2:algo2:03040506ab
AB:CD:EF:00:01:02:03:04:05:06:07:08:09:10:11:12:13:14:15:16
)");
    FingerprintDatabase db;
    db.read_stream(stream);

    std::vector<FingerprintData> expected = {
        { "algo1", { 1, 2, 3, 4, 0xab } },
        { "algo2", { 3, 4, 5, 6, 0xab } },
        { "sha1", { 0xab, 0xcd, 0xef, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 } },
    };
    ASSERT_EQ(db.fingerprints(), expected);
}

TEST(FingerprintDatabase, write)
{
    std::ostringstream stream;

    FingerprintDatabase db;
    db.add_trusted({ "algo1", { 1, 2, 3, 4, 0xab } });
    db.add_trusted({ "algo2", { 3, 4, 5, 6, 0xab } });
    db.write_stream(stream);

    ASSERT_EQ(stream.str(), R"(v2:algo1:01020304ab
v2:algo2:03040506ab
)");
}

TEST(FingerprintDatabase, clear)
{
    FingerprintDatabase db;
    db.add_trusted({ "algo1", { 1, 2, 3, 4, 0xab } });
    db.clear();
    ASSERT_TRUE(db.fingerprints().empty());
}

TEST(FingerprintDatabase, add_trusted_no_duplicates)
{
    FingerprintDatabase db;
    db.add_trusted({ "algo1", { 1, 2, 3, 4, 0xab } });
    db.add_trusted({ "algo2", { 3, 4, 5, 6, 0xab } });
    db.add_trusted({ "algo1", { 1, 2, 3, 4, 0xab } });
    ASSERT_EQ(db.fingerprints().size(), 2);
}

TEST(FingerprintDatabase, is_trusted)
{
    FingerprintDatabase db;
    db.add_trusted({ "algo1", { 1, 2, 3, 4, 0xab } });
    ASSERT_TRUE(db.is_trusted({ "algo1", { 1, 2, 3, 4, 0xab } }));
    ASSERT_FALSE(db.is_trusted({ "algo2", { 1, 2, 3, 4, 0xab } }));
    ASSERT_FALSE(db.is_trusted({ "algo1", { 1, 2, 3, 4, 0xac } }));
}

} // namespace barrier


#ifndef _WIN32
namespace barrier {
class TrustedFingerprintStorageTests : public ::testing::Test {
protected:
    void SetUp() override {
        unsigned char random[16];
        ASSERT_EQ(1, RAND_bytes(random, sizeof(random)));
        static const char hex[] = "0123456789abcdef";
        std::string suffix;
        for (auto byte : random) { suffix += hex[byte >> 4]; suffix += hex[byte & 15]; }
        directory = fs::temp_directory_path() / ("barrier-trust-read-" + suffix);
        ASSERT_TRUE(fs::create_directory(directory));
        ASSERT_EQ(0, chmod(directory.c_str(), 0700));
        target = directory / "trusted.txt";
    }
    void TearDown() override { std::error_code ignored; fs::remove_all(directory, ignored); }
    void write(const std::string& bytes) {
        std::ofstream output(target.c_str(), std::ios::binary);
        output << bytes;
        ASSERT_TRUE(output.good());
    }
    fs::path directory, target;
    FingerprintData peer{"sha256", std::vector<std::uint8_t>(32, 0xab)};
};
TEST_F(TrustedFingerprintStorageTests, ValidPinsAndCrLfAreAccepted)
{
    write(FingerprintDatabase::to_db_line(peer) + "\r\n\n");
    FingerprintDatabase db;
    db.read_trusted(target);
    EXPECT_TRUE(db.is_trusted(peer));
    EXPECT_EQ(1u, db.fingerprints().size());
}
TEST_F(TrustedFingerprintStorageTests, MalformedTailAndOversizeClearPreviousAuthority)
{
    FingerprintDatabase db;
    db.add_trusted(peer);
    write(FingerprintDatabase::to_db_line(peer) + "\nnot a fingerprint\n");
    EXPECT_THROW(db.read_trusted(target), std::runtime_error);
    EXPECT_TRUE(db.fingerprints().empty());
    write(std::string(1024 * 1024 + 1, 'x'));
    EXPECT_THROW(db.read_trusted(target), std::runtime_error);
    EXPECT_TRUE(db.fingerprints().empty());
}
TEST_F(TrustedFingerprintStorageTests, MissingStorageCannotRetainOldPins)
{
    FingerprintDatabase db;
    db.add_trusted(peer);
    EXPECT_NO_THROW(db.read_trusted(target));
    EXPECT_TRUE(db.fingerprints().empty());
    EXPECT_NO_THROW(db.read_trusted(directory / "missing" / "trusted.txt"));
    EXPECT_FALSE(fs::exists(directory / "missing"));
}
TEST_F(TrustedFingerprintStorageTests, LinksAndWritableFilesAreRefusedWithoutRepair)
{
    write(FingerprintDatabase::to_db_line(peer));
    ASSERT_EQ(0, chmod(target.c_str(), 0666));
    FingerprintDatabase db;
    EXPECT_THROW(db.read_trusted(target), std::runtime_error);
    struct stat info{};
    ASSERT_EQ(0, stat(target.c_str(), &info));
    EXPECT_EQ(0666, info.st_mode & 0777);
    ASSERT_EQ(0, chmod(target.c_str(), 0600));
    fs::create_symlink(target, directory / "link");
    EXPECT_THROW(db.read_trusted(directory / "link"), std::runtime_error);
    fs::create_hard_link(target, directory / "hard");
    EXPECT_THROW(db.read_trusted(target), std::runtime_error);
}
TEST_F(TrustedFingerprintStorageTests, UnsafeAncestorAndLinkedFinalFolderAreRefused)
{
    const auto outer = directory / "outer";
    fs::create_directories(outer / "private");
    target = outer / "private" / "trusted.txt";
    write(FingerprintDatabase::to_db_line(peer));
    ASSERT_EQ(0, chmod(outer.c_str(), 0777));
    FingerprintDatabase db;
    EXPECT_THROW(db.read_trusted(target), std::runtime_error);
    ASSERT_EQ(0, chmod(outer.c_str(), 0700));
    fs::create_directory_symlink(outer / "private", directory / "alias");
    EXPECT_THROW(db.read_trusted(directory / "alias" / "trusted.txt"), std::runtime_error);
}
TEST_F(TrustedFingerprintStorageTests, FifoAndInvalidPathsAreRefusedWithoutWaiting)
{
    ASSERT_EQ(0, mkfifo(target.c_str(), 0600));
    FingerprintDatabase db;
    EXPECT_THROW(db.read_trusted(target), std::runtime_error);
    EXPECT_THROW(db.read_trusted(fs::path(target.native() + std::string("\0x", 2))), std::runtime_error);
    EXPECT_THROW(db.read_trusted(directory / "missing" / ".." / "trusted.txt"), std::runtime_error);
}
}
#endif
