/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "io/LogStore.h"
#include "base/log_outputters.h"
#include "test/global/gtest.h"
#include <fstream>
#include <stdexcept>
#include <chrono>
#include <thread>
#ifndef _WIN32
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
namespace {
class LogStoreTests : public ::testing::Test {
protected:
    void SetUp() override {
        char pattern[] = "/tmp/barrier-log-XXXXXX";
        auto result = ::mkdtemp(pattern); ASSERT_NE(nullptr, result);
        folder = result; path = folder / "barrier.log";
    }
    void TearDown() override { barrier::fs::remove_all(folder); }
    std::string read(const barrier::fs::path& p) {
        std::ifstream input(p.native(), std::ios::binary);
        return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }
    void put(const barrier::fs::path& p, const std::string& value) { std::ofstream output(p.native(), std::ios::binary); output << value; }
    barrier::fs::path folder, path;
    const std::time_t now = 1700000000;
};
TEST_F(LogStoreTests, ExactChoicesAndBoundary) {
    for (int days : {0,5,10,12,15,22,28,30,60}) { EXPECT_TRUE(barrier::valid_log_retention(days)); }
    for (int days : {-1,1,6,21,31,61}) { EXPECT_FALSE(barrier::valid_log_retention(days)); }
    barrier::append_log(path, "private", 0, now);
    EXPECT_EQ(0u, barrier::expire_logs(path, 0, now + 100*86400));
    EXPECT_EQ(0u, barrier::expire_logs(path, 5, now - 1));
    EXPECT_EQ(0u, barrier::expire_logs(path, 5, now + 5*86400 - 1));
    EXPECT_EQ(1u, barrier::expire_logs(path, 5, now + 5*86400));
    EXPECT_TRUE(read(path).empty());
    barrier::append_log(path, "fresh", 5, now + 5*86400);
    EXPECT_NE(std::string::npos, read(path).find("fresh"));
    EXPECT_THROW(barrier::expire_logs(path, 1, now), std::invalid_argument);
}
TEST_F(LogStoreTests, ClearsOnlyConfiguredFilesAndKeepsWriterUsable) {
    auto backup = path; backup += ".1";
    barrier::append_log(path, "active", 0, now); barrier::append_log(backup, "backup", 0, now);
    put(folder / "identity.pem", "keep this");
    EXPECT_EQ(2u, barrier::clear_logs(path));
    EXPECT_TRUE(read(path).empty()); EXPECT_TRUE(read(backup).empty());
    EXPECT_EQ("keep this", read(folder / "identity.pem"));
    barrier::append_log(path, "after clearing", 0, now + 1);
    EXPECT_NE(std::string::npos, read(path).find("after clearing"));
    struct stat info{}; ASSERT_EQ(0, ::stat(path.c_str(), &info)); EXPECT_EQ(0600, info.st_mode & 0777);
}
TEST_F(LogStoreTests, ExpiryUsesOldestEntryAndClearsBackupIndependently) {
    auto backup = path; backup += ".1";
    barrier::append_log(path, "old", 0, now); barrier::append_log(path, "newer", 0, now + 4*86400);
    barrier::append_log(backup, "recent archive", 0, now + 4*86400);
    EXPECT_EQ(1u, barrier::expire_logs(path, 5, now + 5*86400)); EXPECT_TRUE(read(path).empty());
    EXPECT_NE(std::string::npos, read(backup).find("recent archive"));
}
TEST_F(LogStoreTests, UnknownBackupRefusesBeforeClearingActive) {
    barrier::append_log(path, "keep", 0, now); auto original = read(path);
    auto backup = path; backup += ".1"; put(backup, "not an application log");
    EXPECT_THROW(barrier::clear_logs(path), std::runtime_error);
    EXPECT_THROW(barrier::expire_logs(path, 5, now + 10*86400), std::runtime_error);
    EXPECT_EQ(original, read(path)); EXPECT_EQ("not an application log", read(backup));
}
TEST_F(LogStoreTests, RefusesLinksAndUnsafeParent) {
    auto target = folder / "target"; barrier::append_log(target, "keep", 0, now); auto original = read(target);
    ASSERT_EQ(0, ::symlink(target.c_str(), path.c_str())); EXPECT_THROW(barrier::clear_logs(path), std::runtime_error);
    barrier::fs::remove(path); ASSERT_EQ(0, ::link(target.c_str(), path.c_str()));
    EXPECT_THROW(barrier::clear_logs(path), std::runtime_error); barrier::fs::remove(path);
    ASSERT_EQ(0, ::chmod(folder.c_str(), 0777)); EXPECT_THROW(barrier::clear_logs(target), std::runtime_error);
    ASSERT_EQ(0, ::chmod(folder.c_str(), 0700)); EXPECT_EQ(original, read(target));
}
TEST_F(LogStoreTests, BusyLogFailsWithoutClearing) {
    barrier::append_log(path, "keep", 0, now); auto original = read(path);
    int fd = ::open(path.c_str(), O_RDWR); ASSERT_GE(fd, 0); ASSERT_EQ(0, ::flock(fd, LOCK_EX | LOCK_NB));
    EXPECT_THROW(barrier::clear_logs(path), std::runtime_error); EXPECT_EQ(original, read(path)); ::close(fd);
    EXPECT_EQ(1u, barrier::clear_logs(path));
}
TEST_F(LogStoreTests, LegacyDatesAndMalformedMarkers) {
    put(path, "[2023-01-01T00:00:00] INFO: legacy\n"); barrier::append_log(path, "later", 0, now);
    EXPECT_NE(std::string::npos, read(path).find("later")); EXPECT_EQ(1u, barrier::expire_logs(path, 60, now));
    for (const auto& invalid : {"# barrier-x log 1 -1\n", "# barrier-x log 1 abc\n", "ordinary text\n"}) {
        put(path, invalid); EXPECT_THROW(barrier::clear_logs(path), std::runtime_error); EXPECT_EQ(invalid, read(path));
    }
}
TEST_F(LogStoreTests, RotationPreservesAgeAndBounds) {
    const std::string message(64000, 'x');
    for (int i=0; i<18; ++i) { barrier::append_log(path, message, 0, now); }
    auto backup = path; backup += ".1"; EXPECT_TRUE(barrier::fs::exists(backup));
    EXPECT_LT(read(path).size(), 1024u*1024u); EXPECT_LT(read(backup).size(), 1024u*1024u);
    EXPECT_EQ(2u, barrier::expire_logs(path, 5, now + 5*86400));
}
TEST_F(LogStoreTests, RefusesOversizedFilesAndFifos) {
    const std::string oversized = "# barrier-x log 1 1700000000\n" + std::string(2*1024*1024, 'x');
    put(path, oversized);
    EXPECT_THROW(barrier::clear_logs(path), std::runtime_error); EXPECT_EQ(oversized, read(path));
    barrier::fs::remove(path); ASSERT_EQ(0, ::mkfifo(path.c_str(), 0600));
    EXPECT_THROW(barrier::clear_logs(path), std::runtime_error);
}
TEST_F(LogStoreTests, RefusesWritableEarlierAncestor) {
    auto child = folder / "private"; ASSERT_TRUE(barrier::fs::create_directory(child));
    auto nested = child / "barrier.log"; barrier::append_log(nested, "keep", 0, now);
    const auto original = read(nested);
    ASSERT_EQ(0, ::chmod(folder.c_str(), 0777));
    EXPECT_THROW(barrier::clear_logs(nested), std::runtime_error);
    ASSERT_EQ(0, ::chmod(folder.c_str(), 0700)); EXPECT_EQ(original, read(nested));
}
TEST_F(LogStoreTests, EngineTimerClearsQuietLogAndStopsPromptly) {
    barrier::append_log(path, "expired", 0, std::time(nullptr) - 6*86400);
    const auto start = std::chrono::steady_clock::now();
    { FileLogOutputter output(path.c_str(), 5);
      for (int i=0; i<100 && !read(path).empty(); ++i) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); }
      EXPECT_TRUE(read(path).empty()); }
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(3));
}
}
#endif
