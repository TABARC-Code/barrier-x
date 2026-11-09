/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "../src/PeerTrustStore.h"
#include <gtest/gtest.h>
#include <QFile>
#include <QLockFile>
#include <QTemporaryDir>
#include <stdexcept>
#ifndef _WIN32
#include <sys/stat.h>
#endif

class PeerTrustStoreTests : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(folder.isValid());
        path = barrier::fs::u8path(folder.filePath("trusted.txt").toStdString());
    }
    void write(const QByteArray& bytes) {
        QFile file(QString::fromStdString(path.u8string()));
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(bytes.size(), file.write(bytes));
    }
    QByteArray bytes() {
        QFile file(QString::fromStdString(path.u8string()));
        if (!file.open(QIODevice::ReadOnly)) { return {}; }
        return file.readAll();
    }
    barrier::FingerprintData peer(unsigned char value) {
        return {"sha256", std::vector<std::uint8_t>(32, value)};
    }
    QTemporaryDir folder;
    barrier::fs::path path;
};
TEST_F(PeerTrustStoreTests, MissingStoreIsCreatedWithTheApprovedPeer)
{
    EXPECT_TRUE(PeerTrustStore::read(path).fingerprints().empty());
    PeerTrustStore::approve(path, peer(1));
    EXPECT_TRUE(PeerTrustStore::read(path).is_trusted(peer(1)));
#ifndef _WIN32
    struct stat info{};
    ASSERT_EQ(0, stat(path.c_str(), &info));
    EXPECT_EQ(0600, info.st_mode & 07777);
#endif
}
TEST_F(PeerTrustStoreTests, SeparateApprovalsMergeWithoutDuplicates)
{
    PeerTrustStore::approve(path, peer(1));
    PeerTrustStore::approve(path, peer(2));
    PeerTrustStore::approve(path, peer(1));
    auto result = PeerTrustStore::read(path);
    EXPECT_EQ(2u, result.fingerprints().size());
    EXPECT_TRUE(result.is_trusted(peer(1)));
    EXPECT_TRUE(result.is_trusted(peer(2)));
}
TEST_F(PeerTrustStoreTests, LegacyAndWindowsLineEndingsArePreservedAsEntries)
{
    write(QByteArray("11:").repeated(19) + "11\r\n\r\n");
    PeerTrustStore::approve(path, peer(2));
    auto result = PeerTrustStore::read(path);
    EXPECT_TRUE(result.is_trusted({"sha1", std::vector<std::uint8_t>(20, 0x11)}));
    EXPECT_TRUE(result.is_trusted(peer(2)));
}
TEST_F(PeerTrustStoreTests, MalformedAndUnknownEntriesLeaveTheStoreUntouched)
{
    for (const auto& contents : {QByteArray("broken\n"), QByteArray("v2:unknown:11\n"),
                                 QByteArray("v2:sha256:11\n")}) {
        write(contents);
        EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
        EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
        EXPECT_EQ(contents, bytes());
    }
}
TEST_F(PeerTrustStoreTests, OversizedStoreIsNotReadOrOverwritten)
{
    const QByteArray contents(1024 * 1024 + 1, 'x');
    write(contents);
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_TRUE(contents == bytes());
}
TEST_F(PeerTrustStoreTests, HeldLockRefusesTheSaveAndReleaseAllowsRetry)
{
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    QLockFile lock(QString::fromStdString(path.u8string()) + ".lock");
    lock.setStaleLockTime(0);
    ASSERT_TRUE(lock.tryLock(0));
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_EQ(original, bytes());
    lock.unlock();
    PeerTrustStore::approve(path, peer(2));
    EXPECT_TRUE(PeerTrustStore::read(path).is_trusted(peer(2)));
}
TEST_F(PeerTrustStoreTests, IncompleteOrLegacyApprovalCannotCreateAStore)
{
    EXPECT_THROW(PeerTrustStore::approve(path, {"sha1", std::vector<std::uint8_t>(20, 1)}), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, {"sha256", std::vector<std::uint8_t>(31, 1)}), std::runtime_error);
    EXPECT_FALSE(barrier::fs::exists(path));
}
TEST_F(PeerTrustStoreTests, DirectoryCannotBecomeATrustFile)
{
    barrier::fs::create_directory(path);
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_TRUE(barrier::fs::is_directory(path));
}
#ifndef _WIN32
TEST_F(PeerTrustStoreTests, SymlinkAndHardlinkDoNotChangeTheirVictim)
{
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    const auto victim = path.parent_path() / "victim";
    barrier::fs::rename(path, victim);
    barrier::fs::create_symlink(victim, path);
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    barrier::fs::remove(path);
    barrier::fs::create_hard_link(victim, path);
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_EQ(original, bytes());
}
TEST_F(PeerTrustStoreTests, GroupWritableStoreNeedsDeliberateRepair)
{
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    ASSERT_EQ(0, chmod(path.c_str(), 0660));
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_EQ(original, bytes());
}
TEST_F(PeerTrustStoreTests, FifoIsRefusedWithoutWaitingForAWriter)
{
    ASSERT_EQ(0, mkfifo(path.c_str(), 0600));
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
}
#endif
