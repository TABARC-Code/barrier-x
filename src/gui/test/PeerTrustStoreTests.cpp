/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "../src/PeerTrustStore.h"
#include <gtest/gtest.h>
#include <QFile>
#include <QLockFile>
#include <QTemporaryDir>
#include <stdexcept>
#include "base/finally.h"
#ifndef _WIN32
#include <sys/stat.h>
#endif
#ifdef BARRIER_TEST_WRAP_PEER_IO
#include <cerrno>
#include <cstdarg>
#include <fcntl.h>
#include <functional>
#include <unistd.h>
#include <utility>
namespace {
thread_local bool fail_write = false, zero_write = false, short_write = false, interrupt_write = false;
thread_local bool fail_sync = false, interrupt_sync = false, fail_mode = false, fail_rename = false;
thread_local bool foreign_folder = false, foreign_link = false, fail_mkdir = false;
thread_local std::function<void(int, const char*, int)> open_hook;
thread_local int write_descriptor_flags = -1;
thread_local std::function<void()> sync_hook, rename_hook;
}
extern "C" int __real_openat(int, const char*, int, ...);
extern "C" int __wrap_openat(int parent, const char* name, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
    }
    if (open_hook) { auto hook = open_hook; hook(parent, name, flags); }
    return flags & O_CREAT ? __real_openat(parent, name, flags, mode) : __real_openat(parent, name, flags);
}
extern "C" int __real_mkdirat(int, const char*, mode_t);
extern "C" int __wrap_mkdirat(int parent, const char* name, mode_t mode)
{
    if (std::exchange(fail_mkdir, false)) { errno = EACCES; return -1; }
    return __real_mkdirat(parent, name, mode);
}
extern "C" int __real_fstatat(int, const char*, struct stat*, int);
extern "C" int __wrap_fstatat(int parent, const char* name, struct stat* info, int flags)
{
    const int result = __real_fstatat(parent, name, info, flags);
    if (result == 0 && S_ISLNK(info->st_mode) && std::exchange(foreign_link, false)) {
        info->st_uid = geteuid() + 1;
    }
    return result;
}
extern "C" ssize_t __real_write(int, const void*, size_t);
extern "C" ssize_t __wrap_write(int fd, const void* data, size_t size)
{
    write_descriptor_flags = fcntl(fd, F_GETFD);
    if (std::exchange(interrupt_write, false)) { errno = EINTR; return -1; }
    if (std::exchange(fail_write, false)) { errno = ENOSPC; return -1; }
    if (std::exchange(zero_write, false)) { return 0; }
    if (std::exchange(short_write, false) && size > 1) { size /= 2; }
    return __real_write(fd, data, size);
}
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd)
{
    if (sync_hook) { auto hook = std::move(sync_hook); sync_hook = {}; hook(); }
    if (std::exchange(interrupt_sync, false)) { errno = EINTR; return -1; }
    if (std::exchange(fail_sync, false)) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
extern "C" int __real_fchmod(int, mode_t);
extern "C" int __real_fstat(int, struct stat*);
extern "C" int __wrap_fstat(int fd, struct stat* info)
{
    const int result = __real_fstat(fd, info);
    if (result == 0 && S_ISDIR(info->st_mode) && std::exchange(foreign_folder, false)) {
        info->st_uid = geteuid() + 1;
    }
    return result;
}
extern "C" int __wrap_fchmod(int fd, mode_t mode)
{
    if (std::exchange(fail_mode, false)) { errno = EPERM; return -1; }
    return __real_fchmod(fd, mode);
}
extern "C" int __real_renameat(int, const char*, int, const char*);
extern "C" int __wrap_renameat(int from, const char* old_name, int to, const char* new_name)
{
    if (rename_hook) { auto hook = std::move(rename_hook); rename_hook = {}; hook(); }
    if (std::exchange(fail_rename, false)) { errno = EIO; return -1; }
    return __real_renameat(from, old_name, to, new_name);
}
#endif

class PeerTrustStoreTests : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(folder.isValid());
        path = barrier::fs::u8path(folder.filePath("trusted.txt").toStdString());
    }
    void TearDown() override {
#ifdef BARRIER_TEST_WRAP_PEER_IO
        fail_write = zero_write = short_write = interrupt_write = false;
        fail_sync = interrupt_sync = fail_mode = fail_rename = false;
        foreign_folder = foreign_link = fail_mkdir = false;
        open_hook = {};
        write_descriptor_flags = -1;
        sync_hook = rename_hook = {};
#endif
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
TEST_F(PeerTrustStoreTests, SymlinkedFolderCannotRedirectApproval)
{
    const auto root = path.parent_path();
    const auto real = root / "real";
    const auto link = root / "link";
    barrier::fs::create_directory(real);
    barrier::fs::create_directory_symlink(real, link);
    path = link / "trusted.txt";
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, peer(1)), std::runtime_error);
    EXPECT_FALSE(barrier::fs::exists(real / "trusted.txt"));
    EXPECT_TRUE(barrier::fs::is_empty(real));
}
TEST_F(PeerTrustStoreTests, WritableFolderMustBeRepairedBeforeReadingOrSaving)
{
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    ASSERT_EQ(0, chmod(path.parent_path().c_str(), 0770));
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_EQ(original, bytes());
    ASSERT_EQ(0, chmod(path.parent_path().c_str(), 0700));
    PeerTrustStore::approve(path, peer(2));
    EXPECT_TRUE(PeerTrustStore::read(path).is_trusted(peer(2)));
}
TEST_F(PeerTrustStoreTests, MissingFolderIsEmptyUntilApprovalCreatesIt)
{
    path = path.parent_path() / "missing" / "trusted.txt";
    EXPECT_TRUE(PeerTrustStore::read(path).fingerprints().empty());
    EXPECT_FALSE(barrier::fs::exists(path.parent_path()));
    PeerTrustStore::approve(path, peer(1));
    EXPECT_TRUE(PeerTrustStore::read(path).is_trusted(peer(1)));
}
TEST_F(PeerTrustStoreTests, EmbeddedNullCannotSelectAnotherFile)
{
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    const auto malformed = barrier::fs::path(path.native() + std::string("\0other", 6));
    EXPECT_THROW(PeerTrustStore::read(malformed), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(malformed, peer(2)), std::runtime_error);
    EXPECT_EQ(original, bytes());
}
#endif
#ifdef BARRIER_TEST_WRAP_PEER_IO
TEST_F(PeerTrustStoreTests, FailedWritesFlushPermissionsAndRenamePreserveApprovals)
{
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    for (bool* fault : {&fail_write, &zero_write, &fail_sync, &fail_mode, &fail_rename}) {
        *fault = true;
        EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
        EXPECT_FALSE(*fault);
        EXPECT_EQ(original, bytes());
        for (const auto& entry : barrier::fs::directory_iterator(path.parent_path())) {
            EXPECT_EQ(path, entry.path());
        }
    }
}
TEST_F(PeerTrustStoreTests, ShortAndInterruptedWritesAndInterruptedFlushAreRetried)
{
    short_write = interrupt_write = interrupt_sync = true;
    PeerTrustStore::approve(path, peer(1));
    EXPECT_FALSE(short_write);
    EXPECT_FALSE(interrupt_write);
    EXPECT_FALSE(interrupt_sync);
    EXPECT_NE(0, write_descriptor_flags & FD_CLOEXEC);
    EXPECT_TRUE(PeerTrustStore::read(path).is_trusted(peer(1)));
}
TEST_F(PeerTrustStoreTests, ForeignFolderOwnershipRefusesReadsAndUpdates)
{
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    foreign_folder = true;
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_FALSE(foreign_folder);
    foreign_folder = true;
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_FALSE(foreign_folder);
    EXPECT_EQ(original, bytes());
}
TEST_F(PeerTrustStoreTests, FolderReplacementBeforePublicationFailsWithoutRedirectingCleanup)
{
    const auto root = path.parent_path();
    path = root / "active" / "trusted.txt";
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    sync_hook = [&] {
        barrier::fs::rename(root / "active", root / "moved");
        barrier::fs::create_directory(root / "active");
    };
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_TRUE(barrier::fs::is_empty(root / "active"));
    path = root / "moved" / "trusted.txt";
    EXPECT_EQ(original, bytes());
    EXPECT_EQ(2, std::distance(barrier::fs::directory_iterator(path.parent_path()), barrier::fs::directory_iterator()));
    // The old Qt lock may remain after its directory moves; it isn't approval data.
    EXPECT_TRUE(barrier::fs::exists(path.native() + ".lock"));
}
TEST_F(PeerTrustStoreTests, LateFolderRenameDoesNotRedirectPublication)
{
    const auto root = path.parent_path();
    path = root / "active" / "trusted.txt";
    PeerTrustStore::approve(path, peer(1));
    rename_hook = [&] {
        barrier::fs::rename(root / "active", root / "moved");
        barrier::fs::create_directory(root / "active");
        PeerTrustStore::approve(path, peer(3));
    };
    PeerTrustStore::approve(path, peer(2));
    auto current = PeerTrustStore::read(path);
    EXPECT_TRUE(current.is_trusted(peer(3)));
    EXPECT_FALSE(current.is_trusted(peer(2)));
    auto held = PeerTrustStore::read(root / "moved" / "trusted.txt");
    EXPECT_TRUE(held.is_trusted(peer(1)));
    EXPECT_TRUE(held.is_trusted(peer(2)));
}
#endif

#ifndef _WIN32
TEST_F(PeerTrustStoreTests, WritableEarlierAncestorCannotHideBehindAPrivateLeaf)
{
    const auto outer = path.parent_path() / "outer";
    path = outer / "private" / "trusted.txt";
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    ASSERT_EQ(0, chmod(outer.c_str(), 0770));
    auto repair = barrier::finally([&] { chmod(outer.c_str(), 0700); });
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_EQ(original, bytes());
    EXPECT_EQ(1, std::distance(barrier::fs::directory_iterator(path.parent_path()), barrier::fs::directory_iterator()));
}
TEST_F(PeerTrustStoreTests, MissingAncestorsAreCreatedPrivatelyEvenWithAnOpenUmask)
{
    const auto outer = path.parent_path() / "outer";
    path = outer / "private" / "trusted.txt";
    const auto previous = umask(0);
    auto restore = barrier::finally([&] { umask(previous); });
    PeerTrustStore::approve(path, peer(1));
    for (const auto& folder : {outer, path.parent_path()}) {
        struct stat info{};
        ASSERT_EQ(0, stat(folder.c_str(), &info));
        EXPECT_EQ(0700, info.st_mode & 0777);
    }
    EXPECT_TRUE(PeerTrustStore::read(path).is_trusted(peer(1)));
}
TEST_F(PeerTrustStoreTests, ExplicitParentTraversalIsRejectedBeforeCreatingAnything)
{
    const auto root = path.parent_path();
    for (const auto& supplied : {root / "missing" / ".." / "trusted.txt", root / ".." / "escape" / "trusted.txt"}) {
        EXPECT_THROW(PeerTrustStore::read(supplied), std::runtime_error);
        EXPECT_THROW(PeerTrustStore::approve(supplied, peer(1)), std::runtime_error);
    }
    EXPECT_TRUE(barrier::fs::is_empty(root));
}
TEST_F(PeerTrustStoreTests, CheckedIntermediateLinksResolveAbsoluteAndRelativeTargets)
{
    const auto root = path.parent_path();
    const auto real = root / "real";
    barrier::fs::create_directory(real);
    barrier::fs::create_directory(root / "container");
    barrier::fs::create_directory_symlink(real, root / "absolute");
    barrier::fs::create_directory_symlink("../real", root / "container" / "relative");
    for (const auto& link : {root / "absolute", root / "container" / "relative"}) {
        const auto supplied = link / "private" / "trusted.txt";
        PeerTrustStore::approve(supplied, peer(1));
        EXPECT_TRUE(PeerTrustStore::read(supplied).is_trusted(peer(1)));
    }
    EXPECT_TRUE(PeerTrustStore::read(real / "private" / "trusted.txt").is_trusted(peer(1)));
}
TEST_F(PeerTrustStoreTests, IntermediateLinksCannotBypassAnUnsafeTargetOrLoopForever)
{
    const auto root = path.parent_path();
    barrier::fs::create_directory(root / "unsafe");
    barrier::fs::create_directory_symlink(root / "unsafe", root / "shortcut");
    ASSERT_EQ(0, chmod((root / "unsafe").c_str(), 0777));
    auto repair = barrier::finally([&] { chmod((root / "unsafe").c_str(), 0700); });
    EXPECT_THROW(PeerTrustStore::approve(root / "shortcut" / "private" / "trusted.txt", peer(1)), std::runtime_error);
    EXPECT_FALSE(barrier::fs::exists(root / "unsafe" / "private"));
    barrier::fs::create_directory_symlink("second", root / "first");
    barrier::fs::create_directory_symlink("first", root / "second");
    EXPECT_THROW(PeerTrustStore::read(root / "first" / "private" / "trusted.txt"), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(root / "first" / "private" / "trusted.txt", peer(1)), std::runtime_error);
}
TEST_F(PeerTrustStoreTests, UserOwnedStickyAncestorsAreNotPublicDropFolders)
{
    if (geteuid() == 0) { GTEST_SKIP() << "Root-owned sticky ancestors have a separate shared-folder policy"; }
    const auto outer = path.parent_path() / "outer";
    path = outer / "private" / "trusted.txt";
    PeerTrustStore::approve(path, peer(1));
    ASSERT_EQ(0, chmod(outer.c_str(), 01777));
    auto repair = barrier::finally([&] { chmod(outer.c_str(), 0700); });
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
}
#endif
#ifdef BARRIER_TEST_WRAP_PEER_IO
TEST_F(PeerTrustStoreTests, IntermediateLinkOwnedByAnotherUserIsRefused)
{
    const auto root = path.parent_path();
    barrier::fs::create_directory(root / "real");
    barrier::fs::create_directory_symlink("real", root / "link");
    path = root / "link" / "private" / "trusted.txt";
    foreign_link = true;
    EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
    EXPECT_FALSE(foreign_link);
    foreign_link = true;
    EXPECT_THROW(PeerTrustStore::approve(path, peer(1)), std::runtime_error);
    EXPECT_FALSE(foreign_link);
    EXPECT_FALSE(barrier::fs::exists(root / "real" / "private"));
}
TEST_F(PeerTrustStoreTests, FailedAncestorCreationDoesNotLeaveAnApprovalOrLock)
{
    path = path.parent_path() / "missing" / "private" / "trusted.txt";
    fail_mkdir = true;
    EXPECT_THROW(PeerTrustStore::approve(path, peer(1)), std::runtime_error);
    EXPECT_FALSE(fail_mkdir);
    EXPECT_FALSE(barrier::fs::exists(path.parent_path().parent_path()));
}
TEST_F(PeerTrustStoreTests, ReplacementBetweenAncestorInspectionAndOpenCannotFollowALink)
{
    const auto root = path.parent_path();
    const auto outer = root / "outer";
    path = outer / "private" / "trusted.txt";
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    barrier::fs::create_directory(root / "victim");
    open_hook = [&](int, const char* name, int flags) {
        if (std::string(name) != "outer" || !(flags & O_DIRECTORY)) { return; }
        open_hook = {};
        barrier::fs::rename(outer, root / "moved");
        barrier::fs::create_directory_symlink(root / "victim", outer);
    };
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_FALSE(open_hook);
    EXPECT_TRUE(barrier::fs::is_empty(root / "victim"));
    path = root / "moved" / "private" / "trusted.txt";
    EXPECT_EQ(original, bytes());
}
TEST_F(PeerTrustStoreTests, EarlierAncestorChangedBeforePublicationPreservesTheOldStore)
{
    const auto outer = path.parent_path() / "outer";
    path = outer / "private" / "trusted.txt";
    PeerTrustStore::approve(path, peer(1));
    const auto original = bytes();
    auto repair = barrier::finally([&] { chmod(outer.c_str(), 0700); });
    sync_hook = [&] { EXPECT_EQ(0, chmod(outer.c_str(), 0777)); };
    EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    EXPECT_EQ(original, bytes());
    EXPECT_EQ(1, std::distance(barrier::fs::directory_iterator(path.parent_path()), barrier::fs::directory_iterator()));
}
#endif

#ifdef BARRIER_TEST_WRAP_PEER_IO
TEST_F(PeerTrustStoreTests, RejectedAncestorWalksReleaseEveryDirectoryDescriptor)
{
    const barrier::fs::path descriptors("/proc/self/fd");
    if (!barrier::fs::is_directory(descriptors)) { GTEST_SKIP() << "Descriptor inventory is unavailable"; }
    const auto outer = path.parent_path() / "outer";
    path = outer / "private" / "trusted.txt";
    PeerTrustStore::approve(path, peer(1));
    ASSERT_EQ(0, chmod(outer.c_str(), 0777));
    auto repair = barrier::finally([&] { chmod(outer.c_str(), 0700); });
    const auto count = [&] {
        return std::distance(barrier::fs::directory_iterator(descriptors), barrier::fs::directory_iterator());
    };
    const auto before = count();
    for (int i = 0; i < 128; ++i) {
        EXPECT_THROW(PeerTrustStore::read(path), std::runtime_error);
        EXPECT_THROW(PeerTrustStore::approve(path, peer(2)), std::runtime_error);
    }
    EXPECT_EQ(before, count());
}
#endif
