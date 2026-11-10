/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2026 barrier-x contributors
 *
 * This package is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License found in LICENSE.
 * This package is distributed WITHOUT ANY WARRANTY; see LICENSE for details.
 */

#include "net/SecureUtils.h"
#include "io/filesystem.h"
#include "base/finally.h"
#include "test/global/gtest.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <stdexcept>

#if SYSAPI_UNIX
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#ifdef BARRIER_TEST_WRAP_CERTIFICATE_IO
#include <cerrno>
namespace {
thread_local bool fail_key_generation = false;
thread_local bool fail_certificate_write = false;
thread_local bool fail_flush = false;
thread_local bool fail_sync = false;
thread_local bool fail_publication = false;
thread_local bool fail_mode_change = false;
thread_local bool fail_file_stat = false;
thread_local bool foreign_owner = false;
thread_local std::function<void()> file_stat_hook;
thread_local int read_descriptor = -1;
thread_local int read_descriptor_flags = -1;
thread_local std::string swapped_path, replacement_path, displaced_path;
thread_local int observed_mode = -1;
thread_local int observed_descriptor_flags = -1;
}

extern "C" int __real_fstat(int, struct stat*);
extern "C" int __wrap_fstat(int descriptor, struct stat* info)
{
    const int result = __real_fstat(descriptor, info);
    if (result == 0 && S_ISREG(info->st_mode)) {
        read_descriptor = descriptor;
        if (fail_file_stat) { fail_file_stat = false; errno = EIO; return -1; }
        if (foreign_owner) { foreign_owner = false; info->st_uid = geteuid() + 1; }
        if (file_stat_hook) { auto hook = std::move(file_stat_hook); file_stat_hook = {}; hook(); }
    }
    return result;
}
extern "C" int __real_fchmod(int, mode_t);
extern "C" int __real_rename(const char*, const char*);
extern "C" int __wrap_fchmod(int descriptor, mode_t mode)
{
    read_descriptor_flags = fcntl(descriptor, F_GETFD);
    if (fail_mode_change) {
        fail_mode_change = false;
        errno = EACCES;
        return -1;
    }
    if (!swapped_path.empty()) {
        auto path = std::move(swapped_path);
        swapped_path.clear();
        if (__real_rename(path.c_str(), displaced_path.c_str()) != 0 ||
            __real_rename(replacement_path.c_str(), path.c_str()) != 0) { return -1; }
    }
    return __real_fchmod(descriptor, mode);
}

extern "C" int __real_EVP_PKEY_keygen(EVP_PKEY_CTX*, EVP_PKEY**);
extern "C" int __wrap_EVP_PKEY_keygen(EVP_PKEY_CTX* context, EVP_PKEY** key)
{
    if (fail_key_generation) {
        fail_key_generation = false;
        return 0;
    }
    return __real_EVP_PKEY_keygen(context, key);
}

extern "C" int __real_PEM_write_X509(FILE*, const X509*);
extern "C" int __wrap_PEM_write_X509(FILE* file, const X509* certificate)
{
    struct stat info{};
    if (fstat(fileno(file), &info) == 0) {
        observed_mode = info.st_mode & 0777;
        observed_descriptor_flags = fcntl(fileno(file), F_GETFD);
    }
    if (fail_certificate_write) {
        fail_certificate_write = false;
        return 0;
    }
    return __real_PEM_write_X509(file, certificate);
}

extern "C" int __real_fflush(FILE*);
extern "C" int __wrap_fflush(FILE* file)
{
    if (fail_flush && file && file != stdout && file != stderr) {
        fail_flush = false;
        errno = EIO;
        return EOF;
    }
    return __real_fflush(file);
}

extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int descriptor)
{
    if (fail_sync) {
        fail_sync = false;
        errno = EIO;
        return -1;
    }
    return __real_fsync(descriptor);
}

extern "C" int __real_rename(const char*, const char*);
extern "C" int __wrap_rename(const char* from, const char* to)
{
    if (fail_publication) {
        fail_publication = false;
        errno = EACCES;
        return -1;
    }
    return __real_rename(from, to);
}
#endif

class CertificateStorageTests : public ::testing::Test {
protected:
    void SetUp() override
    {
        unsigned char random[16];
        ASSERT_EQ(1, RAND_bytes(random, sizeof(random)));
        static const char digits[] = "0123456789abcdef";
        std::string suffix;
        for (unsigned char byte : random) {
            suffix += digits[byte >> 4];
            suffix += digits[byte & 15];
        }
        directory = barrier::fs::temp_directory_path() / ("barrier-cert-test-" + suffix);
        ASSERT_TRUE(barrier::fs::create_directory(directory));
        barrier::fs::permissions(directory, barrier::fs::perms::owner_all);
        target = directory / "identity.pem";
    }

    void TearDown() override
    {
#ifdef BARRIER_TEST_WRAP_CERTIFICATE_IO
        fail_key_generation = fail_certificate_write = fail_flush = fail_sync = false;
        fail_publication = fail_mode_change = fail_file_stat = foreign_owner = false;
        swapped_path.clear();
        replacement_path.clear();
        displaced_path.clear();
        file_stat_hook = {};
#endif
        ERR_clear_error();
        if (!directory.empty()) {
            std::error_code ignored;
            barrier::fs::remove_all(directory, ignored);
        }
    }

    void writeOriginal()
    {
        std::ofstream file;
        barrier::open_utf8_path(file, target);
        file << "original identity";
        ASSERT_TRUE(file.good());
    }

    std::string read(const barrier::fs::path& path)
    {
        std::ifstream file;
        barrier::open_utf8_path(file, path);
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }

    void expectNoTemporaryFiles()
    {
        for (const auto& entry : barrier::fs::directory_iterator(directory)) {
            EXPECT_EQ(std::string::npos, entry.path().filename().u8string().find(".tmp."));
        }
    }

    barrier::fs::path directory;
    barrier::fs::path target;
};

TEST_F(CertificateStorageTests, GeneratesMatchingKeyAndSignedCertificate)
{
    barrier::generate_pem_self_signed_cert(target.u8string());
    auto* file = barrier::fopen_utf8_path(target, "r");
    ASSERT_NE(nullptr, file);
    auto close_file = barrier::finally([&]() { std::fclose(file); });
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
                PEM_read_PrivateKey(file, nullptr, nullptr, nullptr), EVP_PKEY_free);
    ASSERT_NE(nullptr, key);
    EXPECT_GE(EVP_PKEY_bits(key.get()), 3072);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(
                PEM_read_X509(file, nullptr, nullptr, nullptr), X509_free);
    ASSERT_NE(nullptr, certificate);
    EXPECT_EQ(1, X509_check_private_key(certificate.get(), key.get()));
    EXPECT_EQ(1, X509_verify(certificate.get(), key.get()));
    EXPECT_EQ(NID_sha256WithRSAEncryption, X509_get_signature_nid(certificate.get()));
    EXPECT_TRUE(barrier::get_pem_file_cert_fingerprint(target.u8string(),
                                                     barrier::SHA256).valid());
    expectNoTemporaryFiles();
}

TEST_F(CertificateStorageTests, ReplacesExistingFileWithCompleteIdentity)
{
    writeOriginal();
    barrier::generate_pem_self_signed_cert(target.u8string());
    EXPECT_TRUE(read(target) != "original identity");
    EXPECT_TRUE(barrier::get_pem_file_cert_fingerprint(target.u8string(),
                                                     barrier::SHA256).valid());
    expectNoTemporaryFiles();
}

TEST_F(CertificateStorageTests, SupportsUnicodePath)
{
    target = directory / barrier::fs::u8path("cl\xc3\xa9.pem");
    barrier::generate_pem_self_signed_cert(target.u8string());
    EXPECT_TRUE(barrier::get_pem_file_cert_fingerprint(target.u8string(),
                                                     barrier::SHA256).valid());
    auto identity = barrier::read_pem_identity(target.u8string());
    EXPECT_EQ(1, X509_check_private_key(identity.certificate.get(), identity.private_key.get()));
}

TEST_F(CertificateStorageTests, FailedPublicationPreservesDirectory)
{
    barrier::fs::create_directory(target);
    EXPECT_THROW(barrier::generate_pem_self_signed_cert(target.u8string()), std::exception);
    EXPECT_TRUE(barrier::fs::is_directory(target));
    expectNoTemporaryFiles();
}

#if SYSAPI_UNIX
TEST_F(CertificateStorageTests, PrivateFileWithPermissiveUmask)
{
    mode_t previous = umask(0);
    auto restore = barrier::finally([&]() { umask(previous); });
    barrier::generate_pem_self_signed_cert(target.u8string());
    struct stat info{};
    ASSERT_EQ(0, stat(target.c_str(), &info));
    EXPECT_EQ(0600, info.st_mode & 0777);
#ifdef BARRIER_TEST_WRAP_CERTIFICATE_IO
    EXPECT_EQ(0600, observed_mode);
    EXPECT_NE(0, observed_descriptor_flags & FD_CLOEXEC);
#endif
}

TEST_F(CertificateStorageTests, RefusesSymlinkWithoutChangingVictim)
{
    auto victim = directory / "victim";
    { std::ofstream file(victim.c_str()); file << "leave this alone"; }
    barrier::fs::create_symlink(victim, target);
    EXPECT_THROW(barrier::generate_pem_self_signed_cert(target.u8string()), std::exception);
    EXPECT_EQ("leave this alone", read(victim));
    EXPECT_TRUE(barrier::fs::is_symlink(target));
    expectNoTemporaryFiles();
}

TEST_F(CertificateStorageTests, ReplacingHardlinkDoesNotChangeOtherName)
{
    auto victim = directory / "victim";
    { std::ofstream file(victim.c_str()); file << "leave this alone"; }
    barrier::fs::create_hard_link(victim, target);
    barrier::generate_pem_self_signed_cert(target.u8string());
    EXPECT_EQ("leave this alone", read(victim));
    EXPECT_TRUE(read(victim) != read(target));
}
#endif

#ifdef BARRIER_TEST_WRAP_CERTIFICATE_IO
TEST_F(CertificateStorageTests, KeyGenerationFailurePreservesExistingFile)
{
    writeOriginal();
    fail_key_generation = true;
    EXPECT_THROW(barrier::generate_pem_self_signed_cert(target.u8string()), std::runtime_error);
    EXPECT_FALSE(fail_key_generation);
    EXPECT_TRUE(read(target) == "original identity");
    expectNoTemporaryFiles();
}

TEST_F(CertificateStorageTests, CertificateWriteFailurePreservesExistingFile)
{
    writeOriginal();
    fail_certificate_write = true;
    EXPECT_THROW(barrier::generate_pem_self_signed_cert(target.u8string()), std::runtime_error);
    EXPECT_FALSE(fail_certificate_write);
    EXPECT_TRUE(read(target) == "original identity");
    expectNoTemporaryFiles();
}

TEST_F(CertificateStorageTests, FlushFailurePreservesExistingFile)
{
    writeOriginal();
    fail_flush = true;
    EXPECT_THROW(barrier::generate_pem_self_signed_cert(target.u8string()), std::runtime_error);
    EXPECT_FALSE(fail_flush);
    EXPECT_TRUE(read(target) == "original identity");
    expectNoTemporaryFiles();
}

TEST_F(CertificateStorageTests, SyncFailurePreservesExistingFile)
{
    writeOriginal();
    fail_sync = true;
    EXPECT_THROW(barrier::generate_pem_self_signed_cert(target.u8string()), std::runtime_error);
    EXPECT_FALSE(fail_sync);
    EXPECT_TRUE(read(target) == "original identity");
    expectNoTemporaryFiles();
}

TEST_F(CertificateStorageTests, PublicationFailurePreservesExistingFile)
{
    writeOriginal();
    fail_publication = true;
    EXPECT_THROW(barrier::generate_pem_self_signed_cert(target.u8string()), std::exception);
    EXPECT_FALSE(fail_publication);
    EXPECT_TRUE(read(target) == "original identity");
    expectNoTemporaryFiles();
}
#endif

#if SYSAPI_UNIX
TEST_F(CertificateStorageTests, MigratesModeWithoutChangingIdentity)
{
    barrier::generate_pem_self_signed_cert(target.u8string());
    auto bytes = read(target);
    auto fingerprint = barrier::get_pem_file_cert_fingerprint(target.u8string(), barrier::SHA256);
    ASSERT_EQ(0, chmod(target.c_str(), 06777));
#ifdef BARRIER_TEST_WRAP_CERTIFICATE_IO
    read_descriptor_flags = -1;
#endif
    auto identity = barrier::read_pem_identity(target.u8string());
    EXPECT_EQ(fingerprint, barrier::get_ssl_cert_fingerprint(identity.certificate.get(), barrier::SHA256));
    EXPECT_EQ(1, X509_check_private_key(identity.certificate.get(), identity.private_key.get()));
    EXPECT_TRUE(bytes == read(target));
    struct stat info{};
    ASSERT_EQ(0, stat(target.c_str(), &info));
    EXPECT_EQ(0600, info.st_mode & 07777);
#ifdef BARRIER_TEST_WRAP_CERTIFICATE_IO
    ASSERT_NE(-1, read_descriptor_flags);
    EXPECT_NE(0, read_descriptor_flags & FD_CLOEXEC);
#endif
}

TEST_F(CertificateStorageTests, ReadingSymlinkDoesNotRestrictVictim)
{
    auto victim = directory / "victim";
    { std::ofstream file(victim.c_str()); file << "leave this alone"; }
    ASSERT_EQ(0, chmod(victim.c_str(), 0666));
    barrier::fs::create_symlink(victim, target);
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::exception);
    struct stat info{};
    ASSERT_EQ(0, stat(victim.c_str(), &info));
    EXPECT_EQ(0666, info.st_mode & 07777);
    EXPECT_EQ("leave this alone", read(victim));
}

TEST_F(CertificateStorageTests, ReadingHardlinkLeavesBothNamesAlone)
{
    writeOriginal();
    ASSERT_EQ(0, chmod(target.c_str(), 0666));
    auto other = directory / "other";
    barrier::fs::create_hard_link(target, other);
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::exception);
    struct stat info{};
    ASSERT_EQ(0, stat(other.c_str(), &info));
    EXPECT_EQ(0666, info.st_mode & 07777);
    EXPECT_EQ("original identity", read(other));
}

TEST_F(CertificateStorageTests, ReadingDirectoryIsRejected)
{
    barrier::fs::create_directory(target);
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::exception);
}

TEST_F(CertificateStorageTests, ReadingFifoDoesNotWaitForWriter)
{
    ASSERT_EQ(0, mkfifo(target.c_str(), 0600));
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::exception);
}

TEST_F(CertificateStorageTests, OversizedIdentityIsRejected)
{
    { std::ofstream file(target.c_str()); file << std::string(1024 * 1024 + 1, 'x'); }
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::exception);
}

TEST_F(CertificateStorageTests, CertificateWithoutPrivateKeyIsRejected)
{
    barrier::generate_pem_self_signed_cert(target.u8string());
    auto identity = barrier::read_pem_identity(target.u8string());
    FILE* file = fopen(target.c_str(), "wb");
    ASSERT_NE(nullptr, file);
    ASSERT_EQ(1, PEM_write_X509(file, identity.certificate.get()));
    ASSERT_EQ(0, fclose(file));
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::exception);
}

TEST_F(CertificateStorageTests, MismatchedPairKeepsInstalledIdentity)
{
    barrier::generate_pem_self_signed_cert(target.u8string());
    auto identity = barrier::read_pem_identity(target.u8string());
    auto other = directory / "second.pem";
    barrier::generate_pem_self_signed_cert(other.u8string());
    auto second = barrier::read_pem_identity(other.u8string());
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(SSLv23_method()), SSL_CTX_free);
    ASSERT_NE(nullptr, context);
    barrier::load_pem_identity(context.get(), target.u8string());
    FILE* file = fopen(target.c_str(), "wb");
    ASSERT_NE(nullptr, file);
    ASSERT_EQ(1, PEM_write_X509(file, identity.certificate.get()));
    ASSERT_EQ(1, PEM_write_PrivateKey(file, second.private_key.get(), nullptr, nullptr, 0, nullptr, nullptr));
    ASSERT_EQ(0, fclose(file));
    auto bytes = read(target);
    EXPECT_THROW(barrier::load_pem_identity(context.get(), target.u8string()), std::exception);
    EXPECT_TRUE(bytes == read(target));
    EXPECT_EQ(1, SSL_CTX_check_private_key(context.get()));
    EXPECT_EQ(barrier::get_ssl_cert_fingerprint(identity.certificate.get(), barrier::SHA256),
              barrier::get_ssl_cert_fingerprint(SSL_CTX_get0_certificate(context.get()), barrier::SHA256));
}

TEST_F(CertificateStorageTests, EncryptedIdentityDoesNotRequestTerminalInput)
{
    barrier::generate_pem_self_signed_cert(target.u8string());
    auto identity = barrier::read_pem_identity(target.u8string());
    FILE* file = fopen(target.c_str(), "wb");
    ASSERT_NE(nullptr, file);
    unsigned char password[] = "unit-test-passphrase";
    ASSERT_EQ(1, PEM_write_PrivateKey(file, identity.private_key.get(), EVP_aes_256_cbc(),
                                     password, sizeof(password) - 1, nullptr, nullptr));
    ASSERT_EQ(1, PEM_write_X509(file, identity.certificate.get()));
    ASSERT_EQ(0, fclose(file));
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::exception);
}
#endif

#ifdef BARRIER_TEST_WRAP_CERTIFICATE_IO
TEST_F(CertificateStorageTests, ModeChangeFailurePreservesBytesAndClosesDescriptor)
{
    writeOriginal();
    ASSERT_EQ(0, chmod(target.c_str(), 0666));
    fail_mode_change = true;
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::exception);
    EXPECT_FALSE(fail_mode_change);
    EXPECT_EQ(-1, fcntl(read_descriptor, F_GETFD));
    EXPECT_EQ("original identity", read(target));
    struct stat info{};
    ASSERT_EQ(0, stat(target.c_str(), &info));
    EXPECT_EQ(0666, info.st_mode & 07777);
}

TEST_F(CertificateStorageTests, ForeignOwnerIsRejectedBeforeModeChange)
{
    writeOriginal();
    ASSERT_EQ(0, chmod(target.c_str(), 0666));
    foreign_owner = true;
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::exception);
    EXPECT_FALSE(foreign_owner);
    struct stat info{};
    ASSERT_EQ(0, stat(target.c_str(), &info));
    EXPECT_EQ(0666, info.st_mode & 07777);
}

TEST_F(CertificateStorageTests, StatFailureClosesDescriptor)
{
    writeOriginal();
    fail_file_stat = true;
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::exception);
    EXPECT_FALSE(fail_file_stat);
    EXPECT_EQ(-1, fcntl(read_descriptor, F_GETFD));
    EXPECT_EQ("original identity", read(target));
}

TEST_F(CertificateStorageTests, PathReplacementDoesNotChangeLoadedPair)
{
    barrier::generate_pem_self_signed_cert(target.u8string());
    auto fingerprint = barrier::get_pem_file_cert_fingerprint(target.u8string(), barrier::SHA256);
    auto replacement = directory / "replacement.pem";
    barrier::generate_pem_self_signed_cert(replacement.u8string());
    auto replacement_bytes = read(replacement);
    ASSERT_EQ(0, chmod(target.c_str(), 0666));
    ASSERT_EQ(0, chmod(replacement.c_str(), 0666));
    displaced_path = (directory / "displaced.pem").u8string();
    replacement_path = replacement.u8string();
    swapped_path = target.u8string();
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(SSLv23_method()), SSL_CTX_free);
    ASSERT_NE(nullptr, context);
    barrier::load_pem_identity(context.get(), target.u8string());
    EXPECT_TRUE(swapped_path.empty());
    EXPECT_EQ(fingerprint, barrier::get_ssl_cert_fingerprint(SSL_CTX_get0_certificate(context.get()), barrier::SHA256));
    EXPECT_EQ(1, SSL_CTX_check_private_key(context.get()));
    EXPECT_TRUE(replacement_bytes == read(target));
    struct stat info{};
    ASSERT_EQ(0, stat(target.c_str(), &info));
    EXPECT_EQ(0666, info.st_mode & 07777);
    ASSERT_EQ(0, stat(displaced_path.c_str(), &info));
    EXPECT_EQ(0600, info.st_mode & 07777);
}
#endif

#if SYSAPI_UNIX
TEST_F(CertificateStorageTests, UnsafeAncestorIsRefusedBeforeIdentityPermissionsChange)
{
    const auto outer = directory / "outer";
    barrier::fs::create_directories(outer / "private");
    ASSERT_EQ(0, chmod(outer.c_str(), 0700));
    ASSERT_EQ(0, chmod((outer / "private").c_str(), 0700));
    target = outer / "private" / "identity.pem";
    barrier::generate_pem_self_signed_cert(target.u8string());
    const auto original = read(target);
    ASSERT_EQ(0, chmod(target.c_str(), 0666));
    ASSERT_EQ(0, chmod(outer.c_str(), 0777));
    auto repair = barrier::finally([&] { chmod(outer.c_str(), 0700); });
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::runtime_error);
    struct stat info{};
    ASSERT_EQ(0, stat(target.c_str(), &info));
    EXPECT_EQ(0666, info.st_mode & 07777);
    EXPECT_TRUE(original == read(target));
}
TEST_F(CertificateStorageTests, LinkedIdentityFolderIsRefusedBeforeTouchingItsFile)
{
    const auto real = directory / "real";
    barrier::fs::create_directory(real);
    const auto file = real / "identity.pem";
    barrier::generate_pem_self_signed_cert(file.u8string());
    const auto original = read(file);
    ASSERT_EQ(0, chmod(file.c_str(), 0666));
    barrier::fs::create_directory_symlink(real, directory / "link");
    EXPECT_THROW(barrier::read_pem_identity((directory / "link" / "identity.pem").u8string()), std::runtime_error);
    struct stat info{};
    ASSERT_EQ(0, stat(file.c_str(), &info));
    EXPECT_EQ(0666, info.st_mode & 07777);
    EXPECT_TRUE(original == read(file));
}
TEST_F(CertificateStorageTests, CheckedIntermediateLinkKeepsTheSameIdentity)
{
    const auto outer = directory / "outer";
    barrier::fs::create_directories(outer / "private");
    ASSERT_EQ(0, chmod(outer.c_str(), 0700));
    ASSERT_EQ(0, chmod((outer / "private").c_str(), 0700));
    const auto file = outer / "private" / "identity.pem";
    barrier::generate_pem_self_signed_cert(file.u8string());
    const auto expected = barrier::get_pem_file_cert_fingerprint(file.u8string(), barrier::SHA256);
    barrier::fs::create_directory_symlink("outer", directory / "alias");
    auto identity = barrier::read_pem_identity((directory / "alias" / "private" / "identity.pem").u8string());
    EXPECT_EQ(expected, barrier::get_ssl_cert_fingerprint(identity.certificate.get(), barrier::SHA256));
    EXPECT_EQ(1, X509_check_private_key(identity.certificate.get(), identity.private_key.get()));
}
TEST_F(CertificateStorageTests, IdentityParentTraversalAndEmbeddedNullAreRejected)
{
    barrier::generate_pem_self_signed_cert(target.u8string());
    const auto original = read(target);
    EXPECT_THROW(barrier::read_pem_identity(target.u8string() + std::string("\0ignored", 8)), std::runtime_error);
    EXPECT_THROW(barrier::read_pem_identity((directory / "missing" / ".." / target.filename()).u8string()), std::runtime_error);
    EXPECT_FALSE(barrier::fs::exists(directory / "missing"));
    EXPECT_TRUE(original == read(target));
}
TEST_F(CertificateStorageTests, MissingIdentityParentsAreNotCreatedByReading)
{
    const auto missing = directory / "missing" / "private" / "identity.pem";
    EXPECT_THROW(barrier::read_pem_identity(missing.u8string()), std::runtime_error);
    EXPECT_FALSE(barrier::fs::exists(directory / "missing"));
}
#endif
#ifdef BARRIER_TEST_WRAP_CERTIFICATE_IO
TEST_F(CertificateStorageTests, ReplacedParentCannotRedirectIdentityPermissionMigration)
{
    const auto outer = directory / "outer";
    barrier::fs::create_directories(outer / "private");
    ASSERT_EQ(0, chmod(outer.c_str(), 0700));
    ASSERT_EQ(0, chmod((outer / "private").c_str(), 0700));
    target = outer / "private" / "identity.pem";
    barrier::generate_pem_self_signed_cert(target.u8string());
    const auto original = read(target);
    ASSERT_EQ(0, chmod(target.c_str(), 0666));
    std::string replacement;
    file_stat_hook = [&] {
        barrier::fs::rename(outer, directory / "moved");
        barrier::fs::create_directories(outer / "private");
        EXPECT_EQ(0, chmod(outer.c_str(), 0700));
        EXPECT_EQ(0, chmod((outer / "private").c_str(), 0700));
        barrier::generate_pem_self_signed_cert(target.u8string());
        replacement = read(target);
        EXPECT_EQ(0, chmod(target.c_str(), 0666));
    };
    EXPECT_THROW(barrier::read_pem_identity(target.u8string()), std::runtime_error);
    EXPECT_FALSE(file_stat_hook);
    EXPECT_FALSE(replacement.empty());
    EXPECT_TRUE(replacement == read(target));
    EXPECT_TRUE(original == read(directory / "moved" / "private" / "identity.pem"));
    struct stat info{};
    ASSERT_EQ(0, stat(target.c_str(), &info));
    EXPECT_EQ(0666, info.st_mode & 07777);
    EXPECT_EQ(-1, fcntl(read_descriptor, F_GETFD));
}
#endif
