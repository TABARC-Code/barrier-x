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
#include <fstream>
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
thread_local int observed_mode = -1;
thread_local int observed_descriptor_flags = -1;
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
        fail_publication = false;
#endif
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
