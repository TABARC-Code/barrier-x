/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "../src/SslCertificate.h"
#include "common/DataDirectories.h"
#include "net/FingerprintDatabase.h"
#include "net/SecureUtils.h"
#include <gtest/gtest.h>
#include <QTemporaryDir>
#include <QObject>
#include <fstream>
#include <iterator>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <memory>
#if SYSAPI_UNIX
#include <sys/stat.h>

class SslCertificateTests : public ::testing::Test {
protected:
    void SetUp() override
    {
        ASSERT_TRUE(temporary.isValid());
        previous = barrier::DataDirectories::profile();
        barrier::DataDirectories::profile(barrier::fs::u8path(temporary.path().toStdString()));
        path = barrier::DataDirectories::ssl_certificate_path();
        barrier::fs::create_directories(path.parent_path());
    }
    void TearDown() override { barrier::DataDirectories::profile(previous); }
    std::string read(const barrier::fs::path& file)
    {
        std::ifstream input(file.c_str());
        return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }
    void run()
    {
        SslCertificate certificate;
        QObject::connect(&certificate, &SslCertificate::generateFinished, [&] { ++finished; });
        QObject::connect(&certificate, &SslCertificate::error, [&](const QString&) { ++errors; });
        certificate.generateCertificate();
    }
    QTemporaryDir temporary;
    barrier::fs::path previous, path;
    int finished = 0, errors = 0;
};

TEST_F(SslCertificateTests, MigratesExistingIdentityAndKeepsItsFingerprint)
{
    barrier::generate_pem_self_signed_cert(path.u8string());
    const auto bytes = read(path);
    const auto fingerprint = barrier::get_pem_file_cert_fingerprint(path.u8string(), barrier::SHA256);
    ASSERT_EQ(0, chmod(path.c_str(), 0666));
    run();
    EXPECT_EQ(1, finished);
    EXPECT_EQ(0, errors);
    EXPECT_TRUE(bytes == read(path));
    struct stat info{};
    ASSERT_EQ(0, stat(path.c_str(), &info));
    EXPECT_EQ(0600, info.st_mode & 07777);
    barrier::FingerprintDatabase database;
    database.read(barrier::DataDirectories::local_ssl_fingerprints_path());
    EXPECT_TRUE(database.is_trusted(fingerprint));
}

TEST_F(SslCertificateTests, RejectsMalformedIdentityWithoutReplacingIt)
{
    { std::ofstream output(path.c_str()); output << "existing malformed identity"; }
    run();
    EXPECT_EQ(0, finished);
    EXPECT_EQ(1, errors);
    EXPECT_EQ("existing malformed identity", read(path));
    EXPECT_FALSE(barrier::fs::exists(barrier::DataDirectories::local_ssl_fingerprints_path()));
}

TEST_F(SslCertificateTests, RefusesSymlinkWithoutChangingTheVictim)
{
    const auto victim = path.parent_path() / "victim.pem";
    barrier::generate_pem_self_signed_cert(victim.u8string());
    ASSERT_EQ(0, chmod(victim.c_str(), 0644));
    const auto bytes = read(victim);
    barrier::fs::create_symlink(victim, path);
    run();
    EXPECT_EQ(0, finished);
    EXPECT_EQ(1, errors);
    EXPECT_TRUE(barrier::fs::is_symlink(path));
    EXPECT_TRUE(bytes == read(victim));
    struct stat info{};
    ASSERT_EQ(0, stat(victim.c_str(), &info));
    EXPECT_EQ(0644, info.st_mode & 07777);
}

TEST_F(SslCertificateTests, PublicFingerprintWriteFailureIsReportedAndCanBeRetried)
{
    barrier::generate_pem_self_signed_cert(path.u8string());
    const auto bytes = read(path);
    const auto publicPath = barrier::DataDirectories::local_ssl_fingerprints_path();
    barrier::fs::create_directories(publicPath);
    { std::ofstream marker((publicPath / "keep").c_str()); marker << "existing directory"; }
    run();
    EXPECT_EQ(0, finished);
    EXPECT_EQ(1, errors);
    EXPECT_TRUE(bytes == read(path));
    EXPECT_EQ("existing directory", read(publicPath / "keep"));
    barrier::fs::remove(publicPath / "keep");
    barrier::fs::remove(publicPath);
    run();
    EXPECT_EQ(1, finished);
    EXPECT_EQ(1, errors);
    EXPECT_TRUE(bytes == read(path));
    barrier::FingerprintDatabase database;
    database.read(publicPath);
    EXPECT_TRUE(database.is_trusted(barrier::get_pem_file_cert_fingerprint(path.u8string(), barrier::SHA256)));
}
TEST_F(SslCertificateTests, WeakExistingIdentityIsReportedWithoutReplacingIt)
{
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> generator(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    ASSERT_NE(nullptr, generator);
    ASSERT_EQ(1, EVP_PKEY_keygen_init(generator.get()));
    ASSERT_EQ(1, EVP_PKEY_CTX_set_rsa_keygen_bits(generator.get(), 1024));
    EVP_PKEY* raw = nullptr;
    ASSERT_EQ(1, EVP_PKEY_keygen(generator.get(), &raw));
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw, EVP_PKEY_free);
    std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
    ASSERT_NE(nullptr, cert);
    ASSERT_EQ(1, X509_set_version(cert.get(), 2));
    ASSERT_EQ(1, ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1));
    ASSERT_NE(nullptr, X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0));
    ASSERT_NE(nullptr, X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600));
    ASSERT_EQ(1, X509_set_pubkey(cert.get(), key.get()));
    ASSERT_GT(X509_sign(cert.get(), key.get(), EVP_sha256()), 0);
    std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new_file(path.c_str(), "w"), BIO_free);
    ASSERT_NE(nullptr, output);
    ASSERT_EQ(1, PEM_write_bio_PrivateKey(output.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr));
    ASSERT_EQ(1, PEM_write_bio_X509(output.get(), cert.get()));
    output.reset();
    ASSERT_NO_THROW(barrier::read_pem_identity(path.u8string()));
    const auto bytes = read(path);
    run();
    EXPECT_EQ(0, finished);
    EXPECT_EQ(1, errors);
    EXPECT_TRUE(bytes == read(path));
}

TEST_F(SslCertificateTests, PublicFingerprintSymlinkCannotReplaceTheIdentity)
{
    barrier::generate_pem_self_signed_cert(path.u8string());
    const auto bytes = read(path);
    const auto publicPath = barrier::DataDirectories::local_ssl_fingerprints_path();
    barrier::fs::create_directories(publicPath.parent_path());
    barrier::fs::create_symlink(path, publicPath);
    run();
    EXPECT_EQ(0, finished);
    EXPECT_EQ(1, errors);
    EXPECT_TRUE(bytes == read(path));
    EXPECT_TRUE(barrier::fs::is_symlink(publicPath));
}
#endif
