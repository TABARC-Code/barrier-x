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
#endif
