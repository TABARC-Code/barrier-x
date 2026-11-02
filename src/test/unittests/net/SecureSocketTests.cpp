/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2026 barrier-x contributors
 *
 * This package is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License found in LICENSE.
 * This package is distributed WITHOUT ANY WARRANTY; see LICENSE for details.
 */

#include "net/SecureSocket.h"
#include "net/TCPSocketFactory.h"
#include "net/SecureUtils.h"
#include "net/FingerprintDatabase.h"
#include "common/DataDirectories.h"
#include "net/SocketMultiplexer.h"
#include "base/EventQueue.h"
#include "test/global/gtest.h"

#include <memory>
#include <cstdlib>

#ifdef BARRIER_TEST_WRAP_SSL_CONTEXT
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

namespace {
thread_local bool complete_handshake = false;
thread_local bool fake_io = false;
thread_local int io_calls = 0;
thread_local int io_result = 2;
thread_local int io_error = -1;
thread_local bool dirty_io_error_queue = false;
thread_local bool override_peer = false;
thread_local X509* peer_certificate = nullptr;
thread_local SecureSocket* observed_socket = nullptr;
thread_local bool ready_during_verification = false;
thread_local int peer_releases = 0;
thread_local int digest_calls = 0;
thread_local int fail_digest_call = 0;
thread_local bool fail_next_context = false;
thread_local bool fail_next_session = false;
thread_local bool fake_transport = false;
thread_local bool fail_attachment = false;
thread_local int attachment_calls = 0;
thread_local int handshake_calls = 0;
thread_local SSL* last_session = nullptr;
thread_local SSL_CTX* last_created_context = nullptr;
}

// Linker wrapping keeps allocation failure tests out of the production API.
extern "C" SSL_CTX* __real_SSL_CTX_new(const SSL_METHOD* method);
extern "C" SSL_CTX* __wrap_SSL_CTX_new(const SSL_METHOD* method)
{
    if (fail_next_context) {
        fail_next_context = false;
        return nullptr;
    }
    last_created_context = __real_SSL_CTX_new(method);
    return last_created_context;
}
extern "C" SSL* __real_SSL_new(SSL_CTX* context);
extern "C" SSL* __wrap_SSL_new(SSL_CTX* context)
{
    if (fail_next_session) {
        fail_next_session = false;
        return nullptr;
    }
    last_session = __real_SSL_new(context);
    return last_session;
}

extern "C" int __real_SSL_set_fd(SSL* ssl, int fd);
extern "C" int __wrap_SSL_set_fd(SSL* ssl, int fd)
{
    ++attachment_calls;
    if (fake_transport) {
        if (fail_attachment) {
            return 0;
        }
        BIO* transport = BIO_new(BIO_s_mem());
        if (!transport) {
            return 0;
        }
        SSL_set_bio(ssl, transport, transport);
        return 1;
    }
    return __real_SSL_set_fd(ssl, fd);
}

extern "C" int __real_SSL_connect(SSL* ssl);
extern "C" int __real_SSL_accept(SSL* ssl);
extern "C" int __wrap_SSL_connect(SSL* ssl)
{
    ++handshake_calls;
    return fake_transport ? (complete_handshake ? 1 : -1) : __real_SSL_connect(ssl);
}
extern "C" int __wrap_SSL_accept(SSL* ssl)
{
    ++handshake_calls;
    return fake_transport ? (complete_handshake ? 1 : -1) : __real_SSL_accept(ssl);
}
extern "C" int __real_SSL_read(SSL*, void*, int);
extern "C" int __real_SSL_write(SSL*, const void*, int);
extern "C" int __wrap_SSL_read(SSL* ssl, void* buffer, int size)
{
    ++io_calls;
    if (fake_io && ERR_peek_error() != 0) {
        dirty_io_error_queue = true;
    }
    return fake_io ? io_result : __real_SSL_read(ssl, buffer, size);
}
extern "C" int __wrap_SSL_write(SSL* ssl, const void* buffer, int size)
{
    ++io_calls;
    if (fake_io && ERR_peek_error() != 0) {
        dirty_io_error_queue = true;
    }
    return fake_io ? io_result : __real_SSL_write(ssl, buffer, size);
}

extern "C" int __real_SSL_get_error(const SSL* ssl, int result);
extern "C" int __wrap_SSL_get_error(const SSL* ssl, int result)
{
    if (fake_io && io_error >= 0) {
        return io_error;
    }
    return fake_transport ? (complete_handshake ? SSL_ERROR_NONE : SSL_ERROR_WANT_READ) :
                            __real_SSL_get_error(ssl, result);
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
extern "C" X509* __real_SSL_get1_peer_certificate(const SSL*);
extern "C" X509* __wrap_SSL_get1_peer_certificate(const SSL* ssl)
#else
extern "C" X509* __real_SSL_get_peer_certificate(const SSL*);
extern "C" X509* __wrap_SSL_get_peer_certificate(const SSL* ssl)
#endif
{
    if (override_peer) {
        if (observed_socket && observed_socket->isSecureReady()) {
            ready_during_verification = true;
        }
        if (peer_certificate) {
            X509_up_ref(peer_certificate);
        }
        return peer_certificate;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return __real_SSL_get1_peer_certificate(ssl);
#else
    return __real_SSL_get_peer_certificate(ssl);
#endif
}
extern "C" void __real_X509_free(X509*);
extern "C" void __wrap_X509_free(X509* certificate)
{
    if (certificate && certificate == peer_certificate) {
        ++peer_releases;
    }
    __real_X509_free(certificate);
}
extern "C" int __real_X509_digest(const X509*, const EVP_MD*, unsigned char*, unsigned int*);
extern "C" int __wrap_X509_digest(const X509* certificate, const EVP_MD* algorithm,
                                  unsigned char* digest, unsigned int* length)
{
    if (certificate && certificate == peer_certificate && ++digest_calls == fail_digest_call) {
        return 0;
    }
    return __real_X509_digest(certificate, algorithm, digest, length);
}

#endif

class SecureSocketTests : public ::testing::Test {
protected:
    std::unique_ptr<SecureSocket> socket(
            ConnectionSecurityLevel security = ConnectionSecurityLevel::ENCRYPTED)
    {
        return std::make_unique<SecureSocket>(&events, &multiplexer, IArchNetwork::kINET,
                                              security);
    }

    void rejectedIo(SecureSocket& connection)
    {
        char buffer[4] = {};
        int count = 99;
        EXPECT_EQ(-1, connection.secureRead(buffer, sizeof(buffer), count));
        EXPECT_EQ(0, count);
        count = 99;
        EXPECT_EQ(-1, connection.secureWrite(buffer, sizeof(buffer), count));
        EXPECT_EQ(0, count);
    }

    EventQueue events;
    SocketMultiplexer multiplexer;

#ifdef BARRIER_TEST_WRAP_SSL_CONTEXT
    void checkHandshake(int version, bool expected);
    int handshake(SecureSocket& connection, bool server, int descriptor = -1)
    {
        return server ? connection.secureAccept(descriptor) : connection.secureConnect(descriptor);
    }
    barrier::fs::path peer_directory;
    barrier::fs::path saved_profile;
    std::unique_ptr<X509, decltype(&X509_free)> owned_peer{nullptr, X509_free};
    void preparePeer(bool server, bool trusted, barrier::FingerprintType type = barrier::FingerprintType::SHA256)
    {
        saved_profile = barrier::DataDirectories::profile();
        char directory[] = "/tmp/barrier-peer-XXXXXX";
        auto* created = ::mkdtemp(directory);
        ASSERT_NE(nullptr, created);
        peer_directory = created;
        barrier::DataDirectories::profile(peer_directory);
        barrier::fs::create_directories(barrier::DataDirectories::ssl_fingerprints_path());
        auto pem = barrier::DataDirectories::ssl_certificate_path();
        barrier::generate_pem_self_signed_cert(pem);
        auto close_file = [](FILE* file) { fclose(file); };
        std::unique_ptr<FILE, decltype(close_file)> file(fopen(pem.c_str(), "rb"), close_file);
        ASSERT_NE(nullptr, file);
        owned_peer.reset(PEM_read_X509(file.get(), nullptr, nullptr, nullptr));
        ASSERT_NE(nullptr, owned_peer);
        if (trusted) {
            barrier::FingerprintDatabase database;
            database.add_trusted(barrier::get_ssl_cert_fingerprint(owned_peer.get(), type));
            database.write(server ? barrier::DataDirectories::trusted_clients_ssl_fingerprints_path() :
                                    barrier::DataDirectories::trusted_servers_ssl_fingerprints_path());
        }
        peer_certificate = owned_peer.get();
        override_peer = fake_transport = complete_handshake = true;
    }
    void SetUp() override
    {
        fake_io = false;
        io_calls = 0;
        io_result = 2;
        io_error = -1;
        dirty_io_error_queue = false;
        complete_handshake = override_peer = ready_during_verification = false;
        peer_certificate = nullptr;
        observed_socket = nullptr;
        peer_releases = digest_calls = fail_digest_call = 0;
        fail_next_session = false;
        fake_transport = false;
        fail_attachment = false;
        attachment_calls = handshake_calls = 0;
        last_session = nullptr;
    }
    void TearDown() override
    {
        fake_io = false;
        fail_next_session = fake_transport = fail_attachment = false;
        override_peer = complete_handshake = false;
        peer_certificate = nullptr;
        observed_socket = nullptr;
        owned_peer.reset();
        if (!peer_directory.empty()) {
            barrier::DataDirectories::profile(saved_profile);
            std::error_code ignored;
            barrier::fs::remove_all(peer_directory, ignored);
        }
        ERR_clear_error();
    }
#endif
};

TEST_F(SecureSocketTests, IoBeforeInitialisationFailsWithZeroCount)
{
    auto connection = socket();
    rejectedIo(*connection);
}

TEST_F(SecureSocketTests, IoWithoutSessionFailsWithZeroCount)
{
    auto connection = socket();
    connection->initSsl(false);
    rejectedIo(*connection);
}

TEST_F(SecureSocketTests, IoAfterCloseFailsWithZeroCount)
{
    auto connection = socket();
    connection->initSsl(false);
    connection->close();
    rejectedIo(*connection);
}

#ifdef BARRIER_TEST_WRAP_SSL_CONTEXT
TEST_F(SecureSocketTests, LoadingLegacyIdentityRestrictsItsMode)
{
    preparePeer(false, true);
    const auto path = barrier::DataDirectories::ssl_certificate_path();
    ASSERT_EQ(0, chmod(path.c_str(), 0666));
    auto connection = socket();
    connection->initSsl(false);
    ASSERT_TRUE(connection->load_certificates(path));
    struct stat info{};
    ASSERT_EQ(0, stat(path.c_str(), &info));
    EXPECT_EQ(0600, info.st_mode & 07777);
}

TEST_F(SecureSocketTests, FailedIdentityLoadClearsHandledCryptoErrors)
{
    preparePeer(false, true);
    const auto path = barrier::DataDirectories::ssl_certificate_path();
    auto identity = barrier::read_pem_identity(path.u8string());
    FILE* file = fopen(path.c_str(), "wb");
    ASSERT_NE(nullptr, file);
    unsigned char password[] = "unit-test-passphrase";
    ASSERT_EQ(1, PEM_write_PrivateKey(file, identity.private_key.get(), EVP_aes_256_cbc(),
                                     password, sizeof(password) - 1, nullptr, nullptr));
    ASSERT_EQ(1, PEM_write_X509(file, identity.certificate.get()));
    ASSERT_EQ(0, fclose(file));
    auto connection = socket();
    connection->initSsl(false);
    EXPECT_FALSE(connection->load_certificates(path));
    EXPECT_EQ(0u, ERR_peek_error());
}

TEST_F(SecureSocketTests, LoadingIdentityRefusesSymlink)
{
    preparePeer(false, true);
    const auto path = barrier::DataDirectories::ssl_certificate_path();
    const auto original = path.u8string() + ".original";
    barrier::fs::rename(path, original);
    barrier::fs::create_symlink(original, path);
    auto connection = socket();
    connection->initSsl(false);
    EXPECT_FALSE(connection->load_certificates(path));
}

TEST_F(SecureSocketTests, UnapprovedSessionNeverEntersApplicationIo)
{
    fake_transport = fake_io = true;
    auto connection = socket();
    connection->initSsl(false);
    EXPECT_EQ(0, handshake(*connection, false));
    rejectedIo(*connection);
    EXPECT_EQ(0, io_calls);
}

TEST_F(SecureSocketTests, ApprovedSessionReportsOnlyTransferredBytes)
{
    preparePeer(false, true);
    auto connection = socket();
    connection->initSsl(false);
    ASSERT_EQ(1, handshake(*connection, false));
    fake_io = true;
    char buffer[4] = {};
    int count = 99;
    ERR_put_error(ERR_LIB_SSL, 0, 1, __FILE__, __LINE__);
    EXPECT_EQ(2, connection->secureRead(buffer, sizeof(buffer), count));
    EXPECT_EQ(2, count);
    ERR_put_error(ERR_LIB_SSL, 0, 1, __FILE__, __LINE__);
    EXPECT_EQ(2, connection->secureWrite(buffer, sizeof(buffer), count));
    EXPECT_EQ(2, count);
    EXPECT_EQ(2, io_calls);
    EXPECT_FALSE(dirty_io_error_queue);

    // A retry transfers no application bytes; the caller retains the buffer.
    io_result = -1;
    for (int error : {SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE}) {
        io_error = error;
        count = 99;
        EXPECT_EQ(0, connection->secureRead(buffer, sizeof(buffer), count));
        EXPECT_EQ(0, count);
        count = 99;
        EXPECT_EQ(0, connection->secureWrite(buffer, sizeof(buffer), count));
        EXPECT_EQ(0, count);
    }
    io_error = SSL_ERROR_NONE;
    io_result = 2;
    EXPECT_EQ(2, connection->secureRead(buffer, sizeof(buffer), count));
    EXPECT_EQ(2, count);
    EXPECT_EQ(2, connection->secureWrite(buffer, sizeof(buffer), count));
    EXPECT_EQ(2, count);
    connection->isFatal(true);
    int before = io_calls;
    rejectedIo(*connection);
    EXPECT_EQ(before, io_calls);
}

TEST_F(SecureSocketTests, FatalIoClearsReadinessAndReportsZeroBytes)
{
    preparePeer(false, true);
    for (bool writing : {false, true}) {
        fake_io = false;
        auto connection = socket();
        connection->initSsl(false);
        ASSERT_EQ(1, handshake(*connection, false));
        fake_io = true;
        io_result = -1;
        io_error = SSL_ERROR_SSL;
        char buffer[4] = {};
        int count = 99;
        EXPECT_EQ(-1, writing ? connection->secureWrite(buffer, sizeof(buffer), count) :
                                connection->secureRead(buffer, sizeof(buffer), count));
        EXPECT_EQ(0, count);
        EXPECT_TRUE(connection->isFatal());
        EXPECT_FALSE(connection->isSecureReady());
        int before = io_calls;
        rejectedIo(*connection);
        EXPECT_EQ(before, io_calls);
    }
}

TEST_F(SecureSocketTests, InvalidIoArgumentsDoNotEnterOpenSsl)
{
    preparePeer(false, true);
    auto connection = socket();
    connection->initSsl(false);
    ASSERT_EQ(1, handshake(*connection, false));
    fake_io = true;
    char buffer[4] = {};
    for (bool writing : {false, true}) {
        for (int size : {-1, 1}) {
            int count = 99;
            EXPECT_EQ(-1, writing ? connection->secureWrite(nullptr, size, count) :
                                    connection->secureRead(nullptr, size, count));
            EXPECT_EQ(0, count);
        }
        int count = 99;
        EXPECT_EQ(0, writing ? connection->secureWrite(buffer, 0, count) :
                               connection->secureRead(buffer, 0, count));
        EXPECT_EQ(0, count);
    }
    EXPECT_EQ(0, io_calls);
}
#endif

TEST_F(SecureSocketTests, DestroyBeforeInitialisation)
{
    auto connection = socket();
    connection.reset();
}

TEST_F(SecureSocketTests, CloseBeforeInitialisation)
{
    auto connection = socket();
    connection->close();
    connection->close();
    EXPECT_TRUE(connection->isFatal());
    EXPECT_FALSE(connection->isSecureReady());
}

TEST_F(SecureSocketTests, CloseTwiceAfterInitialisation)
{
    auto connection = socket();
    connection->initSsl(false);
    connection->close();
    connection->close();
    EXPECT_TRUE(connection->isFatal());
    EXPECT_FALSE(connection->isSecureReady());
}

TEST_F(SecureSocketTests, ReinitialisationIsRejected)
{
    auto connection = socket();
    connection->initSsl(false);
    EXPECT_THROW(connection->initSsl(false), XSocketCreate);
}

TEST_F(SecureSocketTests, CertificateLoadingWithoutContextFails)
{
    auto connection = socket();
    EXPECT_FALSE(connection->load_certificates("unused-certificate.pem"));
}

TEST_F(SecureSocketTests, FactoryCreatesInitialisedSocket)
{
    TCPSocketFactory factory(&events, &multiplexer);
    std::unique_ptr<IDataSocket> connection(factory.create(IArchNetwork::kINET,
                                                          ConnectionSecurityLevel::ENCRYPTED));
    ASSERT_NE(nullptr, dynamic_cast<SecureSocket*>(connection.get()));
    connection->close();
}

#ifdef BARRIER_TEST_WRAP_SSL_CONTEXT
void SecureSocketTests::checkHandshake(int version, bool expected)
{
    for (bool server : {false, true}) {
        SCOPED_TRACE(server ? "server context" : "client context");
        auto connection = socket();
        connection->initSsl(server);
        SSL_CTX* configured = last_created_context;
        ASSERT_NE(nullptr, configured);

        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> peer(
                    SSL_CTX_new(TLS_method()), SSL_CTX_free);
        ASSERT_NE(nullptr, peer);
        ASSERT_EQ(1, SSL_CTX_set_min_proto_version(peer.get(), version));
        ASSERT_EQ(1, SSL_CTX_set_max_proto_version(peer.get(), version));
        // Allow legacy cryptography in this test only, so rejection measures
        // our version floor rather than the distribution's security level.
        SSL_CTX_set_security_level(configured, 0);
        SSL_CTX_set_security_level(peer.get(), 0);

        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> generator(
                    EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
        ASSERT_NE(nullptr, generator);
        ASSERT_EQ(1, EVP_PKEY_keygen_init(generator.get()));
        ASSERT_EQ(1, EVP_PKEY_CTX_set_rsa_keygen_bits(generator.get(), 2048));
        EVP_PKEY* raw_key = nullptr;
        ASSERT_EQ(1, EVP_PKEY_keygen(generator.get(), &raw_key));
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw_key, EVP_PKEY_free);
        std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
        ASSERT_NE(nullptr, certificate);
        ASSERT_EQ(1, ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1));
        ASSERT_NE(nullptr, X509_gmtime_adj(X509_get_notBefore(certificate.get()), -60));
        ASSERT_NE(nullptr, X509_gmtime_adj(X509_get_notAfter(certificate.get()), 3600));
        ASSERT_EQ(1, X509_set_pubkey(certificate.get(), key.get()));
        X509_NAME* name = X509_get_subject_name(certificate.get());
        ASSERT_EQ(1, X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                    reinterpret_cast<const unsigned char*>("barrier-x test"), -1, -1, 0));
        ASSERT_EQ(1, X509_set_issuer_name(certificate.get(), name));
        ASSERT_GT(X509_sign(certificate.get(), key.get(), EVP_sha256()), 0);
        SSL_CTX* server_context = server ? configured : peer.get();
        ASSERT_EQ(1, SSL_CTX_use_certificate(server_context, certificate.get()));
        ASSERT_EQ(1, SSL_CTX_use_PrivateKey(server_context, key.get()));

        std::unique_ptr<SSL, decltype(&SSL_free)> client(
                    SSL_new(server ? peer.get() : configured), SSL_free);
        std::unique_ptr<SSL, decltype(&SSL_free)> receiver(SSL_new(server_context), SSL_free);
        ASSERT_NE(nullptr, client);
        ASSERT_NE(nullptr, receiver);
        BIO* outbound = nullptr;
        BIO* inbound = nullptr;
        ASSERT_EQ(1, BIO_new_bio_pair(&outbound, 0, &inbound, 0));
        SSL_set_bio(client.get(), outbound, outbound);
        SSL_set_bio(receiver.get(), inbound, inbound);
        SSL_set_connect_state(client.get());
        SSL_set_accept_state(receiver.get());

        auto step = [](SSL* ssl) {
            ERR_clear_error();
            int result = SSL_do_handshake(ssl);
            if (result == 1) {
                return 1;
            }
            int error = SSL_get_error(ssl, result);
            return (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) ? 0 : -1;
        };
        bool complete = false;
        for (int attempt = 0; attempt < 64; ++attempt) {
            int sent = step(client.get());
            int received = step(receiver.get());
            if (sent < 0 || received < 0) {
                break;
            }
            if (sent == 1 && received == 1) {
                complete = true;
                EXPECT_EQ(version, SSL_version(client.get()));
                break;
            }
        }
        EXPECT_EQ(expected, complete);
        ERR_clear_error();
    }
}

TEST_F(SecureSocketTests, RejectsTls10InBothRoles)
{
    checkHandshake(TLS1_VERSION, false);
}

TEST_F(SecureSocketTests, RejectsTls11InBothRoles)
{
    checkHandshake(TLS1_1_VERSION, false);
}

TEST_F(SecureSocketTests, AcceptsTls12InBothRoles)
{
    checkHandshake(TLS1_2_VERSION, true);
}

#ifdef TLS1_3_VERSION
TEST_F(SecureSocketTests, AcceptsTls13InBothRoles)
{
    checkHandshake(TLS1_3_VERSION, true);
}
#endif

TEST_F(SecureSocketTests, ClientContextAllocationFailureThrows)
{
    auto connection = socket();
    fail_next_context = true;
    EXPECT_THROW(connection->initSsl(false), XSocketCreate);
    EXPECT_FALSE(fail_next_context);
    EXPECT_TRUE(connection->isFatal());
    EXPECT_FALSE(connection->load_certificates("unused-certificate.pem"));
    connection->close();
}

TEST_F(SecureSocketTests, ServerContextAllocationFailureThrows)
{
    auto connection = socket();
    fail_next_context = true;
    EXPECT_THROW(connection->initSsl(true), XSocketCreate);
    EXPECT_FALSE(fail_next_context);
    EXPECT_TRUE(connection->isFatal());
}

TEST_F(SecureSocketTests, FactoryReleasesSocketOnContextFailure)
{
    TCPSocketFactory factory(&events, &multiplexer);
    fail_next_context = true;
    EXPECT_THROW({
        std::unique_ptr<IDataSocket> connection(factory.create(
                    IArchNetwork::kINET, ConnectionSecurityLevel::ENCRYPTED));
    }, XSocketCreate);
    EXPECT_FALSE(fail_next_context);
}
#endif

#ifdef BARRIER_TEST_WRAP_SSL_CONTEXT
TEST_F(SecureSocketTests, SessionAllocationFailureStopsBothRoles)
{
    for (bool server : {false, true}) {
        auto connection = socket();
        connection->initSsl(server);
        fake_transport = true;
        fail_next_session = true;
        attachment_calls = handshake_calls = 0;
        EXPECT_EQ(-1, handshake(*connection, server));
        EXPECT_FALSE(fail_next_session);
        EXPECT_TRUE(connection->isFatal());
        EXPECT_FALSE(connection->isSecureReady());
        EXPECT_EQ(-1, handshake(*connection, server));
        EXPECT_EQ(0, attachment_calls);
        EXPECT_EQ(0, handshake_calls);
        connection->close();
        connection->close();
    }
}

TEST_F(SecureSocketTests, TransportAttachmentFailureStopsBothRoles)
{
    for (bool server : {false, true}) {
        auto connection = socket();
        connection->initSsl(server);
        fake_transport = fail_attachment = true;
        attachment_calls = handshake_calls = 0;
        EXPECT_EQ(-1, handshake(*connection, server));
        EXPECT_TRUE(connection->isFatal());
        EXPECT_FALSE(connection->isSecureReady());
        EXPECT_EQ(-1, handshake(*connection, server));
        EXPECT_EQ(1, attachment_calls);
        EXPECT_EQ(0, handshake_calls);
        connection->close();
        connection->close();
    }
}

TEST_F(SecureSocketTests, HandshakeWithoutContextStopsBothRoles)
{
    for (bool server : {false, true}) {
        auto connection = socket();
        EXPECT_EQ(-1, handshake(*connection, server));
        EXPECT_TRUE(connection->isFatal());
        EXPECT_FALSE(connection->isSecureReady());
        EXPECT_EQ(0, attachment_calls);
        EXPECT_EQ(0, handshake_calls);
    }
}

TEST_F(SecureSocketTests, HandshakeAfterCloseStopsBothRoles)
{
    for (bool server : {false, true}) {
        auto connection = socket();
        connection->initSsl(server);
        connection->close();
        EXPECT_EQ(-1, handshake(*connection, server));
        EXPECT_FALSE(connection->isSecureReady());
        EXPECT_EQ(0, attachment_calls);
        EXPECT_EQ(0, handshake_calls);
    }
}

TEST_F(SecureSocketTests, HandshakeRetryRetainsTransportInBothRoles)
{
    for (bool server : {false, true}) {
        auto connection = socket();
        connection->initSsl(server);
        fake_transport = true;
        attachment_calls = handshake_calls = 0;
        ASSERT_EQ(0, handshake(*connection, server));
        SSL* session = last_session;
        ASSERT_NE(nullptr, session);
        BIO* transport = SSL_get_rbio(session);
        ASSERT_NE(nullptr, transport);
        // Queued transport data must survive a WANT_READ retry.
        ASSERT_EQ(7, BIO_write(transport, "pending", 7));
        EXPECT_EQ(0, handshake(*connection, server));
        EXPECT_EQ(session, last_session);
        EXPECT_EQ(transport, SSL_get_rbio(session));
        EXPECT_EQ(7u, BIO_ctrl_pending(SSL_get_rbio(session)));
        EXPECT_EQ(1, attachment_calls);
        EXPECT_EQ(2, handshake_calls);
        EXPECT_FALSE(connection->isFatal());
        EXPECT_FALSE(connection->isSecureReady());
    }
}

TEST_F(SecureSocketTests, RealNonblockingHandshakeRetryKeepsTransportInBothRoles)
{
    for (bool server : {false, true}) {
        struct SocketPair {
            int descriptors[2] = {-1, -1};
            ~SocketPair()
            {
                for (int fd : descriptors) {
                    if (fd >= 0) {
                        ::close(fd);
                    }
                }
            }
        } pair;
        ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM, 0, pair.descriptors));
        int flags = ::fcntl(pair.descriptors[0], F_GETFL);
        ASSERT_GE(flags, 0);
        ASSERT_EQ(0, ::fcntl(pair.descriptors[0], F_SETFL, flags | O_NONBLOCK));
        auto connection = socket();
        connection->initSsl(server);
        attachment_calls = handshake_calls = 0;
        ASSERT_EQ(0, handshake(*connection, server, pair.descriptors[0]));
        SSL* session = last_session;
        ASSERT_NE(nullptr, session);
        BIO* transport = SSL_get_rbio(session);
        ASSERT_NE(nullptr, transport);
        EXPECT_EQ(pair.descriptors[0], SSL_get_fd(session));
        EXPECT_EQ(0, handshake(*connection, server, pair.descriptors[0]));
        EXPECT_EQ(transport, SSL_get_rbio(session));
        EXPECT_EQ(1, attachment_calls);
        EXPECT_EQ(2, handshake_calls);
        EXPECT_FALSE(connection->isFatal());
        EXPECT_FALSE(connection->isSecureReady());
    }
}
#endif

#ifdef BARRIER_TEST_WRAP_SSL_CONTEXT
TEST_F(SecureSocketTests, UntrustedPeerFailsClosedInBothRoles)
{
    for (bool server : {false, true}) {
        // One profile is enough; both trust databases remain empty.
        if (peer_directory.empty()) { ASSERT_NO_FATAL_FAILURE(preparePeer(server, false)); }
        auto connection = socket(ConnectionSecurityLevel::ENCRYPTED_AUTHENTICATED);
        connection->initSsl(server);
        observed_socket = connection.get();
        peer_releases = 0;
        EXPECT_EQ(-1, handshake(*connection, server));
        EXPECT_FALSE(ready_during_verification);
        EXPECT_FALSE(connection->isSecureReady());
        EXPECT_TRUE(connection->isFatal());
        EXPECT_EQ(1, peer_releases);
        EXPECT_EQ(-1, handshake(*connection, server));
        observed_socket = nullptr;
    }
}

TEST_F(SecureSocketTests, MatchingSha256PinSetsReadyOnlyAfterVerification)
{
    ASSERT_NO_FATAL_FAILURE(preparePeer(false, true));
    // Share the same explicit pin with the authenticated server role.
    barrier::fs::copy_file(barrier::DataDirectories::trusted_servers_ssl_fingerprints_path(),
                          barrier::DataDirectories::trusted_clients_ssl_fingerprints_path());
    for (bool server : {false, true}) {
        auto connection = socket(ConnectionSecurityLevel::ENCRYPTED_AUTHENTICATED);
        connection->initSsl(server);
        observed_socket = connection.get();
        peer_releases = 0;
        EXPECT_EQ(1, handshake(*connection, server));
        EXPECT_FALSE(ready_during_verification);
        EXPECT_TRUE(connection->isSecureReady());
        EXPECT_FALSE(connection->isFatal());
        EXPECT_EQ(2, peer_releases);
        connection->close();
        EXPECT_FALSE(connection->isSecureReady());
        observed_socket = nullptr;
    }
}

TEST_F(SecureSocketTests, Sha1OnlyPinDoesNotAuthorisePeer)
{
    ASSERT_NO_FATAL_FAILURE(preparePeer(false, true, barrier::FingerprintType::SHA1));
    auto connection = socket();
    connection->initSsl(false);
    observed_socket = connection.get();
    EXPECT_EQ(-1, handshake(*connection, false));
    EXPECT_FALSE(connection->isSecureReady());
    EXPECT_TRUE(connection->isFatal());
    EXPECT_EQ(1, peer_releases);
}

TEST_F(SecureSocketTests, MissingPeerCertificateFailsClosed)
{
    ASSERT_NO_FATAL_FAILURE(preparePeer(false, false));
    peer_certificate = nullptr;
    auto connection = socket();
    connection->initSsl(false);
    EXPECT_EQ(-1, handshake(*connection, false));
    EXPECT_FALSE(connection->isSecureReady());
    EXPECT_TRUE(connection->isFatal());
}

TEST_F(SecureSocketTests, DigestFailureReleasesPeerAndFailsClosed)
{
    ASSERT_NO_FATAL_FAILURE(preparePeer(false, true));
    digest_calls = 0;
    fail_digest_call = 2;
    auto connection = socket();
    connection->initSsl(false);
    EXPECT_EQ(-1, handshake(*connection, false));
    EXPECT_FALSE(connection->isSecureReady());
    EXPECT_TRUE(connection->isFatal());
    EXPECT_EQ(1, peer_releases);
}
#endif
