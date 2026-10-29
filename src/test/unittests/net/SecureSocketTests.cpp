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
#include "net/SocketMultiplexer.h"
#include "base/EventQueue.h"
#include "test/global/gtest.h"

#include <memory>

#ifdef BARRIER_TEST_WRAP_SSL_CONTEXT
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace {
thread_local bool fail_next_context = false;
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
#endif

class SecureSocketTests : public ::testing::Test {
protected:
    std::unique_ptr<SecureSocket> socket()
    {
        return std::make_unique<SecureSocket>(&events, &multiplexer, IArchNetwork::kINET,
                                              ConnectionSecurityLevel::ENCRYPTED);
    }

    EventQueue events;
    SocketMultiplexer multiplexer;

#ifdef BARRIER_TEST_WRAP_SSL_CONTEXT
    void checkHandshake(int version, bool expected);
#endif
};

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
