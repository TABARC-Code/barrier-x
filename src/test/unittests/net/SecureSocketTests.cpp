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

namespace {
thread_local bool fail_next_context = false;
}

// Linker wrapping keeps allocation failure tests out of the production API.
extern "C" SSL_CTX* __real_SSL_CTX_new(const SSL_METHOD* method);
extern "C" SSL_CTX* __wrap_SSL_CTX_new(const SSL_METHOD* method)
{
    if (fail_next_context) {
        fail_next_context = false;
        return nullptr;
    }
    return __real_SSL_CTX_new(method);
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
