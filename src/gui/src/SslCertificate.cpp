/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2015-2016 Symless Ltd.
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "SslCertificate.h"
#include "common/DataDirectories.h"
#include "base/finally.h"
#include "io/filesystem.h"
#include "net/FingerprintDatabase.h"
#include "net/SecureUtils.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

SslCertificate::SslCertificate(QObject *parent) :
    QObject(parent)
{
    if (barrier::DataDirectories::profile().empty()) {
        emit error(tr("Failed to get profile directory."));
    }
}

void SslCertificate::generateCertificate()
{
    try {
        const auto cert_path = barrier::DataDirectories::ssl_certificate_path();
        barrier::PemIdentity identity;
        if (barrier::fs::exists(barrier::fs::symlink_status(cert_path))) {
            // I preserve files rejected by the reader; a new key would hide the fault.
            identity = barrier::read_pem_identity(cert_path.u8string());
        }
        if (!identity.certificate || !is_certificate_valid(identity.certificate.get())) {
            barrier::fs::create_directories(cert_path.parent_path());
            barrier::generate_pem_self_signed_cert(cert_path.u8string());
            identity = barrier::read_pem_identity(cert_path.u8string());
            emit info(tr("SSL certificate generated."));
        }
        generate_fingerprint(identity.certificate.get());
        emit generateFinished();
    }
    catch (const std::exception& error) {
        // FUTURE(BX-007): I need an explicit repair/replace action that explains
        // the pin changes before replacing an existing identity.
        emit this->error(tr("SSL identity setup failed: ") + QString::fromUtf8(error.what()));
    }
}

void SslCertificate::generate_fingerprint(X509* certificate)
{
    const auto local_path = barrier::DataDirectories::local_ssl_fingerprints_path();
    barrier::fs::create_directories(local_path.parent_path());
    barrier::FingerprintDatabase db;
    db.add_trusted(barrier::get_ssl_cert_fingerprint(certificate, barrier::FingerprintType::SHA1));
    db.add_trusted(barrier::get_ssl_cert_fingerprint(certificate, barrier::FingerprintType::SHA256));
    // FUTURE(BX-002): I still need checked, atomic fingerprint-store publication.
    db.write(local_path);
    emit info(tr("SSL fingerprint generated."));
}

bool SslCertificate::is_certificate_valid(X509* cert)
{
    auto* pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        emit info(tr("Default certificate key file does not contain valid public key"));
        return false;
    }
    auto pubkey_free = barrier::finally([pubkey]() { EVP_PKEY_free(pubkey); });

    auto type = EVP_PKEY_type(EVP_PKEY_id(pubkey));
    if (type != EVP_PKEY_RSA && type != EVP_PKEY_DSA) {
        emit info(tr("Public key in default certificate key file is not RSA or DSA"));
        return false;
    }

    auto bits = EVP_PKEY_bits(pubkey);
    if (bits < 2048) {
        // We could have small keys in old barrier installations
        emit info(tr("Public key in default certificate key file is too small."));
        return false;
    }

    return true;
}
