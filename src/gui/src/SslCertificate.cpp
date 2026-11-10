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
#include "io/PrivateDirectory.h"
#include "net/FingerprintDatabase.h"
#include "net/SecureUtils.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <QSaveFile>
#include <sstream>
#include <stdexcept>

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
        if (barrier::DataDirectories::profile().empty()) {
            throw std::runtime_error("No profile directory is available.");
        }
        const auto cert_path = barrier::DataDirectories::ssl_certificate_path();
        barrier::PemIdentity identity;
        if (barrier::fs::exists(barrier::fs::symlink_status(cert_path))) {
            // I preserve files rejected by the reader; a new key would hide the fault.
            identity = barrier::read_pem_identity(cert_path.u8string());
            if (!is_certificate_valid(identity.certificate.get())) {
                throw std::runtime_error("The existing certificate does not meet the key requirements. It has not been replaced.");
            }
        }
        if (!identity.certificate) {
#if SYSAPI_WIN32
            barrier::fs::create_directories(cert_path.parent_path());
#else
            barrier::PrivateDirectory directory(cert_path.parent_path(), barrier::PrivateDirectoryMode::Create);
#endif
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
    // FUTURE(BX-004): I still need handle-relative public fingerprint storage.
    barrier::fs::create_directories(local_path.parent_path());
    const auto status = barrier::fs::symlink_status(local_path);
    if (barrier::fs::exists(status) && !barrier::fs::is_regular_file(status)) {
        throw std::runtime_error("The public fingerprint path is not a regular file.");
    }
    barrier::FingerprintDatabase db;
    db.add_trusted(barrier::get_ssl_cert_fingerprint(certificate, barrier::FingerprintType::SHA1));
    db.add_trusted(barrier::get_ssl_cert_fingerprint(certificate, barrier::FingerprintType::SHA256));
    std::ostringstream encoded;
    db.write_stream(encoded);
    const auto bytes = encoded.str();
    QSaveFile output(QString::fromStdString(local_path.u8string()));
    output.setDirectWriteFallback(false);
    if (!output.open(QIODevice::WriteOnly) ||
        output.write(bytes.data(), static_cast<qint64>(bytes.size())) != static_cast<qint64>(bytes.size()) ||
        !output.commit()) {
        throw std::runtime_error("Cannot save the public fingerprints: " + output.errorString().toStdString());
    }
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
