/*
    barrier -- mouse and keyboard sharing utility
    Copyright (C) Barrier contributors

    This package is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    found in the file LICENSE that should have accompanied this file.

    This package is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "FingerprintAcceptDialog.h"
#include "ui_FingerprintAcceptDialog.h"
#include "net/SecureUtils.h"
#include <QApplication>
#include <QClipboard>
#include <QPushButton>

FingerprintAcceptDialog::FingerprintAcceptDialog(QWidget *parent,
                                                 BarrierType type,
                                                 const barrier::FingerprintData& fingerprint_sha1,
                                                 const barrier::FingerprintData& fingerprint_sha256) :
    QDialog(parent),
    ui_{std::make_unique<Ui::FingerprintAcceptDialog>()}
{
    ui_->setupUi(this);

    const bool client = type == BarrierType::Server;
    valid_fingerprint_ = fingerprint_sha256.algorithm == "sha256" && fingerprint_sha256.data.size() == 32;
    auto* trust = ui_->buttonBox->addButton(client ? tr("Trust &client") : tr("Trust &server"),
                                           QDialogButtonBox::AcceptRole);
    trust->setObjectName(QStringLiteral("trustPeer"));
    trust->setEnabled(valid_fingerprint_);
    trust->setAutoDefault(false);
    trust->setDefault(false);
    auto* reject = ui_->buttonBox->addButton(tr("&Reject"), QDialogButtonBox::RejectRole);
    reject->setObjectName(QStringLiteral("rejectPeer"));
    reject->setAutoDefault(false);
    // Return mustn't approve a stranger just because the window appeared.
    reject->setDefault(true);
    reject->setFocus();
    auto* copy = ui_->buttonBox->addButton(tr("Copy SHA-&256"), QDialogButtonBox::ActionRole);
    copy->setObjectName(QStringLiteral("copyPeerFingerprint"));
    copy->setAutoDefault(false);
    copy->setEnabled(valid_fingerprint_);
    copy->setAccessibleName(tr("Copy the full public SHA-256 fingerprint"));

    const bool legacy = !client && fingerprint_sha1.algorithm == "sha1" && fingerprint_sha1.data.size() == 20;
    ui_->label_sha1->setVisible(legacy);
    ui_->label_sha1_fingerprint_full->setVisible(legacy);
    if (legacy) {
        ui_->label_sha1_fingerprint_full->setText(
            QString::fromStdString(barrier::format_ssl_fingerprint(fingerprint_sha1.data)));
    }
    ui_->label_title->setText(client ? tr("Verify this client") : tr("Verify this server"));
    if (!valid_fingerprint_) {
        ui_->label_explanation->setText(tr("The peer did not provide a valid SHA-256 fingerprint. Reject this request."));
        return;
    }
    const QString full = QString::fromStdString(barrier::format_ssl_fingerprint(fingerprint_sha256.data));
    ui_->label_sha256_fingerprint_full->setText(
        QString::fromStdString(barrier::format_ssl_fingerprint_columns(fingerprint_sha256.data)));
    ui_->label_sha256_fingerprint_randomart->setText(
        QString::fromStdString(barrier::create_fingerprint_randomart(fingerprint_sha256.data)));
    connect(copy, &QPushButton::clicked, this, [this, full] {
        QApplication::clipboard()->setText(full);
        ui_->copyFeedback->setText(tr("Full SHA-256 fingerprint copied."));
    });
    ui_->label_explanation->setText(client ?
        tr("Compare the full SHA-256 fingerprint with the one shown on your client's screen. "
           "Trust only if they match exactly.\n\n"
           "Trusting saves this fingerprint for future connections. If you're unsure, reject it.") :
        tr("Compare the full SHA-256 fingerprint with the one shown on your server's screen. "
           "Trust only if they match exactly.\n\n"
           "Trusting saves this fingerprint for future connections. If you're unsure, reject it."));
}

void FingerprintAcceptDialog::accept()
{
    if (valid_fingerprint_) { QDialog::accept(); }
}

FingerprintAcceptDialog::~FingerprintAcceptDialog() = default;
