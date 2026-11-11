/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2008 Volker Lanz (vl@fidra.de)
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

#include "SettingsDialog.h"

#include "BarrierLocale.h"
#include "QBarrierApplication.h"
#include "QUtility.h"
#include "AppConfig.h"
#include "SslCertificate.h"
#include "MainWindow.h"
#include "io/LogStore.h"

#include <QtCore>
#include <QtGui>
#include <QMessageBox>
#include <QFileDialog>
#include <QDir>

SettingsDialog::SettingsDialog(QWidget* parent, AppConfig& config) :
    QDialog(parent, Qt::WindowTitleHint | Qt::WindowSystemMenuHint),
    Ui::SettingsDialogBase(),
       m_appConfig(config)
{
    setupUi(this);

    m_Locale.fillLanguageComboBox(m_pComboLanguage);

    m_pLineEditScreenName->setText(appConfig().screenName());
    m_pSpinBoxPort->setValue(appConfig().port());
    m_pLineEditInterface->setText(appConfig().networkInterface());
    m_pComboLogLevel->setCurrentIndex(appConfig().logLevel());
    m_pCheckBoxLogToFile->setChecked(appConfig().logToFile());
    m_pLineEditLogFilename->setText(appConfig().logFilename());
    fillLogRetention(appConfig().logRetentionDays());
    setIndexFromItemData(m_pComboLanguage, appConfig().language());
    m_pCheckBoxAutoHide->setChecked(appConfig().getAutoHide());
    m_pCheckBoxAutoStart->setChecked(appConfig().getAutoStart());
    m_pCheckBoxMinimizeToTray->setChecked(appConfig().getMinimizeToTray());
    m_pCheckBoxEnableCrypto->setChecked(m_appConfig.getCryptoEnabled());
    checkbox_require_client_certificate->setChecked(m_appConfig.getRequireClientCertificate());

#if defined(Q_OS_WIN)
    m_pComboElevate->setCurrentIndex(static_cast<int>(appConfig().elevateMode()));
#else
    // elevate checkbox is only useful on ms windows.
    m_pLabelElevate->hide();
    m_pComboElevate->hide();
#endif
}

void SettingsDialog::accept()
{
    m_appConfig.setScreenName(m_pLineEditScreenName->text());
    m_appConfig.setPort(m_pSpinBoxPort->value());
    m_appConfig.setNetworkInterface(m_pLineEditInterface->text());
    m_appConfig.setCryptoEnabled(m_pCheckBoxEnableCrypto->isChecked());
    m_appConfig.setRequireClientCertificate(checkbox_require_client_certificate->isChecked());
    m_appConfig.setLogLevel(m_pComboLogLevel->currentIndex());
    m_appConfig.setLogToFile(m_pCheckBoxLogToFile->isChecked());
    m_appConfig.setLogFilename(m_pLineEditLogFilename->text());
    m_appConfig.m_LogRetentionDays = m_pComboLogRetention->currentData().toInt();
    m_appConfig.setLanguage(m_pComboLanguage->itemData(m_pComboLanguage->currentIndex()).toString());
    m_appConfig.setElevateMode(static_cast<ElevateMode>(m_pComboElevate->currentIndex()));
    m_appConfig.setAutoHide(m_pCheckBoxAutoHide->isChecked());
    m_appConfig.setAutoStart(m_pCheckBoxAutoStart->isChecked());
    m_appConfig.setMinimizeToTray(m_pCheckBoxMinimizeToTray->isChecked());
    m_appConfig.saveSettings();
    QDialog::accept();
}

void SettingsDialog::reject()
{
    if (m_appConfig.language() != m_pComboLanguage->itemData(m_pComboLanguage->currentIndex()).toString()) {
        QBarrierApplication::getInstance()->switchTranslator(m_appConfig.language());
    }
    QDialog::reject();
}

void SettingsDialog::changeEvent(QEvent* event)
{
    if (event != 0)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            {
                int logLevelIndex = m_pComboLogLevel->currentIndex();
                const int retention = m_pComboLogRetention->currentData().toInt();

                m_pComboLanguage->blockSignals(true);
                retranslateUi(this);
                m_pComboLanguage->blockSignals(false);

                m_pComboLogLevel->setCurrentIndex(logLevelIndex);
                fillLogRetention(retention);
                break;
            }

        default:
            QDialog::changeEvent(event);
        }
    }
}

void SettingsDialog::on_m_pCheckBoxLogToFile_stateChanged(int i)
{
    bool checked = i == 2;

    m_pLineEditLogFilename->setEnabled(checked);
    m_pButtonBrowseLog->setEnabled(checked);
}

void SettingsDialog::on_m_pButtonBrowseLog_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(
        this, tr("Save log file to..."),
        m_pLineEditLogFilename->text(),
        "Logs (*.log *.txt)");

    if (!fileName.isEmpty())
    {
        m_pLineEditLogFilename->setText(fileName);
    }
}

void SettingsDialog::on_m_pComboLanguage_currentIndexChanged(int index)
{
    QString ietfCode = m_pComboLanguage->itemData(index).toString();
    QBarrierApplication::getInstance()->switchTranslator(ietfCode);
}


void SettingsDialog::fillLogRetention(int days)
{
    m_pComboLogRetention->clear();
    for (const int value : {0, 5, 10, 12, 15, 22, 28, 30, 60}) {
        m_pComboLogRetention->addItem(value ? tr("%1 days").arg(value) : tr("0 days (off)"), value);
    }
    m_pComboLogRetention->setCurrentIndex(m_pComboLogRetention->findData(days));
}
bool SettingsDialog::deleteSavedLogs(QWidget* parent, const QString& filename)
{
    QMessageBox question(QMessageBox::Warning, tr("Delete saved logs"),
        tr("Clear the saved contents of this application's configured log and its .1 backup?\n%1\n\n"
           "This also clears the log display. Exported copies and system logs are not included. Files may remain empty so logging can continue.").arg(filename),
        QMessageBox::Yes | QMessageBox::Cancel, parent);
    question.setTextFormat(Qt::PlainText);
    question.setDefaultButton(QMessageBox::Cancel);
    if (question.exec() != QMessageBox::Yes) { return false; }
    try {
        barrier::clear_logs(barrier::fs::u8path(filename.toStdString()));
        return true;
    } catch (const std::exception&) {
        QMessageBox::warning(parent, tr("Logs were not fully deleted"),
            tr("I couldn't clear all configured log files. Check ownership, permissions, file type or another active writer. "
               "No unrelated files are included. Retry after stopping sharing if a log is busy."));
        return false;
    }
}
void SettingsDialog::on_m_pButtonDeleteLogs_clicked()
{
    // I use the saved path, not an uncommitted filename in the editor.
    if (deleteSavedLogs(this, appConfig().logFilename())) { emit logsDeleted(); }
}
