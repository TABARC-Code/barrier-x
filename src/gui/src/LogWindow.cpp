/*
* barrier -- mouse and keyboard sharing utility
* Copyright (C) 2018 Debauchee Open Source Group
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

#include "LogWindow.h"

#include <QDateTime>
#include <QTimer>
#include <QTextDocument>
#include "io/LogStore.h"

static QString getTimeStamp()
{
    QDateTime current = QDateTime::currentDateTime();
    return '[' + current.toString(Qt::ISODate) + ']';
}

LogWindow::LogWindow(QWidget *parent) :
    QDialog(parent)
{
    // explicitly unset DeleteOnClose so the log window can be show and hidden
    // repeatedly until Barrier is finished
    setAttribute(Qt::WA_DeleteOnClose, false);
    setupUi(this);
    // FUTURE(BX-006): I also want a byte cap; a line count only does half the job.
    m_pLogOutput->document()->setMaximumBlockCount(5000);
    connect(m_pButtonDeleteSavedLogs, &QPushButton::clicked, this, &LogWindow::deleteSavedLogsRequested);
    auto timer = new QTimer(this);
    timer->setInterval(60000);
    connect(timer, &QTimer::timeout, this, [this] {
        if (m_retentionDays && m_historyStarted.isValid() &&
            m_historyStarted.secsTo(QDateTime::currentDateTimeUtc()) >= qint64(m_retentionDays) * 86400) { clearLog(); }
    });
    timer->start();
}

void LogWindow::startNewInstance()
{
    // put a space between last log output and new instance.
    if (!m_pLogOutput->toPlainText().isEmpty())
        appendRaw("");
}

void LogWindow::appendInfo(const QString& text)
{
    appendRaw(getTimeStamp() + " INFO: " + text);
}

void LogWindow::appendDebug(const QString& text)
{
    appendRaw(getTimeStamp() + " DEBUG: " + text);
}

void LogWindow::appendError(const QString& text)
{
    appendRaw(getTimeStamp() + " ERROR: " + text);
}

void LogWindow::appendRaw(const QString& text)
{
    if (!m_historyStarted.isValid()) { m_historyStarted = QDateTime::currentDateTimeUtc(); }
    m_pLogOutput->append(text);
}

void LogWindow::on_m_pButtonHide_clicked()
{
    hide();
}

void LogWindow::on_m_pButtonClearLog_clicked()
{
    clearLog();
}

void LogWindow::clearLog() { m_pLogOutput->clear(); m_historyStarted = QDateTime(); }
void LogWindow::setRetentionDays(int days) { m_retentionDays = barrier::valid_log_retention(days) ? days : 0; }
