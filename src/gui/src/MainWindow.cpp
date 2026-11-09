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

#include <iostream>

#include "MainWindow.h"

#include "AboutDialog.h"
#include "ServerConfigDialog.h"
#include "SettingsDialog.h"
#if BARRIER_WITH_DISCOVERY
#include "ZeroconfService.h"
#endif
#include "FingerprintAcceptDialog.h"
#include "PeerTrustStore.h"
#include "QUtility.h"
#include "SslCertificate.h"
#include "ShutdownCh.h"
#include "base/String.h"
#include "base/finally.h"
#include "common/DataDirectories.h"
#include "common/Version.h"
#include "net/FingerprintDatabase.h"
#include "net/SecureUtils.h"

#include <QtCore>
#include <QtGui>
#include <QtNetwork>
#include <QNetworkAccessManager>
#include <QMenu>
#include <QClipboard>
#include <QStatusBar>
#include <QScrollArea>
#include <QTabWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QFileDialog>
#include <QDesktopServices>
#include <QDesktopWidget>

#if defined(Q_OS_MAC)
#include <ApplicationServices/ApplicationServices.h>
#endif

#if defined(Q_OS_WIN)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

static const QString allFilesFilter(QObject::tr("All files (*.*)"));
#if defined(Q_OS_WIN)
static const char barrierConfigName[] = "barrier.sgc";
static const QString barrierConfigFilter(QObject::tr("Barrier Configurations (*.sgc)"));
#else
static const char barrierConfigName[] = "barrier.conf";
static const QString barrierConfigFilter(QObject::tr("Barrier Configurations (*.conf)"));
#endif
static const QString barrierConfigOpenFilter(barrierConfigFilter + ";;" + allFilesFilter);
static const QString barrierConfigSaveFilter(barrierConfigFilter);

static const char* barrierIconFiles[] =
{
#if defined(Q_OS_MAC)
    ":/res/icons/32x32/barrier-disconnected-mask.png",
    ":/res/icons/32x32/barrier-disconnected-mask.png",
    ":/res/icons/32x32/barrier-connected-mask.png",
    ":/res/icons/32x32/barrier-transfering-mask.png"
#else
    ":/res/icons/16x16/barrier-disconnected.png",
    ":/res/icons/16x16/barrier-disconnected.png",
    ":/res/icons/16x16/barrier-connected.png",
    ":/res/icons/16x16/barrier-transfering.png"
#endif
};

static const char* barrierIconNames[] =
{
    "barrier-disconnected",
    "barrier-disconnected",
    "barrier-connected",
    "barrier-transfering"
};

static const char* barrierLargeIcon = ":/res/icons/256x256/barrier.ico";

// FUTURE(BX-007): show trusted identity, connection failure and input focus as
// separate states. A running process does not mean another machine is usable.
MainWindow::MainWindow(QSettings& settings, AppConfig& appConfig) :
    m_Settings(settings),
    m_AppConfig(&appConfig),
    m_pBarrier(NULL),
    m_BarrierState(barrierDisconnected),
    m_ServerConfig(&m_Settings, 5, 3, m_AppConfig->screenName(), this),
    m_pTempConfigFile(NULL),
    m_pTrayIcon(NULL),
    m_pTrayIconMenu(NULL),
    m_AlreadyHidden(false),
    m_pMenuBar(NULL),
    m_pMenuBarrier(NULL),
    m_pMenuHelp(NULL),
    m_pZeroconfService(NULL),
    m_SuppressEmptyServerWarning(false),
    m_ExpectedRunningState(kStopped),
    m_pSslCertificate(NULL),
    m_pLogWindow(new LogWindow(nullptr))
{
    // explicitly unset DeleteOnClose so the window can be show and hidden
    // repeatedly until Barrier is finished
    setAttribute(Qt::WA_DeleteOnClose, false);
    // mark the windows as sort of "dialog" window so that tiling window
    // managers will float it by default (X11)
    setAttribute(Qt::WA_X11NetWmWindowTypeDialog, true);

    setupUi(this);
    peerTrustError->hide();
    setWindowIcon(QIcon(barrierLargeIcon));
    createMenuBar();
    loadSettings();
    initConnections();
    // 2.4.22: I keep page navigation separate from connection actions.
    connect(goToLayout, &QPushButton::clicked, this, [this] { dashboardTabs->setCurrentWidget(layoutPage); });
    connect(goToConnection, &QPushButton::clicked, this, [this] {
        dashboardTabs->setCurrentWidget(connectionPage);
        m_pGroupServer->setFocus();
    });
    connect(openPreferences, &QPushButton::clicked, m_pActionSettings, &QAction::trigger);
    connect(openDashboardLog, &QPushButton::clicked, m_pActionShowLog, &QAction::trigger);
    connect(reviewIdentity, &QPushButton::clicked, this, [this] {
        dashboardTabs->setCurrentWidget(connectionPage);
        connectionPageScroll->ensureWidgetVisible(retryIdentity);
        retryIdentity->setFocus();
    });

    m_pLabelScreenName->setText(getScreenName());
    m_pLabelIpAddresses->setText(getIPAddresses());
    copyAddresses->setEnabled(!m_CopyableAddresses.isEmpty());
    connect(copyAddresses, &QToolButton::clicked, this, [this] {
        if (m_CopyableAddresses.isEmpty()) { return; }
        QApplication::clipboard()->setText(m_CopyableAddresses);
        statusBar()->showMessage(tr("IP addresses copied."), 3000);
    });
    connect(retryIdentity, &QToolButton::clicked, this, [this] { updateSSLFingerprint(true); });
    connect(copyFingerprint, &QToolButton::clicked, this, [this] {
        if (m_CopyableFingerprint.isEmpty()) { return; }
        // I copy the public SHA-256 value, never the shortened label or the key file.
        QApplication::clipboard()->setText(m_CopyableFingerprint);
        statusBar()->showMessage(tr("Full SHA-256 fingerprint copied."), 3000);
    });

#if defined(Q_OS_WIN)
    // ipc must always be enabled, so that we can disable command when switching to desktop mode.
    connect(&m_IpcClient, SIGNAL(readLogLine(const QString&)), this, SLOT(appendLogRaw(const QString&)));
    connect(&m_IpcClient, SIGNAL(errorMessage(const QString&)), this, SLOT(appendLogError(const QString&)));
    connect(&m_IpcClient, SIGNAL(infoMessage(const QString&)), this, SLOT(appendLogInfo(const QString&)));
    m_IpcClient.connectToHost();
#endif

    updateDiscoveryControls();

    m_pComboServerList->hide();
    m_pLabelPadlock->hide();
    frame_fingerprint_details->hide();

    updateSSLFingerprint();
    updateConnectionPresentation();

    connect(toolbutton_show_fingerprint, &QToolButton::clicked, [this](bool checked)
    {
        m_fingerprint_expanded = checked;
        if (m_fingerprint_expanded) {
            frame_fingerprint_details->show();
            toolbutton_show_fingerprint->setArrowType(Qt::ArrowType::UpArrow);
        } else {
            frame_fingerprint_details->hide();
            toolbutton_show_fingerprint->setArrowType(Qt::ArrowType::DownArrow);
        }
    });

    // 2.4.22: I let long pages scroll, including expanded fingerprints.
    resize(820, 700);
    const auto geometry = settings.value("dashboardGeometry").toByteArray();
    if (!geometry.isEmpty()) { restoreGeometry(geometry); }
}

MainWindow::~MainWindow()
{
    if (appConfig().processMode() == Desktop) {
        m_ExpectedRunningState = kStopped;
        stopDesktop();
    }

    saveSettings();

#if BARRIER_WITH_DISCOVERY
    delete m_pZeroconfService;
#endif
    delete m_pSslCertificate;

    // LogWindow is created as a sibling of the MainWindow rather than a child
    // so that the main window can be hidden without hiding the log. because of
    // this it does not get properly cleaned up by the QObject system. also by
    // the time this destructor is called the event loop will no longer be able
    // to clean up the LogWindow so ->deleteLater() will not work
    delete m_pLogWindow;
}

void MainWindow::open()
{
    createTrayIcon();

    if (appConfig().getAutoHide()) {
        hide();
    } else {
        showNormal();
    }

    updateDiscoveryControls();

    // only start if user has previously started. this stops the gui from
    // auto hiding before the user has configured barrier (which of course
    // confuses first time users, who think barrier has crashed).
    if (appConfig().startedBefore() && appConfig().getAutoStart()) {
        m_SuppressEmptyServerWarning = true;
        startBarrier();
        m_SuppressEmptyServerWarning = false;
    }
}

void MainWindow::setStatus(const QString &status)
{
    m_pStatusLabel->setText(status);
}

void MainWindow::updateConnectionPresentation()
{
    const bool active = barrierState() != barrierDisconnected;
    const bool server = (active ? m_ActiveRole : barrier_type()) == BarrierType::Server;
    m_pButtonToggleStart->setText(barrierState() == barrierDisconnected ? tr("&Start") : tr("&Stop"));
    switch (barrierState()) {
    case barrierConnected:
        setStatus(server ? tr("Server running") : tr("Connected to server"));
        connectionHint->setText(server ?
            tr("Use this computer's address and name when setting up your clients.") :
            tr("This computer is using the server's keyboard and mouse."));
        break;
    case barrierConnecting:
        setStatus(server ? tr("Starting server") : tr("Connecting to server"));
        connectionHint->setText(tr("Open the log with F2 for connection details. You can stop this attempt."));
        break;
    case barrierTransfering:
        setStatus(tr("Transfer in progress"));
        connectionHint->setText(tr("The connection is active. Open the log with F2 for details."));
        break;
    case barrierDisconnected:
        setStatus(tr("Stopped"));
        connectionHint->setText(server ?
            tr("Arrange your client screens, then start sharing this computer's keyboard and mouse.") :
            tr("Choose the server you want to use, then start the connection."));
        break;
    }
    if (active && barrier_type() != m_ActiveRole) {
        connectionHint->setText(connectionHint->text() + QLatin1Char(' ') +
            tr("Stop and start again to apply the new computer role."));
    }
    updateDashboard();
    // FUTURE(BX-007): report peer approval and input focus from explicit engine events.
    // A listening server still isn't proof that anyone has turned up.
}

void MainWindow::updateDashboard()
{
    const bool server = barrier_type() == BarrierType::Server;
    layoutTools->setEnabled(server);
    m_pGroupServer->setFlat(!server);
    m_pGroupClient->setFlat(server);
    serverRoleHint->setVisible(server);
    goToLayout->setVisible(server);
    m_pLabelServerName->setVisible(!server);
    m_pLineEditHostname->setVisible(!server);
    m_pCheckBoxAutoConfig->setVisible(!server);
    discoveryHint->setVisible(!server);
    m_pComboServerList->setVisible(!server && m_pCheckBoxAutoConfig->isChecked() && m_pComboServerList->count() > 1);
    goToConnection->setVisible(!server);
    layoutHint->setText(server ?
        tr("Arrange the client screens to match your desk. Each screen name must match its client computer.") :
        tr("Screen layout is configured on the server. Choose Server on Connection to edit it here."));
    dashboardVersion->setText(tr("Development version: %1").arg(QString::fromLatin1(kVersion)));
}

void MainWindow::createTrayIcon()
{
    m_pTrayIconMenu = new QMenu(this);

    m_pTrayIconMenu->addAction(m_pActionStartBarrier);
    m_pTrayIconMenu->addAction(m_pActionStopBarrier);
    m_pTrayIconMenu->addAction(m_pActionShowLog);
    m_pTrayIconMenu->addSeparator();

    m_pTrayIconMenu->addAction(m_pActionMinimize);
    m_pTrayIconMenu->addAction(m_pActionRestore);
    m_pTrayIconMenu->addSeparator();
    m_pTrayIconMenu->addAction(m_pActionQuit);

    m_pTrayIcon = new QSystemTrayIcon(this);
    m_pTrayIcon->setContextMenu(m_pTrayIconMenu);
    m_pTrayIcon->setToolTip("Barrier");

    connect(m_pTrayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
            this, SLOT(trayActivated(QSystemTrayIcon::ActivationReason)));

    setIcon(barrierDisconnected);

    m_pTrayIcon->show();
}

void MainWindow::retranslateMenuBar()
{
    m_pMenuBarrier->setTitle(tr("&Barrier"));
    m_pMenuHelp->setTitle(tr("&Help"));
}

void MainWindow::createMenuBar()
{
    m_pMenuBar = new QMenuBar(this);
    m_pMenuBarrier = new QMenu("", m_pMenuBar);
    m_pMenuHelp = new QMenu("", m_pMenuBar);
    retranslateMenuBar();

    m_pMenuBar->addAction(m_pMenuBarrier->menuAction());
    m_pMenuBar->addAction(m_pMenuHelp->menuAction());

    m_pMenuBarrier->addAction(m_pActionShowLog);
    m_pMenuBarrier->addAction(m_pActionSettings);
    m_pMenuBarrier->addAction(m_pActionMinimize);
    m_pMenuBarrier->addSeparator();
    m_pMenuBarrier->addAction(m_pActionSave);
    m_pMenuBarrier->addSeparator();
    m_pMenuBarrier->addAction(m_pActionQuit);
    m_pMenuHelp->addAction(m_pActionAbout);

    setMenuBar(m_pMenuBar);
}

void MainWindow::loadSettings()
{
    // the next two must come BEFORE loading groupServerChecked and groupClientChecked or
    // disabling and/or enabling the right widgets won't automatically work
    m_pRadioExternalConfig->setChecked(settings().value("useExternalConfig", false).toBool());
    m_pRadioInternalConfig->setChecked(settings().value("useInternalConfig", true).toBool());

    m_pGroupServer->setChecked(settings().value("groupServerChecked", false).toBool());
    m_pLineEditConfigFile->setText(settings().value("configFile", QDir::homePath() + "/" + barrierConfigName).toString());
    m_pGroupClient->setChecked(settings().value("groupClientChecked", true).toBool());
    m_pLineEditHostname->setText(settings().value("serverHostname").toString());
    dashboardTabs->setCurrentIndex(qBound(0, settings().value("dashboardTab", 0).toInt(), dashboardTabs->count() - 1));
}

void MainWindow::initConnections()
{
    connect(m_pActionMinimize, SIGNAL(triggered()), this, SLOT(hide()));
    connect(m_pActionRestore, SIGNAL(triggered()), this, SLOT(showNormal()));
    connect(m_pActionStartBarrier, SIGNAL(triggered()), this, SLOT(startBarrier()));
    connect(m_pActionStopBarrier, SIGNAL(triggered()), this, SLOT(stopBarrier()));
    connect(m_pActionShowLog, SIGNAL(triggered()), this, SLOT(showLogWindow()));
    connect(m_pActionQuit, SIGNAL(triggered()), qApp, SLOT(quit()));
}

void MainWindow::saveSettings()
{
    settings().setValue("dashboardGeometry", saveGeometry());
    settings().setValue("dashboardTab", dashboardTabs->currentIndex());
    // program settings
    settings().setValue("groupServerChecked", m_pGroupServer->isChecked());
    settings().setValue("useExternalConfig", m_pRadioExternalConfig->isChecked());
    settings().setValue("configFile", m_pLineEditConfigFile->text());
    settings().setValue("useInternalConfig", m_pRadioInternalConfig->isChecked());
    settings().setValue("groupClientChecked", m_pGroupClient->isChecked());
    settings().setValue("serverHostname", m_pLineEditHostname->text());

    settings().sync();
}

void MainWindow::setIcon(qBarrierState state)
{
    if (m_pTrayIcon) {
        QIcon icon = QIcon::fromTheme(barrierIconNames[state], QIcon(barrierIconFiles[state]));
#if defined(Q_OS_MAC)
        icon.setIsMask(true);
#endif
        m_pTrayIcon->setIcon(icon);
    }
}

void MainWindow::trayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick)
    {
        if (isVisible())
        {
            hide();
        }
        else
        {
            showNormal();
            activateWindow();
        }
    }
}

void MainWindow::logOutput()
{
    if (m_pBarrier)
    {
        QString text(m_pBarrier->readAllStandardOutput());
        for (QString line : text.split(QRegExp("\r|\n|\r\n"))) {
            if (!line.isEmpty())
            {
                appendLogRaw(line);
            }
        }
    }
}

void MainWindow::logError()
{
    if (m_pBarrier)
    {
        appendLogRaw(m_pBarrier->readAllStandardError());
    }
}

void MainWindow::appendLogInfo(const QString& text)
{
    if (appConfig().logLevel() >= 3) {
        m_pLogWindow->appendInfo(text);
    }
}

void MainWindow::appendLogDebug(const QString& text) {
    if (appConfig().logLevel() >= 4) {
        m_pLogWindow->appendDebug(text);
    }
}

void MainWindow::appendLogError(const QString& text)
{
    m_pLogWindow->appendError(text);
}

void MainWindow::appendLogRaw(const QString& text)
{
    for (QString line : text.split(QRegExp("\r|\n|\r\n"))) {
        if (!line.isEmpty()) {
            m_pLogWindow->appendRaw(line);
            updateFromLogLine(line);
        }
    }
}

void MainWindow::updateFromLogLine(const QString &line)
{
    // TODO: this code makes Andrew cry
    checkConnected(line);
    checkFingerprint(line);
}

void MainWindow::checkConnected(const QString& line)
{
    // TODO: implement ipc connection state messages to replace this hack.
    if (line.contains("started server") ||
        line.contains("connected to server") ||
        line.contains("server status: active"))
    {
        setBarrierState(barrierConnected);

        if (!appConfig().startedBefore() && isVisible()) {
                QMessageBox::information(
                    this, "Barrier",
                    tr("Barrier is now connected. You can close the "
                    "config window and Barrier will remain connected in "
                    "the background."));

            appConfig().setStartedBefore(true);
            appConfig().saveSettings();
        }
    }
}

void MainWindow::checkFingerprint(const QString& line)
{
    QRegExp fingerprintRegex(".*peer fingerprint \\(SHA1\\): ([A-F0-9:]+) \\(SHA256\\): ([A-F0-9:]+)");
    if (!fingerprintRegex.exactMatch(line)) {
        return;
    }

    barrier::FingerprintData fingerprint_sha1 = {
        barrier::fingerprint_type_to_string(barrier::FingerprintType::SHA1),
        barrier::string::from_hex(fingerprintRegex.cap(1).toStdString())
    };

    barrier::FingerprintData fingerprint_sha256 = {
        barrier::fingerprint_type_to_string(barrier::FingerprintType::SHA256),
        barrier::string::from_hex(fingerprintRegex.cap(2).toStdString())
    };

    const BarrierType role = barrierState() == barrierDisconnected ? barrier_type() : m_ActiveRole;
    const bool is_client = role == BarrierType::Client;

    auto db_path = is_client
            ? barrier::DataDirectories::trusted_servers_ssl_fingerprints_path()
            : barrier::DataDirectories::trusted_clients_ssl_fingerprints_path();

    if (m_PeerApprovalOpen) { return; }
    m_PeerApprovalOpen = true;
    auto release = barrier::finally([this] { m_PeerApprovalOpen = false; });
    try {
        if (fingerprint_sha256.data.size() != 32) {
            throw std::runtime_error("The peer did not provide a complete SHA-256 fingerprint.");
        }
        auto database = PeerTrustStore::read(db_path);
        peerTrustError->hide();
        if (database.is_trusted(fingerprint_sha256)) { return; }
        if (is_client) { stopBarrier(); }
        FingerprintAcceptDialog dialog{this, role, fingerprint_sha1, fingerprint_sha256};
        if (dialog.exec() == QDialog::Accepted) {
            PeerTrustStore::approve(db_path, fingerprint_sha256);
            appendLogInfo(tr("Peer approval saved."));
            if (is_client && barrier_type() == role) { startBarrier(); }
        }
    } catch (const std::exception& error) {
        stopBarrier();
        const auto reason = QString::fromUtf8(error.what());
        peerTrustError->setText(tr("Peer trust update failed. Check the profile folder and retry the connection.\n%1").arg(reason));
        peerTrustError->show();
        appendLogError(tr("Peer trust update failed: %1").arg(reason));
    }
}

void MainWindow::restartBarrier()
{
    stopBarrier();
    startBarrier();
}

void MainWindow::proofreadInfo()
{
    m_pLabelPadlock->setVisible(barrierState() == barrierConnected && appConfig().getCryptoEnabled());
    updateConnectionPresentation();
}

void MainWindow::startBarrier()
{
    bool desktopMode = appConfig().processMode() == Desktop;
    bool serviceMode = appConfig().processMode() == Service;

    appendLogDebug("starting process");
    m_ExpectedRunningState = kStarted;
    setBarrierState(barrierConnecting);

    QString app;
    QStringList args;

    args << "-f" << "--no-tray" << "--debug" << appConfig().logLevelText();


    args << "--name" << getScreenName();

    if (desktopMode)
    {
        setBarrierProcess(new QProcess(this));
    }
    else
    {
        // tell client/server to talk to daemon through ipc.
        args << "--ipc";

#if defined(Q_OS_WIN)
        // tell the client/server to shut down when a ms windows desk
        // is switched; this is because we may need to elevate or not
        // based on which desk the user is in (login always needs
        // elevation, where as default desk does not).
        // Note that this is only enabled when barrier is set to elevate
        // 'as needed' (e.g. on a UAC dialog popup) in order to prevent
        // unnecessary restarts when barrier was started elevated or
        // when it is not allowed to elevate. In these cases restarting
        // the server is fruitless.
        if (appConfig().elevateMode() == ElevateAsNeeded) {
                args << "--stop-on-desk-switch";
        }
#endif
    }

#ifndef Q_OS_LINUX

    if (m_ServerConfig.enableDragAndDrop()) {
        args << "--enable-drag-drop";
    }

#endif

    if (!m_AppConfig->getCryptoEnabled()) {
        args << "--disable-crypto";
    }

#if defined(Q_OS_WIN)
    // on windows, the profile directory changes depending on the user that
    // launched the process (e.g. when launched with elevation). setting the
    // profile dir on launch ensures it uses the same profile dir is used
    // no matter how its relaunched.
    args << "--profile-dir" << QString::fromStdString("\"" + barrier::DataDirectories::profile().u8string() + "\"");
#endif

    if ((barrier_type() == BarrierType::Client && !clientArgs(args, app))
        || (barrier_type() == BarrierType::Server && !serverArgs(args, app)))
    {
        stopBarrier();
        return;
    }

    if (desktopMode)
    {
        connect(barrierProcess(), SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(barrierFinished(int, QProcess::ExitStatus)));
        connect(barrierProcess(), SIGNAL(readyReadStandardOutput()), this, SLOT(logOutput()));
        connect(barrierProcess(), SIGNAL(readyReadStandardError()), this, SLOT(logError()));
    }

    m_pLogWindow->startNewInstance();

    appendLogInfo("starting " + QString(barrier_type() == BarrierType::Server ? "server" : "client"));

    qDebug() << args;

    appendLogDebug(QString("command: %1 %2").arg(app, args.join(" ")));

    appendLogInfo("config file: " + configFilename());
    appendLogInfo("log level: " + appConfig().logLevelText());

    if (appConfig().logToFile())
        appendLogInfo("log file: " + appConfig().logFilename());

    if (desktopMode)
    {
        barrierProcess()->start(app, args);
        if (!barrierProcess()->waitForStarted())
        {
            show();
            QMessageBox::warning(this, tr("Program can not be started"), QString(tr("The executable<br><br>%1<br><br>could not be successfully started, although it does exist. Please check if you have sufficient permissions to run this program.").arg(app)));
            return;
        }
    }

    if (serviceMode)
    {
        QString command(app + " " + args.join(" "));
        m_IpcClient.sendCommand(command, appConfig().elevateMode());
    }
}

bool MainWindow::clientArgs(QStringList& args, QString& app)
{
    app = appPath(appConfig().barriercName());

    if (!QFile::exists(app))
    {
        show();
        QMessageBox::warning(this, tr("Barrier client not found"),
                             tr("The executable for the barrier client does not exist."));
        return false;
    }

#if defined(Q_OS_WIN)
    // wrap in quotes so a malicious user can't start \Program.exe as admin.
    app = QString("\"%1\"").arg(app);
#endif

    if (appConfig().logToFile())
    {
        appConfig().persistLogDir();
        args << "--log" << appConfig().logFilenameCmd();
    }

    // check auto config first, if it is disabled or no server detected,
    // use line edit host name if it is not empty
    if (m_pCheckBoxAutoConfig->isChecked()) {
        if (m_pComboServerList->count() != 0) {
            QString serverIp = m_pComboServerList->currentText();
            args << "[" + serverIp + "]:" + QString::number(appConfig().port());
            return true;
        }
    } else if (m_pLineEditHostname->text().isEmpty()) {
        show();
        if (!m_SuppressEmptyServerWarning) {
            QMessageBox::warning(this, tr("Hostname is empty"),
                             tr("Please fill in a hostname for the barrier client to connect to."));
        }
        return false;
    }

    args << "[" + m_pLineEditHostname->text() + "]:" + QString::number(appConfig().port());

    return true;
}

QString MainWindow::configFilename()
{
    QString filename;
    if (m_pRadioInternalConfig->isChecked())
    {
        // TODO: no need to use a temporary file, since we need it to
        // be permanent (since it'll be used for Windows services, etc).
        m_pTempConfigFile = new QTemporaryFile();
        if (!m_pTempConfigFile->open())
        {
            QMessageBox::critical(this, tr("Cannot write configuration file"), tr("The temporary configuration file required to start barrier can not be written."));
            return "";
        }

        serverConfig().save(*m_pTempConfigFile);
        filename = m_pTempConfigFile->fileName();

        m_pTempConfigFile->close();
    }
    else
    {
        if (!QFile::exists(m_pLineEditConfigFile->text()))
        {
            if (QMessageBox::warning(this, tr("Configuration filename invalid"),
                tr("You have not filled in a valid configuration file for the barrier server. "
                        "Do you want to browse for the configuration file now?"), QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes
                    || !on_m_pButtonBrowseConfigFile_clicked())
                return "";
        }

        filename = m_pLineEditConfigFile->text();
    }
    return filename;
}

BarrierType MainWindow::barrier_type() const
{
    return m_pGroupClient->isChecked() ? BarrierType::Client : BarrierType::Server;
}

QString MainWindow::address()
{
    QString address = appConfig().networkInterface();
    if (!address.isEmpty())
        address = "[" + address + "]";
    return address + ":" + QString::number(appConfig().port());
}

QString MainWindow::appPath(const QString& name)
{
    return appConfig().barrierProgramDir() + name;
}

bool MainWindow::serverArgs(QStringList& args, QString& app)
{
    app = appPath(appConfig().barriersName());

    if (!QFile::exists(app))
    {
        QMessageBox::warning(this, tr("Barrier server not found"),
                             tr("The executable for the barrier server does not exist."));
        return false;
    }

#if defined(Q_OS_WIN)
    // wrap in quotes so a malicious user can't start \Program.exe as admin.
    app = QString("\"%1\"").arg(app);
#endif

    if (appConfig().logToFile())
    {
        appConfig().persistLogDir();

        args << "--log" << appConfig().logFilenameCmd();
    }

    if (!appConfig().getRequireClientCertificate()) {
        args << "--disable-client-cert-checking";
    }

    QString configFilename = this->configFilename();
#if defined(Q_OS_WIN)
    // wrap in quotes in case username contains spaces.
    configFilename = QString("\"%1\"").arg(configFilename);
#endif
    args << "-c" << configFilename << "--address" << address();

    return true;
}

void MainWindow::stopBarrier()
{
    appendLogDebug("stopping process");

    m_ExpectedRunningState = kStopped;

    if (appConfig().processMode() == Service)
    {
        stopService();
    }
    else if (appConfig().processMode() == Desktop)
    {
        stopDesktop();
    }

    setBarrierState(barrierDisconnected);

    // HACK: deleting the object deletes the physical file, which is
    // bad, since it could be in use by the Windows service!
#if !defined(Q_OS_WIN)
    delete m_pTempConfigFile;
#endif
    m_pTempConfigFile = NULL;

    // reset so that new connects cause auto-hide.
    m_AlreadyHidden = false;
}

void MainWindow::stopService()
{
    // send empty command to stop service from launching anything.
    m_IpcClient.sendCommand("", appConfig().elevateMode());
}

void MainWindow::stopDesktop()
{
    QMutexLocker locker(&m_StopDesktopMutex);
    if (!barrierProcess()) {
        return;
    }

    appendLogInfo("stopping barrier desktop process");

    if (barrierProcess()->isOpen()) {
        // try to shutdown child gracefully
        barrierProcess()->write(&ShutdownCh, 1);
        barrierProcess()->waitForFinished(5000);
        barrierProcess()->close();
    }

    delete barrierProcess();
    setBarrierProcess(NULL);
}

void MainWindow::barrierFinished(int exitCode, QProcess::ExitStatus)
{
    if (exitCode == 0) {
        appendLogInfo(QString("process exited normally"));
    }
    else {
        appendLogError(QString("process exited with error code: %1").arg(exitCode));
    }

    if (m_ExpectedRunningState == kStarted) {
        QTimer::singleShot(1000, this, SLOT(startBarrier()));
        appendLogInfo(QString("detected process not running, auto restarting"));
    }
    else {
        setBarrierState(barrierDisconnected);
    }
}

void MainWindow::setBarrierState(qBarrierState state)
{
    if (barrierState() == state)
        return;

    if (barrierState() == barrierDisconnected && state != barrierDisconnected) {
        // Configuration can change while the engine runs. Its role cannot follow a checkbox.
        m_ActiveRole = barrier_type();
    }
    if (state != barrierDisconnected)
    {
        disconnect (m_pButtonToggleStart, SIGNAL(clicked()), m_pActionStartBarrier, SLOT(trigger()));
        connect (m_pButtonToggleStart, SIGNAL(clicked()), m_pActionStopBarrier, SLOT(trigger()), Qt::UniqueConnection);
        m_pButtonToggleStart->setText(tr("&Stop"));
        m_pButtonReload->setEnabled(true);
    }
    else if (state == barrierDisconnected)
    {
        disconnect (m_pButtonToggleStart, SIGNAL(clicked()), m_pActionStopBarrier, SLOT(trigger()));
        connect (m_pButtonToggleStart, SIGNAL(clicked()), m_pActionStartBarrier, SLOT(trigger()), Qt::UniqueConnection);
        m_pButtonToggleStart->setText(tr("&Start"));
        m_pButtonReload->setEnabled(false);
    }

    const bool active = state != barrierDisconnected;
    m_pActionStartBarrier->setEnabled(!active);
    m_pActionStopBarrier->setEnabled(active);

    switch (state)
    {
    case barrierConnected: {
        if (m_AppConfig->getCryptoEnabled()) {
            m_pLabelPadlock->show();
        }
        else {
            m_pLabelPadlock->hide();
        }
        break;
    }
    case barrierConnecting:
        m_pLabelPadlock->hide();
        break;
    case barrierDisconnected:
        m_pLabelPadlock->hide();
        break;
    case barrierTransfering:
        break;
    }

    setIcon(state);

    m_BarrierState = state;
    updateConnectionPresentation();
}

void MainWindow::setVisible(bool visible)
{
    QMainWindow::setVisible(visible);
    m_pActionMinimize->setEnabled(visible);
    m_pActionRestore->setEnabled(!visible);

#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070 // lion
    // dock hide only supported on lion :(
    ProcessSerialNumber psn = { 0, kCurrentProcess };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    GetCurrentProcess(&psn);
#pragma GCC diagnostic pop
    if (visible)
        TransformProcessType(&psn, kProcessTransformToForegroundApplication);
    else
        TransformProcessType(&psn, kProcessTransformToBackgroundApplication);
#endif
}

QString MainWindow::getIPAddresses()
{
    QStringList addresses;
    for (const auto& address : QNetworkInterface::allAddresses()) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol && !address.isLoopback()) {
            addresses.append(address.toString());
        }
    }
    addresses.removeDuplicates();
    m_CopyableAddresses = addresses.join(QStringLiteral(", "));
    return addresses.isEmpty() ? tr("No IPv4 address available") : m_CopyableAddresses;
}

QString MainWindow::getScreenName()
{
    if (appConfig().screenName() == "") {
        return QHostInfo::localHostName();
    }
    else {
        return appConfig().screenName();
    }
}

void MainWindow::changeEvent(QEvent* event)
{
    if (event != 0)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
        {
            const bool expanded = m_fingerprint_expanded;
            retranslateUi(this);
            m_pLabelScreenName->setText(getScreenName());
            m_pLabelIpAddresses->setText(getIPAddresses());
            copyAddresses->setEnabled(!m_CopyableAddresses.isEmpty());
            updateSSLFingerprint();
            if (expanded && toolbutton_show_fingerprint->isEnabled()) {
                toolbutton_show_fingerprint->setChecked(true);
                frame_fingerprint_details->show();
                toolbutton_show_fingerprint->setArrowType(Qt::UpArrow);
                m_fingerprint_expanded = true;
            }
            retranslateMenuBar();
            updateDiscoveryControls();

            updateConnectionPresentation();

            break;
        }
        case QEvent::WindowStateChange:
        {
            windowStateChanged();
            break;
        }
        default:
        {
            break;
        }
        }
    }
    // all that do not return are allowing the event to propagate
    QMainWindow::changeEvent(event);
}

void MainWindow::updateZeroconfService()
{
#if BARRIER_WITH_DISCOVERY
    QMutexLocker locker(&m_UpdateZeroconfMutex);
    delete m_pZeroconfService;
    m_pZeroconfService = nullptr;
    if (discoveryAvailable() && !m_AppConfig->wizardShouldRun() &&
            (m_pCheckBoxAutoConfig->isChecked() || barrier_type() == BarrierType::Server)) {
        m_pZeroconfService = new ZeroconfService(this);
    }
#endif
}

void MainWindow::serverDetected(const QString name)
{
    // I ignore late discovery results once the user is choosing a manual address.
    if (!m_pCheckBoxAutoConfig->isChecked() || !discoveryAvailable()) {
        return;
    }
    if (m_pComboServerList->findText(name) == -1) {
        // Note: the first added item triggers startBarrier
        m_pComboServerList->addItem(name);
    }

    if (m_pComboServerList->count() > 1) {
        m_pComboServerList->show();
    }
}

void MainWindow::updateSSLFingerprint(bool retry)
{
    if (m_AppConfig->getCryptoEnabled() && m_pSslCertificate == nullptr) {
        m_pSslCertificate = new SslCertificate(this);
        connect(m_pSslCertificate, &SslCertificate::info, [&](QString info)
        {
            appendLogInfo(info);
        });
        connect(m_pSslCertificate, &SslCertificate::error, this, [this](const QString& message) {
            m_IdentityError = message;
            appendLogError(message);
        });
        retry = true;
    }
    if (m_AppConfig->getCryptoEnabled() && retry) {
        m_IdentityError.clear();
        m_pSslCertificate->generateCertificate();
    }

    toolbutton_show_fingerprint->setEnabled(false);
    toolbutton_show_fingerprint->setChecked(false);
    toolbutton_show_fingerprint->setArrowType(Qt::DownArrow);
    frame_fingerprint_details->hide();
    m_fingerprint_expanded = false;
    copyFingerprint->setEnabled(false);
    m_CopyableFingerprint.clear();
    label_sha1_fingerprint_full->clear();
    label_sha256_fingerprint_full->clear();
    label_sha256_randomart->clear();
    m_pLabelLocalFingerprint->setText(m_AppConfig->getCryptoEnabled() ?
        tr("Unavailable") : tr("Encryption is off"));

    identityError->hide();
    retryIdentity->hide();
    identityAlert->hide();
    reviewIdentity->hide();
    const auto report = [this](const QString& reason) {
        identityError->setText(tr("Secure identity unavailable. Check access to your profile folder, then retry. "
                                  "Open the log with F2 for details.\n%1").arg(reason));
        identityError->show();
        retryIdentity->show();
        identityAlert->show();
        reviewIdentity->show();
    };
    if (!m_AppConfig->getCryptoEnabled()) { return; }
    if (!m_IdentityError.isEmpty()) {
        report(m_IdentityError);
        return;
    }
    barrier::FingerprintDatabase db;
    try {
        const auto local_path = barrier::DataDirectories::local_ssl_fingerprints_path();
        if (!barrier::fs::exists(local_path)) {
            report(tr("Public fingerprints are missing. Retry to rebuild them from the existing identity."));
            return;
        }
        db.read(local_path);
        if (db.fingerprints().size() != 2) {
            report(tr("Public fingerprints could not be read. Retry to rebuild them from the existing identity."));
            return;
        }
    } catch (const std::exception& error) {
        report(QString::fromUtf8(error.what()));
        return;
    }

    for (const auto& fingerprint : db.fingerprints()) {
        if (fingerprint.algorithm == "sha1" && fingerprint.data.size() == 20) {
            auto fingerprint_str = barrier::format_ssl_fingerprint(fingerprint.data);
            label_sha1_fingerprint_full->setText(QString::fromStdString(fingerprint_str));
            continue;
        }

        if (fingerprint.algorithm == "sha256" && fingerprint.data.size() == 32) {
            auto fingerprint_str = barrier::format_ssl_fingerprint(fingerprint.data);
            m_CopyableFingerprint = QString::fromStdString(fingerprint_str);
            fingerprint_str.resize(40);
            fingerprint_str += " ...";

            auto fingerprint_str_cols = barrier::format_ssl_fingerprint_columns(fingerprint.data);
            auto fingerprint_randomart = barrier::create_fingerprint_randomart(fingerprint.data);

            m_pLabelLocalFingerprint->setText(QString::fromStdString(fingerprint_str));
            label_sha256_fingerprint_full->setText(QString::fromStdString(fingerprint_str_cols));
            label_sha256_randomart->setText(QString::fromStdString(fingerprint_randomart));
        }
    }

    if (m_CopyableFingerprint.isEmpty()) {
        report(tr("The public SHA-256 fingerprint is invalid. Retry to rebuild it from the existing identity."));
    }
    toolbutton_show_fingerprint->setEnabled(!m_CopyableFingerprint.isEmpty());
    copyFingerprint->setEnabled(!m_CopyableFingerprint.isEmpty());
}

void MainWindow::on_m_pGroupClient_toggled(bool on)
{
    m_pGroupServer->setChecked(!on);
    updateConnectionPresentation();
    if (on) {
        updateZeroconfService();
    }
}

void MainWindow::on_m_pGroupServer_toggled(bool on)
{
    m_pGroupClient->setChecked(!on);
    updateConnectionPresentation();
    if (on) {
        updateZeroconfService();
    }
}

bool MainWindow::on_m_pButtonBrowseConfigFile_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Browse for a barriers config file"), QString(), barrierConfigOpenFilter);

    if (!fileName.isEmpty())
    {
        m_pLineEditConfigFile->setText(fileName);
        return true;
    }

    return false;
}

bool MainWindow::on_m_pActionSave_triggered()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save configuration as..."), QString(), barrierConfigSaveFilter);

    if (!fileName.isEmpty() && !serverConfig().save(fileName))
    {
        QMessageBox::warning(this, tr("Save failed"), tr("Could not save configuration to file."));
        return true;
    }

    return false;
}

void MainWindow::on_m_pActionAbout_triggered()
{
    AboutDialog(this, appPath(appConfig().barriercName())).exec();
}

void MainWindow::on_m_pActionSettings_triggered()
{
    if (SettingsDialog(this, appConfig()).exec() == QDialog::Accepted) {
        m_pLabelScreenName->setText(getScreenName());
        m_pLabelIpAddresses->setText(getIPAddresses());
        copyAddresses->setEnabled(!m_CopyableAddresses.isEmpty());
        updateSSLFingerprint();
        updateConnectionPresentation();
    }
}

void MainWindow::autoAddScreen(const QString name)
{
    if (!m_ServerConfig.ignoreAutoConfigClient()) {
        int r = m_ServerConfig.autoAddScreen(name);
        if (r != kAutoAddScreenOk) {
            switch (r) {
            case kAutoAddScreenManualServer:
                showConfigureServer(
                    tr("Please add the server (%1) to the grid.")
                        .arg(appConfig().screenName()));
                break;

            case kAutoAddScreenManualClient:
                showConfigureServer(
                    tr("Please drag the new client screen (%1) "
                        "to the desired position on the grid.")
                        .arg(name));
                break;
            }
        }
        else {
            restartBarrier();
        }
    }
}

void MainWindow::showConfigureServer(const QString& message)
{
    ServerConfigDialog dlg(this, serverConfig(), appConfig().screenName());
    dlg.message(message);
    dlg.exec();
}

void MainWindow::on_m_pButtonConfigureServer_clicked()
{
    showConfigureServer();
}

void MainWindow::on_m_pButtonReload_clicked()
{
    restartBarrier();
}

#if defined(Q_OS_WIN)
bool MainWindow::isServiceRunning(QString name)
{
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        appendLogDebug(tr("Cannot query discovery service status (%1)").arg(GetLastError()));
        return false;
    }
    auto close_manager = barrier::finally([&] { CloseServiceHandle(manager); });
    const auto native_name = name.toStdWString();
    SC_HANDLE service = OpenServiceW(manager, native_name.c_str(), SERVICE_QUERY_STATUS);
    if (!service) { return false; }
    auto close_service = barrier::finally([&] { CloseServiceHandle(service); });
    SERVICE_STATUS status{};
    return QueryServiceStatus(service, &status) && status.dwCurrentState == SERVICE_RUNNING;
}
#endif

bool MainWindow::discoveryAvailable()
{
#if !BARRIER_WITH_DISCOVERY
    return false;
#elif defined(Q_OS_WIN)
    return isServiceRunning(QStringLiteral("Bonjour Service"));
#else
    return true;
#endif
}

void MainWindow::updateDiscoveryControls()
{
    const bool available = discoveryAvailable();
    const bool automatic = available && appConfig().autoConfig();
    const bool changed = available != m_DiscoveryWasAvailable ||
        automatic != m_pCheckBoxAutoConfig->isChecked();
    m_DiscoveryWasAvailable = available;
    // I keep the saved preference when the backend is absent. A build switch isn't a user choice.
    const QSignalBlocker blocker(m_pCheckBoxAutoConfig);
    m_pCheckBoxAutoConfig->setChecked(automatic);
    m_pCheckBoxAutoConfig->setEnabled(BARRIER_WITH_DISCOVERY);
    const QString guidance = !available ?
        tr("Automatic discovery is unavailable. Enter a server name or IP address.") :
        automatic ? tr("Automatic discovery is enabled. Turn it off to enter a server address.") :
        tr("Enter the server's name or IP address. Discovery is optional.");
    m_pCheckBoxAutoConfig->setToolTip(guidance);
    discoveryHint->setText(guidance);
    m_pLineEditHostname->setEnabled(!automatic);
    if (!automatic) {
        const QSignalBlocker list_blocker(m_pComboServerList);
        m_pComboServerList->clear();
        m_pComboServerList->hide();
    }
    // Blocked checkbox signals mustn't leave recovered discovery without a reader.
    if (changed) { updateZeroconfService(); }
    // FUTURE(BX-007): show discovery availability separately from connection and peer approval.
}

void MainWindow::on_m_pComboServerList_currentIndexChanged(QString )
{
    if (m_pComboServerList->count() != 0) {
        restartBarrier();
    }
}

void MainWindow::on_m_pCheckBoxAutoConfig_toggled(bool checked)
{
    if (checked && !discoveryAvailable()) {
        updateDiscoveryControls();
        appendLogInfo(tr("Automatic discovery is unavailable. Enter a server name or IP address."));
        return;
    }
    appConfig().setAutoConfig(checked);
    updateDiscoveryControls();
    updateZeroconfService();
}

void MainWindow::windowStateChanged()
{
    if (windowState() == Qt::WindowMinimized && appConfig().getMinimizeToTray())
        hide();
}

void MainWindow::showLogWindow()
{
    m_pLogWindow->show();
}
