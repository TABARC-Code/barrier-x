/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "../src/MainWindow.h"
#include "../src/FingerprintAcceptDialog.h"
#include "common/DataDirectories.h"
#include "common/Version.h"
#include <gtest/gtest.h>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QEvent>
#include <QFile>
#include <QLineEdit>
#include <QTemporaryDir>
#include <memory>
#include <QClipboard>
#include <QLabel>
#include <QToolButton>
#include <QPushButton>
#include <QKeyEvent>
#include <QTabWidget>
#include <QTabBar>
#include <QScrollArea>
#include <QScrollBar>
#include <QRadioButton>
#include "../src/SettingsDialog.h"
#include <QTimer>
#include <QDialog>
#include <QGroupBox>
#include <QHostAddress>
#include "net/FingerprintDatabase.h"
#include "net/SecureUtils.h"
#if BARRIER_WITH_DISCOVERY
#include "../src/ZeroconfServer.h"
#include <QTcpSocket>
#include <QThread>
#endif

class DiscoveryWindow : public MainWindow {
public:
    using MainWindow::MainWindow;
    using MainWindow::clientArgs;
    using MainWindow::setBarrierState;
    using MainWindow::updateSSLFingerprint;
    using MainWindow::checkFingerprint;
    using MainWindow::discoveryAvailable;
    using MainWindow::updateDiscoveryControls;
};
class RecoveryWindow : public DiscoveryWindow {
public:
    using DiscoveryWindow::DiscoveryWindow;
    bool available = false;
    int lifecycleUpdates = 0;
    bool discoveryAvailable() override { return available; }
    void updateZeroconfService() override { ++lifecycleUpdates; }
};
class DiscoveryTests : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(temporary.isValid());
        previous = barrier::DataDirectories::profile();
        barrier::DataDirectories::profile(barrier::fs::u8path(temporary.path().toStdString()));
        settings.reset(new QSettings(temporary.filePath("settings.ini"), QSettings::IniFormat));
        settings->setValue("serverHostname", "manual.example");
        settings->setValue("groupClientChecked", true);
        settings->setValue("groupServerChecked", false);
        settings->setValue("autoStart", false);
        settings->setValue("autoHide", false);
        settings->setValue("startedBefore", false);
        settings->setValue("wizardLastRun", 0);
        settings->setValue("cryptoEnabled", false);
        settings->setValue("logToFile", false);
        settings->setValue("port", 24801);
    }
    void TearDown() override {
        window.reset(); config.reset(); settings.reset();
        barrier::DataDirectories::profile(previous);
    }
    void create(bool automatic) {
        settings->setValue("wizardLastRun", 0);
        settings->setValue("autoConfig", automatic);
        config.reset(new AppConfig(settings.get()));
        window.reset(new DiscoveryWindow(*settings, *config));
    }
    QCheckBox* automatic() { return window->findChild<QCheckBox*>("m_pCheckBoxAutoConfig"); }
    QLineEdit* hostname() { return window->findChild<QLineEdit*>("m_pLineEditHostname"); }
    QComboBox* servers() { return window->findChild<QComboBox*>("m_pComboServerList"); }
    QTemporaryDir temporary;
    barrier::fs::path previous;
    std::unique_ptr<QSettings> settings;
    std::unique_ptr<AppConfig> config;
    std::unique_ptr<DiscoveryWindow> window;
};
TEST_F(DiscoveryTests, ManualChoiceKeepsAddressAndIgnoresLateDiscovery)
{
    create(false);
    ASSERT_NE(nullptr, automatic()); ASSERT_NE(nullptr, hostname()); ASSERT_NE(nullptr, servers());
    EXPECT_FALSE(automatic()->isChecked());
    EXPECT_TRUE(hostname()->isEnabled());
    window->serverDetected("late-discovered.example");
    EXPECT_EQ(0, servers()->count());
    EXPECT_EQ(QString("manual.example"), hostname()->text());
    QStringList args; QString executable;
    ASSERT_TRUE(QFile::exists(QCoreApplication::applicationDirPath() + "/" + config->barriercName()));
    ASSERT_TRUE(window->clientArgs(args, executable));
    EXPECT_EQ(QString("[manual.example]:24801"), args.last());
}
TEST_F(DiscoveryTests, OpeningWindowNeedsNoDiscoveryInstallerPrompt)
{
    create(false);
    window->open();
    QApplication::processEvents();
    EXPECT_EQ(nullptr, QApplication::activeModalWidget());
    EXPECT_TRUE(hostname()->isEnabled());
    EXPECT_EQ(QString("manual.example"), window->hostname());
}
#if !BARRIER_WITH_DISCOVERY
TEST_F(DiscoveryTests, UnavailableBuildPreservesSavedAutomaticPreference)
{
    create(true);
    EXPECT_FALSE(window->discoveryAvailable());
    EXPECT_FALSE(automatic()->isChecked());
    EXPECT_FALSE(automatic()->isEnabled());
    EXPECT_FALSE(automatic()->toolTip().isEmpty());
    EXPECT_TRUE(hostname()->isEnabled());
    EXPECT_TRUE(config->autoConfig());
    window.reset(); config.reset();
    EXPECT_TRUE(settings->value("autoConfig").toBool());
    EXPECT_EQ(QString("manual.example"), settings->value("serverHostname").toString());
}
TEST_F(DiscoveryTests, StaleAutomaticToggleKeepsManualControlsUsable)
{
    create(true);
    ASSERT_TRUE(QMetaObject::invokeMethod(window.get(), "on_m_pCheckBoxAutoConfig_toggled", Qt::DirectConnection, Q_ARG(bool, true)));
    EXPECT_FALSE(automatic()->isChecked());
    EXPECT_FALSE(automatic()->isEnabled());
    EXPECT_TRUE(hostname()->isEnabled());
    EXPECT_TRUE(config->autoConfig());
    EXPECT_EQ(0, servers()->count());
}
TEST_F(DiscoveryTests, LanguageChangeKeepsUnavailableDiscoveryInManualMode)
{
    create(true);
    QEvent language(QEvent::LanguageChange);
    QApplication::sendEvent(window.get(), &language);
    EXPECT_FALSE(automatic()->isChecked());
    EXPECT_FALSE(automatic()->isEnabled());
    EXPECT_TRUE(hostname()->isEnabled());
    EXPECT_FALSE(automatic()->toolTip().isEmpty());
    EXPECT_TRUE(config->autoConfig());
}
#else
TEST_F(DiscoveryTests, ExplicitManualChoiceUpdatesTheSavedPreference)
{
    create(true);
    if (!window->discoveryAvailable()) { GTEST_SKIP() << "Discovery provider is unavailable"; }
    ASSERT_TRUE(automatic()->isChecked());
    automatic()->setChecked(false);
    EXPECT_FALSE(config->autoConfig());
    EXPECT_TRUE(hostname()->isEnabled());
    window.reset(); config.reset();
    EXPECT_FALSE(settings->value("autoConfig").toBool());
}
#endif

#if BARRIER_WITH_DISCOVERY
TEST_F(DiscoveryTests, AvailabilityRefreshReconcilesReaderAndControls)
{
    settings->setValue("autoConfig", true);
    config.reset(new AppConfig(settings.get()));
    RecoveryWindow recovery(*settings, *config);
    recovery.updateDiscoveryControls();
    const int initial = recovery.lifecycleUpdates;
    auto* checkbox = recovery.findChild<QCheckBox*>("m_pCheckBoxAutoConfig");
    auto* address = recovery.findChild<QLineEdit*>("m_pLineEditHostname");
    EXPECT_FALSE(checkbox->isChecked());
    recovery.available = true;
    recovery.updateDiscoveryControls();
    EXPECT_EQ(initial + 1, recovery.lifecycleUpdates);
    EXPECT_TRUE(checkbox->isChecked());
    EXPECT_FALSE(address->isEnabled());
    recovery.updateDiscoveryControls();
    EXPECT_EQ(initial + 1, recovery.lifecycleUpdates);
    recovery.available = false;
    recovery.updateDiscoveryControls();
    EXPECT_EQ(initial + 2, recovery.lifecycleUpdates);
    EXPECT_FALSE(checkbox->isChecked());
    EXPECT_TRUE(address->isEnabled());
    EXPECT_TRUE(config->autoConfig());
}
TEST(DiscoveryListenerTests, AcceptedConnectionsLeaveNoWorkersOrPendingSockets)
{
    for (int attempt = 0; attempt != 20; ++attempt) {
        ZeroconfServer listener;
        ASSERT_TRUE(listener.listen(QHostAddress::LocalHost, 0));
        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, listener.serverPort());
        ASSERT_TRUE(client.waitForConnected(2000));
        ASSERT_TRUE(listener.waitForNewConnection(2000));
        EXPECT_FALSE(listener.hasPendingConnections());
        EXPECT_TRUE(listener.findChildren<QTcpSocket*>().isEmpty());
        EXPECT_TRUE(listener.findChildren<QThread*>().isEmpty());
    }
}
#endif

TEST_F(DiscoveryTests, ConnectionStatusSurvivesLanguageRefreshAndCanBeStopped)
{
    create(false);
    auto* status = window->findChild<QLabel*>("m_pStatusLabel");
    EXPECT_EQ(QString("Stopped"), status->text());
    window->setBarrierState(MainWindow::barrierConnecting);
    EXPECT_EQ(QString("Connecting to server"), status->text());
    EXPECT_TRUE(window->findChild<QAction*>("m_pActionStopBarrier")->isEnabled());
    EXPECT_FALSE(window->findChild<QAction*>("m_pActionStartBarrier")->isEnabled());
    QEvent language(QEvent::LanguageChange);
    QApplication::sendEvent(window.get(), &language);
    EXPECT_EQ(QString("Connecting to server"), status->text());
    EXPECT_EQ(QString("&Stop"), window->findChild<QPushButton*>("m_pButtonToggleStart")->text());
    window->setBarrierState(MainWindow::barrierConnected);
    window->findChild<QGroupBox*>("m_pGroupServer")->setChecked(true);
    EXPECT_EQ(QString("Connected to server"), status->text());
    EXPECT_TRUE(window->findChild<QLabel*>("connectionHint")->text().contains("new computer role"));
    int stops = 0;
    const auto countStops = QObject::connect(window->findChild<QAction*>("m_pActionStopBarrier"),
        &QAction::triggered, [&stops] { ++stops; });
    window->findChild<QPushButton*>("m_pButtonToggleStart")->click();
    QObject::disconnect(countStops);
    EXPECT_EQ(1, stops);
    EXPECT_EQ(QString("Stopped"), status->text());
    window->setBarrierState(MainWindow::barrierConnecting);
    EXPECT_EQ(QString("Starting server"), status->text());
    window->setBarrierState(MainWindow::barrierConnected);
    EXPECT_EQ(QString("Server running"), status->text());
}
TEST_F(DiscoveryTests, DiscoveryGuidanceIsVisibleWithoutHovering)
{
    create(false);
    auto* hint = window->findChild<QLabel*>("discoveryHint");
    ASSERT_NE(nullptr, hint);
    EXPECT_FALSE(hint->text().isEmpty());
    EXPECT_TRUE(hint->wordWrap());
    EXPECT_EQ(Qt::PlainText, hint->textFormat());
    EXPECT_FALSE(hostname()->placeholderText().isEmpty());
    EXPECT_EQ(QString("Server address"), hostname()->accessibleName());
}
TEST_F(DiscoveryTests, AddressCopyUsesPlainAddressesOrLeavesClipboardUntouched)
{
    create(false);
    window->findChild<QGroupBox*>("m_pGroupServer")->setChecked(true);
    auto* copy = window->findChild<QToolButton*>("copyAddresses");
    if (!copy->isEnabled()) {
        QApplication::clipboard()->setText("unchanged");
        copy->click();
        EXPECT_EQ(QString("unchanged"), QApplication::clipboard()->text());
        return;
    }
    window->findChild<QLabel*>("m_pLabelIpAddresses")->setText("<b>display text</b>");
    copy->click();
    const QString copied = QApplication::clipboard()->text();
    EXPECT_FALSE(copied.contains('<'));
    for (const auto& address : copied.split(", ")) {
        EXPECT_EQ(QAbstractSocket::IPv4Protocol, QHostAddress(address).protocol());
        EXPECT_FALSE(QHostAddress(address).isLoopback());
    }
}
TEST_F(DiscoveryTests, FingerprintCopyUsesFullSha256AndClearsWhenDisabled)
{
    settings->setValue("cryptoEnabled", true);
    create(false);
    barrier::FingerprintDatabase database;
    database.read(barrier::DataDirectories::local_ssl_fingerprints_path());
    QString expected;
    for (const auto& fingerprint : database.fingerprints()) {
        if (fingerprint.algorithm == "sha256") {
            expected = QString::fromStdString(barrier::format_ssl_fingerprint(fingerprint.data));
        }
    }
    ASSERT_EQ(95, expected.size());
    auto* copy = window->findChild<QToolButton*>("copyFingerprint");
    ASSERT_TRUE(copy->isEnabled());
    copy->click();
    EXPECT_EQ(expected, QApplication::clipboard()->text());
    EXPECT_FALSE(QApplication::clipboard()->text().contains("..."));
    auto* details = window->findChild<QToolButton*>("toolbutton_show_fingerprint");
    details->click();
    EXPECT_TRUE(details->isChecked());
    QEvent language(QEvent::LanguageChange);
    QApplication::sendEvent(window.get(), &language);
    EXPECT_TRUE(details->isChecked());
    copy->click();
    EXPECT_EQ(expected, QApplication::clipboard()->text());
    config->setCryptoEnabled(false);
    window->updateSSLFingerprint();
    EXPECT_FALSE(copy->isEnabled());
    EXPECT_FALSE(details->isChecked());
    EXPECT_TRUE(window->findChild<QLabel*>("label_sha256_fingerprint_full")->text().isEmpty());
    QApplication::clipboard()->setText("unchanged");
    copy->click();
    EXPECT_EQ(QString("unchanged"), QApplication::clipboard()->text());
}
TEST_F(DiscoveryTests, KeyboardNavigationLeavesStartAndTheWindowCanGrow)
{
    create(false);
    window->show();
    QApplication::processEvents();
    auto* start = window->findChild<QPushButton*>("m_pButtonToggleStart");
    start->setFocus();
    QKeyEvent tab(QEvent::KeyPress, Qt::Key_Tab, Qt::NoModifier);
    QApplication::sendEvent(start, &tab);
    EXPECT_EQ(window->findChild<QTabWidget*>("dashboardTabs")->tabBar(), window->focusWidget());
    const QSize previousSize = window->size();
    window->resize(previousSize + QSize(160, 80));
    QApplication::processEvents();
    EXPECT_GT(window->width(), previousSize.width());
    EXPECT_GT(window->height(), previousSize.height());
}

TEST_F(DiscoveryTests, EditingTheRoleKeepsTheRunningPeersTrustContext)
{
    create(false);
    window->setBarrierState(MainWindow::barrierConnecting);
    window->findChild<QGroupBox*>("m_pGroupServer")->setChecked(true);
    barrier::FingerprintData peer{"sha256", std::vector<std::uint8_t>(32, 0x42)};
    const auto path = barrier::DataDirectories::trusted_servers_ssl_fingerprints_path();
    barrier::fs::create_directories(path.parent_path());
    barrier::FingerprintDatabase database;
    database.add_trusted(peer);
    database.write(path);
    bool prompted = false;
    QTimer cancelUnexpectedPrompt;
    cancelUnexpectedPrompt.setSingleShot(true);
    QObject::connect(&cancelUnexpectedPrompt, &QTimer::timeout, [&prompted] {
        prompted = true;
        if (auto* dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget())) { dialog->reject(); }
    });
    cancelUnexpectedPrompt.start(0);
    window->checkFingerprint(QString("peer fingerprint (SHA1): %1 (SHA256): %2")
        .arg(QString::fromStdString(barrier::format_ssl_fingerprint(std::vector<std::uint8_t>(20, 0x11))))
        .arg(QString::fromStdString(barrier::format_ssl_fingerprint(peer.data))));
    cancelUnexpectedPrompt.stop();
    EXPECT_FALSE(prompted);
    EXPECT_EQ(MainWindow::barrierConnecting, window->barrierState());
}

TEST(PeerApprovalTests, ReturnAndEscapeRejectWhileTrustNeedsAnExplicitAction)
{
    const barrier::FingerprintData sha1{"sha1", std::vector<std::uint8_t>(20, 0x11)};
    const barrier::FingerprintData sha256{"sha256", std::vector<std::uint8_t>(32, 0x42)};
    for (const int key : {Qt::Key_Return, Qt::Key_Escape}) {
        FingerprintAcceptDialog dialog(nullptr, BarrierType::Client, sha1, sha256);
        int approvals = 0, rejections = 0;
        QObject::connect(&dialog, &QDialog::accepted, [&] { ++approvals; });
        QObject::connect(&dialog, &QDialog::rejected, [&] { ++rejections; });
        dialog.show();
        QApplication::processEvents();
        auto* trust = dialog.findChild<QPushButton*>("trustPeer");
        auto* reject = dialog.findChild<QPushButton*>("rejectPeer");
        ASSERT_NE(nullptr, trust); ASSERT_NE(nullptr, reject);
        EXPECT_FALSE(trust->autoDefault());
        EXPECT_TRUE(reject->isDefault());
        EXPECT_EQ(reject, dialog.focusWidget());
        QWidget* target = &dialog;
        if (key == Qt::Key_Return) {
            trust->setFocus();
            target = trust;
            EXPECT_TRUE(reject->isDefault());
        }
        QKeyEvent press(QEvent::KeyPress, key, Qt::NoModifier);
        QApplication::sendEvent(target, &press);
        EXPECT_EQ(0, approvals);
        EXPECT_EQ(1, rejections);
    }
    FingerprintAcceptDialog approved(nullptr, BarrierType::Client, sha1, sha256);
    approved.findChild<QPushButton*>("trustPeer")->click();
    EXPECT_EQ(QDialog::Accepted, approved.result());
}
TEST(PeerApprovalTests, CopyPreservesTheDecisionAndUsesTheFullPublicValue)
{
    const barrier::FingerprintData sha256{"sha256", std::vector<std::uint8_t>(32, 0x42)};
    FingerprintAcceptDialog dialog(nullptr, BarrierType::Client, {}, sha256);
    int decisions = 0;
    QObject::connect(&dialog, &QDialog::accepted, [&] { ++decisions; });
    QObject::connect(&dialog, &QDialog::rejected, [&] { ++decisions; });
    dialog.show();
    QApplication::processEvents();
    auto* copy = dialog.findChild<QPushButton*>("copyPeerFingerprint");
    ASSERT_NE(nullptr, copy);
    EXPECT_FALSE(copy->autoDefault());
    copy->click();
    EXPECT_EQ(QString::fromStdString(barrier::format_ssl_fingerprint(sha256.data)),
              QApplication::clipboard()->text());
    EXPECT_EQ(95, QApplication::clipboard()->text().size());
    EXPECT_EQ(0, decisions);
    EXPECT_TRUE(dialog.isVisible());
    EXPECT_FALSE(dialog.findChild<QLabel*>("copyFeedback")->text().isEmpty());
}
TEST(PeerApprovalTests, MalformedSha256CannotBeCopiedOrApproved)
{
    for (const auto& peer : {barrier::FingerprintData{"sha256", {}},
                            barrier::FingerprintData{"sha256", std::vector<std::uint8_t>(31, 0x42)},
                            barrier::FingerprintData{"sha1", std::vector<std::uint8_t>(32, 0x42)}}) {
        FingerprintAcceptDialog dialog(nullptr, BarrierType::Client, {}, peer);
        EXPECT_FALSE(dialog.findChild<QPushButton*>("trustPeer")->isEnabled());
        auto* copy = dialog.findChild<QPushButton*>("copyPeerFingerprint");
        EXPECT_FALSE(copy->isEnabled());
        QApplication::clipboard()->setText("unchanged");
        copy->click();
        EXPECT_EQ(QString("unchanged"), QApplication::clipboard()->text());
        int approvals = 0;
        QObject::connect(&dialog, &QDialog::accepted, [&] { ++approvals; });
        dialog.accept();
        EXPECT_EQ(0, approvals);
    }
}
TEST(PeerApprovalTests, RoleWordingAndLegacyReferenceAreExplicit)
{
    const barrier::FingerprintData sha1{"sha1", std::vector<std::uint8_t>(20, 0x11)};
    const barrier::FingerprintData sha256{"sha256", std::vector<std::uint8_t>(32, 0x42)};
    FingerprintAcceptDialog server(nullptr, BarrierType::Client, sha1, sha256);
    FingerprintAcceptDialog client(nullptr, BarrierType::Server, sha1, sha256);
    EXPECT_EQ(QString("Trust &server"), server.findChild<QPushButton*>("trustPeer")->text());
    EXPECT_EQ(QString("Trust &client"), client.findChild<QPushButton*>("trustPeer")->text());
    EXPECT_FALSE(server.findChild<QLabel*>("label_sha1")->isHidden());
    EXPECT_TRUE(client.findChild<QLabel*>("label_sha1")->isHidden());
    EXPECT_EQ(Qt::PlainText, server.findChild<QLabel*>("label_explanation")->textFormat());
}

TEST_F(DiscoveryTests, IdentityFailureHidesStaleFingerprintAndRetryRecovers)
{
    const auto identity = barrier::DataDirectories::ssl_certificate_path();
    const auto fingerprints = barrier::DataDirectories::local_ssl_fingerprints_path();
    barrier::fs::create_directories(identity.parent_path());
    barrier::fs::create_directories(fingerprints.parent_path());
    QFile broken(QString::fromStdString(identity.u8string()));
    ASSERT_TRUE(broken.open(QIODevice::WriteOnly));
    broken.write("existing malformed identity");
    broken.close();
    barrier::FingerprintDatabase stale;
    stale.add_trusted({"sha1", std::vector<std::uint8_t>(20, 0x11)});
    stale.add_trusted({"sha256", std::vector<std::uint8_t>(32, 0x42)});
    stale.write(fingerprints);
    settings->setValue("cryptoEnabled", true);
    create(false);
    auto* error = window->findChild<QLabel*>("identityError");
    auto* retry = window->findChild<QToolButton*>("retryIdentity");
    EXPECT_FALSE(error->isHidden());
    auto* tabs = window->findChild<QTabWidget*>("dashboardTabs");
    window->show();
    tabs->setCurrentIndex(2);
    QApplication::processEvents();
    EXPECT_TRUE(window->findChild<QLabel*>("identityAlert")->isVisible());
    EXPECT_TRUE(window->findChild<QPushButton*>("reviewIdentity")->isVisible());
    window->findChild<QPushButton*>("reviewIdentity")->click();
    EXPECT_EQ(0, tabs->currentIndex());
    EXPECT_EQ(Qt::PlainText, error->textFormat());
    EXPECT_TRUE(error->text().contains("profile folder"));
    EXPECT_FALSE(window->findChild<QToolButton*>("copyFingerprint")->isEnabled());
    retry->click();
    ASSERT_TRUE(broken.open(QIODevice::ReadOnly));
    EXPECT_EQ(QByteArray("existing malformed identity"), broken.readAll());
    broken.close();
    ASSERT_TRUE(barrier::fs::remove(identity));
    barrier::generate_pem_self_signed_cert(identity.u8string());
    retry->click();
    EXPECT_TRUE(error->isHidden());
    EXPECT_TRUE(retry->isHidden());
    EXPECT_TRUE(window->findChild<QToolButton*>("copyFingerprint")->isEnabled());
}

TEST_F(DiscoveryTests, MissingPublicFingerprintCanBeRebuiltWithoutChangingTheIdentity)
{
    settings->setValue("cryptoEnabled", true);
    create(false);
    const auto identity = barrier::DataDirectories::ssl_certificate_path();
    QFile pem(QString::fromStdString(identity.u8string()));
    ASSERT_TRUE(pem.open(QIODevice::ReadOnly));
    const auto original = pem.readAll();
    pem.close();
    const auto snapshot = barrier::DataDirectories::local_ssl_fingerprints_path();
    ASSERT_TRUE(barrier::fs::remove(snapshot));
    window->updateSSLFingerprint();
    EXPECT_FALSE(window->findChild<QToolButton*>("copyFingerprint")->isEnabled());
    auto* retry = window->findChild<QToolButton*>("retryIdentity");
    EXPECT_FALSE(retry->isHidden());
    retry->click();
    EXPECT_TRUE(retry->isHidden());
    EXPECT_TRUE(window->findChild<QToolButton*>("copyFingerprint")->isEnabled());
    ASSERT_TRUE(pem.open(QIODevice::ReadOnly));
    EXPECT_TRUE(original == pem.readAll());
}

TEST_F(DiscoveryTests, DashboardNavigationKeepsConnectionActionsAndState)
{
    create(false);
    window->show();
    window->setBarrierState(MainWindow::barrierConnecting);
    auto* tabs = window->findChild<QTabWidget*>("dashboardTabs");
    ASSERT_EQ(3, tabs->count());
    EXPECT_EQ(QString("Connection"), tabs->tabText(0));
    EXPECT_EQ(QString("Screen layout"), tabs->tabText(1));
    EXPECT_EQ(QString("Settings"), tabs->tabText(2));
    window->resize(820, 620);
    QApplication::processEvents();
    EXPECT_EQ(0, window->findChild<QScrollArea*>("connectionPageScroll")->horizontalScrollBar()->maximum());
    int actions = 0;
    const auto started = QObject::connect(window->findChild<QAction*>("m_pActionStartBarrier"),
        &QAction::triggered, [&] { ++actions; });
    const auto stopped = QObject::connect(window->findChild<QAction*>("m_pActionStopBarrier"),
        &QAction::triggered, [&] { ++actions; });
    for (int page = 0; page < tabs->count(); ++page) {
        tabs->setCurrentIndex(page);
        QApplication::processEvents();
        EXPECT_TRUE(window->findChild<QPushButton*>("m_pButtonToggleStart")->isVisible());
        EXPECT_TRUE(window->findChild<QLabel*>("m_pStatusLabel")->isVisible());
        EXPECT_EQ(MainWindow::barrierConnecting, window->barrierState());
    }
    QObject::disconnect(started); QObject::disconnect(stopped);
    EXPECT_EQ(0, actions);
    EXPECT_TRUE(window->findChild<QLabel*>("dashboardVersion")->text().contains(QString::fromLatin1(kVersion)));
}
TEST_F(DiscoveryTests, DashboardPreservesServerConfigurationAndSavedPage)
{
    settings->setValue("useInternalConfig", false);
    settings->setValue("useExternalConfig", true);
    settings->setValue("configFile", "/tmp/custom-barrier.conf");
    create(false);
    auto* tools = window->findChild<QGroupBox*>("layoutTools");
    EXPECT_FALSE(tools->isEnabled());
    window->findChild<QGroupBox*>("m_pGroupServer")->setChecked(true);
    EXPECT_TRUE(tools->isEnabled());
    auto* internal = window->findChild<QRadioButton*>("m_pRadioInternalConfig");
    auto* external = window->findChild<QRadioButton*>("m_pRadioExternalConfig");
    EXPECT_TRUE(external->isChecked());
    EXPECT_TRUE(tools->isAncestorOf(external));
    internal->setChecked(true);
    EXPECT_FALSE(external->isChecked());
    external->setChecked(true);
    EXPECT_FALSE(internal->isChecked());
    window->findChild<QPushButton*>("goToLayout")->click();
    auto* tabs = window->findChild<QTabWidget*>("dashboardTabs");
    EXPECT_EQ(1, tabs->currentIndex());
    tabs->setCurrentIndex(2);
    window.reset(); config.reset();
    EXPECT_FALSE(settings->value("dashboardGeometry").toByteArray().isEmpty());
    create(false);
    EXPECT_EQ(2, window->findChild<QTabWidget*>("dashboardTabs")->currentIndex());
    EXPECT_EQ(QString("/tmp/custom-barrier.conf"), window->findChild<QLineEdit*>("m_pLineEditConfigFile")->text());
    EXPECT_TRUE(window->findChild<QRadioButton*>("m_pRadioExternalConfig")->isChecked());
    EXPECT_EQ(QString("manual.example"), window->hostname());
}
TEST_F(DiscoveryTests, DashboardPreferencesCancelKeepsTheExistingSettings)
{
    create(false);
    auto* tabs = window->findChild<QTabWidget*>("dashboardTabs");
    tabs->setCurrentIndex(2);
    bool opened = false;
    QTimer closeDialog;
    closeDialog.setSingleShot(true);
    QObject::connect(&closeDialog, &QTimer::timeout, [&] {
        auto* active = qobject_cast<QDialog*>(QApplication::activeModalWidget());
        auto* dialog = qobject_cast<SettingsDialog*>(active);
        opened = dialog != nullptr;
        if (dialog) { dialog->findChild<QCheckBox*>("m_pCheckBoxEnableCrypto")->setChecked(true); }
        if (active) { active->reject(); }
    });
    closeDialog.start(0);
    window->findChild<QPushButton*>("openPreferences")->click();
    EXPECT_TRUE(opened);
    EXPECT_FALSE(config->getCryptoEnabled());
    EXPECT_EQ(2, tabs->currentIndex());
}
TEST_F(DiscoveryTests, DashboardScrollsLongIdentityDetailsWithinASmallWindow)
{
    settings->setValue("cryptoEnabled", true);
    create(false);
    window->show();
    window->resize(820, 700);
    QApplication::processEvents();
    EXPECT_EQ(0, window->findChild<QScrollArea*>("connectionPageScroll")->horizontalScrollBar()->maximum());
    window->resize(640, 480);
    window->findChild<QToolButton*>("toolbutton_show_fingerprint")->click();
    QApplication::processEvents();
    auto* scroll = window->findChild<QScrollArea*>("connectionPageScroll");
    ASSERT_NE(nullptr, scroll);
    scroll->ensureWidgetVisible(window->findChild<QLabel*>("label_sha256_fingerprint_full"));
    EXPECT_GT(scroll->verticalScrollBar()->maximum(), 0);
    EXPECT_LT(window->width(), 760);
    EXPECT_LT(window->height(), 600);
    EXPECT_TRUE(window->findChild<QPushButton*>("m_pButtonToggleStart")->isVisible());
}

TEST_F(DiscoveryTests, DashboardPreferencesRefreshTheDisplayedComputerName)
{
    create(false);
    window->findChild<QTabWidget*>("dashboardTabs")->setCurrentIndex(2);
    bool opened = false;
    QTimer acceptDialog;
    acceptDialog.setSingleShot(true);
    QObject::connect(&acceptDialog, &QTimer::timeout, [&] {
        auto* active = qobject_cast<QDialog*>(QApplication::activeModalWidget());
        auto* dialog = qobject_cast<SettingsDialog*>(active);
        opened = dialog != nullptr;
        if (dialog) {
            dialog->findChild<QLineEdit*>("m_pLineEditScreenName")->setText("Workshop-Display");
            active->accept();
        } else if (active) { active->reject(); }
    });
    acceptDialog.start(0);
    window->findChild<QPushButton*>("openPreferences")->click();
    EXPECT_TRUE(opened);
    EXPECT_EQ(QString("Workshop-Display"), config->screenName());
    EXPECT_EQ(QString("Workshop-Display"), window->findChild<QLabel*>("m_pLabelScreenName")->text());
}
