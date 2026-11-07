/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "../src/MainWindow.h"
#include "common/DataDirectories.h"
#include <gtest/gtest.h>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QEvent>
#include <QFile>
#include <QLineEdit>
#include <QTemporaryDir>
#include <memory>
#if BARRIER_WITH_DISCOVERY
#include "../src/ZeroconfServer.h"
#include <QTcpSocket>
#include <QThread>
#endif

class DiscoveryWindow : public MainWindow {
public:
    using MainWindow::MainWindow;
    using MainWindow::clientArgs;
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
