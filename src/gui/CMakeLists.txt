include(${CMAKE_SOURCE_DIR}/cmake/Qt.cmake)
cmake_minimum_required (VERSION 3.20)

find_package (${BARRIER_QT_PACKAGE} ${BARRIER_QT_MINIMUM} REQUIRED COMPONENTS Core Widgets Network)
set (CMAKE_AUTOMOC ON)
set (CMAKE_AUTORCC ON)
set (CMAKE_AUTOUIC ON)
set (CMAKE_INCLUDE_CURRENT_DIR ON)

# files that are used both in tests and the app
set(GUI_COMMON_SOURCE_FILES
    src/Action.cpp
    src/Hotkey.cpp
    src/KeySequence.cpp
)

set(GUI_COMMON_HEADER_FILES
    src/Action.h
    src/Hotkey.h
    src/KeySequence.h
)

set(GUI_SOURCE_FILES
    src/AboutDialog.cpp
    src/ActionDialog.cpp
    src/AddClientDialog.cpp
    src/AppConfig.cpp
    src/BarrierLocale.cpp
    src/BaseConfig.cpp
    src/CommandProcess.cpp
    src/DisplayIsValid.cpp
    src/FingerprintAcceptDialog.cpp
    src/HotkeyDialog.cpp
    src/IpcClient.cpp
    src/Ipc.cpp
    src/IpcReader.cpp
    src/KeySequenceWidget.cpp
    src/LogWindow.cpp
    src/PeerTrustStore.cpp
    src/MainWindow.cpp
    src/NewScreenWidget.cpp
    src/QBarrierApplication.cpp
    src/QUtility.cpp
    src/Screen.cpp
    src/ScreenSettingsDialog.cpp
    src/ScreenSetupModel.cpp
    src/ScreenSetupView.cpp
    src/ServerConfig.cpp
    src/ServerConfigDialog.cpp
    src/SettingsDialog.cpp
    src/SetupWizard.cpp
    src/SslCertificate.cpp
    src/TrashScreenWidget.cpp
    src/VersionChecker.cpp
)

set(GUI_HEADER_FILES
    src/AboutDialog.h
    src/ActionDialog.h
    src/AddClientDialog.h
    src/AppConfig.h
    src/BarrierLocale.h
    src/BaseConfig.h
    src/CommandProcess.h
    src/DisplayIsValid.h
    src/ElevateMode.h
    src/HotkeyDialog.h
    src/IpcClient.h
    src/Ipc.h
    src/IpcReader.h
    src/KeySequenceWidget.h
    src/LogWindow.h
    src/PeerTrustStore.h
    src/MainWindow.h
    src/NewScreenWidget.h
    src/ProcessorArch.h
    src/QBarrierApplication.h
    src/QUtility.h
    src/Screen.h
    src/ScreenSettingsDialog.h
    src/ScreenSetupModel.h
    src/ScreenSetupView.h
    src/ServerConfigDialog.h
    src/ServerConfig.h
    src/SettingsDialog.h
    src/SetupWizard.h
    src/ShutdownCh.h
    src/SslCertificate.h
    src/TrashScreenWidget.h
    src/VersionChecker.h
)

if (BARRIER_BUILD_DISCOVERY)
    list(APPEND GUI_SOURCE_FILES
        src/ZeroconfBrowser.cpp src/ZeroconfRegister.cpp src/ZeroconfServer.cpp
        src/ZeroconfService.cpp)
    list(APPEND GUI_HEADER_FILES
        src/ZeroconfBrowser.h src/ZeroconfRegister.h src/ZeroconfServer.h
        src/ZeroconfService.h src/ZeroconfRecord.h)
endif()

set(GUI_UI_FILES
    src/AboutDialogBase.ui
    src/ActionDialogBase.ui
    src/AddClientDialogBase.ui
    src/FingerprintAcceptDialog.ui
    src/HotkeyDialogBase.ui
    src/LogWindowBase.ui
    src/MainWindowBase.ui
    src/ScreenSettingsDialogBase.ui
    src/ServerConfigDialogBase.ui
    src/SettingsDialogBase.ui
    src/SetupWizardBase.ui
)

if (WIN32)
    set (GUI_RC_FILES res/win/Barrier.rc)
endif()

add_executable (barrier WIN32
    src/main.cpp
    ${GUI_COMMON_SOURCE_FILES}
    ${GUI_COMMON_HEADER_FILES}
    ${GUI_SOURCE_FILES}
    ${GUI_HEADER_FILES}
    ${GUI_UI_FILES}
    ${GUI_RC_FILES}
    res/Barrier.qrc
)

include_directories (./src)

if (WIN32 AND BARRIER_BUILD_DISCOVERY)
    find_path(DNSSD_INCLUDE_DIR dns_sd.h HINTS ENV BONJOUR_SDK_HOME PATH_SUFFIXES Include REQUIRED)
    if (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(DNSSD_LIBRARY_SUFFIXES Lib/x64)
    else()
        set(DNSSD_LIBRARY_SUFFIXES Lib/Win32 Lib/x86)
    endif()
    find_library(DNSSD_LIB dnssd HINTS ENV BONJOUR_SDK_HOME PATH_SUFFIXES ${DNSSD_LIBRARY_SUFFIXES} REQUIRED)
elseif (NOT APPLE AND BARRIER_BUILD_DISCOVERY)
    find_library(DNSSD_LIB dns_sd REQUIRED)
endif()

function(barrier_gui_support target)
    target_link_libraries(${target} net base io common ${BARRIER_QT_PACKAGE}::Core ${BARRIER_QT_PACKAGE}::Widgets ${BARRIER_QT_PACKAGE}::Network ${OPENSSL_LIBS})
    target_compile_definitions(${target} PRIVATE
        BARRIER_WITH_DISCOVERY=$<BOOL:${BARRIER_BUILD_DISCOVERY}>
        BARRIER_VERSION_STAGE="${BARRIER_VERSION_STAGE}" BARRIER_REVISION="${BARRIER_REVISION}")
    if (WIN32)
        target_sources(${target} PRIVATE ../lib/ipc/WinLocalPipe.cpp)
        target_link_libraries(${target} advapi32 wtsapi32)
        set_target_properties(${target} PROPERTIES LINK_FLAGS "/NODEFAULTLIB:LIBCMT")
    elseif (APPLE)
        find_library(APPSERVICES_LIB ApplicationServices REQUIRED)
        target_link_libraries(${target} ${APPSERVICES_LIB})
    endif()
    if (BARRIER_BUILD_DISCOVERY AND NOT APPLE)
        target_link_libraries(${target} ${DNSSD_LIB})
        if (WIN32)
            target_include_directories(${target} PRIVATE ${DNSSD_INCLUDE_DIR})
        endif()
    endif()
    if (HAVE_X11)
        target_link_libraries(${target} X11)
    endif()
endfunction()
barrier_gui_support(barrier)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    install (TARGETS barrier DESTINATION ${BARRIER_BUNDLE_BINARY_DIR})
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux" OR ${CMAKE_SYSTEM_NAME} MATCHES "BSD")
    install (TARGETS barrier DESTINATION bin)
endif()

if (BARRIER_BUILD_TESTS)
    set(GUI_TEST_SOURCE_FILES
        test/KeySequenceTests.cpp
        test/HotkeyTests.cpp
        test/SslCertificateTests.cpp
        test/PeerTrustStoreTests.cpp
        src/PeerTrustStore.cpp
        src/PeerTrustStore.h
        src/SslCertificate.cpp
        src/SslCertificate.h
        test/main.cpp
    )

    add_executable(guiunittests
        ${GUI_TEST_SOURCE_FILES}
        ${GUI_COMMON_SOURCE_FILES}
        ${GUI_COMMON_HEADER_FILES}
    )

    add_test(NAME guiunittests COMMAND guiunittests)
    set_tests_properties(guiunittests PROPERTIES TIMEOUT 60 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")

    target_include_directories(guiunittests PUBLIC ../../ext)
    target_link_libraries(guiunittests ${GTEST_LIBRARIES} ${GMOCK_LIBRARIES} ${BARRIER_QT_PACKAGE}::Core ${BARRIER_QT_PACKAGE}::Widgets ${BARRIER_QT_PACKAGE}::Network ${libs} net base io common ${OPENSSL_LIBS})
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_definitions(guiunittests PRIVATE BARRIER_TEST_WRAP_PEER_IO)
        target_link_options(guiunittests PRIVATE -Wl,--wrap=write -Wl,--wrap=fsync -Wl,--wrap=fchmod -Wl,--wrap=fstat -Wl,--wrap=renameat -Wl,--wrap=openat -Wl,--wrap=mkdirat -Wl,--wrap=fstatat)
    endif()
endif()

if (BARRIER_BUILD_TESTS)
    add_executable(guidiscoverytests
        test/DiscoveryTests.cpp test/discovery-main.cpp
        ${GUI_COMMON_SOURCE_FILES} ${GUI_COMMON_HEADER_FILES}
        ${GUI_SOURCE_FILES} ${GUI_HEADER_FILES} ${GUI_UI_FILES} res/Barrier.qrc)
    barrier_gui_support(guidiscoverytests)
    target_link_libraries(guidiscoverytests ${GTEST_LIBRARIES} ${GMOCK_LIBRARIES})
    add_dependencies(guidiscoverytests barrierc)
    add_test(NAME gui-discovery COMMAND guidiscoverytests)
    set_tests_properties(gui-discovery PROPERTIES TIMEOUT 60 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()
