include(${CMAKE_SOURCE_DIR}/cmake/Qt.cmake)
find_package(${BARRIER_QT_PACKAGE} ${BARRIER_QT_MINIMUM} REQUIRED COMPONENTS Core Network Test)
set(CMAKE_AUTOMOC ON)
add_executable(guiipctests
    IpcReaderTests.cpp
    ../../src/IpcReader.cpp
    ../../src/IpcReader.h
    ../../src/IpcClient.cpp
    ../../src/IpcClient.h
    ../../src/Ipc.cpp
)
target_include_directories(guiipctests PRIVATE ../../src)
target_link_libraries(guiipctests ${BARRIER_QT_PACKAGE}::Core ${BARRIER_QT_PACKAGE}::Network ${BARRIER_QT_PACKAGE}::Test)
add_test(NAME gui-ipc COMMAND guiipctests)
set_tests_properties(gui-ipc PROPERTIES TIMEOUT 60)

if(WIN32)
    target_sources(guiipctests PRIVATE ../../../lib/ipc/WinLocalPipe.cpp)
    target_link_libraries(guiipctests advapi32 wtsapi32)
endif()
