cmake_minimum_required(VERSION 3.20)
project(barrier_native_ipc LANGUAGES CXX)
if(NOT WIN32)
    message(FATAL_ERROR "These checks require Windows tokens and named pipes")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
enable_testing()
add_executable(nativeipctests NativePipeTests.cpp ../../lib/ipc/WinLocalPipe.cpp)
target_link_libraries(nativeipctests PRIVATE advapi32 wtsapi32 netapi32 bcrypt)
target_compile_definitions(nativeipctests PRIVATE _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
add_test(NAME native-ipc COMMAND nativeipctests)
set_tests_properties(native-ipc PROPERTIES TIMEOUT 60)
# I compile the integration points with the SDK even when old desktop dependencies
# prevent linking the full application. This is not a substitute for a desktop run.
add_library(nativeipc_adapters OBJECT HeaderChecks.cpp
    ../../lib/ipc/WinPipeStream.cpp ../../lib/ipc/IpcClient.cpp
    ../../lib/ipc/IpcServer.cpp ../../lib/ipc/IpcClientProxy.cpp
    ../../lib/barrier/win32/DaemonApp.cpp ../../lib/platform/MSWindowsWatchdog.cpp)
target_include_directories(nativeipc_adapters PRIVATE ../../lib ../../../ext ../../../ext/gulrak-filesystem/include)
target_compile_definitions(nativeipc_adapters PRIVATE _WIN32_WINNT=0x0601 WINVER=0x0601 SYSAPI_WIN32=1 WINAPI_MSWINDOWS=1 NOMINMAX WIN32_LEAN_AND_MEAN BARRIER_VERSION="native-check")

add_executable(nativefiletests PrivateFileTests.cpp ../../lib/io/WinPrivateFile.cpp)
target_link_libraries(nativefiletests PRIVATE advapi32 wtsapi32 netapi32 bcrypt)
target_compile_definitions(nativefiletests PRIVATE _WIN32_WINNT=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN)
add_test(NAME native-private-files COMMAND nativefiletests)
set_tests_properties(native-private-files PROPERTIES TIMEOUT 60)
