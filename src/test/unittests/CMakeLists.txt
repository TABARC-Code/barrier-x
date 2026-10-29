# barrier -- mouse and keyboard sharing utility
# Copyright (C) 2012-2016 Symless Ltd.
# Copyright (C) 2009 Nick Bolton
#
# This package is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# found in the file LICENSE that should have accompanied this file.
#
# This package is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

file(GLOB_RECURSE headers "*.h")
file(GLOB_RECURSE sources "*.cpp")

file(GLOB_RECURSE remove_platform "platform/*")
list(REMOVE_ITEM headers ${remove_platform})
list(REMOVE_ITEM sources ${remove_platform})

file(GLOB_RECURSE global_headers "../../test/global/*.h")
file(GLOB_RECURSE global_sources "../../test/global/*.cpp")

list(APPEND headers ${global_headers})
list(APPEND sources ${global_sources})

file(GLOB_RECURSE mock_headers "../../test/mock/*.h")
file(GLOB_RECURSE mock_sources "../../test/mock/*.cpp")

list(APPEND headers ${mock_headers})
list(APPEND sources ${mock_sources})

# platform
if (WIN32)
    file(GLOB platform_sources "platform/MSWindows*.cpp")
    file(GLOB platform_headers "platform/MSWindows*.h")
elseif (APPLE)
    file(GLOB platform_sources "platform/OSX*.cpp")
    file(GLOB platform_headers "platform/OSX*.h")
elseif (UNIX)
    file(GLOB platform_sources "platform/XWindows*.cpp")
    file(GLOB platform_headers "platform/XWindows*.h")
endif()

list(APPEND sources ${platform_headers})
list(APPEND headers ${platform_sources})

include_directories(
    ../../
    ../../../ext
)

if (UNIX)
    include_directories(
        ../../..
    )
endif()

if (BARRIER_ADD_HEADERS)
    list(APPEND sources ${headers})
endif()

add_executable(unittests ${sources})
target_link_libraries(unittests
    arch base client server common io net platform server synlib mt ipc ${GTEST_LIBRARIES} ${GMOCK_LIBRARIES} ${libs} ${OPENSSL_LIBS})

if (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_definitions(unittests PRIVATE BARRIER_TEST_WRAP_SSL_CONTEXT)
    set_property(TARGET unittests APPEND_STRING PROPERTY LINK_FLAGS " -Wl,--wrap=SSL_CTX_new")
endif()

add_test(NAME unit COMMAND unittests)
set_tests_properties(unit PROPERTIES TIMEOUT 120)
add_test(NAME ssl-lifecycle COMMAND unittests --gtest_filter=SecureSocketTests.*)
set_tests_properties(ssl-lifecycle PROPERTIES TIMEOUT 30)
