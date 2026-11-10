# Copyright (C) 2026 barrier-x contributors. GPL; see ../../LICENSE.
find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)
set(tor_plugin "${CMAKE_CURRENT_BINARY_DIR}/barrier-x-tor.pyz")
# The builder refuses overwrite; CMake owns just this generated output.
add_custom_command(OUTPUT "${tor_plugin}"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${tor_plugin}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/build_plugin.py" --output "${tor_plugin}"
    DEPENDS bridge.py build_plugin.py plugin.json README.md "${PROJECT_SOURCE_DIR}/LICENSE"
    VERBATIM)
add_custom_target(barrier-tor-plugin ALL DEPENDS "${tor_plugin}")
install(FILES "${tor_plugin}" DESTINATION share/barrier-x/plugins/tor COMPONENT tor-plugin)
if(BARRIER_BUILD_TESTS)
    add_test(NAME tor-plugin COMMAND "${Python3_EXECUTABLE}" -m unittest discover
        -s "${CMAKE_CURRENT_SOURCE_DIR}" -p "test_*.py" -v)
    set_tests_properties(tor-plugin PROPERTIES TIMEOUT 90)
endif()
