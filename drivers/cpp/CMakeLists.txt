cmake_minimum_required(VERSION 3.16)
project(yamora_cpp VERSION 0.1.0 LANGUAGES CXX)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
find_package(OpenSSL 1.1.1 REQUIRED)
add_library(yamora_cpp src/client.cpp src/cluster.cpp src/json.cpp
    src/binary.cpp src/binary_tls.cpp src/binary_wire.cpp src/binary_reply.cpp)
add_library(yamora::cpp ALIAS yamora_cpp)
target_compile_features(yamora_cpp PUBLIC cxx_std_17)
target_include_directories(yamora_cpp PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(yamora_cpp PUBLIC OpenSSL::SSL OpenSSL::Crypto)
find_package(Threads REQUIRED)
target_link_libraries(yamora_cpp PUBLIC Threads::Threads)
target_compile_options(yamora_cpp PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
set_target_properties(yamora_cpp PROPERTIES EXPORT_NAME cpp
    VERSION ${PROJECT_VERSION} SOVERSION 0)
install(TARGETS yamora_cpp EXPORT yamora_cppTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/yamora DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
set(yamora_cpp_package_dir ${CMAKE_INSTALL_LIBDIR}/cmake/yamora_cpp)
configure_package_config_file(cmake/yamora_cppConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/yamora_cppConfig.cmake
    INSTALL_DESTINATION ${yamora_cpp_package_dir})
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/yamora_cppConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY ExactVersion)
install(EXPORT yamora_cppTargets NAMESPACE yamora::
    DESTINATION ${yamora_cpp_package_dir})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/yamora_cppConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/yamora_cppConfigVersion.cmake
    DESTINATION ${yamora_cpp_package_dir})
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/yamora_cpp)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/yamora_cpp)
install(FILES examples/CMakeLists.txt examples/crud.cpp
    DESTINATION ${CMAKE_INSTALL_DATADIR}/yamora_cpp/examples)
set(CPACK_PACKAGE_NAME yamora-cpp)
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_GENERATOR TGZ)
include(CPack)
include(CTest)
if(BUILD_TESTING)
    find_package(Python3 3.12 REQUIRED COMPONENTS Interpreter)
    find_package(Threads REQUIRED)
    include(tests/binary_build_settings.cmake)
    add_test(NAME cpp_package_smoke COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/package_smoke.py
        --settings ${CMAKE_CURRENT_BINARY_DIR}/binary-mutant-settings-$<CONFIG>.json
        --build ${CMAKE_CURRENT_BINARY_DIR})
    set_tests_properties(cpp_package_smoke PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE)
    add_executable(yamora_cpp_probe tests/probe.cpp)
    target_link_libraries(yamora_cpp_probe PRIVATE yamora::cpp Threads::Threads)
    add_executable(yamora_cpp_binary_probe tests/binary_probe.cpp tests/binary_faults.cpp)
    target_compile_options(yamora_cpp_binary_probe PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    target_link_libraries(yamora_cpp_binary_probe PRIVATE yamora::cpp Threads::Threads)
    target_link_options(yamora_cpp_binary_probe PRIVATE
        "LINKER:--wrap=_ZN6yamora13binary_detail6freezeB5cxx11ESt17basic_string_viewIcSt11char_traitsIcEERKNS_6detail7ControlE"
        "LINKER:--wrap=_ZN6yamora13binary_detail9semanticsERKNS0_5ReplyENS_12BinaryMethodESt17basic_string_viewIcSt11char_traitsIcEES8_S8_RKNS_6detail7ControlE")
    add_test(NAME cpp_binary_contract COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_binary.py $<TARGET_FILE:yamora_cpp_binary_probe>)
    set_tests_properties(cpp_binary_contract PROPERTIES TIMEOUT 240)
    add_test(NAME cpp_binary_mutants COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/binary_mutants.py
        --settings ${CMAKE_CURRENT_BINARY_DIR}/binary-mutant-settings-$<CONFIG>.json)
    set_tests_properties(cpp_binary_mutants PROPERTIES TIMEOUT 240)
    add_executable(yamora_cpp_cluster_probe tests/cluster_probe.cpp tests/cluster_faults.cpp)
    target_compile_options(yamora_cpp_cluster_probe PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    target_link_options(yamora_cpp_cluster_probe PRIVATE
        "LINKER:--wrap=_ZN6yamora6detail6decodeESt17basic_string_viewIcSt11char_traitsIcEERKNS0_7ControlE")
    target_link_libraries(yamora_cpp_cluster_probe PRIVATE yamora::cpp Threads::Threads)
    add_test(NAME cpp_cluster_contract COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cluster.py $<TARGET_FILE:yamora_cpp_cluster_probe>)
    set_tests_properties(cpp_cluster_contract PROPERTIES TIMEOUT 240)
    add_test(NAME cpp_http_contract COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_driver.py $<TARGET_FILE:yamora_cpp_probe>)
    set_tests_properties(cpp_http_contract PROPERTIES TIMEOUT 180)
endif()
