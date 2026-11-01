# Capture effective settings at configure time; CTest selects the active config.
# This is generated build input, never a checked-in snapshot of one toolchain.
function(yamora_binary_json_string output value)
    string(REPLACE "\\" "\\\\" value "${value}")
    string(REPLACE "\"" "\\\"" value "${value}")
    string(REPLACE "\n" "\\n" value "${value}")
    string(REPLACE "\r" "\\r" value "${value}")
    string(REPLACE "\t" "\\t" value "${value}")
    set(${output} "\"${value}\"" PARENT_SCOPE)
endfunction()

set(yamora_binary_cache_names
    CMAKE_CXX_COMPILER CMAKE_CXX_COMPILER_ARG1 CMAKE_CXX_COMPILER_LAUNCHER
    CMAKE_CXX_COMPILER_TARGET CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN
    CMAKE_BUILD_TYPE CMAKE_CONFIGURATION_TYPES CMAKE_MAKE_PROGRAM
    CMAKE_TOOLCHAIN_FILE CMAKE_SYSROOT CMAKE_SYSROOT_COMPILE CMAKE_SYSROOT_LINK
    CMAKE_OSX_ARCHITECTURES CMAKE_OSX_DEPLOYMENT_TARGET CMAKE_OSX_SYSROOT
    CMAKE_POSITION_INDEPENDENT_CODE CMAKE_CXX_STANDARD CMAKE_CXX_STANDARD_REQUIRED
    CMAKE_CXX_EXTENSIONS CMAKE_BUILD_RPATH CMAKE_INSTALL_RPATH
    CMAKE_SKIP_RPATH CMAKE_SKIP_BUILD_RPATH CMAKE_BUILD_WITH_INSTALL_RPATH
    BUILD_SHARED_LIBS Python3_EXECUTABLE OPENSSL_ROOT_DIR OPENSSL_INCLUDE_DIR
    OPENSSL_SSL_LIBRARY OPENSSL_CRYPTO_LIBRARY CMAKE_PREFIX_PATH CMAKE_MODULE_PATH)
get_cmake_property(yamora_binary_all_cache CACHE_VARIABLES)
foreach(name IN LISTS yamora_binary_all_cache)
    if(name MATCHES "^CMAKE_CXX_FLAGS($|_)" OR
       name MATCHES "^CMAKE_(EXE|SHARED|MODULE|STATIC)_LINKER_FLAGS($|_)")
        get_property(type CACHE "${name}" PROPERTY TYPE)
        if(NOT type STREQUAL "INTERNAL")
            list(APPEND yamora_binary_cache_names "${name}")
        endif()
    endif()
endforeach()
list(REMOVE_DUPLICATES yamora_binary_cache_names)
set(yamora_binary_cache_json "")
foreach(name IN LISTS yamora_binary_cache_names)
    if(DEFINED ${name})
        yamora_binary_json_string(value "${${name}}")
        get_property(type CACHE "${name}" PROPERTY TYPE)
        if(NOT type OR type STREQUAL "INTERNAL" OR type STREQUAL "UNINITIALIZED")
            set(type STRING)
        endif()
        if(yamora_binary_cache_json)
            string(APPEND yamora_binary_cache_json ",")
        endif()
        string(APPEND yamora_binary_cache_json
            "\"${name}\":{\"type\":\"${type}\",\"value\":${value}}")
    endif()
endforeach()
yamora_binary_json_string(yamora_binary_cmake "${CMAKE_COMMAND}")
yamora_binary_json_string(yamora_binary_generator "${CMAKE_GENERATOR}")
yamora_binary_json_string(yamora_binary_platform "${CMAKE_GENERATOR_PLATFORM}")
yamora_binary_json_string(yamora_binary_toolset "${CMAKE_GENERATOR_TOOLSET}")
file(GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/binary-mutant-settings-$<CONFIG>.json"
    CONTENT "{\"cmake\":${yamora_binary_cmake},\"generator\":${yamora_binary_generator},\"platform\":${yamora_binary_platform},\"toolset\":${yamora_binary_toolset},\"configuration\":\"$<CONFIG>\",\"probe\":\"$<TARGET_FILE:yamora_cpp_binary_probe>\",\"cache\":{${yamora_binary_cache_json}}}\n")
