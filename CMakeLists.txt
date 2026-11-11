cmake_minimum_required(VERSION 3.16)

project(encrypt C)

include(CTest)

# The native GUI is built by the Xcode project on macOS. Elsewhere, prefer
# the GTK GUI; set this option to OFF for a CLI-only build.
if(APPLE)
    set(_encrypt_gui_default OFF)
else()
    set(_encrypt_gui_default ON)
endif()
option(ENCRYPT_BUILD_GUI "Build the GTK graphical application instead of the CLI" ${_encrypt_gui_default})
option(ENCRYPT_BUILD_TESTS "Build and run unit tests before building the application" ${BUILD_TESTING})

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

pkg_check_modules(LIBGCRYPT REQUIRED IMPORTED_TARGET libgcrypt)
pkg_check_modules(LIBCURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(LIBLZMA REQUIRED IMPORTED_TARGET liblzma)

if(ENCRYPT_BUILD_GUI)
    if(APPLE)
        message(FATAL_ERROR "The macOS GUI is built by the Xcode project; configure with -DENCRYPT_BUILD_GUI=OFF")
    endif()
    pkg_check_modules(GTK3 REQUIRED IMPORTED_TARGET gtk+-3.0 gmodule-2.0)
endif()

if(ENCRYPT_BUILD_TESTS)
    enable_testing()
    pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)
endif()

# Keep the existing version generator as the single source of build metadata.
# It writes src/misc.h, which is included by src/crypt.h.
string(TOUPPER "${CMAKE_BUILD_TYPE}" _encrypt_build_type_upper)
set(_encrypt_config_cflags "${CMAKE_C_FLAGS}")
if(_encrypt_build_type_upper)
    string(APPEND _encrypt_config_cflags " ${CMAKE_C_FLAGS_${_encrypt_build_type_upper}}")
endif()
set(_encrypt_config_cppflags "-Isrc -Icommon -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DGCRYPT_NO_DEPRECATED -DUSE_GCRYPT")
if(ENCRYPT_BUILD_GUI)
    string(APPEND _encrypt_config_cppflags " -DBUILD_GUI")
endif()
execute_process(
    COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/scripts/version.sh"
            "${_encrypt_config_cflags}" "${_encrypt_config_cppflags}" ""
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    RESULT_VARIABLE _encrypt_version_result
)
if(NOT _encrypt_version_result EQUAL 0)
    message(FATAL_ERROR "scripts/version.sh failed (${_encrypt_version_result})")
endif()

set(ENCRYPT_COMMON_SOURCES
    common/src/error.c
    common/src/mem.c
    common/src/ccrypt.c
    common/src/list.c
    common/src/tlv.c
    common/src/version.c
    common/src/config.c
    common/src/cli.c
    common/src/dir.c
    common/src/ecc.c
    common/src/non-gnu.c
)

set(ENCRYPT_CORE_SOURCES
    ${ENCRYPT_COMMON_SOURCES}
    src/crypt.c
    src/encrypt.c
    src/decrypt.c
    src/crypt_io.c
)

add_library(encrypt_core STATIC ${ENCRYPT_CORE_SOURCES})
target_include_directories(encrypt_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/common"
)
target_compile_definitions(encrypt_core PUBLIC
    _GNU_SOURCE
    _FILE_OFFSET_BITS=64
    GCRYPT_NO_DEPRECATED
    USE_GCRYPT
)
target_compile_options(encrypt_core PRIVATE
    -Wall -Wextra -Wformat=2 -Wno-unused-result
)
target_link_libraries(encrypt_core PUBLIC
    PkgConfig::LIBGCRYPT
    PkgConfig::LIBCURL
    PkgConfig::LIBLZMA
    Threads::Threads
)

add_executable(encrypt src/main.c)
target_link_libraries(encrypt PRIVATE encrypt_core)
target_compile_options(encrypt PRIVATE -Wall -Wextra -Wformat=2 -Wno-unused-result)

if(ENCRYPT_BUILD_GUI)
    target_sources(encrypt PRIVATE src/gui-gtk.c)
    target_compile_definitions(encrypt_core PUBLIC BUILD_GUI)
    target_link_libraries(encrypt_core PUBLIC PkgConfig::GTK3)
    target_compile_definitions(encrypt PRIVATE BUILD_GUI)
    target_link_libraries(encrypt PRIVATE PkgConfig::GTK3)
endif()

# Retain the traditional decrypt invocation name on Unix-like systems.
add_custom_command(TARGET encrypt POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E create_symlink
            "$<TARGET_FILE_NAME:encrypt>"
            "$<TARGET_FILE_DIR:encrypt>/decrypt"
    VERBATIM
)

if(ENCRYPT_BUILD_TESTS)
    # Tests for the shared common submodule. Keep its source list aligned with
    # common/Makefile's UNIT_SRC; the test files themselves are discovered so
    # adding a test there does not require editing this file.
    file(GLOB COMMON_UNIT_TEST_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/common/test/test_*.c"
    )
    if(COMMON_UNIT_TEST_SOURCES)
        add_executable(common_unit_tests
            ${COMMON_UNIT_TEST_SOURCES}
            common/src/error.c
            common/src/mem.c
            common/src/list.c
            common/src/tlv.c
            common/src/map.c
            common/src/ecc.c
            common/src/dir.c
            common/src/cli.c
            common/src/config.c
            common/src/ccrypt.c
            common/src/version.c
        )
        target_include_directories(common_unit_tests PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}"
            "${CMAKE_CURRENT_SOURCE_DIR}/common"
            "${CMAKE_CURRENT_SOURCE_DIR}/common/src"
        )
        target_compile_definitions(common_unit_tests PRIVATE
            _GNU_SOURCE _FILE_OFFSET_BITS=64 __DEBUG__ MALLOC_CHECK_=1
        )
        target_compile_options(common_unit_tests PRIVATE
            -Wall -Wextra -Wformat=2 -Wno-unused-result
        )
        target_link_libraries(common_unit_tests PRIVATE
            PkgConfig::CMOCKA PkgConfig::LIBGCRYPT PkgConfig::LIBCURL
            Threads::Threads m
        )
        if(UNIX AND NOT APPLE)
            target_link_options(common_unit_tests PRIVATE
                -Wl,--wrap=malloc
                -Wl,--wrap=calloc
                -Wl,--wrap=realloc
                -Wl,--wrap=strdup
                -Wl,--wrap=strndup
                -Wl,--wrap=vasprintf
            )
        endif()
        add_test(NAME common-unit COMMAND common_unit_tests)
    endif()

    add_executable(test_crypt_io ${ENCRYPT_CORE_SOURCES} test/test_crypt_io.c)
    target_include_directories(test_crypt_io PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
    )
    target_compile_definitions(test_crypt_io PRIVATE
        _GNU_SOURCE _FILE_OFFSET_BITS=64 GCRYPT_NO_DEPRECATED USE_GCRYPT
    )
    target_compile_options(test_crypt_io PRIVATE
        -Wall -Wextra -Wformat=2 -Wno-unused-result
    )
    target_link_libraries(test_crypt_io PRIVATE
        PkgConfig::CMOCKA PkgConfig::LIBGCRYPT PkgConfig::LIBCURL
        PkgConfig::LIBLZMA Threads::Threads
    )
    add_test(NAME crypt-io COMMAND test_crypt_io)

    add_executable(test_crypt_flow ${ENCRYPT_CORE_SOURCES} test/test_crypt_flow.c)
    target_include_directories(test_crypt_flow PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
    )
    target_compile_definitions(test_crypt_flow PRIVATE
        _GNU_SOURCE _FILE_OFFSET_BITS=64 GCRYPT_NO_DEPRECATED USE_GCRYPT
    )
    target_compile_options(test_crypt_flow PRIVATE
        -Wall -Wextra -Wformat=2 -Wno-unused-result
    )
    target_link_libraries(test_crypt_flow PRIVATE
        PkgConfig::CMOCKA PkgConfig::LIBGCRYPT PkgConfig::LIBCURL
        PkgConfig::LIBLZMA Threads::Threads
    )
    add_test(NAME crypt-flow COMMAND test_crypt_flow)

    # Building the application runs the unit suite first. The check target is
    # also available explicitly for developers and CI.
    set(_encrypt_test_targets test_crypt_io test_crypt_flow)
    if(TARGET common_unit_tests)
        list(APPEND _encrypt_test_targets common_unit_tests)
    endif()
    add_custom_target(check
        COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure
        DEPENDS ${_encrypt_test_targets}
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        USES_TERMINAL
    )
    add_dependencies(encrypt check)
endif()

message(STATUS "Application variant: ${ENCRYPT_BUILD_GUI}")
message(STATUS "Unit tests: ${ENCRYPT_BUILD_TESTS}")