cmake_minimum_required(VERSION 3.16)

project(encrypt C)

include(CTest)

# The native GUI is built by the Xcode project on macOS. Elsewhere, prefer
# the GTK GUI; set this option to OFF for a CLI-only build.
if(APPLE)
	set(_gui_default OFF)
else()
	set(_gui_default ON)
endif()
option(BUILD_GUI "Build the GTK graphical application instead of the CLI" ${_gui_default})
option(BUILD_TESTS "Build and run unit tests before building the application" ${BUILD_TESTING})

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Build identity is supplied directly to targets; CMake writes its build
# diagnostics header into the binary tree, never the source tree.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" ENCRYPT_VERSION LIMIT_COUNT 1)
if(NOT ENCRYPT_VERSION)
	message(FATAL_ERROR "VERSION is missing or empty")
endif()

execute_process(
	COMMAND git -C "${CMAKE_CURRENT_SOURCE_DIR}" rev-parse --verify HEAD
	OUTPUT_VARIABLE GIT_COMMIT
	OUTPUT_STRIP_TRAILING_WHITESPACE
	RESULT_VARIABLE _git_result
)
if(NOT _git_result EQUAL 0)
	set(GIT_COMMIT "unknown")
else()
	execute_process(
		COMMAND git -C "${CMAKE_CURRENT_SOURCE_DIR}" status --porcelain
		OUTPUT_VARIABLE _git_status
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
	if(_git_status)
		string(APPEND GIT_COMMIT "-dirty")
	endif()
endif()
# Identify the distribution as well as the kernel/platform.
set(_os_pretty_name "")
if(EXISTS "/etc/os-release")
	execute_process(
		COMMAND sh -c ". /etc/os-release && printf '%s' \"$PRETTY_NAME\""
		OUTPUT_VARIABLE _os_pretty_name
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
endif()
execute_process(
	COMMAND uname -orm
	OUTPUT_VARIABLE _uname
	OUTPUT_STRIP_TRAILING_WHITESPACE
	RESULT_VARIABLE _uname_result
)
if(NOT _uname_result EQUAL 0 OR NOT _uname)
	set(_uname "${CMAKE_SYSTEM_NAME}")
endif()
if(_os_pretty_name)
	set(BUILD_OS "${_os_pretty_name} (${_uname})")
else()
	set(BUILD_OS "${_uname}")
endif()

# Keep the application's compile configuration in one place.
set(INCLUDE_DIRECTORIES
	"${CMAKE_CURRENT_SOURCE_DIR}"
	"${CMAKE_CURRENT_SOURCE_DIR}/src"
	"${CMAKE_CURRENT_SOURCE_DIR}/common"
	"${CMAKE_CURRENT_BINARY_DIR}/generated"
)
set(COMPILE_DEFINITIONS
	_GNU_SOURCE
	_FILE_OFFSET_BITS=64
	GCRYPT_NO_DEPRECATED
	USE_GCRYPT
	"ENCRYPT_VERSION=\"${ENCRYPT_VERSION}\""
	"BUILD_OS=\"${BUILD_OS}\""
	"GIT_COMMIT=\"${GIT_COMMIT}\""
)
set(APPLICATION_DEFINITIONS ${COMPILE_DEFINITIONS})
if(BUILD_GUI)
	list(APPEND APPLICATION_DEFINITIONS BUILD_GUI)
endif()

# These builds target GCC- and Clang-compatible toolchains. Keep the
# project warning flags with the standard C flags so they are visible in
# the generated build diagnostics alongside user-supplied flags.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
	string(APPEND CMAKE_C_FLAGS " -Wall -Wextra -Wformat=2 -Wno-unused-result")
endif()

# Record each useful build setting separately for runtime diagnostics.
string(STRIP "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}}" CMAKE_BUILD_C_FLAGS)
string(JOIN " -D" CMAKE_BUILD_DEFINITIONS ${APPLICATION_DEFINITIONS})
if(CMAKE_BUILD_DEFINITIONS)
	string(PREPEND CMAKE_BUILD_DEFINITIONS "-D")
endif()
set(CMAKE_BUILD_COMPILER "${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
if(CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE_DISPLAY "${CMAKE_BUILD_TYPE}")
else()
	set(CMAKE_BUILD_TYPE_DISPLAY "Unspecified")
endif()
set(CMAKE_BUILD_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_${CMAKE_BUILD_TYPE}}")
string(STRIP "${CMAKE_BUILD_LINKER_FLAGS}" CMAKE_BUILD_LINKER_FLAGS)

function(escape_c_string input output)
	string(REPLACE "\\" "\\\\" _escaped "${input}")
	string(REPLACE "\"" "\\\"" _escaped "${_escaped}")
	string(REPLACE "\n" "\\n" _escaped "${_escaped}")
	string(REPLACE "\r" "\\r" _escaped "${_escaped}")
	set(${output} "${_escaped}" PARENT_SCOPE)
endfunction()

escape_c_string("${CMAKE_BUILD_COMPILER}" CMAKE_BUILD_COMPILER_ESCAPED)
escape_c_string("${CMAKE_BUILD_TYPE_DISPLAY}" CMAKE_BUILD_TYPE_ESCAPED)
if(CMAKE_C_EXTENSIONS)
	set(CMAKE_BUILD_C_STANDARD_DISPLAY "gnu${CMAKE_C_STANDARD}")
else()
	set(CMAKE_BUILD_C_STANDARD_DISPLAY "c${CMAKE_C_STANDARD}")
endif()
escape_c_string("${CMAKE_BUILD_C_STANDARD_DISPLAY}" CMAKE_BUILD_C_STANDARD_ESCAPED)
escape_c_string("${CMAKE_BUILD_C_FLAGS}" CMAKE_BUILD_C_FLAGS_ESCAPED)
escape_c_string("${CMAKE_BUILD_DEFINITIONS}" CMAKE_BUILD_DEFINITIONS_ESCAPED)
escape_c_string("${CMAKE_BUILD_LINKER_FLAGS}" CMAKE_BUILD_LINKER_FLAGS_ESCAPED)

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake_build_flags.h.in"
	"${CMAKE_CURRENT_BINARY_DIR}/generated/cmake_build_flags.h"
	@ONLY
)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

pkg_check_modules(LIBGCRYPT REQUIRED IMPORTED_TARGET libgcrypt)
pkg_check_modules(LIBCURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(LIBLZMA REQUIRED IMPORTED_TARGET liblzma)

if(BUILD_GUI)
	if(APPLE)
		message(FATAL_ERROR "The macOS GUI is built by the Xcode project; configure with -DBUILD_GUI=OFF")
	endif()
	pkg_check_modules(GTK3 REQUIRED IMPORTED_TARGET gtk+-3.0 gmodule-2.0)
endif()

if(BUILD_TESTS)
	enable_testing()
	pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)
endif()

set(COMMON_SOURCES
	common/src/ccrypt.c
	common/src/cli.c
	common/src/config.c
	common/src/dir.c
	common/src/ecc.c
	common/src/error.c
	common/src/list.c
	common/src/mem.c
	common/src/non-gnu.c
	common/src/tlv.c
	common/src/version.c
)

set(CORE_SOURCES
	${COMMON_SOURCES}
	src/crypt.c
	src/encrypt.c
	src/decrypt.c
	src/crypt_io.c
)

add_library(encrypt_core STATIC ${CORE_SOURCES})
target_include_directories(encrypt_core PUBLIC ${INCLUDE_DIRECTORIES})
target_compile_definitions(encrypt_core PUBLIC ${APPLICATION_DEFINITIONS})
target_link_libraries(encrypt_core PUBLIC
	PkgConfig::LIBGCRYPT
	PkgConfig::LIBCURL
	PkgConfig::LIBLZMA
	Threads::Threads
)

add_executable(encrypt src/main.c)
target_link_libraries(encrypt PRIVATE encrypt_core)

if(BUILD_GUI)
	target_sources(encrypt PRIVATE src/gui-gtk.c)
	target_link_libraries(encrypt_core PUBLIC PkgConfig::GTK3)
	target_link_libraries(encrypt PRIVATE PkgConfig::GTK3)
endif()

if(WIN32)
	target_link_libraries(encrypt_core PUBLIC ws2_32)
endif()

# Retain the traditional decrypt invocation name on Unix-like systems.
add_custom_command(TARGET encrypt POST_BUILD
	COMMAND "${CMAKE_COMMAND}" -E create_symlink
			"$<TARGET_FILE_NAME:encrypt>"
			"$<TARGET_FILE_DIR:encrypt>/decrypt"
	VERBATIM
)

if(BUILD_TESTS)
	# Tests for the shared common submodule. This includes tests for
	# unused source files.
	set(COMMON_UNIT_TEST_SOURCES
		common/test/test_main.c
		common/test/test_support.c
		common/src/map.c
		common/test/test_ccrypt.c
		common/test/test_cli.c
		common/test/test_config.c
		common/test/test_dir.c
		common/test/test_ecc.c
		common/test/test_error.c
		common/test/test_list.c
		common/test/test_map.c
		common/test/test_mem.c
		common/test/test_tlv.c
		common/test/test_version.c

	)
	if(COMMON_UNIT_TEST_SOURCES)
		add_executable(common_unit_tests
			${COMMON_UNIT_TEST_SOURCES}
			${COMMON_SOURCES}
		)
		target_include_directories(common_unit_tests PRIVATE
			"${CMAKE_CURRENT_SOURCE_DIR}"
			"${CMAKE_CURRENT_SOURCE_DIR}/common"
			"${CMAKE_CURRENT_SOURCE_DIR}/common/src"
			"${CMAKE_CURRENT_BINARY_DIR}/generated"
		)
		target_compile_definitions(common_unit_tests PRIVATE
			_GNU_SOURCE _FILE_OFFSET_BITS=64 __DEBUG__ MALLOC_CHECK_=1
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

	add_executable(test_crypt_io ${CORE_SOURCES} test/test_crypt_io.c)
	target_include_directories(test_crypt_io PRIVATE ${INCLUDE_DIRECTORIES})
	target_compile_definitions(test_crypt_io PRIVATE ${COMPILE_DEFINITIONS})
	target_link_libraries(test_crypt_io PRIVATE
		PkgConfig::CMOCKA PkgConfig::LIBGCRYPT PkgConfig::LIBCURL
		PkgConfig::LIBLZMA Threads::Threads
	)
	if(WIN32)
		target_link_libraries(test_crypt_io PUBLIC ws2_32)
	endif()
	add_test(NAME crypt-io COMMAND test_crypt_io)

	add_executable(test_crypt_flow ${CORE_SOURCES} test/test_crypt_flow.c)
	target_include_directories(test_crypt_flow PRIVATE ${INCLUDE_DIRECTORIES})
	target_compile_definitions(test_crypt_flow PRIVATE ${COMPILE_DEFINITIONS})
	target_link_libraries(test_crypt_flow PRIVATE
		PkgConfig::CMOCKA PkgConfig::LIBGCRYPT PkgConfig::LIBCURL
		PkgConfig::LIBLZMA Threads::Threads
	)
	if(WIN32)
		target_link_libraries(test_crypt_flow PUBLIC ws2_32)
	endif()
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

message(STATUS "Application variant: ${BUILD_GUI}")
message(STATUS "Unit tests: ${BUILD_TESTS}")
