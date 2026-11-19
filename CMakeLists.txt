cmake_minimum_required(VERSION 3.16)

project(encrypt C)

if(NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_C_FLAGS_DEBUGWITHENCRYPTION
		"${CMAKE_C_FLAGS_DEBUG}"
		CACHE STRING "C compiler flags for DebugWithEncryption" FORCE)

	set(CMAKE_EXE_LINKER_FLAGS_DEBUGWITHENCRYPTION
		"${CMAKE_EXE_LINKER_FLAGS_DEBUG}"
		CACHE STRING "Linker flags for DebugWithEncryption" FORCE)
endif()

include(CTest)
include(GNUInstallDirs)

find_program(GZIP_EXECUTABLE gzip REQUIRED)

set(BASH_COMPLETION_DIR
	"${CMAKE_INSTALL_DATADIR}/bash-completion/completions"
	CACHE PATH "Bash completion installation directory")

set(ZSH_COMPLETION_DIR
	"${CMAKE_INSTALL_DATADIR}/zsh/site-functions"
	CACHE PATH "Zsh completion installation directory")

option(BUILD_GUI "Build the graphical application" ON)
option(BUILD_TESTS "Build and run unit tests before building the application" ${BUILD_TESTING})
option(ENABLE_COVERAGE "Enable code coverage instrumentation and reporting" OFF)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

if(ENABLE_COVERAGE)
	if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
		message(FATAL_ERROR "Coverage is currently supported with GCC only")
	endif()

	if(NOT BUILD_TESTS)
		message(FATAL_ERROR "Coverage requires BUILD_TESTS=ON")
	endif()

	find_program(GCOV_EXECUTABLE NAMES "gcov-${CMAKE_C_COMPILER_VERSION_MAJOR}" gcov REQUIRED)
	find_program(GCOVR_EXECUTABLE gcovr REQUIRED)

	add_compile_options(--coverage)
	add_link_options(--coverage)
endif()

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
	execute_process(COMMAND git -C "${CMAKE_CURRENT_SOURCE_DIR}" status --porcelain
		OUTPUT_VARIABLE _git_status
		OUTPUT_STRIP_TRAILING_WHITESPACE)
	if(_git_status)
		string(APPEND GIT_COMMIT "-dirty")
	endif()
endif()
# Identify the distribution as well as the kernel/platform.
set(_os_pretty_name "")
if(EXISTS "/etc/os-release")
	execute_process(COMMAND sh -c ". /etc/os-release && printf '%s' \"$PRETTY_NAME\""
		OUTPUT_VARIABLE _os_pretty_name
		OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

execute_process(COMMAND uname -orm
	OUTPUT_VARIABLE _uname
	OUTPUT_STRIP_TRAILING_WHITESPACE
	RESULT_VARIABLE _uname_result)

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
	"${CMAKE_CURRENT_BINARY_DIR}/generated")

set(COMPILE_DEFINITIONS
	_GNU_SOURCE
	_FILE_OFFSET_BITS=64
	GCRYPT_NO_DEPRECATED
	USE_GCRYPT
	"ENCRYPT_VERSION=\"${ENCRYPT_VERSION}\""
	"BUILD_OS=\"${BUILD_OS}\""
	"GIT_COMMIT=\"${GIT_COMMIT}\"")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	list(APPEND COMPILE_DEFINITIONS __DEBUG__)
elseif(CMAKE_BUILD_TYPE STREQUAL "DebugWithEncryption")
	list(APPEND COMPILE_DEFINITIONS __DEBUG__)
	list(APPEND COMPILE_DEFINITIONS __DEBUG_WITH_ENCRYPTION__)
endif()
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
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/cmake_build_flags.h.in"
	"${CMAKE_CURRENT_BINARY_DIR}/generated/cmake_build_flags.h"
	@ONLY)

# Solaris: prefer 64-bit pkg-config metadata for 64-bit builds.
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS" AND CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(_solaris_pkgconfig_dir "/usr/lib/64/pkgconfig")

	if(EXISTS "${_solaris_pkgconfig_dir}")
		if(DEFINED ENV{PKG_CONFIG_PATH} AND NOT "$ENV{PKG_CONFIG_PATH}" STREQUAL "")
			set(ENV{PKG_CONFIG_PATH}
				"${_solaris_pkgconfig_dir}:$ENV{PKG_CONFIG_PATH}")
		else()
			set(ENV{PKG_CONFIG_PATH} "${_solaris_pkgconfig_dir}")
		endif()
	endif()
endif()

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

pkg_check_modules(LIBGCRYPT REQUIRED IMPORTED_TARGET libgcrypt)
pkg_check_modules(LIBCURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(LIBLZMA REQUIRED IMPORTED_TARGET liblzma)

if(BUILD_GUI)
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
	common/src/version.c)

set(CORE_SOURCES
	${COMMON_SOURCES}
	src/crypt.c
	src/encrypt.c
	src/decrypt.c
	src/crypt_io.c)

add_library(encrypt_core STATIC ${CORE_SOURCES})
target_include_directories(encrypt_core PUBLIC ${INCLUDE_DIRECTORIES})
target_compile_definitions(encrypt_core PUBLIC ${APPLICATION_DEFINITIONS})
target_link_libraries(encrypt_core PUBLIC
	PkgConfig::LIBGCRYPT
	PkgConfig::LIBCURL
	PkgConfig::LIBLZMA
	Threads::Threads)

if(APPLE AND BUILD_GUI)
	add_executable(encrypt MACOSX_BUNDLE src/main.c)
elseif(WIN32 AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_executable(encrypt WIN32 src/main.c)
else()
	add_executable(encrypt src/main.c)
endif()
target_link_libraries(encrypt PRIVATE encrypt_core)

if(APPLE AND BUILD_GUI)
	find_file(GDK_PIXBUF_SVG_LOADER
		NAMES libpixbufloader-svg.so
		PATHS /opt/local/lib/gdk-pixbuf-2.0/2.10.0/loaders
		NO_DEFAULT_PATH)
	if(NOT GDK_PIXBUF_SVG_LOADER)
		message(FATAL_ERROR "Could not find the GdkPixbuf SVG loader")
	endif()

	set_target_properties(encrypt PROPERTIES
		MACOSX_BUNDLE_BUNDLE_NAME "Encrypt"
		MACOSX_BUNDLE_GUI_IDENTIFIER "org.albinoloverats.encrypt"
		MACOSX_BUNDLE_ICON_FILE "encrypt.icns")
endif()

if(BUILD_GUI)
	target_sources(encrypt PRIVATE src/gui.c)
	target_link_libraries(encrypt_core PUBLIC PkgConfig::GTK3)
	target_link_libraries(encrypt PRIVATE PkgConfig::GTK3)
endif()

if(APPLE AND BUILD_GUI)
	set(MACOS_RESOURCES
		etc/encrypt_mac.glade
		pixmaps/encrypt.icns
		pixmaps/encrypt.png
		pixmaps/encrypt.svg
		pixmaps/encrypt_button.png
		pixmaps/encrypt_key.png)

	set_source_files_properties(${MACOS_RESOURCES} PROPERTIES MACOSX_PACKAGE_LOCATION Resources)

	target_sources(encrypt PRIVATE ${MACOS_RESOURCES})
endif()

if(WIN32)
	configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt.rc.in" "${CMAKE_CURRENT_BINARY_DIR}/generated/encrypt.rc" @ONLY)

	target_sources(encrypt PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated/encrypt.rc")
	target_link_libraries(encrypt_core PUBLIC ws2_32)
endif()

if(NOT WIN32 AND NOT APPLE)
	set(MANPAGE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/docs/encrypt.1a")
	set(MANPAGE_BUILD  "${CMAKE_CURRENT_BINARY_DIR}/encrypt.1")

	add_custom_command( OUTPUT "${MANPAGE_BUILD}"
		COMMAND "${CMAKE_COMMAND}" -E copy
			"${MANPAGE_SOURCE}"
			"${MANPAGE_BUILD}"
		DEPENDS "${MANPAGE_SOURCE}"
	COMMENT "Copying man page"
	VERBATIM)

	add_custom_command(OUTPUT "${MANPAGE_BUILD}.gz"
		COMMAND "${GZIP_EXECUTABLE}" -9 --force "${MANPAGE_BUILD}"
		DEPENDS "${MANPAGE_BUILD}"
		COMMENT "Compressing man page"
		VERBATIM)

	add_custom_target(manpage ALL
		DEPENDS "${MANPAGE_BUILD}.gz"
	)
endif()

if(APPLE AND BUILD_GUI)
	install(TARGETS encrypt BUNDLE DESTINATION .)

	install(FILES "${GDK_PIXBUF_SVG_LOADER}" DESTINATION encrypt.app/Contents/Frameworks)

	install(CODE [[
		set(_bundle "${CMAKE_INSTALL_PREFIX}/encrypt.app")
		set(_frameworks "${_bundle}/Contents/Frameworks")
		set(_loader "${_frameworks}/libpixbufloader-svg.so")
		set(_cache "${_frameworks}/loaders.cache")

		# Locate the MacPorts GdkPixbuf cache generator.
		find_program(_query_loaders
			NAMES gdk-pixbuf-query-loaders
			PATHS /opt/local/bin
			NO_DEFAULT_PATH
		)

		if(NOT _query_loaders)
			message(FATAL_ERROR "Could not find gdk-pixbuf-query-loaders")
		endif()

		# Generate the cache before fixup_bundle changes the loader's
		# dependency paths. This allows the MacPorts utility to load it.
		execute_process(
			COMMAND "${_query_loaders}" "${_loader}"
			OUTPUT_FILE "${_cache}"
			RESULT_VARIABLE _result
		)
		# Make the loader cache independent of the staging directory.
		file(READ "${_cache}" _cache_contents)
		string(REPLACE "\"${_loader}\"" "\"@ENCRYPT_FRAMEWORKS@/libpixbufloader-svg.so\"" _cache_contents "${_cache_contents}")
		file(WRITE "${_cache}" "${_cache_contents}")

		if(NOT _result EQUAL 0)
			message(FATAL_ERROR "Failed to generate GdkPixbuf loaders.cache")
		endif()

		include(BundleUtilities)

		set(BU_CHMOD_BUNDLE_ITEMS ON)

		# Collect and relocate the application's dependencies, including
		# those required by the SVG loader.
		fixup_bundle( "${_bundle}" "${_loader}" "/opt/local/lib")

		# The SVG loader is a dynamically loaded module. Its dependencies
		# must therefore be resolved relative to the module, not the
		# application's executable.
		file(GLOB _framework_libraries "${_frameworks}/*.dylib")

		foreach(_library IN LISTS _framework_libraries)
			get_filename_component(_name "${_library}" NAME)

			execute_process(
				COMMAND "${CMAKE_INSTALL_NAME_TOOL}"
					-change
					"@executable_path/../Frameworks/${_name}"
					"@loader_path/${_name}"
					"${_loader}"
				RESULT_VARIABLE _result
			)

			if(NOT _result EQUAL 0)
				message(FATAL_ERROR "Failed to fix SVG loader dependency: ${_name}")
			endif()
		endforeach()
	]])
elseif(NOT WIN32)
	# Retain the traditional decrypt invocation name on Unix-like systems.
	add_custom_command(TARGET
		encrypt
		POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E create_symlink
				"$<TARGET_FILE_NAME:encrypt>"
				"$<TARGET_FILE_DIR:encrypt>/decrypt"
		VERBATIM)
	install(TARGETS encrypt RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
	install(CODE "
		execute_process(
			COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
			encrypt
			\"\$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/decrypt\"
		)")
	install(FILES etc/encrypt.glade etc/encryptrc etc/magic DESTINATION "${CMAKE_INSTALL_DATADIR}/encrypt")
	install(FILES etc/encrypt.desktop DESTINATION "${CMAKE_INSTALL_DATADIR}/applications")
	install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/etc/autocomplete.bash"
		DESTINATION "${BASH_COMPLETION_DIR}"
		RENAME encrypt)
	install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/etc/autocomplete.zsh"
		DESTINATION "${ZSH_COMPLETION_DIR}"
		RENAME _encrypt)
	install(FILES
		pixmaps/encrypt.svg
		pixmaps/encrypt_button.svg
		pixmaps/encrypt.png
		pixmaps/encrypt_button.png
		pixmaps/encrypt_key.png
		DESTINATION "${CMAKE_INSTALL_DATADIR}/pixmaps")
	install(FILES "${MANPAGE_BUILD}.gz" DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")
endif()

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
		common/test/test_version.c)
	if(COMMON_UNIT_TEST_SOURCES)
		add_executable(common_unit_tests
			${COMMON_UNIT_TEST_SOURCES}
			${COMMON_SOURCES})
		target_include_directories(common_unit_tests PRIVATE
			"${CMAKE_CURRENT_SOURCE_DIR}"
			"${CMAKE_CURRENT_SOURCE_DIR}/common"
			"${CMAKE_CURRENT_SOURCE_DIR}/common/src"
			"${CMAKE_CURRENT_BINARY_DIR}/generated")
		target_compile_definitions(common_unit_tests PRIVATE _GNU_SOURCE _FILE_OFFSET_BITS=64 __DEBUG__ MALLOC_CHECK_=1)
		target_link_libraries(common_unit_tests PRIVATE PkgConfig::CMOCKA PkgConfig::LIBGCRYPT PkgConfig::LIBCURL Threads::Threads m)
		if(UNIX AND NOT APPLE)
			target_link_options(common_unit_tests PRIVATE
				-Wl,--wrap=malloc
				-Wl,--wrap=calloc
				-Wl,--wrap=realloc
				-Wl,--wrap=strdup
				-Wl,--wrap=strndup
				-Wl,--wrap=vasprintf)
		endif()
		add_test(NAME common-unit COMMAND common_unit_tests)
	endif()

	add_executable(test_crypt_io ${CORE_SOURCES} test/test_crypt_io.c)
	target_include_directories(test_crypt_io PRIVATE ${INCLUDE_DIRECTORIES})
	target_compile_definitions(test_crypt_io PRIVATE ${COMPILE_DEFINITIONS})
	target_link_libraries(test_crypt_io PRIVATE
		PkgConfig::CMOCKA PkgConfig::LIBGCRYPT PkgConfig::LIBCURL
		PkgConfig::LIBLZMA Threads::Threads)
	if(WIN32)
		target_link_libraries(test_crypt_io PUBLIC ws2_32)
	endif()
	add_test(NAME crypt-io COMMAND test_crypt_io)

	add_executable(test_crypt_flow ${CORE_SOURCES} test/test_crypt_flow.c)
	target_include_directories(test_crypt_flow PRIVATE ${INCLUDE_DIRECTORIES})
	target_compile_definitions(test_crypt_flow PRIVATE ${COMPILE_DEFINITIONS})
	target_link_libraries(test_crypt_flow PRIVATE
		PkgConfig::CMOCKA PkgConfig::LIBGCRYPT PkgConfig::LIBCURL
		PkgConfig::LIBLZMA Threads::Threads)
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
		USES_TERMINAL)
	add_dependencies(encrypt check)
endif()

if(ENABLE_COVERAGE)
	set(COVERAGE_OUTPUT_DIR "${CMAKE_BINARY_DIR}/coverage")
	add_custom_target(coverage COMMAND "${CMAKE_COMMAND}" -E make_directory "${COVERAGE_OUTPUT_DIR}"
	COMMAND "${GCOVR_EXECUTABLE}"
		--root "${PROJECT_SOURCE_DIR}"
		--object-directory "${CMAKE_BINARY_DIR}"
		--gcov-executable "${GCOV_EXECUTABLE}"
		--filter "${PROJECT_SOURCE_DIR}/src/"
		--filter "${PROJECT_SOURCE_DIR}/common/src/"
		--xml-pretty
		--xml "${COVERAGE_OUTPUT_DIR}/coverage.xml"
		--html-details "${COVERAGE_OUTPUT_DIR}/index.html"
		--print-summary
		DEPENDS encrypt
		WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
		USES_TERMINAL
		VERBATIM)
endif()

message(STATUS "Application variant: ${BUILD_GUI}")
message(STATUS "Unit tests: ${BUILD_TESTS}")
