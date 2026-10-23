#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef _WIN32
#include <io.h>
#include <winsock2.h>
#include <windows.h>
#else
#include <signal.h>
#endif

#include <gcrypt.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "src/ccrypt.h"
#include "src/crypt_io.h"

#ifndef _WIN32
static struct sigaction previous_sigpipe;
#else
static char windows_temp_path[MAX_PATH];
#endif

static int setup(void **state)
{
	(void)state;
	init_crypto();
#ifndef _WIN32
	struct sigaction ignore = { .sa_handler = SIG_IGN };
	sigemptyset(&ignore.sa_mask);
	return sigaction(SIGPIPE, &ignore, &previous_sigpipe);
#else
	return 0;
#endif
}

static int teardown(void **state)
{
	(void)state;
#ifndef _WIN32
	return sigaction(SIGPIPE, &previous_sigpipe, NULL);
#else
	if (windows_temp_path[0])
	{
		DeleteFileA(windows_temp_path);
		windows_temp_path[0] = '\0';
	}
	return 0;
#endif
}

static IO_HANDLE wrap_temp_file(int *fd)
{
#ifdef _WIN32
	char directory[MAX_PATH];
	if (!GetTempPathA(sizeof directory, directory) ||
	    !GetTempFileNameA(directory, "eio", 0, windows_temp_path))
		return NULL;
	*fd = _open(windows_temp_path, _O_RDWR | _O_BINARY);
	if (*fd < 0)
	{
		DeleteFileA(windows_temp_path);
		windows_temp_path[0] = '\0';
	}
#else
	char path[] = "/tmp/encrypt-io-test-XXXXXX";
	*fd = mkstemp(path);
	unlink(path);
#endif
	if (*fd < 0)
		return NULL;
	return io_wrap_fd(*fd);
}

static void test_file_read_write_seek(void **state)
{
	(void)state;
	int fd;
	IO_HANDLE io = wrap_temp_file(&fd);
	assert_non_null(io);
	assert_true(io_is_initialised(io));

	const char expected[] = "predictable I/O";
	assert_int_equal(io_write(io, expected, sizeof expected), sizeof expected);
	assert_int_equal(io_seek(io, 0, SEEK_SET), 0);

	char actual[sizeof expected] = { 0 };
	assert_true(io_read_exact(io, actual, sizeof actual));
	assert_memory_equal(actual, expected, sizeof expected);
	assert_int_equal(io_read(io, actual, sizeof actual), 0);
	assert_int_equal(io_error(io), 0);
	assert_int_equal(io_sync(io), 0);
	assert_int_equal(io_close(io), 0);
}

static void test_exact_read_rejects_empty_input(void **state)
{
	(void)state;
	int fds[2];
	assert_int_equal(pipe(fds), 0);
	IO_HANDLE io = io_wrap_fd(fds[0]);
	assert_non_null(io);
	assert_int_equal(close(fds[1]), 0);

	char value;
	assert_false(io_read_exact(io, &value, sizeof value));
	assert_int_equal(io_error(io), EIO);
	assert_int_equal(io_close(io), -1);
	assert_int_equal(errno, EIO);
}

static void test_exact_read_rejects_truncated_input(void **state)
{
	(void)state;
	int fds[2];
	assert_int_equal(pipe(fds), 0);
	IO_HANDLE io = io_wrap_fd(fds[0]);
	assert_non_null(io);
	assert_int_equal(write(fds[1], "abc", 3), 3);
	assert_int_equal(close(fds[1]), 0);

	char value[5] = { 0 };
	assert_false(io_read_exact(io, value, sizeof value));
	assert_memory_equal(value, "abc", 3);
	assert_int_equal(io_error(io), EIO);
	assert_int_equal(io_close(io), -1);
	assert_int_equal(errno, EIO);
}

#ifndef _WIN32
static void test_pipe_write_failure_is_latched(void **state)
{
	(void)state;
	int fds[2];
	assert_int_equal(pipe(fds), 0);
	assert_int_equal(close(fds[0]), 0);
	IO_HANDLE io = io_wrap_fd(fds[1]);
	assert_non_null(io);

	errno = 0;
	assert_int_equal(io_write(io, "x", 1), -1);
	assert_int_equal(errno, EPIPE);
	assert_int_equal(io_error(io), EPIPE);
	assert_int_equal(io_sync(io), -1);
	assert_int_equal(errno, EPIPE);
	assert_int_equal(io_close(io), -1);
	assert_int_equal(errno, EPIPE);
}
#endif

static void test_pipe_sync_and_seek(void **state)
{
	(void)state;
	int fds[2];
	assert_int_equal(pipe(fds), 0);
	IO_HANDLE io = io_wrap_fd(fds[0]);
	assert_non_null(io);

	assert_int_equal(io_sync(io), 0);
	assert_int_equal(io_seek(io, 0, SEEK_SET), -1);
#ifdef _WIN32
	int seek_error = errno;
	assert_int_not_equal(seek_error, 0);
	assert_int_equal(io_error(io), seek_error);
	assert_int_equal(io_close(io), -1);
	assert_int_equal(errno, seek_error);
#else
	assert_int_equal(errno, ESPIPE);
	assert_int_equal(io_error(io), ESPIPE);
	assert_int_equal(io_close(io), -1);
	assert_int_equal(errno, ESPIPE);
#endif
	assert_int_equal(close(fds[1]), 0);
}

int main(void)
{
	const struct CMUnitTest tests[] =
	{
		cmocka_unit_test_setup_teardown(test_file_read_write_seek, setup, teardown),
		cmocka_unit_test_setup_teardown(test_exact_read_rejects_empty_input, setup, teardown),
		cmocka_unit_test_setup_teardown(test_exact_read_rejects_truncated_input, setup, teardown),
#ifndef _WIN32
		cmocka_unit_test_setup_teardown(test_pipe_write_failure_is_latched, setup, teardown),
#endif
		cmocka_unit_test_setup_teardown(test_pipe_sync_and_seek, setup, teardown)
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
