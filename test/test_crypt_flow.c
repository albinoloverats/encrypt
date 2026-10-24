#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#define TEST_PATH_LENGTH MAX_PATH
#else
#include <limits.h>
#define TEST_PATH_LENGTH PATH_MAX
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "src/common.h"

#include "src/ccrypt.h"
#include "src/crypt.h"
#include "src/decrypt.h"
#include "src/encrypt.h"

#define TEST_DATA_LENGTH (32 * 1024 + 37)
#define TEST_FILE_COUNT 3

static char test_paths[TEST_FILE_COUNT][TEST_PATH_LENGTH];
static size_t test_path_count;

static int setup(void **state)
{
	(void)state;
	test_path_count = 0;
	init_crypto();
	return 0;
}

static int teardown(void **state)
{
	(void)state;
	for (size_t i = 0; i < test_path_count; i++)
	{
#ifdef _WIN32
		DeleteFileA(test_paths[i]);
#else
		unlink(test_paths[i]);
#endif
	}
	test_path_count = 0;
	return 0;
}

static char *create_temp_path(void)
{
	if (test_path_count >= TEST_FILE_COUNT)
		return NULL;

	char *path = test_paths[test_path_count];
#ifdef _WIN32
	char directory[MAX_PATH];
	if (!GetTempPathA(sizeof directory, directory) ||
	    !GetTempFileNameA(directory, "ecf", 0, path))
		return NULL;
#else
	int written = snprintf(path, TEST_PATH_LENGTH, "/tmp/encrypt-flow-test-XXXXXX");
	if (written < 0 || (size_t)written >= TEST_PATH_LENGTH)
		return NULL;
	int fd = mkstemp(path);
	if (fd < 0)
		return NULL;
	if (close(fd) < 0)
	{
		unlink(path);
		return NULL;
	}
#endif
	test_path_count++;
	return path;
}

static bool write_all(int fd, const uint8_t *data, size_t length)
{
	size_t offset = 0;
	while (offset < length)
	{
		ssize_t written = write(fd, data + offset, length - offset);
		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0)
			return false;
		offset += (size_t)written;
	}
	return true;
}

static bool wait_for_completion(crypto_s *crypto)
{
	for (unsigned i = 0; i < 3000; i++)
	{
		if (crypto->status != STATUS_INIT && crypto->status != STATUS_RUNNING)
			return true;
#ifdef _WIN32
		Sleep(10);
#else
		struct timespec delay = { .tv_sec = 0, .tv_nsec = 10 * MILLION };
		nanosleep(&delay, NULL);
#endif
	}
	return crypto->status != STATUS_INIT && crypto->status != STATUS_RUNNING;
}

static void crypto_file_round_trip(bool compressed)
{
	static const uint8_t key[] = "full encrypt/decrypt test key";
	uint8_t expected[TEST_DATA_LENGTH];
	for (size_t i = 0; i < sizeof expected; i++)
		expected[i] = compressed ? (uint8_t)('a' + i % 7) : (uint8_t)(i * 37u);

	char *input_path = create_temp_path();
	char *encrypted_path = create_temp_path();
	char *decrypted_path = create_temp_path();
	assert_non_null(input_path);
	assert_non_null(encrypted_path);
	assert_non_null(decrypted_path);

	int input_fd = open(input_path, O_WRONLY | O_TRUNC | O_BINARY);
	assert_true(input_fd >= 0);
	assert_true(write_all(input_fd, expected, sizeof expected));
	assert_int_equal(close(input_fd), 0);

	crypto_s *encrypt = encrypt_init(input_path, encrypted_path,
	                                 "AES", "SHA256", "CBC", "HMAC_SHA256",
	                                 key, sizeof key, 10, false, compressed,
	                                 false, VERSION_CURRENT);
	assert_non_null(encrypt);
	assert_int_equal(encrypt->status, STATUS_INIT);
	execute(encrypt);
	assert_true(wait_for_completion(encrypt));
	assert_int_equal(encrypt->status, STATUS_SUCCESS);
	assert_string_equal(status(encrypt), "Success");
	deinit(&encrypt);
	assert_null(encrypt);

	crypto_s *decrypt = decrypt_init(encrypted_path, decrypted_path,
	                                 NULL, NULL, NULL, NULL, key, sizeof key,
	                                 0, false);
	assert_non_null(decrypt);
	assert_int_equal(decrypt->status, STATUS_INIT);
	execute(decrypt);
	assert_true(wait_for_completion(decrypt));
	assert_int_equal(decrypt->status, STATUS_SUCCESS);
	assert_string_equal(status(decrypt), "Success");
	deinit(&decrypt);
	assert_null(decrypt);

	struct stat output_stat;
	assert_int_equal(stat(decrypted_path, &output_stat), 0);
	assert_int_equal(output_stat.st_size, sizeof expected);

	int output_fd = open(decrypted_path, O_RDONLY | O_BINARY);
	assert_true(output_fd >= 0);
	uint8_t actual[sizeof expected];
	size_t offset = 0;
	while (offset < sizeof actual)
	{
		ssize_t received = read(output_fd, actual + offset, sizeof actual - offset);
		if (received < 0 && errno == EINTR)
			continue;
		assert_true(received > 0);
		offset += (size_t)received;
	}
	assert_int_equal(close(output_fd), 0);
	assert_memory_equal(actual, expected, sizeof expected);
}

static void test_encrypt_decrypt_file_round_trip(void **state)
{
	(void)state;
	crypto_file_round_trip(false);
}

static void test_compressed_encrypt_decrypt_file_round_trip(void **state)
{
	(void)state;
	crypto_file_round_trip(true);
}

int main(void)
{
	const struct CMUnitTest tests[] =
	{
		cmocka_unit_test_setup_teardown(test_encrypt_decrypt_file_round_trip, setup, teardown),
		cmocka_unit_test_setup_teardown(test_compressed_encrypt_decrypt_file_round_trip, setup, teardown)
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
