#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

#include "common/src/ecc.h"
#include "src/ccrypt.h"
#include "src/crypt_io.h"

#define STREAM_VALID 0
#define STREAM_TRUNCATED 1
#define STREAM_CORRUPTED 2

#ifndef _WIN32
static struct sigaction previous_sigpipe;
#else
static char windows_temp_paths[4][MAX_PATH];
static size_t windows_temp_count;
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
	for (size_t i = 0; i < windows_temp_count; i++)
	{
		DeleteFileA(windows_temp_paths[i]);
		windows_temp_paths[i][0] = '\0';
	}
	windows_temp_count = 0;
	return 0;
#endif
}

static IO_HANDLE wrap_temp_file(int *fd)
{
#ifdef _WIN32
	char directory[MAX_PATH];
	if (windows_temp_count >= sizeof windows_temp_paths / sizeof windows_temp_paths[0])
		return NULL;
	char *path = windows_temp_paths[windows_temp_count];
	if (!GetTempPathA(sizeof directory, directory) ||
	    !GetTempFileNameA(directory, "eio", 0, path))
		return NULL;
	*fd = _open(path, _O_RDWR | _O_BINARY);
	if (*fd < 0)
	{
		DeleteFileA(path);
		path[0] = '\0';
	}
	else
		windows_temp_count++;
#else
	char path[] = "/tmp/encrypt-io-test-XXXXXX";
	*fd = mkstemp(path);
	unlink(path);
#endif
	if (*fd < 0)
		return NULL;
	return io_wrap_fd(*fd);
}

static void flip_file_byte(int fd, off_t offset)
{
	assert_int_equal(lseek(fd, offset, SEEK_SET), offset);
	uint8_t value;
	assert_int_equal(read(fd, &value, sizeof value), sizeof value);
	value ^= 0xff;
	assert_int_equal(lseek(fd, offset, SEEK_SET), offset);
	assert_int_equal(write(fd, &value, sizeof value), sizeof value);
}

static void crypto_round_trip(size_t data_length, bool compressed, bool correction, int stream_damage)
{
	static const uint8_t key[] = "cmocka deterministic test key";
	uint8_t *expected = malloc(data_length ? data_length : 1);
	assert_non_null(expected);
	for (size_t i = 0; i < data_length; i++)
		expected[i] = compressed ? (uint8_t)('a' + i % 7) : (uint8_t)(i * 37u);

	int fd;
	IO_HANDLE writer = wrap_temp_file(&fd);
	assert_non_null(writer);
	if (correction)
		io_correction_init(writer);

	io_extra_s encrypt_options = { IV_RANDOM, true };
	assert_true(io_encryption_init(writer, GCRY_CIPHER_AES, GCRY_MD_SHA256,
	                               GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA256,
	                               10, key, sizeof key, encrypt_options));
	if (compressed)
		io_compression_init(writer);
	io_encryption_checksum_init(writer, GCRY_MD_SHA256);
	assert_int_equal(io_write(writer, expected, data_length), data_length);

	uint8_t *expected_checksum = NULL;
	uint8_t *expected_mac = NULL;
	size_t checksum_length = 0;
	size_t mac_length = 0;
	io_encryption_checksum(writer, &expected_checksum, &checksum_length);
	io_encryption_mac(writer, &expected_mac, &mac_length);
	assert_true(checksum_length > 0);
	assert_true(mac_length > 0);
	assert_int_equal(io_sync(writer), 0);
	if (stream_damage != STREAM_VALID)
	{
		off_t stream_length = io_seek(writer, 0, SEEK_END);
		assert_true(stream_length > 1);
		if (stream_damage == STREAM_CORRUPTED)
			flip_file_byte(fd, stream_length - 1);
		else
		{
#ifdef _WIN32
			assert_int_equal(_chsize_s(fd, stream_length - 1), 0);
#else
			assert_int_equal(ftruncate(fd, stream_length - 1), 0);
#endif
		}
	}

	int read_fd = dup(fd);
	assert_true(read_fd >= 0);
	assert_int_equal(io_close(writer), 0);
	IO_HANDLE reader = io_wrap_fd(read_fd);
	assert_non_null(reader);
	assert_int_equal(io_seek(reader, 0, SEEK_SET), 0);
	if (correction)
		io_correction_init(reader);

	io_extra_s decrypt_options = { IV_RANDOM, false };
	assert_true(io_encryption_init(reader, GCRY_CIPHER_AES, GCRY_MD_SHA256,
	                               GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA256,
	                               10, key, sizeof key, decrypt_options));
	if (compressed)
		io_compression_init(reader);
	io_encryption_checksum_init(reader, GCRY_MD_SHA256);

	uint8_t *actual = malloc(data_length ? data_length : 1);
	assert_non_null(actual);
	bool read_ok = io_read_exact(reader, actual, data_length);
	if (stream_damage != STREAM_VALID)
	{
		if (read_ok)
		{
			uint8_t trailing;
			assert_int_equal(io_read(reader, &trailing, sizeof trailing), -1);
		}
		assert_int_equal(io_error(reader), stream_damage == STREAM_CORRUPTED ? EILSEQ : EIO);
		free(actual);
		free(expected);
		gcry_free(expected_checksum);
		gcry_free(expected_mac);
		assert_int_equal(io_close(reader), -1);
		return;
	}
	assert_true(read_ok);
	assert_memory_equal(actual, expected, data_length);
	if (compressed)
	{
		uint8_t trailing;
		assert_int_equal(io_read(reader, &trailing, sizeof trailing), 0);
	}

	uint8_t *actual_checksum = NULL;
	uint8_t *actual_mac = NULL;
	size_t actual_checksum_length = 0;
	size_t actual_mac_length = 0;
	io_encryption_checksum(reader, &actual_checksum, &actual_checksum_length);
	io_encryption_mac(reader, &actual_mac, &actual_mac_length);
	assert_int_equal(actual_checksum_length, checksum_length);
	assert_memory_equal(actual_checksum, expected_checksum, checksum_length);
	assert_int_equal(actual_mac_length, mac_length);
	assert_memory_equal(actual_mac, expected_mac, mac_length);

	gcry_free(expected_checksum);
	gcry_free(expected_mac);
	gcry_free(actual_checksum);
	gcry_free(actual_mac);
	free(actual);
	free(expected);
	assert_int_equal(io_error(reader), 0);
	assert_int_equal(io_close(reader), 0);
}

static void test_encrypted_io_round_trip(void **state)
{
	(void)state;
	crypto_round_trip(4097, false, false, STREAM_VALID);
}

static void test_compressed_ecc_encrypted_round_trip(void **state)
{
	(void)state;
	crypto_round_trip(4097, true, true, STREAM_VALID);
}

static void test_compressed_empty_payload_round_trip(void **state)
{
	(void)state;
	crypto_round_trip(0, true, false, STREAM_VALID);
}

static void test_compressed_large_payload_round_trip(void **state)
{
	(void)state;
	crypto_round_trip(256 * 1024 + 37, true, false, STREAM_VALID);
}

static void test_truncated_compressed_encrypted_stream_fails(void **state)
{
	(void)state;
	crypto_round_trip(4097, true, false, STREAM_TRUNCATED);
}

static void test_corrupted_compressed_encrypted_stream_fails(void **state)
{
	(void)state;
	crypto_round_trip(4097, true, false, STREAM_CORRUPTED);
}

static void test_truncated_ecc_record_fails(void **state)
{
	(void)state;
	int fd;
	IO_HANDLE io = wrap_temp_file(&fd);
	assert_non_null(io);
	const uint8_t truncated_record[] = { 10, 1, 2, 3 };
	assert_int_equal(io_write(io, truncated_record, sizeof truncated_record), sizeof truncated_record);
	assert_int_equal(io_seek(io, 0, SEEK_SET), 0);
	io_correction_init(io);

	uint8_t value;
	assert_false(io_read_exact(io, &value, sizeof value));
	assert_int_equal(io_error(io), EIO);
	assert_int_equal(io_close(io), -1);
	assert_int_equal(errno, EIO);
}

static void assert_truncated_encryption_header(size_t header_length)
{
	static const uint8_t key[] = "cmocka deterministic test key";
	uint8_t header[64] = { 0 };
	size_t key_length = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES);
	size_t iv_length = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES);
	assert_true(key_length > 0);
	assert_true(iv_length > 0);
	assert_true(key_length + iv_length <= sizeof header);
	assert_true(header_length < key_length + iv_length);

	int fd;
	IO_HANDLE io = wrap_temp_file(&fd);
	assert_non_null(io);
	assert_int_equal(io_write(io, header, header_length), header_length);
	assert_int_equal(io_seek(io, 0, SEEK_SET), 0);

	io_extra_s options = { IV_RANDOM, false };
	errno = 0;
	assert_false(io_encryption_init(io, GCRY_CIPHER_AES, GCRY_MD_SHA256,
	                                GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA256,
	                                10, key, sizeof key, options));
	assert_int_equal(errno, EIO);
	assert_int_equal(io_error(io), EIO);
	assert_false(io_encryption_init(io, GCRY_CIPHER_AES, GCRY_MD_SHA256,
	                                GCRY_CIPHER_MODE_CBC, GCRY_MAC_HMAC_SHA256,
	                                10, key, sizeof key, options));
	assert_int_equal(errno, EIO);
	assert_int_equal(io_close(io), -1);
	assert_int_equal(errno, EIO);
}

static void test_truncated_kdf_salt_fails_initialization(void **state)
{
	(void)state;
	size_t key_length = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES);
	assert_true(key_length > 1);
	assert_truncated_encryption_header(key_length - 1);
}

static void test_truncated_iv_fails_initialization(void **state)
{
	(void)state;
	size_t key_length = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES);
	size_t iv_length = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES);
	assert_true(iv_length > 1);
	assert_truncated_encryption_header(key_length + iv_length - 1);
}

static void ecc_corruption_round_trip(size_t error_count, bool should_recover)
{
	uint8_t expected[ECC_PAYLOAD];
	for (size_t i = 0; i < sizeof expected; i++)
		expected[i] = (uint8_t)(i * 37u);

	int fd;
	IO_HANDLE writer = wrap_temp_file(&fd);
	assert_non_null(writer);
	io_correction_init(writer);
	assert_int_equal(io_write(writer, expected, sizeof expected), sizeof expected);
	assert_int_equal(io_sync(writer), 0);

	static const off_t error_offsets[] = { 1, 38, 130, 255 };
	for (size_t i = 0; i < error_count; i++)
		flip_file_byte(fd, error_offsets[i]);

	int read_fd = dup(fd);
	assert_true(read_fd >= 0);
	assert_int_equal(io_close(writer), 0);
	IO_HANDLE reader = io_wrap_fd(read_fd);
	assert_non_null(reader);
	assert_int_equal(io_seek(reader, 0, SEEK_SET), 0);
	io_correction_init(reader);

	uint8_t actual[ECC_PAYLOAD] = { 0 };
	bool read_ok = io_read_exact(reader, actual, sizeof actual);
	if (should_recover)
	{
		assert_true(read_ok);
		assert_memory_equal(actual, expected, sizeof expected);
		assert_int_equal(io_error(reader), 0);
		assert_int_equal(io_close(reader), 0);
	}
	else
	{
		assert_false(read_ok);
		assert_int_equal(io_error(reader), EIO);
		assert_int_equal(io_close(reader), -1);
		assert_int_equal(errno, EIO);
	}
}

static void test_ecc_corrects_three_corrupted_bytes(void **state)
{
	(void)state;
	ecc_corruption_round_trip(3, true);
}

static void test_ecc_rejects_four_corrupted_bytes(void **state)
{
	(void)state;
	ecc_corruption_round_trip(4, false);
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
		cmocka_unit_test_setup_teardown(test_encrypted_io_round_trip, setup, teardown),
		cmocka_unit_test_setup_teardown(test_compressed_ecc_encrypted_round_trip, setup, teardown),
		cmocka_unit_test_setup_teardown(test_compressed_empty_payload_round_trip, setup, teardown),
		cmocka_unit_test_setup_teardown(test_compressed_large_payload_round_trip, setup, teardown),
		cmocka_unit_test_setup_teardown(test_truncated_compressed_encrypted_stream_fails, setup, teardown),
		cmocka_unit_test_setup_teardown(test_corrupted_compressed_encrypted_stream_fails, setup, teardown),
		cmocka_unit_test_setup_teardown(test_truncated_ecc_record_fails, setup, teardown),
		cmocka_unit_test_setup_teardown(test_truncated_kdf_salt_fails_initialization, setup, teardown),
		cmocka_unit_test_setup_teardown(test_truncated_iv_fails_initialization, setup, teardown),
		cmocka_unit_test_setup_teardown(test_ecc_corrects_three_corrupted_bytes, setup, teardown),
		cmocka_unit_test_setup_teardown(test_ecc_rejects_four_corrupted_bytes, setup, teardown),
#ifndef _WIN32
		cmocka_unit_test_setup_teardown(test_pipe_write_failure_is_latched, setup, teardown),
#endif
		cmocka_unit_test_setup_teardown(test_pipe_sync_and_seek, setup, teardown)
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
