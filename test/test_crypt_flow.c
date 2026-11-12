/*
 * Unit tests.
 * Copyright © 2026, albinoloverats ~ Software Development
 * email: webmaster@albinoloverats.net
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <dirent.h>
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
	#include <netinet/in.h>
	#include <limits.h>
	#define TEST_PATH_LENGTH PATH_MAX
#endif

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/* common includes */

#include "src/common.h"
#include "src/ccrypt.h"

/* project includes */

#include "crypt.h"
#include "decrypt.h"
#include "encrypt.h"

#define TEST_DATA_LENGTH (32 * 1024 + 37)
#define TEST_PATH_COUNT 8

static char test_paths[TEST_PATH_COUNT][TEST_PATH_LENGTH];
static bool test_path_is_directory[TEST_PATH_COUNT];
static size_t test_path_count;
static int original_stdin = -1;
static int original_stdout = -1;

static int setup(void **state)
{
	(void)state;
	test_path_count = 0;
	original_stdin = dup(STDIN_FILENO);
	if (original_stdin < 0)
		return -1;
	original_stdout = dup(STDOUT_FILENO);
	if (original_stdout < 0)
	{
		close(original_stdin);
		original_stdin = -1;
		return -1;
	}
	init_crypto();
	return 0;
}

static void remove_tree(const char *path)
{
#ifdef _WIN32
	DWORD attributes = GetFileAttributesA(path);
	if (attributes == INVALID_FILE_ATTRIBUTES)
		return;
	if (!(attributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		DeleteFileA(path);
		return;
	}
	char pattern[MAX_PATH];
	snprintf(pattern, sizeof pattern, "%s\\*", path);
	WIN32_FIND_DATAA entry;
	HANDLE find = FindFirstFileA(pattern, &entry);
	if (find != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (!strcmp(entry.cFileName, ".") || !strcmp(entry.cFileName, ".."))
				continue;
			char child[MAX_PATH];
			snprintf(child, sizeof child, "%s\\%s", path, entry.cFileName);
			remove_tree(child);
		}
		while (FindNextFileA(find, &entry));
		FindClose(find);
	}
	RemoveDirectoryA(path);
#else
	struct stat info;
	if (lstat(path, &info) < 0)
		return;
	if (!S_ISDIR(info.st_mode))
	{
		unlink(path);
		return;
	}
	DIR *directory = opendir(path);
	if (directory)
	{
		struct dirent *entry;
		while ((entry = readdir(directory)))
		{
			if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
				continue;
			char child[TEST_PATH_LENGTH];
			int length = snprintf(child, sizeof child, "%s/%s", path, entry->d_name);
			if (length >= 0 && (size_t)length < sizeof child)
				remove_tree(child);
		}
		closedir(directory);
	}
	rmdir(path);
#endif
}

static int teardown(void **state)
{
	(void)state;
	for (size_t i = test_path_count; i > 0; i--)
	{
		size_t index = i - 1;
		if (test_path_is_directory[index])
			remove_tree(test_paths[index]);
		else
		{
#ifdef _WIN32
			DeleteFileA(test_paths[index]);
#else
			unlink(test_paths[index]);
#endif
		}
	}
	test_path_count = 0;
	int result = 0;
	if (original_stdin >= 0)
	{
		if (dup2(original_stdin, STDIN_FILENO) < 0)
			result = -1;
		close(original_stdin);
		original_stdin = -1;
	}
	if (original_stdout >= 0)
	{
		if (dup2(original_stdout, STDOUT_FILENO) < 0)
			result = -1;
		close(original_stdout);
		original_stdout = -1;
	}
	return result;
}

static char *create_temp_path(void)
{
	if (test_path_count >= TEST_PATH_COUNT)
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
	test_path_is_directory[test_path_count] = false;
	test_path_count++;
	return path;
}

static char *create_temp_directory(void)
{
	if (test_path_count >= TEST_PATH_COUNT)
		return NULL;

	char *path = test_paths[test_path_count];
#ifdef _WIN32
	char directory[MAX_PATH];
	if (!GetTempPathA(sizeof directory, directory) ||
	    !GetTempFileNameA(directory, "ecf", 0, path))
		return NULL;
	if (!DeleteFileA(path) || !CreateDirectoryA(path, NULL))
		return NULL;
#else
	int written = snprintf(path, TEST_PATH_LENGTH, "/tmp/encrypt-flow-dir-XXXXXX");
	if (written < 0 || (size_t)written >= TEST_PATH_LENGTH || !mkdtemp(path))
		return NULL;
#endif
	test_path_is_directory[test_path_count] = true;
	test_path_count++;
	return path;
}

static void make_child_path(char *path, size_t size, const char *directory, const char *name)
{
#ifdef _WIN32
	int length = snprintf(path, size, "%s\\%s", directory, name);
#else
	int length = snprintf(path, size, "%s/%s", directory, name);
#endif
	assert_true(length >= 0);
	assert_true((size_t)length < size);
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

static void write_file(const char *path, const uint8_t *data, size_t length)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
	assert_true(fd >= 0);
	assert_true(write_all(fd, data, length));
	assert_int_equal(close(fd), 0);
}

static version_e detect_metadata(const char *path)
{
	char *cipher = "";
	char *hash = "";
	char *mode = "";
	char *mac = "";
	version_e version = is_encrypted(path, &cipher, &hash, &mode, &mac, NULL);
	if (version != VERSION_UNKNOWN)
	{
		free(cipher);
		free(hash);
		free(mode);
		free(mac);
	}
	return version;
}

static void write_test_container_metadata(const char *path,
                                         const char *metadata,
                                         size_t available,
                                         size_t declared)
{
	uint64_t header[] =
	{
		htonll(HEADER_0),
		htonll(HEADER_1),
		htonll(get_version(VERSION_CURRENT))
	};
	uint8_t contents[sizeof header + 2 + 255] = { 0 };
	memcpy(contents, header, sizeof header);
	contents[sizeof header] = 0;
	contents[sizeof header + 1] = (uint8_t)declared;
	memcpy(contents + sizeof header + 2, metadata, available);
	write_file(path, contents, sizeof header + 2 + available);
}

static void assert_file_contents(const char *path, const uint8_t *expected, size_t length)
{
	int fd = open(path, O_RDONLY | O_BINARY);
	assert_true(fd >= 0);
	uint8_t *actual = malloc(length ? length : 1);
	assert_non_null(actual);
	size_t offset = 0;
	while (offset < length)
	{
		ssize_t received = read(fd, actual + offset, length - offset);
		if (received < 0 && errno == EINTR)
			continue;
		assert_true(received > 0);
		offset += (size_t)received;
	}
	uint8_t trailing;
	assert_int_equal(read(fd, &trailing, sizeof trailing), 0);
	assert_int_equal(close(fd), 0);
	assert_memory_equal(actual, expected, length);
	free(actual);
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

static crypto_s *new_encrypt(const char *input, const char *output,
                             const char *cipher, const char *hash,
                             const char *mode, const char *mac,
                             bool compressed, bool follow_links,
                             version_e version)
{
	static const uint8_t key[] = "full encrypt/decrypt test key";
	return encrypt_init(input, output, cipher, hash, mode, mac,
	                    key, sizeof key, 10, false, compressed,
	                    follow_links, version);
}

static void assert_encrypt_init_status(const char *input, const char *output,
                                       const char *cipher, const char *hash,
                                       const char *mode, const char *mac,
                                       crypto_status_e expected)
{
	crypto_s *crypto = new_encrypt(input, output, cipher, hash, mode, mac,
	                               false, false, VERSION_CURRENT);
	assert_non_null(crypto);
	assert_int_equal(crypto->status, expected);
	deinit(&crypto);
	assert_null(crypto);
}

static void assert_decrypt_init_status(const char *input, const char *output,
                                      bool raw, crypto_status_e expected)
{
	static const uint8_t key[] = "full encrypt/decrypt test key";
	crypto_s *crypto = decrypt_init(input, output,
	                                raw ? "AES" : NULL,
	                                raw ? "SHA256" : NULL,
	                                raw ? "CBC" : NULL,
	                                raw ? "HMAC_SHA256" : NULL,
	                                key, sizeof key, 10, raw);
	assert_non_null(crypto);
	assert_int_equal(crypto->status, expected);
	deinit(&crypto);
	assert_null(crypto);
}

static void assert_raw_decrypt_init_status(const char *input, const char *output,
                                           const char *cipher, const char *hash,
                                           const char *mode, const char *mac,
                                           crypto_status_e expected)
{
	static const uint8_t key[] = "full encrypt/decrypt test key";
	crypto_s *crypto = decrypt_init(input, output, cipher, hash, mode, mac,
	                                key, sizeof key, 10, true);
	assert_non_null(crypto);
	assert_int_equal(crypto->status, expected);
	deinit(&crypto);
	assert_null(crypto);
}

static void test_encrypt_init_rejects_missing_input_and_same_file_output(void **state)
{
	(void)state;
	char *missing_path = create_temp_path();
	char *input_path = create_temp_path();
	assert_non_null(missing_path);
	assert_non_null(input_path);
	assert_int_equal(unlink(missing_path), 0);

	assert_encrypt_init_status(missing_path, NULL, "AES", "SHA256", "CBC",
	                           "HMAC_SHA256", STATUS_FAILED_IO);

	static const uint8_t original[] = "preserve input";
	write_file(input_path, original, sizeof original);
	assert_encrypt_init_status(input_path, input_path, "AES", "SHA256", "CBC",
	                           "HMAC_SHA256", STATUS_FAILED_OUTPUT_MISMATCH);
	int fd = open(input_path, O_RDONLY | O_BINARY);
	assert_true(fd >= 0);
	uint8_t actual[sizeof original];
	assert_int_equal(read(fd, actual, sizeof actual), sizeof actual);
	assert_int_equal(close(fd), 0);
	assert_memory_equal(actual, original, sizeof original);
}

static void test_encrypt_init_rejects_invalid_algorithms(void **state)
{
	(void)state;
	char *input_path = create_temp_path();
	char *output_path = create_temp_path();
	assert_non_null(input_path);
	assert_non_null(output_path);

	assert_encrypt_init_status(input_path, output_path, "not-a-cipher", "SHA256",
	                           "CBC", "HMAC_SHA256", STATUS_FAILED_UNKNOWN_CIPHER_ALGORITHM);
	assert_encrypt_init_status(input_path, output_path, "AES", "not-a-hash",
	                           "CBC", "HMAC_SHA256", STATUS_FAILED_UNKNOWN_HASH_ALGORITHM);
	assert_encrypt_init_status(input_path, output_path, "AES", "SHA256",
	                           "not-a-mode", "HMAC_SHA256", STATUS_FAILED_UNKNOWN_CIPHER_MODE);
	assert_encrypt_init_status(input_path, output_path, "AES", "SHA256",
	                           "CBC", "not-a-mac", STATUS_FAILED_UNKNOWN_MAC_ALGORITHM);
	assert_encrypt_init_status(input_path, output_path, "AES", "SHA256",
	                           "STREAM", "HMAC_SHA256", STATUS_FAILED_CIPHER_MODE_MISMATCH);
}

static void test_decrypt_init_rejects_missing_input_and_same_file_output(void **state)
{
	(void)state;
	char *missing_path = create_temp_path();
	char *input_path = create_temp_path();
	assert_non_null(missing_path);
	assert_non_null(input_path);
	assert_int_equal(unlink(missing_path), 0);
	assert_decrypt_init_status(missing_path, NULL, false, STATUS_FAILED_IO);

	static const uint8_t original[] = "preserve encrypted input";
	write_file(input_path, original, sizeof original);
	assert_decrypt_init_status(input_path, input_path, false, STATUS_FAILED_OUTPUT_MISMATCH);
	int fd = open(input_path, O_RDONLY | O_BINARY);
	assert_true(fd >= 0);
	uint8_t actual[sizeof original];
	assert_int_equal(read(fd, actual, sizeof actual), sizeof actual);
	assert_int_equal(close(fd), 0);
	assert_memory_equal(actual, original, sizeof original);
}

static void test_decrypt_init_rejects_invalid_raw_algorithms(void **state)
{
	(void)state;
	char *input_path = create_temp_path();
	char *output_path = create_temp_path();
	assert_non_null(input_path);
	assert_non_null(output_path);

	assert_raw_decrypt_init_status(input_path, output_path, "not-a-cipher",
	                               "SHA256", "CBC", "HMAC_SHA256",
	                               STATUS_FAILED_UNKNOWN_CIPHER_ALGORITHM);
	assert_raw_decrypt_init_status(input_path, output_path, "AES",
	                               "not-a-hash", "CBC", "HMAC_SHA256",
	                               STATUS_FAILED_UNKNOWN_HASH_ALGORITHM);
	assert_raw_decrypt_init_status(input_path, output_path, "AES",
	                               "SHA256", "not-a-mode", "HMAC_SHA256",
	                               STATUS_FAILED_UNKNOWN_CIPHER_MODE);
	assert_raw_decrypt_init_status(input_path, output_path, "AES",
	                               "SHA256", "CBC", "not-a-mac",
	                               STATUS_FAILED_UNKNOWN_MAC_ALGORITHM);
}

static void test_decrypt_rejects_unknown_stream_version(void **state)
{
	(void)state;
	char *input_path = create_temp_path();
	char *output_path = create_temp_path();
	assert_non_null(input_path);
	assert_non_null(output_path);
	uint8_t invalid_header[24] = { 0 };
	write_file(input_path, invalid_header, sizeof invalid_header);

	crypto_s *crypto = decrypt_init(input_path, output_path, NULL, NULL, NULL,
	                                NULL, "key", 4, 0, false);
	assert_non_null(crypto);
	assert_int_equal(crypto->status, STATUS_INIT);
	execute(crypto);
	assert_true(wait_for_completion(crypto));
	assert_int_equal(crypto->status, STATUS_FAILED_UNKNOWN_VERSION);
	deinit(&crypto);
	assert_null(crypto);
}

static void test_container_detection_rejects_truncated_headers_and_metadata(void **state)
{
	(void)state;
	char *path = create_temp_path();
	assert_non_null(path);

	uint64_t partial_magic = htonll(HEADER_0);
	write_file(path, (const uint8_t *)&partial_magic, sizeof partial_magic);
	assert_int_equal(is_encrypted(path), VERSION_UNKNOWN);

	uint64_t mismatched_header[] =
	{
		htonll(HEADER_0),
		0,
		htonll(get_version(VERSION_CURRENT))
	};
	write_file(path, (const uint8_t *)mismatched_header, sizeof mismatched_header);
	assert_int_equal(is_encrypted(path), VERSION_UNKNOWN);

	write_test_container_metadata(path, "AES256", 6, 6);
	assert_int_equal(detect_metadata(path), VERSION_UNKNOWN);

	write_test_container_metadata(path, "AES256//CBC/HMAC_SHA256/10",
	                              strlen("AES256//CBC/HMAC_SHA256/10"),
	                              strlen("AES256//CBC/HMAC_SHA256/10"));
	assert_int_equal(detect_metadata(path), VERSION_UNKNOWN);

	write_test_container_metadata(path, "AES256/SHA256/CBC/HMAC_SHA256/zz",
	                              strlen("AES256/SHA256/CBC/HMAC_SHA256/zz"),
	                              strlen("AES256/SHA256/CBC/HMAC_SHA256/zz"));
	assert_int_equal(detect_metadata(path), VERSION_UNKNOWN);

	write_test_container_metadata(path, "AES256/SHA256", 2, 20);
	assert_int_equal(detect_metadata(path), VERSION_UNKNOWN);
}

static void test_key_file_rejects_non_regular_file(void **state)
{
	(void)state;
	char *input = create_temp_path();
	char *output = create_temp_path();
	char *key_path = create_temp_path();
	char *valid_key_path = create_temp_path();
	assert_non_null(input);
	assert_non_null(output);
	assert_non_null(key_path);
	assert_non_null(valid_key_path);
	static const uint8_t key_bytes[] = "file-backed test key";
	write_file(valid_key_path, key_bytes, sizeof key_bytes);
	uint8_t *loaded_key = NULL;
	size_t loaded_key_size = 0;
	assert_true(read_key_file(valid_key_path, &loaded_key, &loaded_key_size));
	assert_int_equal(loaded_key_size, sizeof key_bytes);
	assert_memory_equal(loaded_key, key_bytes, sizeof key_bytes);
	gcry_free(loaded_key);

	assert_int_equal(unlink(key_path), 0);
	assert_int_equal(mkdir(key_path, 0700), 0);
	assert_false(read_key_file(key_path, &loaded_key, &loaded_key_size));
	assert_null(loaded_key);
	assert_int_equal(loaded_key_size, 0);
	static const uint8_t contents[] = "input";
	write_file(input, contents, sizeof contents);

	crypto_s *encrypt = encrypt_init(input, output, "AES", "SHA256", "CBC",
	                                 "HMAC_SHA256", (const uint8_t *)key_path,
	                                 0, 10, false, false, false, VERSION_CURRENT);
	assert_non_null(encrypt);
	assert_int_equal(encrypt->status, STATUS_FAILED_IO);
	deinit(&encrypt);

	crypto_s *decrypt = decrypt_init(input, output, NULL, NULL, NULL, NULL,
	                                 (const uint8_t *)key_path, 0, 10, false);
	assert_non_null(decrypt);
	assert_int_equal(decrypt->status, STATUS_FAILED_IO);
	deinit(&decrypt);

	assert_int_equal(rmdir(key_path), 0);
}

static void test_decrypt_rejects_wrong_key(void **state)
{
	(void)state;
	char *input_path = create_temp_path();
	char *encrypted_path = create_temp_path();
	char *decrypted_path = create_temp_path();
	assert_non_null(input_path);
	assert_non_null(encrypted_path);
	assert_non_null(decrypted_path);
	static const uint8_t plaintext[] = "wrong passwords fail verification";
	write_file(input_path, plaintext, sizeof plaintext);

	crypto_s *encrypt = new_encrypt(input_path, encrypted_path, "AES", "SHA256",
	                                "CBC", "HMAC_SHA256", false, false,
	                                VERSION_CURRENT);
	assert_non_null(encrypt);
	execute(encrypt);
	assert_true(wait_for_completion(encrypt));
	assert_int_equal(encrypt->status, STATUS_SUCCESS);
	deinit(&encrypt);

	crypto_s *decrypt = decrypt_init(encrypted_path, decrypted_path,
	                                 NULL, NULL, NULL, NULL,
	                                 "incorrect key", sizeof "incorrect key", 0, false);
	assert_non_null(decrypt);
	execute(decrypt);
	assert_true(wait_for_completion(decrypt));
	assert_int_equal(decrypt->status, STATUS_FAILED_DECRYPTION);
	deinit(&decrypt);
}

static void test_stdin_stream_round_trip(void **state)
{
	(void)state;
	static const uint8_t key[] = "full encrypt/decrypt test key";
	uint8_t expected[TEST_DATA_LENGTH];
	for (size_t i = 0; i < sizeof expected; i++)
		expected[i] = (uint8_t)(i * 19u);

	char *input_path = create_temp_path();
	char *encrypted_path = create_temp_path();
	char *decrypted_path = create_temp_path();
	assert_non_null(input_path);
	assert_non_null(encrypted_path);
	assert_non_null(decrypted_path);
	write_file(input_path, expected, sizeof expected);

	int input_fd = open(input_path, O_RDONLY | O_BINARY);
	assert_true(input_fd >= 0);
	assert_int_equal(dup2(input_fd, STDIN_FILENO), STDIN_FILENO);
	assert_int_equal(close(input_fd), 0);

	crypto_s *encrypt = encrypt_init(NULL, encrypted_path, "AES", "SHA256",
	                                 "CBC", "HMAC_SHA256", key, sizeof key,
	                                 10, false, false, false, VERSION_CURRENT);
	assert_non_null(encrypt);
	execute(encrypt);
	assert_true(wait_for_completion(encrypt));
	assert_int_equal(encrypt->status, STATUS_SUCCESS);
	deinit(&encrypt);
	assert_int_equal(dup2(original_stdin, STDIN_FILENO), STDIN_FILENO);

	crypto_s *decrypt = decrypt_init(encrypted_path, decrypted_path,
	                                 NULL, NULL, NULL, NULL, key, sizeof key,
	                                 0, false);
	assert_non_null(decrypt);
	execute(decrypt);
	assert_true(wait_for_completion(decrypt));
	assert_int_equal(decrypt->status, STATUS_SUCCESS);
	deinit(&decrypt);

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

static void test_directory_archive_round_trip(void **state)
{
	(void)state;
	static const uint8_t key[] = "full encrypt/decrypt test key";
	static const uint8_t root_contents[] = "root file contents";
	static const uint8_t nested_contents[] = "nested file contents";
	char *source = create_temp_directory();
	char *archive = create_temp_path();
	char *destination = create_temp_directory();
	char *follow_archive = create_temp_path();
	char *follow_destination = create_temp_directory();
	assert_non_null(source);
	assert_non_null(archive);
	assert_non_null(destination);
	assert_non_null(follow_archive);
	assert_non_null(follow_destination);

	char nested[TEST_PATH_LENGTH];
	char empty[TEST_PATH_LENGTH];
	char root_file[TEST_PATH_LENGTH];
	char nested_file[TEST_PATH_LENGTH];
	char hardlink[TEST_PATH_LENGTH];
	char symlink_path[TEST_PATH_LENGTH];
	char inside_archive[TEST_PATH_LENGTH];
	make_child_path(nested, sizeof nested, source, "nested");
	make_child_path(empty, sizeof empty, source, "empty");
	make_child_path(root_file, sizeof root_file, source, "root.txt");
	make_child_path(nested_file, sizeof nested_file, nested, "nested.txt");
	make_child_path(hardlink, sizeof hardlink, source, "root-hardlink.txt");
	make_child_path(symlink_path, sizeof symlink_path, source, "root-symlink.txt");
	make_child_path(inside_archive, sizeof inside_archive, source, "inside.ccrypt");
	assert_int_equal(mkdir(nested, S_IRUSR | S_IWUSR | S_IXUSR), 0);
	assert_int_equal(mkdir(empty, S_IRUSR | S_IWUSR | S_IXUSR), 0);
	write_file(root_file, root_contents, sizeof root_contents);
	write_file(nested_file, nested_contents, sizeof nested_contents);
#ifndef _WIN32
	assert_int_equal(link(root_file, hardlink), 0);
	assert_int_equal(symlink("root.txt", symlink_path), 0);
#endif

	assert_encrypt_init_status(source, inside_archive, "AES", "SHA256", "CBC",
	                           "HMAC_SHA256", STATUS_FAILED_OUTPUT_MISMATCH);
	crypto_s *legacy_directory = encrypt_init(source, archive, "AES", "SHA256",
	                                          "CBC", "HMAC_SHA256", key, sizeof key,
	                                          10, false, false, false, VERSION_2012_11);
	assert_non_null(legacy_directory);
	assert_int_equal(legacy_directory->status, STATUS_FAILED_OUTPUT_MISMATCH);
	deinit(&legacy_directory);

	crypto_s *encrypt = encrypt_init(source, archive, "AES", "SHA256", "CBC",
	                                 "HMAC_SHA256", key, sizeof key, 10, false,
	                                 false, false, VERSION_CURRENT);
	assert_non_null(encrypt);
	assert_int_equal(encrypt->status, STATUS_INIT);
	execute(encrypt);
	assert_true(wait_for_completion(encrypt));
	assert_int_equal(encrypt->status, STATUS_SUCCESS);
	deinit(&encrypt);

	crypto_s *missing_destination = decrypt_init(archive, NULL, NULL, NULL, NULL,
	                                             NULL, key, sizeof key, 0, false);
	assert_non_null(missing_destination);
	execute(missing_destination);
	assert_true(wait_for_completion(missing_destination));
	assert_int_equal(missing_destination->status, STATUS_FAILED_OUTPUT_MISMATCH);
	deinit(&missing_destination);
	assert_int_equal(dup2(original_stdout, STDOUT_FILENO), STDOUT_FILENO);

	encrypt = encrypt_init(source, follow_archive, "AES", "SHA256", "CBC",
	                      "HMAC_SHA256", key, sizeof key, 10, false,
	                      false, true, VERSION_CURRENT);
	assert_non_null(encrypt);
	execute(encrypt);
	assert_true(wait_for_completion(encrypt));
	assert_int_equal(encrypt->status, STATUS_SUCCESS);
	deinit(&encrypt);

	crypto_s *decrypt = decrypt_init(archive, destination, NULL, NULL, NULL,
	                                 NULL, key, sizeof key, 0, false);
	assert_non_null(decrypt);
	execute(decrypt);
	assert_true(wait_for_completion(decrypt));
	assert_int_equal(decrypt->status, STATUS_SUCCESS);
	deinit(&decrypt);

	decrypt = decrypt_init(follow_archive, follow_destination, NULL, NULL, NULL,
	                       NULL, key, sizeof key, 0, false);
	assert_non_null(decrypt);
	execute(decrypt);
	assert_true(wait_for_completion(decrypt));
	assert_int_equal(decrypt->status, STATUS_SUCCESS);
	deinit(&decrypt);

	char output_root_file[TEST_PATH_LENGTH];
	char output_root[TEST_PATH_LENGTH];
	char output_nested[TEST_PATH_LENGTH];
	char output_nested_file[TEST_PATH_LENGTH];
	char output_empty[TEST_PATH_LENGTH];
#ifdef _WIN32
	const char *root_name = strrchr(source, '\\');
#else
	const char *root_name = strrchr(source, '/');
#endif
	root_name = root_name ? root_name + 1 : source;
	make_child_path(output_root, sizeof output_root, destination, root_name);
	make_child_path(output_root_file, sizeof output_root_file, output_root, "root.txt");
	make_child_path(output_nested, sizeof output_nested, output_root, "nested");
	make_child_path(output_nested_file, sizeof output_nested_file, output_nested, "nested.txt");
	make_child_path(output_empty, sizeof output_empty, output_root, "empty");
	struct stat info;
	assert_int_equal(stat(output_root_file, &info), 0);
	assert_int_equal(info.st_size, sizeof root_contents);
	assert_file_contents(output_root_file, root_contents, sizeof root_contents);
	assert_int_equal(stat(output_nested_file, &info), 0);
	assert_int_equal(info.st_size, sizeof nested_contents);
	assert_file_contents(output_nested_file, nested_contents, sizeof nested_contents);
	assert_int_equal(stat(output_empty, &info), 0);
	assert_true(S_ISDIR(info.st_mode));
#ifndef _WIN32
	char output_hardlink[TEST_PATH_LENGTH];
	char output_symlink[TEST_PATH_LENGTH];
	char followed_symlink[TEST_PATH_LENGTH];
	char link_target[TEST_PATH_LENGTH];
	make_child_path(output_hardlink, sizeof output_hardlink, output_root, "root-hardlink.txt");
	make_child_path(output_symlink, sizeof output_symlink, output_root, "root-symlink.txt");
	char follow_root[TEST_PATH_LENGTH];
	make_child_path(follow_root, sizeof follow_root, follow_destination, root_name);
	make_child_path(followed_symlink, sizeof followed_symlink, follow_root, "root-symlink.txt");
	assert_int_equal(stat(output_hardlink, &info), 0);
	struct stat root_info;
	assert_int_equal(stat(output_root_file, &root_info), 0);
	assert_int_equal(info.st_ino, root_info.st_ino);
	ssize_t target_length = readlink(output_symlink, link_target, sizeof link_target - 1);
	assert_true(target_length > 0);
	link_target[target_length] = '\0';
	assert_string_equal(link_target, "root.txt");
	assert_int_equal(stat(followed_symlink, &info), 0);
	assert_true(S_ISREG(info.st_mode));
#endif
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
	assert_int_equal(is_encrypted(encrypted_path), VERSION_CURRENT);
	assert_int_equal(detect_metadata(encrypted_path), VERSION_CURRENT);

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
		cmocka_unit_test_setup_teardown(test_encrypt_init_rejects_missing_input_and_same_file_output, setup, teardown),
		cmocka_unit_test_setup_teardown(test_encrypt_init_rejects_invalid_algorithms, setup, teardown),
		cmocka_unit_test_setup_teardown(test_decrypt_init_rejects_missing_input_and_same_file_output, setup, teardown),
		cmocka_unit_test_setup_teardown(test_decrypt_init_rejects_invalid_raw_algorithms, setup, teardown),
		cmocka_unit_test_setup_teardown(test_decrypt_rejects_unknown_stream_version, setup, teardown),
		cmocka_unit_test_setup_teardown(test_container_detection_rejects_truncated_headers_and_metadata, setup, teardown),
		cmocka_unit_test_setup_teardown(test_key_file_rejects_non_regular_file, setup, teardown),
		cmocka_unit_test_setup_teardown(test_decrypt_rejects_wrong_key, setup, teardown),
		cmocka_unit_test_setup_teardown(test_stdin_stream_round_trip, setup, teardown),
		cmocka_unit_test_setup_teardown(test_directory_archive_round_trip, setup, teardown),
		cmocka_unit_test_setup_teardown(test_encrypt_decrypt_file_round_trip, setup, teardown),
		cmocka_unit_test_setup_teardown(test_compressed_encrypt_decrypt_file_round_trip, setup, teardown)
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
