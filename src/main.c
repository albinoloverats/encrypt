/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2021, albinoloverats ~ Software Development
 * email: encrypt@albinoloverats.net
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#include <pthread.h>

#include <string.h>
#include <stdbool.h>

#include <sys/stat.h>
#include <sys/wait.h>

#include <gcrypt.h>

#if defined __FreeBSD__ || defined __sun || defined __APPLE__
	#include <libgen.h>
#endif

#include "common/common.h"
#include "common/non-gnu.h"
#include "common/error.h"
#include "common/ccrypt.h"
#include "common/version.h"
#include "common/config.h"
#include "common/cli.h"

#ifdef _WIN32
	#include <Shlobj.h>
	extern char *program_invocation_short_name;
	#include "common/dir.h"
#endif

#include "crypt.h"
#include "encrypt.h"
#include "decrypt.h"

#ifdef BUILD_GUI
	#include "gui.h"
	#include "gui-gtk.h"

	#define INIT_WIDGET(W) widgets->W = GTK_WIDGET(gtk_builder_get_object(builder, #W))
#endif


#define DECRYPT "decrypt"


extern char *gui_file_hack_source;
extern char *gui_file_hack_output;

static bool list_ciphers(void);
static bool list_hashes(void);
static bool list_modes(void);
static bool list_macs(void);

static int self_test(void) __attribute__((noreturn));

int main(int argc, char **argv)
{
	error_init();
#ifdef __DEBUG__
	cli_fprintf(stderr, "\n" ANSI_COLOUR_RED "**** %s ****" ANSI_COLOUR_RESET "\n\n", _("DEBUG BUILD"));
#endif
#ifdef _WIN32
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	program_invocation_short_name = dir_get_name(argv[0]);
#endif
#ifndef __DEBUG
	/*
	 * start background thread to check for newer version of encrypt
	 *
	 * NB If (When) encrypt makes it into a package manager for some
	 * distros this can/should be removed as it will be unnecessary
	 */
	version_check_for_update(ENCRYPT_VERSION, UPDATE_URL, DOWNLOAD_URL_TEMPLATE);
#endif

	config_arg_t args[] =
	{
#ifdef BUILD_GUI
	#ifndef _WIN32
		{ 'g', "no-gui",         NULL,            _("Do not use the GUI, even if it’s available"),               CONFIG_ARG_REQ_BOOLEAN, { 0x0 }, false, false, false },
	#endif
		{ 0x1, "key-source",     _("key source"), _("Key data source"),                                          CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, true  },
		{ 0x2, "compress",       NULL,            _("Compress the plain text using the xz algorithm"),           CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, true  },
#endif
		{ 'u', "no-cli",         NULL,            _("Do not display the CLI progress bar"),                      CONFIG_ARG_REQ_BOOLEAN, { 0x0 }, false, false, false },
		{ 'c', "cipher",         _("algorithm"),  _("Algorithm to use to encrypt data; use 'list' to show available cipher algorithms"), CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, false },
		{ 's', "hash",           _("algorithm"),  _("Hash algorithm to generate key; use 'list' to show available hash algorithms"),     CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, false },
		{ 'm', "mode",           _("mode"),       _("The encryption mode to use; use 'list' to show available cipher modes"),            CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, false },
		{ 'a', "mac",            _("mac"),        _("The MAC algorithm to use; use 'list' to show available MACs"),                      CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, false },
		{ 'i', "kdf-iterations", _("iterations"), _("Number of iterations the KDF should use"),                  CONFIG_ARG_REQ_NUMBER,  { 0x0 }, false, false, false },
		{ 'k', "key",            _("key file"),   _("File whose data will be used to generate the key"),         CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, false },
		{ 'p', "password",       _("password"),   _("Password used to generate the key"),                        CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, false },
		{ 'x', "no-compress",    NULL,            _("Do not compress the plain text using the xz algorithm"),    CONFIG_ARG_REQ_BOOLEAN, { 0x0 }, false, false, false },
		{ 'f', "follow",         NULL,            _("Follow symlinks, the default is to store the link itself"), CONFIG_ARG_REQ_BOOLEAN, { 0x0 }, false, false, false },
		{ 'b', "back-compat",    _("version"),    _("Create an encrypted file that is backwards compatible"),    CONFIG_ARG_REQ_STRING,  { 0x0 }, false, true,  false },
#ifndef _WIN32
		{ 'r', "raw",            NULL,            _("Don’t generate or look for an encrypt header; this IS NOT recommended, but can be useful in some (limited) situations"), CONFIG_ARG_REQ_BOOLEAN, { 0x0 }, false, true, false },
#else
		{ 'r', "raw",            NULL,            _("Don't generate or look for an encrypt header; this IS NOT recommended, but can be useful in some (limited) situations"), CONFIG_ARG_REQ_BOOLEAN, { 0x0 }, false, true, false },
#endif
		{ 0x3, "self-test",      NULL,            _("Perform self-test routine"),                                CONFIG_ARG_BOOLEAN,     { 0x0 }, false, true,  true  },
		{ 0x0, NULL, NULL, NULL, CONFIG_ARG_REQ_BOOLEAN, { 0x0 }, false, false, false }
	};
	config_extra_t extra[] =
	{
		{ "source", CONFIG_ARG_STRING,  { 0x0 }, false, false },
		{ "output", CONFIG_ARG_STRING,  { 0x0 }, false, false },
		{ NULL,     CONFIG_ARG_BOOLEAN, { 0x0 }, false, false }
	};
	char *notes[] =
	{
		_("If you do not supply a key or password, you will be prompted for one. This will then be used to generate a key to encrypt the data with (using the specified hash and MAC)."),
		_("To see available algorithms or modes use list as the argument."),
		_("If either the source file or destination file are omitted then stdin/stdout are used."),
		_("When encrypting, -c, -s -m, and -a are required to specify the algorithms you wish to use; when decrypting the algorithms originally used are read from the encrypted file, (although you can omit the algorithm options if you have configured defaults in ~/.encryptrc)."),
		_("If you encrypted data using --raw then you will need to pass the algorithms as arguments when decrypting."),
		_("You can toggle compression and how symbolic links are handled in the configuration file ~/.encryptrc"),
		NULL
	};

	config_about_t about =
	{
		NULL,
		ENCRYPT_VERSION,
		PROJECT_URL,
		ENCRYPTRC
	};
#ifndef _WIN32
	bool dude = false;
	if (!strcmp(basename(argv[0]), DECRYPT))
	{
		about.name = DECRYPT;
		dude = true;

		int x = 0;
#ifdef BUILD_GUI
		x++;
		args[++x].hidden = true;
		args[++x].hidden = true;
#endif
		args[++x].hidden = true;
		args[++x].hidden = true;
		args[++x].hidden = true;
		args[++x].hidden = true;
		args[++x].hidden = true;
		x += 2;
		args[++x].hidden = true;
		args[++x].hidden = true;
		args[++x].hidden = true;
	}
	else
#endif
		about.name = ENCRYPT;
	config_init(about);

	config_parse(argc, argv, args, extra, notes);

	char *source   = extra[0].response_value.string;
	char *output   = extra[1].response_value.string;

	int x = -1;
	bool compress;
#ifdef BUILD_GUI
	#ifndef _WIN32
	bool gui         = !args[++x].response_value.boolean; // gui by default unless --no-gui is specified
	#endif
	char *key_source =  args[++x].response_value.string;
	compress         =  args[++x].response_value.boolean; // compress by default unless --no-compress is specified
#endif
	bool cli         = !args[++x].response_value.boolean; // cli by default unless --no-cli is specified

	char *cipher     =  args[++x].response_value.string;
	char *hash       =  args[++x].response_value.string;
	char *mode       =  args[++x].response_value.string;
	char *mac        =  args[++x].response_value.string;
	uint64_t kdf     =  args[++x].response_value.number;

	char *key        =  args[++x].response_value.string;
	char *password   =  args[++x].response_value.string;

	compress         = !args[++x].response_value.boolean; // compress by default unless --no-compress is specified
	bool follow      =  args[++x].response_value.boolean;

	char *version    =  args[++x].response_value.string;
	bool raw         =  args[++x].response_value.boolean;
	bool test        =  args[++x].response_value.boolean;

	if (test)
		self_test();

	/*
	 * list available algorithms if asked to (possibly both hash and
	 * crypto)
	 */
	bool la = false;
	if (cipher && !strcasecmp(cipher, "list"))
		la = list_ciphers();
	if (hash && !strcasecmp(hash, "list"))
		la = list_hashes();
	if (mode && !strcasecmp(mode, "list"))
		la = list_modes();
	if (mac && !strcasecmp(mac, "list"))
		la = list_macs();
	if (la)
		goto clean_up;

	if (source)
	{
		char *ptr = malloc(0);
		char *c = ptr;
		char *h = ptr;
		char *m = ptr;
		char *a = ptr;
		if (is_encrypted(source, &c, &h, &m, &a, &kdf))
		{
			free(cipher);
			free(hash);
			free(mode);
			free(mac);
			cipher = c;
			hash = h;
			mode = m;
			mac = a;
		}
		free(ptr);
	}

#ifdef BUILD_GUI
	gtk_widgets_t *widgets;
	GtkBuilder *builder;
	GError *error = NULL;

	#if !defined _WIN32
	struct stat n;
	fstat(STDIN_FILENO, &n);
	struct stat t;
	fstat(STDOUT_FILENO, &t);

	if (!gui)
		;
	else
	{
	#else
		(void)cli;
	#endif /* ! _WIN32 */

		if (gtk_init_check(&argc, &argv))
		{
			builder = gtk_builder_new();
	#ifndef _WIN32
		#if !defined __DEBUG__ && !defined __DEBUG_GUI__
			const char *glade_ui_file = GLADE_UI_FILE_DEFAULT;
		#else
			const char *glade_ui_file = GLADE_UI_FILE_BACKUP;
		#endif
	#else
			char *glade_ui_file = calloc(MAX_PATH, sizeof( char ));
			if (!glade_ui_file)
				die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, MAX_PATH);
		#ifndef __DEBUG__
			SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, 0, glade_ui_file);
			strcat(glade_ui_file, "\\");
		#endif /* __DEBUG__ */
			strcat(glade_ui_file, GLADE_UI_FILE_DEFAULT);
	#endif /* ! _WIN32 */
			if (!gtk_builder_add_from_file(builder, glade_ui_file, &error))
			{
				cli_fprintf(stderr, "%s", error->message);
				g_error_free(error);
				error = NULL;
				if (!gtk_builder_add_from_file(builder, GLADE_UI_FILE_BACKUP, &error))
					die(_("%s"), error->message);
			}
	#ifdef _WIN32
			free(glade_ui_file);
	#endif
			/*
			 * allocate widgets structure
			 */
			widgets = g_slice_new(gtk_widgets_t);
			/*
			 * get widgets from UI
			 */
			INIT_WIDGET(main_window);
			INIT_WIDGET(open_button);
			INIT_WIDGET(open_dialog);
			INIT_WIDGET(open_file_label);
			INIT_WIDGET(open_file_image);
			INIT_WIDGET(save_button);
			INIT_WIDGET(save_dialog);
			INIT_WIDGET(save_file_label);
			INIT_WIDGET(save_file_image);
			INIT_WIDGET(crypto_combo);
			INIT_WIDGET(hash_combo);
			INIT_WIDGET(mode_combo);
			INIT_WIDGET(mac_combo);
			INIT_WIDGET(kdf_spinner);
			INIT_WIDGET(password_entry);
			INIT_WIDGET(key_button);
			INIT_WIDGET(key_dialog);
			INIT_WIDGET(key_file_label);
			INIT_WIDGET(key_file_image);
			INIT_WIDGET(encrypt_button);
			INIT_WIDGET(status_bar);
			INIT_WIDGET(progress_dialog);
			INIT_WIDGET(progress_bar_total);
			INIT_WIDGET(progress_bar_current);
			INIT_WIDGET(progress_label);
			INIT_WIDGET(progress_cancel_button);
			INIT_WIDGET(about_dialog);
			INIT_WIDGET(about_version_build_info);
			INIT_WIDGET(build_info_text_buffer);
			INIT_WIDGET(about_new_version_label);
			INIT_WIDGET(compress_menu_item);
			INIT_WIDGET(follow_menu_item);
			INIT_WIDGET(raw_menu_item);
			INIT_WIDGET(compat_menu);
			INIT_WIDGET(key_file_menu_item);
			INIT_WIDGET(key_password_menu_item);
			INIT_WIDGET(raw_encrypt_button);
			INIT_WIDGET(raw_decrypt_button);
			INIT_WIDGET(abort_dialog);
			INIT_WIDGET(abort_button);
			INIT_WIDGET(abort_message);

			gtk_builder_connect_signals(builder, widgets);
			g_object_unref(G_OBJECT(builder));
			gtk_widget_show(widgets->main_window);

			gtk_window_set_transient_for((GtkWindow *)widgets->abort_dialog, (GtkWindow *)widgets->main_window);
			error_gui_init(widgets->abort_dialog, widgets->abort_message);

			if (source)
			{
	#ifndef _WIN32
				if (source[0] != '/')
				{
					char *cwd = getcwd(NULL, 0);
					asprintf(&gui_file_hack_source, "%s/%s", cwd, source);
					free(cwd);
				}
				else
	#endif
					gui_file_hack_source = strdup(source);
				gtk_file_chooser_set_filename((GtkFileChooser *)widgets->open_dialog, gui_file_hack_source);
			}
			if (output)
			{
	#ifndef _WIN32
				if (output[0] != '/')
				{
					char *cwd = getcwd(NULL, 0);
					asprintf(&gui_file_hack_output, "%s/%s", cwd, output);
					free(cwd);
				}
				else
	#endif
					gui_file_hack_output = strdup(output);
				gtk_file_chooser_set_filename((GtkFileChooser *)widgets->save_dialog, gui_file_hack_output);
			}
			file_dialog_okay(NULL, widgets);

			auto_select_algorithms(widgets, cipher, hash, mode, mac, kdf);
			set_compatibility_menu(widgets, version);
			if (!strcasecmp(key_source, "file"))
				set_key_source_menu(widgets, KEY_SOURCE_FILE);
			else
				set_key_source_menu(widgets, KEY_SOURCE_PASSWORD);
			gtk_check_menu_item_set_active((GtkCheckMenuItem *)widgets->compress_menu_item, compress);
			gtk_check_menu_item_set_active((GtkCheckMenuItem *)widgets->follow_menu_item, follow);
			gtk_check_menu_item_set_active((GtkCheckMenuItem *)widgets->raw_menu_item, raw);

			set_raw_buttons(widgets, raw);
			set_status_bar((GtkStatusbar *)widgets->status_bar, STATUS_BAR_READY);

			gtk_main();

			g_slice_free(gtk_widgets_t, widgets);

			goto clean_up;

		}
		else
			cli_fprintf(stderr, _("Could not create GUI - falling back to command line\n"));
	#ifndef _WIN32
	}
	#endif
#endif /* BUILD_GUI */ /* we couldn’t create the gui, so revert back to command line */

#if !defined _WIN32 /* it’s GUI or nothing for Windows */
	/*
	 * get raw key data in form of password/phrase, key file
	 */
	uint8_t *key_data = NULL;
	size_t key_length = 0;
	if (password)
	{
		key_data = (uint8_t *)password;
		key_length = strlen(password);
	}
	else if (key)
		key_data = (uint8_t *)key;
	else if (isatty(STDIN_FILENO))
	{
		key_data = (uint8_t *)getpass(_("Please enter a password: "));
		key_length = strlen((char *)key_data);
		//cli_printf("\n");
	}
	else
		config_show_usage(args, extra);

	/*
	 * here we go ...
	 */
	crypto_t *c;

	if (dude || (source && is_encrypted(source)))
		c = decrypt_init(source, output, cipher, hash, mode, mac, key_data, key_length, kdf, raw);
	else
		c = encrypt_init(source, output, cipher, hash, mode, mac, key_data, key_length, kdf, raw, compress, follow, parse_version(version));

	if (c->status == STATUS_INIT)
	{
		execute(c);
#ifndef __DEBUG__
		/*
		 * only display the UI if not outputting to stdout (and if stderr
		 * is a terminal)
		 */
		struct stat t;
		fstat(STDOUT_FILENO, &t);

		bool ui = isatty(STDERR_FILENO) && (!io_is_stdout(c->output) || c->path || S_ISREG(t.st_mode));
		if (ui && cli)
		{
			cli_t p = { (cli_status_e *)&c->status, &c->current, &c->total };
			cli_display(&p);
		}
		else
			while (c->status == STATUS_INIT || c->status == STATUS_RUNNING)
			{
				struct timespec s = { 0, 10 * MILLION }; /* 10 milliseconds */
				nanosleep(&s, NULL);
			}
#else
		(void)cli;
#endif
	}

	if (c->status != STATUS_SUCCESS)
		cli_fprintf(stderr, ANSI_COLOUR_RED "%s" ANSI_COLOUR_RESET "\n", _(status(c)));

	deinit(&c);
#endif /* ! _WIN32 */

clean_up:
#ifdef BUILD_GUI
	if (key_source)
		free(key_source);
#endif
	if (cipher)
		free(cipher);
	if (hash)
		free(hash);
	if (mode)
		free(mode);
	if (mac)
		free(mac);
	if (key)
		free(key);
	if (password)
		free(password);
	if (version)
		free(version);
	if (extra[0].response_value.string)
		free(extra[0].response_value.string);
	if (extra[1].response_value.string)
		free(extra[1].response_value.string);

	if (version_new_available)
		cli_fprintf(stderr, _(NEW_VERSION_URL), version_available, program_invocation_short_name, strlen(new_version_url) ? new_version_url : PROJECT_URL);

#ifdef __DEBUG__
	cli_fprintf(stderr, "\n" ANSI_COLOUR_RED "**** %s ****" ANSI_COLOUR_RESET "\n\n", _("DEBUG BUILD"));
#endif

	return EXIT_SUCCESS;
}

static bool list_ciphers(void)
{
	const char **l = list_of_ciphers();
	for (int i = 0; l[i] ; i++)
		cli_fprintf(stderr, "%s\n", l[i]);
	return true;
}

static bool list_hashes(void)
{
	const char **l = list_of_hashes();
	for (int i = 0; l[i]; i++)
		cli_fprintf(stderr, "%s\n", l[i]);
	return true;
}

static bool list_modes(void)
{
	const char **l = list_of_modes();
	for (int i = 0; l[i]; i++)
		cli_fprintf(stderr, "%s\n", l[i]);
	return true;
}

static bool list_macs(void)
{
	const char **l = list_of_macs();
	for (int i = 0; l[i]; i++)
		cli_fprintf(stderr, "%s\n", l[i]);
	return true;
}

static int self_test(void)
{
	const char **l = list_of_ciphers();
	unsigned int i, x;
	for (i = 0; l[i]; i++)
		;
	gcry_create_nonce(&x, sizeof x);
	x %= i;
	const char *cipher = l[x];
	l = list_of_hashes();
	for (i = 0; l[i]; i++)
		;
	gcry_create_nonce(&x, sizeof x);
	x %= i;
	const char *hash = l[x];
	l = list_of_modes();
	do
	{
		for (i = 0; l[i]; i++)
			;
		gcry_create_nonce(&x, sizeof x);
		x %= i;
	}
	while (!mode_valid_for_cipher(cipher_id_from_name(cipher), mode_id_from_name(l[x])));
	const char *mode = l[x];
	l = list_of_macs();
	for (i = 0; l[i]; i++)
		;
	gcry_create_nonce(&x, sizeof x);
	x %= i;
	const char *mac = l[x];

	uint16_t key_len;
	gcry_create_nonce(&key_len, sizeof key_len);
	key_len %= 0x0400;
	uint8_t *key = malloc(key_len);
	gcry_create_nonce(key, key_len);

	uint32_t kdf;
	gcry_create_nonce(&kdf, sizeof kdf);
	kdf %= 0x0000FFFF;

	uint32_t buffer_len;
	gcry_create_nonce(&buffer_len, sizeof buffer_len);
	buffer_len %= 0x00FFFFFF;
	uint8_t *buffer_plain = malloc(buffer_len);
	uint8_t *buffer_check = malloc(buffer_len);
	gcry_create_nonce(buffer_plain, buffer_len);

	cli_fprintf(stderr, _("Test cipher        : %s\n"), cipher);
	cli_fprintf(stderr, _("Test hash          : %s\n"), hash);
	cli_fprintf(stderr, _("Test mode          : %s\n"), mode);
	cli_fprintf(stderr, _("Test MAC           : %s\n"), mac);
	cli_fprintf(stderr, _("Test KDF iterations: %" PRIu32 "\n"), kdf);
	cli_fprintf(stderr, _("Test key size      : %" PRIu16 "\n"), key_len);
	cli_fprintf(stderr, _("Test buffer size   : %" PRIu32 "\n"), buffer_len);

	crypto_t *test_encrypt = encrypt_init(NULL, NULL, cipher, hash, mode, mac, key, key_len, kdf, false, true, false, VERSION_CURRENT);
	crypto_t *test_decrypt = decrypt_init(NULL, NULL, cipher, hash, mode, mac, key, key_len, kdf, false);

	FILE *tmp_plain  = tmpfile();
	FILE *tmp_cipher = tmpfile();
	FILE *tmp_check  = tmpfile();

	fwrite(buffer_plain, buffer_len, 1, tmp_plain);
	fseek(tmp_plain, 0, SEEK_SET);

	int64_t fd = fileno(tmp_plain);
	memcpy(test_encrypt->source, &fd, sizeof fd);
	fd = fileno(tmp_cipher);
	memcpy(test_encrypt->output, &fd, sizeof fd);
	memcpy(test_decrypt->source, &fd, sizeof fd);
	fd = fileno(tmp_check);
	memcpy(test_decrypt->output, &fd, sizeof fd);

	cli_fprintf(stderr, _("\nTesting encryption..."));
	execute(test_encrypt);
#ifndef __DEBUG__
	cli_t p = { (cli_status_e *)&test_encrypt->status, &test_encrypt->current, &test_encrypt->total };
	cli_display(&p);
#endif

	fseek(tmp_plain,  0, SEEK_SET);
	fseek(tmp_cipher, 0, SEEK_SET);

	cli_fprintf(stderr, _("Testing decryption..."));
	execute(test_decrypt);
#ifndef __DEBUG__
	p.status  = (cli_status_e *)&test_decrypt->status;
	p.current = &test_decrypt->current;
	p.total   = &test_decrypt->total;
	cli_display(&p);
#endif

	fseek(tmp_check, 0, SEEK_SET);
	fread(buffer_check, buffer_len, 1, tmp_check);

	fclose(tmp_plain);
	fclose(tmp_cipher);
	fclose(tmp_check);

	int r;
	if (memcmp(buffer_plain, buffer_check, buffer_len))
		r = EXIT_FAILURE , cli_fprintf(stderr, _("\nFail: Result not equal to original!\n"));
	else
		r = EXIT_SUCCESS , cli_fprintf(stderr, _("\nSelf-test passed.\n"));

	free(buffer_plain);
	free(buffer_check);

	deinit(&test_encrypt);
	deinit(&test_decrypt);

	exit(r);
}
