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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <ctype.h>
#include <string.h>
#include <stdbool.h>

#ifndef _WIN32
	#include <sys/utsname.h>
	#include <sys/ioctl.h>
	#ifdef __sun
		#include <sys/tty.h>
	#endif
#endif

#include "common/common.h"
#include "common/non-gnu.h"
#include "common/error.h"
#include "common/ccrypt.h"
#include "common/version.h"
#include "common/cli.h"

#ifdef _WIN32
	#include <Shlobj.h>
	extern char *program_invocation_short_name;
#endif

#include "init.h"
#include "crypt.h"

#if __has_include("misc.h")
	#include "misc.h"
#else
	#define ALL_CFLAGS   "(unknown)"
	#define ALL_CPPFLAGS "(unknown)"
#endif

#define HELP_FORMAT_RIGHT_COLUMN 37

static bool is_encrypt(void);

static bool parse_config_boolean(const char *, const char *, bool);
static char *parse_config_tail(const char *, const char *);

static void print_version(void);
static void print_usage(void);

char *KEY_SOURCE[] =
{
	"file",
	"password"
};

extern args_t init(int argc, char **argv)
{
	args_t a = { strdup(DEFAULT_CIPHER),
			strdup(DEFAULT_HASH),
			strdup(DEFAULT_MODE),
			strdup(DEFAULT_MAC),
			KEY_ITERATIONS_DEFAULT,
			NULL, /* key file */
			NULL, /* password */
			NULL, /* source */
			NULL, /* output */
			strdup(get_version_string(VERSION_CURRENT)), /* compatibility */
			KEY_SOURCE_PASSWORD,
			true,    /* compress */
			false,   /* follow links */
			true,    /* show the gui if available */
			true,    /* show the cli if necessary */
			false    /* skip header/verification */
	};

	/*
	 * start background thread to check for newer version of encrypt
	 *
	 * NB If (When) encrypt makes it into a package manager for some
	 * distros this can/should be removed as it will be unnecessary
	 */
	version_check_for_update(ENCRYPT_VERSION, UPDATE_URL, DOWNLOAD_URL_TEMPLATE);

	/*
	 * check for options in rc file (~/.encryptrc)
	 */
	char *rc = NULL;
#ifndef _WIN32
	if (!asprintf(&rc, "%s/%s", getenv("HOME") ? : ".", ENCRYPTRC))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(getenv("HOME")) + strlen(ENCRYPTRC) + 2);
#else
	if (!(rc = calloc(MAX_PATH, sizeof( char ))))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, MAX_PATH);
	SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, rc);
	strcat(rc, "\\");
	strcat(rc, ENCRYPTRC);
#endif
	FILE *f = fopen(rc, "rb");
	if (f)
	{
		char *line = NULL;
		size_t len = 0;

		while (getline(&line, &len, f) >= 0)
		{
			if (line[0] == '#' || len == 0)
				goto end_line;

			if (!strncmp(CONF_COMPRESS, line, strlen(CONF_COMPRESS)) && isspace((unsigned char)line[strlen(CONF_COMPRESS)]))
				a.compress = parse_config_boolean(CONF_COMPRESS, line, a.compress);
			else if (!strncmp(CONF_FOLLOW, line, strlen(CONF_FOLLOW)) && isspace((unsigned char)line[strlen(CONF_FOLLOW)]))
				a.follow = parse_config_boolean(CONF_FOLLOW, line, a.follow);
			else if (!strncmp(CONF_CIPHER, line, strlen(CONF_CIPHER)) && isspace((unsigned char)line[strlen(CONF_CIPHER)]))
			{
				free(a.cipher);
				a.cipher = parse_config_tail(CONF_CIPHER, line);
			}
			else if (!strncmp(CONF_HASH, line, strlen(CONF_HASH)) && isspace((unsigned char)line[strlen(CONF_HASH)]))
			{
				free(a.hash);
				a.hash = parse_config_tail(CONF_HASH, line);
			}
			else if (!strncmp(CONF_MODE, line, strlen(CONF_MODE)) && isspace((unsigned char)line[strlen(CONF_MODE)]))
			{
				free(a.mode);
				a.mode = parse_config_tail(CONF_MODE, line);
			}
			else if (!strncmp(CONF_MAC, line, strlen(CONF_MAC)) && isspace((unsigned char)line[strlen(CONF_MAC)]))
			{
				free(a.mac);
				a.mac = parse_config_tail(CONF_MAC, line);
			}
			else if (!strncmp(CONF_VERSION, line, strlen(CONF_VERSION)) && isspace((unsigned char)line[strlen(CONF_VERSION)]))
			{
				free(a.version);
				a.version = parse_config_tail(CONF_VERSION, line);
			}
			else if (!strncmp(CONF_KDF_ITERATIONS, line, strlen(CONF_KDF_ITERATIONS)) && isspace((unsigned char)line[strlen(CONF_KDF_ITERATIONS)]))
			{
				char *itr = parse_config_tail(CONF_KDF_ITERATIONS, line);
				if (itr)
				{
					a.kdf_iterations = strtoull(itr, NULL, 0);
					free(itr);
				}
			}
			else if (!strncmp(CONF_KEY, line, strlen(CONF_KEY)) && isspace((unsigned char)line[strlen(CONF_KEY)]))
			{
				char *k = parse_config_tail(CONF_KEY, line);
				if (!strcasecmp(KEY_SOURCE[KEY_SOURCE_FILE], k))
					a.key_source = KEY_SOURCE_FILE;
				else
					a.key_source = KEY_SOURCE_PASSWORD;
				free(k);
			}
			else if (!strncmp(CONF_SKIP_HEADER, line, strlen(CONF_SKIP_HEADER)) && isspace((unsigned char)line[strlen(CONF_SKIP_HEADER)]))
				a.raw = parse_config_boolean(CONF_SKIP_HEADER, line, a.raw);
end_line:
			free(line);
			line = NULL;
			len = 0;
		}
		fclose(f);
		free(line);
	}
	free(rc);

	if (argc && argv)
	{
		/*
		 * parse commandline arguments (they override the rc file)
		 */
		struct option options[] =
		{
			{ "help",           no_argument,       0, 'h' },
			{ "version",        no_argument,       0, 'v' },
			{ "licence",        no_argument,       0, 'l' },
			{ "nogui",          no_argument,       0, 'g' },
			{ "cipher",         required_argument, 0, 'c' },
			{ "hash",           required_argument, 0, 's' },
			{ "mode",           required_argument, 0, 'm' },
			{ "mac",            required_argument, 0, 'a' },
			{ "kdf-iterations", required_argument, 0, 'i' },
			{ "key",            required_argument, 0, 'k' },
			{ "password",       required_argument, 0, 'p' },
			{ "no-compress",    no_argument,       0, 'x' },
			{ "back-compat",    required_argument, 0, 'b' },
			{ "follow",         no_argument,       0, 'f' },
			{ "raw",            no_argument,       0, 'r' },
			{ "nocli",          no_argument,       0, 'u' },
			{ NULL,             0,                 0,  0  }
		};

		while (true)
		{
			int index = 0;
			int c = getopt_long(argc, argv, "hvlgc:s:m:a:i:k:p:xb:fru", options, &index);
			if (c == -1)
				break;
			switch (c)
			{
				case 'h':
					show_help();
				case 'v':
					show_version();
				case 'l':
					show_licence();
				case 'g':
					a.gui = false;
					break;
				case 'c':
					free(a.cipher);
					a.cipher = strdup(optarg);
					break;
				case 's':
					free(a.hash);
					a.hash = strdup(optarg);
					break;
				case 'm':
					free(a.mode);
					a.mode = strdup(optarg);
					break;
				case 'a':
					free(a.mac);
					a.mac = strdup(optarg);
					break;
				case 'i':
					a.kdf_iterations = strtoull(optarg, NULL, 0);
					break;
				case 'k':
					if (a.key)
						free(a.key);
					a.key = strdup(optarg);
					break;
				case 'p':
					if (a.password)
						free(a.password);
					a.password = strdup(optarg);
					break;
				case 'x':
					/*
					 * Could possibly use:
					 *     a.compress = !a.compress;
					 * if we wanted to turn compression on even if it was
					 * turned off in the config file
					 */
					a.compress = false;
					break;
				case 'b':
					free(a.version);
					a.version = strdup(optarg);
					break;
				case 'f':
					a.follow = true;
					break;
				case 'r':
					a.raw = true;
					break;
				case 'u':
					a.cli = false;
					break;
				case '?':
				default:
					show_usage();
			}
		}
		while (optind < argc)
			if (!a.source)
				a.source = strdup(argv[optind++]);
			else if (!a.output)
				a.output = strdup(argv[optind++]);
			else
				optind++;
	}
	if (a.source && !strcmp(a.source, "-"))
		free(a.source) , a.source = NULL;
	if (a.output && !strcmp(a.output, "-"))
		free(a.output) , a.output = NULL;
	return a;
}

extern void init_deinit(args_t args)
{
	if (args.cipher)
		free(args.cipher);
	if (args.hash)
		free(args.hash);
	if (args.mode)
		free(args.mode);
	if (args.mac)
		free(args.mac);
	if (args.key)
		free(args.key);
	if (args.password)
		free(args.password);
	if (args.source)
		free(args.source);
	if (args.output)
		free(args.output);
	if (args.version)
		free(args.version);
	return;
}

extern void update_config(const char * const restrict o, const char * const restrict v)
{
	char *rc = NULL;
#ifndef _WIN32
	if (!asprintf(&rc, "%s/%s", getenv("HOME") ? : ".", ENCRYPTRC))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(getenv("HOME")) + strlen(ENCRYPTRC) + 2);
#else
	if (!(rc = calloc(MAX_PATH, sizeof( char ))))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, MAX_PATH);
	SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, rc);
	strcat(rc, "\\");
	strcat(rc, ENCRYPTRC);
#endif
	FILE *f = fopen(rc, "rb+");
	if (!f) /* file doesn’t exist, so create it */
		f = fopen(rc, "wb+");
	if (f)
	{
		FILE *t = tmpfile();
		char *line = NULL;
		size_t len = 0;
		bool found = false;

		for (int i = 0; i < 2; i++)
		{   /*
			 * first iteration: read rc file and change the value second
			 * iteration: read from tmpfile back into rc file
			 */
			while (getline(&line, &len, f) >= 0)
			{
				if (!i && (!strncmp(o, line, strlen(o)) && isspace((unsigned char)line[strlen(o)])))
				{
					free(line);
					asprintf(&line, "%s %s\n", o, v);
					found = true;
				}
				fprintf(t, "%s", line);

				free(line);
				line = NULL;
				len = 0;
			}
			fseek(f, 0, SEEK_SET);
			fseek(t, 0, SEEK_SET);
			if (!i)
				ftruncate(fileno(f), 0);
			FILE *z = f;
			f = t;
			t = z;
		}
		if (!found)
		{
			fseek(f, 0, SEEK_END);
			fprintf(f, "\n%s %s\n", o, v);
		}
		fclose(f);
		free(line);
		fclose(t);
	}
	free(rc);
	return;
}

/*
encrypt version: 2017.09
       built on: Nov 28 2018 16:16:15
     git commit: c32661e
       build os: Arch Linux
       compiler: gcc 8.2.1 20180831
        runtime: Linux 4.19.2-arch1-1-ARCH #1 SMP PREEMPT Tue Nov 13 21:16:19 UTC 2018 x86_64
*/
static void format_version(int i, char *id, char *value)
{
	cli_fprintf(stderr, ANSI_COLOUR_GREEN "%*s" ANSI_COLOUR_RESET ": " ANSI_COLOUR_YELLOW, i, id);
#ifndef _WIN32
	struct winsize ws;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
	int x = ws.ws_col - i - 2;
#else
	//CONSOLE_SCREEN_BUFFER_INFO csbi;
	//GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
	int x = 77 - i;// (csbi.srWindow.Right - csbi.srWindow.Left + 1) - i - 2;
#endif
	for (; isspace(*value); value++)
		;
	int l = strlen(value);
	if (l < x)
		cli_fprintf(stderr, "%s", value);
	else
	{
		int s = 0;
		do
		{
			int e = s + x;
			if (e > l)
				e = l;
			else
				for (; e > s; e--)
					if (isspace(value[e]))
						break;
			if (s)
				cli_fprintf(stderr, "\n%*s  ", i, " ");
			cli_fprintf(stderr, "%.*s", e - s, value + s);
			s = e + 1;
		}
		while (s < l);
	}

	cli_fprintf(stderr, ANSI_COLOUR_RESET "\n");
	return;
}

static void print_version(void)
{
	char *app_name = is_encrypt() ? APP_NAME : ALT_NAME;
	int i = strlen(app_name) + 8;
	char *av = NULL;
	asprintf(&av, _("%s version"), app_name);
	char *git = strndup(GIT_COMMIT, GIT_COMMIT_LENGTH);
	char *runtime = NULL;
#ifndef _WIN32
	struct utsname un;
	uname(&un);
	asprintf(&runtime, "%s %s %s %s", un.sysname, un.release, un.version, un.machine);
#else
	asprintf(&runtime, "%s", windows_version());
#endif
	format_version(i, av,              ENCRYPT_VERSION);
	format_version(i, _("built on"),   __DATE__ " " __TIME__);
	format_version(i, _("git commit"), git);
	format_version(i, _("build os"),   BUILD_OS);
	format_version(i, _("compiler"),   COMPILER);
	format_version(i, _("cflags"),     ALL_CFLAGS);
	format_version(i, _("cppflags"),   ALL_CPPFLAGS);
	format_version(i, _("runtime"),    runtime);
	char *gcv = NULL;
	asprintf(&gcv, "%s (compiled) %s (runtime)", GCRYPT_VERSION, gcry_check_version(NULL));
	format_version(i, _("libgcrypt"), gcv);
	free(gcv);
	free(av);
	free(git);
	free(runtime);
	struct timespec vc = { 0, MILLION }; /* 1ms == 1,000,000ns*/
	while (version_is_checking)
		nanosleep(&vc, NULL);
	if (version_new_available)
	{
		fprintf(stderr, "\n");
		cli_fprintf(stderr, _(NEW_VERSION_URL), version_available, program_invocation_short_name, strlen(new_version_url) ? new_version_url : PROJECT_URL);
	}
	return;
}

static void format_section(char *s)
{
	cli_fprintf(stderr, "\n" ANSI_COLOUR_CYAN "%s" ANSI_COLOUR_RESET ":\n", s);
	return;
}

static void print_usage(void)
{
	char *app_name = is_encrypt() ? APP_NAME : ALT_NAME;
	char *app_usage = is_encrypt() ? APP_USAGE : ALT_USAGE;
	format_section(_("Usage"));
	cli_fprintf(stderr, "  " ANSI_COLOUR_GREEN "%s " ANSI_COLOUR_MAGENTA " %s" ANSI_COLOUR_RESET "\n", app_name, app_usage);
	return;
}

static void format_help_line(char s, char *l, char *v, char *t)
{
	size_t z = HELP_FORMAT_RIGHT_COLUMN - 8 - strlen(l);
	cli_fprintf(stderr, "  " ANSI_COLOUR_WHITE "-%c" ANSI_COLOUR_RESET ", " ANSI_COLOUR_WHITE "--%s" ANSI_COLOUR_RESET, s, l);
	if (v)
	{
		cli_fprintf(stderr, ANSI_COLOUR_WHITE "=" ANSI_COLOUR_YELLOW "<%s>" ANSI_COLOUR_RESET, v);
		z -= 3 + strlen(v);
	}
	fprintf(stderr, "%*s", (int)z, " ");

	cli_fprintf(stderr, ANSI_COLOUR_BLUE);
#ifndef _WIN32
	struct winsize w;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	if (w.ws_col)
	{
		size_t o = 0;
		while (true)
		{
			int l = w.ws_col - HELP_FORMAT_RIGHT_COLUMN - 1;
			while (isspace(t[o]))
				o++;
			/* FIXME wrap on word boundry and handle UTF-8 characters properly */
			o += fprintf(stderr, "%.*s", l, t + o);
			if (o >= strlen(t))
				break;
			if (!isspace(t[o - 1]) && !isspace(t[o]))
				fprintf(stderr, "-");
			fprintf(stderr, "\n%*s", HELP_FORMAT_RIGHT_COLUMN, " ");
		}
	}
	else
#endif /* ! _WIN32 */
		fprintf(stderr, "%s", t);
	cli_fprintf(stderr, ANSI_COLOUR_RESET);

	fprintf(stderr, "\n");
	return;
}

extern void show_help(void)
{
	print_version();
	print_usage();
	format_section(_("Options"));
	format_help_line('h', "help",        NULL,        _("Display this message"));
	format_help_line('l', "licence",     NULL,        _("Display GNU GPL v3 licence header"));
	format_help_line('v', "version",     NULL,        _("Display application version"));
	format_help_line('g', "nogui",       NULL,        _("Do not use the GUI, even if it’s available"));
	format_help_line('u', "nocli",       NULL,        _("Do not display the CLI progress bar"));
	if (is_encrypt())
	{
		format_help_line('c', "cipher",         "algorithm",  _("Algorithm to use to encrypt data"));
		format_help_line('s', "hash",           "algorithm",  _("Hash algorithm to generate key"));
		format_help_line('m', "mode",           "mode",       _("The encryption mode to use"));
		format_help_line('a', "mac",            "mac",        _("The MAC algorithm to use"));
		format_help_line('i', "kdf-iterations", "iterations", _("Number of iterations the KDF should use"));
	}
	format_help_line('k', "key",         "key file",  _("File whose data will be used to generate the key"));
	format_help_line('p', "password",    "password",  _("Password used to generate the key"));
	if (is_encrypt())
	{
		format_help_line('x', "no-compress", NULL,        _("Do not compress the plain text using the xz algorithm"));
		format_help_line('f', "follow",      NULL,        _("Follow symlinks, the default is to store the link itself"));
		format_section(_("Advnaced Options"));
		format_help_line('b', "back-compat", "version",   _("Create an encrypted file that is backwards compatible"));
	}
	else
		format_section(_("Advnaced Options"));
	format_help_line('r', "raw",         NULL,        _("Don’t generate or look for an encrypt header; this IS NOT recommended, but can be useful in some (limited) situations"));
	format_section(_("Notes"));
	fprintf(stderr, _("  • If you do not supply a key or password, you will be prompted for one.\n"));
	if (is_encrypt())
		fprintf(stderr, _("  • To see a list of available algorithms or modes use list as the argument.\n"));
	fprintf(stderr, _("  • If you encrypted data using --raw then you will need to pass the algorithms\n"));
	fprintf(stderr, _("    as arguments when decrypting\n"));
	exit(EXIT_SUCCESS);
}

extern void show_licence(void)
{
	fprintf(stderr, _(TEXT_LICENCE));
	exit(EXIT_SUCCESS);
}

extern void show_usage(void)
{
	print_usage();
	exit(EXIT_SUCCESS);
}

extern void show_version(void)
{
	print_version();
	exit(EXIT_SUCCESS);
}

static bool is_encrypt(void)
{
	return !strncasecmp(program_invocation_short_name, APP_NAME, strlen(APP_NAME));
}

static bool parse_config_boolean(const char *c, const char *l, bool d)
{
	bool r = d;
	char *v = parse_config_tail(c, l);
	if (!strcasecmp(CONF_TRUE, v) || !strcasecmp(CONF_ON, v) || !strcasecmp(CONF_ENABLED, v))
		r = true;
	else if (!strcasecmp(CONF_FALSE, v) || !strcasecmp(CONF_OFF, v) || !strcasecmp(CONF_DISABLED, v))
		r = false;
	free(v);
	return r;
}

static char *parse_config_tail(const char *c, const char *l)
{
	char *x = strdup(l + strlen(c));
	if (!x)
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(l) - strlen(c) + 1);
	size_t i = 0;
	for (i = 0; i < strlen(x) && isspace((unsigned char)x[i]); i++)
		;
	char *y = strdup(x + i);
	if (!y)
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(x) - i + 1);
	free(x);
	for (i = strlen(y) - 1; i > 0 && isspace((unsigned char)y[i]); i--)
		;//y[i] = '\0';
	char *tail = strndup(y, i + 1);
	free(y);
	return tail;
}
