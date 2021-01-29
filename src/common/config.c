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

#include "common.h"
#include "non-gnu.h"
#include "error.h"
#include "ccrypt.h"
#include "version.h"
#include "cli.h"
#include "config.h"

#ifdef _WIN32
	#include <Shlobj.h>
	extern char *program_invocation_short_name;
#endif

#include "crypt.h"


static void show_version(void);
static void show_help(config_arg_t *args, char **about);
static void show_licence(void);

static bool parse_config_boolean(const char *, const char *, bool);
static char *parse_config_tail(const char *, const char *);

static config_about_t about = { 0x0 };


extern void config_init(config_about_t a)
{
	memcpy(&about, &a, sizeof about);
	return;
}

extern int config_parse(int argc, char **argv, config_arg_t *args, char **extra, char **notes)
{
	/*
	 * check for options in rc file
	 */
	if (about.config != NULL)
	{
		char *rc = NULL;
#ifndef _WIN32
		if (!asprintf(&rc, "%s/%s", getenv("HOME") ? : ".", about.config))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(getenv("HOME")) + strlen(about.config) + 2);
#else
		if (!(rc = calloc(MAX_PATH, sizeof( char ))))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, MAX_PATH);
		SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, rc);
		strcat(rc, "\\");
		strcat(rc, about.config);
#endif
		FILE *f = fopen(rc, "rb");
		if (f)
		{
			char *line = NULL;
			size_t len = 0;

			while (getline(&line, &len, f) >= 0)
			{
				if (len == 0 || line[0] == '#')
					goto end_line;

				for (int i = 0; args[i].short_option; i++)
					if (!strncmp(args[i].long_option, line, strlen(args[i].long_option)) && isspace((unsigned char)line[strlen(args[i].long_option)]))
						switch (args[i].response_type)
						{
							case CONFIG_ARG_BOOLEAN:
								args[i].response_value.boolean = parse_config_boolean(args[i].long_option, line, args[i].response_value.boolean);
								break;
							case CONFIG_ARG_NUMBER:
								{
									char *n = parse_config_tail(args[i].long_option, line);
									if (n)
									{
										args[i].response_value.number = strtoull(n, NULL, 0);
										free(n);
									}
								}
								break;
							case CONFIG_ARG_STRING:
								args[i].response_value.string = parse_config_tail(args[i].long_option, line);
								break;
						}
end_line:
				free(line);
				line = NULL;
				len = 0;
			}
			fclose(f);
			free(line);
		}
		free(rc);
	}

	/*
	 * build and populate the getopt structure
	 */
	char *short_options;
	int optlen = 4;
	for (int i = 0; args[i].short_option; i++, optlen += 1)
		;
	if (!(short_options = calloc(optlen, sizeof (char))))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, 4 * sizeof (char));
	struct option *long_options;
	if (!(long_options = calloc(optlen, sizeof (struct option))))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, 4 * sizeof (struct option));

	strcat(short_options, "h");
	long_options[0].name    = "help";
	long_options[0].has_arg = no_argument;
	long_options[0].flag    = NULL;
	long_options[0].val     = 'h';

	strcat(short_options, "v");
	long_options[1].name    = "version";
	long_options[1].has_arg = no_argument;
	long_options[1].flag    = NULL;
	long_options[1].val     = 'v';

	strcat(short_options, "l");
	long_options[2].name    = "licence";
	long_options[2].has_arg = no_argument;
	long_options[2].flag    = NULL;
	long_options[2].val     = 'l';

	for (int i = 0; args[i].short_option; i++)
	{
		char S[1] = "X";
		S[0] = args[i].short_option;
		strcat(short_options, S);
		if (args[i].response_type != CONFIG_ARG_BOOLEAN)
			strcat(short_options, ":");
		long_options[i + 3].name    = args[i].long_option;
		long_options[i + 3].has_arg = args[i].response_type == CONFIG_ARG_BOOLEAN ? no_argument : required_argument;
		long_options[i + 3].flag    = NULL;
		long_options[i + 3].val     = args[i].short_option;
	}

	/*
	 * parse command line options
	 */
	while (true)
	{
		int index = 0;
		int c = getopt_long(argc, argv, short_options, long_options, &index);
		if (c == -1)
			break;
		bool unknown = true;
		if (c == 'h')
			show_help(args, notes);
		else if (c == 'v')
			show_version();
		else if (c == 'l')
			show_licence();
		else if (c == '?')
			config_show_usage(args);
		else
			for (int i = 0; args[i].short_option; i++)
				if (c == args[i].short_option)
				{
					unknown = false;
					switch (args[i].response_type)
					{
						case CONFIG_ARG_NUMBER:
							args[i].response_value.number = strtoull(optarg, NULL, 0);
							break;
						case CONFIG_ARG_STRING:
							if (args[i].response_value.string)
								free(args[i].response_value.string);
							args[i].response_value.string = strdup(optarg);
							break;
						case CONFIG_ARG_BOOLEAN:
							__attribute__((fallthrough)); /* allow fall-through; argument was seen */
						default:
							args[i].response_value.boolean = !args[i].response_value.boolean;
							break;
					}
				}
		if (unknown)
			config_show_usage(args);
	}
	if (!(*extra = calloc(argc, sizeof (char *))))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, argc * sizeof (char *));
	int i = 0;
	for (; optind < argc; i++, optind++)
		if (!(extra[i] = strdup(argv[optind])))
			die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(argv[optind]));
	return i;
}

inline static void format_section(char *s)
{
	cli_fprintf(stderr, "\n" ANSI_COLOUR_CYAN "%s" ANSI_COLOUR_RESET ":\n", s);
	return;
}

static void show_version(void)
{
	version_print(about.name, about.version, about.url);
	exit(EXIT_SUCCESS);
}

inline static void print_usage(config_arg_t *args)
{
#ifndef _WIN32
	struct winsize ws;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
	size_t x = ws.ws_col - strlen(about.name) - 2;
#else
	//CONSOLE_SCREEN_BUFFER_INFO csbi;
	//GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
	size_t x = 77 - strlen(about.name);// (csbi.srWindow.Right - csbi.srWindow.Left + 1) - width - 2;
#endif
	format_section(_("Usage"));
	cli_fprintf(stderr, "  " ANSI_COLOUR_GREEN "%s" ANSI_COLOUR_MAGENTA, about.name);
	for (int i = 0, j = 0; args[i].short_option; i++)
	{
		if (j + 4 + (args[i].option_type ? strlen(args[i].option_type) : 0) > x)
		{
			cli_fprintf(stderr, "\n%*s  ", (int)strlen(about.name), " ");
			j = 2;
		}
		j += cli_fprintf(stderr, " [-%c", args[i].short_option);
		if (args[i].option_type)
			j += cli_fprintf(stderr, " %s", args[i].option_type);
		j += cli_fprintf(stderr, "]");
	}
	cli_fprintf(stderr, ANSI_COLOUR_RESET "\n");
	return;
}

extern void config_show_usage(config_arg_t *args)
{
	print_usage(args);
	exit(EXIT_SUCCESS);
}

static void print_option(int width, char sopt, char *lopt, char *type, char *desc)
{
	size_t z = width - 8 - strlen(lopt);
	cli_fprintf(stderr, "  " ANSI_COLOUR_WHITE "-%c" ANSI_COLOUR_RESET ", " ANSI_COLOUR_WHITE "--%s" ANSI_COLOUR_RESET, sopt, lopt);
	if (type)
	{
		cli_fprintf(stderr, ANSI_COLOUR_WHITE "=" ANSI_COLOUR_YELLOW "<%s>" ANSI_COLOUR_RESET, type);
		z -= 3 + strlen(type);
	}
	fprintf(stderr, "%*s", (int)z, " ");

#ifndef _WIN32
	struct winsize ws;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
	int x = ws.ws_col - width - 2;
#else
	//CONSOLE_SCREEN_BUFFER_INFO csbi;
	//GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
	int x = 77 - width;// (csbi.srWindow.Right - csbi.srWindow.Left + 1) - width - 2;
#endif
	for (; isspace(*desc); desc++)
		;
	int l = strlen(desc);
	cli_fprintf(stderr, ANSI_COLOUR_BLUE);
	if (l < x)
		cli_fprintf(stderr, "%s", desc);
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
					if (isspace(desc[e]))
						break;
			if (s)
				cli_fprintf(stderr, "\n%*s", width, " ");
			cli_fprintf(stderr, "%.*s", e - s, desc + s);
			s = e + 1;
		}
		while (s < l);
	}
	cli_fprintf(stderr, ANSI_COLOUR_RESET "\n");
	return;
}

static void print_notes(char *line)
{
	cli_fprintf(stderr, "  • ");
	//fprintf(stderr, "  • %s\n", notes[i]);
#ifndef _WIN32
	struct winsize ws;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
	int x = ws.ws_col - 5;
#else
	//CONSOLE_SCREEN_BUFFER_INFO csbi;
	//GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
	int x = 72;// (csbi.srWindow.Right - csbi.srWindow.Left + 1) - width - 2;
#endif
	for (; isspace(*line); line++)
		;
	int l = strlen(line);
	if (l < x)
		cli_fprintf(stderr, "%s", line);
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
					if (isspace(line[e]))
						break;
			if (s)
				cli_fprintf(stderr, "\n%*s", 4, " ");
			cli_fprintf(stderr, "%.*s", e - s, line + s);
			s = e + 1;
		}
		while (s < l);
	}
	cli_fprintf(stderr, ANSI_COLOUR_RESET "\n");
	return;
}

static void show_help(config_arg_t *args, char **notes)
{
	version_print(about.name, about.version, about.url);
	print_usage(args);

	int width = 10;
	bool has_advanced = false;
	for (int i = 0; args[i].short_option; i++)
	{
		int w = 10 + strlen(args[i].long_option);
		if (args[i].option_type)
			w += 3 + strlen(args[i].option_type);
		width = width > w ? width : w;
		if (args[i].advanced && !args[i].hidden)
			has_advanced = true;
	}

	format_section(_("Options"));
	print_option(width, 'h', "help",    NULL, "Display this message");
	print_option(width, 'l', "licence", NULL, "Display GNU GPL v3 licence header");
	print_option(width, 'v', "version", NULL, "Display application version");
	for (int i = 0; args[i].short_option; i++)
		if (!args[i].hidden && !args[i].advanced)
			print_option(width, args[i].short_option, args[i].long_option, args[i].option_type ? : NULL, args[i].description);
	if (has_advanced)
	{
		format_section(_("Advnaced Options"));
		for (int i = 0; args[i].short_option; i++)
			if (!args[i].hidden && args[i].advanced)
				print_option(width, args[i].short_option, args[i].long_option, args[i].option_type ? : NULL, args[i].description);
	}
	format_section(_("Notes"));
	for (int i = 0; notes[i] ; i++)
		print_notes(notes[i]);
	exit(EXIT_SUCCESS);
}

static void show_licence(void)
{
	fprintf(stderr, _(TEXT_LICENCE));
	exit(EXIT_SUCCESS);
}

extern void update_config(const char * const restrict o, const char * const restrict v)
{
	char *rc = NULL;
#ifndef _WIN32
	if (!asprintf(&rc, "%s/%s", getenv("HOME") ? : ".", about.config))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(getenv("HOME")) + strlen(about.config) + 2);
#else
	if (!(rc = calloc(MAX_PATH, sizeof( char ))))
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, MAX_PATH);
	SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, rc);
	strcat(rc, "\\");
	strcat(rc, about.config);
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
		{
			/*
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
