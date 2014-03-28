/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2014, albinoloverats ~ Software Development
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

#include "common/common.h"
#include "common/error.h"
#include "common/logging.h"

#ifdef _WIN32
    #include "common/win32_ext.h"
    extern char *program_invocation_short_name;
#endif

#include "init.h"
#include "crypto.h"

static bool parse_config_boolean(const char *, const char *, bool);
static char *parse_config_tail(const char *, const char *);

static void print_version(void);
static void print_usage(void);

extern args_t init(int argc, char **argv)
{
    args_t a = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, true, false, false };

    /*
     * check for options in rc file (~/.encryptrc)
     */
    char *rc = NULL;
    if (!asprintf(&rc, "%s/%s", getenv("HOME") ? : ".", ENCRYPTRC))
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(getenv("HOME")) + strlen(ENCRYPTRC) + 2);

    FILE *f = fopen(rc, "rb");
    if (f)
    {
        char *line = NULL;
        size_t len = 0;

        while (getline(&line, &len, f) >= 0)
        {
            if (line[0] == '#' || len == 0)
                goto fl;

            if (!strncmp(CONF_COMPRESS, line, strlen(CONF_COMPRESS)) && isspace(line[strlen(CONF_COMPRESS)]))
                a.compress = parse_config_boolean(CONF_COMPRESS, line, a.compress);
            else if (!strncmp(CONF_FOLLOW, line, strlen(CONF_FOLLOW)) && isspace(line[strlen(CONF_FOLLOW)]))
                a.follow = parse_config_boolean(CONF_FOLLOW, line, a.follow);
            else if (!strncmp(CONF_CIPHER, line, strlen(CONF_CIPHER)) && isspace(line[strlen(CONF_CIPHER)]))
                a.cipher = parse_config_tail(CONF_CIPHER, line);
            else if (!strncmp(CONF_HASH, line, strlen(CONF_HASH)) && isspace(line[strlen(CONF_HASH)]))
                a.hash = parse_config_tail(CONF_HASH, line);
            else if (!strncmp(CONF_VERSION, line, strlen(CONF_VERSION)) && isspace(line[strlen(CONF_VERSION)]))
                a.version = parse_config_tail(CONF_VERSION, line);

fl:
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
            { "help",        no_argument,       0, 'h' },
            { "version",     no_argument,       0, 'v' },
            { "licence",     no_argument,       0, 'l' },
            { "debug",       optional_argument, 0, 'd' },
            { "quiet",       no_argument,       0, 'q' },
            { "nogui",       no_argument,       0, 'g' },
            { "cipher",      required_argument, 0, 'c' },
            { "hash",        required_argument, 0, 's' },
            { "key",         required_argument, 0, 'k' },
            { "password",    required_argument, 0, 'p' },
            { "no-compress", no_argument,       0, 'x' },
            { "back-compat", required_argument, 0, 'b' },
            { "follow",      no_argument,       0, 'f' },
            { NULL,          0,                 0,  0  }
        };

        while (true)
        {
            int index = 0;
            int c = getopt_long(argc, argv, "hvld::qgc:s:k:p:xfb:", options, &index);
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

                case 'd':
                    optarg ? log_relevel(log_parse_level(optarg)) : log_relevel(LOG_DEFAULT);
                    break;
                case 'q':
                    log_relevel(LOG_ERROR);
                    break;
                case 'g':
                    a.nogui = true;
                    break;
                case 'c':
                    a.cipher = strdup(optarg);
                    break;
                case 's':
                    a.hash = strdup(optarg);
                    break;
                case 'k':
                    a.key = strdup(optarg);
                    break;
                case 'p':
                    a.password = strdup(optarg);
                    break;
                case 'x':
                    /*
                     * Could possibly use:
                     *     a.compress = !a.compress;
                     * if we wanted to turn compression on even if it
                     * was turned off in the config file
                     */
                    a.compress = false;
                    break;
                case 'f':
                    a.follow = true;
                    break;
                case 'b':
                    a.version = strdup(optarg);
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
    if (!o || !v)
        return;

    char *rc = NULL;
    if (!asprintf(&rc, "%s/%s", getenv("HOME") ? : ".", ENCRYPTRC))
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(getenv("HOME")) + strlen(ENCRYPTRC) + 2);

    FILE *f = fopen(rc, "rb+");
    if (!f)
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
             * first iteration: read rc file and change the value
             * second iteration: read from tmpfile back into rc file
             */
            while (getline(&line, &len, f) >= 0)
            {
                if (!i && (!strncmp(o, line, strlen(o)) && isspace(line[strlen(o)])))
                {
                    asprintf(&line, "%s %s\n", o, v);
                    log_message(LOG_VERBOSE, "Updated %s to %s in config file", o, v);
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

static void print_version(void)
{
    char *app_name = !strcmp(program_invocation_short_name, APP_NAME) ? APP_NAME : ALT_NAME;
    fprintf(stderr, _("%s version : %s\n%*s built on: %s %s\n"), app_name, ENCRYPT_VERSION, (int)strlen(app_name), "", __DATE__, __TIME__);
    return;
}

static void print_usage(void)
{
    char *app_name = !strcmp(program_invocation_short_name, APP_NAME) ? APP_NAME : ALT_NAME;
    char *app_usage = !strcmp(program_invocation_short_name, APP_NAME) ? APP_USAGE : ALT_USAGE;
    fprintf(stderr, _("Usage:\n  %s %s\n\n"), app_name, app_usage);
    return;
}

extern void show_help(void)
{
    print_version();
    print_usage();
    fprintf(stderr, _("Options:\n"));
    fprintf(stderr, _("  -h, --help                   Display this message\n"));
    fprintf(stderr, _("  -l, --licence                Display GNU GPL v3 licence header\n"));
    fprintf(stderr, _("  -v, --version                Display application version\n"));
    fprintf(stderr, _("  -d, --debug [log level]      Turn on debugging [to specified level]\n"));
    fprintf(stderr, _("  -q, --quiet                  Turn off all but serious error messages\n"));
    fprintf(stderr, _("  -g, --nogui                  Do not use the GUI, even if it's available\n"));
    if (!strcmp(program_invocation_short_name, APP_NAME))
    {
        fprintf(stderr, _("  -c, --cipher=<algorithm>     Algorithm to use to encrypt data\n"));
        fprintf(stderr, _("  -s, --hash=<algorithm>       Hash algorithm to generate key\n"));
    }
    fprintf(stderr, _("  -k, --key=<key file>         File whose data will be used to generate the key\n"));
    fprintf(stderr, _("  -p, --password=<password>    Password used to generate the key\n"));
    if (!strcmp(program_invocation_short_name, APP_NAME))
    {
        fprintf(stderr, _("  -x, --no-compress            Do not compress the plaintext using the xz algorithm\n"));
        fprintf(stderr, _("  -f, --follow                 Follow symlinks, the default is to store the link itself\n"));
        fprintf(stderr, _("  -b, --back-compat=<version>  Create an encrypted file that is backwards compatible\n"));
    }
    fprintf(stderr, _("\nNote: If you do not supply a key or password, you will be prompted for one.\n"));
    fprintf(stderr, "\n");
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

static bool parse_config_boolean(const char *c, const char *l, bool d)
{
    bool r = d;
    char *v = parse_config_tail(c, l);
    if (!strcasecmp(CONF_TRUE, v) || !strcasecmp(CONF_ON, v) || !strcasecmp(CONF_ENABLED, v))
        r = true;
    else if (!strcasecmp(CONF_FALSE, v) || !strcasecmp(CONF_OFF, v) || !strcasecmp(CONF_DISABLED, v))
        r = false;
    else
        log_message(LOG_WARNING, "Unknown value %s for %s in config file; using default : %s", v, c, d ? "true" : "false");
    free(v);
    return r;
}

static char *parse_config_tail(const char *c, const char *l)
{
    char *x = strdup(l + strlen(c));
    if (!x)
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(l) - strlen(c) + 1);
    size_t i = 0;
    for (i = 0; i < strlen(x) && isspace(x[i]); i++)
        ;
    char *y = strdup(x + i);
    if (!y)
        die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, strlen(x) - i + 1);
    free(x);
    for (i = strlen(y) - 1; i > 0 && isspace(y[i]); i--)
        y[i] = '\0';
    char *tail = strdup(y);
    free(y);
    return tail;
}
