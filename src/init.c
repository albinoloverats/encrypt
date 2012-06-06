/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2012, albinoloverats ~ Software Development
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
#include <getopt.h>

#include <errno.h>
#include <libintl.h>

#include <string.h>
#include <stdbool.h>

#include "common/common.h"
#include "common/logging.h"

#include "init.h"
#include "encrypt.h"

extern args_t init(int argc, char **argv)
{
    struct option options[] =
    {
        { "help",     no_argument,       0, 'h' },
        { "version",  no_argument,       0, 'v' },
        { "licence",  no_argument,       0, 'l' },
        { "debug",    optional_argument, 0, 'd' },
        { "quiet",    no_argument,       0, 'q' },
        { "cipher",   required_argument, 0, 'c' },
        { "hash",     required_argument, 0, 's' },
        { "key",      required_argument, 0, 'k' },
        { "password", required_argument, 0, 'p' },
        { NULL,       0,                 0,  0  }
    };
    args_t a = { NULL };
    
    while (true)
    {
        int index = 0;
        int c = getopt_long(argc, argv, "hvld::qc:s:k:p:", options, &index);
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
                if (optarg)
                    log_relevel(log_parse_level(optarg));
                else
                    log_relevel(LOG_DEFAULT);
                break;
            case 'q':
                log_relevel(LOG_ERROR);
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

    return a;
}

extern void show_help(void)
{
    fprintf(stderr, _("%s version : %s\n%*s built on: %s %s\n"), TEXT_NAME, TEXT_VERSION, (int)strlen(TEXT_NAME), "", __DATE__, __TIME__);
    fprintf(stderr, _("Usage:\n  %s %s\n\n"), TEXT_NAME, TEXT_USAGE);
    fprintf(stderr, _("Options:\n"));
    fprintf(stderr, _("  -h/--help                 Display this message\n"));
    fprintf(stderr, _("  -l/--licence              Display GNU GPL v3 licence header\n"));
    fprintf(stderr, _("  -v/--version              Display application version\n"));
    fprintf(stderr, _("  -d/--debug [log level]    Turn on debugging [to specified level]\n"));
    fprintf(stderr, _("  -q/--quiet                Turn off all but serious error messages\n"));
    fprintf(stderr, _("  -c/--cipher <algorithm>   Algorithm to use to encrypt data\n"));
    fprintf(stderr, _("  -s/--hash <algorithm>     Hash algorithm to generate key\n"));
    fprintf(stderr, _("  -k/--key <key file>       File whose data will be used to generate the key\n"));
    fprintf(stderr, _("  -p/--password <password>  Password used to generate the key\n"));
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
    fprintf(stderr, _("Usage:\n  %s %s\n"), TEXT_NAME, TEXT_USAGE);
    exit(EXIT_SUCCESS);
}

extern void show_version(void)
{
    fprintf(stderr, _("%s version : %s\n%*s built on: %s %s\n"), TEXT_NAME, TEXT_VERSION, (int)strlen(program_invocation_short_name), "", __DATE__, __TIME__);
    exit(EXIT_SUCCESS);
}
