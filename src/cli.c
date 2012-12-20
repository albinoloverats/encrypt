/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright © 2005-2012, albinoloverats ~ Software Development
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

#include <string.h>
#include <signal.h>

#include <sys/stat.h>
#include <time.h>
#include <math.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "common/common.h"

#include "cli.h"
#include "crypto.h"

#define CLI_DEFAULT 80
#define CLI_SINGLE 18
#define CLI_DOUBLE 13

static void cli_sigwinch(int);

static void cli_display_bar(float, float, bool, float);

static int cli_width = CLI_DEFAULT;

extern void cli_display(crypto_t *c)
{
    cli_sigwinch(SIGWINCH);

    struct stat t;
    fstat(STDOUT_FILENO, &t);
    bool ui = isatty(STDERR_FILENO) && (c->output || c->path || S_ISREG(t.st_mode));

    if (ui)
    {
        while (c->status == STATUS_INIT || c->status == STATUS_RUNNING)
        {
            struct timespec s = { 0, MILLION };
            nanosleep(&s, NULL);

            if (c->status == STATUS_INIT)
                continue;

            float pc = (PERCENT * c->total.offset + PERCENT * c->current.offset / c->current.size) / c->total.size;
            if (c->total.offset == c->total.size)
                pc = PERCENT * c->total.offset / c->total.size;

            cli_display_bar(pc, PERCENT * c->current.offset / c->current.size, c->total.size == 1, 0.0f);//(float)c->current.offset / (time(NULL) - c->current.started));
        }
        if (c->status == STATUS_SUCCESS)
            cli_display_bar(PERCENT, PERCENT, c->total.size == 1, 0.0f);//(float)c->current.offset / (time(NULL) - c->current.started));
        fprintf(stderr, "\n");
    }
    else
        while (c->status == STATUS_INIT || c->status == STATUS_RUNNING)
            sleep(1);

    return;
}

static void cli_display_bar(float total, float current, bool single, float bps)
{
    char *prog_bar = NULL;

    if (isnan(total))
        asprintf(&prog_bar, "  0%%");
    else
        asprintf(&prog_bar, "%3.0f%%", total);
    /*
     * display progress bar (currently hardcoded for 80 columns)
     */
    asprintf(&prog_bar, "%s [", prog_bar);
    int pb = single ? cli_width - CLI_SINGLE : cli_width / 2 - CLI_DOUBLE;
    for (int i = 0; i < pb; i++)
    {
        if (i < pb * total / PERCENT)
            asprintf(&prog_bar, "%s=", prog_bar);
        else
            asprintf(&prog_bar, "%s ", prog_bar);
    }
    /*
     * current (if necessary)
     */
    if (!single)
    {
        if (isnan(total))
            asprintf(&prog_bar, "%s]   0%% [", prog_bar);
        else
            asprintf(&prog_bar, "%s] %3.0f%% [", prog_bar, current);
        for (int i = 0; i < pb; i++)
        {
            if (i < pb * current / PERCENT)
                asprintf(&prog_bar, "%s=", prog_bar);
            else
                asprintf(&prog_bar, "%s ", prog_bar);
        }
    }
    asprintf(&prog_bar, "%s]", prog_bar);

    if (isnan(bps))
        asprintf(&prog_bar, "%s  ---.- B/s", prog_bar);
    else
    {
        if (bps < THOUSAND)
            asprintf(&prog_bar, "%s  %5.1f B/s", prog_bar, bps);
        else if (bps < MILLION)
            asprintf(&prog_bar, "%s %5.1f KB/s", prog_bar, bps / KILOBYTE);
        else if (bps < THOUSAND_MILLION)
            asprintf(&prog_bar, "%s %5.1f MB/s", prog_bar, bps / MEGABYTE);
        else if (bps < MILLION_MILLION)
            asprintf(&prog_bar, "%s %5.1f GB/s", prog_bar, bps / GIGABYTE);
    }

    fprintf(stderr, "\r%s", prog_bar);
    free(prog_bar);
    return;
}

static void cli_sigwinch(int s)
{
    struct winsize ws;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
    cli_width = ws.ws_col;
    signal(SIGWINCH, cli_sigwinch);
}
