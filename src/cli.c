/*
 * encrypt ~ a simple, multi-OS encryption utility
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

#include <string.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <math.h>

#ifndef _WIN32
    #include <termios.h>
    #include <sys/ioctl.h>
#endif

#include "common/common.h"

#include "cli.h"
#include "crypt.h"

#define CLI_DEFAULT 80
#define CLI_SINGLE 18
#define CLI_DOUBLE 13

#ifndef _WIN32
static int cli_width = CLI_DEFAULT;

static void cli_display_bar(float, float, bool, bps_t *);
static void cli_sigwinch(int);
#endif

static int cli_bps_sort(const void *, const void *);

extern float cli_calc_bps(bps_t *bps)
{
    bps_t copy[BPS];
    for (int i = 0; i < BPS; i++)
    {
        copy[i].time = bps[i].time;
        copy[i].bytes = bps[i].bytes;
    }
    qsort(copy, BPS, sizeof( bps_t ), cli_bps_sort);
    float avg[BPS - 1] = { 0.0f };
    for (int i = 0; i < BPS - 1; i++)
        /*
         * requires scale factor of MILLION as time is in microseconds
         * not seconds (millions of bytes / micros of seconds, so to
         * speak)
         */
        avg[i] = MILLION * (float)(copy[i + 1].bytes - copy[i].bytes) / (float)(copy[i + 1].time - copy[i].time);
    float val = 0.0;
    for (int i = 0; i < BPS - 1; i++)
        val += avg[i];
    val /= BPS - 1;
    return val;
}

#ifndef _WIN32
extern void cli_display(crypto_t *c)
{
    cli_sigwinch(SIGWINCH);

    struct stat t;
    fstat(STDOUT_FILENO, &t);
    bool ui = isatty(STDERR_FILENO) && (!io_is_stdout(c->output) || c->path || S_ISREG(t.st_mode));

    if (ui)
    {
        bps_t bps[BPS];
        memset(bps, 0x00, BPS * sizeof( bps_t ));
        int b = 0;

        while (c->status == STATUS_INIT || c->status == STATUS_RUNNING)
        {
            struct timespec s = { 0, MILLION };
            nanosleep(&s, NULL);

            if (c->status == STATUS_INIT)
                continue;

            float pc = (PERCENT * c->total.offset + PERCENT * c->current.offset / c->current.size) / c->total.size;
            if (c->total.offset == c->total.size)
                pc = PERCENT * c->total.offset / c->total.size;

            struct timeval tv;
            gettimeofday(&tv, NULL);
            bps[b].time = tv.tv_sec * MILLION + tv.tv_usec;
            bps[b].bytes = c->current.offset;
            b++;
            if (b >= BPS)
                b = 0;

            cli_display_bar(pc, PERCENT * c->current.offset / c->current.size, c->total.size == 1, bps);
        }
        if (c->status == STATUS_SUCCESS)
            cli_display_bar(PERCENT, PERCENT, c->total.size == 1, bps);
        fprintf(stderr, "\n");
    }
    else
        while (c->status == STATUS_INIT || c->status == STATUS_RUNNING)
            sleep(1);

    return;
}

static void cli_display_bar(float total, float current, bool single, bps_t *bps)
{
    char *prog_bar = calloc(cli_width + 1, sizeof( char ));
    sprintf(prog_bar, "%3.0f%%", isnan(total) ? 0.0f : total);
    /*
     * display progress bar
     */
    strcat(prog_bar, " [");
    int pb = single ? cli_width - CLI_SINGLE : cli_width / 2 - CLI_DOUBLE;
    for (int i = 0; i < pb; i++)
        strcat(prog_bar, i < pb * total / PERCENT ? "=" : " ");
    /*
     * current (if necessary)
     */
    if (!single)
    {
        sprintf(prog_bar + strlen(prog_bar), "] %3.0f%% [", isnan(total) ? 0.0f : current);
        for (int i = 0; i < pb; i++)
            strcat(prog_bar, i < pb * current / PERCENT ? "=" : " ");
    }
    strcat(prog_bar, "]");
    /*
     * calculate B/s
     */
    float val = cli_calc_bps(bps);
    if (isnan(val) || val == 0.0f)
        strcat(prog_bar, "  ---.- B/s");
    else
    {
        if (val < THOUSAND)
            sprintf(prog_bar + strlen(prog_bar), "  %5.1f B/s", val);
        else if (val < MILLION)
            sprintf(prog_bar + strlen(prog_bar), " %5.1f KB/s", val / KILOBYTE);
        else if (val < THOUSAND_MILLION)
            sprintf(prog_bar + strlen(prog_bar), " %5.1f MB/s", val / MEGABYTE);
        else if (val < BILLION)
            sprintf(prog_bar + strlen(prog_bar), " %5.1f GB/s", val / GIGABYTE);
#if 0
        else /* if you're getting these kinds of speeds please, please can I have your machine ;-) */
            sprintf(prog_bar + strlen(prog_bar), " %5.1f TB/s", val / TERABYTE);
#endif
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
    (void)s;
}
#endif

static int cli_bps_sort(const void *a, const void *b)
{
    const bps_t *ba = (const bps_t *)a;
    const bps_t *bb = (const bps_t *)b;
    return (ba->time > bb->time) - (ba->time < bb->time);
}
