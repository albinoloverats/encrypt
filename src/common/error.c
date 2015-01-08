/*
 * Common code for error reporting
 * Copyright © 2009-2015, albinoloverats ~ Software Development
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#if !defined _WIN32 && !defined __CYGWIN__ && !defined __FreeBSD__
    #include <execinfo.h>
#endif

#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>

#include "error.h"

#ifdef _WIN32
    #include "common/win32_ext.h"
#endif

#ifdef BUILD_GUI
static void error_gui_alert(const char * const restrict);

static GtkWidget *error_gui_window;
static GtkWidget *error_gui_message;
#else
    #define error_gui_alert(X) (void)(X)
#endif

extern void die(const char * const restrict s, ...)
{
    int ex = errno;
    if (s)
    {
        char *d = NULL;
        va_list ap;
        va_start(ap, s);
#ifndef _WIN32
        vasprintf(&d, s, ap);
        fprintf(stderr, "%s", d);
        error_gui_alert(d);
#else
        uint8_t l = 0xFF;
        d = calloc(l, sizeof( uint8_t ));
        if (d)
            vsnprintf(d, l - 1, s, ap);
        fprintf(stderr, "%s", d);
        error_gui_alert(d);
        if (d)
            free(d);
#endif
        va_end(ap);
        fprintf(stderr, "\n");
    }
    if (ex)
    {
        char * const restrict e = strdup(strerror(ex));
        for (uint32_t i = 0; i < strlen(e); i++)
            e[i] = tolower((unsigned char)e[i]);
        fprintf(stderr, "%s\n", e);
        free(e);
#if !defined _WIN32 && !defined __CYGWIN__ && !defined __FreeBSD__
        void *bt[BACKTRACE_BUFFER_LIMIT];
        int c = backtrace(bt, BACKTRACE_BUFFER_LIMIT);
        char **sym = backtrace_symbols(bt, c);
        if (sym)
        {
            for (int i = 0; i < c; i++)
                fprintf(stderr, "%s\n", sym[i]);
            free(sym);
        }
#endif
    }
    exit(ex);
}

#ifdef BUILD_GUI
extern void error_gui_init(GtkWidget *w, GtkWidget *m)
{
    error_gui_window = w;
    error_gui_message = m;
}

extern void error_gui_close(GtkWidget *w)
{
    (void)w;
    gtk_widget_hide(error_gui_window);
    return;
}

static void error_gui_alert(const char * const restrict msg)
{
    if (error_gui_window)
    {
#if 1
        gtk_label_set_text((GtkLabel *)error_gui_message, msg);
        gtk_dialog_run((GtkDialog *)error_gui_window);
#else
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(error_gui_window),
                GTK_DIALOG_DESTROY_WITH_PARENT,
                GTK_MESSAGE_ERROR,
                GTK_BUTTONS_OK,
                "A fatal error has occurred; encrypt will now close");
        gtk_window_set_default_size(GTK_WINDOW(dialog), 320, 200);
        gtk_widget_set_size_request(dialog, 320, 200);
        gtk_window_set_title(GTK_WINDOW(dialog), "Fatal Error!");
        gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dialog), "%s", msg);
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
#endif
    }
    return;
}
#endif
