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

#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>

#include <string.h>
#include <stdbool.h>

#include <time.h>
#include <math.h>

#include <pthread.h>
#include <sys/stat.h>
#include <libgen.h>

#include "common/common.h"
#include "common/error.h"
#include "common/logging.h"
#include "common/version.h"

#ifdef _WIN32
    #include "common/win32_ext.h"
    extern char *program_invocation_short_name;
#endif

#include "init.h"
#include "main.h"

//#include "cli.h"

#include "crypto.h"
#include "encrypt.h"
#include "decrypt.h"

#ifdef BUILD_GUI
    #include "gui-gtk.h"
#endif

extern char *gtk_file_hack_cipher;
extern char *gtk_file_hack_hash;

extern void cli_display(crypto_t *);
extern void cli_print_line(const char * const restrict s, ...) __attribute__((format(printf, 1, 2)));
static void cli_append_bps(float);

static bool list_ciphers(void);
static bool list_hashes(void);

int main(int argc, char **argv)
{
#ifdef __DEBUG__
    cli_print_line(_("\n**** DEBUG BUILD ****\n"));
#endif

#ifdef _WIN32
    program_invocation_short_name = strdup(argv[0]);
#endif
    args_t args = init(argc, argv);

    /*
     * list available algorithms if asked to (possibly both hash and crypto)
     */
    bool la = false;
    if (args.cipher && !strcasecmp(args.cipher, "list"))
        la = list_ciphers();
    if (args.hash && !strcasecmp(args.hash, "list"))
        la = list_hashes();
    if (la)
        return EXIT_SUCCESS;

    bool dode = false;
    if (!strcmp(argv[0], ALT_NAME))
        dode = true;

#ifdef BUILD_GUI
    gtk_widgets_t *widgets;
    GtkBuilder *builder;
    GError *error = NULL;

    bool fe = false;
    if (args.source)
        fe = file_encrypted(args.source);
#ifndef _WIN32
    struct stat n;
    fstat(STDIN_FILENO, &n);
    struct stat t;
    fstat(STDOUT_FILENO, &t);

    if (fe || (args.hash && args.cipher && (args.source || args.output)))
        ; /* user has given enough arguments on command line that we'll skip the gui */
#if 0 /* currently causing problems */
    else if (!isatty(STDIN_FILENO) && (S_ISREG(n.st_mode) || S_ISFIFO(n.st_mode)))
        ; /* stdin is a redirect from a file or a pipe */
    else if (!isatty(STDOUT_FILENO) && (S_ISREG(t.st_mode) || S_ISFIFO(t.st_mode)))
        ; /* stdout is a redirect to a file or a pipe */
#endif
    else
#endif
    if (gtk_init_check(&argc, &argv))
    {
        builder = gtk_builder_new();
        if (!gtk_builder_add_from_file(builder, GLADE_UI_FILE, &error))
            die(_("%s"), error->message);
        /*
         * allocate widgets structure
         */
        widgets = g_slice_new(gtk_widgets_t);
        /*
         * get widgets from UI
         */
        CH_GET_WIDGET(builder, main_window, widgets);
        CH_GET_WIDGET(builder, open_button, widgets);
        CH_GET_WIDGET(builder, open_dialog, widgets);
        CH_GET_WIDGET(builder, open_file_label, widgets);
        CH_GET_WIDGET(builder, open_file_image, widgets);
        CH_GET_WIDGET(builder, save_button, widgets);
        CH_GET_WIDGET(builder, save_dialog, widgets);
        CH_GET_WIDGET(builder, save_file_label, widgets);
        CH_GET_WIDGET(builder, save_file_image, widgets);
        CH_GET_WIDGET(builder, crypto_combo, widgets);
        CH_GET_WIDGET(builder, hash_combo, widgets);
        CH_GET_WIDGET(builder, key_combo, widgets);
        CH_GET_WIDGET(builder, password_entry, widgets);
        CH_GET_WIDGET(builder, key_button, widgets);
        CH_GET_WIDGET(builder, key_dialog, widgets);
        CH_GET_WIDGET(builder, key_file_label, widgets);
        CH_GET_WIDGET(builder, key_file_image, widgets);
        CH_GET_WIDGET(builder, encrypt_button, widgets);
        CH_GET_WIDGET(builder, status_bar, widgets);
        CH_GET_WIDGET(builder, progress_dialog, widgets);
        CH_GET_WIDGET(builder, progress_bar, widgets);
        CH_GET_WIDGET(builder, progress_cancel_button, widgets);
        CH_GET_WIDGET(builder, progress_close_button, widgets);
        CH_GET_WIDGET(builder, about_dialog, widgets);
        CH_GET_WIDGET(builder, compress_menu_item, widgets);

        gtk_builder_connect_signals(builder, widgets);
        g_object_unref(G_OBJECT(builder));
        gtk_widget_show(widgets->main_window);

        version_check_for_update(widgets);

#ifndef _WIN32
        /*
         * TODO find a way to select and display file to encrypt
         */
        if (args.source)
        {
            char *cwd = getcwd(NULL, 0);
            asprintf(&gtk_file_hack_cipher, "%s/%s", cwd, args.source);
            gtk_file_chooser_set_filename((GtkFileChooser *)widgets->open_dialog, gtk_file_hack_cipher);
            free(cwd);
        }
        if (args.output)
        {
            char *cwd = getcwd(NULL, 0);
            asprintf(&gtk_file_hack_hash, "%s/%s", cwd, args.output);
            gtk_file_chooser_set_filename((GtkFileChooser *)widgets->save_dialog, gtk_file_hack_hash);
            free(cwd);
        }

        file_dialog_okay(NULL, widgets);
#endif
        auto_select_algorithms(widgets, args.cipher, args.hash);
        gtk_check_menu_item_set_active((GtkCheckMenuItem *)widgets->compress_menu_item, args.compress);
        gtk_combo_box_set_active((GtkComboBox *)widgets->key_combo, 0);

        gtk_main();

        g_slice_free(gtk_widgets_t, widgets);

        goto eop;
    }
    else
        fprintf(stderr, _("Could not create GUI - falling back to command line\n"));
#endif /* we couldn't create the gui, so revert back to command line */

#ifndef _WIN32 /* it's GUI or nothing */
    /*
     * start background thread to check for newer version of encrypt
     *
     * NB If (When) encrypt makes it into a package manager for some
     * distro this can/should be removed as it will be unnecessary
     */
    version_check_for_update(ENCRYPT_VERSION, UPDATE_URL);

    /*
     * get raw key data in form of password/phrase, key file
     */
    uint8_t *key;
    size_t length;
    if (args.key)
    {
        key = (uint8_t *)args.key;
        length = 0;
    }
    else if (args.password)
    {
        key = (uint8_t *)args.password;
        length = strlen(args.password);
    }
    else if (isatty(STDIN_FILENO))
    {
        key = (uint8_t *)getpass(_("Please enter a password: "));
        length = strlen((char *)key);
        printf("\n");
    }
    else
        show_usage();
    /*
     * here we go ...
     */
    crypto_t *c;
    
    if (dode || (args.source && file_encrypted(args.source)))
        c = decrypt_init(args.source, args.output, key, length);
    else
        c = encrypt_init(args.source, args.output, args.cipher, args.hash, key, length, args.compress);

    execute(c);

    /*
     * only display the UI if not outputing to stdout (and if stderr is
     * a terminal)
     */
    cli_display(c);

    deinit(&c);

#endif /* ! _WIN32 */

#ifdef BUILD_GUI
eop:
#endif

    if (new_version_available)
        cli_print_line(_(NEW_VERSION_OF_AVAILABLE), program_invocation_short_name);

#ifdef __DEBUG__
    cli_print_line(_("\n**** DEBUG BUILD ****\n"));
#endif

    return EXIT_SUCCESS;
}

extern void cli_display(crypto_t *c)
{
    struct stat t;
    fstat(STDOUT_FILENO, &t);
    bool ui = isatty(STDERR_FILENO) && (c->output || S_ISREG(t.st_mode));

    while (c->status == INIT || c->status == RUNNING)
    {
        if (ui)
        {
            /*
             * display percent complete
             */
            float pc = (100.0 * c->total.offset + 100.0 * c->current.offset / c->current.size) / c->total.size;
            if (c->total.offset == c->total.size)
                pc = 100.0 * c->total.offset / c->total.size;
            fprintf(stderr, "\r%3.0f%% ", pc);
            /*
             * display progress bar (currently hardcoded for 80 columns)
             */
            fprintf(stderr, "[");
            int pb = c->total.size == 1 ? 62 : 27;
            for (int i = 0; i < pb; i++)
            {
                if (i < pb * pc / 100)
                    fprintf(stderr, "=");
                else
                    fprintf(stderr, " ");
            }
            if (c->total.size > 1)
            {
                fprintf(stderr, "] %3.0f%% [", 100.0 * c->current.offset / c->current.size);
                for (int i = 0; i < pb; i++)
                {
                    if (i < (int)((float)pb * c->current.offset / c->current.size))
                        fprintf(stderr, "=");
                    else
                        fprintf(stderr, " ");
                }
            }
            fprintf(stderr, "] ");
            /*
             * display bytes/second (prefixed as necessary)
             */
            cli_append_bps((float)c->current.offset / (time(NULL) - c->current.started));
        }

        struct timespec s = { 0, MILLION };
        nanosleep(&s, NULL);
    }

    if (ui)
    {
        if (c->status == SUCCESS)
        {
            if (c->total.size == 1)
                fprintf(stderr, "\r100%% [==============================================================] ");
            else
                fprintf(stderr, "\r100%% [===========================] 100%% [===========================] ");
            cli_append_bps((float)c->total.total / (time(NULL) - c->total.started));
        }
        fprintf(stderr, "\n");
    }
    return;
}

extern void cli_print_line(const char * const restrict s, ...)
{
    va_list ap;
    va_start(ap, s);
    vfprintf(stderr, s, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void cli_append_bps(float bps)
{
    if (isnan(bps))
        fprintf(stderr, " ---.- B/s");
    else
    {
        if (bps < 1000)
            fprintf(stderr, " %5.1f B/s", bps);
        else if (bps < MILLION)
            fprintf(stderr, "%5.1f KB/s", bps / KILOBYTE);
        else if (bps < THOUSAND_MILLION)
            fprintf(stderr, "%5.1f MB/s", bps / MEGABYTE);
        else if (bps < MILLION_MILLION)
            fprintf(stderr, "%5.1f GB/s", bps / GIGABYTE);
    }
    return;
}

static bool list_ciphers(void)
{
    char **l = list_of_ciphers();
    for (int i = 0; ; i++)
    {
        if (!l[i])
            break;
        else if (strlen(l[i]))
            fprintf(stderr, "%s\n", l[i]);
        free(l[i]);
    }
    free(l);
    return true;
}

static bool list_hashes(void)
{
    char **l = list_of_hashes();
    for (int i = 0; ; i++)
    {
        if (!l[i])
            break;
        else if (strlen(l[i]))
            fprintf(stderr, "%s\n", l[i]);
        free(l[i]);
    }
    free(l);
    return true;
}
