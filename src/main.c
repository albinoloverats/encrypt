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
#include <fcntl.h>
#include <libintl.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <libgen.h>

#include "common/common.h"
#include "common/error.h"
#include "common/logging.h"
#ifdef _WIN32
    #include "common/win32_ext.h"
    extern char *program_invocation_short_name;
#endif

#include "init.h"
#include "main.h"
#include "encrypt.h"
#ifdef BUILD_GUI
    #include "gui.h"
#endif

static void *ui_thread_cli(void *);

static bool list_algorithms_hash(void);
static bool list_algorithms_crypt(void);

static void *check_new_version(void *);
static size_t verify_new_version(void *, size_t, size_t, void *);

static bool new_available = false;

int main(int argc, char **argv)
{
#ifdef __DEBUG__
    fprintf(stderr, _("\n**** DEBUG BUILD ****\n\n"));
#endif

#ifdef _WIN32
    program_invocation_short_name = strdup(argv[0]);
#endif
    args_t args = init(argc, argv);

    /*
     * list available algorithms if asked to (possibly both hash and crypto)
     */
    bool la = false;
    if (args.hash && !strcasecmp(args.hash, "list"))
        la = list_algorithms_hash();
    if (args.cipher && !strcasecmp(args.cipher, "list"))
        la = list_algorithms_crypt();
    if (la)
        return EXIT_SUCCESS;

    pthread_t version_thread;

    bool dodec = false;
    if (!strcmp(argv[0], ALT_NAME))
        dodec = true;

#ifdef BUILD_GUI
    gtk_widgets_t *widgets;
    GtkBuilder *builder;
    GError *error = NULL;

    bool fe = false;
    if (args.source)
        fe = file_encrypted(args.source);
    struct stat s;
#ifndef _WIN32
    fstat(STDIN_FILENO, &s);
    struct stat t;
    fstat(STDOUT_FILENO, &t);

    if (fe || (args.hash && args.cipher && (args.source || args.output)))
        ; /* user has given enough arguments on command line that we'll skip the gui */
    else if (!isatty(STDIN_FILENO) && (S_ISREG(s.st_mode) || S_ISFIFO(s.st_mode)))
        ; /* stdin is a redirect from a file or a pipe */
    else if (!isatty(STDOUT_FILENO) && (S_ISREG(t.st_mode) || S_ISFIFO(t.st_mode)))
        ; /* stdout is a redirect to a file or a pipe */
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
        CH_GET_WIDGET(builder, key_file_button, widgets);
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

        version_thread = bg_thread_initialise(check_new_version, widgets);

        /*
         * TODO find a way to select and display file encrypt
         */
        if (args.source)
        {
            gboolean x = gtk_file_chooser_set_filename((GtkFileChooser *)widgets->open_dialog, args.source);
            char *f = gtk_file_chooser_get_filename((GtkFileChooser *)widgets->open_dialog);
            log_message(LOG_DEBUG, "%s: %s", x ? "true" : "false", f);
        }
#ifdef ABOVE_TODO_IS_DONE
        if (args.output)
        {
            char *cwd = getcwd(NULL, 0);
            stat(args.output, &s);
            char *f = NULL;
            asprintf(&f, "%s/%s", cwd, args.output);
            bool z = false;
            if (S_ISREG(s.st_mode))
                z = gtk_file_chooser_set_filename((GtkFileChooser *)widgets->save_dialog, args.output);
            else
            {
                z = gtk_file_chooser_set_current_folder((GtkFileChooser *)widgets->save_dialog, dirname(f));
                gtk_file_chooser_set_current_name((GtkFileChooser *)widgets->save_dialog, basename(f));
            }
            log_message(LOG_VERBOSE, "%s : %s", z ? "true" : "false", g_quark_to_string(GTK_FILE_CHOOSER_ERROR));
            save_dialog_ok(NULL, widgets);
            free(f);
            free(cwd);
        }
#endif

        file_dialog_okay(NULL, widgets);
        auto_select_algorithms(widgets, args.cipher, args.hash);
        gtk_check_menu_item_set_active((GtkCheckMenuItem *)widgets->compress_menu_item, args.compress);
        gtk_combo_box_set_active((GtkComboBox *)widgets->key_combo, 0);

        /*
         * show main window and start main loop
         */
        update_status_bar(widgets, new_available ? -1 : 0);
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
    version_thread = bg_thread_initialise(check_new_version);

    /*
     * setup where the data is coming from; use stdin/stdout if no files are
     * suggested
     */
    int64_t source = STDIN_FILENO;
    int64_t output = STDOUT_FILENO;

    if (args.source)
    {
        log_message(LOG_VERBOSE, _("Requested source file: %s"), args.source);
        source = open(args.source, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
        if (source < 0)
            die(_("Could not access input file %s"), args.source);
        log_message(LOG_DEBUG, "Opened %s for read access", args.source);
    }
    if (args.output)
    {
        log_message(LOG_VERBOSE, _("Requested output file %s"), args.output);
        output = open(args.output, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY | F_WRLCK, S_IRUSR | S_IWUSR);
        if (output < 0)
            die(_("Could not access output file %s"), args.output);
        log_message(LOG_DEBUG, _("Opened %s for write access"), args.output);
    }

    encrypt_t e_data = { args.cipher, args.hash, { NULL, 0, NULL, 0 }, true, args.compress };
    /*
     * get raw key data in form of password/phrase, key file
     */
    if (args.key)
    {
        int64_t kf = open(args.key, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
        if (kf < 0)
            die(_("Could not access key data file"));
        e_data.key.p_length = lseek(kf, 0, SEEK_END);
        e_data.key.p_data = malloc(e_data.key.p_length);
        if (!e_data.key.p_data)
            die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, e_data.key.p_length);
        read(kf, e_data.key.p_data, e_data.key.p_length);
        close(kf);
    }
    else if (args.password)
    {
        e_data.key.p_data = (uint8_t *)args.password;
        e_data.key.p_length = (uint64_t)strlen((char *)e_data.key.p_data);
    }
    else if (isatty(STDIN_FILENO))
    {
        e_data.key.p_data = (uint8_t *)getpass(_("Please enter a password: "));
        e_data.key.p_length = (uint64_t)strlen((char *)e_data.key.p_data);
    }
    else
        show_usage();
    /*
     * here we go ...
     */
    pthread_t ui_thread = bg_thread_initialise(ui_thread_cli);
    status_e status = PREPROCESSING;
    if (file_encrypted(source) || dodec)
        status = main_decrypt(source, output, e_data);
    else
        status = main_encrypt(source, output, e_data);
    pthread_join(ui_thread, NULL);
    close(source);

    if (status >= CANCELLED)
        fprintf(stderr, _("%s"), FAILED_MESSAGE[status]);

#endif /* ! _WIN32 */

#ifdef BUILD_GUI
eop:
#endif

    pthread_join(version_thread, NULL);
    if (new_available)
        log_message(LOG_INFO, _("A new version of encrypt is available"));

#ifdef __DEBUG__
    fprintf(stderr, _("\n**** DEBUG BUILD ****\n\n"));
#endif

    return EXIT_SUCCESS;
}

static void *ui_thread_cli(void *n)
{
    log_message(LOG_EVERYTHING, _("Starting UI thread..."));
    (void)n;
    fprintf(stderr, _("\rPercent complete: %7.3f%%"), 0.0f);
    uint64_t sz = 0;
    do
    {
#ifndef _WIN32
        struct timespec t = {0, TEN_MILLION};
        struct timespec r = {0, 0};
        do
            nanosleep(&t, &r);
        while (r.tv_sec > 0 && r.tv_nsec > 0);
#endif
        if (!sz)
            sz = get_decrypted_size();
        else
            fprintf(stderr, "\b\b\b\b\b\b\b\b%7.3f%%", (get_bytes_processed() * 100.0f / sz));
    }
    while (get_status() == RUNNING);

    fprintf(stderr, _("\rPercent complete: %7.3f%%\n"), 100.0f);
    log_message(LOG_EVERYTHING, _("Finished UI thread"));
    return NULL;
}

extern pthread_t bg_thread_initialise2(void *(fn)(void *), void *n)
{
    /*
     * initialize background thread
     */
    log_message(LOG_EVERYTHING, _("Setting up UI thread"));
    pthread_t bg_thread;
    pthread_create(&bg_thread, NULL, fn, n);
    return bg_thread;
}

static bool list_algorithms_hash(void)
{
    char **l = get_algorithms_hash();
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

static bool list_algorithms_crypt(void)
{
    char **l = get_algorithms_crypt();
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

static void *check_new_version(void *n)
{
    curl_global_init(CURL_GLOBAL_ALL);
    CURL *curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, "https://albinoloverats.net/encrypt.release");
#ifdef WIN32
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
#endif
    curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, verify_new_version);
    curl_easy_perform(curl_handle);
    curl_easy_cleanup(curl_handle);
#ifdef BUILD_GUI
    if (n)
        update_status_bar((gtk_widgets_t *)n, new_available ? -1 : 0);
#endif
    return n;
}

static size_t verify_new_version(void *p, size_t s, size_t n, void *x)
{
    (void)x;
    char *b = calloc(s + 1, n);
    memcpy(b, p, s * n);
    char *l = strrchr(b, '\n');
    if (l)
        *l = '\0';
    if (strcmp(b, ENCRYPT_VERSION) > 0)
        new_available = true;
    free(b);
    return s * n;
}
