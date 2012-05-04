/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2011, albinoloverats ~ Software Development
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
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include <inttypes.h>
#include <stdbool.h>

#include <pthread.h>
#include <curl/curl.h>

#ifdef _WIN32
    #include <windows.h>
    #include <sys/stat.h>
    extern char *program_invocation_short_name;
#endif

#include "main.h"
#include "encrypt.h"

#include "common/common.h"

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
#ifdef _WIN32
    program_invocation_short_name = strdup(argv[0]);
#endif
    /*
     * handle command line arguments
     */
    args_t hash     = { 's', "hash",     false, true,  NULL, "Hash algorithm to use to generate key" };
    args_t crypt    = { 'c', "crypto",   false, true,  NULL, "Algorithm to encrypt data" };
    args_t password = { 'p', "password", false, true,  NULL, "Password used to generate the key" };
    args_t keyfile  = { 'k', "keyfile",  false, true,  NULL, "File whose data will be used to generate the key" };
    args_t compress = { 'x', "compress", false, false, NULL, "TODO: implement compression" };

    list_t *opts = list_create(NULL);

    list_append(&opts, &hash);
    list_append(&opts, &crypt);
    list_append(&opts, &password);
    list_append(&opts, &keyfile);
#if 0 /* no compression yet */
    list_append(&opts, &compress);
#endif

    list_t *unknown = init(ENCRYPT_NAME, ENCRYPT_VERSION, USAGE_STRING, argv, NULL, opts);
    /*
     * list available algorithms if asked to (possibly both hash and crypto)
     */
    bool la = false;
    if (hash.found && hash.option && !strcasecmp(hash.option, "list"))
        la = list_algorithms_hash();
    if (crypt.found && crypt.option && !strcasecmp(crypt.option, "list"))
        la = list_algorithms_crypt();
    if (la)
        return EXIT_SUCCESS;

    pthread_t version_thread;

#ifdef BUILD_GUI
    gtk_widgets_t *widgets;
    GtkBuilder *builder;
    GError *error = NULL;

    bool fe = false;
    if (list_size(unknown) >= 1)
        fe = file_encrypted((char *)list_get(unknown, 0));
    /*
     * check args for files/passwords/algroithms...
     */
    if ((!fe && (hash.found && crypt.found && (password.found || keyfile.found))) 
      || (fe && (password.found || keyfile.found)))
        ; /* all required arguments were provided, no need for gui */
    else if (gtk_init_check(&argc, &argv))
    {
        builder = gtk_builder_new();
        if (!gtk_builder_add_from_file(builder, GLADE_UI_FILE, &error))
            die("%s", error->message);
        /*
         * allocate widgets structure
         */
        widgets = g_slice_new(gtk_widgets_t);
        /*
         * get widgets from UI
         */
        CH_GET_WIDGET(builder, main_window, widgets);
        CH_GET_WIDGET(builder, file_chooser, widgets);
        CH_GET_WIDGET(builder, out_file_chooser, widgets);
        CH_GET_WIDGET(builder, out_file_entry, widgets);
        CH_GET_WIDGET(builder, crypto_combo, widgets);
        CH_GET_WIDGET(builder, hash_combo, widgets);
        CH_GET_WIDGET(builder, key_combo, widgets);
        CH_GET_WIDGET(builder, password_entry, widgets);
        CH_GET_WIDGET(builder, key_chooser, widgets);
        CH_GET_WIDGET(builder, encrypt_button, widgets);
        CH_GET_WIDGET(builder, status_bar, widgets);
        CH_GET_WIDGET(builder, progress_dialog, widgets);
        CH_GET_WIDGET(builder, progress_bar, widgets);
        CH_GET_WIDGET(builder, progress_cancel_button, widgets);
        CH_GET_WIDGET(builder, progress_close_button, widgets);
        CH_GET_WIDGET(builder, about_dialog, widgets);

        version_thread = bg_thread_initialise(check_new_version, widgets);

        auto_select_algorithms(widgets, crypt.option, hash.option);

        if (list_size(unknown) >= 1)
            gtk_file_chooser_set_filename((GtkFileChooser *)widgets->file_chooser, (char *)list_get(unknown, 0));
        if (list_size(unknown) >= 2)
            gtk_entry_set_text((GtkEntry *)widgets->out_file_entry, (char *)list_get(unknown, 1));
        file_chooser_callback(NULL, widgets);

        gtk_builder_connect_signals(builder, widgets);
        g_object_unref(G_OBJECT(builder));

        gtk_combo_box_set_active((GtkComboBox *)widgets->key_combo, 0);
        /*
         * show main window and start main loop
         */
        update_status_bar(widgets, new_available ? -1 : 0);
        gtk_widget_show(widgets->main_window);
        gtk_main();

        g_slice_free(gtk_widgets_t, widgets);

        goto eop;
    }
    else
        fprintf(stderr, "Could not create GUI - falling back to command line\n");
#endif /* we couldn't create the gui, so revert back to command line */

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

    if (list_size(unknown) >= 1)
    {
        char *nm = (char *)list_get(unknown, 0);
        log_message(LOG_VERBOSE, "find source file %s", nm);
        source = open(nm, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
        if (source < 0)
            die(_("could not access input file %s"), nm);
        log_message(LOG_DEBUG, "opened %s for read access", nm);
    }
    if (list_size(unknown) >= 2)
    {
        char *nm = (char *)list_get(unknown, 1);
        log_message(LOG_VERBOSE, "find output file %s", nm);
        output = open(nm, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY | F_WRLCK, S_IRUSR | S_IWUSR);
        if (output < 0)
            die(_("could not access output file %s"), nm);
        log_message(LOG_DEBUG, "opened %s for write access", nm);
    }

    encrypt_t e_data = { crypt.option, hash.option, { NULL, 0, NULL, 0 }, true, compress.found };
    /*
     * get raw key data in form of password/phrase, key file
     */
    if (password.found)
    {
        if (!password.option || !strlen(password.option))
            die("insufficient password");
        e_data.key.p_data = (uint8_t *)password.option;
        e_data.key.p_length = (uint64_t)strlen((char *)e_data.key.p_data);
    }
    else if (keyfile.found)
    {
        if (!keyfile.option || !strlen(keyfile.option))
            die("invalid key data file");
        int64_t kf = open(keyfile.option, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
        if (kf < 0)
            die("could not access key data file");
        e_data.key.p_length = lseek(kf, 0, SEEK_END);
        e_data.key.p_data = malloc(e_data.key.p_length);
        if (!e_data.key.p_data)
            die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
        pread(kf, e_data.key.p_data, e_data.key.p_length, 0);
        close(kf);
    }
    else
    {
        show_usage(USAGE_STRING);
        return EXIT_FAILURE;
    }
    /*
     * here we go ...
     */
    pthread_t ui_thread = bg_thread_initialise(ui_thread_cli);
    status_e status = PREPROCESSING;
    if (file_encrypted(source))
        status = main_decrypt(source, output, e_data);
    else
        status = main_encrypt(source, output, e_data);
    pthread_join(ui_thread, NULL);
    close(source);

    if (status >= CANCELLED)
        log_message(LOG_WARNING, "%s", FAILED_MESSAGE[status]);

#ifdef BUILD_GUI
eop:
#endif
    pthread_join(version_thread, NULL);

    list_delete(&unknown);
    list_delete(&opts);

    return EXIT_SUCCESS;
}

static void *ui_thread_cli(void *n)
{
    log_message(LOG_EVERYTHING, "starting UI thread...");
    (void)n;
    fprintf(stderr, "\rPercent complete: %7.3f%%", 0.0f);
    uint64_t sz = 0;
    do
    {
        chill(10);
        if (!sz)
            sz = get_decrypted_size();
        else
            fprintf(stderr, "\b\b\b\b\b\b\b\b%7.3f%%", (get_bytes_processed() * 100.0f / sz));
    }
    while (get_status() == RUNNING);

    fprintf(stderr, "\rPercent complete: %7.3f%%", 100.0f);
    fprintf(stderr, "\n");
    log_message(LOG_EVERYTHING, "finished UI thread");
    return NULL;
}

extern pthread_t bg_thread_initialise2(void *(fn)(void *), void *n)
{
    /*
     * initialize background thread
     */
    log_message(LOG_DEBUG, "setting up UI thread");
    pthread_t bg_thread;
    pthread_create(&bg_thread, NULL, fn, n);
    return bg_thread;
}

static bool list_algorithms_hash(void)
{
    list_t *l = get_algorithms_hash();
    int x = list_size(l);
    fprintf(stderr, "%d hashing algorithms\n", x);
    for (int i = 0; i < x; i++)
        fprintf(stderr, "%s\n", (char *)list_get(l, i));
    return true;
}

static bool list_algorithms_crypt(void)
{
    list_t *l = get_algorithms_crypt();
    int x = list_size(l);
    fprintf(stderr, "%d cryptographic algorithms\n", x);
    for (int i = 0; i < x; i++)
        fprintf(stderr, "%s\n", (char *)list_get(l, i));
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
