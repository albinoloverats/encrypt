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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <libintl.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <pthread.h>
#include <libgen.h>

#include "gui.h"

#include "common/common.h"
#include "common/error.h"
#include "common/logging.h"
#ifdef _WIN32
    #include "common/win32_ext.h"
#endif

#include "init.h"
#include "main.h"
#include "encrypt.h"

#define _filename_utf8(A) g_filename_to_utf8(A, -1, NULL, NULL, NULL)

#define NONE_SELECTED "(None)"

extern char *FAILED_MESSAGE[];

/*
 * FIXME There has to be a way to make gtk_file_chooser_set_filename
 * work correctly
 */
char *gtk_file_hack_cipher = NULL;
char *gtk_file_hack_hash = NULL;

static void *bg_thread_gui(void *n);

static gboolean files = false;
static bool encrypting = true;
static bool compress = true;

G_MODULE_EXPORT gboolean file_dialog_display(GtkButton *button, gtk_widgets_t *data)
{
    /*
     * all file selection buttons click-through here
     */
    GtkDialog *d = NULL;
    GtkLabel *l = NULL;
    GtkWidget *i = NULL;
    bool a = true;

    if (button == (GtkButton *)data->open_button)
    {
        d = (GtkDialog *)data->open_dialog;
        l = (GtkLabel *)data->open_file_label;
        i = data->open_file_image;
    }
    else if (button == (GtkButton *)data->save_button)
    {
        d = (GtkDialog *)data->save_dialog;
        l = (GtkLabel *)data->save_file_label;
        i = data->save_file_image;
    }
    else if (button == (GtkButton *)data->key_button)
    {
        d = (GtkDialog *)data->key_dialog;
        l = (GtkLabel *)data->key_file_label;
        i = data->key_file_image;
        a = false;
    }

    if (!d || !l || !i)
        return FALSE;

    if (gtk_dialog_run(d) == GTK_RESPONSE_DELETE_EVENT)
    {
        gtk_label_set_text(l, NONE_SELECTED);
        gtk_widget_hide(i);

        if (a)
        {
            gtk_widget_set_sensitive(data->crypto_combo, FALSE);
            gtk_widget_set_sensitive(data->hash_combo, FALSE);
            gtk_widget_set_sensitive(data->key_combo, FALSE);
            gtk_widget_set_sensitive(data->key_button, FALSE);
        }
        gtk_widget_set_sensitive(data->encrypt_button, FALSE);
    }

    gtk_widget_hide((GtkWidget *)d);

    return TRUE;
}

G_MODULE_EXPORT gboolean file_dialog_okay(GtkButton *button, gtk_widgets_t *data)
{
    gtk_widget_hide(data->open_dialog);
    gtk_widget_hide(data->save_dialog);

    gboolean en = TRUE;
    /*
     * check the source file exists (and is a file)
     */
    char *open_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->open_dialog);
    if (!open_file)
        open_file = gtk_file_hack_cipher;
    if (open_file)
    {
        /*
         * quickly see if the file is encrypted already
         */
        int64_t f = open(open_file, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
        if (f > 0)
        {
            gtk_label_set_text((GtkLabel *)data->open_file_label, _filename_utf8(basename(open_file)));
            gtk_widget_show(data->open_file_image);

            char *c = NULL, *h = NULL;
            if (file_encrypted(f))
            {
                encrypting = false;
                auto_select_algorithms(data, c, h);
            }
            close(f);
            gtk_button_set_label((GtkButton *)data->encrypt_button, encrypting ? LABEL_ENCRYPT : LABEL_DECRYPT);
        }
        else
            en = FALSE;
    }
    else
        en = FALSE;
    g_free(open_file);

    char *save_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->save_dialog);
    if (!save_file)
        save_file = gtk_file_hack_hash;
    if (!save_file || !strlen(save_file))
        en = FALSE;
    else
    {
        struct stat s;
        stat(save_file, &s);
        /*
         * if the destination exists, it has to be a regular file
         */
        if (errno == ENOENT || S_ISREG(s.st_mode))
        {
            gtk_label_set_text((GtkLabel *)data->save_file_label, _filename_utf8(basename(save_file)));
            gtk_widget_show(data->save_file_image);
        }
        else
            en = FALSE;
    }
    g_free(save_file);

    files = en;

    if (encrypting)
    {
        gtk_widget_set_sensitive(data->crypto_combo, en);
        gtk_widget_set_sensitive(data->hash_combo, en);
        if (en)
            algorithm_combo_callback(NULL, data);
    }
    else
        gtk_widget_set_sensitive(data->key_combo, en);

    return TRUE;
}

extern void auto_select_algorithms(gtk_widgets_t *data, char *cipher, char *hash)
{
    char **ciphers = get_algorithms_crypt();
    unsigned slctd_cipher = 0;
    for (unsigned i = 0; ; i++)
    {
        if (!ciphers[i])
            break;
        else if (cipher && !strcasecmp(ciphers[i], cipher))
        {
            slctd_cipher = i + 1;
            log_message(LOG_VERBOSE, _("Selected %d is algorithm: %s"), slctd_cipher, cipher);
        }
        gtk_combo_box_text_append_text((GtkComboBoxText *)data->crypto_combo, ciphers[i]);
        free(ciphers[i]);
    }
    gtk_combo_box_set_active((GtkComboBox *)data->crypto_combo, slctd_cipher);
    free(ciphers);

    char **hashes = get_algorithms_hash();
    unsigned slctd_hash = 0;
    for (unsigned  i = 0; ; i++)
    {
        if (!hashes[i])
            break;
        else if (hash && !strcasecmp(hashes[i], hash))
        {
            slctd_hash = i + 1;
            log_message(LOG_VERBOSE, _("Selected %d is hash: %s"), slctd_hash, hash);
        }
        gtk_combo_box_text_append_text((GtkComboBoxText *)data->hash_combo, hashes[i]);
        free(hashes[i]);
    }
    gtk_combo_box_set_active((GtkComboBox *)data->hash_combo, slctd_hash);
    free(hashes);

    return;
}

G_MODULE_EXPORT gboolean algorithm_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data)
{
    int cipher = gtk_combo_box_get_active((GtkComboBox *)data->crypto_combo);
    int hash = gtk_combo_box_get_active((GtkComboBox *)data->hash_combo);

    gboolean en = files;

    if (!cipher || !hash)
        en = FALSE;

    gtk_widget_set_sensitive(data->key_combo, en);
    gtk_widget_set_sensitive(data->password_entry, en);
    gtk_widget_set_sensitive(data->key_button, en);
    gtk_widget_set_sensitive(data->encrypt_button, en);
    if (en)
        key_combo_callback(NULL, data);

    return TRUE;
}

G_MODULE_EXPORT gboolean key_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data)
{
    switch (gtk_combo_box_get_active((GtkComboBox *)data->key_combo))
    {
        case KEYFILE:
            gtk_widget_set_sensitive(data->password_entry, FALSE);
            gtk_widget_set_sensitive(data->key_button, TRUE);
            gtk_widget_hide(data->password_entry);
            gtk_widget_show(data->key_button);
            key_dialog_okay(NULL, data);
            break;

        case PASSWORD:
            gtk_widget_set_sensitive(data->password_entry, TRUE);
            gtk_widget_set_sensitive(data->key_button, FALSE);
            gtk_widget_show(data->password_entry);
            gtk_widget_hide(data->key_button);
            password_entry_callback(NULL, data);
            break;

        default:
            gtk_widget_set_sensitive(data->password_entry, FALSE);
            gtk_widget_set_sensitive(data->key_button, FALSE);
            gtk_widget_set_sensitive(data->encrypt_button, FALSE);
    }

    return TRUE;
}

G_MODULE_EXPORT gboolean password_entry_callback(GtkComboBox *password_entry, gtk_widgets_t *data)
{
    char *key_data = (char *)gtk_entry_get_text((GtkEntry *)data->password_entry);

    if (key_data && strlen(key_data))
    {
        gtk_widget_set_sensitive(data->encrypt_button, TRUE);
        gtk_widget_grab_default(data->encrypt_button);
    }
    else
        gtk_widget_set_sensitive(data->encrypt_button, FALSE);

    return TRUE;
}

G_MODULE_EXPORT gboolean key_dialog_okay(GtkFileChooser *file_chooser, gtk_widgets_t *data)
{
    gboolean en = TRUE;

    char *key_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->key_dialog);
    if (!key_file || !strlen(key_file))
        en = FALSE;

    struct stat s;
    stat(key_file, &s);
    if (errno == ENOENT || !S_ISREG(s.st_mode))
        en = FALSE;

    gtk_label_set_text((GtkLabel *)data->key_file_label, en ? _filename_utf8(basename(key_file)) : NONE_SELECTED);

    g_free(key_file);

    if (en)
        gtk_widget_show(data->key_file_image);
    else
        gtk_widget_hide(data->key_file_image);

    gtk_widget_set_sensitive(data->encrypt_button, en);
    if (en)
        gtk_widget_grab_default(data->encrypt_button);

    return TRUE;
}

G_MODULE_EXPORT gboolean on_encrypt_button_clicked(GtkButton *button, gtk_widgets_t *data)
{
    log_message(LOG_EVERYTHING, _("Show progress dialog"));
    gtk_widget_show(data->progress_dialog);

    pthread_t bgt = bg_thread_initialise(bg_thread_gui, data);

    log_message(LOG_EVERYTHING, _("Reset cancel/close buttons"));
    gtk_widget_set_sensitive(data->progress_cancel_button, TRUE);
    gtk_widget_show(data->progress_cancel_button);
    gtk_widget_set_sensitive(data->progress_close_button, FALSE);
    gtk_widget_hide(data->progress_close_button);

    log_message(LOG_EVERYTHING, _("Reset progress bar"));
    gtk_progress_bar_set_fraction((GtkProgressBar *)data->progress_bar, 0.0);
    gtk_progress_bar_set_text((GtkProgressBar *)data->progress_bar, "");

    uint64_t sz = 0;

    log_message(LOG_EVERYTHING, _("Update progress bar in loop"));
    status_e status = PREPROCESSING;
    do
    {
        if (!sz)
            sz = get_decrypted_size();
        else
        {
            uint64_t bp = get_bytes_processed();
            gtk_progress_bar_set_fraction((GtkProgressBar *)data->progress_bar, (double)bp / (double)sz);

            char *prgs = NULL;
#ifdef WIN32
            asprintf(&prgs, "%llu", bp);
#else
            asprintf(&prgs, "%" PRIu64 " / %" PRIu64, bp, sz);
#endif
            gtk_progress_bar_set_text((GtkProgressBar *)data->progress_bar, prgs);
            free(prgs);
        }
        status = get_status();
        gtk_main_iteration_do(FALSE);
    }
    while (status == RUNNING);


    void *r = NULL;
    pthread_join(bgt, &r);
    memcpy(&status, r, sizeof status);
    free(r);
    log_message(LOG_VERBOSE, _("Background thread finished with status: %d"), status);

    update_status_bar(data, status);

    char *msg;
    if (status == SUCCEEDED)
    {
        gtk_progress_bar_set_fraction((GtkProgressBar *)data->progress_bar, 1.0);
        msg = STATUS_DONE;
    }
    else
        msg = FAILED_MESSAGE[status];
    gtk_progress_bar_set_text((GtkProgressBar *)data->progress_bar, msg);;

    gtk_widget_set_sensitive(data->progress_cancel_button, FALSE);
    gtk_widget_hide(data->progress_cancel_button);
    gtk_widget_set_sensitive(data->progress_close_button, TRUE);
    gtk_widget_show(data->progress_close_button);

    return TRUE;
}

G_MODULE_EXPORT gboolean on_cancel_button_clicked(GtkButton *button, gtk_widgets_t *data)
{
    log_message(LOG_DEBUG, _("Cancel background thread"));
    stop_running();

    return TRUE;
}

G_MODULE_EXPORT gboolean on_close_button_clicked(GtkButton *button, gtk_widgets_t *data)
{
    gtk_widget_hide(data->progress_dialog);

    return TRUE;
}

extern void update_status_bar(gtk_widgets_t *data, int64_t status)
{
    static int ctx = -1;
    if (ctx != -1)
        gtk_statusbar_pop((GtkStatusbar *)data->status_bar, ctx);
    char *msg;
    if (status == -1)
        msg = STATUS_NEW_VERSION;
    else
        msg = FAILED_MESSAGE[status] ? : STATUS_READY;
    ctx = gtk_statusbar_get_context_id((GtkStatusbar *)data->status_bar, msg);
    gtk_statusbar_push((GtkStatusbar *)data->status_bar, ctx, msg);
}

static void *bg_thread_gui(void *n)
{
    /*
     * TODO add error checking/reporting for file access
     */
    gtk_widgets_t *data = (gtk_widgets_t *)n;

    char *open_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->open_dialog);
    int64_t source = open(open_file, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
    g_free(open_file);

    char *save_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->save_dialog);
    int64_t output = open(save_file, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY | F_WRLCK, S_IRUSR | S_IWUSR);
    g_free(save_file);

    status_e status = SUCCEEDED;
    void *r = calloc(1, sizeof status);

    int key_type = gtk_combo_box_get_active((GtkComboBox *)data->key_combo);
    raw_key_t key = {NULL, 0, NULL, 0};
    switch (key_type)
    {
        case KEYFILE:
            {
                char *key_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->key_dialog);
                int64_t kf = open(key_file, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
                g_free(key_file);
                if (kf < 0)
                {
                    status = FAILED_OTHER;
                    memcpy(r, &status, sizeof status);
                    pthread_exit(r);
                    return NULL;
                }
                key.p_length = lseek(kf, 0, SEEK_END);
                key.p_data = malloc(key.p_length);
                if (!key.p_data)
                    die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, key.p_length);
                read(kf, key.p_data, key.p_length);
                close(kf);
            }
            break;

        case PASSWORD:
            key.p_data = (uint8_t *)gtk_entry_get_text((GtkEntry *)data->password_entry);
            key.p_length = strlen((char *)key.p_data);
            break;
    }
    encrypt_t e_data = { NULL, NULL, key, true, compress };

    if (encrypting)
    {
        int c = gtk_combo_box_get_active((GtkComboBox *)data->crypto_combo);
        int h = gtk_combo_box_get_active((GtkComboBox *)data->hash_combo);
        char **ciphers = get_algorithms_crypt();
        char **hashes = get_algorithms_hash();
        e_data.cipher = ciphers[c - 1]; /* subtract 1 to get algorithm offset from combobox */
        e_data.hash = hashes[h - 1];    /* combobox item 0 is the 'select...' text */
        status = main_encrypt(source, output, e_data);
        for (int i = 0; ; i++)
            if (!ciphers[i])
                break;
            else
                free(ciphers[i]);
        free(ciphers);
        for (int i = 0; ; i++)
            if (!hashes[i])
                break;
            else
                free(hashes[i]);
        free(hashes);
    }
    else
        status = main_decrypt(source, output, e_data);

    close(source);
    close(output);

    if (key_type == PASSWORD)
        g_free(key.p_data);
    else
        free(key.p_data);

    memcpy(r, &status, sizeof status);
    pthread_exit(r);

    return r;
}

G_MODULE_EXPORT gboolean on_about_open(GtkWidget *widget, gtk_widgets_t *data)
{
    gtk_dialog_run((GtkDialog *)data->about_dialog);
    gtk_widget_hide(data->about_dialog);

    return TRUE;
}

G_MODULE_EXPORT gboolean on_compress_toggle(GtkWidget *widget, gtk_widgets_t *data)
{
    compress = gtk_check_menu_item_get_active((GtkCheckMenuItem *)data->compress_menu_item);
    log_message(LOG_VERBOSE, _("Compression is now %s"), compress ? "on" : "off");

    update_config(CONF_COMPRESS, compress ? CONF_TRUE : CONF_FALSE);

    return TRUE;
}
