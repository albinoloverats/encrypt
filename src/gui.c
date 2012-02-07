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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>

#include "encrypt.h"
#include "gui.h"

#include "main.h"

#include "common/common.h"
#include "common/logging.h"

static void check_enable_encrypt_button(gtk_widgets_t *data);

static void *bg_thread_gui(void *n);

static bool encrypting = true;

G_MODULE_EXPORT gboolean file_chooser_callback(GtkWidget *widget, gtk_widgets_t *data)
{
    gtk_widget_set_sensitive(data->key_combo, FALSE);
    gtk_widget_set_sensitive(data->crypto_combo, FALSE);
    gtk_widget_set_sensitive(data->hash_combo, FALSE);
    /*
     * check the source file exists (and is a file)
     */
    char *fname = gtk_file_chooser_get_filename((GtkFileChooser *)data->file_chooser);
    if (!fname)
       return FALSE;
    /*
     * quickly see if the file is encrypted already
     */
    int64_t f = open(fname, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
    if (f < 0)
        return FALSE;
    char *c = NULL, *h = NULL;
    if (file_encrypted(f))
    {
        encrypting = false;
        auto_select_algorithms(data, c, h);
    }
    close(f);
    gtk_button_set_label((GtkButton *)data->encrypt_button, encrypting ? LABEL_ENCRYPT : LABEL_DECRYPT);
    char *odir = gtk_file_chooser_get_filename((GtkFileChooser *)data->out_file_chooser);
    if (!odir)
        return FALSE;
    /*
     * if the destination exists, it has to be a regular file
     */
    char *oname = (char *)gtk_entry_get_text((GtkEntry *)data->out_file_entry);
    if (!oname || !strlen(oname))
        return FALSE;
    char *out_file = NULL;
    asprintf(&out_file, "%s/%s", odir, oname);
    struct stat info;
    if (stat(out_file, &info) == 0 && !S_ISREG(info.st_mode))
    {
        free(out_file);
        return FALSE;
    }
    free(out_file);

    if (encrypting)
    {
        gtk_widget_set_sensitive(data->crypto_combo, TRUE);
        gtk_widget_set_sensitive(data->hash_combo, TRUE);
    }
    gtk_widget_set_sensitive(data->key_combo, TRUE);

    return TRUE;
}

extern void auto_select_algorithms(gtk_widgets_t *data, char *cipher, char *hash)
{
    list_t *ciphers = get_algorithms_crypt();
    uint64_t cc = list_size(ciphers);
    unsigned slctd_cipher = 0;
    for (unsigned i = 0; i < cc; i++)
    {
        char *ct = (char *)list_get(ciphers, i);
        if (cipher && !strcasecmp(ct, cipher))
        {
            slctd_cipher = i + 1;
            log_message(LOG_VERBOSE, "algorithm %s is %d in the list", cipher, slctd_cipher);
        }
        gtk_combo_box_text_append_text((GtkComboBoxText *)data->crypto_combo, ct);
    }
    gtk_combo_box_set_active((GtkComboBox *)data->crypto_combo, slctd_cipher);
    list_delete(&ciphers);

    list_t *hashes = get_algorithms_hash();
    uint64_t hc = list_size(hashes);
    unsigned slctd_hash = 0;
    for (unsigned  i = 0; i < hc; i++)
    {
        char *ht = (char *)list_get(hashes, i);
        if (hash && !strcasecmp(ht, hash))
        {
            slctd_hash = i + 1;
            log_message(LOG_VERBOSE, "algorithm %s is %d in the list", hash, slctd_hash);
        }
        gtk_combo_box_text_append_text((GtkComboBoxText *)data->hash_combo, ht);
    }
    gtk_combo_box_set_active((GtkComboBox *)data->hash_combo, slctd_hash);
    list_delete(&hashes);

    return;
}

G_MODULE_EXPORT gboolean cipher_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data)
{
    check_enable_encrypt_button(data);

    return TRUE;
}

G_MODULE_EXPORT gboolean hash_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data)
{
    check_enable_encrypt_button(data);

    return TRUE;
}

G_MODULE_EXPORT gboolean key_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data)
{
    switch (gtk_combo_box_get_active(combo_box))
    {
        case KEYFILE:
            gtk_widget_set_sensitive(data->password_entry, FALSE);
            gtk_widget_set_sensitive(data->key_chooser, TRUE);
            gtk_widget_show(data->key_chooser);
            gtk_widget_hide(data->password_entry);
            break;

        case PASSWORD:
            gtk_widget_set_sensitive(data->key_chooser, FALSE);
            gtk_widget_set_sensitive(data->password_entry, TRUE);
            gtk_widget_show(data->password_entry);
            gtk_widget_hide(data->key_chooser);
            break;

        default:
            gtk_widget_set_sensitive(data->password_entry, FALSE);
            gtk_widget_set_sensitive(data->key_chooser, FALSE);
    }
    check_enable_encrypt_button(data);

    return TRUE;
}

G_MODULE_EXPORT gboolean password_entry_callback(GtkComboBox *password_entry, gtk_widgets_t *data)
{
    check_enable_encrypt_button(data);

    return TRUE;
}

G_MODULE_EXPORT gboolean key_chooser_callback(GtkFileChooser *file_chooser, gtk_widgets_t *data)
{
    check_enable_encrypt_button(data);

    return TRUE;
}

G_MODULE_EXPORT gboolean on_encrypt_button_clicked(GtkButton *button, gtk_widgets_t *data)
{
    log_message(LOG_DEBUG, "show progress dialog");
    gtk_widget_show(data->progress_dialog);
    //gtk_main_iteration();

    pthread_t bgt = bg_thread_initialise(bg_thread_gui, data);

    log_message(LOG_DEBUG, "reset cancel/close buttons");
    gtk_widget_set_sensitive(data->progress_cancel_button, TRUE);
    gtk_widget_show(data->progress_cancel_button);
    gtk_widget_set_sensitive(data->progress_close_button, FALSE);
    gtk_widget_hide(data->progress_close_button);

    log_message(LOG_DEBUG, "reset progress bar");
    gtk_progress_bar_set_fraction((GtkProgressBar *)data->progress_bar, 0.0);
    gtk_progress_bar_set_text((GtkProgressBar *)data->progress_bar, "");

    uint64_t sz = 0;

    log_message(LOG_DEBUG, "update progress bar in loop");
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
    memcpy(&status, r, sizeof( status ));
    free(r);
    log_message(LOG_DEBUG, "bg thread finished with status %d", status);

    update_status_bar(data, status);

    char *msg;
    switch (status)
    {
        case SUCCEEDED:
            gtk_progress_bar_set_fraction((GtkProgressBar *)data->progress_bar, 1.0);
            msg = "Done";
            break;
        case CANCELLED:
            msg = "Cancelled";
            break;
        default:
            msg = "Failed";
            break;
    }
    gtk_progress_bar_set_text((GtkProgressBar *)data->progress_bar, msg);;

    gtk_widget_set_sensitive(data->progress_cancel_button, FALSE);
    gtk_widget_hide(data->progress_cancel_button);
    gtk_widget_set_sensitive(data->progress_close_button, TRUE);
    gtk_widget_show(data->progress_close_button);

    return TRUE;
}

G_MODULE_EXPORT gboolean on_cancel_button_clicked(GtkButton *button, gtk_widgets_t *data)
{
    log_message(LOG_DEBUG, "cancel background thread");
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

    char *fname = gtk_file_chooser_get_filename((GtkFileChooser *)data->file_chooser);
    int64_t source = open(fname, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);

    char *odir = gtk_file_chooser_get_filename((GtkFileChooser *)data->out_file_chooser);
    char *oname = (char *)gtk_entry_get_text((GtkEntry *)data->out_file_entry);
    char *out_file = NULL;
    asprintf(&out_file, "%s/%s", odir, oname);

    int64_t output = open(out_file, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY | F_WRLCK, S_IRUSR | S_IWUSR);

    status_e status = SUCCEEDED;
    void *r = calloc(1, sizeof( status ));

    int key_type = gtk_combo_box_get_active((GtkComboBox *)data->key_combo);
    raw_key_t key = {NULL, 0, NULL, 0};
    switch (key_type)
    {
        case KEYFILE:
            {
                int64_t kf = open(gtk_file_chooser_get_filename((GtkFileChooser *)data->key_chooser), O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
                if (kf < 0)
                {
                    status = FAILED_OTHER;
                    memcpy(r, &status, sizeof( status ));
                    pthread_exit(r);
                    return NULL;
                }
                key.p_length = lseek(kf, 0, SEEK_END);
                key.p_data = malloc(key.p_length);
                if (!key.p_data)
                    die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
                pread(kf, key.p_data, key.p_length, 0);
                close(kf);
            }
            break;

        case PASSWORD:
            key.p_data = (uint8_t *)gtk_entry_get_text((GtkEntry *)data->password_entry);
            key.p_length = strlen((char *)key.p_data);
            break;
    }
    encrypt_t e_data = { NULL, NULL, key, true, false };

    if (encrypting)
    {
        int c = gtk_combo_box_get_active((GtkComboBox *)data->crypto_combo);
        int h = gtk_combo_box_get_active((GtkComboBox *)data->hash_combo);
        list_t *ciphers = get_algorithms_crypt();
        list_t *hashes = get_algorithms_hash();
        e_data.cipher = list_get(ciphers, c - 1); /* subtract 1 to get algorithm offset from combobox */
        e_data.hash = list_get(hashes, h - 1);    /* combobox item 0 is the 'select...' text */
        status = main_encrypt(source, output, e_data);
        list_delete(&ciphers);
        list_delete(&hashes);
    }
    else
        status = main_decrypt(source, output, e_data);

    close(source);
    close(output);

    memcpy(r, &status, sizeof( status ));
    pthread_exit(r);

    return r;
}

G_MODULE_EXPORT gboolean on_about_open(GtkWidget *widget, gtk_widgets_t *data)
{
    gtk_dialog_run((GtkDialog *)data->about_dialog);
    gtk_widget_hide(data->about_dialog);

    return TRUE;
}

static void check_enable_encrypt_button(gtk_widgets_t *data)
{
    int cipher = encrypting ? gtk_combo_box_get_active((GtkComboBox *)data->crypto_combo) : -1;
    int hash = encrypting ? gtk_combo_box_get_active((GtkComboBox *)data->hash_combo) : -1;

    int key = gtk_combo_box_get_active((GtkComboBox *)data->key_combo);
    char *key_data = NULL;
    switch (key)
    {
        case KEYFILE:
            key_data = gtk_file_chooser_get_filename((GtkFileChooser *)data->key_chooser);
            break;
        case PASSWORD:
            key_data = (char *)gtk_entry_get_text((GtkEntry *)data->password_entry);
            break;
    }

    if (cipher != 0 && hash != 0 && key && key_data && strlen(key_data))
    {
        gtk_widget_set_sensitive(data->encrypt_button, TRUE);
        gtk_widget_grab_default(data->encrypt_button);
    }
    else
        gtk_widget_set_sensitive(data->encrypt_button, FALSE);
    return;
}
