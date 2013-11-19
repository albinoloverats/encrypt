/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2013, albinoloverats ~ Software Development
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

#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#include <sys/time.h>
#include <math.h>
#include <sys/stat.h>
#include <pthread.h>
#include <libgen.h>

#include "gui.h"
#include "gui-gtk.h"

#include "common/common.h"
#include "common/error.h"
#include "common/logging.h"
#include "common/version.h"

#ifdef _WIN32
    #include "common/win32_ext.h"
#endif

#include "init.h"
#include "crypto.h"
#include "encrypt.h"
#include "decrypt.h"
#include "cli.h"

#define _filename_utf8(A) g_filename_to_utf8(A, -1, NULL, NULL, NULL)

#define NONE_SELECTED "(None)"

typedef enum
{
    KEY_NONE,
    KEY_FILE,
    KEY_PASSWORD
}
key_type_e;

/*
 * FIXME There has to be a way to make gtk_file_chooser_set_filename
 * work correctly
 */
char *gui_file_hack_source = NULL;
char *gui_file_hack_output = NULL;

static void key_dialog_okay(gtk_widgets_t *data);

inline static void set_progress_bar(GtkProgressBar *, float);
inline static void set_progress_button(GtkButton *, bool);

static void *gui_process(void *);
inline static void gui_display(crypto_t *, gtk_widgets_t *);

static gboolean _files = false;
static bool _encrypted = false;
static bool _compress = true;
static bool _follow = false;
static version_e _version = VERSION_CURRENT;
static crypto_status_e *_status = NULL;

extern void auto_select_algorithms(gtk_widgets_t *data, char *cipher, char *hash)
{
    const char **ciphers = list_of_ciphers();
    unsigned slctd_cipher = 0;
    for (unsigned i = 0; ciphers[i]; i++)
    {
        if (cipher && !strcasecmp(ciphers[i], cipher))
        {
            slctd_cipher = i + 1;
            log_message(LOG_VERBOSE, _("Selected %d is algorithm: %s"), slctd_cipher, cipher);
        }
#ifndef _WIN32
        gtk_combo_box_text_append_text((GtkComboBoxText *)data->crypto_combo, ciphers[i]);
#else
        gtk_combo_box_append_text((GtkComboBox *)data->crypto_combo, ciphers[i]);
#endif
    }
    gtk_combo_box_set_active((GtkComboBox *)data->crypto_combo, slctd_cipher);

    const char **hashes = list_of_hashes();
    unsigned slctd_hash = 0;
    for (unsigned  i = 0; hashes[i]; i++)
    {
        if (hash && !strcasecmp(hashes[i], hash))
        {
            slctd_hash = i + 1;
            log_message(LOG_VERBOSE, _("Selected %d is hash: %s"), slctd_hash, hash);
        }
#ifndef _WIN32
        gtk_combo_box_text_append_text((GtkComboBoxText *)data->hash_combo, hashes[i]);
#else
        gtk_combo_box_append_text((GtkComboBox *)data->hash_combo, hashes[i]);
#endif
    }
    gtk_combo_box_set_active((GtkComboBox *)data->hash_combo, slctd_hash);

    return;
}

extern void set_compatibility_menu(gtk_widgets_t *data, char *version)
{
    GSList *g = NULL;
    version_e v = parse_version(version);
    for (version_e i = VERSION_CURRENT; i > VERSION_UNKNOWN; i--)
    {
        const char *t = get_version_string(i);
        GtkWidget *m = gtk_radio_menu_item_new_with_label(g, t);
        g = gtk_radio_menu_item_get_group((GtkRadioMenuItem *)m);
        gtk_menu_shell_append((GtkMenuShell *)data->compat_menu, m);
        g_signal_connect(G_OBJECT(m), "toggled", G_CALLBACK(on_compatibility_change), data);
        gtk_widget_show(m);
        if (i == v || i == VERSION_CURRENT)
        {
            gtk_check_menu_item_set_active((GtkCheckMenuItem *)m, TRUE);
            _version = i;
            if (i != VERSION_CURRENT)
                log_message(LOG_VERBOSE, _("Compatibility version: %s"), t);
        }
    }

    return;
}

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

    switch (gtk_dialog_run(d))
    {
        case GTK_RESPONSE_DELETE_EVENT:
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
            break;

        case GTK_RESPONSE_ACCEPT:
        case GTK_RESPONSE_OK:
            if (a)
                file_dialog_okay(button, data);
            else
                key_dialog_okay(data);
            break;
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
        open_file = gui_file_hack_source;
    if (open_file) /* if at first you don't succeed, try, try again */
        open_file = _filename_utf8(open_file);
    if (!open_file || !strlen(open_file))
        en = FALSE;
    else
    {
        struct stat s;
        stat(open_file, &s);
        if (S_ISREG(s.st_mode) || S_ISDIR(s.st_mode))
        {
            gtk_label_set_text((GtkLabel *)data->open_file_label, basename(open_file));
            gtk_widget_show(data->open_file_image);
            /*
             * quickly see if the file is encrypted already
             */
            char *c = NULL, *h = NULL;
            if ((_encrypted = is_encrypted(open_file, &c, &h)))
                auto_select_algorithms(data, c, h);
            gtk_button_set_label((GtkButton *)data->encrypt_button, _encrypted ? LABEL_DECRYPT : LABEL_ENCRYPT);
            en = TRUE;
        }
        else
            en = FALSE;
    }
    if (open_file)
        g_free(open_file);

    char *save_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->save_dialog);
    if (!save_file)
        save_file = gui_file_hack_output;
    if (save_file)
        save_file = _filename_utf8(save_file);
    if (!save_file || !strlen(save_file))
        en = FALSE;
    else
    {
        struct stat s;
        stat(save_file, &s);
        /*
         * if the destination exists, it has to be a regular file
         */
        if (errno == ENOENT || S_ISREG(s.st_mode) || S_ISDIR(s.st_mode))
        {
            gtk_label_set_text((GtkLabel *)data->save_file_label, basename(save_file));
            gtk_widget_show(data->save_file_image);
        }
        else
            en = FALSE;
    }
    if (save_file)
        g_free(save_file);

    _files = en;

    if (_encrypted)
        gtk_widget_set_sensitive(data->key_combo, en);
    else
    {
        gtk_widget_set_sensitive(data->crypto_combo, en);
        gtk_widget_set_sensitive(data->hash_combo, en);
        if (en)
            algorithm_combo_callback(NULL, data);
    }

    return TRUE;
}

G_MODULE_EXPORT gboolean algorithm_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data)
{
    int cipher = gtk_combo_box_get_active((GtkComboBox *)data->crypto_combo);
    int hash = gtk_combo_box_get_active((GtkComboBox *)data->hash_combo);

    gboolean en = _files;

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
        case KEY_FILE:
            gtk_widget_set_sensitive(data->password_entry, FALSE);
            gtk_widget_set_sensitive(data->key_button, TRUE);
            gtk_widget_hide(data->password_entry);
            gtk_widget_show(data->key_button);
            key_dialog_okay(data);
            break;

        case KEY_PASSWORD:
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

static void key_dialog_okay(gtk_widgets_t *data)
{
    bool en = true;

    char *key_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->key_dialog);
    if (key_file)
        key_file = _filename_utf8(key_file);
    if (!key_file || !strlen(key_file))
        en = false;
    else
    {
        struct stat s;
        stat(key_file, &s);
        if (errno == ENOENT || !S_ISREG(s.st_mode))
            en = false;
    }

    gtk_label_set_text((GtkLabel *)data->key_file_label, en ? basename(key_file) : NONE_SELECTED);

    if (key_file)
        g_free(key_file);

    if (en)
        gtk_widget_show(data->key_file_image);
    else
        gtk_widget_hide(data->key_file_image);

    gtk_widget_set_sensitive(data->encrypt_button, en);
    if (en)
        gtk_widget_grab_default(data->encrypt_button);

    return;
}

G_MODULE_EXPORT gboolean on_encrypt_button_clicked(GtkButton *button, gtk_widgets_t *data)
{
    gtk_widget_show(data->progress_dialog);

    set_progress_button((GtkButton *)data->progress_cancel_button, true);
    set_progress_button((GtkButton *)data->progress_close_button, false);
    set_progress_bar((GtkProgressBar *)data->progress_bar_total, 0.0f);
    set_progress_bar((GtkProgressBar *)data->progress_bar_current, 0.0f);
    gtk_widget_show(data->progress_bar_current);

    gui_process(data);

    return TRUE;
}

G_MODULE_EXPORT gboolean on_progress_button_clicked(GtkButton *button, gtk_widgets_t *data)
{
    if (_status && (*_status == STATUS_INIT || *_status == STATUS_RUNNING))
        *_status = STATUS_CANCELLED;
    else
        gtk_widget_hide(data->progress_dialog);

    return TRUE;
}

G_MODULE_EXPORT gboolean on_about_open(GtkWidget *widget, gtk_widgets_t *data)
{
    if (new_version_available)
    {
        char *text = NULL;
        asprintf(&text, NEW_VERSION_OF_AVAILABLE, APP_NAME);
        gtk_label_set_text((GtkLabel *)data->about_new_version_label, text);
        free(text);
    }
    gtk_dialog_run((GtkDialog *)data->about_dialog);
    gtk_widget_hide(data->about_dialog);

    return TRUE;
}

G_MODULE_EXPORT gboolean on_compress_toggle(GtkWidget *widget, gtk_widgets_t *data)
{
    _compress = gtk_check_menu_item_get_active((GtkCheckMenuItem *)data->compress_menu_item);
    update_config(CONF_COMPRESS, _compress ? CONF_TRUE : CONF_FALSE);

    return TRUE;
}

G_MODULE_EXPORT gboolean on_follow_toggle(GtkWidget *widget, gtk_widgets_t *data)
{
    _follow = gtk_check_menu_item_get_active((GtkCheckMenuItem *)data->follow_menu_item);
    update_config(CONF_FOLLOW, _follow ? CONF_TRUE : CONF_FALSE);

    return TRUE;
}

G_MODULE_EXPORT gboolean on_compatibility_change(GtkWidget *widget, gtk_widgets_t *data)
{
    _version = parse_version(gtk_menu_item_get_label((GtkMenuItem *)widget));
    update_config(CONF_VERSION, get_version_string(_version));

    return TRUE;
}

extern void set_status_bar(GtkStatusbar *status_bar, const char *status)
{
    static int ctx = -1;
    if (ctx != -1)
        gtk_statusbar_pop(status_bar, ctx);
    ctx = gtk_statusbar_get_context_id(status_bar, status);
    gtk_statusbar_push(status_bar, ctx, status);

    return;
}

inline static void set_progress_bar(GtkProgressBar *progress_bar, float percent)
{
    gtk_progress_bar_set_fraction(progress_bar, (double)percent / PERCENT);
    char *pc = NULL;
    asprintf(&pc, "%3.0f %%", percent);
    gtk_progress_bar_set_text(progress_bar, pc);
    free(pc);

    return;
}

inline static void set_progress_button(GtkButton *button, bool on)
{
    gtk_widget_set_sensitive((GtkWidget *)button, on);
    if (on)
        gtk_widget_show((GtkWidget *)button);
    else
        gtk_widget_hide((GtkWidget *)button);

    return;
}

static void *gui_process(void *d)
{
    gtk_widgets_t *data = d;

    log_message(LOG_EVERYTHING, _("Initialise crypto routine"));
    char *source = _filename_utf8(gtk_file_chooser_get_filename((GtkFileChooser *)data->open_dialog));
    char *output = _filename_utf8(gtk_file_chooser_get_filename((GtkFileChooser *)data->save_dialog));

    uint8_t *key = NULL;
    size_t length = 0;
    switch (gtk_combo_box_get_active((GtkComboBox *)data->key_combo))
    {
        case KEY_FILE:
            key = (uint8_t *)strdup(_filename_utf8(gtk_file_chooser_get_filename((GtkFileChooser *)data->key_dialog)));
            length = 0;
            break;

        case KEY_PASSWORD:
            key = (uint8_t *)strdup(gtk_entry_get_text((GtkEntry *)data->password_entry));
            length = strlen((char *)key);
            break;
    }

    crypto_t *x;
    if (_encrypted)
        x = decrypt_init(source, output, key, length);
    else
    {
        int c = gtk_combo_box_get_active((GtkComboBox *)data->crypto_combo);
        int h = gtk_combo_box_get_active((GtkComboBox *)data->hash_combo);
        const char **ciphers = list_of_ciphers();
        const char **hashes = list_of_hashes();
        x = encrypt_init(source, output, ciphers[c - 1], hashes[h - 1], key, length, _compress, _follow, _version);
    }

    _status = &x->status;

    free(key);

    if (x->status == STATUS_INIT)
        execute(x);

    gui_display(x, data);

    if (x->status == STATUS_SUCCESS)
    {
        set_progress_bar((GtkProgressBar *)data->progress_bar_total, PERCENT);
        set_progress_bar((GtkProgressBar *)data->progress_bar_current, PERCENT);
    }

    set_status_bar((GtkStatusbar *)data->status_bar, status(x));

    set_progress_button((GtkButton *)data->progress_cancel_button, false);
    set_progress_button((GtkButton *)data->progress_close_button, true);

    deinit(&x);

    return NULL;
}

inline static void gui_display(crypto_t *c, gtk_widgets_t *data)
{
    log_message(LOG_EVERYTHING, _("Update progress bar in loop"));

    bps_t bps[BPS];
    memset(bps, 0x00, BPS * sizeof( bps_t ));
    int b = 0;

    while (c->status == STATUS_INIT || c->status == STATUS_RUNNING)
    {
        gtk_main_iteration_do(FALSE);

#ifndef _WIN32
        struct timespec s = { 0, MILLION };
        nanosleep(&s, NULL);
#else
        Sleep(1);
#endif

        if (c->status == STATUS_INIT)
            continue;

        float pc = (PERCENT * c->total.offset + PERCENT * c->current.offset / c->current.size) / c->total.size;
        if (c->total.offset == c->total.size)
            pc = PERCENT * c->total.offset / c->total.size;
        set_progress_bar((GtkProgressBar *)data->progress_bar_total, pc);

        if (c->total.size == 1)
            gtk_widget_hide(data->progress_bar_current);
        else
            set_progress_bar((GtkProgressBar *)data->progress_bar_current, PERCENT * c->current.offset / c->current.size);

        struct timeval tv;
        gettimeofday(&tv, NULL);
        bps[b].time = tv.tv_sec * MILLION + tv.tv_usec;
        bps[b].bytes = c->current.offset;
        float val = cli_calc_bps(bps);
        b++;
        if (b >= BPS)
            b = 0;

        char *bps_label = NULL;
        if (isnan(val) || val == 0.0f)
            asprintf(&bps_label, "---.- B/s");
        else
        {
            if (val < THOUSAND)
                asprintf(&bps_label, "%5.1f B/s", val);
            else if (val < MILLION)
                asprintf(&bps_label, "%5.1f KB/s", val / KILOBYTE);
            else if (val < THOUSAND_MILLION)
                asprintf(&bps_label, "%5.1f MB/s", val / MEGABYTE);
            else if (val < BILLION)
                asprintf(&bps_label, "%5.1f GB/s", val / GIGABYTE);
            else
                asprintf(&bps_label, "---.- B/s");
                //asprintf(&bps_label, "%5.1f TB/s", val / TERABYTE);
        }
        fprintf(stderr, "\r%s", bps_label);
        gtk_label_set_text((GtkLabel *)data->progress_label, bps_label);
        free(bps_label);
    }

    return;
}
