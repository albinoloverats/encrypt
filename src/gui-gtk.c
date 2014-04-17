/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
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

/*
 * FIXME There has to be a way to make gtk_file_chooser_set_filename
 * work correctly
 */
char *gui_file_hack_source = NULL;
char *gui_file_hack_output = NULL;
static char *cwd = NULL;

inline static void set_progress_bar(GtkProgressBar *, float);
inline static void set_progress_button(GtkButton *, bool);

static void *gui_process(void *);
inline static void gui_display(crypto_t *, gtk_widgets_t *);

static gboolean _files = false;
static bool _encrypted = false;
static bool _compress = true;
static bool _follow = false;
static key_source_e _key_source = KEY_SOURCE_PASSWORD;
static version_e _version = VERSION_CURRENT;
static crypto_status_e *_status = NULL;

extern void auto_select_algorithms(gtk_widgets_t *data, char *cipher, char *hash, char *mode)
{
    const char **ciphers = list_of_ciphers();
    unsigned slctd_cipher = 0;
#ifndef _WIN32
    gtk_combo_box_text_remove_all((GtkComboBoxText *)data->crypto_combo);
#else
    for (unsigned i = 0; ciphers[i]; i++)
        gtk_combo_box_remove_text((GtkComboBox *)data->crypto_combo, 0);
#endif
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
#ifndef _WIN32
    gtk_combo_box_text_remove_all((GtkComboBoxText *)data->hash_combo);
#else
    for (unsigned i = 0; hashes[i]; i++)
        gtk_combo_box_remove_text((GtkComboBox *)data->hash_combo, 0);
#endif
    for (unsigned i = 0; hashes[i]; i++)
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

    const char **modes = list_of_modes();
    unsigned slctd_mode = 0;
#ifndef _WIN32
    gtk_combo_box_text_remove_all((GtkComboBoxText *)data->mode_combo);
#else
    for (unsigned i = 0; modes[i]; i++)
        gtk_combo_box_remove_text((GtkComboBox *)data->mode_combo, 0);
#endif
    for (unsigned i = 0; modes[i]; i++)
    {
        if (mode && !strcasecmp(modes[i], mode))
        {
            slctd_mode = i + 1;
            log_message(LOG_VERBOSE, _("Selected %d is mode: %s"), slctd_mode, mode);
        }
#ifndef _WIN32
        gtk_combo_box_text_append_text((GtkComboBoxText *)data->mode_combo, modes[i]);
#else
        gtk_combo_box_append_text((GtkComboBox *)data->mode_combo, modes[i]);
#endif
    }
    gtk_combo_box_set_active((GtkComboBox *)data->mode_combo, slctd_mode);

    return;
}

extern void set_key_source_menu(gtk_widgets_t *data, key_source_e source)
{
    switch (source)
    {
        case KEY_SOURCE_FILE:
            gtk_check_menu_item_set_active((GtkCheckMenuItem *)data->key_file_menu_item, TRUE);
            gtk_check_menu_item_set_active((GtkCheckMenuItem *)data->key_password_menu_item, FALSE);
            break;
        case KEY_SOURCE_PASSWORD:
            gtk_check_menu_item_set_active((GtkCheckMenuItem *)data->key_file_menu_item, FALSE);
            gtk_check_menu_item_set_active((GtkCheckMenuItem *)data->key_password_menu_item, TRUE);
            break;
    }
    log_message(LOG_VERBOSE, _("Set key source: %s"), KEY_SOURCE[source]);
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

    if (!cwd)
        cwd = strdup(getenv("HOME"));
    gtk_file_chooser_set_current_folder((GtkFileChooser *)d, cwd);

    switch (gtk_dialog_run(d))
    {
        case GTK_RESPONSE_DELETE_EVENT:
            gtk_label_set_text(l, NONE_SELECTED);
            gtk_widget_hide(i);

            if (a)
            {
                gtk_widget_set_sensitive(data->crypto_combo, FALSE);
                gtk_widget_set_sensitive(data->hash_combo, FALSE);
                gtk_widget_set_sensitive(data->mode_combo, FALSE);
                gtk_widget_set_sensitive(data->key_button, FALSE);
            }
            gtk_widget_set_sensitive(data->encrypt_button, FALSE);
            break;

#if 0 /* not yet fully implemented (because I don't like the resulting workflow) */
        case GTK_RESPONSE_ACCEPT:
        case GTK_RESPONSE_OK:
            if (a)
                file_dialog_okay(button, data);
            else
                key_dialog_okay(data);
            break;
#endif
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
            char *c = NULL, *h = NULL, *m = NULL;
            if ((_encrypted = is_encrypted(open_file, &c, &h, &m)))
                auto_select_algorithms(data, c, h, m);
            gtk_button_set_label((GtkButton *)data->encrypt_button, _encrypted ? LABEL_DECRYPT : LABEL_ENCRYPT);
            en = TRUE;
            asprintf(&cwd, "%s", open_file);
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
            asprintf(&cwd, "%s", save_file);
        }
        else
            en = FALSE;
    }
    if (save_file)
        g_free(save_file);

    _files = en;

    if (_encrypted)
    {
        gtk_widget_set_sensitive(data->crypto_combo, FALSE);
        gtk_widget_set_sensitive(data->hash_combo, FALSE);
        gtk_widget_set_sensitive(data->mode_combo, FALSE);
        gtk_widget_set_sensitive(data->password_entry, en);
        gtk_widget_set_sensitive(data->key_button, en);
    }
    else
    {
        gtk_widget_set_sensitive(data->crypto_combo, en);
        gtk_widget_set_sensitive(data->hash_combo, en);
        gtk_widget_set_sensitive(data->mode_combo, en);
        if (en)
            algorithm_combo_callback(NULL, data);
    }

    return (void)button, TRUE;
}

G_MODULE_EXPORT gboolean algorithm_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data)
{
    int cipher = gtk_combo_box_get_active((GtkComboBox *)data->crypto_combo);
    int hash = gtk_combo_box_get_active((GtkComboBox *)data->hash_combo);
    int mode = gtk_combo_box_get_active((GtkComboBox *)data->mode_combo);

    gboolean en = _files;

    if (cipher && hash && mode)
    {
        const char **ciphers = list_of_ciphers();
        const char **hashes = list_of_hashes();
        const char **modes = list_of_modes();

        if (cipher > 0)
            update_config(CONF_CIPHER, ciphers[cipher - 1]);
        if (hash > 0)
            update_config(CONF_HASH, hashes[hash - 1]);
        if (mode > 0)
            update_config(CONF_MODE, modes[mode - 1]);

    }
    else
        en = FALSE;

    gtk_widget_set_sensitive(data->password_entry, en);
    gtk_widget_set_sensitive(data->key_button, en);

    return (void)combo_box, TRUE;
}

G_MODULE_EXPORT gboolean on_key_source_change(GtkWidget *widget, gtk_widgets_t *data)
{
    if (widget == data->key_file_menu_item)
        _key_source = KEY_SOURCE_FILE;
    else if (widget == data->key_password_menu_item)
        _key_source = KEY_SOURCE_PASSWORD;
    update_config(CONF_KEY, KEY_SOURCE[_key_source]);

    gtk_widget_hide(_key_source == KEY_SOURCE_PASSWORD ? data->key_button : data->password_entry);
    gtk_widget_show(_key_source == KEY_SOURCE_PASSWORD ? data->password_entry : data->key_button);

    log_message(LOG_EVERYTHING, _("Set key source: %s"), KEY_SOURCE[_key_source]);

    return (void)data, TRUE;
}

G_MODULE_EXPORT gboolean password_entry_callback(GtkComboBox *password_entry, gtk_widgets_t *data)
{
    char *key_data = (char *)gtk_entry_get_text((GtkEntry *)password_entry);

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

    char *key_file = gtk_file_chooser_get_filename((GtkFileChooser *)file_chooser);
    if (key_file)
        key_file = _filename_utf8(key_file);
    if (!key_file || !strlen(key_file))
        en = FALSE;
    else
    {
        struct stat s;
        stat(key_file, &s);
        if (errno == ENOENT || !S_ISREG(s.st_mode))
            en = FALSE;
        else
            asprintf(&cwd, "%s", key_file);
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

    return TRUE;
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

    return (void)button, TRUE;
}

G_MODULE_EXPORT gboolean on_progress_button_clicked(GtkButton *button, gtk_widgets_t *data)
{
    if (_status && (*_status == STATUS_INIT || *_status == STATUS_RUNNING))
        *_status = STATUS_CANCELLED;
    else
        gtk_widget_hide(data->progress_dialog);

    return (void)button, TRUE;
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

    return (void)widget, TRUE;
}

G_MODULE_EXPORT gboolean on_compress_toggle(GtkWidget *widget, gtk_widgets_t *data)
{
    _compress = gtk_check_menu_item_get_active((GtkCheckMenuItem *)widget);
    update_config(CONF_COMPRESS, _compress ? CONF_TRUE : CONF_FALSE);

    log_message(LOG_EVERYTHING, _("Set compression: %s"), _compress ? _("on") : _("off"));

    return (void)data, TRUE;
}

G_MODULE_EXPORT gboolean on_follow_toggle(GtkWidget *widget, gtk_widgets_t *data)
{
    _follow = gtk_check_menu_item_get_active((GtkCheckMenuItem *)widget);
    update_config(CONF_FOLLOW, _follow ? CONF_TRUE : CONF_FALSE);

    log_message(LOG_EVERYTHING, _("Set link traversal: %s"), _follow ? _("on") : _("off"));

    return (void)data, TRUE;
}

G_MODULE_EXPORT gboolean on_compatibility_change(GtkWidget *widget, gtk_widgets_t *data)
{
    _version = parse_version(gtk_menu_item_get_label((GtkMenuItem *)widget));
    const char *v = get_version_string(_version);
    update_config(CONF_VERSION, v);

    log_message(LOG_EVERYTHING, _("Set link compatibility: %s"), v);

    return (void)data, TRUE;
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
    switch (_key_source)
    {
        case KEY_SOURCE_FILE:
            key = (uint8_t *)strdup(_filename_utf8(gtk_file_chooser_get_filename((GtkFileChooser *)data->key_dialog)));
            length = 0;
            break;

        case KEY_SOURCE_PASSWORD:
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
        int m = gtk_combo_box_get_active((GtkComboBox *)data->mode_combo);
        const char **ciphers = list_of_ciphers();
        const char **hashes = list_of_hashes();
        const char **modes = list_of_modes();
        x = encrypt_init(source, output, ciphers[c - 1], hashes[h - 1], modes[m - 1], key, length, _compress, _follow, _version);
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
        gtk_label_set_text((GtkLabel *)data->progress_label, bps_label);
        free(bps_label);
    }

    return;
}
