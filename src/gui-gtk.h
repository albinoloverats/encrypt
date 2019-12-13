/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2020, albinoloverats ~ Software Development
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

#ifndef _ENCRYPT_GUI_GTK_H_
#define _ENCRYPT_GUI_GTK_H_

#include <gtk/gtk.h>

#include "init.h"

#if !defined _WIN32 && !defined __FreeBSD__
	#define GLADE_UI_FILE_DEFAULT "/usr/share/encrypt/encrypt.glade"
	#define GLADE_UI_FILE_BACKUP  "etc/encrypt.glade"
#elif defined __FreeBSD__
	#define GLADE_UI_FILE_DEFAULT "/usr/local/share/encrypt/encrypt.glade"
	#define GLADE_UI_FILE_BACKUP  "etc/encrypt.glade"
#else
	#define GLADE_UI_FILE_DEFAULT "encrypt\\etc\\encrypt_win.glade"
	#define GLADE_UI_FILE_BACKUP  "etc\\encrypt_win.glade"
#endif

typedef struct gtk_widgets_t
{
	GtkWidget *main_window;
	GtkWidget *open_button;
	GtkWidget *open_dialog;
	GtkWidget *open_file_label;
	GtkWidget *open_file_image;
	GtkWidget *save_button;
	GtkWidget *save_dialog;
	GtkWidget *save_file_label;
	GtkWidget *save_file_image;
	GtkWidget *crypto_combo;
	GtkWidget *hash_combo;
	GtkWidget *mode_combo;
	GtkWidget *mac_combo;
	GtkWidget *kdf_spinner;
	GtkWidget *kdf_iterations;
	GtkWidget *password_entry;
	GtkWidget *key_button;
	GtkWidget *key_dialog;
	GtkWidget *key_file_label;
	GtkWidget *key_file_image;
	GtkWidget *encrypt_button;
	GtkWidget *status_bar;
	GtkWidget *progress_dialog;
	GtkWidget *progress_bar_total;
	GtkWidget *progress_bar_current;
	GtkWidget *progress_label;
	GtkWidget *progress_cancel_button;
	GtkWidget *progress_close_button;
	GtkWidget *about_dialog;
	GtkWidget *about_new_version_label;
	GtkWidget *compress_menu_item;
	GtkWidget *follow_menu_item;
	GtkWidget *raw_menu_item;
	GtkWidget *compat_menu;
	GtkWidget *key_file_menu_item;
	GtkWidget *key_password_menu_item;
	GtkWidget *raw_encrypt_button;
	GtkWidget *raw_decrypt_button;
	GtkWidget *abort_dialog;
	GtkWidget *abort_button;
	GtkWidget *abort_message;
}
gtk_widgets_t;

extern void auto_select_algorithms(gtk_widgets_t *data, char *cipher, char *hash, char *mode, char *mac, uint64_t iter);
extern void set_compatibility_menu(gtk_widgets_t *data, char *version);
extern void set_key_source_menu(gtk_widgets_t *data, key_source_e source);

G_MODULE_EXPORT gboolean file_dialog_display(GtkButton *button, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean file_dialog_okay(GtkButton *button, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean algorithm_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean on_key_source_change(GtkWidget *widget, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean password_entry_callback(GtkComboBox *password_entry, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean key_dialog_okay(GtkFileChooser *file_chooser, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean on_encrypt_button_clicked(GtkButton *button, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean on_progress_button_clicked(GtkButton *button, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean on_about_open(GtkWidget *widget, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean on_compress_toggle(GtkWidget *widget, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean on_follow_toggle(GtkWidget *widget, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean on_compatibility_change(GtkWidget *widget, gtk_widgets_t *data);

extern void set_raw_buttons(gtk_widgets_t *, bool);
extern void set_status_bar(GtkStatusbar *status_bar, const char *status);

#endif /* _ENCRYPT_GUI_GTK_H_ */
