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

#ifndef _ENCRYPT_GUI_GTK_H_
#define _ENCRYPT_GUI_GTK_H_

#include <gtk/gtk.h>

/* Convenience macros for obtaining objects from UI file */
#define CH_GET_OBJECT( builder, name, type, data )  data->name = type( gtk_builder_get_object( builder, #name ) )
#define CH_GET_WIDGET( builder, name, data )        CH_GET_OBJECT( builder, name, GTK_WIDGET, data )

#ifndef _WIN32
    #if defined __DEBUG__ || defined __DEBUG_GUI__
        #define GLADE_UI_FILE "utils/encrypt.glade"
    #else
        #define GLADE_UI_FILE "/usr/share/encrypt/" "encrypt.glade"
    #endif
#else
    #define GLADE_UI_FILE "utils\\encrypt_w32.glade"
#endif

#define LABEL_ENCRYPT "Encrypt"
#define LABEL_DECRYPT "Decrypt"

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
    GtkWidget *key_combo;
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
}
gtk_widgets_t;

G_MODULE_EXPORT gboolean file_dialog_display(GtkButton *button, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean file_dialog_okay(GtkButton *button, gtk_widgets_t *data);

extern void auto_select_algorithms(gtk_widgets_t *data, char *cipher, char *hash);

G_MODULE_EXPORT gboolean algorithm_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean key_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean password_entry_callback(GtkComboBox *password_entry, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean key_dialog_okay(GtkFileChooser *file_chooser, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean on_encrypt_button_clicked(GtkButton *button, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean on_cancel_button_clicked(GtkButton *button, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean on_close_button_clicked(GtkButton *button, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean on_about_open(GtkWidget *widget, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean on_compress_toggle(GtkWidget *widget, gtk_widgets_t *data);

extern char *gtk_file_hack_cipher;
extern char *gtk_file_hack_hash;

#endif /* _ENCRYPT_GUI_GTK_H_ */
