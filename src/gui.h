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

#ifndef _GUI_H_
#define _GUI_H_

#include <gtk/gtk.h>

/* Convenience macros for obtaining objects from UI file */
#define CH_GET_OBJECT( builder, name, type, data )  data->name = type( gtk_builder_get_object( builder, #name ) )
#define CH_GET_WIDGET( builder, name, data )        CH_GET_OBJECT( builder, name, GTK_WIDGET, data )

#if !defined _WIN32
    #if defined __DEBUG__ || defined __DEBUG_GUI__
        #define GLADE_UI_FILE "utils/encrypt.glade"
    #else
        #define GLADE_UI_FILE "/usr/share/encrypt/" "encrypt.glade"
    #endif
#else
    #if defined __DEBUG__ || defined __DEBUG_GUI__
        #define GLADE_UI_FILE "utils/encrypt_w32.glade"
    #else
        #define GLADE_UI_FILE "encrypt_w32.glade"
    #endif
#endif

#define LABEL_ENCRYPT "Encrypt"
#define LABEL_DECRYPT "Decrypt"

#define STATUS_NEW_VERSION "A new version of encrypt is available!"
#define STATUS_READY "Ready"

typedef struct gtk_widgets_t
{
    GtkWidget *main_window;
    GtkWidget *file_chooser;
    GtkWidget *out_file_chooser;
    GtkWidget *out_file_entry;
    GtkWidget *crypto_combo;
    GtkWidget *hash_combo;
    GtkWidget *key_combo;
    GtkWidget *password_entry;
    GtkWidget *key_chooser;
    GtkWidget *encrypt_button;
    GtkWidget *status_bar;
    GtkWidget *progress_dialog;
    GtkWidget *progress_bar;
    GtkWidget *progress_cancel_button;
    GtkWidget *progress_close_button;
    GtkWidget *about_dialog;
    GtkWidget *compress_menu_item;
}
gtk_widgets_t;

G_MODULE_EXPORT gboolean file_chooser_callback(GtkWidget *widget, gtk_widgets_t *data);

extern void auto_select_algorithms(gtk_widgets_t *data, char *cipher, char *hash);

G_MODULE_EXPORT gboolean cipher_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean hash_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean key_combo_callback(GtkComboBox *combo_box, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean password_entry_callback(GtkComboBox *password_entry, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean key_chooser_callback(GtkFileChooser *file_chooser, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean on_encrypt_button_clicked(GtkButton *button, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean on_cancel_button_clicked(GtkButton *button, gtk_widgets_t *data);
G_MODULE_EXPORT gboolean on_close_button_clicked(GtkButton *button, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean on_about_open(GtkWidget *widget, gtk_widgets_t *data);

G_MODULE_EXPORT gboolean on_compress_toggle(GtkWidget *widget, gtk_widgets_t *data);

extern void update_status_bar(gtk_widgets_t *data, int64_t status);

#endif /* _GUI_H_ */
