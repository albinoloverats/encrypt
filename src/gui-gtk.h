/*
 * encrypt ~ a simple, multi-OS encryption utility
 * Copyright © 2005-2026, albinoloverats ~ Software Development
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

#if !defined _ENCRYPT_GUI_GTK_H_
#define _ENCRYPT_GUI_GTK_H_

/*!
 * \file    gui-gtk.h
 * \brief   GTK widget state and callbacks for the graphical interface
 */

#include <gtk/gtk.h>

// submodule include
#include "src/config.h"

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

/*!
 * \brief GTK widgets used by the encrypt/decrypt interface and callbacks
 */
typedef struct gtk_widgets_s
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
	GtkWidget *about_dialog;
	GtkWidget *about_version_build_info;
	GtkWidget *build_info_text_buffer;
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
gtk_widgets_s;

/*!
 * \brief Populate algorithm selectors and select supplied settings
 * \param[in] data  GUI widget state
 * \param[in] cipher Cipher name to select, or NULL for the placeholder
 * \param[in] hash   Hash name to select, or NULL for the placeholder
 * \param[in] mode   Cipher mode to select, or NULL for the placeholder
 * \param[in] mac    MAC name to select, or NULL for the placeholder
 * \param[in] iter   KDF iteration count to display
 */
extern void auto_select_algorithms(gtk_widgets_s *data, char *cipher, char *hash, char *mode, char *mac, uint64_t iter);

/*!
 * \brief Populate the compatibility-version menu
 * \param[in] data    GUI widget state
 * \param[in] version Version label to select; NULL selects the current version
 */
extern void set_compatibility_menu(gtk_widgets_s *data, char *version);

/*!
 * \brief Select the configured key source in the menu
 * \param[in] data       GUI widget state
 * \param[in] key_source Key-file or password selection
 */
extern void set_key_source_menu(gtk_widgets_s *data, key_source_e key_source);

/*!
 * \brief Display the file chooser associated with a button
 * \param[in] button Activating button
 * \param[in] data   GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean file_dialog_display(GtkButton *button, gtk_widgets_s *data);

/*!
 * \brief Accept the currently selected file chooser path
 * \param[in] button Activating button
 * \param[in] data   GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean file_dialog_okay(GtkButton *button, gtk_widgets_s *data);

/*!
 * \brief Update algorithm settings and control sensitivity after selector changes
 * \param[in] combo_box Changed selector
 * \param[in] data      GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean algorithm_combo_callback(GtkComboBox *combo_box, gtk_widgets_s *data);

/*!
 * \brief Switch between key-file and password controls
 * \param[in] widget Activating menu widget
 * \param[in] data   GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_key_source_change(GtkWidget *widget, gtk_widgets_s *data);

/*!
 * \brief Update encryption-button sensitivity when the password changes
 * \param[in] password_entry Password entry widget
 * \param[in] data           GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean password_entry_callback(GtkComboBox *password_entry, gtk_widgets_s *data);

/*!
 * \brief Validate and accept a selected key file
 * \param[in] file_chooser Key-file chooser
 * \param[in] data         GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean key_dialog_okay(GtkFileChooser *file_chooser, gtk_widgets_s *data);

/*!
 * \brief Start an encryption or decryption operation
 * \param[in] button Activating operation button
 * \param[in] data   GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_encrypt_button_clicked(GtkButton *button, gtk_widgets_s *data);

/*!
 * \brief Cancel an active operation or close its progress dialog
 * \param[in] button Activating progress-dialog button
 * \param[in] data   GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_progress_button_clicked(GtkButton *button, gtk_widgets_s *data);

/*!
 * \brief Display the About dialog and build information
 * \param[in] widget Activating widget
 * \param[in] data   GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_about_open(GtkWidget *widget, gtk_widgets_s *data);

/*!
 * \brief Update the compression preference
 * \param[in] widget Toggled menu item
 * \param[in] data   GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_compress_toggle(GtkWidget *widget, gtk_widgets_s *data);

/*!
 * \brief Update the symbolic-link following preference
 * \param[in] widget Toggled menu item
 * \param[in] data   GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_follow_toggle(GtkWidget *widget, gtk_widgets_s *data);

/*!
 * \brief Update the raw-mode preference
 * \param[in] widget Toggled menu item
 * \param[in] data   GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_raw_toggle(GtkWidget *widget, gtk_widgets_s *data);

/*!
 * \brief Update the container compatibility version
 * \param[in] widget Selected version menu item
 * \param[in] data   GUI widget state
 * \return TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_compatibility_change(GtkWidget *widget, gtk_widgets_s *data);

/*!
 * \brief Show the raw-mode operation buttons or the standard operation button
 * \param[in] data GUI widget state
 * \param[in] raw  Whether raw mode is enabled
 */
extern void set_raw_buttons(gtk_widgets_s *data, bool raw);

/*!
 * \brief Replace the message displayed in the status bar
 * \param[in] status_bar Status bar widget
 * \param[in] status     Message to display
 */
extern void set_status_bar(GtkStatusbar *status_bar, const char *status);

#endif /* _ENCRYPT_GUI_GTK_H_ */
