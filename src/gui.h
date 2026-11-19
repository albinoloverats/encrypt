/*!
 * \file    gui.h
 * \brief   Shared GUI state, GTK widgets, and callbacks
 */

#include <gtk/gtk.h>

/*!
 * \file    gui.h
 * \brief   Shared labels, configuration keys, and state for GUI front ends
 */

#define STATUS_BAR_READY "Ready"
#define STATUS_BAD_MODE  "Mode incompatible with cipher"

#define LABEL_ENCRYPT "Encrypt"
#define LABEL_DECRYPT "Decrypt"

#define LABEL_CANCEL "Cancel"
#define LABEL_CLOSE  "Close"

#define SELECT_CIPHER "Select Cipher Algorithm"
#define SELECT_HASH   "Select Hash Algorithm"
#define SELECT_MODE   "Select Cipher Mode"
#define SELECT_MAC    "Select MAC Algorithm"

#define CONF_COMPRESS       "compress"
#define CONF_FOLLOW         "follow"
#define CONF_KDF_ITERATIONS "kdf-iterations"
#define CONF_KEY_SOURCE     "key-source"
#define CONF_CIPHER         "cipher"
#define CONF_HASH           "hash"
#define CONF_MODE           "mode"
#define CONF_MAC            "mac"
#define CONF_VERSION        "version"
#define CONF_SKIP_HEADER    "raw"

/*!
 * \brief Source used to obtain the encryption key
 */
typedef enum
{
	KEY_SOURCE_FILE,     /*!< Read key bytes from a file */
	KEY_SOURCE_PASSWORD /*!< Use the entered password as key material */
}
key_source_e;

/*!
 * \brief Display strings corresponding to key_source_e values
 */
extern char *KEY_SOURCE[];

/*!
 * \brief Optional command-line source path used to preselect a GUI file chooser
 */
extern char *gui_file_hack_source;

/*!
 * \brief Optional command-line output path used to preselect a GUI file chooser
 */
extern char *gui_file_hack_output;



// submodule include
#include "src/config.h"

#if !defined _WIN32 && !defined __APPLE__
	#define GLADE_UI_FILE_DEFAULT "/usr/local/share/encrypt/encrypt.glade"
	#define GLADE_UI_FILE_BACKUP  "etc/encrypt.glade"
#elif defined __APPLE__
	#define GLADE_UI_FILE_DEFAULT "encrypt_mac.glade"
	#define GLADE_UI_FILE_BACKUP  "etc/encrypt_mac.glade"
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
	GMenu *compatibility_menu;
	GtkWidget *raw_encrypt_button;
	GtkWidget *raw_decrypt_button;
	GtkWidget *abort_dialog;
	GtkWidget *abort_button;
	GtkWidget *abort_message;
}
gtk_widgets_s;

/*!
 * \brief Populate algorithm selectors and select supplied settings
 * \param[in]  d  GUI widget state
 * \param[in]  c  Cipher name to select, or NULL for the placeholder
 * \param[in]  h  Hash name to select, or NULL for the placeholder
 * \param[in]  m  Cipher mode to select, or NULL for the placeholder
 * \param[in]  a  MAC name to select, or NULL for the placeholder
 * \param[in]  i  KDF iteration count to display
 */
extern void auto_select_algorithms(gtk_widgets_s *d, char *c, char *h, char *m, char *a, uint64_t i);

/*!
 * \brief Populate the compatibility-version menu
 * \param[in]  d  GUI widget state
 * \param[in]  v  Version label to select; NULL selects the current version
 */
extern void gui_setup_menus(GtkApplication *app, GtkBuilder *builder, gtk_widgets_s *d, bool compress, bool follow, bool raw, const char *key_source, char *version);

/*!
 * \brief Display the file chooser associated with a button
 * \param[in]  b  Activating button
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean file_dialog_display(GtkButton *b, gtk_widgets_s *d);

/*!
 * \brief Accept the currently selected file chooser path
 * \param[in]  b  Activating button
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean file_dialog_okay(GtkButton *b, gtk_widgets_s *d);

/*!
 * \brief Update algorithm settings and control sensitivity after selector changes
 * \param[in]  c  Changed selector
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean algorithm_combo_callback(GtkComboBox *c, gtk_widgets_s *d);

/*!
 * \brief Switch between key-file and password controls
 * \param[in]  w  Activating menu widget
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
/*!
 * \brief Update encryption-button sensitivity when the password changes
 * \param[in]  p  Password entry widget
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean password_entry_callback(GtkComboBox *p, gtk_widgets_s *d);

/*!
 * \brief Validate and accept a selected key file
 * \param[in]  f  Key-file chooser
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean key_dialog_okay(GtkFileChooser *f, gtk_widgets_s *d);

/*!
 * \brief Start an encryption or decryption operation
 * \param[in]  b  Activating operation button
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_encrypt_button_clicked(GtkButton *b, gtk_widgets_s *d);

/*!
 * \brief Cancel an active operation or close its progress dialog
 * \param[in]  b  Activating progress-dialog button
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_progress_button_clicked(GtkButton *b, gtk_widgets_s *d);

/*!
 * \brief Display the About dialog and build information
 * \param[in]  w  Activating widget
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
G_MODULE_EXPORT gboolean on_about_open(GtkWidget *w, gtk_widgets_s *d);

/*!
 * \brief Update the compression preference
 * \param[in]  w  Toggled menu item
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
/*!
 * \brief Update the symbolic-link following preference
 * \param[in]  w  Toggled menu item
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
/*!
 * \brief Update the raw-mode preference
 * \param[in]  w  Toggled menu item
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
/*!
 * \brief Update the container compatibility version
 * \param[in]  w  Selected version menu item
 * \param[in]  d  GUI widget state
 * \return        TRUE after handling the callback
 */
/*!
 * \brief Show the raw-mode operation buttons or the standard operation button
 * \param[in]  d  GUI widget state
 * \param[in]  r  Whether raw mode is enabled
 */
extern void set_raw_buttons(gtk_widgets_s *d, bool r);

/*!
 * \brief Replace the message displayed in the status bar
 * \param[in]  b  Status bar widget
 * \param[in]  s  Message to display
 */
extern void set_status_bar(GtkStatusbar *b, const char *s);

#if defined __APPLE__
extern char *get_mac_path(char *s);

extern void configure_pixbuf_loaders(void);

#define get_mac_resource_path()  get_mac_path("Resources")
#define get_mac_framework_path() get_mac_path("Frameworks")
#define get_mac_cache_path()     get_mac_path("Frameworks/loaders.cache")

#endif

