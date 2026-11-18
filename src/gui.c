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

#if defined __APPLE__
	#include <CoreFoundation/CoreFoundation.h>
	#include <limits.h>
#endif

/* submodule includes */

#include "src/common.h"
#include "src/non-gnu.h"
#include "src/error.h"
#include "src/mem.h"
#include "src/ccrypt.h"
#include "src/version.h"
#include "src/cli.h"
#include "src/dir.h"
#include "src/config.h"

/* project inculdes */

#include "gui.h"

#include "crypt.h"
#include "encrypt.h"
#include "decrypt.h"

#define _filename_utf8(A) g_filename_to_utf8(A, -1, NULL, NULL, NULL)

#define NONE_SELECTED "(None)"

char *KEY_SOURCE[] =
{
	"file",
	"password"
};

/*
 * FIXME There has to be a way to make gtk_file_chooser_set_filename work
 * correctly
 */
char *gui_file_hack_source = NULL;
char *gui_file_hack_output = NULL;
static char *cwd = NULL;

inline static void set_progress_bar(GtkProgressBar *, char *, double);

static void *gui_process(void *);
inline static void gui_display(crypto_s *, gtk_widgets_s *);

static gboolean _files = false;
static bool _encrypted = false;
static bool _compress = true;
static bool _follow = false;
static bool _raw = false;
static key_source_e _key_source = KEY_SOURCE_PASSWORD;
static version_e _version = VERSION_CURRENT;
static crypto_status_e *_status = NULL;


#ifdef __APPLE__

#define CONTENTS_DIRECTORY "/Contents/"

extern char *get_mac_path(char *suffix)
{
	CFBundleRef bundle = CFBundleGetMainBundle();
	if (!bundle)
		return NULL;
	CFURLRef bundle_url = CFBundleCopyBundleURL(bundle);
	if (!bundle_url)
		return NULL;

	CFStringRef bundle_url_string = CFURLCopyFileSystemPath(bundle_url, kCFURLPOSIXPathStyle);
	CFRelease(bundle_url);

	size_t length = (size_t)CFStringGetMaximumSizeForEncoding(CFStringGetLength(bundle_url_string), kCFStringEncodingUTF8);
	size_t capacity = length + strlen(suffix) + strlen(CONTENTS_DIRECTORY);
	char *bundle_path = calloc(capacity, 1);
	if (!bundle_path)
		die(_("Out of memory @ %s:%d:%s [%zu]"), __FILE__, __LINE__, __func__, capacity);

	bool b = CFStringGetCString(bundle_url_string, bundle_path, (CFIndex)length, kCFStringEncodingUTF8);
	CFRelease(bundle_url_string);
	if (!b)
	{
		free(bundle_path);
		return NULL;
	}

	strcat(bundle_path, CONTENTS_DIRECTORY);
	strcat(bundle_path, suffix);
	return bundle_path;
}

static char pixbuf_cache_path[] = "/tmp/encrypt-loaders-XXXXXX";

static void remove_pixbuf_cache(void)
{
	unlink(pixbuf_cache_path);
}

extern void configure_pixbuf_loaders(void)
{
	const char *placeholder = "@ENCRYPT_FRAMEWORKS@";
	char *framework_path = get_mac_framework_path();
	char *cache_path = get_mac_cache_path();

	if (!framework_path || !cache_path)
		die(_("Unable to determine application bundle paths"));

	FILE *input = fopen(cache_path, "rb");
	if (!input)
		die(_("Unable to open GdkPixbuf loader cache: %s"), cache_path);

	if (fseek(input, 0, SEEK_END) != 0)
		die(_("Unable to seek GdkPixbuf loader cache"));

	long length = ftell(input);
	if (length < 0 || fseek(input, 0, SEEK_SET) != 0)
		die(_("Unable to read GdkPixbuf loader cache"));

	char *contents = malloc((size_t)length + 1);
	if (!contents)
		die(_("Out of memory"));

	if (fread(contents, 1, (size_t)length, input) != (size_t)length)
		die(_("Unable to read GdkPixbuf loader cache"));

	fclose(input);
	contents[length] = '\0';

	char *marker = strstr(contents, placeholder);
	if (!marker)
		die(_("GdkPixbuf loader cache placeholder not found"));

	size_t prefix_length = (size_t)(marker - contents);
	size_t marker_length = strlen(placeholder);
	size_t framework_length = strlen(framework_path);
	size_t suffix_length = (size_t)length - prefix_length - marker_length;

	size_t output_length = prefix_length + framework_length + suffix_length;
	char *output = malloc(output_length + 1);
	if (!output)
		die(_("Out of memory"));

	memcpy(output, contents, prefix_length);
	memcpy(output + prefix_length, framework_path, framework_length);
	memcpy(output + prefix_length + framework_length, marker + marker_length, suffix_length);
	output[output_length] = '\0';

	free(contents);
	free(cache_path);

	int fd = mkstemp(pixbuf_cache_path);
	if (fd < 0)
		die(_("Unable to create temporary GdkPixbuf loader cache"));

	FILE *output_file = fdopen(fd, "wb");
	if (!output_file)
		die(_("Unable to open temporary GdkPixbuf loader cache"));

	if (fwrite(output, 1, output_length, output_file) != output_length)
		die(_("Unable to write temporary GdkPixbuf loader cache"));

	free(output);

	if (fclose(output_file))
		die(_("Unable to close temporary GdkPixbuf loader cache"));

	if (setenv("GDK_PIXBUF_MODULEDIR", framework_path, 1) != 0 ||
		setenv("GDK_PIXBUF_MODULE_FILE", pixbuf_cache_path, 1) != 0)
		die(_("Unable to configure GdkPixbuf loader paths"));

	free(framework_path);
	atexit(remove_pixbuf_cache);
}

#endif


extern void auto_select_algorithms(gtk_widgets_s *data, char *cipher, char *hash, char *mode, char *mac, uint64_t iter)
{
	/*
	 * ciphers
	 */
	list_t ciphers = list_of_ciphers();
	unsigned slctd_cipher = 0;
	gtk_combo_box_text_remove_all((GtkComboBoxText *)data->crypto_combo);
	gtk_combo_box_text_append_text((GtkComboBoxText *)data->crypto_combo, SELECT_CIPHER);
	for (unsigned i = 0; i < list_size(ciphers); i++)
	{
		const char *c = list_get(ciphers, i);
		if (cipher && !strcasecmp(c, cipher))
			slctd_cipher = i + 1;
		gtk_combo_box_text_append_text((GtkComboBoxText *)data->crypto_combo, c);
	}
	gtk_combo_box_set_active((GtkComboBox *)data->crypto_combo, slctd_cipher);
	/*
	 * hashes
	 */
	list_t hashes = list_of_hashes();
	unsigned slctd_hash = 0;
	gtk_combo_box_text_remove_all((GtkComboBoxText *)data->hash_combo);
	gtk_combo_box_text_append_text((GtkComboBoxText *)data->hash_combo, SELECT_HASH);
	for (unsigned i = 0; i < list_size(hashes); i++)
	{
		const char *h = list_get(hashes, i);
		if (hash && !strcasecmp(h, hash))
			slctd_hash = i + 1;
		gtk_combo_box_text_append_text((GtkComboBoxText *)data->hash_combo, h);
	}
	gtk_combo_box_set_active((GtkComboBox *)data->hash_combo, slctd_hash);
	/*
	 * modes
	 */
	list_t modes = list_of_modes();
	unsigned slctd_mode = 0;
	gtk_combo_box_text_remove_all((GtkComboBoxText *)data->mode_combo);
	gtk_combo_box_text_append_text((GtkComboBoxText *)data->mode_combo, SELECT_MODE);
	for (unsigned i = 0; i < list_size(modes); i++)
	{
		const char *m = list_get(modes, i);
		if (mode && !strcasecmp(m, mode))
			slctd_mode = i + 1;
		gtk_combo_box_text_append_text((GtkComboBoxText *)data->mode_combo, m);
	}
	gtk_combo_box_set_active((GtkComboBox *)data->mode_combo, slctd_mode);
	/*
	 * MACs
	 */
	list_t macs = list_of_macs();
	unsigned slctd_mac = 0;
	gtk_combo_box_text_remove_all((GtkComboBoxText *)data->mac_combo);
	gtk_combo_box_text_append_text((GtkComboBoxText *)data->mac_combo, SELECT_MAC);
	for (unsigned i = 0; i < list_size(macs); i++)
	{
		const char *m = list_get(macs, i);
		if (mac && !strcasecmp(m, mac))
			slctd_mac = i + 1;
		gtk_combo_box_text_append_text((GtkComboBoxText *)data->mac_combo, m);
	}
	gtk_combo_box_set_active((GtkComboBox *)data->mac_combo, slctd_mac);
	/*
	 * KDF iterations
	 */
	gtk_adjustment_set_value(gtk_spin_button_get_adjustment((GtkSpinButton *)data->kdf_spinner), (double)iter);

	return;
}

static void menu_action_quit(GSimpleAction *action, GVariant *parameter, gpointer user_data)
{
	(void)action;
	(void)parameter;
	gtk_widgets_s *data = user_data;
	gtk_widget_destroy(data->main_window);
}

static void menu_action_about(GSimpleAction *action, GVariant *parameter, gpointer user_data)
{
	(void)action;
	(void)parameter;
	on_about_open(NULL, user_data);
}

static void menu_action_boolean_change(GSimpleAction *action, GVariant *value, gpointer user_data)
{
	gtk_widgets_s *data = user_data;
	const char *name = g_action_get_name(G_ACTION(action));
	gboolean active = g_variant_get_boolean(value);

	if (!strcmp(name, "compress"))
	{
		_compress = active;
		update_config(CONF_COMPRESS, active ? CONF_TRUE : CONF_FALSE);
	}
	else if (!strcmp(name, "follow"))
	{
		_follow = active;
		update_config(CONF_FOLLOW, active ? CONF_TRUE : CONF_FALSE);
	}
	else if (!strcmp(name, "raw"))
	{
		_raw = active;
		update_config(CONF_SKIP_HEADER, active ? CONF_TRUE : CONF_FALSE);
		set_raw_buttons(data, active);
	}

	g_simple_action_set_state(action, value);
}

static void menu_action_key_source_change(GSimpleAction *action, GVariant *value, gpointer user_data)
{
	gtk_widgets_s *data = user_data;
	const char *source = g_variant_get_string(value, NULL);

	_key_source = !strcmp(source, "file") ? KEY_SOURCE_FILE : KEY_SOURCE_PASSWORD;
	update_config(CONF_KEY_SOURCE, KEY_SOURCE[_key_source]);
	gtk_widget_hide(_key_source == KEY_SOURCE_PASSWORD ? data->key_button : data->password_entry);
	gtk_widget_show(_key_source == KEY_SOURCE_PASSWORD ? data->password_entry : data->key_button);
	g_simple_action_set_state(action, value);
}

static void menu_action_compatibility_change(GSimpleAction *action, GVariant *value, gpointer user_data)
{
	(void)user_data;
	_version = parse_version((char *)g_variant_get_string(value, NULL));
	update_config(CONF_VERSION, get_version_string(_version));
	g_simple_action_set_state(action, value);
}

static void menu_add_action(GtkApplication *app, const char *name, GVariant *state, GCallback callback, gpointer data)
{
	GSimpleAction *action = state
		? g_simple_action_new_stateful(name, NULL, state)
		: g_simple_action_new(name, NULL);
	g_signal_connect(action, state ? "change-state" : "activate", callback, data);
	g_action_map_add_action(G_ACTION_MAP(app), G_ACTION(action));
	g_object_unref(action);
}

extern void gui_setup_menus(GtkApplication *app, GtkBuilder *builder, gtk_widgets_s *data, bool compress, bool follow, bool raw, const char *key_source, char *version)
{
	GMenuModel *menubar = G_MENU_MODEL(gtk_builder_get_object(builder, "menubar"));
	version_e selected = parse_version(version);

	data->compatibility_menu = G_MENU(gtk_builder_get_object(builder, "compatibility_menu"));
	_compress = compress;
	_follow = follow;
	_raw = raw;
	_key_source = !strcmp(key_source, "file") ? KEY_SOURCE_FILE : KEY_SOURCE_PASSWORD;
	gtk_widget_hide(_key_source == KEY_SOURCE_PASSWORD ? data->key_button : data->password_entry);
	gtk_widget_show(_key_source == KEY_SOURCE_PASSWORD ? data->password_entry : data->key_button);


	menu_add_action(app, "quit", NULL, G_CALLBACK(menu_action_quit), data);
	menu_add_action(app, "about", NULL, G_CALLBACK(menu_action_about), data);
	menu_add_action(app, "compress", g_variant_new_boolean(compress), G_CALLBACK(menu_action_boolean_change), data);
	menu_add_action(app, "follow", g_variant_new_boolean(follow), G_CALLBACK(menu_action_boolean_change), data);
	menu_add_action(app, "raw", g_variant_new_boolean(raw), G_CALLBACK(menu_action_boolean_change), data);
	menu_add_action(app, "key-source", g_variant_new_string(key_source), G_CALLBACK(menu_action_key_source_change), data);

	if (selected == VERSION_UNKNOWN)
		selected = VERSION_CURRENT;
	_version = selected;
	for (version_e i = VERSION_CURRENT; i > VERSION_UNKNOWN; i--)
	{
		const char *label = get_version_string(i);
		GMenuItem *item = g_menu_item_new(label, NULL);
		g_menu_item_set_action_and_target(item, "app.compatibility", "s", label);
		g_menu_append_item(data->compatibility_menu, item);
		g_object_unref(item);
	}
	menu_add_action(app, "compatibility", g_variant_new_string(get_version_string(selected)), G_CALLBACK(menu_action_compatibility_change), data);

	gtk_application_set_menubar(app, menubar);
#ifdef __APPLE__
	gtk_application_set_app_menu(app, G_MENU_MODEL(gtk_builder_get_object(builder, "app-menu")));
#endif

	return;
}

G_MODULE_EXPORT gboolean file_dialog_display(GtkButton *button, gtk_widgets_s *data)
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
	{
		const char *home = getenv("HOME");
		cwd = strdup(home ? home : ".");
	}
	if (cwd)
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
				gtk_widget_set_sensitive(data->mac_combo, FALSE);
				gtk_widget_set_sensitive(data->kdf_spinner, FALSE);
				gtk_widget_set_sensitive(data->key_button, FALSE);
			}
			gtk_widget_set_sensitive(data->encrypt_button, FALSE);
			gtk_widget_set_sensitive(data->raw_encrypt_button, FALSE);
			gtk_widget_set_sensitive(data->raw_decrypt_button, FALSE);
			break;

#if 0 /* not yet fully implemented (because I don’t like the resulting workflow) */
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

G_MODULE_EXPORT gboolean file_dialog_okay(GtkButton *button, gtk_widgets_s *data)
{
	gtk_widget_hide(data->open_dialog);
	gtk_widget_hide(data->save_dialog);

	gboolean en = TRUE;
	/*
	 * check the source file exists (and is a file)
	 */
	char *open_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->open_dialog);
	bool free_open_file = open_file != NULL;
	if (!open_file)
		open_file = gui_file_hack_source;
	char *open_display = open_file ? _filename_utf8(open_file) : NULL;
	if (!open_file || !open_display || !strlen(open_file))
		en = FALSE;
	else
	{
		struct stat s;
		if (stat(open_file, &s) == 0 && (S_ISREG(s.st_mode) || S_ISDIR(s.st_mode)))
		{
			gtk_label_set_text((GtkLabel *)data->open_file_label, basename(open_display));
			gtk_widget_show(data->open_file_image);
			/*
			 * quickly see if the file is encrypted already
			 */
			char *ptr = m_malloc(1);
			char *c = ptr;
			char *h = ptr;
			char *m = ptr;
			char *a = ptr;
			uint64_t iter;
			if ((_encrypted = is_encrypted(open_file, &c, &h, &m, &a, &iter)))
			{
				auto_select_algorithms(data, c, h, m, a, iter);
				free(c);
				free(h);
				free(m);
				free(a);
			}
			free(ptr);
			gtk_button_set_label((GtkButton *)data->encrypt_button, _encrypted ? LABEL_DECRYPT : LABEL_ENCRYPT);
			en = TRUE;
			char *dir = S_ISREG(s.st_mode) ? dir_get_path(open_file) : strdup(open_file);
			if (cwd)
				free(cwd);
			cwd = dir;
		}
		else
			en = FALSE;
	}
	g_free(open_display);
	if (free_open_file)
		g_free(open_file);

	char *save_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->save_dialog);
	bool free_save_file = save_file != NULL;
	if (!save_file)
		save_file = gui_file_hack_output;
	char *save_display = save_file ? _filename_utf8(save_file) : NULL;
	if (!save_file || !save_display || !strlen(save_file))
		en = FALSE;
	else
	{
		struct stat s;
		/*
		 * if the destination exists, it has to be a regular file
		 */
		int result = stat(save_file, &s);
		if ((result == 0 && (S_ISREG(s.st_mode) || S_ISDIR(s.st_mode))) ||
			(result < 0 && errno == ENOENT))
		{
			gtk_label_set_text((GtkLabel *)data->save_file_label, basename(save_display));
			gtk_widget_show(data->save_file_image);
			char *dir = result == 0 && S_ISDIR(s.st_mode)
				? strdup(save_file)
				: dir_get_path(save_file);
			if (cwd)
				free(cwd);
			cwd = dir;
		}
		else
			en = FALSE;
	}
	g_free(save_display);
	if (free_save_file)
		g_free(save_file);

	_files = en;

	if (_encrypted)
	{
		gtk_widget_set_sensitive(data->crypto_combo, FALSE);
		gtk_widget_set_sensitive(data->hash_combo, FALSE);
		gtk_widget_set_sensitive(data->mode_combo, FALSE);
		gtk_widget_set_sensitive(data->mac_combo, FALSE);
		gtk_widget_set_sensitive(data->kdf_spinner, FALSE);
		gtk_widget_set_sensitive(data->password_entry, en);
		gtk_widget_set_sensitive(data->key_button, en);
	}
	else
	{
		gtk_widget_set_sensitive(data->crypto_combo, en);
		gtk_widget_set_sensitive(data->hash_combo, en);
		gtk_widget_set_sensitive(data->mode_combo, en);
		gtk_widget_set_sensitive(data->mac_combo, en);
		gtk_widget_set_sensitive(data->kdf_spinner, en);
		if (en)
			algorithm_combo_callback(NULL, data);
	}

	return (void)button, TRUE;
}

G_MODULE_EXPORT gboolean algorithm_combo_callback(GtkComboBox *combo_box, gtk_widgets_s *data)
{
	int cipher = gtk_combo_box_get_active((GtkComboBox *)data->crypto_combo);
	int hash = gtk_combo_box_get_active((GtkComboBox *)data->hash_combo);
	int mode = gtk_combo_box_get_active((GtkComboBox *)data->mode_combo);
	int mac = gtk_combo_box_get_active((GtkComboBox *)data->mac_combo);
	int64_t iter = (int64_t)gtk_adjustment_get_value(gtk_spin_button_get_adjustment((GtkSpinButton *)data->kdf_spinner));

	gboolean en = _files;

	if (cipher > 0 && hash > 0 && mode > 0 && mac > 0 && iter > 0)
	{
		list_t ciphers = list_of_ciphers();
		list_t hashes  = list_of_hashes();
		list_t modes   = list_of_modes();
		list_t macs    = list_of_macs();

		update_config(CONF_CIPHER, list_get(ciphers, cipher - 1));
		update_config(CONF_HASH,   list_get(hashes,  hash - 1));
		update_config(CONF_MODE,   list_get(modes,   mode - 1));
		update_config(CONF_MAC,	list_get(macs,	mac - 1));

		char i[22];
		snprintf(i, sizeof i, "%" PRIu64, iter);
		update_config(CONF_KDF_ITERATIONS, i);

		if (!(en = mode_valid_for_cipher(cipher_id_from_name(list_get(ciphers, cipher - 1)), mode_id_from_name(list_get(modes, mode - 1)))))
			set_status_bar((GtkStatusbar *)data->status_bar, _(STATUS_BAD_MODE));
		else
			set_status_bar((GtkStatusbar *)data->status_bar, _(STATUS_BAR_READY));

	}
	else
		en = FALSE;

	gtk_widget_set_sensitive(data->password_entry, en);
	gtk_widget_set_sensitive(data->key_button, en);

	return (void)combo_box, TRUE;
}

G_MODULE_EXPORT gboolean password_entry_callback(GtkComboBox *password_entry, gtk_widgets_s *data)
{
	char *key_data = (char *)gtk_entry_get_text((GtkEntry *)password_entry);

	if (key_data && strlen(key_data))
	{
		gtk_widget_set_sensitive(data->encrypt_button, TRUE);
		gtk_widget_grab_default(_raw ? data->raw_encrypt_button : data->encrypt_button);
		gtk_widget_set_sensitive(data->raw_encrypt_button, TRUE);
		gtk_widget_set_sensitive(data->raw_decrypt_button, TRUE);
	}
	else
	{
		gtk_widget_set_sensitive(data->encrypt_button, FALSE);
		gtk_widget_set_sensitive(data->raw_encrypt_button, FALSE);
		gtk_widget_set_sensitive(data->raw_decrypt_button, FALSE);
	}

	return TRUE;
}

G_MODULE_EXPORT gboolean key_dialog_okay(GtkFileChooser *file_chooser, gtk_widgets_s *data)
{
	gboolean en = TRUE;

	char *key_file = gtk_file_chooser_get_filename((GtkFileChooser *)file_chooser);
	char *key_display = key_file ? _filename_utf8(key_file) : NULL;
	if (!key_file || !key_display || !strlen(key_file))
		en = FALSE;
	else
	{
		struct stat s;
		if (stat(key_file, &s) < 0 || !S_ISREG(s.st_mode))
			en = FALSE;
		else
		{
			char *dir = dir_get_path(key_file);
			if (cwd)
				free(cwd);
			cwd = dir;
		}
	}

	gtk_label_set_text((GtkLabel *)data->key_file_label, en ? basename(key_display) : NONE_SELECTED);

	g_free(key_display);
	g_free(key_file);

	if (en)
		gtk_widget_show(data->key_file_image);
	else
		gtk_widget_hide(data->key_file_image);

	gtk_widget_set_sensitive(data->encrypt_button, en);
	gtk_widget_set_sensitive(data->raw_encrypt_button, en);
	gtk_widget_set_sensitive(data->raw_decrypt_button, en);
	if (en)
		gtk_widget_grab_default(_raw ? data->raw_encrypt_button : data->encrypt_button);

	return TRUE;
}

G_MODULE_EXPORT gboolean on_encrypt_button_clicked(GtkButton *button, gtk_widgets_s *data)
{
	gtk_widget_show(data->progress_dialog);
	gtk_button_set_label((GtkButton *)data->progress_cancel_button, LABEL_CANCEL);
	set_progress_bar((GtkProgressBar *)data->progress_bar_total, NULL, 0.0f);
	set_progress_bar((GtkProgressBar *)data->progress_bar_current, NULL, 0.0f);
	gtk_widget_show(data->progress_bar_current);
	if (_raw)
	{
		if (button == (GtkButton *)data->raw_encrypt_button)
			_encrypted = false;
		else if (button == (GtkButton *)data->raw_decrypt_button)
			_encrypted = true;
	}
	gui_process(data);
	return (void)button, TRUE;
}

G_MODULE_EXPORT gboolean on_progress_button_clicked(GtkButton *button, gtk_widgets_s *data)
{
	if (_status && (*_status == STATUS_INIT || *_status == STATUS_RUNNING))
		*_status = STATUS_CANCELLED;
	else
		gtk_widget_hide(data->progress_dialog);

	return (void)button, TRUE;
}

G_MODULE_EXPORT gboolean on_about_open(GtkWidget *widget, gtk_widgets_s *data)
{

	char *build_info = version_build_info();
	gtk_text_buffer_set_text((GtkTextBuffer *)data->build_info_text_buffer, build_info, -1);
	free(build_info);

	if (version_new_available)
	{
		char *text = NULL;
		asprintf(&text, NEW_VERSION_OF_AVAILABLE, version_available, ENCRYPT);
		gtk_label_set_text((GtkLabel *)data->about_new_version_label, text);
		free(text);
	}
	gtk_dialog_run((GtkDialog *)data->about_dialog);
	gtk_widget_hide(data->about_dialog);

	return (void)widget, TRUE;
}

inline extern void set_raw_buttons(gtk_widgets_s *data, bool raw)
{
	if (raw)
	{
		gtk_widget_hide(data->encrypt_button);
		gtk_widget_show(data->raw_encrypt_button);
		gtk_widget_show(data->raw_decrypt_button);
	}
	else
	{
		gtk_widget_show(data->encrypt_button);
		gtk_widget_hide(data->raw_encrypt_button);
		gtk_widget_hide(data->raw_decrypt_button);
	}
	return;
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

inline static void set_progress_bar(GtkProgressBar *progress_bar, char *text, double percent)
{
	gtk_progress_bar_set_fraction(progress_bar, (double)percent / PERCENT);
	char *pc = NULL;

	char name[CLI_TRUNCATED_DISPLAY_LONG] = { 0x0 };
	char *nm = text ? : CLI_UNKNOWN;
	if (strlen(nm) < CLI_TRUNCATED_DISPLAY_LONG)
		strcpy(name, nm);
	else
	{
		strncpy(name, nm, CLI_TRUNCATED_DISPLAY_SHORT);
		strcat(name, CLI_TRUNCATED_ELLIPSE);
		strcat(name, nm + (strlen(nm) - CLI_TRUNCATED_DISPLAY_SHORT));
	}

	asprintf(&pc, "%s%s%3.0f %%", text ? name : "", text ? " : " : "", percent);
	gtk_progress_bar_set_text(progress_bar, pc);
	free(pc);

	return;
}

static void *gui_process(void *d)
{
	gtk_widgets_s *data = d;

	char *source = gtk_file_chooser_get_filename((GtkFileChooser *)data->open_dialog);
	char *output = gtk_file_chooser_get_filename((GtkFileChooser *)data->save_dialog);
	bool free_source = source != NULL;
	bool free_output = output != NULL;
	if (!source)
		source = gui_file_hack_source;
	if (!output)
		output = gui_file_hack_output;

	uint8_t *key = NULL;
	size_t length = 0;
	char *key_file = NULL;
	switch (_key_source)
	{
		case KEY_SOURCE_FILE:
			{
				key_file = gtk_file_chooser_get_filename((GtkFileChooser *)data->key_dialog);
				length = 0;
				if (key_file)
					key = (uint8_t *)strdup(key_file);
			}
			break;

		case KEY_SOURCE_PASSWORD:
			{
				const char *k = gtk_entry_get_text((GtkEntry *)data->password_entry);
				length = strlen(k);
				key = (uint8_t *)strndup(k, length);
			}
			break;
	}

	int c = gtk_combo_box_get_active((GtkComboBox *)data->crypto_combo);
	int h = gtk_combo_box_get_active((GtkComboBox *)data->hash_combo);
	int m = gtk_combo_box_get_active((GtkComboBox *)data->mode_combo);
	int a = gtk_combo_box_get_active((GtkComboBox *)data->mac_combo);
	uint64_t iter = (uint64_t)gtk_adjustment_get_value(gtk_spin_button_get_adjustment((GtkSpinButton *)data->kdf_spinner));
	list_t ciphers = list_of_ciphers();
	list_t hashes  = list_of_hashes();
	list_t modes   = list_of_modes();
	list_t macs    = list_of_macs();

	if (!source || !output || !key || c <= 0 || h <= 0 || m <= 0 || a <= 0)
	{
		if (free_source)
			g_free(source);
		if (free_output)
			g_free(output);
		g_free(key_file);
		free(key);
		set_status_bar((GtkStatusbar *)data->status_bar, _("Failed: Read/Write error!"));
		gtk_button_set_label((GtkButton *)data->progress_cancel_button, LABEL_CLOSE);
		return NULL;
	}

	crypto_s *x;
	if (_encrypted)
		x = decrypt_init(source, output, list_get(ciphers, c - 1), list_get(hashes, h - 1), list_get(modes, m - 1), list_get(macs, a - 1), key, length, iter, _raw);
	else
		x = encrypt_init(source, output, list_get(ciphers, c - 1), list_get(hashes, h - 1), list_get(modes, m - 1), list_get(macs, a - 1), key, length, iter, _raw, _compress, _follow, _version);

	_status = &x->status;

	if (free_source)
		g_free(source);
	if (free_output)
		g_free(output);
	g_free(key_file);
	free(key);

	if (x->status == STATUS_INIT)
		execute(x);

	gui_display(x, data);

	if (x->status == STATUS_SUCCESS)
	{
		set_progress_bar((GtkProgressBar *)data->progress_bar_total, NULL, PERCENT);
		set_progress_bar((GtkProgressBar *)data->progress_bar_current, NULL, PERCENT);
	}

	set_status_bar((GtkStatusbar *)data->status_bar, status(x));
	gtk_button_set_label((GtkButton *)data->progress_cancel_button, LABEL_CLOSE);

	_status = NULL;
	deinit(&x);

	return NULL;
}

inline static void gui_display(crypto_s *c, gtk_widgets_s *data)
{
	cli_bps_s bps[BPS];
	memset(bps, 0x00, BPS * sizeof( cli_bps_s ));
	int b = 0;

	while (c->status == STATUS_INIT || c->status == STATUS_RUNNING)
	{
		gtk_main_iteration_do(FALSE);

#if !defined _WIN32
		struct timespec s = { 0, MILLION };
		nanosleep(&s, NULL);
#else
		Sleep(1);
#endif

		if (c->status == STATUS_INIT)
			continue;

		double pc = (PERCENT * c->total.offset + PERCENT * c->current.offset / c->current.size) / c->total.size;
		if (c->total.offset == c->total.size)
			pc = PERCENT * c->total.offset / c->total.size;
		set_progress_bar((GtkProgressBar *)data->progress_bar_total, NULL, pc);

		if (c->total.size == 1)
			gtk_widget_hide(data->progress_bar_current);
		else
			set_progress_bar((GtkProgressBar *)data->progress_bar_current, c->current.display, PERCENT * c->current.offset / c->current.size);

		struct timeval tv;
		gettimeofday(&tv, NULL);
		bps[b].time = tv.tv_sec * MILLION + tv.tv_usec;
		bps[b].bytes = c->current.offset;
		double val = cli_calc_bps(bps);
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
