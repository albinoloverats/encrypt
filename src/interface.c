/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2009, albinoloverats ~ Software Development
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

#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>

#include "common/common.h"

#include "src/encrypt.h"
#include "src/callbacks.h"
#include "src/interface.h"
#include "src/support.h"

//extern char *filename_in  = NULL;
//extern char *filename_out = NULL;
//extern char    *key_plain = NULL;

GtkWidget *create_window_main(void)
{
    GtkWidget *window_main;
    GtkWidget *fixed_layout;
    GtkWidget *filechooserbutton_in_file;
    GtkWidget *filechooserbutton_key_file;
    GtkWidget *filechooserbutton_out_dir;
    GtkWidget *label_algorithm;
    GtkWidget *label_password;
    GtkWidget *label_out_dir;
    GtkWidget *label_out_file;
    GtkWidget *entry_password;
    GtkWidget *comboboxentry_algorithm;
    GtkWidget *entry_out_file;
    GtkWidget *button_about;
    GtkWidget *button_do;
    GtkWidget *button_quit;
    GtkWidget *combobox_process;
    GtkWidget *combobox_keyfile;
    GtkWidget *button_generate;
    GtkWidget *alignment_gen;
    GtkWidget *hbox_gen;
    GtkWidget *image_gen;
    GtkWidget *label_gen;

    GtkWidget *alignment1;
    GtkWidget *hbox1;
    GtkWidget *image1;
    GtkWidget *label1;
    GtkWidget *alignment2;
    GtkWidget *hbox2;
    GtkWidget *image2;
    GtkWidget *label2;
    GtkWidget *alignment3;
    GtkWidget *hbox3;
    GtkWidget *image3;
    GtkWidget *label3;

    GtkAccelGroup *accel_group;

    accel_group = gtk_accel_group_new();

    window_main = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_widget_set_size_request(window_main, 384, 392);
    gtk_window_set_title(GTK_WINDOW(window_main), NAME);
    gtk_window_set_default_size(GTK_WINDOW(window_main), 384, 392);
    gtk_window_set_resizable(GTK_WINDOW(window_main), false);
    gtk_window_set_gravity(GTK_WINDOW(window_main), GDK_GRAVITY_CENTER);

    fixed_layout = gtk_fixed_new();
    gtk_widget_show(fixed_layout);
    gtk_container_add(GTK_CONTAINER(window_main), fixed_layout);

    /* 
     * each of these lines of code which get the location of specified files is really bad - why doesn't
     * gtk_file_chooser_set_filename allow paths from the current directory?!
     */
    filechooserbutton_in_file = gtk_file_chooser_button_new(_("Select a File"), GTK_FILE_CHOOSER_ACTION_OPEN);
//#ifndef _WIN32
//    if (filename_in)
//    {
//        if ((!strcmp(filename_in, basename(filename_in))) || (filename_in[0] == '.'))
//            asprintf(&filename_in, "%s/%s", get_current_dir_name(), filename_in);
//        gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(filechooserbutton_in_file), filename_in);
//    }
//#endif /* ! _WIN32 */
    gtk_widget_show(filechooserbutton_in_file);
    gtk_fixed_put(GTK_FIXED(fixed_layout), filechooserbutton_in_file, 192, 32);
    gtk_widget_set_size_request(filechooserbutton_in_file, 160, 32);

    filechooserbutton_key_file = gtk_file_chooser_button_new(_("Select a Key / Passphrase File"), GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_widget_show(filechooserbutton_key_file);
    gtk_fixed_put(GTK_FIXED(fixed_layout), filechooserbutton_key_file, 192, 72);
    gtk_widget_set_size_request(filechooserbutton_key_file, 160, 32);
    g_object_set(filechooserbutton_key_file, "show-hidden", true, NULL);

    filechooserbutton_out_dir = gtk_file_chooser_button_new(_("Select Destination Folder"), GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
//#ifndef _WIN32
//    if (filename_out)
//    {
//        if ((!strcmp(filename_out, basename(filename_out))) || (filename_out[0] == '.'))
//            asprintf(&filename_out, "%s/%s", get_current_dir_name(), filename_out);
//        gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(filechooserbutton_out_dir), dirname(filename_out));
//    }
//#endif /* ! _WIN32 */
    gtk_widget_show(filechooserbutton_out_dir);
    gtk_fixed_put(GTK_FIXED(fixed_layout), filechooserbutton_out_dir, 192, 184);
    gtk_widget_set_size_request(filechooserbutton_out_dir, 160, 32);

    label_algorithm = gtk_label_new(_("Algorithm"));
    gtk_widget_show(label_algorithm);
    gtk_fixed_put(GTK_FIXED(fixed_layout), label_algorithm, 32, 144);
    gtk_widget_set_size_request(label_algorithm, 160, 32);
    gtk_misc_set_alignment(GTK_MISC(label_algorithm), 0, 0.5);

    label_password = gtk_label_new(_("Password"));
    gtk_widget_show(label_password);
    gtk_fixed_put(GTK_FIXED(fixed_layout), label_password, 32, 112);
    gtk_widget_set_size_request(label_password, 160, 24);
    gtk_misc_set_alignment(GTK_MISC(label_password), 0, 0.5);

    label_out_dir = gtk_label_new(_("Destination Directory"));
    gtk_widget_show(label_out_dir);
    gtk_fixed_put(GTK_FIXED(fixed_layout), label_out_dir, 32, 184);
    gtk_widget_set_size_request(label_out_dir, 160, 32);
    gtk_misc_set_alignment(GTK_MISC(label_out_dir), 0, 0.5);

    label_out_file = gtk_label_new(_("Destination File Name"));
    gtk_widget_show(label_out_file);
    gtk_fixed_put(GTK_FIXED(fixed_layout), label_out_file, 32, 224);
    gtk_widget_set_size_request(label_out_file, 160, 24);
    gtk_misc_set_alignment(GTK_MISC(label_out_file), 0, 0.5);

    entry_password = gtk_entry_new();
    gtk_widget_show(entry_password);
    gtk_fixed_put(GTK_FIXED(fixed_layout), entry_password, 192, 112);
    gtk_widget_set_size_request(entry_password, 160, 24);
    gtk_entry_set_visibility(GTK_ENTRY(entry_password), false);

    combobox_process = gtk_combo_box_new_text();
    gtk_widget_show(combobox_process);
    gtk_fixed_put(GTK_FIXED(fixed_layout), combobox_process, 32, 32);
    gtk_widget_set_size_request(combobox_process, 152, 32);
    gtk_combo_box_append_text(GTK_COMBO_BOX(combobox_process), _("Encrypt"));
    gtk_combo_box_append_text(GTK_COMBO_BOX(combobox_process), _("Decrypt"));
    gtk_combo_box_set_active(GTK_COMBO_BOX(combobox_process), 0);

    combobox_keyfile = gtk_combo_box_new_text();
    gtk_widget_show(combobox_keyfile);
    gtk_fixed_put(GTK_FIXED(fixed_layout), combobox_keyfile, 32, 72);
    gtk_widget_set_size_request(combobox_keyfile, 152, 32);
    gtk_combo_box_append_text(GTK_COMBO_BOX(combobox_keyfile), _("Key"));
    gtk_combo_box_append_text(GTK_COMBO_BOX(combobox_keyfile), _("Passphrase"));
    gtk_combo_box_set_active(GTK_COMBO_BOX(combobox_keyfile), 0);

    comboboxentry_algorithm = gtk_combo_box_entry_new_text();
    gtk_widget_show(comboboxentry_algorithm);
    gtk_fixed_put(GTK_FIXED(fixed_layout), comboboxentry_algorithm, 192, 144);
    gtk_widget_set_size_request(comboboxentry_algorithm, 160, 32);

#ifndef _WIN32
    /* 
     * this could be the the same as the windows implementation, but this gives the list sorted :)
     */
    struct dirent **eps;
    int64_t n = scandir("/usr/lib/encrypt/lib", &eps, NULL, alphasort);

    if (n >= 0)
    {
        for (int64_t i = 0; i < n; ++i)
            if (strstr(eps[i]->d_name, ".so"))
#ifdef linux
                gtk_combo_box_append_text(GTK_COMBO_BOX(comboboxentry_algorithm), _(strndup(eps[i]->d_name, strlen(eps[i]->d_name) - 3)));
#else  /*   linux */
            {
                char *s = strdup(eps[i]->d_name);
                char *t = calloc(strlen(eps[i]->d_name), sizeof( char ));
                memcpy(t, s, strlen(eps[i]->d_name) - 3);
                free(s);
                gtk_combo_box_append_text(GTK_COMBO_BOX(comboboxentry_algorithm), _(t));
                free(t);
            }
#endif /* ! linux */
//        if (plugin)
//            gtk_combo_box_insert_text(GTK_COMBO_BOX(comboboxentry_algorithm), 0, strndup(plugin, strlen(plugin) - 3));
#else  /* ! _WIN32 */
    DIR *dp = opendir("/Program Files/encrypt/lib");
    if (dp)
    {
        struct dirent *ep;
        while ((ep = readdir(dp)))
            if (strstr(ep->d_name, ".dll"))
            {
                char *s = strdup(ep->d_name);
                char *t = calloc(strlen(ep->d_name), sizeof( char ));
                memcpy(t, s, strlen(ep->d_name) - 4);
                free(s);
                gtk_combo_box_append_text(GTK_COMBO_BOX(comboboxentry_algorithm), _(t));
                free(t);
            }

        (void) closedir(dp);
#endif /*   _WIN32 */
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(comboboxentry_algorithm), 0);

    entry_out_file = gtk_entry_new();
    gtk_widget_show(entry_out_file);
    gtk_fixed_put(GTK_FIXED(fixed_layout), entry_out_file, 192, 224);
    gtk_widget_set_size_request(entry_out_file, 160, 24);
//#ifndef _WIN32
//    if (filename_out)
//        gtk_entry_set_text(GTK_ENTRY(entry_out_file), basename(filename_out));
//#endif /* ! _WIN32 */

    button_do = gtk_button_new();
    alignment1 = gtk_alignment_new(0.5, 0.5, 0, 0);
    gtk_widget_show(alignment1);
    gtk_container_add(GTK_CONTAINER(button_do), alignment1);

    hbox1 = gtk_hbox_new(false, 2);
    gtk_widget_show(hbox1);
    gtk_container_add(GTK_CONTAINER(alignment1), hbox1);

    image1 = gtk_image_new_from_stock("gtk-execute", GTK_ICON_SIZE_BUTTON);
    gtk_widget_show(image1);
    gtk_box_pack_start(GTK_BOX(hbox1), image1, false, false, 0);

    label1 = gtk_label_new_with_mnemonic(_("_Execute"));
    gtk_widget_show(label1);
    gtk_box_pack_start(GTK_BOX(hbox1), label1, false, false, 0);

    button_quit = gtk_button_new();
    alignment2 = gtk_alignment_new(0.5, 0.5, 0, 0);
    gtk_widget_show(alignment2);
    gtk_container_add(GTK_CONTAINER(button_quit), alignment2);

    hbox2 = gtk_hbox_new(false, 2);
    gtk_widget_show(hbox2);
    gtk_container_add(GTK_CONTAINER(alignment2), hbox2);

    image2 = gtk_image_new_from_stock("gtk-quit", GTK_ICON_SIZE_BUTTON);
    gtk_widget_show(image2);
    gtk_box_pack_start(GTK_BOX(hbox2), image2, false, false, 0);

    label2 = gtk_label_new_with_mnemonic(_("_Quit"));
    gtk_widget_show(label2);
    gtk_box_pack_start(GTK_BOX(hbox2), label2, false, false, 0);

    button_about = gtk_button_new();
    alignment3 = gtk_alignment_new(0.5, 0.5, 0, 0);
    gtk_widget_show(alignment3);
    gtk_container_add(GTK_CONTAINER(button_about), alignment3);

    hbox3 = gtk_hbox_new(false, 2);
    gtk_widget_show(hbox3);
    gtk_container_add(GTK_CONTAINER(alignment3), hbox3);

    image3 = gtk_image_new_from_stock("gtk-about", GTK_ICON_SIZE_BUTTON);
    gtk_widget_show(image3);
    gtk_box_pack_start(GTK_BOX(hbox3), image3, false, false, 0);

    label3 = gtk_label_new_with_mnemonic(_("_About"));
    gtk_widget_show(label3);
    gtk_box_pack_start(GTK_BOX(hbox3), label3, false, false, 0);

    gtk_widget_show(button_about);
    gtk_fixed_put(GTK_FIXED(fixed_layout), button_about, 56, 328);
    gtk_widget_set_size_request(button_about, 96, 32);
    gtk_widget_add_accelerator(button_about, "clicked", accel_group, GDK_A, (GdkModifierType)GDK_MOD1_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_about, "clicked", accel_group, GDK_A, (GdkModifierType)GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);

    gtk_widget_show(button_do);
    gtk_fixed_put(GTK_FIXED(fixed_layout), button_do, 224, 256);
    gtk_widget_set_size_request(button_do, 96, 64);
    gtk_widget_add_accelerator(button_do, "clicked", accel_group, GDK_E, (GdkModifierType)GDK_MOD1_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_do, "clicked", accel_group, GDK_E, (GdkModifierType)GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_do, "clicked", accel_group, GDK_Return, (GdkModifierType)0, GTK_ACCEL_VISIBLE);

    gtk_widget_show(button_quit);
    gtk_fixed_put(GTK_FIXED(fixed_layout), button_quit, 224, 328);
    gtk_widget_set_size_request(button_quit, 96, 32);
    gtk_widget_add_accelerator(button_quit, "clicked", accel_group, GDK_Q, (GdkModifierType)GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_quit, "clicked", accel_group, GDK_Q, (GdkModifierType)GDK_MOD1_MASK, GTK_ACCEL_VISIBLE);

    button_generate = gtk_button_new();
    gtk_widget_show(button_generate);
    gtk_fixed_put(GTK_FIXED(fixed_layout), button_generate, 56, 288);
    gtk_widget_set_size_request(button_generate, 96, 32);
    gtk_widget_add_accelerator(button_generate, "clicked", accel_group, GDK_K, (GdkModifierType)GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_generate, "clicked", accel_group, GDK_K, (GdkModifierType)GDK_MOD1_MASK, GTK_ACCEL_VISIBLE);

    alignment_gen = gtk_alignment_new(0.5, 0.5, 0, 0);
    gtk_widget_show(alignment_gen);
    gtk_container_add(GTK_CONTAINER(button_generate), alignment_gen);

    hbox_gen = gtk_hbox_new(false, 2);
    gtk_widget_show(hbox_gen);
    gtk_container_add(GTK_CONTAINER(alignment_gen), hbox_gen);

    image_gen = gtk_image_new_from_stock("gtk-dialog-authentication", GTK_ICON_SIZE_BUTTON);
    gtk_widget_show(image_gen);
    gtk_box_pack_start(GTK_BOX(hbox_gen), image_gen, false, false, 0);

    label_gen = gtk_label_new_with_mnemonic(_("_Key"));
    gtk_widget_show(label_gen);
    gtk_box_pack_start(GTK_BOX(hbox_gen), label_gen, false, false, 0);

    g_signal_connect((gpointer) window_main, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect((gpointer) button_about, "clicked", G_CALLBACK(on_button_about_clicked), NULL);
    g_signal_connect((gpointer) button_do, "clicked", G_CALLBACK(on_button_do_clicked), NULL);
    g_signal_connect((gpointer) button_quit, "clicked", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect((gpointer) button_generate, "clicked", G_CALLBACK(on_button_generate_clicked), NULL);

    /* Store pointers to all widgets, for use by lookup_widget(). */
    GLADE_HOOKUP_OBJECT_NO_REF(window_main, window_main, "window_main");
    GLADE_HOOKUP_OBJECT(window_main, fixed_layout, "fixed_layout");
    GLADE_HOOKUP_OBJECT(window_main, filechooserbutton_in_file, "filechooserbutton_in_file");
    GLADE_HOOKUP_OBJECT(window_main, filechooserbutton_key_file, "filechooserbutton_key_file");
    GLADE_HOOKUP_OBJECT(window_main, filechooserbutton_out_dir, "filechooserbutton_out_dir");
    GLADE_HOOKUP_OBJECT(window_main, label_algorithm, "label_algorithm");
    GLADE_HOOKUP_OBJECT(window_main, label_password, "label_password");
    GLADE_HOOKUP_OBJECT(window_main, label_out_dir, "label_out_dir");
    GLADE_HOOKUP_OBJECT(window_main, label_out_file, "label_out_file");
    GLADE_HOOKUP_OBJECT(window_main, entry_password, "entry_password");
    GLADE_HOOKUP_OBJECT(window_main, comboboxentry_algorithm, "comboboxentry_algorithm");
    GLADE_HOOKUP_OBJECT(window_main, entry_out_file, "entry_out_file");
    GLADE_HOOKUP_OBJECT(window_main, button_about, "button_about");
    GLADE_HOOKUP_OBJECT(window_main, button_do, "button_do");
    GLADE_HOOKUP_OBJECT(window_main, button_quit, "button_quit");
    GLADE_HOOKUP_OBJECT(window_main, combobox_process, "combobox_process");
    GLADE_HOOKUP_OBJECT(window_main, combobox_keyfile, "combobox_keyfile");
    GLADE_HOOKUP_OBJECT(window_main, button_generate, "button_generate");
    GLADE_HOOKUP_OBJECT(window_main, alignment_gen, "alignment_gen");
    GLADE_HOOKUP_OBJECT(window_main, hbox_gen, "hbox_gen");
    GLADE_HOOKUP_OBJECT(window_main, image_gen, "image_gen");
    GLADE_HOOKUP_OBJECT(window_main, label_gen, "label_gen");

    GLADE_HOOKUP_OBJECT(window_main, hbox1, "hbox1");
    GLADE_HOOKUP_OBJECT(window_main, image1, "image1");
    GLADE_HOOKUP_OBJECT(window_main, label1, "label1");
    GLADE_HOOKUP_OBJECT(window_main, hbox2, "hbox2");
    GLADE_HOOKUP_OBJECT(window_main, image2, "image2");
    GLADE_HOOKUP_OBJECT(window_main, label2, "label2");
    GLADE_HOOKUP_OBJECT(window_main, hbox3, "hbox3");
    GLADE_HOOKUP_OBJECT(window_main, image3, "image3");
    GLADE_HOOKUP_OBJECT(window_main, label3, "label3");

    gtk_window_add_accel_group(GTK_WINDOW(window_main), accel_group);

    return window_main;
}

GtkWidget *create_window_about(void)
{
    GtkWidget *window_about;
    GtkWidget *fixed_about;
    GtkWidget *scrolledwindow_about;
    GtkWidget *textview_about;
    GtkWidget *button_about_close;
    GtkWidget *image_icon_about;
    GtkWidget *image_icon_logo;

    GtkWidget *alignment4;
    GtkWidget *hbox4;
    GtkWidget *image4;
    GtkWidget *label4;

    GtkAccelGroup *accel_group;

    accel_group = gtk_accel_group_new();

    window_about = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_widget_set_size_request(window_about, 416, 320);
    gtk_window_set_title(GTK_WINDOW(window_about), _("About encrypt"));
    gtk_window_set_position(GTK_WINDOW(window_about), GTK_WIN_POS_CENTER_ON_PARENT);
    gtk_window_set_modal(GTK_WINDOW(window_about), true);
    gtk_window_set_resizable(GTK_WINDOW(window_about), false);
    gtk_window_set_destroy_with_parent(GTK_WINDOW(window_about), true);
    gtk_window_set_icon_name(GTK_WINDOW(window_about), "gtk-about");
    gtk_window_set_skip_taskbar_hint(GTK_WINDOW(window_about), true);
    gtk_window_set_skip_pager_hint(GTK_WINDOW(window_about), true);
    gtk_window_set_gravity(GTK_WINDOW(window_about), GDK_GRAVITY_CENTER);

    fixed_about = gtk_fixed_new();
    gtk_widget_show(fixed_about);
    gtk_container_add(GTK_CONTAINER(window_about), fixed_about);

    scrolledwindow_about = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_show(scrolledwindow_about);
    gtk_fixed_put(GTK_FIXED(fixed_about), scrolledwindow_about, 16, 96);
    gtk_widget_set_size_request(scrolledwindow_about, 384, 168);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledwindow_about), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scrolledwindow_about), GTK_SHADOW_IN);

    textview_about = gtk_text_view_new();
    gtk_widget_show(textview_about);
    gtk_container_add(GTK_CONTAINER(scrolledwindow_about), textview_about);
    gtk_widget_set_size_request(textview_about, 288, 160);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(textview_about), false);
    gtk_text_view_set_accepts_tab(GTK_TEXT_VIEW(textview_about), false);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(textview_about), GTK_WRAP_NONE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(textview_about), false);
    char *about_text = NULL;

#ifndef _WIN32
    if (asprintf(&about_text, _("%s\n  version : %s\n  built on: %s %s\n\n%s\nWebsite\n  %s\n\nContributors\n %s\n\nCopyright\n  %s\n\nLicence\n%s"), NAME, VERSION, __DATE__, __TIME__, _(TEXT_ABOUT), TEXT_SITE, TEXT_CONTRIB, TEXT_COPY, _(TEXT_LICENCE)) < 0)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
#else  /* ! _WIN32 */
    uint32_t l = strlen(_("%s\n  version : %s\n  built on: %s %s\n\n%s\nWebsite\n %s\n\nContributors\n %s\n\nCopyright\n %s\n\nLicence\n%s"));
    l += strlen(NAME);
    l += strlen(VERSION);
    l += strlen(__DATE__);
    l += strlen(__TIME__);
    l += strlen(_(TEXT_ABOUT));
    l += strlen(TEXT_SITE);
    l += strlen(TEXT_CONTRIB);
    l += strlen(TEXT_COPY);
    l += strlen(_(TEXT_LICENCE));
    about_text = calloc(l + 1, sizeof( char ));
    if (!about_text)
        die(_("out of memory @ %s:%i"), __FILE__, __LINE__);
    sprintf(about_text, _("%s\n  version : %s\n  built on: %s %s\n\n%s\nWebsite\n  %s\n\nContributors\n %s\n\nCopyright\n  %s\n\nLicence\n%s"), NAME, VERSION, __DATE__, __TIME__, _(TEXT_ABOUT), TEXT_SITE, TEXT_CONTRIB, TEXT_COPY, _(TEXT_LICENCE)) < 0)
#endif /*   _WIN32 */
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview_about)), about_text, -1);

    button_about_close = gtk_button_new();
    alignment4 = gtk_alignment_new(0.5, 0.5, 0, 0);
    gtk_widget_show(alignment4);
    gtk_container_add(GTK_CONTAINER(button_about_close), alignment4);

    hbox4 = gtk_hbox_new(false, 2);
    gtk_widget_show(hbox4);
    gtk_container_add(GTK_CONTAINER(alignment4), hbox4);

    image4 = gtk_image_new_from_stock("gtk-close", GTK_ICON_SIZE_BUTTON);
    gtk_widget_show(image4);
    gtk_box_pack_start(GTK_BOX(hbox4), image4, false, false, 0);

    label4 = gtk_label_new_with_mnemonic(_("_Close"));
    gtk_widget_show(label4);
    gtk_box_pack_start(GTK_BOX(hbox4), label4, false, false, 0);

    gtk_widget_show(button_about_close);
    gtk_fixed_put(GTK_FIXED(fixed_about), button_about_close, 160, 272);
    gtk_widget_set_size_request(button_about_close, 96, 32);
    gtk_widget_add_accelerator(button_about_close, "clicked", accel_group, GDK_C, (GdkModifierType)GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_about_close, "clicked", accel_group, GDK_C, (GdkModifierType)GDK_MOD1_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_about_close, "clicked", accel_group, GDK_Return, (GdkModifierType)0, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_about_close, "clicked", accel_group, GDK_Escape, (GdkModifierType)0, GTK_ACCEL_VISIBLE);

    image_icon_about = create_pixmap("encrypt.xpm");
    gtk_widget_show(image_icon_about);
    gtk_fixed_put(GTK_FIXED(fixed_about), image_icon_about, 224, 0);
    gtk_widget_set_size_request(image_icon_about, 96, 96);

    image_icon_logo = create_pixmap("albinoloverats.xpm");
    gtk_widget_show(image_icon_logo);
    gtk_fixed_put(GTK_FIXED(fixed_about), image_icon_logo, 96, 0);
    gtk_widget_set_size_request(image_icon_logo, 96, 96);

    g_signal_connect((gpointer) button_about_close, "clicked", G_CALLBACK(on_button_about_close_clicked), NULL);

    /* Store pointers to all widgets, for use by lookup_widget(). */
    GLADE_HOOKUP_OBJECT_NO_REF(window_about, window_about, "window_about");
    GLADE_HOOKUP_OBJECT(window_about, fixed_about, "fixed_about");
    GLADE_HOOKUP_OBJECT(window_about, scrolledwindow_about, "scrolledwindow_about");
    GLADE_HOOKUP_OBJECT(window_about, textview_about, "textview_about");
    GLADE_HOOKUP_OBJECT(window_about, button_about_close, "button_about_close");
    GLADE_HOOKUP_OBJECT(window_about, image_icon_about, "image_icon_about");
    GLADE_HOOKUP_OBJECT(window_about, image_icon_logo, "image_icon_logo");

    GLADE_HOOKUP_OBJECT(window_about, hbox4, "hbox4");
    GLADE_HOOKUP_OBJECT(window_about, image4, "image4");
    GLADE_HOOKUP_OBJECT(window_about, label4, "label4");

    gtk_window_add_accel_group(GTK_WINDOW(window_about), accel_group);

    return window_about;
}

GtkWidget *create_window_wait(void)
{
    GtkWidget *window_wait;
    GtkWidget *fixed_wait;
    GtkWidget *button_wait_close;
    GtkWidget *image_wait;
    GtkWidget *label_wait;

    GtkWidget *alignment5;
    GtkWidget *hbox5;
    GtkWidget *image5;
    GtkWidget *label5;

    GtkAccelGroup *accel_group;

    accel_group = gtk_accel_group_new();

    window_wait = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_widget_set_size_request(window_wait, 240, 160);
    gtk_window_set_title(GTK_WINDOW(window_wait), _("Please wait..."));
    gtk_window_set_position(GTK_WINDOW(window_wait), GTK_WIN_POS_CENTER_ON_PARENT);
    gtk_window_set_modal(GTK_WINDOW(window_wait), true);
    gtk_window_set_default_size(GTK_WINDOW(window_wait), 240, 160);
    gtk_window_set_resizable(GTK_WINDOW(window_wait), false);
    gtk_window_set_destroy_with_parent(GTK_WINDOW(window_wait), true);
    gtk_window_set_icon_name(GTK_WINDOW(window_wait), "gtk-dialog-error");

    fixed_wait = gtk_fixed_new();
    gtk_widget_show(fixed_wait);
    gtk_container_add(GTK_CONTAINER(window_wait), fixed_wait);

    button_wait_close = gtk_button_new();
    alignment5 = gtk_alignment_new(0.5, 0.5, 0, 0);
    gtk_widget_show(alignment5);
    gtk_container_add(GTK_CONTAINER(button_wait_close), alignment5);

    hbox5 = gtk_hbox_new(false, 2);
    gtk_widget_show(hbox5);
    gtk_container_add(GTK_CONTAINER(alignment5), hbox5);

    image5 = gtk_image_new_from_stock("gtk-close", GTK_ICON_SIZE_BUTTON);
    gtk_widget_show(image5);
    gtk_box_pack_start(GTK_BOX(hbox5), image5, false, false, 0);

    label5 = gtk_label_new_with_mnemonic(_("_Close"));
    gtk_widget_show(label5);
    gtk_box_pack_start(GTK_BOX(hbox5), label5, false, false, 0);

    gtk_widget_show(button_wait_close);
    gtk_fixed_put(GTK_FIXED(fixed_wait), button_wait_close, 72, 112);
    gtk_widget_set_size_request(button_wait_close, 96, 32);
    gtk_widget_set_sensitive(button_wait_close, false);
    gtk_widget_add_accelerator(button_wait_close, "clicked", accel_group, GDK_C, (GdkModifierType)GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_wait_close, "clicked", accel_group, GDK_C, (GdkModifierType)GDK_MOD1_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_wait_close, "clicked", accel_group, GDK_Return, (GdkModifierType)0, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_wait_close, "clicked", accel_group, GDK_Escape, (GdkModifierType)0, GTK_ACCEL_VISIBLE);

    image_wait = gtk_image_new_from_icon_name("gtk-dialog-warning", GTK_ICON_SIZE_DIALOG);
    gtk_widget_show(image_wait);
    gtk_fixed_put(GTK_FIXED(fixed_wait), image_wait, 88, 8);
    gtk_widget_set_size_request(image_wait, 64, 64);

    label_wait = gtk_label_new(_("Please wait..."));
    gtk_widget_show(label_wait);
    gtk_fixed_put(GTK_FIXED(fixed_wait), label_wait, 20, 64);
    gtk_widget_set_size_request(label_wait, 200, 48);
    gtk_label_set_justify(GTK_LABEL(label_wait), GTK_JUSTIFY_CENTER);
    gtk_label_set_line_wrap(GTK_LABEL(label_wait), true);

    g_signal_connect((gpointer)window_wait, "destroy", G_CALLBACK(on_button_wait_close_clicked), NULL);
    g_signal_connect((gpointer)button_wait_close, "clicked", G_CALLBACK(on_button_wait_close_clicked), NULL);

    /* Store pointers to all widgets, for use by lookup_widget(). */
    GLADE_HOOKUP_OBJECT_NO_REF(window_wait, window_wait, "window_wait");
    GLADE_HOOKUP_OBJECT(window_wait, fixed_wait, "fixed_wait");
    GLADE_HOOKUP_OBJECT(window_wait, button_wait_close, "button_wait_close");
    GLADE_HOOKUP_OBJECT(window_wait, image_wait, "image_wait");
    GLADE_HOOKUP_OBJECT(window_wait, label_wait, "label_wait");

    GLADE_HOOKUP_OBJECT(window_wait, hbox5, "hbox5");
    GLADE_HOOKUP_OBJECT(window_wait, image5, "image5");
    GLADE_HOOKUP_OBJECT(window_wait, label5, "label5");

    gtk_window_add_accel_group(GTK_WINDOW(window_wait), accel_group);

    return window_wait;
}

GtkWidget *create_window_generate(void)
{
    GtkWidget *window_generate;
    GtkWidget *fixed_gen;
    GtkWidget *spinbutton_size;
    GtkWidget *entry_display_size;
    GtkWidget *entry_gen_save_name;
    GtkWidget *button_gen_go;
    GtkWidget *alignment2;
    GtkWidget *hbox2;
    GtkWidget *image2;
    GtkWidget *label3;
    GtkWidget *button_gen_close;
    GtkWidget *label_gen_size;
    GtkWidget *label_gen_save_as;
    GtkWidget *label_gen_save_in;
    GtkWidget *filechooserbutton_gen_save;
    GtkAccelGroup *accel_group;
    GtkWidget *alignment5;
    GtkWidget *hbox5;
    GtkWidget *image5;
    GtkWidget *label5;

    accel_group = gtk_accel_group_new();

    window_generate = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_widget_set_size_request(window_generate, 240, 208);
    gtk_window_set_title(GTK_WINDOW(window_generate), _("Generate Key"));
    gtk_window_set_position(GTK_WINDOW(window_generate), GTK_WIN_POS_CENTER_ON_PARENT);
    gtk_window_set_modal(GTK_WINDOW(window_generate), true);
    gtk_window_set_resizable(GTK_WINDOW(window_generate), false);
    gtk_window_set_destroy_with_parent(GTK_WINDOW(window_generate), true);
    gtk_window_set_icon_name(GTK_WINDOW(window_generate), "gtk-dialog-authentication");
    gtk_window_set_gravity(GTK_WINDOW(window_generate), GDK_GRAVITY_CENTER);

    fixed_gen = gtk_fixed_new();
    gtk_widget_show(fixed_gen);
    gtk_container_add(GTK_CONTAINER(window_generate), fixed_gen);

    spinbutton_size = gtk_spin_button_new_with_range(128, 4096, 8);
    gtk_widget_show(spinbutton_size);
    gtk_fixed_put(GTK_FIXED(fixed_gen), spinbutton_size, 160, 16);
    gtk_widget_set_size_request(spinbutton_size, 60, 24);
    gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(spinbutton_size), true);

    entry_display_size = gtk_entry_new();
    gtk_widget_show(entry_display_size);
    gtk_fixed_put(GTK_FIXED(fixed_gen), entry_display_size, 16, 56);
    gtk_widget_set_size_request(entry_display_size, 208, 24);
    gtk_editable_set_editable(GTK_EDITABLE(entry_display_size), false);

    entry_gen_save_name = gtk_entry_new();
    gtk_widget_show(entry_gen_save_name);
    gtk_fixed_put(GTK_FIXED(fixed_gen), entry_gen_save_name, 64, 128);
    gtk_widget_set_size_request(entry_gen_save_name, 160, 24);

    button_gen_go = gtk_button_new();
    gtk_widget_show(button_gen_go);
    gtk_fixed_put(GTK_FIXED(fixed_gen), button_gen_go, 16, 160);
    gtk_widget_set_size_request(button_gen_go, 96, 32);
    gtk_widget_add_accelerator(button_gen_go, "clicked", accel_group, GDK_G, (GdkModifierType)GDK_MOD1_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_gen_go, "clicked", accel_group, GDK_G, (GdkModifierType)GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_gen_go, "clicked", accel_group, GDK_Return, (GdkModifierType)0, GTK_ACCEL_VISIBLE);

    alignment2 = gtk_alignment_new(0.5, 0.5, 0, 0);
    gtk_widget_show(alignment2);
    gtk_container_add(GTK_CONTAINER(button_gen_go), alignment2);

    hbox2 = gtk_hbox_new(false, 2);
    gtk_widget_show(hbox2);
    gtk_container_add(GTK_CONTAINER(alignment2), hbox2);

    image2 = gtk_image_new_from_stock("gtk-redo", GTK_ICON_SIZE_BUTTON);
    gtk_widget_show(image2);
    gtk_box_pack_start(GTK_BOX(hbox2), image2, false, false, 0);

    label3 = gtk_label_new_with_mnemonic(_("_Generate"));
    gtk_widget_show(label3);
    gtk_box_pack_start(GTK_BOX(hbox2), label3, false, false, 0);

    button_gen_close = gtk_button_new();
    alignment5 = gtk_alignment_new(0.5, 0.5, 0, 0);
    gtk_widget_show(alignment5);
    gtk_container_add(GTK_CONTAINER(button_gen_close), alignment5);

    hbox5 = gtk_hbox_new(false, 2);
    gtk_widget_show(hbox5);
    gtk_container_add(GTK_CONTAINER(alignment5), hbox5);

    image5 = gtk_image_new_from_stock("gtk-close", GTK_ICON_SIZE_BUTTON);
    gtk_widget_show(image5);
    gtk_box_pack_start(GTK_BOX(hbox5), image5, false, false, 0);

    label5 = gtk_label_new_with_mnemonic(_("_Close"));
    gtk_widget_show(label5);
    gtk_box_pack_start(GTK_BOX(hbox5), label5, false, false, 0);

    gtk_widget_show(button_gen_close);
    gtk_fixed_put(GTK_FIXED(fixed_gen), button_gen_close, 128, 160);
    gtk_widget_set_size_request(button_gen_close, 96, 32);
    gtk_widget_add_accelerator(button_gen_close, "clicked", accel_group, GDK_C, (GdkModifierType)GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_gen_close, "clicked", accel_group, GDK_C, (GdkModifierType)GDK_MOD1_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_gen_close, "clicked", accel_group, GDK_S, (GdkModifierType)GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_gen_close, "clicked", accel_group, GDK_S, (GdkModifierType)GDK_MOD1_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(button_gen_close, "clicked", accel_group, GDK_Escape, (GdkModifierType)0, GTK_ACCEL_VISIBLE);

    label_gen_size = gtk_label_new(_("Key size (bits)"));
    gtk_widget_show(label_gen_size);
    gtk_fixed_put(GTK_FIXED(fixed_gen), label_gen_size, 16, 16);
    gtk_widget_set_size_request(label_gen_size, 144, 24);
    gtk_misc_set_alignment(GTK_MISC(label_gen_size), 0, 0.5);

    label_gen_save_as = gtk_label_new(_("Save As"));
    gtk_widget_show(label_gen_save_as);
    gtk_fixed_put(GTK_FIXED(fixed_gen), label_gen_save_as, 16, 128);
    gtk_widget_set_size_request(label_gen_save_as, 48, 24);
    gtk_misc_set_alignment(GTK_MISC(label_gen_save_as), 0, 0.5);

    label_gen_save_in = gtk_label_new(_("Save In"));
    gtk_widget_show(label_gen_save_in);
    gtk_fixed_put(GTK_FIXED(fixed_gen), label_gen_save_in, 16, 88);
    gtk_widget_set_size_request(label_gen_save_in, 48, 32);
    gtk_misc_set_alignment(GTK_MISC(label_gen_save_in), 0, 0.5);

    filechooserbutton_gen_save = gtk_file_chooser_button_new(_("Select A Directory"),
      GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
    gtk_widget_show(filechooserbutton_gen_save);
    gtk_fixed_put(GTK_FIXED(fixed_gen), filechooserbutton_gen_save, 64, 88);
    gtk_widget_set_size_request(filechooserbutton_gen_save, 160, 32);

    g_signal_connect((gpointer) entry_gen_save_name, "changed", G_CALLBACK(on_entry_gen_save_name_changed), NULL);
    g_signal_connect((gpointer) button_gen_go, "clicked", G_CALLBACK(on_button_gen_go_clicked), NULL);
    g_signal_connect((gpointer) button_gen_close, "clicked", G_CALLBACK(on_button_gen_close_clicked), NULL);

    /* Store pointers to all widgets, for use by lookup_widget(). */
    GLADE_HOOKUP_OBJECT_NO_REF(window_generate, window_generate, "window_generate");
    GLADE_HOOKUP_OBJECT(window_generate, fixed_gen, "fixed_gen");
    GLADE_HOOKUP_OBJECT(window_generate, spinbutton_size, "spinbutton_size");
    GLADE_HOOKUP_OBJECT(window_generate, entry_display_size, "entry_display_size");
    GLADE_HOOKUP_OBJECT(window_generate, entry_gen_save_name, "entry_gen_save_name");
    GLADE_HOOKUP_OBJECT(window_generate, button_gen_go, "button_gen_go");
    GLADE_HOOKUP_OBJECT(window_generate, alignment2, "alignment2");
    GLADE_HOOKUP_OBJECT(window_generate, hbox2, "hbox2");
    GLADE_HOOKUP_OBJECT(window_generate, image2, "image2");
    GLADE_HOOKUP_OBJECT(window_generate, label3, "label3");
    GLADE_HOOKUP_OBJECT(window_generate, button_gen_close, "button_gen_close");
    GLADE_HOOKUP_OBJECT(window_generate, label_gen_size, "label_gen_size");
    GLADE_HOOKUP_OBJECT(window_generate, label_gen_save_as, "label_gen_save_as");
    GLADE_HOOKUP_OBJECT(window_generate, label_gen_save_in, "label_gen_save_in");
    GLADE_HOOKUP_OBJECT(window_generate, filechooserbutton_gen_save, "filechooserbutton_gen_save");
    GLADE_HOOKUP_OBJECT(window_generate, hbox5, "hbox5");
    GLADE_HOOKUP_OBJECT(window_generate, image5, "image5");
    GLADE_HOOKUP_OBJECT(window_generate, label5, "label5");

    gtk_window_add_accel_group(GTK_WINDOW(window_generate), accel_group);

    return window_generate;
}
