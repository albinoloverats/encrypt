/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2008, albinoloverats ~ Software Development
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

#ifdef HAVE_CONFIG_H
  #include <config.h>
#endif /* HAVE_CONFIG_H */

#ifndef _WIN32
  #include <dlfcn.h>
  #include <sys/wait.h>
#else  /* ! _WIN32 */
  #include <windows.h>
#endif /*   _WIN32 */

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <getopt.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <gtk/gtk.h>

#include "encrypt.h"
#include "plugins.h"

#include "callbacks.h"
#include "interface.h"
#include "support.h"

#define PLUGIN_DETAILS_MASK "\nAlgorithm Details\n    Name\t\t: %s\n    Author\t\t: %s\n    Copyright\t: %s\n    Licence\t: %s\n    Year\t\t: %s\n    Block size\t: %s\n\nKey Details\n    Name\t\t: %s\n    Authors\t: %s\n    Copyright\t: %s\n    Licence\t: %s\n    Year\t\t: %s\n    Key size\t: %s\n\nPlugin Details\n    Authors\t: %s\n    Copyright\t: %s\n    Licence\t: %s\n    Version\t: %s\n\nAdditional Details\n    %s\n"

void on_button_about_clicked(GtkWidget *widget)
{
    /* 
     * woot woot - this is the about box :p
     */
    GtkWidget *window_about, *textview_about;

    window_about = create_window_about();
    gtk_widget_show(window_about);
    /* 
     * find out which algorithm the user wants to know about; if no algorithm is selected then just return all happy :)
     */
    GtkComboBoxEntry *alg = (GtkComboBoxEntry *)lookup_widget(GTK_WIDGET(widget), "comboboxentry_algorithm");
    if (!strcmp(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)), ""))
        return;
    /* 
     * set everything up so we can get some info about the given algorithm
     */
    char *filename_mod  = NULL;
    char *details = NULL;

    info_t *about = NULL;
    info_t *(*fp)(void);

    errno = 0;
#ifndef _WIN32
    void *file_mod = NULL;
    if (!strchr(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)), '/'))
        asprintf(&filename_mod, "/usr/lib/encrypt/lib/%s.so", gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)));
#else  /* ! _WIN32 */
    HANDLE file_mod = NULL;
    if (!strchr(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)), '\\'))
    {
        filename_mod = calloc(strlen("/Program Files/encrypt/lib/") + strlen(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg))) + 1, sizeof( char ));
        sprintf(filename_mod, "/Program Files/encrypt/lib/%s", gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)));
    }
#endif /*   _WIN32 */
    else
        filename_mod = strdup(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)));
    /* 
     * find the plugin, open it, etc...
     */
    if (!(file_mod = open_mod(filename_mod)))
    {
        free(filename_mod);
        textview_about = lookup_widget(window_about, "textview_about");
        gtk_text_buffer_insert_at_cursor(gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview_about)), details, -1);
        return;
    }
    free(filename_mod);

#ifndef _WIN32
    if (!(fp = (info_t *(*)(void))dlsym(file_mod, "plugin_info")))
  #ifdef _DLFCN_H
        dlclose(file_mod);
  #endif /* _DLFCN_H */
#else
    if (!(fp = (void *)GetProcAddress(file_mod, "plugin_info")))
#endif
    {
        details = strdup("\nError: could not find plugin information\n");
        textview_about = lookup_widget(window_about, "textview_about");
        gtk_text_buffer_insert_at_cursor(gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview_about)), details, -1);
        return;
    }
    /* 
     * now get the info
     */
    about = fp();
#ifndef _WIN32
    asprintf(&details, PLUGIN_DETAILS_MASK,
            about->algorithm_name,  about->algorithm_authors,  about->algorithm_copyright,  about->algorithm_licence,  about->algorithm_year,  about->algorithm_block,
            about->key_name,        about->key_authors,        about->key_copyright,        about->key_licence,        about->key_year,        about->key_size,
            about->module_authors,  about->module_copyright,   about->module_licence,       about->module_version,     about->module_comment);
#else  /* ! _WIN32 */
    /* 
     * woot for Windows
     */
    details = calloc(strlen(PLUGIN_DETAILS_MASK) +
            strlen(about->algorithm_name) + strlen(about->algorithm_authors) + strlen(about->algorithm_copyright) + strlen(about->algorithm_licence) + strlen(about->algorithm_year) + strlen(about->algorithm_block) +
            strlen(about->key_name) +       strlen(about->key_authors) +       strlen(about->key_copyright) +       strlen(about->key_licence) +       strlen(about->key_year) +       strlen(about->key_size) +
            strlen(about->module_authors) + strlen(about->module_copyright) +  strlen(about->module_licence) +      strlen(about->module_version) +    strlen(about->module_comment), sizeof( char ));
    sprintf(details, PLUGIN_DETAILS_MASK,
            about->algorithm_name,  about->algorithm_authors,  about->algorithm_copyright,  about->algorithm_licence,  about->algorithm_year,  about->algorithm_block,
            about->key_name,        about->key_authors,        about->key_copyright,        about->key_licence,        about->key_year,        about->key_size,
            about->module_authors,  about->module_copyright,   about->module_licence,       about->module_version,     about->module_comment);
#endif /*   _WIN32 */

    /*
     * go on a free'ing spree...
     */
    free(about->algorithm_name);
    free(about->algorithm_authors);
    free(about->algorithm_copyright);
    free(about->algorithm_licence);
    free(about->algorithm_year);
    free(about->algorithm_block);

    free(about->key_name);
    free(about->key_authors);
    free(about->key_copyright);
    free(about->key_licence);
    free(about->key_year);
    free(about->key_size);

    free(about->module_authors);
    free(about->module_copyright);
    free(about->module_licence);
    free(about->module_version);
    free(about->module_comment);

    free(about);

#ifdef _DLFCN_H
    dlclose(file_mod);
#endif

    textview_about = lookup_widget(window_about, "textview_about");
    gtk_text_buffer_insert_at_cursor(gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview_about)), details, -1);
}


void on_button_do_clicked(GtkWidget *widget)
{
    char *filename_in  = NULL;
    char *filename_out = NULL;
    char *filename_mod = NULL;

    int64_t  file_in  = -1;
    int64_t  file_out = -1;
#ifndef _WIN32
    void    *file_mod = NULL;
#else  /* ! _WIN32 */
    HANDLE   file_mod = NULL;
#endif /*   _WIN32 */

    char    *key_plain = NULL;
    uint8_t *key_data  = NULL;
    uint8_t  key_type  = NOTSET;

    uint8_t function = NOTSET;

    int64_t (*fp)(int64_t, int64_t, uint8_t *);

    errno = EXIT_SUCCESS;

    /* 
     * bring up the popup whilst everything happens
     */
    GtkWidget *window_wait;
    window_wait = create_window_wait();
    gtk_widget_show(window_wait);
    GtkWidget *button_wait_close = lookup_widget(window_wait, "button_wait_close");
    GtkWidget *label_text = lookup_widget(window_wait, "label_wait");

    /* 
     * get the name of the file to do something to
     */
    GtkFileChooser *filechooser_in = (GtkFileChooser *)lookup_widget(GTK_WIDGET(widget), "filechooserbutton_in_file");
    if (!gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(filechooser_in)))
    {
        gtk_label_set_text((GtkLabel *)label_text, "Missing: file to en/decrypt");
        gtk_widget_set_sensitive(button_wait_close, true);
        return;
    }
    filename_in = strdup((char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(filechooser_in)));
    /* 
     * get the name of the destination directory and then the name of the file
     */
    GtkFileChooser *dirchooser_out = (GtkFileChooser *)lookup_widget(GTK_WIDGET(widget), "filechooserbutton_out_dir");
    if (!gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dirchooser_out)))
    {
        gtk_label_set_text((GtkLabel *)label_text, "Missing: destination directory");
        gtk_widget_set_sensitive(button_wait_close, true);
        return;
    }
    GtkEntry *fileentry_out = (GtkEntry *)lookup_widget(GTK_WIDGET(widget), "entry_out_file");
    if (!strcmp(gtk_entry_get_text(GTK_ENTRY(fileentry_out)), ""))
    {
        gtk_label_set_text((GtkLabel *)label_text, "Missing: output file name");
        gtk_widget_set_sensitive(button_wait_close, true);
        return;
    }
#ifndef _WIN32
    asprintf(&filename_out, "%s/%s", (char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dirchooser_out)), (char *)gtk_entry_get_text(GTK_ENTRY(fileentry_out)));
#else  /* ! _WIN32 */
    filename_out = calloc(strlen((char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dirchooser_out))) + strlen((char *)gtk_entry_get_text(GTK_ENTRY(fileentry_out)) + 2), sizeof( char ));
    sprintf(filename_out, "%s/%s", (char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dirchooser_out)), (char *)gtk_entry_get_text(GTK_ENTRY(fileentry_out)));
#endif /*   _WIN32 */

    /* 
     * get the name of the passphrase file (if we can) else try for a password
     */
    GtkFileChooser *filechooser_key = (GtkFileChooser *)lookup_widget(GTK_WIDGET(widget), "filechooserbutton_key_file");
    if (gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(filechooser_key)))
    {
        GtkComboBox *filecombo_key = (GtkComboBox *)lookup_widget(GTK_WIDGET(widget), "combobox_keyfile");
        if (!gtk_combo_box_get_active(filecombo_key))
        {
            key_plain = strdup((char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(filechooser_key)));
            key_type = KEYFILE;
        }
        else
        {
            key_plain = strdup((char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(filechooser_key)));
            key_type = PASSFILE;
        }
    }
    else
    {
        GtkEntry *passwd = (GtkEntry *)lookup_widget(GTK_WIDGET(widget), "entry_password");
        if (!strcmp(gtk_entry_get_text(GTK_ENTRY(passwd)), ""))
        {
            free(filename_in);
            free(filename_out);
            gtk_label_set_text((GtkLabel *) label_text, "Missing: key file / passphrase file / password");
            gtk_widget_set_sensitive(button_wait_close, true);
            return;
        }
        key_plain = strdup((char *)gtk_entry_get_text(GTK_ENTRY(passwd)));
        key_type = PASSWORD;
    }

    /* 
     * does the user wish to encrypt or decrypt
     */
    GtkComboBox *enc = (GtkComboBox *)lookup_widget(GTK_WIDGET(widget), "combobox_process");
    if (!gtk_combo_box_get_active(enc))
        function = ENCRYPT;
    else
        function = DECRYPT;

    /* 
     * lastly we find out which algorithm the user wants to use
     */
    GtkComboBoxEntry *filecombo_mod = (GtkComboBoxEntry *)lookup_widget(GTK_WIDGET(widget), "comboboxentry_algorithm");
    if (!strcmp(gtk_combo_box_get_active_text(GTK_COMBO_BOX(filecombo_mod)), ""))
    {
        free(filename_in);
        free(filename_out);
        free(key_plain);
        gtk_label_set_text((GtkLabel *) label_text, "Missing: algorithm selection");
        gtk_widget_set_sensitive(button_wait_close, true);
        return;
    }
#ifndef _WIN32
    if (!strchr(gtk_combo_box_get_active_text(GTK_COMBO_BOX(filecombo_mod)), '/'))
        asprintf(&filename_mod, "/usr/lib/encrypt/lib/%s.so", gtk_combo_box_get_active_text(GTK_COMBO_BOX(filecombo_mod)));
#else  /* ! _WIN32 */
    if (!strchr(gtk_combo_box_get_active_text(GTK_COMBO_BOX(filecombo_mod)), '\\'))
    {
        filename_mod = calloc(strlen("/Program Files/encrypt/lib/") + strlen(gtk_combo_box_get_active_text(GTK_COMBO_BOX(filecombo_mod))) + 2, sizeof( char ));
        sprintf(filename_mod, "/Program Files/encrypt/lib/%s", gtk_combo_box_get_active_text(GTK_COMBO_BOX(filecombo_mod)));
    }
#endif /*   _WIN32 */
    else
        filename_mod = strdup(gtk_combo_box_get_active_text(GTK_COMBO_BOX(filecombo_mod)));
    /*
     * open the plugin
     */
    if (!(file_mod = open_mod(filename_mod)))
    {
        free(filename_in);
        free(filename_out);
        free(key_plain);
        free(filename_mod);
        gtk_label_set_text((GtkLabel *) label_text, "Error: could not open plugin");
        gtk_widget_set_sensitive(button_wait_close, true);
        return;
    }
    free(filename_mod);

    /* 
     * now open all of the files - if we can't then something has happened to
     * them since the user selected them or they don't have permission to
     * read/write them
     */
    if ((file_in = open(filename_in, O_RDONLY | O_BINARY | F_RDLCK)) < 0)
    {
#ifdef _DLFCN_H
        dlclose(file_mod);
#endif /* _DLFCN_H */
        free(filename_in);
        free(filename_out);
        free(key_plain);
        gtk_label_set_text((GtkLabel *)label_text, "Error: could not access input file");
        gtk_widget_set_sensitive(button_wait_close, true);
        return;
    }
    free(filename_in);
    if ((file_out = open(filename_out, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | F_WRLCK, S_IRUSR | S_IWUSR)) < 0)
    {
#ifdef _DLFCN_H
        dlclose(file_mod);
#endif /* _DLFCN_H */
        close(file_in);
        free(filename_out);
        free(key_plain);
        gtk_label_set_text((GtkLabel *)label_text, "Error: could not access/create output file");
        gtk_widget_set_sensitive(button_wait_close, true);
        return;
    }
    free(filename_out);
    /* 
     * if we're using a key directly then do that, else if we're not using a
     * password - that is, we're generating a key from a file instead - do
     * that (passwords come later)
     */
    if (!(key_data = key_calculate(file_mod, key_plain, key_type)))
    {
#ifdef _DLFCN_H
        dlclose(file_mod);
#endif /* _DLFCN_H */
        close(file_in);
        close(file_out);
        free(key_plain);
        gtk_label_set_text((GtkLabel *)label_text, "Error: could not create key");
        gtk_widget_set_sensitive(button_wait_close, true);
        return;
    }
    free(key_plain);

    /* 
     * search for the function we want - if we were able to load the module
     * then it should be there
     */
#ifndef _WIN32
    if (!(fp = (int64_t (*)(int64_t, int64_t, uint8_t *))dlsym(file_mod, function == ENCRYPT ? "plugin_encrypt" : "plugin_decrypt")))
#else
    if (!(fp = (int64_t)GetProcAddress(file_mod, function == ENCRYPT ? "plugin_encrypt" : "plugin_decrypt")))
#endif
    {
#ifdef _DLFCN_H
        dlclose(file_mod);
#endif /* _DLFCN_H */
        close(file_in);
        close(file_out);
        free(key_data);
        gtk_label_set_text((GtkLabel *)label_text, "Error: could not import module function");
        gtk_widget_set_sensitive(button_wait_close, true);
        return;
    }

    /* 
     * we fork a child process to do the actual encrypting so that the parent can draw the message box to keep the user
     * happy - this also means the window says updated and doesn't become blanked by other windows moving over it
     *
     * it's not a problem that we haven't forked before here because at all previous points where we alter one of the
     * visible windows we return almost immediately, thus gtk can redraw automatically for us
     */
    args_t *a = calloc(1, sizeof( args_t ));
    a->fp       = fp;
    a->file_in  = file_in;
    a->file_out = file_out;
    a->key_data = key_data;

    pthread_t thrd;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_create(&thrd, &attr, thread_main, (void *)a);

    /* need to keep gui drawn correctly */
    while (gtk_events_pending())
        gtk_main_iteration();

    void *s;
    pthread_join(thrd, &s);

    /* 
     * free remaining data blocks, close all files
     */
    free(key_data);
#ifdef _DLFCN_H
    dlclose(file_mod);
#endif
    close(file_in);
    close(file_out);
    if (*((int64_t *)s) == EXIT_SUCCESS)
        gtk_label_set_text((GtkLabel *)label_text, "Done");
    else
        gtk_label_set_text((GtkLabel *)label_text, "Error: an unexpected error occured");
    gtk_widget_set_sensitive(button_wait_close, true);

    return;
}


void *thread_main(void *arg)
{
    args_t *a = arg;
    int64_t s = a->fp(a->file_in, a->file_out, a->key_data);
    pthread_exit((void *)&s);
}


void on_button_generate_clicked(void)
{
    gtk_widget_show(create_window_generate());
}


void on_button_gen_go_clicked(GtkWidget *widget)
{
    GtkSpinButton *keysize = (GtkSpinButton *)lookup_widget(GTK_WIDGET(widget), "spinbutton_size");
    uint64_t l = (gtk_spin_button_get_value_as_int(keysize)) / 8;
    char *h = calloc(l * 2, sizeof( char ));
    srand48(time(0));
    for (uint64_t i = 0; i < l; i++)
#ifndef _WIN32
        asprintf(&h, "%s%02X", h, (uint8_t)(lrand48() % 256));
#else
        sprintf(h, "%s%02X", h, (uint8_t)(lrand48() % 256));
#endif
    GtkEntry *display_size = (GtkEntry *)lookup_widget(GTK_WIDGET(widget), "entry_display_size");
    gtk_entry_set_text(display_size, h);
    free(h);
    return;
}


/*
 * these three functions are like ronseal
 */
void on_button_about_close_clicked(GtkWidget *widget)
{
    gtk_widget_destroy(lookup_widget(GTK_WIDGET(widget), "window_about"));
}


void on_button_wait_close_clicked(GtkWidget *widget)
{
    gtk_widget_destroy(lookup_widget(GTK_WIDGET(widget), "window_wait"));
}


/*
 * actually this function also does a few extra things...
 */
void on_button_gen_close_clicked(GtkWidget *widget)
{
    /* 
     * get the name of the directory and then the name of the file to save the key to
     */
    GtkFileChooser *outdir = (GtkFileChooser *)lookup_widget(GTK_WIDGET(widget), "filechooserbutton_gen_save");
    if (gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(outdir)) == NULL)
    {
        gtk_widget_destroy(lookup_widget(GTK_WIDGET(widget), "window_generate"));
        return;
    }
    GtkEntry *outfile = (GtkEntry *) lookup_widget(GTK_WIDGET(widget), "entry_gen_save_name");
    if (strcmp(gtk_entry_get_text(GTK_ENTRY(outfile)), "") == 0)
    {
        gtk_widget_destroy(lookup_widget(GTK_WIDGET(widget), "window_generate"));
        return;
    }
    char *out_filename = NULL;

#ifndef _WIN32
    asprintf(&out_filename, "%s/%s", (char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(outdir)), (char *)gtk_entry_get_text(GTK_ENTRY(outfile)));
#else
    out_filename = malloc(strlen((char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(outdir))) + strlen((char *)gtk_entry_get_text(GTK_ENTRY(outfile)) + 2));
    sprintf(out_filename, "%s/%s", (char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(outdir)), (char *)gtk_entry_get_text(GTK_ENTRY(outfile)));
#endif
    /* 
     * now get the key from the text box
     */
    GtkEntry *k = (GtkEntry *)lookup_widget(GTK_WIDGET(widget), "entry_display_size");
    if (strcmp(gtk_entry_get_text(GTK_ENTRY(k)), "") == 0)
    {
        gtk_widget_destroy(lookup_widget(GTK_WIDGET(widget), "window_generate"));
        return;
    }
    char *key = strdup((char *)gtk_entry_get_text(GTK_ENTRY(k)));
    int file;

    if ((file = open(out_filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0)
    {
        gtk_widget_destroy(lookup_widget(GTK_WIDGET(widget), "window_generate"));
        return;
    }
    free(out_filename);
    write(file, key, strlen(key));
    close(file);
    gtk_widget_destroy(lookup_widget(GTK_WIDGET(widget), "window_generate"));
}


void on_entry_gen_save_name_changed(GtkWidget *widget)
{
    GtkEntry *outfile = (GtkEntry *) lookup_widget(GTK_WIDGET(widget), "entry_gen_save_name");
    GtkLabel *label5 = (GtkLabel *) lookup_widget(GTK_WIDGET(widget), "label5");
    GtkImage *image5 = (GtkImage *) lookup_widget(GTK_WIDGET(widget), "image5");
    if (strcmp(gtk_entry_get_text(GTK_ENTRY(outfile)), "") == 0)
    {
        gtk_label_set_markup_with_mnemonic(label5, "_Close");
        gtk_image_set_from_stock(image5, "gtk-close", GTK_ICON_SIZE_BUTTON);
        return;
    }
    gtk_label_set_markup_with_mnemonic(label5, "_Save");
    gtk_image_set_from_stock(image5, "gtk-save", GTK_ICON_SIZE_BUTTON);
    return;
}
