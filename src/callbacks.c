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
#endif

#ifndef _WIN32
#include <dlfcn.h>
#include <sys/wait.h>
#else
#include <windows.h>
#endif

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <getopt.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <gtk/gtk.h>

#include "encrypt.h"
#include "plugins.h"

#include "callbacks.h"
#include "interface.h"
#include "support.h"


void on_button_about_clicked(GtkWidget *widget)
{
    /* 
     * woot woot - this is the about box :p
     */
    GtkWidget *window_about, *textview_about;

    window_about = create_window_about();
    gtk_widget_show(window_about);
    /* 
     * find out which algorithm the user wants to know about; if no algorithm
     * is selected then just return all happy :)
     */
    GtkComboBoxEntry *alg = (GtkComboBoxEntry *)lookup_widget(GTK_WIDGET(widget), "comboboxentry_algorithm");
    if (strcmp(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)), "") == 0)
        return;
    /* 
     * set everything up so we can get some info about the given algorithm
     */
    char *plugin = NULL, *details = NULL;
    struct about_info about, (*about_plugin) (void);

    errno = 0;
#ifndef _WIN32
    char *errstr = NULL;
    void *module;

    if (strchr(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)), '/') == NULL)
        asprintf(&plugin, "/usr/lib/encrypt/lib/%s.so", gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)));
#else
    HANDLE module;

    if (strchr(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)), '\\') == NULL)
    {
        plugin = calloc(strlen(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg))) + 24, sizeof (char));
        sprintf(plugin, "/Program Files/encrypt/lib/%s", gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)));
    }
#endif
    else
        plugin = strdup(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)));
    /* 
     * find the plugin, open it, etc...
     */
#ifndef _WIN32
    if ((module = dlopen(plugin, RTLD_LAZY)) == NULL)
    {
        errstr = dlerror();
        asprintf(&details, "\n%s: could not open plugin %s\n%s\n", NAME, plugin, errstr);
        fprintf(stderr, "%s: could not open plugin %s\n%s\n", NAME, plugin, errstr);
#else
    if ((module = LoadLibrary(plugin)) == NULL)
    {
        details = calloc(strlen(NAME) + strlen(": could not open plugin \n") + strlen(plugin) + 2, sizeof (char));
        sprintf(details, "\n%s: could not open plugin %s\n", NAME, plugin);
        fprintf(stderr, "\n%s: could not open plugin %s\n", NAME, plugin);
#endif
        goto cleanup;
    }
#ifndef _WIN32
    if ((about_plugin = (struct about_info(*)(void))dlsym(module, "about")) == NULL) {
        errstr = dlerror();
        asprintf(&details, "\n%s: could not find plugin information in %s\n%s\n", NAME, plugin, errstr);
        fprintf(stderr, "%s: could not find plugin information in %s\n%s\n", NAME, plugin, errstr);
#else
    if ((about_plugin = (void *)GetProcAddress(module, "about")) == NULL)
    {
        details = calloc(strlen(NAME) + strlen(": could not find plugin information in \n") + strlen(plugin) + 2, sizeof (char));
        sprintf(details, "\n%s: could not find plugin information in %s\n", NAME, plugin);
        fprintf(stderr, "\n%s: could not find plugin information in %s\n", NAME, plugin);
#endif
        goto cleanup;
    }
    free(plugin);
    /* 
     * now get the info
     */
    about = about_plugin();
#ifndef _WIN32
    asprintf(&details, "\nAlgorithm Details\n    Name\t\t: %s\n    Author\t\t: %s\n    Copyright\t: %s\n    Licence\t: %s\n    Year\t\t: %s\n    Block size\t: %s\n\nKey Details\n    Name\t\t: %s\n    Authors\t: %s\n    Copyright\t: %s\n    Licence\t: %s\n    Year\t\t: %s\n    Key size\t: %s\n\nPlugin Details\n    Authors\t: %s\n    Copyright\t: %s\n    Licence\t: %s\n    Version\t: %s\n\nAdditional Details\n    %s\n", about.a_name, about.a_authors, about.a_copyright, about.a_licence, about.a_year, about.a_block, about.k_name, about.k_authors, about.k_copyright, about.k_licence, about.k_year, about.k_size, about.m_authors, about.m_copyright, about.m_licence, about.m_version, about.o_comment);
#else
    /* 
     * woot for Windows
     */
    details = calloc(362 + strlen(about.a_name) + strlen(about.a_authors) + strlen(about.a_copyright) + strlen(about.a_licence) + strlen(about.a_year) + strlen(about.a_block) + strlen(about.k_name) + strlen(about.k_authors) + strlen(about.k_copyright) + strlen(about.k_licence) + strlen(about.k_year) + strlen(about.k_size) + strlen(about.m_authors) + strlen(about.m_copyright) + strlen(about.m_licence) + strlen(about.m_version) + strlen(about.o_comment), sizeof (char)); sprintf(details, "\nAlgorithm Details\n    Name\t\t: %s\n    Author\t\t: %s\n    Copyright\t: %s\n    Licence\t: %s\n    Year\t\t: %s\n    Block size\t: %s\n\nKey Details\n    Name\t\t: %s\n    Authors\t: %s\n    Copyright\t: %s\n    Licence\t: %s\n    Year\t\t: %s\n    Key size\t: %s\n\nPlugin Details\n    Authors\t: %s\n    Copyright\t: %s\n    Licence\t: %s\n    Version\t: %s\n\nAdditional Details\n    %s\n", about.a_name, about.a_authors, about.a_copyright, about.a_licence, about.a_year, about.a_block, about.k_name, about.k_authors, about.k_copyright, about.k_licence, about.k_year, about.k_size, about.m_authors, about.m_copyright, about.m_licence, about.m_version, about.o_comment);
#endif
    /* 
     * finally close the module, set the additional text and return
     */
  cleanup:
#ifdef _DLFCN_H
    if (module != NULL)
        dlclose(module);
#endif
    textview_about = lookup_widget(window_about, "textview_about");

    gtk_text_buffer_insert_at_cursor(gtk_text_view_get_buffer(GTK_TEXT_VIEW (textview_about)), details, -1);
}


void on_button_do_clicked(GtkWidget * widget)
{
    char *in_filename = NULL, *out_filename = NULL, *key_filename = NULL, *pass_filename = NULL, *errstr = NULL, *password = NULL, *plugin = NULL, *function = NULL;

#ifndef _WIN32
    void *module = NULL;
#else
    HANDLE module;
#endif
    void *key_block = NULL, *(*key_read)(int), *(*gen_file)(int), *(*gen_text)(void *, long unsigned);
    char unsigned pass = FALSE, key = FALSE;
    int in_file = 0, out_file = 1, key_file = -1, pass_file = -1, *(*exec_plugin)(int, int, void *);

    errno = 0;
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
    GtkFileChooser *infile = (GtkFileChooser *)lookup_widget(GTK_WIDGET(widget), "filechooserbutton_in_file");
    if (gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(infile)) == NULL)
    {
        gtk_label_set_text((GtkLabel *)label_text, "Missing: file to en/decrypt");
        gtk_widget_set_sensitive(button_wait_close, TRUE);
        return;
    }
    in_filename = strdup((char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(infile)));
    /* 
     * get the name of the destination directory and then the name of the file
     */
    GtkFileChooser *outdir = (GtkFileChooser *)lookup_widget(GTK_WIDGET(widget), "filechooserbutton_out_dir");
    if (gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(outdir)) == NULL)
    {
        gtk_label_set_text((GtkLabel *)label_text, "Missing: destination directory");
        gtk_widget_set_sensitive(button_wait_close, TRUE);
        return;
    }
    GtkEntry *outfile = (GtkEntry *)lookup_widget(GTK_WIDGET(widget), "entry_out_file");
    if (strcmp(gtk_entry_get_text(GTK_ENTRY(outfile)), "") == 0)
    {
        gtk_label_set_text((GtkLabel *)label_text, "Missing: output file name");
        gtk_widget_set_sensitive(button_wait_close, TRUE);
        return;
    }
#ifndef _WIN32
    asprintf(&out_filename, "%s/%s", (char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(outdir)), (char *)gtk_entry_get_text(GTK_ENTRY(outfile)));
#else
    out_filename = calloc(strlen((char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(outdir))) + strlen((char *)gtk_entry_get_text(GTK_ENTRY(outfile)) + 2), sizeof (char));
    sprintf(out_filename, "%s/%s", (char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(outdir)), (char *)gtk_entry_get_text(GTK_ENTRY(outfile)));
#endif
    /* 
     * get the name of the passphrase file (if we can) else try for a password
     */
    GtkComboBox *keyphrase = (GtkComboBox *)lookup_widget(GTK_WIDGET(widget), "combobox_keyfile");
    GtkFileChooser *keyfile = (GtkFileChooser *)lookup_widget(GTK_WIDGET(widget), "filechooserbutton_key_file");
    GtkEntry *passwd = (GtkEntry *)lookup_widget(GTK_WIDGET(widget), "entry_password");
    if (gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(keyfile)) != NULL)
    {
        if (gtk_combo_box_get_active(keyphrase) == 0)
        {
            key_filename = strdup((char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(keyfile)));
            key = TRUE;
            pass = FALSE;
        }
        else
        {
            pass_filename = strdup((char *)gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(keyfile)));
            key = FALSE;
            pass = FALSE;
        }
    }
    else
    {
        if (strcmp(gtk_entry_get_text(GTK_ENTRY(passwd)), "") == 0)
        {
            gtk_label_set_text((GtkLabel *) label_text, "Missing: key file / passphrase file / password");
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
        password = strdup((char *)gtk_entry_get_text(GTK_ENTRY(passwd)));
        key = FALSE;
        pass = TRUE;
    }
    /* 
     * does the user wish to encrypt or decrypt
     */

    GtkComboBox *enc = (GtkComboBox *) lookup_widget(GTK_WIDGET(widget), "combobox_process");
    if (gtk_combo_box_get_active(enc) == 0)
        function = strdup("enc_main");
    else
        function = strdup("dec_main");
    /* 
     * lastly we find out which algorithm the user wants to use
     */
    GtkComboBoxEntry *alg = (GtkComboBoxEntry *)lookup_widget(GTK_WIDGET(widget), "comboboxentry_algorithm");
    if (strcmp(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)), "") == 0)
    {
        gtk_label_set_text((GtkLabel *) label_text, "Missing: algorithm selection");
        gtk_widget_set_sensitive(button_wait_close, TRUE);
        return;
    }
#ifndef _WIN32
    if (strchr(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)), '/') == NULL)
        asprintf(&plugin, "/usr/lib/encrypt/lib/%s.so", gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)));
#else
    if (strchr(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)), '\\') == NULL)
    {
        plugin = calloc(strlen(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg))) + 24, sizeof (char));
        sprintf(plugin, "/Program Files/encrypt/lib/%s", gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)));
    }
#endif
    else
        plugin = strdup(gtk_combo_box_get_active_text(GTK_COMBO_BOX(alg)));
    /* 
     * now open all of the files - if we can't then something has happened to
     * them since the user selected them or they don't have permission to
     * read/write them
     */
    if (in_filename != NULL)
    {
        if ((in_file = open(in_filename, O_RDONLY | O_BINARY | F_RDLCK)) < 0)
        {
#ifndef _WIN32
            asprintf(&errstr, "%s: could not access input file %s ", NAME, in_filename);
#else
            errstr = calloc(strlen(NAME) + strlen(": could not access input file ") + strlen(in_filename) + 2, sizeof (char));
            sprintf(errstr, "%s: could not access input file %s ", NAME, in_filename);
#endif
            perror(errstr);
            gtk_label_set_text((GtkLabel *)label_text, errstr);
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
        free(in_filename);
    }
    if (out_filename != NULL)
    {
        if ((out_file = open(out_filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | F_WRLCK, S_IRUSR | S_IWUSR)) < 0)
        {
#ifndef _WIN32
            asprintf(&errstr, "%s: could not access/create output file %s ", NAME, out_filename);
#else
            errstr = calloc(strlen(NAME) + strlen(": could not access/create output file ") + strlen(out_filename) + 2, sizeof (char));
            sprintf(errstr, "%s: could not access/create output file %s ", NAME, out_filename);
#endif
            perror(errstr);
            gtk_label_set_text((GtkLabel *)label_text, errstr);
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
        free(out_filename);
    }
    /* 
     * if we're using a key directly then do that, else if we're not using a
     * password - that is, we're generating a key from a file instead - do
     * that (passwords come later)
     */
    if (key && !pass)
    {
        if ((key_file = open(key_filename, O_RDONLY | O_BINARY | F_RDLCK)) < 0)
        {
#ifndef _WIN32
            asprintf(&errstr, "%s: could not access passphrase file %s ", NAME, key_filename);
#else
            errstr = calloc(strlen(NAME) + strlen(": could not access passphrase file ") + strlen(key_filename) + 2, sizeof (char));
            sprintf(errstr, "%s: could not access passphrase file %s ", NAME, key_filename);
#endif
            perror(errstr);
            gtk_label_set_text((GtkLabel *)label_text, errstr);
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
        free(key_filename);
    }
    else if (!key && !pass)
    {
        if ((pass_file = open(pass_filename, O_RDONLY | O_BINARY | F_RDLCK)) < 0)
        {
#ifndef _WIN32
            asprintf(&errstr, "%s: could not access passphrase file %s ", NAME, pass_filename);
#else
            errstr = calloc(strlen(NAME) + strlen(": could not access passphrase file ") + strlen(pass_filename) + 2, sizeof (char));
            sprintf(errstr, "%s: could not access passphrase file %s ", NAME, pass_filename);
#endif
            perror(errstr);
            gtk_label_set_text((GtkLabel *)label_text, errstr);
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
        free(pass_filename);
    }
    /* 
     * find and load the encryption module if we can, otherwise fail and
     * alert the user
     */
#ifndef _WIN32
    if ((module = dlopen(plugin, RTLD_LAZY)) == NULL)
    {
        asprintf(&errstr, "%s: could not open plugin %s\n%s\n", NAME, plugin, dlerror());
#else
    if ((module = LoadLibrary(plugin)) == NULL)
    {
        errstr = calloc(strlen(NAME) + strlen(": could not open plugin ") + strlen(plugin) + 2, sizeof (char));
        sprintf(errstr, "%s: could not open plugin %s\n", NAME, plugin);
#endif
        fprintf(stderr, errstr);
        gtk_label_set_text((GtkLabel *)label_text, errstr);
        gtk_widget_set_sensitive(button_wait_close, TRUE);
        return;
    }
    /* 
     * search for the function we want - if we were able to load the module
     * then it should be there
     */
#ifndef _WIN32
    if ((exec_plugin = (int *(*)(int, int, void *))dlsym(module, function)) == NULL)
    {
        asprintf(&errstr, "%s: could not import module function for %sryption\n%s\n", NAME, enc ? "enc" : "dec", dlerror());
#else
    if ((exec_plugin = (void *)GetProcAddress(module, function)) == NULL)
    {
        errstr = calloc(strlen(NAME) + strlen(": could not import module funtion for __ryption ") + 2, sizeof (char));
        sprintf(errstr, "%s: could not import module funtion for %sryption\n", NAME, enc ? "enc" : "dec");
#endif
        fprintf(stderr, errstr);
        gtk_label_set_text((GtkLabel *)label_text, errstr);
        gtk_widget_set_sensitive(button_wait_close, TRUE);
        return;
    }
    free(function);
    /* 
     * now it's time to generate the key from the data provided - let's allow
     * the plugin to do what it wants, returning a pointer to the key it will
     * use NOTE: the middle of the three if's does not generate a key, it
     * reads a previously generated key from a file
     */
    if (!key && pass)
    {
#ifndef _WIN32
        if ((gen_text = (void *(*)(void *, long unsigned))dlsym(module, "gen_text")) == NULL)
        {
            asprintf(&errstr, "%s: could not import key from text generating function\n%s\n", NAME, dlerror());
#else
        if ((gen_text = (void *)GetProcAddress(module, "gen_text")) == NULL)
        {
            errstr = calloc(strlen(NAME) + strlen(": could not import key from text generating function") + 2, sizeof (char));
            sprintf(errstr, "%s: could not import key from text generating function\n", NAME);
#endif
            fprintf(stderr, errstr);
            gtk_label_set_text((GtkLabel *)label_text, errstr);
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
        if ((key_block = gen_text(password, strlen(password))) == NULL)
        {
#ifndef _WIN32
            asprintf(&errstr, "%s: could not create key from password ", NAME);
#else
            errstr = calloc(strlen(NAME) + strlen(": could not create key from password ") + 2, sizeof (char));
            sprintf(errstr, "%s: could not create key from password ", NAME);
#endif
            perror(errstr);
            gtk_label_set_text((GtkLabel *)label_text, errstr);
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
    }
    else if (key && !pass)
    {
#ifndef _WIN32
        if ((key_read = (void *(*)(int))dlsym(module, "key_read")) == NULL)
        {
            asprintf(&errstr, "%s: cound not import key file reading function\n%s\n", NAME, dlerror());
#else
        if ((key_read = (void *)GetProcAddress(module, "key_read")) == NULL)
        {
            errstr = calloc(strlen(NAME) + strlen(": could not import key file reading function\n") + 2, sizeof (char));
            sprintf(errstr, "%s: could not import key file reading function\n", NAME);
#endif
            fprintf(stderr, errstr);
            gtk_label_set_text((GtkLabel *)label_text, errstr);
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
        if ((key_block = key_read(key_file)) == NULL)
        {
#ifndef _WIN32
            asprintf(&errstr, "%s: could not read key from file ", NAME);
#else
            errstr = calloc(strlen(NAME) + strlen(": could not read key from file ") + 2, sizeof (char));
            sprintf(errstr, "%s: could not read key from file ", NAME);
#endif
            perror(errstr);
            gtk_label_set_text((GtkLabel *) label_text, errstr);
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
        close(key_file);
    }
    else if (!key && !pass)
    {
#ifndef _WIN32
        if ((gen_file = (void *(*)(int))dlsym(module, "gen_file")) == NULL)
        {
            asprintf(&errstr, "%s: could not import key from file generating function\n%s\n", NAME, dlerror());
#else
        if ((gen_file = (void *) GetProcAddress(module, "gen_file")) == NULL)
        {
            errstr = calloc(strlen(NAME) + strlen(": could not import key from file generating function\n") + 2, sizeof (char));
            sprintf(errstr, "%s: could not import key from file generating function\n", NAME);
#endif
            fprintf(stderr, errstr);
            gtk_label_set_text((GtkLabel *)label_text, errstr);
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
        if ((key_block = gen_file(pass_file)) == NULL)
        {
#ifndef _WIN32
            asprintf(&errstr, "%s: could not create key from file", NAME);
#else
            errstr = calloc(strlen(NAME) + strlen(": could not create key from file ") + 2, sizeof (char));
            sprintf(errstr, "%s: could not create key from file ", NAME);
#endif
            perror(errstr);
            gtk_label_set_text((GtkLabel *)label_text, errstr);
            gtk_widget_set_sensitive(button_wait_close, TRUE);
            return;
        }
        close(pass_file);
    }
    /* 
     * we fork a child process to do the actual encrypting so that the parent
     * can draw the message box to keep the user happy - this also means the
     * window says updated and doesn't become blanked by other windows moving
     * over it
     *
     * it's not a problem that we haven't forked before here because at all
     * previous points where we alter one of the visible windows we return
     * almost immediately, thus gtk can redraw automatically for us
     */
#ifndef _WIN32
    int status;
    pid_t pid = fork();

    if (!pid)
    {
#else
        /* 
         * you just have to love the elegence of this...
         */
        for (int loop = 0; loop < 10; loop++)
            gtk_main_iteration();
#endif
        /* 
         * we made it - if we reach here then everything is okay and we're now
         * ready to start :)
         */
    errno = (long)exec_plugin(in_file, out_file, key_block);
#ifndef _WIN32
        _exit(errno);
    }
    else if (pid == -1)
    {
        asprintf(&errstr, "%s: could not fork child process ", NAME);
        perror(errstr);
        status = errno;
    }
    else
    {
        while (!waitpid(pid, &status, WNOHANG))
            gtk_main_iteration_do(FALSE);
    }

    errno = status;
#endif
    /* 
     * close all open files
     */
    free(key_block);
    free(plugin);
#ifdef _DLFCN_H
    dlclose(module);
#endif
    if (in_file > 2)
        close(in_file);
    if (out_file > 2)
        close(out_file);
    if (errno == EXIT_SUCCESS)
        gtk_label_set_text((GtkLabel *)label_text, "Done");
    else
    {
#ifndef _WIN32
        asprintf(&errstr, "%s: an unexpected error occured ", NAME);
#else
        errstr = calloc(strlen(NAME) + strlen(": an unexpected error occured ") + 2, sizeof (char));
        sprintf(errstr, "%s: an unexected error occured ", NAME);
#endif
        perror(errstr);
        gtk_label_set_text((GtkLabel *) label_text, errstr);
    }

    gtk_widget_set_sensitive(button_wait_close, TRUE);
    return;
}


void on_button_generate_clicked(void)
{
    gtk_widget_show(create_window_generate());
}


void on_button_gen_go_clicked(GtkWidget *widget)
{
    GtkSpinButton *keysize = (GtkSpinButton *)lookup_widget(GTK_WIDGET(widget), "spinbutton_size");
    int part = 0, size = (gtk_spin_button_get_value_as_int(keysize)) / 8;

#ifndef _WIN32
    char *value = "";
    srand48(time(0));
#else
    char *value = calloc(size * 2, sizeof (char));
    srand(time(0));
#endif
    for (int loop = 0; loop < size; loop++)
    {
#ifndef _WIN32
        part = lrand48() % 256;
        asprintf(&value, "%s%02X", value, part);
#else
        part = rand() % 256;
        sprintf(value, "%s%02X", value, part);
#endif
    }
    GtkEntry *display_size = (GtkEntry *)lookup_widget(GTK_WIDGET(widget), "entry_display_size");
    gtk_entry_set_text(display_size, value);
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
     * get the name of the directory and then the name of the file to save the
     * key to
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
