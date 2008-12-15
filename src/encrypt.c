/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2007, albinoloverats ~ Software Development
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

#ifndef _WIN32 /* if we're compiling a 'proper' os (ie not windows) ... */
#include <dlfcn.h>
#else
#include <windows.h>
#endif

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <dirent.h>
#include <getopt.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "encrypt.h"
#include "plugins.h"

#ifdef _BUILD_GUI_
#include <gtk/gtk.h>
#include "interface.h"
#include "support.h"
#endif

/*
 * if we're building the GUI then these get defined here as globals, else
 * they're local to main only (below)
 */
#ifdef _BUILD_GUI_
char *in_filename = NULL, *out_filename = NULL, *key_filename = NULL, *pass_filename = NULL, *password = NULL, *plugin = NULL, *function = NULL;
#endif

int main(int argc, char **argv)
{
    char *errstr = NULL;

#ifndef _WIN32
    void *module = NULL;
#else
    HANDLE module;
#endif
    void *key_block = NULL, *(*key_read)(int), *(*gen_file)(int), *(*gen_text)(void *, long unsigned);

#ifndef _BUILD_GUI_
    char *in_filename = NULL, *out_filename = NULL, *key_filename = NULL, *pass_filename = NULL, *password = NULL, *plugin = NULL, *function = NULL;
#endif
    char unsigned enc = FALSE, pass = FALSE, key = FALSE;
    int opt = 0, in_file = 0, out_file = 1, key_file = -1, pass_file = -1, *(*exec_plugin)(int, int, void *);

    errno = 0;
#ifndef _BUILD_GUI_
    /* 
     * start as we mean to go on...
     */
    if (argc < 2)
    {
        show_usage();
        return EXIT_FAILURE;
    }
#endif
    /* 
     * get all of the command line options and arguments - note that if the
     * plugin string contains / then we treat it as a path to the plugin,
     * instead of allowing the system to find it
     */
    while (TRUE)
    {
        static struct option long_options[] = {
            {"in"      , required_argument, 0, 'i'},
            {"out"     , required_argument, 0, 'o'},
            {"keyfile" , required_argument, 0, 'k'},
            {"passfile", required_argument, 0, 'f'},
            {"password", required_argument, 0, 'p'},
            {"encrypt" , required_argument, 0, 'e'},
            {"decrypt" , required_argument, 0, 'd'},
            {"generate", required_argument, 0, 'g'},
            {"about"   , required_argument, 0, 'a'},
            {"modules" ,       no_argument, 0, 'm'},
            {"help"    ,       no_argument, 0, 'h'},
            {"licence" ,       no_argument, 0, 'l'},
            {"version" ,       no_argument, 0, 'v'},
            {0, 0, 0, 0}
        };
        int optex = 0;

        opt = getopt_long(argc, argv, "i:o:k:f:p:e:d:g:a:mhlv", long_options, &optex);
        if (opt == -1)
            break;
        switch (opt)
        {
            case 'i':
                in_filename = strdup(optarg);
                break;
            case 'o':
                out_filename = strdup(optarg);
                break;
            case 'k':
                key_filename = strdup(optarg);
                key = TRUE;
                pass = FALSE;
                break;
            case 'f':
                pass_filename = strdup(optarg);
                key = FALSE;
                pass = FALSE;
                break;
            case 'p':
                password = strdup(optarg);
                key = FALSE;
                pass = TRUE;
                break;
            case 'e':
#ifndef _WIN32
                if (strchr(optarg, '/') == NULL)
                    asprintf(&plugin, "%s.so", optarg);
#else
                if (strchr(optarg, '\\') == NULL)
                {
                    plugin = calloc(strlen(optarg) + 5, sizeof (char));
                    sprintf(plugin, "%s.dll", optarg);
                }
#endif
                else
                    plugin = strdup(optarg);
                function = strdup("enc_main");
                enc = TRUE;
                break;
            case 'd':
#ifndef _WIN32
                if (strchr(optarg, '/') == NULL)
                    asprintf(&plugin, "%s.so", optarg);
#else
                if (strchr(optarg, '\\') == NULL)
                {
                    plugin = calloc(strlen(optarg) + 5, sizeof (char));
                    sprintf(plugin, "%s.dll", optarg);
                }
#endif
                else
                    plugin = strdup(optarg);
                function = strdup("dec_main");
                enc = FALSE;
                break;
            case 'a':
                return algorithm_info(optarg);
            case 'g':
                return generate_key(optarg, key_filename);
            case 'h':
                show_help();
                return EXIT_SUCCESS;
            case 'l':
                show_licence();
                return EXIT_SUCCESS;
            case 'm':
                list_modules();
                return EXIT_SUCCESS;
            case 'v':
                show_version();
                return EXIT_SUCCESS;
            case '?':
                return EXIT_FAILURE;
            default:
                return EXIT_FAILURE;
                /* 
                 * it's worth noting that unknown options cause encrypt to
                 * bail
                 */
        }
    }
#ifdef _BUILD_GUI_
    /* 
     * now we've parsed the command line arguments, try and draw the gui (if
     * we've been told to build it) and if we can; also, if enough options are
     * passed we might as well do something with them...
     */
    if (!gtk_init_check(&argc, &argv))
    {
        fprintf(stderr, "%s: could not initialize GTK interface\n", NAME);
        show_usage();
        return EXIT_FAILURE;
    }
    if ((((in_filename == NULL) && (out_filename == NULL)) || (plugin == NULL) || ((key_filename == NULL) && (pass_filename == NULL) && (password == NULL))))
    {
        GtkWidget *window_main;

#ifdef ENABLE_NLS
        bindtextdomain(GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
        bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
        textdomain(GETTEXT_PACKAGE);
#endif
        gtk_set_locale();
        add_pixmap_directory("./pixmap");
#ifndef _WIN32
        add_pixmap_directory("/usr/lib/encrypt/pixmap");
#else
        add_pixmap_directory("/Program Files/encrypt/pixmap");
#endif
        window_main = create_window_main();
        gtk_widget_show(window_main);
        gtk_main();
        return EXIT_SUCCESS;
    }
    else
    {
#endif
        /* 
         * done that, now check everything is okay - note that we need to
         * check this in case the gui could not be dran
         */
        if (plugin == NULL)
        {
            fprintf(stderr, "%s: missing options -- e  or -- d\n", NAME);
            return EXIT_FAILURE;
        }
        if ((key_filename == NULL) && (pass_filename == NULL) && (password == NULL))
        {
            fprintf(stderr, "%s: missing options -- k  or -- f or -- p\n", NAME);
            return EXIT_FAILURE;
        }
        /* 
         * open the files iff we have a name for them, otherwise stick with
         * the defaults (stdin/stdout) defined above
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
                return errno;
            }
            free(in_filename);
        }
        if (out_filename != NULL)
        {
            if ((out_file = open(out_filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | F_WRLCK, S_IRUSR | S_IWUSR)) < 0)
            {
#ifndef _WIN32
                asprintf(&errstr, "%s: could not access/create output file %s  ", NAME, out_filename);
#else
                errstr = calloc(strlen(NAME) + strlen(": could not access/create output file ") + strlen(out_filename) + 2, sizeof (char));
                sprintf(errstr, "%s: could not access/create output file %s ", NAME, out_filename);
#endif
                perror(errstr);
                return errno;
            }
            free(out_filename);
        }
        /* 
         * if we're using a key directly then do that, else if we're not using
         * a password - that is, we're generating a key from a file instead -
         * do that (passwords come later)
         */
        if ((key) && (!pass))
        {
            if ((key_file = open(key_filename, O_RDONLY | O_BINARY | F_RDLCK)) < 0)
            {
#ifndef _WIN32
                asprintf(&errstr, "%s: could not access fey file %s ", NAME, key_filename);
#else
                errstr = calloc(strlen(NAME) + strlen(": could not access key file ") + strlen(key_filename) + 2, sizeof (char));
                sprintf(errstr, "%s: could not access key file %s ", NAME, key_filename);
#endif
                perror(errstr);
                return errno;
            }
            free(key_filename);
        }
        else if ((!key) && (!pass))
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
                return errno;
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
#else
        if ((module = LoadLibrary(plugin)) == NULL)
        {
#endif
            fprintf(stderr, "%s: could not open plugin %s\n%s\n", NAME, plugin, dlerror());
            return EXIT_FAILURE;
        }
        /* 
         * search for the function we want - if we were able to load the
         * module then it should be there
         */
#ifndef _WIN32
        if ((exec_plugin = (int *(*)(int, int, void *))dlsym(module, function)) == NULL)
        {
#else
        if ((exec_plugin = (void *)GetProcAddress(module, function)) == NULL)
        {
#endif
            fprintf(stderr, "%s: could not import module function for %sryption\n%s\n", NAME, enc ? "enc" : "dec", dlerror());
            return EXIT_FAILURE;
        }
        free(function);
        /* 
         * now it's time to generate the key from the data provided - let's
         * allow the plugin to do what it wants, returning a pointer to the
         * key it will use NOTE: the middle of the three if's does not
         * generate a key, it reads a previously generated key from a file
         */
        if ((!key) && (pass))
        {
#ifndef _WIN32
            if ((gen_text = (void *(*)(void *, long unsigned))dlsym(module, "gen_text")) == NULL)
            {
#else
            if ((gen_text = (void *)GetProcAddress(module, "gen_text")) == NULL)
            {
#endif
                fprintf(stderr, "%s: could not import key from text generating function\n%s\n", NAME, dlerror());
                return EXIT_FAILURE;
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
                return errno;
            }
        }
        else if ((key) && (!pass))
        {
#ifndef _WIN32
            if ((key_read = (void *(*)(int))dlsym(module, "key_read")) == NULL)
            {
#else
            if ((key_read = (void *)GetProcAddress(module, "key_read")) == NULL)
            {
#endif
                fprintf(stderr, "%s: cound not import key file reading function\n%s\n", NAME, dlerror());
                return EXIT_FAILURE;
            }
            if ((key_block = key_read(key_file)) == NULL)
            {
#ifndef _WIN32
                asprintf(&errstr, "%s: could not read key from file", NAME);
#else
                errstr = calloc(strlen(NAME) + strlen(": could not read key from file ") + 2, sizeof (char));
                sprintf(errstr, "%s: could not read key from file ", NAME);
#endif
                perror(errstr);
                return errno;
            }
            close(key_file);
        }
        else if ((!key) && (!pass))
        {
#ifndef _WIN32
            if ((gen_file = (void *(*)(int))dlsym(module, "gen_file")) == NULL)
            {
#else
            if ((gen_file = (void *)GetProcAddress(module, "gen_file")) == NULL)
            {
#endif
                fprintf(stderr, "%s: could not import key from file generating function\n%s\n", NAME, dlerror());
                return EXIT_FAILURE;
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
                return errno;
            }
            close(pass_file);
        }
        /* 
         * we made it - if we reach here then everything is okay and we're now
         * ready to start :)
         */
        errno = (long)exec_plugin(in_file, out_file, key_block);
        /* 
         * if there's an error tell the user - however it's unlikely we'll
         * know exactly what the error is
         */
        if (errno != EXIT_SUCCESS)
        {
#ifndef _WIN32
            asprintf(&errstr, "%s: an unexpected error occured ", NAME);
#else
            errstr = calloc(strlen(NAME) + strlen(": an unexpected error occured ") + 2, sizeof (char));
            sprintf(errstr, "%s: an unexpected error occured ", NAME);
#endif
            perror(errstr);
        }
        /* 
         * close all open files obviously if in_file / out_file are stdin /
         * stdout it makes no sense to close them
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
        return EXIT_SUCCESS;
#ifdef _BUILD_GUI_
    }
#endif
}

int algorithm_info(char *algorithm)
{
    /* 
     * set everything up so we can get some info about the given algorithm
     */
    char *plugin = NULL;
    struct about_info about, (*about_plugin)(void); 
    errno = 0;
#ifndef _WIN32
    void *module;

    if (strchr(algorithm, '/') == NULL)
        asprintf(&plugin, "%s.so", algorithm);
#else
    HANDLE module;

    if (strchr(algorithm, '\\') == NULL)
    {
        plugin = calloc(strlen(algorithm) + 5, sizeof (char));
        sprintf(plugin, "%s.dll", algorithm);
    }
#endif
    else
        plugin = strdup(algorithm);
    /* 
     * find the plugin, open it, etc...
     */
#ifndef _WIN32
    if ((module = dlopen(plugin, RTLD_LAZY)) == NULL)
    {
#else
    if ((module = LoadLibrary(plugin)) == NULL)
    {
#endif
#ifdef _DLFCN_H
        fprintf(stderr, "%s: could not open plugin %s\n%s\n", NAME, plugin, dlerror());
#endif
        return EXIT_FAILURE;
    }
    free(plugin);
#ifndef _WIN32
    if ((about_plugin = (struct about_info(*)(void))dlsym(module, "about")) == NULL)
    {
#else
    if ((about_plugin = (void *)GetProcAddress(module, "about")) == NULL)
    {
#endif
        fprintf(stderr, "%s: could not find plugin information\n%s\n", NAME, dlerror());
        return EXIT_FAILURE;
    }
    /* 
     * now get the info
     */
    about = about_plugin();
    fprintf(stdout, "Algorithm Details\n");
    fprintf(stdout, "  Name       : %s\n", about.a_name);
    fprintf(stdout, "  Authors    : %s\n", about.a_authors);
    fprintf(stdout, "  Copyright  : %s\n", about.a_copyright);
    fprintf(stdout, "  Licence    : %s\n", about.a_licence);
    fprintf(stdout, "  Year       : %s\n", about.a_year);
    fprintf(stdout, "  Block size : %s\n", about.a_block);
    fprintf(stdout, "\nKey Details\n");
    fprintf(stdout, "  Name       : %s\n", about.k_name);
    fprintf(stdout, "  Authors    : %s\n", about.k_authors);
    fprintf(stdout, "  Copyright  : %s\n", about.k_copyright);
    fprintf(stdout, "  Licence    : %s\n", about.k_licence);
    fprintf(stdout, "  Year       : %s\n", about.k_year);
    fprintf(stdout, "  Key size   : %s\n", about.k_size);
    fprintf(stdout, "\nPlugin Details\n");
    fprintf(stdout, "  Authors    : %s\n", about.m_authors);
    fprintf(stdout, "  Copyright  : %s\n", about.m_copyright);
    fprintf(stdout, "  Licence    : %s\n", about.m_licence);
    fprintf(stdout, "  Version    : %s\n", about.m_version);
    fprintf(stdout, "\nAdditional Details\n");
    fprintf(stdout, "  %s\n", about.o_comment);
    /* 
     * finally close the module and return
     */
#ifdef _DLFCN_H
    dlclose(module);
#endif
    return errno;
}

int generate_key(char *s, char *file)
{
    /* 
     * generate a key (for later use) of a given size - it's up to each
     * algorithm plugin to decide how to use a given key file (all keys are in
     * hex)
     */
    FILE *out = stdout;
    int size = strtol(s, NULL, 10) / 8, part = 0;
    char *errstr = NULL;

#ifndef _WIN32
    srand48(time(0));
#else
    srand(time(0));
#endif
    /* 
     * either print the hex key to stdout, or to a file if we can
     */
    if (file != NULL)
    {
        if ((out = fopen(file, "w")) == NULL)
        {
#ifndef _WIN32
            asprintf(&errstr, "%s: could not access/create key file %s ", NAME, file);
#else
            errstr = calloc(strlen(NAME) + strlen(": could not access/create key file ") + strlen(file) + 2, sizeof (char));
            sprintf(errstr, "%s: could not access/create key file %s ", NAME, file);
#endif
            perror(errstr);
            return errno;
        }
        free(file);
    }
    for (int loop = 0; loop < size; loop++)
    {
#ifndef _WIN32
        part = lrand48() % 256;
#else
        part = rand() % 256;
#endif
        fprintf(out, "%02X", part);
    }
    return errno;
}

void list_modules(void)
{
    /*
     * list all modules which are installed in /usr/lib/encrypt
     */
    fprintf(stdout, "Installed Modules:\n");
#ifndef _WIN32
    /* 
     * linux version is much nicer than the windows (this is becoming common)
     */
    struct dirent **eps;
    int n = scandir("/usr/lib/encrypt/lib", &eps, NULL, alphasort);
    if (n >= 0)
    {
        for (int cnt = 0; cnt < n; ++cnt)
            if (strstr(eps[cnt]->d_name, ".so") != NULL)
#ifdef linux
                fprintf(stdout, "  %s\n", strndup(eps[cnt]->d_name, strlen(eps[cnt]->d_name) - 3));
#else
            {
                char *tfn = calloc(strlen(eps[cnt]->d_name), sizeof (char));
                memcpy(tfn, eps[cnt]->d_name, strlen(eps[cnt]->d_name) - 3);
                fprintf(stdout, "  %s\n", tfn);
            }
#endif
#else
    DIR *dp;
    dp = opendir("/Program Files/encrypt/lib");
    if (dp != NULL)
    {
        struct dirent *ep;
        while ((ep = readdir(dp)))
            if (strstr(ep->d_name, ".dll"))
                fprintf(stdout, "  %s\n", ep->d_name);
        (void)closedir(dp);
#endif
    }

}

void show_help(void)
{
    /* 
     * boo
     */
    show_version();
    show_usage();
    fprintf(stderr, "\nOptions:\n\n");
    fprintf(stderr, "  -i, --in       FILE        Input file\n");
    fprintf(stderr, "  -o, --out      FILE        Output file\n");
    fprintf(stderr, "  -k, --keyfile  FILE        Key file (must come first if generating a key)\n");
    fprintf(stderr, "  -f, --passfile FILE        File to use as passphrase to generate key\n");
    fprintf(stderr, "  -p, --password PASSWORD    Use given password to generate key\n");
    fprintf(stderr, "  -e, --encrypt  ALGORITHM   Algorithm to use for encryption\n");
    fprintf(stderr, "  -d, --decrypt  ALGORITHM   Algorithm to use for decryption\n");
    fprintf(stderr, "  -a, --about    ALGORITHM   Information about a particular algorithm\n");
    fprintf(stderr, "  -g, --generate SIZE        Generate a key of specified size (in bits)\n");
    fprintf(stderr, "  -m, --modules              List all installed modules\n");
    fprintf(stderr, "  -h, --help                 This help list\n");
    fprintf(stderr, "  -l, --licence              An overview of the GNU GPL\n");
    fprintf(stderr, "  -v, --version              Show version number and quit\n\n");
    fprintf(stderr, "If -i or -o are omitted then stdin/stdout are used.  Either -e or -d must be\n");
    fprintf(stderr, "present if you intend to do something, as well as -k -f or -p. Using -g will\n");
    fprintf(stderr, "generate a random key and echo it to stdout unless -g is preceded by -k; the\n");
    fprintf(stderr, "key can be used later with the -k option. However -a -m -h -l -v may be used\n");
    fprintf(stderr, "on their own or not at all.\n");
}

void show_licence(void)
{
    /* 
     * simple GNU GPL blurb
     */
    fprintf(stderr, "This program is free software: you can redistribute it and/or modify\n");
    fprintf(stderr, "it under the terms of the GNU General Public License as published by\n");
    fprintf(stderr, "the Free Software Foundation, either version 3 of the License, or\n");
    fprintf(stderr, "(at your option) any later version.\n\n");
    fprintf(stderr, "This program is distributed in the hope that it will be useful,\n");
    fprintf(stderr, "but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
    fprintf(stderr, "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
    fprintf(stderr, "GNU General Public License for more details.\n\n");
    fprintf(stderr, "You should have received a copy of the GNU General Public License\n");
    fprintf(stderr, "along with this program.  If not, see <http://www.gnu.org/licenses/>.\n");
}

void show_usage(void)
{
    /* 
     * c'mon! how hard is this!
     */
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [OPTION] [ARGUMENT] ...\n", NAME);
}

void show_version(void)
{
    /* 
     * i suppose this really should just print a simple numerical value, but
     * what the heck...
     */
    fprintf(stderr, "%s version %s\n", NAME, VERSION);
}
