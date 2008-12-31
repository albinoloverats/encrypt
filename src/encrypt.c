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

#ifdef HAVE_CONFIG_H
  #include <config.h>
#endif /* HAVE_CONFIG_H */

#ifndef _WIN32 /* if we're compiling a 'proper' os (ie not windows) ... */
  #include <dlfcn.h>
#else  /* ! _WIN32 */
  #include <windows.h>
#endif /*   _WIN32 */

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <dirent.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "encrypt.h"
#include "plugins.h"

#ifdef _BUILD_GUI_
  #include <gtk/gtk.h>
  #include "interface.h"
  #include "support.h"
#endif /* _BUILD_GUI_ */

/*
 * if we're building the GUI then these get defined here as globals, else they're local to main only (below)
 */
//#ifdef _BUILD_GUI_
//    char *filename_in  = NULL;
//    char *filename_out = NULL;
//    char    *key_plain = NULL;
//#endif /* _BUILD_GUI */

int main(int argc, char **argv)
{
    char *filename_in  = NULL;
    char *filename_out = NULL;

    int64_t  file_in  = STDIN_FILENO;
    int64_t  file_out = STDOUT_FILENO;
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

    if (signal(SIGINT, sigint) == SIG_ERR)
    {
        fprintf(stderr, "%s: could not set SIGINT handler\n", NAME);
        return errno;
    }

#ifndef _BUILD_GUI_
    /* 
     * start as we mean to go on...
     */
    if (argc < 2)
        return show_usage();
#endif /* _BUILD_GUI */
    /* 
     * get all of the command line options and arguments - note that if the plugin string contains / then we treat it
     * as a path to the plugin, instead of allowing the system to find it
     */
    while (true)
    {
        static struct option long_options[] =
        {
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
        int32_t optex = 0;
        int32_t opt = getopt_long(argc, argv, "i:o:k:f:p:e:d:g:a:mhlv", long_options, &optex);
        if (opt < 0)
            break;
        switch (opt)
        {
            case 'i':
                filename_in = strdup(optarg);
                break;
            case 'o':
                filename_out = strdup(optarg);
                break;
            case 'k':
                key_plain = strdup(optarg);
                key_type  = KEYFILE;
                break;
            case 'f':
                key_plain = strdup(optarg);
                key_type  = PASSFILE;
                break;
            case 'p':
                key_plain = strdup(optarg);
                key_type  = PASSWORD;
                break;
            case 'e':
                file_mod = open_mod(optarg);
                function = ENCRYPT;
                break;
            case 'd':
                file_mod = open_mod(optarg);
                function = DECRYPT;
                break;
            case 'a':
                return algorithm_info(optarg);
            case 'g':
                return key_generate(optarg, key_plain);
            case 'h':
                return show_help();
            case 'l':
                return show_licence();
            case 'm':
                return list_modules();
            case 'v':
                return show_version();
            case '?':
            default:
                die("%s: unknown option %c\n", NAME, opt);
                /* 
                 * it's worth noting that unknown options cause encrypt to bail
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
    
    if ((!filename_in && !filename_out) || (!function) || (!key_type))
    {
        GtkWidget *window_main;

  #ifdef ENABLE_NLS
        bindtextdomain(GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
        bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
        textdomain(GETTEXT_PACKAGE);
  #endif /* ENABLE_NLS */
        gtk_set_locale();
        add_pixmap_directory("./pixmap");
  #ifndef _WIN32
        add_pixmap_directory("/usr/lib/encrypt/pixmap");
  #else  /* ! _WIN32 */
        add_pixmap_directory("/Program Files/encrypt/pixmap");
  #endif /*   _WIN32 */
        window_main = create_window_main();
        gtk_widget_show(window_main);
        gtk_main();

        free(filename_in);
        free(filename_out);
        return EXIT_SUCCESS;
    }
    else
    {
#endif /* _BUILD_GUI_ */
        /* 
         * open the files iff we have a name for them, otherwise stick with the defaults (stdin/stdout) defined above
         */
        if (filename_in)
        {
            if ((file_in = open(filename_in, O_RDONLY | O_BINARY | F_RDLCK)) < 0)
                die("%s: could not access input file %s\n", NAME, filename_in);
            free(filename_in);
        }
        if (filename_out)
        {
            if ((file_out = open(filename_out, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | F_WRLCK, S_IRUSR | S_IWUSR)) < 0)
                die("%s: could not access/create output file %s\n", NAME, filename_out);
            free(filename_out);
        }
        /* 
         * generate a binary key using the chosen method
         */
        key_data = key_calculate(file_mod, key_plain, key_type);
        free(key_plain);
        /* 
         * search for the function we want - if we were able to load the module then it should be there, otherwise it's
         * likely that the user forgot to give us a name for the module above
         */
#ifndef _WIN32
        if (!(fp = (int64_t (*)(int64_t, int64_t, uint8_t *))dlsym(file_mod, function == ENCRYPT ? "plugin_encrypt" : "plugin_decrypt")))
#else  /* ! _WIN32 */
        if (!(fp = (void *)GetProcAddress(file_mod, function == ENCRYPT ? "plugin_encrypt" : "plugin_decrypt")))
#endif /*   _WIN32 */
            die("%s: could not import module function for %sryption\n", NAME, function == ENCRYPT ? "enc" : "dec");
        /* 
         * we made it - if we reach here then everything is okay and we're now ready to start :)
         */
        int64_t s = fp(file_in, file_out, key_data);
        /* 
         * if there's an error tell the user - however it's unlikely we'll know exactly what the error is
         */
        if (s != EXIT_SUCCESS)
            die("%s: an unexpected error has occured\n", NAME);
        /* 
         * close all open files obviously if in_file / out_file are stdin / stdout it makes no sense to close them
         */
        free(key_data);
#ifdef _DLFCN_H
        dlclose(file_mod);
#endif /* _DLFCN_H */
        if (file_in != STDIN_FILENO)
            close(file_in);
        if (file_out != STDOUT_FILENO)
            close(file_out);
        return EXIT_SUCCESS;
#ifdef _BUILD_GUI_
    }
#endif /* _BUILD_GUI_ */
}

void *open_mod(char *n)
{
#ifndef _WIN32
    void *p = NULL;
#else  /* ! _WIN32 */
    HANDLE p = NULL;
#endif /*   _WIN32 */
    if (!n)
         die("%s: module name cannot be (null)\n", NAME);
#ifndef _WIN32
    if (!strchr(n, '/'))
        asprintf(&n, "%s.so", n);
    if (!(p = dlopen(n, RTLD_LAZY)))
#else  /* ! _WIN32 */
    if (!strchr(n, '\\') && !strchr(n, '/'))
    {
        n = realloc(n, strlen(n) + 5);
        sprintf(n, "%s.dll", n);
    }
    if (!(p = LoadLibrary(n)))
#endif /*   _WIN32 */
        die("%s: could not open plugin %s\n", NAME, n);
    return p;
}

int64_t algorithm_info(char *n)
{
    if (!n)
        die("%s: missing module name\n", NAME);
    void *p = open_mod(n);
    if (!p)
        die("%s: invalid pointer to module\n", NAME);
    /* 
     * set everything up so we can get some info about the given algorithm
     */
    info_t *about, *(*fp)(void); 
    errno = 0;

#ifndef _WIN32
    if (!(fp = (info_t *(*)(void))dlsym(p, "plugin_info")))
#else   /* ! _WIN32 */
    if (!(fp = (void *)GetProcAddress(p, "plugin_info")))
#endif /*   _WIN32 */
        die("%s: could not find plugin information\n", NAME);
    /* 
     * now get the info
     */
    about = fp();
    fprintf(stdout, "Algorithm Details\n");
    fprintf(stdout, "  Name       : %s\n", about->algorithm_name);
    fprintf(stdout, "  Authors    : %s\n", about->algorithm_authors);
    fprintf(stdout, "  Copyright  : %s\n", about->algorithm_copyright);
    fprintf(stdout, "  Licence    : %s\n", about->algorithm_licence);
    fprintf(stdout, "  Year       : %s\n", about->algorithm_year);
    fprintf(stdout, "  Block size : %s\n", about->algorithm_block);
    fprintf(stdout, "\nKey Details\n");
    fprintf(stdout, "  Name       : %s\n", about->key_name);
    fprintf(stdout, "  Authors    : %s\n", about->key_authors);
    fprintf(stdout, "  Copyright  : %s\n", about->key_copyright);
    fprintf(stdout, "  Licence    : %s\n", about->key_licence);
    fprintf(stdout, "  Year       : %s\n", about->key_year);
    fprintf(stdout, "  Key size   : %s\n", about->key_size);
    fprintf(stdout, "\nPlugin Details\n");
    fprintf(stdout, "  Authors    : %s\n", about->module_authors);
    fprintf(stdout, "  Copyright  : %s\n", about->module_copyright);
    fprintf(stdout, "  Licence    : %s\n", about->module_licence);
    fprintf(stdout, "  Version    : %s\n", about->module_version);
    fprintf(stdout, "\nAdditional Details\n");
    fprintf(stdout, "  %s\n", about->module_comment);

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
        dlclose(p);
#endif /* _DLFCN_H */
    return errno;
}

int64_t key_generate(char *s, char *f)
{
    /* 
     * generate a key (for later use) of a given size - it's up to each algorithm plugin to decide how to use a given
     * key file (all keys are in hex)
     */
    uint64_t l = strtol(s, NULL, 10) / 8;
    FILE *k = stdout;
    errno = EXIT_SUCCESS;
    srand48(time(0));
    /* 
     * either print the hex key to stdout, or to a file if we can
     */
    if (f)
        if (!(k = fopen(f, "w")))
            die("%s: could not access/create key file %s\n", NAME, f);
    for (uint64_t i = 0; i < l; i++)
        fprintf(k, "%02X", (uint8_t)(lrand48() % 256));
    if (k == stdout)
        printf("\n");
    fclose(k);
    return errno;
}

uint8_t *key_calculate(void *p, char *s, uint8_t k)
{
    if (!p)
        die("%s: invalid pointer to module\n", NAME);
    if (!s)
        die("%s: missing data for key generation\n", NAME);
    uint8_t *c = NULL;
    uint8_t *d = NULL;
    uint64_t l = 0;
    switch (k)
    {
        case KEYFILE:
            {
                int64_t  f = 0;
                if ((f = open(s, O_RDONLY)) < 0)
                    die("%s: could not access key file %s\n", NAME, s);
                l = lseek(f, 0, SEEK_END);
                lseek(f, 0, SEEK_SET);
                d = calloc(l, sizeof( uint8_t ));
                if (!d)
                    return NULL;
                for (uint64_t i = 0; i < l / 2; i++)
                {
                    char c[3] = { 0x00 };
                    read(f, &c, 2 * sizeof( uint8_t ));
                    d[i] = strtol(c, NULL, 0x0F);
                }
                close(f);
                return d;
            }
            break; // why?
        case PASSFILE:
            {
                int64_t f = 0;
                if ((f = open(s, O_RDONLY)) < 0)
                    die("%s: could not access passphrase file %s\n", NAME, s);
                l = lseek(f, 0, SEEK_END);
                lseek(f, 0, SEEK_SET);
                c = calloc(l, sizeof( uint8_t ));
                read(f, c, l);
                close(f);
            }
            break;
        case PASSWORD:
            {
                c = (uint8_t *)strdup(s);
                l = strlen(s);
            }
            break;
        default:
            die("%s: invalid key type\n", NAME);
    }
    uint8_t *(*fp)(uint8_t *, size_t);
    
#ifndef _WIN32
    if (!(fp = (uint8_t *(*)(uint8_t *, size_t))dlsym(p, "plugin_key")))
#else   /* ! _WIN32 */
    if (!(fp = (void *)GetProcAddress(p, "plugin_key")))
#endif /*   _WIN32 */
        die("%s: could not find plugin function %s\n", NAME, "plugin_key");
    d = fp(c, l);
    free(c);
    return d;
}

int64_t list_modules(void)
{
    errno = EXIT_SUCCESS;
    /*
     * list all modules which are installed in /usr/lib/encrypt
     */
    fprintf(stdout, "Installed Modules:\n");
#ifndef _WIN32
    /* 
     * linux version is much nicer than the windows (this is becoming common)
     */
    struct dirent **eps;
    int64_t n = scandir("/usr/lib/encrypt/lib", &eps, NULL, alphasort);
    if (n >= 0)
    {
        for (int64_t i = 0; i < n; ++i)
            if (strstr(eps[i]->d_name, ".so"))
  #ifdef linux
                fprintf(stdout, "  %*s\n", (uint32_t)(strlen(eps[i]->d_name) - 3), eps[i]->d_name);
  #else  /*   linux */
            {
                char *n = calloc(strlen(eps[i]->d_name), sizeof( char ));
                memcpy(n, eps[i]->d_name, strlen(eps[i]->d_name) - 3);
                fprintf(stdout, "  %s\n", n);
            }
  #endif /* ! linux */
    free(*eps);
#else  /* ! _WIN32 */
    DIR *dp = opendir("/Program Files/encrypt/lib");
    if (dp)
    {
        struct dirent *ep;
        while ((ep = readdir(dp)))
            if (strstr(ep->d_name, ".dll"))
                fprintf(stdout, "  %s\n", ep->d_name);
        (void)closedir(dp);
#endif /*   _WIN32 */
    }
    return errno;
}

void die(const char *s, ...)
{
    va_list ap;
    va_start(ap, s);
#ifndef _BUILD_GUI_
    vfprintf(stderr, s, ap);
#endif /* _BUILD_GUI_ */
    va_end(ap);
#ifndef _BUILD_GUI_
    exit(errno);
#endif /* _BUILD_GUI_ */
}

void sigint(int s)
{
    signal(s, sigint);
    fprintf(stderr, "\r%s: ignoring signal SIGINT\n", NAME);
}

int64_t show_help(void)
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
    fprintf(stderr, "  -m, --modules              List all available algorithms\n");
    fprintf(stderr, "  -h, --help                 This help list\n");
    fprintf(stderr, "  -l, --licence              An overview of the GNU GPL\n");
    fprintf(stderr, "  -v, --version              Show version number and quit\n\n");
    fprintf(stderr, "If -i or -o are omitted then stdin/stdout are used.  Either -e or -d must be\n");
    fprintf(stderr, "present if you intend to do something, as well as -k -f or -p. Using -g will\n");
    fprintf(stderr, "generate a random key and echo it to stdout unless -g is preceded by -k; the\n");
    fprintf(stderr, "key can be used later with the -k option. However -a -m -h -l -v may be used\n");
    fprintf(stderr, "on their own or not at all.\n");
    return EXIT_SUCCESS;
}

int64_t show_licence(void)
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
    return EXIT_SUCCESS;
}

int64_t show_usage(void)
{
    /* 
     * c'mon! how hard is this!
     */
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [OPTION] [ARGUMENT] ...\n", NAME);
    return EXIT_SUCCESS;
}

int64_t show_version(void)
{
    fprintf(stderr, "%s commit date: %s\n%*s build date : %s %s\n", NAME, VERSION, (int)strlen(NAME), "", __DATE__, __TIME__);
    return EXIT_SUCCESS;
}
