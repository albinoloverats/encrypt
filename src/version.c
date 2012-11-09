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

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <curl/curl.h>

#include "version.h"
#include "encrypt.h"
#ifdef BUILD_GUI
    #ifndef __APPLE__
        #include "gui-gtk.h"
    #else
        #include "AppDelegate.h"
    #endif
#endif

static size_t verify_new_version(void *, size_t, size_t, void *);

bool new_version_available = false;

extern void *check_new_version(void *n)
{
    curl_global_init(CURL_GLOBAL_ALL);
    CURL *curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, "https://albinoloverats.net/encrypt.release");
#ifdef WIN32
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
#endif
    curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, verify_new_version);
    curl_easy_perform(curl_handle);
    curl_easy_cleanup(curl_handle);
#if defined BUILD_GUI && !defined __APPLE__
    if (n)
        update_status_bar((gtk_widgets_t *)n, new_version_available ? -1 : 0);
#endif
    return n;
}

static size_t verify_new_version(void *p, size_t s, size_t n, void *x)
{
    (void)x;
    char *b = calloc(s + 1, n);
    memcpy(b, p, s * n);
    char *l = strrchr(b, '\n');
    if (l)
        *l = '\0';
    if (strcmp(b, ENCRYPT_VERSION) > 0)
        new_version_available = true;
    free(b);
    return s * n;
}
