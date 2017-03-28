/*
 * Version checking functions (non-applications specific)
 * Copyright © 2005-2017, albinoloverats ~ Software Development
 * email: webmaster@albinoloverats.net
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
#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>

#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include <curl/curl.h>
#include <pthread.h>

#ifndef _WIN32
	#include <sys/stat.h>
	#include <sys/wait.h>
#else
	#include <windows.h>
#endif

#ifdef __APPLE__
	#include "osx.h"
#endif

#include "version.h"

static void version_install_latest(char *);
static void *version_check(void *);
static size_t version_verify(void *, size_t, size_t, void *);

bool new_version_available = false;
char *version_available = NULL;
char *new_version_url = NULL;

static char *update = NULL;

typedef struct
{
	char *current;
	char *check_url;
	char *update_url;
}
version_check_t;

extern void version_check_for_update(char *current_version, char *check_url, char *download_url)
{
	pthread_t vt;
	pthread_attr_t a;
	pthread_attr_init(&a);
	pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);

	version_check_t *info = calloc(sizeof( version_check_t ), 1);
	info->current = current_version;
	info->check_url = check_url;
	info->update_url = download_url;

	pthread_create(&vt, &a, version_check, info);
	pthread_attr_destroy(&a);
	return;
}

static void *version_check(void *n)
{
	version_check_t *info = (version_check_t *)n;
	curl_global_init(CURL_GLOBAL_ALL);
	CURL *ccheck = curl_easy_init();
	curl_easy_setopt(ccheck, CURLOPT_URL, info->check_url);
#ifdef WIN32
	curl_easy_setopt(ccheck, CURLOPT_SSL_VERIFYPEER, 0L);
#endif
	curl_easy_setopt(ccheck, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(ccheck, CURLOPT_WRITEDATA, info->current);
	curl_easy_setopt(ccheck, CURLOPT_WRITEFUNCTION, version_verify);
	curl_easy_perform(ccheck);
	curl_easy_cleanup(ccheck);
	if (new_version_available && info->update_url)
	{
		/* download new version */
		CURL *cupdate = curl_easy_init();
		/*
		 * default template for our projects download url is /downloads/project/version/project-version
		 * and as the project knows and can set everything except the new version number this is sufficient
		 */
		asprintf(&new_version_url, info->update_url, version_available, version_available);
		curl_easy_setopt(cupdate, CURLOPT_URL, new_version_url);
#ifdef WIN32
		curl_easy_setopt(cupdate, CURLOPT_SSL_VERIFYPEER, 0L);
#endif
		curl_easy_setopt(cupdate, CURLOPT_NOPROGRESS, 1L);
#ifndef _WIN32
		asprintf(&update, "%s/update-%s-XXXXXX", P_tmpdir ,version_available);
		int64_t fd = mkstemp(update);
		fchmod(fd, S_IRUSR | S_IWUSR | S_IXUSR);
#else
		char p[MAX_PATH] = { 0x0 };
		GetTempPath(sizeof p, p);
		asprintf(&update, "%supdate-%s.exe", p, version_available);
		int64_t fd = open(update, O_CREAT | O_WRONLY | O_BINARY);
#endif
		if (fd > 0)
		{
			FILE *fh = fdopen(fd, "wb");
			curl_easy_setopt(cupdate, CURLOPT_WRITEDATA, fh);
			curl_easy_perform(cupdate);
			curl_easy_cleanup(cupdate);
			fclose(fh);
			close(fd);

			version_install_latest(update);
		}
		free(update);
	}
	pthread_exit(n);
}

static void version_install_latest(char *u)
{
	if (!new_version_available || !u)
		return;
#if !defined __APPLE__ && !defined _WIN32
	char *u2 = strdup(u);
	pid_t pid = fork();
	if (pid == 0)
	{
		execl(u2, basename(u2), NULL);
		unlink(u2);
		free(u2);
		_exit(EXIT_FAILURE);
	}
	else if (pid > 0)
	{
		waitpid(pid, NULL, 0);
		unlink(u2);
		free(u2);
	}
#elif defined __APPLE__
	char *dmg = NULL;
	asprintf(&dmg, "%s.dmg", u);
	rename(u, dmg);
	//execl("/usr/bin/open", "open", dmg, NULL);
	osx_open_file(dmg);
	unlink(dmg);
	free(dmg);
#elif defined _WIN32
	ShellExecute(NULL, "open", u, NULL, NULL, SW_SHOWNORMAL);
#endif
	return;
}

static size_t version_verify(void *p, size_t s, size_t n, void *v)
{
	char *b = calloc(s + 1, n);
	memcpy(b, p, s * n);
	char *l = strrchr(b, '\n');
	if (l)
		*l = '\0';
	if (strcmp(b, (char *)v) > 0)
	{
		new_version_available = true;
		asprintf(&version_available, "%s", b);
	}
	free(b);
	return s * n;
}
