// SPDX-License-Identifier: GPL-2.0
/*
 * utils: set of common functions
 *
 * Copyright (C) 2020 Patrick Uiterwijk <patrick@puiterwijk.org>
 * Copyright (C) 2010 Cyril Hrubis <chrubis@suse.cz>
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"

#ifndef MIN
# define MIN(a, b) ({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a < _b ? _a : _b; \
})
#endif /* MIN */

static int file_exist(const char *path)
{
	struct stat st;

	if (!access(path, R_OK) && !stat(path, &st) && S_ISREG(st.st_mode))
		return 1;

	return 0;
}

int get_cmd_path(const char *prog_name, char *buf, size_t buf_len)
{
	const char *path = (const char *)getenv("PATH");
	const char *start = path;
	const char *end;
	size_t size, ret;

	if (path == NULL)
		return -1;

	do {
		end = strchr(start, ':');

		if (end != NULL)
			snprintf(buf, MIN(buf_len, (size_t) (end - start + 1)),
				 "%s", start);
		else
			snprintf(buf, buf_len, "%s", start);

		size = strlen(buf);

		/*
		 * "::" inside $PATH, $PATH ending with ':' or $PATH starting
		 * with ':' should be expanded into current working directory.
		 */
		if (size == 0) {
			snprintf(buf, buf_len, ".");
			size = strlen(buf);
		}

		/*
		 * If there is no '/' ad the end of path from $PATH add it.
		 */
		if (buf[size - 1] != '/')
			ret =
			    snprintf(buf + size, buf_len - size, "/%s",
				     prog_name);
		else
			ret =
			    snprintf(buf + size, buf_len - size, "%s",
				     prog_name);

		if (buf_len - size > ret && file_exist(buf))
			return 0;

		if (end != NULL)
			start = end + 1;

	} while (end != NULL);

	return -1;
}

int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

int hex2bin(void *dst, const char *src, size_t count)
{
	int hi, lo;

	while (count--) {
		if (*src == ' ')
			src++;

		hi = hex_to_bin(*src++);
		lo = hex_to_bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -1;

		*(uint8_t *)dst++ = (hi << 4) | lo;
	}
	return 0;
}
