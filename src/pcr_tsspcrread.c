/*
 * ima-evm-utils - IMA/EVM support utilities
 *
 * Copyright (C) 2011 Nokia Corporation
 * Copyright (C) 2011,2012,2013 Intel Corporation
 * Copyright (C) 2013,2014 Samsung Electronics
 *
 * Authors:
 * Dmitry Kasatkin <dmitry.kasatkin@nokia.com>
 *                 <dmitry.kasatkin@intel.com>
 *                 <d.kasatkin@samsung.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, the copyright holders give permission to link the
 * code of portions of this program with the OpenSSL library under certain
 * conditions as described in each individual source file and distribute
 * linked combinations including the program with the OpenSSL library. You
 * must comply with the GNU General Public License in all respects
 * for all of the code used other than as permitted herein. If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so. If you do not
 * wish to do so, delete this exception statement from your version. If you
 * delete this exception statement from all source files in the program,
 * then also delete it in the license file.
 *
 * File: pcr_tsspcrread.c
 *	 PCR reading implementation based on IBM TSS2
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/sha.h>

#define USE_FPRINTF
#include "utils.h"
#include "imaevm.h"

#define CMD "tsspcrread"

static char path[PATH_MAX];

int tpm2_pcr_supported(void)
{
	if (imaevm_params.verbose > LOG_INFO)
		log_info("Using %s to read PCRs.\n", CMD);

	if (get_cmd_path(CMD, path, sizeof(path))) {
		log_debug("Couldn't find '%s' in $PATH\n", CMD);
		return 0;
	}

	log_debug("Found '%s' in $PATH\n", CMD);
	return 1;
}

int tpm2_pcr_read(const char *algo_name, uint32_t pcr_handle, uint8_t *hwpcr,
		 int len, char **errmsg)
{
	FILE *fp;
	char pcr[100];	/* may contain an error */
	char cmd[PATH_MAX + 50];
	int ret;

	sprintf(cmd, "%s -halg %s -ha %u -ns 2> /dev/null",
		path, algo_name, pcr_handle);
	fp = popen(cmd, "r");
	if (!fp) {
		ret = asprintf(errmsg, "popen failed: %s", strerror(errno));
		if (ret == -1)	/* the contents of errmsg is undefined */
			*errmsg = NULL;
		return -1;
	}

	if (fgets(pcr, sizeof(pcr), fp) == NULL) {
		ret = asprintf(errmsg, "tsspcrread failed: %s",
			       strerror(errno));
		if (ret == -1)	/* the contents of errmsg is undefined */
			*errmsg = NULL;
		ret = pclose(fp);
		return -1;
	}

	/* get the popen "cmd" return code */
	ret = pclose(fp);

	/* Treat an unallocated bank as an error */
	if (!ret && (strlen(pcr) < SHA_DIGEST_LENGTH))
		ret = -1;

	if (!ret)
		hex2bin(hwpcr, pcr, len);
	else
		*errmsg = strndup(pcr, strlen(pcr) - 1); /* remove newline */

	return ret;
}
