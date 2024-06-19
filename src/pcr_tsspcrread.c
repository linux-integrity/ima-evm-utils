// SPDX-License-Identifier: GPL-2.0-or-later
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
		log_info("Couldn't find '%s' in %s\n", CMD, path);
		return 0;
	}

	log_debug("Found '%s' in %s\n", CMD, path);
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
