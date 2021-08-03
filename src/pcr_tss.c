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
 * File: pcr_tss.c
 *	 PCR reading implementation based on Intel TSS2
 */

#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>

#ifdef HAVE_LIBTSS2_ESYS
# include <tss2/tss2_esys.h>

# ifdef HAVE_LIBTSS2_RC
#  include <tss2/tss2_rc.h>
#  define LIB "tss2-rc-decode"
# else
#  define LIB "tss2-esys"
# endif

#endif /* HAVE_LIBTSS2_ESYS */

#define USE_FPRINTF
#include "imaevm.h"

int tpm2_pcr_supported(void)
{
	if (imaevm_params.verbose > LOG_INFO)
		log_info("Using %s to read PCRs.\n", LIB);

	return 1;
}

static int pcr_selections_match(TPML_PCR_SELECTION *a, TPML_PCR_SELECTION *b)
{
	int i, j;

	if (a->count != b->count)
		return 0;

	for (i = 0; i < a->count; i++) {
		if (a->pcrSelections[i].hash != b->pcrSelections[i].hash)
			return 0;
		if (a->pcrSelections[i].sizeofSelect != b->pcrSelections[i].sizeofSelect)
			return 0;
		for (j = 0; j < a->pcrSelections[i].sizeofSelect; j++) {
			if (a->pcrSelections[i].pcrSelect[j] != b->pcrSelections[i].pcrSelect[j])
				return 0;
		}
	}

	return 1;
}

static inline int tpm2_set_errmsg(char **errmsg, const char *message, TSS2_RC ret)
{
#ifdef HAVE_LIBTSS2_RC
		return asprintf(errmsg, "%s: %s", message, Tss2_RC_Decode(ret));
#else
		return asprintf(errmsg, "%s: #%d", message, ret);
#endif
}

static TPM2_ALG_ID algo_to_tss2(const char *algo_name)
{
	if (!strcmp(algo_name, "sha1"))
		return TPM2_ALG_SHA1;
	else if (!strcmp(algo_name, "sha256"))
		return TPM2_ALG_SHA256;

	return TPM2_ALG_ERROR;
}

int tpm2_pcr_read(const char *algo_name, uint32_t pcr_handle, uint8_t *hwpcr,
		 int len, char **errmsg)
{
	TSS2_ABI_VERSION abi_version = {
		.tssCreator = 1,
		.tssFamily = 2,
		.tssLevel = 1,
		.tssVersion = 108,
	};
	ESYS_CONTEXT *ctx = NULL;
	TSS2_RC ret = 0;
	TPML_PCR_SELECTION *pcr_select_out;
	TPML_DIGEST *pcr_digests;
	UINT32 pcr_update_counter;

	TPM2_ALG_ID algid = algo_to_tss2(algo_name);
	if (algid == TPM2_ALG_ERROR) {
		ret = asprintf(errmsg, "unsupported tss2 algorithm");
		if (ret == -1)	/* the contents of errmsg are undefined */
			*errmsg = NULL;
		return -1;
	}

	TPML_PCR_SELECTION pcr_select_in = {
		.count = 1,
		.pcrSelections = {
			{
				.hash = algid,
				.sizeofSelect = 3,
				.pcrSelect = { 0x00, 0x00, 0x00 },
			}
		}
	};

	pcr_select_in.pcrSelections[0].pcrSelect[pcr_handle / 8] =
	    (1 << (pcr_handle % 8));

	ret = Esys_Initialize(&ctx, NULL, &abi_version);
	if (ret != TPM2_RC_SUCCESS) {
		ret = tpm2_set_errmsg(errmsg, "esys initialize failed", ret);
		if (ret == -1)	/* the contents of errmsg are undefined */
			*errmsg = NULL;
		return -1;
	}

	ret = Esys_PCR_Read(ctx,
			    ESYS_TR_NONE,
			    ESYS_TR_NONE,
			    ESYS_TR_NONE,
			    &pcr_select_in,
			    &pcr_update_counter,
			    &pcr_select_out,
			    &pcr_digests);
	Esys_Finalize(&ctx);
	if (ret != TPM2_RC_SUCCESS) {
		ret = tpm2_set_errmsg(errmsg, "esys PCR reading failed", ret);
		if (ret == -1)	/* the contents of errmsg is undefined */
			*errmsg = NULL;
		return -1;
	}

	if (!pcr_selections_match(&pcr_select_in, pcr_select_out)) {
		Esys_Free(pcr_select_out);
		Esys_Free(pcr_digests);

		ret = asprintf(errmsg, "TPM returned incorrect PCRs");
		if (ret == -1)	/* the contents of errmsg are undefined */
			*errmsg = NULL;
		return -1;
	}
	Esys_Free(pcr_select_out);

	if (pcr_digests->count != 1 || pcr_digests->digests[0].size != len) {
		Esys_Free(pcr_digests);
		ret = asprintf(errmsg, "TPM returned incorrect digests");
		if (ret == -1)	/* the contents of errmsg is undefined */
			*errmsg = NULL;
		return -1;
	}

	memcpy(hwpcr, pcr_digests->digests[0].buffer, len);
	Esys_Free(pcr_digests);
	return 0;
}
