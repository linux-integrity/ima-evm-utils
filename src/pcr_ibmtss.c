// SPDX-License-Identifier: GPL-2.0
/*
 * Support PCR reading implementation based on IBM TSS2
 *
 * Copyright (C) 2021 IBM Ken Goldman <kgoldman@us.ibm.com>
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

#define TPM_POSIX	/* use Posix, not Windows constructs in TSS */
#undef MAX_DIGEST_SIZE	/* imaevm uses a different value than the TSS */
#include <ibmtss/tss.h>

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

/* Table mapping C strings to TCG algorithm identifiers */
typedef struct tdAlgorithm_Map {
	const char *algorithm_string;
	TPMI_ALG_HASH algid;
} Algorithm_Map;

Algorithm_Map algorithm_map[] = {
				 { "sha1", TPM_ALG_SHA1},
				 { "sha256", TPM_ALG_SHA256},
#if 0	/* uncomment as these digest algorithms are supported */
				 { "", TPM_ALG_SHA384},
				 { "", TPM_ALG_SHA512},
				 { "", TPM_ALG_SM3_256},
				 { "", TPM_ALG_SHA3_256},
				 { "", TPM_ALG_SHA3_384},
				 { "", TPM_ALG_SHA3_512},
#endif
};

/*
 * algorithm_string_to_algid() converts a digest algorithm from a C string to a
 * TCG algorithm identifier as defined in the TCG Algorithm Regisrty..
 *
 *  Returns TPM_ALG_ERROR if the string has an unsupported value.
 */
static TPMI_ALG_HASH algorithm_string_to_algid(const char *algorithm_string)
{
	size_t 	i;

	for (i=0 ; i < sizeof(algorithm_map)/sizeof(Algorithm_Map) ; i++) {
		if (strcmp(algorithm_string, algorithm_map[i].algorithm_string)
		    == 0) {
			return algorithm_map[i].algid; 		/* if match */
		}
	}
	return TPM_ALG_ERROR;
}

/*
 * tpm2_pcr_read - read the PCR
 *
 * algo_name: PCR digest algorithm (the PCR bank) as a C string
 * pcr_handle: PCR number to read
 * hwpcr: buffer for the PCR output in binary
 * len: allocated size of hwpcr and should match the digest algorithm
 */
int tpm2_pcr_read(const char *algo_name, uint32_t pcr_handle, uint8_t *hwpcr,
		  int len, char **errmsg)
{
        int 			ret = 0;	/* function return code */
	TPM_RC			rc = 0;		/* TCG return code */
	TPM_RC 			rc1 = 0;	/* secondary return code */
	PCR_Read_In 		pcr_read_in;	/* command input */
	PCR_Read_Out 		pcr_read_out;	/* response output */
	TSS_CONTEXT		*tss_context = NULL;
	TPMI_ALG_HASH 		alg_id;		/* PCR algorithm */

	alg_id = algorithm_string_to_algid(algo_name);
	if (alg_id == TPM_ALG_ERROR) {
		ret = asprintf(errmsg, "tpm2_pcr_read: unknown algorithm %s",
			       algo_name);
		if (ret == -1) 	/* the contents of errmsg is undefined */
			*errmsg = NULL;
		rc = 1;
		goto end;
	}

	rc = TSS_Create(&tss_context);
	if (rc != 0)
		goto end;

	/* call TSS to execute the command */
	pcr_read_in.pcrSelectionIn.count = 1;
	pcr_read_in.pcrSelectionIn.pcrSelections[0].hash = alg_id;
	pcr_read_in.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
	pcr_read_in.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
	pcr_read_in.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
	pcr_read_in.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
	pcr_read_in.pcrSelectionIn.pcrSelections[0].pcrSelect[pcr_handle / 8] =
		1 << (pcr_handle % 8);
	rc = TSS_Execute(tss_context,
			 (RESPONSE_PARAMETERS *)&pcr_read_out,
			 (COMMAND_PARAMETERS *)&pcr_read_in,
			 NULL,
			 TPM_CC_PCR_Read,
			 TPM_RH_NULL, NULL, 0);
	if (rc != 0)
		goto end;

	/* nothing read, bank missing */
	if (pcr_read_out.pcrValues.count == 0) {
		ret = asprintf(errmsg, "tpm2_pcr_read: returned count 0 for %s",
			       algo_name);
		if (ret == -1) /* the contents of errmsg is undefined */
			*errmsg = NULL;
		rc = 1;
		goto end;
	}
	/* len parameter did not match the digest algorithm */
	else if (pcr_read_out.pcrValues.digests[0].t.size != len) {
		ret = asprintf(errmsg,
			       "tpm2_pcr_read: "
			       "expected length %d actual %u for %s",
			       len, pcr_read_out.pcrValues.digests[0].t.size,
			       algo_name);
		if (ret == -1)	/* the contents of errmsg is undefined */
			*errmsg = NULL;
		rc = 1;
		goto end;
	} else {
		memcpy(hwpcr,
		       pcr_read_out.pcrValues.digests[0].t.buffer,
		       pcr_read_out.pcrValues.digests[0].t.size);
	}
end:
	/* Call delete even on errors to free context resources */
	rc1 = TSS_Delete(tss_context);

	/* map TCG return code to function return code */
	if ((rc == 0) && (rc1 == 0))
		return 0;
	else
		return -1;
}
