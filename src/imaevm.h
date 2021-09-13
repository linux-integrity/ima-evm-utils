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
 * File: imaevm.h
 *	 IMA/EVM header file
 */

#ifndef _LIBIMAEVM_H
#define _LIBIMAEVM_H

#include <linux/fs.h>
#include <stdint.h>
#include <syslog.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#ifdef USE_FPRINTF
#define do_log(level, fmt, args...)	\
	({ if (level <= imaevm_params.verbose) fprintf(stderr, fmt, ##args); })
#define do_log_dump(level, p, len, cr)	\
	({ if (level <= imaevm_params.verbose) imaevm_do_hexdump(stderr, p, len, cr); })
#else
#define do_log(level, fmt, args...)	syslog(level, fmt, ##args)
#define do_log_dump(level, p, len, cr)
#endif

#ifdef DEBUG
#define log_debug(fmt, args...)		do_log(LOG_DEBUG, "%s:%d " fmt, __func__ , __LINE__ , ##args)
#define log_debug_dump(p, len)		do_log_dump(LOG_DEBUG, p, len, true)
#define log_debug_dump_n(p, len)	do_log_dump(LOG_DEBUG, p, len, false)
#else
#define log_debug(fmt, args...)
#define log_debug_dump(p, len)
#endif

#define log_dump(p, len)		do_log_dump(LOG_INFO, p, len, true)
#define log_dump_n(p, len)		do_log_dump(LOG_INFO, p, len, false)
#define log_info(fmt, args...)		do_log(LOG_INFO, fmt, ##args)
#define log_err(fmt, args...)		do_log(LOG_ERR, fmt, ##args)
#define log_errno(fmt, args...)		do_log(LOG_ERR, fmt ": errno: %s (%d)\n", ##args, strerror(errno), errno)

#ifndef DEFAULT_HASH_ALGO
#define DEFAULT_HASH_ALGO "sha256"
#endif

#define	DATA_SIZE	4096
#define SHA1_HASH_LEN   20

#define MAX_DIGEST_SIZE		64
#define MAX_SIGNATURE_SIZE	1024

#define __packed __attribute__((packed))

enum evm_ima_xattr_type {
	IMA_XATTR_DIGEST = 0x01,
	EVM_XATTR_HMAC,
	EVM_IMA_XATTR_DIGSIG,
	IMA_XATTR_DIGEST_NG,
	EVM_XATTR_PORTABLE_DIGSIG,
};

struct h_misc {
	unsigned long ino;
	uint32_t generation;
	uid_t uid;
	gid_t gid;
	unsigned short mode;
};

struct h_misc_32 {
	uint32_t ino;
	uint32_t generation;
	uid_t uid;
	gid_t gid;
	unsigned short mode;
};

struct h_misc_64 {
	uint64_t ino;
	uint32_t generation;
	uid_t uid;
	gid_t gid;
	unsigned short mode;
};

struct h_misc_digsig {
	uid_t uid;
	gid_t gid;
	unsigned short mode;
};

enum pubkey_algo {
	PUBKEY_ALGO_RSA,
	PUBKEY_ALGO_MAX,
};

enum digest_algo {
	DIGEST_ALGO_SHA1,
	DIGEST_ALGO_SHA256,
	DIGEST_ALGO_MAX
};

enum digsig_version {
	DIGSIG_VERSION_1 = 1,
	DIGSIG_VERSION_2
};

struct pubkey_hdr {
	uint8_t version;	/* key format version */
	uint32_t timestamp;	/* key made, always 0 for now */
	uint8_t algo;
	uint8_t nmpi;
	char mpi[0];
} __packed;

struct signature_hdr {
	uint8_t version;	/* signature format version */
	uint32_t timestamp;	/* signature made */
	uint8_t algo;
	uint8_t hash;
	uint8_t keyid[8];
	uint8_t nmpi;
	char mpi[0];
} __packed;

/* reflect enum hash_algo from include/uapi/linux/hash_info.h */
enum pkey_hash_algo {
	PKEY_HASH_MD4,
	PKEY_HASH_MD5,
	PKEY_HASH_SHA1,
	PKEY_HASH_RIPE_MD_160,
	PKEY_HASH_SHA256,
	PKEY_HASH_SHA384,
	PKEY_HASH_SHA512,
	PKEY_HASH_SHA224,
	PKEY_HASH_RIPE_MD_128,
	PKEY_HASH_RIPE_MD_256,
	PKEY_HASH_RIPE_MD_320,
	PKEY_HASH_WP_256,
	PKEY_HASH_WP_384,
	PKEY_HASH_WP_512,
	PKEY_HASH_TGR_128,
	PKEY_HASH_TGR_160,
	PKEY_HASH_TGR_192,
	PKEY_HASH_SM3_256,
	PKEY_HASH_STREEBOG_256,
	PKEY_HASH_STREEBOG_512,
	PKEY_HASH__LAST
};

/*
 * signature format v2 - for using with asymmetric keys
 */
struct signature_v2_hdr {
	uint8_t version;	/* signature format version */
	uint8_t	hash_algo;	/* Digest algorithm [enum pkey_hash_algo] */
	uint32_t keyid;		/* IMA key identifier - not X509/PGP specific*/
	uint16_t sig_size;	/* signature size */
	uint8_t sig[0];		/* signature payload */
} __packed;

struct libimaevm_params {
	int verbose;
	int x509;
	const char *hash_algo;
	const char *keyfile;
	const char *keypass;
	uint32_t keyid;		/* keyid overriding value, unless 0. (Host order.) */
	ENGINE *eng;
};

struct RSA_ASN1_template {
	const uint8_t *data;
	size_t size;
};

#define	NUM_PCRS 24
#define DEFAULT_PCR 10

extern struct libimaevm_params imaevm_params;

void imaevm_do_hexdump(FILE *fp, const void *ptr, int len, bool cr);
void imaevm_hexdump(const void *ptr, int len);
int ima_calc_hash(const char *file, uint8_t *hash);
int imaevm_get_hash_algo(const char *algo);
RSA *read_pub_key(const char *keyfile, int x509);
EVP_PKEY *read_pub_pkey(const char *keyfile, int x509);

void calc_keyid_v1(uint8_t *keyid, char *str, const unsigned char *pkey, int len);
void calc_keyid_v2(uint32_t *keyid, char *str, EVP_PKEY *pkey);
int key2bin(RSA *key, unsigned char *pub);
uint32_t imaevm_read_keyid(const char *certfile);

int sign_hash(const char *algo, const unsigned char *hash, int size, const char *keyfile, const char *keypass, unsigned char *sig);
int verify_hash(const char *file, const unsigned char *hash, int size, unsigned char *sig, int siglen);
int ima_verify_signature(const char *file, unsigned char *sig, int siglen, unsigned char *digest, int digestlen);
void init_public_keys(const char *keyfiles);
int imaevm_hash_algo_from_sig(unsigned char *sig);
const char *imaevm_hash_algo_by_id(int algo);

#endif
