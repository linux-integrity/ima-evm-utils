#ifndef _LIBEVM_H
#define _LIBEVM_H

#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>

#include <sys/stat.h>
#include <sys/param.h>
#include <dirent.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#ifdef USE_FPRINTF
#define do_log(level, fmt, args...)	({ if (level <= params.verbose) fprintf(stderr, fmt, ##args); })
#define do_log_dump(level, p, len, cr)	({ if (level <= params.verbose) do_dump(stderr, p, len, cr); })
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

#define	DATA_SIZE	4096
#define SHA1_HASH_LEN   20

#define	EXT2_IOC_GETVERSION	_IOR('v', 1, long)
#define	EXT34_IOC_GETVERSION	_IOR('f', 3, long)

#define	FS_IOC_GETFLAGS		_IOR('f', 1, long)
#define	FS_IOC_SETFLAGS		_IOW('f', 2, long)
#define FS_IOC32_GETFLAGS	_IOR('f', 1, int)
#define FS_IOC32_SETFLAGS	_IOW('f', 2, int)

#define __packed __attribute__((packed))

struct h_misc {
	unsigned long ino;
	uint32_t generation;
	uid_t uid;
	gid_t gid;
	unsigned short mode;
} hmac_misc;

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

enum pkey_hash_algo {
	PKEY_HASH_MD4,
	PKEY_HASH_MD5,
	PKEY_HASH_SHA1,
	PKEY_HASH_RIPE_MD_160,
	PKEY_HASH_SHA256,
	PKEY_HASH_SHA384,
	PKEY_HASH_SHA512,
	PKEY_HASH_SHA224,
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


typedef int (*verify_hash_fn_t)(const unsigned char *hash, int size, unsigned char *sig, int siglen, const char *keyfile);

struct libevm_params {
	int verbose;
	const char *hash_algo;
	int user_hash_algo;
	int x509;
	char *keyfile;
	verify_hash_fn_t verify_hash;
};

struct RSA_ASN1_template {
	const uint8_t *data;
	size_t size;
};

extern const struct RSA_ASN1_template RSA_ASN1_templates[PKEY_HASH__LAST];
extern struct libevm_params params;

void do_dump(FILE *fp, const void *ptr, int len, bool cr);
void dump(const void *ptr, int len);
int get_filesize(const char *filename);
int ima_calc_hash(const char *file, uint8_t *hash);
int get_hash_algo(const char *algo);
RSA *read_pub_key(const char *keyfile);
int verify_hash_v1(const unsigned char *hash, int size, unsigned char *sig, int siglen, const char *keyfile);
int verify_hash_v2(const unsigned char *hash, int size, unsigned char *sig, int siglen, const char *keyfile);

int verify_hash(const unsigned char *hash, int size, unsigned char *sig, int siglen);
int ima_verify_signature(const char *file, unsigned char *sig, int siglen);

#endif
