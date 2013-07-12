/*
 * evm-utils - IMA/EVM support utilities
 *
 * Copyright (C) 2011 Nokia Corporation
 * Copyright (C) 2011,2012,2013 Intel Corporation
 *
 * Authors:
 * Dmitry Kasatkin <dmitry.kasatkin@nokia.com>
 *                 <dmitry.kasatkin@intel.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * File: evmctl.c
 *	 IMA/EVM control program
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <attr/xattr.h>
#include <getopt.h>
#include <signal.h>
#include <keyutils.h>
#include <asm/byteorder.h>
#include <syslog.h>
#include <attr/xattr.h>
#include <dirent.h>
#include <ctype.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#define USE_FPRINTF

#ifdef USE_FPRINTF
#define do_log(level, fmt, args...)	({ if (level <= verbose) fprintf(stderr, fmt, ##args); })
#define do_log_dump(level, p, len)	({ if (level <= verbose) do_dump(stderr, p, len); })
#else
#define do_log(level, fmt, args...)	syslog(level, fmt, ##args)
#define do_log_dump(p, len)
#endif

#ifdef DEBUG
#define log_debug(fmt, args...)		do_log(LOG_DEBUG, "%s:%d " fmt, __func__ , __LINE__ , ##args)
#define log_debug_dump(p, len)		do_log_dump(LOG_DEBUG, p, len)
#else
#define log_debug(fmt, args...)
#define log_debug_dump(p, len)
#endif

#define log_dump(p, len)		do_log_dump(LOG_INFO, p, len)
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
} __attribute__ ((packed));

struct signature_hdr {
	uint8_t version;	/* signature format version */
	uint32_t timestamp;	/* signature made */
	uint8_t algo;
	uint8_t hash;
	uint8_t keyid[8];
	uint8_t nmpi;
	char mpi[0];
} __attribute__ ((packed));

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

const char *const pkey_hash_algo[PKEY_HASH__LAST] = {
	[PKEY_HASH_MD4]		= "md4",
	[PKEY_HASH_MD5]		= "md5",
	[PKEY_HASH_SHA1]	= "sha1",
	[PKEY_HASH_RIPE_MD_160]	= "rmd160",
	[PKEY_HASH_SHA256]	= "sha256",
	[PKEY_HASH_SHA384]	= "sha384",
	[PKEY_HASH_SHA512]	= "sha512",
	[PKEY_HASH_SHA224]	= "sha224",
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
} __attribute__ ((packed));


/*
 * Hash algorithm OIDs plus ASN.1 DER wrappings [RFC4880 sec 5.2.2].
 */
static const uint8_t RSA_digest_info_MD5[] = {
	0x30, 0x20, 0x30, 0x0C, 0x06, 0x08,
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, /* OID */
	0x05, 0x00, 0x04, 0x10
};

static const uint8_t RSA_digest_info_SHA1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x0E, 0x03, 0x02, 0x1A,
	0x05, 0x00, 0x04, 0x14
};

static const uint8_t RSA_digest_info_RIPE_MD_160[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x24, 0x03, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x14
};

static const uint8_t RSA_digest_info_SHA224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
	0x05, 0x00, 0x04, 0x1C
};

static const uint8_t RSA_digest_info_SHA256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x20
};

static const uint8_t RSA_digest_info_SHA384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
	0x05, 0x00, 0x04, 0x30
};

static const uint8_t RSA_digest_info_SHA512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
	0x05, 0x00, 0x04, 0x40
};

static const struct RSA_ASN1_template {
	const uint8_t *data;
	size_t size;
} RSA_ASN1_templates[PKEY_HASH__LAST] = {
#define _(X) { RSA_digest_info_##X, sizeof(RSA_digest_info_##X) }
	[PKEY_HASH_MD5]		= _(MD5),
	[PKEY_HASH_SHA1]	= _(SHA1),
	[PKEY_HASH_RIPE_MD_160]	= _(RIPE_MD_160),
	[PKEY_HASH_SHA256]	= _(SHA256),
	[PKEY_HASH_SHA384]	= _(SHA384),
	[PKEY_HASH_SHA512]	= _(SHA512),
	[PKEY_HASH_SHA224]	= _(SHA224),
#undef _
};

static char *evm_config_xattrnames[] = {
	"security.selinux",
	"security.SMACK64",
	"security.ima",
	"security.capability",
	NULL
};

struct command {
	char *name;
	int (*func)(struct command *cmd);
	int cmd;
	char *arg;
	char *msg;		/* extra info message */
};

static int verbose = LOG_INFO - 1;
static int g_argc;
static char **g_argv;
static int xattr = 1;
static int sigdump;
static int digest;
static int digsig;
static const char *hash_algo = "sha1";
static int user_hash_algo;
static char *keypass;
static int sigfile;
static int modsig;
static char *uuid_str;
static int x509;
static char *keyfile;

typedef int (*sign_hash_fn_t)(const char *algo, const unsigned char *hash, int size, const char *keyfile, unsigned char *sig);

static sign_hash_fn_t sign_hash;

typedef int (*verify_hash_fn_t)(const unsigned char *hash, int size, unsigned char *sig, int siglen, const char *keyfile);

static verify_hash_fn_t verify_hash;

struct command cmds[];
static void print_usage(struct command *cmd);

static void do_dump(FILE *fp, const void *ptr, int len)
{
	int i;
	uint8_t *data = (uint8_t *) ptr;

	for (i = 0; i < len; i++)
		fprintf(fp, "%02x", data[i]);
	fprintf(fp, "\n");
}

static void dump(const void *ptr, int len)
{
	do_dump(stdout, ptr, len);
}

static inline int get_filesize(const char *filename)
{
	struct stat stats;
	/*  Need to know the file length */
	stat(filename, &stats);
	return (int)stats.st_size;
}

static inline int get_fdsize(int fd)
{
	struct stat stats;
	/*  Need to know the file length */
	fstat(fd, &stats);
	return (int)stats.st_size;
}

static int bin2file(const char *file, const char *ext, const unsigned char *data, int len)
{
	FILE *fp;
	char name[strlen(file) + (ext ? strlen(ext) : 0) + 2];
	int err;

	if (ext)
		sprintf(name, "%s.%s", file, ext);
	else
		sprintf(name, "%s", file);

	log_info("Writing to %s\n", name);

	fp = fopen(name, "w");
	if (!fp) {
		log_err("Unable to open %s for writing\n", name);
		return -1;
	}
	err = fwrite(data, len, 1, fp);
	fclose(fp);
	return err;
}

static unsigned char *file2bin(const char *file, const char *ext, int *size)
{
	FILE *fp;
	int len;
	unsigned char *data;
	char name[strlen(file) + (ext ? strlen(ext) : 0) + 2];

	if (ext)
		sprintf(name, "%s.%s", file, ext);
	else
		sprintf(name, "%s", file);

	log_info("Reading to %s\n", name);

	len = get_filesize(name);
	fp = fopen(name, "r");
	if (!fp) {
		log_err("Unable to open %s\n", name);
		return NULL;
	}
	data = malloc(len);
	if (!fread(data, len, 1, fp))
		len = 0;
	fclose(fp);

	*size = len;
	return data;
}

/*
 * Create binary key representation suitable for kernel
 */
static int key2bin(RSA *key, unsigned char *pub)
{
	int len, b, offset = 0;
	struct pubkey_hdr *pkh = (struct pubkey_hdr *)pub;

	/* add key header */
	pkh->version = 1;
	pkh->timestamp = 0;	/* PEM has no timestamp?? */
	pkh->algo = PUBKEY_ALGO_RSA;
	pkh->nmpi = 2;

	offset += sizeof(*pkh);

	len = BN_num_bytes(key->n);
	b = BN_num_bits(key->n);
	pub[offset++] = b >> 8;
	pub[offset++] = b & 0xff;
	BN_bn2bin(key->n, &pub[offset]);
	offset += len;

	len = BN_num_bytes(key->e);
	b = BN_num_bits(key->e);
	pub[offset++] = b >> 8;
	pub[offset++] = b & 0xff;
	BN_bn2bin(key->e, &pub[offset]);
	offset += len;

	return offset;
}

static RSA *read_pub_key(const char *keyfile)
{
	FILE *fp;
	RSA *key = NULL;
	X509 *crt = NULL;
	EVP_PKEY *pkey = NULL;

	fp = fopen(keyfile, "r");
	if (!fp) {
		log_err("Unable to open keyfile %s\n", keyfile);
		return NULL;
	}

	if (x509) {
		crt = d2i_X509_fp(fp, NULL);
		if (!crt) {
			log_err("d2i_X509_fp() failed\n");
			goto out;
		}
		pkey = X509_extract_key(crt);
		if (!pkey) {
			log_err("X509_extract_key() failed\n");
			goto out;
		}
		key = EVP_PKEY_get1_RSA(pkey);
	} else {
		key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	}

	if (!key)
		log_err("PEM_read_RSA_PUBKEY() failed\n");

out:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (crt)
		X509_free(crt);
	fclose(fp);
	return key;
}

static void calc_keyid_v1(uint8_t *keyid, char *str, const unsigned char *pkey, int len)
{
	uint8_t sha1[SHA_DIGEST_LENGTH];
	uint64_t id;

	SHA1(pkey, len, sha1);

	/* sha1[12 - 19] is exactly keyid from gpg file */
	memcpy(keyid, sha1 + 12, 8);
	log_debug("keyid: ");
	log_debug_dump(keyid, 8);

	id = __be64_to_cpup((__be64 *) keyid);
	sprintf(str, "%llX", (unsigned long long)id);
	log_info("keyid: %s\n", str);
}

static void calc_keyid_v2(uint32_t *keyid, char *str, RSA *key)
{
	uint8_t sha1[SHA_DIGEST_LENGTH];
	unsigned char *pkey = NULL;
	int len;

	len = i2d_RSAPublicKey(key, &pkey);

	SHA1(pkey, len, sha1);

	/* sha1[12 - 19] is exactly keyid from gpg file */
	memcpy(keyid, sha1 + 16, 4);
	log_debug("keyid: ");
	log_debug_dump(keyid, 4);

	sprintf(str, "%x", __be32_to_cpup(keyid));
	log_info("keyid: %s\n", str);

	free(pkey);
}

static RSA *read_priv_key(const char *keyfile)
{
	FILE *fp;
	RSA *key;

	fp = fopen(keyfile, "r");
	if (!fp) {
		log_err("Unable to open keyfile %s\n", keyfile);
		return NULL;
	}
	key = PEM_read_RSAPrivateKey(fp, NULL, NULL, keypass);
	if (!key)
		log_err("PEM_read_RSAPrivateKey() failed\n");

	fclose(fp);
	return key;
}

int get_hash_algo_v1(const char *algo)
{

	if (!strcmp(algo, "sha1"))
		return DIGEST_ALGO_SHA1;
	else if (!strcmp(algo, "sha256"))
		return DIGEST_ALGO_SHA256;

	return -1;
}

static int sign_hash_v1(const char *hashalgo, const unsigned char *hash, int size, const char *keyfile, unsigned char *sig)
{
	int err, len, hashalgo_idx;
	SHA_CTX ctx;
	unsigned char pub[1024];
	RSA *key;
	char name[20];
	unsigned char sighash[20];
	struct signature_hdr *hdr = (struct signature_hdr *)sig;
	uint16_t *blen;

	log_info("hash: ");
	log_dump(hash, size);

	key = read_priv_key(keyfile);
	if (!key)
		return -1;

	/* now create a new hash */
	hdr->version = (uint8_t) DIGSIG_VERSION_1;
	hdr->timestamp = time(NULL);
	hdr->algo = PUBKEY_ALGO_RSA;
	hashalgo_idx = get_hash_algo_v1(hashalgo);
	if (hashalgo_idx < 0) {
		log_err("Signature version 1 does not support hash algo %s\n",
			hashalgo);
		return -1;
	}
	hdr->hash = (uint8_t) hashalgo_idx;

	len = key2bin(key, pub);
	calc_keyid_v1(hdr->keyid, name, pub, len);

	hdr->nmpi = 1;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, hash, size);
	SHA1_Update(&ctx, hdr, sizeof(*hdr));
	SHA1_Final(sighash, &ctx);
	log_info("sighash: ");
	log_dump(sighash, sizeof(sighash));

	err = RSA_private_encrypt(sizeof(sighash), sighash, sig + sizeof(*hdr) + 2, key, RSA_PKCS1_PADDING);
	RSA_free(key);
	if (err < 0) {
		log_err("RSA_private_encrypt() failed: %d\n", err);
		return 1;
	}

	len = err;

	/* we add bit length of the signature to make it gnupg compatible */
	blen = (uint16_t *) (sig + sizeof(*hdr));
	*blen = __cpu_to_be16(len << 3);
	len += sizeof(*hdr) + 2;
	log_info("evm/ima signature: %d bytes\n", len);
	if (sigdump || verbose >= LOG_INFO)
		dump(sig, len);

	return len;
}

uint8_t get_hash_algo(const char *algo)
{
	int i;

	for (i = 0; i < PKEY_HASH__LAST; i++)
		if (!strcmp(algo, pkey_hash_algo[i]))
			return i;

	return PKEY_HASH_SHA1;
}

static int sign_hash_v2(const char *algo, const unsigned char *hash, int size, const char *keyfile, unsigned char *sig)
{
	struct signature_v2_hdr *hdr = (struct signature_v2_hdr *)sig;
	int len;
	RSA *key;
	char name[20];
	unsigned char *buf;
	const struct RSA_ASN1_template *asn1;

	log_info("hash: ");
	log_dump(hash, size);

	key = read_priv_key(keyfile);
	if (!key)
		return -1;

	hdr->version = (uint8_t) DIGSIG_VERSION_2;
	hdr->hash_algo = get_hash_algo(algo);

	calc_keyid_v2(&hdr->keyid, name, key);

	asn1 = &RSA_ASN1_templates[hdr->hash_algo];

	buf = malloc(size + asn1->size);
	if (!buf)
		return -1;

	memcpy(buf, asn1->data, asn1->size);
	memcpy(buf + asn1->size, hash, size);
	len = RSA_private_encrypt(size + asn1->size, buf, hdr->sig,
				  key, RSA_PKCS1_PADDING);
	RSA_free(key);
	if (len < 0) {
		log_err("RSA_private_encrypt() failed: %d\n", len);
		return -1;
	}

	/* we add bit length of the signature to make it gnupg compatible */
	hdr->sig_size = __cpu_to_be16(len);
	len += sizeof(*hdr);
	log_info("evm/ima signature: %d bytes\n", len);
	if (sigdump || verbose >= LOG_INFO)
		dump(sig, len);

	return len;
}

static int find_xattr(const char *list, int list_size, const char *xattr)
{
	int len;

	for (; list_size > 0; len++, list_size -= len, list += len) {
		len = strlen(list);
		if (!strcmp(list, xattr))
			return 1;
	}
	return 0;
}

static int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

static void pack_uuid(const char *uuid_str, char *to)
{
	int i;
	for (i = 0; i < 16; ++i) {
		*to++ = (hex_to_bin(*uuid_str) << 4) |
			(hex_to_bin(*(uuid_str + 1)));
		uuid_str += 2;
		switch (i) {
		case 3:
		case 5:
		case 7:
		case 9:
			uuid_str++;
			continue;
		}
	}
}

static int get_uuid(struct stat *st, char *uuid)
{
	uint32_t dev;
	unsigned minor, major;
	char path[PATH_MAX], _uuid[37];
	FILE *fp;
	size_t len;

	if (uuid_str[0] != '-') {
		pack_uuid(uuid_str, uuid);
		return 0;
	}

	dev = st->st_dev;
	major = (dev & 0xfff00) >> 8;
	minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);

	log_debug("dev: %u:%u\n", major, minor);
	sprintf(path, "blkid -s UUID -o value /dev/block/%u:%u", major, minor);

	fp = popen(path, "r");
	if (!fp) {
		log_err("popen() failed\n");
		return -1;
	}

	len = fread(_uuid, 1, sizeof(_uuid), fp);
	pclose(fp);
	if (len != sizeof(_uuid)) {
		log_err("fread() failed\n");
		return -1;
	}

	pack_uuid(_uuid, uuid);

	log_info("uuid: ");
	log_dump(uuid, 16);

	return 0;
}

static int calc_evm_hash(const char *file, unsigned char *hash)
{
	struct stat st;
	int fd, err;
	uint32_t generation;
	EVP_MD_CTX ctx;
	unsigned int mdlen;
	char **xattrname;
	char xattr_value[1024];
	char list[1024];
	ssize_t list_size;
	char uuid[16];

	fd = open(file, 0);
	if (fd < 0) {
		log_err("Unable to open %s\n", file);
		return -1;
	}

	if (fstat(fd, &st)) {
		log_err("fstat() failed\n");
		return -1;
	}

	if (ioctl(fd, EXT34_IOC_GETVERSION, &generation)) {
		log_err("ioctl() failed\n");
		return -1;
	}

	close(fd);

	log_info("generation: %u\n", generation);

	list_size = llistxattr(file, list, sizeof(list));
	if (list_size < 0) {
		log_err("llistxattr() failed\n");
		return -1;
	}

	err = EVP_DigestInit(&ctx, EVP_sha1());
	if (!err) {
		log_err("EVP_DigestInit() failed\n");
		return 1;
	}

	for (xattrname = evm_config_xattrnames; *xattrname != NULL; xattrname++) {
		err = getxattr(file, *xattrname, xattr_value, sizeof(xattr_value));
		if (err < 0) {
			log_info("no xattr: %s\n", *xattrname);
			continue;
		}
		if (!find_xattr(list, list_size, *xattrname)) {
			log_info("skipping xattr: %s\n", *xattrname);
			continue;
		}
		/*log_debug("name: %s, value: %s, size: %d\n", *xattrname, xattr_value, err);*/
		log_info("name: %s, size: %d\n", *xattrname, err);
		log_debug_dump(xattr_value, err);
		err = EVP_DigestUpdate(&ctx, xattr_value, err);
		if (!err) {
			log_err("EVP_DigestUpdate() failed\n");
			return 1;
		}
	}

	memset(&hmac_misc, 0, sizeof(hmac_misc));
	hmac_misc.ino = st.st_ino;
	hmac_misc.generation = generation;
	hmac_misc.uid = st.st_uid;
	hmac_misc.gid = st.st_gid;
	hmac_misc.mode = st.st_mode;

	err = EVP_DigestUpdate(&ctx, (const unsigned char *)&hmac_misc, sizeof(hmac_misc));
	if (!err) {
		log_err("EVP_DigestUpdate() failed\n");
		return 1;
	}

	if (uuid_str) {
		err = get_uuid(&st, uuid);
		if (err)
			return -1;

		err = EVP_DigestUpdate(&ctx, (const unsigned char *)uuid, sizeof(uuid));
		if (!err) {
			log_err("EVP_DigestUpdate() failed\n");
			return 1;
		}
	}

	err = EVP_DigestFinal(&ctx, hash, &mdlen);
	if (!err) {
		log_err("EVP_DigestFinal() failed\n");
		return 1;
	}

	return mdlen;
}

static int sign_evm(const char *file, const char *key)
{
	unsigned char hash[20];
	unsigned char sig[1024] = "\x03";
	int len, err;

	len = calc_evm_hash(file, hash);
	if (len <= 1)
		return len;

	len = sign_hash("sha1", hash, len, key, sig + 1);
	if (len <= 1)
		return len;

	if (xattr) {
		err = setxattr(file, "security.evm", sig, len + 1, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int add_file_hash(const char *file, EVP_MD_CTX *ctx)
{
	uint8_t *data;
	int err, size, bs = DATA_SIZE;
	size_t len;
	FILE *fp;

	data = malloc(bs);
	if (!data) {
		log_err("malloc failed\n");
		return -1;
	}

	fp = fopen(file, "r");
	if (!fp) {
		log_err("Unable to open %s\n", file);
		return -1;
	}

	for (size = get_fdsize(fileno(fp)); size; size -= len) {
		len = MIN(size, bs);
		err = fread(data, len, 1, fp);
		if (!err) {
			if (ferror(fp)) {
				log_err("fread() error\n\n");
				return -1;
			}
			break;
		}
		err = EVP_DigestUpdate(ctx, data, len);
		if (!err) {
			log_err("EVP_DigestUpdate() failed\n");
			return 1;
		}
	}

	fclose(fp);
	free(data);

	return 0;
}

static int add_dir_hash(const char *file, EVP_MD_CTX *ctx)
{
	int err;
	struct dirent *de;
	DIR *dir;
	unsigned long long ino, off;
	unsigned int type;

	dir = opendir(file);
	if (!dir) {
		log_err("Unable to open %s\n", file);
		return -1;
	}

	while ((de = readdir(dir))) {
		ino = de->d_ino;
		off = de->d_off;
		type = de->d_type;
		log_debug("entry: %s, ino: %llu, type: %u, off: %llu, reclen: %hu\n",
			  de->d_name, ino, type, off, de->d_reclen);
		err = EVP_DigestUpdate(ctx, de->d_name, strlen(de->d_name));
		/*err |= EVP_DigestUpdate(ctx, &off, sizeof(off));*/
		err |= EVP_DigestUpdate(ctx, &ino, sizeof(ino));
		err |= EVP_DigestUpdate(ctx, &type, sizeof(type));
		if (!err) {
			log_err("EVP_DigestUpdate() failed\n");
			return 1;
		}
	}

	closedir(dir);

	return 0;
}

static int add_link_hash(const char *path, EVP_MD_CTX *ctx)
{
	int err;
	char buf[1024];

	err = readlink(path, buf, sizeof(buf));
	if (err <= 0)
		return -1;

	log_info("link: %s -> %.*s\n", path, err, buf);
	return !EVP_DigestUpdate(ctx, buf, err);
}

static int add_dev_hash(struct stat *st, EVP_MD_CTX *ctx)
{
	uint32_t dev = st->st_rdev;
	unsigned major = (dev & 0xfff00) >> 8;
	unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
	log_info("device: %u:%u\n", major, minor);
	return !EVP_DigestUpdate(ctx, &dev, sizeof(dev));
}

static int calc_hash(const char *file, uint8_t *hash)
{
	struct stat st;
	EVP_MD_CTX ctx;
	const EVP_MD *md;
	unsigned int mdlen;
	int err;

	/*  Need to know the file length */
	err = lstat(file, &st);
	if (err < 0) {
		log_err("stat() failed\n");
		return err;
	}

	md = EVP_get_digestbyname(hash_algo);
	if (!md) {
		log_err("EVP_get_digestbyname() failed\n");
		return 1;
	}

	err = EVP_DigestInit(&ctx, md);
	if (!err) {
		log_err("EVP_DigestInit() failed\n");
		return 1;
	}

	switch (st.st_mode & S_IFMT) {
	case S_IFREG:
		err = add_file_hash(file, &ctx);
		break;
	case S_IFDIR:
		err = add_dir_hash(file, &ctx);
		break;
	case S_IFLNK:
		err = add_link_hash(file, &ctx);
		break;
	case S_IFIFO: case S_IFSOCK:
	case S_IFCHR: case S_IFBLK:
		err = add_dev_hash(&st, &ctx);
		break;
	default:
		log_errno("Unsupported file type");
		return -1;
	}

	if (err)
		return err;

	err = EVP_DigestFinal(&ctx, hash, &mdlen);
	if (!err) {
		log_err("EVP_DigestFinal() failed\n");
		return 1;
	}

	return mdlen;
}

static int hash_ima(const char *file)
{
	unsigned char hash[65] = "\x01"; /* MAX hash size + 1 */
	int len, err;

	len = calc_hash(file, hash + 1);
	if (len <= 1)
		return len;

	if (verbose >= LOG_INFO)
		log_info("hash: ");

	if (sigdump || verbose >= LOG_INFO)
		dump(hash, len + 1);

	if (xattr) {
		err = setxattr(file, "security.ima", hash, len + 1, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int cmd_hash_ima(struct command *cmd)
{
	char *file = g_argv[optind++];

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	return hash_ima(file);
}

static int sign_ima(const char *file, const char *key)
{
	unsigned char hash[64];
	unsigned char sig[1024] = "\x03";
	char magic[] = "This Is A Crypto Signed Module";
	int len, err;

	len = calc_hash(file, hash);
	if (len <= 1)
		return len;

	len = sign_hash(hash_algo, hash, len, key, sig + 1);
	if (len <= 1)
		return len;

	/* add header */
	len++;

	if (modsig) {
		/* add signature length */
		*(uint16_t *)(sig + len) = __cpu_to_be16(len - 1);
		len += sizeof(uint16_t);
		memcpy(sig + len, magic, sizeof(magic) - 1);
		len += sizeof(magic) - 1;
		bin2file(file, "sig", sig + 1, len - 1);
		return 0;
	}

	if (sigfile)
		bin2file(file, "sig", sig + 1, len - 1);

	if (xattr) {
		err = setxattr(file, "security.ima", sig, len, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int cmd_sign_ima(struct command *cmd)
{
	char *key, *file = g_argv[optind++];

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	key = keyfile ? : "/etc/keys/privkey_evm.pem";

	return sign_ima(file, key);

}

static int cmd_sign_evm(struct command *cmd)
{
	char *key, *file = g_argv[optind++];
	int err;

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	if (!digsig && !digest) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	key = keyfile ? : "/etc/keys/privkey_evm.pem";

	if (digsig) {
		err = sign_ima(file, key);
		if (err)
			return err;
	}

	if (digest) {
		err = hash_ima(file);
		if (err)
			return err;
	}

	return sign_evm(file, key);
}

static int verify_hash_v1(const unsigned char *hash, int size, unsigned char *sig, int siglen, const char *keyfile)
{
	int err, len;
	SHA_CTX ctx;
	unsigned char out[1024];
	RSA *key;
	unsigned char sighash[20];
	struct signature_hdr *hdr = (struct signature_hdr *)sig;

	log_info("hash: ");
	log_dump(hash, size);

	key = read_pub_key(keyfile);
	if (!key)
		return 1;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, hash, size);
	SHA1_Update(&ctx, hdr, sizeof(*hdr));
	SHA1_Final(sighash, &ctx);
	log_info("sighash: ");
	log_dump(sighash, sizeof(sighash));

	err = RSA_public_decrypt(siglen - sizeof(*hdr) - 2, sig + sizeof(*hdr) + 2, out, key, RSA_PKCS1_PADDING);
	RSA_free(key);
	if (err < 0) {
		log_err("RSA_public_decrypt() failed: %d\n", err);
		return 1;
	}

	len = err;

	if (len != sizeof(sighash) || memcmp(out, sighash, len) != 0) {
		log_err("Verification failed: %d\n", err);
		return -1;
	} else {
		/*log_info("Verification is OK\n");*/
		printf("Verification is OK\n");
	}

	return 0;
}

static int verify_hash_v2(const unsigned char *hash, int size, unsigned char *sig, int siglen, const char *keyfile)
{
	int err, len;
	unsigned char out[1024];
	RSA *key;
	struct signature_v2_hdr *hdr = (struct signature_v2_hdr *)sig;
	const struct RSA_ASN1_template *asn1;

	log_info("hash: ");
	log_dump(hash, size);

	key = read_pub_key(keyfile);
	if (!key)
		return 1;

	err = RSA_public_decrypt(siglen - sizeof(*hdr), sig + sizeof(*hdr), out, key, RSA_PKCS1_PADDING);
	RSA_free(key);
	if (err < 0) {
		log_err("RSA_public_decrypt() failed: %d\n", err);
		return 1;
	}

	len = err;

	asn1 = &RSA_ASN1_templates[hdr->hash_algo];

	if (len < asn1->size || memcmp(out, asn1->data, asn1->size)) {
		log_err("Verification failed: %d\n", err);
		return -1;
	}

	len -= asn1->size;

	if (len != size || memcmp(out + asn1->size, hash, len)) {
		log_err("Verification failed: %d\n", err);
		return -1;
	}

	/*log_info("Verification is OK\n");*/
	printf("Verification is OK\n");

	return 0;
}

static int verify_evm(const char *file, const char *key)
{
	unsigned char hash[20];
	unsigned char sig[1024];
	int len;

	len = calc_evm_hash(file, hash);
	if (len <= 1)
		return len;

	len = getxattr(file, "security.evm", sig, sizeof(sig));
	if (len < 0) {
		log_err("getxattr failed\n");
		return len;
	}

	if (sig[0] != 0x03) {
		log_err("security.evm has not signature\n");
		return -1;
	}

	return verify_hash(hash, sizeof(hash), sig + 1, len - 1, key);
}

static int cmd_verify_evm(struct command *cmd)
{
	char *key, *file = g_argv[optind++];

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	key = keyfile ? : x509 ?
			"/etc/keys/x509_evm.der" :
			"/etc/keys/pubkey_evm.pem";

	return verify_evm(file, key);
}

static int get_hash_algo_from_sig(unsigned char *sig)
{
	uint8_t hashalgo;

	if (sig[0] == 1) {
		hashalgo = ((struct signature_hdr *)sig)->hash;

		if (hashalgo >= DIGEST_ALGO_MAX)
			return -1;

		switch (hashalgo) {
		case DIGEST_ALGO_SHA1:
			return PKEY_HASH_SHA1;
		case DIGEST_ALGO_SHA256:
			return PKEY_HASH_SHA256;
		default:
			return -1;
		}
	} else if (sig[0] == 2) {
		hashalgo = ((struct signature_v2_hdr *)sig)->hash_algo;
		if (hashalgo >= PKEY_HASH__LAST)
			return -1;
		return hashalgo;
	} else
		return -1;
}

static int verify_ima(const char *file, const char *key)
{
	unsigned char hash[64];
	unsigned char sig[1024];
	int len, hashlen;
	int sig_hash_algo;

	if (xattr) {
		len = getxattr(file, "security.ima", sig, sizeof(sig));
		if (len < 0) {
			log_err("getxattr failed\n");
			return len;
		}
	}

	if (sigfile) {
		void *tmp;
		tmp = file2bin(file, "sig", &len);
		sig[0] = 0x03;
		memcpy(sig+1, tmp, len++);
		free(tmp);
	}

	if (sig[0] != 0x03) {
		log_err("security.ima has no signature\n");
		return -1;
	}

	/* If user specified an hash algo on command line, let it override */
	if (!user_hash_algo) {
		sig_hash_algo = get_hash_algo_from_sig(sig + 1);
		if (sig_hash_algo < 0) {
			log_err("Invalid signature\n");
			return -1;
		}

		/* Use hash algorithm as retrieved from signature */
		hash_algo = pkey_hash_algo[sig_hash_algo];
	}

	hashlen = calc_hash(file, hash);
	if (hashlen <= 1)
		return hashlen;

	return verify_hash(hash, hashlen, sig + 1, len - 1, key);
}

static int cmd_verify_ima(struct command *cmd)
{
	char *key, *file = g_argv[optind++];

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	key = keyfile ? : x509 ?
			"/etc/keys/x509_evm.der" :
			"/etc/keys/pubkey_evm.pem";

	return verify_ima(file, key);
}

static int cmd_import(struct command *cmd)
{
	char *inkey, *ring = NULL;
	unsigned char _pub[1024], *pub = _pub;
	int id, len, err = -1;
	char name[20];
	uint8_t keyid[8];
	RSA *key = NULL;

	inkey = g_argv[optind++];
	if (!inkey) {
		inkey = x509 ? "/etc/keys/x509_evm.der" :
			       "/etc/keys/pubkey_evm.pem";
	} else
		ring = g_argv[optind++];

	if (!ring)
		id = KEY_SPEC_USER_KEYRING;
	else
		id = atoi(ring);

	key = read_pub_key(inkey);
	if (!key)
		goto out;

	if (x509) {
		pub = file2bin(inkey, NULL, &len);
		if (!pub)
			goto out;
		calc_keyid_v2((uint32_t *)keyid, name, key);
	} else {
		len = key2bin(key, pub);
		calc_keyid_v1(keyid, name, pub, len);
	}

	log_info("Importing public key %s from file %s into keyring %d\n", name, inkey, id);

	id = add_key(x509 ? "asymmetric" : "user", x509 ? NULL : name, pub, len, id);
	if (id < 0) {
		log_err("add_key failed\n");
		goto out;
	}

	log_info("keyid: %d\n", id);
	printf("%d\n", id);

	err = 0;
out:
	if (key)
		RSA_free(key);
	if (x509)
		free(pub);

	return err;
}

#define MAX_KEY_SIZE 128

static int calc_evm_hmac(const char *file, const char *keyfile, unsigned char *hash)
{
	struct stat st;
	int fd, err;
	uint32_t generation;
	HMAC_CTX ctx;
	unsigned int mdlen;
	char **xattrname;
	unsigned char xattr_value[1024];
	unsigned char *key;
	int keylen;
	unsigned char evmkey[MAX_KEY_SIZE];
	char list[1024];
	ssize_t list_size;

	key = file2bin(keyfile, NULL, &keylen);
	if (!key) {
		log_err("Unable to read a key: %s\n\n", keyfile);
		return -1;
	}

	if (keylen > sizeof(evmkey)) {
		log_err("key is too long\n");
		return -1;
	}

	/* EVM key is 128 bytes */
	memcpy(evmkey, key, keylen);
	memset(evmkey + keylen, 0, sizeof(evmkey) - keylen);

	fd = open(file, 0);
	if (fd < 0) {
		log_err("Unable to open %s\n", file);
		return -1;
	}

	if (fstat(fd, &st)) {
		log_err("fstat() failed\n");
		return -1;
	}

	if (ioctl(fd, EXT34_IOC_GETVERSION, &generation)) {
		log_err("ioctl() failed\n");
		return -1;
	}

	close(fd);

	log_info("generation: %u\n", generation);

	list_size = llistxattr(file, list, sizeof(list));
	if (list_size <= 0) {
		log_err("llistxattr() failed\n");
		return -1;
	}

	err = HMAC_Init(&ctx, evmkey, sizeof(evmkey), EVP_sha1());
	if (!err) {
		log_err("HMAC_Init() failed\n");
		return 1;
	}

	for (xattrname = evm_config_xattrnames; *xattrname != NULL; xattrname++) {
		err = getxattr(file, *xattrname, xattr_value, sizeof(xattr_value));
		if (err < 0) {
			log_info("no xattr: %s\n", *xattrname);
			continue;
		}
		if (!find_xattr(list, list_size, *xattrname)) {
			log_info("skipping xattr: %s\n", *xattrname);
			continue;
		}
		/*log_debug("name: %s, value: %s, size: %d\n", *xattrname, xattr_value, err);*/
		log_info("name: %s, size: %d\n", *xattrname, err);
		log_debug_dump(xattr_value, err);
		err = HMAC_Update(&ctx, xattr_value, err);
		if (!err) {
			log_err("HMAC_Update() failed\n");
			return 1;
		}
	}

	memset(&hmac_misc, 0, sizeof(hmac_misc));
	hmac_misc.ino = st.st_ino;
	hmac_misc.generation = generation;
	hmac_misc.uid = st.st_uid;
	hmac_misc.gid = st.st_gid;
	hmac_misc.mode = st.st_mode;

	err = HMAC_Update(&ctx, (const unsigned char *)&hmac_misc, sizeof(hmac_misc));
	if (!err) {
		log_err("HMAC_Update() failed\n");
		return 1;
	}
	err = HMAC_Final(&ctx, hash, &mdlen);
	if (!err) {
		log_err("HMAC_Final() failed\n");
		return 1;
	}
	HMAC_CTX_cleanup(&ctx);

	free(key);

	return mdlen;
}

static int hmac_evm(const char *file, const char *key)
{
	unsigned char hash[20];
	unsigned char sig[1024] = "\x02";
	int len, err;

	len = calc_evm_hmac(file, key, hash);
	if (len <= 1)
		return len;

	log_info("hmac: ");
	log_dump(hash, len);
	memcpy(sig + 1, hash, len);

	if (xattr) {
		err = setxattr(file, "security.evm", sig, len + 1, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int cmd_hmac_evm(struct command *cmd)
{
	char *key, *file = g_argv[optind++];
	int err;

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	if (!digsig && !digest) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	key = keyfile ? : "/etc/keys/privkey_evm.pem";

	if (digsig) {
		err = sign_ima(file, key);
		if (err)
			return err;
	}

	if (digest) {
		err = hash_ima(file);
		if (err)
			return err;
	}

	return hmac_evm(file, "/etc/keys/evm-key-plain");
}

static void print_usage(struct command *cmd)
{
	printf("usage: %s %s\n", cmd->name, cmd->arg ? cmd->arg : "");
}

static void print_full_usage(struct command *cmd)
{
	if (cmd->name)
		printf("usage: %s %s\n", cmd->name, cmd->arg ? cmd->arg : "");
	if (cmd->msg)
		printf("%s", cmd->msg);
}

static int print_command_usage(struct command *cmds, char *command)
{
	struct command *cmd;

	for (cmd = cmds; cmd->name; cmd++) {
		if (strcmp(cmd->name, command) == 0) {
			print_full_usage(cmd);
			return 0;
		}
	}
	printf("invalid command: %s\n", command);
	return -1;
}

static void print_all_usage(struct command *cmds)
{
	struct command *cmd;

	printf("commands:\n");

	for (cmd = cmds; cmd->name; cmd++) {
		if (cmd->arg)
			printf(" %s %s\n", cmd->name, cmd->arg);
		else if (cmd->msg)
			printf(" %s", cmd->msg);
	}
}

static int call_command(struct command *cmds, char *command)
{
	struct command *cmd;

	for (cmd = cmds; cmd->name; cmd++) {
		if (strcasecmp(cmd->name, command) == 0)
			return cmd->func(cmd);
	}
	printf("Invalid command: %s\n", command);
	return -1;
}

static int cmd_help(struct command *cmd)
{
	if (!g_argv[optind]) {
		print_usage(cmd);
		return 0;
	} else
		return print_command_usage(cmds, g_argv[optind]);
}

static void usage(void)
{
	printf("Usage: evmctl [-v] <command> [OPTIONS]\n");

	print_all_usage(cmds);

	printf(
		"\n"
		"  -a, --hashalgo     sha1 (default), sha224, sha256, sha384, sha512\n"
		"  -s, --imasig       also make IMA signature\n"
		"  -d, --imahash      also make IMA hash\n"
		"  -f, --sigfile      store IMA signature in .sig file instead of xattr\n"
		"  -m, --modsig       store module signature in .sig file instead of xattr\n"
		"  -x, --x509         signing key is in x509 DER format (signing v2 for using asymmetric keys)\n"
		"  -k, --key          path to signing key (default keys are /etc/keys/{privkey,pubkey}_evm.pem)\n"
		"  -p, --pass         password for encrypted signing key\n"
		"  -n                 print result to stdout instead of setting xattr\n"
		"  -v                 increase verbosity level\n"
		"  -h, --help         display this help and exit\n"
		"\n");
}

struct command cmds[] = {
	{"help", cmd_help, 0, "<command>"},
	{"import", cmd_import, 0, "[--x509] pubkey keyring", "Import public key into the keyring.\n"},
	{"sign", cmd_sign_evm, 0, "[--imahash | --imasig ] [--key key] [--pass password] file", "Sign file metadata.\n"},
	{"verify", cmd_verify_evm, 0, "file", "Verify EVM signature (for debugging).\n"},
	{"ima_sign", cmd_sign_ima, 0, "[--sigfile | --modsig] [--key key] [--pass password] file", "Make file content signature.\n"},
	{"ima_verify", cmd_verify_ima, 0, "file", "Verify IMA signature (for debugging).\n"},
	{"ima_hash", cmd_hash_ima, 0, "file", "Make file content hash.\n"},
#ifdef DEBUG
	{"hmac", cmd_hmac_evm, 0, "[--imahash | --imasig ] file", "Sign file metadata with HMAC using symmetric key (for testing purpose).\n"},
#endif
	{0, 0, 0, NULL}
};

static struct option opts[] = {
	{"help", 0, 0, 'h'},
	{"imasig", 0, 0, 's'},
	{"imahash", 0, 0, 'd'},
	{"hashalgo", 1, 0, 'a'},
	{"pass", 1, 0, 'p'},
	{"sigfile", 0, 0, 'f'},
	{"modsig", 0, 0, 'm'},
	{"uuid", 1, 0, 'u'},
	{"x509", 0, 0, 'x'},
	{"key", 1, 0, 'k'},
	{}

};

int main(int argc, char *argv[])
{
	int err = 0, c, lind;

	g_argv = argv;
	g_argc = argc;

	sign_hash = sign_hash_v1;
	verify_hash = verify_hash_v1;

	while (1) {
		c = getopt_long(argc, argv, "hvnsda:p:fu:xk:", opts, &lind);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			exit(0);
			break;
		case 'v':
			verbose++;
			break;
		case 'd':
			digest = 1;
			break;
		case 's':
			digsig = 1;
			break;
		case 'n':
			/* do not set Extended Attributes... just print signature */
			xattr = 0;
			sigdump = 1;
			break;
		case 'a':
			hash_algo = optarg;
			user_hash_algo = 1;
			break;
		case 'p':
			keypass = optarg;
			break;
		case 'f':
			sigfile = 1;
			xattr = 0;
			break;
		case 'm':
			modsig = 1;
			xattr = 0;
			break;
		case 'u':
			uuid_str = optarg;
			break;
		case 'x':
			x509 = 1;
			sign_hash = sign_hash_v2;
			verify_hash = verify_hash_v2;
			break;
		case 'k':
			keyfile = optarg;
			break;
		case '?':
			exit(1);
			break;
		default:
			log_err("getopt() returned: %d (%c)\n", c, c);
		}
	}

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	if (argv[optind] == NULL)
		usage();
	else
		err = call_command(cmds, argv[optind++]);

	if (err) {
		unsigned long error;
		if (errno)
			log_err("errno: %s (%d)\n", strerror(errno), errno);
		for (;;) {
			error = ERR_get_error();
			if (!error)
				break;
			log_err("%s\n", ERR_error_string(error, NULL));
		}
	}

	ERR_free_strings();
	EVP_cleanup();

	return err;
}
