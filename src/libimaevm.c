// SPDX-License-Identifier: LGPL-2.0-or-later
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
 * File: libimaevm.c
 *	 IMA/EVM library
 */

/* should we use logger instead for library? */
#define USE_FPRINTF

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <asm/byteorder.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#if CONFIG_IMA_EVM_PROVIDER
#include <openssl/provider.h>
#include <openssl/ui.h>
#include <openssl/store.h>
#endif

#include "imaevm.h"
#include "hash_info.h"

static int read_keyid_from_cert(uint32_t *keyid_be, const char *certfile,
				int try_der);

/* Names that are primary for OpenSSL. */
static const char *const pkey_hash_algo[PKEY_HASH__LAST] = {
	[PKEY_HASH_MD4]		= "md4",
	[PKEY_HASH_MD5]		= "md5",
	[PKEY_HASH_SHA1]	= "sha1",
	[PKEY_HASH_RIPE_MD_160]	= "rmd160",
	[PKEY_HASH_SHA256]	= "sha256",
	[PKEY_HASH_SHA384]	= "sha384",
	[PKEY_HASH_SHA512]	= "sha512",
	[PKEY_HASH_SHA224]	= "sha224",
	[PKEY_HASH_SM3_256]	= "sm3",
	[PKEY_HASH_STREEBOG_256] = "md_gost12_256",
	[PKEY_HASH_STREEBOG_512] = "md_gost12_512",
};

/* Names that are primary for the kernel. */
static const char *const pkey_hash_algo_kern[PKEY_HASH__LAST] = {
	[PKEY_HASH_STREEBOG_256] = "streebog256",
	[PKEY_HASH_STREEBOG_512] = "streebog512",
};

struct libimaevm_params imaevm_params = {
	.verbose = LOG_INFO,
	.x509 = 1,
	.hash_algo = DEFAULT_HASH_ALGO,
};

static void __attribute__ ((constructor)) libinit(void);

void imaevm_do_hexdump(FILE *fp, const void *ptr, int len, bool newline)
{
	int i;
	uint8_t *data = (uint8_t *) ptr;

	for (i = 0; i < len; i++)
		fprintf(fp, "%02x", data[i]);
	if (newline)
		fprintf(fp, "\n");
}

void imaevm_hexdump(const void *ptr, int len)
{
	imaevm_do_hexdump(stdout, ptr, len, true);
}

const char *imaevm_hash_algo_by_id(int algo)
{
	if (algo < PKEY_HASH__LAST)
		return pkey_hash_algo[algo];
	if (algo < HASH_ALGO__LAST)
		return hash_algo_name[algo];

	log_err("digest %d not found\n", algo);
	return NULL;
}

/* Output all remaining openssl error messages. */
static void output_openssl_errors(void)
{
	while (ERR_peek_error()) {
		char buf[256];
		/* buf must be at least 256 bytes long according to man */

		ERR_error_string(ERR_get_error(), buf);
		log_err("openssl: %s\n", buf);
	}
}

static int add_file_hash(const char *file, EVP_MD_CTX *ctx)
{
	uint8_t *data;
	int err = -1, bs = DATA_SIZE;
	off_t size, len;
	FILE *fp;
	struct stat stats;

	fp = fopen(file, "r");
	if (!fp) {
		log_err("Failed to open: %s\n", file);
		return -1;
	}

	data = malloc(bs);
	if (!data) {
		log_err("malloc failed\n");
		goto out;
	}

	if (fstat(fileno(fp), &stats) == -1) {
		log_err("Failed to fstat: %s (%s)\n", file, strerror(errno));
		goto out;
	}

	for (size = stats.st_size; size; size -= len) {
		len = MIN(size, bs);
		if (fread(data, len, 1, fp) != 1) {
			if (ferror(fp)) {
				log_err("fread() failed\n\n");
				goto out;
			}
			break;
		}
		if (!EVP_DigestUpdate(ctx, data, len)) {
			log_err("EVP_DigestUpdate() failed\n");
			err = 1;
			goto out;
		}
	}
	err = 0;
out:
	fclose(fp);
	free(data);

	return err;
}

int ima_calc_hash2(const char *file, const char *hash_algo, uint8_t *hash)
{
	const EVP_MD *md;
	struct stat st;
	EVP_MD_CTX *pctx;
	unsigned int mdlen;
	int err;
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX ctx;
	pctx = &ctx;
#else
	pctx = EVP_MD_CTX_new();
#endif

	/*  Need to know the file length */
	err = lstat(file, &st);
	if (err < 0) {
		log_err("Failed to stat: %s\n", file);
		goto err;
	}

	md = EVP_get_digestbyname(hash_algo);
	if (!md) {
		log_err("EVP_get_digestbyname(%s) failed\n", hash_algo);
		err = 1;
		goto err;
	}

	err = EVP_DigestInit(pctx, md);
	if (!err) {
		log_err("EVP_DigestInit() failed\n");
		err = 1;
		goto err;
	}

	switch (st.st_mode & S_IFMT) {
	case S_IFREG:
		err = add_file_hash(file, pctx);
		break;
	default:
		log_err("Unsupported file type (0x%x)", st.st_mode & S_IFMT);
		err = -1;
		goto err;
	}

	if (err)
		goto err;

	err = EVP_DigestFinal(pctx, hash, &mdlen);
	if (!err) {
		log_err("EVP_DigestFinal() failed\n");
		err = 1;
		goto err;
	}
	err = mdlen;
err:
	if (err == 1)
		output_openssl_errors();
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	EVP_MD_CTX_free(pctx);
#endif
	return err;
}

int ima_calc_hash(const char *file, uint8_t *hash)
{
	return ima_calc_hash2(file, imaevm_params.hash_algo, hash);
}

EVP_PKEY *read_pub_pkey(const char *keyfile, int x509)
{
	FILE *fp;
	EVP_PKEY *pkey = NULL;
	struct stat st;

	if (!keyfile)
		return NULL;

	fp = fopen(keyfile, "r");
	if (!fp) {
		if (imaevm_params.verbose > LOG_INFO)
			log_info("Failed to open keyfile: %s\n", keyfile);
		return NULL;
	}

	if (fstat(fileno(fp), &st) == -1) {
		log_err("Failed to fstat key file: %s\n", keyfile);
		goto out;
	}

	if ((st.st_mode & S_IFMT) != S_IFREG) {
		if (imaevm_params.verbose > LOG_INFO)
			log_err("Key file is not regular file: %s\n", keyfile);
		goto out;
	}

	if (x509) {
		X509 *crt = d2i_X509_fp(fp, NULL);

		if (!crt) {
			log_err("Failed to d2i_X509_fp key file: %s\n",
				keyfile);
			goto out;
		}
		pkey = X509_extract_key(crt);
		X509_free(crt);
		if (!pkey) {
			log_err("Failed to X509_extract_key key file: %s\n",
				keyfile);
			goto out;
		}
	} else {
		pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
		if (!pkey)
			log_err("Failed to PEM_read_PUBKEY key file: %s\n",
				keyfile);
	}

out:
	if (!pkey)
		output_openssl_errors();
	fclose(fp);
	return pkey;
}

#if CONFIG_SIGV1
RSA *read_pub_key(const char *keyfile, int x509)
{
	EVP_PKEY *pkey;
	RSA *key;

	pkey = read_pub_pkey(keyfile, x509);
	if (!pkey)
		return NULL;
	key = EVP_PKEY_get1_RSA(pkey);
	EVP_PKEY_free(pkey);
	if (!key) {
		log_err("read_pub_key: unsupported key type\n");
		output_openssl_errors();
		return NULL;
	}
	return key;
}

static int verify_hash_v1(const char *file, const unsigned char *hash, int size,
			  unsigned char *sig, int siglen, const char *keyfile)
{
	int err, len;
	SHA_CTX ctx;
	unsigned char out[1024];
	RSA *key;
	unsigned char sighash[20];
	struct signature_hdr *hdr = (struct signature_hdr *)sig;

	log_info("hash-v1: ");
	log_dump(hash, size);

	key = read_pub_key(keyfile, 0);
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
		log_err("%s: RSA_public_decrypt() failed: %d\n", file, err);
		output_openssl_errors();
		return 1;
	}

	len = err;

	if (len != sizeof(sighash) || memcmp(out, sighash, len) != 0) {
		log_err("%s: verification failed: %d\n", file, err);
		return -1;
	}

	return 0;
}
#endif  /* CONFIG_SIGV1 */

struct public_key_entry {
	struct public_key_entry *next;
	uint32_t keyid;
	char name[9];
	EVP_PKEY *key;
};
static struct public_key_entry *g_public_keys = NULL;

static EVP_PKEY *find_keyid(struct public_key_entry *public_keys,
			    uint32_t keyid)
{
	struct public_key_entry *entry, *tail = public_keys;
	int i = 1;

	for (entry = public_keys; entry; entry = entry->next) {
		if (entry->keyid == keyid)
			return entry->key;
		i++;
		tail = entry;
	}

	/* add unknown keys to list */
	entry = calloc(1, sizeof(struct public_key_entry));
	if (!entry) {
		perror("calloc");
		return 0;
	}
	entry->keyid = keyid;
	if (tail)
		tail->next = entry;
	else
		public_keys = entry;
	log_err("key %d: %x (unknown keyid)\n", i, __be32_to_cpup(&keyid));
	return 0;
}

void imaevm_free_public_keys(struct public_key_entry *public_keys)
{
	struct public_key_entry *entry = public_keys, *next;

	while (entry) {
		next = entry->next;
		if (entry->key)
			free(entry->key);
		free(entry);
		entry = next;
	}
}

int imaevm_init_public_keys(const char *keyfiles,
			    struct public_key_entry **public_keys)
{
	struct public_key_entry *entry;
	char *tmp_keyfiles, *keyfiles_free;
	char *keyfile;
	int err = 0;
	int i = 1;

	if (!public_keys)
		return -EINVAL;

	*public_keys = NULL;

	tmp_keyfiles = strdup(keyfiles);
	keyfiles_free = tmp_keyfiles;

	while ((keyfile = strsep(&tmp_keyfiles, ", \t")) != NULL) {
		if ((*keyfile == '\0') || (*keyfile == ' ') ||
		    (*keyfile == '\t'))
			continue;

		entry = malloc(sizeof(struct public_key_entry));
		if (!entry) {
			perror("malloc");
			err = -ENOMEM;
			break;
		}

		entry->key = read_pub_pkey(keyfile, 1);
		if (!entry->key) {
			free(entry);
			continue;
		}

		if (read_keyid_from_cert(&entry->keyid, keyfile, 1) < 0)
			calc_keyid_v2(&entry->keyid, entry->name, entry->key);

		sprintf(entry->name, "%x", __be32_to_cpup(&entry->keyid));
		log_info("key %d: %s %s\n", i++, entry->name, keyfile);
		entry->next = *public_keys;
		*public_keys = entry;
	}

	free(keyfiles_free);
	if (err < 0)
		imaevm_free_public_keys(*public_keys);
	return err;
}

void init_public_keys(const char *keyfiles)
{
	imaevm_init_public_keys(keyfiles, &g_public_keys);
}

/*
 * Verify a signature, prefixed with the signature_v2_hdr, either based
 * directly or indirectly on the file data hash.
 *
 * version 2: directly based on the file data hash (e.g. sha*sum)
 * version 3: indirectly based on the hash of the struct ima_file_id, which
 *	      contains the xattr type (enum evm_ima_xattr_type), the hash
 *	      algorithm (enum hash_algo), and the file data hash
 *	      (e.g. fsverity digest).
 *
 * Return: 0 verification good, 1 verification bad, -1 error.
 *
 * (Note: signature_v2_hdr struct does not contain the 'type'.)
 */
static int verify_hash_common(struct public_key_entry *public_keys,
			      const char *file, const char *hash_algo,
			      const unsigned char *hash,
			      int size, unsigned char *sig, int siglen)
{
	int ret = -1;
	EVP_PKEY *pkey, *pkey_free = NULL;
	struct signature_v2_hdr *hdr = (struct signature_v2_hdr *)sig;
	EVP_PKEY_CTX *ctx;
	const EVP_MD *md;
	const char *st;

	if (imaevm_params.verbose > LOG_INFO) {
		log_info("hash(%s): ", hash_algo);
		log_dump(hash, size);
	}

	pkey = find_keyid(public_keys, hdr->keyid);
	if (!pkey) {
		uint32_t keyid = hdr->keyid;

		if (imaevm_params.verbose > LOG_INFO)
			log_info("%s: verification failed: unknown keyid %x\n",
				 file, __be32_to_cpup(&keyid));
		return -1;
	}

#if defined(EVP_PKEY_SM2) && OPENSSL_VERSION_NUMBER < 0x30000000
	/* If EC key are used, check whether it is SM2 key */
	if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
		EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
		int curve = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
		if (curve == NID_sm2)
			EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
	}
#endif

	st = "EVP_PKEY_CTX_new";
	if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
		goto err;
	st = "EVP_PKEY_verify_init";
	if (!EVP_PKEY_verify_init(ctx))
		goto err;
	st = "EVP_get_digestbyname";
	md = EVP_get_digestbyname(hash_algo);
	if (!md)
		goto err;
	st = "EVP_PKEY_CTX_set_signature_md";
	if (!EVP_PKEY_CTX_set_signature_md(ctx, md))
		goto err;
	st = "EVP_PKEY_verify";
	ret = EVP_PKEY_verify(ctx, sig + sizeof(*hdr),
			      siglen - sizeof(*hdr), hash, size);
	if (ret == 1)
		ret = 0;
	else if (ret == 0) {
		log_err("%s: verification failed: %d (%s)\n",
			file, ret, ERR_reason_error_string(ERR_get_error()));
		output_openssl_errors();
		ret = 1;
	}
err:
	if (ret < 0 || ret > 1) {
		log_err("%s: verification failed: %d (%s) in %s\n",
			file, ret, ERR_reason_error_string(ERR_peek_error()),
			st);
		output_openssl_errors();
		ret = -1;
	}
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey_free);
	return ret;
}

/*
 * Verify a signature, prefixed with the signature_v2_hdr, directly based
 * on the file data hash.
 *
 * Return: 0 verification good, 1 verification bad, -1 error.
 */
static int verify_hash_v2(struct public_key_entry *public_keys,
			  const char *file, const char *hash_algo,
			  const unsigned char *hash,
			  int size, unsigned char *sig, int siglen)
{
	/* note: signature_v2_hdr does not contain 'type', use sig + 1 */
	return verify_hash_common(public_keys, file, hash_algo, hash, size,
				  sig + 1, siglen - 1);
}

/*
 * Verify a signature, prefixed with the signature_v2_hdr, indirectly based
 * on the file data hash.
 *
 * Return: 0 verification good, 1 verification bad, -1 error.
 */
static int verify_hash_v3(struct public_key_entry *public_keys,
			  const char *file, const char *hash_algo,
			  const unsigned char *hash,
			  int size, unsigned char *sig, int siglen)
{
	unsigned char sigv3_hash[MAX_DIGEST_SIZE];
	int ret;

	ret = calc_hash_sigv3(sig[0], hash_algo, hash, sigv3_hash);
	if (ret < 0)
		return ret;

	/* note: signature_v2_hdr does not contain 'type', use sig + 1 */
	return verify_hash_common(public_keys, file, hash_algo, sigv3_hash,
				  size, sig + 1, siglen - 1);
}

#define HASH_MAX_DIGESTSIZE 64	/* kernel HASH_MAX_DIGESTSIZE is 64 bytes */

struct ima_file_id {
	__u8 hash_type;		/* xattr type [enum evm_ima_xattr_type] */
	__u8 hash_algorithm;	/* Digest algorithm [enum hash_algo] */
	__u8 hash[HASH_MAX_DIGESTSIZE];
} __packed;

/*
 * Calculate the signature format version 3 hash based on the portion
 * of the ima_file_id structure used, not the entire structure.
 *
 * On success, return the hash length, otherwise for openssl errors
 * return 1, other errors return -EINVAL.
 */
int calc_hash_sigv3(enum evm_ima_xattr_type type, const char *algo,
		    const unsigned char *in_hash, unsigned char *out_hash)
{
	struct ima_file_id file_id = { .hash_type = IMA_VERITY_DIGSIG };
	uint8_t *data = (uint8_t *) &file_id;

	const EVP_MD *md;
	EVP_MD_CTX *pctx;
	unsigned int mdlen;
	int err;
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX ctx;
	pctx = &ctx;
#else
	pctx = EVP_MD_CTX_new();
#endif
	int hash_algo;
	int hash_size;
	unsigned int unused;

	if (type != IMA_VERITY_DIGSIG) {
		log_err("Only fsverity supports signature format v3 (sigv3)\n");
		return -EINVAL;
	}

	if (!algo) {
		log_err("Hash algorithm unspecified\n");
		return -EINVAL;
	}

	if ((hash_algo = imaevm_get_hash_algo(algo)) < 0) {
		log_err("Hash algorithm %s not supported\n", algo);
		return -EINVAL;
	}
	file_id.hash_algorithm = hash_algo;

	md = EVP_get_digestbyname(algo);
	if (!md) {
		log_err("EVP_get_digestbyname(%s) failed\n", algo);
		err = 1;
		goto err;
	}

	hash_size = EVP_MD_size(md);
	memcpy(file_id.hash, in_hash, hash_size);

	err = EVP_DigestInit(pctx, md);
	if (!err) {
		log_err("EVP_DigestInit() failed\n");
		err = 1;
		goto err;
	}

	unused = HASH_MAX_DIGESTSIZE - hash_size;
	if (!EVP_DigestUpdate(pctx, data, sizeof(file_id) - unused)) {
		log_err("EVP_DigestUpdate() failed\n");
		err = 1;
		goto err;
	}

	err = EVP_DigestFinal(pctx, out_hash, &mdlen);
	if (!err) {
		log_err("EVP_DigestFinal() failed\n");
		err = 1;
		goto err;
	}
	err = mdlen;
err:
	if (err == 1)
		output_openssl_errors();
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	EVP_MD_CTX_free(pctx);
#endif
	return err;
}

int imaevm_get_hash_algo(const char *algo)
{
	int i;

	/* first iterate over builtin algorithms */
	for (i = 0; i < PKEY_HASH__LAST; i++)
		if (pkey_hash_algo[i] &&
		    !strcmp(algo, pkey_hash_algo[i]))
			return i;

	for (i = 0; i < PKEY_HASH__LAST; i++)
		if (pkey_hash_algo_kern[i] &&
		    !strcmp(algo, pkey_hash_algo_kern[i]))
			return i;

	/* iterate over algorithms provided by kernel-headers */
	for (i = 0; i < HASH_ALGO__LAST; i++)
		if (hash_algo_name[i] &&
		    !strcmp(algo, hash_algo_name[i]))
			return i;

	return -1;
}

int imaevm_hash_algo_from_sig(unsigned char *sig)
{
	uint8_t hashalgo;

	if (sig[0] == DIGSIG_VERSION_1) {
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
	} else if (sig[0] == DIGSIG_VERSION_2 || sig[0] == DIGSIG_VERSION_3) {
		hashalgo = ((struct signature_v2_hdr *)sig)->hash_algo;
		if (hashalgo >= PKEY_HASH__LAST)
			return -1;
		return hashalgo;
	} else
		return -1;
}

int imaevm_verify_hash(struct public_key_entry *public_keys, const char *file,
		       const char *hash_algo, const unsigned char *hash,
		       int size, unsigned char *sig, int siglen)
{
	/* Get signature type from sig header */
	if (sig[1] == DIGSIG_VERSION_1) {
#if CONFIG_SIGV1
		const char *key = NULL;

		/* Read pubkey from RSA key */
		if (!imaevm_params.keyfile)
			key = "/etc/keys/pubkey_evm.pem";
		else
			key = imaevm_params.keyfile;
		return verify_hash_v1(file, hash, size, sig + 1, siglen - 1,
					 key);
#else
		log_info("Signature version 1 deprecated.");
		return -1;
#endif
	} else if (sig[1] == DIGSIG_VERSION_2) {
		return verify_hash_v2(public_keys, file, hash_algo, hash, size,
				      sig, siglen);
	} else if (sig[1] == DIGSIG_VERSION_3) {
		return verify_hash_v3(public_keys, file, hash_algo, hash, size,
				      sig, siglen);
	} else
		return -1;
}

int verify_hash(const char *file, const unsigned char *hash, int size,
		unsigned char *sig, int siglen)
{
	return imaevm_verify_hash(g_public_keys, file, imaevm_params.hash_algo,
				  hash, size, sig, siglen);
}

int ima_verify_signature2(struct public_key_entry *public_keys, const char *file,
			  unsigned char *sig, int siglen,
			  unsigned char *digest, int digestlen)
{
	unsigned char hash[MAX_DIGEST_SIZE];
	int hashlen, sig_hash_algo;
	const char *hash_algo;

	if (sig[0] != EVM_IMA_XATTR_DIGSIG && sig[0] != IMA_VERITY_DIGSIG) {
		log_err("%s: xattr ima has no signature\n", file);
		return -1;
	}

	if (!digest && sig[0] == IMA_VERITY_DIGSIG) {
		log_err("%s: calculating the fs-verity digest is not supported\n", file);
		return -1;
	}

	sig_hash_algo = imaevm_hash_algo_from_sig(sig + 1);
	if (sig_hash_algo < 0) {
		log_err("%s: Invalid signature\n", file);
		return -1;
	}
	/* Use hash algorithm as retrieved from signature */
	hash_algo = imaevm_hash_algo_by_id(sig_hash_algo);

	/*
	 * Validate the signature based on the digest included in the
	 * measurement list, not by calculating the local file digest.
	 */
	if (digest && digestlen > 0)
		return imaevm_verify_hash(public_keys, file,
					  hash_algo, digest, digestlen,
					  sig, siglen);

	hashlen = ima_calc_hash2(file, hash_algo, hash);
	if (hashlen <= 1)
		return hashlen;
	assert(hashlen <= sizeof(hash));

	return imaevm_verify_hash(public_keys, file, hash_algo, hash, hashlen,
				  sig, siglen);
}

int ima_verify_signature(const char *file, unsigned char *sig, int siglen,
			 unsigned char *digest, int digestlen)
{
	return ima_verify_signature2(g_public_keys, file, sig, siglen,
				     digest, digestlen);
}

#if CONFIG_SIGV1
/*
 * Create binary key representation suitable for kernel
 */
int key2bin(RSA *key, unsigned char *pub)
{
	int len, b, offset = 0;
	struct pubkey_hdr *pkh = (struct pubkey_hdr *)pub;
	const BIGNUM *n, *e;

#if OPENSSL_VERSION_NUMBER < 0x10100000
	n = key->n;
	e = key->e;
#else
	RSA_get0_key(key, &n, &e, NULL);
#endif

	/* add key header */
	pkh->version = 1;
	pkh->timestamp = 0;	/* PEM has no timestamp?? */
	pkh->algo = PUBKEY_ALGO_RSA;
	pkh->nmpi = 2;

	offset += sizeof(*pkh);

	len = BN_num_bytes(n);
	b = BN_num_bits(n);
	pub[offset++] = b >> 8;
	pub[offset++] = b & 0xff;
	BN_bn2bin(n, &pub[offset]);
	offset += len;

	len = BN_num_bytes(e);
	b = BN_num_bits(e);
	pub[offset++] = b >> 8;
	pub[offset++] = b & 0xff;
	BN_bn2bin(e, &pub[offset]);
	offset += len;

	return offset;
}

void calc_keyid_v1(uint8_t *keyid, char *str, const unsigned char *pkey, int len)
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

	if (imaevm_params.verbose > LOG_INFO)
		log_info("keyid-v1: %s\n", str);
}
#endif /* CONFIG_SIGV1 */

/*
 * Calculate keyid of the public_key part of EVP_PKEY
 */
void calc_keyid_v2(uint32_t *keyid, char *str, EVP_PKEY *pkey)
{
	X509_PUBKEY *pk = NULL;
	const unsigned char *public_key = NULL;
	int len;

	/* This is more generic than i2d_PublicKey() */
	if (X509_PUBKEY_set(&pk, pkey) &&
	    X509_PUBKEY_get0_param(NULL, &public_key, &len, NULL, pk)) {
		uint8_t sha1[SHA_DIGEST_LENGTH];

		SHA1(public_key, len, sha1);
		/* sha1[12 - 19] is exactly keyid from gpg file */
		memcpy(keyid, sha1 + 16, 4);
	} else
		*keyid = 0;

	log_debug("keyid: ");
	log_debug_dump(keyid, 4);
	sprintf(str, "%x", __be32_to_cpup(keyid));

	if (imaevm_params.verbose > LOG_INFO)
		log_info("keyid: %s\n", str);

	X509_PUBKEY_free(pk);
}

/*
 * Extract SKID from x509 in openssl portable way.
 */
static const unsigned char *x509_get_skid(X509 *x, int *len)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	ASN1_STRING *skid;

	/*
	 * This will cache extensions.
	 * OpenSSL uses this method itself.
	 */
	if (X509_check_purpose(x, -1, -1) != 1)
		return NULL;
	skid = x->skid;
#else
	const ASN1_OCTET_STRING *skid = X509_get0_subject_key_id(x);
#endif
	if (len)
		*len = ASN1_STRING_length(skid);
#if OPENSSL_VERSION_NUMBER < 0x10100000
	return ASN1_STRING_data(x->skid);
#else
	return ASN1_STRING_get0_data(skid);
#endif
}

/*
 * read_keyid_from_cert() - Read keyid from SKID from x509 certificate file
 * @keyid_be:	Output 32-bit keyid in network order (BE);
 * @certfile:	Input filename.
 * @try_der:	true:  try to read in DER from if there is no PEM,
 *		       cert is considered mandatory and error will be issued
 *		       if there is no cert;
 *		false: only try to read in PEM form, cert is considered
 *		       optional.
 * Return:	0 on success, -1 on error.
 */
static int read_keyid_from_cert(uint32_t *keyid_be, const char *certfile, int try_der)
{
	X509 *x = NULL;
	FILE *fp;
	const unsigned char *skid;
	int skid_len;

	if (!(fp = fopen(certfile, "r"))) {
		log_err("Cannot open %s: %s\n", certfile, strerror(errno));
		return -1;
	}
	if (!PEM_read_X509(fp, &x, NULL, NULL)) {
		if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE) {
			ERR_clear_error();
			if (try_der) {
				rewind(fp);
				d2i_X509_fp(fp, &x);
			} else {
				/*
				 * Cert is optional and there is just no PEM
				 * header, then issue debug message and stop
				 * trying.
				 */
				log_debug("%s: x509 certificate not found\n",
					  certfile);
				fclose(fp);
				return -1;
			}
		}
	}
	fclose(fp);
	if (!x) {
		ERR_print_errors_fp(stderr);
		log_err("read keyid: %s: Error reading x509 certificate\n",
			certfile);
		return -1;
	}

	if (!(skid = x509_get_skid(x, &skid_len))) {
		log_err("read keyid: %s: SKID not found\n", certfile);
		goto err_free;
	}
	if (skid_len < sizeof(*keyid_be)) {
		log_err("read keyid: %s: SKID too short (len %d)\n", certfile,
			skid_len);
		goto err_free;
	}
	memcpy(keyid_be, skid + skid_len - sizeof(*keyid_be), sizeof(*keyid_be));
	log_info("keyid %04x (from %s)\n", ntohl(*keyid_be), certfile);
	X509_free(x);
	return 0;

err_free:
	X509_free(x);
	return -1;
}

/*
 * imaevm_read_keyid() - Read 32-bit keyid from the cert file
 * @certfile:	File with certificate in PEM or DER form.
 *
 * Try to read keyid from Subject Key Identifier (SKID) of x509 certificate.
 * Autodetect if cert is in PEM (tried first) or DER encoding.
 *
 * Return: 0 on error or 32-bit keyid in host order otherwise.
 */
uint32_t imaevm_read_keyid(const char *certfile)
{
	uint32_t keyid_be = 0;

	read_keyid_from_cert(&keyid_be, certfile, true);
	/* On error keyid_be will not be set, returning 0. */
	return ntohl(keyid_be);
}

static EVP_PKEY *read_priv_pkey_engine(ENGINE *e, const char *keyfile,
				       const char *keypass, uint32_t keyid)
{
#ifdef CONFIG_IMA_EVM_ENGINE
	EVP_PKEY *pkey;

	if (!keyid) {
		log_err("When using a pkcs11 URI you must provide the keyid with an option\n");
		return NULL;
	}

	if (keypass) {
		if (!ENGINE_ctrl_cmd_string(e, "PIN", keypass, 0)) {
			log_err("Failed to set the PIN for the private key\n");
			goto err_engine;
		}
	}
	pkey = ENGINE_load_private_key(e, keyfile, NULL, NULL);
	if (!pkey) {
		log_err("Failed to load private key %s\n", keyfile);
		goto err_engine;
	}
	return pkey;

err_engine:
	output_openssl_errors();
	return NULL;
#else
	log_err("OpenSSL \"engine\" support is disabled\n");
	return NULL;
#endif
}

#ifdef CONFIG_IMA_EVM_PROVIDER
static int ui_get_pin(UI *ui, UI_STRING *uis)
{
	return UI_set_result(ui, uis, UI_get0_user_data(ui));
}

static EVP_PKEY *read_priv_pkey_provider(OSSL_PROVIDER *p, const char *keyfile,
					 const char *keypass, uint32_t keyid)
{
	UI_METHOD *ui_method = NULL;
	OSSL_STORE_INFO *info;
	OSSL_STORE_CTX *store;
	EVP_PKEY *pkey = NULL;
	int typ;

	if (!keyid) {
		log_err("When using a pkcs11 URI you must provide the keyid with an option\n");
		return NULL;
	}

	if (keypass) {
		ui_method = UI_create_method("PIN reader");
		if (!ui_method)
			return NULL;
		UI_method_set_reader(ui_method, ui_get_pin);
	}
	store = OSSL_STORE_open_ex(keyfile, NULL, "provider=pkcs11", ui_method,
				   (void *)keypass, NULL, NULL, NULL);
	if (!store) {
		log_err("Failed to open store for provider=pkcs11\n");
		goto err_provider;
	}
	for (info = OSSL_STORE_load(store);
	     info != NULL && pkey == NULL;
	     info = OSSL_STORE_load(store)) {
		typ = OSSL_STORE_INFO_get_type(info);

		switch (typ) {
		case OSSL_STORE_INFO_PKEY:
			pkey = OSSL_STORE_INFO_get1_PKEY(info);
			break;
		}
		OSSL_STORE_INFO_free(info);
	}
	OSSL_STORE_close(store);

	if (!pkey) {
		log_err("Failed to load private key %s\n", keyfile);
		goto err_provider;
	}
	return pkey;

err_provider:
	output_openssl_errors();
	return NULL;
}
#endif

static EVP_PKEY *read_priv_pkey(const char *keyfile, const char *keypass,
				const struct imaevm_ossl_access *access_info,
				uint32_t keyid)
{
	FILE *fp;
	EVP_PKEY *pkey = NULL;

	if (!strncmp(keyfile, "pkcs11:", 7)) {
		if (!access_info) {
			log_err("PKCS11 engine or provider not specified");
			return NULL;
		}

		switch (access_info->type) {
		case IMAEVM_OSSL_ACCESS_TYPE_ENGINE:
			pkey = read_priv_pkey_engine(access_info->u.engine,
						     keyfile, keypass, keyid);
			break;
#ifdef CONFIG_IMA_EVM_PROVIDER
		case IMAEVM_OSSL_ACCESS_TYPE_PROVIDER:
			pkey = read_priv_pkey_provider(access_info->u.provider,
						       keyfile, keypass, keyid);
			break;
#endif
		}
	} else {
		fp = fopen(keyfile, "r");
		if (!fp) {
			log_err("Failed to open keyfile: %s\n", keyfile);
			return NULL;
		}
		pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void *)keypass);
		if (!pkey) {
			log_err("Failed to PEM_read_PrivateKey key file: %s\n",
				keyfile);
			output_openssl_errors();
		}

		fclose(fp);
	}

	return pkey;

}

#if CONFIG_SIGV1
static RSA *read_priv_key(const char *keyfile, const char *keypass,
			  const struct imaevm_ossl_access *access_info,
			  uint32_t keyid)
{
	EVP_PKEY *pkey;
	RSA *key;

	pkey = read_priv_pkey(keyfile, keypass, access_info, keyid);
	if (!pkey)
		return NULL;
	key = EVP_PKEY_get1_RSA(pkey);
	EVP_PKEY_free(pkey);
	if (!key) {
		log_err("read_priv_key: unsupported key type\n");
		output_openssl_errors();
		return NULL;
	}
	return key;
}

static int get_hash_algo_v1(const char *algo)
{

	if (!strcmp(algo, "sha1"))
		return DIGEST_ALGO_SHA1;
	else if (!strcmp(algo, "sha256"))
		return DIGEST_ALGO_SHA256;

	return -1;
}

static int sign_hash_v1(const char *hashalgo, const unsigned char *hash,
			int size, const char *keyfile, const char *keypass,
			unsigned char *sig,
			const struct imaevm_ossl_access *access_info,
			uint32_t keyid)
{
	int len = -1, hashalgo_idx;
	SHA_CTX ctx;
	unsigned char pub[1024];
	RSA *key;
	char name[20];
	unsigned char sighash[20];
	struct signature_hdr *hdr;
	uint16_t *blen;

	if (!hash) {
		log_err("sign_hash_v1: hash is null\n");
		return -1;
	}

	if (size < 0) {
		log_err("sign_hash_v1: size is negative: %d\n", size);
		return -1;
	}

	if (!hashalgo) {
		log_err("sign_hash_v1: hashalgo is null\n");
		return -1;
	}

	if (!sig) {
		log_err("sign_hash_v1: sig is null\n");
		return -1;
	}

	log_info("hash(%s): ", hashalgo);
	log_dump(hash, size);

	key = read_priv_key(keyfile, keypass, access_info, keyid);
	if (!key)
		return -1;

	hdr = (struct signature_hdr *)sig;

	/* now create a new hash */
	hdr->version = (uint8_t) DIGSIG_VERSION_1;
	hdr->timestamp = time(NULL);
	hdr->algo = PUBKEY_ALGO_RSA;
	hashalgo_idx = get_hash_algo_v1(hashalgo);
	if (hashalgo_idx < 0) {
		log_err("Signature version 1 does not support hash algo %s\n",
			hashalgo);
		goto out;
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

	len = RSA_private_encrypt(sizeof(sighash), sighash, sig + sizeof(*hdr) + 2, key, RSA_PKCS1_PADDING);
	if (len < 0) {
		log_err("RSA_private_encrypt() failed: %d\n", len);
		output_openssl_errors();
		goto out;
	}

	/* we add bit length of the signature to make it gnupg compatible */
	blen = (uint16_t *) (sig + sizeof(*hdr));
	*blen = __cpu_to_be16(len << 3);
	len += sizeof(*hdr) + 2;
	log_info("evm/ima signature-v1: %d bytes\n", len);
out:
	RSA_free(key);
	return len;
}
#endif /* CONFIG_SIGV1 */

/*
 * @sig is assumed to be of (MAX_SIGNATURE_SIZE - 1) size
 * Return: -1 signing error, >0 length of signature
 */
static int sign_hash_v2(const char *algo, const unsigned char *hash,
			int size, const char *keyfile, const char *keypass,
			unsigned char *sig,
			const struct imaevm_ossl_access *access_info,
			uint32_t keyid)
{
	struct signature_v2_hdr *hdr;
	int len = -1;
	EVP_PKEY *pkey;
	char name[20];
	EVP_PKEY_CTX *ctx = NULL;
	const EVP_MD *md;
	size_t sigsize;
	const char *st;

	if (!hash) {
		log_err("sign_hash_v2: hash is null\n");
		return -1;
	}

	if (size < 0) {
		log_err("sign_hash_v2: size is negative: %d\n", size);
		return -1;
	}

	if (!sig) {
		log_err("sign_hash_v2: sig is null\n");
		return -1;
	}

	if (!algo) {
		log_err("sign_hash_v2: algo is null\n");
		return -1;
	}

	log_info("hash(%s): ", algo);
	log_dump(hash, size);

	pkey = read_priv_pkey(keyfile, keypass, access_info, keyid);
	if (!pkey)
		return -1;

	hdr = (struct signature_v2_hdr *)sig;
	hdr->version = (uint8_t) DIGSIG_VERSION_2;

	hdr->hash_algo = imaevm_get_hash_algo(algo);
	if (hdr->hash_algo == (uint8_t)-1) {
		log_err("sign_hash_v2: hash algo is unknown: %s\n", algo);
		return -1;
	}

#if defined(EVP_PKEY_SM2) && OPENSSL_VERSION_NUMBER < 0x30000000
	/* If EC key are used, check whether it is SM2 key */
	if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
		EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
		int curve = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
		if (curve == NID_sm2)
			EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
	}
#endif

	if (keyid)
		keyid = htonl(keyid);
	else {
		int keyid_read_failed = read_keyid_from_cert(&keyid, keyfile, false);

		if (keyid_read_failed)
			calc_keyid_v2(&keyid, name, pkey);
	}
	hdr->keyid = keyid;

	st = "EVP_PKEY_CTX_new";
	if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
		goto err;
	st = "EVP_PKEY_sign_init";
	if (!EVP_PKEY_sign_init(ctx))
		goto err;
	st = "EVP_get_digestbyname";
	if (!(md = EVP_get_digestbyname(algo)))
		goto err;
	st = "EVP_PKEY_CTX_set_signature_md";
	if (!EVP_PKEY_CTX_set_signature_md(ctx, md))
		goto err;
	st = "EVP_PKEY_sign";
	sigsize = MAX_SIGNATURE_SIZE - sizeof(struct signature_v2_hdr) - 1;
	if (!EVP_PKEY_sign(ctx, hdr->sig, &sigsize, hash, size))
		goto err;
	len = (int)sigsize;

	/* we add bit length of the signature to make it gnupg compatible */
	hdr->sig_size = __cpu_to_be16(len);
	len += sizeof(*hdr);
	log_info("evm/ima signature: %d bytes\n", len);

err:
	if (len == -1) {
		log_err("sign_hash_v2: signing failed: (%s) in %s\n",
			ERR_reason_error_string(ERR_peek_error()), st);
		output_openssl_errors();
	}
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return len;
}

static int check_ossl_access(const struct imaevm_ossl_access *access_info)
{
	switch (access_info->type) {
	case IMAEVM_OSSL_ACCESS_TYPE_NONE:
#ifdef CONFIG_IMA_EVM_ENGINE
	case IMAEVM_OSSL_ACCESS_TYPE_ENGINE:
#endif
#ifdef CONFIG_IMA_EVM_PROVIDER
	case IMAEVM_OSSL_ACCESS_TYPE_PROVIDER:
#endif
		return 0;

	default:
		errno = EINVAL;
		return -1;
	}
}

int imaevm_signhash(const char *hashalgo, const unsigned char *hash, int size,
		    const char *keyfile, const char *keypass,
		    unsigned char *sig, long sigflags,
		    const struct imaevm_ossl_access *access_info,
		    uint32_t keyid)
{
	int rc;

	if (access_info) {
		rc = check_ossl_access(access_info);
		if (rc)
			return rc;
	}
	if (sigflags & ~IMAEVM_SIGFLAGS_SUPPORT) {
		/* unsupported flag */
		errno = EINVAL;
		return -1;
	}

	if (sigflags & IMAEVM_SIGFLAG_SIGNATURE_V1) {
#if CONFIG_SIGV1
		return sign_hash_v1(hashalgo, hash, size, keyfile, keypass, sig,
				    access_info, keyid);
#else
		log_info("Signature version 1 deprecated.");
		return -1;
#endif
	}

	return sign_hash_v2(hashalgo, hash, size, keyfile, keypass, sig,
			    access_info, keyid);
}


int sign_hash(const char *hashalgo, const unsigned char *hash, int size,
	      const char *keyfile, const char *keypass, unsigned char *sig)
{
	const struct imaevm_ossl_access access_info = {
		.type = IMAEVM_OSSL_ACCESS_TYPE_ENGINE,
		.u.engine = imaevm_params.eng,
	};
	int sigflags = imaevm_params.x509 ? 0 : IMAEVM_SIGFLAG_SIGNATURE_V1;
	if (!keypass)	/* Avoid breaking existing libimaevm usage */
		keypass = imaevm_params.keypass;

	return imaevm_signhash(hashalgo, hash, size, keyfile, keypass, sig,
			       sigflags, &access_info, imaevm_params.keyid);
}

static void libinit()
{

#if OPENSSL_VERSION_NUMBER < 0x10100000
	OpenSSL_add_all_algorithms();
	OPENSSL_add_all_algorithms_conf();
#else

	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
			    OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
	ERR_load_crypto_strings();
#endif
}
