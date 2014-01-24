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
 * File: libevm.c
 *	 IMA/EVM library
 */

/* should we use logger instead for library? */
#define USE_FPRINTF

#include "libevm.h"

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

const struct RSA_ASN1_template RSA_ASN1_templates[PKEY_HASH__LAST] = {
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

struct libevm_params params = {
	.verbose = LOG_INFO - 1,
	.hash_algo = "sha1",
};

void do_dump(FILE *fp, const void *ptr, int len, bool cr)
{
	int i;
	uint8_t *data = (uint8_t *) ptr;

	for (i = 0; i < len; i++)
		fprintf(fp, "%02x", data[i]);
	if (cr)
		fprintf(fp, "\n");
}

void dump(const void *ptr, int len)
{
	do_dump(stdout, ptr, len, true);
}

int get_filesize(const char *filename)
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

int ima_calc_hash(const char *file, uint8_t *hash)
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

	md = EVP_get_digestbyname(params.hash_algo);
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

RSA *read_pub_key(const char *keyfile, int x509)
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

int verify_hash_v1(const unsigned char *hash, int size, unsigned char *sig, int siglen, const char *keyfile)
{
	int err, len;
	SHA_CTX ctx;
	unsigned char out[1024];
	RSA *key;
	unsigned char sighash[20];
	struct signature_hdr *hdr = (struct signature_hdr *)sig;

	log_info("hash: ");
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

int verify_hash_v2(const unsigned char *hash, int size, unsigned char *sig, int siglen, const char *keyfile)
{
	int err, len;
	unsigned char out[1024];
	RSA *key;
	struct signature_v2_hdr *hdr = (struct signature_v2_hdr *)sig;
	const struct RSA_ASN1_template *asn1;

	log_info("hash: ");
	log_dump(hash, size);

	key = read_pub_key(keyfile, 1);
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

int get_hash_algo(const char *algo)
{
	int i;

	for (i = 0; i < PKEY_HASH__LAST; i++)
		if (!strcmp(algo, pkey_hash_algo[i]))
			return i;

	return PKEY_HASH_SHA1;
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

int verify_hash(const unsigned char *hash, int size, unsigned char *sig, int siglen)
{
	char *key;
	int x509;

	/* Get signature type from sig header */
	if (sig[0] == DIGSIG_VERSION_1) {
		params.verify_hash = verify_hash_v1;
		/* Read pubkey from RSA key */
		x509 = 0;
	} else if (sig[0] == DIGSIG_VERSION_2) {
		params.verify_hash = verify_hash_v2;
		/* Read pubkey from x509 cert */
		x509 = 1;
	} else
		return -1;

	/* Determine what key to use for verification*/
	key = params.keyfile ? : x509 ?
			"/etc/keys/x509_evm.der" :
			"/etc/keys/pubkey_evm.pem";

	return params.verify_hash(hash, size, sig, siglen, key);
}

int ima_verify_signature(const char *file, unsigned char *sig, int siglen)
{
	unsigned char hash[64];
	int hashlen, sig_hash_algo;

	if (sig[0] != 0x03) {
		log_err("security.ima has no signature\n");
		return -1;
	}

	sig_hash_algo = get_hash_algo_from_sig(sig + 1);
	if (sig_hash_algo < 0) {
		log_err("Invalid signature\n");
		return -1;
	}
	/* Use hash algorithm as retrieved from signature */
	params.hash_algo = pkey_hash_algo[sig_hash_algo];

	hashlen = ima_calc_hash(file, hash);
	if (hashlen <= 1)
		return hashlen;

	return verify_hash(hash, hashlen, sig + 1, siglen - 1);
}
