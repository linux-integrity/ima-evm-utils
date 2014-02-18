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
 * File: evmctl.c
 *	 IMA/EVM control program
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <attr/xattr.h>
#include <getopt.h>
#include <keyutils.h>
#include <asm/byteorder.h>
#include <ctype.h>

#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#define USE_FPRINTF

#include "imaevm.h"

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

static int g_argc;
static char **g_argv;
static int xattr = 1;
static int sigdump;
static int digest;
static int digsig;
static char *keypass;
static int sigfile;
static int x509 = 1;
static char *uuid_str = "+";
static char *search_type;
static int recursive;
static int msize;
static dev_t fs_dev;

typedef int (*find_cb_t)(const char *path);
static int find(const char *path, int dts, find_cb_t func);

#define REG_MASK	(1 << DT_REG)
#define DIR_MASK	(1 << DT_DIR)
#define LNK_MASK	(1 << DT_LNK)
#define CHR_MASK	(1 << DT_CHR)
#define BLK_MASK	(1 << DT_BLK)

typedef int (*sign_hash_fn_t)(const char *algo, const unsigned char *hash, int size, const char *keyfile, unsigned char *sig);

static sign_hash_fn_t sign_hash;

struct command cmds[];
static void print_usage(struct command *cmd);

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

static int get_hash_algo_v1(const char *algo)
{

	if (!strcmp(algo, "sha1"))
		return DIGEST_ALGO_SHA1;
	else if (!strcmp(algo, "sha256"))
		return DIGEST_ALGO_SHA256;

	return -1;
}

static int sign_hash_v1(const char *hashalgo, const unsigned char *hash, int size, const char *keyfile, unsigned char *sig)
{
	int len = -1, hashalgo_idx;
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
		goto out;
	}

	/* we add bit length of the signature to make it gnupg compatible */
	blen = (uint16_t *) (sig + sizeof(*hdr));
	*blen = __cpu_to_be16(len << 3);
	len += sizeof(*hdr) + 2;
	log_info("evm/ima signature: %d bytes\n", len);
	if (sigdump || params.verbose >= LOG_INFO)
		dump(sig, len);
out:
	RSA_free(key);
	return len;
}

static int sign_hash_v2(const char *algo, const unsigned char *hash, int size, const char *keyfile, unsigned char *sig)
{
	struct signature_v2_hdr *hdr = (struct signature_v2_hdr *)sig;
	int len = -1;
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
		goto out;

	memcpy(buf, asn1->data, asn1->size);
	memcpy(buf + asn1->size, hash, size);
	len = RSA_private_encrypt(size + asn1->size, buf, hdr->sig,
				  key, RSA_PKCS1_PADDING);
	if (len < 0) {
		log_err("RSA_private_encrypt() failed: %d\n", len);
		goto out;
	}

	/* we add bit length of the signature to make it gnupg compatible */
	hdr->sig_size = __cpu_to_be16(len);
	len += sizeof(*hdr);
	log_info("evm/ima signature: %d bytes\n", len);
	if (sigdump || params.verbose >= LOG_INFO)
		dump(sig, len);
out:
	if (buf)
		free(buf);
	RSA_free(key);
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

static int hex2bin(uint8_t *dst, const char *src, size_t count)
{
	int hi, lo;

	while (count--) {
		if (*src == ' ')
			src++;

		hi = hex_to_bin(*src++);
		lo = hex_to_bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -1;

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}

#define hex_asc_lo(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)   hex_asc[((x) & 0xf0) >> 4]

const char hex_asc[] = "0123456789abcdef";

/* this is faster than fprintf - makes sense? */
static void bin2hex(uint8_t *buf, size_t buflen, FILE *stream)
{
	char asciihex[2];

	for (; buflen--; buf++) {
		asciihex[0] = hex_asc_hi(*buf);
		asciihex[1] = hex_asc_lo(*buf);
		fwrite(asciihex, 2, 1, stream);
	}
}

static int pack_uuid(const char *uuid_str, char *uuid)
{
	int i;
	char *to = uuid;

	for (i = 0; i < 16; ++i) {
		if (!uuid_str[0] || !uuid_str[1]) {
			log_err("wrong UUID format\n");
			return -1;
		}
		*to++ = (hex_to_bin(*uuid_str) << 4) |
			(hex_to_bin(*(uuid_str + 1)));
		uuid_str += 2;
		switch (i) {
		case 3:
		case 5:
		case 7:
		case 9:
			if (*uuid_str != '-') {
				log_err("wrong UUID format\n");
				return -1;
			}
			uuid_str++;
			continue;
		}
	}
	log_info("uuid: ");
	log_dump(uuid, 16);
	return 0;
}

static int get_uuid(struct stat *st, char *uuid)
{
	uint32_t dev;
	unsigned minor, major;
	char path[PATH_MAX], _uuid[37];
	FILE *fp;
	size_t len;

	if (uuid_str[0] != '+')
		return pack_uuid(uuid_str, uuid);

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

	return pack_uuid(_uuid, uuid);
}

static int calc_evm_hash(const char *file, unsigned char *hash)
{
	struct stat st;
	int err;
	uint32_t generation = 0;
	EVP_MD_CTX ctx;
	unsigned int mdlen;
	char **xattrname;
	char xattr_value[1024];
	char list[1024];
	ssize_t list_size;
	char uuid[16];
	struct h_misc_64 hmac_misc;
	int hmac_size;

	if (lstat(file, &st)) {
		log_err("lstat() failed\n");
		return -1;
	}

	if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) {
		/* we cannot at the momement to get generation of special files..
		 * kernel API does not support it */
		int fd = open(file, 0);
		if (fd < 0) {
			log_err("Unable to open %s\n", file);
			return -1;
		}
		if (ioctl(fd, EXT34_IOC_GETVERSION, &generation)) {
			log_err("ioctl() failed\n");
			return -1;
		}
		close(fd);
	}

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
		err = lgetxattr(file, *xattrname, xattr_value, sizeof(xattr_value));
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

	if (msize == 0) {
		struct h_misc *hmac = (struct h_misc *)&hmac_misc;
		hmac_size = sizeof(*hmac);
		hmac->ino = st.st_ino;
		hmac->generation = generation;
		hmac->uid = st.st_uid;
		hmac->gid = st.st_gid;
		hmac->mode = st.st_mode;
	} else if (msize == 64) {
		struct h_misc_64 *hmac = (struct h_misc_64 *)&hmac_misc;
		hmac_size = sizeof(*hmac);
		hmac->ino = st.st_ino;
		hmac->generation = generation;
		hmac->uid = st.st_uid;
		hmac->gid = st.st_gid;
		hmac->mode = st.st_mode;
	} else {
		struct h_misc_32 *hmac = (struct h_misc_32 *)&hmac_misc;
		hmac_size = sizeof(*hmac);
		hmac->ino = st.st_ino;
		hmac->generation = generation;
		hmac->uid = st.st_uid;
		hmac->gid = st.st_gid;
		hmac->mode = st.st_mode;
	}

	log_debug("hmac_misc (%d): ", hmac_size);
	log_debug_dump(&hmac_misc, hmac_size);

	err = EVP_DigestUpdate(&ctx, &hmac_misc, hmac_size);
	if (!err) {
		log_err("EVP_DigestUpdate() failed\n");
		return 1;
	}

	if (*uuid_str != '-') {
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
		err = lsetxattr(file, "security.evm", sig, len + 1, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int hash_ima(const char *file)
{
	unsigned char hash[65] = "\x01"; /* MAX hash size + 1 */
	int len, err;

	len = ima_calc_hash(file, hash + 1);
	if (len <= 1)
		return len;

	if (params.verbose >= LOG_INFO)
		log_info("hash: ");

	if (sigdump || params.verbose >= LOG_INFO)
		dump(hash, len + 1);

	if (xattr) {
		err = lsetxattr(file, "security.ima", hash, len + 1, 0);
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
	int len, err;

	len = ima_calc_hash(file, hash);
	if (len <= 1)
		return len;

	len = sign_hash(params.hash_algo, hash, len, key, sig + 1);
	if (len <= 1)
		return len;

	/* add header */
	len++;

	if (sigfile)
		bin2file(file, "sig", sig, len);

	if (xattr) {
		err = lsetxattr(file, "security.ima", sig, len, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int get_file_type(const char *path, const char *search_type)
{
	int err, dts = 0, i;
	struct stat st;

	for (i = 0; search_type[i]; i++) {
		switch (search_type[i]) {
		case 'f':
			dts |= REG_MASK; break;
		case 'd':
			dts |= DIR_MASK; break;
		case 's':
			dts |= BLK_MASK | CHR_MASK | LNK_MASK; break;
		case 'm':
			/* stay within the same filesystem*/
			err = lstat(path, &st);
			if (err < 0) {
				log_err("stat() failed\n");
				return err;
			}
			fs_dev = st.st_dev; /* filesystem to start from */
			break;
		}
	}

	return dts;
}

static int sign_ima_file(const char *file)
{
	char *key;

	key = params.keyfile ? : "/etc/keys/privkey_evm.pem";

	return sign_ima(file, key);
}

static int cmd_sign_ima(struct command *cmd)
{
	char *file = g_argv[optind++];
	int err, dts = REG_MASK; /* only regular files by default */

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	if (recursive) {
		if (search_type) {
			dts = get_file_type(file, search_type);
			if (dts < 0)
				return dts;
		}
		err = find(file, dts, sign_ima_file);
	} else {
		err = sign_ima_file(file);
	}

	return err;
}

static int cmd_sign_hash(struct command *cmd)
{
	char *key, *token, *line = NULL;
	int hashlen = 0;
	size_t line_len;
	ssize_t len;
	unsigned char hash[64];
	unsigned char sig[1024] = "\x03";
	int siglen;

	key = params.keyfile ? : "/etc/keys/privkey_evm.pem";

	/* support reading hash (eg. output of shasum) */
	while ((len = getline(&line, &line_len, stdin)) > 0) {
		/* remove end of line */
		if (line[len - 1] == '\n')
			line[--len] = '\0';

		/* find the end of the hash */
		token = strpbrk(line, ", \t");
		hashlen = token ? token - line : strlen(line);

		hex2bin(hash, line, hashlen);
		siglen = sign_hash(params.hash_algo, hash, hashlen/2,
				 key, sig + 1);
		if (siglen <= 1)
			return siglen;

		fwrite(line, len, 1, stdout);
		fprintf(stdout, " ");
		bin2hex(sig, siglen + 1, stdout);
		fprintf(stdout, "\n");
	}

	if (!hashlen) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	return 0;
}

static int sign_evm_path(const char *file)
{
	char *key;
	int err;

	key = params.keyfile ? : "/etc/keys/privkey_evm.pem";

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

static int cmd_sign_evm(struct command *cmd)
{
	char *path = g_argv[optind++];
	int err, dts = REG_MASK; /* only regular files by default */

	if (!path) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	if (recursive) {
		if (search_type) {
			dts = get_file_type(path, search_type);
			if (dts < 0)
				return dts;
		}
		err = find(path, dts, sign_evm_path);
	} else {
		err = sign_evm_path(path);
	}

	return err;
}

static int verify_evm(const char *file)
{
	unsigned char hash[20];
	unsigned char sig[1024];
	int len;

	len = calc_evm_hash(file, hash);
	if (len <= 1)
		return len;

	len = lgetxattr(file, "security.evm", sig, sizeof(sig));
	if (len < 0) {
		log_err("getxattr failed\n");
		return len;
	}

	if (sig[0] != 0x03) {
		log_err("security.evm has not signature\n");
		return -1;
	}

	return verify_hash(hash, sizeof(hash), sig + 1, len - 1);
}

static int cmd_verify_evm(struct command *cmd)
{
	char *file = g_argv[optind++];

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	return verify_evm(file);
}

static int verify_ima(const char *file)
{
	unsigned char sig[1024];
	int len;

	if (xattr) {
		len = lgetxattr(file, "security.ima", sig, sizeof(sig));
		if (len < 0) {
			log_err("getxattr failed\n");
			return len;
		}
	}

	if (sigfile) {
		void *tmp;
		tmp = file2bin(file, "sig", &len);
		memcpy(sig, tmp, len);
		free(tmp);
	}

	return ima_verify_signature(file, sig, len);
}

static int cmd_verify_ima(struct command *cmd)
{
	char *file = g_argv[optind++];

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	return verify_ima(file);
}

static int cmd_import(struct command *cmd)
{
	char *inkey, *ring = NULL;
	unsigned char _pub[1024], *pub = _pub;
	int id, len, err = 0;
	char name[20];
	uint8_t keyid[8];
	RSA *key;

	inkey = g_argv[optind++];
	if (!inkey) {
		inkey = x509 ? "/etc/keys/x509_evm.der" :
			       "/etc/keys/pubkey_evm.pem";
	} else
		ring = g_argv[optind++];

	id = KEY_SPEC_USER_KEYRING; /* default keyring */

	if (ring) {
		if (ring[0] != '@') {
			id = atoi(ring);
		} else {
			if (strcmp(ring, "@t") == 0)
				id = -1;
			else if (strcmp(ring, "@p") == 0)
				id = -2;
			else if (strcmp(ring, "@s") == 0)
				id = -3;
			else if (strcmp(ring, "@u") == 0)
				id = -4;
			else if (strcmp(ring, "@us") == 0)
				id = -5;
			else if (strcmp(ring, "@g") == 0)
				id = -6;
		}
	}

	key = read_pub_key(inkey, x509);
	if (!key)
		return 1;

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
		err = id;
	} else {
		log_info("keyid: %d\n", id);
		printf("%d\n", id);
	}
	if (x509)
		free(pub);
out:
	RSA_free(key);
	return err;
}

#define MAX_KEY_SIZE 128

static int calc_evm_hmac(const char *file, const char *keyfile, unsigned char *hash)
{
	struct stat st;
	int err = -1;
	uint32_t generation = 0;
	HMAC_CTX ctx;
	unsigned int mdlen;
	char **xattrname;
	unsigned char xattr_value[1024];
	unsigned char *key;
	int keylen;
	unsigned char evmkey[MAX_KEY_SIZE];
	char list[1024];
	ssize_t list_size;
	struct h_misc_64 hmac_misc;
	int hmac_size;

	key = file2bin(keyfile, NULL, &keylen);
	if (!key) {
		log_err("Unable to read a key: %s\n\n", keyfile);
		return -1;
	}

	if (keylen > sizeof(evmkey)) {
		log_err("key is too long\n");
		goto out;
	}

	/* EVM key is 128 bytes */
	memcpy(evmkey, key, keylen);
	memset(evmkey + keylen, 0, sizeof(evmkey) - keylen);

	if (lstat(file, &st)) {
		log_err("lstat() failed\n");
		goto out;
	}

	if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) {
		/* we cannot at the momement to get generation of special files..
		 * kernel API does not support it */
		int fd = open(file, 0);
		if (fd < 0) {
			log_err("Unable to open %s\n", file);
			goto out;
		}
		if (ioctl(fd, EXT34_IOC_GETVERSION, &generation)) {
			log_err("ioctl() failed\n");
			goto out;
		}
		close(fd);
	}

	log_info("generation: %u\n", generation);

	list_size = llistxattr(file, list, sizeof(list));
	if (list_size <= 0) {
		log_err("llistxattr() failed\n");
		goto out;
	}

	err = !HMAC_Init(&ctx, evmkey, sizeof(evmkey), EVP_sha1());
	if (err) {
		log_err("HMAC_Init() failed\n");
		goto out;
	}

	for (xattrname = evm_config_xattrnames; *xattrname != NULL; xattrname++) {
		err = lgetxattr(file, *xattrname, xattr_value, sizeof(xattr_value));
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
		err = !HMAC_Update(&ctx, xattr_value, err);
		if (err) {
			log_err("HMAC_Update() failed\n");
			goto out_ctx_cleanup;
		}
	}

	memset(&hmac_misc, 0, sizeof(hmac_misc));

	if (msize == 0) {
		struct h_misc *hmac = (struct h_misc *)&hmac_misc;
		hmac_size = sizeof(*hmac);
		hmac->ino = st.st_ino;
		hmac->generation = generation;
		hmac->uid = st.st_uid;
		hmac->gid = st.st_gid;
		hmac->mode = st.st_mode;
	} else if (msize == 64) {
		struct h_misc_64 *hmac = (struct h_misc_64 *)&hmac_misc;
		hmac_size = sizeof(*hmac);
		hmac->ino = st.st_ino;
		hmac->generation = generation;
		hmac->uid = st.st_uid;
		hmac->gid = st.st_gid;
		hmac->mode = st.st_mode;
	} else {
		struct h_misc_32 *hmac = (struct h_misc_32 *)&hmac_misc;
		hmac_size = sizeof(*hmac);
		hmac->ino = st.st_ino;
		hmac->generation = generation;
		hmac->uid = st.st_uid;
		hmac->gid = st.st_gid;
		hmac->mode = st.st_mode;
	}

	log_debug("hmac_misc (%d): ", hmac_size);
	log_debug_dump(&hmac_misc, hmac_size);

	err = !HMAC_Update(&ctx, (const unsigned char *)&hmac_misc, hmac_size);
	if (err) {
		log_err("HMAC_Update() failed\n");
		goto out_ctx_cleanup;
	}
	err = !HMAC_Final(&ctx, hash, &mdlen);
	if (err)
		log_err("HMAC_Final() failed\n");
out_ctx_cleanup:
	HMAC_CTX_cleanup(&ctx);
out:
	free(key);
	return err ?: mdlen;
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
		err = lsetxattr(file, "security.evm", sig, len + 1, 0);
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

	key = params.keyfile ? : "/etc/keys/privkey_evm.pem";

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

static int ima_fix(const char *path)
{
	int fd, size, len, ima = 0, evm = 0;
	char buf[1024], *list = buf;

	log_info("%s\n", path);

	if (xattr) {
		/* re-measuring takes a time
		 * in some cases we can skip labeling if xattrs exists
		 */
		size = llistxattr(path, list, sizeof(buf));
		if (size < 0) {
			log_errno("llistxattr() failed: %s\n", path);
			return -1;
		}
		for (; size > 0; len++, size -= len, list += len) {
			len = strlen(list);
			if (!strcmp(list, "security.ima"))
				ima = 1;
			else if (!strcmp(list, "security.evm"))
				evm = 1;
		}
		if (ima && evm)
			return 0;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_errno("%s open failed", path);
		return -1;
	}

	close(fd);

	return 0;
}

static int find(const char *path, int dts, find_cb_t func)
{
	struct dirent *de;
	DIR *dir;

	if (fs_dev) {
		struct stat st;
		int err = lstat(path, &st);
		if (err < 0) {
			log_err("stat() failed\n");
			return err;
		}
		if (st.st_dev != fs_dev)
			return 0;
	}

	dir = opendir(path);
	if (!dir) {
		log_err("Unable to open %s\n", path);
		return -1;
	}

	if (fchdir(dirfd(dir))) {
		log_err("Unable to chdir %s\n", path);
		return -1;
	}

	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, "..") || !strcmp(de->d_name, "."))
			continue;
		log_debug("path: %s, type: %u\n", de->d_name, de->d_type);
		if (de->d_type == DT_DIR)
			find(de->d_name, dts, func);
		else if (dts & (1 << de->d_type))
			func(de->d_name);
	}

	if (chdir("..")) {
		log_err("Unable to chdir %s\n", path);
		return -1;
	}

	if (dts & DIR_MASK)
		func(path);

	closedir(dir);

	return 0;
}

static int cmd_ima_fix(struct command *cmd)
{
	char *path = g_argv[optind++];
	int err, dts = REG_MASK; /* only regular files by default */
	struct stat st;

	if (!path) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	xattr = 0; /* do not check xattrs, fix everything */

	if (search_type) {
		int i;

		dts = 0;
		for (i = 0; search_type[i]; i++) {
			switch (search_type[i]) {
			case 'f':
				dts |= REG_MASK; break;
			case 'd':
				dts |= DIR_MASK; break;
			case 's':
				dts |= BLK_MASK | CHR_MASK | LNK_MASK; break;
			case 'x':
				/* check xattrs */
				xattr = 1; break;
			case 'm':
				/* stay within the same filesystem*/
				err = lstat(path, &st);
				if (err < 0) {
					log_err("stat() failed\n");
					return err;
				}
				fs_dev = st.st_dev; /* filesystem to start from */
				break;
			}
		}
	}

	err = find(path, dts, ima_fix);
	if (err)
		return err;

	return 0;
}


static char *pcrs = "/sys/class/misc/tpm0/device/pcrs";

static int tpm_pcr_read(int idx, uint8_t *pcr, int len)
{
	FILE *fp;
	char *p, pcr_str[7], buf[70]; /* length of the TPM string */

	sprintf(pcr_str, "PCR-%d", idx);

	fp = fopen(pcrs, "r");
	if (!fp) {
		log_err("Unable to open %s\n", pcrs);
		return -1;
	}

	for (;;) {
		p = fgets(buf, sizeof(buf), fp);
		if (!p)
			break;
		if (!strncmp(p, pcr_str, 6)) {
			hex2bin(pcr, p + 7, len);
			return 0;
		}
	}
	fclose(fp);
	return -1;
}

#define TCG_EVENT_NAME_LEN_MAX	255

struct template_entry {
	struct {
		uint32_t pcr;
		uint8_t digest[SHA_DIGEST_LENGTH];
		uint32_t name_len;
	} header  __packed;
	char name[TCG_EVENT_NAME_LEN_MAX + 1];
	int template_len;
	uint8_t *template;
	int template_buf_len;
};

static uint8_t zero[SHA_DIGEST_LENGTH];
static uint8_t fox[SHA_DIGEST_LENGTH];

int validate = 1;

void ima_extend_pcr(uint8_t *pcr, uint8_t *digest, int length)
{
	SHA_CTX ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, pcr, length);
	if (validate && !memcmp(digest, zero, length))
		SHA1_Update(&ctx, fox, length);
	else
		SHA1_Update(&ctx, digest, length);
	SHA1_Final(pcr, &ctx);
}

static int ima_verify_tamplate_hash(struct template_entry *entry)
{
	uint8_t digest[SHA_DIGEST_LENGTH];

	if (!memcmp(zero, entry->header.digest, sizeof(zero)))
		return 0;

	SHA1(entry->template, entry->template_len, digest);

	if (memcmp(digest, entry->header.digest, sizeof(digest))) {
		log_err("template hash error\n");
		return 1;
	}

	return 0;
}

void ima_show(struct template_entry *entry)
{
	log_debug("ima, digest: ");
	log_debug_dump(entry->header.digest, sizeof(entry->header.digest));
}

void ima_ng_show(struct template_entry *entry)
{
	uint8_t *fieldp = entry->template;
	uint32_t field_len;
	int total_len = entry->template_len, digest_len, len, sig_len;
	uint8_t *digest, *sig = NULL;
	char *algo, *path;

	/* get binary digest */
	field_len = *(uint8_t *)fieldp;
	fieldp += sizeof(field_len);
	total_len -= sizeof(field_len);

	algo = (char *)fieldp;
	len = strlen(algo) + 1;
	digest_len = field_len - len;
	digest = fieldp + len;

	/* move to next field */
	fieldp += field_len;
	total_len -= field_len;

	/* get path */
	field_len = *(uint8_t *)fieldp;
	fieldp += sizeof(field_len);
	total_len -= sizeof(field_len);

	path = (char *)fieldp;

	/* move to next field */
	fieldp += field_len;
	total_len -= field_len;

	if (!strcmp(entry->name, "ima-sig")) {
		/* get signature */
		field_len = *(uint8_t *)fieldp;
		fieldp += sizeof(field_len);
		total_len -= sizeof(field_len);

		if (field_len) {
			sig = fieldp;
			sig_len = field_len;

			/* move to next field */
			fieldp += field_len;
			total_len -= field_len;
		}
	}

	/* ascii_runtime_measurements */
	log_info("%d ", entry->header.pcr);
	log_dump_n(entry->header.digest, sizeof(entry->header.digest));
	log_info(" %s %s", entry->name, algo);
	log_dump_n(digest, digest_len);
	log_info(" %s", path);

	if (sig) {
		log_info(" ");
		log_dump(sig, sig_len);
		ima_verify_signature(path, sig, sig_len);
	} else
		log_info("\n");

	if (total_len)
		log_err("Remain unprocessed data: %d\n", total_len);
}

static int ima_measurement(const char *file)
{
	uint8_t pcr[SHA_DIGEST_LENGTH] = {0,};
	uint8_t pcr10[SHA_DIGEST_LENGTH];
	struct template_entry entry = { .template = 0 };
	FILE *fp;
	int err;

	memset(fox, 0xff, SHA_DIGEST_LENGTH);

	log_debug("Initial PCR value: ");
	log_debug_dump(pcr, sizeof(pcr));

	fp = fopen(file, "rb");
	if (!fp) {
		log_err("Unable to open measurement file\n");
		return -1;
	}

	while ((err = fread(&entry.header, sizeof(entry.header), 1, fp))) {
		ima_extend_pcr(pcr, entry.header.digest, SHA_DIGEST_LENGTH);

		if (!fread(entry.name, entry.header.name_len, 1, fp)) {
			log_err("Unable to read template name\n");
			return -1;
		}

		entry.name[entry.header.name_len] = '\0';

		if (!fread(&entry.template_len, sizeof(entry.template_len), 1, fp)) {
			log_err("Unable to read template length\n");
			return -1;
		}

		if (entry.template_buf_len < entry.template_len) {
			free(entry.template);
			entry.template_buf_len = entry.template_len;
			entry.template = malloc(entry.template_len);
		}

		if (!fread(entry.template, entry.template_len, 1, fp)) {
			log_err("Unable to read template\n");
			return -1;
		}

		if (validate)
			ima_verify_tamplate_hash(&entry);

		if (!strcmp(entry.name, "ima"))
			ima_show(&entry);
		else
			ima_ng_show(&entry);
	}

	fclose(fp);

	tpm_pcr_read(10, pcr10, sizeof(pcr10));

	log_info("PCRAgg: ");
	log_dump(pcr, sizeof(pcr));

	log_info("PCR-10: ");
	log_dump(pcr10, sizeof(pcr10));

	if (memcmp(pcr, pcr10, sizeof(pcr))) {
		log_err("PCRAgg does not match PCR-10\n");
		return -1;
	}

	return 0;
}

static int cmd_ima_measurement(struct command *cmd)
{
	char *file = g_argv[optind++];

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	return ima_measurement(file);
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
		"  -1, --rsa          signing key is in RSA DER format (signing v1)\n"
		"  -k, --key          path to signing key (default keys are /etc/keys/{privkey,pubkey}_evm.pem)\n"
		"  -p, --pass         password for encrypted signing key\n"
		"  -u, --uuid         use file system UUID in HMAC calculation (EVM v2)\n"
		"  -t, --type         file types to fix 'fdsxm' (f - file, d - directory, s - block/char/symlink)\n"
		"                     x - skip fixing if both ima and evm xattrs exist (caution: they may be wrong)\n"
		"                     m - stay on the same filesystem (like 'find -xdev')\n"
		"  -n                 print result to stdout instead of setting xattr\n"
		"  -r, --recursive    recurse into directories (sign)\n"
		"  --x32              force signature for 32 bit target system\n"
		"  --x64              force signature for 32 bit target system\n"
		"  -v                 increase verbosity level\n"
		"  -h, --help         display this help and exit\n"
		"\n");
}

struct command cmds[] = {
	{"help", cmd_help, 0, "<command>"},
	{"import", cmd_import, 0, "[--rsa] pubkey keyring", "Import public key into the keyring.\n"},
	{"sign", cmd_sign_evm, 0, "[-r] [--imahash | --imasig ] [--key key] [--pass password] file", "Sign file metadata.\n"},
	{"verify", cmd_verify_evm, 0, "file", "Verify EVM signature (for debugging).\n"},
	{"ima_sign", cmd_sign_ima, 0, "[--sigfile] [--key key] [--pass password] file", "Make file content signature.\n"},
	{"ima_verify", cmd_verify_ima, 0, "file", "Verify IMA signature (for debugging).\n"},
	{"ima_hash", cmd_hash_ima, 0, "file", "Make file content hash.\n"},
	{"ima_measurement", cmd_ima_measurement, 0, "file", "Verify measurement list (experimental).\n"},
	{"ima_fix", cmd_ima_fix, 0, "[-t fdsxm] path", "Recursively fix IMA/EVM xattrs in fix mode.\n"},
	{"sign_hash", cmd_sign_hash, 0, "[--key key] [--pass password]", "Sign hashes from shaXsum output.\n"},
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
	{"uuid", 2, 0, 'u'},
	{"rsa", 0, 0, '1'},
	{"key", 1, 0, 'k'},
	{"type", 1, 0, 't'},
	{"recursive", 0, 0, 'r'},
	{"m32", 0, 0, '3'},
	{"m64", 0, 0, '6'},
	{}

};

int main(int argc, char *argv[])
{
	int err = 0, c, lind;

	g_argv = argv;
	g_argc = argc;

	while (1) {
		c = getopt_long(argc, argv, "hvnsda:p:fu::xk:t:r", opts, &lind);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			exit(0);
			break;
		case 'v':
			params.verbose++;
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
			params.hash_algo = optarg;
			break;
		case 'p':
			keypass = optarg;
			break;
		case 'f':
			sigfile = 1;
			xattr = 0;
			break;
		case 'u':
			uuid_str = optarg ?: "+";
			break;
		case '1':
			x509 = 0;
			break;
		case 'k':
			params.keyfile = optarg;
			break;
		case 't':
			search_type = optarg;
			break;
		case 'r':
			recursive = 1;
			break;
		case '3':
			msize = 32;
			break;
		case '6':
			msize = 64;
			break;
		case '?':
			exit(1);
			break;
		default:
			log_err("getopt() returned: %d (%c)\n", c, c);
		}
	}

	if (x509)
		sign_hash = sign_hash_v2;
	else
		sign_hash = sign_hash_v1;

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
