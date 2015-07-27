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
#include <linux/xattr.h>
#include <getopt.h>
#include <keyutils.h>
#include <ctype.h>
#include <termios.h>

#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#define USE_FPRINTF

#include "imaevm.h"

static char *evm_default_xattrs[] = {
	XATTR_NAME_SELINUX,
	XATTR_NAME_SMACK,
	XATTR_NAME_IMA,
	XATTR_NAME_CAPS,
	NULL
};

static char *evm_extra_smack_xattrs[] = {
	XATTR_NAME_SELINUX,
	XATTR_NAME_SMACK,
	XATTR_NAME_SMACKEXEC,
	XATTR_NAME_SMACKTRANSMUTE,
	XATTR_NAME_SMACKMMAP,
	XATTR_NAME_IMA,
	XATTR_NAME_CAPS,
	NULL
};

static char **evm_config_xattrnames = evm_default_xattrs;

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
static bool check_xattr;
static int sigdump;
static int digest;
static int digsig;
static int sigfile;
static char *uuid_str;
static char *search_type;
static int recursive;
static int msize;
static dev_t fs_dev;
static bool evm_immutable;

#define HMAC_FLAG_UUID			0x0001
#define HMAC_FLAG_UUID_SET		0x0002
static unsigned long hmac_flags = HMAC_FLAG_UUID;

typedef int (*find_cb_t)(const char *path);
static int find(const char *path, int dts, find_cb_t func);

#define REG_MASK	(1 << DT_REG)
#define DIR_MASK	(1 << DT_DIR)
#define LNK_MASK	(1 << DT_LNK)
#define CHR_MASK	(1 << DT_CHR)
#define BLK_MASK	(1 << DT_BLK)

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
		log_err("Failed to open: %s\n", name);
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
		log_err("Failed to open: %s\n", name);
		return NULL;
	}
	data = malloc(len);
	if (!fread(data, len, 1, fp))
		len = 0;
	fclose(fp);

	*size = len;
	return data;
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

	if (hmac_flags & HMAC_FLAG_UUID_SET)
		return pack_uuid(uuid_str, uuid);

	dev = st->st_dev;
	major = (dev & 0xfff00) >> 8;
	minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);

	log_debug("dev: %u:%u\n", major, minor);
	sprintf(path, "blkid -s UUID -o value /dev/block/%u:%u", major, minor);

	fp = popen(path, "r");
	if (!fp)
		goto err;

	len = fread(_uuid, 1, sizeof(_uuid), fp);
	pclose(fp);
	if (len != sizeof(_uuid))
		goto err;

	return pack_uuid(_uuid, uuid);
err:
	log_err("Failed to read UUID. Root access might require.\n");
	return -1;
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
		log_err("Failed to stat: %s\n", file);
		return -1;
	}

	if (!evm_immutable) {
		if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) {
			/* we cannot at the momement to get generation of special files..
			 * kernel API does not support it */
			int fd = open(file, 0);

			if (fd < 0) {
				log_err("Failed to open: %s\n", file);
				return -1;
			}
			if (ioctl(fd, FS_IOC_GETVERSION, &generation)) {
				log_err("ioctl() failed\n");
				return -1;
			}
			close(fd);
		}
		log_info("generation: %u\n", generation);
	}

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

	if (evm_immutable) {
		struct h_misc_digsig *hmac = (struct h_misc_digsig *)&hmac_misc;

		hmac_size = sizeof(*hmac);
		hmac->uid = st.st_uid;
		hmac->gid = st.st_gid;
		hmac->mode = st.st_mode;
	} else if (msize == 0) {
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

	if (!evm_immutable && (hmac_flags & HMAC_FLAG_UUID)) {
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
	unsigned char sig[1024];
	int len, err;

	len = calc_evm_hash(file, hash);
	if (len <= 1)
		return len;

	len = sign_hash("sha1", hash, len, key, NULL, sig + 1);
	if (len <= 1)
		return len;

	/* add header */
	len++;
	sig[0] = EVM_IMA_XATTR_DIGSIG;

	if (evm_immutable)
		sig[1] = 3; /* immutable signature version */

	if (sigdump || params.verbose >= LOG_INFO)
		dump(sig, len);

	if (xattr) {
		err = lsetxattr(file, "security.evm", sig, len, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int hash_ima(const char *file)
{
	unsigned char hash[66]; /* MAX hash size + 2 */
	int len, err, offset;
	int algo = get_hash_algo(params.hash_algo);

	if (algo > PKEY_HASH_SHA1) {
		hash[0] = IMA_XATTR_DIGEST_NG;
		hash[1] = algo;
		offset = 2;
	} else {
		hash[0] = IMA_XATTR_DIGEST;
		offset = 1;
	}

	len = ima_calc_hash(file, hash + offset);
	if (len <= 1)
		return len;

	len += offset;

	if (params.verbose >= LOG_INFO)
		log_info("hash: ");

	if (sigdump || params.verbose >= LOG_INFO)
		dump(hash, len);

	if (xattr) {
		err = lsetxattr(file, "security.ima", hash, len, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int sign_ima(const char *file, const char *key)
{
	unsigned char hash[64];
	unsigned char sig[1024];
	int len, err;

	len = ima_calc_hash(file, hash);
	if (len <= 1)
		return len;

	len = sign_hash(params.hash_algo, hash, len, key, NULL, sig + 1);
	if (len <= 1)
		return len;

	/* add header */
	len++;
	sig[0] = EVM_IMA_XATTR_DIGSIG;

	if (sigdump || params.verbose >= LOG_INFO)
		dump(sig, len);

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
		case 'x':
			check_xattr = true; break;
		case 'm':
			/* stay within the same filesystem*/
			err = lstat(path, &st);
			if (err < 0) {
				log_err("Failed to stat: %s\n", path);
				return err;
			}
			fs_dev = st.st_dev; /* filesystem to start from */
			break;
		}
	}

	return dts;
}

static int do_cmd(struct command *cmd, find_cb_t func)
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
		err = find(path, dts, func);
	} else {
		err = func(path);
	}

	return err;
}

static int cmd_hash_ima(struct command *cmd)
{
	return do_cmd(cmd, hash_ima);
}

static int sign_ima_file(const char *file)
{
	const char *key;

	key = params.keyfile ? : "/etc/keys/privkey_evm.pem";

	return sign_ima(file, key);
}

static int cmd_sign_ima(struct command *cmd)
{
	return do_cmd(cmd, sign_ima_file);
}

static int cmd_sign_hash(struct command *cmd)
{
	const char *key;
	char *token, *line = NULL;
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
				 key, NULL, sig + 1);
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
	const char *key;
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
	return do_cmd(cmd, sign_evm_path);
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
		log_err("getxattr failed: %s\n", file);
		return len;
	}

	if (sig[0] != 0x03) {
		log_err("security.evm has no signature\n");
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
			log_err("getxattr failed: %s\n", file);
			return len;
		}
	}

	if (sigfile) {
		void *tmp = file2bin(file, "sig", &len);

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
		inkey = params.x509 ? "/etc/keys/x509_evm.der" :
				      "/etc/keys/pubkey_evm.pem";
	} else
		ring = g_argv[optind++];

	id = KEY_SPEC_USER_KEYRING; /* default keyring */

	if (ring) {
		if (ring[0] != '@') {
			int base = 10;

			if (ring[0] == '0' && ring[1] == 'x')
				base = 16;
			id = strtoul(ring, NULL, base);
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

	key = read_pub_key(inkey, params.x509);
	if (!key)
		return 1;

	if (params.x509) {
		pub = file2bin(inkey, NULL, &len);
		if (!pub)
			goto out;
		calc_keyid_v2((uint32_t *)keyid, name, key);
	} else {
		len = key2bin(key, pub);
		calc_keyid_v1(keyid, name, pub, len);
	}

	log_info("Importing public key %s from file %s into keyring %d\n", name, inkey, id);

	id = add_key(params.x509 ? "asymmetric" : "user", params.x509 ? NULL : name, pub, len, id);
	if (id < 0) {
		log_err("add_key failed\n");
		err = id;
	} else {
		log_info("keyid: %d\n", id);
		printf("%d\n", id);
	}
	if (params.x509)
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
		log_err("Failed to read a key: %s\n", keyfile);
		return -1;
	}

	if (keylen > sizeof(evmkey)) {
		log_err("key is too long: %d\n", keylen);
		goto out;
	}

	/* EVM key is 128 bytes */
	memcpy(evmkey, key, keylen);
	memset(evmkey + keylen, 0, sizeof(evmkey) - keylen);

	if (lstat(file, &st)) {
		log_err("Failed to stat: %s\n", file);
		goto out;
	}

	if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) {
		/* we cannot at the momement to get generation of special files..
		 * kernel API does not support it */
		int fd = open(file, 0);

		if (fd < 0) {
			log_err("Failed to open %s\n", file);
			goto out;
		}
		if (ioctl(fd, FS_IOC_GETVERSION, &generation)) {
			log_err("ioctl() failed\n");
			goto out;
		}
		close(fd);
	}

	log_info("generation: %u\n", generation);

	list_size = llistxattr(file, list, sizeof(list));
	if (list_size <= 0) {
		log_err("llistxattr() failed: %s\n", file);
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
	unsigned char sig[1024];
	int len, err;

	len = calc_evm_hmac(file, key, hash);
	if (len <= 1)
		return len;

	log_info("hmac: ");
	log_dump(hash, len);
	memcpy(sig + 1, hash, len);

	if (xattr) {
		sig[0] = EVM_XATTR_HMAC;
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
	const char *key, *file = g_argv[optind++];
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

	if (check_xattr) {
		/* re-measuring takes a time
		 * in some cases we can skip labeling if xattrs exists
		 */
		size = llistxattr(path, list, sizeof(buf));
		if (size < 0) {
			log_errno("Failed to read xattrs (llistxattr): %s\n", path);
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
		log_errno("Failed to open file: %s", path);
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
			log_err("Failed to stat: %s\n", path);
			return err;
		}
		if (st.st_dev != fs_dev)
			return 0;
	}

	dir = opendir(path);
	if (!dir) {
		log_err("Failed to open directory %s\n", path);
		return -1;
	}

	if (fchdir(dirfd(dir))) {
		log_err("Failed to chdir %s\n", path);
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
		log_err("Failed to chdir: %s\n", path);
		return -1;
	}

	if (dts & DIR_MASK)
		func(path);

	closedir(dir);

	return 0;
}

static int cmd_ima_fix(struct command *cmd)
{
	return do_cmd(cmd, ima_fix);
}

static int ima_clear(const char *path)
{
	log_info("%s\n", path);
	lremovexattr(path, "security.ima");
	lremovexattr(path, "security.evm");

	return 0;
}

static int cmd_ima_clear(struct command *cmd)
{
	return do_cmd(cmd, ima_clear);
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
	int err = -1;

	memset(fox, 0xff, SHA_DIGEST_LENGTH);

	log_debug("Initial PCR value: ");
	log_debug_dump(pcr, sizeof(pcr));

	fp = fopen(file, "rb");
	if (!fp) {
		log_err("Failed to open measurement file: %s\n", file);
		return -1;
	}

	while (fread(&entry.header, sizeof(entry.header), 1, fp)) {
		ima_extend_pcr(pcr, entry.header.digest, SHA_DIGEST_LENGTH);

		if (!fread(entry.name, entry.header.name_len, 1, fp)) {
			log_err("Unable to read template name\n");
			goto out;
		}

		entry.name[entry.header.name_len] = '\0';

		if (!fread(&entry.template_len, sizeof(entry.template_len), 1, fp)) {
			log_err("Unable to read template length\n");
			goto out;
		}

		if (entry.template_buf_len < entry.template_len) {
			free(entry.template);
			entry.template_buf_len = entry.template_len;
			entry.template = malloc(entry.template_len);
		}

		if (!fread(entry.template, entry.template_len, 1, fp)) {
			log_err("Unable to read template\n");
			goto out;
		}

		if (validate)
			ima_verify_tamplate_hash(&entry);

		if (!strcmp(entry.name, "ima"))
			ima_show(&entry);
		else
			ima_ng_show(&entry);
	}

	tpm_pcr_read(10, pcr10, sizeof(pcr10));

	log_info("PCRAgg: ");
	log_dump(pcr, sizeof(pcr));

	log_info("PCR-10: ");
	log_dump(pcr10, sizeof(pcr10));

	if (memcmp(pcr, pcr10, sizeof(pcr))) {
		log_err("PCRAgg does not match PCR-10\n");
		goto out;
	}

	err = 0;
out:
	fclose(fp);

	return err;
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
		"  -s, --imasig       make IMA signature\n"
		"  -d, --imahash      make IMA hash\n"
		"  -f, --sigfile      store IMA signature in .sig file instead of xattr\n"
		"      --rsa          use RSA key type and signing scheme v1\n"
		"  -k, --key          path to signing key (default: /etc/keys/{privkey,pubkey}_evm.pem)\n"
		"  -p, --pass         password for encrypted signing key\n"
		"  -r, --recursive    recurse into directories (sign)\n"
		"  -t, --type         file types to fix 'fdsxm' (f: file, d: directory, s: block/char/symlink)\n"
		"                     x - skip fixing if both ima and evm xattrs exist (use with caution)\n"
		"                     m - stay on the same filesystem (like 'find -xdev')\n"
		"  -n                 print result to stdout instead of setting xattr\n"
		"  -u, --uuid         use custom FS UUID for EVM (unspecified: from FS, empty: do not use)\n"
		"      --smack        use extra SMACK xattrs for EVM\n"
		"      --m32          force EVM hmac/signature for 32 bit target system\n"
		"      --m64          force EVM hmac/signature for 64 bit target system\n"
		"  -v                 increase verbosity level\n"
		"  -h, --help         display this help and exit\n"
		"\n");
}

struct command cmds[] = {
	{"--version", NULL, 0, ""},
	{"help", cmd_help, 0, "<command>"},
	{"import", cmd_import, 0, "[--rsa] pubkey keyring", "Import public key into the keyring.\n"},
	{"sign", cmd_sign_evm, 0, "[-r] [--imahash | --imasig ] [--key key] [--pass [password] file", "Sign file metadata.\n"},
	{"verify", cmd_verify_evm, 0, "file", "Verify EVM signature (for debugging).\n"},
	{"ima_sign", cmd_sign_ima, 0, "[--sigfile] [--key key] [--pass [password] file", "Make file content signature.\n"},
	{"ima_verify", cmd_verify_ima, 0, "file", "Verify IMA signature (for debugging).\n"},
	{"ima_hash", cmd_hash_ima, 0, "file", "Make file content hash.\n"},
	{"ima_measurement", cmd_ima_measurement, 0, "file", "Verify measurement list (experimental).\n"},
	{"ima_fix", cmd_ima_fix, 0, "[-t fdsxm] path", "Recursively fix IMA/EVM xattrs in fix mode.\n"},
	{"ima_clear", cmd_ima_clear, 0, "[-t fdsxm] path", "Recursively remove IMA/EVM xattrs.\n"},
	{"sign_hash", cmd_sign_hash, 0, "[--key key] [--pass [password]", "Sign hashes from shaXsum output.\n"},
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
	{"pass", 2, 0, 'p'},
	{"sigfile", 0, 0, 'f'},
	{"uuid", 2, 0, 'u'},
	{"rsa", 0, 0, '1'},
	{"key", 1, 0, 'k'},
	{"type", 1, 0, 't'},
	{"recursive", 0, 0, 'r'},
	{"m32", 0, 0, '3'},
	{"m64", 0, 0, '6'},
	{"smack", 0, 0, 256},
	{"version", 0, 0, 257},
	{}

};

static char *get_password(void)
{
	struct termios flags, tmp_flags;
	char *password, *pwd;
	int passlen = 64;

	password = malloc(passlen);
	if (!password) {
		perror("malloc");
		return NULL;
	}

	tcgetattr(fileno(stdin), &flags);
	tmp_flags = flags;
	tmp_flags.c_lflag &= ~ECHO;
	tmp_flags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &tmp_flags) != 0) {
		perror("tcsetattr");
		return NULL;
	}

	printf("PEM password: ");
	pwd = fgets(password, passlen, stdin);

	/* restore terminal */
	if (tcsetattr(fileno(stdin), TCSANOW, &flags) != 0) {
		perror("tcsetattr");
		return NULL;
	}

	return pwd;
}

int main(int argc, char *argv[])
{
	int err = 0, c, lind;

	g_argv = argv;
	g_argc = argc;

	while (1) {
		c = getopt_long(argc, argv, "hvnsda:p::fu::k:t:ri", opts, &lind);
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
			if (optarg)
				params.keypass = optarg;
			else
				params.keypass = get_password();
			break;
		case 'f':
			sigfile = 1;
			xattr = 0;
			break;
		case 'u':
			uuid_str = optarg;
			if (uuid_str)
				hmac_flags |= HMAC_FLAG_UUID_SET;
			else
				hmac_flags &= ~HMAC_FLAG_UUID;
			break;
		case '1':
			params.x509 = 0;
			break;
		case 'k':
			params.keyfile = optarg;
			break;
		case 'i':
			evm_immutable = true;
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
		case 256:
			evm_config_xattrnames = evm_extra_smack_xattrs;
			break;
		case 257:
			printf("evmctl %s\n", VERSION);
			exit(0);
			break;
		case '?':
			exit(1);
			break;
		default:
			log_err("getopt() returned: %d (%c)\n", c, c);
		}
	}

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
	BIO_free(NULL);
	return err;
}
