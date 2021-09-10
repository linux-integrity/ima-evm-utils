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
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <getopt.h>
#include <keyutils.h>
#include <ctype.h>
#include <termios.h>
#include <assert.h>

#include <openssl/asn1.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>
#include "hash_info.h"
#include "pcr.h"
#include "utils.h"

#ifndef XATTR_APPAARMOR_SUFFIX
#define XATTR_APPARMOR_SUFFIX "apparmor"
#define XATTR_NAME_APPARMOR XATTR_SECURITY_PREFIX XATTR_APPARMOR_SUFFIX
#endif

#define USE_FPRINTF

#include "imaevm.h"

static char *evm_default_xattrs[] = {
	XATTR_NAME_SELINUX,
	XATTR_NAME_SMACK,
	XATTR_NAME_APPARMOR,
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
	XATTR_NAME_APPARMOR,
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
static char *ino_str;
static char *uid_str;
static char *gid_str;
static char *mode_str;
static char *generation_str;
static char *caps_str;
static char *ima_str;
static char *selinux_str;
static char *search_type;
static char *verify_bank;
static int verify_list_sig;
static int recursive;
static int msize;
static dev_t fs_dev;
static bool evm_immutable;
static bool evm_portable;

#define HMAC_FLAG_NO_UUID	0x0001
#define HMAC_FLAG_CAPS_SET	0x0002

static unsigned long hmac_flags;

typedef int (*find_cb_t)(const char *path);
static int find(const char *path, int dts, find_cb_t func);

#define REG_MASK	(1 << DT_REG)

struct command cmds[];
static void print_usage(struct command *cmd);

static const char *xattr_ima = "security.ima";
static const char *xattr_evm = "security.evm";

struct tpm_bank_info {
	int digest_size;
	int supported;
	const char *algo_name;
	uint8_t digest[MAX_DIGEST_SIZE];
	uint8_t pcr[NUM_PCRS][MAX_DIGEST_SIZE];
};

/* One --pcrs file per hash-algorithm/bank */
#define MAX_PCRFILE 2
static char *pcrfile[MAX_PCRFILE];
static unsigned npcrfile;

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
	size_t len;
	unsigned char *data;
	char name[strlen(file) + (ext ? strlen(ext) : 0) + 2];
	struct stat stats;

	if (ext)
		sprintf(name, "%s.%s", file, ext);
	else
		sprintf(name, "%s", file);

	log_info("Reading to %s\n", name);

	fp = fopen(name, "r");
	if (!fp) {
		log_err("Failed to open: %s\n", name);
		return NULL;
	}
	if (fstat(fileno(fp), &stats) == -1) {
		log_err("Failed to fstat: %s (%s)\n", name, strerror(errno));
		fclose(fp);
		return NULL;
	}
	len = stats.st_size;

	data = malloc(len);
	if (!data) {
		log_err("Failed to malloc %zu bytes: %s\n", len, name);
		fclose(fp);
		return NULL;
	}
	if (fread(data, len, 1, fp) != 1) {
		log_err("Failed to fread %zu bytes: %s\n", len, name);
		fclose(fp);
		free(data);
		return NULL;
	}
	fclose(fp);

	*size = (int)len;
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

	if (uuid_str)
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
        const EVP_MD *md;
	struct stat st;
	int err;
	uint32_t generation = 0;
	EVP_MD_CTX *pctx;
	unsigned int mdlen;
	char **xattrname;
	char xattr_value[1024];
	char list[1024];
	ssize_t list_size;
	char uuid[16];
	struct h_misc_64 hmac_misc;
	int hmac_size;
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX ctx;
	pctx = &ctx;
#else
	pctx = EVP_MD_CTX_new();
#endif

	if (lstat(file, &st)) {
		log_err("Failed to stat: %s\n", file);
		return -1;
	}

	if (generation_str)
		generation = strtoul(generation_str, NULL, 10);
	if (ino_str)
		st.st_ino = strtoul(ino_str, NULL, 10);
	if (uid_str)
		st.st_uid = strtoul(uid_str, NULL, 10);
	if (gid_str)
		st.st_gid = strtoul(gid_str, NULL, 10);
	if (mode_str)
		st.st_mode = strtoul(mode_str, NULL, 10);

	if (!evm_immutable) {
		if (S_ISREG(st.st_mode) && !generation_str) {
			int fd = open(file, 0);

			if (fd < 0) {
				log_err("Failed to open: %s\n", file);
				return -1;
			}
			if (ioctl(fd, FS_IOC_GETVERSION, &generation)) {
				log_err("ioctl() failed\n");
				close(fd);
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

	md = EVP_get_digestbyname(imaevm_params.hash_algo);
	if (!md) {
		log_err("EVP_get_digestbyname(%s) failed\n",
			imaevm_params.hash_algo);
		return 1;
	}

	err = EVP_DigestInit(pctx, md);
	if (!err) {
		log_err("EVP_DigestInit() failed\n");
		return 1;
	}

	for (xattrname = evm_config_xattrnames; *xattrname != NULL; xattrname++) {
		int use_xattr_ima = 0;

		if (!strcmp(*xattrname, XATTR_NAME_SELINUX) && selinux_str) {
			err = strlen(selinux_str) + 1;
			if (err > sizeof(xattr_value)) {
				log_err("selinux[%u] value is too long to fit into xattr[%zu]\n",
					err, sizeof(xattr_value));
				return -1;
			}
			strcpy(xattr_value, selinux_str);
		} else if (!strcmp(*xattrname, XATTR_NAME_IMA) && ima_str) {
			err = strlen(ima_str) / 2;
			if (err > sizeof(xattr_value)) {
				log_err("ima[%u] value is too long to fit into xattr[%zu]\n",
					err, sizeof(xattr_value));
				return -1;
			}
			hex2bin(xattr_value, ima_str, err);
		} else if (!strcmp(*xattrname, XATTR_NAME_IMA) && evm_portable){
			err = lgetxattr(file, xattr_ima, xattr_value,
					sizeof(xattr_value));
			if (err < 0) {
				log_err("EVM portable sig: %s required\n",
					xattr_ima);
				return -1;
			}
			use_xattr_ima = 1;
		} else if (!strcmp(*xattrname, XATTR_NAME_CAPS) && (hmac_flags & HMAC_FLAG_CAPS_SET)) {
			if (!caps_str)
				continue;
			err = strlen(caps_str);
			if (err >= sizeof(xattr_value)) {
				log_err("caps[%u] value is too long to fit into xattr[%zu]\n",
					err + 1, sizeof(xattr_value));
				return -1;
			}
			strcpy(xattr_value, caps_str);
		} else {
			err = lgetxattr(file, *xattrname, xattr_value, sizeof(xattr_value));
			if (err < 0) {
				log_info("no xattr: %s\n", *xattrname);
				continue;
			}
			if (!find_xattr(list, list_size, *xattrname)) {
				log_info("skipping xattr: %s\n", *xattrname);
				continue;
			}
		}
		/*log_debug("name: %s, value: %s, size: %d\n", *xattrname, xattr_value, err);*/
		log_info("name: %s, size: %d\n",
			 use_xattr_ima ? xattr_ima : *xattrname, err);
		log_debug_dump(xattr_value, err);
		err = EVP_DigestUpdate(pctx, xattr_value, err);
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
		if (!evm_portable) {
			hmac->ino = st.st_ino;
			hmac->generation = generation;
		}
		hmac->uid = st.st_uid;
		hmac->gid = st.st_gid;
		hmac->mode = st.st_mode;
	} else if (msize == 64) {
		struct h_misc_64 *hmac = (struct h_misc_64 *)&hmac_misc;

		hmac_size = sizeof(*hmac);
		if (!evm_portable) {
			hmac->ino = st.st_ino;
			hmac->generation = generation;
		}
		hmac->uid = st.st_uid;
		hmac->gid = st.st_gid;
		hmac->mode = st.st_mode;
	} else {
		struct h_misc_32 *hmac = (struct h_misc_32 *)&hmac_misc;

		hmac_size = sizeof(*hmac);
		if (!evm_portable) {
			hmac->ino = st.st_ino;
			hmac->generation = generation;
		}
		hmac->uid = st.st_uid;
		hmac->gid = st.st_gid;
		hmac->mode = st.st_mode;
	}

	log_debug("hmac_misc (%d): ", hmac_size);
	log_debug_dump(&hmac_misc, hmac_size);

	err = EVP_DigestUpdate(pctx, &hmac_misc, hmac_size);
	if (!err) {
		log_err("EVP_DigestUpdate() failed\n");
		return 1;
	}

	if (!evm_immutable && !evm_portable &&
	    !(hmac_flags & HMAC_FLAG_NO_UUID)) {
		err = get_uuid(&st, uuid);
		if (err)
			return -1;

		err = EVP_DigestUpdate(pctx, (const unsigned char *)uuid, sizeof(uuid));
		if (!err) {
			log_err("EVP_DigestUpdate() failed\n");
			return 1;
		}
	}

	err = EVP_DigestFinal(pctx, hash, &mdlen);
	if (!err) {
		log_err("EVP_DigestFinal() failed\n");
		return 1;
	}

	return mdlen;
}

static int sign_evm(const char *file, const char *key)
{
	unsigned char hash[MAX_DIGEST_SIZE];
	unsigned char sig[MAX_SIGNATURE_SIZE];
	int len, err;

	len = calc_evm_hash(file, hash);
	if (len <= 1)
		return len;
	assert(len <= sizeof(hash));

	len = sign_hash(imaevm_params.hash_algo, hash, len, key, NULL, sig + 1);
	if (len <= 1)
		return len;
	assert(len < sizeof(sig));

	/* add header */
	len++;
	if (evm_portable)
		sig[0] = EVM_XATTR_PORTABLE_DIGSIG;
	else
		sig[0] = EVM_IMA_XATTR_DIGSIG;

	if (evm_immutable)
		sig[1] = 3; /* immutable signature version */

	if (sigdump || imaevm_params.verbose >= LOG_INFO)
		imaevm_hexdump(sig, len);

	if (xattr) {
		err = lsetxattr(file, xattr_evm, sig, len, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int hash_ima(const char *file)
{
	unsigned char hash[MAX_DIGEST_SIZE + 2]; /* +2 byte xattr header */
	int len, err, offset;
	int algo = imaevm_get_hash_algo(imaevm_params.hash_algo);

	if (algo < 0) {
		log_err("Unknown hash algo: %s\n", imaevm_params.hash_algo);
		return -1;
	}
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
	assert(len + offset <= sizeof(hash));

	len += offset;

	if (imaevm_params.verbose >= LOG_INFO)
		log_info("hash(%s): ", imaevm_params.hash_algo);

	if (sigdump || imaevm_params.verbose >= LOG_INFO)
		imaevm_hexdump(hash, len);

	if (xattr) {
		err = lsetxattr(file, xattr_ima, hash, len, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int sign_ima(const char *file, const char *key)
{
	unsigned char hash[MAX_DIGEST_SIZE];
	unsigned char sig[MAX_SIGNATURE_SIZE];
	int len, err;

	len = ima_calc_hash(file, hash);
	if (len <= 1)
		return len;
	assert(len <= sizeof(hash));

	len = sign_hash(imaevm_params.hash_algo, hash, len, key, NULL, sig + 1);
	if (len <= 1)
		return len;
	assert(len < sizeof(sig));

	/* add header */
	len++;
	sig[0] = EVM_IMA_XATTR_DIGSIG;

	if (sigdump || imaevm_params.verbose >= LOG_INFO)
		imaevm_hexdump(sig, len);

	if (sigfile)
		bin2file(file, "sig", sig, len);

	if (xattr) {
		err = lsetxattr(file, xattr_ima, sig, len, 0);
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

	key = imaevm_params.keyfile ? : "/etc/keys/privkey_evm.pem";

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
	unsigned char hash[MAX_DIGEST_SIZE];
	unsigned char sig[MAX_SIGNATURE_SIZE] = "\x03";
	int siglen;

	key = imaevm_params.keyfile ? : "/etc/keys/privkey_evm.pem";

	/* support reading hash (eg. output of shasum) */
	while ((len = getline(&line, &line_len, stdin)) > 0) {
		/* remove end of line */
		if (line[len - 1] == '\n')
			line[--len] = '\0';

		/* find the end of the hash */
		token = strpbrk(line, ", \t");
		hashlen = token ? token - line : strlen(line);

		assert(hashlen / 2 <= sizeof(hash));
		hex2bin(hash, line, hashlen / 2);
		siglen = sign_hash(imaevm_params.hash_algo, hash, hashlen / 2,
				 key, NULL, sig + 1);
		if (siglen <= 1)
			return siglen;
		assert(siglen < sizeof(sig));

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

	key = imaevm_params.keyfile ? : "/etc/keys/privkey_evm.pem";

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
	unsigned char hash[MAX_DIGEST_SIZE];
	unsigned char sig[MAX_SIGNATURE_SIZE];
	int sig_hash_algo;
	int mdlen;
	int len;

	len = lgetxattr(file, xattr_evm, sig, sizeof(sig));
	if (len < 0) {
		log_err("getxattr failed: %s\n", file);
		return len;
	}

	if ((sig[0] != EVM_IMA_XATTR_DIGSIG) &&
	    (sig[0] != EVM_XATTR_PORTABLE_DIGSIG)) {
		log_err("%s has no signature\n", xattr_evm);
		return -1;
	}

	if (sig[0] == EVM_XATTR_PORTABLE_DIGSIG) {
		if (sig[1] != DIGSIG_VERSION_2) {
			log_err("Portable sig: invalid type\n");
			return -1;
		}
		evm_portable = true;
	}

	sig_hash_algo = imaevm_hash_algo_from_sig(sig + 1);
	if (sig_hash_algo < 0) {
		log_err("unknown hash algo: %s\n", file);
		return -1;
	}
	imaevm_params.hash_algo = imaevm_hash_algo_by_id(sig_hash_algo);

	mdlen = calc_evm_hash(file, hash);
	if (mdlen <= 1)
		return mdlen;
	assert(mdlen <= sizeof(hash));

	return verify_hash(file, hash, mdlen, sig + 1, len - 1);
}

static int cmd_verify_evm(struct command *cmd)
{
	char *file = g_argv[optind++];
	int err;

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	if (imaevm_params.x509) {
		if (imaevm_params.keyfile) /* Support multiple public keys */
			init_public_keys(imaevm_params.keyfile);
		else			   /* assume read pubkey from x509 cert */
			init_public_keys("/etc/keys/x509_evm.der");
	}

	err = verify_evm(file);
	if (!err && imaevm_params.verbose >= LOG_INFO)
		log_info("%s: verification is OK\n", file);
	return err;
}

static int verify_ima(const char *file)
{
	unsigned char sig[MAX_SIGNATURE_SIZE];
	int len;

	if (sigfile) {
		void *tmp = file2bin(file, "sig", &len);

		if (!tmp) {
			log_err("Failed reading: %s\n", file);
			return -1;
		}
		if (len > sizeof(sig)) {
			log_err("Signature file is too big: %s\n", file);
			free(tmp);
			return -1;
		}
		memcpy(sig, tmp, len);
		free(tmp);
	} else {
		len = lgetxattr(file, xattr_ima, sig, sizeof(sig));
		if (len < 0) {
			log_err("getxattr failed: %s\n", file);
			return len;
		}
	}

	return ima_verify_signature(file, sig, len, NULL, 0);
}

static int cmd_verify_ima(struct command *cmd)
{
	char *file = g_argv[optind++];
	int err, fails = 0;

	if (imaevm_params.x509) {
		if (imaevm_params.keyfile) /* Support multiple public keys */
			init_public_keys(imaevm_params.keyfile);
		else			   /* assume read pubkey from x509 cert */
			init_public_keys("/etc/keys/x509_evm.der");
	}

	errno = 0;
	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	do {
		err = verify_ima(file);
		if (err)
			fails++;
		if (!err && imaevm_params.verbose >= LOG_INFO)
			log_info("%s: verification is OK\n", file);
	} while ((file = g_argv[optind++]));
	return fails > 0;
}

static int cmd_convert(struct command *cmd)
{
	char *inkey;
	unsigned char _pub[1024], *pub = _pub;
	int len, err = 0;
	char name[20];
	uint8_t keyid[8];
	RSA *key;

	imaevm_params.x509 = 0;

	inkey = g_argv[optind++];
	if (!inkey) {
		inkey = imaevm_params.x509 ? "/etc/keys/x509_evm.der" :
					     "/etc/keys/pubkey_evm.pem";
	}

	key = read_pub_key(inkey, imaevm_params.x509);
	if (!key)
		return 1;

	len = key2bin(key, pub);
	calc_keyid_v1(keyid, name, pub, len);

	bin2file(inkey, "bin", pub, len);
	bin2file(inkey, "keyid", (const unsigned char *)name, strlen(name));

	RSA_free(key);
	return err;
}

static int cmd_import(struct command *cmd)
{
	char *inkey, *ring = NULL;
	unsigned char _pub[1024], *pub = _pub;
	int id, len, err = 0;
	char name[20];
	uint8_t keyid[8];

	inkey = g_argv[optind++];
	if (!inkey) {
		inkey = imaevm_params.x509 ? "/etc/keys/x509_evm.der" :
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

	if (imaevm_params.x509) {
		EVP_PKEY *pkey = read_pub_pkey(inkey, imaevm_params.x509);

		if (!pkey)
			return 1;
		pub = file2bin(inkey, NULL, &len);
		if (!pub) {
			EVP_PKEY_free(pkey);
			return 1;
		}
		calc_keyid_v2((uint32_t *)keyid, name, pkey);
		EVP_PKEY_free(pkey);
	} else {
		RSA *key = read_pub_key(inkey, imaevm_params.x509);

		if (!key)
			return 1;
		len = key2bin(key, pub);
		calc_keyid_v1(keyid, name, pub, len);
		RSA_free(key);
	}

	log_info("Importing public key %s from file %s into keyring %d\n", name, inkey, id);

	id = add_key(imaevm_params.x509 ? "asymmetric" : "user",
		     imaevm_params.x509 ? NULL : name, pub, len, id);
	if (id < 0) {
		log_err("add_key failed\n");
		err = id;
	} else {
		log_info("keyid: %d\n", id);
		printf("%d\n", id);
	}
	if (imaevm_params.x509)
		free(pub);
	return err;
}

static int setxattr_ima(const char *file, char *sig_file)
{
	unsigned char *sig;
	int len, err;

	if (sig_file)
		sig = file2bin(sig_file, NULL, &len);
	else
		sig = file2bin(file, "sig", &len);
	if (!sig)
		return 0;

	err = lsetxattr(file, xattr_ima, sig, len, 0);
	if (err < 0)
		log_err("setxattr failed: %s\n", file);
	free(sig);
	return err;
}

static int cmd_setxattr_ima(struct command *cmd)
{
	char *file, *sig = NULL;

	if (sigfile)
		sig = g_argv[optind++];
	file =  g_argv[optind++];

	if (!file) {
		log_err("Parameters missing\n");
		print_usage(cmd);
		return -1;
	}

	return setxattr_ima(file, sig);
}

#define MAX_KEY_SIZE 128

static int calc_evm_hmac(const char *file, const char *keyfile, unsigned char *hash)
{
        const EVP_MD *md;
	struct stat st;
	int err = -1;
	uint32_t generation = 0;
	HMAC_CTX *pctx;
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
#if OPENSSL_VERSION_NUMBER < 0x10100000
	HMAC_CTX ctx;
	pctx = &ctx;
#else
	pctx = HMAC_CTX_new();
#endif

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
	if (keylen < sizeof(evmkey))
		memset(evmkey + keylen, 0, sizeof(evmkey) - keylen);

	if (lstat(file, &st)) {
		log_err("Failed to stat: %s\n", file);
		goto out;
	}

	if (S_ISREG(st.st_mode)) {
		int fd = open(file, 0);

		if (fd < 0) {
			log_err("Failed to open %s\n", file);
			goto out;
		}
		if (ioctl(fd, FS_IOC_GETVERSION, &generation)) {
			log_err("ioctl() failed\n");
			close(fd);
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

	md = EVP_get_digestbyname(imaevm_params.hash_algo);
	if (!md) {
		log_err("EVP_get_digestbyname(%s) failed\n",
			imaevm_params.hash_algo);
		goto out;
	}

	err = !HMAC_Init_ex(pctx, evmkey, sizeof(evmkey), md, NULL);
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
		err = !HMAC_Update(pctx, xattr_value, err);
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

	err = !HMAC_Update(pctx, (const unsigned char *)&hmac_misc, hmac_size);
	if (err) {
		log_err("HMAC_Update() failed\n");
		goto out_ctx_cleanup;
	}
	err = !HMAC_Final(pctx, hash, &mdlen);
	if (err)
		log_err("HMAC_Final() failed\n");
out_ctx_cleanup:
#if OPENSSL_VERSION_NUMBER < 0x10100000
	HMAC_CTX_cleanup(pctx);
#else
	HMAC_CTX_free(pctx);
#endif
out:
	free(key);
	return err ?: mdlen;
}

static int hmac_evm(const char *file, const char *key)
{
	unsigned char hash[MAX_DIGEST_SIZE];
	unsigned char sig[MAX_SIGNATURE_SIZE];
	int len, err;

	len = calc_evm_hmac(file, key, hash);
	if (len <= 1)
		return len;
	assert(len <= sizeof(hash));

	log_info("hmac: ");
	log_dump(hash, len);
	assert(len < sizeof(sig));
	memcpy(sig + 1, hash, len);

	if (xattr) {
		sig[0] = EVM_XATTR_HMAC;
		err = lsetxattr(file, xattr_evm, sig, len + 1, 0);
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

	key = imaevm_params.keyfile ? : "/etc/keys/privkey_evm.pem";

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
			if (!strcmp(list, xattr_ima))
				ima = 1;
			else if (!strcmp(list, xattr_evm))
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
	lremovexattr(path, xattr_ima);
	lremovexattr(path, xattr_evm);

	return 0;
}

static int cmd_ima_clear(struct command *cmd)
{
	return do_cmd(cmd, ima_clear);
}

#define TCG_EVENT_NAME_LEN_MAX	255

struct template_entry {
	struct {
		uint32_t pcr;
		uint8_t digest[SHA_DIGEST_LENGTH];
		uint32_t name_len;
	} header  __packed;
	char name[TCG_EVENT_NAME_LEN_MAX + 1];
	uint32_t template_buf_len;
	uint32_t template_len;
	uint8_t *template;
};

static uint8_t zero[MAX_DIGEST_SIZE];

static int ignore_violations = 0;

static int ima_verify_template_hash(struct template_entry *entry)
{
	uint8_t digest[SHA_DIGEST_LENGTH];
	static int line = 0;

	line++;

	if (!memcmp(zero, entry->header.digest, sizeof(digest)))
		return 0;

	SHA1(entry->template, entry->template_len, digest);

	if (memcmp(digest, entry->header.digest, sizeof(digest))) {
		if (imaevm_params.verbose > LOG_INFO)
			log_info("Failed to verify template data digest(line %d).\n",
				  line);
		return 1;
	}

	return 0;
}

void ima_show(struct template_entry *entry)
{
	if (imaevm_params.verbose <= LOG_INFO)
		return;

	log_info("%d ", entry->header.pcr);
	log_dump_n(entry->header.digest, sizeof(entry->header.digest));
	log_info(" %s ", entry->name);
	log_dump_n(entry->template, SHA_DIGEST_LENGTH);
	log_info(" %s\n", entry->template + SHA_DIGEST_LENGTH);
}

/*
 * Keep track of unknown or malformed template names.
 *
 * Return 1 for found, return 0 for not found.
 */
static int lookup_template_name_entry(char *template_name)
{
	struct template_name_entry {
		struct template_name_entry *next;
		char name[];
	} *entry;
	static struct template_name_entry *template_names = NULL;

	for (entry = template_names; entry != NULL; entry = entry->next) {
		if (strcmp(entry->name, template_name) == 0)
			return 1;
	}

	entry = malloc(sizeof(struct template_name_entry) +
			strlen(template_name) + 1);
	if (entry) {
		strcpy(entry->name, template_name);
		entry->next = template_names;
		template_names = entry;
	}
	return 0;
}

void ima_ng_show(struct template_entry *entry)
{
	uint8_t *fieldp = entry->template;
	uint32_t field_len;
	int total_len = entry->template_len, digest_len, len, sig_len, fbuf_len;
	uint8_t *digest, *sig = NULL, *fbuf = NULL;
	char *algo, *path;
	int found;
	int err;

	/* get binary digest */
	field_len = *(uint32_t *)fieldp;
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
	field_len = *(uint32_t *)fieldp;
	fieldp += sizeof(field_len);
	total_len -= sizeof(field_len);

	path = (char *)fieldp;

	/* move to next field */
	fieldp += field_len;
	total_len -= field_len;

	if (!strcmp(entry->name, "ima-sig")) {
		/* get signature */
		field_len = *(uint32_t *)fieldp;
		fieldp += sizeof(field_len);
		total_len -= sizeof(field_len);

		if (field_len) {
			sig = fieldp;
			sig_len = field_len;

			/* move to next field */
			fieldp += field_len;
			total_len -= field_len;
		}
	} else if (!strcmp(entry->name, "ima-buf")) {
		field_len = *(uint32_t *)fieldp;
		fieldp += sizeof(field_len);
		total_len -= sizeof(field_len);
		if (field_len) {
			fbuf = fieldp;
			fbuf_len = field_len;

			/* move to next field */
			fieldp += field_len;
			total_len -= field_len;
		}
	}

	/* ascii_runtime_measurements */
	if (imaevm_params.verbose > LOG_INFO) {
		log_info("%d ", entry->header.pcr);
		log_dump_n(entry->header.digest, sizeof(entry->header.digest));
		log_info(" %s %s", entry->name, algo);
		log_dump_n(digest, digest_len);
		log_info(" %s", path);
		if (fbuf) {
			log_info(" ");
			log_dump_n(fbuf, fbuf_len);
		}
	}

	if (sig) {
		if (imaevm_params.verbose > LOG_INFO) {
			log_info(" ");
			log_dump(sig, sig_len);
		}
		if (verify_list_sig)
			err = ima_verify_signature(path, sig, sig_len,
						   digest, digest_len);
		else
			err = ima_verify_signature(path, sig, sig_len, NULL, 0);
		if (!err && imaevm_params.verbose > LOG_INFO)
			log_info("%s: verification is OK\n", path);
	} else {
		if (imaevm_params.verbose > LOG_INFO)
			log_info("\n");
	}

	if (total_len) {
		found = lookup_template_name_entry(entry->name);
		if (!found)
			log_err("Template \"%s\" contains unprocessed data: "
				 "%d bytes\n", entry->name, total_len);
	}
}

static void set_bank_info(struct tpm_bank_info *bank, const char *algo_name)
{
	const EVP_MD *md;

	bank->algo_name = algo_name;
	md = EVP_get_digestbyname(bank->algo_name);
	if (!md)
		return;

	bank->supported = 1;
	bank->digest_size = EVP_MD_size(md);
}

static struct tpm_bank_info *init_tpm_banks(int *num_banks)
{
	struct tpm_bank_info *banks = NULL;
	const char *default_algos[] = {"sha1", "sha256"};
	int num_algos = sizeof(default_algos) / sizeof(default_algos[0]);
	int i, j;

	banks = calloc(num_algos, sizeof(struct tpm_bank_info));
	if (!banks)
		return banks;

	/* re-calculate the PCRs digests for only known algorithms */
	*num_banks = num_algos;
	for (i = 0; i < num_algos; i++) {
		for (j = 0; j < HASH_ALGO__LAST; j++) {
			if (!strcmp(default_algos[i], hash_algo_name[j]))
				set_bank_info(&banks[i], hash_algo_name[j]);
		}
	}
	return banks;
}

/*
 * Compare the calculated TPM PCR banks against the PCR values read.
 * The banks_mask parameter allows to select which banks to consider.
 * A banks_maks of 0x3 would consider banks 1 and 2, 0x2 would only
 * consider the 2nd bank, ~0 would consider all banks.
 *
 * On failure to match any TPM bank, fail comparison.
 */
static int compare_tpm_banks(int num_banks, struct tpm_bank_info *bank,
			     struct tpm_bank_info *tpm_bank,
			     unsigned int banks_mask, unsigned long entry_num)
{
	int i, j;
	int ret = 0;

	for (i = 0; i < num_banks; i++) {
		if (!bank[i].supported || !tpm_bank[i].supported)
			continue;
		/* do we need to look at the n-th bank ? */
		if ((banks_mask & (1 << i)) == 0)
			continue;
		for (j = 0; j < NUM_PCRS; j++) {
			if (memcmp(bank[i].pcr[j], zero, bank[i].digest_size)
			    == 0)
				continue;

			if (memcmp(bank[i].pcr[j], tpm_bank[i].pcr[j],
				     bank[i].digest_size) != 0)
				ret = 1;

			if ((!ret && imaevm_params.verbose <= LOG_INFO) ||
			    (ret && imaevm_params.verbose <= LOG_DEBUG))
				continue;

			log_info("%s: PCRAgg  %d: ", bank[i].algo_name, j);
			log_dump(bank[i].pcr[j], bank[i].digest_size);

			log_info("%s: TPM PCR-%d: ", tpm_bank[i].algo_name, j);
			log_dump(tpm_bank[i].pcr[j], tpm_bank[i].digest_size);

			if (!ret)
				log_info("%s PCR-%d: succeed at entry %lu\n",
					 bank[i].algo_name, j, entry_num);
			else
				log_info("%s: PCRAgg %d does not match TPM PCR-%d\n",
					 bank[i].algo_name, j, j);
		}
	}
	return ret;
}

/* Calculate the template hash for a particular hash algorithm */
static int calculate_template_digest(EVP_MD_CTX *pctx, const EVP_MD *md,
				     struct template_entry *entry,
				     struct tpm_bank_info *bank)
{
	unsigned int mdlen;
	int err;

	err = EVP_DigestInit(pctx, md);
	if (!err) {
		printf("EVP_DigestInit() failed\n");
		goto out;
	}

	err = EVP_DigestUpdate(pctx, entry->template, entry->template_len);
	if (!err) {
		printf("EVP_DigestUpdate() failed\n");
		goto out;
	}

	err = EVP_DigestFinal(pctx, bank->digest, &mdlen);
	if (!err)
		printf("EVP_DigestUpdate() failed\n");
out:
	if (!err)
		err = 1;
	return err;
}

/* Extend a specific TPM bank with the template hash */
static int extend_tpm_bank(EVP_MD_CTX *pctx, const EVP_MD *md,
			   struct template_entry *entry,
			   struct tpm_bank_info *bank)
{
	unsigned int mdlen;
	int err;

	err = EVP_DigestInit(pctx, md);
	if (!err) {
		printf("EVP_DigestInit() failed\n");
		goto out;
	}

	err = EVP_DigestUpdate(pctx, bank->pcr[entry->header.pcr],
			       bank->digest_size);
	if (!err) {
		printf("EVP_DigestUpdate() failed\n");
		goto out;
	}

	err = EVP_DigestUpdate(pctx, bank->digest, bank->digest_size);
	if (!err) {
		printf("EVP_DigestUpdate() failed\n");
		goto out;
	}

	err = EVP_DigestFinal(pctx, bank->pcr[entry->header.pcr], &mdlen);
	if (!err)
		printf("EVP_DigestFinal() failed\n");

out:
	if (!err)
		err = 1;
	return err;
}

/* Calculate and extend the template hash for multiple hash algorithms */
static void extend_tpm_banks(struct template_entry *entry, int num_banks,
			     struct tpm_bank_info *bank,
			     struct tpm_bank_info *padded_bank)
{
	EVP_MD_CTX *pctx;
	const EVP_MD *md;
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX ctx;
	pctx = &ctx;
#else
	pctx = EVP_MD_CTX_new();
#endif
	int err;
	int i;

	for (i = 0; i < num_banks; i++) {
		if (!bank[i].supported)
			continue;
		md = EVP_get_digestbyname(bank[i].algo_name);
		if (!md) {
			printf("EVP_get_digestbyname(%s) failed\n",
				bank[i].algo_name);
			bank[i].supported = 0;
			continue;
		}

		/*
		 * Measurement violations are 0x00 digests, which are extended
		 * into the TPM as 0xff.  Verifying the IMA measurement list
		 * will fail, unless the 0x00 digests are converted to 0xff's.
		 *
		 * Initially the sha1 digest, including violations, was padded
		 * with zeroes before being extended into the TPM.  With the
		 * per TPM bank digest, violations are the full per bank digest
		 * size.
		 */
		if (memcmp(entry->header.digest, zero, SHA_DIGEST_LENGTH) == 0) {
			if (!ignore_violations) {
				memset(bank[i].digest, 0x00, bank[i].digest_size);
				memset(padded_bank[i].digest, 0x00, padded_bank[i].digest_size);
			} else {
				memset(bank[i].digest, 0xff,
				       bank[i].digest_size);

				memset(padded_bank[i].digest, 0x00,
				       padded_bank[i].digest_size);
				memset(padded_bank[i].digest, 0xff,
				       SHA_DIGEST_LENGTH);
			}
		} else {
			err = calculate_template_digest(pctx, md, entry,
							&bank[i]);
			if (!err) {
				bank[i].supported = 0;
				continue;
			}

			/*
			 * calloc set the memory to zero, so just copy the
			 * sha1 digest.
			 */
			memcpy(padded_bank[i].digest, entry->header.digest,
			       SHA_DIGEST_LENGTH);
		}

		/* extend TPM BANK with template digest */
		err = extend_tpm_bank(pctx, md, entry, &bank[i]);
		if (!err)
			bank[i].supported = 0;

		/* extend TPM BANK with zero padded sha1 template digest */
		err = extend_tpm_bank(pctx, md, entry, &padded_bank[i]);
		if (!err)
			padded_bank[i].supported = 0;
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	EVP_MD_CTX_free(pctx);
#endif
}

static int read_one_bank(struct tpm_bank_info *tpm_bank, FILE *fp)
{
	char *p, pcr_str[8], buf[MAX_DIGEST_SIZE * 2 + 8];
	int i = 0;
	int result = -1;
	for (;;) {
		p = fgets(buf, sizeof(buf), fp);
		if (!p || i >= NUM_PCRS)
			break;
		sprintf(pcr_str, "PCR-%2.2d", i);
		if (!strncmp(p, pcr_str, 6))
			hex2bin(tpm_bank->pcr[i++], p + 7, tpm_bank->digest_size);
		result = 0;
	}
	return result;
}

static char *pcrs = "/sys/class/tpm/tpm0/device/pcrs";  /* Kernels >= 4.0 */
static char *misc_pcrs = "/sys/class/misc/tpm0/device/pcrs";

/* Read one of the TPM 1.2 sysfs files if present */
static int read_sysfs_pcrs(int num_banks, struct tpm_bank_info *tpm_banks)
{
	FILE *fp;
	int i, result;

	fp = fopen(pcrs, "r");
	if (!fp)
		fp = fopen(misc_pcrs, "r");
	if (!fp)
		return -1;

	result = read_one_bank(&tpm_banks[0], fp);
	fclose(fp);
	if (result < 0)
		return result;
	tpm_banks[0].supported = 1;
	for (i = 1; i < num_banks; i++)
		tpm_banks[i].supported = 0;
	return 0;

}

/* Read PCRs from per-bank file(s) specified via --pcrs */
static int read_file_pcrs(int num_banks, struct tpm_bank_info *tpm_banks)
{
	struct stat s;
	FILE *fp;
	char *p;
	const char *alg, *path;
	int i, j, bank, result;

	for (i = 0; i < num_banks; i++)
		tpm_banks[i].supported = 0;

	for (i = 0; i < npcrfile; i++) {
		p = strchr(pcrfile[i], ',');
		if (p) {
			*p = 0;
			alg = pcrfile[i];
			path = ++p;
		} else {
			alg = "sha1";
			path = pcrfile[i];
		}

		bank = -1;
		for (j = 0; j < num_banks; j++) {
			if (!strcmp(tpm_banks[j].algo_name, alg)) {
				bank = j;
				break;
			}
		}
		if (bank < 0) {
			log_err("Unknown algorithm '%s'\n", alg);
			return -1;
		}

		if (stat(path, &s) == -1) {
			log_err("Could not stat '%s'\n", path);
			return -1;
		}

		if (!S_ISREG(s.st_mode)) {
			log_err("PCR file: not a regular file or link to regular file\n");
			return -1;
		}

		fp = fopen(path, "r");
		if (!fp) {
			log_err("Could not open '%s'\n", path);
			return -1;
		}

		result = read_one_bank(&tpm_banks[bank], fp);
		fclose(fp);
		if (result < 0)
			return result;
		tpm_banks[bank].supported = 1;
	}

	return 0;
}

/*
 * Attempt to read TPM PCRs from either TPM 1.2 or multiple TPM 2.0 banks.
 *
 * On success reading from any TPM bank, return 0.
 */
static int read_tpm_banks(int num_banks, struct tpm_bank_info *bank)
{
	int tpm_enabled = 0;
	char *errmsg = NULL;
	int i;
	uint32_t pcr_handle;
	int err;

	/* If --pcrs was specified, read only from the specified file(s) */
	if (npcrfile)
		return read_file_pcrs(num_banks, bank);

	/* Else try reading PCRs from the sysfs file if present */
	if (read_sysfs_pcrs(num_banks, bank) == 0)
		return 0;

	/* Any userspace applications available for reading TPM 2.0 PCRs? */
	if (!tpm2_pcr_supported()) {
		log_debug("Failed to read TPM 2.0 PCRs\n");
		return 1;
	}

	/* Read PCRs from multiple TPM 2.0 banks */
	for (i = 0; i < num_banks; i++) {
		err = 0;
		for (pcr_handle = 0;
		     pcr_handle < NUM_PCRS && !err;
		     pcr_handle++) {
			err = tpm2_pcr_read(bank[i].algo_name, pcr_handle,
					    bank[i].pcr[pcr_handle],
					    bank[i].digest_size,
					    &errmsg);
			if (err) {
				log_debug("Failed to read %s PCRs: (%s)\n",
					  bank[i].algo_name, errmsg);
				free(errmsg);
				bank[i].supported = 0;
			}
		}
		if (bank[i].supported)
			tpm_enabled = 1;
	}
	return tpm_enabled ? 0 : 1;
}

static int ima_measurement(const char *file)
{
	struct tpm_bank_info *pseudo_padded_banks;
	struct tpm_bank_info *pseudo_banks;
	struct tpm_bank_info *tpm_banks;
	int is_ima_template, cur_template_fmt;
	int num_banks = 0;
	int tpmbanks = 1;
	int first_record = 1;
	unsigned int pseudo_padded_banks_mask, pseudo_banks_mask;
	unsigned long entry_num = 0;
	int c;

	struct template_entry entry = { .template = 0 };
	FILE *fp;
	int invalid_template_digest = 0;
	int err_padded = -1;
	int err = -1;

	errno = 0;
	memset(zero, 0, MAX_DIGEST_SIZE);

	pseudo_padded_banks = init_tpm_banks(&num_banks);
	pseudo_banks = init_tpm_banks(&num_banks);
	tpm_banks = init_tpm_banks(&num_banks);

	fp = fopen(file, "rb");
	if (!fp) {
		log_err("Failed to open measurement file: %s\n", file);
		return -1;
	}

	if (imaevm_params.keyfile)	/* Support multiple public keys */
		init_public_keys(imaevm_params.keyfile);
	else				/* assume read pubkey from x509 cert */
		init_public_keys("/etc/keys/x509_evm.der");

	/*
	 * Reading the PCRs before walking the IMA measurement list
	 * guarantees that all of the measurements are included in
	 * the PCRs.
	 */
	if (read_tpm_banks(num_banks, tpm_banks) != 0)
		tpmbanks = 0;

	/* A mask where each bit represents the banks to check against */
	pseudo_banks_mask = (1 << num_banks) - 1;
	pseudo_padded_banks_mask = pseudo_banks_mask;

	/* Instead of verifying all the banks, only verify a single bank */
	for (c = 0; c < num_banks; c++) {
		if (verify_bank
		    && strcmp(pseudo_padded_banks[c].algo_name, verify_bank)) {
			pseudo_banks_mask ^= (1 << c);
			pseudo_padded_banks_mask ^= (1 << c);
			break;
		}
	}

	while (fread(&entry.header, sizeof(entry.header), 1, fp) == 1) {
		entry_num++;
		if (entry.header.pcr >= NUM_PCRS) {
			log_err("Invalid PCR %d.\n", entry.header.pcr);
			fclose(fp);
			exit(1);
		}
		if (entry.header.name_len > TCG_EVENT_NAME_LEN_MAX) {
			log_err("%d ERROR: event name too long!\n",
				entry.header.name_len);
		       fclose(fp);
		       exit(1);
		}

		memset(entry.name, 0x00, sizeof(entry.name));
		if (!fread(entry.name, entry.header.name_len, 1, fp)) {
			log_err("Unable to read template name\n");
			goto out;
		}

	       /*
		* The "ima" template format can not be mixed with other
		* template formats records.
		*/
		if (!first_record) {
			cur_template_fmt = strcmp(entry.name, "ima") == 0 ? 1 : 0;
			if ((is_ima_template && !cur_template_fmt) ||
			    (!is_ima_template && cur_template_fmt)) {
				log_err("Mixed measurement list containing \"ima\" and other template formats not supported.\n");
				goto out;
			}
		} else {
			first_record = 0;
			is_ima_template = strcmp(entry.name, "ima") == 0 ? 1 : 0;
		}

		/* The "ima" template data is not length prefixed.  Skip it. */
		if (!is_ima_template) {
			if (!fread(&entry.template_len,
				   sizeof(entry.template_len), 1, fp)) {
				log_err("Unable to read template length\n");
				goto out;
			}
		} else {
			entry.template_len = SHA_DIGEST_LENGTH +
					     TCG_EVENT_NAME_LEN_MAX + 1;
		}

		if (entry.template_buf_len < entry.template_len) {
			free(entry.template);
			entry.template_buf_len = entry.template_len;
			entry.template = malloc(entry.template_len);
		}

		if (!is_ima_template) {
			if (!fread(entry.template, entry.template_len, 1, fp)) {
				log_errno("Unable to read template\n");
				goto out;
			}
		} else {
			uint32_t field_len;
			uint32_t len;

			/*
			 * The "ima" template data format is digest,
			 * filename length, filename.
			 */
			if (!fread(entry.template, SHA_DIGEST_LENGTH, 1, fp)) {
				log_errno("Unable to read file data hash\n");
				goto out;
			}

			/*
			 * Read the filename length, but it isn't included
			 * in the template data hash calculation.
			 */
			len = fread(&field_len, sizeof(field_len), 1, fp);
			if (len <= 0) {
				log_errno("Failed reading file name length\n");
				goto out;
			}
			if (field_len > TCG_EVENT_NAME_LEN_MAX) {
				log_err("file pathname is too long\n");
				goto out;
			}

			len = fread(entry.template + SHA_DIGEST_LENGTH,
				    field_len, 1, fp);
			if (len != 1) {
				log_errno("Failed reading file name\n");
				goto out;
			}

			/*
			 * The template data is fixed sized, zero out
			 * the remaining memory.
			 */
			len = SHA_DIGEST_LENGTH + field_len;
			memset(entry.template + len, 0x00,
			       entry.template_buf_len - len);
		}

		extend_tpm_banks(&entry, num_banks, pseudo_banks,
				 pseudo_padded_banks);

		/* Recalculate and verify template data digest */
		err = ima_verify_template_hash(&entry);
		if (err)
			invalid_template_digest = 1;

		if (is_ima_template)
			ima_show(&entry);
		else
			ima_ng_show(&entry);

		if (!tpmbanks)
			continue;

		for (c = 0; c < num_banks; c++) {
			if ((pseudo_banks_mask & (1 << c)) == 0)
				continue;
			/* The measurement list might contain too many entries,
			 * compare the re-calculated TPM PCR values after each
			 * extend.
			 */
			err = compare_tpm_banks(num_banks, pseudo_banks,
						tpm_banks, 1 << c, entry_num);
			if (!err)
				pseudo_banks_mask ^= (1 << c);
		}
		if (pseudo_banks_mask == 0)
			break;

		for (c = 0; c < num_banks; c++) {
			if ((pseudo_padded_banks_mask & (1 << c)) == 0)
				continue;
			/* Compare against original SHA1 zero padded TPM PCR values */
			err_padded = compare_tpm_banks(num_banks,
						       pseudo_padded_banks,
						       tpm_banks,
						       1 << c, entry_num);
			if (!err_padded)
				pseudo_padded_banks_mask ^= (1 << c);
		}
		if (pseudo_padded_banks_mask == 0)
			break;
	}

	if (tpmbanks == 0)
		log_info("Failed to read any TPM PCRs\n");
	else {
		if (!err)
			log_info("Matched per TPM bank calculated digest(s).\n");
		else if (!err_padded) {
			log_info("Matched SHA1 padded TPM digest(s).\n");
			err = 0;
		} else
			log_info("Failed to match per TPM bank or SHA1 padded TPM digest(s).\n");
	}

	if (invalid_template_digest) {
		log_info("Failed to verify template data digest.\n");
		err = 1;
	}

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

#define MAX_EVENT_DATA_SIZE 200000
static int read_binary_bios_measurements(char *file, struct tpm_bank_info *bank)
{
	struct {
		struct {
			uint32_t pcr;
			int type;
			unsigned char digest[SHA_DIGEST_LENGTH];
			uint32_t len;
		} header;
		unsigned char data[MAX_EVENT_DATA_SIZE];
	} event;
	struct stat s;
	FILE *fp;
	SHA_CTX c;
	int err = 0;
	int len;
	int i;

	if (stat(file, &s) == -1) {
		errno = 0;
		return 1;
	}

	if (!S_ISREG(s.st_mode)) {
		log_info("Bios event log: not a regular file or link to regular file\n");
		return 1;
	}

	fp = fopen(file, "r");
	if (!fp) {
		log_errno("Failed to open TPM 1.2 event log.\n");
		return 1;
	}

	if (imaevm_params.verbose > LOG_INFO)
		log_info("Reading the TPM 1.2 event log %s.\n", file);

	/* Extend the pseudo TPM PCRs with the event digest */
	while (fread(&event, sizeof(event.header), 1, fp) == 1) {
		if (imaevm_params.verbose > LOG_INFO) {
			log_info("%02u ", event.header.pcr);
			log_dump(event.header.digest, SHA_DIGEST_LENGTH);
		}
		if (event.header.pcr >= NUM_PCRS) {
			log_err("Invalid PCR %d.\n", event.header.pcr);
			err = 1;
			break;
		}
		SHA1_Init(&c);
		SHA1_Update(&c, bank->pcr[event.header.pcr], 20);
		SHA1_Update(&c, event.header.digest, 20);
		SHA1_Final(bank->pcr[event.header.pcr], &c);
		if (event.header.len > MAX_EVENT_DATA_SIZE) {
			log_err("Event data event too long.\n");
			err = 1;
			break;
		}
		len = fread(event.data, event.header.len, 1, fp);
		if (len != 1) {
			log_errno("Failed reading event data (short read)\n");
			break;
		}
	}
	fclose(fp);

	if (imaevm_params.verbose <= LOG_INFO)
		return err;

	for (i = 0; i < NUM_PCRS; i++) {
		log_info("PCR-%2.2x ", i);
		log_dump(bank->pcr[i], SHA_DIGEST_LENGTH);

	}
	return err;
}

static void calc_bootaggr(struct tpm_bank_info *bank)
{
	EVP_MD_CTX *pctx;
	unsigned int mdlen;
	const EVP_MD *md;
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX ctx;
	pctx = &ctx;
#else
	pctx = EVP_MD_CTX_new();
#endif
	int err = 0;
	int i;

	md = EVP_get_digestbyname(bank->algo_name);

	err = EVP_DigestInit(pctx, md);
	if (!err) {
		printf("EVP_DigestInit() failed\n");
		goto out;
	}

	for (i = 0; i < 8;  i++) {
		err = EVP_DigestUpdate(pctx, bank->pcr[i], bank->digest_size);
		if (!err) {
			log_err("EVP_DigestUpdate() failed\n");
			goto out;
		}
	}

	if (strcmp(bank->algo_name, "sha1") != 0) {
		for (i = 8; i < 10; i++) {
			err = EVP_DigestUpdate(pctx, bank->pcr[i], bank->digest_size);
			if (!err) {
				log_err("EVP_DigestUpdate() failed\n");
				goto out;
			}
		}
	}

	err = EVP_DigestFinal(pctx, bank->digest, &mdlen);
	if (!err) {
		log_err("EVP_DigestFinal() failed\n");
		goto out;
	}

out:
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	EVP_MD_CTX_free(pctx);
#endif
	return;
}

/*
 * The "boot_aggregate" format is the TPM PCR bank algorithm, a colon
 * separator, followed by a per bank TPM PCR bank specific digest.
 * Store the TPM PCR bank specific "boot_aggregate" value as a newline
 * terminated string in the provided buffer.
 */
static int append_bootaggr(char *bootaggr, struct tpm_bank_info *tpm_banks)
{
	uint8_t *buf;
	int j;

	strcpy(bootaggr, tpm_banks->algo_name);
	j = strlen(tpm_banks->algo_name);
	bootaggr[j++] = ':';

	for (buf = tpm_banks->digest;
	     buf < (tpm_banks->digest + tpm_banks->digest_size);
	     buf++) {
		bootaggr[j++] = hex_asc_hi(*buf);
		bootaggr[j++] = hex_asc_lo(*buf);
	}

	bootaggr[j++] = '\n';
	return j;
}

/*
 * The IMA measurement list boot_aggregate is the link between the preboot
 * event log and the IMA measurement list.  Read and calculate all the
 * possible per TPM bank boot_aggregate digests based on the existing PCRs
 * 0 - 9 to validate against the IMA boot_aggregate record. If the digest
 * algorithm is SHA1, only PCRs 0 - 7 are considered to avoid ambiguity.
 */
static int cmd_ima_bootaggr(struct command *cmd)
{
	struct tpm_bank_info *tpm_banks;
	int bootaggr_len = 0;
	char *bootaggr;
	int num_banks = 0;
	int offset = 0;
	int err = 0;
	int i;

	char *file = g_argv[optind++];

	/*
	 * Instead of just reading the TPM 1.2 PCRs, walk the exported
	 * TPM 1.2 SHA1 event log, calculating the PCRs.
	 */
	if (file) {
		tpm_banks = init_tpm_banks(&num_banks);

		/* TPM 1.2 only supports SHA1.*/
		for (i = 1; i < num_banks; i++)
			tpm_banks[i].supported = 0;

		err = read_binary_bios_measurements(file, tpm_banks);
		if (err) {
			log_info("Failed reading the TPM 1.2 event log %s.\n",
				 file);
			return -1;
		}
	} else {
		tpm_banks = init_tpm_banks(&num_banks);
		if (read_tpm_banks(num_banks, tpm_banks) != 0) {
			log_info("Failed to read any TPM PCRs\n");
			return -1;
		}
	}

	/*
	 * Allocate enough memory for the per TPM 2.0 PCR bank algorithm,
	 * the colon separator, the boot_aggregate digest and newline.
	 *
	 * Format: <hash algorithm name>:<boot_aggregate digest>\n ...
	 */
	for (i = 0; i < num_banks; i++) {
		if (!tpm_banks[i].supported)
			continue;
		bootaggr_len += strlen(tpm_banks[i].algo_name) + 1;
		bootaggr_len += (tpm_banks[i].digest_size * 2) + 1;
	}
	/* Make room for the trailing null */
	bootaggr = malloc(bootaggr_len + 1);

	/*
	 * Calculate and convert the per TPM 2.0 PCR bank algorithm
	 * "boot_aggregate" digest from binary to asciihex.  Store the
	 * "boot_aggregate" values as a list of newline terminated
	 * strings.
	 */
	for (i = 0; i < num_banks; i++) {
		if (!tpm_banks[i].supported)
			continue;
		calc_bootaggr(&tpm_banks[i]);
		offset += append_bootaggr(bootaggr + offset, tpm_banks + i);
	}
	bootaggr[bootaggr_len] = '\0';
	printf("%s", bootaggr);
	free(bootaggr);
	return 0;
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
		"  -a, --hashalgo     sha1, sha224, sha256, sha384, sha512, streebog256, streebog512 (default: %s)\n"
		"  -s, --imasig       make IMA signature\n"
		"  -d, --imahash      make IMA hash\n"
		"  -f, --sigfile      store IMA signature in .sig file instead of xattr\n"
		"      --xattr-user   store xattrs in user namespace (for testing purposes)\n"
		"      --rsa          use RSA key type and signing scheme v1\n"
		"  -k, --key          path to signing key (default: /etc/keys/{privkey,pubkey}_evm.pem)\n"
		"                     or a pkcs11 URI\n"
		"      --keyid n      overwrite signature keyid with a 32-bit value in hex (for signing)\n"
		"      --keyid-from-cert file\n"
		"                     read keyid value from SKID of a x509 cert file\n"
		"  -o, --portable     generate portable EVM signatures\n"
		"  -p, --pass         password for encrypted signing key\n"
		"  -r, --recursive    recurse into directories (sign)\n"
		"  -t, --type         file types to fix 'fxm' (f: file)\n"
		"                     x - skip fixing if both ima and evm xattrs exist (use with caution)\n"
		"                     m - stay on the same filesystem (like 'find -xdev')\n"
		"  -n                 print result to stdout instead of setting xattr\n"
		"  -u, --uuid         use custom FS UUID for EVM (unspecified: from FS, empty: do not use)\n"
		"      --smack        use extra SMACK xattrs for EVM\n"
		"      --m32          force EVM hmac/signature for 32 bit target system\n"
		"      --m64          force EVM hmac/signature for 64 bit target system\n"
		"      --ino          use custom inode for EVM\n"
		"      --uid          use custom UID for EVM\n"
		"      --gid          use custom GID for EVM\n"
		"      --mode         use custom Mode for EVM\n"
		"      --generation   use custom Generation for EVM(unspecified: from FS, empty: use 0)\n"
		"      --ima          use custom IMA signature for EVM\n"
		"      --selinux      use custom Selinux label for EVM\n"
		"      --caps         use custom Capabilities for EVM(unspecified: from FS, empty: do not use)\n"
		"      --verify-sig   verify measurement list signatures\n"
		"      --engine e     preload OpenSSL engine e (such as: gost)\n"
		"      --ignore-violations ignore ToMToU measurement violations\n"
		"  -v                 increase verbosity level\n"
		"  -h, --help         display this help and exit\n"
		"\n"
		"Environment variables:\n\n"
		"EVMCTL_KEY_PASSWORD  : Private key password to use; do not use --pass option\n"
		"\n", DEFAULT_HASH_ALGO);
}

struct command cmds[] = {
	{"--version", NULL, 0, ""},
	{"help", cmd_help, 0, "<command>"},
	{"import", cmd_import, 0, "[--rsa] pubkey keyring", "Import public key into the keyring.\n"},
	{"convert", cmd_convert, 0, "key", "convert public key into the keyring.\n"},
	{"sign", cmd_sign_evm, 0, "[-r] [--imahash | --imasig ] [--key key] [--pass [password] file", "Sign file metadata.\n"},
	{"verify", cmd_verify_evm, 0, "file", "Verify EVM signature (for debugging).\n"},
	{"ima_sign", cmd_sign_ima, 0, "[--sigfile] [--key key] [--pass [password] file", "Make file content signature.\n"},
	{"ima_verify", cmd_verify_ima, 0, "file", "Verify IMA signature (for debugging).\n"},
	{"ima_setxattr", cmd_setxattr_ima, 0, "[--sigfile file]", "Set IMA signature from sigfile\n"},
	{"ima_hash", cmd_hash_ima, 0, "file", "Make file content hash.\n"},
	{"ima_measurement", cmd_ima_measurement, 0, "[--ignore-violations] [--verify-sig [--key key1, key2, ...]] [--pcrs [hash-algorithm,]file [--pcrs hash-algorithm,file] ...] [--verify-bank hash-algorithm] file", "Verify measurement list (experimental).\n"},
	{"ima_boot_aggregate", cmd_ima_bootaggr, 0, "[--pcrs hash-algorithm,file] [TPM 1.2 BIOS event log]", "Calculate per TPM bank boot_aggregate digests\n"},
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
	{"portable", 0, 0, 'o'},
	{"smack", 0, 0, 128},
	{"version", 0, 0, 129},
	{"inode", 1, 0, 130},
	{"uid", 1, 0, 131},
	{"gid", 1, 0, 132},
	{"mode", 1, 0, 133},
	{"generation", 1, 0, 134},
	{"ima", 1, 0, 135},
	{"selinux", 1, 0, 136},
	{"caps", 2, 0, 137},
	{"verify-sig", 0, 0, 138},
	{"engine", 1, 0, 139},
	{"xattr-user", 0, 0, 140},
	{"ignore-violations", 0, 0, 141},
	{"pcrs", 1, 0, 142},
	{"verify-bank", 2, 0, 143},
	{"keyid", 1, 0, 144},
	{"keyid-from-cert", 1, 0, 145},
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
		free(password);
		return NULL;
	}

	printf("PEM password: ");
	pwd = fgets(password, passlen, stdin);

	/* restore terminal */
	if (tcsetattr(fileno(stdin), TCSANOW, &flags) != 0) {
		perror("tcsetattr");
		free(password);
		return NULL;
	}

	if (pwd == NULL) {
		free(password);
		return NULL;
	}

	return password;
}

static ENGINE *setup_engine(const char *engine_id)
{
	ENGINE *eng = ENGINE_by_id(engine_id);
	if (!eng) {
		log_err("engine %s isn't available\n", optarg);
		ERR_print_errors_fp(stderr);
	} else if (!ENGINE_init(eng)) {
		log_err("engine %s init failed\n", optarg);
		ERR_print_errors_fp(stderr);
		ENGINE_free(eng);
		eng = NULL;
	}
	if (eng)
		ENGINE_set_default(eng, ENGINE_METHOD_ALL);
	return eng;
}

int main(int argc, char *argv[])
{
	int err = 0, c, lind;
	unsigned long keyid;
	char *eptr;

#if !(OPENSSL_VERSION_NUMBER < 0x10100000)
	OPENSSL_init_crypto(
#ifndef DISABLE_OPENSSL_CONF
			    OPENSSL_INIT_LOAD_CONFIG |
#endif
			    OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);
#endif
	g_argv = argv;
	g_argc = argc;

	while (1) {
		c = getopt_long(argc, argv, "hvnsda:op::fu::k:t:ri", opts, &lind);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			exit(0);
			break;
		case 'v':
			imaevm_params.verbose++;
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
			imaevm_params.hash_algo = optarg;
			break;
		case 'p':
			if (optarg)
				imaevm_params.keypass = optarg;
			else
				imaevm_params.keypass = get_password();
			break;
		case 'f':
			sigfile = 1;
			break;
		case 'u':
			uuid_str = optarg;
			if (!uuid_str)
				hmac_flags |= HMAC_FLAG_NO_UUID;
			break;
		case '1':
			imaevm_params.x509 = 0;
			break;
		case 'k':
			imaevm_params.keyfile = optarg;
			break;
		case 'i':
			if (evm_portable)
				log_err("Portable and immutable options are exclusive, ignoring immutable option.");
			else
				evm_immutable = true;
			break;
		case 'o':
			if (evm_immutable)
				log_err("Portable and immutable options are exclusive, ignoring portable option.");
			else
				evm_portable = true;
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
		case 128:
			evm_config_xattrnames = evm_extra_smack_xattrs;
			break;
		case 129:
			printf("evmctl %s\n", VERSION);
			exit(0);
			break;
		case 130:
			ino_str = optarg;
			break;
		case 131:
			uid_str = optarg;
			break;
		case 132:
			gid_str = optarg;
			break;
		case 133:
			mode_str = optarg;
			break;
		case 134:
			generation_str = optarg;
			break;
		case 135:
			ima_str = optarg;
			break;
		case 136:
			selinux_str = optarg;
			break;
		case 137:
			caps_str = optarg;
			hmac_flags |= HMAC_FLAG_CAPS_SET;
			break;
		case 138:
			verify_list_sig = 1;
			break;
		case 139: /* --engine e */
			imaevm_params.eng = setup_engine(optarg);
			if (!imaevm_params.eng)
				goto error;
			break;
		case 140: /* --xattr-user */
			xattr_ima = "user.ima";
			xattr_evm = "user.evm";
			break;
		case 141: /* --ignore-violations */
			ignore_violations = 1;
			break;
		case 142:
			if (npcrfile >= MAX_PCRFILE) {
				log_err("too many --pcrfile options\n");
				exit(1);
			}
			pcrfile[npcrfile++] = optarg;
			break;
		case 143:
			verify_bank = optarg;
			break;
		case 144:
			errno = 0;
			keyid = strtoul(optarg, &eptr, 16);
			/*
			 * ULONG_MAX is error from strtoul(3),
			 * UINT_MAX is `imaevm_params.keyid' maximum value,
			 * 0 is reserved for keyid being unset.
			 */
			if (errno || eptr - optarg != strlen(optarg) ||
			    keyid == ULONG_MAX || keyid > UINT_MAX ||
			    keyid == 0) {
				log_err("Invalid keyid value.\n");
				exit(1);
			}
			imaevm_params.keyid = keyid;
			break;
		case 145:
			keyid = imaevm_read_keyid(optarg);
			if (keyid == 0) {
				log_err("Error reading keyid.\n");
				exit(1);
			}
			imaevm_params.keyid = keyid;
			break;
		case '?':
			exit(1);
			break;
		default:
			log_err("getopt() returned: %d (%c)\n", c, c);
		}
	}

	if (!imaevm_params.keypass)
		imaevm_params.keypass = getenv("EVMCTL_KEY_PASSWORD");

	if (imaevm_params.keyfile != NULL &&
	    imaevm_params.eng == NULL &&
	    !strncmp(imaevm_params.keyfile, "pkcs11:", 7)) {
		imaevm_params.eng = setup_engine("pkcs11");
		if (!imaevm_params.eng)
			goto error;
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
		if (err < 0)
			err = 125;
	}

error:
	if (imaevm_params.eng) {
		ENGINE_finish(imaevm_params.eng);
		ENGINE_free(imaevm_params.eng);
#if OPENSSL_API_COMPAT < 0x10100000L
		ENGINE_cleanup();
#endif
	}
	ERR_free_strings();
	EVP_cleanup();
	BIO_free(NULL);
	return err;
}
