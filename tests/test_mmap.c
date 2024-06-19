// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Tool to test IMA MMAP_CHECK and MMAP_CHECK_REQPROT hooks.
 */
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/personality.h>

/*
 * Convention: return 1 for errors that should not occur, as they are
 * setup-related, return 2 for errors that might occur due to testing
 * conditions.
 */
#define ERR_SETUP 1
#define ERR_TEST 2

int main(int argc, char *argv[])
{
	struct stat st;
	void *ptr, *ptr_write = NULL;
	int ret, fd, fd_write, prot = PROT_READ;

	if (!argv[1]) {
		printf("Missing file parameter\n");
		return ERR_SETUP;
	}

	if (argv[2] && !strcmp(argv[2], "read_implies_exec")) {
		ret = personality(READ_IMPLIES_EXEC);
		if (ret == -1) {
			printf("Failed to set personality, err: %d (%s)\n",
			       -errno, strerror(errno));
			return ERR_SETUP;
		}
	}

	if (stat(argv[1], &st) == -1) {
		printf("Failed to access %s, err: %d (%s)\n", argv[1], -errno,
		       strerror(errno));
		return ERR_SETUP;
	}

	if (argv[2] && !strcmp(argv[2], "exec_on_writable")) {
		fd_write = open(argv[1], O_RDWR);
		if (fd_write == -1) {
			printf("Failed to open %s in r/w, err: %d (%s)\n",
			       argv[1], -errno, strerror(errno));
			return ERR_SETUP;
		}

		ptr_write = mmap(0, st.st_size, PROT_WRITE, MAP_SHARED,
				 fd_write, 0);
		close(fd_write);

		if (ptr_write == MAP_FAILED) {
			printf("Failed mmap() with PROT_WRITE on %s, err: %d (%s)\n",
			       argv[1], -errno, strerror(errno));
			return ERR_SETUP;
		}
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		printf("Failed to open %s in ro, err: %d (%s)\n", argv[1],
		       -errno, strerror(errno));

		if (ptr_write && munmap(ptr_write, st.st_size) == -1)
			printf("Failed munmap() of writable mapping on %s, err: %d (%s)\n",
			       argv[1], -errno, strerror(errno));

		return ERR_SETUP;
	}

	if (argv[2] && !strncmp(argv[2], "exec", 4))
		prot |= PROT_EXEC;

	ptr = mmap(0, st.st_size, prot, MAP_PRIVATE, fd, 0);

	close(fd);

	if (ptr_write && munmap(ptr_write, st.st_size) == -1) {
		printf("Failed munmap() of writable mapping on %s, err: %d (%s)\n",
		       argv[1], -errno, strerror(errno));
		return ERR_SETUP;
	}

	if (ptr == MAP_FAILED) {
		ret = ERR_SETUP;
		if (argv[2] && !strcmp(argv[2], "exec_on_writable") &&
		    errno == EACCES)
			ret = ERR_TEST;
		else
			printf("Failed mmap() with PROT_READ%s on %s, err: %d (%s)\n",
			       (prot & PROT_EXEC) ? " | PROT_EXEC" : "",
			       argv[1], -errno, strerror(errno));

		return ret;
	}

	ret = 0;

	if (argv[2] && !strcmp(argv[2], "mprotect")) {
		ret = mprotect(ptr, st.st_size, PROT_EXEC);
		if (ret == -1) {
			ret = ERR_SETUP;
			if (errno == EPERM)
				ret = ERR_TEST;
			else
				printf("Unexpected mprotect() error on %s, err: %d (%s)\n",
				       argv[1], -errno, strerror(errno));
		}
	}

	if (munmap(ptr, st.st_size) == -1) {
		printf("Failed munmap() of mapping on %s, err: %d (%s)\n",
		       argv[1], -errno, strerror(errno));
		return ERR_SETUP;
	}

	return ret;
}
