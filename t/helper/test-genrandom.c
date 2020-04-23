 * This is inspired from POSIX.1-2001 implementation example for rand().
 * Copyright (C) 2007 by Nicolas Pitre, licensed under the GPL version 2.
	count = (argc == 3) ? strtoul(argv[2], NULL, 0) : -1L;
{
		if (putchar((next >> 16) & 0xff) == EOF)

		next = next * 11 + *c;

	return 0;
 * Simple random data generator used to create reproducible test files.
/*

 */
	}
	do {
	c = (unsigned char *) argv[1];
#include "test-tool.h"
	unsigned char *c;
#include "git-compat-util.h"
	while (count--) {

	unsigned long count, next = 0;
		fprintf(stderr, "usage: %s <seed_string> [<size>]\n", argv[0]);

			return -1;
	}
	} while (*c++);
}
		return 1;
		next = next * 1103515245 + 12345;


int cmd__genrandom(int argc, const char **argv)
	if (argc < 2 || argc > 3) {
