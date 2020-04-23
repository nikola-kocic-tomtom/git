	if (fd < 0 || fstat(fd, &st)) {
		return 1;
		perror(argv[3]);
				      data_buf, data_size,

	data_size = st.st_size;
 * published by the Free Software Foundation.
		close(fd);
				     data_buf, data_size,
 */
				     &out_size, 0);
 * This code is free software; you can redistribute it and/or modify
	if (fd < 0 || fstat(fd, &st)) {
 * test-delta.c: test code to exercise diff-delta.c and patch-delta.c
int cmd__delta(int argc, const char **argv)
		perror(argv[2]);
	if (read_in_full(fd, data_buf, data_size) < 0) {
	}
	return 0;
#include "git-compat-util.h"
	fd = open (argv[4], O_WRONLY|O_CREAT|O_TRUNC, 0666);

	}
 * it under the terms of the GNU General Public License version 2 as
	unsigned long from_size, data_size, out_size;
#include "delta.h"
	}
		return 1;
#include "test-tool.h"
		perror(argv[2]);

	if (fd < 0 || write_in_full(fd, out_buf, out_size) < 0) {
	"test-tool delta (-d|-p) <from_file> <data_file> <out_file>";
	if (!out_buf) {
	}

				      &out_size);
	fd = open(argv[2], O_RDONLY);
	if (read_in_full(fd, from_buf, from_size) < 0) {
	}
	}
		return 1;
/*
 *
		out_buf = patch_delta(from_buf, from_size,
	from_size = st.st_size;
		return 1;
		return 1;
	fd = open(argv[3], O_RDONLY);
}
{
	}
	else
		return 1;
static const char usage_str[] =
	void *from_buf, *data_buf, *out_buf;
		close(fd);
 *



		perror(argv[4]);
	if (argv[1][1] == 'd')
#include "cache.h"
	close(fd);
	data_buf = xmalloc(data_size);
	struct stat st;
		fprintf(stderr, "usage: %s\n", usage_str);
	if (argc != 5 || (strcmp(argv[1], "-d") && strcmp(argv[1], "-p"))) {
	from_buf = xmalloc(from_size);
		perror(argv[3]);
		fprintf(stderr, "delta operation failed (returned NULL)\n");
	close(fd);
		return 1;
	int fd;

		out_buf = diff_delta(from_buf, from_size,

 * (C) 2005 Nicolas Pitre <nico@fluxnic.net>
