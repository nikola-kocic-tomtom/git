		die_errno("git get-tar-commit-id: EOF before reading tar header");
		die_errno("git get-tar-commit-id: read error");
/* ustar header + extended global header content */
	return 0;
 * Copyright (c) 2005, 2006 Rene Scharfe
	struct ustar_header *header = (struct ustar_header *)buffer;
		return 1;
	if (n < 0)
	n = read_in_full(0, buffer, HEADERSIZE);
		return 1;
#define RECORDSIZE	(512)
 */

#include "tar.h"
#include "builtin.h"
	char *content = buffer + RECORDSIZE;
#include "commit.h"
	    hash_algo_by_length((len - 1) / 2) == GIT_HASH_UNKNOWN)

	const char *comment;
#include "quote.h"
/*
	len = strtol(content, &end, 10);
	if (header->typeflag[0] != 'g')
		return 1;

	len -= comment - content;
	ssize_t n;
{
static const char builtin_get_tar_commit_id_usage[] =

		usage(builtin_get_tar_commit_id_usage);
}
	if (argc != 1)


		die_errno("git get-tar-commit-id: write error");
	if (n != HEADERSIZE)
	long len;
	char *end;

	if (write_in_full(1, comment, len) < 0)
int cmd_get_tar_commit_id(int argc, const char **argv, const char *prefix)
	char buffer[HEADERSIZE];
		return 1;
	if (errno == ERANGE || end == content || len < 0)
#define HEADERSIZE (2 * RECORDSIZE)

	if (!skip_prefix(end, " comment=", &comment))
#include "cache.h"
	if (len < 1 || !(len % 2) ||
"git get-tar-commit-id";
