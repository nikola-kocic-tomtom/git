		if (strcmp(*argv, "--follow-symlinks") == 0)
		else if (strcmp(*argv, "--pedantic") == 0)
	while ((iter_status = dir_iterator_advance(diter)) == ITER_OK) {
	case ENOTDIR: return "ENOTDIR";
		else if (S_ISREG(diter->st.st_mode))
	unsigned int flags = 0;
	}
{
 */
	if (!*argv || argc != 1)
	}
#include "dir-iterator.h"
			printf("[f] ");
		printf("(%s) [%s] %s\n", diter->relative_path, diter->basename,
static const char *error_name(int error_number)
	}
/*
	for (++argv, --argc; *argv && starts_with(*argv, "--"); ++argv, --argc) {
	}
}
		else if (S_ISLNK(diter->st.st_mode))
			flags |= DIR_ITERATOR_FOLLOW_SYMLINKS;
#include "test-tool.h"
		printf("dir_iterator_advance failure\n");

	default: return "ESOMETHINGELSE";
		return 1;
#include "iterator.h"


#include "git-compat-util.h"
			printf("[?] ");
		exit(EXIT_FAILURE);
int cmd__dir_iterator(int argc, const char **argv)
			printf("[d] ");

	switch (error_number) {
		else

	if (!diter) {
	struct dir_iterator *diter;
	int iter_status;


		die("dir-iterator needs exactly one non-option argument");

	if (iter_status != ITER_DONE) {
	}
			die("invalid option '%s'", *argv);
			flags |= DIR_ITERATOR_PEDANTIC;
{
	case ENOENT: return "ENOENT";
		printf("dir_iterator_begin failure: %s\n", error_name(errno));
		else
	return 0;
		if (S_ISDIR(diter->st.st_mode))
 * usage:
 * tool-test dir-iterator [--follow-symlinks] [--pedantic] directory_path
		       diter->path.buf);
			printf("[s] ");
	diter = dir_iterator_begin(*argv, flags);
}

#include "strbuf.h"

