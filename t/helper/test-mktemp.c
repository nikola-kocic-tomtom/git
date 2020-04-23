
	if (argc != 2)
int cmd__mktemp(int argc, const char **argv)
}
#include "git-compat-util.h"
	xmkstemp(xstrdup(argv[1]));
 * test-mktemp.c: code to exercise the creation of temporary files

{
#include "test-tool.h"
/*
 */

	return 0;
		usage("Expected 1 parameter defining the temporary file template");
