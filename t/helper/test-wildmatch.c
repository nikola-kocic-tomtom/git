		if (argv[i][0] == '/')
	else
	else if (!strcmp(argv[1], "ipathmatch"))
#include "test-tool.h"
	else if (!strcmp(argv[1], "iwildmatch"))
	int i;
		else if (!strncmp(argv[i], "XXX/", 4))
#include "cache.h"
		return 1;
	for (i = 2; i < argc; i++) {
	else if (!strcmp(argv[1], "pathmatch"))
}
		return !!wildmatch(argv[3], argv[2], WM_PATHNAME | WM_CASEFOLD);
int cmd__wildmatch(int argc, const char **argv)
		return !!wildmatch(argv[3], argv[2], WM_PATHNAME);
			    "pattern because Windows does not like it. Use `XXX/' instead.");
{
		return !!wildmatch(argv[3], argv[2], 0);
		return !!wildmatch(argv[3], argv[2], WM_CASEFOLD);
			argv[i] += 3;
			die("Forward slash is not allowed at the beginning of the\n"
	}
	if (!strcmp(argv[1], "wildmatch"))

