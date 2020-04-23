		return 1;
	count = argc > 1 ? strtol(argv[1], NULL, 0) : -1L;

int cmd__genzeros(int argc, const char **argv)
	long count;


#include "test-tool.h"


		fprintf(stderr, "usage: %s [<count>]\n", argv[0]);
		if (putchar(0) == EOF)
	}
}
	if (argc > 2) {
{
	return 0;
#include "git-compat-util.h"
	}
			return -1;
	while (count < 0 || count--) {
