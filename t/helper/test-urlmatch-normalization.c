		argv++;
	 * For one url, succeed if url_normalize succeeds on it, fail otherwise.
	return (url1 && url2 && !strcmp(url1, url2)) ? 0 : 1;
	 * and url_normalize succeeds, print the result followed by "\n".  If
int cmd__urlmatch_normalization(int argc, const char **argv)
			return 1;
	if (argc == 2) {
	}

	if (opt_p || opt_l)
		if (!url1)
#include "test-tool.h"
		struct url_info info;
		die("%s", usage);
	url2 = url_normalize(argv[2], NULL);
		return 0;
	 * -l is given (one url only) and url_normalize succeeds, print the
		if (opt_l)
#include "urlmatch.h"

	url1 = url_normalize(argv[1], NULL);
		if (opt_p)

	/*


	}
	 * returned length in decimal followed by "\n".
	 */
	char *url1, *url2;
{
		url1 = url_normalize(argv[1], &info);
	 * the results compare equal with strcmp.  If -p is given (one url only)

	int opt_p = 0, opt_l = 0;
}
			printf("%u\n", (unsigned)info.url_len);
	} else if (argc > 1 && !strcmp(argv[1], "-l")) {
		die("%s", usage);
		opt_l = 1;
		argv++;
	if (argc < 2 || argc > 3)
			printf("%s\n", url1);

	if (argc > 1 && !strcmp(argv[1], "-p")) {
		argc--;
#include "git-compat-util.h"
	 * For two urls, succeed only if url_normalize succeeds on both and
		argc--;
		opt_p = 1;
	const char usage[] = "test-tool urlmatch-normalization [-p | -l] <url1> | <url1> <url2>";
