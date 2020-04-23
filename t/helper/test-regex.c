		die("failed regcomp() for pattern '%s'", pat);

static int test_regex_bug(void)
	char *pat = "[^={} \t]+";
	if (regcomp(&r, pat, flags))
				break;
	{ "NOTBOL",	 REG_NOTBOL	},
	char *str = "={}\nfred";
	if (regexec(&r, str, 1, m, 0))
		usage("test-tool regex --bug\n"
	{ "STARTEND",	 REG_STARTEND	},
		die("failed regcomp() for pattern '%s'", pat);
	}
#endif
	const char *str;
{

	/* http://sourceware.org/bugzilla/show_bug.cgi?id=3957  */
	{ "EXTENDED",	 REG_EXTENDED	},
		argv++;
				flags |= rf->flag;

		die("regex bug confirmed: re-build git with NO_REGEX=1");

			}
	regmatch_t m[1];
};
		      "test-tool regex <pattern> <string> [<options>]");
#include "test-tool.h"
	pat = *argv++;
			die("do not recognize %s", *argv);
	regex_t r;

			if (!strcmp(*argv, rf->name)) {

#include "git-compat-util.h"
	const char *name;
	const char *pat;
	regmatch_t m[1];
		struct reg_flag *rf;
		for (rf = reg_flags; rf->name; rf++)

	int flags = 0;
{
#include "gettext.h"
static struct reg_flag reg_flags[] = {
	while (*argv) {
	return 0;
	regex_t r;
	{ "ICASE",	 REG_ICASE	},
	int flag;
	argv++;
		return 1;
		return test_regex_bug();
	git_setup_gettext();
}

		if (!rf->name)
	else if (argc < 3)
int cmd__regex(int argc, const char **argv)
struct reg_flag {
	if (regcomp(&r, pat, REG_EXTENDED | REG_NEWLINE))

}
	if (m[0].rm_so == 3) /* matches '\n' when it should not */
};
	if (argc == 2 && !strcmp(argv[1], "--bug"))
	{ "NEWLINE",	 REG_NEWLINE	},
	if (regexec(&r, str, 1, m, 0))

#ifdef REG_STARTEND

	str = *argv++;
	{ NULL, 0 }
		die("no match of pattern '%s' to string '%s'", pat, str);
	return 0;
