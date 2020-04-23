NULL
			    N_("use simple diff colors")),
	argv_array_clear(&other_arg);
			usage_with_options(builtin_range_diff_usage, options);
		strbuf_addstr(&range2, argv[1]);
	struct strbuf range1 = STRBUF_INIT, range2 = STRBUF_INIT;
		if (!*b)
}
		strbuf_addf(&range1, "%s..%.*s", b, a_len, a);
		error(_("need two commit ranges"));
				  PARSE_OPT_OPTARG),
			die(_("no .. in range: '%s'"), argv[1]);


#include "cache.h"
	repo_diff_setup(the_repository, &diffopt);
	res = show_range_diff(range1.buf, range2.buf, creation_factor,
		if (!b) {
		strbuf_addf(&range1, "%s..%s", argv[0], argv[1]);
	git_config(git_diff_ui_config, NULL);
N_("git range-diff [<options>] <base> <old-tip> <new-tip>"),
	} else if (argc == 1) {
	struct argv_array other_arg = ARGV_ARRAY_INIT;
};


	strbuf_release(&range2);
		strbuf_addf(&range2, "%.*s..%s", a_len, a, b);
	int simple_color = -1;
			    N_("Percentage by which creation is weighted")),
#include "parse-options.h"
	struct option range_diff_options[] = {
	};
		OPT_PASSTHRU_ARGV(0, "notes", &other_arg,
	options = parse_options_concat(range_diff_options, diffopt.parseopts);

		if (!strstr(argv[1], ".."))
		if (!strstr(argv[0], ".."))


		}
		OPT_BOOL(0, "no-dual-color", &simple_color,
	diff_setup_done(&diffopt);
	}
{

			a_len = strlen(a);
		strbuf_addstr(&range1, argv[0]);
	if (!simple_color)
#include "builtin.h"
			die(_("no .. in range: '%s'"), argv[0]);
		OPT_INTEGER(0, "creation-factor", &creation_factor,
			     builtin_range_diff_usage, 0);

			      simple_color < 1, &diffopt, &other_arg);
	int res = 0;

static const char * const builtin_range_diff_usage[] = {
			error(_("single arg format must be symmetric range"));
		if (!a_len) {
				  N_("notes"), N_("passed to 'git log'"),
		b += 3;
		usage_with_options(builtin_range_diff_usage, options);
			a = "HEAD";
	argc = parse_options(argc, argv, prefix, options,
		const char *b = strstr(argv[0], "..."), *a = argv[0];

	/* force color when --dual-color was used */
			b = "HEAD";
int cmd_range_diff(int argc, const char **argv, const char *prefix)
	strbuf_release(&range1);
#include "config.h"
		}
#include "range-diff.h"
		a_len = (int)(b - a);
	return res;
N_("git range-diff [<options>] <old-base>..<old-tip> <new-base>..<new-tip>"),

		int a_len;
	} else {
	struct diff_options diffopt = { NULL };
	struct option *options;
		diffopt.use_color = 1;
	int creation_factor = RANGE_DIFF_CREATION_FACTOR_DEFAULT;
	} else if (argc == 3) {
	if (argc == 2) {
		OPT_END()
		strbuf_addf(&range2, "%s..%s", argv[0], argv[2]);
	FREE_AND_NULL(options);

N_("git range-diff [<options>] <old-tip>...<new-tip>"),

