		if (setup_rerere(the_repository, &merge_rr,
		OPT_END(),
			if (merge_rr.items[i].util != RERERE_RESOLVED)
			       prefix, argv + 1);

				printf("%s\n", merge_rr.items[i].string);
	if (read_mmfile(&minus, file1) || read_mmfile(&plus, file2))
				/* prepare for later call to
	if (argc < 1)

			warning(_("'git rerere forget' without paths is deprecated"));

#include "builtin.h"
	string_list_clear(&merge_rr, 1);
	xdemitconf_t xecfg;
			printf("%s\n", merge_rr.items[i].string);
	fflush(stdout);
	printf("--- a/%s\n+++ b/%s\n", label1, label2);
#include "xdiff-interface.h"
		struct pathspec pathspec;
	} else
{
		rerere_remaining(the_repository, &merge_rr);
	mmfile_t minus, plus;
	struct option options[] = {
	return 0;
#include "rerere.h"
		flags = RERERE_AUTOUPDATE;
	NULL,
	} else if (!strcmp(argv[0], "diff")) {
		for (i = 0; i < merge_rr.nr; i++) {
	} else if (!strcmp(argv[0], "gc"))
	struct string_list merge_rr = STRING_LIST_INIT_DUP;
	free(minus.ptr);
	return 0;
	xdemitcb_t ecb;
				merge_rr.items[i].util = NULL;
	xpparam_t xpp;
	if (!strcmp(argv[0], "forget")) {
}
	ecb.out_hunk = NULL;
	free(plus.ptr);
{
		return rerere_forget(the_repository, &pathspec);
}
		return -1;
static int diff_two(const char *file1, const char *label1,
	memset(&xpp, 0, sizeof(xpp));
	ret = xdi_diff(&minus, &plus, &xpp, &xecfg, &ecb);
			return 0;
static int outf(void *dummy, mmbuffer_t *ptr, int nbuf)


#include "pathspec.h"
		if (setup_rerere(the_repository, &merge_rr,


#include "cache.h"

};
int cmd_rerere(int argc, const char **argv, const char *prefix)
		const char *file2, const char *label2)
		usage_with_options(rerere_usage, options);

		for (i = 0; i < merge_rr.nr; i++)
	xpp.flags = 0;
	ecb.out_line = outf;
#include "parse-options.h"
#include "dir.h"
	for (i = 0; i < nbuf; i++)
		OPT_SET_INT(0, "rerere-autoupdate", &autoupdate,
	N_("git rerere [clear | forget <path>... | status | remaining | diff | gc]"),
			else
#include "xdiff/xdiff.h"
	git_config(git_xmerge_config, NULL);



		for (i = 0; i < merge_rr.nr; i++) {
		return repo_rerere(the_repository, flags);
	int i;
{
	};
	xecfg.ctxlen = 3;
				die(_("unable to generate diff for '%s'"), rerere_path(id, NULL));
		if (argc < 2)
	int i, autoupdate = -1, flags = 0;
static const char * const rerere_usage[] = {
	if (!strcmp(argv[0], "clear")) {
	memset(&xecfg, 0, sizeof(xecfg));
	return ret;
#include "string-list.h"
	int ret;


		flags = RERERE_NOAUTOUPDATE;
			const char *path = merge_rr.items[i].string;
		rerere_clear(the_repository, &merge_rr);
#include "config.h"
	if (autoupdate == 0)
			return -1;
		rerere_gc(the_repository, &merge_rr);
	if (autoupdate == 1)
		if (write_in_full(1, ptr[i].ptr, ptr[i].size) < 0)
			if (diff_two(rerere_path(id, "preimage"), path, path, path))
			N_("register clean resolutions in index"), 1),
	argc = parse_options(argc, argv, prefix, options, rerere_usage, 0);
				 flags | RERERE_READONLY) < 0)

		}
	} else if (!strcmp(argv[0], "remaining")) {
	}
				 flags | RERERE_READONLY) < 0)
	else if (!strcmp(argv[0], "status")) {
		}
				 * string_list_clear() */
}
			const struct rerere_id *id = merge_rr.items[i].util;
		parse_pathspec(&pathspec, 0, PATHSPEC_PREFER_CWD,
			return 0;
