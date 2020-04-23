		    buffer_is_binary(mmfs[i].ptr, mmfs[i].size))
	int quiet = 0;
	const char *names[3] = { NULL, NULL, NULL };
	for (i = 0; i < 3; i++) {
	xmp.file1 = names[0];
			ret = error_errno("Could not open %s for writing",
		char *fpath = prefix_filename(prefix, argv[0]);
{
}

	xmp.style = 0;
}
		/* Read the configuration file */
			return error_errno("failed to redirect stderr to /dev/null");
	}
					  filename);

		int ret;
			     N_("set labels for file1/orig-file/file2"), &label_cb),
			    XDL_MERGE_FAVOR_OURS),
		else if (result.size &&
			ret = error_errno("Could not write to %s", filename);
	return ret;
	if (argc != 3)
#include "config.h"
	xmp.ancestor = names[1];
	xmp.level = XDL_MERGE_ZEALOUS_ALNUM;
	NULL
			return -1;
	if (startup_info->have_repository) {
	names[label_count++] = arg;

			return error("Cannot merge binary files: %s",
			xmp.style = git_xmerge_style;
	mmbuffer_t result = {NULL, 0};
#include "parse-options.h"
		OPT_INTEGER(0, "marker-size", &xmp.marker_size,
		const char *filename = argv[0];
		if (0 <= git_xmerge_style)
	if (label_count >= 3)
		free(result.ptr);
	static int label_count = 0;
	for (i = 0; i < 3; i++)
			    XDL_MERGE_FAVOR_UNION),
	const char **names = (const char **)opt->value;
		OPT_BOOL('p', "stdout", &to_stdout, N_("send results to standard output")),
{
	mmfile_t mmfs[3];

		OPT_SET_INT(0, "union", &xmp.favor, N_("for conflicts, use a union version"),
	return 0;

			    N_("for conflicts, use this marker size")),

#include "cache.h"
	if (ret >= 0) {



		FILE *f = to_stdout ? stdout : fopen(fpath, "wb");
};
	ret = xdl_merge(mmfs + 1, mmfs + 0, mmfs + 2, &xmp, &result);
		OPT_CALLBACK('L', NULL, names, N_("name"),
			    XDL_MERGE_FAVOR_THEIRS),

			names[i] = argv[i];
		fname = prefix_filename(prefix, argv[i]);

	BUG_ON_OPT_NEG(unset);
		return error("too many labels on the command line");

		if (mmfs[i].size > MAX_XDIFF_SIZE ||
#include "xdiff/xdiff.h"
	xmparam_t xmp = {{0}};
		git_config(git_xmerge_config, NULL);
	N_("git merge-file [<options>] [-L <name1> [-L <orig> [-L <name2>]]] <file1> <orig-file> <file2>"),
		if (ret)

		if (!f)
	argc = parse_options(argc, argv, prefix, options, merge_file_usage, 0);

int cmd_merge_file(int argc, const char **argv, const char *prefix)
static int label_cb(const struct option *opt, const char *arg, int unset)
	if (quiet) {
		ret = read_mmfile(mmfs + i, fname);

	xmp.favor = 0;
	}
		else if (fclose(f))
static const char *const merge_file_usage[] = {

	}
		ret = 127;
		OPT_END(),
		OPT_SET_INT(0, "diff3", &xmp.style, N_("use a diff3 based merge"), XDL_MERGE_DIFF3),
		OPT_SET_INT(0, "ours", &xmp.favor, N_("for conflicts, use our version"),
	struct option options[] = {
			ret = error_errno("Could not close %s", filename);
		OPT_SET_INT(0, "theirs", &xmp.favor, N_("for conflicts, use their version"),
		if (!freopen("/dev/null", "w", stderr))

		if (!names[i])
		usage_with_options(merge_file_usage, options);
		free(fpath);
	}
		char *fname;
	xmp.file2 = names[2];
		free(mmfs[i].ptr);
			 fwrite(result.ptr, result.size, 1, f) != 1)
		OPT__QUIET(&quiet, N_("do not warn about conflicts")),
#include "xdiff-interface.h"
	};

					argv[i]);
		free(fname);
	if (ret > 127)
#include "builtin.h"
	int ret = 0, i = 0, to_stdout = 0;
