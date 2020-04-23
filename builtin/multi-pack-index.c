		return midx_repack(the_repository, opts.object_dir,
#include "config.h"
		  N_("during repack, collect pack-files of smaller size into a batch that is larger than this size")),
		opts.object_dir = get_object_directory();

		return verify_midx_file(the_repository, opts.object_dir, flags);

		flags |= MIDX_PROGRESS;
	}
		OPT_MAGNITUDE(0, "batch-size", &opts.batch_size,
#include "midx.h"
		return expire_midx_packs(the_repository, opts.object_dir, flags);
		die(_("--batch-size option is only for 'repack' subcommand"));
	unsigned long batch_size;
		usage_with_options(builtin_multi_pack_index_usage,
} opts;
	const char *object_dir;


}
};
				   builtin_multi_pack_index_options);
int cmd_multi_pack_index(int argc, const char **argv,
	static struct option builtin_multi_pack_index_options[] = {
			     builtin_multi_pack_index_options,
	if (!strcmp(argv[0], "verify"))

		return write_midx_file(opts.object_dir, flags);
	die(_("unrecognized subcommand: %s"), argv[0]);
		OPT_BOOL(0, "progress", &opts.progress, N_("force progress reporting")),
		OPT_END(),
			(size_t)opts.batch_size, flags);

	git_config(git_default_config, NULL);
	if (argc == 0)
		die(_("too many arguments"));
		return 1;
			     builtin_multi_pack_index_usage, 0);
			 const char *prefix)
		OPT_FILENAME(0, "object-dir", &opts.object_dir,
	NULL
	if (opts.progress)
	if (argc > 1) {
#include "cache.h"
	argc = parse_options(argc, argv, prefix,
	trace2_cmd_mode(argv[0]);
	N_("git multi-pack-index [<options>] (write|verify|expire|repack --batch-size=<size>)"),

#include "parse-options.h"
	if (!opts.object_dir)
	if (!strcmp(argv[0], "expire"))


	if (!strcmp(argv[0], "repack"))

	};
#include "builtin.h"

#include "trace2.h"


static struct opts_multi_pack_index {
		  N_("object directory containing set of packfile and pack-index pairs")),
	opts.progress = isatty(2);
	if (opts.batch_size)
{
static char const * const builtin_multi_pack_index_usage[] = {
	int progress;
	unsigned flags = 0;
	if (!strcmp(argv[0], "write"))
