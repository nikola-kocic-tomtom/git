	argc = parse_options(argc, argv, prefix, prune_packed_options,
#include "parse-options.h"
int cmd_prune_packed(int argc, const char **argv, const char *prefix)


	return 0;

#include "packfile.h"
#include "progress.h"
#include "builtin.h"
	N_("git prune-packed [-n | --dry-run] [-q | --quiet]"),
static struct progress *progress;
		OPT_END()

}

	display_progress(progress, nr + 1);
	NULL
	/* Ensure we show 100% before finishing progress */
	int *opts = data;
	display_progress(progress, 256);
{
	if (!has_object_pack(oid))

	else
}
}
		unlink_or_warn(path);
		printf("rm -f %s\n", path);
	if (*opts & PRUNE_PACKED_DRY_RUN)
{
			PRUNE_PACKED_DRY_RUN),
void prune_packed_objects(int opts)
		return 0;
		progress = start_delayed_progress(_("Removing duplicate objects"), 256);

	prune_packed_objects(opts);
	const struct option prune_packed_options[] = {
		OPT_BIT('n', "dry-run", &opts, N_("dry run"),
		OPT_NEGBIT('q', "quiet", &opts, N_("be quiet"),
			   PRUNE_PACKED_VERBOSE),
		rmdir(path);
};

			     prune_packed_usage, 0);
			      prune_packed_usage,

#include "cache.h"
static int prune_object(const struct object_id *oid, const char *path,
{
}
	if (opts & PRUNE_PACKED_VERBOSE)
			      prune_packed_options);
		usage_msg_opt(_("too many arguments"),

#include "object-store.h"
	int opts = isatty(2) ? PRUNE_PACKED_VERBOSE : 0;
{
	return 0;
	if (!(*opts & PRUNE_PACKED_DRY_RUN))
	if (argc > 0)

static const char * const prune_packed_usage[] = {
	int *opts = data;
			 void *data)
				      prune_object, NULL, prune_subdir, &opts);
	return 0;
	stop_progress(&progress);


	};
	for_each_loose_file_in_objdir(get_object_directory(),
static int prune_subdir(unsigned int nr, const char *path, void *data)
