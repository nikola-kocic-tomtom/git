		show_progress = isatty(2);
{
	if (!show_only)
		fprintf(stderr, "Unable to open directory %s\n", path);
	if (show_only || verbose) {
}
	initialized = 1;
	struct stat st;
	if (!show_only)
{
	if (repository_format_precious_objects)

#include "parse-options.h"

	return obj && (obj->flags & SEEN);
	read_replace_refs = 0;
	if (show_progress == -1)
 * files beginning with "tmp_") accumulating in the object
{
		unlink_or_warn(fullpath);
		OPT__DRY_RUN(&show_only, N_("do not remove, show only")),
	argc = parse_options(argc, argv, prefix, options, prune_usage, 0);
	struct progress *progress = NULL;
	if (initialized)
	return 0;
static int prune_cruft(const char *basename, const char *path, void *data)
		return 0;
	const struct option options[] = {
#include "diff.h"
	save_commit_buffer = 0;
		if (starts_with(de->d_name, "tmp_"))
	struct rev_info revs;
		prune_tmp_file(path);
	prune_packed_objects(show_only ? PRUNE_PACKED_DRY_RUN : 0);
 * and the pack directories.
		return;
		perform_reachability_traversal(&revs);
}
	N_("git prune [-n] [-v] [--progress] [--expire <time>] [--] [<head>...]"),
			die("unrecognized argument: %s", name);
#include "revision.h"





{
}
		enum object_type type = oid_object_info(the_repository, oid,
	expire = TIME_MAX;
static void perform_reachability_traversal(struct rev_info *revs)
	}

		return 0;
		       (type > 0) ? type_name(type) : "unknown");
	if (show_only || verbose)
	ref_paranoia = 1;

	while ((de = readdir(dir)) != NULL)
			 N_("limit traversal to objects outside promisor packfiles")),
{
		error("Could not stat '%s'", fullpath);
			void *data)
 * failed temporary packs (and more rarely indexes and other
	struct stat st;
		OPT__VERBOSE(&verbose, N_("report pruned objects")),
/*
		return;
	if (lstat(fullpath, &st))

	perform_reachability_traversal(revs);
	}
		fprintf(stderr, "bad sha1 file: %s\n", path);
static int prune_subdir(unsigned int nr, const char *path, void *data)
		printf("%s %s\n", oid_to_hex(oid),
 * Write errors (particularly out of space) can result in
		return 0;
	DIR *dir;
		fetch_if_missing = 0;
#include "reachable.h"
		return 0;
			       struct rev_info *revs)

				N_("expire objects older than <time>")),
};
	mark_reachable_objects(revs, 1, expire, progress);
	if (!dir) {
	struct rev_info *revs = data;
		struct object_id oid;
 */
	remove_temporary_files(get_object_directory());
				      prune_cruft, prune_subdir, &revs);
		if (!get_oid(name, &oid)) {
		else
static int verbose;
int cmd_prune(int argc, const char **argv, const char *prefix)
}
		}

	}

		OPT_BOOL(0, "progress", &show_progress, N_("show progress")),
	dir = opendir(path);
	if (!show_only)
		return error("Could not stat '%s'", fullpath);
static int prune_tmp_file(const char *fullpath)

	while (argc--) {

							NULL);
	obj = lookup_object(the_repository, oid);
	if (lstat(fullpath, &st)) {

	if (show_progress)
}
static timestamp_t expire;

#include "cache.h"
	return 0;
	if (is_repository_shallow(the_repository)) {
		die(_("cannot prune in a precious-objects repo"));
{
	stop_progress(&progress);
static int prune_object(const struct object_id *oid, const char *fullpath,
		/* report errors, but do not stop pruning */

#include "progress.h"
	char *s;
		printf("Removing stale temporary file %s\n", fullpath);
	}
	return 0;


#include "commit.h"
	if (st.st_mtime > expire)
static int is_object_reachable(const struct object_id *oid,
	repo_init_revisions(the_repository, &revs, prefix);
	closedir(dir);
	}

	struct object *obj;
static const char * const prune_usage[] = {
	if (exclude_promisor_objects) {
								    name);
		const char *name = *argv++;
	if (is_object_reachable(oid, revs))
	static int initialized;
		progress = start_delayed_progress(_("Checking connectivity"), 0);
		unlink_or_warn(fullpath);
}
{

static int show_progress = -1;
	remove_temporary_files(s);
#include "builtin.h"
		OPT_EXPIRY_DATE(0, "expire", &expire,
		OPT_BOOL(0, "exclude-promisor-objects", &exclude_promisor_objects,

static void remove_temporary_files(const char *path)
		rmdir(path);

static int show_only;
	struct dirent *de;
}
	};
{
	int exclude_promisor_objects = 0;
	NULL
			add_pending_object(&revs, object, "");
	for_each_loose_file_in_objdir(get_object_directory(), prune_object,
#include "object-store.h"

		OPT_END()
	if (st.st_mtime > expire)
	else

		prune_shallow(show_only ? PRUNE_SHOW_ONLY : 0);
	return 0;
	return 0;
	}
}
			prune_tmp_file(mkpath("%s/%s", path, de->d_name));
			struct object *object = parse_object_or_die(&oid,
	if (starts_with(basename, "tmp_obj_"))
		revs.exclude_promisor_objects = 1;
	free(s);
	s = mkpathdup("%s/pack", get_object_directory());
