	if (nongit)
 * Builtin "git diff"
	 * N=0, M=0:
	/* Blob vs file in the working tree*/
	int blobs = 0, paths = 0;
	oid[1 - swap] = &ent1->item->oid;
		if (!strcmp(argv[i], "--")) {
		     &blob[0]->item->oid, &blob[1]->item->oid,
		 * diff A...B where there is at least one merge base
static int builtin_diff_blobs(struct rev_info *revs,
	rev.diffopt.flags.allow_external = 1;
	 *

}
static int builtin_diff_b_f(struct rev_info *revs,
	while (1 < argc) {
	/*
			break;
	return run_diff_index(revs, cached);
		 * base and B.  Note that we pick one merge base at
		}
	    (revs->diffopt.output_format & DIFF_FORMAT_PATCH))
{
	 * Do we have --cached and not have a pending object, then
	one = alloc_filespec(old_path);
	}
		int flags = (obj->flags & UNINTERESTING);
			if (!strcmp(arg, "--"))
	/* Were we asked to do --no-index explicitly? */
		SWAP(old_mode, new_mode);
				break;
"git diff [<options>] [<commit> [<commit>]] [--] [<path>...]";
	int fd;


	 */
	int swap = 0;
		usage(builtin_diff_usage);
#include "color.h"
		usage(builtin_diff_usage);
	/*
	 */
		if (obj->type == OBJ_TREE) {
	 * swap them.
}
	    revs->max_count != -1 || revs->min_age != -1 ||
#define DIFF_NO_INDEX_EXPLICIT 1
			obj = parse_object(the_repository, &obj->oid);
	/*
	 * dense one, --cc can be explicitly asked for, or just rely
	result = diff_result_code(&rev.diffopt, result);
		if (!obj)
	UNLEAK(ent);

			add_object_array(obj, name, &ent);
	if (!ent.nr) {
	 * Make sure there is one revision (i.e. pending object),

	/*
	if (no_index)
	 *	compare a blob with a working tree file.
		else if (!strcmp(argv[1], "-q"))

		struct object_array_entry *entry = &rev.pending.objects[i];
							   the_repository->hash_algo->empty_tree);
				}
			    struct object_array_entry **blob)
	 * N=1, M=0:
			obj->flags |= flags;
	/* If this is a no-index diff, just run it and exit there. */

#include "commit.h"
	else if (ent.objects[0].item->flags & UNINTERESTING) {
			result = builtin_diff_files(&rev, argc, argv);
	read_cache();

		 * Treat git diff with at least one path outside of the

		argv++; argc--;
	 *      tree vs tree (diff-tree)
		else
			}
	}
					   &ent.objects[0], &ent.objects[1]);
		blob[0]->mode = mode;
		return;
	if (lstat(path, &st))
	 *      compare two random blobs.  P must be zero.
#define DIFF_NO_INDEX_IMPLICIT 2
			      int argc, const char **argv)
{
			break;

		 * repo the same as if the command would have been executed
	 */
		swap = 1;
	}
		     1, 0,
		paths += rev.prune_data.nr;
			revs->max_count = 1;
	for (i = 1; i < ents; i++)
			usage(builtin_diff_usage);
	UNLEAK(rev);
	/*
	const struct object_id *(oid[2]);
					add_pending_object(&rev, &tree->object, "HEAD");
	} else if (read_cache() < 0) {
{
	discard_cache();
		usage(builtin_diff_usage);
	return run_diff_files(revs, options);
					struct tree *tree;
}
	repo_init_revisions(the_repository, &rev, prefix);
		revs->dense_combined_merges = revs->combine_merges = 1;
	const unsigned mode = canon_mode(S_IFREG | 0644);
			no_index = DIFF_NO_INDEX_EXPLICIT;
	if (read_cache_preload(&revs->diffopt.pathspec) < 0) {
		 * between A and B.  We have ent.objects[0] ==
		}
				if (!rev.pending.nr) {

	unsigned int options = 0;
			die(_("unhandled object '%s' given."), name);
	struct oid_array parents = OID_ARRAY_INIT;
	 *
	fd = hold_locked_index(&lock_file, 0);
	diff_set_mnemonic_prefix(&revs->diffopt, "o/", "w/");
	if (opt->flags.reverse_diff) {
			break;
		result = builtin_diff_index(&rev, argc, argv);
	}
			       (!path_inside_repo(prefix, argv[i]) ||

	return 0;
		SWAP(old_path, new_path);
	diff_tree_oid(oid[0], oid[1], "", &revs->diffopt);
		}
			i++;

		/*
				 !strcmp(arg, "--staged")) {
	int cached = 0;
	GUARD_PATHSPEC(&revs->prune_data, PATHSPEC_FROMTOP | PATHSPEC_LITERAL);
	UNLEAK(blob);
	}
					       ent.objects, ent.nr);

	struct stat st;

	git_config(git_diff_ui_config, NULL);
				usage(builtin_diff_usage);

	path = revs->prune_data.items[0].match;
	 *	cache vs files (diff-files)
		result = builtin_diff_tree(&rev, argc, argv,
	else if (blobs)
	 *      compare two filesystem entities (aka --no-index).
	diff_tree_combined(&ent[0].item->oid, &parents,

	if (opt->prefix &&
		setup_work_tree();
			   revs->dense_combined_merges, revs);
{
			die(_("invalid object '%s' given."), name);
		int i;
	precompose_argv(argc, argv);
	 * Also there could be M blobs there, and P pathspecs.
	 * Other cases are errors.
	prefix = setup_git_directory_gently(&nongit);

		if (!strcmp(argv[1], "--base"))
		return -1;
	rev.diffopt.flags.allow_textconv = 1;
static int builtin_diff_index(struct rev_info *revs,
			 const char *old_path,
/*
	}
	 * "diff --base" should not combine merges because it was not
		if (!strcmp(arg, "--cached") || !strcmp(arg, "--staged"))
	}
			if (paths)
#include "tag.h"
		exit(diff_no_index(&rev, no_index == DIFF_NO_INDEX_IMPLICIT,
static void stuff_change(struct diff_options *opt,
#include "revision.h"
		obj = deref_tag(the_repository, obj, NULL, 0);
	struct rev_info rev;
static const char builtin_diff_usage[] =
		else if (!strcmp(argv[1], "-h"))
	}

		else if (!strcmp(argv[1], "--theirs"))
	rev.diffopt.stat_width = -1;
#include "diffcore.h"
static int builtin_diff_tree(struct rev_info *revs,
			options |= DIFF_SILENT_ON_REMOVED;
	return 0;
		usage(builtin_diff_usage);
	rev.diffopt.skip_stat_unmatch = !!diff_auto_refresh_index;
}
	 */
		case 2:
			blobs++;
		case 1:
		 */
		perror("read_cache");

				 int ents)
	setup_work_tree();
	 * N=0, M=1, P=1:
		 * merge-base, ent.objects[ents-2] == A, and
		return;
		 * ent.objects[ents-1] == B.  Show diff between the
}
#include "builtin.h"
	 * N=0, M=2:
		argv++; argc--;
{
		     path);
		die(_("'%s': not a regular file or symlink"), path);
	diff_flush(&revs->diffopt);
static int builtin_diff_files(struct rev_info *revs, int argc, const char **argv)
	 * and there is no revision filtering parameters.
#include "blob.h"
		     blob_path(blob[0]), blob_path(blob[1]));
		 */
		     1, 1,
	if (blob[0]->mode == S_IFINVALID)


			 int old_oid_valid,
		rev.diffopt.output_format = DIFF_FORMAT_PATCH;
	     strncmp(new_path, opt->prefix, opt->prefix_length)))
		return;
		blob[1]->mode = mode;
			 const char *new_path)
	 * Otherwise, we are doing the usual "git" diff; set up any

		die_errno(_("failed to stat '%s'"), path);
}

		 * the same way as "git diff --no-index <a> <b>", which acts
		     blob[0]->mode, blob[1]->mode,
			     int argc, const char **argv,



			return -1;
	argc = setup_revisions(argc, argv, &rev, NULL);
	}



	setup_diff_pager(&rev.diffopt);
	int i;
static const char *blob_path(struct object_array_entry *entry)
		default:
	 */

			break;

	if (!revs->dense_combined_merges && !revs->combine_merges)
	log_tree_diff_flush(revs);
	for (i = 0; i < rev.pending.nr; i++) {
	if (blob[0]->mode == S_IFINVALID)
		die(_("Not a git repository"));
	struct diff_filespec *one, *two;
		} else {
		} else if (obj->type == OBJ_BLOB) {
			      int argc, const char **argv,
	return result;
	if (!rev.pending.nr) {
			 unsigned old_mode, unsigned new_mode,
				die(_("more than two blobs given: '%s'"), name);
		diff_setup_done(&rev.diffopt);
				 struct object_array_entry *ent,

		result = builtin_diff_combined(&rev, argc, argv,
	if (argc > 1)
					   &ent.objects[ent.nr-1]);
					   &ent.objects[0],
	stuff_change(&revs->diffopt,
		 * as a colourful "diff" replacement.
	rev.diffopt.stat_graph_width = -1;
			 int new_oid_valid,


	    (strncmp(old_path, opt->prefix, opt->prefix_length) ||
	if (!rev.diffopt.output_format) {
		if (argv[i][0] != '-')
			obj = &get_commit_tree(((struct commit *)obj))->object;

	if (revs->pending.nr != 1 ||



		     &blob[0]->item->oid, &null_oid,
	 *      tree vs cache (diff-index --cached)
	}

			return error(_("invalid option: %s"), argv[1]);
	if (argc > 1)
				 int argc, const char **argv,
		const char *arg = argv[1];
	    revs->max_age != -1)
	rev.diffopt.ita_invisible_in_index = 1;
	init_diff_ui_defaults();
	} else
static int builtin_diff_combined(struct rev_info *revs,
	int result = 0;
int cmd_diff(int argc, const char **argv, const char *prefix)
			cached = 1;
	if (!cached) {

	diffcore_std(&revs->diffopt);
	if (argc > 1)
	/*
#include "oid-array.h"
			no_index = DIFF_NO_INDEX_IMPLICIT;
			usage(builtin_diff_usage);
	 * asked to.  "diff -c" should not densify (if the user wants
		if (read_cache_preload(&revs->diffopt.pathspec) < 0) {
 */
	struct object_array_entry *blob[2];

	oid_array_clear(&parents);
	else if (ent.nr == 1)
	const char *path;
#include "lockfile.h"
#include "cache.h"
	 *
			 const struct object_id *old_oid,
	 * and not at all in diff-cached.
			result = builtin_diff_b_f(&rev, argc, argv, blob);
		 * random if there are more than one.
	return 0;
		     blob[0]->mode, canon_mode(st.st_mode),
 *
	    oideq(old_oid, new_oid) && (old_mode == new_mode))
	 * We could get N tree-ish in the rev.pending_objects list.
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		oid_array_append(&parents, &ent[i].item->oid);
	/*

	else if (ent.nr == 2)
		if (nongit || ((argc == i + 2) &&
{
	stuff_change(&revs->diffopt,
}
	if (argc > 1)
	 * on the default).
	 * default to HEAD by hand.  Eek.
	rev.diffopt.flags.recursive = 1;
			    int argc, const char **argv,
			revs->max_count = 2;
			usage(builtin_diff_usage);
	 */
	if (!no_index) {
	fill_filespec(two, new_oid, new_oid_valid, new_mode);
	 * Default to intent-to-add entries invisible in the

		else if (!strcmp(argv[1], "--ours"))
			else if (!strcmp(arg, "--cached") ||
	refresh_cache(REFRESH_QUIET|REFRESH_UNMERGED);
 * Copyright (c) 2006 Junio C Hamano
{
	 */
#include "submodule.h"
	oid[swap] = &ent0->item->oid;
	diff_queue(&diff_queued_diff, one, two);

	fill_filespec(one, old_oid, old_oid_valid, old_mode);
		}
		for (i = 1; i < argc; i++) {
	 *
	/*
			revs->max_count = 3;
		case 0:
			break;
				   argc, argv));
#include "log-tree.h"
	struct object_array ent = OBJECT_ARRAY_INIT;
	 * Now, do the arguments look reasonable?
	 */
		const char *name = entry->name;
			      struct object_array_entry **blob)
		result = builtin_diff_tree(&rev, argc, argv,
		     blob[0]->path ? blob[0]->path : path,
		refresh_index_quietly();
}
		}
				usage(builtin_diff_usage);
	if (fd < 0)
			perror("read_cache_preload");
	 * index. This makes them show up as new files in diff-files
	}
		if (!strcmp(argv[i], "--no-index"))
#include "diff.h"
static void refresh_index_quietly(void)

	 * N=2, M=0:
		struct object *obj = entry->item;
			if (2 <= blobs)
	return entry->path ? entry->path : entry->name;
	while (1 < argc && argv[1][0] == '-') {
		blob[0]->mode = canon_mode(st.st_mode);
		SWAP(old_oid, new_oid);
		else
				add_head_to_pending(&rev);
		revs->combine_merges = revs->dense_combined_merges = 1;
		if (!obj->parsed)

		/*
{
			     struct object_array_entry *ent1)
		usage(builtin_diff_usage);
	if (1 < rev.diffopt.skip_stat_unmatch)
		return -1;
			blob[blobs] = entry;

			     struct object_array_entry *ent0,

}
{
	struct lock_file lock_file = LOCK_INIT;
				!path_inside_repo(prefix, argv[i + 1]))))

	if (ent1->item->flags & UNINTERESTING)
	two = alloc_filespec(new_path);

					tree = lookup_tree(the_repository,
			const char *arg = argv[i];
	/* Set up defaults that will apply to both no-index and regular diffs. */
		if (obj->type == OBJ_COMMIT)
	 * We saw two trees, ent0 and ent1.  If ent1 is uninteresting,
	int i;
	if (blob[1]->mode == S_IFINVALID)
	if (revs->max_count == -1 && !revs->combine_merges &&
			 const struct object_id *new_oid,
	if (!(S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)))
	diffcore_std(&revs->diffopt);
				break;
}
			result = builtin_diff_blobs(&rev, argc, argv, blob);
	 * further defaults that apply to regular diffs.
			if (paths != 1)
{
	if (!is_null_oid(old_oid) && !is_null_oid(new_oid) &&
		usage(builtin_diff_usage);
	int nongit = 0, no_index = 0;
	 * N=0, M=0, P=2:
	return 0;

	if (rev.prune_data.nr)
	for (i = 1; i < argc; i++) {
	diff_flush(&revs->diffopt);
	 *
		switch (blobs) {
	repo_update_index_if_able(the_repository, &lock_file);
#include "config.h"
		 * outside of a git repository.  In this case it behaves
		perror("read_cache_preload");


