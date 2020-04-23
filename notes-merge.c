				  const char *buf, unsigned long size)
		struct object_id obj_oid, blob_oid;
		       conflicts);
		/* D/F conflict, checkout p->remote */
static void check_notes_merge_worktree(struct notes_merge_options *o)
			MOVE_ARRAY(list + i + 1, list + i, len - i);
{
			break;
			die("failed to concatenate notes "
		*occupied = 1;
	}
	msg += 2;
	strbuf_release(&path);
static void write_note_to_worktree(const struct object_id *obj,
	diff_setup_done(&opt);
			    const struct object_id *base,
}
#include "repository.h"
		base_oid = &bases->item->object.oid;
		}
			oid_to_hex(result_oid));

	const char *lref = o->local_ref ? o->local_ref : "local version";
		commit_list_insert(remote, &parents); /* LIFO order */
		    oid_to_hex(&local_oid), o->local_ref);
	/*
		die_errno("could not open %s", path.buf);
	trace_printf("\tlocal commit: %.7s\n", oid_to_hex(&local_oid));
	       oid_to_hex(remote));
		printf("Finalized notes merge commit: %s\n",
			       "%.7s -> %.7s. Skipping!\n", p->one->path,
			 * Either this is a true addition (1), or it is part
		} else { /* modification */

}
	static int last_index;
	 * found notes to 'partial_tree'. Write the updated notes tree to
	/* obj belongs at, or immediately preceding, index i (0 <= i <= len) */

		}
			       "%.7s -> %.7s. Skipping!\n", p->one->path,
		die("blob expected in note %s for object %s",
		die("Cannot merge empty notes ref (%s) into empty notes ref "
		assert(!is_null_oid(&p->two->oid));
			 * (2) mp->local is uninitialized; set to p->two->sha1
		/* result == remote commit */
	}
			assert(is_null_oid(&mp->local) ||
			       oideq(&mp->local, &uninitialized));

			printf("Concatenating unique lines in local and remote "
	struct diff_options opt;
			continue;
	 * Return 0 if change is successfully resolved (stored in notes_tree).
		if (o->verbosity >= 2)
			       oid_to_hex(&p->one->oid),
		break;
				  git_path(NOTES_MERGE_WORKTREE));
		else if (cmp < 0) /* obj belongs between i-1 and i */
	trace_printf("\tmerge_changes(num_changes = %i)\n", *num_changes);
		i = 0;
		return -1;
	 */
	} else if (!(remote = lookup_commit_reference(o->repo, &remote_oid))) {

	enum object_type type;
	free_commit_list(bases);
		if (ret < 0) {
		base_oid = &bases->item->object.oid;
{
		struct commit_list *parents = NULL;
		 * Failed to get remote_oid. If o->remote_ref looks like an
		o->has_worktree = 1;
	default:
#include "dir.h"
		goto found_result;
	char hex_oid[GIT_MAX_HEXSZ];
	trace_printf("\tmerge_from_diffs(base = %.7s, local = %.7s, "

	 * but instead written to NOTES_MERGE_WORKTREE with conflict markers).
	 * commit message and parents from 'partial_commit'.
				    "previous merge before you start a new "
	diffcore_std(&opt);
	switch (o->strategy) {
				    "(%s exists)."), git_path("NOTES_MERGE_*"));
	struct strbuf buf = STRBUF_INIT;
		assert(oideq(&mp->obj, &obj));


		if (insert_new && i < len) {

			       p->status, oid_to_hex(&p->one->oid),

			oidcpy(&mp->obj, &obj);
}
		local = NULL; /* local_oid == null_oid indicates unborn ref */
		}
		       oid_to_hex(&mp->obj), oid_to_hex(&mp->base),
	 * Iterate through files in .git/NOTES_MERGE_WORKTREE and add all
		}
	int i, conflicts = 0;
	 */
		base_oid = &null_oid;
		printf("Committing notes in notes merge worktree at %s\n",
}
			/* Ignore epipe */

	struct object_id obj, base, local, remote;
			    strlen(msg), result_oid);
				"deleted in %s and modified in %s. Version from %s "

			  &local, o->local_ref, &remote, o->remote_ref,
	conflicts = merge_changes(o, changes, &num_changes, t);
			       oid_to_hex(&p->two->oid));
		    git_path(NOTES_MERGE_WORKTREE));
}
found_result:
#include "diff.h"
	}
#include "cache.h"
	strbuf_addch(&path, '/');
	die("Unknown strategy (%i).", o->strategy);
		if (!check_refname_format(o->remote_ref, 0)) {
			 * (1) mp->local is uninitialized; set to p->two->sha1
}
#include "commit-reach.h"
	opt.output_format = DIFF_FORMAT_NO_OUTPUT;

	case NOTES_MERGE_RESOLVE_MANUAL:
		 */
		goto found_result;
		else /* if (cmp > 0) */ { /* obj belongs between i and i+1 */
		       oid_to_hex(&mp->local));
		commit_list_insert(local, &parents);
		oidcpy(result_oid, &remote_oid);
		       "Merge result: %i unmerged notes and a clean notes tree\n",
	if (!bases) {
		 * unborn ref, perform the merge using an empty notes tree.
						 const struct object_id *remote,
	oidclr(result_oid);
		if (file_exists(git_path(NOTES_MERGE_WORKTREE)) &&
			    const struct object_id *remote,
				break;
	}
				oid_to_hex(&p->obj), lref, rref, rref);
		if (add_note(t, &p->obj, &p->remote, combine_notes_cat_sort_uniq))
			      struct notes_merge_options *o)
	while (*path && i < the_hash_algo->hexsz) {
		assert(is_null_oid(&p->one->oid));
				assert(is_null_oid(&mp->base));
			die("Failed to resolve remote notes ref '%s'",
#include "notes-merge.h"
	trace_printf("notes_merge(): result = %i, result_oid = %.7s\n",
	int i = last_index < len ? last_index : len - 1;
		       oid_to_hex(&p->local),


		}
		base_tree_oid = get_commit_tree_oid(bases->item);
	return 0;
{

		if (o->verbosity >= 4)
static void diff_tree_local(struct notes_merge_options *o,
	const char *buffer = get_commit_buffer(partial_commit, NULL);
				    "notes merge (%s exists).\nPlease, use "
		struct object_id obj;
		die("cannot read note %s for object %s",

	 * Remove all files within .git/NOTES_MERGE_WORKTREE. We do not remove
			printf("CONFLICT (delete/modify): Notes for object %s "
				    "'git notes merge --commit' or 'git notes "
	read_mmblob(&local, &p->local);
#include "refs.h"

	return conflicts;
	trace_printf("\tdiff_tree_local(len = %i, base = %.7s, local = %.7s)\n",

	strbuf_init(&(o->commit_msg), 0);
		}
			trace_printf("\t\tIgnoring local-only change for %s: "

			len++;

	int i = 0;
	 * Both diff_tree_remote() and diff_tree_local() tend to process
			 */
		       struct object_id *result_oid)
		die("missing '%s'. This should not happen",

static struct object_id uninitialized = {

int notes_merge_commit(struct notes_merge_options *o,
	 * Finally store the new commit object OID into 'result_oid'.
		struct notes_merge_pair *mp;
	repo_diff_setup(o->repo, &opt);
		}
	       oid_to_hex(base), oid_to_hex(remote));
{
	if (oideq(&local->object.oid, base_oid)) {
			 struct notes_merge_pair *changes, int *num_changes,
	 * list is expensive (using memmove()).
			 */
			printf("One merge base found (%.7s)\n",
	if (*path || i != the_hash_algo->hexsz)
		       struct notes_tree *partial_tree,
	closedir(dir);
			die("failed to concatenate notes "
			 *
	if (o->verbosity >= 4)
		die("Could not parse local commit %s (%s)",
	opt.flags.recursive = 1;

			       oid_to_hex(base_oid));
		/* Already merged; result == local commit */


		if (o->verbosity >= 4)
	}
		} else {
		if (o->verbosity >= 2)
			printf("CONFLICT (%s): Merge conflict in notes for "
		struct notes_merge_pair *list, int len, struct object_id *obj,
	if (!local && !remote)
			trace_printf("\t\tCannot merge entry '%s' (%c): "
	baselen = path.len;
	git_path_buf(&path, NOTES_MERGE_WORKTREE);
		goto found_result;
	int fd;
	int baselen;

	close(fd);
	free(base.ptr);
	ret = remove_dir_recursively(&buf, REMOVE_DIR_KEEP_TOPLEVEL);
				NOTES_MERGE_WORKTREE "/.test")))
			 *
	/* add "Conflicts:" section to commit message first time through */
		struct diff_filepair *p = diff_queued_diff.queue[i];
			oidcpy(&mp->local, &uninitialized);
	} else {
	return 1;
		if (verify_notes_filepair(p, &obj)) {

			printf("Fast-forward\n");
			i++;
	}
			oidcpy(&mp->base, &p->one->oid);
			printf("Added resolved note for object %s: %s\n",
	const char *msg = strstr(buffer, "\n\n");
	changes = diff_tree_remote(o, base, remote, &num_changes);
			die_errno("unable to create directory %s",
	diff_tree_oid(base, remote, "", &opt);
						oid_to_hex(&p->obj));
		struct object_id *result_oid)
		       oid_to_hex(&mp->remote));
	if (o->verbosity >= 3)
			else
	/*
	}
		if (o->verbosity >= 2)

	remove_note(t, p->obj.hash);
	if (!local) {
	while ((e = readdir(dir)) != NULL) {
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
	if (!o->has_worktree) {
	mmfile_t base, local, remote;
	}
				"object %s\n", reason,
		strbuf_setlen(&path, baselen);
	write_buf_to_worktree(obj, buf, size);
	unuse_commit_buffer(partial_commit, buffer);

			assert(oideq(&p->one->oid, &mp->base));
			 */
	int result = 0;
		assert(!is_null_oid(&p->local));
	struct notes_merge_pair *changes;
{
			/* no local change; adopt remote change */
		if (verify_notes_filepair(p, &obj)) {
}
			die("Failed to add resolved note '%s' to notes tree",
	if (safe_create_leading_directories_const(path))
	free(changes);
			 * Set mp->local to p->two->sha1.
	if (i < 0)
	opt.flags.recursive = 1;
{
				"notes for %s\n", oid_to_hex(&p->obj));
	check_notes_merge_worktree(o);
	case DIFF_STATUS_DELETED:
static int ll_merge_in_worktree(struct notes_merge_options *o,
			 * (2) mp->local is not uninitialized; don't touch it
		return merge_one_change_manual(o, p, t);

		cmp = oidcmp(obj, &list[i].obj);
struct notes_merge_pair {

	} else {
}
				"deleted in %s and modified in %s. Version from %s "
						 const struct object_id *base,
				"(%.7s)\n", oid_to_hex(base_oid));
		assert(!is_null_oid(&p->remote));
			path.buf);
			/* no remote change; nothing to do */
	for (i = 0; i < *num_changes; i++) {
			oidcpy(&mp->remote, &p->two->oid);
{
			BUG("combine_notes_overwrite failed");
			/*
	}
		goto found_result;

	return get_oid_hex(hex_oid, oid);

	return conflicts ? -1 : 1;
						 int *num_changes)
		if (get_oid_hex(e->d_name, &obj_oid)) {
	       o->local_ref, o->remote_ref);
			    const struct object_id *local)
		/* write file as blob, and add to partial_tree */
	else {
	 * _appends_), we don't care that inserting into the middle of the
	int status;
			continue;

	DIR *dir;
		struct stat st;
			/* need file-level merge between local and remote */
		    "(%s)", o->remote_ref, o->local_ref);
	result = merge_from_diffs(o, base_tree_oid,
				oid_to_hex(&p->obj), rref, lref, lref);
				"left in tree.\n",
	diff_tree_local(o, changes, num_changes, base, local);
	       "local = %.7s, remote = %.7s)\n",
		if (o->verbosity >= 1)
			if (o->verbosity >= 3)
		/* TODO: How to handle multiple merge-bases? */
	if (!dir)
#include "object-store.h"
		write_note_to_worktree(&p->obj, &p->remote);
	}
	status = ll_merge(&result_buf, oid_to_hex(&p->obj), &base, NULL,
		/* nothing to do */
	return ret;
	void *buf = read_object_file(note, &type, &size);
		trace_printf("\t\tStored remote change for %s: %.7s -> %.7s\n",

			trace_printf("\t\t\tskipping (no remote change)\n");
	if (is_null_oid(&p->local)) {
	dir = opendir(path.buf);
		 * Abort if NOTES_MERGE_WORKTREE already exists
}
	 * index, and search sequentially from there until the appropriate
	diff_setup_done(&opt);
				oidcpy(&mp->base, &p->one->oid);
		*occupied = 0;
		printf("Merging remote commit %.7s into local commit %.7s with "

	if (!buf)
		if (index_path(o->repo->index, &blob_oid, path.buf, &st, HASH_WRITE_OBJECT))
#include "xdiff-interface.h"

			 * This is a true modification. p->one->sha1 shall
	case DIFF_STATUS_MODIFIED:
			 * of an A/D pair (2), or D/A pair (3):
		path++;
			trace_printf("\t\t\tneed content-level merge\n");

			 * (3) mp->local is null_sha1;     set to p->two->sha1
			    o->remote_ref);
			    "(combine_notes_cat_sort_uniq)");
	else if (!check_refname_format(o->local_ref, 0) &&
		if (is_dot_or_dotdot(e->d_name))
	}
	free(remote.ptr);
{
			continue;
				  get_commit_tree_oid(remote), local_tree);
			break;
			       p->status, oid_to_hex(&p->one->oid),
	       oid_to_hex(&p->obj), oid_to_hex(&p->base),
	if (get_oid(o->remote_ref, &remote_oid)) {
		} else if (oideq(&p->local, &uninitialized) ||
		}
	/*
			printf("Concatenating local and remote notes for %s\n",

		else if (cmp < 0 && prev_cmp <= 0) /* obj belongs < i */
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" \
}
		else if (cmp > 0 && prev_cmp >= 0) /* obj belongs > i */
			continue;
		assert(is_null_oid(&p->two->oid));
		if (o->verbosity >= 2)
	o->repo = r;
	assert(local && remote);

	       len, oid_to_hex(base), oid_to_hex(local));
	diff_flush(&opt);
	if (o->verbosity >= 4)
	if (oideq(&remote->object.oid, base_oid)) {
		struct notes_merge_pair *mp;
	}
			    path.buf);
	 * merge_pairs in ascending order. Therefore, cache last returned
			die("Failed to write blob object from '%s'", path.buf);
}
		if (stat(path.buf, &st))
	int num_changes, conflicts;
			} else if (is_null_oid(&p->two->oid)) { /* deletion */

		printf("Removing notes merge worktree at %s/*\n", buf.buf);
int notes_merge(struct notes_merge_options *o,
	git_path_buf(&buf, NOTES_MERGE_WORKTREE);
	}
		       oid_to_hex(&mp->obj), oid_to_hex(&mp->base),

			 struct notes_tree *t)
		is_null_oid(&local_oid))

				"left in tree.\n",
	}
	struct object_id local_oid, remote_oid;
			die_errno("Failed to stat '%s'", path.buf);
	read_mmblob(&base, &p->base);
	return list + i;
	free(local.ptr);

		base_tree_oid = the_hash_algo->empty_tree;
#include "diffcore.h"
}
		struct object_id obj;
		assert(!is_null_oid(&p->remote));
#include "strbuf.h"

		assert(p->one->mode == p->two->mode);
	return result;

					path.buf, e->d_name);
			continue;
{
static struct notes_merge_pair *find_notes_merge_pair_pos(

	} else if (!file_exists(git_path(NOTES_MERGE_WORKTREE)))
				   struct notes_merge_pair *p,
	opt.output_format = DIFF_FORMAT_NO_OUTPUT;
		if (is_null_oid(&p->base))
		    oid_to_hex(note), oid_to_hex(obj));
				  get_commit_tree_oid(local),
	assert(!strcmp(o->local_ref, local_tree->ref));
		    !is_empty_dir(git_path(NOTES_MERGE_WORKTREE))) {
		return 0;

	 * the DB, and commit the resulting tree object while reusing the
						oid_to_hex(&p->obj));

			printf("Using local notes for %s\n",
				    "merge --abort' to commit/abort the "
		if (occupied) {
	 * the current working directory of the user.
		/* Commit (partial) result */
				oid_to_hex(&p->obj));
	/* Dereference o->local_ref into local_sha1 */
	struct strbuf path = STRBUF_INIT;
		prev_cmp = cmp;
		oidcpy(result_oid, &local->object.oid);
	if (!o->has_worktree)

		 */
			die_errno("notes-merge");
		buf += ret;
		break;
		} else {
		mp = find_notes_merge_pair_pos(changes, len, &obj, 1, &occupied);
		assert(!is_null_oid(&p->local));
	if ((status < 0) || !result_buf.ptr)
	mmbuffer_t result_buf;
	       oid_to_hex(&p->local), oid_to_hex(&p->remote));
	strbuf_addf(&(o->commit_msg), "\t%s\n", oid_to_hex(&p->obj));
			conflicts += merge_one_change(o, p, t);
			trace_printf("\t\t\tskipping (local == remote)\n");
		struct notes_merge_pair *p = changes + i;
		die("Failed to execute internal merge");
	/*

	if (result != 0) { /* non-trivial merge (with or without conflicts) */
		}
static struct notes_merge_pair *diff_tree_remote(struct notes_merge_options *o,
	strbuf_release(&(o->commit_msg));
	}
	struct notes_merge_pair *changes;
		if (o->verbosity >= 1)
			 *     (will be overwritten by following addition)
	return status;
	/* Find merge bases */
		printf("Auto-merging notes for %s\n", oid_to_hex(&p->obj));
		return 0;
				die(_("You have not concluded your notes merge "
}
			printf("No merge base found; doing history-less merge\n");
		trace_printf("\t\t%.7s: %.7s -> %.7s/%.7s\n",
			if (is_null_oid(&p->one->oid)) { /* addition */
			memset(list + i, 0, sizeof(struct notes_merge_pair));
}
		die("partial notes commit has empty message");
		assert(!is_null_oid(&p->one->oid));
{

	if (!msg || msg[2] == '\0')
		mp = find_notes_merge_pair_pos(changes, len, &obj, 0, &match);
	case DIFF_STATUS_ADDED:
{
	while (size > 0) {
	repo_diff_setup(o->repo, &opt);
		if (o->verbosity >= 2)

				printf("Skipping non-SHA1 entry '%s%s'\n",
		base_tree_oid = get_commit_tree_oid(bases->item);
	last_index = i;
		} else if (oideq(&p->local, &p->remote)) {
			       "%.7s -> %.7s\n", oid_to_hex(&obj),
	case NOTES_MERGE_RESOLVE_OURS:
	free(result_buf.ptr);
				     combine_notes_overwrite))
		}
			 * match mp->base, and mp->local shall be uninitialized.
	if (o->verbosity >= 3)
	switch (p->status) {
				   struct notes_tree *t)

		}
			/*
		int insert_new, int *occupied)

	assert(o->local_ref && o->remote_ref);

	diff_tree_oid(base, local, "", &opt);
		if (o->verbosity >= 2)
			    "(combine_notes_concatenate)");
			    struct notes_merge_pair *p, struct notes_tree *t)
		/* result == local commit */
			assert(oideq(&mp->obj, &obj));
{
	fd = xopen(path, O_WRONLY | O_EXCL | O_CREAT, 0666);
	case NOTES_MERGE_RESOLVE_THEIRS:
	return path_to_oid(p->one->path, oid);
	bases = get_merge_bases(local, remote);
		if (!cmp) /* obj belongs @ i */
	diff_flush(&opt);
				BUG("combine_notes_overwrite failed");
	char *path = git_pathdup(NOTES_MERGE_WORKTREE "/%s", oid_to_hex(obj));
	       result, oid_to_hex(result_oid));
		} else {
			hex_oid[i++] = *path;
			 * Either this is a true deletion (1), or it is part
{
			if (advice_resolve_conflict)
			printf("CONFLICT (delete/modify): Notes for object %s "
static int merge_from_diffs(struct notes_merge_options *o,
static int verify_notes_filepair(struct diff_filepair *p, struct object_id *oid)
	while (i >= 0 && i < len) {
				    "notes merge."), git_path("NOTES_MERGE_*"));
	if (!cmp)
		if (o->verbosity >= 1)
}
			printf("Using remote notes for %s\n",
			if (oideq(&mp->local, &uninitialized))
		 * Must establish NOTES_MERGE_WORKTREE.

		       oid_to_hex(&p->remote));
	strbuf_release(&buf);

	} else if (is_null_oid(&p->remote)) {
		if (is_null_oid(&p->two->oid)) { /* deletion */
			/* same change in local and remote; nothing to do */
static int merge_changes(struct notes_merge_options *o,
				struct notes_merge_pair *p)
		trace_printf("\t\tStored local change for %s: %.7s -> %.7s\n",
			oidcpy(&mp->local, &p->two->oid);
		const char *reason = "content";
							oid_to_hex(&p->obj));
		write_note_to_worktree(&p->obj, &p->local);
{
		size -= ret;
	read_mmblob(&remote, &p->remote);
}

			 * (1) mp->local is uninitialized; set it to null_sha1
	else if (!(local = lookup_commit_reference(o->repo, &local_oid)))
			oidclr(&remote_oid);
}
		/* NOTES_MERGE_WORKTREE should already be established */
				assert(is_null_oid(&mp->remote));
				    o->commit_msg.len, result_oid);
		return 0;
		/*
			"merge-base %.7s\n", oid_to_hex(&remote->object.oid),
			} else
				oidclr(&mp->local);
		oidcpy(result_oid, &remote->object.oid);
			printf("Already up to date!\n");

		oidcpy(result_oid, &local_oid);
		if (oideq(&p->base, &p->remote)) {
		if (add_note(t, &p->obj, &p->remote, combine_notes_overwrite))
			oidcpy(&mp->local, &p->two->oid);
	case NOTES_MERGE_RESOLVE_UNION:
		}
			assert(oideq(&mp->local, &uninitialized));
	write_buf_to_worktree(&p->obj, result_buf.ptr, result_buf.size);
		printf(t->dirty ?
#include "notes.h"
	       "remote = %.7s)\n", oid_to_hex(base), oid_to_hex(local),
};
	clear_pathspec(&opt.pathspec);
#include "notes-utils.h"
	trace_printf("\tdiff_tree_remote(base = %.7s, remote = %.7s)\n",
		break;
			    struct notes_tree *t)
			break;
		die_errno("unable to create directory for '%s'", path);
	return changes;
			       oid_to_hex(&p->two->oid));
		/* D/F conflict, checkout p->local */


	o->verbosity = NOTES_MERGE_VERBOSITY_DEFAULT;
			       oid_to_hex(&p->two->oid));
	free(path);
	for (i = 0; i < diff_queued_diff.nr; i++) {

	diffcore_std(&opt);
		ssize_t ret = write_in_full(fd, buf, size);
			   oideq(&p->local, &p->base)) {
			if (add_note(t, &p->obj, &p->remote,
		struct diff_filepair *p = diff_queued_diff.queue[i];
	/* Dereference o->remote_ref into remote_oid */

				die(_("You have not concluded your previous "
#include "ll-merge.h"
		    oid_to_hex(&remote_oid), o->remote_ref);


	int prev_cmp = 0, cmp = -1;
{
	trace_printf("notes_merge(o->local_ref = %s, o->remote_ref = %s)\n",
			i++;
				   const struct object_id *note)
		if (!match) {
		if (add_note(partial_tree, &obj_oid, &blob_oid, NULL))
	 * position is found.
static int merge_one_change(struct notes_merge_options *o,
			 * of an A/D pair (2), or D/A pair (3):
	 * Return 1 is change results in a conflict (NOT stored in notes_tree,
		strbuf_addstr(&(o->commit_msg), "\n\nConflicts:\n");
static int merge_one_change_manual(struct notes_merge_options *o,
		    oid_to_hex(note), oid_to_hex(obj));
	clear_pathspec(&opt.pathspec);
	}
static int path_to_oid(const char *path, struct object_id *oid)
				oid_to_hex(&obj_oid), oid_to_hex(&blob_oid));
		int match;
		die("Could not parse remote commit %s (%s)",
	 */
		return -1;
		       oid_to_hex(&p->obj), oid_to_hex(&p->base),
	struct commit_list *bases = NULL;
	unsigned long size;
		       struct commit *partial_commit,
	changes = xcalloc(diff_queued_diff.nr, sizeof(struct notes_merge_pair));
		if (safe_create_leading_directories_const(git_path(
		if (o->verbosity >= 3)
			    const struct object_id *local,
};
	 * Since inserts only happen from diff_tree_remote() (which mainly
			trace_printf("\t\tCannot merge entry '%s' (%c): "
	trace_printf("\t\t\tmerge_one_change_manual(obj = %.7s, base = %.7s, "
	*num_changes = len;
		ll_merge_in_worktree(o, p);
		} else if (is_null_oid(&p->one->oid)) { /* addition */

	trace_printf("\t\t\tremoving from partial merge result\n");
	const char *rref = o->remote_ref ? o->remote_ref : "remote version";
int notes_merge_abort(struct notes_merge_options *o)
		if (add_note(t, &p->obj, &p->remote, combine_notes_concatenate))
	trace_printf("\tremote commit: %.7s\n", oid_to_hex(&remote_oid));
	assert(!strcmp(p->one->path, p->two->path));
	if (o->verbosity >= 4)

		/* Fast-forward; result == remote commit */
				assert(!"Invalid existing change recorded");

		/* "regular" conflict, checkout result of ll_merge() */
	int i;
	memset(o, 0, sizeof(struct notes_merge_options));
			/* We've found an addition/deletion pair */
	free(buf);
			 * (3) mp->local is uninitialized; set it to null_sha1
	if (!remote) {
	int ret;
	}
		die("Failed to resolve local notes ref '%s'", o->local_ref);
		return 0;
			    const struct object_id *base,
	for (i = 0; i < diff_queued_diff.nr; i++) {
			remote = NULL;
void init_notes_merge_options(struct repository *r,
	struct dirent *e;
			oid_to_hex(&local->object.oid),
	if (type != OBJ_BLOB)
			    struct notes_merge_pair *changes, int len,

	create_notes_commit(o->repo, partial_tree, partial_commit->parents, msg,

	case NOTES_MERGE_RESOLVE_CAT_SORT_UNIQ:
	if (o->verbosity >= 2)
	 *
			if (errno == EPIPE)
	}


		if (o->verbosity >= 4)
	struct commit *local, *remote;
			reason = "add/add";
		struct notes_tree *local_tree,
		/*
{
			oid_to_hex(base_oid));
		       "Merge result: %i unmerged notes and a dirty notes tree\n" :
	struct diff_options opt;

	} else if (!bases->next) {
			printf("Multiple merge bases found. Using the first "
		if (*path != '/')
	int i, len = 0;
			i--;
#include "commit.h"
			/*
	 * the .git/NOTES_MERGE_WORKTREE directory itself, since it might be
{
	if (read_ref_full(o->local_ref, 0, &local_oid, NULL))
		strbuf_addstr(&path, e->d_name);
static void write_buf_to_worktree(const struct object_id *obj,
			  o->repo->index, NULL);
			trace_printf("\t\t\tno local change, adopted remote\n");
		create_notes_commit(o->repo, local_tree, parents, o->commit_msg.buf,
	const struct object_id *base_oid, *base_tree_oid;
		int occupied;
				oidcpy(&mp->remote, &p->two->oid);

	 */
