			      super_prefixed(old->name));
	for (e = 0; e < NB_UNPACK_TREES_ERROR_TYPES; e++) {
			    const char *name, size_t namelen,
static int unpack_nondirectories(int n, unsigned long mask,
		 */
		int update = 0;
			 * deletion of the path was staged;
	}
	/* ERROR_NOT_UPTODATE_FILE */
	/*
	if (o->src_index->fsmonitor_last_update)
	 * ODB twice for the same OID.  This should yield a nice speed
{


		fprintf(o, "%s (missing)\n", label);
static void invalidate_ce_path(const struct cache_entry *ce,
	for (i = 1; i < o->head_idx; i++) {
		else
	     i++) {
		 * If that file is already outside worktree area, don't
	int df_conflict_head = 0;
		return error(ERRORMSG(o, e), super_prefixed(path));
						       pl, default_match,
	 * data from the earlier cell.
static int find_cache_pos(struct traverse_info *info,
		/*
			  !same(oldtree, newtree) && /* 18 and 19 */
		    strncmp(ce->name, ce2->name, namelen) ||
		if (!are_same_oid(names, names + i))
	if (!strcmp(cmd, "checkout"))

				cache += processed;
}
		}
		return 0;
/* Whole directory matching */
	int remote_match = 0;
}

			     o->merge_size);
	const struct cache_entry *result;
	 * n commits.
}
	}
			  struct pattern_list *pl,
		} else
		return rc;
	 * if this entry is truly up-to-date because this file may be
{

{
	if (submodule_move_head(ce->name, old_id, new_id, flags))
				   struct unpack_trees_options *o)

	else
		      : _("Your local changes to the following files would be overwritten by %s:\n%%s");
	msgs[ERROR_WOULD_LOSE_ORPHANED_REMOVED] =
	 * compare as bigger than a directory leading up to it!
{
static int apply_sparse_checkout(struct index_state *istate,
	if (index) {
static int verify_uptodate_sparse(const struct cache_entry *ce,
	ret = check_updates(o) ? (-2) : 0;
	/* ERROR_WOULD_LOSE_SUBMODULE */
/*
		/*
						      OBJECT_INFO_FOR_PREFETCH))
	 * up in checkouts and merges when the commits are similar.
static void mark_ce_used(struct cache_entry *ce, struct unpack_trees_options *o)
			struct cache_entry *ce = index->cache[i];
			discard_cache_entry(merge);

	 */
	 * The previous round may already have decided to
		return 0;
		ce->ce_flags &= ~CE_MATCHED;
	if (0 <= pos)
 * number of traversed entries.
}
	}
	}
{
	/*
	if (0 <= pos)

	return nr - (cache_end - cache);
{
		 * (i.e. marked CE_UNPACKED) at this point. But to be safe,
		if (ce->ce_flags & CE_REMOVE)

			strbuf_setlen(prefix, prefix->len - len - 1);
{
	return df_name_compare(ce_name, ce_len, S_IFREG, name, namelen, mode);
			return error_errno("cannot stat '%s'", ce->name);
		 * Deleted in one and unchanged in the other.
	/*
			if (stages[i] && stages[i] != o->df_conflict_entry) {
				ret = -1;
	}
 * Keep the index entries at stage0, collapse stage1 but make sure
				 struct unpack_trees_options *o)
	const struct index_state *index = o->src_index;
				    struct traverse_info *info)
					 * entry *and* the tree
	struct dir_struct d;
		else if (i + 1 < o->head_idx)
	/*
				      struct traverse_info *info)
	else {
	const struct name_entry *p = names;
					break;
				if (strncmp(ce->name, info->traverse_path,
 * information across a "fast-forward", favoring a successful merge
			continue;
			if (unpack_index_entry(ce, o) < 0)
	if (!strcmp(cmd, "checkout"))
static int verify_clean_submodule(const char *old_sha1,

	 * First let's make sure we do not have a local modification
	if (do_compare_entry(ce, info->prev,
		mark_ce_used(src[0], o);
		if (submodule_from_ce(ce) && file_exists(ce->name)) {
	char label[100];
		_("Cannot update submodule:\n%s");
				if (!newtree)
	if (!o->merge || dirmask != ((1 << n) - 1))
 * cache	: pointer to an index entry
		 * and overwritten with o->result at the end of this function,
				goto return_failed;
		 * If CE_UPDATE is set, verify_uptodate() must be called already
	 * Special case: ERROR_BIND_OVERLAP refers to a pair of paths, we
		 * By default, when CE_REMOVE is on, CE_WT_REMOVE is also
/*

		if (o->update && S_ISGITLINK(old->ce_mode) &&
 *   cache[0]->name[0..(prefix_len-1)]
{
 * is not tracked, unless it is ignored.
}
	}
	/*
 */

static void debug_unpack_callback(int n,
	 *
			 */
	result = index_file_exists(&o->result, name, len, 0);
			ce_len = new_ce_len;
}

			return check_submodule_move_head(ce, oid_to_hex(&ce->oid),
		int len, dtype;
	invalidate_ce_path(ce, o);
		make_empty_cache_entry(istate, len);
		return 0;
		/*
	strbuf_reset(&prefix);
	if (!len)
			error(ERRORMSG(o, ERROR_BIND_OVERLAP),
			 */
	/* ERROR_SPARSE_NOT_UPTODATE_FILE */
	argv_array_init(&opts->msgs_to_free);
				  unsigned long mask,
			struct stat st;
							    oid_to_hex(&ce->oid),
	 * overwritten.
		}
	newinfo.pathspec = info->pathspec;
	 * display_error_msgs()
		return 0;
	 */
			if (verify_uptodate(ce2, o))
			ce = head;


		 */
					     names, info) < 0)
	if (o->trivial_merges_only && o->nontrivial_merge) {
			/* clear_c_f_dir eats a whole dir already? */
 *
{
	int any_anc_missing = 0;
			mark_ce_used_same_name(src[0], o);

			     struct unpack_trees_options *o,
	 */
	if (o->exiting_early)
	trace2_region_enter("unpack_trees", label, the_repository);
	 * because wider traversals don't happen that often and we

}
		 * overwrite it.
		ce->ce_flags &= ~CE_SKIP_WORKTREE;
	ce_name = ce->name + pathlen;
	return verify_uptodate_1(ce, o, ERROR_NOT_UPTODATE_FILE);
			continue;
		/*
			 *

		if (!ce_in_traverse_path(ce, info)) {
		if (new_ce_len > ce_len) {
	int i;
	return add_index_entry(&o->result, ce,
}
		 * ce_name sorts after p->path; could it be that we

		string_list_append(&list, ce->name);
			       struct unpack_trees_options *o)
 * Bind merge.
		 * Previously unmerged entry left as an existence
{
	enum pattern_match_result ret, orig_ret;
		 * Deleted in both.
		if (verify_clean_subdirectory(ce, o) < 0)
		ret = traverse_trees(o->src_index, len, t, &info);

			}
		dfc = xcalloc(1, cache_entry_size(0));
		BUG("pos %d doesn't point to the first entry of %s in index",
 */
			 (oldtree && newtree &&
				return 1;
			return 0;
}
		} else if (oldtree && newtree &&
	string_list_clear(&list, 0);
			 */
		       o->src_index->cache[pos + nr_entries - 1]->name);

			BUG("Wrong condition to get here buddy");
	const struct cache_entry *a = src[1];
			    struct strbuf *prefix,

}

		ret = unpack_failed(o, "Merge requires file-level merging");
				     const char *old_id,
		path = xmemdupz(ce->name, len);
	struct stat st;
			}
		index->cache[i]->ce_flags &= ~CE_MATCHED;
			ce->ce_flags &= ~CE_UPDATE;
	 * Otherwise, insert in a list for future display by
	/*
			 * Unpack existing index entries that sort before the
			int matches;

		    (remote_deleted && head && head_match)) {
			continue;
		return reject_merge(index, o);
		 * below.
	int len = ce_namelen(ce);

		      unsigned int set, unsigned int clear)
}
	if (current) {
	if (unpack_nondirectories(n, mask, dirmask, src, names, info) < 0)
	       oideq(&a->oid, &b->oid);
			    enum pattern_match_result default_match,
		return 0;

		}

		 */
		}
 */
			       const struct traverse_info *info)
		}

		    (head_deleted && remote && remote_match) ||
	strbuf_addch(prefix, '/');
			 */
			int ret = check_submodule_move_head(ce, oid_to_hex(&old->oid),
	if (o->debug_unpack)
		 struct unpack_trees_options *o)
			      struct unpack_trees_options *o)
			if (processed) {

			    struct pattern_list *pl,
	if (o->diff_index_cached)
		; /* keep checking */
static struct cache_entry *create_ce_entry(const struct traverse_info *info,
static void add_entry(struct unpack_trees_options *o,
				struct unpack_trees_options *o);
			return ce;
		return 0;

	ce->ce_flags = create_ce_flags(stage);
	ce->ce_mode = create_ce_mode(n->mode);
						     default_match, progress_nr);
	}
				  const char *cmd)
		flags |= SUBMODULE_MOVE_HEAD_FORCE;
	 * do. But we walk all paths in an iterative loop instead.
static void restore_cache_bottom(struct traverse_info *info, int bottom)
		 * cache entry from the index aware logic.
	strbuf_setlen(&buf[idx], super_prefix_len);
	}
		return verify_clean_submodule(sub_head ? NULL : oid_to_hex(&oid),
		for (i = 1; i < o->head_idx; i++) {
	int nr_entries;
	 */
			goto return_failed;


}

			tree_ce->ce_flags = create_ce_flags(0);

		for (i = 1; i < o->head_idx; i++) {
		/*
{
		head = NULL;
	static struct strbuf buf[2] = {STRBUF_INIT, STRBUF_INIT};
return_failed:
 * This gets called when there was no index entry for the tree entry 'dst',

				return -1;
	string_list_sort(&list);
	int i, ret, bottom;
				 struct checkout *state)
	for (i = 0; i < index->cache_nr; i++)
	}
	if (!strcmp(cmd, "checkout"))
	if (len > MAX_UNPACK_TREES)
		int new_ce_len, len, rc;

	}
static int verify_absent_1(const struct cache_entry *ce,

}

		}
		}
	}
	}
static int compare_entry(const struct cache_entry *ce, const struct traverse_info *info, const struct name_entry *n)


		mark_new_skip_worktree(o->pl, &o->result,

static int unpack_failed(struct unpack_trees_options *o, const char *message)
	    (pos > 0 && starts_with(o->src_index->cache[pos-1]->name, name.buf)))
			/*
	state.force = 1;
			int ret = check_submodule_move_head(ce, NULL,
	while (!p->mode)
	strbuf_release(&name);

				      prefix,
		return 0;
		 * have files under p->path directory in the index?

			  int select_mask, int clear_mask,
		 * also stat info may have lost after merged_entry() so calling
	struct unpack_trees_options *o = info->data;
 * (1) before removing entries from the working tree if the gitmodules file has
		 * New index entries. In sparse checkout, the following
	if (!o->skip_sparse_checkout && !o->pl) {
 *
/*
		} else {
			matches = cache_tree_matches_traversal(o->src_index->cache_tree,
		while (bottom < o->src_index->cache_nr &&

		while (1) {
			update |= CE_UPDATE;

}
					goto return_failed;
/*
	struct cache_entry *src[MAX_UNPACK_TREES + 1] = { NULL, };
		return error("Cannot do a bind merge of %d trees",
		o->cache_bottom = -2 - pos;

	struct unpack_trees_options *o = info->data;
static void add_same_unmerged(const struct cache_entry *ce,
		}
	/* ERROR_WOULD_LOSE_UNTRACKED_OVERWRITTEN */
		o->cache_bottom = bottom;
}
		else
			if (do_add_entry(o, src[i], 0, 0))
				else
					 * entries, we'll skip this
			struct unpack_trees_options *o)
			ce_stage(ce),
{
		int stage;
		msg = advice_commit_before_merge
		msg = advice_commit_before_merge
	int pos;
		return mask;
	int e, i;
	ret = call_unpack_fn(src, o);
				continue;
}

	rval = clear_ce_flags_1(istate,
	return !is_null_oid(&name_j->oid) && !is_null_oid(&name_k->oid) && oideq(&name_j->oid, &name_k->oid);
		_("Updating the following directories would lose untracked files in them:\n%s");
		slash = strchr(name, '/');
		       o->src_index->cache[pos]->name,
		pos = -1 - pos;
		 * have "t/a" in the index.
		 */
		 *
	} else if (!(old->ce_flags & CE_CONFLICTED)) {
		orphaned_error = ERROR_WOULD_LOSE_ORPHANED_OVERWRITTEN;
		if (verify_absent(merge,
		/*
			return 0;
	"Entry '%s' overlaps with '%s'.  Cannot bind.",
		istate->cache_changed |= CE_ENTRY_CHANGED;
		return -1;

			return cmp;
			      struct cache_entry **cache, int nr,
 *
	/* Are we supposed to look at the index too? */
	/* Find first entry with a real name (we could use "mask" too) */
		if (result->ce_flags & CE_REMOVE)
		 */
		rc = call_unpack_fn((const struct cache_entry * const *)src, o);
		 * save and restore cache_bottom anyway to not miss
			if (ce != o->df_conflict_entry)
		if (select_flag && !(ce->ce_flags & select_flag))
			break;
		return -1;
		ce->ce_flags |= CE_UPDATE;
	 * First, if there's a #16 situation, note that to prevent #13
	}
	discard_index(&o->result);
static const char *super_prefixed(const char *path)
 * only in diff-index, and it wants a single callback.  Skip
 * check and change there as well.
			}
		}
	index = stages[0];
}
						  WRITE_TREE_SILENT |
			      struct strbuf *prefix,
#include "unpack-trees.h"

			bottom++;
 * return it.  If name p is a directory in the index, do not return
		      : _("The following untracked working tree files would be removed by checkout:\n%%s");
{
		trace_performance_leave("traverse_trees");
	if (result) {

	int rval;

/*
}

	if (mask == dirmask && !src[0])
 */
	if (!o->update || !o->verbose_update)
	 *
		struct traverse_info info;
		argv_array_pushf(&opts->msgs_to_free, msg, cmd, cmd);
			/* 20 or 21 */
		mark_ce_used_same_name(ce, o);
	return ce;
	static unsigned idx = ARRAY_SIZE(buf) - 1;
{
int oneway_merge(const struct cache_entry * const *src,
	struct cache_entry *merge = dup_cache_entry(ce, &o->result);

#include "progress.h"
		 * Sparse checkout loop #2: set NEW_SKIP_WORKTREE on entries not in loop #1
 *     has been marked for update.  This situation is specified by 'state' != NULL.

	return pos;
			tree_ce = xrealloc(tree_ce, new_ce_len);
			if (r)
		setup_traverse_info(&info, prefix);

			  "Please move or remove them before you %s.")
			memset(tree_ce, 0, new_ce_len);
	while (!p->mode)
		add_entry(o, next, 0, 0);
}
		return o->quiet ? -1 :
	 * avoid the search setup.

 * Error messages expected by scripts out of plumbing commands such as
		invalidate_ce_path(ce, o);
				      pl, ret,
			     const char *path)
			  const char *p, size_t p_len)
	"Entry '%s' not uptodate. Cannot merge.",
		if (o->result.cache_nr && empty_worktree) {
		for (i = 0; i < n; i++) {
	msgs[ERROR_WOULD_LOSE_SUBMODULE] =
				    struct name_entry *names,
	if (orig_ret == UNDECIDED)
	for (i = 0; i < nr_entries; i++) {
		ce->ce_flags |= CE_WT_REMOVE;
	 * get here in the first place.
	int i;
				  struct unpack_trees_options *o)

			submodule_free(the_repository);
		/* special case: "diff-index --cached" looking at a tree */
			 * (because we're already past all possible
				 const struct traverse_info *info)
		ret = orig_ret;
	 * Do what unpack_callback() and unpack_nondirectories() normally
			mark_ce_used(ce2, o);
#endif
		int empty_worktree = 1;
		o->result.split_index = NULL;
	count = 0;
	struct checkout state = CHECKOUT_INIT;
static int check_submodule_move_head(const struct cache_entry *ce,
 * Two-way merge.
	 * 1. Pretend the narrowest worktree: only unmerged entries
{

	struct index_state *istate,
		return error("Cannot do a twoway merge of %d trees",
	return df_name_compare(ce_name, ce_len, S_IFREG, name, namelen, mode);
		show_stage_entry(stderr, "remote ", stages[remote_match]);
	 */
		if (index)
				     struct unpack_trees_options *o)
		else if (i > 1 && are_same_oid(&names[i], &names[i - 2]))
	if (was_skip_worktree && ce_skip_worktree(ce)) {
		src[0] = o->src_index->cache[pos + i];
	const struct cache_entry *oldtree = src[1];
	const struct cache_entry *old = src[0];
 * Perform the loading of the repository's gitmodules file.  This function is

	newinfo.mode = p->mode;
		/*
	if (was_skip_worktree != ce_skip_worktree(ce)) {
		if (index && !same(index, remote) && !same(index, head))


	return 0;
	}
			 * Everything under the name matches; skip the
	    !starts_with(o->src_index->cache[pos]->name, name.buf) ||
	if (should_update_submodules())
		cnt++;
		 * Sparse checkout is meant to narrow down checkout area
	xsnprintf(label, sizeof(label), "clear_ce_flags(0x%08lx,0x%08lx)",
	return -1;
 * them using setup_unpack_trees_porcelain(), for example.
	int pos = o->cache_bottom;

	int len = ce_namelen(ce);
#include "argv-array.h"
		 */
		return add_rejected_path(o, ERROR_NOT_UPTODATE_DIR, ce->name);

	}
 *
	/*
 * we invalidate o->result, we need to update it to use

			return deleted_entry(oldtree, current, o);
	int len = ce_namelen(ce);
	else if (!strcmp(cmd, "merge"))
		 * we will end up overwriting local changes in the work tree.
		      ? _("The following untracked working tree files would be removed by merge:\n%%s"
int verify_uptodate(const struct cache_entry *ce,
	int nr_buf = 0;
	if (errno == ENOENT)


				      select_mask, clear_mask,
		if (ret < 0)
		}
		ret = traverse_by_cache_tree(pos, nr_entries, n, info);
 * NOTE! This *only* compares up to the size of the traverse path
	state->clone = 1;
		pl.use_cone_patterns = core_sparse_checkout_cone;
		return add_rejected_path(o, ERROR_WOULD_LOSE_SUBMODULE, ce->name);
				if (ce_in_traverse_path(ce, &info))
		if (cmp)
	int was_skip_worktree = ce_skip_worktree(ce);
	if (o->clone)
		merge->ce_flags |= CE_NEW_SKIP_WORKTREE;
		return path;
}
		    n == 1 && dirmask == 1 && S_ISDIR(names->mode)) {
	int i;
		      ? _("The following untracked working tree files would be overwritten by merge:\n%%s"
		 * E.g.  ce_name == "t-i", and p->path == "t"; we may
		for (i = 0; i < o->result.cache_nr; i++) {
	if (list.nr) {


			  "on a case-insensitive filesystem) and only one from the same\n"
	msgs[ERROR_BIND_OVERLAP] = _("Entry '%s' overlaps with '%s'.  Cannot bind.");
{
		 * delay returning it.
	string_list_append(&o->unpack_rejects[e], path);
static int same(const struct cache_entry *a, const struct cache_entry *b)
	}
		}
	/* len+1 because the cache_entry allocates space for NUL */

	if (!o->skip_sparse_checkout) {
		free(buf[i]);
	msgs[ERROR_WOULD_LOSE_UNTRACKED_REMOVED] =
	 * Ignore that lstat() if it matches.
				   int show_progress)
			}
		      ? _("Your local changes to the following files would be overwritten by %s:\n%%s"
	 * If we have not precomputed the traverse path, it is quicker

{
			int cmp;
		o->cache_bottom = o->src_index->cache_nr;
				discard_cache_entry(merge);
	struct index_state *index = o->src_index;

			continue;
		 * ce2->name is an entry in the subdirectory to be
	}
		argv_array_pushf(&opts->msgs_to_free, msg, cmd, cmd);
		      ? _("The following untracked working tree files would be overwritten by checkout:\n%%s"
		clear_pattern_list(&pl);
	for (pos = o->cache_bottom; pos < index->cache_nr; pos++) {
			}
		if (!(ce->ce_flags & CE_MATCHED))
{
				   int select_flag, int skip_wt_flag,
		char *path;
	struct stat st;
		move_index_extensions(&o->result, o->src_index);
 */
#define ERRORMSG(o,type) \

		      : _("Your local changes to the following files would be overwritten by checkout:\n%%s");
	nr_entries = all_trees_same_as_cache_tree(n, dirmask, names, info);
	 */
	if (pos >= 0)

			return reject_merge(current, o);
			return -1;
{
		ce_slash = strchr(ce_name, '/');

	if (remote && !df_conflict_head && head_match && !remote_match) {
	if (!!a != !!b)
#include "attr.h"
	}
		}
void setup_unpack_trees_porcelain(struct unpack_trees_options *opts,
	} else if (pl->use_cone_patterns && orig_ret == NOT_MATCHED) {

			ret = default_match;
	o->result.initialized = 1;
		if (src[i] && src[i] != o->df_conflict_entry)
			int i;
 * and we're on a case-insensitive filesystem.
		remote = NULL;
	 * now do the rest.
				break;
	if (show_progress)
	struct name_entry *p;
	if (!old) {
 *
	pos = index_name_pos(o->src_index, name.buf, name.len);
			  same(current, newtree)) || /* 6 and 7 */
	 * in that directory.
	unsigned cnt = 0;
		    ce2->name[namelen] != '/')
	    is_excluded(o->dir, o->src_index, name, &dtype))
		}
		 * verify_uptodate() again may fail
	 */
	int count;
		o->result.split_index = o->src_index->split_index;
			  "Please commit your changes or stash them before you switch branches.")
		      ? _("Your local changes to the following files would be overwritten by merge:\n%%s"
		o->cache_bottom = bottom;
		o->result.split_index->refcount++;
							    oid_to_hex(&ce->oid),

	if (newtree == o->df_conflict_entry)
	struct index_state *index = &o->result;
		 */
}
static int unpack_index_entry(struct cache_entry *ce,
	strbuf_make_traverse_path(&name, info, names->path, names->pathlen);
	if (pos < 0)
			/*
{
				istate->cache,
	"Updating '%s' would lose untracked files in it",

			if (!(ce->ce_flags & CE_UPDATE) ||
	struct cache_entry *ce =
	if (orphaned_error == ERROR_WOULD_LOSE_UNTRACKED_OVERWRITTEN)
int unpack_trees(unsigned len, struct tree_desc *t, struct unpack_trees_options *o)
		unsigned changed = ie_match_stat(o->src_index, ce, &st, flags);
{
		 * o->dst_index (and thus o->src_index) will be discarded
		      : _("The following untracked working tree files would be overwritten by checkout:\n%%s");
	msgs[ERROR_NOT_UPTODATE_DIR] =
			stage = 2;
	o->result.timestamp.nsec = o->src_index->timestamp.nsec;
	if (cmp)
	}
	if (o->cache_bottom < o->src_index->cache_nr &&
	int cmp;
	else
				strbuf_addf(&path, "\t%s\n", rejects->items[i].string);
	/* #1 */

	errs |= finish_delayed_checkout(&state, NULL);
#if DBRT_DEBUG
 * TODO: We should actually invalidate o->result, not src_index [1].
 * o->pl. Do "ce_flags &= ~clear_mask" on those entries. Return the
	 */
	else
		}
	 * We don't bother doing the full O(n^2) search for larger n,
	return -1;
{
 */
	 * anything in the existing directory there.
	free(pathbuf);
			cmp = compare_entry(ce, info, p);
		 * Added in both, identically.
			int r = check_submodule_move_head(ce,
/*
		fprintf(stderr, _("Aborting\n"));

	 */
	}
		info.pathspec = o->pathspec;
			  "Please move or remove them before you merge.")
#include "split-index.h"
	if (!was_skip_worktree && ce_skip_worktree(ce)) {
	opts->show_all_errors = 1;
		report_collided_checkout(index);

			 */
	/* #14, #14ALT, #2ALT */
			/*
{
 * prefix_len	: an offset to its path
		if (lstat(path, &st))
		dtype = ce_to_dtype(ce);
	if (super_prefix_len < 0) {
	if (!o->skip_sparse_checkout && (ce->ce_flags & CE_NEW_SKIP_WORKTREE))

static void mark_all_ce_unused(struct index_state *index)
			 * is always true in this case.

}

			 * cache_bottom entry is already unpacked, so
	 * is being replaced with a blob.
			return -1;
	int namelen;
		progress_nr++;
	 * Sparse checkout loop #1: set NEW_SKIP_WORKTREE on existing entries
	struct unpack_trees_options *o = info->data;
			 */
	o->result.timestamp.sec = o->src_index->timestamp.sec;
			     enum unpack_trees_error_types e,
		if (p_len < ce_len && !memcmp(ce_name, p, p_len) &&
			/*
			ce->ce_flags &= ~skip_wt_flag;
		return 0;
			if (!oid_object_info_extended(the_repository, &ce->oid,
	}
	if (!a && !b)
		newtree = NULL;
			break;
		/*
		  (unsigned long)select_mask, (unsigned long)clear_mask);
			continue; /* keep looking */
	mark_ce_used(ce, o);

	for (i = 0; i < index->cache_nr; i++) {

		} else if (state && (ce->ce_flags & CE_UPDATE)) {
	unsigned long conflicts = info->df_conflicts | dirmask;

	}
	/*
	struct unpack_trees_options *o = info->data;
			   enum unpack_trees_error_types error_type,
	/*
		if (o->prefix) {
	struct tree_desc t[MAX_UNPACK_TREES];
	/*
		oid_array_clear(&to_fetch);
}

	mark_all_ce_unused(o->src_index);
{
	strbuf_setlen(prefix, prefix->len - 1);
		 * ce->name is explicitly excluded, so it is Ok to
			 * Check if we can skip future cache checks
}
					struct traverse_info *info)
			struct cache_entry *ce = src[i + o->merge];
#include "cache-tree.h"
	int i;

static void show_stage_entry(FILE *o,
{
			    unsigned mode)
	if (pl->use_cone_patterns && orig_ret == MATCHED_RECURSIVE) {
	int i;
		 * create a new one.
	 */
static int verify_absent_sparse(const struct cache_entry *ce,
	return errs != 0;
		debug_path(info->prev);
}
	 */

				continue;
{
	if (o->show_all_errors)
		msg = advice_commit_before_merge
	if (o->reset)

	/* Below are "no merge" cases, which require that the index be

		else if (head)

					}
	/*

 * path.
static void mark_new_skip_worktree(struct pattern_list *pl,

		int len = ce_namelen(ce2);
		mark_new_skip_worktree(o->pl, o->src_index, 0,


	for (pos = locate_in_src_index(ce, o); pos < index->cache_nr; pos++) {


		BUG("We need cache-tree to do this optimization");
{
	cache_tree_invalidate_path(o->src_index, ce->name);
 * o->result until unpacking is complete, we invalidate them on
				continue;
 * over a merge failure when it makes sense.  For details of the
}
			  "Please commit your changes or stash them before you %s.")
	"Untracked working tree file '%s' would be overwritten by merge.",
	debug_path(info);
			src[i + o->merge] = o->df_conflict_entry;
				ce = find_cache_entry(info, p);
 * those bits enabled are traversed.
					     basename, &dtype, pl, istate);
		if (!(ce->ce_flags & CE_UPDATE) && verify_uptodate_sparse(ce, o))
}
	       n->path ? n->path : "(missing)");
	static struct cache_entry *dfc;
	msgs[ERROR_WOULD_LOSE_ORPHANED_OVERWRITTEN] =
	"Submodule '%s' cannot checkout new HEAD.",
	}
		 * Do not allow users to do that.
{
	if (!head_match || !remote_match) {
}
			continue;
			      struct pattern_list *pl,
	progress = get_progress(o);
		debug_unpack_callback(n, mask, dirmask, names, info);
					goto return_failed;
		if (select_mask && !(ce->ce_flags & select_mask)) {
static struct cache_entry *find_cache_entry(struct traverse_info *info,
	if (o->dst_index) {
	 * something other than the head: #14(ALT) and #2ALT, where it
{
				discard_cache_entry(ce);
			continue;
	 * we are about to extract "ce->name"; we would not want to lose
			/* 10 or 11 */

{
	int i;
		string_list_clear(rejects, 0);
		return 0;
	/*
	ce_len -= pathlen;
	}
			o->skip_sparse_checkout = 1;

	for (pos = -pos - 1; pos < index->cache_nr; pos++) {
	const struct cache_entry *head;


				 const struct name_entry *names,
	const struct cache_entry *remote = stages[o->head_idx + 1];
							    o);
	const struct cache_entry *index;
		if (!ret) {
			progress_nr += processed;
}
}
static int all_trees_same_as_cache_tree(int n, unsigned long dirmask,
static inline int call_unpack_fn(const struct cache_entry * const *src,
				"HEAD", oid_to_hex(&ce->oid), o);
	}
}
/*
	printf("* unpack mask %lu, dirmask %lu, cnt %d ",
				if (ce_stage(ce)) {

static void load_gitmodules_file(struct index_state *index,
	if (!o->skip_sparse_checkout && (ce->ce_flags & CE_NEW_SKIP_WORKTREE))
		       o->src_index->cache[bottom]->ce_flags & CE_UNPACKED)
		if (!df_conflict_remote && remote_match && !head_match)
			super_prefix_len = buf[0].len;

			       ADD_CACHE_OK_TO_ADD | ADD_CACHE_OK_TO_REPLACE);
			if (!o->result.cache_tree)
		if (!o->merge)
			for (i = 0; i < rejects->nr; i++)
static int verify_uptodate_1(const struct cache_entry *ce,
	return 1;
						       select_mask, clear_mask,
	/*
			repo_read_gitmodules(the_repository, 0);
 * We call unpack_index_entry() with an unmerged cache entry
		 * we don't care.
		display_progress(istate->progress, progress_nr);

			return merged_entry(head, index, o);
			if (!ce_skip_worktree(ce))
	const struct cache_entry *old = src[0];

 * entry having more data at the end!
	int ret, pos;
		if (!changed)
	int ce_len = 0;
						return mask;
	static int super_prefix_len = -1;
{
	return 0;
 * path. We'll walk these trees in an iterative loop using cache-tree/index

		      ? _("The following untracked working tree files would be overwritten by %s:\n%%s"
		return 0;
	if (!o->quiet && !o->exiting_early) {
		return cmp;
 *
 * without actually calling it. If you change the logic here you may need to
			}
	clear_ce_flags(istate, select_flag, skip_wt_flag, pl, show_progress);
	if (ce->ce_flags & CE_NEW_SKIP_WORKTREE)
	}
 * instead of ODB since we already know what these trees contain.
		      struct unpack_trees_options *o)
 * Check that checking out ce->sha1 in subdir ce->name is not
	const char *ce_name;
			super_prefix_len = 0;
	"Working tree file '%s' would be overwritten by sparse checkout update.",
	for (i = 0; i < n; i++)

				&prefix,
	/*
	 */
		const char *prefix = o->prefix ? o->prefix : "";

		 * so just use src_index's split_index to avoid having to
		index->cache[i]->ce_flags &= ~(CE_UNPACKED | CE_ADDED | CE_NEW_SKIP_WORKTREE);
		/*
		int cmp, ce_len;
			 * correct CE_NEW_SKIP_WORKTREE
		const struct cache_entry *ce = index->cache[i];
			o->pl = &pl;
	/* ERROR_WOULD_LOSE_UNTRACKED_REMOVED */
					      struct index_state *index)
	return rc;
{
	}
			  "Please move or remove them before you switch branches.")
	pos = find_cache_pos(info->prev, info->name, info->namelen);
		if (add_patterns_from_file_to_list(sparse, "", 0, &pl, NULL) < 0)

				if (!ce)
		 * If the merge bit is set, then the cache entries are
						name, &dtype, pl, istate);


			ce = index;
 * used by 'check_update()' to perform loading of the gitmodules file in two

{
			  "Please move or remove them before you merge.")
		struct cache_entry *next = index->cache[pos];

#endif

	}
		const char *name, *slash;
static int locate_in_src_index(const struct cache_entry *ce,
		is_transient ?

		mark_ce_used(next, o);

		discard_index(&o->result);
			invalidate_ce_path(ce, o);
			   struct unpack_trees_options *o)
 * One-way merge.
		if (verify_uptodate(index, o))
#if DBRT_DEBUG
	int update = CE_UPDATE;
		const struct cache_entry *ce = index->cache[cnt];
	printf("%s", info->name);
		}
{
	/*
	 * conflict resolution files.
 * src_index instead with the assumption that they will be copied to
	if (o->aggressive) {
				return -1;
			something_displayed = 1;
		return 0;
	struct unpack_trees_options *o = info->data;

				++o->cache_bottom;
	if (!info->traverse_path)
	oidcpy(&ce->oid, &n->oid);

		 */
			      char *basename,
	/*
			t[i] = t[i - 1];
				return ret;
	if (!ce)
{
			      struct unpack_trees_options *o)
	}
	return add_rejected_path(o, ERROR_WOULD_OVERWRITE, ce->name);
		istate->progress = start_delayed_progress(
						ce_namelen(ce),

	 * Matched entries will have skip_wt_flag cleared (i.e. "in")
{
 * N-way merge "len" trees.  Returns 0 on success, -1 on failure to manipulate the
	if (head) { count += keep_entry(head, o); }
				       CE_NEW_SKIP_WORKTREE, o->verbose_update);
	return check_submodule_move_head(ce, old_sha1,
		 * traverse_trees() finishes in unpack_trees(), then:
 * Top level path has prefix_len zero.
 * o->result.cache_tree as well.
 *     been marked for removal.  This situation is specified by 'state' == NULL.

			    int progress_nr)
		else {
			display_progress(progress, ++cnt);
			const struct object_id *oid = NULL;


 * matches the stat information, and assume it's that other file!
	}
	}
			     enum unpack_trees_error_types error_type)

				enum unpack_trees_error_types error_type,
	int i, ret;
	int cnt = 0;
	p = names;
	state.refresh_cache = 1;
				ret = check_ok_to_remove(path, len, DT_UNKNOWN, NULL,
{
 */
				src[0] = ce;

		int remote_deleted = !remote;

		if (!(ce->ce_flags & CE_UNPACKED))
	}
	int pos;
			    int progress_nr);
		return ret;
			 * entire hierarchy.  diff_index_cached codepath
		const char *super_prefix = get_super_prefix();

			checkout_entry(ce, state, NULL, NULL);
		 * but it does not make sense to narrow down to empty working
				return -1;
		}
				update |= CE_UPDATE;
		 */
		}
	int no_anc_exists = 1;

	add_entry(o, ce, CE_REMOVE, 0);
		struct cache_entry *ce2 = o->src_index->cache[i];
		if (!ce_stage(ce2)) {
				strbuf_addstr(&buf[i], super_prefix);
	if (i)
}
			if (ret)
}
		if (!stages[i] || stages[i] == o->df_conflict_entry)
	if (!head && !remote && any_anc_missing)
		name = ce->name + prefix->len;
				     const char *new_id,
			 same(current, oldtree) && !same(current, newtree)) {
					 oid_to_hex(&ce->oid), o);

/*
					  ce_to_dtype(ce), ce, &st,
		df_conflict_head = 1;

		      : _("Your local changes to the following files would be overwritten by merge:\n%%s");
	if (remote) { count += keep_entry(remote, o); }

			return -1;
}
	int pfxlen = info->pathlen;
	if (!submodule_from_ce(ce))
	if (!sub)


		struct string_list *rejects = &o->unpack_rejects[e];
		else {
 */
		debug_name_entry(i, names + i);
	strbuf_addstr(&buf[idx], path);

	 * }
		new_ce_len = cache_entry_size(len);
	int i, d;
	return verify_uptodate_1(ce, o, ERROR_SPARSE_NOT_UPTODATE_FILE);
	    o->src_index->cache[o->cache_bottom] == ce) {
				    unsigned long df_conflicts,
 */
static int clear_ce_flags(struct index_state *istate,
		if (o->reset && o->update && !ce_uptodate(old) && !ce_skip_worktree(old) &&
				      unsigned mode)
				ret = check_submodule_move_head(ce,
			ret = error_errno("cannot stat '%s'", path);
 * (2) before checking out entries to the working tree if the gitmodules file
	memset(&o->result, 0, sizeof(o->result));
	if (pos >= 0) {
	 *
	return ret;
	return ce_namelen(ce) > traverse_path_len(info, tree_entry_len(n));

 * [1] src_index->cache_tree is also used in unpack_callback() so if
		 * verify_absent() will be delayed until after
 */
						add_same_unmerged(ce, o);

 * Traverse the index, find every entry that matches according to
	ret = unpack_failed(o, NULL);
					struct name_entry *names,
						       prefix->buf + prefix->len - len,

	untracked_cache_invalidate_path(o->src_index, ce->name, 1);

	/* If ce_len < pathlen then we must have previously hit "name == directory" entry */
							       names, info);
			    int select_mask, int clear_mask,
			break;
	const struct cache_entry *src;
		msg = advice_commit_before_merge
				progress_nr += processed;
	if (head) {
	 * cannot easily display it as a list.
 * Note that traverse_by_cache_tree() duplicates some logic in this function
	 *	This is perfectly normal. Move on;
			return 0;
	struct cache_entry *src[MAX_UNPACK_TREES + 1] = { NULL, };
	namelen = ce_namelen(ce);
		else {
	/* Did it exist in the index? */

{
	ce->ce_flags |= CE_UNPACKED;
		if (!state && ce->ce_flags & CE_WT_REMOVE) {
		p++;
			      int progress_nr)
	printf("ent#%d %06o %s\n", i,
		return deleted_entry(old, old, o);
	else

	       struct unpack_trees_options *o)
			    const struct traverse_info *info,
	const struct submodule *sub = submodule_from_ce(ce);
		while (ce < cache_end) {

			if (apply_sparse_checkout(&o->result, ce, o)) {
	}
	 * Ok, we've filled in up to any potential index entry in src[0],
			strbuf_release(&path);
		 * unprocessed entries before 'pos'.
			 (!oldtree && newtree &&
/*
{
{
static int find_cache_pos(struct traverse_info *, const char *p, size_t len);
	 * if (!was_skip_worktree && !ce_skip_worktree()) {
	if (o->diff_index_cached)
		df_conflict_remote = 1;

	/*
		 * This also removes the UPDATE flag on a match; otherwise

	trace_performance_leave("unpack_trees");
			    ie_match_stat(o->src_index, old, &st, CE_MATCH_IGNORE_VALID|CE_MATCH_IGNORE_SKIP_WORKTREE))
 *
#include "tree.h"
 * Compare the traverse-path to the cache entry without actually
				empty_worktree = 0;
							    o);
		if (slash) {
static int verify_absent_sparse(const struct cache_entry *ce,
		warning(_("the following paths have collided (e.g. case-sensitive paths\n"
	display_progress(istate->progress, progress_nr);
		return 1;
			return 0;
static int icase_exists(struct unpack_trees_options *o, const char *name, int len, struct stat *st)
 * The rule is:
static struct progress *get_progress(struct unpack_trees_options *o)
		if (!cmp)
	if (info->prev) {
}
	}
			any_anc_missing = 1;
	goto done;
		if (message)
		if (!o->merge || df_conflicts)
	if (nr_entries > 0) {

	state.quiet = 1;
		 * If the will have NEW_SKIP_WORKTREE, also set CE_SKIP_WORKTREE
		oidcpy(&tree_ce->oid, &src[0]->oid);
	}
		errno = 0;

		msg = advice_commit_before_merge
	 * are checked out
	for (i = 1; i < n; i++)
			  "Please move or remove them before you switch branches.")
	ce_len = ce_namelen(ce);
			if (verify_uptodate(old, o)) {

			if (!cmp) {
			break;
	} else {
			no_anc_exists = 0;

			new_ce_len <<= 1;

	memset(&d, 0, sizeof(d));

/*
				count++;
	mark_all_ce_unused(o->src_index);

}
 *
		rc = cache_end - cache;
static int verify_absent(const struct cache_entry *,
	int ret;
 * the other unmerged entry with the same name.
		die("unpack_trees takes at most %d trees", MAX_UNPACK_TREES);
	/* rejected paths may not have a static buffer */
		else
	while(cache != cache_end) {
			free(tree_ce);
			unlink_entry(ce);
		struct cache_entry *ce = *cache;


 * The tree traversal is looking at name p.  If we have a matching entry,
		struct cache_entry *ce = *cache_end;

		ce->ce_flags &= ~CE_UPDATE;
			ce->ce_mode,
			}
	 * outside checkout area
			for (i = 0; i < ARRAY_SIZE(buf); i++)
	pathlen = info->pathlen;
		 */
		unsigned int bit = 1ul << i;
 * check and change there as well.
	if (!(old->ce_flags & CE_CONFLICTED) && verify_uptodate(old, o))
 * having to generate the textual representation of the traverse
	 */
				break;
		if (submodule_from_ce(ce) && file_exists(ce->name)) {
	else if (newtree) {

static int do_compare_entry(const struct cache_entry *ce,
	if (o->merge_size != 2)
	ce_len = ce_namelen(ce);
	"Working tree file '%s' would be removed by sparse checkout update.",

		msg = advice_commit_before_merge
			 * we can never match it; don't check it
	if (!o->keep_pattern_list)
		 */
	 * present file that is not ignored.
		}
	remove_scheduled_dirs();
		 */
}
		return merged_entry(newtree, current, o);

/*
		fprintf(stderr, "read-tree: warning #16 detected\n");
			if (!ce)
		}
	/* Now handle any directories.. */
		o->result.updated_workdir = 1;
					ce = stages[i];

			return keep_entry(current, o);
			display_progress(progress, ++cnt);

		return 0;
	const struct cache_entry *a = src[1];
	       mask, dirmask, n);
static int switch_cache_bottom(struct traverse_info *info)


	 * 2. Widen worktree according to sparse-checkout file.
{
		int flags = CE_MATCH_IGNORE_VALID|CE_MATCH_IGNORE_SKIP_WORKTREE;
				strbuf_setlen(prefix, prefix->len - len);
		enum pattern_match_result ret;
			if (o->diff_index_cached)
		} else {
	}
		      ? _("Your local changes to the following files would be overwritten by checkout:\n%%s"
					 * If we skip unmerged index

	if (pos >= o->src_index->cache_nr ||
	if (ce_len < pathlen)
	} else {
	for (i = 0; i < n; i++, dirmask >>= 1) {
				       o->verbose_update);
		 *    correct CE_NEW_SKIP_WORKTREE
		return error("Cannot do a oneway merge of %d trees",
	/*
		/* If it's a directory, try whole directory match first */
}
		while (1) {
			add_entry(o, ce2, CE_REMOVE, 0);
 * and in fact are encouraged to reword them to better suit their particular
 * but we found a file in the working tree that 'lstat()' said was fine,
		struct cache_entry *ce = index->cache[i];

}
		int rc = call_unpack_fn((const struct cache_entry * const *)src,
	int pos = index_name_pos(index, ce->name, len);
				}
		 *  - CE_NEW_SKIP_WORKTREE will be computed correctly
				if (unpack_index_entry(ce, o) < 0)
	ret = o->cache_bottom;
	if (ce_stage(ce))
		struct cache_entry *ce = index->cache[pos];
	 * delete this path, which is in a subdirectory that
 * But since cache tree and untracked cache both are not copied to
			return 0;
	 * Make sure they don't modify worktree if they are already
			if (lstat(old->name, &st) ||
	argv_array_clear(&opts->msgs_to_free);
		}

		ce->ce_flags |= CE_SKIP_WORKTREE;
 */
	trace2_region_leave("unpack_trees", label, the_repository);
		return 0;
			ce->ce_flags &= ~clear_mask;

	if (!core_apply_sparse_checkout || !o->update)

			/*
				  unsigned long dirmask,
		struct cache_entry **ce = cache;
			ce_len = ce_slash - ce_name;
			if (same(stages[i], remote)) {
		return -1;
	ce_name = ce->name + pathlen;
		 * verify_absent() call here does nothing in sparse
		if (rc < 0) {

	if (!old) {
			    struct cache_entry **cache, int nr,

#include "submodule.h"
	const struct name_entry *n,
	for (i = 0; i < index->cache_nr; i++)
	if (S_ISDIR(st->st_mode)) {

			 enum unpack_trees_error_types,
			return reject_merge(oldtree, o);
			mark_ce_used(src[0], o);
			if (ret)
			 * verify_absent() check (the check is effectively disabled

				cache_tree_verify(the_repository, &o->result);
 * add error messages on path <path>
			return -1;
			 * prefix the tree is spliced into.  Note that o->merge
	for (i = 0; i < ARRAY_SIZE(opts->unpack_rejects); i++)
	 */
			progress_nr++;
#include "object-store.h"
 * Set/Clear CE_NEW_SKIP_WORKTREE according to $GIT_DIR/info/sparse-checkout
{
	mark_all_ce_unused(o->src_index);


		 * checkout (i.e. o->skip_sparse_checkout == 0)
						       progress_nr);
	}
			if (pos == o->cache_bottom)
		/*
	 * make sure that it matches head.
	 * target 'ce' was absent, because there is an old
	if (o->merge_size != 1)
			    struct cache_entry **cache, int nr,
		argv_array_pushf(&opts->msgs_to_free, msg, cmd, cmd);
							 NULL, o);
	for (i = locate_in_src_index(ce, o);
	o->nontrivial_merge = 1;
						     prefix,
		 * not considered interesting above, we don't care here.
	if (ce_stage(ce)) {
			}
 * dst_index at the end.
			  "Please move or remove them before you %s.")
		 */
 * anything, as we will want to match it when the traversal descends into
		struct cache_entry *ce = istate->cache[i];
		 * Prefetch the objects that are to be checked out in the loop
	}
		} else if (oldtree && !newtree && same(current, oldtree)) {

			return 0;
	while (pos < index->cache_nr) {
}
}

	if (old && same(old, a)) {
		if (len != ce_namelen(next) ||
	int something_displayed = 0;
		if (ce->ce_flags & (CE_UPDATE | CE_WT_REMOVE))
{
		opts->unpack_rejects[i].strdup_strings = 1;

	 * because cache-tree would be invalidated and we would never
	char *pathbuf;
static void debug_path(struct traverse_info *info)
	 *

			 struct unpack_trees_options *o)
}
}
		ce->ce_flags |= CE_UPDATE_IN_BASE;
static int clear_ce_flags_1(struct index_state *istate,
		 * removed.
	do_add_entry(o, dup_cache_entry(ce, &o->result), set, clear);
static int reject_merge(const struct cache_entry *ce,
	 */
	trace_performance_leave("check_updates");
	return add_rejected_path(o, error_type, ce->name);
	int i;


				      const struct traverse_info *info,
				ret = -1;
int threeway_merge(const struct cache_entry * const *stages,
	if (!super_prefix_len)
	git_attr_set_direction(GIT_ATTR_CHECKIN);
	 * cases that we historically had git-merge-one-file resolve.
	struct cache_entry **cache_end;
					break;
		 * not stored in the index.  otherwise construct the
		return check_ok_to_remove(ce->name, ce_namelen(ce),
	/*
	return count;
	 * When 2 peer OIDs are the same, we just copy the tree
		/*
		memcpy(tree_ce->name, src[0]->name, len + 1);
				  struct traverse_info *info)
	int i;
			      enum unpack_trees_error_types error_type,
				BUG("both update and delete flags are set on %s",
#include "fsmonitor.h"
			    int select_mask, int clear_mask,
	/* ERROR_NOT_UPTODATE_DIR */
				istate->cache_nr,
	 */
		display_error_msgs(o);
			return 0;
		msg = advice_commit_before_merge
				  struct unpack_trees_options *o)
	}
	ret = traverse_trees(o->src_index, n, t, &newinfo);
				struct cache_entry *ce = next_cache_entry(o);
	return a->ce_mode == b->ce_mode &&
	"Untracked working tree file '%s' would be removed by merge.",
		 struct unpack_trees_options *o)
	 */
 * If select_mask is non-zero, only entries whose ce_flags has on of
	 * Under the "aggressive" rule, we resolve mostly trivial
	}
			ce_len = ce_namelen(ce) - pfxlen;
		return;
 */
		 * them.
 */
	}
	const char **msgs = opts->msgs;

		if (!(mask & bit))
		 * files that are in "foo/" we would lose
			     info->name, info->namelen, info->mode))
		else
		}

			label,
	if (ce_stage(ce))
	int df_conflict_remote = 0;
	int is_transient)
			  "Please commit your changes or stash them before you merge.")
			for (i = 1; i < o->head_idx; i++) {
	 * If ce (blob) is the same name as the path (which is a tree
				if (!o->show_all_errors)
#include "refs.h"


}
	/*
	/* ERROR_WOULD_OVERWRITE */
		die("programming error in a caller of mark_ce_used_same_name");
{
		 * See if we can re-use the old CE directly?
	/* Do we have *only* directories? Nothing to do */
static void setup_collided_checkout_detection(struct checkout *state,
	if (!info->prev)
static int index_pos_by_traverse_info(struct name_entry *names,
	int rc;
			(*ce)->ce_flags &= ~clear_mask;
			errs |= checkout_entry(ce, &state, NULL, NULL);
	return buf[idx].buf;
		 */
		 * This is tricky -- if we have modified
		if (ret == MATCHED || ret == MATCHED_RECURSIVE)
		for (i = 0; i < index->cache_nr; i++) {
	 * Process all entries that have the given prefix and meet
		/*

	int pos = index_name_pos(index, GITMODULES_FILE, strlen(GITMODULES_FILE));
		int ret;
		      : _("The following untracked working tree files would be removed by merge:\n%%s");
	git_attr_set_direction(GIT_ATTR_CHECKOUT);
		    memcmp(ce->name, next->name, len))
		 * marker by read_index_unmerged();
		}
		}
	if (!a || a == o->df_conflict_entry)

	if (!same(remote, head)) {
				keep_entry(stages[i], o);
		if (S_ISGITLINK(ce->ce_mode))
	 */
			 * because CE_NEW_SKIP_WORKTREE is set unconditionally).
		if (ce->ce_flags & CE_UPDATE) {
		return -1;

		return do_compare_entry_piecewise(ce, info, name, namelen, mode);
			strbuf_add(prefix, name, len);
	}
	const char *msg;
	struct unpack_trees_options *o = info->data;
	int i;
						  WRITE_TREE_REPAIR);
			continue;

	return ret;
		return 0;
		      ? _("The following untracked working tree files would be removed by checkout:\n%%s"
		}
		    should_update_submodules() && !verify_uptodate(old, o))

		return ret;
		/*
			break;
		/* Non-directory */
	struct unpack_trees_options *o = info->data;
	if (was_skip_worktree && !ce_skip_worktree(ce)) {
	if (!o->skip_sparse_checkout)
		show_stage_entry(stderr, "head   ", stages[head_match]);
	memset(&pl, 0, sizeof(pl));
			if (same(oldtree, newtree))


	if (!ce)
		if (ret < 0)
	void *buf[MAX_UNPACK_TREES];
		if (submodule_from_ce(ce))
	if (o->quiet)
		src[i + o->merge] = create_ce_entry(info, names + i, stage, &o->result, o->merge);
#include "config.h"
					break;
	return pos;
						     info->mode);
/*

	/* ERROR_WOULD_LOSE_ORPHANED_REMOVED */
			    enum pattern_match_result default_match,
		/* #5ALT, #15 */
				return add_rejected_path(o, error_type, ce->name);

		if (prefix->len && strncmp(ce->name, prefix->buf, prefix->len))
		remove_marked_cache_entries(index, 0);

	for (i = 0; i < index->cache_nr; i++) {
	struct cache_entry **cache_end = nr ? cache + nr : cache;
			 struct unpack_trees_options *o)
		}

			struct cache_entry *ce = o->result.cache[i];
		/*
{
	if (ignore_case && icase_exists(o, name, len, st))


				       CE_ADDED, CE_SKIP_WORKTREE | CE_NEW_SKIP_WORKTREE,
	return 1;
						     select_mask, clear_mask, pl,
}
	if (info->prev) {
				if (unpack_index_entry(ce, o) < 0)
	if (!dfc)
static void display_error_msgs(struct unpack_trees_options *o)
		ret = path_matches_pattern_list(ce->name,

	else if (!strcmp(cmd, "merge"))
			struct cache_entry *ce;
				pl, 0, 0);
		trace_performance_leave("check_updates");

static void report_collided_checkout(struct index_state *index)
		pos++;

	}
		return -1;
	} else {
	}

 * stage0 does not have anything there.
	if (!o->update || o->dry_run) {
	}
		if (!sub_head && oideq(&oid, &ce->oid))
				  struct name_entry *names,
			update |= old->ce_flags & (CE_SKIP_WORKTREE | CE_NEW_SKIP_WORKTREE);

			len = slash - name;
}
		ce->ce_flags &= ~CE_UPDATE;

			if (!ce)
		   struct unpack_trees_options *o)
		if (errno != ENOENT)
}
			ce->ce_flags &= ~CE_WT_REMOVE;
		ce_name = ce->name + pfxlen;
			cache++;
static void mark_ce_used_same_name(struct cache_entry *ce,
		 */
			repo_read_gitmodules(the_repository, 0);
	pos = -pos - 1;
	bottom = switch_cache_bottom(&newinfo);
 * See if we can find a case-insensitive match in the index that also
			total++;
			stage = 0;
	/*
		ret = 0;
				oid = &names[i].oid;
			 * it does not do any look-ahead, so this is safe.
}
}
		else
	 * It may be that the 'lstat()' succeeded even though
		}
	int pos = find_cache_pos(info, p->path, p->pathlen);
		      ? _("The following untracked working tree files would be removed by %s:\n%%s"
#include "repository.h"
		return;
			 * Entries marked with CE_ADDED in merged_entry() do not have

	if (a && old)
/*
				if (stages[i] && stages[i] != o->df_conflict_entry) {
		BUG("This is a directory and should not exist in index");
	return deleted_entry(oldtree, current, o);
			struct strbuf path = STRBUF_INIT;
	if (o->merge) {
		tree_ce->ce_mode = src[0]->ce_mode;
			if (index)
{
		setup_collided_checkout_detection(&state, index);
	 * it is quicker to use the precomputed version.
						     info->name, info->namelen,
	o->result.version = o->src_index->version;
	for (cache_end = cache; cache_end != cache + nr; cache_end++) {

	struct cache_entry *tree_ce = NULL;

#include "dir.h"
		      const struct cache_entry *ce,
		else if (remote)
 * Note that traverse_by_cache_tree() duplicates some logic in this function
	}

			copy_cache_entry(merge, old);
	if (ce_len < pathlen)
	o->cache_bottom = bottom;
		      : _("The following untracked working tree files would be overwritten by %s:\n%%s");
		else if (i + 1 > o->head_idx)
static inline int are_same_oid(struct name_entry *name_j, struct name_entry *name_k)

	 * Then we need to make sure that we do not lose a locally

{
	else
static int traverse_trees_recursive(int n, unsigned long dirmask,
		char *sparse = git_pathdup("info/sparse-checkout");
	  ? ((o)->msgs[(type)])      \

	newinfo.pathlen = st_add3(newinfo.pathlen, tree_entry_len(p), 1);
			 (oldtree && newtree &&
					if (o->skip_unmerged) {
		if (len < namelen ||
	}

		 * bother remove it.
{
	/* ERROR_WOULD_LOSE_ORPHANED_OVERWRITTEN */

			invalidate_ce_path(old, o);
	 * up-to-date to avoid the files getting overwritten with
 */
 *

	if (head == o->df_conflict_entry) {
/*
		 * discarded in the following block.  In this case,
	struct pattern_list pl;
static int deleted_entry(const struct cache_entry *ce,
	return cnt;
		if (conflicts & bit) {
	if ((a->ce_flags | b->ce_flags) & CE_CONFLICTED)
		int bottom = o->cache_bottom;

	if (o->clone)
 * CE_ADDED, CE_UNPACKED and CE_NEW_SKIP_WORKTREE are used internally
		/*
	"Entry '%s' not uptodate. Cannot update sparse checkout.",
	struct unpack_trees_options *o = info->data;
						       prefix,
		/* #13, #3ALT */
 * itself - the caller needs to do the final check for the cache

	 * Fetch the tree from the ODB for each peer directory in the
	}
	if (o->merge_size != 1)
				head_match = i;
		o->result.split_index = init_split_index(&o->result);
	}
	if (o->dir &&

/*
	if (index && !same(index, head))
static int traverse_by_cache_tree(int pos, int nr_entries, int nr_names,
			    struct pattern_list *pl,


	make_traverse_path(ce->name, len + 1, info, n->path, n->pathlen);
		return o->src_index->cache[pos];


	} else {
	else
				struct unpack_trees_options *o)
	 * entry that is different only in case..

 */
		idx = 0;
					/*
							 &st, error_type, o);
				 unsigned long dirmask,
			if (info->traverse_path) {
			return -1;
					    info->pathlen) > 0)
	if (!o->src_index->split_index) {
	newinfo.name = p->path;
				      progress_nr);
		if (no_anc_exists && head && remote && same(head, remote))
		if (len != ce_namelen(next) ||
		       nr_entries,
		if (verify_absent(ce, ERROR_WOULD_LOSE_UNTRACKED_REMOVED, o))
	 */
	 *
	msgs[ERROR_WOULD_OVERWRITE] = msgs[ERROR_NOT_UPTODATE_FILE] =
			if (same(oldtree, newtree) || o->reset) {

				return ret;
		return 0;
		if (ce_stage(src[0]))
		invalidate_ce_path(old, o);

					_("Updating index flags"),
				remote_match = i;
					return deleted_entry(current, current, o);
	pathlen = info->pathlen;
		goto done;
			error(ERRORMSG(o, e), super_prefixed(path.buf));
	if (o->merge && src[0]) {
		if (ce->ce_flags & CE_WT_REMOVE) {

			return reject_merge(index, o);
	const struct cache_entry *newtree = src[2];
		 * found "foo/." in the working tree.

	if (pos < -1)
			cache += processed;
	memset(opts->msgs, 0, sizeof(opts->msgs));
done:
					istate->cache_nr);
 */
	if (o->dir)
		o->result.fsmonitor_last_update = o->src_index->fsmonitor_last_update;

				return mask;
		}

		}
		info.fn = unpack_callback;
		return 0;
		cmp = name_compare(p, p_len, ce_name, ce_len);
	}
	return ret;
		 *  - verify_absent() be called again, this time with
	if (o->debug_unpack)
		if (ret == UNDECIDED)
	else if (pos < 0)
 * situation better.  See how "git checkout" and "git merge" replaces
	return merged_entry(a, old, o);
	return (info->pathlen < ce_namelen(ce));
		return keep_entry(old, o);
		if (same(old, merge)) {
				return deleted_entry(index, index, o);

	newinfo.df_conflicts |= df_conflicts;
		mark_fsmonitor_invalid(istate, ce);
{
			else
		if ((head_deleted && remote_deleted) ||
	for (i = 0; i < istate->cache_nr; i++) {
	int cmp = do_compare_entry(ce, info, n->path, n->pathlen, n->mode);
		if (0 < cmp)
	ce->ce_flags = (ce->ce_flags & ~clear) | set;
		if (*info->prev->name)
	if (o->index_only)
	 */
		rc = cache_end - cache;
}
					return -1;
static int verify_clean_subdirectory(const struct cache_entry *ce,
#include "cache.h"
	ce_len -= pathlen;
		if (traverse_trees_recursive(n, dirmask, mask & ~dirmask,
					 */
{
				select_mask, clear_mask,
			       struct unpack_trees_options *o)
static int unpack_callback(int n, unsigned long mask, unsigned long dirmask, struct name_entry *names, struct traverse_info *info)
{
	oidcpy(&o->result.oid, &o->src_index->oid);
{

		discard_index(o->dst_index);
	return -1;
		 */
			      super_prefixed(a->name),
	} else {
		if (submodule_from_ce(ce)) {
		invalidate_ce_path(merge, o);
	add_entry(o, ce, 0, 0);
	  : (unpack_plumbing_errors[(type)]) )
static int check_updates(struct unpack_trees_options *o)
	for (i = 0; i < nr_buf; i++)
/*
		 */
{
		/*
			stage = 1;
				  const struct cache_entry *ce,
		break;
		return 0;
			}
			return merged_entry(head, index, o);
		o->skip_sparse_checkout = 1;
		d.exclude_per_dir = o->dir->exclude_per_dir;
 * different situations:

		info.data = o;
			/*
}
}
			struct cache_entry *ce = next_cache_entry(o);
	list.cmp = fspathcmp;
				    ce->name);

	return verify_absent_1(ce, error_type, o);
			    struct strbuf *prefix,
		 * on to get that file removed from both index and worktree.
		return cmp;
			if (!cache_tree_fully_valid(o->result.cache_tree))
{
		}
};
		return -1;
				     struct unpack_trees_options *o)
	struct index_state *index = o->src_index;
		return -1;
		      : _("The following untracked working tree files would be removed by %s:\n%%s");
	"Entry '%s' would be overwritten by merge. Cannot merge.",
	 * to avoid doing so.  But if we have precomputed it,
 */
	msgs[ERROR_WOULD_LOSE_UNTRACKED_OVERWRITTEN] =
	if (remote == o->df_conflict_entry) {
{
	struct strbuf name = STRBUF_INIT;

		 */
	 */
			else
			int processed;
	if (cmp)

	src = index_file_exists(o->src_index, name, len, 1);
	}
	 * here, as the return value of this function is fed to
				src[d] = tree_ce;
 * We do not want to remove or overwrite a working tree file that
		    pos, name.buf);
		 * All entries up to 'pos' must have been processed
	       n->path ? n->mode : 0,
	}
			}
			add_entry(o, ce, 0, 0);
			stage = 3;
	clear |= CE_HASHED;
	return src && !ie_match_stat(o->src_index, src, st, CE_MATCH_IGNORE_VALID|CE_MATCH_IGNORE_SKIP_WORKTREE);
				continue;


			oid_to_hex(&ce->oid),

	if (has_promisor_remote()) {
								oid_to_hex(&ce->oid),
				 struct cache_entry *ce,
	else
static int ce_in_traverse_path(const struct cache_entry *ce,
					    const struct name_entry *p)
			}

		 * Exact match; if we have a directory we need to
	pathbuf = xstrfmt("%.*s/", namelen, ce->name);
		 * If we are not going to update the submodule, then

int bind_merge(const struct cache_entry * const *src,
	 * CE_VALID and CE_SKIP_WORKTREE cheat, we better check again
 * without actually calling it. If you change the logic here you may need to
		return 0;
			if (ce && !head_deleted) {
			goto return_failed;
		/*

		    ce_name[p_len] < '/')
	else
		if (oldtree && !o->initial_checkout) {
static struct cache_entry *next_cache_entry(struct unpack_trees_options *o)
			if (cmp < 0) {
		 * Historic default policy was to allow submodule to be out
/* Here come the merge functions */
		/*
static int add_rejected_path(struct unpack_trees_options *o,
	src[0] = ce;
		return merged_entry(remote, index, o);
			struct unpack_trees_options *o)
		cache++;
	if (!a)
	struct index_state *index = o->src_index;
{
 *

			if (dirmask & 1)
	for (i = 0; i < n; i++) {
	 */
	remove_marked_cache_entries(index, 0);
 * resulting index, -2 on failure to reflect the changes to the work tree.
	     i < o->src_index->cache_nr;
	 */


	 */
}
	int pos;
	int i;
	if (o->index_only || o->reset || !o->update)
	head = stages[o->head_idx];
		load_gitmodules_file(index, &state);
{
{
	return 1;
static int verify_absent(const struct cache_entry *ce,
		return 0;
	enable_delayed_checkout(&state);
				 struct unpack_trees_options *o)
	}
	newinfo.namelen = p->pathlen;
	if (oldtree == o->df_conflict_entry)
	i = read_directory(&d, o->src_index, pathbuf, namelen+1, NULL);
		msg = advice_commit_before_merge
			 * entries in the traverse path).

	return 0;
		return 0;
	 * and #14.
		int cmp = do_compare_entry_piecewise(ce, info->prev,
		len = ce_namelen(src[0]);
			ce = remote;

		/*
			if (same(stages[i], head)) {
	 * Even if the beginning compared identically, the ce should


			strbuf_addch(prefix, '/');
/*
		_("The following working tree files would be removed by sparse checkout update:\n%s");
/*
int twoway_merge(const struct cache_entry * const *src,
#include "submodule-config.h"
 * - take the stat information from stage0, take the data from stage1
		}
{
 */

	for (i = 0; i < index->cache_nr; i++) {
	cmp = strncmp(ce->name, info->traverse_path, info->pathlen);
		 * construct "transient" cache_entries, as they are
		update |= CE_ADDED;
		msg = advice_commit_before_merge
static int keep_entry(const struct cache_entry *ce,
 * When a CE gets turned into an unmerged entry, we
			ret = unpack_failed(o, "Sparse checkout leaves no entry on working directory");

			update = 0;
}
		 * tree. This is usually a mistake in sparse checkout rules.
					  error_type, o);
		p++;

static void debug_name_entry(int i, struct name_entry *n)
/*

			oid_array_append(&to_fetch, &ce->oid);
		if (!ce_stage(ce) && !(ce->ce_flags & CE_CONFLICTED))
			  same(current, newtree))) {

	int pathlen, ce_len;
		 * We are checking out path "foo" and
		ret = 0;
		printf("Unpacked %d entries from %s to %s using cache-tree\n",
	}
	putchar('\n');
}
	 * descriptor data.  This implicitly borrows the buffer
	struct index_state *index = o->src_index;
static const char *unpack_plumbing_errors[NB_UNPACK_TREES_ERROR_TYPES] = {
static int clear_ce_flags_1(struct index_state *istate,
					      ce, o);
		tree_ce->ce_namelen = len;
static int do_compare_entry_piecewise(const struct cache_entry *ce,
	return ret;

	unsigned cnt = 0, total = 0;
	const struct cache_entry *current = src[0];
			      enum pattern_match_result default_match,
	 * We start with cases where the index is allowed to match
{
		}

				 struct cache_entry **src,
		add_entry(o, old, update, CE_STAGEMASK);
	if (ret > 0)

			t[i] = t[i - 2];
			ce->name);
		ret = 0;
			 * again.


}

					goto return_failed;
				   struct index_state *istate,
		*o->dst_index = o->result;
	return start_delayed_progress(_("Updating files"), total);
		return 1;
			buf[nr_buf++] = fill_tree_descriptor(the_repository, t + i, oid);

		if (same(head, remote))
				  ERROR_WOULD_LOSE_UNTRACKED_OVERWRITTEN, o)) {
		int pos = index_pos_by_traverse_info(names, info);
	clone_checkout_metadata(&state.meta, &o->meta, NULL);
 * Fast path if we detect that all trees are the same as cache-tree at this
	trace_performance_enter();
	 * Merge strategies may set CE_UPDATE|CE_REMOVE outside checkout

		return NULL;
						   to_fetch.oid, to_fetch.nr);
		struct object_id oid;
	size_t len = traverse_path_len(info, tree_entry_len(n));
		if (current->ce_flags & CE_CONFLICTED) {
 * read-tree.  Non-scripted Porcelain is not required to use these messages
				break;
		if (o->diff_index_cached &&
			while (1) {
	enum unpack_trees_error_types orphaned_error = error_type;
	/*
			    S_ISGITLINK(ce->ce_mode))
			const struct cache_entry *old,

		    memcmp(ce->name, next->name, len))
	if (!o->show_all_errors)
			return reject_merge(current, o);
	int dtype = DT_DIR;
			goto done;
								NULL, o);
	} else if (lstat(ce->name, &st)) {
}
 */
	stop_progress(&istate->progress);
					return merged_entry(newtree, current, o);
	stop_progress(&progress);
static int verify_uptodate_sparse(const struct cache_entry *ce,
	}
	/* #2, #3, #4, #6, #7, #9, #10, #11. */
	if (should_update_submodules())
	ce->ce_namelen = len;
			 * Do the real check now because we have had
	}
			processed = clear_ce_flags_1(istate, cache, cache_end - cache,
				enum unpack_trees_error_types,
			ce->ce_flags |= skip_wt_flag;
	o->src_index = NULL;

 * indicating if it should be display in porcelain or not
			  "colliding group is in the working tree:\n"));
 * going to overwrite any working files.
					 * entries associated with it!
	struct index_state *index = &o->result;
	struct unpack_trees_options *o = info->data;
			return ce_slash ? -2 - pos : pos;
	return NULL;
{
}
		trace_performance_enter();
	}
}
	}
		free(path);

	int len;
		}
		for (i = 0; i < list.nr; i++)
void clear_unpack_trees_porcelain(struct unpack_trees_options *opts)
			if (ce->ce_flags & CE_ADDED &&
			 unsigned int set, unsigned int clear)
	/*
		mark_ce_used(next, o);
}
		 */
				}
	newinfo.prev = info;
			return error("%s", message);
			}


			}
	if (o->merge) {

	const char *ce_name;
		struct cache_entry *ce = index->cache[pos];

{
{


				      const char *name, size_t namelen,
	return add_rejected_path(o, error_type, name);


	int errs = 0;
			return merged_entry(newtree, current, o);

	return ret;
	/* ERROR_BIND_OVERLAP */
		    struct unpack_trees_options *o)
 * The current path ("prefix") including the trailing '/' is
		load_gitmodules_file(index, NULL);
	 * error() using the unpack_*_errors[] templates we see above.
static int do_add_entry(struct unpack_trees_options *o, struct cache_entry *ce,
		 * so apply_sparse_checkout() won't attempt to remove it from worktree
		 * of sync wrt the superproject index. If the submodule was
		struct cache_entry *ce = index->cache[i];
	if (something_displayed)
						      NULL,
	else if (len > 0) {

		 *
{


	trace_performance_enter();
	struct traverse_info newinfo;

		if (verify_absent_sparse(ce, ERROR_WOULD_LOSE_UNTRACKED_OVERWRITTEN, o))
}
		ret = default_match;
		}
}
			continue; /* keep looking */
	}
	int stage,
				if (!o->show_all_errors)
	 */

			return merged_entry(head, index, o);
	unsigned flags = SUBMODULE_MOVE_HEAD_DRY_RUN;
	 * select_mask condition
	if (o->merge) {
			if (submodule_from_ce(ce))
			return -1;
			     o->merge_size);
		free(sparse);
	return 0;
 * want it to be up-to-date
		bottom = o->cache_bottom;

		return 0;
			      const struct cache_entry *ce, struct stat *st,


	 * we will be descending into), it won't be inside it.
}
				  struct traverse_info *info)
		if (i > 0 && are_same_oid(&names[i], &names[i - 1]))
}
	}
					break;
			for (d = 1; d <= nr_names; d++)
	( ((o) && (o)->msgs[(type)]) \
		fprintf(o, "%s%06o %s %d\t%s\n",

 */
			 enum unpack_trees_error_types error_type,
			fprintf(stderr, "  '%s'\n", list.items[i].string);
		return NULL;
			break;
	 * For 2- and 3-way traversals, we try to avoid hitting the
		if (strncmp(ce->name, prefix->buf, prefix->len))
			continue;
{
		}
		 *
		} else if ((!oldtree && !newtree) || /* 4 and 5 */
	}
		const char *ce_name, *ce_slash;
			promisor_remote_get_direct(the_repository,
			     o->merge_size);
	for (; cnt < index->cache_nr; cnt++) {
	free(tree_ce);
 * display all the error messages stored in a nice way
	/*
	return mask;
		struct oid_array to_fetch = OID_ARRAY_INIT;
				cache_tree_update(&o->result,
			}
		make_empty_transient_cache_entry(len) :
	return cache_tree_matches_traversal(o->src_index->cache_tree, names, info);
	 * verify_absent() and verify_uptodate().
	return verify_absent_1(ce, orphaned_error, o);
	else if (o->reset || ce_uptodate(ce))
	 * is permitted to match the result instead.
	/*
	if (!o->merge)
	static struct strbuf prefix = STRBUF_INIT;

			 const struct cache_entry *old,
	/* Any left-over entries in the index? */
#include "tree-walk.h"
/*
{
			      struct unpack_trees_options *o)
	int pos = index_name_pos(index, ce->name, len);
			      int select_mask, int clear_mask,
		      : _("The following untracked working tree files would be overwritten by merge:\n%%s");
}
	if (len) {
			return 0;


	struct unpack_trees_options *o = info->data;
	} else if (o->src_index == o->dst_index) {
		oldtree = NULL;
		}
		}
	if (++idx >= ARRAY_SIZE(buf))
	state.istate = index;
			 * special cases D/F conflicts in such a way that
			/* Migrate old flags over */
			  same(oldtree, newtree)) || /* 14 and 15 */
 */
			if (git_env_bool("GIT_TEST_CHECK_CACHE_TREE", 0))

/*

			return rc;
			}
	msgs[ERROR_SPARSE_NOT_UPTODATE_FILE] =
	len = check_leading_path(ce->name, ce_namelen(ce));
				ce = next_cache_entry(o);
	if (do_add_entry(o, merge, update, CE_STAGEMASK) < 0)
	int head_match = 0;
		set |= CE_WT_REMOVE;
		const struct cache_entry *ce = index->cache[pos];
				o->cache_bottom += matches;
		 * That way we get the uptodate stat info.
}
	 * D/F conflicts and higher stage entries are not a concern
	 * It is necessary and sufficient to have two static buffers
	const struct cache_entry *src[MAX_UNPACK_TREES + 1] = { NULL, };
		}

		info.show_all_errors = o->show_all_errors;

	for (i = 0; i < n; i++)
	if (dirmask) {
{
		return 0;
				if (verify_absent(ce, ERROR_WOULD_LOSE_UNTRACKED_REMOVED, o))
		if (to_fetch.nr)
			return -1;


}
		if (ce_slash)
	struct progress *progress;
	 * area as a result of ce_skip_worktree() shortcuts in

		if (o->skip_unmerged) {

		return merged_entry(a, NULL, o);
 * corresponding to the type <e> with the message <msg>

			  int show_progress)
	}
		if (!super_prefix) {
		 */
				  struct unpack_trees_options *o);
		struct cache_entry *next = index->cache[pos];
	if ((ce->ce_flags & CE_VALID) || ce_skip_worktree(ce))


			!(old->ce_flags & CE_FSMONITOR_VALID)) {
		_("The following working tree files would be overwritten by sparse checkout update:\n%s");
			if (ce->ce_flags & CE_WT_REMOVE)

		return 0;
			    verify_absent(ce, ERROR_WOULD_LOSE_UNTRACKED_OVERWRITTEN, o)) {
	orig_ret = path_matches_pattern_list(prefix->buf, prefix->len,
static int clear_ce_flags_dir(struct index_state *istate,


 * The rule is to "carry forward" what is in the index without losing
	else if (!strcmp(cmd, "merge"))
			ce++;

				o->result.cache_tree = cache_tree();
	if (set & CE_REMOVE)
		int head_deleted = !head;
	/* If undecided, use matching result of parent dir in defval */
		const struct cache_entry *ce = NULL;
	return rval;
		int sub_head = resolve_gitlink_ref(ce->name, "HEAD", &oid);
	restore_cache_bottom(&newinfo, bottom);
 * the directory.
			processed = clear_ce_flags_dir(istate, cache, cache_end - cache,

		if (rejects->nr > 0) {
	if (S_ISGITLINK(ce->ce_mode)) {
	}
static int merged_entry(const struct cache_entry *ce,
	 * If we have an entry in the index cache, then we want to
					return unpack_failed(o, NULL);
		_("Cannot update sparse checkout: the following entries are not up to date:\n%s");
	o->df_conflict_entry = dfc;
 * "carry forward" rule, please see <Documentation/git-read-tree.txt>.
		else
	if (!lstat(ce->name, &st)) {
	int i;
	int pathlen, ce_len;
{

	 */
		if (ce->ce_flags & CE_UNPACKED) {
	strbuf_addch(&name, '/');
			     const char *label, const struct cache_entry *ce)
		rc = clear_ce_flags_1(istate, cache, cache_end - cache,
	struct string_list list = STRING_LIST_INIT_NODUP;
	int ret = o->fn(src, o);
					o);
		/*
}
 *
static int check_ok_to_remove(const char *name, int len, int dtype,
	newinfo = *info;

			putchar('/');
#include "promisor-remote.h"

			if (matches) {
	o->merge_size = len;
			 struct unpack_trees_options *);

