	    &dirty_submodule, &revs->diffopt) < 0)
		    old_entry->name, 0, dirty_submodule);

			int num_compare_stages = 0;
	struct tree_desc t;
				show_combined_diff(dpath, 2,
	 * New file in the index: it might actually be different in
	if (has_symlink_leading_path(ce->name, ce_namelen(ce)))
{
	/*
 * the source trees, with the old index being really mainly
				     unsigned *dirty_submodule)
/*
				continue;
			  &dirty_submodule, &revs->diffopt) < 0) {

	unsigned int mode, oldmode;
			else {
	if (!cached && !ce_uptodate(ce)) {
		p = xmalloc(combine_diff_path_size(2, pathlen));
/*
 *
			if (!revs->diffopt.flags.find_copies_harder)
			struct stat st;
{
		memcpy(p->path, new_entry->name, pathlen);
				 */
	 * looking at its content)
				diff_addremove(&revs->diffopt, '+', ce->ce_mode,
	if (diff_cache(&revs, tree_oid, NULL, 1))

			 int cached, int match_missing)
		idx = NULL;
			dpath->next = NULL;
			  int cached, int match_missing)
#include "unpack-trees.h"
		exit(128);
			set_diffopt_flags_from_submodule_config(diffopt, ce->name);
	 */
#include "quote.h"

	memset(&opts, 0, sizeof(opts));
 * We're supposed to advance o->pos to skip what we have already processed.
		if (changed) {
int run_diff_index(struct rev_info *revs, int cached)
static int diff_cache(struct rev_info *revs,
		struct combine_diff_path *p;
			return -1;
int run_diff_files(struct rev_info *revs, unsigned int option)



						DIFF_STATUS_MODIFIED;
/*
	return (rev.diffopt.flags.has_changes != 0);
		if (!is_missing_file_error(errno))
	}
		 */
		return 0;
			FREE_AND_NULL(dpath);
			}
			path_len = ce_namelen(ce);
			    old_oid, new_oid,
 * Return 1 when changes are detected, 0 otherwise. If the DIRTY_SUBMODULES
				   ce_intent_to_add(ce)) {
 * also be multiple unmerged entries (in which case idx_pos/idx_nr will
	if (!tree) {
			if (revs->combine_merges && num_compare_stages == 2) {
					int mode = nce->ce_mode;
		oldmode = ce->ce_mode;

				}
	}
			return -1;
	opt.def = def;


					       &ce->oid,
	init_tree_desc(&t, tree->buffer, tree->size);
			dpath = xmalloc(combine_diff_path_size(5, path_len));
		if (!ce_path_match(istate, ce, &revs->prune_data, NULL))
		memset(p->parent, 0, 2 * sizeof(struct combine_diff_parent));
	return unpack_trees(1, &t, &opts);

			 int report_missing,
			dpath->path[path_len] = '\0';
	unsigned ce_option = ((option & DIFF_RACY_IS_MODIFIED)

				stage = ce_stage(nce);
}
		unsigned int oldmode, newmode;
	object_array_clear(&rev.pending);
static void show_new_file(struct rev_info *revs,
					perror(ce->name);

				if (changed < 0) {
 * modified at all but wants to know all the conditions that are met (new
	unsigned dirty_submodule = 0;
/*
 */

		old_oid = &ce->oid;
	opts.head_idx = 1;
	 * Something added to the tree?
	opts.dst_index = NULL;
				/* Stage #2 (ours) is the first parent,
		 *
		p->path[pathlen] = 0;
{
	 * "!revs->ignore_merges".
static int get_stat_data(const struct cache_entry *ce,
		if (changed < 0)

		struct object_id sub;

	const struct cache_entry *tree = src[1];
			unsigned int wt_mode = 0;
static int show_modified(struct rev_info *revs,
 * Has the work tree entity been removed?
				 unsigned int mode,

		if (ce_uptodate(ce) || ce_skip_worktree(ce))
		do_oneway_diff(o, idx, tree);
			dpath->path = (char *) &(dpath->parent[5]);
			memset(&(dpath->parent[0]), 0,
	}
					dpath->parent[stage-2].mode = ce_mode_from_stat(nce, mode);
	if (ce_path_match(revs->diffopt.repo->index,
	 */
{
			} else if (revs->diffopt.ita_invisible_in_index &&
		 * so we will return 0.
}
	if (cached && idx && ce_stage(idx)) {
	diff_flush(&revs->diffopt);

				 const struct cache_entry *ce,
		changed = check_removed(ce, &st);
 * single tree.
	    (!oideq(oid, &old_entry->oid) || !oideq(&old_entry->oid, &new_entry->oid))) {
		p->parent[1].mode = old_entry->ce_mode;
	}
					       the_hash_algo->empty_tree, 0,
			struct combine_diff_path *dpath;


			 * Show the diff for the 'ce' if we found the one
		 * or a checked out submodule.  Either case this is not
	/*
	}
 * option is set, the caller does not only want to know if a submodule is
	return 0;
	int diff_unmerged_stage = revs->max_count;
		/*
				 const char *prefix,
					       ce->name, 0);
 */
				if (stage == diff_unmerged_stage)
	if (get_stat_data(new_entry, &oid, &mode, cached, match_missing,
		tree = NULL;
 */
		       oid, oid_valid, ce->name, dirty_submodule);
		if (!diffopt->flags.override_submodule_config)
#include "fsmonitor.h"
	int changed = ie_match_stat(diffopt->repo->index, ce, st, ce_option);
		p->mode = mode;
		       struct unpack_trees_options *o)
#include "revision.h"
		      const struct object_id *tree_oid,
			size_t path_len;
	trace_performance_since(start, "diff-files");
 */
	return 0;
	if (diff_unmerged_stage < 0)
	/* Show difference between old and new */
	unsigned int mode;
	struct rev_info *revs = o->unpack_data;
 * checked out).  Return negative for an error.
		diff_index_show_file(revs, "-", tree, &tree->oid, 1,
}
	opts.pathspec = &revs->diffopt.pathspec;
 */
			continue;
		pair = diff_unmerge(&revs->diffopt, idx->name);
	if (mode == oldmode && oideq(oid, &old_entry->oid) && !dirty_submodule &&
	struct tree *tree;
	return 0;
					break;
					       ce->name, 0);

		BUG("run_diff_index must be passed exactly one tree");
	for (i = 0; i < entries; i++) {
#include "submodule.h"
				wt_mode = 0;
			if (!changed)
		return -1;
					oidcpy(&dpath->parent[stage - 2].oid,
 * at a time. The index entry may be a single stage-0 one, but it could
}
				     struct stat *st, unsigned ce_option,
		       int ita_invisible_in_index)

						    0, dirty_submodule);
			 */
						   revs->dense_combined_merges,
		oidcpy(&p->parent[1].oid, &old_entry->oid);
		    resolve_gitlink_ref(ce->name, "HEAD", &sub))
{
}
	struct object_array_entry *ent;
}
			}


int index_differs_from(struct repository *r,
					continue;
	setup_revisions(0, NULL, &rev, &opt);
			 const struct object_id **oidp,
	diffcore_std(&revs->diffopt);
	unsigned int mode = ce->ce_mode;
						   revs);
		return 1;
		p->parent[0].status = DIFF_STATUS_MODIFIED;

static void diff_index_show_file(struct rev_info *revs,
			struct diff_filepair *pair;
	if (lstat(ce->name, st) < 0) {
				struct cache_entry *nce = istate->cache[i];
	 * there was a directory in the index and a tree
			 * from the desired stage.
	}
			 unsigned *dirty_submodule, struct diff_options *diffopt)
	struct index_state *istate = revs->diffopt.repo->index;
static int oneway_diff(const struct cache_entry * const *src,
			  idx ? idx : tree,
			struct stat st;
		show_combined_diff(p, 2, revs->dense_combined_merges, revs);
	const struct object_id *oid = &ce->oid;
	if (revs->pending.nr != 1)
				     tree->ce_mode, 0);
	if (revs->combine_merges && !cached &&
 * diff-index
	return 0;
			     tree_name ? tree_name : oid_to_hex(tree_oid));
	trace_performance_enter();

		}
	match_missing = !revs->ignore_merges;

			 const struct cache_entry *new_entry,
		return;
	struct setup_revision_opt opt;
	*oidp = oid;
	/*

					     0);
			   const struct cache_entry *idx,
		struct diff_flags orig_flags = diffopt->flags;
		}
		return;
		exit(128);
	tree = parse_tree_indirect(tree_oid);

 * diff-files
	    !revs->diffopt.flags.find_copies_harder)
			       sizeof(struct combine_diff_parent)*5);
					     &old_entry->oid, 1, old_entry->ce_mode,
	int match_missing, cached;
			if (ce_stage(ce) != diff_unmerged_stage)
	 * the working tree.

			diff_index_show_file(revs, "-", old_entry,
			 * Compensate for loop update
}
			}
		} else {
 * The unpack_trees() interface is designed for merging, so
	opts.src_index = revs->diffopt.repo->index;
	opts.unpack_data = revs;
		if (!changed && !dirty_submodule) {
	entries = istate->cache_nr;
			    !is_null_oid(old_oid),
			changed = 0;
					dpath->parent[stage-2].status =
	 * not mean "do not ignore merges", but "match_missing".
}
	 *
			newmode = ce->ce_mode;
	 */

	opts.index_only = cached;
	}
			ce_mark_uptodate(ce);
			oid = &null_oid;

			if (changed) {
			  &revs->prune_data, NULL)) {

		if (diff_can_quit_early(&revs->diffopt)) {
		      const char *tree_name,
 * This wrapper makes it all more readable, and takes care of all

 *
		return 1;
			oidclr(&dpath->oid);

	run_diff_index(&rev, 1);
					num_compare_stages++;
{
	    revs->diffopt.ita_invisible_in_index &&
	diff_index_show_file(revs, "+", new_file, oid, !is_null_oid(oid), mode, dirty_submodule);
				continue;
								 diffopt->flags.ignore_untracked_in_submodules);
			    ce->name, 0, dirty_submodule);
	 * Something removed from the tree?

			 unsigned int *modep,
/*

	 */
	if (get_stat_data(new_file, &oid, &mode, cached, match_missing,
	return 0;

/*
	repo_init_revisions(opt->repo, &revs, NULL);
		else if (changed) {
	}
			return 1;
	const struct cache_entry *idx = src[0];
			/*
		if (ce->ce_flags & CE_VALID) {
 * Has a file changed or has a submodule new commits or a dirty work tree?
			mode = ce_mode_from_stat(ce, st.st_mode);

					       &nce->oid);
#include "cache.h"
	if (diff_cache(revs, &ent->item->oid, ent->name, cached))
			pair = diff_unmerge(&revs->diffopt, ce->name);
	 * But with the revision flag parsing, that's found in
	diff_flush(&revs->diffopt);
			i--;

			changed = check_removed(ce, &st);
			memcpy(dpath->path, ce->name, path_len);

		new_oid = changed ? &null_oid : &ce->oid;
		diff_unmerged_stage = 2;
{

	show_modified(revs, tree, idx, 1, cached, match_missing);
	rev.diffopt.flags.exit_with_status = 1;
				return 0;

 * the skipping, the path matching, the type conflict cases etc.
	cached = o->index_only ||

			      ? CE_MATCH_RACY_IS_DIRTY : 0);
	/*
				*modep = mode;
		oidclr(&p->oid);
	trace_performance_leave("diff-index");
	}

	const struct object_id *oid;
			}

 */
 * compared with the cache entry ce still exists (the latter includes
	opts.pathspec->recursive = 1;
		/* If CE_VALID is set, don't look at workdir for file removal */
				diff_addremove(&revs->diffopt, '-', ce->ce_mode,
				i++;

	/*
		 * a case where something was removed from the work tree,
		diff_flags_or(&rev.diffopt.flags, flags);
		const struct object_id *old_oid, *new_oid;
		if (tree)
			 (!changed || diffopt->flags.dirty_submodules))
					perror(ce->name);
		int pathlen = ce_namelen(new_entry);
	}
		 * Otherwise, if the directory is not a submodule
		return 0;

	struct rev_info *revs = o->unpack_data;
	 */
				if (strcmp(ce->name, nce->name))
			 const struct cache_entry *old_entry,
				wt_mode = ce_mode_from_stat(ce, st.st_mode);
#include "commit.h"
	unsigned dirty_submodule = 0;
				continue;
	return changed;
			if (wt_mode)
	}
	opts.fn = oneway_diff;
	if (S_ISDIR(st->st_mode)) {

		p->path = (char *) &p->parent[2];
 * For diffing, the index is more important, and we only have a
	diff_set_mnemonic_prefix(&revs->diffopt, "i/", "w/");
		}
				pair->two->mode = wt_mode;
		unsigned dirty_submodule = 0;
			o->exiting_early = 1;
			/*
/*

				free(dpath);
	uint64_t start = getnanotime();
		}
	return 0;
		    &old_entry->oid, oid, 1, !is_null_oid(oid),
				*oidp = oid;
			fill_filespec(pair->one, &tree->oid, 1,
			changed = check_removed(ce, &st);
 * This gets a mix of an existing index and a tree, one pathname entry
		return error("bad tree object %s",
 */
			  const struct cache_entry *new_file,
		       const char *def, const struct diff_flags *flags,
#include "diffcore.h"
		 * repository, that means ce which was a blob turned into
		return;
#include "refs.h"
		if (diffopt->flags.ignore_submodules)

	diff_change(&revs->diffopt, oldmode, mode,
			newmode = ce_mode_from_stat(ce, st.st_mode);

		diff_change(&revs->diffopt, oldmode, newmode,
		changed = match_stat_with_submodule(diffopt, ce, &st,
				if (changed < 0) {
				     const struct cache_entry *ce,
	/*
			changed = 0;
	if (S_ISGITLINK(ce->ce_mode)) {
		diffopt->flags = orig_flags;
	    idx && ce_intent_to_add(idx)) {
		}
		int changed;
	 */
	memset(&opt, 0, sizeof(opt));
				/* diff against the proper unmerged stage */
	repo_init_revisions(r, &rev, NULL);

 * used for being replaced by the result.
	 * Backward compatibility wart - "diff-index -m" does
static void do_oneway_diff(struct unpack_trees_options *o,
	diffcore_fix_diff_index();
	*modep = mode;
			    !is_null_oid(new_oid),
	 * delete of the tree and a create of the file.
			changed = match_stat_with_submodule(&revs->diffopt, ce, &st,
							    ce_option, &dirty_submodule);
		struct cache_entry *ce = istate->cache[i];
	diff_set_mnemonic_prefix(&revs->diffopt, "c/", cached ? "i/" : "w/");
			   const struct cache_entry *tree)
			if (match_missing) {
#include "dir.h"

		}
	if (o->index_only &&

 * Return 1 if it was removed from the work tree, 0 if an entity to be
			break;
 *
	struct rev_info rev;
	if (!idx) {
 * the fairly complex unpack_trees() semantic requirements, including
				int stage;
		struct diff_filepair *pair;
			continue;
	rev.diffopt.flags.quick = 1;
		p->parent[0].mode = new_entry->ce_mode;
{
}
		else if (!diffopt->flags.ignore_dirty_submodules &&
				 * stage #3 (theirs) is the second.
	diff_addremove(&revs->diffopt, prefix[0], mode,
{
 * commits, untracked content and/or modified content).
		return;
			return;	/* nothing to diff.. */
}
	struct rev_info revs;
}
		(idx && ((idx->ce_flags & CE_VALID) || ce_skip_worktree(idx)));
		show_new_file(revs, idx, cached, match_missing);
	 * in the tree. From a diff standpoint, that's a
	ent = revs->pending.objects;
			 int cached, int match_missing,
				 unsigned dirty_submodule)
#include "cache-tree.h"
	struct unpack_trees_options opts;
			}
	oldmode = old_entry->ce_mode;

	if (flags)
{
	if (tree == o->df_conflict_entry)
				 const struct object_id *oid, int oid_valid,
	 * i-t-a entries do not actually exist in the index (if we're
{
 * Copyright (C) 2005 Junio C Hamano
	copy_pathspec(&revs.prune_data, &opt->pathspec);
		if (ce_stage(ce)) {
			*dirty_submodule = is_submodule_modified(ce->name,
	revs.diffopt = *opt;
		 * directory (i.e. the submodule is not checked out),
		if (!tree)
 * exists for ce that is a submodule -- it is a submodule that is not
	int entries, i;
		p->next = NULL;
 *


			return -1;
		 * a directory --- the blob was removed!
					       !is_null_oid(&ce->oid),
	return 0;
	rev.diffopt.ita_invisible_in_index = ita_invisible_in_index;
		struct stat st;
}
		if (!S_ISGITLINK(ce->ce_mode) &&

}
/* A file entry went away or appeared */
 *
		if (report_missing)
	opts.diff_index_cached = (cached &&

		p->parent[1].status = DIFF_STATUS_MODIFIED;
					ce = nce;

static int check_removed(const struct cache_entry *ce, struct stat *st)
		 * If ce is already a gitlink, we can have a plain
		free(p);
 * the case where a directory that is not a submodule repository
			return -1;
{
#include "diff.h"
	if (!tree)
	/* if the entry is not checked out, don't examine work tree */
				  !revs->diffopt.flags.find_copies_harder);
			while (i < entries) {
static int match_stat_with_submodule(struct diff_options *diffopt,
 * give you the position and number of entries in the index).
	const struct object_id *oid;
				continue;
		oidcpy(&p->parent[0].oid, &new_entry->oid);
				continue;
int do_diff_cache(const struct object_id *tree_oid, struct diff_options *opt)
			mark_fsmonitor_valid(istate, ce);
		      int cached)
{
		int changed;
				}
	 * Unpack-trees generates a DF/conflict entry if
	diffcore_std(&revs->diffopt);
		if (diff_can_quit_early(&revs->diffopt))
	}
	opts.merge = 1;
				if (2 <= stage) {
				}
			 */


 * the different source entries are designed primarily for
				      tree->ce_mode);
					continue;
			dpath->mode = wt_mode;
