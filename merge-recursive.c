	struct strbuf sb = STRBUF_INIT;
	if (show(opt, 4)) {
	strbuf_release(&dirpath);
		    struct commit *h2,
			write_in_full(fd, buf, size);
		}
			  const struct diff_filespec *a,
	mmfile_t orig, src1, src2;
	free(temp);
	 * data structures are still needed and referenced in
				oidcpy(&result->blob.oid, &a->oid);
			 * stage and in other_stage (think of rename +
					   merge_ent->dir)->util = merge_ent;
						      ren1_dst,
 */
			break;
	add = &ci->ren2->dst_entry->stages[flip_stage(3)];
		unpack_trees_finish(opt);
		if (ren1->processed)
	if (update_cache) {
				 "writing to %s instead."),

			hashmap_entry_init(&collision_ent->ent,
	if (!merge_detect_rename(opt))
 *      In the future, we could potentially record this info as well and
		changed = b;
			= (void *)sre;
		switch (ci->rename_type) {
		path_clean &= warn_about_dir_renamed_entries(opt, ci->ren2);

	string_list_clear(rename, 1);
	return strcmp(e1->target_file, e2->target_file);
			   !merge_ent->non_unique_new_dir) {
		*result = make_virtual_commit(opt->repo, result_tree,
	if (!mfi->clean) {
	const struct dir_rename_entry *e1, *e2;
{
							    opt->branch2,
		} /* avoid erroring on values from future versions of git */
		*count += 1;

	 * update_file()/would_lose_untracked(); see every comment in this
		 *   2) renames (in effect if !old_path) could mean that
			/* BUG: We should only remove ren1_src in the base

	if (!merge_bases) {
	other_branch = (ren->branch == opt->branch1 ?
			   struct strbuf *base, const char *path,
			fd = open(path, O_WRONLY | O_TRUNC | O_CREAT, mode);
		oidcpy(&dfs->oid, &null_oid);
			case MERGE_VARIANT_THEIRS:
		commit_list_insert(h2, &(*result)->parents->next);
	}
{
		oldlen++;

			int *count = entry->possible_new_dirs.items[i].util;
					clean_merge = -1;
	char merged_revision[GIT_MAX_HEXSZ + 2];
		 * The slight variance among the cases is due to the fact
		case MERGE_VARIANT_THEIRS:

		struct object *o = &(commit->object);
		return err(opt, _("add_cacheinfo failed for path '%s'; merge aborting."), path);
	free(dir_renames);
{
				const struct diff_filespec *o,
	return ret;
				update_entry(ren1->dst_entry,
	init_tree_desc_from_tree(t+0, common);
			if (*count == max)
		       entry->dir, entry->new_dir.buf, path, entry->new_dir.buf);
		 * cases the path was not tracked.
};
		/* Case A: Deleted in one */
		if ((opt->rename_score = parse_rename_score(&arg)) == -1 || *arg != 0)
			 * and/or work tree, but we do not do that now.

	}
	int suffix = 0;
				     &ci->ren1->dst_entry->stages[other_stage]);
	else
	const char *rev_args[] = { "rev-list", "--merges", "--ancestry-path",
	if (mark_conflicted) {
				 * file, then the merge will be clean.
	opt->priv->unpack_opts.src_index = opt->repo->index;
	if (!mfi.clean && !opt->priv->call_depth &&
	head_pairs = get_diffpairs(opt, common, head);
		    memcmp(path, last_file, last_len) == 0 &&
	return clean;
			}
		       oid_to_hex(&merges.objects[0].item->oid), path);
}
			      subtree_shift);
	return clean;
{
static struct diff_queue_struct *get_diffpairs(struct merge_options *opt,
		 */
	commit->object.parsed = 1;
	/* Two files, a & b, were renamed to the same thing, c. */

	if (!git_config_get_string("merge.directoryrenames", &value)) {
					     prev_path2, prev_path1,

		return update_stages(opt, dest->path, NULL,
	 * side of history could have merged multiple directories into one,
	 * would_lose_untracked).  Instead, reverse the order of the calls
		return 0; /* not clean, but conflicted */
				       struct tree *b_tree,
/* Low level file merging, update and removal */
			conf = _("file/directory");

		if (!ce_stage(ce))
	if (!opt->priv->call_depth && opt->buffer_output < 2)

static void unpack_trees_finish(struct merge_options *opt)
	}
	}
		return 0;
	int parent_count;
	       !strcmp(opt->ancestor, "constructed merge base"));
		 skip_prefix(s, "rename-threshold=", &arg)) {
	} else if (ren->dir_rename_original_type == 'R' && clean) {
struct stage_data {
		} else if (tree_has_path(opt->repo, head, head_ent->dir)) {
		const char *path = df_sorted_entries.items[i].string;
	 * that will result in a spurious rename/rename(1to2) conflict.  An

			if (handle_rename_delete(opt, ci))
		if (pair->status != 'R' && !new_path) {


static void collision_init(struct hashmap *map)
				setup_rename_conflict_info(RENAME_NORMAL,
		return -1;
				oidcpy(&result->blob.oid, &b->oid);
	}
		struct tree *o, struct tree *a, struct tree *b,
		 * overwritten it: the committed "conflicts" were
			}
{
	if (opt->priv->call_depth)
			entry->processed = 0;
		 */
	}

		 * possible_new_dirs, and instead of manually iterating the
				   oideq(&dst_other.oid, &ren1->pair->two->oid)) {
		 */
	       end_of_new != new_path)
	strbuf_setlen(base, baselen);
	 * If both got back to the beginning of their strings, then the
	output(opt, 1, _("CONFLICT (rename/rename): "

{
		}

	 *    "a/b/c/d/e/foo.c" -> "a/b/some/thing/else/e/foo.c"
	}
			       0)) {
		}
{
static struct commit *make_virtual_commit(struct repository *repo,
		 * only record the file at dest->path in the appropriate
	/*
			b->path = ci->ren2->pair->two->path;
}
	struct commit_list *iter;
		strbuf_release(&dirpath);
	const struct rename *sre;
				result);
{
			 */
	free(alt_path);

		changed = a;
	int ret = 0;
				MERGE_DIRECTORY_RENAMES_NONE;
		struct dir_rename_entry *dir_rename_ent;
		 * Despite the four nearly duplicate messages and argument
			       struct diff_queue_struct *pairs)

				struct tree **result)
				       change, old_path, delete_branch, change_past, path,
	if (opt->priv->call_depth)
	if (entry->rename_conflict_info) {
	 * Case #2: There are one or more merges that contain a and b in
	if (dir == NULL)
		strbuf_add_unique_abbrev(&opt->obuf, &commit->object.oid,
		struct commit *m1 = (struct commit *) merges.objects[i].item;
{
	if (opt->priv->call_depth || !was_tracked(opt, path))
	 * appearing before files below the corresponding directory.
	 * record the original destination name.
		opt->subtree_shift = arg;
			src_other.mode = ren1->src_entry->stages[other_stage].mode;
	struct merge_file_info mfi_c2;
static int dir_rename_cmp(const void *unused_cmp_data,

			     int update_wd)
	int merge_status;
	strbuf_grow(&new_path, newlen);
		string_list_clear(&e->source_files, 0);
		free(value);
	return !get_tree_entry(r,
		tree = lookup_tree(opt->repo, opt->repo->hash_algo->empty_tree);
	 *   Side 2:      dumbdir/afile, dumbdir/bfile
	    read_oid_strbuf(opt, &a->oid, &abuf))
		return 0;
				}
			clean_merge = handle_rename_rename_2to1(opt, ci);
				  NULL,
	 *   a) The merge is clean
				    opt->priv->call_depth * 2, &mfi))
			   unsigned int mode, int stage, void *context)
	opt->priv->unpack_opts.src_index = &opt->priv->orig_index;
	struct hashmap_iter iter;
		if (i >= a_renames->nr) {
{

	struct dir_rename_entry *merge_ent;
	 * smrtdir/bfile.  That gives us bfile in dumbdir vs being in
		if (nce != ce)
		next = current;
	if (end_of_new == new_path &&

				 * add-source cases).
			       path, strlen(path), ignore_case);
	 * example:
	const char *delete_branch = (opt->branch1 == ren->branch ?
	} else {

	}
					     ren1->pair->one,
			clean_merge = handle_rename_add(opt, ci);
		if (opt->priv->call_depth) {
{
	clean &= process_renames(opt, ri->head_renames, ri->merge_renames);
	new_path = apply_dir_rename(entry, path);
	/* Case #1: a is contained in b or vice versa */
	rev_opts.submodule = path;
 *      in get_directory_renames(), except that would prevent us from

			b->path = ci->ren2->pair->two->path;
							   opt, ren1, NULL);
			const char *title;
}


	 * merge-recursive to update the working tree first and the index
	} else {
	 * branch if we just ensure that branch1 == opt->branch1.  So, simply
		 * this entry was deleted altogether. a_mode == 0 means

{
			result->merge = 1;


	if (errno == ENOENT)

	return dfs->mode != 0 && !is_null_oid(&dfs->oid);
	char *base, *name1, *name2;
	struct collision_entry key;
	update_wd = !was_dirty(opt, pair->two->path);

	 * any working directory changes.
	int b_valid = is_valid(b);
	 * merged contents, or just write out to differently named files.
 * Return a new string that replaces the beginning portion (which matches
	if (update_working_directory) {
					common, head, merge, entries,
	if (oentry) {
	} else if (merge_bases) {
		  oid_to_hex(&a->object.oid));
				 * update_file().
	 * it.  So we need to provide a good warning about what's

	 * and bail on directory renames for such paths.
{
		DIFF_XDL_SET(opt, IGNORE_CR_AT_EOL);
	if (opt->priv->call_depth)
				  _("do not know what to do with %06o %s '%s'"),
	 * since in other cases any changes in their order due to
		       "for example\n"
			clean_merge = 0;
 * We need the three trees in the merge ('o_tree', 'a_tree' and 'b_tree')
		break;
			continue;
		      const int extra_marker_size)
		item = string_list_lookup(unmerged, ce->name);
	 */
			 const struct diff_filespec *o,
		      int check_working_copy, int empty_ok)
	return 0;
		return 0;
			} else {
				return -1;
		if (bad_max == max)
struct path_hashmap_entry {
			result->blob.mode = a->mode;
	e1 = container_of(eptr, const struct dir_rename_entry, ent);
	 * really want a change to a base file to be propagated through
			return -1;
		case RENAME_VIA_DIR:
		if (in_merge_bases(b, commit))
 *      implicit renaming of files that should be left in place.  (See
		 * No need to call update_file() on path when change_branch ==
	struct hashmap current_file_dir_set;
	 * removed to make room for the corresponding directory if needed.
	if (is_null_oid(a))
		if (num_merge_bases == 1)
		if (S_ISGITLINK(contents->mode)) {
	 * Finally, record the new location.
static int handle_rename_rename_2to1(struct merge_options *opt,
	 */
					dir_re_merge, dir_re_head, head,
		return 0;
	}
		 * case we can just allow the normal processing to happen
		if (path_clean < clean_merge)
	 * were part of the first non-matching subdir name going back from
		strbuf_reset(&opt->obuf);
{
							    opt->branch1,
	struct diff_filespec *c1 = ci->ren1->pair->two;

}

							ci->ren2->branch,
	strbuf_addch(&opt->obuf, '\n');
		output(opt, 1, _("Refusing to lose dirty file at %s"),
	struct object_id hashy;
	const char *arg;
			 */
	opt->repo = repo;
	if (collision_ent->reported_already) {
	    renormalize_buffer(idx, path, abuf.buf, abuf.len, &abuf))
		delete_branch = opt->branch2;
	} else if (would_lose_untracked(opt, path)) {
		}
		if (remove_path(path))
		clean = 0;
				remove_file_from_index(opt->repo->index, path);
	if (!s || !*s)
				ent /* member name */) {
		ll_opts.variant = 0;
		return NULL;
			/* 3. rename/rename(1to2) */
		}
		if (!opt->priv->call_depth &&

		switch (opt->recursive_variant) {
	if (pos < 0)
	 */
			goto cleanup;
	buf = read_object_file(oid, &type, &size);
	struct strbuf abuf = STRBUF_INIT;

	 * be processed before the corresponding file involved in the D/F
	free(alt_path);
			strbuf_addstr(&opt->obuf, _("(bad commit)\n"));
		delete_branch = opt->branch1;
			 * add-source case).
	opt->priv->orig_index = *opt->repo->index;
		 * When the merge fails, the result contains files
	hashmap_add(&opt->priv->current_file_dir_set, &entry->e);
	if (!clean && new_path) {

	 */
	int i;
	 * be the "winning" target location for the directory rename.  This
			return -1;
		 * top.  Fix that.
				ret = err(opt, _("Unable to add %s to database"),
static void handle_directory_level_conflicts(struct merge_options *opt,
				BUG("unprocessed path??? %s",
					struct hashmap *collisions,
	/*
	int clean;

}
		strbuf_release(&sb);
				     rename_branch == opt->branch1 ? dest : NULL,
 *   1. Check for both sides renaming to the same thing, in order to avoid

static int handle_change_delete(struct merge_options *opt,
	struct cache_entry *ce;
		entries = get_unmerged(opt->repo->index);
{
	revs.single_worktree = path != NULL;

	    !(*result = write_in_core_index_as_tree(opt->repo)))
static int save_files_dirs(const struct object_id *oid,
	struct diff_filespec *add;


	if (ignore_case)
		return;
			ren2 = lookup->util;
	read_mmblob(&orig, &o->oid);
					struct hashmap *dir_renames,
}
		 */
			ren2->processed = 1;
						 struct string_list *entries)
	}
	const char *msg;
	return dirty;
	free_buf:

	hashmap_free_entries(&collisions, struct collision_entry, ent);
		}
			output(opt, 2, _("Adding %s"), path);
			add_object_array(o, NULL, &merges);
			BUG("unsupported object type in the tree");
	if (item) {
		       pair->two->path);
	 * multiple other files by a merge?
			 * are different strings.
	string_list_clear(&opt->priv->df_conflict_file_set, 1);
	item->util = e;
		return 0;
	path_side_2_desc = xstrfmt("version of %s from %s", path, b->path);
/* add a string to a strbuf, but converting "/" to "_" */
			result->clean = merge_submodule(opt, &result->blob.oid,
							   opt, ren1, NULL);
	struct commit *commit = alloc_commit_node(repo);
	unsigned processed:1;
		opt->recursive_variant = MERGE_VARIANT_THEIRS;
				struct tree *head,
			 */
		free(value);
	strbuf_release(&obuf);
		 * past the '/' character.

				  ren->branch == opt->branch1 ? NULL : dest))
	initial_cleanup_rename(head_pairs, dir_re_head);
	repo_diff_setup(opt->repo, &opts);
						  new_dir);
				ent /* member name */) {
		strbuf_add_separated_string_list(&collision_paths, ", ",
	}
		return 1;
			if (try_merge) {
 * Returns whether path was tracked in the index before the merge started
		if (!dir_rename_ent)
	 * Purpose of src_entry and dst_entry:
	 * When we have two renames involved, it's easiest to get the
			free(new_path);

	if (pos < istate->cache_nr &&
	 */
		}
	const char *update_path = path;
				clean_merge = -1;
	/*
static int was_dirty(struct merge_options *opt, const char *path)
			remove_file(opt, 1, ren1_src,
static void remove_hashmap_entries(struct hashmap *dir_renames,
static int update_stages(struct merge_options *opt, const char *path,
}
	}
			ret = add_index_entry(istate, nce, options);
		item->util = re->dst_entry;
		string_list_append(&df_sorted_entries, next->string)->util =
							o->path,
			free(new_dir);
static struct hashmap *get_directory_renames(struct diff_queue_struct *pairs)
	}
	const char *add_branch = (opt->branch1 == rename_branch ?
		fputs(opt->obuf.buf, stdout);
		 * a directory rename AND user had an untracked file
		return err(opt, _("object %s is not a blob"), oid_to_hex(oid));
	if (opts.detect_rename > DIFF_DETECT_RENAME)
	 * possibility occurs.

			return clean;
				best = entry->possible_new_dirs.items[i].string;
		return 1;
					o_tree, a_tree, b_tree, entries);

		repo_read_index(opt->repo);
				if (update_file_flags(opt,
		strbuf_release(&e->new_dir);
 * for these (temporary) data.
					 struct tree *tree)
	 * end_of_old and end_of_new to the NEXT '/' character.  That will
	int dirty = 1;
	}
static char *check_for_directory_rename(struct merge_options *opt,
	 * In all cases where we can do directory rename detection,
				   const int extra_marker_size,
		case 2:
				src_other.path = (char *)ren1_src;

	 * (executing update_file first and then update_stages).
				       struct diff_queue_struct *pairs,
static int find_first_merges(struct repository *repo,
		} else {

	/*
	 * Typically, we think of a directory rename as all files from a
	}
		return 1;
					  CE_MATCH_REFRESH | CE_MATCH_IGNORE_MISSING);
		/*
		}
 * any implicit directory renames inferred from the other side of history.
	}
		return NULL;
			}
			output(opt, 2, _("Fast-forwarding submodule %s"), path);

#include "commit-reach.h"
		 * flag to avoid making the file appear as if it were
	 * the mode S_IFDIR so that D/F conflicts will sort correctly.

			 const void *unused_keydata)
	struct diff_queue_struct *head_pairs, *merge_pairs;
#include "commit.h"
}
	int other_stage = (ci->ren1->branch == opt->branch1 ? 3 : 2);
}
	c->maybe_tree = t;
	else if (!strcmp(s, "no-renames"))
	} else if (tree_has_path(opt->repo, tree, new_path)) {
		output(opt, 1, _("CONFLICT (%s): Merge conflict in %s"),
				goto free_buf;
		       path, new_path);
				       struct string_list *entries,
		opt->priv->unpack_opts.index_only = 1;
	}
}
		}
				    c2, path_side_2_desc,
			if (i != j && in_merge_bases(m2, m1)) {
				  0, (!opt->priv->call_depth && !is_dirty), 0))
			int is_dirty = 0; /* unpack_trees would have bailed if dirty */
	struct string_list a_by_dst = STRING_LIST_INIT_NODUP;
static void apply_directory_rename_modifications(struct merge_options *opt,
	struct pretty_print_context ctx = {0};
	       opt->detect_renames <= DIFF_DETECT_COPY);
	if (merge_mode_and_contents(opt, o, a, b, path,
			renames2Dst = &a_by_dst;
				break;
	 * in-memory index which will break calls to would_lose_untracked()
				ent /* member name */) {
			continue;


	struct lock_file lock = LOCK_INIT;
				 * Probably not a clean merge, but it's
	 *   b) The merge matches what was in HEAD (content, mode, pathname)
			ret = err(opt, _("blob expected for %s '%s'"),
			ll_opts.variant = XDL_MERGE_FAVOR_OURS;

			if (handle_rename_rename_1to2(opt, ci))
				remove_file(opt, 1, ren1_src, 1);
			   const struct object_id *oid,
	remove_hashmap_entries(dir_re_head, &remove_from_head);
	 * places, and that the bulk of them ended up in the same place.
	if (cmp)
			merge_status = merge_3way(opt, &result_buf, o, a, b,
					 commit_a, commit_b);
			return -1;
		 * set to the rename target path; we need to set two of these
	}


					b = ren1->pair->two;
	       !strcmp(path, istate->cache[pos]->name)) {
	reset_revision_walk();
		else if (S_ISREG(a->mode)) {

	char *path = c1->path; /* == c2->path */

	 * process_entry().  But there are a few things we can free now.
		       &tree->object.oid,
	else {
static void dir_rename_init(struct hashmap *map)
/*
			string_list_insert(&opt->priv->df_conflict_file_set, last_file);
		ren1->processed = 1;
		if (!item) {
			if (strcmp(ren1_src, ren2_src) != 0)
		switch (ce_stage(istate->cache[pos])) {
				     o, a, b, ci);
							     re, tree, o_tree,

		struct string_list_item *lookup;

	if (opts.needed_rename_limit > opt->priv->needed_rename_limit)
 *   dir:                original name of directory being renamed
	int update_wd;
		struct diff_filespec *temp;
	if (result->merge)
					  a->path);

	df_sorted_entries.cmp = string_list_df_name_compare;
static int show(struct merge_options *opt, int v)
			  const struct hashmap_entry *entry_or_key,
{
	       ren->pair->one->path, ren->dir_rename_original_dest, ren->branch,
	}
					  ci->ren1->branch,
 *   non_unique_new_dir: if true, could not determine new_dir
	remove_hashmap_entries(dir_re_head, &remove_from_head);
	 *
			/*

	struct diff_filespec blob; /* mostly use oid & mode; sometimes path */
		return NULL;
	string_list_clear(&a_by_dst, 0);
			strbuf_release(&merge_ent->new_dir);
			string_list_append(&remove_from_merge,
		remove_file(opt, 0, collide_path, 0);
			opt->detect_directory_renames =
				rename_type = RENAME_ONE_FILE_TO_TWO;
struct collision_entry {
	 * Note: There is no need to consider the opposite case, with a
	key.target_file = target_file;
	ri->merge_renames = get_renames(opt, opt->branch2, merge_pairs,

	 */

	    (opt->detect_directory_renames == MERGE_DIRECTORY_RENAMES_CONFLICT &&
	if (unmerged_index(istate)) {
	 * Remove the collision path, if it wouldn't cause dirty contents
		char *old_dir, *new_dir;
		output(opt, 1, _("Refusing to lose untracked file"

	int needed_rename_limit;
static int unpack_trees_start(struct merge_options *opt,
}
}
	/* we can not handle deletion conflicts */
		name1 = mkpathdup("%s:%s", branch1, a->path);
		if (!entry->non_unique_new_dir)
	/* Successful unlink is good.. */
		new_path = unique_path(opt, path, ci->ren1->branch);
	 * confusion; See testcases 9c and 9d of t6043.
			continue;
			     struct rename_conflict_info *ci)
	       "Rename %s->%s in %s.  Added %s in %s"),
		} else {
			goto free_buf;
	int clean;
static struct string_list *get_renames(struct merge_options *opt,
		case RENAME_ADD:
{
			    const struct object_id *merge,
	for (i = 0; i < istate->cache_nr; i++) {
	 * renamed/merged to dumbdir, and change the diff_filepair for
 * dictionary contains one entry for every path with a non-zero stage entry.
		/*

		strbuf_reset(&opt->obuf);
				 * premature to set clean_merge to 0 here,
int merge_recursive(struct merge_options *opt,
		       &re->dst_entry->stages[stage].oid,
	       b->path, c2->path, ci->ren2->branch);

	 */
				     repo_get_commit_tree(opt->repo, h1),
}

			int try_merge;

	 */
	struct string_list possible_new_dirs;
static inline void setup_rename_conflict_info(enum rename_type rename_type,
		char *new_path; /* non-NULL only with directory renames */
 *         that should be detected at the individual path level.
					   oid_to_hex(merge_bases[i]));
				break;
	format_commit_message(commit, " %h: %m %s", &sb, &ctx);
		re->dir_rename_original_type = '\0';
		ci->ren2->dst_entry->rename_conflict_info = ci;
			       !opt->priv->call_depth && !S_ISGITLINK(a->mode),
	 * Do not unlink a file in the work tree if we are not
	/* Default return values: NULL, meaning no rename */
	RENAME_ONE_FILE_TO_TWO,
			if (len)
	 * that files from the original directory went to two different
			const char *ren2_dst = ren2->pair->two->path;
	 * Multiple files can be mapped to the same path due to directory
		case 0:
	char *dir;
		return mfi->clean;
	       opt->recursive_variant <= MERGE_VARIANT_THEIRS);
	merge_finalize(opt);
	} else {
{
static int detect_and_process_renames(struct merge_options *opt,
 * Check whether a directory in the index is in the way of an incoming
	if (!(commit_base = lookup_commit_reference(opt->repo, base)) ||
	 * "NOTE" in update_stages(), doing so will modify the current
	/*
			 struct diff_filespec *b)



			assert(entry->new_dir.len == 0);
	else if (skip_prefix(s, "find-renames=", &arg) ||
			    int num_merge_bases,
		} else {
			       "directory rename(s) putting the following "
	if (merge_mode_and_contents(opt, a, c,
	 * we can instead place it at new_path.  It is guaranteed to
	 * renamed by the directory rename detection into the same path,
	final_cleanup_rename(re_info->head_renames);
static int process_renames(struct merge_options *opt,
	diff_tree_oid(&o_tree->object.oid, &tree->object.oid, "", &opts);
	free(src2.ptr);
static struct commit_list *reverse_commit_list(struct commit_list *list)
						      clean_merge);
	/*
	*new_dir = NULL;
	 * could not be a directory rename (our rule elsewhere that a
	hashmap_add(&opt->priv->current_file_dir_set, &entry->e);

	int o_valid = is_valid(o);
		 * Merge modes

	    !(commit_b = lookup_commit_reference(opt->repo, b))) {
		return 0;
				  oid_to_hex(&contents->oid), path);
	 *
	struct string_list *head_renames;


{
			if (clean_merge < 0)
		}
			return -1;
	if (is_null_oid(base))
			contents = b;

}
					     struct tree *head,
static struct stage_data *insert_stage_data(struct repository *r,
						    char *target_file)
		opt->verbosity = strtol(merge_verbosity, NULL, 10);
	 * We use the mode S_IFDIR for everything else for simplicity,

static void add_flattened_path(struct strbuf *out, const char *s)
	oldlen = strlen(entry->dir);
		strbuf_addch(&opt->obuf, ' ');
static int merge_start(struct merge_options *opt, struct tree *head)
			/* 2. This wasn't a directory rename after all */
		}
		 * as the rename; we need to make old_path + oldlen advance
			struct commit *base;
static inline void set_commit_tree(struct commit *c, struct tree *t)
 * toplevel of the repository and do not include a trailing '/'.  Also:
}
	clear_unpack_trees_porcelain(&opt->priv->unpack_opts);
	 * needs slightly special handling.
	const struct diff_filespec *dest = ren->pair->two;
			const char *ren2_src = ren2->pair->one->path;
		if (!o_valid) {
}
}
			clean_merge = handle_rename_via_dir(opt, ci);
							   opt, ren1, NULL);

	hashmap_for_each_entry(dir_re_head, &iter, head_ent,
	int ret;
}
	 */
{

	for (i = 0; i < merges.nr; i++) {

			dst_other.mode = ren1->dst_entry->stages[other_stage].mode;
static int collision_cmp(const void *unused_cmp_data,
			break;
	/* See if the file we were tracking before matches */

	 * saved copy.  (verify_uptodate() checks src_index, and the original
		 * already resolved.
	ri->merge_renames = NULL;
				 * the base stage (think of rename +
			/*
		return handle_file_collision(opt, collide_path,
static void merge_finalize(struct merge_options *opt)
		saved_b1 = opt->branch1;
}
{
							    path, NULL, NULL,
	add_flattened_path(&newpath, branch);
				  const struct object_id *tree,
		return 0;
				const char *change_branch,
		opt->detect_renames = git_config_rename("diff.renames", value);
	 * detection.  This differs from handle_rename_normal, because
		} else {
	if (rename == NULL)
	assert(opt->detect_directory_renames > MERGE_DIRECTORY_RENAMES_NONE);
	 * If end_of_new got back to the beginning of its string, and
	 * the "e/foo.c" part is the same, we just want to know that
	RENAME_TWO_FILES_TO_ONE
	 * versions of 'after' in corresponding locations.  Thus, we have a
				return err(opt, _("Could not parse object '%s'"),
	RENAME_VIA_DIR,
			  const void *unused_keydata)
		if (!collision_ent) {
					       struct tree *tree)
	struct setup_revision_opt rev_opts;
		ll_opts.virtual_ancestor = 1;

	int i;
	/*
		 * initialize it here and free it when we are done running
	/*
		int boolval = git_parse_maybe_bool(value);
		opt->xdl_opts |= value;
	 *
		default:
	return ret;
			int fd;
	/* Find the first non-matching character traversing backwards */
		/*
		} else {
	else {
	assert(opt->verbosity >= 0 && opt->verbosity <= 5);
	struct collision_entry *collision_ent;
	 */


	}
 *      the affected directories, thus cleaning up the merge output.
		free(e->target_file);
	const struct index_state *idx = opt->repo->index;
	free(orig.ptr);
{
				const struct diff_filespec *a,
	 * but without the pre-increment, the one on the right would stay
		 * filepaths were xstrndup'ed before inserting into
	setup_unpack_trees_porcelain(&opt->priv->unpack_opts, "merge");
		       "by using:\n\n"
			break;
		collision_ent->reported_already = 1;
		strbuf_add_separated_string_list(&collision_paths, ", ",
	opt->renormalize = 0;



	hashmap_for_each_entry(dir_re_merge, &iter, merge_ent,
				    &ci->ren2->src_entry->stages[ostage2],
{
	while ((commit = get_revision(&revs)) != NULL) {

		 */
	 *
static int merge_3way(struct merge_options *opt,
		else
	string_list_sort(&df_sorted_entries);
	if (merge_mode_and_contents(opt, &null, a, b, collide_path,
		      const struct diff_filespec *o,
	/*

			ce->ce_flags |= CE_SKIP_WORKTREE;
						 struct rename *re,
			string_list_append(&remove_from_merge,
				     struct string_list *entries)
			remove_file_from_index(opt->repo->index, path);
	else if (skip_prefix(s, "diff-algorithm=", &arg)) {
		const char *saved_b1, *saved_b2;
	return new_path;
	 * rename/merge of the root directory into some subdirectory
			unlink(path);
	item = string_list_insert(entries, path);
		msg = _("CONFLICT (file location): %s renamed to %s in %s, "
						strhash(new_path));
	struct strbuf dirpath = STRBUF_INIT;
#include "ll-merge.h"
	if (update_wd) {
	get_tree_entry_if_blob(r, &b->object.oid, path, &e->stages[3]);
					dir_re_head, dir_re_merge, merge,
	if (read_oid_strbuf(opt, &o->oid, &obuf) ||
	char *prev_path_desc;
		collision_ent = collision_find_entry(collisions, new_path);
				rename_type = RENAME_ONE_FILE_TO_ONE;
	 *    a/b/s          and         a/b/
				       change_branch, change_branch, path);
		struct rename_conflict_info *ci = entry->rename_conflict_info;
	final_cleanup_rename(re_info->merge_renames);
			       path);
		struct string_list *entries;
	*opt->repo->index = tmp_index;
			   !head_ent->non_unique_new_dir &&
			item->util = xcalloc(1, sizeof(struct stage_data));
	read_tree_recursive(opt->repo, tree, "", 0, 0,
			 * if we are not dealing with a rename + add-source
			    opt->priv->call_depth || would_lose_untracked(opt, prev_path1));
	if (merge_bases) {

	struct string_list *renames;
	if (S_ISDIR(dfs->mode)) {
	 * (multiple target directories received the same number of files),
	if (!ce)
						 struct tree *tree,
			out->buf[i] = '_';
		/* This should only happen when entry->non_unique_new_dir set */
		 * at the location where both files end up after the
	else if (!strcmp(s, "no-renormalize"))

		 * so that we don't have to pass it to around.
		 * src_entry, i.e. this didn't use to be a rename, in which
 */
			output(opt, 3,
					 DEFAULT_ABBREV);
		      const char *branch1,
	/*
	    merge_mode_and_contents(opt, b,
			}
		 *      file to a different path.
}
					struct path_hashmap_entry, e);
	return -1;
	return handle_file_collision(opt, path, a->path, b->path,
	code = unpack_trees_start(opt, merge_base, head, merge);
		free(new_path);

		entry = items_to_remove->items[i].util;
			unlink(df_path);
		merge_bases = reverse_commit_list(merge_bases);
	int a_valid = is_valid(a);

	dir_rename_warning(msg, is_add, clean, opt, ren);
			output(opt, 1, _("CONFLICT (%s): There is a directory with name %s in %s. "
				ret = err(opt, _("failed to symlink '%s': %s"),
	/* Unlink any D/F conflict files that are in the way */
							ci->ren2->branch);

static int read_oid_strbuf(struct merge_options *opt,
			string_list_append(&remove_from_head,
	 * otherwise look the same).  If it was originally a rename ('R'),
		struct tree *tree;
}
	const struct diff_filespec *changed;
	struct dir_rename_entry *entry;
			setup_rename_conflict_info(RENAME_TWO_FILES_TO_ONE,
				   "--all", merged_revision, NULL };
		break;
			/* 1. Renamed identically; remove it from both sides */

		 * two directory renames.  See testcase 10d of t6043.
}
	path_side_1_desc = xstrfmt("version of %s from %s", path, a->path);
				const struct diff_filespec *b)
	 */
			       COMMIT_LOCK | SKIP_IF_UNCHANGED))
		case RENAME_TWO_FILES_TO_ONE:
static void output_commit_title(struct merge_options *opt, struct commit *commit)
	 * file will simply be removed (in make_room_for_path()) to make
		       new_path, collision_paths.buf);
				return ret;
	    !strncmp(dirpath.buf, istate->cache[pos]->name, dirpath.len)) {

						  file_from_stage2 ? NULL : &mfi->blob))
	}
	 */
 */

{
				    ci->ren1->branch, ci->ren2->branch,
{
				    1 + opt->priv->call_depth * 2, &mfi))
				struct tree *merge,
						   dir_renames);
 * Toggle the stage number between "ours" and "theirs" (2 and 3).
		ce = opt->priv->orig_index.cache[pos];
	assert(opt->repo);
				  char *directory)
				 * update_file_flags() instead of
		pos = index_name_pos(&opt->priv->orig_index, path, strlen(path));
				output(opt, 2, _("Removing %s"), path);
 * Returns whether path was tracked in the index before the merge started,
		opt->branch1 = "Temporary merge branch 1";

		if (S_ISREG(a->mode)) {

		 * and update_wd=0, but that's a no-op.
				       struct hashmap *dir_rename_exclusions,
			return -1;
					clean = ret;
#include "cache.h"
		output_commit_title(opt, h2);
			BUG("entry->non_unqiue_dir not set and !new_path");
	int pos = index_name_pos(&opt->priv->orig_index, path, strlen(path));
			   struct string_list *a_renames,
		re->dst_entry->processed = 1;
static int merge_mode_and_contents(struct merge_options *opt,
			ce = index_file_exists(opt->repo->index, path, strlen(path),
	 * NOTE: It is usually a bad idea to call update_stages on a path
				      struct tree *common,
		char *new_path = find_path_for_conflict(opt, a->path,
					re->pair->one->path,
	va_end(ap);
			result->blob.mode = a->mode;
		o->path = temp->path = ci->ren1->pair->one->path;
	else if (skip_prefix(s, "subtree=", &arg))
			if (!(base = get_ref(opt->repo, merge_bases[i],
		DIFF_XDL_SET(opt, IGNORE_WHITESPACE_CHANGE);
	else if (!strcmp(s, "find-renames")) {
		return !dirty;
		entry = dir_rename_find_entry(dir_renames, old_dir);
		result->clean = 0;
		if (make_room_for_path(opt, path) < 0) {
			       &hashy, &mode_o);
static int handle_content_merge(struct merge_file_info *mfi,
}
	/* Return early if ren was not affected/created by a directory rename */
			 const char *path,
			      const char *old_path)
		return -1;
		output_commit_title(opt, h1);
				o = ren1->pair->one;
	 * If 'before' is renamed to 'after' then src_entry will contain
	 * pedagogically correct to adjust it.
	 * adjacent, in particular with the file of the D/F conflict
			if (ret)
 * and its oid and mode match the specified values
	struct strbuf sb = STRBUF_INIT;
			re->src_entry = insert_stage_data(opt->repo,
	 * correct things into stage 2 and 3, and to make sure that the
	hashmap_for_each_entry(&collisions, &iter, e,
			entry = xmalloc(sizeof(*entry));
	strbuf_vaddf(&opt->obuf, fmt, ap);
	}
		 * directory (e.g. 'some/subdir' -> ''), then we want to
	assert(opt->obuf.len == 0);


					     ren1->pair->two,
			   struct object_id *result, const char *path,

		ancestor_name = merge_base_abbrev.buf;
	}
	pos = index_name_pos(istate, dirpath.buf, dirpath.len);
		mfi->clean = 0;


		}
			diff_free_filepair(pair);
	if (dir_in_way(opt->repo->index, path, !opt->priv->call_depth, 0) ||
}
	}
	 * index by unpack_trees().  Due to that either-or requirement, we
}
			re->dst_entry->processed = 1;
	     !opt->priv->call_depth)) {
				      struct string_list *entries,
				   const struct diff_filespec *a,
				/*
		if (parse_commit(commit) != 0)


	git_config_get_int("merge.renamelimit", &opt->rename_limit);
		/*
	const char *modify_branch, *delete_branch;
		if (oideq(&a->oid, &b->oid) || oideq(&a->oid, &o->oid))
		char *best = NULL;
		 * want to code up the checks for it and a better fix is
}
		 * file.
		} else
struct dir_rename_entry {
					     struct tree *merge)
		return 0;
		 */
					 DEFAULT_ABBREV);
	/*
	}
	remove_hashmap_entries(dir_re_merge, &remove_from_merge);
	switch (parent_count) {
		*new_dir = xstrdup("");
		if (pair->status != 'R')
	if ((S_IFMT & a->mode) != (S_IFMT & b->mode)) {
	struct dir_rename_entry *entry;
	oentry = dir_rename_find_entry(dir_rename_exclusions, entry->new_dir.buf);
	else
		 * that:
		item->util = re;
	if (handle_change_delete(opt,
	struct hashmap *dir_re_head, *dir_re_merge;
	}
			collision_ent->target_file = new_path;
				break;
	 * a/b/.
		current->next = next;
	if (in_merge_bases(commit_b, commit_a)) {

#include "lockfile.h"
		if (show(opt, 3)) {
	/*
		      const struct diff_filespec *b,
	}
	/*
	add = &ci->ren1->dst_entry->stages[flip_stage(2)];
static void dir_rename_entry_init(struct dir_rename_entry *entry,
			if (update_stages(opt, path, o, a, b))
	}
		if (a_valid) {
	if (!unlink(path))
	item = string_list_lookup(entries, new_path);
 * file.  Return 1 if so.  If check_working_copy is non-zero, also
struct rename {
	 * Here, while working on Side 1, we could notice that otherdir was
/*
					&old_dir,        &new_dir);
update_index:

					&clean);

	strbuf_vaddf(&opt->obuf, err, params);

	re->dir_rename_original_dest = pair->two->path;

			       struct merge_options *opt,
	struct hashmap *dir_renames;
	/*
			ren2 = b_renames->items[j++].util;

	 * For each destination path, we need to see if there is a
	/*
			if (update_file_flags(opt, contents, path, 1, !a_valid))
		pos++;
	 * well, using update_stages_for_stage_data(), but as per the big
			if (update_file(opt, 0, contents, new_path))
		if (dir_in_way(opt->repo->index, path,
		if (S_ISREG(contents->mode) ||
{
	return clean_merge;
	FLEX_ALLOC_MEM(entry, path, newpath.buf, newpath.len);
	while (pos < istate->cache_nr &&
	for (iter = merge_bases; iter; iter = iter->next) {

	struct string_list *unmerged = xcalloc(1, sizeof(struct string_list));
		output(opt, 1, _("CONFLICT (implicit dir rename): Existing "
	}
		free(buf);
	if (opt->buffer_output > 1)

		if (!ret)
				strbuf_addf(&opt->obuf, "%.*s\n", len, title);
		remove_file(opt, 1, prev_path2,
	assert(opt->buffer_output <= 2);
			 * the submodule directory and update its index
		modify_branch = opt->branch2;
			free(old_dir);
		pos = -1 - pos;
			last_file = path;
					common, head, merge, entries,
	struct diff_filespec *a = ci->ren1->pair->two;


		dir_re_head  = xmalloc(sizeof(*dir_re_head));
		output(opt, 1, _("Refusing to lose dirty file at %s"),
	/* find commit which merges them */
	if (type != OBJ_BLOB) {
			return err(opt, msg, path, _(": perhaps a D/F conflict?"));
	set_commit_tree(commit, tree);
		if (tree_has_path(opt->repo, merge, merge_ent->dir)) {
	int last_len = 0;

	}
	free(path_desc);
	strbuf_addstr(&dirpath, path);
	int clean = 1, is_add;
				/* BUG: We should only remove ren1_src in

		output(opt, 1, _("Failed to merge submodule %s (commits not present)"), path);
		return;
		return clean;
#include "diff.h"
		re->processed = 0;
	} else {

		if (ci && !df_conflict_remains)
				     repo_get_commit_tree(opt->repo,
	if (opt->verbosity >= 5)
		}
	if (opt->subtree_shift) {
	if (ren->dir_rename_original_type == 'A' && clean) {
	ctx.date_mode.type = DATE_NORMAL;
	if (mfi->clean && was_tracked_and_matches(opt, path, &mfi->blob) &&
 */
		 * avoid returning
	for (i = 0, j = 0; i < a_renames->nr || j < b_renames->nr;) {
	/* Sanity checks on opt */
 */
		msg = _("Path updated: %s renamed to %s in %s, inside a "

	if (add_submodule_odb(path)) {
	struct dir_rename_entry *head_ent;
	if (!strcmp(s, "ours"))
	strbuf_addchars(&opt->obuf, ' ', opt->priv->call_depth * 2);
{
int parse_merge_opt(struct merge_options *opt, const char *s)
	} else {
				 * file already in the working copy, so call
			clean_merge = handle_content_merge(&mfi, opt, path,
		opt->detect_renames = 1;
static struct dir_rename_entry *check_dir_renamed(const char *path,
static int process_entry(struct merge_options *opt,
	oidcpy(&entry->stages[2].oid, &a->oid);
		const char *ren1_src, *ren1_dst;
	 * between a RENAME_DELETE conflict and RENAME_VIA_DIR (they
		merge_bases = get_merge_bases(h1, h2);
			result->clean = (merge_status == 0);
	 * check the current index instead of the original one.
	 * winner gets recorded in new_dir.  If there is no winner
				 */
		    !head_ent->non_unique_new_dir &&
	 * to ensure that's the case.
			break;
		return -1;
			 */

			    const struct hashmap_entry *entry_or_key,

	       end_of_old != old_path &&
			struct diff_filespec src_other, dst_other;
			if (a_valid)
	end_of_new = strchr(++end_of_new, '/');
	return unmerged;
		 * Check if last_file & path correspond to a D/F conflict;

		return NULL;
	 * reinstated with a new unique name at the time it is processed.
 * For dir_rename_entry, directory names are stored as a full path from the
		const struct diff_filespec *contents;
	RENAME_NORMAL = 0,
			/* One file renamed on both sides */
	assert(opt->detect_directory_renames >= MERGE_DIRECTORY_RENAMES_NONE &&
		default:
	if (!object)
		 * will only occur when it exists in stage 2 as a

	 * if our side of history added the same file basename to each of

			continue;
	 * somewhere else in a later commit?  At merge time, we just know
}
				     rename_branch, add_branch,
				output(opt, 1, _("CONFLICT (%s/delete): %s deleted in %s "
				ent /* member name */) {
				 rename_branch, delete_branch,
	 *    "a/b/c/d" was renamed to "a/b/some/thing/else"
				 opt->priv->call_depth ? NULL : orig->path,
	result->clean = 1;
	struct commit_list *ca = NULL;
		name2 = mkpathdup("%s", branch2);
	memset(opt, 0, sizeof(struct merge_options));
		strbuf_complete(&opt->obuf, '\n');
			       _("CONFLICT (add/add): Merge conflict in %s"),
static void update_entry(struct stage_data *entry,
 * level conflicts for the renamed location.  If there is a rename and
			     S_ISGITLINK(ci->ren1->pair->two->mode)))
				 * the file being renamed: clean merge.
	 * ensure that branch1 == opt->branch1.  So, simply flip arguments
	struct index_state *istate = opt->repo->index;
							ci->ren1->branch);
	 * have at least one non-null oid, meaning at least two will be
				    path, NULL,
	 *
		 * If it has stage #2 then it was tracked
	opts.rename_score = opt->rename_score;
				      struct tree *one, struct tree *two,
	       ren->dir_rename_original_type == 'R');
static char *apply_dir_rename(struct dir_rename_entry *entry,
				     path_hash(newpath.buf), newpath.buf) ||
		if (df_pathlen < pathlen &&


	 * the various handle_rename_*() functions update the index
		if (!old_dir)
		 * and that the current working copy happens to match, in
			a->path = ci->ren1->pair->two->path;
		/*
		return -1;

{
	 * because as noted above the root directory always exists so it
	return (2 + 3) - stage;

}
 *   Caller must ensure that old_path starts with entry->dir + '/'.
		 * merge-recursive interoperate anyway, so punting for
	 * merges that contain another found merge and save them in
		clean = 0;
	struct dir_rename_entry *entry = check_dir_renamed(path, dir_renames);

		 * which case we are unnecessarily touching the working
			int ret = 0, merge_status;
				const char *path, const char *old_path,
static int dir_in_way(struct index_state *istate, const char *path,
	struct object *object;
	if (prev_path1)
		update_wd = 0;
	}
			; /* no output */
	path_desc = xstrfmt("%s and %s, both renamed from %s",
		 * We cannot arbitrarily accept either a_sha or b_sha as
	} else if (o_valid && (!a_valid || !b_valid)) {
			 * Probably unclean merge, but if the renamed file
				clean_merge = -1;
}
	} else if (ren->dir_rename_original_type == 'A' && !clean) {
	struct strbuf merge_base_abbrev = STRBUF_INIT;
			break;
static int string_list_df_name_compare(const char *one, const char *two)
			return -1;
			return -1;

	int code, clean;
	 * flip arguments around if we don't have that.
		if (handle_file_collision(opt, a->path,

				BUG("ren1_src != ren2_src");
	}
				    char **old_dir, char **new_dir)
/*
		ret = remove_file_from_index(opt->repo->index, path);
static int update_file_flags(struct merge_options *opt,
	 * be dirty, though.
	for (i = 0; i < entries->nr; i++) {
	struct diff_filespec *o = &entry->stages[1];

	}
	int side = (ren->branch == opt->branch1 ? 2 : 3);
	struct diff_filespec *a = &entry->stages[2];
	}
		if (remove_file_from_index(opt->repo->index, path))
		} else {
	get_tree_entry(opt->repo,
		 * list and free'ing each, just lie and tell

	compute_collisions(&collisions, dir_renames, pairs);
		strbuf_release(&opt->obuf);
			char *new_path = unique_path(opt, path, add_branch);
	ci = xcalloc(1, sizeof(struct rename_conflict_info));
					  path, strerror(errno));
		case RENAME_DELETE:
	if (0 <= pos)
	struct string_list remove_from_merge = STRING_LIST_INIT_NODUP;

};
			goto free_buf;
{
	assert(opt->detect_renames >= -1 &&

	 * so, for this example, this function returns "a/b/c/d" in
#include "revision.h"
{
				  const char *path,

	}
 * See if there is a directory rename for path, and if there are any file
				int is_dirty,
		if (entry)
				 const char *branch1, const char *branch2,
				struct rename_conflict_info *ci)
{
	return hashmap_get_entry(hashmap, &key, ent, NULL);

	return renames;
			ce = opt->repo->index->cache[pos];
		if (add_cacheinfo(opt, contents, path, 0, refresh,
	struct commit *next_commit = get_ref(opt->repo, merge, opt->branch2);
				const struct diff_filespec *b,
	if (clear)
			}
		/* possible_new_dirs already cleared in get_directory_renames */
		if (update_stages(opt, dest->path, NULL,
			}
		*old_dir = xstrndup(old_path, end_of_old - old_path);
	char path[FLEX_ARRAY];
{
			      struct tree *merge)
	case 1:
#include "object-store.h"
#include "alloc.h"
		       "which will accept this suggestion.\n"),

				       "Rename directory %s->%s in %s"),
		 */
static int handle_rename_add(struct merge_options *opt,
			if (symlink(lnk, path))

		 *      !alt_path) could cause us to need to write the
		       collide_path);
		remove_file(opt, 1, prev_path1,
	/*

			 * into stage 1, from head-commit into stage 2, and
static int tree_has_path(struct repository *r, struct tree *tree,
				/*
		struct string_list_item *item;
	clean = (opt->detect_directory_renames == MERGE_DIRECTORY_RENAMES_TRUE);
			return -1;
}
		unsigned cnt = commit_list_count(merge_bases);
		/* we were not tracking this path before the merge */
	}
	}
			unsorted_string_list_delete_item(&opt->priv->df_conflict_file_set,
			"directory that was renamed in %s; moving it to %s.");
			       " at %s; adding as %s instead"),
			strbuf_release(&head_ent->new_dir);
		item = string_list_lookup(entries, re->pair->one->path);
				    path_side_1_desc,
		 merge:1;
{
		}
		oidcpy(result, b);
		count = item->util;
	char *temp = xstrdup(path);
	 * Record the original change status (or 'type' of change).  If it
{
		       "  git update-index --cacheinfo 160000 %s \"%s\"\n\n"
	for (i = 0; i < rename->nr; i++) {
			item->util = xcalloc(1, sizeof(int));
		       &re->dst_entry->stages[stage].mode);
	} else {
		*end = '\0';

						      1, /* update_cache */
	       "Rename %s->%s in %s"),
			       "%s was renamed to multiple other directories, "
}
			 struct diff_filespec *o,
			last_file = NULL;
static int update_file(struct merge_options *opt,
					       struct tree *o_tree,
 *      doing the previous check and thus failing testcase 6b.)
				   const struct diff_filespec *blob)
static int would_lose_untracked(struct merge_options *opt, const char *path)
		msg = _("Path updated: %s added in %s inside a "
		 * old one as unnecessary (...unless it is shared by
			 */
				       "and %s in %s. Version %s of %s left in tree."),
				const struct diff_filespec *b,
		}
	return lookup_tree(repo, &shifted);
	struct diff_filespec *b = ci->ren2->pair->two;
	 *   Side 1:      smrtdir/afile, otherdir/bfile
	free(pairs->queue);
		}
	if (!update_wd)
							     entries);

 *   NOTE: We do NOT check for rename/rename(2to1) conflicts at the
						 struct tree *b_tree,
	}
			"inside a directory that was renamed in %s, "
	initial_cleanup_rename(merge_pairs, dir_re_merge);
		ren1->src_entry->processed = 1;
}
		}
 * there are no conflicts, return the new name.  Otherwise, return NULL.
	prev_path_desc = xstrfmt("version of %s from %s", path, a->path);
			goto free_buf;
static int merge_submodule(struct merge_options *opt,
							    a, b);
		item = string_list_lookup(entries, re->pair->two->path);
	struct object_array merges = OBJECT_ARRAY_INIT;
		    update_stages(opt, a->path, NULL, a, NULL))
	 */
				     struct rename_conflict_info *ci)

{


{
	rc = unpack_trees(3, t, &opt->priv->unpack_opts);
				       struct tree *tree,
		if (add_cacheinfo(opt, b, path, 3, 0, options))
			strbuf_release(&merge_ent->new_dir);
	if (opt->branch1 != branch1) {
		}
	struct dir_rename_entry *e;
	/* .. and so is no existing file */
		return make_virtual_commit(repo, (struct tree*)object, name);
		 * original entry for re->dst_entry is no longer
		entry->possible_new_dirs.strdup_strings = 1;
	string_list_clear(items_to_remove, 0);
	init_tree_desc_from_tree(t+2, merge);
	/*
	if (merge_mode_and_contents(opt, a, c1,
		 */
		return NULL;
	struct diff_filespec *b = ci->ren2->pair->one;

	ll_opts.xdl_opts = opt->xdl_opts;
			     struct commit *a, struct commit *b)
				     rename_branch == opt->branch1 ? NULL : dest);
		opt->renormalize = 0;
{
		ancestor_name = "merged common ancestors";
				    struct commit *h2,
		merge = shift_tree_object(opt->repo, head, merge,
{
		}
				const struct diff_filespec *o,
			if (!mfi->clean) {
static inline int flip_stage(int stage)

		}
			 * Manually fix up paths; note:
		opt->xdl_opts &= ~XDF_DIFF_ALGORITHM_MASK;
			    &match_all, save_files_dirs, opt);
			    const struct object_id *head,

	ostage2 = flip_stage(ostage1);
}
	assert(ren->dir_rename_original_dest);
}

	const char *key = keydata;

				const char *path,
	opt->ancestor = NULL;  /* avoid accidental re-use of opt->ancestor */
{
	if (clean &&
	 *    a/b/star/foo/whatever.c -> a/b/tar/foo/random.c
			other_branch = opt->branch1;
	if (pos < 0)
	} else if (opt->ancestor && !opt->priv->call_depth) {
	 * behavior for those paths.
						      &collisions,

		 * longer exists on the other side of history), the
				setup_rename_conflict_info(RENAME_DELETE,
	strbuf_release(&merge_base_abbrev);
	const char *last_file = NULL;
			 */
	oidcpy(result, a);
				bad_max = max;
}
		 * possible_new_dirs that it did the strdup'ing so that it
			/*
		int bad_max = 0;
		nce = refresh_cache_entry(istate, ce,
			re->dst_entry = item->util;
			ren2->processed = 1;
	 * renames done by the other side of history.  Since that other
		ret = (obuf.len == abuf.len && !memcmp(obuf.buf, abuf.buf, obuf.len));
			if (strcmp(ren1_dst, ren2_dst) != 0)
/*

	struct hashmap_entry ent;
	if (merge_start(opt, repo_get_commit_tree(opt->repo, h1)))
			if (compare <= 0)
	hashmap_entry_init(&key.ent, strhash(dir));
	 *   c) The target path is usable (i.e. not involved in D/F conflict)
		struct rename *ren1 = NULL, *ren2 = NULL;
	if (oideq(&o->oid, &a->oid))
	else if (!strcmp(s, "ignore-cr-at-eol"))

		int path_clean;
	const struct rename *re;
	opt->priv->unpack_opts.aggressive = !merge_detect_rename(opt);
{
	entry->stages[2].mode = a->mode;
{
{

	ci->ren2->src_entry->stages[ostage2].path = b->path;
	 *
		output(opt, 1, _("Adding as %s instead"), new_path);
	 */
			    write_object_file(result_buf.ptr, result_buf.size,
	       a->path, c->path, rename_branch,

		       new_path, collision_paths.buf);

	size_t i = out->len;

	hashmap_for_each_entry(dir_renames, &iter, entry,
						   entries, &re_info);
			oidcpy(&src_other.oid,
	 * explicitly rather than relying on unpack_trees() to have done it.
		    struct commit **result)
		long value = parse_algorithm_value(arg);
			}
	 * re->dst_entry->stages[stage].oid will be the null_oid, so it's
static unsigned int path_hash(const char *path)
{

				    1 + opt->priv->call_depth * 2, &mfi_c2))

	 *   Base commit: dumbdir/afile, otherdir/bfile
	if (write_locked_index(opt->repo->index, &lock,
						  extra_marker_size);
					   merge_ent->dir)->util = merge_ent;
					  ci->ren1->branch,
					   head_ent->dir)->util = head_ent;
		dfs->mode = 0;
						      dir_rename_exclusions,
	}
	repo_init_revisions(repo, &revs, NULL);
	 * It may be tempting to actually update the index at this point as
			clean_merge = 0;
			ren1 = a_renames->items[i++].util;
		const char *conf;
	 */
/*
		    path[last_len] == '/') {
	xsnprintf(merged_revision, sizeof(merged_revision), "^%s",
 * Merge the commits h1 and h2, return the resulting virtual
				       change, path, delete_branch, change_past,
			ret = update_file(opt, 0, o, update_path);
	/*
	renames = xcalloc(1, sizeof(struct string_list));
		 * with conflict markers. The cleanness flag is
 * Create a dictionary mapping file names to stage_data objects. The
	} else if (collision_ent->source_files.nr > 1) {
	const char *ancestor_name;
	return rc;
	}
		}
	}

	 * For
				if (!ret)
			/*
	 * non-matching character, we're now comparing:

						      0  /* update_wd    */))
	 * implicit rename into a directory we renamed on our side, because

	int ret = 0; /* assume changed for safety */
				oidcpy(&result->blob.oid, &a->oid);

					a = ren1->pair->two;
	if (entry->new_dir.len == 0)
		enum object_type type;

	opt->priv->unpack_opts.dst_index = &tmp_index;

	opts.output_format = DIFF_FORMAT_NO_OUTPUT;
		head_ent = dir_rename_find_entry(dir_re_head, merge_ent->dir);
		output(opt, 2, _("Auto-merging %s"), filename);

	merge_recursive_config(opt);
		 * tree file.  It's not a likely enough scenario that I
			clean_merge = handle_file_collision(opt,
	if (collision_ent == NULL)
	int i;
			goto update_index;
	 * but it can't.  This function needs to know whether path was in
	case 0:
{

				       const char *branch,
}
						 &collision_ent->source_files);
		update_path = alt_path = unique_path(opt, path, change_branch);
			 * know that head_ent->new_dir and merge_ent->new_dir
			int renamed_stage = a_renames == renames1 ? 2 : 3;
		if (!merged_merge_bases)
		} else if (j >= b_renames->nr) {
		opt->detect_renames = 0;
	flush_output(opt);
			if (!e->processed) {
struct rename_info {
		return;
				    _("modify"), _("modified"));
					 struct hashmap *collisions,
			   const struct object_id *b)
	} else if (ren->dir_rename_original_type == 'R' && !clean) {
				       struct tree *o_tree,
	return clean;
			struct strbuf strbuf = STRBUF_INIT;
			case MERGE_VARIANT_OURS:
	struct path_hashmap_entry *entry;
	 *
 *      i.e. a rename where only some of the files within the directory
					  ci->ren2->branch,
					struct hashmap *dir_rename_exclusions,
		ren1->dst_entry->processed = 1;
	unsigned non_unique_new_dir:1;
{
			return -1;
	*old_dir = NULL;

	pair->two->path = new_path;
		string_list_insert(&a_by_dst, sre->pair->two->path)->util
	 * suggestion to the user, but leave it marked unmerged so the
						 dir_re_head, head,
	       "rename \"%s\"->\"%s\" in \"%s\"%s"),
	 * We've found the first non-matching character in the directory
	 * We can skip updating the working tree file iff:

	 * To achieve this, we sort with df_name_compare and provide
	merge_status = ll_merge(result_buf, a->path, &orig, base,
				int file_from_stage2 = was_tracked(opt, path);
	}
	merged_merge_bases = pop_commit(&merge_bases);
				ren1 = a_renames->items[i++].util;

		 * However, add_cacheinfo() will delete the old cache entry
	return 0;
		output(opt, 1, _("CONFLICT (directory rename split): "
				output(opt, 1, _("CONFLICT (%s/delete): %s deleted in %s "
	va_end(params);

	return ret;
}
		*clean_merge &= (new_path != NULL);
		sre = b_renames->items[i].util;
}
			ren2_dst = ren2->pair->two->path;
		DIFF_XDL_SET(opt, IGNORE_WHITESPACE_AT_EOL);
				ren2 = b_renames->items[j++].util;
	int i, j;
		if (status == SCLD_EXISTS)
		struct tree *merge,
}
	int clean = 1;
		} else {
	return strcmp(e1->dir, e2->dir);
		shift_tree(repo, &one->object.oid, &two->object.oid, &shifted, 0);
	 * conflict.  If the D/F directory ends up being removed by the
	struct rev_info revs;
	return (opt->detect_renames >= 0) ? opt->detect_renames : 1;
	while ((end = strrchr(temp, '/'))) {
{
			/*
					  struct rename *ren)
 * Get information of all renames which occurred in 'pairs', making use of
	if (!*subtree_shift) {
					struct tree *tree,
	opt->priv->unpack_opts.head_idx = 2;
		}
	/*
			o->path = NULL;
			break;
	}
}
}
	struct diff_filespec null;
	struct dir_rename_entry *oentry = NULL;
	    end_of_old != old_path && end_of_old[-1] == '/') {

}
				 orig, dest,
		if (value < 0)
	ri->head_renames  = get_renames(opt, opt->branch1, head_pairs,
	if (branch1 != opt->branch1) {
	 * As it turns out, this also prevents N-way transient rename
		 *     '' + '/filename'
			 const struct hashmap_entry *eptr,
	unsigned short mode_o;

}
	struct path_hashmap_entry *entry;
			  const struct diff_filespec *o,
			       head_ent->dir, merge_ent->new_dir.buf, opt->branch2);
/*
 * Fredrik Kuivinen.
	for (i = 0; i < opt->priv->df_conflict_file_set.nr; i++) {
	       opt->detect_directory_renames <= MERGE_DIRECTORY_RENAMES_TRUE);
		dir_rename_init(dir_re_merge);
	if (clean < 0)
	const struct path_hashmap_entry *a, *b;
	for (i = 0; i < pairs->nr; ++i) {
		}

	int ret = 0;
		return;

		 */
	} else if (a_valid && b_valid) {
		/*
	hashmap_entry_init(&key.ent, strhash(target_file));
	o->path = a->path = b->path = (char*)path;
	va_start(ap, fmt);
	opt->priv->unpack_opts.merge = 1;
}
		if (last_file &&
		const char *add_branch;
			       MERGE_DIRECTORY_RENAMES_CONFLICT);
int merge_trees(struct merge_options *opt,
		if (handle_file_collision(opt, b->path,
	 * merge, then we won't have to touch the D/F file.  If the D/F
		/*
					     ren2->pair->two);
}

	 * Here we only care that entries for D/F conflicts are
		ancestor_name = "empty tree";
}
		df_conflict_remains = 1;
	string_list_clear(&b_by_dst, 0);
			continue;
	} else if (!o_valid && !a_valid && !b_valid) {
			add_object_array(merges.objects[i].item, NULL, result);
			opt->ancestor = "constructed merge base";
				return 0;
			    a->path, b->path, o->path);
	unsigned reported_already:1;
		 * For cases with a single rename, {o,a,b}->path have all been
	if (ci && dir_in_way(opt->repo->index, path, !opt->priv->call_depth,
{
		}
	 */
	output(opt, clean ? 2 : 1, msg,

	if (is_valid(add)) {

		/* if there is no common ancestor, use an empty tree */
				  contents->mode, oid_to_hex(&contents->oid), path);
					 &merged_merge_bases->object.oid,
				       change, old_path, delete_branch, change_past, path,
		case RENAME_NORMAL:
	 * function, because we strictly require all code paths in
	struct stage_data *src_entry;
		return clean;


{
			struct stage_data *e = entries->items[i].util;
	if (status) {
	char *end;
	for (i = 0; i < b_renames->nr; i++) {
	strbuf_addstr(&new_path, &old_path[oldlen]);
{

			       "renames tried to put these paths there: %s"),
					     b, a);

					clean = 0;
		int i;
	assert(opt->ancestor != NULL);
	 * See testcases 9e and all of section 5 from t6043 for examples.

	 */
			       df_path);
	 * Note that we do not need to worry about merge-recursive itself
	}
#include "builtin.h"
}
		free(buf);
	 * src_entry nor dst_entry can have all three of their stages have
	 * this lets us remember and report accurately about the transitive
	diff_queued_diff.queue = NULL;
{
	ci->ren1->dst_entry->stages[other_stage].path = mfi.blob.path = c->path;
		hashmap_remove(dir_renames, &entry->ent, NULL);
	char *file_path = dest->path;
	int clean;
	 * those directories, then all N of them would get implicitly
	}
		}
		}
		if (update_file(opt, 0, &mfi.blob,
	if (!git_config_get_string("diff.renames", &value)) {
{
		/* Update dest->path both in index and in worktree */

static void record_df_conflict_files(struct merge_options *opt,
			collision_ent = xcalloc(1,
	struct merge_remote_desc *desc;
		struct collision_entry *collision_ent;


}
}
	ret = add_index_entry(istate, ce, options);
	int ostage1, ostage2;

		    update_stages(opt, b->path, NULL, NULL, b))
			add_branch = opt->branch1;
	const char *branch; /* branch that the rename occurred on */
	object = deref_tag(repo, parse_object(repo, oid),
		int pos;
			"directory that was renamed in %s; moving it to %s.");

		re->dir_rename_original_dest = NULL;
	a = container_of(eptr, const struct path_hashmap_entry, e);
{
#include "merge-recursive.h"
	unpack_trees_finish(opt);
	va_list params;
	if (!in_merge_bases(commit_base, commit_a) ||
static int merge_trees_internal(struct merge_options *opt,
	int i;
	pair->status = 'R';

		if (type != OBJ_BLOB) {

				    const char *path,
		opt->detect_renames = git_config_rename("merge.renames", value);
	opt->detect_renames = -1;
	if (code != 0) {
	 * saying the file would have been overwritten), but it might
	 * the file to end up in smrtdir.  And the way to achieve that is
		get_files_dirs(opt, merge);
	       other_branch, ren->pair->two->path);
				 * Also, there is no need to overwrite the
	/* get all revisions that merge commit a */
	/* Now we've got all merges that contain a and b. Prune all
		opt->priv->call_depth++;
	struct string_list_item *item;
	return ret;
		get_files_dirs(opt, head);
				  oid_to_hex(&contents->oid), path);
		final_cleanup_renames(&re_info);
	if (merge_mode_and_contents(opt, o, a, b, path_desc,
			clean_merge = handle_rename_normal(opt, path, o, a, b,
 *      testcase 6b in t6043 for details.)
		}
		saved_b2 = opt->branch2;
	if (opt->buffer_output < 2 && opt->obuf.len) {
				const struct diff_filespec *o,
		clean = 0;
	}
	if (oideq(&merge_base->object.oid, &merge->object.oid)) {
	 * transitive rename to move it from dumbdir/bfile to

/*

			 * Manually fix up paths; note,
	 * or an untracked file to get lost.  We'll either overwrite with

	/*
			 const char *branch)
		} else if (show(opt, 2))

 * Since we want to write the index eventually, we cannot reuse the index
		return 0;
	    !(commit_a = lookup_commit_reference(opt->repo, a)) ||
		} else {
};
}
	if (ren2 && ren1->branch != opt->branch1) {
	struct stage_data *e = xcalloc(1, sizeof(struct stage_data));
			commit_list_insert(base, &ca);
			 * guess it's a clean merge?
		 * we had that path and want to actively remove it.
{

	/*
struct merge_file_info {
/*
	if (in_merge_bases(commit_a, commit_b)) {
		 * path.  Before creating a new entry, we need to mark the
				    opt->priv->call_depth * 2, mfi))
		return 1;
	ci->ren1->src_entry->stages[other_stage].path = a->path;
	}
					      struct rename *ren2)
		free(value);
static struct string_list *get_unmerged(struct index_state *istate)
			return -1;

	cache_tree_free(&opt->repo->index->cache_tree);
static int handle_rename_rename_1to2(struct merge_options *opt,
	       a->path, c1->path, ci->ren1->branch,
			ll_opts.variant = 0;
	 */
 */
	struct hashmap collisions;
		/*
			diff_free_filepair(pair);
			break;
			update_wd = 0;
	/* Find or create a new re->dst_entry */
			output_commit_title(opt, commit_b);
				       "and %s to %s in %s. Version %s of %s left in tree."),
		 * having complete messages makes the job easier for
	return 0;
	 * directory needs to be written to the working copy, then the D/F
	va_start(params, err);
		} else {
		if (show(opt, 4) || opt->priv->call_depth)
}
							   is_dirty,
	hashmap_for_each_entry(dir_renames, &iter, e,
			clean_merge = path_clean;
}
				   const char *branch2,

static int handle_rename_normal(struct merge_options *opt,
				      const char *subtree_shift)
			string_list_append(&remove_from_merge,

		record_df_conflict_files(opt, entries);
		if (clean < 0) {
		output(opt, 5, Q_("found %u common ancestor:",


		if (!item)
	ll_opts.renormalize = opt->renormalize;
	struct commit *commit_base, *commit_a, *commit_b;
				 struct diff_filespec *b)
		dir_re_merge = get_directory_renames(merge_pairs);
 * Returns an index_entry instance which doesn't have to correspond to
	 * git-completion.bash when you add new options
	else if (!strcmp(s, "subtree"))
		 * available if we restructure how unpack_trees() and

 *   3. Check for rename/rename(1to2) conflicts (at the directory level).
	ci->ren1->dst_entry->processed = 0;
#include "diffcore.h"
	 * the working tree due to EITHER having been tracked in the index
	if (!ren)
						 &collision_ent->source_files);
	       c->path, add_branch);
};
		struct tree *merge_base)
	assert(opt->ancestor == NULL ||
			       struct rename *ren)
	 * We want each directory rename to represent where the bulk of the
		size_t df_pathlen = strlen(df_path);
	opts.flags.recursive = 1;
		opt->buffer_output = 0;
		DIFF_XDL_SET(opt, IGNORE_WHITESPACE);
	int rc;
	char *new_path = NULL;
	if (!renormalize)
			conf = _("directory/file");
			/* Directory didn't change at all; ignore this one. */
		new_path = check_for_directory_rename(opt, pair->two->path, tree,

	return clean;
		clean = 0; /* not clean, but conflicted */
		output(opt, 1, _("Failed to merge submodule %s (not fast-forward)"), path);
			re->src_entry = item->util;
		 */
	 * and the file need to be present, then the D/F file will be
			continue;
	}
				clean_merge = -1;
#include "blob.h"
	 * target directory received the most files so we can declare it to
static int is_valid(const struct diff_filespec *dfs)
			unuse_commit_buffer(commit, msg);
		}
	 * The caller needs to have ensured that it has pre-populated
		/* BUG: We should only mark src_entry as processed if we
						 struct tree *a_tree,
	struct string_list *merge_renames;

				break;
	 * directory which still exists is not considered to have been
		name1 = mkpathdup("%s", branch1);
	ce = index_file_exists(opt->priv->unpack_opts.src_index,
	/*
		 */
	return clean;
		 * i.e. whether path is last_file+'/'+<something>.
		opt->renormalize = 1;
			strbuf_addstr(&entry->new_dir, best);


/* Per entry merge function */
	dir_renames = xmalloc(sizeof(*dir_renames));
	}
	struct index_state tmp_index = { NULL };
					re->pair->two->path,
		if (!item) {
					      blob_type, &result->blob.oid))
	get_tree_entry_if_blob(r, &a->object.oid, path, &e->stages[2]);
		      const struct diff_filespec *a,
		DIFF_XDL_CLR(opt, NEED_MINIMAL);
						 struct diff_filepair *pair,
			} else {
	}
	/*
	}
	       "Rename %s->%s in %s. "
		} else if (!strcasecmp(value, "conflict")) {
 * There are a couple things we want to do at the directory level:
 * Recursive Merge algorithm stolen from git-merge-recursive.py by

		oidcpy(&e->stages[ce_stage(ce)].oid, &ce->oid);
			ren2->src_entry->processed = 1;

	/* save all revisions from the above list that contain b */

static int handle_file_collision(struct merge_options *opt,
	if (is_valid(add)) {
				    renamed_stage == 2 || !was_tracked(opt, ren1_src));
				}

			enum rename_type rename_type;
					a = &src_other;
	mfi.clean &= !alt_path;
	else if (!strcmp(s, "histogram"))
			return -1;
	const struct rename *ren = ci->ren1;
			 const char *path)

		} else {
		return -1;

			assert(opt->branch1 == ci->ren1->branch);

		if (change_branch != opt->branch1 || alt_path)
				const struct diff_filespec *changed,
		const char *path,
			       "files."),
			       path);
			       "path(s) there: %s."),
		/*
	enum rename_type rename_type;
			return -1;

	 * 2 will notice the rename from dumbdir to smrtdir, and do the
		 * It's weird getting a reverse merge with HEAD on the bottom
	int i;
 *      the original directory.  These represent a partial directory rename,
	/*
			    struct commit **result)
	diff_queued_diff.nr = 0;
		opts.detect_rename = DIFF_DETECT_RENAME;
	e2 = container_of(entry_or_key, const struct collision_entry, ent);
							&b->oid);
		die("revision walk setup failed");
		update_path = alt_path = unique_path(opt, collide_path, "merged");
		opt->subtree_shift = "";
 * Get the diff_filepairs changed between o_tree and tree.
{
	 * around if we don't have that.
			/*
			 * a clean merge?
	} else {
	}
	 * Now that 'foo' and 'foo/bar' compare equal, we have to make sure
/*
		return 1;
		}
				clean_merge = -1;

							   ci);
	strbuf_release(&abuf);
	char *path_side_1_desc;
				MERGE_DIRECTORY_RENAMES_TRUE :
	int ret;
	struct diff_queue_struct *ret;
		return -1;

		output(opt, 2, _(
	 * performed.  Comparison can be skipped if both files are
			case MERGE_VARIANT_NORMAL:
			return -1;

	opt->priv = xcalloc(1, sizeof(*opt->priv));
		return -1;

	ci->rename_type = rename_type;
					  struct tree *tree,
		}
				struct rename_conflict_info *ci)
			}
		output(opt, 1, _("CONFLICT (implicit dir rename): Cannot map "
	 * what if someone first moved two files from the original
	if (renormalize_buffer(idx, path, obuf.buf, obuf.len, &obuf) |
	 * to know which portion of the directory, if any, changed.
		 */
		output(opt, 1, _("Failed to merge submodule %s (multiple merges found)"), path);
			last_len = len;
			free(file_path);
		shift_tree_by(repo, &one->object.oid, &two->object.oid, &shifted,
			try_merge = 0;

}
enum rename_type {
		 * Since we're renaming on this side of history, and it's
	entry->processed = 1;
static int was_tracked(struct merge_options *opt, const char *path)
			 * collisions.

#include "submodule.h"
		}
		e->stages[ce_stage(ce)].mode = ce->ce_mode;
			   name, strlen(name));
			output(opt, 1, _("CONFLICT (rename/rename): "
		flush_output(opt);
		string_list_insert(&collision_ent->source_files,
	 */
	 * second.  Doing otherwise would break
	oidcpy(&entry->stages[3].oid, &b->oid);
		re->pair = pair;
			       &tree->object.oid, path,
		re->branch = branch;
	parent_count = find_first_merges(opt->repo, &merges, path,
			      struct tree *head,
	assert(ren->dir_rename_original_type == 'A' ||

			      const char *name)
	/* If there is a D/F conflict and the file for such a conflict
	const char *msg = _("failed to create path '%s'%s");
		/*

	if (oideq(&two->object.oid, &shifted))
	    !df_conflict_remains) {
		get_renamed_dir_portion(pair->one->path, pair->two->path,
	if (repo_index_has_changes(opt->repo, head, &sb)) {
	return handle_change_delete(opt,

	strbuf_addf(&newpath, "%s~", path);
		struct string_list *entries)
				  side == 2 ? &mfi.blob : NULL,
	strbuf_release(&collision_paths);

				setup_rename_conflict_info(RENAME_ADD,

	/* Copy the old and new directories into *old_dir and *new_dir. */
				       "Rename directory %s->%s in %s. "
			     const char *path,
	int pos;
};
			 */
			hashmap_put(dir_renames, &entry->ent);
		base  = mkpathdup("%s:%s", opt->ancestor, o->path);
	status = safe_create_leading_directories_const(path);
	 * was originally an add ('A'), this lets us differentiate later
static int err(struct merge_options *opt, const char *err, ...)
			       struct hashmap *dir_renames,
	hashmap_init(map, collision_cmp, NULL, 0);
		else
	 * the source of one of our directory renames.
	    !in_merge_bases(commit_base, commit_b)) {
		struct cache_entry *nce;
	 * This may look like it can be simplified to:
				 opt->priv->call_depth ? orig->path : dest->path,

		 *      may know the file by.
		/*
void init_merge_options(struct merge_options *opt,
				MERGE_DIRECTORY_RENAMES_CONFLICT;
				    const char *branch1,
	 *
			else if (opt->priv->call_depth)
}
			output_commit_title(opt, commit_a);
		for (i = 0; i < num_merge_bases; ++i) {
	}
			       conf, path, other_branch, path, new_path);
	assert(opt->rename_score >= 0 && opt->rename_score <= MAX_SCORE);


	RENAME_ONE_FILE_TO_ONE,
	 * from *this* side of history.  This is not representable in the
	struct merge_options *opt = context;
	 * have a rename of old_path's directory to the root directory.
	unsigned clean:1,
	ret = get_tree_entry(r, tree, path, &dfs->oid, &dfs->mode);
		opt->verbosity >= 5;
	if (was_dirty(opt, collide_path)) {
	    opt->detect_directory_renames == MERGE_DIRECTORY_RENAMES_CONFLICT &&
	 * After dropping the basename and going back to the first
		char *new_path;
		*result = head;
	} else {
		struct diff_filepair *pair = pairs->queue[i];
	 * end_of_old got back to the beginning of some subdirectory, then
		opt->detect_renames = 1;
{
	}
					     struct hashmap *dir_re_merge,
				if (!oideq(&a->oid, &b->oid))
static void flush_output(struct merge_options *opt)
	 * currently exists in the working tree, we want to allow it to be
			    const struct hashmap_entry *eptr,

	int twolen = strlen(two);
	char *path = c->path;
	return 0;

	/*
		case RENAME_ONE_FILE_TO_TWO:

			 * BUG: We should only mark src_entry as processed
		return;
		else {
		if (update_file(opt, 0, &mfi.blob,
		       pair->two->path,
	/* Sanity check on repo state; index must match head */
	if (0 > pos)
 *
	memset(&opt->priv->unpack_opts, 0, sizeof(opt->priv->unpack_opts));
	int options = ADD_CACHE_OK_TO_ADD | ADD_CACHE_SKIP_DFCHECK;


		for (i = 0; i < entry->possible_new_dirs.nr; i++) {

	/* Merge the content and write it out */
	if (!opt->buffer_output)
	if (is_valid(a)) {
	 *
	return new_path;
		/*
		else if (oideq(&b->oid, &o->oid))
					result->clean = 0;
	 * moving into place.  That slot will be empty and available for us
	/* Remove rename sources if rename/add or rename/rename(2to1) */
			/* do not overwrite file if already present */
		case RENAME_ONE_FILE_TO_ONE:
	if (opt->priv->call_depth) {
	if (merge_start(opt, head))
	 * where the bulk of the files went.
	else if (!strcmp(s, "patience"))
	is_add = (ren->dir_rename_original_type == 'A');
			       _("Removing %s to make room for subdirectory\n"),
	assert(opt->recursive_variant >= MERGE_VARIANT_NORMAL &&
	free(prev_path_desc);
	read_mmblob(&src2, &b->oid);

	struct strbuf obuf = STRBUF_INIT;
}
	 * to make sure that the content merge puts HEAD before the other
		       ren->pair->one->path, ren->branch,
		}

	       (!opt->priv->call_depth && file_exists(newpath.buf))) {
					  ci->ren2->branch,
				update_entry(ren1->dst_entry, o, a, b);
	       o->path, a->path, ci->ren1->branch,
	struct diff_filespec *a = ci->ren1->pair->one;
			string_list_append(&remove_from_head,
	 * before calling update_file on that same path, since it can
	} else {
	strbuf_init(&entry->new_dir, 0);
					     oid_to_hex(merge_bases[i]))))
	hashmap_entry_init(&entry->e, path_hash(entry->path));

		struct cache_entry *ce;
	strbuf_addstr(base, path);
		if (ignore_case) {
		remove_file(opt, 1, path, !a->mode);
	}
	 * sometimes lead to spurious "refusing to lose untracked file..."
		 * If stage #0, it is definitely tracked.
 * NOTE:
			oidcpy(&dst_other.oid,
					  NULL, NULL,
			opt->branch2 : opt->branch1);
			if (handle_modify_delete(opt, path, o, a, b))
static char *unique_path(struct merge_options *opt,

	if (o)
{
	 * The first loop below simply iterates through the list of file
		 */
{
			result->blob.mode = b->mode;
				setup_rename_conflict_info(RENAME_VIA_DIR,
			}
	}
	struct rename *ren1;
			   struct string_list *b_renames)
static void initial_cleanup_rename(struct diff_queue_struct *pairs,
 *         directory level, because merging directories is fine.  If it
	if (prepare_revision_walk(&revs))
		return 1;


		       const struct diff_filespec *contents,
				const struct diff_filespec *o,

	}
}
		 * through the entries. Keeping it in the merge_options as
	       "Rename \"%s\"->\"%s\" in branch \"%s\" "
	return handle_file_collision(opt,
{
	strbuf_addch(&dirpath, '/');
	discard_index(opt->repo->index);
	int clean = 1;

/*
		BUG("fatal merge failure, shouldn't happen.");
	strbuf_addchars(&opt->obuf, ' ', opt->priv->call_depth * 2);
	const char *update_path = collide_path;

		/*
 * 0 in the case where the working-tree dir exists but is empty.
				    prev_path_desc,
	struct diff_filespec *o = ci->ren1->pair->one;
		/*
			contents = a;

	if (strcmp(a->path, b->path) || strcmp(a->path, o->path) != 0) {
		}
		merge_ent = dir_rename_find_entry(dir_re_merge, head_ent->dir);
	 * the directory rename (otherwise, '\0' and NULL for these two vars).
			return -1;
					&clean);
			       "%s, even though it's in the way."),
		if (is_dirty) {
			struct cache_entry *ce;
				goto cleanup_and_return;
				try_merge = 1;
	struct index_state *istate = opt->repo->index;
			return -1;
{
	} else if (would_lose_untracked(opt, collide_path)) {
		collision_ent->reported_already = 1;
		    path[df_pathlen] == '/' &&
{
		opt->xdl_opts = DIFF_WITH_ALG(opt, HISTOGRAM_DIFF);
static void compute_collisions(struct hashmap *collisions,
		if (S_ISREG(e->stages[2].mode) || S_ISLNK(e->stages[2].mode)) {
}
			item = string_list_insert(unmerged, ce->name);
	discard_index(&opt->priv->orig_index);
				struct merge_options *opt,
	struct collision_entry *e;
}
}
			return -1;
};
	e1 = container_of(eptr, const struct collision_entry, ent);
	return 0;

				       "and %s in %s. Version %s of %s left in tree at %s."),
	 * to put multiple paths into the same location.  Warn
			safe_create_leading_directories_const(path);

		 * Write the file in worktree at file_path.  In the index,
		update_path = alt_path = unique_path(opt, collide_path, "merged");
			     NULL, 512);
			pos = index_name_pos(opt->repo->index, path, strlen(path));

		 * For rename/rename conflicts, we'll manually fix paths below.

		 * The relevant directory sub-portion of the original full
		if (!buf) {
		 * lists below and the ugliness of the nested if-statements,
static void output(struct merge_options *opt, int v, const char *fmt, ...)
			/* Renamed in 1, maybe changed in 2 */

	struct string_list b_by_dst = STRING_LIST_INIT_NODUP;
			break;
				size = strbuf.len;
}
			clean_merge = 0;

	return strbuf_detach(&newpath, NULL);
		    !strbuf_cmp(&head_ent->new_dir, &merge_ent->new_dir)) {
	 */
				ret = err(opt, _("failed to open '%s': %s"),
			 * merges cleanly and the result can then be
				     c->path, a->path, NULL,
	unsigned long size;
				   const char *branch1,
		return; /* Note: *old_dir and *new_dir are still NULL */
			 const struct diff_filespec *blob,

	 * sorting cause no problems for us.
	char *target_file;
	ci->ren1->dst_entry->rename_conflict_info = ci;
	 * copy in opt->priv->orig_index.  Update src_index to point to the
	 * Please update $__git_merge_strategy_options in
			mmbuffer_t result_buf;
	}
				      struct rename_info *ri)
		return 1;
	struct commit_list *next = NULL, *current, *backup;
	opt->verbosity = 2;
		if (show(opt, 3)) {
	set_merge_remote_desc(commit, comment, (struct object *)commit);
}
			struct stage_data *e = entries->items[i].util;
	int update_cache = opt->priv->call_depth || clean;
		dir_rename_ent = check_dir_renamed(pair->two->path,
	repo_hold_locked_index(opt->repo, &lock, LOCK_DIE_ON_ERROR);
	 */
	end_of_new = strrchr(new_path, '/');
		return 0;
		/*
{
}
	}
	 * If we're merging merge-bases, we don't want to bother with
	ret = xmalloc(sizeof(*ret));
		flush_output(opt);
	if (!opt->priv->call_depth && would_lose_untracked(opt, dest->path)) {
	return mfi.clean;
	for (i = 0; i < df_sorted_entries.nr; i++) {
	 * index and the working copy.  We need to remove it so that
		 * If someone renamed/merged a subdirectory into the root
}
	 */
		       const char *path, int no_wd)
	 * that we need to make.  Instead, we need to just make sure that
	} else {
	init_tree_desc_from_tree(t+1, head);
			output_commit_title(opt, iter->item);
	/*
				 struct rename_conflict_info *ci)
		 */
		return NULL;
	}
		for (i = 0; i < merges.nr; i++)
	return 0;
		for (i = 0; i < entries->nr; i++) {
	 * open for us to write to.
		return 0;
		if (!opt->priv->call_depth &&
	    ren->dir_rename_original_dest) {
		if (ren1) {
	default:
		struct diff_filepair *pair = pairs->queue[i];
	hashmap_init(map, dir_rename_cmp, NULL, 0);
		}
static void get_files_dirs(struct merge_options *opt, struct tree *tree)
/**

	 *   return !was_tracked(opt, path) && file_exists(path)
	free(name1);
	if (!buf)
	opts.show_rename_progress = opt->show_rename_progress;
				     opt->branch2 : opt->branch1);
	 * happening, and fall back to no-directory-rename detection
	struct cache_entry *ce;
				    opt->branch1, opt->branch2,
					o_tree, a_tree, b_tree, entries);
static struct collision_entry *collision_find_entry(struct hashmap *hashmap,
		return err(opt, _("Unable to write index."));
			 * from merge-commit into stage 3.  We keep track
		return -1;
	if (object->type != OBJ_COMMIT)
	hashmap_free_entries(dir_renames, struct dir_rename_entry, ent);
	int baselen = base->len;
	end_of_old = strrchr(old_path, '/');
				const struct diff_filespec *a,
	}
}
	const char *reason = _("content");
	 */
	 * unchanged since their sha1s have already been compared.

			entry->non_unique_new_dir = 1;
	null.mode = 0;
	/*
	 * For each directory with files moved out of it, we find out which
			SWAP(ren2, ren1);
							ci->ren1->branch,
	}
}

		 * them, simply reuse the base version for virtual merge base.


	 * entry has the mapping of old directory name to new directory name

				     &result_tree);
	struct dir_rename_entry *entry = NULL;
	 * directory in one commit, and then renamed the directory
		return remove_file_from_index(opt->repo->index, dest->path);
	/*
				       "and %s to %s in %s. Version %s of %s left in tree at %s."),
static int handle_rename_delete(struct merge_options *opt,
			    const struct object_id **merge_bases,
	const char *other_branch;
			 * unpack_trees loads entries from common-commit
	return (S_ISDIR(mode) ? READ_TREE_RECURSIVE : 0);
			if (strcmp(ren1_dst, ren2_dst) != 0) {
/*
		if (add_cacheinfo(opt, a, path, 2, 0, options))
			opt->detect_directory_renames = boolval ?
		}
				max = *count;
		 * Only way we get here is if both renames were from
			 const struct diff_filespec *b)
}
	 * user needs to confirm the resolution.
		output(opt, 1, _("Failed to merge submodule %s (merge following commits not found)"), path);
	 * the submodule. If there is only one, then present it as a
					   head_ent->dir)->util = head_ent;
	 * Also, since this is a rename, both src_entry and dst_entry will
	memset(&match_all, 0, sizeof(match_all));
				    branch1, branch2, opt->priv->call_depth * 2, &mfi))
			}
					 const char *path,
	 * there is no content merge to do; just move the file into the
			 const struct diff_filespec *a,

			     int update_cache,
		return NULL;
		/*
		 */
		opt->branch2 = saved_b2;
		} else if (S_ISLNK(a->mode)) {
}
	free(path_side_1_desc);
			renames2Dst = &b_by_dst;
	struct hashmap_iter iter;

			if (!old_path) {
			continue;
	oidcpy(&null.oid, &null_oid);
		 * opposed to decaring a local hashmap is for convenience
	} else {

		 * opt->branch1 && !alt_path, since that would needlessly touch

		print_commit((struct commit *) merges.objects[0].item);
				       change_branch, change_branch, path, alt_path);
				 struct diff_filespec *a,
			       contents->mode != S_IFGITLINK);

			const char *msg = get_commit_buffer(commit, NULL);
	 * tracking it.
				    const char *branch2)
	free(base);
	struct string_list source_files;
		return -1;
		if (0 <= boolval) {
	const struct collision_entry *e1, *e2;
			output(opt, 2, _("Fast-forwarding submodule %s"), path);
	 * caller notify us if we started with conflicts.
			free(new_path);
	 */
};
	 * cannot be considered to be renamed.
	int pos = index_name_pos(&opt->priv->orig_index, path, strlen(path));
}
	/* .. but not some other error (who really cares what?) */
	struct tree *ignored;
			    ren1->dir_rename_original_type == 'A') {
	struct index_state *istate = opt->repo->index;
		diff_free_filepair(re->pair);
		string_list_insert(&b_by_dst, sre->pair->two->path)->util
	flush_output(opt);
	entry->processed = 0;
				clean_merge = -1;
	 * file which mentions "update_stages".
	if (update_file(opt, mfi.clean, &mfi.blob, update_path))
		strbuf_add_unique_abbrev(&merge_base_abbrev,
	}
	int clear = 1;
	memset(result, 0, sizeof(struct object_array));
				    opt->branch1, opt->branch2,
	else if (!strcmp(s, "ignore-space-at-eol"))
	}
	 * non-null.  Of the six oids, a typical rename will have three be
	int status, i;
{
				       change_branch, change_branch, path, alt_path);
			err(opt, _("merging of trees %s and %s failed"),
	opt->buffer_output = 1;

	desc = merge_remote_util(commit);
	if (!ren->dir_rename_original_dest)

		if (merge_recursive_internal(opt, merged_merge_bases, iter->item,
	collision_init(collisions);
					  NULL, NULL,

	if (df_conflict_remains || is_dirty) {
	oidcpy(&entry->stages[1].oid, &o->oid);

	if (!ret && update_cache) {
	struct string_list df_sorted_entries = STRING_LIST_INIT_NODUP;
	ci->ren1 = ren1;
		if (!oideq(&a->oid, &o->oid) && !oideq(&b->oid, &o->oid))
	/*
		/*
				ret = err(opt, _("Failed to execute internal merge"));
static void dir_rename_warning(const char *msg,
	struct commit *commit;
	struct strbuf collision_paths = STRBUF_INIT;
	int onelen = strlen(one);
		 */
	ll_opts.extra_marker_size = extra_marker_size;
	struct object_array merges;
		struct stage_data *e = df_sorted_entries.items[i].util;
	/*
		if (update_file(opt, 1, dest, dest->path))
			int compare = strcmp(a_renames->items[i].string,
	cleanup:
			add_branch = opt->branch2;
	int call_depth;
	 * renamed means the root directory can never be renamed -- because
	if (merged_merge_bases == NULL) {
			struct merge_file_info mfi;

	} else
		return 1; /* clean */
	/*
	if (prev_path2)
	fprintf(stderr, "%s\n", sb.buf);
					      struct merge_options *opt,

			if (compare >= 0)
		case MERGE_VARIANT_OURS:
	char *path_desc;
			 * We may later decide to recursively descend into
				const char *path,
			item = string_list_insert(&entry->possible_new_dirs,
		 * correct; since there is no true "middle point" between
	output(opt, 1, _("CONFLICT (rename/add): "
	output(opt, 1, _("CONFLICT (rename/rename): "
			 * that was case (1), already checked above.  So we
			if (!old_path) {
		e = item->util;
	struct hashmap_entry ent;
	int oldlen, newlen;
			apply_directory_rename_modifications(opt, pair, new_path,
		       path, branch2, new_path);
	else if (!strcmp(s, "renormalize"))
	struct diff_filespec *c = ci->ren1->pair->two;
	char *value = NULL;
};
cleanup_and_return:
		opt->branch2 = "Temporary merge branch 2";
	free(pairs);
		if (merge_ent &&
				      struct tree *merge,
	/*
				 opt->priv->call_depth || clean, !opt->priv->call_depth);
		struct string_list_item *next = &entries->items[i];
		} else if (head_ent &&

			break;
}

#include "advice.h"
	diff_flush(&opts);
		opt->xdl_opts = DIFF_WITH_ALG(opt, PATIENCE_DIFF);
				    &ci->ren1->src_entry->stages[other_stage],
			clean_merge = 0;

		strbuf_setlen(&newpath, base_len);
 *   possible_new_dirs:  temporary used to help determine new_dir; see comments
	assert(opt->xdl_opts >= 0);
		       int clean,
							&o->oid,
	return check_working_copy && !lstat(path, &st) && S_ISDIR(st.st_mode) &&
		free(e->dir);
				const struct diff_filespec *a,
	/* store a in result in case we fail */
		*new_dir = xstrdup("");
			if (!e->processed)
	struct diff_filepair *pair;
	 * handle_path_level_conflicts().  In other words,
	 * renaming that occurred via the directory rename detection.  Also,
	opt->ancestor = ancestor_name;
	struct commit *merged_merge_bases;
	if (!git_config_get_string("merge.renames", &value)) {
				ent /* member name */) {
					     b_renames->items[j].string);
		/*
	char *alt_path = NULL;
	while (*--end_of_new == *--end_of_old &&
	strbuf_addbuf(&new_path, &entry->new_dir);
	enum object_type type;
			/* we only use sha1 and mode of these */

		free(new_path);

	}
			else if (*count > max) {

	struct dir_rename_entry key;



		return -1;

	else if (!strcmp(s, "ignore-space-change"))
 */
	} else if (update_file(opt, mfi->clean, &mfi->blob, path))
}

			 * Probably unclean merge, but if the two renamed
	 * rename/add.

							     a_tree, b_tree,

	int normalize = opt->renormalize;
}
		} else {
				       opt->priv->needed_rename_limit, 0);
		/*
			       "more than one path to %s; implicit directory "
	if (entry->non_unique_new_dir)
	if (parse_commit((struct commit *)object))
	string_list_clear(&df_sorted_entries, 0);
					       extra_marker_size, result);
					  opt->subtree_shift);

				 * because if the rename merges cleanly and
	 * room for the necessary paths.  Note that if both the directory
		int i;
}
static struct commit *get_ref(struct repository *repo,
	if (!is_valid(o))
	/* Free memory we no longer need */
				&src1, name1, &src2, name2,
	struct strbuf newpath = STRBUF_INIT;
				clean_merge = 0;
		return -1;
	RENAME_ADD,
	/*
		if (!new_path)
		for (j = 0; j < merges.nr; j++) {
			oidcpy(&result->blob.oid, &b->oid);
	dir_rename_init(dir_renames);
							 "ancestor");

		BUG("collision_ent is NULL");
	 * desired final location.
	*new_dir = xstrndup(new_path, end_of_new - new_path);
	RENAME_DELETE,

	 * It's easiest to get the correct things into stage 2 and 3, and
		return;
		return clean;
			renames1 = a_renames;
		}
}
	if (!opt->priv->call_depth)
	else
	       opt->priv->call_depth ? _(" (left unresolved)") : "");

	 * files from that directory end up; this function exists to find
		flush_output(opt);
	void *buf;
static int path_hashmap_cmp(const void *cmp_data,
	 * to not let Side1 do the rename to dumbdir, since we know that is
		return err(opt, _("refusing to lose untracked file at '%s'"),
}
	strbuf_init(&opt->obuf, 0);
	assert(a->path && b->path && o->path && opt->ancestor);
{
	ci->ren2 = ren2;
			if (oideq(&src_other.oid, &null_oid) &&
	}

			continue;
	collision_ent = collision_find_entry(collisions, new_path);
	object_array_clear(&merges);
	int update_working_directory = !opt->priv->call_depth && !no_wd;
		opt->priv->call_depth--;
{
		free(new_path);
			if (fd < 0) {
		dir_re_merge = xmalloc(sizeof(*dir_re_merge));
		void *buf;
	/* Check whether to treat directory renames as a conflict */
		file_path = unique_path(opt, dest->path, ren->branch);
		goto error_return;
			ret = update_file(opt, 0, changed, update_path);
				if (update_stages(opt, path, o, a, b))
				    struct commit **result)
							   opt, ren1, NULL);
	 * Some cleanup is deferred until cleanup_renames() because the
			update_wd = 0;
		BUG("Impossible dir_rename_original_type/clean combination");
		    struct commit_list *merge_bases,
		output(opt, 1, _("Failed to merge submodule %s (commits don't follow merge-base)"), path);
	 * if they came from a rename/rename(2to1)), but had IDENTICAL
	}
{
	struct index_state orig_index;
					  add, &mfi.blob) < 0)
			 * of which side corresponds to the rename.
	return (!opt->priv->call_depth && opt->verbosity >= v) ||

	char *end_of_old, *end_of_new;
	 */
}
		entry = dir_rename_find_entry(dir_renames, temp);
		return two;
{

		dir_re_head = get_directory_renames(head_pairs);
static void final_cleanup_rename(struct string_list *rename)
				BUG("ren1_dst != ren2_dst");
						  struct hashmap *dir_renames)
int merge_recursive_generic(struct merge_options *opt,
			return -1;
		re = rename->items[i].util;
		       dest->path, file_path);
	struct cache_entry *ce;
	 */
	git_config_get_int("diff.renamelimit", &opt->rename_limit);
/*
			       "as %s instead"),
{
struct merge_options_internal {
			oidcpy(&result->blob.oid, &a->oid);
				   struct merge_file_info *result)
		/* TODO: refactor, so that 1/2 are not needed */
							   o, a, b, NULL);
		/*
	const struct rename *ren = ci->ren1;
		item = string_list_lookup(&entry->possible_new_dirs, new_dir);
		 * for it).
		 * If so, record that it's okay to remove last_file to make
			    oid_to_hex(&merge->object.oid));
			       "file/dir at %s in the way of implicit "
		    !merge_ent->non_unique_new_dir &&

	struct object_id shifted;
{
	char *path_side_2_desc;
{
		new_path = unique_path(opt, path, branch1);

{
		if (add_cacheinfo(opt, o, path, 1, 0, options))
		if ((!a_valid && !b_valid) ||
	 */
static inline int merge_detect_rename(struct merge_options *opt)
		if (ce_skip_worktree(ce)) {
			 * files merge cleanly and the two resulting files
	return clean;
		 */
				 const char *collide_path,

	}
				    1 + opt->priv->call_depth * 2, &mfi_c1) ||
	const char *rename_branch = ren->branch;
}
	if (a->mode != o->mode)
{
	if (merge_verbosity)
	 * the versions of 'before' from the merge_base, HEAD, and MERGE in
		for (i = entries->nr-1; 0 <= i; i--) {
	}
	if (is_null_oid(b))

		return strcmp(a->path, key ? key : b->path);
};

		output(opt, 1, _("Error: Refusing to lose untracked file at %s; "
			; /* no output */
{
					   head_ent->dir)->util = head_ent;
		       "If this is correct simply add it to the index "
			} else if (oideq(&src_other.oid, &null_oid)) {
		/* File not part of directory rename if it wasn't renamed */
static void get_renamed_dir_portion(const char *old_path, const char *new_path,
			/* case D: Modified in both, but differently. */
		if (clean < 0)
	 */
	while (hashmap_get_from_hash(&opt->priv->current_file_dir_set,
		 */
	 * If new_path contains no directory (end_of_new is NULL), then we
			}
			 * can then be two-way merged cleanly, I guess it's
		discard_index(opt->repo->index);
		else {
				  ren->branch == opt->branch1 ? dest : NULL,
static int handle_modify_delete(struct merge_options *opt,

	if (end_of_old == old_path && end_of_new == new_path &&

	/*
	}
		 * side of the conflict markers and the other branch on the
				      struct tree *head,
		oidcpy(result, a);
				    struct commit_list *merge_bases,
		; /* Do nothing; all in the while loop */
	strbuf_attach(dst, buf, size, size + 1);
	 * Check for one-sided add/add/.../add conflicts, i.e.
			       &ren1->src_entry->stages[other_stage].oid);


	}
}
		output(opt, 1, _("Refusing to lose untracked file at "
#include "xdiff-interface.h"


	opts.output_format = DIFF_FORMAT_NO_OUTPUT;
	return ret;
	clean = merge_recursive_internal(opt, h1, h2, merge_bases, result);
	if (would_lose_untracked(opt, path))
	*old_dir = xstrndup(old_path, end_of_old - old_path);
	if (clean < 0)
					   merge_ent->dir)->util = merge_ent;
	if (opt->priv->call_depth) {
	if (ren2) {
static void merge_recursive_config(struct merge_options *opt)
			       "Unclear where to place %s because directory "
{
	    update_stages(opt, collide_path, NULL, a, b))
			remove_file(opt, 1, path, !a_valid);
				free(buf);
	 * smrtdir, a rename/rename(1to2) conflict.  We really just want
			string_list_append(&remove_from_head,
	struct strbuf new_dir;
	*ret = diff_queued_diff;
	 * is ignored; we're interested in handling conflicts.)
	}
				int ret = process_entry(opt, path, e);
	char *alt_path = NULL;
			      const struct object_id *oid,
	memset(&rev_opts, 0, sizeof(rev_opts));
	 * that there is no winner), we no longer need possible_new_dirs.
	struct string_list_item *item;
 *      were renamed elsewhere.  (Technically, this could be done earlier
	else
					b = &src_other;

				    modify_branch, delete_branch,
	key.dir = dir;
			int len = find_commit_subject(msg, &title);
		if (update_file(opt, 0, dest, file_path))
			    opt->priv->call_depth || would_lose_untracked(opt, prev_path2));
	end_of_old = strchr(++end_of_old, '/');
	struct merge_file_info mfi;


		name2 = mkpathdup("%s:%s", branch2, b->path);


		}
	int stage = (tree == a_tree ? 2 : 3);
			 struct diff_filespec *a,
	for (current = list; current; current = backup) {
static int handle_rename_via_dir(struct merge_options *opt,
	return 0;
	free(rename);

		else
	if (is_add) {
	for (i = 0; i < pairs->nr; ++i) {
		rollback_lock_file(&lock);
	null.path = (char *)collide_path;

	return new_path;

		struct string_list_item *item;
		new_path = apply_dir_rename(dir_rename_ent, pair->two->path);
				buf = strbuf_detach(&strbuf, NULL);
 * commit object and a flag indicating the cleanness of the merge.
		struct stage_data *e;
	/* FIXME: can't handle linked worktrees in submodules yet */
			setup_rename_conflict_info(rename_type, opt, ren1, ren2);
		 * translators.
		 * re->dst_entry is for the before-dir-rename path, and we
	string_list_init(&opt->priv->df_conflict_file_set, 1);
		}
						  branch1, branch2,
	 * stages 1, 2, and 3; dst_entry will contain the respective
		 * higher stage.
	mfi_c1.blob.path = path;
	 * Note: binary | is used so that both renormalizations are
	int pos = index_name_pos(istate, path, strlen(path));
 * a real cache entry in Git's index.

{
		if (!entry) {
			"inside a directory that was renamed in %s, "
			"suggesting it should perhaps be moved to %s.");
		       path, entry->dir);
#include "cache-tree.h"
					return -1;
}
	struct hashmap_iter iter;
			 */
	return onelen - twolen;
	struct diff_filespec stages[4]; /* mostly for oid & mode; maybe path */
	strbuf_addstr(out, s);
 */
	} else if ((!o_valid && a_valid && !b_valid) ||
}
		clean = 1;
cleanup:
	    *end_of_old == *end_of_new)
					     NULL, &merged_merge_bases) < 0)
	read_mmblob(&src1, &a->oid);
{
 *                       in get_directory_renames() for details
	/*
	}
	int search = !opt->priv->call_depth;
	if ((opt->detect_directory_renames == MERGE_DIRECTORY_RENAMES_TRUE) ||
		strbuf_addstr(&opt->obuf, "error: ");

		      const char *branch2,
	clean = merge_trees_internal(opt, head, merge, merge_base, &ignored);
			result->blob.mode = b->mode;
	}
	 * updating the index after unpack_trees() and before calling this
 *      omit reporting rename/rename(1to2) conflicts for each path within
	/* Skip the search if makes no sense to the calling context.  */
	/*

		if (update_stages(opt, path,
			/*
	int clean;
				"found %u common ancestors:", cnt), cnt);
	} else {
		/*
					      struct rename *ren1,
			 */
	struct commit *head_commit = get_ref(opt->repo, head, opt->branch1);

		new_path = unique_path(opt, path, branch1);
					const char *path,
		commit_list_insert(h1, &(*result)->parents);
	return ignore_case ? strihash(path) : strhash(path);
		 * will free them for us.
				output(opt, 1, _("CONFLICT (%s/delete): %s deleted in %s "
				 */
	mfi_c2.blob.path = path;
		 * FIXME: It's possible that the two files are identical

	opt->priv->unpack_opts.fn = threeway_merge;
	remove_hashmap_entries(dir_re_merge, &remove_from_merge);
			break;

	clean = merge_trees_internal(opt,
		err(opt, _("Your local changes to the following files would be overwritten by merge:\n  %s"),
		output(opt, 1, _("%s is a directory in %s adding "

	 * certain directory being moved to a target directory.  However,

		    (!a_valid && blob_unchanged(opt, o, b, normalize, path))) {
	if (desc)
				    o, changed,
					int *clean_merge)
	}
		    struct commit *h1,
				const char *delete_branch,
	if (!search)
static int was_tracked_and_matches(struct merge_options *opt, const char *path,
		output(opt, 2, _("Found a possible merge resolution for the submodule:\n"));
	       o->path, b->path, ci->ren2->branch,
		 * ignored (unless indicating an error), it was never
		hashmap_free_entries(&opt->priv->current_file_dir_set,
		struct string_list_item *item;
					      "merged tree");
	if (opt->priv->call_depth &&
		if (S_ISREG(contents->mode)) {
		opt->recursive_variant = MERGE_VARIANT_OURS;
#include "string-list.h"
		int max = 0;
	 */
	clean = handle_content_merge(&mfi, opt, path, was_dirty(opt, path),
		}
	ri->head_renames = NULL;
			continue;
			       "to %s, because %s itself was renamed."),

	int clean_merge = 1;
			return -1;
		add->path = mfi.blob.path = a->path;
			/* Case C: Added in both (check for same permissions) */
				       struct hashmap *dir_renames,
				    entries->items[i].string);

	}
	struct rename_conflict_info *ci;
				       change_branch, change_branch, path);
	struct diff_filespec *a = ci->ren1->pair->one;
	}
				    opt->branch1, opt->branch2,
				     repo_get_commit_tree(opt->repo, h2),
			if (b->mode != o->mode) {

			   const struct object_id *base, const struct object_id *a,
}

	opts.flags.rename_empty = 0;
				  ADD_CACHE_OK_TO_ADD))
	 * The files underneath the directories of such D/F conflicts will

			/*
__attribute__((format (printf, 3, 4)))
	 * We do not have logic to handle the detection of copies.  In
		 *
				  opt->branch2 : opt->branch1);
		char *new_path;
	/* Store things in diff_filespecs for functions that need it */
}
	struct diff_filespec *c2 = ci->ren2->pair->two;
	char *new_path = NULL;
			} else if ((dst_other.mode == ren1->pair->two->mode) &&
							 i, 0);
		merge_base = shift_tree_object(opt->repo, head, merge_base,
	 * represent the entire directory rename.
		return new_path;
	 * Since we don't turn on break-rewrites by default, neither
	 * index is the one that had the necessary modification timestamps.)
		      mmbuffer_t *result_buf,
	}
			 const char *path, int stage, int refresh, int options)
	struct hashmap_iter iter;

		base  = mkpathdup("%s", opt->ancestor);
}
						  file_from_stage2 ? &mfi->blob : NULL,
		add->path = mfi.blob.path = b->path;

		remove_file_from_index(opt->repo->index, o->path);
	 * index, and users aren't going to easily be able to make sense of
	int i;
			if ((merge_status < 0) || !result_buf.ptr)
	unsigned df_conflict_remains = 0;
				 _("rename"), _("renamed")))

		    strncmp(path, df_path, df_pathlen) == 0) {
				   struct string_list *items_to_remove)
						sizeof(struct collision_entry));
}
	const char *merge_verbosity;
	}
	}
	if (opt->buffer_output < 2)

			ret = err(opt, _("cannot read object %s '%s'"),
	remove_file(opt, 1, pair->two->path, !update_wd);
	 * fact, it may not even make sense to add such logic: would we
	 *    a/b/star/      and         a/b/tar/

				   const struct diff_filespec *b,

		return -1;
	entry->stages[1].mode = o->mode;
	b = container_of(entry_or_key, const struct path_hashmap_entry, e);


		return strcasecmp(a->path, key ? key : b->path);
	if (opt->priv->call_depth)
	}
	char *new_path = NULL;


	for (i = 0; i < items_to_remove->nr; i++) {
			o->path = ci->ren1->pair->one->path;

#include "attr.h"
		return -1;
	 * total of six modes and oids, though some will be null.  (Stage 0
	return clean_merge;


	 * result.
			a->path = ci->ren1->pair->two->path;
	free(name2);
}


		unsigned long size;

}
				    struct commit *h1,

						       collisions, tree);
{
		output(opt, 1, _("WARNING: Avoiding applying %s -> %s rename "
	 */
	 * paths.  That means the current characters we were looking at
				output(opt, 1, _("CONFLICT (%s/delete): %s deleted in %s "
			/* Two different files renamed to the same thing */

	ce = make_cache_entry(istate, blob->mode, &blob->oid, path, stage, 0);
	char *dir_rename_original_dest;
	struct string_list df_conflict_file_set;
	va_list ap;
	if (end_of_new == NULL) {
			       int is_add,

	else if (!strcmp(s, "theirs"))
	struct merge_file_info mfi;
		dir_rename_init(dir_re_head);
		} else if ((lookup = string_list_lookup(renames2Dst, ren1_dst))) {
	opt->rename_limit = -1;
		return; /* Note: *old_dir and *new_dir are still NULL */
		output(opt, 3, _("Skipped %s (merged same as existing)"), path);
				   pair->two->path);
			return 0;

		 * (which we only allow when the directory in question no
				contains_another = 1;
		return clean;
			 * two-way merged cleanly with the added file, I
	if (show(opt, 2))
	 * that 'foo' comes before 'foo/bar'.
	 * we set non_unique_new_dir.  Once we've determined the winner (or
	 * Update opt->repo->index to match the new results, AFTER saving a
		goto cleanup;
				     &mfi_c1.blob, &mfi_c2.blob);
		!has_symlink_leading_path(path, strlen(path));
		 * ...because we'll be using this new one.
		temp = (opt->branch1 == ci->ren1->branch) ? b : a;
}
	struct merge_file_info mfi;
		output(opt, 1, _("Failed to merge submodule %s (not checked out)"), path);
{
{
	opt->detect_directory_renames = MERGE_DIRECTORY_RENAMES_CONFLICT;
	FLEX_ALLOC_MEM(entry, path, base->buf, base->len);

		buf = read_object_file(&contents->oid, &type, &size);
{
	struct stage_data *dst_entry;
	for (i = 0; i < a_renames->nr; i++) {

				       int *clean_merge)
	return next;
	if (object->type == OBJ_TREE)
	ostage1 = ci->ren1->branch == opt->branch1 ? 3 : 2;
		re->dst_entry = insert_stage_data(opt->repo, new_path,
	 * This next part is a little weird.  We do not want to do an
	 * FIXME: If both a & b both started with conflicts (only possible
		return 0;
					       branch2, branch1,
				else if (ret < 0) {
				 const char *prev_path2,
	char dir_rename_original_type;
		new_path = handle_path_level_conflicts(opt, path, entry,
static int remove_file(struct merge_options *opt, int clean,
	struct merge_file_info mfi_c1;

	 * contents including those conflicts, then in the next line we claim
	return (oideq(&ce->oid, &blob->oid) && ce->ce_mode == blob->mode);
 * information; tree is always equal to either a_tree or b_tree.
	unmerged->strdup_strings = 1;
		/* clear out previous settings */
				if (update_stages(opt, path, NULL,
 */
			 * ren[12]->pair->two->path are actually equal.

			free(new_path);
					  path, strerror(errno));
		!(empty_ok && is_empty_dir(path)) &&
				struct tree *merge_base,
	 */
		mark_conflicted = 1;
		struct tree *head,
				 * Added file on the other side identical to
static struct dir_rename_entry *dir_rename_find_entry(struct hashmap *hashmap,
			     struct object_array *result, const char *path,
	return clean ? 0 : 1;
	 * the root directory always exists).

		/* we were tracking this path before the merge */
	string_list_init(&entry->possible_new_dirs, 0);
#include "tag.h"
		if (a->mode == b->mode || a->mode == o->mode)
	struct strbuf new_path = STRBUF_INIT;
				reason, path);
	 * directory rename(s) can affect this side of history
			    oid_to_hex(&head->object.oid),
	base_len = newpath.len;

	get_tree_entry_if_blob(r, &o->object.oid, path, &e->stages[1]);
	struct string_list remove_from_head = STRING_LIST_INIT_NODUP;
{
		struct rename_info re_info;
struct rename_conflict_info {
	setup_revisions(ARRAY_SIZE(rev_args)-1, rev_args, &revs, &rev_opts);
		 * path.  We could call update_file_flags() with update_cache=0
 */
	 * If end_of_old is NULL, old_path wasn't in a directory, so there
	 * renames, finding out how often each directory rename pair

		hashmap_init(&opt->priv->current_file_dir_set, path_hashmap_cmp,
			 const char *path, struct stage_data *entry)
		if (pair->status != 'A' && pair->status != 'R')
	int cmp = df_name_compare(one, onelen, S_IFDIR,
	init_tree_desc(desc, tree->buffer, tree->size);
}
	dirty = verify_uptodate(ce, &opt->priv->unpack_opts) != 0;
		path_clean = warn_about_dir_renamed_entries(opt, ci->ren1);
		 */
		/* Case B: Added in one. */
	 */
			strbuf_release(&head_ent->new_dir);
	 * original type ('A' or 'R') and it's original destination before
	else

				const char *change, const char *change_past)
 * entry->dir), with entry->new_dir.  In perl-speak:
				if (a_renames == renames1) {
	return commit;
	}
 * check the working directory.  If empty_ok is non-zero, also return
			output(opt, 3, _("Fast-forwarding submodule %s to the following commit:"), path);

					return -1;
				new_path ? new_path : b->path))
	 */
		 * deleted by the user.
			}
	 * where implicit renames from the other side doing

		clean = 0;
}

		clean = detect_and_process_renames(opt, merge_base, head, merge,
{
		else
{
		}
/*

{

	size_t base_len;
	/* check whether both changes are forward */
			const char *path = entries->items[i].string;
			free(lnk);
	entry->stages[3].mode = b->mode;
					 struct dir_rename_entry *entry,
		    (!b_valid && blob_unchanged(opt, o, a, normalize, path)) ||
	} else {
		return cmp;
					     struct hashmap *dir_re_head,
			ret = err(opt,
#include "tree-walk.h"
		msg = _("CONFLICT (file location): %s added in %s "
 *   new_path_name = (old_path =~ s/entry->dir/entry->new_dir/);
	e2 = container_of(entry_or_key, const struct dir_rename_entry, ent);
			       "Adding %s as %s"),
			    const void *keydata)
			return -1;
	return result->nr;
		error("%s", opt->obuf.buf);

	/*
	/*

	/* One file was renamed in both branches, but to different names. */
		ancestor_name = opt->ancestor;
		} else
		/* [nothing|directory] -> ([nothing|directory], file) */
	 * and we want to be comparing:
	 * That's why oentry and dir_rename_exclusions is here.
		handle_directory_level_conflicts(opt,
		if (new_path)
				 */
		 * Determine whether path could exist as a file in the
		struct diff_filepair *pair = pairs->queue[i];
			/* Modify/delete; deleted side may have put a directory in the way */

		 * before this merge started.  All other
		char *new_path = find_path_for_conflict(opt, b->path,
		return -1;
static void print_commit(struct commit *commit)
		 */
		output(opt, clean ? 2 : 1, msg,
 *   new_dir:            final name of directory being renamed
	 */
	merge_verbosity = getenv("GIT_MERGE_VERBOSITY");
						      ren1->pair->two,
		if (update_file(opt, 0, &mfi->blob, new_path)) {

		    sb.buf);
	for (; i < out->len; i++)
		string_list_clear(&entry->possible_new_dirs, 1);

		       const char *path)
	const struct diff_filespec *orig = ren->pair->one;
		return -1;
					  const char *comment)
			if (ce && ce_stage(ce) == 0 && strcmp(path, ce->name))
	/*
	if (refresh) {

		pos = -1 - pos;
		struct rename *re;
	else if (!strcmp(s, "ignore-all-space"))
	const char *rename_branch = ci->ren1->branch;
	return (struct commit *)object;
		 * actually used, as result of merge_trees has always
static struct tree *shift_tree_object(struct repository *repo,
	 * otherdir/bfile into a rename into dumbdir/bfile.  However, Side
#include "dir.h"

	struct stat st;
	result->merge = 0;
	 */
				     &mfi.blob,
	return merge_status;
			 const struct hashmap_entry *entry_or_key,
		diff_warn_rename_limit("merge.renamelimit",
{
			clean_merge = 0;

			renames1 = b_renames;
		contains_another = 0;
	 */
	 * content merge puts HEAD before the other branch if we just
				       change, path, delete_branch, change_past,
			other_branch = opt->branch2;
 * to be able to associate the correct cache entries with the rename
}
			oidcpy(&result->blob.oid, &b->oid);
						      dir_renames,
static int warn_about_dir_renamed_entries(struct merge_options *opt,
		opt->priv->needed_rename_limit = opts.needed_rename_limit;
	}
	const struct diff_filespec *dest = ren->pair->two;
	/* Sanity checks */
	return e;
	} else {

	hashmap_entry_init(&entry->ent, strhash(directory));
/*
	return file_exists(path);
			 * case.
		setup_rename_conflict_info(rename_type, opt, ren2, ren1);

	 */
#include "config.h"
		else {
	assert(opt->rename_limit >= -1);

			hashmap_put(collisions, &collision_ent->ent);
	newlen = entry->new_dir.len + (strlen(old_path) - oldlen) + 1;
	int clean_merge = 1, i, j;
	return hashmap_get_entry(hashmap, &key, ent, NULL);

		output(opt, 0, _("Already up to date!"));
			return err(opt, _("add_cacheinfo failed to refresh for path '%s'; merge aborting."), path);
					goto cleanup;
		sre = a_renames->items[i].util;
			oidcpy(&result->blob.oid, &a->oid);
		} else if (show(opt, 2))
	}
		opt->rename_score = 0;
				   next->util;
	struct diff_options opts;
					     branch2, branch1,

			  const struct hashmap_entry *eptr,


				result->clean = 0;
	return strbuf_detach(&new_path, NULL);
			output(opt, 3, _("Fast-forwarding submodule %s to the following commit:"), path);
	struct diff_filespec *b = &entry->stages[3];
static int add_cacheinfo(struct merge_options *opt,
	struct rename_conflict_info *rename_conflict_info;
	if (!show(opt, v))
	struct merge_file_info mfi;
						 dir_re_merge, merge);
	clean = merge_recursive(opt, head_commit, next_commit, ca,
	}
	ci->ren1->src_entry->stages[ostage1].path = a->path;
	}
	diff_setup_done(&opts);
	assert(o->path && a->path && b->path);
		 * necessary...
		re->dst_entry = item->util;

		}

	 * messages from update_file (via make_room_for path via
		 * working directory as a possible D/F conflict.  This
	assert(opt->branch1 && opt->branch2);
			      struct tree *common,
		free(entries);
	return err(opt, msg, path, _(": perhaps a D/F conflict?"));
	return dir_renames;
			/* do not touch working file if it did not exist */
	return 0;
		string_list_clear(entries, 1);
	opts.detect_rename = merge_detect_rename(opt);
			   struct strbuf *dst)
	 */
			break;
				struct diff_filespec *o, *a, *b;
		ren1_src = ren1->pair->one->path;
		    (!has_symlinks && S_ISLNK(contents->mode))) {
	if (opt->priv->call_depth) {

	 * we have a rename/merge of a subdirectory into the root, which
	 * If the basename of the file changed, we don't care.  We want
	if (show(opt, 5)) {
			} else {
	entry->non_unique_new_dir = 0;
	if (dir_in_way(opt->repo->index, path, !opt->priv->call_depth, 0)) {
	struct pathspec match_all;
static void init_tree_desc_from_tree(struct tree_desc *desc, struct tree *tree)
		    len > last_len &&

							  merged_merge_bases),
		for (iter = merge_bases; iter; iter = iter->next)
	struct tree_desc t[3];
	 */
						  entries);
	 * If directory rename detection affected this rename, what was its
{
	for (i = 0; i < pairs->nr; ++i) {
		strbuf_addch(&opt->obuf, '\n');
}

	}
}
		int len = strlen(path);
			     const struct diff_filespec *contents,
						  o_tree, a_tree, b_tree,
	if (!entry)
	 * The reason for the increment is cases like
			ll_opts.variant = XDL_MERGE_FAVOR_THEIRS;
		if (pair->status == 'R')

		if (!alt_path) {
	return ret;
			output(opt, 1, _("Refusing to lose dirty file at %s"),
	 * and we'd get an add/add/.../add conflict, and all those adds
	assert(opt->show_rename_progress >= 0 && opt->show_rename_progress <= 1);
			return err(opt, _("merge returned no commit"));
		return merge_mode_and_contents(opt, o, b, a,
{
	 * the end of the strings.  Get the whole name by advancing both
}

		item = string_list_insert(renames, pair->one->path);
			break;

	 * to write to because of the collision checks in
 *   2. Prune directory renames if there are still files left in the
			print_commit((struct commit *) merges.objects[i].item);
				   const char *filename,
	return clean;
		if (ci->ren2) {
		strbuf_addf(&opt->obuf, "virtual %s\n", desc->name);
{
	struct unpack_trees_options unpack_opts;
	struct rename *ren2;
	int i;
	}
		opt->branch1 = saved_b1;
				const char *path,
			char *lnk = xmemdupz(buf, size);
	 * We don't actually look at pair->status again, but it seems
		output(opt, 4, _("Merging:"));
						    path, buf, size, &strbuf, NULL)) {
			       head_ent->dir, head_ent->new_dir.buf, opt->branch1,
	 *
		return err(opt, msg, path, "");
			int other_stage =   a_renames == renames1 ? 3 : 2;
					  &mfi.blob, add) < 0)
			} else
	 * it was clean.  If someone cares about this case, we should have the
		} else {
		reason = _("add/add");
	FREE_AND_NULL(opt->priv);
		if (ren2) {

				     ci->ren1->branch, ci->ren2->branch,
	free(path_side_2_desc);
	else {
							&a->oid,
	 */
	}
	int contains_another;
	/*
			int mode = (contents->mode & 0100 ? 0777 : 0666);
	object_array_clear(&merges);
			       &ren1->dst_entry->stages[other_stage].oid);
		if (!item)
static int blob_unchanged(struct merge_options *opt,
		}
		if (S_ISGITLINK(mfi->blob.mode))
	if (a)
	struct ll_merge_options ll_opts = {0};
	 * not be untracked (unpack_trees() would have errored out

		const struct cache_entry *ce = istate->cache[i];

	 * rename/add collision.  If not, we can write the file out
						      char *dir)
			return -1;
	 * that we want to apply to path.
		if (file_path != dest->path)
static int make_room_for_path(struct merge_options *opt, const char *path)
static char *find_path_for_conflict(struct merge_options *opt,
error_return:
		   (!o_valid && !a_valid && b_valid)) {
 *         causes conflicts for files within those merged directories, then
			struct repository *repo)
	re->dir_rename_original_type = pair->status;
	if (b)
}
	 * The order of the rest of the list is irrelevant for us.
		 * need it to hold information for the after-dir-rename

			 * unchanged in the other */
#include "repository.h"
	}
{
			free(result_buf.ptr);
			close(fd);
				struct rename_conflict_info *ci)
	 */
	entry->dir = directory;
	/* Make sure leading directories are created */
{
	 * directory didn't change at all, only the basename did.
		if (add_cacheinfo(opt, &mfi->blob, path,
 */
			"suggesting it should perhaps be moved to %s.");

				new_path ? new_path : a->path))
		if (!contains_another)
			unpack_trees_finish(opt);
{
				    opt->branch1, opt->branch2,
		       other_branch, ren->pair->two->path);

	 *

			 */

	/* a was renamed to c, and a separate c was added. */
	 */

		 * now...
				opt->repo->index, &ll_opts);
};
			/*

		 *      there are two names for the path that the user
	 * Handle file adds that need to be renamed due to directory rename
			ren2->dst_entry->processed = 1;
{
			strbuf_release(&head_ent->new_dir);
			if (convert_to_working_tree(opt->repo->index,
		modify_branch = opt->branch1;

		re = xmalloc(sizeof(*re));
static void final_cleanup_renames(struct rename_info *re_info)
			switch (opt->recursive_variant) {
				       struct tree *a_tree,
		free(new_path);
		if (pair->status != 'A' && pair->status != 'R') {
		 * are not dealing with a rename + add-source case.
#include "unpack-trees.h"
static int get_tree_entry_if_blob(struct repository *r,
		} else if (S_ISLNK(contents->mode)) {

		 * back to the rename source.

		return err(opt, _("cannot read object %s"), oid_to_hex(oid));

			       int clean,
			output(opt, 1,
	strbuf_release(&sb);
				result->merge = 1;

		int refresh = (!opt->priv->call_depth &&
	 * unpack_trees() will have read pair->two->path into the
	int i;
						 struct tree *o_tree,
	struct tree *result_tree;
		} else if (S_ISGITLINK(a->mode)) {
		int *count;
				     struct rename_conflict_info *ci)
	return entry;
	if (clean < 0) {

		*old_dir = xstrndup(old_path, --end_of_old - old_path);
				   const struct diff_filespec *o,
		 * and add a new one.  We need to copy over any skip_worktree
 */
	 * collisions with all paths that map to new_path.  Do a quick check
			/* something else exists */
		item = string_list_insert(entries, new_path);
	 * non-null oids, meaning at most four of the six will be non-null.
		ren1_dst = ren1->pair->two->path;
	return 0;
}
	}
	if (clean < 0) {
	struct hashmap_entry e;

}
				    &ci->ren1->src_entry->stages[ostage1],
						 char *new_path,
		if (!nce)
			   path);
	if (!new_path) {
	struct rename *ren = ci->ren1;
	    (!opt->priv->call_depth && would_lose_untracked(opt, path))) {

	diffcore_std(&opts);
 */

	if (opt->priv->call_depth)

			re->dst_entry = insert_stage_data(opt->repo,
	 * Update the stage_data with the information about the path we are
	return !is_dirty && mfi->clean;

				  side == 2 ? NULL : &mfi.blob))
				   struct hashmap *dir_renames)
{
	git_config(git_xmerge_config, NULL);
{
						   opt, ren1, ren2);
			 * ren[12]->pair->one->path are equal.
			char *ren2_dst;
	int mark_conflicted = (opt->detect_directory_renames ==

			} else {
	 * non-null.  Only two implies a rename/delete, and four implies a
			 * means there is no directory rename for us to use,
		 *   1) directory/file conflicts (in effect if
			return -1;

			 * which means it won't cause us any additional
 */
	hashmap_entry_init(&entry->e, path_hash(entry->path));
		 * Only need the hashmap while processing entries, so
static char *handle_path_level_conflicts(struct merge_options *opt,
 */
	return update_file_flags(opt, contents, path,
			 * dir_rename_ent->non_unique_new_path is true, which
		backup = current->next;
		merged_merge_bases = make_virtual_commit(opt->repo, tree,
			if (!ret &&
 * The thieves were Alex Riesen and Johannes Schindelin, in June/July 2006


					       ignore_case);
}
	unsigned processed:1;
	git_config_get_int("merge.verbosity", &opt->verbosity);
		struct string_list *renames1, *renames2Dst;


		goto cleanup;
		if (out->buf[i] == '/')
				} else {
			 * We can assume it's not rename/rename(1to1) because
		} else {
	}
			  int renormalize, const char *path)
	 * before the merge OR having been put into the working copy and
	if (end_of_old == NULL)
			reason = _("submodule");
		}
	 * *old_dir and "a/b/some/thing/else" in *new_dir.
			= (void *)sre;
static int merge_recursive_internal(struct merge_options *opt,
{
	assert(opt->priv == NULL);
		 */
		return;
			/* 2. This wasn't a directory rename after all */
	merge_pairs = get_diffpairs(opt, common, merge);
	} else {
		strbuf_addf(&newpath, "_%d", suffix++);
		const char *other_branch;
			dir_rename_entry_init(entry, old_dir);
			struct commit *m2 = (struct commit *) merges.objects[j].item;
				  struct diff_filespec *dfs)

	free(src1.ptr);
	int clean;
	parse_tree(tree);

			return -1;
	 * to the specified location.
			       "with no destination getting a majority of the "
		       collide_path);
		const char *df_path = opt->priv->df_conflict_file_set.items[i].string;
		 */
{
		 * due to a directory rename on the other side of history

	opts.rename_limit = (opt->rename_limit >= 0) ? opt->rename_limit : 1000;
	merge_finalize(opt);
		size_t pathlen = strlen(path);

{
				  two, twolen, S_IFDIR);
			/* Deleted in both or deleted in one and
		opt->priv->unpack_opts.update = 1;
		return -1;
		} else {
		if (remove_file_from_index(opt->repo->index, path))
	/* Ensure D/F conflicts are adjacent in the entries list. */
					       filename,
					       opt->subtree_shift);
		 * room for path and friends if needed.
			} else if (!oideq(&dst_other.oid, &null_oid)) {
	ce = opt->priv->orig_index.cache[pos];
				 const char *prev_path1,
				 * the merge exactly matches the newly added
