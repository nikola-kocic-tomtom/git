		if (commit == interesting_cache)
static void mark_tree_contents_uninteresting(struct repository *r,
		revs->grep_filter.ignore_case = 1;
	parse_pathspec(&revs->prune_data, PATHSPEC_ALL_MAGIC & ~PATHSPEC_LITERAL,

		blob->object.flags |= flags;
}
				break;

	left_first = left_count < right_count;
			break;
	for (p = list; p; p = p->next) {
		struct worktree *wt = *p;
			/* ??? CMDLINEFLAGS ??? */
		revs->grep_filter.ignore_locale = 1;

	} while (made_progress);
			else if (process_parents(revs, commit, &revs->commits, NULL) < 0) {
static inline int relevant_commit(struct commit *commit)
}
		if (revs->full_diff)

	if (!left_count || !right_count)
	other = lookup_commit_or_die(&oid, "MERGE_HEAD");

}
		while ((i+1 < istate->cache_nr) &&
				return NULL;

		revs->max_parents = atoi(optarg);
	}

		struct commit *parent = p->item;
	}
}
	/*
		add_decoration(&revs->merge_simplification, &commit->object, st);
		 * boundary commits.
}
		revs->left_right = 1;
		return tail;
	 * commits, it is most useful to define it so that "irrelevant"

		nth_parent++;
	 * in a bottom-up fashion.
	if (revs->first_parent_only)
	return parents;
			       revs->prefix, prune_data.argv);
		b_name = "HEAD";
	if (revs->children.name)
	/*
			commit->object.flags |= TREESAME;

		struct commit *c = list->item;
		struct commit_list *p = *list;
		 * Detached form ("--pretty X" as opposed to "--pretty=X")
			if (!*slot)
	clear_prio_queue(&info->indegree_queue);
			if (p)
{
		strbuf_release(&namemail);
			/*
	if (blob->object.flags & UNINTERESTING)
		 */
		revs->rewrite_parents = 1;
	struct commit *c;
static int mark_treesame_root_parents(struct commit *commit)
			return;
		return;
	}
	if (!cant_be_filename && !strcmp(arg, "..")) {
static void mark_one_parent_uninteresting(struct commit *commit,
	} else if (!strcmp(arg, "--dense")) {
	return for_each_bisect_ref(refs, fn, cb_data, term_good);
				if (!(parents->item->object.flags & TMP_MARK))
		show = show_early_output;
			commit_list_insert(elem->item, &bottom);

}
		free(*ref_excludes_p);
{
	if (revs->cherry_pick || revs->cherry_mark)
		return;
	for_each_reflog(handle_one_reflog, &cb);
	/*
		if (relevant_commit(p))
				 * we are interested in, we do not want
		die(_("your current branch appears to be broken"));
{
	struct all_refs_cb *cb = cb_data;
	memset(&info->indegree_queue, 0, sizeof(info->indegree_queue));
}
}
{
			free_commit_list(revs->previous_parents);
};
	 *    !TREESAME INTERESTING parents (and we don't have treesame[]

}
	revs->pending.objects = NULL;
 * for non-root commits).
}
			     uint32_t gen_cutoff)
		handle_refs(refs, revs, *flags, refs_for_each_remote_ref);
	/*
	int slop = SLOP;
static int compact_treesame(struct rev_info *revs, struct commit *commit, unsigned nth_parent)
	if (seen_dashdash)
	if (!*b_name)
			if (revs->track_linear)
}
#include "tree.h"
	struct worktree *wt;
	return status;
		init_all_refs_cb(&cb, revs, *flags);
	 * Rewrite our list of parents. Note that this cannot
	if (!refs) {
	/* Compute patch-ids for one side */

static int handle_one_reflog_ent(struct object_id *ooid, struct object_id *noid,
		return 1;


	} else if (!strcmp(arg, "--root")) {
	}
			char **slot = revision_sources_at(revs->sources, commit);
	if (revs->no_walk && (obj->flags & UNINTERESTING))
	    !strcmp(arg, "--indexed-objects") ||
		die("--show-linear-break and --graph are incompatible");
	 */
	/*

	const char *arg = arg_;
	} else if (!strcmp(arg, "--show-pulls")) {
	/* feed the list reversed */

		 */
	} else if (!strcmp(arg, "--abbrev-commit")) {
			    is_promisor_object(&p->object.oid)) {
			 *     as a valid filename.
		record_author_date(&info->author_date, c);
	return marked;
	struct oidset_iter iter;
			return object;

		strbuf_addf(path, "%s%s", baselen ? "/" : "", sub->name);
		revs->pretty_given = 1;
	 * rewrite this one yet.
	int orig_cnt = commit_list_count(commit->parents);
		struct commit_list *p;
	}
	/* Prepend "fake" headers as needed */
	       !revs->simplify_history &&
static struct merge_simplify_state *locate_simplify_state(struct rev_info *revs, struct commit *commit)
	struct tree *t1 = get_commit_tree(commit);
			return rewrite_one_noparents;
		hashmap_put(map, &entry->ent);
		p->item->object.flags &= ~TMP_MARK;
				return commit_show;
		   skip_prefix(arg, "--notes=", &optarg)) {
		if (revs->track_linear)
	}
		marked->object.flags &= ~TMP_MARK;
		 * that we'd otherwise have done in limit_list().
		revs->expand_tabs_in_log = 0;
	 * If we've just become a non-merge commit, update TREESAME
	}
		unsigned flags = commit->object.flags;
					 struct object *obj,
	if (revs->limited) {
}
	memset(&a_oc, 0, sizeof(a_oc));
	cb.all_revs = revs;
	if (!tree)
		revs->encode_email_headers = 0;
 */
		revs->edge_hint_aggressive = 1;

		st->nparents - nth_parent - 1);

			p->object.flags |= SEEN;
		c = pop_commit(&revs->commits);
			} else {
static int entry_unshown(struct object_array_entry *entry, void *cb_data_unused)
	ctx->argc -= n;
	 * We grep in the user's output encoding, under the assumption that it
	struct hashmap_iter map_iter;
		}
		}
	 *
	 *

	 */
		/*
		p->object.flags |= left_flag;
	if (revs->single_worktree)
void add_index_objects_to_pending(struct rev_info *revs, unsigned int flags)
 *   1. We're not using remove_empty_trees at all.
		return;
	/*
		/* fallthrough */
static void compute_indegrees_to_depth(struct rev_info *revs,
			     const struct object_id *oid,
	if (revs->reflog_info && revs->graph)
	 * When implementing your new pseudo-option, remember to
	}
			}
	 * If it is non-zero, then either we don't have a max_count at all
			 * This our second loop iteration - so we now know
		revs->verbose_header = 1;
	struct commit_list *p;
			cnt++;
		pst = locate_simplify_state(revs, p->item);
	pp = &commit->parents;
	/*
 *
	 * that has no differences in the path set if one exists.
	strbuf_release(&buf);

	 */
					break;
	if (c && revs->graph)
				if (!(irrelevant_change || relevant_change))
	while (*pp) {
	int argcount;

		revs->diff = 1;
		revs->grep_filter.pattern_type_option = GREP_PATTERN_TYPE_BRE;
		revs->rewrite_parents = 1;
	    starts_with(arg, "--remotes=") || starts_with(arg, "--no-walk="))
		(*ref_excludes_p)->strdup_strings = 1;
	} else if ((argcount = parse_long_opt("max-age", argv, &optarg))) {

{
	}
		struct commit *commit = l->item;
			    unsigned flags)
	 * yet, so we won't have a parent of a parent
	} else if (!strcmp(arg, "--combined-all-paths")) {
		if (p->flags & (CHILD_SHOWN | SHOWN))
	 * set in its original order, so this isn't too hard.
		if (revs->reflog_info)
		die("cannot combine --no-walk with --graph");
		return commit_ignore;
	if (object->type == OBJ_BLOB) {
	struct commit *c = prio_queue_get(&info->indegree_queue);
		struct commit *parent = p->item;
	struct strbuf refname = STRBUF_INIT;
		}
{
				p->object.flags |= UNINTERESTING;

		revs->rewrite_parents = 1;
	 * reading the object buffer, so use it whenever possible.
	       c->generation >= gen_cutoff)
		       ce_same_name(ce, istate->cache[i+1]))
	/*
	rewrite_parent_fn_t rewrite_parent)
				       FOR_EACH_OBJECT_PROMISOR_ONLY);
	} else if (!strcmp(arg, "--remove-empty")) {
	}
				struct rev_info *revs,

	int cnt;
			die("bad revision '%s'", sb.buf);
	unsigned flags)
	} else if (!strcmp(arg, "--no-commit-id")) {
		revs->topo_order = 1;
		strbuf_addch(&buf, '\n');
		       PATHSPEC_PREFER_FULL | PATHSPEC_LITERAL_PATH, "", prune);

	 * Commands like "git shortlog" will not accept the options below
	/* Signal whether we need per-parent treesame decoration */
		else
	if (!ref_excludes)
	 */
		struct commit *commit = pop_commit(&list);
	a_obj->flags |= a_flags;
	 * before the source list? Definitely _not_ done.
	}

	while ((p = *pp) != NULL) {
		revs->no_walk = 0;
	} else if (!strcmp(arg, "--remotes")) {
		revs->verbose_header = 1;
	 */
	 * allowing irrelevant merges from uninteresting branches to be
			}
}
	} else if (!strcmp(arg, "--verify-objects")) {
{
				continue;
static void set_children(struct rev_info *revs)
	}
enum commit_action get_commit_action(struct rev_info *revs, struct commit *commit)
				read_revisions_from_stdin(revs, &prune_data);
	struct indegree_slab indegree;
	struct hashmap_entry ent;
		revs->abbrev_commit = 1;
		return 0;
	int argcount;
	worktrees = get_worktrees(0);
	if (mark && !mark[2]) {
	/* Ok, we're closing in.. */
	    comparison_date(revs, commit) > revs->min_age)
	 * immediately, and remove the no-longer-needed decoration.
	for_each_string_list_item(item, ref_excludes) {
	    (revs->show_pulls && (commit->object.flags & PULL_MERGE)))
		test_flag_and_insert(&info->explore_queue, p->item, TOPO_WALK_EXPLORED);
	 * --full-history --simplify-merges would produce "I-A-X", showing
	} else if (!strcmp(arg, "--left-right")) {
	b_name = dotdot + 2;
		return -1;
	uint32_t min_generation;
static int handle_one_ref(const char *path, const struct object_id *oid,

		unsigned relevant_change, irrelevant_change;
	} else if (!strcmp(arg, "--right-only")) {
		 *	prune_data.path = NULL;
	revs->repo = r;
{
			if (argv[i + 1])


}
	 * update_treesame, which should be kept in sync.
	switch (revs->sort_order) {

}
	if (ref_excluded(cb->all_revs->ref_excludes, path))
		revs->grep_filter.pattern_type_option = GREP_PATTERN_TYPE_FIXED;
		if (wt->is_current)
	} else if (skip_prefix(arg, "--max-parents=", &optarg)) {
	struct all_refs_cb *cb = cb_data;

	struct commit_list *bases;
	}
				}
			REALLOC_ARRAY(prune, prune_num);
#include "mailmap.h"
			}
}
	}

	 */
		return "+";
	/* Check the other side */
	memset(&info->explore_queue, 0, sizeof(info->explore_queue));

	const unsigned hexsz = the_hash_algo->hexsz;
	}
			       void *cb_data, const char *term)
static struct commit *get_revision_1(struct rev_info *revs)
	explore_to_depth(revs, c->generation);
				 * interesting.  Remove its parents
		for (p = revs->previous_parents; p; p = p->next)
static void read_revisions_from_stdin(struct rev_info *revs,

		simplify_merges(revs);
			parent->next = NULL;
		strbuf_addf(&namemail, "%.*s <%.*s>",

	}
{
		else if (revs->abbrev > hexsz)
	flags = flags & UNINTERESTING ? flags | BOTTOM : flags & ~BOTTOM;
}
}
		 * commits on the left branch in this loop.
	if (!c) {

{
			die("--ancestry-path given but there are no bottom commits");
		struct cache_tree_sub *sub = it->down[i];

		}
	}
				break;
		exclude = get_merge_bases(a, b);
	memcpy(&old_pending, &revs->pending, sizeof(old_pending));
			continue;
			struct commit *c = p->item;
		revs->commits = reversed;
			if (revs->remove_empty_trees &&
		if (rewrite_parents(revs, commit, rewrite_one) < 0)
	struct commit_list *l;
 * Awkward naming - this means one parent we are TREESAME to.
	if (opt && opt->assume_dashdash) {
					die("--stdin given twice?");
	bases = get_merge_bases(head, other);
};
	 * Put all of the actual boundary commits from revs->boundary_commits
	strbuf_addf(&bisect_refs, "refs/bisect/%s", term);
	 * first parent (even if not "relevant" by the above definition).
	} else if (!strcmp(arg, "--objects")) {


	 * register it in the list at the top of handle_revision_opt.
	} else if (!strcmp(arg, "--always")) {
	}
	struct object *a_obj, *b_obj;
	const char *submodule = NULL;

	a_obj = parse_object(revs->repo, &a_oid);

	init_tree_desc(&desc, tree->buffer, tree->size);
				seen_dashdash = 1;
		tail = &yet_to_do;
	 */
				exit(128);
			    for_each_good_bisect_ref);
	/*
		struct strbuf path = STRBUF_INIT;
		else if (revs->topo_walk_info)
		revs->no_walk = 0;
		 * tagged commit by specifying both --simplify-by-decoration

		if (flags & UNINTERESTING) {
 * that may have affected it.
		revs->pretty_given = 1;
		if (!p->parents)
}
 * commit, based on the revision options.
		unsigned n;
 * Before walking the history, keep the set of "negative" refs the
	if (!commit->parents) {
			revs->max_count--;
		die(_("--first-parent is incompatible with --bisect"));
	}
			return -1;
		switch (object_type(entry.mode)) {
					     040000, path->buf);
{
	int diff = addremove == '+' ? REV_TREE_NEW : REV_TREE_OLD;
				if (relevant_commit(p->item))

	 * history dense, we consider it always to be a change..
	} else {
		   skip_prefix(arg, "--format=", &optarg)) {
	}
	}
	       (oid = oidset_iter_next(&iter))) {
	clear_object_flags(SEEN | ADDED | SHOWN | TOPO_WALK_EXPLORED | TOPO_WALK_INDEGREE);
static void merge_queue_into_list(struct prio_queue *q, struct commit_list **list)
	struct strbuf buf = STRBUF_INIT;
}
			git_log_output_encoding = xstrdup(optarg);
	if (!commit->parents) {
{
	cb->warned_bad_reflog = 0;

		}
	 * always TREESAME to its simplification.
	} else if ((argcount = parse_long_opt("skip", argv, &optarg))) {

		handle_refs(refs, revs, *flags, refs_head_ref);
	if (!entry) {
	}
		int len = interpret_branch_name(name, 0, &buf, 0);
	 * root commit.  We do not rewrite parents of such commit
	} else if (!strcmp(arg, "--indexed-objects")) {
static int handle_dotdot_1(const char *arg, char *dotdot,
		revs->track_first_time = 0;
		c->object.flags |= UNINTERESTING;
	size_t baselen = path->len;

static struct commit_list **simplify_one(struct rev_info *revs, struct commit *commit, struct commit_list **tail)
		revs->abbrev_commit_given = 1;
	}
		return 1;
 */
	revs->abbrev = DEFAULT_ABBREV;
{
	oidset_iter_init(trees, &iter);
		if (nth_parent != 0)
		 *	prune_data.nr = 0;
			    const char *name,
	cb.all_flags = flags;
	mark = strstr(arg, "^!");
		return c;

		struct commit_list *parent = *pp;
		revs->def = opt ? opt->def : NULL;
		return 0;
			mark_tree_contents_uninteresting(revs->repo, tree);
define_commit_slab(author_date_slab, timestamp_t);
			if (relevant_commit(p))
	}
				      &revs->prune_data);

	refname = resolve_ref_unsafe(def, 0, NULL, &flags);
 * commit, and this selects one of our parents, then we can safely simplify to
		int gently = revs->ignore_missing_links ||
			marked -= leave_one_treesame_to_parent(revs, commit);
	for (p = worktrees; *p; p++) {
		return -1;
void reset_revision_walk(void)
		struct commit_list *exclude;


		if (wt->is_current)
		submodule = opt->submodule;
	}
	 * done.)
		struct merge_simplify_state *st;
	} else if ((argcount = parse_long_opt("glob", argv, &optarg))) {
		indegree_walk_step(revs);
		if (revs->sources) {

	add_pending_object(revs, &other->object, "MERGE_HEAD");
	if (get_oid_committish(arg, &oid))
		cnt = 1;
	l->next = add_decoration(&revs->children, &parent->object, l);
	if (!everybody_uninteresting(src, interesting_cache))
		*mark = '^';

		return;

				if (!unmarked) {
 * empty tree). Better name suggestions?
	 *          /		o: a commit that touches the paths;
	}
			 * the first parent chain, in order to avoid derailing the

					unmarked = p->item;
			return rewrite_one_ok;
		 const struct object_id *new_oid,
	} else {
	for (p = name; *p && *p != '\n'; p++)
	/*
	for (p = list; p; p = p->next) {
		 * pathspec for the parent directory.
		if (!add_parents_only(revs, arg, flags ^ (UNINTERESTING | BOTTOM), 0))
	     parents;

		if (c)
		return argcount;
		revs->max_age = approxidate(optarg);
{
		revs->no_walk = 0;
				mark_parents_uninteresting(p);
	 *
		struct commit *commit = (struct commit *)object;
	while (object->type == OBJ_TAG) {
{
		return 0;
		case REV_TREE_NEW:
	if (!revs->prune)
{
	int relevant_change = 0, irrelevant_change = 0;
	return marked;
		revs->limited = 1;
	if (!object)
			continue;
	if (revs->include_check &&
		struct tree *tree = lookup_tree(revs->repo, &it->oid);
	warn_on_object_refname_ambiguity = save_warning;
	parents = *saved_parents_at(revs->saved_parents_slab, commit);
	}
	struct object_id oid;

	 * For 1-parent commits, or if first-parent-only, then return that
	struct all_refs_cb cb;
				break;
{
			    comparison_date(revs, commit) < revs->max_age)
		int len = sb.len;
	struct object *obj;
}
	if (!symmetric) {
	paths_and_oids_clear(&map);
		revs->encode_email_headers = 1;
	return c;
	if (revs->expand_tabs_in_log < 0)
	} else if (!strcmp(arg, "-m")) {

		revs->print_parents = 1;

	struct commit_list *parents;
	int parent_number;
	struct commit_list *p;

	/*
		list = list->next;
	} else if (!strcmp(arg, "--children")) {
	int warned_bad_reflog;

	 */
		struct commit *commit = handle_commit(revs, e);
	add_pending_commit_list(revs, bases, UNINTERESTING | BOTTOM);
 * that have already been shown to try to free up some space.
	if (diff_tree_oid(&t1->object.oid, &t2->object.oid, "",
#include "hashmap.h"
				return NULL;
	} else {
			return rewrite_one_ok;
		case rewrite_one_ok:
 * Return a single relevant commit from a parent list. If we are a TREESAME
		if (!((struct tag*)it)->tagged)
	commit->object.flags |= ADDED;
		revs->simplify_history = 0;
		revs->dense = 1;
	}
		revs->abbrev_commit = 1;
	}
		revs->count = 1;
	return 1;
	for (i = 0; i < it->subtree_nr; i++) {
		if (!repo_parse_commit(revs->repo, c))
				commit_list_insert_by_date(p, list);
{
		if (revs->first_parent_only)
			parent = parent->next;
}
		 * when --full-diff is in effect.
	 * anyway.
			exclude_parent = strtoul(mark + 2, &end, 10);
	if (1 < cnt) {
	struct commit_list *list;
		revs->graph = graph_init(revs);
	if (revs->ignore_missing)
		revs->children.name = "children";
	    starts_with(arg, "--exclude=") ||

			continue;

		revs->diffopt.flags.tree_in_recursive = 1;


{
	 */
						return commit_show;
		 unsigned old_mode, unsigned new_mode,

		cherry_pick_list(newlist, revs);
		revs->always_show_header = 1;
	if (prefix && !revs->diffopt.prefix) {
	 * parent that the default simplify_history==1 scan would have followed,
		pst = locate_simplify_state(revs, parent);
	const char *name_for_errormsg;
	/* either cherry_mark or cherry_pick are true */
	return 0;
	 * after it has been marked uninteresting.
		init_all_refs_cb(&cb, revs, *flags);
		revs->verify_objects = 1;
		int *pi;
	struct author_date_slab author_date;
	struct merge_simplify_state *st, *pst;
			commit->object.flags |= TREESAME;
	}
	flags = 0;
	 *
		list = yet_to_do;

	} else if (!strcmp(arg, "-v")) {
}
	status = refs_for_each_fullref_in(refs, bisect_refs.buf, fn, cb_data, 0);
		if (relevant_parents ? relevant_change : irrelevant_change)

	if (*ref_excludes_p) {
		if (strtoul_ui(optarg, 10, &revs->early_output) < 0)
		if (flags & UNINTERESTING) {
	init_all_refs_cb(&cb, revs, flags);
}
	while (tree_entry(&desc, &entry)) {
	}
		if (ts->treesame[n]) {
	struct topo_walk_info *info = revs->topo_walk_info;

	/*
				return NULL;
			copy_pathspec(&revs->diffopt.pathspec,
			return error("-n requires an argument");
	struct commit *relevant = NULL;
				return -1;
			    !revs->simplify_history &&
			      struct packed_git *pack,
	e1 = container_of(eptr, const struct path_and_oids_entry, ent);
		 * pathspec whatsoever", here is the place to do so.
	struct commit_list **pp, *parent;
			while (revs->skip_count > 0) {
			if (!*slot)
 * And when computing --ancestry-path "A..B", the A-X connection is more
		revs->dense = 0;
		mode = 0;
	     (parent = *pp) != NULL;
	/*
	    : "Invalid revision range %s", arg);
		/*
	if (commit->object.flags & UNINTERESTING)
		revs->edge_hint = 1;
		strbuf_release(&path);
const char *get_revision_mark(const struct rev_info *revs, const struct commit *commit)
		}
	    revs->diffopt.flags.follow_renames)
	return retval >= 0 && (tree_difference == REV_TREE_SAME);
	struct commit_list *p;
static int rev_compare_tree(struct rev_info *revs,
			strbuf_addstr(&buf, name + len);
	revs->max_count = -1;
	struct commit_list *bottom = NULL;
	struct topo_walk_info *info = revs->topo_walk_info;
			commit->object.flags &= ~TREESAME;
					continue;

				       uint32_t gen_cutoff)

			}
	}
#include "diff.h"

		revs->tree_objects = 1;
	 * for. In addition, it means we will match the "notes" encoding below,
		*interesting_cache = commit;
 * reach A.

	unsigned int nr = info->nr;
void put_revision_mark(const struct rev_info *revs, const struct commit *commit)

	return 0;
	info->explore_queue.compare = compare_commits_by_gen_then_commit_date;

		 const struct object_id *old_oid,
		revs->linear = p != NULL;
		if (*pi)
	struct topo_walk_info *info = revs->topo_walk_info;
	prio_queue_put(q, c);
{
		revs->simplify_merges = 1;
	if (!tree)
			 * use "relevant" here rather than just INTERESTING,

		it->flags |= flags;
	if (revs->no_walk != REVISION_WALK_NO_WALK_UNSORTED)

static int still_interesting(struct commit_list *src, timestamp_t date, int slop,
		while (parent) {
			return commit_ignore;

		revs->max_parents = 1;
		unkv[(*unkc)++] = arg;
		info->topo_queue.compare = compare_commits_by_author_date;
	struct prio_queue topo_queue;
	struct index_state *istate = revs->repo->index;
				continue;
	 *    against the first parent (and again we lack treesame[] decoration).
	hashmap_free_entries(map, struct path_and_oids_entry, ent);
	if (!*ref_excludes_p) {
static void add_pending_commit_list(struct rev_info *revs,

		}

	 * because we know that it is modifiable heap memory, and that while
	clear_indegree_slab(&info->indegree);
	revs->max_age = -1;
{
		return argcount;
	if (it->entry_count >= 0) {
		flags ^= UNINTERESTING | BOTTOM;
	ALLOC_GROW(info->rev, nr + 1, info->alloc);
	/* Do not walk unless we have both types of trees. */

		revs->track_first_time = 1;
		revs->show_root_diff = 1;
		int marked = mark_redundant_parents(commit);
	return 0;
		return NULL;
	 */
 * and removing the used arguments from the argument list.
		 */
			struct object *obj, const char *name)
		old_same = !!(commit->object.flags & TREESAME);
		if (revs->right_only) {
static void add_message_grep(struct rev_info *revs, const char *pattern)
	}
	 */

	 * Default log would produce "I" by following the first parent;
	if (!commit_match(commit, revs))

	unsigned int mode = entry->mode;
		it = get_reference(revs, arg, &oid, 0);
		return;
	} else if (revs->topo_order)
		if (it->type != OBJ_TAG)
	} else if ((argcount = parse_long_opt("date", argv, &optarg))) {
		if (!it && revs->ignore_missing)
{

	for (pp = &commit->parents, nth_parent = 0, relevant_parents = 0;
		revs->expand_tabs_in_log = revs->expand_tabs_in_log_default;
	 */
	for (cnt = 0, p = commit->parents; p; p = p->next) {
		if (obj->flags & UNINTERESTING) {
		commit_stack_push(pending, l->item);
		if (*(indegree_slab_at(&info->indegree, c)) == 1)
		if (revs->right_only)
		 */
					 const char *name, unsigned mode)
	} else if (!strcmp(arg, "--show-signature")) {

		revs->linear = 1;
		return get_revision_internal(revs);
	struct commit_list *l = xcalloc(1, sizeof(*l));
				    unsigned int flags)
/*
		const char *message, void *cb_data)
	if (opt)
	if (revs->sort_order == REV_SORT_BY_AUTHOR_DATE)
	    starts_with(arg, "--branches=") || starts_with(arg, "--tags=") ||
				continue;

	do {
		if (revs->tag_objects && !(flags & UNINTERESTING))

			    oid_to_hex(&commit->object.oid));

		add_rev_cmdline(revs, object, oid_to_hex(&object->oid),
		 * not allowed, since the argument is optional.
	int left_count = 0, right_count = 0;
		if (!revs->prune_data.nr)
	struct commit_list *p;

		 */
		if (parent->object.flags & UNINTERESTING)
	for (p = bottom; p; p = p->next)
		else

	revs->pruning.change_fn_data = revs;

{
	for (i = 0; i < array->nr; i++) {
		get_sha1_flags |= GET_OID_COMMITTISH;
 * caller has asked to exclude.
		 */
			    oid_to_hex(&p->object.oid));
		if (!seen_end_of_options && *arg == '-') {
			add_pending_object(cb->all_revs, o, "");
		line_log_filter(revs);
 * whether the whole change is REV_TREE_NEW, or if there's another type
			    rev_same_tree_as_empty(revs, p)) {
			if (queue)
			mark_parents_uninteresting(commit);
	/* Copy the commit to temporary if we are using "fake" headers */
	struct commit *commit;
			continue;
	 * If revs->topo_order is set, sort the boundary commits
	*dotdot = '.';

	init_patch_ids(revs->repo, &ids);
			prio_queue_get(q); /* pop item */
static struct commit *handle_commit(struct rev_info *revs,
	free(oc.path);
/* Assumes either left_only or right_only is set */
	 *    decoration anyway);
	struct commit_list **pp, *p;

		 * were elided.  So we save the parents on the side
	if (revs->line_level_traverse &&


	*dotdot = '\0';

	/*
	    return 0;
 *
		if (handle_revision_arg(sb.buf, revs, 0,

			revs->no_walk = REVISION_WALK_NO_WALK_SORTED;
	 * here. However, it may turn out that we've

	st->nparents = n;
	else if (commit->object.flags & UNINTERESTING)
	struct topo_walk_info *info = revs->topo_walk_info;
	return 0;
			 *
static void add_rev_cmdline_list(struct rev_info *revs,
				 struct tree *tree,
}
	for (p = list; p; p = p->next)
			if (queue)
 */
volatile show_early_output_fn_t show_early_output;
	return c;

	if (!cant_be_filename)
			right_count++;
	revs->min_age = -1;

	} else if ((argcount = parse_long_opt("exclude", argv, &optarg))) {
	return 0;
		marked += mark_treesame_root_parents(commit);
	} else if (!strcmp(arg, "--basic-regexp")) {
 * to filter the result of "A..B" further to the ones that can actually

}
		if (rev_same_tree_as_empty(revs, commit))
#include "revision.h"
	for (l = revs->commits; l; l = l->next) {
			 */
	 *
	add_pending_object(revs, obj, "HEAD");
		int exclude_parent = 1;
		revs->topo_order = 1;
		revs->show_notes_given = 1;
	for (p = list; p; p = p->next)


{
		init_saved_parents(revs->saved_parents_slab);
	if (!revs->boundary)
	oidset_iter_init(trees, &iter);
	revs->commits = newlist;
static int path_and_oids_cmp(const void *hashmap_cmp_fn_data,

	struct commit *c = prio_queue_get(&info->explore_queue);
void mark_trees_uninteresting_sparse(struct repository *r,
			update_treesame(revs, c);
	int symmetric = 0;
static inline int want_ancestry(const struct rev_info *revs)
	}
	struct topo_walk_info *info = revs->topo_walk_info;
		revs->date_mode_explicit = 1;
	 * merge and its parents don't simplify to one relevant commit
	const char *arg = arg_;
			list = &p->next;
		if (o) {

			if (strcmp(arg, "--"))
		revs->tag_objects = 1;
				die("bad revision '%s'", arg);
	} else if ((argcount = parse_long_opt("min-age", argv, &optarg))) {
static int commit_rewrite_person(struct strbuf *buf, const char *what, struct string_list *mailmap)
		struct commit *item = prio_queue_peek(q);
		revs->right_only = 1;
	 * If we have more than one relevant parent, or no relevant parents
		p->item->object.flags |= TMP_MARK;
{

			    is_promisor_object(&tag->tagged->oid))

		return argcount;
	if (parents == EMPTY_PARENT_LIST)
		revs->diffopt.pickaxe_opts |= DIFF_PICKAXE_IGNORE_CASE;
	if (!st) {
	free_worktrees(worktrees);
	revs->pruning.flags.has_changes = 0;
	 */
		limit_to_ancestry(bottom, newlist);
	cb.wt = NULL;
			return error("bad --default argument");
				irrelevant_change |= !st->treesame[n];

	free(b_oc.path);
	} else if (!strcmp(arg, "--grep-debug")) {

	return 0;
		add_pending_object_with_path(revs, object, name, mode, path);
	 */
	add_grep(revs, pattern, GREP_PATTERN_BODY);
		revs->tree_blobs_in_commit_order = 1;
	if (opt && opt->tweak)
	if (revs->min_age != -1 &&
	/*
	 * TREESAME is irrelevant unless prune && dense;
define_commit_slab(saved_parents, struct commit_list *);
		/*
	} else if (!strcmp(arg, "--cc")) {
	const char *name = ".alternate";
	return commit_show;
	    revs->diffopt.filter ||
	 * No source list at all? We're definitely done..
		revs->ignore_missing = 1;
		show(revs, newlist);
/*
		options->flags.has_changes = 1;
	 */
		st->simplified = commit;
		}
static int limit_list(struct rev_info *revs)


void add_ref_exclusion(struct string_list **ref_excludes_p, const char *exclude)
	}
	while ((!has_interesting || !has_uninteresting) &&
	struct commit_list *h = reduce_heads(commit->parents);
	 * If still a merge, defer update until update_treesame().
			if (opts > 0) {
		return;
				continue;
 * The goal is to get REV_TREE_NEW as the result only if the

	for (left = i = 1; i < argc; i++) {
#include "blob.h"

		 * not allowed, since the argument is optional.
		revs->limited = 1;
	int hash = strhash(path);
			   struct commit_list **list, struct prio_queue *queue)
 * (which are also moved to the head of the argument list)
static enum rewrite_result rewrite_one(struct rev_info *revs, struct commit **pp)
		pi = indegree_slab_at(&info->indegree, parent);
			const char * const usagestr[])
	return revs->reflog_info ?
			if (revs->exclude_promisor_objects &&
	}
}
	struct commit_list *list, *next;

		object_array_filter(array, entry_unshown, NULL);
		int *pi = indegree_slab_at(&info->indegree, parent);
		enable_default_display_notes(&revs->notes_opt, &revs->show_notes);
		revs->tag_objects = 1;
				 */

	 */
static inline int limiting_can_increase_treesame(const struct rev_info *revs)
		 const char *fullpath,
	 */
						   &left, argv, opt);
 * diff consists of all '+' (and no other changes), REV_TREE_OLD
			     const struct hashmap_entry *entry_or_key,

		*mark = 0;
	len = endp - person;
	cb->all_revs = revs;
						oid_to_hex(&commit->object.oid));
			if (revs->treesame.name &&
#include "bisect.h"
		if (0 < len && name[len] && buf.len)
		struct commit *p = *pp;

	clear_prio_queue(&info->explore_queue);
static void add_child(struct rev_info *revs, struct commit *parent, struct commit *child)
	struct add_alternate_refs_data *data = vdata;
		struct commit *commit = p->item;
		prio_queue_reverse(&info->topo_queue);
			       int *unkc, const char **unkv,
static void paths_and_oids_init(struct hashmap *map)
	    get_oid_with_context(revs->repo, b_name, oc_flags, &b_oid, b_oc))
		 *	free(prune_data.path);
	revs->pruning.flags.quick = 1;
		mark_one_parent_uninteresting(l->item, &pending);
	ctx->argv += n;
static const char *term_bad;
		revs->reverse_output_stage = 1;
		if (commit) {
	FREE_AND_NULL(revs->topo_walk_info);
	st = locate_simplify_state(revs, commit);
		return 0;
	tree_difference |= diff;
		oidset_init(&entry->trees, 16);
	}
	if (revs->def == NULL)
	}
		struct object *object = &commit_list->item->object;
	for (parents = commit->parents, parent_number = 1;
			if (opts > 0) {
			p = commit_list_insert(item, list);
	add_decoration(&revs->treesame, &commit->object, st);
	maillen = ident.mail_end - ident.mail_begin;
	 * Blob object? You know the drill by now..
	save_warning = warn_on_object_refname_ambiguity;
	info->rev[nr].item = item;
		struct tree *tree = lookup_tree(r, oid);
		add_alternate_refs_to_pending(revs, *flags);
 * connection to the actual bottom commit is not viewed as a side branch, but

			has_interesting = 1;

	 *
		commit_rewrite_person(&buf, "\nauthor ", opt->mailmap);
				 &revs->grep_filter);
		if (parse_commit(commit) < 0)
	return tree_difference;
	const char *name = entry->name;
	for (elem = list; elem; elem = elem->next)
			 * to a later parent. In the simplified history,
	fprintf(out, "%s ", oid_to_hex(&obj->oid));
	 * and return NULL.
	handle_one_reflog_commit(noid, cb_data);
		 * we are done computing the boundaries.
		die("--combined-all-paths makes no sense without -c or --cc");
static int for_each_bisect_ref(struct ref_store *refs, each_ref_fn fn,
	} else if (!strcmp(arg, "--author-date-order")) {
			return commit;
	 * not returned from get_revision_1().  Before returning
		add_message_grep(revs, optarg);
			continue;
		if (nth_parent == 1) {
			if (revs->show_pulls && (commit->object.flags & PULL_MERGE))
	revs->max_parents = -1;
	while ((c = prio_queue_peek(&info->indegree_queue)) &&
	struct topo_walk_info *info = revs->topo_walk_info;
		revs->blob_objects = 1;
		strbuf_setlen(path, baselen);

		return;

	if (split_ident_line(&ident, person, len))
		struct commit *p = parent->item;
static int remove_marked_parents(struct rev_info *revs, struct commit *commit)
		prepare_show_merge(revs);
}
			po->item->object.flags |= TMP_MARK;
			}
	 * in such a case, the immediate parent from that branch
{
	revs->pruning.repo = r;
}
		case commit_ignore:
			list = &p->next; /* skip newly added item */
	}

	/*


			return commit_error;
	struct rev_info *all_revs;
#include "utf8.h"

	struct object *obj;
		 * if we are not limited by path.  This means that you will
}
		 * All of the normal commits have already been returned,
}
struct add_alternate_refs_data {
		revs->expand_tabs_in_log = val;
}


		opt->tweak(revs, opt);
				argv_array_pushv(&prune_data, argv + i + 1);
	revs->topo_walk_info = xmalloc(sizeof(struct topo_walk_info));


	const char *encoding;
		commit_list_insert(commit, &yet_to_do);
	 * wasn't uninteresting), in which case we need
	if ((revs->diffopt.pickaxe_opts & DIFF_PICKAXE_KINDS_MASK) ||
	struct object *object = entry->item;

	for (i = 0; i < old_pending.nr; i++) {
			break;
			die("--cherry-pick is incompatible with --cherry-mark");
	/*

static int handle_one_reflog(const char *refname_in_wt,
		 * get_revision_1() runs out the commits, and
			   struct object_context *a_oc,

		if (parent->generation < info->min_generation) {
	compute_indegrees_to_depth(revs, info->min_generation);
	    ? "Invalid symmetric difference expression %s"
 * by eliminating side branches.
	if (array->nr == array->alloc)
}
			return REV_TREE_SAME;
}
		if (revs->sort_order == REV_SORT_BY_AUTHOR_DATE)

		if (!object) {
	entry = hashmap_get_entry(map, &key, ent, NULL);
	}
	if (revs->combined_all_paths && !revs->combine_merges)
{
		 * if (prune_data.nr == 1 && !strcmp(prune_data[0], ":")) {
	} else if (!strcmp(arg, "--oneline")) {
	 *
static struct commit *commit_stack_pop(struct commit_stack *stack)
			die("Failed to simplify parents of commit %s",
		cb->wt = wt;
		revs->dense_combined_merges = 0;
	 * prune parents - we want the maximal uninteresting
		struct all_refs_cb cb;
			if (slop)
	struct commit_list *newlist = NULL;
	compile_grep_patterns(&revs->grep_filter);
	} else if (!strcmp(arg, "--extended-regexp") || !strcmp(arg, "-E")) {
				     cb);
		revs->bisect = 1;
	    (revs->limited && limiting_can_increase_treesame(revs)))
					child->object.flags |= UNINTERESTING;
				commit->object.flags |= PULL_MERGE;
	return left;
	 * get_revision_1().  Ignore the error and continue printing the
			revs->abbrev = MINIMUM_ABBREV;
	if (!obj)
		if (left_first != !!(flags & SYMMETRIC_LEFT))
}
	return revs->prune && revs->dense &&
	} else if (skip_prefix(arg, "--branches=", &optarg)) {
{
	if (i != cnt || cnt+marked != orig_cnt)
	if (!revs->remove_empty_trees || tree_difference != REV_TREE_NEW)
			break;
			slop = still_interesting(list, date, slop, &interesting_cache);


	hashmap_entry_init(&key.ent, hash);
		repo_read_index(revs->repo);
					ts->treesame[nth_parent] = 1;
			continue;
			left_count++;
			save_parents(revs, commit);

	int made_progress;
				commit->object.flags |= SHOWN;
				/* We are adding all the specified
	for (p = commit->parents; p; p = p->next) {
	} else if (!strcmp(arg, "--not")) {
	key.path = (char *)path;
{
	fputc('\n', out);
struct merge_simplify_state {
	 * simplify the commit history and find the parent

	 * store a sentinel value for an empty (i.e., NULL) parent
	if (exclude_parent &&
		    int addremove, unsigned mode,
	return action;

	for_each_alternate_ref(add_one_alternate_ref, &data);

	if (buf.len)
	revs->simplify_history = 1;
 *        .     /

		return NULL;
	hashmap_for_each_entry(map, &iter, entry, ent /* member name */) {

		p = &commit_list_insert(commit, p)->next;
	/* clean up the result, removing the simplified ones */
		if (revs->topo_order)
			/* Subproject commit - not in this repository */
		handle_refs(refs, revs, *flags, for_each_bad_bisect_ref);
		relevant_parents = 0;
	 * TREESAME will have been set purely on that parent.
	else
/*
	 * Example:
		revs->skip_count = atoi(optarg);
	 *
		c->object.flags |= BOUNDARY;
static int handle_dotdot(const char *arg,
	if (!is_encoding_utf8(get_log_output_encoding()))
	if (revs->reverse) {
 * those merges as if they were single-parent. TREESAME is defined to consider
		return 0;
	 *   I--------*X       A modified the file, but mainline merge X used
		usage_with_options(usagestr, options);
				made_progress = 1;
#include "graph.h"

		return;
	unsigned long flags = object->flags;
	}
	mark = strstr(arg, "^-");
	 */
	 * Does the source list still have interesting commits in
		add_header_grep(revs, GREP_HEADER_REFLOG, optarg);
	if (!revs->single_worktree)
			  struct rev_info *revs, int symmetric)
{
}
				     (char *)message, strlen(message));
		return commit_ignore;
		/*

	struct commit *head, *other;

static void paths_and_oids_clear(struct hashmap *map)

			return -1;
				if (ts)
		}
	struct strbuf bisect_refs = STRBUF_INIT;
		return;
{
static void init_topo_walk(struct rev_info *revs)
		if (flags & BOUNDARY)
	struct commit *c;
		return 0;

		if (strtol_i(arg + 1, 10, &revs->max_count) < 0 ||
void show_object_with_name(FILE *out, struct object *obj, const char *name)
		return 0;

	unsigned char treesame[FLEX_ARRAY];
			     parents = parents->next) {
	else if (commit->object.flags & PATCHSAME)
static struct treesame_state *initialise_treesame(struct rev_info *revs, struct commit *commit)
			break;
	ret = handle_dotdot_1(arg, dotdot, revs, flags, cant_be_filename,
		for_each_glob_ref(handle_one_ref, optarg, &cb);
	struct object_id oid;
};
			 * For consistency with TREESAME and simplification
	 * The ones that are not marked with TMP_MARK are uninteresting
		if (parent->object.flags & TMP_MARK) {
void mark_parents_uninteresting(struct commit *commit)
}
		 */

	if (c->object.flags & flag)
	/*
	free_commit_list(revs->previous_parents);
	 * Otherwise, it simplifies to what its sole relevant parent
		unsigned relevant_parents;
	enum rewrite_result ret = rewrite_one_1(revs, pp, &queue);
	while (commit_list) {
			char **slot = revision_sources_at(revs->sources, p);
		revs->combined_all_paths = 1;
		hashmap_entry_init(&entry->ent, hash);
	/*
			if (!revs->show_pulls || !nth_parent)
	struct object_id *oid;
	 * set.
			if (p->parents)
	 * reached this commit some other way (where it
	die(symmetric
	struct tree *t2 = get_commit_tree(commit);
	struct all_refs_cb cb;
{
	 * Check if any commits have become TREESAME by some of their parents
		revs->unpacked = 1;
static void explore_walk_step(struct rev_info *revs)
static void paths_and_oids_insert(struct hashmap *map,
	else if (!revs || revs->left_right) {
		revs->show_notes_given = 1;

		revs->treesame.name = "treesame";

{
	free_commit_list(h);
	while ((c = prio_queue_peek(&info->explore_queue)) &&
		revs->blob_objects = 1;
	 * on the output of reduce_heads(). reduce_heads outputs the reduced
	/* pop next off of topo_queue */
	while (pending.nr > 0)
	if (opt->grep_filter.use_reflog_filter) {
		if (limit_list(revs) < 0)
{

			if (!(commit->object.flags & SEEN)) {
		return "^";
		      const struct object_id *oid, unsigned int flags)

	if (parse_tree_gently(tree, 1) < 0)
	}
	info->rev[nr].name = xstrdup(name);
				prio_queue_put(queue, p);
		test_flag_and_insert(&info->indegree_queue, parent, TOPO_WALK_INDEGREE);
		struct commit *a, *b;
		revs->simplify_history = 0;
				cb->name_for_errormsg);

		const char *email, timestamp_t timestamp, int tz,
				     flags_exclude);
static void do_add_index_objects_to_pending(struct rev_info *revs,
	 */
		if (!strcmp(optarg, "sorted"))
	}
	} else if ((argcount = parse_long_opt("grep", argv, &optarg))) {
		struct commit *commit;


	revs->pending.alloc = 0;
	 * If we don't do pruning, everything is interesting
		revs->grep_filter.all_match = 1;
	} else if ((argcount = parse_long_opt("after", argv, &optarg))) {
	if (parse_tree_gently(tree, 1) < 0)
	/* First count the commits on the left and on the right */
		if (strcmp(optarg, "none"))
	 *    \       /        "-s ours", so took the version from I. X is
#include "object-store.h"
	}

	if (revs->prune && revs->dense) {

	 * Mark the ones that can reach bottom commits in "list",
		revs->show_pulls = 1;
		object->flags |= flags;
	} else if (!strcmp(arg, "--expand-tabs")) {
				relevant_parents++;
		object = get_reference(revs, revs->def, &oid, 0);
		if (revs->cherry_mark)
	commit = (struct commit *)it;
			}

	 * to mark its parents recursively too..
	struct object_array old_pending;
			pn = pn->next;
						revs, argc - i, argv + i,
#include "log-tree.h"
	/*
}
			break;
}
		/*

	struct topo_walk_info *info = revs->topo_walk_info;

	for (p = commit->parents, n = 0; p; p = p->next, n++) {

}
					    unsigned int flags)
		case REV_TREE_OLD:

	}
			}

		if (read_index_from(&istate,
	} else if (!strcmp(arg, "--count")) {
		}
		struct treesame_state *st;

	int i, prune_num = 1; /* counting terminating NULL */
		reversed = NULL;
	diff_setup_done(&revs->diffopt);
	FREE_AND_NULL(stack->items);
		revs->right_only = 1;
{
		revs->blob_objects = 1;
}

			char *end;
			continue;
{
			return 1;
int rewrite_parents(struct rev_info *revs, struct commit *commit,
		revs->sort_order = REV_SORT_BY_COMMIT_DATE;
		(*pi)--;
			continue;
			if (process_parents(revs, p, NULL, queue) < 0)
		revs->diffopt.prefix_length = strlen(prefix);
			 * between relevant commits to tie together topology.
	return (commit->object.flags & (UNINTERESTING | BOTTOM)) != UNINTERESTING;
		return 2;
	if (!revs->saved_parents_slab) {
		clear_ref_exclusion(&revs->ref_excludes);
		if (revs->ignore_missing)
	/*
		if (!commit)
			warning("reflog of '%s' references pruned commits",
	 * If revs->commits is non-NULL at this point, an error occurred in
}
	 */
	/* clear the temporary mark */
	 * --full-history --simplify-merges will produce "I-A-B". But this is a
#define SLOP 5
	l->item = child;
		 */
		test_flag_and_insert(&info->indegree_queue, c, TOPO_WALK_INDEGREE);
			      namemail.buf, namemail.len);
	surviving_parents = 0;
			if (relevant)
			 * in the path we are limited to by the pathspec.

			   struct strbuf *path, unsigned int flags)
	pp = &commit->parents;
	 * We want to keep only the first set of parents.  We need to
	 * For multi-parent commits, identify a sole relevant parent, if any.
	free_commit_list(bases);
	strbuf_worktree_ref(cb->wt, &refname, refname_in_wt);
/* How many extra uninteresting commits we want to see.. */
		struct object *o = parse_object(cb->all_revs->repo, oid);
		struct object *object = &commit_list->item->object;
		handle_refs(refs, revs, *flags, refs_for_each_ref);
	free_tree_buffer(tree);
		revs->min_age = approxidate(optarg);
	struct ident_split ident;
		else if (!cb->warned_bad_reflog) {
		revs->verbose_header = 1;
		revs->def = argv[1];
	}
	 * parents cannot make us !TREESAME - if we have any relevant
	/* We are done with the TMP_MARK */
		*pp = copy_commit_list(commit->parents);
	if (revs->unpacked && has_object_pack(&commit->object.oid))
	if (revs->max_age != -1 && (c->date < revs->max_age))
			      uint32_t pos,
		}
static void read_pathspec_from_stdin(struct strbuf *sb,
static inline void test_flag_and_insert(struct prio_queue *q, struct commit *c, int flag)
		add_pending_object(revs, it, arg);
		if (!opts)
		if (!revs->limited) {

		if (revs->sources) {
	struct commit_list *parents;

		struct commit *commit = list->item;
	object = get_reference(revs, arg, &oid, flags ^ local_flags);
}
			continue; /* current index already taken care of */
		struct object *obj = &commit->object;
		return 0;
 * only relevant parents, if any. If we are TREESAME to our on-graph parents,
}
 * Returns the number of arguments left that weren't recognized
	} else if (!strcmp(arg, "--merge")) {
	} else if ((argcount = parse_long_opt("until", argv, &optarg))) {
		if (flags & BOUNDARY)
	strbuf_release(&bisect_refs);
void parse_revision_opt(struct rev_info *revs, struct parse_opt_ctx_t *ctx,
	if (commit->object.flags & ADDED)

		revs->max_count = atoi(optarg);
		 *	prune_data.alloc = 0;
{
{
			die("--cherry is incompatible with --left-only");



		revs->show_signature = 0;
{
	for (p = c->parents; p; p = p->next) {
			continue;
			break;
		}

	} else {
					    oid_to_hex(&p->object.oid));
	/* Pickaxe, diff-filter and rename following need diffs */
			for (parents = c->parents;

	}
					 struct prio_queue *queue)
		revs->limited = 1;
	return st;
	 * will be rewritten to be the merge base.
	 * Normal non-merge commit? If we don't want to make the
		*flags ^= UNINTERESTING | BOTTOM;
	 * If our max_count counter has reached zero, then we are done. We

	 *      o----X		X: the commit we are looking at;
			if (revs->ignore_missing_links || (flags & UNINTERESTING))

 *
	for (l = commit->parents; l; l = l->next)
		add_pending_object_with_path(revs, object, name, mode, path);
	info = revs->topo_walk_info;

					break;
	const char *mark = get_revision_mark(revs, commit);
		c->object.flags |= UNINTERESTING;
	 * This is unfortunate; the initial tips need to be shown
		revs->expand_tabs_in_log = 8;
	 *   I------X         A modified the file, but it was reverted in B,
		/*
		st->simplified = pst->simplified;

	struct commit *commit;
			    int whence,
{
				return rewrite_one_error;
	else
{
		return "=";
	}
		return 0;
	if (revs->line_level_traverse) {
	}
		revs->sort_order = REV_SORT_IN_GRAPH_ORDER;
		 * We need some something like get_submodule_worktrees()

			return NULL;
		pst = locate_simplify_state(revs, p->item);
	free_tree_buffer(tree);
		 * through to the non-tag handlers below. Do not
		if (flags & UNINTERESTING)

			   &revs->pruning) < 0)
int ref_excluded(struct string_list *ref_excludes, const char *path)

		id = has_commit_patch_id(commit, &ids);
{

{
		commit->object.flags |= TREESAME;
		 * see the usual "commits that touch the paths" plus any

		if (commit->parents->next)
	 * in topological order
	revs->sort_order = REV_SORT_IN_GRAPH_ORDER;
	pn = h;
				      struct argv_array *prune)
			/* Subproject commit - not in this repository */
			if (opts < 0)
			info->min_generation = parent->generation;
static unsigned update_treesame(struct rev_info *revs, struct commit *commit)
	name = ident.name_begin;
}
		revs->simplify_history = 0;
	} else if (skip_prefix(arg, "--min-parents=", &optarg)) {
	if (c)
		return 2;
				return commit_ignore;
		    int oid_valid,
			parent->object.flags |= TMP_MARK;
			continue;
	 * If we are TREESAME to a marked-for-deletion parent, but not to any
		get_reflog_message(&buf, opt->reflog_info);
	if (commit->object.flags & SHOWN)
	 * Find either in the original commit message, or in the temporary.
	} else if (!strcmp(arg, "--standard-notes")) {
#include "commit-slab.h"
			    struct commit *parent, struct commit *commit)
	b_obj = parse_object(revs->repo, &b_oid);
			if (list)
			continue;
 * A "relevant" commit is one that is !UNINTERESTING (ie we are including it
		mark_parents_uninteresting(c);
					  struct commit_list *orig)
	 * Note that it is possible that the simplification chooses a different
	 *     /    /		o: a commit that touches the paths;
			if (list)
{
			return 0;
		if (rev_same_tree_as_empty(revs, commit))


		revs->topo_order = 1;
	} else if (!strcmp(arg, "--no-abbrev")) {


	add_pending_object(revs, object, name);
static void expand_topo_walk(struct rev_info *revs, struct commit *commit)
			if (parse_commit_gently(p, 1) < 0)
				commit->object.flags |= SHOWN;
	int retval;
		 * create_boundary_commit_list() has populated
			continue;
	if (revs->def && !revs->pending.nr && !revs->rev_input_given && !got_rev_arg) {
	} else if (!strcmp(arg, "-t")) {
		return argcount;
			 * (1) all filenames must exist;
			die("--cherry-mark is incompatible with --cherry-pick");
	}
		die("cannot combine --parents and --children");
		*(indegree_slab_at(&info->indegree, c)) = 0;
		revs->cherry_mark = 1;
		return "-";
 *
		 int old_oid_valid, int new_oid_valid,
	struct prio_queue indegree_queue;
	else {
				revs->skip_count--;
				if (parse_commit(p) < 0)
	 * If the commit is uninteresting, don't try to
		struct commit *commit = p->item;
	}
	if (revs->first_parent_only && revs->bisect)
				 handle_one_reflog_ent, cb_data);

		if (p->object.flags & UNINTERESTING)
				revs->limited = 1;
}

	data.revs = revs;
		revs->break_bar = xstrdup(optarg);

		if (revs->first_parent_only)
	/*
	/*
		return revs->ignore_missing ? 0 : -1;

			strbuf_addstr(&buf, message);
		if (starts_with(arg, "--show-notes=") &&
			      ident.mail_end - ident.name_begin + 1,
	} else if (!strcmp(arg, "--objects-edge-aggressive")) {
	/*
				if (!c)

{
		if (!id)
	return for_each_bisect_ref(refs, fn, cb_data, term_bad);
	head = lookup_commit_or_die(&oid, "HEAD");
			seen_dashdash = 1;
	int retval;
	} else if (!strcmp(arg, "--do-walk")) {
		 * is worth showing if it has a tag pointing at it.
}

		update_treesame(revs, commit);
						&flags);
	}
	if (get_oid_with_context(revs->repo, arg, get_sha1_flags, &oid, &oc))
	if (revs->no_walk)
	unsigned n;
			  int flag, void *cb_data)
		p->item->object.flags &= ~TMP_MARK;
		 * Do not free(list) here yet; the original list
		if (revs->linear)
	 * Commit object? Just return it, we'll do all the complex
		 * and pathspec.
	} else if ((argcount = parse_long_opt("committer", argv, &optarg))) {
 *
	unsigned left_flag;
		return 0;
		revs->min_parents = 2;
	revs->previous_parents = copy_commit_list(commit->parents);
		revs->date_mode.type = DATE_RELATIVE;
		return argcount;
{
	if (istate->cache_tree) {
static void add_one_alternate_ref(const struct object_id *oid,
			 * first iteration.
	} else if (!strcmp(arg, "--perl-regexp") || !strcmp(arg, "-P")) {

		if (st->simplified == commit)
	for (p = list; p; p = p->next) {
	int i;
void mark_tree_uninteresting(struct repository *r, struct tree *tree)
				    struct commit_list *commit_list,
		revs->break_bar = "                    ..........";
	revs->rev_input_given = 1;
}
	strbuf_release(&refname);

	}
}
}
	c->object.flags |= flag;
					  struct commit_stack *pending)

		add_other_reflogs_to_pending(&cb);

				 * (they are grandparents for us).
	}
			continue;
					 struct commit **pp,
	return 0;
	int left_first;
	if (!orig)
	}
	int flags;
{
				continue;
}
	add_pending_object_with_path(revs, a_obj, a_name, a_oc->mode, a_oc->path);
		return SLOP;
		if (!buf.len)
	} else if (skip_prefix(arg, "-n", &optarg)) {
	return relevant;
	if (!revs->reflog_info && revs->grep_filter.use_reflog_filter)
	}
	struct commit_list *p;
	}
	}
	 * ones we got from get_revision_1() but they themselves are

static struct commit *one_relevant_parent(const struct rev_info *revs,
			tail = simplify_one(revs, commit, tail);
	int local_flags;
	 * simplifies to.
		if (strtol_i(arg, 10, &val) < 0 || val < 0)

	tree_difference = REV_TREE_SAME;
	} else if (!strcmp(arg, "--relative-date")) {
}
	grep_commit_pattern_type(GREP_PATTERN_TYPE_UNSPECIFIED,
	 * NOTE!
	} else if (!strcmp(arg, "--topo-order")) {
	} else if (!strcmp(arg, "--no-min-parents")) {

			return -1;
			return commit_ignore;

		revs->notes_opt.use_default_notes = 0;
}
		return;
		return; /* do not add the commit itself */
	 *    \    /          meaning mainline merge X is TREESAME to both

	o->flags |= UNINTERESTING | SEEN;
			if (ts)
	return !(entry->item->flags & SHOWN);

	 * simplified away. Only if we have only irrelevant parents do we
{
		revs->tree_objects = 1;
		case OBJ_BLOB:
 */
}

	if (revs->simplify_merges)
	/* no update_treesame() - removing duplicates can't affect TREESAME */
			struct commit *p = parent->item;
		b = lookup_commit_reference(revs->repo, &b_obj->oid);
{
	struct commit_list *po, *pn;
	if (revs->topo_walk_info)
{

		}
		revs->limited = 1;
	} else if (!strcmp(arg, "--cherry-mark")) {
	if (seen_dashdash)
	for (i = 0; i < istate->cache_nr; i++) {
	}

	while (list) {
		/*
				c->object.flags |= TMP_MARK;
	info->nr++;
	} else if ((argcount = parse_long_opt("before", argv, &optarg))) {
{
struct path_and_oids_entry {
	struct rev_info *revs = options->change_fn_data;
static int handle_revision_pseudo_opt(const char *submodule,
		 * A commit that is not pointed by a tag is uninteresting
	 * unmarked parents, unmark the first TREESAME parent. This is the
		if (commit->object.flags & TREESAME) {
	if (revs->track_first_time) {
	endp = strchr(person, '\n');

	} else if (!strcmp(arg, "--invert-grep")) {
		add_cache_tree(sub->cache_tree, revs, path, flags);
	append_header_grep_pattern(&revs->grep_filter, field, pattern);
};
	/*
		if (!(p->object.flags & TREESAME))


		if (c->generation < info->min_generation)
	}
		init_reflog_walk(&revs->reflog_info);
{
}
}

		die(_("-L does not yet support diff formats besides -p and -s"));
	 * boundary commits. But we want to avoid calling get_revision_1, which
	 * the merge commit X and that it changed A, but not making clear that
		if (!st)
		}
	}
		else
	if (revs->sort_order == REV_SORT_IN_GRAPH_ORDER)
	if (!is_null_oid(oid)) {
		/* Commit without changes? */
		}
			struct commit_list *parents;

	struct commit *c;
static void add_alternate_refs_to_pending(struct rev_info *revs,
	} else if (!strcmp(arg, "--merges")) {
#include "cache.h"
		revs->abbrev = DEFAULT_ABBREV;
static const char *term_good;
		date = commit->date;
				continue;
			removed++;
{
			p->object.flags |= SEEN;
	struct commit_list *rlist = NULL;

		if (revs->cherry_pick)
	if (revs->reflog_info && revs->limited)
static int rev_same_tree_as_empty(struct rev_info *revs, struct commit *commit)
		format_display_notes(&commit->object.oid, &buf, encoding, 1);
					 struct object *obj,
	/*
	 * out).
 * if the whole diff is removal of old data, and otherwise
				  const char *path,
		revs->dense_combined_merges = 1;

	} else if (!strcmp(arg, "--all-match")) {
		return;
	} else if (!strcmp(arg, "--encode-email-headers")) {
		revs->min_age = approxidate(optarg);
	if (process_parents(revs, commit, NULL, NULL) < 0) {
		yet_to_do = NULL;
	int marked = 0;
		*dotdot = '\0';
				seen_end_of_options = 1;
	struct oidset trees;
	} else if (!strcmp(arg, "--full-history")) {
	ALLOC_GROW(stack->items, stack->nr + 1, stack->alloc);
		if (exclude_parent && parent_number != exclude_parent)
			continue;
	/* Second, deal with arguments and options */
		if (!(c->object.flags & CHILD_SHOWN))
}
	 * wasn't uninteresting), in which case we need
		c->object.flags |= SHOWN;
		object = parse_object(revs->repo, get_tagged_oid(tag));

	} else if (!strcmp(arg, "-c")) {

		next = list->next;


		if (revs->first_parent_only)

		clear_saved_parents(revs->saved_parents_slab);
		if (parse_commit_gently(p, gently) < 0) {

	struct commit_list *p;
		if (argc <= 1)
	person = strstr(buf->buf, what);
	revs->pruning.flags.recursive = 1;
				     struct oidset *trees)
 * that parent.
		struct object_context oc;
void clear_ref_exclusion(struct string_list **ref_excludes_p)

		revs->cherry_mark = 1;
	if (!c)
	const char *p;
	unsigned int flags_exclude = flags ^ (UNINTERESTING | BOTTOM);
 * You may only call save_parents() once per commit (this is checked
 * further to the ones that can reach one of the commits in "bottom".
		return REV_TREE_OLD;
	b_obj->flags |= b_flags;
				whence, flags);
{
			prune[prune_num-1] = NULL;
	if (n <= 0) {

/*
	}
{
		return c;
{


{
			commit->object.flags |= TRACK_LINEAR;
#include "reflog-walk.h"
	struct name_entry entry;
	if (revs->diffopt.output_format & ~DIFF_FORMAT_NO_OUTPUT)
	}
	}
	 * should be rewritten to?  Otherwise we are not ready to
	for (p = bottom; p; p = p->next)
 * A definition of "relevant" commit that we can use to simplify limited graphs
			return ">";
			*pp = p->next;
			 * A merge commit is a "diversion" if it is not
		 * If we are simplifying by decoration, then the commit
	object_array_clear(&old_pending);
		revs->min_age = atoi(optarg);
			revs->no_walk = REVISION_WALK_NO_WALK_UNSORTED;
{
					     ce->ce_mode, ce->name);
	if (!dotdot)
		revs->topo_order = 1;
		if (left_first == !!(flags & SYMMETRIC_LEFT))
				 * "root" commit.
			prio_queue_put(&info->topo_queue, c);

	} else if (!strcmp(arg, "--parents")) {
	struct commit_list *elem, *bottom = NULL;

	     parents = parents->next, parent_number++) {
{
 */
		if (!pst->simplified) {
	 * Normally we haven't parsed the parent

	add_pending_object(revs, &head->object, "HEAD");
			 */
		if (ce_path_match(istate, ce, &revs->prune_data, NULL)) {
		refs = get_submodule_ref_store(submodule);
			commit->object.flags |= TREESAME;
		discard_index(&istate);
		revs->early_output = 100;
	return object;
		revs->ancestry_path = 1;
	} else if (!strcmp(arg, "--bisect")) {
		 */
 * Treating bottom commits as relevant ensures that a limited graph's
	if (parse_commit_gently(c, 1) < 0)
		if (st->treesame[0] && revs->dense)
	} else if (!strcmp(arg, "--simplify-merges")) {
		struct index_state istate = { NULL };
		else
static void reset_topo_walk(struct rev_info *revs)
	 * to the list of objects to look at later..
		if (revs->exclude_promisor_objects && is_promisor_object(oid))
			revs->previous_parents = NULL;
		mark_trees_uninteresting_sparse(r, &entry->trees);
	} else if (!strcmp(arg, "--first-parent")) {
	 * TREESAME is straightforward for single-parent commits. For merge
	tree_difference = REV_TREE_SAME;
	obj->flags |= UNINTERESTING;
		struct object_array_entry *e = old_pending.objects + i;
{
		object->flags |= flags;
void add_head_to_pending(struct rev_info *revs)
 * Y-X, despite A being flagged UNINTERESTING.

			      void *cb)

	person += strlen(what);
	} else if (!strcmp(arg, "--objects-edge")) {
		revs->no_walk = 0;
			info->min_generation = c->generation;
			tail = &commit_list_insert(commit, tail)->next;
			revs->notes_opt.use_default_notes = 1;
static void handle_refs(struct ref_store *refs,
	add_pending_object_with_path(revs, obj, name, mode, NULL);

struct commit_list *get_saved_parents(struct rev_info *revs, const struct commit *commit)
#include "cache-tree.h"
	const char *optarg;

	} else if (!strcmp(arg, "--simplify-by-decoration")) {

	const char *mail;
		for_each_glob_ref_in(handle_one_ref, optarg, "refs/tags/", &cb);
	add_rev_cmdline(revs, object, arg_, REV_CMD_REV, flags ^ local_flags);
	} else if ((argcount = parse_long_opt("encoding", argv, &optarg))) {
			break;
		if (parse_commit_gently(parent, 1) < 0)
		symmetric = 1;
		clear_ref_exclusion(&revs->ref_excludes);
	if (!istate->cache_nr)
			commit->object.flags &= ~TREESAME;
	return "";

	struct object_id oid;
#include "string-list.h"
			/*
	if (process_parents(revs, c, NULL, NULL) < 0)
	struct treesame_state *ts = lookup_decoration(&revs->treesame, &commit->object);

 * the result of "A..B" without --ancestry-path, and limits the latter
			     const void *keydata)


	for (p = list; p; p = p->next) {
		if (fetch_if_missing)
/*
		revs->topo_order = 1;
#define EMPTY_PARENT_LIST ((struct commit_list *)-1)
	struct commit_list *l;
	}
		return 0;
	} else if (!strcmp(arg, "-r")) {
	sort_in_topological_order(&revs->commits, revs->sort_order);
		    const char *fullpath, unsigned dirty_submodule)
		if (!revs->ignore_missing_links)

		}
}
		revs->simplify_history = 0;
 */
			return NULL;
	struct object_context oc;
	 */
	}
		/* accept -<digit>, like traditional "head" */
		if (relevant_commit(commit)) {
	/*

	}
		parent->object.flags |= TMP_MARK;

	if (!strcmp(arg, "--all")) {
 *   2. We saw anything except REV_TREE_NEW.
	if (!endp)
	if (!strcmp(arg, "--all") || !strcmp(arg, "--branches") ||
		 * revs->commits with the remaining commits to return.
#include "worktree.h"
	 * understanding odd missed merges that took an old version of a file.
		revs->edge_hint = 1;
		revs->topo_order = 1;
	int seen_end_of_options = 0;
 * The only time we care about the distinction is when
	int nth_parent, removed = 0;
		return 1;
				commit->object.flags |= TREESAME;
	if (opt->grep_filter.header_list && opt->mailmap) {
			argc = i;
static struct commit *next_topo_commit(struct rev_info *revs)

	unsigned int a_flags, b_flags;
	struct prio_queue queue = { compare_commits_by_commit_date };
	 * Default log from X would produce "I". Without this check,
 */
			else
		add_pending_object_with_mode(revs, object, revs->def, oc.mode);
}
		return tail;
				irrelevant_change = 1;
		clear_ref_exclusion(&revs->ref_excludes);
	struct commit_list *yet_to_do, **tail;
		add_ref_exclusion(&revs->ref_excludes, optarg);
	}

	object = get_reference(cb->all_revs, path, oid, cb->all_flags);
	} else if (!strcmp(arg, "--ancestry-path")) {
	for (i = 0; i < istate->cache_nr; i++) {
		if ((n < revs->min_parents) ||
		b_flags = flags;
		p = &(l->item->object);
		return dotdot_missing(arg, dotdot, revs, symmetric);
		return "*";
	while ((oid = oidset_iter_next(&iter))) {
			(*pi)++;

		return 0;
 */
	const char *name;
	st = lookup_decoration(&revs->merge_simplification, &commit->object);
	if (!blob)
					if (++n >= 2)
			if (seen_dashdash || *arg == '^')
	 * boundary commits are the commits that are parents of the

}
#include "patch-ids.h"
	for (p = list; p; p = p->next) {
		else
struct treesame_state {
	for (p = commit->parents; p; p = p->next) {
		if (add_parents_only(revs, arg, flags, 0))
{
				*slot = *revision_sources_at(revs->sources, commit);
 *
static void prepare_show_merge(struct rev_info *revs)
	return 1;
			    struct object *item,

		/*
		get_commit_format(optarg, revs);
		if (revs->previous_parents) {
		return argcount;
		st->treesame + nth_parent + 1,
	/*
	if ((commit->object.flags & UNINTERESTING) || !commit->parents) {

		else
	add_rev_cmdline_list(revs, bases, REV_CMD_MERGE_BASE, UNINTERESTING | BOTTOM);
		}
		revs->track_first_time = 1;
			if (tree->object.flags & UNINTERESTING) {
		return;
		verify_non_filename(revs->prefix, arg);
	}

		revs->commits = NULL;
	 */
static void commit_stack_clear(struct commit_stack *stack)
		return;

		revs->diff = 1;
	if (*arg == '^') {
	pp = saved_parents_at(revs->saved_parents_slab, commit);
	}
		revs->boundary = 1;
		if (revs->abbrev < MINIMUM_ABBREV)

}

			continue;
			prune_num++;
	 */
		return;
			return NULL;
	cb->name_for_errormsg = refname.buf;
	int i;
	} else if (!strcmp(arg, "--single-worktree")) {
			revs->prune = 1;
				commit->object.flags |= SEEN;

				try_to_simplify_commit(revs, commit);
	while (strbuf_getline(&sb, stdin) != EOF) {
			if (p->item->object.flags & TMP_MARK) {
}
	} else if (skip_prefix(arg, "--early-output=", &optarg)) {
			 * If we want ancestry, then need to keep any merges
			tail = &commit_list_insert(p->item, tail)->next;



 */
		struct tree *tree = (struct tree *)object;
	if (revs->combine_merges)
	struct rev_info *revs = cb;
	if (revs->rewrite_parents && revs->children.name)
	return st;
		p->item = pst->simplified;
			break;
			if (c->object.flags & (UNINTERESTING | TREESAME))
		*mark = 0;
				    &ctx->cpidx, ctx->out, NULL);
		}


			if (revs->first_parent_only)
	struct string_list_item *item;
	memset(revs, 0, sizeof(*revs));
{
		revs->diff = 1;
	stack->nr = stack->alloc = 0;

	tree_difference = REV_TREE_DIFFERENT;
				    struct object_array_entry *entry)
	struct object *object = get_reference(revs, name, oid, flags);
	for (parent = commit->parents; parent; parent = parent->next) {
	/*
	revs->dense = 1;
		case OBJ_BLOB:
		path = NULL;
				continue;
	grep_init(&revs->grep_filter, revs->repo, prefix);
			return commit_ignore;
				continue;
	} else {
	st = lookup_decoration(&revs->treesame, &commit->object);
		revs->sort_order = REV_SORT_BY_AUTHOR_DATE;
		case rewrite_one_error:
{
	} else if (!strcmp(arg, "--no-merges")) {
			if (*end != '\0' || !exclude_parent)
	add_pending_object_with_path(revs, object, arg, oc.mode, oc.path);
			int (*for_each)(struct ref_store *, each_ref_fn, void *))
		for_each_packed_object(mark_uninteresting, revs,
	init_indegree_slab(&info->indegree);
		return commit->parents;
				if (!revs->ignore_missing_links)
		add_object_array(p, NULL, &revs->boundary_commits);
				 * to lose the other branches of this
		return old_same;
	 * I to X, and X is not an important merge.
			mark_parents_uninteresting(commit);
		fputc(*p, out);
				 refname.buf,
		revs->tag_objects = 1;

	 * Detect and simplify both cases.
		die("cannot use --grep-reflog without --walk-reflogs");

	hashmap_for_each_entry(&map, &map_iter, entry, ent /* member name */)
	 * base TREESAME on them. Note that this logic is replicated in

	if (map_user(mailmap, &mail, &maillen, &name, &namelen)) {
		free_commit_list(bottom);
	 * with regard to that parent, and we can simplify accordingly.
 * *name is copied.
{
	size_t len, namelen, maillen;
	 * does not have any commit that touches the given paths;
		if (pn && po->item == pn->item) {
		a_name = "HEAD";
		return argcount;
		c = pop_commit(&revs->commits);

			break;
			     int flag, void *cb_data)
		if (revs->first_parent_only)
		object = parse_object(revs->repo, oid);
{
	else if ((argcount = parse_long_opt("author", argv, &optarg))) {
	*ref_excludes_p = NULL;
		add_cache_tree(istate->cache_tree, revs, &path, flags);
	mail = ident.mail_begin;
		return REV_TREE_DIFFERENT;
	if (!obj)
	 * NEEDSWORK: decide if we want to remove parents that are
			if (p->item == NULL || /* first commit */

					    struct index_state *istate,
		}
		*pp = EMPTY_PARENT_LIST;
		struct object *object;
		} else	/* revs->left_only is set */
}
}
				    get_worktree_git_dir(wt)) > 0)

	if (--st->nparents == 1) {
	struct commit_list **pp, *p;
};
		if (revs->max_count > 0)
}


			 struct rev_info *revs,
 * of change. Which means we can stop the diff early in either of these
	mark_tree_contents_uninteresting(r, tree);
 * This is used to compute "rev-list --ancestry-path A..B", as we need
		}

	    exclude_parent > commit_list_count(commit->parents))
	struct topo_walk_info *info;

		 * If we have fewer left, left_first is set and we omit
				int argc, const char **argv, int *flags)

		init_all_refs_cb(&cb, revs, *flags);

	if (!get_commit_tree(commit))
	if (commit->parents && commit->parents->next) {
		/*
	for (p = worktrees; *p; p++) {
	 */
		die("cannot combine --walk-reflogs with --graph");

	 * in it.

	*dotdot = '.';

	int i = 0, marked = 0;
	while ((p = *pp) != NULL) {
}

		revs->ignore_merges = 0;
	 * don't simply return NULL because we still might need to show
		if (!(commit->object.flags & UNINTERESTING))
	/*
		revs->date_mode_explicit = 1;
			}
		blob = lookup_blob(revs->repo, &ce->oid);
static void free_saved_parents(struct rev_info *revs)
{


		return commit;

		commit = pop_commit(&list);

	struct treesame_state *st = xcalloc(1, st_add(sizeof(*st), n));
	if (revs->topo_order && !generation_numbers_enabled(the_repository))
			break;
		switch (object_type(entry.mode)) {
struct commit *get_revision(struct rev_info *revs)
	}
	hashmap_init(map, path_and_oids_cmp, NULL, 0);
		return;
}
		return NULL;
	struct commit_list *l;


static int mark_uninteresting(const struct object_id *oid,
		default:
static void file_add_remove(struct diff_options *options,
	message = logmsg_reencode(commit, NULL, encoding);
	    !strcmp(arg, "--alternate-refs") ||
		return 0;
		return orig->item;
	 * not marked with TMP_MARK from commit->parents for commits
			mark_tree_uninteresting(r, lookup_tree(r, &entry.oid));
static void commit_stack_push(struct commit_stack *stack, struct commit *commit)
	while (po) {
{
implement_shared_commit_slab(revision_sources, char *);
		free(add_decoration(&revs->treesame, &commit->object, NULL));
		 * and we are now returning boundary commits.
		}
				    unsigned int flags)
{
	if (revs->graph && revs->track_linear)
			if (!strcmp(arg, "--end-of-options")) {
	for_each(refs, handle_one_ref, &cb);
	struct path_and_oids_entry key;

	memset(&b_oc, 0, sizeof(b_oc));
			 * (2) all rev-args must not be interpretable
		return;
		return 0;
	 * reached this commit some other way (where it
	 * A commit simplifies to itself if it is a root, if it is
	}
		revs->no_walk = 0;
			}
	if (!object) {
	 */
	struct strbuf sb;
	}


			if (revs->exclude_promisor_objects &&
	 * this function).
}
		commit_list_insert(p->item, &rlist);
	struct commit_list *p;
	} else
		if (revs->first_parent_only)
		if (commit->object.flags & SYMMETRIC_LEFT)
	} else if (!strcmp(arg, "--no-notes")) {

		retval = grep_buffer(&opt->grep_filter, buf.buf, buf.len);
}
	}

	 *
{
	if (!a_obj || !b_obj)
 * parent list, if we are maintaining the per-parent treesame[] decoration.
		revs->max_parents = -1;
{
		id->commit->object.flags |= cherry_flag;
		return argcount;

			*pi = 2;
	 *
		revs->limited = 1;
			struct rev_info *revs, unsigned flags,

static void handle_one_reflog_commit(struct object_id *oid, void *cb_data)
static struct object *get_reference(struct rev_info *revs, const char *name,
		return REV_TREE_NEW;
	 * in the resulting list.  We may not want to do that, though.
	int all_flags;
{
			     parents;
			 const char *prefix)
	memmove(st->treesame + nth_parent,
	} else if (!strcmp(arg, "--reverse")) {

		 * .e.g with adding all HEADs from --all, which is not
#include "prio-queue.h"
		bottom = collect_bottom_commits(list);
	char *dotdot = strstr(arg, "..");
				if (child)
		arg++;

struct all_refs_cb {
		break;
}
	if (!*a_name)

		if (c->object.flags & (SHOWN | BOUNDARY))
	 */
	handle_one_reflog_commit(ooid, cb_data);
	struct object *object;
	}
	} else if (!strcmp(arg, "--cherry-pick")) {
		revs->reverse = 0;

static int mark_redundant_parents(struct commit *commit)
	return old_same;
		revs->pretty_given = 1;
	} else if (!strcmp(arg, "--no-max-parents")) {
	return 1;

 * that are descendants of A.  This takes the list of bottom commits and
		/* just A..B */
		st = xcalloc(1, sizeof(*st));
}
	 * and it doesn't make sense to omit that path when asking for a
	 */
		return argcount;
#include "dir.h"
			sort_in_topological_order(&revs->commits, revs->sort_order);

{
		const char *arg = argv[i];
	if (get_oid("MERGE_HEAD", &oid))


		for_each_glob_ref_in(handle_one_ref, optarg, "refs/remotes/", &cb);
	struct commit_list *l;
		pp = &parent->next;
			 * traversal to follow a side branch that brought everything
		 * propagate path data from the tag's pending entry.
	}
		die("--unpacked=<packfile> no longer supported.");
				   struct commit **interesting_cache)
	if (revs->exclude_promisor_objects) {
			const struct option *options,
		 * --full-diff on simplified parents is no good: it
	if (revs->boundary == 2) {
		st = locate_simplify_state(revs, commit);
	retval = diff_tree_oid(NULL, &t1->object.oid, "", &revs->pruning);
		b_name++;
			 * merge, remember per-parent treesame if needed.
	if (revs->show_merge)
		revs->simplify_by_decoration = 1;
static void try_to_simplify_commit(struct rev_info *revs, struct commit *commit)
static struct commit *get_revision_internal(struct rev_info *revs)
		clear_ref_exclusion(&revs->ref_excludes);
static int add_parents_only(struct rev_info *revs, const char *arg_, int flags,
{

			argv_array_pushv(&prune_data, argv + i);
		revs->limited = 1;
			break;


	remove_duplicate_parents(revs, commit);
					REVARG_CANNOT_BE_FILENAME))
	struct merge_simplify_state *st;
	if (revs->diffopt.objfind)
	nth_parent = 0;
	add_object_array_with_path(obj, name, &revs->pending, mode, path);
{
		if (argc <= 1)
		return SLOP;
			 * If this will remain a potentially-simplifiable
	} else if (skip_prefix(arg, "--show-notes=", &optarg) ||
			strbuf_addstr(&buf, message);
					    oid_to_hex(&commit->object.oid),
}
	return 0;
		struct commit *commit = list->item;
		revs->max_parents = 1;
			return;
	 * for us to throw it away.
	ids.diffopts.pathspec = revs->diffopt.pathspec;
		revs->cherry_pick = 1;

static int for_each_good_bisect_ref(struct ref_store *refs, each_ref_fn fn, void *cb_data)
		/*
			commit->object.flags |= TREESAME;

	default: /* REV_SORT_IN_GRAPH_ORDER */
		string_list_clear(*ref_excludes_p, 0);
		revs->topo_order = 1;
		return commit_ignore;
			die("'%s': not a non-negative integer", arg);
				 * paths from this parent, so the
	if (date <= src->item->date)
					  unsigned int flags)
		if (revs->left_only)
	 */
	struct object_id a_oid, b_oid;
					     struct tree *tree)
			if (p->object.flags & SEEN)


			commit = next_topo_commit(revs);
	if (!revs->prune)
					die("cannot simplify commit %s (invalid %s)",
	if (revs->line_level_traverse)
static void add_cache_tree(struct cache_tree *it, struct rev_info *revs,
		return NULL;
		return;
{
struct commit_stack {

	 * grep_buffer may modify it for speed, it will restore any
	cb->all_flags = flags;
		int opts = diff_opt_parse(&revs->diffopt, argv, argc, revs->prefix);
	revs->expand_tabs_in_log = -1;
			continue;
		struct patch_id *id;
	} else if (!strcmp(arg, "--boundary")) {
	}
	obj = &tree->object;
				}

static void init_all_refs_cb(struct all_refs_cb *cb, struct rev_info *revs,
};
static void file_change(struct diff_options *options,

 * important than Y-X, despite both A and Y being flagged UNINTERESTING.
		struct commit *parent = p->item;
	 * If the repository has commit graphs, repo_parse_commit() avoids
			return dotdot_missing(arg, dotdot, revs, symmetric);
	if (revs->commits) {
		if (c->object.flags & TMP_MARK)
}
		if (parent->object.flags & TMP_MARK) {
	} else if (!strcmp(arg, "--early-output")) {
				    buf.buf[0] ? buf.buf: name);
		if (revs->min_age != -1 && (commit->date > revs->min_age))
		 * Have just removed the only parent from a non-merge.
	blob->object.flags |= UNINTERESTING;
	oidset_init(&key.trees, 0);
}
		struct strbuf namemail = STRBUF_INIT;
		break;
}
static void gc_boundary(struct object_array *array)
		add_rev_cmdline_list(revs, exclude, REV_CMD_MERGE_BASE,
		add_header_grep(revs, GREP_HEADER_AUTHOR, optarg);

		return commit_ignore;
	} else if (!strcmp(arg, "-g") || !strcmp(arg, "--walk-reflogs")) {
		add_index_objects_to_pending(revs, *flags);

		else
			die("unable to parse commit %s", name);
	init_tree_desc(&desc, tree->buffer, tree->size);


		return;
	struct tree_desc desc;
			die("cannot simplify commit %s (because of %s)",
		 */

	/*

			       const struct setup_revision_opt* opt)

		 * the parents here. We also need to do the date-based limiting
	if (!refname || !(flags & REF_ISSYMREF) || (flags & REF_ISBROKEN))
		commit = list->item;
			relevant_parents++;

	if (limiting_can_increase_treesame(revs))
	 */
		oidset_clear(&entry->trees);
 * This does not recalculate the master TREESAME flag - update_treesame()
	 * (-1), or it is still counting, in which case we decrement.
	} else if (!strcmp(arg, "--show-notes") || !strcmp(arg, "--notes")) {
	return c;
{
	    !strcmp(arg, "--tags") || !strcmp(arg, "--remotes") ||

				 * history beyond this parent is not
	} else if (!strcmp(arg, "--left-only")) {

		st = lookup_decoration(&revs->treesame, &commit->object);
		revs->show_signature = 1;

	struct commit_list **p = &newlist;

 * object_array_each_func_t.)
	}

}
		/*

	info->rev[nr].flags = flags;

			commit->object.flags &= ~(ADDED | SEEN | SHOWN);
		oidcpy(&oid, &((struct tag*)it)->tagged->oid);
		/* Can't prune commits with rename following: the paths change.. */
	 * several times: once for each appearance in the reflog.
		for (p = commit->parents; p; p = p->next)
	/*
		free_commit_list(exclude);
	obj = parse_object(revs->repo, &oid);
			BUG("--single-worktree cannot be used together with submodule");
	 * it had just taken the I version. With this check, the topology above
	size_t nr, alloc;
				*slot = xstrdup(name);
		commit_list_insert(c, &revs->commits);
	if (c)
	}
			cb->warned_bad_reflog = 1;
	 *
			}
	 * here. However, it may turn out that we've
	if (relevant_parents ? !relevant_change : !irrelevant_change)
	if (!revs->saved_parents_slab)
				break;
			    !(commit->object.flags & UNINTERESTING)) {
}
/*
	    !revs->include_check(commit, revs->include_check_data))
		die("bad tree compare for commit %s", oid_to_hex(&commit->object.oid));
				compact_treesame(revs, commit, surviving_parents);
			BUG("exclude_promisor_objects can only be used when fetch_if_missing is 0");
}


	}
	revs->expand_tabs_in_log_default = 8;
	options->flags.has_changes = 1;
			}

 * Add an entry to refs->cmdline with the specified information.
	/* de-munge so we report the full argument */
		clear_ref_exclusion(&revs->ref_excludes);
	return 0;
	data.flags = flags;
	if (!t2)
	 */
	 * changes before returning.
	struct commit *parent;
	if (!src)
		refs_for_each_reflog(get_worktree_ref_store(wt),
				c = get_revision_1(revs);
	memset(&info->topo_queue, 0, sizeof(info->topo_queue));
	if (bottom) {
			return "<";
#include "commit-reach.h"

		if (!show)
		*(indegree_slab_at(&info->indegree, c)) = 1;

	} else if (!strcmp(arg, "-n")) {
				i += opts - 1;
		return argcount;
			die("update_treesame %s", oid_to_hex(&commit->object.oid));
	 * UNINTERESTING, if it touches the given paths, or if it is a
{
			      &a_oc, &b_oc);
	struct object *object;
			compact_treesame(revs, commit, nth_parent);
		const struct cache_entry *ce = istate->cache[i];
		}
		die("compact_treesame %u", nth_parent);
	struct commit_list *list = orig;
			continue;
	}
		get_commit_format("oneline", revs);
	unsigned has_interesting = 0, has_uninteresting = 0;
	if (!c) {
		return argcount;
	int relevant_parents, nth_parent;

		graph_update(revs->graph, c);
{

				p->parents = NULL;
	 * reasonable result - it presents a logical full history leading from

			continue;

static void simplify_merges(struct rev_info *revs)
	return ret;


		revs->max_age = atoi(optarg);
	 */
	if (commit->parents)
	} else if (skip_prefix(arg, "--expand-tabs=", &arg)) {

			if (revs->max_age != -1 &&
		if (revs->reflog_info)
		init_topo_walk(revs);

	if (!handle_dotdot(arg, revs, flags, revarg_opt))

	const char *arg = argv[0];

	if (revs->reverse_output_stage) {
	revs->skip_count = -1;

	/*
		return opts;
	if (revs->simplify_merges ||
		commit_list = commit_list->next;
	 */
 * in our list), or that is a specified BOTTOM commit. Then after computing

		disable_display_notes(&revs->notes_opt, &revs->show_notes);

		}
	if (!t1)
			/* If we didn't have a "--":
			   struct rev_info *revs, int flags,
		p->item->object.flags &= ~TMP_MARK;
			add_pending_object(revs, object, tag->tag);
	 * Reverse the list so that it will be likely that we would
	struct object *o = parse_object(revs->repo, oid);
		add_pending_object(revs, object, oid_to_hex(&object->oid));

	if (revs->reflog_info && obj->type == OBJ_COMMIT) {
	 * Do we know what commit all of our parents that matter
		revs->tree_objects = 1;
	if (object->type == OBJ_COMMIT) {
	 *    *A-*B           parents.
		set_children(revs);

		if (!c)
		if (process_parents(revs, commit, &list, NULL) < 0)
		if (tree->object.flags & UNINTERESTING)
		struct object_id oid;

		if (!len)
			return error("invalid argument to --no-walk");
}
	append_grep_pattern(&revs->grep_filter, ptn, "command line", 0, what);
	 */
		a = lookup_commit_reference(revs->repo, &a_obj->oid);
#include "commit.h"

	 * Grepping the commit log
		    revs->notes_opt.use_default_notes < 0)
		if (!revs->single_worktree)
	if (!opt->grep_filter.pattern_list && !opt->grep_filter.header_list)
		add_pending_commit_list(revs, exclude, flags_exclude);
 * Parse revision information, filling in the "rev_info" structure,
 *         W---Y
#include "refs.h"
	yet_to_do = NULL;
{
		a_flags = flags | SYMMETRIC_LEFT;
				continue;
	try_to_simplify_commit(revs, commit);
			return NULL;

static void add_header_grep(struct rev_info *revs, enum grep_header_field field, const char *pattern)

			c->object.flags |= SHOWN;
	refs_for_each_reflog_ent(get_main_ref_store(the_repository),
	for (p = commit->parents; p; p = p->next) {
		if (!tree)
		free(entry->path);
		return;
	}
	fputs(mark, stdout);

	clear_prio_queue(&queue);
	const char *path = entry->path;
	while (list) {

	}
	}
				next = commit_list_append(commit, next);
		return 0;

{
{
	 * Further, a merge of an independent branch that doesn't
			paths_and_oids_insert(map, entry.path, &entry.oid);
{
		if (parse_commit(p) < 0)
	 * Tree object? Either mark it uninteresting, or add it
		if (handle_revision_arg(arg, revs, flags, revarg_opt)) {
	unsigned int flags;
			die("options not supported in --stdin mode");
}
#include "repository.h"
#include "tag.h"
	if (revs->prune_data.nr) {
		/*
	} else if (!strcmp(arg, "--full-diff")) {
		while ((c = get_revision_internal(revs)))

	struct object *it;
	 * activate, and we _do_ drop the default parent. Example:
		create_boundary_commit_list(revs);


		struct object *p;
		revs->topo_order = 1;
	object->flags |= flags;
			commit = pop_commit(&revs->commits);
		made_progress = 0;
	 * boundary commits anyway.  (This is what the code has always
	strbuf_init(&sb, 1000);
static void add_pending_object_with_mode(struct rev_info *revs,
		 unsigned old_dirty_submodule, unsigned new_dirty_submodule)

	    revs->prune && revs->dense && want_ancestry(revs)) {
	free_patch_ids(&ids);
	 *
		seen_dashdash = 1;

		revs->abbrev_commit = 0;
	 * TREESAME parent from the default, in which case this test doesn't
		handle_refs(refs, revs, *flags, refs_for_each_branch_ref);
		/*
	struct object *object;
			if (commit->object.flags & SYMMETRIC_LEFT)
			 int cant_be_filename)
		revs->full_diff = 1;
		}
	 * simplified full history. Retaining it improves the chances of
	if (!cant_be_filename) {

		struct commit_list *p;
	/*
		revs->first_parent_only = 1;
static int leave_one_treesame_to_parent(struct rev_info *revs, struct commit *commit)
int prepare_revision_walk(struct rev_info *revs)
		if (!revs->limited)
		 * If we have fewer left, left_first is set and we omit
	 * into revs->commits
		if ((p = one_relevant_parent(revs, p->parents)) == NULL)
			return 0;
			if (revs->reflog_info)
		/*
		*pp = p;

	struct hashmap_iter iter;
			 */
	merge_queue_into_list(&queue, &revs->commits);
		revs->diffopt.flags.recursive = 1;
			struct commit_list *p;

	struct path_and_oids_entry *entry;
		if (!wildmatch(item->string, path, 0))
	 * Does the destination list contain entries with a date
	struct commit_list *list = revs->commits;
		clear_ref_exclusion(&revs->ref_excludes);
}
		return;
				commit_list_insert_by_date(p, list);
	case REV_SORT_BY_COMMIT_DATE:
	}

		revs->left_only = 1;

	} else if (opt && opt->allow_exclude_promisor_objects &&
{
		/* this could happen with uninitialized submodules */
}

			interesting_cache = NULL;
	if (mark) {
	} else if (skip_prefix(arg, "--abbrev=", &optarg)) {
	/* First, search for "--" */
}
		/*
		for (list = newlist; list; list = list->next) {
	revs->commit_format = CMIT_FMT_DEFAULT;
		for (i = 1; i < argc; i++) {
	if (revs->simplify_by_decoration) {
}

 * treated as part of the graph. For example:
		 *	call init_pathspec() to set revs->prune_data here.
		*ref_excludes_p = xcalloc(1, sizeof(**ref_excludes_p));
		 */
		 */
				 */
	return (revs->rewrite_parents || revs->children.name);
		revs->max_count = atoi(optarg);
			*mark = '^';
		info->topo_queue.compare = NULL;
		verify_non_filename(revs->prefix, arg);


		entry->path = xstrdup(key.path);
{
}
	} else if (!strcmp(arg, "--no-encode-email-headers")) {

		p->flags |= CHILD_SHOWN;
			add_child(revs, p->item, commit);

				    const struct object_id *oid,
	 * It is possible that we are a merge and one side branch
	 * Tag object? Look what it points to..
		revs->exclude_promisor_objects = 1;
			/*
		add_rev_cmdline(revs, it, arg_, REV_CMD_PARENTS_ONLY, flags);
define_commit_slab(indegree_slab, int);
			i++;
			die("unable to add index blob to traversal");

			return -1;
	    !strcmp(arg, "--bisect") || starts_with(arg, "--glob=") ||

	mark = strstr(arg, "^@");
		revs->blob_objects = 1;
	if (revs->first_parent_only || !orig->next)
			prio_queue_put(&info->topo_queue, parent);
			prune[prune_num-2] = ce->name;
	} else if ((argcount = parse_long_opt("grep-reflog", argv, &optarg))) {
	}
			 * TREESAME here.
			return NULL;
	} else if (!strcmp(arg, "--no-standard-notes")) {

/*
			continue;
			} else
			revs->abbrev = hexsz;

	}
static struct commit_list *collect_bottom_commits(struct commit_list *list)

		die("cannot combine --reverse with --graph");

	if (revarg_opt & REVARG_COMMITTISH)

		revs->limited = 1; /* needs limit_list() */
	 * it? Definitely not done..
{
			commit = next_reflog_entry(revs->reflog_info);
{
					marked = p->item;
				    worktree_git_path(wt, "index"),

		if (revs->max_age != -1 && (commit->date < revs->max_age))
		for (p = rlist; p; p = p->next) {

	commit->object.flags |= UNINTERESTING;

	struct commit_list **pp;
	    (commit->object.flags & UNINTERESTING) ||
		local_flags = UNINTERESTING | BOTTOM;
	if (revs->reverse && revs->graph)
		return argcount;
			continue;
	do_add_index_objects_to_pending(revs, revs->repo->index, flags);
		add_reflogs_to_pending(revs, *flags);
		add_pending_object_with_path(revs, &tree->object, "",
			die("'%s': not a non-negative integer", optarg);
		}
{
	if (!cnt ||
					ts->treesame[0] = 1;
{

		if (S_ISGITLINK(ce->ce_mode))
	struct treesame_state *st;
		return;
	add_pending_oid(cb->all_revs, path, oid, cb->all_flags);
	for (l = commit->parents; l; l = l->next)
	    (parent = one_relevant_parent(revs, commit->parents)) == NULL ||
	strbuf_release(&sb);
	return 0;
	if (cnt) {

			i++;
		case OBJ_TREE:

		info->topo_queue.cb_data = &info->author_date;
			     struct commit **interesting_cache)
	 * affect our TREESAME flags in any way - a commit is
		add_children_by_path(r, tree, &map);
			if (c->object.flags & (TMP_MARK | UNINTERESTING))
	struct object_array_entry *objects = array->objects;
			die("compact_treesame %u", nth_parent);
enum commit_action simplify_commit(struct rev_info *revs, struct commit *commit)
		for_each_glob_ref_in(handle_one_ref, optarg, "refs/heads/", &cb);
	struct worktree **worktrees, **p;
		struct commit *c = list->item;

	if (get_oid_with_context(revs->repo, a_name, oc_flags, &a_oid, a_oc) ||
}
		if (revs->left_only)

	}
{
	if (buf.len)
	namelen = ident.name_end - ident.name_begin;
	}

	 * is retained.

		get_commit_format(NULL, revs);
	} else if (!strcmp(arg, "--alternate-refs")) {
	}
			return 0;


		default:
		 *
	for (p = commit->parents; p; p = p->next) {
		switch (simplify_commit(revs, commit)) {
			;

		revs->show_merge = 1;
		revs->saved_parents_slab = xmalloc(sizeof(struct saved_parents));
	}
				continue;
 * coming from outside the graph, (ie from irrelevant parents), and treat
		return;
		revs->single_worktree = 1;
	 * if first_parent_only is set, then the TREESAME flag is locked
	struct commit *simplified;
	 * so we will not end up with a buffer that has two different encodings
	list = revs->commits;
				     handle_one_reflog,
	return surviving_parents;
	struct treesame_state *ts = lookup_decoration(&revs->treesame, &commit->object);
	revs->pruning.change = file_change;
		return argcount;
			if (!want_ancestry(revs))
 * should be called to update it after a sequence of treesame[] modifications
	init_grep_defaults(revs->repo);
	char *person, *endp;
	/* Did the user ask for any diff output? Run the diff! */

		revs->grep_filter.pattern_type_option = GREP_PATTERN_TYPE_PCRE;
		 * }
			if (tree->object.flags & UNINTERESTING) {
		return argcount;
		switch (rev_compare_tree(revs, p, commit)) {

	/*
		revs->max_count = atoi(argv[1]);

	/*
}
	/* use a shallow copy for the lookup */
	if (revs->left_only || revs->right_only)
	 * if simplify_history is set, we can't have a mixture of TREESAME and
		surviving_parents++;
	}
	}
		}

		st->simplified = commit;
				relevant_change |= !st->treesame[n];
	 * to mark its parents recursively too..

	 */
			die("'%s': not a non-negative integer", arg + 1);
	 */
					break;


			commit->parents = parent;
{
	add_rev_cmdline(revs, b_obj, b_name, REV_CMD_RIGHT, b_flags);
		if (flags & BOUNDARY)
{

			record_author_date(&info->author_date, c);
	while (tree_entry(&desc, &entry)) {
{
		revs->simplify_history = 0;
}
}

{
		   !strcmp(arg, "--exclude-promisor-objects")) {
				prio_queue_put(queue, p);

	 */
		else


	struct argv_array prune_data = ARGV_ARRAY_INIT;
		revs->diffopt.prefix = prefix;
		}

		struct commit *parent = p->item;
	const char *message;
		gc_boundary(&revs->boundary_commits);
		return argcount;
	 * const because it may come from the cached commit buffer. That's OK,
		if (parse_commit_gently(c, 1))
		commit_list_sort_by_date(&revs->commits);
		 * is used later in this function.
	struct ref_store *refs;
	a_name = arg;
{
	 * Limitations on the graph functionality
	if (!person)
			mark_blob_uninteresting(lookup_blob(r, &entry.oid));
	memset(info, 0, sizeof(struct topo_walk_info));
	c = prio_queue_get(&info->topo_queue);
		die("bad object %s", name);
		limit_left_right(newlist, revs);
	if (revs->ancestry_path) {
	int i, flags, left, seen_dashdash, got_rev_arg = 0, revarg_opt;
		*mark = 0;
		revs->simplify_merges = 1;
	} else if (!strcmp(arg, "--no-walk")) {
		 * } else {
		case REV_TREE_DIFFERENT:
	head->object.flags |= SYMMETRIC_LEFT;
	add_rev_cmdline(data->revs, obj, name, REV_CMD_REV, data->flags);
{
	if (!unmarked && marked) {
 * Must be called immediately after removing the nth_parent from a commit's
 * When computing "A..B", the A-X connection is at least as important as

	int seen_dashdash = 0;
		if (sb.buf[0] == '-') {
#define COMMIT_STACK_INIT { NULL, 0, 0 }
			struct commit *c = list->item;

	 * becoming UNINTERESTING.
	unsigned n = commit_list_count(commit->parents);
 * a limited list, during processing we can generally ignore boundary merges
				struct blob *child = lookup_blob(r, &entry.oid);
	 */
	}
void add_pending_object(struct rev_info *revs,

			object = NULL;
	int save_warning;
 */
			commit->object.flags &= ~TREESAME;

/*
			 * is enabled, so do not mark the object as
	if (revs->reverse) {
	} else if (skip_prefix(arg, "--remotes=", &optarg)) {
		 * Just ".."?  That is not a range but the

			die("--right-only is incompatible with --left-only");
	return 1;
	} else {
		read_bisect_terms(&term_bad, &term_good);
	}
	 * Note that we cast away the constness of "message" here. It is
			do_add_index_objects_to_pending(revs, &istate, flags);
	    !strcmp(arg, "--no-walk") || !strcmp(arg, "--do-walk") ||
		else if (flags & SYMMETRIC_LEFT)
		die("--merge without HEAD?");
}
	char *path;
		c = (struct commit *)(objects[i].item);
 * we don't care if we were !TREESAME to non-graph parents.
void add_pending_oid(struct rev_info *revs, const char *name,
	} else if ((argcount = parse_long_opt("since", argv, &optarg))) {
		revs->diffopt.flags.recursive = 1;
	struct object_context a_oc, b_oc;
	add_pending_object_with_path(revs, b_obj, b_name, b_oc->mode, b_oc->path);
		enable_ref_display_notes(&revs->notes_opt, &revs->show_notes, optarg);

static void NORETURN diagnose_missing_default(const char *def)
	} else if (starts_with(arg, "--unpacked=")) {

		if (!blob)

		}
		}
			    oideq(&p->item->object.oid, &commit->object.oid))
	if (action == commit_show &&

	/* pseudo revision arguments */

		strbuf_splice(buf, ident.name_begin - buf->buf,
				  void *vdata)
	if (*pp)
		 * will show spurious changes from the commits that
		add_header_grep(revs, GREP_HEADER_COMMITTER, optarg);
			die("Failed to traverse parents of commit %s",
		if (!parent->parents && (parent->object.flags & TREESAME)) {
	}
			relevant = commit;

	tail = &revs->commits;
	 * We don't care about the tree any more

			    oid_to_hex(&commit->object.oid));
	 * 'c', we need to mark its parents that they could be boundaries.
			opts = handle_revision_pseudo_opt(submodule,
		unsigned flags = commit->object.flags;
	}
		commit_rewrite_person(&buf, "\ncommitter ", opt->mailmap);
/*
	struct path_and_oids_entry *entry;
	} else if (skip_prefix(arg, "--show-linear-break=", &optarg)) {
			*pp = parent->next;
	struct commit *c;
	}
	/*
}
	unsigned cherry_flag;
	return slop-1;
				ts = initialise_treesame(revs, commit);
 */
	add_pending_object(data->revs, obj, name);
	 * Normally we haven't parsed the parent
	free(a_oc.path);
		mark_one_parent_uninteresting(commit_stack_pop(&pending),
	} else if (!strcmp(arg, "--branches")) {
	/*
			init_all_refs_cb(&cb, revs, *flags);
		if (*pi == 1)
		revs->abbrev = 0;
	if (opt->show_notes) {
}

				continue;
		clear_ref_exclusion(&revs->ref_excludes);
			die("bad object %s", oid_to_hex(&tag->tagged->oid));
static void track_linear(struct rev_info *revs, struct commit *commit)
	clear_prio_queue(&info->topo_queue);
		pp = &p->next;

	 * If we have only one relevant parent, then TREESAME will be set purely
	 * (the first two cases are already handled at the beginning of

	struct tree_desc desc;
		struct commit *c = p->item;
	unsigned int oc_flags = GET_OID_COMMITTISH | GET_OID_RECORD_PATH;
	for (p = c->parents; p; p = p->next)
	    (revs->diffopt.output_format & ~(DIFF_FORMAT_PATCH | DIFF_FORMAT_NO_OUTPUT)))
		copy_pathspec(&revs->pruning.pathspec, &revs->prune_data);
				relevant_change = 1;
{
	cb->wt = NULL;
	 */
}
static int everybody_uninteresting(struct commit_list *orig,
		break;

	if (revs->max_count) {
		struct tree *tree = lookup_tree(r, oid);
static int dotdot_missing(const char *arg, char *dotdot,
}
	if (removed && !(commit->object.flags & TREESAME))
}
		struct blob *blob;
		 * We'll handle the tagged object by looping or dropping
	struct treesame_state *ts = NULL;
		parse_date_format(optarg, &revs->date_mode);
 */
	revs->commits = NULL;
		revs->notes_opt.use_default_notes = 1;


			     const struct hashmap_entry *eptr,
			die("--left-only is incompatible with --right-only"
 *

			for (n = 0, p = commit->parents; p; p = p->next)
		if (!bottom)

		return argcount;
static void add_children_by_path(struct repository *r,
	struct commit_list **next = &revs->commits;
		}
		/*
{
 * remove_empty_trees is in effect, in which case we care only about
	paths_and_oids_init(&map);
		} else {

		it = &parents->item->object;
{
	unuse_commit_buffer(commit, message);

	const char *refname;
	clear_pathspec(&revs->prune_data);
	     pp = &parent->next, nth_parent++) {
	warn_on_object_refname_ambiguity = 0;
{
		 * Different handling, as we lack decoration.
		struct all_refs_cb cb;
		if (get_oid_with_context(revs->repo, revs->def, 0, &oid, &oc))
		revs->combine_merges = 1;
	struct tree *t1 = get_commit_tree(parent);
			marked++;
		return;
			return rewrite_one_ok;
	commit_stack_clear(&pending);
		revs->grep_filter.pattern_type_option = GREP_PATTERN_TYPE_ERE;
		}
	worktrees = get_worktrees(0);
			continue;
		else
				if (revs->read_from_stdin++)
		int val;
	struct commit_stack pending = COMMIT_STACK_INIT;
		if (get_name_decoration(&commit->object))
		die("--merge without MERGE_HEAD?");
			o->flags |= cb->all_flags;
		show_early_output = NULL;
			return REV_TREE_DIFFERENT;
		}
			   struct object_context *b_oc)
	} else if (!strcmp(arg, "--sparse")) {
					child->object.flags |= UNINTERESTING;
		return;
					      &pending);
		list = list->next;
#include "packfile.h"
			if (!revs->topo_order || !generation_numbers_enabled(the_repository))
	if (*b_name == '.') {
}
	} else if (!strcmp(arg, "--in-commit-order")) {
	}
/*
static int for_each_bad_bisect_ref(struct ref_store *refs, each_ref_fn fn, void *cb_data)
		}
			continue;

}
	if (!revs->dense && !commit->parents->next)
	int i;
	} else if (!strcmp(arg, "--show-linear-break")) {
	const char *optarg;
			struct all_refs_cb cb;
	char *mark;
		c = get_revision_1(revs);
				  const struct object_id *oid)
	struct object_array *array = &revs->boundary_commits;
	}
	} else if (!strcmp(arg, "--no-abbrev-commit")) {
			diagnose_missing_default(revs->def);
	 *  ----o----X		X: the commit we are looking at;
		return;
	int cant_be_filename = revarg_opt & REVARG_CANNOT_BE_FILENAME;
static void add_other_reflogs_to_pending(struct all_refs_cb *cb)
		else
static void explore_to_depth(struct rev_info *revs,
	die(_("your current branch '%s' does not have any commits yet"),
		revs->no_walk = REVISION_WALK_NO_WALK_SORTED;
		entry = xcalloc(1, sizeof(struct path_and_oids_entry));
			*mark = '^';
{
	const char **prune = NULL;
			    " or --cherry");

		if (marked)

	}

{
		return;
static void add_pending_object_with_path(struct rev_info *revs,
		 * If we need to introduce the magic "a lone ':' means no
	info->indegree_queue.compare = compare_commits_by_gen_then_commit_date;
	int n = handle_revision_opt(revs, ctx->argc, ctx->argv,
		revs->grep_filter.debug = 1;

	}
		if (!revs->full_diff)
			}
		relevant_change = irrelevant_change = 0;
		argv_array_push(prune, sb->buf);
			 * we "divert" the history walk to the later
		return tail;
		revs->diff = 1;
	}
static int tree_difference = REV_TREE_SAME;
	argv_array_clear(&prune_data);
	if (oid_object_info(revs->repo, oid, NULL) == OBJ_COMMIT) {
 * Return true for entries that have not yet been shown.  (This is an
{

	} else if (revs->graph)
		revs->no_commit_id = 1;

	struct name_entry entry;
			}
	return 0;
		commit->object.flags |= cherry_flag;
	return stack->nr ? stack->items[--stack->nr] : NULL;
	if (mark && !mark[2]) {
	struct patch_ids ids;
		else if (!strcmp(optarg, "unsorted"))
		 * Update revs->commits to contain the list of
	encoding = get_log_output_encoding();
}
		error("unknown option `%s'", ctx->argv[0]);
	unsigned get_sha1_flags = GET_OID_RECORD_PATH;
		 * supported right now, so stick to single worktree.
	while (q->nr) {
	/* Examine existing parents while marking ones we have seen... */
{

			int n;
		 */
	while (commit_list) {
	}
		revs->min_parents = 0;
			}
static void save_parents(struct rev_info *revs, struct commit *commit)

		return 0;

			git_log_output_encoding = "";
}


	unsigned int nparents;
	enum commit_action action = get_commit_action(revs, commit);

	struct commit_list **pp = &commit->parents;
	{
		 * before we can go through all worktrees of a submodule,
	if (!t1)
				 * side branch brought the entire change

		else
	if (obj->flags & UNINTERESTING)
			 * to treat bottom commit(s) as part of the topology.
		case OBJ_TREE:
		explore_walk_step(revs);
}
			 */
 *
	} else if (!strcmp(arg, "--tags")) {
	}
		for (p = commit->parents, n = 0; p; n++, p = p->next) {
		return c;
			continue;
	revs->grep_filter.status_only = 1;
		 */
static int commit_match(struct commit *commit, struct rev_info *opt)
		if (marked)
		revs->diff = 1;
				continue;
		struct commit_list *p;
	while (1) {
	if (revs->saved_parents_slab)
	} else if (!strcmp(arg, "--graph")) {
		commit_list = commit_list->next;
		return 0;
	struct commit *c = NULL;

	add_rev_cmdline(revs, a_obj, a_name, REV_CMD_LEFT, a_flags);
		revs->diff = 1;
		tail = &commit_list_insert(commit, tail)->next;
	add_rev_cmdline(cb->all_revs, object, path, REV_CMD_REF, cb->all_flags);
				expand_topo_walk(revs, commit);
	 * (and multiple irrelevant ones), then we can't select a parent here
static enum rewrite_result rewrite_one_1(struct rev_info *revs,
static void mark_blob_uninteresting(struct blob *blob)
}
	} else if (!strcmp(arg, "--default")) {
	if (st->simplified)
		revs->tag_objects = 1;

					die("Failed to traverse parents of commit %s",
	    refname);

	/*
			has_uninteresting = 1;
		}
			}
	struct hashmap map;
	struct commit_list *p;
}

{
			continue;
		if (!revs->single_worktree) {
	e2 = container_of(entry_or_key, const struct path_and_oids_entry, ent);
};
			else if (revs->topo_walk_info)
		add_pending_object_with_path(revs, &blob->object, "",
	clear_author_date_slab(&info->author_date);
static void indegree_walk_step(struct rev_info *revs)
			cnt = remove_marked_parents(revs, commit);
			if (!nth_parent)
	return nth_parent;
				 struct commit_list *commit_list,
		return revs->ignore_missing ? 0 : -1;
	 * parents, then we only consider TREESAMEness with respect to them,
		info->topo_queue.compare = compare_commits_by_commit_date;
		case rewrite_one_noparents:
	 * in the order given from the revision traversal machinery.
	if (get_oid("HEAD", &oid))
		}
 * of B but not ancestors of A but further limits the result to those
#include "line-log.h"
				     struct argv_array *prune)
	} else if (!strcmp(arg, "--ignore-missing")) {
}
	init_display_notes(&revs->notes_opt);
	return bottom;
	if (it->type != OBJ_COMMIT)

	 *
			commit = pop_commit(&list);
	string_list_append(*ref_excludes_p, exclude);
			int j;

	free_worktrees(worktrees);
		}
		struct commit *c = lookup_commit(revs->repo, oid);
				if (child)
	int surviving_parents;
			return 0;
{
		strbuf_addstr(&buf, message);
		revs->abbrev = strtoul(optarg, NULL, 10);
			 struct rev_info *revs, int flags,
		die("mark_redundant_parents %d %d %d %d", orig_cnt, cnt, i, marked);
	for (list = revs->commits; list; list = list->next) {
		 */
		refs = get_main_ref_store(revs->repo);
	/* Want these for sanity-checking only */

		struct all_refs_cb cb;
	 * yet, so we won't have a parent of a parent
		if (!ce_stage(ce))
		}
 * REV_TREE_DIFFERENT (of course if the trees are the same we
		init_all_refs_cb(&cb, revs, *flags);
	 * ---o----'
			break;
	else if (revs->cherry_mark)
			argv[i] = NULL;
	return ret;
				 int whence,
			const char *arg = argv[i];
		revs->remove_empty_trees = 1;
			compute_indegrees_to_depth(revs, info->min_generation);
		get_reflog_timestamp(revs->reflog_info) :
				continue;
	 * In this case, save_parents() will be called multiple times.
			/*
	struct rev_info *revs;
		handle_refs(refs, revs, *flags, refs_for_each_tag_ref);
		parse_pathspec(&revs->prune_data, 0, 0,
		 * If we haven't done the list limiting, we need to look at
	} else if (!strcmp(arg, "--reflog")) {
	while (list) {
	c = get_revision_internal(revs);
		revs->invert_grep = 1;
		revs->topo_order = 1;
	if (get_oid("HEAD", &oid))
	} else if (!strcmp(arg, "--abbrev")) {

	struct prio_queue explore_queue;
	return strcmp(e1->path, e2->path);
		default:
	 */
	    !(commit->object.flags & TREESAME) ||
		revs->show_notes_given = 1;
			return;
	 * list to distinguish it from a not-yet-saved list, however.
	 */
		if (commit->object.flags & UNINTERESTING)
	int ret;
 */
		cnt = remove_duplicate_parents(revs, commit);
		 * switch to boundary commits output mode.
	} else if (!strcmp(arg, "--pretty")) {
{
			if (!(commit->object.flags & SYMMETRIC_LEFT))

		    const struct object_id *oid,
			continue;
				if (!marked)
			    int exclude_parent)

	po = commit->parents;
struct topo_walk_info {
	repo_diff_setup(revs->repo, &revs->diffopt);
		struct strbuf buf = STRBUF_INIT;
	struct commit *c;
static timestamp_t comparison_date(const struct rev_info *revs,
		 * fewer right, we skip the left ones.
	const struct path_and_oids_entry *e1, *e2;
	/* Append "fake" message parts as needed */
	struct commit **items;
		}
}
static void limit_left_right(struct commit_list *list, struct rev_info *revs)
		    ((revs->max_parents >= 0) && (n > revs->max_parents)))
		tree->object.flags |= flags;
{

	 *
	 *
}
}
{
static void limit_to_ancestry(struct commit_list *bottom, struct commit_list *list)

		while (list) {
			 * Do not compare with later parents when we care only about
	info->rev[nr].whence = whence;
		commit->date;
		b_flags = flags;
				struct tree *child = lookup_tree(r, &entry.oid);
	    !strcmp(arg, "--reflog") || !strcmp(arg, "--not") ||
	putchar(' ');
	 */
	struct object_id oid;
		free_commit_list(revs->commits);
	if (revs->min_parents || (revs->max_parents >= 0)) {
	if (submodule) {
			if (relevant_commit(p->item)) {

		revs->track_linear = 1;
		if (!revs->diffopt.flags.follow_renames)
	}
			free(p);
	cherry_flag = revs->cherry_mark ? PATCHSAME : SHOWN;
	revs->diffopt.abbrev = revs->abbrev;
/*
	 */
}
 * want REV_TREE_SAME).

	}
static void cherry_pick_list(struct commit_list *list, struct rev_info *revs)
	} else if (!strcmp(arg, "--no-show-signature")) {
	struct rev_cmdline_info *info = &revs->cmdline;
}
			other_head_refs(handle_one_ref, &cb);


			 */
				i += opts - 1;
		else {
		 */
		/* A...B -- find merge bases between the two */
		struct worktree *wt = *p;
		revs->prune = 1;
	revs->pruning.flags.has_changes = 0;
	return opt->invert_grep ? !retval : retval;
 *
 * If array is on the verge of a realloc, garbage-collect any entries
	} else if (skip_prefix(arg, "--no-walk=", &optarg)) {
		struct commit *commit = *interesting_cache;
	if (!c)
		die("cannot combine --reverse with --walk-reflogs");
			*pp = p->next;
	while (yet_to_do) {
			die("compact_treesame parents mismatch");
	int old_same;
	 * might do a considerable amount of work finding the next commit only
		revs->diff = 1;
		struct cache_entry *ce = istate->cache[i];
			if (!strcmp(arg, "--stdin")) {
	for (l = c->parents; l; l = l->next) {
		po=po->next;

#include "decorate.h"
		arg++;

}
		revs->diff = 1;
		struct commit *parent = p->item;
	}
					continue;
			if (!revs->simplify_history || !relevant_commit(p)) {
	} else if (!strcmp(arg, "--fixed-strings") || !strcmp(arg, "-F")) {
	}
		switch (rewrite_parent(revs, &parent->item)) {
		revs->rewrite_parents = 1;
		revs->combine_merges = 1;
				 unsigned flags)
		return -1;
void repo_init_revisions(struct repository *r,

		strbuf_addstr(&buf, "reflog ");
	if (object->type == OBJ_TREE) {

}
}
		reset_topo_walk(revs);
	struct all_refs_cb *cb = cb_data;

			     revs->exclude_promisor_objects;
		show_early_output_fn_t show;

		handle_refs(refs, revs, *flags ^ (UNINTERESTING | BOTTOM),
	if (prune_data.argc) {
	}
	} else if (skip_prefix(arg, "--pretty=", &optarg) ||
					 const char *path)
}
		revs->track_linear = 1;
	if (commit->object.flags & BOUNDARY)
static int remove_duplicate_parents(struct rev_info *revs, struct commit *commit)
		if (!a || !b)
	 * process parents before children.
	 *         r		r: a root commit not touching the paths
			for (j = i; j < argc; j++)
	if (!st || nth_parent >= st->nparents)
	 *
{
	obj = get_reference(data->revs, name, oid, data->flags);
{
		if (!revs->tree_objects)
	return commit->object.flags & TREESAME;
		revarg_opt |= REVARG_CANNOT_BE_FILENAME;
{
	}
			 * but the latter we have checked in the main loop.
		if (!buf.len)
		revs->show_notes_given = 1;
		revs->tree_objects = 1;
	int cnt = commit_list_count(h);

			    oid_to_hex(&commit->object.oid),
		if (elem->item->object.flags & BOTTOM)
}
	}
		revs->show_log_size = 1;
	if (revs->reverse && revs->reflog_info)
		revs->min_parents = atoi(optarg);
{
	else

					 const char *name, unsigned mode,
	if (revs->no_walk)
	unsigned i;
{
		clear_ref_exclusion(&revs->ref_excludes);
	       !revs->first_parent_only;
		retval = grep_buffer(&opt->grep_filter,

void add_reflogs_to_pending(struct rev_info *revs, unsigned flags)
			break;
			continue;
		revs->no_walk = 0;
	/*
				track_linear(revs, commit);


		struct all_refs_cb cb;

		a_flags = flags_exclude;
	/*

	 * is the encoding they are most likely to write their grep pattern

 * Return a timestamp to be used for --since/--until comparisons for this
	skip_prefix(refname, "refs/heads/", &refname);
			opts = handle_revision_opt(revs, argc - i, argv + i,
		if (mark[2]) {
			return NULL;
			/* drop merges unless we want parenthood */
			parent->object.flags &= ~TMP_MARK;
	if (parse_commit_gently(c, 1) < 0)
		if (!add_parents_only(revs, arg, flags ^ (UNINTERESTING | BOTTOM), exclude_parent))
	add_pending_object_with_mode(revs, obj, name, S_IFINVALID);
	struct object *obj;
		pp = &p->next;
			    (int)namelen, name, (int)maillen, mail);
	if (!strlen(mark))
	/* Removing parents can only increase TREESAMEness */
		seen_dashdash = 0;
	revs->ignore_merges = 1;
	struct path_and_oids_entry *entry;
}
				if (revs->disable_stdin) {
	info->min_generation = GENERATION_NUMBER_INFINITY;
		revs->limited = 1;
}

	oidset_insert(&entry->trees, oid);
	if ((argcount = parse_long_opt("max-count", argv, &optarg))) {
		 * commits on the right branch in this loop.  If we have
	} else if (!strcmp(arg, "--regexp-ignore-case") || !strcmp(arg, "-i")) {
#include "commit-graph.h"
	} else if ((*arg == '-') && isdigit(arg[1])) {
	while (1) {
	 * Ok, the commit wasn't uninteresting. Try to
	 * touch the path will reduce to a treesame root parent:
	 * unless parse_revision_opt queues them (as opposed to erroring
}
				    (struct commit *)obj,
{
				/* Even if a merge with an uninteresting

/*
	revs->limited = 1;
			 * we're dealing with a merge.
	revs->prefix = prefix;
	 * reachability crud.

			break;
		return 1;
	for (list = revs->commits; list; list = next) {
	old_same = st->treesame[nth_parent];
{
	}
	 * Have we handled this one?
{
		struct tag *tag = (struct tag *) object;
#include "argv-array.h"
		init_author_date_slab(&info->author_date);
int setup_revisions(int argc, const char **argv, struct rev_info *revs, struct setup_revision_opt *opt)
	}
	if (*interesting_cache) {

{
}

		 * Have we seen the same patch id?
		revs->reverse ^= 1;
			 * Initialise the array with the comparison from our
				 struct hashmap *map)
}


		return 0;
	revs->pruning.add_remove = file_add_remove;

		return;
	free_commit_list(rlist);
 * cases:
	int status;
	return 0;
		 * Detached form ("--no-walk X" as opposed to "--no-walk=X")
{
					argv[left++] = arg;
static int handle_revision_opt(struct rev_info *revs, int argc, const char **argv,
static int process_parents(struct rev_info *revs, struct commit *commit,
	}
			got_rev_arg = 1;

		revs->limited = 1;
				verify_filename(revs->prefix, argv[j], j == i);

		free_saved_parents(revs);
			   int cant_be_filename,
		if (p && p->item->date >= item->date)
	repo_read_index(revs->repo);
	struct commit_list *parent = commit->parents;
	/*
	die("%s is unknown object", name);
 * cf mark_treesame_root_parents: root parents that are TREESAME (to an
int handle_revision_arg(const char *arg_, struct rev_info *revs, int flags, unsigned revarg_opt)
 *   ....Z...A---X---o---o---B
	if (*arg == '^') {

		add_reflog_for_walk(revs->reflog_info,
	} else if (!strcmp(arg, "--log-size")) {
	revarg_opt = opt ? opt->revarg_opt : 0;
	}

		}
		case commit_error:
				if (revs->first_parent_only)
	struct commit *interesting_cache = NULL;
	 */
}
			int opts;
	 * When walking with reflogs, we may visit the same commit
 *
	if (commit->object.flags & UNINTERESTING)
	revs->pending.nr = 0;

	struct add_alternate_refs_data data;
	while (strbuf_getline(sb, stdin) != EOF)
		return;
		case REV_TREE_SAME:
				 * IOW, we pretend this parent is a
}
	return tail;
			unkv[(*unkc)++] = arg;
		revs->ignore_merges = 0;
		}
		if (!(p->object.flags & SEEN)) {
	if (c->object.flags & UNINTERESTING)

 * "rev-list --ancestry-path A..B" computes commits that are ancestors

	       c->generation >= gen_cutoff)
			commit_list_insert(c, &reversed);
	} else if (!strcmp(arg, "--unpacked")) {
	}
	} else if (!strcmp(arg, "--date-order")) {
			revs->linear = !!(c && c->object.flags & TRACK_LINEAR);
		read_pathspec_from_stdin(&sb, prune);
		struct commit *p = parent->item;
		test_flag_and_insert(&info->explore_queue, c, TOPO_WALK_EXPLORED);
	}
		 */
	struct commit_list *p;
	struct commit *unmarked = NULL, *marked = NULL;
		revs->boundary = 2;
		    revs->max_count < 0)
	return 0;
			 * TREESAME to its first parent but is TREESAME
				   struct commit *commit)
}
	case REV_SORT_BY_AUTHOR_DATE:
	const char *arg = argv[0];
	 * An UNINTERESTING commit simplifies to itself, so does a
	stack->items[stack->nr++] = commit;
{
	local_flags = 0;
			marked++;
				 * merge, so we just keep going.
		revs->max_age = approxidate(optarg);
{
static void create_boundary_commit_list(struct rev_info *revs)
	struct commit_list *list = orig;
			if (len == 2 && sb.buf[1] == '-') {
static void add_rev_cmdline(struct rev_info *revs,
		int n = commit_list_count(commit->parents);
{
	timestamp_t date = TIME_MAX;
		/*
#include "grep.h"
	 * Not ready to remove items yet, just mark them for now, based
/*
}
	} else if (!strcmp(arg, "--no-expand-tabs")) {
	}
		struct commit *commit = p->item;
	/*
static void add_grep(struct rev_info *revs, const char *ptn, enum grep_pat_token what)
			continue;
	 *     `-*A--'         TREESAME to I and !TREESAME to A.
		struct commit *commit = p->item;
	} else if (!strcmp(arg, "--cherry")) {
		strbuf_release(&buf);
	struct worktree **worktrees, **p;
		 *	terminate prune_data.alloc with NULL and
		add_commit_patch_id(commit, &ids);
		if (!revs->blob_objects)
	while (list) {
	if (revs->no_walk && revs->graph)
	} else if (skip_prefix(arg, "--tags=", &optarg)) {
		}
			break;
		die("cannot combine --walk-reflogs with history-limiting options");
		 */
	 */
		/*
}
{
	 *
	for (list = revs->commits; list; list = list->next) {
{
			 * parent. These commits are shown when "show_pulls"
	if (!has_uninteresting || !has_interesting)
{

		unsigned flags = commit->object.flags;
			obj->flags |= UNINTERESTING;
	for (;;) {
			object = (struct object *) c;
			}
	if (commit->object.flags & UNINTERESTING) {
		if (c) {
		else
	const char *a_name, *b_name;
	/*
		}

		*dotdot = '.';
	left_flag = (commit->object.flags & SYMMETRIC_LEFT);
		revs->verbose_header = 1;
	struct commit_list *reversed;
}
