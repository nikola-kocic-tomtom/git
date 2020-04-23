

	/* Enable recursion indefinitely */

		try_to_follow_renames(old_oid, new_oid, &base, opt);
	GUARD_PATHSPEC(&opt->pathspec, PATHSPEC_FROMTOP | PATHSPEC_LITERAL);
		}
	last->next = p;
 *
			/* t↓,  ∀ pi=p[imin]  pi↓ */
	int i;
	 */
	q->nr = 0;


 * 1)  t < p[imin]  ->  ∀j t ∉ Pj  ->  "+t" ∈ D(T,Pj)  ->  D += "+t";  t↓
	unsigned mode, const struct object_id *oid)
			p = emit_path(p, base, opt, nparent,
			if (tpi_valid) {
			/* same rule as in emitthis */
			if (match == all_entries_not_interesting)
#endif
		 * 1) all modes for tp[i]=tp[imin] should be the same wrt
	while (t->size) {

 */
					tpi_valid ?
		 * diff_queued_diff, we will also use that as the path in
		free(pprev);
 *      Due to this convention, if trees are scanned in sorted order, all
 *
 * 2)  t > p[imin]
		 * to the list and can reuse its memory, leaving it as
 *
 *	Please keep attention to the common D(A,[B]) case when working on the
}
	size_t alloclen = combine_diff_path_size(nparent, len);
		recurse = 1;
}
		strbuf_add(base, path, pathlen);
		pathlen = tree_entry_len(&t->entry);
		int addremove;
		 * the future!
 *     3.2) pi = p[imin]  ->  investigate δ(t,pi)
 * Compare two tree entries, taking into account only path/S_ISDIR(mode),

int diff_tree_oid(const struct object_id *old_oid,

	if (emitthis) {
/*

		    !strcmp(p->two->path, opt->pathspec.items[0].match)) {
	if (opt->flags.recursive && isdir) {
/*
	for (i = 0; i < nparent; ++i)
		/* fixup markings for entries before imin */
		  const char *base_str, struct diff_options *opt)
			else {
			for (i = 0; i < nparent; ++i)

	 */
	struct diff_options diff_opts;
 *	|-|   |--|     |--|
	strbuf_release(&base);
 *
	 * We should reject wildcards as well. Unfortunately we
					done = 0;
 *	 .     .        .
		 * allocated (for faster realloc - we don't need copying old data).
			path[0] = p->one->path;
	if ((nr) <= 2) \
 *	D(T,P1...Pn)	- combined diff from T to parents P1,...,Pn
 *	nparent must be > 0.
 *
 * NOTE empty (=invalid) descriptor(s) take part in comparison as +infty,
		/* t < p[imin] */
				for (i = 0; i < nparent; ++i) {
		if ((p->status == 'R' || p->status == 'C') &&
	repo_diff_setup(opt->repo, &diff_opts);
/*
 *
			skip_uninteresting(&t, base, opt);
				}
				  struct strbuf *base, struct diff_options *opt)
		}
			/* D += {δ(t,pi) if pi=p[imin];  "+a" if pi > p[imin]} */
}
 *
static inline void update_tp_entries(struct tree_desc *tp, int nparent)
			update_tp_entries(tp, nparent);
			const struct object_id *oid_i;
		 *
	for (i = 0; i < q->nr; i++) {
{
	p->path[len] = 0;

	if (!t1->size)
 */
 *     in any case t↓  ∀ pi=p[imin]  pi↓


	}
 * 3 cases on how/when it should be called and behaves:

 * D(T,P1...Pn) calculation scheme
	assert(t || tp);
	else if (!t2->size)
		/*
			    const struct object_id *new_oid,
		p->next = (struct combine_diff_path *)(intptr_t)alloclen;
		for (i = 0; i < nparent; ++i) {
 * generate paths for combined diff D(sha1,parents_oid[])
	choice = q->queue[0];
 *	|.|   |. |     |. |
	phead.next = NULL;
/*

		 */

 */
}

	return retval;
			}
	opt->found_follow = 0;
 *              ->  D += ⎨
 *

			 * rename information.
					if (tp[i].entry.mode & S_IFXMIN_NEQ)
 *	| |   |  |     |  |
 *
			update_tree_entry(&t);
	oidcpy(&p->oid, oid ? oid : &null_oid);
 *	D(T,Pj)		- diff between T..Pj
	if (p->mode && p0->mode) {
 *      |
		skip_emit_tp:
	struct combine_diff_path *p;
			}
	}
			unsigned mode_i;
	int pathlen;
				t->size = 0;
		tptree[i] = fill_tree_descriptor(opt->repo, &tp[i], parents_oid[i]);
	 * original one, or the rename/copy we found)
 * We start from all trees, which are sorted, and compare their entries in
 *	|-|   |--| ... |--|      imin = argmin(p1...pn)
				       PATHSPEC_ALL_MAGIC & ~PATHSPEC_LITERAL,
{
		int imin, cmp;
 *	p->next = NULL;
	 *   diff_tree_oid(parent, commit) )
	struct combine_diff_path *p, const struct object_id *oid,


		return t2->size ? 1 : 0;
 * and append it to paths list tail.
	}
 *      the same name - thanks to base_name_compare().
	q->queue[0] = choice;
	e2 = &t2->entry;
				!t ? DIFF_STATUS_DELETED :
 * NOTE
				       PATHSPEC_LITERAL_PATH, "", path);
 */

				skip_uninteresting(&tp[i], base, opt);
	strbuf_setlen(base, old_baselen);
 *
			p->parent[i].mode = mode_i;
		}
} while(0)
					&t, /*tp=*/NULL, -1);
			else {
						goto skip_emit_tp;

 *
 * p->parent[] remains uninitialized.
	/* Go through the new set of filepairing, and see if we find a more interesting one */

	struct strbuf *base, struct diff_options *opt, int nparent,

			break;
	return p;
	int i;
	 * free pre-allocated last element, if any
	unsigned short mode;
 *
		imin = 0;
	/*

			update_tree_entry(&t);
 * Schematic deduction of what every case means, and what to do, follows:
{
			oid = &p0->oid;
	return 0;
	 */
		for (i = 1; i < nparent; ++i) {
 *
	FAST_ARRAY_ALLOC(tp, nparent);
			 * it makes to sort the renames out (among other
 * The paths are generated scanning new tree and all parents trees
 *
	}
 * Memory for created elements could be reused:
static int ll_diff_tree_oid(const struct object_id *old_oid,

				}
 * we will update/use/emit entry for diff only with it unset.
 *  - not a valid previous file
 *	code, in order not to slow it down.
		 * On the other hand, if path needs to be kept, we need to
		free((x)); \

 *
		struct combine_diff_path *pprev = p;
 *	 -     -        -
struct combine_diff_path *diff_tree_paths(
		if (opt->pathchange)
		 * Found a source? Not only do we use that for the new
	int retval;

int diff_root_tree_oid(const struct object_id *new_oid, const char *base, struct diff_options *opt)
		const struct object_id *oid;

		strbuf_addch(base, '/');
{
			/* ∀ pi=p[imin]  pi↓ */
	return cmp;
	cmp = base_name_compare(e1->path, tree_entry_len(e1), e1->mode,

		/* path present in resulting tree */
			 * The caller expects us to return a set of vanilla

static int ll_diff_tree_oid(const struct object_id *old_oid,
						DIFF_STATUS_MODIFIED :
	/* at least something has to be valid */
	int nparent, const struct strbuf *base, const char *path, int pathlen,
		if (!t.size) {
	retval = ll_diff_tree_oid(old_oid, new_oid, &base, opt);
 * - if you do need to keep the element
	for (;;) {
	if (t) {
		else {
 *
			    struct strbuf *base, struct diff_options *opt);
 *     3.1) ∃j: pj > p[imin]  ->  "+t" ∈ D(T,Pj)  ->  only pi=p[imin] remains to investigate
#define FAST_ARRAY_ALLOC(x, nr) do { \
		else
	return p;

			    struct strbuf *base, struct diff_options *opt)
				e2->path, tree_entry_len(e2), e2->mode);
 *	  The memory is then reused from p.
	e1 = &t1->entry;

		p = path_appendnew(p, nparent, base, path, pathlen, mode, oid);
				if (tp[i].size) {
	enum interesting match;
	pathchange_fn_t pathchange_old = opt->pathchange;

	struct combine_diff_path *p, const struct object_id *oid,

static int tree_entry_pathcmp(struct tree_desc *t1, struct tree_desc *t2)

			 * things), but we already have found renames
 *	 .     .        .
			cmp = tree_entry_pathcmp(&tp[i], &tp[imin]);
			if (!opt->flags.find_copies_harder) {

		isdir = S_ISDIR(mode);
 * so for clients,
	p = ll_diff_tree_paths(p, oid, parents_oid, nparent, base, opt);
	free(ttree);
		FAST_ARRAY_FREE(parents_oid, nparent);
	ll_diff_tree_oid(old_oid, new_oid, base, &diff_opts);
					&t, tp, imin);
			parents_oid[i] = tpi_valid ? &tp[i].entry.oid : NULL;
			mode = p->mode;
		int keep;
			1, 1, p->path, 0, 0);
	}
	 * path. Magic that matches more than one path is not
	diffcore_std(&diff_opts);

	const struct object_id *oid;
			/* t↓ */
 *  - single entry
		 *

		/*
 *
			for (i = 0; i < nparent; i++)
 *	process(p);
			const char *path[2];
	opt->pathchange = emit_diff_first_parent_only;
	const char *path;
		p = ll_diff_tree_paths(p, oid, parents_oid, nparent, base, opt);
			 * ourselves; signal diffcore_std() not to muck with

					    (t.entry.mode != tp[i].entry.mode))
 *
 *
		oid = tree_entry_extract(t, &path, &mode);
/*

					       base, 0, &opt->pathspec);
	struct diff_queue_struct *q = &diff_queued_diff;
			/* D += "+t" */
		}
		diff_free_filepair(p);
		} else {
static void try_to_follow_renames(const struct object_id *old_oid,


			int done = 1;
		 *


			addremove = '+';
			keep = opt->pathchange(opt, p);
{
}
					if (tp[i].entry.mode & S_IFXMIN_NEQ)
		update_tree_entry(t);
 *	- if last->next != NULL, it is assumed that p=last->next was returned
	 * Then, discard all the non-relevant file pairs...
			/* Switch the file-pairs around */
	opt->pathchange = pathchange_old;
 *                       ⎩"+t"     - if pi>p[imin]
}
	p->mode = mode;
		if (!(tp[i].entry.mode & S_IFXMIN_NEQ))
		}
		for (i = 0; i < imin; ++i)
 *	 t,  tp		-> path modified/added
		  const struct object_id *new_oid,
	struct combine_diff_path phead, *p;
 *	1)  t < p[imin];
	 * fact has no wildcards. nowildcard_len is merely a hint for
 * Helper functions for tree diff generation
		(x) = xalloca((nr) * sizeof(*(x))); \
 *			   (M for tp[i]=tp[imin], A otherwise)
{
			 * tp[i] is valid, if present and if tp[i]==tp[imin] -
 *	- if last->next == NULL, the memory is allocated;
				oid_i = &null_oid;
	return p;

			oidcpy(&p->parent[i].oid, oid_i);

	}
		 */
 * emitted on the go via opt->pathchange() callback, so it is possible to
		!DIFF_FILE_VALID(diff_queued_diff.queue[0]->one);
			parse_pathspec(&opt->pathspec,
	diff_opts.flags.find_copies_harder = 1;
		 *    S_ISDIR, thanks to base_name_compare().

		cmp = tree_entry_pathcmp(&t, &tp[imin]);
}

	if (p && (alloclen > (intptr_t)p->next)) {

 * Does it look like the resulting diff might be due to a rename?
	for (i = nparent-1; i >= 0; i--)
	const struct object_id **parents_oid, int nparent,
		if (diff_can_quit_early(opt))
						continue;
 *      |
 *
		mode = 0;
 *

	struct strbuf *base, struct diff_options *opt)
		FREE_AND_NULL(p);
	p->path = (char *)&(p->parent[nparent]);
 */
			p = pprev;
 * new path should be added to combine diff
	if (!p) {
	}
 *                       ⎧δ(t,pi)  - if pi=p[imin]
	}
 *
		if (cmp == 0) {
			tp[i].entry.mode |= S_IFXMIN_NEQ;	/* pi > p[imin] */

 *	p = path_appendnew(p, ...);
	return 0;	/* we are done with p */
			}
{
 *	 t, !tp		-> path added, all parents lack it
	int old_baselen = base->len;
 *
		}
{
		 * a path was removed - take path from imin parent. Also take
			}
 *
 *
	/*
 * Make a new combine_diff_path from path/mode/sha1
			if (cmp < 0) {
	for (i = 0; i < q->nr; i++) {
	int cmp;
 * at any time there could be 3 cases:
 * ~~~~~~~~
			 */
	struct combine_diff_parent *p0 = &p->parent[0];
} while(0)

 * NOTE files and directories *always* compare differently, even when having
	strbuf_addstr(&base, base_str);
	void *ttree, **tptree;

{
		 * until we go to it next round, .next holds how many bytes we
 * process the result as batch or incrementally.
 *
 *
 *      v
#include "diff.h"
	if (!*base_str && opt->flags.follow_renames && diff_might_be_rename())
 * -------------------------------
	}
	 */
		 * mode from that parent, to decide on recursion(1).
 *      non-empty descriptors will be processed first.
#include "diffcore.h"
 *
/* ∀ pi=p[imin]  pi↓ */

		 * much memory was allocated.
		/*
			oid = &p->oid;
		ALLOC_ARRAY((x), nr); \
		/* t = p[imin] */
			}

	 * follow-rename code is very specific, we need exactly one
	if (opt->pathspec.has_wildcard)
 *

			p->parent[i].status =
	}
 * (see ll_diff_tree_paths for what it means there)
						DIFF_STATUS_ADDED;
}
/*
	struct combine_diff_path *p, const struct object_id *oid,
		unsigned int mode;
 *     3.1+3.2) looking at δ(t,pi) ∀i: pi=p[imin] - if all != ø  ->
	diff_opts.break_opt = opt->break_opt;
 * The theory behind such scan is as follows:

		tp[0].entry.mode &= ~S_IFXMIN_NEQ;
 *	; don't forget to free tail->next in the end
	else \
 *      so that they sort *after* valid tree entries.
		const struct object_id **parents_oid;
		struct diff_filepair *p = q->queue[i];
	/* empty descriptors sort after valid tree entries */
 *	3)  t = p[imin].
						continue;
	const struct object_id **parents_oid, int nparent,
		p = p->next;

			/* Update the path we use from now on.. */
static inline int diff_might_be_rename(void)

 *	process(p);
 *
		 * mark entries whether they =p[imin] along the way
	/*
static struct combine_diff_path *path_appendnew(struct combine_diff_path *last,
		die("BUG:%s:%d: wildcards are not supported",
 *
 *	 T     P1       Pn
	FAST_ARRAY_FREE(tptree, nparent);

		}
#if 0

	memcpy(p->path, base->buf, base->len);
 *
 *

			    const struct object_id *new_oid,
	FAST_ARRAY_ALLOC(tptree, nparent);



		 */
		else if (cmp < 0) {
		/* compare t vs p[imin] */
	 * .. and re-instate the one we want (which might be either the

	 * about dry-run mode and returns wildcard info.

	}
 *	so this diff paths generator can, and is used, for plain diffs
		    __FILE__, __LINE__);
			 * filepairs to let a later call to diffcore_std()
		 * see path_appendnew() for details.
 *	Usual diff D(A,B) is by definition the same as combined diff D(A,[B]),
 * simultaneously, similarly to what diff_tree() was doing for 2 trees.

	/*
		match = tree_entry_interesting(opt->repo->index, &t->entry,
		if (opt->pathspec.nr) {
	struct strbuf base;
			 */
	struct tree_desc t, *tp;
{
	if (recurse) {
		}
	 */
 *
			 * otherwise, we should ignore it.


	 * optimization. Let it slip for now until wildmatch is taught
			p->next = NULL;
		if (!keep)
					break;
	diff_opts.rename_score = opt->rename_score;
	FAST_ARRAY_FREE(tp, nparent);

}
 */
		 */

	/*
	ttree = fill_tree_descriptor(opt->repo, &t, oid);
	int i, isdir, recurse = 0, emitthis = 1;
	diff_setup_done(&diff_opts);
 *
static int emit_diff_first_parent_only(struct diff_options *opt, struct combine_diff_path *p)
			update_tree_entry(&tp[i]);
		for (i = 0; i < nparent; ++i) {
				tp[i].entry.mode &= ~S_IFXMIN_NEQ;
}
 */
		if (match) {
 * Resulting paths are appended to combine_diff_path linked list, and also, are
 *
	return diff_tree_oid(NULL, new_oid, base, opt);

 * convert path -> opt->diff_*() callbacks
	if ((nr) > 2) \
			/*
	struct diff_filepair *choice;
			clear_pathspec(&opt->pathspec);
					/*t=*/NULL, tp, imin);
	else {
	memcpy(p->path + base->len, path, pathlen);
 *	generation too.
{
		pathlen = tree_entry_len(&tp[imin].entry);
		/* t > p[imin] */
 * D(T,P1...Pn) = D(T,P1) ^ ... ^ D(T,Pn)	(regarding resulting paths set)
	}
				mode_i = tp[i].entry.mode;
		opt->add_remove(opt, addremove, mode, oid, 1, p->path, 0);
	diff_tree_paths(&phead, new_oid, &old_oid, 1, base, opt);
			break;
	struct strbuf *base, struct diff_options *opt);
 *	!t,  tp		-> path removed from all parents
		}
		/*
 *
	 *
					/* diff(t,pi) != ø */
				for (i = 0; i < nparent; ++i)
					goto skip_emit_t_tp;
	diff_opts.output_format = DIFF_FORMAT_NO_OUTPUT;
/*
 *
	 * (see path_appendnew() for details about why)
		if (p->mode) {
 *	2)  t > p[imin];



 *	p = path_appendnew(p, ...);
				break;
	clear_pathspec(&diff_opts.pathspec);
	size_t len = st_add(base->len, pathlen);
 *	p = pprev;
 * 3)  t = p[imin]
			if (!opt->flags.find_copies_harder) {
	/*
		 * lookup imin = argmin(p1...pn),
	 * supported.
	const struct object_id **parents_oid, int nparent,
 * NOTE
		FAST_ARRAY_ALLOC(parents_oid, nparent);
/*

 *	|t|   |p1|     |pn|
		isdir = S_ISDIR(mode);
static struct combine_diff_path *ll_diff_tree_paths(
	opt->pathspec.recursive = opt->flags.recursive;
		struct combine_diff_path *pprev = p;
 * with p and it can be freed.
 *
#include "tree.h"
			q->queue[i] = choice;
		 */
 * emits diff to first parent only, and tells diff tree-walker that we are done
	int imin)
			/*
 * lock-step:



	p = last->next;
static void skip_uninteresting(struct tree_desc *t, struct strbuf *base,
		keep = 1;
	for (i = 0; i < nparent; ++i)


 *
	diff_opts.single_follow = opt->pathspec.items[0].match;
			int tpi_valid = tp && !(tp[i].entry.mode & S_IFXMIN_NEQ);


	FREE_AND_NULL(p->next);
		}
			p = emit_path(p, base, opt, nparent,
			mode = p0->mode;
#define S_IFXMIN_NEQ	S_DIFFTREE_IFXMIN_NEQ
	struct tree_desc *t, struct tree_desc *tp,
					/* p[i] > p[imin] */
	for (p = phead.next; p;) {
		/* comparing is finished when all trees are done */
 * - if you don't need to keep the element after processing
		tree_entry_extract(&tp[imin], &path, &mode);
	/* Remove the file creation entry from the diff queue, and remember it */
			choice = p;
		 * correct its .next to NULL, as it was pre-initialized to how
	diff_opts.flags.recursive = 1;
	int i;
		/*
					if (!oideq(&t.entry.oid, &tp[i].entry.oid) ||
			break;
 *

				  const struct object_id *new_oid,
{
			}

				tp[i].entry.mode |= S_IFXMIN_NEQ;
		skip_emit_t_tp:
 * internal mode marker, saying a tree entry != entry of tp[imin]
	 */
			/* are either pi > p[imin] or diff(t,pi) != ø ? */
	struct strbuf *base, struct diff_options *opt)
		 * If a path was filtered or consumed - we don't need to add it
static struct combine_diff_path *emit_path(struct combine_diff_path *p,
	} else {
	/* if last->next is !NULL - it is a pre-allocated memory, we can reuse */
			addremove = '-';


			if (done)


{
#include "cache.h"
		opt->change(opt, p0->mode, p->mode, &p0->oid, &p->oid,
			else if (cmp == 0) {
 *
 *
			opt->found_follow = 1;
		emitthis = opt->flags.tree_in_recursive;
	q->nr = 1;
			update_tp_entries(tp, nparent);
			path[1] = NULL;
 *	  earlier by this function, and p->next was *not* modified.
		 * pre-allocated element on the tail.
		free(tptree[i]);
			/* ∀i pi=p[imin] -> D += "-p[imin]" */

			p = emit_path(p, base, opt, nparent,
 *     2.1) ∃j: pj > p[imin]  ->  "-p[imin]" ∉ D(T,Pj)  ->  D += ø;  ∀ pi=p[imin]  pi↓
			}
}

				tp[i].entry.mode &= ~S_IFXMIN_NEQ;
		return -1;
				mode_i = 0;
}
#define FAST_ARRAY_FREE(x, nr) do { \
		struct diff_filepair *p = q->queue[i];
		}
	 * ( log_tree_diff() parses commit->parent before calling here via
				imin = i;

			int tpi_valid = tp && !(tp[i].entry.mode & S_IFXMIN_NEQ);
		p = xmalloc(alloclen);
	}
		oid = NULL;
				oid_i = &tp[i].entry.oid;
	struct name_entry *e1, *e2;
static struct combine_diff_path *ll_diff_tree_paths(
 * but not their sha1's.
	 * load parents first, as they are probably already cached.
 *	pprev = p;
 *     2.2) ∀i  pi = p[imin]  ->  pi ∉ T  ->  "-pi" ∈ D(T,Pi)  ->  D += "-p[imin]";  ∀i pi↓
	strbuf_init(&base, PATH_MAX);
 */
}
	return p;
			       struct diff_options *opt)
	return diff_queued_diff.nr == 1 &&
	 * haven't got a reliable way to detect that 'foo\*bar' in
