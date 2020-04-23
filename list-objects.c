		if (!ctx->revs->tree_objects)
	else if (!failed_parse)
	ctx.show_data = show_data;
					show_edge(commit);
	 * Pre-filter known-missing objects when explicitly requested.
static void process_gitlink(struct traversal_context *ctx,
{


}
			mark_tree_uninteresting(revs->repo,
			/*

 *  - is the subproject actually checked out?
#include "trace.h"
	if (r & LOFR_MARK_SEEN)
#include "revision.h"
			    const unsigned char *sha1,
}

		return;
		struct commit *parent = parents->item;

		 * an incomplete list of missing objects.
	} else {

{
struct traversal_context {
	if (r & LOFR_MARK_SEEN)
	}
#include "cache.h"
{
		trace_printf("Skipping contents of tree %s...\n", base->buf);
		if (!tree)

				mark_tree_uninteresting(revs->repo,
		struct object *obj = pending->item;
			struct commit *commit = list->item;
		 * requested.  This may cause the actual filter to report
	int failed_parse;
			oidset_insert(&set, &tree->object.oid);
	struct strbuf csp; /* callee's scratch pad */
			if (match == entry_not_interesting)
}

	 */

	if (!obj)
			die(_("unable to load root tree for commit %s"),
			 struct strbuf *base,
 *
#include "diff.h"
			     struct oidset *set)
		for (list = revs->commits; list; list = list->next) {

			path = "";
	show_commit_fn show_commit,
{
void traverse_commit_list(struct rev_info *revs,
{
}

			continue;
 *    to the alternates list, and add it if not.
	r = list_objects_filter__filter_object(ctx->revs->repo,
	struct name_entry entry;
			struct commit *commit = (struct commit *)obj;

			}
			mark_edge_parents_uninteresting(commit, revs, show_edge);
		}
void traverse_commit_list_filtered(
};
				}
		}
			if (!t) {
		struct commit *parent = parents->item;
 * we do not recurse into the subproject.
		if (revs->edge_hint && !(parent->object.flags & SHOWN)) {
	traverse_trees_and_blobs(ctx, &csp);
		 */
	}
#include "packfile.h"
	 * Note that this "--exclude-promisor-objects" pre-filtering
	int i;
	ctx.revs = revs;
			parent->object.flags |= SHOWN;
{
}
				    entry.path, oid_to_hex(&tree->object.oid));
	if (failed_parse) {
	ctx.show_commit = show_commit;
	enum interesting match = ctx->revs->diffopt.pathspec.nr == 0 ?
		const char *name = pending->name;
		}
 * which would involve:
			}
	show_object_fn show_object;
	add_pending_object(revs, &tree->object, "");
			struct blob *b = lookup_blob(ctx->revs->repo, &entry.oid);
		if (obj->type == OBJ_TREE) {

		die("bad blob object");
	enum list_objects_filter_result r;
}
				      "but is not a blob"),
	void *show_data;
		for (i = 0; i < revs->cmdline.nr; i++) {
		return;
		 */
	struct commit_list *list;
			ctx->show_object(obj, name, ctx->show_data);
#include "list-objects-filter-options.h"
			process_blob(ctx, (struct blob *)obj, base, path);
 * reason to see superprojects and subprojects as such a

	strbuf_setlen(base, baselen);
			if (commit->object.flags & UNINTERESTING)
			process_tree(ctx, t, base, entry.path);
			  show_commit_fn show_commit,
			}
			show_edge(parent);
	if (obj->flags & (UNINTERESTING | SEEN))
		if (obj->type == OBJ_BLOB) {
		tree->object.flags |= UNINTERESTING;
			parent->object.flags |= SHOWN;
	for (parents = commit->parents; parents; parents = parents->next) {
		struct object_array_entry *pending = ctx->revs->pending.objects + i;
		strbuf_addch(base, '/');
	}
}
	size_t pathlen;
	strbuf_init(&csp, PATH_MAX);
		return;
	if (revs->edge_hint_aggressive) {
	struct tree_desc desc;
			 struct tree *tree,
					       LOFS_BLOB, obj,
	for (i = 0; i < ctx->revs->pending.nr; i++) {
				tree->object.flags |= UNINTERESTING;
		}
	    !has_object_file(&obj->oid) &&
		if (!(parent->object.flags & UNINTERESTING))
		if (obj->flags & (UNINTERESTING | SEEN))
{
					       ctx->filter);
	 *


static void do_traverse(struct traversal_context *ctx)
		all_entries_interesting : entry_not_interesting;
		oidset_insert(set, &tree->object.oid);
	}
	if (r & LOFR_SKIP_TREE)
					commit->object.flags |= SHOWN;
		ctx->show_commit(commit, ctx->show_data);
					       base->buf, &base->buf[baselen],
			process_tree(ctx, (struct tree *)obj, base, path);
		if (revs->edge_hint && !(parent->object.flags & SHOWN)) {
	int i;
		for (list = revs->commits; list; list = list->next) {
		}
 * So for now, there is just a note that we *could* follow
				  struct strbuf *base)

/*
 * We *could* eventually add a flag that actually does that,
	struct commit_list *parents;
		}
	if (r & LOFR_DO_SHOW)

		return;

		return;
		if (!revs->do_not_die_on_missing_tree)
					base, entry.path);
static void process_tree(struct traversal_context *ctx,
#include "tree-walk.h"
			 * tree directory without allocation churn?
	while (tree_entry(&desc, &entry)) {
			 * needs a reallocation for each commit. Can we pass the
			      show_edge_fn show_edge,
		else if (get_commit_tree(commit)) {
		 * Pre-filter known-missing tree objects when explicitly
	struct traversal_context ctx;
		/*
				    entry.path, oid_to_hex(&tree->object.oid));
				die(_("entry '%s' in tree %s has tree mode, "
		oidset_init(&set, 16);

					    struct rev_info *revs,
	struct object *obj = &tree->object;
	}
	if (!obj)
#include "blob.h"
			add_pending_tree(ctx->revs, tree);

			 const char *name)
					       LOFS_END_TREE, obj,
	ctx.show_data = show_data;
		struct oidset set;
		die("unknown pending object %s (%s)",
			process_blob(ctx, b, base, entry.path);
#include "tag.h"
	if (r & LOFR_MARK_SEEN)
			continue;
	struct rev_info *revs;
	for (parents = commit->parents; parents; parents = parents->next) {
					       path->buf, &path->buf[pathlen],
	 * may cause the actual filter to report an incomplete list
	}
	init_tree_desc(&desc, tree->buffer, tree->size);
			}
			     struct rev_info *revs,
		}
	struct rev_info *revs,
	if (r & LOFR_DO_SHOW)
	ctx.show_commit = show_commit;

	struct oidset *omitted)

			continue;
			 struct blob *blob,
		obj->flags |= SEEN;
#include "commit.h"
 * However, it's unclear whether there is really ever any
			if (!(obj->flags & SHOWN)) {
			    struct strbuf *path,
		if (match != all_entries_interesting) {
	failed_parse = parse_tree_gently(tree, 1);
	do_traverse(&ctx);

	pathlen = path->len;
	while ((commit = get_revision(ctx->revs)) != NULL) {
			      oid_to_hex(&commit->object.oid));
			if (obj->type != OBJ_COMMIT || !(obj->flags & UNINTERESTING))

		else {
	    is_promisor_object(&obj->oid))
		obj->flags |= SEEN;
		if (ctx->revs->tree_blobs_in_commit_order)
		mark_trees_uninteresting_sparse(revs->repo, &set);

	struct traversal_context ctx;
 * having gitlinks in the first place!).
					       base->buf, &base->buf[baselen],
		} else if (commit->object.parsed) {
			continue;
			 struct strbuf *path,
			b->object.flags |= NOT_USER_GIVEN;
	struct commit_list *parents;
					    show_edge_fn show_edge)
				obj->flags |= SHOWN;
#include "tree.h"
		else if (S_ISGITLINK(entry.mode))
	 * of missing objects.
			  show_object_fn show_object,
	r = list_objects_filter__filter_object(ctx->revs->repo,
			 const char *name)
	 * later (depending on other filtering criteria).
			process_gitlink(ctx, entry.oid.hash,
	struct object *obj = &blob->object;

			struct commit *commit = list->item;
		const char *path = pending->path;
		mark_tree_uninteresting(revs->repo, get_commit_tree(parent));
			continue;
		if (S_ISDIR(entry.mode)) {
 * humongous pack - avoiding which was the whole point of
		die("bad tree object");
}
static void process_tree_contents(struct traversal_context *ctx,
	struct list_objects_filter_options *filter_options,
		 * an uninteresting boundary commit may not have its tree
	do_traverse(&ctx);

							get_commit_tree(commit));
			t->object.flags |= NOT_USER_GIVEN;
	if (obj->flags & (UNINTERESTING | SEEN))
			return;
			struct tree *tree = get_commit_tree(commit);
	ctx.show_object = show_object;
	struct filter *filter;
					       LOFS_BEGIN_TREE, obj,
			if (match == all_entries_not_interesting)
	}
		process_tree_contents(ctx, tree, base);
 * Processing a gitlink entry currently does nothing, since
	 * Otherwise, a missing object error message may be reported
			; /* do not bother loading tree */
			struct object *obj = revs->cmdline.rev[i].item;
	if (r & LOFR_DO_SHOW)
}
void mark_edges_uninteresting(struct rev_info *revs,
 * the link, and how to do it. Whether it necessarily makes
		if (revs->exclude_promisor_objects &&
			     show_edge_fn show_edge,
	int baselen = base->len;
		    oid_to_hex(&obj->oid), name);
	object_array_clear(&ctx->revs->pending);
			struct tree *tree = get_commit_tree(commit);
{
	free_tree_buffer(tree);
		 * parsed yet, but we are not going to show them anyway
	/* Nothing to do */
 *
			  void *show_data)

#include "object-store.h"
 *    recursively.
static void mark_edge_parents_uninteresting(struct commit *commit,
						get_commit_tree(commit));
	assert(base->len == 0);

	strbuf_addstr(base, name);

		}
	show_object_fn show_object,
	ctx.filter = list_objects_filter__init(omitted, filter_options);
		}
static void process_tree(struct traversal_context *ctx,
	strbuf_setlen(path, pathlen);
			match = tree_entry_interesting(ctx->revs->repo->index,

	r = list_objects_filter__filter_object(ctx->revs->repo,
		    is_promisor_object(&obj->oid))
{
	void *show_data,
		/*
				continue;
 *  - process the commit (or tag) the gitlink points to
			add_edge_parents(commit, revs, show_edge, &set);
	/*

						       &entry, base, 0,

				continue;
		oidset_clear(&set);
#include "list-objects-filter.h"
					       ctx->filter);
	if (!revs->tree_objects)
{
 * "unified" object pool (potentially resulting in a totally
	ctx.filter = NULL;
		if (obj->type == OBJ_TAG) {
			      int sparse)
				show_edge(commit);

			tree->object.flags |= NOT_USER_GIVEN;
	if (base->len)
	struct commit *commit;
			    const char *name)

		if (!(parent->object.flags & UNINTERESTING))
			return;
		}

			 * NEEDSWORK: Adding the tree and then flushing it here
				  struct tree *tree,
		ctx->show_object(obj, path->buf, ctx->show_data);

						       &ctx->revs->diffopt.pathspec);
		obj->flags |= SEEN;
{
}
				continue;
	strbuf_release(&csp);
			continue;
static void add_pending_tree(struct rev_info *revs, struct tree *tree)
	ctx.show_object = show_object;

	if (!ctx->revs->blob_objects)
			die("bad tree object %s", oid_to_hex(&obj->oid));
static void traverse_trees_and_blobs(struct traversal_context *ctx,
	}
	strbuf_addstr(path, name);

		struct tree *tree = get_commit_tree(parent);
	enum list_objects_filter_result r;

				die(_("entry '%s' in tree %s has blob mode, "
			if (commit->object.flags & UNINTERESTING) {
		ctx->show_object(obj, base->buf, ctx->show_data);
 * any sense what-so-ever to ever do that is another issue.
#include "list-objects.h"
			 const char *name);
static void process_blob(struct traversal_context *ctx,
 *  - if so, see if the subproject has already been added
			struct tree *t = lookup_tree(ctx->revs->repo, &entry.oid);
	struct rev_info *revs = ctx->revs;
				      "but is not a tree"),
				break;
			 struct strbuf *base,
					       ctx->filter);

				if (revs->edge_hint_aggressive && !(commit->object.flags & SHOWN)) {
		if (revs->ignore_missing_links)
static void add_edge_parents(struct commit *commit,
 */

			if (!b) {
 *
	if (ctx->revs->exclude_promisor_objects &&
			obj->flags |= SEEN;
	if (sparse) {
			traverse_trees_and_blobs(ctx, &csp);
			 struct tree *tree,
			continue;
	list_objects_filter__free(ctx.filter);
		if (!path)
			 */
				     struct strbuf *base)

	ctx.revs = revs;
		}
	show_commit_fn show_commit;
		ctx->show_object(obj, base->buf, ctx->show_data);
			show_edge(parent);
{

		}
}
}
