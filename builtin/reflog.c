	while (tree_entry(&desc, &entry)) {
		if (parse_worktree_ref(refname, NULL, NULL, &refname))
	case REF_TYPE_MAIN_PSEUDOREF:
			for (elem = cb->tips; elem; elem = elem->next)
{
	return cmd_log_reflog(argc, argv, prefix);

		return 1;
			commit_list_insert(commit, &pending);
	struct reflog_expire_cfg *ent;
{

		status |= reflog_expire(ref, &oid, flags,
	git_config(reflog_expire_config, NULL);
		cb->expire_unreachable = default_reflog_expire_unreachable;

		UE_HEAD
				die(_("'%s' is not a valid timestamp"), arg);
{
			break;
	timestamp_t expire_total;
		}
			if (commit->object.flags & REACHABLE)
			cb->unreachable_expire_kind = UE_NORMAL;
		return 1;
	if (is_incomplete)
	 * from reflog if the repository was pruned with older git.
		if (!strcmp(arg, "--")) {
			tree->object.flags |= INCOMPLETE;
}
	struct reflog_expire_cfg *ent;
						&cb);
				is_incomplete = 1;
		} else {
	 */
		const char *email, timestamp_t timestamp, int tz,

			for_each_ref(push_tip_to_list, &cb->tips);
	 * and cache earlier.  The commits reachable by this commit
			break;
	struct tree *tree;
		mark_reachable(cb);
	}
		set_reflog_expiry_param(&cb.cmd, explicit_expiry, ref);
					reflog_expiry_cleanup,
		commit->object.flags |= INCOMPLETE;
		commit = lookup_commit_reference_gently(the_repository, oid,
{
	struct collected_reflog *e;
		pending->item->object.flags &= ~REACHABLE;
		if (!data) {
		else if (arg[0] == '-')
	if (commit->object.flags & REACHABLE)
	if (complete)
						should_expire_reflog_ent,
		UE_ALWAYS,
#include "diff.h"

		if (cb->unreachable_expire_kind == UE_ALWAYS)
	struct expire_reflog_policy_cb *cb = cb_data;
	/* With no command, we default to showing it. */
		for (i = 0; i < found.nr; i++) {
	 * complete.  After that, mark these commits also as SEEN.

		}
static timestamp_t default_reflog_expire;



	unsigned int flags = 0;
	do_all = status = 0;
	 * they are available via all worktrees.
/* Remember to update object flag allocation in object.h */
			continue;

	unsigned int flags = 0;
	if (commit->object.flags & SEEN)
	timestamp_t expire_total;

}

		if (!spec) {
		 * from the "commit" until we reach SEEN commits (which are
		if (!(slot & EXPIRE_TOTAL))
struct collected_reflog {
		struct commit *c;
			flags |= EXPIRE_REFLOGS_VERBOSE;

			set_reflog_expiry_param(&cb.cmd, explicit_expiry, e->reflog);
		free(collected.e);
		return 1;
				clear_commit_marks(elem->item, REACHABLE);
static int is_head(const char *refname)

	old_commit = new_commit = NULL;

		if (!dwim_log(argv[i], spec - argv[i], &oid, &ref)) {
	struct reflog_expire_cfg *next;
		return 1;
#include "tree-walk.h"
static int collect_reflog(const char *ref, const struct object_id *oid, int unused, void *cb_data)
		struct commit_list *parent;
		return cmd_log_reflog(argc - 1, argv + 1, prefix);


	add_object_array(&commit->object, NULL, &found);
			if (!all_worktrees && !(*p)->is_current)
N_("git reflog [ show | expire | delete | exists ]");
	if (cb->unreachable_expire_kind != UE_ALWAYS) {
		if (!is_incomplete) {
	return 1;
		else
	if (timestamp < cb->cmd.expire_unreachable) {
static timestamp_t default_reflog_expire_unreachable;
	int recno;
	int explicit_expiry = 0;
}
	switch (slot) {
		else if (!strcmp(arg, "--")) {
				(struct commit *)found.objects[i].item;
	save_commit_buffer = 0;
	cb->e[cb->nr++] = e;
		 * we have seen during this process are complete.
		cb->cmd.recno++;
		return 0;
		cb->mark_limit = cb->cmd.expire_total;
		slot = EXPIRE_TOTAL;
 * Starting from commits in the cb->mark_list, mark commits that are
			free(e);
		return 0;
	 */
static int cmd_reflog_delete(int argc, const char **argv, const char *prefix)
	object_array_clear(&found);
	}
			    int flags, void *cb_data)
		slot = EXPIRE_UNREACH;
		else if (!strcmp(arg, "--updateref"))
}
   "[--verbose] [--all] <refs>...");
	 * Avoid collecting the same shared ref multiple times because
}
	if (is_null_oid(oid))
		} else {
	} else if (!strcmp(key, "reflogexpireunreachable")) {
	cb->tips = NULL;

static const char reflog_exists_usage[] =
			status |= error(_("%s points nowhere!"), argv[i]);
		if (flags & EXPIRE_REFLOGS_VERBOSE)

	timestamp_t expire;
			putchar('\n');

		break;

		    ent->pattern[len] == '\0')
		else if (c->object.flags & SEEN)
	struct commit_list *leftover = NULL;
			if (!tree_is_complete(get_commit_tree_oid(c))) {
static void reflog_expiry_prepare(const char *refname,
			if (p->object.flags & STUDYING)
				    const char *message, void *cb_data)
static int commit_is_complete(struct commit *commit)
		if (cb->unreachable_expire_kind == UE_HEAD) {
	strbuf_worktree_ref(cb->wt, &newref, ref);
	if (cb.cmd.stalefix) {
		/*
static int reflog_expire_config(const char *var, const char *value, void *cb)
}
		struct collect_reflog_cb collected;
		return git_default_config(var, value, cb);
		if (cb->unreachable_expire_kind == UE_HEAD) {

	 * even in older repository.  We cannot trust what's reachable
			free_commit_list(cb->tips);
			flags |= EXPIRE_REFLOGS_DRY_RUN;
		cb->unreachable_expire_kind = UE_ALWAYS;
			add_object_array(&p->object, NULL, &found);
		commit->object.flags |= REACHABLE;
	return !is_incomplete;
		}

	ent = find_cfg_ent(pattern, pattern_len);
};
	case REF_TYPE_OTHER_PSEUDOREF:
		enum object_type type;
		int recno;
	struct expire_reflog_policy_cb cb;
		commit->object.flags |= REACHABLE;
	}
							1);
static const char reflog_delete_usage[] =
		 * If we come here, we have (1) traversed the ancestry chain
#define STUDYING	(1u<<11)
	/*
				cb->expire_unreachable = ent->expire_unreachable;
	struct commit *tip_commit;
		if (unreachable(cb, old_commit, ooid) || unreachable(cb, new_commit, noid))
			return ent;
static int cmd_reflog_expire(int argc, const char **argv, const char *prefix)
		return cmd_reflog_exists(argc - 1, argv + 1, prefix);
	for (ent = reflog_expire_cfg; ent; ent = ent->next) {
					&cb);
			break;
	tree = lookup_tree(the_repository, oid);
	if (!strcmp(key, "reflogexpire")) {
			if (parse_expiry_date(arg, &cb.cmd.expire_unreachable))
		else if (!strcmp(arg, "--all"))
		if (parse_commit(commit))
	default:
			i++;
{
}
}

		else if (arg[0] == '-')
static int push_tip_to_list(const char *refname, const struct object_id *oid,
		else if (!strcmp(arg, "--updateref"))
	add_object_array(&commit->object, NULL, &study);
#include "revision.h"
		for (p = worktrees; *p; p++) {
			cb->expire_unreachable = 0;
			}
	struct commit_list **list = cb_data;
	default_reflog_expire = now - 90 * 24 * 3600;
	timestamp_t expire_unreachable;
			struct commit_list *elem;
 * main "reflog"
   "[--rewrite] [--updateref] [--stale-fix] [--dry-run | -n] "
			return 0;
	return status;
		 * known to be complete), and (2) made sure that the commits
	 */
	for (pending = cb->mark_list; pending; pending = pending->next)
		switch (slot) {
N_("git reflog delete [--rewrite] [--updateref] "
	switch (ref_type(refname)) {
				commit_list_insert(elem->item, &cb->mark_list);
	pending = cb->mark_list;
{
	memset(&found, 0, sizeof(found));
		unsigned long size;
	unsigned long mark_limit;


		if (!strcmp(arg, "--dry-run") || !strcmp(arg, "-n"))
	char pattern[FLEX_ARRAY];
		/*
		else if (!strcmp(arg, "--")) {
		if (!c->object.parsed && !parse_object(the_repository, &c->object.oid))

	strbuf_release(&newref);
	}
	if (!commit_is_complete(commit))
	}
		}
			return 1;

	} unreachable_expire_kind;
			break;
			return 0;
		free(ref);
			return -1;
				    const char *email, timestamp_t timestamp, int tz,

			flags |= EXPIRE_REFLOGS_VERBOSE;
				die(_("'%s' is not a valid timestamp"), arg);

			for (i = 0; i < found.nr; i++)
	if (tree->object.flags & INCOMPLETE)
#include "commit.h"
{
					reflog_expiry_cleanup,
	 * We have walked all the objects reachable from the refs
	for (i = 1; i < argc; i++) {

	cb->mark_list = leftover;

	return !(commit->object.flags & REACHABLE);
		struct object_id oid;
		}
}
struct collect_reflog_cb {
	return 0;
			flags |= EXPIRE_REFLOGS_DRY_RUN;
	struct object_array found;
		}


	if (!strcmp(ref, "refs/stash")) {
	int pattern_len;
	if (!cb->wt->is_current && ref_type(ref) == REF_TYPE_NORMAL)
	if (commit->object.flags & INCOMPLETE)
			c->object.flags |= INCOMPLETE;
	if (timestamp < cb->cmd.expire_total)
	commit->object.flags |= STUDYING;
	if (!pattern) {

					reflog_expiry_prepare,
static int tree_is_complete(const struct object_id *oid)

			break;

	ALLOC_GROW(cb->e, cb->nr + 1, cb->alloc);
{
	FLEX_ALLOC_STR(e, reflog, newref.buf);
#include "object-store.h"
		}
	return 0;
		repo_init_revisions(the_repository, &cb.cmd.revs, prefix);
			found.objects[i].item->flags |= SEEN;

	char reflog[FLEX_ARRAY];
		free_worktrees(worktrees);
			parent = parent->next;
	for (i = 1; i < argc; i++) {
	if (slot == (EXPIRE_TOTAL|EXPIRE_UNREACH))

			i++;
			p->object.flags |= STUDYING;
		c = (struct commit *)object_array_pop(&study);
 */
struct expire_reflog_policy_cb {
	int i, start = 0;
}
	}
		if (git_config_expiry_date(&expire, var, value))
		 * are complete.  Which means that we know *all* the commits

#include "refs.h"

	for (i = 0; i < found.nr; i++)
	tip_commit = lookup_commit_reference_gently(the_repository, oid, 1);
			continue;
#include "builtin.h"
static void set_reflog_expiry_param(struct cmd_reflog_expire_cb *cb, int slot, const char *ref)

	}
	if (flags & REF_ISSYMREF)
	}
		memset(&collected, 0, sizeof(collected));
						reflog_expiry_prepare,
		found.objects[i].item->flags &= ~STUDYING;
				cb->expire_total = ent->expire_total;
	 * Find all commits that are reachable and are not marked as
	 * up using the supplied sha1.
static void reflog_expiry_cleanup(void *cb_data)
			cb->expire_total = 0;
#include "reachable.h"

	if (!is_incomplete) {
	struct reflog_expire_cfg *ent;
			struct collected_reflog *e = collected.e[i];
	if (cb->cmd.recno && --(cb->cmd.recno) == 0)
	int i;
		if (*ep == '}') {
	    (!keep_entry(&old_commit, ooid) || !keep_entry(&new_commit, noid)))

	 */

			commit_list_insert(cb->tip_commit, &cb->mark_list);
/* NEEDSWORK: switch to using parse_options */
	return ent;
	}
	struct strbuf newref = STRBUF_INIT;
{
	for (; i < argc; i++) {
		UE_NORMAL,
		return;
	case EXPIRE_TOTAL:
		}
		}
/*
#include "repository.h"
			return 1;
		}
	/*
		cb->expire_total = default_reflog_expire;

	if (!reflog_expire_cfg_tail)
			add_object_array(&p->object, NULL, &study);
			flags |= EXPIRE_REFLOGS_REWRITE;
		else if (skip_prefix(arg, "--expire-unreachable=", &arg)) {

		char *ep, *ref;
		const char *message, void *cb_data)
			cb.cmd.stalefix = 1;
	if (check_refname_format(argv[start], REFNAME_ALLOW_ONELEVEL))
			break;
	const char *pattern, *key;
	reflog_expire_cfg_tail = &(ent->next);
	return complete;
					should_expire_reflog_ent,
		return -1;
			flags |= EXPIRE_REFLOGS_REWRITE;

		die(_("invalid ref format: %s"), argv[start]);
		return 0;
 */
	if (!commit)
	 *
			break;
			cb.cmd.expire_total = approxidate(spec + 2);
 */

	 * If unconfigured, make stash never expire
	} else
			commit_list_insert(commit, &leftover);

		return 0;
		return cmd_reflog_expire(argc - 1, argv + 1, prefix);

		recno = strtoul(spec + 2, &ep, 10);
	 * SEEN as well.
			/* mark all found commits as complete, iow SEEN */
		for (i = 0; i < collected.nr; i++) {

	return !reflog_exists(argv[start]);
 * reachable from them.  Stop the traversal at commits older than
		return error(_("no reflog specified to delete"));

	struct rev_info revs;
			if (!(slot & EXPIRE_UNREACH))
		 */

		if (flags & EXPIRE_REFLOGS_VERBOSE)
	/* Reachable from the current ref?  Don't prune. */

		for (parent = c->parents; parent; parent = parent->next) {
		break;
		if (!dwim_log(argv[i], strlen(argv[i]), &oid, &ref)) {
				continue;
	if (!(slot & EXPIRE_UNREACH))
{
			explicit_expiry |= EXPIRE_UNREACH;
	}
	int i, status, do_all, all_worktrees = 1;
{
#define REACHABLE	(1u<<12)
			for (elem = cb->tips; elem; elem = elem->next)

	}
		case EXPIRE_TOTAL:

		if (!strncmp(ent->pattern, pattern, len) &&
	if (argc < 2 || *argv[1] == '-')
		return 0;
			default_reflog_expire_unreachable = expire;

	}
	 */
{
			for_each_reflog_ent(ref, count_reflog_ent, &cb);
		return cmd_log_reflog(argc, argv, prefix);
N_("git reflog exists <ref>");
			struct commit_list *elem;
		while (parent) {
	struct commit_list *pending;
		tree->buffer = data;
};
		else if (!strcmp(arg, "--verbose"))
		const char *arg = argv[i];

	struct commit *commit;
	if (!cb->cmd.expire_total || timestamp < cb->cmd.expire_total)
			cb.cmd.recno = -recno;
	 * commit are missing, mark this commit as INCOMPLETE.
	struct expire_reflog_policy_cb *cb = cb_data;
static struct reflog_expire_cfg *find_cfg_ent(const char *pattern, size_t len)

	struct commit_list *tips;

	int is_incomplete = 0;
	 * If some of the objects that are needed to complete this
	struct expire_reflog_policy_cb cb;
{
		ent->expire_unreachable = expire;
{
	} else {

		reflog_expire_cfg_tail = &reflog_expire_cfg;
   "[--dry-run | -n] [--verbose] <refs>...");
			continue;
					     collect_reflog, &collected);
			tree->object.flags |= INCOMPLETE;
/*
int cmd_reflog(int argc, const char **argv, const char *prefix)

		if (!has_object_file(&entry.oid) ||
			default_reflog_expire = expire;
		 */
	if (argc - i < 1)
		struct object_id oid;
		return 1;
	memset(&cb, 0, sizeof(cb));
	commit = lookup_commit_reference_gently(the_repository, oid, 1);
	if (!tree)

		return 0;
};
		return cmd_reflog_delete(argc - 1, argv + 1, prefix);
	*reflog_expire_cfg_tail = ent;
}
	struct commit_list *mark_list;
	else {
	int i, status = 0;
	timestamp_t expire_limit = cb->mark_limit;
		const char *arg = argv[i];
			for_each_reflog_ent(ref, count_reflog_ent, &cb);
	}
						reflog_expiry_cleanup,
	struct object_array study;
	int slot;
{
		}

{
		if (is_null_oid(oid))
		return 0;
	oidcpy(&e->oid, oid);
#define INCOMPLETE	(1u<<10)
			continue;
	if (tree->object.flags & SEEN)
	if (!tip_commit)
		return 0;
	/*
		const char *spec = strstr(argv[i], "@{");
		usage(_(reflog_exists_usage));
		else if (arg[0] == '-')
static const char reflog_expire_usage[] =
			struct commit *c =
			if (parse_expiry_date(arg, &cb.cmd.expire_total))
	/*
	}
	return !strcmp(refname, "HEAD");
static int unreachable(struct expire_reflog_policy_cb *cb, struct commit *commit, struct object_id *oid)
	if (!ent)
	default_reflog_expire_unreachable = now - 30 * 24 * 3600;

#include "dir.h"

			cb->unreachable_expire_kind = UE_ALWAYS;
			clear_commit_marks(cb->tip_commit, REACHABLE);
		return 1;

	 * We may or may not have the commit yet - if not, look it
					&cb);
} *reflog_expire_cfg, **reflog_expire_cfg_tail;
		if (!(slot & EXPIRE_UNREACH))
			usage(_(reflog_delete_usage));
	/*
		}
	return 0;

	FLEX_ALLOC_MEM(ent, pattern, pattern, len);
struct cmd_reflog_expire_cb {
	}
	if (!commit) {
	object_array_clear(&study);
		if (!wildmatch(ent->pattern, ref, 0)) {

	while (pending) {
		struct commit_list *parent;
		else
			status |= error(_("not a reflog: %s"), argv[i]);
		}
	int stalefix;
		if (c->object.flags & INCOMPLETE) {
	/* free object arrays */

	}

static int cmd_reflog_exists(int argc, const char **argv, const char *prefix)

	 * We can trust the commits and objects reachable from refs
	commit_list_insert(tip_commit, list);
			complete = 0;
			continue;
			i++;
{
		return 0;
	struct collect_reflog_cb *cb = cb_data;
			struct commit *p = parent->item;

static const char reflog_usage[] =
 * us again to restart the traversal with longer expire_limit.
		if (commit->date < expire_limit) {

	if (do_all) {
	if (!strcmp(argv[1], "show"))
		cb->tip_commit = lookup_commit_reference_gently(the_repository,
	 */
   "[--expire-unreachable=<time>] "
	if (argc > 1 && !strcmp(argv[1], "-h"))
					should_expire_reflog_ent,
		cb->tip_commit = NULL;
	struct cmd_reflog_expire_cb cmd;
			all_worktrees = 0;
		/* Not a commit -- keep it */
		 * encountered during the above traversal refer to trees that
		for (i = 0; i < found.nr; i++)


		else if (!strcmp(arg, "--verbose"))
		if (commit->object.flags & REACHABLE)
	cb.cmd.expire_total = default_reflog_expire;
	struct collected_reflog **e;
		}
#define EXPIRE_TOTAL   01
	if (!cb->cmd.expire_unreachable || is_head(refname)) {
	if (argc - start != 1)
	return status;
}

			printf(_("Marking reachable objects..."));
			status |= error(_("no reflog for '%s'"), argv[i]);

		usage(_(reflog_usage));
	while (study.nr) {
			explicit_expiry |= EXPIRE_TOTAL;

	struct commit *old_commit, *new_commit;
};
	if (cb->cmd.stalefix &&
			break;
		else if (skip_prefix(arg, "--expire=", &arg)) {

		else
		}
		tree->object.flags |= SEEN;
		return; /* both given explicitly -- nothing to tweak */
		struct worktree **worktrees, **p;
		struct commit *commit = pop_commit(&pending);
	free_tree_buffer(tree);
}
	/* early return */
		}

		void *data = read_object_file(oid, &type, &size);
 * Return true iff the specified reflog entry should be expired.
		status |= reflog_expire(ref, &oid, flags,
	if (!(slot & EXPIRE_TOTAL))
	struct expire_reflog_policy_cb *cb = cb_data;
			usage(_(reflog_expire_usage));
	}

			refs_for_each_reflog(get_worktree_ref_store(*p),
		case EXPIRE_UNREACH:

		}
			collected.wt = *p;
	}
			do_all = 1;
	}
					reflog_expiry_prepare,
		break;
		worktrees = get_worktrees(0);
				  const struct object_id *oid,
	cb->mark_list = NULL;
			status |= reflog_expire(e->reflog, &e->oid, flags,
static int should_expire_reflog_ent(struct object_id *ooid, struct object_id *noid,
		 * make sure all commits in "found" array have all the

				continue;
	case EXPIRE_UNREACH:
	if (!strcmp(argv[1], "delete"))
	}
	timestamp_t expire_unreachable;
		parent = commit->parents;
}
	struct name_entry entry;
	for (ent = reflog_expire_cfg; ent; ent = ent->next)
	memset(&study, 0, sizeof(study));
		cb->mark_limit = 0; /* dig down to the root */
#include "lockfile.h"
	memset(&cb, 0, sizeof(cb));
			usage(_(reflog_exists_usage));
		}
		}
/*
	return 0;

			is_incomplete = 1;
	if (cb->cmd.expire_unreachable <= cb->cmd.expire_total)
	if (cb->unreachable_expire_kind != UE_ALWAYS) {
{
		return 0;
		    (S_ISDIR(entry.mode) && !tree_is_complete(&entry.oid))) {

	if (!strcmp(argv[1], "exists"))
N_("git reflog expire [--expire=<time>] "
		else if (!strcmp(arg, "--stale-fix"))
	if (cb->mark_list && cb->mark_limit) {
			return;
}
		char *ref;
		ent->expire_total = expire;
	}
	 * must meet SEEN commits -- and then we should mark them as
		}
static int keep_entry(struct commit **it, struct object_id *oid)
	 * Make sure everything in this commit exists.
		else
		else if (!strcmp(arg, "--rewrite"))
}
	/* clear flags from the objects we traversed */
	struct tree_desc desc;
			continue;
		if (!strcmp(arg, "--dry-run") || !strcmp(arg, "-n"))
}
	for (i = 1; i < argc; i++) {
	struct expire_reflog_policy_cb *cb = cb_data;
	complete = 1;
	struct commit *tip_commit;
		break;
	struct worktree *wt;
				continue;
	if (!tree->buffer) {
								oid, 1);
		return git_default_config(var, value, cb);
	return 0;
			flags |= EXPIRE_REFLOGS_UPDATE_REF;
		} else {
				found.objects[i].item->flags |= SEEN;
		if (!commit)
	start = i;
			return -1;
	for ( ; i < argc; i++) {

	}
			flags |= EXPIRE_REFLOGS_UPDATE_REF;
	enum {
				  void *cb_data)
		int i;
		}
#include "config.h"
	 * SEEN.  Then make sure the trees and blobs contained are

				c->object.flags |= INCOMPLETE;
static int count_reflog_ent(struct object_id *ooid, struct object_id *noid,
#define EXPIRE_UNREACH 02
static void mark_reachable(struct expire_reflog_policy_cb *cb)
	struct object_id oid;
		 * necessary objects.
		if (git_config_expiry_date(&expire, var, value))
	timestamp_t now = time(NULL);
		}
	*it = commit;
		const char *arg = argv[i];
static struct reflog_expire_cfg {
	}
			continue;


 * the expire_limit and queue them back, so that the caller can call
		else if (!strcmp(arg, "--single-worktree"))


			if (!(slot & EXPIRE_TOTAL))
		mark_reachable_objects(&cb.cmd.revs, 0, 0, NULL);
	init_tree_desc(&desc, tree->buffer, tree->size);
			commit = parent->item;
	int alloc;
}
	/* Nothing matched -- use the default value */
	int complete;
	if (!strcmp(argv[1], "expire"))
		mark_reachable(cb);
			cb.cmd.expire_total = 0;
	/*
		cb->unreachable_expire_kind = UE_HEAD;
#include "worktree.h"
		else if (!strcmp(arg, "--rewrite"))
}

	if (parse_config_key(var, "gc", &pattern, &pattern_len, &key) < 0)
			return 0;

{
	}
			BUG("not a worktree ref: %s", refname);
	int nr;
		tree->size = size;
		if (!cb->tip_commit)
		}
	cb.cmd.expire_unreachable = default_reflog_expire_unreachable;

/* expiry timer slot */
			break;
