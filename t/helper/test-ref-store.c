		       int tz, const char *msg, void *cb_data)
{
			struct worktree *wt = *p;
{
	} else
	const char *ref;

	return ret;
			       flags, UPDATE_REFS_DIE_ON_ERR);
	return refs_for_each_reflog(refs, each_ref, NULL);
		for (p = worktrees; *p; p++) {
	const char *new_sha1_buf = notnull(*argv++, "new-sha1");

	{ "peel-ref", cmd_peel_ref },
#include "cache.h"

	struct strbuf err = STRBUF_INIT;
		die("ref store required");
static int cmd_resolve_ref(struct ref_store *refs, const char **argv)
static int cmd_for_each_reflog_ent(struct ref_store *refs, const char **argv)

	{ "delete-reflog", cmd_delete_reflog },
	const char *target = notnull(*argv++, "target");

	const char *refname = notnull(*argv++, "refname");
	die("not supported yet");
	return refs_for_each_reflog_ent(refs, refname, each_reflog, refs);
	return 0;
	const char *msg = notnull(*argv++, "msg");
	return refs_delete_refs(refs, msg, &refnames, flags);
	const char *func;
	if (!ret)
	die("unknown function %s", func);

	{ "for-each-reflog-ent", cmd_for_each_reflog_ent },

{
	{ "for-each-reflog", cmd_for_each_reflog },
	struct object_id old_oid;
	const char *refname = notnull(*argv++, "refname");
	if (get_oid_hex(old_sha1_buf, &old_oid) ||
	if (!argv[0]) {
}
	} else if (!strcmp(argv[0], "main")) {
		if (!*p)

	{ "reflog-exists", cmd_reflog_exists },
	{ "rename-ref", cmd_rename_ref },
{

	struct object_id oid;
{

	func = *argv++;
static int cmd_reflog_exists(struct ref_store *refs, const char **argv)
	const char *refname = notnull(*argv++, "refname");
	return ret;
static int cmd_create_reflog(struct ref_store *refs, const char **argv)
static unsigned int arg_flags(const char *arg, const char *name)

				      &oid, &flags);

{
}
{
#include "object-store.h"
			return cmd->func(refs, argv);
static int cmd_update_ref(struct ref_store *refs, const char **argv)

	return arg;

{
	const char *msg = notnull(*argv++, "msg");
#include "refs.h"
	int (*func)(struct ref_store *refs, const char **argv);
}
		die("no ref store");
static int cmd_rename_ref(struct ref_store *refs, const char **argv)

	struct ref_store *refs;
	} else if (skip_prefix(argv[0], "worktree:", &gitdir)) {
	int resolve_flags = arg_flags(*argv++, "resolve-flags");
	return ref ? 0 : 1;
static int cmd_delete_reflog(struct ref_store *refs, const char **argv)
	const char *oldref = notnull(*argv++, "oldref");
	{ "delete-ref", cmd_delete_ref },

		puts(oid_to_hex(&oid));
#include "repository.h"
	const char *refname = notnull(*argv++, "refname");
	    get_oid_hex(new_sha1_buf, &new_oid))

{
int cmd__ref_store(int argc, const char **argv)
static int cmd_for_each_reflog(struct ref_store *refs, const char **argv)
	const char *refname = notnull(*argv++, "refname");
	unsigned int flags = arg_flags(*argv++, "flags");
}
static int cmd_delete_refs(struct ref_store *refs, const char **argv)


			die("no such worktree: %s", gitdir);
	return ret;
{
static int cmd_create_symref(struct ref_store *refs, const char **argv)
		if (!strcmp(func, cmd->name))
	setup_git_directory();
		ret = strbuf_git_path_submodule(&sb, gitdir, "objects/");


	{ "for-each-ref", cmd_for_each_ref },
	argv = get_store(argv + 1, &refs);
			} else if (!strcmp(gitdir, wt->id))
	int ret;
	printf("%s %s %s %"PRItime" %d %s\n",

static int each_ref(const char *refname, const struct object_id *oid,

	return refs_for_each_ref_in(refs, prefix, each_ref, NULL);
}
		puts(err.buf);
			       &new_oid, &old_oid,
struct command {

	while (*argv)
	const char *msg = *argv++;
		}
{
	if (get_oid_hex(sha1_buf, &old_oid))
{
	const char *refname = notnull(*argv++, "refname");
	const char *gitdir;
					break;
	/* consume store-specific optional arguments if needed */
static int cmd_peel_ref(struct ref_store *refs, const char **argv)
		string_list_append(&refnames, *argv++);
}
}
};
	int flags;
}
static int cmd_delete_ref(struct ref_store *refs, const char **argv)

}



	const char *logmsg = *argv++;
		int ret;
	{ "resolve-ref", cmd_resolve_ref },
}
	return 0;
		*refs = get_submodule_ref_store(gitdir);

{
	int force_create = arg_flags(*argv++, "force-create");
	const char *refname = notnull(*argv++, "refname");
	const char *refname = notnull(*argv++, "refname");


}
static const char *notnull(const char *arg, const char *name)

{
static const char **get_store(const char **argv, struct ref_store **refs)
	struct object_id oid;
static int cmd_reflog_expire(struct ref_store *refs, const char **argv)
		die("not sha-1");
	return refs_for_each_reflog_ent_reverse(refs, refname, each_reflog, refs);
		die("%s required", name);

	return refs_delete_ref(refs, msg, refname, &old_oid, flags);
{
	{ "create-symref", cmd_create_symref },
{
		die("unknown backend %s", argv[0]);
	       committer, timestamp, tz, msg);
	return 0;
}
	 */

		die("ref function required");
static int each_reflog(struct object_id *old_oid, struct object_id *new_oid,
	if (err.len)
	unsigned int flags = arg_flags(*argv++, "flags");
		add_to_alternates_memory(sb.buf);
	for (cmd = commands; cmd->name; cmd++) {
		*refs = get_main_ref_store(the_repository);

				break;
		die("not sha-1");

{
}


	const char *newref = notnull(*argv++, "newref");
	       oid_to_hex(old_oid), oid_to_hex(new_oid),
}
}

		       const char *committer, timestamp_t timestamp,
}

	const char *sha1_buf = notnull(*argv++, "old-sha1");

	{ "for-each-reflog-ent-reverse", cmd_for_each_reflog_ent_reverse },
{

	{ NULL, NULL }
{
	if (!*refs)
	if (!arg)

static int cmd_verify_ref(struct ref_store *refs, const char **argv)
	struct strbuf err = STRBUF_INIT;
	ret = refs_peel_ref(refs, refname, &oid);
				/* special case for main worktree */
	 * backend transaction functions can't be tested separately
		strbuf_release(&sb);
	/*

	ret = refs_create_reflog(refs, refname, force_create, &err);
		struct worktree **p, **worktrees = get_worktrees(0);
	struct object_id old_oid;

	} else if (skip_prefix(argv[0], "submodule:", &gitdir)) {
	const char *refname = notnull(*argv++, "refname");
	{ "update-ref", cmd_update_ref },


}
#include "worktree.h"
{
		*refs = get_worktree_ref_store(*p);
	const char *refname = notnull(*argv++, "refname");
	struct string_list refnames = STRING_LIST_INIT_NODUP;
	return argv + 1;
	return refs_rename_ref(refs, oldref, newref, logmsg);
	return !refs_reflog_exists(refs, refname);

}
	const char *name;
#include "test-tool.h"
{

};

	struct object_id new_oid;
	return refs_pack_refs(refs, flags);
		struct strbuf sb = STRBUF_INIT;
	const char *old_sha1_buf = notnull(*argv++, "old-sha1");
	{ "create-reflog", cmd_create_reflog },
}
	const char *prefix = notnull(*argv++, "prefix");
			die("strbuf_git_path_submodule failed: %d", ret);
	ret = refs_verify_refname_available(refs, refname, NULL, NULL, &err);
	return refs_delete_reflog(refs, refname);
	unsigned int flags = arg_flags(*argv++, "flags");

}
	ref = refs_resolve_ref_unsafe(refs, refname, resolve_flags,
static struct command commands[] = {
	}

	{ "verify-ref", cmd_verify_ref },
	const char *refname = notnull(*argv++, "refname");
static int cmd_pack_refs(struct ref_store *refs, const char **argv)
	return refs_create_symref(refs, refname, target, logmsg);
	unsigned int flags = arg_flags(*argv++, "flags");

	int ret;
{
	const char *logmsg = *argv++;
		    int flags, void *cb_data)
	if (err.len)
}
	return atoi(notnull(arg, name));
				if (!strcmp(gitdir, "main"))
	struct command *cmd;
	printf("%s %s 0x%x\n", oid_to_hex(oid), refname, flags);
	if (!func)
	return refs_update_ref(refs, msg, refname,
	printf("%s %s 0x%x\n", oid_to_hex(&oid), ref ? ref : "(null)", flags);
		puts(err.buf);
{
static int cmd_for_each_reflog_ent_reverse(struct ref_store *refs, const char **argv)

	{ "reflog-expire", cmd_reflog_expire },
	int ret;
		if (ret)
}
	{ "pack-refs", cmd_pack_refs },


static int cmd_for_each_ref(struct ref_store *refs, const char **argv)
	{ "delete-refs", cmd_delete_refs },
			if (!wt->id) {
}
