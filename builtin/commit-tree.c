{

	int status = git_gpg_config(var, value, NULL);
	if (buf->len)
}
	}

#include "config.h"
	struct strbuf *buf = opt->value;
		if (parents->item == parent) {
	for (parents = *parents_p; parents; parents = parents->next) {
	return 0;

		const char *arg, int unset)
		die_errno(_("git commit-tree: failed to read '%s'"), arg);
		if (fd < 0)
static const char *sign_commit;
		die(_("must give exactly one tree"));
/*
#include "repository.h"
	}
			die_errno(_("git commit-tree: failed to open '%s'"), arg);
	struct object_id oid;
	else {
	return git_default_config(var, value, cb);
 * GIT - The information manager from hell
	};
	BUG_ON_OPT_NEG_NOARG(unset, arg);
		const char *arg, int unset)
			parse_parent_arg_callback },
	strbuf_addstr(buf, arg);

}
		die(_("not a valid object name %s"), argv[0]);

	if (!strcmp(arg, "-"))
}
			N_("GPG sign commit"), PARSE_OPT_OPTARG, NULL, (intptr_t) "" },

static int commit_tree_config(const char *var, const char *value, void *cb)
	}
	int fd;
		strbuf_addch(buf, '\n');
	return 0;

static int parse_file_arg_callback(const struct option *opt,
	if (argc != 1)

		parents_p = &parents->next;
	if (!buffer.len) {
		strbuf_release(&buffer);
	if (commit_tree(buffer.buf, buffer.len, &tree_oid, parents, &commit_oid,

			die_errno(_("git commit-tree: failed to read"));
static int parse_parent_arg_callback(const struct option *opt,
			N_("id of a parent commit object"), PARSE_OPT_NONEG,
	N_("git commit-tree [(-p <parent>)...] [-S[<keyid>]] [(-m <message>)...] "
 */
		{ OPTION_CALLBACK, 'F', NULL, &buffer, N_("file"),

{
	commit_list_insert(parent, parents_p);
			parse_file_arg_callback },

}
 *
	BUG_ON_OPT_NEG_NOARG(unset, arg);
int cmd_commit_tree(int argc, const char **argv, const char *prefix)
{
#include "tree.h"

static const char * const commit_tree_usage[] = {
	BUG_ON_OPT_NEG_NOARG(unset, arg);
	printf("%s\n", oid_to_hex(&commit_oid));
	if (argc < 2 || !strcmp(argv[1], "-h"))
	git_config(commit_tree_config, NULL);
static int parse_message_arg_callback(const struct option *opt,
	if (strbuf_read(buf, fd, 0) < 0)
{
	argc = parse_options(argc, argv, prefix, options, commit_tree_usage, 0);

		die_errno(_("git commit-tree: failed to close '%s'"), arg);
		{ OPTION_CALLBACK, 'm', NULL, &buffer, N_("message"),
#include "gpg-interface.h"

			return;
	new_parent(lookup_commit(the_repository, &oid), parents);
#include "commit.h"
}
	if (status)
}
	NULL

#include "utf8.h"
{
static void new_parent(struct commit *parent, struct commit_list **parents_p)
		fd = 0;
		usage_with_options(commit_tree_usage, options);
			NULL, sign_commit)) {

	if (buf->len)

#include "parse-options.h"
 * Copyright (C) Linus Torvalds, 2005
		die(_("not a valid object name %s"), arg);
	struct commit_list *parents;
	struct object_id tree_oid;
		OPT_END()
{
	assert_oid_type(&oid, OBJ_COMMIT);
	struct option options[] = {
#include "cache.h"

	return 0;
	strbuf_complete_line(buf);
#include "builtin.h"
	if (get_oid_tree(argv[0], &tree_oid))
#include "object-store.h"


			N_("commit message"), PARSE_OPT_NONEG,
	if (get_oid_commit(arg, &oid))
		{ OPTION_STRING, 'S', "gpg-sign", &sign_commit, N_("key-id"),
	struct strbuf *buf = opt->value;
	struct commit_list **parents = opt->value;
	if (fd && close(fd))

	static struct strbuf buffer = STRBUF_INIT;
		return status;
	}

		"[(-F <file>)...] <tree>"),
			parse_message_arg_callback },
	strbuf_release(&buffer);
		return 1;

	return 0;
		strbuf_addch(buf, '\n');
			N_("read commit log message from file"), PARSE_OPT_NONEG,
		if (strbuf_read(&buffer, 0, 0) < 0)
		fd = open(arg, O_RDONLY);
	struct object_id *oid = &parent->object.oid;
		}
		const char *arg, int unset)
		{ OPTION_CALLBACK, 'p', NULL, &parents, N_("parent"),
	struct object_id commit_oid;
			error(_("duplicate parent %s ignored"), oid_to_hex(oid));



	struct commit_list *parents = NULL;
};
