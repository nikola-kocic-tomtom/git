		info->status = PUSH_STATUS_NOTQUERIED;
	int dry_run = 0, result = 0;
	int urlset_nr;
				rename.new_name, strlen(rename.new_name));
	}

	};
	N_("git remote set-branches --add <name> <branch>..."),
{
	/* Old URL specified. Demand that one matches. */
	N_("git remote remove <name>"),

static struct string_list branch_list = STRING_LIST_INIT_NODUP;
			get_head_names(remote_refs, states);

		string_list_append(list, remote->name)->util = NULL;
			for (i = 0; i < states.heads.nr; i++)
	string_list_clear(&states->stale, 1);
	for (kr = branches->keep->list; kr; kr = kr->next) {
		strbuf_addstr(&buf, item->string);
	if (!refspec_updated)


		if (rename_ref(item->string, buf.buf, buf2.buf))
		*mirror = MIRROR_NONE;
		strbuf_addf(tmp, "refs/heads/%s:refs/remotes/%s/%s",
	} status;
	else if (strip_suffix(key, ".rebase", &key_len))
};
}
	remotename = argv[1];

	case PUSH_STATUS_NOTQUERIED:
	TAGS_SET = 2
static int show_remote_info_item(struct string_list_item *item, void *cb_data)
		printf("\n");
		for (i = 0; i < track.nr; i++) {
	struct transport *transport;
		memset(&refspec, 0, sizeof(refspec));
	} else
	struct ref *ref, *matches;
	if (!remote->push.nr) {
			git_config_set(buf.buf, rename.new_name);
		else
	}
		}
		for_each_string_list(info.list, show_push_info_item, &info);
	return 0;
}
		info.width = 0;
	for (i = 1; i < merge->nr; i++)
	if (argc > 3)


	int url_nr;


		die(_("Invalid old URL pattern: %s"), oldurl);
				     info.list->nr),
			negative_matches++;

	struct known_remote *next;
					item->util ? (const char *)item->util : "");
	N_("git remote get-url [--push] [--all] <name>"),
			item = string_list_append(&states->push, _("(matching)"));
			strbuf_splice(&buf2,
		printf_ln(msg, merge->items[0].string);
	struct string_list remote_branches = STRING_LIST_INIT_DUP;



	else if (!strcmp(argv[0], "update"))
		info.width = 0;
		strbuf_reset(&buf);
};
	struct option options[] = {
		else
		info->width = n;
				  "\t%s\n"
}
	if (all_mode) {
	string_list_clear(&track, 0);
		struct string_list_item *item = branch_list.items + i;
		return 1;
	const struct string_list_item *a = va;
			for (i = 0; i < states.heads.nr; i++)
		else if (branch_info->rebase == REBASE_MERGES)
		*mirror = MIRROR_PUSH;
		return 0;
		{ OPTION_CALLBACK, 0, "mirror", &mirror, "(push|fetch)",
		printf_ln(_("merges with remote %s"), merge->items[0].string);
			string_list_append(&states->new_refs, abbrev_branch(ref->name));
	}
	handle_push_default(rename.old_name, rename.new_name);
		  : _("(no URL)"));
	return 0;
	char *push_remote_name;
	argc = parse_options(argc, argv, NULL, options, builtin_remote_add_usage,
static int set_branches(int argc, const char **argv)
	r->remote = remote;
	struct strbuf buf = STRBUF_INIT, buf2 = STRBUF_INIT;
	if (!starts_with(key, "branch."))
}

	const char **url;
		/* warn */
			url_nr = states.remote->url_nr;
	enum rebase_type rebase;

		OPT_BOOL('\0', "all", &all_mode,
		else if (has_object_file(&ref->old_oid) &&
	memset(&refspec, 0, sizeof(refspec));

					continue;
		for_each_string_list(info.list, show_remote_info_item, &info);

}
		free_remote_ref_states(&states);
		} else if (string_list_has_string(&states->tracked, name))
		OPT_END()

	struct strbuf key = STRBUF_INIT;
}
		old_remote_context = STRBUF_INIT;
			strbuf_addf(&buf, "branch.%s.pushremote", item->string);
}
	};

		item = string_list_append(&states->push, _("(matching)"));
	if (argc < 3 || argc > 4 || ((add_mode || delete_mode) && argc != 3))

	return 0;
		OPT_END()
};
	struct show_info *show_info = cb_data;

	struct branches_for_remote *branches = cb_data;
				     "  Local refs configured for 'git push'%s:",

	N_("git remote show [<options>] <name>"),
	};
};
}

{
		for_each_string_list(&states.tracked, add_remote_to_show_info, &info);
static int append_ref_to_tracked_list(const char *refname,
				int add_mode)
{
			 * TRANSLATORS: the colon ':' should align

			      skipped.nr));
	const char **url;
	printf("    %-*s ", show_info->width, item->string);
		printf("    %-*s", info->width, name);
	const char **urlset;
#include "parse-options.h"
	newremote = remote_get(rename.new_name);
}
		if (states.remote->pushurl_nr) {
			url_nr = states.remote->pushurl_nr;
	char *remote_name;
	if (!dry_run)
	if (!add_mode && remove_all_fetch_refspecs(key.buf)) {
		if (add_mode)
			for (k = keys; *k; k++) {
		type = PUSH_REMOTE;
		git_config_set_multivar(buf.buf, remote->url[i], "^$", 0);
		error(_("Unknown subcommand: %s"), argv[0]);
	N_("git remote set-url [--push] <name> <newurl> [<oldurl>]"),
		memset(&states, 0, sizeof(states));
		return 0;
}

	 */

	item->util = branch_info;
	if (skipped.nr) {
				 " may be one of the following):\n"));
	struct known_remote *kr;
		result = set_url(argc, argv);
	else {
	int width = show_info->width + 4;
		query_flag = (GET_REF_STATES | GET_HEAD_NAMES | GET_PUSH_REF_STATES);
			get_push_ref_states(remote_refs, states);
		strbuf_addf(tmp, "refs/%s:refs/%s",
	enum { REMOTE, MERGE, REBASE, PUSH_REMOTE } type;
	struct strbuf buf = STRBUF_INIT;
	else if (!strcmp(argv[0], "set-url"))
		PARSE_OPT_STOP_AT_NON_OPTION);
	struct push_default_info* info = cb;
	}
		char *ptr;
		struct string_list_item *item = remote_branches.items + i;
		if (info->push_remote_name && !strcmp(info->push_remote_name, remote->name)) {
		strbuf_addstr(&buf, item->string);
			states->remote->url[0] : NULL);
{
	strbuf_addf(&key, "remote.%s.fetch", remotename);
#define MIRROR_FETCH 1
			  "\t%s:%d\n"
				      strlen(rename.old_name), rename.new_name,
	refspec.force = 0;
				 struct ref_states *states,
	if (!states.stale.nr) {
			die(_("renaming '%s' failed"), item->string);

		/* silently skip over other non-remote refs */
		return 0;
	memset(&states, 0, sizeof(states));
	N_("git remote [-v | --verbose] update [-p | --prune] [(<group> | <remote>)...]"),
	}
		urlset_nr = remote->pushurl_nr;
		else if (states.heads.nr == 1)
			info->status = PUSH_STATUS_UPTODATE;
		argv[1] = "-v";
	free_remote_ref_states(&states);
static int verbose;
		strbuf_reset(&buf2);
			string_list_append(&track, "*");
	return result;
				   name, mirror, &buf2);
	string_list_clear(&branches, 0);

		PUSH_STATUS_CREATE = 0,
	struct push_info *info;
		type = REMOTE;
			info->status = PUSH_STATUS_CREATE;
static int get_one_entry(struct remote *remote, void *priv)
static const char * const builtin_remote_prune_usage[] = {
{
		show_info->width = n;

			const char *keys[] = { "remote", "merge", NULL }, **k;
static int get_ref_states(const struct ref *remote_refs, struct ref_states *states)

			 ref_newer(&ref->new_oid, &ref->old_oid))

			printf_ln(_("  HEAD branch: %s"), states.heads.items[0].string);
		result = get_url(argc, argv);
	/* else fetch mode */
#include "remote.h"


static int show_push_info_item(struct string_list_item *item, void *cb_data)
		}
	argv_array_push(&fetch_argv, "--multiple");
{
		strbuf_addf(&url_buf, "%s (fetch)", remote->url[0]);
		return 0;
	} else {
	struct push_info *push_info = item->util;
			     0);
	int i, opt_a = 0, opt_d = 0, result = 0;
		result |= prune_remote(*argv, dry_run);

		die(_("No such remote: '%s'"), argv[1]);

	info->linenr = current_config_line();
	if (remote->mirror)
		*mirror = MIRROR_FETCH;
		 */

	char *dest;
	};
		if (info->push_remote_name && !strcmp(info->push_remote_name, rename.old_name)) {
		if (states.remote->mirror)
				    fetch_map, 1);


				     "  Local branches configured for 'git pull':",
	struct string_list_item *item;
		string_list_append(list, remote->name)->util =
	result = for_each_remote(get_one_entry, &list);
	struct option options[] = {
	int n = strlen(item->string);
	read_branches();

	if (remote->pushurl_nr) {
		OPT_END()


	else if (!arg) {
static const char *abbrev_ref(const char *name, const char *prefix)
	match_push_refs(local_refs, &push_map, &remote->push, MATCH_REFS_NONE);
	}
	N_("git remote set-url [--push] <name> <newurl> [<oldurl>]"),
	N_("git remote set-branches [--add] <name> <branch>..."),
		die(_("no URLs configured for remote '%s'"), remotename);
}
	url = argv[1];
	struct strbuf name_buf = STRBUF_INIT;
	N_("git remote set-url --delete <name> <url>"),
		if (!remote_find_tracking(kr->remote, &refspec))
		if (item->util)
	}
				item->string, buf.buf);

	int i, refspec_updated = 0;
	} else {
		if (!ref_exists(buf2.buf))
N_("--mirror is dangerous and deprecated; please\n"
	int mirror = remote->mirror;
	argv_array_clear(&fetch_argv);
	stale_refs = get_stale_heads(&states->remote->fetch, fetch_map);
	 * First remove symrefs, then rename the rest, finally create
	return result;
		OPT_END()

	}

	add_branches(remote, branches, key.buf);


	warn_dangling_symrefs(stdout, dangling_msg, &refs_to_prune);
	case MERGE: {
	const char *orig_key = key;
}
	return 0;
			arg = _(" tracked");
	free(info);
		return 0;
	int cmp = strcmp(a->string, b->string);
 * Sorting comparison for a string list that has push_info
	argc = parse_options(argc, argv, NULL, options, builtin_remote_sethead_usage,
	strbuf_release(&buf);
			warning(_("Not updating non-default fetch refspec\n"
	if (argc != 1)
	free_refs(local_refs);
{
	rename.old_name = argv[1];

	struct remote *remote;
		argv_array_push(&fetch_argv, prune ? "--prune" : "--no-prune");
	N_("git remote set-url --add <name> <newurl>"),
}
		strbuf_reset(&buf3);
			    N_("or do not fetch any tag at all (--no-tags)"), TAGS_UNSET),

		PUSH_STATUS_FASTFORWARD,
	return 0;
		status = _("up to date");

		if (!i)
	if (remote->url_nr > 0) {
	return 0;
#include "config.h"
		return show_all();


				     "  Remote branches:%s",
			die(_("Could not get fetch map for refspec %s"),
	if (remote_find_tracking(branches->remote, &refspec))
	remote = remote_get(remotename);


		old_name, CONFIG_SCOPE_UNKNOWN, STRBUF_INIT, -1 };
	NULL
	switch (push_info->status) {
			item->util = xstrdup(symref);
}


			strbuf_addf(&buf, "branch.%s.remote", item->string);
	/* don't delete non-remote-tracking refs */
	strbuf_release(&refspec);
};

		usage_with_options(builtin_remote_rename_usage, options);
	struct ref_states *states = cb_data;
	if (fetch && fetch_remote(name))
		const char *refname = item->util;

	int i, prune = -1;
#include "run-command.h"
	return 0;
	else if (!strcmp(arg, "fetch"))
			 N_("delete refs/remotes/<name>/HEAD")),
	for_each_remote(add_known_remote, &known_remotes);
	for (ref = stale_refs; ref; ref = ref->next) {
	get_remote_ref_states(remote, &states, GET_REF_STATES);
		item->util = xstrdup(ref->name);
	argc = parse_options(argc, argv, NULL, options, builtin_remote_seturl_usage,

	} else
		/* remote branch info */
		struct string_list_item *item = branch_list.items + i;
		const char *msg;
	struct ref *ref, *stale_refs;

	struct string_list track = STRING_LIST_INIT_NODUP;
}

};

};
	int i, url_nr;

	if ((n = strlen(branch_item->string)) > show_info->width)
	else if (remote->origin == REMOTE_BRANCHES)
		else
		usage_with_options(builtin_remote_add_usage, options);
	int result;

		if (info.list->nr)
	const char *name, *url;
		if (!default_defined) {

			if (verbose)
		get_remote_ref_states(argv[0], &states, GET_HEAD_NAMES);
static void clear_push_info(void *util, const char *string)
	cb_data.branches = &branches;

		*mirror = MIRROR_BOTH;

			       push_info->dest);

struct known_remotes {

	N_("git remote set-head <name> (-a | --auto | -d | --delete | <branch>)"),
	N_("git remote add [<options>] <name> <url>"),
		status = _("fast-forwardable");
static int config_read_branches(const char *key, const char *value, void *cb)


				die(_("could not unset '%s'"), buf.buf);

	}

		OPT_END()


	struct string_list new_refs, stale, tracked, heads, push;
		oidcpy(&ref->new_oid, &ref->peer_ref->new_oid);
		return;
		get_push_ref_states_noquery(states);
		break;
		break;
	TAGS_DEFAULT = 1,
			PARSE_OPT_OPTARG | PARSE_OPT_COMP_ARG, parse_mirror_opt },
	if (delete_mode)
		OPT_BOOL('\0', "add", &add_mode,
	 * refs, which are invalidated when deleting a branch.
	};
	NULL
	for (i = 0; i < oldremote->fetch.raw_nr; i++) {

 */
	struct ref_states *states = show_info->states;

{
		 * truth value with >= REBASE_TRUE.
{
	strbuf_addch(tmp, '+');
	if (argc != 2)
		return 0;
		info = item->util = xcalloc(1, sizeof(struct push_info));
			url = states.remote->url;
		if (info.list->nr)
		if (starts_with(refname, "refs/heads/"))
			 */
};
static void handle_push_default(const char* old_name, const char* new_name)
	name = xmemdupz(key, key_len);
			arg = _(" stale (use 'git remote prune' to remove)");
static int cmp_string_with_push(const void *va, const void *vb)
	} else {
	 */
}
		return migrate_file(oldremote);
	const struct object_id *oid, int flags, void *cb_data)

	for (i = 0; i < remote_branches.nr; i++) {
			string_list_append(branches->skipped,
	struct ref_states *states;

	remotename = argv[0];
	int forced;
}
	const char *src = item->string, *status = NULL;
	/*
	struct string_list *list = priv;
		else
		strbuf_addf(&url_buf, "%s (push)", url[i]);

	} else if (opt_d && !opt_a && argc == 1) {
	states->remote = remote_get(name);

	return 0;

		printf(fmt, arg);


						item->string, *k);
			refspec_updated = 1;
		result = mv(argc, argv);
	if (not)
	if (verbose)
	else
}

static int get_head_names(const struct ref *remote_refs, struct ref_states *states)
		if (symref && (flag & REF_ISSYMREF))
		OPT_BOOL('a', "auto", &opt_a,
{
	return git_config_set_multivar_gently(key, NULL, NULL, 1);
	struct string_list list = STRING_LIST_INIT_NODUP;

	info = item->util;
			result |= error(_("Could not delete %s"), buf.buf);
			string_list_append(&states->stale, abbrev_branch(ref->name));
	NULL
			  "now names the non-existent remote '%s'"),

		strbuf_addf(&buf3, "remote: renamed %s to %s",
static const char * const builtin_remote_sethead_usage[] = {
		if (query & GET_REF_STATES)
		OPT_STRING_LIST('t', "track", &track, N_("branch"),


};
	};
		else
		result = rm(argc, argv);
		git_config_set_multivar(name_buf.buf, NULL, oldurl, 1);
	string_list_clear(&list, 1);

		strbuf_reset(&buf);
	struct ref_states *states = info->states;
	}
				"remote %s");
		error(_("no remote specified"));
			git_config_set(buf.buf, rename.new_name);
	struct string_list_item *item;
		die(_("No such remote: '%s'"), rename.old_name);

					   abbrev_branch(refname));
static const char mirror_advice[] =
	if (!item->util)
	if (!remote_is_configured(remote, 1))
	const struct object_id *oid, int flags, void *cb_data)
}
	strbuf_addf(&buf, "remote.%s.fetch", rename.new_name);
	N_("git remote add [-t <branch>] [-m <master>] [-f] [--tags | --no-tags] [--mirror=<fetch|push>] <name> <url>"),
	}
		strbuf_reset(&buf);
			printf_ln(_(" * [would prune] %s"),
static int set_head(int argc, const char **argv)
	return 0;
	return 0;
	struct ref_states states;
			else {

	case PUSH_STATUS_UPTODATE:
			printf_ln(_("  Push  URL: %s"), _("(no URL)"));
	return 0;
		}
		}
	if (!delete_mode)
	if (flags & REF_ISSYMREF)
}
#include "refs.h"
		*found = 1;
	const char *symref;
static int show(int argc, const char **argv)
			string_list_append(&info->merge, merge);
		info.width = info.width2 = 0;
	struct branch_info *info;
	if ((n = strlen(push_item->string)) > show_info->width)
			struct string_list_item *item = list.items + i;
	struct remote *remote;
	/* Use the fetch URL when no push URLs were found or requested. */
		handle_push_default(remote->name, NULL);
			 N_("prune remotes after fetching")),
				      ptr-buf2.buf + strlen(":refs/remotes/"),
		break;
	struct known_remotes *all = cb_data;
	}
	}
		OPT_END()
		die(_("--add --delete doesn't make sense"));
	if ((!oldurl && !delete_mode) || add_mode) {

	strbuf_release(&buf2);

	unsigned *mirror = opt->value;
#include "strbuf.h"
				buf2.buf);
	struct refspec_item refspec;
static int get_remote_default(const char *key, const char *value, void *priv)
};
	struct option options[] = {
	strbuf_addf(&buf, "remote.%s.url", name);

				  "\tPlease update the configuration manually if necessary."),
			die(_("creating '%s' failed"), buf.buf);
			 * translation.
		else if (string_list_has_string(&states->stale, name))

		int i;
		OPT_BOOL('\0', "delete", &delete_mode,
	}
	git_config_set(buf.buf, url);
	git_config_set_multivar(key, tmp->buf, "^$", 0);
{
		PUSH_STATUS_DELETE,
	argc = parse_options(argc, argv, NULL, options,
#include "transport.h"
				printf("%s\t%s\n", item->string,
	/* Special cases that add new entry. */

	printf_ln(_("Pruning %s"), remote);
	strbuf_release(&buf);
		remote_refs = transport_get_remote_refs(transport, NULL);
	struct remote *remote;
			 N_("set refs/remotes/<name>/HEAD according to remote")),

	if (delete_mode && !negative_matches && !push_mode)
			 const char *key)
	}
		else
			       fetch_tags == TAGS_SET ? "--tags" : "--no-tags");
	string_list_insert(info->list, item->string);
}

				strbuf_addf(&buf, "branch.%s.%s",
	if (remote->origin == REMOTE_REMOTES)
			return error(_("Could not setup master '%s'"), master);
		url_nr = remote->url_nr;
			     0);
	string_list_clear(&remote_branches, 1);
	if (!remote_is_configured(remote, 1))
	const char *name = item->string;
			old_name);

struct ref_states {

}
	rename.new_name = argv[2];
	for (i = 0; i < remote->url_nr; i++)
#define GET_HEAD_NAMES (1<<1)
	}
	git_config(config_read_push_default, &push_default);
		get_remote_ref_states(*argv, &states, query_flag);
	return 0;
	struct ref *ref, *local_refs, *push_map;

	}
			die(_("could not set '%s'"), "remote.pushDefault");
	r = xmalloc(sizeof(*r));
		OPT_STRING('m', "master", &master, N_("branch"), N_("master branch")),

}
	if (branch_info->rebase >= REBASE_TRUE) {
	else
			     PARSE_OPT_KEEP_ARGV0);
{

		url_nr = remote->url_nr;
struct show_info {
	string_list_clear(&states->heads, 0);
	else
	all->list = r;
		return 0;
};
			printf_ln("%s", url[i]);
		info = item->util = xcalloc(1, sizeof(struct push_info));
	memset(&states, 0, sizeof(states));
		url_nr = remote->pushurl_nr;

		die(_("No such remote '%s'"), remotename);
static int remove_all_fetch_refspecs(const char *key)
	for (i = 0; i < urlset_nr; i++)
	strbuf_reset(&buf);
	int width, width2;
#define MIRROR_NONE 0
	item->util = push_item->util;
	return 0;
	states->push.strdup_strings = 1;

{

	strbuf_release(&buf);
	cb_data.skipped = &skipped;
		info->dest = xstrdup(abbrev_branch(ref->name));
	    !value || strcmp(value, info->old_name))
	if (!remote_is_configured(remote, 1))
	struct show_info info;

			    N_("delete URLs")),
	struct remote *remote;
struct push_info {
	enum {
			 N_("return all URLs")),
	oldremote = remote_get(rename.old_name);
			continue;
			      "Note: Some branches outside the refs/remotes/ hierarchy were not removed;\n"
		OPT_BOOL('\0', "push", &push_mode,
		die(_("Will not delete all non-push URLs"));
};
}
	argc = parse_options(argc, argv, NULL, options, builtin_remote_geturl_usage, 0);
	else
	git_config(config_read_branches, NULL);
	int i;
		string_list_clear(info.list, 0);
			 N_("add URL")),
	if (argc < 1)
	if ((n = strlen(push_info->dest)) > show_info->width2)
	struct remote *remote = states->remote;
	for (; argc; argc--, argv++) {
		else if (!new_name && result && result != CONFIG_NOTHING_SET)
		for_each_string_list(&states.new_refs, add_remote_to_show_info, &info);
		warning("%s", _(mirror_advice));
	if (starts_with(refname, buf.buf)) {
			       abbrev_ref(refname, "refs/remotes/"));
static int read_remote_branches(const char *refname,
#include "string-list.h"
		}

}
		die(_("'%s' is not a valid remote name"), name);
	}
	default:
};
		string_list_append(&states->tracked, abbrev_branch(refspec.src));

	if (remote->mirror)
	string_list_clear(&states->new_refs, 0);
	};
{
{
			printf_ln(_("    %-*s pushes to %-*s (%s)"), show_info->width, src,
	int n;

static int parse_mirror_opt(const struct option *opt, const char *arg, int not)
	struct option options[] = {
		break;
	struct option options[] = {
	struct ref *fetch_map = NULL, **fetch_map_tail = &fetch_map;
	struct push_default_info push_default = {
		urlset = remote->pushurl;
		}
		strbuf_addf(&buf, "refs/remotes/%s/HEAD", name);
	N_("git remote rename <old> <new>"),
	case PUSH_STATUS_CREATE:
				rename.new_name, strlen(rename.new_name));
	struct string_list skipped = STRING_LIST_INIT_DUP;
	git_config_set_multivar(buf.buf, NULL, NULL, 1);

			       push_info->dest);
		oldurl = argv[3];
	else if (!strcmp(argv[0], "get-url"))
}
{
	strbuf_addf(&buf, "remote.%s.fetch", remote->name);
		result |= delete_refs("remote: prune", &refs_to_prune, 0);
static int set_remote_branches(const char *remotename, const char **branches,
	if (!remote_is_configured(remote, 1))
		if (!states.heads.nr)
		git_config(get_remote_default, &default_defined);

#include "argv-array.h"
	}
	NULL
	}
	struct show_info *info = cb_data;
			printf_ln(Q_("  Remote branch:%s",
			get_ref_states(remote_refs, states);
 * structs in its util field
			value = abbrev_branch(space + 1);
	} else {
	name = argv[0];
			printf_ln(_("  HEAD branch: %s"), _("(not queried)"));
	if (push_default.scope >= CONFIG_SCOPE_COMMAND)
		transport = transport_get(states->remote, states->remote->url_nr > 0 ?

		}

   "\t use --mirror=fetch or --mirror=push instead");
	const char *remotename = remote->name;
		PUSH_STATUS_OUTOFDATE,
			    N_("import all tags and associated objects when fetching"),
			warning(_("more than one %s"), orig_key);
	argv_array_push(&fetch_argv, "fetch");
		if (ptr) {
		url_nr = remote->pushurl_nr;
	int n;
	struct option options[] = {
		if (create_symref(buf.buf, buf2.buf, "remote add"))
#include "builtin.h"
	if (strip_suffix(key, ".remote", &key_len))
	string_list_sort(&states->stale);
			}
#define MIRROR_PUSH 2
		usage_with_options(builtin_remote_rm_usage, options);
	if (add_mode && delete_mode)
			N_("set up remote as a mirror to push to or fetch from"),
			info->status = PUSH_STATUS_FASTFORWARD;
	struct strbuf refspec = STRBUF_INIT;
		break;

	item = string_list_append(show_info->list, push_item->string);
		else
	if (strcmp(key, "remotes.default") == 0) {

	struct string_list refs_to_prune = STRING_LIST_INIT_NODUP;
			if (result && result != CONFIG_NOTHING_SET)
		int result = git_config_set_gently("remote.pushDefault",
		strbuf_addf(&buf, "remote.%s.fetch", name);
			char *merge;
		argv_array_push(&fetch_argv, "default");
}
static int config_read_push_default(const char *key, const char *value,
		OPT__VERBOSE(&verbose, N_("be verbose; must be placed before a subcommand")),
			 N_("manipulate push URLs")),
	if (remote_is_configured(newremote, 1))
	states->new_refs.strdup_strings = 1;
	} else if (show_info->any_rebase) {

}
				 int query)
	struct remote *remote;
	int i, result;
	}
	N_("git remote set-url --add <name> <newurl>"),
	const char *newurl = NULL;
static int mv(int argc, const char **argv)
	int matches = 0, negative_matches = 0;



				     info.list->nr),
		return 0;
	case REBASE:
	struct option options[] = {
	struct remote *remote;
	free(info->dest);
		printf_ln("%s", *url);
{
	strbuf_addf(&buf, "remote.%s.url", remote->name);
		char *space = strchr(value, ' ');

static int add_remote_to_show_info(struct string_list_item *item, void *cb_data)

			printf_ln(_(" * [pruned] %s"),
		free(head_name);
	strbuf_release(&name_buf);
		if (git_config_rename_section(buf.buf, NULL) < 1)
	string_list_clear_func(&states->push, clear_push_info);
			result |= error(_("Cannot determine remote HEAD"));
	struct remote *remote;
			printf_ln(_("    %-*s pushes to %s"), show_info->width, src,
static int show_local_info_item(struct string_list_item *item, void *cb_data)

		strbuf_addstr(&buf2, oldremote->fetch.raw[i]);
		while (space) {
		result = prune(argc, argv);
	case PUSH_STATUS_OUTOFDATE:
			continue;
	NULL

	struct refspec_item refspec;
	regex_t old_regex;
	return result;

	TAGS_UNSET = 0,
	refspec.src = refspec.dst = "refs/heads/*";
		} else if (oideq(&ref->old_oid, &ref->new_oid))

{
		if (query & GET_PUSH_REF_STATES)
				skipped.items[i].string);
		info->rebase = rebase_parse_value(value);
	};
{
			return 0;
		struct ref_states states;

	NULL
		git_config_set_multivar(buf.buf, buf2.buf, "^$", 0);
		const char *arg = "";
				item->string, buf.buf);

			fmt = _(" new (next fetch will store in remotes/%s)");
		; /* pass */

	struct string_list *remote_branches;

{
		const struct refspec_item *spec = &remote->push.items[i];
static int fetch_remote(const char *name)
		git_config_set_multivar(buf.buf, remote->push.raw[i], "^$", 0);
	newurl = argv[2];
	}
		printf(_("%-*s    and with remote %s\n"), width, "",
		return error(_("unknown mirror argument: %s"), arg);
	return result ? 1 : 0;
		info->forced = spec->force;
	for_each_string_list_item(item, &states.stale)
	for (ref = matches; ref; ref = ref->next)
/*
		urlset_nr = remote->url_nr;

};
	if (argc < 1)
			printf("%s/HEAD set to %s\n", argv[0], head_name);
			printf_ln(_("  Push  URL: %s"), url[i]);
		free_remote_ref_states(&states);
{
		result = set_head(argc, argv);
		status = _("local out of date");
	string_list_sort(&states->new_refs);

	int fetch = 0, fetch_tags = TAGS_DEFAULT;
static void free_remote_ref_states(struct ref_states *states)
{
static const char * const builtin_remote_setbranches_usage[] = {
		strbuf_reset(&buf2);

static int rm(int argc, const char **argv)
	struct string_list_item *item;
	key += strlen("branch.");
		if (create_symref(buf.buf, buf2.buf, buf3.buf))
		item->util = xcalloc(1, sizeof(struct push_info));
		string_list_clear(info.list, 0);

	}
	struct known_remotes *keep;
			msg = _("rebases onto remote %s");
			item = string_list_append(&states->push, spec->src);
	return 0;
	struct show_info *show_info = cb_data;
	strbuf_reset(tmp);
	struct string_list info_list = STRING_LIST_INIT_NODUP;
		urlset = remote->url;
		if (branch_info->rebase == REBASE_INTERACTIVE)
		OPT_BOOL('n', NULL, &no_query, N_("do not query remotes")),
	free_refs(push_map);

			die(_("could not unset '%s'"), "remote.pushDefault");
	cb_data.keep = &known_remotes;
		const char *fmt = "%s";
	return 0;

	}
	strbuf_release(&buf);
	if (!mirror || mirror & MIRROR_FETCH) {
		argv[2] = name;
	struct branch_info *branch_info = branch_item->util;
		else
	struct strbuf buf = STRBUF_INIT, buf2 = STRBUF_INIT, buf3 = STRBUF_INIT,
		if (!regexec(&old_regex, urlset[i], 0, NULL, 0))
		die(_("remote %s already exists."), name);
	 * the branches one by one, since for_each_ref() relies on cached

struct branches_for_remote {
enum {
		warning(_("The %s configuration remote.pushDefault in:\n"
		else if (!states.heads.nr)
		}
				      strlen(rename.new_name));
	struct string_list *merge = &branch_info->merge;
{
	else if (!strcmp(argv[0], "rm") || !strcmp(argv[0], "remove"))

	case PUSH_STATUS_FASTFORWARD:
	string_list_clear(&states->tracked, 0);

			url = states.remote->pushurl;
	N_("git remote remove <name>"),
	int flag;
	}
	NULL
			 N_("query push URLs rather than fetch URLs")),
	if (!opt_a && !opt_d && argc == 2) {
}
			printf(_("  HEAD branch (remote HEAD is ambiguous,"
		result = set_branches(argc, argv);
	return 0;
		}
			result |= error(_("Not a valid ref: %s"), buf2.buf);
{
		OPT_END()
	struct push_info *info = util;
				printf("    %s\n", states.heads.items[i].string);
	int i;

				N_("branch(es) to track")),
		int flag = 0;
	/*
		usage_with_options(builtin_remote_geturl_usage, options);
			git_config_set(name_buf.buf, newurl);
{
#include "rebase.h"
	NULL
		string_list_append(list, remote->name)->util =
		result = show_all();
static int add_local_to_show_info(struct string_list_item *branch_item, void *cb_data)
			space = strchr(value, ' ');
}

		if (opt_a)
	if (!delete_mode && !matches)
		break;
		for_each_string_list(&states.stale, add_remote_to_show_info, &info);
	for (ref = push_map; ref; ref = ref->next) {
			printf_ln(_("  Local refs will be mirrored by 'git push'"));
	return retval;
		strbuf_reset(&buf);
	remote = remote_get(argv[1]);
	strbuf_addf(&buf, "refs/remotes/%s/", rename->old_name);
	remote = remote_get(remotename);
	if (!remote_find_tracking(states->remote, &refspec))
		? _(" %s will become dangling!")
	memset(&info, 0, sizeof(info));
	struct show_info *show_info = cb_data;
		return 0;
			printf_ln(_("  HEAD branch: %s"), _("(unknown)"));
	switch (type) {
		printf_ln(_("  Fetch URL: %s"), states.remote->url_nr > 0 ?
	for (i = 0; i < branch_list.nr; i++) {
		OPT_END()
static const char * const builtin_remote_show_usage[] = {
		strbuf_splice(&buf2, strlen("refs/remotes/"), strlen(rename.old_name),
}

		oldurl = newurl;
	r->next = all->list;
	return name;
	if (branch_list.nr)
		return error(_("Could not fetch %s"), name);
	struct remote *remote = states->remote;
	struct strbuf url_buf = STRBUF_INIT;
	memset(&refspec, 0, sizeof(refspec));
		OPT__DRY_RUN(&dry_run, N_("dry run")),
		if (no_query)
	const char *old_name;
		for (i = 0; i < url_nr; i++)
	char *name;
	if (argc == 0) {
}
static int set_url(int argc, const char **argv)
		for_each_string_list(&branch_list, add_local_to_show_info, &info);

			warning(_("more than one %s"), orig_key);
	}
static int prune_remote(const char *remote, int dry_run)
			item = string_list_append(&states->push, _("(delete)"));
	int i, push_mode = 0, add_mode = 0, delete_mode = 0;

}
		status = _("create");
		else
static int get_push_ref_states_noquery(struct ref_states *states)
	int retval;
			info->status = PUSH_STATUS_DELETE;
	strbuf_addf(&buf, "remote.%s.push", remote->name);
					  "Please choose one explicitly with:"));
#define abbrev_branch(name) abbrev_ref((name), "refs/heads/")


	}
			git_config_set_multivar(name_buf.buf, newurl,
	if (!url_nr) {
		: _(" %s has become dangling!");
	for (i = 0; i < url_nr; i++)
		if (!ref->peer_ref || !ref_exists(ref->peer_ref->name))
		       merge->items[i].string);

		for_each_ref(append_ref_to_tracked_list, states);
static int get_remote_ref_states(const char *name,
	return 0;
		strbuf_addf(&buf, "refs/remotes/%s/HEAD", argv[0]);
		return error(_("No such remote: '%s'"), name);
		else if (create_symref(buf.buf, buf2.buf, "remote set-head"))
			arg = _(" ???");

	if (argc != 3)
	 * the new symrefs.
		/* git pull info */
	int result = 0;
	N_("git remote prune [-n | --dry-run] <name>"),
			       show_info->width2, push_info->dest, status);
	}
static void add_branches(struct remote *remote, const char **branches,
	N_("git remote prune [<options>] <name>"),
	struct known_remote *r;

	int no_query = 0, result = 0, query_flag = 0;
	strbuf_reset(&buf);
	struct argv_array fetch_argv = ARGV_ARRAY_INIT;
		break;
	N_("git remote [-v | --verbose]"),
	item = string_list_insert(&branch_list, name);
		/* advise user how to delete local branches */
{
		git_config_set(buf.buf, "true");
		struct branch_info *info = item->util;
	if (!valid_fetch_refspec(buf2.buf))
static void read_branches(void)
		show_info->width = n;
	if (status) {
static const char * const builtin_remote_update_usage[] = {
		fprintf_ln(stderr,
	struct string_list_item *item;
	if (regcomp(&old_regex, oldurl, REG_EXTENDED))
	strbuf_release(&key);
	}
	struct string_list_item *item;
	if (argc < 2)
	push_map = copy_ref_list(remote_refs);
		info->dest = xstrdup(spec->dst ? spec->dst : item->string);
	else if (!strcmp(argv[0], "rename"))
		if (query & GET_HEAD_NAMES)
		item = string_list_append(rename->remote_branches, refname);
struct branch_info {
	string_list_sort(&refs_to_prune);

	const struct string_list_item *b = vb;

		git_config_set_multivar(buf.buf, remote->fetch.raw[i], "^$", 0);
	states->stale.strdup_strings = 1;
	else if (strip_suffix(key, ".merge", &key_len))

		else
	return 0;
}
};
	int result;
			die(_("deleting '%s' failed"), item->string);
	struct option options[] = {
	printf_ln(_("URL: %s"),
			     0);
			item->string);
		struct string_list_item *item =
}
		info->forced = ref->force;
		OPT_SET_INT(0, "tags", &fetch_tags,
		if (push_info->forced)
			       abbrev_ref(refname, "refs/remotes/"));
	enum config_scope scope;
			printf_ln(_("    %-*s forces to %-*s (%s)"), show_info->width, src,

	return set_remote_branches(argv[0], argv + 1, add_mode);
		unlink_or_warn(git_path("remotes/%s", remote->name));
	struct string_list_item *item;
	}
	result = for_each_ref(add_branch_for_removal, &cb_data);

		/*
		struct branch_info *info = item->util;
};
		item->util = xcalloc(1, sizeof(struct branch_info));
		return 0;
		int url_nr;

		if (!ref->peer_ref)
	}
{
		die(_("'%s' is not a valid remote name"), rename.new_name);

		break;
		strbuf_addf(&buf2, "refs/remotes/%s/%s", name, master);
	get_fetch_map(remote_refs, &refspec, &fetch_map_tail, 0);
	if (master) {
		break;
		struct string_list_item *item;
	struct ref_states states;
	if (mirror && master)

{
			result = git_config_set_gently(buf.buf, NULL);
		die(_("specifying branches to track makes sense only with fetch mirrors"));

		} else
					die(_("could not unset '%s'"), buf.buf);
			msg = _("rebases interactively onto remote %s");
{
	return 0;
	item = string_list_insert(show_info->list, branch_item->string);
	string_list_clear(&skipped, 0);
	if (!url_nr)
			config_scope_name(push_default.scope),
		if (dry_run)
{
	struct strbuf buf = STRBUF_INIT;
			head_name = xstrdup(states.heads.items[0].string);


{
		return 1;

		string_list_sort(&states->tracked);
	if (!states->remote)
	for (i = 0; i < remote->push.raw_nr; i++)
	if (states->queried) {
	else if (push_default.scope >= CONFIG_SCOPE_LOCAL) {
		usage_with_options(builtin_remote_prune_usage, options);
	} else {
	states->push.strdup_strings = 1;
	for_each_string_list_item(item, &states.stale) {
	return 0;
		head_name = xstrdup(argv[1]);
				rename.new_name, strlen(rename.new_name));
					    NULL, &flag);

		refspec.dst = (char *)refname;
		transport_disconnect(transport);
	if (!branch_info->merge.nr || !branch_info->remote_name ||
	else if (!strcmp(argv[0], "add"))
static int show_all(void)

	}
struct push_default_info
		strbuf_reset(&buf2);
		unlink_or_warn(git_path("branches/%s", remote->name));
	return result;

	for (i = 0; i < branch_list.nr; i++) {
		show_info->width2 = n;
		return error(_("Could not rename config section '%s' to '%s'"),

		strbuf_addf(&buf2, "refs/remotes/%s/%s", argv[0], head_name);
	char *head_name = NULL;
		int i;
	for (; argc; argc--, argv++)
		string_list_append(&info->merge, xstrdup(value));
	else if (!strcmp(argv[0], "show"))
	/* don't delete a branch if another remote also uses it */
	strbuf_reset(&buf);
	info.states = &states;
	struct rename_info *rename = cb_data;
	int i;
	string_list_clear(&refs_to_prune, 0);

	if (prune != -1)
			}
static int migrate_file(struct remote *remote)
		info->dest = xstrdup(item->string);
};
	} else
		url = remote->pushurl;
{
	remote = remote_get(remotename);
		free_remote_ref_states(&states);
	struct remote *remote;
{
	return cmp ? cmp : strcmp(a_push->dest, b_push->dest);
static int get_push_ref_states(const struct ref *remote_refs,
	else if (!strcmp(argv[0], "set-branches"))
	else if (!strcmp(argv[0], "set-head"))
	if (run_command_v_opt(argv, RUN_GIT_CMD))
	else if (!strcmp(arg, "push"))
int cmd_remote(int argc, const char **argv, const char *prefix)
	if (argc < 1)
{
	read_branches();
	}
	string_list_sort(&states->tracked);

			result |= error(_("Multiple remote HEAD branches. "
		struct string_list_item *item = remote_branches.items + i;
	int i;
}
	local_refs = get_local_heads();
		type = REBASE;

		for (i = 0; i < skipped.nr; i++)
	}
	for (i = 0; i < remote->push.nr; i++) {
	}
	return 0;
	argc = parse_options(argc, argv, NULL, options, builtin_remote_show_usage,
		printf_ln(_(" merges with remote %s"), merge->items[0].string);
				strbuf_detach(&url_buf, NULL);
	refspec.dst = (char *)refname;
	int i;
		else if (strlen(spec->src))
		if (push_info->forced)



}
	N_("git remote set-branches <name> <branch>..."),

	struct remote *to_delete;
	printf_ln(_("Updating %s"), name);
	else if (!strcmp(argv[0], "prune"))
#include "refspec.h"
		return 0;
static int get_url(int argc, const char **argv)
out:
	}
	struct string_list *list;

		add_branch(key, *branches, remotename, mirror, &refspec);
	strbuf_addf(&buf2, "remote.%s", rename.new_name);
		strbuf_addstr(&buf2, item->util);
	if (!starts_with(refname, "refs/remotes/")) {
	if (head_name) {

		if (delete_ref(NULL, item->string, NULL, REF_NO_DEREF))

	strbuf_reset(&buf);
		OPT_BOOL('p', "prune", &prune,

}
				fprintf(stderr, "  git remote set-head %s %s\n",
	struct remote *oldremote, *newremote;
	for (i = 0; i < remote_branches.nr; i++) {
	N_("git remote rename <old> <new>"),
#define GET_PUSH_REF_STATES (1<<2)
	struct string_list merge;
	if (branch_info->rebase >= REBASE_TRUE && branch_info->merge.nr > 1) {
		  ? states.remote->url[0]
}
				strbuf_detach(&url_buf, NULL);
		url = remote->url;
#define GET_REF_STATES (1<<0)
	free_refs(fetch_map);
	info->scope = current_config_scope();
	if (push_mode) {
	for (i = 1; i < argc; i++)
static int add(int argc, const char **argv)
	struct option options[] = {
	} else {

	int default_defined = 0;
		string_list_append(&refs_to_prune, item->util);
			msg = _("rebases interactively (with merges) onto "
	return 0;
struct known_remote {
		ptr = strstr(buf2.buf, old_remote_context.buf);
	if (push_mode) {
	} else if (push_default.scope >= CONFIG_SCOPE_SYSTEM) {
		die(_("remote %s already exists."), rename.new_name);
		       const char *remotename, int mirror, struct strbuf *tmp)
		strbuf_addf(&name_buf, "remote.%s.url", remotename);

				  no_query ? _(" (status not queried)") : "");

				branchname, branchname);
		show_info->any_rebase = 1;
				if (result && result != CONFIG_NOTHING_SET)
};
static const char * const builtin_remote_add_usage[] = {
	unsigned mirror = MIRROR_NONE;

};
		if (!item->util)
	NULL
};
		item = string_list_append(&states->push,
		argv_array_push(&fetch_argv, "-v");
		for_each_string_list(info.list, show_local_info_item, &info);
		info->push_remote_name = xstrdup(value);
	argv[argc] = NULL;
		strbuf_reset(&buf2);
	argc = parse_options(argc, argv, NULL, options, builtin_remote_prune_usage,

	struct known_remotes known_remotes = { NULL, NULL };
		       states.remote->url[0] : _("(no URL)"));
		} else {
	}
		info->status = PUSH_STATUS_NOTQUERIED;
	free_refs(matches);
	for (i = 0; i < remote->fetch.raw_nr; i++)
	}
{

	for (; *branches; branches++)
	const char *remotename = NULL;
	N_("git remote set-head <name> (-a | --auto | -d | --delete | <branch>)"),
			matches++;
	if (strcmp(fetch_argv.argv[fetch_argv.argc-1], "default") == 0) {
	N_("git remote [-v | --verbose] show [-n] <name>"),
	struct show_info *show_info = cb_data;

	struct rename_info rename;
				result = git_config_set_gently(buf.buf, NULL);
		result = show(argc, argv);

static int update(int argc, const char **argv)
{
			return error(_("Could not remove config section '%s'"), buf.buf);
	{
static const char * const builtin_remote_seturl_usage[] = {
	strbuf_addf(&old_remote_context, ":refs/remotes/%s/", rename.old_name);
	N_("git remote get-url [--push] [--all] <name>"),
{
		OPT_END()
static const char * const builtin_remote_rename_usage[] = {
static int add_push_to_show_info(struct string_list_item *push_item, void *cb_data)
	}
	rename.remote_branches = &remote_branches;
	}
		OPT_BOOL('\0', "push", &push_mode,
		return 0;
	struct option options[] = {

						   new_name);
		strbuf_addf(&buf2, "remote: renamed %s to %s",
	struct string_list *branches, *skipped;
	remote = remote_get(name);
	for (i = 0; i < states->remote->fetch.nr; i++)
	if (branch_info->rebase >= REBASE_TRUE)
	read_branches();

				states->remote->fetch.raw[i]);
	int i, push_mode = 0, all_mode = 0;
	NULL
		 * Consider invalid values as false and check the
				buf.buf, buf2.buf);

		for (i = 0; i < list.nr; i++) {
	int add_mode = 0;
				printf("%s\n", item->string);
	const char *argv[] = { "fetch", name, NULL, NULL };
	if (argc)

{

	strbuf_addf(&buf, "refs/heads/test:refs/remotes/%s/test", rename.new_name);

	size_t key_len;
	void *cb)
	strbuf_release(&buf);
		int *found = priv;
	return result;
		usage_with_options(builtin_remote_sethead_usage, options);
	if (mirror & MIRROR_PUSH) {
		strbuf_reset(&buf);

	cb_data.remote = remote;
		result = update(argc, argv);
	refspec.pattern = 1;


			       show_info->width2, push_info->dest, status);
		string_list_append(&states->heads, abbrev_branch(ref->name));
	for_each_ref(read_remote_branches, &rename);
		die(_("No such remote '%s'"), remotename);
		die(_("No such URL found: %s"), oldurl);
		argv_array_push(&fetch_argv, argv[i]);
			     0);
	if (n > info->width)


	return 0;
				     info.list->nr));
	for (i = 0; i < remote_branches.nr; i++) {
	};

	const char *old_name;
		result = add(argc, argv);

		if (info->push_remote_name)
	states->tracked.strdup_strings = 1;
			    TAGS_SET),
	    strcmp(states->remote->name, branch_info->remote_name))
#include "object-store.h"
	struct ref *fetch_map = NULL, **tail = &fetch_map;
	refspec.dst = (char *)refname;
						       "^$", 0);

	regfree(&old_regex);
	const struct push_info *a_push = a->util;
{
	struct branches_for_remote cb_data;

	const char *remotename = NULL;
{
	}
		OPT_END()
static int prune(int argc, const char **argv)
	int linenr;
static const char * const builtin_remote_rm_usage[] = {
		if (!(flag & REF_ISSYMREF))
	struct branch_info *branch_info = item->util;

	if (query) {
		read_ref_full(item->string, RESOLVE_REF_READING, NULL, &flag);
	};
	if (mirror && !(mirror & MIRROR_FETCH) && track.nr)
{
	int queried;
		BUG("unexpected type=%d", type);
			result |= error(_("Could not setup %s"), buf.buf);
		OPT_BOOL('f', "fetch", &fetch, N_("fetch the remote branches")),
	const struct ref *remote_refs;
		strbuf_addf(&buf, "remote.%s.tagopt", name);
	struct string_list branches = STRING_LIST_INIT_DUP;
	if (remote_is_configured(remote, 1))
		string_list_clear(info.list, 0);

		if (info.list->nr)
	struct strbuf buf = STRBUF_INIT;
			 * with the one in " Fetch URL: %s"
	const char *master = NULL;
		for (i = 0; i < url_nr; i++)
		else {
	int any_rebase;
		die(_("No such remote '%s'"), remotename);
			/*

		struct push_info *info;
	info.list = &info_list;
	}

static int add_branch_for_removal(const char *refname,
	struct option options[] = {
		info.any_rebase = 0;
	struct show_info *info = cb_data;
	}
	return 0;
			continue;
	list.strdup_strings = 1;
		if (new_name && result && result != CONFIG_NOTHING_SET)
			string_list_append(&states->tracked, abbrev_branch(ref->name));
	case PUSH_STATUS_DELETE:
	retval = run_command_v_opt(fetch_argv.argv, RUN_GIT_CMD);
	if (!strcmp(rename.old_name, rename.new_name) && oldremote->origin != REMOTE_CONFIG)

}

		printf("    %s\n", name);
			info->status = PUSH_STATUS_OUTOFDATE;
		goto out;

		strbuf_release(&key);

		OPT_BOOL('\0', "add", &add_mode, N_("add branch")),
		strbuf_addf(&buf, "remote.%s", remote->name);
			argv_array_pop(&fetch_argv);
			      "to delete it, use:",
	} else if (opt_a && !opt_d && argc == 1) {
		error(_("invalid branch.%s.merge; cannot rebase onto > 1 branch"),
	return 0;
	if (verbose) {
}
	return 0;
	 * We cannot just pass a function to for_each_ref() which deletes
	const struct object_id *oid, int flags, void *cb_data)
		if (track.nr == 0)
		if (get_fetch_map(remote_refs, &states->remote->fetch.items[i], &tail, 1))
		string_list_sort(&list);

	if (!valid_fetch_refspec(buf.buf))
	return result;
			strbuf_addf(&buf, "branch.%s.pushremote", item->string);
		OPT_END()
		if (delete_ref(NULL, buf.buf, NULL, REF_NO_DEREF))
			printf_ln(Q_("  Local ref configured for 'git push'%s:",
			strbuf_reset(&buf);
		strbuf_addf(&name_buf, "remote.%s.pushurl", remotename);
		if (string_list_has_string(&states->new_refs, name)) {
				if (i && !strcmp((item - 1)->string, item->string))
	argc = parse_options(argc, argv, NULL, options, builtin_remote_update_usage,
};

{
		else

{
	}
	strbuf_addf(&buf, "remote.%s", rename.old_name);
		git_config_set(buf.buf,


			      "to delete them, use:",
		usage_with_options(builtin_remote_usage, options);
	struct known_remote *list;

		states->queried = 1;
	strbuf_reset(&info->origin);
	known_remotes.to_delete = remote;
			strbuf_reset(&buf);
	for (ref = fetch_map; ref; ref = ref->next) {

{

		/* make sure it's valid */
		value = abbrev_branch(value);

		symref = resolve_ref_unsafe(refname, RESOLVE_REF_READING,
	struct ref_states *states)
	if (!remote_is_configured(oldremote, 1))

	states->heads.strdup_strings = 1;
			fprintf(stderr, "  git branch -d %s\n",

			   Q_("Note: A branch outside the refs/remotes/ hierarchy was not removed;\n"
}

	const char *oldurl = NULL;
				  no_query ? _(" (status not queried)") : "");
		strbuf_splice(&buf, strlen("refs/remotes/"), strlen(rename.old_name),
			argv_array_push(&fetch_argv, "--all");
			push_default.origin.buf, push_default.linenr,
			printf_ln(_("    %-*s forces to %s"), show_info->width, src,
	struct push_info *push_info = push_item->util;
	skip_prefix(name, prefix, &name);

			     PARSE_OPT_KEEP_ARGV0);
	if (argc != 2)
	if (!no_query)
		else if (is_null_oid(&ref->old_oid))
	struct strbuf origin;
		width++;
		usage_with_options(builtin_remote_setbranches_usage, options);


		die(_("specifying a master branch makes no sense with --mirror"));
		if (spec->matching)
		const char **url;
		for_each_string_list(&states.push, add_push_to_show_info, &info);
	argc = parse_options(argc, argv, prefix, options, builtin_remote_usage,

		if (info->remote_name)
	if (git_config_rename_section(buf.buf, buf2.buf) < 1)
	if (strcmp(key, "remote.pushdefault") ||
					argv[0], states.heads.items[i].string);
		url = remote->pushurl;
		type = MERGE;
		break;
				strbuf_reset(&buf);
		src = _("(none)");
	strbuf_addstr(&info->origin, current_config_name());
		PUSH_STATUS_UPTODATE,
	else if (strip_suffix(key, ".pushremote", &key_len))
	if (fetch_tags != TAGS_DEFAULT) {
	N_("git remote update [<options>] [<group> | <remote>]..."),

			add_branch(buf.buf, track.items[i].string,
			merge = xstrndup(value, space - value);
}
			continue;
			     builtin_remote_setbranches_usage, 0);
		struct string_list_item *item = remote_branches.items + i;
	struct refspec_item refspec;
		info = item->util;
	NULL
static int add_known_remote(struct remote *remote, void *cb_data)
	if (!strcmp(all->to_delete->name, remote->name))
	string_list_append(branches->branches, refname);
			printf_ln(Q_("  Local branch configured for 'git pull':",
		strbuf_splice(&buf, strlen("refs/remotes/"), strlen(rename.old_name),
	if (!result)
}
	if (mirror)
	matches = guess_remote_head(find_ref_by_name(remote_refs, "HEAD"),
		} else
		return 0;
			strbuf_reset(&buf);
		else if (states.heads.nr > 1) {
			item->util = NULL;
		  states.remote->url_nr
	case PUSH_REMOTE:
		result = delete_refs("remote: remove", &branches, REF_NO_DEREF);

static const char * const builtin_remote_usage[] = {
	}
		if (info->remote_name && !strcmp(info->remote_name, remote->name)) {
		usage_with_options(builtin_remote_seturl_usage, options);

		return 0;
	free_refs(stale_refs);
	if (!result) {
	}
		if (info->remote_name && !strcmp(info->remote_name, rename.old_name)) {

					  abbrev_branch(ref->peer_ref->name));

struct rename_info {

	strbuf_addf(&buf2, "refs/heads/test:refs/remotes/%s/test", name);
	};

	free_refs(fetch_map);
	N_("git remote set-url --delete <name> <url>"),
{
		if (is_null_oid(&ref->new_oid)) {
	case REMOTE:
{
		printf_ln(_("* remote %s"), *argv);
	struct strbuf buf = STRBUF_INIT, buf2 = STRBUF_INIT;

		/* git push info */



		QSORT(info.list->items, info.list->nr, cmp_string_with_push);
		strbuf_reset(&buf);
		status = _("delete");
		OPT_SET_INT(0, NULL, &fetch_tags,
		strbuf_addf(&buf, "remote.%s.mirror", name);
		PUSH_STATUS_NOTQUERIED
	if (!result) {
	return 0;
		OPT_BOOL('d', "delete", &opt_d,
	strbuf_release(&buf2);
		url = remote->url;
#include "commit-reach.h"
}
		info->remote_name = xstrdup(value);

		git_config_set_multivar(name_buf.buf, newurl, oldurl, 0);

	memset(&cb_data, 0, sizeof(cb_data));
	}
#define MIRROR_BOTH (MIRROR_FETCH|MIRROR_PUSH)
static void add_branch(const char *key, const char *branchname,
	const char *new_name;
static const char * const builtin_remote_geturl_usage[] = {
	const char *dangling_msg = dry_run
	url_nr = 0;
			arg = states->remote->name;
	const struct push_info *b_push = b->util;
		}

				branchname, remotename, branchname);
