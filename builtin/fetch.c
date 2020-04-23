
	struct ref *rm;
		 * command-line arguments, the destination ref might
	/* Now append any refs to be updated opportunistically: */
			    remote, result);
{
#include "config.h"
	fclose(fp);
#include "sigchain.h"
static void check_not_current_branch(struct ref *ref_map)


	free(url);
	if (rs->nr) {
	strbuf_addstr(&l, local);
						       summary_width);
		return 1;
static inline void fetch_one_setup_partial(struct remote *remote)

		} else {
	nlen = strlen(needle);
	if (!update_head_ok)
		old_nr = oids->nr;
static int check_exist_and_connected(struct ref *ref_map)
			backfill_tags(transport, ref_map);
		result = fetch_multiple(&list, max_children);
int cmd_fetch(int argc, const char **argv, const char *prefix)
}
					strbuf_addf(&note, "%s ", kind);
			format_display(display, r ? '!' : 't', _("[tag update]"),
		 */
			   int flag, void *cbdata)
	struct ref *ref, *stale_refs = get_stale_heads(rs, ref_map);
			expand_list_objects_filter_spec(&filter_options);
	if (all) {
}
	return ref_map;
}
	int maybe_prune_tags;

			default:
		must_list_refs = 0;
	}
	argv_array_push(&cp->args, remote);
static int fetch_finished(int result, struct strbuf *out,
{
	if (!remote->skip_default_update)
{
 abort:
	char *url;
		/* Use the defaults */
}

			    !oidset_contains(&fetch_oids, &item->oid))
			die(_("fetch --all does not make sense with refspecs"));
#define PRUNE_TAGS_BY_DEFAULT 0 /* do we prune tags by default? */
			die(_("--filter can only be used with the remote "
			what = _("[new ref]");
	if (deepen_relative)
		}
			struct object_id oid;
	int retcode = 0;
	FILE *fp = fopen_for_writing(filename);
	transport_set_option(transport, TRANS_OPT_DEEPEN_RELATIVE, NULL);
	if (compact_format) {
		if (rm->status == REF_STATUS_REJECT_SHALLOW ||
		url = xstrdup("foreign");

	return df_conflict ? STORE_REF_ERROR_DF_CONFLICT
static const char warn_show_forced_updates[] =
		} else if (forced_updates_ms > FORCED_UPDATES_DELAY_WARNING_IN_MS) {
	}
		? transport->smart_options->connectivity_checked : 0;
		remote = remote_get(NULL);


		return;
				ref->force = rm->peer_ref->force;
		refspec_ref_prefixes(rs, &ref_prefixes);
	/* if not appending, truncate FETCH_HEAD */
			       remote, pretty_ref, summary_width);

	if (!strcmp(k, "fetch.showforcedupdates")) {
	if (!append && !dry_run) {

			commit_graph_flags |= COMMIT_GRAPH_WRITE_PROGRESS;
		forced_updates_ms += (getnanotime() - t_before) / 1000000;
	return 0;

		 * fetch.
		die(_("depth %s is not a positive number"), depth);
	} else if (refmap.nr) {
	struct ref *rm;
	}
	OPT__FORCE(&force, N_("force overwrite of local reference"), 0),
			refspec_append(&rs, tag);
	if (type < 0)
					fprintf(stderr, _("From %.*s\n"),
		struct ref *rm;
	remote = state->remotes->items[state->next++].string;
	}
			what = _("[new tag]");
	git_config_get_string_const("fetch.output", &format);
	/*
		 * Keep the new pack's ".keep" file around to allow the caller
	if (unshallow) {
	add_options_to_argv(&argv);
	else if (!strcasecmp(format, "compact"))
		format_display(display, r ? '!' : '+', quickref.buf,
		    N_("allow updating of HEAD ref")),
				    remote->fetch.items[i].dst[0])
   " to avoid this check.\n");

		const char *refname = remote_ref_item->string;

	if (skip_prefix(key, "remotes.", &key) && !strcmp(key, g->name)) {
	 * objects reachable.  Running rev-list here will return with
		r = s_update_ref(msg, ref, 0);
						struct refname_hash_entry, ent);
	transport = transport_get(remote, NULL);
				break;
	 */
static struct option builtin_fetch_options[] = {
		}
}
				       remote, pretty_ref, summary_width);

	if (!strcmp(k, "fetch.prunetags")) {
		 * at a nonexisting branch.  If we were indeed called by

	rlen   = utf8_strwidth(prettify_refname(ref->name));
}
	if (tags == TAGS_SET)
		else
				die(_("Fetching a group and specifying refspecs does not make sense"));
	OPT_BOOL('k', "keep", &keep, N_("keep downloaded pack")),
				strbuf_addf(&note, "'%s' of ", what);
	for (i = 0; i < argc; i++) {
				rc |= update_local_ref(ref, what, rm, &note,
}
		for (rm = ref_map; rm; rm = rm->next) {
static int parse_refmap_arg(const struct option *opt, const char *arg, int unset)

	free(msg);
		max = max * 2 / 3;
{
	if (!rla)
		 * from the tags option so that one of the latter,
	struct ref **rm = cb_data;
}
		uint64_t t_before = getnanotime();
		llen = 0;
			if (has_merge &&
	else
				shown_url = 1;
		 * entries, so we set them FETCH_HEAD_IGNORE below.
	if (!remote)
	prepare_format_display(ref_map);
			 * Note: has_merge implies non-NULL branch->remote_name

			if (ref) {
		   PARSE_OPT_HIDDEN, option_fetch_parse_recurse_submodules },
	struct hashmap existing_refs;
	if (tags == TAGS_SET || tags == TAGS_DEFAULT) {
		else if (0 <= fetch_prune_config)
#include "connected.h"
		string_list_clear(&refnames, 0);
}

	}
	 * If this is a partial-fetch request, we enable partial on
		struct parallel_fetch_state state = { argv.argv, list, 0, 0 };
fail:

		return 0;
		if (depth)
	return ret;


		 * configured refspec.  In these cases, we want to


#define PRUNE_BY_DEFAULT 0 /* do we prune by default? */
	OPT_INTEGER(0, "deepen", &deepen_relative,
		if (ref_prefixes.argc)
	strbuf_release(&note);
	if (cannot_reuse) {
		rm = rm->next;
	argv_array_pushv(&cp->args, state->argv);

	}
	if (remote) {
			strbuf_release(&sb);
static int fetch_write_commit_graph = -1;
	if (!strcmp(k, "fetch.prune")) {
			unsigned int hash = strhash(refname);
			return errcode;
	while (ref && ref->status == REF_STATUS_REJECT_SHALLOW)
	if (set_upstream) {
						      branch->name,
		   N_("deepen history of shallow repository based on time")),

		}
				string_list_append_nodup(g->list,
			if (rm->peer_ref) {
}
	if (!find_and_replace(&r, local, "*"))
	refspec_clear(&rs);
			}
static int s_update_ref(const char *action,
		 * remote-tracking reference.  However, we do not want
	for (ref = refs; ref; ref = ref->next) {
		printf(_("Fetching %s\n"), remote);
			rm->fetch_head_status = FETCH_HEAD_MERGE;
}
	struct ref **tail = &ref_map;
		 * take the opportunity to update their configured
						    &options,
				add_merge_config(&ref_map, remote_refs, branch, &tail);
						 &ref->old_oid, 1);
			/*
		}
				fprintf(stderr, _("From %.*s\n"), url_len, url);
}
		return 0;
		    (remote->fetch.nr ||
	if (fetch_refs(transport, ref_map) || consume_refs(transport, ref_map)) {
		    N_("deepen history of shallow clone")),
					note.buf);
	if (raw_url)

	if (update_head_ok)
		if (refmap.nr)
	int url_len, i, rc = 0;



		 * explicitly (via command line or configuration); we
	struct string_list list = STRING_LIST_INIT_DUP;
		   N_("prepend this to submodule path output"), PARSE_OPT_HIDDEN },
			if (!ref_map)
			prune = fetch_prune_config;
		gtransport->server_options = &server_options;
						    &fetch_next_remote,
			free(tag);
		ref_map = NULL;
			 *
	sigchain_push_common(unlock_pack_on_signal);
		url = xstrdup("foreign");
		gsecondary = NULL;
		if (0 <= remote->prune)
	} else if (force || ref->force) {
		    !oidset_contains(&fetch_oids, &item->oid))
		struct branch *branch = branch_get(NULL);
		if (transport->remote->fetch_tags == -1)
	if (4 < i && !strncmp(".git", url + i - 3, 4))
				;
			   (const char *)&deepen_not);
{
static void format_display(struct strbuf *display, char code,
	return 0;
		compact_format = 0;

					shown_url = 1;
	}
		return error_errno(_("cannot open %s"), filename);
		/*
		 * 'git pull', it will notice the misconfiguration because
		/*
			/* Zero or one remotes */
	struct argv_array argv_gc_auto = ARGV_ARRAY_INIT;
		/*
			}
		 * Nicely describe the new ref we're fetching.
		} else {
		;
	if (ends_with(haystack->buf, needle))
		 * Base this on the remote's ref name, as it's
		if (force || ref->force) {

static struct strbuf default_rla = STRBUF_INIT;
	strbuf_release(&l);
				struct ref ***tail)
						    submodule_prefix,
		refspec_append(&rs, TAG_REFSPEC);
			BUG("unseen remote ref?");
	 */
	gtransport = NULL;
}
		error(_("some local refs could not be updated; try running\n"

	string_list_clear(&list, 0);
static int fetch_one(struct remote *remote, int argc, const char **argv, int prune_tags_ok)
	else if (tags == TAGS_DEFAULT && *autotags)
	struct branch *current_branch = branch_get(NULL);
	 * a good (0) exit status and we'll bypass the fetch that we
	char *url;
	 * when remote helper is used (setting it to an empty string
	     the_repository->settings.fetch_write_commit_graph)) {

		strbuf_addstr(&quickref, "..");
			prune = PRUNE_BY_DEFAULT;

	struct hashmap existing_refs;
{
		recurse_submodules = parse_fetch_recurse_submodules_arg(k, v);
		ref = ref->next;


	if (update_shallow)
	if (filter_options.no_filter)
	return !!hashmap_get_from_hash(map, strhash(refname), refname);
		die(_("configuration fetch.output contains invalid value %s"),
static int truncate_fetch_head(void)
		}
		 * by ref_remove_duplicates() in favor of one of these
#include "refs.h"

#include "commit-graph.h"
	const char *pretty_ref = prettify_refname(ref->name);
		strbuf_release(&quickref);
		struct argv_array options = ARGV_ARRAY_INIT;
		 N_("fetch from all remotes")),
		    "remote name from which new revisions should be fetched."));

}
		transport_unlock_pack(gtransport);
		/* split list by white space */
				get_fetch_map(remote_refs, &remote->fetch.items[i], &tail, 0);
	if (deepen && deepen_not.nr)
	if (oideq(&ref->old_oid, &ref->new_oid)) {
		trace2_region_leave("fetch", "fetch_refs", the_repository);
static void set_option(struct transport *transport, const char *name, const char *value)
	if (keep)
	OPT_SET_INT('t', "tags", &tags,
{
		free_refs(ref_map);
		result = delete_refs("fetch: prune", &refnames, 0);
		if (deepen_relative < 0)
	/*
	return 1;
		refcol_width = rlen;
				break;
		    refname_hash_exists(&existing_refs, ref->name))
		return -1;
	atexit(unlock_pack);
		 */
			   const char *remote, const char *local,
		struct string_list refnames = STRING_LIST_INIT_NODUP;
	struct strbuf note = STRBUF_INIT;

		trace2_region_leave("fetch", "remote_refs", the_repository);
		int r;
			       remote, pretty_ref, summary_width);
	const char *what, *kind;
		 * request ambiguous and err on the safe side by doing
	strbuf_release(&r);
	if (max_children != 1 && list->nr != 1) {
	int fast_forward = 0;
		 * the head, and the old value of the head isn't empty...
			tags = TAGS_SET;
			else if (starts_with(source_ref->name, "refs/tags/"))
					merge_status_marker,
	}
		argv_array_push(argv, "-v");
	 * will be printed in update_local_ref)
		die(_("No remote repository specified.  Please, specify either a URL or a\n"
#include "submodule-config.h"
	int remote_via_config = remote_is_configured(remote, 0);
		struct ref *rm, **old_tail = *tail;
	if (!is_null_oid(&ref->old_oid) &&
	const char *remote = task_cb;
		}
		int old_nr;
};
{
 * everything we are going to fetch already exists and is connected
	int ret;
	}
			       remote, pretty_ref, summary_width);
		if (verbosity > 0)
}
	size_t len = strlen(refname);
static struct transport *gtransport;
	}
	if (filter_options.choice) {
			return 1;
};
		} else {
	}
static int do_fetch(struct transport *transport,
				rm->fetch_head_status = FETCH_HEAD_NOT_FOR_MERGE;
	int exit_code;
		struct remote *remote = remote_get(name);
	while (rm) {
	 * without deepen-since. Similar story for deepen-not.
			 * ref given in branch.<name>.merge, too.
			if (i >= argc)
	(void) refname_hash_add(refname_map, refname, oid);

static void clear_item(struct refname_hash_entry *item)

		refspec_ref_prefixes(&transport->remote->fetch, &ref_prefixes);
	argc = parse_options(argc, argv, prefix,
		 */
	if (maybe_prune_tags && (argc || !remote_via_config))
	struct strbuf err = STRBUF_INIT;
	 * check_connected() allows objects to merely be promised, but
	if (depth && atoi(depth) < 1)
					struct refname_hash_entry, ent);

				   0, msg, &err))
			       int tags, int *autotags)
			    !has_object_file_with_flags(&item->oid, quick_flags) &&

				   &ref->new_oid,
static const char warn_time_show_forced_updates[] =
	struct transport *transport;
				       remote, pretty_ref, summary_width);

	return 0;

	} else if (!strcmp(k, "fetch.recursesubmodules")) {
#include "cache.h"

		die("--refmap option is only meaningful with command-line refspec(s).");

}
				what = "";
	msg = xstrfmt("%s: %s", rla, action);
			goto abort;
		const char *name = remote_ref ? remote_ref->name : "";
		goto fail;
}
	const int quick_flags = OBJECT_INFO_QUICK | OBJECT_INFO_SKIP_FETCH_OBJECT;
	url_len = i + 1;
		trace2_region_enter("fetch", "fetch_refs", the_repository);
	cannot_reuse = transport->cannot_reuse ||
	if (verbosity >= 0)
	if (!fetch_refs(transport, ref_map))
{
	int summary_width = transport_summary_width(stale_refs);
	packet_trace_identity("fetch");
			prune_refs(&transport->remote->fetch,
	/*
	if (must_list_refs) {
	if (current_branch &&
static uint64_t forced_updates_ms = 0;
/* Update local refs based on the ref values fetched from a remote */
			tag = xstrfmt("refs/tags/%s:refs/tags/%s",
		if (item &&
					       *kind ? kind : "branch", NULL,

	ref_transaction_free(transaction);

			    int summary_width)
			if (rm->status == REF_STATUS_REJECT_SHALLOW) {
			}
}
{

			continue;
	/*
		clear_item(item);
{
						    &fetch_failed_to_start,
		int commit_graph_flags = COMMIT_GRAPH_WRITE_SPLIT;
	/* no need to be strict, transport_set_option() will validate it again */
};
	if (deepen)
		goto fail;
static struct string_list server_options = STRING_LIST_INIT_DUP;
	return;
			name, transport->url);


		if (max_children < 0)
	 * add them to the list of refs to be fetched
	*task_cb = remote;
		retcode = 1;

	}

		struct ref *source_ref = NULL;
   "flag or run 'git config fetch.showForcedUpdates true'.");
	{ OPTION_CALLBACK, 0, "recurse-submodules", &recurse_submodules, N_("on-demand"),
		print_compact(display, remote, local);
			if (rs->items[i].dst && rs->items[i].dst[0])
	return 0;
		if (source_ref) {
	if (ret) {
	struct hashmap *refname_map = cbdata;
			     void *cb, void **task_cb)
		if (max_children < 0)
	string_list_clear(&remote_refs_list, 0);
	const char *p = NULL;
			if (!strcmp(source_ref->name, "HEAD") ||
			    const char *placeholder)
static struct string_list deepen_not = STRING_LIST_INIT_NODUP;
			fetch_one_setup_partial(remote);
	 * "git fetch --refmap='' origin foo"
static void add_options_to_argv(struct argv_array *argv)
					     NULL);
			      "configured in extensions.partialclone"));
	if (!verbosity && oideq(&ref->peer_ref->old_oid, &ref->old_oid))
	struct refname_hash_entry *item = NULL;
static int add_remote_or_group(const char *name, struct string_list *list)
static void add_merge_config(struct ref **head,
		    N_("fetch all tags and associated objects"), TAGS_SET),
	 * Not precise calculation for compact mode because '*' can
static int get_one_remote_for_fetch(struct remote *remote, void *priv)
{
static int fetch_prune_config = -1; /* unspecified */
	/*
	hashmap_add(map, &ent->ent);
static const char *submodule_prefix = "";
			die(_("--depth and --unshallow cannot be used together"));
static int refcol_width = 10;
/*
			commit = lookup_commit_reference_gently(the_repository,
		if (!starts_with(ref->name, "refs/tags/"))
};
				check_for_new_submodule_commits(&rm->old_oid);

	return exit_code;
	struct string_list_item *remote_ref_item;
	prepare_repo_settings(the_repository);
	strbuf_splice(haystack, p - haystack->buf, nlen,

			     builtin_fetch_options, builtin_fetch_usage, 0);
	transport_disconnect(gtransport);


	if (depth || deepen_since || deepen_not.nr)

				if (verbosity >= 0)
			char *tag;
	item->ignore = 1;
		struct branch *branch = branch_get("HEAD");
	} else {
	ref_map = ref_remove_duplicates(ref_map);
		   N_("path to upload pack on remote end")),
		run_command_v_opt(argv_gc_auto.argv, RUN_GIT_CMD);
			url_len = i + 1;
}
	if (result) {
		 * We only prune based on refspecs specified
	const char *remote = task_cb;
						   const char *refname,
		return 1;
 cleanup:
		int max_children = max_jobs;
		set_option(transport, TRANS_OPT_DEEPEN_RELATIVE, "yes");
		strbuf_addf(display, "%-*s -> *", refcol_width, remote);
		int r;
			}

	OPT_BOOL('p', "prune", &prune,
			    const char *needle,
	    starts_with(ref->name, "refs/tags/")) {

	int ret = check_exist_and_connected(ref_map);
		argv_array_push(argv, "--recurse-submodules=on-demand");
}
	} else {
	transport_unlock_pack(transport);
		fetch_parallel_config = git_config_int(k, v);
#include "submodule.h"
   "but that check has been disabled. To re-enable, use '--show-forced-updates'\n"
		/* Merge everything on the command line (but not --tags) */
			else if (skip_prefix(rm->name, "refs/remotes/", &what))
		 * opportunistic entries with FETCH_HEAD_IGNORE.
/* Fetch multiple remotes in parallel */
			goto cleanup;

	else
	OPT_BOOL('m', "multiple", &multiple,
		/*
	for (rm = orefs; rm; rm = rm->next) {
static int add_one_refname(const char *refname,
#include "packfile.h"
			      int connectivity_checked, struct ref *ref_map)
	if (gtransport)
		 * there is no entry in the resulting FETCH_HEAD marked
				merge_status_marker = "not-for-merge";
			rc = error(_("%s did not send all necessary objects\n"), url);
		return 0;
	return retcode;
	    !has_object_file_with_flags(&item->oid, quick_flags) &&
			warn_dangling_symref(stderr, dangling_msg, ref->name);
			 * if the remote we're fetching from is the same
	len = 21 /* flag and summary */ + rlen + 4 /* -> */ + llen;
	}
			die(_("fetch --all does not take a repository argument"));
	}
	OPT_SET_INT('4', "ipv4", &family, N_("use IPv4 addresses only"),
	}
					warning(_("reject %s because shallow roots are not allowed to be updated"),
	struct remote_group_data g;
{
				      argv[i], argv[i]);
		 * Not fetched to a remote-tracking branch?  We need to fetch

		return 0;
	else if (tags == TAGS_UNSET)
		if (starts_with(name, "refs/tags/")) {
static int fetch_failed_to_start(struct strbuf *out, void *cb, void *task_cb)
	NULL
	sigchain_pop(signo);



				warning(_("not setting upstream for a remote remote-tracking branch"));
	if (plen > nlen && p[nlen] != '/')
			max_children = fetch_parallel_config;
	return result;
		set_option(transport, TRANS_OPT_UPDATE_SHALLOW, "yes");
	/*
	OPT_STRING_LIST(0, "negotiation-tip", &negotiation_tip, N_("revision"),
	if (fast_forward) {
static int consume_refs(struct transport *transport, struct ref *ref_map)
		return;
		recurse_submodules = r;

		}
		ret = transport_fetch_refs(transport, ref_map);
	return 0;
		item = NULL;
		 * If item is non-NULL here, then we previously saw a
	if (force)
	type = oid_object_info(the_repository, &ref->new_oid, NULL);
		   void *cb_data)
			}
	{ OPTION_STRING, 0, "submodule-prefix", &submodule_prefix, N_("dir"),
				} else {

static void prepare_format_display(struct ref *ref_map)
				*autotags = 1;
				}
	refname_hash_init(&remote_refs);
	OPT_STRING(0, "shallow-since", &deepen_since, N_("time"),
	if (!result && (recurse_submodules != RECURSE_SUBMODULES_OFF)) {
		if (rs->nr) {
	struct oid_array *oids = cb_data;
		strbuf_add_unique_abbrev(&quickref, &current->object.oid, DEFAULT_ABBREV);
		set_option(transport, TRANS_OPT_DEEPEN_NOT,
	struct string_list remote_refs_list = STRING_LIST_INIT_NODUP;

	const char *name;
	for (rm = ref_map; rm; rm = rm->next) {
	}
				 transport->remote->name,



	hashmap_free_entries(&remote_refs, struct refname_hash_entry, ent);
	 * use FETCH_HEAD as a refname to refer to the ref to be merged.
static int fetch_prune_tags_config = -1; /* unspecified */

{
static struct list_objects_filter_options filter_options;
		    N_("control recursive fetching of submodules"),
		rm = alloc_ref(item->refname);
   "'--no-show-forced-updates' or run 'git config fetch.showForcedUpdates false'\n"
							url_len, url);
	}
		 N_("accept refs that update .git/shallow")),
		set_option(transport, TRANS_OPT_KEEP, "yes");
	if (!compact_format)
		set_option(transport, TRANS_OPT_UPLOADPACK, upload_pack);
		for (ref = stale_refs; ref; ref = ref->next)
		memset(&refspec, 0, sizeof(refspec));
#include "promisor-remote.h"

	const char *format = "full";

static int all, append, dry_run, force, keep, multiple, update_head_ok;
	if (list->nr == prev_nr) {
		}

static int prune = -1; /* unspecified */
	}
			       r ? _("unable to update local ref") : NULL,
	refname_hash_init(&existing_refs);

	if (prune != -1)
			ref_map = get_remote_ref(remote_refs, "HEAD");
	 * really need to perform.  Claiming failure now will ensure
				if (source_ref) {
		argv_array_push(argv, "-v");
	 */
		if (errcode)
			remote = remote_get(argv[0]);
 * We would want to bypass the object transfer altogether if
	int i;

		}
		int max_children = max_jobs;
		url = transport_anonymize_url(raw_url);
		if (transport->smart_options)
	BUG_ON_OPT_NEG(unset);
				struct ref **head,
{
				       r ? _("unable to update local ref") : NULL,
	}
			    const char *remote,
						   xstrndup(value, wordlen));
		 * it anyway to allow this branch's "branch.$name.merge"
#include "builtin.h"
	char *msg;
	e2 = container_of(entry_or_key, const struct refname_hash_entry, ent);
		fast_forward = 1;
	if (prune_tags != -1)
	}
	OPT_BOOL(0, "show-forced-updates", &fetch_show_forced_updates,
	 * We may have a final lightweight tag that needs to be
				       _("(none)"), prettify_refname(ref->name),


			add_negotiation_tips(transport->smart_options);

	if (keep)
	OPT_PARSE_LIST_OBJECTS_FILTER(&filter_options),

	const char **argv;
{
	 * request a partial-fetch, do a normal fetch.
static int recurse_submodules_default = RECURSE_SUBMODULES_ON_DEMAND;
	OPT_BOOL(0, "auto-gc", &enable_auto_gc,
static int git_fetch_config(const char *k, const char *v, void *cb)
			int r;
			    struct strbuf *display,
		/* no command line request */
			size_t wordlen = strcspn(value, " \t\n");
		int i;
				die(_("You need to specify a tag name."));
			if (argc > 1)
		remote_refs = transport_get_remote_refs(transport, &ref_prefixes);
	OPT_BOOL(0, "write-commit-graph", &fetch_write_commit_graph,
		 */
		oidcpy(&rm->old_oid, &item->oid);
				die(_("No such remote or remote group: %s"), argv[i]);

	} else if (multiple) {

		return;
	struct strbuf l = STRBUF_INIT;
			refspec_append(&rs, argv[i]);
	for (; ref_map; ref_map = ref_map->next)
	if (dry_run)
				   check_old ? &ref->old_oid : NULL,
			}
		check_not_current_branch(ref_map);
static int store_updated_refs(const char *raw_url, const char *remote_name,
	/* opportunistically-updated references: */
			   const char *summary, const char *error,
			tail = &ref_map->next;
				clear_item(item);
{
	OPT_END()
		if (fetch_parallel_config < 0)
						    max_children);
	 */
	} else if (transport->remote && transport->remote->fetch.nr)
	refname_hash_init(&existing_refs);
	struct parallel_fetch_state *state = cb;
		**tail = rm;
				warning(_("not setting upstream for a remote tag"));
		return r;
		return r;
#include "parse-options.h"
			TRANSPORT_FAMILY_IPV4),
	if (state->next < 0 || state->next >= state->remotes->nr)
		}
	current = lookup_commit_reference_gently(the_repository,
		warning(_("Option \"%s\" is ignored for %s\n"),
					       *what ? what : "HEAD",
 * or inherit the default filter-spec from the config.
			format_display(&sb, '-', _("[deleted]"), NULL,
		else

	}
static void find_non_local_tags(const struct ref *refs,

	return 1;
		: _("   (%s has become dangling)");
		result = run_processes_parallel_tr2(max_children,
	 */
#include "argv-array.h"
		return 0;
			item = NULL;
	if (prune) {
		if (ref_map)

		strbuf_addstr(&quickref, "...");
{
						    "fetch", "parallel/fetch");
			else
static int verbosity, deepen_relative, set_upstream;
		 */
	/*

			fetch_refspec = &remote->fetch;

	} else {
 */
	    (fetch_write_commit_graph < 0 &&
			    !strcmp(branch->remote_name, remote->name))
		   N_("deepen history of shallow clone")),

	}
		int r;
		argv_array_clear(&argv_gc_auto);
	else
	free(msg);
static int progress = -1;
	int autotags = (transport->remote->fetch_tags == 1);
	if (gsecondary)
	argv_array_clear(&ref_prefixes);


			if (4 < i && !strncmp(".git", url + i - 3, 4))
			argc--;
		argv_array_push(argv, "--force");
#include "refspec.h"
	if (rs->nr) {
	if (!append && !dry_run) {
static const char *deepen_since;
	 * Explicit --no-filter argument overrides everything, regardless
			struct refname_hash_entry *peer_item;
	if (!filter_options.choice)
						    &fetch_finished,
			strbuf_reset(&note);
	sigchain_pop(SIGPIPE);
		return 0;
			for (i = 0; i < remote->fetch.nr; i++) {
		} else if (starts_with(name, "refs/heads/")) {
	transaction = ref_transaction_begin(&err);
		strbuf_add_unique_abbrev(&quickref, &ref->new_oid, DEFAULT_ABBREV);

	return ent;
			       r ? _("unable to update local ref") : _("forced update"),
struct remote_group_data {
					goto skip;
						    verbosity < 0,
}
		argv_array_pushl(&argv_gc_auto, "gc", "--auto", NULL);
	TAGS_SET = 2
	int i;

#include "remote.h"

	strbuf_addf(display, "%c %-*s ", code, width, summary);
	struct ref *ref = *rm;

	} else {
		/* Single remote or group */
		if (progress)
		rla = default_rla.buf;
{
		 N_("set upstream for git pull/fetch")),
{
	int summary_width = transport_summary_width(ref_map);
	  N_("specify fetch refmap"), PARSE_OPT_NONEG, parse_refmap_arg },
	/* if neither --no-tags nor --tags was specified, do automated tag
	struct strbuf r = STRBUF_INIT;
			peer_item = hashmap_get_entry_from_hash(&existing_refs,

		argv_array_push(argv, "--tags");

	if (verbosity >= 1)
static int iterate_ref_map(void *cb_data, struct object_id *oid)
			tags = TAGS_UNSET;
		for (rm = *old_tail; rm; rm = rm->next)
				       summary_width);
	 */

		else if (!is_repository_shallow(the_repository))
	struct commit *current = NULL, *updated;
	OPT_BOOL('a', "append", &append,
static void add_negotiation_tips(struct git_transport_options *smart_options)
	char *remote;
	if (item &&
	 */
	 * If we are deepening a shallow clone we already have these
		 * remote-tracking ref that would be derived from the
	TAGS_DEFAULT = 1,
{
		     (has_merge && !strcmp(branch->remote_name, remote->name)))) {
					fprintf(stderr, " %s\n", note.buf);
		state->result = -1;
						    &state,
	OPT_INTEGER('j', "jobs", &max_jobs,
	const char *dangling_msg = dry_run

	OPT_SET_INT('n', NULL, &tags,
			argv_array_push(&ref_prefixes, "refs/tags/");
	if (prune_tags < 0) {
	struct string_list *list;
static const char * const builtin_fetch_usage[] = {
		if (!has_object_file_with_flags(&r->old_oid,
		find_non_local_tags(remote_refs, &ref_map, &tail);
static void unlock_pack_on_signal(int signo)
				if (*kind)
	 * following ... */
		    format);
		result = fetch_one(remote, argc, argv, prune_tags_ok);
	int must_list_refs = 1;

				}
			       _("can't fetch in current branch"),
	 * checked to see if it needs fetching.
	/*
	struct refname_hash_entry *ent;


			continue;
		print_remote_to_local(display, remote, local);
	error("%s", err.buf);
	unlock_pack();
		 N_("append to .git/FETCH_HEAD instead of overwriting")),

		else
		 * When there are several such branches, consider the
	OPT_BOOL('u', "update-head-ok", &update_head_ok,

	for (i = 1; i < argc; i++)
	    !(update_head_ok || is_bare_repository()) &&
	if (negotiation_tip.nr) {
		for (i = 0; i < fetch_refspec->nr; i++)
static struct ref *get_ref_map(struct remote *remote,
		return 0;
		 * current one, i.e. the one fetched to FETCH_HEAD.
		int r = git_config_bool(k, v) ?

	if (filter_options.choice) {
				 ref_map);

	    !is_null_oid(&ref->old_oid)) {

	for (rm = ref_map; rm; rm = rm->next) {

				error(_("Could not fetch %s"), name);
		}
		compact_format = 1;


		 * to fetch then we can mark the ref entry in the list
		    !has_object_file_with_flags(&item->oid, quick_flags) &&
		if (!fetch_show_forced_updates) {
		rm->peer_ref = alloc_ref(item->refname);
		for (i = 0; i < rs->nr; i++) {
			if (recurse_submodules != RECURSE_SUBMODULES_OFF)
}

		 * We compute these entries now, based only on the
	if (!has_promisor_remote() && !filter_options.choice)
	if (verbosity >= 0) {
	else
}
						OBJECT_INFO_SKIP_FETCH_OBJECT))
		 * refspecs specified on the command line.  But we add
	 * filter-spec as the default for subsequent fetches to this
		 */

	} else if (argc == 0) {
		 * The peeled ref always follows the matching base
	for (i = 0; i < branch->merge_nr; i++) {
		 * don't care whether --tags was specified.
	if (!current || !updated) {
		if (refname_hash_exists(&remote_refs, ref->name) ||
	 * protocol for that, but for now, just force a new connection

	else
		add_options_to_argv(&options);
	struct remote *remote = NULL;
	int prune_tags_ok = 1;
	/* Record the command line for the reflog */
	if (!connectivity_checked) {
		argv_array_push(argv, "--recurse-submodules");
	 */
		} else {
	struct string_list *remotes;
			   : STORE_REF_ERROR_OTHER;
						fputc(url[i], fp);
N_("Fetch normally indicates which branches had a forced update,\n"
		const char *what;
static int refname_hash_exists(struct hashmap *map, const char *refname)
		transport_disconnect(gsecondary);
}
}
			msg = "storing ref";
	}
			if (!rm->peer_ref) {
	for_each_ref(add_one_refname, &existing_refs);
	if (!ref)
						rm->peer_ref ? rm->peer_ref->name : rm->name);
static void print_compact(struct strbuf *display,
		rm = ref_map;

	OPT_BOOL(0, "progress", &progress, N_("force progress reporting")),
static int max_jobs = -1, submodule_fetch_jobs_config = -1;
	struct parallel_fetch_state *state = cb;
		/*
{

	struct argv_array argv = ARGV_ARRAY_INIT;
			if (!rs->items[i].exact_sha1) {
		      1, PARSE_OPT_NONEG),

			else if (starts_with(source_ref->name, "refs/remotes/"))

	if (enable_auto_gc) {
	if (tags == TAGS_DEFAULT && autotags) {

{
	oidset_clear(&fetch_oids);
		int errcode = truncate_fetch_head();
		 */
			TRANSPORT_FAMILY_IPV6),
	OPT_SET_INT_F(0, "unshallow", &unshallow,
			return 0;
	if (!dry_run) {
			result = state.result;
		return 0;
		 * If this is the head, and it's not okay to update
		if (depth)
	char *rla = getenv("GIT_REFLOG_ACTION");
				continue;
	 * merged entries are written before not-for-merge. That lets readers
	}
	return result;
		 */

#include "list-objects-filter-options.h"
		      N_("convert to a complete repository"),
		if (rm->peer_ref) {
		format_display(display, r ? '!' : ' ', quickref.buf,
#include "commit-reach.h"
		}
			    starts_with(source_ref->name, "refs/heads/"))
		for (rm = ref_map; rm; rm = rm->next)
				oidcpy(&rm->peer_ref->old_oid, old_oid);
		tail = &rm->next;
	 */
					ref_map->fetch_head_status = FETCH_HEAD_MERGE;

		if (list.nr > 1) {
	 * explicitly given filter-spec or inherit the filter-spec from
		p = strstr(haystack->buf, needle);
			}
	ret = store_updated_refs(transport->url,
	if (verbosity >= 2)
	}
		if (ends_with(ref->name, "^{}")) {
	if (fetch_show_forced_updates) {
	struct branch *current_branch = branch_get(NULL);
	if (tags == TAGS_DEFAULT && autotags)
	}
static int enable_auto_gc = 1;
	for (want_status = FETCH_HEAD_MERGE;
		 N_("dry run")),
						fputs("\\n", fp);
		 * to mention these entries in FETCH_HEAD at all, as
	/*
		if (retcode)
	}
		string_list_append(list, remote->name);
	     want_status++) {

	return 0;
	int ret, df_conflict = 0;

		    name, value, transport->url);

 skip:
				if (verbosity >= 0 && !shown_url) {
		/* also fetch all tags */
	sigchain_push(SIGPIPE, SIG_IGN);
			/* More than one remote */
		else
{
			url_len = strlen(url);
	}
	create_fetch_oidset(head, &fetch_oids);
		 * for merging.
			format_display(display, '!', _("[rejected]"), _("would clobber existing tag"),
						      source_ref->name);
	const struct ref *ref;
	OPT_BOOL(0, "set-upstream", &set_upstream,
			format_display(display, '=', _("[up to date]"), NULL,
			if (rm->fetch_head_status != want_status)
		 * to check if it is a lightweight tag that we want to
			  const char *remote, const char *local)
		           struct ref ***tail)
			if (!strcmp(rm->name, "HEAD")) {
static int refname_hash_entry_cmp(const void *hashmap_cmp_fn_data,
		 * fetched branch that is meant to be merged with the
}
	if (!strcmp(k, "submodule.recurse")) {

	const struct refname_hash_entry *e1, *e2;
static int prune_refs(struct refspec *rs, struct ref *ref_map,
{
	hashmap_free_entries(&existing_refs, struct refname_hash_entry, ent);
			else {
#include "commit.h"

	if (!fp)
		item = hashmap_get_entry_from_hash(&remote_refs, hash, refname,
		 * more likely to follow a standard layout.
#include "object-store.h"
			max_children = fetch_parallel_config;
		}
	struct ref *ref_map;
		 */
	}

		struct ref **tail = &ref_map;
static int fetch_show_forced_updates = 1;
		if (old_nr == oids->nr)
static struct refspec refmap = REFSPEC_INIT_FETCH;

		 * them to the list following the refspecs resulting
			prune_tags = PRUNE_TAGS_BY_DEFAULT;
				printf(_("Fetching %s\n"), name);
		fetch_show_forced_updates = git_config_bool(k, v);
		get_fetch_map(remote_refs, tag_refspec, &tail, 0);
}
	 * If no prior partial clone/fetch and the current fetch DID NOT
{

		return 0;
			die(_("Refusing to fetch into current branch %s "
	refspec_append(&refmap, arg);
#include "repository.h"
		      "branches"), remote_name);
		r = s_update_ref("fast-forward", ref, 1);
	hashmap_init(map, refname_hash_entry_cmp, NULL, 0);
	strbuf_release(&err);
		format_display(display, r ? '!' : '*', what,

enum {
		if (transport->remote->fetch_tags == 2)
static int add_oid(const char *refname, const struct object_id *oid, int flags,

			depth = xstrfmt("%d", INFINITE_DEPTH);

	strbuf_addstr(&default_rla, "fetch");
			rm->fetch_head_status = FETCH_HEAD_MERGE;
			prune_tags_ok = (argc == 1);
			r = s_update_ref("updating tag", ref, 0);
		p = haystack->buf + haystack->len - nlen;
	if (filter_options.choice && !has_promisor_remote())
			N_("report that we have only objects reachable from this object")),
			    "of non-bare repository"), current_branch->refname);
				   transport->url);
}
		      "(lower priority than config files)"),
				url_len = i - 3;
		struct strbuf quickref = STRBUF_INIT;
		strbuf_addf(&default_rla, " %s", argv[i]);
		struct strbuf quickref = STRBUF_INIT;
#include "branch.h"
}
		argv_array_push(argv, "--update-head-ok");
	struct ref *rm = *head;
		/*
			}
	}
	}
	g.name = name; g.list = list;
static struct transport *gsecondary;
		}

	} else {
			warning("Ignoring --negotiation-tip because the protocol does not support it.");
		set_option(transport, TRANS_OPT_DEPTH, depth);



			if (!shown_url) {
				install_branch_config(0,
	}
			if (get_oid(s, &oid))
			warning(_("no source branch found.\n"

	*tail = orefs;
	if (len >= max)
					       "FETCH_HEAD", summary_width);
	ref_map = get_ref_map(transport->remote, remote_refs, rs,
{
				must_list_refs = 1;
			warning("Ignoring --negotiation-tip=%s because it does not match any refs",
		return;
			ref_map->fetch_head_status = FETCH_HEAD_MERGE;
	int i, result = 0;
static void print_remote_to_local(struct strbuf *display,
	close_object_store(the_repository->objects);
	transport_set_option(transport, TRANS_OPT_FOLLOWTAGS, NULL);
	trace2_region_enter("fetch", "consume_refs", the_repository);


		df_conflict = (ret == TRANSACTION_NAME_CONFLICT);
	fetch_config_from_gitmodules(&submodule_fetch_jobs_config,
}

			   const struct ref *remote_refs,

	}
	ref_transaction_free(transaction);
		deepen = 1;
	}
#include "oidset.h"
#include "transport.h"
		/*
}
		      " 'git remote prune %s' to remove any old, conflicting "
	struct refspec rs = REFSPEC_INIT_FETCH;
			string_list_append(&refnames, ref->name);
				result = 1;
			warning(_(warn_time_show_forced_updates),
static struct transport *prepare_transport(struct remote *remote, int deepen)
		/*
		if (0 <= remote->prune_tags)

	int ignore;

	if (rc & STORE_REF_ERROR_DF_CONFLICT)
		if (max_children < 0)
			argv_array_push(&argv_gc_auto, "--quiet");
			die(_("--deepen and --depth are mutually exclusive"));
	max    = term_columns();
			else if (skip_prefix(rm->name, "refs/tags/", &what))
}
		}
		*tail = &rm->next;
		for (ref = stale_refs; ref; ref = ref->next) {

	 * is not unsetting). We could extend the remote helper
static int shown_url = 0;
	/*
	struct object_id oid;

			       remote, pretty_ref, summary_width);
		die(_("object %s not found"), oid_to_hex(&ref->new_oid));
	int plen, nlen;
		fetch_prune_config = git_config_bool(k, v);
	if (advice_fetch_show_forced_updates) {
	}

	if (raw_url)
			    !oidset_contains(&fetch_oids, &ref->old_oid) &&
		set_option(transport, TRANS_OPT_LIST_OBJECTS_FILTER, spec);
		    N_("do not fetch all tags (--no-tags)"), TAGS_UNSET),
 */
	    ref_transaction_update(transaction, ref->name,
	fclose(fp);
	}
			return r;
			prune_refs(rs, ref_map, transport->url);
		argv_array_push(argv, prune ? "--prune" : "--no-prune");
	}
	argv_array_pushl(&argv, "fetch", "--append", "--no-auto-gc",
		transport = gsecondary;
		 * OIDs
static void backfill_tags(struct transport *transport, struct ref *ref_map)
	struct ref_transaction *transaction;

	 * the config.
}
					*autotags = 1;
		 * have been missing or have been different than the
	for_each_ref(add_one_refname, &existing_refs);
		 N_("write the commit-graph after fetching")),
			strbuf_reset(&note);
				  const void *keydata)
				for (i = 0; i < url_len; ++i)
		for (i = 0; i < list->nr; i++) {


					warning(_("multiple branches detected, incompatible with --set-upstream"));
	OPT_BOOL('P', "prune-tags", &prune_tags,
				break;
			if (branch_merge_matches(branch, i, rm->name)) {
				  const char *remote, const char *local)
	int result = 0;
		string_list_append(list, remote->name);
			N_("deepen history of shallow clone, excluding rev")),
	struct commit *commit;
		if (!has_glob_specials(s)) {
				"you need to specify exactly one branch with the --set-upstream option."));
		 N_("check for forced-updates on all updated branches")),
	int url_len, i, result = 0;
			argv++;
	oidcpy(oid, &ref->old_oid);
		return r;
		}
			die(_("fetch.parallel cannot be negative"));

		for (i = 0; i < rs->nr; i++) {
	raise(signo);
	     want_status <= FETCH_HEAD_IGNORE;
			continue;
			struct ref *ref,
	e1 = container_of(eptr, const struct refname_hash_entry, ent);
				forced_updates_ms / 1000.0);

		}


	int connectivity_checked = transport->smart_options
			}
	char refname[FLEX_ARRAY];
	OPT_STRING(0, "upload-pack", &upload_pack, N_("path"),
	transport_unlock_pack(transport);
		/* TODO should this also die if we have a previous partial-clone? */

	struct check_connected_options opt = CHECK_CONNECTED_INIT;
	*rm = ref->next;
			die(_("Negative depth in --deepen is not supported"));
static struct refname_hash_entry *refname_hash_add(struct hashmap *map,
 * "git fetch"
	TAGS_UNSET = 0,
	if (r > 0)
			if (note.len) {

			"--no-write-commit-graph", NULL);
			msg = "storing head";
	struct argv_array ref_prefixes = ARGV_ARRAY_INIT;
			}
					if ('\n' == url[i])
				kind = "branch";
		 * which has FETCH_HEAD_NOT_FOR_MERGE, is not removed
		 * to be honored by 'git pull', but we do not have to

	transport->family = family;
		submodule_fetch_jobs_config = parse_submodule_fetchjobs(k, v);

		for_each_glob_ref(add_oid, s, oids);
		if (!remote_is_configured(remote, 0))
	return rc;
		partial_clone_get_default_filter_spec(&filter_options, remote->name);
		strbuf_addf(display, "  (%s)", error);

	if (prune < 0) {
	 * appear on the left hand side of '->' and shrink the column
}
}
			if (peer_item) {
			       r ? _("unable to update local ref") : NULL,
{
		      placeholder, strlen(placeholder));
#include "utf8.h"
		 * current branch. The relevant upstream is the
N_("It took %.2f seconds to check forced updates. You can use\n"
		return 0;
		get_fetch_map(remote_refs, &refspec, tail, 1);
	int max, rlen, llen, len;
				s);
			 * as given in branch.<name>.remote, we add the
			 */
	struct oid_array *oids = xcalloc(1, sizeof(*oids));
{
	int prev_nr = list->nr;
	free_refs(ref_map);
				fputc('\n', fp);
			struct ref *ref = NULL;

	OPT_BOOL(0, "dry-run", &dry_run,
static struct string_list negotiation_tip = STRING_LIST_INIT_NODUP;
			continue;
	}
	} else
	 * rough estimation to see if the output line is too long and
		    struct refspec *rs)
{
	if (depth)
	if (deepen_relative) {
		strbuf_add_unique_abbrev(&quickref, &current->object.oid, DEFAULT_ABBREV);

				struct object_id *old_oid = &peer_item->oid;
		} else {
	if (upload_pack)
static const char *depth;
		for (i = 0; i < argc; i++)
		return;
	cp->git_cmd = 1;
	if (maybe_prune_tags && remote_via_config)

}
	if (p > haystack->buf && p[-1] != '/')
	    !strcmp(ref->name, current_branch->name) &&
			  void *cb, void *task_cb)

	    !oidset_contains(&fetch_oids, &item->oid))

	 * this repo if not already enabled and remember the given
{
/*
	FLEX_ALLOC_MEM(ent, refname, refname, len);
	enum object_type type;
 * Fetching from the promisor remote should use the given filter-spec

	OPT_BOOL(0, "update-shallow", &update_shallow,
						hash, refname,
		if (!item)

	const char *filename = git_path_fetch_head(the_repository);
	if (deepen && deepen_since)
{

	}
	} else
	struct parallel_fetch_state *state = cb;
						      transport->remote->name,
static int get_remote_group(const char *key, const char *value, void *priv)
}
			   const struct object_id *oid,
	int i;
				rm->fetch_head_status = FETCH_HEAD_MERGE;
{

			} else
	 * of any prior partial clones and fetches.
	}
};
struct parallel_fetch_state {
		 N_("prune local tags no longer on remote and clobber changed tags")),
		strbuf_release(&quickref);
	}

	struct oidset fetch_oids = OIDSET_INIT;
		oidset_insert(out, &rm->old_oid);
		write_commit_graph_reachable(the_repository->objects->odb,
	int r = transport_set_option(transport, name, value);

			}
	smart_options->negotiation_tips = oids;
		if (argc == 1)


	 * can be used to tell the command not to store anywhere
		die("--filter can only be used when extensions.partialClone is set");
		if (ref_map->peer_ref && !strcmp(current_branch->refname,
			}
				ref = alloc_ref(rm->peer_ref->name);
	struct hashmap_entry ent;
						    recurse_submodules_default,

			prune = remote->prune;
			warning(_(warn_show_forced_updates));
	return 1;
	struct ref *r;
		die(_("Option \"%s\" value \"%s\" is not valid for %s"),
			fprintf(stderr, " %s\n",sb.buf);
			clear_item(item);
	}
	if (!fp)
		int has_merge = branch_has_merge_config(branch);
		}
			if (*what) {

	if (gsecondary) {
				oidcpy(&ref->old_oid, &rm->peer_ref->old_oid);
		struct refspec_item refspec;
		 * nothing and just emit a warning.
		depth = xstrfmt("%d", deepen_relative);
	N_("git fetch --all [<options>]"),
	/*
		fetch_prune_tags_config = git_config_bool(k, v);
	if (refcol_width < rlen)
{
				     &recurse_submodules);
		return 0;
				kind = "tag";


	 * For all the tags in the remote_refs_list,
		      const char *raw_url)
	FILE *fp;
		 * For any refs that we happen to be fetching via
	int i;
				continue;
		goto cleanup;

	}

		   N_("default for recursive fetching of submodules "
	N_("git fetch [<options>] [<repository> [<refspec>...]]"),

					else
		transport_set_option(transport, TRANS_OPT_FOLLOWTAGS, "1");
	print_remote_to_local(display, r.buf, l.buf);
	if (r < 0)

	return check_connected(iterate_ref_map, &rm, &opt);
		trace2_region_enter("fetch", "remote_refs", the_repository);
		struct check_connected_options opt = CHECK_CONNECTED_INIT;
	return strcmp(e1->refname, keydata ? keydata : e2->refname);
		/* No arguments -- use default remote */

	else if (verbosity < 0)
{
			msg = "storing tag";
		/*
	 * Do a partial-fetch from the promisor remote using either the
	struct ref *orefs = NULL, **oref_tail = &orefs;
}
	}

	transport_set_option(transport, TRANS_OPT_DEPTH, "0");
	trace2_region_leave("fetch", "consume_refs", the_repository);
	}
	}

static int prune_tags = -1; /* unspecified */
	url_len = strlen(url);
		else
	if (!transaction ||
	git_config(git_fetch_config, NULL);
				/* do not write anything to FETCH_HEAD */
			    !has_object_file_with_flags(&ref->old_oid, quick_flags) &&
			int check_old)
		format_display(display, '!', _("[rejected]"), _("non-fast-forward"),
			struct strbuf sb = STRBUF_INIT;
	if (tags == TAGS_SET)
		argv_array_push(argv, "-q");
	}
		result = fetch_populated_submodules(the_repository,
}
	const struct ref *remote_refs;
			else if (skip_prefix(rm->name, "refs/heads/", &what))
		/*
	return !!result;
			argv_array_push(&argv, name);
		retcode = truncate_fetch_head();
		must_list_refs = 1;
		rm->fetch_head_status = FETCH_HEAD_IGNORE;
	strbuf_release(&err);
	if (fetch_write_commit_graph > 0 ||
		/* Unless we have already decided to ignore this item... */
	const char *filename = dry_run ? "/dev/null" : git_path_fetch_head(the_repository);
				break;
		else if (argc > 1)
		(void) add_remote_or_group(argv[0], &list);
	return 0;
	struct ref *rm;
	fp = fopen(filename, "a");
	if (ret) {
	hashmap_entry_init(&ent->ent, strhash(refname));
		return error_errno(_("cannot open %s"), filename);
	 * we need all direct targets to exist.
		url = transport_anonymize_url(raw_url);
	for (r = rm; r; r = r->next) {
	maybe_prune_tags = prune_tags_ok && prune_tags;
		if (check_connected(iterate_ref_map, &rm, &opt)) {
		item = refname_hash_add(&remote_refs, ref->name, &ref->old_oid);
{
	}
		argv_array_push(argv, prune_tags ? "--prune-tags" : "--no-prune-tags");
	}
static int fetch_next_remote(struct child_process *cp, struct strbuf *out,
			switch (rm->fetch_head_status) {


	strbuf_addf(display, "%-*s -> %s", refcol_width, remote, local);

			if (item &&
	return 0;
	free(url);

		 * time to update refs to reference the new objects.
		/* All arguments are assumed to be remotes or groups */
	state->result = error(_("Could not fetch %s"), remote);
		find_non_local_tags(remote_refs, &ref_map, &tail);
	{ OPTION_CALLBACK, 0, "recurse-submodules-default",
		find_and_replace(&l, remote, "*");
	strbuf_addstr(&r, remote);
		unsigned int hash = strhash(refname);
			fetch_refspec = &refmap;
		argv_array_push(argv, "--no-tags");
	OPT_SET_INT('6', "ipv6", &family, N_("use IPv6 addresses only"),

	if (!strcasecmp(format, "full"))
	for_each_string_list_item(remote_ref_item, &remote_refs_list) {

			max_children = submodule_fetch_jobs_config;
		 * ref, so if we see a peeled ref that we don't want

struct refname_hash_entry {
		partial_clone_register(remote->name, &filter_options);
		 N_("prune remote-tracking branches no longer on remote")),
				 connectivity_checked,
				  const struct hashmap_entry *entry_or_key,
						 &ref->new_oid, 1);
	 * remote.
		     /* Note: has_merge implies non-NULL branch->remote_name */
}
		}
	oidcpy(&ent->oid, oid);
}
			continue;
		 *

		consume_refs(transport, ref_map);
			const char *name = list->items[i].string;
	struct remote_group_data *g = priv;
	struct ref *ref_map = NULL;
	 * back.
				warning(_("unknown branch type"));
				if (want_status == FETCH_HEAD_MERGE)
#define FORCED_UPDATES_DELAY_WARNING_IN_MS (10 * 1000)
		for (rm = ref_map; rm; rm = rm->next) {

				what = rm->name;
			prune_tags = fetch_prune_tags_config;
	for (i = 0; i < negotiation_tip.nr; i++) {
		free_refs(ref_map);
				    !remote->fetch.items[0].pattern)
		if (rm)
	 */
			value += wordlen + (value[wordlen] != '\0');
{


			case FETCH_HEAD_MERGE:
		 */
		set_option(transport, TRANS_OPT_FROM_PROMISOR, "1");
{
		argv_array_push(argv, "--keep");

{
		} else {
		 * We're setting the upstream configuration for the
}
	git_config(get_remote_group, &g);
	}
		 * as one to ignore by setting util to NULL.

				if (remote->fetch.items[i].dst &&

			if (!add_remote_or_group(argv[i], &list))
		if (!result)
				   ref_map,
		argv_array_push(&argv, "--end-of-options");
	}
	if (tags == TAGS_DEFAULT) {
			       remote, pretty_ref, summary_width);

	return 0;
#define STORE_REF_ERROR_DF_CONFLICT 2

	argv_array_clear(&argv);
}
static void adjust_refcol_width(const struct ref *ref)
static int fetch_refs(struct transport *transport, struct ref *ref_map)
{
		set_option(transport, TRANS_OPT_DEEPEN_SINCE, deepen_since);
};

		deepen_since || deepen_not.nr;
{

				format_display(&note, '*',
		argv_array_clear(&options);
		const char *spec =
	struct hashmap remote_refs;
			if (!commit)
	}

	int next, result;
		 * We can avoid listing refs if all of them are exact
	llen   = utf8_strwidth(prettify_refname(ref->peer_ref->name));


				fprintf(fp, "%s\t%s\t%s",
{
			if (verbosity >= 0)
			get_fetch_map(ref_map, &fetch_refspec->items[i], &oref_tail, 1);
				kind = "";
	if (dry_run)
	 * should not be counted (we can't do precise calculation
		    !rm->peer_ref ||
	{ OPTION_CALLBACK, 0, "refmap", NULL, N_("refmap"),
	N_("git fetch [<options>] <group>"),
								1);
		return;
		return 0;
		while (*value) {
{
static enum transport_family family;
			return -1;
				kind = "remote-tracking branch";
	N_("git fetch --multiple [<options>] [(<repository> | <group>)...]"),
	return ret;
	if (!strcmp(k, "fetch.parallel")) {
}

static int compact_format;
	}
#include "run-command.h"
	exit_code = do_fetch(gtransport, &rs);
	ret = ref_transaction_commit(transaction, &err);
	int width = (summary_width + strlen(summary) - gettext_width(summary));
	 * anyway because we don't know if the error explanation part
			if (wordlen >= 1)
				die("%s is not a valid object", s);
			}
static int fetch_parallel_config = 1;
	return 0;
			argv_array_pop(&argv);
		}

			const char *merge_status_marker = "";
						   const struct object_id *oid)
		 *
	struct ref *rm = ref_map;
	OPT_BOOL(0, "all", &all,

#include "string-list.h"

			const char *refname = rm->peer_ref->name;

								&rm->old_oid,
				oidcpy(&ref->new_oid, &rm->old_oid);

	if (recurse_submodules == RECURSE_SUBMODULES_ON)
		url_len = i - 3;


{
	OPT_STRING(0, "depth", &depth, N_("depth"),

		return -1; /* end of the list */
			i++;
	 * we perform the network exchange to deepen our history.
	/*
	oid_array_append(oids, oid);
				die(_("Couldn't find remote ref HEAD"));
			get_fetch_map(remote_refs, &rs->items[i], &tail, 0);
	 * We do a pass for each fetch_head_status type in their enum order, so
		           struct branch *branch,
	if (!p)
		    !strcmp(rm->name, "HEAD"))
				kind = "";

			prune_tags = remote->prune_tags;
}
	int i;
	hashmap_free_entries(&existing_refs, struct refname_hash_entry, ent);
	struct string_list *list = priv;
	int want_status;
					ref_map->peer_ref->name))

		if (filter_options.choice)
		? _("   (%s will become dangling)")
	gtransport = prepare_transport(remote, 1);


		refspec_append(&remote->fetch, TAG_REFSPEC);
			    const struct ref *remote_ref,
	 * Once we have set TRANS_OPT_DEEPEN_SINCE, we can't unset it
					source_ref = rm;
	 */



		 * fail if branch.$name.merge is misconfigured to point
	OPT_STRING_LIST(0, "shallow-exclude", &deepen_not, N_("revision"),
		strbuf_addf(out, _("could not fetch '%s' (exit code: %d)\n"),

static void refname_hash_init(struct hashmap *map)
			}

		refspec.src = branch->merge[i]->src;
			continue;
		else if (0 <= fetch_prune_tags_config)
		if (item->ignore)

			oid_array_append(oids, &oid);

/*
		argv_array_push(argv, "--dry-run");
		    N_("number of submodules fetched in parallel")),
	if (!strcmp(k, "submodule.fetchjobs")) {
				       remote, pretty_ref, summary_width);
	/* uptodate lines are only shown on high verbosity level */
		/* skip duplicates and refs that we already have */

	 */
	for (i = url_len - 1; url[i] == '/' && 0 <= i; i--)
}
		strbuf_add_unique_abbrev(&quickref, &ref->new_oid, DEFAULT_ABBREV);
		 N_("run 'gc --auto' after fetching")),
			die(_("--unshallow on a complete repository does not make sense"));
						    recurse_submodules,
			if (run_command_v_opt(argv.argv, RUN_GIT_CMD)) {
			       struct refspec *rs,
		string_list_insert(&remote_refs_list, ref->name);
		for (rm = *head; rm; rm = rm->next) {
		adjust_refcol_width(rm);

	updated = lookup_commit_reference_gently(the_repository,
		r = s_update_ref("forced-update", ref, 1);
	}
		const char *msg;
				free(ref);

static int update_local_ref(struct ref *ref,


		if (remote &&
		format_display(display, '!', _("[rejected]"),
				if (!i && !has_merge && ref_map &&
	else if (recurse_submodules == RECURSE_SUBMODULES_ON_DEMAND)
		return;
	}
		 * they would simply be duplicates of existing
 * locally.

{
		    PARSE_OPT_OPTARG, option_fetch_parse_recurse_submodules },
	if (error)
			RECURSE_SUBMODULES_ON : RECURSE_SUBMODULES_OFF;
	int cannot_reuse;
	 */
	free_refs(stale_refs);
	/*
	if (is_bare_repository() || !current_branch)
		 N_("fetch from multiple remotes")),
			for (i = url_len - 1; url[i] == '/' && 0 <= i; i--)
		if (!strcmp(argv[i], "tag")) {
{
	return git_default_config(k, v, cb);
	}


 */
		/* no command line request */

		struct refspec *fetch_refspec;
}

	opt.quiet = 1;
			continue;
		   &recurse_submodules_default, N_("on-demand"),
static int fetch_multiple(struct string_list *list, int max_children)
{
		transport_unlock_pack(gsecondary);
	if (!strcmp(remote, local)) {

	if (server_options.nr)
static const char *upload_pack;

		 * ref not followed by a peeled reference, so we need
	if (!ret)
			what = _("[new branch]");
		struct ref *rm;
				  const struct hashmap_entry *eptr,
			      tags, &autotags);
static void create_fetch_oidset(struct ref **head, struct oidset *out)
		gsecondary = prepare_transport(transport->remote, 0);
	return transport;

#define STORE_REF_ERROR_OTHER 1
	transport_set_verbosity(transport, verbosity, progress);
			case FETCH_HEAD_NOT_FOR_MERGE:
					     commit_graph_flags,
		return 0;
	}
		(void) for_each_remote(get_one_remote_for_fetch, &list);
static int find_and_replace(struct strbuf *haystack,

		} else {
static void unlock_pack(void)
static int recurse_submodules = RECURSE_SUBMODULES_DEFAULT;

			   int summary_width)
	OPT__VERBOSITY(&verbosity),
			       const struct ref *remote_refs,
		const char *s = negotiation_tip.items[i].string;
		fast_forward = in_merge_bases(current, updated);
				/* fall-through */
		if (filter_options.choice || has_promisor_remote())
static int tags = TAGS_DEFAULT, unshallow, update_shallow, deepen;
		if (verbosity < 0)
	OPT_STRING_LIST('o', "server-option", &server_options, N_("server-specific"), N_("option to transmit")),
	plen = strlen(p);
					oid_to_hex(&rm->old_oid),
		remote_refs = NULL;
