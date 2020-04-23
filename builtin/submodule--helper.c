		return 1;
				die(_("%s doesn't support --super-prefix"),
	strbuf_release(&sb);
		 */
	unsigned just_cloned;

			   N_("string"),


	strbuf_release(&sb);
		foreach_alt_odb(add_possible_reference_from_superproject, &sas);
 * relative to the submodule working tree, if up_path is specified, or to

	strbuf_addf(&sb, "submodule.%s.update", sub->name);
static void print_status(unsigned int flags, char state, const char *path,
{
	 * for having the same output for dir/sub_dir
	int recursive = 0;




	free(displaypath);
	}
		struct strbuf buf = STRBUF_INIT;
static int module_name(int argc, const char **argv, const char *prefix)

{
			     git_submodule_helper_usage, 0);
	if (argc != 1)
			printf(format, displaypath);

}

	argv_array_pushf(&cp_config.args, "submodule.%s\\.", sub->name);

		return;
	}
	int progress = 0;
		die("submodule--helper remote-branch takes exactly one arguments, got %d", argc);
	unsigned flags = ABSORB_GITDIR_RECURSE_SUBMODULES;
		}
	git_dir = read_gitfile(buf.buf);
		sas.error_mode = SUBMODULE_ALTERNATE_ERROR_IGNORE;
			       struct pathspec *pathspec,
	if (is_dir_sep(remoteurl[len-1]))

}
			    N_("parallel jobs")),
	return 0;
		argv_array_pushf(&cpr.args, "%s/", displaypath);
		strbuf_reset(&sb);

		goto cleanup;
	sub = submodule_from_path(the_repository, &null_oid, path);
	int recommend_shallow;
	strbuf_addf(&remotesb, "remote.%s.url", remote);
	free(remote);
	free(displaypath);
			 path, NULL);
	if (!strcmp(var, "submodule.fetchjobs"))

int cmd_submodule__helper(int argc, const char **argv, const char *prefix)
				   module_clone_options);
		OPT_STRING(0, "depth", &suc.depth, "<depth>",
			printf(" (%s)", name);
		error_strategy = xstrdup("die");
		suc->quickstop = 1;
		printf(_("could not create empty submodule directory %s"),
	/* detached HEAD */
			die(_("Expecting a full ref name, got %s"), refname);
	if (!result)
		argv_array_pushl(&cpr.args, "submodule--helper", "status",
		goto cleanup;
	const char *name = NULL, *url = NULL, *depth = NULL;
		strbuf_addf(&sb, "/modules/%s/", sas->submodule_name);
		OPT_STRING(0, "prefix", &prefix,
		if (!(flags & OPT_FORCE)) {
			   N_("reference repository")),


			if (run_command(&cp_rm))
				if (!strcmp(rs->src, "HEAD")) {
	{"status", module_status, SUPPORT_SUPER_PREFIX},
		int i;
		*rfind = '\0';
	if (!url_is_local_not_ssh(remoteurl) || is_absolute_path(remoteurl))
	}
		usage_with_options(git_submodule_helper_usage,
		OPT_STRING(0, "recursive-prefix", &suc.recursive_prefix,
		out->command = sub->update_strategy.command;
				      struct strbuf *err,
					   error_strategy);
	if (!strcmp(error_strategy, "die"))

#include "builtin.h"
		    argv[1]);
		strbuf_addf(out, _("Skipping unmerged submodule %s"), sb.buf);

	struct deinit_cb info = DEINIT_CB_INIT;
		OPT_STRING(0, "prefix", &prefix,
			return 1;
	}
	} error_mode;
		cpr.dir = path;
static int module_deinit(int argc, const char **argv, const char *prefix)
				; /* nothing */
		ALLOC_GROW(list->entries, list->nr + 1, list->alloc);
				const char *up_path)
	res = relative_url(remoteurl, url, up_path);
		BUG("cannot have prefix '%s' and superprefix '%s'",
cleanup:
			sub_origin_url = xstrdup(sub->url);

			     git_submodule_helper_usage, 0);
{
	{"ensure-core-worktree", ensure_core_worktree, 0},
	unsigned int flags;
		strbuf_addf(out,
	};
	}
}
	free(*remoteurl);
		strbuf_release(&sb);


{
		char *sm_alternate;
		NULL
		argv_array_push(&child->args, suc->depth);
			need_free_url = 1;
		else
{
	}
				sub->name, url, displaypath);
	info.argc = argc;
	remoteurl = xstrdup(argv[2]);
	const struct submodule *sub;
	const char *val;

		char *cfg_file, *abs_path;
	argv_array_pushl(&cp.args, "submodule--helper",
		 */

			}
	const char *up_path = NULL;

	argc--;

		      displaypath);
	{"config", module_config, 0},
		ce = suc->list.entries[suc->current];
		if (prepare_to_clone_next_submodule(ce, child, suc, err)) {
	{"update-module-mode", module_update_module_mode, 0},
	info.prefix = prefix;
		die(_("could not get submodule directory for '%s'"), path);
		argv_array_push(&child->args, "--progress");
	};
	}
		argv_array_push(&cp.args, single_branch ?
	.recommend_shallow = -1, \
		}

		argv_array_pushl(&cp.args, "--depth", depth, NULL);
static int print_default_remote(int argc, const char **argv, const char *prefix)
		return 1;
				displaypath);
{
	const char *prefix;
			}

}
	.update = SUBMODULE_UPDATE_STRATEGY_INIT, \
static char *relative_url(const char *remote_url,
#include "repository.h"
		if (!prepare_to_clone_next_submodule(ce, child, suc, err)) {
		const struct cache_entry *ce = list->entries[i];
	struct option module_foreach_options[] = {
}
			printf("%06o %s U\t", ce->ce_mode, oid_to_hex(&null_oid));
	argv_array_push(&child->args, "clone");

	struct submodule_alternate_setup sas = SUBMODULE_ALTERNATE_SETUP_INIT;
		strbuf_addf(err, _("Failed to clone '%s' a second time, aborting"),
	struct strbuf buf = STRBUF_INIT;
	/* setup alternateLocation and alternateErrorStrategy in the cloned submodule if needed */

		free(abs_path);
	int quiet = 0;
}
#define USE_THE_INDEX_COMPATIBILITY_MACROS
	strbuf_addf(&sb, "%s%s%s", remoteurl, colonsep ? ":" : "/", url);
	} else if (sub->update_strategy.type != SM_UPDATE_UNSPECIFIED) {
	const char *const git_submodule_helper_usage[] = {
		if (!strcmp(refname, "HEAD"))
	/* configuration parameters which are passed on to the children */
	index = suc->current - suc->list.nr;
		argv_array_push(&cp.args, object_id);
{
					 path, NULL);
	cp.use_shell = 1;
			super_config_url = xstrdup(sub->url);
		NULL

		if (!remove_dir_recursively(&sb_rm, 0))
	puts(res);
		sm_alternate = compute_alternate_path(sb.buf, &err);
	if (module_list_compute(argc, argv, prefix, &pathspec, &list) < 0)
	/* index into 'list', the list of submodules to look into for cloning */
	parse_pathspec(pathspec, 0,
 * when a local part has a colon in its path component, too.
	for_each_listed_submodule(&list, runcommand_in_submodule_cb, &info);
		warning(_("could not look up configuration '%s'. Assuming this repository is its own authoritative upstream."), remotesb.buf);
			up_path = get_up_path(path);
	child->no_stdin = 1;
	if (!strcmp(head, "HEAD"))
}
		die(_("failed to update remote for submodule '%s'"),
{
#define OPT_QUIET (1 << 0)
			*p = suc->current;
#define SYNC_CB_INIT { NULL, 0 }
		error("pathspec and --all are incompatible");
	char *cw;
		      displaypath);
			      "branch from superproject, but the superproject "
		abs_path = absolute_pathdup(path);
	};
				    sas->submodule_name, err.buf);
	/* failed clones to be retried again */
{
	struct strbuf sb = STRBUF_INIT;
			 "--ignore-submodules=dirty", "--quiet", "--",

			free(sm_alternate);
	if (quiet)
	if (just_cloned &&
			    N_("whether the initial clone should follow the shallow recommendation")),

		DO_UNSET = 2
		 */

	}
}
		return displaypath;
		argv_array_pushf(&cp.env_array, "name=%s", sub->name);
			strbuf_addstr(&sb, ce->name);
{
	if (strip_suffix(odb->path, "/objects", &len)) {
			     git_submodule_helper_usage, 0);
	struct strbuf displaypath_sb = STRBUF_INIT;

	char *key;
		OPT_END()


	const struct object_id *ce_oid = &list_item->oid;
	return 0;

static void determine_submodule_update_strategy(struct repository *r,

	}
	if (repo_submodule_init(&subrepo, the_repository, sub))
				      void *suc_cb,
#define SUBMODULE_ALTERNATE_SETUP_INIT { NULL, \
					sas->submodule_name, err.buf);
#include "parse-options.h"
	    (out->type == SM_UPDATE_MERGE ||
		module_list_active(&list);
		return xstrfmt("%s%s", super_prefix, path);
		else
				      void *suc_cb,
	cp.git_cmd = 1;
		out = xstrdup(sb.buf);

	} else if (super_prefix) {
	prepare_submodule_repo_env(&cp.env_array);
	if (git_config_set_in_file_gently(sb.buf, remote_key, sub_origin_url))
	fputs(submodule_strategy_to_string(&update_strategy), stdout);
static int module_list(int argc, const char **argv, const char *prefix)
		printf(_("Synchronizing submodule url for '%s'\n"),
	struct child_process cp = CHILD_PROCESS_INIT;
				   "parallel/update");
	 * Only mention uninitialized submodules when their
	strbuf_release(&sb);
	info.prefix = prefix;
	if (!sub)

		strbuf_addstr(&sb, "../");
					 item->string, NULL);
cleanup:
	child->err = -1;
 * Determine whether 'ce' needs to be cloned. If so, prepare the 'child' to
	free(key);
		if (git_config_set_gently(sb.buf, url))

	update_clone_config_from_gitmodules(&suc.max_jobs);
{
{
	strbuf_reset(&displaypath_sb);
			   unsigned int flags)
		if (!(flags & OPT_QUIET))
			free(oldurl);
	return 0;


			strbuf_reset(&sb);
	} command = 0;
	}
	if (update)
	 * by default, only initialize 'active' modules.

		       !strcmp(ce->name, active_cache[i + 1]->name))
	if (!sub)
	 * contains a single argument. This is done for maintaining a faithful
		 * before porting, it is also made available after porting.
		} else
			     git_submodule_helper_usage, 0);
	for_each_listed_submodule(&list, status_submodule_cb, &info);
	if (argc < 3)
	puts(res);


		refspec_appendn(&refspec, argv + 2, argc - 2);
	if (!up_path || !is_relative)
#define SUBMODULE_UPDATE_CLONE_INIT { \
	struct pathspec pathspec;
		up_path = argv[2];
		 * existing PATH variable. Hence, to avoid that, we expose
	if (!p)
	}
		OPT__FORCE(&force, N_("Remove submodule working trees even if they contain local changes"), 0),
	/* Get the submodule's head ref and determine if it is detached */
		return 1;
		NULL
struct submodule_update_clone {
 */



	 * Check if 'path' ends with slash or not


	const struct submodule *sub;
	free(sm_alternate);
	if (!refname)

	free(remote);


	strbuf_reset(&sb);
		free(toplevel);
	{"deinit", module_deinit, 0},
			   int quiet, int progress, int single_branch)
		ps_matched = xcalloc(pathspec->nr, 1);
	struct strbuf sb = STRBUF_INIT;
	free(remote);
					    just_cloned, path, update,
	};
		fprintf(stdout, "%s\n", ce->name);



{
	argc = parse_options(argc, argv, prefix, module_config_options,
	}
	/* update parameter passed via commandline */
{
		    starts_with_dot_slash(sub->url)) {
	if (suc->warn_if_uninitialized) {
	suc->update_clone_nr++;

}
	argc = parse_options(argc, argv, prefix, module_init_options,
			die(_("Invalid update mode '%s' for submodule path '%s'"),
	strbuf_release(&sb);

		if (!refs) {
	if (!strcmp(refname, "HEAD"))
			die(_("No url found for submodule path '%s' in .gitmodules"),
		cpr.git_cmd = 1;
			const struct refspec_item *rs = &refspec.items[i];
	 * This is to avoid pushing to the exact same URL as the parent.
}
	repo_init_revisions(the_repository, &rev, NULL);
{
				NULL);
			   N_("path into the working tree, across nested "

	ret = remote_submodule_branch(argv[1]);
	if (!sub)
	up_path = argv[1];


	{"remote-branch", resolve_remote_submodule_branch, 0},
 * working tree. Returns the origin URL of the submodule.
}
	free(remoteurl);
		OPT_STRING(0, "prefix", &prefix,
	const char *recursive_prefix;
	if (!head)
	free(displaypath);
			remoteurl = strbuf_detach(&sb, NULL);
	if (single_branch >= 0)
		remoteurl[len-1] = '\0';
		if (!refname)
	struct child_process cp_config = CHILD_PROCESS_INIT;
	struct object_id head_oid;
			suc->current ++;

			     git_submodule_helper_usage, 0);
	struct pathspec pathspec;
	{"foreach", module_foreach, SUPPORT_SUPER_PREFIX},
		 * Prepend a './' to ensure all relative
		OPT_END()

 * http://a.com/b  ../../../c       http:/c          error out
	else
static const char alternate_error_advice[] = N_(

	strbuf_release(&sb);
	      "subcommand"), argv[1]);
}
		OPT_STRING(0, "path", &path,
}
	int dissociate;
		 * otherwise a submodule name containing '/' will be broken
			     git_submodule_helper_usage, 0);
				void *cb_data)
	int recursive;
	};
		&& update_type == SM_UPDATE_NONE)) {

			fprintf(stderr, _("warning: command update mode suggested for submodule '%s'\n"),
	 * set in the per-worktree config.
		die(_("run_command returned non-zero status for %s\n."),
			url = sub->url;


}
	info.prefix = prefix;


	 * if HEAD then the superproject is in a detached head state, otherwise
	char *remote_key = NULL;
}
		info.flags |= OPT_RECURSIVE;
		OPT_END()
	if (argc > 2) {
static void init_submodule_cb(const struct cache_entry *list_item, void *cb_data)
{
	char *remoteurl, *res;

	struct strbuf sb = STRBUF_INIT;

		p = xmalloc(sizeof(*p));
	if (argc == 4)
	 * We saved the output and put it out all at once now.
	};
	fprintf(stdout, "dummy %s %d\t%s\n",
	} else {
				       void *cb_data)
	if (argc != 2 && argc != 3)
	 * standard layout with .git/(modules/<name>)+/objects
	if (!skip_prefix(refname, "refs/heads/", &refname))
		struct strbuf sb = STRBUF_INIT;

		sub_origin_url = xstrdup("");
static void status_submodule(const char *path, const struct object_id *ce_oid,
		if (!strcmp(argv[1], commands[i].cmd)) {
			url = compute_submodule_clone_url(oldurl);
				      each_submodule_fn fn, void *cb_data)
		die(_("Failed to resolve HEAD as a valid ref."));
}


		N_("git submodule--helper foreach [--quiet] [--recursive] [--] <command>"),
	if (flags & OPT_RECURSIVE) {
		refspec_clear(&refspec);
	free(sub_origin_url);

			strbuf_addf(&sb, "%s/%s", suc->recursive_prefix, ce->name);
		if (sub->update_strategy.type == SM_UPDATE_COMMAND)
	if (module_list_compute(0, NULL, prefix, &pathspec, &list) < 0)
		oidcpy(output, oid);
				break;


		print_status(flags, '+', path, ce_oid, displaypath);
	path = argv[1];
	}
	printf("%c%s %s", state, oid_to_hex(oid), displaypath);

		argv_array_pushf(&cp.args, "path=%s; %s",
				 sub->name, sub->url, displaypath);
	for (i = 0; i < list.nr; i++) {
 * http://a.com/b/ ../c             http://a.com/c   same as previous line, but
/*
		cp.git_cmd = 1;
		OPT__QUIET(&suc.quiet, N_("don't print cloning progress")),
				      displaypath);
}
	}
	int i;
	int (*fn)(int, const char **, const char *);
			   N_("use --reference only while cloning")),

	if (!capture_command(&cp_config, &sb_config, 0) && sb_config.len) {
				die(_("Submodule work tree '%s' contains local "



		strbuf_release(&buf);
			   const char *depth, struct string_list *reference, int dissociate,
	return 0;
	};
		if (ce_stage(ce))
 * relative file system path (if the superproject origin URL is a relative
		 * Since the path variable was accessible from the script
			url = compute_submodule_clone_url(sub->url);
	argc = parse_options(argc, argv, prefix, module_clone_options,


		struct string_list_item *item;
	if (!strcmp(branch, ".")) {
				}
		OPT_END()
	return 0;
	struct init_cb info = INIT_CB_INIT;
		OPT__QUIET(&quiet, "Suppress output for cloning a submodule"),
 */

	const char *update = NULL;
{

		}
	suc.prefix = prefix;
	free(remoteurl);
	static const char *describe_tags[] = { "--tags", NULL };

	const struct submodule *sub = NULL;

	struct module_list list = MODULE_LIST_INIT;
	if (!info->quiet)

	     out->type == SM_UPDATE_REBASE ||
		OPT_END()
		info.flags |= OPT_QUIET;

		prepare_possible_alternates(name, &reference);
static int resolve_relative_url_test(int argc, const char **argv, const char *prefix)
		OPT_BOOL(0, "dissociate", &suc.dissociate,
				oid_to_hex(ce_oid));

			continue;

{
	printf("\n");
	info.prefix = prefix;
}
		OPT__QUIET(&quiet, N_("Suppress submodule status output")),
typedef void (*each_submodule_fn)(const struct cache_entry *list_item,
 *

		OPT_BOOL(0, "recommend-shallow", &suc.recommend_shallow,
			if (get_super_prefix() &&


	free(error_strategy);
static int clone_submodule(const char *path, const char *gitdir, const char *url,

	struct option module_init_options[] = {
	};

			    N_("check if it is safe to write to the .gitmodules file"),
		detached_head = 1;
struct foreach_cb {

	if (module_list_compute(argc, argv, prefix, &pathspec, &list) < 0)

		usage("git submodule--helper <command>");
}
	if (!file_exists(sm_gitdir)) {
	strbuf_release(&sb_config);
}
		strbuf_release(&sb);
static const char *remote_submodule_branch(const char *path)
	return 0;
		print_status(flags, '+', path, &oid, displaypath);

	else
		return 0;
	int colonsep = 0;
		char *sub_key = xstrfmt("submodule.%s", sub->name);
						struct submodule_update_strategy *out)
	if (pathspec.nr)


	const struct cache_entry *ce;
			die(_("failed to recurse into submodule '%s'"),
	char *res;
						const char *update,
			     git_submodule_helper_usage, 0);
	 */
	if (sub && sub->url) {
	enum {
		argv_array_push(&child->args, suc->single_branch ?
	}

	child->stdout_to_stderr = 1;
		OPT_BOOL(0, "dissociate", &dissociate,
	}
		die("submodule %s doesn't exist", argv[1]);

	int quiet;
static char *get_default_remote(void)
		struct refspec refspec = REFSPEC_INIT_PUSH;
			 * to make sure an entry is returned only once.
		const char *format;
	return update_submodules(&suc);
		out->type = sub->update_strategy.type;
	 * translation from shell script.
 * URL repo. The `up_path` argument, if specified, is the relative
		while (i + 1 < active_nr &&
	struct pathspec pathspec;
		strbuf_release(&buf);
				/* fallthrough */
	char *sm_alternate = NULL, *error_strategy = NULL;
	if (!sub) {
	{"clone", module_clone, 0},
	cp.no_stdin = 1;
 * The `url` argument is the URL that navigates to the submodule origin
static void prepare_possible_alternates(const char *sm_name,
		argv_array_push(&cpr.args, "--");
	else if (!strcmp(error_strategy, "ignore"))
	free(upd);

	const char *superproject_head;

static int module_foreach(int argc, const char **argv, const char *prefix)


		return 1;
	}
	 * Set active flag for the submodule being initialized
 * the superproject working tree otherwise.
{
		argv_array_push(&cpr.args, "--super-prefix");
		argv_array_push(&child->args, "--require-init");



	/* Equivalent to ACTION_SET in builtin/config.c */


		struct child_process cp = CHILD_PROCESS_INIT;
		}

		strbuf_addch(out, '\n');
static int git_update_clone_config(const char *var, const char *value,
					    !strcmp(head, superproject_head))
	strbuf_reset(&sb);
			char *oldurl = url;

	struct init_cb *info = cb_data;
	 * $sm_path, $displaypath, $sha1 and $toplevel only when the command

	{"is-active", is_active, 0},
static int add_possible_reference_from_superproject(

	const char *super_prefix = get_super_prefix();
"An alternate computed from a superproject's alternate is invalid.\n"
		return 1;

	if (module_list_compute(argc, argv, prefix, &pathspec, &list) < 0)
	argv_array_pushl(&cp_config.args, "config", "--get-regexp", NULL);
		die(_("submodule--helper print-default-remote takes no arguments"));
	.single_branch = -1, \
};
	strbuf_addf(&sb, "submodule.%s.url", sub->name);

		goto cleanup;
		BUG("We could get the submodule handle before?");
static int module_init(int argc, const char **argv, const char *prefix)
		struct strbuf sb = STRBUF_INIT;
	}
	static const char *describe_all_always[] = { "--all", "--always", NULL };


	return 0;
	}
	}
		if (!capture_command(&cp, &sb, 0)) {
		N_("git submodule--helper init [<options>] [<path>]"),
{

				die(_("submodule '%s' cannot add alternate: %s"),
	ALLOC_GROW(suc->update_clone, suc->update_clone_nr + 1,
/*
	} else if (prefix) {
static int ensure_core_worktree(int argc, const char **argv, const char *prefix)
			 info->prefix, info->flags);
		if (!skip_prefix(refname, "refs/heads/", &refname))
 * http://a.com/b  ../../c          http://c         error out

		die("submodule--helper is-active takes exactly 1 argument");
			break;
			if (git_config_get_string(sb.buf, &remote_url))

		result = -1;
		 * the user later decides to init this submodule again

	const char *url;
	argv_array_pushl(&child->args, "--path", sub->path, NULL);

			switch (count_refspec_match(rs->src, local_refs, NULL)) {
	int progress;
		active_modules.entries[active_modules.nr++] = ce;
	struct submodule_update_clone suc = SUBMODULE_UPDATE_CLONE_INIT;
		OPT__QUIET(&quiet, N_("Suppress submodule status output")),
		if (run_command(&cpr))
			goto cleanup;
				   module_deinit_options);
		die("submodule--helper update-module-clone expects <just-cloned> <path> [<update>]");
			    url, path);

	strbuf_addf(&sb, "%s/modules/%s", get_git_dir(), name);

	if (!(flags & OPT_QUIET))
				      void *idx_task_cb)

		OPT_STRING(0, "url", &url,
		if (flags & OPT_QUIET)

	if (!submodule_from_path(the_repository, &null_oid, path))
		} else


		free((void*)url);

	} else {
	if (state == ' ' || state == '+') {
		die(_("Value '%s' for submodule.alternateLocation is not recognized"), sm_alternate);
static char *compute_rev_name(const char *sub_path, const char* object_id)
		die(_("could not get a repository handle for submodule '%s'"), path);
		if (starts_with_dot_slash(sub->url) ||
	init_submodule(list_item->name, info->prefix, info->flags);
}
	if (suc->recommend_shallow && sub->recommend_shallow == 1)
		usage_with_options(git_submodule_helper_usage,


	int quiet = 0;
#define DEINIT_CB_INIT { NULL, 0 }
				return 1;
	{"relative-path", resolve_relative_path, 0},
		strbuf_addch(out, '\n');
	strbuf_release(&buf);
	res = relative_url(remoteurl, url, up_path);
	const struct submodule *sub;

	if (prefix && super_prefix) {
		   "[--single-branch] "
		      path);
	int force = 0;
		struct child_process cpr = CHILD_PROCESS_INIT;
		strbuf_release(&sb);
	const struct cache_entry *ce;

	{"push-check", push_check, 0},
		absorb_git_dir_into_superproject(list.entries[i]->name, flags);
		return 1;
	};
	if (ends_with(url, "/"))
		prepare_submodule_repo_env(&cpr.env_array);


	strbuf_addf(&sb, "%s/.git", ce->name);

}
				"recursing in the nested submodules of %s\n."),
			default:
	struct strbuf sb = STRBUF_INIT;
	submodule_to_gitdir(&sb, path);

	/*
			_("Submodule path '%s' not initialized"),
{
	if (!is_absolute_path(path)) {
	int quiet = 0;
static int update_clone_task_finished(int result,
}
			ABSORB_GITDIR_RECURSE_SUBMODULES),
	    !is_git_directory(git_dir)) {

			       oid_to_hex(&ce->oid), ce_stage(ce));
		ce  = suc->failed_clones[idx];

			     git_submodule_helper_usage, PARSE_OPT_KEEP_ARGV0);
	const char *const git_submodule_helper_usage[] = {
	const char *prefix;

		return xstrdup(path);
			cp_rm.git_cmd = 1;
			   N_("string"),
	{"name", module_name, 0},
		/* detached HEAD */
			    N_("force cloning progress")),
		; /* do nothing */
		return 1;
	 */

	if (repo_config_get_string_const(the_repository, sb.buf, &url)) {
		die(_("failed to get the default remote for submodule '%s'"),
 * NEEDSWORK: This works incorrectly on the domain and protocol part.
static void for_each_listed_submodule(const struct module_list *list,
	argv_array_push(&cp.args, "--");
		struct child_process cpr = CHILD_PROCESS_INIT;

				      struct strbuf *err,
	/*
 * When the output is a relative file system path, the path is either
		print_status(flags, '-', path, ce_oid, displaypath);
	free(head);

			if (check_submodule_name(*argv) < 0)
	struct pathspec pathspec;
	} else {

	if (info->argv[0] && run_command(&cp))
static int module_list_compute(int argc, const char **argv,
{
	strbuf_addf(&sb, "submodule.%s.url", sub->name);
#include "submodule.h"
	argc = parse_options(argc, argv, prefix, module_deinit_options,
	strbuf_reset(&sb);
	struct submodule_update_clone *suc = suc_cb;
	if (suc->single_branch >= 0)
		if (info->quiet)
#include "refs.h"
		die("remote '%s' not configured", argv[1]);
			displaypath);
	struct submodule_update_strategy update;
 * http://a.com/b  ../c             http://a.com/c   as is
					   struct child_process *child,
		argv_array_pushv(&cp.args, info->argv);
}
	rev.abbrev = 0;
		}
	}
		return;
				_("Submodule '%s' (%s) registered for path '%s'\n"),
	if (starts_with_dot_slash(sb.buf))
"submodule.alternateErrorStrategy to 'info' or, equivalently, clone with\n"

}
	 */
	/*

	p = git_pathdup_submodule(path, "config");
	{"check-name", check_name, 0},
	/* remove the .git/config entries (unless the user already did it) */
					   "cloning, doesn't need cloning "
	if (!is_submodule_populated_gently(path, NULL))
	diff_files_result = run_diff_files(&rev, 0);
		struct child_process cpr = CHILD_PROCESS_INIT;
			    displaypath);


cleanup:
	if (suc->prefix)

	{"resolve-relative-url", resolve_relative_url, 0},
	struct pathspec pathspec;
{
		if (!starts_with_dot_slash(remoteurl) &&
 * file system path).
		}
		OPT_STRING_LIST(0, "reference", &reference,

			N_("Recurse into nested submodules")),
	const char *path;

		OPT_BOOL(0, "single-branch", &suc.single_branch,
}
	argc = parse_options(argc, argv, prefix, module_update_clone_options,
 * Exit non-zero if any of the submodule names given on the command line is
		 * remoteurls start with './' or '../'
	}
	}
			string_list_append(sas->reference, xstrdup(sb.buf));




	char *ps_matched = NULL;
struct module_list {
	free(sm_gitdir);
	 *   checkout involve more straightforward sequential I/O.
		argv_array_push(&child->args, "--depth=1");
	sub = submodule_from_path(the_repository, &null_oid, path);
	const char *update_string;
	{"init", module_init, SUPPORT_SUPER_PREFIX},
	 * For the purpose of executing <command> in the submodule,


static char *compute_submodule_clone_url(const char *rel_url)
		strbuf_addch(err, '\n');
	struct repository subrepo;


	 * NEEDSWORK: the command currently has access to the variables $name,
	for_each_listed_submodule(&list, deinit_submodule_cb, &info);
			return commands[i].fn(argc - 1, argv + 1, prefix);
	int i;
}
	int all = 0;
	int dissociate = 0, require_init = 0;
	cp.dir = path;
		N_("git submodule--helper absorb-git-dirs [<options>] [<path>...]"),
	return 0;
static int is_active(int argc, const char **argv, const char *prefix)
	return result;
	if (!is_submodule_active(the_repository, path)) {

		unlink_or_warn(sb.buf);
	sas.reference = reference;
	return 0;
	if (validate_submodule_git_dir(sm_gitdir, name) < 0)
	enum SUBMODULE_ALTERNATE_ERROR_MODE {
			   N_("use --reference only while cloning")),
					if (!detached_head &&
			die(_("could not create directory '%s'"), sm_gitdir);
	const char *path, *update = NULL;
};
		      path);
	}

	 * NEEDSWORK: In a multi-working-tree world, this needs to be
	} else {
		OPT__QUIET(&quiet, N_("Suppress output for initializing a submodule")),
		free(sub_key);
	size_t len;
	connect_work_tree_and_git_dir(path, sm_gitdir, 0);
	struct deinit_cb *info = cb_data;
	if (rfind) {
	int argc;
	};
			 */
}
		}
	char *sub_git_dir = xstrfmt("%s/.git", path);
	free(key);
	char *sub_origin_url, *super_config_url, *displaypath;
	if (git_config_get_string(remotesb.buf, &remoteurl)) {
}
	struct update_clone_data *update_clone;

	struct object_id *output = cb_data;
		for_each_string_list_item(item, &suc->references)
	const char *prefix;
	int index;
}
	int idx = *idxP;

}
		const char *value = (argc == 3) ? argv[2] : NULL;
		info.flags |= OPT_QUIET;
			       struct module_list *list)
	const struct submodule *sub = submodule_from_path(r, &null_oid, path);
	else
		ALLOC_GROW(active_modules.entries,
	char *remoteurl = NULL;
	int just_cloned;
	struct strbuf sb = STRBUF_INIT;
		 * NEEDSWORK: instead of dying, automatically call
	}
	const struct submodule *sub;
					die("HEAD does not match the named branch in the superproject");
				      "modifications; use '-f' to discard them"),
	die(_("'%s' is not a valid submodule--helper "
{
{
		struct object_directory *odb, void *sas_cb)
	strbuf_reset(&sb);
	int i;
	if (argc != 2)
		up_path = NULL;
	argc = parse_options(argc, argv, prefix, module_list_options,
			printf("%06o %s %d\t", ce->ce_mode,
		die(_("refusing to create/use '%s' in another submodule's "
	{"print-default-remote", print_default_remote, 0},

	const char *displaypath = NULL;

		git_config_set_in_file(p, "submodule.alternateLocation",

		if (run_command(&cpr))
			if (!check_submodule_name(buf.buf))
	if (!sub)
			   N_("path"),

					  "--single-branch" :
	free(remoteurl);
	 * child process.
		}
	unsigned int flags;
	free(displaypath);


	key = xstrfmt("submodule.%s.branch", sub->name);
	const char *const git_submodule_helper_usage[] = {
#include "diffcore.h"
				const char *url,
static int resolve_relative_url(int argc, const char **argv, const char *prefix)
static struct cmd_struct commands[] = {
	if (quiet)
		N_("git submodule--helper update-clone [--prefix=<path>] [<path>...]"),
	for_each_listed_submodule(&list, init_submodule_cb, &info);
	}
	/*
	struct child_process cp = CHILD_PROCESS_INIT;
	const char *url = NULL;
static int prepare_to_clone_next_submodule(const struct cache_entry *ce,
	if (update) {
	};
			case 0:
	static const char *describe_contains[] = { "--contains", NULL };
	if (argc == 3)
					    ce->name, &displaypath_sb);

	for (i = 0; i < list.nr; i++)
	url = argv[3];

{
	if (need_free_url)
		branch = sub->branch;
	if (argc != 4)
						describe_all_always, NULL };
	int *idxP = idx_task_cb;
	const char **argv;
}
			argv_array_pushl(&cp_rm.args, "rm", "-qn",
	.max_jobs = 1, \
		 * remove the whole section so we have a clean state when
		submodule_unset_core_worktree(sub);
	sm_gitdir = absolute_pathdup(sb.buf);
		goto cleanup;
		argv_array_push(&cp.args, "--dissociate");
{
	/*

			die(_("Submodule (%s) branch configured to inherit "
	if (argc == 3 || (argc == 2 && command == DO_UNSET)) {
	if (force)


	if (repo_config_get_string_const(the_repository, key, &branch))
	needs_cloning = !file_exists(sb.buf);
{
	free(super_config_url);
struct cmd_struct {
	relurl = relative_url(remoteurl, rel_url, NULL);
	struct pathspec pathspec;
	if (git_config_get_string(sb.buf, &url)) {
	sub = submodule_from_path(the_repository, &null_oid, path);
	for (i = 0; i < list->nr; i++)

			_("Maybe you want to use 'update --init'?"));

static int update_submodules(struct submodule_update_clone *suc)
		N_("git submodule--helper config --check-writeable"),
}


	struct module_list list = MODULE_LIST_INIT;
		CHECK_WRITEABLE = 1,
		die(_("no submodule mapping found in .gitmodules for path '%s'"),
			die(_("Failed to register url for submodule path '%s'"),
	int quiet;


			   N_("reference repository")),
}
	 * it will be the resolved head ref.
		 * on windows. And since environment variables are
					       &rev, NULL);
		    !starts_with_dot_dot_slash(remoteurl)) {

	/* Equivalent to ACTION_GET in builtin/config.c */
	if (!is_dir_sep(path[strlen(path) - 1]))
static int module_update_module_mode(int argc, const char **argv, const char *prefix)

		argv_array_pushf(&cpr.args, "%s/", displaypath);


	if (!diff_result_code(&rev.diffopt, diff_files_result)) {

		path = strbuf_detach(&sb, NULL);

	static const char **describe_argv[] = { describe_bare, describe_tags,
		printf("%s\n", remote);
#include "run-command.h"
#define SUPPORT_SUPER_PREFIX (1<<0)

	char *remoteurl, *relurl;
	suc->update_clone[suc->update_clone_nr].just_cloned = needs_cloning;
		N_("git submodule--helper clone [--prefix=<path>] [--quiet] "
	if (!sub || !sub->name)
	const struct submodule *sub;
 * Returns 1 if it was the last chop before ':'.
	if (!remote || remote->origin == REMOTE_UNCONFIGURED)
		 * path via the args argv_array and not via env_array.
	}
}

	 */
	 * When the url starts with '../', remove that and the
		if (flags & OPT_QUIET)
		      path);
		return 1;
	if (!strcmp(up_path, "(null)"))
	if (!sm_alternate)
	strbuf_reset(&sb);
	int update_clone_nr; int update_clone_alloc;
 * http://a.com/b  ../../../../../c    .:c           error out
		die(_("Expecting a full ref name, got %s"), refname);
		} else if (starts_with_dot_slash(url))
		*max_jobs = parse_submodule_fetchjobs(var, value);
	if (git_config_get_string(sb.buf, &dest))
		if (require_init && !access(path, X_OK) && !is_empty_dir(path))
		ret = dest;

			       const char *prefix,
	printf("%s", relative_path(argv[1], argv[2], &sb));
			argv_array_push(&cpr.args, "--quiet");
			die(_("No such ref: %s"), "HEAD");
			die(_("bad value for update parameter"));
						break;
		strbuf_addstr(&sb, "../");
		const struct cache_entry *ce = active_cache[i];
{
#include "object-store.h"
static void module_list_active(struct module_list *list)

	argv_array_push(&cp.args, "--no-checkout");
		OPT_BOOL(0, "single-branch", &single_branch,
{
				    rs->src);
	else
	else
		if (suc->recursive_prefix)

	const char *depth;
	if (idx < suc->list.nr) {
		 * absorbgitdirs and (possibly) warn.
	struct string_list reference = STRING_LIST_INIT_NODUP;
		if (!(flags & OPT_QUIET))
 *
};
			     git_submodule_helper_usage, 0);
	superproject_head = argv[1];
	strbuf_release(&sb);
	struct submodule_update_clone *suc = suc_cb;

	 */

		   suc->update_clone_alloc);

			argv_array_push(&cpr.args, "--quiet");

		*idx_task_cb = p;
	 */

			return 0;

			case 1:

			   N_("alternative anchor for relative paths")),
		argv_array_push(&cp.args, "--progress");
	char *displaypath;
		} else {
		info.flags |= OPT_QUIET;
	 * If there are no path args and submodule.active is set then,
	} else
	struct option module_list_options[] = {

	int need_free_url = 0;
	}
		suc->current ++;
		list->entries[list->nr++] = ce;
	return 0;
		remoteurl = xgetcwd();
	strbuf_addf(&sb, "branch.%s.remote", refname);
	path = argv[2];
		SUBMODULE_ALTERNATE_ERROR_IGNORE
	char *displaypath;

	strbuf_reset(&sb);
		    !S_ISGITLINK(ce->ce_mode))
				val, path);
	free(remoteurl);
	return ret;

	int single_branch = -1;
	if (quiet)
		die(_("failed to register url for submodule path '%s'"),
	return needs_cloning;

	return 0;
			*remoteurl);
	char *sub_config_path = NULL;
			BUG("how did we read update = !command from .gitmodules?");
		die(_("no submodule mapping found in .gitmodules for path '%s'"),
	SUBMODULE_ALTERNATE_ERROR_IGNORE, NULL }
	const char *prefix;
	struct strbuf sb = STRBUF_INIT;
	sas.submodule_name = sm_name;

		die("resolve-relative-url-test only accepts three arguments: <up_path> <remoteurl> <url>");
	struct sync_cb info = SYNC_CB_INIT;
		return print_config_from_gitmodules(the_repository, argv[1]);
	     out->type == SM_UPDATE_NONE))
	if (module_list_compute(argc, argv, prefix, &pathspec, &list) < 0)
#include "quote.h"
	if (suc->references.nr) {

		return;
	if (error_strategy)
	}
					    &update_strategy);

		argv_array_pushf(&cp.env_array, "toplevel=%s", toplevel);
	struct remote *remote;
			format = _("Cleared directory '%s'\n");
	int failed_clones_nr, failed_clones_alloc;
{
{
	if (!git_dir)
		OPT_CMDMODE(0, "check-writeable", &command,

		   "[--reference <repository>] [--name <name>] [--depth <depth>] "
	/*
	free(sm_alternate);
	struct strbuf sb = STRBUF_INIT;
			die(_("could not resolve HEAD ref inside the "
static int starts_with_dot_dot_slash(const char *str)
	if (git_config_set_gently(sb.buf, super_config_url))
		OPT_END()
}
	printf("%s\n", sub->name);

	if (oid)
 * invalid. If no names are given, filter stdin to print only valid names
	if (argc != 2)


		die("resolve-relative-url only accepts one or two arguments");
	return 0;
			   N_("alternative anchor for relative paths")),
		goto cleanup;
		/* the repository is its own authoritative upstream */
		die(_("No url found for submodule path '%s' in .gitmodules"),
			 N_("Recurse into nested submodules")),
		die(_("No url found for submodule path '%s' in .gitmodules"),
}

		N_("git submodule--helper config <name> [<value>]"),
	if (suc->dissociate)
		update_submodule(&suc->update_clone[i]);
		/*
		die(_("index file corrupt"));

			char *remote = get_default_remote();
	const struct submodule *sub;
	struct string_list references;
		 * be taken as a file name.
static int module_status(int argc, const char **argv, const char *prefix)
	strbuf_strip_suffix(&sb, "\n");
			 N_("clone only one branch, HEAD or --branch")),
		NULL
	git_config_get_string("submodule.alternateLocation", &sm_alternate);
		die("submodule--helper relative-path takes exactly 2 arguments, got %d", argc);
cleanup:
			   N_("path into the working tree")),
	const char *branch = NULL;
	sync_submodule(list_item->name, info->prefix, info->flags);
		die(_("cannot strip one component off url '%s'"),
{
{
				die("src refspec '%s' must name a ref",
	 */
	struct strbuf sb_config = STRBUF_INIT;
static void deinit_submodule_cb(const struct cache_entry *list_item,
		struct object_id oid;
		die(_("Value '%s' for submodule.alternateErrorStrategy is not recognized"), error_strategy);
			die(_("failed to recurse into submodule '%s'"), path);
			     unsigned int ce_flags, const char *prefix,
			i++;
			upd = xstrdup("none");

		goto cleanup;
	if (argc == 1 && command == CHECK_WRITEABLE)
	char *key;
			   N_("url where to clone the submodule from")),
		N_("git submodule--helper sync [--quiet] [--recursive] [<path>]"),
			switch (sas->error_mode) {
				sub->name);
		url = xstrdup(sub->url);
	 */
			   N_("path"),

}
	displaypath = get_submodule_displaypath(path, prefix);
		BUG("submodule--helper ensure-core-worktree <path>");
{
};
static int push_check(int argc, const char **argv, const char *prefix)
	const char *const git_submodule_helper_usage[] = {
{
	struct option module_update_clone_options[] = {
}
	{"absorb-git-dirs", absorb_git_dirs, SUPPORT_SUPER_PREFIX},
{
		out = xstrdup(sb.buf + 2);
	.list = MODULE_LIST_INIT, \

		OPT_BIT(0, "cached", &info.flags, N_("Use commit stored in the index instead of the one stored in the submodule HEAD"), OPT_CACHED),
			free(remote_url);
			    ce->name);
	return 1;
				 * checked out in the superproject.
	int quiet = 0;
					       diff_files_args.argv,
			sub_origin_url = relative_url(remote_url, sub->url, up_path);
		   "--url <url> --path <path>"),
	argc = parse_options(argc, argv, prefix, module_status_options,

		strbuf_release(&sb_rm);
{
	git_config_get_string("submodule.alternateErrorStrategy", &error_strategy);

	if (sm_alternate)
			int *p = xmalloc(sizeof(*p));
		OPT_INTEGER('j', "jobs", &suc.max_jobs,

		OPT_BOOL(0, "recursive", &recursive,
		strbuf_add(&sb, odb->path, len);
	struct module_list list = MODULE_LIST_INIT;

	/*
#define OPT_FORCE (1 << 3)
		*rfind = '\0';
		if (run_command(&cpr))
		is_relative = 1;
	usage_with_options(git_submodule_helper_usage, module_config_options);
	oidcpy(&suc->update_clone[suc->update_clone_nr].oid, &ce->oid);
	struct sync_cb *info = cb_data;
	if (!sub)
static int module_config(int argc, const char **argv, const char *prefix)
#define STATUS_CB_INIT { NULL, 0 }
};
				    quiet, progress, single_branch))
	if (!argc && git_config_get_value_multi("submodule.active"))
#include "remote.h"
		OPT_END()

 * (which is primarily intended for testing).
	struct strbuf sb = STRBUF_INIT;

			 displaypath);
	size_t len = strlen(remoteurl);
		return "master";
	if (remote)

	} else {
	child->git_cmd = 1;
			argv_array_pushl(&child->args, "--reference", item->string, NULL);
	/*
	 * last directory in remoteurl.
};
		       PATHSPEC_PREFER_FULL,

#include "advice.h"
	return 0;

		idx -= suc->list.nr;
	rfind = strrchr(*remoteurl, ':');

	struct module_list list;
	if (suc->update.type == SM_UPDATE_NONE

	if (dissociate)


	struct module_list list = MODULE_LIST_INIT;
			argv_array_push(&cpr.args, "--cached");
		argv_array_push(&cp.args, "describe");
			    DO_UNSET),
	sub = submodule_from_path(the_repository, &null_oid, path);
	displaypath = get_submodule_displaypath(path, info->prefix);

		strbuf_release(&sb);
	{"list", module_list, 0},
	struct module_list active_modules = MODULE_LIST_INIT;
	return str[0] == '.' && is_dir_sep(str[1]);

			"git dir"), sm_gitdir);
	char *remoteurl = xstrdup(remote_url);


		git_config_set_gently(sb.buf, "true");
		out->type = SM_UPDATE_CHECKOUT;

	const char *cmd;
		info.flags |= OPT_FORCE;
		struct ref_store *refs = get_submodule_ref_store(path);
		 * as the last part of a missing submodule reference would

				/*
			die(_("please make sure that the .gitmodules file is in the working tree"));

	char *out;
	/*
	remote = pushremote_get(argv[1]);
	free(idxP);
		N_("git submodule--helper list [--prefix=<path>] [<path>...]"),
	sub = submodule_from_path(the_repository, &null_oid, path);
		}
}

		N_("git submodule deinit [--quiet] [-f | --force] [--all | [--] [<path>...]]"),
"To allow Git to clone without an alternate in such a case, set\n"
			displaypath);
	struct object_id oid;
	if (!argc && !all)

					advise(_(alternate_error_advice));
	return 0;
		 * We need to end the new path with '/' to mark it as a dir,
		print_status(flags, 'U', path, &null_oid, displaypath);
static void next_submodule_warn_missing(struct submodule_update_clone *suc,
 * Return either an absolute URL or filesystem path (if the superproject
	return 0;
		prepare_submodule_repo_env(&cpr.env_array);
	const char *path = list_item->name;
			   N_("path"),
	while (url) {
		OPT_END()
	char *dest = NULL, *ret;
	return 0;
	 * The loop above tried cloning each submodule once, now try the
		argv_array_pushl(&cpr.args, "--super-prefix", NULL);
		prepare_submodule_repo_env(&cp.env_array);

		 * protect submodules containing a .git directory
	 */
		return 1;

		if (git_config_set_gently(sb.buf, upd))
static int check_name(int argc, const char **argv, const char *prefix)
	const char *refname = resolve_ref_unsafe("HEAD", 0, NULL, NULL);
		goto cleanup;
	if (info->recursive) {
static void deinit_submodule(const char *path, const char *prefix,
		return 1;
	struct foreach_cb *info = cb_data;


	struct status_cb info = STATUS_CB_INIT;
	sub = submodule_from_path(the_repository, &null_oid, argv[1]);


	}
	};
	} else if (!(flags & OPT_CACHED)) {
	argc = parse_options(argc, argv, prefix, module_sync_options,
		else
		argv_array_pushl(&child->args, "--prefix", suc->prefix, NULL);
	/* If we want to stop as fast as possible and return an error */
		NULL

		cpr.dir = path;
	if (!needs_cloning)
			     git_submodule_helper_usage, 0);
	if (suc->quiet)

	}
		OPT_BIT(0, "recursive", &info.flags, N_("recurse into nested submodules"), OPT_RECURSIVE),
	if (module_list_compute(argc, argv, prefix, &pathspec, &suc.list) < 0)
	struct module_list list = MODULE_LIST_INIT;
	char *upd = NULL, *url = NULL, *displaypath;
static void runcommand_in_submodule_cb(const struct cache_entry *list_item,
	}
	int alloc, nr;

}
	 * entry list.
	if (argc != 2)

	}
		cpr.git_cmd = 1;
	for (i = count_slashes(path); i; i--)
	const struct cache_entry **failed_clones;
	const struct cache_entry **entries;
				      void *idx_task_cb)

	cp.dir = path;
	if (argc != 2)


	free(url);
					      "--single-branch" :

			case SUBMODULE_ALTERNATE_ERROR_IGNORE:
	free(sub_config_path);
			printf(_("Submodule '%s' (%s) unregistered for path '%s'\n"),

		/*
			   active_modules.alloc);
	if (ps_matched && report_path_error(ps_matched, pathspec))
			 const struct object_id *oid, const char *displaypath)

		if (!(flags & OPT_QUIET))
	strbuf_addstr(&sb, "/config");
			return strbuf_detach(&sb, NULL);

};
	char *rfind = find_last_dir_sep(*remoteurl);
			print_status(flags, '-', path, ce_oid, displaypath);
	return !is_submodule_active(the_repository, argv[1]);
	cp_config.git_cmd = 1;
		    starts_with_dot_dot_slash(sub->url)) {

						const char *path,
			   N_("name of the new submodule")),

	struct argv_array diff_files_args = ARGV_ARRAY_INIT;

	};
	*remoteurl = xstrdup(".");
}
	strbuf_addf(&sb, "remote.%s.url", remote);
	};
	int i;
	struct child_process cp = CHILD_PROCESS_INIT;
	if (argc < 2 || !strcmp(argv[1], "-h"))

	return 0;
		OPT_BOOL(0, "all", &all, N_("Unregister all submodules")),
	/* Copy "update" setting when it is not set yet */
	if (reference->nr) {
}
		OPT_CMDMODE(0, "unset", &command,
	remote = get_default_remote();
		git_dir = buf.buf;
	if (rfind) {
			argv_array_push(&cpr.args, "--quiet");
	 * Copy url setting when it is not set yet.
	if (is_relative || !strcmp(".", *remoteurl))

	int is_relative = 0;
		git_config_set_in_file(cfg_file, "core.worktree", rel_path);
			   N_("path"),

				 "--recursive", NULL);
	 * The remote must be configured.
	if (!branch)
		OPT_BIT(0, "--recursive", &flags, N_("recurse into submodules"),
	if (argc || !url || !path || !*path)
		}
		return xstrdup("origin");
		goto cleanup;
			   N_("string"),
 */

	struct option module_config_options[] = {
	git_config(git_update_clone_config, &suc.max_jobs);

	if (is_directory(path)) {
struct update_clone_data {
"'--reference-if-able' instead of '--reference'."
	} else
	/*
		for_each_string_list_item(item, reference)
		strbuf_addch(err, '\n');
		NULL
		if (is_directory(sub_git_dir))
				      void *suc_cb,
 * repo. When relative, this URL is relative to the superproject origin
		ret = xstrdup("origin");
			   N_("force cloning progress")),
	}

		if (starts_with_dot_dot_slash(sub->url) ||

		remoteurl = xgetcwd();
	return 0;

			case SUBMODULE_ALTERNATE_ERROR_INFO:
	free(remote_key);



		strbuf_addf(&sb, "%s/index", sm_gitdir);
	git_config_get_string("submodule.alternateErrorStrategy", &error_strategy);
	if (!is_submodule_active(the_repository, path))
		struct strbuf sb = STRBUF_INIT;
	argv_array_pushl(&child->args, "--url", url, NULL);

		 * The environment variable "PATH" has a very special purpose
		argv_array_pushv(&cpr.args, info->argv);
	const char *const git_submodule_helper_usage[] = {
			      "submodule '%s'"), path);
struct sync_cb {
	just_cloned = git_config_int("just_cloned", argv[1]);
			free(remote);
	const char *const git_submodule_helper_usage[] = {
	 * - the listener can avoid doing any work if fetching failed.
	if (!is_submodule_active(the_repository, ce->name)) {
		return NULL;
	struct pathspec pathspec;

		ucd->sub->path);
			    N_("unset the config in the .gitmodules file"),
	struct string_list *reference;
		    starts_with_dot_slash(url)) {
			strbuf_strip_suffix(&sb, "\n");
	struct option module_sync_options[] = {

		if (sm_alternate) {
				continue;

			char *remote_url, *up_path;
		return 1;
#include "cache.h"
		OPT_STRING(0, "name", &name,
	char *p, *path = NULL, *sm_gitdir;
	free(list->entries);
		return 0;
#define INIT_CB_INIT { NULL, 0 }
struct status_cb {
	return 0;
		if (safe_create_leading_directories_const(sm_gitdir) < 0)
			*idx_task_cb = p;
	int max_jobs;
	if (read_cache() < 0)

		*p = suc->current;
	} else {
				    0, ps_matched, 1) ||
		const char *name = compute_rev_name(path, oid_to_hex(oid));

		argv_array_pushl(&cpr.args, "submodule--helper", "sync",
#include "connect.h"
	argv_array_push(&child->args, "submodule--helper");
		NULL
	/*
			displaypath);
	suc->quickstop = 1;
	sub = submodule_from_path(the_repository, &null_oid, ce->name);
 *

	if (!repo_config_get_string_const(the_repository, key, &update_string)) {

	sub = submodule_from_path(the_repository, &null_oid, path);
		}

	const char *const git_submodule_helper_usage[] = {
			 "print-default-remote", NULL);


		/*
	argv_array_pushl(&diff_files_args, "diff-files",

			die(_("clone of '%s' into submodule path '%s' failed"),
	if (index < suc->failed_clones_nr) {
		 */
		return 1;
	if (!error_strategy)
				 * If LHS matches 'HEAD' then we need to ensure
}
	argc = parse_options(argc, argv, prefix, embed_gitdir_options,
	strbuf_release(&sb);
		OPT_BOOL(0, "recursive", &info.recursive,
	struct strbuf remotesb = STRBUF_INIT;
					      "--no-single-branch");
	};
static int module_clone(int argc, const char **argv, const char *prefix)
	if (capture_command(&cp, &sb, 0))
		char *displaypath = xstrdup(relative_path(path, prefix, &sb));
		if (!sub->url)
			    displaypath);

			strbuf_addf(&sb, "./%s", remoteurl);
	if (argc == 2 && command != DO_UNSET)

	/* to be consumed by git-submodule.sh */
	argv_array_push(&cp.args, "clone");
#include "revision.h"
	git_config_get_string("submodule.alternateLocation", &sm_alternate);
	struct submodule_update_strategy update_strategy = { .type = SM_UPDATE_CHECKOUT };
	enum submodule_update_type update_type;
	return run_command(&cp);
			if (rs->pattern || rs->matching)
{
	static const char *describe_bare[] = { NULL };

		argv_array_push(&cpr.args, "--super-prefix");
{

				fprintf_ln(stderr, _("submodule '%s' cannot add alternate: %s"),
	diff_files_args.argc = setup_revisions(diff_files_args.argc,
{
	*list = active_modules;
	}
	int current;
	if (argc < 3 || argc > 4)
	if (argc != 3)
	 * paths have been specified.
	int i;
		is_relative = 0;

		ce  = suc->list.entries[idx];
		struct strbuf *out, const char *displaypath)
}
			     unsigned int flags)
	 * If the alternate object store is another repository, try the
			url += 3;

	int *max_jobs = cb;

		next_submodule_warn_missing(suc, out, displaypath);
#define OPT_RECURSIVE (1 << 2)

		print_status(flags, ' ', path, ce_oid,
		if (!match_pathspec(&the_index, pathspec, ce->name, ce_namelen(ce),
			   N_("rebase, merge, checkout or none")),

				 */
static int chop_last_dir(char **remoteurl, int is_relative)
}
		argv_array_pushf(&cp.env_array, "displaypath=%s", displaypath);
	int single_branch;
{
		die(_("No such ref: %s"), "HEAD");
		free(cfg_file);




		struct string_list *reference)

	int quiet = 0;
	if (suc->quickstop)
			   N_("disallow cloning into non-empty directory")),
	}
#include "config.h"
					   struct strbuf *out)
	free(out);
		if (parse_submodule_update_strategy(val, out) < 0)
static int handle_submodule_head_ref(const char *refname,
#include "dir.h"

};
	return 0;
	return 0;
 */
{
	};
	struct status_cb *info = cb_data;
static void sync_submodule_cb(const struct cache_entry *list_item, void *cb_data)
struct submodule_alternate_setup {
				   update_clone_task_finished, suc, "submodule",
		git_config_rename_section_in_file(NULL, sub_key, NULL);
			free(remoteurl);
	key = xstrfmt("submodule.%s.update", sub->name);
	}
		if (parse_submodule_update_strategy(update, &suc.update) < 0)
		path = xstrdup(path);
	int detached_head = 0;
			     displaypath);
		ucd->just_cloned,

		if (!is_submodule_active(the_repository, ce->name))
		OPT_END()
{
	unsigned int flags;
		argv_array_pushf(&cp.env_array, "sha1=%s",
	strbuf_reset(&sb);
		if (name)
	.references = STRING_LIST_INIT_DUP, \
{
				    commands[i].cmd);
 * http://a.com/b  ../../../../c    http:c           error out
		die(_("Use '--all' if you really want to deinitialize all submodules"));
			      "directory (use 'rm -rf' if you really want "

{
			displaypath);
		OPT__QUIET(&quiet, N_("Suppress output of synchronizing submodule url")),
				   void *cb)
	char *displaypath = NULL;

	head = resolve_refdup("HEAD", 0, &head_oid, NULL);
 * path that navigates from the submodule working tree to the superproject
	int i, result = 0;
	deinit_submodule(list_item->name, info->prefix, info->flags);
#include "pathspec.h"

				     void *cb_data)
	if (git_config_get_string(sb.buf, &remoteurl))
			colonsep |= chop_last_dir(&remoteurl, is_relative);
		sas.error_mode = SUBMODULE_ALTERNATE_ERROR_INFO;
		cp.no_stderr = 1;

	};
	run_processes_parallel_tr2(suc->max_jobs, update_clone_get_next_task,
				displaypath);
	 */
	return 0;


	struct submodule_alternate_setup *sas = sas_cb;
	info.argv = argv;
					   struct submodule_update_clone *suc,
			die(_("directory not empty: '%s'"), path);
	/* Check if the submodule has been initialized. */
		argv_array_pushl(&cp.args, "--separate-git-dir", gitdir, NULL);
	const char *prefix;
	free(ps_matched);
		sq_quote_buf(&sb, path);
	}
	};
		argv_array_pushf(&cp.env_array, "sm_path=%s", path);


		strbuf_addf(out, _("Skipping submodule '%s'"), displaypath);
		return config_set_in_gitmodules_file_gently(argv[1], value);
		/* Possibly a url relative to parent */
{
		NULL
	}
	if (quiet)
	url = argv[1];
		SUBMODULE_ALTERNATE_ERROR_DIE,
	}
	char *key;

	prepare_submodule_repo_env(&cp.env_array);
};
	if ((CE_STAGEMASK & ce_flags) >> CE_STAGESHIFT) {

		OPT_BOOL(0, "progress", &suc.progress,
	displaypath = get_submodule_displaypath(path, prefix);
};
	const char *git_dir;
	struct option embed_gitdir_options[] = {
		NULL
	if (flags & OPT_QUIET)
{

	struct strbuf sb = STRBUF_INIT;

	struct option module_clone_options[] = {
	return 0;
		OPT_BOOL(0, "progress", &progress,
static int update_clone_get_next_task(struct child_process *child,


	for_each_listed_submodule(&list, sync_submodule_cb, &info);
 * origin URL is an absolute URL or filesystem path, respectively) or a
			   N_("disallow cloning into non-empty directory")),

			free(up_path);
		OPT_BOOL(0, "require-init", &suc.require_init,


	/* remove the submodule work tree (unless the user already did it) */
		argv_array_pushl(&cpr.args, "submodule--helper", "foreach", "--recursive",
	 * - the listener does not have to interleave their (checkout)
		}


	}
		strbuf_addstr(&sb_rm, path);
	if (suc->require_init)

	else if (!strcmp(sm_alternate, "no"))
	}

}
	    || (suc->update.type == SM_UPDATE_UNSPECIFIED

	if (all && argc) {
	int diff_files_result;
			/*
}
		 */
/* the result should be freed by the caller. */


		suc->failed_clones[suc->failed_clones_nr++] = ce;
	struct submodule_update_clone *suc = suc_cb;

			 * Skip entries with the same name in different stages
	for (; suc->current < suc->list.nr; suc->current++) {
		if (refs_head_ref(refs, handle_submodule_head_ref, &oid))
		OPT_BOOL(0, "require-init", &require_init,
	};
	if (quiet)
	strbuf_reset(&sb);
static int resolve_relative_path(int argc, const char **argv, const char *prefix)
			      "specified number of revisions")),
		rel_path = relative_path(abs_path, subrepo.gitdir, &sb);
	const char *const git_submodule_helper_usage[] = {
		cpr.git_cmd = 1;
	 * .gitmodules, so look it up directly.
}


	suc->update_clone[suc->update_clone_nr].sub = sub;
			    CHECK_WRITEABLE),
	free(displaypath);

 * NEEDSWORK: Given how chop_last_dir() works, this function is broken

		/*
	free(error_strategy);
			 N_("clone only one branch, HEAD or --branch")),
			format = _("Could not remove submodule work tree '%s'\n");
}
{
		if (parse_submodule_update_strategy(update, out) < 0)
	return relurl;
				 "--recursive", NULL);
		displaypath = relative_path(suc->recursive_prefix,

		struct ref *local_refs = get_local_heads();
	struct strbuf sb = STRBUF_INIT;

}

				printf("%s\n", buf.buf);
	git_config(git_diff_basic_config, NULL);
	argv_array_push(&cp.args, url);
			   N_("where the new submodule will be cloned to")),
{
	 * To look up the url in .git/config, we must not fall back to
	if (info->argc == 1) {
static void status_submodule_cb(const struct cache_entry *list_item,
	unsigned warn_if_uninitialized : 1;
	return branch;
	strbuf_reset(&sb);
		} else {
	if (pathspec->nr)
		NULL
/**
	return 0;
}
	free(path);
			die(_("Submodule work tree '%s' contains a .git "
	if (!repo_config_get_string(&subrepo, "core.worktree", &cw)) {
{
		cfg_file = repo_git_path(&subrepo, "config");
					   sm_alternate);
		const struct cache_entry *ce = list.entries[i];
	strbuf_addf(&sb, "submodule.%s.url", sub->name);
		oid_to_hex(&ucd->oid),
		strbuf_addch(out, '\n');
static char *get_up_path(const char *path)
		return 0;
	for (i = 0; i < active_nr; i++) {
	char *sm_alternate = NULL, *error_strategy = NULL;

		while (*++argv) {
	{"resolve-relative-url-test", resolve_relative_url_test, 0},
		int *p;
	argv_array_pushl(&child->args, "--name", sub->name, NULL);
		if (sub->update_strategy.type == SM_UPDATE_COMMAND) {
		sas.error_mode = SUBMODULE_ALTERNATE_ERROR_DIE;
				     const struct object_id *oid, int flags,
				   update_clone_start_failure,
	if (suc->progress)
	if (module_list_compute(argc, argv, prefix, &pathspec, &list) < 0)
	if (mkdir(path, 0777))
		for (i = 0; i < refspec.nr; i++) {
		info.flags |= OPT_QUIET;

		OPT_STRING(0, "depth", &depth,

	struct option module_deinit_options[] = {
			url += 2;
}
static char *get_submodule_displaypath(const char *path, const char *prefix)
			struct child_process cp_rm = CHILD_PROCESS_INIT;
 *                                                   ignore trailing slash in url
			   active_modules.nr + 1,
		const char *rel_path;
			    !(commands[i].option & SUPPORT_SUPER_PREFIX))
	struct module_list list = MODULE_LIST_INIT;
	status_submodule(list_item->name, &list_item->oid, list_item->ce_flags,
	unsigned quickstop : 1;
		/*
#include "diff.h"
	const char *prefix;
 * remote_url      url              outcome          expectation
		SUBMODULE_ALTERNATE_ERROR_INFO,
	const struct submodule *sub;
static int module_sync(int argc, const char **argv, const char *prefix)
			     unsigned int flags)
						int just_cloned,
	int needs_cloning = 0;
	displaypath = get_submodule_displaypath(path, prefix);
#define OPT_CACHED (1 << 1)
	if (argc > 1) {
			   suc->failed_clones_nr + 1,
		next_submodule_warn_missing(suc, out, displaypath);
	else if (!strcmp(error_strategy, "info"))
#define MODULE_LIST_INIT { NULL, 0, 0 }
		argv_array_push(&child->args, "--quiet");
		char *toplevel = xgetcwd();
			      "submodule boundaries")),
	} else if (!repo_config_get_string_const(r, key, &val)) {
		goto cleanup;
	free(p);
		 * case-insensitive in windows, it interferes with the
static int update_clone_start_failure(struct strbuf *err,
	strbuf_addf(&sb, "%s%s", up_path, out);

		usage(_("git submodule--helper name <path>"));
		const char *prefix)
	 * That means:
	struct option module_status_options[] = {
			die(_("Invalid update mode '%s' configured for submodule path '%s'"),
		cpr.dir = path;

	    sub->update_strategy.type != SM_UPDATE_UNSPECIFIED) {
cleanup:
	argv++;
		strbuf_addstr(out,
{
		argv_array_push(&cp.args, "--quiet");
	return NULL;
	for (i = 0; i < suc->update_clone_nr; i++)


	free(key);
		const char *refname = resolve_ref_unsafe("HEAD", 0, NULL, NULL);
		update_type = parse_submodule_update_type(update_string);


	info.prefix = prefix;
			      "is not on any branch"), sub->name);
			continue;
				if (advice_submodule_alternate_error_strategy_die)
		OPT__QUIET(&info.quiet, N_("Suppress output of entering each submodule command")),
			die(_("Failed to register update mode for submodule path '%s'"), displaypath);
			   N_("path"),
	unsigned option;
		if (flags & OPT_CACHED)
		       prefix, argv);
{
	const char ***d;

	int i;
			   N_("path"),
#include "dir.h"


	cp.git_cmd = 1;
		argv_array_pushf(&cpr.args, "%s/", displaypath);
		OPT_END()
			   unsigned int flags)

		strbuf_addf(&sb, "%s/%s", get_git_work_tree(), path);
	};
		update_type = sub->update_strategy.type;
			die(_("run_command returned non-zero status while "
		if (safe_create_leading_directories_const(path) < 0)
				      void **idx_task_cb)
{
static int resolve_remote_submodule_branch(int argc, const char **argv,
			   N_("string"),

		OPT_STRING(0, "prefix", &prefix,
			   N_("repo"),
			strbuf_addstr(err, "BUG: submodule considered for "
	if (!is_submodule_active(the_repository, path) ||
	free(res);


		update = argv[3];
	struct pathspec pathspec;

static int absorb_git_dirs(int argc, const char **argv, const char *prefix)
	 */

		strbuf_reset(&sb);
	if (!is_submodule_populated_gently(path, NULL))
		die("submodule--helper push-check requires at least 2 arguments");
				 sb.buf, info->argv[0]);
	 * separate shell is used for the purpose of running the
	if (!strcmp(sm_alternate, "superproject"))
				update, path);
		argv_array_push(&child->args, "--dissociate");
		N_("git submodule status [--quiet] [--cached] [--recursive] [<path>...]"),
		super_config_url = xstrdup("");
	char *head;
			/* LHS must match a single ref */
	struct module_list list = MODULE_LIST_INIT;
struct deinit_cb {
	} else {
		if (starts_with_dot_dot_slash(url) ||
static void sync_submodule(const char *path, const char *prefix,
	argv_array_push(&cp.args, path);


		prepare_submodule_repo_env(&cpr.env_array);
	remote_key = xstrfmt("remote.%s.url", sb.buf);


	unsigned require_init;
			fprintf(stderr,
	return strbuf_detach(&sb, NULL);
	const char *const git_submodule_helper_usage[] = {
	argc = parse_options(argc, argv, prefix, module_foreach_options,
	return 0;
	/*
	}
	const char *submodule_name;
			      path);
 * run the clone. Returns 1 if 'ce' needs to be cloned, 0 otherwise.

	for (i = 0; i < list->nr; i++) {
		struct strbuf sb = STRBUF_INIT;
static void update_submodule(struct update_clone_data *ucd)
	const struct submodule *sub;
	if (suc->recursive_prefix)

	prepare_submodule_repo_env(&cp.env_array);

		while (strbuf_getline(&buf, stdin) != EOF) {

	/* Check the refspec */


			strbuf_addf(&sb, "remote.%s.url", remote);
		strbuf_addch(out, '\n');
			   N_("path into the working tree")),
#define FOREACH_CB_INIT { 0 }
	 *
			    ce->name);

		return out;
			suc->current++;


	printf("%s", ret);
	{"update-clone", update_clone, 0},
	if (!ret)
		if (starts_with_dot_dot_slash(url)) {
			super_config_url = relative_url(remote_url, sub->url, NULL);
		git_config_set_in_file(p, "submodule.alternateErrorStrategy",
				void *cb_data)
	for (d = describe_argv; *d; d++) {
	}

		else

struct init_cb {
	strbuf_reset(&sb);
	 */
	char *remote = get_default_remote();
		cp.dir = sub_path;


	 */
	argv_array_clear(&diff_files_args);
	if (ce_stage(ce)) {
			      "to remove it including all of its history)"),
		struct strbuf err = STRBUF_INIT;

	 *   work with our fetching.  The writes involved in a
		if (!is_writing_gitmodules_ok())
	if (git_config_get_string(sb.buf, &upd) &&
}
		argv_array_pushv(&cp.args, *d);
/*
	/*
		return refname;
	determine_submodule_update_strategy(the_repository,
		ALLOC_GROW(suc->failed_clones,


				 * that it matches the same named branch
			case SUBMODULE_ALTERNATE_ERROR_DIE:
		fn(list->entries[i], cb_data);
{
			   suc->failed_clones_alloc);
			argv_array_pushl(&cp.args, "--reference",
	if (gitdir && *gitdir)
			die(_("could not create directory '%s'"), path);
static int update_clone(int argc, const char **argv, const char *prefix)
	} else {
	if (module_list_compute(argc, argv, prefix, &pathspec, &list) < 0)
	unsigned int flags;
				  void *cb_data);

			upd = xstrdup(submodule_strategy_to_string(&sub->update_strategy));
		    prefix, super_prefix);
		goto cleanup;
};
	return str[0] == '.' && str[1] == '.' && is_dir_sep(str[2]);
	free(res);

	key = xstrfmt("submodule.%s.update", sub->name);
	if (recursive)
	return strbuf_detach(&sb, NULL);
	}
		displaypath = ce->name;
	strbuf_addf(&buf, "%s/.git", path);
		OPT_STRING(0, "update", &update,

	 * and dir/sub_dir/
		strbuf_addf(err, _("Failed to clone '%s'. Retry scheduled"),
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
				remote_url = xgetcwd();


	if (progress)
}
	int i;
			   N_("depth for shallow clones")),
		return is_writing_gitmodules_ok() ? 0 : -1;

	if (flags & OPT_RECURSIVE) {
	struct strbuf sb = STRBUF_INIT;

	const char *ret;
		struct string_list_item *item;


	{"sync", module_sync, SUPPORT_SUPER_PREFIX},
	struct foreach_cb info = FOREACH_CB_INIT;
	const char *const git_submodule_helper_usage[] = {


	strbuf_release(&remotesb);
static void init_submodule(const char *path, const char *prefix,
}
	if (depth && *depth)
#include "submodule-config.h"
	 * stragglers again, which we can imagine as an extension of the
		N_("git submodule--helper config --unset <name>"),
}
		struct strbuf sb_rm = STRBUF_INIT;

{
	else {
					   "any more?\n");
		strbuf_addf(&sb, "submodule.%s.active", sub->name);
	 * superproject's resolved head ref.
						describe_contains,
	struct rev_info rev;
		ce = suc->failed_clones[index];
		suc.warn_if_uninitialized = 1;

}
		strbuf_setlen(&sb, sb.len - 1);
	if (suc->depth)

	char *remote = get_default_remote();


{


static int starts_with_dot_slash(const char *str)
{
		}
		if (clone_submodule(path, sm_gitdir, url, depth, &reference, dissociate,
#include "refspec.h"
}
		OPT_STRING_LIST(0, "reference", &suc.references, N_("repo"),
	const char *up_path, *url;
	char *remote;
#include "string-list.h"


	displaypath = get_submodule_displaypath(path, prefix);
);
		out->type = SM_UPDATE_CHECKOUT;
					  "--no-single-branch");
			   N_("Create a shallow clone truncated to the "
		printf(_("Entering '%s'\n"), displaypath);
	free(sub_git_dir);


