{
	oid_array_clear(&ref_tips_after_fetch);
		struct object_id *one, struct object_id *two,
		strbuf_addf(&spf->submodules_with_errors, "\t%s\n",
{

		"submodule",
	if (!submodule || !submodule->name) {
	return (struct oid_array *) item->util;
	if (task->commits)

	}
{
				path);
		return 0;
		strbuf_addstr(&sb, get_super_prefix_or_empty());
	return 1;
		oid_array_for_each_unique(commits, append_oid_to_argv, &cp.args);
		fprintf(stderr, _("Errors during submodule fetch:\n%s"),
			break;
		struct object_id head_oid;

{
	argv_array_push(&cp.args, empty_tree_oid_hex());


 */
	strbuf_addstr(&entry, ".path");

					    ce->name);
 * Perform a check in the submodule to see if the remote and refspec work.
				 const struct refspec *rs)
	strbuf_release(&buf);
		if (capture_command(&cp, &out, GIT_MAX_HEXSZ + 1) || out.len)
		for_each_string_list_item(item, sl) {
	cp.git_cmd = 1;
	int i, prefixlen;

				argv_array_pushf(&cp.args, "--push-option=%s",
	else if (!strcmp(value, "merge"))
		if (repo_config_get_string_const(the_repository, key, &ignore))
			strbuf_addf(&sb, "%s/.git", path);
		const char *path = NULL;
	struct child_process cp = CHILD_PROCESS_INIT;
		strbuf_addch(&sb, '/');
	argv_array_pushl(&cp.args, "diff", "--submodule=diff", NULL);
	free(real_old_git_dir);
			 "always" : "never");
	ret = !repo_config_get_string(repo, key, &value);

	}
	strbuf_reset(buf);
		free(out);
	/*
	return 0;
 * having its git directory within the working tree to the git dir nested
	FREE_AND_NULL(p->repo);
	const char *argv[] = {
	for (var = local_repo_env; *var; var++) {

	if (!file_exists(GITMODULES_FILE)) /* Do nothing without .gitmodules */
		return 0;
	int fast_forward = 0, fast_backward = 0;
static const char *default_name_or_path(const char *path_or_name)
		/* regular untracked files */
	free(old_git_dir);
	return 0;
	unsigned dirty_submodule = 0;
					    _("Could not access submodule '%s'\n"),
output_header:
}
	if (run_command(&cp)) {
		unsigned dirty_submodule,
			/* unpopulated as expected */

		* superproject did not rewrite the git file links yet,
	it = string_list_lookup(&spf->changed_submodule_names, task->sub->name);
	struct string_list changed_submodule_names;
 *

static int get_fetch_recurse_config(const struct submodule *submodule,
				   get_next_submodule,
}
	struct commit_list *merge_bases = NULL;
}
		strbuf_release(&sb);
	if (sub) {
			fast_backward = 1;
	} else {
		struct commit_list *merge_bases)
	sub = submodule_from_path(the_repository, &null_oid, path);
static void fetch_task_release(struct fetch_task *p)
	const struct submodule *sub;
	if (!submodule_uses_gitfile(path))
			 * the submodule is not initialized
 * when doing so.
	strbuf_addstr(buf, submodule);
#include "argv-array.h"

		oid_array_for_each_unique(task->commits,
		return ret;
		clear_pathspec(&ps);
			continue;
			strbuf_release(&gitdir);
{
		return 0;
		die(_("Cannot change unmerged .gitmodules, resolve merge conflicts first"));

};
	cp.dir = path;
	else
		/* Could be an unchanged submodule, not contained in the list */
			     const struct remote *remote,
	if (finish_command(&cp)) {
	/*
		finish_command(&cp);
	 * Example: having a submodule named `hippo` and another one named
			cp.dir = path;
	cp.dir = path;
	cp.dir = path;
}
	int oid_fetch_tasks_nr, oid_fetch_tasks_alloc;
{
	}

		free(key);
			for (i = 0; i < rs->raw_nr; i++)
		if (submodule_has_commits(r, path, commits)) {
	struct argv_array args;
{

	cp.out = -1;
	cp.dir = path;
		if (prefixlen <= ce_len)
{
			fast_forward = 1;
			die(_("could not start 'git status' in submodule '%s'"),

 * Collect the paths of submodules in 'changed' which have changed based on
			       const struct pathspec *ps)
static int append_oid_to_argv(const struct object_id *oid, void *data)

		strbuf_git_path(buf, "%s/%s", "modules", sub->name);
	const struct object_id *commit_oid = me->commit_oid;
					     (int)(p - git_dir), git_dir);

		if (strncmp(ce->name, prefix, ce_len))

	}
	if (is_gitmodules_unmerged(the_repository->index))
		(get_oid(GITMODULES_INDEX, &oid) < 0 && get_oid(GITMODULES_HEAD, &oid) < 0);
			argv_array_pushl(&cp.args, "update-ref", "HEAD",
		die(_("relocate_gitdir for submodule '%s' with "
	if (dirty_submodule & DIRTY_SUBMODULE_MODIFIED)
		cp->git_cmd = 1;

	if (!is_submodule_populated_gently(path_or_name, &error_code))
	return config_update_recurse_submodules == RECURSE_SUBMODULES_ON;
	int command_line_option;
			       struct object_id *excl_oid,
	fprintf(stderr, _("Migrating git directory of '%s%s' from\n'%s' to\n'%s'\n"),

		goto done;
	else
	prepare_submodule_repo_env(&cp.env_array);
}
	cp.no_stdin = 1;
		diffopt->flags.ignore_dirty_submodules = 1;
			free(gitdir);
			    !is_empty_dir(ce->name)) {
				return error(_("submodule git dir '%s' is "
			continue;

static int fetch_finish(int retvalue, struct strbuf *err,

		case RECURSE_SUBMODULES_ON_DEMAND:
	 * of the former.
		goto out;
	cp.dir = path;
	else
		submodule = submodule_from_name(r, &null_oid, name->string);
	char *old_git_dir = NULL, *real_old_git_dir = NULL, *real_new_git_dir = NULL;
		if (!path)
	const char *sub_git_dir;
		/*
		} else {
	else if (!strcmp(arg, "dirty"))
		spf->result = 1;
		case RECURSE_SUBMODULES_ON:
{

 * Check if the .gitmodules file is unmerged. Parsing of the .gitmodules file
	}
		return (struct oid_array *) item->util;

		if (run_command(&cp))
{
	int ret = 0;

{
			strbuf_release(&sb);
	git_dir = read_gitfile(buf.buf);
		return 0;
					  void *data)
		return 0;
	 * all the information the user needs.
			ret = 0;
	if (add_submodule_odb(path))
{
	p->free_sub = 0;
		cp.no_stdin = 1;
	}
		    cb->path, oid_to_hex(oid), type_name(type));
	int pos = index_name_pos(istate, GITMODULES_FILE, strlen(GITMODULES_FILE));
		if (!head)
		argv_array_pushl(&cp.args, "--super-prefix", sb.buf,
	};

}
			/*
				dirty_submodule |= DIRTY_SUBMODULE_MODIFIED;
	free(real_new_git_dir);
	}
	argv_array_pushl(&cp.args, "--literal-pathspecs", "-C", "..",
		prepare_submodule_repo_env(&cp.env_array);
	for (; *p; p++) {
				return 1;
		free((void*)p->sub);
 *
	const char *path;
		error_code_ptr = NULL;
	struct strbuf buf = STRBUF_INIT;

	prepare_submodule_repo_env_no_git_dir(out);
		}
	return dirty_submodule;
#include "string-list.h"
		return 0;
		die(_("in unpopulated submodule '%s'"), ce->name);

	cp.out = -1;
	struct argv_array args = ARGV_ARRAY_INIT;
	oid_array_for_each_unique(commits, append_oid_to_argv, &argv);
		 * We're only interested in the name after the tab.
		message = "(new submodule)";
void die_in_unpopulated_submodule(const struct index_state *istate,
	strbuf_addstr(&sect, "submodule.");
			/* T = line type, XY = status, SSSS = submodule state */
 * have a corresponding 'struct oid_array' (in the 'util' field) which lists
 * checks whether there is a submodule in the working directory at that
		/*

	fetch_task_release(task);
			die(_("could not recurse into submodule '%s'"), path);

/*

void show_submodule_inline_diff(struct diff_options *o, const char *path,
 * working tree or, if it doesn't, that a brand new .gitmodules file is going
		argv_array_push(&args, oid_to_hex(excl_oid));
	struct commit *left = NULL, *right = NULL;
#include "refs.h"
		free(real_common_git_dir);
		BUG("could not get submodule information for '%s'", path);

			*task_cb = task;
	return 0;
			subpath, NULL);
		task->commits = commits;
}
		return SM_UPDATE_MERGE;



	sub_git_dir = resolve_gitdir_gently(gitdir.buf, &err_code);
		if (flags & ~ABSORB_GITDIR_RECURSE_SUBMODULES)
		struct argv_array args = ARGV_ARRAY_INIT;

	if (spf->oid_fetch_tasks_nr) {
 * work on.
#include "revision.h"

		if (commit->object.flags & SYMMETRIC_LEFT)
{
			return NULL;
			has_commit.result = 0;
	 * it in the object store of the correct submodule and have it
			message = "(commits not present)";
	argv_array_pushf(out, "%s=%s", GIT_DIR_ENVIRONMENT,

		argv_array_pushl(&cp.args, "rev-list", "-n", "1", NULL);
	if (!sub)
		ret = -1;
			struct strbuf submodule_prefix = STRBUF_INIT;
	ret->name = name;
					ABSORB_GITDIR_RECURSE_SUBMODULES);
	if (!S_ISGITLINK(ce->ce_mode))

	}
			ignore_cp_exit_code = 1;
		goto out;
#include "worktree.h"
void die_path_inside_submodule(const struct index_state *istate,
	cp.git_cmd = 1;
 * put them into the left and right pointers.
	strbuf_addf(&buf, "%s/.git", path);
			fetch_task_release(task);
		struct cache_entry *ce = istate->cache[i];

		die(_("staging updated .gitmodules failed"));
	}
	int result;
		spf->oid_fetch_tasks[spf->oid_fetch_tasks_nr] = task;
		return NULL;
}
	if (is_null_oid(one))
		if (!starts_with(real_sub_git_dir, real_common_git_dir))
		return 0;
	return 0;
	len = strbuf_read(&sb, cp.out, PATH_MAX);
		diffopt->flags.ignore_untracked_in_submodules = 1;
	return ret;

	struct child_process cp = CHILD_PROCESS_INIT;
 * Writing to the .gitmodules file requires that the file exists in the
		 * We might have a superproject, but it is harder
		return strbuf_detach(&sb, NULL);

		die(_("Cannot change unmerged .gitmodules, resolve merge conflicts first"));
}
		struct fetch_task *task;

};
		const struct submodule *sub;
	run_processes_parallel_tr2(max_parallel_jobs,
		else if (is_gitmodules_unmerged(the_repository->index))
#include "parse-options.h"
	reset_revision_walk();
			unlink_or_warn(sb.buf);
		strbuf_addf(&sb, "%s:\n", fast_backward ? " (rewind)" : "");
			       int flags, void *data)
	if (start_command(&cp))


{

			/*
#include "run-command.h"
	struct commit *commit;
		if (remote->origin != REMOTE_UNCONFIGURED) {
				       struct argv_array *argv)
		int v = git_config_bool(var, value) ?
	argv_array_pushl(&cp.args, "status", "--porcelain",
		int ce_len = ce_namelen(ce);

	return finish_command(&cp);
		cp.git_cmd = 1;
			die(_("could not lookup name for submodule '%s'"), path);
	strbuf_reset(&sb);
	strbuf_release(&sb);
	struct string_list_item *name;

	struct commit_list *merge_bases = NULL;
	spf.default_option = default_option;
	cp.no_stdin = 1;
	/* submodule.<name>.active is set */

	}
out:


		argv_array_pushf(&cp.args, "--src-prefix=%s%s/",
		  NULL, 0, 0, STRBUF_INIT}
		argv_array_push(&cp.args, "-uno");
		 */
	struct child_process cp = CHILD_PROCESS_INIT;
		die(_("could not lookup name for submodule '%s'"), path);
	if (old_head && !is_submodule_populated_gently(path, error_code_ptr))

	if (git_config_set_in_file_gently(config_path, "core.worktree", NULL))
int is_staging_gitmodules_ok(struct index_state *istate)
	default:
#include "config.h"
		diff_rev.diffopt.format_callback = collect_changed_submodules_cb;
{
		/* '../' is not a git repository */
		/* Maybe the user already did that, don't error out here */
#include "cache.h"


	char *config_path = xstrfmt("%s/modules/%s/config",
	return 0;


out:
	ret->path = name;
			submodule_push_check(needs_pushing.items[i].string,
}
			if (buf.buf[5] == 'S' && buf.buf[8] == 'U')
#include "commit-reach.h"
	/* Now test that all nested submodules use a gitfile too */
	if (run_command(&cp))
{
	struct child_process cp = CHILD_PROCESS_INIT;
				   "submodule", "parallel/fetch");
		struct strbuf submodule_prefix = STRBUF_INIT;
			    task->sub->name);
	else if (!strcmp(value, "checkout"))
	 *
				 struct oid_array *commits)

 * .gitmodules file. Return 0 only if a .gitmodules file was found, a section
	if (!(flags & SUBMODULE_MOVE_HEAD_FORCE))
	submodule = submodule_from_path(the_repository, &null_oid, path);

	cp.dir = path;
		cp.dir = path;
		strbuf_release(&gitdir);
	if (!submodule_from_path(r, NULL, NULL))
		 */
		 */
		strbuf_addch(&sb, '\n');

	type = parse_submodule_update_type(value);
	 * Perform a cheap, but incorrect check for the existence of 'commits'.
	if (retvalue) {
	/* Is this the second time we process this submodule? */
static struct repository *get_submodule_repo_for(struct repository *r,
	 */
	 */
	struct repository *sub;
		goto out;
					   const char *name)

		strbuf_addstr(&sb, path);
{
		free(head);
			submodule_reset_index(path);
		* This can happen if the superproject is a submodule
	key = xstrfmt("submodule.%s.active", module->name);
		goto done;
}
 */
			for_each_string_list_item(item, push_options)
	FILE *fp;
		 */
int bad_to_remove_submodule(const char *path, unsigned flags)
	/* NEEDSWORK: should we have oid_array_init()? */
					fn, cb_data);
		submodule = submodule_from_name(r, &null_oid, name->string);
		strbuf_release(&submodule_prefix);
	argv_array_pushl(&cp.args, "read-tree", "-u", "--reset", NULL);
		return;
void show_submodule_summary(struct diff_options *o, const char *path,
		struct child_process cp = CHILD_PROCESS_INIT;
	argv_array_push(&spf.args, "--recurse-submodules-default");

	/*
	code = finish_command(&cp);
	struct strbuf gitdir = STRBUF_INIT;


	initialized_fetch_ref_tips = 0;

		if ((*merge_bases)->item == *left)
	free_submodules_oids(&submodules);
			  const struct refspec *rs,
			prepare_submodule_repo_env(&cp.env_array);
	strbuf_release(&sb);
		error_code_ptr = &error_code;
	cp.no_stderr = 1;
		argv_array_push(&cp.args, rs->raw[i]);
 * Migrate the git directory of the submodule given by path from

}
}

	add_pending_object(rev, &left->object, path);
	argv_array_pushl(&cp.args, "read-tree", "--recurse-submodules", NULL);
	free(gitdir);
		return ret;
			struct strbuf sb = STRBUF_INIT;
{
					"'%s' collides with a submodule named "

		/*
{
/*
			parse_update_recurse_submodules_arg(opt->long_name,
#include "object-store.h"
		argv_array_pushv(&cp->args, spf->args.argv);
		if (fetch_recurse != RECURSE_SUBMODULES_NONE)
	argv_array_push(&argv, "--not");
	char *p;
	*left = lookup_commit_reference(sub, one);
	const struct object_id *commit_oid;
	if (left)

		 */

	if (!strcmp(value, "none"))
		data.commit_oid = &commit->object.oid;
		strbuf_release(&sect);

		char *super_sub, *super_wt;
	if (!strcmp(var, "submodule.recurse")) {

	}
	oid_array_for_each_unique(&ref_tips_before_fetch,
	if (spf.submodules_with_errors.len > 0)
		struct repository *sub,
	free(value);
{



	}
	} else {
		commits = submodule_commits(changed, name);
		argv_array_push(&cp.args, "-uall");
/*
			const struct string_list_item *item;

		ret = 1;
}
	cp.git_cmd = 1;
			     const struct string_list *push_options,
	cp.no_stdin = 1;
				       struct string_list *changed,
		argv_array_push(&cp.args, "-uno");
		struct object_id *one, struct object_id *two,
}
const char *submodule_strategy_to_string(const struct submodule_update_strategy *s)
		 * indicate failure if the subsequent fetch fails.
static int push_submodule(const char *path,
		return "merge";
		int needs_pushing = 0;
			return error(_("submodule '%s' has dirty index"), path);
				    buf.buf);
{
	if (flags & SUBMODULE_REMOVAL_IGNORE_UNTRACKED)
	cp.git_cmd = 1;
	/* No need to check if there are no submodules configured */
	if (!is_submodule_active(the_repository, path))

		struct oid_array *commits = name->util;
}
		}

	if (!sub_git_dir) {
			prepare_submodule_repo_env_in_gitdir(&cp->env_array);
/*
struct collect_changed_submodules_cb_data {
 * pending (if in oid_fetch_tasks in struct submodule_parallel_fetch)
				continue;
			if (!task->sub ||
static void submodule_reset_index(const char *path)
	else
}
			 * the child any more, neither output nor its exit code.
 * what the submodule pointers were updated to during the change.
static int config_update_recurse_submodules = RECURSE_SUBMODULES_OFF;
		die(_("Could not run 'git status --porcelain=2' in submodule %s"), path);
			continue;
			child_process_init(cp);


	cp.argv = argv;
}

		* Maybe populated, but no git directory was found?
	if (has_commit.result) {

	real_new_git_dir = real_pathdup(new_git_dir, 1);

 * the submodule path we can get away with just one function which only

		diff_rev.diffopt.format_callback_data = &data;
		return 0;
			 const char *new_head,
	}
int remove_path_from_gitmodules(const char *path)
		if (submodule)
		diff_rev.diffopt.output_format |= DIFF_FORMAT_CALLBACK;
	struct repository *repo;
					   "submodule--helper",
			if (S_ISGITLINK(ce->ce_mode) &&
		return SM_UPDATE_UNSPECIFIED;

	argv_array_clear(&argv);
				 o->a_prefix, path);
	strbuf_release(&objects_directory);
		return;
			argv_array_push(&cp.args, "--dry-run");
		return 0;
					 each_ref_fn fn, void *cb_data)
static void relocate_single_git_dir_into_superproject(const char *path)
		return "none";
		return -1;
	struct strbuf buf = STRBUF_INIT;
	git_dir = read_gitfile(buf.buf);
		struct object_id *one, struct object_id *two,
		/* NEEDSWORK: have get_default_remote from submodule--helper */
		/* The submodule is not checked out, so it is not modified */
	}
		config_update_recurse_submodules =

			*name->string = '\0';
int validate_submodule_git_dir(char *git_dir, const char *submodule_name)
{
	for (i = 0; i < options->argc; i++)
		ret = -1;
			die(_("Could not run 'git rev-list <commits> --not --remotes -n 1' command in submodule %s"),

		 * maintainer integrating work from other people. In
		if (task->repo) {

	int ret = 0;
 * Fetch in progress (if callback data) or
			needs_pushing = 1;

static int submodule_has_dirty_index(const struct submodule *sub)
}

		if (!push_submodule(path, remote, rs,
				submodule = submodule_from_name(me->repo,
	if (run_command(&cp))
	if (!(left || is_null_oid(one)) ||
	/*
			/* make sure the index is clean as well */
	new_git_dir = git_pathdup("modules/%s", sub->name);
	if (prepare_submodule_summary(&rev, path, left, right, merge_bases)) {


#include "commit.h"

	return 0;


		cp.git_cmd = 1;
			const struct cache_entry *ce = istate->cache[pos];
{
	struct strbuf sect = STRBUF_INIT;
	int pos = index_name_pos(istate, GITMODULES_FILE, strlen(GITMODULES_FILE));
			diff_emit_submodule_add(o, sb.buf);
			die(_("could not run 'git status' in submodule '%s'"),

	char *key = NULL;
	if (commits->nr) {
static void show_submodule_header(struct diff_options *o,
	if ((pos >= 0) && (pos < istate->cache_nr)) {

/*
	 * Attempt to lookup the commit references, and determine if this is
			return 1;
	}


}
		}
	struct child_process cp = CHILD_PROCESS_INIT;



					path);
			argv_array_init(&cp->args);

 * Try to update the "path" entry in the "submodule.<name>" section of the
		else

int option_parse_recurse_submodules_worktree_updater(const struct option *opt,
}
{
	struct strbuf sb = STRBUF_INIT;
		 * failed, even though there may be a subsequent fetch
	const char *name = default_name_or_path(path);
	if (unset) {
	if (finish_command(&cp) && !ignore_cp_exit_code)
		struct pathspec ps;
	return ret;
/*
	rev->left_right = 1;
void stage_updated_gitmodules(struct index_state *istate)
	 * which is expensive.
		char *head;
		if (buf.buf[0] == 'u' ||
	 * Verify that the remote and refspec can be propagated to all
	if (left)

			       struct object_id *incl_oid)
	     (!is_null_oid(two) && !*right))
		goto output_header;
	return 0;
	free_submodules_oids(&subs);
	if (!(flags & SUBMODULE_MOVE_HEAD_DRY_RUN)) {
			"ls-files", "-z", "--stage", "--full-name", "--",
		argv_array_pushf(&cp.args, "--src-prefix=%s%s/",
	struct repository *sub;
	struct repository *repo;
	else if (!strcmp(value, "rebase"))
		unsigned dirty_submodule)
		return -1;
	argv_array_push(&cp.args, oid_to_hex(old_oid));
	if (item->util)
static int for_each_remote_ref_submodule(const char *submodule,
void handle_ignore_submodules_arg(struct diff_options *diffopt,

}
	item->util = xcalloc(1, sizeof(struct oid_array));
		/* Is it already absorbed into the superprojects git dir? */

#include "repository.h"
	close(cp.out);
	memset(task, 0, sizeof(*task));

		struct pretty_print_context ctx = {0};
	oid_array_append(array, oid);

		}
	if (!submodule_has_commits(r, path, commits))
		if (flags & SUBMODULE_REMOVAL_DIE_ON_ERROR)
	}
	}
 * path_from_default_name(). Since the default name is the same as
			continue;
	}
	if (start_command(&cp))
				continue;
 * will be disabled because we can't guess what might be configured in
		 * correct answer would be "We do not know" instead of

/*
{
			if (ret < 0)
				path);
			  const struct remote *remote,
			argv_array_push(&cp->args, submodule_prefix.buf);

		 * without having the submodule around, this indicates
	dst->type = type;
	 */
				argv_array_push(&cp.args, rs->raw[i]);
		}
		diff_tree_combined_merge(commit, 1, &diff_rev);
		 * idea to not indicate failure in this case, and only
			path = submodule->path;
			return NULL;
	/*
/*
	 * instead of a remote name).
								&null_oid, path);
	ret = config_set_in_gitmodules_file_gently(entry.buf, newpath);
 * via the regular submodule-config. Create a fake submodule, which we can
		struct strbuf out = STRBUF_INIT;
	}
	struct argv_array argv = ARGV_ARRAY_INIT;
		cp.git_cmd = 1;
		/*

	strbuf_release(&sb);
out:
	if (!should_update_submodules())
	module = submodule_from_path(repo, &null_oid, path);
		}
			oid_to_hex(&list->item->object.oid));
static void free_submodules_oids(struct string_list *submodules)
	}
	free_submodules_oids(&spf.changed_submodule_names);
	setup_revisions(0, NULL, rev, NULL);
				   const char *path,

	static const char format[] = "  %m %s";
	cp.git_cmd = 1;

		task->free_sub = 1;

	for (i = 0; i < needs_pushing.nr; i++) {
				    push_options, dry_run)) {


int submodule_uses_gitfile(const char *path)
	/* submodule.active is set */
#include "submodule-config.h"
	cp.no_stderr = 1;
	repo_init_revisions(r, &rev, NULL);
	struct has_commit_data has_commit = { r, 1, path };
			int i;

	calculate_changed_submodule_paths(r, &spf.changed_submodule_names);

	spf.quiet = quiet;
	if (is_gitmodules_unmerged(the_repository->index))
	else

{
			      struct strbuf *err, void *data, void **task_cb)
		strbuf_release(&sb);
#define SPF_INIT {0, ARGV_ARRAY_INIT, NULL, NULL, 0, 0, 0, 0, \
	 * We prevent the contents of sibling submodules' git directories to
			handle_ignore_submodules_arg(diffopt, ignore);
	struct strbuf sb = STRBUF_INIT;

	submodule = submodule_from_path(the_repository, &null_oid, oldpath);

		struct string_list *changed_submodule_names)
		struct child_process cp = CHILD_PROCESS_INIT;

}

	cp.no_stdin = 1;
		diff_emit_submodule_modified(o, path);
				  const char *prefix)
		/*
	if (ignore_untracked)
}
	string_list_remove_empty_items(changed_submodule_names, 1);
{
	argv_array_push(&cp.args, head);
void submodule_unset_core_worktree(const struct submodule *sub)
						 const struct submodule *sub)
				      &ctx);

	cp.dir = sub->path;
	 * `.git/modules/hippo/` and `.git/modules/hippo/hooks/`, respectively,

			git_path("modules/%s", sub->name), 0);

	/* Are there commits we want, but do not exist? */
		}
	 * Collect all submodules (whether checked out or not) for which new


	return spf.result;
		message = "(commits not present)";
	struct argv_array argv = ARGV_ARRAY_INIT;
 * this would normally be two functions: default_name_from_path() and
		/* If it is an actual gitfile, it doesn't need migration. */
{
		prepare_submodule_repo_env(&cp.env_array);
	if (repo_read_index(r) < 0)
		spf->oid_fetch_tasks_nr++;
	oid_array_filter(commits,
	 */
	string_list_clear(submodules, 1);
		cp.git_cmd = 1;

		if (old_head) {
}
{
	return out;
	}
	return prepare_revision_walk(rev);

	if (!(flags & SUBMODULE_REMOVAL_IGNORE_IGNORED_UNTRACKED))
				   fetch_start_failure,
		return 0;

out:
	if (!(flags & SUBMODULE_MOVE_HEAD_DRY_RUN)) {
				warning(_("Submodule in commit %s at path: "
		connect_work_tree_and_git_dir(path,
			break;
	if (sub) {
	argv_array_push(&argv, "find_unpushed_submodules");
		return 0;

 */

		warning(_("Could not find section in .gitmodules where path=%s"), oldpath);

void set_diffopt_flags_from_submodule_config(struct diff_options *diffopt,
			if (!spf->quiet)

		struct rev_info diff_rev;
	int *error_code_ptr, error_code;
static void calculate_changed_submodule_paths(struct repository *r,
{
	struct argv_array *argv = data;
	if (!it)
	const char * const *var;
#include "remote.h"
			connect_work_tree_and_git_dir(path, gitdir, 1);

		cp.dir = path;
			 task->repo);
	subpath = relative_path(cwd, one_up.buf, &sb);
			if (buf.len < strlen("T XY SSSS"))


	strbuf_complete(buf, '/');
	diffopt->flags.ignore_untracked_in_submodules = 0;
		if (lstat(GITMODULES_FILE, &st) == 0 &&
			      sub, &left, &right, &merge_bases);
		return "rebase";
		if (repo_init(ret, gitdir.buf, NULL)) {
 * Die if the submodule can't be pushed.

	if (!sub)
	for (list = merge_bases; list; list = list->next) {
	return refs_for_each_remote_ref(get_submodule_ref_store(submodule),
		die(_("refusing to move '%s' into an existing git dir"),
			cp->git_cmd = 1;
		get_super_prefix_or_empty(), path,
			argv_array_push(&args, item->string);
 */
	argv_array_push(&spf.args, "fetch");



	cp.no_stdout = 1;
		argv_array_push(&cp.args, "rev-list");
		for (i = 0; i < needs_pushing.nr; i++)
		strbuf_repo_worktree_path(&gitdir, r, "%s/.git", sub->path);
			argv_array_push(out, *var);
	real_old_git_dir = real_pathdup(old_git_dir, 1);
		/*
		/* There is an unrelated git repository at '../' */
	commits = it->util;

		data.repo = r;
	if (code == 128)

#include "oid-array.h"
			continue;

	return 1;
	old_git_dir = xstrfmt("%s/.git", path);
 * Initialize a repository struct for a submodule based on the provided 'path'.
 * to be created (i.e. it's neither in the index nor in the current branch).
		repo_init_revisions(r, &diff_rev, NULL);
	}
		 * No entry in .gitmodules? Technically not a submodule,
/**
		ctx.date_mode = rev->date_mode;
			return fetch_recurse;
	rev->first_parent_only = 1;
	struct oid_array *array = data;
		diffopt->flags.ignore_submodules = 1;
	if (!file_exists(GITMODULES_FILE)) /* Do nothing without .gitmodules */
		}


			      sub, &left, &right, &merge_bases);
		if (istate->cache_nr > pos) {  /* there is a .gitmodules */

	char *gitdir = xstrfmt("%s/.git", path);
	if (!is_git_directory(git_dir)) {
static const char *get_super_prefix_or_empty(void)
		argv_array_pushl(&cp.args, "--not", "--remotes", "-n", "1" , NULL);
		return 0;

	}
		return 0;
		 * to determine.
void prepare_submodule_repo_env(struct argv_array *out)
			 */
	return 1;
}
		argv_array_pushf(&cp.args, "--dst-prefix=%s%s/",
		if (submodule_has_dirty_index(sub))
	if ((!is_null_oid(one) && !*left) ||
	prepare_submodule_repo_env(&cp.env_array);
			strbuf_addf(&submodule_prefix, "%s%s/",
			char *gitdir = xstrfmt("%s/modules/%s",
		/*
	enum object_type type = oid_object_info(cb->repo, oid, NULL);
		add_pending_object(rev, &list->item->object,
 */

			free(task);
int is_gitmodules_unmerged(const struct index_state *istate)
	 * `hippo/hooks` would result in the git directories
		"foreach",
	int default_option;
			if (run_command(&cp)) {

	strbuf_release(&entry);
	/* Treat revision walker failure the same as missing commits */
	struct repository *ret = xmalloc(sizeof(*ret));

{
		strbuf_addf(&sb, " %s\n", message);
	}
	if (arg)
	}
	struct string_list_item *item;
		 * in-place where a gitlink is. Keep supporting them.
	case SM_UPDATE_REBASE:
			free(task);
	}
			if (ce_namelen(ce) == strlen(GITMODULES_FILE) &&

	if (old_head && !(flags & SUBMODULE_MOVE_HEAD_FORCE)) {
		die(_("could not create directory '%s'"), new_git_dir);
 * Check if the .gitmodules file has unstaged modifications.  This must be
			    memcmp(buf.buf + 5, "S..U", 4))
	/* Not populated? */

		if (submodule)
		goto out;
	enum object_type type = oid_object_info(subrepo, oid, NULL);
	}

	const struct submodule *submodule;
	string_list_clear(&needs_pushing, 0);
	left->object.flags |= SYMMETRIC_LEFT;
			die(_("'%s' not recognized as a git repository"), git_dir);
	const struct commit *commit;
		if (!task->sub) {
	return needs_pushing->nr;
	ret = xmalloc(sizeof(*ret));
	strbuf_release(&sect);
static struct oid_array ref_tips_after_fetch;
}
		if (ignore)

		super_wt = xstrdup(cwd);
		if (!S_ISGITLINK(p->two->mode))
	}
	free(key);
		ret = 1;
 */
		list->item->object.flags |= UNINTERESTING;
}
	fetch_task_release(task);
		sub = submodule_from_path(the_repository, &null_oid, submodule);

		die(_("index file corrupt"));

	strbuf_add_unique_abbrev(&sb, one, DEFAULT_ABBREV);
	task->sub = submodule_from_path(r, &null_oid, path);

		free_commit_list(merge_bases);
		argv_array_push(&cp.args, "push");
	 */

		repo_format_commit_message(r, commit, format, &sb,
	if (code)
		diff_emit_submodule_error(o, "(diff failed)\n");
		     ignore_untracked)) {
	prepare_submodule_repo_env(&cp.env_array);

		strbuf_release(&buf);
	if (!file_exists(path) || is_empty_dir(path))
			/* also set the HEAD accordingly */
	prepare_submodule_repo_env(&cp.env_array);
			continue;
	if (merge_bases)
	struct submodule_parallel_fetch *spf = cb;
}
		oid_array_for_each_unique(commits, append_oid_to_argv, &cp.args);
{
	struct commit_list *list;

int submodule_touches_in_range(struct repository *r,
	}
		prepare_submodule_repo_env(&cp.env_array);
	strbuf_addf(&buf, "%s/.git", path);
		int super_sub_len;
			    !string_list_lookup(
		if (!name)
		if (is_directory(git_dir))

		repo_clear(p->repo);
		 * NOTE: We do consider it safe to return "no" here. The
	if (start_command(&cp))

					oid_to_hex(commit_oid), p->two->path);
			die(_("Failed to resolve HEAD as a valid ref."));
	/* We need a valid left and right commit to display a difference */
	prepare_submodule_repo_env(&cp.env_array);
	argv_array_pushl(&cp.args, "status", "--porcelain=2", NULL);
		const char *value;
	return ret;
	}
 * Put the gitdir for a submodule (given relative to the main
	strbuf_release(&sb);

		BUG("callback cookie bogus");
	memset(ret, 0, sizeof(*ret));

	add_pending_object(rev, &right->object, path);
{
	if (type == SM_UPDATE_COMMAND)
		warning(_("Could not remove .gitmodules entry for %s"), path);
		return spf->command_line_option;
			path = default_name_or_path(name->string);

	return spf->default_option;

static const struct submodule *get_non_gitmodules_submodule(const char *path)
}

{
 * Unlike repo_submodule_init, this tolerates submodules not present
						commit_oid, p->two->path);
static void prepare_submodule_repo_env_no_git_dir(struct argv_array *out)
	int err_code;
	cp.no_stdin = 1;
		if (old_head && (flags & SUBMODULE_MOVE_HEAD_FORCE)) {
static int commit_missing_in_sub(const struct object_id *oid, void *data)
	const char *cwd = xgetcwd();
/*

	return ret;
	if (start_command(&cp))
		argv_array_init(&cp->args);
			/* local config overrules everything except commandline */
		for (j = 0; j < ps->nr ; j++) {
		const char *path = needs_pushing.items[i].string;
	int result;
		super_sub = strchr(sb.buf, '\t') + 1;
 */
				      remote->name, &needs_pushing))
	key = xstrfmt("submodule.%s.url", module->name);

 * checked before allowing modifications to the .gitmodules file with the
		struct strbuf sb = STRBUF_INIT;
	 * but the latter directory is already designated to contain the hooks

	cp.out = -1;

	if (!module)
		argv_array_clear(&args);
		argv_array_push(&args, "--not");

	if (len <= suffix_len || (p = git_dir + len - suffix_len)[-1] != '/' ||
		switch (get_fetch_recurse_config(task->sub, spf))

	argv_array_push(argv, oid_to_hex(oid));
	if (git_dir) {
	spf.prefix = prefix;

	return submodule_from_path(the_repository, &null_oid, ce->name);
{
 * (and staging them) would blindly overwrite ALL the old content.
}



}
	prefixlen = strlen(prefix);
#include "diff.h"
	cp.no_stdin = 1;
#include "dir.h"
	/* No need to check if there are no submodules configured */
			read_gitfile_error_die(err_code, path, NULL);
		 * FIXME:
		* itself and was just absorbed. The absorption of the
			 * An empty directory is normal,

	return 1;
		cp.no_stdin = 1;
int git_default_submodule_config(const char *var, const char *value, void *cb)
	struct child_process cp = CHILD_PROCESS_INIT;
 * Moves a submodule at a given path from a given head to another new head.
	if (!is_inside_work_tree())
				strbuf_addf(err, _("Fetching submodule %s%s\n"),
	if (git_config_rename_section_in_file(GITMODULES_FILE, sect.buf, NULL) < 0) {
}
	}
	    strcmp(p, submodule_name))
	len = strbuf_read(&buf, cp.out, 1024);
	}
		initialized_fetch_ref_tips = 1;
		diff_emit_submodule_error(o, "(revision walker failed)\n");
				    get_git_dir(), sub->name);
	cp.dir = path;

		return NULL;
		return 0;
	if (read_gitfile(old_git_dir))
	if (submodule_to_gitdir(&sb, path) || repo_init(out, sb.buf, NULL)) {
			strbuf_release(&gitdir);
	sub = submodule_from_path(the_repository, &null_oid, path);

				   "--ignore-submodules=none", NULL);

	int i;


	 * diff format and wishes to actually see all differences even if they
		return -1;
	struct has_commit_data *cb = data;
/*
	    !(right || is_null_oid(two)))

}
		{
		*task_cb = task;

	}

	struct strbuf objects_directory = STRBUF_INIT;
	argv_array_pushf(&cp.args, "--super-prefix=%s%s/",
	}
	}
	cp.no_stdin = 1;
		return NULL;

	if (start_command(&cp)) {
static int prepare_submodule_summary(struct rev_info *rev, const char *path,
}
		cp.no_stdin = 1;
			diff_emit_submodule_del(o, sb.buf);
			  sub->path);
	if (len > 2)
	return 0;
			if (buf.buf[0] == 'u' ||
/*
	argv_array_push(&cp.args, "push-check");
	if (p->repo)
			void *cb, void *task_cb)
 *
					    const char *path)
	 * More detailed error information will be provided by the

		return;
		/* Check if the submodule has a dirty index. */



 * in its superprojects git dir under modules/.
			RECURSE_SUBMODULES_ON : RECURSE_SUBMODULES_OFF;
		if (!S_ISGITLINK(ce->ce_mode))
	else if (*value == '!')
			continue;
	/* TODO: other options may need to be passed here. */
		    ((dirty_submodule & DIRTY_SUBMODULE_UNTRACKED) ||
	if (flags & SUBMODULE_MOVE_HEAD_DRY_RUN)
	if (!submodule_from_path(r, NULL, NULL))
}
static void submodule_push_check(const char *path, const char *head,
	int ret;
		NULL,
	struct collect_changed_submodules_cb_data *me = data;
		goto out;
		*/

	 */


		die(_("bad --ignore-submodules argument: %s"), arg);
						       spf->prefix,
		 * present, make sure it exists in the submodule's object store
	if (!strbuf_realpath(&one_up, "../", 0))
		int cwd_len = strlen(cwd);

int parse_submodule_update_strategy(const char *value,
	}
{
		struct strbuf buf = STRBUF_INIT;
		if (!S_ISGITLINK(ce->ce_mode))
	cp.git_cmd = 1;
		return 1;
	struct child_process cp = CHILD_PROCESS_INIT;
	argv_array_push(&argv, "--not");

 */
	if (p->free_sub)
void absorb_git_dir_into_superproject(const char *path,
	const struct submodule *submodule = submodule_from_path(the_repository,

		 */
			relocate_single_git_dir_into_superproject(path);
			continue;
	argv_array_pushf(&cp.args, "--color=%s", want_color(o->use_color) ?
static int submodule_needs_pushing(struct repository *r,
	 * add new options
		prepare_submodule_repo_env(&cp.env_array);
	ret = strbuf_git_path_submodule(&objects_directory, path, "objects/");
		return 0;
			    !strcmp(ce->name, GITMODULES_FILE))
	 * Please update _git_status() in git-completion.bash when you

 * When a submodule is not defined in .gitmodules, we cannot access it
	ret = subs.nr;
	*merge_bases = repo_get_merge_bases(sub, *left, *right);
 * .gitmodules unless the user resolves the conflict.
	sl = repo_config_get_value_multi(repo, "submodule.active");

		s = "";
				   &spf,
	add_to_alternates_memory(objects_directory.buf);
	return path_or_name;


		argv_array_push(&cp->args, submodule_prefix.buf);
		return 0;
		}
 * the revisions as specified in 'argv'.  Each entry in 'changed' will also
	cp.git_cmd = 1;



	struct string_list submodules = STRING_LIST_INIT_DUP;
			if (!submodule_uses_gitfile(path))
	cp.git_cmd = 1;
	return 0;

	}
/* Cheap function that only determines if we're interested in submodules at all */
			fprintf(stderr, _("Unable to push submodule '%s'\n"), path);
	for_each_string_list_item(item, submodules)
/* TODO: remove this function, use repo_submodule_init instead. */
	if (remote->origin != REMOTE_UNCONFIGURED) {
	}
		parse_pathspec(&ps, 0, 0, NULL, args.argv);
		return NULL;
 *
				   get_super_prefix_or_empty(), path);
{
		* fix it now.

				continue;
		new_oid = two;
		return -1;


			       int default_option,
		return SM_UPDATE_CHECKOUT;
	 * won't be propagated due to the remote being unconfigured (e.g. a URL
static void collect_changed_submodules_cb(struct diff_queue_struct *q,

 * Check if the .gitmodules file is safe to write.

		cp.dir = path;
		spf->oid_fetch_tasks_nr--;

	 * Warn about missing commits in the submodule project, but only if

		else if ((*merge_bases)->item == *right)
}
	if (prepare_revision_walk(&rev))
		char *key;
 * For edge cases (a submodule coming into existence or removing a submodule)
/**
int add_submodule_odb(const char *path)
		 * in-place where a gitlink is. Keep supporting them.
		die(_("process for submodule '%s' failed"), path);

	switch (s->type) {
		argv_array_push(&spf.args, options->argv[i]);
	if (!is_null_oid(excl_oid)) {
		char *real_common_git_dir = real_pathdup(get_git_common_dir(), 1);
		free(key);
int submodule_move_head(const char *path,
		}
	return task;
	struct string_list *changed;
	const char *message = NULL;
	if (!strcmp(arg, "all"))
		ret = match_pathspec(repo->index, &ps, path, strlen(path), 0, NULL, 1);
	if (repo_submodule_init(ret, r, sub)) {
	if (submodule) {
	 * haven't yet been committed to the submodule yet.
	return file_exists(GITMODULES_FILE) ||
	fp = xfdopen(cp.out, "r");
		unsigned dirty_submodule)
		message = "(submodule deleted)";
			spf->count++;

			}
		cp.dir = path;



	cp.no_stdout = 1;
	if (finish_command(&cp))
		    buf.buf[0] == '1' ||
			continue;
			     struct oid_array *commits,

	struct string_list needs_pushing = STRING_LIST_INIT_DUP;
};
	clear_commit_marks(right, ~0);

		return "checkout";
 */
	argv_array_push(&args, "--"); /* args[0] program name */
		}

		strbuf_addstr(buf, git_dir);

#include "quote.h"
}
			       const struct argv_array *options,
		 * and that it is reachable from a ref.
	}


		"test -f .git",
	int ignore_cp_exit_code = 0;
#include "blob.h"
	prepare_submodule_repo_env(&cp.env_array);
{
	clear_commit_marks(left, ~0);
				ret = -1;
	if (!(dirty_submodule & DIRTY_SUBMODULE_MODIFIED))
	else
{
	struct string_list_item *it;

			continue;
	/* default value, "--submodule-prefix" and its value are added later */
	else if (!strcmp(arg, "untracked"))
	struct repository *out = xmalloc(sizeof(*out));
 * modifications the user didn't stage herself too. That might change in a
	return 0;


		struct stat st;
		return NULL;
out:

	return ret;
					"the same. Skipping it."),

int get_superproject_working_tree(struct strbuf *buf)
	for (i = 0; i < q->nr; i++) {
}
		}
		return;
				strbuf_addf(err,


			name = submodule->name;

			 commit_missing_in_sub,
				   fetch_finish,
		pos = -1 - pos;

	struct fetch_task *task = xmalloc(sizeof(*task));


	p->sub = NULL;
	return NULL;

static struct oid_array ref_tips_before_fetch;
	if (o->flags.reverse_diff) {
		char *real_sub_git_dir = real_pathdup(sub_git_dir, 1);
		 * around. If a user did however change the submodules
					     head, remote, rs);
				   "--cached", "HEAD", NULL);
		struct strbuf gitdir = STRBUF_INIT;
			}
done:
		goto out;


			argv_array_push(&cp->args, default_argv);
					     git_dir,
	/*
				 const struct remote *remote,
		const struct string_list_item *item;
					 "--no-deref", new_head, NULL);
			spf->oid_fetch_tasks[spf->oid_fetch_tasks_nr - 1];

		if (buf.buf[0] == '?')
 * it is in the index or in the current branch, because writing new values
			*p = c;
	free(config_path);
						       task->sub->path);
			cp.git_cmd = 1;
		argv_array_pushl(&cp.args, "--not", "--all", NULL);

	const struct submodule *module;
	}
		data.changed = changed;

	struct fetch_task *task = task_cb;

			default_argv = "on-demand";
	if (submodule) {
				/* other change */
{
		if (!path)

	const char *git_dir;
{
		super_sub_len = strlen(super_sub);
	}
		default:
	argv_array_clear(&spf.args);
	const struct submodule *submodule;
	if (!is_git_directory(buf->buf)) {
	return 0;
		 * There is a superproject having this repo as a submodule.
 * in .gitmodules. This function exists only to preserve historical behavior,

		argv_array_push(&cp->args, "origin");
		int ce_len = ce_namelen(ce);

			return 0;
	ssize_t len;



		if (submodule)

 * Determine if a submodule has been initialized at a given 'path'
	if (!r->worktree)
	struct fetch_task *task = task_cb;
		}
	struct strbuf entry = STRBUF_INIT;
	}
	if (submodule_uses_worktrees(path))

		sub = submodule_from_path(the_repository, &null_oid, path);
		submodule = submodule_from_path(me->repo,
			fetch_recurse = parse_fetch_recurse_submodules_arg(key, value);
}
{

		task = fetch_task_create(spf->r, ce->name);
			get_super_prefix_or_empty(), path);

	argv_array_pop(&cp.env_array);
	 * reachable from a ref, so we can fail early without spawning rev-list
		if (new_head) {
	case SM_UPDATE_NONE:
	argv_array_clear(&argv);
	spf.command_line_option = command_line_option;
				ret = -1;

}
	 * a fast forward or fast backwards update.
			   spf->oid_fetch_tasks_alloc);
	else if (is_null_oid(two))
 * repository worktree) into `buf`, or return -1 on error.
			 */
	if (!git_dir) {

							    arg);
 * pass NULL for old or new respectively.
		head = resolve_refdup("HEAD", 0, &head_oid, NULL);
		return 0;
		argv_array_push(&cp.args, oid_to_hex(new_oid));
			   spf->oid_fetch_tasks_nr + 1,
	if (validate_submodule_git_dir(new_git_dir, sub->name) < 0)
}
		return 1;
				 o->a_prefix, path);
{
}
	if (!repo_config_get_bool(repo, key, &ret)) {
	case OBJ_BAD:
{
		const char *path = NULL;

 * staging any previous modifications.
	}
		if (!sub) {

	struct string_list_item *name;
				BUG("invalid status --porcelain=2 line %s",
	prepare_submodule_repo_env(&cp.env_array);
			path = default_name_or_path(name->string);
	int code;
		cp.out = -1;
			name = default_name_or_path(p->two->path);
	free(new_git_dir);

			submodule_unset_core_worktree(sub);
	}
	argv_array_pushf(&argv, "--remotes=%s", remotes_name);
		config_update_recurse_submodules = v;
	struct strbuf sb = STRBUF_INIT;
		struct oid_array *commits;
		task->sub = get_non_gitmodules_submodule(path);
		}
	const struct submodule *sub;
	strbuf_addstr(&entry, submodule->name);
				/* nested untracked file */

	struct child_process cp = CHILD_PROCESS_INIT;
		free(key);
	spf->result = 1;
 */
	argv_array_push(&args, oid_to_hex(incl_oid));
{
 */
 * location.
		close(cp.out);
#include "thread-utils.h"
	struct oid_array *commits;
	}
		warning(_("Could not find section in .gitmodules where path=%s"), path);
		struct cache_entry *ce = istate->cache[i];
	while ((commit = get_revision(rev))) {


	if (!task || !task->sub)
			}
	cp.no_stdout = 1;
 * NULL when the submodule is not present.
		 * The format is <mode> SP <hash> SP <stage> TAB <full name> \0,
		super_wt[cwd_len - super_sub_len] = '\0';
	struct string_list subs = STRING_LIST_INIT_DUP;
			     struct string_list *needs_pushing)

	struct strbuf sb = STRBUF_INIT;

	strbuf_release(&sb);
	const struct submodule *sub;
		if (!message)
	case OBJ_COMMIT:
int update_path_in_gitmodules(const char *oldpath, const char *newpath)
		 * Even if the submodule is checked out and the commit is
			/* make sure name does not collide with existing one */
static void prepare_submodule_repo_env_in_gitdir(struct argv_array *out)
int is_submodule_active(struct repository *repo, const char *path)

	argv_array_push(&cp.args, new_head ? new_head : empty_tree_oid_hex());
 * Helper function to display the submodule header line prior to the full
		if (!sub)
	 */
	oid_array_clear(&ref_tips_before_fetch);
		cb->result = 0;
		const char *path,
	show_submodule_header(o, path, one, two, dirty_submodule,
}
	/* Actually push the submodules */

			     struct oid_array *commits,
		else


				   append_oid_to_argv, &argv);
}
{
		ret = -1;
		/*
	return ret;
	for (i = 0; i < istate->cache_nr; i++) {
		if (!repo_config_get_string_const(spf->r, key, &value)) {
		return SM_UPDATE_REBASE;

	out->submodule_prefix = xstrdup(path);
				spf->result = 1;
static int check_has_commit(const struct object_id *oid, void *data)
		const char *name;
		argv_array_push(&cp.args, "--ignored");
}
{
static int append_oid_to_array(const char *ref, const struct object_id *oid,
/*


			if (is_empty_dir(path))
 * Returns the repository struct on success,
static struct fetch_task *fetch_task_create(struct repository *r,
						 item->string);
		}
	diffopt->flags.ignore_submodules = 0;
 * and negative values for errors.
			     int dry_run)
}
	 * do not have the commit object anywhere, there is no chance we have
	struct string_list_item *item;
		ret = 1;

	if (flags & ABSORB_GITDIR_RECURSE_SUBMODULES) {

			argv_array_push(&cp->args, "--submodule-prefix");

static void collect_changed_submodules(struct repository *r,
 *
			path = submodule->path;

								commit_oid, name);
 * summary output.
		argv_array_push(&cp->args, "on-demand");
	}
			cp->dir = task->repo->gitdir;
	if (spf->command_line_option != RECURSE_SUBMODULES_DEFAULT)
	if (right)
		if (strcmp(*var, CONFIG_DATA_ENVIRONMENT))
	const char *git_dir;
					task->sub->name))
		const struct cache_entry *ce = spf->r->index->cache[spf->count];
 *
	strbuf_add_unique_abbrev(&sb, two, DEFAULT_ABBREV);
/*
	size_t len = strlen(git_dir), suffix_len = strlen(submodule_name);
	struct rev_info rev;
		key = xstrfmt("submodule.%s.fetchRecurseSubmodules", submodule->name);

#include "diffcore.h"
		    ie_modified(istate, istate->cache[pos], &st, 0) & DATA_CHANGED)
			if (item->len <= ce_len)
		die(_("revision walk setup failed"));

	int quiet;
	cp.no_stdin = 1;
static void print_submodule_summary(struct repository *r, struct rev_info *rev, struct diff_options *o)

}
		argv_array_push(&cp.args, old_head ? old_head : empty_tree_oid_hex());
			ignore = submodule->ignore;
		repo_clear(sub);
{
}
		diff_emit_submodule_error(o, "(diff failed)\n");
			char c = *p;
		return -1;
	 */
		strbuf_release(&out);
	while ((commit = get_revision(&rev))) {
	}
			return;
	}
		}
 * Check if it is a bad idea to remove a submodule, i.e. if we'd lose data
	if (!s)
int submodule_to_gitdir(struct strbuf *buf, const char *submodule)
	/*
	if (code == 0 && len == 0)
	return (const struct submodule *) ret;
 */
			BUG("we don't know how to pass the flags down?");
	return ret;

	strbuf_release(&buf);
 * future version when we learn to stage the changes we do ourselves without

		oid_array_clear((struct oid_array *) item->util);
	item = string_list_insert(submodules, name);
 * path is configured. Return 0 only if a .gitmodules file was found, a section
	show_submodule_header(o, path, one, two, dirty_submodule,
{

	int error_code;
	char *value = NULL;
	/* Pending fetches by OIDs */
	if (message)
		if (run_command(&cp))
	relocate_gitdir(path, real_old_git_dir, real_new_git_dir);


	if (add_file_to_index(istate, GITMODULES_FILE, 0))
	print_submodule_summary(sub, &rev, o);

		diff_emit_submodule_pipethrough(o, sb.buf, sb.len);
	case SM_UPDATE_MERGE:
}
	 * reason to try and display a summary. The header line should contain

			if (item->len == ce_len + 1)

		 * but historically we supported repositories that happen to be

			string_list_insert(needs_pushing, path);


		close(cp.out);
			break;
		argv_array_push(&cp.args, "-u");

 * Try to remove the "submodule.<name>" section from .gitmodules where the given
		 * has already been printed.
	fclose(fp);
	if (right)
			 const char *old_head,
			     const char *remotes_name,
		if (prefix[ce_len] != '/')
	prepare_submodule_repo_env(&cp.env_array);
	int ret = 0;
	struct submodule_parallel_fetch *spf = cb;
{
		cp->dir = task->repo->gitdir;


	/* fallback to checking if the URL is set */
{
				absorb_git_dir_into_superproject(path,
}
		die(_("submodule entry '%s' (%s) is a %s, not a commit"),

}
			continue;
			argv_array_push(&cp.args, remote->name);
	struct child_process cp = CHILD_PROCESS_INIT;
}
	/* argv.argv[0] will be ignored by setup_revisions */
	setup_revisions(argv->argc, argv->argv, &rev, NULL);
				dirty_submodule |= DIRTY_SUBMODULE_UNTRACKED;
}
		clear_commit_marks(left, ~0);

	return ret;

	char *new_git_dir;

		  STRING_LIST_INIT_DUP, \
		return SM_UPDATE_NONE;
		struct commit **left, struct commit **right,


	struct strbuf sb = STRBUF_INIT;
		struct diff_filepair *p = q->queue[i];
			    item->original, ce_len, ce->name);
}
	}
}

{


		const char *default_argv;
{
		else
	const struct object_id *old_oid = the_hash_algo->empty_tree, *new_oid = the_hash_algo->empty_tree;
	}
const struct submodule *submodule_from_ce(const struct cache_entry *ce)
			spf.submodules_with_errors.buf);
		diff_emit_submodule_untracked(o, path);
{
		return 0;
	}
done:
		}
	/*

		case RECURSE_SUBMODULES_OFF:

int fetch_populated_submodules(struct repository *r,
	if (!sub) {
	/* early return if there isn't a path->module mapping */
unsigned is_submodule_modified(const char *path, int ignore_untracked)
		die(_("could not recurse into submodule '%s'"), sub->path);
static struct repository *open_submodule(const char *path)

 */
void check_for_new_submodule_commits(struct object_id *oid)
		strbuf_addf(&submodule_prefix, "%s%s/",
	else
		} else {
	if (sl) {
			goto cleanup;

	struct strbuf one_up = STRBUF_INIT;
			if (strncmp(ce->name, item->match, ce_len))
		prepare_submodule_repo_env_in_gitdir(&cp->env_array);
	if (flags & SUBMODULE_MOVE_HEAD_FORCE)
	for (; spf->count < spf->r->index->cache_nr; spf->count++) {
	const char *subpath;
		if (start_command(&cp))
int is_submodule_populated_gently(const char *path, int *return_error_code)
}
			  const struct string_list *push_options,
	cp.git_cmd = 1;
			const struct pathspec_item *item = &ps->items[j];
		}
	return s;
				    struct submodule_parallel_fetch *spf)
 */
	}
/*
	strbuf_release(&one_up);
			oid_array_clear(commits);
				    get_git_dir(), sub->name);
			die(_("Pathspec '%s' is in submodule '%.*s'"),
	strbuf_addstr(&sb, (fast_backward || fast_forward) ? ".." : "...");
	int ret = 0;
int is_writing_gitmodules_ok(void)
	for (i = 0; i < rs->raw_nr; i++)
		    submodule_name, git_dir);
		child_process_init(cp);
	strbuf_addf(&sb, "Submodule %s ", path);
	oid_array_for_each_unique(&ref_tips_after_fetch,

{

 * Dies if any paths in the provided pathspec descends into a submodule
	struct strbuf sb = STRBUF_INIT;
		if (flags & SUBMODULE_REMOVAL_DIE_ON_ERROR)


		free(sub);
			  int dry_run)
	diff_emit_submodule_header(o, sb.buf);
		struct commit_list **merge_bases)
	}
	if (dirty_submodule & DIRTY_SUBMODULE_UNTRACKED)
		key = xstrfmt("submodule.%s.ignore", submodule->name);

struct has_commit_data {
	int i;
		char *key;
	}
	struct repository *r;
	argv_array_push(&cp.args, "submodule--helper");
	 * child process.
	while (strbuf_getwholeline(&buf, fp, '\n') != EOF) {
		if (super_sub_len > cwd_len ||
		if (err_code == READ_GITFILE_ERR_STAT_FAILED) {

/*
		config_update_recurse_submodules = RECURSE_SUBMODULES_OFF;
	if (!find_unpushed_submodules(r, commits,

	argv_array_clear(&args);
{
	if (!git_dir)
	case SM_UPDATE_UNSPECIFIED:


static struct oid_array *submodule_commits(struct string_list *submodules,
		argv_array_push(&cp->args, "--submodule-prefix");
		"--quiet",
		argv_array_push(&cp.args, "-n");
				 o->b_prefix, path);
		if (strbuf_read(&buf, cp.out, the_hash_algo->hexsz + 1))
	strbuf_addstr(buf, ".git");


		ctx.output_encoding = get_log_output_encoding();
	if (for_each_remote_ref_submodule(path, has_remote, NULL) > 0) {
	}
			diffopt->flags.ignore_submodules = 1;
	return ret;

		    real_old_git_dir);
int should_update_submodules(void)
	close(cp.out);
	if (type == SM_UPDATE_UNSPECIFIED)
{
					     const char *path)
		if (!S_ISGITLINK(ce->ce_mode))
		goto out;
	switch (type) {

		 */
		struct child_process cp = CHILD_PROCESS_INIT;
		strbuf_reset(buf);

		die(_("could not start ls-files in .."));
				 const char *path,
			if (is_git_directory(git_dir))
{
	struct commit *left = NULL, *right = NULL;
			connect_work_tree_and_git_dir(path, gitdir, 0);
	struct oid_array *commits; /* Ensure these commits are fetched */
	const struct string_list *sl;
	if (safe_create_leading_directories_const(new_git_dir) < 0)
struct fetch_task {
				   struct oid_array *commits)
	cp.out = -1;
}
cleanup:


				rmdir_or_warn(path);
	}
	for (i = 0; i < istate->cache_nr; i++) {

		config_update_recurse_submodules = RECURSE_SUBMODULES_ON;
{
		old_oid = one;
	if (!initialized_fetch_ref_tips) {
static int has_remote(const char *refname, const struct object_id *oid,
		 */
	struct repository *repo;
		warning(_("Could not unset core.worktree setting in submodule '%s'"),
		BUG("submodule name '%s' not a suffix of git dir '%s'",
		strbuf_realpath(buf, super_wt, 1);

	case SM_UPDATE_COMMAND:
 */
	collect_changed_submodules(r, &subs, &args);

		 * to fixup the submodule in the force case later.
}
				name = NULL;
		case RECURSE_SUBMODULES_DEFAULT:
{
/*

	if (pos < 0) { /* .gitmodules not found or isn't merged */
{
		strbuf_setlen(&sb, 0);
 * with the correct path=<oldpath> setting was found and we could update it.
	/*


	prepare_submodule_repo_env_no_git_dir(out);
	if (merge_bases)
}

	struct submodule_parallel_fetch *spf = data;

}
		free(sub);
				      unsigned flags)
	if (!name)

			free(ret);
	dst->command = NULL;
		if (!task)

	while (strbuf_getwholeline_fd(&sb, cp.out, '\n') != EOF)
			BUG("returned path string doesn't match cwd?");

	struct submodule_parallel_fetch spf = SPF_INIT;
		repo_clear(sub);
	argv_array_pushf(out, "%s=.", GIT_DIR_ENVIRONMENT);
	return ret;
	struct strbuf submodules_with_errors;
					  append_oid_to_argv, &cp->args);
		"--recursive",

		const struct submodule *submodule;
	if (!submodule || !submodule->name) {
	if (!left || !right || !sub)
	sub = open_submodule(path);
		die(_("ls-tree returned unexpected return code %d"), code);
		return 1;

		if (err_code != READ_GITFILE_ERR_NOT_A_REPO)
					       "inside git dir '%.*s'"),
		oid_array_append(commits, &p->two->oid);

		 * No entry in .gitmodules? Technically not a submodule,
}
		die(_("'git status --porcelain=2' failed in submodule %s"), path);
			       int quiet, int max_parallel_jobs)
	strbuf_release(&buf);
/*
/*
 */
	int i;
			argv_array_pushv(&cp->args, spf->args.argv);

	repo_init_revisions(the_repository, rev, NULL);
	oid_array_for_each_unique(commits, check_has_commit, &has_commit);
struct submodule_parallel_fetch {
 * Embeds a single submodules git directory into the superprojects git dir,
		fprintf(stderr, _("Pushing submodule '%s'\n"), path);
	 * If the submodule has modified content, we will diff against the
	enum submodule_update_type type;
	argv_array_push(&cp.args, remote->name);
 */

	if (for_each_remote_ref_submodule(path, has_remote, NULL) > 0) {
		 * to prevent die()-ing. We'll use connect_work_tree_and_git_dir
		struct oid_array *commits = name->util;
	git_dir = read_gitfile(buf->buf);
		strbuf_release(&sb);
		struct collect_changed_submodules_cb_data data;
			 unsigned flags)
			 DEFAULT_GIT_DIR_ENVIRONMENT);
	argv_array_push(&argv, "--"); /* argv[0] program name */
	 * object store, and then querying for each commit's existence.  If we
		const struct submodule *submodule;
	oid_array_append(&ref_tips_after_fetch, oid);
	 * submodules.  This check can be skipped if the remote and refspec
					   "absorb-git-dirs", NULL);

	/*
		strbuf_reset(buf);
	free(key);
	else if (strcmp(arg, "none"))

				 o->b_prefix, path);
	int ret = 0;
		struct submodule_update_strategy *dst)
{
	collect_changed_submodules(r, &submodules, &argv);
				goto out;
		/*
			cp.no_stdin = 1;
					  struct diff_options *options,

			ret = -1;
			       void *cb, void *task_cb)
	int ret;
}
enum submodule_update_type parse_submodule_update_type(const char *value)
int push_unpushed_submodules(struct repository *r,
	argv_array_pushf(&cp.args, "--super-prefix=%s%s/",
		die(_("could not reset submodule index"));
	const struct submodule *sub;
		} else {
 * If it can locate the submodule git directory it will create a repository
	int ret = 0;

			if (item->match[ce_len] != '/')
		ret = error(_("Submodule '%s' could not be updated."), path);
			if (submodule) {
	ssize_t len;
		struct child_process cp = CHILD_PROCESS_INIT;

		struct fetch_task *task =
{
	 * work tree, under the assumption that the user has asked for the
			dirty_submodule |= DIRTY_SUBMODULE_UNTRACKED;
	struct repository *subrepo = data;
	int i, j;

	collect_changed_submodules(r, changed_submodule_names, &argv);
					    spf->prefix, ce->name);
	 */
		int fetch_recurse = submodule->fetch_recurse;
	struct submodule *ret = NULL;
	strbuf_release(&gitdir);
		 */
			default_argv = "yes";
	 */
		 * but historically we supported repositories that happen to be
	struct rev_info rev;
			child_process_init(&cp);
	if (oideq(one, two)) {
				continue;

	}
						     const char *arg, int unset)
static int get_next_submodule(struct child_process *cp,
		/*
		 * Object is missing or invalid. If invalid, an error message

	if (ret)
{
	return has_commit.result;
};
	for_each_string_list_item(name, changed_submodule_names) {
		const char *ignore;
		 * NEEDSWORK: This indicates that the overall fetch
		strbuf_release(&buf);
	int i, ret = 1;
		      int flags, void *cb_data)
				  const char *arg)
			*p = '\0';
}
static int fetch_start_failure(struct strbuf *err,
	if (resolve_gitdir_gently(gitdir, return_error_code))
	if (*merge_bases) {

 * intention to stage them later, because when continuing we would stage the
	int ret = 0;

static int submodule_has_commits(struct repository *r,
		const struct submodule *submodule;
			     const struct refspec *rs,

		return needs_pushing;
	const char *prefix;
	if (flags & SUBMODULE_MOVE_HEAD_FORCE)
	strbuf_addf(&gitdir, "%s/.git", path);
		goto done;
		if ((dirty_submodule & DIRTY_SUBMODULE_MODIFIED) &&
 */
			if (name)
{
 */
	*right = lookup_commit_reference(sub, two);
	 * clash.
}
		 * by commit hash that might work. It may be a good
	const char *git_dir;
		git_dir = buf.buf;
				continue;
	sub = open_submodule(path);
{
		argv_array_push(&cp.args, "-m");
	return type != OBJ_COMMIT;
		    strcmp(&cwd[cwd_len - super_sub_len], super_sub))
		    buf.buf[0] == '2') {
	cp.no_stdin = 1;

		else {
		 * "No push needed", but it is quite hard to change
	spf.r = r;
			return 0;

	}
	int ret = 0;
	const char *s = get_super_prefix();
}

	argv_array_pushl(&cp.args, "diff-index", "--quiet",
#include "submodule.h"
	if (!is_directory(objects_directory.buf)) {
 * It is not safe to write to .gitmodules if it's not in the working tree but
		 * both cases it should be safe to skip this check.

		if (submodule_needs_pushing(r, path, commits))
	}
		for_each_ref(append_oid_to_array, &ref_tips_before_fetch);
		task->repo = get_submodule_repo_for(spf->r, task->sub);
		      "more than one worktree not supported"), path);
		return SM_UPDATE_COMMAND;
	return 0;

		real_old_git_dir, real_new_git_dir);
	 * If we don't have both a left and a right pointer, there is no
			continue;


		clear_commit_marks(right, ~0);
	/* Mark it as a submodule */
 * handle for the submodule and lookup both the left and right commits and
	if (!prefix)
	int count;
	case SM_UPDATE_CHECKOUT:
					&spf->changed_submodule_names,
	prepare_submodule_repo_env(&cp.env_array);
	 * This is done by adding the submodule's object store to the in-core
}
 * non recursively.
		if (push_options && push_options->nr) {

				   append_oid_to_argv, &argv);
				    get_git_dir(), sub->name);
	struct fetch_task **oid_fetch_tasks;
		 * the submodule pointer without having the submodule
	if (starts_with(sb.buf, "160000")) {
		}
}
	struct string_list *changed = me->changed;

{
 * Dies if the provided 'prefix' corresponds to an unpopulated submodule
int find_unpushed_submodules(struct repository *r,
	strbuf_reset(&buf);
 * Return 1 if we'd lose data, return 0 if the removal is fine,
		}
}
			    spf->prefix, task->sub->path);
		ALLOC_GROW(spf->oid_fetch_tasks,
		}
	if (!task->sub) {

{
		cp.no_stdin = 1;
}
	 * Simply indicate if 'submodule--helper push-check' failed.
	for_each_string_list_item(name, &submodules) {
	struct strbuf buf = STRBUF_INIT;
	 * commits have been recorded upstream in "changed_submodule_names".

		strbuf_addf(&sb, "!%s", s->command);
	free((void*)dst->command);
}
		dst->command = xstrdup(value + 1);
			 * We're not interested in any further information from

		free_commit_list(merge_bases);
{
			    buf.buf[0] == '2' ||
		strbuf_release(&buf);
static int initialized_fetch_ref_tips;
		 * Pass non NULL pointer to is_submodule_populated_gently
		argv_array_push(&cp.args, "--reset");

		struct commit *left, struct commit *right,
	diffopt->flags.ignore_dirty_submodules = 0;
	unsigned free_sub : 1; /* Do we need to free the submodule? */
	if (run_command(&cp))

	return ret;
		if (dry_run)
			       const char *prefix, int command_line_option,

		if (is_dir_sep(*p)) {
 * with the correct path=<path> setting was found and we could remove it.
		 * an expert who knows what they are doing or a
		return NULL;
			free(gitdir);
		free(real_sub_git_dir);


	strbuf_addstr(&sect, submodule->name);
			char *gitdir = xstrfmt("%s/modules/%s",
	 * they aren't null.
	struct object_id oid;
	strbuf_addstr(&entry, "submodule.");
			strbuf_release(&submodule_prefix);
			/* We don't know what broke here. */
{
		argv_array_pushf(&cp.args, "--dst-prefix=%s%s/",
		return -1;
		free(super_wt);
	string_list_sort(&spf.changed_submodule_names);
 */

{
