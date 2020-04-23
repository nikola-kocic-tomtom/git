	return ret;
#include "branch.h"
			     PARSE_OPT_NOARG | PARSE_OPT_OPTARG),
				  sb_repo.buf);
	}
	cp.dir = wt->path;
		return 1;

	if (!worktree_lock_reason(wt))
		die(_("validation failed, cannot remove working tree: %s"),

		die_errno(_("failed to move '%s' to '%s'"), wt->path, dst.buf);
		return lock_worktree(ac - 1, av + 1, prefix);
			printf("detached\n");
			*abbrev = sha1_len;

	N_("git worktree lock [<options>] <path>"),
	}
		goto done;
	 */
	worktrees = get_worktrees(0);
static pid_t junk_pid;
			   N_("checkout <branch> even if already checked out in other worktree"),
{
	return add_worktree(path, branch, &opts);
	N_("git worktree move <worktree> <new-path>"),
		int path_len = strlen(wt[i]->path);
	if (!commit)
			die_errno(_("could not create directory of '%s'"),
	/*
		 * directory exists but is empty. But it's a rare case and
	}
#include "refs.h"
			    av[0], old_reason);
		die(_("'%s' is not a working tree"), av[0]);
			cp.stdout_to_stderr = 1;

		usage_with_options(worktree_usage, options);

		free(path);
}
		usage_with_options(worktree_usage, options);
	if (ret < 0 && errno == ENOTDIR)
			continue;
			cp.no_stdin = 1;
		if (*reason)

		die(_("'%s' is not a working tree"), av[0]);
	printf("%s\n", sb.buf);
				find_unique_abbrev(&wt->head_oid, DEFAULT_ABBREV));
		strbuf_addstr(&sb, junk_git_dir);
			die(_("cannot remove a locked working tree, lock reason: %s\nuse 'remove -f -f' to override or unlock first"),
		die(_("target '%s' already exists"), dst.buf);
	struct option options[] = {
	return 0;
			cp.argv = NULL;
	struct option options[] = {
				continue;
		usage_with_options(worktree_usage, options);
	int ret = 0;
		die_errno(_("could not create leading directories of '%s'"),
	}
				 oid_to_hex(&commit->object.oid), NULL);
	cp.out = -1;
	git_path_buf(&sb_repo, "worktrees/%s", name);
	}
				die(_("invalid reference: %s"), branch);
	}
				continue;
	close(fd);
		usage_with_options(worktree_usage, options);
	if (force < 2)
	while (mkdir(sb_repo.buf, 0777)) {
	junk_work_tree = xstrdup(path);
	struct strbuf sb_git = STRBUF_INIT, sb_repo = STRBUF_INIT;
		strbuf_addstr(&sb, junk_work_tree);
	if (ac < 1 || ac > 2)
		}
static void print_preparing_worktree_line(int detach,
		error_errno(_("failed to delete '%s'"), sb.buf);
	ac = parse_options(ac, av, prefix, options, worktree_usage, 0);
	int cur_path_len = strlen(wt->path);
		return list(ac - 1, av + 1, prefix);
		return remote;
	strbuf_reset(&sb);
	strbuf_add(&sb, name, path + len - name);
	is_junk = 1;
}
		    original_path);

	if (opts->checkout) {
	if (!is_junk || getpid() != junk_pid)
	struct worktree **worktrees, *wt;
		if (run_command(&cp))
{

	free(path);
	 * or is_git_directory() will reject the directory. Any value which
done:
		OPT_EXPIRY_DATE(0, "expire", &expire,
			if (!commit)
		else if (wt->head_ref)
		OPT__FORCE(&force,
			free(ref);


	raise(signo);
{

		argv_array_push(&cp.args, branch);
static void prune_worktrees(void)
					 oid_to_hex(&commit->object.oid),
	int ret = 0;
	return ret;
	if (!wt)
	}

	sigchain_push_common(remove_junk_on_signal);
	if (is_directory(worktree_git_path(wt, "modules"))) {
		if (!commit) {
			    id, strerror(errno));
		new_branch = new_branch_force;
		strbuf_trim_trailing_dir_sep(&dst);
					 "1", NULL);
	if (rename(wt->path, dst.buf) == -1)
{
			 N_("try to match the new branch name with a remote-tracking branch")),
		if (path_len > *maxlen)
/*
	if (ac)

	validate_no_submodules(wt);

	for (i = 0; wt[i]; i++) {
			    reason);

			   N_("create a new branch")),
		if (ret)
			*maxlen = path_len;
	return 0;
	if (read_result < 0) {
		strbuf_release(&s);
	cp.env = child_env.argv;

		if (opts.quiet)

		reason = worktree_lock_reason(wt);

{

		if (wt->is_detached)
	if (ret || !opts->keep_locked) {

	int ret;
	cp.git_cmd = 1;
	for (name = path + len - 1; name > path; name--)
		OPT__DRY_RUN(&show_only, N_("do not remove, show only")),
static int guess_remote;
	strbuf_release(&sb);
	ac = parse_options(ac, av, prefix, options, worktree_usage, 0);
	if (junk_git_dir) {
	int is_branch = 0;

			die(_("cannot move a locked working tree, lock reason: %s\nuse 'move -f -f' to override or unlock first"),
		return;
	UNLEAK(opts);
		OPT_STRING(0, "reason", &reason, N_("string"),
		strbuf_addf(reason, _("Removing worktrees/%s: gitdir file does not exist"), id);
		for (i = 0; i < istate.cache_nr; i++) {
			struct commit *commit = lookup_commit_reference_by_name(branch);
}
}
		strbuf_addf(&sb_repo, "%d", counter);
		return 1;
#include "checkout.h"
	if (remove_dir_recursively(&sb, 0)) {
	strbuf_release(&sb_git);
		cp.env = child_env.argv;
	strbuf_reset(&sb);
	char buf[1];
	if (ret)

		const char *sep = find_last_dir_sep(wt->path);
	ret = remove_dir_recursively(&sb, 0);
	if (new_branch_force) {
	update_worktree_location(wt, dst.buf);
		OPT_PASSTHRU(0, "track", &opt_track, NULL,
	usage_with_options(worktree_usage, options);
	len = xsize_t(st.st_size);
		strbuf_addf(reason,
	ret = xread(cp.out, buf, sizeof(buf));
	argv_array_pushf(&child_env, "%s=%s", GIT_WORK_TREE_ENVIRONMENT, path);
		struct object_id oid;
	if (!strcmp(av[1], "add"))
	if (force < 2)
	memset(&opts, 0, sizeof(opts));
	wt = find_worktree_by_path(worktrees, path);
done:

static int move_worktree(int ac, const char **av, const char *prefix)
}
};
		if (show_only || verbose)
			 GIT_WORK_TREE_ENVIRONMENT, wt->path);
	}
	 */
	if (wt->is_bare)
			die(_("'%s' is already locked, reason: %s"),
		}
	struct strbuf sb = STRBUF_INIT;

		OPT_BOOL(0, "lock", &opts.keep_locked, N_("keep the new working tree locked")),
				   get_worktree_git_dir(wt)) > 0) {
	}
		die(_("'%s' is a main working tree"), av[0]);
			argv_array_pushl(&cp.args, absolute_path(hook),
	read_result = read_in_full(fd, path, len);
		die(_("working trees containing submodules cannot be moved or removed"));
			die(_("could not figure out destination name from '%s'"),
		delete_worktrees_dir_if_empty();
	else
	if (ac < 2)

static int remove_worktree(int ac, const char **av, const char *prefix)
	if (old_reason) {
	if (!strcmp(av[1], "list"))
	argv_array_pushf(&child_env, "%s=%s/.git",
static void show_worktree_porcelain(struct worktree *wt)
	}
		remove_dir_recursively(&sb, 0);
	validate_no_submodules(wt);
		branch = new_branch;
	strbuf_release(&errmsg);
	strbuf_addf(&sb, "%s/locked", sb_repo.buf);
			  original_path);
	if (!is_directory(git_path("worktrees/%s", id))) {
		close(fd);
	N_("git worktree list [<options>]"),
	fd = open(git_path("worktrees/%s/gitdir", id), O_RDONLY);
			 PARSE_OPT_NOCOMPLETE),
			remote = unique_tracking_name(branch, &oid, NULL);
			continue;
	}
			check_clean_worktree(wt, av[0]);
			}

		strbuf_reset(&sb);
		}
	}

	int i;
	struct stat st;
	closedir(dir);
	strbuf_addf(&sb, "%s/HEAD", sb_repo.buf);
static timestamp_t expire;
	if (!is_branch)
	strbuf_release(&sb_name);
		write_file(sb.buf, "added with --lock");
}
	if (!opts->detach && !strbuf_check_branch_ref(&symref, refname) &&
		if (sha1_len > *abbrev)
	atexit(remove_junk);
	if (ac != 1)
	if ((!locked && opts->force) || (locked && opts->force > 1)) {
	}
		argv_array_clear(&cp.args);

#include "builtin.h"

			die_if_checked_out(symref.buf, 0);
	const char *name;
	strbuf_release(&sb);

	const char *s = worktree_basename(path, &n);
	strbuf_release(&sb_repo);
			int err;
		die(_("'%s' is already locked"), av[0]);
		strbuf_addf(reason, _("Removing worktrees/%s: unable to read gitdir file (%s)"),
	struct option options[] = {
			cp.env = env;
		die(_("The main working tree cannot be locked or unlocked"));
			   PARSE_OPT_NOCOMPLETE),
	} else if (read_index_from(&istate, worktree_git_path(wt, "index"),
			  sb_git.buf);
		OPT_END()

	if (ac != 1)
		strbuf_release(&symref);
	}
		usage_with_options(worktree_usage, options);
	int path_adj = cur_path_len - utf8_strwidth(wt->path);
	struct index_state istate = { NULL };

	 * Until we sort this out, all submodules are "dirty" and
		branch = "@{-1}";
		if ((errno != EEXIST) || !counter /* overflow */)

	struct dirent *d;
	worktrees = get_worktrees(0);
		if (hook) {
		guess_remote = git_config_bool(var, value);

		struct commit *commit = lookup_commit_reference_by_name(new_branch);
		found_submodules = 1;
		else if (wt->head_ref) {
	remove_junk();
	write_file(git_common_path("worktrees/%s/locked", wt->id),
	junk_git_dir = xstrdup(sb_repo.buf);
	}
static char *junk_work_tree;
	strbuf_addf(&sb, "%s/gitdir", sb_repo.buf);
		if (is_dot_or_dotdot(d->d_name))
{
		return prune(ac - 1, av + 1, prefix);
			goto done;
	*new_branch = branchname;
	sigchain_pop(signo);

	struct strbuf reason = STRBUF_INIT;
	write_file(sb.buf, "%s", realpath.buf);
	} else if (new_branch) {
	struct option options[] = {
{
	}
	char *path;
		if (!force)
	strbuf_release(&sb);

	struct strbuf symref = STRBUF_INIT;
					 oid_to_hex(&null_oid),
		struct strbuf symref = STRBUF_INIT;
		if (is_dir_sep(*name)) {
	if (!show_only)
		else {
		}
static void remove_junk_on_signal(int signo)
static int list(int ac, const char **av, const char *prefix)
	else {
static void delete_worktrees_dir_if_empty(void)
	if (ret)
		ret = -1;
	if (wt->is_bare)
		return add(ac - 1, av + 1, prefix);
		strbuf_addf(&sb, "%-*s ", abbrev_len,
			char *ref = shorten_unambiguous_ref(wt->head_ref, 0);
	struct strbuf sb = STRBUF_INIT;
		else
		printf_ln(_("Preparing worktree (new branch '%s')"), new_branch);
	int locked;
	return git_default_config(var, value, cb);
	strbuf_realpath(&realpath, sb_git.buf, 1);
		int path_maxlen = 0, abbrev = DEFAULT_ABBREV, i;
}
#include "argv-array.h"
			return 0;

	 * Hook failure does not warrant worktree deletion, so run hook after
 */
	if (is_main_worktree(wt))
	struct worktree **worktrees;
static int prune_worktree(const char *id, struct strbuf *reason)
	/*
		if (s)
		die(_("'%s' is a missing but locked worktree;\nuse 'add -f -f' to override, or 'unlock' and 'prune' or 'remove' to clear"), path);
	cp.git_cmd = 1;



	N_("git worktree unlock <path>"),
	const char *branch;
	argv_array_pushl(&cp.args, "status",
}
		prefix = "";

	if (!strcmp(av[1], "unlock"))
{
		die(_("'%s' already exists"), path);
	len = strlen(path);
	argv_array_clear(&child_env);
	if (!wt)
	};
#include "run-command.h"
	ret |= delete_git_dir(wt->id);
	if (!strcmp(branch, "-"))


	if (safe_create_leading_directories_const(sb_git.buf))
	};
			break;
	close(cp.out);
	 * continue on even if ret is non-zero, there's no going back
		/*
	}

	int ret;


		goto done;
{
		ret = run_command(&cp);
	 * after the preparation is over.
	int checkout;
	if (reason) {
	strbuf_addstr(&sb, wt->path);
				new_branch = branch;
			ret = run_command(&cp);


	    ref_exists(ref.buf)) {
		cp.git_cmd = 1;

	ret = run_command(&cp);
		strbuf_addf(reason, _("Removing worktrees/%s: invalid gitdir file"), id);
{
 * user, then it's ok to remove it.
		struct object_id oid;
	};
	/* is 'refname' a branch or commit? */
	expire = TIME_MAX;
	strbuf_release(&sb);
	printf("\n");
		    ref_exists(s.buf))
		argv_array_pushl(&cp.args, "update-ref", "HEAD",
	}
	free_worktrees(worktrees);
		is_branch = 1;
		if (!porcelain)
		cp.argv = NULL;
		return 1;
		free(path);
	return ret;
	strbuf_release(&symref);

		struct child_process cp = CHILD_PROCESS_INIT;
		die(_("validation failed, cannot move working tree: %s"),
	if (guess_remote) {
{
		if (!opts->force)
				show_worktree(worktrees[i], path_maxlen, abbrev);
		die(_("'%s' is not a working tree"), av[0]);
static int show_only;
	if (!wt)

{
		OPT_END()

	if (!opts->keep_locked)
	struct strbuf sb = STRBUF_INIT;
 * Note, "git status --porcelain" is used to determine if it's safe to
{
	struct strbuf dst = STRBUF_INIT;
		strbuf_addf(&sb, "%s/locked", sb_repo.buf);
	const char *reason = NULL;
 * (potentially bad) user settings and only delete a worktree when
	int porcelain = 0;
	if (!len) {
	int fd;
	struct strbuf ref = STRBUF_INIT;
	if (!wt)
			strbuf_reset(&path);
		} else {
struct add_opts {
}


			printf_ln(_("Preparing worktree (resetting branch '%s'; was at %s)"),
			  original_path, ret);
			strbuf_addstr(&sb, "(detached HEAD)");
		OPT_END()
	}
	sanitize_refname_component(sb.buf, &sb_name);
	if (!prefix)
	struct strbuf errmsg = STRBUF_INIT;
	ret = finish_command(&cp);
	prune_worktrees();
			argv_array_push(&cp.args, "--quiet");
		argv_array_pushl(&cp.args, "reset", "--hard", "--no-recurse-submodules", NULL);
			strbuf_addf(&path, "%s/%s", wt->path, ce->name);
			argv_array_push(&cp.args, "--quiet");
			if (!is_submodule_populated_gently(path.buf, &err))

		die(_("'%s' is not a working tree"), av[0]);
		return 0;
	if (!wt)
}
	const char *reason = "", *old_reason;

static int delete_git_dir(const char *id)
	 * is_junk is cleared, but do return appropriate code when hook fails.
	commit = lookup_commit_reference_by_name(refname);
	memset(&cp, 0, sizeof(cp));
	};
		ret = unlink(sb.buf);
	free_worktrees(worktrees);
		OPT_END()
	int len, ret;
		counter++;
	if (locked)
	struct commit *commit = NULL;
		printf("HEAD %s\n", oid_to_hex(&wt->head_oid));
	while (len && is_dir_sep(path[len - 1]))
		if (opts->quiet)
	const char *name;
	path = prefix_filename(prefix, av[0]);
		return move_worktree(ac - 1, av + 1, prefix);
		struct worktree **worktrees = get_worktrees(GWT_SORT_LINKED);
		if (*reason)
	worktrees = get_worktrees(0);
	if (ret)
}
	if (is_main_worktree(wt))
static int delete_git_work_tree(struct worktree *wt)
	wt = find_worktree(worktrees, prefix, av[0]);
	int force;
	FREE_AND_NULL(junk_work_tree);
static int git_worktree_config(const char *var, const char *value, void *cb)
	if (stat(git_path("worktrees/%s/gitdir", id), &st)) {
	if (!strcmp(av[1], "lock"))
	int quiet;
		const char *hook = find_hook("post-checkout");
{
		die(_("invalid reference: %s"), refname);
	path = xmallocz(len);
	int n;
	} else {
	ssize_t read_result;
	}
{

		reason = worktree_lock_reason(wt);
		return 1;
		   "%s", reason);
 * it's absolutely safe to do so from _our_ point of view because we
	while ((d = readdir(dir)) != NULL) {
			found_submodules = 1;
	unsigned int counter = 0;
				 const char *original_path)
	while (len && (path[len - 1] == '\n' || path[len - 1] == '\r'))

		argv_array_push(&cp.args, "branch");
	printf("worktree %s\n", wt->path);
	char *path;
{
	free_worktrees(worktrees);
	}
		strbuf_reset(&reason);
	path = prefix_filename(prefix, av[1]);



			 N_("force removal even if worktree is dirty or locked"),

 * configuration, so if a normal "git status" shows "clean" for the
	}
		}
static int verbose;
		    errmsg.buf);
		strbuf_addf(reason, _("Removing worktrees/%s: not a valid directory"), id);
	struct option options[] = {
}
#include "worktree.h"
		if (new_branch_force)
	validate_worktree_add(path, opts);
				show_worktree_porcelain(worktrees[i]);
	else {
			struct cache_entry *ce = istate.cache[i];
		    die(_("unable to re-add worktree '%s'"), path);
		 * this simpler check is probably good enough for now.
		if (!sep)
	strbuf_realpath(&realpath, get_git_common_dir(), 1);
	}

	if (!!opts.detach + !!new_branch + !!new_branch_force > 1)
	return ret;
		die_errno(_("failed to run 'git status' on '%s'"),
	int force = 0;
	 */
	ac = parse_options(ac, av, prefix, options, worktree_usage, 0);
			return -1;

		die(_("'%s' is a main working tree"), av[0]);
	junk_pid = getpid();
	}

			printf("branch %s\n", wt->head_ref);
{
			    _("Removing worktrees/%s: short read (expected %"PRIuMAX" bytes, read %"PRIuMAX")"),
		die(_("-b, -B, and --detach are mutually exclusive"));
	strbuf_reset(&sb);
	ac = parse_options(ac, av, prefix, options, worktree_usage, 0);
	strbuf_release(&sb);
		return 0;
	if (validate_worktree(wt, &errmsg, WT_VALIDATE_WORKTREE_MISSING_OK))
		free(path);
static const char *dwim_branch(const char *path, const char **new_branch)
	opts.checkout = 1;
#include "submodule.h"
static void check_clean_worktree(struct worktree *wt,
	wt = find_worktree(worktrees, prefix, av[0]);
	write_file(sb.buf, "../..");
	wt = find_worktree(worktrees, prefix, av[0]);
}

}
	}
		OPT_END()
		OPT__FORCE(&force,

		usage_with_options(worktree_usage, options);
static const char * const worktree_usage[] = {
	name = worktree_basename(path, &len);
		remove_dir_recursively(&sb, 0);
		struct commit *commit;
				 symref.buf, NULL);
		die(_("'%s' is not locked"), av[0]);
{
		const char *s = dwim_branch(path, &new_branch);
			if (porcelain)
			strbuf_addf(reason, _("Removing worktrees/%s: gitdir file points to non-existent location"), id);
#include "config.h"
	 * This is to keep resolve_ref() happy. We need a valid HEAD

		delete_git_dir(d->d_name);
	/*
		return unlock_worktree(ac - 1, av + 1, prefix);
	ac = parse_options(ac, av, prefix, options, worktree_usage, 0);
	return 0;
			 GIT_DIR_ENVIRONMENT, wt->path);
	delete_worktrees_dir_if_empty();
				  find_unique_abbrev(&commit->object.oid, DEFAULT_ABBREV));
		const char *remote;
		die(_("'%s' is a missing but already registered worktree;\nuse 'add -f' to override, or 'prune' or 'remove' to clear"), path);
}
	struct strbuf sb = STRBUF_INIT;
	struct strbuf sb = STRBUF_INIT, realpath = STRBUF_INIT;
		printf("bare\n");
		OPT_END()
}
	strbuf_release(&errmsg);
	const char *reason = NULL;
	struct option options[] = {
	if (!file_exists(path)) {
				  branch);
	 */
		OPT_BOOL(0, "detach", &opts.detach, N_("detach HEAD at named commit")),

		if (opt_track)
		int sha1_len;
	if (!strcmp(av[1], "prune"))

	git_config(git_worktree_config, NULL);
	strbuf_release(&dst);
	if (is_directory(dst.buf)) {
	struct worktree *wt;
		if (!detach && !strbuf_check_branch_ref(&s, branch) &&

	struct strbuf path = STRBUF_INIT;
		die(_("cannot remove a locked working tree;\nuse 'remove -f -f' to override or unlock first"));
	}

	}
	};

			 PARSE_OPT_NOCOMPLETE),
static int unlock_worktree(int ac, const char **av, const char *prefix)
		die(_("cannot move a locked working tree;\nuse 'move -f -f' to override or unlock first"));
{
		 */
};
static int add_worktree(const char *path, const char *refname,
	return 0;
	if (!ret && opts->checkout) {
		print_preparing_worktree_line(opts.detach, branch, new_branch, !!new_branch_force);
	const char *branchname = xstrndup(s, n);
	else {
}
	struct worktree **worktrees, *wt;
			measure_widths(worktrees, &abbrev, &path_maxlen);
{

	if (file_exists(path) && !is_empty_dir(path))
	if (!opts.quiet)
	ac = parse_options(ac, av, prefix, options, worktree_usage, 0);
			continue;

	if (!dir)
				N_("expire working trees older than <time>")),

	};
	worktrees = get_worktrees(0);
			strbuf_addf(&sb, "[%s]", ref);
		len--;
	if (!sb_name.len)
		OPT_END()
#include "parse-options.h"
	if (file_exists(git_path("worktrees/%s/locked", id)))
#include "cache.h"
					  int force_new_branch)
	if (ac == 2 && !new_branch && !opts.detach) {
{
static char *junk_git_dir;
 *
	if (reason) {

		die(_("The main working tree cannot be locked or unlocked"));
	if (ac != 2)
{
			const char *env[] = { "GIT_DIR", "GIT_WORK_TREE", NULL };

	if (!strcmp(var, "worktree.guessremote")) {
		commit = lookup_commit_reference_by_name(branch);
		OPT_END()
	return ret;
	if (!strbuf_check_branch_ref(&ref, branchname) &&

		if (delete_git_dir(wt->id))
		} else
		    errmsg.buf);
		return 1;
		BUG("How come '%s' becomes empty after sanitization?", sb.buf);
	N_("git worktree prune [<options>]"),
	path[len] = '\0';
	 * will abort this function.
	};
	write_file(sb_git.buf, "gitdir: %s/worktrees/%s",
	int ret;
	if (file_exists(wt->path)) {
	if (ac != 1)
			    wt->path);
		    st.st_mtime <= expire) {

			const struct add_opts *opts)
	const char *opt_track = NULL;
	strbuf_reset(&sb);
			printf_ln(_("Preparing worktree (detached HEAD %s)"),
	if (ret)
static const char *worktree_basename(const char *path, int *olen)
		if (!commit)
		return 1;
static int prune(int ac, const char **av, const char *prefix)
	return NULL;

		}
	ac = parse_options(ac, av, prefix, options, worktree_usage, 0);
	UNLEAK(branchname);
	ret = unlink_or_warn(git_common_path("worktrees/%s/locked", wt->id));
	    ref_exists(symref.buf)) {
		if (stat(git_path("worktrees/%s/index", id), &st) ||

			argv_array_push(&cp.args, "--quiet");
static void show_worktree(struct worktree *wt, int path_maxlen, int abbrev_len)

#include "dir.h"
{
	if (is_main_worktree(wt))
	UNLEAK(path);
			cp.git_cmd = 0;
		strbuf_release(&ref);
	strbuf_addstr(&dst, path);
			    id, strerror(errno));
	}
int cmd_worktree(int ac, const char **av, const char *prefix)
	if (read_result != len) {
		OPT__VERBOSE(&verbose, N_("report pruned working trees")),

	if (file_exists(dst.buf))
		OPT_BOOL(0, "checkout", &opts.checkout, N_("populate the new working tree")),
	DIR *dir = opendir(git_path("worktrees"));
	strbuf_release(&path);
	discard_index(&istate);
			     N_("set up tracking mode (see git-branch(1))"),
	argv_array_pushf(&child_env, "%s=%s",
	struct option options[] = {
	if (ac < 2 && !new_branch && !opts.detach) {
	}

	strbuf_release(&reason);
			else
		argv_array_pushl(&cp.args, "symbolic-ref", "HEAD",
	free_worktrees(worktrees);
	write_file(sb.buf, "%s", oid_to_hex(&null_oid));
	branch = ac < 2 ? "HEAD" : av[1];
	if (ret)
			cp.trace2_hook_name = "post-checkout";
			if (remote) {
}
			    id, (uintmax_t)len, (uintmax_t)read_result);

	 * looks like an object ID will do since it will be immediately
	 * worktree.
	int i, found_submodules = 0;

		 * There could be false positives, e.g. the "modules"
	*olen = len;
		if (!prune_worktree(d->d_name, &reason))
static void validate_no_submodules(const struct worktree *wt)
	 * lock the incomplete repo so prune won't delete it, unlock
		free_worktrees(worktrees);
}
		error_errno(_("failed to delete '%s'"), sb.buf);
		strbuf_addf(reason, _("Removing worktrees/%s: unable to read gitdir file (%s)"),
			return 1;
	if (ac)
	size_t len;
	strbuf_addf(&sb_git, "%s/.git", path);
			name++;



					  const char *branch,
	 * replaced by the symbolic-ref or update-ref invocation in the new
}
static void validate_worktree_add(const char *path, const struct add_opts *opts)
		usage_with_options(worktree_usage, options);
static void remove_junk(void)
		sha1_len = strlen(find_unique_abbrev(&wt[i]->head_oid, *abbrev));
		struct strbuf s = STRBUF_INIT;

		OPT_STRING('B', NULL, &new_branch_force, N_("branch"),
				  find_unique_abbrev(&commit->object.oid, DEFAULT_ABBREV));
	const char *new_branch = NULL;
	is_junk = 0;

	if (new_branch) {
		write_file(sb.buf, "initializing");
	int force = 0;
		if (*old_reason)
		die(_("'%s' contains modified or untracked files, use --force to delete it"),
			unique_tracking_name(*new_branch, &oid, NULL);
		if (wt->is_detached)
		OPT_STRING('b', NULL, &new_branch, N_("branch"),

	return 0;

	return name;
	free_worktrees(worktrees);
	strbuf_release(&realpath);
	/*
	cp.env = child_env.argv;
		strbuf_setlen(&sb_repo, len);
	FREE_AND_NULL(junk_git_dir);
	};
	struct argv_array child_env = ARGV_ARRAY_INIT;
}
	strbuf_addf(&sb, "%-*s ", 1 + path_maxlen + path_adj, wt->path);

	locked = !!worktree_lock_reason(wt);
	}
		if (!opts.force &&
{
			break;
				branch = remote;
	}
		usage_with_options(worktree_usage, options);
	}
			    reason);

		   realpath.buf, name);
			die_if_checked_out(symref.buf, 0);
		free(path);
#include "sigchain.h"
		len--;
		if (show_only)
		strbuf_reset(&sb);
	name = strrchr(sb_repo.buf, '/') + 1;
	else {
	argv_array_pushf(&child_env, "%s=%s", GIT_DIR_ENVIRONMENT, sb_git.buf);
		OPT_BOOL(0, "guess-remote", &guess_remote,


		die_errno(_("could not create leading directories of '%s'"),
		die_errno(_("failed to run 'git status' on '%s', code %d"),
	name = sb_name.buf;
	struct worktree **worktrees, *wt;

}

		OPT__QUIET(&opts.quiet, N_("suppress progress reporting")),
	struct strbuf sb_name = STRBUF_INIT;
	int len;
	struct add_opts opts;
	 */

		strbuf_addstr(&sb, "(bare)");
	strbuf_addf(&sb, "%s/commondir", sb_repo.buf);
	strbuf_addstr(&sb, git_common_path("worktrees/%s", id));
			argv_array_push(&cp.args, opt_track);
		}
	len = sb_repo.len;
		die(_("--[no-]track can only be used if a new branch is created"));

	if (validate_worktree(wt, &errmsg, 0))
			   N_("reason for locking")),
		return remove_worktree(ac - 1, av + 1, prefix);
			argv_array_push(&cp.args, "--force");
		OPT_BOOL(0, "porcelain", &porcelain, N_("machine-readable output")),
	struct strbuf errmsg = STRBUF_INIT;
	}
			printf("%s\n", reason.buf);
static int is_junk;
static int add(int ac, const char **av, const char *prefix)
	if (junk_work_tree) {
			printf_ln(_("Preparing worktree (checking out '%s')"),
		argv_array_push(&cp.args, new_branch);
 * know better.

			strbuf_addstr(&sb, "(error)");
	if (is_main_worktree(wt))

		ret |= delete_git_work_tree(wt);
	ret = start_command(&cp);
	if (fd < 0) {
	}

{
	int keep_locked;
		for (i = 0; worktrees[i]; i++) {
{
	struct child_process cp = CHILD_PROCESS_INIT;



	}
	if (found_submodules)

			printf_ln(_("Preparing worktree (new branch '%s')"), new_branch);
	} else if (opt_track) {
static void measure_widths(struct worktree **wt, int *abbrev, int *maxlen)
	N_("git worktree remove [<options>] <worktree>"),
	struct argv_array child_env = ARGV_ARRAY_INIT;
	else
			 "--porcelain", "--ignore-submodules=none",
			 NULL);
			cp.dir = path;
		goto done;
}

}
				  new_branch,

			   N_("create or reset a branch")),
	rmdir(git_path("worktrees")); /* ignore failed removal */
}
			  sb_repo.buf);
			 N_("force move even if worktree is dirty or locked"),
	/*
	const char *new_branch_force = NULL;
static int lock_worktree(int ac, const char **av, const char *prefix)
	}
		return branchname;
	worktrees = get_worktrees(0);
	struct child_process cp;
		OPT__FORCE(&opts.force,
	N_("git worktree add [<options>] <path> [<commit-ish>]"),
	if (!strcmp(av[1], "move"))
#include "utf8.h"
	 * from here.
	wt = find_worktree(worktrees, prefix, av[0]);
	if (force_new_branch) {
	if (safe_create_leading_directories_const(sb_repo.buf))
		    !strbuf_check_branch_ref(&symref, new_branch) &&
	char *path;
		unlink_or_warn(sb.buf);
 * This assumption may be a bad one. We may want to ignore
		strbuf_addstr(&dst, sep);
		    ref_exists(symref.buf))
		return;
	if (!strcmp(av[1], "remove"))
}
	free(path);
	int detach;

			if (!S_ISGITLINK(ce->ce_mode))
					  const char *new_branch,
		if (opts->quiet)
	NULL
	struct option options[] = {
	struct worktree **worktrees, *wt;
	old_reason = worktree_lock_reason(wt);
		const char *remote =
 * delete a whole worktree. "git status" does not ignore user
			branch = s;
