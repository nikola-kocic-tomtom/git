	struct parse_opt_ctx_t ctx;
	default:
			N_("let files replace directories and vice-versa"), 1),
	path = get_mtime_path(path);
	if (mark_skip_worktree_only) {
			PARSE_OPT_NOARG | PARSE_OPT_NONEG,
	struct repository *r = the_repository;
}
	if (add_cache_entry(ce_2, ADD_CACHE_OK_TO_ADD)) {
	report("chmod %cx '%s'", flip, path);
	int newfd, entries, has_errors = 0, nul_term_line = 0;
			PARSE_OPT_NOARG | PARSE_OPT_NONEG, NULL, UNMARK_FLAG},
		OPT_SET_INT(0, "force-write-index", &force_write,
	int pos;
		fprintf(stderr, "Not in the middle of a merge.\n");
			N_("refresh: ignore submodules"),
	/*
		{OPTION_LOWLEVEL_CALLBACK, 0, "cacheinfo", NULL,
		}
		struct cache_entry *old = NULL;
 * Default to not allowing changes to the list of files. The
		if (!ignore_skip_worktree_entries && allow_remove &&
			if (refresh_args.flags & REFRESH_QUIET)
			discard_cache_entry(old);

				     struct object_id *oid,
			PARSE_OPT_NOARG | PARSE_OPT_NONEG, NULL, MARK_FLAG},
		if (parseopt_state != PARSE_OPT_DONE)
	return 0;
		unsigned int mode;
	ce_2 = read_one_ent("our", &head_oid, path, namelen, 2);
		if (!ctx.argc)
			ptr = tab + 1; /* point at the head of path */
		close(fd);
		goto done;
}
		 * so updating it does not make sense.

	parse_options_start(&ctx, argc, argv, prefix,
	int ret = 0;
	}
#define USE_THE_INDEX_COMPATIBILITY_MACROS

		if (preferred_index_format < INDEX_FORMAT_LB ||
	 */
 *  - missing file (ENOENT or ENOTDIR). That's ok if we're
 */
	} /* else stat is valid */
		 * index file and matches "git ls-files --stage" output.
#define MARK_FLAG 1
		strbuf_release(&unquoted);
			warning(_("core.splitIndex is set to false; "
		case PARSE_OPT_COMPLETE:
{
	}
}
		discard_cache_entry(ce);
		fprintf_ln(stderr,_("directory stat info does not "
		err |= unresolve_one(p);
#include "builtin.h"


	len = strlen(path);
}
			warning(_("core.splitIndex is set to true; "
		return NULL;
{
		/* Subdirectory match - error out */
				     "after adding a new directory"));
		OPT_SET_INT(0, "test-untracked-cache", &untracked_cache,
	fputc('.', stderr);
		{OPTION_LOWLEVEL_CALLBACK, 0, "stdin", &read_from_stdin, NULL,
	if (!match_stat_data(&base, &st)) {
{
 * tool doesn't actually care, but this makes it harder to add
			exit(0);
	/* Exact match: file or existing gitlink */
	char *cwd;
			warning(_("core.fsmonitor is set; "
/*
		 * into the index file.
		       info_only ? 0 : HASH_WRITE_OBJECT)) {
			NULL, 0, reupdate_callback},
static const char *get_mtime_path(const char *path)

	if (!verify_path(path, mode))

	int namelen = strlen(path);
		/* If there isn't, either it is unmerged, or
	 */
			die("git update-index: --cacheinfo cannot add %s", path);
		if (pos < active_nr) {
			N_("clear assumed-unchanged bit"),
		if (tab[-2] == ' ' && '0' <= tab[-1] && tab[-1] <= '3') {
{
	remove_file_from_cache(path);
			    !memcmp(ce->name, path, namelen))

	ce->ce_flags = create_ce_flags(0);
	struct lock_file lock_file = LOCK_INIT;
static int add_one_path(const struct cache_entry *old, const char *path, int len, struct stat *st)
		free(p);
	if (is_missing_file_error(err))
			N_("repopulate stages #2 and #3 for the listed paths"),
		case PARSE_OPT_NON_OPTION:
 */
static int do_unresolve(int ac, const char **av,

			/* mode ' ' sha1 '\t' name
	resolve_undo_clear();
		/* This reads lines formatted in one of three formats:
				chmod_path(set_executable_bit, p);
	}
		discard_cache_entry(ce);

			}
			if (set_executable_bit)
	endp++;
	atexit(remove_test_directory);
	 */
		st.st_mode = 0;
		return;
			goto bad_line;

	const char *p;
		}
				if (unquote_c_style(&unquoted, buf.buf, NULL))
	const char *arg, int unset)
		if (mark)
		 * (3) mode         SP sha1 SP stage TAB path
	parse_pathspec(&pathspec, 0,
	struct parse_opt_ctx_t *ctx, const struct option *opt,

	read_index_info(*nul_term_line);
			N_("write out the index even if is not flagged as changed"), 1),
		case PARSE_OPT_UNKNOWN:
 *
#include "fsmonitor.h"
	BUG_ON_OPT_ARG(arg);
	int pos;
	BUG_ON_OPT_NEG(unset);
		{OPTION_SET_INT, 0, "no-fsmonitor-valid", &mark_fsmonitor_only, NULL,

}
		{OPTION_CALLBACK, 0, "really-refresh", &refresh_args, NULL,
		if (ce->name[len] > '/')
	ret = 1;
	strbuf_release(&mtime_dir);
	strbuf_reset(&sb);
	git_config(git_default_config, NULL);
		char *p = prefix_path(prefix, prefix_length, arg);
			the_index.cache_changed |= SPLIT_INDEX_ORDERED;

	close(fd);
		return error("option '%s' must be the last argument", opt->long_name);
				return 0;
static int refresh_callback(const struct option *opt,
	if (active_cache_changed || force_write) {
	ctx->argv += ctx->argc - 1;
			tab[-(hexsz + 1)] != ' ')
{
	entries = read_cache();
	if (0 <= pos) {
			PARSE_OPT_NOARG | PARSE_OPT_NONEG,

	argc = parse_options_end(&ctx);

	if (ce && ce_skip_worktree(ce)) {
			PARSE_OPT_NONEG,
{
	    mark_fsmonitor_only)
	ce_3 = read_one_ent("their", &merge_head_oid, path, namelen, 3);
#define UNMARK_FLAG 2

	if (get_tree_entry(the_repository, ent, path, &oid, &mode)) {
				const char *arg, int unset)

	if (index_path(&the_index, &ce->oid, path, st,
			if (add_cacheinfo(mode, &oid, path_name, stage))

	struct stat st;
	discard_cache_entry(ce_2);
		OPT_BOOL(0, "split-index", &split_index,
	const char *arg, int unset)


		OPT_BIT('q', NULL, &refresh_args.flags,
		int save_nr;
			    options, PARSE_OPT_STOP_AT_NON_OPTION);
		 * or worse yet 'allow_replace', active_nr may decrease.
		strbuf_release(&buf);
 *  - it's already a gitlink in the index, and we keep it that
		return -1; /* not a new-style cacheinfo */
				    path_name);
	allow_add = allow_replace = allow_remove = 1;
				const char *arg, int unset)
{
			N_("notice files missing from worktree"), 1),
			if (ce_stage(ce) &&
		remove_fsmonitor(&the_index);
	avoid_racy();
		close(fd);

				die("git update-index: unable to update %s",
	if (ctx->argc <= 3)
			 N_("with --stdin: input lines are terminated by null bytes")),
	if (mark_valid_only) {
	if (mkdir(path, 0700))

		return 0;
	struct cache_entry *ce;
	return refresh(opt->value, REFRESH_REALLY);
	ret = -1;

		pos = unmerge_cache_entry_at(pos);
			old = read_one_ent(NULL, &head_oid,
		goto fail;
				goto free_return;
			 * ptr[-41] is at the beginning of sha1
	fprintf_ln(stderr, _(" OK"));

	if (rmdir(path))
					die("line is badly quoted");
	BUG_ON_OPT_ARG(arg);
		fputc('\n', stderr);

{
	ce->ce_namelen = len;
		if (the_index.split_index)
	for (pos = 0; pos < active_nr; pos++) {
			chmod_callback},
	xstat_mtime_dir(&st);
		}
			die("index-version %d not in range: %d..%d",
		else

	 * filename arguments as they come.

	if (fsmonitor > 0) {
	struct stat st;
	option = allow_add ? ADD_CACHE_OK_TO_ADD : 0;
			setup_work_tree();
		{OPTION_LOWLEVEL_CALLBACK, 0, "index-info", &nul_term_line, NULL,
		       prefix, av + 1);
	if (assume_unchanged)
				  "remove or change it, if you really want to "
				    "change after adding a new file"));

	report("add '%s'", path);
		goto free_return;
	struct parse_opt_ctx_t *ctx, const struct option *opt,
		if (r->settings.core_untracked_cache == UNTRACKED_CACHE_REMOVE)
		}
static int mark_ce_flags(const char *path, int flag, int mark)
				strbuf_swap(&buf, &unquoted);
		free(path);
	return error("%s: is a directory - add files inside instead", path);
			die("git update-index: unable to remove %s", path);

	if (!add_cache_entry(ce_3, ADD_CACHE_OK_TO_ADD))
		 */
			PARSE_OPT_NOARG | PARSE_OPT_NONEG, NULL, UNMARK_FLAG},
 *    (NOTE! This is old and arguably fairly strange behaviour.
	putchar('\n');
		cache_tree_invalidate_path(&the_index, path);
		if (!verify_path(path_name, mode)) {
			PARSE_OPT_NONEG | PARSE_OPT_NOARG,

	BUG_ON_OPT_NEG(unset);

		goto done;
		fprintf_ln(stderr, _("directory stat info does not "
#include "config.h"
 *    to try to update it as a directory.
	int preferred_index_format = 0;


		if (git_config_get_fsmonitor() == 1)
				  "disable split index"));
	}
		if (git_config_get_split_index() == 0)
			     path);
#include "cache.h"

		}
 *    exist as such any more. If removal isn't allowed, it's
 *    git directory, and it should be *added* as a gitlink.
				     unsigned int *mode,
			fprintf(stderr, "Ignoring path %s\n", path_name);
 *    removed as a file if removal is allowed, since it doesn't
	BUG_ON_OPT_NEG(unset);
		char *ptr, *tab;
			 * ptr[-1] points at tab,
			return add_one_path(ce, path, len, st);
		if (ce->name[len] < '/')
	len = strlen(path);
				"disable fsmonitor"));
	int has_head = 1;
	struct cache_entry *ce;
			/* mode == 0 means there is no such path -- remove */
	ctx->argc -= 3;
}
			 N_("do not touch index-only entries")),
				     "change after deleting a directory"));
	}
static int resolve_undo_clear_callback(const struct option *opt,
	int i;
	strbuf_release(&buf);
		if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK))
 *    succeeds.
		return -1;
	error("%s: cannot add their version to the index.", path);
		remove_dir_recursively(&mtime_dir, 0);
		 * back on 3-way merge.
	if (read_ref("HEAD", &head_oid))
	}
 * files be revision controlled.

 *
		/* Be careful.  The working tree may not have the
	/* Read HEAD and MERGE_HEAD; if MERGE_HEAD does not exist, we
	avoid_racy();
	rollback_lock_file(&lock_file);
		error("%s: cannot add our version to the index.", path);
	int *read_from_stdin = opt->value;
	int force_write = 0;

	if (old && !ce_stage(old) && !ce_match_stat(old, st, 0))
	struct refresh_params refresh_args = {0, &has_errors};
		mode = ul;
	}
		return NULL;
		tab = strchr(ptr, '\t');
		return -1;
	struct object_id oid;
	setup_work_tree();
	unsigned short mode;
	avoid_racy();
static void report(const char *fmt, ...)
	fputc('.', stderr);
		 * resolved as "removed" by mistake.  We do not
			unable_to_lock_die(get_index_file(), lock_error);
		const char *arg = av[i];
		}
			parseopt_state = parse_options_step(&ctx, options,
	const char *arg, int unset)
			error("%s: not in %s branch.", path, which);
static int force_remove;
		 * reports, and used to reconstruct a partial tree
	case UC_ENABLE:
		if (get_oid_hex(tab - hexsz, &oid) ||

		OPT_SET_INT(0, "remove", &allow_remove,
			tab = tab - 2; /* point at tail of sha1 */
		ctx->argv++;
		stat_errno = errno;
	 * First things first: get the stat information, to decide
{
	avoid_racy();
	struct strbuf buf = STRBUF_INIT;
		if (remove_file_from_cache(path))
	struct option options[] = {
		return;
	}
				     "change after deleting a file"));
			}
static int ignore_skip_worktree_entries;
	}
	if (newfd < 0)
/*
		return -1;
struct refresh_params {
	int pos, len;
	/* Error out. */
	if (fd < 0)
	discard_cache_entry(ce_3);
		report(_("fsmonitor enabled"));

	    get_oid_hex(*++ctx->argv, &oid) ||
#include "resolve-undo.h"
	if (pos < 0)
{
		if (old && ce->ce_mode == old->ce_mode &&

		{OPTION_SET_INT, 0, "skip-worktree", &mark_skip_worktree_only, NULL,
		return;
	return sb.buf;
	return has_errors ? 1 : 0;

	int read_from_stdin = 0;
 *    we're going to keep it unchanged in the index!)
	struct strbuf uq = STRBUF_INIT;
	getline_fn = nul_term_line ? strbuf_getline_nul : strbuf_getline_lf;
	ctx->argv += ctx->argc - 1;
	/*
		OPT_SET_INT(0, "info-only", &info_only,
		const struct cache_entry *ce = active_cache[pos++];
	fill_stat_data(&base, &st);
	 * what to do about the pathname!
		if (the_index.version != preferred_index_format)

			PARSE_OPT_NOARG | PARSE_OPT_NONEG, NULL, MARK_FLAG},

		if (!nul_term_line && path_name[0] == '"') {
	fd = create_file("newfile");
}
		return remove_one_path(path);
				chmod_path(set_executable_bit, p);
	case UC_UNSPECIFIED:
 *    an error.
			die("Unable to mark file %s", path);
	}
		/*

			path);

			N_("mark files as \"index-only\""),
		die("git update-index: --cacheinfo cannot add %s", *ctx->argv);
 * GIT - The information manager from hell
	}
	if (oideq(&ce_2->oid, &ce_3->oid) &&
	return 0;
	memcpy(ce->name, path, namelen);

		{OPTION_CALLBACK, 0, "refresh", &refresh_args, NULL,
		break;
				die("git update-index: bad quoting of path name");
		return !test_if_untracked_cache_is_supported();
			stage = tab[-1] - '0';
		BUG("bad untracked_cache value: %d", untracked_cache);
	va_end(vp);
 redo:
		case PARSE_OPT_ERROR:
int cmd_update_index(int argc, const char **argv, const char *prefix)
				    ptr);
		goto free_return;
		OPT_BOOL(0, "ignore-skip-worktree-entries", &ignore_skip_worktree_entries,
	if (!mkdtemp(mtime_dir.buf))
			N_("report actions to standard output"), 1),
}
			N_("mark files as fsmonitor valid"),
	if (process_path(path, &st, stat_errno))

		while (getline_fn(&buf, stdin) != EOF) {
				const char *arg, int unset)
	switch (untracked_cache) {
			N_("override the executable bit of the listed files"),


	avoid_racy();
}
		return process_directory(path, len, st);
	int *has_errors = opt->value;
		setup_work_tree();

	struct parse_opt_ctx_t *ctx, const struct option *opt,

	ul = strtoul(arg, &endp, 8);
		if (ptr == buf.buf || *ptr != ' '
			if (ce_namelen(ce) == namelen &&
		{OPTION_LOWLEVEL_CALLBACK, 'g', "again", &has_errors, NULL,
	const char *arg, int unset)
		{OPTION_SET_INT, 0, "no-assume-unchanged", &mark_valid_only, NULL,
	struct object_id oid;
	return 0;
			N_("enable or disable split index")),
{
static int parse_new_style_cacheinfo(const char *arg,
			 const char *path, int stage)
/*
	report("add '%s'", path);
 * like "git update-index *" and suddenly having all the object
		has_head = 0;
{
		mark_fsmonitor_invalid(&the_index, active_cache[pos]);
	const char *path;
	/* consume remaining arguments. */
		break;
			N_("ignore files missing from worktree"),
	if (!verbose)
	int len, option;
	if (!resolve_gitlink_ref(path, "HEAD", &oid))
		{OPTION_SET_INT, 0, "fsmonitor-valid", &mark_fsmonitor_only, NULL,
	/* No match - should we add it as a gitlink? */
	return err;

		}
	ce->ce_namelen = namelen;
			PARSE_OPT_NOARG | /* disallow --cacheinfo=<mode> form */
{


	ce->ce_flags = create_ce_flags(stage);
{

	if (strtoul_ui(*++ctx->argv, 8, &mode) ||
static int process_directory(const char *path, int len, struct stat *st)

			N_("add the specified entry to the index"),
 * Handle a path that couldn't be lstat'ed. It's either:
	read_cache();
}
		}
				     const char **path)
	cwd = xgetcwd();
			usage_with_options(update_index_usage, options);
	va_start(vp, fmt);
static int allow_remove;
}
		ul = strtoul(buf.buf, &ptr, 8);
static void xrmdir(const char *path)

	xstat_mtime_dir(&st);
		fprintf(stderr, "%s: identical in both, skipping.\n",
	newfd = hold_locked_index(&lock_file, 0);
	char *flip = opt->value;

			N_("refresh stat information"),
	if (mark_fsmonitor_only) {
	}
			PARSE_OPT_NONEG | PARSE_OPT_NOARG,
			warning(_("core.fsmonitor is unset; "
			goto redo;

	if (rmdir(mtime_dir.buf))
		return error("option '%s' must be the last argument", opt->long_name);
	int pos = cache_name_pos(path, len);
		 * (2) mode SP type SP sha1          TAB path
	fputc('.', stderr);
	 * Custom copy of parse_options() because we want to handle
				strbuf_reset(&unquoted);
		    || errno || (unsigned int) ul != ul)
static int verbose;

		active_cache[pos]->ce_flags |= CE_UPDATE_IN_BASE;
	int prefix_length = prefix ? strlen(prefix) : 0;
			N_("do not ignore new files"), 1),
	return 0;

			if (ctx.argv[0][1] == '-')
		OPT_SET_INT(0, "verbose", &verbose,
	struct stat_data base;
	path = get_mtime_path(path);
			PARSE_OPT_NOARG | PARSE_OPT_NONEG, NULL, MARK_FLAG},
			NULL, 0, stdin_callback},
		break;
				  "remove or change it, if you really want to "
		return 0;
};
	struct parse_opt_ctx_t *ctx, const struct option *opt,
	UC_TEST,
		lock_error = errno;
		fprintf_ln(stderr, _("directory stat info does not "
	    add_cacheinfo(mode, &oid, *++ctx->argv, 0))
				const char *arg, int unset)
{
			die("Unable to write new index file");
		return error("Invalid path '%s'", path);
{
static int test_if_untracked_cache_is_supported(void)
{
};
	if (ctx->argc != 1)
		ret = -1;
	    ce_2->ce_mode == ce_3->ce_mode) {
		goto fail;
	fill_stat_data(&base, &st);
		goto done;
			NULL, 0,
	fputc('.', stderr);
	errno = 0;
		goto free_return;


 *
		OPT_BOOL('z', NULL, &nul_term_line,
	if (!verify_path(path, st.st_mode)) {
				"enable fsmonitor"));

	} else {
		return add_one_path(NULL, path, len, st);
			REFRESH_UNMERGED),
static int info_only;

 *    We might want to make this an error unconditionally, and

	*has_errors = do_unresolve(ctx->argc, ctx->argv,
			    N_("enable untracked cache without testing the filesystem"), UC_FORCE),
	if (!match_stat_data(&base, &st)) {
		if (save_nr != active_nr)
		/* If there is no HEAD, that means it is an initial
		fprintf(stderr, "Ignoring path %s\n", path);
		if (mark_ce_flags(path, CE_SKIP_WORKTREE, mark_skip_worktree_only == MARK_FLAG))
	if (!allow_remove)
		report(_("Untracked cache enabled for '%s'"), get_git_work_tree());
	case UC_TEST:
	return 0;
	}
static int create_file(const char *path)
		return process_lstat_error(path, stat_errno);
				error("unknown option '%s'", ctx.argv[0] + 2);
			if (remove_file_from_cache(path_name))
	if (chmod_cache_entry(ce, flip) < 0)

		case PARSE_OPT_DONE:
				  "disable the untracked cache"));
}
{
	return 0;
		return;
}
	xunlink("newfile");
	return 0;
			strbuf_reset(&uq);

static enum parse_opt_result reupdate_callback(
		switch (parseopt_state) {
	ce->ce_mode = create_ce_mode(mode);
			NULL, 0, stdin_cacheinfo_callback},
			update_one(p);
	BUG_ON_OPT_ARG(arg);
{
	*mode = ul;
		if (add_cacheinfo(mode, &oid, path, 0))
	/*
 */
	ctx->argc = 1;
				  "remove or change it, if you really want to "
	struct parse_opt_ctx_t *ctx, const struct option *opt,
			}
		goto done;
			warning(_("core.untrackedCache is set to false; "
			if (resolve_gitlink_ref(path, "HEAD", &oid) < 0)
{
	 * not use if we could usleep(10) if USE_NSEC is defined. The

	/* Read HEAD and run update-index on paths that are
	setup_work_tree();
	 * stuff HEAD version in stage #2,
		 *

		else {
			N_("(for porcelains) forget saved unresolved conflicts"),
			    !memcmp(ce->name, path, namelen)) {
	struct object_id oid;
	int stat_errno = 0;

		die_errno(_("failed to create directory %s"), path);
		if (pos < active_nr) {
	BUG_ON_OPT_NEG(unset);
static int xstat_mtime_dir(struct stat *st)
		 * (1) mode         SP sha1          TAB path
 *    supposed to be removing it and the removal actually
		if (git_config_get_fsmonitor() == 0)
	free(cwd);
			die("Unable to mark file %s", path);

	if (mark_valid_only || mark_skip_worktree_only || force_remove ||
	if (pos >= 0) {
}

 fail:
			N_("add entries from standard input to the index"),
	int fd;
	}
	path = get_mtime_path(path);
}
	int *nul_term_line = opt->value;
	}

	int pos = cache_name_pos(path, namelen);
	ctx->argc = 1;
{
		struct strbuf buf = STRBUF_INIT;

	return fd;
{
			if (set_executable_bit)
			const char *path = ctx.argv[0];
	}
	UC_FORCE
		the_index.version = preferred_index_format;
	ce->ce_mode = create_ce_mode(mode);
		 * commit.  Update everything in the index.
{
		exit(0);
		update_one(path);
	ce = make_empty_cache_entry(&the_index, namelen);
			ptr[-(hexsz + 2)] = ptr[-1] = 0;
		report(_("Untracked cache disabled"));
		remove_untracked_cache(&the_index);
		OPT_BIT(0, "unmerged", &refresh_args.flags,

				exit(128);
static struct object_id merge_head_oid;
				prefix, prefix ? strlen(prefix) : 0);
	}
	}
	BUG_ON_OPT_NEG(unset);
	 */

	strbuf_getline_fn getline_fn;
		/* Should this be an unconditional error? */
	while (getline_fn(&buf, stdin) != EOF) {
	pos = cache_name_pos(path, len);
}
	*read_from_stdin = 1;
		OPT_END()
 * Copyright (C) Linus Torvalds, 2005
	else if (lstat(path, &st) < 0) {
	}
			char *p;
	 */
static enum parse_opt_result stdin_cacheinfo_callback(
			N_("like --refresh, but ignore assume-unchanged setting"),
static int process_path(const char *path, struct stat *st, int stat_errno)
	xunlink("new-dir/new");
	if (mode == S_IFDIR) {
#include "quote.h"
		die_errno(_("failed to stat %s"), mtime_dir.buf);
			const struct cache_entry *ce = active_cache[pos];
	xrmdir("new-dir");

static enum parse_opt_result cacheinfo_callback(
	if (S_ISDIR(st->st_mode))
		{OPTION_LOWLEVEL_CALLBACK, 0, "unresolve", &has_errors, NULL,
			const char *prefix, int prefix_length)
static struct cache_entry *read_one_ent(const char *which,
	/* Inexact match: is there perhaps a subdirectory match? */
	 * are not doing a merge, so exit with success status.
	/* Grab blobs from given path from HEAD and MERGE_HEAD,
	int *has_errors;
		discard_cache_entry(old);
		struct object_id oid;
	case UC_FORCE:
	*has_errors = do_reupdate(ctx->argc, ctx->argv, prefix);
		char *path;
	struct cache_entry *ce_2 = NULL, *ce_3 = NULL;

	struct pathspec pathspec;
	BUG_ON_OPT_NEG(unset);
	fprintf(stderr, _("Testing mtime in '%s' "), cwd);
	if ((arg[0] != '-' && arg[0] != '+') || arg[1] != 'x' || arg[2])
		OPT_BIT(0, "ignore-missing", &refresh_args.flags,
	pos = cache_name_pos(path, strlen(path));
 free_return:
		 * path anymore, in which case, under 'allow_remove',
		/* already merged */
	the_index.updated_skipworktree = 1;


}
	}
	int fsmonitor = -1;



	BUG_ON_OPT_ARG(arg);
	int split_index = -1;
	strbuf_release(&uq);
			exit(129);
	int *has_errors = opt->value;
	xstat_mtime_dir(&st);
	if (add_cache_entry(ce, option))
			break;
{
/* Untracked cache mode */

	die("git update-index: cannot chmod %cx '%s'", flip, path);

static void xmkdir(const char *path)
static int mark_fsmonitor_only;

	clear_pathspec(&pathspec);
		fprintf_ln(stderr, _("directory stat info changes "
 *  - it doesn't exist at all in the index, but it is a valid
	/* consume remaining arguments. */
	BUG_ON_OPT_ARG(arg);
		}
 *    way, and update it if we can (if we cannot find the HEAD,
	if (add_cache_entry(ce, option)) {
	struct cache_entry *ce;
		die_errno(_("failed to delete directory %s"), mtime_dir.buf);
 *
	if (ctx->argc != 1)
			/* Do nothing to the index if there is no HEAD! */
static struct object_id head_oid;
	avoid_racy();
		if (strncmp(ce->name, path, len))

		    remove_file_from_cache(path))
static int chmod_callback(const struct option *opt,
	xstat_mtime_dir(&st);
	return 0;
}
		die_errno(_("failed to delete file %s"), path);
			refresh_callback},
			N_("clear skip-worktree bit"),
static const char * const update_index_usage[] = {
	return 0;

		 * The first format is what "git apply --index-info"
	write_or_die(fd, "data", 4);
			p = prefix_path(prefix, prefix_length, buf.buf);
		return error("%s: cannot add to the index - missing --add option?", path);
	UC_UNSPECIFIED = -1,
{
	/* See if there is such entry in the index. */
		if (newfd < 0) {
		OPT_SET_INT(0, "replace", &allow_replace,
		if (ce_stage(ce) || !ce_path_match(&the_index, ce, &pathspec, NULL))
			N_("continue refresh even when index needs update"),
	strbuf_getline_fn getline_fn;
			error("%s: not a blob in %s branch.", path, which);
	if (!match_stat_data(&base, &st)) {
	 */
		/* no resolve-undo information; fall back */
							    update_index_usage);
					   ce->name, ce_namelen(ce), 0);
		return error("%s: is a directory - add individual files instead", path);
		die("malformed index info %s", buf.buf);
}
	fill_stat_cache_info(&the_index, ce, st);
	}
			PARSE_OPT_NONEG | PARSE_OPT_LITERAL_ARGHELP,
			break;
#include "dir.h"
}
	if (*has_errors)

	*path = p + 1;
				"set it if you really want to "
				  "enable the untracked cache"));
static int add_cacheinfo(unsigned int mode, const struct object_id *oid,
	 * merged and already different between index and HEAD.
		path_name = ptr;
			die("Unable to mark file %s", path);

	N_("git update-index [<options>] [--] [<file>...]"),
			    N_("test if the filesystem supports untracked cache"), UC_TEST),
			N_("write index in this format")),
			PARSE_OPT_NONEG | PARSE_OPT_NOARG,
#include "lockfile.h"
		OPT_SET_INT(0, "force-untracked-cache", &untracked_cache,
}

			if (unquote_c_style(&uq, path_name, NULL)) {

static void avoid_racy(void)
			break;
	 * stuff MERGE_HEAD version in stage #3.
				  "remove or change it, if you really want to "
	BUG_ON_OPT_NEG(unset);

		ctx->argc--;
			PARSE_OPT_NOARG | PARSE_OPT_NONEG,
		die("No HEAD -- no initial commit yet?");
		if (has_head)
	oidcpy(&ce->oid, &oid);

		goto done;
			    preferred_index_format,
		if (r->settings.core_untracked_cache == UNTRACKED_CACHE_WRITE)

		active_cache_changed |= CE_ENTRY_CHANGED;
{
		fprintf_ln(stderr, _("directory stat info does not change "
enum uc_mode {
static enum parse_opt_result stdin_callback(
		die_errno("Could not make temporary directory");
			ctx.argv++;
	unsigned int mode;
			N_("remove named paths even if present in worktree"), 1),
	return add_one_path(ce, path, len, st);
	if (remove_file_from_cache(path))
			if (!nul_term_line && buf.buf[0] == '"') {
	return -1;
			cacheinfo_callback},
		const struct cache_entry *ce = active_cache[pos];
		if (mark_ce_flags(path, CE_FSMONITOR_VALID, mark_fsmonitor_only == MARK_FLAG))
		add_fsmonitor(&the_index);
			active_cache[pos]->ce_flags |= flag;

{
{
		if (which)
#include "refs.h"
		fputc('\n', stderr);

				     "after updating a file"));
		remove_split_index(&the_index);
	fputc('.', stderr);
#include "tree-walk.h"

		return error("%s: cannot remove from the index", path);
			update_one(p);
					"%s: skipping still unmerged path.\n",
		const struct cache_entry *ce = active_cache[pos];
};
	BUG_ON_OPT_NEG(unset);
	int parseopt_state = PARSE_OPT_UNKNOWN;
		if (git_config_get_split_index() == 1)
	bad_line:
		return error("%s: cannot add to the index - missing --add option?",
		       PATHSPEC_PREFER_CWD,
			 */
	if (split_index > 0) {
{
#include "split-index.h"
	BUG_ON_OPT_ARG(arg);
		 * working directory version is assumed "good"
	xstat_mtime_dir(&st);
			add_split_index(&the_index);
		{
		else

		return error("option 'cacheinfo' expects <mode>,<sha1>,<path>");
		active_cache_changed = 0;
	if (argc == 2 && !strcmp(argv[1], "-h"))
		die_errno(_("failed to create file %s"), path);
done:
			ctx.argc--;
			N_("only update entries that differ from HEAD"),
}
}
static int allow_replace;
	ce->ce_flags = create_ce_flags(stage);
		OPT_BOOL(0, "fsmonitor", &fsmonitor,
		 */
	if (preferred_index_format) {
}
	xstat_mtime_dir(&st);
	if (read_ref("MERGE_HEAD", &merge_head_oid)) {
 *    use "--force-remove" if you actually want to force removal).
		else {
				error("unknown switch '%c'", *ctx.opt);

	ce->ce_mode = ce_mode_from_stat(old, st->st_mode);

			goto bad_line;
			else
}

		}
static int allow_add;
	}
	if (!arg)
	memcpy(ce->name, path, len);
 *  - permission error. That's never ok.

	ce->ce_namelen = len;
	const struct cache_entry *ce;
{
	va_list vp;

}
		report("remove '%s'", path);
}
		if (mark_ce_flags(path, CE_VALID, mark_valid_only == MARK_FLAG))
	}
			break;
			continue;

			    INDEX_FORMAT_LB, INDEX_FORMAT_UB);
			N_("clear fsmonitor valid bit"),
	memcpy(ce->name, path, len);
	xstat_mtime_dir(&st);
		save_nr = active_nr;
}
			N_("enable or disable file system monitor")),
			N_("enable/disable untracked cache")),
#include "cache-tree.h"
	char set_executable_bit = 0;
	if (!match_stat_data(&base, &st)) {
	strbuf_addf(&sb, "%s/%s", mtime_dir.buf, path);
 * files to the revision control by mistake by doing something
	path = get_mtime_path(path);
	return error("lstat(\"%s\"): %s", path, strerror(err));
{
	if (!parse_new_style_cacheinfo(ctx->argv[1], &mode, &oid, &path)) {
	while (ctx.argc) {

	return 0;
	if (has_symlink_leading_path(path, len))
	int namelen = strlen(path);
	}
	unsigned long ul;

{

	pos = -pos-1;
			return error("%s: cannot remove from the index", path);
	BUG_ON_OPT_ARG(arg);
		 *
			REFRESH_IGNORE_SUBMODULES),
		if (!mode) {
	 * ignore it?
		case PARSE_OPT_HELP:
	close(create_file("new-dir/new"));
		ret = -1;
}
		 * want to do anything in the former case.
static int mark_skip_worktree_only;
				     "adding a file inside subdirectory"));
					path);
	}
#include "parse-options.h"
		    oideq(&ce->oid, &old->oid)) {
static enum parse_opt_result unresolve_callback(
			N_("read list of paths to be updated from standard input"),
		fputc('\n', stderr);
{
	*flip = arg[0];
static void read_index_info(int nul_term_line)
	}
 */
/*
			continue;
	} else if (!fsmonitor) {
		fputc('\n', stderr);
		die_errno(_("failed to delete directory %s"), path);
static int refresh(struct refresh_params *o, unsigned int flag)
	const int hexsz = the_hash_algo->hexsz;
		       const char *prefix)
	return ce;
	if (force_remove) {
	/* Was the old index entry already up-to-date? */
				die("git update-index: unable to remove %s",
					int namelen, int stage)
static int really_refresh_callback(const struct option *opt,
	ce = active_cache[pos];
	vprintf(fmt, vp);
__attribute__((format (printf, 1, 2)))
			really_refresh_callback},

	int fd, ret = 0;
	fd = open(path, O_CREAT | O_RDWR, 0644);
			const struct cache_entry *ce = active_cache[pos];
	}
	if (errno || endp == arg || *endp != ',' || (unsigned int) ul != ul)
	UC_DISABLE = 0,
	if (mtime_dir.len)
	xmkdir("new-dir");
			continue; /* unchanged */
	NULL
		{OPTION_SET_INT, 0, "no-skip-worktree", &mark_skip_worktree_only, NULL,
	if (match_stat_data(&base, &st)) {
	const char *prefix = startup_info->prefix;
		unsigned long ul;
			ptr = tab + 1; /* point at the head of path */

{
		return 0;
	int lock_error = 0;
	return 0;
		 */
			free(p);
{
{
	if (read_ref("HEAD", &head_oid))
	strbuf_addstr(&mtime_dir, "mtime-test-XXXXXX");
			p = prefix_path(prefix, prefix_length, path);
				fprintf(stderr,
	const char *prefix = startup_info->prefix;
			PARSE_OPT_NONEG | PARSE_OPT_NOARG,
				  "enable split index"));
	}
	if (0 <= pos) {
		return remove_one_path(path);
}
	int pos;
		if (S_ISGITLINK(ce->ce_mode)) {
	for (i = 1; i < ac; i++) {
	}
		return 0;
static void xunlink(const char *path)
	prepare_repo_settings(r);
		 * The second format is to stuff "git ls-tree" output
	} else if (!split_index) {
		setup_work_tree();
	};
		OPT_INTEGER(0, "index-version", &preferred_index_format,
	unsigned int flags;
	int option;

	option = allow_add ? ADD_CACHE_OK_TO_ADD : 0;
	return ret;
			N_("<mode>,<object>,<path>"),

	case UC_DISABLE:
{
	char *endp;
		continue;
	/* we will diagnose later if it turns out that we need to update it */
	enum uc_mode untracked_cache = UC_UNSPECIFIED;
			warning(_("core.untrackedCache is set to true; "
			stage = 0;
	oidcpy(&ce->oid, oid);

			continue;
		pos = -pos-1;
		fprintf_ln(stderr, _("directory stat info changes after "
		 */
	ce = make_empty_cache_entry(&the_index, len);
		char *path_name;
	static struct strbuf sb = STRBUF_INIT;
 *  - it used to exist as a subdirectory (ie multiple files with

static void chmod_path(char flip, const char *path)
				return 0;
	}
		fputc('\n', stderr);
		return error("'%s' is beyond a symbolic link", path);
static int process_lstat_error(const char *path, int err)
			active_cache[pos]->ce_flags &= ~flag;
		OPT_SET_INT(0, "force-remove", &force_remove,
		{OPTION_CALLBACK, 0, "chmod", &set_executable_bit, "(+|-)x",
	}
	fill_stat_data(&base, &st);
			N_("add to index only; do not add content to object database"), 1),
static int do_reupdate(int ac, const char **av,

			    ce_namelen(ce) == namelen &&
 *

	fill_stat_data(&base, &st);
		active_cache_changed = 0;
	}
static void remove_test_directory(void)
static void update_one(const char *path)

	sleep(1);
			goto bad_line;

			REFRESH_IGNORE_MISSING),
	return;
			PARSE_OPT_NOARG | PARSE_OPT_NONEG, NULL, UNMARK_FLAG},
		{OPTION_SET_INT, 0, "assume-unchanged", &mark_valid_only, NULL,
			N_("refresh even if index contains unmerged entries"),
	if (!ce_2 || !ce_3) {
	*o->has_errors |= refresh_cache(o->flags | flag);
 *    this particular prefix) in the index, in which case it's wrong

	if (*has_errors)
		OPT_BIT(0, "ignore-submodules", &refresh_args.flags,

		 * This format is to put higher order stages into the
		die("Unable to process path %s", path);
	read_head_pointers();

	fputc('.', stderr);
	}
		report(_("fsmonitor disabled"));
		return error("%s: does not exist and --remove not passed", path);
		 * that is used for phony merge base tree when falling
		struct strbuf unquoted = STRBUF_INIT;
		add_untracked_cache(&the_index);
	BUG_ON_OPT_ARG(arg);
	if (unlink(path))
		}
	int err = 0;
	while (pos < active_nr) {
		OPT_SET_INT(0, "add", &allow_add,
		 *
	struct cache_entry *ce;
	return 0;
		goto done;
	ce = pos < 0 ? NULL : active_cache[pos];
		 * On the other hand, removing it from index should work
	return refresh(opt->value, 0);
}
	if (stat_errno)

	if (match_stat_data(&base, &st)) {
	return ret;
#include "pathspec.h"
		return;
static int remove_one_path(const char *path)
		}
		    INDEX_FORMAT_UB < preferred_index_format)

		 */
}
	return 0;
			N_("mark files as \"not changing\""),
			NULL, 0, unresolve_callback},
}


		fputc('\n', stderr);
	option |= allow_replace ? ADD_CACHE_OK_TO_REPLACE : 0;
		if (!tab || tab - ptr < hexsz + 1)
}
		return;
		}
	 * field nsec could be there, but the OS could choose to
		ce->ce_flags |= CE_VALID;
			free(p);
	option |= allow_replace ? ADD_CACHE_OK_TO_REPLACE : 0;
		usage_with_options(update_index_usage, options);
	getline_fn = nul_term_line ? strbuf_getline_nul : strbuf_getline_lf;
		st.st_mode = 0;
	if (parse_oid_hex(endp, oid, &p) || *p != ',')
static struct strbuf mtime_dir = STRBUF_INIT;

static void read_head_pointers(void)
			char *p;
}
					struct object_id *ent, const char *path,
 *  - it's a *file* in the index, in which case it should be
		}
	}
			REFRESH_QUIET),
		int stage;
		{OPTION_CALLBACK, 0, "clear-resolve-undo", NULL, NULL,

	BUG_ON_OPT_NEG(unset);
	ce = make_empty_cache_entry(&the_index, len);
static int mark_valid_only;
		path = xstrdup(ce->name);
	if (read_from_stdin) {
	const char *arg, int unset)
 * Handle a path that was a directory. Four cases:

				"remove it if you really want to "
		return error("option 'chmod' expects \"+x\" or \"-x\"");
	UC_ENABLE,
		if (which)
			path_name = uq.buf;

		OPT_BOOL(0, "untracked-cache", &untracked_cache,
}
	if (entries < 0)
		errno = 0;
 *
	}
		die("cache corrupted");
static int unresolve_one(const char *path)
		return 0;
			active_cache_changed |= SOMETHING_CHANGED;
	pos = cache_name_pos(path, namelen);
			resolve_undo_clear_callback},
	if (stat(mtime_dir.buf, st))
	return 0;
}
