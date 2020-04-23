	int *empty_entry_found = cb_data;
	/* --work-tree is set without --git-dir; use discovered one */

		ret = 1;
	 * see Documentation/config/alias.txt.
 *  - either an objects/ directory _or_ the proper

				prefix ? prefix : "",
			return 0;
			die_errno(_("fork failed"));
	 */


				die_errno(_("cannot chdir to '%s'"), git_work_tree_cfg);
	return -(i & 0666);
	char *r = prefix_path_gently(prefix, len, NULL, path);
	has_common = get_common_dir(&sb, gitdir);
{
 * argument (which could have been a revision), and
		prefix = NULL;
int read_repository_format(struct repository_format *format, const char *path)
	if (is_missing_file_error(errno)) {

		error_code = READ_GITFILE_ERR_READ_FAILED;
		free(gitfile);
	int offset;
		return PERM_EVERYBODY;
		/* Avoid a trailing "/." */
	clear_repository_format(&repo_fmt);
	repository_format_worktree_config = candidate->worktree_config;

			die_errno(_("cannot come back to cwd"));
	strbuf_release(&path);

			return GIT_DIR_HIT_MOUNT_POINT;
	/* Parse octal numbers */
		if (is_absolute_path(git_work_tree_cfg))

	if (verify_repository_format(candidate, &err) < 0) {
	struct strbuf data = STRBUF_INIT;
		filter_string_list(&ceiling_dirs, 0,
	if (starts_with(arg, ":("))
	    startup_info->have_repository ||
		if (*path == '/') {
/*
	 */
		/* #16d */
 * not, since the config can only be read _after_ this function was called.
 * as true, because even if such a filename were to exist, we want
		free(r);
		if (normalize_path_copy_len(sanitized, path, remaining_prefix)) {
	}
		return PERM_GROUP;
 *
	GIT_DIR_NONE = 0,
	struct stat st;
 *  foo          -> sub1/sub2/foo  (full prefix)
	clear_repository_format(&candidate);
	 */
	 * - ../../.git

 * diagnose_misspelt_rev == 0 for the next ones (because we already
		return suspect;
	/* --work-tree is set without --git-dir; use discovered one */
	const char *ext;

		if (chdir(cwd->buf))

}
	}
		if (chdir(worktree))
	char *path0;
		    arg);

	one_filesystem = !git_env_bool("GIT_DISCOVERY_ACROSS_FILESYSTEM", 0);
	 */
{
	/*
		}
	 * the GIT_PREFIX environment variable must always match. For details
		break;
			} else if (error_code != READ_GITFILE_ERR_STAT_FAILED)
		warning("ignoring git dir '%s': %s",
			inside_work_tree = -1;
	struct repository_format *data = vdata;
}
}
			die(_("cannot change to '%s'"), dir.buf);
		break;
 * This function is typically called to check that a "file or rev"
	 */
		strbuf_reset(&path);

	case GIT_DIR_BARE:
		die(_("not a git repository: %s"), dir);

#include "cache.h"
}
cleanup_return:
	else if (!git_env_bool(GIT_IMPLICIT_WORK_TREE_ENVIRONMENT, 1)) {
		}
	 */
		return PERM_GROUP;
	    gitfile_error == READ_GITFILE_ERR_READ_FAILED)
	len = read_in_full(fd, buf, st.st_size);
	set_git_dir(gitdirenv, 0);
			 int *remaining_prefix, const char *path)
	char *to_free = NULL;


{
{
		free(buf);
	inside_git_dir = 0;
	const char *worktree;
	 * Mask filemode value. Others can not get write permission.

	if (GIT_REPO_VERSION_READ < format->version) {
{
int check_filename(const char *prefix, const char *arg)
				escaped = 1;
	return sanitized;
	}
	if (getenv(GIT_WORK_TREE_ENVIRONMENT) || git_work_tree_cfg) {
		/* non-fatal; follow return path */
				die_errno(_("cannot chdir to '%s'"), gitdirenv);
void verify_non_filename(const char *prefix, const char *arg)
		}
		strbuf_addch(dir, '/');
		    absolute_path(hint_path));
	if (check_repository_format_gently(gitdir, repo_fmt, nongit_ok))
	 */
	/* check whole path */
			strbuf_addch(dir, '/');
			strbuf_addstr(gitdir, gitdirenv);
#include "dir.h"
		ceil_offset = longest_ancestor_length(dir->buf, &ceiling_dirs);
		current_device = get_device_or_die(dir->buf, NULL, 0);
		strbuf_setlen(&path, len);
	strbuf_addstr(&sb, "/config");
	 * Let's assume that we are in a git repository.

	int i;
{
	/* long-form pathspec magic */

{

	}
	wtlen = strlen(work_tree);
	dir = buf + 8;
{

	const char *work_tree = get_git_work_tree();
	/*
	 * is unset.
		break;
			strbuf_addch(&dir, '/');
	return ret;
				return 0;
 *    a proper "ref:", or a regular file HEAD that has a properly
		goto cleanup_return;
{
		inside_work_tree = is_inside_dir(get_git_work_tree());
/*

/*
		has_common = 0;
	if (*endptr != 0)

	if (PATH_MAX - 40 < strlen(gitdirenv))
	}

static int check_repo_format(const char *var, const char *value, void *vdata)
			return GIT_DIR_HIT_CEILING;
	worktree = get_git_work_tree();
		goto cleanup_return;
			setenv(GIT_PREFIX_ENVIRONMENT, "", 1);
	 * At this point, nongit_ok is stable. If it is non-NULL and points
 * `dir` parameter; upon return, the `dir` buffer will contain the path of
		break;
		strbuf_release(&sb);
	}
}
	return buf.st_dev;
		return NULL;
	if (format->version == -1)
		return git_config_bool(var, value) ? PERM_GROUP : PERM_UMASK;
	strbuf_addf(&dir, "%s/config", commondir->buf + commondir_offset);
			strbuf_addf(&path, "%s/", gitdir);
static int work_tree_config_is_bogus;
{
	work_tree = get_git_work_tree();
	if (initialized)
		return NULL;

	if (!is_git_directory(gitdirenv)) {
	strbuf_release(&data);

{
void read_gitfile_error_die(int error_code, const char *path, const char *dir)
	static struct strbuf cwd = STRBUF_INIT;

const char *setup_git_directory(void)

		set_git_dir(gitdirenv, 1);
	 * Treat values 0, 1 and 2 as compatibility cases, otherwise it is

	case READ_GITFILE_ERR_TOO_LARGE:
}
 * GIT_CEILING_DIRECTORIES turns off canonicalization for all
	return inside_git_dir;
	case GIT_DIR_EXPLICIT:
		die("%s", err.buf);
void setup_work_tree(void)
				return GIT_DIR_INVALID_GITFILE;
static void init_repository_format(struct repository_format *format)
		if (!real_path) {
		int empty_entry_found = 0;
 * Opposite of the above: the command line did not have -- marker
					    struct repository_format *repo_fmt,
	if (getenv(DB_ENVIRONMENT)) {
	strbuf_addch(cwd, '/');
static dev_t get_device_or_die(const char *path, const char *prefix, int prefix_len)
	struct repository_format *data = vdata;
 * /dir/repo              (exactly equal to work tree)   -> (empty string)
					 const char *arg,
	if (looks_like_pathspec(arg) || check_filename(prefix, arg))
	initialized = 1;
	off = offset_1st_component(path);
}
		}

				    format->unknown_extensions.items[i].string);
		goto cleanup_return;

	/*
		free(gitfile);

			goto done;
#endif
		if (git_work_tree_cfg) {


		goto cleanup_return;
		if (nongit_ok) {
	}
	}
 * return_error_code is NULL the function will die instead (for most
 * discards it if unusable.  The presence of an empty entry in

 *
		if (access(getenv(DB_ENVIRONMENT), X_OK))


	return NULL;
	if (!fmt)
	if (!is_absolute_path(dir) && (slash = strrchr(path, '/'))) {
 * The "diagnose_misspelt_rev" is used to provide a user-friendly
	 * user gave us ":(icase)foo" is just stupid.  A magic pathspec
	size_t gitdir_offset = gitdir->len, cwd_len;
		len--;
		return NULL;

	 * code paths so we also need to explicitly setup the environment if
	struct repository_format repo_fmt = REPOSITORY_FORMAT_INIT;
	const char *gitdirenv;

	if (wtlen <= len && !fspathncmp(path, work_tree, wtlen)) {
	strbuf_release(&dir);
 *    GIT_OBJECT_DIRECTORY environment variable

	/* #16.2, #17.2, #20.2, #21.2, #24, #25, #28, #29 (see t1510) */
		size_t pathlen = slash+1 - path;
		if (!value)
char *prefix_path_gently(const char *prefix, int len,
	/* both get_git_work_tree() and cwd are already normalized */
		}
	}
		    "read and write permissions."), i);
	}
	}
 * Check for arguments that don't resolve as actual files,
			git_work_tree_cfg = xstrdup(candidate->work_tree);
/*
	init_repository_format(format);
	/* ... or fall back the most general message. */
				prefix ? "/" : "", path);
			die(_("cannot change to '%s'"), dir.buf);
}
	}
	}
			   struct strbuf *gitdir)
 */
	} else {
 * dereferencing symlinks outside the work tree, for example:

		 */
	if (read_gitfile_gently(path->buf, &gitfile_error) || is_git_directory(path->buf))
	}
	return 0;
			return GIT_DIR_BARE;
			core_worktree = xgetcwd();
int get_common_dir_noenv(struct strbuf *sb, const char *gitdir)
		else {
					gitdirenv = DEFAULT_GIT_DIR_ENVIRONMENT;
			return config_error_nonbool(var);
	const char *orig = path;
			strbuf_addf(err, "\n\t%s",
	}
{
		strbuf_addstr(sb, gitdir);
	}
	case PERM_UMASK:               /* 0 */
 * /dir/file              (work tree is /)               -> dir/file
	get_common_dir(&path, suspect);
		 */
	if (fd == -1)

	}
	}
			free(sanitized);
	strbuf_realpath(&realpath, dir, 1);
		if (dir.len < cwd.len && chdir(dir.buf))
		return 1;
	strbuf_setlen(path, orig_path_len);
	/*
	if (nongit_ok && *nongit_ok) {
	char *endptr;

		/* work tree might match beginning of a symlink to work tree */

		data->work_tree = xstrdup(value);
	} else {
	if (!check_filename(prefix, arg))
		free(to_free);
	if (offset >= cwd->len)
		else if (!strcmp(ext, "partialclone")) {

		maybe_die_on_misspelt_object_name(r, arg, prefix);

	if (st.st_size > max_file_size) {
	if (!work_tree)
			string_list_append(&data->unknown_extensions, ext);
		}
	if (!strcmp(value, "umask"))

 * it to be preceded by the "--" marker (or we want the user to
	char *dir = NULL;
{
}
		return NULL;

 * will only complain about an inexisting file.
				gitdir = DEFAULT_GIT_DIR_ENVIRONMENT;
	int len = prefix ? strlen(prefix) : 0;
	return error_code ? NULL : path;
{
	struct strbuf dir = STRBUF_INIT, gitdir = STRBUF_INIT;
		return ret;
	if (ceil_offset < 0)
	free(format->partial_clone);
	if (!is_git_directory(dir)) {
	strbuf_complete(path, '/');
			if (die_on_error ||
				inside_work_tree = -1;

 *
				      int *nongit_ok)
			*path = '/';
				return 1;
		error_code = READ_GITFILE_ERR_NOT_A_REPO;
		free(gitfile);
	}
	case READ_GITFILE_ERR_NO_PATH:
 * relative to the work tree root, or NULL, if the current working
	return 0;
 * entry. Note that a filename that begins with "-" never verifies
	}
		item->string = real_path;
		strbuf_setlen(dir, offset > min_offset ?  offset : min_offset);
	}
	} else if (!is_absolute_path(ceil)) {
			    error_code == READ_GITFILE_ERR_NOT_A_FILE) {
	 * Wildcard characters imply the user is looking to match pathspecs
	}
 */
	if (offset != cwd->len) {

		fmt = &repo_fmt;
 * argument is unambiguous. In this case, the caller will want
	/*
const char *read_gitfile_gently(const char *path, int *return_error_code)
		strbuf_addbuf(&path, &data);
	if (value == NULL)
struct startup_info *startup_info = &the_startup_info;
				      void *cb_data)
int path_inside_repo(const char *prefix, const char *path)
			data->partial_clone = xstrdup(value);
	return read_gitfile_gently(suspect, return_error_code);
	}

	size_t wtlen;
			return 0;
	 * the user has set GIT_DIR.  It may be beneficial to disallow bogus
{
		 * pick up core.bare and core.worktree from per-worktree
		const char *hint_path = get_git_work_tree();

		free(gitfile);
			die(_("not a git repository (or any parent up to mount point %s)\n"
		else
 * /dir1/repo/dir2/file   (work tree is /dir1/repo)      -> dir2/file
 *  ../foo       -> sub1/foo       (remaining prefix is sub1/)
	strbuf_addstr(&path, "/refs");
		setenv(GIT_PREFIX_ENVIRONMENT, "", 1);
 */
		return 0;
	i = strtol(value, &endptr, 8);
		strbuf_add_real_path(sb, path.buf);
	get_common_dir(commondir, gitdir->buf + gitdir_offset);
		if (escaped) {
		if (!*arg) /* ":/" is root dir, always exists */
		strbuf_addstr(err, _("unknown repository extensions found:"));
#include "config.h"
	/*
		return PERM_UMASK;
/*
		if (one_filesystem &&
		 * record any known extensions here; otherwise,
	struct stat buf;

	 * ignored previously).
				   canonicalize_ceiling_entry, &empty_entry_found);
	int has_common;
	 * NEEDSWORK: currently we allow bogus GIT_DIR values to be set in some
			free(gitfile);
		return;
	struct strbuf path = STRBUF_INIT;
			memmove(path, path + wtlen, len - wtlen + 1);
		if (remaining_prefix)
	int escaped = 0;
	} else {
		strbuf_setlen(commondir, commondir_offset);
	/* If not an octal number, maybe true/false? */
			return 0;
	 * If GIT_DIR is set explicitly, we're not going
		die_errno(_("setsid failed"));
	char *sanitized;
		}
		return -1;
}
	    getenv(GIT_DIR_ENVIRONMENT)) {
	int ret = 0;
 * Find the part of an absolute path that lies inside the work tree by
	}

	memcpy(format, &fresh, sizeof(fresh));
	GIT_DIR_INVALID_GITFILE = -3
 * invalid object name (e.g. HEAD:foo). If set to 0, the diagnosis
 * Also, we avoid changing any global state (such as the current working
			*nongit_ok = 1;
	}
		}
		if (normalize_path_copy_len(sanitized, sanitized, remaining_prefix)) {

	return prefix;
		set_git_dir(gitdirenv, 0);
			die_errno(_("cannot chdir to '%s'"), worktree);
}
	 */
	if (offset != offset_1st_component(cwd->buf))

		if (strbuf_read_file(&data, path.buf, 0) <= 0)
		goto cleanup_return;
			if (chdir(git_work_tree_cfg))
}
	struct repository_format candidate = REPOSITORY_FORMAT_INIT;
{
	case OLD_PERM_EVERYBODY:       /* 2 */
			if (chdir(cwd->buf))
	 * this.
	 * Test in the following order (relative to the dir):
	if (strbuf_getcwd(&cwd))
	 * - ../ (bare)
	const char *work_tree_env = getenv(GIT_WORK_TREE_ENVIRONMENT);
	/* check each '/'-terminated level */
	if (!is_inside_work_tree() || is_inside_git_dir())
static const char *setup_bare_git_dir(struct strbuf *cwd, int offset,
		BUG("unhandled setup_git_directory_1() result");

		else
	 * we treat a missing config as a silent "ok", even when nongit_ok
	 */
}
		static const char *gitdir;

	 *   etc.
			return NULL;
	inside_work_tree = 1;
		strbuf_addstr(gitdir, gitdirenv);
	if (dir.len < cwd_len && !is_absolute_path(gitdir->buf + gitdir_offset)) {
		return 1;
			free(sanitized);
	}
#else
	if (stat(path, &st)) {
	case GIT_DIR_HIT_MOUNT_POINT:
 * directory) to allow early callers.
	die(_("ambiguous argument '%s': both revision and filename\n"
		strbuf_addf(&sb, "%s/config.worktree", gitdir);
int get_common_dir(struct strbuf *sb, const char *gitdir)
	const char *p;
				/* NEEDSWORK: fail if .git is not file nor dir */
	buf[len] = '\0';
	size_t len;
		prefix = setup_explicit_git_dir(gitdir.buf, &cwd, &repo_fmt, nongit_ok);
	if (check_repository_format_gently(gitdirenv, repo_fmt, nongit_ok)) {
 * /dir/repolink/file     (repolink points to /dir/repo) -> file
		if (candidate->work_tree) {
	 *
		close(fd);
		break;

#include "chdir-notify.h"
	if (!*ceil) {
		      "Use 'git <command> -- <path>...' to specify paths that do not exist locally."),
			else
				return config_error_nonbool(var);
	    !is_dir_sep(dir->buf[min_offset - 1])) {

 * Verify a filename that we got as an argument for a pathspec
	char *r = prefix_path_gently(prefix, len, NULL, path);
	strbuf_addf(&path, "%s/commondir", gitdir);
	}
			data->worktree_config = git_config_bool(var, value);
	if (repository_format_worktree_config) {
		/*
	assert(orig_path_len != 0);

{
			set_git_work_tree(core_worktree);
	if (*arg == '-')
	return 0;

		}
	close(1);
			*path = '\0';
		else if (!strcmp(ext, "preciousobjects"))

	if (!strcmp(value, "all") ||
 *  - either a HEAD symlink or a HEAD file that is formatted as
			break;
		die_errno(_("error opening '%s'"), path);
#include "promisor-remote.h"
			*remaining_prefix = len;
const char *setup_git_directory_gently(int *nongit_ok)
		if (abspath_part_inside_repo(sanitized)) {
static int abspath_part_inside_repo(char *path)
	}
	 */
		buf = dir;
	path += off;
}
 */
		set_git_work_tree(".");
	return ret;
				strbuf_release(&realpath);
			      (int)(len - 8), buf + 8);
	strbuf_reset(&path);
			return NULL;
 *  - a refs/ directory

{
		if (candidate->is_bare != -1) {
	} else if (skip_prefix(arg, ":!", &arg) ||
		gitdir = offset == cwd->len ? "." : xmemdupz(cwd->buf, offset);
int is_inside_work_tree(void)
		*empty_entry_found = 1;
	      "'git <command> [<revision>...] -- [<file>...]'"), arg);
			return NULL;
		return NULL;
	struct strbuf path = STRBUF_INIT;
	switch (i) {
}
	if (!has_common) {
	 * The returned gitdir is relative to dir, and if dir does not reflect
	else {
}
static int inside_git_dir = -1;
	if (skip_prefix(arg, ":/", &arg)) {
}
	 * the current working directory, we simply make the gitdir absolute.
 *
	char *ceil = item->string;
		*path0 = '\0';
	if (!strcmp(cwd->buf, worktree)) { /* cwd == worktree */
	struct string_list ceiling_dirs = STRING_LIST_INIT_DUP;
 * use a format like "./-filename")
 * prefix always ends with a '/' character.
 * will be set to an error code and NULL will be returned. If
	strbuf_addstr(&path, suspect);
		case 0:
		 * As a safeguard against setup_git_directory_gently_1 returning

		min_offset++;
	for (p = arg; *p; p++) {
	}
		data.buf[data.len] = '\0';
		goto done;
}
		die(_("invalid gitfile format: %s"), path);
	}
{
			*remaining_prefix = 0;
	strbuf_addbuf(&dir, &cwd);
		return get_common_dir_noenv(sb, gitdir);
	size_t orig_path_len = path->len;

	return ret;
		/* Keep entry but do not canonicalize it */
	 * - ./ (bare)
	strbuf_complete(&path, '/');
{
#ifdef NO_POSIX_GOODIES
		arg = to_free = prefix_filename(prefix, arg);
			setenv(GIT_PREFIX_ENVIRONMENT, prefix, 1);
			warning("core.bare and core.worktree do not make sense");
		else

	if (!strcmp(value, "group"))
		}
					  int *nongit_ok)
	 * cause any increase in the match. Likewise ignore backslash-escaped
	return -1;
		prefix = setup_discovered_git_dir(gitdir.buf, &cwd, dir.len,
		return;
		strbuf_addstr(sb, git_env_common_dir);

	strbuf_release(&path);
	}
	default:
	if (format->version >= 1 && format->unknown_extensions.nr) {
	if (!work_tree || chdir_notify(work_tree))

 * is relative to `dir` (i.e. *not* necessarily the cwd).
void sanitize_stdfds(void)
	for (;;) {
	if (one_filesystem)
static int check_repository_format_gently(const char *gitdir, struct repository_format *candidate, int *nongit_ok)
	      "Use '--' to separate paths from revisions, like this:\n"
#include "repository.h"
	 *
	git_config_clear();
char *prefix_path(const char *prefix, int len, const char *path)
	const char *prefix = NULL;
		ceil_offset = min_offset - 2;
		break;
	return -1;
		if (nongit_ok) {
		ret = 1;
}
	 * - .git/
	int fd;
	errno = ENOSYS;
	if (candidate->version < 0)
	else
			escaped = 0;
		strbuf_insert(gitdir, gitdir_offset, dir.buf, dir.len);
		}
{
		return 0;
	/* Add a '/' at the end */
		ret = 1;
		free(item->string);
}
	die_verify_filename(the_repository, prefix, arg, diagnose_misspelt_rev);
	strbuf_release(&dir);
		die(_("'$%s' too big"), GIT_DIR_ENVIRONMENT);
		die_errno(_("open /dev/null or dup failed"));
	/*
	}
		error_code = READ_GITFILE_ERR_NO_PATH;
{
	strbuf_release(&realpath);
	check_repository_format_gently(get_git_dir(), fmt, NULL);
	 * to do any discovery, but we still do repository
}
		read_gitfile_error_die(error_code, path, dir);
		return 0; /* file does not exist */
	}

	case GIT_DIR_HIT_CEILING:
			const char *gitdir = getenv(GIT_DIR_ENVIRONMENT);
static const char *setup_explicit_git_dir(const char *gitdirenv,
static int read_worktree_config(const char *var, const char *value, void *vdata)
		strbuf_addch(cwd, '/');
		*nongit_ok = 1;
	read_repository_format(candidate, sb.buf);
	case READ_GITFILE_ERR_NOT_A_REPO:
}
	}
			if (!value)
		/*
	git_config_from_file(check_repo_format, path, format);
							  struct strbuf *gitdir,
{
		return NULL;
	while (*path) {
		 * set startup_info->have_repository to 1 when we did nothing to
		die(_("this operation must be run in a work tree"));
	strbuf_realpath(&realpath, path0, 1);
		die_errno(_("failed to stat '%*s%s%s'"),
 * saw a filename, there's not ambiguity anymore).
{
	case READ_GITFILE_ERR_NOT_A_FILE:



	 * validation.
	if (strcmp(var, "core.bare") == 0) {
		return NULL;
int daemonize(void)
 * remaining_prefix is not NULL, return the actual prefix still

		if (prefix)
	/*
	strbuf_setlen(&path, len);
	struct strbuf realpath = STRBUF_INIT;
	if (git_env_common_dir) {
	}
	struct strbuf dir = STRBUF_INIT, err = STRBUF_INIT;
int is_git_directory(const char *suspect)
	case READ_GITFILE_ERR_INVALID_FORMAT:
	GIT_DIR_HIT_CEILING = -1,

}
	    !strcmp(value, "everybody"))
		error_code = READ_GITFILE_ERR_NOT_A_FILE;
		if (!is_absolute_path(data.buf))
	const char *slash;
	 * updated accordingly.
}
	}
		gitdirenv = read_gitfile_gently(dir->buf, die_on_error ?
		strbuf_release(&dir);
	 * Make sure subsequent git processes find correct worktree
		return 1;
}
			    GIT_REPO_VERSION_READ, format->version);
	GIT_DIR_DISCOVERED,
	if (is_bare_repository_cfg > 0) {



	      "'git <command> [<revision>...] -- [<file>...]'"), arg);
	inside_git_dir = 1;
		return GIT_DIR_EXPLICIT;
	if (min_offset && min_offset == dir->len &&
	if (prefix)
const char *resolve_gitdir_gently(const char *suspect, int *return_error_code)
		error_code = READ_GITFILE_ERR_TOO_LARGE;
		while (data.len && (data.buf[data.len - 1] == '\n' ||

	path0 = path;
{

	inside_work_tree = 0;
			     struct strbuf *err)

{
			free(core_worktree);
	if (!lstat(arg, &st)) {
	close(2);
	if (getenv(GIT_WORK_TREE_ENVIRONMENT) || git_work_tree_cfg) {
#include "string-list.h"
	struct repository_format repo_fmt = REPOSITORY_FORMAT_INIT;
		}

		*nongit_ok = 0;
	if (strcmp(gitdir, DEFAULT_GIT_DIR_ENVIRONMENT))
 */
}
	if (offset >= 0) {	/* cwd inside worktree? */
	/* Make "offset" point past the '/' (already the case for root dirs) */
		goto cleanup_return;
	 * that the next queries to the configuration reload complete
{
	if (file_exists(path.buf)) {
		     int diagnose_misspelt_rev)
		if (chdir(cwd->buf))

				die_errno(_("cannot come back to cwd"));
	if (getenv(GIT_WORK_TREE_ENVIRONMENT))
				      struct repository_format *repo_fmt,
		 * check_repository_format will complain
					    int *nongit_ok)
	} else if (*empty_entry_found) {
 * Test if it looks like we're at a git directory.
	struct strbuf sb = STRBUF_INIT;
				memmove(path0, path + 1, len - (path - path0));
		BUG("unknown error code");
	if (verify_repository_format(&candidate, &err) < 0) {
	    /* GIT_DIR_EXPLICIT */
		startup_info->have_repository = 0;
 * If set to 1, the diagnosis will try to diagnose "name" as an
		goto cleanup_return;
		startup_info->prefix = prefix;
	} else {
		return -1;
		return; /* flag */
			set_git_work_tree(git_work_tree_cfg);
	if (*arg == '-')
		int offset = dir->len, error_code = 0;
		set_git_dir(".", 0);
	      "Use '--' to separate paths from revisions, like this:\n"
		string_list_clear(&ceiling_dirs, 0);
					 int diagnose_misspelt_rev)

		clear_repository_format(format);
	if (r) {
			warning("%s", err.buf);
		/* NEEDSWORK: discern between ENOENT vs other errors */
}
			goto done;
	die(_("ambiguous argument '%s': unknown revision or path not in the working tree.\n"
	if (gitfile_error == READ_GITFILE_ERR_OPEN_FAILED ||
	return read_worktree_config(var, value, vdata);
	cwd_len = dir.len;
	}
	set_git_work_tree(".");
 * return path to git directory if found. The return value comes from
/*
			/* #22.2, #30 */
 *    formatted sha1 object name.
	struct strbuf err = STRBUF_INIT;
		set_git_dir(cwd->buf, 0);
	case READ_GITFILE_ERR_STAT_FAILED:
		     const char *arg,
	switch (error_code) {
};
{
		strbuf_addf(err, _("Expected git repo version <= %d, found %d"),
 *
	fd = open(path, O_RDONLY);
		} else if (is_glob_special(*p)) {
}
	int error_code = 0;

 * directory is not a strict subdirectory of the work tree root. The
	static struct strbuf realpath = STRBUF_INIT;
		free(to_free);
	gitfile = (char*)read_gitfile(gitdirenv);
	if (inside_git_dir < 0)
		}
		if (offset != cwd->len && !is_absolute_path(gitdir))
}
	 * begins with a colon and is followed by a non-alnum; do not
{
		free(gitfile);
static int canonicalize_ceiling_entry(struct string_list_item *item,
				prefix_len,
		}
	close(0);
 * /dir/symlink1/symlink2 (symlink1 points to work tree) -> symlink2
			strbuf_release(&err);
	int ret = 0;
		    "(0%.3o).\nThe owner of files must always have "

					  struct strbuf *cwd,
 * The input parameter must contain an absolute path, and it must already be
	const struct repository_format fresh = REPOSITORY_FORMAT_INIT;
			data.len--;
 *
}
	if (fd < 0) {

	case OLD_PERM_GROUP:           /* 1 */
	if (strcmp(var, "core.repositoryformatversion") == 0)

 * the discovered .git/ directory, if any. If `gitdir` is not absolute, it
			setup_git_env(gitdir);
		strbuf_setlen(dir, offset);

void check_repository_format(struct repository_format *fmt)
	strbuf_reset(&dir);
			repo_set_hash_algo(the_repository, repo_fmt.hash_algo);
 * Try to read the location of the git directory from the .git file,
		return -1;
	/*
	/*
		default:



	if (!diagnose_misspelt_rev)
		strbuf_setlen(gitdir, gitdir_offset);
	if (!(arg[0] == ':' && !isalnum(arg[1])))
{
		string_list_split(&ceiling_dirs, env_ceiling_dirs, PATH_SEP, -1);
	 * repository and that the caller expects startup_info to reflect
 * The directory where the search should start needs to be passed in via the
 * as a filename.
	case READ_GITFILE_ERR_READ_FAILED:
		return 1;
	else /* #2, #10 */
		gitfile = xstrdup(gitfile);
 */
			return 1;
	free(buf);
					 const char *prefix,
 */
		gitdirenv = gitfile;
	if ((i & 0600) != 0600)
	if (setsid() == -1)

	/* these are errors */
	if (env_ceiling_dirs) {
		if (gitdirenv) {
static int looks_like_pathspec(const char *arg)
		}
			strbuf_realpath(&realpath, path0, 1);
	}
		inside_git_dir = is_inside_dir(get_git_dir());
	else if (git_work_tree_cfg) { /* #6, #14 */
/*
			    DEFAULT_GIT_DIR_ENVIRONMENT);
	}
		error_code = READ_GITFILE_ERR_STAT_FAILED;

		if (chdir(cwd->buf))
int is_inside_git_dir(void)
	default:
static enum discovery_result setup_git_directory_gently_1(struct strbuf *dir,
		 * config if present
			if (is_bare_repository_cfg == 1)
{


	}
	if (inside_work_tree < 0)
		   skip_prefix(arg, ":^", &arg)) {

 *
		sanitized = xstrfmt("%.*s%s", len, len ? prefix : "", path);
					  struct repository_format *repo_fmt,
	}
		if (offset <= min_offset)
	if (gitfile) {
	switch (fork()) {
		if (remaining_prefix)
		if (dir.len < cwd.len && chdir(dir.buf))
		    current_device != get_device_or_die(dir->buf, NULL, offset))

static void NORETURN die_verify_filename(struct repository *r,
	} else {
						  &repo_fmt, nongit_ok);
void verify_filename(const char *prefix,
	while (buf[len - 1] == '\n' || buf[len - 1] == '\r')
	if (work_tree_env)

		} else if (!strcmp(ext, "worktreeconfig"))
						NULL : &error_code);
	const char *git_env_common_dir = getenv(GIT_COMMON_DIR_ENVIRONMENT);
}
		error_code = READ_GITFILE_ERR_OPEN_FAILED;
			return 1;
{

			strbuf_addstr(gitdir, ".");
	return cwd->buf + offset;
		return 1;
			    dir.buf);
		if (offset > min_offset)
	/*

	}
 * a shared buffer.
		goto cleanup_return;
	if (/* GIT_DIR_EXPLICIT, GIT_DIR_DISCOVERED, GIT_DIR_BARE */
	if (stat(path, &buf)) {
}
	int one_filesystem = 1;
	}
		setenv(GIT_WORK_TREE_ENVIRONMENT, ".", 1);
		die(_("no path in gitfile: %s"), path);
	size_t len;
	strbuf_release(&gitdir);
	die_errno(_("failed to stat '%s'"), arg);
	if (!starts_with(buf, "gitdir: ")) {
			die_errno(_("cannot come back to cwd"));
			strbuf_setlen(gitdir, gitdir_offset);

		}
		set_git_dir(gitdir, 0);
	 * that aren't in the filesystem. Note that this doesn't include
	size_t commondir_offset = commondir->len;

			*nongit_ok = -1;
	 * Regardless of the state of nongit_ok, startup_info->prefix and
	}
			if (fspathcmp(realpath.buf, work_tree) == 0) {

	while (fd != -1 && fd < 2)
	case GIT_DIR_NONE:


			; /* continue */
	}
	 * Saying "'(icase)foo' does not exist in the index" when the
	string_list_clear(&candidate->unknown_extensions, 0);
	}
 * On failure, if return_error_code is not NULL, return_error_code
	GIT_DIR_HIT_MOUNT_POINT = -2,
	/* #0, #1, #5, #8, #9, #12, #13 */
	int root_len;

		if (offset <= ceil_offset)
int verify_repository_format(const struct repository_format *format,
 * We cannot decide in this function whether we are in the work tree or
		 * find a repository.
	return 0;
		die(_("'%s' is outside repository at '%s'"), path,
			return GIT_DIR_DISCOVERED;
 * diagnose_misspelt_rev == 1 when verifying the first non-rev
static struct startup_info the_startup_info;
	dev_t current_device = 0;
	 * to a non-zero value, then this means that we haven't found a
	}
		if (!*arg) /* excluding everything is silly, but allowed */
	 * configuration (including the per-repo config file that we
	const int max_file_size = 1 << 20;  /* 1MB */
{
	close(fd);
	/* A filemode value was given: 0xxx */
{
		offset++;
		return -1;
	 */
	repository_format_precious_objects = candidate->precious_objects;
	 * If it turns out later that we are somewhere else, the value will be
	 * the environment if we have a repository.
		strbuf_release(&realpath);


}
	}
	}
	int off;
}
	else if (error_code)
	char *gitfile;
}
		if (!the_repository->gitdir) {
			work_tree_config_is_bogus = 1;
{


	if (!r) {

 */

		root_len = offset_1st_component(cwd->buf);
	ssize_t len;
							  int die_on_error)
		data->version = git_config_int(var, value);
			char *core_worktree;
		set_git_dir(gitdir, (offset != cwd->len));
	const char *env_ceiling_dirs = getenv(CEILING_DIRECTORIES_ENVIRONMENT);
		sanitized = xmallocz(strlen(path));
	/* check if work tree is already the prefix */
		if (chdir(cwd->buf))

 * Normalize "path", prepending the "prefix" for relative paths. If

	}

 * and we parsed the arg as a refname.  It should not be interpretable

{

 * from GIT_CEILING_DIRECTORIES using real_pathdup(), or
	/* set_git_work_tree() must have been called by now */

		free(data->work_tree);


/* #16.1, #17.1, #20.1, #21.1, #22.1 (see t1510) */
		return;
 * Returns the "prefix", a path to the current working directory
			if (!gitdir)
		case -1:
			exit(0);
		if (startup_info->have_repository)
 * We want to see:
/*
	if (validate_headref(path.buf))
}
	if (!S_ISREG(st.st_mode)) {
			die(_("not a git repository (or any of the parent directories): %s"),

 *  ../../bar    -> bar            (no remaining prefix)
		set_git_work_tree(work_tree_env);
		return NULL;
		 */
		startup_info->prefix = NULL;
		if (!hint_path)
	path = realpath.buf;
	int ceil_offset = -1, min_offset = offset_1st_component(dir->buf);
	buf = xmallocz(st.st_size);
			hint_path = get_git_dir();
		die(_("too large to be a .git file: '%s'"), path);
done:


	const char *work_tree;
		if (is_git_directory(dir->buf)) {
		startup_info->have_repository = 1;
		path++;
	setenv(GIT_IMPLICIT_WORK_TREE_ENVIRONMENT, "0", 1);
		free(to_free);
	}

int discover_git_directory(struct strbuf *commondir,

	case GIT_DIR_DISCOVERED:
{

	 * Not all paths through the setup code will call 'set_git_dir()' (which
enum discovery_result {
	if (access(path.buf, X_OK))
			;
			      "Stopping at filesystem boundary (GIT_DISCOVERY_ACROSS_FILESYSTEM not set)."),
}
 * but which look sufficiently like pathspecs that we'll consider
		char *to_free = NULL;
	} else if (strcmp(var, "core.worktree") == 0) {
		/* #18, #26 */
 * them such for the purposes of rev/pathspec DWIM parsing.
		/*

	sanitize_stdfds();
		off = wtlen;
 * remains in the path. For example, prefix = sub1/sub2/ and path is
	return r;
		if (!strcmp(ext, "noop"))
 *  `pwd`/../bar -> sub1/bar       (no remaining prefix)
{
		fd = dup(fd);
		int i;
		set_git_dir(gitdirenv, 0);


		return -1;
	GIT_DIR_BARE,
 * normalized.
	 * setting-up the git directory. If so, clear the cache so
	read_repository_format(&candidate, dir.buf);
		return PERM_GROUP;
	/* cwd outside worktree */
		dir = xstrfmt("%.*s%.*s", (int)pathlen, path,
		die(_("%s: no such path in the working tree.\n"
		strbuf_setlen(cwd, offset > root_len ? offset : root_len);
			return NULL;
	}
			free(git_work_tree_cfg);
 * the directory where the search ended, and `gitdir` will contain the path of
			if (chdir(gitdirenv))
		return 0;
	if (setup_git_directory_gently_1(&dir, gitdir, 0) <= 0) {
		strbuf_addstr(dir, DEFAULT_GIT_DIR_ENVIRONMENT);
			return -1;

		if (!nongit_ok)
	if (fspathcmp(realpath.buf, work_tree) == 0) {

int is_nonbare_repository_dir(struct strbuf *path)
}
 */
		return cwd->buf + offset;
 * cases).
void clear_repository_format(struct repository_format *format)
	 * environment is in a consistent state after setup, explicitly setup
	return inside_work_tree;
	int fd = open("/dev/null", O_RDWR, 0);
	if (len < 9) {

			}
				if (is_git_directory(dir->buf))
		strbuf_release(&err);
	return 0;
}
	 */
			gitdir->buf + gitdir_offset, err.buf);
/* if any standard file descriptor is missing open it to /dev/null */
		prefix = setup_bare_git_dir(&cwd, dir.len, &repo_fmt, nongit_ok);
		return -1;
	 */
/*
		die(_("error reading %s"), path);
		if (!gitdirenv) {
		char *real_path = real_pathdup(ceil, 0);
			return GIT_DIR_HIT_CEILING;
		die(_("not a git repository: '%s'"), gitdirenv);
		die(_("option '%s' must come before non-option arguments"), arg);
	if (is_git_directory(suspect))
	/*
			die_errno(_("cannot come back to cwd"));
	 * directly sets up the environment) so in order to guarantee that the
		goto done;
	    !strcmp(value, "world") ||
	/* Check worktree-related signatures */
	}
		while (--offset > ceil_offset && !is_dir_sep(dir->buf[offset]))
static int inside_work_tree = -1;
		die(_("unable to set up work tree using invalid config"));
		error_code = READ_GITFILE_ERR_INVALID_FORMAT;
int git_config_perm(const char *var, const char *value)

	clear_repository_format(&repo_fmt);
{
	return setup_git_directory_gently(NULL);
	 * a chmod value to restrict to.
	string_list_clear(&format->unknown_extensions, 0);

			free(sanitized);
	startup_info->have_repository = 1;
	 * let maybe_die_on_misspelt_object_name() even trigger.
	clear_repository_format(format);
		*nongit_ok = 1;
	 * GIT_DIR values at some point in the future.
		return;
	}
	 * x flags for directories are handled separately.
	}
	/* Check non-worktree-related signatures */
		git_config_from_file(read_worktree_config, sb.buf, candidate);
	if (gitdirenv) {
	}
	if (check_repository_format_gently(".", repo_fmt, nongit_ok))
		const char *ret;
	strbuf_addstr(&path, "HEAD");
	strbuf_addstr(path, ".git");

			die_errno(_("cannot come back to cwd"));

		}
	return 0;
	}
	 * - ../.git
		die(_("problem with core.sharedRepository filemode value "
			gitdir = to_free = real_pathdup(gitdir, 1);
		return PERM_EVERYBODY;
		if (!strcmp(".", gitdir->buf + gitdir_offset))
	else if (skip_prefix(var, "extensions.", &ext)) {
		for (i = 0; i < format->unknown_extensions.nr; i++)
	ret = 1;
		return PERM_UMASK;
			/* work tree is the root, or the whole path */
		set_git_dir(gitdirenv, 0);
			is_bare_repository_cfg = candidate->is_bare;
		data->is_bare = git_config_bool(var, value);
	case READ_GITFILE_ERR_OPEN_FAILED:
	len = path.len;
	set_repository_format_partial_clone(candidate->partial_clone);
		} else if (path[wtlen - 1] == '/' || path[wtlen] == '\0') {
	/* #3, #7, #11, #15, #19, #23, #27, #31 (see t1510) */
	struct stat st;

			die_errno(_("failed to read %s"), path.buf);
 * subsequent entries.

		 * this value, fallthrough to BUG. Otherwise it is possible to
	 * - .git (file containing "gitdir: <path>")
	if (is_absolute_path(orig)) {
		die_errno(_("Unable to read current working directory"));
	 * if $GIT_WORK_TREE is set relative
		if (!nongit_ok)
	 * backslash even though it's a glob special; by itself it doesn't
		return setup_explicit_git_dir(gitdir, cwd, repo_fmt, nongit_ok);
	free(format->work_tree);
	return format->version;
			data->precious_objects = git_config_bool(var, value);
	 * For historical use of check_repository_format() in git-init,
	/*
 * diagnosis when dying upon finding that "name" is not a pathname.
		if (path[wtlen] == '/') {
				    data.buf[data.len - 1] == '\r'))

	len = strlen(path);
static const char *setup_discovered_git_dir(const char *gitdir,
	 * - ../.git/
	int ret = 0;
 */
		return 1; /* file exists */
	free(gitfile);
		 * we fall through to recording it as unknown, and
			memmove(path, path + wtlen + 1, len - wtlen);
	GIT_DIR_EXPLICIT,
	if (nongit_ok)
		strbuf_addstr(&path, "/objects");
					    struct strbuf *cwd, int offset,
		return 0;
	static int initialized = 0;
	if (fd > 2)
		if (access(path.buf, X_OK))
	if (work_tree_config_is_bogus)

	 * wildcard characters.
 *
/*
		*return_error_code = error_code;
	switch (setup_git_directory_gently_1(&dir, &gitdir, 1)) {
	strbuf_release(&sb);
		ret = setup_explicit_git_dir(gitdir, cwd, repo_fmt, nongit_ok);
	return 0;
 * A "string_list_each_func_t" function that canonicalizes an entry
 *  ../../sub1/sub2/foo -> sub1/sub2/foo (but no remaining prefix)
			if (*p == '\\')
	return NULL;
	char *buf = NULL;
	if (return_error_code)
	else if (is_bare_repository_cfg > 0) {
	if (strbuf_getcwd(&dir))

	 * We may have read an incomplete configuration before
	int gitfile_error;
	gitdirenv = getenv(GIT_DIR_ENVIRONMENT);
	offset = dir_inside_of(cwd->buf, worktree);
		clear_repository_format(&candidate);
	if (len != st.st_size) {
