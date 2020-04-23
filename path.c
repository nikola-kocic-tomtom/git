 * trailing slashes (except for the root directory, which is denoted by "/").
			  struct strbuf *sb)
	}
/*

 * allowed.
static int do_submodule_path(struct strbuf *buf, const char *path,
		   in_off < in_len) {
	while (i < prefix_len && j < in_len && prefix[i] == in[j]) {
{
 * | logs/refs/bisect/a | /refs/bisect/a | logs             | as per fn    |
	strbuf_cleanup_path(&sb);
			*prefix_len = dst - dst0;
	{ 0, 0, 1, "shallow" },
 * | logs               | \0             | logs             | as per fn    |
		check_repository_format(NULL);
	if (!the_repository->different_commondir)
}
	va_end(args);
 * The key is partially normalized: consecutive slashes are skipped.
	int i;
const char *worktree_git_path(const struct worktree *wt, const char *fmt, ...)
 * For performance reasons, _all_ Alternate Data Streams of `.git/` are
			dst--;
		update_common_dir(buf, git_submodule_dir.len, git_submodule_common_dir.buf);
	for (;;) {
		} else if (in[j] != prefix[i]) {
		return 0;
 * | logstore           | not called     | n/a              | -1           |
		int len = strlen(path);
					src++;
		return -1;
 * component anytime during the normalization. Otherwise, returns success (0).


			while (is_dir_sep(in[j]))

 * (2) "~user/path" to mean path under named user's home directory;
		add_to_trie(&common_trie, p->path, p);
 * prefix is common.
	/*
	 * further.
			len = 0; /* root matches anything, with length 0 */
				return 0;

		if (is_dir_sep(prefix[i])) {
	strbuf_complete(&git_submodule_dir, '/');
	va_list args;
			return NULL;
const char *relative_path(const char *in, const char *prefix,
		die(_("Could not make %s writable by group"), dir);
 * children.  If value is not NULL, the trie node is a terminal node.
	struct strbuf path = STRBUF_INIT;
}
		len = readlink(path, buffer, sizeof(buffer)-1);
#include "submodule-config.h"
				while (is_dir_sep(*src))
	struct trie *children[256];
int is_ntfs_dotgitignore(const char *name)

 * ancestor directory, excluding any trailing slashes, or -1 if no prefix
	return pw;

		 * sanity check on untrusted input.
				return -1;
static void strbuf_worktree_gitdir(struct strbuf *buf,
	return sb;
 * path = Canonical absolute path
	void *old;
	va_end(args);
			return -1;
char *xdg_config_home(const char *filename)
 * definition
	va_end(args);
}
}
	char *contents;
		 */
		 */
				   const struct repository *repo,
		 * Split this node: child will contain this node's
			return 0;
/* strip arbitrary amount of directory separators at end of path */
	va_list args;
	strbuf_vaddf(buf, fmt, args);

	if (get_shared_repository() < 0)
 * positive, then return its return value.  If fn returns negative,
		strbuf_add(&validated_path, path, len);
	{ 0, 1, 1, "svn" },
	if (path_len && !is_dir_sep(path[path_len - 1]))
	int err;

	{ 1, 0, 1, "gc.pid" },
	while (is_dir_sep(*src))
}
}
			} else if (src[1] == '.') {
			if (c != ' ' && c != '.')
		old = root->value;
	{ 0, 1, 1, "remotes" },
	} else if (c == 'g' || c == 'G') {
		if (dst <= dst0)
			while (is_dir_sep(prefix[i]))
	gitdir_len = buf->len;
			c = '/';
		j++;
}
			return -1;

	else
	 * sl becomes true immediately after seeing '/' and continues to
	va_end(args);
{
		while ((1 < len) && (path[len-1] == '/'))
const char *git_path(const char *fmt, ...)
	/* Clean it up */
	err = do_submodule_path(buf, path, fmt, args);
static int trie_find(struct trie *root, const char *key, match_fn fn,
		while (isspace(*refname))
	new_mode = calc_shared_perm(old_mode);
 * are common to all elements with this prefix, optionally followed by some
 * part before suffix (sans trailing directory separators).
	{ 1, 1, 1, "logs" },
}
		return 0;
{

		else
			report_garbage(PACKDIR_FILE_GARBAGE, sb.buf);
const char *enter_repo(const char *path, int strict)
	va_list args;
	 */
	int i;
	if (!in_len)
	if (err) {
{
		if (c == '.') {
		size_t username_len = first_slash - username;
	}
 * This function is intended to be used by `git fsck` even on platforms where

	struct stat st;
	if (child)
	}
				j++;
	init_common_trie();

		}
		}
	struct common_dir *dir = value;
	else
	va_end(args);
char *git_pathdup_submodule(const char *path, const char *fmt, ...)
static struct passwd *getpw_str(const char *username, size_t len)
	int result;

	strbuf_cleanup_path(buf);
 *
/*
		if (len == 1 && ceil[0] == '/')
		if (root->contents[i] == key[i])
	strbuf_vaddf(buf, fmt, args);
 * returned path.
					/* reject //, /./ and /../ */
			if (real_home)
	va_start(args, fmt);
	ssize_t len;
}
	buffer[len] = '\0';
			strbuf_reset(&used_path);
			perror(dir);


	if (!repo->worktree)
	child = root->children[(unsigned char)*key];

		} else if (!c)
 *   to `.git/`.
		return 0;
			}
		   /* "in" not end with '/' */
		tweak = -get_shared_repository();
		} else {
		/* Partial path normalization: skip consecutive slashes. */
	int is_abs1, is_abs2;
	va_start(args, fmt);
			chmod(path, (new_mode & ~S_IFMT)) < 0)
				}
{
	int has_lock_suffix = strbuf_strip_suffix(buf, LOCK_SUFFIX);
			continue;
				   const struct worktree *wt)
	const char *end;
		set_git_dir(".", 0);

		strbuf_remove(sb, 0, path - sb->buf);
	sl = 1; ndot = 0;

}
	return NULL;
 * Unless "strict" is given, we check "%s/.git", "%s", "%s.git/.git", "%s.git"
{
 * | key                | unmatched      | prefix to node   | return value |
 * Give path as relative to prefix.
	     * (i.e. prefix not end with '/')
		strbuf_release(&buf);
	if (lstat(path, &st) < 0)
	} else
		tweak |= (tweak & 0444) >> 2;
	va_end(args);
int is_ntfs_dotgitattributes(const char *name)
		 * A path component that begins with . could be
	}
	 * be true as long as dots continue after that without intervening
		goto only_spaces_and_periods;
		/* bypass dos_drive, for "c:" is identical to "C:" */
 * /-terminated prefix with a value left, then return the negative
	do_git_common_path(the_repository, pathname, fmt, args);
			path++;
			if (!src[1]) {
	key += i;
	return (char *)cleanup_path(buf);
	return NULL;
		char ch = *p++;
}
		if (is_dir_sep(prefix[i])) {
	}
 * If all goes well, we return the directory we used to chdir() (but
	unsigned len;
#include "worktree.h"
 */
			return in;
		buf->buf[newlen] = '/';
		/* End of key */
					return -1;
	len = read_in_full(fd, buffer, sizeof(buffer)-1);
 *

	index = (index + 1) % ARRAY_SIZE(pathname_array);
/*
		return -1;
	{ 0, 1, 0, "refs/worktree" },
 * if path is NULL.
	struct trie *child;
		/* we have reached the end of the key */
		 * (3) ".." and ends  -- strip one and terminate.
}
			    const struct repository *repo,
	    /* "/foo" is not a prefix of "/foobar" */
			return NULL;
{
 * def
 * - Removes ".." components, and the components the precede them.
 * canonical form: empty components, or "." or ".." components are not
					src += 3;
	{ 0, 0, 0, "info/sparse-checkout" },
		return in;
		const char *first_slash = strchrnul(path, '/');
	 */
{
	    /* "prefix" seems like prefix of "in" */
		adjust_git_path(repo, buf, gitdir_len);
			*dst++ = c;
	 * done in <435560F7.4080006@zytor.com> thread, now enter_repo()
				src++;
 * Returns failure (non-zero) if a ".." component appears as first path
	while (is_dir_sep(in[j]))
				   dotgit_ntfs_shortname_prefix);

				if (ndot < 3)
	do_git_path(the_repository, NULL, sb, fmt, args);
		const char *path = p->path;
	va_start(args, fmt);
/*
	if (get_common_dir_noenv(&git_submodule_common_dir, git_submodule_dir.buf))
			return 0;
			/* in="/a/b", prefix="/a/b/c/" */
	return ret;
 *   `.git` is the first item in a directory, therefore it will be associated
 *
	for (i = 0, saw_tilde = 0; i < 8; i++)
	new_node->value = value;
	int tweak;
	else if (share && adjust_shared_perm(dir))

	strbuf_addstr(sb, in);
 * First, one directory to try is determined by the following algorithm.
}
static void do_worktree_path(const struct repository *repo,
		}
	struct strbuf *sb = &pathname_array[index];
	static struct strbuf validated_path = STRBUF_INIT;
		return -1;
{
 * - Squashes sequences of '/' except "//server/share" on Windows

	int fd;
			else
	return err;
		     void *baton)
	int gitdir_len;
}
const char *mkpath(const char *fmt, ...)
		return result;
	struct common_dir *p;
	/*
		if (name[i] == '\0')
		continue;
	root->value = value;

	/*
	struct strbuf git_submodule_dir = STRBUF_INIT;

	return 0;
		char c = *src++;
 * backlash characters in the provided `name` specially: they are interpreted
	strbuf_release(&sb);

/* Returns 0 on success, negative on failure. */
	va_start(args, fmt);
	while (key[0] == '/' && key[1] == '/')
	struct strbuf *pathname = get_pathname();
			return 0;
	va_list args;
		if (root->value)

		}

 * root: len = 0, children a and d non-NULL, value = NULL.

	va_start(args, fmt);
 * then it is a newly allocated string. Returns NULL on getpw failure or
		/* Copy read bits to execute bits */
			saw_tilde = 1;
	if (!dir->is_dir && unmatched[0] == 0)
	strbuf_release(&git_submodule_common_dir);
		return -1;
 *
		if (errno != EEXIST) {
			sl = 1;
		 * (4) "../"          -- strip one, eat slash and continue.
	strbuf_addbuf(buf, &git_submodule_dir);
	strbuf_cleanup_path(buf);
		/* we have reached the end of the key */
			    const char *fmt, ...)

 */
	va_list args;
				if (0 < ndot && ndot < 3)
			}

	 * https://en.wikipedia.org/wiki/8.3_filename?
	else if (!strcmp(base, "index"))
int looks_like_command_line_option(const char *str)
	else {
 */
		int i;

	va_start(args, fmt);
		dst--;	/* go to trailing '/' */

 *   automatically trimmed. Therefore, `.git . . ./` is a valid way to refer
		strbuf_addch(buf, '/');
/*
	}
		if (c != '.' && c != ' ')
			if (!newpath)
{
		if (chdir(path))
	int newlen = strlen(newdir);
		} else {

 *
	 * does not do getcwd() based path canonicalization.
	if (home)
	va_end(args);
		goto cleanup;
		if (is_dir_sep(c))
}

 * Return a string with ~ and ~user expanded via getpw*.  If buf != NULL,
		replace_dir(buf, git_dir_len + 7, repo->objects->odb->path);
static void update_common_dir(struct strbuf *buf, int git_dir_len,
	dst0 = dst;
 * | logs/refs          | /refs          | logs             | as per fn    |
char *strip_path_suffix(const char *path, const char *suffix)
			struct stat st;
	{ 0, 1, 1, "rr-cache" },
				c = *src++;
 * prefix that has not been overridden by user pathspec.
{
}
	if (!(mode & S_IWUSR))

		strbuf_add(&used_path, path, len);
		child = root->children[(unsigned char)key[root->len]];
			if (!stat(used_path.buf, &st) &&
	if (strncmp(buf, dir, len) || !is_dir_sep(buf[len]))
		 * go up one level.
{
	len = vsnprintf(buf, n, fmt, args);
	return strbuf_detach(&path, NULL);
/*
	if (path > sb->buf)
 *
			continue;
 *
}
	int in_len = in ? strlen(in) : 0;
cleanup:
	if (!strncasecmp(name, dotgit_name, 6) && name[6] == '~' &&
	 * followed by ~1, ... ~4?
 * is an ancestor.  (Note that this means 0 is returned if prefixes is
		*dst++ = c;
	if (!p || (*p != '/' && *p != '~'))

}
{
int strbuf_git_path_submodule(struct strbuf *buf, const char *path,

			return NULL;
static const char *cleanup_path(const char *path)
		key++;
		new_mode |= FORCE_DIR_SET_GID;
static void do_git_path(const struct repository *repo,
		root->len = i;
}
		}
	unsigned is_dir:1;
	else if (!prefix_len)
static void replace_dir(struct strbuf *buf, int len, const char *newdir)
		if (username_len == 0) {
		return buf;
 * definite
			make_trie_node(key + i + 1, value);

			      const char *common_dir)

	do_git_path(repo, NULL, &path, fmt, args);
	new_node->len = strlen(key);
	struct stat st;
 *   format (up to eight characters for the basename, three for the file
	struct strbuf *pathname = get_pathname();
	    /* "/foo" is a prefix of "/foo" */

 *
	if (key[i]) {
		if (p->ignore_garbage)
	return pathname->buf;
}
	       (!is_abs1 && !is_abs2);
		new_mode |= (new_mode & 0444) >> 2;
				return 0;
		const char *gitfile;
	}
				} else if (is_dir_sep(src[2])) {
		return;
{
REPO_GIT_PATH_FUNC(cherry_pick_head, "CHERRY_PICK_HEAD")
		i = len + 1;
		else

}
			       va_list args)
	assert(filename);
	if (!strcmp(path, "/"))

			/* in="/a/b/c", prefix="/a/b" */
		else if (ch == '/') {
			/* in="/a/b", prefix="/a/b" */
	return pathname->buf;
	if (!*key) {
			while (is_dir_sep(c))
	}
	va_list args;
		} else if (is_dir_sep(in[j])) {
		else if (!strncmp(path, ceil, len) && path[len] == '/')
			if (name[++i] < '1' || name[i] > '9')
{

	do_git_path(repo, NULL, sb, fmt, args);
			else
	 */
		/* git ~1 */
 * name refers to a `.git` file or directory, or to any of these synonyms, and
 *
				      strlen(newpath));

			struct passwd *pw = getpw_str(username, username_len);
 *    a: len = 2, contents = bc, value = (data for "abc")
 *
			return 0;
			else if (ch == '/') {
			return NULL;

		strbuf_addstr(buf, repo->commondir);

	if (!*key) {
	if (skip_prefix(path, "./", &path)) {
#include "string-list.h"
		strbuf_addstr(&buf, in + j);
#include "object-store.h"
			while (is_dir_sep(prefix[i]))
	{ 0, 1, 1, "lost-found" },
 * are not considered to be their own ancestors.  path must be in a
{
int daemon_avoid_alias(const char *p)
 * then call fn with the next-longest /-terminated prefix of the key
				  const char *dotgit_ntfs_shortname_prefix)

	return path;
			return 0;
	struct passwd *pw;
	}
};
	char buffer[256];
}
 * - For yet other historical reasons, NTFS supports so-called "Alternate Data
{
 *           e: len = 0, children all NULL, value = (data for "definite")
 * On NTFS, we need to be careful to disallow certain synonyms of the `.git/`

	return str && str[0] == '-';
 */
	{ 0, 1, 0, "logs/refs/rewritten" },
		root->children[(unsigned char)key[i]] =
		if (is_dir_sep(c)) {
 *
 */
	if (!wt)
		if (gitfile) {
int is_ntfs_dotgitmodules(const char *name)
	if (need_sep)
 * Returns true if the path ends with components, considering only complete path
};
				return 1;
		if (PATH_MAX <= len)
	{ 0, 1, 1, "info" },
	if (is_git_directory(".")) {

		else if (saw_tilde) {

				/* (1) */
 * ["/"].) "/foo" is not considered an ancestor of "/foobar".  Directories

	va_list args;
 * portion of the key and the found value.  If fn returns 0 or
 * For example, consider the trie containing only [logs,
	if (get_st_mode_bits(path, &old_mode) < 0)
 * abc
 * logs/refs/bisect], both with values, but not logs/refs.
			while (is_dir_sep(in[j]))

	}
		static const char *suffix[] = {
	char *base = buf->buf + git_dir_len;
		!is_dir_sep(newdir[newlen - 1]);
					/* reject /.$ and /..$ */
	int sl, ndot;
	return strbuf_detach(&user_path, NULL);
 * If real_home is true, strbuf_realpath($HOME) is used in the expansion.
		}
			       const char *fmt, ...)
	is_abs1 = is_absolute_path(path1);
				goto return_null;
			len--;
	}
	return -1;
		len--;	 /* keep one char, to be replaced with '/'  */
 * Note that this function is purely textual.  It does not follow symlinks,
			    struct strbuf *buf, int git_dir_len)
}
	if (!prefix || !prefix[0])
{
			if (!pw)
	if (have_same_root(in, prefix))
 * The trie would look like:
	return mode;
static void *add_to_trie(struct trie *root, const char *key, void *value)
		}
		return -2;
	va_start(args, fmt);
				/* (2) */
	 * Anything else, just open it and try to see if it is a symbolic ref.
 *
		while ((c = *src++) != '\0' && !is_dir_sep(c))
	while (len && is_dir_sep(path[len - 1]))

				i++;
 * prefix_len is reduced. In the end prefix_len is the remaining
{

	{ 0, 1, 1, "objects" },
		if (prefix_len && *prefix_len > dst - dst0)
	close(fd);
	int in_off = 0;
static int is_ntfs_dot_generic(const char *name,

	const char *refname;
		child->len = root->len - i - 1;

static struct trie common_trie;
 * Inline helper to make sure compiler resolves strlen() on literals at
static ssize_t stripped_path_suffix_offset(const char *path, const char *suffix)
			return 1;
	   )
			}
	char c;
			in_off = j;
{
 * except DWIM suffixing.
		return 0;

{
	strbuf_cleanup_path(buf);
		    ((c = *(name++)) != 'i' && c != 'I') ||
	int len = strlen(dir);
	if (
 * Determines, for each path in prefixes, whether the "prefix"
	do_git_common_path(repo, sb, fmt, args);
 */
 */

	if (dir->is_dir && (unmatched[0] == 0 || unmatched[0] == '/'))

	else {

	va_start(args, fmt);
int normalize_path_copy(char *dst, const char *src)
		else if (path[--path_len] != suffix[--suffix_len])
		int len = strlen(ceil);
			strbuf_setlen(&used_path, baselen);
	va_end(args);
		return -1;

#include "repository.h"
	return 0;
		    ((c = *(name++)) != 't' && c != 'T') ||
	static int index;
	if(buf->len && !is_dir_sep(buf->buf[buf->len - 1]))
		child = xmalloc(sizeof(*child));
		 * special:

			      const char *fmt, ...)
REPO_GIT_PATH_FUNC(merge_msg, "MERGE_MSG")
 *       i: len = 3, contents = nit, children e and i non-NULL, value = NULL
 */
	va_start(args, fmt);

		strbuf_addch(buf, '/');
	int len;
void safe_create_dir(const char *dir, int share)
	/* Not considered garbage for report_linked_checkout_garbage */
 * Add a key/value pair to a trie.  The key is assumed to be \0-terminated.
		/* copy up to the next '/', and eat all '/' */


			in_off = in_len;
/*
	va_list args;
			return 0;
				if (!src[2]) {
/* $buf =~ m|$dir/+$file| but without regex */
		tweak = get_shared_repository();
{

		if (j >= in_len) {
			char *newpath = expand_user_path(used_path.buf, 0);
		 * (1) "." and ends   -- ignore and terminate.
	 */
return_null:
	else if (repo->different_commondir)
}
	if (get_shared_repository() < 0)
		strbuf_splice(buf, 0, buf->len,
			prefix_off = i;
		strbuf_addstr(buf, repo->gitdir);
			convert_slashes(user_path.buf);
		return NULL;

		return mkpathdup("%s/.config/git/%s", home, filename);

			in_off = in_len;

		child->value = root->value;

	    prefix_off < prefix_len) {
 * forbidden, not just `::$INDEX_ALLOCATION`.
		 */
		};
}
			return -1;
REPO_GIT_PATH_FUNC(squash_msg, "SQUASH_MSG")
}
	}
	strbuf_addstr(&user_path, to_copy);
			continue;
struct trie {
	}
	}
	int len;
	 * This resurrects the belts and suspenders paranoia check by HPA

		   /* "in" is short than "prefix" */
	}
 * | logs/refs/bisect   | \0             | logs/refs/bisect | as per fn    |
		} else if (tolower(name[i]) != dotgit_ntfs_shortname_prefix[i])

 * | logs/refs/b        | /refs/b        | logs             | as per fn    |
	va_end(args);

	if (result >= 0 || (*key != '/' && *key != 0))

	va_end(args);
				ndot++;
					/* (3) */
						   child->len);
			return fn(key, root->value, baton);
		return;
	unsigned ignore_garbage:1;

static struct strbuf *get_pathname(void)
			}
/*
	int i, max_len = -1;
			char c = name[i++];
	if (ret)
		}
		c = *(name++);

	}
	do_worktree_path(repo, sb, fmt, args);

		}
		strbuf_setlen(&sb, len);
		 * dst0..dst is prefix portion, and dst[-1] is '/';
		gitfile = read_gitfile(used_path.buf);
	}
{
	/*
}
	}
{
						src++;
 *   with the short name `git~1` (unless short names are disabled).
}
 * - Removes "." components.
			in_off = j;
{
	p++;
	    !is_dir_sep(prefix[i-1]) && !is_dir_sep(in[j])
 */
	return sb->buf;
{

		return -1;
	if (S_ISLNK(st.st_mode)) {
	return strbuf_detach(&path, NULL);
		if (len > max_len)
			continue; /* no match */

	strbuf_addstr(buf, repo->commondir);
	return is_ntfs_dot_str(name, "gitignore", "gi250a");
		if (is_dir_sep(path[path_len - 1])) {

	if (cache_home && *cache_home)

	if (mkdir(dir, 0777) < 0) {
	char *username_z = xmemdupz(username, len);
}
#endif
}

static int calc_shared_perm(int mode)
{
	else if (git_hooks_path && dir_prefix(base, "hooks"))
	if (mode & S_IXUSR)
	err = do_submodule_path(&buf, path, fmt, args);

	return is_ntfs_dot_generic(name, dotgit_name, strlen(dotgit_name),
 *
	if (trie_find(&common_trie, base, check_common, NULL) > 0)
 * no such prefix, return -1.  Otherwise call fn with the unmatched
static void do_git_common_path(const struct repository *repo,
		return -1;
void strbuf_repo_worktree_path(struct strbuf *sb,
	if (!strict) {

 * prefix of the key for which the trie contains a value.  If there is
	return stripped_path_suffix_offset(path, components) != -1;
{
 * separators), and -1 otherwise.

	va_start(args, fmt);
		return NULL;
	{ 0, 1, 1, "hooks" },

			       size_t len,
	int path_len = strlen(path), suffix_len = strlen(suffix);

			     const char *fmt, va_list args)
 */
}
	else if (!wt->id)

	return normalize_path_copy_len(dst, src, NULL);
		}
	}
	else
		if (is_dir_sep(prefix[i])) {
			*dst++ = '/';
{
		    *(name++) != '~' ||
	va_start(args, fmt);
	{ 1, 0, 0, "logs/HEAD" },
	strbuf_vaddf(buf, fmt, args);

}
			"/.git", "", ".git/.git", ".git", NULL,
	 *
only_spaces_and_periods:
 * prefixes = string_list containing normalized, absolute paths without
	strbuf_addstr(buf, repo->worktree);
		strbuf_addch(buf, '/');
	return old;
	const char *home, *cache_home;
	do_git_path(the_repository, NULL, pathname, fmt, args);


		if (!c || c == '\\' || c == '/' || c == ':')
static int check_common(const char *unmatched, void *value, void *baton)
 * (0) If "strict" is given, the path is used as given and no DWIM is

	/* Belongs to the common dir, though it may contain paths that don't */
char *git_path_buf(struct strbuf *buf, const char *fmt, ...)
}
			return 0;
	goto only_spaces_and_periods;
 *   Which means that `git~1/` is a valid way to refer to `.git/`.

{
	}
	};
	va_list args;
	if (!get_shared_repository())
			max_len = len;
		if (is_dir_sep(prefix[i])) {
	while (prefix[i]) {

	struct strbuf sb = STRBUF_INIT;
 */
	/*
		new_node->contents = xmalloc(new_node->len);
{
 * | logs/refs/bisect/a | /a             | logs/refs/bisect | as per fn    |
 * directory:
	int prefix_len = prefix ? strlen(prefix) : 0;
		while (*path == '/')
char *repo_worktree_path(const struct repository *repo, const char *fmt, ...)
			return add_to_trie(child, key + root->len + 1, value);
		char c = *src;
			 * We know our needles contain only ASCII, so we clamp
#include "strbuf.h"
	struct trie *new_node = xcalloc(1, sizeof(*new_node));
		}
}
 */
	if (S_ISDIR(old_mode)) {
			while (is_dir_sep(prefix[i]))
static inline int is_ntfs_dot_str(const char *name, const char *dotgit_name,
	{ 0, 0, 1, "config" },
			return -1;

		}
		root->value = value;
			return -1;

			strbuf_addstr(&user_path, pw->pw_dir);
	return NULL;
	strbuf_splice(buf, 0, len, newdir, newlen);
			       const struct repository *repo,
			if (name[i] < '0' || name[i] > '9')

	va_start(args, fmt);
	struct strbuf *pathname = get_pathname();
	 */
	 */
 *   `.git::$INDEX_ALLOCATION/`.
	if (i >= prefix_len) {
 * chdir() to it. If none match, or we fail to chdir, we return NULL.
	else
			 * here to make the results of tolower() sane.
/*
		return "./";

	}
	if (lstat(path, &st) < 0)
	    i >= prefix_len &&


}
	return strbuf_detach(&path, NULL);
		strbuf_reset(&validated_path);
{
static inline int chomp_trailing_dir_sep(const char *path, int len)
 * | logs/refs/bisect/  | /              | logs/refs/bisect | as per fn    |
	return strbuf_detach(&buf, NULL);
static int have_same_root(const char *path1, const char *path2)
			return -1;
	if (
		if (gitfile)
		len--;
			const struct worktree *wt, struct strbuf *buf,
		mode |= tweak;
	{ 0, 1, 0, "logs/refs/worktree" },
}
		i++;

static void init_common_trie(void)
		strbuf_addstr(&sb, path);
 * Otherwise returns NULL.
{
		return;
/*
				i++;
			return 0;
 * Get relative path by removing "prefix" from "in". This function
}
		if (!in_len)
/*
	ssize_t offset = stripped_path_suffix_offset(path, suffix);
 */
 *   short name `git~1` were already used. In Git, however, we guarantee that

 * Helper function for update_common_dir: returns 1 if the dir
 * end with a '/', then the callers need to be fixed up accordingly.
	return chomp_trailing_dir_sep(path, path_len);
 *     done. Otherwise:
static int is_dir_file(const char *buf, const char *dir, const char *file)
		return NULL;
 * verify the existence of the path, or make any system calls.
			 */
 *
		return NULL;
 * components, and false otherwise.
#include "dir.h"
 * | (If fn in the previous line returns -1, then fn is called once more:) |
		return -1;
	strbuf_vaddf(pathname, fmt, args);

			return 0;
	if (skip_prefix(buffer, "ref:", &refname)) {
	}
 *
				return NULL;
	va_end(args);

			strbuf_addstr(sb, "../");
 * If path ends with suffix (complete path components), returns the
				break;
			  const char *fmt, ...)
	strbuf_vaddf(&sb, fmt, args);
			} else if (is_dir_sep(src[1])) {

	for (p = common_list; p->path; p++)
 * to increase performance when traversing the path to work_tree.
	const struct common_dir *p;
				ndot = 0;
		for (i = 0; suffix[i]; i++) {
/*
			       const char *fmt,
	*mode = st.st_mode;
 * |--------------------|----------------|------------------|--------------|
		return in;
	    in[j] &&
{
{
		} else {
	return 0;

		}
				return 0;
	c = *(name++);
			break;
REPO_GIT_PATH_FUNC(revert_head, "REVERT_HEAD")
	int i = 0, j = 0;
}
			return 0;
	pw = getpwnam(username_z);
					goto up_one;
REPO_GIT_PATH_FUNC(merge_head, "MERGE_HEAD")
}
		memcpy(new_node->contents, key, new_node->len);
			    (S_ISREG(st.st_mode) ||
		return mkpathdup("%s/git/%s", cache_home, filename);

}
			const char *fmt, va_list args)
			       const char *dotgit_ntfs_shortname_prefix)
 * the size of the path, but will never grow it.
			if (ch == '.')
		return in;
	if (!in[j])

		return mkpathdup("%s/git/%s", config_home, filename);
 *    d: len = 2, contents = ef, children i non-NULL, value = (data for "def")
	do_git_path(the_repository, NULL, &path, fmt, args);
		else if (ch == 0)
	else

/*
	return is_ntfs_dot_str(name, "gitattributes", "gi7d29");
}
		}
		j++;
	 * return immediately in those cases, without looking at `name` any

{
 * handle its return value the same way.  If there is no shorter
		if (((c = *(name++)) != 'g' && c != 'G') ||
	strbuf_reset(sb);
	else
	if (is_dir_file(base, "info", "grafts"))
{
	if (!*key) {
	struct trie *child;
	int err;
			if (!is_dir_sep(suffix[suffix_len - 1]))
	strbuf_reset(buf);
	while (1) {
		if (!path_len)
	 * Is it a regular NTFS short name, i.e. shortened to 6 characters,
				return 0;
	{ 0, 0, 1, "packed-refs" },

		 * (2) "./"           -- ignore them, eat slash and continue.
static struct trie *make_trie_node(const char *key, void *value)

		const char *username = path + 1;

 * Search a trie for some key.  Find the longest /-or-\0-terminated
			while (is_dir_sep(in[j]))
		return path;
	} else if (
		result = trie_find(child, key + 1, fn, baton);
		}
 * - For other historical reasons, file names that do not conform to the 8.3
	while (suffix_len) {
	strbuf_addf(&sb, "%s/", get_git_dir());
	 */
{
 * - Ensures that components are separated by '/' (Windows only)
 * (i.e. a parent directory) for which the trie contains a value, and
			      repo->graft_file, strlen(repo->graft_file));
	unsigned is_common:1;
{
		    *(name++) != '1')
	strbuf_vaddf(buf, fmt, args);
	struct strbuf user_path = STRBUF_INIT;
					while (is_dir_sep(*src))
}
	if (!path)

 * (1) "~/path" to mean path under the running user's home directory;
		while (dst0 < dst && dst[-1] != '/')
		} else if (i >= 6)

	{ 0, 1, 0, "refs/rewritten" },
	{ 0, 1, 1, "refs" },
		strbuf_reset(&used_path);
REPO_GIT_PATH_FUNC(fetch_head, "FETCH_HEAD")
		strbuf_addstr(buf, LOCK_SUFFIX);
}
/*
	return buf->buf;
#include "lockfile.h"

 *

		 */
	static struct strbuf buf = STRBUF_INIT;
			  const struct repository *repo,
typedef int (*match_fn)(const char *unmatched, void *value, void *baton);
{
	{ 0, 1, 1, "common" },
		if (key[i] == '/' && key[i+1] == '/') {
		else if (name[i] & 0x80) {
};

	do_worktree_path(repo, &path, fmt, args);
	cache_home = getenv("XDG_CACHE_HOME");
 *              value = (data for "definition")
			return NULL;

 * as directory separators.
		/* Windows: dst[-1] cannot be backslash anymore */
{
{
	free(username_z);
	strbuf_reset(sb);
	 * Is this a detached HEAD?

	/* Make sure it is a "refs/.." symlink */
	return max_len;
 */
static int common_trie_done_setup;
		(is_dir_sep(buf[len]) || buf[len] == '\0');
		strbuf_addstr(sb, "../");
		} else {

		else
static struct common_dir common_list[] = {
		if (root->value && !root->len)
 * Git should therefore not track it.
 * - For historical reasons, file names that end in spaces or periods are
		memcpy(child->children, root->children, sizeof(root->children));
 * For example, consider the following set of strings:
#include "cache.h"
{

		memset(root->children, 0, sizeof(root->children));
 * the last character in the path before the suffix (sans trailing directory
 *   type for directories, allowing `.git/` to be accessed via
	return NULL;
	if (need_sep)
	return is_ntfs_dot_str(name, "gitmodules", "gi7eba");
 *
 * return value of the most recent fn invocation.
		len++;
		else
					/* (4) */
	config_home = getenv("XDG_CONFIG_HOME");
		strlcpy(buf, bad_path, n);
	is_abs2 = is_absolute_path(path2);
{
		}

}
		if (sl) {
char *repo_git_path(const struct repository *repo,
	strbuf_grow(sb, in_len);
	if (fd < 0)
{
{
 *   extension, certain characters not allowed such as `+`, etc) are associated
			else if (ch == 0) {
	int ret;
	if ((name[0] == '.' && !strncasecmp(name + 1, dotgit_name, len))) {
	va_end(args);
	     */
 * links.  User relative paths are also returned as they are given,
 *
{
		replace_dir(buf, git_dir_len + 5, git_hooks_path);
		} else if (name[i] == '~') {
			suffix_len = chomp_trailing_dir_sep(suffix, suffix_len);
int longest_ancestor_length(const char *path, struct string_list *prefixes)
	    /*
			/* in="/a/bbb/c", prefix="/a/b" */
			continue;
					return -1;
int adjust_shared_perm(const char *path)
{
	do_git_path(the_repository, wt, pathname, fmt, args);
 *   Streams", i.e. metadata associated with a given file, referred to via
	{ 0, 1, 1, "branches" },
	static struct strbuf used_path = STRBUF_INIT;
	if (!get_oid_hex(buffer, &oid))
					goto up_one;

	 * Copy initial part of absolute path: "/", "C:/", "//server/share/".
 * in this order. We select the first one that is a valid git repository, and
}
#include "packfile.h"
				strbuf_addstr(&user_path, home);
REPO_GIT_PATH_FUNC(merge_mode, "MERGE_MODE")
		mode = (mode & ~0777) | tweak;
		STRBUF_INIT, STRBUF_INIT, STRBUF_INIT, STRBUF_INIT
	old = root->value;
	/*
 *

			strbuf_addstr(&used_path, gitfile);
 * A simpler implementation of relative_path

			path = gitfile;
	va_list args;
 * (4) "/absolute/path" to mean absolute directory.
 * is an ancestor directory of path.  Returns the length of the longest
{


 * | a                  | not called     | n/a              | -1           |
{
	return !strncmp(buf, dir, len) &&
	return buf.buf;
	/*
 * prefix_len != NULL is for a specific case of prefix_pathspec():
		/* Copy read bits to execute bits */
		if (child) {
	/*
	 * advanced partway through the string. That's okay, though, as we
		if (chdir(used_path.buf))
			if (!is_dir_sep(in[j]))
static char bad_path[] = "/bad-path/";
				continue;
	if (((old_mode ^ new_mode) & ~S_IFMT) &&
	va_end(args);
#include "path.h"
	     * but "/foo" is not a prefix of "/foobar"
		to_copy = first_slash;
	const char *to_copy = path;
	{ 0, 1, 0, "refs/bisect" },
			return fn(key, root->value, baton);
	for (i = 0; i < prefixes->nr; i++) {
		if (used_path.buf[0] == '~') {
	if (path[0] == '~') {
		/*
	if (buf->len && !is_dir_sep(buf->buf[buf->len - 1]))
		if (file_exists(sb.buf))
				j++;
		strbuf_splice(buf, 0, buf->len,
const char *git_common_path(const char *fmt, ...)
	ret = submodule_to_gitdir(&git_submodule_dir, path);
		   j >= in_len &&
	/* Partial path normalization: skip consecutive slashes */
char *xdg_cache_home(const char *filename)
			if (!home)
	home = getenv("HOME");
	struct strbuf *pathname = get_pathname();
static void strbuf_cleanup_path(struct strbuf *sb)
char *git_pathdup(const char *fmt, ...)
			child->contents = xstrndup(root->contents + i + 1,
		}
			       const char *dotgit_name,
}
int normalize_path_copy_len(char *dst, const char *src, int *prefix_len)


	common_trie_done_setup = 1;

{
	if (len >= n) {

{
		/*
 *   `<filename>:<stream-name>:<stream-type>`. There exists a default stream
	 * Is it a symbolic ref?
			     struct strbuf *buf,
	{ 0, 1, 1, "worktrees" },
		return fn(key, root->value, baton);
	}
		    const char *fmt, ...)
		root->value = NULL;
	}
	struct strbuf path = STRBUF_INIT;
{
				i++;
}
void strbuf_repo_git_path(struct strbuf *sb,
	int old_mode, new_mode;
	const char *home, *config_home;

		goto return_null;
 */
REPO_GIT_PATH_FUNC(merge_rr, "MERGE_RR")

	for (i = 0; i < root->len; i++) {
			      repo->index_file, strlen(repo->index_file));
		/*
		return old;
	va_list args;

	for (p = common_list; p->path; p++) {
		const char *gitfile = read_gitfile(path);
{

 * | logs/              | /              | logs             | as per fn    |
			ndot = 0;
	*dst = '\0';

 * (3) "relative/path" to mean cwd relative directory; or
			if (!c || c == ':')

		src++;
 * A compressed trie.  A trie node consists of zero or more characters that
}
	return 0;
{
	for (;;) {
			j++;
 * If there was an existing value for this key, return it.
}
 *           i: len = 2, contents = on, children all NULL,
	va_start(args, fmt);
	va_start(args, fmt);
 * NEEDSWORK: This function doesn't perform normalization w.r.t. trailing '/'.
	}
 *   Note: Technically, `.git/` could receive the short name `git~2` if the
{
int is_ntfs_dotgit(const char *name)
{
	va_end(args);
}
	return pathname->buf;
 */
 * normalized, any time "../" eats up to the prefix_len part,
	struct strbuf git_submodule_common_dir = STRBUF_INIT;

	else if (dir_prefix(base, "objects"))
int ends_with_path_components(const char *path, const char *components)
}
		i = 8;
				i++;
		return dir->is_common;
}

	    name[7] >= '1' && name[7] <= '4') {
{
	va_list args;

 * before ~user is expanded), avoiding getcwd() resolving symbolic
		const char *ceil = prefixes->items[i].string;
			refname++;

		strbuf_addstr(&buf, ".");
	int i = 0, j = 0;
char *mkpathdup(const char *fmt, ...)
}
 * assume that src == dst and src[0..prefix_len-1] is already
	return offset == -1 ? NULL : xstrndup(path, offset);
 * When this function returns 1, it indicates that the specified file/directory
	static struct strbuf pathname_array[4] = {
{
	char *dst0;

		if (child->len) {
	{ 0, 1, 0, "logs/refs/bisect" },
	}
	}

	struct strbuf path = STRBUF_INIT;
	in += in_off;
		return in;

 *
	strbuf_cleanup_path(buf);
	if (new_node->len) {
	if (root->value)
	struct object_id oid;
}
		 * existing children.
	return !strcmp(buf + len, file);
		return mkpathdup("%s/.cache/git/%s", home, filename);
			child = make_trie_node(key + root->len + 1, value);
				sl = ndot = 0;
	len = sb.len;
	return new_node;
#ifdef GIT_WINDOWS_NATIVE
void report_linked_checkout_garbage(void)
	strbuf_reset(&buf);
}
	/* We have matched the entire compressed section */
	if (common_trie_done_setup)
	return cleanup_path(pathname->buf);
		path = validated_path.buf;
	const char *base = buf->buf + git_dir_len;
				src += 2;
		if (root->contents[i] != key[i])
}
		return dir->is_common;
/*
			    (S_ISDIR(st.st_mode) && is_git_directory(used_path.buf)))) {
		/* .git */
 * For everything but the root folder itself, the normalized path should not
			i = prefix_off;
	}
	while (i < prefix_len) {
	if (!repo->worktree)
		for (;;) {
	if (len < 0)

		if (!suffix[i])

			const char *home = getenv("HOME");
	 * Is it a fall-back NTFS short name (for details, see
	va_start(args, fmt);
}
	 * Note that when we don't find `.git` or `git~1` we end up with `name`
				strbuf_add_real_path(&user_path, home);
 * | logs/refs/bisected | /refs/bisected | logs             | as per fn    |
void strbuf_git_common_path(struct strbuf *sb,
 * If path ends with suffix (complete path components), returns the offset of
	 */
 *
	home = getenv("HOME");
				strbuf_addstr(&validated_path, suffix[i]);
			return in;
 * Utilities for paths and pathnames
	if (home)
	while (src < end) {
	int need_sep = (buf->buf[len] && !is_dir_sep(buf->buf[len])) &&




			; /* match of length len */
			strbuf_attach(&used_path, newpath, strlen(newpath),
	if (!wt)
			path_len = chomp_trailing_dir_sep(path, path_len);
 * Performs the following normalizations on src, storing the result in dst:
 * It is okay if dst == src, but they should not overlap otherwise.

			root->children[(unsigned char)key[root->len]] = child;

	void *value;
	va_end(args);
char *mksnpath(char *buf, size_t n, const char *fmt, ...)
		strbuf_git_common_path(buf, repo, "worktrees/%s", wt->id);
		result = -1;
 *
	strbuf_release(&git_submodule_dir);
		replace_dir(buf, git_dir_len, common_dir);
int validate_headref(const char *path)
struct common_dir {
	if (config_home && *config_home)
 * The strbuf may or may not be used, so do not assume it contains the
 * The "dst" buffer must be at least as long as "src"; normalizing may shrink
	}

	}
	va_end(args);
	const char *path = cleanup_path(sb->buf);
			continue;
		root->children[(unsigned char)root->contents[i]] = child;
			exit(1);
 * |--------------------|----------------|------------------|--------------|
		    ((c = *(name++)) != 't' && c != 'T'))
			while (is_dir_sep(prefix[i]))
			strbuf_addstr(&used_path, suffix[i]);
	if (has_lock_suffix)
const char *remove_leading_path(const char *in, const char *prefix)
static int get_st_mode_bits(const char *path, int *mode)
	return len;
		/* This is the newly-added child. */
 * compile time.
	assert(filename);

{
}
					src += 2;
char *expand_user_path(const char *path, int real_home)

	int prefix_off = 0;
	fd = open(path, O_RDONLY);
	int saw_tilde;
		if (((c = *(name++)) != 'i' && c != 'I') ||
		update_common_dir(buf, git_dir_len, repo->commondir);
			key++;
	const char *path;
	int len = strlen(dir);
void strbuf_git_path(struct strbuf *sb, const char *fmt, ...)
{
	va_list args;
}
	}

	}
		i = j = has_dos_drive_prefix(in);
		 * We can handle arbitrary-sized buffers, but this remains as a
	}
		if (len >= 5 && !memcmp("refs/", buffer, 5))
}
			     const char *fmt, va_list args)
		i++;

static void adjust_git_path(const struct repository *repo,
	if (path == NULL)

			return "./";
static int dir_prefix(const char *buf, const char *dir)
	if (!is_dir_sep(prefix[prefix_len - 1]))
	strbuf_worktree_gitdir(buf, repo, wt);
	up_one:
	strbuf_release(&user_path);

			i++;
			size_t baselen = used_path.len;
 * first appears in v1.5.6-1-g044bbbc, and makes git_dir shorter


	while (is_dir_sep(buf[len]))

		return -1;
	va_list args;
	end = src + offset_1st_component(src);
		}
 *
	va_list args;
			/*
				j++;
			       struct strbuf *buf,
	if (c == '.') {
	do_git_path(the_repository, NULL, buf, fmt, args);
				return in;
	size_t i;
}
	va_list args;
}

	/* Matched the entire compressed section */
/*

 * the backslash is a regular filename character, therefore it needs to handle
				goto return_null;

		/*
{
}
	for (i = 0; i < root->len; i++) {
		return -1;
	return (is_abs1 && is_abs2 && tolower(path1[0]) == tolower(path2[0])) ||
	 * non-dot character.
	va_start(args, fmt);
 * | logs/refs/         | /refs/         | logs             | as per fn    |
REPO_GIT_PATH_FUNC(shallow, "shallow")
	struct strbuf buf = STRBUF_INIT;
	return strbuf_detach(&sb, NULL);
{
 *
	in_len -= in_off;
	{ 0, 0, 0, NULL }
			src--;
	struct strbuf sb = STRBUF_INIT;
 *   with a so-called "short name", at least on the `C:` drive by default.
		if (starts_with(refname, "refs/"))
		tweak &= ~0222;
	if (buf->len && !is_dir_sep(buf->buf[buf->len - 1]))
