/* copies root part from remaining to resolved, canonicalizing it on the way */
		/* relative path; can use CWD as the initial resolved path */
	size_t offset = offset_1st_component(path->buf);
	while (remaining.len > 0) {



 * dealing with tracked content in the working tree.
			if (errno != ENOENT || remaining.len) {
	strbuf_reset(next);
 * NULL on errors (without generating any output).
}
}
				else
	strbuf_release(&realpath);
					die_errno("Invalid path '%s'",

		len--;
			}
					      st.st_size);

		retval = strbuf_detach(&realpath, NULL);
	strbuf_setlen(path, len);
				if (die_on_error)
		} else if (next.len == 1 && !strcmp(next.buf, ".")) {
				 * relative symlink


					    "on path '%s'", MAXSYMLINKS, path);
 * symlink to a directory, we do not want to say it is a directory when
				 * be replaced with the contents of the symlink
				/*
	strbuf_add_absolute_path(&sb, path);
	/* look for the next component */
				 * strip off the last component since it will
	struct stat st;
	strbuf_remove(remaining, 0, end - remaining->buf);
 *
{
static void strip_last_component(struct strbuf *path)
		if (lstat(resolved->buf, &st)) {



		pfx_len = 0;
				else
		strbuf_reset(resolved);
	static struct strbuf sb = STRBUF_INIT;
	}
	if (!resolved->len) {
	int offset = offset_1st_component(remaining->buf);
int is_directory(const char *path)
				/* absolute symlink; set resolved to root */
	for (end = start; *end && !is_dir_sep(*end); end++)
					die("More than %d nested symlinks "
	/* Skip sequences of multiple path-separators */


 * The directory part of path (i.e., everything up to the last
	strbuf_add(resolved, remaining->buf, offset);
	else
/*

 * Do not use this for inspecting *tracked* content.  When path is a
/* removes the last path component from 'path' except if 'path' is root */
 * and extra slashes removed) equivalent to the specified path.  (If

	char *start = NULL;
			if (num_symlinks++ > MAXSYMLINKS) {
	while (offset < len && is_dir_sep(path->buf[len - 1]))
			if (die_on_error)
		}
{
		/* append the next component and resolve resultant path */
	return strbuf_detach(&path, NULL);
			strbuf_reset(&symlink);
			}
{
 */
	if (strbuf_realpath(&realpath, path, die_on_error))
			strbuf_addch(resolved, '/');
#endif
				else
		strbuf_add(&path, pfx, pfx_len);
char *prefix_filename(const char *pfx, const char *arg)
						  resolved->buf);
			continue;

	if (!retval)
error_out:
		strbuf_addbuf(resolved, &next);
	return retval;

	for (start = remaining->buf; is_dir_sep(*start); start++)
				get_root_part(resolved, &symlink);
char *strbuf_realpath(struct strbuf *resolved, const char *path,

}
	convert_slashes(resolved->buf);
#ifndef MAXSYMLINKS
}
		; /* nothing */


#include "cache.h"
				die_errno("unable to get current working directory");
	struct stat st;
}

}
			strip_last_component(resolved);
	char *retval = NULL;
{
			if (is_absolute_path(symlink.buf)) {
 * Return the real path (i.e., absolute path, with symlinks resolved
 * dir_sep) must denote a valid, existing directory, but the last
			if (len < 0) {
	}
	/* remove the component from 'remaining' */
				strip_last_component(resolved);
	/* Find start of the last component */
	int num_symlinks = 0;
 * Use this to get an absolute path from a relative one. If you want
					goto error_out;
	/* Skip sequences of multiple path-separators */
			 */
	struct strbuf next = STRBUF_INIT;
	struct strbuf symlink = STRBUF_INIT;
 */
			continue; /* empty component */
}
					goto error_out;

		} else if (next.len == 2 && !strcmp(next.buf, "..")) {
char *real_pathdup(const char *path, int die_on_error)
	size_t pfx_len = pfx ? strlen(pfx) : 0;
		      int die_on_error)
				 */
/*
 * component need not exist.  If die_on_error is set, then die with an
			} else {
const char *absolute_path(const char *path)


	return strbuf_detach(&sb, NULL);
	else if (is_absolute_path(arg))
			strbuf_swap(&symlink, &remaining);
	}
}
	/* Iterate over the remaining path components */


#define MAXSYMLINKS 32
 * to resolve links, you should use strbuf_realpath.
			 * if there are still remaining components to resolve
	size_t len = path->len;
			len = strbuf_readlink(&symlink, resolved->buf,
{
		} else if (S_ISLNK(st.st_mode)) {
			/* '..' component; strip the last path component */
	/* Find end of the path component */
/*
			if (remaining.len) {
		; /* nothing to prefix */
	strbuf_addstr(&path, arg);
	strbuf_remove(remaining, 0, offset);
			ssize_t len;
{

	if (!pfx_len)
 * you want an absolute path but don't mind links, use

		else
/* We allow "recursive" symbolic links. Only within reason, though. */
				goto error_out;
		if (die_on_error)
	retval = resolved->buf;
 * informative error message if there is a problem.  Otherwise, return
	strbuf_release(&next);
/* get (and remove) the next component in 'remaining' and place it in 'next' */
			/* error out unless this was the last component */
}
 * absolute_path().)  Places the resolved realpath in the provided strbuf.
				errno = ELOOP;
	struct strbuf sb = STRBUF_INIT;
char *absolute_pathdup(const char *path)
						  resolved->buf);
			/*
	strbuf_reset(resolved);

			goto error_out;
		if (!is_dir_sep(resolved->buf[resolved->len - 1]))
			 */
			else
	strbuf_addstr(&remaining, path);
					goto error_out;


			 * use the symlink as the remaining components that
	convert_slashes(path.buf + pfx_len);
	while (offset < len && !is_dir_sep(path->buf[len - 1]))
		}

				if (die_on_error)
{
			}
			 * then append them to symlink
				strbuf_addch(&symlink, '/');
			die("The empty string is not a valid path");
	return (!stat(path, &st) && S_ISDIR(st.st_mode));
			continue; /* '.' component */
	strbuf_add(next, start, end - start);
	struct strbuf realpath = STRBUF_INIT;
#ifdef GIT_WINDOWS_NATIVE

	strbuf_add_absolute_path(&sb, path);
	strbuf_reset(&sb);

	char *retval = NULL;
			/*
	get_root_part(resolved, &remaining);
			}

		len--;
	strbuf_release(&remaining);
			 * need to be resolved
{
{
		; /* nothing */
				strbuf_addbuf(&symlink, &remaining);
			}
	struct strbuf remaining = STRBUF_INIT;
 */


#endif
		}

	return sb.buf;
static void get_root_part(struct strbuf *resolved, struct strbuf *remaining)
	strbuf_release(&symlink);
		get_next_component(&next, &remaining);

#endif
		if (strbuf_getcwd(resolved)) {
				if (die_on_error)
#ifdef GIT_WINDOWS_NATIVE
static void get_next_component(struct strbuf *next, struct strbuf *remaining)
	return retval;
	struct strbuf path = STRBUF_INIT;
	char *end = NULL;
		if (next.len == 0) {
	if (!*path) {
					die_errno("Invalid symlink '%s'",
