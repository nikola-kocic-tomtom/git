int commit_lock_file(struct lock_file *lk)
		backoff_ms = multiplier * INITIAL_BACKOFF_MS;
		    "remove the file manually to continue."),
}
			return fd; /* success */
{
}

		else if (errno != EEXIST)
	static int random_initialized = 0;
	int fd = lock_file_timeout(lk, path, flags, timeout_ms);
		random_initialized = 1;
/* Make sure errno contains a meaningful value on error */
#include "lockfile.h"
	    strcmp(ret.buf + ret.len - LOCK_SUFFIX_LEN, LOCK_SUFFIX))
		errno = save_errno;

#define BACKOFF_MAX_MULTIPLIER 1000
 * exactly once. If timeout_ms is -1, try indefinitely.

		return lock_file(lk, path, flags);
static int lock_file(struct lock_file *lk, const char *path, int flags)
		    "may have crashed in this repository earlier:\n"
 * chain of symlinks if necessary.  Otherwise, leave path unmodified.

}
#define INITIAL_BACKOFF_MS 1L
			struct strbuf buf = STRBUF_INIT;
	if (timeout_ms == 0)
			 */
{
 */
	while (depth--) {
	while (i && path->buf[i - 1] == '/')


static int lock_file_timeout(struct lock_file *lk, const char *path,
 */
	if (err == EEXIST) {
				      int flags, long timeout_ms)
}
	if (commit_lock_file_to(lk, result_path)) {
	return 0;
			break;
		resolve_symlink(&filename);
}
 */
/*

	int multiplier = 1;
 * milliseconds. The longest backoff period is approximately
	strbuf_setlen(path, i);
{
		free(result_path);
			    absolute_path(path), strerror(err));
/*
			    absolute_path(path), strerror(err));
	if (timeout_ms > 0)
/* This should return a meaningful errno on failure */
 * If path is a symlink, attempt to overwrite it with a path to the
	static struct strbuf link = STRBUF_INIT;
	return lk->tempfile ? lk->tempfile->fd : -1;
	 */

	if (!random_initialized) {
		strbuf_addbuf(path, &link);
	long remaining_ms = 0;

{
		if (fd >= 0)
		strbuf_addf(buf, _("Unable to create '%s.lock': %s"),
		/* back off for between 0.75*backoff_ms and 1.25*backoff_ms */
		    "are terminated then try again. If it still fails, a git process\n"
		remaining_ms -= wait_ms;
	}
	free(result_path);
			strbuf_release(&buf);
		if (flags & LOCK_DIE_ON_ERROR)

			 * link is a relative path, so replace the

	return fd;

	char *result_path = get_locked_file_path(lk);

			     int flags, long timeout_ms)
		if (multiplier > BACKOFF_MAX_MULTIPLIER)
	int i = path->len;
int hold_lock_file_for_update_timeout(struct lock_file *lk, const char *path,
 * Constants defining the gaps between attempts to lock a file. The
			 * last element of p with it.
	strbuf_setlen(&ret, ret.len - LOCK_SUFFIX_LEN);
 */
		int save_errno = errno;

 * path = absolute or relative path name
	 * then go backwards until a slash, or the beginning of the
		remaining_ms = timeout_ms;
	strbuf_reset(&link);
 * first backoff period is approximately INITIAL_BACKOFF_MS
			strbuf_reset(path);
			multiplier = BACKOFF_MAX_MULTIPLIER;
 * Try locking path, retrying with quadratic backoff for at least
		else
			/*
 */
	int n = 1;
NORETURN void unable_to_lock_die(const char *path, int err)
	strbuf_addstr(&filename, path);
	die("%s", buf.buf);
/*

#include "cache.h"


		wait_ms = (750 + rand() % 500) * backoff_ms / 1000;
}
	/*
	struct strbuf buf = STRBUF_INIT;
/*
 * symlink chain that started with the original path.
/*

char *get_locked_file_path(struct lock_file *lk)
	unable_to_lock_message(path, err, &buf);
	struct strbuf filename = STRBUF_INIT;

			/* absolute path simply replaces p */
{
}
		else
{

		    "an editor opened by 'git commit'. Please make sure all processes\n"
			unable_to_lock_die(path, errno);
	}

}
 * Remove the last path name element from path (leaving the preceding
	/* back up past trailing slashes, if any */
			return -1; /* failure other than lock held */
	 * string

		if (flags & LOCK_REPORT_ON_ERROR) {

	strbuf_addstr(&filename, LOCK_SUFFIX);

	if (fd < 0) {
 * (BACKOFF_MAX_MULTIPLIER * INITIAL_BACKOFF_MS) milliseconds.

{
	while (i && path->buf[i - 1] != '/')
	strbuf_addstr(&ret, get_tempfile_path(lk->tempfile));
		sleep_millisec(wait_ms);
 *
		i--;

	strbuf_release(&filename);
	}
	struct strbuf ret = STRBUF_INIT;

	} else
 * path to the empty string.
	lk->tempfile = create_tempfile(filename.buf);
 * real file or directory (which may or may not exist), following a
		}
		if (is_absolute_path(link.buf))
}
			return -1; /* failure due to timeout */
 * "/", if any).  If path is empty or the root directory ("/"), set

		multiplier += 2*n + 1;
		long backoff_ms, wait_ms;

		if (strbuf_readlink(&link, path->buf, path->len) < 0)
			error("%s", buf.buf);
	if (ret.len <= LOCK_SUFFIX_LEN ||
	while (1) {
		/* Recursion: (n+1)^2 = n^2 + 2n + 1 */
	if (!(flags & LOCK_NO_DEREF))
		strbuf_addf(buf, _("Unable to create '%s.lock': %s.\n\n"
	int depth = MAXDEPTH;
			trim_last_path_component(path);
		return -1;
void unable_to_lock_message(const char *path, int err, struct strbuf *buf)
		    "Another git process seems to be running in this repository, e.g.\n"
		else if (timeout_ms > 0 && remaining_ms <= 0)
		srand((unsigned int)getpid());
		int fd;
 *
	/* remove ".lock": */
			n++;
	}

			unable_to_lock_message(path, errno, &buf);
#define MAXDEPTH 5
 * timeout_ms milliseconds. If timeout_ms is 0, try locking the file
		fd = lock_file(lk, path, flags);
		i--;
		BUG("get_locked_file_path() called for malformed lock object");

	}

 *
 * either be left unmodified or will name a different symlink in a
 * Copyright (c) 2005, Junio C Hamano
	return strbuf_detach(&ret, NULL);
{
 * path contains a path that might be a symlink.
static void trim_last_path_component(struct strbuf *path)
static void resolve_symlink(struct strbuf *path)
 * This is a best-effort routine.  If an error occurs, path will
{
/* We allow "recursive" symbolic links. Only within reason, though */
