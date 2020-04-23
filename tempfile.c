#include "sigchain.h"
	close_tempfile_gently(tempfile);
	return 0;
{
	activate_tempfile(tempfile);

		tempfile->fp = NULL;
		return;
	tempfile->fd = -1;
	strbuf_add_absolute_path(&tempfile->filename, path);
				errno = EIO;

}
 *
		return -1;
		atexit(remove_tempfiles_on_exit);
	if (!is_tempfile_active(tempfile))
	if (rename(tempfile->filename.buf, path)) {
struct tempfile *xmks_tempfile_m(const char *filename_template, int mode)
	strbuf_add_absolute_path(&tempfile->filename, path);

{
	return tempfile;
FILE *get_tempfile_fp(struct tempfile *tempfile)

		BUG("fdopen_tempfile() called for open object");
 *

	if (!tempfile)
	int fd;
 *   - `fd` holds a file descriptor open for writing to it
static struct tempfile *new_tempfile(void)
	if (tempfile->fd < 0) {
 * `tempfile` has an `owner` field that records the owner's PID. This
static void remove_tempfiles(int in_signal_handler)
	if (!is_tempfile_active(tempfile))
	if (close_tempfile_gently(tempfile)) {
const char *get_tempfile_path(struct tempfile *tempfile)
 *   - `fd` is -1 and `fp` is `NULL`
	return tempfile->filename.buf;
}
		die_errno("Unable to create temporary file '%s'",
 * - Inactive (after `delete_tempfile()`, `rename_tempfile()`, or a
	raise(signo);
		} else {
	if (!initialized) {
		BUG("get_tempfile_path() called for inactive object");
	remove_tempfiles(1);
 *   `reopen_tempfile()`). In this state:
struct tempfile *mks_tempfile_tsm(const char *filename_template, int suffixlen, int mode)
	const char *tmpdir;
static void deactivate_tempfile(struct tempfile *tempfile)
	}
 *   - `filename` holds the filename of the temporary file

	tempfile->fp = NULL;
 *   registered in `tempfile_list`, and `on_list` is set.
		BUG("fdopen_tempfile() called for inactive object");
	remove_tempfiles(0);
}


	strbuf_release(&full_template);

#include "cache.h"
		if (p->fd >= 0)
		BUG("reopen_tempfile called for an open object");
}
	deactivate_tempfile(tempfile);
{

}
}
static void remove_tempfiles_on_signal(int signo)
			continue;


	deactivate_tempfile(tempfile);
				    O_RDWR | O_CREAT | O_EXCL, 0666);
		BUG("activate_tempfile called for active object");
struct tempfile *mks_tempfile_sm(const char *filename_template, int suffixlen, int mode)
		BUG("reopen_tempfile called for an inactive object");
		BUG("rename_tempfile called for inactive object");
 *

	struct tempfile *tempfile = xmalloc(sizeof(*tempfile));
 * - Uninitialized. In this state the object's `on_list` field must be
	if (!is_tempfile_active(tempfile))
	if (tempfile->fp)
	return tempfile->fp;

 *   - `active` is set
 * temporary files in a linked list, `tempfile_list`. An `atexit(3)`
	} else {
 * handler and a signal handler are registered, to clean up any active
static VOLATILE_LIST_HEAD(tempfile_list);
	strbuf_add_absolute_path(&full_template, filename_template);
		delete_tempfile(tempfile_p);
	return err ? -1 : 0;
	tempfile->active = 1;
			if (!fclose(fp))
	int err;
	if (adjust_shared_perm(tempfile->filename.buf)) {
 *   - `owner` holds the PID of the process that created the file
	volatile struct volatile_list_head *pos;
	sigchain_pop(signo);
{
	}
int get_tempfile_fd(struct tempfile *tempfile)
 *   - `filename` is empty (usually, though there are transitory

 *
	activate_tempfile(tempfile);
	}

			err = fclose(fp);
}

 */
		return NULL;

{
	tempfile->fd = git_mkstemps_mode(tempfile->filename.buf, suffixlen, mode);
	activate_tempfile(tempfile);
		int save_errno = errno;
	free(tempfile);


	tempfile->fp = fdopen(tempfile->fd, mode);

	tempfile->fd = git_mkstemps_mode(tempfile->filename.buf, suffixlen, mode);
}
		BUG("get_tempfile_fd() called for inactive object");
static void activate_tempfile(struct tempfile *tempfile)

		/* Try again w/o O_CLOEXEC: the kernel might not support it */
	fd = tempfile->fd;
		err = close(fd);
 *
		error("cannot fix permission bits on %s", tempfile->filename.buf);
		deactivate_tempfile(tempfile);
	tmpdir = getenv("TMPDIR");
struct tempfile *register_tempfile(const char *path)
 * - Active, file closed (after `close_tempfile_gently()`). Same
		sigchain_push_common(remove_tempfiles_on_signal);
	if (!is_tempfile_active(tempfile) || tempfile->fd < 0)
 *
	if (fp) {
 *
 *
 * the `tempfile` objects that comprise it must be kept in
		return NULL;
	return tempfile->fd;
		BUG("get_tempfile_fp() called for inactive object");
 *   `fd` is -1, and `fp` is `NULL`.
}
}
	strbuf_addf(&tempfile->filename, "%s/%s", tmpdir, filename_template);
	INIT_LIST_HEAD(&tempfile->list);
	*tempfile_p = NULL;
	if (!is_tempfile_active(tempfile))

 *   - the temporary file exists
	struct tempfile *tempfile = *tempfile_p;
}
 * - Active, file open (after `create_tempfile()` or
 *     `fdopen_tempfile()` has been called on the object
	FILE *fp;
struct tempfile *create_tempfile(const char *path)
{

 * If the program exits while a temporary file is active, we want to
	}
 *     states in which this condition doesn't hold). Client code should
	tempfile->fd = open(tempfile->filename.buf,
		deactivate_tempfile(tempfile);
 * State diagram and cleanup
		errno = save_errno;
	return tempfile;
 * -------------------------
FILE *fdopen_tempfile(struct tempfile *tempfile, const char *mode)
	if (0 <= tempfile->fd)
			err = -1;
 *     *not* rely on the filename being empty in this state.
{

		tempfile->fd = open(tempfile->filename.buf,
	}
	return tempfile;

		return NULL;

 * make sure that we remove it. This is done by remembering the active
		deactivate_tempfile(tempfile);


/*
	tempfile->owner = getpid();
	return tempfile;
	pid_t me = getpid();

	strbuf_release(&tempfile->filename);
		delete_tempfile(tempfile_p);

 * A temporary file is owned by the process that created it. The
	list_for_each(pos, &tempfile_list) {
}
			close(p->fd);
			unlink_or_warn(p->filename.buf);
 * temporary files.
	tempfile->owner = 0;
	tempfile->active = 0;

}
	if (!is_tempfile_active(tempfile))
void delete_tempfile(struct tempfile **tempfile_p)
 *
		}

	}
{
	struct tempfile *tempfile = *tempfile_p;

	if (is_tempfile_active(tempfile))
	tempfile->fd = open(tempfile->filename.buf, O_WRONLY|O_TRUNC);
	static int initialized;
	struct tempfile *tempfile = new_tempfile();
{
		struct tempfile *p = list_entry(pos, struct tempfile, list);
	if (tempfile->fd < 0) {
		return 0;
		errno = save_errno;
 * self-consistent states at all times.
	strbuf_init(&tempfile->filename, 0);
/* Make sure errno contains a meaningful value on error */

	struct tempfile *tempfile;
 * The possible states of a `tempfile` object are as follows:
	return tempfile;
 *   - `active` is unset
}
{
{
	}
	activate_tempfile(tempfile);

{
 * file created by its parent.
	struct tempfile *tempfile = new_tempfile();
	if (tempfile->fd < 0) {
		initialized = 1;
	return tempfile->fd;
}
 *   - `fp` holds a pointer to an open `FILE` object if and only if

		if (in_signal_handler)

 * field is used to prevent a forked process from deleting a temporary
 *   zero but the rest of its contents need not be initialized. As
	strbuf_add_absolute_path(&tempfile->filename, filename_template);
	volatile_list_del(&tempfile->list);
{
static void remove_tempfiles_on_exit(void)
{
	}

 *   soon as the object is used in any way, it is irrevocably
	return tempfile;
	struct strbuf full_template = STRBUF_INIT;
}
	volatile_list_add(&tempfile->list, &tempfile_list);
	if (!is_tempfile_active(tempfile))
{
	*tempfile_p = NULL;
	struct tempfile *tempfile = new_tempfile();
 *   as the previous state, except that the temporary file is closed,
	if (!is_tempfile_active(tempfile))
 * Because the signal handler can run at any time, `tempfile_list` and
	fp = tempfile->fp;
	struct tempfile *tempfile = new_tempfile();
	tempfile = mks_tempfile_m(full_template.buf, mode);
	if (O_CLOEXEC && tempfile->fd < 0 && errno == EINVAL)


			    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
			  full_template.buf);
 *
int reopen_tempfile(struct tempfile *tempfile)

		if (!is_tempfile_active(p) || p->owner != me)
			unlink(p->filename.buf);
{
	unlink_or_warn(tempfile->filename.buf);
int close_tempfile_gently(struct tempfile *tempfile)
	if (!tmpdir)


		else
}
}
	return tempfile->fp;

		delete_tempfile(&tempfile);
#include "tempfile.h"
		return -1;
{
		return NULL;
int rename_tempfile(struct tempfile **tempfile_p, const char *path)

		int save_errno = errno;
{
 *   - the object is removed from `tempfile_list` (but could be used again)
	}
		if (ferror(fp)) {
	tempfile->active = 0;
 *   failed attempt to create a temporary file). In this state:
{
}
		tmpdir = "/tmp";
		p->active = 0;
	tempfile->fd = -1;
