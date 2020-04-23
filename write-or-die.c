		check_pipe(errno);
#include "run-command.h"
#include "cache.h"

 * we've already lost the error code, and cannot report it any
{
 * flush entirely since it's not needed.

void fsync_or_die(int fd, const char *msg)
				skip_stdout_flush = 1;
 *
	if (fflush(f)) {
	}
	if (f == stdout) {
 * Of course, if the flush happened within the write itself,
		check_pipe(errno);
}
{
		if (skip_stdout_flush < 0) {
		die_errno("write error");
		die_errno("write error");

void maybe_flush_or_die(FILE *f, const char *desc)
void fprintf_or_die(FILE *f, const char *fmt, ...)
	int ret;

	}
		}
 * If the file handle is stdout, and stdout is a file, then skip the
		die_errno("write failure on '%s'", desc);
	struct stat st;
	if (fsync(fd) < 0) {
	char *cp;
	static int skip_stdout_flush = -1;
			cp = getenv("GIT_FLUSH");
			else
		die_errno("fsync error on '%s'", msg);
}
	va_end(ap);
 * the right error code on the flush).

	}
{
		if (skip_stdout_flush && !ferror(f))
	if (ret < 0) {
 * to get error handling (and to get better interactive
			return;
			else if ((fstat(fileno(stdout), &st) == 0) &&
 */
 * more. So we just ignore that case instead (and hope we get
	va_start(ap, fmt);
	if (write_in_full(fd, buf, count) < 0) {
				 S_ISREG(st.st_mode))
{
 * behaviour - not buffering excessively).
void write_or_die(int fd, const void *buf, size_t count)
				skip_stdout_flush = 0;
			if (cp)
		check_pipe(errno);

	ret = vfprintf(f, fmt, ap);
 * Some cases use stdio, but want to flush after the write
/*
	}
 *

}
	}
	va_list ap;
				skip_stdout_flush = (atoi(cp) == 0);
}
