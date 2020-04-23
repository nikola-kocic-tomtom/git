	 * If we get an IO error, just close the trace dst.
 *

			if (attempt_count > 0) {
	 * Allow "af_unix:[<type>:]<absolute_path>"
		ret = 1;
	}
		uds_try |= TR2_DST_UDS_TRY_STREAM;
#include "trace2/tr2_sysenv.h"
		warning("trace2: could not connect to socket '%s' for '%s' tracing: %s",

	}
	if (uds_try & TR2_DST_UDS_TRY_DGRAM) {
	max_files_var = tr2_sysenv_get(TR2_SYSENV_MAX_FILES);
			tr2env_dst_debug = 0;
	strbuf_addstr(&sentinel_path, DISCARD_SENTINEL_NAME);
}
	if (!tr2env_max_files) {
				      const char *tgt_value)
	dst->need_close = 0;

		e = tr2_dst_try_uds_connect(path, SOCK_STREAM, &fd);
	dst->initialized = 1;

			tr2_sysenv_display_name(dst->sysenv_var),
		sid = last_slash + 1;
 * writing too many trace files to a directory.
{
				(int) base_path_len, path.buf,
	size_t base_path_len;
	unsigned int uds_try = 0;
	 * We do not use write_in_full() because we do not want

	/* check file count */
	/* don't open twice */


	 *
	dst->fd = 0;
	unsigned attempt_count;
	struct stat statbuf;
	if (dst->initialized)

static void tr2_dst_malformed_warning(struct tr2_dst *dst,
	}
	 *
	dst->initialized = 1;
	 * If they omit the socket type, try one and then the other.
	strbuf_addstr(&path, tgt_prefix);
		if (tr2_dst_want_warning())
			return tr2_dst_try_path(dst, tgt_value);
	return !!tr2_dst_get_trace_fd(dst);
{
				"many files in target directory %s",
	 *
			tr2env_dst_debug = atoi(env_value) > 0;
	int fd;
}
	int fd;
				strerror(errno));
	if (!strcmp(tgt_value, "1") || !strcasecmp(tgt_value, "true")) {

		return dst->fd;
	if (tr2env_dst_debug == -1) {
		return dst->fd;
}
int tr2_dst_get_trace_fd(struct tr2_dst *dst)
}
	if (strlen(tgt_value) == 1 && isdigit(*tgt_value)) {
	strbuf_addstr(&path, tgt_prefix);
 */
	 * the system can write them in 1 attempt and we won't see
		if (!env_value || !*env_value)

		close(dst->fd);
 * Check to make sure we're not overloading the target directory with too many

		uds_try |= TR2_DST_UDS_TRY_DGRAM;

static int tr2_dst_want_warning(void)
 * How many attempts we will make at creating an automatically-named trace file.
		strbuf_release(&path);

	/* check sentinel */
		dst->fd = open(sentinel_path.buf, O_WRONLY | O_CREAT | O_EXCL, 0666);

	 * files and the kernel handles the atomic seek+write. If
		return dst->fd;
 * how many files we can write to a directory before entering discard mode.
	if (dst->fd == -1) {
	if (tr2_dst_want_warning())
				break;

#define PREFIX_AF_UNIX "af_unix:"

	/*
				tr2_sysenv_display_name(dst->sysenv_var),
{

	if (last_slash)
	}
		close(fd);
	dst->initialized = 1;
				tgt_value,

	if (!is_dir_sep(path.buf[path.len - 1]))
/*

		else
	}
#define PREFIX_AF_UNIX_DGRAM "af_unix:dgram:"
	if (dirp)
		dst->too_many_files = 1;
	dirp = opendir(path.buf);
	static int tr2env_dst_debug = -1;
	 */
 * it's zero or unset, disable this check. Next check for the presence of a

	*out_fd = fd;

{
int tr2_dst_trace_want(struct tr2_dst *dst)
#define MAX_AUTO_ATTEMPTS 10
	 * chunking), so we can talk to either DGRAM or STREAM type sockets.
		warning("unable to write trace to '%s': %s",
 * files. First get the threshold (if present) from the config or envvar. If
			if (dst->fd != -1)
{
				tgt_prefix);
	strbuf_addbuf(&sentinel_path, &path);

#include "cache.h"

void tr2_dst_write_line(struct tr2_dst *dst, struct strbuf *buf_line)
	    !strcasecmp(tgt_value, "false")) {
	return 0;
#endif
	 * a short-write.
		return 0;
			warning("trace2: could not open '%s' for '%s' tracing: %s",
/*
		if (!e)
		return errno;
	dst->fd = fd;
			warning("trace2: invalid AF_UNIX value '%s' for '%s' tracing",
	return tr2env_dst_debug;
	DIR *dirp;

	strbuf_release(&path);
			goto connected;

		dst->fd = atoi(tgt_value);
	warning("trace2: unknown value for '%s': '%s'",
		return 0;
static int tr2_dst_too_many_files(struct tr2_dst *dst, const char *tgt_prefix)
	const char *max_files_var;
	else if (skip_prefix(tgt_value, PREFIX_AF_UNIX, &path))
	 * Allow the user to explicitly request the socket type.
 * This can be overridden via the TR2_SYSENV_MAX_FILES setting.
	if (uds_try & TR2_DST_UDS_TRY_STREAM) {

	if (skip_prefix(tgt_value, PREFIX_AF_UNIX_STREAM, &path))

		dst->fd = STDERR_FILENO;
{
	    strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
	if (!tgt_value || !strcmp(tgt_value, "") || !strcmp(tgt_value, "0") ||
				tr2_sysenv_display_name(dst->sysenv_var),
{
	 * a short-write to try again.  We are using O_APPEND mode

	if (dst->need_close)
	if (fd == -1)
	base_path_len = path.len;
}

	 * another thread or git process is concurrently writing to
 * When set to zero, disables directory file count checks. Otherwise, controls
 * sentinel file, then check file count.

	if (file_count >= tr2env_max_files) {
			warning("trace2: could not open '%.*s' for '%s' tracing: %s",

#define TR2_DST_UDS_TRY_DGRAM  (1 << 1)
					  const char *tgt_value)
/*
	if (!path || !*path) {

	} else if (too_many_files == 1) {
 * Returns 0 if tracing should proceed as normal. Returns 1 if the sentinel file
		tr2env_max_files = max_files;
	dst->fd = fd;

static int tr2_dst_try_unix_domain_socket(struct tr2_dst *dst,
		if (tr2_dst_want_warning())
		return dst->fd;
 * writing traces again.
cleanup:


			strerror(e));
	if (is_absolute_path(tgt_value)) {
	return ret;
		if (!e)
		if (tr2_dst_want_warning())
{
	int too_many_files;

{
		goto cleanup;
	}
	}
				tr2_sysenv_display_name(dst->sysenv_var));
connected:
		if (is_directory(tgt_value))
 * are too many files but there was no sentinel file, which means we have
	 *

	while (file_count < tr2env_max_files && dirp && readdir(dirp))

	}

	}
				strbuf_setlen(&path, base_path_len);
#define DISCARD_SENTINEL_NAME "git-trace2-discard"

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
	}

	last_slash = strrchr(sid, '/');
	dst->initialized = 1;
	if (fd == -1) {
				tgt_value,

	strbuf_complete_line(buf_line); /* ensure final NL on buffer */
static int tr2_dst_try_uds_connect(const char *path, int sock_type, int *out_fd)

				strbuf_addf(&path, ".%d", attempt_count);

	struct strbuf path = STRBUF_INIT;
	 * Trace2 always writes complete individual messages (without

#ifndef NO_UNIX_SOCKETS
/*
}
	if (max_files_var && *max_files_var && ((max_files = atoi(max_files_var)) >= 0))
		tr2_dst_trace_disable(dst);
			}

		ret = 0;
error:
		closedir(dirp);
#define PREFIX_AF_UNIX_STREAM "af_unix:stream:"
void tr2_dst_trace_disable(struct tr2_dst *dst)
		return tr2_dst_try_unix_domain_socket(dst, tgt_value);
	if (write(fd, buf_line->buf, buf_line->len) >= 0)
 * We expect that some trace processing system is gradually collecting files
	int e;

		tr2_dst_trace_disable(dst);
				path, tr2_sysenv_display_name(dst->sysenv_var));
	}
	int fd = tr2_dst_get_trace_fd(dst);
			strerror(errno));
	const char *path = NULL;
	const char *tgt_value;
		tr2_dst_trace_disable(dst);
 * created and should write traces to the sentinel file.
 * already exists, which means tracing should be disabled. Returns -1 if there
			goto error;
		if (tr2_dst_want_warning())
			return tr2_dst_try_auto_path(dst, tgt_value);
	strlcpy(sa.sun_path, path, sizeof(sa.sun_path));
}
	if (tr2_dst_want_warning())
		dst->fd = 0;

			warning("trace2: invalid AF_UNIX path '%s' for '%s' tracing",
	}
	return 0;
	 */
	tr2_dst_trace_disable(dst);
	}
{
		ret = -1;
	strbuf_addstr(&path, sid);
	return dst->fd;
		strbuf_release(&path);

	}

	 *
 */
static int tr2env_max_files = 0;
		tr2_dst_trace_disable(dst);

	tr2_dst_trace_disable(dst);
		return 0;



				tr2_sysenv_display_name(dst->sysenv_var),
#define TR2_DST_UDS_TRY_STREAM (1 << 0)

}
}
static int tr2_dst_try_path(struct tr2_dst *dst, const char *tgt_value)
	if (!is_dir_sep(path.buf[path.len - 1])) {
	tr2_dst_malformed_warning(dst, tgt_value);
	int fd = open(tgt_value, O_WRONLY | O_APPEND | O_CREAT, 0666);

	if (!is_absolute_path(path) ||
	/* Get the config or envvar and decide if we should continue this check */
	 * this fd or file, our remainder-write may not be contiguous
	else if (skip_prefix(tgt_value, PREFIX_AF_UNIX_DGRAM, &path))
	/* Always warn about malformed values. */
	/*
	dst->need_close = 1;

static int tr2_dst_try_auto_path(struct tr2_dst *dst, const char *tgt_prefix)
		goto cleanup;
		tr2_sysenv_display_name(dst->sysenv_var), tgt_value);
			dst->fd = open(path.buf, O_WRONLY | O_CREAT | O_EXCL, 0666);
	fd = socket(AF_UNIX, sock_type, 0);
	strbuf_release(&path);

 */
	strbuf_release(&sentinel_path);
		if (tr2_dst_want_warning())
		strbuf_addch(&path, '/');
		else
	}
	const char *last_slash, *sid = tr2_sid_get();
				strerror(errno));
		int e = errno;
 */
	int file_count = 0, max_files = 0, ret = 0;
		file_count++;
{
		for (attempt_count = 0; attempt_count < MAX_AUTO_ATTEMPTS; attempt_count++) {
 * from the target directory; after it removes the sentinel file we'll start
			warning("trace2: not opening %s trace file due to too "
	tgt_value = tr2_sysenv_get(dst->sysenv_var);
	 * It is assumed that TRACE2 messages are short enough that
	 * confuse readers.  So just don't bother.
	sa.sun_family = AF_UNIX;
	}
		strbuf_addch(&path, '/');

		return;
		goto cleanup;
 * Sentinel file used to detect when we should discard new traces to avoid
	if (!stat(sentinel_path.buf, &statbuf)) {

	}
	return dst->fd;
		const char *env_value = tr2_sysenv_get(TR2_SYSENV_DST_DEBUG);
			goto connected;

	dst->need_close = 1;

#ifndef NO_UNIX_SOCKETS
	return dst->fd;
		}
	tr2_dst_trace_disable(dst);
	if (starts_with(tgt_value, PREFIX_AF_UNIX))
		if (e != EPROTOTYPE)
			path, tr2_sysenv_display_name(dst->sysenv_var),
		return 0;


#include "trace2/tr2_sid.h"

 *
	 * with our initial write of this message.  And that will
}
#include "trace2/tr2_dst.h"
	too_many_files = tr2_dst_too_many_files(dst, tgt_prefix);
	dst->need_close = 1;
		e = tr2_dst_try_uds_connect(path, SOCK_DGRAM, &fd);
	struct sockaddr_un sa;
	struct strbuf path = STRBUF_INIT, sentinel_path = STRBUF_INIT;
#endif
	if (!too_many_files) {
		return e;
}
	dst->initialized = 1;
	return 0;

		uds_try |= TR2_DST_UDS_TRY_STREAM | TR2_DST_UDS_TRY_DGRAM;
		return 0;
