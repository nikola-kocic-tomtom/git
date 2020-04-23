		check_preimage_overflow(preimage.max_off, 1);
}
#include "strbuf.h"
		die("cannot apply delta");
		*mode *= 8;
	/* ls "path/to/file" */
		preimage.max_off++;	/* room for newline */
			const char *old_data, uint32_t old_mode)
		die_short_read(input);
	if (*uuid && *url) {
static void check_preimage_overflow(off_t a, off_t b)
		const char *log, timestamp_t timestamp, const char *note_ref)
	die("invalid dump: unexpected end of file");

	assert(len >= 0);

			const struct strbuf *log,
	ls_from_active_commit(path);
}
static int parse_ls_response(const char *response, uint32_t *mode,
	first_commit_done = 0;
			BUG("unexpected fast_export_ls_rev error: %s",
void fast_export_end_commit(uint32_t revision)

	return 0;

}
	}
	fputc('\n', stdout);
	return buf.buf;

	fflush(stdout);
 * See LICENSE for details.
void fast_export_begin_note(uint32_t revision, const char *author,
}

	int err;
}
	if (buffer_copy_bytes(input, len) != len)
	const char *response_end;
	if (mode == S_IFLNK) {
}
	fputc('\n', stdout);
	die("unexpected end of fast-import feedback");
static struct line_buffer report_buffer = LINE_BUFFER_INIT;

		*mode_out = S_IFDIR;
	postimage_len = apply_delta(len, input, old_data, old_mode);
	quote_c_style(path, NULL, stdout, 0);
	printf("\"\n");
	static struct strbuf data = STRBUF_INIT;
	const char *tab;
		die("invalid ls response: missing mode: %s", response);
		printf("cat-blob %s\n", old_data);
	printf("data %"PRIuMAX"\n", (uintmax_t)loglen);
		return line;
	static int postimage_initialized;
	strbuf_reset(&data);
		check_preimage_overflow(preimage.max_off, strlen("link "));
	if (*response == 'm') {	/* Missing. */
static long apply_delta(off_t len, struct line_buffer *input,
	if (firstnote) {
#include "quote.h"

	printf("commit %s\n", note_ref);
		*mode += ch - '0';
	printf("data 0\n\n");
	} else {
	static struct strbuf buf = STRBUF_INIT;
			die("invalid cat-blob response: %s", response);
	if (buffer_ferror(&report_buffer))
	static int firstnote = 1;
 * Licensed under a two-clause BSD-style license.
				uint32_t old_mode, const char *old_data,
		   *author ? author : "nobody",
{
}
{
void fast_export_begin_commit(uint32_t revision, const char *author,
	return 0;
		die_errno("error closing fast-import feedback stream");
void fast_export_modify(const char *path, uint32_t mode, const char *dataref)
	err = fast_export_ls_rev(revision, src, &mode, &data);
			timestamp_t timestamp, const char *local_ref)
	}
	type = strstr(header, " blob ");
	if (ret < 0)
static int init_postimage(void)
	if (response_end - response < (signed) strlen("100644") ||
	*mode = 0;
{
	*len = n;
	postimage_initialized = 1;
		/* Read the remainder of preimage and trailing newline. */
	printf("data %"PRIuMAX"\n", (uintmax_t) len);
	const char *line = buffer_read_line(&report_buffer);
	for (; *response != ' '; response++) {
	}
	}
	n = strtoumax(type + strlen(" blob "), (char **) &end, 10);
	/* ' blob ' or ' tree ' */
static void ls_from_active_commit(const char *path)
{
{
void fast_export_delete(const char *path)
	if (n == UINTMAX_MAX || n > maximum_signed_value_of_type(off_t))
{
	printf("committer %s <%s@%s> %"PRItime" +0000\n",
	printf("progress Imported commit %"PRIu32".\n\n", revision);
}
		if (ch < '0' || ch > '7')
		die("cannot open temporary file for blob retrieval");

{
		die("unexpected ls response: not a tree or blob: %s", response);
void fast_export_blob_delta(uint32_t mode,
{
	if (old_mode == S_IFLNK) {
{
	}

}
	if (old_data) {
 */
		strbuf_addstr(&preimage.buf, "link ");
}
		die("invalid ls response: missing tab: %s", response);
	putchar('\n');
	}
		if (revision > 1)
				"\n\ngit-svn-id: %s@%"PRIu32" %s\n",
{
static const char *get_response_line(void)
		return 0;




			printf("from %s^0", note_ref);
		   *uuid ? uuid : "local", timestamp);
			printf("from :%"PRIu32"\n", revision - 1);
	FILE *out;


	fast_export_modify(path, mode, "inline");
}
static void die_short_read(struct line_buffer *input)
#include "fast_export.h"
		fast_export_delete(dst);

	if (ends_with(header, " missing"))
			    strerror(errno));
}
	if (svndiff0_apply(input, len, &preimage, out))
	}
	const char *type;
}
}

			die("invalid ls response: mode is not octal: %s", response);
static char gitsvnline[MAX_GITSVN_LINE_LEN];
	}
	fputc('\n', stdout);
	printf("N %s %s\n", dataref, committish);
	printf("commit %s\n", local_ref);
	long ret;
		die("blob too large for current definition of off_t");
void fast_export_buf_to_data(const struct strbuf *data)
		return -1;
{
	if (!tab)
void fast_export_data(uint32_t mode, off_t len, struct line_buffer *input)
			die("cannot seek to end of input");
				uint32_t *mode, struct strbuf *dataref)
	quote_c_style(path, NULL, stdout, 0);
			die("missing newline after cat-blob response");
	if (mode == S_IFLNK) {
void fast_export_deinit(void)
	}
	quote_c_style(path, NULL, stdout, 0);
	putchar(' ');
	}
void fast_export_init(int fd)
	size_t loglen = strlen(log);
		postimage_len -= strlen("link ");
/*


	strbuf_add(dataref, response, tab - response);

static struct line_buffer postimage = LINE_BUFFER_INIT;
	fputc('\n', stdout);
		preimage.max_off += strlen("link ");
	if (old_data) {
		if (errno != ENOENT)
		if (buffer_skip_bytes(input, 5) != 5)
	if (!dataref) {
	return buffer_tmpfile_init(&postimage);
	putchar('\n');
	    (response[1] != 'b' && response[1] != 't'))
	if (!type)
void fast_export_note(const char *committish, const char *dataref)
	}
{
				 url, revision, uuid);
		die("cannot read temporary file for blob retrieval");
	fwrite(data->buf, data->len, 1, stdout);
{
	uint32_t mode;
	int err;
		const char *response;
		log = &empty;
	printf("ls \"");
	long postimage_len;

	}
		fflush(stdout);
	if (signed_add_overflows(a, b))
{
	putchar('D');

					struct strbuf *dataref)
		if (parse_cat_response_line(response, &preimage.max_off))
		assert(!signed_add_overflows(preimage.max_off, 1));
{
		return error("cat-blob header contains garbage after length: %s", header);
}
		return NULL;

	printf("mark :%"PRIu32"\n", revision);
{
static uint32_t first_commit_done;
		return error("cat-blob header has wrong object type: %s", header);
		firstnote = 0;
	strbuf_reset(&buf);
}
#define MAX_GITSVN_LINE_LEN 4096
		die_errno("error reading dump file");

{
	if (init_postimage() || !(out = buffer_tmpfile_rewind(&postimage)))
{

	if (*end)

{
		return;
int fast_export_ls(const char *path, uint32_t *mode, struct strbuf *dataref)
	ret = buffer_tmpfile_prepare_to_read(&postimage);
	if (response_end - response < (signed) strlen(" blob ") ||

	return parse_ls_response(get_response_line(), mode, dataref);
		die_errno("error reading from fast-import");
int fast_export_ls_rev(uint32_t rev, const char *path,
static int parse_cat_response_line(const char *header, off_t *len)
		return error("blob too large for current definition of off_t");
		buffer_skip_bytes(&postimage, strlen("link "));


	uintmax_t n;
void fast_export_copy(uint32_t revision, const char *src, const char *dst)
			die("invalid dump: symlink too short for \"link\" prefix");
	if (postimage_initialized)
	if (buffer_fdinit(&report_buffer, fd))
		/* svn symlink blobs start with "link " */
	/* Dataref. */
	/* Mode must be 100644, 100755, 120000, or 160000. */
	fwrite(log->buf, log->len, 1, stdout);
	if (buffer_deinit(&report_buffer))
			BUG("unexpected fast_export_ls error: %s",
{
	if (!first_commit_done) {
	response += strlen(" blob ");
	quote_c_style(path, NULL, stdout, 1);
#include "sliding_window.h"
	ls_from_rev(rev, path);

	printf("M %06"PRIo32" %s ", mode, dataref);
		(uintmax_t) (log->len + strlen(gitsvnline)));
		char ch = *response;
	    response[strlen("100644")] != ' ')
	printf("ls :%"PRIu32" ", rev);
{
	return ret;
		return error("cat-blob header contains negative length: %s", header);
	buffer_copy_bytes(&postimage, postimage_len);

	if (err) {

	if (!log)
	/* ls :5 path/to/old/file */
		fast_export_truncate(path, mode);
const char *fast_export_read_path(const char *path, uint32_t *mode_out)
	assert(len >= 0);
static void fast_export_truncate(const char *path, uint32_t mode)
	if (end == type + strlen(" blob "))
#include "svndiff.h"
}
	if (buffer_ferror(input))
	fwrite(log, loglen, 1, stdout);
	tab = memchr(response, '\t', response_end - response);
		if (move_window(&preimage, preimage.max_off - 1, 1))

}
	printf("data %"PRIuMAX"\n", (uintmax_t)data->len);
		return;
	err = fast_export_ls(path, mode_out, &buf);
	fflush(stdout);
		if (len < 5)
}
	fast_export_modify(dst, mode, data.buf);
}
}
	printf("committer %s <%s@%s> %"PRItime" +0000\n", author, author, "local", timestamp);
		die_errno("cannot read from file descriptor %d", fd);
		return error("cat-blob reports missing blob: %s", header);
	if (line)
			const char *uuid, const char *url,
	static const struct strbuf empty = STRBUF_INIT;
		response = get_response_line();

			die_short_read(input);
}
		snprintf(gitsvnline, MAX_GITSVN_LINE_LEN,
		check_preimage_overflow(preimage.max_off, 1);
		if (preimage.buf.buf[0] != '\n')
	assert(response);
{
		len -= 5;
		if (revision > 1)
	printf("data %ld\n", postimage_len);
		if (errno != ENOENT)
}
				off_t len, struct line_buffer *input)
		*gitsvnline = '\0';
}
	printf("data %"PRIuMAX"\n",
	struct sliding_view preimage = SLIDING_VIEW_INIT(&report_buffer, 0);
	if (err) {
	return parse_ls_response(get_response_line(), mode, dataref);
	printf("%s\n", gitsvnline);
		/* Treat missing paths as directories. */
	if (memchr(type + strlen(" blob "), '-', end - type - strlen(" blob ")))
static void ls_from_rev(uint32_t rev, const char *path)
		   *author ? author : "nobody",
		return error("cat-blob header does not contain length: %s", header);

	putchar('\n');
}

	/* Mode. */

{
	const char *end;
	}
		first_commit_done = 1;
{
			    strerror(errno));
/* NEEDSWORK: move to fast_export_init() */
#include "line_buffer.h"
	strbuf_release(&preimage.buf);
		errno = ENOENT;
	response_end = response + strlen(response);
{
#include "cache.h"
