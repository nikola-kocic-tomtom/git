		/* strlen(key) + 1 */
	if (buffer_deinit(&input))
#define NODEACT_UNKNOWN 0
 * Licensed under a two-clause BSD-style license.

	strbuf_init(&rev_ctx.log, 4096);
				begin_revision(local_ref);
			if (constcmp(t, "UUID"))
	} else {
		fast_export_begin_note(rev_ctx.revision, "remote-svn",
		return error_errno("cannot open %s", filename ? filename : "NULL");
	const int have_props = node_ctx.prop_length != -1;
	strbuf_init(&node_ctx.dst, 4096);
	switch (keylen + 1) {
		case sizeof("Revision-number"):
		switch (val - t - 1) {

		    constcmp(key, "svn:executable"))
}
				continue;
	dump_ctx.version = 1;
		if (node_ctx.prop_length)
			} else {
#include "fast_export.h"
		uint32_t mode;
		break;
	fast_export_blob_delta(node_ctx.type, old_mode, old_data,
		node_ctx.type = keylen == strlen("svn:executable") ?
		return;
			handle_property(&key, &val, &type_set);
	char *t;
{
}
	reset_dump_ctx(url);
	strbuf_release(&rev_ctx.note);
	if (active_ctx == REV_CTX)
				if (*t == 'T')
		return;
static void handle_node(void)
#define DATE_RFC2822_LEN 31
			dump_ctx.version = atoi(val);
		strbuf_addf(&mark, ":%"PRIu32, rev_ctx.revision);

	node_ctx.type = 0;
			node_ctx.type = S_IFREG | 0644;
	strbuf_init(&node_ctx.src, 4096);
				fprintf(stderr, "Unexpected content length header: %"PRIu32"\n", len);
{
	node_ctx.prop_length = -1;
static void end_revision(const char *note_ref)
#define NODEACT_REPLACE 4
}
		case sizeof("Content-length"):
	node_ctx.srcRev = 0;
		rev_ctx.timestamp, remote_ref);
	struct strbuf src, dst;
	 */
		}
} node_ctx;
		old_data = fast_export_read_path(node_ctx.dst.buf, &mode);
		ch = buffer_read_char(&input);

		if (mode != S_IFDIR && type == S_IFDIR)
	case sizeof("svn:executable"):
	strbuf_release(&rev_ctx.author);
 * Parse and rearrange a svnadmin dump.
			if (!constcmp(t + strlen("Node-"), "path")) {
	uint32_t text_delta, prop_delta;
{
	 * Adjust mode to reflect properties.
		case sizeof("UUID"):
	if (!have_text) {
	} else if (node_ctx.action == NODEACT_CHANGE) {
	 * Old text for this node:
	}
	 * we keep track of whether a mode has been set and reset to
			}
			if (constcmp(t, "Prop-delta"))
		if (!val) {
		begin_revision(local_ref);
	if(buffer_fdinit(&input, xdup(in_fd)))
			break;
			} else if (!strcmp(val, "change")) {
				fprintf(stderr, "Unknown node-action: %s\n", val);
		case sizeof("Node-copyfrom-path"):
			die("invalid dump: cannot modify a directory into a file");
				reset_node_ctx(val);
		switch (type) {
			node_ctx.prop_delta = !strcmp(val, "true");
	case sizeof("svn:special"):
		return;
	uint32_t action, srcRev, type;
	if (type == S_IFDIR)	/* directories are not tracked. */
	}

	 *  empty_blob	- empty

			return;
	if (url)
	rev_ctx.revision = revision;
			node_ctx.srcRev = atoi(val);
	uint32_t version;
			break;
			continue;
				end_revision(notes_ref);
	fast_export_modify(node_ctx.dst.buf, node_ctx.type, "inline");
		strbuf_release(&mark);

#define NODE_CTX 2	/* node metadata */
					die("unrepresentable length in dump: %s", val);
			break;
			if (!strcmp(val, "delete")) {
		const char type = t[0];

int svndump_init(const char *filename)
			continue;
static void reset_rev_ctx(uint32_t revision)
	strbuf_reset(&node_ctx.dst);
static struct {
#include "svndump.h"
			if (!t)
		if (val.len < len)
			strbuf_reset(&dump_ctx.uuid);
	return 0;
	if (node_ctx.action == NODEACT_DELETE) {
			if (constcmp(t, "Node-copyfrom-path"))
	if (active_ctx == NODE_CTX)
			} else if (!strcmp(val, "add")) {

				node_ctx.action = NODEACT_DELETE;
				node_ctx.action = NODEACT_REPLACE;
{
			reset_rev_ctx(atoi(val));
		die("invalid dump: Node-path block lacks Node-action");
				char *end;
}
			if (constcmp(t, "Node-"))
	if (node_ctx.action == NODEACT_CHANGE && !*node_ctx.dst.buf) {
		die("invalid dump: directories cannot have text attached");
			strbuf_addf(&rev_ctx.note, "%s\n", t);
		if (keylen == strlen("svn:executable") &&
	init(REPORT_FILENO);

	}
				strbuf_addf(&rev_ctx.note, "%s\n", t);

 * Compare start of string to literal of equal length;

	static const char *const empty_blob = "::empty::";
		fast_export_end_commit(rev_ctx.revision);
	uint32_t len;
		if (constcmp(key, "svn:date"))
}
		if (constcmp(key, "svn:log"))
		old_data = NULL;
		fprintf(stderr, "Output error\n");
	return;
			break;
			die_short_read();
		buffer_read_binary(&input, &val, len);
			len = atoi(val);
	strbuf_reset(&rev_ctx.log);
		}
		node_ctx.action = NODEACT_ADD;
					node_ctx.text_length = (off_t) len;
			warning("invalid timestamp: %s", val->buf);
	}
void svndump_read(const char *url, const char *local_ref, const char *notes_ref)
}
				break;
		uint32_t len;
				continue;
	timestamp_t timestamp;
	 * NEEDSWORK: to support simple mode changes like

			strbuf_addf(&rev_ctx.note, "%s\n", t);
	 * Save the result.
	struct strbuf uuid, url;
				struct strbuf *val,
			break;
}
{
}
	assert(old_data);
			} else if (active_ctx == NODE_CTX) {
				uint32_t *type_set)
		strbuf_reset(&val);
				active_ctx = INTERNODE_CTX;
			if (active_ctx == REV_CTX) {
					node_ctx.prop_length = (off_t) len;
			continue;
		if (parse_date_basic(val->buf, &rev_ctx.timestamp, NULL))
	reset_node_ctx(NULL);
		old_mode = mode;
				if (!isdigit(*val) || *end)
	const uint32_t type = node_ctx.type;
 * must be guarded by length test.
{
			t = buffer_read_line(&input);
				continue;
{
	uint32_t revision;
					handle_node();
static void read_props(void)
	} else if (node_ctx.action == NODEACT_ADD) {
			die("invalid dump: unsets svn:date");
		return;
			break;


int svndump_init_fd(int in_fd, int back_fd)
				break;

	if (node_ctx.action == NODEACT_REPLACE) {
		die_short_read();
			die("invalid dump: expected newline after %s", val.buf);
					die("invalid dump: non-numeric length %s", val);

			continue;
	uint32_t active_ctx = DUMP_CTX;

void svndump_deinit(void)
	/*
	const char *old_data = NULL;
#include "cache.h"
	strbuf_release(&dump_ctx.uuid);
			strbuf_addf(&rev_ctx.note, "%s\n", t);
		case 'V':
 * svnadmin dump --incremental -r<startrev>:<endrev> <repository> >outfile
				active_ctx = NODE_CTX;
	if (have_props) {
	/*
		if (mode == S_IFDIR && type != S_IFDIR)
				die("invalid dump: expected blank line after content length header");

	}
	const int have_text = node_ctx.text_length != -1;
	node_ctx.text_length = -1;
			die("invalid dump: cannot modify a file into a directory");
			if (constcmp(t, "Revision-number"))
static struct {
	strbuf_reset(&rev_ctx.note);
		if (constcmp(key, "svn:author"))
static void init(int report_fd)
	fast_export_begin_commit(rev_ctx.revision, rev_ctx.author.buf,
static void die_short_read(void)
	uint32_t old_mode = S_IFREG | 0644;
static void reset_node_ctx(char *fname)
	 */
	}
	strbuf_release(&node_ctx.dst);
		case sizeof("Node-copyfrom-rev"):
 *
				fprintf(stderr, "Unknown node-kind: %s\n", val);

	 */
				continue;
				"copyfrom info, text, or properties");
	die("invalid dump: unexpected end of file");
			strbuf_reset(&node_ctx.src);
			read_props();
	 * plain file only if not.  We should be keeping track of the
	if (node_ctx.srcRev) {
				S_IFLNK;
	strbuf_reset(&rev_ctx.author);
{
	/*
{

	case sizeof("svn:log"):
/*
	node_ctx.prop_delta = 0;
	strbuf_release(&rev_ctx.log);
				continue;
}
	const char *t;
		else
		if (*val != ' ')
	strbuf_release(&node_ctx.src);
		fast_export_note(mark.buf, "inline");
	}
			die("invalid dump: adds node without text");
{
			strbuf_addstr(&node_ctx.src, val);

			}
			die("invalid dump: deletion node has "
		case sizeof("Node-action"):
		fast_export_data(node_ctx.type, node_ctx.text_length, &input);
				node_ctx.action = NODEACT_ADD;
			strbuf_addf(&rev_ctx.note, "%s\n", t);
} rev_ctx;
	static struct strbuf val = STRBUF_INIT;
			strbuf_swap(&rev_ctx.author, val);
		if (!val)
		fprintf(stderr, "Input error\n");
}
		break;
				    dump_ctx.version);
			break;
}
		if (type != S_IFDIR)
{
	if (have_text && type == S_IFDIR)
	 */
	node_ctx.action = NODEACT_UNKNOWN;
				continue;
			strbuf_reset(&rev_ctx.author);
			break;
			die("invalid dump: unsets svn:log");
			if (active_ctx == NODE_CTX)
static struct {
		case sizeof("Text-delta"):
		if (!val)
			if (constcmp(t, "Text") && constcmp(t, "Prop"))
		case 'K':
	strbuf_release(&dump_ctx.url);
 * Create the dump with:
			if (constcmp(t + 4, "-content-length"))
	/*

		}
	reset_node_ctx(NULL);
				if (active_ctx == NODE_CTX)
	/*
	strbuf_init(&rev_ctx.author, 4096);
			if (active_ctx == REV_CTX)
	const char *key = key_buf->buf;
/* States: */
				die_short_read();
	strbuf_reset(&node_ctx.src);
#include "strbuf.h"
	}

		if (ch != '\n')
			old_data = NULL;
		fast_export_delete(node_ctx.dst.buf);
			if (!val)
		fast_export_modify(node_ctx.dst.buf, node_ctx.type, "inline");
				node_ctx.type = S_IFDIR;
	case sizeof("svn:date"):
	}
			continue;
			if (constcmp(t, "Node-action"))
	 *  "<dataref>"	- data retrievable from fast-import

}
	struct strbuf mark = STRBUF_INIT;
		else if (have_text)
			break;
			active_ctx = REV_CTX;
	strbuf_release(&rev_ctx.log);
	fast_export_init(report_fd);
		/* Discard trailing newline. */
	off_t prop_length, text_length;
					begin_revision(local_ref);
			die("invalid property line: %s", t);
 */
	}
#define NODEACT_ADD 2
		if (have_text || have_props || node_ctx.srcRev)
	if (active_ctx != DUMP_CTX)
}
		fast_export_delete(node_ctx.dst.buf);
	uint32_t type_set = 0;
	 *	V 1
		else
		val++;
			node_ctx.type = type;
				if (buffer_skip_bytes(&input, len) != len)
	 *	svn:special
		}
static void begin_revision(const char *remote_ref)

			if (dump_ctx.version > 3)
	while ((t = buffer_read_line(&input))) {
	 *	svn:executable
}
			die("invalid dump: root of tree is not a regular file");
				uintmax_t len;
				node_ctx.action = NODEACT_UNKNOWN;
				handle_node();
#define DUMP_CTX 0	/* dump metadata */
	strbuf_init(&dump_ctx.uuid, 4096);


		if (!val)
	 * symlink and executable bits separately instead.
#define NODEACT_CHANGE 1
	 */
			if (constcmp(t + strlen("Node-"), "kind"))
		die_errno("error reading dump file");
				continue;
			{
		len = atoi(&t[2]);
		fast_export_buf_to_data(&rev_ctx.note);
{
		strbuf_addstr(&dump_ctx.url, url);
				handle_node();
			break;
			strbuf_addstr(&dump_ctx.uuid, val);
				node_ctx.text_length, &input);
	 *	K 11
	}
	node_ctx.text_delta = 0;
		*type_set = 1;
			break;

			}
			die("invalid property line: %s", t);
			if (constcmp(t, "SVN-fs-dump-format-version"))
		case sizeof("Node-path"):
			} else {

	char *val;
	if (!rev_ctx.revision)	/* revision 0 gets no git commit. */
	reset_dump_ctx(NULL);
		val = strchr(t, ':');
		break;
				else
			old_data = empty_blob;
} dump_ctx;
		node_ctx.type = mode;
	if (ferror(stdout))
		strbuf_swap(&rev_ctx.log, val);

				node_ctx.action = NODEACT_CHANGE;
	if (old_data == empty_blob)
	reset_rev_ctx(0);
			if (!strcmp(val, "dir"))
	strbuf_init(&rev_ctx.note, 4096);
		case sizeof("Text-content-length"):
		fast_export_modify(node_ctx.dst.buf, node_ctx.type, old_data);
			break;
		old_data = NULL;
#define constcmp(s, ref) memcmp(s, ref, sizeof(ref) - 1)
	 *	D 14
			die_short_read();
		if (*type_set) {
	strbuf_release(&rev_ctx.author);
			if (active_ctx != DUMP_CTX)

		fast_export_copy(node_ctx.srcRev, node_ctx.src.buf, node_ctx.dst.buf);
	strbuf_reset(&dump_ctx.uuid);
			else if (!strcmp(val, "file"))
		int ch;
	case sizeof("svn:author"):
			} else if (!strcmp(val, "replace")) {
static void reset_dump_ctx(const char *url)
			}
		&rev_ctx.log, dump_ctx.uuid.buf, dump_ctx.url.buf,
		case sizeof("SVN-fs-dump-format-version"):
	 *  NULL	- directory or bug
			strbuf_addf(&rev_ctx.note, "%s\n", t);
		if (!val)
#define REPORT_FILENO 3
			if (*t)
				continue;
			strbuf_swap(&key, &val);
	rev_ctx.timestamp = 0;

 */
	if (rev_ctx.revision) {
			handle_property(&val, NULL, &type_set);
				return;
static void handle_property(const struct strbuf *key_buf,
	init(xdup(back_fd));
	strbuf_reset(&dump_ctx.url);
			node_ctx.action = NODEACT_CHANGE;

		if (node_ctx.action == NODEACT_ADD)

#define INTERNODE_CTX 3	/* between nodes */
#define REV_CTX  1	/* revision metadata */
		end_revision(notes_ref);
		if (keylen == strlen("svn:special") &&
{
	if (fname)
			if (constcmp(t, "Content-length"))
	while ((t = buffer_read_line(&input)) && strcmp(t, "PROPS-END")) {
	reset_dump_ctx(NULL);
				break;
	size_t keylen = key_buf->len;
				continue;
				if (len > maximum_signed_value_of_type(off_t))
#include "line_buffer.h"
 * See LICENSE for details.
				node_ctx.text_delta = !strcmp(val, "true");
				continue;
/*
		case 'D':
		if (!type || t[1] != ' ')
				continue;
				die("expected svn dump format version <= 3, found %"PRIu32,
void svndump_reset(void)
				continue;
	if (!node_ctx.text_delta) {
		if (ch == EOF)
			if (constcmp(t, "Node-copyfrom-rev"))
#define NODEACT_DELETE 3
}
	return 0;
				(S_IFREG | 0755) :
			else
static struct line_buffer input = LINE_BUFFER_INIT;
	 *	*
			strbuf_reset(&key);
		return error_errno("cannot open fd %d", in_fd);
	struct strbuf log, author, note;
				node_ctx.type = S_IFREG | 0644;
{
			if (!constcmp(t, "Text-delta")) {
		    constcmp(key, "svn:special"))
	if (buffer_ferror(&input))
		if (!node_ctx.prop_delta)
					die_short_read();
	reset_rev_ctx(0);
{
		return;
		handle_node();
				if (active_ctx == REV_CTX)
				read_props();
			die("invalid dump: sets type twice");
	if (buffer_init(&input, filename))
		if (type == S_IFDIR)
		val++;
		default:
	strbuf_init(&dump_ctx.url, 4096);

			}
	 * Find old content (old_data) and decide on the new mode.
			break;
	static struct strbuf key = STRBUF_INIT;
	if (buffer_ferror(&input))
		strbuf_addstr(&node_ctx.dst, fname);
				len = strtoumax(val, &end, 10);

		/* For the fast_export_* functions, NULL means empty. */
	fast_export_deinit();
				"Note created by remote-svn.", rev_ctx.timestamp, note_ref);
