	 * The section that defines the loosest possible
static int check_header(struct mailinfo *mi,
	ungetc(peek, mi->input);
		if (!line->len || (line->len == 1 && line->buf[0] == '\n')) {
}
			c -= '0' - 52;
	for (i = 0; header[i]; i++) {
			c = 0x20;
			return 1;
		strbuf_remove(line, 0, 1);
	/* Unstuff space-stuffed line. */
			handle_filter(mi, prev);
		mi->input_error = -1;
		else
		case '[':
				break; /* drop trailing newline */
	return ret;
	strbuf_add(&mi->email, bra + 1, ket - bra - 1);
		switch (tolower(encoding)) {

	/* Pick up the string around '@', possibly delimited with <>
static void output_header_lines(FILE *fout, const char *hdr, const struct strbuf *data)
	}
		strbuf_strip_suffix(&mi->inbody_header_accum, "\n");
			continue;
	strbuf_reset(it);
				return 1;
				flush_inbody_header_accum(mi);

	}
	if (boundary) {
	while (mi->content < mi->content_top) {
		}
	for (c = line; *c; c++) {
	 */
	case TE_BASE64:
			    const struct strbuf *line)
}
			 * as a header continuation line.
	do {
		visible = 0;
		strbuf_add(prev, line->buf, len - !!mi->delsp);
	}
	strbuf_addbuf(it, &outbuf);

		}
	return !memcmp(SAMPLE + (cp - line), cp, strlen(SAMPLE) - (cp - line));
	struct strbuf *src = name;
	int i;
			if (subject->len <= at + 3)
			strbuf_release(&newline);
			else {
					}
	strbuf_init(out, q_seg->len);
		strbuf_add(&sb, line->buf + len, line->len - len);
		in = ep + 2;
	struct strbuf *ret;
	struct strbuf sb = STRBUF_INIT;
	strbuf_rtrim(line);
	struct strbuf charset_q = STRBUF_INIT, piecebuf = STRBUF_INIT;
static int convert_to_utf8(struct mailinfo *mi,

			len--;
	}
static inline int patchbreak(const struct strbuf *line)
		peek = fgetc(mi->input);
}
		char c = at[-1];
static void handle_content_transfer_encoding(struct mailinfo *mi,
}


			if (mi->inbody_header_accum.len) {
			if (prev.len) {
	if (starts_with(line->buf, "Index: "))
	}
			sb->buf[pos] = ' ';
		return is_format_patch_separator(line->buf + 1, line->len - 1);
			len = strlen(sp);
	}
	return 1;
		    (59 <= ch && ch <= 126))
static int is_rfc2822_header(const struct strbuf *line)
			continue;
handle_body_out:

}
	strbuf_trim(&f);
	 * e-mail address.
		len--;
		strbuf_rtrim(&continuation);
					     const struct strbuf *line)

				if (!isspace(*scan))

		return 0; /* mi->input_error already set */
	}
			return 1;
			return 0;
	return in;
				cleanup_space(hdr);

		if (!find_boundary(mi, line))
	strbuf_init(&f, from->len);
		return;
static int is_scissors_line(const char *line)
}
		return;
static struct strbuf *decode_q_segment(const struct strbuf *q_seg, int rfc2047)
	strbuf_addch(&newline, '\n');
	memset(mi, 0, sizeof(*mi));
		}
	el = strcspn(at, " \n\t\r\v\f>");
		case 1:
	mi->delsp = has_attr_value(line->buf, "delsp=", "yes");
		strbuf_addch(&outbuf, c);
			case '\\':
	int c;
			mi->input_error = -1;
	 * optional-field = field-name ":" unstructured CRLF
				handle_filter_flowed(mi, sb, &prev);
	strbuf_init(&mi->inbody_header_accum, 0);
			case '(':
			ret = 1;

		if ((!memcmp(c, ">8", 2) || !memcmp(c, "8<", 2) ||
			strbuf_insert(line, 0, prev.buf, prev.len);
		size_t remove;
	strbuf_reset(&mi->email);
	size_t len = line->len;
}
		 */
	strbuf_init(&outbuf, line->len);

		case '(':
			/* Prepend any previous partial lines */
			for (cnt = 0; isspace(sb->buf[pos + cnt + 1]); cnt++);
	/* Beginning of a "diff -" header? */
{
			struct strbuf **lines, **it, *sb;
	 * perforation must occupy more than a third of the visible
	strbuf_release(&mi->inbody_header_accum);
			goto release_return;


		}
		len = strlen("Message-Id: ");
		/* Re-add the newline */
			/*
	/* perhaps others here */
	return mi->input_error;
{
}
	return 0;
	}
	 * field-name = 1*ftext

		else if (mi->p_hdr_data[i])
			break;
		if (mi->input_error)
	/* Skip up to the first boundary */
		strbuf_addch(line, '\n');
#include "cache.h"
	handle_filter(mi, line);
		/* we hit an end boundary */
	int scissors = 0, gap = 0;
	}
		if (*c == '-') {
		}
{
static int has_attr_value(const char *line, const char *name, const char *value)

		if (!find_boundary(mi, line))
	mi->transfer_encoding = TE_DONTCARE;
		strbuf_init(*out, line->len);
				strbuf_addch(outbuf, ')');
	/* John Doe <johndoe> */
	/* Save flowed line for later, but without the soft line break. */
			 * This is a scissors line; do not consider this line

			return 0;
		if (peek == EOF) {

	if (!cmitmsg) {

			if ((subject->buf[at + 1] == 'e' ||

	strbuf_release(&outbuf);
	int ch;
		mi->header_stage = 1;
			}

		goto again;
		mi->transfer_encoding = TE_BASE64;
		/* E.g.
	int found_error = 1; /* pessimism */
			continue;
			len = ep - sp;
	cmitmsg = fopen(msg, "w");
	free(mi->message_id);
				continue;
			switch (c) {
	if (strbuf_getline_lf(line, mi->input))
	strbuf_add(&mi->email, at, el);

		if ((!hdr_data[i] || overwrite) && cmp_header(line, header[i])) {

	while (in - it->buf <= it->len && (ep = strstr(in, "=?")) != NULL) {
	ap += strlen(name);
static int slurp_attr(const char *line, const char *name, struct strbuf *attr)

		/* Only trim the first (blank) line of the commit message

static int is_format_patch_separator(const char *line, int len)
		break;
		return 1;

}
			at[-1] = ' ';
		if (cp + 3 - it->buf > it->len)
	for (;;) {
		for (i = 0; header[i]; i++) {
	strbuf_release(ret);
	strbuf_init(&mi->email, 0);
		mi->filter_stage++;
	 */
	strbuf_release(&line);
	 */
	return 1;
				return in;
			in = unquote_comment(&outbuf, in);

		if (strbuf_getline_lf(&continuation, in))
			cleanup_space(hdr);

	while ((c = *in++) != 0) {
	int take_next_literally = 0;
	 * but we have removed the email part, so
		if (mi->input_error)
#include "utf8.h"
		strbuf_addbuf(&mi->inbody_header_accum, line);
	int c, pos = 0, acc = 0;
{
		}


static void handle_content_type(struct mailinfo *mi, struct strbuf *line)
	free(ret);
		return 0;

	if (strcasestr(line->buf, "base64"))
		if (!mi->s_hdr_data[i] && cmp_header(line, header[i]))
		ret = 1;
			hdr = mi->s_hdr_data[i];
	if (*ap == '"') {

	if (!mi->inbody_header_accum.len)
		if (take_next_literally == 1) {
			}
	if (starts_with(line->buf, ">From") && isspace(line->buf[5]))
		if (!encoding || cp[2] != '?')
	 * - remove extra spaces which could stay after email (case 'c'), and
	    !memcmp(line->buf + (*(mi->content_top))->len, "--", 2)) {
{
	if (!line->len || !is_rfc2822_header(line)) {
			return error("empty patch: '%s'", patch);
 * Returns 1 if the given line or any line beginning with the given line is an

			continue; /* garbage */
			if (ch >= 0) {
	cp += 40;
	get_sane_name(&mi->name, &mi->name, &mi->email);

	struct mailinfo *mi = mi_;
	int take_next_literally = 0;
 * case insensitively.
static void decode_transfer_encoding(struct mailinfo *mi, struct strbuf *line)
		return 1;
	}
#include "config.h"
		}
		 * ep : "=?iso-2022-jp?B?GyR...?= foo"
}
	if (line->len < 4)
 */
				in = unquote_comment(outbuf, in);
		for (i = 3; i < line->len; i++) {
{
		check_header(mi, &line, mi->p_hdr_data, 1);
		for (i = 0; mi->p_hdr_data[i]; i++)
			strbuf_addch(out, (acc | c));
				cleanup_subject(mi, hdr);
			     memmem(subject->buf + at, remove, "PATCH", 5)))
		free(boundary);
				perforation++;
			goto check_header_out;
	return 0;

		decode_header(mi, &sb);

	if (cmp_header(line, "Message-Id")) {
	strbuf_release(&newline);
		/* space followed by a filename? */
	fwrite(line->buf, 1, line->len, mi->patchfile);
{
		strbuf_addch(outbuf, c);
	const char *in = line->buf;
	strbuf_remove(&f, at - f.buf, el + (at[el] ? 1 : 0));
		/* Just whitespace? */
	} while (!strbuf_getwholeline(line, mi->input, '\n'));
				strbuf_add(&outbuf, in, ep - in);
			goto release_return;
			/*

	}
		fprintf(fout, "%s: %.*s\n", hdr, len, sp);
	if (!*out) {

			handle_header(&hdr_data[i], &sb);
	assert(!mi->filter_stage);
			return 0;
}
{
		if (!ep)
	if (mi->use_inbody_headers && mi->header_stage) {
		strbuf_add(&sb, line->buf + len, line->len - len);
		if (++mi->content_top >= &mi->content[MAX_BOUNDARIES]) {

			strbuf_list_free(lines);
				if (isspace(subject->buf[at]))
			if (in_perforation) {
			break;
	return !strncasecmp(line->buf, hdr, len) && line->len > len &&
			}
	 */
}
			return 0;
		case 0:
		strbuf_release(dec);
}
		} else {
	switch (mi->transfer_encoding) {
static void handle_filter(struct mailinfo *mi, struct strbuf *line)
			 * normalize the meta information to utf8.
	strbuf_release(&mi->log_message);
			at++;
out:
	while ((c = *in++) != 0) {
			}
		return 0;

				 * before the one we are about to process.
				continue;
			     charset, mi->metainfo_charset);

	 * field name is "3.6.8 Optional fields".
	/* normalize the log message to UTF-8. */
	if (!out) {
		mi->input_error = -1;
	struct strbuf newline = STRBUF_INIT;
		break;
{
static void handle_info(struct mailinfo *mi)
		}
		strbuf_reset(&charset_q);
	size_t i;



		     !memcmp(c, ">%", 2) || !memcmp(c, "%<", 2))) {
	/* Get the first part of the line. */

	/* CVS "Index: " line? */
				break;
			mi->content_top = &mi->content[MAX_BOUNDARIES] - 1;
		case ' ': case '\t': case ':':
static const char *header[MAX_HDR_PARSED] = {
			acc = (c & 3) << 6;
		/* only print inbody headers if we output a patch file */
	 * width of the line, and dashes and scissors must occupy more
		mi->content_top--;
		if (mi->patch_lines && mi->s_hdr_data[i])
		strbuf_release(boundary);
		if (mi->add_message_id)
		if (ch == ':')
{
			 * that begins at ep, but there is something
	fclose(cmitmsg);
		mi->use_scissors = git_config_bool(var, value);
			return 0;
			error("Detected mismatched boundaries, can't recover");
			char *scan;
		return;
		if (c == '=') {
			case '\\':
		return 0;

				continue;
	if (len != strlen(SAMPLE))
	 */
		ret = decode_b_segment(line);
			/* garbage -- fall through */

			strbuf_addf(&mi->log_message,
	if (!ket)
	/* This is fallback, so do not bother if we already have an
			continue;
		if (take_next_literally == 1) {
		/*
		perror(patch);
static struct strbuf *decode_b_segment(const struct strbuf *b_seg)
			    (7 <= remove &&
	while (at > f.buf) {
	strbuf_addstr(&outbuf, in);
				goto handle_body_out;
		ends = "\"";
			continue;
{
	unquote_quoted_pair(&f);
			goto release_return;
		case 'b':
			struct strbuf *hdr_data[], int overwrite)
	/* slurp in this section's info */

	mi->patch_lines++;
	 * Even though there can be arbitrary cruft on the same line
{
			     subject->buf[at + 1] == 'E') &&
		case '"':
		goto out;
static int is_multipart_boundary(struct mailinfo *mi, const struct strbuf *line)
	}
	while (1) {
	}
	free(mi->p_hdr_data);
		}
			}
			dec = decode_b_segment(&piecebuf);
	 */
				return in;
{
}
{

	strbuf_release(&mi->name);
}
		if (mi->header_stage)
			}
	strbuf_release(&prev);
{
	if (prev.len)
		if (mi->use_scissors && is_scissors_line(line->buf)) {
	if (!mi->metainfo_charset || !charset || !*charset)

	}
	if (!starts_with(var, "mailinfo."))
	char *in, *ep, *cp;
		perror(msg);
			return 1;
	}
		ungetc(peek, in);
			hdr = mi->p_hdr_data[i];
		ret = decode_q_segment(line, 0);
			in_perforation = 1;
	if (!skip_prefix(line, "From ", &cp))
			strbuf_addch(out, (acc | (c >> 2)));
					if (sb->buf[sb->len - 1] != '\n') {
			 * The partial chunk is saved in "prev" and will be
	return 0;
		for (i = 0; header[i]; i++)
static int check_inbody_header(struct mailinfo *mi, const struct strbuf *line)
	if (mi->email.len)
				break;
		}
			}
	return 0;
	return 1;
			 * at a time to handle_filter()

			goto release_return;
	if (convert_to_utf8(mi, line, mi->charset.buf))
				 * anyway.
	 * - trim from both ends, possibly removing the () pair at the end
	 * "---<sp>*" is a manual separator

	 * If we already have one email, don't take any confusing lines

		if (convert_to_utf8(mi, dec, charset_q.buf))
	strbuf_reset(out);
static void flush_inbody_header_accum(struct mailinfo *mi)
		else if ('a' <= c && c <= 'z')
			for (it = lines; (sb = *it); it++) {
	in = it->buf;
		strbuf_addbuf(&outbuf, dec);
		{
	}

		}
	out = reencode_string(line->buf, mi->metainfo_charset, charset);
		decode_transfer_encoding(mi, line);
			mi->message_id = strbuf_detach(&sb, NULL);
	/* process the email header */
	else if (strcasestr(line->buf, "quoted-printable"))

	static const char SAMPLE[] =
				    "Message-Id: %s\n", mi->message_id);
		mi->header_stage = 0;
		}
	found_error = 0;
	struct strbuf prev = STRBUF_INIT;
	/*
	strbuf_reset(&mi->name);
{

#include "strbuf.h"

		}
	if (f.buf[0] == '(' && f.len && f.buf[f.len - 1] == ')') {
}
{
	strbuf_insert(line, 0, prev->buf, prev->len);
		 * them to give ourselves a clean restart.
		if (isspace(*c)) {
{
		goto out;
release_return:
			}
{

static int git_mailinfo_config(const char *var, const char *value, void *mi_)

	strbuf_release(&mi->charset);
		if (first_nonblank == NULL)
}
			goto release_return;
	const char *rest;

		goto check_header_out;

	}
		if (isspace(sb->buf[pos])) {
			for (scan = in; scan < ep; scan++)
	strbuf_addch(line, '\n');
	case TE_DONTCARE:
			continue;
static void handle_body(struct mailinfo *mi, struct strbuf *line)
	const char *cp;
		 * ep : "=?ISO-8859-1?Q?Foo=FCbar?= baz"
			scissors += 2;
		case TE_BASE64:
		case 'r': case 'R':
}
static int find_boundary(struct mailinfo *mi, struct strbuf *line)
	char *at;
		return 0;
	default:
		boundary = NULL;
	char *cp = line->buf;
			if (!mi->keep_subject) {
	for (pos = 0; pos < sb->len; pos++) {
	}
		if (in != ep) {


		len = strlen("Content-Transfer-Encoding: ");

		if (rfc2047 && c == '_') /* rfc2047 4.2 (2) */
	int rc = slurp_attr(line, name, &sb) && !strcasecmp(sb.buf, value);
			/* Unwrap inline B and Q encoding, and optionally
			 * appended by the next iteration of read_line_with_nul().
	}
		handle_content_transfer_encoding(mi, &sb);
}
			c -= 'a' - 26;
	 * If so, stop here, and return false ("not a header")
			const struct strbuf *line,
	strbuf_init(boundary, line->len);

	/*
	at = strchr(f.buf, '@');
		strbuf_add(&sb, line->buf + len, line->len - len);
static const char *unquote_comment(struct strbuf *outbuf, const char *in)
	if (!bra)
check_header_out:


	flush_inbody_header_accum(mi);
	strbuf_init(&mi->charset, 0);
			strbuf_addch(out, (acc | (c >> 4)));
	}
	free(mi->s_hdr_data);
						strbuf_addbuf(&prev, sb);

	}
	 * Now we need to eat all the continuation lines..
	if (skip_prefix(line->buf, "-- ", &rest) && rest - line->buf == len) {
	if (*(mi->content_top)) {
	if (name->len < 3 || 60 < name->len || strchr(name->buf, '@') ||
		/* skip to the next boundary */
	return out;
			perforation++;
	/*
		/* process any boundary lines */
				/*
			handle_from(mi, hdr);
	strbuf_init(out, b_seg->len);
	get_sane_name(&mi->name, &f, &mi->email);
	while ((c = *in++) != 0) {
		}
			break;
			take_next_literally = 0;
		if ((33 <= ch && ch <= 57) ||
	if (patchbreak(line)) {

{
static int is_inbody_header(const struct mailinfo *mi,
	strbuf_trim(&mi->name);
	 * - "john.doe@xz (John Doe)"			(b), or
			 * multiple new lines.  Pass only one chunk




		ret = 1;
	return 0;
		ep += 2;
	}
				break;
		gap * 2 < perforation);
	struct strbuf *out = xmalloc(sizeof(struct strbuf));


	}
		return;
				 * the space, since we later normalize it
	}
				continue;
	}
}

		if (c == '<') {
			pos = strchr(subject->buf + at, ']');
		return error("cannot convert from %s to %s",
		strbuf_addch(outbuf, c);
		mi->transfer_encoding = TE_QP;
	else
{
}
{

	if (line->len >= (*(mi->content_top))->len + 2 &&
		if (line->buf[3] == ' ' && !isspace(line->buf[4]))
		switch (subject->buf[at]) {
			break;
		if (prev->len) {
		return -1;
}
		return 0;
static void handle_header(struct strbuf **out, const struct strbuf *line)
	if (starts_with(line->buf, "diff -"))
	if (!strcmp(var, "mailinfo.scissors")) {
		goto check_header_out;
	}
	if (mi->use_scissors && is_scissors_line(line->buf)) {
		ap++;
		strchr(name->buf, '<') || strchr(name->buf, '>'))
	int c;
		if (*(mi->content_top) && is_multipart_boundary(mi, line))
	 */

		return 0;
		}
	strbuf_add(attr, ap, sz);


			flush_inbody_header_accum(mi);
 * on our mailing lists.  For example, we do not even treat header lines
	}
	while (read_one_header_line(&line, mi->input))
	else if (name == out)
		/* pop the current boundary off the stack */
#define MAX_HDR_PARSED 10
		   will fail first.  But just in case..
		if (mi->message_id)
			unsigned char c = line->buf[i];
int mailinfo(struct mailinfo *mi, const char *msg, const char *patch)
			   struct strbuf *line, const char *charset)
		 */
			c = 62;
	int c;
	mi->format_flowed = has_attr_value(line->buf, "format=", "flowed");
	return 0;
	if (!at) {
			ch = hex2chr(in);
	/*
	 * - "John (zzz) Doe <john.doe@xz> (Comment)"	(c)


again:
		in_perforation = 0;
			c -= 'A';
{
		char *pos;
				 * If the input had a space after the ], keep
	/*
	}
}
		if (ep - it->buf >= it->len || !(cp = strchr(ep, '?')))
	 */
			acc = (c & 15) << 4;
	} else
	mi->s_hdr_data = xcalloc(MAX_HDR_PARSED, sizeof(*(mi->s_hdr_data)));
		sp = ep + 1;
	 * Yuck, 2822 header "folding"
	if (!mi->patchfile) {
		strbuf_setlen(&f, f.len - 1);
	bra = strchr(line->buf, '<');
static void handle_from(struct mailinfo *mi, const struct strbuf *from)


	while ((c = *in++) != 0) {

	return 0;
{
	}
	struct strbuf outbuf = STRBUF_INIT, *dec;
	 *
			lines = strbuf_split(line, '\n');
	struct strbuf *content_top = *(mi->content_top);
				strbuf_release(mi->s_hdr_data[i]);
			mi->content_top = mi->content;
		return 0;
		case 2:
	size_t sz;
		strbuf_reset(*out);
	/* Content stuff */
	strbuf_reset(&mi->email);
		int len = strlen(header[i]);
		else
		if (isspace(c))
		switch (pos++) {
		switch (mi->transfer_encoding) {
{
}
	while ((ch = *cp++)) {
	if (starts_with(line->buf, "---")) {
	}
	else
	const char *c;
			case '"':
{
{
				handle_header(&mi->s_hdr_data[i], line);
	const char *in = q_seg->buf;
		/* technically won't happen as is_multipart_boundary()

			fprintf(mi->output, "%s: %s\n", header[i], hdr->buf);
	strbuf_release(&f);
		return 1;
			c++;
	strbuf_addch(outbuf, '(');


			break;
	struct strbuf *hdr;

		}
			handle_filter_flowed(mi, line, &prev);


	size_t pos, cnt;
		if (c == '+')
		 */
		return git_default_config(var, value, NULL);
		else if ('0' <= c && c <= '9')

			if (!strcmp("Subject", header[i])) {
	 * ftext = %d33-57 / %59-126
		strbuf_addbuf(line, &continuation);
	const char *first_nonblank = NULL, *last_nonblank = NULL;
		len--;
}
	int i, ret = 0, len;

		case TE_QP:
	while (!strbuf_getline_lf(line, mi->input)) {
static int handle_commit_msg(struct mailinfo *mi, struct strbuf *line)
		if (!ep)
	/*
	struct strbuf continuation = STRBUF_INIT;
}
		return 0;

		return;
			strbuf_release(mi->s_hdr_data[i]);
	case TE_QP:
		handle_filter(mi, &prev);
	return in;


		strbuf_release(&newline);
	if (mi->s_hdr_data)
		return;
					break;
		return;
		switch (c) {
	slurp_attr(line->buf, "charset=", &mi->charset);

			if (!pos)
	    (line->buf[0] == ' ' || line->buf[0] == '\t')) {
			in = unquote_quoted_string(&outbuf, in);
	 * than half of the perforation.
	mi->patchfile = fopen(patch, "w");
{
		return 1;
	FILE *cmitmsg;
			if (c == '\n')
		strbuf_insert(boundary, 0, "--", 2);
		} else {

	cleanup_space(&f);

					at += 1;
	int visible, perforation = 0, in_perforation = 0;
			decode_header(mi, &sb);
				take_next_literally = 1;
{
static void cleanup_space(struct strbuf *sb)
	/* search for the interesting parts */
static inline int cmp_header(const struct strbuf *line, const char *hdr)
			break;
		break;
		}
		} else if (!strcmp(header[i], "From")) {
	for (i = 0; header[i]; i++) {

	}
	/* Prepend any previous partial lines */

			 */
	int len = strlen(hdr);
		ret = 1;
	if (mi->header_stage) {
			return;
	if (strbuf_getline_lf(line, in))

	strbuf_addbuf(line, ret);
	strbuf_release(&charset_q);
	 *
	struct strbuf outbuf;
		}
	strbuf_addbuf(&f, from);
{
}
	}
 * mi->s_hdr_data).
			/*

		strbuf_release(*(mi->content_top));

	 *
	if (slurp_attr(line->buf, "boundary=", boundary)) {


			if (!mi->keep_non_patch_brackets_in_subject ||

			break;
			fprintf(mi->output, "Author: %s\n", mi->name.buf);

	if (mi->email.len && strchr(at + 1, '@'))
	}
		case 'q':


			switch (c) {
	int i;

}
	if (!check_header(mi, &mi->inbody_header_accum, mi->s_hdr_data, 0))
	"From","Subject","Date",
				handle_filter(mi, &prev);
	}

{
		decode_header(mi, &sb);
}
		src = email;
			acc = (c << 2);
			if (scan != ep || in == it->buf) {
	mi->header_stage = 1;
	const char *sp = data->buf;
	size_t at = 0;
		len = strlen("Content-Type: ");
	}
	case 1:
	}
		int len;
{

		return 0;
	else
	strbuf_reset(&mi->inbody_header_accum);
		return 1;

			 */

		check_header(mi, line, mi->p_hdr_data, 0);
/*
		continuation.buf[0] = ' ';
		return;
	const char *in = b_seg->buf;
	while ((c = *in++) != 0) {
	if (cmp_header(line, "Content-Transfer-Encoding")) {
}
		encoding = cp[1];
	size_t el;
	flush_inbody_header_accum(mi);
 * to have enough heuristics to grok MIME encoded patches often found
		return 0;
		handle_content_type(mi, &sb);
		if (!strcmp(header[i], "Subject")) {


				/*
		strbuf_addch(out, c);
}
			in_perforation = 1;
	sz = strcspn(ap, ends);
	strbuf_release(&outbuf);
		}
	/* replenish line */
				strbuf_remove(subject, at, remove);
	/* Count mbox From headers as headers */
		return 0;
{

	while (at < subject->len) {
		else
	git_config(git_mailinfo_config, mi);
	handle_body(mi, &line);
static int read_one_header_line(struct strbuf *line, FILE *in)
			strbuf_remove(sb, pos + 1, cnt);
				 */
	strbuf_swap(&outbuf, line);
		int i;
}
		}
	fclose(mi->patchfile);
	strbuf_init(&mi->log_message, 0);
static void handle_filter_flowed(struct mailinfo *mi, struct strbuf *line,
	if (is_inbody_header(mi, line)) {
			    subject->buf[at + 2] == ':') {
static void handle_patch(struct mailinfo *mi, const struct strbuf *line)

		int peek;
	do {
			if (!isspace(c))
						/* Partial line, save it for later. */

static const char *unquote_quoted_string(struct strbuf *outbuf, const char *in)
			 */
		default:
static void unquote_quoted_pair(struct strbuf *line)
			/* flush any leftover */
static void cleanup_subject(struct mailinfo *mi, struct strbuf *subject)
			 */
{
	strbuf_setlen(attr, 0);
			 * before the encoded word.
				 */
	struct strbuf *out = xmalloc(sizeof(struct strbuf));
	return out;
void setup_mailinfo(struct mailinfo *mi)
		break;


		goto check_header_out;

			break;
	if (starts_with(line->buf, "[PATCH]") && isspace(line->buf[7])) {
static void parse_bogus_from(struct mailinfo *mi, const struct strbuf *line)

	for (i = 0; header[i]; i++)
				strbuf_remove(subject, at, 3);

			 * This is a decoded line that may contain
		return;
				 * unless we have just processed an
			break;
		strbuf_setlen(&mi->log_message, 0);
				continue;

		break;
	strbuf_init(&mi->name, 0);
	 * (e.g. "cut here"), in order to avoid misidentification, the
			first_nonblank = c;
		return 0;
			if (d == '\n' || !d)
	fprintf(mi->output, "\n");
		if (len && line->buf[len - 1] == '\r')
		handle_patch(mi, line);
			if (mi->s_hdr_data[i])
	struct strbuf f;
	strbuf_addbuf(*out, line);
	strbuf_attach(line, out, strlen(out), strlen(out));
	}

 */
			 */
	if (len && line->buf[0] == ' ') {
		strbuf_reset(&piecebuf);
		FREE_AND_NULL(*(mi->content_top));
						break;
	strbuf_release(&sb);
void clear_mailinfo(struct mailinfo *mi)
static void get_sane_name(struct strbuf *out, struct strbuf *name, struct strbuf *email)
			break;
		if (!ep)
		char *ep = strchr(sp, '\n');
			remove = pos - subject->buf + at + 1;

		*(mi->content_top) = boundary;

			goto handle_body_out;
{
		strbuf_add(&charset_q, ep, cp - ep);
			continue;
	}
		handle_filter(mi, &newline);
			goto release_return;
	if (same_encoding(mi->metainfo_charset, charset))
		}
#include "mailinfo.h"
				strbuf_addch(out, ch);
			perforation += 2;
	/* Keep signature separator as-is. */
	strbuf_addbuf(&mi->log_message, line);
			int ch, d = *in;
	return ((content_top->len <= line->len) &&
		ends = "; \t";
	strbuf_reset(line);
			case ')':
			c = 63;
		mi->header_stage = check_inbody_header(mi, line);
{
				 * We should not lose that "something",
	int c;
			break;
		default:
	ket = strchr(bra, '>');
		}
			return 1;
}
	mi->content_top = mi->content;
	strbuf_release(&piecebuf);
			}
		free(*(mi->content_top));
	int i;
	 * "--- <filename>" starts patches without headers
	if (!ap)
		peek = fgetc(in);
			output_header_lines(mi->output, "Subject", hdr);
		parse_bogus_from(mi, from);

		for (i = 0; mi->s_hdr_data[i]; i++)
		if (--mi->content_top < mi->content) {
	const char *ends, *ap = strcasestr(line, name);
	if (!mi->format_flowed) {
}
	int peek;
				 * it.  We don't bother with finding the end of
		handle_filter(mi, line);
}
}

	mi->p_hdr_data = xcalloc(MAX_HDR_PARSED, sizeof(*(mi->p_hdr_data)));
	char *out;
		} else {
				mi->header_stage = 0;
};
	if (len && line->buf[len - 1] == ' ') {
			break;
		return 0;
	if (line->buf[len - 1] == '\n') {
		}

 * in-body header (that is, check_header will succeed when passed

}

		 * We may have already read "secondary headers"; purge
		mi->transfer_encoding = TE_DONTCARE;
			return 0;
	struct strbuf *boundary = xmalloc(sizeof(struct strbuf));
			acc = pos = 0;

		last_nonblank = c;
	if (found_error)
		visible < perforation * 3 &&
	}
		strbuf_add(&piecebuf, cp + 3, ep - cp - 3);
	strbuf_addbuf(out, src);
	/* Decode in..ep, possibly in-place to ot */
			mi->s_hdr_data[i] = NULL;
		else if ('A' <= c && c <= 'Z')
				at += remove;
		fclose(cmitmsg);
}
		}
{
}
		decode_header(mi, &sb);
			continue;
			continue;
	 * Is it an empty line or not a valid rfc2822 header?
/* NOTE NOTE NOTE.  We do not claim we do full MIME.  We just attempt
			cleanup_space(hdr);
		BUG("inbody_header_accum, if not empty, must always contain a valid in-body header");

		strbuf_insert(&sb, 0, "Content-Type: ", len);
	strbuf_reset(prev);
	}
				gap++;
	switch (mi->filter_stage) {
	if (cmp_header(line, "Content-Type")) {
		/* Unwrap transfer encoding */

			break;



		if (peek != ' ' && peek != '\t')

		ep = strstr(cp + 3, "?=");
	} while (isspace(peek));
{
	strbuf_release(&mi->email);
			}
			fprintf(mi->output, "Email: %s\n", mi->email.buf);
	if (mi->inbody_header_accum.len &&
static int handle_boundary(struct mailinfo *mi, struct strbuf *line)
		handle_filter(mi, line);
{
		return -1;
		int encoding;
			break;
			break;
	case 0:
	fwrite(mi->log_message.buf, 1, mi->log_message.len, cmitmsg);
			 * We are about to process an encoded-word
				return 1;
	if (strspn(cp, "0123456789abcdef") != 40)
		}

			break;
				take_next_literally = 1;
				 * encoded-word, and there is only LWS
				if (*(it + 1) == NULL) /* The last line */
			}
	}
		at--;
		case 3:
			error("Too many boundaries to handle");
		return 0;
			strbuf_add(&sb, line->buf + len + 2, line->len - len - 2);
}
{
				strbuf_reset(&prev);
				in += 2;
	while (read_one_header_line(line, mi->input))
	}

	}
{
	if (starts_with(cp, "From ") || starts_with(cp, ">From "))
		if (peek == EOF)
	 *   (cases 'a' and 'b').
}
static void decode_header(struct mailinfo *mi, struct strbuf *it)
	strbuf_trim(subject);
	/* set some defaults */
			dec = decode_q_segment(&piecebuf, 1);
		if (*(mi->content_top) && is_multipart_boundary(mi, line)) {
	return (scissors && 8 <= visible &&
		/* fallthrough */
	 * The mark must be at least 8 bytes long (e.g. "-- >8 --").
	} else
				 struct strbuf *prev)
		else if (c == '/')
		"From e6807f3efca28b30decfecb1732a56c7db1137ee Mon Sep 17 00:00:00 2001\n";

	 * pair; that is the email part.
		 */
			strbuf_remove(subject, at, 1);
			strbuf_reset(prev);
	}
	strbuf_reset(&mi->charset);
	}
		strbuf_remove(&f, 0, 1);

	 * - "John Doe <john.doe@xz>"			(a), or
			/*
	return rc;
		int i;
			}
	strbuf_release(&continuation);
	if (mi->p_hdr_data)

			strbuf_release(mi->p_hdr_data[i]);

		return 1;
	strbuf_add(&mi->name, line->buf, bra - line->buf);
		!memcmp(line->buf, content_top->buf, content_top->len));
		free(dec);
	struct strbuf line = STRBUF_INIT;
		 * when ignoring in-body headers.
		}
	strbuf_release(&sb);
		strbuf_addbuf(&mi->inbody_header_accum, line);
			fclose(cmitmsg);
}

			mi->input_error = -1;
		*out = xmalloc(sizeof(struct strbuf));
	 *
	struct strbuf sb = STRBUF_INIT;

	/* The remainder is name.  It could be

	}
	if (first_nonblank && last_nonblank)
	handle_info(mi);
	 */
	mi->use_inbody_headers = 1;
		visible = last_nonblank - first_nonblank + 1;
			line->buf[len] == ':' && isspace(line->buf[len + 1]);
		if (!handle_commit_msg(mi, line))
			if (!handle_boundary(mi, line))
			strbuf_reset(&prev);
	return 0;


{
			take_next_literally = 0;
	char *bra, *ket;
