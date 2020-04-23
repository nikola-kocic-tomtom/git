
				 * We should not lose that "something",
		check_header(mi, &line, mi->p_hdr_data, 1);
	int c;


		handle_patch(mi, line);
		src = email;
	mi->header_stage = 1;
	mi->use_inbody_headers = 1;
	return 0;
	if (first_nonblank && last_nonblank)
	strbuf_release(ret);
			acc = pos = 0;

{
{
	 * Even though there can be arbitrary cruft on the same line
	if (!bra)

static void handle_content_transfer_encoding(struct mailinfo *mi,
			return 0;
		/* space followed by a filename? */
	/* Get the first part of the line. */
	strbuf_remove(&f, at - f.buf, el + (at[el] ? 1 : 0));
{

		strbuf_reset(&piecebuf);
	strbuf_reset(&mi->name);
		switch (pos++) {
	strbuf_add(attr, ap, sz);
	for (i = 0; header[i]; i++)
		}
	 * - "john.doe@xz (John Doe)"			(b), or
		 */
				take_next_literally = 1;


		mi->transfer_encoding = TE_QP;
static int convert_to_utf8(struct mailinfo *mi,
				at += remove;
	}
			hdr = mi->s_hdr_data[i];

			    (7 <= remove &&
			case '(':
	if (len && line->buf[0] == ' ') {
		case ' ': case '\t': case ':':
			 * at a time to handle_filter()
			continue;
	free(ret);
	while (1) {
		case 0:
}
	/* set some defaults */
	while (mi->content < mi->content_top) {
		else if (c == '/')
		case TE_QP:
			in = unquote_comment(&outbuf, in);
	if (!out) {

		continuation.buf[0] = ' ';
	fwrite(line->buf, 1, line->len, mi->patchfile);
	return 0;
static void cleanup_subject(struct mailinfo *mi, struct strbuf *subject)
		if (!ep)
	if (!mi->patchfile) {
		strbuf_reset(*out);
		strbuf_addch(line, '\n');
	int visible, perforation = 0, in_perforation = 0;

}
		if (!find_boundary(mi, line))
		visible = last_nonblank - first_nonblank + 1;
			if ((subject->buf[at + 1] == 'e' ||
}
			struct strbuf *hdr_data[], int overwrite)

				strbuf_release(mi->s_hdr_data[i]);
	if (line->buf[len - 1] == '\n') {
		mi->header_stage = check_inbody_header(mi, line);

	if (same_encoding(mi->metainfo_charset, charset))
	fwrite(mi->log_message.buf, 1, mi->log_message.len, cmitmsg);
}

}
	/* Content stuff */
		strbuf_addbuf(line, &continuation);
		strbuf_addch(outbuf, c);
		if (len && line->buf[len - 1] == '\r')
		/* pop the current boundary off the stack */

	for (i = 0; header[i]; i++) {
	 *
static void handle_body(struct mailinfo *mi, struct strbuf *line)

static void handle_content_type(struct mailinfo *mi, struct strbuf *line)
		}
		case '(':
	const char *in = line->buf;
{
}
	el = strcspn(at, " \n\t\r\v\f>");
			 */
		strbuf_addbuf(&mi->inbody_header_accum, line);
			   struct strbuf *line, const char *charset)
		else if (mi->p_hdr_data[i])
		}
		if (peek == EOF) {
				flush_inbody_header_accum(mi);
			/* garbage -- fall through */
			else {
		/* E.g.
		return;
		strbuf_remove(line, 0, 1);
		return 0;

	if (slurp_attr(line->buf, "boundary=", boundary)) {
		if (isspace(sb->buf[pos])) {

		return -1;
out:
	do {


	int c;
{
						strbuf_addbuf(&prev, sb);
}
		/* we hit an end boundary */
		}

		if (strbuf_getline_lf(&continuation, in))
		default:
	}
		}

			take_next_literally = 0;
				 */
		if (*(mi->content_top) && is_multipart_boundary(mi, line)) {
		else if ('0' <= c && c <= '9')
		last_nonblank = c;
			strbuf_release(mi->p_hdr_data[i]);
static void output_header_lines(FILE *fout, const char *hdr, const struct strbuf *data)
#define MAX_HDR_PARSED 10
	mi->transfer_encoding = TE_DONTCARE;
				continue;
			strbuf_reset(&prev);

static int is_rfc2822_header(const struct strbuf *line)
	git_config(git_mailinfo_config, mi);
	strbuf_release(&sb);
		}
	strbuf_reset(it);
	while (read_one_header_line(&line, mi->input))
}
	fclose(mi->patchfile);
	return 0;
				strbuf_addch(outbuf, ')');
	int i;
	strbuf_release(&outbuf);
		}
{

			c++;
	if (!skip_header(line, hdr, &val_str))
		case '[':
{
			break;
			 * that begins at ep, but there is something
	/* Pick up the string around '@', possibly delimited with <>
	strbuf_attach(line, out, strlen(out), strlen(out));
	}
			continue;
	}
{

int mailinfo(struct mailinfo *mi, const char *msg, const char *patch)

			if (c == '\n')
	memset(mi, 0, sizeof(*mi));
	found_error = 0;
	if (strcasestr(line->buf, "base64"))
		mi->header_stage = 0;
}
		return;
	return 1;
{
		return -1;
	if (mi->p_hdr_data)
	}
		break;
	if (convert_to_utf8(mi, line, mi->charset.buf))
		case '"':
static struct strbuf *decode_q_segment(const struct strbuf *q_seg, int rfc2047)
			goto release_return;
			strbuf_addch(out, (acc | (c >> 4)));
	mi->patch_lines++;

	handle_body(mi, &line);
			dec = decode_b_segment(&piecebuf);
	in = it->buf;
			 * This is a decoded line that may contain

	strbuf_trim(&mi->name);
static int handle_commit_msg(struct mailinfo *mi, struct strbuf *line)

				 struct strbuf *prev)
		/*
static void unquote_quoted_pair(struct strbuf *line)
				 * the space, since we later normalize it
	if (*(mi->content_top)) {
			perforation += 2;
{
			continue;
		/* skip to the next boundary */
	char *out;
	while ((ch = *cp++)) {
	    !memcmp(line->buf + (*(mi->content_top))->len, "--", 2)) {
	if (mi->header_stage) {
static void get_sane_name(struct strbuf *out, struct strbuf *name, struct strbuf *email)
	} else
	else if (name == out)
			for (it = lines; (sb = *it); it++) {
				continue;
	/* process the email header */
			/* flush any leftover */
	struct strbuf *boundary = xmalloc(sizeof(struct strbuf));

				take_next_literally = 1;
			acc = (c & 15) << 4;
	 * field name is "3.6.8 Optional fields".
	strbuf_release(&f);

	strbuf_addbuf(line, ret);

	if (patchbreak(line)) {
#include "strbuf.h"

	}
	default:
	int ch;
#include "cache.h"
		if (ep - it->buf >= it->len || !(cp = strchr(ep, '?')))
		if (!encoding || cp[2] != '?')
	if (parse_header(line, "Content-Type", mi, &sb)) {
static int parse_header(const struct strbuf *line,
{
			fprintf(mi->output, "Email: %s\n", mi->email.buf);
				strbuf_remove(subject, at, 3);
			c -= 'A';
{
		case 1:

	free(mi->message_id);

		case 3:
		if (mi->header_stage)
	case 1:
	return 1;
	free(mi->p_hdr_data);
		if (--mi->content_top < mi->content) {
			}
	out = reencode_string(line->buf, mi->metainfo_charset, charset);
		{
	} while (isspace(peek));



			strbuf_addch(out, (acc | c));
	/* The remainder is name.  It could be
	struct strbuf outbuf = STRBUF_INIT, *dec;
		/* Just whitespace? */

	}
}
	strbuf_reset(&mi->charset);
			return 0;
	sz = strcspn(ap, ends);
	}

			strbuf_addch(out, (acc | (c >> 2)));
{

			}
	if (!at) {
	strbuf_addbuf(out, src);
}
	} while (!strbuf_getwholeline(line, mi->input, '\n'));
	int i;
	if (starts_with(line->buf, "---")) {
		strbuf_setlen(&f, f.len - 1);
void setup_mailinfo(struct mailinfo *mi)
	strbuf_release(&mi->email);
		goto again;
static int handle_boundary(struct mailinfo *mi, struct strbuf *line)

}
			case '\\':
		ret = 1;
	get_sane_name(&mi->name, &f, &mi->email);
	if (mi->email.len)
		strbuf_addch(&outbuf, c);
			continue;

	if (starts_with(line->buf, "diff -"))
{
	const char *in = b_seg->buf;
	}
static void parse_bogus_from(struct mailinfo *mi, const struct strbuf *line)
		if (take_next_literally == 1) {
			return 0;
}
	strbuf_release(&mi->log_message);
		strbuf_release(*(mi->content_top));
		}
}
	case TE_QP:
			strbuf_release(&newline);
	/*
					     const struct strbuf *line)
	}
			ret = 1;
	 * - remove extra spaces which could stay after email (case 'c'), and
	int i, ret = 0;
}
	 * If we already have one email, don't take any confusing lines
	 * "---<sp>*" is a manual separator

		/* Unwrap transfer encoding */

	const char *rest;
			break;
		else
			if (scan != ep || in == it->buf) {
		for (i = 0; header[i]; i++) {
{
		case 'r': case 'R':
			mi->content_top = mi->content;
		if ((!memcmp(c, ">8", 2) || !memcmp(c, "8<", 2) ||
static void handle_header(struct strbuf **out, const struct strbuf *line)
{
			return 0;
/*
	struct strbuf newline = STRBUF_INIT;
	}

			}
	FILE *cmitmsg;
}
	strbuf_init(&mi->email, 0);


				    "Message-Id: %s\n", mi->message_id);
	char *at;
#include "utf8.h"

		}

	int scissors = 0, gap = 0;
		return 0;

		if (c == '+')
{
			if (mi->inbody_header_accum.len) {
		else if ('A' <= c && c <= 'Z')
	 * width of the line, and dashes and scissors must occupy more
		 * when ignoring in-body headers.
static void handle_filter(struct mailinfo *mi, struct strbuf *line)
	strbuf_reset(&mi->email);

			mi->message_id = strbuf_detach(&sb, NULL);
				 * anyway.
	for (pos = 0; pos < sb->len; pos++) {
		visible = 0;
			if (ch >= 0) {
{
	strbuf_reset(&mi->inbody_header_accum);
				gap++;
			const char *hdr,
 */

		at--;
{
	while (at < subject->len) {
	 * Is it an empty line or not a valid rfc2822 header?
	}

	}

		ret = 1;
		if (*c == '-') {

			flush_inbody_header_accum(mi);
		handle_filter(mi, line);
		for (i = 0; mi->p_hdr_data[i]; i++)
		boundary = NULL;
static inline int skip_header(const struct strbuf *line, const char *hdr,
		perror(patch);
	return !memcmp(SAMPLE + (cp - line), cp, strlen(SAMPLE) - (cp - line));
	 * - trim from both ends, possibly removing the () pair at the end
	decode_header(mi, val);
}
		if (rfc2047 && c == '_') /* rfc2047 4.2 (2) */
		 * ep : "=?ISO-8859-1?Q?Foo=FCbar?= baz"
	    (line->buf[0] == ' ' || line->buf[0] == '\t')) {
		ep += 2;
	/* Unstuff space-stuffed line. */

	 */
		if (!find_boundary(mi, line))
static struct strbuf *decode_b_segment(const struct strbuf *b_seg)
	mi->p_hdr_data = xcalloc(MAX_HDR_PARSED, sizeof(*(mi->p_hdr_data)));
	return in;
	strbuf_addbuf(it, &outbuf);

		parse_bogus_from(mi, from);

		break;
		if ((!hdr_data[i] || overwrite) &&
			cleanup_space(hdr);
			in_perforation = 1;
	/*
	strbuf_add(&mi->email, at, el);
		switch (subject->buf[at]) {
	strbuf_release(&charset_q);
		return is_format_patch_separator(line->buf + 1, line->len - 1);
{

		/* process any boundary lines */

	strbuf_addbuf(&mi->log_message, line);
			 * as a header continuation line.
	else if (strcasestr(line->buf, "quoted-printable"))
}
		mi->filter_stage++;
			if (!strcmp("Subject", header[i])) {
		strbuf_release(&newline);
	}
	assert(!mi->filter_stage);
/* NOTE NOTE NOTE.  We do not claim we do full MIME.  We just attempt
			}
				in += 2;
	struct strbuf *out = xmalloc(sizeof(struct strbuf));
		strbuf_addch(out, c);
		if (mi->use_scissors && is_scissors_line(line->buf)) {
				 */
	if (len != strlen(SAMPLE))
		return 0;
	const char *in = q_seg->buf;

			if (!handle_boundary(mi, line))
			at++;
		int peek;
		if (!handle_commit_msg(mi, line))
	strbuf_reset(line);
			handle_header(&hdr_data[i], &sb);
		mi->input_error = -1;
			break;

	for (c = line; *c; c++) {
static void handle_from(struct mailinfo *mi, const struct strbuf *from)
		}
static int slurp_attr(const char *line, const char *name, struct strbuf *attr)
			handle_filter(mi, prev);
		return 0;
	}

 * case insensitively.
		peek = fgetc(mi->input);
	if (!ket)
		return error("cannot convert from %s to %s",
			sb->buf[pos] = ' ';
	strbuf_swap(&outbuf, line);
			fprintf(mi->output, "%s: %s\n", header[i], hdr->buf);
	*outval = val;
	strbuf_reset(prev);
				if (!isspace(*scan))
			break;
			    const struct strbuf *line)
				 * it.  We don't bother with finding the end of
		return 1;
		 */
		default:
static int check_header(struct mailinfo *mi,
			struct strbuf **lines, **it, *sb;
	struct strbuf sb = STRBUF_INIT;
	char *cp = line->buf;
	}
				/*
	while (!strbuf_getline_lf(line, mi->input)) {
	strbuf_release(&mi->inbody_header_accum);
			scissors += 2;
	}
	strbuf_init(out, q_seg->len);
	strbuf_init(&mi->log_message, 0);
			fclose(cmitmsg);
{
			len = strlen(sp);
	/* CVS "Index: " line? */
		mi->input_error = -1;
	if (mi->use_scissors && is_scissors_line(line->buf)) {
		strbuf_addbuf(&mi->inbody_header_accum, line);
	switch (mi->filter_stage) {
	}

			for (scan = in; scan < ep; scan++)
		return 1;
		if (!mi->s_hdr_data[i] && skip_header(line, header[i], &val))
			goto check_header_out;
		 * We may have already read "secondary headers"; purge
		ap++;
	flush_inbody_header_accum(mi);
static int find_boundary(struct mailinfo *mi, struct strbuf *line)
	}
		return 0;
				return 1;
	 * field-name = 1*ftext

static int read_one_header_line(struct strbuf *line, FILE *in)
	if (strbuf_getline_lf(line, in))
		perror(msg);

		return 0;

		strbuf_release(boundary);
			return 1;
	if (parse_header(line, "Message-Id", mi, &sb)) {
	slurp_attr(line->buf, "charset=", &mi->charset);
		/* only print inbody headers if we output a patch file */
	int peek;
	if (!mi->metainfo_charset || !charset || !*charset)
			strbuf_addf(&mi->log_message,
	/* replenish line */
	while ((c = *in++) != 0) {
static void handle_info(struct mailinfo *mi)

	 */

	 * perforation must occupy more than a third of the visible
			handle_filter_flowed(mi, line, &prev);
{
	return 0;
			const struct strbuf *line,
	struct strbuf line = STRBUF_INIT;
		goto check_header_out;
{
	if (!starts_with(var, "mailinfo."))
		return 1;
{
	}
	if (!skip_iprefix(line->buf, hdr, &val) ||
 * unwrapped, and optionally normalize the meta information to utf8.
 * on our mailing lists.  For example, we do not even treat header lines
	if (!mi->format_flowed) {
	handle_filter(mi, line);
	const char *sp = data->buf;
		break;


	return (scissors && 8 <= visible &&
		*out = xmalloc(sizeof(struct strbuf));

		size_t remove;
static int is_format_patch_separator(const char *line, int len)
			acc = (c << 2);
			}
	if (f.buf[0] == '(' && f.len && f.buf[f.len - 1] == ')') {
		return;
	if (mi->s_hdr_data)
			remove = pos - subject->buf + at + 1;
			 * This is a scissors line; do not consider this line

	strbuf_addch(outbuf, '(');
	strbuf_addstr(&outbuf, in);
	const char *val_str;
			c = 62;
				continue;
		if ((33 <= ch && ch <= 57) ||
	if (!*out) {
				if (isspace(subject->buf[at]))
		if (!ep)
		encoding = cp[1];
				in = unquote_comment(outbuf, in);
	}
		if (convert_to_utf8(mi, dec, charset_q.buf))
		len--;
			ch = hex2chr(in);

	while (at > f.buf) {
			goto release_return;
	if (prev.len)
			in = unquote_quoted_string(&outbuf, in);

			return 1;
			goto handle_body_out;
	for (;;) {
			perforation++;

			return;
 * Returns 1 if the given line or any line beginning with the given line is an
		switch (mi->transfer_encoding) {
				return in;
static int is_multipart_boundary(struct mailinfo *mi, const struct strbuf *line)

			 * The partial chunk is saved in "prev" and will be
		visible < perforation * 3 &&
}
					break;
			strbuf_release(mi->s_hdr_data[i]);
		    parse_header(line, header[i], mi, &sb)) {
			first_nonblank = c;
	strbuf_addstr(val, val_str);
		}

		}
				break;
}
	/* normalize the log message to UTF-8. */
	strbuf_addbuf(*out, line);
{
			char *scan;
		if (first_nonblank == NULL)
			    subject->buf[at + 2] == ':') {
		/* Re-add the newline */
			error("Too many boundaries to handle");
			struct mailinfo *mi,
				strbuf_remove(subject, at, remove);
		ends = "; \t";
}
			 * We are about to process an encoded-word
	if (skip_prefix(line->buf, "-- ", &rest) && rest - line->buf == len) {

	if (!ap)
}
			continue; /* garbage */
			break;
	/* John Doe <johndoe> */

		if (mi->input_error)

	struct strbuf *hdr;
	if (found_error)
	}
	if (starts_with(line->buf, "[PATCH]") && isspace(line->buf[7])) {
static const char *unquote_comment(struct strbuf *outbuf, const char *in)
	int rc = slurp_attr(line, name, &sb) && !strcasecmp(sb.buf, value);
		}

{
	strbuf_release(&prev);
{
	struct strbuf f;
	strbuf_init(out, b_seg->len);
		switch (tolower(encoding)) {
		sp = ep + 1;
				continue;
	 *   (cases 'a' and 'b').

		if (isspace(c))
	return in;
	do {
{
			fprintf(mi->output, "Author: %s\n", mi->name.buf);
	const char *ends, *ap = strcasestr(line, name);
	if (boundary) {
		return;
		case TE_BASE64:
		FREE_AND_NULL(*(mi->content_top));
}
	/* Count mbox From headers as headers */
	/*
	if (starts_with(line->buf, "Index: "))
		mi->use_scissors = git_config_bool(var, value);
{
	struct strbuf sb = STRBUF_INIT;
			dec = decode_q_segment(&piecebuf, 1);
	 * "--- <filename>" starts patches without headers
			pos = strchr(subject->buf + at, ']');
	return out;
		}
	while (read_one_header_line(line, mi->input))

			len--;
			error("Detected mismatched boundaries, can't recover");

{
		in_perforation = 0;
/*
	 */
		goto check_header_out;

		}
	const char *first_nonblank = NULL, *last_nonblank = NULL;

	struct strbuf charset_q = STRBUF_INIT, piecebuf = STRBUF_INIT;
	return 1;

		}
	strbuf_add(&mi->email, bra + 1, ket - bra - 1);
	}
		if (mi->message_id)

		if (peek != ' ' && peek != '\t')
}

			      const char **outval)
		int i;
		/* fallthrough */
		if (line->buf[3] == ' ' && !isspace(line->buf[4]))
			handle_from(mi, hdr);
	 */

		free(boundary);
			break;
			return 1;
		strbuf_add(prev, line->buf, len - !!mi->delsp);



		return;
}
	}
	strbuf_rtrim(line);
	}
		 * ep : "=?iso-2022-jp?B?GyR...?= foo"

	return 0;

}
	strbuf_setlen(attr, 0);
	mi->patchfile = fopen(patch, "w");
			case ')':
	}
			switch (c) {
		return 0;
					}
			switch (c) {
		}
			if (in_perforation) {
	 * ftext = %d33-57 / %59-126

static const char *unquote_quoted_string(struct strbuf *outbuf, const char *in)
						break;
			break;
check_header_out:
			mi->s_hdr_data[i] = NULL;
	fclose(cmitmsg);
	/* Prepend any previous partial lines */
				break;
			strbuf_reset(prev);
		/* Only trim the first (blank) line of the commit message
	}
	}
		} else {

		*(mi->content_top) = boundary;
	switch (mi->transfer_encoding) {
	} else
		goto out;
		decode_transfer_encoding(mi, line);
			return 1;
static int check_inbody_header(struct mailinfo *mi, const struct strbuf *line)
	}
	strbuf_add(&mi->name, line->buf, bra - line->buf);
		 */
	size_t el;
		ends = "\"";
				strbuf_add(&outbuf, in, ep - in);
				if (*(it + 1) == NULL) /* The last line */


	strbuf_release(&outbuf);
#include "mailinfo.h"
	 *
		if (isspace(*c)) {
			}
				goto handle_body_out;
	return ret;
	mi->delsp = has_attr_value(line->buf, "delsp=", "yes");
		return 1;
}
release_return:
		check_header(mi, line, mi->p_hdr_data, 0);
	/* slurp in this section's info */

}
	return mi->input_error;
{
	return 0;
	struct strbuf continuation = STRBUF_INIT;
	 * but we have removed the email part, so
		if (c == '<') {
			}
		!memcmp(line->buf, content_top->buf, content_top->len));
	mi->format_flowed = has_attr_value(line->buf, "format=", "flowed");
 * to have enough heuristics to grok MIME encoded patches often found
				handle_filter_flowed(mi, sb, &prev);
	 */
}
				cleanup_space(hdr);

		strbuf_add(&charset_q, ep, cp - ep);
	 * The mark must be at least 8 bytes long (e.g. "-- >8 --").
}
	const char *c;
			/*
		strbuf_addch(outbuf, c);
}
			for (cnt = 0; isspace(sb->buf[pos + cnt + 1]); cnt++);
	    *val++ != ':')
	if (starts_with(cp, "From ") || starts_with(cp, ">From "))
		}
			return 0;
	while (isspace(*val))
			 * multiple new lines.  Pass only one chunk
		return 0;
				break;
			if (d == '\n' || !d)

}
			len = ep - sp;
			c = 63;
	 * than half of the perforation.
			goto release_return;
	if (!mi->inbody_header_accum.len)
	flush_inbody_header_accum(mi);

	struct strbuf outbuf;
	return ((content_top->len <= line->len) &&
	cp += 40;
			int ch, d = *in;
static void handle_patch(struct mailinfo *mi, const struct strbuf *line)

void clear_mailinfo(struct mailinfo *mi)
		return 0;
			if (!mi->keep_non_patch_brackets_in_subject ||
{
	strbuf_addch(line, '\n');

			     subject->buf[at + 1] == 'E') &&
}
	}
		}

	while (in - it->buf <= it->len && (ep = strstr(in, "=?")) != NULL) {
		if (!ep)
		"From e6807f3efca28b30decfecb1732a56c7db1137ee Mon Sep 17 00:00:00 2001\n";
	struct strbuf *ret;
	while ((c = *in++) != 0) {
		if (mi->input_error)
	 *
			mi->input_error = -1;
	at = strchr(f.buf, '@');

	 * If so, stop here, and return false ("not a header")

			strbuf_remove(subject, at, 1);
		free(dec);

	strbuf_init(&mi->inbody_header_accum, 0);
	}
	struct strbuf *content_top = *(mi->content_top);
		if (peek == EOF)
		mi->transfer_encoding = TE_BASE64;
		} else {
	if (name->len < 3 || 60 < name->len || strpbrk(name->buf, "@<>"))
		 */

	strbuf_init(&f, from->len);
		if (!strcmp(header[i], "Subject")) {
{
	while ((c = *in++) != 0) {
	}
		handle_content_type(mi, &sb);
				 * before the one we are about to process.
	 */

	return 0;
	mi->content_top = mi->content;

	static const char SAMPLE[] =
	else
	strbuf_insert(line, 0, prev->buf, prev->len);
		}
}
	/* Decode in..ep, possibly in-place to ot */
					if (sb->buf[sb->len - 1] != '\n') {
		return 0;
			if (!isspace(c))


		fprintf(fout, "%s: %.*s\n", hdr, len, sp);
	mi->s_hdr_data = xcalloc(MAX_HDR_PARSED, sizeof(*(mi->s_hdr_data)));
	size_t len = line->len;
static int has_attr_value(const char *line, const char *name, const char *value)
			break;
	strbuf_trim(&f);

	/* Keep signature separator as-is. */
}
			lines = strbuf_split(line, '\n');
		return;
			}
static int is_scissors_line(const char *line)
	/* search for the interesting parts */
	 * optional-field = field-name ":" unstructured CRLF
			if (mi->s_hdr_data[i])
			goto release_return;

				strbuf_reset(&prev);
			goto release_return;
	cleanup_space(&f);
	}

{
handle_body_out:
		if (!line->len || (line->len == 1 && line->buf[0] == '\n')) {
		gap * 2 < perforation);
{
	char *in, *ep, *cp;
		return git_default_config(var, value, NULL);
		     !memcmp(c, ">%", 2) || !memcmp(c, "%<", 2))) {

			cleanup_space(hdr);
			}
	struct mailinfo *mi = mi_;

		return 0; /* mi->input_error already set */

	 * - "John (zzz) Doe <john.doe@xz> (Comment)"	(c)

		return 0;
		ret = decode_b_segment(line);

	while ((c = *in++) != 0) {
{

	handle_info(mi);

static int git_mailinfo_config(const char *var, const char *value, void *mi_)
		 * them to give ourselves a clean restart.
			mi->input_error = -1;
			strbuf_list_free(lines);
				strbuf_addch(out, ch);
			     memmem(subject->buf + at, remove, "PATCH", 5)))
			return 0;
	 * Yuck, 2822 header "folding"

	const char *val;
	size_t i;
}
	size_t at = 0;
	if (!strcmp(var, "mailinfo.scissors")) {

	 */
		strbuf_add(&piecebuf, cp + 3, ep - cp - 3);

		for (i = 0; header[i]; i++)
		len--;
			/*
{
		BUG("inbody_header_accum, if not empty, must always contain a valid in-body header");
	else

			struct strbuf *val)
		else

 * Returns true if "line" contains a header matching "hdr", in which case "val"
				 * If the input had a space after the ], keep
	strbuf_release(&newline);
	strbuf_addch(&newline, '\n');
	if (!skip_prefix(line, "From ", &cp))
{
		strbuf_init(*out, line->len);
		free(*(mi->content_top));
{

		ret = 1;
		return;
		ep = strstr(cp + 3, "?=");
	for (i = 0; header[i]; i++) {
			continue;
		if (mi->add_message_id)
		    (59 <= ch && ch <= 126))
 */
		return;
			acc = (c & 3) << 6;
		handle_filter(mi, &newline);
	return rc;
}
			output_header_lines(mi->output, "Subject", hdr);
			 */
		return 1;
	strbuf_init(boundary, line->len);
	}
		handle_content_transfer_encoding(mi, &sb);

	if (len && line->buf[len - 1] == ' ') {
		goto check_header_out;
{
	strbuf_release(&line);
};
		int len;
	/* Save flowed line for later, but without the soft line break. */
				 * encoded-word, and there is only LWS
	fprintf(mi->output, "\n");
	case TE_DONTCARE:
	if (strspn(cp, "0123456789abcdef") != 40)
	strbuf_release(&piecebuf);
 * mi->s_hdr_data).
	if (!check_header(mi, &mi->inbody_header_accum, mi->s_hdr_data, 0))
			continue;
		return;
	 * (e.g. "cut here"), in order to avoid misidentification, the
	strbuf_init(&mi->charset, 0);
	return 1;
		return 0;
			continue;
static inline int patchbreak(const struct strbuf *line)
		return 0;
		case 2:
 * in-body header (that is, check_header will succeed when passed
			}
		strbuf_rtrim(&continuation);
			break;
			/*
	 */
			unsigned char c = line->buf[i];
	if (!line->len || !is_rfc2822_header(line)) {
	strbuf_release(&mi->charset);
		} else if (!strcmp(header[i], "From")) {
			}
		peek = fgetc(in);
	}
				continue;
	}
	/*
			}
	while ((c = *in++) != 0) {
	int i;
			take_next_literally = 0;
		strbuf_strip_suffix(&mi->inbody_header_accum, "\n");
	const char *cp;
			case '\\':
		case 'q':
		strbuf_addbuf(&outbuf, dec);

		mi->transfer_encoding = TE_DONTCARE;
	}
			     charset, mi->metainfo_charset);

	strbuf_init(&outbuf, line->len);
				return in;

		strbuf_insertstr(boundary, 0, "--");
			strbuf_remove(sb, pos + 1, cnt);
	}
#include "config.h"
			if (subject->len <= at + 3)
		if (c == '=') {
		int i;
	strbuf_release(&mi->name);
			 * before the encoded word.
	strbuf_release(&continuation);

					at += 1;
			/*
			goto release_return;
				mi->header_stage = 0;
		return 0;
		return 1;
	if (parse_header(line, "Content-Transfer-Encoding", mi, &sb)) {
				handle_filter(mi, &prev);
	strbuf_reset(&mi->email);
		} else {
			 * appended by the next iteration of read_line_with_nul().
		}
 */
						/* Partial line, save it for later. */
		goto out;
		switch (c) {
		case 'b':
			mi->content_top = &mi->content[MAX_BOUNDARIES] - 1;
	free(mi->s_hdr_data);
		if (prev->len) {

		val++;
	strbuf_trim(subject);
		char c = at[-1];
	strbuf_addbuf(&f, from);
	}
	if (mi->inbody_header_accum.len &&
	}
	 */

		in = ep + 2;
		if (take_next_literally == 1) {
	struct strbuf *out = xmalloc(sizeof(struct strbuf));
	/*
		else
	int c;
		strbuf_release(dec);
		handle_filter(mi, line);
				/*
	}
			hdr = mi->p_hdr_data[i];
				handle_header(&mi->s_hdr_data[i], line);
		return 0;
		if (mi->patch_lines && mi->s_hdr_data[i])
	if (is_inbody_header(mi, line)) {
		break;

	case TE_BASE64:
			continue;
		}
			in_perforation = 1;
		if (++mi->content_top >= &mi->content[MAX_BOUNDARIES]) {
	struct strbuf *src = name;
		break;

				cleanup_subject(mi, hdr);
		char *pos;
			c -= 'a' - 26;
}
	/* Beginning of a "diff -" header? */
		if (*(mi->content_top) && is_multipart_boundary(mi, line))
	size_t sz;

static void cleanup_space(struct strbuf *sb)
	if (line->len >= (*(mi->content_top))->len + 2 &&
	"From","Subject","Date",
			break;
	if (mi->email.len && strchr(at + 1, '@'))
	 * e-mail address.
		strbuf_setlen(&mi->log_message, 0);
		ret = decode_q_segment(line, 0);
	}
	if (!cmitmsg) {
			return error("empty patch: '%s'", patch);
}
	return out;
			break;
	}
			break;
	if (starts_with(line->buf, ">From") && isspace(line->buf[5]))
	int found_error = 1; /* pessimism */
}
{
		int encoding;
			c = 0x20;
	 * - "John Doe <john.doe@xz>"			(a), or
static void flush_inbody_header_accum(struct mailinfo *mi)
static void decode_transfer_encoding(struct mailinfo *mi, struct strbuf *line)
			break;
static int is_inbody_header(const struct mailinfo *mi,
	size_t pos, cnt;
			at[-1] = ' ';
		if (ch == ':')
	case 0:
	/*
		if (in != ep) {
	 * pair; that is the email part.
		   will fail first.  But just in case..
			/* Prepend any previous partial lines */
		for (i = 3; i < line->len; i++) {
		handle_filter(mi, &prev);
	}
		for (i = 0; mi->s_hdr_data[i]; i++)
		}
	cmitmsg = fopen(msg, "w");
	int c;

	if (mi->use_inbody_headers && mi->header_stage) {

		char *ep = strchr(sp, '\n');
		}
	char *bra, *ket;
	bra = strchr(line->buf, '<');

			break;
	int take_next_literally = 0;


				perforation++;
		}
	const char *val;
			break;
static void decode_header(struct mailinfo *mi, struct strbuf *it)
	 * Now we need to eat all the continuation lines..
}

		strbuf_reset(&charset_q);
	if (line->len < 4)
}
	strbuf_init(&mi->name, 0);
		else if ('a' <= c && c <= 'z')

	else
	}
	ap += strlen(name);
	ket = strchr(bra, '>');
	/* This is fallback, so do not bother if we already have an
			c -= '0' - 52;
 * will contain the value of the header with any RFC2047 B and Q encoding
		mi->content_top--;
	return 1;
	}
	/* perhaps others here */
		ungetc(peek, in);

	unquote_quoted_pair(&f);
	ungetc(peek, mi->input);
}
		return 0;


			break;
			strbuf_insert(line, 0, prev.buf, prev.len);
	if (*ap == '"') {
	int c, pos = 0, acc = 0;
			continue;

{
	return 0;
		mi->header_stage = 1;
		/* technically won't happen as is_multipart_boundary()
	get_sane_name(&mi->name, &mi->name, &mi->email);
	int take_next_literally = 0;
	strbuf_reset(out);
	/* Skip up to the first boundary */

		fclose(cmitmsg);
			if (!mi->keep_subject) {
	if (strbuf_getline_lf(line, mi->input))
			 */
{
			case '"':
				return 1;
	 * The section that defines the loosest possible
				 * unless we have just processed an
			if (!pos)
	struct strbuf prev = STRBUF_INIT;
	strbuf_release(&sb);
				break; /* drop trailing newline */
			 */
		if (cp + 3 - it->buf > it->len)
static void handle_filter_flowed(struct mailinfo *mi, struct strbuf *line,
		}
		strbuf_remove(&f, 0, 1);
			if (prev.len) {
again:
	 *
static const char *header[MAX_HDR_PARSED] = {
