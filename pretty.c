			pp_user_info(pp, "Commit", sb, name, encoding);
			end = strchr(start, ')');
static size_t builtin_formats_len;
	else if (skip_prefix(fmt, "tformat:", &fmt) || strchr(fmt, '%'))
const char *format_subject(struct strbuf *sb, const char *msg,

		if (commit_encoding)
		if (!strcmp(commit_formats[i].name, name)) {
			space = 0;
	if (!mail_map) {
		break;
		if (*end == ',') {
		int modifier = *placeholder == 'C';
			string_list_append(&pp->in_body_headers,
		{ "oneline",	CMIT_FMT_ONELINE,	1,	0 },
		}
		c->flush_type = flush_left;
	 * as far as 'format_commit_item' assumes it in UTF-8
		if (context.commit_encoding &&
	 * This replacement actually consumes the buffer we hand it, so we do
	}
}
				get_reflog_selector(sb,
	line_end = strchrnul(line, '\n');
			commit_format = &commit_formats[i];
	/* These formats treat the title line specially. */
	case 'N':
	const struct string_list *list = ud;
		} else
		out = replace_encoding_header(out, output_encoding);

	while ((ch = *s++) != '\0') {
	strbuf_expand(sb, format, format_commit_item, &context);

	}
	if (part == 'l' || part == 'L') {	/* local-part */

	*val = v;
				strbuf_addstr(sb, "undefined");
{


		strbuf_addch(sb, '\n');
				break;
	flush_right,
			add_rfc2047(sb, namebuf, namelen,
	case 't':		/* abbreviated tree hash */
		strbuf_addch(sb, '\n');
		default:
	case '+':

			continue;
		strbuf_addch(sb, '\n');
		break;
void userformat_find_requirements(const char *fmt, struct userformat_want *w)

			if (width < 0)
						 c->pretty_ctx->abbrev);
		}
		ch++;
			if (c->auto_color && sb->len)
}

	if (padding < 0) {
				       const char **end, const char **valuestart,
			strbuf_addstr(sb, c->pretty_ctx->notes_message);
	const struct commit *commit;
		strbuf_addstr(sb, msg + c->message_off + 1);
			flush_type = flush_left_and_steal;
	}
		{ "full",	CMIT_FMT_FULL,		0,	8 },
	cp = strchr(cp, '\n');
#include "notes.h"
	if (!argval) {
		if (!linelen || is_blank_line(line, &linelen))
						    (placeholder[1] == 'd'));
	if (same_encoding(use_encoding, output_encoding)) {
	flush_both
		(sb->buf[sb->len - 1 - trimlen] == '.'
	context->commit_header_parsed = 1;
		basic_color = GIT_COLOR_BLUE;
			if (has_non_ascii(pp->in_body_headers.items[i].string)) {
static struct cmt_fmt_map *find_commit_format_recursive(const char *sought,
	while (!starts_with(cp, "encoding ")) {
static char *get_header(const char *msg, const char *key)
		for (i = 0; i < pp->in_body_headers.nr; i++) {

		magic = ADD_SP_BEFORE_NON_EMPTY;
			tz = strtol(ident->tz_begin, NULL, 10);
				break;
			break;
	switch (part) {
	 *
			 struct strbuf *sb)
}
		placeholder += consumed;
				strbuf_addstr(sb, c->signature_check.signer);
		if (!is_blank_line(msg, &ll))

			if (*ch != 'm')
		if (!encoding)
	enum flush_type flush_type;
		format_decorations_extended(sb, commit, c->auto_color, "", ", ", "");
		} else

		die("invalid --pretty format: %s", arg);
		goto skip;
		*end = p + 1;
		 * MEDIUM == DEFAULT shows only author with dates.
		strbuf_addstr(sb, pp->after_subject);
		if (same_encoding(utf8, output_enc))
	rev->commit_format = CMIT_FMT_USERFORMAT;

	const char *basic_color = NULL;
		/*
{
	return ret;

		}
	while (len && isspace(line[len - 1]))
				strbuf_addch(sb, ' ');
		return 1;
	namebuf = ident.name_begin;
				 void *context)
			strbuf_addstr(sb, pp->in_body_headers.items[i].string);
		strbuf_release(&sepbuf);
		return placeholder_len;

	const char *use_encoding;

					    len - (padding - 2),
	if (pp->expand_tabs_in_log)
	 *    within encoded words.
				need_8bit_cte = 1;
			strbuf_add_unique_abbrev(sb, &p->item->object.oid,
			if (*ch == ' ') {
			*commit_encoding = get_header(msg, "encoding");
		  struct strbuf *sb,
		/* .. and the de-tabified tab */
			start = end + 1;
				return 0;
	int i;
	c->flush_type = no_flush;
	if (pp->fmt != CMIT_FMT_ONELINE)
		(c >= '0' && c <= '9') || c == '.' || c == '_';
	if (output_enc) {
	c->indent2 = new_indent2;

		 * this point, we are done with msg. If we allocated a fresh
	int space = 2;
	for (i = sb->len - 1; i >= 0; i--)
			strbuf_addf(sb, encoded_fmt, p[i]);
	}
	trunc_right
		}
		return end - placeholder + 1;
	else
		if (msg == get_cached_commit_buffer(r, commit, NULL))
#include "string-list.h"
	case ')':
		strbuf_add(sb, line, linelen);
				 const char *msg, int len,
		const char *end = start + strcspn(start, ",)");
	case 'T':		/* tree hash */
};
		}
		format_commit_message(commit, user_format, sb, pp);
			 * as a literal string, and the previous

		found = find_commit_format_recursive(found->user_format,
				 const char *line, int linelen)
		strbuf_addchars(sb, ' ', padding);
	}
			add_merge_info(pp, sb, commit);
					break;
	while (sb->len - trimlen > start_len &&
		case 'K':
			continue;
		return placeholder_len;
		return;
	strbuf_rtrim(sb);
			strbuf_add(&buf, namebuf, namelen);
};
		*msg_p += linelen;
		}
				if (ch == '\n' && msg[i+1] == '\n')
		/*
	int line_len = last_line_length(sb);
		strbuf_addstr(sb, oid_to_hex(&commit->object.oid));
	case '\\':
			case 'G':
			break;
	char *line_end;
	if (!s)

	unsigned commit_message_parsed:1;
		placeholder++;
	}

			if (!end)
		|| sb->buf[sb->len - 1 - trimlen] == '-'))
		 * we calculate padding in columns, now
			"MIME-Version: 1.0\n"
		}
		occupied += c->pretty_ctx->graph_width;
static size_t format_commit_item(struct strbuf *sb, /* in UTF-8 */
	size_t width, indent1, indent2;
		return placeholder_len;
static void add_rfc2047(struct strbuf *sb, const char *line, size_t len,
		strbuf_grow(sb, linelen + indent + 20);
	} else {

	else if (skip_prefix(placeholder + 1, "green", &rest))
{
			break;
	const int placeholder_len = 2;

{
{
	if (skip_prefix(placeholder + 1, "red", &rest))
}
	const char *message;
	}
				pp->preserve_subject ? "\n" : " ");
			return 1;
		       const char *encoding, enum rfc2047_type type)

	trunc_none,
	return 0;

	case '(':
			case TRUST_MARGINAL:
{
}
		/*
	struct cmt_fmt_map *commit_format;
		if (placeholder[1] == '(') {
		case 's':	/* reflog message */
		if (skip_prefix(line, "author ", &name)) {
	if (pp->in_body_headers.nr) {
			context->committer.off = name - msg;
				 * header part first.
	const char *utf8 = "UTF-8";
			  const char *placeholder,
	    || part == 'D' || part == 'r' || part == 'i')
			if (c->signature_check.gpg_output)
		for (in_body = i = 0; (ch = msg[i]); i++) {
		parse_object(the_repository, &commit->object.oid);
	if (*placeholder == '+' || *placeholder == '-' || *placeholder == ' ')
			if (*p != ',' && *p != ')')
		date = parse_timestamp(ident->date_begin, NULL, 10);
	return len > 4 && starts_with(line + strspn(line, ">"), "From ");
	if (!commit->object.parsed)
		 * result, which will be done by modifying the buffer. If we


			return -1;

		return 1;
			return 0;
	namelen = s.name_end - s.name_begin;
	if (placeholder[1] == '(') {
	struct cmt_fmt_map builtin_formats[] = {
	case ';':
	/* Make sure there is an EOLN for the non-oneline case */

		if (*arg == ':') {
	if (commit_encoding)
	commit_format->name = xstrdup(name);
	} else if (orig_len != sb->len) {

				} else if (match_placeholder_arg_value(arg, "separator", &arg, &argval, &arglen)) {

	case CMIT_FMT_FULLER:
			format_trailers_from_commit(sb, msg + c->subject_off, &opts);
static void parse_commit_header(struct format_commit_context *context)
}
{

			if (p != commit->parents)

			}
	    !parent || !parent->next)
		return placeholder_len;
		/*
static size_t parse_padding_placeholder(const char *placeholder,
{
			case 'X':
	case ',':

					uintptr_t len = arglen;
			fmt_output_email_subject(sb, pp->rev);
		to_column = 1;
	strbuf_init(&title, 80);
			 * Otherwise, we decided to treat %C<unknown>

	c->indent1 = new_indent1;
			strbuf_addstr(&buf, ">\n");
				strbuf_addstr(sb, "never");
		const char *at = memchr(mail, '@', maillen);
		case 'G':
	switch (*ch++) {
		if (c->pretty_ctx->notes_message) {
		if (!end)
					strbuf_reset(&sepbuf);
{
	/* Skip excess blank lines at the beginning of body, if any... */
						    c->pretty_ctx->reflog_info,
		    struct strbuf *sb)


		if (!linelen)
		c->flush_type = flush_type;
	if (pp->fmt == CMIT_FMT_ONELINE || cmit_fmt_is_mail(pp->fmt))
	 *    'phrase' MUST be separated from any adjacent 'word', 'text' or
		map_user(pp->mailmap, &mailbuf, &maillen, &namebuf, &namelen);
	int total_consumed = 0, len, padding = c->padding;
		} else {
}
		int is_special = (chrlen > 1) || is_rfc2047_special(*p, type);
	return 0;
	free(strval);
	const char *ch = placeholder;

		 * had characters with badly defined
	context.message = repo_logmsg_reencode(r, commit,
	for (i = 0; i < len; i++) {
	trailer_out:

			}

	int is_alias;

			add_rfc822_quoted(&quoted, namebuf, namelen);
		case 'n':
	if (!output_encoding || !*output_encoding) {
	}
				case TRUST_NEVER:
} *commit_formats;
	/*
		*commit_encoding = encoding;
		strbuf_addstr(sb, "From: ");
		pp_title_line(pp, &msg, sb, encoding, need_8bit_cte);

		rev->commit_format = CMIT_FMT_DEFAULT;
		 * No encoding work to be done. If we have no encoding header
	mailbuf = ident.mail_begin;
			break;
	}
		ADD_SP_BEFORE_NON_EMPTY
			return format_reflog_person(sb,
			/* End of header */

}

			add_rfc2047(sb, title.buf, title.len,
			    ch + 1 - p != display_mode_esc_sequence_len(p))
		break;
enum flush_type {
		case 'E':
static struct cmt_fmt_map *find_commit_format(const char *sought)
 * pp_handle_indent() prints out the intendation, and
		} else {
		if (!c)
			const char *p;

		}
	}
		return 1;
			case 'B':
		for (p = commit->parents; p; p = p->next) {
		return 1;
	}
			context->committer.len = msg + eol - name;
}
		pp_remainder(pp, &msg, sb, indent);
			    (int)namelen, namebuf, (int)maillen, mailbuf);
	switch (placeholder[0]) {
		strbuf_addbuf(sb, &title);
	 * convert a commit message to UTF-8 first
	*msg_p = format_subject(&title, *msg_p,
				return 0;
		 * There's actual encoding work to do. Do the reencoding, which
	for (i = 0; i < len; i++) {
						 -6, 1, max_length);
	if (cmit_fmt_is_mail(pp->fmt)) {
		padding = (-padding) - occupied;
		}
	strbuf_addch(sb, '\n');

		save_user_format(rev, arg, 1);
	if (pp->after_subject) {
	default:
	char *out;
	if (c->wrap_start < sb->len)
	ident = get_reflog_ident(log);
	int auto_color;
{
			return 1;
	else if (skip_prefix(placeholder + 1, "blue", &rest))
#include "gpg-interface.h"
	}
			break;
		return;
	flush_left_and_steal,
				strbuf_addstr(sb, GIT_COLOR_RESET);
}
	case 'a':	/* author ... */
			 * local_sb as we're cutting sb
			p = *valuestart + *valuelen;
			namebuf = pp->from_ident->name_begin;
		strbuf_addstr(sb, diff_get_color(c->auto_color, DIFF_RESET));
		strbuf_addstr(sb, show_ident_date(&s, dmode));
void repo_format_commit_message(struct repository *r,
		return 1;
	int v;
	return 0; /* unknown placeholder */
	return 0;
	size_t len;
		const char *start = ch + 1;
		/* "=%02X" * chrlen, or the byte itself */
						len--;

	/*
		.wrap_start = sb->len
{
}
	size_t namelen, maillen;
		return 1;
	const char *msg = repo_get_commit_buffer(r, commit, NULL);
		*val = 1;
			namelen = pp->from_ident->name_end - namebuf;
	}
		 */

				if (*next == ',') {
					opts.separator = &sepbuf;
	return v ? xmemdupz(v, len) : NULL;
		case trunc_left:
	return width;
	 * worrying about width - there's nothing more to
	struct cmt_fmt_map *found = NULL;
	v = git_parse_maybe_bool(strval);

}
		if (*ch == '<') {
		padding = padding - len + local_sb.len;
	case 'S':		/* tag/branch like --source */
			found = &commit_formats[i];
	if (!log)
		date = 0;
			/* check for trailing ansi sequences */
							const char *original,
					break;
					if (len && argval[len - 1] == ':')
		msg += linelen;

					if (!argval)
			 const struct commit *commit,
		if (istitlechar(*msg)) {
		 * programs do not understand this and just leave the

		int linelen = get_one_line(msg);
	}

				break;
			space |= 1;
		/* Skip over the printed part .. */
		return 0;
	size_t remain = end - start;
	 * format.  Make sure we did not strip the blank line
}
	 * case we just return the commit message verbatim.
			strbuf_add_wrapped_bytes(sb, quoted.buf, quoted.len,
		} else
	}
	size_t res;
			case TRUST_ULTIMATE:
		if (non_ascii(ch) || ch == '\n')
 * de-tabifying.


	int first = 1;
	if (*ch == '(') {
{
					is_mboxrd_from(line, linelen))
	struct ident_split s;
	char *commit_encoding;
		*msg_p += linelen;
		format_subject(sb, msg + c->subject_off, " ");
	context->message_off = i;
		    (pp->fmt == CMIT_FMT_FULL || pp->fmt == CMIT_FMT_FULLER)) {
	strbuf_expand(&dummy, fmt, userformat_want_item, w);
		const char *ch = sb->buf + sb->len - 1;
static void add_merge_info(const struct pretty_print_context *pp,
	/* These offsets are relative to the start of the commit message. */
		return placeholder_len;
			flush_type = flush_both;
			int ret = parse_color(sb, placeholder, c);
			ch = p - 1;
			    (pp->fmt == CMIT_FMT_FULLER) ? 4 : 0, "    ",
	}
		int eol;
	 * rule out special printable characters (' ' should be the only
		case trunc_right:
					fmt = xstrndup(argval, arglen);
	 *    one that precedes an address in a From, To, or Cc header.  The ABNF
	 */
	strbuf_swap(&tmp, sb);
				break;
				const struct pretty_print_context *pretty_ctx)
			flush_type = flush_left;
	const char *mailbuf, *namebuf;
		  const char *what, struct strbuf *sb,
		if (*p == '=') {
		/* Output the data .. */

	int i;

			strbuf_addch(sb, '\n');
	int first = 1;

		line_len += encoded_len;
			if (linelen != the_hash_algo->hexsz + 8)
			return 1;
			0, DATE_SHORT, "%C(auto)%h (%s, %ad)" },
	RFC2047_SUBJECT,
		strbuf_addf(sb, " <%.*s>\n", (int)maillen, mailbuf);
			if (pp->fmt == CMIT_FMT_SHORT)
			parents_shown = 1;
		if (!(slot && *slot))
			if (c->signature_check.primary_key_fingerprint)
	for (;;) {
		} else if (skip_prefix(begin, "always,", &begin)) {
	/*
	/*
				size_t new_indent2)
	user_format = xstrdup(cp);

	strbuf_remove(sb, sb->len - trimlen, trimlen);
		break;
	else if (skip_prefix(placeholder + 1, "reset", &rest))

			strbuf_add_unique_abbrev(sb, oidp, pp->abbrev);
	 *
			    const struct date_mode *mode)
				 const char *placeholder,
		 * adjacent 'encoded- word's.
	return 0;
				padding++;
#include "utf8.h"
		strbuf_remove(&tmp, start, len);
				const struct commit *commit,
					in_body = 1;

	if (skip_prefix(arg, "format:", &arg)) {
					 get_commit_tree_oid(commit),
			case TRUST_UNDEFINED:
}
static int is_blank_line(const char *line, int *len_p)
		 * at all, then there's nothing to do, and we can return the
}
	if (!s.date_begin)
}
				break;
		strbuf_add(sb, mail, maillen);
	 *    letters, decimal digits, "!", "*", "+", "-", "/", "=", and "_"
		total_consumed++;
	case 'b':	/* body */
	strbuf_grow(out, len + 2);
static void parse_commit_message(struct format_commit_context *c)

	strbuf_attach(&tmp, buf, strlen(buf), strlen(buf) + 1);
		   ARRAY_SIZE(builtin_formats));
			*valuestart = NULL;
	int i;
						    c->pretty_ctx->reflog_info,
			}
	commit_format->user_format = fmt;
{
#include "reflog-walk.h"
			return 0;
		/*
	/* trim any trailing '.' or '-' characters */
	 */
			maillen = at - mail;

	if (cmit_fmt_is_mail(pp->fmt) && sb->len <= beginning_of_body)
	if (v == -1)
		 * the cached copy from get_commit_buffer, we need to duplicate it
	 * and only knows about ASCII, but be defensive about that)
	} else {
	}
					free(fmt);
				strbuf_addstr(sb, c->signature_check.primary_key_fingerprint);
			char *next;
	trimlen = 0;
	git_config(git_pretty_formats_config, NULL);
				strbuf_addstr(sb, c->signature_check.key);

							-6, 1, max_length);
				c->truncate = trunc_left;

					    "..");
				width = strtoul(start, &next, 10);
		int width;
	const char *p;
		case 'D':
		return 0;
	struct commit_list *p;
	if (ident->date_begin && ident->date_end)

	case '@':
		NO_MAGIC,
		return;

	const char *msg = c->message + c->message_off;

		}
	}
	return 0;


		if (width < 0) {
	struct signature_check signature_check;
	struct format_commit_context *c = context;
	for (i = 0; i < builtin_formats_len; i++) {
		int occupied;
		strbuf_wrap(sb, c->wrap_start, c->width, c->indent1, c->indent2);
			break;
}
	case 'd':

	/*
};

	static const int max_length = 78; /* per rfc2047 */
	enum flush_type flush_type;
		total_consumed += consumed;
						encoding, RFC2047_SUBJECT);
		const char *line = msg;
		if (magic == ADD_LF_BEFORE_NON_EMPTY)
			/* the default is the same as "auto" */
		 * According to RFC 2047, we could encode the special character

		/* just replaces XXXX in 'encoding XXXX\n' */
{
			free(pp->in_body_headers.items[i].string);
static int needs_rfc2047_encoding(const char *line, int len)
		else
	return 0;
	return fmt == CMIT_FMT_USERFORMAT && !*user_format;
		 * FULLER shows both authors and dates.
		if (!sb)
	}
	case 'P':		/* parent hashes */

		if (pp->abbrev)
			return 1;
		strbuf_addf(sb, "%sDate: %s\n", what,

		strbuf_addbuf(sb, &local_sb);
	return rest - placeholder;
								 &next, 10);
		if (linelen == 1)

{
	int i;
		 * Each 'encoded-word' MUST represent an integral number of
		const char *end = strchr(begin, ')');
	/* the next value means "wide enough to that column" */
	len = cp + 1 - (buf + start);
				ch--;
	else
	if (!commit_format)
	 */
}
		case 'N':

		break;


	}

		return 1;

	for (;;) {
	if (need_8bit_cte > 0) {



				strbuf_addstr(sb, c->signature_check.fingerprint);
		} else if (skip_prefix(msg + i, "committer ", &name)) {
		char color[COLOR_MAXLEN];
			p = ch - 1;
		 * If it wasn't well-formed utf8, or it
			break;

		{ "mboxrd",	CMIT_FMT_MBOXRD,	0,	0 },
		int linelen = get_one_line(line);
			else if (starts_with(start, "mtrunc)"))
	name = s.name_begin;
		case 'P':
				}

		flush_type = flush_right;
			break;
{
		ret++;
	switch (placeholder[0]) {
			   const char *line_separator)
		parse_commit_message(c);
		if (!start)
		const char *start = strrchr(sb->buf, '\n');

	}
	switch (placeholder[0]) {
	case '"':
{
				   void *context)
	struct commit_list *parent = commit->parents;
			if (c->signature_check.fingerprint)
	unsigned long beginning_of_body;
	int width = 0;
				 commit_format->is_tformat);
	int i;
	const struct string_list_item *item;

{
			if (!want_color(c->pretty_ctx->color))
		int width = pp_utf8_width(line, tab);
		strbuf_addstr(sb, oid_to_hex(get_commit_tree_oid(commit)));
		/* notin' */
}
	} else {
			break;
				 const struct commit *commit,
					   strbuf_detach(&buf, NULL));
	mail = s.mail_begin;
		strbuf_addch(sb, ' ');
		mail_map = xcalloc(1, sizeof(*mail_map));
	if (output_enc) {
		strbuf_grow(sb, linelen + 2);
		 *
		const char *line = *msg_p;
		 * still leaves the header to be replaced in the next step. At

		case '?':
	const char *rest = placeholder;

		return placeholder_len;

	strbuf_release(&local_sb);
	rewrap_message_tail(sb, &context, 0, 0, 0);

	 * rfc2047, section 4.2:
		if (!modifier)
		 */
				return end - placeholder + 1;

				return 0;
	switch (ch) {
		if (starts_with(line, "parent ")) {
		int ch = line[i];
	}
	commit_format->format = CMIT_FMT_USERFORMAT;
		const char *name;
{

		int consumed = format_commit_one(&local_sb, placeholder, c);
	}
}
				die("bad parent line in commit");
	} else {
	c->body_off = msg - start;
		return 1;
	}

				width += term_columns();
{
	const struct pretty_print_context *pretty_ctx;
		ALLOC_GROW(commit_formats, commit_formats_len+1,

						    &c->pretty_ctx->date_mode,
		break;
	len = utf8_strnwidth(local_sb.buf, -1, 1);
	else {
	case '.':
			 * %C(auto) is still valid.
		} else if (*ch == '>') {
	const char *user_format;
}
		const char *name, *line = *msg_p;
	}
{
					if (*next == ',') {
{
					opts.filter_data = &filter_list;
	const char *argval;
			if (end > start) {
				return end - placeholder + 1;
	strval = xstrndup(argval, arglen);
	case CMIT_FMT_MEDIUM:
void get_commit_format(const char *arg, struct rev_info *rev)


		return 1;
	int parents_shown = 0;
		goto skip;
	if (pp->fmt == CMIT_FMT_ONELINE)
			if (p != commit->parents)
	}
{
	 * %gn, %ge, etc.; 'sb' cannot be updated, but we still need
	if (part == 'e' || part == 'E') {	/* email */
static void pp_header(struct pretty_print_context *pp,
					     line, linelen);
				    const char *placeholder,
	builtin_formats_len = commit_formats_len;
	if (!c->commit_message_parsed)

			output_enc = context.commit_encoding;

}
		   const char **msg_p,
			strbuf_addch(out, '\\');
		char *next;
	}
static int match_placeholder_bool_arg(const char *to_parse, const char *candidate,

	}
/*
			mailbuf = pp->from_ident->mail_begin;

	}
	if (pp->fmt != CMIT_FMT_ONELINE && !pp->print_email_subject) {
					opts.only_trailers = 1;
		save_user_format(rev, arg, 0);
		if (at)
			strbuf_addstr(&buf, "From: ");
						     num_redirections+1);
	if (!ident)

	 * between the header and the body.
{

		}
}
	switch (placeholder[0]) {

	 */
{
		switch (s[i]) {
	maillen = ident.mail_end - ident.mail_begin;
	}
			/* nothing to do; we do not respect want_color at all */
	else
			for (;;) {
		else if (pp->expand_tabs_in_log)
		if (!linelen)
		       local_sb.len);
	/*
	if (c->flush_type == flush_left_and_steal) {
			if (!end || end == start)

		DEL_LF_BEFORE_EMPTY,
}
		case trunc_middle:

				char part,
	maillen = s.mail_end - s.mail_begin;
	case 'H':		/* commit hash */
	 *    particular, SPACE and TAB MUST NOT be represented as themselves
		}
{
				return 0;
		} else if (needs_rfc822_quoting(namebuf, namelen)) {
				while (*(msg+1) == '.')
		    needs_rfc2047_encoding(namebuf, namelen)) {
	unsigned commit_header_parsed:1;
		memcpy(sb->buf + sb_len + offset, local_sb.buf,
	 *    In this case the set of characters that may be used in a "Q"-encoded
	c->wrap_start = sb->len;
	default:
			strbuf_utf8_replace(&local_sb,
		const char *header_fmt =
		out = reencode_string(msg, output_encoding, use_encoding);
		return 0;
		strbuf_addstr(sb, msg + c->body_off);
		w->notes = 1;
		else if (c->flush_type == flush_both)
		w->source = 1;
	size_t subject_off;
			"Content-Transfer-Encoding: 8bit\n";
{
	strbuf_addchars(sb, ' ', indent);
		struct string_list filter_list = STRING_LIST_INIT_NODUP;
	res = strbuf_expand_literal_cb(sb, placeholder, NULL);
	}
	 */
		      const char *encoding,
static char *replace_encoding_header(char *buf, const char *encoding)
				/* author could be non 7-bit ASCII but
			     const char *line, int linelen)
		strbuf_addf(sb, "%s: %.*s%.*s <%.*s>\n", what,
				struct reflog_walk_info *log,
				strbuf_addch(sb, c->signature_check.result);

			break;
		}
	 */
		if (non_ascii(ch))
		int i, ch, in_body;
		 * width (control characters etc), just
				    encoding, RFC2047_ADDRESS);
			strbuf_addch(sb, *msg);
				case TRUST_UNDEFINED:
					   !match_placeholder_bool_arg(arg, "valueonly", &arg, &opts.value_only))
			strbuf_add(&buf, mailbuf, maillen);
		  const char *line, const char *encoding)
		case 'F':

			repo_unuse_commit_buffer(r, commit, msg);
	if (cmit_fmt_is_mail(pp->fmt) && need_8bit_cte == 0) {
			strbuf_addf(sb, "?=\n =?%s?q?", encoding);
			switch (c->signature_check.trust_level) {
	}
			return 0;
	size_t maillen, namelen;
						indent2 = strtoul(next + 1,
	if (pos)

	c->width = new_width;
static size_t parse_color(struct strbuf *sb, /* in UTF-8 */
		{ "medium",	CMIT_FMT_MEDIUM,	0,	8 },
	strbuf_release(&title);
		format_sanitized_subject(sb, msg + c->subject_off);

	else {
				} else if (!match_placeholder_bool_arg(arg, "only", &arg, &opts.only_trailers) &&
	size_t body_off;
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	COPY_ARRAY(commit_formats, builtin_formats,
	 *    8-bit values which correspond to printable ASCII characters other
		if (!(c->pretty_ctx->rev && c->pretty_ctx->rev->sources))
	 * rfc2047, section 5.3:
	struct userformat_want *w = context;

}
	rev->commit_format = commit_format->format;
		occupied = utf8_strnwidth(start, -1, 1);
		string_list_clear(&pp->in_body_headers, 0);
	/* '=' and '_' are special cases and have been checked above */
	 */
		die("invalid --pretty format: "
		save_user_format(rev, commit_format->user_format,
					 -last_line_length(sb), 1, max_length);
		else if (magic == ADD_SP_BEFORE_NON_EMPTY)
		 * FULL shows both authors but not dates.
				 const char *output_encoding)
	static const int max_encoded_length = 76; /* per rfc2047 */
				const char *argval;
	enum date_mode_type default_date_mode_type;
		if (pp->from_ident && ident_cmp(pp->from_ident, &ident)) {
			return end - placeholder + 1;
	if (magic != NO_MAGIC)
					return 0;

	if (out)
}
		while (len > padding && ch > sb->buf) {
			if (*msg == '.')
			    show_ident_date(&ident, &pp->date_mode));
	/* then convert a commit message to an actual output encoding */
				(int) indent1, (int) indent2, (int) width);
	if (skip_prefix(placeholder, "(trailers", &arg)) {
	} else {

				const char *placeholder,
#include "cache.h"

		  int indent)
		int n = utf8_width(&start, &remain);
					    "..");
	}
	if (!skip_prefix(var, "pretty.", &name))
	/*
	const char *output_enc = pretty_ctx->output_encoding;
	while ((tab = memchr(line, '\t', linelen)) != NULL) {
	/*
	struct format_commit_context context = {
{
		break;
	commit_format = find_commit_format(arg);
		strbuf_addch(sb, '\n');
		 */
		return placeholder_len;
		 * give up on trying to align things.
		{ "raw",	CMIT_FMT_RAW,		0,	0 },
		.pretty_ctx = pretty_ctx,
	char *cp = buf;
		if (*arg == ')') {
	}
			 */
	return format_person_part(sb, part, ident, strlen(ident), dmode);
	const char *fmt;
		rev->use_terminator = 1;
		return 1;
		if (is_blank_line(line, &linelen)) {
	strbuf_addch(out, '"');
	if (pp->print_email_subject) {
		return placeholder_len;


			maillen = pp->from_ident->mail_end - mailbuf;
	if (split_ident_line(&ident, line, line_end - line))

		 * are using a fresh copy, we can reuse it. But if we are using

				break;
				   &c->pretty_ctx->date_mode);
	    c->indent2 == new_indent2)
				strbuf_addch(sb, ' ');
{
	if (placeholder[0] == 'G') {
			/*
	beginning_of_body = sb->len;
		const char *begin = placeholder + 2;
		 */
	if (!commit_format) {
	int padding;
}
		struct object_id *oidp = &parent->item->object.oid;
	case CMIT_FMT_MBOXRD:
	size_t trimlen;
struct chunk {
		if (tz >= INT_MAX || tz <= INT_MIN)

			offset = (padding - len) / 2;
	}
}
		if (line_len + encoded_len + 2 > max_encoded_length) {

	strbuf_addch(sb, '\n');

			case TRUST_FULLY:
		int chrlen = mbs_chrlen(&line, &len, encoding);
		 * git-completion.bash when you add new formats.
	switch (placeholder[0]) {
		case 'e':
		 * characters.  A multi-octet character may not be split across
	case 'c':	/* committer ... */
	return !len;
		width = strtol(start, &next, 10);
		 * underscore in place. Thus, we do nothing special here, which


			strbuf_addch(out, s[i]);
		if (next == start || width == 0)
{
		return;
}
				break;
		return 1;
		placeholder++;
	rev->use_terminator = 0;
				p--;
			case 'N':
		int i;
				strbuf_addstr(sb, "fully");
	case 'i':	/* date, ISO 8601-like */
	const char *encoding;
		if (c->commit_encoding)

		} else {
			pp_handle_indent(pp, sb, indent, line, linelen);
		   struct strbuf *sb,
		    needs_rfc2047_encoding(title.buf, title.len))
{

	case 's':
		if (!parents_shown) {
#include "commit.h"
			offset = padding - len;
					}
			rewrap_message_tail(sb, c, width, indent1, indent2);

	 * they cannot support things like "auto" or "always" at all).
	repo_unuse_commit_buffer(r, commit, context.message);
}
				 * the log may be so; skip over the
		rev->date_mode.type = commit_format->default_date_mode_type;
		return 0;
		placeholder++;
	msg = format_subject(NULL, msg, NULL);
	const char *msg;
		consumed = format_commit_one(sb, placeholder, context);
	return !(isalnum(ch) || ch == '!' || ch == '*' || ch == '+' || ch == '-' || ch == '/');
	/* Now we need to parse the commit message. */
		size_t ret = 0;
}

		}
					opts.filter = format_trailer_match_cb;
		size_t match_len;
void pp_title_line(struct pretty_print_context *pp,
				continue;

		return;
			/* It won't fit with trailing "?=" --- break the line */
		} else if (skip_prefix(msg + i, "author ", &name)) {
			  struct format_commit_context *c)
{
	 *    than "=", "?", and "_" (underscore), MAY be represented as those
		 * RFC 2047, section 5 (3):

	 *
{
					  encoding, strlen(encoding));
		return ret;
		commit_formats_len++;
{
};
 */
			break;
		else {
	static struct string_list *mail_map;
 */

	free(context.commit_encoding);
			continue;
	const char *name;
			*valuelen = 0;

		match_len = strlen(commit_formats[i].name);


		    original);
	commit_formats_len = ARRAY_SIZE(builtin_formats);
		 */
	if (pp->fmt == CMIT_FMT_USERFORMAT) {
	} magic = NO_MAGIC;
		strbuf_addstr(sb, show_ident_date(&s, DATE_MODE(ISO8601)));
	case '-':
		int i;
		fmt = user_format;
			if (!want_color(c->pretty_ctx->color))
	 */
 * the whole line (without the final newline), after
		else
	if (skip_prefix(fmt, "format:", &fmt))
			strbuf_add_tabexpand(sb, pp->expand_tabs_in_log,
					indent1 = strtoul(next + 1, &next, 10);
		if (!end || end == start)
				   msg + c->author.off, c->author.len,
	/* How many bytes are already used on the last line? */
	 *    As a replacement for a 'word' entity within a 'phrase', for example,
		break;
	if (!rev->date_mode_explicit && commit_format->default_date_mode_type)
		 * Otherwise, we still want to munge the encoding header in the
		if (pp->fmt == CMIT_FMT_RAW) {
	int len = *len_p;
			break;
		}
		for (eol = i; msg[eol] && msg[eol] != '\n'; eol++)
	default:
	for (; *msg && *msg != '\n'; msg++) {

	while (len) {
		    !strncasecmp(item->string, key->buf, key->len))
		break;
	int indent = 4;
	return 0;
			struct strbuf quoted = STRBUF_INIT;
			return 1;
			pp_user_info(pp, "Author", sb, name, encoding);
		int	    encoded_len = is_special ? 3 * chrlen : 1;
		switch (c->truncate) {



			break;
		 * convert it back to chars

	msg = skip_blank_lines(msg);
}
static int git_pretty_formats_config(const char *var, const char *value, void *cb)
	struct cmt_fmt_map *commit_format = NULL;
	enum {
	}
	RFC2047_ADDRESS
			start = sb->buf;

	case 'N':
			return msg;
		}
				break;
			strbuf_insertstr(sb, orig_len, "\n");
		setup_commit_formats();

{
		      const struct commit *commit,
		if (key->len == (uintptr_t)item->util &&
				   &c->pretty_ctx->date_mode);
		}
	strbuf_grow(sb, len * 3 + strlen(encoding) + 100);
	 */
				continue;
	if (magic == NO_MAGIC)
	}
	 * If the re-encoding failed, out might be NULL here; in that
	strbuf_release(&tmp);
		if (pp->encode_email_headers &&
				get_reflog_message(sb, c->pretty_ctx->reflog_info);
	case 'I':	/* date, ISO 8601 strict */

		if (out)
	}
		/*
			if (ret)
	const char *arg;
	strbuf_addstr(sb, "Merge:");
int has_non_ascii(const char *s)

{
			case 'E':
			else if (non_ascii(ch)) {
	const char *msg = c->message;


				size_t arglen;
	 * at this point because is_empty_line would've trimmed all
			break;
{
const char *show_ident_date(const struct ident_split *ident,
	if (((struct format_commit_context *)context)->flush_type != no_flush)
		return 0;
					msg++;

		return 1;
						     original,
		case '"':
		}
	size_t len;
		linelen -= tab + 1 - line;


	case CMIT_FMT_EMAIL:
	}
	strbuf_add(sb, line, linelen);
			strbuf_insertstr(sb, orig_len, " ");
				c->truncate = trunc_right;
	case '<':
			else if (starts_with(start, "ltrunc)"))
		commit_format->is_tformat = 0;
	if (need_8bit_cte == 0) {

static struct cmt_fmt_map {
		return;
			*valuestart = p + 1;
	if (!*arg || skip_prefix(arg, "tformat:", &arg) || strchr(arg, '%')) {
	for (;;) {
			struct strbuf buf = STRBUF_INIT;
	pp_header(pp, encoding, commit, &msg, sb);
		if (i == eol) {
		len--;
			break;
				need_8bit_cte = 1;
	struct strbuf local_sb = STRBUF_INIT;
			return;
			strbuf_add(sb, line, linelen);
		basic_color = GIT_COLOR_RED;

		c->padding = to_column ? -width : width;
				default:
	}
/* High bit set, or ISO-2022-INT */

		for (i = 0; i < chrlen; i++)

		magic = DEL_LF_BEFORE_EMPTY;
	/* just a guess, we may have to also backslash-quote */
			check_commit_signature(c->commit, &(c->signature_check));
skip:
#include "log-tree.h"
			}
	return msg;
	if (valuestart) {
enum trunc_type {
					char *fmt;
		if (found == NULL || found_match_len > match_len) {
			out = (char *)msg;
	 *    (underscore, ASCII 95.)>.  An 'encoded-word' that appears within a
	if (found && found->is_alias) {

		 * message verbatim (whether newly allocated or not).
	case ':':
		string_list_clear(&filter_list, 0);
	char *encoding;
	}
{

			return;
	 *    'special' by 'linear-white-space'.
		break;
	case '>':
		if (ident->tz_begin && ident->tz_end)
	int expand_tabs_in_log;
	for (i = 0; msg[i]; i++) {
			break;
			die(_("unable to parse --pretty format"));
	 * rule out non-ASCII characters and non-printable characters (the
	rev->expand_tabs_in_log_default = commit_format->expand_tabs_in_log;
	int ch;
	strbuf_release(&dummy);
static void strbuf_wrap(struct strbuf *sb, size_t pos,
		memset(commit_format, 0, sizeof(*commit_format));
		if (skip_prefix(line, "committer ", &name) &&
			if (*p != '\033' ||

	for (;;) {
		int linelen = get_one_line(*msg_p);
		return 2;
{
		strbuf_add(sb, mail, maillen);
			strbuf_add_wrapped_bytes(sb, title.buf, title.len,
	case 'h':		/* abbreviated commit hash */
		   int need_8bit_cte)
	if (split_ident_line(&s, msg, len) < 0)
	}
						    placeholder[1],
		   const char *encoding,
	msg = skip_blank_lines(msg);
		return 1;
		if (!cp || *++cp == '\n')
		opts.no_divider = 1;
				strbuf_addstr(sb, "ultimate");
		return 0;
	}
	}
	/*
				struct format_commit_context *c,
		cp = strchr(cp, '\n');

						    &c->pretty_ctx->date_mode);
	int to_column = 0;
					       &context.commit_encoding,
static int needs_rfc822_quoting(const char *s, int len)
	if (!cp)

		/* we have re-coded to UTF-8; drop the header */

		line = tab + 1;
		if (!user_format)
			const char **name, size_t *name_len)
		break;
	strbuf_addf(sb, "=?%s?q?", encoding);
		}

	if (!c->commit_header_parsed)
	c->commit_message_parsed = 1;
	encoding = get_header(msg, "encoding");
	*len_p = len;
{

	struct chunk author;

				break;
			const char *end = strchr(start, ')');
		for (i = 0; i < pp->in_body_headers.nr; i++) {
	 */
			strbuf_grow(sb, linelen + 80);
			break;

	while (remain) {
			strbuf_attach(sb, out, outsz, outsz + 1);
			}
		switch (placeholder[1]) {
		struct process_trailer_options opts = PROCESS_TRAILER_OPTIONS_INIT;
		first = 0;
		strbuf_addstr(sb, show_ident_date(&s, DATE_MODE(RFC2822)));
				if (match_placeholder_arg_value(arg, "key", &arg, &argval, &arglen)) {
		    "'%s' references an alias which points to itself",
	 * a line matching /^From $/ here would only have len == 4
	pp.fmt = fmt;
			/* with enough slop */
	if (*ch == '|') {
					    0, len - (padding - 2),
			return 0;
	}
	case 'D':
			context->author.off = name - msg;
		basic_color = GIT_COLOR_RESET;
	case 'r':	/* date, relative */
	}
}
				strbuf_addch(sb, '-');
		strbuf_addstr(sb, get_revision_mark(NULL, commit));
	 */

	int i;
			return 0;
		case 'd':	/* reflog selector */
	if (git_config_string(&fmt, var, value))
			; /* do nothing */
		}
		case 'S':

		}
}
		msg += linelen;
				switch (c->signature_check.trust_level) {
		.commit = commit,
		if (max_length <
	case '[':
		return format_person_part(sb, placeholder[1],

		return end - placeholder + 1;
#include "trailer.h"
		if (skip_prefix(begin, "auto,", &begin)) {
	case '<':

				if (*next != ')')
		strbuf_addstr(sb, basic_color);
		if (indent)
		 */
		} else {
	int consumed;
	if (!commit_formats)
	}
		*end = p;

	long tz = 0;
	}
			if (first)
				      const char **end, int *val)
{
		{ "reference",	CMIT_FMT_USERFORMAT,	1,	0,
	strbuf_addstr(sb, "?=");
	}
				size_t new_width, size_t new_indent1,

					 c->pretty_ctx->abbrev);
			return buf;
}
		}
		 */
	 * are a few colors that can be specified without parentheses (and
	const char *msg = context->message;
	unuse_commit_buffer(commit, reencoded);
		} else
					break;
		first = 0;
	int i;

		return 1;
	int i;
	size_t wrap_start;
		}
	return total_consumed;
}

		return 1;
	struct strbuf title;
		return placeholder_len;
		 * ' ' (space) with '_' (underscore) for readability. But many

			switch (c->signature_check.result) {

		return 0;	/* unknown %g placeholder */
		return 2;
	strbuf_add_wrapped_text(&tmp, sb->buf + pos,
	case 'B':	/* raw body */
		return;
		if (color_parse_mem(begin, end - begin, color) < 0)
	size_t start, len;
		return 1;
	 * The caller may append additional body text in e-mail
		strbuf_addstr(sb, diff_get_color(c->auto_color, DIFF_COMMIT));
}
			strbuf_addstr(&buf, " <");
			strbuf_addstr(sb, oid_to_hex(oidp));

		return msg;
							int num_redirections)
		return placeholder_len;
			break;
{
	if (commit_format->format == CMIT_FMT_USERFORMAT) {
			if (c->pretty_ctx->reflog_info)
			 */
		    last_line_length(sb) + strlen(" <") + maillen + strlen(">"))
	flush_left,
			return;
	 * not have to worry about freeing the old "out" here.

		if (out)

			case TRUST_NEVER:

		parse_commit_header(c);
			   commit_formats_alloc);
					  len - strlen("encoding \n"),
	if (*p == ')') {
			size_t width, size_t indent1, size_t indent2)
		if (c->flush_type == flush_left)
		return consumed;
		return 0;
	return !isascii(ch) || ch == '\033';
			else
	case 'C':
	/* these are independent of the commit */
static int get_one_line(const char *msg)
		strbuf_addf(sb, "Date:   %s\n",
void pp_commit_easy(enum cmit_fmt fmt, const struct commit *commit,

			"Content-Type: text/plain; charset=%s\n"
		}
}
	if (non_ascii(ch) || !isprint(ch))
	if (part == 't') {	/* date, UNIX timestamp */
static void add_rfc822_quoted(struct strbuf *out, const char *s, int len)
		if (n < 0 || !start)
	size_t off;

		char *out = reencode_string_len(sb->buf, sb->len,
	 * reading from either a bogus commit, or a reflog entry with
}
		}

			return 0;
	 * We need to check and emit Content-type: to mark it
}

	/*
	 * whitespace character considered printable, but be defensive and use
		strbuf_add_tabexpand(sb, pp->expand_tabs_in_log, line, linelen);
#include "color.h"
static int format_trailer_match_cb(const struct strbuf *key, void *ud)
			break;
	}
		case trunc_none:
	 *    definition for 'phrase' from RFC 822 thus becomes:
		strbuf_add(sb, line, linelen);
#include "diff.h"
	if (part == 'n' || part == 'N') {	/* name */
		case 'T':
				break;
	}
		}

	return 1;
static int is_rfc822_special(char ch)
	free(user_format);
	return out ? out : msg;
			strbuf_grow(sb, num * (GIT_MAX_HEXSZ + 10) + 20);
		{ "email",	CMIT_FMT_EMAIL,		0,	0 },
		commit_format->is_tformat = 1;
	if (num_redirections >= commit_formats_len)
	return mail_map->nr && map_user(mail_map, email, email_len, name, name_len);
		return 0;
{
struct format_commit_context {
	if (c->width == new_width && c->indent1 == new_indent1 &&
		strbuf_splice(&tmp, start + strlen("encoding "),
}
			return 0;
	case 'p':		/* abbreviated parent hashes */
	}
		 * causes ' ' to be encoded as '=20', avoiding this problem.
						    c->pretty_ctx->date_mode_explicit,
	struct ident_split ident;
	if (!(skip_prefix(to_parse, candidate, &p)))
					strbuf_addch(sb, 'U');
			return ret;
}
		if (sb->buf[i] == '\n')
}
{
static struct cmt_fmt_map *find_commit_format(const char *sought);
	if (date_overflows(date))
		strbuf_addstr(sb, show_ident_date(&s, DATE_MODE(RELATIVE)));
}
				const char *format, struct strbuf *sb,
	for (i = 0; i < len; i++)

static char *user_format;
			strbuf_utf8_replace(&local_sb,
		if (!first)

}

	for (i = 0; i < commit_formats_len; i++) {
	int is_tformat;

	 *    phrase = 1*( encoded-word / word )
					    padding - 2, len - (padding - 2),
}
		strbuf_addf(sb, "Date: %s\n",

	const char *v = find_commit_header(msg, key, &len);
		trimlen++;

		parent = parent->next;
		return 2;
	return found;
		if (!strcmp(commit_formats[i].name, name))
		}
						output_enc, utf8, &outsz);
{
		strbuf_addch(sb, '\n');
			if (space == 1)
		return 1;
	while (parent) {
	}
				}
			line_len = strlen(encoding) + 5 + 1; /* =??q? plus SP */
					    padding / 2 - 1,
	start = cp - buf;
	 * align.
static int istitlechar(char c)
				 */
			strbuf_grow(sb, linelen + 80);
		 * Please update $__git_log_pretty_formats in
		 * to avoid munging the cached copy.
			return 1;
static void format_sanitized_subject(struct strbuf *sb, const char *msg)
	case 'w':
static int mailmap_name(const char **email, size_t *email_len,
	case 'f':	/* sanitized subject */
	const char *start = c->message;
			strbuf_add_wrapped_bytes(sb, namebuf, namelen,
	if (isspace(ch) || ch == '=' || ch == '?' || ch == '_')
	const char *tab;
			unsigned num = commit_list_count(commit->parents);
	 * non-ASCII check should be redundant as isprint() is not localized
	return 0;

		strbuf_addch(sb, '\n');


			return 7; /* consumed 7 bytes, "C(auto)" */
	}
	return msg;
				return 0;
			/* fall through */
static int is_rfc2047_special(char ch, enum rfc2047_type type)
void pretty_print_commit(struct pretty_print_context *pp,
	/*
	if (pp->fmt != CMIT_FMT_ONELINE)
			    show_ident_date(&ident, &pp->date_mode));
}
	strbuf_addch(out, '"');
		commit_format->is_alias = 1;
	struct strbuf tmp = STRBUF_INIT;

		return 1;

static void pp_handle_indent(struct pretty_print_context *pp,
			return 0;
	for (i = builtin_formats_len; i < commit_formats_len; i++) {
 * Generic support for pretty-printing the header
		if (*placeholder != '%')
{
	no_flush,
	enum cmit_fmt format;
	int need_8bit_cte = pp->need_8bit_cte;
	c->subject_off = msg - start;
		strbuf_add_unique_abbrev(sb, &commit->object.oid,
{
			strbuf_addstr(sb, c->commit_encoding);

		      struct strbuf *sb)
	if (cmit_fmt_is_mail(pp->fmt)) {
}
	use_encoding = encoding ? encoding : utf8;
		default:
	static const char *utf8 = "UTF-8";
	}
			if (to_column)
	enum trunc_type truncate;
		for (p = commit->parents; p; p = p->next) {
}
	if (!match_placeholder_arg_value(to_parse, candidate, end, &argval, &arglen))
		int ll = linelen;
	case 'D':	/* date, RFC2822 style */
				c->truncate = trunc_middle;
			strbuf_utf8_replace(&local_sb,
		break;
		if (!linelen)
	trunc_left,
enum rfc2047_type {
		slot = revision_sources_at(c->pretty_ctx->rev->sources, commit);
	line_len += strlen(encoding) + 5; /* 5 for =??q? */
	return 0;	/* unknown placeholder */
#include "mailmap.h"
	for (;;) {
			break;
		 */
	msg = skip_blank_lines(msg);
			break;
	encoding = get_log_output_encoding();
	}

	 * isspace())
			if (!in_body) {
	if ((pp->fmt == CMIT_FMT_ONELINE) || (cmit_fmt_is_mail(pp->fmt)) ||
	pretty_print_commit(&pp, commit, sb);
void pp_remainder(struct pretty_print_context *pp,
		strbuf_addstr(sb, diff_get_color(c->auto_color, DIFF_RESET));

{
	}
	};
		format_decorations(sb, commit, c->auto_color);
		if ((i + 1 < len) && (ch == '=' && line[i+1] == '?'))
	const struct commit *commit = c->commit;
	struct chunk committer;
	trunc_middle,
static int last_line_length(struct strbuf *sb)
	case 'e':	/* encoding */
		basic_color = GIT_COLOR_GREEN;
	/* these depend on the commit */
		/*
		strbuf_addstr(sb, color);
};
	timestamp_t date = 0;
	orig_len = sb->len;
const char *repo_logmsg_reencode(struct repository *r,
		strbuf_addstr(sb, *slot);
				   msg + c->committer.off, c->committer.len,
			c->truncate = trunc_none;
		strbuf_setlen(sb, ch + 1 - sb->buf);
		consumed = format_and_pad_commit(sb, placeholder, context);

	 */
		/*
		      const char **msg_p,
		free(encoding);
		/*
		if (starts_with(placeholder + 1, "(auto)")) {
		/* message_off is always left at the initial newline */
		strbuf_addstr(sb, show_ident_date(&s, DATE_MODE(SHORT)));
		return res;
		while (sb->len && sb->buf[sb->len - 1] == '\n')
	 *
				void *context)


			strbuf_addstr(sb, line_separator);
		size_t outsz;
}
	while (1) {
		case '\\':
	}
		{ "short",	CMIT_FMT_SHORT,		0,	0 },
{
	size_t message_off;
		    !same_encoding(context.commit_encoding, utf8))
		commit_format = &commit_formats[commit_formats_len];
		}

		}
{
	/*
	if (len > padding) {
		return -1;
			c->auto_color = want_color(c->pretty_ctx->color);
	msg = reencoded = logmsg_reencode(commit, NULL, encoding);
			if (c->signature_check.key)
						goto trailer_out;
	}

					string_list_append(&filter_list, argval)->util = (char *)len;


					   !match_placeholder_bool_arg(arg, "unfold", &arg, &opts.unfold) &&
		strbuf_addf(sb, header_fmt, encoding);
		return 1;
static size_t format_commit_one(struct strbuf *sb, /* in UTF-8 */
static void rewrap_message_tail(struct strbuf *sb,
	case '>':
	case ']':
		return buf; /* should not happen but be defensive */
	}
int commit_format_is_empty(enum cmit_fmt fmt)
		int linelen = get_one_line(line);
		if (c == '\n')
	ALLOC_GROW(commit_formats, commit_formats_len, commit_formats_alloc);
	}
	case 'S':
	/* currently all placeholders have same length */
		struct strbuf sepbuf = STRBUF_INIT;
					    "..");
			ret = arg - placeholder + 1;
		return;
			max_length = 76; /* per rfc2047 */
	case 's':	/* subject */
			const char *start = placeholder + 2;
			case 'R':
			     struct strbuf *sb, int indent,
	case '>':
const char *skip_blank_lines(const char *msg)
static void save_user_format(struct rev_info *rev, const char *cp, int is_tformat)
			strbuf_insert(&local_sb, 0, p, ch + 1 - p);

	struct strbuf tmp = STRBUF_INIT;
static void setup_commit_formats(void)
{
	 * We handle things like "%C(red)" above; for historical reasons, there

	/* The following ones are relative to the result struct strbuf. */
	if (part == 'n' || part == 'e' || part == 't' || part == 'd'
	rev->use_terminator = commit_format->is_tformat;
		strbuf_add(&tmp, sb->buf, pos);
	if (type != RFC2047_ADDRESS)
	case ' ':

	size_t start_len = sb->len;
		if (is_rfc822_special(s[i]))
		return 1;

		mailmap_name(&mail, &maillen, &name, &namelen);
static size_t commit_formats_len;
				c->auto_color = 0;
	char *strval;
static size_t format_person_part(struct strbuf *sb, char part,
			tz = 0;


			    show_ident_date(&ident, DATE_MODE(RFC2822)));
	 * to compute a valid return value.

			   struct strbuf *sb, const struct commit *commit)
		indent = 0;
			strbuf_setlen(sb, sb->len - 1);

	if (is_encoding_utf8(encoding)) {
			 * got a good ansi sequence, put it back to
	if ((orig_len == sb->len) && magic == DEL_LF_BEFORE_EMPTY) {
	size_t orig_len;
	const char *reencoded;
	int ret = 0;
	}
				strbuf_addstr(sb, c->signature_check.gpg_output);
	strbuf_grow(sb, title.len + 1024);
				 char **commit_encoding,
		if (!starts_with(commit_formats[i].name, sought))
	}
	switch (pp->fmt) {
		strbuf_addchars(sb, ' ', tabwidth - (width % tabwidth));
	case '<':

		strbuf_add_unique_abbrev(sb,

			output_enc = NULL;
			unsigned long width = 0, indent1 = 0, indent2 = 0;
		else
			/*
	return find_commit_format_recursive(sought, sought, 0);
	}
			ch++;
		return format_person_part(sb, placeholder[1],
static int is_mboxrd_from(const char *line, int len)
static size_t userformat_want_item(struct strbuf *sb, const char *placeholder,
		if (pp->rev)
	size_t found_match_len = 0;

	}
static int non_ascii(int ch)
void pp_user_info(struct pretty_print_context *pp,
	if (pp->fmt == CMIT_FMT_ONELINE || cmit_fmt_is_mail(pp->fmt))
	if (*p == ',') {
			case 'Y':
			}
static int match_placeholder_arg_value(const char *to_parse, const char *candidate,
static size_t format_and_pad_commit(struct strbuf *sb, /* in UTF-8 */
		strbuf_addstr(sb, show_ident_date(&s, DATE_MODE(ISO8601_STRICT)));

	}
			if (c->pretty_ctx->reflog_info)


	return sb->len - (i + 1);
#include "revision.h"
	};


static size_t commit_formats_alloc;
	if (is_tformat)
	}
{
	if (basic_color && want_color(c->pretty_ctx->color))
			strbuf_addstr(sb, oid_to_hex(&p->item->object.oid));
			arg++;
			}
		if (width < 0)
			strbuf_add(sb, line, linelen);
		const char *encoded_fmt = is_special ? "=%02X"    : "%c";
		return parse_padding_placeholder(placeholder, c);
		 */
	if (!commit_encoding)
			break;
		read_mailmap(mail_map, NULL);
	return strbuf_detach(&tmp, NULL);
	return consumed + 1;
		switch(placeholder[1]) {
				const struct date_mode *dmode)
				    struct format_commit_context *c)
					strbuf_addch(sb, 'G');

		if (pp->encode_email_headers &&
			return 2;
		ADD_LF_BEFORE_NON_EMPTY,
		return 0;
	const char *ident;
			break;

}
static void strbuf_add_tabexpand(struct strbuf *sb, int tabwidth,

	const char *name;
			found_match_len = match_len;
		int sb_len = sb->len, offset = 0;
	/* guess if there is an encoding header before a \n\n */
	 */
					       utf8);
}
			}
			*valuelen = strcspn(*valuestart, ",)");
			context->author.len = msg + eol - name;

		 * copy, we can free it.
	struct strbuf dummy = STRBUF_INIT;
{
static int format_reflog_person(struct strbuf *sb,
			while (ch - p < 10 && *p != '\033')
{
				strbuf_addch(sb, '>');
	default:



		const unsigned char *p = (const unsigned char *)line;
					 c->pretty_ctx->abbrev);
			return 2;
	case 'g':		/* reflog info */
	if (!arg) {
		i = eol;
		strbuf_addstr(sb, diff_get_color(c->auto_color, DIFF_COMMIT));
				strbuf_addstr(sb, "marginal");

	switch (*placeholder) {
	int max_length = 78; /* per rfc2822 */

	 * Print out everything after the last tab without
}

					struct format_commit_context *c)
	/* For the rest we have to parse the commit header. */
	}
	char **slot;
	}
	 *    'encoded-word' is restricted to: <upper and lower case ASCII
	return show_date(date, tz, mode);

			out = xstrdup(msg);
			continue;
			if (pp->fmt == CMIT_FMT_MBOXRD &&
		strbuf_add(sb, name, namelen);
		{ "fuller",	CMIT_FMT_FULLER,	0,	8 },
		return placeholder_len;
	if (!fmt) {
	}
	namelen = ident.name_end - ident.name_begin;
	}
	if (pp->mailmap)
		width += n;
		}
	for_each_string_list_item (item, list) {
		if (!c->signature_check.result)
/*

			if (c->signature_check.signer)
	if (res)
	case 'd':	/* date */
		return 1;
	struct pretty_print_context pp = {0};
	/*
			ch++;
		magic = ADD_LF_BEFORE_NON_EMPTY;
}
	}
static int pp_utf8_width(const char *start, const char *end)
				       size_t *valuelen)
	size_t arglen;

	case 'm':		/* left/right/bottom */
	 * as 8-bit if we haven't done so.
	 * trailing space
	const char *name, *mail;
				break;
			strbuf_release(&quoted);
		  const char **msg_p,
#include "config.h"
	 *    characters.  (But see section 5 for restrictions.)  In
		strbuf_add(sb, line, tab - line);
					strbuf_expand(&sepbuf, fmt, strbuf_expand_literal_cb, NULL);
		strbuf_add(sb, s.date_begin, s.date_end - s.date_begin);
				 const struct date_mode *dmode)

}
{
		char c = *msg++;
	if (part == 'N' || part == 'E' || part == 'L') /* mailmap lookup */


			if (starts_with(start, "trunc)"))
