	int written = 0;
		len -= last;
}
			continue;
				    string, len))
		char ch = src[i];
		strbuf_addch(dst, '\r');
					(int)(len - 9), string + 9);
			fputs(ws, stream);
}
	{ "tab-in-indent", WS_TAB_IN_INDENT, 0, 1 },

			else
		written = i + 1;
					strbuf_addch(dst, '\t');
	}

			strbuf_addstr(&err, "trailing whitespace");
/*
			while (0 < len && isspace(src[len-1]))
	}
	int last_space_in_indent = -1;
		 */
		src += last;
			result |= WS_TAB_IN_INDENT;
{
#include "cache.h"
	int fixed = 0;
			break;
			if (negated)


			fputc('\r', stream);
	/*
			fwrite(line + written,
	if (add_cr_to_tail)

	int last_tab_in_indent = -1;
			if (strncmp(whitespace_rule_names[i].rule_name,
	if (len > 0 && line[len - 1] == '\n') {

				need_fix_leading_space = 1;
			}
			fputs(set, stream);
		if (line[i] != '\t')
			fputs(reset, stream);
	 * at src.  Typically src[len-1] is '\n', unless this is
				rule &= ~whitespace_rule_names[i].rule_bits;
				last = last_space_in_indent + 1;
		   FILE *stream, const char *set,
			    len - trailing_whitespace, 1, stream);
	/* Check for indent using non-tab. */
				consecutive_spaces++;

		len--;
			}

		if (stream) {
			add_nl_to_tail = 1;
		if (!isspace(*line))
	/* Check indentation */
		} else
	} else if ((ws_rule & WS_TAB_IN_INDENT) && last_tab_in_indent >= 0) {
		}

	value = attr_whitespace_rule->items[0].value;


				fwrite(line + written, i - written, 1, stream);
	}
		int negated = 0;
	if (stream) {

		ep = strchrnul(string, ',');
		/* false (-whitespace) */
		if (line[i] == ' ')
{
		src += last;
		} else if (ws_rule & WS_TAB_IN_INDENT) {
/* Copy the line onto the end of the strbuf while fixing whitespaces */
			if (last_tab_in_indent < last_space_in_indent)
				fwrite(line + written, i - written, 1, stream);
	const char *rule_name;
		int i;
	return result;
				fputs(reset, stream);
		if (err.len)
			    !whitespace_rule_names[i].exclude_default)
		if (err.len)
 * Copyright (c) 2007 Junio C Hamano
					strbuf_addch(dst, ' ');
		trailing_newline = 1;
			len--;
	}
		if (ch == '\t') {
		/* Highlight errors in trailing whitespace. */
		strbuf_addch(dst, '\n');
		if (*string == '-') {
unsigned ws_check(const char *line, int len, unsigned ws_rule)
				fwrite(line + i, 1, 1, stream);
}
	if (ATTR_TRUE(value)) {
}
	/* Logic is simpler if we temporarily ignore the trailing newline. */
			else
	 */
	{ "trailing-space", WS_TRAILING_SPACE, 0 },
		/* Process indent ourselves */
		   const char *reset, const char *ws)
	}
				all_rule |= whitespace_rule_names[i].rule_bits;


		fixed = 1;
		exclude_default:1;
		/* Emit non-highlighted (middle) segment. */
/* The returned string should be freed by the caller. */
	}
	 * Strip trailing whitespace
			return 0;
		}
		(*error_count)++;
}
			strbuf_addstr(&err, ", ");
		len--;
	for (i = 0; i < len; i++) {
				fputs(ws, stream);
			    ws_tab_width(ws_rule) <= i - last_tab_in_indent)
	int add_nl_to_tail = 0;
{
			}
	(void)ws_check_emit_1(line, len, ws_rule, stream, set, reset, ws);
			string++;
			strbuf_addch(dst, ' ');
	int trailing_whitespace = -1;
	}
int ws_blank_line(const char *line, int len, unsigned ws_rule)
	if (add_nl_to_tail)
		}
	if (!attr_whitespace_rule)

		if (trailing_whitespace != len) {
 * Whitespace rules
				len--;
	{ "blank-at-eof", WS_BLANK_AT_EOF, 0 },
				fwrite(line + i, 1, 1, stream);
	 * len is number of bytes to be copied from src, starting
				strbuf_addstr(&err, ", ");

			    0 <= last_space_in_indent)
	{ "indent-with-non-tab", WS_INDENT_WITH_NON_TAB, 0 },
	/* Check for trailing whitespace. */
			strbuf_addstr(&err, ", ");
				add_cr_to_tail = !!(ws_rule & WS_CR_AT_EOL);
		if (trailing_whitespace - written > 0) {
			if ((ws_rule & WS_SPACE_BEFORE_TAB) &&

		if (trailing_newline)
				rule &= ~WS_TAB_WIDTH_MASK;
			if (isspace(line[i])) {
			}
	}

		 */
			len--;
	static struct attr_check *attr_whitespace_rule;
	}
		unsigned all_rule = ws_tab_width(whitespace_rule_cfg);
	return strbuf_detach(&err, NULL);
	unsigned loosens_error:1,
	} else {
				if (consecutive_spaces == ws_tab_width(ws_rule)) {
				warning("tabwidth %.*s out of range",
	if (rule & WS_TAB_IN_INDENT && rule & WS_INDENT_WITH_NON_TAB)
		trailing_whitespace = len;
	if (fixed && error_count)
			fputs(reset, stream);
		return ws_tab_width(whitespace_rule_cfg);
		/*
	{ "space-before-tab", WS_SPACE_BEFORE_TAB, 0 },
				strbuf_addch(dst, src[i]);
			break;
	if (ws_rule & WS_BLANK_AT_EOL) {
			if (0 < tabwidth && tabwidth < 0100) {
	git_check_attr(istate, pathname, attr_whitespace_rule);
	for (i = 0; i < trailing_whitespace; i++) {
static unsigned ws_check_emit_1(const char *line, int len, unsigned ws_rule,
			}
	while (string) {
				}
		size_t len;
				} while ((dst->len - start) % ws_tab_width(ws_rule));
			else
		len = ep - string;
			    trailing_whitespace - written, 1, stream);
		len -= last;
		for (i = len - 1; i >= 0; i--) {
				consecutive_spaces = 0;
unsigned parse_whitespace_rule(const char *string)
	int i;

			strbuf_addstr(&err, "new blank line at EOF");
	}
{

	 */
		 * between src[0..last-1], strip the funny spaces,
		fixed = 1;
			negated = 1;
		return whitespace_rule_cfg;
	while (len-- > 0) {
}
			fputc('\n', stream);
		int last = last_tab_in_indent + 1;
		}
		if (!len)
	if (ws & WS_INDENT_WITH_NON_TAB) {
unsigned whitespace_rule(struct index_state *istate, const char *pathname)
		trailing_carriage_return = 1;
		if (ws & WS_BLANK_AT_EOF) {
	return ws_check_emit_1(line, len, ws_rule, NULL, NULL, NULL, NULL);
		if (ws_rule & WS_INDENT_WITH_NON_TAB) {
		while (0 < consecutive_spaces--)
		const char *ep;
	strbuf_add(dst, src, len);
	if ((ws_rule & WS_INDENT_WITH_NON_TAB) && i - written >= ws_tab_width(ws_rule)) {
				const char *reset, const char *ws)
		/* Expand tabs into spaces */
	 * for now we just use this stupid definition.
{
	} else if (ATTR_FALSE(value)) {
			strbuf_addstr(&err, ", ");
		if (0 < len && isspace(src[len - 1])) {
	{ "blank-at-eol", WS_BLANK_AT_EOL, 0 },
	{ "cr-at-eol", WS_CR_AT_EOL, 1 },
			last_tab_in_indent = i;
	}
#include "attr.h"
				do {
void ws_check_emit(const char *line, int len, unsigned ws_rule,
			} else {
	struct strbuf err = STRBUF_INIT;
		attr_whitespace_rule = attr_check_initl("whitespace", NULL);
		}
		/* string */
		line++;
} whitespace_rule_names[] = {
			if (err.len)
	 * whitespace characters when ws_rule has WS_CR_AT_EOL, but
		}
	 */
				len--;
	 * We _might_ want to treat CR differently from other
		}
		die("cannot enforce both tab-in-indent and indent-with-non-tab");
			if (stream) {

				rule |= tabwidth;
		string = string + strspn(string, ", \t\n\r");
static struct whitespace_rule {
	}
			/* have "last" point at one past the indent */
			}
				result |= WS_BLANK_AT_EOL;
	}
		int last = last_tab_in_indent + 1;
	if (ws & WS_SPACE_BEFORE_TAB) {
			if (!whitespace_rule_names[i].loosens_error &&
				last = last_tab_in_indent + 1;
		if (err.len)
		if ((ws_rule & WS_SPACE_BEFORE_TAB) && written < i) {
			last_space_in_indent = i;
		}
	    len > 0 && line[len - 1] == '\r') {
		int consecutive_spaces = 0;
	int add_cr_to_tail = 0;
		}
	else {
	}

		if (trailing_carriage_return)
		strbuf_addstr(&err, "indent with spaces");
		/*
			break;
	int trailing_newline = 0;
			fwrite(line + written, i - written + 1, 1, stream);
			result |= WS_SPACE_BEFORE_TAB;
		}
 */
				trailing_whitespace = i;
					consecutive_spaces = 0;

				fputs(ws, stream);

	if ((ws & WS_TRAILING_SPACE) == WS_TRAILING_SPACE)
			char ch = src[i];
		 * The non-highlighted part ends at "trailing_whitespace".
	unsigned rule_bits;

		} else if (stream) {
	}
				fputs(reset, stream);
	return rule;
		for (i = 0; i < ARRAY_SIZE(whitespace_rule_names); i++) {
		int start = dst->len;
	const char *value;
void ws_fix_copy(struct strbuf *dst, const char *src, int len, unsigned ws_rule, int *error_count)
	int trailing_carriage_return = 0;
	}

	if (ws & WS_TAB_IN_INDENT) {
 *
	/*
			if (src[i] == '\t')
		 * Now the rest of the line starts at "written".
			    need_fix_leading_space = 1;
			if (ch != ' ') {
	unsigned result = 0;
		for (i = 0; i < last; i++) {
		 * updating them to tab as needed.
	if (need_fix_leading_space) {
			if (0 < len && src[len - 1] == '\r') {
	return 1;
			fwrite(line + written, i - written, 1, stream);
				strbuf_addch(dst, ch);
		/* reset to default (!whitespace) */
		return parse_whitespace_rule(value);
		int i;
	 * the incomplete last line.
		}
				continue;
}
		for (i = 0; i < last; i++) {
		return all_rule;
			if (stream) {
		strbuf_addstr(&err, "trailing whitespace");

	 */
	if ((ws_rule & WS_CR_AT_EOL) &&
			else
}
			fputs(ws, stream);
			if ((ws_rule & WS_INDENT_WITH_NON_TAB) &&
			else
			break;
{
		if (ws & WS_BLANK_AT_EOL)
			fputs(reset, stream);
		}
	if (ws_rule & WS_BLANK_AT_EOL) {
/* If stream is non-NULL, emits the line after checking. */
				FILE *stream, const char *set,
		strbuf_addstr(&err, "space before tab in indent");
		for (i = 0; i < ARRAY_SIZE(whitespace_rule_names); i++)
};

	} else if (ATTR_UNSET(value)) {
{
	if (trailing_whitespace == -1)
			fixed = 1;
		if (0 < len && src[len - 1] == '\n') {
	/*
		result |= WS_INDENT_WITH_NON_TAB;
		string = ep;
		}
	int i;
		/* true (whitespace) */
				break;
			fwrite(line + trailing_whitespace,
		if (strncmp(string, "tabwidth=", 9) == 0) {
			unsigned tabwidth = atoi(string + 9);
		strbuf_addstr(&err, "tab in indent");
		}
	int need_fix_leading_space = 0;
	 * Check leading whitespaces (indent)
		written = i;

	unsigned rule = WS_DEFAULT_RULE;
		} else if (ch == ' ') {
{
				rule |= whitespace_rule_names[i].rule_bits;
char *whitespace_error_string(unsigned ws)
	/*
