			 * single-quotes only if they need escaping,
		quote_c_style(name, NULL, fp, 0);
void sq_append_quote_argv_pretty(struct strbuf *dst, const char **argv)
		/* octal values with first digit over 4 overflow */
		default:

	if (*src == '*')
	strbuf_vaddf(&src, fmt, ap);
#include "quote.h"
	const char nl = '\n';
			strbuf_addch(sb, c);
	/* 0x78 */  -1,  -1,  -1,  -1,  -1,  -1,  -1,   1,
	if (*quoted++ != '"')
	const char bq = '\\';

		  case '\\':
			strbuf_addch(sb, '\\');
				c = *++src;
	}
	}
			if (!next || !isspace(*src))
					break;
			if (next)
		size_t len = strcspn(src, "'!");
};

		case '\\': case '"':
		if (array)
	int ch, ac;
	strbuf_addch(sb, sq);
	/* 0x58 */  -1,  -1,  -1,  -1,'\\',  -1,  -1,  -1,
			break;
 *     Return value is the same as in (1).


 * + Returns -1 in case of error, and doesn't touch the strbuf. Though note
		switch (*++src) {
#include "argv-array.h"
void sq_quote_argv_pretty(struct strbuf *dst, const char **argv)
				return NULL;
	const char sq = '\'';
	strbuf_addch(sb, sq);
 * 0 means: quote as octal if (quote_path_fully)
		case 'n': ch = '\n'; break;
 * (2) if sb or fp are not NULL, it emits the c_style quoted version

 * C-style name unquoting.
		case 'b': ch = '\b'; break;
}
	return sq_lookup[(unsigned char)c] + quote_path_fully > 0;
	strbuf_setlen(sb, oldlen);
	sq_quote_buf(dst, src.buf);
		return;
		case '{': case '}':
 *   that this function will allocate memory in the strbuf, so calling
		}
		if (!dequoted)
			if ((ch = *quoted++) < '0' || '7' < ch)
{
			*dst = 0;
{
		int ch;
	va_list ap;

	while ((c = *src++)) {
 */
		}
{
	/* Copy into destination buffer. */
 * Legacy function to append each argv value, quoted as necessasry,
		for (len = 0; !sq_must_quote(s[len]); len++);
		case '\\':
			return -1;
	for (;;) {
		}
	/* Avoid losing a zero-length string by adding '' */
static inline int need_bs_quote(char c)
	}
	if (p == name)   /* no ending quote needed */
	}
		sq_quote_buf_pretty(dst, argv[i]);
		strbuf_addch(sb, *src++);
			return 0;
	while ((c = *src++)) {
			EMIT(sq_lookup[ch]);
			return arg;
			EMIT(((ch >> 3) & 07) + '0');
			/* only the end '$' is special and needs quoting */

	strbuf_addch(dst, '\'');
				*dst++ = src[1];
		strbuf_addstr(sb, path);
		while (need_bs_quote(*src)) {
			/* fallthrough */


			EMIT(((ch >> 6) & 03) + '0');
{
}
	struct strbuf src = STRBUF_INIT;
	char *next = arg;
{
	for (;;) {
		}

			 * and only if we resume the single-quoted part

			strbuf_addch(sb, bq);
 * space in the result.

int sq_dequote_to_argv_array(char *arg, struct argv_array *array)
}
		if (c == sq || c == bq)
	size_t len, count = 0;

 *     number of bytes that are needed to hold c_style quoted version of name,

	} while (next);
 *     of name, enclosed with double quotes if asked and needed only.
 *   result in the strbuf `sb'.
		quote_c_style(prefix, sb, NULL, 1);
		if (len == maxlen || (maxlen < 0 && !p[len]))
			*dst++ = c;
/*
#define X8(x)   x, x, x, x, x, x, x, x
			if (endp)
   This stops at the first \0 because it's marked as a character needing an
	int i;
#define X16(x)  X8(x), X8(x)
			if (*src == '\0')
			strbuf_addch(sb, '"');
			}
		  default:
	char c;
	struct strbuf sb = STRBUF_INIT;
			goto error;
			break; /* verbatim */
			strbuf_addch(dst, *src++);
			  struct strbuf *out)
	static const char ok_punct[] = "+,-./:=@_^";
	return len;
		strbuf_addch(sb, c);
		case '[': case ']':
				*endp = quoted;
 * -1 means: never quote
{
 */
	size_t oldlen = sb->len, len;
	while ((c = *src++)) {
	}
		}

#undef EMIT
			if (need_bs_quote(src[1]) && src[2] == '\'') {
 *     returns it.

/* quote path as relative to the given prefix */

	while (*src) {

	while ((c = *src++)) {

			strbuf_addstr(sb, "\\n");
	do {                                        \
	char *dst = arg;
}

static char *sq_dequote_step(char *arg, char **next)

	strbuf_release(&src);
		return 0;
			break;
static int sq_dequote_to_argv_internal(char *arg,
		/* beginning '*' is not special, no quoting */
}

	strbuf_addch(sb, sq);
	}
	for (p = src; *p; p++) {
	} else {
	}
		return -1;
static inline int sq_must_quote(char c)
				continue;

		/* only beginning '^' is special and needs quoting */
 *  a!b      ==> a'\!'b    ==> 'a'\!'b'
 *

 * is replaced with '\!', and the whole thing is enclosed in a
	if (!*arg)
void sq_quotef(struct strbuf *dst, const char *fmt, ...)
	}
{
		c = *++src;
void write_name_quoted(const char *name, FILE *fp, int terminator)
	struct strbuf sb = STRBUF_INIT;
{
	return sq_dequote_step(arg, NULL);
 *  a b      ==> a b       ==> 'a b'
		strbuf_add(sb, quoted, len);


			strbuf_addch(sb, '"');
			strbuf_addstr(dst, "'\\");
				    struct strbuf *sb, FILE *fp, int no_dq)
{
void python_quote_buf(struct strbuf *sb, const char *src)
void basic_regex_quote_buf(struct strbuf *sb, const char *src)
		strbuf_addch(sb, c);
				goto error;
			*next = src;
{
	int i;
{
				strbuf_addch(sb, '\\');
/* Help to copy the thing properly quoted for the shell safety.
			continue;
	const char bq = '\\';
	return sq_dequote_to_argv_internal(arg, NULL, NULL, NULL, array);

		case '\f':
	}
	return count;
}
 */

char *sq_dequote(char *arg)
			strbuf_addch(sb, c);
static size_t quote_c_style_counted(const char *name, ssize_t maxlen,
 * Append each argv value, quoted as necessary, with whitespace between them.
		ch = (unsigned char)*p++;
		fputs(name, fp);
 *  name     ==> name      ==> 'name'
}
		case 'r': ch = '\r'; break;
	const char *p;
	if (*src == '^') {
 *     counting the double quotes around it but not terminating NUL, and
		if (!nodq)

 * (1) if sb and fp are both NULL, inspect the input name and counts the
		quote_c_style(path, sb, NULL, 1);
   escape */
		quoted += len;
					ac = ((ch - '0') << 6);

		case 'v': ch = '\v'; break;
	char c;

				*next = NULL;
			*dst = 0;
	return quote_c_style_counted(name, -1, sb, fp, nodq);
	if (maxlen < 0) {
	/* 0x00 */   1,   1,   1,   1,   1,   1,   1, 'a',
/* returns the longest prefix not needing a quote up to maxlen if positive.
}
		EMIT('\\');
		EMIT('"');
}
	sq_append_quote_argv_pretty(dst, argv);
			strbuf_addch(sb, c);
			goto error;
	/*           0    1    2    3    4    5    6    7 */
void sq_quote_buf(struct strbuf *dst, const char *src)

	strbuf_addch(sb, '"');
	/* 0x08 */ 'b', 't', 'n', 'v', 'f', 'r',   1,   1,
			argv_array_push(array, dequoted);
		default:
{
			return arg;
	} while (0)
 */
	va_end(ap);
		return 0;
	size_t len;
}
}

		if (!isalnum(*p) && !strchr(ok_punct, *p)) {
		if (sq_lookup[ch] >= ' ') {
			maxlen -= len + 1;
/*
/*
	/* 0x80 */ /* set to 0 */
{
			continue;
				FILE *fp, int terminator)
	char c;
	write_name_quoted(name, fp, terminator);
	}
				default:
			EMIT(((ch >> 0) & 07) + '0');
/* quoting as a string literal for other languages */
			break;
void perl_quote_buf(struct strbuf *sb, const char *src)
	fputc(terminator, fp);
	if (argv[0])
	if (terminator) {
	const char *p = name;
	} else {
	do {                                        \
		case '\0':
			break;
int sq_dequote_to_argv(char *arg, const char ***argv, int *nr, int *alloc)
		if (sb) strbuf_addch(sb, (c));          \

		case 'f': ch = '\f'; break;
	char *to_free = NULL;
{
		  case '"':
		}
	EMITBUF(p, len);
		}
			 * afterward.
int quote_path_fully = 1;
	/* 0x60 */ X16(-1), X8(-1),

		/* We stepped out of sq */
			} while (isspace(c));
	}
 */

		if (argv) {
			strbuf_addch(sb, '\\');

		}
	char *src = arg;
 * Updates endp pointer to point at one past the ending double quote if given.
		count++;                                \
			ALLOC_GROW(*argv, *nr + 1, *alloc);
{
			strbuf_addstr(sb, "\\t");
	strbuf_release(&sb);

 * Quoted should point at the opening double quote.
	    quote_c_style(path, NULL, NULL, 0)) {
		case 'a': ch = '\a'; break;

	char c;
{
 *
			break;
		strbuf_addstr(sb, prefix);
			strbuf_addch(sb, bq);
		case '\n':
 * with whitespace before each value.  This results in a leading
			strbuf_addch(dst, '\'');
		if (maxlen >= 0)
	if (!*src) {
 *  original     sq_quote     result
}
		strbuf_addstr(dst, "''");
		}
		/* Fallthrough */
		if (sb) strbuf_add(sb, (s), (l));       \
 * + Returns 0 if it was able to unquote the string properly, and appends the
}
#define EMIT(c)                                 \
int unquote_c_style(struct strbuf *sb, const char *quoted, const char **endp)
  error:
 *  a'b      ==> a'\''b    ==> 'a'\''b'
			break;
		strbuf_addch(dst, ' ');
}
}
		}
		case '\t':
	strbuf_addch(dst, '\'');
}
			sq_quote_buf(dst, src);
	do {

 * c: quote as "\\c"
}
			do {
			if ((ch = *quoted++) < '0' || '7' < ch)
	return (c == '\'' || c == '!');
			break;
		if (c == nl) {
{
/* 1 means: quote as octal
		switch (*quoted++) {
				goto error;
	} else {
		src += len;
		len = next_quote_pos(p, maxlen);
		char *dequoted = sq_dequote_step(next, &next);
		switch (c) {

 *
	return sq_dequote_to_argv_internal(arg, argv, nr, alloc, NULL);
#define EMITBUF(s, l)                           \
	const char sq = '\'';
	for (;;) {
{
{
	if (!no_dq)
}
		sq_quote_buf(dst, argv[i]);
	strbuf_grow(dst, 255);


 */
	name = relative_path(name, prefix, &sb);
 *   strbuf_release is mandatory whichever result unquote_c_style returns.
			(*argv)[(*nr)++] = dequoted;
		case '\r':
	if (dst->buf == src)
		EMITBUF(p, len);

static size_t next_quote_pos(const char *s, ssize_t maxlen)
}
/*
{
static signed char const sq_lookup[256] = {
		p += len;
					ac |= ((ch - '0') << 3);
		}
			return NULL;
 * C-style name quoting.
		len = strcspn(quoted, "\"\\");
	strbuf_reset(out);
	strbuf_release(&sb);
		if (c == sq || c == bq)
 * any single quote is replaced with '\'', any exclamation point
	}
	free(to_free);
	va_start(ap, fmt);
			strbuf_addch(sb, c);
	return out->buf;
	if (quote_c_style(prefix, NULL, NULL, 0) ||
				       const char ***argv, int *nr, int *alloc,
			break;
 * single quote pair.
		case '\v':

	strbuf_addch(sb, '"');
			}


		case 't': ch = '\t'; break;

	quote_c_style_counted(rel, strlen(rel), out, NULL, 0);
			strbuf_addch(dst, ' ');
			strbuf_addstr(sb, "\\r");
#include "cache.h"
		strbuf_addch(dst, ' ');


				src += 2;
		strbuf_add(dst, src, len);
		if (fp) fwrite((s), (l), 1, fp);        \
			 */
		case '*':
		switch (c) {
		strbuf_addch(sb, ch);
		if (fp) fputc((c), fp);                 \
		to_free = strbuf_detach(dst, NULL);
	/* if we get here, we did not need quoting */

			break;
		default:
		strbuf_addch(sb, '\\');
		if (i > 0)
	/* 0x20 */  -1,  -1, '"',  -1,  -1,  -1,  -1,  -1,
		case '[':
		} else {
		case '$': case '\\': case '"':
		case '.':
{
 *
			/*
void quote_two_c_style(struct strbuf *sb, const char *prefix, const char *path, int nodq)
			break;
			EMIT('"');
	char c;
		if (!no_dq && p == name)
			strbuf_addch(sb, 'n');
	if (*src != '\'')
{
	/* 0x10 */ X16(1),
{
			strbuf_addch(sb, bq);

	return 0;

	for (i = 0; argv[i]; i++) {
			return;
}
 *     However, if name does not need c_style quoting, it returns 0.
		return NULL;
 *
				       struct argv_array *array)


{
		count += (l);                           \
size_t quote_c_style(const char *name, struct strbuf *sb, FILE *fp, int nodq)
	strbuf_addch(sb, sq);

char *quote_path_relative(const char *in, const char *prefix,
 * E.g.
	}

		for (len = 0; len < maxlen && !sq_must_quote(s[len]); len++);
		case '\\':
		if (!c)

	return -1;

void write_name_quoted_relative(const char *name, const char *prefix,
		case '$':
	}

	} while (0)
		if (!nodq)
}
					ac |= (ch - '0');
			strbuf_addstr(sb, "\\f");
			strbuf_addstr(sb, "\\v");

}
	for (i = 0; argv[i]; ++i) {
		case '0': case '1': case '2': case '3':
					ch = ac;
void tcl_quote_buf(struct strbuf *sb, const char *src)
}
		strbuf_addch(sb, *src++);
			 * Allow backslashed characters outside of
{
			break;
	/* 0x28 */ X16(-1), X16(-1), X16(-1),
		if (c != '\'') {

		switch ((ch = *quoted++)) {
}

}
	const char *rel = relative_path(in, prefix, &sb);
void sq_quote_buf_pretty(struct strbuf *dst, const char *src)
	strbuf_addstr(dst, src);
void sq_quote_argv(struct strbuf *dst, const char **argv)
	}
