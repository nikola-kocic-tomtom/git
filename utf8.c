					else
		dst += src - old;
{

		indent = 0;
		return 0;
	 * For writing, UTF-16 iconv typically creates "UTF-16BE-BOM"
 */
	if (same_utf_encoding("UTF-16LE-BOM", out_encoding)) {
		}
			continue;
{
	else if (position == ALIGN_MIDDLE) {
 */
 *    - Non-spacing and enclosing combining characters (general
	int utf8_compensation = slen - display_len;
			 */
		}
			return 0;
			break;
 *
		    /* overlong? */
	   !(has_bom_prefix(data, len, utf16_be_bom, sizeof(utf16_be_bom)) ||
static int git_wcwidth(ucs_char_t ch)
 *    - Other C0/C1 control characters and DEL will lead to a return
}
		in_encoding = "UTF-16";
		if (!src) 	/* broken utf-8, do nothing */
	return p - s;

	/*
 *   character length. Otherwise `text` is treated as limited by NUL.
	if (same_utf_encoding("utf-8", name))
 *    - All remaining characters (including all printable

		mid = min + (max - min) / 2;
void strbuf_utf8_align(struct strbuf *buf, align_type position, unsigned int width,
}

		pick_one_utf8_char(&p, &r);
		case 0x200c: /* ZERO WIDTH NON-JOINER */
	return (
		subst_len = strlen(subst);
		dst = utf8;

	iconv_ibp cp;
#ifndef NO_ICONV
	*text += chrlen;
/* This code is originally from http://www.cl.cam.ac.uk/~mgk25/ucs/ */
		while (skip_ansi &&
		w = -indent;
 * would eventually appear in the string.  *remainder_p is also reduced
				assume_utf8 = 0;
/*
				text = bol = space + isspace(*space);
	if (*p++ != '[')
}
			w += utf8_width(&text, NULL);
	if (bisearch(ch, zero_width, ARRAY_SIZE(zero_width) - 1))
{
	while (*text) {
	return 1;
/*

		c = next_hfs_char(&path);
		bom_str = utf16_be_bom;
}
			*outpos = '\0';
	outpos = out + bom_len;
 * end of that character.  When remainder_p is not NULL, the location
		} else {
			goto invalid;
int is_hfs_dotgitattributes(const char *path)
		p++;
	   !(has_bom_prefix(data, len, utf32_be_bom, sizeof(utf32_be_bom)) ||
				dst += subst_len;

			src += n;
 * in ISO 10646.

 * by the number of bytes we have consumed.
 * if the string does not look like a valid utf8 string.
	typedef char * iconv_ibp;
		return 0;
	iconv_t conv;
		w += n;
 */
 *
	dst = sb_dst.buf;
			eol++;
	}
			goto out;
		ch = ((s[0] & 0x0f) << 12) |
{
		/* 110XXXXx 10xxxxxx */
retry:
			w += n;
		case 0x206c: /* INHIBIT ARABIC FORM SHAPING */
			}
	 * Sorted list of non-overlapping intervals of non-spacing characters,
		ch = ((s[0] & 0x1f) << 6) | (s[1] & 0x3f);
		if (remainder < 4 ||
	} else if (*s < 0x80) {
	if (!src)
 *    - The null character (U+0000) has a column width of 0.
		 * TODO use iconv to decode one char and obtain its chrlen
		c = *text;
			continue;
 * a character (see pick_one_utf8_char() above).
			  size_t *outsz)
		    (s[1] & 0xc0) != 0x80 ||
		}
			min = mid + 1;
	 */
	va_list arg;

	/* test for 8-bit control characters */
 * name directly or one of its alternative names. E.g. UTF-16BE is the
		bom_len = sizeof(utf32_be_bom);
	remainder = (remainder_p ? *remainder_p : 999);
{
			   : 1 /* not valid UTF-8 -> raw byte sequence */;
 * Returns first character length in bytes for multi-byte `text` according to
	if (remainder < 1) {
		case 0x200d: /* ZERO WIDTH JOINER */
		}
	while (src < end) {

{
				w = indent = indent2;
	 * stop at the first NUL.
	/* UTF-16LE-BOM is the same as UTF-16 for reading */
	if (remainder_p)
	}

{
		out_encoding = "UTF-16LE";
	/*
		if (*eol == '\n')
 * Wrap the text, if necessary. The variable indent is the indent for the
		incr = 4;
 *
static const char utf32_le_bom[] = {'\xFF', '\xFE', '\0', '\0'};
		return 0;
				space = text;

		indent = indent2;
	while (*text) {
#include "strbuf.h"

	strbuf_grow(&sb_dst, sb_src->len + subst_len);
		strbuf_addchars(buf, ' ', indent);
 * Inline wrapper to make sure the compiler resolves strlen() on literals at
 *      have a column width of 0.
	} else if ((s[0] & 0xf0) == 0xe0) {
				return NULL;
int same_encoding(const char *src, const char *dst)
	va_end(arg);
	}
		case 0x202b: /* RIGHT-TO-LEFT EMBEDDING */
	if (!in_encoding)
				text++;
 * character as follows:
	if (bisearch(ch, double_width, ARRAY_SIZE(double_width) - 1))
		return "UTF-8";
		return NULL;
		const char *eol = strchrnul(text, '\n');

		int skip;
{
	) || (
			text++;
		    /* U+FFFE or U+FFFF? */
		    (s[0] == 0xf0 && (s[1] & 0xf0) == 0x80) ||
	if (*p++ != '\033')
 */
						strbuf_addch(buf, '\n');
		bom_str = utf32_be_bom;

	if (indent < 0) {
 *      etc.) have a column width of 1.

				*outsz_p = outpos - out;
	size_t remainder, incr;

 * the next character. When remainder_p is not NULL, it points at the
/* The following two functions define the column width of an ISO 10646
	);
	if (position == ALIGN_LEFT)
static int is_hfs_dot_generic(const char *path,
	outsz = insz;

	 */
	const char *p = *text;
	strbuf_setlen(&sb_dst, dst - sb_dst.buf);
			memcpy(dst, src, n);
	ucs_char_t last;
			string += skip;
		incr = 2;
		strbuf_add_indented_text(buf, text, indent1, indent2);
	if (len < strlen(utf8_bom) ||
	if (ch < 32 || (ch >= 0x7f && ch < 0xa0))

static void strbuf_add_indented_text(struct strbuf *buf, const char *text,
		if (assume_utf8) {
	int chrlen;
	iconv_close(conv);


 *

		case 0x206e: /* NATIONAL DIGIT SHAPES */
			if (!text) {
		 * returning 0 is good enough for is_hfs_dotgit
 * - When `remainder_p` is not NULL, on entry `*remainder_p` is how much bytes
		n = utf8_width((const char**)&src, NULL);
int is_encoding_utf8(const char *name)
			}
{
			text += skip;
 * location that stores the number of remaining bytes we can use to pick

	/* binary search in table of double width characters */
	    memcmp(*text, utf8_bom, strlen(utf8_bom)))
		ucs_char_t out = pick_one_utf8_char(in, NULL);
{
 *      ISO 8859-1 and WGL4 characters, Unicode control characters,
 * for the printed string, assuming that the string is utf8.
		incr = 1;
#include "unicode-width.h"
	if (ucs < table[0].first || ucs > table[max].last)
	strbuf_vaddf(&buf, format, arg);
				strbuf_add(buf, start, text - start);
static const char utf16_le_bom[] = {'\xFF', '\xFE'};
void strbuf_add_wrapped_text(struct strbuf *buf,
		case 0x202d: /* LEFT-TO-RIGHT OVERRIDE */

int skip_utf8_bom(char **text, size_t len)
		case 0x206b: /* ACTIVATE SYMMETRIC SWAPPING */
	struct strbuf sb_dst = STRBUF_INIT;
	}
	 * spelling. We do so only as a fallback in case the platform
#endif
	return columns;
		 * make the results of tolower() sane.
				if (!c)
 * `encoding`.

 */
}
	return 0;
		 * to realize it cannot be .git
 */
	/*

	char *tmp = xstrndup(data, len);
#endif
		return 0;
}

	  (same_utf_encoding("UTF-32BE",  enc) ||

 */
	return is_hfs_dot_str(path, "git");
int is_hfs_dotgit(const char *path)
	if (skip_iprefix(src, "utf", &src) && skip_iprefix(dst, "utf", &dst)) {
	if (c != '.')
	if (remainder_p)
{

				strbuf_addch(buf, '\n');
		size_t skip;
		case 0x200e: /* LEFT-TO-RIGHT MARK */
	if (!dst)
{
		return 0;
/*

	strbuf_add_wrapped_text(buf, tmp, indent, indent2, width);
		while ((skip = display_mode_esc_sequence_len(text)))
static const char *fallback_encoding(const char *name)
	  (has_bom_prefix(data, len, utf16_be_bom, sizeof(utf16_be_bom)) ||
				strbuf_setlen(buf, orig_len);
					w |= 0x07;
	 * in HFS+, but this is enough to catch our fairly vanilla
		    (s[1] & 0xc0) != 0x80 ||

 * If indent is negative, assume that already -indent columns have been
	 */
{
		return out;
	}
		len = strlen(string);
	const char *bom_str = NULL;
 * Pick the next char from the stream, ignoring codepoints an HFS+ would.
		    /* surrogate? */
		else {
 * consumed (and no extra indent is necessary for the first line).
int is_utf8(const char *text)

				free(out);
}
#else
	const char *orig = string;
{
		out_encoding = "UTF-16BE";
	return string ? width : len;
	) || (
	const char *bol, *space, *start = text;
		bom_len = sizeof(utf16_le_bom);
	/* binary search in table of non-spacing characters */
static inline int is_hfs_dot_str(const char *path, const char *needle)

	 */

	return (
{
		       (skip = display_mode_esc_sequence_len(string)) != 0)
	c = next_hfs_char(&path);
		utf8_width(&text, NULL);
	ucs_char_t ch;
}

	int slen = strlen(s);
int mbs_chrlen(const char **text, size_t *remainder_p, const char *encoding)
	while (max >= min) {
		memcpy(dst, old, src - old);
	bol = text;

}

 *
		 */
		}
}
			if (outsz_p)
int utf8_strnwidth(const char *string, int len, int skip_ansi)
		}

	 * Some platforms do not have the variously spelled variants of
	columns = fputs(buf.buf, stream);
		    (s[0] & 0xfe) == 0xc0)
	/*
{
		case 0x206a: /* INHIBIT SYMMETRIC SWAPPING */
		int left = (width - display_len) / 2;

	while (1) {
 */
			  const char *out_encoding, const char *in_encoding,
		if (!text)
		return 2;
	int mid;
 * Returns true (1) if the src encoding name matches the dst encoding
/*
				else
	size_t orig_len = buf->len;
	}
}


 * This implementation assumes that ucs_char_t characters are encoded
				     int indent, int indent2)

	);

 * If the string was not a valid UTF-8, *start pointer is set to NULL
		size_t cnt = iconv(conv, &cp, &insz, &outpos, &outsz);
}
		if (*text == '\n' || *text == '\t' || *text == '\r') {


 * pointed to by the variable start. The pointer is updated to point at
{
		src = utf8;
}

	   same_utf_encoding("UTF-16LE", enc)) &&
}

	     has_bom_prefix(data, len, utf32_le_bom, sizeof(utf32_le_bom)))
	struct strbuf buf = STRBUF_INIT;
			max = mid - 1;
	 * Even though latin-1 is still seen in e-mail
		strbuf_addstr(buf, s);
int has_prohibited_utf_bom(const char *enc, const char *data, size_t len)
					return;
{
	if (len == -1)
		 * We know our needles contain only ASCII, so we clamp here to
{
		switch (out) {
	return ch;
		*start = NULL;
{
	char *src = sb_src->buf;
		text = eol;
	strbuf_release(&sb_dst);
#include "utf8.h"
		if (src >= end)
						goto new_line;
	va_start(arg, format);
		    (s[1] & 0xc0) != 0x80 ||
 *    - Other format characters (general category code Cf in the Unicode
	 * Some users under Windows want the little endian version
	/*
	ucs_char_t first;
 *
		strbuf_addf(buf, "%*s%-*s", left, "", width - left + utf8_compensation, s);
		     (s[2] & 0xfe) == 0xbe))
	char *dst;

	out = xmalloc(outalloc);
		/* 0xxxxxxx */
	return is_hfs_dot_str(path, "gitmodules");
		case 0x202e: /* RIGHT-TO-LEFT OVERRIDE */
		if (remainder < 2 ||
	 * A caller that assumes NUL terminated text can choose
		char *old;
	 * of the system tools and libc as much as possible.
	   has_bom_prefix(data, len, utf32_le_bom, sizeof(utf32_le_bom)))
			continue;
		bom_len = sizeof(utf16_be_bom);
	int columns;
		return 0;
	outalloc = st_add(outsz, 1 + bom_len); /* for terminating NUL */
	if (subst)
	out = reencode_string_iconv(in, insz, conv, bom_len, outsz);
/* auxiliary function for binary search in interval table */
		    (s[0] == 0xf4 && s[1] > 0x8f) || s[0] > 0xf4)
	} else if (position == ALIGN_RIGHT)
					}
};
		if (ucs > table[mid].last)
	 */
	return 0;
			outalloc = st_add3(sofar, st_mult(insz, 2), 32);
			      const char *needle, size_t needle_len)
			 * converting the rest.
 *
				}
	const char *p = s;
size_t display_mode_esc_sequence_len(const char *s)
		skip_prefix(dst, "-", &dst);
		columns = utf8_strwidth(buf.buf);
 * Wrapper for fprintf and returns the total number of columns required
	}

		return 1;
}
 */
	     has_bom_prefix(data, len, utf16_le_bom, sizeof(utf16_le_bom)))
	} else if ((s[0] & 0xf8) == 0xf0) {
		/*

out:
	static const char utf8[] = "UTF-8";
		ch = ((s[0] & 0x07) << 18) | ((s[1] & 0x3f) << 12) |
		if (cnt == (size_t) -1) {
						goto new_line;
 * compile time.
		chrlen = 1;
		out_encoding = "UTF-32BE";
	return name;
}

	if (!strcasecmp(name, "latin-1"))
 * Given a buffer and its encoding, return it re-encoded
 */
	 * one.
	ucs_char_t c;
	   (same_utf_encoding(enc, "UTF-32")) &&
		if (n && w >= pos && w < pos + width) {
 *
	   same_utf_encoding("UTF-32LE", enc)) &&

 *      category code Mn or Me in the Unicode database) have a
	   has_bom_prefix(data, len, utf16_le_bom, sizeof(utf16_le_bom)))
	} else if ((s[0] & 0xe0) == 0xc0) {
			goto invalid;

	for (;;) {
 *   we can consume from text, and on exit `*remainder_p` is reduced by returned
	return data && bom && (len >= bom_len) && !memcmp(data, bom, bom_len);
		    (s[3] & 0xc0) != 0x80 ||
char *reencode_string_len(const char *in, size_t insz,
				subst = NULL;

		width += utf8_width(&string, NULL);
	 * headers, some platforms only install ISO-8859-1.
			 * it is likely that insz is not enough for
struct interval {
		strbuf_addf(buf, "%-*s", width + utf8_compensation, s);
	if (!*start)
			return 0;
	strbuf_release(&buf);
		 * gets converted to a percent-sequence, but
 *      column width of 0.
		    (s[2] & 0xc0) != 0x80 ||
		strbuf_add(buf, text, eol - text);
	}

		return;
		while ((n = display_mode_esc_sequence_len(src))) {
const char utf8_bom[] = "\357\273\277";
		 */
invalid:
int is_hfs_dotgitignore(const char *path)
		/* 1110XXXX 10Xxxxxx 10xxxxxx */
		bom_str = utf16_be_bom;
 * - The `text` pointer is updated to point at the next character.
			  const char *bom, size_t bom_len)
				w++;
	strbuf_swap(sb_src, &sb_dst);
	if (!name)
	if (ch == 0)
 * and the return value is undefined.
	if (indent < 0)
		return "ISO-8859-1";
}
			continue;
	int indent, w, assume_utf8 = 1;
int utf8_fprintf(FILE *stream, const char *format, ...)
		goto invalid;
					space++;
	unsigned char *s = (unsigned char *)*start;
	 * there's a great deal of other case-folding that occurs
	return 1;
 *      Report #11 have a column width of 2.
	return out;

	while (string && string < orig + len) {
 * holds the number of bytes remaining in the string that we are allowed
	int w = 0, subst_len = 0;
	space = NULL;
		/* 11110XXX 10XXxxxx 10xxxxxx 10xxxxxx */
	return is_hfs_dot_str(path, "gitattributes");
	}
{
	return 1;
}
 *      value of -1.
		return 0;
	return git_wcwidth(ch);
	size_t outsz, outalloc;
{
					return;
new_line:
 * Returns the total number of columns required by a null-terminated

	size_t bom_len = 0;
	size_t r = (remainder_p ? *remainder_p : SIZE_MAX);


		*remainder_p -= chrlen;
	if (is_encoding_utf8(name))
 * to make is_hfs_dotgit() work, and should not be used otherwise.
	}
			}
int is_hfs_dotgitmodules(const char *path)


	   (same_utf_encoding(enc, "UTF-16")) &&
			dst += n;

					start = space;
	return utf8_strnwidth(string, -1, 0);
{
		return !strcasecmp(src, dst);
			text++;
		in_encoding = fallback_encoding(in_encoding);
 *
				if (c == '\t')
	} else if (same_utf_encoding("UTF-16BE-BOM", out_encoding)) {
					else if (!isalnum(*space))
			}
	 */
 * Pick one ucs character starting from the location *start points at,
		conv = iconv_open(out_encoding, in_encoding);
		*remainder_p = remainder - incr;
		       const char *s)
			outpos = out + sofar;
		return 0;
			w++;
		return 1;
	if (out && bom_str && bom_len)
		return 1;
	typedef const char * iconv_ibp;
	return is_hfs_dot_str(path, "gitignore");
				if (!c && text == start)
static ucs_char_t pick_one_utf8_char(const char **start, size_t *remainder_p)
/*

#include "git-compat-util.h"
{
		 * for now, let's treat encodings != UTF-8 as one-byte
			size_t sofar;
	  (same_utf_encoding("UTF-16BE", enc) ||
	ucs_char_t ch = pick_one_utf8_char(start, remainder_p);
	 * We handle UTF-16 and UTF-32 ourselves only if the platform does not
		/*
	if (r < 1)
	  (has_bom_prefix(data, len, utf32_be_bom, sizeof(utf32_be_bom)) ||
			out = xrealloc(out, outalloc);
		case 0x206d: /* ACTIVATE ARABIC FORM SHAPING */
		old = src;
 * This function returns the number of columns occupied by the character
	} else if (same_utf_encoding("UTF-16", out_encoding)) {
 * same as UTF16BE.

				space = NULL;
	 * UTF-8, so let's fall back to trying the most official
 *    - SOFT HYPHEN (U+00AD) has a column width of 1.
			return 0;
	 * does understand the user's spelling, but not our official
 *      Full-width (F) category as defined in Unicode Technical

	 * not to bother with the remainder length.  We will
		/* these code points are ignored completely */
static int bisearch(ucs_char_t ucs, const struct interval *table, int max)
char *reencode_string_iconv(const char *in, size_t insz, iconv_t conv,
	*text += strlen(utf8_bom);
		space = text;
{

	 * provide a BOM (which we require), since we want to match the behavior
	 *
{
		if (!*in)
		if (conv == (iconv_t) -1)

	if (*p++ != 'm')
int utf8_width(const char **start, size_t *remainder_p)
			else {
	}
		if (tolower(c) != *needle)
	if (width <= 0) {
			return 0;
#ifdef ICONV_OMITS_BOM
{
 * string, assuming that the string is utf8.  Returns strlen() instead
 */
		bom_len = sizeof(utf16_be_bom);
#if defined(OLD_ICONV) || (defined(__sun__) && !defined(_XPG6))
	char *out, *outpos;
		return;
				goto retry;
	if (conv == (iconv_t) -1) {
}
		char c;
}
static int same_utf_encoding(const char *src, const char *dst)
 *

/*
		return 0;
	char *out;
}
		if (!c || isspace(c)) {
			return 1;
		ch = *s;
				memcpy(dst, subst, subst_len);
		bom_str = utf16_le_bom;
}
static ucs_char_t next_hfs_char(const char **in)

		}
	int min = 0;
	 * hard-coded needles.
/*
		    (s[0] == 0xed && (s[1] & 0xe0) == 0xa0) ||

	return is_hfs_dot_generic(path, needle, strlen(needle));
	}
{
		case 0x200f: /* RIGHT-TO-LEFT MARK */
static const char utf16_be_bom[] = {'\xFE', '\xFF'};
#endif
/*
				else if (c == '\n') {
		strbuf_addf(buf, "%*s", width + utf8_compensation, s);
	cp = (iconv_ibp)in;
 *      database) and ZERO WIDTH SPACE (U+200B) have a column width of 0.

void strbuf_add_wrapped_bytes(struct strbuf *buf, const char *data, int len,
		case 0x202c: /* POP DIRECTIONAL FORMATTING */
		return 0;
	int width = 0;
		    /* overlong? */
		    (s[0] == 0xef && s[1] == 0xbf &&
		out_encoding = "UTF-16BE";
	/*
		 */
		const char *text, int indent1, int indent2, int width)

			((s[1] & 0x3f) << 6) | (s[2] & 0x3f);
}
	if (c && !is_dir_sep(c))
}
{
	if (is_encoding_utf8(encoding)) {

	return 0;
					strbuf_addchars(buf, ' ', indent);

	}
		return 0;

	if (same_utf_encoding(src, dst))
{
	}
}

void strbuf_utf8_replace(struct strbuf *sb_src, int pos, int width,
 * and return it, while updating the *start pointer to point at the
	return chrlen;
	}
}
		    (s[0] == 0xe0 && (s[1] & 0xe0) == 0x80) ||
	c = next_hfs_char(&path);
/*
		chrlen = p ? (p - *text)
		return 0;

		else
	conv = iconv_open(out_encoding, in_encoding);
 *    - Spacing characters in the East Asian Wide (W) or East Asian
		size_t n;
		if (remainder < 3 ||
 *
 * with iconv.  If the conversion fails, returns NULL.
	} else {
			if (w <= width || !space) {
			goto invalid;
	return !strcasecmp(src, dst);
			sofar = outpos - out;

}
			     int indent, int indent2, int width)
static const char utf32_be_bom[] = {'\0', '\0', '\xFE', '\xFF'};
int utf8_strwidth(const char *string)
		/*
}
	w = indent = indent1;
			if (subst) {
				if (space)
			/* insz has remaining number of bytes.
	}
 * to pick from.  Otherwise we are allowed to pick up to the NUL that

/*
	if (same_utf_encoding("UTF-16LE-BOM", in_encoding))
		incr = 3;
			}
}
		return -1;
		case 0x202a: /* LEFT-TO-RIGHT EMBEDDING */
 *    - Hangul Jamo medial vowels and final consonants (U+1160-U+11FF)
	}
			outsz = outalloc - sofar - 1;
	if (display_len >= width) {
					if (*space == '\n') {
{
			 * since we started outsz the same as insz,
	*start += incr;

	free(tmp);
	int display_len = utf8_strnwidth(s, slen, 0);

	} else if (same_utf_encoding("UTF-32", out_encoding)) {
			if (errno != E2BIG) {
}
 * first line, indent2 is the indent for all other lines.
 * Note that this is _not_ complete by any means. It's just enough
}
		}
		out_encoding = fallback_encoding(out_encoding);
}
		memcpy(out, bom_str, bom_len);
		    (s[2] & 0xc0) != 0x80 ||
	while (isdigit(*p) || *p == ';')
	else {
			break;
		case 0xfeff: /* ZERO WIDTH NO-BREAK SPACE */
		if (c > 127)
	for (; needle_len > 0; needle++, needle_len--) {
		case 0x206f: /* NOMINAL DIGIT SHAPES */
	char *end = src + sb_src->len;

{
				const char *start = bol;
	return out;
			    size_t bom_len, size_t *outsz_p)

						strbuf_addch(buf, ' ');
			((s[2] & 0x3f) << 6) | (s[3] & 0x3f);
				text = start;
	}
			return NULL;
			 const char *subst)
		skip_prefix(src, "-", &src);
		else if (ucs < table[mid].first)
		 * check for malformed utf8. Technically this
int is_missing_required_utf_bom(const char *enc, const char *data, size_t len)
	return 1;
		    /* > U+10FFFF? */
static int has_bom_prefix(const char *data, size_t len,

	while (1) {
	if (0 <= columns) /* keep the error from the I/O */
