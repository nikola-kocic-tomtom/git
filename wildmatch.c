					if (strchr((char*)text, '/') != NULL)
						if (ISALPHA(t_ch))
				return WM_NOMATCH;
							matched = 1;
		switch (p_ch) {
						if (t_ch == p_ch)
/* What character marks an inverted character class? */
				 * with WM_PATHNAME matches the next
					       (match_slash || t_ch != '/')) {
			return WM_ABORT_ALL;
# define ISBLANK(c) (ISASCII(c) && isblank(c))
#define ISPRINT(c) (ISASCII(c) && isprint(c))
					} else if (CC_EQ(s,i, "punct")) {
				 * only if there are no more slash characters. */
					} else if (CC_EQ(s,i, "cntrl")) {
					p_ch = *++p;
#define ISLOWER(c) (ISASCII(c) && islower(c))
					} else /* malformed [:class:] string */
					}
					match_slash = 0;
# define ISBLANK(c) ((c) == ' ' || (c) == '\t')
				if (!match_slash) {
					 * nothing and go ahead match the rest of the


			do {
			negated = p_ch == NEGATE_CLASS ? 1 : 0;
			if (negated) {

				const char *slash = strchr((char*)text, '/');
					} else if (CC_EQ(s,i, "upper")) {


#define ISUPPER(c) (ISASCII(c) && isupper(c))
					if (t_ch != p_ch)
				return WM_NOMATCH;
						return WM_MATCH;
				/*
					} else if (CC_EQ(s,i, "space")) {
							matched = 1;
					}
**  Rich $alz is now <rsalz@bbn.com>.
				/* the slash is consumed by the top-level for loop */
#define ISCNTRL(c) (ISASCII(c) && iscntrl(c))
					} else if (CC_EQ(s,i, "digit")) {
					/*
		}
			} else
**  Modified by Wayne Davison to special-case '/' matching, to make '**'
# define ISASCII(c) 1
					 * <star star slash>, just assume it matches
						if (ISLOWER(t_ch))
/*
						return matched;
/* Match the "pattern" against the "text" string. */

				t_ch = *++text;
			p_ch = *++p;
			p_ch = *++p;
				if ((matched = dowild(p, text, flags)) != WM_NOMATCH) {
					} else if (CC_EQ(s,i, "graph")) {
#define NEGATE_CLASS2	'^'
						if (ISUPPER(t_ch))
						p_ch = tolower(p_ch);
**  work differently than '*', and to fix the character-class code.
			/* Literal match with following character.  Note that the test
					 * pattern with the remaining string. This
				 */
				}
#ifdef isgraph
}
	for ( ; (p_ch = *p) != '\0'; text++, p++) {
							matched = 1;
				return WM_NOMATCH;
							matched = 1;
{
							matched = 1;
							matched = 1;


#else
						return WM_ABORT_ALL;
					int i;
			 * in "default" handles the p[1] == '\0' failure case. */
						if (ISSPACE(t_ch))
						if (ISBLANK(t_ch))
typedef unsigned char uchar;
#endif
		if ((flags & WM_CASEFOLD) && ISUPPER(p_ch))
						matched = 1;
	return dowild((const uchar*)pattern, (const uchar*)text, flags);
					if (!match_slash || matched != WM_ABORT_TO_STARSTAR)
							matched = 1;
						else if ((flags & WM_CASEFOLD) && ISLOWER(t_ch))
			}
#define CC_EQ(class, len, litmatch) ((len) == sizeof (litmatch)-1 \
							t_ch = tolower(t_ch);
						if (ISPRINT(t_ch))
*/
			while (1) {
						uchar t_ch_upper = toupper(t_ch);
			}
							matched = 1;
					else if ((flags & WM_CASEFOLD) && ISLOWER(t_ch)) {
					} else if (CC_EQ(s,i, "blank")) {
			if (*++p == '*') {

#define NEGATE_CLASS	'!'
				while (*++p == '*') {}
				} else if (p_ch == '-' && prev_ch && p[1] && p[1] != ']') {
			/* Match anything but '/'. */
# define ISGRAPH(c) (ISASCII(c) && isprint(c) && !isspace(c))
						/* Didn't find ":]", so treat like a normal set. */
**  It is 8bit clean.
					 * otherwise it breaks C comment syntax) match
		if ((flags & WM_CASEFOLD) && ISUPPER(t_ch))
					if (!p_ch)
					} else if (CC_EQ(s,i, "lower")) {
		uchar t_ch, prev_ch;
						p_ch = '[';
				else if ((prev_p < pattern || *prev_p == '/') &&
					while ((t_ch = *text) != '\0' &&
				text = (const uchar*)slash;
	return *text ? WM_NOMATCH : WM_MATCH;
						if (ISCNTRL(t_ch))
**
						return WM_NOMATCH;
						p_ch = *++p;
				match_slash = flags & WM_PATHNAME ? 0 : 1;
					return WM_ABORT_ALL;
				const uchar *prev_p = p - 2;
				/* Inverted character class. */
						matched = 1;
			continue;
							return WM_ABORT_ALL;
						return WM_ABORT_ALL;
		case '*':
				if (t_ch == '\0')
							matched = 1;
		int matched, match_slash, negated;
				    (*p == '\0' || *p == '/' ||
					} else if (CC_EQ(s,i, "alpha")) {
#ifdef isblank
			matched = 0;
				/*
			if (*p == '\0') {
							matched = 1;
}
			    ((flags & WM_PATHNAME) && t_ch == '/'))
				     (p[0] == '\\' && p[1] == '/'))) {
							matched = 1;
						return WM_NOMATCH;
				 */
#define ISALPHA(c) (ISASCII(c) && isalpha(c))
				if (!p_ch)
		case '\\':
						return WM_ABORT_ALL;
					 * both foo/bar and foo/a/bar.
					p_ch = 0; /* This makes "prev_ch" get set to 0. */
			}
					if ((flags & WM_CASEFOLD) && ISUPPER(p_ch))
							break;
#include "cache.h"
					if (CC_EQ(s,i, "alnum")) {
static int dowild(const uchar *p, const uchar *text, unsigned int flags)
						if (!p_ch)
{
			/* FALLTHROUGH */
					}
					p_ch = *++p;
/* Match pattern "p" against "text" */
			if (matched == negated ||
		default:
					    dowild(p + 1, text, flags) == WM_MATCH)
						if (ISALNUM(t_ch))
					p_ch = *p;
					for (s = p += 2; (p_ch = *p) && p_ch != ']'; p++) {} /*SHARED ITERATOR*/
			if ((flags & WM_PATHNAME) && t_ch == '/')
				if (p_ch == '\\') {
						continue;
						p = s - 2;
#define ISDIGIT(c) (ISASCII(c) && isdigit(c))
#else
							matched = 1;
					 */
					/* without WM_PATHNAME, '*' == '**' */
int wildmatch(const char *pattern, const char *text, unsigned int flags)
#endif
					match_slash = 1;
						if (ISGRAPH(t_ch))
					i = p - s - 1;
							matched = 1;
					if (p[0] == '/' &&
				 * directory
				if (!slash)
							matched = 1;
				} else if (!match_slash && t_ch == '/')
				 * Try to advance faster when an asterisk is
#define ISXDIGIT(c) (ISASCII(c) && isxdigit(c))
					matched = 1;
				 * _one_ asterisk followed by a slash
				 * the first slash as it cannot belong to '*'.
		case '?':
					if (t_ch == p_ch)
#include "wildmatch.h"
					p_ch = 0; /* This makes "prev_ch" get set to 0. */
					 * helps make foo/<*><*>/bar (<> because
						if (ISPUNCT(t_ch))
				break;
						if (ISDIGIT(t_ch))
				if (!(flags & WM_PATHNAME))
					 * Assuming we already match 'foo/' and are at
					} else if (CC_EQ(s,i, "xdigit")) {
	const uchar *pattern = p;
			t_ch = tolower(t_ch);
					}
			if (t_ch != p_ch)
			return WM_ABORT_ALL;
				    && strncmp((char*)class, litmatch, len) == 0)
**
	}
					if (!p_ch)
**  Do shell-style pattern matching for ?, \, [], and * characters.
#else
					if (t_ch <= p_ch && t_ch >= prev_ch)
				/* Trailing "**" matches everything.  Trailing "*" matches

**  Written by Rich $alz, mirror!rs, Wed Nov 26 19:03:17 EST 1986.
			/* Assign literal 1/0 because of "matched" comparison. */
				    && *(class) == *(litmatch) \
				} else /* WM_PATHNAME is set */
	uchar p_ch;
							matched = 1;
				} else if (t_ch == p_ch)
			} while (prev_ch = p_ch, (p_ch = *++p) != ']');
						if (t_ch == p_ch)
					if (i < 0 || p[-1] != ':') {
				} else if (p_ch == '[' && p[1] == ':') {
					return WM_ABORT_TO_STARSTAR;
				 * that the string before the literal
# define ISGRAPH(c) (ISASCII(c) && isgraph(c))
			continue;
				if (!is_glob_special(*p)) {
						if (ISXDIGIT(t_ch))
			} else if (!match_slash && *p == '/') {
					return WM_NOMATCH;
			p_ch = tolower(p_ch);
						if ((flags & WM_CASEFOLD) && ISUPPER(t_ch))
					match_slash = 1;
						text++;
					break;

#define ISALNUM(c) (ISASCII(c) && isalnum(c))
#endif
				return WM_MATCH;
				}
#if defined STDC_HEADERS || !defined isascii
				 * If match_slash is false, do not look past
				 * must belong to "*".
			if (p_ch == NEGATE_CLASS2)
		case '[':
				p_ch = NEGATE_CLASS;
				 * followed by a literal. We know in this case
				/* without WM_PATHNAME, '*' == '**' */
#define ISSPACE(c) (ISASCII(c) && isspace(c))
		if ((t_ch = *text) == '\0' && p_ch != '*')
#endif
					const uchar *s;
# define ISASCII(c) isascii(c)
			continue;
			prev_ch = 0;
#define ISPUNCT(c) (ISASCII(c) && ispunct(c))
						if (t_ch_upper <= p_ch && t_ch_upper >= prev_ch)
#ifdef NEGATE_CLASS2
					if (p_ch == '\\') {
				p_ch = *++p;
					} else if (CC_EQ(s,i, "print")) {

