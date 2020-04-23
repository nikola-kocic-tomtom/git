		/* S_Z */  CMP, +1,  +1,  -1,  CMP, CMP, -1,  CMP, CMP
		/* S_F */  S_N, S_F, S_F,
	for (i = 0; i < prereleases->nr; i++) {
	c2 = *p2++;
		return diff;
/*
	 */
		c1 = *p1++;
		/* S_F */  CMP, CMP, CMP, CMP, CMP, CMP, CMP, CMP, CMP,
			prereleases = deprecated_prereleases;
 * string will be forced to be on top.
			    int *diff)
	unsigned char c1, c2;
 * returning less than, equal to or greater than zero if S1 is less
	for (i = start; i <= end; i++)

	return 1;
/*
 * If both s1 and s2 contain a (different) suffix around that position,
		c2 = *p2++;
		return 0;
#include "string-list.h"
 * to GPLv2.
		const char *suffix = prereleases->items[i].string;
	const unsigned char *p2 = (const unsigned char *) s2;
			    const char *s2,
		int start, suffix_len = strlen(suffix);
static const struct string_list *prereleases;
 */
 * If more than one different contained suffixes start at that earliest
	static const int8_t result_type[] = {
	if (prereleases && swap_prereleases(s1, s2, (const char *) p1 - s1 - 1,
	 */
		/* S_Z */  S_N, S_F, S_Z
					    i, &match1);

 * off is the offset of the first different character in the two strings
	if (match1.conf_pos >= 0 && match2.conf_pos >= 0)
	const unsigned char *p1 = (const unsigned char *) s1;
		find_better_matching_suffix(s1, suffix, suffix_len, start,
	 * Transition   (10) 0  (01) d  (00) x
	default:

		while (isdigit (*p1++))
		} else
	}
 * If any of the strings contains more than one different suffixes around
			match->start = i;
	 * A better match either starts earlier or starts at the same offset
	 * Symbol(s)    0       [1-9]   others
	struct suffix_match match1 = { -1, off, -1 };
		return 0;
#define  S_F    0x6
}
	else /* if (match2.conf_pos >= 0) */
 * fractionnal parts, S_Z: idem but with leading Zeroes only
		if (suffix_len < off)
			start = off - suffix_len;
 */


	int start;
		*diff = match1.conf_pos - match2.conf_pos;
			    int off,
		state = next_state[state];
		state += (c1 == '0') + (isdigit (c1) != 0);
#define  S_Z    0x9
static int initialized;

struct suffix_match {
		*diff = -1;
	int end = match->len < suffix_len ? match->start : match->start-1;
 * s1 and s2. If either s1 or s2 contains a prerelease suffix containing

 * suffixes.
	while ((diff = c1 - c2) == 0) {

	}
/*
 * suffix which starts at the earliest offset in that string.
					int suffix_len, int start, int conf_pos,
		if (starts_with(tagname + i, suffix)) {
		return 0;
	if (match1.conf_pos == match2.conf_pos)
			if (deprecated_prereleases)
		/* S_I */  S_N, S_I, S_I,

		/* S_I */  CMP, -1,  -1,  +1,  LEN, LEN, +1,  LEN, LEN,
		prereleases = git_config_get_value_multi("versionsort.suffix");
{
		 * and "v1.0-rcY": the caller should decide based on "X"
 * that offset or a suffix ends right before that offset, then that
#define  LEN    3
	 * but is longer.
 * configuration.


		/* state    x    d    0  */
					    i, &match2);
	int i;
			match->len = suffix_len;
		/* S_N */  CMP, CMP, CMP, CMP, LEN, CMP, CMP, CMP, CMP,
	if (match1.conf_pos == -1 && match2.conf_pos == -1)
 * offset, then that string is sorted according to the longest of those
		if (c1 == '\0')
#define  S_N    0x0
	int len;
				return 1;


 *

					struct suffix_match *match)
	if (p1 == p2)
	static const uint8_t next_state[] = {
			if (!isdigit (*p2++))
			break;
		/* state   x/x  x/d  x/0  d/x  d/d  d/0  0/x  0/d  0/0  */
	c1 = *p1++;
	}
 * than, equal to or greater than S2 (for more info, see the texinfo
		return diff;
	/*
		deprecated_prereleases = git_config_get_value_multi("versionsort.prereleasesuffix");
	else if (match1.conf_pos >= 0)
#include "cache.h"
		return state;
	case LEN:
		 * and "Y". */

	/* Hint: '0' is a digit too.  */
 * versioncmp(): copied from string/strverscmp.c in glibc commit

	}
	case CMP:
	int state, diff;
 * their order is determined by the order of those two suffixes in the
/* result_type: CMP: return diff; LEN: compare using len_diff/diff */
}
		find_better_matching_suffix(s2, suffix, suffix_len, start,
	};
 * Compare S1 and S2 as strings holding indices/version numbers,
static int swap_prereleases(const char *s1,

 *
}
	state = result_type[state * 3 + (((c2 == '0') + (isdigit (c2) != 0)))];
 */
		const struct string_list *deprecated_prereleases;
 * that position, then that string is sorted according to the contained
/*
 */
				warning("ignoring versionsort.prereleasesuffix because versionsort.suffix is set");
 * states: S_N: normal, S_I: comparing integral part, S_F: comparing
#define  CMP    2
		}

	int i;
 * ee9247c38a8def24a59eb5cfb7196a98bef8cfdc, reformatted to Git coding
	switch (state) {
};
		/* Found the same suffix in both, e.g. "-rc" in "v1.0-rcX"
int versioncmp(const char *s1, const char *s2)
	};
		initialized = 1;
 * doc).
			start = 0;
		if (prereleases) {
		*diff = 1;
{
			match->conf_pos = conf_pos;
	/*

static void find_better_matching_suffix(const char *tagname, const char *suffix,

		/* S_N */  S_N, S_I, S_Z,

#define  S_I    0x3

	state = S_N + ((c1 == '0') + (isdigit (c1) != 0));
 * style. The implementation is under LGPL-2.1 and Git relicenses it
		return isdigit (*p2) ? -1 : diff;
 * Return non-zero if *diff contains the return value for versioncmp()
		else

	struct suffix_match match2 = { -1, off, -1 };

#include "config.h"
					    &diff))
	int conf_pos;
			return diff;
{
	if (!initialized) {
