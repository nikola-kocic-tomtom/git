static int patience_diff(mmfile_t *file1, mmfile_t *file2,
	int result = 0;
	result->xpp = xpp;
	memset(result->entries, 0, result->alloc * sizeof(struct entry));
				!xdl_recmatch(record->ptr, record->size,

		return NULL;
	int next1, next2;
	struct entry **sequence = xdl_malloc(map->nr * sizeof(struct entry *));

static struct entry *find_longest_common_sequence(struct hashmap *map)
		else
	 * is _not_ the hash anymore, but a linearized version of it.  In
					map->xpp, map->env,
static int patience_diff(mmfile_t *file1, mmfile_t *file2,
		return;
	for (i = 0; i < xpp->anchors_nr; i++) {
/*
		sequence[i] = entry;
 * Between those common lines, the patience diff algorithm is applied
{
			continue;
	/* trivial case: one side is empty */
	return left;
static void insert_record(xpparam_t const *xpp, int line, struct hashmap *map,
				return -1;
		 * sequence;

	}
		unsigned anchor : 1;
 *
		 */
 *
 *  This library is free software; you can redistribute it and/or
	}
 *  This library is distributed in the hope that it will be useful,
		map->last->next = map->entries + index;
	xpparam_t xpp;
 *
			line1, count1, line2, count2);
	/* are there any matching lines at all? */
static int fill_hashmap(mmfile_t *file1, mmfile_t *file2,

	else
			env->xdf2.rchg[line2++ - 1] = 1;
 * It is assumed that env has been prepared using xdl_prepare().
}
	/* environment is cleaned up in xdl_diff() */
static int walk_common_sequence(struct hashmap *map, struct entry *first,
#define NON_UNIQUE ULONG_MAX
 */
	 * xdl_classify_record()), the "ha" member of the records (AKA lines)
{
		entry->previous = i < 0 ? NULL : sequence[i];
	map->entries[index].hash = record->ha;
/*
		 * in either the first or the second file.
	}
 * Now, the algorithm tries to extend the set of common lines by growing
	 * After xdl_prepare_env() (or more precisely, due to
		return 0;
		 * 0 = unused entry, 1 = first line, 2 = second, etc.
	}
		first = first->next;
	for (;;) {
 *
		} else if (i == longest) {
		entry->previous->next = entry;
		/* Try to grow the line ranges of common lines */
 * common lines.
		xdl_free(map.entries);
	 * other words, the "ha" member is guaranteed to start with 0 and
	int nr, alloc;
		return -1;
			map->has_matches = 1;
		if (map->entries[index].hash != record->ha ||
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
	return result;
	map->entries[index].anchor = is_anchor(xpp, map->env->xdf1.recs[line - 1]->ptr);
		xdl_free(sequence);
	int left = -1, right = longest;

			right = middle;
/*
	 * So we multiply ha by 2 in the hope that the hashing was
 *  <http://www.gnu.org/licenses/>.
	entry = sequence[longest - 1];

 *
 *  Lesser General Public License for more details.
 * the line ranges where the files have identical lines.
					map->xpp->flags)) {

 * that the order in the sequence agrees with the order of the lines in

	return xdl_fall_back_diff(map->env, &xpp,
{
		int line1, int count1, int line2, int count2)

	if (fill_hashmap(file1, file2, xpp, env, &map,
 * the order in file1.  For each of these pairs, the longest (partial)
 * second file.
		}
					other->ptr, other->size,
 * sequence whose last element's line2 is smaller is determined.
	 */
 * This function has to be called for each recursion into the inter-hunk


}
	if (!count1) {
 *
	while (left + 1 < right) {
		insert_record(xpp, line2++, result, 2);


 *
{
		unsigned long line1, line2;
	/*
 * both files.  These are intuitively the ones that we want to see as

 */
		if (pass == 2)
		while(count2--)
		xpparam_t const *xpp, xdfenv_t *env)
		/*
		if (!first)
		/* Recurse */
}

	mmfile_t *file1, *file2;
	entry->next = NULL;
 * Find the longest sequence with a smaller last element (meaning a smaller
	memset(&map, 0, sizeof(map));
			line1++;
	if (!map.has_matches) {
		i = binary_search(sequence, longest, entry);
			map->entries[index].line2 = NON_UNIQUE;
		return -1;
	 * If not -1, this entry in sequence must never be overridden.
				next1--;
}
 *  License as published by the Free Software Foundation; either
		record2->ptr, record2->size, map->xpp->flags);
		int line1, int count1, int line2, int count2)
	map->entries[index].line1 = line;
	result->file2 = file2;
	first = find_longest_common_sequence(&map);
{

		}
		map->entries[index].previous = map->last;
		if (entry->anchor) {
}

			continue;
 * are handled by the well-known Myers algorithm.
	while (count1--)
{
		}
		int line1, int count1, int line2, int count2)
		map->env->xdf1.recs : map->env->xdf2.recs;
		 * "next" & "previous" are used for the longest common

		if (pass == 1 || map->entries[index].line2)
 */

 * recursively, until no unique line pairs can be found; these line ranges
		return;
/*
			env->xdf1.rchg[line1++ - 1] = 1;
	while (map->entries[index].line1) {
		line1 = first->line1 + 1;
/*
		return 0;

 * The basic idea of patience diff is to find lines that are unique in
				next2--;
 */
 *  modify it under the terms of the GNU Lesser General Public
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
static int fall_back_to_classic_diff(struct hashmap *map,
	}
	/* were common records found? */
		other = map->env->xdf1.recs[map->entries[index].line1 - 1];
			longest++;
	} *entries, *first, *last;
 *
		struct hashmap *result,
	 * the second record's ha can only be 0 or 1, etc.
		line2 = first->line2 + 1;
		}

	 *
	} else if (!count2) {
	 */
		xpparam_t const *xpp, xdfenv_t *env,
		entry = entry->previous;

static int is_anchor(xpparam_t const *xpp, const char *line)
		return 0;
	}
		else
			struct hashmap submap;

		insert_record(xpp, line1++, result, 1);
		} else {

 */
			line1, count1, line2, count2))
	int anchor_i = -1;
		 * initially, "next" reflects only the order in file1.
}
	result->file1 = file1;
			next2 = end2;
	xrecord_t *record = records[line - 1], *other;
				match(map, line1, line2)) {
 */
		/* by construction, no two entries can be equal */

	 * Therefore, overriding entries before this has no effect, so
			continue;
 *  Davide Libenzi <davidel@xmailserver.org>
	if (!longest) {
		 */
 * This is a hash mapping from line hash to line numbers in the first and
		xpparam_t const *xpp, xdfenv_t *env,
	}
	if (pass == 2)
	/* No common unique lines were found */
			next1 = first->line1;
	struct entry {
 * both files) naturally defines an initial set of common lines.
static int binary_search(struct entry **sequence, int longest,
	struct entry *entry;

		if (!entry->line2 || entry->line2 == NON_UNIQUE)
			return 1;
 * item per sequence length: the sequence with the smallest last
 * and if none was found, ask xdl_do_diff() to do the job.
	 * do not do that either.
			line2++;
		 * If 1, this entry can serve as an anchor. See
{
		struct entry *entry)
		while (first->next &&
	 * "unique enough".
	while (entry->previous) {
	return entry;
	if (map->last) {
		if (sequence[middle]->line2 > entry->line2)
	result->entries = (struct entry *)
int xdl_do_patience_diff(mmfile_t *file1, mmfile_t *file2,

	}
 * line2, as we construct the sequence with entries ordered by line1).
			first = first->next;
	map->last = map->entries + index;
	int index = (int)((record->ha << 1) % map->alloc);
	if (!map->first)
			next1 = end1;
		struct entry *next, *previous;
	return 0;
			env->xdf1.rchg[line1++ - 1] = 1;
			if (++index >= map->alloc)
 * The idea is to start with the list of common unique lines sorted by
	/* We know exactly how large we want the hash map */
	map->nr++;
 */
	xrecord_t *record1 = map->env->xdf1.recs[line1 - 1];

{
 *
}
			  int pass)

	xpparam_t const *xpp;

		if (next1 > line1 || next2 > line2) {
			memset(&submap, 0, sizeof(submap));
			}
		if (first) {
 * The maximal ordered sequence of such line pairs (where ordered means
	xdl_free(map.entries);
 *
	/* Iterate starting at the last element, adjusting the "next" members */
	unsigned long has_matches;
 * This function assumes that env was prepared with xdl_prepare_env().
		int middle = left + (right - left) / 2;

				first->next->line1 == first->line1 + 1 &&
					line2, next2 - line2))
		 * line2 is NON_UNIQUE if the line is not unique

	return patience_diff(file1, file2, xpp, env,
				index = 0;
		++i;
			while (next1 > line1 && next2 > line2 &&
	}
};
		while(count2--)

			next2 = first->line2;
		unsigned long hash;
	/*
					line1, next1 - line1,
 *  License along with this library; if not, see
		return -1;
	result->alloc = count1 * 2;
		/*
			return 0;
				first->next->line2 == first->line2 + 1)
}
	if (!result->entries)
	xrecord_t *record2 = map->env->xdf2.recs[line2 - 1];
		while (line1 < next1 && line2 < next2 &&
	if (xdl_prepare_env(file1, file2, xpp, env) < 0)
	xpp.flags = map->xpp->flags & ~XDF_DIFF_ALGORITHM_MASK;
			line1, count1, line2, count2);

 * element (in terms of line2).

/* The argument "pass" is 1 for the first file, 2 for the second. */
			longest = anchor_i + 1;
		map->first = map->entries + index;
	xdfenv_t *env;
	for (entry = map->first; entry; entry = entry->next) {
			1, env->xdf1.nrec, 1, env->xdf2.nrec);
 *  LibXDiff by Davide Libenzi ( File Differential Library )
	int i;
		result = walk_common_sequence(&map, first,
 *  You should have received a copy of the GNU Lesser General Public
		xpparam_t const *xpp, xdfenv_t *env,
static int match(struct hashmap *map, int line1, int line2)
}
		xdl_malloc(result->alloc * sizeof(struct entry));

		}

		while(count1--)
	int end1 = line1 + count1, end2 = line2 + count2;
		 * Documentation/diff-options.txt for more information.
}
 * Recursively find the longest common sequence of unique lines,
 * restricted to a smaller part of the files.
	xrecord_t **records = pass == 1 ?
			env->xdf2.rchg[line2++ - 1] = 1;
			if (patience_diff(map->file1, map->file2,
	struct entry *first;

		if (i <= anchor_i)
	xdl_free(sequence);
	while (count2--)
/*
		while(count1--)
		int line1, int count1, int line2, int count2);
			map->entries[index].line2 = line;
	/* First, fill with entries from the first file */

		/*
	}
	int longest = 0, i;
		result = fall_back_to_classic_diff(&map,
	if (first)
 *  version 2.1 of the License, or (at your option) any later version.
 * parts, as previously non-unique lines can become unique when being
	/* return the index in "sequence", _not_ the sequence length */
					match(map, next1 - 1, next2 - 1)) {
 *  Copyright (C) 2003-2016 Davide Libenzi, Johannes E. Schindelin
	/* Then search for matches in the second file */
/*
			left = middle;
	result->env = env;
 * For efficiency, the sequences are kept in a list containing exactly one
				  line1, count1, line2, count2);
	return 0;
	struct hashmap map;
#include "xinclude.h"
{
			anchor_i = i;
{
		if (!strncmp(line, xpp->anchors[i], strlen(xpp->anchors[i])))
	return xdl_recmatch(record1->ptr, record1->size,
 *
		int line1, int count1, int line2, int count2)
struct hashmap {
		 */
