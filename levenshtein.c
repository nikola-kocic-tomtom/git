 *
 * "i" and the substring of string2 of length "j + 1".
		row1[j] = j * a;

	ALLOC_ARRAY(row0, len2 + 1);
 *
		int *dummy;
 * - a (for insertion, AKA "Add")
			if (i > 0 && j > 0 && string1[i - 1] == string2[j] &&
 *
				row2[j + 1] = row0[j - 1] + w;
 * This function implements the Damerau-Levenshtein algorithm to
 * - s (as in "Substitution")
 * string1 that the distance is calculated for.
 * operation is a substitution, a swap, a deletion, or an insertion.
 * i (in string1) and j (in string2), respectively, given that the last
 * calculate a distance between strings.
#include "levenshtein.h"
			/* deletion */
 * This implementation allows the costs to be weighted:
 * It does so by calculating the costs of the path ending in characters
{
		}
}
	for (i = 0; i < len1; i++) {
			if (row2[j + 1] > row1[j + 1] + d)
 * The idea is to build a distance matrix for the substrings of both
 */
	i = row1[len2];
 * - w (as in "sWap")
 * Note that this algorithm calculates a distance _iff_ d == a.
			row2[j + 1] = row1[j] + s * (string1[i] != string2[j]);
	}
		row1 = row2;
 * All the big loop does is determine the partial minimum-cost paths.
 * Damerau-Levenshtein distance between the substring of string1 of length
 * Basically, it says how many letters need to be swapped, substituted,
 * plus one insertion, only two rows would be needed).
	int len1 = strlen(string1), len2 = strlen(string2);
		row2[0] = (i + 1) * d;

/*
int levenshtein(const char *string1, const char *string2,
	free(row0);
	free(row1);
			if (row2[j + 1] > row2[j] + a)
#include "cache.h"
 *
 * are kept in memory (if swaps had the same or higher cost as one deletion
		row0 = row1;
	return i;

	free(row2);
		row2 = dummy;
				row2[j + 1] = row1[j + 1] + d;
 * of string1 of length "i"), and row0 the row before that.
 * row2 holds the current row, row1 the previous row (i.e. for the substring

		dummy = row0;
 *
			/* substitution */
 *
 * deleted from, or added to string1, at least, to get string2.
		int w, int s, int a, int d)
 *
	int i, j;
 * - d (as in "Deletion")
			/* swap */
					string1[i] == string2[j - 1] &&
			/* insertion */
					row2[j + 1] > row0[j - 1] + w)
	int *row0, *row1, *row2;

	for (j = 0; j <= len2; j++)
 * strings.  To avoid a large space complexity, only the last three rows

				row2[j + 1] = row2[j] + a;
 *
 *
	ALLOC_ARRAY(row2, len2 + 1);
	ALLOC_ARRAY(row1, len2 + 1);
 * At any stage, "i + 1" denotes the length of the current substring of
		for (j = 0; j < len2; j++) {

 * In other words, at the start of the big loop, row2[j + 1] contains the
 *
