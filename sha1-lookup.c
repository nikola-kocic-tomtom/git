	uint32_t hi, lo;
	while (lo < hi) {
 *    - if it is a hit, we are happy.
		return -1;
	hi = ntohl(fanout_nbo[*sha1]);
{
 *                      hi = mi; "mi is larger than target"
		mi = lo + (hi - lo) / 2;
 *              if (!cmp)
			if (result)
			return 1;
		*result = lo;
 */
 *
	} while (lo < hi);
	size_t hi = nr;
/*
 * The sha1 of element i (between 0 and nr - 1) should be returned
			if (hiv < miv)
		}
	lo = ((*sha1 == 0x0) ? 0 : ntohl(fanout_nbo[*sha1 - 1]));
 *
 *
 *      do {
			}
 *      one slot after it, because we allow lo to be at the target.
	do {
		if (!cmp) {
 *
 *              else


 * pick mi that is much closer to lo than the midway.
			hiv = take2(fn(nr - 1, table) + ofs);
				 * At this point miv could be equal


			hi = mi;
}
					break;
		int cmp = hashcmp(table + mi * stride, sha1);
				return index_pos_to_insert_pos(nr);
	}

	     sha1_access_fn fn)
 *              int mi = lo + (hi - lo) / 2;
 *   slot that is guaranteed to be above the target (it can never
 * - We find a point 'mi' between lo and hi (mi could be the same
static uint32_t take2(const unsigned char *sha1)
 *                      lo = mi+1; "mi is smaller than target"
{
#include "cache.h"
		}
 *              if (cmp > 0)
		else
	size_t mi = 0;
				if (lo <= mi && mi < hi)
int sha1_pos(const unsigned char *hash, void *table, size_t nr,
	if (result)
#include "sha1-lookup.h"
 *    - if it is strictly higher than the target, we update hi with
 * When choosing 'mi', we do not have to take the "middle" but
 *                      return (mi is the wanted one)
 *   the target.  There are three cases:
				mi = (nr - 1) * (miv - lov) / (hiv - lov);
		if (cmp > 0)
				 * to hiv (but sha1 could still be higher);
				 * kept.
 */
			if (miv < lov)
 *   be at the target).
}
	return ((sha1[0] << 8) | sha1[1]);
			lo = mi + 1;
int bsearch_hash(const unsigned char *sha1, const uint32_t *fanout_nbo,

				 * the invariant of (mi < hi) should be
 * satisfied.  When we somehow know that the distance between the
}

 * The table should contain "nr" elements.
		if (!cmp)
		for (ofs = 0; ofs < the_hash_algo->rawsz - 2; ofs += 2) {
	return index_pos_to_insert_pos(lo);
		size_t lov, hiv, miv, ofs;
 *    - if it is strictly lower than the target, we update lo to be
 *              int cmp = "entry pointed at by mi" minus "target";

		 const unsigned char *table, size_t stride, uint32_t *result)
 *      it.
		if (cmp > 0)
	return 0;
 * anywhere in between lo and hi, as long as lo <= mi < hi is
 *
 * Conventional binary search loop looks like this:

				return -1;
	}

			return mi;
 *      } while (lo < hi);
	if (!nr)
/*
			lo = mi + 1;
			if (lov != hiv) {
			lov = take2(fn(0, table) + ofs);
 *
	size_t lo = 0;

 *
	if (nr != 1) {
				/*
		else
 *   above the target (it could be at the target), hi points at a
				BUG("assertion failed in binary search");
 * The invariants are:
		unsigned mi = lo + (hi - lo) / 2;
 * target and lo is much shorter than the target and hi, we could
 * by "fn(i, table)".
{
		int cmp;
				 */
			miv = take2(hash + ofs);
				*result = mi;
			hi = mi;
 *
 * - When entering the loop, lo points at a slot that is never
 *   as lo, but never can be the same as hi), and check if it hits
		cmp = hashcmp(fn(mi, table), hash);
