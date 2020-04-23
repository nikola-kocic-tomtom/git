	ALLOC_ARRAY(p->revindex, num_ent + 1);
{
		for (i = 0; i < num_ent; i++) {
		 */
	/*
 * ordered by offset, so if you know the offset of an object, next offset
#undef BUCKETS
	free(pos);
	 * partial results into "entries", we sort back and forth between the
}
			lo = mi + 1;
		return NULL;
	to = tmp;
	int pos;

	unsigned i;
		/*

	if (pos < 0)
	p->revindex[num_ent].offset = p->pack_size - hashsz;
	 */
struct revindex_entry *find_pack_revindex(struct packed_git *p, off_t ofs)
 * corresponding pack file where each object's data starts, but the entries
			const uint32_t off = ntohl(*off_32++);

		 */
	/*
	const unsigned hashsz = the_hash_algo->rawsz;
	 */
 * also rather expensive to find the sha1 for an object given its offset.
	p->revindex[num_ent].nr = -1;
		else
	 * This knows the pack format -- the hash trailer
			p->revindex[i].nr = i;
		const uint32_t *off_64 = off_32 + p->num_objects;
 * Pack index for existing packs give us easy access to the offsets into

 * parameter must be at least as large as the largest offset in the array,

		if (open_pack_index(p))
	 * keep track of them with alias pointers, always sorting from "from"
#define BUCKETS (1 << DIGIT_SIZE)

	 * packfile) quit after two rounds of radix-sorting.
 * get the object sha1 from the main index.

 * size is easily available by examining the pack entry header).  It is
	return -1;
				off_64 += 2;
	/*
	} else {
		 * means we cannot use the more obvious "i >= 0" loop condition
 * and lets us quit the sort early.
			const uint32_t hl = *((uint32_t *)(index + (hashsz + 4) * i));
 */
{
 * is where its packed representation ends and the index_nr can be used to
	int lo = 0;

	return 0;
{
	 * real array and temporary storage. In each iteration of the loop, we
	sort_revindex(p->revindex, num_ent, p->pack_size);
	 * the digit that is N bits from the (least significant) end.
			p->revindex[i].nr = i;


	pos = find_revindex_position(p, ofs);
	ALLOC_ARRAY(tmp, n);
		create_pack_revindex(p);
#define BUCKET_FOR(a, i, bits) (((a)[(i)].offset >> (bits)) & (BUCKETS-1))
 * do not store the size of the compressed representation (uncompressed
		unsigned i;
	return p->revindex + pos;
			return -1;

		 * bucket. We can then cumulatively add the index from the
	 * to "to".

	/*
		 * Now "to" contains the most sorted list, so we swap "from" and
	if (from != entries)

}
			}
	int hi = p->num_objects + 1;
	if (!p->revindex) {
		 * for counting backwards, and must instead check for
				p->revindex[i].offset = get_be64(off_64);
		for (i = n - 1; i != UINT_MAX; i--)
/*
	 * we have to move it back from the temporary storage.
	 * on (and any higher) will be zero for all entries, and our loop will
		return NULL;
int find_revindex_position(struct packed_git *p, off_t ofs)
		 * Now we can drop the elements into their correct buckets (in
	unsigned *pos;
				p->revindex[i].offset = off;
 * The pack index file is sorted by object name mapping to offset;
		/*
		 * Note that we use an unsigned iterator to make sure we can
			p->revindex[i].offset = ntohl(hl);
	index += 4 * 256;
 */
		const uint32_t *off_32 =
	/*
	 */

		if (revindex[mi].offset == ofs) {
		memset(pos, 0, BUCKETS * sizeof(*pos));
		 * handle 2^32-1 objects, even on a 32-bit system. But this
			to[--pos[BUCKET_FOR(from, i, bits)]] = from[i];
		 * wrap-around with UINT_MAX.
}
	 */
		for (i = 0; i < num_ent; i++) {

}

static void sort_revindex(struct revindex_entry *entries, unsigned n, off_t max)
	for (bits = 0; max >> bits; bits += DIGIT_SIZE) {

		const unsigned mi = lo + (hi - lo) / 2;
	const unsigned num_ent = p->num_objects;
	 * If we ended with our data in the original array, great. If not,
{
			return mi;
		 * "to" for the next iteration.

 *
	}
	 */
	 * If (max >> bits) is zero, then we know that the radix digit we are
			(uint32_t *)(index + 8 + p->num_objects * (hashsz + 4));
	from = entries;
		 * our temporary array).  We iterate the pos counter backwards
static void create_pack_revindex(struct packed_git *p)
/*
	 * be a no-op, as everybody lands in the same zero-th bucket.
			if (!(off & 0x80000000)) {
		 * bucket, which gives us a relative offset from the last
	}
	const struct revindex_entry *revindex = p->revindex;
	 * We use a "digit" size of 16 bits. That keeps our memory
	} while (lo < hi);
		/*
	const char *index = p->index_data;
	 * usage reasonable, and we can generally (for a 4G or smaller
			hi = mi;
 * this revindex array is a list of offset/index_nr pairs
		COPY_ARRAY(entries, tmp, n);

	 * We want to know the bucket that a[i] will go into when we are using
	ALLOC_ARRAY(pos, BUCKETS);

			} else {
#include "cache.h"
		 * array itself, to keep the sort stable.
		 * We want pos[i] to store the index of the last element that
	 */
	/*
 * It sorts each of the "n" items in "entries" by its offset field. The "max"
		} else if (ofs < revindex[mi].offset)
			pos[BUCKET_FOR(from, i, bits)]++;
#include "object-store.h"
 */
		 * will go in bucket "i" (actually one past the last element).
#include "packfile.h"
 *
		 * To do this, we first count the items that will go in each
 * Ordered list of offsets of objects in the pack.

/*
		}
{
#define DIGIT_SIZE (16)
	 * We need O(n) temporary storage. Rather than do an extra copy of the
#include "pack-revindex.h"
	}
		 * to avoid using an extra index to count up. And since we are
 * This is a least-significant-digit radix sort.
#undef DIGIT_SIZE

	error("bad offset for revindex");
		}
#undef BUCKET_FOR
	int bits;
	do {
			pos[i] += pos[i-1];
		for (i = 1; i < BUCKETS; i++)
	struct revindex_entry *tmp, *from, *to;
	free(tmp);

}
	 * follows immediately after the last object data.
		 * going backwards there, we must also go backwards through the
		 */
		 * previous bucket to get the true index.
		 *
		for (i = 0; i < n; i++)
	if (p->index_version > 1) {

	if (load_pack_revindex(p))
		SWAP(from, to);
int load_pack_revindex(struct packed_git *p)
