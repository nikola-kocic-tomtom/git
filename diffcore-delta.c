 */
		s++;
	return new_spanhash;
 * size under the current 2<<17 maximum, which can hold this many
			   unsigned long *literal_added)
	int bucket, lim;
		}
 * We are doing an approximation so we do not really have to waste

			d++;
/*
	if (!src_count) {
		accum1 += c;
		int bucket;
	n = 0;
	new_spanhash = xmalloc(st_add(sizeof(*orig),
	hash = xmalloc(st_add(sizeof(*hash),
		d++;
			if (d->hashval >= s->hashval)

		return -1;
				return spanhash_rehash(top);
	struct spanhash *h;

		}
		if (!s->cnt)

 * HASHBASE < INITIAL_FREE(17).  We want to keep the maximum hashtable
	QSORT(hash->data, 1ul << hash->alloc_log2, spanhash_cmp);
		la += d->cnt;

			   void **dst_count_p,
{
			*dst_count_p = dst_count;
			h->cnt = cnt;
		if (lim <= bucket)
			   struct diff_filespec *dst,
					 unsigned int hashval, int cnt)
	while (1) {
		}
			if (top->free < 0)
			h->cnt += cnt;
		bucket = o->hashval & (sz - 1);
 * to deal with binary data.  So we cut them into chunks delimited by

	return 0;
 * memory by actually storing the sequence.  We just hash them into
		if (is_text && c == '\r' && sz && *buf == '\n')
			continue;
	}
	return hash;
		src_count = *src_count_p;
		}
				       struct diff_filespec *one)
	memset(new_spanhash->data, 0, sizeof(struct spanhash) * sz);
			      st_mult(sizeof(struct spanhash), 1<<i)));
	const struct spanhash *a = a_;
	struct spanhash *s, *d;
	}
		src_cnt = s->cnt;
			}
	for (i = 0; i < osz; i++) {
			continue;
		return !b->cnt ? 0 : 1;
			return top;
/* A prime rather carefully chosen between 2^16..2^17, so that
	}
}
	s = src_count->data;
		unsigned dst_cnt, src_cnt;
	int i;
		if (d->cnt && d->hashval == s->hashval) {

		while (d->cnt) {
 * and destination added more.
	}
			return top;
	bucket = hashval & (lim - 1);
			if (sz <= bucket)
 * Almost all data we are interested in are text, but sometimes we have

		/* Ignore CR in CRLF sequence if text */

	accum1 = accum2 = 0;
}
struct spanhash_top {
		if (!h->cnt) {
				h->cnt = o->cnt;

	unsigned int hashval;

#include "cache.h"
		if (++n < 64 && c != '\n')
 */
#define INITIAL_FREE(sz_log2) ((1<<(sz_log2))*(sz_log2-3)/(sz_log2))
				break;
	hash->alloc_log2 = i;
 * somewhere around 2^16 hashbuckets and count the occurrences.
	sc = la = 0;
			break; /* we checked all in src */
				new_spanhash->free--;
		else
	const struct spanhash *b = b_;
		a->hashval > b->hashval ? 1 : 0;
static struct spanhash_top *add_spanhash(struct spanhash_top *top,
	if (!a->cnt)
	d = dst_count->data;
			struct spanhash *h = &(new_spanhash->data[bucket++]);
	free(orig);
 * destination.  If the destination has more, everything was copied,
	int free;
	if (!dst_count) {
#include "diff.h"
 * LF byte, or 64-byte sequence, whichever comes first, and hash them.
		dst_count = hash_chars(r, dst);
				break;

 *
		if (dst_count_p)
			   struct diff_filespec *src,
{

		n = 0;
		free(src_count);
		if (h->hashval == hashval) {
	int sz = osz << 1;
	if (!b->cnt)
	return a->hashval < b->hashval ? -1 :
 * counts are the same, everything was copied from source to
};
			dst_cnt = d->cnt;
		hashval = (accum1 + accum2 * 0x61) % HASHBASE;
		if (src_count_p)
#include "diffcore.h"
			d++;
	unsigned int cnt;
		}
		accum1 = accum2 = 0;
	struct spanhash_top *hash;
		accum1 = (accum1 << 7) ^ (accum2 >> 25);
/* We leave more room in smaller hash but do not let it
	struct spanhash data[FLEX_ARRAY];
}
			top->free--;
	int osz = 1 << orig->alloc_log2;
int diffcore_count_changes(struct repository *r,
		struct spanhash *o = &(orig->data[i]);
			bucket = 0;
	unsigned int accum1, accum2, hashval;
#define HASHBASE 107927
		dst_cnt = 0;
		unsigned int old_1 = accum1;
{
	int alloc_log2;
 * Idea here is very simple.
	if (!src_count_p)
	for (;;) {
}
	hash->free = INITIAL_FREE(i);
				bucket = 0;
static struct spanhash_top *spanhash_rehash(struct spanhash_top *orig)
 *
	}
			   unsigned long *src_copied,

			continue;
		if (src_cnt < dst_cnt) {
struct spanhash {
		dst_count = *dst_count_p;
static struct spanhash_top *hash_chars(struct repository *r,
 * grow to have unused hole too much.
			sc += dst_cnt;
	unsigned int sz = one->size;
{
 *
};
		}

	if (dst_count_p)
			if (!h->cnt) {
 * different values before overflowing to hashtable of size 2<<18.
		sz--;

	int i, n;
	new_spanhash->free = INITIAL_FREE(new_spanhash->alloc_log2);
		accum2 = (accum2 << 7) ^ (old_1 >> 25);
	while (sz) {
	lim = (1 << top->alloc_log2);

	memset(hash->data, 0, sizeof(struct spanhash) * (1<<i));
/* Wild guess at the initial hash size */
				h->hashval = o->hashval;
 * than the destination buffer, that means the difference are the
		free(dst_count);
 */
		h = &(top->data[bucket++]);
	i = INITIAL_HASH_SIZE;
#define INITIAL_HASH_SIZE 9

	}
 * For those chunks, if the source buffer has more instances of it
		hash = add_spanhash(hash, hashval, n);
	struct spanhash_top *new_spanhash;
			*src_count_p = src_count;

 * number of bytes not copied from source to destination.  If the
			h->hashval = hashval;
			la += d->cnt;
	}
		src_count = hash_chars(r, src);
	while (d->cnt) {
			la += dst_cnt - src_cnt;
		if (!o->cnt)
static int spanhash_cmp(const void *a_, const void *b_)
{
	*literal_added = la;
	if (src_count_p)
}
			     st_mult(sizeof(struct spanhash), sz)));
	/* A count of zero compares at the end.. */
	int is_text = !diff_filespec_is_binary(r, one);
	if (!dst_count_p)
	unsigned long sc, la;
	src_count = dst_count = NULL;
	struct spanhash_top *src_count, *dst_count;

	unsigned char *buf = one->data;
			   void **src_count_p,
		unsigned int c = *buf++;
			sc += src_cnt;
	*src_copied = sc;
		while (1) {
	new_spanhash->alloc_log2 = orig->alloc_log2 + 1;
