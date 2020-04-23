
		}
	memcpy(b, t, (n - n2) * s);
/*
			b1 += s;

	b1 = b;
int git_qsort_s(void *b, size_t n, size_t s,
			   int (*cmp)(const void *, const void *, void *),
{
			tmp += s;
 * by Mike Haertel, which is a part of the GNU C Library.
			tmp += s;
	size_t n1, n2;
{

	b2 = (char *)b + (n1 * s);
		/* It's somewhat large, so malloc it.  */
		/* The temporary array fits on the small on-stack buffer. */
	char *b1, *b2;
#include "../git-compat-util.h"
	tmp = t;
		if (cmp(b1, b2, ctx) <= 0) {
		msort_with_tmp(b, n, s, cmp, buf, ctx);
		memcpy(tmp, b1, n1 * s);
	char buf[1024];
	n1 = n / 2;
 */
		int (*cmp)(const void *, const void *, void *), void *ctx)
		free(tmp);
	if (!b || !cmp)
	if (n1 > 0)


		return -1;

	}
}
			--n2;
static void msort_with_tmp(void *b, size_t n, size_t s,

			memcpy(tmp, b1, s);
	while (n1 > 0 && n2 > 0) {
	if (n <= 1)
	const size_t size = st_mult(n, s);
			b2 += s;

 * A merge sort implementation, simplified from the qsort implementation
		char *tmp = xmalloc(size);
			   char *t, void *ctx)
	}
	msort_with_tmp(b2, n2, s, cmp, t, ctx);
		} else {
			--n1;
		msort_with_tmp(b, n, s, cmp, tmp, ctx);
	} else {
	if (!n)
	if (size < sizeof(buf)) {
	msort_with_tmp(b1, n1, s, cmp, t, ctx);
		return 0;
 * Added context pointer, safety checks and return value.
	return 0;

	char *tmp;
	n2 = n - n1;
			memcpy(tmp, b2, s);
		return;
}

