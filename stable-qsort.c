		}
	} else {
/*
	while (n1 > 0 && n2 > 0) {
	msort_with_tmp(b2, n2, s, cmp, t);
		return;
		free(tmp);
	}
			--n2;
	n1 = n / 2;
			b1 += s;
			   char *t)
	msort_with_tmp(b1, n1, s, cmp, t);

			--n1;

			tmp += s;
	char buf[1024];
	if (size < sizeof(buf)) {
	if (n <= 1)
void git_stable_qsort(void *b, size_t n, size_t s,
{
	b1 = b;
	b2 = (char *)b + (n1 * s);
}

	n2 = n - n1;
	if (n1 > 0)
	memcpy(b, t, (n - n2) * s);

	const size_t size = st_mult(n, s);
		/* It's somewhat large, so malloc it.  */
		msort_with_tmp(b, n, s, cmp, buf);
		char *tmp = xmalloc(size);


		if (cmp(b1, b2) <= 0) {
	tmp = t;
			   int (*cmp)(const void *, const void *),
		/* The temporary array fits on the small on-stack buffer. */

 * A merge sort implementation, simplified from the qsort implementation
 */
			tmp += s;
 * by Mike Haertel, which is a part of the GNU C Library.
	size_t n1, n2;
			memcpy(tmp, b2, s);
			memcpy(tmp, b1, s);
		} else {
		      int (*cmp)(const void *, const void *))
{

		memcpy(tmp, b1, n1 * s);
static void msort_with_tmp(void *b, size_t n, size_t s,
			b2 += s;
	}
	char *b1, *b2;
#include "git-compat-util.h"
}
	char *tmp;

		msort_with_tmp(b, n, s, cmp, tmp);
