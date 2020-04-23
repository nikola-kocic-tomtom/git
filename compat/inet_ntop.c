 * inet_ntop6(src, dst, size)
 */
			best = cur;
inet_ntop(int af, const void *src, char *dst, size_t size)
	/*
				return (NULL);
	    (NS_IN6ADDRSZ / NS_INT16SZ))
		if (i == 6 && best.base == 0 &&
				cur.len++;
		/* Are we inside the best run of 0x00's? */
			*tp++ = ':';
	if (cur.base != -1) {
/*
 *	convert IPv6 binary address into presentation (printable) format
 *	(1) uses no statics
	 */
 * return:
#ifndef NO_IPV6
		return (inet_ntop6(src, dst, size));

{
		    i < (best.base + best.len)) {
		return (NULL);
	}
 * WARNING: Don't even consider trying to compile this on a system where
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * purpose with or without fee is hereby granted, provided that the above
#ifndef NS_INADDRSZ
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
	unsigned int words[NS_IN6ADDRSZ / NS_INT16SZ];
#define NS_INADDRSZ	4
	tp = tmp;
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
	}
const char *
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 */
 *	convert a network format address to presentation format.
 * return:
 */
 *	Paul Vixie, 1996.
#ifndef NO_IPV6
		return (NULL);
	cur.len = 0;

	default:
	switch (af) {
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
	/*
	memset(words, '\0', sizeof words);
			if (i == best.base)
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	return (dst);
				if (best.base == -1 || cur.len > best.len)
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
	int i;
	 * Crays, there is no such thing as an integer variable with 16 bits.
			continue;
	best.len = 0;
 *
	int nprinted;
 * copyright notice and this permission notice appear in all copies.
		} else {
#endif
	*tp++ = '\0';
	 * Preprocess:
		return (NULL);	/* we assume "errno" was set by "snprintf()" */
		if (words[i] == 0) {
 * Permission to use, copy, modify, and distribute this software for any
		best.base = -1;
 * inet_ntop4(src, dst, size)
{
	char tmp[sizeof "255.255.255.255"];
}
	 * Format the result.
 * author:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
	 * Keep this in mind if you think this function should have been coded
/*
	/*
/* char *
 */
		/* Are we following an initial run of 0x00s or any real hex? */
		errno = EAFNOSUPPORT;
 * SOFTWARE.
		}
	/*
 *
			if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
#define NS_INT16SZ	2

	/* Was it a trailing run of 0x00's? */
#include "../git-compat-util.h"
			else
#ifndef NS_INT16SZ
		}
	 * to use pointer overlays.  All the world's not a VAX.

	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
			if (cur.base == -1)
	 * Check for overflow, copy, and we're done.
		if (best.base != -1 && i >= best.base &&
 * notes:
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
#endif
 */
		errno = ENOSPC;
			}
 * author:
	strlcpy(dst, tmp, size);
	 * to contain a value of the specified size.  On some systems, like
				cur.base = i, cur.len = 1;
	 */
	if ((size_t)nprinted >= size) {
	 */
	static const char fmt[] = "%u.%u.%u.%u";
			tp += strlen(tp);
	strlcpy(dst, tmp, size);
/* const char *
#endif

		return (inet_ntop4(src, dst, size));
 *	Paul Vixie, 1996.
	 * Note that int32_t and int16_t need only be "at least" large enough
	struct { int base, len; } best, cur;
#endif
/* const char *
		errno = ENOSPC;
 * author:
				*tp++ = ':';
static const char *
		/* Is this address an encapsulated IPv4? */
	 *	Copy the input (bytewise) array into a wordwise array.
	 */
 *	(2) takes a u_char* not an in_addr as input
	case AF_INET6:
#define NS_IN6ADDRSZ	16
#ifndef NS_IN6ADDRSZ
	cur.base = -1;
					best = cur;
	if (nprinted < 0)
			break;
	}
		}
	if (best.base != -1 && (best.base + best.len) ==

 *	Paul Vixie, 1996.

	}
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
				cur.base = -1;
inet_ntop6(const u_char *src, char *dst, size_t size)
		tp += snprintf(tp, sizeof tmp - (tp - tmp), "%x", words[i]);
 * inet_ntop(af, src, dst, size)
#endif
 *	format an IPv4 address
{
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
	if ((size_t)(tp - tmp) > size) {
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.

	if (best.base != -1 && best.len < 2)
 *	`dst' (as a const)
		if (best.base == -1 || cur.len > best.len)
	}
		*tp++ = ':';
	best.base = -1;
		if (i != 0)
}

static const char *

		return (NULL);
inet_ntop4(const u_char *src, char *dst, size_t size)
	return (dst);
	for (i = 0; i < NS_IN6ADDRSZ; i++)
	case AF_INET:
	}
}
	nprinted = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
			if (cur.base != -1) {
	/* NOTREACHED */
