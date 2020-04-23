#endif
static int
 * author:
                *tp++ = (unsigned char) val & 0xff;
                        if (octets == 4)
 * copyright notice and this permission notice appear in all copies.
                        endp[- i] = colonp[n - i];
        return (1);
        case AF_INET:
                                if (colonp)
        unsigned char tmp[NS_INADDRSZ], *tp;
#endif
        static const char digits[] = "0123456789";
                        val |= (pch - xdigits);
                        val <<= 4;
                        saw_xdigit = 1;
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.

                          xdigits_u[] = "0123456789ABCDEF";
        *(tp = tmp) = 0;
                        colonp[n - i] = 0;
 */
        return (1);
                if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
        memcpy(dst, tmp, NS_INADDRSZ);
                if ((pch = strchr(digits, ch)) != NULL) {
 *      1 if `src' is a valid [RFC1884 2.2] address, else 0.
                                        return (0);
                                return (0);
        if (*src == ':')
        const char *xdigits, *curtok;
        }
 *      Paul Vixie, 1996.
 *      like inet_aton() but without all the hexadecimal and shorthand.

                if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
        switch (af) {
 * return:
        curtok = src;
inet_pton6(const char *src, unsigned char *dst)
                for (i = 1; i <= n; i++) {
 */
 *
                if (*++src != ':')

                        curtok = src;
        saw_xdigit = 0;
 * notice:
                        unsigned int new = *tp * 10 + (pch - digits);
                return (0);
                if (pch != NULL) {

                                return (0);
                        *tp++ = (unsigned char) val & 0xff;

 *      convert presentation level address to network order binary form.
                                if (++octets > 4)
        saw_digit = 0;
                        continue;
                int i;
 * purpose with or without fee is hereby granted, provided that the above
 * author:
                const char *pch;
                        return (0);
 * WARNING: Don't even consider trying to compile this on a system where


                *tp++ = (unsigned char) (val >> 8) & 0xff;
                const int n = tp - colonp;
        if (colonp != NULL) {
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING

 *      (1) does not touch `dst' unless it's returning 1.
                        }
                tp = endp;
#ifndef NO_IPV6
        octets = 0;
        }
}
#define NS_INT16SZ       2
}
 * return:
                if (ch == ':') {
                                        return (0);
#ifndef NO_IPV6
                return (inet_pton4(src, dst));
 *      -1 if some other error occurred (`dst' is untouched in this case, too)
{


                        *++tp = 0;
#ifndef NO_IPV6
                                colonp = tp;

        }
                                continue;
        if (tp != endp)
 * isc_net_pton(af, src, dst)

        default:
 *      (2) :: in a full address is silently ignored.
        unsigned char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
/* int
#ifndef NS_IN6ADDRSZ
                if (tp + NS_INT16SZ > endp)
/*
        int ch, saw_xdigit;
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
        /* NOTREACHED */
                }
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
inet_pton4(const char *src, unsigned char *dst)
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
                        }
                        return (0);
#ifndef NS_INT16SZ
 */
                return (inet_pton6(src, dst));
        unsigned int val;
                                saw_digit = 1;
        memcpy(dst, tmp, NS_IN6ADDRSZ);

 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
                        pch = strchr((xdigits = xdigits_u), ch);
#include "../git-compat-util.h"
 * author:
#endif

                        *tp++ = (unsigned char) (val >> 8) & 0xff;
        static const char xdigits_l[] = "0123456789abcdef",
 *      does not touch `dst' unless it's returning 1.
                errno = EAFNOSUPPORT;
                }
                                return (0);
                        if (val > 0xffff)
                        val = 0;
 *      inspired by Mark Andrews.
#ifndef NS_INADDRSZ
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 *      to network format (which is usually some kind of binary format).

 *      1 if the address was valid for the specified address family
 *      convert from presentation format (which usually means ASCII printable)
/* int
#endif
 *      Paul Vixie, 1996.
                return (-1);
/* int
#endif
        case AF_INET6:
                 * overlapping regions, we'll do the shift by hand.
int
                        break;  /* '\0' was seen by inet_pton4(). */
 *
                        continue;
                                return (0);
{
#define NS_IN6ADDRSZ    16
        }
        }
 * inet_pton6(src, dst)

        if (saw_xdigit) {
        if (octets < 4)
                return (0);
inet_pton(int af, const char *src, void *dst)
                        if (!saw_xdigit) {
                } else
 */
        int saw_digit, octets, ch;
        while ((ch = *src++) != '\0') {
#define NS_INADDRSZ      4
#endif
}
                        if (! saw_digit) {
 * credit:
                return (0);
                } else if (ch == '.' && saw_digit) {
        colonp = NULL;
                    inet_pton4(curtok, tp) > 0) {
 * Copyright (C) 1996-2001  Internet Software Consortium.
                        saw_digit = 0;
 * return:
static int inet_pton6(const char *src, unsigned char *dst);
                        if (tp + NS_INT16SZ > endp)
 *      1 if `src' is a valid dotted quad, else 0.
                        tp += NS_INADDRSZ;
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
                const char *pch;
static int
 *      Paul Vixie, 1996.
                        saw_xdigit = 0;
                        saw_xdigit = 0;
static int inet_pton4(const char *src, unsigned char *dst);
                /*
 * notice:
        endp = tp + NS_IN6ADDRSZ;
        while ((ch = *src++) != '\0') {
                        return (0);
 */
                 */
        val = 0;
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
        memset((tp = tmp), '\0', NS_IN6ADDRSZ);
                }
/*
 * Permission to use, copy, modify, and distribute this software for any
                        if (new > 255)
                }
 *      0 if the address wasn't valid (`dst' is untouched in this case)
                 * Since some memmove()'s erroneously fail to handle
 * inet_pton4(src, dst)
                        *tp = new;
{
        /* Leading :: requires some special handling. */
