			if (nb > n)
			memset(&c->buf.b[cnt], 0, 64 - cnt);
	c->hash[2] = 0x98BADCFE;
}
		n -= nb;

			}
			nb = n >> 6;
		   unsigned int nblocks);
 */
	c->hash[4] = 0xC3D2E1F0;

{
#include <string.h>
		cnt = 0;
{
		if (cnt < 64)
	if (cnt > 56) {
	}
		if (c->cnt || n < 64) {
}

}
				c->cnt = 0;
			ppc_sha1_core(c->hash, p, nb);
	while (n != 0) {

	ppc_sha1_core(c->hash, c->buf.b, 1);
	}
			nb = 64 - c->cnt;
		}
		p += nb;
 * It calls an external sha1_core() to process blocks of 64 bytes.
int ppc_SHA1_Init(ppc_SHA_CTX *c)

	return 0;
 *
int ppc_SHA1_Update(ppc_SHA_CTX *c, const void *ptr, unsigned long n)
void ppc_sha1_core(uint32_t *hash, const unsigned char *p,

	const unsigned char *p = ptr;
				ppc_sha1_core(c->hash, c->buf.b, 1);
 * SHA-1 implementation.
 * Copyright (C) 2005 Paul Mackerras <paulus@samba.org>
	c->buf.b[cnt++] = 0x80;
			nb <<= 6;
				nb = n;
			if ((c->cnt += nb) == 64) {
	c->hash[0] = 0x67452301;
		} else {
	c->len += (uint64_t) n << 3;
 *
		ppc_sha1_core(c->hash, c->buf.b, 1);
	return 0;
/*
#include <stdio.h>
	unsigned int cnt = c->cnt;
	c->buf.l[7] = c->len;
int ppc_SHA1_Final(unsigned char *hash, ppc_SHA_CTX *c)
			memcpy(&c->buf.b[c->cnt], p, nb);
	if (cnt < 56)
	c->hash[1] = 0xEFCDAB89;
	c->hash[3] = 0x10325476;
		memset(&c->buf.b[cnt], 0, 56 - cnt);
	unsigned long nb;
{
	return 0;
	c->len = 0;
	memcpy(hash, c->hash, 20);
 * This version assumes we are running on a big-endian machine.
#include "sha1.h"
	c->cnt = 0;
