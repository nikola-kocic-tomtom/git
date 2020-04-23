void git_SHA1DCFinal(unsigned char hash[20], SHA1_CTX *ctx)
 * Same as SHA1DCInit, but with default save_hash=0
	SHA1DCUpdate(ctx, data, len);
	const char *data = vdata;
	}
void git_SHA1DCInit(SHA1_CTX *ctx)
	if (!SHA1DCFinal(hash, ctx))

void git_SHA1DCUpdate(SHA1_CTX *ctx, const void *vdata, unsigned long len)
 */
	die("SHA-1 appears to be part of a collision attack: %s",
/*
{
		len -= INT_MAX;
#ifdef DC_SHA1_EXTERNAL
 * Same as SHA1DCFinal, but convert collision attack case into a verbose die().
}
	while (len > INT_MAX) {
 */
	/* We expect an unsigned long, but sha1dc only takes an int */
#endif
}
		return;
}
		SHA1DCUpdate(ctx, data, INT_MAX);

	SHA1DCInit(ctx);
 * Same as SHA1DCUpdate, but adjust types to match git's usual interface.
/*
{
	SHA1DCSetSafeHash(ctx, 0);
#include "cache.h"
{
	    hash_to_hex_algop(hash, &hash_algos[GIT_HASH_SHA1]));

/*
 */
		data += INT_MAX;
