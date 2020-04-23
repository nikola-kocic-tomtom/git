}
	ctx->state[2] = 0x3c6ef372ul;
{

		len -= left;
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,0xb00327c8);
}
	h  = t0 + t1;
	t0 = h + sigma1(e) + ch(e, f, g) + ki + W[i];   \
		W[i] = get_be32(buf);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,0xbf597fc7);
	for (i = 0; i < 16; i++, buf += sizeof(uint32_t))
		blk_SHA256_Transform(ctx, data);
	ctx->state[1] = 0xbb67ae85ul;
	ctx->size = 0;

	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,0x80deb1fe);
			left = len;
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,0x76f988da);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,0x2e1b2138);
void blk_SHA256_Final(unsigned char *digest, blk_SHA256_CTX *ctx)
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,0x5b9cca4f);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,0x766a0abb);
static inline uint32_t sigma1(uint32_t x)
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,0x550c7dc3);
		blk_SHA256_Transform(ctx, ctx->buf);
	padlen[1] = htonl((uint32_t)(ctx->size << 3));
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,0x06ca6351);
	d += t0;                                        \
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,0xa831c66d);
	static const unsigned char pad[64] = { 0x80 };
	/* copy the state into 512-bits into W[0..15] */
		if (len_buf)
#define RND(a,b,c,d,e,f,g,h,i,ki)                    \

		if (len < left)
}
		len_buf = (len_buf + left) & 63;
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],9,0x12835b01);


static inline uint32_t ror(uint32_t x, unsigned n)
	blk_SHA256_Update(ctx, padlen, 8);
	for (i = 0; i < 8; i++, digest += sizeof(uint32_t))
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],2,0xb5c0fbcf);
		W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,0xc24b8b70);
static void blk_SHA256_Transform(blk_SHA256_CTX *ctx, const unsigned char *buf)
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],3,0xe9b5dba5);
	unsigned int padlen[2];
{
#include "./sha256.h"
	uint32_t S[8], W[64], t0, t1;
	ctx->state[6] = 0x1f83d9abul;
	while (len >= 64) {
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,0x72be5d74);
}
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,0xf40e3585);
	ctx->state[3] = 0xa54ff53aul;
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,0x27b70a85);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,0xc76c51a3);

	padlen[0] = htonl((uint32_t)(ctx->size >> 29));
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,0x650a7354);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],8,0xd807aa98);
{

{

	t1 = sigma0(a) + maj(a, b, c);                  \
	return ror(x, 17) ^ ror(x, 19) ^ (x >> 10);
{
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,0x84c87814);
	ctx->state[0] = 0x6a09e667ul;
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,0xa4506ceb);
#define BLKSIZE blk_SHA256_BLKSIZE
		ctx->state[i] += S[i];
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],0,0x428a2f98);
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,0x2748774c);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],5,0x59f111f1);
	i = ctx->size & 63;
{
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,0x243185be);
	ctx->state[4] = 0x510e527ful;
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],4,0x3956c25b);
		unsigned int left = 64 - len_buf;

	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,0x92722c85);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,0x106aa070);


}
{
	/* Read the data into buf and process blocks as they get full */
}
	for (i = 0; i < 8; i++)
{
	/* copy state into S */
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,0x34b0bcb5);
	/* fill W[16..63] */
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,0x682e6ff3);
}
	unsigned int len_buf = ctx->size & 63;
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,0x983e5152);
	if (len_buf) {
	return ror(x, 6) ^ ror(x, 11) ^ ror(x, 25);
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],7,0xab1c5ed5);
	int i;
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,0xc19bf174);
static inline uint32_t gamma0(uint32_t x)
	return ror(x, 2) ^ ror(x, 13) ^ ror(x, 22);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],1,0x71374491);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,0x391c0cb3);

	blk_SHA256_Update(ctx, pad, 1 + (63 & (55 - i)));
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,0x81c2c92e);
		data = ((const char *)data + 64);
	return z ^ (x & (y ^ z));
}
	/* copy output */
	if (len)
	}
}


{
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,0xd192e819);
	/* Pad with a binary 1 (ie 0x80), then zeroes, then length */
		memcpy(ctx->buf, data, len);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,0x748f82ee);
static inline uint32_t sigma0(uint32_t x)
	for (i = 0; i < 8; i++)
		len -= 64;
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,0x14292967);
	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,0xefbe4786);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,0x19a4c116);
}
	ctx->state[7] = 0x5be0cd19ul;
#undef BLKSIZE
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,0xa2bfe8a1);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,0xc6e00bf3);

	ctx->offset = 0;
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,0x8cc70208);
		S[i] = ctx->state[i];
	return ror(x, 7) ^ ror(x, 18) ^ (x >> 3);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,0x5cb0a9dc);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,0xbef9a3f7);
static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
void blk_SHA256_Update(blk_SHA256_CTX *ctx, const void *data, size_t len)

	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,0x78a5636f);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,0x53380d13);
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],6,0x923f82a4);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,0x4a7484aa);
}
#include "git-compat-util.h"

	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,0x4ed8aa4a);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,0x2de92c6f);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,0xd5a79147);
static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z)

	}
		memcpy(len_buf + ctx->buf, data, left);
	ctx->state[5] = 0x9b05688cul;
		put_be32(digest, ctx->state[i]);

			return;
	RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,0xc67178f2);

	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,0xa81a664b);
	int i;

		data = ((const char *)data + left);
	RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,0x90befffa);
	RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,0x240ca1cc);
{
	RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,0x9bdc06a7);
void blk_SHA256_Init(blk_SHA256_CTX *ctx)

	return ((x | y) & z) | (x & y);
	return (x >> n) | (x << (32 - n));
	ctx->size += len;
{
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,0x4d2c6dfc);
	RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,0xd6990624);
	for (i = 16; i < 64; i++)
	RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,0x0fc19dc6);
	RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,0xe49b69c1);
static inline uint32_t gamma1(uint32_t x)
#undef RND



	RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,0x1e376c08);
