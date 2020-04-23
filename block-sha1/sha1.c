		blk_SHA1_Block(ctx, data);
 * none of the original Mozilla code remains.
	T_20_39(21, E, A, B, C, D);
 * 'volatile', since there are lots of registers).
	T_20_39(25, A, B, C, D, E);
	T_60_79(79, B, C, D, E, A);
 * So to avoid that mess which just slows things down, we force
	T_20_39(34, B, C, D, E, A);
	T_60_79(70, A, B, C, D, E);
/*

	B = SHA_ROR(B, 2); } while (0)

	T_0_15( 4, B, C, D, E, A);

	T_40_59(42, D, E, A, B, C);
	T_40_59(58, C, D, E, A, B);
	T_40_59(41, E, A, B, C, D);

	int i;
	T_0_15( 9, B, C, D, E, A);
	T_0_15( 5, A, B, C, D, E);
#include "sha1.h"
		if (len < left)
/*
	T_16_19(19, B, C, D, E, A);
	T_40_59(57, D, E, A, B, C);
	ctx->H[0] = 0x67452301;
	/* Output hash */
		unsigned int left = 64 - lenW;
			return;

#define SHA_SRC(t) get_be32((unsigned char *) block + (t)*4)
	T_40_59(49, B, C, D, E, A);
	T_20_39(33, C, D, E, A, B);
 * perhaps more importantly it's possibly faster on any uarch that does a
}
	T_20_39(32, D, E, A, B, C);
	T_40_59(47, D, E, A, B, C);
	T_40_59(52, D, E, A, B, C);
	T_60_79(64, B, C, D, E, A);
	T_40_59(48, C, D, E, A, B);

		memcpy(ctx->W, data, len);
{
 * and at least gcc will make an unholy mess of it.
 * see what the value will be).
	T_40_59(55, A, B, C, D, E);
 * Force usage of rol or ror by selecting the one with the smaller constant.
	T_20_39(29, B, C, D, E, A);
  #define setW(x, val) (W(x) = (val))
 * SHA1 routine optimized to do word accesses rather than byte accesses,
	T_20_39(22, D, E, A, B, C);
	T_16_19(17, D, E, A, B, C);
	ctx->H[1] = 0xefcdab89;
	unsigned int padlen[2];
 * the input data, the next mix it from the 512-bit array.
	T_60_79(61, E, A, B, C, D);


#if defined(__i386__) || defined(__x86_64__)

}
#define SHA_ROL(X,n)	SHA_ROT(X,n,32-(n))
	ctx->H[4] = 0xc3d2e1f0;
	i = ctx->size & 63;
	if (len)
	T_16_19(18, C, D, E, A, B);
	T_40_59(40, A, B, C, D, E);

	T_0_15(11, E, A, B, C, D);
	T_60_79(71, E, A, B, C, D);
	T_0_15( 8, C, D, E, A, B);
	T_60_79(69, B, C, D, E, A);

	T_0_15(15, A, B, C, D, E);
/* this is only to get definitions for memcpy(), ntohl() and htonl() */
	T_0_15( 7, D, E, A, B, C);

	/* Round 1 - tail. Input from 512-bit mixing array */
	T_0_15(14, B, C, D, E, A);
	T_20_39(39, B, C, D, E, A);
	T_60_79(60, A, B, C, D, E);
		data = ((const char *)data + 64);
	ctx->size = 0;

	T_20_39(31, E, A, B, C, D);
void blk_SHA1_Final(unsigned char hashout[20], blk_SHA_CTX *ctx)
	T_60_79(68, C, D, E, A, B);
	A = ctx->H[0];

	C = ctx->H[2];

	T_20_39(27, D, E, A, B, C);
	T_40_59(50, A, B, C, D, E);
#define T_60_79(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (B^C^D) ,  0xca62c1d6, A, B, C, D, E )
 * between each SHA_ROUND, otherwise gcc happily get wild with spilling and

	ctx->size += len;
/*
	ctx->H[3] = 0x10325476;
 * machines with less than ~25 registers, that won't really work,
	T_40_59(51, E, A, B, C, D);

 *
#define T_16_19(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (((C^D)&B)^D) , 0x5a827999, A, B, C, D, E )
#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
{
}
 * to the optimized asm with this (ie on PPC you don't want that
#define SHA_ROL(x,n)	SHA_ASM("rol", x, n)
#else
	T_40_59(56, E, A, B, C, D);
	E = ctx->H[4];
/*
#define SHA_ROR(X,n)	SHA_ROT(X,32-(n),n)

	unsigned int TEMP = input(t); setW(t, TEMP); \
	T_0_15( 3, C, D, E, A, B);
	}
 *
 */
 * try to change the array[] accesses into registers. However, on
 * suggested by Artur Skawina - that will also make gcc unable to
	T_60_79(63, C, D, E, A, B);
	for (i = 0; i < 5; i++)
#define T_20_39(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, (B^C^D) , 0x6ed9eba1, A, B, C, D, E )
	/* Round 1 - iterations 0-16 take their input from 'block' */
	unsigned int lenW = ctx->size & 63;
	T_20_39(30, A, B, C, D, E);
 * try to do the silly "optimize away loads" part because it won't
  #define setW(x, val) do { W(x) = (val); __asm__("":::"memory"); } while (0)

		lenW = (lenW + left) & 63;
	D = ctx->H[3];
	T_60_79(66, E, A, B, C, D);
/* This "rolls" over the 512-bit array */
		if (lenW)
	T_60_79(76, E, A, B, C, D);

	T_40_59(46, E, A, B, C, D);
	padlen[0] = htonl((uint32_t)(ctx->size >> 29));

	/* Round 4 */
	T_40_59(44, B, C, D, E, A);
	T_0_15( 1, E, A, B, C, D);
	T_0_15(10, A, B, C, D, E);
	ctx->H[0] += A;
	T_40_59(45, A, B, C, D, E);
	T_60_79(62, D, E, A, B, C);
static void blk_SHA1_Block(blk_SHA_CTX *ctx, const void *block)
	T_60_79(73, C, D, E, A, B);
	/* Round 3 */
	T_0_15( 2, D, E, A, B, C);

#endif

		data = ((const char *)data + left);

void blk_SHA1_Update(blk_SHA_CTX *ctx, const void *data, unsigned long len)
	T_20_39(35, A, B, C, D, E);
	T_0_15( 6, E, A, B, C, D);
	T_60_79(74, B, C, D, E, A);
 * It _can_ generate slightly smaller code (a constant of 1 is special), but
	static const unsigned char pad[64] = { 0x80 };
	unsigned int array[16];
		memcpy(lenW + (char *)ctx->W, data, left);
 * Ben Herrenschmidt reports that on PPC, the C version comes close
 */
	if (lenW) {
 * Where do we get the source from? The first 16 iterations get it from
	T_16_19(16, E, A, B, C, D);
#define SHA_ROUND(t, input, fn, constant, A, B, C, D, E) do { \
 *
	/* Round 2 */
		len -= left;
	T_40_59(53, C, D, E, A, B);
 * the stack frame size simply explode and performance goes down the drain.
	T_20_39(28, C, D, E, A, B);
	T_60_79(77, D, E, A, B, C);
#define T_40_59(t, A, B, C, D, E) SHA_ROUND(t, SHA_MIX, ((B&C)+(D&(B^C))) , 0x8f1bbcdc, A, B, C, D, E )
	T_60_79(75, A, B, C, D, E);
	padlen[1] = htonl((uint32_t)(ctx->size << 3));

			left = len;
	/* Read the data into W and process blocks as they get full */
	unsigned int A,B,C,D,E;
	ctx->H[3] += D;
	T_0_15(12, D, E, A, B, C);
		len -= 64;
	T_40_59(59, B, C, D, E, A);
		blk_SHA1_Block(ctx, ctx->W);

	T_60_79(72, D, E, A, B, C);

		put_be32(hashout + i * 4, ctx->H[i]);
  #define setW(x, val) (*(volatile unsigned int *)&W(x) = (val))
#define SHA_ASM(op, x, n) ({ unsigned int __res; __asm__(op " %1,%0":"=r" (__res):"i" (n), "0" (x)); __res; })
	ctx->H[4] += E;
#define T_0_15(t, A, B, C, D, E)  SHA_ROUND(t, SHA_SRC, (((C^D)&B)^D) , 0x5a827999, A, B, C, D, E )
	ctx->H[1] += B;
	T_0_15(13, C, D, E, A, B);
	T_20_39(36, E, A, B, C, D);
	T_20_39(37, D, E, A, B, C);
	T_20_39(23, C, D, E, A, B);
	}
 * This was initially based on the Mozilla SHA1 implementation, although

	B = ctx->H[1];
{
	T_60_79(78, C, D, E, A, B);
	T_20_39(24, B, C, D, E, A);
	blk_SHA1_Update(ctx, padlen, 8);
#define W(x) (array[(x)&15])
 */
#elif defined(__GNUC__) && defined(__arm__)
	ctx->H[2] = 0x98badcfe;
	T_20_39(38, C, D, E, A, B);
 * and to avoid unnecessary copies into the context array.
 * If you have 32 registers or more, the compiler can (and should)
	blk_SHA1_Update(ctx, pad, 1 + (63 & (55 - i)));
	T_60_79(65, A, B, C, D, E);
#else
	T_60_79(67, D, E, A, B, C);
#define SHA_MIX(t) SHA_ROL(W((t)+13) ^ W((t)+8) ^ W((t)+2) ^ W(t), 1);
#include "../git-compat-util.h"
#define SHA_ROT(X,l,r)	(((X) << (l)) | ((X) >> (r)))
	T_0_15( 0, A, B, C, D, E);
 * the stores to memory to actually happen (we might be better off
	while (len >= 64) {
	T_40_59(43, C, D, E, A, B);
{
void blk_SHA1_Init(blk_SHA_CTX *ctx)

 * rotate with a loop.
	T_40_59(54, B, C, D, E, A);
 * On ARM we get the best code generation by forcing a full memory barrier
	E += TEMP + SHA_ROL(A,5) + (fn) + (constant); \
#define SHA_ROR(x,n)	SHA_ASM("ror", x, n)
#endif
	/* Pad with a binary 1 (ie 0x80), then zeroes, then length */
	T_20_39(20, A, B, C, D, E);
	ctx->H[2] += C;
 *

	/* Initialize H with the magic constants (see FIPS180 for constants) */

	T_20_39(26, E, A, B, C, D);
 */
}
 * with a 'W(t)=(val);asm("":"+m" (W(t))' there instead, as
