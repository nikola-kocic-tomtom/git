	SHA1_STORE_STATE(76)
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(b, c, d, e, a, m, W, 4, temp);

	SHA1_STORE_STATE(3)
#ifdef DOSTORESTATE4
#endif
#define HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(a, b, c, d, e, m, t) \

	SHA1COMPRESS_FULL_ROUND4_STEP(e, a, b, c, d, W, 66, temp);
/*
#endif
	SHA1_STORE_STATE(15)
#ifdef DOSTORESTATE71
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, W, 56);
	SHA1COMPRESS_FULL_ROUND3_STEP(a, b, c, d, e, W, 40, temp);
		sha1_process(ctx, (uint32_t*)(ctx->buffer));
	if (t > 42) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(d, e, a, b, c, me2, 42); \
#pragma warning(pop)
	if (t <= 72) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, me2, 72); \
#ifdef DOSTORESTATE2
	case 69:

	if (t > 30) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(a, b, c, d, e, me2, 30); \
	{

SHA1_RECOMPRESS(6)
	case 36:
	if (t <= 50) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, me2, 50); \
#ifdef DOSTORESTATE49
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, W, 20);
	SHA1COMPRESS_FULL_ROUND2_STEP(e, a, b, c, d, W, 31, temp);
	case 7:
#ifdef DOSTORESTATE11
#endif
	uint32_t a,b,c,d,e;
#endif
#ifdef DOSTORESTATE69
#endif
static void sha1_recompression_step(uint32_t step, uint32_t ihvin[5], uint32_t ihvout[5], const uint32_t me2[80], const uint32_t state[5])
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, W, 67);
#endif

	SHA1_STORE_STATE(56)
#define sha1_mix(W, t)  (rotate_left(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1))
	SHA1COMPRESS_FULL_ROUND4_STEP(a, b, c, d, e, W, 65, temp);

	ctx->total = 0;

	case 38:
#ifdef DOSTORESTATE18
			{
		break;
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(d, e, a, b, c, m, W, 7, temp);

	case 30:
#ifdef DOSTORESTATE10
* See accompanying file LICENSE.txt or copy at
#ifdef DOSTORESTATE61
						ctx->m2[j] = ctx->m1[j] ^ sha1_dvs[i].dm[j];
#endif
#ifdef DOSTORESTATE30
#ifdef SHA1DC_CUSTOM_TRAILING_INCLUDE_SHA1_C
#ifdef BUILDNOCOLLDETECTSHA1COMPRESSION
	if (t > 24) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(b, c, d, e, a, me2, 24); \
#ifdef SHA1DC_CUSTOM_INCLUDE_SHA1_C
#ifdef DOSTORESTATE8
#include SHA1DC_CUSTOM_INCLUDE_SHA1_C
		break;
#ifdef DOSTORESTATE56
#include <string.h>


SHA1_RECOMPRESS(1)
	SHA1_STORE_STATE(17)
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, W, 43);
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, W, 11);

#ifdef DOSTORESTATE25

{
#endif
		break;
		ctx->total += 64;
#ifdef DOSTORESTATE2
	if (t > 18) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(c, d, e, a, b, me2, 18); \
		sha1recompress_fast_40(ihvin, ihvout, me2, state);
		break;
	ctx->reduced_round_coll = 0;
		break;
	if (t > 22) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(d, e, a, b, c, me2, 22); \
	SHA1_STORE_STATE(10)
	SHA1COMPRESS_FULL_ROUND4_STEP(d, e, a, b, c, W, 77, temp);
SHA1_RECOMPRESS(78)
		sha1recompress_fast_9(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, W, 62);
#ifdef DOSTORESTATE52
	SHA1COMPRESS_FULL_ROUND4_STEP(e, a, b, c, d, W, 76, temp);
{
#define SHA1COMPRESS_FULL_ROUND3_STEP(a, b, c, d, e, W, t, temp) \
#endif

		sha1recompress_fast_79(ihvin, ihvout, me2, state);
 * http://www.oracle.com/technetwork/server-storage/solaris/portingtosolaris-138514.html
		sha1recompress_fast_11(ihvin, ihvout, me2, state);
					/* to verify SHA-1 collision detection code with collisions for reduced-step SHA-1 */
#endif
	if (t <= 29) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, me2, 29); \
	SHA1_STORE_STATE(54)
#ifdef DOSTORESTATE23
	if (t > 26) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(e, a, b, c, d, me2, 26); \
	SHA1_STORE_STATE(44)
#ifdef DOSTORESTATE78
#pragma warning(disable: 4127)  /* Compiler complains about the checks in the above macro being constant. */
	case 74:
#endif
	uint64_t total;
	SHA1_STORE_STATE(37)
	SHA1COMPRESS_FULL_ROUND2_STEP(a, b, c, d, e, W, 25, temp);
	case 51:
	ihvout[0] = ihvin[0] + a; ihvout[1] = ihvin[1] + b; ihvout[2] = ihvin[2] + c; ihvout[3] = ihvin[3] + d; ihvout[4] = ihvin[4] + e; \

	output[8] = (unsigned char)(ctx->ihv[2] >> 24);
	case 78:
#include <memory.h>
#ifdef DOSTORESTATE26


	if (t > 31) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(e, a, b, c, d, me2, 31); \
SHA1_RECOMPRESS(14)
	case 71:
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

	SHA1COMPRESS_FULL_ROUND3_STEP(d, e, a, b, c, W, 57, temp);
	{temp = sha1_mix(W, t); sha1_store(W, t, temp); e += temp + rotate_left(a, 5) + sha1_f2(b,c,d) + 0x6ED9EBA1; b = rotate_left(b, 30); }
#ifdef DOSTORESTATE79
	if (t > 60) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(a, b, c, d, e, me2, 60); \
	SHA1_STORE_STATE(39)

	ctx->ihv1[3] = ctx->ihv[3];
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, W, 13);
	SHA1COMPRESS_FULL_ROUND3_STEP(e, a, b, c, d, W, 51, temp);

	SHA1COMPRESS_FULL_ROUND3_STEP(e, a, b, c, d, W, 56, temp);

	case 1:
	case 29:
		break;
 * brought in by standard headers. See glibc.git and
#endif
		break;
		break;
 * the defined(_BIG_ENDIAN) && defined(_LITTLE_ENDIAN) part prevents
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, W, 14);
SHA1_RECOMPRESS(24)
	if (t > 12) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(d, e, a, b, c, me2, 12); \
#endif
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, W, 54);

#endif
	SHA1COMPRESS_FULL_ROUND3_STEP(b, c, d, e, a, W, 44, temp);
/* Not under GCC-alike or glibc or *BSD or newlib */
#endif
	case 79:

	SHA1COMPRESS_FULL_ROUND2_STEP(c, d, e, a, b, W, 33, temp);
#ifdef DOSTORESTATE33
		sha1recompress_fast_78(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, W, 44);
#ifdef DOSTORESTATE24

#endif
	if (t <= 20) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, me2, 20); \
SHA1_RECOMPRESS(65)
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, W, 15);
	if (t > 48) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(c, d, e, a, b, me2, 48); \

#ifdef DOSTORESTATE28
SHA1_RECOMPRESS(76)
SHA1_RECOMPRESS(45)
	SHA1COMPRESS_FULL_ROUND2_STEP(c, d, e, a, b, W, 23, temp);
		sha1recompress_fast_32(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, W, 69);
	if (t <= 21) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, me2, 21); \
#ifdef DOSTORESTATE51
	SHA1COMPRESS_FULL_ROUND2_STEP(a, b, c, d, e, W, 35, temp);
SHA1_RECOMPRESS(41)
		break;

#ifdef SHA1DC_BIGENDIAN
		memcpy(ctx->buffer + left, buf, len);

#endif
#define SHA1DC_BIGENDIAN
	}
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, W, 10);
/* Not under GCC-alike */
		break;
#else
 * Defines Big Endian on a whitelist of OSs that are known to be Big
#endif
#endif
	ctx->safe_hash = SHA1DC_INIT_SAFE_HASH_DEFAULT;
		sha1recompress_fast_13(ihvin, ihvout, me2, state);
		sha1recompress_fast_36(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE60


		break;
#endif
SHA1_RECOMPRESS(57)
	uint32_t a = ihv[0], b = ihv[1], c = ihv[2], d = ihv[3], e = ihv[4];
	ctx->buffer[59] = (unsigned char)(total >> 32);
	default:
		sha1recompress_fast_10(ihvin, ihvout, me2, state);
		break;

	case 17:
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, W, 72);
		break;
							sha1_compression_W(ctx->ihv, ctx->m1);
#ifdef DOSTORESTATE39
#endif
	case 73:
#endif
	SHA1_STORE_STATE(27)

	if (t > 20) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(a, b, c, d, e, me2, 20); \
	if (t <= 26) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, me2, 26); \

	SHA1COMPRESS_FULL_ROUND4_STEP(a, b, c, d, e, W, 60, temp);
#ifdef DOSTORESTATE42


}
		break;
#endif

	case 4:
	uint32_t padn = (last < 56) ? (56 - last) : (120 - last);
#if __BYTE_ORDER == __BIG_ENDIAN

	if (t > 4) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(b, c, d, e, a, me2, 4); \
#ifdef DOSTORESTATE40
	output[1] = (unsigned char)(ctx->ihv[0] >> 16);
#endif
	if (t <= 68) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, me2, 68); \
#endif
	SHA1_STORE_STATE(38)

	case 64:
#ifdef DOSTORESTATE32
#ifdef DOSTORESTATE18
	SHA1COMPRESS_FULL_ROUND1_STEP_EXPAND(c, d, e, a, b, W, 18, temp);
#define SHA1DC_INIT_SAFE_HASH_DEFAULT 1
		break;
	{ b = rotate_right(b, 30); e -= rotate_left(a, 5) + sha1_f2(b,c,d) + 0x6ED9EBA1 + m[t]; }
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, W, 27);
SHA1_RECOMPRESS(61)
#endif
	case 56:
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, W, 76);
#ifdef DOSTORESTATE59

	if (t > 40) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(a, b, c, d, e, me2, 40); \

	{x = ((x << 8) & 0xFF00FF00) | ((x >> 8) & 0xFF00FF); x = (x << 16) | (x >> 16);}
	case 21:
	sha1_process(ctx, (uint32_t*)(ctx->buffer));
#define HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(a, b, c, d, e, m, t) \
		sha1recompress_fast_64(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE64
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(a, b, c, d, e, m, W, 10, temp);
#ifdef DOSTORESTATE56
#endif
#endif
	unsigned i, j;
{
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, W, 55);
	if (t <= 2) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, me2, 2); \

#ifdef DOSTORESTATE11
	SHA1_STORE_STATE(24)
	SHA1COMPRESS_FULL_ROUND4_STEP(d, e, a, b, c, W, 67, temp);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, W, 69);
		break;
#elif (defined(_AIX) || defined(__hpux))
	SHA1_STORE_STATE(11)
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(e, a, b, c, d, m, W, 11, temp);
	case 12:
#ifdef DOSTORESTATE24
	ihv[0] += a; ihv[1] += b; ihv[2] += c; ihv[3] += d; ihv[4] += e;
#endif
#endif
	if (t <= 33) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, me2, 33); \
#ifdef DOSTORESTATE38
	if (t > 13) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(c, d, e, a, b, me2, 13); \
#ifdef DOSTORESTATE5
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, W, 4);
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, W, 3);

void SHA1DCInit(SHA1_CTX* ctx)

	SHA1COMPRESS_FULL_ROUND4_STEP(a, b, c, d, e, W, 70, temp);

	if (t > 69) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(b, c, d, e, a, me2, 69); \
		break;

	if (t <= 79) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, me2, 79); \
	ctx->ihv1[4] = ctx->ihv[4];
	output[7] = (unsigned char)(ctx->ihv[1]);
	if (t <= 55) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, me2, 55); \
#pragma warning(push)

		break;
#endif
{

	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, W, 40);
{ \
#ifdef DOSTORESTATE76
#endif
	SHA1_STORE_STATE(23)
	SHA1COMPRESS_FULL_ROUND4_STEP(a, b, c, d, e, W, 75, temp);

		sha1recompress_fast_5(ihvin, ihvout, me2, state);
#endif

						}

	output[4] = (unsigned char)(ctx->ihv[1] >> 24);
		{
		break;
	if (t > 11) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(e, a, b, c, d, me2, 11); \
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, W, 73);
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, W, 17);
	case 3:
	SHA1COMPRESS_FULL_ROUND3_STEP(c, d, e, a, b, W, 48, temp);

	SHA1COMPRESS_FULL_ROUND3_STEP(d, e, a, b, c, W, 42, temp);
	SHA1COMPRESS_FULL_ROUND4_STEP(c, d, e, a, b, W, 73, temp);
#ifdef DOSTORESTATE35
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, W, 6);
	if (t <= 74) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, me2, 74); \
SHA1_RECOMPRESS(47)
     defined(__386) || defined(_M_X64) || defined(_M_AMD64))
	{temp = sha1_mix(W, t); sha1_store(W, t, temp); e += temp + rotate_left(a, 5) + sha1_f1(b,c,d) + 0x5A827999; b = rotate_left(b, 30); }
#define HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(a, b, c, d, e, m, t) \

	ctx->ihv1[2] = ctx->ihv[2];
#endif

#ifdef DOSTORESTATE51
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, W, 73);
#endif
	if (t <= 62) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, me2, 62); \
	case 67:
SHA1_RECOMPRESS(30)
#ifdef DOSTORESTATE40

		sha1recompress_fast_43(ihvin, ihvout, me2, state);
#endif
	case 58:

							sha1_compression_W(ctx->ihv, ctx->m1);
 * https://sourceforge.net/p/predef/wiki/Endianness/ and
#ifdef DOSTORESTATE26
#ifdef DOSTORESTATE77
#endif
	if (t > 34) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(b, c, d, e, a, me2, 34); \


}
	if (t <= 53) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, me2, 53); \
	case 8:
	if (t > 53) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(c, d, e, a, b, me2, 53); \
#include "ubc_check.h"
	case 11:

#endif
	fill = 64 - left;
#ifdef DOSTORESTATE46
#endif

#endif
		break;
#define sha1_f2(b,c,d) ((b)^(c)^(d))
	SHA1_STORE_STATE(70)
#endif
SHA1_RECOMPRESS(48)
#endif
#ifdef DOSTORESTATE21
#endif
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, W, 32);
#ifdef DOSTORESTATE50
		sha1recompress_fast_17(ihvin, ihvout, me2, state);
	if (t > 63) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(c, d, e, a, b, me2, 63); \
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(a, b, c, d, e, m, W, 5, temp);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, W, 78);
#endif
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, W, 5);
	SHA1COMPRESS_FULL_ROUND4_STEP(d, e, a, b, c, W, 72, temp);
		break;
	SHA1_STORE_STATE(33)
#endif

	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, W, 47);
{

}
#ifdef DOSTORESTATE39
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(a, b, c, d, e, m, W, 15, temp);
#endif
#endif
#ifdef DOSTORESTATE13
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, W, 21);
#endif
	if (t <= 52) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, me2, 52); \

	if (t <= 40) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, me2, 40); \
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, W, 66);
		sha1recompress_fast_55(ihvin, ihvout, me2, state);

		sha1recompress_fast_74(ihvin, ihvout, me2, state);
	if (t <= 25) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, me2, 25); \
#endif
	case 65:
#define SHA1DC_BIGENDIAN
		sha1recompress_fast_47(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE19
	if (t <= 77) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, me2, 77); \
		break;
#endif
#endif
#define HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, m, t) \
#endif
#ifdef DOSTORESTATE03
#ifndef SHA1DC_NO_STANDARD_INCLUDES
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, W, 31);
	if (t <= 59) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, me2, 59); \
	if (t <= 28) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, me2, 28); \
		sha1recompress_fast_3(ihvin, ihvout, me2, state);


	case 15:
	if (t <= 39) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, me2, 39); \
#ifdef DOSTORESTATE66
#endif

#ifdef DOSTORESTATE20
		sha1recompress_fast_38(ihvin, ihvout, me2, state);
#endif
	SHA1_STORE_STATE(21)
		sha1_process(ctx, (uint32_t*)(buf));
	if (t <= 17) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, me2, 17); \

		sha1recompress_fast_52(ihvin, ihvout, me2, state);
#endif
	if (t <= 7) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, me2, 7); \
		sha1recompress_fast_24(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE49
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, W, 43);
#if (defined(SHA1DC_FORCE_LITTLEENDIAN) && defined(SHA1DC_BIGENDIAN))
		sha1recompress_fast_63(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, W, 72);

#ifdef DOSTORESTATE73
	sha1_compression_states(ctx->ihv, block, ctx->m1, ctx->states);


	if (t > 73) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(c, d, e, a, b, me2, 73); \
#ifdef DOSTORESTATE13

#ifdef DOSTORESTATE20
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(d, e, a, b, c, m, W, 12, temp);
	if (t <= 48) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, me2, 48); \

SHA1_RECOMPRESS(71)

	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, W, 11);
SHA1_RECOMPRESS(10)
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, W, 16);
		sha1recompress_fast_51(ihvin, ihvout, me2, state);
	case 18:
#endif
		left = 0;
#endif
	if (t > 45) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(a, b, c, d, e, me2, 45); \
		break;
	ctx->ubc_check = 1;
	case 23:
#endif

#endif
#ifdef DOSTORESTATE15
	case 2:
#endif

	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, W, 16);
#endif
}
#ifdef DOSTORESTATE3
	if (t <= 15) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, me2, 15); \
#define SHA1DC_BIGENDIAN
SHA1_RECOMPRESS(58)
#ifdef DOSTORESTATE68

	ctx->buffer[61] = (unsigned char)(total >> 16);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, W, 79);
#ifdef DOSTORESTATE54
		sha1recompress_fast_34(ihvin, ihvout, me2, state);
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(b, c, d, e, a, m, W, 9, temp);
SHA1_RECOMPRESS(31)
#define HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, m, t) \
	output[3] = (unsigned char)(ctx->ihv[0]);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, W, 59);
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, W, 12);

						|| (ctx->reduced_round_coll && 0==((ctx->ihv1[0] ^ ctx->ihv2[0]) | (ctx->ihv1[1] ^ ctx->ihv2[1]) | (ctx->ihv1[2] ^ ctx->ihv2[2]) | (ctx->ihv1[3] ^ ctx->ihv2[3]) | (ctx->ihv1[4] ^ ctx->ihv2[4]))))
#endif
	if (t > 8) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(c, d, e, a, b, me2, 8); \

void SHA1DCSetDetectReducedRoundCollision(SHA1_CTX* ctx, int reduced_round_coll)
	SHA1_STORE_STATE(46)
	if (t <= 78) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, me2, 78); \
	case 13:
		sha1recompress_fast_72(ihvin, ihvout, me2, state);
#endif
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, W, 29);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, W, 75);

	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, W, 61);
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, W, 3);
	if (len > 0)
		break;
	if (t > 16) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(e, a, b, c, d, me2, 16); \
		W[i] = sha1_mix(W, i);
	SHA1_STORE_STATE(9)
#endif
		break;
#ifdef DOSTORESTATE04
#endif


	if (t > 62) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(d, e, a, b, c, me2, 62); \

	SHA1COMPRESS_FULL_ROUND4_STEP(d, e, a, b, c, W, 62, temp);
#ifdef DOSTORESTATE44

		sha1recompress_fast_57(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, W, 50);
		sha1recompress_fast_39(ihvin, ihvout, me2, state);
#elif defined(__BYTE_ORDER) && defined(__BIG_ENDIAN)
void SHA1DCSetSafeHash(SHA1_CTX* ctx, int safehash)
	SHA1_STORE_STATE(12)
	SHA1_STORE_STATE(72)
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, W, 44);
#endif

#ifdef DOSTORESTATE71

		break;
#ifdef DOSTORESTATE12


		sha1recompress_fast_41(ihvin, ihvout, me2, state);
					for (j = 0; j < 80; ++j)
	output[14] = (unsigned char)(ctx->ihv[3] >> 8);
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, W, 36);
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, W, 30);
	else
	if (t <= 24) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, me2, 24); \
	SHA1COMPRESS_FULL_ROUND2_STEP(e, a, b, c, d, W, 21, temp);
		sha1recompress_fast_56(ihvin, ihvout, me2, state);
	if (t > 51) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(e, a, b, c, d, me2, 51); \
		ctx->ubc_check = 0;
}
SHA1_RECOMPRESS(17)
	SHA1_STORE_STATE(2)
	if (t > 35) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(a, b, c, d, e, me2, 35); \
#ifdef DOSTORESTATE74
#ifdef DOSTORESTATE72
#endif
#endif
SHA1_RECOMPRESS(79)
		len -= 64;
#endif
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, W, 6);
#endif
#ifdef DOSTORESTATE62
#endif
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, W, 62);
#ifdef DOSTORESTATE70
	SHA1DCUpdate(ctx, (const char*)(sha1_padding), padn);

	output[15] = (unsigned char)(ctx->ihv[3]);
	}
		sha1recompress_fast_27(ihvin, ihvout, me2, state);
#endif
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(c, d, e, a, b, m, W, 3, temp);
	if (t <= 69) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, me2, 69); \

	ctx->ihv[4] = 0xC3D2E1F0;
#ifdef DOSTORESTATE62
		break;
#ifdef DOSTORESTATE17
		sha1recompress_fast_62(ihvin, ihvout, me2, state);

	SHA1_STORE_STATE(14)
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, W, 34);

#endif
	{temp = sha1_mix(W, t); sha1_store(W, t, temp); e += temp + rotate_left(a, 5) + sha1_f4(b,c,d) + 0xCA62C1D6; b = rotate_left(b, 30); }
#endif
		sha1recompress_fast_21(ihvin, ihvout, me2, state);
#endif
	ctx->ihv[0] = 0x67452301;
#undef SHA1DC_BIGENDIAN
#endif
#ifdef DOSTORESTATE76

#endif
	SHA1COMPRESS_FULL_ROUND3_STEP(e, a, b, c, d, W, 41, temp);
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, W, 35);
	SHA1_STORE_STATE(48)
#ifdef DOSTORESTATE24
	if (t > 65) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(a, b, c, d, e, me2, 65); \
SHA1_RECOMPRESS(36)
	ctx->ihv1[1] = ctx->ihv[1];
}
	output[12] = (unsigned char)(ctx->ihv[3] >> 24);
		break;
SHA1_RECOMPRESS(20)
	SHA1_STORE_STATE(78)

	case 41:
	case 26:
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, W, 77);
	ctx->buffer[60] = (unsigned char)(total >> 24);
	case 22:
	if (t <= 1) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, me2, 1); \
#ifdef DOSTORESTATE70
SHA1_RECOMPRESS(33)
		break;
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(d, e, a, b, c, m, W, 2, temp);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, W, 45);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, W, 46);
SHA1_RECOMPRESS(75)
	if (t > 39) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(b, c, d, e, a, me2, 39); \
	ihv[0] += a; ihv[1] += b; ihv[2] += c; ihv[3] += d; ihv[4] += e;
		ctx->safe_hash = 1;
#ifdef DOSTORESTATE69
		ctx->total += fill;
#ifdef DOSTORESTATE48

	case 50:
#endif
	if (t > 75) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(a, b, c, d, e, me2, 75); \
		break;
#ifdef DOSTORESTATE64
{
	SHA1_STORE_STATE(1)
		sha1recompress_fast_54(ihvin, ihvout, me2, state);

#endif

	SHA1_STORE_STATE(25)

	SHA1_STORE_STATE(45)
		break;
{
#endif
#ifdef DOSTORESTATE19
	SHA1_STORE_STATE(64)
		break;
	if (t <= 16) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, me2, 16); \
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, W, 15);
	if (t <= 13) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, me2, 13); \
#endif /*UNALIGNED ACCESS DETECTION*/
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(e, a, b, c, d, m, W, 6, temp);
	if (t > 17) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(d, e, a, b, c, me2, 17); \
	output[9] = (unsigned char)(ctx->ihv[2] >> 16);
	if (t <= 61) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, me2, 61); \
	if (t > 70) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(a, b, c, d, e, me2, 70); \
	SHA1COMPRESS_FULL_ROUND3_STEP(a, b, c, d, e, W, 45, temp);

#ifdef DOSTORESTATE52
SHA1_RECOMPRESS(40)
/*
#ifdef DOSTORESTATE48
	SHA1COMPRESS_FULL_ROUND4_STEP(e, a, b, c, d, W, 71, temp);
#ifdef DOSTORESTATE19
#endif
#define SHA1DC_BIGENDIAN
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, W, 32);
#endif
#endif
	if (t <= 47) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, me2, 47); \
#ifdef DOSTORESTATE59
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, W, 42);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, W, 58);


***/
SHA1_RECOMPRESS(60)
#ifdef DOSTORESTATE6
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, W, 25);
#ifdef DOSTORESTATE00
#endif
#endif
#endif
#endif
	output[2] = (unsigned char)(ctx->ihv[0] >> 8);
#endif
	SHA1_STORE_STATE(65)
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, W, 40);

SHA1_RECOMPRESS(67)
#endif
#ifdef DOSTORESTATE12
	output[5] = (unsigned char)(ctx->ihv[1] >> 16);
SHA1_RECOMPRESS(19)
#ifdef DOSTORESTATE47
	if (t > 58) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(c, d, e, a, b, me2, 58); \
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, W, 33);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, W, 66);
	if (t <= 65) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, me2, 65); \
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, W, 35);
		sha1recompress_fast_49(ihvin, ihvout, me2, state);
{
	case 6:
#ifdef _MSC_VER
	if (t <= 58) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, me2, 58); \
       defined(__sparc))

	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, W, 28);
#ifdef DOSTORESTATE10
SHA1_RECOMPRESS(63)
	SHA1_STORE_STATE(75)
SHA1_RECOMPRESS(37)

#endif
				{
}
#endif
#ifdef DOSTORESTATE44
		sha1recompress_fast_37(ihvin, ihvout, me2, state);

#endif

#endif
		ctx->safe_hash = 0;
#define SHA1DC_ALLOW_UNALIGNED_ACCESS
	case 32:
#endif
	output[19] = (unsigned char)(ctx->ihv[4]);
		buf += fill;
		if (ctx->ubc_check)

#define SHA1DC_BIGENDIAN
#endif
#endif
#ifdef DOSTORESTATE35

static const unsigned char sha1_padding[64] =

#else
#endif
	{sha1_load(m, t, temp); sha1_store(W, t, temp); e += temp + rotate_left(a, 5) + sha1_f1(b,c,d) + 0x5A827999; b = rotate_left(b, 30);}
		if (ubc_dv_mask[0] != 0)

#if defined(SHA1DC_FORCE_UNALIGNED_ACCESS) || defined(SHA1DC_ON_INTEL_LIKE_PROCESSOR)
#ifdef DOSTORESTATE71
	SHA1_STORE_STATE(26)
#endif
/*
	SHA1_STORE_STATE(74)
	ctx->found_collision = 0;
	if (t <= 51) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, me2, 51); \
	SHA1_STORE_STATE(67)

	SHA1COMPRESS_FULL_ROUND1_STEP_EXPAND(d, e, a, b, c, W, 17, temp);
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, W, 1);
	case 68:
SHA1_RECOMPRESS(16)
#endif
#endif
#endif
#endif
	SHA1COMPRESS_FULL_ROUND3_STEP(b, c, d, e, a, W, 59, temp);
#ifdef DOSTORESTATE46
#ifdef DOSTORESTATE50
void SHA1DCSetUseDetectColl(SHA1_CTX* ctx, int detect_coll)
	else
	a = ihv[0]; b = ihv[1]; c = ihv[2]; d = ihv[3]; e = ihv[4];
	SHA1COMPRESS_FULL_ROUND3_STEP(d, e, a, b, c, W, 52, temp);
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(e, a, b, c, d, m, W, 1, temp);
		sha1recompress_fast_46(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE31
	if (t <= 0) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, me2, 0); \
	ctx->buffer[63] = (unsigned char)(total);

	if (t <= 38) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, me2, 38); \
		memcpy(ctx->buffer, buf, 64);
SHA1_RECOMPRESS(49)
#ifdef DOSTORESTATE35
#ifdef DOSTORESTATE74

/*ENDIANNESS SELECTION*/
#ifdef DOSTORESTATE74
#include <stdio.h>
#ifdef DOSTORESTATE47
	SHA1_STORE_STATE(66)
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, W, 71);
#ifdef DOSTORESTATE5
	case 49:
static void sha1recompress_fast_ ## t (uint32_t ihvin[5], uint32_t ihvout[5], const uint32_t me2[80], const uint32_t state[5]) \

#endif
#endif
#endif
	if (t <= 31) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, me2, 31); \


	case 14:
		break;
#ifdef DOSTORESTATE50
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, W, 24);
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, W, 17);

 * clang.git's 3b198a97d2 ("Preprocessor: add __BYTE_ORDER__
#define rotate_right(x,n) (((x)>>(n))|((x)<<(32-(n))))
	case 43:
		break;
#ifdef DOSTORESTATE54
	if (t <= 71) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, me2, 71); \
SHA1_RECOMPRESS(38)
		break;
#ifdef DOSTORESTATE43
#define SHA1COMPRESS_FULL_ROUND2_STEP(a, b, c, d, e, W, t, temp) \
	SHA1COMPRESS_FULL_ROUND4_STEP(b, c, d, e, a, W, 74, temp);
	if (t > 50) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(a, b, c, d, e, me2, 50); \
#ifdef DOSTORESTATE70
#endif

#endif
		sha1recompress_fast_16(ihvin, ihvout, me2, state);
		break;
#ifdef DOSTORESTATE05
#endif
#endif
#define SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(a, b, c, d, e, m, W, t, temp) \
	SHA1_STORE_STATE(47)
	SHA1COMPRESS_FULL_ROUND2_STEP(d, e, a, b, c, W, 37, temp);
	uint32_t last = ctx->total & 63;
	if (t <= 34) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, me2, 34); \
#endif /*FORCE ALIGNED ACCESS*/
#endif
#ifdef DOSTORESTATE77
#ifdef DOSTORESTATE23

#endif
#ifdef DOSTORESTATE31
#endif
	if (t > 27) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(d, e, a, b, c, me2, 27); \
SHA1_RECOMPRESS(18)

	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, W, 23);
		sha1recompress_fast_65(ihvin, ihvout, me2, state);
/* Not under GCC-alike or glibc */
	SHA1_STORE_STATE(50)
#ifdef DOSTORESTATE57
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, W, 19);

#ifdef DOSTORESTATE54
		sha1recompress_fast_59(ihvin, ihvout, me2, state);
#endif
#endif
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, W, 49);

#endif
#ifdef DOSTORESTATE53
		sha1recompress_fast_70(ihvin, ihvout, me2, state);
		break;

						break;
#endif /* defined(SHA1DC_ALLOW_UNALIGNED_ACCESS) */
SHA1_RECOMPRESS(2)
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, W, 68);
SHA1_RECOMPRESS(13)
#endif

		break;
 */
#endif
#endif
#endif
		ctx->ubc_check = 1;
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#endif

	if (t > 78) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(c, d, e, a, b, me2, 78); \
#ifdef DOSTORESTATE72
#endif
SHA1_RECOMPRESS(69)
	if (t <= 30) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, me2, 30); \
	SHA1COMPRESS_FULL_ROUND2_STEP(b, c, d, e, a, W, 29, temp);
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, W, 23);
	if (detect_coll)
#endif
{
/*

	case 52:

#ifdef DOSTORESTATE10
#endif
	#define sha1_load(m, t, temp)  { temp = m[t]; sha1_bswap32(temp); }
	SHA1COMPRESS_FULL_ROUND4_STEP(b, c, d, e, a, W, 64, temp);
	SHA1_STORE_STATE(31)
	SHA1COMPRESS_FULL_ROUND1_STEP_EXPAND(b, c, d, e, a, W, 19, temp);
}
}
	uint32_t W[80];
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, W, 71);
#ifdef DOSTORESTATE65
	SHA1_STORE_STATE(71)
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, W, 70);
	if (t > 72) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(d, e, a, b, c, me2, 72); \
						if (ctx->safe_hash)
#ifdef DOSTORESTATE72
	case 33:
	case 47:

	SHA1COMPRESS_FULL_ROUND2_STEP(e, a, b, c, d, W, 36, temp);
	{ e += rotate_left(a, 5) + sha1_f4(b,c,d) + 0xCA62C1D6 + m[t]; b = rotate_left(b, 30); }
	if (t <= 57) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, me2, 57); \
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, W, 57);
	output[0] = (unsigned char)(ctx->ihv[0] >> 24);
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4]; \
		}
#endif
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, W, 51);
		sha1recompress_fast_68(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, W, 33);
	if (safehash)

	if (t > 1) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(e, a, b, c, d, me2, 1); \
	SHA1_STORE_STATE(16)
#ifdef DOSTORESTATE56


* Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow (danshu@microsoft.com)
#ifdef DOSTORESTATE16
						{
#ifdef DOSTORESTATE34

#ifdef DOSTORESTATE52
		sha1_process(ctx, (uint32_t*)(ctx->buffer));
SHA1_RECOMPRESS(7)
	if (t <= 37) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, me2, 37); \
	if (t <= 41) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, me2, 41); \
#ifdef DOSTORESTATE41

	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, W, 2);

	{
void sha1_compression_states(uint32_t ihv[5], const uint32_t m[16], uint32_t W[80], uint32_t states[80][5])
#endif
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, W, 53);
	else
		break;
		sha1recompress_fast_76(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE57
#ifdef DOSTORESTATE42

SHA1_RECOMPRESS(28)
 * Should define Big Endian for a whitelist of known processors. See
	if (t > 56) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(e, a, b, c, d, me2, 56); \

#ifdef DOSTORESTATE47
		break;
	SHA1COMPRESS_FULL_ROUND3_STEP(c, d, e, a, b, W, 58, temp);
	if (t <= 12) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, me2, 12); \

#endif
	case 76:
#endif
	case 62:
#endif
#endif
		break;
	output[10] = (unsigned char)(ctx->ihv[2] >> 8);
#endif
SHA1_RECOMPRESS(15)
#ifdef DOSTORESTATE18
{

		break;
	SHA1_STORE_STATE(20)
#endif
#endif
	SHA1_STORE_STATE(49)
		break;

	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, W, 45);
#endif
	ctx->buffer[57] = (unsigned char)(total >> 48);

#endif
#ifdef DOSTORESTATE75
 * Endian-only. See

	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(a, b, c, d, e, m, W, 0, temp);


#endif
{
/*#error "Uncomment this to see if you fall through all the detection"*/
	SHA1_STORE_STATE(52)
	SHA1COMPRESS_FULL_ROUND2_STEP(a, b, c, d, e, W, 30, temp);
	SHA1COMPRESS_FULL_ROUND2_STEP(b, c, d, e, a, W, 39, temp);
	SHA1COMPRESS_FULL_ROUND3_STEP(c, d, e, a, b, W, 43, temp);

/* Not under GCC-alike or glibc or *BSD or newlib or <processor whitelist> */

		sha1recompress_fast_42(ihvin, ihvout, me2, state);
#endif
					{

#ifdef DOSTORESTATE13
#ifdef DOSTORESTATE61
#ifdef DOSTORESTATE49
#ifdef DOSTORESTATE29
	SHA1_STORE_STATE(22)

#endif

SHA1_RECOMPRESS(9)
 * predefined macro", 2012-07-27)
	if (t <= 10) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, me2, 10); \
#ifdef DOSTORESTATE55
		break;
#ifdef DOSTORESTATE33
	SHA1_STORE_STATE(7)
SHA1_RECOMPRESS(4)


	SHA1COMPRESS_FULL_ROUND3_STEP(b, c, d, e, a, W, 54, temp);
}
#ifdef DOSTORESTATE36
#endif

#ifdef DOSTORESTATE29
	case 61:
		sha1recompress_fast_14(ihvin, ihvout, me2, state);
		break;
	SHA1COMPRESS_FULL_ROUND4_STEP(b, c, d, e, a, W, 69, temp);
	case 37:
SHA1_RECOMPRESS(46)
#ifdef DOSTORESTATE53
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, W, 18);
#endif
#endif
	if (t <= 6) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, me2, 6); \
	if (t <= 46) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, me2, 46); \
	case 10:
#define sha1_f1(b,c,d) ((d)^((b)&((c)^(d))))
	if (t > 46) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(e, a, b, c, d, me2, 46); \
#endif
		sha1recompress_fast_28(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, W, 9);
	unsigned i;
					if ((0 == ((ihvtmp[0] ^ ctx->ihv[0]) | (ihvtmp[1] ^ ctx->ihv[1]) | (ihvtmp[2] ^ ctx->ihv[2]) | (ihvtmp[3] ^ ctx->ihv[3]) | (ihvtmp[4] ^ ctx->ihv[4])))
SHA1_RECOMPRESS(3)
#define rotate_left(x,n)  (((x)<<(n))|((x)>>(32-(n))))
#ifdef DOSTORESTATE63
	case 77:

		break;
#endif
int SHA1DCFinal(unsigned char output[20], SHA1_CTX *ctx)
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, W, 41);
	if (t > 59) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(b, c, d, e, a, me2, 59); \
	if (left && len >= fill)
#endif
#endif
#ifdef DOSTORESTATE58
/***
#endif
#endif
	case 57:
		break;
	SHA1COMPRESS_FULL_ROUND2_STEP(e, a, b, c, d, W, 26, temp);
		break;
	if (t <= 67) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, me2, 67); \
#endif
	SHA1COMPRESS_FULL_ROUND2_STEP(d, e, a, b, c, W, 22, temp);
void SHA1DCSetUseUBC(SHA1_CTX* ctx, int ubc_check)
		break;
#define sha1_store(W, t, x)	*(volatile uint32_t *)&W[t] = x
#ifdef DOSTORESTATE39
		sha1recompress_fast_53(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, W, 63);
					sha1_recompression_step(sha1_dvs[i].testt, ctx->ihv2, ihvtmp, ctx->m2, ctx->states[sha1_dvs[i].testt]);
	ctx->ihv1[0] = ctx->ihv[0];

		sha1recompress_fast_25(ihvin, ihvout, me2, state);
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#ifdef DOSTORESTATE43
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, W, 59);
	SHA1COMPRESS_FULL_ROUND3_STEP(e, a, b, c, d, W, 46, temp);
SHA1_RECOMPRESS(74)
	case 39:
	for (i = 16; i < 80; ++i)
   Because Little-Endian architectures are most common,
#ifdef DOSTORESTATE14
 */

	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, W, 8);
#endif
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, W, 64);
#ifdef DOSTORESTATE34
#ifdef DOSTORESTATE22

#endif

#ifdef DOSTORESTATE67
		break;
#endif
		break;

	ctx->ihv[2] = 0x98BADCFE;
	if (t > 15) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(a, b, c, d, e, me2, 15); \
		ctx->reduced_round_coll = 0;

#define SHA1DC_BIGENDIAN
#ifdef DOSTORESTATE60
	if (t <= 3) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, me2, 3); \
#ifdef DOSTORESTATE66

 * Should detect Big Endian under GCC since at least 4.6.0 (gcc svn
	{
		sha1recompress_fast_18(ihvin, ihvout, me2, state);
	if (t > 71) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(e, a, b, c, d, me2, 71); \
		len -= fill;
	SHA1_STORE_STATE(19)
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, W, 52);
	if (t <= 23) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, me2, 23); \
SHA1_RECOMPRESS(21)
SHA1_RECOMPRESS(44)
	while (len >= 64)
	SHA1_STORE_STATE(79)
#if defined(SHA1DC_ALLOW_UNALIGNED_ACCESS)
#endif
#define SHA1COMPRESS_FULL_ROUND1_STEP_EXPAND(a, b, c, d, e, W, t, temp) \
#ifdef DOSTORESTATE76
		break;
#endif
#endif
	SHA1_STORE_STATE(8)
	if (t <= 43) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, me2, 43); \

#ifdef DOSTORESTATE77
				}
   If you are compiling on a big endian platform and your compiler does not define one of these,
#endif /* Big Endian detection */
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, W, 22);
		ctx->total += len;
		sha1recompress_fast_26(ihvin, ihvout, me2, state);
		break;

	if (t > 33) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(c, d, e, a, b, me2, 33); \
#if (defined(SHA1DC_FORCE_BIGENDIAN) && !defined(SHA1DC_BIGENDIAN))
	SHA1_STORE_STATE(77)
	ctx->ihv[1] = 0xEFCDAB89;

	SHA1_STORE_STATE(55)
#ifdef DOSTORESTATE37



#ifdef _MSC_VER
#endif
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, W, 76);

	if (t <= 36) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, me2, 36); \
#endif
	if (t > 79) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(b, c, d, e, a, me2, 79); \
	if (t <= 70) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, me2, 70); \
		abort();
#endif
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, W, 60);
	if (t > 7) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(d, e, a, b, c, me2, 7); \

#endif
#ifdef DOSTORESTATE16
		break;
		ctx->detect_coll = 0;
	if (reduced_round_coll)
/*
	if (t > 5) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(a, b, c, d, e, me2, 5); \
	if (t <= 75) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, me2, 75); \
#ifdef DOSTORESTATE08

		sha1recompress_fast_20(ihvin, ihvout, me2, state);
			}
#ifdef DOSTORESTATE41
#ifdef DOSTORESTATE7
#endif
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, W, 39);
#ifdef DOSTORESTATE1

			for (i = 0; sha1_dvs[i].dvType != 0; ++i)
#ifdef DOSTORESTATE15
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, W, 41);
	if (t > 68) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(c, d, e, a, b, me2, 68); \
#endif
	if (t > 76) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(e, a, b, c, d, me2, 76); \
		buf += 64;

#endif

	ctx->detect_coll = 1;
SHA1_RECOMPRESS(25)

	if (t > 3) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(c, d, e, a, b, me2, 3); \
#endif

	return ctx->found_collision;
#endif
	if (t <= 27) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, me2, 27); \
	case 42:
		break;
#ifdef DOSTORESTATE4
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, W, 61);
void SHA1DCUpdate(SHA1_CTX* ctx, const char* buf, size_t len)
SHA1_RECOMPRESS(42)
	ctx->buffer[58] = (unsigned char)(total >> 40);
		sha1recompress_fast_0(ihvin, ihvout, me2, state);

#ifdef DOSTORESTATE9
#endif
	{ b = rotate_right(b, 30); e -= rotate_left(a, 5) + sha1_f3(b,c,d) + 0x8F1BBCDC + m[t]; }
#endif
	if (t <= 19) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, me2, 19); \
 * This also works under clang since 3.2, it copied the GCC-ism. See
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, W, 56);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, W, 55);

#endif
     defined(i386) || defined(__i386) || defined(__i386__) || defined(__i486__)  || \
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, W, 2);
/* Not under GCC-alike or glibc or *BSD or newlib or <processor whitelist> or <os whitelist> */
	SHA1_STORE_STATE(62)
	if (t <= 63) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, me2, 63); \
		{
#ifdef DOSTORESTATE65
		sha1recompress_fast_31(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE67
#endif
SHA1_RECOMPRESS(29)
	SHA1COMPRESS_FULL_ROUND2_STEP(c, d, e, a, b, W, 38, temp);
		break;
 */
#include <stdlib.h>
	ihv[0] += a; ihv[1] += b; ihv[2] += c; ihv[3] += d; ihv[4] += e;
#ifdef DOSTORESTATE38
	if (t > 6) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(e, a, b, c, d, me2, 6); \
SHA1_RECOMPRESS(70)
	if (t > 61) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(e, a, b, c, d, me2, 61); \
		break;
	SHA1COMPRESS_FULL_ROUND3_STEP(c, d, e, a, b, W, 53, temp);

	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, W, 51);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, W, 46);
		break;
	uint32_t ihvtmp[5];
#ifdef DOSTORESTATE3
SHA1_RECOMPRESS(51)
	{

#endif
#ifdef DOSTORESTATE78
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, W, 26);
	output[18] = (unsigned char)(ctx->ihv[4] >> 8);
	output[11] = (unsigned char)(ctx->ihv[2]);

#endif
#define HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(a, b, c, d, e, m, t) \
#endif
	if (t > 10) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(a, b, c, d, e, me2, 10); \
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

	if (t > 67) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(d, e, a, b, c, me2, 67); \
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, W, 0);
#if (defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64) || \
#ifdef DOSTORESTATE06
	if (t > 37) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(d, e, a, b, c, me2, 37); \
	total = ctx->total - padn;
	if (t > 23) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(c, d, e, a, b, me2, 23); \
#endif
#ifdef DOSTORESTATE60

	if (t > 57) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(d, e, a, b, c, me2, 57); \
	SHA1COMPRESS_FULL_ROUND3_STEP(d, e, a, b, c, W, 47, temp);
		memcpy(ctx->buffer + left, buf, fill);
#endif
		sha1recompress_fast_73(ihvin, ihvout, me2, state);


}
	if (t <= 9) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, me2, 9); \
SHA1_RECOMPRESS(35)
	memcpy(W, m, 16 * 4);
	if (t > 43) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(c, d, e, a, b, me2, 43); \
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, W, 20);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, W, 63);
	if (t > 38) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(c, d, e, a, b, me2, 38); \
	if (t <= 76) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, me2, 76); \
#ifdef DOSTORESTATE14
SHA1_RECOMPRESS(66)
	if (ctx->detect_coll)
#endif
#ifdef DOSTORESTATE63
	ctx->buffer[56] = (unsigned char)(total >> 56);


	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, W, 0);
	SHA1_STORE_STATE(63)

#endif
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, W, 18);
	if (t > 2) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(d, e, a, b, c, me2, 2); \
		break;
	if (t <= 42) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, me2, 42); \
		break;
	SHA1_STORE_STATE(60)
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, W, 34);
		sha1recompress_fast_19(ihvin, ihvout, me2, state);
#endif
#define SHA1DC_ON_INTEL_LIKE_PROCESSOR
#ifdef DOSTORESTATE25
#ifdef DOSTORESTATE7
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, W, 38);
#ifdef DOSTORESTATE55
#endif
	SHA1_STORE_STATE(61)
#ifdef DOSTORESTATE22
		break;
#endif
	if (t > 66) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(e, a, b, c, d, me2, 66); \
			ubc_check(ctx->m1, ubc_dv_mask);
#endif
#endif
#elif (defined(__ARMEB__) || defined(__THUMBEB__) || defined(__AARCH64EB__) || \
		break;
	ctx->buffer[62] = (unsigned char)(total >> 8);
		sha1recompress_fast_58(ihvin, ihvout, me2, state);
#endif
#endif


   we only set SHA1DC_BIGENDIAN if one of these conditions is met.

	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, W, 49);

		break;
SHA1_RECOMPRESS(26)

	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, W, 77);
#endif
#endif
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, W, 64);
#endif

#ifdef DOSTORESTATE79
SHA1_RECOMPRESS(68)
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, W, 22);
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, W, 27);
#endif
	if (t > 55) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(a, b, c, d, e, me2, 55); \

	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, W, 39);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, W, 54);
	a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4]; \
#ifdef DOSTORESTATE73
#endif
	total <<= 3;
 */
#ifdef DOSTORESTATE32
#ifdef DOSTORESTATE31

		ctx->reduced_round_coll = 1;
/*
SHA1_RECOMPRESS(54)
#define sha1_f3(b,c,d) (((b)&(c))+((d)&((b)^(c))))

#ifdef DOSTORESTATE29
#endif
#ifdef DOSTORESTATE17
#ifdef DOSTORESTATE26
	SHA1COMPRESS_FULL_ROUND4_STEP(c, d, e, a, b, W, 68, temp);
		ctx->detect_coll = 1;

void sha1_compression(uint32_t ihv[5], const uint32_t m[16])
SHA1_RECOMPRESS(34)
#endif

	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, W, 24);

#define SHA1COMPRESS_FULL_ROUND4_STEP(a, b, c, d, e, W, t, temp) \

#endif
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(d, e, a, b, c, W, 67);
#ifdef DOSTORESTATE58
SHA1_RECOMPRESS(43)
#endif

	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, W, 38);
#ifdef DOSTORESTATE21

#ifdef DOSTORESTATE12


#ifdef DOSTORESTATE33
		break;
	SHA1_STORE_STATE(69)
#endif

	case 48:
#ifdef DOSTORESTATE53
	if (t > 29) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(b, c, d, e, a, me2, 29); \
	left = ctx->total & 63;
				if (ubc_dv_mask[0] & ((uint32_t)(1) << sha1_dvs[i].maskb))
	case 72:
#endif

#endif
#endif
		break;

SHA1_RECOMPRESS(55)
	SHA1_STORE_STATE(59)

     defined(__i586__) || defined(__i686__) || defined(_M_IX86) || defined(__X86__) || \
	if (t <= 22) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, me2, 22); \
	SHA1COMPRESS_FULL_ROUND4_STEP(b, c, d, e, a, W, 79, temp);
SHA1_RECOMPRESS(12)
	if (t > 44) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(b, c, d, e, a, me2, 44); \
	if (t > 25) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(a, b, c, d, e, me2, 25); \
		break;
		break;
	case 5:
#endif
	SHA1_STORE_STATE(68)
	case 35:
	}
	if (t > 77) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(d, e, a, b, c, me2, 77); \
		break;
	SHA1_STORE_STATE(36)
	output[6] = (unsigned char)(ctx->ihv[1] >> 8);
#endif
#endif
		sha1recompress_fast_61(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE27

#ifdef DOSTORESTATE75
#ifdef DOSTORESTATE27
#define sha1_bswap32(x) \
#endif


	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, W, 57);
	SHA1_STORE_STATE(53)
#ifdef DOSTORESTATE27
	{
#ifdef DOSTORESTATE57
	{ b = rotate_right(b, 30); e -= rotate_left(a, 5) + sha1_f1(b,c,d) + 0x5A827999 + m[t]; }
	#define sha1_load(m, t, temp)  { temp = m[t]; }

	case 55:
#endif
{
#ifdef DOSTORESTATE11
	if (t <= 11) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, me2, 11); \

	if (t > 49) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(b, c, d, e, a, me2, 49); \
	if (t <= 60) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, me2, 60); \
	unsigned left, fill;
#endif
#endif /*BUILDNOCOLLDETECTSHA1COMPRESSION*/
#include SHA1DC_CUSTOM_TRAILING_INCLUDE_SHA1_C
 */
#endif
#endif
SHA1_RECOMPRESS(0)
	if (t > 21) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(e, a, b, c, d, me2, 21); \
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, W, 48);
 * rev #165881). See
#endif
	if (t > 9) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(b, c, d, e, a, me2, 9); \

	if (t > 36) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(e, a, b, c, d, me2, 36); \
#ifdef DOSTORESTATE9

	SHA1_STORE_STATE(5)
		break;
	if (t > 64) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(b, c, d, e, a, me2, 64); \
	SHA1COMPRESS_FULL_ROUND3_STEP(a, b, c, d, e, W, 55, temp);

SHA1_RECOMPRESS(64)
	SHA1_STORE_STATE(28)

	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, W, 7);
	}
SHA1_RECOMPRESS(22)
		sha1recompress_fast_75(ihvin, ihvout, me2, state);
{
 *
		sha1recompress_fast_77(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE63
	SHA1COMPRESS_FULL_ROUND2_STEP(b, c, d, e, a, W, 24, temp);
#ifdef DOSTORESTATE61
		break;
	SHA1_STORE_STATE(41)
 * *BSD and newlib (embedded linux, cygwin, etc).
	if (t <= 35) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, me2, 35); \
#ifdef DOSTORESTATE42
SHA1_RECOMPRESS(56)
#ifdef DOSTORESTATE59
	case 63:

	case 27:

	case 53:
#ifdef DOSTORESTATE37
#elif defined(_BYTE_ORDER) && defined(_BIG_ENDIAN) && defined(_LITTLE_ENDIAN)
 * Should detect Big Endian under glibc.git since 14245eb70e ("entered
	if (t <= 4) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, me2, 4); \
		sha1recompress_fast_15(ihvin, ihvout, me2, state);
#include <sys/types.h> /* make sure macros like _BIG_ENDIAN visible */

	SHA1_STORE_STATE(4)
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, W, 65);
#endif
SHA1_RECOMPRESS(59)
#ifdef DOSTORESTATE21
	ctx->ihv[3] = 0x10325476;
	case 40:
	if (len == 0)
SHA1_RECOMPRESS(62)
	if (t <= 66) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(e, a, b, c, d, me2, 66); \
static void sha1_compression_W(uint32_t ihv[5], const uint32_t W[80])
#endif
#endif
	case 9:
		sha1recompress_fast_12(ihvin, ihvout, me2, state);
		break;
SHA1_RECOMPRESS(23)
#ifdef DOSTORESTATE28
	case 66:
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, W, 42);
SHA1_RECOMPRESS(32)
#define HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, m, t) \
#ifdef DOSTORESTATE22

}
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, W, 10);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, W, 79);
#ifdef DOSTORESTATE09
	SHA1COMPRESS_FULL_ROUND2_STEP(d, e, a, b, c, W, 32, temp);
		sha1recompress_fast_7(ihvin, ihvout, me2, state);
#endif
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, W, 78);
#endif
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(b, c, d, e, a, W, 29);
		sha1recompress_fast_50(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE25
	case 60:
#ifdef DOSTORESTATE44
#endif
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, W, 12);
#ifdef DOSTORESTATE17
#endif
		break;
#ifdef DOSTORESTATE73

	ctx->callback = callback;
	SHA1COMPRESS_FULL_ROUND2_STEP(c, d, e, a, b, W, 28, temp);
 * into RCS", 1992-11-25). Defined in <endian.h> which will have been
					}
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, W, 74);

#ifdef DOSTORESTATE75
		sha1recompress_fast_4(ihvin, ihvout, me2, state);
#define sha1_f4(b,c,d) ((b)^(c)^(d))
	{ b = rotate_right(b, 30); e -= rotate_left(a, 5) + sha1_f4(b,c,d) + 0xCA62C1D6 + m[t]; }
#ifdef DOSTORESTATE45

#ifdef DOSTORESTATE0
#endif
	SHA1_STORE_STATE(0)
#endif
	case 0:
		break;
}
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(b, c, d, e, a, m, W, 14, temp);
#endif
#ifdef DOSTORESTATE48
		sha1recompress_fast_33(ihvin, ihvout, me2, state);
	SHA1_STORE_STATE(73)
#endif
* Distributed under the MIT Software License.

#endif

       defined(__MIPSEB__) || defined(__MIPSEB) || defined(_MIPSEB) || \
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, W, 4);
		sha1recompress_fast_30(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, W, 68);
 * https://sourceforge.net/p/predef/wiki/Endianness/
#ifdef DOSTORESTATE79


	SHA1COMPRESS_FULL_ROUND3_STEP(a, b, c, d, e, W, 50, temp);
 */

	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, W, 65);
#ifdef DOSTORESTATE36

 * about below, we blacklist specific processors here. We could add
	SHA1_STORE_STATE(43)
#endif
#endif
SHA1_RECOMPRESS(77)
	if (t <= 49) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, me2, 49); \
#endif

#ifdef DOSTORESTATE68
#endif
		sha1recompress_fast_1(ihvin, ihvout, me2, state);
SHA1_RECOMPRESS(72)
	{ e += rotate_left(a, 5) + sha1_f1(b,c,d) + 0x5A827999 + m[t]; b = rotate_left(b, 30); }

	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, W, 52);

		}
	if (t > 74) HASHCLASH_SHA1COMPRESS_ROUND4_STEP_BW(b, c, d, e, a, me2, 74); \
#endif
	case 24:
#ifdef DOSTORESTATE1
#define HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, m, t) \

	SHA1_STORE_STATE(18)
	if (t > 28) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(c, d, e, a, b, me2, 28); \
#ifdef DOSTORESTATE66
	uint32_t ubc_dv_mask[DVMASKSIZE] = { 0xFFFFFFFF };
#endif
SHA1_RECOMPRESS(8)
		sha1recompress_fast_2(ihvin, ihvout, me2, state);
	if (t <= 73) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(c, d, e, a, b, me2, 73); \
	SHA1_STORE_STATE(30)
/* We do nothing more here for now */
#ifndef SHA1DC_FORCE_ALIGNED_ACCESS
 */
#ifdef DOSTORESTATE62
	case 44:
#ifdef DOSTORESTATE45
#ifdef DOSTORESTATE78
static void sha1_process(SHA1_CTX* ctx, const uint32_t block[16])
#ifdef DOSTORESTATE01
#endif
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, W, 75);
	case 45:
};

	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(e, a, b, c, d, W, 1);
#define SHA1_RECOMPRESS(t) \
   Note that all MSFT platforms are little endian,
#endif
#ifdef DOSTORESTATE69
#ifdef DOSTORESTATE38
		sha1recompress_fast_71(ihvin, ihvout, me2, state);
	if (t > 52) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(d, e, a, b, c, me2, 52); \
	if (t <= 32) HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, me2, 32); \
	else
#endif

#endif
SHA1_RECOMPRESS(27)
#ifdef DOSTORESTATE68
	case 20:
	SHA1_STORE_STATE(13)
	output[17] = (unsigned char)(ctx->ihv[4] >> 16);
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)

	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, W, 25);
	case 34:
SHA1_RECOMPRESS(53)
/*
	SHA1COMPRESS_FULL_ROUND4_STEP(c, d, e, a, b, W, 63, temp);
#ifdef DOSTORESTATE46
	SHA1_STORE_STATE(58)
#ifdef DOSTORESTATE16
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, W, 5);
		sha1recompress_fast_66(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE8

	if (t > 41) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(e, a, b, c, d, me2, 41); \
	if (t <= 8) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, me2, 8); \
	SHA1COMPRESS_FULL_ROUND4_STEP(e, a, b, c, d, W, 61, temp);
	case 46:
#endif
	if (t > 54) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(b, c, d, e, a, me2, 54); \

	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, W, 13);
SHA1_RECOMPRESS(5)
	if (t > 19) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(b, c, d, e, a, me2, 19); \
#ifndef SHA1DC_INIT_SAFE_HASH_DEFAULT
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, W, 8);

 * this condition from matching with Solaris/sparc.

		sha1recompress_fast_8(ihvin, ihvout, me2, state);
#ifdef DOSTORESTATE40
	SHA1COMPRESS_FULL_ROUND3_STEP(b, c, d, e, a, W, 49, temp);
 * https://gcc.gnu.org/onlinedocs/cpp/Common-Predefined-Macros.html
	SHA1COMPRESS_FULL_ROUND2_STEP(d, e, a, b, c, W, 27, temp);
}
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, W, 37);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(d, e, a, b, c, W, 47);

	ihvin[0] = a; ihvin[1] = b; ihvin[2] = c; ihvin[3] = d; ihvin[4] = e; \
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(c, d, e, a, b, W, 28);
#ifdef DOSTORESTATE43
SHA1_RECOMPRESS(11)
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(d, e, a, b, c, W, 37);
	SHA1_STORE_STATE(42)
#ifdef DOSTORESTATE32
#endif
	SHA1_STORE_STATE(32)
	}
#ifdef DOSTORESTATE28

#ifdef DOSTORESTATE41
#ifdef DOSTORESTATE34
	if (t <= 56) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(e, a, b, c, d, me2, 56); \
	SHA1COMPRESS_FULL_ROUND2_STEP(b, c, d, e, a, W, 34, temp);

SHA1_RECOMPRESS(50)

	if (t <= 54) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, me2, 54); \
#ifdef DOSTORESTATE51
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(c, d, e, a, b, m, W, 13, temp);
	{temp = sha1_mix(W, t); sha1_store(W, t, temp); e += temp + rotate_left(a, 5) + sha1_f3(b,c,d) + 0x8F1BBCDC; b = rotate_left(b, 30); }

		sha1recompress_fast_67(ihvin, ihvout, me2, state);
SHA1_RECOMPRESS(73)
	case 28:
#ifdef __unix__
		sha1recompress_fast_48(ihvin, ihvout, me2, state);
#endif
#endif
		break;
	SHA1_STORE_STATE(51)
	output[13] = (unsigned char)(ctx->ihv[3] >> 16);
#endif
#endif
#endif

		break;
	case 70:
#endif

SHA1_RECOMPRESS(52)
	switch (step)
#endif
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, W, 19);
	SHA1_STORE_STATE(35)
 * (Solaris defines only one endian macro)
#ifdef DOSTORESTATE0
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, W, 74);
		sha1recompress_fast_60(ihvin, ihvout, me2, state);
#endif

						ctx->found_collision = 1;
#endif
#endif
	if (t <= 14) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, me2, 14); \
#if _BYTE_ORDER == _BIG_ENDIAN
#endif
#endif
	output[16] = (unsigned char)(ctx->ihv[4] >> 24);
	if (t <= 45) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, me2, 45); \
#endif
#ifdef DOSTORESTATE65
#endif
#ifdef DOSTORESTATE37
     defined(_X86_) || defined(__THW_INTEL__) || defined(__I86__) || defined(__INTEL__) || \
#ifdef DOSTORESTATE58
	if (t <= 44) HASHCLASH_SHA1COMPRESS_ROUND3_STEP(b, c, d, e, a, me2, 44); \
	if (t > 47) HASHCLASH_SHA1COMPRESS_ROUND3_STEP_BW(d, e, a, b, c, me2, 47); \
#ifdef DOSTORESTATE30
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(a, b, c, d, e, W, 30);
	SHA1COMPRESS_FULL_ROUND1_STEP_EXPAND(e, a, b, c, d, W, 16, temp);
		break;

	case 59:
#endif
	SHA1_STORE_STATE(34)
#endif
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, W, 48);
#ifdef DOSTORESTATE15
	SHA1_STORE_STATE(57)
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, W, 21);
		sha1recompress_fast_23(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, W, 58);
#endif
#endif
 * more, see e.g. https://wiki.debian.org/ArchitectureSpecificsMemo
	case 25:
	SHA1COMPRESS_FULL_ROUND1_STEP_LOAD(c, d, e, a, b, m, W, 8, temp);
	ctx->callback = NULL;
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(a, b, c, d, e, W, 50);
#endif
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, W, 60);

		sha1recompress_fast_45(ihvin, ihvout, me2, state);
	{ e += rotate_left(a, 5) + sha1_f2(b,c,d) + 0x6ED9EBA1 + m[t]; b = rotate_left(b, 30); }
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, W, 36);
		break;
* https://opensource.org/licenses/MIT
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, W, 31);
#endif
#endif
#endif
	if (t <= 5) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(a, b, c, d, e, me2, 5); \
		break;


	SHA1_STORE_STATE(40)
{

	if (t > 32) HASHCLASH_SHA1COMPRESS_ROUND2_STEP_BW(d, e, a, b, c, me2, 32); \
#ifdef DOSTORESTATE55
#ifdef DOSTORESTATE07
#ifdef DOSTORESTATE6
		break;
	case 31:
#ifdef DOSTORESTATE67
#include "sha1.h"
#ifdef DOSTORESTATE64
   so none of these will be defined under the MSC compiler.
	case 75:
void SHA1DCSetCallback(SHA1_CTX* ctx, collision_block_callback callback)
#ifdef DOSTORESTATE14
		sha1recompress_fast_22(ihvin, ihvout, me2, state);
	HASHCLASH_SHA1COMPRESS_ROUND4_STEP(a, b, c, d, e, W, 70);
		sha1recompress_fast_44(ihvin, ihvout, me2, state);
	uint32_t a = ihv[0], b = ihv[1], c = ihv[2], d = ihv[3], e = ihv[4];
	if (t <= 18) HASHCLASH_SHA1COMPRESS_ROUND1_STEP(c, d, e, a, b, me2, 18); \
		sha1recompress_fast_69(ihvin, ihvout, me2, state);
#endif

	SHA1_STORE_STATE(6)
#else /* Not under GCC-alike or glibc or *BSD or newlib or <processor whitelist> or <os whitelist> or <processor blacklist> */
#ifdef DOSTORESTATE20
#elif defined(SHA1DC_ON_INTEL_LIKE_PROCESSOR)
		return;
#endif
	SHA1COMPRESS_FULL_ROUND2_STEP(a, b, c, d, e, W, 20, temp);
 * https://lore.kernel.org/git/93056823-2740-d072-1ebd-46b440b33d7e@felt.demon.nl/
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
SHA1_RECOMPRESS(39)
	SHA1_STORE_STATE(29)
#define SHA1_STORE_STATE(i) states[i][0] = a; states[i][1] = b; states[i][2] = c; states[i][3] = d; states[i][4] = e;


#ifdef DOSTORESTATE23
		sha1recompress_fast_35(ihvin, ihvout, me2, state);
#endif
	case 19:
	if (t > 14) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(b, c, d, e, a, me2, 14); \
#endif

	case 54:
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(d, e, a, b, c, W, 7);
	uint32_t temp;
#ifdef DOSTORESTATE30
	SHA1COMPRESS_FULL_ROUND4_STEP(c, d, e, a, b, W, 78, temp);
	HASHCLASH_SHA1COMPRESS_ROUND2_STEP(e, a, b, c, d, W, 26);
		break;
#endif

#ifdef DOSTORESTATE45
	if (t <= 64) HASHCLASH_SHA1COMPRESS_ROUND4_STEP(b, c, d, e, a, me2, 64); \
   you will have to add whatever macros your tool chain defines to indicate Big-Endianness.
		sha1recompress_fast_29(ihvin, ihvout, me2, state);
	{ e += rotate_left(a, 5) + sha1_f3(b,c,d) + 0x8F1BBCDC + m[t]; b = rotate_left(b, 30); }
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, W, 9);
	HASHCLASH_SHA1COMPRESS_ROUND1_STEP(b, c, d, e, a, W, 14);
	case 16:

#ifdef DOSTORESTATE02
 * As a last resort before we do anything else we're not 100% sure
	if (ubc_check)
	HASHCLASH_SHA1COMPRESS_ROUND3_STEP(c, d, e, a, b, W, 53);
#ifdef DOSTORESTATE36
	if (t > 0) HASHCLASH_SHA1COMPRESS_ROUND1_STEP_BW(a, b, c, d, e, me2, 0); \
		sha1recompress_fast_6(ihvin, ihvout, me2, state);
#endif
