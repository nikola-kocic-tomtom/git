 * zlib wrappers to make sure we don't silently miss errors

void git_inflate_init_gzip_only(git_zstream *strm)
		break;
/*
		if ((strm->avail_out && !strm->z.avail_out) &&
}


{
		/*
void git_deflate_init(git_zstream *strm, int level)
	s->avail_out -= bytes_produced;
	      strm->z.msg ? strm->z.msg : "no message");
}

				 ? 0 : flush);
	/*

	zlib_post_call(strm);

	zlib_pre_call(strm);

}
	/* Z_BUF_ERROR: normal, needs more space in the output buffer */
	 * Use default 15 bits, +16 is to generate gzip header/trailer
	status = inflateEnd(&strm->z);
		 */
	case Z_OK:
	int status;
		if (status == Z_MEM_ERROR)
	do_git_deflate_init(strm, level, -15);
		return;
static const char *zerr_to_string(int status)
	}
void git_deflate_end(git_zstream *strm)
	 * yield Z_DATA_ERROR when fed zlib format.
	for (;;) {

static void do_git_deflate_init(git_zstream *strm, int level, int windowBits)
	default:
	status = deflateInit(&strm->z, level);
int git_inflate(git_zstream *strm, int flush)
}
	s->next_in = s->z.next_in;
}
	case Z_BUF_ERROR:
static inline uInt zlib_buf_cap(unsigned long len)
		return;


		return;
	if (status == Z_OK)
	if (status == Z_OK)
}
void git_inflate_end(git_zstream *strm)
{
		BUG("total_in mismatch");
		return "needs dictionary";


		return status;
	int status;
	zlib_post_call(strm);
unsigned long git_deflate_bound(git_zstream *strm, unsigned long size)
	return status;
	zlib_pre_call(strm);
	case Z_STREAM_END:
		zlib_pre_call(strm);
	int status = git_deflate_abort(strm);
	status = inflateInit(&strm->z);
	zlib_pre_call(strm);
	die("inflateInit: %s (%s)", zerr_to_string(status),
	status = deflateEnd(&strm->z);
	s->total_in = s->z.total_in;
	status = deflateEnd(&strm->z);
 * with zlib in a single call to inflate/deflate.

		zlib_post_call(strm);


	int status;
	int status;
	/*

	bytes_consumed = s->z.next_in - s->next_in;
		return "stream consistency error";
	memset(strm, 0, sizeof(*strm));
	if (status == Z_OK)

	return status;
{
}
}
/* #define ZLIB_BUF_MAX ((uInt)-1) */
		 */
	return deflateBound(&strm->z, size);
	 */
}
#if defined(NO_DEFLATE_BOUND) || ZLIB_VERNUM < 0x1200
	s->avail_in -= bytes_consumed;
				 ? 0 : flush);
/*
{
	 * data without zlib header and trailer.
	s->z.next_out = s->next_out;
void git_deflate_init_gzip(git_zstream *strm, int level)
	if (status == Z_OK)
	if (s->z.total_out != s->total_out + bytes_produced)
	int status;
	}
	int status;
{

	error("inflate: %s (%s)", zerr_to_string(status),
	zlib_post_call(strm);
		return "wrong version";
{
	for (;;) {
	s->total_out = s->z.total_out;
	return status;
		zlib_pre_call(strm);
{
{
	error("deflateEnd: %s (%s)", zerr_to_string(status),
	s->z.next_in = s->next_in;
	    strm->z.msg ? strm->z.msg : "no message");

	if (status == Z_OK)
}
	zlib_post_call(strm);

{
#define ZLIB_BUF_MAX ((uInt) 1024 * 1024 * 1024) /* 1GB */
	    strm->z.msg ? strm->z.msg : "no message");
	status = inflateInit2(&strm->z, windowBits);
	error("inflateEnd: %s (%s)", zerr_to_string(status),
}
int git_deflate(git_zstream *strm, int flush)
		 * Let zlib work another round, while we can still
static void zlib_pre_call(git_zstream *s)
	int status;
}
void git_inflate_init(git_zstream *strm)
		status = inflate(&strm->z,
	}
	      strm->z.msg ? strm->z.msg : "no message");
		return "unknown error";
	switch (status) {
		return;

	zlib_pre_call(strm);
		return;
	case Z_MEM_ERROR:
	int status;
	return status;
{
	die("deflateInit2: %s (%s)", zerr_to_string(status),
	 */
	s->next_out = s->z.next_out;

}
	    strm->z.msg ? strm->z.msg : "no message");
	zlib_post_call(strm);

int git_deflate_end_gently(git_zstream *strm)
	unsigned long bytes_consumed;
	if (s->z.total_in != s->total_in + bytes_consumed)
		 * make progress.
	do_git_deflate_init(strm, level, 15 + 16);
}

{
	case Z_VERSION_ERROR:
	}
	default:


 * limits the size of the buffer we can use to 4GB when interacting
	/* Z_BUF_ERROR: normal, needs more space in the output buffer */

 * at init time.
{
int git_deflate_abort(git_zstream *strm)

void git_deflate_init_raw(git_zstream *strm, int level)
}
		    (status == Z_OK || status == Z_BUF_ERROR))
	s->z.avail_out = zlib_buf_cap(s->avail_out);
	case Z_DATA_ERROR:
	status = deflateInit2(&strm->z, level,
		status = deflate(&strm->z,
	zlib_post_call(strm);
		/* Never say Z_FINISH unless we are feeding everything */
{

}
	}
	case Z_BUF_ERROR:
			continue;
{
		if (status == Z_MEM_ERROR)

	error("deflate: %s (%s)", zerr_to_string(status),
	switch (status) {
				  8, Z_DEFAULT_STRATEGY);
	case Z_NEED_DICT:
	int status;
		zlib_post_call(strm);
	case Z_OK:
	unsigned long bytes_produced;


	switch (status) {
		 * Let zlib work another round, while we can still
	die("deflateInit: %s (%s)", zerr_to_string(status),
	 */
{
static void zlib_post_call(git_zstream *s)
 */
			die("inflate: out of memory");
#endif
		return "data stream error";

{
				 (strm->z.avail_in != strm->avail_in)
		/* Never say Z_FINISH unless we are feeding everything */
#include "cache.h"
	zlib_pre_call(strm);
	die("inflateInit2: %s (%s)", zerr_to_string(status),
	zlib_pre_call(strm);
	/*

	s->z.total_out = s->total_out;
	default:
{
		    (status == Z_OK || status == Z_BUF_ERROR))
	 * Use default 15 bits, +16 is to accept only gzip and to
	s->z.avail_in = zlib_buf_cap(s->avail_in);
	const int windowBits = 15 + 16;
		break;
		BUG("total_out mismatch");
				 (strm->z.avail_in != strm->avail_in)
		return "out of memory";
		 * make progress.
	memset(strm, 0, sizeof(*strm));
		if ((strm->avail_out && !strm->z.avail_out) &&
	zlib_pre_call(strm);
	 * Use default 15 bits, negate the value to get raw compressed
	 * instead of the zlib wrapper.
			continue;
				  Z_DEFLATED, windowBits,
	      strm->z.msg ? strm->z.msg : "no message");
	bytes_produced = s->z.next_out - s->next_out;
		break;
 * avail_in and avail_out in zlib are counted in uInt, which typically

	s->z.total_in = s->total_in;
	case Z_STREAM_END:
 */
	if (status == Z_OK)
		break;
}
#define deflateBound(c,s)  ((s) + (((s) + 7) >> 3) + (((s) + 63) >> 6) + 11)
	return (ZLIB_BUF_MAX < len) ? ZLIB_BUF_MAX : len;
	zlib_post_call(strm);
		/*
		return status;
	case Z_STREAM_ERROR:
	    strm->z.msg ? strm->z.msg : "no message");
		return;
			die("deflate: out of memory");
	      strm->z.msg ? strm->z.msg : "no message");
