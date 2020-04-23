	secs = tv.tv_sec;
		  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
	struct timeval tv;

	gettimeofday(&tv, NULL);
		  (long)tv.tv_usec);

		  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
	secs = tv.tv_sec;
}
void tr2_tbuf_utc_datetime(struct tr2_tbuf *tb)
	gettimeofday(&tv, NULL);
	struct timeval tv;
	gmtime_r(&secs, &tm);
	gmtime_r(&secs, &tm);
	struct tm tm;

#include "tr2_tbuf.h"
#include "cache.h"
		  tm.tm_min, tm.tm_sec, (long)tv.tv_usec);
	struct tm tm;
	gettimeofday(&tv, NULL);
{
	xsnprintf(tb->buf, sizeof(tb->buf),
	secs = tv.tv_sec;
	time_t secs;

	time_t secs;
{
void tr2_tbuf_local_time(struct tr2_tbuf *tb)
void tr2_tbuf_utc_datetime_extended(struct tr2_tbuf *tb)
	xsnprintf(tb->buf, sizeof(tb->buf), "%4d%02d%02dT%02d%02d%02d.%06ldZ",


	struct timeval tv;
{
	struct tm tm;
		  tm.tm_min, tm.tm_sec, (long)tv.tv_usec);
}
	time_t secs;
	xsnprintf(tb->buf, sizeof(tb->buf), "%02d:%02d:%02d.%06ld", tm.tm_hour,
}
		  "%4d-%02d-%02dT%02d:%02d:%02d.%06ldZ", tm.tm_year + 1900,
	localtime_r(&secs, &tm);



