
	throughput_string(&tp->display, total, rate);
struct progress *start_delayed_progress(const char *title, uint64_t total)

/*
	unsigned int avg_misecs;
					last_count_len - counters_sb->len + 1 :


	int show_update = 0;
					    cols - progress->title_len - 1 : 0;
}
	 * We have x = bytes and y = nanosecs.  We want z = KiB/s:
	const char *title;
	 *	z = x / y'
	now_ns = progress_getnanotime(progress);
			unsigned int misecs, rate;
	tp->avg_misecs -= tp->last_misecs[tp->idx];
}
	setitimer(ITIMER_REAL, &v, NULL);
	finish_if_sparse(*p_progress);
	return start_progress_delay(title, total, get_default_delay(), 0);
	clear_progress_signal();
{
{
 * This code is free software; you can redistribute it and/or modify
	tp = (progress->throughput) ? progress->throughput->display.buf : "";
	const char *tp;

}
	uint64_t prev_ns;

		return;
					counters_sb->buf, eol);

 * Copyright (c) 2007 by Nicolas Pitre <nico@fluxnic.net>
}
	if (progress_testing)
		progress_update = 1;
static void set_progress_signal(void)

	 *
	if (!progress)
		strbuf_reset(counters_sb);
{
	unsigned delay;
struct progress {
	struct itimerval v = {{0,},};
}
			const char *eol = done ? done : "\r";
	int title_len;

 * for 'test-tool progress'.
	} else if (progress_update) {
	tp->curr_total = total;
struct throughput {
 * Simple text-based progress display module for GIT
	progress_update = 1;
{
{
		if (percent != progress->last_percent || progress_update) {
	if (progress->throughput)
 * decide when to call display_progress() rather than calling it for every

		char *buf;

					     unsigned delay, unsigned sparse)
	strbuf_init(&progress->counters_sb, 0);
		unsigned percent = n * 100 / progress->total;
{
}
				progress->split = 1;
	off_t prev_total;


	int last_count_len = counters_sb->len;
			size_t progress_line_len = progress->title_len +
#include "gettext.h"
		return;
	 * obtained with:
	 *	y' = (y * 4398) >> 32
struct progress *start_progress(const char *title, uint64_t total)
	progress_update = 0;
	count = total - tp->prev_total;
	unsigned int misecs, count, rate;
				    (uintmax_t)n, (uintmax_t)progress->total,
	struct itimerval v;
	return start_progress_delay(title, total, 0, 0);
			rate = tp->curr_total / (misecs ? misecs : 1);
			/* The "+ 2" accounts for the ": ". */
		return;
{
{
	    progress->last_value != progress->total)
		progress_update = 0;
void stop_progress(struct progress **p_progress)
		tp->prev_ns = now_ns;
		if (is_foreground_fd(fileno(stderr)) || done) {

		return;

	sa.sa_handler = progress_interval;
	int split;
	unsigned int idx;

 * These are only intended for testing the progress output, i.e. exclusively
	struct strbuf *counters_sb = &progress->counters_sb;
}
}
};
{
	signal(SIGALRM, SIG_IGN);
/*
	unsigned int last_misecs[TP_IDX_MAX];
			throughput_string(&tp->display, tp->curr_total, rate);
	/* only update throughput every 0.5 s */
{
		return;
}
		}
 * Here "sparse" means that the caller might use some sampling criteria to

static void progress_interval(int signum)
			strbuf_reset(counters_sb);
	*p_progress = NULL;
	setitimer(ITIMER_REAL, &v, NULL);
	if (progress->delay && (!progress_update || --progress->delay))

}
		strbuf_addf(counters_sb, "%"PRIuMAX"%s", (uintmax_t)n, tp);
{
#include "strbuf.h"
		strbuf_release(&progress->throughput->display);
 */
	struct sigaction sa;
			if (progress->split) {
};
 *
		return progress->start_ns + progress_test_ns;
	if (progress_testing)
#include "config.h"
static int get_default_delay(void)
	uint64_t now_ns;
	uint64_t start_ns;
	struct strbuf counters_sb;
void display_progress(struct progress *progress, uint64_t n)
	progress->delay = delay;
/*
	free(progress);

	uint64_t total;

	progress->last_value = -1;
		strbuf_init(&tp->display, 0);
	unsigned sparse;
	progress->total = total;
	 *	y' = y * 1024 / 1000000000
	tp->idx = (tp->idx + 1) % TP_IDX_MAX;
		/* Force the last update */
	}
		return getnanotime();
		}
				    "%3u%% (%"PRIuMAX"/%"PRIuMAX")%s", percent,
static void finish_if_sparse(struct progress *progress)
	struct progress *progress = *p_progress;
					(int) clear_len, eol);


	if (progress_testing)
			}
}
	if (show_update) {
	return progress;
					progress->title, (int) clear_len, "",
{

 * it under the terms of the GNU General Public License version 2 as
	return start_progress_delay(title, total, get_default_delay(), 1);
	uint64_t last_value;

	strbuf_humanise_rate(buf, rate * 1024);
	}
	 *	z = x / y * 1000000000 / 1024
uint64_t progress_test_ns = 0;
}
	    progress->sparse &&
			} else if (!done && cols < progress_line_len) {
}
			fflush(stderr);

		return;
	struct progress *progress = xmalloc(sizeof(*progress));

		display(progress, progress->last_value, NULL);
					0;
#define TP_IDX_MAX      8
	tp->avg_misecs += misecs;
	if (!progress)
	strbuf_release(&progress->counters_sb);
static struct progress *start_progress_delay(const char *title, uint64_t total,
			progress->last_percent = percent;
	progress->last_percent = -1;
	progress->throughput = NULL;
	return tpgrp < 0 || tpgrp == getpgid(0);
	progress->title = title;
	sigaction(SIGALRM, &sa, NULL);
	if (progress->last_value != -1) {
{
static int is_foreground_fd(int fd)

		display(progress, progress->last_value, buf);
 */
 * integer value in[0 .. total).  In particular, the caller might not call
	 *
	progress->title_len = utf8_strwidth(title);

	 *	y' = y * (2^10 / 2^42) * (2^42 / 1000000000)
{
	/*
		struct throughput *tp = progress->throughput;
	sa.sa_flags = SA_RESTART;
	stop_progress_msg(p_progress, _("done"));
void progress_test_force_update(void)
 * message to show 100%.

	tp->prev_ns = now_ns;
	unsigned int avg_bytes;
		tp->prev_total = tp->curr_total = total;
			strbuf_addf(counters_sb,
	v.it_value = v.it_interval;
static void display(struct progress *progress, uint64_t n, const char *done)
		return;

	struct throughput *tp;


	sigemptyset(&sa.sa_mask);
#include "trace.h"

		show_update = 1;
		progress->throughput = tp = xcalloc(1, sizeof(*tp));
	 *	z = (x / 1024) / (y / 1000000000)
	 *	y' = y / 2^32 * 4398
}
	if (progress->total) {

 * display_progress() for the last value in the range.
		buf = xstrfmt(", %s.\n", msg);
	off_t curr_total;
		delay_in_secs = git_env_ulong("GIT_PROGRESS_DELAY", 2);
 *

	unsigned last_percent;
			uint64_t now_ns = progress_getnanotime(progress);

{
			int cols = term_columns();
	 *
static uint64_t progress_getnanotime(struct progress *progress)
			size_t clear_len = counters_sb->len < last_count_len ?
	struct strbuf display;
}
				fprintf(stderr, "  %s%*s", counters_sb->buf,
void display_throughput(struct progress *progress, uint64_t total)
	progress->split = 0;

			show_update = 1;

	struct throughput *throughput;
	if (progress->last_value != -1 && progress_update)
				fprintf(stderr, "%s: %s%*s", progress->title,
	tp->avg_bytes -= tp->last_bytes[tp->idx];
				clear_len = progress->title_len + 1 < cols ?
		free(buf);
	rate = tp->avg_bytes / tp->avg_misecs;
	else
{
	progress->start_ns = getnanotime();
void progress_test_force_update(void); /* To silence -Wmissing-prototypes */
			misecs = ((now_ns - progress->start_ns) * 4398) >> 32;
					       uint64_t total)
	progress_update = 0;
static volatile sig_atomic_t progress_update;
	}
	memset(&sa, 0, sizeof(sa));
}
	free(progress->throughput);
	if (now_ns - tp->prev_ns <= 500000000)

		}
#include "utf8.h"
	set_progress_signal();

	int tpgrp = tcgetpgrp(fd);
}
		if (tp) {
	strbuf_humanise_bytes(buf, total);
struct progress *start_sparse_progress(const char *title, uint64_t total)
 *
static void clear_progress_signal(void)
}
{
static void throughput_string(struct strbuf *buf, uint64_t total,
#include "cache.h"
					counters_sb->buf, (int) clear_len, eol);

{

	unsigned int last_bytes[TP_IDX_MAX];
	return start_progress_delay(title, total, 0, 1);
	progress_update = 1;
#include "progress.h"

	if (delay_in_secs < 0)
 * published by the Free Software Foundation.
	}
		display_progress(progress, progress->total);
						counters_sb->len + 2;
	tp->avg_bytes += count;

	 *	z = x / (y * 1024 / 1000000000)
	strbuf_addstr(buf, " | ");
			      unsigned int rate)
	tp->last_misecs[tp->idx] = misecs;
	if (!tp) {
	if (progress)
	strbuf_reset(buf);

	static int delay_in_secs = -1;
	if (progress &&
	 * To simplify things we'll keep track of misecs, or 1024th of a sec
	progress->sparse = sparse;
	tp->prev_total = total;

	tp->last_bytes[tp->idx] = count;
		display(progress, n, NULL);
	 */
{
 * When "sparse" is set, stop_progress() will automatically force the done
int progress_testing;
	progress->last_value = n;
	v.it_interval.tv_usec = 0;
				fprintf(stderr, "%s:%*s\n  %s%s",
}
 */
				    tp);
struct progress *start_delayed_sparse_progress(const char *title,
	return delay_in_secs;
	misecs = ((now_ns - tp->prev_ns) * 4398) >> 32;
	tp = progress->throughput;
void stop_progress_msg(struct progress **p_progress, const char *msg)

	v.it_interval.tv_sec = 1;
	strbuf_addstr(buf, ", ");
			} else {
