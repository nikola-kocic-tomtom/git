

static void print_trace_line(struct trace_key *key, struct strbuf *buf)
		/* initialize offset if high resolution timer works */
void trace_performance_leave(const char *format, ...)
	if (!trace_want(key))
	strbuf_complete_line(buf);
	trace_performance_vprintf_fl(NULL, 0, getnanotime() - start,
		BUG("Too deep indentation");
	time_t secs;

{
	       ((scaled_low_ns * cnt.LowPart) >> scale);
}
		case '\\': strbuf_addstr(&new_path, "\\\\"); break;
		warning("unable to write trace for %s: %s",

		return;
			key->fd = fd;
	trace_printf_key(&trace_setup_key, "setup: git_common_dir: %s\n", quote_crnl(get_git_common_dir()));
	va_list ap;
	/* print current timestamp */

}
{
}
void trace_command_performance(const char **argv)

	}
	va_start(ap, format);
	static int scale;
	struct tm tm;
	key->initialized = 1;
			"         If you want to trace into a file, then please set %s\n"

static uint64_t perf_start_times[10];




{
			offset = 1;

	strbuf_vaddf(&buf, format, ap);

	static const char space[] = "          ";

		warning("unknown trace value for '%s': %s\n"
		perf_indent--;
void trace_printf_key_fl(const char *file, int line, struct trace_key *key,
		strbuf_addf(&buf, ":%.*s ", perf_indent, space);
}

static void trace_argv_vprintf_fl(const char *file, int line,
	va_end(ap);
	struct timespec ts;

	return key->fd;
	va_end(ap);
		return key->fd;

	struct strbuf buf = STRBUF_INIT;
	trace_write(key, buf, len);
#else
		} else {
	va_end(ap);
	va_start(ap, format);
	}
		close(key->fd);
		path++;
 *
	struct strbuf buf = STRBUF_INIT;
	strbuf_release(&buf);

{
{
#endif

			     const char *format, va_list ap)
		key->fd = atoi(trace);
	else if (is_absolute_path(trace)) {
	va_list ap;
void trace_verbatim(struct trace_key *key, const void *buf, unsigned len)
}
		return;
}
{
{
	now = getnanotime();
 * Returns nanoseconds since the epoch (01/01/1970), for performance tracing
	va_end(ap);
}
	/* align trace output (column 40 catches most files names in git) */
	gettimeofday(&tv, NULL);
	/* print file:line */
	trace_performance_vprintf_fl(file, line, nanos - since, format, ap);
			  const char *format, ...)
	return now;
}

	va_start(ap, format);
	struct timeval tv;

void trace_argv_printf(const char **argv, const char *format, ...)

	return new_path.buf;
	if (key->need_close)
			key->need_close = 1;
	strbuf_reset(&command_line);
}
	print_trace_line(&trace_perf_key, &buf);
{

		uint64_t now = gettimeofday_nanos();
void trace_performance_fl(const char *file, int line, uint64_t nanos,
			scaled_low_ns >>= 1;
 *  GNU General Public License for more details.
	trace = getenv(key->key);
 *  This program is distributed in the hope that it will be useful,
	if (!format) /* Allow callers to leave without tracing anything */
	else
void trace_performance_since(uint64_t start, const char *format, ...)

		if (highres)
	key->need_close = 0;
		while (scaled_low_ns >= 0x100000000LL) {
#elif defined (GIT_WINDOWS_NATIVE)
		/* initialization succeeded, return offset + high res time */
		return;
	if (!prefix)
	return (uint64_t) ts.tv_sec * 1000000000 + ts.tv_nsec;
	free(cwd);
	va_start(ap, format);
		scale = 32;
		return;

	va_end(ap);
{
	if (!path)
void trace_performance_leave_fl(const char *file, int line,
		strbuf_addch(buf, ' ');
	return (uint64_t) tv.tv_sec * 1000000000 + tv.tv_usec * 1000;
 */
	localtime_r(&secs, &tm);

{
	if (trace_want(&trace_bare))

	if (!format) /* Allow callers to leave without tracing anything */
			warning("could not open '%s' for tracing: %s",
}

		 * high_ns >> 32). For maximum precision, we scale this factor

	}
		high_ns = (1000000000LL << 32) / (uint64_t) cnt.QuadPart;
 * Copyright (C) 2006 Christian Couder
void trace_argv_printf_fl(const char *file, int line, const char **argv,
}
	va_start(ap, format);
	trace_printf_key(&trace_setup_key, "setup: worktree: %s\n", quote_crnl(git_work_tree));
static void print_command_performance_atexit(void)
	va_list ap;
			scale--;
	strbuf_release(&buf);
				  va_list ap)
	trace_write(key, buf->buf, buf->len);
}

	gettimeofday(&tv, NULL);

	strbuf_addbuf(&buf, data);


}

	uint64_t now;

	static struct trace_key trace_bare = TRACE_KEY_INIT(BARE);
	uint64_t since;
	    !strcmp(trace, "0") || !strcasecmp(trace, "false"))
		/* high_ns = number of ns per cnt.HighPart */
{
{
	strbuf_addf(buf, "%s:%d ", file, line);

	strbuf_release(&buf);
			key->key, trace, key->key);
}
	va_start(ap, format);
			      const char *format, ...)
	va_list ap;
		atexit(print_command_performance_atexit);


	print_trace_line(key, &buf);
		git_work_tree = "(null)";
	strbuf_reset(&new_path);
	since = perf_start_times[perf_indent];
{
	if (perf_indent)
	if (write_in_full(get_trace_fd(key), buf, len) < 0) {


	const char *git_work_tree;
		    tm.tm_sec, (long) tv.tv_usec);
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		if (perf_indent >= strlen(space))
static inline uint64_t gettimeofday_nanos(void)

static const char *quote_crnl(const char *path)
#include "quote.h"
		 */
void trace_performance(uint64_t nanos, const char *format, ...)
		prefix = "(null)";
	}
	uint64_t since;
			BUG("Too deep indentation");
	char *cwd;
	static uint64_t high_ns, scaled_low_ns;

}
static void trace_performance_vprintf_fl(const char *file, int line,
	if (offset > 1) {
/*
uint64_t trace_performance_enter(void)

	strbuf_release(&buf);
	return !!get_trace_fd(key);
static int get_trace_fd(struct trace_key *key)

	if (!prepare_trace_line(file, line, &trace_default_key, &buf))
	trace_performance_vprintf_fl(NULL, 0, nanos, format, ap);
	else if (!strcmp(trace, "1") || !strcasecmp(trace, "true"))
}
			key->key, strerror(errno));
{
		uint64_t highres = highres_nanos();
{
#include "cache.h"
					 va_list ap)

				     format, ap);
	va_end(ap);


	trace_printf_key(&trace_setup_key, "setup: prefix: %s\n", quote_crnl(prefix));
	if (!prepare_trace_line(file, line, key, &buf))
void trace_printf_key(struct trace_key *key, const char *format, ...)
	va_list ap;
	trace_performance_vprintf_fl(NULL, 0, getnanotime() - since,
	cwd = xgetcwd();
	if (!prepare_trace_line(file, line, key, &buf))
	va_list ap;
	key->initialized = 1;

	}
		return;
static int perf_indent;
		return NULL;

	if (!(git_work_tree = get_git_work_tree()))



}


	if (!scale) {

}
	va_start(ap, format);
 *
			return 0;
	va_list ap;
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
{
	static struct strbuf new_path = STRBUF_INIT;
	if (!trace_want(key))
int trace_want(struct trace_key *key)
{
{
#ifdef HAVE_VARIADIC_MACROS

	} else {
	if (!prepare_trace_line(file, line, &trace_perf_key, &buf))


		return;
}
				trace, strerror(errno));
void trace_strbuf_fl(const char *file, int line, struct trace_key *key,


		default:
	sq_quote_argv_pretty(&command_line, argv);
	va_end(ap);
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
# define highres_nanos() 0
/* FIXME: move prefix to startup_info struct and get rid of this arg */

 *
static void trace_write(struct trace_key *key, const void *buf, unsigned len)
}
		return 0;
}
	/* if QPF worked on initialization, we expect QPC to work as well */
		case '\n': strbuf_addstr(&new_path, "\\n"); break;
{
	va_end(ap);
	} else {
	}

	trace_performance_leave("git command:%s", command_line.buf);
	key->fd = 0;
		perf_indent--;
		key->fd = 0;

	print_trace_line(key, &buf);
{
		return;

	return (high_ns * cnt.HighPart) +
{
	va_start(ap, format);
{
 * Copyright (C) 2006 Mike McCormack
 * (i.e. favoring high precision over wall clock time accuracy).

			trace_disable(key);
	struct strbuf buf = STRBUF_INIT;
#if defined(HAVE_CLOCK_GETTIME) && defined(HAVE_CLOCK_MONOTONIC)
}
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	trace_performance_vprintf_fl(file, line, nanos, format, ap);
		if (!QueryPerformanceFrequency(&cnt))
	LARGE_INTEGER cnt;
void trace_disable(struct trace_key *key)
	/* unit tests may want to disable additional trace output */


#endif /* HAVE_VARIADIC_MACROS */
}
{
		}
	va_end(ap);
	trace_vprintf_fl(NULL, 0, &trace_default_key, format, ap);
 *  This program is free software; you can redistribute it and/or modify
		trace_disable(key);
	since = perf_start_times[perf_indent];

	va_list ap;
	strbuf_addf(buf, "%02d:%02d:%02d.%06ld ", tm.tm_hour, tm.tm_min,
static inline uint64_t highres_nanos(void)
		return offset + highres_nanos();
{

	/* don't open twice */
void trace_repo_setup(const char *prefix)
				  const char **argv, const char *format,

		return now;
 *  You should have received a copy of the GNU General Public License
		/*

		if (fd == -1) {


	va_start(ap, format);
		scaled_low_ns = high_ns;
	trace_printf_key(&trace_setup_key, "setup: git_dir: %s\n", quote_crnl(get_git_dir()));
	if (!trace_want(&trace_perf_key))
				     format, ap);
static void trace_vprintf_fl(const char *file, int line, struct trace_key *key,
struct trace_key trace_setup_key = TRACE_KEY_INIT(SETUP);
struct trace_key trace_default_key = { "GIT_TRACE", 0, 0, 0 };
	struct timeval tv;
void trace_strbuf(struct trace_key *key, const struct strbuf *data)
					 uint64_t nanos, const char *format,
}
		return 1;

struct trace_key trace_perf_key = TRACE_KEY_INIT(PERFORMANCE);
	if (perf_indent + 1 < ARRAY_SIZE(perf_start_times))
 *  (at your option) any later version.
 *
static struct strbuf command_line = STRBUF_INIT;
static inline uint64_t highres_nanos(void)
		 * Number of ns per cnt.LowPart is 10^9 / frequency (or
 * Copyright (C) 2002-2004 Oswald Buddenhagen <ossi@users.sf.net>

	else if (strlen(trace) == 1 && isdigit(*trace))
	va_end(ap);
	print_trace_line(&trace_default_key, &buf);
/* Get a trace file descriptor from "key" env variable. */
{
	trace_strbuf_fl(NULL, 0, key, data);
}
		}
		return gettimeofday_nanos();
	const char *trace;
	if (!trace_want(&trace_setup_key))


 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
		switch (*path) {
	if (!trace || !strcmp(trace, "") ||
		return 0;
		     const struct strbuf *data)
}
		trace_disable(key);
	if (!trace_want(&trace_perf_key))


	trace_argv_vprintf_fl(file, line, argv, format, ap);
		/* initialization failed, fall back to gettimeofday */
 * GIT - The information manager from hell
	if (!command_line.len)
}
	strbuf_addf(&buf, "performance: %.9f s", (double) nanos / 1000000000);
	va_start(ap, format);
 *  the Free Software Foundation; either version 2 of the License, or
		int fd = open(trace, O_WRONLY | O_APPEND | O_CREAT, 0666);
		return 0;
	sq_quote_argv_pretty(&buf, argv);
			strbuf_addch(&new_path, *path);

{
		key->fd = STDERR_FILENO;
	return 1;
uint64_t getnanotime(void)
		perf_indent++;
		else
	} else if (offset == 1) {
 */
		}
		return;
	perf_start_times[perf_indent] = now;
			      struct trace_key *key, struct strbuf *buf)
	trace_argv_vprintf_fl(NULL, 0, argv, format, ap);
	while (*path) {
{
	trace_vprintf_fl(file, line, key, format, ap);
	QueryPerformanceCounter(&cnt);
 * Copyright (C) 2004 Theodore Y. Ts'o <tytso@mit.edu>
static int prepare_trace_line(const char *file, int line,
	if (perf_indent)

#else
	struct strbuf buf = STRBUF_INIT;
				uint64_t nanos, const char *format, ...)
		 * so that it just fits within 32 bit (i.e. won't overflow if
{
			 const char *format, ...)
		 * multiplied with cnt.LowPart).
}
	while (buf->len < 40)
		strbuf_vaddf(&buf, format, ap);
	secs = tv.tv_sec;
/*
void trace_printf(const char *format, ...)
	va_list ap;


{
			offset = now - highres;
{
	static uint64_t offset;
}
 *  it under the terms of the GNU General Public License as published by
		case '\r': strbuf_addstr(&new_path, "\\r"); break;
#endif
	if (format && *format) {
}
			"         to an absolute pathname (starting with /)",
	strbuf_vaddf(&buf, format, ap);

	trace_printf_key(&trace_setup_key, "setup: cwd: %s\n", quote_crnl(cwd));

#ifndef HAVE_VARIADIC_MACROS
		return;
	va_list ap;
	if (key->initialized)

}

	trace_performance_enter();
	trace_vprintf_fl(NULL, 0, key, format, ap);
{
