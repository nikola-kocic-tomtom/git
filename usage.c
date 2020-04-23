{
	va_end(params);
}
	va_end(params);
	int i, j;
{
	return -1;
static void (*error_routine)(const char *err, va_list params) = error_builtin;
#include "cache.h"
	BUG_vfl(NULL, 0, fmt, ap);
	die_routine(fmt_with_err(buf, sizeof(buf), fmt), params);
}
		} else {
	 * manually calls fprintf(stderr,...) with the actual detailed
	va_start(ap, fmt);
	char prefix[256];

	die_routine = routine;
}
	va_end(params);
			j--;
static const char *fmt_with_err(char *buf, int n, const char *fmt)
static NORETURN_PTR void (*usage_routine)(const char *err, va_list params) = usage_builtin;
	va_list params;

int error_errno(const char *fmt, ...)
	err = strerror(errno);
	/* Truncation is acceptable here */

{

		char data[FLEX_ARRAY];
		return 0;
#undef error_errno
	 * syntax error before calling usage().
	 * Currently, the (err, params) are usually just the static usage
}
void set_die_routine(NORETURN_PTR void (*routine)(const char *err, va_list params))
	fflush(stderr);


	 * TODO It would be nice to update the call sites to pass both
	p = msg + prefix_len;
		fprintf(stderr, "BUG!!! too long a prefix '%s'\n", prefix);
void NORETURN die_errno(const char *fmt, ...)
	trace2_cmd_error_va(err, params);
	 * before using it (because an 'ap' can only be walked once).
{
	vreportf("usage: ", err, params);
}
}

	 * cmd_main(), we don't know what verb to report.  Force it to this
	}
#ifdef SUPPRESS_ANNOTATED_LEAKS
{
	 */
#endif
	size_t prefix_len = strlen(prefix);
#undef error
	if (die_is_recursing()) {
		if ((str_error[j++] = err[i++]) != '%')

	 */

/* If we are in a dlopen()ed .so write to a global variable would segfault
	va_start(params, fmt);
static NORETURN void die_builtin(const char *err, va_list params)
/*




	usagef("%s", err);
/* Only set this, ever, from t/helper/, when verifying that bugs are caught. */
			break;

	va_list params;
	}

int BUG_exit_code;
	va_start(params, err);
		struct suppressed_leak_root *next;
	vreportf("error: ", err, params);

	static int dying;
 *
{
#include "git-compat-util.h"
{
	 * the static usage string and the detailed error message.
}
	memcpy(msg, prefix, prefix_len);
	char buf[1024];
static NORETURN void usage_builtin(const char *err, va_list params)
	va_end(params);
	/*

	} else {

	 * string which isn't very useful here.  Usually, the call site
void vreportf(const char *prefix, const char *err, va_list params)
	}
{

}

	*(p++) = '\n'; /* we no longer need a NUL */
{
	va_start(params, warn);
	return -1;
{
	 * to facilitate post-processing.
		snprintf(prefix, sizeof(prefix), "BUG: ");

	if (BUG_exit_code)


	va_list params;
{
	error_routine(fmt_with_err(buf, sizeof(buf), fmt), params);
}
			stderr);
	va_end(params);
		exit(BUG_exit_code);
	FLEX_ALLOC_MEM(root, data, ptr, len);
	va_list params;
	 *
}
 * GIT - The information manager from hell
{
static void error_builtin(const char *err, va_list params)
	vreportf("warning: ", warn, params);

}
	return error_routine;
	for (; p != pend - 1 && *p; p++) {
	exit(129);
	va_end(params);
	va_start(params, warn);
	if (vsnprintf(p, pend - p, err, params) < 0)
	warn_routine = routine;
}
	va_start(params, err);
	/*
}
	die_is_recursing = routine;
{
{
	va_start(params, err);
	die_routine(err, params);
		exit(128);
#endif
	}
			*p = '?';
	 */
	root->next = suppressed_leaks;
{
#else
void NORETURN usage(const char *err)
	}
	if (die_is_recursing()) {
	 */
		abort();

	 * before using it (because an 'ap' can only be walked once).
	suppressed_leaks = root;
			str_error[j++] = '%';
	} else if (dying == 2) {
	vreportf(prefix, fmt, params);
}
	warn_routine(warn, params);
	snprintf(buf, n, "%s: %s", fmt, str_error);
void set_warn_routine(void (*routine)(const char *warn, va_list params))
void (*get_error_routine(void))(const char *err, va_list params)
		fputs("fatal: recursion detected in die handler\n", stderr);
	if (dying > recursion_limit) {
{
void set_die_is_recursing_routine(int (*routine)(void))
	va_end(params);
		snprintf(prefix, sizeof(prefix), "BUG: %s:%d: ", file, line);
	for (i = j = 0; err[i] && j < sizeof(str_error) - 1; ) {
	va_end(ap);

	error_routine(err, params);
		}
{
{
static NORETURN_PTR void (*die_routine)(const char *err, va_list params) = die_builtin;
			continue;
	 * We call this trace2 function first and expect it to va_copy 'params'
	struct suppressed_leak_root *root;



}
	va_start(ap, fmt);
	if (sizeof(msg) <= prefix_len) {
	va_list ap;
}
	/*
void warning(const char *warn, ...)
	va_start(params, fmt);
	trace2_cmd_error_va(err, params);
void NORETURN die(const char *err, ...)
	else
	 * "b" is "something less than Inf", since the point is to

{
#ifdef HAVE_VARIADIC_MACROS
{
	dying++;
	return warn_routine;
void set_error_routine(void (*routine)(const char *err, va_list params))
 * (ugh), so keep things static. */
	 * "maximum number of pthreads we'll ever plausibly spawn" and
	char *p, *pend = msg + sizeof(msg);


	vreportf("fatal: ", err, params);
}
	va_list params;
	exit(128);
	static const int recursion_limit = 1024;
void (*get_warn_routine(void))(const char *warn, va_list params)

void unleak_memory(const void *ptr, size_t len)
{
	 * When we detect a usage error *before* the command dispatch in
void warning_errno(const char *warn, ...)
}
	va_list ap;
		return 1;
	trace2_cmd_name("_usage_");
		return 0;
}

		exit(128);
}
	/*
	abort();
	 * We call this trace2 function first and expect it to va_copy 'params'
	char buf[1024];
{
	/* truncation via snprintf is OK here */

	 * prevent infinite recursion.
{

	 */

	static struct suppressed_leak_root {
void NORETURN usagef(const char *err, ...)


}
	str_error[j] = 0;
	warn_routine(fmt_with_err(buf, sizeof(buf), warn), params);
static void warn_builtin(const char *warn, va_list params)
static int die_is_recursing_builtin(void)
static void (*warn_routine)(const char *err, va_list params) = warn_builtin;
}
	BUG_vfl(file, line, fmt, ap);

	error_routine = routine;
static int (*die_is_recursing)(void) = die_is_recursing_builtin;

		if (iscntrl(*p) && *p != '\t' && *p != '\n')

{
	write_in_full(2, msg, p - msg);
NORETURN void BUG(const char *fmt, ...)
	} *suppressed_leaks;
	/*
int error(const char *err, ...)

{
		if (j < sizeof(str_error) - 1) {


static NORETURN void BUG_vfl(const char *file, int line, const char *fmt, va_list params)
	char buf[1024];
			/* No room to double the '%', so we overwrite it with
NORETURN void BUG_fl(const char *file, int line, const char *fmt, ...)
}
}
	va_list params;
 * Copyright (C) Linus Torvalds, 2005
		*p = '\0'; /* vsnprintf() failed, clip at prefix */
	usage_routine(err, params);
 */
	if (file)
			 * '\0' below */
		fputs("fatal: recursion detected in die_errno handler\n",
	va_list params;
	char msg[4096];
	}
}
	 * Just an arbitrary number X where "a < x < b" where "a" is

		warning("die() called many times. Recursion error or racy threaded death!");
	char str_error[256], *err;


	return buf;
	va_end(ap);

