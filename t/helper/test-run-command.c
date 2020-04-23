		NULL
	/* Then close it, and try to delete it. */
		if (i < skip)

	if (argc > 1 && !strcmp(argv[1], "testsuite"))
	proc.argv = (const char **)argv + 3;


				argv_array_push(&args, buf);

/*
		die("Could not start child process");
	struct strbuf out = STRBUF_INIT;

	argv_array_pushl(&cp.args,


static int no_job(struct child_process *cp,
{
			 "be verbose, redirected to a file"),

	 */

		string_list_append(&suite->failed, name);
		for (i = 0; i < argc; i++)
		}
			arg_count = argc;
	if (max_jobs <= 0)
		OPT_BOOL('q', "quiet", &suite.quiet, "be terse"),
	const char *test;
		die("Could not open the current directory");
#include "git-compat-util.h"
	char special[] = ".?*\\^_\"'`{}()[]<>@~&+:;$%"; // \t\r\n\a";
	return res;
	if (start_command(&cp) < 0)
	if (!dir)

		/* No pattern: match all */
			fprintf(stderr, "Trials completed: %d\n", (int)i);
	argv_array_clear(&args);
		die("Could not delete '%s'", path);
					(my_random() % (ARRAY_SIZE(buf) - min_len));
					     arg, out.buf + k);
static int number_callbacks;
	strbuf_release(&buf);
		exit(inherit_handle_child());
	 * We are running a quote-stress test.
	*task_cb = (void *)test;

	int next;

 *
		exit(run_processes_parallel(jobs, parallel_next,
{

	};

#include "strbuf.h"
	suite.tests.strdup_strings = suite.failed.strdup_strings = 1;

	struct option options[] = {
#include "parse-options.h"
	};
	if (!strcmp(argv[1], "start-command-ENOENT")) {

	int tmp;

			testsuite_usage, PARSE_OPT_STOP_AT_NON_OPTION);
}
	if (!strcmp(argv[1], "run-command-abort"))

		if (start_command(&proc) < 0 && errno == ENOENT)
	}
	struct dirent *d;

				     (int)out.len, (int)k);
}
		if (msys2)
		suite.tests.nr, max_jobs);

}
	memset(&suite, 0, sizeof(suite));
		else

		}
		argv_array_push(&cp->args, "-x");

{
struct testsuite {
		  void *cb,
	struct argv_array args = ARGV_ARRAY_INIT;
		exit(run_processes_parallel(jobs, no_job,
			}
	DIR *dir;
		OPT_BOOL('v', "verbose", &suite.verbose, "be verbose"),
		} else {
		return 1;
	string_list_append(&suite->failed, name);
			const char *arg = args.argv[j + arg_offset];
		max_jobs = suite.tests.nr;
					 "quote-echo", NULL);
			return 0;
#include "run-command.h"

{
#include "thread-utils.h"
	strbuf_addstr(err, "no further jobs available\n");
			ret = error("got %d bytes, but consumed only %d",
 * it under the terms of the GNU General Public License version 2 as
			continue;
		arg_offset = args.argc;
		"test-tool run-command quote-stress-test <options>",
	if (suite->quiet)
	fprintf(stderr, "Running %d tests (%d at a time)\n",
				argv_array_push(&args, argv[j]);
	return 1;
	struct child_process cp = CHILD_PROCESS_INIT;
}
		OPT_END()
{
		return !!quote_stress_test(argc - 1, argv + 1);
			 void **task_cb)
	jobs = atoi(argv[2]);
int cmd__run_command(int argc, const char **argv)
	if (!strcmp(argv[1], "run-command-no-jobs"))
			argv_array_clear(&args);
	if (suite->verbose_log)
	cp.in = -1;
static int test_finished(int result, struct strbuf *err, void *cb,
			for (j = 0; j < arg_count; j++)
		    !isdigit(p[3]) || !isdigit(p[4]) || p[5] != '-' ||
		if (*p != 't' || !isdigit(p[1]) || !isdigit(p[2]) ||
		return 0;
		argv_array_push(&cp->args, "-v");
	if (!strcmp(argv[1], "inherited-handle-child"))
	char path[PATH_MAX];
			 void *cb,
		if (i && (i % 100) == 0)
	NULL

			 "test-tool", argv0, "inherited-handle-child", NULL);
{
	argv_array_pushl(&cp->args, "sh", test, NULL);
static uint64_t my_random(void)
	strbuf_addf(out, "FAILED TO START: '%s'\n", name);
		OPT_INTEGER('n', "trials", &trials, "Number of trials"),
		return 1;
	const char *name = (const char *)task_cb;
 * published by the Free Software Foundation.
		size_t arg_count, arg_offset;
	return 0;
		return 1;
		max_jobs = online_cpus();
		ret = 1;


	if (close(cp.in) < 0 || finish_command(&cp) < 0)
	return 1;

				break;
{
static int quote_stress_test(int argc, const char **argv)
		OPT_BOOL('V', "verbose-log", &suite.verbose_log,

			fprintf(stderr, "\t%s\n", suite.failed.items[i].string);
	 * were passed in.
	if (!suite.tests.nr)
				     test_finished, &suite);
		fprintf(stderr, "%d tests failed:\n\n", suite.failed.nr);

	return 1;
	struct string_list tests, failed;
			argv_array_pushl(&args, "sh", "-c",
static int quote_echo(int argc, const char **argv)

				string_list_append(&suite.tests, p);
	if (argc < 3)

		OPT_END()
	tmp = xmkstemp(path);
	cp.no_stdout = cp.no_stderr = 1;
			die("env specifier without a value");
	strbuf_release(&out);
			return ret;
{
	struct testsuite suite = TESTSUITE_INIT;

}

		OPT_BOOL(0, "write-junit-xml", &suite.write_junit_xml,
	strbuf_addf(err, "Output of '%s':\n", test);
	int quiet, immediate, verbose, verbose_log, trace, write_junit_xml;

	{ STRING_LIST_INIT_DUP, STRING_LIST_INIT_DUP, -1, 0, 0, 0, 0, 0, 0 }


#include "wildmatch.h"
	argv_array_pushv(&cp->args, d->argv);

 */
	struct child_process proc = CHILD_PROCESS_INIT;
			 struct strbuf *err,
					    "echoed back as '%s'",
			fprintf(stderr, "Trial #%d failed. Arguments:\n", i);
		argv_array_push(&cp->args, "--quiet");
 * (C) 2009 Ilari Liusvaara <ilari.liusvaara@elisanet.fi>

		die("No tests match!");
		if (argc > 0) {
			 "stop at first failed test case(s)"),
					    NULL, task_finished, &proc));
	if (!strcmp(argv[1], "run-command-parallel"))
		argv_array_push(&proc.env_array, argv[2]);
}
	string_list_clear(&suite.tests, 0);
			continue;
	return 0;
}



	/*
	if (suite->write_junit_xml)

	struct option options[] = {
	/* First, open an inheritable handle */
	my_random_next = my_random_next * 1103515245 + 12345;

	}
				size_t min_len = 1;
	if (unlink(path))
static int test_failed(struct strbuf *out, void *cb, void *task_cb)
		const char *p = d->d_name;
			if (strcmp(arg, out.buf + k))
};
			 void *pp_task_cb)

				char buf[20];
						ARRAY_SIZE(special)];
}
{
		if (ret) {
			if (!wildmatch(argv[i], p, 0)) {
		struct child_process cp = CHILD_PROCESS_INIT;


#include "test-tool.h"

		argv++;


	return !!ret;
	}
	return 0;
{
			return error("Failed to spawn child process");
{
	setenv("MSYS_NO_PATHCONV", "1", 0);
}
	if (suite->verbose)
		strbuf_reset(&out);
	if (suite->next >= suite->tests.nr)
			for (j = 0; j < arg_count; j++)
	struct testsuite *suite = cb;
	closedir(dir);
			}
 *
	}
	};

	close(tmp);
		OPT_BOOL('x', "trace", &suite.trace, "trace shell commands"),

	argc = parse_options(argc, argv, NULL, options, usage, 0);

		OPT_INTEGER('j', "jobs", &max_jobs, "run <N> jobs in parallel"),
	if (suite.failed.nr > 0) {
	printf("Received %s\n", buf.buf);
	if (suite->immediate)
}

	strbuf_addstr(err, "asking for a quick stop\n");

		die("Child did not finish");
static int inherit_handle_child(void)
#include "parse-options.h"
					    NULL, NULL, &proc));
	uint64_t res = my_random_next;
		exit(testsuite(argc - 1, argv + 1));
static int parallel_next(struct child_process *cp,
	for (i = 0; i < trials; i++) {
					    NULL, task_finished, &proc));
		argv += 2;
	proc.argv = (const char **)argv + 2;

	argc = parse_options(argc, argv, NULL, options,

	while ((d = readdir(dir))) {
			trials = 1;
}

	number_callbacks++;
		}
		  struct strbuf *err,

static int next_test(struct child_process *cp, struct strbuf *err, void *cb,
		fwrite(argv[1], strlen(argv[1]), 1, stdout);
				for (k = 0; k < arg_len; k++)
	if (!strcmp(argv[1], "run-command"))
static int inherit_handle(const char *argv0)
	return 0;
		argc--;
static int testsuite(int argc, const char **argv)
	strbuf_addf(err, "%s: '%s'\n", result ? "FAIL" : "SUCCESS", name);
					buf[k] = special[my_random() %
				buf[arg_len] = '\0';

	if (suite->trace)
		argv_array_push(&cp->args, "-i");
		}
	if (number_callbacks >= 4)
}
			for (j = 0; j < arg_count; j++) {
	return 0;


	struct testsuite *suite = cb;
	if (!strcmp(argv[1], "inherited-handle"))
	"test-run-command testsuite [<options>] [<pattern>...]",
	if (argc >= 2 && !strcmp(argv[1], "quote-echo"))
		     void **task_cb)
			k += strlen(out.buf + k) + 1;

		for (j = 0, k = 0; j < arg_count; j++) {
	int jobs;
				ret = error("incorrectly quoted arg: '%s', "
			string_list_append(&suite.tests, p);
			arg_count = 1 + (my_random() % 5);
		OPT_INTEGER('s', "skip", &skip, "Skip <n> trials"),

	 * spawn a subprocess that runs quote-stress with a
		for (i = 0; i < suite.failed.nr; i++)
	fprintf(stderr, "check usage\n");
	test = suite->tests.items[suite->next++].string;
			continue;
		fputc('\0', stdout);
}
		cp.argv = args.argv;
			 void *pp_cb,
	const char * const usage[] = {
	int i, j, k, trials = 100, skip = 0, msys2 = 0;
	ret = run_processes_parallel(max_jobs, next_test, test_failed,
	if (argc >= 2 && !strcmp(argv[1], "quote-stress-test"))
		if (!argc) {
static int task_finished(int result,
	const char *name = (const char *)task_cb;
	if (argc < 3)
#include "gettext.h"
	struct strbuf buf = STRBUF_INIT;
	struct child_process *d = cb;


	 * special option that echoes back the arguments that
		argv_array_push(&cp->args, "--write-junit-xml");
	if (strbuf_read(&buf, 0, 0) < 0)
#include "string-list.h"
	if (result)
			argv_array_pushl(&args, "test-tool", "run-command",
	}
		argv_array_clear(&args);
		exit(run_processes_parallel(jobs, parallel_next,

	}

	return 1;
		return !!quote_echo(argc - 1, argv + 1);
		if (!argv[2])
	while (argc > 1) {

		OPT_BOOL('m', "msys2", &msys2, "Test quoting for MSYS2's sh"),

static uint64_t my_random_next = 1234;
 * This code is free software; you can redistribute it and/or modify
					 "printf %s\\\\0 \"$@\"", "skip", NULL);
	struct testsuite *suite = cb;
					(int)j, args.argv[j + arg_offset]);


#define TESTSUITE_INIT \
	int max_jobs = 1, i, ret;
		if (k != out.len)
	if (max_jobs > suite.tests.nr)

 * test-run-command.c: test run command API.
				size_t arg_len = min_len +
		exit(run_command(&proc));
	dir = opendir(".");
	return 0;
		argc -= 2;

	strbuf_addstr(err, "preloaded output of a child\n");
			strbuf_release(&out);
		int ret = 0;
};
		argv_array_push(&cp->args, "-V");
				fprintf(stderr, "arg #%d: '%s'\n",
#include "cache.h"
		  void **task_cb)
		return 0;
		if (pipe_command(&cp, NULL, 0, &out, 0, NULL, 0) < 0)
			 void *task_cb)
	string_list_clear(&suite.failed, 0);
			 "write JUnit-style XML files"),
static const char * const testsuite_usage[] = {
	return 0;
{
		die("Could not read stdin");
	while (!strcmp(argv[1], "env")) {
		fprintf(stderr, "FAIL %s\n", argv[1]);
		exit(inherit_handle(argv[0]));
#include "argv-array.h"
		OPT_BOOL('i', "immediate", &suite.immediate,

		    !ends_with(p, ".sh"))
{
			 struct strbuf *err,
	xsnprintf(path, sizeof(path), "out-XXXXXX");

