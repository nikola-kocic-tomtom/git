	};
	struct strbuf line = STRBUF_INIT;
			uint64_t item_count = strtoull(end, &end, 10);
extern uint64_t progress_test_ns;

 *   "update" - Set the 'progress_update' flag.
 *                                  byte count as parameter.  The 'millis'
		NULL
#include "gettext.h"
#include "progress.h"
		char *end;
 */
	const char *usage[] = {
	int total = 0;
/*
	return 0;
	struct option options[] = {
	}
 *
		} else if (!strcmp(line.buf, "update"))
 *
			if (*end != '\0')
 *

	progress_testing = 1;
			progress_test_ns = test_ms * 1000 * 1000;

			display_progress(progress, item_count);
	};
 *                                  specify the time elapsed since the
 *                                  start_progress() call.
	stop_progress(&progress);
		die("need a title for the progress output");
	while (strbuf_getline(&line, stdin) != EOF) {
				die("invalid input: '%s'\n", line.buf);
	const char *title;
	struct progress *progress;
	if (argc != 1)

		OPT_INTEGER(0, "total", &total, "total number of items"),
				       (const char **) &end)) {
 * A test helper to exercise the progress display.
				die("invalid input: '%s'\n", line.buf);
 */
 * These are defined in 'progress.c', but are not exposed in 'progress.h',

 * See 't0500-progress-display.sh' for examples.
 *                        as parameter.
#include "parse-options.h"
			progress_test_force_update();
{
			die("invalid input: '%s'\n", line.buf);
		} else if (skip_prefix(line.buf, "throughput ",
#include "strbuf.h"

		"test-tool progress [--total=<n>] <progress-title>",
	argc = parse_options(argc, argv, NULL, options, usage, 0);
}
			if (*end != ' ')
			uint64_t byte_count, test_ms;
			byte_count = strtoull(end, &end, 10);
void progress_test_force_update(void);
			test_ms = strtoull(end + 1, &end, 10);
#include "test-tool.h"
/*
		OPT_END(),
		if (skip_prefix(line.buf, "progress ", (const char **) &end)) {

 *   "progress <items>" - Call display_progress() with the given item count
int cmd__progress(int argc, const char **argv)
			if (*end != '\0')
	progress = start_progress(title, total);
 * because they are exclusively for testing.
	title = argv[0];

extern int progress_testing;
 * Reads instructions from standard input, one instruction per line:
				die("invalid input: '%s'\n", line.buf);
		else
 *   "throughput <bytes> <millis> - Call display_throughput() with the given
			display_throughput(progress, byte_count);
