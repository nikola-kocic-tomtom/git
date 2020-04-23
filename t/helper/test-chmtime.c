 *
 *	test-tool chmtime +<seconds> (or -<seconds>) file...
	if (timespec_arg(argv[i], &set_time, &set_eq)) {


#include <utime.h>
		if (get == 0) {
			printf("%"PRIuMAX"\n", mtime);

 * file(s) or just print it. The program does not change atime or
		if (!(sb.st_mode & S_IWUSR) &&
 * the file mtime offset to 0:

#include "git-compat-util.h"
	if ((*set_eq && *set_time < 0) || *set_eq == 2) {
	}

 *
 * Examples:
	if (*set_eq) {
				chmod(argv[i], sb.st_mode | S_IWUSR)) {
		} else if (verbose) {

#endif
 *	test-tool chmtime <seconds> file...
	if (i == argc) {
 *
	} else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {

	}
		goto usage;
		}

		mtime = utb.modtime < 0 ? 0: utb.modtime;
	const char *timespec = arg;
		uintmax_t mtime;
		if (stat(argv[i], &sb) < 0) {
		utb.actime = sb.st_atime;
}
		++i;
	long int set_time = 0;
			        argv[i], strerror(errno));
		}
	fprintf(stderr, "usage: %s %s\n", argv[0], usage_str);


	}
{
		struct utimbuf utb;
			return 1;
	if (strcmp(argv[i], "--get") == 0 || strcmp(argv[i], "-g") == 0) {
 *
 * To set the mtime to current time:

	static int verbose;
		get = 1;
	}
 *	test-tool chmtime -v +0 file

 *
 *
		if (*timespec == '+') {
			fprintf(stderr, "Failed to stat %s: %s\n",
		goto usage;
			goto usage;
 *	test-tool chmtime --get +1 file
		time_t now = time(NULL);
int cmd__chmtime(int argc, const char **argv)
		}
		verbose = 1;
 *	test-tool chmtime =+0 file

 *
	}
#ifdef GIT_WINDOWS_NATIVE
	int i = 1;
		timespec++;

	for (; i < argc; i++) {
 *
}
	}
 *	test-tool chmtime =+<seconds> (or =-<seconds>) file...
	int set_eq = 0;
	*set_eq = (*timespec == '=') ? 1 : 0;
		}
	} else {
 *

		++i;
		if (get) {
		goto usage;
 * ctime (their values are explicitly preserved).
 * The mtime can be changed to an absolute value:
	*set_time = strtol(timespec, &test, 10);
		return 0;
static const char usage_str[] =
			printf("%"PRIuMAX"\t%s\n", mtime, argv[i]);
static int timespec_arg(const char *arg, long int *set_time, int *set_eq)
			return 1;
		if (utb.modtime != sb.st_mtime && utime(argv[i], &utb) < 0) {
usage:
	if (argc < 3)
		++i;
		}
{
 * To print the mtime and the file name use --verbose and set
			fprintf(stderr, "Not a base-10 integer: %s\n", argv[i] + 1);
 *
	if (i == argc)
 *
 *
			return 1;
 * To set the file mtime offset to +1 and print the new value:
		utb.modtime = set_eq ? set_time : sb.st_mtime + set_time;
 *
 *	test-tool chmtime =<seconds> file...
 *
		struct stat sb;
		}
		*set_time += now;
	"(-v|--verbose|-g|--get) (+|=|=+|=-|-)<seconds> <file>...";
	/* no mtime change by default */
 *
			*set_eq = 2; /* relative "in the future" */
 *
	static int get;
			        argv[i], strerror(errno));
#include "test-tool.h"
			timespec++;
			fprintf(stderr, "Could not make user-writable %s: %s",
				argv[i], strerror(errno));
	return 0;
	return 1;

 * Or relative to the current mtime of the file:
 * To print only the mtime use --get:
 *	test-tool chmtime --get file
/*

	}
	return 1;
	char *test;
	if (*test) {
 * This program can either change modification time of the given
			fprintf(stderr, "Failed to modify time on %s: %s\n",
 */
 * Relative to the current time as returned by time(3):
