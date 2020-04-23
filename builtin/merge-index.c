				force_file = 1;
	read_cache();
	do {
int cmd_merge_index(int argc, const char **argv, const char *prefix)
		die("git merge-index: %s not in the cache", path);
	/* Without this we cannot rely on waitpid() to tell
	}

	int i;
{

static void merge_one_path(const char *path)
	int i, force_file = 0;
	} while (++pos < active_nr);
		arguments[stage + 4] = ownbuf[stage];
	i = 1;
	const char *arguments[] = { pgm, "", "", "", path, "", "", "", NULL };
	if (!found)
	 */

		xsnprintf(ownbuf[stage], sizeof(ownbuf[stage]), "%o", ce->ce_mode);
		oid_to_hex_r(hexbuf[stage], &ce->oid);
	 * already merged and there is nothing to do.
			err++;
			if (!strcmp(arg, "-a")) {
			continue;
			break;
		i++;

	if (err && !quiet)

		if (!ce_stage(ce))
		merge_entry(-pos-1, path);
#include "run-command.h"
}
	 * what happened to our children.
		if (strcmp(ce->name, path))
		die("merge program failed");
			}
}
		found++;
{
		merge_one_path(arg);
{
	}
				merge_all();
		arguments[stage] = hexbuf[stage];
	pgm = argv[i++];
		i += merge_entry(i, ce->name)-1;
	if (run_command_v_opt(arguments, 0)) {
static const char *pgm;
static void merge_all(void)
static int err;
	if (!strcmp(argv[i], "-o")) {
	}
		i++;
static int merge_entry(int pos, const char *path)
	/*
{
		}
static int one_shot, quiet;
	for (; i < argc; i++) {
	}
#include "builtin.h"
	char hexbuf[4][GIT_MAX_HEXSZ + 1];
	return err;
		quiet = 1;
	if (!strcmp(argv[i], "-q")) {
			}

			if (!strcmp(arg, "--")) {
				continue;
		const struct cache_entry *ce = active_cache[i];
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		const char *arg = argv[i];
	}
	int found;
	return found;
	signal(SIGCHLD, SIG_DFL);
	 */
		int stage = ce_stage(ce);
	if (pos < 0)
		}
		usage("git merge-index [-o] [-q] <merge-program> (-a | [--] [<filename>...])");
			exit(1);
	if (argc < 3)
			if (!quiet)
	int pos = cache_name_pos(path, strlen(path));

		const struct cache_entry *ce = active_cache[pos];
		one_shot = 1;
		die("git merge-index: %s not in the cache", path);
				die("merge program failed");
	for (i = 0; i < active_nr; i++) {


}
	if (pos >= active_nr)
			die("git merge-index: unknown option %s", arg);
	 * If it already exists in the cache as stage0, it's
		if (!force_file && *arg == '-') {
		if (one_shot)
		else {
				continue;

	char ownbuf[4][60];

	found = 0;
}


