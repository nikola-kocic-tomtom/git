#include "builtin.h"
	 * normalize these forms to "foo.pack" for "index-pack --verify".
			     verify_pack_usage, 0);

	argv[2] = arg.buf;
		argv[1] = "--verify";

		strbuf_addstr(&arg, ".pack");
		else {
}
		if (verify_one_pack(argv[i], flags))
	return err;
				printf("%s: ok\n", arg.buf);
static const char * const verify_pack_usage[] = {
	strbuf_addstr(&arg, path);
	N_("git verify-pack [-v | --verbose] [-s | --stat-only] <pack>..."),
	if (stat_only)
		OPT_BIT('s', "stat-only", &flags, N_("show statistics only"),
	int stat_only = flags & VERIFY_PACK_STAT_ONLY;
	return err;
	struct strbuf arg = STRBUF_INIT;
int cmd_verify_pack(int argc, const char **argv, const char *prefix)
static int verify_one_pack(const char *path, unsigned int flags)
	/*
		argv[1] = "--verify-stat";
		argv[1] = "--verify-stat-only";
	 */
	const char *argv[] = {"index-pack", NULL, NULL, NULL };

		if (err)
	else
			VERIFY_PACK_STAT_ONLY),

	 * In addition to "foo.pack" we accept "foo.idx" and "foo";
}
};

	struct child_process index_pack = CHILD_PROCESS_INIT;

	if (strbuf_strip_suffix(&arg, ".idx") ||
			printf("%s: bad\n", arg.buf);
	unsigned int flags = 0;

		OPT_BIT('v', "verbose", &flags, N_("verbose"),
	    !ends_with(arg.buf, ".pack"))
	index_pack.git_cmd = 1;

{
			err = 1;
			if (!stat_only)
	if (verbose || stat_only) {
	int verbose = flags & VERIFY_PACK_VERBOSE;
	int i;
	err = run_command(&index_pack);
	else if (verbose)
	NULL
	}
		usage_with_options(verify_pack_usage, verify_pack_options);
	int err;
#include "config.h"


{
	if (argc < 1)
	strbuf_release(&arg);
#define VERIFY_PACK_STAT_ONLY 02
		OPT_END()
#include "cache.h"
	for (i = 0; i < argc; i++) {

#include "run-command.h"
	argc = parse_options(argc, argv, prefix, verify_pack_options,
	const struct option verify_pack_options[] = {
	};
	index_pack.argv = argv;
			VERIFY_PACK_VERBOSE),
#include "parse-options.h"
#define VERIFY_PACK_VERBOSE 01
	}

		}
	git_config(git_default_config, NULL);
	int err = 0;
