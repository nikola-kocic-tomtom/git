	}
	argc = parse_options_cmd_bundle(argc, argv, prefix,
	memset(&header, 0, sizeof(header));
static int cmd_bundle_create(int argc, const char **argv, const char *prefix) {
	struct option options[] = {
static const char * const builtin_bundle_verify_usage[] = {

	memset(&header, 0, sizeof(header));
	const char* bundle_file;
		PARSE_OPT_STOP_AT_NON_OPTION);
static int cmd_bundle_list_heads(int argc, const char **argv, const char *prefix) {

	};
	argc = parse_options(argc, argv, prefix, options, builtin_bundle_usage,


	/* bundle internals use argv[1] as further parameters */
static int parse_options_cmd_bundle(int argc,
};
static int cmd_bundle_verify(int argc, const char **argv, const char *prefix) {
 * This function can create a bundle or provide information on an existing
		return 1;
	};
		return 1;
	int all_progress_implied = 0;
	int newargc;


	if ((bundle_fd = read_bundle_header(bundle_file, &header)) < 0)
  N_("git bundle list-heads <file> [<refname>...]"),
  N_("git bundle list-heads <file> [<refname>...]"),
	struct bundle_header header;
  N_("git bundle create [<options>] <file> <git-rev-list args>"),
			    N_("do not show bundle details")),
	int bundle_fd = -1;
  NULL
	if (argc < 1)
		result = cmd_bundle_unbundle(argc, argv, prefix);
	/* bundle internals use argv[1] as further parameters */
#include "parse-options.h"

  N_("git bundle create [<options>] <file> <git-rev-list args>"),
		die(_("Need a repository to unbundle."));
};
			builtin_bundle_verify_usage, options, &bundle_file);
		usage_with_options(usagestr, options);
		OPT_BOOL('q', "quiet", &quiet,
		die(_("Need a repository to create a bundle."));
		argv_array_push(&pack_opts, "--progress");
 * Invocation must include action.
		OPT_END()
static const char * const builtin_bundle_usage[] = {
	struct option options[] = {
	int bundle_fd = -1;

			builtin_bundle_create_usage, options, &bundle_file);

		OPT_END()
			    N_("show progress meter during object writing phase"), 2),
	close(bundle_fd);
	/* bundle internals use argv[1] as further parameters */

	if (verify_bundle(the_repository, &header, !quiet))
	if (argc < 2)
	else {
static int verbose;
		OPT_END()
		result = cmd_bundle_create(argc, argv, prefix);
  N_("git bundle verify [<options>] <file>"),
}
	argc = parse_options_cmd_bundle(argc, argv, prefix,
		usage_with_options(builtin_bundle_usage, options);
	int bundle_fd = -1;
	struct option options[] = {
};

	fprintf(stderr, _("%s is okay\n"), bundle_file);
		OPT_SET_INT('q', "quiet", &progress,
	return !!create_bundle(the_repository, bundle_file, argc, argv, &pack_opts);


	packet_trace_identity("bundle");
	struct option options[] = {
	/* bundle internals use argv[1] as further parameters */
	};
	if ((bundle_fd = read_bundle_header(bundle_file, &header)) < 0)
			 &all_progress_implied,
	int quiet = 0;
	if (!startup_info->have_repository)
			builtin_bundle_unbundle_usage, options, &bundle_file);
		OPT_SET_INT(0, "all-progress", &progress,
		OPT_END()
			 N_("similar to --all-progress when progress meter is shown")),
}


		const struct option options[],
		const char **argv,
/*
	memset(&header, 0, sizeof(header));

	if (progress == 0)
	const char* bundle_file;
		const char* prefix,
static const char * const builtin_bundle_list_heads_usage[] = {
  N_("git bundle unbundle <file> [<refname>...]"),
	struct argv_array pack_opts;
		usage_with_options(builtin_bundle_usage, options);
#include "bundle.h"
	else if (!strcmp(argv[0], "create"))
#include "cache.h"
#include "argv-array.h"
};
	struct bundle_header header;

		result = cmd_bundle_verify(argc, argv, prefix);
	return 0;

 * Basic handler for bundle files to connect repositories via sneakernet.
}
		OPT__VERBOSE(&verbose, N_("be verbose; must be placed before a subcommand")),
		argv_array_push(&pack_opts, "--quiet");
	struct bundle_header header;
	close(bundle_fd);
	};
	else if (!strcmp(argv[0], "verify"))
	if (!startup_info->have_repository)
	const char* bundle_file;
#include "builtin.h"
	if ((bundle_fd = read_bundle_header(bundle_file, &header)) < 0)
}
}
 * bundle supporting "fetch", "pull", and "ls-remote".

		OPT_SET_INT(0, "progress", &progress,
  N_("git bundle verify [<options>] <file>"),
  N_("git bundle unbundle <file> [<refname>...]"),
int cmd_bundle(int argc, const char **argv, const char *prefix)

static const char * const builtin_bundle_create_usage[] = {
  NULL
	else if (!strcmp(argv[0], "list-heads"))
		return 1;
	newargc = parse_options(argc, argv, NULL, options, usagestr,
{
	else if (progress == 1)
	else if (!strcmp(argv[0], "unbundle"))
  NULL
		OPT_END()
	argv_array_init(&pack_opts);

	else if (progress == 2)
		argv_array_push(&pack_opts, "--all-progress-implied");
	*bundle_file = prefix_filename(prefix, argv[0]);


		const char **bundle_file) {

};
  NULL
		return 1;
}
		argv_array_push(&pack_opts, "--all-progress");
		error(_("Unknown subcommand: %s"), argv[0]);
	argc = parse_options_cmd_bundle(argc, argv, prefix,

static const char * const builtin_bundle_unbundle_usage[] = {

		list_bundle_refs(&header, argc, argv);
 */
	if (progress && all_progress_implied)

	const char* bundle_file;
			    N_("do not show progress meter"), 0),
			    N_("show progress meter"), 1),
	return newargc;
	struct option options[] = {
			     PARSE_OPT_STOP_AT_NON_OPTION);
	return !!unbundle(the_repository, &header, bundle_fd, 0) ||

	argc = parse_options_cmd_bundle(argc, argv, prefix,
	return !!list_bundle_refs(&header, argc, argv);
	int progress = isatty(STDERR_FILENO);
	return result ? 1 : 0;
		OPT_BOOL(0, "all-progress-implied",
			builtin_bundle_list_heads_usage, options, &bundle_file);

		result = cmd_bundle_list_heads(argc, argv, prefix);
	};
	int result;
static int cmd_bundle_unbundle(int argc, const char **argv, const char *prefix) {
		const char * const usagestr[],
  NULL

