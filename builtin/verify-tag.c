			had_error = !!error("tag '%s' not found.", name);

			had_error = 1;
	int status = git_gpg_config(var, value, cb);
	const struct option verify_tag_options[] = {
#include "parse-options.h"
		if (format.format)
			continue;
	};
 *
#include "ref-filter.h"

};

		N_("git verify-tag [-v | --verbose] [--format=<format>] <tag>..."),
#include "tag.h"
		NULL
		struct object_id oid;
		flags |= GPG_VERIFY_OMIT_STATUS;
		}
	}
static const char * const verify_tag_usage[] = {
		OPT_END()
{
#include "builtin.h"
	argc = parse_options(argc, argv, prefix, verify_tag_options,
	while (i < argc) {
{

		if (get_oid(name, &oid)) {
		OPT_BIT(0, "raw", &flags, N_("print raw gpg status output"), GPG_VERIFY_RAW),

/*
		OPT_STRING(0, "format", &format.format, N_("format"), N_("format to use for the output")),
 * Builtin "git verify-tag"
	git_config(git_verify_tag_config, NULL);
	return had_error;
		}
		usage_with_options(verify_tag_usage, verify_tag_options);
			usage_with_options(verify_tag_usage,

static int git_verify_tag_config(const char *var, const char *value, void *cb)
	struct ref_format format = REF_FORMAT_INIT;
		flags |= GPG_VERIFY_VERBOSE;
	if (status)
			continue;
 * Based on git-verify-tag.sh
	return git_default_config(var, value, cb);
			pretty_print_ref(name, &oid, &format);
		OPT__VERBOSE(&verbose, N_("print tag contents")),
 */
					   verify_tag_options);
 *
#include "config.h"
	unsigned flags = 0;
}
}
			     verify_tag_usage, PARSE_OPT_KEEP_ARGV0);
	if (format.format) {
#include "run-command.h"
	if (verbose)



 * Copyright (c) 2007 Carlos Rica <jasampler@gmail.com>
		return status;
	if (argc <= i)

	}
		if (gpg_verify_tag(&oid, name, flags)) {
	int i = 1, verbose = 0, had_error = 0;
#include "cache.h"
#include "gpg-interface.h"

		if (verify_ref_format(&format))
int cmd_verify_tag(int argc, const char **argv, const char *prefix)
		const char *name = argv[i++];
