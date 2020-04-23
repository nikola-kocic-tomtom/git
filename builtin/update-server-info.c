
	int force = 0;

#include "parse-options.h"
		OPT__FORCE(&force, N_("update the info files from scratch"), 0),
	N_("git update-server-info [--force]"),
#include "cache.h"
			     update_server_info_usage, 0);

	NULL
int cmd_update_server_info(int argc, const char **argv, const char *prefix)
#include "builtin.h"
	git_config(git_default_config, NULL);
#include "config.h"
};
static const char * const update_server_info_usage[] = {
	};
{
	struct option options[] = {
		OPT_END()
	argc = parse_options(argc, argv, prefix, options,
	return !!update_server_info(force);
}

	if (argc > 0)
		usage_with_options(update_server_info_usage, options);
