};

#include "parse-options.h"
#include "config.h"
	git_config(git_default_config, NULL);
		usage_with_options(pack_refs_usage, opts);
{
	N_("git pack-refs [<options>]"),

int cmd_pack_refs(int argc, const char **argv, const char *prefix)
}
		OPT_END(),
#include "refs.h"
	NULL
		OPT_BIT(0, "prune", &flags, N_("prune loose refs (default)"), PACK_REFS_PRUNE),
	struct option opts[] = {
	};
	if (parse_options(argc, argv, prefix, opts, pack_refs_usage, 0))
	unsigned int flags = PACK_REFS_PRUNE;
static char const * const pack_refs_usage[] = {
#include "builtin.h"
	return refs_pack_refs(get_main_ref_store(the_repository), flags);
#include "repository.h"
		OPT_BIT(0, "all",   &flags, N_("pack everything"), PACK_REFS_ALL),
