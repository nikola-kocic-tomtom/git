				   &state, &force_apply, &options,
	argc = apply_parse_options(argc, argv,
static const char * const apply_usage[] = {
#include "cache.h"
	NULL
	if (check_apply_state(&state, force_apply))
int cmd_apply(int argc, const char **argv, const char *prefix)

#include "builtin.h"
	ret = apply_all_patches(&state, argc, argv, options);
#include "parse-options.h"
	return ret;
	clear_apply_state(&state);
};
{
		exit(128);

	struct apply_state state;


#include "lockfile.h"
}


	int force_apply = 0;
				   apply_usage);
	if (init_apply_state(&state, the_repository, prefix))


		exit(128);
#include "apply.h"
	int ret;
	N_("git apply [<options>] [<patch>...]"),
	int options = 0;
