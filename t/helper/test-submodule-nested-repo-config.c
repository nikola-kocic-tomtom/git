

}
	return 0;
	setup_git_directory();
	if (repo_submodule_init(&subrepo, the_repository, sub)) {

static void die_usage(int argc, const char **argv, const char *msg)
	submodule_free(the_repository);
int cmd__submodule_nested_repo_config(int argc, const char **argv)

	/* Read the config of _child_ submodules. */
		die_usage(argc, argv, "Submodule not found.");
	sub = submodule_from_path(the_repository, &null_oid, argv[1]);
	fprintf(stderr, "Usage: %s <submodulepath> <config name>\n", argv[0]);
	const struct submodule *sub;


	print_config_from_gitmodules(&subrepo, argv[2]);
#include "test-tool.h"

	fprintf(stderr, "%s\n", msg);
#include "submodule-config.h"
	exit(1);
	struct repository subrepo;
	if (argc < 3)
		die_usage(argc, argv, "Wrong number of arguments.");

	}
}
{
{
