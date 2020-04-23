

		} else
		arg++;
	while (arg[0] && starts_with(arg[0], "--")) {
			submodule = submodule_from_name(the_repository,
}

#include "config.h"
	int lookup_name = 0;
	int my_argc = argc;

		commit = arg[0];
							&commit_oid, path_or_name);
static void die_usage(int argc, const char **argv, const char *msg)
					submodule->url, submodule->path);
	}

		const char *commit;
	int output_url = 0;
		const char *path_or_name;
		else if (get_oid(commit, &commit_oid) < 0)


					submodule->name, submodule->path);
#include "test-tool.h"

		if (!strcmp(arg[0], "--url"))
			submodule = submodule_from_path(the_repository,

			lookup_name = 1;
#include "submodule-config.h"
		if (!submodule)
	const char **arg = argv;
		struct object_id commit_oid;
	}

{
		if (lookup_name) {
		path_or_name = arg[1];
		const struct submodule *submodule;
			printf("Submodule name: '%s' for path '%s'\n",

		if (commit[0] == '\0')
		else
	submodule_free(the_repository);
	return 0;
	if (my_argc % 2 != 0)
		die_usage(argc, argv, "Wrong number of arguments.");
	setup_git_directory();
							&commit_oid, path_or_name);
	exit(1);
	arg++;
		if (!strcmp(arg[0], "--name"))
		my_argc--;
{
		arg += 2;
			oidclr(&commit_oid);
	while (*arg) {
	fprintf(stderr, "Usage: %s [<commit> <submodulepath>] ...\n", argv[0]);
	my_argc--;
#include "cache.h"
int cmd__submodule_config(int argc, const char **argv)
			die_usage(argc, argv, "Submodule not found.");
	fprintf(stderr, "%s\n", msg);
			output_url = 1;
			printf("Submodule url: '%s' for path '%s'\n",

			die_usage(argc, argv, "Commit not found.");

		if (output_url)
#include "submodule.h"
}
