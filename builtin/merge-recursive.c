

	struct object_id h1, h2;
	return failed;
			warning(Q_("cannot handle more than %d base. "

				(int)ARRAY_SIZE(bases)-1, argv[i]);

				die(_("unknown option %s"), arg);
		usagef(builtin_merge_recursive_usage, argv[0]);
		die(_("could not resolve ref '%s'"), o.branch1);
	int i, failed;
	if (repo_read_index_unmerged(the_repository))
				    (int)ARRAY_SIZE(bases)-1),
	for (i = 1; i < argc; ++i) {
			struct object_id *oid = xmalloc(sizeof(struct object_id));
		o.subtree_shift = "";
	xsnprintf(githead_env, sizeof(githead_env), "GITHEAD_%s", branch);
	init_merge_options(&o, the_repository);
	name = getenv(githead_env);
				   "cannot handle more than %d bases. "
				break;
		die(_("could not resolve ref '%s'"), o.branch2);
	"git %s <base>... -- <head> <remote> ...";
	char *name;
	struct merge_options o;
	if (argv[0] && ends_with(argv[0], "-subtree"))
	struct commit *result;
		if (starts_with(arg, "--")) {
				   "Ignoring %s.",



#include "cache.h"
	o.branch1 = argv[++i];

			bases[bases_count++] = oid;
	free(better2);
		if (bases_count < ARRAY_SIZE(bases)-1) {
	if (failed < 0)


	failed = merge_recursive_generic(&o, &h1, &h2, bases_count, bases, &result);
			if (get_oid(argv[i], oid))
			if (!arg[2])
	if (o.verbosity >= 3)
	if (argc < 4)
#include "commit.h"

		}
	const struct object_id *bases[21];
				   "Ignoring %s.",
		else
		printf(_("Merging %s with %s\n"), o.branch1, o.branch2);
			if (parse_merge_opt(&o, arg + 2))
	if (get_oid(o.branch1, &h1))
				die(_("could not parse object '%s'"), argv[i]);
	o.branch1 = better1 = better_branch_name(o.branch1);
	o.branch2 = better2 = better_branch_name(o.branch2);
	char *better1, *better2;
#include "tag.h"
{
	unsigned bases_count = 0;
	if (argc - i != 3) /* "--" "<head>" "<remote>" */
	if (strlen(branch) != the_hash_algo->hexsz)
		die_resolve_conflict("merge");
static char *better_branch_name(const char *branch)
	}

		return xstrdup(branch);
		}
	o.branch2 = argv[++i];
		const char *arg = argv[i];
	free(better1);
{
#include "builtin.h"
int cmd_merge_recursive(int argc, const char **argv, const char *prefix)
	static char githead_env[8 + GIT_MAX_HEXSZ + 1];

		die(_("not handling anything other than two heads merge."));
	return xstrdup(name ? name : branch);
#include "merge-recursive.h"
}

	if (get_oid(o.branch2, &h2))


		return 128; /* die() error code */
			continue;
}
static const char builtin_merge_recursive_usage[] =
#include "xdiff-interface.h"
