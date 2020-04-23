	for (rev = result; rev; rev = rev->next) {

}


		OPT_BOOL('a', "all", &show_all, N_("output all common ancestors")),
	for (rev = revs; rev; rev = rev->next)
		return handle_is_ancestor(argc, argv);
	return show_merge_base(rev, rev_nr, show_all);
	}
		die("Not a valid commit name %s", arg);
		return 0;
		if (argc < 2)
	result = get_octopus_merge_bases(revs);


#include "parse-options.h"
	r = lookup_commit_reference(the_repository, &revkey);
	}
	result = get_merge_bases_many_dirty(rev[0], rev_nr - 1, rev + 1);

	struct commit **rev;
static int handle_independent(int count, const char **args)
	reduce_heads_replace(&result);
#include "builtin.h"
	ALLOC_ARRAY(rev, argc);
	return r;
	int show_all = 0;
		return handle_fork_point(argc, argv);


		die("Not a valid object name: '%s'", commitname);
	free_commit_list(revs);
	if (cmdmode == 'r')

	struct commit_list *revs = NULL;

{
	if (!result)
			break;
#include "commit-reach.h"
		if (show_all)
	if (cmdmode == 'f') {
	for (i = count - 1; i >= 0; i--)
	struct commit_list *result, *rev;
		OPT_CMDMODE(0, "octopus", &cmdmode,
	if (argc != 2)
	free_commit_list(revs);

		OPT_CMDMODE(0, "is-ancestor", &cmdmode,
	fork_point = get_fork_point(argv[0], derived);
	derived = lookup_commit_reference(the_repository, &oid);
}
		die("--independent cannot be used with --all");

			    N_("find where <commit> forked from reflog of <ref>"), 'f'),
		usage_with_options(merge_base_usage, options);
		return handle_independent(argc, argv);
};
	struct option options[] = {
		if (argc < 1 || 2 < argc)
{
	const char *commitname;
}
{
		return 1;
			break;

#include "commit.h"
	printf("%s\n", oid_to_hex(&fork_point->object.oid));
	if (cmdmode == 'r' && show_all)
		printf("%s\n", oid_to_hex(&rev->item->object.oid));
	argc = parse_options(argc, argv, prefix, options, merge_base_usage, 0);
}

	commitname = (argc == 2) ? argv[1] : "HEAD";
static int handle_is_ancestor(int argc, const char **argv)
	reduce_heads_replace(&revs);
	N_("git merge-base [-a | --all] --octopus <commit>..."),
	return 0;
#include "revision.h"
		die("--is-ancestor takes exactly two commits");

		return 1;
}

	free_commit_list(result);
static struct commit *get_commit_reference(const char *arg)
	if (argc < 2)
	}
int cmd_merge_base(int argc, const char **argv, const char *prefix)
}
	if (in_merge_bases(one, two))

		return 1;
	struct object_id revkey;
	if (get_oid(arg, &revkey))
		return handle_octopus(argc, argv, show_all);

	struct commit *derived, *fork_point;
{
	free_commit_list(result);
	int i;
	}
		return 1;

		if (!show_all)
			    N_("find ancestors for a single n-way merge"), 'o'),
	N_("git merge-base --fork-point <ref> [<commit>]"),
	struct commit *r;

	if (!revs)
		printf("%s\n", oid_to_hex(&rev->item->object.oid));
	for (r = result; r; r = r->next) {
		OPT_CMDMODE(0, "fork-point", &cmdmode,

	N_("git merge-base --is-ancestor <commit> <commit>"),
	struct commit *one, *two;

		OPT_CMDMODE(0, "independent", &cmdmode,

	if (cmdmode == 'a') {
{
#include "repository.h"
	};
	if (!result)

		printf("%s\n", oid_to_hex(&r->item->object.oid));
	struct object_id oid;
		die("Not a valid object name %s", arg);

static int handle_octopus(int count, const char **args, int show_all)
#include "config.h"
	return 0;
	struct commit_list *revs = NULL, *rev;
			    N_("list revs not reachable from others"), 'r'),
	one = get_commit_reference(argv[0]);

			usage_with_options(merge_base_usage, options);
			die("--is-ancestor cannot be used with --all");
	int rev_nr = 0;

{
	NULL
	return 0;
	if (get_oid(commitname, &oid))
	N_("git merge-base --independent <commit>..."),
	if (!r)
static const char * const merge_base_usage[] = {
	for (i = count - 1; i >= 0; i--)

#include "refs.h"
		commit_list_insert(get_commit_reference(args[i]), &revs);
	int i;
		if (!show_all)

{
	struct commit_list *result, *r;

	N_("git merge-base [-a | --all] <commit> <commit>..."),

	return 0;
	while (argc-- > 0)
		return 1;
	int cmdmode = 0;

		rev[rev_nr++] = get_commit_reference(*argv++);


	if (!fork_point)



		OPT_END()
static int handle_fork_point(int argc, const char **argv)
	two = get_commit_reference(argv[1]);

#include "cache.h"
#include "diff.h"
static int show_merge_base(struct commit **rev, int rev_nr, int show_all)

		commit_list_insert(get_commit_reference(args[i]), &revs);
	else
			    N_("is the first one ancestor of the other?"), 'a'),
	if (cmdmode == 'o')
			usage_with_options(merge_base_usage, options);
}
	git_config(git_default_config, NULL);
