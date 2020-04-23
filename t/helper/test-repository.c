
	memset(the_repository, 0, sizeof(*the_repository));
	 */
#include "tree.h"

	repo_set_hash_algo(the_repository, hash_algo_by_ptr(r.hash_algo));



	} else if (!strcmp(argv[1], "get_commit_tree_in_graph")) {
#include "object-store.h"
}
	if (!parse_commit_in_graph(&r, c))
		struct object_id oid;
	for (parent = c->parents; parent; parent = parent->next)
#include "config.h"
	memset(the_repository, 0, sizeof(*the_repository));
	} else {
		test_parse_commit_in_graph(argv[2], argv[3], &oid);
#include "commit-graph.h"
	struct repository r;
	tree = get_commit_tree_in_graph(&r, c);
		die("Couldn't init repo");
			die("cannot parse oid '%s'", argv[4]);

	if (!tree)

			die("not enough arguments");
{
	return 0;
				       const struct object_id *commit_oid)
	if (repo_init(&r, gitdir, worktree))


		struct object_id oid;
int cmd__repository(int argc, const char **argv)
	repo_clear(&r);
			die("not enough arguments");
	printf("%"PRItime, c->date);
	repo_clear(&r);
	struct commit *c;

#include "object.h"
		printf(" %s", oid_to_hex(&parent->item->object.oid));
	struct commit_list *parent;
	if (!parse_commit_in_graph(&r, c))

		if (argc < 5)

		die("Couldn't get commit tree");
	 * parse it first.
#include "commit.h"


	if (repo_init(&r, gitdir, worktree))
		if (parse_oid_hex(argv[4], &oid, &argv[4]))
{
	setup_git_env(gitdir);
	struct tree *tree;
	printf("\n");
	struct commit *c;
		die("Couldn't parse commit");
					  const struct object_id *commit_oid)


		die("Couldn't init repo");
}
	setup_git_env(gitdir);
		die("unrecognized '%s'", argv[1]);
	if (!strcmp(argv[1], "parse_commit_in_graph")) {
{
		if (parse_oid_hex(argv[4], &oid, &argv[4]))
	repo_set_hash_algo(the_repository, hash_algo_by_ptr(r.hash_algo));
	int nongit_ok = 0;
	setup_git_directory_gently(&nongit_ok);
			die("cannot parse oid '%s'", argv[4]);
	/*

		if (argc < 5)
static void test_parse_commit_in_graph(const char *gitdir, const char *worktree,
	c = lookup_commit(&r, commit_oid);
		die("must have at least 2 arguments");
	struct repository r;
	if (argc < 2)
		die("Couldn't parse commit");
	 * get_commit_tree_in_graph does not automatically parse the commit, so
#include "repository.h"


#include "cache.h"
	}
		test_get_commit_tree_in_graph(argv[2], argv[3], &oid);

	printf("%s\n", oid_to_hex(&tree->object.oid));
#include "test-tool.h"
static void test_get_commit_tree_in_graph(const char *gitdir,
	c = lookup_commit(&r, commit_oid);

					  const char *worktree,
}
