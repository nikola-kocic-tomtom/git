
	shift_tree(the_repository, &one->object.oid, &two->object.oid, &shifted, -1);
		die("cannot parse %s as an object name", av[2]);
		die("not a tree-ish %s", av[1]);

#include "cache.h"
}
	if (get_oid(av[1], &hash1))
{
		die("not a tree-ish %s", av[2]);
#include "test-tool.h"
int cmd__match_trees(int ac, const char **av)
	if (!two)
	struct tree *one, *two;
	if (get_oid(av[2], &hash2))
	one = parse_tree_indirect(&hash1);
	struct object_id hash1, hash2, shifted;
	setup_git_directory();

	exit(0);

	printf("shifted: %s\n", oid_to_hex(&shifted));
	if (!one)
	two = parse_tree_indirect(&hash2);
		die("cannot parse %s as an object name", av[1]);
#include "tree.h"

