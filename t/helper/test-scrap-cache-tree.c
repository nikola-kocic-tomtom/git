#include "cache.h"
{
#include "test-tool.h"
		die("unable to read index file");
#include "tree.h"

	return 0;

}
	setup_git_directory();
#include "cache-tree.h"
	if (write_locked_index(&the_index, &index_lock, COMMIT_LOCK))
	active_cache_tree = NULL;
	struct lock_file index_lock = LOCK_INIT;
	hold_locked_index(&index_lock, LOCK_DIE_ON_ERROR);
int cmd__scrap_cache_tree(int ac, const char **av)
	if (read_cache() < 0)
		die("unable to write index file");
#include "lockfile.h"
