

#include "cache.h"
	}
int cmd__write_cache(int argc, const char **argv)
	for (i = 0; i < cnt; i++) {
		cnt = strtol(argv[1], NULL, 0);
#include "lockfile.h"
	struct lock_file index_lock = LOCK_INIT;
		hold_locked_index(&index_lock, LOCK_DIE_ON_ERROR);
}
	return 0;
	read_cache();
	setup_git_directory();
	int i, cnt = 1;
		if (write_locked_index(&the_index, &index_lock, COMMIT_LOCK))
{
			die("unable to write index file");
	if (argc == 2)
#include "test-tool.h"
