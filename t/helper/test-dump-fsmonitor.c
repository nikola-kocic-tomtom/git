	struct index_state *istate = the_repository->index;
#include "cache.h"

#include "test-tool.h"
	if (do_read_index(istate, the_repository->index_file, 0) < 0)
}
		die("unable to read index file");
		printf((istate->cache[i]->ce_flags & CE_FSMONITOR_VALID) ? "+" : "-");
		printf("no fsmonitor\n");
	printf("fsmonitor last update %s\n", istate->fsmonitor_last_update);
	if (!istate->fsmonitor_last_update) {
		return 0;

	setup_git_directory();

	int i;

	return 0;
	}
	for (i = 0; i < istate->cache_nr; i++)
{
int cmd__dump_fsmonitor(int ac, const char **av)
