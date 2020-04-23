
	struct split_index *si;
static void show_bit(size_t pos, void *data)
	if (!si) {
#include "ewah/ewok.h"
}
	}
#include "cache.h"
	printf("base %s\n", oid_to_hex(&si->base_oid));
#include "split-index.h"
	printf("replacements:");
	printf(" %d", (int)pos);
		printf("not a split index\n");
	if (si->delete_bitmap)
	if (si->replace_bitmap)
	setup_git_directory();

	printf("\n");
		return 0;
	for (i = 0; i < the_index.cache_nr; i++) {
	si = the_index.split_index;
		       oid_to_hex(&ce->oid), ce_stage(ce), ce->name);
		printf("%06o %s %d\t%s\n", ce->ce_mode,
	return 0;
	printf("own %s\n", oid_to_hex(&the_index.oid));
		struct cache_entry *ce = the_index.cache[i];
}
	}
		ewah_each_bit(si->replace_bitmap, show_bit, NULL);
	do_read_index(&the_index, av[1], 1);
{

int cmd__dump_split_index(int ac, const char **av)
	printf("\ndeletions:");
#include "test-tool.h"
{
	int i;
		ewah_each_bit(si->delete_bitmap, show_bit, NULL);

