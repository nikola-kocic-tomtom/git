#include "cache.h"
		return 1;
	printf("\nnum_objects: %d\n", m->num_objects);
		printf(" object-offsets");
	return read_midx_file(argv[1]);

	       m->num_packs);

		printf(" large-offsets");
	printf("object-dir: %s\n", m->object_dir);
	if (argc != 2)

	uint32_t i;
static int read_midx_file(const char *object_dir)


{
	for (i = 0; i < m->num_packs; i++)
		usage("read-midx <object-dir>");
		printf(" oid-fanout");
	printf("chunks:");
	if (m->chunk_large_offsets)
		printf("%s\n", m->pack_names[i]);
{
	struct multi_pack_index *m = load_multi_pack_index(object_dir, 1);
	       m->signature,
	if (m->chunk_object_offsets)
		printf(" oid-lookup");

#include "test-tool.h"

	if (m->chunk_pack_names)
#include "object-store.h"
#include "midx.h"
	if (m->chunk_oid_fanout)
	return 0;
		printf(" pack-names");
	printf("packs:\n");
	       m->num_chunks,


	if (m->chunk_oid_lookup)
int cmd__read_midx(int argc, const char **argv)
	       m->version,
	printf("header: %08x %d %d %d\n",
	if (!m)
}
#include "repository.h"

}

