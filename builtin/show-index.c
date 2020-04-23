			die("corrupt index file");
				offset = (((uint64_t)ntohl(off64[0])) << 32) |
			uint32_t crc;
{
	static unsigned int top_index[256];
		version = ntohl(top_index[1]);
					die("unable to read 64b offset %u", off64_nr);
			struct object_id oid;
#include "builtin.h"
	unsigned int version;
			if (fread(&entries[i].crc, 4, 1, stdin) != 1)
				die("unable to read entry %u/%u", i, nr);
}
		free(entries);


				die("unable to read 32b offset %u/%u", i, nr);
	int i;
			printf("%" PRIuMAX " %s (%08"PRIx32")\n",
			uint32_t off = ntohl(entries[i].off);
		for (i = 0; i < nr; i++)
		for (i = 0; i < nr; i++)
			die("unknown index version");
		struct {
			unsigned int offset, entry[(GIT_MAX_RAWSZ + 4) / sizeof(unsigned int)];
	nr = 0;
			printf("%u %s\n", offset, hash_to_hex((void *)(entry+1)));
#include "pack.h"
static const char show_index_usage[] =
int cmd_show_index(int argc, const char **argv, const char *prefix)
			die("unable to read index");
			} else {
			die("unable to read index");
	}
					die("inconsistent 64b offset index");
#include "cache.h"
		for (i = 0; i < nr; i++)
				uint32_t off64[2];

		}
		}
		if (fread(top_index, 256 * 4, 1, stdin) != 1)
	if (top_index[0] == htonl(PACK_IDX_SIGNATURE)) {
	for (i = 0; i < 256; i++) {
"git show-index";
						     ntohl(off64[1]);

			}
			uint32_t off;
		version = 1;
		for (i = 0; i < nr; i++) {
			       oid_to_hex(&entries[i].oid),
		if (n < nr)
			if (!(off & 0x80000000)) {
				offset = off;
		if (fread(&top_index[2], 254 * 4, 1, stdin) != 1)
			       ntohl(entries[i].crc));
		ALLOC_ARRAY(entries, nr);
		usage(show_index_usage);
	const unsigned hashsz = the_hash_algo->rawsz;
			if (fread(&entries[i].off, 4, 1, stdin) != 1)
				die("unable to read sha1 %u/%u", i, nr);
	}
	} else {
		unsigned n = ntohl(top_index[i]);
			       (uintmax_t) offset,
	return 0;
		} *entries;
		for (i = 0; i < nr; i++) {
			if (fread(entry, 4 + hashsz, 1, stdin) != 1)
			offset = ntohl(entry[0]);
	} else {
	}
				off64_nr++;
			if (fread(entries[i].oid.hash, hashsz, 1, stdin) != 1)
	if (argc != 1)
		unsigned off64_nr = 0;
	if (version == 1) {
		if (version < 2 || version > 2)
		die("unable to read header");
				if ((off & 0x7fffffff) != off64_nr)
		nr = n;
	if (fread(top_index, 2 * 4, 1, stdin) != 1)
				die("unable to read crc %u/%u", i, nr);
			uint64_t offset;
				if (fread(off64, 8, 1, stdin) != 1)
	unsigned nr;
