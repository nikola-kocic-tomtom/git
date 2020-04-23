			entry = alloc_test_entry(hash, p1, p2);
	size_t vlen = strlen(value);

			/* add entries */
	case HASH_METHOD_FNV:
		}
	memcpy(entry->key + klen + 1, value, vlen + 1);

		}
	unsigned int i, j;


		break;
		hash = strhash(key);
	{
		}

				printf("%s\n", i1);

			hashmap_entry_init(&entries[i]->ent, hashes[i]);
			else
	struct test_entry *entry = xmalloc(st_add4(sizeof(*entry), klen, vlen, 2));

#define HASH_METHOD_X2 4

			struct hashmap_entry key;
		hash = 0;
			free(entry);
	for (i = 0; i < TEST_SIZE; i++) {
	}
/*
			printf("Unknown command %s\n", cmd);
 * Read stdin line by line and print result of commands to stdout:
			}
#include "test-tool.h"
				hashmap_entry_init(&entries[i]->ent, hashes[i]);

			  const struct hashmap_entry *entry_or_key,
		} else {

			hashmap_for_each_entry(&map, &iter, entry,

				hashmap_add(&map, &entries[i]->ent);
				printf("strintern(%s) != strintern(%s)", i1, i2);
			hashmap_add(&map, &entries[i]->ent);

			/* setup static key */
			/* create entry with key = p1, value = p2 */
/*
		entries[i] = alloc_test_entry(0, buf, "");

#include "hashmap.h"
		/* test map lookups */
{
	struct hashmap map;

 */
static unsigned int hash(unsigned int method, unsigned int i, const char *key)
{
		} else if (!strcmp("perfhashmap", cmd) && p1 && p2) {
static struct test_entry *alloc_test_entry(unsigned int hash,
				hashmap_get_from_hash(&map, hashes[i],
	const struct test_entry *e1, *e2;
			/* print result */
			/* remove entry from hashmap */

 * Usage: time echo "perfhashmap method rounds" | test-tool hashmap
			const char *i1 = strintern(p1);
{
		/* test adding to the map */
		unsigned int hash = 0;
		return strcmp(e1->key, key ? key : e2->key);
		/* break line into command and up to two parameters */
	hashmap_init(&map, test_entry_cmp, &icase, 0);
		if (p1) {

		cmd = strtok(line.buf, DELIM);
			hashmap_free(&map);
			else if (i1 == p1)

			/* test that strintern works */
	const int ignore_case = cmp_data ? *((int *)cmp_data) : 0;
		/* fill the map (sparsely if specified) */
			puts(entry ? get_value(entry) : "NULL");
	else
	case HASH_METHOD_IDIV10:
struct test_entry

	icase = argc > 1 && !strcmp("ignorecase", argv[1]);
			hashmap_add(&map, &entry->ent);
	} else {

		struct test_entry *entry;

		return strcasecmp(e1->key, key ? key : e2->key);
		break;
{
		}
 */

	case HASH_METHOD_I:

	switch (method & 3)
	if (method & HASH_METHOD_X2)
#include "git-compat-util.h"
#define TEST_SPARSE 8
			p2 = strtok(NULL, DELIM);
			entry = rm ? container_of(rm, struct test_entry, ent)
 * remove key -> NULL / old value
static int test_entry_cmp(const void *cmp_data,
			hash = icase ? strihash(p1) : strhash(p1);
#define HASH_METHOD_IDIV10 2
		for (j = 0; j < rounds; j++) {
	return hash;

			perf_hashmap(atoi(p1), atoi(p2));
 * get key -> NULL / value

	memcpy(entry->key, key, klen + 1);
	/* process commands from stdin */
	int icase;


 * size -> tablesize numentries
static void perf_hashmap(unsigned int method, unsigned int rounds)
	if (ignore_case)

			entry = hashmap_get_entry_from_hash(&map, hash, p1,
		p1 = strtok(NULL, DELIM);
	strbuf_release(&line);
	struct hashmap_entry ent;
					: NULL;

 * iterate -> key1 value1\nkey2 value2\n...

	char buf[16];
				printf("%s %s\n", entry->key, get_value(entry));
		hashes[i] = hash(method, i, entries[i]->key);
			/* add / replace entry */

#define HASH_METHOD_I 1
	ALLOC_ARRAY(hashes, TEST_SIZE);
	while (strbuf_getline(&line, stdin) != EOF) {


			       hashmap_get_size(&map));

			/* print and free replaced entry, if any */
	/* key and value as two \0-terminated strings */
			struct hashmap_entry *rm;
 * hash key -> strhash(key) memhash(key) strihash(key) memihash(key)
		char *cmd, *p1 = NULL, *p2 = NULL;
	}
			hashmap_for_each_entry_from(&map, entry, ent)
 *
		hashmap_init(&map, test_entry_cmp, NULL, 0);
}
		hash = 2 * hash;
	/* init hash map */
		if (!strcmp("add", cmd) && p1 && p2) {

			puts(entry ? get_value(entry) : "NULL");
		} else if (!strcmp("intern", cmd) && p1) {
			hashmap_init(&map, test_entry_cmp, NULL, 0);

			entry = hashmap_put_entry(&map, entry, ent);
#define HASH_METHOD_FNV 0
	int padding; /* hashmap entry no longer needs to be the first member */
		j = (method & TEST_SPARSE) ? TEST_SIZE / 10 : TEST_SIZE;

		} else if (!strcmp("put", cmd) && p1 && p2) {

			}
#define DELIM " \t\r\n"
		break;
						      entries[i]->key);
int cmd__hashmap(int argc, const char **argv)

			rm = hashmap_remove(&map, &key, p1);
	ALLOC_ARRAY(entries, TEST_SIZE);
		hashmap_free(&map);
			/* add to hashmap */
				puts(get_value(entry));
			/* create entry with key = p1, value = p2 */
			hashmap_entry_init(&key, hash);
		}
	return e->key + strlen(e->key) + 1;
#define HASH_METHOD_0 3
	e1 = container_of(eptr, const struct test_entry, ent);

			continue;
{
		hash = i / 10;
	return 0;

	if (method & TEST_ADD) {
							struct test_entry, ent);
 *
			  const struct hashmap_entry *eptr,
	size_t klen = strlen(key);
	struct test_entry **entries;
 * perfhashmap method rounds -> test hashmap.[ch] performance

static const char *get_value(const struct test_entry *e)
 * Test performance of hashmap.[ch]
		/* ignore empty lines */
	const char *key = keydata;
	struct hashmap map;
}
			else if (i1 != i2)
			struct hashmap_iter iter;
		} else if (!strcmp("get", cmd) && p1) {
				puts("NULL");
				printf("strintern(%s) returns %s\n", p1, i1);

		for (i = 0; i < j; i++) {
}
						ent /* member name */)
{
		} else if (!strcmp("size", cmd)) {
		xsnprintf(buf, sizeof(buf), "%i", i);
	}
	e2 = container_of(entry_or_key, const struct test_entry, ent);
	case HASH_METHOD_0:
			/* lookup entry in hashmap */
			if (!entry)
 * put key value -> NULL / old value
	unsigned int *hashes;
			  const void *keydata)
		if (!cmd || *cmd == '#')
			/* print result and free entry*/
		break;
		hash = i;
	hashmap_free_entries(&map, struct test_entry, ent);
				printf("strintern(%s) returns input pointer\n", p1);
			entry = alloc_test_entry(hash, p1, p2);
#define TEST_SIZE 100000
#define TEST_ADD 16
	unsigned int hash = 0;
	return entry;
			printf("%u %u\n", map.tablesize,


			/* print table sizes */
	char key[FLEX_ARRAY];
	struct strbuf line = STRBUF_INIT;

			const char *i2 = strintern(p1);
			if (strcmp(i1, p1))
		} else if (!strcmp("remove", cmd) && p1) {
	}
}
{
					   char *key, char *value)

};
		} else if (!strcmp("iterate", cmd)) {
			free(entry);
			for (i = 0; i < TEST_SIZE; i++) {
}
			for (i = 0; i < TEST_SIZE; i++) {
		for (j = 0; j < rounds; j++) {
#include "strbuf.h"
	hashmap_entry_init(&entry->ent, hash);

}

