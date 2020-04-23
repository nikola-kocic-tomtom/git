			const struct hashmap_entry *unused2,
	unsigned int hash = FNV32_BASE;
	struct hashmap_entry *old;
struct hashmap_entry *hashmap_get_next(const struct hashmap *map,
}

unsigned int memihash_cont(unsigned int hash_seed, const void *buf, size_t len)
	size_t len;
void hashmap_iter_init(struct hashmap *map, struct hashmap_iter *iter)
		struct hashmap_entry *e;
	alloc_table(map, size);
			rehash(map, map->tablesize >> HASHMAP_RESIZE_BITS);
		return;
			/*
		const struct hashmap_entry *e1, const struct hashmap_entry *e2,
#include "hashmap.h"
{
	}
}

{

{
			c -= 'a' - 'A';
static inline unsigned int bucket(const struct hashmap *map,
{
}
	return hash;
	}
			e->next = map->table[b];
		while (e) {

	}
}
	while (len--) {
		hash = (hash * FNV32_PRIME) ^ c;
	/* initialize string pool hashmap */
			 */

		if (current) {
	e2 = container_of(entry_or_key, const struct pool_entry, ent);
 * Incorporate another chunk of data into a memihash
		e = &(*e)->next;
			return current;
struct hashmap_entry *hashmap_get(const struct hashmap *map,
	free(map->table);

	entry->next = map->table[b];
		/*

	unsigned char data[FLEX_ARRAY];
	}
	iter->tablepos = 0;
			struct hashmap_entry *next = e->next;

}
			 * offset (caller being hashmap_free_entries)
	static struct hashmap map;

	while ((c = (unsigned char) *str++)) {
		map->shrink_at = map->grow_at / ((1 << HASHMAP_RESIZE_BITS) + 1);
}
{
	else
}
{
{
	/* remove existing entry */
		!map->cmpfn(map->cmpfn_data, e1, e2, keydata));

static void alloc_table(struct hashmap *map, unsigned int size)
	unsigned char *ucbuf = (unsigned char *) buf;
}
	const struct pool_entry *e1, *e2;
	unsigned int size = HASHMAP_INITIAL_SIZE;
unsigned int strihash(const char *str)
			const void *unused_keydata)
{
		struct hashmap_iter iter;
	return hash;



		hash = (hash * FNV32_PRIME) ^ c;

			map->table[b] = e;
		unsigned int c = *ucbuf++;
	return old;

	/* fix size and rehash if appropriate */
/*
				const struct hashmap_entry *key,

			c -= 'a' - 'A';
{
 * computation.
{
#define HASHMAP_INITIAL_SIZE 64
	struct pool_entry key, *e;
		const struct hashmap_entry *key, const void *keydata)
}
#define FNV32_BASE ((unsigned int) 0x811c9dc5)
	return old;
	if (entry_offset >= 0) { /* called by hashmap_free_entries */
			return NULL;
	unsigned int b = bucket(map, entry);
	 * Keep track of the number of items in the map and
	return hash;
			return e;
/* load factor in percent */
		size <<= HASHMAP_RESIZE_BITS;
struct pool_entry {
	return e;
		hashmap_init(&map, pool_entry_cmp, NULL, 0);
#define HASHMAP_RESIZE_BITS 2
		if (map->private_size < map->shrink_at)
}
	initial_size = (unsigned int) ((uint64_t) initial_size * 100

		 */
		e->len = len;
{
			  const void *keydata)
	struct hashmap_entry *old = hashmap_remove(map, entry, NULL);
}

{
	while (initial_size > size)
			iter->next = current->next;
	for (; e; e = e->next)
	hashmap_add(map, entry);
		hashmap_iter_init(map, &iter);
	hashmap_entry_init(&key.ent, memhash(data, len));
/* grow / shrink by 2^2 */
	return 0;



{
			  const struct hashmap_entry *entry_or_key,
			c -= 'a' - 'A';
static inline int entry_equals(const struct hashmap *map,
{
	       (e1->hash == e2->hash &&
	if (!e) {
	old = *e;
	unsigned int c, hash = FNV32_BASE;
}
 */
{
	memset(map, 0, sizeof(*map));
		if (map->private_size > map->grow_at)

	old->next = NULL;
		hash = (hash * FNV32_PRIME) ^ c;

	iter->map = map;
				struct hashmap_entry *entry)
	map->table[b] = entry;
static void rehash(struct hashmap *map, unsigned int newsize)

		}
	map->grow_at = (unsigned int) ((uint64_t) size * HASHMAP_LOAD_FACTOR / 100);
	return (e1 == e2) ||
			unsigned int b = bucket(map, e);
			 * like container_of, but using caller-calculated
{
			  const struct hashmap_entry *eptr,
{
		const void *cmpfn_data, size_t initial_size)
}

{
	if (!*e)
	return hash;

	memset(map, 0, sizeof(*map));
	struct hashmap_entry **e = &map->table[bucket(map, key)];
}
unsigned int strhash(const char *str)
	}
 * Generic implementation of hash-based key value mappings.
}
			/ HASHMAP_LOAD_FACTOR);
			rehash(map, map->tablesize << HASHMAP_RESIZE_BITS);
	return hash & (map->tablesize - 1);
struct hashmap_entry *hashmap_put(struct hashmap *map,
}
	map->cmpfn = equals_function ? equals_function : always_equal;
	while (*e && !entry_equals(map, *e, key, keydata))
	while ((c = (unsigned char) *str++))
	if (size <= HASHMAP_INITIAL_SIZE)
	unsigned char *ucbuf = (unsigned char *) buf;

void hashmap_init(struct hashmap *map, hashmap_cmp_fn equals_function,
/*
		if (c >= 'a' && c <= 'z')

		while ((e = hashmap_iter_next(&iter)))

#define HASHMAP_LOAD_FACTOR 80
	/* add entry */
{
	for (;;) {

	struct hashmap_entry *current = iter->next;
	while (len--) {
		const struct hashmap_entry *key)
}
		current = iter->map->table[iter->tablepos++];

	map->table = xcalloc(size, sizeof(struct hashmap_entry *));
static inline struct hashmap_entry **find_entry_ptr(const struct hashmap *map,
				const void *keydata)
	}
	struct hashmap_entry **e = find_entry_ptr(map, key, keydata);
	/* lookup interned string in pool */
		 * The shrink-threshold must be slightly smaller than
		map->private_size++;
	*e = old->next;
{
}
	key.len = len;

	}

		 * (grow-threshold / resize-factor) to prevent erratic resizing,
static int always_equal(const void *unused_cmp_data,

	/* fix size and rehash if appropriate */
	while (len--) {
unsigned int memihash(const void *buf, size_t len)
}
struct hashmap_entry *hashmap_remove(struct hashmap *map,
		}
static int pool_entry_cmp(const void *unused_cmp_data,
		const void *keydata)
	}
	}
	alloc_table(map, newsize);
					const struct hashmap_entry *key,
	return *find_entry_ptr(map, key, keydata);
unsigned int memhash(const void *buf, size_t len)
		/* not found: create it */
{
}
	unsigned int i, oldsize = map->tablesize;
			e = next;
	struct hashmap_entry **oldtable = map->table;

int hashmap_bucket(const struct hashmap *map, unsigned int hash)

	unsigned int c, hash = FNV32_BASE;
		hashmap_entry_init(&e->ent, key.ent.hash);
	map->tablesize = size;
		map->shrink_at = 0;
		return NULL;
	struct hashmap_entry ent;
		unsigned int c = *ucbuf++;
}
	map->do_count_items = 1;
#define FNV32_PRIME ((unsigned int) 0x01000193)
	if (map->do_count_items) {
	 */
	for (i = 0; i < oldsize; i++) {
	unsigned int hash = FNV32_BASE;
	/*
struct hashmap_entry *hashmap_iter_next(struct hashmap_iter *iter)
{
const void *memintern(const void *data, size_t len)
	if (!map || !map->table)
	/* calculate initial table size and allocate the table */
			const struct hashmap_entry *unused1,
#include "cache.h"
		 * thus we divide by (resize-factor + 1).
	e1 = container_of(eptr, const struct pool_entry, ent);
};
		hashmap_add(&map, &e->ent);
	if (map->do_count_items) {
	iter->next = NULL;
	return hash;
void hashmap_free_(struct hashmap *map, ssize_t entry_offset)
{
	unsigned char *ucbuf = (unsigned char *) buf;
		hash = (hash * FNV32_PRIME) ^ c;
	unsigned int hash = hash_seed;
	free(oldtable);
	e = hashmap_get_entry(&map, &key, ent, data);
 */
					const void *keydata)
		unsigned int c = *ucbuf++;
		if (iter->tablepos >= iter->map->tablesize)
}



		if (c >= 'a' && c <= 'z')
		if (c >= 'a' && c <= 'z')

	return e1->data != keydata &&
		FLEX_ALLOC_MEM(e, data, data, len);
	return e->data;
		struct hashmap_entry *e = oldtable[i];

		if (entry_equals(map, entry, e, NULL))
	return key->hash & (map->tablesize - 1);
	       (e1->len != e2->len || memcmp(e1->data, keydata, e1->len));
	return NULL;


	}
	if (!map.tablesize)

		map->private_size--;
	/* calculate resize thresholds for new size */
}
void hashmap_add(struct hashmap *map, struct hashmap_entry *entry)
		hash = (hash * FNV32_PRIME) ^ c;
	 * allow the map to automatically grow as necessary.
	map->cmpfn_data = cmpfn_data;
	struct hashmap_entry *e = entry->next;
			const struct hashmap_entry *entry)
			free((char *)e - entry_offset);
