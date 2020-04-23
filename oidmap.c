	hashmap_free_(&map->map, free_entries ? 0 : -1);

void *oidmap_get(const struct oidmap *map, const struct object_id *key)
	return hashmap_get_from_hash(&map->map, oidhash(key), key);
}
static int oidmap_neq(const void *hashmap_cmp_fn_data,
#include "oidmap.h"

	return hashmap_put(&map->map, &to_put->internal_entry);
{

	hashmap_init(&map->map, oidmap_neq, NULL, initial_size);
	b = container_of(e2, const struct oidmap_entry, internal_entry);
{
void oidmap_free(struct oidmap *map, int free_entries)
	if (!map->map.cmpfn)
}




	struct hashmap_entry entry;
void *oidmap_put(struct oidmap *map, void *entry)
{
	hashmap_entry_init(&to_put->internal_entry, oidhash(&to_put->oid));
	if (!map->map.cmpfn)

	return !oideq(&a->oid, &b->oid);
		      const void *keydata)

		oidmap_init(map, 0);
#include "cache.h"
		return;
	if (keydata)
		      const struct hashmap_entry *e1,

		      const struct hashmap_entry *e2,
}

	hashmap_entry_init(&entry, oidhash(key));
	if (!map->map.cmpfn)
		return NULL;
	a = container_of(e1, const struct oidmap_entry, internal_entry);
	const struct oidmap_entry *a, *b;
void oidmap_init(struct oidmap *map, size_t initial_size)
{
void *oidmap_remove(struct oidmap *map, const struct object_id *key)
		oidmap_init(map, 0);
}
}


	struct oidmap_entry *to_put = entry;

	if (!map)
	/* TODO: make oidmap itself not depend on struct layouts */
{
	return hashmap_remove(&map->map, &entry, key);
{
		return !oideq(&a->oid, (const struct object_id *) keydata);
}
