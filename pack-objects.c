		if (cnt == nr) {
void oe_map_new_pack(struct packing_data *pack)
#include "cache.h"
/*

	return new_entry;

	v |= v >> 2;
	for (i = 0; i < pdata->nr_objects; i++) {
						       &entry->idx.oid,
	uint32_t i;
	if (pdata->layer)
					 int *found)
	while (pdata->index[i] > 0) {
void oe_set_delta_ext(struct packing_data *pdata,
	}


{

}

		if (oideq(oid, &pdata->objects[pos].idx.oid)) {
{

	ALLOC_ARRAY(pack->in_pack, pack->nr_alloc);
			BUG("duplicate object inserted into hash");
	new_entry = pdata->objects + pdata->nr_objects++;
			REALLOC_ARRAY(pdata->delta_size, pdata->nr_alloc);

	 * (i.e. in_pack_idx also zero) should return NULL.
	v |= v >> 8;
	if (pdata->in_pack)
	pdata->oe_size_limit = git_env_ulong("GIT_TEST_OE_SIZE",
 *
	v |= v >> 1;
	return v + 1;

	int found;
							&new_entry->idx.oid,
 * this fall back code, just stay simple and fall back to using
 * A new pack appears after prepare_in_pack_by_idx() has been
	mapping[cnt++] = NULL;

	struct object_entry *base;
	return i;
		pdata->index_size = 1024;

{
#include "pack.h"
	struct object_entry *entry;
			free(mapping);
/* assume pdata is already zero'd by caller */
	oidcpy(&base->idx.oid, oid);

			REALLOC_ARRAY(pdata->tree_depth, pdata->nr_alloc);

		uint32_t pos = pdata->index[i] - 1;
}
	}
		BUG("packing_data has already been converted to pack array");
{
					 const struct object_id *oid,
	} else {
{
}



}
		pdata->tree_depth[pdata->nr_objects - 1] = 0;
static inline uint32_t closest_pow2(uint32_t v)

	free(pdata->index);
{
			return;
			return i;
						   1UL << OE_DELTA_SIZE_BITS);
		 * do not initialize in_pack_by_idx[] to force the
	v |= v >> 16;
		 */

	FREE_AND_NULL(pack->in_pack_by_idx);
	if (!found)

		if (pdata->layer)
	delta->ext_base = 1;
			BUG("Duplicate object in hash");
		int found;
		uint32_t ix = locate_object_entry_hash(pdata,
	base->preferred_base = 1;
 * have to deal with full array anyway. And since it's hard to test
		}
static uint32_t locate_object_entry_hash(struct packing_data *pdata,
	/*
		}
 * run. This is likely a race.
	/* These flags mark that we are not part of the actual pack output. */
	}
	pdata->index = xcalloc(pdata->index_size, sizeof(*pdata->index));

		/*
void prepare_packing_data(struct repository *r, struct packing_data *pdata)

		if (found)
		pdata->in_pack[pdata->nr_objects - 1] = NULL;
		prepare_in_pack_by_idx(pdata);
	return &pdata->objects[pdata->index[i] - 1];
static void prepare_in_pack_by_idx(struct packing_data *pdata)
	struct object_entry *new_entry;
	v = v - 1;
{
		      const struct object_id *oid)
		uint32_t pos = locate_object_entry_hash(pdata,
	ALLOC_GROW(pdata->ext_bases, pdata->nr_ext + 1, pdata->alloc_ext);
		return NULL;

			*found = 1;
		mapping[cnt] = p;

		if (found)
}
	*found = 0;
#include "pack-objects.h"
	}
	if (pack->in_pack)
}
			REALLOC_ARRAY(pdata->in_pack, pdata->nr_alloc);
	base = &pdata->ext_bases[pdata->nr_ext++];
		rehash_objects(pdata);
}
	init_recursive_mutex(&pdata->odb_lock);
	memset(new_entry, 0, sizeof(*new_entry));
		      struct object_entry *delta,
	if (!pdata->index_size)
						       &found);


		p->index = cnt;
		if (pdata->tree_depth)
 */
					     1U << OE_SIZE_BITS);

#include "config.h"

		pdata->index[pos] = pdata->nr_objects;
{
	uint32_t i, mask = (pdata->index_size - 1);
		pdata->layer[pdata->nr_objects - 1] = 0;
	pdata->repo = r;


	i = oidhash(oid) & mask;


	if (git_env_bool("GIT_TEST_FULL_IN_PACK_ARRAY", 0)) {
		entry++;
		int found;
 * We could map this new pack to in_pack_by_idx[] array, but then we
	base->filled = 1;
	v |= v >> 4;

	for (i = 0; i < pack->nr_objects; i++)
		i = (i + 1) & mask;
	pdata->index_size = closest_pow2(pdata->nr_objects * 3);
#include "packfile.h"

			REALLOC_ARRAY(pdata->layer, pdata->nr_alloc);
struct object_entry *packlist_alloc(struct packing_data *pdata,

	 * oe_in_pack() on an all-zero'd object_entry

	}
		return NULL;
	entry = pdata->objects;
	else {
	memset(base, 0, sizeof(*base));
		 * slow path in oe_in_pack()
	oidcpy(&new_entry->idx.oid, oid);
				   const struct object_id *oid)
		pdata->nr_alloc = (pdata->nr_alloc  + 1024) * 3 / 2;
	pdata->in_pack_by_idx = mapping;
	if (pdata->nr_objects >= pdata->nr_alloc) {
		pdata->index[ix] = i + 1;
	int cnt = 0, nr = 1U << OE_IN_PACK_BITS;
		REALLOC_ARRAY(pdata->objects, pdata->nr_alloc);
	ALLOC_ARRAY(mapping, nr);
	struct packed_git **mapping, *p;
							&found);


static void rehash_objects(struct packing_data *pdata)

struct object_entry *packlist_find(struct packing_data *pdata,

 * in_pack[] array.
	delta->delta_idx = base - pdata->ext_bases + 1;
}
		if (!pdata->in_pack_by_idx)

	if (pdata->index_size < 1024)

	if (pdata->tree_depth)
	 */
	}
	for (p = get_all_packs(pdata->repo); p; p = p->next, cnt++) {
	i = locate_object_entry_hash(pdata, oid, &found);
				    const struct object_id *oid)
	uint32_t i;
		pack->in_pack[i] = oe_in_pack(pack, pack->objects + i);
	uint32_t i;


		if (pdata->delta_size)
#include "object.h"


}
	pdata->oe_delta_size_limit = git_env_ulong("GIT_TEST_OE_DELTA_SIZE",
	if (pdata->index_size * 3 <= pdata->nr_objects * 4)
{
