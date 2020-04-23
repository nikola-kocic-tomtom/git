}
		if (i > 0 && oideq(array->oid + i, array->oid + i - 1))
int oid_array_for_each_unique(struct oid_array *array,
	for (i = 0; i < array->nr; i++) {
{
{
			continue;
	return sha1_pos(oid->hash, array->oid, array->nr, sha1_access);
	array->sorted = 0;
	return 0;
	return array[index].hash;
	array->sorted = 1;
		      for_each_oid_fn want,
			      for_each_oid_fn fn,
		       for_each_oid_fn fn,

{
}
			if (src != dst)

{
	FREE_AND_NULL(array->oid);
	size_t i;
}
#include "sha1-lookup.h"
}
void oid_array_append(struct oid_array *array, const struct object_id *oid)
#include "oid-array.h"
{
	ALLOC_GROW(array->oid, array->nr + 1, array->alloc);
	return oidcmp(a, b);
			return ret;

	array->nr = dst;

	return 0;
}
void oid_array_filter(struct oid_array *array,
}
		if (ret)
			dst++;
	array->sorted = 0;
	struct object_id *array = table;



		ret = fn(array->oid + i, data);
		int ret;
	size_t i;
	array->nr = 0;
		int ret = fn(array->oid + i, data);

}
		if (want(&oids[src], cb_data)) {
	}

{
				oidcpy(&oids[dst], &oids[src]);
	if (!array->sorted)

	if (!array->sorted)
static void oid_array_sort(struct oid_array *array)
	oidcpy(&array->oid[array->nr++], oid);
}
{
			      void *data)
#include "cache.h"
			return ret;

	}
static int void_hashcmp(const void *a, const void *b)
		if (ret)
	QSORT(array->oid, array->nr, void_hashcmp);
int oid_array_lookup(struct oid_array *array, const struct object_id *oid)
		}

	array->alloc = 0;
	size_t nr = array->nr, src, dst;
static const unsigned char *sha1_access(size_t index, void *table)
void oid_array_clear(struct oid_array *array)
	for (i = 0; i < array->nr; i++) {
		oid_array_sort(array);
		oid_array_sort(array);

		       void *data)
int oid_array_for_each(struct oid_array *array,
}
		      void *cb_data)
	for (src = dst = 0; src < nr; src++) {

	struct object_id *oids = array->oid;

{
	}
	/* No oid_array_sort() here! See oid-array.h */
{
