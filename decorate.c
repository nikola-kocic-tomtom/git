{

	while (entries[j].base) {
{
	for (i = 0; i < old_size; i++) {

	for (;;) {

{
	if (!n->size)
 * decorate.c - decorate a git object with some arbitrary

			return NULL;

			continue;
	n->size = (old_size + 1000) * 3 / 2;
static void grow_decoration(struct decoration *n)
	if (nr > n->size * 2 / 3)
#include "object.h"
void *lookup_decoration(struct decoration *n, const struct object *obj)
	int size = n->size;
	struct decoration_entry *entries = n->entries;
			void *old = entries[j].decoration;

	n->nr++;
	/* nothing to lookup */
	j = hash_obj(obj, n->size);
		if (!decoration)
{
}
	int old_size = n->size;
	n->nr = 0;
		if (++j == n->size)

			entries[j].decoration = decoration;
	entries[j].decoration = decoration;
			j = 0;
	return oidhash(&obj->oid) % n;
 * data.
	}

	entries[j].base = base;
static void *insert_decoration(struct decoration *n, const struct object *base, void *decoration)
/*
	free(old_entries);
#include "cache.h"

		if (!ref->base)
	}
		const struct object *base = old_entries[i].base;
		void *decoration = old_entries[i].decoration;
			return old;
void *add_decoration(struct decoration *n, const struct object *obj,
		}
}
			j = 0;

			return ref->decoration;
}
static unsigned int hash_obj(const struct object *obj, unsigned int n)
		grow_decoration(n);
}
	unsigned int j = hash_obj(base, size);
	return insert_decoration(n, obj, decoration);
	n->entries = xcalloc(n->size, sizeof(struct decoration_entry));
	int i;
		void *decoration)
		if (ref->base == obj)
	struct decoration_entry *old_entries = n->entries;
	return NULL;
		if (entries[j].base == base) {
}
		insert_decoration(n, base, decoration);
	}

 */
{
		struct decoration_entry *ref = n->entries + j;
		return NULL;
		if (++j >= size)
	int nr = n->nr + 1;
#include "decorate.h"
	unsigned int j;
