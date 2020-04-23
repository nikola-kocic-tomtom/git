
{
const char *blob_type = "blob";

	return 0;
#include "cache.h"
	return object_as_type(r, obj, OBJ_BLOB, 0);
	struct object *obj = lookup_object(r, oid);
	if (!obj)
#include "blob.h"

int parse_blob_buffer(struct blob *item, void *buffer, unsigned long size)
		return create_object(r, oid, alloc_blob_node(r));
struct blob *lookup_blob(struct repository *r, const struct object_id *oid)
	item->object.parsed = 1;
{
}
}
#include "alloc.h"
#include "repository.h"
