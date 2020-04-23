 * If a replacement for object oid has been set up, return the
	die(_("replace depth too high for object %s"), oid_to_hex(oid));
				const struct object_id *oid,
		free(repl_obj);
#include "oidmap.h"
		if (!repl_obj)
						 const struct object_id *oid)
/*
	return 0;
	}
#include "commit.h"
	prepare_replace_object(r);
	const char *hash = slash ? slash + 1 : refname;
		pthread_mutex_unlock(&r->objects->replace_mutex);

	if (oidmap_put(r->objects->replace_map, repl_obj))
{

	for_each_replace_ref(r, register_replace_ref, NULL);
}
	while (depth-- > 0) {

	}
	const struct object_id *cur = oid;

/* We allow "recursive" replacement. Only within reason, though */

	if (r->objects->replace_map_initialized) {
				int flag, void *cb_data)
	pthread_mutex_lock(&r->objects->replace_mutex);
	oidmap_init(r->objects->replace_map, 0);

	const char *slash = strrchr(refname, '/');

		xmalloc(sizeof(*r->objects->replace_map));
	r->objects->replace_map =

	/* Copy sha1 from the read ref */
		die(_("duplicate replace ref: %s"), refname);
	pthread_mutex_unlock(&r->objects->replace_mutex);
void prepare_replace_object(struct repository *r)
	/* Try to recursively replace the object */
#include "refs.h"
{

				const char *refname,
		struct replace_object *repl_obj =

	struct replace_object *repl_obj = xmalloc(sizeof(*repl_obj));

 * permanently-allocated value.  This function always respects replace
	/* Register new object */
	int depth = MAXREPLACEDEPTH;
const struct object_id *do_lookup_replace_object(struct repository *r,
	oidcpy(&repl_obj->replacement, oid);
#include "object-store.h"
		return 0;
	}
}
 * The return value is either oid or a pointer to a
		cur = &repl_obj->replacement;
static int register_replace_ref(struct repository *r,

#include "repository.h"
#define MAXREPLACEDEPTH 5
		return;
		warning(_("bad replace ref name: %s"), refname);


			return cur;
}
	if (get_oid_hex(hash, &repl_obj->original.oid)) {
	r->objects->replace_map_initialized = 1;
			oidmap_get(r->objects->replace_map, cur);
 * replacement object's name (replaced recursively, if necessary).
	if (r->objects->replace_map_initialized)
#include "cache.h"
 */
#include "replace-object.h"
 * references, regardless of the value of read_replace_refs.
	/* Get sha1 from refname */
{
		return;
