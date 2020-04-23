	o->object_state = allocate_alloc_state();
			release_tag_memory((struct tag*)obj);
	}

#include "cache.h"
	return obj;
	return NULL;
	 * above.
		warning(_("object %s has unknown type id %d"), oid_to_hex(oid), type);
}

			array->nr++;


				objects[array->nr] = objects[src];
	else
int object_list_contains(struct object_list *list, struct object *obj)
			if (!get_cached_commit_buffer(r, commit, NULL)) {
 * the specified sha1.  n must be a power of 2.  Please note that the
}
static unsigned int hash_obj(const struct object_id *oid, unsigned int n)
struct object *get_indexed_object(unsigned int idx)
	die(_("unable to parse object: %s"), name ? name : oid_to_hex(oid));


	return 0;
	r->parsed_objects->nr_objs++;
	pthread_mutex_destroy(&o->replace_mutex);
		return obj;
}

#include "tree.h"

	hash[j] = obj;
		struct commit *commit = lookup_commit(r, oid);
#include "packfile.h"
	int new_hash_size = r->parsed_objects->obj_hash_size < 32 ? 32 : 2 * r->parsed_objects->obj_hash_size;
					return NULL;
			continue;


				*eaten_p = 1;
			error(_("hash mismatch %s"), oid_to_hex(oid));

		/* Use our own empty string instead of allocating one: */
		struct object *obj = the_repository->parsed_objects->obj_hash[i];
struct object *lookup_unknown_object(const struct object_id *oid)
	return o;
	/*
#include "object.h"
	FREE_AND_NULL(o->commit_state);
		struct blob *blob = lookup_blob(r, oid);
#include "tag.h"
{

	stat_validity_clear(o->shallow_stat);

	object_array_release_entry(&array->objects[array->nr - 1]);
		SWAP(r->parsed_objects->obj_hash[i],
void raw_object_store_clear(struct raw_object_store *o)

void *object_as_type(struct repository *r, struct object *obj, enum object_type type, int quiet)


	}
 * hash map.
		i++;
					  buffer, &eaten);
	unsigned alloc = array->alloc;
	free_object_directories(o);
}
		if (!obj)
				if (parse_tree_buffer(tree, buffer, size))
struct object *object_array_pop(struct object_array *array)
	insert_obj_hash(obj, r->parsed_objects->obj_hash,
			if (!tree->object.parsed) {
			continue;
 * in an unspecified state and should not be examined.
			obj->flags &= ~flags;
 */
		return NULL;
				struct object_array *array,

 */
		entry->name = object_array_slopbuf;
	 * As objects are allocated in slabs (see alloc.c), we do
static void free_object_directory(struct object_directory *odb)
{
			}
}
	free(odb->path);
	o->commit_graph_attempted = 0;
/*
	struct object_array_entry *objects = array->objects;
			i = 0;
	} else {
	FREE_AND_NULL(o->blob_state);
	} else if (type == OBJ_COMMIT) {
		 * Move object to where we started to look for it so
			if (parse_tag_buffer(r, tag, buffer, size))
		}
		if (obj->type == OBJ_TREE)
/*
	int i;
	FREE_AND_NULL(o->tag_state);
			release_commit_memory(o, (struct commit*)obj);

		array->objects = objects;
 * initialized without requiring a malloc/free.
		*list = p->next;
{
struct object *parse_object_buffer(struct repository *r, const struct object_id *oid, enum object_type type, unsigned long size, void *buffer, int *eaten_p)
/*


	}
	clear_alloc_state(o->tree_state);
	clear_alloc_state(o->object_state);
	for (i = 0; i < o->obj_hash_size; i++) {
	return the_repository->parsed_objects->obj_hash[idx];
	memset(o, 0, sizeof(*o));
	}
		if (check_object_signature(r, repl, NULL, 0, NULL) < 0) {
		free(ent->name);
 * return value is *not* consistent across computer architectures.
/*
}
	struct object *obj;
	INIT_LIST_HEAD(&o->packed_git_mru);
	while (*list) {
{
	for (src = 0; src < nr; src++) {
	new_hash = xcalloc(new_hash_size, sizeof(struct object *));



			obj = &commit->object;
	r->parsed_objects->obj_hash = new_hash;
	unsigned long size;
{
static void insert_obj_hash(struct object *obj, struct object **hash, unsigned int size)

	o->blob_state = allocate_alloc_state();
{
	new_list->item = item;
		if (!strcmp(object->name, name))
	enum object_type type;
		return obj;


	}

				return NULL;
		obj = parse_object_buffer(r, oid, type, size,
	struct object *o = parse_object(the_repository, oid);
void object_list_free(struct object_list **list)
}
	} else if (type == OBJ_TAG) {
			obj->type = type;
	unsigned nr = array->nr, i;
			}
			if (parse_blob_buffer(blob, buffer, size))
 * A zero-length string to which object_array_entry::name can be
}
	INIT_LIST_HEAD(&o->packed_git_mru);
}
	unsigned nr = array->nr;
		REALLOC_ARRAY(objects, alloc);

				   const char *name)
	struct object *obj;
	o->is_shallow = -1;
	array->nr = dst;
	const struct object_id *repl = lookup_replace_object(r, oid);
struct object_list *object_list_insert(struct object *item,
	void *buffer;

	struct raw_object_store *o = xmalloc(sizeof(*o));
	for (i = 0; i < nr; i++, object++)

			free(buffer);
			obj->flags &= ~flags;
	unsigned int i, first;
	 *
static void grow_object_hash(struct repository *r)
	free_commit_buffer_slab(o->buffer_slab);

		else if (obj->type == OBJ_TAG)
static int contains_name(struct object_array *array, const char *name)
	oidcpy(&obj->oid, oid);
	return o;
 * must be a power of 2).  On collisions, simply overflow to the next
	return obj;

	FREE_AND_NULL(o->object_state);
}

	if (o)
}

	struct object_list *new_list = xmalloc(sizeof(struct object_list));
 * Look up the record for the given sha1 in the hash map stored in
	free(ent->path);
#include "commit-graph.h"
{
	if ((obj && obj->type == OBJ_BLOB && repo_has_object_file(r, oid)) ||
	*eaten_p = 0;
}
	for (i=0; i < the_repository->parsed_objects->obj_hash_size; i++) {
		}
	if (obj && obj->parsed)
{
	int i;
	     oid_object_info(r, oid, NULL) == OBJ_BLOB)) {
		 * that we do not need to walk the hash table the next

	return ret;
				unsigned mode, const char *path)
 */
	return 0;
		if (commit) {
		parse_blob_buffer(lookup_blob(r, oid), NULL, 0);
}
	o->commit_state = allocate_alloc_state();
	}
		struct tree *tree = lookup_tree(r, oid);
		entry->name = NULL;

	if (ent->name != object_array_slopbuf)
	if (gentle)
		list = list->next;
	struct object *obj = lookup_object(the_repository, oid);
 * obj_hash.  Return NULL if it was not found.
	int i;

			obj = &tree->object;
		if (j >= size)
		if (i == r->parsed_objects->obj_hash_size)
	return object_type_strings[type];
	/*
		entry->path = NULL;
	entry->item = obj;
	obj->parsed = 0;
	} else if (type == OBJ_TREE) {
	obj = lookup_object(r, oid);

{
	if (len < 0)
void clear_commit_marks_all(unsigned int flags)
	o->packed_git = NULL;
}
		 * time we look for it.
 * Free all memory associated with an entry; the result is

		entry->path = xstrdup(path);
	NULL,		/* OBJ_NONE = 0 */
				       struct object_list **list_p)
		grow_object_hash(r);

{


		}
			r->parsed_objects->obj_hash_size);
			if (!tree->buffer)
	else if (obj->type == OBJ_NONE) {
		}
	for (i = 0; i < array->nr; i++)
		}

	else if (!*name)
	FREE_AND_NULL(o->alternate_db);
	o->odb_tail = NULL;
			if (src != array->nr)
	struct object_array_entry *entry;


{
	}
	int eaten;
	for (i = 0; i < r->parsed_objects->obj_hash_size; i++) {

		obj = NULL;
			init_commit_node(r, (struct commit *) obj);
}
		return NULL;
{
		else if (obj->type == OBJ_COMMIT)
			return 1;
		return -1;
	if (!obj)
	return oidhash(oid) & (n - 1);
		if (oideq(oid, &obj->oid))
}
 * Return a numerical hash value between 0 and n-1 for the object with
	}

}
	struct object_array_entry *objects = array->objects;
{
	hashmap_init(&o->pack_map, pack_map_entry_cmp, NULL, 0);
}
			       return NULL;
	obj->flags = 0;
struct object *parse_object(struct repository *r, const struct object_id *oid)
	o->tag_state = allocate_alloc_state();
	*list_p = new_list;
		if (tag) {


{
	for (i = 0; i < the_repository->parsed_objects->obj_hash_size; i++) {
	free(r->parsed_objects->obj_hash);
		if (tree) {
	return the_repository->parsed_objects->obj_hash_size;
	return obj;
const char *type_name(unsigned int type)

		object_array_release_entry(&array->objects[i]);
void *create_object(struct repository *r, const struct object_id *oid, void *o)
	if (obj->type == type)
{
		} else {
	}
	first = i = hash_obj(oid, r->parsed_objects->obj_hash_size);
	pthread_mutex_init(&o->replace_mutex, NULL);
		return o;
		if (check_object_signature(r, repl, buffer, size,
}
{
				*eaten_p = 1;
{

{
	struct object *obj = o;

	 */
			 object_array_each_func_t want, void *cb_data)
	}
		if (!quiet)
static void object_array_release_entry(struct object_array_entry *ent)
				objects[dst] = objects[src];
	entry = &objects[nr];
unsigned int get_max_object_index(void)


		if (!contains_name(array, objects[src].name)) {
			return NULL;
	odb_clear_loose_cache(odb);

	return obj;
#include "blob.h"
		insert_obj_hash(obj, new_hash, new_hash_size);
	o->commit_graph = NULL;
}
	add_object_array_with_path(obj, name, array, S_IFINVALID, NULL);
		obj = create_object(the_repository, oid,
	return new_list;
		alloc = (alloc + 32) * 2;
		}
static const char *object_type_strings[] = {
void object_array_remove_duplicates(struct object_array *array)
}
struct raw_object_store *raw_object_store_new(void)
{
		if (obj && obj->type == OBJ_COMMIT)
	hashmap_free(&o->pack_map);
};
	for (i = 1; i < ARRAY_SIZE(object_type_strings); i++)
		return obj;
			object_array_release_entry(&objects[src]);
	oidmap_free(o->replace_map, 1);
		if (list->item == obj)

/*

	    (!obj && repo_has_object_file(r, oid) &&
	}
{
}
	clear_alloc_state(o->blob_state);
		    object_type_strings[i][len] == '\0')
	buffer = repo_read_object_file(r, oid, &type, &size);
	o->shallow_stat = xcalloc(1, sizeof(*o->shallow_stat));
}
			if (parse_commit_buffer(r, commit, buffer, size, 1))
	array->nr--;
	if (r->parsed_objects->obj_hash_size - 1 <= r->parsed_objects->nr_objs * 2)
struct object *parse_object_or_die(const struct object_id *oid,
	clear_alloc_state(o->commit_state);
	o->buffer_slab = allocate_commit_buffer_slab();
			      type_name(obj->type), type_name(type));
	entry->mode = mode;
}
void add_object_array(struct object *obj, const char *name, struct object_array *array)
 * Return true iff array already contains an entry with name.
{
	struct object *obj;
 * Insert obj into the hash table hash, which has length size (which
	o->buffer_slab = NULL;
 * empty bucket.
	free_commit_graph(o->commit_graph);
/*
	if (path)
#include "commit.h"
{
 */
	 * Before doing so, we need to free any additional memory
{
	}
			j = 0;
	 * not need to free each object, but each slab instead.
		o->odb = next;
	unsigned int j = hash_obj(&obj->oid, size);
		     r->parsed_objects->obj_hash[first]);
	else
				return NULL;
		return NULL;
			break;
		next = o->odb->next;
{
#include "alloc.h"
			free_tree_buffer((struct tree*)obj);
		array->alloc = alloc;
	while (hash[j]) {
	if (obj && i != first) {
		return obj;
}
	obj = NULL;
void parsed_object_pool_clear(struct parsed_object_pool *o)
	}

	int i;
	if (type == OBJ_BLOB) {
	close_object_store(o);
	while ((obj = r->parsed_objects->obj_hash[i]) != NULL) {
	unsigned nr = array->nr, src;
	die(_("invalid object type \"%s\""), str);
	}
		}
			return i;

struct object *lookup_object(struct repository *r, const struct object_id *oid)
		struct object *obj = the_repository->parsed_objects->obj_hash[i];
		if (obj)
	 * Note that this size must always be power-of-2 to match hash_obj
		if (blob) {

	while (list) {
			object_array_release_entry(&objects[src]);
			dst++;
		len = strlen(str);
 */
	struct object *ret;
#include "object-store.h"
void add_object_array_with_path(struct object *obj, const char *name,
		if (!strncmp(str, object_type_strings[i], len) &&
		free(p);
	if (!array->nr)
	}
	"tag",		/* OBJ_TAG = 4 */
			error(_("hash mismatch %s"), oid_to_hex(repl));
	}


	FREE_AND_NULL(o->replace_map);
	if (nr >= alloc) {


}
	free(odb);
	clear_alloc_state(o->tag_state);
		free_object_directory(o->odb);
		}
}
	if (!r->parsed_objects->obj_hash)
	array->nr = ++nr;
}
		return NULL;
		if (type == OBJ_COMMIT)
	FREE_AND_NULL(array->objects);
	array->nr = 0;
}
	}
	FREE_AND_NULL(o->shallow_stat);

	 */

{

			return NULL;
		else
	for (src = dst = 0; src < nr; src++) {

	if (!name)
	new_list->next = *list_p;
int type_from_string_gently(const char *str, ssize_t len, int gentle)
{
	struct object_array_entry *object = array->objects;
		struct object_list *p = *list;
 * power of 2 (but at least 32).  Copy the existing values to the new
/*
	FREE_AND_NULL(o->obj_hash);
				set_commit_buffer(r, commit, buffer, size);
void clear_object_flags(unsigned flags)
	o->obj_hash_size = 0;
			return 1;

		/*
{
		} else {
 */
					   type_name(type)) < 0) {
 */

	"blob",		/* OBJ_BLOB = 3 */
			      oid_to_hex(&obj->oid),
}
{
	if (buffer) {
		struct object_directory *next;
{
static char object_array_slopbuf[1];
				tree->object.parsed = 0;
	}
}
	else {

	 * the objects may hold.
	o->loaded_alternates = 0;
	ret = array->objects[array->nr - 1].item;
	struct object **new_hash;
	int i;
void object_array_clear(struct object_array *array)
	o->tree_state = allocate_alloc_state();

		entry->name = xstrdup(name);
struct parsed_object_pool *parsed_object_pool_new(void)
				    alloc_object_node(the_repository));
			free(buffer);

		j++;
{
}
{
	array->nr = array->alloc = 0;
	if (type >= ARRAY_SIZE(object_type_strings))
	FREE_AND_NULL(o->tree_state);
	"commit",	/* OBJ_COMMIT = 1 */
 * Increase the size of the hash map stored in obj_hash to the next
		struct object *obj = o->obj_hash[i];
		struct object *obj = r->parsed_objects->obj_hash[i];
static void free_object_directories(struct raw_object_store *o)
			obj = &blob->object;
{
		if (want(&objects[src], cb_data)) {
	struct object_array_entry *objects = array->objects;

		if (!eaten)


			obj = &tag->object;
	unsigned i;
		if (!obj)
	r->parsed_objects->obj_hash_size = new_hash_size;
		struct tag *tag = lookup_tag(r, oid);
}

		return lookup_object(r, oid);
			error(_("object %s is a %s, not a %s"),
			if (src != dst)
	while (o->odb) {
{

void object_array_filter(struct object_array *array,
		 */
	unsigned nr = array->nr, src, dst;
	"tree",		/* OBJ_TREE = 2 */
	struct parsed_object_pool *o = xmalloc(sizeof(*o));
#include "replace-object.h"
	memset(o, 0, sizeof(*o));
