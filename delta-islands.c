	uint32_t i;
	rl = kh_value(remote_islands, pos);
	khiter_t pos;
 * of "old". Otherwise, the new bitmap is empty.
	return NULL;
	island_marks = kh_init_oid_map();
			     ARRAY_SIZE(matches), matches, 0))
	for (i = 0; i < nr; i++) {
		 * parent.
#include "cache.h"
		khiter_t pos = kh_get_oid_map(island_marks, entry->idx.oid);
{

		island_count = dst;
		if (oe_type(&to_pack->objects[i]) == OBJ_TREE) {

		strbuf_release(&re);

		if (!obj)

	QSORT(todo, nr, tree_depth_compare);
	int i, m;
		kh_value(island_marks, pos) = island_bitmap_new(NULL);
{
		b->refcount--;



static int island_bitmap_is_subset(struct island_bitmap *self,
		regmatch_t *match = &matches[m];
				continue;
	}

#include "progress.h"
			return 0;
	add_ref_to_island(island_name.buf, oid);
	uint32_t i;

}

			return -1;
				oe_set_layer(to_pack, entry, 0);
#define ISLAND_BITMAP_MASK(x) (1 << (x % 32))
			       int flags, void *data)
		if (match->rm_so == -1)

#include "tree-walk.h"
		warning(_("island regex from config has "
			todo[nr].entry = &to_pack->objects[i];
	for_each_ref(find_island_for_ref, NULL);

	 */
			nr++;
		island_bitmap_set(marks, island_counter);
		}
	if (!island_marks)

static int find_island_for_ref(const char *refname, const struct object_id *oid,
		struct strbuf re = STRBUF_INIT;
void propagate_island_marks(struct commit *commit)

	return 1;
		root_marks = kh_value(island_marks, pos);
		marks = create_or_get_island_marks(obj);
	if (trg_pos >= kh_end(island_marks))

		}
	if (src_pos >= kh_end(island_marks))
		b = kh_value(island_marks, pos) = island_bitmap_new(b);
{
		}

		kh_key(remote_islands, pos) = xstrdup(island_name);
		if ((self->bits[i] & super->bits[i]) != self->bits[i])
				list[dst] = list[src];
		free_tree_buffer(tree);
	for (i = 0; i < island_bitmap_size; ++i)
	if (a_bitmap) {
	 * multiple parent trees.
			  "too many capture groups (max=%d)"),
	if (i < 0)
}
		}
	}

{

		progress_state = start_progress(_("Propagating island marks"), nr);
	return 0;
#include "blob.h"


		memcpy(b, old, size);
			  struct packing_data *to_pack)
			}
			(int)ARRAY_SIZE(matches) - 2);
		/* If it was a tag, also make sure we hit the underlying object. */
#include "oid-array.h"
#include "diff.h"
		island_counter_core = island_counter;
		while (obj && obj->type == OBJ_TAG) {
static int island_config_callback(const char *k, const char *v, void *cb)
	uint64_t sha_core;
#include "khash.h"
	island_bitmap_or(b, marks);
		struct object *obj = parse_object(r, &rl->oids.oid[i]);
	if (!strcmp(k, "pack.islandcore"))


	free(todo);
}
	for (i = 0; i < to_pack->nr_objects; i++) {
		struct island_bitmap *root_marks = kh_value(island_marks, pos);
			todo[nr].depth = oe_tree_depth(to_pack, &to_pack->objects[i]);
			if (list[ref]->hash == list[src]->hash)
			obj->flags |= NEEDS_BITMAP;
	/*
{

	uint32_t i;
}
{
static void island_bitmap_set(struct island_bitmap *self, uint32_t i)

void resolve_tree_islands(struct repository *r,
}
{
}
		set_island_marks(&get_commit_tree(commit)->object, root_marks);
		for (p = commit->parents; p; p = p->next)
	git_config(island_config_callback, NULL);
	stop_progress(&progress_state);
	});
}
		if (!regexec(&island_regexes[i], refname,
	 * so we can diagnose below a config with more capture groups

		if (regcomp(&island_regexes[island_regexes_nr], re.buf, REG_EXTENDED))


	khiter_t pos = kh_put_str(remote_islands, island_name, &hash_ret);
static unsigned int island_regexes_alloc, island_regexes_nr;
static regex_t *island_regexes;
			obj = ((struct tag *)obj)->tagged;
	if (old)

		kh_value(island_marks, pos) = marks;



	regmatch_t matches[16];
		 */


	return (self->bits[ISLAND_BITMAP_BLOCK(i)] & ISLAND_BITMAP_MASK(i)) != 0;
	if (a_pos < kh_end(island_marks))
	ALLOC_ARRAY(list, island_count);

	ALLOC_ARRAY(todo, to_pack->nr_objects);

				parse_object(r, &obj->oid);
			die(_("bad tree object %s"), oid_to_hex(&ent->idx.oid));
		if (pos < kh_end(remote_islands))
	island_counter++;
	struct remote_island *rl = NULL;
static unsigned island_counter_core;

	}

		return 1;
	if (b_pos < kh_end(island_marks))
	if (!strcmp(k, "pack.island")) {

	if (hash_ret) {

	khiter_t a_pos, b_pos;
#include "delta.h"


{
};
#include "pack-objects.h"

		if (island_name.len)
	 * If we don't have a bitmap for the target, we can delta it
			set_island_marks(obj, root_marks);
			obj = lookup_object(r, &entry.oid);
	struct tree_islands_todo *todo;


		struct name_entry entry;

	memcpy(&sha_core, oid->hash, sizeof(uint64_t));
{
		struct island_bitmap *super)
	b_pos = kh_get_oid_map(island_marks, *b);
}
void load_delta_islands(struct repository *r, int progress)


	b->refcount = 1;
			if (obj) {
		init_tree_desc(&desc, tree->buffer, tree->size);
		return 0;
	khiter_t pos;

}
				marks = create_or_get_island_marks(obj);
}
	}
static void mark_remote_island_1(struct repository *r,
		if (!b_bitmap || !island_bitmap_is_subset(a_bitmap, b_bitmap))

{

static int tree_depth_compare(const void *a, const void *b)
	}
		while (tree_entry(&desc, &entry)) {
	if (hash_ret)
				island_bitmap_set(marks, island_counter);

	for (m = 1; m < ARRAY_SIZE(matches); m++) {
	for (ref = 0; ref + 1 < island_count; ref++) {
	const struct tree_islands_todo *todo_a = a;
	int hash_ret;
	int nr = 0;
		a->bits[i] |= b->bits[i];
	island_bitmap_size = (island_count / 32) + 1;
	self->bits[ISLAND_BITMAP_BLOCK(i)] |= ISLAND_BITMAP_MASK(i);

int in_same_island(const struct object_id *trg_oid, const struct object_id *src_oid)
			set_island_marks(&p->item->object, root_marks);
{
	}

	b = kh_value(island_marks, pos);
	 */
			continue;
			continue;

	unsigned int island_count, dst, src, ref, i = 0;
static struct island_bitmap *create_or_get_island_marks(struct object *obj)

	return kh_value(island_marks, pos);
		fprintf(stderr, _("Marked %d islands, done.\n"), island_counter);
 * Allocate a new bitmap; if "old" is not NULL, the new bitmap will be a copy

	uint32_t refcount;
	/* If we aren't using islands, assume everything goes together. */
			return kh_value(remote_islands, pos);
	if (progress)
		display_progress(progress_state, i+1);
		struct commit_list *p;
			  int progress,
	}
#include "config.h"
}
KHASH_INIT(str, const char *, void *, 1, kh_str_hash_func, kh_str_hash_equal)
			break;
				continue;

	 * we don't want to base any deltas on it!
/*
	oid_array_append(&rl->oids, oid);
	khiter_t trg_pos, src_pos;
	/*
	rl->hash += sha_core;

		return git_config_string(&core_island_name, k, v);
	 * We do have it. Make sure we split any copy-on-write before
			struct island_bitmap *bitmap = kh_value(island_marks, pos);
			die(_("failed to load island regex for '%s': %s"), k, re.buf);
				kh_value(island_marks, src_pos));
	if (b_bitmap) {
		strbuf_add(&island_name, refname + match->rm_so, match->rm_eo - match->rm_so);

		/*
	 * if the source (our delta base) doesn't have a bitmap,
};
#include "attr.h"
static unsigned island_counter;
	struct island_bitmap *a_bitmap = NULL, *b_bitmap = NULL;

	pos = kh_put_oid_map(island_marks, obj->oid, &hash_ret);
	core = get_core_island();
	}
		return 1;
	/*

	 * (and passed their marks on to root trees, as well. We must make sure
		struct island_bitmap *root_marks;
	 * We process only trees, as commits and tags have already been handled

		if (*v != '^')
#include "revision.h"
		return 0;

	int hash_ret;
		kh_value(remote_islands, pos) = xcalloc(1, sizeof(struct remote_island));
}
{
}
		ALLOC_GROW(island_regexes, island_regexes_nr + 1, island_regexes_alloc);
		}
#include "tree.h"
	for (i = island_regexes_nr - 1; i >= 0; i--) {
	size_t size = sizeof(struct island_bitmap) + (island_bitmap_size * 4);
	int hash_ret;
#define ISLAND_BITMAP_BLOCK(x) (x / 32)
static void add_ref_to_island(const char *island_name, const struct object_id *oid)
	}
	if (!island_marks)

	}
{
	uint32_t bits[FLEX_ARRAY];
		 * We don't have one yet; make a copy-on-write of the
		struct object_entry *entry = &to_pack->objects[i];
#include "object.h"

	int i;
		b_bitmap = kh_value(island_marks, b_pos);
	return 0;

	 */
	deduplicate_islands(r);
			if (src != dst)

		pos = kh_get_oid_map(island_marks, ent->idx.oid);
	src_pos = kh_get_oid_map(island_marks, *src_oid);

	}
		a_bitmap = kh_value(island_marks, a_pos);
static void island_bitmap_or(struct island_bitmap *a, const struct island_bitmap *b)
	a_pos = kh_get_oid_map(island_marks, *a);
	}

		khiter_t pos;
	struct remote_island *island, *core = NULL, **list;
static struct island_bitmap *island_bitmap_new(const struct island_bitmap *old)
	}
		return;
		oe_set_layer(to_pack, entry, 1);
}
	struct island_bitmap *b = xcalloc(1, size);
static const char *core_island_name;
	return todo_a->depth - todo_b->depth;
	/*
	/* walk backwards to get last-one-wins ordering */

static void set_island_marks(struct object *obj, struct island_bitmap *marks)
	 */
	 * than we support.
		struct island_bitmap *marks;
struct remote_island {
	}
	 * against anything -- it's not an important object
			strbuf_addch(&island_name, '-');
static struct remote_island *get_core_island(void)
};

{

	trg_pos = kh_get_oid_map(island_marks, *trg_oid);
static int island_bitmap_get(struct island_bitmap *self, uint32_t i)
	if (self == super)
		return 0;
	struct progress *progress_state = NULL;
static kh_oid_map_t *island_marks;
	return b;
	for (i = 0; i < rl->oids.nr; ++i) {
	strbuf_release(&island_name);
		if (!v)
	struct island_bitmap *b;
		mark_remote_island_1(r, list[i], core && list[i]->hash == core->hash);
#include "refs.h"
	unsigned int depth;
	 */
			struct object *obj;
}
#include "commit.h"
{


			dst++;
	return 2;



	 * updating.
		for (src = ref + 1, dst = src; src < island_count; src++) {
		island_regexes_nr++;
{
#include "delta-islands.h"


	for (i = 0; i < to_pack->nr_objects; ++i) {
	/*



				continue;
	if (!island_marks)
			if (S_ISGITLINK(entry.mode))
	for (i = 0; i < island_bitmap_size; ++i) {
		if (!a_bitmap || !island_bitmap_is_subset(b_bitmap, a_bitmap))
}
}
{
		tree = lookup_tree(r, &ent->idx.oid);
	struct strbuf island_name = STRBUF_INIT;
		khiter_t pos = kh_get_str(remote_islands, core_island_name);

			if (!obj)
			strbuf_addch(&re, '^');
	free(list);
			return 1;
	 * propagate down the tree properly, even if a sub-tree is found in

	for (i = 0; i < island_count; ++i) {
	if (b->refcount > 1) {
	khiter_t pos = kh_get_oid_map(island_marks, commit->object.oid);
	return 0;


		list[i++] = island;

	uint32_t i;
struct tree_islands_todo {
		parse_commit(commit);


		if (pos >= kh_end(island_marks))
	if (hash_ret) {
	 * We should advertise 'ARRAY_SIZE(matches) - 2' as the max,
	remote_islands = kh_init_str();
}
		if (!tree || parse_tree(tree) < 0)
	if (matches[ARRAY_SIZE(matches) - 1].rm_so != -1)
	if (progress)
		if (pos < kh_end(island_marks)) {
	uint64_t hash;
				 int is_core_island)
		if (is_core_island && obj->type == OBJ_COMMIT)
			return config_error_nonbool(k);

{
		struct tree *tree;
#include "pack.h"
static uint32_t island_bitmap_size;
int compute_pack_layers(struct packing_data *to_pack)

static kh_str_t *remote_islands;

		strbuf_addstr(&re, v);
#include "list-objects.h"

	island_count = kh_size(remote_islands);
		return 1;
		return 1;
	if (is_core_island)
			continue;
	return island_bitmap_is_subset(kh_value(island_marks, trg_pos),
#include "pack-bitmap.h"



			if (island_bitmap_get(bitmap, island_counter_core))

 */
	kh_foreach_value(remote_islands, island, {
{
	}
#include "tag.h"

static void deduplicate_islands(struct repository *r)


	if (pos < kh_end(island_marks)) {
}
struct island_bitmap {

		struct tree_desc desc;
	 * to process them in descending tree-depth order so that marks
}


	if (core_island_name) {
		struct object_entry *ent = todo[i].entry;

	const struct tree_islands_todo *todo_b = b;
				 struct remote_island *rl,

int island_delta_cmp(const struct object_id *a, const struct object_id *b)
		return;
		marks->refcount++;
	}

	if (!core_island_name || !island_marks)
{

	struct object_entry *entry;
	pos = kh_put_oid_map(island_marks, obj->oid, &hash_ret);
	}
		return 0;
	struct oid_array oids;

