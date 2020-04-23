};
#define REPORT(name, type)	\
{


 *
union any_object {
	void *ret;
 * up with maximal alignment because it doesn't know what the object alignment
#include "blob.h"
struct alloc_state {
#include "commit.h"

static void report(const char *name, unsigned int count, size_t size)
		  r->parsed_objects->name##_state->count * sizeof(type) >> 10)
}
}
    report(#name, r->parsed_objects->name##_state->count, \
	/* bookkeeping of allocations */
{

void clear_alloc_state(struct alloc_state *s)
 * The standard malloc/free wastes too much space for objects, partly because

	FREE_AND_NULL(s->slabs);
	s->count++;
	struct object *obj = alloc_node(r->parsed_objects->object_state, sizeof(union any_object));
	c->index = alloc_commit_index(r);
	void *p;   /* first free node in current allocation */
	return t;
		ALLOC_GROW(s->slabs, s->slab_nr + 1, s->slab_alloc);
	}

		s->p = xmalloc(BLOCKING * node_size);
static inline void *alloc_node(struct alloc_state *s, size_t node_size)
}
		s->slabs[s->slab_nr++] = s->p;
	int count; /* total number of nodes allocated */
	struct commit commit;
}
{

#include "alloc.h"
	c->graph_pos = COMMIT_NOT_FROM_GRAPH;
	ret = s->p;
#include "tag.h"
	memset(ret, 0, node_size);
		free(s->slabs[s->slab_nr]);
	int nr;    /* number of nodes left in current allocation */
	t->object.type = OBJ_TAG;
	return c;
#include "tree.h"
	int slab_nr, slab_alloc;

void *alloc_blob_node(struct repository *r)
struct alloc_state *allocate_alloc_state(void)
	REPORT(object, union any_object);

	fprintf(stderr, "%10s: %8u (%"PRIuMAX" kB)\n",
	}

{
{
}
	c->generation = GENERATION_NUMBER_INFINITY;
	void **slabs;
}
	t->object.type = OBJ_TREE;
	REPORT(commit, struct commit);

	c->object.type = OBJ_COMMIT;
	REPORT(blob, struct blob);
void init_commit_node(struct repository *r, struct commit *c)
	struct blob blob;
{
{
	struct tag *t = alloc_node(r->parsed_objects->tag_state, sizeof(struct tag));
	obj->type = OBJ_NONE;
static unsigned int alloc_commit_index(struct repository *r)
	return xcalloc(1, sizeof(struct alloc_state));
		s->slab_nr--;

 * it maintains all the allocation infrastructure, but even more because it ends
	struct object object;
	s->nr--;
#define BLOCKING 1024
	return ret;

		s->nr = BLOCKING;
}
{

 * alloc.c  - specialized allocator for internal objects
void *alloc_tag_node(struct repository *r)
	struct commit *c = alloc_node(r->parsed_objects->commit_state, sizeof(struct commit));
}
	struct blob *b = alloc_node(r->parsed_objects->blob_state, sizeof(struct blob));

#include "cache.h"
 * for the new allocation is.
{
{
{
}
	if (!s->nr) {

	return t;
}
 * Copyright (C) 2006 Linus Torvalds
	struct tree *t = alloc_node(r->parsed_objects->tree_state, sizeof(struct tree));

#include "object.h"
}

	return obj;

void *alloc_commit_node(struct repository *r)
	b->object.type = OBJ_BLOB;
void *alloc_object_node(struct repository *r)
}
/*
	struct tree tree;
			name, count, (uintmax_t) size);
	return b;
	s->p = (char *)s->p + node_size;
	while (s->slab_nr > 0) {
	struct tag tag;
void alloc_report(struct repository *r)
	REPORT(tag, struct tag);
{
	init_commit_node(r, c);

 *
};
void *alloc_tree_node(struct repository *r)
 */
	return r->parsed_objects->commit_count++;

	REPORT(tree, struct tree);
