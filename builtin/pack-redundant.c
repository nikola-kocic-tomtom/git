		if (after == list->back)
		llist_sorted_difference_inplace(all_objects, pl->remaining_objects);
	}
		fprintf(stderr, "containing %lu duplicate objects "
	return ret;
#include "repository.h"
	} else {/* insert in front */
	(*list)->front = (*list)->back = NULL;

		new_item->next = after->next;
		add_pack(p);
static inline struct llist_item *llist_insert_back(struct llist *list,

		hint = NULL;

	free(ary);
}
#include "packfile.h"

static size_t sizeof_union(struct packed_git *p1, struct packed_git *p2)
				if (hint != NULL && hint != list->front) {
{
			new_item->next = list->front;
		}
	memcpy(p, entry, sizeof(struct pack_list));
			fprintf(stderr, "\t%s\n", pl->pack->pack_name);
{
	if (pl_a->remaining_objects->size == pl_b->remaining_objects->size) {
	struct llist_item *next;
static inline size_t pack_list_size(struct pack_list *pl)
	p1_step = hashsz + ((p1->index_version < 2) ? 4 : 0);
	       p2_off < p2->num_objects * p2_step)
	while (pl) {
		while (subset) {
	}
	p2_base += 256 * 4 + ((p2->pack->index_version < 2) ? 4 : 8);
			ret++;

static void llist_sorted_difference_inplace(struct llist *A,
"git pack-redundant [--verbose] [--alt-odb] (--all | <filename.pack>...)";
			return llist_insert(list, prev, oid);
	struct llist_item *prev, *l;


		return -1;
					hint = NULL;
			continue;
	pl = unique;
		old_item = old_item->next;
	p->next = *pl;
	/* ignore objects given on stdin */
	new_item->next = NULL;
		else
	struct pack_list *subset;

static void scan_alt_odb_packs(void)
			return prev;
{
		fprintf(stderr, "There are %lu packs available in alt-odbs.\n",
}
	ary[n - 1]->next = NULL;
	list->size++;
		else
int cmd_pack_redundant(int argc, const char **argv, const char *prefix)
	while (l) {
	} else if (pl_a->remaining_objects->size < pl_b->remaining_objects->size) {
		alt = alt->next;
		return 0;
		list->front = new_item;

	*list = xmalloc(sizeof(struct llist));
	struct llist_item *hint, *b;
		/* sort by remaining objects, more objects first */

		}
}
	struct object_id *oid;
	prev = NULL;
	if (pl == NULL)
		if (A->pack == pl->pack)
		while (l) {
		l = l->next;
			p1_off += p1_step;

		usage(pack_redundant_usage);
			pl = pl->next;

	off_t ret = 0;

	new_item = ret->front = llist_item_get();
	l = (hint == NULL) ? list->front : hint;
{
		free(missing);
		}
	}
static void load_all(void)
	const unsigned char *p1_base, *p2_base;

		return pack_list_insert(&altodb_packs, &l);
static inline struct llist_item *llist_insert_sorted_unique(struct llist *list,
					p2_hint);
		p2->unique_objects = llist_copy(p2->remaining_objects);
	l.unique_objects = NULL;
		}
	unique_pack_objects = llist_copy(all_objects);
	while (pl) {
}
	}
			subset = subset->next;
{
		return;
			verbose = 1;
#include "object-store.h"
			llist_item_put(&new_item[i]);
	}
		/* cmp ~ p1 - p2 */
	p2_step = hashsz + ((p2->pack->index_version < 2) ? 4 : 0);
	while (pl) {
					      const struct object_id *oid)

	llist_sorted_difference_inplace(unique_pack_objects, missing);
	}
		hint = llist_sorted_remove(A, b->oid, hint);
static int cmp_remaining_objects(const void *a, const void *b)

		int cmp = hashcmp(p1_base + p1_off, p2_base + p2_off);
			return 1;

		}
	}
			(unsigned long)pack_list_size(altodb_packs));
	struct llist_item *new_item;
		else

		fprintf(stderr, "%luMB of redundant packs in total.\n",

		if (list->size == 0)


				     struct llist *B)

/* another O(n^2) function ... */
		scan_alt_odb_packs();
/* computes A\B */


	struct llist_item *hint, *l;
	while ((subset = pl->next)) {

			list->back = new_item;
	if (alt_odb)
	*min = unique;

		fprintf(stderr, "Redundant packs (with indexes):\n");
					/* we don't know the previous element */

		llist_sorted_difference_inplace(pl->remaining_objects, unique_pack_objects);
	struct pack_list *min = NULL, *red, *pl;
	}
					       const struct pack_list *B)
		pl = min;
			list->size--;

		pl = pl->next;
* This file is licensed under the GPL v2.
					      struct llist_item *after,
		/* cmp ~ p1 - p2 */
static inline struct pack_list * pack_list_insert(struct pack_list **pl,
	p2_base += 256 * 4 + ((p2->index_version < 2) ? 4 : 8);
	while (pl) {
		}
}
			if (prev == NULL) {
	const struct object_id *oid;
	p1_base += 256 * 4 + ((p1->index_version < 2) ? 4 : 8);
	struct pack_list l;
	if ( free_nodes ) {
		if (cmp < 0) { /* p1 has the object, p2 doesn't */
	} else {
	hint = NULL;

*
	else
		pl = pl->next;
static void minimize(struct pack_list **min)

	llist_init(&all_objects);
	struct llist_item *new_item, *old_item, *prev;

{
		while (*(argv + i) != NULL)
	while (alt) {
	free_nodes = item;
			oid = xmalloc(sizeof(*oid));
		} else { /* p2 has the object, p1 doesn't */
static struct pack_list * pack_list_difference(const struct pack_list *A,
		pl = pl->next;
	return ret;
			return l;

static inline void llist_init(struct llist **list)
	struct pack_list **ary, *p;
}
	if (local_packs == NULL)
			l = l->next;
{
		pl = pl->next;
		pl = pl->next;
	struct packed_git *p = get_all_packs(the_repository);
		load_all();
static inline off_t pack_set_bytecount(struct pack_list *pl)
						   const struct object_id *oid)
	}
	return prev;
		}
}
/* Sort pack_list, greater size of remaining_objects first */
	}
	new_item->oid = list->front->oid;
		p = p->next;
}
#include "builtin.h"
			p2_off += p2_step;
		if (*arg == '-')
static void cmp_two_packs(struct pack_list *p1, struct pack_list *p2)
static void cmp_local_packs(void)
{
}
	size_t n = pack_list_size(*pl);
{
	return ret;
					(const struct object_id *)(p1_base + p1_off),

}

	cmp_local_packs();
	while (p) {
		if (!strcmp(arg, "--alt-odb")) {

		return ret;
		const int cmp = oidcmp(l->oid, oid);
	minimize(&min);
		free_nodes = free_nodes->next;
	while (old_item) {
	p1_step = hashsz + ((p1->pack->index_version < 2) ? 4 : 0);
			local = local->next;
					p1_hint);
	}
	}
	}
	load_all_objects();
			list->back = new_item;
	QSORT(ary, n, cmp_remaining_objects);
		return pack_list_insert(&local_packs, &l);
	return llist_insert(list, list->back, oid);
	base = p->index_data;
{

			p2_off += p2_step;
{
	const unsigned int hashsz = the_hash_algo->rawsz;
	l.all_objects_size = l.remaining_objects->size;
			pack_list_insert(&unique, pl);
	if (verbose) {



		fprintf(stderr, "The smallest (bytewise) set of packs is:\n");
	else
			p2_off += p2_step;
}
		if (!strcmp(arg, "--")) {
			p1_off += p1_step;

static inline struct llist_item * llist_sorted_remove(struct llist *list, const struct object_id *oid, struct llist_item *hint)

	*pl = ary[0];
		}
	while ((subset = pl)) {
		return NULL;
static inline struct llist_item *llist_insert(struct llist *list,
}
		if (pl_a->all_objects_size == pl_b->all_objects_size)
#define BLKSIZE 512
							alt->remaining_objects);
	struct packed_git *p = get_all_packs(the_repository);
	return ret;
	/* return if there are no objects missing from the unique set */
	if (!p->pack_local && !(alt_odb || verbose))
	}
{
	char buf[GIT_MAX_HEXSZ + 2]; /* hex hash + \n + \0 */
}
		       pl->pack->pack_name);



	pl = B;
static void load_all_objects(void)
	int i;
	/* remove unique pack objects from the non_unique packs */
	}

	struct llist *remaining_objects;
	p2_base = p2->pack->index_data;
	while (b) {
	struct pack_list *pl, *unique = NULL, *non_unique = NULL;
		}
			p1_off += p1_step;

	while (pl) {
		for (pl = non_unique->next; pl && pl->remaining_objects->size > 0;  pl = pl->next)
		fprintf(stderr, "A total of %lu unique objects were considered.\n",
	ret = xmalloc(sizeof(struct pack_list));
{
	}
		non_unique = non_unique->next;
		while (pl) {
	/* remove objects present in remote packs */
			cmp_two_packs(pl, subset);
	return new_item;
	struct llist_item *prev = NULL, *l;
		}
		if (strstr(p->pack_name, filename))
	size_t ret = 0;
*
* Copyright 2005, Lukas Sandstrom <lukass@etek.chalmers.se>
		l = l->next;
} *local_packs = NULL, *altodb_packs = NULL;
	{
	       p2_off < p2->pack->num_objects * p2_step)
		sort_pack_list(&non_unique);


			ret += sizeof_union(pl->pack, subset->pack);
	new_item->oid = oid;
				list->front = l->next;

					   struct pack_list *entry)

{
		if (!cmp) { /* already exists */
static struct pack_list * add_pack_file(const char *filename)

	llist_init(&ignore);
	ret->next = pack_list_difference(A->next, B);
	while (l) {
		ret += pl->pack->index_size;
		}
		if (cmp > 0) /* not in list, since sorted */
	pl = local_packs;
	struct llist *ret;
}
		pack_list_insert(min, non_unique);
	struct packed_git *pack;
		printf("%s\n%s\n",
		if (non_unique->remaining_objects->size == 0)
struct llist_item {
					(const struct object_id *)(p1_base + p1_off),
}
	while (p1_off < p1->num_objects * p1_step &&
	} else {
	pl = non_unique;
			p2_off += p2_step;
		pl = pl->next;


}
		new_item = free_nodes;
	const unsigned char *base;
		return NULL;
	pl = local_packs;

	if (!p2->unique_objects)
	}

static inline struct llist_item *llist_item_get(void)


	while (non_unique) {
	struct pack_list *next;
		ret++;
static struct llist {
	const unsigned char *p1_base, *p2_base;
static struct pack_list * add_pack(struct packed_git *p)
			const struct object_id *oid, struct llist_item *hint)
		}
			return prev;
			alt_odb = 1;
			continue;

	}
	while (pl) {
	}

		pl = pl->next;
	if (A == NULL)

	if (load_all_packs)
	b = B->front;



	struct llist_item *front;
		b = b->next;
		       sha1_pack_index_name(pl->pack->hash),
			return pack_list_difference(A->next, B);
	return ret;
	int i;
	for (n = 0, p = *pl; p; p = p->next)
	}
	p2_base = p2->index_data;
	/* prepare an array of packed_list for easier sorting */
			i++;
}
		if (!strcmp(arg, "--all")) {
		if (cmp == 0) {
			(unsigned long)pack_set_bytecount(min)/1024);
	while (pl) {
			if (l == list->back)
		new_item = llist_item_get();
	while (off < p->num_objects * step) {
	if (after != NULL) {

	while (p1_off < p1->pack->num_objects * p1_step &&
	struct llist_item *back;
		ary[i]->next = ary[i + 1];
static struct llist_item *free_nodes;
		after->next = new_item;
}
		if (!cmp) { /* found */
		/* have the same remaining_objects, big pack first */
		ary[n++] = p;


				die("Bad object ID on stdin: %s", buf);
static size_t get_pack_redundancy(struct pack_list *pl)
	}
	struct llist *missing, *unique_pack_objects;
{
/* this scales like O(n^2) */
			break;
}
{



	if (strlen(filename) < 40)
{
	unsigned long p1_off = 0, p2_off = 0, p1_step, p2_step;
{
	memcpy(ret, A, sizeof(struct pack_list));
	}
		prev->next = new_item;
		} else { /* p2 has the object, p1 doesn't */
	while (pl) {
				"with a total size of %lukb.\n",
	pl = red = pack_list_difference(local_packs, min);
		const char *arg = argv[i];
}
		return 1;
	}
	}
			} else
	while (pl != NULL) {
			add_pack_file(*(argv + i++));
	if (missing->size == 0) {
	if (verbose)
	}
		p = p->next;
	size_t size;
		llist_sorted_difference_inplace(missing, pl->remaining_objects);
		off += step;
{
		}
	const unsigned int hashsz = the_hash_algo->rawsz;
{
	unsigned long p1_off = 0, p2_off = 0, p1_step, p2_step;
							  l->oid, hint);
/* returns a pointer to an item in front of sha1 */
	if (!isatty(0)) {
} *all_objects; /* all objects which must be present in local packfiles */
	ret->back = new_item;

	struct pack_list *pl_b = *((struct pack_list **)b);
			(unsigned long)all_objects->size);
static int load_all_packs, verbose, alt_odb;
			llist_insert_sorted_unique(ignore, oid, NULL);
	*pl = p;
}

{
	if (open_pack_index(p))
	l = (hint == NULL) ? list->front : hint;
{
		ALLOC_ARRAY(new_item, BLKSIZE);
		pl = pl->next;
			return add_pack(p);
	struct pack_list *p = xmalloc(sizeof(struct pack_list));
};
		p1->unique_objects = llist_copy(p1->remaining_objects);
			continue;
	}
	const struct pack_list *pl;

}
		if (cmp > 0) { /* we insert before this entry */
		while (local) {
		pl = pl->next;
		}
		int cmp = oidcmp(l->oid, oid);
	/* link them back again */
			hint = llist_insert_sorted_unique(all_objects,
	if ((ret->size = list->size) == 0)
	}
	new_item->next = NULL;
		else

		die("Bad pack filename: %s", filename);
	p1_base += 256 * 4 + ((p1->pack->index_version < 2) ? 4 : 8);

	struct pack_list *ret;
			continue;

	struct pack_list *pl = local_packs;

*
	struct llist_item *new_item = llist_item_get();
	if (n < 2)

	size_t all_objects_size;
redo_from_start:
			llist_sorted_difference_inplace(local->remaining_objects,
			p1_hint = llist_sorted_remove(p1->unique_objects,

{
	missing = llist_copy(all_objects);
	struct llist_item *p1_hint = NULL, *p2_hint = NULL;
	l.pack = p;
		pl = pl->next;
		if (!strcmp(arg, "--verbose")) {
			llist_sorted_difference_inplace(pl->remaining_objects, non_unique->remaining_objects);
	while (pl) {
				prev->next = l->next;
			load_all_packs = 1;
	}
	alt = altodb_packs;
	die("Filename %s not found in packed_git", filename);
{
	}
	if (p->pack_local)
	base += 256 * 4 + ((p->index_version < 2) ? 4 : 8);
	return llist_insert_back(list, oid);
		l = pl->remaining_objects->front;

	llist_init(&ret);
		if (cmp < 0) { /* p1 has the object, p2 doesn't */
static struct llist * llist_copy(struct llist *list)
		while ((subset = subset->next))
	struct llist *unique_objects;
			return -1;
	ary = xcalloc(n, sizeof(struct pack_list *));
	struct pack_list *pl_a = *((struct pack_list **)a);
		return;
	size_t ret = 0;
		prev = new_item;
		if (pl->unique_objects->size)
	unsigned long off = 0, step;
		llist_insert_back(l.remaining_objects, (const struct object_id *)(base + off));
		prev = l;

				}
	p1_base = p1->pack->index_data;
	p2_step = hashsz + ((p2->index_version < 2) ? 4 : 0);
	p1_base = p1->index_data;
			(unsigned long)pack_set_bytecount(red)/(1024*1024));
			(unsigned long)get_pack_redundancy(min),

		prev = l;
	return ret;
		const int cmp = hashcmp(p1_base + p1_off, p2_base + p2_off);
		new_item->oid = old_item->oid;
				list->back = prev;
			p1_off += p1_step;
		pl = pl->next;
{
		return NULL;
	item->next = free_nodes;
	old_item = list->front->next;
/*

			if (get_oid_hex(buf, oid))
	for (i = 0; i < n - 1; i++)
	{
			break;
	llist_sorted_difference_inplace(all_objects, ignore);
	struct pack_list *subset, *pl = local_packs;
		if (cmp == 0) {
		llist_sorted_difference_inplace(pl->remaining_objects, ignore);
		local = local_packs;
			llist_item_put(l);

		ret += pl->pack->pack_size;
{

			usage(pack_redundant_usage);
			return 0;
	llist_init(&l.remaining_objects);
	return 0;

		for (; i < BLKSIZE; i++)
	/* find out which objects are missing from the set of unique packs */
		}
			p2_hint = llist_sorted_remove(p2->unique_objects,
	return p;

static inline void llist_item_put(struct llist_item *item)
}
					goto redo_from_start;
		else if (pl_a->all_objects_size < pl_b->all_objects_size)
			break;
static const char pack_redundant_usage[] =


	return new_item;
	for (i = 1; i < argc; i++) {
*/
	pl = altodb_packs;
}
	struct pack_list *local, *alt;
	size_t ret = 0;
	}
	if (!p1->unique_objects)
	/* insert at the end */
	struct llist *ignore;
static void sort_pack_list(struct pack_list **pl)
		pl = pl->next;
}
		die("Zero packs found!");

		/* sort the non_unique packs, greater size of remaining_objects first */
static struct pack_list {
		}
			continue;
		while (fgets(buf, sizeof(buf), stdin)) {
		int i = 1;

			pack_list_insert(&non_unique, pl);
	(*list)->size = 0;
	if (argc == 2 && !strcmp(argv[1], "-h"))
	step = the_hash_algo->rawsz + ((p->index_version < 2) ? 4 : 0);
	while (p) {
}
