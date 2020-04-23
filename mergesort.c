	void *ptr;

			p.ptr = q.ptr;
				set_next_fn(prev, curr);

};
			p.len = l;
	void *p = l->ptr;
}
	unsigned long len;
static void *get_nth_next(void *list, unsigned long n,
					curr = pop_item(&q, get_next_fn);
		      void *(*get_next_fn)(const void *),
		else

				if (!p.len)
		      void (*set_next_fn)(void *, void *),
				void *prev = curr;
				else if (compare_fn(p.ptr, q.ptr) > 0)
}
		p.ptr = list;
	return list;
			q.len = q.ptr ? l : 0;

}

		q.ptr = get_nth_next(p.ptr, l, get_next_fn);
			while (p.len || q.len) {
#include "mergesort.h"
		struct mergesort_sublist p, q;
			}

				else if (!q.len)
		      int (*compare_fn)(const void *, const void *))
		set_next_fn(curr, NULL);
	l->ptr = get_next_fn(l->ptr);
	}
					curr = pop_item(&q, get_next_fn);
	return p;
	for (l = 1; ; l *= 2) {
		while (p.ptr) {
{
struct mergesort_sublist {
	while (n-- && list)
	if (!list)
	unsigned long l;
			  void *(*get_next_fn)(const void *))
					curr = pop_item(&p, get_next_fn);


					curr = pop_item(&p, get_next_fn);

				else
			q.ptr = get_nth_next(p.ptr, l, get_next_fn);
			list = curr = pop_item(&p, get_next_fn);
			list = curr = pop_item(&q, get_next_fn);
		if (!q.ptr)
		if (compare_fn(p.ptr, q.ptr) > 0)
		list = get_next_fn(list);
		void *curr;
		}
		p.len = q.len = l;
		return NULL;
		      void *(*get_next_fn)(const void *))
{
	return list;
void *llist_mergesort(void *list,
			break;

static void *pop_item(struct mergesort_sublist *l,
{
#include "cache.h"
	l->len = l->ptr ? (l->len - 1) : 0;
