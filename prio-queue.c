


	int ix, child;
		swap(queue, i, j);
	}

		if (compare(queue, parent, ix) <= 0)



void *prio_queue_peek(struct prio_queue *queue)
	if (!queue->nr)
	if (!queue->nr)
		return NULL;
	result = queue->array[0].data;
	if (!queue->compare)
	if (queue->compare != NULL)
		return queue->array[queue->nr - 1].data;

static inline void swap(struct prio_queue *queue, int i, int j)
	SWAP(queue->array[i], queue->array[j]);
{
		    compare(queue, child, child + 1) >= 0)
		BUG("prio_queue_reverse() on non-LIFO queue");

}
{
}
		child = ix * 2 + 1; /* left */
	ALLOC_GROW(queue->array, queue->nr + 1, queue->alloc);
#include "cache.h"
		cmp = queue->array[i].ctr - queue->array[j].ctr;
		if (compare(queue, ix, child) <= 0)
}
			break;
		return queue->array[--queue->nr].data; /* LIFO */
{
{
		return result;
		return; /* LIFO */
{
void *prio_queue_get(struct prio_queue *queue)
		if (child + 1 < queue->nr &&
	for (ix = queue->nr - 1; ix; ix = parent) {
	return queue->array[0].data;
#include "prio-queue.h"
	FREE_AND_NULL(queue->array);
	/* Push down the one at the root */
	/* Bubble up the new one */
	queue->nr++;
	queue->array[queue->nr].ctr = queue->insertion_ctr++;
	for (i = 0; i < (j = (queue->nr - 1) - i); i++)
void clear_prio_queue(struct prio_queue *queue)
	queue->array[queue->nr].data = thing;
	int ix, parent;
}
	return cmp;


	queue->insertion_ctr = 0;
		swap(queue, parent, ix);
	if (!queue->compare)
		swap(queue, child, ix);
	void *result;
	int cmp = queue->compare(queue->array[i].data, queue->array[j].data,
	}



	/* Append at the end */
}
	return result;
	if (!queue->compare)
static inline int compare(struct prio_queue *queue, int i, int j)
	for (ix = 0; ix * 2 + 1 < queue->nr; ix = child) {
	int i, j;
{
void prio_queue_put(struct prio_queue *queue, void *thing)
			child++; /* use right child */
	queue->alloc = 0;

	queue->nr = 0;
void prio_queue_reverse(struct prio_queue *queue)
}
		return NULL;
	if (!--queue->nr)
		parent = (ix - 1) / 2;
	queue->array[0] = queue->array[queue->nr];
			break;
}

				 queue->cb_data);
{
	if (!cmp)

