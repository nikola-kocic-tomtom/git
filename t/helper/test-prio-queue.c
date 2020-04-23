#include "prio-queue.h"
	return 0;
			prio_queue_put(&pq, v);
			void *peek = prio_queue_peek(&pq);
{
	}
{
			show(get);
			pq.compare = NULL;
int cmd__prio_queue(int argc, const char **argv)
			*v = atoi(*argv);
static int intcmp(const void *va, const void *vb, void *data)
	const int *a = va, *b = vb;
{
		printf("%d\n", *v);
		} else if (!strcmp(*argv, "stack")) {
	while (*++argv) {
}
				BUG("peek and get results do not match");
	if (!v)

				show(get);

		} else if (!strcmp(*argv, "dump")) {
				get = prio_queue_get(&pq);
			int *v = xmalloc(sizeof(*v));


		}
	free(v);
			if (peek != get)
#include "test-tool.h"
}
			void *peek;
					BUG("peek and get results do not match");
	else
#include "cache.h"
	return *a - *b;
		if (!strcmp(*argv, "get")) {
			void *get;

				if (peek != get)
		printf("NULL\n");
			void *get = prio_queue_get(&pq);
			while ((peek = prio_queue_peek(&pq))) {
	struct prio_queue pq = { intcmp };
}
static void show(int *v)
		} else {
			}
