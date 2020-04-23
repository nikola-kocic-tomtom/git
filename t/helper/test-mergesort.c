static int compare_strings(const void *a, const void *b)
{
	((struct line *)a)->next = b;
		if (strbuf_getwholeline(&sb, stdin, '\n'))
	struct line *line, *p = NULL, *lines = NULL;
{
int cmd__mergesort(int argc, const char **argv)


	char *text;
{
		lines = lines->next;
static void set_next(void *a, void *b)
	}

#include "cache.h"
			break;
			line->next = NULL;
#include "mergesort.h"
	while (lines) {
		if (p) {
static void *get_next(const void *a)
		p = line;
	return ((const struct line *)a)->next;
{
		printf("%s", lines->text);

	return strcmp(x->text, y->text);
}

		} else {
	lines = llist_mergesort(lines, get_next, set_next, compare_strings);
#include "test-tool.h"
}
		}
			line->next = p->next;
			lines = line;

		line->text = strbuf_detach(&sb, NULL);
	for (;;) {
}
};
	return 0;
		line = xmalloc(sizeof(struct line));
}
	struct line *next;
	}
struct line {
	const struct line *x = a, *y = b;

			p->next = line;
	struct strbuf sb = STRBUF_INIT;

