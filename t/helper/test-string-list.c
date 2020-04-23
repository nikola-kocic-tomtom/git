
	}
		parse_string_list(&list, argv[2]);
		 */
		printf("\n");
		 * Split by newline, but don't create a string_list item
		printf("-\n");

		string_list_clear(&list, 0);

		int i;
		struct string_list list = STRING_LIST_INIT_DUP;
	int i;

}
		write_list(&list);
{

		return 0;
		int maxsplit = atoi(argv[4]);
		return 0;
		return 0;
		struct string_list list = STRING_LIST_INIT_NODUP;
	if (argc == 2 && !strcmp(argv[1], "sort")) {
		 * Retain only the items that have the specified prefix.

#include "cache.h"
			strbuf_setlen(&sb, sb.len - 1);

		struct string_list list = STRING_LIST_INIT_DUP;


		struct string_list list = STRING_LIST_INIT_NODUP;


		const char *s = argv[2];
}
		argv[1] ? argv[1] : "(there was none)");
		int maxsplit = atoi(argv[4]);
		string_list_sort(&list);
	if (argc == 5 && !strcmp(argv[1], "split_in_place")) {
{
		 */

static void write_list_compact(const struct string_list *list)
		i = string_list_split_in_place(&list, s, delim, maxsplit);
	if (argc == 3 && !strcmp(argv[1], "remove_duplicates")) {
		for_each_string_list_item(item, &list)
		strbuf_release(&sb);
	if (argc == 5 && !strcmp(argv[1], "split")) {
	for (i = 0; i < list->nr; i++)
	}

	}
		return 0;
		string_list_clear(&list, 0);
	}
 * single empty string).  list->strdup_strings must be set.
		write_list_compact(&list);
}
		string_list_clear(&list, 0);
			printf(":%s", list->items[i].string);

		string_list_remove_duplicates(&list, 0);
		write_list(&list);
		if (sb.len && sb.buf[sb.len - 1] == '\n')
	const char *prefix = (const char *)cb_data;
	if (!list->nr)
		string_list_clear(&list, 0);
/*
		for (i = 1; i < list->nr; i++)
 * ':'-separated list of strings, or "-" to indicate an empty string
	}

#include "string-list.h"
	return starts_with(item->string, prefix);
		printf("[%d]: \"%s\"\n", i, list->items[i].string);
		char *s = xstrdup(argv[2]);
		printf("%s", list->items[0].string);
			puts(item->string);

	return 1;
		write_list_compact(&list);
		int delim = *argv[3];
	if (!strcmp(arg, "-"))
		struct string_list_item *item;
		int delim = *argv[3];
		return 0;
{
}
		strbuf_read(&sb, 0, 0);
		/*
		int i;
		 * Arguments: list|- prefix

{

 */

static int prefix_cb(struct string_list_item *item, void *cb_data)
		i = string_list_split(&list, s, delim, maxsplit);
 * list (as opposed to "", which indicates a string list containing a
		/*
		printf("%d\n", i);
static void parse_string_list(struct string_list *list, const char *arg)
		struct string_list list = STRING_LIST_INIT_DUP;
static void write_list(const struct string_list *list)
	int i;
#include "test-tool.h"
		string_list_split_in_place(&list, sb.buf, '\n', -1);
		free(s);
		printf("%d\n", i);
	fprintf(stderr, "%s: unknown function name: %s\n", argv[0],
	(void)string_list_split(list, arg, ':', -1);
}
{

	if (argc == 4 && !strcmp(argv[1], "filter")) {
		parse_string_list(&list, argv[2]);
		string_list_clear(&list, 0);
		filter_string_list(&list, 0, prefix_cb, (void *)prefix);
		 * for the empty string after the last separator.
	else {
		const char *prefix = argv[3];
int cmd__string_list(int argc, const char **argv)
		return;
		struct strbuf sb = STRBUF_INIT;
	}
 * Parse an argument into a string list.  arg should either be a
