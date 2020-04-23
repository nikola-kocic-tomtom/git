			*exact_match = 1;
	return list->items + i;
	while (left + 1 < right) {
		}

			if (free_util)
}

}
{
}
struct string_list_item *string_list_insert(struct string_list *list, const char *string)
		else if (compare > 0)
	*exact_match = 0;
			if (!cmp(list->items[dst - 1].string, list->items[src].string)) {
void string_list_sort(struct string_list *list)
			} else
{
		MOVE_ARRAY(list->items + i, list->items + i + 1, list->nr - i);

	if (exact_match)

int string_list_has_string(const struct string_list *list, const char *string)
	int exact_match, i = get_entry_index(list, string, &exact_match);
{
	return NULL;
int unsorted_string_list_has_string(struct string_list *list,
		count++;
		end = strchr(p, delim);

	for (src = 0; src < list->nr; src++) {
/*
	}
		int i;
	for_each_string_list_item(item, list)
		}
{
	return index;
	return unsorted_string_list_lookup(list, string) != NULL;
}
				    const char *string)
static int add_entry(int insert_at, struct string_list *list, const char *string)

			int free_util)
{
			right = middle;
{
	if (index < 0)
		}
	list->items[index].util = NULL;
	return *item->string != '\0';
	return sort_ctx->cmp(one->string, two->string);
	for (;;) {
		return NULL;
		xstrdup(string) : (char *)string;
	list->nr = list->alloc = 0;
	}
{
	memset(list, 0, sizeof(*list));
	struct string_list_item *retval;
	return exact_match;
	return list->items + index;
			for (i = 0; i < list->nr; i++)
	compare_strings_fn cmp = list->cmp ? list->cmp : strcmp;
			   list->nr - index);
	if (list->items) {
				free(list->items[i].string);
	int left = -1, right = list->nr;

	list->items = NULL;
			left = middle;
			list->items[dst++] = list->items[src];
			return middle;
		}
			for (i = 0; i < list->nr; i++)
		}
	return right;

		if (maxsplit >= 0 && count > maxsplit) {
void string_list_remove_duplicates(struct string_list *list, int free_util)
	struct string_list_item *item;
}
{
		}
{
		}
	int exact_match;
	list->strdup_strings = strdup_strings;
{
}
			break;

{
			return item;
 * Encapsulate the compare function pointer because ISO C99 forbids
struct string_list_item *string_list_append_nodup(struct string_list *list,
			for (i = 0; i < list->nr; i++)
	for (;;) {
}
	int index = get_entry_index(list, string, &exact_match);
	list->nr++;

	if (list->nr > 1) {
			string_list_each_func_t want, void *cb_data)
void unsorted_string_list_delete_item(struct string_list *list, int i, int free_util)
}

					    const char *string)
{
}

	get_entry_index(list, string, &exact_match);
	int count = 0;
		index = -1 - (negative_existing_index ? index : 0);
}

}
	list->nr = dst;

		if (end) {
}
				  int negative_existing_index)
		count++;
			list,
	for (i = 0; i < list->nr; i++)
	list->items[i] = list->items[list->nr-1];
	list->nr--;


		list->nr = dst;
		end = strchr(p, delim);
		if (compare < 0)
				free(list->items[i].util);
	}
			free(list->items[i].util);

		die("internal error in string_list_split_in_place(): "
struct string_list_item *string_list_lookup(struct string_list *list, const char *string)
				if (free_util)
void string_list_init(struct string_list *list, int strdup_strings)
/* returns -1-index if already exists */
		int middle = left + (right - left) / 2;
		} else {

	char *p = string, *end;
	ALLOC_GROW(list->items, list->nr + 1, list->alloc);
struct string_list_item *unsorted_string_list_lookup(struct string_list *list,
 * casting from void * to a function pointer and vice versa.

			p = end + 1;
		}

	if (list->strdup_strings)

#include "string-list.h"
	if (list->strdup_strings)
}
	int i = get_entry_index(list, string, &exact_match);
		else {
int for_each_string_list(struct string_list *list,
{


	retval->string = string;
	retval->util = NULL;
			return count;
		if (end) {
		free(list->items[i].string);
		free(list->items);
	const struct string_list_item *one = a;
		int compare = cmp(string, list->items[middle].string);
		return -1 - index;
	}
				list->items[dst++] = list->items[src];
		free(list->items[i].util);
	compare_strings_fn cmp;
			       int delim, int maxsplit)
{
			for (i = 0; i < list->nr; i++)
	filter_string_list(list, free_util, item_is_not_empty, NULL);
	if (exact_match) {
		for (src = dst = 1; src < list->nr; src++) {
			return count;
}
				free(list->items[src].util);
	int exact_match;
}
					free(list->items[src].string);
};
	return retval;
	int i, ret = 0;
 * inserted */
int string_list_find_insert_index(const struct string_list *list, const char *string,
		compare_strings_fn cmp = list->cmp ? list->cmp : strcmp;

		}
		if (maxsplit >= 0 && count > maxsplit) {
			p = end + 1;
		int src, dst;
	return string_list_append_nodup(

	if (free_util)
			if (list->strdup_strings)
		if (!cmp(string, item->string))
	if (list->items) {
}
					free(list->items[src].util);
void filter_string_list(struct string_list *list, int free_util,
	if (!list->strdup_strings)
	}
	int index = add_entry(-1, list, string);

		if (want(&list->items[src], cb_data)) {
		index = -1 - index;
		}
{
	retval = &list->items[list->nr++];
		if (list->strdup_strings)
}

{
			return count;
		}
	compare_strings_fn cmp = list->cmp ? list->cmp : strcmp;
	struct string_list_sort_ctx sort_ctx = {list->cmp ? list->cmp : strcmp};
}
			string_list_append_nodup(list, xmemdupz(p, end - p));
	if (!exact_match)
	}
	QSORT_S(list->items, list->nr, cmp_items, &sort_ctx);
	if (exact_match)
			string_list_append(list, p);
}
{
{

			free(list->items[i].string);

{
	list->items[index].string = list->strdup_strings ?
static int get_entry_index(const struct string_list *list, const char *string,
			 string_list_each_func_t fn, void *cb_data)
	struct string_list_sort_ctx *sort_ctx = ctx;
	list->nr = list->alloc = 0;
{

	const char *p = string, *end;
		list->nr--;
						  char *string)

void string_list_clear_func(struct string_list *list, string_list_clear_func_t clearfunc)
	return index;
		if (clearfunc) {
}
		if ((ret = fn(&list->items[i], cb_data)))
}
int string_list_split(struct string_list *list, const char *string,
		if (list->strdup_strings) {

{
{
void string_list_remove_empty_items(struct string_list *list, int free_util)

			list->strdup_strings ? xstrdup(string) : (char *)string);

						     const char *string)
{
			*end = '\0';
}
	int count = 0;
struct string_list_sort_ctx
			return count;
			string_list_append(list, p);

		MOVE_ARRAY(list->items + index + 1, list->items + index,
/* if there is no exact match, point to the index where the entry could be
struct string_list_item *string_list_append(struct string_list *list,
static int item_is_not_empty(struct string_list_item *item, void *unused)
				clearfunc(list->items[i].util, list->items[i].string);
#include "cache.h"
		} else {
}
	int src, dst = 0;
{
static int cmp_items(const void *a, const void *b, void *ctx)
		    "list->strdup_strings must not be set");
		if (free_util) {
void string_list_remove(struct string_list *list, const char *string,
int string_list_split_in_place(struct string_list *list, char *string,
 */

			string_list_append(list, p);
				free(list->items[src].string);
		int *exact_match)
		      int delim, int maxsplit)
		free(list->items);
	if (index < list->nr)
	const struct string_list_item *two = b;
		int i;
		die("internal error in string_list_split(): "
	}
		} else {
{

		if (free_util)
	list->items = NULL;
	int exact_match = 0;
	int index = insert_at != -1 ? insert_at : get_entry_index(list, string, &exact_match);
	return ret;
		if (list->strdup_strings) {
			string_list_append(list, p);
void string_list_clear(struct string_list *list, int free_util)

				free(list->items[i].string);
		    "list->strdup_strings must be set");
			string_list_append(list, p);
				if (list->strdup_strings)
}
	int exact_match;
	ALLOC_GROW(list->items, list->nr+1, list->alloc);
	}
