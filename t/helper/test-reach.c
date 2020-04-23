			if (Y_array[i]->object.flags & reachable_flag)
	else if (!strcmp(av[1], "in_merge_bases"))
		printf("%s(A,X):\n", av[1]);
			case 'X':
		init_contains_cache(&cache);
	while (list) {

		list = list->next;


				A = c;
		if (buf.len < 3)
			    buf.buf, oid_to_hex(&oid));
			die("failed to resolve %s", buf.buf + 2);
#include "cache.h"
		else
		int i, count = 0;

	else if (!strcmp(av[1], "is_descendant_of"))
				ALLOC_GROW(X_array, X_nr + 1, X_alloc);


		}
	A = B = NULL;
		struct contains_cache cache;
	} else if (!strcmp(av[1], "commit_contains")) {

static void print_sorted_commit_ids(struct commit_list *list)
		printf("%s(X):\n", av[1]);
	struct object_id oid_A, oid_B;
		struct object_id oid;
			die("failed to load commit for input %s resulting in oid %s\n",
#include "commit.h"

			default:

		}
	}

#include "config.h"
	} else if (!strcmp(av[1], "can_all_from_reach_with_flag")) {
}
				B = c;
		}
		printf("%s(A,B):%d\n", av[1], in_merge_bases(A, B));
		string_list_append(&s, oid_to_hex(&list->item->object.oid));
		struct commit_list *list = get_merge_bases_many(A, X_nr, X_array);
		printf("%s(X,_,_,0,0):%d\n", av[1], can_all_from_reach_with_flag(&X_obj, 2, 4, 0, 0));
		}

#include "string-list.h"
		struct commit_list *iter = Y;
	else if (!strcmp(av[1], "get_merge_bases_many")) {
}
				break;
		if (!peeled)
				commit_list_insert(c, &Y);
				die(_("commit %s is not marked reachable"),
	}

	} else if (!strcmp(av[1], "reduce_heads")) {
				oidcpy(&oid_B, &oid);
		printf("%s(_,A,X,_):%d\n", av[1], commit_contains(&filter, A, X, &cache));
	struct object_array X_obj = OBJECT_ARRAY_INIT;
				break;
								reachable_flag);
int cmd__reach(int ac, const char **av)
#include "test-tool.h"
				die("unexpected start of line: %c", buf.buf[0]);
	if (!strcmp(av[1], "ref_newer"))
	int i;
		print_sorted_commit_ids(list);
		printf("%s(A,X):%d\n", av[1], is_descendant_of(A, X));
		struct ref_filter filter;
		struct commit_list *list = get_reachable_subset(X_array, X_nr,
		printf("get_reachable_subset(X,Y)\n");
	string_list_sort(&s);
		if (get_oid_committish(buf.buf + 2, &oid))
	strbuf_release(&buf);
			filter.with_commit_tag_algo = 0;
			iter->item->object.flags |= 2;
			continue;

	while (strbuf_getline(&buf, stdin) != EOF) {
		struct commit *c;
{
	X = Y = NULL;
	}
#include "commit-reach.h"
#include "tag.h"
#include "ref-filter.h"
			case 'B':
		const int reachable_flag = 1;
			case 'A':
				ALLOC_GROW(Y_array, Y_nr + 1, Y_alloc);


				add_object_array(orig, NULL, &X_obj);
	int X_nr, X_alloc, Y_nr, Y_alloc;
	exit(0);
{
	struct commit_list *X, *Y;



		print_sorted_commit_ids(list);
				commit_list_insert(c, &X);
		if (ac > 2 && !strcmp(av[2], "--tag"))
			    buf.buf, oid_to_hex(&oid));
		exit(1);
				break;
	struct commit **X_array, **Y_array;

			filter.with_commit_tag_algo = 1;
	struct repository *r = the_repository;
		for (i = 0; i < Y_nr; i++) {
		peeled = deref_tag_noverify(orig);
			die("failed to load commit for input %s resulting in oid %s\n",
	} else if (!strcmp(av[1], "get_reachable_subset")) {
		struct object *peeled;
		printf("%s\n", s.items[i].string);
				count--;
		if (!c)
			case 'Y':

				    oid_to_hex(&list->item->object.oid));
			count++;
		printf("%s(X,Y):%d\n", av[1], can_all_from_reach(X, Y, 1));

		struct commit_list *current;
		struct object *orig;
	struct commit *A, *B;
				X_array[X_nr++] = c;
				break;


		c = object_as_type(r, peeled, OBJ_COMMIT, 0);
			die(_("too many commits marked reachable"));

	struct string_list s = STRING_LIST_INIT_DUP;

		printf("%s(A,B):%d\n", av[1], ref_newer(&oid_A, &oid_B));
		if (count < 0)

	} else if (!strcmp(av[1], "can_all_from_reach")) {

				Y_array[Y_nr++] = c;
	string_list_clear(&s, 0);
			if (!(list->item->object.flags & reachable_flag))
	ALLOC_ARRAY(X_array, X_alloc);
	ALLOC_ARRAY(Y_array, Y_alloc);
		while (iter) {
		struct commit_list *list = reduce_heads(X);
	for (i = 0; i < s.nr; i++)
		print_sorted_commit_ids(list);
	struct strbuf buf = STRBUF_INIT;
				oidcpy(&oid_A, &oid);
			iter = iter->next;
	if (ac < 2)
								Y_array, Y_nr,

#include "parse-options.h"
		for (current = list; current; current = current->next) {
	X_nr = Y_nr = 0;
		orig = parse_object(r, &oid);
	setup_git_directory();
	X_alloc = Y_alloc = 16;
		switch (buf.buf[0]) {
