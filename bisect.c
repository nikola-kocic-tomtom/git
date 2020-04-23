	 * and errors in the child process, signaled by res > 0
		 * so that the call chain can simply check
		if (p->item->object.flags & UNINTERESTING)
	free(rev);
					   const struct object_id *oid)



	}
	rev[n++] = get_commit_reference(r, current_bad_oid);
	char *filename;
			printf(_("Bisecting: a merge base must be tested\n"));
		return best_bisection(list, nr);
	if (!all) {
	}
}
	}
			best = list;
{

	free(array);
static unsigned get_prn(unsigned count)
	int prn, index, i;
	}
			/*
					     int nr, int *weights,
		"Maybe you mistook %s and %s revs?\n"),

				   int *count,
	revs.limited = 1;
		entry = p;
	int res = 0;
	return filtered;
#include "quote.h"
	if (!good_revs.nr)

	b = (struct commit_dist *)b_;

	const char *filename = git_path_bisect_terms();
		return 0;

				   struct commit_list **tried,
 * If that's not the case, we need to check the merge bases.
			/* Does it happen to be at exactly half-way? */
	for (p = list, i = 0; i < cnt; i++) {
				res = BISECT_INTERNAL_SUCCESS_MERGE_BASE;
 *
	struct commit_list *p;
				*skipped_first = -1;
 * but traversal is with pathspec).
	 */
		char *good_hex = join_oid_array_hex(&good_revs, ' ');
{
 * If a merge base must be tested by the user, its source code will be
	while (strbuf_getline_lf(&str, fp) != EOF) {



	/* Clean up objects used, as they will be reused. */
		}
	struct rev_info revs;

int estimate_bisect_steps(int all)
		if (p) {
 * - If one is "good" (or "old"), that's good, we have nothing to do.
			    int flag, void *cb_data)
				continue;
{
	strbuf_release(&good_prefix);
{
			tried = &list->next;
		unsigned long size;
	for (; n > 1; n >>= 1)
	struct commit_list *p, *best;
	argv_checkout[2] = bisect_rev_hex;
				/* indicate early success */


 * - If a merge base must be tested, on success return
	free(filename);
		float y = (x + (float)val / x) / 2;
	}
				*skipped_first = 1;
 * Estimate the number of bisect steps left (after the current step)
			*tried = list;
	*rev_nr = n;
	strbuf_release(&str);
			res = bisect_checkout(mb, no_checkout);
	while (counted < nr) {
	     p = next) {
{
	ALLOC_ARRAY(rev, 1 + good_revs.nr);
	rev = get_bad_and_good_commits(r, &rev_nr);
	 */
	}
					return list;
		strbuf_addstr(&joined_hexs, oid_to_hex(array->oid + i));
		return BISECT_NO_TESTABLE_COMMIT;


	result = delete_refs("bisect: remove", &refs_for_removal, REF_NO_DEREF);
		for (pp = commit->parents; pp; pp = pp->next)
 * n - 1 steps left looks like:
		strbuf_reset(&buf);
			fprintf(stderr, " %.*s", subject_len, subject_start);

	 * 3 is halfway of 6 but 2 and 4 are not.
}
	FILE *fp;
	struct stat st;
	if (stat(filename, &st) || !S_ISREG(st.st_mode))
	find_bisection(&revs.commits, &reaches, &all, !!skipped_revs.nr);
 */
static const char *argv_show_branch[] = {"show-branch", NULL, NULL};
	if (!res) {

					     &size);
		p->next = last;
static struct commit_list *best_bisection_sorted(struct commit_list *list, int nr)
			break;
	}
		if (commit->object.flags & (UNINTERESTING | COUNTED))
			best_distance = distance;

	struct strbuf str = STRBUF_INIT;
	int log2 = 0;
	return strbuf_detach(&joined_hexs, NULL);
	 * Count the number of total and tree-changing items on the
		goto done;
		strbuf_getline_lf(&str, fp);
	if (read_bisect_refs())
{
#include "oid-array.h"
/*
			/*
static int compare_commit_dist(const void *a_, const void *b_)
			/*
	struct commit_dist *array = xcalloc(nr, sizeof(*array));
	free(good_hex);
			free_commit_list(list->next);

static inline int exp2i(int n)
	if (all < 3)
			*read_bad = "bad";
		die(_("Not a valid commit name %s"), oid_to_hex(oid));
 * have to return a fully filtered list.
}
	if (!current_bad_oid)
 *
			if (!(flags & TREESAME)) {
	for_each_ref_in("refs/bisect", mark_for_removal, (void *) &refs_for_removal);
	int nr = 0;

static struct commit_list *best_bisection(struct commit_list *list, int nr)
	update_ref(NULL, "BISECT_EXPECTED_REV", bisect_rev, NULL, 0, UPDATE_REFS_DIE_ON_ERR);

				show_list("bisection 2 count one",
	 */
	/*
			 */

#include "revision.h"
	}

		}
		      struct commit_list *list)
	unlink_or_warn(git_path_bisect_terms());

int bisect_clean_state(void)
		log2++;
		*skipped_first = 0;

	} else {
	int cnt, i;
		commit->object.flags &= ~COUNTED;


	}
	}
static struct commit_weight commit_weight;
#include "diff.h"


	const char *filename = git_path_bisect_names();
	FILE *fp = fopen(filename, "r");
	/*

	 */
 * - If one is "skipped", we can't know but we should warn.
				/* This means we know it's not skipped */
{
		oid_array_append(&good_revs, oid);
{
			list->item = best->item;
			fprintf(stderr, "%3d", weight(p));
			res = handle_bad_merge_base();
			weight_set(p, -1);
static inline int log2i(int n)
			die(_("Badly quoted content in file '%s': %s"),
			 * BISECT_ANCESTORS_OK file is not absolutely necessary,


				    const struct object_id *bad)
		 * Using BISECT_INTERNAL_SUCCESS_1ST_BAD_FOUND (-10)

	free(weights);
		case 0:
	argv_show_branch[1] = bisect_rev_hex;
		unsigned flags = p->item->object.flags;

	repo_init_revisions(r, revs, prefix);



	result = get_merge_bases_many(rev[0], rev_nr - 1, rev + 1);
	 * can both be treated as regular BISECT_FAILURE (-1).
				"between %s and [%s].\n"),
			*f = list;
{
/*
	if (!skipped_revs.nr)
static GIT_PATH_FUNC(git_path_head_name, "head-name")
			(flags & TREESAME) ? ' ' : 'T',

#include "refs.h"
				counted++;
	if (skipped_first)
	bisect_common(&revs);
	return list;
	int reaches = 0, all = 0, nr, steps;
	 * So we will first count distance of merges the usual
					  counted, nr, list);
		if (distance > best_distance) {
	counted = 0;
	fclose(fp);
	/*
	 * way, and then fill the blanks using cheaper algorithm.
	strbuf_release(&str);
	struct strbuf buf = STRBUF_INIT;
	int nr, on_list;
#include "log-tree.h"

static GIT_PATH_FUNC(git_path_bisect_ancestors_ok, "BISECT_ANCESTORS_OK")
	/* Check if all good revs are ancestor of the bad rev. */
static int check_ancestors(struct repository *r, int rev_nr,
	struct strbuf good_prefix = STRBUF_INIT;
	return list;
	refs_for_removal.strdup_strings = 1;
	if (a->distance != b->distance)
			break;
			}
	if (!tried)
	char *steps_msg;
		next = p->next;

	int count;
	/* Bisecting with no good rev is ok. */
	 * then you can reach one commit more than that parent
		printf("%s\n", oid_to_hex(&tried->item->object.oid));
		res = !strcmp(str.buf, oid_to_hex(oid));
		}
}
}
			free(p);
		*read_bad = strbuf_detach(&str, NULL);

		if (!(commit->object.flags & TREESAME))
 * We use (*skipped_first == -1) to mean "it has been found that the
}
		printf(_("%s was both %s and %s\n"),
	for (i = 0; i < good_revs.nr; i++)
		if (p->item->object.flags & UNINTERESTING)
	};
{

			nr++;
			 * bisection step.
		return 0;
		d = (y > x) ? y - x : x - y;
		res = error_if_skipped_commits(tried, current_bad_oid);
		if (nr - distance < distance)

		enum object_type type;


static int count_distance(struct commit_list *entry)
	if (!skipped_revs.nr)
			continue;
	/*
	if (p->item->object.flags & TREESAME)
	do {
	return BISECT_FAILED;
		  "Bisecting: %d revisions left to test after this %s\n",

			distance = nr - distance;
		       term_good,
		 * until the cmd_bisect__helper() caller.
			struct commit_list *q;
	for (i = 0; i < array->nr; i++) {
static const char *term_good;

		if (res < 0)
static struct commit *get_commit_reference(struct repository *r,
	return c;
	if (read_paths)
			break;
	int result = 0;
	return nr;
	return rev;
			if (previous)
	fprintf(stderr, _("Some %s revs are not ancestors of the %s rev.\n"


	return for_each_ref_in("refs/bisect/", register_ref, NULL);
		current_bad_oid = xmalloc(sizeof(*current_bad_oid));
		rev[n++] = get_commit_reference(r, good_revs.oid + i);
static int register_ref(const char *refname, const struct object_id *oid,
				show_list("bisection 2 count one",
	 * end up counting them twice that way.
	if (!val)
			 * the bisection process will continue at the next
 * We read them and store them to adapt the messages accordingly.
#include "cache.h"
 * It means that we want to know if the first commit in the list is
	clear_commit_marks_many(rev_nr, rev, ALL_REV_FLAGS);
	int res;

{

static enum bisect_error handle_bad_merge_base(void)
}
			 * Errors in `run_command()` itself, signaled by res < 0,

};
		}
	return res;
{
		list->next = NULL;
	}
	struct commit *commit;
 */
static int count_interesting_parents(struct commit *commit)
	int best_distance = -1;
static void show_diff_tree(struct repository *r,
		if (!find_all && halfway(p, nr))

	steps = estimate_bisect_steps(all);
		} else if (!strcmp(term_bad, "new") && !strcmp(term_good, "old")) {
	return BISECT_ONLY_SKIPPED_LEFT;
		else
}
				   int show_all,
			f = &list->next;
	for (p = list, cnt = 0; p; p = p->next) {
		}
			fprintf(stderr, " %.*s", 8,
	if (strbuf_getline_lf(&str, fp) != EOF)
		res = check_merge_bases(rev_nr, rev, no_checkout);
			continue;

	QSORT(array, cnt, compare_commit_dist);
{
	struct argv_array rev_argv = ARGV_ARRAY_INIT;
		/*
		if (i < cnt - 1)
				bad_hex, bad_hex, good_hex);

/*
	return res;
				"This means the bug has been fixed "
 * ancestor of the "bad" rev.
	return oidcmp(&a->commit->object.oid, &b->commit->object.oid);
		return error(_("a %s revision is needed"), term_bad);

	 * count_distance() for single strand of pearls.
	strbuf_addstr(&good_prefix, "-");
		"must be skipped.\n"

	while (list) {
	**commit_weight_at(&commit_weight, elem->item) = weight;

		return res;
	setup_revisions(ARRAY_SIZE(argv) - 1, argv, &opt, NULL);
/*

		*skipped_first = 0;
		if (nr - distance < distance)
{
		if (flags & UNINTERESTING) {
	}
	}

		 * for negative return values for early returns up
			 * otherwise inherit it from q directly.
		}
	steps_msg = xstrfmt(Q_("(roughly %d step)", "(roughly %d steps)",
{
{
		case 1:
	 * they usually reach the same ancestor and you would
	struct strbuf str = STRBUF_INIT;
		fprintf(stderr, " %.*s", 8, oid_to_hex(&commit->object.oid));
	}
	res = (revs.commits != NULL);
#include "bisect.h"
}
			(flags & COUNTED) ? 'C' : ' ');
 * This does "git diff-tree --pretty COMMIT" without one fork+exec.
	/* Cleanup head-name if it got left by an old version of git-bisect */
	struct commit_dist *a, *b;
	n = log2i(all);
 * So if the first commit is skipped, we cannot take the shortcut to
 * - If we don't know, we should check it out and ask the user to test.
	free(steps_msg);
	struct commit_list *tried;

		}
}

		"diff-tree", "--pretty", "--stat", "--summary", "--cc", NULL
{
static struct oid_array good_revs;
	return 1 << n;
			 * might be wrong.
		}

			return;
}
static int read_bisect_refs(void)
		 */
	int i;

 * and P(2^n + x) < 0.5 means 2^n < 3x
 * Custom integer square root from
			 * So, just signal with a warning that something
static struct commit **get_bad_and_good_commits(struct repository *r,
	/*
static int mark_for_removal(const char *refname, const struct object_id *oid,
			} else if (skipped_first && !*skipped_first) {
 * checkout the trial commit but instead simply updates BISECT_HEAD.
		strbuf_addf(&buf, "dist=%d", array[i].distance);
}
		 * We should return error here only if the "bad"
	const char *argv[] = {
		if (res)

	for (p = list; p; p = p->next) {

		free_commit_list(p->next);
					  counted, nr, list);

	int n, counted;
	return **commit_weight_at(&commit_weight, elem->item);
			strbuf_addch(&joined_hexs, delim);
 * - If one is "bad" (or "new"), it means the user assumed something wrong
 * The terms used for this bisect session are stored in BISECT_TERMS.
		       term_bad);
	} else {
	if (check_ancestors(r, rev_nr, rev, prefix))

 *
		goto done;
 * "check_merge_bases" checks that merge bases are not "bad" (or "new").
	printf(_("We cannot bisect more!\n"));
static void read_bisect_paths(struct argv_array *array)
}
						int *rev_nr)

		} else {
			   struct commit **rev, const char *prefix)

			 */
			close(fd);

 * non-merge entries.
			return res;
			*read_good = "good";
	strbuf_release(&buf);
		return BISECT_FAILED;
	}
				bad_hex, bad_hex, good_hex);
	return best;
 * unknown.  After running count_distance() first, they will get zero
}
	for ( ; tried; tried = tried->next)
		return list;
 *
	struct commit_list *filtered = NULL, **f = &filtered;
 * In this function, passing a not NULL skipped_first is very special.
			     int read_paths)
	return log2;
			/* Move current to tried list */
{
	if (revs->tree_objects)
			break;
		if (weight(p) != -2)

	show_list("bisection 2 sorted", 0, nr, list);
					    const char *prefix,
 * BISECT_INTERNAL_SUCCESS_MERGE_BASE (-11) a special condition
	list = filter_skipped(list, tried, 0, &count, &skipped_first);
	unlink_or_warn(git_path_bisect_log());
		else
			return p;
 */
 */
		if (!(flags & TREESAME))
	fclose(fp);
		p->next = NULL;
		*count = 0;
		list = next;
			    filename, str.buf);

	return (int)x;
			/*
		return 0;
	float d, x = val;
static const char *argv_checkout[] = {"checkout", "-q", NULL, "--", NULL};
			     const char *bad_format, const char *good_format,
	}
static void show_list(const char *debug, int counted, int nr,
 * just "return list" when we find the first non skipped commit, we
	} else if (starts_with(refname, good_prefix.buf)) {
				 oid_to_hex(good_revs.oid + i));
	unlink_or_warn(git_path_bisect_expected_rev());
{
		struct commit_list *next = list->next;

	unlink_or_warn(git_path_bisect_start());
	struct string_list *refs = cb_data;

 */
		"We continue anyway."),
	cur = list;
		if (errno == ENOENT) {
{
}
			fprintf(stderr, _("The merge base %s is bad.\n"
struct commit_dist {
			term_bad);
	*tried = NULL;
 * check_good_are_ancestors_of_bad().
	while (list) {
		printf("%s is the first %s commit\n", oid_to_hex(bisect_rev),
			return -abs(res);


				filename);

			}
		if (oideq(mb, current_bad_oid)) {
			/* Move current to filtered list */
		distance = weight(p);
			warning_errno(_("could not create file '%s'"),

	if (!skipped_first)
			continue;
			if (!show_all) {
		distance = weight(p);
 *
static int is_expected_rev(const struct object_id *oid)
#include "object-store.h"
	strbuf_release(&str);
static void bisect_common(struct rev_info *revs)
{
	 */
#include "commit-slab.h"
}
		*read_good = strbuf_detach(&str, NULL);
#define DEBUG_BISECT 0
		if (*commit_weight_at(&commit_weight, p->item))
	for (count = 0, p = commit->parents; p; p = p->next) {
 * first commit is not skipped". In this case *skipped_first is set back

	return (e < 3 * x) ? n : n - 1;
	clear_commit_weight(&commit_weight);
		} else {
	return 0;
		term_good, term_bad, term_good, term_bad);

	enum bisect_error res = BISECT_OK;
		if (i + 1 < array->nr)
	return bisect_checkout(bisect_rev, no_checkout);
 * skipped because we will want to test a commit away from it if it is
	 * However, if you have more than one parents, you cannot
 */
	}

		show_diff_tree(r, prefix, revs.commits->item);
			break;
	res = run_command_v_opt(argv_show_branch, RUN_GIT_CMD);
			int flags, void *cb_data)

		oid_array_append(&skipped_revs, oid);
	if (no_checkout) {
	enum bisect_error res = BISECT_OK;
		 * This means the bisection process succeeded.
	unlink_or_warn(git_path_bisect_run());
	bisect_rev = &revs.commits->item->object.oid;
	int count, skipped_first;
		argv_array_pushf(&rev_argv, good_format,
		struct commit *commit = list->item;
	for (n = 0, p = list; p; p = p->next) {

	free_commit_list(result);
{

	res = check_good_are_ancestors_of_bad(r, prefix, no_checkout);
		x = y;
	return res;
 * to 0 just before the function returns.
	}
		struct object *obj = &(array[i].commit->object);
		if (!strcmp(term_bad, "bad") && !strcmp(term_good, "good")) {
		return b->distance - a->distance; /* desc sort */
		if (sq_dequote_to_argv_array(str.buf, array))
	if (!strcmp(refname, term_bad)) {
static inline int halfway(struct commit_list *p, int nr)
		subject_len = find_commit_subject(buf, &subject_start);
 * weight = -1 means it has one parent and its distance is yet to
		return 0;
			 * otherwise, it is known not to reach any
		/* Create file BISECT_ANCESTORS_OK. */
 * weight = -2 means it has more than one parent and its distance is
	*commit_list = best;

			continue;
	if (!fp) {
	e = exp2i(n);
		commit->object.flags |= COUNTED;
static char *join_oid_array_hex(struct oid_array *array, char delim)

	     p;
}
		unsigned flags = p->item->object.flags;
	int i;
 */
	count = count * 1103515245 + 12345;
	 * If you have only one parent in the resulting set
				p = p->next;
			     const char *prefix,
	string_list_append(&refs_for_removal, xstrdup("BISECT_HEAD"));
	 * steps)" translation.
		list = list->next;
#include "argv-array.h"
	 */
	fprintf(stderr, "%s (%d/%d)\n", debug, counted, nr);
}
			handle_skipped_merge_base(mb);
#define COUNTED		(1u<<16)

			distance = nr - distance;
		int subject_len;
	fp = fopen_or_warn(filename, "r");
	struct commit_list *p;
		p = commit->parents;

	/* rev_argv.argv[0] will be ignored by setup_revisions */
	int *weights;
		array[cnt].distance = distance;
	if (!stat(filename, &st) && S_ISREG(st.st_mode))
	warning(_("the merge base between %s and [%s] "
	}
 * We use the convention that return BISECT_INTERNAL_SUCCESS_1ST_BAD_FOUND (-10) means
				bad_hex, term_bad, term_good, bad_hex, good_hex);
		return BISECT_MERGE_BASE_CHECK;


	}
 * Default is bad/good.
			continue;

/*
static GIT_PATH_FUNC(git_path_bisect_terms, "BISECT_TERMS")
			 */
	char *mb_hex = oid_to_hex(mb);
				return p;
		struct commit *commit = p->item;

				"This means the first '%s' commit is "

				if (q->item->object.flags & UNINTERESTING)
	/*

	bisect_rev_setup(r, &revs, prefix, "^%s", "%s", 0);
 */
			fprintf(stderr, _("The merge base %s is new.\n"
	memcpy(bisect_rev_hex, oid_to_hex(bisect_rev), the_hash_algo->hexsz + 1);
	return skip_away(list, count);
 * zero or positive weight is the number of interesting commits it can
		 * commit is also a "skip" commit.
				weight_set(p, weight(q));
	string_list_clear(&refs_for_removal, 0);

	if (skipped_first && *skipped_first == -1)
#include "config.h"
	if (best) {
	if (!find_all)
		last = p;
			fprintf(stderr, "---");
	struct strbuf str = STRBUF_INIT;
	for (i = 0; i < good_revs.nr; i++)
{
	filename = git_pathdup("BISECT_ANCESTORS_OK");
 * This is a pseudo random number generator based on "man 3 rand".
	FILE *fp = xfopen(filename, "r");
				weight_set(p, weight(q)+1);
#include "sha1-lookup.h"
	init_commit_weight(&commit_weight);
		if (!find_all) {
		p->item = array[i].commit;
	index = (count * prn / PRN_MODULO) * sqrti(prn) / sqrti(PRN_MODULO);
 * the bisection process finished successfully.

	struct commit **rev;
 * P(2^n + x) == (2^n - x) / (2^n + x)
{

{

	 * introduced in the commit 4796e823a.
		fprintf(stderr, "\n");
		"git bisect cannot work properly in this case.\n"
	}
			nr++;

			}
		  steps), steps);

	if (!DEBUG_BISECT)
	weights = xcalloc(on_list, sizeof(*weights));
static GIT_PATH_FUNC(git_path_bisect_names, "BISECT_NAMES")

}
static enum bisect_error error_if_skipped_commits(struct commit_list *tried,
	case -1: case 0: case 1:
		weight_set(p, count_distance(p));
 *
}
				return cur;
	while (entry) {

		if (flags & TREESAME)

			 * tree-changing commit and gets weight 0.
			return list;

	prn = get_prn(count);
		die("revision walk setup failed");
{
{
	argv_array_push(&rev_argv, "bisect_rev_setup");
	if (res)
			if (0 <= weight(p))




 done:
		fprintf(stderr, _("No testable commit found.\n"
}
 * https://en.wikipedia.org/wiki/Integer_square_root
			   struct commit *commit)
 * and we must return error with a non 0 error code.
		return list;
/*
	printf("There are only 'skip'ped commits left to test.\n"
enum bisect_error bisect_next_all(struct repository *r, const char *prefix, int no_checkout)
			if (!(flags & TREESAME)) {

		}

			best = p;
	if (DEBUG_BISECT)
	 */
static GIT_PATH_FUNC(git_path_bisect_run, "BISECT_RUN")
	struct commit_list *p;
			for (q = p->item->parents; q; q = q->next) {
#include "commit.h"

		/* Does it happen to be at exactly half-way? */
static struct commit_list *managed_skipped(struct commit_list *list,
				"The property has changed "
			 * can both be treated as regular BISECT_FAILURE (-1).

		} else {
#include "run-command.h"

		if (res)
			return res;
	argv_array_pushf(&rev_argv, bad_format, oid_to_hex(current_bad_oid));
	x = all - e;
	git_config(git_diff_ui_config, NULL);

 * for this application.
	/* Check if file BISECT_ANCESTORS_OK exists. */
	/* Do the real work of finding bisection commit. */
				   int *skipped_first)
		update_ref(NULL, "BISECT_HEAD", bisect_rev, NULL, 0,
static enum bisect_error check_good_are_ancestors_of_bad(struct repository *r,
static const char *term_bad;
	} while (d >= 0.5);
	struct strbuf joined_hexs = STRBUF_INIT;
	} else if (starts_with(refname, "skip-")) {
		if (fd < 0)
	}
		return list;
			if (count)

}
	if (oideq(bisect_rev, current_bad_oid)) {
	for (; result; result = result->next) {
{
	argv_array_push(&rev_argv, "--");
	 * just add their distance and one for yourself, since
	}
{
#include "list-objects.h"
static inline int weight(struct commit_list *elem)
}
		return 1;
	for (p = list; p; p = p->next) {
static struct commit_list *do_find_bisection(struct commit_list *list,
	 * Errors in `run_command()` itself, signaled by res < 0,
				weight_set(p, 1);
 * reach, including itself.  Especially, weight = 0 means it does not
 * is increased by one between each call, but that should not matter

	int n, x, e;
					     int find_all)
	int distance;


static inline void weight_set(struct commit_list *elem, int weight)
	enum bisect_error res = BISECT_OK;

		return 0;
		cnt++;
	revs.commits = managed_skipped(revs.commits, &tried);
}

	char *bad_hex = oid_to_hex(current_bad_oid);

		strbuf_getline_lf(&str, fp);


static GIT_PATH_FUNC(git_path_bisect_expected_rev, "BISECT_EXPECTED_REV")
			if (skipped_first && !*skipped_first)
	for (nr = on_list = 0, last = NULL, p = *commit_list;
{
		return best_bisection_sorted(list, nr);

	char bisect_rev_hex[GIT_MAX_HEXSZ + 1];
 */
 * be computed.
		const char *subject_start;

		read_bisect_paths(&rev_argv);
{
/*
 * It is not used properly because the seed is the argument and it
 * checked out to be tested by the user and we will return.
		"between %s and %s.\n"
		array[cnt].commit = p->item;
	nr = all - reaches - 1;

			continue;
	char *good_hex = join_oid_array_hex(&good_revs, ' ');

static void clear_distance(struct commit_list *list)
			weight_set(p, -2);
static struct object_id *current_bad_oid;
	struct stat st;

			p = p->next;
					    int no_checkout)
	read_bisect_terms(&term_bad, &term_good);
	revs->commit_format = CMIT_FMT_UNSPECIFIED;
	}

	revs->abbrev = 0;
				return previous;
		switch (count_interesting_parents(commit)) {
	unlink_or_warn(git_path_bisect_ancestors_ok());
{
{
		struct commit_list *pp;
	}
	*tried = NULL;
#define PRN_MODULO 32768

		die(_("reading bisect refs failed"));
 * indeed skipped.
			break;
	switch (2 * weight(p) - nr) {
 * We care just barely enough to avoid recursing for
			 * weight for p is unknown but q is known.
}
			if (!find_all && halfway(p, nr))
	struct commit **rev;
		res = error_if_skipped_commits(tried, NULL);
			while (p) {
	enum bisect_error res = BISECT_OK;
	       "The first %s commit could be any of:\n", term_bad);
	 * TRANSLATORS: the last %s will be replaced with "(roughly %d
			 * and errors in the child process, signaled by res > 0
				oid_to_hex(&pp->item->object.oid));
{

	show_list("bisection 2 counted all", counted, nr, list);
		 */
	struct commit_list *list, *p, *best, *next, *last;
	strbuf_addstr(&good_prefix, term_good);
	struct rev_info revs;
	return -abs(res);
		if (i == index) {
	else

	 * list, while reversing the list.
	bisect_rev_setup(r, &revs, prefix, "%s", "^%s", 1);
	if (bad)

static void handle_skipped_merge_base(const struct object_id *mb)
		char *buf = read_object_file(&commit->object.oid, &type,
/*
{
				"between %s and [%s].\n"),
		struct commit *commit = entry->item;
	if (!c)
			die_errno(_("could not read file '%s'"), filename);
			"Maybe you started with bad path parameters?\n"));



		previous = cur;
			}
}

 *
		*commit_weight_at(&commit_weight, p->item) = &weights[n++];
 * BISECT_INTERNAL_SUCCESS_1ST_BAD_FOUND return code into an error or a non zero exit code.
		} else if (0 <= oid_array_lookup(&skipped_revs, mb)) {
	for (p = list; p; p = p->next) {
static enum bisect_error bisect_checkout(const struct object_id *bisect_rev, int no_checkout)
				continue;
		*reaches = weight(best);
		for (p = list; p; p = p->next) {
	best = list;
				if (0 <= weight(q))
		    int *all, int find_all)
	fclose(fp);
		} else {
 * In this case the calling function or command should not turn a
	show_list("bisection 2 entry", 0, 0, *commit_list);
					break;
	log_tree_commit(&opt, commit);
	if (!fp)
		count++;
			   const char *prefix,
		return BISECT_OK;
		const struct object_id *mb = &result->item->object.oid;
		return 0;

}
static struct commit_list *skip_away(struct commit_list *list, int count)
static enum bisect_error check_merge_bases(int rev_nr, struct commit **rev, int no_checkout)
static void bisect_rev_setup(struct repository *r, struct rev_info *revs,
			else
		return;

 *
	return (count/65536) % PRN_MODULO;
	return count;
}
			(flags & UNINTERESTING) ? 'U' : ' ',
	 * Cleanup BISECT_START last to support the --no-checkout option
 */
static int sqrti(int val)
				counted++;
	*all = nr;
static GIT_PATH_FUNC(git_path_bisect_log, "BISECT_LOG")
void read_bisect_terms(const char **read_bad, const char **read_good)

	if (prepare_revision_walk(revs))
	show_list("bisection 2 initialize", counted, nr, list);
		unsigned flags = p->item->object.flags;
					continue;
}
}
		add_name_decoration(DECORATION_NONE, buf.buf, obj);
{
	list = last;
	 * Don't short-cut something we are not going to return!
static struct oid_array skipped_revs;
				nr += count_distance(p);
 * "check_good_are_ancestors_of_bad" checks that all "good" revs are

		mark_edges_uninteresting(revs, NULL, 0);
		int distance;
 * If no_checkout is non-zero, the bisection process does not
	return result;
		}
		if (0 <= oid_array_lookup(&skipped_revs, &list->item->object.oid)) {
		fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0600);
			}
	}
 * used for bisection, and we just don't care enough.
	/* XXX leak rev_argv, as "revs" may still be pointing to it */
		struct commit *commit = p->item;
		  nr), nr, steps_msg);
 * This is a truly stupid algorithm, but it's only
{


	if (count)

{
			fprintf(stderr, _("The merge base %s is %s.\n"
}
		} else if (0 <= oid_array_lookup(&good_revs, mb)) {
{
		fprintf(stderr, "%c%c%c ",
	previous = NULL;
			 * add one for p itself if p is to be counted,
	string_list_append(refs, ref);
	struct rev_info opt;
				"between %s and [%s].\n"),
			if (!oideq(&cur->item->object.oid, current_bad_oid))
			if (!q)
	for (i = 0; cur; cur = cur->next, i++) {
 * for early success, this will be converted back to 0 in
	struct commit_list *cur, *previous;
 * reach any tree-changing commits (e.g. just above uninteresting one

		printf("%s\n", oid_to_hex(bad));
	struct commit *c = lookup_commit_reference(r, oid);
		oidcpy(current_bad_oid, oid);
		if (flags & TREESAME)
		unsigned flags = commit->object.flags;
 * or positive distance.
}
	char *ref = xstrfmt("refs/bisect%s", refname);
		on_list++;
	 * can reach.  So we do not have to run the expensive
}
 *
	struct commit_list *result;
/*
	return 0;
}

	bisect_common(&revs);
			   UPDATE_REFS_DIE_ON_ERR);
	if (p) {
/* Remember to update object flag allocation in object.h */
	unlink_or_warn(git_path_head_name());

		}

#include "commit-reach.h"
	const char *filename = git_path_bisect_expected_rev();
		default:

	printf(Q_("Bisecting: %d revision left to test after this %s\n",
		int distance;
}
			continue;
			p = p->next;
			best->next = NULL;
	 *
	/*

}

		bad_hex, good_hex, term_bad, mb_hex, bad_hex);
		char *bad_hex = oid_to_hex(current_bad_oid);
	default:
	}


		clear_distance(list);
/*
		/*
	 * 2 and 3 are halfway of 5.

{
	 *
	/* There may be some refs packed during bisection */
}
void find_bisection(struct commit_list **commit_list, int *reaches,
		struct commit_list *p;
		res = run_command_v_opt(argv_checkout, RUN_GIT_CMD);

				(*count)++;

		strbuf_trim(&str);

			unsigned flags = p->item->object.flags;
	a = (struct commit_dist *)a_;
struct commit_list *filter_skipped(struct commit_list *list,
	if (!revs.commits) {
					   struct commit_list **tried)
	return res;
	setup_revisions(rev_argv.argc, rev_argv.argv, revs, NULL);

 */

			if (!res)

	repo_init_revisions(r, &opt, prefix);

	if (is_expected_rev(current_bad_oid)) {
/*
	unlink_or_warn(git_path_bisect_names());
	best = do_find_bisection(list, nr, weights, find_all);
	struct string_list refs_for_removal = STRING_LIST_INIT_NODUP;
}
}

{

		if (subject_len)
				if (!skipped_first || !*skipped_first)
		"So we cannot be sure the first %s commit is "
		unsigned flags = commit->object.flags;
static GIT_PATH_FUNC(git_path_bisect_start, "BISECT_START")

}
	struct object_id *bisect_rev;
	int fd, rev_nr;
define_commit_slab(commit_weight, int *);
 * For any x between 0 included and 2^n excluded, the probability for
	show_list("bisection 2 count_distance", counted, nr, list);
}



	struct commit_list *p;
		return BISECT_INTERNAL_SUCCESS_1ST_BAD_FOUND;
			 */
		counted++;
		return 0;
		       oid_to_hex(current_bad_oid),

	int i, n = 0;
