static const char rev_list_usage[] =
			 * and we don't need any graph output.  (This
	 * If we're counting reachable objects, we can't handle a max count of
	if (arg_missing_action)
		else
		}
		mark_edges_uninteresting(&revs, show_edge, 0);
	/*
		}
		if (!strcmp(arg, ("--no-object-names"))) {

		if (skip_prefix(arg, "--missing=", &arg))
			children = children->next;
		else if (revs.cherry_mark)
	if (arg_show_object_names)
		return;

			use_bitmap_index = 1;
}
	 */
	 * of commits we'd get would be essentially random.
	/*
int cmd_rev_list(int argc, const char **argv, const char *prefix)
#include "list-objects.h"
	 * A bisect set of size N has (N-1) commits further
"    --bisect-all"
	max_count = revs->max_count;
	if (revs->count) {
		 tag_count = 0,
}
	 * to test, as we already know one bad one.
{
		putchar(' ');
		arg_missing_action = MA_ERROR;
		}
		.allow_exclude_promisor_objects = 1,
"    --objects | --objects-edge\n"

			bisect_show_vars = 1;
			 * Add a newline after the commit message.
			continue;
"    --max-count=<n>\n"
	/*
"    --count\n"
static int show_object_fast(
		free_commit_list(commit->parents);
static inline void finish_object__ma(struct object *obj)
	      !revs.pending.nr) &&
	if (info->flags & REV_LIST_QUIET)
	if (finish_object(obj, name, cb_data))
/* display only the oid of each object encountered */
	if (max_count >= 0 && max_count < commit_count)
	case MA_ERROR:
		return 1;
"    --stdin\n"

	}

	off_t found_offset)

			return 0;
		}
{
	int bisect_find_all = 0;
static inline int parse_missing_action_value(const char *value)
		if (!strcmp(arg, ("--no-" CL_ARG__FILTER))) {
		progress = start_delayed_progress(show_progress, 0);
"    --parents\n"
		}
{
static struct oidset omitted_objects;
"    --header | --pretty\n"
		struct oidset_iter iter;
	if (arg_print_omitted)
	int bisect_show_vars = 0;
		fputs(oid_to_hex(&commit->object.oid), stdout);
	 * (ignore) them.
		if (bisect_show_vars)

	if (info->show_timestamp)
		printf("%"PRItime" ", commit->date);

			printf(" %s", oid_to_hex(&parents->item->object.oid));
			if (graph_show_remainder(revs->graph))
		ctx.date_mode_explicit = revs->date_mode_explicit;
		return;
	if (!revs->commits)
"    --all\n"
			info.show_timestamp = 1;
	    (revs->tag_objects || revs->tree_objects || revs->blob_objects))
			revs.verbose_header = 1;
"  ordering output:\n"
	if (revs->print_parents) {
	return 0;
	}
			if (revs.exclude_promisor_objects)
			fetch_if_missing = 0;
		if (!strcmp(arg, "--bisect-all")) {
			printf("?%s\n", oid_to_hex(oid));
	}

		if (skip_prefix(arg, "--progress=", &arg)) {
			bisect_list = 1;

static struct list_objects_filter_options filter_options;

#include "list-objects-filter-options.h"
	struct packed_git *found_pack,
	}
#include "packfile.h"
	 * commit.
	/*
			parents = parents->next;
		return 1;
	 * This must be saved before doing any walking, since the revision
	if (bisect_list) {

	 * machinery will count it down to zero while traversing.
		find_bisection(&revs.commits, &reaches, &all, bisect_find_all);
	return 0;
			return 0;
	if (flags & BISECT_SHOW_ALL) {
"    --bisect-vars\n"
	case MA_PRINT:
{
		while ((oid = oidset_iter_next(&iter)))
;

	if (info->header_prefix)
			revs->count_same++;
static int try_bitmap_count(struct rev_info *revs,
		}
"    --children\n"
	    (revs.left_right || revs.cherry_mark))
		if (!try_bitmap_count(&revs, &filter_options))
}
		struct strbuf buf = STRBUF_INIT;
		cnt = reaches;
	print_var_str("bisect_rev", hex);
	return 0;

	struct bitmap_index *bitmap_git;
#include "commit.h"
	int use_bitmap_index = 0;
		finish_commit(commit);
		if (!strcmp(arg, "--test-bitmap")) {

		struct object_id *oid;
		return;

	traverse_bitmap_commit_list(bitmap_git, revs, &show_object_fast);
		else

		usage(rev_list_usage);
	enum object_type type,
		info.flags |= REV_LIST_QUIET;
	 *
			continue;
	if (revs.diffopt.flags.quick)
{
		}

#include "object.h"
		const char *arg = argv[i];
}
static enum missing_action arg_missing_action;
		return;
	print_var_int("bisect_bad", reaches - 1);
			if (revs->commit_format != CMIT_FMT_ONELINE)
	if (revs->children.name) {

	 */
		if (skip_prefix(arg, ("--" CL_ARG__FILTER "="), &arg)) {
			continue;
	memset(&info, 0, sizeof(info));

			return;
	     !revs.rev_input_given && !revs.read_from_stdin) ||
		else if (revs.left_right)
	case MA_ALLOW_PROMISOR:

		die("missing %s object '%s'",

	 * revs->commits can reach "reaches" commits among
		revs.do_not_die_on_missing_tree = 1;

#include "cache.h"
		return;
	}
static void show_commit(struct commit *commit, void *data)
		if (is_promisor_object(&obj->oid))
		}
		if (revs.commit_format == CMIT_FMT_ONELINE)
			printf("%d\n", revs.count_left + revs.count_right);
	struct rev_info *revs = info->revs;
			continue;
"  limiting output:\n"
		 * field for traversal that is not a left-right traversal,
			bisect_list = 1;
	free_bitmap_index(bitmap_git);

	/*
			parse_list_objects_filter(&filter_options, arg);
	struct rev_list_info info;
			if (buf.len && buf.buf[buf.len - 1] == '\n')
"    --date-order\n"
	}
			arg_show_object_names = 0;

	 */
		while (children) {
	if (revs->count) {

	if (revs->verbose_header) {
		die("unexpected missing %s object '%s'",
"    --left-right\n"
			 * always happens with CMIT_FMT_ONELINE, and it
		info.hdr_termination = '\n';
	const struct object_id *oid,
#include "reflog-walk.h"
		/* The command line has a --pretty  */

			    struct list_objects_filter_options *filter)
				 revs->tag_objects ? &tag_count : NULL);
		die("revision walk setup failed");
		}
	}
	 * A bitmap result can't know left/right, etc, because we don't
			/*
	if (!strcmp(value, "allow-any")) {
{
	return 0;
"    --no-merges\n"
		children = lookup_decoration(&revs->children, &commit->object);
		return;
		return;

		fetch_if_missing = 0;
		}
		bisect_list = 1;
#include "bisect.h"
			      revs.grep_filter.header_list);
	 */
	/*
			 * the rest of the graph output for this
	 * actually traverse.
			 */
			 */
		printf("------\n");
		 * The object count is always accumulated in the .count_right

			continue;
	 */
	for (i = 1; i < argc; i++) {
}
	}
"git rev-list [OPTION] <commit-id>... [ -- paths... ]\n"
"    --[no-]object-names\n"
		}
		BUG("unhandled missing_action");
	else if (revs.verbose_header)
	}
	} else {
		if (!strcmp(arg, "--timestamp")) {
			graph_show_commit_msg(revs->graph, stdout, &buf);
	if (info->flags & REV_LIST_QUIET) {
		struct commit_list *parents = commit->parents;
	}
			 * ends the last line of the commit message,
	if (cnt < reaches)

		arg_missing_action = MA_PRINT;
#include "list-objects-filter.h"
	if (revs.count &&
		while ((oid = oidset_iter_next(&iter)))
static void finish_commit(struct commit *commit)
	const char *show_progress = NULL;
	maybe_flush_or_die(stdout, "stdout");
		if (skip_prefix(arg, "--missing=", &arg)) {
		if (!strcmp(arg, "--exclude-promisor-objects")) {
		return -1;
"  formatting output:\n"

			revs.exclude_promisor_objects = 1;
	print_var_int("bisect_all", all);

		if (buf.len) {
				die(_("object filtering requires --objects"));
	struct rev_info *revs = info->revs;
		struct pretty_print_context ctx = {0};
	free_bitmap_index(bitmap_git);
		parse_object(the_repository, &obj->oid);
	}
	}
	if (argc == 2 && !strcmp(argv[1], "-h"))
		return;
				putchar('\n');

		 tree_count = 0,
	if (revs->max_count >= 0 &&
"    --no-max-parents\n"
			printf("~%s\n", oid_to_hex(oid));
		 */
#define DEFAULT_OIDSET_SIZE     (16*1024)

"    --topo-order\n"
	MA_ALLOW_ANY,    /* silently allow ALL missing objects */


}
		revs.commit_format = CMIT_FMT_RAW;
"    --min-parents=<n>\n"
		else if (commit->object.flags & SYMMETRIC_LEFT)
static void show_edge(struct commit *commit)
	repo_init_revisions(the_repository, &revs, prefix);
	if (!strcmp(value, "print")) {
		if (!strcmp(arg, ("--object-names"))) {
	 * Whether or not we try to dynamically fetch missing objects
"    --max-age=<epoch>\n"
		die(_("rev-list does not support display of notes"));
	if (revs.show_notes)

#include "log-tree.h"
};
	if (prepare_revision_walk(&revs))
static int finish_object(struct object *obj, const char *name, void *cb_data)
"    --remove-empty\n"
	}
	if (oid_object_info_extended(the_repository, &obj->oid, NULL, 0) < 0) {
	return 1;
		show_object_with_name(stdout, obj, name);
#include "progress.h"
"    --sparse\n"
		if (!strcmp(arg, "--bisect-vars")) {
		return -1;
			/*
			 * we need to add graph padding on this line.
		fetch_if_missing = 0;
			bisect_find_all = 1;
#include "config.h"
	default:
{
		oidset_clear(&omitted_objects);
	display_progress(progress, ++progress_counter);

			continue;
enum missing_action {
		}
	bitmap_git = prepare_bitmap_walk(revs, filter);
	 * "--exclude-promisor-objects" acts as a pre-filter on missing objects
		usage(rev_list_usage);
	printf("%s=%d\n", var, val);
	info.revs = &revs;
		finish_commit(commit);
		arg_missing_action = MA_ALLOW_PROMISOR;
			 *
	}
	else
	if (revs->abbrev_commit && revs->abbrev)
		return 1;
	case MA_ALLOW_ANY:

	}
		strbuf_release(&buf);



			putchar('\n');
	}
		 * and cmd_rev_list() made sure that a .count request that
	if (info->revs->verify_objects && !obj->parsed && obj->type != OBJ_COMMIT)
	show_decorations(revs, commit);
		printf("%s\n", oid_to_hex(&obj->oid));
	if (!revs->count)
"    --max-parents=<n>\n"
}
			revs->count_right++;
	MA_PRINT,        /* print ALL missing objects in special section */
	 * Scan the argument list before invoking setup_revisions(), so that we
		}

		revs->count_right++;
				break;

			revs->count_left++;
			printf("%d\t%d\t%d\n", revs.count_left, revs.count_right, revs.count_same);
	if (!strcmp(value, "error")) {
			 * newline.  In this case the newline simply
	cnt = all - reaches;

	if (!strcmp(value, "allow-promisor")) {
				 revs->blob_objects ? &blob_count : NULL,
	 * know if fetch_if_missing needs to be set to 0.
		fputs(get_revision_mark(revs, commit), stdout);
	 * We can't use a bitmap result with a traversal limit, since the set

			 *
			printf("%d\t%d\n", revs.count_left + revs.count_right, revs.count_same);
		struct commit_list *children;

		struct object_id *oid;
		pretty_print_commit(&ctx, commit, &buf);
				graph_show_padding(revs->graph);
				graph_show_oneline(revs->graph);

	if (!bitmap_git)

	uint32_t name_hash,
		fputs(info->header_prefix, stdout);
}

	if (revs.commit_format != CMIT_FMT_UNSPECIFIED) {
		return -1;

	if (revs->left_right || revs->cherry_mark)
	for (i = 1; i < argc; i++) {
	else
			printf(" %s", oid_to_hex(&children->item->object.oid));
		if (!strcmp(arg, "--use-bitmap-index")) {
	graph_show_commit(revs->graph);
		(arg_print_omitted ? &omitted_objects : NULL));
	if (use_bitmap_index) {
	}

	revs.commit_format = CMIT_FMT_UNSPECIFIED;

		return;
		usage(rev_list_usage);
			printf("%d\t%d\n", revs.count_left, revs.count_right);
			putchar(info->hdr_termination);
static struct oidset missing_objects;
"    --unpacked\n"
}

	 * by not crossing the boundary from realized objects to promisor
	uint32_t commit_count = 0,

		if (graph_show_remainder(revs->graph))
	}
"    --abbrev=<n> | --no-abbrev\n"
	int cnt, flags = info->flags;

{
	printf("%s='%s'\n", var, val);
	if (!revs->graph)
			if (revs->commit_format == CMIT_FMT_ONELINE)
	finish_commit(commit);
			continue;
	}
	stop_progress(&progress);


				struct list_objects_filter_options *filter)
		}
			continue;
		return 1;
"  special purpose:\n"
	struct rev_list_info *info = cb_data;
"    --reverse\n"
	     (!(revs.tag_objects || revs.tree_objects || revs.blob_objects) &&
			 * commit.
#include "revision.h"
	traverse_commit_list_filtered(
	if (revs->commits)
			if (parse_missing_action_value(arg))

			bisect_list = 1;
	return 0;
			info.header_prefix = "commit ";
			show_progress = arg;

	struct rev_list_info *info = data;
				die(_("cannot combine --exclude-promisor-objects and --missing"));

	if (revs->max_count >= 0)
	struct commit_list *tried;
		ctx.date_mode = revs->date_mode;
	 *
		return 1;
		    type_name(obj->type), oid_to_hex(&obj->oid));
#include "oidset.h"
			continue; /* already handled above */
#include "pack-bitmap.h"
			revs.show_decorations = 1;
	 * can either print, allow (ignore), or conditionally allow
}
	if (revs.tree_objects)
	char hex[GIT_MAX_HEXSZ + 1] = "";
	struct setup_revision_opt s_r_opt = {
		ctx.abbrev = revs->abbrev;
			continue;
		} else {
		if (!strcmp(arg, "--filter-print-omitted")) {
	if (bisect_list)
	if (revs.count) {
		oidset_iter_init(&missing_objects, &iter);

		 * the show_object() callback, does not ask for .left_right.
}
		return;

			break;
		/* Only --header was specified */



		if (!strcmp(arg, "--exclude-promisor-objects"))
	for (i = 1 ; i < argc; i++) {
	 * objects.
	free_commit_buffer(the_repository->parsed_objects,
#include "object-store.h"
	revs.abbrev = DEFAULT_ABBREV;
		return 1;
	 * "all" commits.  If it is good, then there are
	revs->commits = filter_skipped(revs->commits, &tried,
	count_bitmap_commit_list(bitmap_git, &commit_count,
"    --min-age=<epoch>\n"
		      stdout);
		return -1;
	bitmap_git = prepare_bitmap_walk(revs, filter);
			list_objects_filter_set_no_filter(&filter_options);
	 * from the server, we currently DO NOT have the object.  We
			return 0;
		ctx.color = revs->diffopt.use_color;
			      revs.grep_filter.pattern_list ||
			 * Usually, this newline produces a blank
		oidset_init(&omitted_objects, DEFAULT_OIDSET_SIZE);
	struct rev_info revs;
			arg_show_object_names = 1;

	}
				       NULL, NULL);
}

	if (arg_missing_action == MA_PRINT) {

static int arg_print_omitted; /* print objects omitted by filter */
		if (!strcmp(arg, "--bisect")) {
			return show_bisect_vars(&info, reaches, all);
	if (arg_missing_action == MA_PRINT)

	MA_ALLOW_PROMISOR, /* silently allow all missing PROMISOR objects */
		oidset_insert(&missing_objects, &obj->oid);
		int reaches, all;
static int try_bitmap_traversal(struct rev_info *revs,
	git_config(git_default_config, NULL);
#include "builtin.h"
	if (!bitmap_git)
		fputs(find_unique_abbrev(&commit->object.oid, revs->abbrev),
		commit->parents = NULL;


		ctx.output_encoding = get_log_output_encoding();
		&filter_options, &revs, show_commit, show_object, &info,
		fetch_if_missing = 0;
			 * format doesn't explicitly end in a newline.)
#include "pack.h"
		revs.limited = 1;
		}
{

	}
}
static void print_var_str(const char *var, const char *val)
#include "diff.h"
			 * happens with CMIT_FMT_USERFORMAT when the
	switch (arg_missing_action) {
		if (!strcmp(arg, "--header")) {
"    --no-min-parents\n"

		}
			continue;
	argc = setup_revisions(argc, argv, &revs, &s_r_opt);
"    --bisect\n"
			arg_print_omitted = 1;
	int i;
static void print_var_int(const char *var, int val)
		 * wants to count non-commit objects, which is handled by
	struct rev_info *revs = info->revs;
	int exclude,
	    revs.diff)
	print_var_int("bisect_nr", cnt - 1);

"    --branches\n"
	/* This function only handles counting, not general traversal. */
			if (filter_options.choice && !revs.blob_objects)
		return -1;


	 * On the other hand, if it is bad, then the set
		oid_to_hex_r(hex, &revs->commits->item->object.oid);
		}
				putchar('\n');
	printf("-%s\n", oid_to_hex(&commit->object.oid));
	/*
{
	print_var_int("bisect_good", all - reaches - 1);
	 * to bisect is "reaches".
"    --quiet\n"
{
			continue; /* already handled above */
}
		while (parents) {
	    (revs.tag_objects || revs.tree_objects || revs.blob_objects) &&
	return 0;
		oidset_iter_init(&omitted_objects, &iter);
	int max_count;

	int bisect_list = 0;
				 revs->tree_objects ? &tree_count : NULL,
		commit_count = max_count;
			info.flags |= BISECT_SHOW_ALL;
static struct progress *progress;
{
		oidset_init(&missing_objects, DEFAULT_OIDSET_SIZE);
		traverse_commit_list(revs, show_commit, show_object, info);
	if (commit->parents) {
		if (!try_bitmap_traversal(&revs, &filter_options))
		oidset_clear(&missing_objects);

	if (arg_print_omitted) {
		const char *arg = argv[i];
static void finish_commit(struct commit *commit);
		if (commit->object.flags & PATCHSAME)
			   commit);
	MA_ERROR = 0,    /* fail if any missing objects are encountered */

	if (revs.bisect)
	};
			 * padding line between entries, in which case

	 * commits to traverse, since we don't know which objects go with which
	printf("%d\n", commit_count + tree_count + blob_count + tag_count);
{
	}
			continue;
		    type_name(obj->type), oid_to_hex(&obj->oid));
		putchar('\n');
	struct rev_list_info *info = cb_data;
static int show_bisect_vars(struct rev_list_info *info, int reaches, int all)
		struct oidset_iter iter;
static void show_object(struct object *obj, const char *name, void *cb_data)
		}
	 */
static int arg_show_object_names = 1;

	display_progress(progress, ++progress_counter);
	fprintf(stdout, "%s\n", oid_to_hex(oid));
"    --abbrev-commit\n"
		finish_object__ma(obj);
			 * However, the commit message may not end in a
	 * Let "--missing" to conditionally set fetch_if_missing.
	struct bitmap_index *bitmap_git;

		return -1;
	else
{
#include "graph.h"
	if (show_progress)
		const char *arg = argv[i];

			info.header_prefix = "";
	 * (all-reaches) commits left to be bisected.
	print_var_int("bisect_steps", estimate_bisect_steps(all));
	if (revs->commit_format == CMIT_FMT_ONELINE)
			 * If the message buffer is empty, just show
		ctx.fmt = revs->commit_format;
	if ((!revs.commits && reflog_walk_empty(revs.reflog_info) &&
static unsigned progress_counter;
"    --remotes\n"
		else

				       flags & BISECT_SHOW_ALL,
		if (revs.left_right && revs.cherry_mark)
	save_commit_buffer = (revs.verbose_header ||
			continue;

"    --tags\n"
		die(_("marked counting is incompatible with --objects"));

		/*
	 */
		arg_missing_action = MA_ALLOW_ANY;
			test_bitmap_walk(&revs);

	}
		 blob_count = 0;
