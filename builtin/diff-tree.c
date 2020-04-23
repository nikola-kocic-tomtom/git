#define USE_THE_INDEX_COMPATIBILITY_MACROS
			pptr = &commit_list_insert(parent, pptr)->next;
				fputs(line, stdout);
			pptr = &(commit->parents);
	/*
		tree1 = opt->pending.objects[0].item;
			/* Free the real parent list */
			usage(diff_tree_usage);
	int len = strlen(line);

		break;
		int saved_dcctc = 0;
	opt->diff = 1;
		}

		die(_("index file corrupt"));
			continue;
	static struct rev_info *opt = &log_tree_opt;
#include "cache.h"
	argc = setup_revisions(argc, argv, opt, &s_r_opt);
		return -1;
	case 0:
		return stdin_diff_trees((struct tree *)obj, p);
			  oid_to_hex(&tree2->object.oid));
			struct object_id oid;
		}

#include "repository.h"
#include "config.h"
}
"  --combined-all-paths\n"
	struct object_id oid;
static void diff_tree_tweak_rev(struct rev_info *rev, struct setup_revision_opt *opt)
		tree1 = opt->pending.objects[0].item;
	struct tree *tree2;
	return 0;
{
	if (!commit)
	 * second one is marked UNINTERESTING, we recover the original
		if (!read_stdin)
	while (--argc > 0) {
	char line[1000];
	}
	precompose_argv(argc, argv);
			if (get_oid_hex(line, &oid)) {
		else
}
		      "", &log_tree_opt.diffopt);
	if (read_stdin) {
	tree2 = lookup_tree(the_repository, &oid);
		if (rev->dense_combined_merges)
		}
		}
		usage(diff_tree_usage);
"git diff-tree [--stdin] [-m] [-c | --cc] [-s] [-v] [--pretty] [-t] [-r] [--root] "
			}
	git_config(git_diff_basic_config, NULL); /* no "diff" UI options */
		if (!strcmp(arg, "--stdin")) {
		if (tree2->flags & UNINTERESTING) {
		diff_tree_commit_oid(&tree1->oid);
	if (read_cache() < 0)
	if (!tree2 || parse_tree(tree2))
}
	      oid_to_hex(&oid), type_name(obj->type));
			rev->diffopt.output_format = DIFF_FORMAT_RAW;
"  --root        include the initial commit as diff against /dev/null\n"
	switch (opt->pending.nr) {
	if (!len || line[len-1] != '\n')
	printf("%s %s\n", oid_to_hex(&tree1->object.oid),
	}

	struct commit_list **pptr = NULL;
	 * which means the same thing. If we get the latter, i.e. the
		log_tree_diff_flush(opt);
	s_r_opt.tweak = diff_tree_tweak_rev;

{
static struct rev_info log_tree_opt;
	return diff_result_code(&opt->diffopt, 0);
		struct commit *parent = lookup_commit(the_repository, &oid);
		}
	if (obj->type == OBJ_TREE)
	struct object_id oid;

		opt->diffopt.needed_rename_limit = saved_nrl;
	error("Object %s is a %s, not a commit or tree",
				fflush(stdout);
	opt->disable_stdin = 1;
		tree2 = opt->pending.objects[1].item;
	if (argc == 2 && !strcmp(argv[1], "-h"))
	 * order the user gave, i.e. "a..b", by swapping the trees.
#include "commit.h"
COMMON_DIFF_OPTIONS_HELP;
"  --cc          show combined diff for merge commits removing uninteresting hunks\n"
			read_stdin = 1;
#include "submodule.h"
	case 2:
	/* Graft the fake parents locally to the commit */
	return log_tree_commit(&log_tree_opt, commit);
	int read_stdin = 0;
			else {

	struct object_id oid;
					saved_dcctc = 1;

	return log_tree_commit(&log_tree_opt, commit);
	while (isspace(*p++) && !parse_oid_hex(p, &oid, &p)) {
	 * NOTE!  We expect "a..b" to expand to "^a b" but it is
	 */
	if (!isspace(*p++) || parse_oid_hex(p, &oid, &p) || *p)
/* Diff one or more commits. */
		const char *arg = *++argv;
		usage(diff_tree_usage);
	if (!rev->diffopt.output_format) {
		if (!pptr) {
	diff_tree_oid(&tree1->object.oid, &tree2->object.oid,
	case 1:
#include "builtin.h"

			free_commit_list(commit->parents);

	struct object *tree1, *tree2;
		if (opt->diffopt.detect_rename) {
	struct object *obj;

static int diff_tree_stdin(char *line)
		}

		int saved_nrl = 0;
					saved_nrl = opt->diffopt.needed_rename_limit;
			opt->diffopt.setup |= DIFF_SETUP_USE_SIZE_CACHE;
		if (parent) {
		break;
				diff_tree_stdin(line);
		return error("Need exactly two trees, separated by a space");
}

	memset(&s_r_opt, 0, sizeof(s_r_opt));
{
static int diff_tree_commit_oid(const struct object_id *oid)

		return -1;
	 * perfectly valid for revision range parser to yield "b ^a",
			}
				if (saved_nrl < opt->diffopt.needed_rename_limit)
	if (parse_oid_hex(line, &oid, &p))
	if (!obj)

static int stdin_diff_commit(struct commit *commit, const char *p)
"  -r            diff recursively\n"

	log_tree_diff_flush(&log_tree_opt);
	return -1;
		return -1;
			if (!the_index.cache)
		break;
}
	struct setup_revision_opt s_r_opt;
	opt->abbrev = 0;
#include "log-tree.h"
/* Diff two trees. */

		return stdin_diff_commit((struct commit *)obj, p);
			SWAP(tree2, tree1);
{
	}


			commit->parents = NULL;
static const char diff_tree_usage[] =
	repo_init_revisions(the_repository, opt, prefix);
	const char *p;
		opt->diffopt.degraded_cc_to_c = saved_dcctc;
	line[len-1] = 0;
int cmd_diff_tree(int argc, const char **argv, const char *prefix)
}
"  -c            show combined diff for merge commits\n"
static int stdin_diff_trees(struct tree *tree1, const char *p)
"                show name of file in all parents for combined diffs\n"
		while (fgets(line, sizeof(line), stdin)) {
{
"[<common-diff-options>] <tree-ish> [<tree-ish>] [<path>...]\n"
	struct commit *commit = lookup_commit_reference(the_repository, oid);
		return -1;
	}
		return -1;
		diff_tree_oid(&tree1->oid, &tree2->oid, "", &opt->diffopt);
	obj = parse_object(the_repository, &oid);
	if (obj->type == OBJ_COMMIT)
				if (opt->diffopt.degraded_cc_to_c)
	}
{
#include "diff.h"
				repo_read_index(the_repository);
			rev->diffopt.output_format = DIFF_FORMAT_PATCH;

