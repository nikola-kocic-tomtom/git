				 "--peel-tag", "--name-only", "--no-undefined",
		OPT_INTEGER(0, "candidates", &max_candidates,
	if (!peel_ref(path, &peeled)) {
	while (list) {
		if (!n->tag || parse_tag(n->tag))
		    !skip_prefix(path, "refs/remotes/", &path_to_match)) {
static int always;
	argv_array_pushl(&args, "internal: The first arg is not parsed",
	unsigned misnamed:1;
static int get_name(const char *path, const struct object_id *oid, int flag, void *cb_data)
#include "blob.h"
}
		argv_array_init(&args);
	return 0;
	}
	 * in an error message).  --all allows any refs to be used.
		die(_("Not a valid object name %s"), arg);
	}
static int max_candidates = 10;
		if (always)
				n->path, n->tag->tag);
}
	if (get_oid(arg, &oid))
#include "object-store.h"
			int fd, result;
		}
			}

		int found = 0;
			p->object.flags |= c->object.flags;
		if (label_width < 0) {
	int is_annotated, prio;
	if (n->tag) {
		}
			for (i = 0; i < ARRAY_SIZE(prio_names); i++) {
			   const struct hashmap_entry *entry_or_key,
		 * Select one to keep based upon their tagger date.

			       struct tag **tag)

				return 1;
{
			argv_array_push(&args, "--always");
	N_("head"), N_("lightweight"), N_("annotated"),
	} else {
	repo_init_revisions(the_repository, &revs, NULL);
	if (n->prio == 2 && !n->tag) {
				if (label_width < w)
		is_annotated = 0;
			argv_array_push(&args, "HEAD");
	 * we fall back to lightweight ones (even without --tags,
	struct tag *tag;
{
		if (c->object.flags & best->flag_within) {
			}
		{OPTION_STRING, 0, "broken",  &broken, N_("mark"),
#include "argv-array.h"
{
		return cmd_name_rev(args.argc, args.argv, prefix);
					annotated_cnt++;
static void append_name(struct commit_name *n, struct strbuf *dst)

	}
		strbuf_addstr(dst, suffix);
		e->prio = prio;
		struct commit_name **slot;
		if (!all) {
	if (n && (tags || all || n->prio == 2)) {
		t = lookup_tag(the_repository, oid);
		if (n->misnamed || longformat)

		}
static void append_suffix(int depth, const struct object_id *oid, struct strbuf *dst)

	if (prepare_revision_walk(&revs))
		e->misnamed = 0;
		OPT_STRING_LIST(0, "exclude", &exclude_patterns, N_("pattern"),
};
	}
				t->flag_within = 1u << match_cnt;
		if (!e->tag) {
}
	 * By default, we only use annotated tags, but with --tags
			       int prio,
			       const struct object_id *oid)
	if (max_candidates < 0)

	if (oideq(&pcd->looking_for, &obj->oid) && !pcd->dst->len) {
	const struct commit_name *cn1, *cn2;
	"diff-index", "--quiet", "HEAD", "--", NULL
		have_util = 1;
			parents = parents->next;
#include "list-objects.h"
		NULL);

	if (replace_name(e, prio, oid, &tag)) {
		OPT_BOOL(0, "always",        &always,
			argv_array_pushv(&args, argv);

{

				max_candidates, max_candidates,

			strbuf_add_unique_abbrev(dst, cmit_oid, abbrev);
};
	unsigned flag_within;
			die(_("No tags can describe '%s'.\n"
	if (contains) {

		return 0;
		struct hashmap_iter iter;
		fprintf(stderr, _("describe %s\n"), arg);
	struct option options[] = {
		strbuf_addstr(dst, n->path);
	struct commit_name *name;
		describe("HEAD", 1);
		struct argv_array args;
				argv_array_pushf(&args, "--exclude=refs/tags/%s", item->string);
		struct object_id *cmit_oid = &cmit->object.oid;
static void add_to_known_names(const char *path,
	puts(sb.buf);
#include "lockfile.h"
	traverse_commit_list(&revs, process_commit, process_object, &pcd);
{
		OPT_BOOL(0, "tags",       &tags, N_("use any tag, even unannotated")),
		"--objects", "--in-commit-order", "--reverse", "HEAD",
	 */
#include "hashmap.h"
	} else {
	return 0;
	struct possible_tag all_matches[MAX_TAGS];
		die(_("--long is incompatible with --abbrev=0"));
static const char *suffix, *dirty, *broken;
			read_cache();

	}
{
		struct string_list_item *item;
			       const struct object_id *oid,
	 * pattern.
{

	unsigned name_checked:1;
		OPT__ABBREV(&abbrev),
			if (!t || parse_tag(t))
	if (cmit)
			argv_array_pushv(&cp.args, diff_index_args);
	if (abbrev < 0)
#include "parse-options.h"
				t->name = n;
	n = find_commit_name(&cmit->object.oid);
			if (first_parent)
	struct tag *tag = NULL;
		OPT_BOOL(0, "debug",      &debug, N_("debug search strategy on stderr")),
		}
#include "config.h"

			       const struct object_id *peeled,


	return seen_commits;
		max_candidates = 0;
	else if (is_tag)
{
			if (!dirty)
		*tag = t;
	struct process_commit_data *pcd = data;
			case 1:
	if (suffix)
	cmit = lookup_commit_reference_gently(the_repository, &oid, 1);
		struct string_list_item *item;

	const char *path_to_match = NULL;

		struct commit_list *parents = c->parents;
	save_commit_buffer = 0;
			    oid_to_hex(cmit_oid));
		}
		prio = 1;
		OPT_BOOL(0, "long",       &longformat, N_("always use long format")),
			c = lookup_commit_reference_gently(the_repository,
		prio = 2;
				/* diff-index aborted abnormally */
}
	cmit = lookup_commit_reference(the_repository, oid);
		if (broken) {
		reset_revision_walk();

			refresh_index(&the_index, REFRESH_QUIET|REFRESH_UNMERGED,
	unsigned int unannotated_cnt = 0;
			if (!tags && !all && n->prio < 2) {
struct process_commit_data {
				strbuf_addstr(dst, suffix);
}
	if (gave_up_on) {

	for_each_rawref(get_name, NULL);

		is_annotated = !oideq(oid, &peeled);
				break;
			result = run_diff_index(&revs, 0);
	else
				suffix = dirty;
			n->misnamed = 1;
	QSORT(all_matches, match_cnt, compare_pt);
		fprintf(stderr, _("traversed %lu commits\n"), seen_commits);
	if (debug)
	if (skip_prefix(path, "refs/tags/", &path_to_match)) {
			       int prio,
		OPT_BOOL(0, "first-parent", &first_parent, N_("only follow first parent")),
			N_("show abbreviated commit object as fallback")),
				break;
static const char *diff_index_args[] = {
			}
			if (c)
		die(_("No names found, cannot describe anything."));
		die(_("%s is neither a commit nor blob"), arg);
		if (strcmp(n->tag->tag, all ? n->path + 5 : n->path)) {
};
			    N_("only output exact matches"), 0),

static int commit_name_neq(const void *unused_cmp_data,
}
}
		clear_commit_marks(cmit, -1);
			best->depth++;
	struct commit_name *n;
				w = strlen(_(prio_names[i]));
		return a->depth - b->depth;
};
{
		}
};

				}
			fprintf(stderr,

				struct possible_tag *t = &all_matches[cur_match];
	if (a->found_order != b->found_order)
			e->path = NULL;


	 * If we're given exclude patterns, first exclude any tag which match
	struct hashmap_entry entry;
static unsigned long finish_depth_computation(
static int abbrev = -1; /* unspecified */
				if (n->prio == 2)
		if (gave_up_on) {
	struct commit_list *list;
		while (parents) {
		if (all)
	while (*list) {
			struct commit *p = parents->item;
	if (a->depth != b->depth)

}
	}
			   N_("do not consider tags matching <pattern>")),
		die("revision walk setup failed");
	if (argc == 0) {
		struct commit_name *n;
		/* Reject anything outside refs/tags/ unless --all */
		if (!t || parse_tag(t))
		free(e->path);
				if (!(i->object.flags & best->flag_within))
	struct commit_list **list,
	reset_revision_walk();
		strbuf_addf(pcd->dst, ":%s", path);
	return hashmap_get_entry_from_hash(&names, oidhash(peeled), peeled,
		}
}
		if (annotated_cnt && !list) {
				t->depth = seen_commits - 1;

	if (!max_candidates)
				if (t->depth < best_depth) {
{
		} else if (dirty) {
static int tags;	/* Allow lightweight tags */
	 * any of the exclude pattern.
					best_depth = t->depth;
	if (all_matches[0].name->misnamed || abbrev)
			case 0:
	unsigned long seen_commits = 0;
			switch (run_command(&cp)) {
	}
			e->tag = t;
					label_width = w;

}
{
	hashmap_init(&names, commit_name_neq, NULL, 0);
	if (debug)
	N_("git describe [<options>] --dirty"),
			unsigned best_within = 0;
		if (!e) {
	git_config(git_default_config, NULL);
	if (debug) {
	} else {
	if (longformat && abbrev == 0)
			if (!(c->object.flags & t->flag_within))
	 * we still remember lightweight ones, only to give hints
		slot = commit_names_peek(&commit_names, c);
				return 0;
	return 0;
			struct child_process cp = CHILD_PROCESS_INIT;
static inline struct commit_name *find_commit_name(const struct object_id *peeled)
	} else if (dirty) {
		describe_blob(oid, &sb);
	char *path;
	strbuf_addf(dst, "-%d-g%s", depth, find_unique_abbrev(oid, abbrev));
			struct possible_tag *t = &all_matches[cur_match];
{
			if (!diff_result_code(&revs.diffopt, result))
			return 1;
}
	cn2 = container_of(entry_or_key, const struct commit_name, entry);
				t->depth++;
			oidcpy(&e->peeled, peeled);
		describe_commit(&oid, &sb);
				break;
		strbuf_addstr(dst, n->tag->tag);

static const char * const describe_usage[] = {
				break;
	 */
	struct object_id looking_for;
		if (unannotated_cnt)
			warning(_("tag '%s' is externally known as '%s'"),
	free_commit_list(list);
			return 0;
		}
		/* Multiple annotated tags point to the same commit.
				BUG("malformed internal diff-index command line");
static struct string_list exclude_patterns = STRING_LIST_INIT_NODUP;
		OPT_END(),
	strbuf_release(&sb);


			while (a) {
			if (0 <= fd)
		die(_("no tag exactly matches '%s'"), oid_to_hex(&cmit->object.oid));
			t = lookup_tag(the_repository, &e->oid);
				struct possible_tag *t = &all_matches[match_cnt++];
			cp.no_stdin = 1;

	} else {
	if (!e || e->prio < prio)
	commit_list_insert(cmit, &list);
	 */
		seen_commits++;
		if (always) {
					best_within = t->flag_within;
#include "exec-cmd.h"
		OPT_BOOL(0, "all",        &all, N_("use any ref")),

	}
	unsigned long seen_commits = 0;
	struct commit *cmit;
			append_suffix(0, n->tag ? get_tagged_oid(n->tag) : oid, dst);
static int replace_name(struct commit_name *e,
			struct commit_list *a = *list;
	cn1 = container_of(eptr, const struct commit_name, entry);
			PARSE_OPT_OPTARG, NULL, (intptr_t) "-dirty"},
				c->object.flags |= t->flag_within;
/* diff-index command arguments to check if working tree is dirty. */
{
	N_("git describe [<options>] [<commit-ish>...]"),
				if (debug)
	}


			    N_("consider <n> most recent tags (default: 10)")),
			setup_work_tree();
	struct rev_info revs;
			strbuf_addstr(dst, suffix);
struct commit_name {
	if (setup_revisions(args.argc, args.argv, &revs, NULL) > 1)
			   const struct hashmap_entry *eptr,
		if (!found)
		seen_commits++;

			if (!wildmatch(item->string, path_to_match, 0)) {
			for (cur_match = 0; cur_match < match_cnt; cur_match++) {
	};
define_commit_slab(commit_names, struct commit_name *);
	struct process_commit_data pcd = { null_oid, oid, dst, &revs};

}
				 NULL);
		n->tag = lookup_tag(the_repository, &n->oid);
		}

		} else
				"gave up search at %s\n"),
	int is_tag = 0;
		}
		return;



	return !oideq(&cn1->peeled, peeled ? peeled : &cn2->peeled);
#include "commit-slab.h"
		e->path = xstrdup(path);
		fprintf(stderr, _("No exact match on refs or tags, searching to describe\n"));

		{OPTION_STRING, 0, "dirty",  &dirty, N_("mark"),
		}
						oid_to_hex(&c->object.oid));
	unsigned int match_cnt = 0, annotated_cnt = 0, cur_match;
	struct object_id peeled;
		struct commit *c;
};
}
			parents = parents->next;

	append_name(all_matches[0].name, dst);

	else if (oid_object_info(the_repository, &oid, NULL) == OBJ_BLOB)
			p->object.flags |= c->object.flags;


			fd = hold_locked_index(&index_lock, 0);
						struct commit_name, entry);
		for (cur_match = 0; cur_match < match_cnt; cur_match++) {
		e->name_checked = 0;
				break;
	pcd->current_commit = commit->object.oid;
		static int label_width = -1;
		if (e->tag->date < t->date)
				commit_list_insert_by_date(p, list);
#include "commit.h"
struct possible_tag {
#include "builtin.h"
	struct strbuf sb = STRBUF_INIT;
	int contains = 0;
			if (suffix)
			struct commit *p = parents->item;
			if (!(p->object.flags & SEEN))
		for_each_string_list_item(item, &exclude_patterns) {
		append_suffix(all_matches[0].depth, &cmit->object.oid, dst);
#include "cache.h"


		}


	int found_order;
	}
			if (!wildmatch(item->string, path_to_match, 0))

				suffix = NULL;
	}
		prio = 0;
		abbrev = DEFAULT_ABBREV;
				suffix = NULL;
				oid_to_hex(&gave_up_on->object.oid));
			}
			return 0;
				      NULL, NULL, NULL);
	}

		while (parents) {
#define USE_THE_INDEX_COMPATIBILITY_MACROS
			    oid_to_hex(cmit_oid));

	if (exclude_patterns.nr) {

	struct process_commit_data *pcd = data;
			struct rev_info revs;
		n->name_checked = 1;
			}

		OPT_STRING_LIST(0, "match", &patterns, N_("pattern"),
		OPT_BOOL(0, "contains",   &contains, N_("find the tag that comes after the commit")),
}
			/* Only accept reference of known type if there are match/exclude patterns */
	/*
					entry /* member name */) {

				a = a->next;
int cmd_describe(int argc, const char **argv, const char *prefix)
	unsigned prio:2; /* annotated tag = 2, tag = 1, head = 0 */
			   const void *peeled)
			default:
				argv_array_pushf(&args, "--refs=refs/tags/%s", item->string);
		else
static void describe_blob(struct object_id oid, struct strbuf *dst)
				suffix = dirty;
		oidcpy(&e->oid, oid);
			for_each_string_list_item(item, &exclude_patterns)
	struct strbuf *dst;

		oidcpy(&peeled, oid);
	} else if (all) {

		return 1;
		die(_("--dirty is incompatible with commit-ishes"));
	else
static const char *prio_names[] = {
		seen_commits--;
static int longformat;
			hashmap_entry_init(&e->entry, oidhash(peeled));
		}

		for (cur_match = 0; cur_match < match_cnt; cur_match++) {
		max_candidates = MAX_TAGS;
	int depth;
			parse_commit(p);
	return 0;
		append_name(n, dst);
		argv_array_pushl(&args, "name-rev",

			PARSE_OPT_OPTARG, NULL, (intptr_t) "-broken"},
	NULL
		hashmap_for_each_entry(&names, &iter, n,
	struct object_id peeled;
static int all;	/* Any valid ref can be used */
#include "diff.h"
		init_commit_names(&commit_names);
		struct tag *t;
static struct string_list patterns = STRING_LIST_INIT_NODUP;
			cp.no_stdout = 1;
		commit_list_insert_by_date(gave_up_on, &list);
static void describe_commit(struct object_id *oid, struct strbuf *dst)
	struct object_id oid;
static int compare_pt(const void *a_, const void *b_)
static struct hashmap names;
	}
			for_each_string_list_item(item, &patterns)
		struct commit_list *parents = c->parents;
	cmit->object.flags = SEEN;
				dirty = "-dirty";
		}

			e = xmalloc(sizeof(struct commit_name));
				struct commit *i = a->item;
	if (e->prio == 2 && prio == 2) {

			}
		}
		for_each_string_list_item(item, &patterns) {
		 */
	struct rev_info *revs;

static void process_object(struct object *obj, const char *path, void *data)
	}
	else if (max_candidates > MAX_TAGS)

		if (n) {
				break;
		struct string_list_item *item;
				} else if (t->depth == best_depth) {
		}
		return a->found_order - b->found_order;
static void process_commit(struct commit *commit, void *data)
static void describe(const char *arg, int last_one)
	struct commit *cmit, *gave_up_on = NULL;
#include "revision.h"
	argc = parse_options(argc, argv, prefix, options, describe_usage, 0);
static struct commit_names commit_names;
	}

				break;
	}
		    !skip_prefix(path, "refs/heads/", &path_to_match) &&
	seen_commits += finish_depth_computation(&list, &all_matches[0]);
			N_("append <mark> on broken working tree (default: \"-broken\")"),
			N_("append <mark> on dirty working tree (default: \"-dirty\")"),
	add_to_known_names(all ? path + 5 : path + 10, &peeled, prio, oid);
	struct object_id oid;
				found = 1;

		/* Stop if last remaining path already covered by best candidate(s) */
			    "Try --always, or create some tags."),
		 */
				label_width, _(prio_names[t->name->prio]),
			return;

		struct commit *c = pop_commit(&list);
			else {
			repo_init_revisions(the_repository, &revs, prefix);
					best_within |= t->flag_within;
				t->depth, t->name->path);
				commit_list_insert_by_date(p, &list);
			struct possible_tag *t = &all_matches[cur_match];
				suffix = broken;
	/*
			return 0;
			} else if (match_cnt < max_candidates) {
	list = NULL;
	if (!last_one)
{

	struct possible_tag *a = (struct possible_tag *)a_;
			if (setup_revisions(args.argc, args.argv, &revs, NULL) != 1)
				_("more than %i tags found; listed %i most recent\n"
			struct lock_file index_lock = LOCK_INIT;
					break;
#include "tag.h"
				t->found_order = match_cnt;
		if (suffix)
		e->tag = tag;
				unannotated_cnt++;
	struct possible_tag *best)
				*commit_names_at(&commit_names, c) = n;
	}
#define MAX_TAGS	(FLAG_BITS - 1)

	/* Is it annotated? */
	if (!hashmap_get_size(&names) && !always)
	struct possible_tag *b = (struct possible_tag *)b_;
			if (!(p->object.flags & SEEN))
		if ((exclude_patterns.nr || patterns.nr) &&
		}
			strbuf_addstr(dst, "tags/");


		struct commit *c = pop_commit(list);
			die(_("annotated tag %s not available"), n->path);
	}

		/*
	struct commit_name *e = find_commit_name(peeled);
			describe(*argv++, argc == 0);
			}

		free_commit_list(pcd->revs->commits);
			    "However, there were unannotated tags: try --tags."),
			int best_depth = INT_MAX;
		OPT_SET_INT(0, "exact-match", &max_candidates,
		n = slot ? *slot : NULL;
	struct object_id current_commit;
			argv_array_pushv(&args, diff_index_args);
			if (!a)
#include "refs.h"
	struct argv_array args = ARGV_ARRAY_INIT;
			cp.git_cmd = 1;
			}
	if (n->tag && !n->name_checked) {
			die(_("No annotated tags can describe '%s'.\n"
	} else if (broken) {
		BUG("setup_revisions could not handle all args?");
	}
		else
}
			   N_("only consider tags matching <pattern>")),
			parse_commit(p);
static int debug;	/* Display lots of verbose info */
	if (!match_cnt) {
	if (patterns.nr) {
		describe_commit(&pcd->current_commit, pcd->dst);
		 * Exact match to an existing ref.
		die(_("--broken is incompatible with commit-ishes"));
					fprintf(stderr, _("finished search at %s\n"),
			hashmap_add(&names, &e->entry);

		while (argc-- > 0)
{
		}

				repo_update_index_if_able(the_repository, &index_lock);
		pcd->revs->commits = NULL;
static int first_parent;

			int i, w;
		is_tag = 1;
		if (argc)
	 * If we're given patterns, accept only tags which match at least one
							   &n->peeled, 1);
			struct argv_array args = ARGV_ARRAY_INIT;
			if ((c->object.flags & best_within) == best_within) {
			argv_array_push(&args, "--tags");
#include "run-command.h"
			else
	/*
			fprintf(stderr, " %-*s %8d %s\n",
	if (!have_util) {
static int have_util;
				gave_up_on = c;
	if (is_annotated)
