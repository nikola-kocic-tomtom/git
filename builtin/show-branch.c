		return error("unrecognized reflog param '%s'", arg);
	}
			free(logmsg);
		if (commit_to_name(c))
		struct commit *commit = list->item;

		exit(0);
					printf("~%d", name->generation);
				continue;
		if (1 < num_rev) {
			 char **ref_name,
			parse_commit(p);
		fprintf(stderr, "No revs to be shown.\n");
	enum rev_sort_order sort_order = REV_SORT_IN_GRAPH_ORDER;
		/* glob style match */
static int name_first_parent_chain(struct commit *c)
				struct commit *p = parents->item;
		/* Has the base been specified? */
			 * HEAD points at.
	git_config(git_show_branch_config, NULL);
}
	sort_in_topological_order(&seen, sort_order);
			  int flag, void *cb_data)


				printf("%s%c%s [%s] ",
	unsigned int rev_mask[MAX_REVS];
		if ((flags & all_revs) == all_revs)
		if (name && name->head_name) {
	if (!name) {
		int va, vb;
	if (!parent_name ||
			int ca = *a;
		if (!dwim_ref(*av, strlen(*av), &oid, &ref))
		       unsigned char *head_sha1, unsigned char *sha1)
			if (*ep) {
				name_first_parent_chain(p);
		list = list->next;
	skip_prefix(pretty_str, "[PATCH] ", &pretty_str);
	return append_ref(refname + ofs, oid, 0);

		exit(0);
			 struct commit **rev,
			 * Also --all and --remotes do not make sense either.
			parents = c->parents;
	struct strbuf pretty = STRBUF_INIT;
		if (independent || merge_base)
			/* We are only interested in adding the branch
		int has_head = 0;

			printf("[%s", name->head_name);
		if (flag & (1u << (i + REV_SHIFT)))
			 N_("show possible merge bases")),
			 */
			if (!msg)
				timestamp_t at;
			int tz;
			ac = 1;
		}
	if (!strcmp(var, "showbranch.default")) {
			error(_("no matching refs with %s"), av);
			argv_array_push(&default_args, "show-branch");
	}
		OPT_BOOL(0, "independent", &independent,
	}
			   int flag, void *cb_data)
		if (commit->object.flags == flag)

		OPT_SET_INT(0, "topo-order", &sort_order,
		 */
	}
{
		*commit_name_slab_at(&name_slab, commit) = name;
		}
			       MAX_REVS), MAX_REVS);
		if (commit->object.flags & UNINTERESTING)

		while (0 < ac) {
				else if (i == head_at)
	const char *pretty_str = "(unavailable)";
		return 0;

		if (commit->object.flags == flag)
				       mark, get_color_reset_code());
		struct commit *commit = pop_commit(&seen);
		for (i = 0; i < num_rev; i++) {
	for (i = 0; i < num_rev; i++) {


{
	 * uninteresting commits not interesting.
{
				else
		char *ref;
			putchar('\n');
{
	for (num_rev = 0; ref_name[num_rev]; num_rev++) {
		if (rev[i] == commit)
		int base = 0;
}
{
		      int num_rev, int extra)
			    REV_SORT_IN_GRAPH_ORDER),

}
	/* If both heads/foo and tags/foo exists, get_sha1 would
		struct commit *commit = rev[i];
			if (rev[i] == c) {
		skip_prefix(name, "heads/", &name);

					strbuf_addf(&newname, "^%d", nth);
					&timestamp, &tz, NULL)) {
					strbuf_addf(&newname, "%s~%d",
	return 0;
		}
{
			return va - vb;
	     p++)
				/* header lines never need name */
					head_oid.hash, NULL))
	for (i = 0; i < num_rev; i++)
			 */
	 * branches under refs/heads/hold/, and v0.99.9? to show
static void name_commits(struct commit_list *list,
	return append_ref(refname, oid, 0);
		}
					    ref, flags, at, -1, &oid, NULL,


	}

			const char *name = head;

	/* Give names to commits */
}
		arg = "";
			if (!ca)
				else
{
			    N_("show <n> more commits after the common ancestor"),
			       find_unique_abbrev(&commit->object.oid,
#include "config.h"
		int flags = commit->object.flags & all_mask;
		pp_commit_easy(CMIT_FMT_ONELINE, commit, &pretty);
					   builtin_show_branch_options);
{
			n = commit_to_name(c);
			die(Q_("only %d entry can be shown at one time.",
				head_at = i;
	struct commit *rev[MAX_REVS], *commit;
		while (1) {
#define REV_SHIFT	 2
			 * already uninteresting one.  Mark its parents
				name_commit(c, ref_name[i], 0);
static struct commit *interesting(struct commit_list *list)
		return show_independent(rev, num_rev, rev_mask);
		/*
}
	}
					strbuf_addstr(&newname, n->head_name);
	if (!*tail)
		if (reflog_base) {

{
	 * Postprocess to complete well-poisoning.
					    NULL, NULL, &base);
			free(nth_desc);
	return 0;
				printf("%c [%s] ",
static int match_ref_slash = 0;
	for (;;) {
		commit = lookup_commit_reference(the_repository, &revkey);
static void join_revs(struct commit_list **list_p,
		for (i = 0; i < ref_name_cnt; i++)
	if (!commit_name)
	 * omit it.
				parents = parents->next;

	const char *tail;
static const char *find_digit_prefix(const char *s, int *v)
	int shown_merge_point = 0;
	if (!head || (head_sha1 && sha1 && !hasheq(head_sha1, sha1)))
			 N_("show only commits not on the first branch")),
	char *ep;
 * we count only the first-parent relationship for naming purposes.
			commit_list_insert_by_date(commit, &list);
	struct commit *commit = lookup_commit_reference_gently(the_repository,
			fake_av[1] = NULL;
#define DEFAULT_REFLOG	4
			append_ref(nth_desc, &oid, 1);


		for_each_ref(append_head_ref, NULL);
		int orig_cnt = ref_name_cnt;


	if (extra < 0)



	if (want_color(showbranch_use_color))
	if (starts_with(refname, "refs/heads/"))
			    PARSE_OPT_OPTARG | PARSE_OPT_NONEG,
	int all_revs = all_mask & ~((1u << REV_SHIFT) - 1);
}
		/* Avoid adding the same thing twice */
		}
			if (!*av)
	 * refs/tags/v0.99.9a and friends.
	return 0;
	if (commit->object.parsed) {
	}
	}
		 * default_arg is now passed to parse_options(), so we need to
	int with_current_branch = 0;
			int is_merge = !!(commit->parents &&
}
	 * Otherwise, if it is a merge that is reachable from only one
	if (1 < num_rev || extra < 0) {
		else
	reflog = strtoul(arg, &ep, 10);

static int mark_seen(struct commit *commit, struct commit_list **seen_p)
		sort_ref_range(orig_cnt, ref_name_cnt);
		p = c->parents->item;
	int slash = count_slashes(refname);
 */
				reflog = i;
	}
		return 1;
		parse_commit(commit);
		if (get_oid(ref_name[num_rev], &revkey))
			puts(oid_to_hex(&commit->object.oid));
			for (i = 0; i < num_rev; i++)
			 int num_rev)
static int ref_name_cnt;
#include "pretty.h"
	if (extra || reflog) {

{
			 * already parsed.  No reason to find new ones
		OPT_END()
		if (!c->parents)
/* Parent is the first parent of the commit.  We may name it
		showbranch_use_color = git_config_colorbool(var, value);
			     int flag, void *cb_data)
		free(ref);
			if (!strcmp(refname, ref_name[i]))
			    int num_rev,
	if (!starts_with(refname, "refs/heads/"))

			}
	commit_list_sort_by_date(&seen);
			i += name_first_parent_chain(cl->item);
{
		OPT_BOOL(0, "current", &with_current_branch,
static void append_one_rev(const char *av)


			    N_("show commits in topological order"),

	if (starts_with(refname, "refs/tags/"))

	if (ac <= topics && all_heads + all_remotes == 0)
		int changed = 0;
		mark_seen(commit, &seen);
		for (cl = list; cl; cl = cl->next) {
		for (i = 0; !has_head && i < ref_name_cnt; i++) {

				at = approxidate(reflog_base);
	return 0;
			struct commit_list *parents;
			}
				has_head++;
/*
	 */

}
}
	}
struct commit_name {
			}
			 N_("name commits with their object names")),
		{ OPTION_INTEGER, 0, "more", &extra, N_("n"),
		 * internal bookkeeping.
			       int flag, void *cb_data)
{
			}
				puts(reflog_msg[i]);
	if (head) {
	ac = parse_options(ac, av, prefix, builtin_show_branch_options,
		}
		OPT_BOOL('r', "remotes", &all_remotes,
			}
		struct commit_list *s;
	int all_mask = ((1u << (REV_SHIFT + num_rev)) - 1);
				extra--;
	struct commit_list *list = NULL, *seen = NULL;
			return config_error_nonbool(var);
			else {
static void snarf_refs(int head, int remotes)
		i = 0;
	while (1) {
	const char *head_name; /* which head's ancestor? */


 * UNINTERESTING definition from revision.h here.
	all_mask = ((1u << (REV_SHIFT + num_rev)) - 1);
				break;
		 * and so on.  REV_SHIFT bits from bit 0 are used for
	struct object_id head_oid;
		name_commit(parent, commit_name->head_name,
	int independent = 0;
		if (MAX_REVS <= num_rev)
		OPT_BOOL('a', "all", &all_heads,
}
	int all_mask, all_revs;

					mark = '+';
	struct commit_name *name = commit_to_name(commit);
	if (!starts_with(refname, "refs/tags/"))
	/*
				for (j = 0; j < i; j++)
					  commit->parents->next);
#include "refs.h"
		name = xmalloc(sizeof(*name));
	int num_rev, i, extra = 0;
			while (parents) {
			slash--;
			commit->object.flags |= UNINTERESTING;
	 * get confused.
		return 0;
	int all_heads = 0, all_remotes = 0;
		/* rev#0 uses bit REV_SHIFT, rev#1 uses bit REV_SHIFT+1,
		if (shown_merge_point && --extra < 0)
		    ref_name_cnt < MAX_REVS)
	flag = commit->object.flags;
			if (dense && is_merge &&
			if (mark_seen(p, seen_p) && !still_interesting)
		int still_interesting = !!interesting(*list_p);

	int i = 0;
		return commit;
			 N_("show remote-tracking branches")),
			    !is_merge_point &&
       "		[--no-name | --sha1-name] [--topics] [(<rev> | <glob>)...]"),

			 * as uninteresting commits _only_ if they are

	for (tail = refname; *tail && match_ref_slash < slash; )
			if (!commit_to_name(c))
		shown_merge_point |= is_merge_point;
			    commit_name->generation + 1);
			die(_("'%s' is not a valid ref."), ref_name[num_rev]);
	struct commit_name *name;
	 * seen_p list.  Mark anything that can be reached from
};
			exit_status = 0;
	do {
		return append_head_ref(refname, oid, flag, cb_data);
}
	} while (i);

		if (!commit)
				else
		return 1;
		int this_flag = commit->object.flags;

		for (i = 0; i < reflog; i++) {
			c = cl->item;
	int no_name = 0;

		for_each_ref(append_remote_ref, NULL);
			      &head_oid, NULL);
	return version_cmp(*a, *b);
	} while (i);

				else if (is_merge)
	init_commit_name_slab(&name_slab);
			if (!reflog) {
			       "only %d entries can be shown at one time.",
		all_remotes = 1;

		c = cl->item;
		OPT_BOOL(0, "topics", &topics,

		if (!commit_to_name(c))
			const char *msg;
	else if (*ep)
		for_each_ref(append_matching_ref, NULL);
		OPT__COLOR(&showbranch_use_color,
						  rev[i]->object.oid.hash);

	if (wildmatch(match_ref_pattern, tail, 0))
			 N_("show remote-tracking and local branches")),
			a++;
		unsigned int flag = 1u << (num_rev + REV_SHIFT);
						  DEFAULT_ABBREV));
			commit_list_insert_by_date(p, list_p);
		if (!commit_to_name(p)) {

		b = find_digit_prefix(b, &vb);
	}
	while (list) {
	/* Then commits on the first parent ancestry chain */
	else
	if (merge_base)
	    commit_name->generation + 1 < parent_name->generation)
	int i, flag, count;
 * TODO: convert this use of commit->object.flags to commit-slab
		all_heads = 1;
}
			 *
			if (name->generation) {
	const char **base = (const char **)opt->value;


static int git_show_branch_config(const char *var, const char *value, void *cb)
static int compare_ref_name(const void *a_, const void *b_)

}
	while (*list_p) {
				ca = 0;
				switch (n->generation) {
    N_("git show-branch [-a | --all] [-r | --remotes] [--topo-order | --date-order]\n"
				if (!(p->object.flags & UNINTERESTING)) {
		 * mimic the real argv a bit better.
			for (i = 0; i < num_rev; i++) {
			if ('0' <= cb && cb <= '9')
	name->head_name = head_name;
	if (!strcmp(var, "color.showbranch")) {
		for (i = 0; i < num_rev; i++) {
static void name_parent(struct commit *commit, struct commit *parent)
		rev[num_rev] = commit;
				die(_("no branches given, and HEAD is not valid"));
 * number is better than the name it already has.
		return show_merge_base(seen, num_rev);
		struct object_id revkey;
	puts(pretty_str);
	skip_prefix(head, "refs/heads/", &head);
static struct commit_name *commit_to_name(struct commit *commit)
	return 0;
				struct strbuf newname = STRBUF_INIT;
			if (((c->object.flags & all_revs) != all_revs) &&
	}
			/* The current commit is either a merge base or
				continue;
	if (count == 1)
			    unsigned int *rev_mask)

	int ver;

static char *ref_name[MAX_REVS + 1];
						    n->head_name, n->generation);
		 */

}
static int append_tag_ref(const char *refname, const struct object_id *oid,
       "		[--more=<n> | --list | --independent | --merge-base]\n"
	}
	};
	if (!commit->object.flags) {
	if (!get_oid(av, &revkey)) {
static int append_ref(const char *refname, const struct object_id *oid,
			if ('0' <= ca && ca <= '9')

							       oid, 1);
				break;
static const char *match_ref_pattern = NULL;

	/* If the commit is tip of the named branches, do not
		return column_colors_ansi[idx % column_colors_ansi_max];
		for (cl = list; cl; cl = cl->next) {
	if (!no_name) {
	if (!allow_dups) {
			if (topics &&
	if (strpbrk(av, "*?[")) {
	}
static int append_matching_ref(const char *refname, const struct object_id *oid,
			if (extra < 0)
			puts(oid_to_hex(&commit->object.oid));
			char *nth_desc;
		match_ref_slash = count_slashes(av);
	if (!sha1_name && !no_name)
	int dense = 1;
	int i;
}
	const char *p;
	return *commit_name_slab_at(&name_slab, commit);
			break;
	if (*ep == ',')
/* Name the commit as nth generation ancestor of head_name;

		commit->object.flags |= UNINTERESTING;
	for (i = count = 0; i < n; i++) {
 */
		if (*tail++ == '/')
define_commit_slab(commit_name_slab, struct commit_name *);

	return append_ref(refname + ofs, oid, 0);
	/* Sort topologically */
    N_("git show-branch (-g | --reflog)[=<n>[,<base>]] [--list] [<ref>]"),
			struct commit *c = s->item;
		struct commit *commit = pop_commit(list_p);
			    ref_name[num_rev], oid_to_hex(&revkey));
	if (reflog) {
		name_commits(seen, rev, ref_name, num_rev);
		}
		reflog = DEFAULT_REFLOG;
			name_parent(c, p);
			      int unset)
		c = p;
		rev_mask[i] = rev[i]->object.flags;
				struct commit *p = parents->item;
	ref_name[ref_name_cnt] = NULL;
			nth = 0;
	int ofs = 13;
	}
			skip_prefix(name, "refs/heads/", &name);
			if (ca != cb)
			if (read_ref_at(get_main_ref_store(the_repository),
				msg = "(none)";
			   show_branch_usage, PARSE_OPT_STOP_AT_NON_OPTION);
		ver = ver * 10 + ch - '0';
	/* If nothing is specified, show all branches by default */
	}
	char ch;

					ref, flags, 0, base + i, &oid, &logmsg,
		}
					changed = 1;
		if (!(flags & UNINTERESTING) &&
			putchar(' ');
}
	int generation; /* how many parents away from head_name */
	name->generation = nth;
	}
		return 0;
			struct commit_list *parents;
}
		return 0;
			   MAX_REVS), refname, MAX_REVS);
			die(_("cannot find commit %s (%s)"),
	struct commit_name *parent_name = commit_to_name(parent);
	else {

		*base = NULL;
					ref_name[i],
	}
						    RESOLVE_REF_READING, &oid,
		int flags = commit->object.flags & all_mask;
	/* If both heads/foo and tags/foo exists, get_sha1 would
	int i;
#include "color.h"
		ofs = 5;
}
			}
	 */
		sort_ref_range(orig_cnt, ref_name_cnt);
		struct commit *commit = pop_commit(&seen);
static struct argv_array default_args = ARGV_ARRAY_INIT;

			 * Asking for --more in reflog mode does not
{
			flags |= UNINTERESTING;
	while (c) {

 * commit is nth generation ancestor of, if that generation
		return;
			}
{
#include "commit-slab.h"
 * as (n+1)th generation ancestor of the same head_name as

					break;
{
static int show_merge_base(struct commit_list *seen, int num_rev)

			printf("] ");

	/* If nothing is specified, try the default first */
	if (!ref_name_cnt) {
		unsigned int flags = 0;
	 *
	const char *reflog_base = NULL;
		else
	struct object_id revkey;
			    REV_SORT_BY_COMMIT_DATE),
	head = resolve_refdup("HEAD", RESOLVE_REF_READING,
			    N_("topologically sort, maintaining date order "
					mark = '*';
}
		while (parents) {
		warning(Q_("ignoring %s; cannot handle more than %d ref",
	if (get_oid(refname + ofs, &tmp) || !oideq(&tmp, oid))
static void show_one_commit(struct commit *commit, int no_name)
					mark = ' ';
				read_ref_at(get_main_ref_store(the_repository),
	return !strcmp(head, name);
	 * get confused.
			break;
		return GIT_COLOR_RESET;
		struct object_id oid;
				       get_color_code(i),

	for (cl = list; cl; cl = cl->next) {
					p->object.flags |= UNINTERESTING;
			}
				cb = 0;
		return 0;
#include "builtin.h"
			static const char *fake_av[2];
	return "";
				show_one_commit(rev[i], 1);
	}
	if (0 <= extra)
		return;
	int all_revs = all_mask & ~((1u << REV_SHIFT) - 1);
			msg = strchr(logmsg, '\t');
				case 1:
			i++;
	const char * const*a = a_, * const*b = b_;
static int version_cmp(const char *a, const char *b)
				continue;

	char *head;
		if (0 <= extra) {
}
{
	}

			    (this_flag & (1u << REV_SHIFT)))

		if (reflog && ((0 < extra) || all_heads || all_remotes))
static const char *get_color_code(int idx)
						show_date(timestamp, tz,
					break;
			   "ignoring %s; cannot handle more than %d refs",
			return 0;
	}
{
			struct commit *p = parents->item;
				}
		argv_array_push(&default_args, value);
	}
	int head_at = -1;
		}
}

{
			printf("[%s] ",

	if (want_color(showbranch_use_color))
static int append_remote_ref(const char *refname, const struct object_id *oid,
				break;
static const char* show_branch_usage[] = {

			    N_("show <n> most recent ref-log entries starting at "
	/* Finally, any unnamed commits */
	 */

	struct commit *c;
	}
		}
		return 0;
		if (all_heads + all_remotes)
		ac = default_args.argc;

			else
				return ca - cb;
	name = *commit_name_slab_at(&name_slab, commit);
#include "argv-array.h"
		return;
		}
				default:
}
		      int allow_dups)

			 * make sense.  --list is Ok.
}
			die(_("--reflog is incompatible with --all, --remotes, "
				parents = parents->next;
			    N_("show refs unreachable from any other ref")),
		OPT_BOOL(0, "merge-base", &merge_base,
			if ((this_flag & flags) == flags)
			    parse_reflog_param },

	return "";
			       "cannot handle more than %d revs.",
							  DATE_MODE(RELATIVE)),
				if (name->generation == 1)
	char *reflog_msg[MAX_REVS];
		}
	int sha1_name = 0;
{
	return i;
		/* "listing" mode is incompatible with
	/* First give names to the given heads */
{
					continue;
			 * here.
						  head_oid.hash,
	int topics = 0;

	struct object_id tmp;
			count++;
static struct commit_name_slab name_slab;
		if (ac != 1)
			    N_("color '*!+-' corresponding to the branch")),
					strbuf_addch(&newname, '^');
	     '0' <= (ch = *p) && ch <= '9';

			 */
		return 0;

		if (!has_head) {
}
		if (!value)
			while (parents) {
				continue;
			snarf_refs(all_heads, all_remotes);
{
	while (seen) {
			timestamp_t timestamp;
		if (ac == 0) {
			usage_with_options(show_branch_usage,
		join_revs(&list, &seen, num_rev, extra);
	}
				name_commit(p, strbuf_detach(&newname, NULL), 0);
					putchar(' ');
		return 0;
	return p;
						    NULL);

				nth++;
		}
		for (s = *seen_p; s; s = s->next) {
			 N_("include the current branch")),

}
		if (!default_args.argc)
		}
	if (!arg)
		int saved_matches = ref_name_cnt;
static int show_independent(struct commit **rev,

	int all_mask = ((1u << (REV_SHIFT + num_rev)) - 1);
		OPT_SET_INT(0, "sparse", &dense,
		      struct commit_list **seen_p,
	struct object_id tmp;
	struct commit_name *commit_name = commit_to_name(commit);
		return append_tag_ref(refname, oid, flag, cb_data);
			break;

		pretty_str = pretty.buf;
					break;
#include "parse-options.h"
			if (rev_is_head(head,
    NULL
	int exit_status = 1;
	if (with_current_branch && head) {

		int orig_cnt = ref_name_cnt;
						msg);
		if (MAX_REVS < reflog)
			       "where possible"),
		*base = ep + 1;
	return append_ref(refname + 5, oid, 0);
static int showbranch_use_color = -1;
				if (nth == 1)
				if (commit_to_name(p))
	if (reflog <= 0)
			ac--; av++;
	 */
		append_ref(av, &revkey, 0);

{
{
	if (remotes) {
	return git_color_default_config(var, value, cb);
	if (MAX_REVS <= ref_name_cnt) {
		commit_list_insert(commit, seen_p);
			char *logmsg;
}

		a = find_digit_prefix(a, &va);
static void sort_ref_range(int bottom, int top)
				putchar('-');
{
		unsigned int flag = rev_mask[i];
#define UNINTERESTING	01
			struct commit_name *n;
		sort_ref_range(saved_matches, ref_name_cnt);
				printf("%s%c%s",
	strbuf_release(&pretty);
	 * At this point we have all the commits we have seen in
				continue;
		if (!changed)
	int merge_base = 0;
	struct commit_list *cl;
{
	}
static int omit_in_dense(struct commit *commit, struct commit **rev, int n)
					strbuf_addf(&newname, "%s^", n->head_name);
	die("bad sha1 reference %s", av);
static int reflog = 0;
			if (is_head)
	int i;
				case 0:
			b++;
{
		OPT_BOOL(0, "no-name", &no_name, N_("suppress naming strings")),
				/* Ah, that is a date spec... */
}
			int j;
		i = 0;
	}
	if (ac == 1 && default_args.argc) {
		mark_seen(commit, seen_p);
	struct option builtin_show_branch_options[] = {
		commit->object.flags |= flag;
		}
		}
			break;
	if (!commit)

			int is_head = rev_is_head(head,
	BUG_ON_OPT_NEG(unset);
			nth_desc = xstrfmt("%s@{%d}", *av, base+i);
				return 0;
#include "cache.h"

#define MAX_REVS	(FLAG_BITS - REV_SHIFT) /* should not exceed bits_per_int - REV_SHIFT */



{

		av = default_args.argv;
		if (!*a && !*b)
	return exit_status;
	if (independent)
			reflog_msg[i] = xstrfmt("(%s) %s",
			}

					printf("^");
				       is_head ? '*' : '!',
			av = fake_av;
	for (p = s, ver = 0;
				       is_head ? '*' : ' ', ref_name[i]);
				       get_color_code(i),
		OPT_SET_INT(0, "date-order", &sort_order,
			append_one_rev(*av);
		return 0;

	while (seen) {
			continue;
			p->object.flags |= flags;
				       get_color_reset_code(), ref_name[i]);
	if (get_oid(refname + ofs, &tmp) || !oideq(&tmp, oid))
	}
}
		match_ref_pattern = av;
			fake_av[0] = resolve_refdup("HEAD",
		show_one_commit(commit, no_name);
		 * independent nor merge-base modes.
#include "dir.h"

	int ofs = 11;
}
		ofs = 5;
{
			die(_("--reflog option needs one branch name"));
	if (all_heads)
			return 0;
	 */
			else
		}
	all_revs = all_mask & ~((1u << REV_SHIFT) - 1);
			die(Q_("cannot handle more than %d rev.",

	/* we want to allow pattern hold/<asterisk> to show all
			       MAX_REVS), MAX_REVS);
		if (va != vb)
						  ref_name[i],
 * instead to store a pointer to ref name directly. Then use the same
	return NULL;
{



			    omit_in_dense(commit, rev, num_rev))
			int nth;
static const char *get_color_reset_code(void)
			/*
static void name_commit(struct commit *commit, const char *head_name, int nth)
	do {
};

	}
			parents = c->parents;
			char *ep;
	return 0;
	/* Show list; --more=-1 means list-only */
		    ((flags & all_revs) == all_revs)) {

		{ OPTION_CALLBACK, 'g', "reflog", &reflog_base, N_("<n>[,<base>]"),
		struct commit_list *parents;
	}
			       "base"),
static int append_head_ref(const char *refname, const struct object_id *oid,
					mark = '-';
			base = strtoul(reflog_base, &ep, 10);
	 * tip, it is not that interesting.
		int is_merge_point = ((this_flag & all_revs) == all_revs);
		if (saved_matches == ref_name_cnt &&
			int cb = *b;
			append_one_rev(name);
				msg++;
			parents = parents->next;
			    N_("show merges reachable from only one tip"), 0),
		OPT_BOOL(0, "sha1-name", &sha1_name,
				i++;
       "		[--current] [--color[=<when>] | --no-color] [--sparse]\n"
		OPT_SET_INT(0, "list", &extra, N_("synonym to more=-1"), -1),
	}
			int this_flag = p->object.flags;
		struct commit *p;
		return 0;
		parents = commit->parents;
int cmd_show_branch(int ac, const char **av, const char *prefix)
			continue;
	ref_name[ref_name_cnt++] = xstrdup(refname);
				int mark;
		 */
	if (!skip_prefix(name, "refs/heads/", &name))
		if (!still_interesting && extra <= 0)
			    PARSE_OPT_OPTARG, NULL, (intptr_t)1 },
				}
			    !(c->object.flags & UNINTERESTING))
 */
			break;
		}
				if (!(this_flag & (1u << (i + REV_SHIFT))))

			break;
			      "--independent or --merge-base"));
static int rev_is_head(const char *head, const char *name,
	*v = ver;
	if (!starts_with(refname, "refs/remotes/"))
	QSORT(ref_name + bottom, top - bottom, compare_ref_name);
static int parse_reflog_param(const struct option *opt, const char *arg,
			die(_("no such ref %s"), *av);
	for (i = 0; i < n; i++)
