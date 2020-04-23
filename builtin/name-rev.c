		 * stale pointers when it processes the parents.
}


	/*
	NULL
					   parents_to_queue_alloc);
			cutoff = cutoff - CUTOFF_DATE_SLOP;
	start_name = create_or_update_name(start_commit, taggerdate, 0, 0,
			parent_name = create_or_update_name(parent, taggerdate,
				break;

	if (cmp)
}
static const char *name_ref_abbrev(const char *refname, int shorten_unambiguous)
	for_each_ref(name_ref, &data);
}
		o = parse_object(the_repository, &t->tagged->oid);
		char buffer[2048];
	int alloc;
			if (!name)
			else
				break;
				continue;

	return name;
		return cmp;

static struct rev_name *create_or_update_name(struct commit *commit,
				cutoff = commit->date;
		printf("%s ", caller_name ? caller_name : oid_to_hex(oid));
		 * This string might still be shared with ancestors
		from_tag = starts_with(path, "refs/tags/");
			OPTION_SET_INT, 0, "peel-tag", &peel_tag, NULL,
			(name->taggerdate == taggerdate &&
			}
			 from_tag, deref);
			 * the 'v1.*' in the acceptable refnames, so we
					parent_name->tip_name = name->tip_name;
	tip_table.table[tip_table.nr].deref = deref;
		int matched = 0;
	free(parents_to_queue);
		printf("undefined\n");
	return -1;
		 * for them as well, so name_rev() will replace these
	if (is_valid_rev_name(name)) {
		}
				continue;
		struct object *object;
{

static char const * const name_rev_usage[] = {
#include "tag.h"
	struct name_ref_data data = { 0, 0, STRING_LIST_INIT_NODUP, STRING_LIST_INIT_NODUP };
	const char *name;
	name->generation = generation;
#include "builtin.h"
	const char *subpath = path;
	} else {
}
	strip_suffix(name->tip_name, "^0", &len);
	N_("git name-rev [<options>] --all"),
		if (e->commit) {
	if (o && o->type == OBJ_COMMIT) {
	tip_table.sorted = 0;
{
		strbuf_grow(&sb, len +
	if (!tip_table.table || !tip_table.nr)
		OPT_GROUP(""),
	return table[ix].oid.hash;
	 * favor a tag over a non-tag.
	struct tip_table_entry *table = table_;
	int sorted;
		strbuf_addf(buf, "~%d", n->generation);
	UNLEAK(revs);
			 !ishex(*(p+1))) {
	}
		usage_with_options(name_rev_usage, opts);
				 e->from_tag, e->deref);
		struct tag *t = (struct tag *) o;

					   from_tag);
			} else {
	tip_table.table[tip_table.nr].commit = commit;
					*argv);
	}
				parents = parents->next, parent_number++) {
					*argv);
	int found;
{
static timestamp_t cutoff = TIME_MAX;
		add_object_array(object, *argv, &revs);
static void name_tips(void)
					lookup_object(the_repository, &oid);
		return 0;

			p_start = p + 1;
			parse_commit(parent);
					      int generation, int distance,
define_commit_slab(commit_rev_name, struct rev_name);
			 * Check all patterns even after finding a match, so
}
	while (subpath) {
					      int from_tag)
 * changing this value
		/* The first parent must come out first from the prio_queue */
	add_to_tip_table(oid, path, can_abbreviate_output, commit, taggerdate,
}

#define MERGE_TRAVERSAL_WEIGHT 65535
#include "commit.h"

		int from_tag, int deref)
							    distance, from_tag);

					*argv);
	if (name->taggerdate != taggerdate)
			if (data->name_only)

	} else if (all) {

		}
		cutoff = 0;
			struct rev_name *parent_name;
		return NULL;


{


	if (name)

	while ((commit = prio_queue_get(&queue))) {
			  timestamp_t taggerdate,

#include "commit-slab.h"
	}
struct name_ref_data {
		return get_exact_ref_match(o);

	if (all + transform_stdin + !!argc > 1) {
			}
		strbuf_strip_suffix(buf, "^0");
		return NULL;
			if (cutoff > commit->date)
	while (o && o->type == OBJ_TAG) {
		for (i = 0; i < max; i++) {
	const struct object_id *oid = &obj->oid;

	 * shorter hops.
		strbuf_reset(buf);
	}

	} else {
	char *tip_name;
	int nr;
		printf("%s\n", name);
{
	if (!n->generation)
		int parent_number = 1;
	return refname;
#include "cache.h"
		skip_prefix(refname, "refs/", &refname);
	struct rev_name *start_name;
	if (cutoff) {


				distance = name->distance + MERGE_TRAVERSAL_WEIGHT;
		OPT_BOOL(0, "all", &all, N_("list all commits reachable from all refs")),

	return NULL;

	 * Try to set better names first, so that worse ones spread


	struct object_array revs = OBJECT_ARRAY_INIT;
			/* A Hidden OPT_BOOL */
		OPT_BOOL(0, "stdin", &transform_stdin, N_("read from stdin")),
	};
	const struct tip_table_entry *a = a_, *b = b_;
	tip_table.table[tip_table.nr].from_tag = from_tag;
			 nth_tip_table_ent);
		unsigned int from_tag:1;
	/*

		fwrite(p_start, p - p_start, 1, stdout);
	int counter = 0;
		if (commit) {
		taggerdate = t->date;
	for (i = 0; i < tip_table.nr; i++) {
		start_name->tip_name = xstrdup(tip_name);
static void name_rev(struct commit *start_commit,

	tip_table.nr++;
		return (name->taggerdate > taggerdate ||
		OPT_BOOL(0, "name-only", &data.name_only, N_("print only names (no SHA-1)")),
		strbuf_addf(&sb, "%.*s~%d^%d", (int)len, name->tip_name,
	const struct commit *c;
			  int from_tag)
/* How many generations are maximally preferred over _one_ merge traversal? */
		if (!object) {
	}
	struct object *o = parse_object(the_repository, oid);
		struct rev_name *name = get_commit_rev_name(commit);
		else if (++counter == hexsz &&
				matched = 1;
				printf("%.*s (%s)", p_len, p_start, name);
	if (name->from_tag != from_tag)
		int i;
			struct commit *parent = parents->item;
			if (!obj || obj->type != OBJ_COMMIT)

			default: /* matched subpath */

	int can_abbreviate_output = data->tags_only && data->name_only;

	return 0;
		 * (generation > 0).  We can release it here regardless,

	return name && (name->generation || name->tip_name);
		if (peel_tag) {
		if (taggerdate == TIME_MAX)
	}
				printf("%.*s%s", p_len - hexsz, p_start, name);
} tip_table;
	struct strbuf sb = STRBUF_INIT;
			   N_("show abbreviated commit object as fallback")),
		max = get_max_object_index();
	int from_tag;
		if (!is_better_name(name, taggerdate, distance, from_tag))
#include "refs.h"
			if (!get_oid(p - (hexsz - 1), &oid)) {
		if (!wildmatch(filter, subpath, 0))
	}
		printf("%s\n", find_unique_abbrev(oid, DEFAULT_ABBREV));
		for (parents = commit->parents;
		}
		return name->taggerdate > taggerdate;
		/* If none of the patterns matched, stop now */
	if (data->tags_only && !starts_with(path, "refs/tags/"))
}
static int subpath_matches(const char *path, const char *filter)
#define ishex(x) (isdigit((x)) || ((x) >= 'a' && (x) <= 'f'))
	struct commit **parents_to_queue = NULL;
	if (shorten_unambiguous)
struct rev_name {
	size_t parents_to_queue_nr, parents_to_queue_alloc = 0;

		start_name->tip_name = xstrfmt("%s^0", tip_name);
	/* ... or tiebreak to favor older date */
				generation = name->generation + 1;
#include "sha1-lookup.h"
#define CUTOFF_DATE_SLOP 86400

		OPT_STRING_LIST(0, "exclude", &data.exclude_filters, N_("pattern"),

		if (get_oid(*argv, &oid)) {
	int from_tag = 0;
				if (o)
		/* See if any of the patterns match. */
	if (transform_stdin) {
		}
	if (all || transform_stdin)
		return -1;
			fprintf(stderr, "Could not get sha1 for %s. Skipping.\n",
			if (!commit) {
			}
	else
	int tags_only;
			     timestamp_t taggerdate, int from_tag, int deref)
			    1 + decimal_width(parent_number));


		struct commit_list *parents;
		; /* refname already advanced */
		OPT_END(),
	if (!n)
			struct object *obj = get_indexed_object(i);
				continue;
		commit = NULL;
	struct strbuf buf = STRBUF_INIT;
			continue;
	memset(&queue, 0, sizeof(queue)); /* Use the prio_queue as LIFO */
		}
	/*
static const char *get_exact_ref_match(const struct object *o)


				matched = 1;
	struct tip_table_entry {

	for (p_start = p; *p; p++) {
				parents_to_queue[parents_to_queue_nr] = parent;
		}

		 */

		return buf->buf;
	clear_prio_queue(&queue);
{
			}
{
		return;

		while (!feof(stdin)) {
		OPT_BOOL(0, "always",     &always,
		die("cannot describe '%s'", oid_to_hex(oid));
		if (!t->tagged)
			/*
		return name->distance > distance;
/* may return a constant string or use "buf" as scratch space */
}
	}

	tip_table.table[tip_table.nr].taggerdate = taggerdate;
			  int distance,
			taggerdate = commit->date;
			cutoff = TIME_MIN;
		strbuf_addf(&sb, "%.*s^%d", (int)len, name->tip_name,
	return 0;
	name = get_rev_name(obj, &buf);
		struct string_list_item *item;
	if (deref)
		subpath = strchr(subpath, '/');
	const unsigned hexsz = the_hash_algo->hexsz;

		deref = 1;
	struct rev_name *name = commit_rev_name_peek(&rev_names, commit);
							  object, *argv, 0);
					   parents_to_queue_nr + 1,
};
		return n->tip_name;
	/* Older is better. */

		OPT_BOOL(0, "tags", &data.tags_only, N_("only use tags to name the commits")),
		struct string_list_item *item;
				return 0;
			struct object_id oid;
		if (!ishex(*p))
		return from_tag;
	tip_table.table[tip_table.nr].refname = xstrdup(refname);
			    name->generation, parent_number);
		const char *refname;
		for_each_string_list_item(item, &data->ref_filters) {
				   N_("ignore refs matching <pattern>")),
	name->distance = distance;
	int i;
					name = get_rev_name(o, &buf);
	oidcpy(&tip_table.table[tip_table.nr].oid, oid);
				       parents_to_queue[--parents_to_queue_nr]);
				generation = 0;
								parent_number);

			*(p+1) = 0;

		}
		      const char *caller_name,



	struct name_ref_data *data = cb_data;
{

{
	struct rev_name *n;
		{

	struct string_list exclude_filters;
	const struct tip_table_entry *a = a_, *b = b_;
}
			free(name->tip_name);
};
	else
	if (!name_only)
	if (o->type != OBJ_COMMIT)
static int name_ref(const char *path, const struct object_id *oid, int flags, void *cb_data)
	 * When comparing names based on tags, prefer names
	 * based on the older tag, even if it is farther away.
		struct tip_table_entry *e = &tip_table.table[i];
	}
	if (data->ref_filters.nr) {

			return subpath - path;
{
				can_abbreviate_output = 1;
static void show_name(const struct object *obj,

static struct commit_rev_name rev_names;
static const char *get_rev_name(const struct object *o, struct strbuf *buf)
				continue;
		object = parse_object(the_repository, &oid);
	int deref = 0;
			    1 + decimal_width(parent_number));
	found = sha1_pos(o->oid.hash, tip_table.table, tip_table.nr,
		strbuf_grow(&sb, len +
		struct object_id oid;
	/* keep the current one if we cannot decide */
			continue;
static struct tip_table {

	int cmp;

	if (0 <= found)
	parse_commit(start_commit);
	if (!tip_table.sorted) {
				distance = name->distance + 1;
		else
			if (!p)
			char *p = fgets(buffer, sizeof(buffer), stdin);
			     int shorten_unambiguous, struct commit *commit,
			 * willingness to accept a shortened output by having

};
		refname = shorten_unambiguous_ref(refname, 0);
				struct object *o =
static const unsigned char *nth_tip_table_ent(size_t ix, void *table_)

		QSORT(tip_table.table, tip_table.nr, tipcmp);
		struct object_id oid;
{
						get_parent_name(name,
static int cmp_by_tag_and_age(const void *a_, const void *b_)
	struct string_list ref_filters;
			switch (subpath_matches(path, item->string)) {
	else if (always)
	struct commit *commit = NULL;
	n = get_commit_rev_name(c);
			fprintf(stderr, "Could not get object for %s. Skipping.\n",
		}
			object = (struct object *)commit;
		int i, max;
				break;
	 * less.
		for_each_string_list_item(item, &data->exclude_filters) {
	int distance;
	refname = name_ref_abbrev(refname, shorten_unambiguous);
{
	}
		for (i = 0; i < revs.nr; i++)
			struct object *peeled = deref_tag(the_repository,
			    parent_number);

					      timestamp_t taggerdate,
}
		error("Specify either a list, or --all, not both!");
			 * 'refs/tags/v*'.  We should show it as 'v1.4'.

			PARSE_OPT_NOARG | PARSE_OPT_HIDDEN, NULL, 1,
		return tip_table.table[found].refname;
 * One day.  See the 'name a rev shortly after epoch' test in t6120 when
	struct strbuf buf = STRBUF_INIT;
	if (a->taggerdate < b->taggerdate)
		struct commit *commit;
static int is_better_name(struct rev_name *name,
			if (parent->date < cutoff)
		OPT_BOOL(0, "undefined", &allow_undefined, N_("allow to print `undefined` names (default)")),
				parents_to_queue_nr++;
			name_rev(e->commit, e->refname, e->taggerdate,
	return oidcmp(&a->oid, &b->oid);
		/*
			 * When a user asked for 'refs/tags/v*' and 'v1.*',
							    generation,
 */


		 * because the new name that has just won will be better


static void add_to_tip_table(const struct object_id *oid, const char *refname,
		}
				if (parent_number > 1)
			char c = *(p+1);

			int generation, distance;
	struct rev_name *name = commit_rev_name_at(&rev_names, commit);
	else if (skip_prefix(refname, "refs/heads/", &refname))

			if (parent_number > 1) {
	if (from_tag && name->from_tag)
	return a->taggerdate != b->taggerdate;
static struct rev_name *get_commit_rev_name(const struct commit *commit)
	 */
	}
	struct commit *commit;
}
	strbuf_release(&buf);
{
	name->taggerdate = taggerdate;
			case 0: /* matched fully */

{
		while (parents_to_queue_nr)
	/*
			if (subpath_matches(path, item->string) >= 0)
	timestamp_t taggerdate;
		if (cutoff > TIME_MIN + CUTOFF_DATE_SLOP)
	if (start_commit->date < cutoff)

		if (object) {
}

			int p_len = p - p_start + 1;
	 * We are now looking at two non-tags.  Tiebreak to favor

static int tipcmp(const void *a_, const void *b_)
		return;
		strbuf_addstr(buf, n->tip_name);

{
}
		timestamp_t taggerdate;
	 */
#include "parse-options.h"
		}
	if (!start_name)

	 */

			show_name(obj, NULL,
	ALLOC_GROW(tip_table.table, tip_table.nr + 1, tip_table.alloc);
		commit = (struct commit *)o;

	else {
	}
	char *p_start;
	git_config(git_default_config, NULL);
{

			if (parent_name) {
			 */
			prio_queue_put(&queue,
			if (peeled && peeled->type == OBJ_COMMIT)
	name_tips();
	else if (allow_undefined)
#include "prio-queue.h"
					parent_name->tip_name =
	struct option opts[] = {
}
	}
		/* check for undeflow */
		if (!name->generation)
			 name->distance > distance));
				  always, allow_undefined, data.name_only);

static int is_valid_rev_name(const struct rev_name *name)
	}
	return strbuf_detach(&sb, NULL);
	} *table;
				ALLOC_GROW(parents_to_queue,
{
	 * We know that at least one of them is a non-tag at this point.
			 * both of which match, the user is showing her
				else
		if (subpath)
				break;

		tip_table.sorted = 1;
	name->from_tag = from_tag;
	argc = parse_options(argc, argv, prefix, opts, name_rev_usage, 0);
	if (p_start != p)
			}
	if (data->exclude_filters.nr) {
}
			const char *name = NULL;
static void name_rev_line(char *p, struct name_ref_data *data)
			subpath++;
	for (; argc; argc--, argv++) {
		}
	int generation;
}
			case -1: /* did not match */
#include "config.h"
/*
				   N_("only use refs matching <pattern>")),
			    1 + decimal_width(name->generation) +
			break; /* broken repository */
				parents;
	}
		const char *tip_name, timestamp_t taggerdate,
		if (!matched)
		parents_to_queue_nr = 0;
{
			 * shouldn't stop when seeing 'refs/tags/v1.4' matches
			counter = 0;

}
	init_commit_rev_name(&rev_names);
	}
static char *get_parent_name(const struct rev_name *name, int parent_number)

			name_rev_line(p, &data);
int cmd_name_rev(int argc, const char **argv, const char *prefix)

	return is_valid_rev_name(name) ? name : NULL;
			return NULL;
		}
	 */
			 * that we can see if a match with a subpath exists.
		unsigned int deref:1;
	size_t len;
}
	if (name->distance != distance)
	N_("git name-rev [<options>] <commit>..."),
		struct commit *commit;
	struct prio_queue queue;
			counter = 0;
			N_("dereference tags in the input (internal use)"),
}
	N_("git name-rev [<options>] --stdin"),

			*(p+1) = c;
{
	/* flush */

#include "repository.h"
		      int always, int allow_undefined, int name_only)
			show_name(revs.objects[i].item, revs.objects[i].name,
	c = (const struct commit *) o;

	strbuf_release(&buf);
	else
	prio_queue_put(&queue, start_commit);
	if (name->generation > 0) {
	cmp = b->from_tag - a->from_tag;
		OPT_STRING_LIST(0, "refs", &data.ref_filters, N_("pattern"),
	return 0;
	timestamp_t taggerdate = TIME_MAX;
			return 0;
		},
	QSORT(tip_table.table, tip_table.nr, cmp_by_tag_and_age);
				  always, allow_undefined, data.name_only);
				commit = (struct commit *)peeled;
	int all = 0, transform_stdin = 0, allow_undefined = 1, always = 0, peel_tag = 0;
	int name_only;
				fprintf(stderr, "Could not get commit for %s. Skipping.\n",
	/* Prefer tags. */
