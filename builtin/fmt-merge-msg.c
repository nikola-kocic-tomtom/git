		  N_("alias for --log (deprecated)"),
		if (!is_bool && merge_log_config < 0)
	for (i = 0; i < subjects.nr; i++)
		add_branch_desc(out, name);
			bp = ep;
	while (parents) {
			; /* merely annotated */
static void fmt_merge_msg_title(struct strbuf *out,
			string_list_append_nodup(&subjects,
		int len;
		}
	const char *field;
#include "repository.h"
	while (pos < in->len) {
	strbuf_addstr(out, "Merge ");
	if (src) {
			origin = xmemdupz(origin + 1, len - 2);
	struct object *branch;
			       struct strbuf *in, struct object_id *head)
		origin = xstrfmt("%s of %s", origin, src);
		int is_bool;
		for (i = 0; i < list->nr - 1; i++)
static int handle_line(char *line, struct merge_parents *merge_parents)

	const char *message = NULL;
	opts.add_title = !message;
		if (size == len)
{

		resolve_refdup("HEAD", RESOLVE_REF_READING, &head_oid, NULL);
	name = strstr(buffer, field);
	}
		rev.ignore_merges = 1;

		commit_list_insert(parent, &parents);
	strbuf_complete_line(tagbuf);
			      unsigned long len)
	}
		} else {
		item->util = xcalloc(1, sizeof(struct src_data));
			    people->items[1].string,
	}
	int flags = UNINTERESTING | TREESAME | SEEN | SHOWN | ADDED;
	free(current_branch_to_free);
		newline = strchr(p, '\n');


		pulling_head = 1;
		commit_list_insert(head_commit, &parents);
				record_person('c', &committers, commit);
}
 * hundreds of heads at a time anyway.
		src_data->head_status |= 2;
	if (table->nr && find_merge_parent(table, given, commit))

				result->item[j] = result->item[i];
			strbuf_addstr(&sig, "gpg verification failed.\n");
			subsep = ", ";
		src_data->head_status |= 2;

	const char *buffer = get_commit_buffer(commit, NULL);
	oidcpy(&table->item[table->nr].commit, commit);


	return 0;
	} else {
		string_list_append(&src_data->branch, origin);
}
			strbuf_addf(out, " of %s", srcs.items[i].string);

			first_tag = i;
						strlen(origins.items[first_tag].string));
static void add_people_count(struct strbuf *out, struct string_list *people)
static struct merge_parent *find_merge_parent(struct merge_parents *table,
#include "commit.h"
static void record_person(int which, struct string_list *people,
			record_person('a', &authors, commit);
	}
		struct commit *head;
	string_list_clear(&committers, 0);
		return;
			record_person('c', &committers, commit);
	strbuf_addf(out, "\n%c %s ", comment_line_char, label);
	struct fmt_merge_msg_opts opts;
			/* do not list a merge but count committer */
	const char *origin, *tag_name;
		if (src_data->tag.nr) {

static struct string_list srcs = STRING_LIST_INIT_DUP;
	struct commit_list *parents;
	if (argc > 0)

		return;
	} *item;
			!sigc.gpg_output)
			strbuf_addstr(out, subsep);
		tag_body += 2;
	struct option options[] = {

	if (strbuf_read(&input, fileno(in), 0) < 0)
		sep = "; ";
			     struct object_id *commit)
		item = string_list_append(&srcs, src);
	} else {
	i = get_oid_hex(line, &oid);

{
			    struct string_list *authors,
	if (head_commit)
		  PARSE_OPT_OPTARG, NULL, DEFAULT_MERGE_LOG_LEN },
	credit_people(out, authors, 'a');
		origin_data->is_local_branch = 0;
static void credit_people(struct strbuf *out,
	if (sig->len) {
			die("error in line %d: %.*s", i, len, p);
		 * Do not use get_merge_parent() here; we do not have
					      tagline.len);
					&src_data->r_branch, out);
	int alloc, nr;
	const char *tag_body = strstr(buf, "\n\n");
#define util_as_integral(elem) ((intptr_t)((elem)->util))

		len = parse_signature(buf, size);
}
		strbuf_add(tagbuf, tag_body, buf + len - tag_body);

	const char *label;
	QSORT(committers->items, committers->nr,

		}
{
{

	void *current_branch_to_free;


		src_data->head_status |= 2;
		while (*bp) {
	     skip_prefix(me, them->items->string, &me) &&
#include "fmt-merge-msg.h"

	struct object_id head_oid;
		struct strbuf sig = STRBUF_INIT;
		len = newline ? newline - p : strlen(p);
		  DEFAULT_MERGE_LOG_LEN },
		if (given && !oideq(&table->item[i].given, given))
		struct object_id oid;
		{ OPTION_INTEGER, 0, "summary", &shortlog_len, N_("n"),
	      cmp_string_list_util_as_integral);
		char *buf = read_object_file(oid, &type, &size);
	clear_commit_marks(head, flags);
	if (!strcmp(key, "merge.log") || !strcmp(key, "merge.summary")) {
		strbuf_addf(out, "\n* %s: (%d commits)\n", name, count);
{
		else
	elem->util = (void*)(util_as_integral(elem) + 1);
		struct string_list *list, struct strbuf *out)
	else if (people->nr == 2)
/*
	if (kind == 'a') {
	if (opts->shortlog_len) {
		if (is_bool && merge_log_config)

		strbuf_addstr(&output, message);
	 */
{
	parents = NULL;
	struct string_list_item *item;



					out);
		}
static void fmt_merge_msg_sigs(struct strbuf *out)
			if (i != j)
			subsep = ", ";
			  struct string_list *them,


		strbuf_add_commented_lines(tagbuf, sig->buf, sig->len);
	find_merge_parents(&merge_parents, in, &head_oid);
	free(merge_parents.item);
		name_end--;
		string_list_append(&src_data->r_branch, origin);
	data->tag.strdup_strings = 1;
		in = fopen(inpath, "r");
					strlen(origins.items[i].string));
	FILE *in = stdin;
	int i, tag_number = 0, first_tag = 0;
		current_branch += 11;
		struct signature_check sigc = { 0 };
	strbuf_release(&tagbuf);
}
	int limit = opts->shortlog_len;
	if (starts_with(line + hexsz + 1, "not-for-merge"))
	struct string_list committers = STRING_LIST_INIT_DUP;
	}
	const unsigned hexsz = the_hash_algo->hexsz;
	int i;
		src += 4;
	struct strbuf desc = STRBUF_INIT;
		origin = src;
			continue;
		if (handle_line(p, &merge_parents))
	if (opts->credit_people)
		format_commit_message(commit, "%s", &sb, &ctx);
	int pos = 0, i, j;
	const char *me;
}
{
		if (commit && !oideq(&table->item[i].commit, commit))
	unsigned is_local_branch:1;
}
	int pulling_head = 0;

		OPT_FILENAME('F', "file", &inpath, N_("file to read from")),
	const struct string_list_item *a = a_, *b = b_;
}
	return 0;

}
		if (parse_oid_hex(p, &oid, &q) ||
}

		     struct fmt_merge_msg_opts *opts,
		pulling_head = 0;
};
		char *newline, *p = in->buf + pos;
	if (prepare_revision_walk(rev))
	struct strbuf input = STRBUF_INIT, output = STRBUF_INIT;
	if (origin_data->is_local_branch && use_branch_desc)
		struct commit *parent;
			    (int)util_as_integral(&people->items[0]));
	origin_data = xcalloc(1, sizeof(struct origin_data));
	struct commit *commit;
		label = "By";
			continue;
		name_end--;
	for (i = 0; i < origins.nr; i++) {
		if (!parent)
	} else {
		return;
			      struct strbuf *sig,
#include "refs.h"
		     struct strbuf *out)
		 * util field yet.
					      struct object_id *commit)
struct src_data {
		return 3;
	head->object.flags |= UNINTERESTING;
		merge_log_config = git_config_bool_or_int(key, value, &is_bool);
	int i, count = 0;
		if (!tag_number++) {
static void add_merge_parent(struct merge_parents *table,
	struct merge_parent {
		strbuf_addbuf(out, &tagbuf);
	struct string_list branch, tag, r_branch, generic;

	git_config(fmt_merge_msg_config, NULL);
	}
					origins.items[i].string,
		if (src_data->head_status == 3) {
	if (line[len - 1] == '\n')
{
		const char *subsep = "";
	data->generic.strdup_strings = 1;
	src_data = item->util;
		if (!count && opts->credit_people)
struct merge_parents {
}
	char *name_buf, *name, *name_end;

		else
	add_pending_object(rev, branch, name);
		char *newline = strchr(p, '\n');
		for (i = 0; i < result->nr; i++)
		die("No current branch");
struct origin_data {
}
	else

	head_commit = lookup_commit(the_repository, head);
	if (inpath && strcmp(inpath, "-")) {
	int head_status;
				 head, &rev, opts, out);
	int ret;
		strbuf_addstr(out, sep);
		rev.limited = 1;
	struct src_data *src_data;
static int cmp_string_list_util_as_integral(const void *a_, const void *b_)
		add_people_info(out, &authors, &committers);
	    (them->nr == 1 &&
		strbuf_complete_line(out);
	}
		rev.commit_format = CMIT_FMT_ONELINE;
		signature_check_clear(&sigc);
		else if (check_signature(buf, len, buf + len, size - len, &sigc) &&

			strbuf_addstr(out, srcs.items[i].string);
		if (subjects.nr > limit)



	data->branch.strdup_strings = 1;
			     struct object_id *given,
		string_list_append(&src_data->generic, line);

	if (!find_merge_parent(merge_parents, &oid, NULL))
{
		const char *bp = desc.buf;
	const struct object_id *oid = &origin_data->oid;
		if (src_data->r_branch.nr) {
			strbuf_addstr(out, subsep);
		fmt_merge_msg_sigs(out);
	}
		}
	return NULL;
			continue;
	struct object_id oid;
 */
}
			const char *ep = strchrnul(bp, '\n');

		if (src_data->head_status == 1) {
}
	if (!strcmp("master", current_branch))
		/*
			die_errno("cannot open '%s'", inpath);

		strbuf_addstr(out, plural);
			string_list_append(&subjects,
	const char *current_branch;
	credit_people(out, committers, 'c');
			  int kind)

		if (src_data->generic.nr) {
		strbuf_addf(out, "%s (%d) and others",

						origins.items[first_tag].string,
		const char *q;
	next:
	if (i)

static void add_branch_desc(struct strbuf *out, const char *name)
			N_("use <text> as start of message")),
		i++;
	struct strbuf sb = STRBUF_INIT;
		repo_init_revisions(the_repository, &rev, NULL);
			strbuf_addf(out, "  : %.*s", (int)(ep - bp), bp);
		    q[1] != '\t')
		strbuf_ltrim(&sb);
	for (i = 0; i < srcs.nr; i++) {
	/*
 * I know, I know, this is inefficient, but you won't be pulling and merging
		struct object *obj;
	if (pulling_head) {
					   oid_to_hex(&commit->object.oid));
		string_list_append(&src_data->tag, tag_name);
			fmt_tag_signature(&tagbuf, &sig, buf, len);
			return error("%s: negative length %s", key, value);
				   const char *buffer)
		strbuf_complete_line(out);


		  struct fmt_merge_msg_opts *opts)
	if (message)
	}
		     struct commit *head,
		elem->util = (void *)0;
	char *src;
#include "config.h"
	return 0;
				    list->items[i].string);
		    q[0] != '\t' ||
	} else if (!strcmp(key, "merge.branchdesc")) {
		die("revision walk setup failed");
{
	struct merge_parents merge_parents;

		int len;
		int len = strlen(origin);

		else
		me = git_author_info(IDENT_NO_DATE);
		strbuf_addf(out, "%s%s", singular, list->items[0].string);
	const char *inpath = NULL;

		return 2;
	return 0;
		label = "Via";

}
			    people->items[0].string,
int fmt_merge_msg_config(const char *key, const char *value, void *cb)
			print_joined("commit ", "commits ", &src_data->generic,
					out);
#include "builtin.h"

	string_list_clear(&authors, 0);

		if (strcmp(".", srcs.items[i].string))
	argc = parse_options(argc, argv, prefix, options, fmt_merge_msg_usage,
	if (origins.nr)
static struct string_list origins = STRING_LIST_INIT_DUP;
			continue;
		return 0; /* subsumed by other parents */
{
	if (starts_with(current_branch, "refs/heads/"))
		if (opts->credit_people)

		strbuf_release(&sig);
	}
	if (strcmp(".", src))
		}
			    (int)util_as_integral(&people->items[1]));
	while (pos < in->len) {
	} else
		for (i = 0; i < origins.nr; i++)
	reduce_heads_replace(&parents);
			strbuf_addf(out, "  %s\n", subjects.items[i].string);
	if (!item) {
		OPT_END()
			fmt_tag_signature(&tagbuf, &sig, buf, len);
			strbuf_addf(out, "%s%s", i > 0 ? ", " : "",
		add_merge_parent(result, &obj->oid, &parent->object.oid);
	for (i = 0; i < table->nr; i++) {
	field = (which == 'a') ? "\nauthor " : "\ncommitter ";
};
		if (commit->parents && commit->parents->next) {
	/* get current branch */

	} else {
	memset(&merge_parents, 0, sizeof(merge_parents));
		origin = src;
#include "revision.h"
			    (int)util_as_integral(&people->items[0]),
	} else if (skip_prefix(line, "tag ", &tag_name)) {
{
	setup_revisions(0, NULL, rev, NULL);
				struct strbuf tagline = STRBUF_INIT;
		return;
	item = unsorted_string_list_lookup(&srcs, src);
	opts.credit_people = 1;

		return;
		p[len] = 0;
		 * "name" here and we do not want to contaminate its
	if (line[hexsz + 1] != '\t')
	record_person_from_buf(which, people, buffer);
				strbuf_release(&tagline);
	name += strlen(field);
#include "string-list.h"
	else if (people->nr)
			}
		if (origin[0] == '\'' && origin[len - 1] == '\'')
	char *sep = "";
	if (ret)
					      struct object_id *given,
	struct string_list authors = STRING_LIST_INIT_DUP;
	while (isspace(*name_end) && name <= name_end)
	if (!elem) {
	elem = string_list_lookup(people, name_buf);
			if (*ep)
		src = line;
		}
		strbuf_addch(tagbuf, '\n');

		count++;
	if (!name)
	for (i = j = 0; i < result->nr; i++) {
		line[len - 1] = 0;
		pos += len + !!newline;
			print_joined("branch ", "branches ", &src_data->branch,
	ALLOC_GROW(table->item, table->nr + 1, table->alloc);
		if (!buf || type != OBJ_TAG)
	string_list_clear(&subjects, 0);
	memset(&opts, 0, sizeof(opts));
	if (!branch || branch->type != OBJ_COMMIT)


	 * "branch 'frotz' of git://that/repository.git".
	struct string_list subjects = STRING_LIST_INIT_DUP;
		return ret;
		enum object_type type;
	if (*name_end)
	oidcpy(&origin_data->oid, &oid);

	table->item[table->nr].used = 0;
			subsep = ", ";
static void record_person_from_buf(int which, struct string_list *people,
	write_in_full(STDOUT_FILENO, output.buf, output.len);

		 */
	branch = deref_tag(the_repository, parse_object(the_repository, oid),
			continue;


}
		src_data->head_status |= 2;
				result->item[i].used = 1;
	} else if (skip_prefix(line, "branch ", &origin)) {
	add_people_count(out, them);
		struct rev_info rev;
		strbuf_addf(out, "\n* %s:\n", name);
		return &table->item[i];
	struct commit *head_commit;
		len = newline ? newline - p : strlen(p);

		me = git_committer_info(IDENT_NO_DATE);
	int i = 0, pos = 0;
		die_errno("could not read input file");
			strbuf_addstr(out, "HEAD");
	if (shortlog_len < 0)

	rev->commits = NULL;
	if (tag_body) {
	if (tagbuf.len) {
		return;
			  struct commit *commit)
	if (people->nr == 1)
		return 1;
{

#include "object-store.h"
	/* get a line */
			    people->items[0].string,
	if (!read_branch_desc(&desc, name)) {
	while ((commit = get_revision(rev)) != NULL) {
		parent = (struct commit *)peel_to_type(NULL, 0, obj, OBJ_COMMIT);
	name_end = strchrnul(name, '<');
			print_joined("tag ", "tags ", &src_data->tag, out);
		     struct origin_data *origin_data,
		}
	ret = fmt_merge_msg(&input, &output, &opts);
			strbuf_addch(&tagbuf, '\n');
#include "branch.h"
	strbuf_complete_line(out);
			goto next;
	line += hexsz + 2;
		usage_with_options(fmt_merge_msg_usage, options);
}
static int use_branch_desc;
	}

	else
			strbuf_add_commented_lines(&tagbuf,

		  PARSE_OPT_OPTARG | PARSE_OPT_HIDDEN, NULL,
#include "diff.h"
	 * At this point, line points at the beginning of comment e.g.
	clear_commit_marks((struct commit *)branch, flags);

#include "tag.h"
	table->nr++;
						 strbuf_detach(&sb, NULL));
		}
	data->r_branch.strdup_strings = 1;
		free(buf);
	if (list->nr == 1) {
}
/* merge data per repository where the merged tips came from */

	if (!strcmp(".", src) || !strcmp(src, origin)) {
			strbuf_addstr(out, subsep);
		OPT_STRING('m', "message", &message, N_("text"),
			      const char *buf,

{
		obj = parse_object(the_repository, &oid);
			strbuf_addstr(out, "  ...\n");
	NULL
	if (opts->add_title && srcs.nr)
			/* the 'tip' committer */
	string_list_append(&origins, origin)->util = origin_data;
	}
		head = lookup_commit_or_die(&head_oid, "HEAD");
	if (!current_branch)
				const char *current_branch)
	if (len < hexsz + 3 || line[hexsz] != '\t')
		  N_("populate log with at most <n> entries from shortlog"),
	};
#include "commit-reach.h"
		     struct rev_info *rev,
	      cmp_string_list_util_as_integral);
			if (opts->credit_people)
		}

};
			j++;
		struct pretty_print_context ctx = {0};

	struct string_list_item *elem;
		init_src_data(item->util);
	}
	struct object_id oid;
		origin = line;
	int i, len = strlen(line);
				 origins.items[i].util,
	}

	rev->pending.nr = 0;
			if (oideq(&result->item[i].commit, &cmit->object.oid))
	}
	current_branch = current_branch_to_free =
		struct object_id commit;
		if (!in)
			subsep = ", ";
		unsigned char used;
static void add_people_info(struct strbuf *out,
		src_data->head_status |= 1;
	}
		if (i >= limit)
	struct strbuf tagbuf = STRBUF_INIT;
		strbuf_addstr(out, people->items[0].string);
	struct origin_data *origin_data;

			    struct string_list *committers)
		strbuf_addf(out, "%s (%d) and %s (%d)",
	int i = 0;
			continue;

	result->nr = j;
{
			   oid_to_hex(oid),
	free(name_buf);
		strbuf_addch(out, '\n');
		pos += len + !!newline;
static void find_merge_parents(struct merge_parents *result,
	src = strstr(line, " of ");
{
		shortlog_len = (merge_log_config > 0) ? merge_log_config : 0;
		return 0;
static void shortlog(const char *name,
			print_joined("remote-tracking branch ", "remote-tracking branches ",
			strbuf_addstr(&sig, sigc.gpg_output);
	if (!them->nr ||
}
	unuse_commit_buffer(commit, buffer);
	}
		{ OPTION_INTEGER, 0, "log", &shortlog_len, N_("n"),
}
	int shortlog_len = -1;
			merge_log_config = DEFAULT_MERGE_LOG_LEN;


{
				strbuf_addch(&tagline, '\n');
	opts.shortlog_len = shortlog_len;
		return git_default_config(key, value, cb);
	}
		struct object_id *oid = origins.items[i].util;
	}
	strbuf_release(&desc);
	free_commit_list(rev->commits);

		elem = string_list_insert(people, name_buf);

#include "cache.h"
	oidcpy(&table->item[table->nr].given, given);
		if (src_data->branch.nr) {
	if (list->nr == 0)
		fmt_merge_msg_title(out, current_branch);

static void fmt_tag_signature(struct strbuf *tagbuf,
		struct src_data *src_data = srcs.items[i].util;
		if (!sb.len)
		origin_data->is_local_branch = 1;

		strbuf_addch(out, '\n');
	}
		struct commit *cmit = pop_commit(&parents);
	     starts_with(me, " <")))
{
			continue; /* skip not-for-merge */
	} else if (skip_prefix(line, "remote-tracking branch ", &origin)) {
			     0);
		strbuf_addf(out, " and %s", list->items[list->nr - 1].string);
		use_branch_desc = git_config_bool(key, value);

	add_pending_object(rev, &head->object, "^HEAD");
#include "gpg-interface.h"
	     me &&
	return util_as_integral(b) - util_as_integral(a);
		unsigned long size, len;
};
	} else {

	}
				strbuf_add_commented_lines(&tagline,
	 * Find the repository name and point it with src.
				strbuf_insert(&tagbuf, 0, tagline.buf,

static void init_src_data(struct src_data *data)
		char *p = in->buf + pos;

			if (tag_number == 2) {
	if (name_end < name)
{
int cmd_fmt_merge_msg(int argc, const char **argv, const char *prefix)
	N_("git fmt-merge-msg [-m <message>] [--log[=<n>] | --no-log] [--file <file>]"),
				ep++;
			   the_hash_algo->hexsz);
			shortlog(origins.items[i].string,
	if (count > limit)
{
			strbuf_addstr(out, subsep);
}
		struct object_id given;
		strbuf_addf(out, " into %s\n", current_branch);
		}

	name_buf = xmemdupz(name, name_end - name + 1);
int fmt_merge_msg(struct strbuf *in, struct strbuf *out,
		int i;
	QSORT(authors->items, authors->nr,
static const char * const fmt_merge_msg_usage[] = {
		*src = 0;
		if (result->item[i].used) {


static void print_joined(const char *singular, const char *plural,
