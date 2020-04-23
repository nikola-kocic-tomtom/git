		if (!graft) {
		next = next ? next + 1 : tail;
static inline int standard_header_field(const char *field, size_t len)
		if (!eof)
	return c;
	 * if everything else stays the same.
}
		p = skip_blank_lines(p + 2);
	}

	 * the tips serve as a starting set for the work queue.
	const char *eol;

		handle_signed_tag(parent, tail);
		struct commit *commit = parents->item;
	**tail = mergetag;
	revs.initial = 1;
			die("cannot read commit object %s",

static int find_invalid_utf8(const char *buf, int len)
struct commit_graft *lookup_commit_graft(struct repository *r, const struct object_id *oid)
struct commit_graft *read_graft_line(struct strbuf *line)
	}
{
{
	return c;
	ret = bases->item;

	ret = v->buffer;
	free_commit_list(orig);
#include "refs.h"
		 */
		return NULL;
		it = NULL;
		die("Ambiguous refname: '%s'", refname);
	struct buffer_slab *bs = xmalloc(sizeof(*bs));


					in_signature = 1;

struct commit_extra_header *read_commit_extra_headers(struct commit *commit,
	r->parsed_objects->grafts[pos] = graft;
		commit = commit->parents->item;
	return NULL;
	while (line) {
	struct commit_graft *graft;
	}

		commit->object.flags &= ~mark;
				if (skip_prefix(line, gpg_sig_headers[i], &p) &&
	struct merge_remote_desc *desc;


	switch (dwim_ref(refname, strlen(refname), &oid, &full_refname)) {
	result = commit_tree_extended(msg, msg_len, tree, parents, ret,
	 * if (verify_signed_buffer(buf, len, buf + len, size - len, ...))
{


struct commit *pop_commit(struct commit_list **stack)
		return NULL;
}
	else
		if (ret || (check_trust && signature_check.trust_level < TRUST_MARGINAL))

	return 0;
	for (; l; l = l->next )
	 * it does not validate, but the integrator may not have the
		return -1;
 *
		load_commit_graph_info(r, item);
	}
	/* dateptr < buf && buf[-1] == '\n', so parsing will stop at buf-1 */

	ret = run_hook_ve(hook_env.argv,name, args);
			     oid_to_hex(&item->object.oid));
		len -= bytes;
	struct commit_extra_header *extra, *to_free;
		queue.compare = NULL;

	int res = 0;
 *
	clear_commit_marks_many(1, &commit, mark);
	/* And check the encoding */
	if (sig_start)
			/* the previous was not trailing comment */
	struct commit_list *bases;
	char *date_end;
	strbuf_addch(&buffer, '\n');
		if (bad < 0)

		while (c & 0x40) {
#include "object-store.h"

			in_signature = 0;
				  const struct commit *commit)
			*sizep = 0;
	case 0:
	 * NOTE! This ordering means that the same exact tree merged with a
	if (a_date < b_date)

		return error("bad tree pointer %s in commit %s",
		if (tail <= bufptr + parent_entry_len + 1 ||
 * This verifies that the buffer is in proper utf8 format.
}
		 * emitted. we can emit it now.
		if (eol - line > key_len &&

	int offset = 0;



	strbuf_addf(&buffer, "committer %s\n", git_committer_info(IDENT_STRICT));
	return lookup_commit_reference_gently(r, oid, 0);
	 * phase 0 verifies line, counts hashes in line and allocates graft
		return NULL;
		 */
	const char *gpg_sig_header = gpg_sig_headers[hash_algo_by_ptr(the_hash_algo)];
		return NULL;
{
			graft = xmalloc(st_add(sizeof(*graft),
	struct commit **commit;
		enum object_type type;
{
	if (!fp)
	struct object_id parent;
		*(indegree_slab_at(&indegree, commit)) = 0;
{
	int in_old_conflicts_block = 0;
	if (parse_commit(commit))
					     oid_to_hex(&item->object.oid));
	struct commit_list **pptr;
		unsigned int codepoint;
 *     return list;

			 excluded_header_field(line, eof - line, exclude))
	return parse_timestamp(dateptr, NULL, 10);
			commit_list_insert_by_date(commit, list);
	if (tail <= bufptr + tree_entry_len + 1 || memcmp(bufptr, "tree ", 5) ||
	const char *sig_start = NULL;
}
		copypos += len;
		return 0;
		while (parents) {
	init_buffer_slab(bs);
		die(_("Commit %s does not have a GPG signature."), hex);
	strbuf_addf(&buffer, "author %s\n", author);
	unsigned long size;
	}
{
		if (strcmp(extra->key, "mergetag"))
			 */
	if (buf + 9 >= tail)
		max_val = max_codepoint[bytes];

		size_t xlen = strlen(*exclude);
}
		return;
			continue; /* not a merge tag */
{
		int bytes, bad_offset;

		/*
			sig_end = next;
	/* newer commits with larger date first */
 */
			 const struct object_id *tree,
		c = buf->buf[pos];
		    bufptr[parent_entry_len] != '\n')
			int *pi = indegree_slab_at(&indegree, parent);
static int collect_one_reflog_ent(struct object_id *ooid, struct object_id *noid,
		}
	if (item->parents) {
	/* update the indegree */
		eol = strchrnul(p, '\n');
		queue.cb_data = &author_date;
		pptr = &commit_list_insert(commit, pptr)->next;
		/* nada */;
			free(graft);
	*merge_desc_slab_at(&merge_desc_slab, commit) = desc;
				goto bad_graft_data;
	va_start(args, name);
			    int check_trust)
{
	while (buf < tail && *buf++ != '\n')
	while (commit) {
}
	}
	new_list->item = item;
		}
			if (!new_parent)
static int commit_graft_pos(struct repository *r, const unsigned char *sha1)
void set_commit_buffer(struct repository *r, struct commit *commit, void *buffer, unsigned long size)
	struct commit_list **pp = list;
struct commit_list *copy_commit_list(struct commit_list *list)
			codepoint |= *buf & 0x3f;
		else
void record_author_date(struct author_date_slab *author_date,
		if (sizep)
	extra = read_commit_extra_header_lines(buffer, size, exclude);
	struct commit_extra_header *extra = NULL, **tail = &extra, *it = NULL;
		return;
	strbuf_release(&buffer);
	struct commit_list *head = NULL;
	return;

		warning(_("%s %s is not a commit!"),
		return get_commit_tree_in_graph(r, commit);
   "You may want to amend it after fixing the message, or set the config\n"
		*sizep = v->size;
	void *buffer;
define_commit_slab(merge_desc_slab, struct merge_remote_desc *);
	clear_indegree_slab(&indegree);
{
const char *commit_type = "commit";
			bytes++;
			in_signature = 1;
int run_commit_hook(int editor_is_used, const char *index_file,
	return tree ? &tree->object.oid : NULL;
}
	if (!startup_info->have_repository)
		return -1;
	if (pos < 0)
		free(buffer);
	unsigned c = 0;

	return commit_graft_table[index]->oid.hash;
	assert_oid_type(tree, OBJ_TREE);
 * Append a commit to the end of the commit_list.
static const unsigned char *commit_graft_sha1_access(size_t index, void *table)
	set_commit_tree(item, tree);
		}
				    *p == ' ') {
		return -1;

			return bad_offset;
		int i;
	for (line = buffer, eob = line + size;


	bases = get_merge_bases_many(commit, revs.nr, revs.commit);
		v->size = 0;
	struct commit_list *list = NULL;
int for_each_mergetag(each_mergetag_fn fn, struct commit *commit, void *data)
		}
#include "gpg-interface.h"
}
void clear_commit_marks_many(int nr, struct commit **commit, unsigned int mark)
	struct commit_extra_header *extra = NULL;
		strbuf_remove(buf, pos, 1);

		if (len == xlen && !memcmp(field, *exclude, xlen))


		queue.compare = compare_commits_by_author_date;
 * Inspect the given string and determine the true "end" of the log message, in

						   &graft->parent[i]);


	if (use_commit_graph && parse_commit_in_graph(r, item))
	if (!v) {
	/* find the end of the header */
	struct merge_remote_desc *desc;
	unsigned long size;
define_commit_slab(indegree_slab, int);
	strbuf_addf(&buffer, "tree %s\n", oid_to_hex(tree));
	if (commit && !merge_remote_util(commit))
	/* We no longer need the commit list */
	return 0;
	 * find the tips


	mergetag->value = buf;
	 * We could verify this signature and either omit the tag when
	const int tree_entry_len = the_hash_algo->hexsz + 5;
	char *buf;
	return r->parsed_objects->grafts[pos];
	append_merge_tag_headers(parents, &tail);
}
		}
	for (extra = to_free; !res && extra; extra = extra->next) {
		for (i = 0; i < graft->nr_parent; i++) {
	}
static void add_extra_header(struct strbuf *buffer,
 */
		c++;
			return line + key_len + 1;
		add_one_commit(ooid, revs);
		codepoint = (c & 0x7f) >> bytes;

		offset++;
			return error("bad parent %s in commit %s",
	}
	free_commit_extra_headers(to_free);
		struct commit *commit = next->item;
		eof = memchr(line, ' ', next - line);
	void *buffer;

	const struct commit *a = a_, *b = b_;
			next_line = buf + len;
void repo_unuse_commit_buffer(struct repository *r,
	if (a_date > b_date)
				  int tz, const char *message, void *cbdata)
	fclose(fp);
	c->maybe_tree = t;
		MOVE_ARRAY(the_repository->parsed_objects->grafts + pos,
				}
	return commit_list_insert(item, pp);
			 const char *author, const char *sign_commit,

static void *commit_list_get_next(const void *a)
	if (!line->len || line->buf[0] == '#')

				const char *p;

	}
#include "wt-status.h"
				/* dump the whole remainder of the buffer */
				  const char *ident, timestamp_t timestamp,
		return;
}
	if (!exclude)
		if (bytes < 1 || 3 < bytes)
		break;
			 "Please use \"git replace --convert-graft-file\"\n"
		/* nada */;
	c->object.parsed = 0;
	if (buf >= tail)
	for (next = orig; next; next = next->next) {

			(r->parsed_objects->grafts_nr - pos - 1) *
	while (line < tail) {
		break;
		}
			next_line++;
			    oid_to_hex(&parent->object.oid));
			if (--(*pi) == 1)
			     struct commit *item, int quiet_on_missing)
	int ok = 1;
{
	if (*p) {
}
int compare_commits_by_gen_then_commit_date(const void *a_, const void *b_, void *unused)
		 * the result cannot be trusted.
				/* dump the whole remainder of the buffer */
		 * many more bytes this sequence should have.

		free(extra);
	if (!buf || type != OBJ_TAG)


			return bad_offset;
static void commit_list_set_next(void *a, void *next)
	 * This is unfortunate; the initial tips need to be shown
static void add_one_commit(struct object_id *oid, struct rev_collect *revs)
	clear_prio_queue(&queue);
}
/*
		unsigned long size;
				prio_queue_put(&queue, parent);

	 * in the order given from the revision traversal machinery.
	commit = (struct commit *)peel_to_type(name, 0, obj, OBJ_COMMIT);
	strbuf_add(&buffer, msg, msg_len);
			die(_("Commit %s has an untrusted GPG signature, "
		    !strncmp(line, key, key_len) &&
	}
 * --amend" on an existing commit, we also ignore "Conflicts:".  To
 * Topological sort support

	for (;;) {
		/* U+xxFFFE and U+xxFFFF are guaranteed non-characters. */
		/* nada */;
	const char *tail = buf->buf + buf->len;
/*
		}
 *     assert(commit_list_count(list) == 2);
			   the_repository->parsed_objects->grafts + pos + 1,
	while (list)
	if (!obj)
static struct commit_extra_header *read_commit_extra_header_lines(
	argv_array_clear(&hook_env);
	int ret = 1;
{
}
	timestamp_t date;
	return commit;


	while (line < tail) {

	if (r->parsed_objects->commit_graft_prepared)
	commit->object.flags |= TMP_MARK;
	if (!orig)
	if (!c)
struct rev_collect {
		 */
			graft->nr_parent = i;
	return object_as_type(r, obj, OBJ_COMMIT, quiet);
		return 0;
			*sizep = 0;
				   unsigned long *sizep)
	struct strbuf buffer;
		extra = next;
{
		do {

	/*

		replace[1] = 0x80 + (c & 0x3f);
 * next starts by pointing to the variable that holds the head of an
		struct commit *commit = next->item;
int parse_signed_commit(const struct commit *commit,
			ref_name, oid_to_hex(oid));
}


		unsigned char replace[2];
	if (item->object.parsed)
	return item;
	struct commit *commit;


		memmove(r->parsed_objects->grafts + pos + 1,
		return;
 * the last item on the list as new commits are appended.
	struct object_id dummy_oid, *oid;
#include "diff.h"
		/*

size_t ignore_non_trailer(const char *buf, size_t len)
				continue;

	struct strbuf signature = STRBUF_INIT;
	int i, phase;
			     oid_to_hex(&item->object.oid));
{

		if (!parents)
}
	struct object_id oid;
		return error("Object %s not a commit",
int commit_tree_extended(const char *msg, size_t msg_len,

	int pos = commit_graft_pos(the_repository, oid->hash);
	const char *gpg_sig_header = gpg_sig_headers[hash_algo_by_ptr(the_hash_algo)];
		return create_object(r, oid, alloc_commit_node(r));
		strbuf_addch(buffer, '\n');
	if (!ident_line)
	while (parents) {
		ret = fn(the_repository->parsed_objects->grafts[i], cb_data);
		else {
}
{
	unsigned long size;
		}
	default:
				      unsigned int mark)
	if (get_oid_hex(bufptr + 5, &parent) < 0)
{
	while ((commit = prio_queue_get(&queue)) != NULL) {
{
free_return:
		 * codepoints beyond U+10FFFF, which are guaranteed never to exist.
 * Usage example:
static void handle_signed_tag(struct commit *parent, struct commit_extra_header ***tail)
	for (i = ret = 0; i < the_repository->parsed_objects->grafts_nr && !ret; i++)
	if (get_oid(name, &oid))
		while ((parents = parents->next))
	else if (a->date > b->date)
		if (!new_parent)
		if (sort_order == REV_SORT_BY_AUTHOR_DATE)
			saw_signature = 1;
		}
	 */
	else if (a_date > b_date)
	case REV_SORT_BY_AUTHOR_DATE:
	/*
	struct commit *commit;
		return 1;
{
		goto free_return;
		item->parents = NULL;
	struct commit_buffer *v = buffer_slab_peek(
			  int ignore_dups)
#include "commit.h"

#include "tag.h"
}
			}
	while (list)
	while (buf < tail && *buf++ != '>')

		0x7f, 0x7ff, 0xffff, 0x10ffff
	enum object_type type;

				       parse_object(r, oid),
	error("bad graft data: %s", line->buf);
struct commit *lookup_commit_or_die(const struct object_id *oid, const char *ref_name)
	/* Person/date information */
	unuse_commit_buffer(commit, buffer);
		const char *next = memchr(line, '\n', tail - line);
	switch (sort_order) {
		if (&bases->item->object == &revs.commit[i]->object)
	if (sign_commit && do_sign_commit(&buffer, sign_commit)) {
static int excluded_header_field(const char *field, size_t len, const char **exclude)
	if (!commit ||

		offset += bytes;
	const char *eoh;
	if (advice_graft_file_deprecated)


		/* And verify that they are good continuation bytes */
			 struct commit_list *parents, struct object_id *ret,
			strbuf_add(signature, sig, next - sig);
	if (pos < r->parsed_objects->grafts_nr)
}
{
					sig_end = next;
		struct commit *new_parent;
				     oid_to_hex(&parent),
	if (sort_order == REV_SORT_IN_GRAPH_ORDER)


	struct tree *tree;

		/*
	/*
		inspos = eoh - buf->buf + 1;
{
			r->parsed_objects->grafts_nr,

		/* Simple US-ASCII? No worries. */

		/*
	}
	struct object *obj = deref_tag(r,
		parents = commit->parents;
		pp = &p->next;
			      struct commit_extra_header ***tail)
	assert(!graft);

	struct commit *commit;
}
	struct commit_buffer *v = buffer_slab_peek(
	mergetag->key = xstrdup("mergetag");

		const char *next = memchr(line, '\n', tail - line);
static int do_sign_commit(struct strbuf *buf, const char *keyid)
	return commit;
static const char commit_utf8_warn[] =

			error("Could not read %s",

	if (parse_commit(item))

		}
	const char *buffer, size_t size,
	size_t cutoff = wt_status_locate_end(buf, len);
		unsigned int min_val, max_val;

int check_commit_signature(const struct commit *commit, struct signature_check *sigc)
	const void *ret = get_cached_commit_buffer(r, commit, sizep);
	/* The format is just "Commit Parent1 Parent2 ...\n" */
		strbuf_insert(buf, pos, replace, 2);
	const char *buffer = get_commit_buffer(commit, NULL);
	return sig_start != NULL;
		parents = parents->next;
	if (v) {
		struct commit_list *parents;
	const char *sig_end = NULL;
			struct commit *commit)
	v->buffer = buffer;
	if (!(v && v->buffer == buffer))
#include "commit-graph.h"
	default: /* 'N' */
			; /* a pathname in the conflicts block */
	const struct commit *a = a_, *b = b_;

	return NULL;
		 */
}
	return &new_commit->next;
	enum object_type type;
	clear_buffer_slab(bs);
		return 0;
		/* So are anything in the range U+FDD0..U+FDEF. */
#include "run-command.h"
	case 1:
	mergetag->len = size;

		if (!graft)

 *

			int *pi = indegree_slab_at(&indegree, parent);

		return -1;


}
}
	 * later auditor may have it while auditing, so let's not run
		(len == 6 && !memcmp(field, "author", 6)) ||
		return 1;
	struct commit *ret = NULL;
	if (!oideq(oid, &c->object.oid)) {
struct commit *pop_most_recent_commit(struct commit_list **list,
	pptr = &item->parents;
}
		clear_commit_marks_1(&list, *commit, mark);

	struct commit_buffer *v = buffer_slab_peek(
	struct commit_list **pptr;
		it->key = xmemdupz(line, eof-line);
			   the_repository->parsed_objects->grafts_nr - pos - 1);
}
		const struct object_id *oid, int quiet)
			inspos += gpg_sig_header_len;


	eoh = strstr(buf->buf, "\n\n");
void free_commit_list(struct commit_list *list)
			r->parsed_objects->grafts + pos,
		bufptr += parent_entry_len + 1;

}
			 "\n"
}
	if (!encoding_is_utf8)
			struct commit *parent = parents->item;
	}
	*list = NULL;
 */
 */
	struct strbuf buf = STRBUF_INIT;
		goto cleanup_return;

		if (sizep)
{
	const char *p = commit_buffer;
	}
	case REV_SORT_BY_COMMIT_DATE:
	const char *tail = buffer;
			sig = line + gpg_sig_header_len + 1;
	free(full_refname);
		/* Do we *have* that many bytes? */

	struct argv_array hook_env = ARGV_ARRAY_INIT;
		replace[0] = 0xc0 + (c >> 6);
			new_parent = lookup_commit(r,
	case 'G':
			return;

	graft_file = get_graft_file(r);

 *
		break;
#include "mergesort.h"
}
			parents = parents->next;

			if (*line == '\n')
	    !ident.date_begin || !ident.date_end)
	free_commit_buffer(pool, c);
					sig_start = line;
		inspos += len;
void verify_merge_signature(struct commit *commit, int verbosity,
	find_unique_abbrev_r(hex, &commit->object.oid, DEFAULT_ABBREV);
		   r->parsed_objects->grafts_alloc);

}
	for (copypos = 0; sig.buf[copypos]; ) {
			return error("bad parents in commit %s", oid_to_hex(&item->object.oid));
	sigc->result = 'N';
	FLEX_ALLOC_STR(desc, name, name);
void sort_in_topological_order(struct commit_list **list, enum rev_sort_order sort_order)
void free_commit_extra_headers(struct commit_extra_header *extra)
			codepoint <<= 6;
			    oid_to_hex(&commit->object.oid), type_name(type));
		    item ? oid_to_hex(&item->object.oid) : "(null)");


{
		pop_commit(&list);
		else if (standard_header_field(line, eof - line) ||
	const char *tail = NULL;
	int encoding_is_utf8;
}
			      const void *buffer)
	struct rev_collect revs;
const void *detach_commit_buffer(struct commit *commit, unsigned long *sizep)
	const char **exclude)
{
	 *
	for (i = 0; i < revs.nr; i++)
 *     next = commit_list_append(c2, next);
	while (bufptr + parent_entry_len < tail && !memcmp(bufptr, "parent ", 7)) {
		return 0;
static struct commit_extra_header *read_commit_extra_header_lines(const char *buf, size_t len, const char **);
 *
	if (sizep)
	pos = -pos - 1;
	in_signature = 0;
		return -1;
		queue.compare = compare_commits_by_commit_date;
	 */
				 struct commit *commit, unsigned int mark)

define_commit_slab(buffer_slab, struct commit_buffer);
		else if (starts_with(line, "gpgsig")) {
	if (revs.nr <= i)
struct commit_list **commit_list_append(struct commit *commit,
	const char *bufptr = buffer;
}
		return 1;
		if (sizep)
		prio_queue_reverse(&queue);
	 * a common ancestor among reflog entries.
	}
{
	tail = buffer + size;

			break;
			/* is this the first of the run of comments? */
			/* continuation */
		if (p->item->date < item->date) {

		strbuf_addf(&buffer, "parent %s\n",
	if (sizep)
const void *repo_get_commit_buffer(struct repository *r,
	int inspos, copypos;
	return head;
	unuse_commit_buffer(commit, buffer);

		strbuf_reset(&buf);
		for (i = 0; *tail != '\0'; i++) {
	}
	ALLOC_GROW(r->parsed_objects->grafts,
	*next = new_commit;
	tree = lookup_tree(r, &parent);
	if (commit->maybe_tree || !commit->object.parsed)
		revs->initial = 0;

		len--;
}
	if (a->date < b->date)
{
	strbuf_rtrim(line);
		bol = next_line - buf;
{
		return NULL;

	c->index = 0;


			 "\"git config advice.graftFileDeprecated false\""));
	strbuf_release(&buf);
/*


	}
	return 0;
		add_one_commit(&oid, &revs);
		p++;
			prio_queue_put(&queue, commit);
N_("Warning: commit message did not conform to UTF-8.\n"
}
		const char *author, const char *sign_commit)
struct commit_buffer {
	if (size == len)
struct tree *repo_get_commit_tree(struct repository *r,

					     oid_to_hex(&graft->parent[i]),
	int ret;
		strbuf_insert(buf, inspos, bol, len);
		/* also record the author dates, if needed */

#include "cache.h"
	}

	}
}
		 * all children of commit have already been
		/*

	while (buf < tail && *buf++ != '\n')
		die(_("could not parse %s"), ref_name);
}

cleanup_return:
				   const struct commit *commit,
		result = -1;
	struct author_date_slab *author_date = cb_data;
	struct commit *item = top ? top->item : NULL;
bad_graft_data:
}
}
	*tail = &mergetag->next;
}
			goto bad_graft_data;
		if (line == eol)


		fprintf(stderr, _(commit_utf8_warn));
		break;
}
	if (encoding_is_utf8 && !verify_utf8(&buffer))
	return v->buffer;


						      const char **exclude)
		if (in_signature && line[0] == ' ')
		return error("bogus commit object %s", oid_to_hex(&item->object.oid));
	 */
	struct object *obj;
}
struct commit *get_merge_parent(const char *name)
		(len == 8 && !memcmp(field, "encoding", 8)));
			return bad_offset;
		(len == 6 && !memcmp(field, "parent", 6)) ||
		unsigned char c = *buf++;
		if (eof + 1 < next)
	unsigned long size, len;
	struct tree *tree = get_commit_tree(commit);

			continue;
	return result;
	return 0;
	}


	/* make sure shallows are read */
}
			struct commit *parent = parents->item;
		if (codepoint < min_val || codepoint > max_val)
		next = next ? next + 1 : tail;
	int key_len = strlen(key);
}
{
	void *ret;

		 * Presumably this is leftover from an earlier failed parse;
			struct strbuf *payload, struct strbuf *signature)
	else if (a->date > b->date)

	return ret;
	if (get_oid_committish(name, &oid))
		 * valid range.
#include "advice.h"
void release_commit_memory(struct parsed_object_pool *pool, struct commit *c)
	struct commit_list *p;
	new_commit->item = commit;
	while (len) {
		goto free_return;


		die("unable to parse commit %s",
	};
	const char *ident_line;
		 * The clone is shallow if nr_parent < 0, and we must
		if (sig) {


	const struct commit *a = a_, *b = b_;
	free_commit_list(c->parents);
	if (memcmp(buf, "committer", 9))
	static const unsigned int max_codepoint[] = {
 *
{
	read_graft_file(r, graft_file);
	tail += size;
	timestamp_t a_date = ((const struct commit_list *)a)->item->date;
			 struct commit_extra_header *extra)
void commit_list_sort_by_date(struct commit_list **list)
	*list_p = new_list;
	/*

	 *	warn("warning: signed tag unverified.");
		strbuf_remove(buf, sig_start - buf->buf, sig_end - sig_start);
	free(buffer);
{
#include "commit-slab.h"

		(len == 9 && !memcmp(field, "committer", 9)) ||
		if (!parse_commit(commit) && !(commit->object.flags & mark)) {
	timestamp_t a_date = *(author_date_slab_at(author_date, a));
		if (it)
int remove_signature(struct strbuf *buf)
	}
			return ok;
	struct object *obj = lookup_object(r, oid);
	struct object_id oid;

 * Indexed by hash algorithm identifier.
			in_old_conflicts_block = 0;
	unsigned long size;

				strbuf_add(&buf, line + 1, next - (line + 1));
	*list = llist_mergesort(*list, commit_list_get_next, commit_list_set_next,
		set_commit_buffer(r, item, buffer, size);

	long pos = 0;
		if (in_signature && line[0] == ' ')
}
		return 0;
		if (!(mark & commit->object.flags))
	int gpg_sig_header_len = strlen(gpg_sig_header);
static int read_graft_file(struct repository *r, const char *graft_file)
	} else
		struct commit_graft *graft = read_graft_line(&buf);
				return error("bad graft parent %s in commit %s",

				(*pi)++;
	if (top) {
	if (a->generation < b->generation)

	if (!revs.nr)
	}
}

}
		 * Place the encoded bits at the bottom of the value and compute the
		} else if (boc) {
				boc = bol;
	while (extra) {

			strbuf_insert(buf, inspos, gpg_sig_header, gpg_sig_header_len);
{

{
		    line[key_len] == ' ') {
			     struct commit_extra_header *extra)
}
};
	}
		return 0;
			    oid_to_hex(&commit->object.oid));
#include "commit-reach.h"
		}

struct object_id *get_commit_tree_oid(const struct commit *commit)
	buffer = repo_read_object_file(r, &item->object.oid, &type, &size);
{
		const char *next_line = memchr(buf + bol, '\n', len - bol);
		       hex, signature_check.signer);
	for (i = 0; i < revs.nr; i++)
	int result;
const char *find_commit_header(const char *msg, const char *key, size_t *out_len)
			sig = line + 1;
	int gpg_sig_header_len = strlen(gpg_sig_header);
			oid = graft ? &graft->parent[i] : &dummy_oid;
			return NULL;
	ret = parse_commit_buffer(r, item, buffer, size, 0);
	 */
	const char *buffer = get_commit_buffer(commit, &size);
		strbuf_add_lines(buffer, " ", extra->value, extra->len);
struct commit *lookup_commit_reference(struct repository *r, const struct object_id *oid)
	add_one_commit(noid, revs);
	return repo_parse_commit_internal(r, item, quiet_on_missing, 1);
	struct ident_split ident;
		if ((codepoint & 0xfffe) == 0xfffe)
	return graft;
			it->value = strbuf_detach(&buf, &it->len);
		*(indegree_slab_at(&indegree, commit)) = 1;
#include "sha1-lookup.h"

}
	FILE *fp = fopen_or_warn(graft_file, "r");

	return 0;

			       int quiet_on_missing,
	     line < eob && *line != '\n';
	}
			if (!boc)

		revs.commit[i]->object.flags &= ~TMP_MARK;
{
				commit_list_compare_by_date);
	const int parent_entry_len = the_hash_algo->hexsz + 7;
	if (0 <= pos) {
static struct merge_desc_slab merge_desc_slab = COMMIT_SLAB_INIT(1, merge_desc_slab);
	}
			bufptr[tree_entry_len] != '\n')
	const char *buffer = get_commit_buffer(commit, &size);
		}
	struct commit_graft *graft = NULL;
	struct commit_list *parents = ret->parents;
int repo_parse_commit_gently(struct repository *r,
	to_free = read_commit_extra_headers(commit, NULL);
			error("duplicate graft data: %s", buf.buf);
struct commit *lookup_commit(struct repository *r, const struct object_id *oid)
		if ((codepoint & 0x1ff800) == 0xd800)
}
	char *graft_file;
}



void append_merge_tag_headers(struct commit_list *parents,
	struct commit_extra_header *mergetag;
{
		return error("bad tree pointer in commit %s",
			 * guaranteeing topological order.
		eol = p;
		set_merge_remote_desc(commit, name, obj);
	}
	return ret;
			 "to convert the grafts into replace refs.\n"
	new_list->next = *list_p;
static const char *gpg_sig_headers[] = {

	char hex[GIT_MAX_HEXSZ + 1];
void clear_commit_marks(struct commit *commit, unsigned int mark)
		init_author_date_slab(&author_date);
		keyid = get_signing_key();
	struct commit *commit;
int save_commit_buffer = 1;

	if (!item)
	struct commit_buffer *v = buffer_slab_peek(
	/*


		r->parsed_objects->buffer_slab, commit);
 * trailing comment lines and blank lines.  To support "git commit -s


	}
			record_author_date(&author_date, commit);

	free_commit_list(bases);
void free_commit_buffer(struct parsed_object_pool *pool, struct commit *commit)
	ret = check_signature(payload.buf, payload.len, signature.buf,

}

	size_t boc = 0;
	pos = commit_graft_pos(r, oid->hash);
			if (!*pi)
			*out_len = eol - line - key_len - 1;
		ok = 0;
		if (*line == ' ') {
static int commit_list_compare_by_date(const void *a, const void *b)
const void *get_cached_commit_buffer(struct repository *r, const struct commit *commit, unsigned long *sizep)
	v->size = 0;
	strbuf_release(&signature);
}
		the_repository->parsed_objects->buffer_slab, commit);
		break; /* good */
	}
		   r->parsed_objects->grafts_nr + 1,
		line = next;
int for_each_commit_graft(each_commit_graft_fn fn, void *cb_data)
			strbuf_add(&buf, eof + 1, next - (eof + 1));
				return bad_offset;
   "variable i18n.commitencoding to the encoding your project uses.\n");
#include "pkt-line.h"
		r->parsed_objects->buffer_slab, commit);

	"gpgsig-sha256",
	if (!ret) {
int find_commit_subject(const char *commit_buffer, const char **subject)
			if (!boc)
	for_each_reflog_ent(full_refname, collect_one_reflog_ent, &revs);
	ret = check_commit_signature(commit, &signature_check);
			      "allegedly by %s."), hex, signature_check.signer);
{
	if (extra->len)
	struct commit *ret = pop_commit(list);
	struct commit_list *new_commit = xmalloc(sizeof(struct commit_list));
{
	item->object.parsed = 1;
			return;
				next = tail;
	struct strbuf payload = STRBUF_INIT;
	return NULL;
		exclude++;
	case 'B':
/*
		free(top);
		 * Must be between 1 and 3 more bytes.  Longer sequences result in
	return ret;
		    const char *name, ...)
			/*
			commit_list_insert(parents->item, plist);
		/* We know 'c' must be in the range 128-255 */
	if (item->object.parsed)
 * Performs an in-place topological sort on the list supplied.
		return 0;
			break; /* found */
static int verify_utf8(struct strbuf *buf)
	return -1;
			continue;
	}
		next = memchr(line, '\n', eob - line);
		return NULL;
	for (next = orig; next; next = next->next) {





}
}
				   void *cb_data)
	}
		if (parse_oid_hex(line->buf, oid, &tail))

		author = git_author_info(IDENT_STRICT);
			if (!isspace(*tail++) || parse_oid_hex(tail, oid, &tail))
	struct object_id oid;
	strbuf_init(&buffer, 8192); /* should avoid reallocs for the headers */
	int result;
#include "prio-queue.h"
	while (parents) {
}
	if (parse_signed_commit(commit, &payload, &signature) <= 0)
		r->parsed_objects->buffer_slab, commit);
	if (a->date < b->date)
	int nr;
int register_commit_graft(struct repository *r, struct commit_graft *graft,
	/* newer commits with larger date first */
					       st_mult(sizeof(struct object_id), i)));
		pos += bad;
static timestamp_t parse_commit_date(const char *buf, const char *tail)
			int i;
	for (phase = 0; phase < 2; phase++) {
	the_repository->parsed_objects->grafts_nr--;
		die(_("Commit %s has a bad GPG signature "
		return quiet_on_missing ? -1 :

		line = next;
{
 * and does the conversion.
		oid = graft ? &graft->oid : &dummy_oid;
		return -1;
		add_extra_header(&buffer, extra);
}
			     oid_to_hex(&parent),
	     line = next) {
	/* newer commits first */
int compare_commits_by_author_date(const void *a_, const void *b_,
	if (revs->initial) {
		goto cleanup_return;
			eof = next;
}
int parse_commit_buffer(struct repository *r, struct commit *item, const void *buffer, unsigned long size, int check_graph)
	dateptr = buf;
	if (save_commit_buffer && !ret) {
	ALLOC_GROW(revs->commit, revs->nr + 1, revs->alloc);
{
	struct commit_graft **commit_graft_table = table;
	struct signature_check signature_check;
		} else {
{
			/* otherwise, it is just continuing */
		} else {
	if (pos + 1 < the_repository->parsed_objects->grafts_nr)

	if (verbosity >= 0 && signature_check.result == 'G')

fail_exit:
		bytes = 0;
		new_parent = lookup_commit(r, &parent);
	/* Mark them and clear the indegree */
	while (!strbuf_getwholeline(&buf, fp, '\n')) {
	}

			     oid_to_hex(&item->object.oid));
	while (*p && (*p != '\n' || p[1] != '\n'))
	ident_line = find_commit_header(buffer, "author", &ident_len);
		struct commit_extra_header *next = extra->next;
}
	struct commit_buffer *v = buffer_slab_at(
		argv_array_push(&hook_env, "GIT_EDITOR=:");

		return;
		for (parents = commit->parents; parents ; parents = parents->next) {
	/* And the found one must be one of the reflog entries */
	v->size = size;
{
#include "alloc.h"
		 * not traverse its real parents even when we unhide them.
	memset(&signature_check, 0, sizeof(signature_check));
			 line[gpg_sig_header_len] == ' ')
		line = *eol ? eol + 1 : NULL;
	free_commit_extra_headers(extra);
	struct strbuf sig = STRBUF_INIT;
		if (graft && (graft->nr_parent < 0 || grafts_replace_parents))
				      author, sign_commit, extra);
			commit->object.flags |= mark;
}
		 */
			return bad_offset;
	mergetag = xcalloc(1, sizeof(*mergetag));
		res = fn(commit, extra, data);
	return res;

	return bs;
	return result;
	while (parents) {
#include "notes.h"
	 * phase 1 fills graft
	 */
			 * when all their children have been emitted thereby
	}

	while (nr--) {
	}
	}
		clear_author_date_slab(&author_date);
}
		it->value = strbuf_detach(&buf, &it->len);
		const char *eol = strchrnul(line, '\n');
		*stack = top->next;
	int i;
		bad = find_invalid_utf8(buf->buf + pos, buf->len - pos);
	 * There should be one and only one merge base, when we found
		free(extra->value);
		goto out;
	if (commit->graph_pos != COMMIT_NOT_FROM_GRAPH)


	init_indegree_slab(&indegree);
			die("expected commit for %s, got %s",

			in_old_conflicts_block = 1;
	if (memcmp(buf, "author", 6))
	size_t ident_len;

		struct commit *new_parent;
		pp = commit_list_append(list->item, pp);
{

		} while (--bytes);
		pos += 2;
		goto fail_exit; /* malformed date */
	obj = parse_object(the_repository, &oid);
	return extra;
	}
	return ret;
		if (type != OBJ_COMMIT)
		const char *sig = NULL;

		struct commit_list *parents;
{
void parse_commit_or_die(struct commit *item)

{
{
		goto out;
	if (!buffer)
		}
	int i, ret;
		min_val = max_codepoint[bytes-1] + 1;
}
	/*

}

		return 0;

{
			       int use_commit_graph)
	}
		it = xcalloc(1, sizeof(*it));

					struct commit_list **next)
	argv_array_pushf(&hook_env, "GIT_INDEX_FILE=%s", index_file);
		/* Surrogates are only for UTF-16 and cannot be encoded in UTF-8. */
}

		if (len < bytes)
		bad_offset = offset-1;
	while (bol < cutoff) {
	struct commit_list *new_list = xmalloc(sizeof(struct commit_list));

 * order to find where to put a new Signed-off-by: line.  Ignored are
	return ret;
{
		const char *eol = strchrnul(bol, '\n');
	}
		pptr = &commit_list_insert(new_parent, pptr)->next;
		else if (starts_with(line, gpg_sig_header) &&
	char *full_refname;
	if (type != OBJ_COMMIT) {
		FREE_AND_NULL(v->buffer);
	strbuf_release(&payload);
	size_t bol = 0;
		 * Count how many more high bits set: that's how
struct commit_list *commit_list_insert(struct commit *item, struct commit_list **list_p)
	bufptr += tree_entry_len + 1; /* "tree " + "hex sha1" + "\n" */
	default: /* REV_SORT_IN_GRAPH_ORDER */
	r->parsed_objects->commit_graft_prepared = 1;
	const char *line, *next, *eof, *eob;
	const char *line = msg;
	}
		return -1;

		if (codepoint >= 0xfdd0 && codepoint <= 0xfdef)


 *     struct commit_list **next = &list;
	prepare_commit_graft(r);
{
		unsigned char c;
 * support "git commit -v", we truncate at cut lines.
			       struct commit *item,
	return boc ? len - boc : len - cutoff;
 * empty commit_list, and is updated to point to the "next" field of
{
		struct commit_list *parents = next->item->parents;
unsigned commit_list_count(const struct commit_list *l)
};
	if (it)
			 "Turn this message off by running\n"

		if (*(indegree_slab_at(&indegree, commit)) == 1)
{
			for (i = 1; i < GIT_HASH_NALGOS; i++) {
int unregister_shallow(const struct object_id *oid)
	len = parse_signature(buf, size);
/*
}
			if (*pi)
{
		return 1;
	/* And add the comment */
int compare_commits_by_commit_date(const void *a_, const void *b_, void *unused)
	"gpgsig",
	if (graft) {

	commit = lookup_commit(the_repository, oid);
		ret = repo_read_object_file(r, &commit->object.oid, &type, &size);
void set_merge_remote_desc(struct commit *commit,
		if (!next_line)
	int pos = commit_graft_pos(r, graft->oid.hash);
	memset(&revs, 0, sizeof(revs));
		return 0;
	*subject = p;
		pool->buffer_slab, commit);
		free_commit_list(item->parents);
			if (*line == '\n')
	while (extra) {
{
	buf = read_object_file(&desc->obj->oid, &type, &size);
		*tail = it;
				       NULL, 0);
}
{
	va_end(args);
	pptr = list;
	return 0;
	if (split_ident_line(&ident, ident_line, ident_len) ||
		return 1;
{
{
	if (sign_buffer(buf, &sig, keyid)) {
#include "revision.h"

	/* use date as a heuristic when generations are equal */
			*sizep = size;
	if (!keyid || !*keyid)
		return 0;
		/* Reject codepoints that are out of range for the sequence length. */
		advise(_("Support for <GIT_DIR>/info/grafts is deprecated\n"
#include "repository.h"
	unuse_commit_buffer(commit, buffer);
		inspos = buf->len;

	int pos;
	*(author_date_slab_at(author_date, commit)) = date;
{
 *     struct commit_list *list;
		if (!copypos) {
}
	if (sort_order == REV_SORT_BY_AUTHOR_DATE)
		strbuf_insertstr(buf, inspos++, " ");
				next = tail;
		commit++;
		*sizep = v->size;
	if (memchr(msg, '\0', msg_len))
{
	struct prio_queue queue;
			continue;
{
 */

	if (!editor_is_used)
int repo_parse_commit_internal(struct repository *r,
	NULL,
	return *merge_desc_slab_at(&merge_desc_slab, commit);
{
{
	return sha1_pos(sha1, r->parsed_objects->grafts,
		if (buf[bol] == comment_line_char || buf[bol] == '\n') {

{
			if ((*buf++ & 0xc0) != 0x80)
	result = write_object_file(buffer.buf, buffer.len, commit_type, ret);
}
			   const char *name, struct object *obj)

	 *
			continue;
		return 1;

			in_signature = 0;

	 *
		return NULL;
	}
		extra = extra->next;
	return ((const struct commit_list *)a)->next;
		goto fail_exit; /* no author line */
	memset(&queue, '\0', sizeof(queue));
	strbuf_release(&sig);
	 */
	struct commit *c = lookup_commit_reference(the_repository, oid);

	return 0;
	struct indegree_slab indegree;
	r->parsed_objects->grafts_nr++;
void prepare_commit_graft(struct repository *r)
		next = next ? next + 1 : eob;
	struct strbuf buf = STRBUF_INIT;
	    parse_commit(commit))
		/*
	revs->commit[revs->nr++] = commit;
	 * verify-signed-buffer here for now...
void free_commit_buffer_slab(struct buffer_slab *bs)
	return new_list;
	va_list args;
	return object_as_type(r, obj, OBJ_COMMIT, 0);
	encoding_is_utf8 = is_encoding_utf8(git_commit_encoding);
	desc = merge_remote_util(parent);
	else
	if (!v) {

			c <<= 1;

	timestamp_t b_date = ((const struct commit_list *)b)->item->date;
	return ret;
struct commit *lookup_commit_reference_gently(struct repository *r,
	return ((len == 4 && !memcmp(field, "tree", 4)) ||
	struct author_date_slab author_date;
			strbuf_add(payload, line, next - line);
	struct commit_list **pp = &head;
	else if (a->generation > b->generation)




		const char *bol = sig.buf + copypos;
				     oid_to_hex(&item->object.oid));
	return eol - p;
 */
	while ((p = *pp) != NULL) {
	 * tips are nodes not reachable from any other node in the list
		      "allegedly by %s."), hex, signature_check.signer);
	if (!author)
		} else if (in_old_conflicts_block && buf[bol] == '\t') {
{
	struct commit_extra_header *extra = NULL, **tail = &extra;
	const char *line, *tail;
	for (next = orig; next; next = next->next) {
			commit_graft_sha1_access);
	is_repository_shallow(r);
		tail = &it->next;
		parents = parents->next;
	}
{
		/* The format is just "Commit Parent1 Parent2 ...\n" */
static inline void set_commit_tree(struct commit *c, struct tree *t)


	return 0;
		 */

		signature.len, sigc);
{
			 "\n"
	if (!obj)
{
	if (pos < 0)
	/*
		int len = (eol - bol) + !!*eol;
	int alloc;
	new_commit->next = NULL;
{
	if (is_null_oid(oid))
	if (a_date < b_date)
		}
	saw_signature = 0;

		clear_commit_marks_1(&list, pop_commit(&list), mark);
	int ret;
}
	while (*exclude) {
	    (commit->object.flags & TMP_MARK) ||
{
		if (!ret)
	timestamp_t b_date = *(author_date_slab_at(author_date, b));
	desc->obj = obj;
		free((void *)buffer);
				boc = bol;
			 "and will be removed in a future Git version.\n"
}
		return commit->maybe_tree;
		}
	line = buffer;
	if (!eoh)
	set_commit_tree(c, NULL);
	}

{
{
	const char *line = buf->buf;
	while (list) {
	int in_signature, saw_signature = -1;
	graft = lookup_commit_graft(r, &item->object.oid);
 *     next = commit_list_append(c1, next);
}

	if (!desc || !desc->obj)
define_commit_slab(author_date_slab, timestamp_t);
out:
struct buffer_slab *allocate_commit_buffer_slab(void)
	return ret;

			sizeof(*r->parsed_objects->grafts));
	}
	const char *dateptr;
		return 0;
			     oid_to_hex(&item->object.oid));
	}

{
			if (it)
	struct commit_list *top = *stack;
		return;
	 * different order of parents will be a _different_ changeset even
		strbuf_addf(&buffer, "encoding %s\n", git_commit_encoding);
	if (buf >= tail)
	return 0;

		if (c < 0x80)
{
	*list = NULL;
		die("No such ref: '%s'", refname);
		 * clear it out in preparation for us re-parsing (we'll hit the
		if (register_commit_graft(r, graft, 1))
struct merge_remote_desc *merge_remote_util(struct commit *commit)
		    get_oid_hex(bufptr + 7, &parent) ||
	item->date = parse_commit_date(bufptr, tail);
			return bad_offset;
struct commit *get_fork_point(const char *refname, struct commit *commit)


	v->buffer = NULL;
 * Returns the number of bytes from the tail to ignore, to be fed as
}
/* count number of children that have not been emitted */
#include "utf8.h"
		int bad;
			pptr = &commit_list_insert(new_parent, pptr)->next;

	 * Let the hook know that no editor will be launched.
		goto fail_exit; /* malformed "author" line */
{
			return 1;
}
}
		struct commit *parent = pop_commit(&parents);
}
		 * same error, but that's good, since it lets our caller know
}
	commit = lookup_commit_reference(the_repository, &oid);
{
	date = parse_timestamp(ident.date_begin, &date_end, 10);
		strbuf_release(&sig);
{
			boc = 0;
	}

	 */
{
			      const struct commit *commit,

	if (buf + 6 >= tail)
}
}
		return error("a NUL byte in commit log message not allowed.");
	if (!tree)
struct commit *lookup_commit_reference_by_name(const char *name)
		printf(_("Commit %s has a good GPG signature by %s\n"),
		return -1;
	free(buf);
	if (check_graph)
	return saw_signature;
}
}
{

			continue;
	return ret;
	 * public key of the signer of the tag he is merging, while a
	signature_check_clear(&signature_check);
	free(bs);
			free(r->parsed_objects->grafts[pos]);
	int in_signature = 0;
	return 0;
			return bad_offset;
	if (!bases || bases->next)
	return 0;
		} else if (starts_with(buf + bol, "Conflicts:\n")) {

	if (date_end != ident.date_end)
		list = list->next;
	/* Not having i18n.commitencoding is the same as having utf-8 */
		struct commit *parent = parents->item;
}
 * the second parameter to append_signoff().
	return extra;
	((struct commit_list *)a)->next = next;
{

};
}
		return -1;
		free(extra->key);

struct commit_list * commit_list_insert_by_date(struct commit *item, struct commit_list **list)

{
		if (ignore_dups)
	switch (signature_check.result) {
{
static void clear_commit_marks_1(struct commit_list **plist,
	struct commit_list *next, *orig = *list;

 * If it isn't, it assumes any non-utf8 characters are Latin1,

	struct rev_collect *revs = cbdata;
/*
			 * parents are only enqueued for emission
	unsigned int initial : 1;
int commit_tree(const char *msg, size_t msg_len, const struct object_id *tree,
		struct commit_list *parents, struct object_id *ret,
 out:
	strbuf_addstr(buffer, extra->key);
		return NULL;
{
	int ret;
			r->parsed_objects->grafts[pos] = graft;
