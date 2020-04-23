				       oid_to_hex(&commit->object.oid));
	int e = 0;
	len_b = strlen(name_b);
				 * Getting here means we have a commit which
		buf = anonymize_blob(&size);
			die("Tag %s points nowhere?", e->name);
	struct ident_split split;
	return strbuf_detach(&out, len);
#include "log-tree.h"
		return;
						  anonymize_oid(&spec->oid) :
			 * because the diff is calculated based on the prior
	show_progress();
{
		else {
			printf("reset %s\nfrom :%d\n\n", name, mark
			continue;
		if (!tag)
	tagger = memmem(buf, message ? message - buf : size, "\ntagger ", 8);
		usage_with_options (fast_export_usage, options);
			string_list_append(&extra_refs, full_name)->util = commit;
		case DIFF_STATUS_TYPE_CHANGED:
		signed_tag_mode = WARN_STRIP;
			}
			/* Ignore this tag altogether */
		int mark;
				break;
	*len = ret->anon_len;
{
	}
	struct object_array commits = OBJECT_ARRAY_INIT;
	revs.diffopt.flags.recursive = 1;

		if (check_object_signature(the_repository, oid, buf, size,
		commit = lookup_commit(the_repository, &oid);
				printf("M %06o %s ", spec->mode,
		if (!strcasecmp(arg, "abort"))
		len = split.mail_end - split.name_begin;


static int depth_first(const void *a_, const void *b_)
		const char *signature = strstr(message,
		message += 2;

/*
static inline uint32_t ptr_to_mark(void * mark)
		return (struct commit *)tag;
static void show_progress(void)
			return;
{
	else
			string_list_insert(changed, spec->path);
	    (get_object_mark(&commit->parents->item->object) != 0 ||

		default:
		}
			oid_to_hex(&tag->object.oid));
	if (mark_tags) {
		"refs/remotes/",
	return strbuf_detach(&out, NULL);
		while (tag && tag->object.type == OBJ_TAG) {
	add_decoration(&idnums, object, mark_to_ptr(mark));
	struct object *object;
			char *private;
				continue;
static struct refspec refspecs = REFSPEC_INIT_FETCH;


			string_list_insert(changed, spec->path);
	strbuf_addf(&out, "anonymous blob %d", counter++);
			    "%s; use --reencode=[yes|no] to handle it",
		if (!commit) {
				tagged_mark = get_object_mark(tagged);
static struct string_list extra_refs = STRING_LIST_INIT_NODUP;
		if (mark)
			string_list_append(&tag_refs, full_name)->util = tag;
		free(buf);
				ospec->path ? ospec->path : "none",
#include "utf8.h"
			break;
		if (!mark && !reference_excluded_commits)
		if (dwim_ref(e->name, strlen(e->name), &oid, &full_name) != 1)
	printf("%.*s%sdata %d\n%.*s\n",
	init_revision_sources(&revision_sources);



			|| *mark_end != ' ' || get_oid_hex(mark_end + 1, &oid))
	parse_commit_or_die(commit);
		message_size = strlen(message);


	/* we handle encodings */
	skip_prefix(name, "refs/tags/", &name);
			die("corrupt mark line: %s", line);
	int i;
		"refs/tags/",
			putchar('\n');
	struct option options[] = {

	mark_next_object(&commit->object);
	int i;
	}
	static int counter;
{
	while ((commit = get_revision(&revs))) {
	else if (!strcmp(arg, "warn-strip"))
	/*
{
	       (int)(tagger_end - tagger), tagger,
		int mark = get_object_mark(obj);
	} else {
			 * Links refer to objects in another repositories;
		OPT_STRING(0, "import-marks", &import_filename, N_("file"),
			 N_("Fake a tagger when tags lack one")),
			break;

	author++;
	}
		signed_tag_mode = STRIP;
	 * O(N^2).  Compared to a history walk and diffing trees, this is
}
	struct string_list refspecs_list = STRING_LIST_INIT_NODUP;
	return 0;
	 * We also leave "master" as a special case, since it does not reveal
	enum object_type type;

			       );
			case WARN:
	fclose(f);
	struct commit *commit;
	f = xfopen(input_file, "r");
			 */
			}
	struct anonymized_entry key, *ret;
	}
	strbuf_reset(&anon);
	FILE *f;
		break;
				printf("M %06o :%d ", spec->mode,
				printf("%c ", q->queue[i]->status);
	else if (!strcmp(arg, "rewrite"))
	which_buffer %= ARRAY_SIZE(buffers);
					printf("reset %s\nfrom %s\n\n",
		}
	if (tagged->type == OBJ_TAG) {
	encoding = find_encoding(committer_end, message);
	char *buf;
	if (!eaten)
		object = (struct object *)lookup_blob(the_repository, oid);
		case REENCODE_NO:
		commit = (struct commit *)object_array_pop(commits);
static int parse_opt_reencode_mode(const struct option *opt,
			     N_("Dump marks to this file")),
	else if (!strcmp(arg, "strip"))
				if (!p) {
				 * it.
				continue;
	while (tagged->type == OBJ_TAG) {
	if (e)
{
		if (e->item->type != OBJ_TAG)
			die("tag %s tags unexported object; use "
	printf("commit %s\nmark :%"PRIu32"\n", refname, last_idnum);
			if (tagged->type == OBJ_TAG && !mark_tags) {

		struct object *object;
	mark_next_object(object);
			continue;
static const char *anonymize_refname(const char *refname)
		printf("reset %s\n", refname);
 * lookups for "a" will yield the same value.
	a = container_of(eptr, const struct anonymized_entry, hash);
	unsigned long size;

	}
	const char *orig;
	const char *needle = "\nencoding ";
			}
		printf("original-oid %s\n", oid_to_hex(oid));
{
	switch (e->item->type) {
		OPT_CALLBACK(0, "reencode", &reencode_mode, N_("mode"),
	if (unset || !strcmp(arg, "abort"))
			handle_commit(commit, &revs, &paths_of_changed_objects);
}
		signed_tag_mode = VERBATIM;
			refspec_append(&refspecs, refspecs_list.items[i].string);
				    oid_to_hex(&tag->object.oid));
		error("Unable to write marks file %s.", file);
static struct hashmap idents;
		return error("Unknown tag-of-filtered mode: %s", arg);
			die("corrupt mark line: %s", line);
		printf("from %s\n", oid_to_hex(&tagged->oid));
	 * Handle files below a directory first, in case they are all deleted
{
{

	       tagger == tagger_end ? "" : "\n",
	revs.topo_order = 1;


			else {
		anonymize_ident_line(&author, &author_end);
			handle_tag(name, (struct tag *)object);
	}

}
	static struct strbuf buffers[] = { STRBUF_INIT, STRBUF_INIT };
		OPT_STRING(0, "import-marks-if-exists",
}
			parse_object(the_repository, &tag->object.oid);
 * Copyright (C) 2007 Johannes E. Schindelin
		}
		object = parse_object_buffer(the_repository, oid, type,
	static const char *prefixes[] = {
}
static int reference_excluded_commits;

	if (import_filename && revs.prune_data.nr)


	if (need_quote)
	return (a->status == 'R') - (b->status == 'R');
		message += 2;
	committer_end = strchrnul(committer, '\n');
struct anonymized_entry {
			    "--tag-of-filtered-object=<mode> to handle it",
	/*
		tagger_end = strchrnul(tagger, '\n');
			}
		strbuf_addch(out, ' ');
	argc = parse_options(argc, argv, prefix, options, fast_export_usage,
static int mark_tags;
	static uint32_t counter = 1; /* avoid null oid */
	int tagged_mark;
		if (!mark || mark_end == line + 1
{
				    ospec->mode == spec->mode)
	return anon.buf;

			if (private) {
	       (int)(author_end - author), author,
		BUG("malformed line fed to anonymize_ident_line: %.*s",
	     *import_filename = NULL,
	strbuf_addf(&out, "User %d <user%d@example.com>", counter, counter);
	while (fgets(line, sizeof(line), f)) {
}

		return;
		case OBJ_COMMIT:
	log_tree_diff_flush(rev);
static void handle_tail(struct object_array *commits, struct rev_info *revs,
		OPT_BOOL(0, "no-data", &no_data, N_("Skip output of blob data")),
	}
		     needle, strlen(needle));
	object = lookup_object(the_repository, oid);
			    encoding, oid_to_hex(&commit->object.oid));
			break;
	if (!tagged_mark) {

			case SIGNED_TAG_ABORT:

#include "diffcore.h"
					/* delete the ref */

				 * just means deletion of the ref.

		parse_commit_or_die(commit->parents->item);
		       name, oid_to_hex(&null_oid));
int cmd_fast_export(int argc, const char **argv, const char *prefix)
static enum { SIGNED_TAG_ABORT, VERBATIM, WARN, WARN_STRIP, STRIP } signed_tag_mode = SIGNED_TAG_ABORT;
	if (prepare_revision_walk(&revs))
	if (!buf)

			die("Encountered commit-specific encoding %s in commit "

		struct diff_filespec *ospec = q->queue[i]->one;
static int show_original_ids;
					return;
static void export_marks(char *file)
				     const char *arg, int unset)
		commit = get_commit(e, full_name);
static char *anonymize_commit_message(const char *old)
		handle_commit(commit, revs, paths_of_changed_objects);

	const char *end_of_header;
	if (tagged_mark)
			     N_("Use the done feature to terminate the stream")),

				/*

	name_a = a->one ? a->one->path : a->two->path;
}
		if (deco->base && deco->base->type == 1) {
	char *reencoded = NULL;
				die(_("Error: Cannot export nested tags unless --mark-tags is specified."));
		 * Make sure this ref gets properly updated eventually, whether
	enum object_type type;
#include "builtin.h"
		return error("Unknown signed-tags mode: %s", arg);
#include "config.h"
#include "remote.h"
		case DIFF_STATUS_ADDED:
		return;
	f = fopen_for_writing(file);
static enum { REENCODE_ABORT, REENCODE_YES, REENCODE_NO } reencode_mode = REENCODE_ABORT;
		    (int)(*end - *beg), *beg);
				name = anonymize_refname(name);
	const char *anon;
	if (anonymize) {
	else {
		const char *end_of_component = strchrnul(path, '/');
				      split.name_begin, &len);
		printf("encoding %s\n", encoding);
			return error("Unknown reencoding mode: %s", arg);

#include "object.h"
		tag_of_filtered_mode = TAG_FILTERING_ABORT;
	refspec_clear(&refspecs);
			mark = ptr_to_mark(deco->decoration);
		export_marks(export_filename);
		warning("Omitting tag %s,\nsince tags of trees (or tags of tags of trees, etc.) are not supported.",
 *
				 * in its history to be deleted, which basically
};

{
{
static struct commit *get_commit(struct rev_cmdline_entry *e, char *full_name)
	}
		}
}
		die("could not find author in commit %s",
				const struct hashmap_entry *eptr,

			continue;
	bol += strlen(needle);
		printf("mark :%"PRIu32"\n", last_idnum);
	struct strbuf out = STRBUF_INIT;
 */
 * the easy way out for now, and just generate arbitrary content.
				 * referencing excluded commits, set the ref
	 */
	strbuf_add(out, *beg, end_of_header - *beg);


/*
			show_progress();
	N_("git fast-export [rev-list-opts]"),
				if (!reference_excluded_commits) {
}
 * We do not even bother to cache commit messages, as they are unlikely
		size_t len;
	if (import_filename)
								      &spec->oid);
			/* only commits */
{
	rev->diffopt.output_format = saved_output_format;
		OPT_CALLBACK(0, "signed-tags", &signed_tag_mode, N_("mode"),
{
	const char *tagger, *tagger_end, *message;
	return strbuf_detach(&out, len);
	else if (!strcmp(arg, "drop"))
	int i;

		return NULL;
			 N_("Output full tree for each commit")),
	};
	hashmap_entry_init(&key.hash, memhash(orig, *len));
{
		if (last_idnum < mark)

			}
}
	struct hashmap_entry hash;

				 * was excluded by a negative refspec (e.g.
	const struct diff_filepair *b = *((const struct diff_filepair **)b_);
	    !full_tree) {
		strbuf_add(out, split.date_begin, split.tz_end - split.date_begin);
				    "--signed-tags=<mode> to handle it",
	free(buf);
		case REWRITE:
	if (cmp)
	 * appear in the output before it is renamed (e.g., when a file
	if (tagged->type == OBJ_TREE) {

			 * If a change in the file corresponding to ospec->path
	struct strbuf out = STRBUF_INIT;
			tagger = "";
			break;
}
 * Basically keep a cache of X->Y so that we can repeatedly replace
	return 0;
		case DROP:
				refspec->dst, oid_to_hex(&null_oid));
	struct commit *commit;
			     parse_opt_reencode_mode),

			static struct hashmap tags;

	for (parent = commit->parents; parent; parent = parent->next)
{
	static int counter;
	 * so that tags remain tags and so forth.
static void anonymize_path(struct strbuf *out, const char *path,

	};
	for (i = 0; i < q->nr; i++) {
 * We anonymize each component of a path individually,
	}
			     N_("Apply refspec to exported refs")),
	/* handle tag->tagged having been filtered out due to paths specified */
	tagged = tag->tagged;
		ret->anon = generate(orig, len);
				tagged_mark = get_object_mark(&p->object);
{
		    oid_to_hex(&commit->object.oid));
	cmp = memcmp(name_a, name_b, len);

		case DIFF_STATUS_MODIFIED:
	if (full_tree)
	 * anything interesting.
	}
	}
		import_marks(import_filename, 0);
		if (*path)
				}
			 * contents, not the current contents.  So, declare a
}
static inline void mark_object(struct object *object, uint32_t mark)
 * Ideally we would want some transformation of the blob data here
		default: /* OBJ_TAG (nested tags) is already handled */
		if (p->parents && p->parents->next)
#include "refspec.h"
				/* set ref to commit using oid, not mark */
			     parse_opt_signed_tag_mode),
	void *decoration = lookup_decoration(&idnums, object);
	       (int)message_size, (int)message_size, message ? message : "");
			die("oid mismatch in blob %s", oid_to_hex(oid));
	struct commit *p;
	const char *name_a, *name_b;
#include "decorate.h"
		switch (q->queue[i]->status) {
	}
			printf(":%d\n", mark);
				 * fast-export ^master master).  If we are
 */
static int anonymize;

		struct rev_cmdline_entry *e = info->rev + i;
	if (!bol)
	if ((++counter % progress) == 0)
			}
		printf("reset %s\nfrom %s\n\n",
#include "object-store.h"
		hashmap_init(map, anonymized_entry_cmp, NULL, 0);
static int anonymized_entry_cmp(const void *unused_cmp_data,
	*beg = out->buf;
		struct object_id oid;

			     N_("Import marks from this file")),
	} else {
		case DIFF_STATUS_COPIED:
#include "blob.h"
			continue;
		if (!commit)
	unsigned char *out = xcalloc(hashsz, 1);
	git_config(git_default_config, NULL);
	else if (!strcmp(arg, "warn"))
	}
	}
				q->queue[i]->status,
		for (i = 0; i < refspecs_list.nr; i++)
 */
				if (oideq(&ospec->oid, &spec->oid) &&
#include "diff.h"
 * is farmed out to the generate function.
		type = oid_object_info(the_repository, &oid, NULL);
		/* handle nested tags */
		struct diff_filespec *spec = q->queue[i]->two;
			 * copy or rename only if there was no change observed.
		deco++;
	static struct hashmap objs;
		struct object *object = extras->items[i].util;

}
	else if (strchr(path, ' '))
	for (i = 0; i < idnums.size; i++) {
		if (has_unshown_parent(commit)) {
	} else {
{
static int no_data;
	string_list_sort(&extra_refs);
		struct object *obj = &p->item->object;
}
/*
	int len_a, len_b, len;
	/* strcmp will sort 'd' before 'd/e', we want 'd/e' before 'd' */
	if (show_original_ids)
		case TAG_FILTERING_ABORT:
	e |= ferror(f);
	}

 * we already handle blob content caching with marks.
}
static void export_blob(const struct object_id *oid)
			continue;
		case DIFF_STATUS_RENAMED:
	if (!tagger) {
			PARSE_OPT_KEEP_ARGV0 | PARSE_OPT_KEEP_UNKNOWN);
	if (anonymize) {
				printf("reset %s\nfrom %s\n\n",
		if (line[0] != ':' || !line_end)
}
}
	buf = read_object_file(&tag->object.oid, &type, &size);
	}
static inline void *mark_to_ptr(uint32_t mark)
			putchar('\n');
 * There's no need to cache this result with anonymize_mem, since
#include "cache.h"
	if (!author)
		return NULL;
	default:
 * the same anonymized string with another. The actual generation
		OPT_END()

	struct strbuf out = STRBUF_INIT;
		anonymize_path(&anon, path, &paths, anonymize_path_component);


	if (use_done_feature)
/*
	return 0;
}
	lastimportid = last_idnum;
		die("could not find committer in commit %s",
	key.orig_len = *len;
		printf("original-oid %s\n", oid_to_hex(&commit->object.oid));
		OPT_BOOL(0, "mark-tags", &mark_tags,
static const char *find_encoding(const char *begin, const char *end)
		size_t len = end_of_component - path;
{


	end_of_header = strchr(*beg, ' ');

		static struct hashmap paths;
static void handle_commit(struct commit *commit, struct rev_info *rev,
			break;
}
			anonymize_ident_line(&tagger, &tagger_end);
				e->name,
 */
	refname = *revision_sources_at(&revision_sources, commit);

}

{
			message = anonymize_mem(&tags, anonymize_tag,
				struct object *object = lookup_object(the_repository,
		ident = anonymize_mem(&idents, anonymize_ident,
	if (export_filename && lastimportid != last_idnum)
	committer = strstr(author_end, "\ncommitter ");
		die_errno("Unable to open marks file %s for writing.", file);
		if (type != OBJ_COMMIT)
			tag = (struct tag *)tag->tagged;
			add_object_array(&commit->object, NULL, commits);
			}
		if (!buf)
#include "refs.h"
	if (!strcmp(refname, "refs/heads/master"))
}
	 * Move 'R'ename entries last so that all references of the file
	}
			break;
static int use_done_feature;
}
		const char *c = anonymize_mem(map, generate, path, &len);

		printf("progress %d objects\n", counter);
			die("could not read blob %s", oid_to_hex(oid));
		return;
			die("object not found: %s", oid_to_hex(&oid));
			return;
		OPT_BOOL(0, "fake-missing-tagger", &fake_missing_tagger,
	handle_tags_and_duplicates(&tag_refs);
	struct string_list *changed = data;
	size_t message_size = 0;
			break;

}
	if (!decoration)
}
		name = anonymize_refname(name);
	strbuf_addf(&out, "tag message %d", counter++);
	     reference_excluded_commits) &&
	if (use_done_feature)
	if (message)
{
		break;
		else
			     N_("select handling of signed tags"),

 * that is unreversible, but would still be the same size and have
			strbuf_addch(out, *path++);
	if (argc == 1)
}

		if (*refspec->src)
		break;

		strbuf_add(out, ident, len);
		static struct strbuf anon = STRBUF_INIT;
		ret = xmalloc(sizeof(*ret));
			return NULL;
	else if (!strcmp(arg, "verbatim") || !strcmp(arg, "ignore"))

			print_path(spec->path);
		return 0;
					continue;
		mark_next_object(&tag->object);
 * to be repeated verbatim, and it is not that interesting when they are.
				 * it has been filtered to nothing.  Delete
	switch (git_parse_maybe_bool(arg)) {
		char *full_name;
	printf("data %"PRIuMAX"\n", (uintmax_t)size);
 * requirements there are probably mutually exclusive, so let's take
	repo_init_revisions(the_repository, &revs, prefix);
			free(buf);
		if (!p->parents)
					       name, oid_to_hex(&null_oid));
		die("could not read tag %s", oid_to_hex(&tag->object.oid));
		 * through a commit or manually at the end.

				/* fallthru */
	for (i = 0; i < refspecs.nr; i++) {
		printf("%s", path);
	if (unset || !strcmp(arg, "abort"))
		diff_tree_oid(get_commit_tree_oid(commit->parents->item),
		print_path_1(path);
				oid_to_hex(&deco->base->oid)) < 0) {
	anonymize_path(&anon, refname, &refs, anonymize_ref_component);
		reencode_mode = REENCODE_ABORT;
	uint32_t lastimportid;
#include "commit-slab.h"
		}

					  const char *arg, int unset)
	case 1:
{
{
		usage_with_options (fast_export_usage, options);
	 */
	const char *encoding, *message;
	cmp = len_b - len_a;
		switch(commit->object.type) {
static int fake_missing_tagger;
		reencoded = anonymize_commit_message(message);
	}
	revs.diffopt.format_callback = show_filemodify;
			commit = rewrite_commit((struct commit *)object);
			    N_("Label tags with mark ids")),
			tagger = "tagger Unspecified Tagger "
	struct strbuf *out;
			private = apply_refspecs(&refspecs, full_name);
				spec->path ? spec->path : "none");
			    oid_to_hex(&tag->object.oid));
		if (signature)

	       (int)(committer_end - committer), committer);
			/* create refs pointing to already seen commits */
{
	b = container_of(entry_or_key, const struct anonymized_entry, hash);
	case 0:
				 */


{
	static struct strbuf anon = STRBUF_INIT;
		case OBJ_COMMIT:
		return cmp;
}
	const struct diff_filepair *a = *((const struct diff_filepair **)a_);
	string_list_remove(&extra_refs, refname, 0);
	if (import_filename && import_filename_if_exists)
		tagger++;
#include "string-list.h"
	return bol;
						message, &message_size);
	return strbuf_detach(&out, len);
	int i;
	NULL
}
/*

		 */
		object->flags |= SHOWN;
	if (is_null_oid(oid))
{
	static unsigned which_buffer;

					       "\n-----BEGIN PGP SIGNATURE-----\n");
				full_name = private;
				 const void *orig, size_t *len)
			reencoded = reencode_string(message, "UTF-8", encoding);
		struct object_id oid;
		struct commit *commit;

 *
	free(reencoded);
		"refs/heads/",
		die(_("Cannot pass both --import-marks and --import-marks-if-exists"));
			    struct diff_options *options, void *data)
static void *anonymize_ref_component(const void *old, size_t *len)

	strbuf_addf(&out, "ref%d", counter++);

	get_tags_and_duplicates(&revs.cmdline);
			break;
	len = (len_a < len_b) ? len_a : len_b;
					break;
		if (p->object.flags & UNINTERESTING)
			break;
		tagged = ((struct tag *)tagged)->tagged;
	strbuf_reset(out);
	put_be32(out + hashsz - 4, counter++);
			} else if (tagged->type == OBJ_COMMIT) {
				type_name(e->item->type));
			 &reference_excluded_commits, N_("Reference parents which are not in fast-export stream by object id")),
		case OBJ_TAG:
	return (void *)(uintptr_t)mark;
		if (e->flags & UNINTERESTING)


	}
			printf("D ");
	counter++;

	revs.diffopt.format_callback_data = &paths_of_changed_objects;
	name_b = b->one ? b->one->path : b->two->path;
 */
			    e = 1;

	unsigned int i;
	}
			export_blob(&diff_queued_diff.queue[i]->two->oid);
		    oid_to_hex(&commit->object.oid));
	int i;
}

	return xstrfmt("subject %d\n\nbody\n", counter++);
		"refs/"
			handle_tail(&commits, &revs, &paths_of_changed_objects);
	bol = memmem(begin, end ? end - begin : strlen(begin),


	for (i = 0; i < ARRAY_SIZE(prefixes); i++) {
#include "revision.h"
	int need_quote = quote_c_style(path, NULL, NULL, 0);
	printf("\n");

		}
			if (no_data || S_ISGITLINK(spec->mode))
		else
			  ? strlen(reencoded) : message
	struct commit_list *parent;
		return 0;
	}
			    break;
{
				"<unspecified-tagger> 0 +0000";
		line_end = strchr(line, '\n');
	 * repo may have enough refs for this to become slow.
		uint32_t mark;

	int cmp;
			printf("%s\n", oid_to_hex(anonymize ?
	}
		OPT_BOOL(0, "use-done-feature", &use_done_feature,
	/*
		memcmp(a->orig, b->orig, a->orig_len);

		printf("from :%d\n", tagged_mark);
#include "tag.h"
	}
	if (!progress)
static void *anonymize_ident(const void *old, size_t *len)
		if (message) {
	else
			case WARN_STRIP:
		printf("original-oid %s\n", oid_to_hex(&tag->object.oid));
	char *export_filename = NULL,
	struct rev_info revs;
		die("revision walk setup failed");
		hashmap_entry_init(&ret->hash, key.hash.hash);
	} else if (encoding) {

		else
				 * Neither this object nor any of its
	if (anonymize) {
			      get_commit_tree_oid(commit), "", &rev->diffopt);
	 * and the directory changes to a file or symlink.
			case STRIP:
		OPT_CALLBACK(0, "tag-of-filtered-object", &tag_of_filtered_mode, N_("mode"),
			if (!commit) {
			   void *(*generate)(const void *, size_t *))
	printf("blob\nmark :%"PRIu32"\n", last_idnum);
	static int counter;
	size_t orig_len;
	uint32_t mark;
	if (no_data)
	 * was copied and renamed in the same commit).
		return (struct commit *)e->item;
			if (anonymize)
	FILE *f;

		struct refspec_item *refspec = &refspecs.items[i];
static int full_tree;

static struct commit *rewrite_commit(struct commit *p)
					free(buf);
 * The paths are cached via anonymize_mem so that repeated
static const char *fast_export_usage[] = {
			   struct hashmap *map,
		ret->orig_len = *len;
		mark_object(object, mark);
		if (!S_ISGITLINK(diff_queued_diff.queue[i]->two->mode))
	int saved_output_format = rev->diffopt.output_format;
		eaten = 0;
			     N_("select handling of tags that tag filtered objects"),
			     &import_filename_if_exists,
	if (!object)
				 */
					oid_to_hex(&tag->object.oid));
				print_path(spec->path);
		struct tag *tag = (struct tag *)e->item;
		strbuf_reset(&anon);
	unuse_commit_buffer(commit, commit_buffer);
		printf("deleteall\n");
	return out;
		}

			switch(signed_tag_mode) {
		refname = anonymize_refname(refname);

		import_marks(import_filename_if_exists, 1);


static void *anonymize_path_component(const void *path, size_t *len)
static void print_path_1(const char *path)

		ret->orig = xstrdup(orig);
	return anonymize_mem(&objs, generate_fake_oid, oid, &len);
		string_list_clear(&refspecs_list, 1);

	revs.rewrite_parents = 1;
	struct strbuf out = STRBUF_INIT;
	show_progress();
				 void *(*generate)(const void *, size_t *),
		switch(tag_of_filtered_mode) {
		printf("done\n");
/*
static int progress;
}

			print_path(spec->path);
			    N_("Show original object ids of blobs/commits")),
			/* Queue again, to be handled later */
		if (!*revision_sources_at(&revision_sources, commit))
	object->flags |= SHOWN;
	return strbuf_detach(&out, len);
 * order (and by themselves should not be too revealing).
				type_name(commit->object.type));
				putchar('\n');
				   "", &rev->diffopt);
{
				const void *unused_keydata)
		i++;
			break;
						  anonymize_oid(&obj->oid) :

			}
static struct string_list tag_refs = STRING_LIST_INIT_NODUP;
			continue;
		return cmp;
	for (i = 0, p = commit->parents; p; p = p->next) {
		OPT_STRING(0, "export-marks", &export_filename, N_("file"),
		return;
		print_path_1(anon.buf);
static struct decoration idnums;
	struct commit *commit;
			/*

static int parse_opt_signed_tag_mode(const struct option *opt,
				 * to the exact commit.  Otherwise, the user

	     *import_filename_if_exists = NULL;
	static int counter;
		strbuf_addstr(out, "Malformed Ident <malformed@example.com> 0 -0000");
	size_t anon_len;
 * the same data relationship to other blobs (so that we get the same
				message_size = signature + 1 - message;
		if (anonymize)
	char *bol, *eol;
	struct stat sb;
	/* Trees have no identifier in fast-export output, thus we have no way
	*size = out.len;
				       get_object_mark(object));
#include "parse-options.h"
	       reencoded ? reencoded : message ? message : "");
}
}
static void handle_tag(const char *name, struct tag *tag)
					     size, buf, &eaten);

	const char *refname;
			     parse_opt_tag_of_filtered_mode),
	return 0;
		if (type < 0)
	end_of_header++;
	ret = hashmap_get_entry(map, &key, hash, NULL);
	argc = setup_revisions(argc, argv, &revs, NULL);
		enum object_type type;
	tagged_mark = get_object_mark(tagged);
	}

			return 1;

		die("Could not read blob %s", oid_to_hex(oid));
	}
	message = strstr(committer_end, "\n\n");
	struct strbuf out = STRBUF_INIT;

	out = &buffers[which_buffer++];
			if (!mark) {
		diff_root_tree_oid(get_commit_tree_oid(commit),
		if (has_unshown_parent(commit)) {
	if (!anonymize)
		else
	printf("\n");
		const char *name = extras->items[i].string;
static inline void mark_next_object(struct object *object)

static void anonymize_ident_line(const char **beg, const char **end)
static void *generate_fake_oid(const void *old, size_t *len)
			error("Object %s already has a mark", oid_to_hex(&oid));
	/* handle signed tags */
			 * output the SHA-1 verbatim.
	handle_tags_and_duplicates(&extra_refs);

			 * has been observed, we cannot trust its contents
};
	mark_object(object, ++last_idnum);

			 */
		printf("feature done\n");
static void *anonymize_tag(const void *old, size_t *len)

	case OBJ_COMMIT:
static char *anonymize_blob(unsigned long *size)
	if (size && fwrite(buf, size, 1, stdout) != 1)
					   type_name(type)) < 0)
	       (unsigned)(reencoded
					oid_to_hex(&tag->object.oid));
	strbuf_addf(&out, "path%d", counter++);

static void show_filemodify(struct diff_queue_struct *q,
			warning("Tag points to object of unexpected type %s, skipping.",
		}
static void print_path(const char *path)
	for (;;) {
	}
	if (check_exists && stat(input_file, &sb))
	message = memmem(buf, size, "\n\n", 2);
	if (refspecs_list.nr) {

		if (refspecs.nr) {

static void handle_tags_and_duplicates(struct string_list *extras)
		reencode_mode = REENCODE_YES;
 * delta and packing behavior as the original). But the first and last
	while (commits->nr) {

static void handle_deletes(void)
			strbuf_addstr(&anon, prefixes[i]);
	if (!map->cmpfn)
	}
		}
		OPT_BOOL(0, "anonymize", &anonymize, N_("anonymize output")),
			die("not a commit? can't happen: %s", oid_to_hex(&oid));
			*revision_sources_at(&revision_sources, commit) = full_name;
	}
				/* fallthru */
	return ret->anon;
	printf("%.*s\n%.*s\n",
{
				   const char *arg, int unset)
	static struct hashmap refs;

			/* fallthrough */
	 */

	default:
	if (anonymize) {
	static int counter;
		OPT_BOOL(0, "show-original-ids", &show_original_ids,
	printf("data %u\n%s",
	if (!committer)
			  ? strlen(message) : 0),
			    N_("show progress after <n> objects")),
				 * ancestors touch any relevant paths, so
		struct commit *commit;
	if (!split_ident_line(&split, end_of_header, *end - end_of_header) &&

{
	/* Export the referenced blobs, and remember the marks. */


	if (message) {
#include "commit.h"

			warning("%s: Unexpected object of type %s, skipping.",
		p = p->parents->item;
		OPT_STRING_LIST(0, "refspec", &refspecs_list, N_("refspec"),
	/* skip "committer", "author", "tagger", etc */
	return p;
			  struct string_list *paths_of_changed_objects)
			reencode_mode = REENCODE_ABORT;
 * "git fast-export" builtin command
	}
	author_end = strchrnul(author, '\n');
		case DIFF_STATUS_DELETED:

		switch(reencode_mode) {

 */
	const struct anonymized_entry *a, *b;
				       oid_to_hex(anonymize ?
				       name, oid_to_hex(&null_oid));
	for (i = 0; i < info->nr; i++) {
	len_a = strlen(name_a);
		    !(parent->item->object.flags & UNINTERESTING))
					printf("reset %s\nfrom %s\n\n",
	}
				warning("exporting signed tag %s",
static int parse_opt_tag_of_filtered_mode(const struct option *opt,

		quote_c_style(path, NULL, stdout, 0);
	/*
	return (uint32_t)(uintptr_t)mark;
			     N_("file"),
	}
 * so that paths a/b and a/c will share a common root.
}
	if (!f)
}
	eol = strchrnul(bol, '\n');
		}
	 * to output tags of trees, tags of tags of trees, etc.  Simply omit


		OPT_INTEGER(0, "progress", &progress,
{
			if (fprintf(f, ":%"PRIu32" %s\n", mark,
		case REENCODE_ABORT:
	string_list_clear(paths_of_changed_objects, 0);
		int i;
}
				print_path(ospec->path);

	const char *commit_buffer;
		object = &commit->object;
		}
static int has_unshown_parent(struct commit *commit)
	e |= fclose(f);
		*line_end = '\0';
			if (!string_list_has_string(changed, ospec->path)) {
		if (!(parent->item->object.flags & SHOWN) &&
static void import_marks(char *input_file, int check_exists)
			case VERBATIM:
				free(full_name);
				const struct hashmap_entry *entry_or_key,
	 * just lost in the noise in practice.  However, theoretically a
	if (commit->parents &&

}
	*end = out->buf + out->len;

{
	 * If any of these prefixes is found, we will leave it intact
	if (!commit->parents)
	size_t len = the_hash_algo->rawsz;
			mark = get_object_mark(&commit->object);

		anonymize_ident_line(&committer, &committer_end);
		mark = strtoumax(line + 1, &mark_end, 10);
static void get_tags_and_duplicates(struct rev_cmdline_info *info)



		die_errno("could not write blob '%s'", oid_to_hex(oid));


			} else {

	while (*path) {
			printf("from ");
	 * FIXME: string_list_remove() below for each ref is overall
			printf("merge ");
			last_idnum = mark;
			struct string_list *paths_of_changed_objects)
				printf("reset %s\nfrom %s\n\n", name,
	return 0;
			break;
		if (i == 0)
{
	char line[512];
			continue;
	string_list_remove_duplicates(&extra_refs, 0);
			add_object_array(&commit->object, NULL, &commits);
				string_list_insert(changed, spec->path);
		}
{


	}
	struct decoration_entry *deco = idnums.entries;
	int eaten;
	if (show_original_ids)
	key.orig = orig;

	unsigned long size;
						  &spec->oid));

		OPT_BOOL(0, "reference-excluded-parents",
				/*
	    split.date_begin) {
	else if (import_filename_if_exists)
		ret->anon_len = *len;
	 */
		if (!(p->object.flags & TREESAME))

	tagged = tag->tagged;
	 */
		path = end_of_component;
	struct object *tagged;
	if (unset) {

	if (object && object->flags & SHOWN)
				putchar(' ');
{
		case REENCODE_YES:
}
					       name, oid_to_hex(&null_oid));
	/*
static enum { TAG_FILTERING_ABORT, DROP, REWRITE } tag_of_filtered_mode = TAG_FILTERING_ABORT;
#include "quote.h"
				die("encountered signed tag %s; use "
	struct string_list paths_of_changed_objects = STRING_LIST_INIT_DUP;
 * but keep timestamps intact, as they influence things like traversal
	if (!end_of_header)
	return ptr_to_mark(decoration);

				break;
				 * wants the branch exported but every commit
		signed_tag_mode = WARN;
			/*
	}
		case OBJ_BLOB:
	char *buf;
	else
	static int counter;
		if (fake_missing_tagger)
		}
static const struct object_id *anonymize_oid(const struct object_id *oid)

		switch (object->type) {
static const void *anonymize_mem(struct hashmap *map,
		reencode_mode = REENCODE_NO;

				warning("stripping signature from tag %s",
	int i;
		if (skip_prefix(refname, prefixes[i], &refname)) {

}
{
		const char *ident;
	if (!ret) {
	rev->diffopt.output_format = DIFF_FORMAT_CALLBACK;
	else
		tagger_end = tagger + strlen(tagger);
	revs.sources = &revision_sources;
 * Our strategy here is to anonymize the names and email addresses,
	handle_deletes();
		/*

		signed_tag_mode = SIGNED_TAG_ABORT;
	 */
	committer++;
	for (i = 0; i < diff_queued_diff.nr; i++)
			export_blob(&commit->object.oid);


		}
				}
	if (message) {
			die("Unexpected comparison status '%c' for %s, %s",
		tag_of_filtered_mode = DROP;
{
	for (i = extras->nr - 1; i >= 0; i--) {
		return;
			     N_("select handling of commit messages in an alternate encoding"),
						  &obj->oid));
		OPT_BOOL(0, "full-tree", &full_tree,
{
		printf("\"%s\"", path);
		hashmap_put(map, &ret->hash);
			     N_("Import marks from this file if it exists")),
static int get_object_mark(struct object *object)
	QSORT(q->queue, q->nr, depth_first);
	case OBJ_TAG: {
	if (show_original_ids)
	printf("tag %s\n", name);
		printf("reset %s\nfrom %s\n\n",
		strbuf_add(out, c, len);
	const unsigned hashsz = the_hash_algo->rawsz;
			continue;
				p = rewrite_commit((struct commit *)tagged);
}
	const char *author, *author_end, *committer, *committer_end;
static struct revision_sources revision_sources;
		tag_of_filtered_mode = REWRITE;
	if (cmp)

static uint32_t last_idnum;
{
{
	 * such tags.
		full_tree = 1;
}
	if (argc > 1)
		if (object->flags & SHOWN)
	commit_buffer = get_commit_buffer(commit, NULL);
		return refname;

	struct commit_list *p;
	if (!reencoded && encoding)
	*eol = '\0';
}
		char *line_end, *mark_end;

	static int counter = 0;
				/* tagged->type is either OBJ_BLOB or OBJ_TAG */
	return a->orig_len != b->orig_len ||
	author = strstr(commit_buffer, "\nauthor ");
		buf = read_object_file(oid, &type, &size);
	else
