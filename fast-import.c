		else
	struct object_entry *oe;
		s->shift = marks->shift + 10;
	f->next_avail = avail_tree_table[hc];
	uintmax_t mark;
	} else if (skip_prefix(p, "inline ", &p)) {
		 * at least rawsz bytes within any window it maps.  But
		unsigned pos = sizeof(hdr) - 1;
	/*
				unsigned long size;
		if (parse_mapped_oid_hex(p, &oid, &p))

		c += e->name->str_len + 1;
		e->tree = NULL;
{
		option_rewrite_submodules(arg, &sub_marks_from);
		return -1;
	end_packfile();
		struct tag *t, *prev = NULL;
{

#include "dir.h"
	if (read_ref(b->name, &old_oid))
			duplicate_count += duplicate_count_by_type[i];
		marks = s;
{
		committer = parse_ident(v);
{
		e->tree = new_tree_content(8);
		    e->name->str_len % 2)
		unread_command_buf = 1;
	char *r = mem_pool_alloc(&fi_mem_pool, len);


	}
	unsigned long n = ulong_arg("--cat-blob-fd", fd);
/* All calls must be guarded by find_object() or find_mark() to
	const char *p,
			s.avail_in = n;
	} else {
		 * and dump_branches() will handle ref deletions first, so
	if (!unquote_c_style(&d_uq, d, &endp)) {
		if (!buf || type != OBJ_TREE)
	struct strbuf tmp_file = STRBUF_INIT;
			while (git_deflate(&s, Z_FINISH) == Z_OK)
		release_tree_content_recursive(root->tree);
	const char *p,
		}
}
		/* Register the packfile with core git's machinery. */
	/* Peel one layer. */
	fprintf(rpt, "  commit clock: %" PRIuMAX "\n", b->last_commit);
	free(committer);
{
	if (keep_fd < 0)
		ref_transaction_free(transaction);
}

			"encoding %s\n",
		; /* Don't die - this feature is supported */
			die("Garbage after path in: %s", command_buf.buf);
	return mark;
		/* The above may have reallocated the current tree_content */
	for (b = branch_table[hc]; b; b = b->table_next_branch)
	memcpy(r, s, len);
		e->depth = 0;
#include "object-store.h"
			break;
	running = 1;

		e = t->entries[i];
		struct tag *tg;
};
	pack_size = sizeof(hdr);
	} else {
} whenspec_type;
#else
	char *buf;

		store_object(OBJ_BLOB, &buf, last, oidout, mark);


		/* This new object needs to *not* have the current pack_id. */
	memcpy(path + i, hex_sha1 + j, the_hash_algo->hexsz - j);

			if (tree_content_set(e, slash1 + 1, oid, mode, subtree)) {
		show_stats = 1;
	while (s->shift) {
		if (oe->type != OBJ_BLOB)
			|| *end != ' '
	crc32_begin(pack_file);
	import_marks_file = make_fast_import_path(marks);
		break;
	checkpoint_requested = 1;
		die("Missing space before < in ident string: %s", buf);
		const char *endp;
	}

	}
	if (finalize_object_file(curr_index_name, name.buf))
	char *buf;

	    ref_transaction_update(transaction, b->name, &b->oid, &old_oid,
		"author %s\n"
	/* build the tree and the commit */
	}
	char *buf = NULL;
	if (!skip_prefix(command_buf.buf, "from ", &from))
			}

		hdrlen = encode_in_pack_object_header(hdr, sizeof(hdr),
}
	strbuf_reset(&new_data);
	if (*buf == '<')
	case S_IFGITLINK:

	}
	cat_blob_write("\n", 1);
	struct last_object *last,
static struct string_list sub_marks_to = STRING_LIST_INIT_DUP;
	hashwrite(pack_file, &hdr, sizeof(hdr));
#include "delta.h"
		path[i++] = hex_sha1[j++];
	struct tree_entry *root,
			parse_new_commit(v);
	if (!root->tree)
		inline_data = 1;
				oidcpy(&e->versions[1].oid, oid);
static unsigned long cur_active_branches;

				leaf.tree);
	tree_content_get(root, p, &leaf, 1);

	fputc('\n', rpt);
	if (myoe && myoe->pack_id != MAX_PACK_ID) {
		if (*endp)

 * The amount of additional space required in order to write an object into the
	odb_pack_name(&name, pack_data->hash, "keep");

		die("unknown --date-format argument %s", fmt);
		enum object_type type = oe ? oe->type :
	struct strbuf err = STRBUF_INIT;
			e = p->active_next_branch;

	cat_blob_write(buf, size);
		le = find_object(&root->versions[0].oid);
}
		 * deletion?


	struct tree_content *t,
	parse_mark();
static void truncate_pack(struct hashfile_checkpoint *checkpoint)
		duplicate_count_by_type[OBJ_BLOB]++;
		int saved_errno = errno;
{
	else {
	}
	b = xmalloc(sizeof(struct object_entry_pool)
	blocks = b;
			parse_ls(v, b);
	free((void *)curr_index_name);
"git fast-import [--date-format=<f>] [--max-pack-size=<n>] [--big-file-threshold=<n>] [--depth=<n>] [--active-branches=<n>] [--export-marks=<marks.file>]";
	}
		failure |= error_errno("Unable to write marks file %s",
	}

	e->pack_id = pack_id;
		s = lookup_branch(from);
		if (b->branch_tree.tree) {
	if (object_count) {
	unsigned int i;

			&deltalen, dat->len - the_hash_algo->rawsz);
	xsnprintf(output, sizeof(output), "%s\n", oid_to_hex(&oe->idx.oid));
/* Submodule marks */
	struct branch *table_next_branch;
{


 */

	}
static uintmax_t alloc_count;
		author = parse_ident(v);
	b->num_notes = 0;

	myoe = find_object(oid);


	if (skip_prefix(command_buf.buf, "encoding ", &v)) {
		fclose(pack_edges);
	for (i = 0; t && i < t->entry_count; i++) {
		    "tag %s\n",
#include "csum-file.h"
	int algo;
		/* This _may_ be a note entry, or a subdir containing notes */
	if (!skip_prefix(command_buf.buf, "from ", &from))
	if (!skip_prefix(command_buf.buf, "data ", &data))

	enum object_type type;
		e = e->next;

	for_each_mark(from, 0, insert_mapped_mark, to);

			fprintf(pack_edges, "%s:", new_p->pack_name);

	if (delta) {
		/*
	const char *base;
	case 0755:
		if (hash_algos[algo].format_id == the_hash_algo->format_id)
	const char *tag_name;
		finalize_hashfile(pack_file, cur_pack_oid.hash, 0);
}
	if (delta) {

	t->delta_depth = lo.depth;
	}
	static struct strbuf d_uq = STRBUF_INIT;
	/* Build the table of object IDs. */
	 */
	return 1;
	for (;;) {
	}
}
	unsigned int i;

		return -1;
	struct tag *t;
		inline_data = 1;

		}
			uintmax_t i = idnum >> s->shift;
	unsigned int merge_count;
		alloc_objects(object_entry_alloc);
	/* Determine if we should auto-checkpoint. */

		close_pack_windows(p);
static unsigned int hc_str(const char *s, size_t len)
		hashwrite(pack_file, hdr, hdrlen);
 * Return the first character after the value in *endptr.
		die("Invalid attempt to create duplicate branch: %s", name);
static uintmax_t change_note_fanout(struct tree_entry *root,
	}
#include "mem-pool.h"
	WHENSPEC_NOW
	checkpoint_requested = 0;
static uintmax_t next_mark;
		mark = strtoumax(line + 1, &end, 10);
		|| get_oid_hex(buf + 5, &b->branch_tree.versions[1].oid))
		struct object_entry *oe = find_mark(marks, idnum);
}



	uintmax_t num_notes;
static whenspec_type whenspec = WHENSPEC_RAW;
		cat_blob_write(line.buf, line.len);
static void release_tree_content(struct tree_content *t)
						oid_to_hex(&t->oid));
		e->pack_id = pack_id;
 * an unknown SHA-1 to find_object() or an undefined mark to
	string_list_insert(list, s)->util = ms;
		strbuf_addf(&new_data, "parent %s\n",


{
			struct object_entry *oe = find_mark(marks, idnum);

static void parse_feature(const char *feature)
			die("Date in ident must be 'now': %s", buf);
	return 0;
			*((void**)e) = e + 1;
	dump_tags();
				continue;
	path[i + the_hash_algo->hexsz - j] = '\0';
	struct branch b;
	} else
	unsigned char fanout = 0;
		a = s->entries[i];
	struct object_id oid;
			root->versions[1].mode = S_IFDIR;
		relative_marks_paths = 1;
		}
	for (i = 0, j = 0, del = 0; i < t->entry_count; i++) {
	if (hashfile_truncate(pack_file, checkpoint))
		if (p != uq.buf) {
static void parse_get_mark(const char *p)
found_entry:
	last = idx + object_count;
	default:
	}

 * this condition and use read_sha1_file() instead.
	release_tree_content(t);
		if (length < len)
}
	struct branch *b;

{
		oidcpy(&b->oid, &s->oid);
{
	e = new_tree_entry();

}

	t = root->tree;
		depth : DEPTH_BITS;

		s->data.sets[0] = marks;
}
	const char *slash1;
				char *buf = gfi_unpack_entry(oe, &size);

		fixup_pack_header_footer(pack_data->pack_fd, pack_data->hash,
		return oe;
	struct tree_entry branch_tree;
				 * completely different one, it's not a good
			return error("Branch %s is missing commits.", b->name);
};
	case OBJ_COMMIT:
		e = insert_object(oid);
		b = new_branch(arg);
	/* ls SP (<tree-ish> SP)? <path> */
	git_deflate_end(&s);
		/*
}
			die("Corrupt mode in %s", oid_to_hex(oid));
}
			die("Not in a commit: %s", command_buf.buf);
	return failure ? 1 : 0;
							oid, NULL);
static uintmax_t delta_count_by_type[1 << TYPE_BITS];
				first_tag = t->next_tag;
}
	 * calculation should not take long.
	b->pack_id = MAX_PACK_ID;
	}
{
	unsigned int entry_capacity; /* must match avail_tree_content */
	} else if (skip_prefix(p, "inline ", &p)) {
	if (first_tag) {

static int failure;
			strbuf_addbuf(sb, &command_buf);
			construct_path_with_fanout(hex_oid, fanout, realpath);

		for (e = o->next_free; e-- != o->entries;)
static void read_marks(void)
	struct branch *b;
		die(_("feature '%s' forbidden in input without --allow-unsafe-features"),

		if (!mark || end == line + 1
	git_config(git_default_config, NULL);
	fputs("---------------------------------\n", rpt);
	}
	if (strchr(arg, '-') || endptr == arg || *endptr)
	struct branch *active_next_branch;
		build_mark_map_one(fromp->util, top->util);
			parse_checkpoint();
	} else if (!strcmp(feature, "get-mark")) {
	s = lookup_branch(objectish);
		unlink_or_warn(pack_data->pack_name);
			break;
	struct tree_entry *leaf,
	if (*p == ':') {
		if (*p++ != ' ')
	else


{
					if (e->tree->entries[n]->versions[1].mode) {
		oe = find_mark(marks, parse_mark_ref_space(&p));
	pack_size = checkpoint->offset;
	n = slash1 - p;


			parse_option(v);
		if (validate_raw_date(ltgt, &ident) < 0)
	c = mem_pool_alloc(&fi_mem_pool, sizeof(struct atom_str) + len + 1);
	} else
		fprintf(stderr, "---------------------------------------------------------------------\n");
	 * Output based on batch_one_object() from cat-file.c.
	if (!oe)
		s.avail_in = dat->len;
				free(rc->buf);
 *
		}
			(unsigned int)(e->versions[v].mode & ~NO_DELTA),
	parse_from(b);
	const char *orig_src = src;
static void insert_oid_entry(struct mark_set *s, struct object_id *oid, uintmax_t mark)
	struct packed_git *p;

struct hash_list {
	struct strbuf data;
	git_zstream s;
		}
 * oe->pack_id must not be MAX_PACK_ID.  Such an oe is usually from
	if (*p == '"') {
		if (is_null_oid(&s->oid))
		release_tree_content_recursive(e->tree);
			parse_new_blob();
		} else {
			fputs(tg->name, rpt);
	const char *v;
}
	if (fanout >= the_hash_algo->rawsz)
		die("internal consistency error creating the index");
	struct last_object *last,
		read_next_command();
	if (inline_data) {
		strbuf_attach(&last_blob.data, buf, size, size);
};
		die("Missing > in ident string: %s", buf);
	} else
static struct object_entry *insert_object(struct object_id *oid)

	}
	unsigned char *out_buf = xmalloc(out_sz);
		if (oideq(oid, &e->idx.oid))
{
	object_count = 0;
	setup_git_directory();
	num = strtoul(src, &endp, 10);
	if (backup_leaf)

	pack_size += s.total_out;
	}
		unlink_or_warn(name.buf);
	else if (import_marks_file_ignore_missing && errno == ENOENT)
		} else

				parse_cat_blob(v);

	s.avail_out = out_sz - hdrlen;
		next_mark = strtoumax(v, NULL, 10);
		}
	} else {

	p++;
		}
	avail_tree_entry = *((void**)e);
	struct tree_content *subtree)
				       export_marks_file);
{
	for_each_string_list_item(fromp, from) {
}
	offset = checkpoint.offset;
	struct avail_tree_content *next_avail;
	else if (!strcmp(fmt, "now"))
	strbuf_release(&ref_name);

		}
				}


	if (close(keep_fd))
		case Z_STREAM_END:
{
	size_t name_len;
	struct tree_entry *b = *((struct tree_entry**)_b);
		goto found_entry;
static const char *create_index(void)

		b->name->str_dat, b->name->str_len, b->versions[1].mode);
		die("Invalid ref name or SHA1 expression: %s", from);
		if (*a != '-' || !strcmp(a, "--"))
		whenspec = WHENSPEC_NOW;
}
				load_tree(e);
		struct branch *b;
	struct tree_entry *e, leaf;
{
	}
			if (!e->tree)
			s.next_in = in_buf;
}
	return base_name_compare(
		stream_blob(len, oidout, mark);
	if (*ltgt != ' ')
	} else {
struct branch {
		e->type = type;
{
			t->entries[j++] = e;
		oe = find_object(&oid);
		oidcpy(oidout, &oid);
	/* <commit-ish> */
	/* Now parse the notemodify command. */
	if (!b->active) {
		n->next = NULL;
			die("Unsupported command: %s", command_buf.buf);
	ALLOC_ARRAY(idx, object_count);
	if (term_char != '\n' && term_char != EOF)


		else if (skip_prefix(command_buf.buf, "cat-blob ", &v))

	}
		e->versions[1].mode = S_IFDIR;
		e = dereference(e, &oid);
		if (t) {
		if (0 < len && !s.avail_in) {
struct atom_str {
		}
	} else if (!is_null_oid(&oid)) {
		e = t->entries[i];
	fputc('\n', rpt);
}
	int k;
	for (lu = 0; lu < branch_table_sz; lu++) {
	strbuf_reset(sb);
		die("Empty path component found in input");
			*len_res = len;
		zombie = 1;
	for (i = 0; i < (cmd_save - 1); i++)
}
		oe = NULL; /* not used with inline_data, but makes gcc happy */
				die("EOF in data (terminator '%s' not found)", term);
		failure |= error_errno("unable to create leading directories of %s",
	if (*p == ':') {


		error("%s", err.buf);
	strbuf_addf(&new_data,
		end = strchr(line, '\n');
}
	switch (whenspec) {
	else {
	struct object_id oid;
		 */
}
{
		oidcpy(&oid, &e->idx.oid);
		break;
	/* ensure there is a space delimiter even if there is no name */
				free(buf);
			}
	if (parse_one_option(option))
	vsnprintf(message, sizeof(message), err, params);
	struct tree_entry *e;
						       &commit_oid,
static int tree_content_set(
	running = 0;
{

	if (!show_stats)
	p->do_not_close = 1;
}
	} else {
		       e->name->str_len);
		return 0;
				e->tree = new_tree_content(8);
			return 0;
		idnum -= i << s->shift;
		old_cmit = lookup_commit_reference_gently(the_repository,
		load_tree(root);
	if (it == kh_end(sub_oid_map)) {
	case OBJ_TAG:
	if (export_marks_file)
		return;
	size_t maxlen = 0;
						fprintf(pack_edges, " %s",
	uint32_t type : TYPE_BITS,
			die("Not a %s (actually a %s): %s",
			if (!*slash1 || !S_ISDIR(e->versions[1].mode))

	struct tree_entry *b = *((struct tree_entry**)_b);
		return -1;
			uintmax_t idnum = parse_mark_ref_eol(from);
	/* file_change* */

	unkeep_all_packs();
	for (c = atom_table[hc]; c; c = c->next_atom)
	mktree(t, 1, &new_tree);
	}
	strbuf_grow(b, maxlen);
		case Z_OK:
static void option_depth(const char *depth)
	for (i = 1; i < global_argc; i++) {
	struct tree_content *t;
	}
			tree_content_set(orig_root, realpath,
	oidclr(&b->branch_tree.versions[0].oid);
	struct tree_entry *e;
}
		} else {
}
		strbuf_addf(&line, "%s missing\n", oid_to_hex(oid));
}
	return num_notes;
		for (k = 0; k < 1024; k++) {
	all_packs[pack_id] = p;
		skip_optional_lf();
	struct object_id oid;

	uintmax_t len;
	else if (s) {
			oe = s->data.marked[idnum];

			t->pack_id = MAX_PACK_ID;

	return 1;
	fputc('\n', rpt);
	if (new_fanout != prev_fanout)

			if (!S_ISDIR(e->versions[1].mode)) {

	read_next_command();
 * the need for the corresponding .idx file.  This unpacking rule

		die("Not a tree-ish: %s", command_buf.buf);
		buf = gfi_unpack_entry(oe, &size);
	if (!p)
	insert_mark(s, mark, e);
	struct tag *t;
	if (*p != ':')
				e->versions[1].mode = S_IFDIR;
		QSORT(t->entries, t->entry_count, tecmp1);
		dump_marks();
			FREE_AND_NULL(delta);
	e = insert_object(&oid);

	if (last) {
	strbuf_addf(&new_data, "tree %s\n",
static void dump_marks(void);
		b = new_branch(arg);
	}
static struct strbuf old_tree = STRBUF_INIT;
static uintmax_t parse_mark_ref_eol(const char *p)
		struct object_entry *e;
		cnt = cnt & 7 ? ((cnt / 8) + 1) * 8 : cnt;
		leaf->tree = NULL;
	if (skip_prefix(feature, "date-format=", &arg)) {
				oidclr(&root->versions[1].oid);
	sub_oid_map = kh_init_oid_map();
			}
	if (t->entry_count == t->entry_capacity)

		max_packsize = v;
discard_pack:
		fprintf(stderr, "      commits:   %10" PRIuMAX " (%10" PRIuMAX " duplicates %10" PRIuMAX " deltas of %10" PRIuMAX" attempts)\n", object_count_by_type[OBJ_COMMIT], duplicate_count_by_type[OBJ_COMMIT], delta_count_by_type[OBJ_COMMIT], delta_count_attempts_by_type[OBJ_COMMIT]);
			oidcpy(&n->oid, &s->oid);
	return e;
	fputs("-----------------\n", rpt);
			type = oe->type;
{
{
}
	struct branch *s;
		oidcpy(&oid, &oe->idx.oid);
static void note_change_n(const char *p, struct branch *b, unsigned char *old_fanout)

{
		strbuf_addf(&ref_name, "refs/tags/%s", t->name);
			last->depth = 0;
}

	for (h = 0; h < ARRAY_SIZE(object_table); h++) {
	if (ltgt != buf && ltgt[-1] != ' ')
	struct object_entry *oe;

static int relative_marks_paths;
	name_len = ltgt - buf;
	if (!e) {
	struct tag *t;
		else {
{
	int limit;
	} else if (!strcmp(feature, "cat-blob")) {
	struct object_entry *e;
	case WHENSPEC_RAW:
		lo.data = old_tree;


		t->pack_id = pack_id;
	t->delta_depth = 0;
	if (!b->branch_tree.tree || !max_active_branches) {
{
				mode & ~NO_DELTA, type, hash_to_hex(hash));
static void option_date_format(const char *fmt)
}

		    tmp_hex_oid_len > hexsz ||
		unkeep_all_packs();


	sigaction(SIGUSR1, &sa, NULL);
	b->branch_tree.versions[0].mode = S_IFDIR;
		lo.offset = le->idx.offset;
static struct object_entry_pool *blocks;
		fanout++;

/* The .pack file being generated */
	merge_list = parse_merge(&merge_count);
static void tree_content_replace(
		strbuf_addch(&line, '\n');
	if (c != last)
		from_mark = parse_mark_ref_eol(from);
typedef void (*mark_set_inserter_t)(struct mark_set *s, struct object_id *oid, uintmax_t mark);

	} else {
		buf = read_object_file(oid, &type, &size);
{
			else

	unsigned delete : 1;

		pack_size += sizeof(hdr) - pos;
		} else if (v < 1024 * 1024) {
		release_tree_content_recursive(b->branch_tree.tree);
 * ensure the 'struct object_entry' passed was written by this
	mark = strtoumax(p, endptr, 10);
#define PACK_SIZE_THRESHOLD (the_hash_algo->rawsz * 3)
		if (limit && limit < len) {
{
	fputs("END OF CRASH REPORT\n", rpt);

		return;
	root->tree = t = new_tree_content(8);
		d = d_uq.buf;
	if (from_stream && !allow_unsafe_features)
	enum object_type type = 0;
	return NULL;
	fputc('\n', rpt);
		if (line[0] != ':' || !end)


			prev = t;
}
				die("EOF in data (%" PRIuMAX " bytes remaining)", len);
	n = slash1 - p;
#include "builtin.h"
	fprintf(rpt, "    parent process     : %"PRIuMAX"\n", (uintmax_t) getppid());
}
	if (is_null_oid(oid))
		strbuf_addf(&new_data, "parent %s\n",
	if (argc == 2 && !strcmp(argv[1], "-h"))
		if (!endp)
static void parse_reset_branch(const char *arg)
static uintmax_t marks_set_count;
	return 1;
		 * separators), OR directory entries that may contain note
	store_tree(&b->branch_tree);

				e->tree = subtree;
static uintmax_t parse_mark_ref_space(const char **p)
			continue;
static void load_tree(struct tree_entry *root)
	 */
		t->pack_id = MAX_PACK_ID;
			b->delete = 1;
	last_tag = t;
	unsigned int h;

		oidcpy(&oid, &s->oid);
			type = oid_object_info(the_repository, &oid, NULL);
		enum object_type type = oid_object_info(the_repository,
	if (b->active)
	fprintf(rpt, "    fast-import process: %"PRIuMAX"\n", (uintmax_t) getpid());
				 *
	memset(&sa, 0, sizeof(sa));
static void parse_mark(void)
		const char *v;
			/* Rename fullpath to realpath */

	struct avail_tree_content *f = (struct avail_tree_content*)t;

{
		check_unsafe_feature("import-marks-if-exists", from_stream);
		}
	struct object_entry *oe = NULL;
	cnt = cnt & 7 ? (cnt / 8) + 1 : cnt / 8;
	free(tagger);
	sa.sa_flags = SA_RESTART;
		}
		struct tree_entry *orig_root, struct tree_entry *root,
	if (require_explicit_termination && feof(stdin))
		enum object_type type = oid_object_info(the_repository, oid,
		memcpy(backup_leaf, e, sizeof(*backup_leaf));
	if (command_buf.len > 0)
}
			die("Missing space after source: %s", command_buf.buf);

	return 0;
		return;
	git_hash_ctx c;
		if (!git_parse_ulong(option, &v))
			die("Missing space after tree-ish: %s", command_buf.buf);
		failure |= error("%s", err.buf);

	int ret;
	/* mark ... */
		usage(fast_import_usage);
	avail_tree_table = xcalloc(avail_tree_table_sz, sizeof(struct avail_tree_content*));
	avail_tree_entry = e;
		e = root;

	}
	unsigned int i;
		option_depth(option);


static int seen_data_command;
		free(merge_list);

	c->next_atom = atom_table[hc];
	union {


		tree_content_remove(&b->branch_tree, p, NULL, 0);
			die("Invalid SHA1 in tag: %s", command_buf.buf);
	strbuf_release(&name);

			e->branch_tree.tree = NULL;
	b->branch_tree.versions[1].mode = S_IFDIR;
	memset(t, 0, sizeof(struct tag));
	e = find_object(&b.oid);
		}
		}
	e = find_object(oid);
{
	max_active_branches = ulong_arg("--active-branches", branches);

			leaf.versions[1].mode,
			export_marks_file, strerror(saved_errno));
		}
		for (e = object_table[h]; e; e = e->next)
	unsigned int r = 0;
 */
		else if (skip_prefix(command_buf.buf, "ls ", &v))
		else if (skip_prefix(command_buf.buf, "tag ", &v))
static struct avail_tree_content **avail_tree_table;
	the_hash_algo->update_fn(&c, hdr, hdrlen);
}
		fprintf(stderr, "Total objects:   %10" PRIuMAX " (%10" PRIuMAX " duplicates                  )\n", total_count, duplicate_count);

			release_tree_entry(e);
			continue;
		e->tree = subtree;
			fputs("  ", rpt);
	e->next = object_table[h];
	ref_transaction_free(transaction);
}
static void file_change_m(const char *p, struct branch *b)

	free(buf);
{
	if (skip_prefix(command_buf.buf, "tagger ", &v)) {
	if (!oe) {
		char *term = xstrdup(data);
	} else if (!strcmp(feature, "notes") || !strcmp(feature, "ls")) {
		tree_entry_allocd += n * sizeof(struct tree_entry);
							  &b->oid, 0);
					fprintf(pack_edges, " %s",
static struct tree_content *grow_tree_content(

	struct child_process unpack = CHILD_PROCESS_INIT;
		read_next_command();

	free(buf);
		}
			die("Only one import-marks command allowed per stream");

{
	}
		fanout--;
		*((void**)e) = NULL;
	if (check_refname_format(name, REFNAME_ALLOW_ONELEVEL))
	num = strtoul(src + 1, &endp, 10);
}

static struct packed_git *pack_data;
{
		die("No value after ':' in mark: %s", command_buf.buf);
	}
}
		pack_report();
		e->pack_id = MAX_PACK_ID;
	strbuf_addbuf(&new_data, &msg);
				&& !starts_with(command_buf.buf, "option ")) {
	struct atom_str *next_atom;
	} else if (!strcmp(option, "quiet")) {

		}
		b->num_notes = change_note_fanout(&b->branch_tree, new_fanout);
		insert_mark(marks, mark, e);
	} else if (inline_data) {
		hdrlen = encode_in_pack_object_header(hdr, sizeof(hdr),
		if (!oideq(&b->oid, &oe->idx.oid)) {
		 * of 2 chars.
		mode = (mode << 3) + (c - '0');
static void unkeep_all_packs(void);
		tagger = parse_ident(v);
	if (!*p && allow_root) {

	skip_optional_lf();
	else
			if (oe->type != OBJ_COMMIT)
	} else
		die_errno("cannot create keep file");
	return rv;
		for (i = 0; i < ARRAY_SIZE(duplicate_count_by_type); i++)
	struct strbuf name = STRBUF_INIT;
		oe = NULL; /* not used with inline_data, but makes gcc happy */

	unsigned int hc = hc_str(s, len) % atom_table_sz;
		whenspec = WHENSPEC_RFC2822;
	if (!root->tree)
	if (e->idx.offset) {
	char *s = xstrdup(arg);
		switch (status) {
				die("Not a valid commit: %s", from);
			s->data.sets[i]->shift = s->shift - 10;

	struct branch *b;
	reset_pack_idx_option(&pack_idx_opts);
	enum object_type type,
	case WHENSPEC_RFC2822:
	char output[GIT_MAX_HEXSZ + 2];
static void parse_argv(void);

	skip_optional_lf();
			if (tree_content_remove(e, slash1 + 1, backup_leaf, 0)) {
	struct avail_tree_content *f, *l = NULL;
typedef enum {
			e->name->str_dat, '\0');
{
	unsigned int i;
	char *committer = NULL;

	if (**p == ':') {	/* <mark> */
 */
	unsigned int i, n;
	else
		d->entries[i] = b;
				return 1;
		 * Accept the sha1 without checking; it expected to be in
}
		if (from_stream)
}
static char* make_fast_import_path(const char *path)

					S_ISDIR(mode) ?  "Tree" : "Blob",
	if (!git_config_get_int("pack.indexversion", &indexversion_value)) {
	}
			s.next_out = out = xrealloc(out, s.avail_out);
			break;
static struct branch *new_branch(const char *name)
		mode |= S_IFREG;
	sa.sa_handler = checkpoint_signal;
		unpack_limit = limit;
			/* This is a subdir that may contain note entries */
	assert(e);
static unsigned long branch_load_count;
	if (f) {
			break;
static void parse_option(const char *option)
	if (!n)
			die("Unknown mark: %s", command_buf.buf);

	for (k = 0; k < pack_id; k++) {
}
		oidcpy(oidout, &oid);
		fprintf(stderr, "      trees  :   %10" PRIuMAX " (%10" PRIuMAX " duplicates %10" PRIuMAX " deltas of %10" PRIuMAX" attempts)\n", object_count_by_type[OBJ_TREE], duplicate_count_by_type[OBJ_TREE], delta_count_by_type[OBJ_TREE], delta_count_attempts_by_type[OBJ_TREE]);
	} else
	fclose(rpt);
		/* If we're using the same algorithm, pass it through. */

		oid_to_hex(&b->branch_tree.versions[1].oid));
	static const char *msg = "fast-import";
		}
/*
	int indexversion_value;
	e->type = type;
}

		option_import_marks(arg, from_stream, 0);
		return;
}
	}

	fprintf(rpt, "  tip commit  : %s\n", oid_to_hex(&b->oid));
	fclose(f);
	const uint16_t mode,
			if (skip_prefix(command_buf.buf, "cat-blob ", &v))
	free(delta);
	last_blob.depth = 0;
		oidclr(&b->branch_tree.versions[1].oid);
{
				e->versions[1].mode = mode;
					type_name(oe->type), command_buf.buf);
	while (!e || e->type != OBJ_TREE)
		hashcpy(e->versions[0].oid.hash, (unsigned char *)c);
		new_p = add_packed_git(idx_name, strlen(idx_name), 1);
	struct object_entry *e;
	src = endp + 1;
static void end_packfile(void);
static void parse_cat_blob(const char *p)
		tagger = NULL;
					e->versions[0].mode |= NO_DELTA;
	const char *from;
	if (stdin_eof) {
		failure |= error("Unable to write marks file %s: %s",
		if (!buf)
		strbuf_reset(&line);
	t->entry_count = 0;
		struct object_entry *marked[1024];
static void check_unsafe_feature(const char *feature, int from_stream)
				fullpath, tmp_fullpath_len, fanout);
	}
	return 1;
	if (S_ISGITLINK(mode)) {

	if (skip_prefix(command_buf.buf, "author ", &v)) {

		fclose(pack_edges);
	}
		cur_active_branches--;
	if (S_ISDIR(leaf.versions[1].mode))
		hashflush(pack_file);
	if (show_stats) {
	f++;
		} else {
	rc_free = mem_pool_alloc(&fi_mem_pool, cmd_save * sizeof(*rc_free));
	dump_marks();
	read_next_command();
		die("Not a mark: %s", p);
		 * data is stale and is not valid.  Closing all windows
		for (b = branch_table[i]; b; b = b->table_next_branch)
	else
	oidcpy(&e->idx.oid, oid);
	int allow_root)
		pack_id++;
		e->pack_id = MAX_PACK_ID;
		struct tree_entry *e = t->entries[i];
		}
		datestamp(&ident);
static unsigned long ulong_arg(const char *option, const char *arg)
	else
	odb_pack_name(&name, pack_data->hash, "pack");
		option_import_marks(arg, from_stream, 1);
				       export_marks_file);

	if (!root->tree)
	algo = parse_oid_hex_any(hex, oid, end);

		cycle_packfile();


		if (last->no_swap) {
		if (object_count <= unpack_limit) {

	int amt)
			continue;
{
			die("Invalid raw date \"%s\" in ident: %s", ltgt, buf);
#define MAX_PACK_ID ((1<<PACK_ID_BITS)-1)

static int global_argc;
{
	}
		struct branch *e, *l = NULL, *p = NULL;
	/*

		last->depth = e->depth;
		author ? author : committer, committer);
	return find_object(oid);
	/* hex oid + '/' between each pair of hex digits + NUL */

		 * We're interested in EITHER existing note entries (entries
		strbuf_release(&err);


	ref_transaction_free(transaction);
{
static off_t max_packsize;
	t = root->tree;
	while ((num_notes >>= 8))
		|| (pack_size + PACK_SIZE_THRESHOLD + len) < pack_size)
				die("Not a commit (actually a %s): %s",
				load_tree(e);
#include "cache.h"
	unsigned no_swap : 1;
	if (!store_object(OBJ_COMMIT, &new_data, NULL, &b->oid, next_mark))
		struct packed_git *p = all_packs[k];
	case 0644:
	if (skip_prefix(command_buf.buf, "original-oid ", &v))
	hashfile_checkpoint(pack_file, &checkpoint);

	cat_blob_write(output, the_hash_algo->hexsz + 1);
			if (!n && feof(stdin))
static struct branch **branch_table;
	avail_tree_table[hc] = f;
		}
static struct strbuf new_data = STRBUF_INIT;
			n += s;
	strbuf_reset(&uq);
	if (!transaction ||
			for (i = 0; i < branch_table_sz; i++) {
	cat_blob_write(line.buf, line.len);
static struct object_entry *parse_treeish_dataref(const char **p)

static void for_each_mark(struct mark_set *m, uintmax_t base, each_mark_fn_t callback, void *p)
	cat_blob(oe, &oid);
		if (*endp != ' ')
			hdr[--pos] = 128 | (--ofs & 127);
	b->next_pool = blocks;
	uintmax_t orig_idnum = idnum;
	unsigned long size;
		die("Missing space after > in ident string: %s", buf);

	if (seen_data_command)
	if (skip_prefix(data, "<<", &data)) {
static unsigned long max_active_branches = 5;
	if (b->branch_tree.tree)
	if (skip_prefix(option, "max-pack-size=", &option)) {
		last_blob.offset = oe->idx.offset;
}
			active_branches = e->active_next_branch;
	}
	if (*end++ != ' ')
					int from_stream, int ignore_missing)
		quote_c_style(path, &line, NULL, 0);
{
	struct recent_command *prev;
static int store_object(

static unsigned long object_count;
	e->name = to_atom(p, n);
}
		if (!old_cmit || !new_cmit)

	struct strbuf name = STRBUF_INIT;
	const char *v;
	}
		else if (skip_prefix(command_buf.buf, "D ", &v))
						 &b->oid);
static void checkpoint(void)
				 * delta base any more, and besides, we've

	start_packfile();
	/*
typedef void (*each_mark_fn_t)(uintmax_t mark, void *obj, void *cbp);
{
				 * parent directory of p exists, then p cannot
	unsigned int hc = hc_entries(cnt);

static void set_checkpoint_signal(void)
{

	r->entry_count = t->entry_count;
}
				cmd_hist.next->prev = &cmd_hist;
		blob_type;
}
		e->name = to_atom(c, strlen(c));
	while (read_next_command() != EOF) {
int cmd_main(int argc, const char **argv)
		fprintf(stderr, "      tags   :   %10" PRIuMAX " (%10" PRIuMAX " duplicates %10" PRIuMAX " deltas of %10" PRIuMAX" attempts)\n", object_count_by_type[OBJ_TAG], duplicate_count_by_type[OBJ_TAG], delta_count_by_type[OBJ_TAG], delta_count_attempts_by_type[OBJ_TAG]);
	struct strbuf err = STRBUF_INIT;

		else if (skip_prefix(command_buf.buf, "option git ", &v))
			v = 1024 * 1024;
			die("Blob not found: %s", command_buf.buf);
}
		new_cmit = lookup_commit_reference_gently(the_repository,
			return 0;
	while (status != Z_STREAM_END) {
	load_tree(&b->branch_tree);
static void dump_tags(void)
	} versions[2];
static char *pool_strdup(const char *s)
		if (tmp_hex_oid_len == hexsz && !get_oid_hex(hex_oid, &oid)) {
	if (type != OBJ_BLOB)

	if (oidout)
		}
 * current pack. This is the hash lengths at the end of the pack, plus the
		return;
	unsigned char new_fanout;
						      OBJ_OFS_DELTA, deltalen);
			last->data = *dat;
		b->active = 1;
		if (type != OBJ_BLOB)
			strbuf_addstr(&uq, p);
}
		die_errno("Failed seeking to start of '%s'", p->pack_name);

		} else if (S_ISDIR(e->versions[1].mode)) {
	uint16_t inline_data = 0;
	struct branch *b = lookup_branch(name);
		return;
	static int zombie;
			maxlen += t->entries[i]->name->str_len + 34;
}
				die("EOF in data (%lu bytes remaining)",
	case OBJ_TREE:	/* easy case. */
	unsigned int depth;
static void write_crash_report(const char *err)

{
	strbuf_release(&err);
	strbuf_addstr(result, orig_src);
	parse_original_identifier();

	}
static struct strbuf command_buf = STRBUF_INIT;
	} else {

{
		release_tree_entry(t->entries[i]);
}

			return c;
	} else if (find_sha1_pack(oid.hash,
			oidcpy(&b->oid, &oe->idx.oid);
		inserter(s, &oid, mark);
	if ((max_packsize
	oidclr(&root->versions[0].oid);

	} else {
static void parse_ls(const char *p, struct branch *b);
	git_deflate_end(&s);
	sigemptyset(&sa.sa_mask);

	if (!seen_data_command)

		die("Garbage after mark: %s", command_buf.buf);
	fflush(stdout);

	marks = mem_pool_calloc(&fi_mem_pool, 1, sizeof(struct mark_set));

	insert_mark(s, mark, xmemdupz(oid, sizeof(*oid)));
static void insert_mark(struct mark_set *s, uintmax_t idnum, struct object_entry *oe)

	/* <dataref> or 'inline' */
	if (is_null_oid(&b->branch_tree.versions[1].oid))
	argv_array_push(&unpack.args, "unpack-objects");
static void option_rewrite_submodules(const char *arg, struct string_list *list)
	fclose(fp);
}

			return e;
	}
		for (b = branch_table[lu]; b; b = b->table_next_branch)
	struct object_entry *e;
done:
		return 0;
		e->idx.offset = 1; /* just not zero! */
	if (leaf.tree)
}
	dump_branches();
	seen_data_command = 1;
		return;




		truncate_pack(&checkpoint);
	const char *slash1;
	unsigned long num;
			e->versions[0].mode = e->versions[1].mode;


		}
	f = fdopen_lock_file(&mark_lock, "w");
}
		if (!c)

static void option_cat_blob_fd(const char *fd)
/*

	switch (oe->type) {
	} else {
		if (f->entry_capacity >= cnt)
static void build_mark_map_one(struct mark_set *from, struct mark_set *to)

			if (rc)
	b->active = 0;
{
	}
		release_tree_content_recursive(e->tree);
	const char *v;
{

	parse_and_store_blob(&last_blob, NULL, next_mark);
			die("unexpected deflate failure: %d", status);
		if (last) {
		}

	int term_char = fgetc(stdin);

		/* read previous mark file */

	if (!unquote_c_style(&uq, p, &endp)) {
			goto cleanup;
			die(_("Missing to marks for submodule '%s'"), fromp->string);
		s = s->data.sets[i];
		die_errno("cannot read '%s'", import_marks_file);
		require_explicit_termination = 1;
	b->last_commit = object_count_by_type[OBJ_COMMIT];
	memset(oid->hash, 0, sizeof(oid->hash));
			s->data.sets[i] = mem_pool_calloc(&fi_mem_pool, 1, sizeof(struct mark_set));
			die("Garbage after path in: %s", command_buf.buf);

		fputs("Annotated Tags\n", rpt);
	global_argv = argv;
			die("corrupt mark line: %s", line);
	unpack.stdout_to_stderr = 1;

	hdrlen = xsnprintf((char *)out_buf, out_sz, "blob %" PRIuMAX, len) + 1;
static void file_change_d(const char *p, struct branch *b)
		die("Invalid ref name or SHA1 expression: %s", p);
	struct object_id oid;
			/* ignore non-git options*/;
	}
{

	oidcpy(oid, kh_value(sub_oid_map, it));
}
		e = root;

	transaction = ref_transaction_begin(&err);
	char message[2 * PATH_MAX];
							       commit_type,
	if (skip_prefix(command_buf.buf, "mark :", &v)) {
	struct ref_transaction *transaction;
		if (*arg != '-' || !strcmp(arg, "--"))
static int parse_one_option(const char *option)
		die("unknown option --%s", a);
				if (e->tree)
			s.next_out = out_buf;
		    "object %s\n"
	import_marks_file_from_stream = from_stream;
}
{
 * process instance.  We unpack the entry by the offset, avoiding
		return 0;
		die("Missing space after mark: %s", command_buf.buf);

		/* missing SP path LF */
	strbuf_release(&last_blob.data);
				return 1;
}
		memcpy(fullpath + tmp_fullpath_len, e->name->str_dat,
		die("Path %s not in branch", s);
static void construct_path_with_fanout(const char *hex_sha1,

	while (command_buf.len > 0) {
			strbuf_addch(sb, '\n');
	if (commit_lock_file(&mark_lock)) {
	struct tree_entry *root,

		    feature);
static int unpack_limit = 100;
		unsigned long v;
		rc_free[i].next = &rc_free[i + 1];
	struct object_entry_pool *b;



		; /* already handled during early option parsing */
	b->table_next_branch = branch_table[hc];

		a->name->str_dat, a->name->str_len, a->versions[1].mode,

	if (!v)

	return do_change_note_fanout(root, root, hex_oid, 0, path, 0, fanout);
		fprintf(rpt, "  %2lu) %6" PRIuMAX" %s\n",
	} else if (oe) {
			p = uq.buf;
		/* Ensure SHA-1 objects are padded with zeros. */
}
		S_ISGITLINK(mode) ? commit_type :

			die("data is too large to use in this context");
		e->depth = last->depth + 1;
	free(loc);
	struct tree_entry *root,
	struct object_entry *end;

	if (!transaction) {
	/* cat-blob SP <object> LF */
		e->depth = 0;
}
		die("Too large fanout (%u)", fanout);
	char *author = NULL;
		max_active_branches);

		}
	static const char *msg = "fast-import";
		return; /* nothing to insert */

	rc_free[cmd_save - 1].next = NULL;

static void mktree(struct tree_content *t, int v, struct strbuf *b)
			    type_name(type), command_buf.buf);
		if (!s.avail_out || status == Z_STREAM_END) {
		write_crash_report(message);
{
				/* Note entry is in correct location */
		die("Corrupt mode: %s", command_buf.buf);
		quote_c_style(path, &line, NULL, 0);
		if (oideq(oid, &e->idx.oid))
	c->str_len = len;
static int unread_command_buf;

		die("Expected committer but didn't get one");
	       &b->branch_tree.versions[1].oid);
		struct branch *b;
	WHENSPEC_RAW = 1,

#include "config.h"
}
	read_mark_file(marks, f, insert_object_entry);
		 * with exactly 40 hex chars in path, not including directory

	}
	return 1;
					"bad pack.indexversion=%"PRIu32, pack_idx_opts.version);

	struct object_id oid;
		else if (!strcmp("deleteall", command_buf.buf))
struct mark_set {
		oidcpy(&oid, &oe->idx.oid);
				p = l;
static struct object_entry *object_table[1 << 16];
		unsigned char fanout, char *path)
		struct tree_entry *e = new_tree_entry();

	strbuf_add(&ident, buf, name_len);
 * works because we only use OBJ_REF_DELTA within the packfiles
	if (!s)
							NULL);
				for (n = 0; n < e->tree->entry_count; n++) {
	strbuf_release(&err);
	/* tag payload/message */
	load_tree(&b->branch_tree);
static void parse_get_mark(const char *p);

struct tree_content {
		if (t->entries[i]->tree)

static unsigned int avail_tree_table_sz = 100;
			avail_tree_table[hc] = f->next_avail;
 *
	return git_pathdup("info/fast-import/%s", path);
		return;
	slash1 = strchrnul(p, '/');
	return 0;

static int allow_unsafe_features;
		else if (starts_with(command_buf.buf, "progress "))
	unsigned pack_id : PACK_ID_BITS;

		struct object_entry *oe;

	pack_fd = odb_mkstemp(&tmp_file, "pack/tmp_pack_XXXXXX");
			return b;
		path[i++] = hex_sha1[j++];
		read_next_command();
		option_date_format(arg);
		e->type = OBJ_BLOB;
	else
	construct_path_with_fanout(oid_to_hex(&commit_oid), *old_fanout, path);
 * Parse the mark reference, and complain if this is not the end of
	struct object_entry *next;
		break;
{
		else if (skip_prefix(command_buf.buf, "commit ", &v))
	s.next_out = out_buf + hdrlen;
		pack_id : PACK_ID_BITS,
static uintmax_t object_count_by_type[1 << TYPE_BITS];
		truncate_pack(&checkpoint);
	if (!leaf.versions[1].mode)
	b->next_free = b->entries;
		tree_content_replace(&b->branch_tree,
							NULL);
	}
				num_notes++;
			checkpoint();
	struct object_entry *next_free;
	read_next_command();
						       &commit_oid);
static const char *import_marks_file;
	 * Fix this by traversing the tree and counting the number of notes
			if (!loosen_small_pack(pack_data)) {
	t = root->tree;
			if (m->data.marked[k])
	if (!oe || oe->pack_id == MAX_PACK_ID) {
	if (!n && !allow_root)
		die("The commit %s is corrupt", oid_to_hex(&b->oid));
		memcpy(hex_oid + hex_oid_len, e->name->str_dat,
	if (encoding)
			s.avail_in = dat->len;
		cycle_packfile();
static void *avail_tree_entry;
		duplicate_count_by_type[type]++;
{
	const char *ltgt;
 * the string.
	b->num_notes++;
static struct tree_entry *new_tree_entry(void)
{
	hdr.hdr_version = htonl(2);
	case WHENSPEC_NOW:
		while (ofs >>= 7)
static void git_pack_config(void)



		oe = find_mark(marks, from_mark);
			die("Can't add a note on empty branch.");
	else if (!strcmp(fmt, "rfc2822"))

	}
	object_table[h] = e;

		if (*endp)
	struct object_id oid;
		return 0;
	*f = '\0';
		strbuf_reset(&line);
{

		n = xmalloc(sizeof(*n));
{
}
			die("Invalid dataref: %s", command_buf.buf);
	unsigned long hdrlen;
	struct object_entry *e;
		memcpy(b, a, sizeof(*a));
	if (ret == 0)
}
			e = active_branches;
	if (S_ISDIR(root->versions[0].mode) && le && le->pack_id == pack_id) {
	}
	the_hash_algo->update_fn(&c, out_buf, hdrlen);
		strbuf_add(b, e->versions[v].oid.hash, the_hash_algo->rawsz);
static int parse_mapped_oid_hex(const char *hex, struct object_id *oid, const char **end)
				e->pack_id = MAX_PACK_ID;
		if (!new_p)
	if (!avail_tree_entry) {
 cleanup:
	return list;

		if (tmp_fullpath_len)
	char *f = strchr(s, ':');
{
}
		b->num_notes = change_note_fanout(&b->branch_tree, 0xff);
	branch_count++;
	if (!is_null_oid(&b->oid))
			rc->prev = cmd_tail;
	strbuf_release(&line);

}

					   &t->oid, NULL, 0, msg, &err)) {
			if (prev)
	fputs(message, stderr);
		type = oe->type;
/* Memory pools */
	} else {	/* <sha1> */
		for (tg = first_tag; tg; tg = tg->next_tag) {
	root->tree = newtree;
		strbuf_release(&line);

				goto discard_pack;
		else if (starts_with(command_buf.buf, "option "))
				parse_from_existing(b);
	if (!root->tree)
		uintmax_t total_count = 0, duplicate_count = 0;
	struct object_entry *le = NULL;

		die_errno("cannot read '%s'", f);
};
		duplicate_count_by_type[type]++;
	size_t len = strlen(s) + 1;
		if (checkpoint_requested)
	 * b->num_notes == 0, and consequently, old_fanout might be wrong.
	unsigned int i;
 *
		else
				num_notes++;

		p = uq.buf;
#include "blob.h"

static int tree_content_get(
};
static uintmax_t delta_count_attempts_by_type[1 << TYPE_BITS];
	return r;
			idnum -= i << s->shift;
		return;
		fprintf(stderr, "     objects:    %10" PRIuMAX " KiB\n", (alloc_count*sizeof(struct object_entry))/1024);
	return oe;
		 * the newly written data.
			for (t = first_tag; t; t = t->next_tag) {
static struct object_entry *find_object(struct object_id *oid)
	struct object_entry_pool *o;
	unsigned int hc = hc_str(name, strlen(name)) % branch_table_sz;
	 * A directory in preparation would have a sha1 of zero
	struct tree_entry *a = *((struct tree_entry**)_a);
	return NULL;
static void *gfi_unpack_entry(

		char *fullpath, unsigned int fullpath_len,
	}
	} else if (!get_oid(from, &oid)) {
	alloc_count += cnt;
		return;
		die("mark :%" PRIuMAX " not declared", orig_idnum);
}
	 * until it is saved.  Save, for simplicity.

				goto found_entry;
	}
static struct hash_list *parse_merge(unsigned int *count)
		tree_content_set(e, slash1 + 1, oid, mode, subtree);
		if (is_null_oid(&b->oid))
		t = root->tree;
	else
	} else if (!strcmp(feature, "done")) {
	for (i = 0; i < t->entry_count; i++)
			root->tree = t = grow_tree_content(t, t->entry_count);
	dump_branches();
		struct object_entry *e = parse_treeish_dataref(&p);
		top = string_list_lookup(to, fromp->string);
	if (!*d) {	/* C "path/to/subdir" "" */
		else if (skip_prefix(command_buf.buf, "N ", &v))
	struct hash_list *merge_list = NULL;
	unsigned int h = oid->hash[0] << 8 | oid->hash[1];
		die("Expected 'data n' command, found: %s", command_buf.buf);
	struct strbuf *dat,

		/* We cannot carry a delta into the new pack. */
	for (e = object_table[h]; e; e = e->next)
		while (s && s->shift) {
	t = root->tree;

	}
		if (ref_transaction_update(transaction, ref_name.buf,
			b->branch_tree.tree = NULL;
	 *

		if (!fromp->util) {

		merge_list = next;
		b->name->str_dat, b->name->str_len, b->versions[0].mode);
static off_t pack_size;
			p->active_next_branch = e->active_next_branch;
	store_object(OBJ_TREE, &new_tree, &lo, &root->versions[1].oid, 0);
			rc->buf = xstrdup(command_buf.buf);
		die("Unknown mark: %s", command_buf.buf);
static void store_tree(struct tree_entry *root)
		 * Also, each path component in a note entry must be a multiple
	unsigned char prev_fanout, new_fanout;
		close_pack_windows(pack_data);
		uintmax_t i = idnum >> s->shift;
}
				 * when writing out the parent directory.

			++lu, b->last_commit, b->name);
	parse_mark();

		load_tree(root);

	} else {
		first_tag = t;

		read_next_command();
		if (t->entry_count == t->entry_capacity)
	free(idx);
}

	struct object_id *oidout,
	struct branch *s;
		load_tree(root);
}
	static struct strbuf uq = STRBUF_INIT;



		goto cleanup;
	if (!export_marks_file || (import_marks_file && !import_marks_file_done))
			die("Not a blob (actually a %s): %s",

	}
		return -1;


	struct object_id oid;
		if (p) {
	if (!unquote_c_style(&s_uq, s, &endp)) {
				invalidate_pack_id(pack_id);
}
		die("cannot store pack file");

		r = r * 31 + *s++;
	oe = find_mark(marks, parse_mark_ref_eol(p));
static int loosen_small_pack(const struct packed_git *p)

			    "tagger %s\n", tagger);
	} else if (skip_prefix(option, "depth=", &option)) {
			die("Can't load tree %s", oid_to_hex(oid));
	return mark;
}
	dump_tags();
static void unkeep_all_packs(void)
		strbuf_addf(b, "%o %s%c",

						       commit_type, &size,
	struct object_entry *e = object_table[h];
	if (algo == GIT_HASH_UNKNOWN)

static int parse_one_feature(const char *feature, int from_stream)
static void option_export_pack_edges(const char *edges)
	struct strbuf line = STRBUF_INIT;
		if (c < '0' || c > '7')
		goto del_entry;
	parse_from(b);

	/* Make SHA-1 object IDs have all-zero padding. */
	struct object_id *oidout,
		char *hex_oid, unsigned int hex_oid_len,
{
		idx_name = keep_pack(create_index());
	unsigned int shift;
	unpack.in = p->pack_fd;
		oidcpy(&commit_oid, &s->oid);
	struct object_entry *oe;
		if (pack_edges) {

		die("Invalid ref name or SHA1 expression: %s", objectish);

			die("object not found: %s", oid_to_hex(oid));
	struct tree_content *t;
	 * We don't parse most options until after we've seen the set of

{
	 * characters.
	c->str_dat[len] = 0;

		die(_("Expected 'mark' command, got %s"), command_buf.buf);
	checkpoint_requested = 1;
		&& (pack_size + PACK_SIZE_THRESHOLD + len) > max_packsize)
static const char fast_import_usage[] =
		struct object_entry *oe = find_object(&oid);
		oidclr(&old_oid);

	e->tree = NULL;
		error_errno("can't write crash report %s", loc);
	} else if (*from == ':') {
			}
	t = mem_pool_alloc(&fi_mem_pool, sizeof(struct tag));
	WHENSPEC_RFC2822,
		strbuf_addch(&line, '\n');
			if (!*slash1) {
	unsigned int i, n;
			if (strbuf_getline_lf(&command_buf, stdin) == EOF)
		oe->type = type;
			die("unknown option %s", a);
	struct tree_content *t;
	if (*p == '"') {
						OBJ_TREE: OBJ_BLOB;
	fwrite(command_buf.buf, 1, command_buf.len, stdout);
}
		endp = strchr(s, ' ');
				}
	static struct strbuf msg = STRBUF_INIT;
	case S_IFREG | 0755:
	new_fanout = convert_num_notes_to_fanout(b->num_notes);
static const char **global_argv;
}

{
		b->branch_tree.tree = NULL;
			if (!strcmp(fullpath, realpath)) {
	uintmax_t mark;
			die("Invalid dataref: %s", command_buf.buf);
	const char *from;
	if (!rpt) {
	}
	struct object_entry *e;
{
	free(out_buf);

	while (merge_list) {
	unsigned long rv = strtoul(arg, &endptr, 0);
	if (i != global_argc)
	return t;
	const unsigned hexsz = the_hash_algo->hexsz;
static void cat_blob(struct object_entry *oe, struct object_id *oid)
	skip_optional_lf();
	atom_table[hc] = c;
	} else {
		f->entry_capacity = cnt;
	}
		enum object_type type;
	exit(128);
		e->active = 0;
{
				 * file or symlink matching the name of the
	int keep_fd;
		return;

	unsigned active : 1;
		pack_idx_opts.version = indexversion_value;
		unsigned char fanout)
	the_hash_algo->final_fn(oid.hash, &c);
	while ((c = *str++) != ' ') {
	e->versions[0].mode = 0;

	}
	read_next_command();
{
	strbuf_addf(&line, "%s %s %"PRIuMAX"\n", oid_to_hex(oid),
	else
	struct tree_content *r = new_tree_content(t->entry_count + amt);
	else
		release_tree_entry(root);
	/* argv hasn't been parsed yet, do so */
	struct tree_entry *backup_leaf,
		}
	strbuf_reset(&d_uq);
		die("Empty path component found in input");
}
	else {
		fprintf(stderr, "---------------------------------------------------------------------\n");
#include "quote.h"
	}
		e->type = type;

	}
			die("Garbage after SHA1: %s", command_buf.buf);
static void dump_marks(void)
};
	ltgt = buf + strcspn(buf, "<>");
		if (read_next_command() == EOF)
static const char *export_marks_file;
	}
	if (f)
}
		e->type = OBJ_BLOB;
		buf = read_object_file(oid, &type, &size);
			if (!S_ISDIR(e->versions[1].mode))
			return -1;
		die("stream ends early");
		insert_mark(marks, mark, e);
	} else if (*p == ':') {

	if (hold_lock_file_for_update(&mark_lock, export_marks_file, 0) < 0) {
	struct object_entry *e;
		for (e = active_branches; e; e = e->active_next_branch) {
 * find_mark(), where the mark was reloaded from an existing marks
			git_die_config("pack.indexversion",
			rc->prev->next = rc;



		buf = gfi_unpack_entry(myoe, &size);
			return tree_content_get(e, slash1 + 1, leaf, 0);


		 * window covered [p->pack_size, p->pack_size + rawsz) its
				cmd_hist.next = rc->next;
	if (!*p) {
	strbuf_reset(&s_uq);
static void parse_new_blob(void)
					command_buf.buf);
	/* from ... */
			file_change_d(v, b);
/*
		QSORT(t->entries, t->entry_count, tecmp0);
static void parse_progress(void)
		if (type < 0)
		 * entries (with < 40 hex chars in path).
	int allow_root)
		strbuf_reset(&uq);
			if (b->pack_id == id)
				die("Failed to remove path %s", fullpath);
			size_t s = strbuf_fread(sb, length - n, stdin);
static int validate_raw_date(const char *src, struct strbuf *result)
		if (!b)
		for (k = 0; k < 1024; k++) {

		size_t n = 0, length = (size_t)len;
			return 0;
		else
struct recent_command {
	int status = Z_OK;
	oidclr(&root->versions[1].oid);
	unsigned long size;
	}
	if (!skip_prefix(command_buf.buf, prefix, &base))
				return 0;
		return -1;
	struct object_entry *oe;
		else if (oe) {
	hdrlen = encode_in_pack_object_header(out_buf, out_sz, OBJ_BLOB, len);
			file_change_cr(v, b, 0);
static volatile sig_atomic_t checkpoint_requested;
}

static uintmax_t duplicate_count_by_type[1 << TYPE_BITS];
		die("--cat-blob-fd cannot exceed %d", INT_MAX);
		if (!e->versions[v].mode)
		struct object_id oid;
	unsigned short str_len;


		fprintf(stderr, "Memory total:    %10" PRIuMAX " KiB\n", (tree_entry_allocd + fi_mem_pool.pool_alloc + alloc_count*sizeof(struct object_entry))/1024);
		if (unquote_c_style(&uq, p, &endp))
	p->pack_fd = pack_fd;

		free(buf);
	/* NEEDSWORK: perhaps check for reasonable values? */
			unread_command_buf = 0;
#define MAX_DEPTH ((1<<DEPTH_BITS)-1)
		char *end;
static struct pack_idx_option pack_idx_opts;
	char str_dat[FLEX_ARRAY]; /* more */
	char *buf;
	set_die_routine(die_nicely);
			}

			write_branch_report(rpt, b);
#include "repository.h"
		if (parse_mapped_oid_hex(p, &oid, &p))

		struct object_id *t = &s->branch_tree.versions[1].oid;
	if ((idnum >> s->shift) < 1024) {
	if (oe && oe->pack_id == pack_id) {
	if (last_tag)
					oid_object_info(the_repository, &oid,
		/* cache it! */
	die("This version of fast-import does not support option: %s", option);
	fprintf(rpt, "  status      :");
/* Input stream parsing */
	/*
		hashcpy(e->versions[1].oid.hash, (unsigned char *)c);
	return c;
#include "object.h"
			return 0;
	if (!f)
	if (*slash1) {
	struct object_id *fromoid = object;
		e = find_mark(marks, parse_mark_ref_space(p));

	} else if (skip_prefix(feature, "export-marks=", &arg)) {
		check_unsafe_feature(feature, from_stream);
	}
	fputc('\n', stderr);
		oidcpy(&b->branch_tree.versions[0].oid, t);

		fprintf(stderr, "      atoms:     %10u\n", atom_cnt);
static void option_import_marks(const char *marks,

		*tail = n;
	struct ref_transaction *transaction;

			die("Missing space after SHA1: %s", command_buf.buf);


			die("Can't tag an empty branch.");
		 */
	}
{
		big_file_threshold = v;
	if (is_null_oid(&b->oid)) {
		all_packs[pack_id] = new_p;
	struct tree_content *newtree)
			if (fanout == 0xff) {

				die("Mark :%" PRIuMAX " not a commit", idnum);
		unsigned long size;
		;
	if (memcmp("tree ", buf, 5)
		if (strcmp("now", ltgt))
			pack_size += n;
				 * thrown away the tree entries needed to

		read_marks();
			release_tree_content_recursive(b->branch_tree.tree);


static int update_branch(struct branch *b)
		if (type < 0)
		die(_("Expected format name:filename for submodule rewrite option"));

	if (!buf)
		buf = read_object_with_reference(the_repository,
		free(buf);
		}
	}
	}
}
		active_branches = b;
}
static struct object_entry *dereference(struct object_entry *oe,
		struct commit *old_cmit, *new_cmit;
			die(_("Missing from marks for submodule '%s'"), fromp->string);
	struct recent_command *next;
		oidclr(&b->branch_tree.versions[0].oid);
		if (!oe)
	slash1 = strchrnul(p, '/');
static int tree_content_remove(
		die("cannot store index file");
	dump_marks();
	void *out, *delta;
	}

				 * to avoid modifying the preimage tree used

		uintmax_t len = strtoumax(data, NULL, 10);
			die("Invalid dataref: %s", command_buf.buf);
static void print_ls(int mode, const unsigned char *hash, const char *path)
	kh_value(sub_oid_map, it) = tooid;
	while (fanout) {


	struct branch *s;
	if (!mode) {
		else if (skip_prefix(command_buf.buf, "feature ", &v))
	fputs("Most Recent Commands Before Crash\n", rpt);
	for (rc = cmd_hist.next; rc != &cmd_hist; rc = rc->next) {
	if (!f) {
					release_tree_content_recursive(e->tree);
		 * in order to make sure the deletion actually takes effect,
	const char *endp;
		/* ok */
	if (mark)
	static const char *keep_msg = "fast-import";
		e->pack_id = MAX_PACK_ID;
	} else {
			dat->buf, dat->len,
				/*
		return xstrdup(path);
		parse_from_commit(b, buf, size);
	const char *v;
		parse_from_existing(b);
{

		fprintf(stderr, "Alloc'd objects: %10" PRIuMAX "\n", alloc_count);
	struct object_id *oid = &root->versions[1].oid;
	unsigned int delta_depth;

	char *endptr;
static void cycle_packfile(void)
	s = s_uq.buf;
			if (*slash1 && !S_ISDIR(e->versions[1].mode))
		leaf.tree);
			fflush(pack_edges);
		if (*p)


			    oid_to_hex(&merge_list->oid));
{
	} else if (skip_prefix(option, "big-file-threshold=", &option)) {
				load_tree(e);
	for (i = 1; i < argc; i++) {
	struct tree_entry *e;
	for (i = 0; i < t->entry_count; i++) {
		if (!strcmp("blob", command_buf.buf))
 *
		    "type %s\n"
	 * plus the terminating NUL.  Note that there is no slash at the end, so
	struct branch *s;
	/* ensure the branch is active/loaded */
	}
		e->versions[0].mode = e->versions[1].mode;
	tree_content_set(&b->branch_tree, p, &oid, mode, NULL);
	b->name = pool_strdup(name);
/* Branch data */

		    oid_to_hex(&oid), type_name(type), t->name);
			encoding);
						return 1;
{
		die("Corrupt mode: %s", command_buf.buf);
{
{
		strbuf_addf(&line, "%06o %s %s\t",
{
		if (p != uq.buf) {
		if (command_buf.buf[0] == '#')
	ltgt++;
				 * If p names a file in some subdirectory, and a
	int pack_fd;
	fprintf(rpt, "%s:\n", b->name);
	}
		} else if (!get_oid(from, &n->oid)) {
	size_t in_sz = 64 * 1024, out_sz = 64 * 1024;
	} else if (skip_prefix(feature, "rewrite-submodules-from=", &arg)) {
		oidcpy(&oid, &oe->idx.oid);
	d->delta_depth = s->delta_depth;
		p = uq.buf;
	}



		e->active_next_branch = NULL;
	unsigned int hc = hc_entries(f->entry_capacity);
		else if (!strcmp("done", command_buf.buf))
			break;
 * file and is referencing an object that this fast-import process
	*modep = mode;
#define NO_DELTA S_ISUID
							       &size, &n->oid);
			strbuf_swap(&last->data, dat);
		unsigned int n = tree_entry_alloc;
	if (!(root->versions[0].mode & NO_DELTA))
			if (e->last_commit < min_commit) {
	}


		else if (skip_prefix(command_buf.buf, "C ", &v))

		oidclr(&b->branch_tree.versions[1].oid);
struct avail_tree_content {
	strbuf_reset(b);
	}
	}
	end_packfile();
		if (!skip_prefix(a, "--", &a))
}

	} else if (skip_prefix(feature, "rewrite-submodules-from=", &arg)) {
		rollback_lock_file(&mark_lock);
	switch (oe->type) {
	tree_content_set(&b->branch_tree, d,
		if(!import_marks_file_from_stream)
 * oe must not be NULL.  Such an oe usually comes from giving
	unsigned int i, n;
		}
	struct string_list_item *fromp, *top;
static void parse_new_commit(const char *arg)
static struct recent_command *cmd_tail = &cmd_hist;
#endif
			rc->next = cmd_hist.prev;
			parse_get_mark(v);
	parse_original_identifier();
			size_t n = fread(in_buf, 1, cnt, stdin);
	unsigned int h = oid->hash[0] << 8 | oid->hash[1];
	struct pack_header hdr;
static const char *get_mode(const char *str, uint16_t *modep)
	} data;
			}
		max_packsize = packsizelimit_value;
}
	cat_blob_fd = (int) n;
static void build_mark_map(struct string_list *from, struct string_list *to)
static void release_tree_content_recursive(struct tree_content *t)
		encoding = xstrdup(v);
			size_t n = s.next_out - out_buf;
		die("Missing dest: %s", command_buf.buf);
{
				   0, msg, &err) ||
			git_deflate_init(&s, pack_compression_level);
	for (f = avail_tree_table[hc]; f; l = f, f = f->next_avail)
	}
				parse_and_store_blob(&last_blob, &oid, 0);
}
 */
	struct pack_idx_entry idx;

{
		    get_oid_hex(buf + strlen("tree "), oid))
				 * But after replacing the subdir with a
static struct last_object last_blob = { STRBUF_INIT, 0, 0, 0 };
		duplicate_count_by_type[OBJ_BLOB]++;
}
static int read_next_command(void)
		"committer %s\n",
			die("Garbage after dest in: %s", command_buf.buf);

	uintmax_t mark)
			continue;
	char path[GIT_MAX_RAWSZ * 3];

	it = kh_put_oid_map(sub_oid_map, *fromoid, &ret);
			warning("minimum max-pack-size is 1 MiB");
		if (skip_prefix(a, "cat-blob-fd=", &a)) {
	hdr.hdr_entries = 0;

			option_cat_blob_fd(a);
	const char *from;

		if (!git_parse_ulong(option, &v))
	 * "feature" lines at the start of the stream (which allows the command
		; /* Don't die - this feature is supported */
	/* get-mark SP <object> LF */

		option_rewrite_submodules(arg, &sub_marks_to);
		(*count)++;
struct object_entry {

			die("Can't load tree %s", oid_to_hex(oid));

			e++;
		if (!e)
		       e->name->str_len);
		    type_name(type), (uintmax_t)size);
	return fanout;
			warning("max-pack-size is now in bytes, assuming --max-pack-size=%lum", v);
		/*
			fputs(oid_to_hex(&tg->oid), rpt);
static void parse_argv(void)
		if (commit_oe->type != OBJ_COMMIT)
	n = slash1 - p;
	 * When loading a branch, we don't traverse its tree to count the real
				       export_marks_file);

	}
	char *loc = git_pathdup("fast_import_crash_%"PRIuMAX, (uintmax_t) getpid());
		*end = 0;

	atom_cnt++;

}
		read_next_command();
{
	ltgt = ltgt + 1 + strcspn(ltgt + 1, "<>");
			if (!s && feof(stdin))
	return strbuf_detach(&name, NULL);
static struct atom_str *to_atom(const char *s, unsigned short len)
			}
		if (parse_mapped_oid_hex(p, &oid, &p))
	strbuf_reset(&uq);
	the_hash_algo->update_fn(&c, dat->buf, dat->len);

	}
static unsigned long max_depth = 50;
		const char *a = global_argv[i];
{
	off_t offset;
/* Configured limits on output */
	struct atom_str *c;
		    get_oid_hex(buf + strlen("object "), oid))
	const struct object_id *oid,
		return;
static int parse_data(struct strbuf *sb, uintmax_t limit, uintmax_t *len_res)
				hex_oid, tmp_hex_oid_len,
			v *= 1024 * 1024;
		last_blob.depth = oe->depth;
			if (type < 0)
		install_packed_git(the_repository, new_p);
		} else if (!top || !top->util) {
	if (!n) {

static void parse_original_identifier(void)

}
			/* This is a note entry */
{
		hdr[pos] = ofs & 127;
		option_active_branches(option);
static unsigned int object_entry_alloc = 5000;
static struct mem_pool fi_mem_pool =  {NULL, 2*1024*1024 -
	e = avail_tree_entry;
		delta_count_attempts_by_type[type]++;
		hashwrite(pack_file, hdr + pos, sizeof(hdr) - pos);
	struct tree_entry *entries[FLEX_ARRAY]; /* more */
				callback(base + k, m->data.marked[k], p);
		 * back to read a previously written object.  If an old
				 * make a delta against it.
					struct object_id *oid)
	if (*ltgt != '<')
		tmp_fullpath_len = fullpath_len;
	b->num_notes = 0;
	fprintf(rpt, "  old tree    : %s\n",
		last->offset = e->idx.offset;
	}
			const char *v;
	}
		tmp_hex_oid_len = hex_oid_len + e->name->str_len;
	while (skip_prefix(command_buf.buf, "merge ", &from)) {
}
{

		fullpath[tmp_fullpath_len] = '\0';
	if (s) {
			if (!t->next_tag)
	for_each_mark(marks, 0, dump_marks_fn, f);
				rc_free = rc->next;
	unsigned char hdr[96];
}
	b->end = b->entries + cnt;
				die("Not a valid object: %s", from);
	 * the number of slashes is one less than half the number of hex
		if (S_ISDIR(mode))
		tmp_fullpath_len += e->name->str_len;
		else if (skip_prefix(command_buf.buf, "reset ", &v))

	struct object_id oid, commit_oid;
	git_deflate_init(&s, pack_compression_level);
	/* original-oid ... */
	} else {
	}
				 * We need to leave e->versions[0].sha1 alone
		 * footer is present at the file end and must promise
	while (e) {
	*((void**)e) = avail_tree_entry;
static unsigned int pack_id;
static int import_marks_file_from_stream;
	return cnt < avail_tree_table_sz ? cnt : avail_tree_table_sz - 1;
static char *keep_pack(const char *curr_index_name)


	if (e->tree && is_null_oid(&e->versions[1].oid))
	d = new_tree_content(s->entry_count);

	 */
#ifndef SIGUSR1	/* Windows, for example */

			note_change_n(v, b, &prev_fanout);
				if (!S_ISDIR(mode)
static kh_oid_map_t *sub_oid_map;
	unsigned char *in_buf = xmalloc(in_sz);
	struct tree_entry *root,
		p = uq.buf;
	if (p == pack_data && p->pack_size < (pack_size + the_hash_algo->rawsz)) {

			}
{
	} else if (skip_prefix(option, "active-branches=", &option)) {
	endp++;
		avail_tree_entry = e;
static void parse_from_existing(struct branch *b)
		*old_fanout = convert_num_notes_to_fanout(b->num_notes);
	} else if (!strcmp(option, "allow-unsafe-features")) {
	}
	 * The size of path is due to one slash between every two hex digits,
	static struct strbuf uq = STRBUF_INIT;
		S_ISDIR(mode) ? tree_type :
	fputs("-----------------\n", rpt);
	keep_fd = odb_pack_keep(name.buf);

		a->name->str_dat, a->name->str_len, a->versions[0].mode,
	free(out);

	c = buf;
		die("Branch name doesn't conform to GIT standards: %s", name);
		if (e->branch_tree.tree) {
static void release_tree_entry(struct tree_entry *e)

		break;
	struct last_object lo = { STRBUF_INIT, 0, 0, /* no_swap */ 1 };

}
				return 1;

	}
			if (term_len == command_buf.len

}
	struct tree_content *t;
		return NULL;
	return e;
		if (a->tree && is_null_oid(&b->versions[1].oid))
		if (*(*p)++ != ' ')
}
			del++;
		oid_to_hex(&b->branch_tree.versions[1].oid));
		delta = diff_delta(last->data.buf, last->data.len,

	free(encoding);
	struct tree_entry *root = NULL;
static int require_explicit_termination;
	strbuf_addch(&new_data, '\n');
		if (parse_mapped_oid_hex(*p, &oid, p))
	return b;
		load_tree(root);
	write_or_die(keep_fd, keep_msg, strlen(keep_msg));
		    oid_to_hex(oid), type_name(type));
	} else if (!get_oid(objectish, &b->oid)) {
};
		die("Can't read object %s", oid_to_hex(oid));
			delete_ref(NULL, b->name, NULL, 0);
		ungetc(term_char, stdin);
	struct hash_list *list = NULL, **tail = &list, *n;
	} else {
		delta = NULL;
				/* Counting mode, no rename */

		usage(fast_import_usage);
		strbuf_reset(&ref_name);
	} else if (skip_prefix(feature, "rewrite-submodules-to=", &arg)) {

		fputs(" dirty", rpt);
		case Z_BUF_ERROR:
		struct tree_entry *e = t->entries[i];
						&& oideq(&e->versions[1].oid, oid))
		fprintf(stderr, "      marks:     %10" PRIuMAX " (%10" PRIuMAX " unique    )\n", (((uintmax_t)1) << marks->shift) * 1024, marks_set_count);
		struct packed_git *new_p;
{
	const char *d;
		oe = insert_object(oid);
		struct hash_list *next = merge_list->next;
		relative_marks_paths = 0;
		struct object_entry *commit_oe = find_mark(marks, commit_mark);

	strbuf_reset(&new_data);
	the_hash_algo->init_fn(&c);
	new_fanout = convert_num_notes_to_fanout(b->num_notes);
	struct object_entry *e;
	tmpfile = write_idx_file(NULL, idx, object_count, &pack_idx_opts,
			cmd_tail = rc;
static char *parse_ident(const char *buf)
	unsigned int entry_count;

static unsigned int hc_entries(unsigned int cnt)
	uintmax_t mark)

			continue;
		oe = find_object(&oid);
		; /* do nothing; we have the feature */

	prev_fanout = convert_num_notes_to_fanout(b->num_notes);
			die("Garbage after path in: %s", command_buf.buf);


		die_errno("cannot truncate pack to skip duplicate");
static void load_branch(struct branch *b)
	if (*src != '-' && *src != '+')
					(unsigned long)(length - n));
	fputc('\n', rpt);
	FREE_AND_NULL(pack_data);
			max_depth = MAX_DEPTH;
	s.avail_out = git_deflate_bound(&s, s.avail_in);
	build_mark_map(&sub_marks_from, &sub_marks_to);
			file_change_m(v, b);
			fullpath[tmp_fullpath_len++] = '/';
{
	fputc('\n', rpt);
		uintmax_t commit_mark = parse_mark_ref_eol(p);
	while (len-- > 0)
		if (*endp)
			die("Invalid rfc2822 date \"%s\" in ident: %s", ltgt, buf);
		die("Object %s is a %s but a blob was expected.",
	fp = fopen(f, "r");
		die_errno("failed to write keep file");

		tree_content_replace(&b->branch_tree, &oid, mode, NULL);
{
		+ cnt * sizeof(struct object_entry));
struct tree_content;
				min_commit = e->last_commit;
{
	for (i = 0; i < t->entry_count; i++) {
{
	struct object_entry_pool *next_pool;
			} else
	return r;

	/* No such object? */
		size_t term_len = command_buf.len - (data - command_buf.buf);
		}
		}
	for (t = first_tag; t; t = t->next_tag)
		oid_to_hex(&b->branch_tree.versions[0].oid));
		force_update = 1;
		mktree(t, 0, &old_tree);
static void release_tree_entry(struct tree_entry *e);
	/* build the tag object */

{
				rc = cmd_hist.next;
	uint16_t mode, inline_data = 0;
	mark = parse_mark_ref(p, &end);
	if (!root->tree)
		object_count++;
				type_name(expected), type_name(type),
				goto del_entry;
		p->pack_size = pack_size + the_hash_algo->rawsz;
		fputs(rc->buf, rpt);
	static struct strbuf uq = STRBUF_INIT;
		free(buf);
		free(term);
	fputc('\n', rpt);
		struct tag *t;
	return e;
	strbuf_addbuf(&new_data, &msg);
		off_t ofs = e->idx.offset - last->offset;
		&leaf.versions[1].oid,
{
	if (is_null_oid(&oid))
	}
		lo.depth = t->delta_depth;
			   type_name(type), (unsigned long)dat->len) + 1;
	const char *arg;
	}

}
	if (!fp)
		if (!strcmp(arg, "--allow-unsafe-features"))
				command_buf.buf);

};
{
	}
 * We abuse the setuid bit on directories to mean "do not delta".
	struct branch *b;
	} else if (!strcmp(option, "stats")) {
	for (i = 0; i < t->entry_count; i++) {
		if (l)
	if (is_null_oid(&b->oid)) {
	/* Determine if we should auto-checkpoint. */
}
	if (!is_null_oid(&root->versions[1].oid))
		for (;;) {

/* Signal handling */

		s.avail_in = deltalen;
	if (!S_ISDIR(mode))
	char hex_oid[GIT_MAX_HEXSZ], path[GIT_MAX_HEXSZ + (GIT_MAX_HEXSZ / 2) - 1 + 1];
	struct packed_git *p = all_packs[oe->pack_id];
	pack_edges = xfopen(edges, "a");
		whenspec = WHENSPEC_RAW;
	case S_IFREG | 0644:
	} else {

{
static struct branch *active_branches;
		|| (pack_size + PACK_SIZE_THRESHOLD + s.total_out) < pack_size) {
	const char *endp;
	c = idx;

		cur_active_branches,
	/* See show_tree(). */
		oidcpy(&e->versions[1].oid, oid);

}
				 */

		if (e->name->str_len == n && !fspathncmp(p, e->name->str_dat, n)) {
	else if (e->tree)
	} else if (find_sha1_pack(oid.hash,
		die("Not a valid commit: %s", oid_to_hex(&b->oid));
			die("Unknown mark: %s", command_buf.buf);
	}
			if (!seen_data_command
 *   idnum ::= ':' bigint;
	struct tree_entry *a = *((struct tree_entry**)_a);
	struct object_entry *myoe;
	const char *p,
		 * and we have modified it since the last time we scanned

#include "pack.h"
	struct tree_entry leaf;

	errno = 0;
		else if (*from == ':') {
			file_change_deleteall(b);
		}
	e = new_object(oid);
	if (b->pack_id < MAX_PACK_ID)
		if (!s->data.sets[i]) {

};
static void file_change_deleteall(struct branch *b)
			oidcpy(&n->oid, &oe->idx.oid);
	strbuf_addch(&new_data, '\n');
static void parse_alias(void)
	struct object_entry *oe,
/* Our last blob */
		else if (skip_prefix(command_buf.buf, "ls ", &v))
	uintmax_t num_notes = 0;
		const char *arg = argv[i];
	if (blocks->next_free == blocks->end)
			fputc('\n', rpt);
			hashwrite(pack_file, out_buf, n);
				if (t->pack_id == pack_id)
			}
		if (t->pack_id == id)

			fputs("* ", rpt);
			return 0;
	}
	hdrlen = xsnprintf((char *)hdr, sizeof(hdr), "%s %lu",
		read_next_command();

		else if (skip_prefix(command_buf.buf, "R ", &v))
	case OBJ_TAG:
		show_stats = 0;
{
{
			die("Git links cannot be specified 'inline': %s",
};

}
	if (!strcmp(fmt, "raw"))
			len -= n;
static void unload_one_branch(void)


 * length of one object ID.
	const unsigned hexsz = the_hash_algo->hexsz;
		read_next_command();
	if (!git_config_get_int("fastimport.unpacklimit", &limit))
			die("Not a blob (actually a %s): %s",
		c += the_hash_algo->rawsz;

	if (lseek(p->pack_fd, 0, SEEK_SET) < 0)
		t->entries[t->entry_count++] = e;
			die("Invalid path: %s", command_buf.buf);

}
	t = (struct tree_content*)f;
		root = new_tree_entry();
	struct hash_list *next;
{
	static struct strbuf msg = STRBUF_INIT;
}
{
}
static struct atom_str **atom_table;


/* Tree management */
		if (b->delete)


	} else {
	const char *c;
	unsigned int i, j, del;
	e->idx.offset = pack_size;
static struct tree_content *dup_tree_content(struct tree_content *s)
	t = root->tree;
			continue;
	struct object_id oid;
{
	pack_data = p;
{
				  get_all_packs(the_repository))) {
#include "run-command.h"
static uintmax_t do_change_note_fanout(
					}
		fprintf(stderr, "      blobs  :   %10" PRIuMAX " (%10" PRIuMAX " duplicates %10" PRIuMAX " deltas of %10" PRIuMAX" attempts)\n", object_count_by_type[OBJ_BLOB], duplicate_count_by_type[OBJ_BLOB], delta_count_by_type[OBJ_BLOB], delta_count_attempts_by_type[OBJ_BLOB]);
	}
		free(idx_name);
		buf = read_object_file(oid, &unused, &size);
	memset(&b, 0, sizeof(b));
		return;

	read_next_command();

			p = uq.buf;
	}
	return strbuf_detach(&ident, NULL);
	set_checkpoint_signal();
static void start_packfile(void)
				break;

	if ((max_packsize

				 pack_data->hash);

		if (!strcmp(name, b->name))
#include "commit-reach.h"
			strbuf_release(&last->data);
		strbuf_addf(&new_data,
static void *find_mark(struct mark_set *s, uintmax_t idnum)
		if (!oe) {
	struct object_id old_oid;
		 * we need to remove the tag from our list of tags to update.
}
		die(_("Expected 'to' command, got %s"), command_buf.buf);

		e = find_object(&oid);
	if (!git_config_get_ulong("pack.packsizelimit", &packsizelimit_value))
static unsigned long branch_count;
	if (b)
				backup_leaf = NULL;
}


		unpack_limit = limit;
 * Given a pointer into a string, parse a mark reference:
		die("Got option command '%s' after data command", option);
	if (*endptr == p)
static unsigned int atom_table_sz = 4451;
static void insert_object_entry(struct mark_set *s, struct object_id *oid, uintmax_t mark)
	return r;
static void invalidate_pack_id(unsigned int id)
	char realpath[GIT_MAX_HEXSZ + ((GIT_MAX_HEXSZ / 2) - 1) + 1];
	struct tree_entry_ms {
static struct string_list sub_marks_from = STRING_LIST_INIT_DUP;
	e->idx.crc32 = crc32_end(pack_file);
			num_notes += do_change_note_fanout(orig_root, e,

static void alloc_objects(unsigned int cnt)
static uintmax_t parse_mark_ref(const char *p, char **endptr)
		oe->idx.offset = 1;
	fputs("Active Branch LRU\n", rpt);
		else if (!strcmp("checkpoint", command_buf.buf))
 * Complain if the following character is not what is expected,
	r->delta_depth = t->delta_depth;
		t->delta_depth = myoe->depth;
	struct strbuf ident = STRBUF_INIT;
	fprintf(rpt, "fast-import crash report:\n");
	if (!parse_objectish_with_prefix(&b, "to "))
		 * we don't actually create the footer here.
		}
		else
			parse_alias();
					 cur_pack_oid.hash, pack_size);
	t->name = pool_strdup(arg);
			parse_new_tag(v);
						 &b->oid, commit_type, &size,
	unpack.git_cmd = 1;
static void insert_mapped_mark(uintmax_t mark, void *object, void *cbp)

	else
	if (e->tree)
				oid_to_hex(&old_oid));
{
			parse_reset_branch(v);
		e->idx.crc32 = crc32_end(pack_file);
	if (!*endp)
	char *tagger;

		if (myoe->type != OBJ_TREE)
			l = e;
		if (size < hexsz + strlen("object ") ||
	free(in_buf);
							oid_to_hex(&b->oid));
	else if (!git_config_get_int("transfer.unpacklimit", &limit))
	uintmax_t mark;
		cycle_packfile();
	transaction = ref_transaction_begin(&err);
	struct tree_entry *a, *b;
	if (rename)
	if (root->tree)

	struct object_id oid;
			parse_feature(v);
	unsigned long hdrlen, deltalen;
	fputs(err, rpt);
static struct object_entry *new_object(struct object_id *oid)
{

/* Where to write output of cat-blob commands */
	case OBJ_COMMIT:
	atom_table = xcalloc(atom_table_sz, sizeof(struct atom_str*));
	return parse_objectish(b, from);
#include "commit.h"
		for (b = branch_table[lu]; b; b = b->table_next_branch)
static void end_packfile(void)
	}
/* Table of objects we've written. */
	/* to ... */
	if (mark)
		fprintf(stderr, "\n");


			if (!e->tree)
	b = mem_pool_calloc(&fi_mem_pool, 1, sizeof(struct branch));
	fputc('\n', stdout);
				break;
		struct object_id oid;
	e = insert_object(&oid);
 */
			if (!*slash1)

		uint16_t mode;
			last->offset = 0;
		struct object_id cur_pack_oid;

static unsigned long branch_table_sz = 1039;
					return 0;
		b->num_notes--;


	unsigned int pack_id;
	/* tagger ... */
			unread_command_buf = 1;
	if (!unquote_c_style(&uq, p, &endp)) {
		unsigned long v;
		f = mem_pool_alloc(&fi_mem_pool, sizeof(*t) + sizeof(t->entries[0]) * cnt);
			strbuf_addstr(&uq, p);
		leaf.versions[1].mode,
static unsigned int cmd_save = 100;
		leaf->tree = dup_tree_content(e->tree);
	if (!b || root != &b->branch_tree)
	const char *name;
				parse_from_commit(b, buf, size);
		oidcpy(&b->branch_tree.versions[1].oid, t);
static void cat_blob_write(const char *buf, unsigned long size)


	}
			if (oe->type != OBJ_COMMIT)
	if (type <= 0) {
}
{
	global_argc = argc;
}
 * created by fast-import.
	if (import_marks_file)
static void dump_marks_fn(uintmax_t mark, void *object, void *cbp) {
	}
#define DEPTH_BITS 13
	clear_delta_base_cache();
struct tag {
	uintmax_t from_mark = 0;
	const uint16_t mode,
}
				for (b = branch_table[i]; b; b = b->table_next_branch) {
	}
			allow_unsafe_features = 1;
			total_count += object_count_by_type[i];
			s.avail_out = git_deflate_bound(&s, s.avail_in);
	/* Git does not track empty, non-toplevel directories. */
 * instance did not write out to a packfile.  Callers must test for
		}
		if (parse_date(ltgt, &ident) < 0)
				if (S_ISDIR(e->versions[0].mode))
		memset(oid.hash, 0, sizeof(oid.hash));
				command_buf.buf);
}
	strbuf_reset(&line);
};
	if (!force_update && !is_null_oid(&old_oid)) {
	parse_data(&msg, 0, NULL);
		if (max_depth > MAX_DEPTH)
	if (!next_mark)
	if (b == s)

		 */
	memcpy(c->str_dat, s, len);
	if (tree_content_remove(&b->branch_tree, path, NULL, 0))
del_entry:
	unsigned long lu;
struct object_entry_pool {
	unsigned char c;
	const char *endp;
			failure |= error("%s", err.buf);
		free(buf);
		return;
			}
		e = t->entries[i];
		die_errno("Write to frontend failed");
}
		while (read_next_command() != EOF) {
	for (i = 0; i < branch_table_sz; i++) {
	fputc('\n', rpt);
	fputs("fatal: ", rpt);
		if (!is_null_oid(&root->versions[1].oid))
	case S_IFDIR:

	fputs("fatal: ", stderr);
		if (!in_merge_bases(old_cmit, new_cmit)) {
	tree_content_remove(&b->branch_tree, p, NULL, 1);
{
	release_tree_content(t);
	unsigned int i = 0, j = 0;
				prev->next_tag = t->next_tag;

	}
	if (!b)
	static struct strbuf buf = STRBUF_INIT;
	struct hashfile_checkpoint checkpoint;

		}
		enum object_type type = oid_object_info(the_repository, &oid,
	return d;

{
	hdr.hdr_signature = htonl(PACK_SIGNATURE);
			s = s->data.sets[i];
			die("Directories cannot be specified 'inline': %s",
		/* The object is stored in the packfile we are writing to
	} else if (!strcmp(feature, "alias")) {
	s = lookup_branch(from);
	}
		failure |= error_errno("Unable to write file %s",
			fputc('\n', pack_edges);
	}
	static struct strbuf line = STRBUF_INIT;


				 * So let's just explicitly disable deltas
{
	}
	return mark;
{
		fprintf(stderr, "Total branches:  %10lu (%10lu loads     )\n", branch_count, branch_load_count);
	 * command-line options that impact how we interpret the feature lines.
		enum object_type unused;
		uintmax_t mark;
 * Parse the mark reference, demanding a trailing space.  Return a
{
	release_tree_content_recursive(b->branch_tree.tree);
			&leaf.versions[1].oid,
{
static struct strbuf new_tree = STRBUF_INIT;
{
{
	char *encoding = NULL;
	const char *type =
	if (parse_data(&buf, big_file_threshold, &len))
	while ((idnum >> s->shift) >= 1024) {
		failure |= error("%s", err.buf);
	unsigned int hc = hc_str(name, strlen(name)) % branch_table_sz;
{
		return 1;
	fputs("  last pack   : ", rpt);
static struct mark_set *marks;
		if (e->versions[1].mode) {
	if (n > (unsigned long) INT_MAX)
	fputs("  pos  clock name\n", rpt);
		oidcpy(&root->versions[1].oid, &e->idx.oid);
	read_next_command();
		load_branch(b);
static unsigned int tree_entry_alloc = 1000;
			s.next_in = (void *)dat->buf;
		oe = find_object(&oid);
	struct object_entry *e = object;
	}
		/* Print the boundary */
	fprintf(rpt, "    at %s\n", show_date(time(NULL), 0, DATE_MODE(ISO8601)));
	e->versions[1].mode = 0;
	FLEX_ALLOC_STR(p, pack_name, tmp_file.buf);

	/* We can't carry a delta across packfiles. */
	if (!relative_marks_paths || is_absolute_path(path))
			die("Mark :%" PRIuMAX " not a commit", idnum);

	die("This version of fast-import does not support feature %s.", feature);
						oidclr(&root->versions[1].oid);
	return tmpfile;
		break;
	switch (mode) {

	mark = parse_mark_ref(*p, &end);
/* Stats and misc. counters */
	struct object_entry entries[FLEX_ARRAY]; /* more */
	export_marks_file = make_fast_import_path(marks);

static struct tag *first_tag;
				&& !strcmp(term, command_buf.buf))
		break;
			oidcpy(&e->versions[0].oid, &e->versions[1].oid);


		}
		&& (pack_size + PACK_SIZE_THRESHOLD + s.total_out) > max_packsize)
				&leaf.versions[1].oid,
		unread_command_buf = 0;
			die("object not found: %s", oid_to_hex(oid));
	if (!oe)
		static struct strbuf uq = STRBUF_INIT;
	e = blocks->next_free++;

	}

				return EOF;
	if (!zombie) {
				&& !starts_with(command_buf.buf, "feature ")
	oidcpy(&b->branch_tree.versions[0].oid,
}
					 pack_data->pack_name, object_count,
 * the standard read_sha1_file() when it happens.
	if (skip_prefix(command_buf.buf, "committer ", &v)) {
}
	FILE *f = fopen(import_marks_file, "r");

	struct atom_str *name;
	struct branch *b;
		if (rc->next == &cmd_hist)


	}
	FILE *f = cbp;
	return 1;
		return -1;
	fputs("  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n", rpt);
		if (!e->versions[1].mode ||
	last_blob.offset = 0;
	ltgt++;
				 * for the subtree.
	strbuf_addf(&new_data,
	unsigned int entry_capacity; /* must match tree_content */
	fputs("Marks\n", rpt);
	object_count_by_type[type]++;
		else if (skip_prefix(command_buf.buf, "get-mark ", &v))
		die("Expected from command, got %s", command_buf.buf);
		uintmax_t idnum = parse_mark_ref_eol(objectish);

	unsigned long size;

			failure |= update_branch(b);
	}

}
#define PACK_ID_BITS 16
		fprintf(rpt, "%u", b->pack_id);
	unsigned int i, tmp_hex_oid_len, tmp_fullpath_len;
		ALLOC_ARRAY(e, n);
	start_packfile();

	}
static void parse_cat_blob(const char *p);
	if (errno || endp == src + 1 || *endp || 1400 < num)
{
}
				break;

		root->tree = t = grow_tree_content(t, t->entry_count);
}
	hashwrite(pack_file, out, s.total_out);
static int parse_objectish(struct branch *b, const char *objectish)
		next_mark = 0;
{
		if (parse_one_option(a))
	}
	if (b->num_notes == 0 && *old_fanout == 0) {
	if (!buf)
			die("Not a tree: %s", oid_to_hex(oid));
		if (oe->type != OBJ_COMMIT)
		s.next_in = delta;
	struct lock_file mark_lock = LOCK_INIT;
}
	struct object_id oid;

				leaf.versions[1].mode,
		unload_one_branch();
		if (is_null_oid(&s->oid))
	if (pack_edges)
		if (delta) {
			return e;
	parse_original_identifier();

				last_tag = prev;
#include "lockfile.h"
		for_each_mark(marks, 0, dump_marks_fn, rpt);
	FILE *rpt = fopen(loc, "w");
	b = lookup_branch(arg);
	struct strbuf ref_name = STRBUF_INIT;
	static int running;

{
static void stream_blob(uintmax_t len, struct object_id *oidout, uintmax_t mark)
static int cat_blob_fd = STDOUT_FILENO;
	} else {
	struct tree_content *d;
static void file_change_cr(const char *s, struct branch *b, int rename)
}
	branch_table = xcalloc(branch_table_sz, sizeof(struct branch*));
	if (b->delete && skip_prefix(b->name, "refs/tags/", &tag_name)) {
/* Atom management */
	}
	git_zstream s;
static void parse_and_store_blob(
	if (pack_edges)
static void read_mark_file(struct mark_set *s, FILE *f, mark_set_inserter_t inserter)
	ms = xcalloc(1, sizeof(*ms));
	it = kh_get_oid_map(sub_oid_map, *oid);
	d = endp;
	struct sigaction sa;
		oidcpy(&commit_oid, &commit_oe->idx.oid);
	char line[512];
}
	cat_blob_write(line.buf, line.len);
	if (write_in_full(cat_blob_fd, buf, size) < 0)
}
	skip_optional_lf();
		}
			if (e->pack_id == id)
	unsigned long packsizelimit_value;
{
						&& e->versions[1].mode == mode
static unsigned int atom_cnt;
		unsigned char fanout)
	const char *tmpfile;
		if (skip_prefix(command_buf.buf, "M ", &v))
	struct object_id *tooid = find_mark(cbp, mark);
	oidclr(&e->versions[1].oid);
	slash1 = strchrnul(p, '/');
static struct tag *last_tag;

			rc = rc_free;
{
		 * the packfile as the core unpacker code assumes the
	}
	if (e->idx.offset) {

		option_export_marks(arg);
	enum object_type type;

		oe = find_mark(marks, parse_mark_ref_eol(p));
static void parse_from_commit(struct branch *b, char *buf, unsigned long size)
		oidclr(&b->oid);
		if (v < 8192) {
	oidcpy(&oid, &b->branch_tree.versions[1].oid);
	}
}
		fputc('\n', rpt);
	p = get_mode(p, &mode);
		enum object_type expected = S_ISDIR(mode) ?
static int import_marks_file_ignore_missing;
static void parse_checkpoint(void)
}

			parse_cat_blob(v);
		die("%s: argument must be a non-negative integer", option);
			return 0;

	return 0;

	unsigned long lu;
		}
	if (*p == ':') {
{


		if (type < 0)
	odb_pack_name(&name, pack_data->hash, "idx");
 * either a space or end of the string.
	*p = end;
	return e;
{

	}
			die("Missing space after source: %s", command_buf.buf);
	fputs("Inactive Branches\n", rpt);
	read_next_command();
					if (b->pack_id == pack_id)
	fputs("-----\n", rpt);
		e->idx.offset = 1; /* just not zero! */
	return run_command(&unpack);
	if (errno || endp == src || *endp != ' ')
	s.next_out = out = xmalloc(s.avail_out);
	struct tree_content *t;
		if (c->str_len == len && !strncmp(s, c->str_dat, len))


	 */
			die("corrupt mark line: %s", line);

		cur_active_branches++;
		}
		type = oe->type;
struct last_object {
	char *end;
	the_hash_algo->init_fn(&c);
			die("core git rejected index %s", idx_name);
	       &b->branch_tree.versions[1].oid);
{
		die("Missing < in ident string: %s", buf);
		die("Got feature command '%s' after data command", feature);
	}
	parse_mark();
	}
	struct recent_command *rc;

	max_depth = ulong_arg("--depth", depth);
	FILE *f;
	} else if (!strcmp(feature, "force")) {
	oidclr(&b->branch_tree.versions[1].oid);
static struct tree_content *new_tree_content(unsigned int cnt)

		if (type < 0)
	fprintf(rpt, "  cur tree    : %s\n",
			die("Not a valid commit: %s", p);
	default:
	free(author);
		fprintf(stderr, "%s statistics:\n", argv[0]);
}
	}
		hashwrite(pack_file, hdr, hdrlen);
		odb_pack_name(&name, p->hash, "keep");
};
	uintmax_t last_commit;
	 */
		root = &b->branch_tree;
			die("Missing space after SHA1: %s", command_buf.buf);
}
		 */
			unsigned long size;
		close(pack_data->pack_fd);
			if (pack_id == e->pack_id)
{
		if (pack_idx_opts.version > 2)
		fputc('\n', rpt);
	while (c != (buf + size)) {
	}
	}
	strbuf_release(&tmp_file);
			fputc(' ', rpt);
		die("--depth cannot exceed %u", MAX_DEPTH);
{
	khiter_t it;

	if (running || !pack_data)
			the_hash_algo->update_fn(&c, in_buf, n);
	struct tree_content *t;
	} else if (!strcmp(feature, "no-relative-marks")) {
		marks_set_count++;
				oidclr(&root->versions[1].oid);
{
static void parse_ls(const char *p, struct branch *b)
	parse_mark();
				type_name(oe->type), command_buf.buf);
	if (m->shift) {
	if (!buf || size < the_hash_algo->hexsz + 6)

static struct branch *lookup_branch(const char *name)
	} else if (!strcmp(feature, "relative-marks")) {

			store_tree(t->entries[i]);
			else {
		int i;
			b->tree = NULL;

	if (max_depth > MAX_DEPTH)
/*

	object_count++;
	} else {
			leaf.tree);
		if (*p++ != ' ')
	pack_file = hashfd(pack_fd, p->pack_name);
		} else {
				; /* nothing */
		object_count_by_type[OBJ_BLOB]++;

	fputc('\n', rpt);
	alloc_objects(object_entry_alloc);
	print_ls(leaf.versions[1].mode, leaf.versions[1].oid.hash, p);
			break;
			s.avail_out = out_sz;
	uint16_t mode = 0;

	fprintf(f, ":%" PRIuMAX " %s\n", mark, oid_to_hex(&e->idx.oid));
			}
	if (parse_one_feature(feature, 1))
#include "packfile.h"
}


		if (!buf || size < the_hash_algo->hexsz + 6)
static void set_checkpoint_signal(void)
	fputs("-------------------\n", rpt);
}


		; /* Don't die - this feature is supported */

		b->pack_id = pack_id;
	s = lookup_branch(p);
	}
		} else
			if (m->data.sets[k])
		if (*endp)
	the_hash_algo->final_fn(oid.hash, &c);
 * pointer to the space.
	static int stdin_eof = 0;
	struct tree_entry *e;
	}
	if (store_object(OBJ_TAG, &new_data, NULL, &t->oid, next_mark))
			die("Invalid SHA1 in commit: %s", command_buf.buf);
	 * This means that recently loaded notes refs might incorrectly have
		if (e->name->str_len == n && !fspathncmp(p, e->name->str_dat, n)) {
		&& cur_active_branches >= max_active_branches) {
			parse_progress();
	}
				b->name, oid_to_hex(&b->oid),


	while (cur_active_branches

		fputs(" loaded", rpt);
static void checkpoint_signal(int signo)
	s->data.marked[idnum] = oe;
		 *

	struct object_id oid;
							       &n->oid,
static int import_marks_file_done;
	import_marks_file_done = 1;
	if (seen_data_command)
}
		e->idx.offset = 1; /* just not zero! */
	if (oe->pack_id != MAX_PACK_ID) {	/* in a pack being written */
		 * another repository.
	    ref_transaction_commit(transaction, &err)) {
}
		path[i++] = '/';
	for (i = 0; i < s->entry_count; i++) {
	t->entry_count -= del;
		default:
		argv_array_push(&unpack.args, "-q");
static struct hashfile *pack_file;
		option_export_pack_edges(option);
		char *idx_name;
		if (t->entries[i]->versions[v].mode)
	if (s) {
	} else if (skip_prefix(feature, "import-marks-if-exists=", &arg)) {
	crc32_begin(pack_file);
	if (ref_transaction_commit(transaction, &err))
	e->idx.offset = 0;
	if (*end != '\0')
		release_tree_content_recursive(leaf.tree);
static void option_export_marks(const char *marks)
	return 1;
static unsigned char convert_num_notes_to_fanout(uintmax_t num_notes)
	} else if (skip_prefix(option, "export-pack-edges=", &option)) {
		buf = gfi_unpack_entry(oe, &size);
		return;
		if (size < hexsz + strlen("tree ") ||
		status = git_deflate(&s, len ? 0 : Z_FINISH);
	} else if (!get_oid(p, &commit_oid)) {
	import_marks_file_ignore_missing = ignore_missing;
	for (o = blocks; o; o = o->next_pool)
	COPY_ARRAY(r->entries, t->entries, t->entry_count);
	fputc('\n', rpt);
	struct mark_set *ms;
	}
							NULL);
		if (s)

	}
		fprintf(stderr, "       pools:    %10lu KiB\n", (unsigned long)((tree_entry_allocd + fi_mem_pool.pool_alloc) /1024));
			die("Mark :%" PRIuMAX " not a commit", commit_mark);

	} else if (skip_prefix(feature, "import-marks=", &arg)) {

	memcpy(leaf, e, sizeof(*leaf));
		}
		strbuf_reset(&line);
	struct tree_content *t;
}
			git_deflate_end(&s);
{
		return;
		 * Elsewhere, we call dump_branches() before dump_tags(),

{
		return 0;

		branch_load_count++;
		}
		if (parse_one_feature(a, 0))
				goto del_entry;
		goto done; /* Marks file does not exist */
		b = new_tree_entry();
	*count = 0;
		close(pack_data->pack_fd);
		parse_argv();
	git_hash_ctx c;
		 * NEEDSWORK: replace list of tags with hashmap for faster
	}
		tree_content_remove(&b->branch_tree, s, &leaf, 1);
			if (oe->pack_id != MAX_PACK_ID) {
static unsigned int show_stats = 1;
		while (n-- > 1) {
		oidcpy(&oid, &oe->idx.oid);
static void option_active_branches(const char *branches)
	struct tree_entry leaf = {NULL};
		if (unread_command_buf) {

	unsigned long *sizep)
	return base_name_compare(
						      type, dat->len);
	fputc('\n', rpt);
	strbuf_init(&command_buf, 0);
			    oid_to_hex(&b->oid));

	parse_data(&msg, 0, NULL);
		end_packfile();
	 * line to override stream data). But we must do an early parse of any
{
		; /* nothing */
		b->active_next_branch = active_branches;
	oidcpy(&b->branch_tree.versions[0].oid,
	struct pack_idx_entry **idx, **c, **last;
	}

			}
			if (stdin_eof)
				b->pack_id = MAX_PACK_ID;
			parse_ls(v, NULL);
	return str;
				*c++ = &e->idx;
		die("Can't create a branch from itself: %s", b->name);
 */
	branch_table[hc] = b;
		e->pack_id = pack_id + 1;
	const char *slash1;
/*
			die("Invalid dataref: %s", command_buf.buf);
		e->idx.offset = offset;
	 * number of notes (too expensive to do this for all non-note refs).
	if (finalize_object_file(pack_data->pack_name, name.buf))
	char *end;
		else if (!strcmp("alias", command_buf.buf))
				 * exist and need not be deleted.
		char *buf;
		die("Non-directories cannot have subtrees");
		tree_content_get(&b->branch_tree, s, &leaf, 1);
			free(buf);
	const char *name;

	if (!committer)
	}
			die("Invalid ref name or SHA1 expression: %s", from);
		if (type != expected)
	for (i = 0; i < t->entry_count; i++) {
	}
				  get_all_packs(the_repository))) {
	construct_path_with_fanout(oid_to_hex(&commit_oid), new_fanout, path);
		pack_size += hdrlen;
		}
	unsigned int i;
	if (*ltgt != '>')
		e->versions[1].mode = mode;
		/* mode SP type SP object_name TAB path LF */
	read_next_command();
	if (object_count) {
				/*
		oe->pack_id = MAX_PACK_ID;
		oe = find_mark(marks, parse_mark_ref_space(&p));
	if (S_ISDIR(mode) && is_empty_tree_oid(&oid) && *p) {
#include "tree.h"
}
		s = mem_pool_calloc(&fi_mem_pool, 1, sizeof(struct mark_set));
			|| get_oid_hex_any(end + 1, &oid) == GIT_HASH_UNKNOWN)
	d->entry_count = s->entry_count;
{
			if (!strcmp(t->name, tag_name))
	}
		load_tree(root);
	struct tree_content *tree;
	/*
static int tecmp0 (const void *_a, const void *_b)
	off_t offset;
		s.next_in = (void *)dat->buf;
static void dump_branches(void)
			file_change_cr(v, b, 1);
		&& dat->len > the_hash_algo->rawsz) {
static struct recent_command cmd_hist = {&cmd_hist, &cmd_hist, NULL};
	if (tagger)
		fputs(" active", rpt);
{
#include "khash.h"
			size_t cnt = in_sz < len ? in_sz : (size_t)len;
		fprintf(stderr, "---------------------------------------------------------------------\n");
		load_tree(root);
		while (n < length) {
		unsigned long size;

	if (safe_create_leading_directories_const(export_marks_file)) {
			continue;
	static struct strbuf s_uq = STRBUF_INIT;

		type = OBJ_COMMIT;
	struct tag *next_tag;
	return 0;
{
	fprintf(rpt, "    active_branches = %lu cur, %lu max\n",

			char *buf = read_object_with_reference(the_repository,
static NORETURN void die_nicely(const char *err, va_list params)
							  &old_oid, 0);
static int parse_objectish_with_prefix(struct branch *b, const char *prefix)
		char *buf = read_object_with_reference(the_repository,
		}
		c = get_mode(c, &e->versions[1].mode);

		/* Invoke change_note_fanout() in "counting mode". */
	memset(&leaf, 0, sizeof(leaf));

		return EOF;
		for (i = 0; i < ARRAY_SIZE(object_count_by_type); i++)
	return 0;
static struct packed_git **all_packs;
{
		if (s)
			/* There is no mem_pool_free(t) function to call. */
static int tecmp1 (const void *_a, const void *_b)
	} else if (*objectish == ':') {
	b = lookup_branch(arg);
	for (b = active_branches, lu = 0; b; b = b->active_next_branch)
{
		pack_size += hdrlen;
		die("Root cannot be a non-directory");
	uintmax_t k;
{
		/* We have to offer rawsz bytes additional on the end of
			struct recent_command *rc;
}
		free(loc);
{
				" (new tip %s does not contain %s)",
			}
	khiter_t it;
 *
		oidclr(&b->branch_tree.versions[0].oid);
/* Tag data */
	oidclr(&e->versions[0].oid);
		if (inline_data)
	/* We've already seen this object. */
		store_tree(&leaf);
		parse_and_store_blob(&last_blob, &oid, 0);
	read_mark_file(ms, fp, insert_oid_entry);
	REALLOC_ARRAY(all_packs, pack_id + 1);
				for_each_mark(m->data.sets[k], base + (k << m->shift), callback, p);

		struct object_id *oids[1024];
	return parse_objectish(b, base);
			warning("Not updating %s"


		strbuf_add(&s_uq, s, endp - s);
		return 0;
	if (!s->data.marked[idnum])
		last_tag->next_tag = t;
	oidclr(&root->versions[1].oid);
		tail = &n->next;
	while (fgets(line, sizeof(line), f)) {
	case S_IFLNK:
			return NULL;
		return 1;
				command_buf.buf);
static struct recent_command *rc_free;
		else if (skip_prefix(command_buf.buf, "cat-blob ", &v))
		uintmax_t min_commit = ULONG_MAX;
{
				       sizeof(struct mp_block), 0 };
		fputs("--------------\n", rpt);

	for (i = 0; i < t->entry_count; i++) {
	if (!*slash1 && !S_ISDIR(mode) && subtree)
			parse_cat_blob(v);
				 */
	const struct object_id *oid,
static int force_update;
			if (!tree_content_remove(orig_root, fullpath, &leaf, 0))
		delta_count_by_type[type]++;
	if (!git_config_get_ulong("pack.depth", &max_depth)) {
static size_t tree_entry_allocd;

	assert(*p == ':');
	for (i = 0; i < t->entry_count; i++) {
		 */
}
static void parse_new_tag(const char *arg)
	}
	if (b) {
static FILE *pack_edges;
	char *endp;

		if (e->name->str_len == n && !fspathncmp(p, e->name->str_dat, n)) {
		check_unsafe_feature("import-marks", from_stream);

				continue;
			if (!e->tree)
		for (t = first_tag; t; t = t->next_tag) {

	insert_mark(marks, next_mark, e);
	else
	return unpack_entry(the_repository, p, oe->idx.offset, &type, sizep);
#include "refs.h"


	if (oidout)
	} else {
	if (b->branch_tree.tree && !oideq(&oid, &b->branch_tree.versions[1].oid)) {
	for (t = first_tag; t; t = t->next_tag) {
	while (git_deflate(&s, Z_FINISH) == Z_OK)
			else {
			read_marks();
 * find_mark().  Callers must test for this condition and use
			stdin_eof = strbuf_getline_lf(&command_buf, stdin);
struct tree_entry {
static int parse_from(struct branch *b)
		--buf;
static void skip_optional_lf(void)
	t->entries[t->entry_count++] = e;
	tree_content_set(&b->branch_tree, path, &oid, S_IFREG | 0644, NULL);
			l->next_avail = f->next_avail;
}
		die("Can't load object %s", oid_to_hex(oid));
	 * when b->num_notes == 0. If the notes tree is truly empty, the
	fprintf(stderr, "fast-import: dumping crash report to %s\n", loc);
{
		e = t->entries[i];
		struct mark_set *sets[1024];
			b->tree = dup_tree_content(a->tree);
	git_pack_config();
	git_deflate_init(&s, pack_compression_level);
}
	for (lu = 0; lu < branch_table_sz; lu++) {
		strbuf_addstr(&line, "missing ");
		strbuf_addf(&new_data,
			die("%s not found: %s",

		read_next_command();
	if (last && last->data.len && last->data.buf && last->depth < max_depth
			if (!buf || size < the_hash_algo->hexsz + 6)
	FILE *fp;
		fprintf(rpt, "  exported to %s\n", export_marks_file);

			release_tree_content_recursive(e->branch_tree.tree);
		 * and updating the packfile length ensures we can read
	if (import_marks_file) {
	const char *data;
	oidcpy(&root->versions[1].oid, oid);
				parse_argv();
	struct object_entry *e;
static void write_branch_report(FILE *rpt, struct branch *b)
}
