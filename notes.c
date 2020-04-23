	static char path[FANOUT_PATH_MAX];
		notes_ref = GIT_NOTES_DEFAULT_REF;
			memset(object_oid.hash + len, 0, hashsz - len - 1);

 */
	cb_data.root = &root;
	n->next = p->next;
			type = PTR_TYPE_SUBTREE;
	}
		return; /* key mismatch, nothing to remove */
			 * is a direct relationship between subtree entries at
static struct leaf_node *note_tree_find(struct notes_tree *t,
		}
	return 0;
 * - Replace the matching leaf_node with a NULL entry (and free the leaf_node).
static void construct_path_with_fanout(const unsigned char *hash,
};
	while (fanout) {
	struct string_list split = STRING_LIST_INIT_NODUP;
{
	cb_data.nn_list = &(t->first_non_note);
{
 * Otherwise replace the int_node at the given index in the given parent node
{
		if (!raw)
	if (non_note_cmp(p, n) == 0) { /* n ~= p; overwrite p with n */
	string_list_clear(&display_notes_refs, 0);
	      int force, combine_notes_fn combine_notes)
	if (has_object_file(object_oid))
	if (note_path[note_path_len - 1] == '/') {

	struct note_delete_list *n;
		die("Failed to read notes tree referenced by %s (%s)",
				}
			p = tree->a[i];
 * subtree.
{

	/*
static inline int matches_tree_write_stack(struct tree_write_stack *tws,

		break;
	if (!raw) {
		if (flags & NOTES_PRUNE_VERBOSE)
 * used instead.
#include "refs.h"
			size_t len = prefix_len;
	struct leaf_node *l;
	if (!is_null_oid(cur_oid))
		return 0;
					path[path_len++] = '/';
static int notes_display_config(const char *k, const char *v, void *cb)
 * - ptr & 3 == 1 - pointer to next internal node - cast to struct int_node *
	ret = tree_write_stack_finish_subtree(tws);
	}
		free(msg);
 * Search to the tree location appropriate for the given leaf_node's key:

	n->sha1 = object_oid->hash;
		/*
{
}
	/* consolidate this tree level, and parent levels, if possible */
	void **p = note_tree_search(t, &tree, &n, key_sha1);
	       !note_tree_consolidate(parent_stack[i], parent_stack[i - 1],
		 */
	*show_notes = 1;
			}
	return 0;
static void format_note(struct notes_tree *t, const struct object_id *object_oid,
	if (!t->initialized)

	string_list_clear(&opt->extra_notes_refs, 0);
	strbuf_init(&root.buf, 256 * (32 + the_hash_algo->hexsz)); /* assume 256 entries */
	struct tree_write_stack root;
}

	struct leaf_node *l;
struct note_delete_list {
		else {
			free(l);

	void **p = note_tree_search(t, &tree, &n, entry->key_oid.hash);
 * - Else, create a new int_node, holding both the node-at-location and the
		}
	size_t note_path_len = strlen(note_path);
	else {
	if (is_null_oid(&l.val_oid)) /* no note was removed */
		unsigned char *hash)
	const char *hex_hash = hash_to_hex(hash);
		*tree = CLR_PTR_TYPE(p);
}
					free(entry);
int remove_note(struct notes_tree *t, const unsigned char *object_sha1)
			/* This is potentially the remainder of the SHA-1 */
			if (hex_to_bytes(object_oid.hash + len++, entry.path, 1))
				if (oideq(&l->val_oid, &entry->val_oid)) {
	return 0;
 * 16-array of pointers to its children.
 * A notes tree may contain entries that are not notes, and that do not follow

	}
	struct note_delete_list **l = (struct note_delete_list **) cb_data;
	unsigned long cur_len, new_len, buf_len;

handle_non_note:
	for (i = 0; i < n; i++) {
	string_list_clear(&sort_uniq_list, 0);
		combine_notes = t->combine_notes;
	t->prev_non_note = NULL;
 * How to consolidate an int_node:
 *   then unpack the subtree-to-be-inserted into the location.

	for (i = 0; display_notes_trees[i]; i++)
			construct_path_with_fanout(l->key_oid.hash, fanout,
	int flags;
		n++;
	struct non_note *n = p ? p->next : *d->nn_list;
	opt->use_default_notes = -1;
/* note: takes ownership of path string */
	struct non_note *p = t->prev_non_note, *n;
	char *data;
	    !is_encoding_utf8(output_encoding)) {
const char *default_notes_ref(void)
	string_list_split(list, data, '\n', -1);
#define CLR_PTR_TYPE(ptr)       ((void *) ((uintptr_t) (ptr) & ~3))
	found = note_tree_find(t, t->root, 0, oid->hash);

	return 0;
		if (is_null_oid(&entry->val_oid))
	}
	trees[counter] = NULL;
	 * The following is a simple heuristic that works well in practice:


	unsigned long linelen, msglen;
				path[path_len] = '\0';
		}
	*p = SET_PTR_TYPE(NULL, PTR_TYPE_NULL);
			 * entries at level 'n >= 2 * fanout' should NOT be
	d->nn_prev = p;
 * To insert a leaf_node:
	void *p = (*tree)->a[0];
	if (!notes_ref)
		const char *path, unsigned int mode,
{
#include "object-store.h"
		msglen--;
		strbuf_insertstr(sb, 0, "refs/");
/*
		struct string_list_item *item;
	}
		 * strict byte-based progressive fanout structure
	git_config(notes_display_config, &load_config_refs);
			return ret;
	if ((n % 2) || (n > 2 * fanout))
	n->next = NULL;
 *    - If a[n] is an int_node, recurse from #2 into that node and increment n
	new_node = (struct int_node *) xcalloc(1, sizeof(struct int_node));
		return t != OBJ_BLOB || !data;
		struct leaf_node *entry)
	if (!t)
			    "from %s",
}
		return; /* cannot consolidate top level */
	 * fanout level corresponds to _two_ 16-tree levels), peek at all 16

		strbuf_addch(sb, '\n');
			/*
			struct strbuf non_note_path = STRBUF_INIT;
			config_error_nonbool(k);


	xsnprintf(path + i, FANOUT_PATH_MAX - i, "%s", hex_hash + j);
				 string_list_join_lines_helper, &buf))
	if (ret)
		for_each_glob_ref(string_list_add_one_ref, glob, list);

				assert(path_len < FANOUT_PATH_MAX - 1);
 * As a subtree entry, the key is the prefix SHA1 (w/trailing NULs) of the
					l->key_oid.hash[KEY_INDEX] * 2 + fanout;
 * the prefix. The value is the SHA1 of the tree object containing the notes
			strbuf_detach(&buf, NULL));
	}
#define GET_PTR_TYPE(ptr)       ((uintptr_t) (ptr) & 3)
		linelen = strchrnul(msg_p, '\n') - msg_p;
		} else {
			return fanout;
/* Free the entire notes data contained in the given tree */
	load_subtree(t, &root_tree, t->root, 0);
		return &((*tree)->a[i]);
		{
		case PTR_TYPE_NOTE:
				strbuf_addch(&non_note_path, *q++);
static struct string_list display_notes_refs = STRING_LIST_INIT_NODUP;
		t = &default_notes_tree;
{
			load_subtree(t, l, tree, n);
};
/*
	/* replace tree with p in parent[index] */
	struct object_id object;
	if (ret)

	string_list_remove_empty_items(&sort_uniq_list, 0);



{
	struct int_node *parent_stack[GIT_MAX_RAWSZ];
			    type == PTR_TYPE_NOTE ? "note" : "subtree",
	/* read in both note blob objects */
	if (cur_msg[cur_len - 1] == '\n')
	/* read_sha1_file NUL-terminates */
	if (!new_msg || !new_len || new_type != OBJ_BLOB) {
#include "cache.h"
	struct leaf_node l;
			string_list_add_refs_from_colon_sep(&display_notes_refs,
struct tree_write_stack {
				tree->a[i] = NULL;
void format_display_notes(const struct object_id *object_oid,
	const unsigned hashsz = the_hash_algo->rawsz;
	if (!oideq(&l->key_oid, &entry->key_oid))
/*
}
}
 * whether or not the given existing fanout should be expanded for this
}


	char *msg, *msg_p;
			break;
	opt->extra_notes_refs.strdup_strings = 0;
 * - If location holds a matching subtree entry, unpack the subtree at that
	note_tree_remove(t, t->root, 0, &l);
	 */
	if (!t)
}
	*p = SET_PTR_TYPE(new_node, PTR_TYPE_INTERNAL);
	assert(!t->initialized);
	enum object_type t;
	assert(fanout < the_hash_algo->rawsz);
			strbuf_addstr(&non_note_path, entry.path);
 * If the given notes_tree structure is not initialized, it will be auto-
	if (!notes_ref)
	return found ? &found->val_oid : NULL;
		format_note(display_notes_trees[i], object_oid, sb,
	return 0;
 * Search the tree until the appropriate location for the given key is found:
			/*
void init_display_notes(struct display_notes_opt *opt)
	char path[2]; /* path to subtree in next, if any */
	t->combine_notes = combine_notes;
			skip_prefix(ref, "refs/", &ref);
		p = tree->a[i];
			(*tree)->a[i] = NULL;
}
		unsigned char fanout, char *path)

		 * (i.e. using 2/38, 2/2/36, etc. fanouts).
		/* subtree entry */
					note_tree_remove(t, tree, n, entry);
{
 * Fill the given strbuf with the notes associated with the given object.
{
	t->ref = xstrdup_or_null(notes_ref);
 */
}
 * the tree objects produced by write_notes_tree().
	struct notes_tree **trees;
		free(entry);
}
void expand_loose_notes_ref(struct strbuf *sb)
			/* fall through */
		 * subtree containing this entry based on our
	    get_oid_treeish(notes_ref, &object_oid))
	assert(t->initialized);
	return  write_each_non_note_until(note_path, d) ||
			 * level 'n' in the tree, and the 'fanout' variable:

	/* first, build stack of ancestors between root and current node */
						    &entry->val_oid);
			return l;

 */
		if (display_ref_env) {
void enable_default_display_notes(struct display_notes_opt *opt, int *show_notes)
	t->dirty = 1;
	int ret = 0;
		if (!unsorted_string_list_has_string(list, glob))

		n->next = t->first_non_note;
		/* fallback to expand_notes_ref */
	if (!oid)
			return note_tree_insert(t, tree, n, entry, type,
		return; /* we're happy */
}
					 path,
	/* concatenate cur_msg and new_msg into buf */
#define PTR_TYPE_INTERNAL 1
 * 1. Start at the root node, with n = 0
static void note_tree_remove(struct notes_tree *t,
	if (is_null_oid(&entry->val_oid)) { /* skip insertion of empty note */
	assert(memchr(path + 3 * n, '/', path_len - (3 * n)) == NULL);
#include "blob.h"
}
	assert(t->initialized);
		t = &default_notes_tree;
	assert(GET_PTR_TYPE(*p) == PTR_TYPE_NOTE ||
	while (l) {
static void **note_tree_search(struct notes_tree *t, struct int_node **tree,

	}

		strbuf_release(&n->buf);
	}
static void load_subtree(struct notes_tree *t, struct leaf_node *subtree,
	n->mode = mode;
		    notes_ref, oid_to_hex(&object_oid));

/*
		combine_notes_fn combine_notes)
/*
	 * level, so we return an incremented fanout.
	/* n sorts equal or after p */
		struct notes_tree *t = xcalloc(1, sizeof(struct notes_tree));
	strbuf_add(buf, hash, the_hash_algo->rawsz);
	struct object_id key_oid;
	return 0;
		path[i++] = hex_hash[j++];


		goto out;
	}
void load_display_notes(struct display_notes_opt *opt)
 */
}
	struct object_id val_oid;
			return ret;
				return -2;
struct int_node {
		break;
				strbuf_addch(&non_note_path, '/');
	char *display_ref_env;
	const struct object_id *existing_note = get_note(t, to_obj);
{
		if (note_tree_insert(t, node, n, l, type,
{
	/* Prepare for traversal of current notes tree */
	if (n) {
		struct int_node *node, unsigned int n)
	/* next, unwind stack until note_tree_consolidate() is done */
		void *cb_data)

		t->first_non_note = n;
			printf("%s\n", hash_to_hex(l->sha1));
	return ret;
				      GET_NIBBLE(i - 1, entry->key_oid.hash)))
	memcpy(buf + cur_len + 2, new_msg, new_len);

{
	struct non_note **nn_list;
			 * the note tree that have not yet been explored. There
	return  full_path[0] == tws->path[0] &&
	unsigned char i;
			 * the length:
}

			if (!SUBTREE_SHA1_PREFIXCMP(l->key_oid.hash,
		return;
		const struct object_id *note_oid, combine_notes_fn combine_notes)
		path[i++] = '/';
	for (i = 0; i < 16; i++) {
 * Search to the tree location appropriate for the given leaf_node's key:
			 * except for the last byte, where we write
		tws = tws->next;
	if (!force && existing_note)
}


			free(msg);
}
	/* create a new blob object from buf */
/*
		note_tree_free(t->root);
		case PTR_TYPE_NOTE:
static int tree_write_stack_finish_subtree(struct tree_write_stack *tws)
		die("Could not read %s for notes-index",
 * Determine optimal on-disk fanout for this part of the notes tree
	for (i = 0; i < split.nr; i++)
				goto handle_non_note;
 *
 * distinguished by the LSb of the leaf node pointer (see above).
		if (GET_PTR_TYPE(tree->a[i]) != PTR_TYPE_NULL) {
			*p = NULL;
}
		return note_tree_search(t, tree, n, key_sha1);
	if (!t)


	free(l);
		notes_ref = default_notes_ref();
	 * later, along with any empty strings that came from empty
			die("Failed to load %s %s into notes tree "
	for (i = 0; i < 16; i++) {
	}
	}
	ALLOC_ARRAY(trees, refs->nr + 1);
	size_t path_len = strlen(path);
	struct strbuf *buf = cb_data;
	      write_object_file(root.buf.buf, root.buf.len, tree_type, result);
 * (raw != 0) gives the %N userformat; otherwise, the note message is given
		const char *full_path)
void disable_display_notes(struct display_notes_opt *opt, int *show_notes)
			for (i = 0; i < prefix_len; i++) {
}
	assert(t->initialized);
	if (!t)
		if (!SUBTREE_SHA1_PREFIXCMP(entry->key_oid.hash, l->key_oid.hash)) {

 * - ptr & 3 == 0 - NULL pointer, assert(ptr == NULL)
		return 1;
 * Given a (sub)tree and the level in the internal tree structure, determine
		if (path_len == 2 * (hashsz - prefix_len)) {
			add_non_note(t, strbuf_detach(&non_note_path, NULL),
 * referenced object, using the last byte of the key to store the length of
			goto handle_non_note;
		init_notes(t, NULL, NULL, 0);
			warning("notes ref %s is invalid", glob);

	void *buf;
			/* recurse into int_node */
{
		return add_note(t, to_obj, &null_oid, combine_notes);
	char *path;
	return 0;
				if (!ret && is_null_oid(&l->val_oid))
	assert(t->initialized);
				const struct object_id *new_oid)
		const char *path)
	return 0;
	data = read_object_file(oid, &t, &len);

	strbuf_addstr(buf, item->string);
			if (!S_ISDIR(entry.mode))
	case PTR_TYPE_NULL:
	struct non_note *nn_prev;
	unsigned int i = 0, j = 0;
	void *p = NULL;
 *      - a note entry which may or may not match the key
		free(n);
		if (!(flags & NOTES_PRUNE_DRYRUN))
			}
		combine_notes = combine_notes_concatenate;
	else if (existing_note)

			}

		unsigned char fanout)
		const unsigned char *key_sha1)
	struct leaf_node *found;
/*
}
		return 0;
#include "notes.h"
{
	write_tree_entry(&tws->buf, mode, path + 3 * n, path_len - (3 * n),
	enum object_type cur_type, new_type;
 *
			ret = for_each_note_helper(t, CLR_PTR_TYPE(p), n + 1,

	if (note)
						    entry->key_oid.hash)) {
		return;

{
		oidcpy(&l->val_oid, &entry.oid);
			break;
			msg = reencoded;
int copy_note(struct notes_tree *t,
		return;
				   int flag, void *cb)
	if (!notes_ref)
	while (tree_entry(&desc, &entry)) {
	int ret;
		l = xcalloc(1, sizeof(*l));
 * - ptr & 3 == 3 - pointer to subtree entry - cast to struct leaf_node *
		struct write_each_note_data *d)
		string_list_append(&display_notes_refs, default_notes_ref());
#define FANOUT_PATH_MAX GIT_MAX_HEXSZ + FANOUT_PATH_SEPARATORS_MAX + 1
 * initialized to the default value (see documentation for init_notes() above).
	free(buf);
			if (!S_ISREG(entry.mode))

 * (sub)tree.
	while (3 * n + 2 < path_len && path[3 * n + 2] == '/') {
		each_note_fn fn, void *cb_data)
			load_config_refs = 1;
				strbuf_addch(&non_note_path, *q++);
	if (!notes_ref)
int combine_notes_overwrite(struct object_id *cur_oid,

	int *load_refs = cb;
	switch (GET_PTR_TYPE(p)) {
		void *cb_data)
		} else {
	t->prev_non_note = n;


{
{
}
static int string_list_add_one_ref(const char *refname, const struct object_id *oid,
	if (GET_PTR_TYPE(*p) == PTR_TYPE_NOTE) {
{
	oidcpy(&root_tree.val_oid, &oid);

	return NULL;
#include "config.h"
	struct strbuf buf = STRBUF_INIT;
static void load_subtree(struct notes_tree *t, struct leaf_node *subtree,
	}

	buf[cur_len + 1] = '\n';
				construct_path_with_fanout(l->key_oid.hash,
	if (GET_PTR_TYPE(*p) != PTR_TYPE_NOTE)
}
	struct string_list sort_uniq_list = STRING_LIST_INIT_DUP;
	(memcmp(key_sha1, subtree_sha1, subtree_sha1[KEY_INDEX]))
		t = &default_notes_tree;
	display_notes_refs.strdup_strings = 1;
	struct object_id oid;
{
			    flags & FOR_EACH_NOTE_YIELD_SUBTREES) {
{
{
		i--;
				return ret;
 * - ptr & 3 == 2 - pointer to note entry - cast to struct leaf_node *
				if (path[path_len - 1] != '/')
 * Values of the 'fanout' variable:
void free_notes(struct notes_tree *t)
	buf = (char *) xmalloc(buf_len);
		return 1;
struct leaf_node {

		size_t path_len = strlen(entry.path);

				free(entry);
	       GET_PTR_TYPE(*p) == PTR_TYPE_SUBTREE);

	assert(display_notes_trees);

		return -2;
	/* Determine common part of tree write stack */

	oidclr(&l.val_oid);
{
}
	return trees;

		free(n);
	/* create a new blob object from sort_uniq_list */
	if (!t)
	return note_tree_insert(t, t->root, 0, l, PTR_TYPE_NOTE, combine_notes);
		write_tree_entry(&tws->buf, 040000, tws->path, 2, s.hash);
	struct int_node *parent, unsigned char index)
			; /* do nothing, prefer note to non-note */
	while (t->first_non_note) {
			load_config_refs = 0;
	strbuf_addstr(&buf, ref);
		t->prev_non_note = p;
	struct object_id oid, object_oid;

		return 0;
			strbuf_addstr(sb, "    ");
	for_each_string_list_item(item, refs) {
		}
			return note_tree_search(t, tree, n, key_sha1);
				ret = combine_notes(&l->val_oid,
}
	}
		unsigned char *n, const unsigned char *key_sha1)
	free(cur_msg);
	if (!combine_notes)
		case PTR_TYPE_SUBTREE:
	unsigned int i;
			    const struct object_id *new_oid)
	struct non_note *next; /* grounded (last->next == NULL) */

				/* Create trailing slash, if needed */
	}
 * To find a leaf_node:
	/* Finally add given entry to the current tree object */
	if (!t->first_non_note) {
	if (string_list_add_note_lines(&sort_uniq_list, new_oid))
	assert(i == n && parent_stack[i] == tree);
		write_each_note_helper(d->root, note_path, mode, note_oid);
			return note_tree_search(t, tree, n, key_sha1);
	if (is_null_oid(oid))
		tws = tws->next;
		assert(!*p);
			}
}
			break;
		}
		unsigned char type;
		p = n;
 */
			       combine_notes);

	/* we will end the annotation by a newline anyway */
	oidclr(&root_tree.key_oid);
}
	/* Weave non-note entries into note entries */
 *    subtree entry and remove it; restart search at the current level.
		 * directory part of the path must be deduced from the
	static const char utf8[] = "utf-8";

		tws->next = NULL;
	assert(t->initialized);
 * value is the SHA1 of the note object.
#include "tree-walk.h"

						     &n->oid);
	unsigned int i;
		return;
	return 0;
		j = GET_NIBBLE(i, entry->key_oid.hash);

	if (*load_refs && !strcmp(k, "notes.displayref")) {
				goto handle_non_note;
			 * unpacking subtree entries that exist below the
}
	free(t->ref);
{
	string_list_clear(&split, 0);
		goto out;
		t = &default_notes_tree;
		ret = tree_write_stack_finish_subtree(n);
	}

	while (tws && 3 * n < path_len &&
		}
#define GET_NIBBLE(n, sha1) ((((sha1)[(n) >> 1]) >> ((~(n) & 0x01) << 2)) & 0x0f)
			 * preserved, but rather consolidated into the above
		path[i++] = hex_hash[j++];
		if (ret)
		return;
}
	struct tree_write_stack *n;

 * internal nodes, and struct leaf_node as leaf nodes. Each int_node has a
	      write_each_non_note_until(NULL, &cb_data) ||

static int write_each_non_note_until(const char *note_path,
		string_list_add_refs_by_glob(list, split.items[i].string);
	struct write_each_note_data *d =
 * etc.
	}
 * objects in load_subtree(), and the non-notes are correctly written back into


	n->next = NULL;
 *      restart search at the current level.
		case PTR_TYPE_INTERNAL:
struct non_note {
		const struct object_id *note_oid, char *note_path,
	for (msg_p = msg; msg_p < msg + msglen; msg_p += linelen + 1) {

		const struct object_id *oid)
}
{
			if (n < 2 * fanout &&
	t->dirty = 0;

	struct object_id s;
		/* fall through */
	const unsigned char *sha1;
	while (n && (!note_path || (cmp = strcmp(n->path, note_path)) <= 0)) {
			l = (struct leaf_node *) CLR_PTR_TYPE(p);
		continue;
	/* tws point to last matching tree_write_stack entry */


				goto handle_non_note; /* entry.path is not a SHA1 */

	}
	assert(note_path_len <= GIT_MAX_HEXSZ + FANOUT_PATH_SEPARATORS);
#include "string-list.h"

	}
	t->dirty = 1;
						combine_notes);
}
/*
		BUG("prefix_len (%"PRIuMAX") is too small", (uintmax_t)prefix_len);
	for_each_note(t, 0, prune_notes_helper, &l);
	unsigned int mode = 0100644;
	const struct object_id *note = get_note(t, from_obj);
	if (!opt || opt->use_default_notes > 0 ||
	if (prefix_len >= hashsz)
		free(new_msg);
		t->prev_non_note = t->first_non_note->next;
		FOR_EACH_NOTE_YIELD_SUBTREES;
		free(cur_msg);
static void add_non_note(struct notes_tree *t, char *path,
		unsigned char n, unsigned char fanout, int flags,
		const char *path, unsigned int path_len, const
	prefix_len = subtree->key_oid.hash[KEY_INDEX];

					 const char *globs)
	}
				load_subtree(t, l, tree, n);
				 cb_data);
		}
	unsigned int i;
	n->next = *l;
			free(l);
		} else if (path_len == 2) {
 * - 1: 2/38 fanout
	if (t != OBJ_BLOB || !data || !len) {
static void tree_write_stack_init_subtree(struct tree_write_stack *tws,
	}
	char *cur_msg = NULL, *new_msg = NULL, *buf;

 * we still need to keep track of them. Keep a simple linked list sorted alpha-
	return 0;
	struct write_each_note_data cb_data;
		case PTR_TYPE_SUBTREE:
			struct strbuf *sb, const char *output_encoding, int raw)
}
	tws->next = n;
 * - If location is unused (NULL), store the tweaked pointer directly there
				free(l);
 * The bottom 2 bits of each pointer is used to identify the pointer type
	struct strbuf buf = STRBUF_INIT;
 * Use a non-balancing simple 16-tree structure with struct int_node as
			 */
		die("Cannot use notes ref %s", notes_ref);
	if (!combine_notes)
	/* Start subtrees needed to satisfy path */

 */
		n++;
	l = (struct leaf_node *) xmalloc(sizeof(struct leaf_node));
	free(buf);
		goto out;
			l = (struct leaf_node *) CLR_PTR_TYPE(p);
	ret = note_tree_insert(t, new_node, n + 1, l, GET_PTR_TYPE(*p),
		l = l->next;
			    output_encoding, raw);
			 * preserved, since they correspond exactly to a fanout
	void *a[16];
}
	if (flags & NOTES_INIT_WRITABLE && read_ref(notes_ref, &object_oid))
int combine_notes_ignore(struct object_id *cur_oid,
			const char *q = oid_to_hex(&subtree->key_oid);
	fanout = determine_fanout(tree, n, fanout);
		/* n sorts before t->first_non_note */

			  struct strbuf *sb, const char *output_encoding, int raw)
	struct leaf_node *l;
		return 0;
			type = PTR_TYPE_NOTE;
		switch (GET_PTR_TYPE(p)) {
void enable_ref_display_notes(struct display_notes_opt *opt, int *show_notes,
			 * Pad the rest of the SHA-1 with zeros,
			(*tree)->a[0] = NULL;
			if (oideq(&l->key_oid, &entry->key_oid)) {
	ret = write_object_file(buf, buf_len, blob_type, cur_oid);
				goto handle_non_note; /* entry.path is not a SHA1 */
{
	int ret = 0;
	memcpy(object_oid.hash, subtree->key_oid.hash, prefix_len);
 *   node-to-be-inserted, and store the new int_node into the location.
	if (opt) {
};
 * 3. Use the nth nibble of the key as an index into a:
		tws->path[0] = tws->path[1] = '\0';
void prune_notes(struct notes_tree *t, int flags)
 * Leaf nodes come in two variants, note entries and subtree entries,
 * As a note entry, the key is the SHA1 of the referenced object, and the
	}
{
	       matches_tree_write_stack(tws, path + 3 * n)) {
	p->next = n;
	if (!(msg = read_object_file(oid, &type, &msglen)) || type != OBJ_BLOB) {
 * for human consumption.
		ret = write_object_file(n->buf.buf, n->buf.len, tree_type, &s);
	oidcpy(&entry->val_oid, &l->val_oid);



	if (!t)
{
	if (get_oid(sb->buf, &object)) {
		strbuf_add(sb, msg_p, linelen);
		struct object_id oid;

 * betically on the non-note path. The list is populated when parsing tree
		struct int_node *tree, unsigned char n,
			skip_prefix(ref, "notes/", &ref);
 *      - an unused leaf node (NULL)
 * Search to the tree location appropriate for the given key:
	else if (non_note_cmp(t->first_non_note, n) <= 0)
			free(entry);
	unsigned int mode;
	if (!cur_msg || !cur_len || cur_type != OBJ_BLOB) {
		void *p = tree->a[i];
	/* n sorts between p and p->next */

			/* This can't be part of a note */
		expand_notes_ref(sb);
	t->first_non_note = NULL;
				return ret;

		struct int_node *tree, unsigned char n,
	if (!unsorted_string_list_has_string(refs, refname))
static unsigned char determine_fanout(struct int_node *tree, unsigned char n,
}


		if (!ref || !strcmp(ref, GIT_NOTES_DEFAULT_REF)) {

			/* unpack 'l' and restart insert */

			free(CLR_PTR_TYPE(p));
{
		free(t->first_non_note->path);
static int note_tree_insert(struct notes_tree *t, struct int_node *tree,
	assert(GET_PTR_TYPE(entry) == 0); /* no type bits set */
	assert(CLR_PTR_TYPE(parent->a[index]) == tree);
			 * Subtree entries at level 'n < 2 * fanout' should be
		cur_msg = read_object_file(cur_oid, &cur_type, &cur_len);

		const char *ref = t->ref;
		}

	memcpy(buf, cur_msg, cur_len);
	string_list_append(&opt->extra_notes_refs,
		 * filename is already found in entry.path, but the
	/*
			*p = SET_PTR_TYPE(entry, type);
static int for_each_note_helper(struct notes_tree *t, struct int_node *tree,
		display_ref_env = getenv(GIT_NOTES_DISPLAY_REF_ENVIRONMENT);
 * If a note entry with matching key, return the note entry, else return NULL.

 *    - Otherwise, we have found one of the following:
	p = (*tree)->a[i];
}
					 hashsz - prefix_len))
			/* unpack tree and resume search */
	i = GET_NIBBLE(*n, key_sha1);
void expand_notes_ref(struct strbuf *sb)
	}
				/* invoke callback with subtree */
 * 2. If a[0] at the current level is a matching subtree entry, unpack that
/*

		}
void init_notes(struct notes_tree *t, const char *notes_ref,
		unsigned char n, struct leaf_node *entry, unsigned char type,
}

	return for_each_note_helper(t, t->root, 0, 0, flags, fn, cb_data);
	if (!n)
 */
	      tree_write_stack_finish_subtree(&root) ||
	struct leaf_node *l;
#define SUBTREE_SHA1_PREFIXCMP(key_sha1, subtree_sha1) \
	struct non_note *p = d->nn_prev;
	memset(opt, 0, sizeof(*opt));
 */

			load_subtree(t, l, *tree, *n);
}
};
 *      - a subtree entry which does not match the key
	if (get_tree_entry(the_repository, &object_oid, "", &oid, &mode))

	/* failed to find object => prune this note */
	parent->a[index] = p;
	}
		notes_ref = getenv(GIT_NOTES_REF_ENVIRONMENT);
	 * lines within the file.
	if (!t)
	n = (struct note_delete_list *) xmalloc(sizeof(*n));
	int ret;
	 * subtree entries, then there are likely plenty of notes below this

	t->update_ref = (flags & NOTES_INIT_WRITABLE) ? t->ref : NULL;
	int ret;
		t = &default_notes_tree;
	buf = fill_tree_descriptor(the_repository, &desc, &subtree->val_oid);
	buf[cur_len] = '\n';
	struct name_entry entry;
{
	if (flags & NOTES_INIT_EMPTY || !notes_ref ||

		cur_len--;
		struct int_node *node, unsigned int n);
		; /* do nothing  */
out:


		strbuf_insertstr(sb, 0, "refs/notes/");
	strbuf_addf(buf, "%o %.*s%c", mode, path_len, path, '\0');
	return 0;
		oidcpy(&l->key_oid, &object_oid);
		}
	assert(tws->path[0] == '\0' && tws->path[1] == '\0');
	else if (starts_with(sb->buf, "notes/"))
	string_list_sort(&sort_uniq_list);
		new_msg = read_object_file(new_oid, &new_type, &new_len);
int for_each_note(struct notes_tree *t, int flags, each_note_fn fn,
						     item->string);
	assert(GET_PTR_TYPE(entry) == 0); /* no type bits set */
				/* skip concatenation if l == entry */
struct notes_tree default_notes_tree;
		p = p->next;
		     oid_to_hex(&subtree->val_oid));
		combine_notes_fn combine_notes, int flags)
 * - 3: 2/2/2/34 fanout
		if (hasheq(key_sha1, l->key_oid.hash))
	int counter = 0;
		default:
	opt->extra_notes_refs.strdup_strings = 1;
 *

			continue;
}
	oidcpy(&l->key_oid, object_oid);
	return 0;
		case PTR_TYPE_NOTE:
#define PTR_TYPE_NULL     0
/*
static void note_tree_free(struct int_node *tree)
		switch (GET_PTR_TYPE(tree->a[i])) {
		fanout--;
#define KEY_INDEX (the_hash_algo->rawsz - 1)
#define FANOUT_PATH_SEPARATORS_MAX ((GIT_MAX_HEXSZ / 2) - 1)
{
			strbuf_addf(sb, "\nNotes (%s):\n", ref);
static int write_each_note_helper(struct tree_write_stack *tws,
			if (p) /* more than one entry */
	hashcpy(n->oid.hash, sha1);
		char *reencoded = reencode_string(msg, output_encoding, utf8);
			 */
	if (string_list_add_note_lines(&sort_uniq_list, cur_oid))
			}

	struct tree_write_stack *root;



 * - 0: No fanout (all notes are stored directly in the root notes tree)
			 const struct object_id *new_oid)
}
	hashcpy(l.key_oid.hash, object_sha1);
		if (get_oid(glob, &oid))

{
	strbuf_release(&buf);
	*show_notes = 1;
		return;
	}
		return fanout;
		string_list_add_refs_by_glob(&display_notes_refs, v);

	struct object_id object_oid;
	unsigned long len;
		note_path_len--;
	for (i = 0; i < 16; i++) {
	if (t->root)
	if (GET_PTR_TYPE(p) == PTR_TYPE_SUBTREE) {
		free(new_msg);
	ret = write_object_file(buf.buf, buf.len, blob_type, cur_oid);
			    !(flags & FOR_EACH_NOTE_DONT_UNPACK_SUBTREES)) {
		full_path[2] == '/';
		oidcpy(cur_oid, new_oid);
	case PTR_TYPE_NOTE:
		const struct object_id *note_oid, char *note_path,
	if (starts_with(sb->buf, "refs/notes/"))
	oidcpy(&l->val_oid, note_oid);
		struct leaf_node *l = (struct leaf_node *) CLR_PTR_TYPE(*p);
	while (i > 0 &&
		mode = 040000;
			size_t i;
	if (!buf)
	assert(!display_notes_trees);

			    oid_to_hex(&object_oid), t->ref);
		switch (type) {
 * - 2: 2/2/36 fanout
	}
}
	    (opt->use_default_notes == -1 && !opt->extra_notes_refs.nr)) {
		t = &default_notes_tree;
	assert(tree && parent);
	tws->path[0] = path[0];
	t->root = (struct int_node *) xcalloc(1, sizeof(struct int_node));
	}
	struct note_delete_list *l = NULL;
		l = (struct leaf_node *) CLR_PTR_TYPE(p);
 */
			object_oid.hash[KEY_INDEX] = (unsigned char)len;
		unsigned int mode, const unsigned char *sha1)

}
{
	l = (struct leaf_node *) CLR_PTR_TYPE(*p);
	if (!t)
 * If there are > 1 non-NULL entries, give up and return non-zero.
	 */
 */
			/* unpack tree and resume search */
		}
{
		if (note_path && cmp == 0)
					 void *cb_data)
	if (prefix_len * 2 < n)
			string_list_add_refs_by_glob(&display_notes_refs,
};
 * - If location holds a note entry that matches the note-to-be-inserted, then
}
			msglen = strlen(msg);
	struct note_delete_list *next;
		t = &default_notes_tree;
{
				/* unpack subtree and resume traversal */
	default:

	struct tree_write_stack *n = tws->next;


				unsigned int path_len =
				ret = fn(&l->key_oid, &l->val_oid,
	root.path[0] = root.path[1] = '\0';
int add_note(struct notes_tree *t, const struct object_id *object_oid,
	return 0;
					 cb_data);
 * The root node is a statically allocated struct int_node.
							    display_ref_env);
	n->path[0] = n->path[1] = '\0';
 */
		} else
		free(data);
	return strcmp(a->path, b->path);
	} else {
}
				free(entry);

void string_list_add_refs_from_colon_sep(struct string_list *list,
	}

						   path);
 *
		t->first_non_note = t->prev_non_note;
				/* unpack 'entry' */
#define PTR_TYPE_SUBTREE  3
	oidcpy(cur_oid, new_oid);
			string_list_append(list, glob);
	struct int_node *new_node;
	flags = FOR_EACH_NOTE_DONT_UNPACK_SUBTREES |
		 * knowledge that the overall notes tree follows a
				     combine_notes_concatenate))
					return 0;
		return ret;
		for_each_string_list_item(item, &opt->extra_notes_refs)
	free(t->root);
	}
	/* we have found a matching entry */
		switch (GET_PTR_TYPE(p)) {
	}
		xmalloc(sizeof(struct tree_write_stack));

							   path);
			break;
		p->mode = n->mode;
	if (for_each_string_list(&sort_uniq_list,
				     entry.mode, entry.oid.hash);
		notes_ref = notes_ref_name; /* value of core.notesRef config */
		 * Determine full path for this non-note entry. The

	string_list_remove_duplicates(&sort_uniq_list, 0);
	display_notes_trees = load_notes_trees(&display_notes_refs, 0);
			if (hex_to_bytes(object_oid.hash + prefix_len, entry.path,
{

	free(globs_copy);
	struct leaf_node root_tree;
	tws->path[1] = path[1];
		const char *ref) {
	/* we will separate the notes by two newlines anyway */
		return ret;
		full_path[1] == tws->path[1] &&
	return note_tree_insert(t, new_node, n + 1, entry, type, combine_notes);
}
			if (ret)

		case PTR_TYPE_SUBTREE:
 * - If location holds a note entry that matches the subtree-to-be-inserted,
	if (p && (GET_PTR_TYPE(p) != PTR_TYPE_NOTE))
		void *cb_data)
#include "strbuf.h"
	void **p = note_tree_search(t, &tree, &n, entry->key_oid.hash);
	n = (struct tree_write_stack *)
		(struct write_each_note_data *) cb_data;
	/* non-matching leaf_node */

 * tree, and return 0.
			load_subtree(t, l, *tree, *n);
				/* internal nodes must be trees */
}
	assert(!tws->next);

	int load_config_refs = 0;
			 * directory in the on-disk structure. However, subtree
	struct tree_write_stack *next;
	t->initialized = 1;
	if (non_note_cmp(p, n) < 0)

		return; /* type mismatch, nothing to remove */
/* hex oid + '/' between each pair of hex digits + NUL */
void string_list_add_refs_by_glob(struct string_list *list, const char *glob)
	const char *notes_ref = NULL;

		parent_stack[i + 1] = CLR_PTR_TYPE(parent_stack[i]->a[j]);
 * the naming conventions of notes. There are typically none/few of these, but
	buf_len = cur_len + 2 + new_len;
	if (!t)
{
	*l = n;
{
		t = &default_notes_tree;
		assert(strcmp(p->path, n->path) == 0);
		(*n)++;
	ret = for_each_note(t, flags, write_each_note, &cb_data) ||


 *
		t = &default_notes_tree;

struct write_each_note_data {
{
		const struct object_id *oid)
{
static int string_list_add_note_lines(struct string_list *list,
/*
	/* There should be no more directory components in the given path */
		if (!SUBTREE_SHA1_PREFIXCMP(key_sha1, l->key_oid.hash)) {
	free(msg);

	oid = get_note(t, object_oid);
			free(l);
		t->first_non_note = n;
			if (n >= 2 * fanout ||
	free(new_msg);
	void *p;
				fanout, flags, fn, cb_data);
	int i;


		else
	 * For each even-numbered 16-tree level (remember that each on-disk
	return ret;
		p = t->first_non_note;
	n->path = path;
	while (p->next && non_note_cmp(p->next, n) <= 0)
	for (i = 0; i < 16; i++) {
{
static int write_each_note(const struct object_id *object_oid,

	opt->use_default_notes = -1;
	return 0;
	return ret;
	switch (GET_PTR_TYPE(*p)) {
			 oid->hash);
	}
 * Add the lines from the named object to list, with trailing
				goto redo;
 * - Copy the matching entry's value into the given entry.
	*show_notes = 0;
	case PTR_TYPE_SUBTREE:

		return 0; /* nothing to do for this note */
 *   combine the two notes (by calling the given combine_notes function).
		case PTR_TYPE_INTERNAL:
		init_notes(t, item->string, combine_notes_ignore, flags);
}
	unsigned short mode;
	}
		l = (struct leaf_node *) CLR_PTR_TYPE(p);

#define SET_PTR_TYPE(ptr, type) ((void *) ((uintptr_t) (ptr) | (type)))
		struct leaf_node *l;
				return 0;

	char *globs_copy = xstrdup(globs);
	/* we have been strdup'ing ourselves, so trick
	int i;
	}
	 * entries at that tree level. If all of them are either int_nodes or
}
 * If the given notes_tree is NULL, the internal/default notes_tree will be

static struct notes_tree **display_notes_trees;
		return add_note(t, to_obj, note, combine_notes);

	}
			note_tree_free(CLR_PTR_TYPE(p));
{
			return ret;
 *   location, and restart the insert operation from that level.
struct notes_tree **load_notes_trees(struct string_list *refs, int flags)
		if (reencoded) {
		case PTR_TYPE_SUBTREE:
			 * notes tree level. We achieve this by unconditionally
static int prune_notes_helper(const struct object_id *object_oid,
static int non_note_cmp(const struct non_note *a, const struct non_note *b)
		oidcpy(&p->oid, &n->oid);
	strbuf_release(&root.buf);
	memset(t, 0, sizeof(struct notes_tree));

				      const struct object_id *oid)
 * with the only NOTE entry (or a NULL entry if no entries) from the given
static int note_tree_consolidate(struct int_node *tree,
{
 */
	if (msglen && msg[msglen - 1] == '\n')

	opt->use_default_notes = 1;
	string_list_remove_empty_items(&split, 0);
{

			break;
				load_subtree(t, entry, tree, n);
	struct leaf_node *l;
	const struct object_id *oid;
	expand_notes_ref(&buf);
		}
	return fanout + 1;
			strbuf_addstr(sb, "\nNotes:\n");
#define PTR_TYPE_NOTE     2

		if (ret)
	size_t prefix_len;
};
	n = (struct non_note *) xmalloc(sizeof(struct non_note));
	int ret;
static void write_tree_entry(struct strbuf *buf, unsigned int mode,
	unsigned char i, j;
			 * Subtree entries in the note tree represent parts of
int combine_notes_concatenate(struct object_id *cur_oid,

			 * threshold level at 'n = 2 * fanout'.
	strbuf_init(&n->buf, 256 * (32 + the_hash_algo->hexsz)); /* assume 256 entries per tree */
}
	case PTR_TYPE_INTERNAL:
		return 0;

	int cmp = 0, ret;
{
}
#define FANOUT_PATH_SEPARATORS (the_hash_algo->rawsz - 1)
		string_list_append(refs, refname);
			ret = write_each_note_helper(d->root, n->path, n->mode,
	/* Write tree objects representing current notes tree */

}

	 * add an empty string to the list.  But it will be removed
	struct strbuf buf;
	      const struct object_id *from_obj, const struct object_id *to_obj,
	}
			      const struct object_id *new_oid)
	/* read both note blob objects into unique_lines */
 *    - If a matching subtree entry, unpack that subtree entry (and remove it);
		BUG("prefix_len (%"PRIuMAX") is out of range", (uintmax_t)prefix_len);
{
			/* This is potentially an internal node */
		tree_write_stack_init_subtree(tws, path + 3 * n);
 * - Consolidate int_nodes repeatedly, while walking up the tree towards root.
#include "utf8.h"
	else

{
redo:
 * The list argument must have strdup_strings set on it.
static int string_list_join_lines_helper(struct string_list_item *item,
	parent_stack[0] = t->root;
	enum object_type type;
 * newlines removed.

		if (!v)
/*
		}
		case PTR_TYPE_INTERNAL:
	return notes_ref;
	struct string_list_item *item;

{
	 * string_list into free()ing strings */
	if (output_encoding && *output_encoding &&

		note_path[note_path_len] = '\0';
 *      In any case, set *tree and *n, and return pointer to the tree location.
		if (!SUBTREE_SHA1_PREFIXCMP(key_sha1, l->key_oid.hash)) {
			ret = fn(&l->key_oid, &l->val_oid, path,
	free(tree);
	if (has_glob_specials(glob)) {
}
	 * If the last line of the file is EOL-terminated, this will
				/* notes must be blobs */
	root.next = NULL; /* last forward entry in list is grounded */


	case PTR_TYPE_SUBTREE:
		trees[counter++] = t;

		free(t->first_non_note);
	assert(t->initialized);
	struct string_list *refs = cb;
	int ret = 1;
	struct tree_desc desc;
 * - If location does not hold a matching entry, abort and do nothing.

	}
	free(data);
		if (ret)

const struct object_id *get_note(struct notes_tree *t,
	string_list_split_in_place(&split, globs_copy, ':', -1);
	assert(list->strdup_strings);
			remove_note(t, l->sha1);
	unsigned int i;
int combine_notes_cat_sort_uniq(struct object_id *cur_oid,
							   fanout,
	if (!is_null_oid(new_oid))
	cb_data.nn_prev = NULL;
		n = n->next;
#include "tree.h"
	strbuf_addch(buf, '\n');
	l = (struct leaf_node *) CLR_PTR_TYPE(*p);
	unsigned int n = 0;
 * To remove a leaf_node:

int write_notes_tree(struct notes_tree *t, struct object_id *result)
{
