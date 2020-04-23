			else
	}
		 * Return early if base is shorter than the
				dirmask |= 1ul << i;
	 * There are three possibilities where *a* could be hiding
			if (!remainder) {

		if (item->nowildcard_len == item->len)
				goto done;
	/*
	*entry = desc->entry;
			 * FIXME: attributes _can_ match directories and we
			if (!size)
				 * be performed in the submodule itself.

		free(s);
		 * returned, allowing the caller to terminate early.

		/* keep looking */
			goto done;
}
			if (!match_dir_prefix(item, base_str, match, matchlen))
}
		struct tree_desc t;

	if (S_ISDIR(entry->mode) &&
			unsigned long size;
		 */
		   int n, struct tree_desc *t,

		/* Handle symlinks to e.g. a//b by removing leading slashes */
 *

static void free_extended_entry(struct tree_desc_x *t)

		return;
	    positive >= entry_interesting &&
	/* #3, #4, #7, #13, #14, #17 */
	}
 * If there are no symlinks, or the end result of the symlink chain
{
	return ps_strncmp(item, base, match, len);
	/* Always points to the end of the name we're about to add */
int tree_entry_gently(struct tree_desc *desc, struct name_entry *entry)
	}
		char *first_slash;
		/*

	 */
		if (basecmp(item, base, match, baselen))
	if (pathlen && base[pathlen-1] == '/')
		 */
		 * character.  More accurate matching can then
	/*
}
				else
			if (name_compare(e->path, len, first, first_len) < 0) {
				return entry_not_interesting;
			dirlen--;
{

			 const struct traverse_info *info,
		 * at least matches up to the first wild
 */
				strbuf_add(result_path, namebuf.buf,
 * entry "t" from this call, the caller will let us know by calling
	 *   5  |  file |    1     |    1     |   0
	oidcpy(&current_tree_oid, tree_oid);
				goto done;
		 * In other words, if we have never reached this point
	char *traverse_path;
	const char *path;


	    positive <= entry_not_interesting) /* #1, #2, #11, #12 */
		for (i = 0; i < n; i++) {
			 */
	hashcpy(desc->entry.oid.hash, (const unsigned char *)path + len);
	struct tree_desc t;
}
/* :(icase)-aware string compare */
		if ((!exclude &&   item->magic & PATHSPEC_EXCLUDE) ||
		return 1; /* keep looking */
static int match_dir_prefix(const struct pathspec_item *item,
	while (probe.size) {
			parents_nr++;
		}


				 */
						   base->len - base_offset, item);
		tx[i].d = t[i];
}
struct tree_desc_x {
 * process the named entry first.  We will remember that we haven't
		 */
			 */

			if (!first) {
}
		if (++entrylen == namelen) {

	 * optimization as in match_entry. For now just be happy with
	 * we could have checked entry against the non-wildcard part
					 !!S_ISDIR(entry->mode),
#include "cache.h"
	 * (*) An exclude pattern interested in a directory does not
		}
	if (update_tree_entry_gently(desc))
		default:
		break;
 *    blob    "t-1"
	int result = init_tree_desc_internal(desc, buffer, size, &err);

		int first_len = 0;
	int retval;
		free(parents[i].tree);
				retval = FOUND;
			    ps->max_depth == -1) {
			e = &entry[i];
			continue;

			return 0;
{
		buf = read_object_with_reference(r, oid, tree_type, &size, NULL);
	 * necessarily mean it will exclude all of the directory. In
	const unsigned char *end = (const unsigned char *)desc->entry.path + desc->entry.pathlen + 1 + the_hash_algo->rawsz;
		       PATHSPEC_ICASE |
	if (item->magic & PATHSPEC_ICASE)
		 * than the current path.
					const struct name_entry *entry,
			   const char *name, struct object_id *result,

			 */
	if (update_tree_entry_internal(desc, &err)) {
		info = info->prev;
			contents = repo_read_object_file(r,
	size_t pathlen = strlen(base);
		}

	else if (*never_interesting != entry_not_interesting) {
				  struct traverse_info *info,
		/*

			size_t len;
		   unsigned short *mode)
	 *  13  |  dir  |    1     |   -1     |   1

		strbuf_setlen(base, base_offset + baselen);
					entry_clear(e);
				    ps->max_depth) ?
	struct strbuf namebuf = STRBUF_INIT;
		*matched = 0;
				continue;
	struct tree_desc_skip *skip;
		/* Now we have in entry[i] the earliest name from the trees */
 * Is a tree entry interesting given the pathspec we have?
}
				continue;
	struct tree_desc d;
static int match_wildcard_base(const struct pathspec_item *item,

	 * The caller wants "first" from this tree, or nothing.
			}
	 *   4  |  file |    1     |    0     |   1
{
		 * matched case-sensitively. If the entry is a
	if (t->d.entry.path == a->path) {
							  &root);
		/*
	 * Extract the first entry from the tree_desc, but skip the


			parent = &parents[parents_nr - 1];
			goto interesting;
	 *   1  |  file |   -1     |  -1..2   |  -1
		if (ps->recurse_submodules && S_ISGITLINK(entry->mode) &&
			void *tree;
{
struct dir_state {
	while (t->size) {
	return tree_entry_interesting(istate, e, base,
		 * matching, but it's trickier (and not to forget that
 * processed the first entry yet, and in the later call skip the
{
		traverse_path = xstrndup(base.buf, base.len);

		/* We could end up here via a symlink to dir/.. */
	return 0;
		       const char *match, int matchlen,
					break;
	strbuf_release(&err);
}
	    (positive == all_entries_interesting &&
		 * one.  In either case, they will never match the
	case -1:
	    negative == entry_interesting)
		/*
	desc->entry.pathlen = len - 1;
	if (pos >= pathlen)
		 * directory is already matched, we only need to match

	if (!tree)

		const char *base_str = base->buf + base_offset;
		return still_interesting;
		/* We have processed this entry already. */
			entry_interesting : entry_not_interesting;
/*
		strbuf_release(&err);
};
 * root-level link to ../foo), the portion of the link which is
				if (!info->show_all_errors)
		mask = 0;

	}
		   const struct object_id *tree_oid,
				 * When matching against submodules with
		traverse_path = xstrndup(info->name, info->pathlen);
}
}
			    (matchlen < pathlen) ? matchlen : pathlen);
 *
}
	 * case | entry | positive | negative | result
					return all_entries_interesting;
static int find_tree_entry(struct repository *r, struct tree_desc *t,
	if (!ps->nr) {
	return 0;
	struct strbuf err = STRBUF_INIT;
	switch (check_entry_match(first, first_len, path, len)) {
		BUG("too small buffer passed to make_traverse_path");
		}
		}
		 * the variable to -1 and that is what will be
			goto done;
	unsigned long size = 0;
				if (!e->path)
			 * Must not return all_entries_not_interesting
		cmp = memcmp(name, entry, entrylen);
	 * files inside. So don't write such directories off yet.
			return !basecmp(item, base, match, matchlen);
		return decode_tree_entry(desc, buffer, size, err);
	strbuf_release(&err);
			}
}
/*

		mode = (mode << 3) + (c - '0');
		if (!S_ISDIR(*mode))
		skip->prev = t->skip;
		*/
	return entry_interesting;
	 * name is "first" may be hiding behind the current entry "path".
				first = e->path;
	for (i = ps->nr - 1; i >= 0; i--) {
		}
	/*
			 *
				if (remainder)
						    &current_tree_oid, &type,
	if (*str == ' ')
};
				 const struct pathspec *ps,
		   const char *base, const char *match, int len)
	if (update_tree_entry_internal(desc, &err))
				goto done;
	 * (0) If a and b are the same name, we are trivially happy.
 */
	 *
					goto interesting;
				retval = FOUND;
			/*
	info->traverse_path = NULL;
		free(tree);
			continue;
		   struct traverse_info *info)
			if (parents_nr == 1) {
	path = a->path;
			/*
			if (!tree)
			return 1;
		 */
	struct tree_desc_skip *skip;
match_wildcards:
		 */

	while ((c = *str++) != ' ') {
					struct strbuf *base, int base_offset,

	 * was specified, all of them are interesting.
				goto done;
	unsigned char c;
		 * we cheated and did not do strncmp(), so we do
	info->pathlen = pathlen ? pathlen + 1 : 0;
			init_tree_desc(&t, tree, size);
	 */
		int len;
		}
	return error;
	if ((positive == entry_interesting &&
	return 0;
	     negative >= entry_interesting) || /* #5, #6, #16 */
static int decode_tree_entry(struct tree_desc *desc, const char *buf, unsigned long size, struct strbuf *err)
		 * the prefix.
			struct dir_state *parent;
{
			strbuf_remove(&namebuf, 0,

	 * We need to look-ahead -- we suspect that a subtree whose
#include "tree-walk.h"
		       PATHSPEC_LITERAL |
		       PATHSPEC_EXCLUDE |
	 *  20  |  dir  |    2     |    2     |  -1

		name = info->name;
	 *
	/*
	void *buf = NULL;
 * This is Linux's built-in max for the number of symlinks to follow.
				extended_entry_extract(tx + i, e, first, first_len);
 *    blob    "t-2"
	struct object_id root;
	 *  16  |  dir  |    1     |    2     |   0
 *
	} else {

				retval = FOUND;
			 * At this point, we have followed at a least
	if (size < hashsz + 3 || buf[size - (hashsz + 1)]) {

		if (interesting) {
	 * (1) *a* == "t",   *b* == "ab"  i.e. *b* sorts earlier than *a* no
			if (contents[0] == '/') {
		if (!t->d.size) {

			if (follows_remaining-- == 0) {
	size -= len;
	 * If the base is a subdirectory of a path which
	 * leading directory and is shorter than match.
				    !ps_strncmp(item, match + baselen,
	/* Just a random prefix match */
			       const char *base, int baselen,
			contents_start = contents;
		retval = find_tree_entry(r, &t, name, oid, mode);
	const void *ptr;
enum interesting tree_entry_interesting(struct index_state *istate,
	if (still_interesting < 0)
		pathlen--;
		die("%s", err.buf);
			 * can probably return all_entries_interesting or
				      1 + first_slash - namebuf.buf);
{
			goto interesting;
		return 1;

	 *  10  |  file |    2     |    2     |  -1
		 *
	positive = do_match(istate, entry, base, base_offset, ps, 0);
	if (!*path) {

/*

	 *   6  |  file |    1     |    2     |   0
			mask |= 1ul << i;
		return 1; /* keep looking */
 */
		if (cmp > 0)
		       PATHSPEC_MAXDEPTH |
}
			}
		} else if (S_ISREG(*mode)) {
		update_tree_entry(&t->d);
		if (!skip)
		return positive;
	return result;
 * Pre-condition: either baselen == base_offset (i.e. empty path)
	}
	/* #8, #18 */
	return 0;
		if (baselen == 0 || !basecmp(item, base_str, match, baselen)) {
			return 0;
	strbuf_release(&base);
	if (!size) {
		}
					&never_interesting))
void *fill_tree_descriptor(struct repository *r,
			}
				 struct strbuf *base, int base_offset,
		 * matching. We could do something clever with inexact
		if (ret)
	unsigned long size;
void strbuf_make_traverse_path(struct strbuf *out,
		for (i = 0; i < n; i++)
	return all_entries_not_interesting; /* #10, #20 */
			oidcpy(result, &oid);
	static struct traverse_info dummy;
#define GET_TREE_ENTRY_FOLLOW_SYMLINKS_MAX_LINKS 40
	/*
	if (!matchlen ||
			if (match_entry(item, entry, pathlen,
}

						    &link_len);
		return get_tree_entry(r, &oid, name + entrylen, result, mode);
		retval = -1;
			if (mask & (1ul << i))
	info->name = base;
		struct object_id *tree_oid, const char *name,
		struct tree_desc_skip *skip = xmalloc(sizeof(*skip));
	desc->buffer = buffer;
 * symlink points outside the repository (e.g. a link to /foo or a
	void *tree;
			} else {
		if (pos < namelen)
		 * be performed in the submodule itself.
	while (1) {
}

	for (;;) {

/*
		unsigned long mask, dirmask;
	desc->buffer = buf;
			die("unable to read tree %s", oid_to_hex(oid));
				/* Cull the ones that are not the earliest */
	unsigned int mode, len;
					match + baselen, matchlen - baselen,
			if (namebuf.buf[0] == '\0') {
 * From the extended tree_desc, extract the first name entry, while
			if (!e->path)

	init_tree_desc(&t, NULL, 0UL);

	return 0;
		return 0;
			goto done;
 */
				  struct strbuf *base,
		 */
		for (i = 0; i < n; i++) {
			unsigned long link_len;
			strbuf_setlen(base, base_offset + baselen);
	 *  15  |  dir  |    1     |    1     |   1 (*)

	case 0:

}
	if (basecmp(item, base, match, matchlen))
		die(_("too-short tree file"));
enum get_oid_result get_tree_entry_follow_symlinks(struct repository *r,
		/* Either there must be no base, or the base must match. */
			/* If it doesn't match, move along... */

		return -1;
		 * "Never interesting" trick requires exact

	struct name_entry entry[MAX_TRAVERSE_TREES];
/*
		while (dirlen && match[dirlen - 1] != '/')
			enum object_type type;
					  info->name, info->namelen);
	if (size)
				 const struct name_entry *entry,
			 */
 * already.
	strbuf_release(&err);
int init_tree_desc_gently(struct tree_desc *desc, const void *buffer, unsigned long size)

{

		if (!buf)
	make_traverse_path(out->buf + out->len, out->alloc - out->len,
			 * of those files inside may match some attributes
	return path;
			/*
		/*
			 * one symlink, so on error we need to report this.
	if (oid) {
				e = entry + i;
	if (n >= ARRAY_SIZE(entry))
		return within_depth(base->buf + base_offset, baselen,
	negative = do_match(istate, entry, base, base_offset, ps, 1);
	if (result)
	const unsigned hashsz = the_hash_algo->rawsz;

 * entry we processed early when update_extended_entry() is called.
static void update_extended_entry(struct tree_desc_x *t, struct name_entry *a)

			   info, name, namelen);
	}
}
				oidcpy(result, &root);
	path = get_mode(buf, &mode);
	probe = t->d;
				retval = FOUND;

static int update_tree_entry_internal(struct tree_desc *desc, struct strbuf *err)
 * See the code for enum get_oid_result for a description of
	struct tree_desc probe;
			init_tree_desc(&t, parent->tree, parent->size);
	 * base comparison.
			retval = DANGLING_SYMLINK;
	strbuf_setlen(out, out->len + len);
		if (ps->recursive && S_ISDIR(entry->mode))
	int retval = MISSING_OBJECT;
{
		}
		    ( exclude && !(item->magic & PATHSPEC_EXCLUDE)))
		 * non-wildcard part but it does not match.
		 * with their common parts?
	unsigned long len = end - (const unsigned char *)buf;
		return -1;
	return retval;
		*matched = baselen;
	const char *match = item->match;
		 * linux-2.6 does not show any clear improvements,
		 * wildcard characters, ensure that the entry
				continue;
{
	struct object_id oid;
	if (negative <= entry_not_interesting)
	}
		if (item->attr_match_nr) {

{

		}
	 *   2  |  file |    0     |  -1..2   |   0
	if (positive == all_entries_interesting &&

 * or base[baselen-1] == '/' (i.e. with trailing slash).

 * Find a tree entry by following symlinks in tree_sha (which is
	entry_clear(a);
	 *
	if (size)
			entry_clear(a);
		 * partly because of the nowildcard_len optimization
			}

		}
							  &current_tree_oid,
				return entry_interesting;

			if (S_ISDIR(entry[i].mode))
	 */
			    const char *match, int matchlen)
static void entry_clear(struct name_entry *a)
			strbuf_setlen(base, base_offset + baselen);
		if (!pos)
	size_t i, parents_nr = 0;

		       PATHSPEC_GLOB |
	if (baselen) {
static int match_entry(const struct pathspec_item *item,
			 * Consider all directories interesting (because some
	}
			BUG("traverse_info ran out of list items");
		 * [1], which saves a memcpy and potentially a
		if (!git_fnmatch(item, match, base->buf + base_offset,
	 */
				      0, info->pathspec);
		if (entrylen > namelen)
		return 2;
				if (ps->recursive && S_ISDIR(entry->mode))
		/*
				 */
		 * and another tree may return "t".  We want to grab

	if (!desc->size)
		}
				first_len = len;
{
		const char *first = NULL;
			return 0;


static int init_tree_desc_internal(struct tree_desc *desc, const void *buffer, unsigned long size, struct strbuf *err)
		}
	int i;
	size_t pos = st_add(info->pathlen, namelen);
			/*
			break;
		return 0;
				len = namebuf.len;
	 * We are looking at *b* in a tree.
		 * When matching against submodules with
				if (name_compare(e->path, len, first, first_len))
	if (m == -1)
			strbuf_remove(&namebuf, 0, 1);
static void entry_extract(struct tree_desc *t, struct name_entry *a)

		struct name_entry *e = NULL;
		namelen = info->namelen;

				if (!item->attr_match_nr)
		    !ps_strncmp(item, match, base->buf + base_offset,
	 * Otherwise we know *a* won't appear in the tree without
	 * -----+-------+----------+----------+-------
		struct object_id oid;
		switch (check_entry_match(first, first_len, path, len)) {
	info->traverse_path = traverse_path;
		if (match[pathlen] != '/')
				first = e->path;
 * process "t-1" and "t-2" but extract "t".  After processing the
 */
{
				   struct name_entry *a,
	enum interesting never_interesting = ps->has_wildcard ?
	unsigned int mode = 0;
static int basecmp(const struct pathspec_item *item,

		entry_not_interesting : all_entries_not_interesting;
			return NULL;
static const char *get_mode(const char *str, unsigned int *modep)
		return decode_tree_entry(desc, buf, size, err);
		if ((first_slash = strchr(namebuf.buf, '/'))) {
				 * character.  More accurate matching can then
	 */
 * Pre-condition: either baselen == base_offset (i.e. empty path)
		update_tree_entry(t);
		skip->ptr = a->path;

	struct tree_desc_skip *p, *s;
		 * non-wildcard part but it does not match. Note that
int update_tree_entry_gently(struct tree_desc *desc)
	}

			BUG("traverse_info pathlen does not match strings");
			if (remainder)

		case -1:
		return 1;
					goto interesting;
	if (size < len)
	/* b comes after a; are we looking at case (2)? */
	for (;;) {
	struct strbuf err = STRBUF_INIT;
		entry_clear(a);
static enum interesting do_match(struct index_state *istate,
		if (!ps->recursive ||
		       PATHSPEC_FROMTOP |
	int cmp = name_compare(a, a_len, b, b_len);
		match += n;
			retval = FOUND;
	return str;
				  int still_interesting)
	}
	/* Initialize the descriptor entry */
	int follows_remaining = GET_TREE_ENTRY_FOLLOW_SYMLINKS_MAX_LINKS;
	struct strbuf base = STRBUF_INIT;
		 * eventually by basecmp with special treatment for

			for (i = 0; i < n; i++) {
		}
	for (i = 0; i < parents_nr; i++)
	unsigned long size = desc->size;
}
 * pathspec. item->nowildcard_len must be greater than zero. Return
			char *contents, *contents_start;
			       const struct traverse_info *info,
		entry_extract(&t->d, a);
							  tree_type, &size,
	buf = end;
	/*
/**
		strbuf_add(base, entry->path, pathlen);
	} else
	 *   9  |  file |    2     |    1     |   0
		while (namebuf.buf[0] == '/') {
	/* #15, #19 */
{
static void extended_entry_extract(struct tree_desc_x *t,
		if (interesting < 0)
			continue;
	int error = 0;

	/*

					goto interesting;
	int namelen = strlen(name);

		for (i = 0; i < n; i++) {
#include "object-store.h"

				 item->nowildcard_len)) {
		info->prev = &dummy;
				/*
			    const char *base,

			strbuf_setlen(base, base_offset + baselen);
{
	    match[matchlen - 1] == '/')
						 item->nowildcard_len - baselen))
			return 0;
		}
{

	int pathlen, baselen = base->len - base_offset;
		 * pathspecs are either outside of base, or inside the
		    ps->max_depth == -1)
		}
		p = s->prev;
	} else {
			 * appears in a symlink.


		 * later on.
	 * (2) *a* == "t",   *b* == "t-2" and "t" is a subtree in the tree;
			continue;
		 * that here.
		 * While we could avoid concatenation in certain cases
			if (remainder)
	 */
			}

	if (!info->pathspec || still_interesting == 2)
				    S_ISGITLINK(entry->mode) &&
	}
		 * We have not seen any match that sorts later
	 *   7  |  file |    2     |   -1     |   2
		}
		    !match_wildcard_base(item, base_str, baselen, &matched))
	desc->entry.path = path;

		return entry_interesting;
		}
				retval = NOT_DIR;
	free(traverse_path);
		strbuf_addstr(err, _("too-short tree object"));
	if (item->magic & PATHSPEC_ICASE) {
			/* descend */
		int find_result;
	 * (3) *a* == "t-2", *b* == "t"   and "t-2" is a blob in the tree.
			*matched = matchlen;
		update_tree_entry(&t->d);
	const char *path;
					 ps->max_depth))
		path = a->path;
		struct object_id *result, struct strbuf *result_path,

			return all_entries_interesting;
		 * https://lore.kernel.org/git/7vmxo5l2g4.fsf@alter.siamese.dyndns.org/
	int i;
		m = ps_strncmp(item, match, entry->path, pathlen);
		die("%s", err.buf);



#include "dir.h"
	desc->size = size;
	void *tree;
			entry_clear(a);
			parents[parents_nr].size = size;
		 */
		 * than the wildcard's codepath of '[Tt][Hi][Is][Ss]'

	init_tree_desc(desc, buf, size);
		strbuf_addstr(err, _("malformed mode in tree entry"));
	 * ones that we already returned in earlier rounds.
	 *   8  |  file |    2     |    0     |   1
	/*
struct tree_desc_skip {
				goto interesting;
		if (namebuf.buf[0] == '\0') {
		interesting = prune_traversal(istate, e, info, &base, interesting);
{

		}
			break;
		base += n;
			return 0;
		 * match_entry does not check if the prefix part is

		/* Split namebuf into a first component and a remainder */

			if (S_ISDIR(entry->mode))
				if (!git_fnmatch(item, match + baselen, entry->path,

		 * in git_fnmatch(). Avoid micro-optimizations here.
	}
	if (a_len < b_len && !memcmp(a, b, a_len) && b[a_len] < '/')

}
		int matchlen = item->len, matched = 0;
			 * even though the parent dir does not)
					      &current_tree_oid, mode);
		 * directory
		/* a comes after b; it does not matter if it is case (3)
			}
		entry_extract(&probe, a);
	     negative == entry_interesting)) /* #9 */
	strbuf_grow(out, len);

		 */
	info->namelen = pathlen;

	size_t len = traverse_path_len(info, namelen);


			struct dir_state *parent;
		BUG("traverse_trees() called with too many trees (%d)", n);

	}
		return -1;
		strbuf_make_traverse_path(&base, info->prev,
		if (!S_ISDIR(entry->mode) && !S_ISGITLINK(entry->mode))
		 * fnmatch() on it.

 * assumed to be the root of the repository).  In the event that a
						entry->path,
			continue;
		oidcpy(&oid, tree_entry_extract(t, &entry, mode));
		return -1;
	update_tree_entry(desc);
done:

			strbuf_splice(&namebuf, 0, len,
 * with the sha1 of the found object, and *mode will hold the mode of
		if (!t.buffer) {
		 * Match all directories. We'll try to match files


	*entry = desc->entry;
				  struct name_entry *e,
	if (!cmp)
		len -= n;
		return entry_not_interesting;
	struct tree_desc_x tx[ARRAY_SIZE(entry)];
	if (pathlen > matchlen)
		 * glibc). Just disable it for now. It can't be worse
				len = tree_entry_len(e);


	struct strbuf err = STRBUF_INIT;
	struct strbuf err = STRBUF_INIT;
			parent = &parents[parents_nr - 1];
		return entry_interesting;
			break;
	len = strlen(path) + 1;
int tree_entry(struct tree_desc *desc, struct name_entry *entry)
	}
			break;
}
		if (first) {
	 *
			ret = match_pathspec_attrs(istate, base->buf + base_offset,
		if (m < 0)

	GUARD_PATHSPEC(ps,
	}

			extended_entry_extract(tx + i, e, NULL, 0);
{
				goto interesting;
	if (!first || !a->path)
		return NULL;

	 * behind *b*.
					   namebuf.len);
#include "tree.h"
				goto done;
			 * prematurely. We do not know if all entries do not
		const char *match = item->match;
		 * the rest, which is shorter so _in theory_ faster.
{
 * non-zero if base is matched.
		dirlen = matchlen;
{
			mask &= trees_used;
	if (init_tree_desc_internal(desc, buffer, size, &err))
 * Perform matching on the leading non-wildcard part of
			init_tree_desc(&t, parent->tree, parent->size);
	unsigned long size;
	free(parents);
			if (a->path == skip->ptr)
		char *remainder = NULL;
		if (S_ISDIR(*mode)) {
		*never_interesting = entry_not_interesting;
	if (info->prev) {
				oidcpy(result, &current_tree_oid);
	}
{
			free(parent->tree);
	pathlen = tree_entry_len(entry);
};
	path[pos] = 0;
{
			free(contents);
	desc->size = size;
 * the object.
void init_tree_desc(struct tree_desc *desc, const void *buffer, unsigned long size)
	for (i = 0; i < n; i++) {
	*a = t->entry;
	struct tree_desc_skip *prev;
	 *                                matter what.

			continue;
				 * at least matches up to the first wild
			}
					 baselen - matchlen - 1,
			parents_nr--;
		if (b_len < a_len && !memcmp(a, b, b_len) && a[b_len] < '/')

		 * though it may have "t" that is a subtree behind it,
	memset(info, 0, sizeof(*info));

			struct object_id root;
		   const char *name,
			strbuf_remove(&namebuf, 0, remainder ? 3 : 2);
			int ret;
		 * A tree may have "t-2" at the current location even
	strbuf_addstr(&namebuf, name);
char *make_traverse_path(char *path, size_t pathlen,

	 * If common part matched earlier then it is a hit,
}
		strbuf_addstr(err, _("empty filename in tree entry"));
		/*
		int dirlen;
 * points to an object inside the repository, result will be filled in
		/*
		 * subsequent entries.  In such a case, we initialized
			break;
	for (i = 0; i < n; i++)
			trees_used = info->fn(n, mask, dirmask, entry, info);
			if (trees_used < 0) {
	 *  18  |  dir  |    2     |    0     |   1
 * paying attention to the candidate "first" name.  Most importantly,
 * when looking for an entry, if there are entries that sorts earlier
{

	struct dir_state *parents = NULL;
	free(tree);
		 * in future, see

		return positive;
 * choice.

		continue;
	*modep = mode;
				if (ps->recurse_submodules &&
		if (!strcmp(namebuf.buf, "..")) {
interesting:
		int trees_used;
		return cmp;
		 */
			oidcpy(result, &oid);
			continue;
 * Is a tree entry interesting given the pathspec we have?
				len = first_slash - namebuf.buf;
	 *  19  |  dir  |    2     |    1     |   1 (*)
		int entrylen, cmp;
			if (!ps->recursive ||
			break; /* not found */
			parents[parents_nr].tree = tree;
			   struct tree_desc *desc,
	 */
static int check_entry_match(const char *a, int a_len, const char *b, int b_len)
	return 0;
 * update_extended_entry() that we can remember "t" has been processed
			 * all_entries_not_interesting here if matched.
			}
	return 1;


		pos -= namelen;
		if (baselen >= matchlen) {
					const struct pathspec *ps)
	return buf;
		/* Stop processing this tree after error */
				break; /* found */
				*mode = 0;
			 * We could end up with .. in the namebuf if it
}
		 * all "t" from all trees to match in such a case.
			   const struct object_id *oid)
		 * pattern.
		t->skip = skip;
	    base[matchlen] == '/' ||
				goto done;
		unsigned short *mode)
		 * after iterating all pathspecs, it means all
		 * realloc, it turns out not worth it. Measurement on

		}
	if (!desc->size)
		if (baselen >= matchlen) {
 * or base[baselen-1] == '/' (i.e. with trailing slash).
{
	 *
	strbuf_release(&namebuf);
	}
	while (1) {
		} else if (S_ISLNK(*mode)) {
		const struct pathspec_item *item = ps->items+i;
{
			    !(ps->magic & PATHSPEC_MAXDEPTH) ||
				/* Too many symlinks followed */
		m = strncmp(match, entry->path,
			 * match some attributes with current attr API.

		}
			continue;
		 * base but sorts strictly earlier than the current
		desc->size = 0;
 *
	return -1;
			e = entry + i;
		 */
			return entry_interesting;
		       enum interesting *never_interesting)
	if (name[0] == '\0') {

		oidcpy(oid, &root);
			if (item->nowildcard_len < item->len) {
	return never_interesting; /* No matches */
		return 0;
		error("%s", err.buf);
		    !(ps->magic & PATHSPEC_MAXDEPTH) ||
			}
	/* the wildcard part is not considered in this function */
 * That limit, of course, does not affect git, but it's a reasonable
			}
		return 0;

				goto done;
 *    blob    "t=1"
			t.buffer = NULL;
				item->nowildcard_len)) {

					return entry_interesting;
			       int *matched)
	return 1;
	 *  11  |  dir  |   -1     |  -1..2   |  -1
}
	if (!m)
	}
				free(contents);
				namebuf.buf[link_len] = '/';
				oidcpy(result, &current_tree_oid);
			never_interesting = entry_not_interesting;
		memcpy(path + pos, name, namelen);
		 * [1] if match_wildcard_base() says the base
				retval = FOUND;
		if (find_result) {
int traverse_trees(struct index_state *istate,
		if (!mask)
}
		const char *entry;
			strbuf_add(base, entry->path, pathlen);
	if (pathlen)
#include "pathspec.h"
		 * Concatenate base and entry->path into one and do
 *
 * E.g. if the underlying tree object has these entries:
			else
			oidcpy(result, &parents[parents_nr - 1].oid);
		if (entrylen == namelen) {

				      contents_start, link_len);
	if (!path) {
		tx[i].skip = NULL;
		 * later than the path we are currently looking at.
				update_extended_entry(tx + i, entry + i);
				   const char *first,

			if (within_depth(base_str + matchlen + 1,
		}
	 * -----+-------+----------+----------+-------
	 *   3  |  file |    1     |   -1     |   1
	len = tree_entry_len(a);
			if (!ret)
	return -1; /* a cannot appear in the tree */
						item->nowildcard_len - baselen))
		 * least one pathspec that would sort equal to or
	}
	 * that is not in base and does similar never_interesting
		ret = strncmp(base, match, n);
 * outside the repository will be returned in result_path, and *mode
	 * scanning further.
{
			   unsigned short *mode)
				first_len = len;
	const void *buf = desc->buffer;
	 *  17  |  dir  |    2     |   -1     |   2
}
				strbuf_addstr(result_path, contents);
{
		 * directory and part of prefix, it'll be rematched
void update_tree_entry(struct tree_desc *desc)
				continue;
				 * Match all directories. We'll try to
		 * strcasecmp is locale-dependent, at least in
		/* Look up the first (or only) path component in the tree. */
void setup_traverse_info(struct traverse_info *info, const char *base)
			e = entry + i;
	int interesting = 1;
		return;
		/*
	 */
	 * wildcard case, it can't decide until looking at individual
int get_tree_entry(struct repository *r,
	return retval;
	} else {

 */
	/* Most common case first -- reading sync'd trees */
			*first_slash = 0;
}
			update_tree_entry(&probe);
					*first_slash = '/';
				 * match files later on.
		/*
}
		case 0:
			 const char *name, size_t namelen)
	int m = -1; /* signals that we haven't called strncmp() */
				/*

			if (!contents)

	enum interesting positive, negative;

	}
			return ret;
				error = trees_used;

 *    tree    "t"
	strbuf_release(&err);
	for (s = t->skip; s; s = p) {
		dirmask = 0;
		if (name[entrylen] != '/')
		 * Return early if base is longer than the
			return 0;
		free_extended_entry(tx + i);

{
		return entry_interesting;
static inline int prune_traversal(struct index_state *istate,
}
	memset(a, 0, sizeof(*a));
	if (0 < cmp) {
				   int first_len)
	 *  12  |  dir  |    0     |  -1..2   |   0
 * in the tree object representation than that name, skip them and
		find_result = find_tree_entry(r, &t, namebuf.buf,
	int matchlen = item->nowildcard_len;

					continue;
		init_tree_desc(&t, tree, size);
	tree = read_object_with_reference(r, tree_oid, tree_type, &size, &root);
			len = tree_entry_len(e);
		 * base ends with '/' so we are sure it really matches
	 *  14  |  dir  |    1     |    0     |   1

			/* Descend the tree */
			remainder = first_slash + 1;
		len = tree_entry_len(a);
		return 0;
}
	 * because we rejected the case where path is not a
	 * The caller wants to pick *a* from a tree or nothing.
		/*
	}
		int ret, n = len > item->prefix ? item->prefix : len;
{
		       PATHSPEC_ATTR);
	}
 *
 * will be set to 0.  It is assumed that result_path is uninitialized.
		if (c < '0' || c > '7')
				 * wildcard characters, ensure that the entry

			}
			break;
			       const char *name, size_t namelen)
			tree = read_object_with_reference(r,
			oidcpy(&parents[parents_nr].oid, &root);
}
	}
	default:

		 * max_depth is ignored but we may consider support it
		 * If we come here even once, that means there is at

 * and the "first" asks for "t", remember that we still need to
		return 0;
	if (!(ps->magic & PATHSPEC_EXCLUDE) ||
		   struct object_id *oid,
		entrylen = tree_entry_len(&t->entry);

			/* Follow a symlink */
		 * Does match sort strictly earlier than path
	desc->entry.mode = canon_mode(mode);
			if (!entry[i].path)
	    negative == entry_not_interesting)
		*never_interesting = entry_not_interesting;
				retval = SYMLINK_LOOP;
		 *

		path[--pos] = '/';


{
		       const struct name_entry *entry, int pathlen,
		for (skip = t->skip; skip; skip = skip->prev)

		if (item->nowildcard_len &&
			if (!remainder) {
		 */
		 */
	if (matchlen > pathlen) {
				*mode = 0;

		/* we have returned this entry early */

		error("%s", err.buf);
 * the return values.
			parent = &parents[parents_nr - 1];
	}
	struct object_id current_tree_oid;
		if (cmp < 0)

			return;
	size_t parents_alloc = 0;

		/*

				goto done;
				    !!S_ISDIR(entry->mode),
	int len;
}
				 int exclude)
		strbuf_addch(&base, '/');
	}
		if (!info)
		return -1;
			break;
			ALLOC_GROW(parents, parents_nr + 1, parents_alloc);
				goto match_wildcards;
