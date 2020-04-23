	void *buffer;
		    !memcmp(name, prefix, toplen)) {
	if (!buf)
static void match_trees(const struct object_id *hash1,
	int toplen;
			}

		struct object_id *shifted,
static int base_name_entries_compare(const struct name_entry *a,
		candidate = 0;
				/* they are different */
}
	return score;
	}
{
	oidcpy(shifted, hash2);
	 */
		int depth_limit)
	next:
		unsigned short mode;
		oidcpy(shifted, hash2);
	return score;
	return score;
	/*
		if (score > best_score)
	buf = read_object_file(oid1, &type, &sz);
		 */
 */
		score = -5;
	status = write_object_file(buf, sz, tree_type, result);
		if (one.size && two.size)
 * Match one itself and its subtrees with two and pick the best match.
						       two.entry.mode);
			score += score_missing(two.entry.mode);
		   const char *shift_prefix)
	char *add_prefix;


		}
		/* Both are plausible -- we need to evaluate the score */
	void *one_buf = fill_tree_desc_strict(&one, hash1);
	else
	}
	match_trees(hash1, hash2, &add_score, &add_prefix, "", depth_limit);
	/* Can hash2 be a tree at shift_prefix in tree hash1? */
	return score;
		struct object_id tree_oid;
			candidate = 1;
	while (desc.size) {
		 * shift tree2 down by adding shift_prefix above it

	int score;
		score = -100;


	    S_ISDIR(mode1))

{
static void *fill_tree_desc_strict(struct tree_desc *desc,
		die("cannot read tree %s", oid_to_hex(oid1));
		update_tree_entry(&desc);
		score = -50;
		const struct object_id *hash1,


}

			/* path appears in both */
			int *best_score,

	if (!*add_prefix)
			 *     know it points into our non-const "buf"
	enum object_type type;
		} else if (cmp > 0) {
			/* two lacks this entry */
	init_tree_desc(desc, buffer, size);
			/*
			break;
		}
			} else {
			return;
	unsigned char *rewrite_here;
			update_tree_entry(&one);
	 * two with a few fake trees to match the prefix.
static int score_trees(const struct object_id *hash1, const struct object_id *hash2)

		return;
 * other hand, it could cover tree one and we might need to pick a
				score += score_differs(one.entry.mode,
	del_prefix = xcalloc(1, 1);
		candidate |= 2;
		int best_score = score_trees(hash1, hash2);
		/*
{
	int add_score, del_score;

			char *newbase = xstrfmt("%s%s/", base, path);
/*
		if (get_tree_entry(r, hash2, del_prefix, shifted, &mode))
	struct tree_desc desc;
				die("entry %s in tree %s is not a tree", name,
			update_tree_entry(&two);
		update_tree_entry(&one);
	while (one.size) {
	struct tree_desc one;
	}
 * replacing it with another tree "oid2".
		int score;
	hashcpy(rewrite_here, rewrite_with->hash);
	}
static int score_matches(unsigned mode1, unsigned mode2)
		   struct object_id *shifted,
		splice_tree(hash1, shift_prefix, hash2, shifted);

			free(newbase);
	rewrite_here = NULL;
{
	return base_name_compare(a->path, tree_entry_len(a), a->mode,
}
 * shifted down by prefixing otherwise empty directories.  On the
	char *subpath;
/*
			    del_prefix, oid_to_hex(hash2));
		if (*best_score < score) {
		 * shift tree2 up by removing shift_prefix from it
	else
							 strlen(desc.entry.path) +
		else
	}
		if (!*del_prefix)
		}
		   const struct object_id *hash2,
	if (!get_tree_entry(r, hash2, shift_prefix, &sub2, &mode2) &&
		int score;
			update_tree_entry(&one);
}
			/* path2 does not appear in one */
		const struct object_id *elem;
	 * value '2' to avoid excessive overhead.
{
	int score = 0;
 */

		else if (two.size)
	struct tree_desc one;
	struct object_id subtree;
#include "cache.h"
		 * to match tree1.
		/* We need to pick a subtree of two */
			if (!oideq(&one.entry.oid, &two.entry.oid)) {
	const struct object_id *rewrite_with;
	else if (S_ISDIR(mode1))
		   const struct object_id *hash1,
		return;
 * correspond to a subtree of one, in which case it needs to be
	init_tree_desc(&desc, buf, sz);
		oidcpy(shifted, &sub2);
	free(one_buf);
#include "object-store.h"
	free(two_buf);
	for (;;) {
	 * pick only subtree of two.
	unsigned candidate = 0;
		return;
	/*
	    S_ISDIR(mode2))
				/* same subtree or blob */
static int splice_tree(const struct object_id *oid1, const char *prefix,
 * Unfortunately we cannot fundamentally tell which one to

	void *two_buf = fill_tree_desc_strict(&two, hash2);
				   const struct object_id *hash)
		elem = tree_entry_extract(&one, &path, &mode);
	return buffer;


		int cmp;
	if (!depth_limit)
	if (!get_tree_entry(r, hash1, shift_prefix, &sub1, &mode1) &&
}
			die("cannot find path %s in tree %s",
				     const struct name_entry *b)
{
	add_prefix = xcalloc(1, 1);
			break;
			cmp = -1;
		rewrite_with = oid2;
	 * See if one's subtree resembles two; if so we need to prefix
			 *     char *" (for the hash stored after it)
		die("entry %.*s not found in tree %s", toplen, prefix,
			 */
			rewrite_here = (unsigned char *)(desc.entry.path +

	if (candidate == 3) {
		score = -500;

 */

			best_score = score;

			/* path1 does not appear in two */
void shift_tree(struct repository *r,


			if (!S_ISDIR(mode))
	else
}
	if (!candidate) {
		hashcpy(tree_oid.hash, rewrite_here);
{
	int score;
		die("unable to read tree (%s)", oid_to_hex(hash));
	enum object_type type;
		       const struct object_id *oid2, struct object_id *result)
static int score_missing(unsigned mode)
		}
		score = -1000;
	else if (S_ISLNK(mode))
	else if (S_ISLNK(mode1))
 * Inspect two trees, and give a score that tells how similar they are.
			candidate = 2;
			char **best_match,
	unsigned short mode1, mode2;

	free(buf);

			*best_match = xstrfmt("%s%s", base, path);
	if (S_ISDIR(mode1) != S_ISDIR(mode2))
}
	/*
}
	else if (S_ISLNK(mode1) != S_ISLNK(mode2))

			const char *base,


{
	/* Heh, we found SHA-1 collisions between different kind of objects */
	 * NEEDSWORK: this limits the recursion depth to hardcoded

 * results in a tree shape similar to one.  The tree two might
}
	else if (S_ISLNK(mode1) != S_ISLNK(mode2))
		candidate |= 1;
			cmp = base_name_entries_compare(&one.entry, &two.entry);
		rewrite_with = &subtree;
	if (*subpath)
		depth_limit = 2;
		score = score_trees(&sub1, hash2);
	} else {
		if (!S_ISDIR(mode))
		const struct object_id *hash2,
{

		score = 250;
	toplen = subpath - prefix;

		} else {
	return status;
		/*

	subpath = strchrnul(prefix, '/');
	if (add_score < del_score) {
		if (status)
/*
 * The user says the trees will be shifted by this much.
			return status;
	 */
{
		else if (one.size)
			goto next;
		score = 1000;
			*best_score = score;

	free(one_buf);
 */
		if (score > best_score) {

			int recurse_limit)
		die("%s is not a tree", oid_to_hex(hash));
						       two.entry.mode);

				score += score_matches(one.entry.mode,
		 * to match tree1.
	}
 * A tree "oid1" has a subdirectory at "prefix".  Come up with a tree object by
	}
		}
static int score_differs(unsigned mode1, unsigned mode2)
	unsigned long sz;

	if (type != OBJ_TREE)
 * be prefixed, as recursive merge can work in either direction.
#include "tree.h"
 * We are trying to come up with a merge between one and two that
/*
			cmp = 1;
		if (cmp < 0) {

	/* Assume we do not have to do any shifting */

 * subtree of it.
	 */
	match_trees(hash2, hash1, &del_score, &del_prefix, "", depth_limit);
		    oid_to_hex(oid1));
		score = -50;
	struct object_id sub1, sub2;
							 1);
		score = score_trees(elem, hash2);
}
			const struct object_id *hash2,
	if (*subpath) {
	splice_tree(hash1, add_prefix, hash2, shifted);
			 *   - to flip the "char *" (for the path) to "unsigned
			 *   - to discard the "const"; this is OK because we
	if (S_ISDIR(mode))
		tree_entry_extract(&desc, &name, &mode);
		score = -50;
		status = splice_tree(&tree_oid, subpath, oid2, &subtree);
		/* Neither is plausible -- do not shift */
void shift_tree_by(struct repository *r,
#include "tree-walk.h"
	int status;
 */
		score = 500;
	buffer = read_object_file(hash, &type, &size);
	/* Can hash1 be a tree at shift_prefix in tree hash2? */

				    newbase, recurse_limit - 1);
			 * We cast here for two reasons:
	struct tree_desc two;
			update_tree_entry(&two);
		unsigned short mode;


		if (strlen(name) == toplen &&
	void *one_buf = fill_tree_desc_strict(&one, hash1);
			match_trees(elem, hash2, best_score, best_match,
	if (!buffer)
			free(*best_match);
		const char *name;
	if (S_ISDIR(mode1) != S_ISDIR(mode2))
			 *
	int score;
			/* two has more entries */
		if (recurse_limit) {
				    oid_to_hex(oid1));
/*
	 * See if two's subtree resembles one; if so we need to
			 *
	add_score = del_score = score_trees(hash1, hash2);
				 b->path, tree_entry_len(b), b->mode);
		subpath++;
		unsigned short mode;
	else
	char *buf;
		const char *path;
	if (!rewrite_here)
		score = score_trees(&sub2, hash1);
	char *del_prefix;
	if (candidate == 1)
		score = -100;
			score += score_missing(one.entry.mode);
	unsigned long size;
		 */
