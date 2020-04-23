	res->path = path;
	their = NULL;
	mmfile_t src, dst;
		/* We added, modified or removed, they did not touch -- take ours */
static void *get_tree_descriptor(struct repository *r,
}
	case 2:

	return merge_blobs(the_repository->index, path,
		entry = link_entry(1, info, n + 0, entry);
			   base, our, their, size);

			return "added in both";
}

	if (repo_get_oid(r, rev, &oid))
#include "merge-blobs.h"
{
 *    NOTE NOTE NOTE! FIXME! We really really need to walk the index
 *
	buf2 = fill_tree_descriptor(r, t + 2, ENTRY_OID(n + 2));
	const char *path;
static void unresolved_directory(const struct traverse_info *info,

	int i;
	return mask;
 *	"2 mode sha1 filename"
	struct merge_list *link;
		oideq(&a->oid, &b->oid) &&


		entry = link_entry(2, info, n + 1, entry);
static char *traverse_path(const struct traverse_info *info, const struct name_entry *n)
 * The output will be either:
		printf("%.*s", (int) mb[i].size, mb[i].ptr);
	show_result();
}
static int threeway_callback(int n, unsigned long mask, unsigned long dirmask, struct name_entry *entry, struct traverse_info *info)
		usage(merge_tree_usage);
	struct merge_list *res = xcalloc(1, sizeof(*res));
{
	free(dst.ptr);
 * The successful merge rules are the same as for the three-way merge
	return res;
#include "builtin.h"
 *    in parallel with this too!
{
		return;
		a->mode == b->mode;
#include "exec-cmd.h"
		/*



	buf = fill_tree_descriptor(r, desc, &oid);
	else
 *	 "0 mode sha1 filename"
	xpp.flags = 0;
	}

		base = entry->blob;
	info.fn = threeway_callback;
{
	return	!is_null_oid(&a->oid) &&
	}
 * seen as the directory going away, and the filename being created.
	struct merge_list *entry = NULL;
	setup_traverse_info(&info, base);
		entry = entry->link;
{


	add_merge_entry(entry);
	xdemitcb_t ecb;
 *	"3 mode sha1 filename"
	if (dirmask == mask)
	ecb.out_line = show_outf;
		return "removed in both";
	unresolved_directory(info, n);
#undef ENTRY_OID
	if (entry->stage == 3)
		if (entry->stage == 2)

	if (!src.ptr)
}

 * This walks the (sorted) trees in lock-step, checking every possible

	const char *path;
	walk = merge_result;
				 const char *rev)
	add_merge_entry(final);
}
	}
}
				 struct name_entry n[3])

		if (entry->link)
			resolve(info, entry+1, entry+2);
{
	final->link = orig;
	buf1 = get_tree_descriptor(r, t+0, argv[1]);
		return mask;
	const char *path;
static void merge_trees(struct tree_desc t[3], const char *base)
	do {
		path = traverse_path(info, n);
#define ENTRY_OID(e) (((e)->mode && S_ISDIR((e)->mode)) ? &(e)->oid : NULL)
}
}
		die("unknown rev %s", rev);
	case 0:
 *

	if (n + 3 <= p)
#include "blob.h"
		mask |= (1 << i);
	free(buf2);
		return mask;
	res->mode = mode;
	free(newbase);
	xdemitconf_t xecfg;
	orig = create_entry(2, ours->mode, &ours->oid, path);
	char *newbase;
#include "tree-walk.h"
		entry = link_entry(3, info, n + 2, entry);
		printf("  %-6s %o %s %s\n", desc[entry->stage], entry->mode, oid_to_hex(&entry->blob->object.oid), entry->path);
		return "added in local";

			dirmask |= (1 << i);
		show_diff(walk);
	if (n[1].mode && !S_ISDIR(n[1].mode))
			return read_object_file(&entry->blob->object.oid,
 *  - successful merge
	}
int cmd_merge_tree(int argc, const char **argv, const char *prefix)

 * conflicts, because they won't ever compare the same.

			break;
/* An empty entry never compares same, not even to another empty entry */
	if (!entry->stage)
	free(buf2);
 *
	newbase = traverse_path(info, p);

	path = traverse_path(info, result);
		entry = entry->link;
	struct name_entry *p;

static int both_empty(struct name_entry *a, struct name_entry *b)
	case 3:
	free(src.ptr);
	if (same_entry(entry+0, entry+2) || both_empty(entry+0, entry+2)) {
static struct merge_list *link_entry(unsigned stage, const struct traverse_info *info, struct name_entry *n, struct merge_list *entry)
		 * If we did not touch a directory but they made it
		size = 0;


		their = entry->blob;
	free(buf3);
	if (same_entry(entry+1, entry+2) || both_empty(entry+1, entry+2)) {
}
	/* Same in both? */

 * Think of this as a three-way diff.

}
{
	xecfg.ctxlen = 3;

	for (p = n; p < n + 3; p++) {
static void *result(struct merge_list *entry, unsigned long *size)
	unresolved(info, entry);
	void *buf;
	enum object_type type;
{
	} while (entry);
	return NULL;
	if (entry->link)
{
	struct strbuf buf = STRBUF_INIT;
	struct traverse_info info;
	src.ptr = origin(entry, &size);
		walk = walk->next;

	unsigned dirmask = 0, mask = 0;

	return is_null_oid(&a->oid) && is_null_oid(&b->oid);
	ecb.out_hunk = NULL;
	src.size = size;
			/* We did not touch, they modified -- take theirs */
}
	memset(&xecfg, 0, sizeof(xecfg));
	struct object_id oid;

	buf2 = get_tree_descriptor(r, t+1, argv[2]);
{
{
		 * into a file, we fall through and unresolved()
		return entry;
static void unresolved(const struct traverse_info *info, struct name_entry n[3])

	if (xdi_diff(&src, &dst, &xpp, &xecfg, &ecb))
		path = entry->path;

	struct repository *r = the_repository;
	/* If it's already ours, don't bother showing it */
	if (entry)
	buf0 = fill_tree_descriptor(r, t + 0, ENTRY_OID(n + 0));
	unsigned long size;
 *  - conflict:
{
static void resolve(const struct traverse_info *info, struct name_entry *ours, struct name_entry *result)
		/* Modified, added or removed identically */
		/*
		struct merge_list *link = entry->link;
static struct merge_list *create_entry(unsigned stage, unsigned mode, const struct object_id *oid, const char *path)
		entry = link;


		}
	free(buf1);
	ecb.priv = NULL;
	traverse_trees(&the_index, 3, t, &info);
 * in git-read-tree.
	}
 * IOW, if a directory changes to a filename, it will automatically be
}
	merge_trees(t, "");

		return "added in remote";
		return; /* there is no tree here */
		if (p->mode && S_ISDIR(p->mode))
static struct merge_list *merge_result, **merge_result_end = &merge_result;
	final = create_entry(0, result->mode, &result->oid, path);
		entry = entry->link;
	unsigned int stage : 2;
#include "object-store.h"

	enum object_type type;
		 * Treat missing entries as directories so that we return
	if (!buf)
	xpparam_t xpp;
 *    where not all of the 1/2/3 lines may exist, of course.
		resolve(info, NULL, entry+1);
		if (!n[i].mode || S_ISDIR(n[i].mode))
	for (i = 0; i < 3; i++) {
	return 0;
 * name. Note that directories automatically sort differently from other
	}
	if (!entry)
{
	dst.size = size;


		 * after unresolved_directory has handled this.
	switch (entry->stage) {
 *
	free(buf0);
static void show_diff(struct merge_list *entry)
};
	entry = entry->link;
		 */
		die("unable to generate diff");
	buf1 = fill_tree_descriptor(r, t + 1, ENTRY_OID(n + 1));

		if (!is_null_oid(&entry[2].oid) && !S_ISDIR(entry[2].mode)) {
	if (entry && entry->stage == 2) {
	strbuf_make_traverse_path(&buf, info, n->path, n->pathlen);
	struct merge_list *orig, *final;

		return read_object_file(&entry->blob->object.oid, &type, size);
static void show_result(void)
	res->stage = stage;
}
	return link;
	if (n[2].mode && !S_ISDIR(n[2].mode))
	res->blob = lookup_blob(the_repository, oid);
		return "removed in local";


	struct merge_list *link;	/* other stages for this object */
		resolve(info, NULL, entry+1);
	return buf;
	if (n[0].mode && !S_ISDIR(n[0].mode))
{
{
}
}
		 */
 *
	struct blob *base, *our, *their;

struct merge_list {
	merge_trees(t, newbase);

	const char *path = entry->path;

	struct repository *r = the_repository;
	return strbuf_detach(&buf, NULL);
/*
	dst.ptr = result(entry, &size);
	link = create_entry(stage, n->mode, &n->oid, path);
		show_result_list(walk);


	unsigned int mode;
{
	while (walk) {
{
	our = NULL;

	if (!ours)
static void add_merge_entry(struct merge_list *entry)
#define USE_THE_INDEX_COMPATIBILITY_MACROS
#include "xdiff-interface.h"
	}
		size = 0;
	link->link = entry;
{
	printf("%s\n", explanation(entry));
}
static const char merge_tree_usage[] = "git merge-tree <base-tree> <branch1> <branch2>";
	free(buf1);
{
	struct blob *blob;
 *	"1 mode sha1 filename"
	struct merge_list *walk;
						&type, size);
	while (entry) {
		die("%s is not a tree", rev);
static void show_result_list(struct merge_list *entry)

static const char *explanation(struct merge_list *entry)
		return "changed in both";
		return;
}
		return "merged";
 */

	struct tree_desc t[3];
	/* Existed in base */
	base = NULL;
static int same_entry(struct name_entry *a, struct name_entry *b)
 * Merge two trees together (t[1] and t[2]), using a common base (t[0])

	*merge_result_end = entry;
			return mask;
		 * recurses down.  Likewise for the opposite case.
	}
	}
	if (argc != 4)
 * as the origin.
}
}

static int show_outf(void *priv_, mmbuffer_t *mb, int nbuf)
}
	void *buf0, *buf1, *buf2;

		static const char *desc[4] = { "result", "base", "our", "their" };

	if (!dst.ptr)
	if (same_entry(entry+0, entry+1)) {
 * files (see "base_name_compare"), so you'll never see file/directory
		our = entry->blob;
	merge_result_end = &entry->next;

	int i;
	struct merge_list *next;
	buf3 = get_tree_descriptor(r, t+2, argv[3]);
	return 0;
	for (i = 0; i < nbuf; i++)
 *
	if (!n->mode)
static void merge_trees(struct tree_desc t[3], const char *base);

		!is_null_oid(&b->oid) &&
{
	return "removed in remote";
	if (entry)
	}
				 struct tree_desc *desc,
static void *origin(struct merge_list *entry, unsigned long *size)
	if (entry->stage == 1) {
#include "repository.h"

	void *buf1, *buf2, *buf3;
	struct tree_desc t[3];
