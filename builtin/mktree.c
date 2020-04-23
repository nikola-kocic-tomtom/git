


		while (1) {
{
			 * The object exists but is of the wrong type.
	char *ptr, *ntr;
	if (obj_type < 0) {
	size_t size;
			 * This is a problem regardless of allow_missing
				path, oid_to_hex(&oid), type_name(obj_type), type_name(mode_type));
	 *     mode SP type SP sha1 TAB name
	 * These should all agree.
	ptr = ntr + 1; /* type */
			puts(oid_to_hex(&oid));
		OPT_BOOL('z', NULL, &nul_term_line, N_("input is NUL terminated")),
		strbuf_addf(&buf, "%o %s%c", ent->mode, ent->name, '\0');
	oidcpy(&ent->oid, oid);
		struct strbuf p_uq = STRBUF_INIT;
	NULL

				got_eof = 1;
}
	strbuf_getline_fn getline_fn;
	strbuf_release(&buf);
		if (obj_type != mode_type) {
			fflush(stdout);
	path = (char *)p + 1;  /* at the beginning of name */
 */
static const char *mktree_usage[] = {
	if (!ntr || parse_oid_hex(ntr + 1, &oid, &p) ||
				if (is_batch_mode)
			 * consistent with the original non-batch behaviour of mktree.
		}
	struct treeent *a = *(struct treeent **)a_;
		}
static struct treeent {
int cmd_mktree(int ac, const char **av, const char *prefix)
		}
		die("path %s contains slash", path);
	}

	/*

#include "object-store.h"
		OPT_SET_INT( 0 , "batch", &is_batch_mode, N_("allow creation of more than one tree"), 1),
		strbuf_add(&buf, ent->oid.hash, the_hash_algo->rawsz);
	strbuf_init(&buf, size);
	enum object_type mode_type; /* object type derived from mode */
			/*


			 * Execution gets here if the last tree entry is terminated with a
	 */
	N_("git mktree [-z] [--missing] [--batch]"),
	append_to_tree(mode, &oid, path);
	int len;
	const struct option option[] = {
				 b->name, b->len, b->mode);
	struct object_id oid;
	if (mode_type != type_from_string(ptr)) {
 * Copyright (c) Junio C Hamano, 2006, 2009
			/*
 *
	/* Check the type of object identified by sha1 */
	write_object_file(buf.buf, buf.len, tree_type, oid);
	    *p != '\t')
}

			if (sb.buf[0] == '\0') {
	mode_type = object_type(mode);
			 * new-line.  The final new-line has been made optional to be
		used=0; /* reset tree entry buffer for re-use in batch mode */
				die("input format error: (blank line only valid in batch mode)");
}



static void write_tree(struct object_id *oid)
	struct treeent *b = *(struct treeent **)b_;
	unsigned mode;

	int got_eof = 0;
#include "parse-options.h"
	int nul_term_line = 0;
	 * Read non-recursive ls-tree output format:
#include "quote.h"


	mode = strtoul(ptr, &ntr, 8);

#include "tree.h"
	unsigned mode;
	int i;
	size_t len = strlen(path);
static int alloc, used;
	}
	strbuf_release(&sb);
			; /* no problem - missing objects are presumed to be of the right type */
			; /* skip creating an empty tree */
	char name[FLEX_ARRAY];
	exit(0);

	FLEX_ALLOC_MEM(ent, name, path, len);
	/*

/*
{
	ent->len = len;
	for (i = 0; i < used; i++) {
			write_tree(&oid);
				/* empty lines denote tree boundaries in batch mode */
		die("input format error: %s", buf);
		} else {
			die("entry '%s' object %s is a %s but specified type was (%s)",
		struct treeent *ent = entries[i];
#include "builtin.h"
	ptr = buf;
			mktree_line(sb.buf, nul_term_line, allow_missing);
}

		size += 32 + entries[i]->len;
{
		if (unquote_c_style(&p_uq, path, NULL))
	getline_fn = nul_term_line ? strbuf_getline_nul : strbuf_getline_lf;
		die("input format error: %s", buf);
					break;
	/* It is perfectly normal if we do not have a commit from a submodule */
	int allow_missing = 0;
			 * because the new tree entry will never be correct.

	const char *p;


		if (allow_missing) {
	QSORT(entries, used, ent_compare);
	 * Object type is redundantly derivable three ways.
	}
			if (getline_fn(&sb, stdin) == EOF) {
	if (strchr(path, '/'))
		OPT_END()
{
static void mktree_line(char *buf, int nul_term_line, int allow_missing)
	obj_type = oid_object_info(the_repository, &oid, NULL);
	 */
	while (!got_eof) {
		path = to_free = strbuf_detach(&p_uq, NULL);
			}
		OPT_SET_INT( 0 , "missing", &allow_missing, N_("allow missing objects"), 1),
		allow_missing = 1;
} **entries;
		if (is_batch_mode && got_eof && used < 1) {
	char *path, *to_free = NULL;
	struct treeent *ent;
static void append_to_tree(unsigned mode, struct object_id *oid, char *path)
	if (!nul_term_line && path[0] == '"') {
	struct object_id oid;
	int is_batch_mode = 0;
	struct strbuf sb = STRBUF_INIT;
	free(to_free);
	enum object_type obj_type; /* object type derived from sha */
	ALLOC_GROW(entries, used + 1, alloc);
	}
	struct object_id oid;
	entries[used++] = ent;
	ac = parse_options(ac, av, prefix, option, mktree_usage, 0);
}
		die("entry '%s' object type (%s) doesn't match mode type (%s)",
		}
	ntr = strchr(ptr, ' ');
				break;
	for (size = i = 0; i < used; i++)

			die("invalid quoting");
	return base_name_compare(a->name, a->len, a->mode,
			die("entry '%s' object %s is unavailable", path, oid_to_hex(&oid));
			 */
	};
			path, ptr, type_name(mode_type));
	} else {
	if (ptr == ntr || !ntr || *ntr != ' ')
			 */
};
			}
{
static int ent_compare(const void *a_, const void *b_)
	struct strbuf buf;
	ent->mode = mode;
	}
		} else {
	if (S_ISGITLINK(mode))
 * GIT - the stupid content tracker
	*ntr++ = 0; /* now at the beginning of SHA1 */
