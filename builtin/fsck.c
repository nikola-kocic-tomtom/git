			/*
		 * object hash as we do below. Our loop would potentially
static int mark_loose_for_connectivity(const struct object_id *oid,

	default:
		if (!get_oid(arg, &oid)) {
		check_unreachable_object(obj);
	 * We obviously want the object to be parsed,
static int fsck_obj_buffer(const struct object_id *oid, enum object_type type,

	enum object_type type;
		struct worktree *wt = *p;
	mark_unreachable_referents(oid);
		fprintf_ln(stderr, _("Checking connectivity (%d objects)"), max);
		errors_found |= ERROR_OBJECT;
	 * got dropped.
				continue;

	/* fsck knows how to handle missing promisor objects */
	argc = parse_options(argc, argv, prefix, fsck_opts, fsck_usage, 0);
	/*
	 * Avoid passing OBJ_NONE to fsck_walk, which will parse the object
		if (has_object_pack(&obj->oid))
		      oid_to_hex(oid), path);
		fprintf_ln(stderr,
		strbuf_worktree_ref(wt, &ref, "HEAD");
			error(_("%s: invalid reflog entry %s"),

		fsck_obj_options.strict = 1;
		return 0;
	err = fsck_object(obj, buffer, size, &fsck_obj_options);
		show_unreachable = 0;
#include "config.h"
		show_progress = isatty(2);

				describe_object(&obj->oid));
	 * Unreachable object that exists? Show it if asked to,
		verify_index_checksum = 1;
		include_reflogs = 0;
		if (parent && !has_object_file(&obj->oid)) {
	obj->flags |= REACHABLE;
	if (obj->flags & SEEN)
/*
	if (!obj || !(obj->flags & HAS_OBJ))
	while (pending.nr) {
static int fsck_obj(struct object *obj, void *buffer, unsigned long size)
	}
					struct packed_git *pack,
	switch (msg_type) {
static void fsck_object_dir(const char *path)

}
	return 0;

		if (fsck_finish(&fsck_obj_options))
	return 0;
		 */
	if (verbose)
static char const * const fsck_usage[] = {
			 default_refs++;
		if (include_reflogs)
	OPT_BOOL(0, "full", &check_full, N_("also consider packs and alternate objects")),
			if (safe_create_leading_directories_const(filename)) {
		/*
		struct commit *commit = (struct commit *) obj;
			   printable_type(&obj->oid, obj->type),
	if (!eaten)
static struct fsck_options fsck_obj_options = FSCK_OPTIONS_DEFAULT;
	 * The only case data is NULL or type is OBJ_ANY is when
	obj->flags |= HAS_OBJ;
	/*
		error(_("%s: invalid sha1 pointer %s"),
}

		return 0;
	int eaten;
	if (type == OBJ_NONE)
				if (is_promisor_object(&oid))
			printf_ln(_("dangling %s %s"),

			commit_graph_verify.argv = verify_argv;

	if (!*head_points_at) {
/* This flag is set if something points to this object. */
	fsck_handle_reflog_oid(refname, ooid, 0);
		if (null_is_error) {
}
static int fsck_error_func(struct fsck_options *o,
		free_tree_buffer((struct tree *)obj);
static int objerror(struct object *obj, const char *err)
	traverse_reachable();
	/* Look up all the requirements, warn about missing objects.. */
			 * valid ref.

		    msg_type);
				progress = start_progress(_("Checking objects"), total);

		error(_("invalid parameter: expected sha1, got '%s'"), arg);
		if (write_lost_and_found) {

		if (is_promisor_object(oid)) {

		if (head_points_at && !is_null_oid(&head_oid))
	}


	if (obj->type == OBJ_COMMIT) {
static int include_reflogs = 1;
		fsck_set_msg_types(&fsck_obj_options, sb.buf);
	 */
	/*
#include "object-store.h"
	 * "!USED" means that nothing at all points to it, including
				/* verify gives error messages itself */
		for_each_packed_object(mark_packed_unreachable_referents, NULL, 0);

			for (p = get_all_packs(the_repository); p;
static int show_dangling = 1;
		 * traversal.
	unsigned int nr = 0;
{
			  const char **head_points_at,
	const char *head_points_at;
			 return 0;
	if (verbose)
	/*
	 */
				  printable_type(&tag->tagged->oid, tag->tagged->type),
{
	 */
	strbuf_worktree_ref(cb_data, &refname, logname);
{
static void get_default_heads(void)
	return 0;
					die_errno(_("could not write '%s'"), filename);
	OPT_BOOL(0, "strict", &check_strict, N_("enable more strict checking")),
static int fsck_head_link(const char *head_ref_name,
			verify_argv[3] = odb->path;
	struct object *parent = data;

static void check_unreachable_object(struct object *obj)
		} else if (!is_promisor_object(oid)) {
	/*
		struct object *obj = parse_object(the_repository, &it->oid);

		fsck_enable_object_names(&fsck_walk_options);
					     void *data)
	case FSCK_ERROR:
}
	}
	case FSCK_WARN:
				   (struct commit *)obj);
			struct packed_git *p;
{
		error(_("%s: not a commit"), refname);
	mark_object_reachable(obj);
	return 0;
static int name_objects;

}
	OPT_BOOL(0, "root", &show_root, N_("report root nodes")),
	}
#include "dir.h"

				count += p->num_objects;
static void mark_object_reachable(struct object *obj)
	 * Showing dangling objects is valid, though (as those
{
	obj->flags |= USED;

		strbuf_addf(&sb, "skiplist=%s", path);
		result |= traverse_one_object(object_array_pop(&pending));
	return -1;
			if (!blob)
{
	if (check_strict)
				errors_found |= ERROR_COMMIT_GRAPH;
	read_replace_refs = 0;
 * Check a single unreachable object

				continue;

					continue;
	if (connectivity_only && (show_dangling || write_lost_and_found)) {
		const char *midx_argv[] = { "multi-pack-index", "verify", NULL, NULL, NULL };
	 *
}
	if (is_null_oid(head_oid)) {

			     oid, "%s", refname);
					  filename);
	if (verbose)
}
			fsck_handle_ref(ref.buf, &head_oid, 0, NULL);
	}
	options.walk = mark_used;
	max = get_max_object_index();
}
		error(_("%s: object corrupt or missing: %s"),
	if (!(obj->flags & HAS_OBJ)) {
	OPT_BOOL(0, "unreachable", &show_unreachable, N_("show unreachable objects")),
		verify_ce_order = 1;

static int check_strict;
	if (!default_refs) {
	OPT_BOOL(0, "lost-found", &write_lost_and_found,
		/* We'll continue with the rest despite the error.. */
		/* ... and the reference to parent is safe here */
}
			struct progress *progress = NULL;
	if (!argc) {
					     ":%s", active_cache[i]->name);
		return 0; /* keep checking other objects */
		prepare_alt_odb(the_repository);
	if (obj->flags & REACHABLE)
		}
		display_progress(progress, ++nr);
	 * in this case (ie this implies --cache).
		return 0;
						progress, count))
	return 0;
{
			   enum object_type object_type,
						     refname, timestamp);
#define ERROR_OBJECT 01
static int mark_packed_for_connectivity(const struct object_id *oid,

	struct worktree **worktrees, **p;
	struct object_id head_oid;
{
		fprintf_ln(stderr, _("Checking cache tree"));


	return 0;
				error(_("%s: object missing"), oid_to_hex(&oid));
	}
#define ERROR_REACHABLE 02
			printf_ln(_("tagged %s %s (%s) in %s"),

{
		if (show_tags && tag->tagged) {
	struct fsck_options options = FSCK_OPTIONS_DEFAULT;
{
		progress = start_progress(_("Checking object directories"), 256);
	}
	OPT_BOOL(0, "reflogs", &include_reflogs, N_("make reflogs head nodes (default)")),
		return 0; /* keep checking other objects */
	NULL

	if (0 <= it->entry_count) {
static int fsck_head_link(const char *head_ref_name,
			midx_verify.argv = midx_argv;
	OPT__VERBOSE(&verbose, N_("be verbose")),
			   oid_to_hex(ooid), oid_to_hex(noid));
		return error(_("%s: object corrupt or missing"),
					   &active_cache[i]->oid);
		fprintf_ln(stderr, _("Checking object directory"));
}

	return fsck_obj(obj, buffer, size);

		 *
		errors_found |= ERROR_REACHABLE;
	strbuf_release(&refname);
				obj->type == OBJ_COMMIT ? "commit" : "other",
				errors_found |= ERROR_COMMIT_GRAPH;
		show_progress = 0;
			     head_ref_name, *head_points_at);

static int show_tags;
		return 0;
	 */
}
}
	if (!obj) {
		   describe_object(&obj->oid), err);
			}
	}
			   describe_object(oid), message);
{
		 * and ignore any that weren't present in our earlier

					errors_found |= ERROR_PACK;
	ret = type_name(type);
			return 1;
 * Check a single reachable object
 */
			   describe_object(&obj->oid));
{
static int fsck_cruft(const char *basename, const char *path, void *data)
	}
					void *data)
	int i;
	struct object *obj = lookup_object(the_repository, oid);
{

	if (fsck_walk(obj, NULL, &fsck_obj_options))
#define ERROR_COMMIT_GRAPH 020
		}
	/*
static void mark_unreachable_referents(const struct object_id *oid)
static int mark_packed_unreachable_referents(const struct object_id *oid,
		/* ... these references to parent->fld are safe here */
					     "%s", arg);
}
{
			      oid_to_hex(&it->oid));
		BUG("read_loose_object streamed a non-blob");
		}
		fprintf_ln(stderr, _("bad sha1 file: %s"), path);
		/* TRANSLATORS: e.g. warning in tree 01bfda: <more explanation> */
	 * not exist).
	return 0;
}
							&obj->oid, NULL);
		return;
	}
	display_progress(progress, nr + 1);
	fsck_walk(obj, NULL, &options);
	 * unreachable objects with USED. Do that now to make --dangling, etc
}
		   printable_type(&obj->oid, obj->type),
				  printable_type(&parent->oid, parent->type),
	 * Not having any default heads isn't really fatal, but
	 * So we just print a warning about it, and clear the

				error(_("could not create lost-found"));
}
static struct option fsck_opts[] = {
			  struct object_id *head_oid);
static int mark_object(struct object *obj, int type, void *data, struct fsck_options *options)
					     struct packed_git *pack,
{
{
				       void *data)
				  describe_object(&obj->oid));
	if (write_lost_and_found) {
			if (show_progress) {
	/*

		for_each_loose_object(mark_loose_unreachable_referents, NULL, 0);
	if (obj->type != OBJ_COMMIT && is_branch(refname)) {

	return fsck_describe_object(&fsck_walk_options, oid);
	 * set of unreachable objects, so we show them even if the user
			   printable_type(oid, object_type),

		error(_("%s: object could not be parsed: %s"),

#define ERROR_REFS 010
#define HAS_OBJ   0x0004
		return; /* not part of our original set */
static int connectivity_only;
		return 1;
	 * dangling objects are likely lost heads).

		 */
		return 0;
	if (!obj) {
	 * that function has non-NULL obj hence ...
static void check_connectivity(void)
	return 0; /* keep checking other objects, even if we saw an error */
static int check_full = 1;
	int null_is_error = 0;
			error(_("%s: invalid sha1 pointer in cache-tree"),
	}
				  describe_object(&parent->oid),
		if (obj)
	if (show_progress)
		keep_cache_objects = 1;
 */
#include "fsck.h"
		errors_found |= ERROR_REFS;
	}
		null_is_error = 1;
	unsigned long size;
			   describe_object(oid), message);
	int i, max;
#include "builtin.h"
	OPT_BOOL(0, "dangling", &show_dangling, N_("show dangling objects")),
		struct strbuf ref = STRBUF_INIT;

		printf_ln(_("missing %s %s"),


	 *
		 * be added to "pending").
#include "worktree.h"
				     p = p->next) {
#include "refs.h"
}
}
			mark_object_reachable(obj);
			errors_found |= ERROR_REACHABLE;
{
	}
	if (verbose)
							   &oid);
				     head_ref_name);
static int fsck_handle_ref(const char *refname, const struct object_id *oid,
static void check_object(struct object *obj)
	if (show_unreachable) {

	}
	OPT_END(),
				fprintf(f, "%s\n", describe_object(&obj->oid));
}
				    "              to %7s %s"),
		free_commit_buffer(the_repository->parsed_objects,
	git_config(fsck_config, NULL);
			stop_progress(&progress);
		struct child_process commit_graph_verify = CHILD_PROCESS_INIT;
static void check_reachable_object(struct object *obj)
		const char *message, void *cb_data)

		fsck_head_link(ref.buf, &head_points_at, &head_oid);

	default_refs++;
		}
	return 0;

#include "tree.h"

	 * object points to it. Ignore it - it's not interesting, and we showed

	 */

	}
	 * With --connectivity-only, we won't have actually opened and marked
	mark_unreachable_referents(oid);
			obj->flags |= USED;
				die_errno(_("could not finish '%s'"),
		objerror(obj, _("broken links"));

	obj->flags &= ~(REACHABLE | SEEN);
			midx_argv[3] = odb->path;
	 */
	 * mark_object_reachable() calls us.  All the callers of
	for_each_loose_file_in_objdir(path, fsck_loose, fsck_cruft, fsck_subdir,
{
			obj->flags |= USED;
				  describe_object(&commit->object.oid));
	struct object *obj = lookup_unknown_object(oid);
			if (fclose(f))
	/*
				  contents, &eaten);
		if (obj && (obj->flags & HAS_OBJ)) {
	stop_progress(&progress);
static int fsck_cache_tree(struct cache_tree *it)
static const char *describe_object(const struct object_id *oid)

		fprintf_ln(stderr, _("Checking reflog %s->%s"),
		obj->flags |= USED;
		/* TRANSLATORS: e.g. error in tree 01bfda: <more explanation> */
	 * hasn't asked for _all_ unreachable objects. If you have

			if (timestamp)
static int show_unreachable;

				if (stream_blob_to_fd(fileno(f), &obj->oid, NULL, 1))
	return errors_found;
			if (S_ISGITLINK(mode))
static const char *printable_type(const struct object_id *oid,
			child_process_init(&midx_verify);
	OPT_BOOL(0, "connectivity-only", &connectivity_only, N_("check only connectivity")),
	struct object *obj;

	mark_object(obj, OBJ_ANY, NULL, NULL);
				  tag->tag,
				for (p = get_all_packs(the_repository); p;
			   int flag, void *cb_data)
		check_full = 1;
{
			  printable_type(&obj->oid, obj->type),
{
			   const struct object_id *oid,


		obj = lookup_object(the_repository, oid);
		free((char *)path);
			   unsigned long size, void *buffer, int *eaten)
	 * since this is something that is prunable.
static int keep_cache_objects;
			FILE *f;
		strbuf_release(&sb);


	for (i = 0; i < it->subtree_nr; i++)
	}
			errors_found |= ERROR_OBJECT;
			continue;

			      refname, oid_to_hex(oid));
		struct object_id oid;
		BUG("%d (FSCK_IGNORE?) should never trigger this callback",
			  struct object_id *head_oid)
			char *filename = git_pathdup("lost-found/%s/%s",
		fsck_set_msg_type(&fsck_obj_options, var, value);
static int mark_used(struct object *obj, int type, void *data, struct fsck_options *options)
			object_as_type(the_repository, obj, type, 0);
	if (obj->type == OBJ_COMMIT)
	OPT_BOOL(0, "progress", &show_progress, N_("show progress")),
		fsck_put_object_name(&fsck_walk_options, &it->oid, ":");

			 * Increment default_refs anyway, because this is a
		for (i = 0; i < active_nr; i++) {
	 * Otherwise? It's there, it's unreachable, and some other unreachable
				if (verify_pack(the_repository,
		return error(_("%s points to something strange (%s)"),
			blob = lookup_blob(the_repository,
			child_process_init(&commit_graph_verify);
			   _("notice: %s points to an unborn branch (%s)"),


{
		return error(_("invalid %s"), head_ref_name);

out:

static int fsck_handle_reflog_ent(struct object_id *ooid, struct object_id *noid,
	if (show_progress == -1)

		for (odb = the_repository->objects->odb; odb; odb = odb->next) {
	struct progress *progress = NULL;
	return git_default_config(var, value, cb);

#include "packfile.h"
			errors_found |= ERROR_REFS;
static struct fsck_options fsck_walk_options = FSCK_OPTIONS_DEFAULT;
			mark_object_reachable(obj);
		 * Further recursion does not need to be performed on this
}
					    const char *path,
	display_progress(progress, 256);
#define REACHABLE 0x0001
		printf_ln(_("broken link from %7s %s"),
	add_object_array(obj, NULL, &pending);
		return 0;
{
	 * Missing unreachable object? Ignore it. It's not like
	return 0;
			return error(_("%s: detached HEAD points at nothing"),
		if (show_dangling)
	return result;
	if (!starts_with(basename, "tmp_obj_"))
	N_("git fsck [<options>] [<object>...]"),

	else
			struct blob *blob;
			  describe_object(&parent->oid));
	if (!git_config_get_bool("core.multipackindex", &i) && i) {
			  describe_object(&obj->oid));
	 *
		if (!obj) {
				continue;
	 * sense (since in this case everything will obviously
	 * "show_unreachable" flag.
	/* TRANSLATORS: e.g. error in tree 01bfda: <more explanation> */
	OPT_BOOL(0, "tags", &show_tags, N_("report tags")),
	}
	else if (!starts_with(*head_points_at, "refs/heads/")) {
static int default_refs;
static void mark_object_for_connectivity(const struct object_id *oid)
	obj->flags &= ~(REACHABLE | SEEN);
	fsck_obj_options.error_func = fsck_error_func;
	if (!is_null_oid(oid)) {
		return 0;
			mark_object_reachable(obj);
			  (type == OBJ_ANY ? _("unknown") : type_name(type)),
	 * Note, buffer may be NULL if type is OBJ_BLOB. See
	/* Traverse the pending reachable objects */
{
	 * If we've not been given any explicit head information, do the
	obj->flags |= USED;
	 * it does mean that "--unreachable" no longer makes any
				  describe_object(&obj->oid));
		}

	}

	obj = parse_object_buffer(the_repository, oid, type, size,
	int result = fsck_walk(obj, obj, &fsck_walk_options);
		return 1;
	if (obj->type == OBJ_TAG) {
			refs_for_each_reflog(get_worktree_ref_store(wt),

	if (obj->flags & REACHABLE)
		errors_found |= ERROR_OBJECT;
				N_("write dangling objects in .git/lost-found")),

static int traverse_one_object(struct object *obj)
	return !!result;
int cmd_fsck(int argc, const char **argv, const char *prefix)
		if (obj->type != OBJ_TREE)


	 * default ones from .git/refs. We also consider the index file
	struct object_directory *odb;
		printf_ln(_("broken link from %7s %s"),
	/*
	}
}

}

	if (!contents && type != OBJ_BLOB)
		free_tree_buffer(tree);
		for_each_packed_object(mark_packed_for_connectivity, NULL, 0);
			return;
		 * object since it is a promisor object (so it does not need to
}
				  describe_object(&tag->object.oid));
			check_object(obj);

}
	int err;
		}
	const char *ret;
		errors_found |= ERROR_OBJECT;
	 * Such starting points are more interesting than some random
	fsck_handle_reflog_oid(refname, noid, timestamp);
{
static int fsck_subdir(unsigned int nr, const char *path, void *progress)


	struct object *obj;
	}
	}
		struct child_process midx_verify = CHILD_PROCESS_INIT;
	if (type != OBJ_ANY && obj->type != type)
		return;
	 * we miss it (since it can't be reached), nor do we want
				  printable_type(&obj->oid, obj->type),
				errors_found |= ERROR_OBJECT;

	OPT_BOOL(0, "name-objects", &name_objects, N_("show verbose names for reachable objects")),

			 */
		}


			}
					total += p->num_objects;
		}
}

		struct tag *tag = (struct tag *) obj;
			f = xfopen(filename, "w");
				  printable_type(&obj->oid, obj->type),
	for_each_reflog_ent(refname.buf, fsck_handle_reflog_ent, refname.buf);
				free(filename);
	 * to complain about it being unreachable (since it does
		errors_found |= ERROR_OBJECT;
#include "progress.h"
static int fsck_handle_reflog(const char *logname, const struct object_id *oid,
	worktrees = get_worktrees(0);
			return; /* it is in pack - forget about it */

			uint32_t total = 0, count = 0;
				  describe_object(&tag->tagged->oid),
{
	errors_found = 0;
	void *contents;
	 * start looking at, for example.
		fprintf_ln(stderr, _("Checking %s link"), head_ref_name);
}
		for (odb = the_repository->objects->odb; odb; odb = odb->next)

	if (keep_cache_objects) {
	int i;

#include "commit.h"
	if (!(obj->flags & HAS_OBJ))
		return; /* reachable objects already traversed */
		printf_ln(_("unreachable %s %s"),
	}
static void fsck_handle_reflog_oid(const char *refname, struct object_id *oid,

	/*
	if (!obj)
		 * these in memory, we must not iterate over the internal
			mode = active_cache[i]->ce_mode;
static struct object_array pending;
			fsck_put_object_name(&fsck_walk_options, &oid,
	}
	obj->flags |= HAS_OBJ;

	}
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		 * Instead, we'll just go back to the source list of objects,
		if (active_cache_tree)
		read_cache();
						     "%s@{%"PRItime"}",

			struct object *obj;
		return;
static int fsck_config(const char *var, const char *value, void *cb)
{
		objerror(parent, _("wrong object type in link"));
	 * do a full fsck

#include "streaming.h"
	if (connectivity_only) {
	check_connectivity();
	if (!ret)
		}
	 * of some set of unreachable objects, usually a commit that
			}
	/*
};
		 * Even though we already have a "struct object" for each of

		errors_found |= ERROR_REACHABLE;
	 * except if it was in a pack-file and we didn't
{
			obj = &blob->object;
		struct tree *tree = (struct tree *)obj;
	if (read_loose_object(path, oid, &type, &size, &contents) < 0) {
				}
static int traverse_reachable(void)
			   head_ref_name, *head_points_at + 11);
			  describe_object(&obj->oid));

		 * resize the hash, making our iteration invalid.

	for (i = 0; i < max; i++) {
	fsck_put_object_name(&fsck_walk_options,
{
	mark_object_for_connectivity(oid);
		}
			  _("unknown"));
		for (odb = the_repository->objects->odb; odb; odb = odb->next) {
	 */
			free(filename);
{
	if (show_progress)
	stop_progress(&progress);
			     oid_to_hex(oid));
	const char *refname = cb_data;
			unsigned int mode;
		ret = _("unknown");
	obj = parse_object(the_repository, oid);
	if (!strcmp(*head_points_at, head_ref_name))
#include "tree-walk.h"
	*head_points_at = resolve_ref_unsafe(head_ref_name, 0, head_oid, NULL);
	}
	for (i = 0; i < argc; i++) {

	 */
				      progress);
static int fsck_loose(const struct object_id *oid, const char *path, void *data)
		/*
			  const char **head_points_at,
	if (verbose)
			commit_graph_verify.git_cmd = 1;
#define USED      0x0008
	OPT_BOOL(0, "cache", &keep_cache_objects, N_("make index objects head nodes")),
	}
		err |= fsck_cache_tree(it->down[i]->cache_tree);
		const char *path;
	if (!git_config_get_bool("core.commitgraph", &i) && i) {
	struct object *obj;
				  eaten);
		      refname, oid_to_hex(oid));
			err |= objerror(obj, _("non-tree in cache-tree"));

		if (is_promisor_object(&obj->oid))
	return ret;
				fsck_put_object_name(&fsck_walk_options, oid,
	if (obj->type == OBJ_TREE) {
	}

		free(contents);
#include "blob.h"

			printf_ln(_("root %s"),
		fprintf_ln(stderr, _("warning in %s %s: %s"),
		goto out;
					uint32_t pos,
	int result = 0;
			struct object *obj = lookup_object(the_repository,
	if (!(obj->flags & USED)) {
	if (obj->type == OBJ_NONE) {
		prepare_alt_odb(the_repository);
	 * accurate.
			verify_argv[2] = "--object-dir";
	} else {

	fsck_obj_options.walk = mark_used;
			   printable_type(oid, object_type),
	fetch_if_missing = 0;
			fsck_put_object_name(&fsck_walk_options, &obj->oid,
		errors_found |= ERROR_REACHABLE;
		if (type > 0)
}
					if (open_pack_index(p))
static int mark_loose_unreachable_referents(const struct object_id *oid,
	if (obj->flags & REACHABLE)

	return 0;
	return 0;
	free_worktrees(worktrees);

	fprintf_ln(stderr, _("error in %s %s: %s"),
{
			if (!obj || !(obj->flags & HAS_OBJ)) {
			midx_verify.git_cmd = 1;
	if (!(obj->flags & HAS_OBJ)) {

			fsck_cache_tree(active_cache_tree);
	}
		struct strbuf sb = STRBUF_INIT;

	obj = parse_object_buffer(the_repository, oid, type, size, buffer,
		struct object *obj = get_indexed_object(i);

}
		}
#include "decorate.h"
		}
	if (name_objects)
			if (obj->type == OBJ_BLOB) {
	errors_found |= ERROR_OBJECT;
	}
			}
#define ERROR_PACK 04

			   int msg_type, const char *message)
			      int flag, void *cb_data)

		errors_found |= ERROR_REFS;
			if (run_command(&commit_graph_verify))
		if (!eaten)
		fprintf_ln(stderr, _("error in %s %s: %s"),
/*
						p, fsck_obj_buffer,
		progress = start_delayed_progress(_("Checking connectivity"), 0);
		if (git_config_pathname(&path, var, value))
		type = oid_object_info(the_repository, oid, NULL);
	if (err)
	fsck_walk_options.walk = mark_object;
				  enum object_type type)
	return 0;
#include "run-command.h"

		check_reachable_object(obj);
	 * be unreachable by definition.
#include "repository.h"


#define SEEN      0x0002
	int err = 0;
			  printable_type(&parent->oid, parent->type),
	struct progress *progress = NULL;

}
	if (is_promisor_object(&obj->oid))

static int show_root;
	if (fsck_obj(obj, contents, size))
		if (!commit->parents && show_root)
		/* detached HEAD */
	return err;
static int verbose;
		if (check_full) {
			midx_argv[2] = "--object-dir";
		const char *arg = argv[i];
					    void *data)
			obj->flags |= USED;
		return 1;
	timestamp_t timestamp)
			return 1;
	 * verify_packfile(), data_valid variable for details.
			     p = p->next) {
	return err;
	}
	 */

		strbuf_release(&ref);
				       const char *path,
{
	mark_object_for_connectivity(oid);
	for (p = worktrees; *p; p++) {
{
	 * (and we want to avoid parsing blobs).
	if (verbose)
	if (skip_prefix(var, "fsck.", &var)) {
	struct object *obj;
	}
	for_each_rawref(fsck_handle_ref, NULL);
	if (!obj) {
			errors_found |= ERROR_REFS;
		const char *email, timestamp_t timestamp, int tz,

	if (obj->type == OBJ_TREE)

		fprintf_ln(stderr, _("Checking %s"), describe_object(&obj->oid));
	 */
						continue;
	if (!obj) {

			} else

		for_each_loose_object(mark_loose_for_connectivity, NULL, 0);
			errors_found |= ERROR_REACHABLE;
}
static int show_progress = -1;
#include "cache-tree.h"
			fsck_object_dir(odb->path);
		return;
static int write_lost_and_found;


	if (verbose)
		prepare_alt_odb(the_repository);

		      oid_to_hex(oid), path);
		errors_found |= ERROR_REFS;
	}
		mark_object_reachable(obj);
}
		get_default_heads();
	}
			  printable_type(&obj->oid, obj->type),
		const char *verify_argv[] = { "commit-graph", "verify", NULL, NULL, NULL };

#include "pack.h"
	struct strbuf refname = STRBUF_INIT;
					     fsck_handle_reflog, wt);
		fprintf_ln(stderr, _("Checking %s %s"),

	}
}
		enum object_type type = oid_object_info(the_repository,
	 * all the interesting cases above.
		return 1;
{
			printf_ln(_("broken link from %7s %s\n"
	 * deleted a branch by mistake, this is a prime candidate to
		errors_found |= ERROR_OBJECT;
	if (strcmp(var, "fsck.skiplist") == 0) {
static int errors_found;
	 * other unreachable objects. In other words, it's the "tip"

	obj->flags |= SEEN;
		fprintf_ln(stderr, _("notice: No default references"));
			if (run_command(&midx_verify))
}
#include "cache.h"
#include "parse-options.h"
};
			free(contents);
#include "tag.h"
				return;
	if (verbose)
					     uint32_t pos,
	obj->flags |= HAS_OBJ;
	 */
{
}
