		rr_dir->status_nr = variant;
		the_hash_algo->final_fn(hash, &ctx);


		 */
static void free_rerere_id(struct string_list_item *item)
			rr_item->util = NULL;
	unsigned char hash[GIT_MAX_RAWSZ];
	 * hand resolved in the working tree since then, but the
			fclose(io.input);
	struct strbuf buf = STRBUF_INIT;
static void rerere_io_putstr(const char *str, struct rerere_io *io)
	io.io.wrerror = 0;
{
		cutoff = cutoff_resolve;
{
		rr_dir = xmalloc(sizeof(*rr_dir));
	 * NEEDSWORK: handle conflicts from merges with
/*
			if (hunk != RR_SIDE_2)
		int conflict_type;
		MOVE_ARRAY(rerere_dir + pos + 1, rerere_dir + pos,
		    S_ISREG(e2->ce_mode) &&
		die(_("could not create directory '%s'"), git_path_rr_cache());
		rr_dir = find_rerere_dir(e->d_name);
		int variant;
		return NULL; /* BUG */
	ll_merge(&result, path, &mmfile[0], NULL,
	}
		return 0;
		free(mmfile[i].ptr);

#include "sha1-lookup.h"
				break;

	return 0;
	if (fclose(f))
		fd = 0;

{
				free_rerere_id(it);
 * stages we have already looked at in this invocation of this
		if (!id)
	while (!io->getline(&buf, io)) {

	 * initial run would catch all and register their preimages.

	struct dirent *de;
	if (ret < 1)
	git_config_get_bool("rerere.autoupdate", &rerere_autoupdate);
#define RR_HAS_POSTIMAGE 1
				    rerere_id_hex(id), id->variant,
}

	struct stat st;
static int has_rerere_resolution(const struct rerere_id *id)
		free(result.ptr);
	fclose(in);
 * NEEDSWORK: shouldn't we be calling this from "reset --hard"?
}
	rollback_lock_file(&write_lock);
		error(_("there were errors while writing '%s' (%s)"),

			if (hunk != RR_SIDE_1 && hunk != RR_ORIGINAL)

			string_list_insert(conflict, (const char *)e->name);
static struct rerere_dir {
{

 * handle, i.e. the ones that has both stages #2 and #3.
		goto fail_exit;

		return rr_cache_exists;
{
{
	}
static int handle_cache(struct index_state *istate,
		}
		struct rerere_id id;
	int i;
 * normalizing the conflicted hunks to the "output".  Subclasses of
	if (io.io.output && fclose(io.io.output))
	/*
	const struct cache_entry *ce;
 * update it.  Or it may have been resolved by the user and we may

}
	if (!strcmp(name, filename)) {
		const char *path = rerere_path(id, "postimage");
	if (!rerere_enabled)
#include "lockfile.h"
#define RR_HAS_PREIMAGE 2
		i = check_one_conflict(r->index, i, &conflict_type);
	return rerere_dir[pos];
	/* None of the existing one applies; we need a new variant */
}
				  const char *path,
				the_hash_algo->update_fn(ctx, one.buf ?
		if (!rr_dir)
{

		}
		struct rerere_id *id;
	filename = rerere_path(id, "postimage");
	variant = id->variant;
int setup_rerere(struct repository *r, struct string_list *merge_rr, int flags)

}
	return 0;


static void git_rerere_config(void)
	for (i = 0; i < conflict.nr; i++) {
void rerere_clear(struct repository *r, struct string_list *merge_rr)
			string_list_append(&to_remove, e->d_name);

static void rerere_strbuf_putconflict(struct strbuf *buf, int ch, size_t size)
	int i;
 * ... and its getline() method implementation

		 * cleanly, there is no point maintaining our own variant.
		     id.variant < id.collection->status_nr;
	item = string_list_insert(rr, path);
	git_hash_ctx ctx;

 * got in the "cur".
	struct strbuf input;
			*type = THREE_STAGED;
static timestamp_t rerere_last_used_at(struct rerere_id *id)
	if (rerere_enabled < 0)
			string_list_insert(update, path);
	while (marker_size--)
	if (!ep)
 * (including LF).
			error_errno(_("cannot unlink '%s'"), filename);
 */
	timestamp_t cutoff_noresolve = now - 15 * 86400;
		return -1;
}
	if (then < cutoff)

		const struct cache_entry *e2 = istate->cache[i];
		    ce_stage(e3) == 3 &&
 * the conflict this time around.
	fprintf_ln(stderr, _("Updated preimage for '%s'"), path);


 * The path indicated by rr_item may still have conflict for which we
		 * yet.
		ep++;
		return -1;
		if (!handle_file(istate, path, NULL, NULL)) {
		}
 * "conflict ID", a HT and pathname, terminated with a NUL, and is
			continue;
		int cleanly_resolved;
			const char *path, unsigned char *hash, const char *output)

	}
	pos = -pos - 1;
{
		else if (hunk == RR_ORIGINAL)
	return 0;
		else if (hunk == RR_SIDE_2)

	int variant;
		else
 * remaining" to do this without abusing merge_rr.
		return;
	 * "thisimage" temporary file.
		*variant = 0;
		unlink_rr_item(id);
 */
		pos = -1 - pos;
		return i + 1;
				   _("Resolved '%s' using previous resolution."),
			has_conflicts = 1;

	unsigned char hash[GIT_MAX_HEXSZ];

	git_config_get_expiry_in_days("gc.rerereresolved", &cutoff_resolve, now);
	}
		return 0;

		if (is_rr_file(de->d_name, "postimage", &variant)) {

		ret = ll_merge(result, path, &base, NULL, cur, "", &other, "",
	while (!strbuf_getwholeline(&buf, in, '\0')) {
	} hunk = RR_SIDE_1;
		ret = 1;
				the_hash_algo->update_fn(ctx, two.buf ?
			remove_variant(id);

	if (want_sp && *buf != ' ')
	variant++;
	int i;
		 * Ask handle_file() to scan and assign a
	for (i = 0; i < to_remove.nr; i++)
struct rerere_io_file {
	io.input = fopen(path, "r");

			       struct string_list_item *rr_item,

	while ((de = readdir(dir)) != NULL) {
	int i, fd;
static int rerere_autoupdate;

	}
		return error(_("index file corrupt"));
static const unsigned char *rerere_dir_hash(size_t i, void *table)

	 * And remember that we can record resolution for this
	int want_sp;

	has_conflicts = handle_path(hash, (struct rerere_io *)&io, marker_size);
			continue;
	if (hash)
		 */
	if (hash)

{
	}
		error_errno(_("could not write '%s'"), path);
const char *rerere_path(const struct rerere_id *id, const char *file)
	strbuf_release(&buf);
		}
	 */
}
			goto fail_exit;
static int handle_file(struct index_state *istate,
}

		      path, strerror(io.io.wrerror));
			else
	 */
	git_config_get_expiry_in_days("gc.rerereunresolved", &cutoff_noresolve, now);
	fclose(io.input);
				die(_("corrupt MERGE_RR"));
	return has_conflicts;
		char *path;
		i = ce_stage(ce) - 1;
		if (buf.buf[hexsz] != '.') {
 *
			if (errno)
	want_sp = (marker_char == '<') || (marker_char == '>');
		 * A three-way merge. Note that this honors user-customizable
		} else if (is_rr_file(de->d_name, "preimage", &variant)) {
{

	return new_rerere_id_hex(hash_to_hex(hash));
			fit_variant(rr_dir, variant);
		unsigned long size;

		if (!has_rerere_resolution(id))
static int write_rr(struct string_list *rr, int out_fd)
		struct rerere_id *id;
 * Garbage collection support
		if (!mmfile[i].ptr && !mmfile[i].size)
	struct string_list merge_rr = STRING_LIST_INIT_DUP;
{
			fprintf_ln(stderr,
		if (*(path++) != '\t')
		for (id.variant = 0, id.collection = rr_dir;
		return;
	/*
 * Remove the recorded resolution for a given conflict ID
	FILE *f;

static int try_merge(struct index_state *istate,
	struct rerere_dir *rr_dir = id->collection;
		ferr_puts(str, io->output, &io->wrerror);
	const char *filename;
		vid.variant = variant;

	if (variant < 0) {
		struct string_list_item *item = &update->items[i];
		/* There has to be the hash, tab, path and then NUL */
		 &mmfile[2], "theirs",
	ret = handle_cache(istate, path, hash, NULL);

	if (then)
		if (read_mmfile(&cur, rerere_path(id, "thisimage"))) {
 * entries to allow the caller to show "rerere remaining".
		rerere_forget_one_path(r->index, it->string, &merge_rr);
}
			mmfile[i].size = size;
		    S_ISREG(e3->ce_mode))
		return -1;
/*
	struct rerere_io io;
	return fd;
	then = rerere_last_used_at(id);
	return write_rr(&merge_rr, fd);
static int rerere_dir_nr;
 * Do *not* write MERGE_RR file out after calling this function.
							 two.buf : "",
static void read_rr(struct repository *r, struct string_list *rr)
static int is_rerere_enabled(void)
		return 0;
		rr_dir->status_alloc = 0;
int rerere_remaining(struct repository *r, struct string_list *merge_rr)
	find_conflict(r, &conflict);

	int status_alloc, status_nr;
	    read_mmfile(&other, rerere_path(id, "postimage")))
/*
		     mmfile_t *cur, mmbuffer_t *result)

 */
		 &mmfile[1], "ours",
		io.io.output = fopen(output, "w");
		if (ret != 0 && string_list_has_string(rr, path)) {
		return 0;
				    rr->items[i].string, 0);
 *   is expected to be stored).
	rollback_lock_file(&write_lock);
			strbuf_release(&conflict);
		die(_("unable to write new index file"));
	fprintf(stderr, _("Forgot resolution for '%s'\n"), path);
	else {
		io.io.output = fopen(output, "w");
	return strbuf_getwholeline(sb, io->input, '\n');
/*
		cleanly_resolved = !try_merge(istate, id, path, &cur, &result);
	free(base.ptr);

	int wrerror;
 * though.
		warning_errno(_("failed utime() on '%s'"),
		if (ret < 1)
		buf.buf[hexsz] = '\0';
		return 0;
	return stat(rerere_path(id, "postimage"), &st) ? (time_t) 0 : st.st_mtime;
	pos = sha1_pos(hash, rerere_dir, rerere_dir_nr, rerere_dir_hash);
			hunk = RR_SIDE_2;
 * safe case, i.e. both side doing the deletion and modification that
	 * Normalize the conflicts in path and write it out to

		/* Ensure that the directory exists. */
 */
		 */
#include "dir.h"
 */
	/* Skip the entries with the same name */
		fclose(io.io.output);
		return error_errno(_("could not open '%s'"), path);
}
 * hunks and -1 if an error occurred.
 * without knowing what modification is being discarded.  The only
	enum {
	if (id->variant <= 0)
{

#define PUNTED 1
	int variant;
 * resolved) may apply cleanly to the contents stored in "path", i.e.
	unlink_or_warn(rerere_path(id, "preimage"));
}
/* if rerere_enabled == -1, fall back to detection of .git/rr-cache */
	unlink_or_warn(rerere_path(id, "thisimage"));
	id = new_rerere_id(hash);
		struct strbuf buf = STRBUF_INIT;


		if (0 < id->variant)
	id->collection = find_rerere_dir(hex);
			rerere_id_hex(id), file, id->variant);
	}
 * strbuf

	if (ret)
	unlink_or_warn(git_path_merge_rr(r));


			return;
		}
	 */
	handle_cache(istate, path, hash, rerere_path(id, "preimage"));
			string_list_insert(merge_rr, (const char *)e->name);
/*
		} else if (is_cmarker(buf.buf, '|', marker_size)) {
	}

static int rerere_dir_alloc;
	 * Grab the conflict ID and optionally write the original
	char *ep;

	len = strlen(path);
	if (fd < 0)
	/*
			if (strbuf_cmp(&one, &two) > 0)
	struct rerere_dir **rr_dir = table;
		 * If there already is a different variant that applies
	    read_mmfile(&cur, rerere_path(id, "thisimage"))) {
			die(_("corrupt MERGE_RR"));
			if (hunk == RR_SIDE_1)
	 */
static GIT_PATH_FUNC(git_path_rr_cache, "rr-cache")
/*
	for (i = 0; i < update->nr; i++) {
			copy_file(rerere_path(id, "postimage"), path, 0666);
			mmfile[i].ptr = read_object_file(&ce->oid, &type,
}

		if (*buf++ != marker_char)

#include "string-list.h"
			   int marker_size, git_hash_ctx *ctx)
	for (i = 0; i < rr->nr; i++) {
	struct string_list_item *item;
	/* Only handle regular files with both stages #2 and #3 */

 * Require the exact number of conflict marker letters, no more, no
		unsigned char hash[GIT_MAX_RAWSZ];
 */

 * alphabetically earlier comes before the other one, while
	/*
 */
	if (!io->input.len)
			return -1;

#include "attr.h"
	     id->variant < id->collection->status_nr;
struct rerere_io_mem {
{
	int marker_size = ll_merge_marker_size(istate, path);
	}
	git_config_get_bool("rerere.enabled", &rerere_enabled);
	struct rerere_io_file io;
			strbuf_addbuf(out, &one);

	 * labelled (e.g. "||||| common" is often seen but "|||||"

		for (variant = 0; variant < rr_dir->status_nr; variant++)
	if (id->collection->status[variant] & RR_HAS_POSTIMAGE) {
		string_list_insert(rr, path)->util = id;

		assert(rr->items[i].util != RERERE_RESOLVED);
		RR_SIDE_1 = 0, RR_SIDE_2, RR_ORIGINAL
#include "ll-merge.h"
	/* Has the user resolved it already? */
 * computing the "conflict ID", which is just an SHA-1 hash of

	return 1;
	struct rerere_dir *rr_dir = id->collection;

 */
 *
 * Subclass of rerere_io that reads from an in-core buffer that is a
static int handle_conflict(struct strbuf *out, struct rerere_io *io,
	if (setup_rerere(r, merge_rr, 0) < 0)
static void assign_variant(struct rerere_id *id)

	if (!dir)
	}
	/*
	int variant = id->variant;
/*
				    rerere_id_hex(id),
	if (!count || *err)
	int pos, len, i, has_conflicts;
 * abstraction.  It reads a conflicted contents from one place via
static void rerere_io_putmem(const char *mem, size_t sz, struct rerere_io *io)
	}
	if (i + 1 < istate->cache_nr) {
	for (id->variant = 0;
}
				break;
	for (i = 0; i < r->index->cache_nr;) {

			variant = 0;
		if (conflict_type == PUNTED)
	unlink_or_warn(rerere_path(id, "postimage"));

	 * Reproduce the conflicted merge in-core
#define RESOLVED 0

		 */
 * only have the preimage for that conflict, in which case the result
	timestamp_t then;
	dir = opendir(git_path("rr-cache"));
	return rr_dir[i]->hash;
	if (io.io.wrerror)
		struct rerere_dir *rr_dir;
/*
		now_empty = 1;
	*variant = strtol(suffix + 1, &ep, 10);
		i++;
/*
		i++;
	return 0;
		goto fail_exit;
	 * always are labeled like "<<<<< ours" or ">>>>> theirs",
{
		ret = handle_file(r->index, path, hash, NULL);
{
 */
			path = buf.buf + hexsz;
 * we are unable to handle, and return the determination in *type.
	int has_conflicts = -1;
	return has_conflicts;
	struct lock_file index_lock = LOCK_INIT;
	}
	unsigned char *status;
	struct dirent *e;
	else
		fprintf_ln(stderr, _("Staged '%s' using previous resolution."),
		struct rerere_id vid = *id;
		return 0;
		rerere_dir[pos] = rr_dir;
	int ret;
 * function.
	return 0;
		id = rr->items[i].util;
		return git_path("rr-cache/%s", rerere_id_hex(id));
		id->collection->status[variant] &= ~RR_HAS_POSTIMAGE;
	mmbuffer_t result = {NULL, 0};
static int is_cmarker(char *buf, int marker_char, int marker_size)

#include "xdiff-interface.h"
	/* Nuke the recorded resolution for the conflict */
 * rerere_io object.
int repo_rerere(struct repository *r, int flags)
	if (!skip_prefix(name, filename, &suffix) || *suffix != '.')
 */
	}
		return error_errno(_("writing '%s' failed"), path);
		if (!then)
}
}
{
}
 * "postimage" (i.e. the corresponding contents with conflicts
		return 0;
	free(id);
	if (write_locked_index(r->index, &index_lock,

			variant = strtol(buf.buf + hexsz + 1, &path, 10);
	int pos;
		if (!has_rerere_resolution(id)) {
	f = fopen(path, "w");
	 * contents with conflict markers out.
	FILE *in = fopen_or_warn(git_path_merge_rr(r), "r");
		/* Make sure the array is big enough ... */
	return hash_to_hex(id->collection->hash);
				    rr->items[i].string, 0);
							hash ? &ctx : NULL);
	}
		}


		do_rerere_one_path(r->index, &rr->items[i], &update);
static struct rerere_dir *find_rerere_dir(const char *hex)
{
	return 1;
	item->util = id;
	int fd;
			strbuf_reset(&out);

	if (errno || *ep)
			hunk = RR_ORIGINAL;
		id->variant = variant;

			   struct string_list *rr, int fd)
{
	if (!io.input)
			if (it != NULL) {
}
		if (write_in_full(out_fd, buf.buf, buf.len) < 0)
	strbuf_addch(buf, '\n');
static void update_paths(struct repository *r, struct string_list *update)
}
			rerere_strbuf_putconflict(out, '<', marker_size);
		/*
			prune_one(&id, cutoff_resolve, cutoff_noresolve);
		}
				break;

		}
		io.io.wrerror = error_errno(_("failed to flush '%s'"), path);
		const struct cache_entry *e3 = istate->cache[i + 1];
				break;
		 * this one.
		int conflict_type;
	FILE *output;
	struct rerere_io io;
			unlink_rr_item(id);

			       COMMIT_LOCK | SKIP_IF_UNCHANGED))
			strbuf_addbuf(&one, &buf);
{
/*
static void ferr_write(const void *p, size_t count, FILE *fp, int *err)
/*

		assert(id->variant >= 0);
	if (fwrite(result.ptr, result.size, 1, f) != 1)
static int do_plain_rerere(struct repository *r,
	/* Update "path" with the resolution */


		int variant;


}
		return error(_("could not parse conflict hunks in '%s'"), path);
		if (conflict_type == THREE_STAGED)
 * used to keep track of the set of paths that "rerere" may need to
 * perform mergy operations, possibly leaving conflicted index entries
	DIR *dir = opendir(git_path("rr-cache/%s", hash_to_hex(rr_dir->hash)));
		cutoff = cutoff_noresolve;
			string_list_remove(rr, path, 1);
 * preimages, abandon them if the user did not resolve them or
	variant = id->variant;
	 */
 * less, followed by SP or any whitespace
			exit(128);
		struct rerere_id *id = merge_rr->items[i].util;
	strbuf_init(&io.input, 0);
static struct rerere_id *new_rerere_id_hex(char *hex)
	memset(&io, 0, sizeof(io));
	return write_rr(rr, fd);
		} else {

	/*
	strbuf_attach(&io.input, result.ptr, result.size, result.size);
	strbuf_release(&out);
			remove_variant(string_list_lookup(rr, path)->util);


		return;
				strbuf_addbuf(&two, &conflict);
}
	timestamp_t cutoff;
{
}
		enum object_type type;
{
	for (i = 0; i < 3; i++)
	if (variant >= 0) {
	}
	int ret;
		ce = istate->cache[pos++];
}
	id->collection->status[id->variant] = 0;
}
	if ((handle_file(istate, path, NULL, rerere_path(id, "thisimage")) < 0) ||
			rerere_strbuf_putconflict(out, '=', marker_size);
}
 */
			fprintf_ln(stderr, _("Recorded resolution for '%s'."), path);
			if (ctx) {
	mmfile_t base = {NULL, 0}, other = {NULL, 0};
{
			free(cur.ptr);

		unsigned char hash[GIT_MAX_RAWSZ];
{

	unmerge_index(r->index, pathspec);
	for (i = 0; i < merge_rr->nr; i++) {
}

		if (unlink(path))
 *
	if (output)
{
	 * the common ancestor in diff3-style output is not always
	for (i = 0; i < 3; i++)
			errno = 0;
	 */
		return git_path("rr-cache/%s/%s", rerere_id_hex(id), file);
#include "pathspec.h"
}
			item->string);
	if (id->collection->status_nr <= id->variant) {
#include "object-store.h"
 *

 * and working tree files.
		return error(_("could not parse conflict hunks in '%s'"), path);
{
	struct strbuf buf = STRBUF_INIT, conflict = STRBUF_INIT;
}
	if (!rr_cache_exists && mkdir_in_gitdir(git_path_rr_cache()))

 * During a conflict resolution, after "rerere" recorded the
	timestamp_t now = time(NULL);
		return;
	if (read_mmfile(&base, rerere_path(id, "preimage")) ||
 * The main entry point that is called internally from codepaths that
		 istate, NULL);
		then = rerere_created_at(id);
	if (0 <= pos)
 * ... and its getline() method implementation
		} else
	int fd, status;
static int rerere_enabled = -1;
	struct rerere_id *id = rr_item->util;
	struct rerere_id *id = xmalloc(sizeof(*id));
	id->variant = variant;
	 * the postimage.
 * for failure.
	else
static int find_conflict(struct repository *r, struct string_list *conflict)
		/*
static void prune_one(struct rerere_id *id,
	int i;
{
	while (!io->getline(&buf, io)) {
	/*


	const char *path = rr_item->string;
/*
	free_rerere_dirs();
		ALLOC_GROW(rerere_dir, rerere_dir_nr + 1, rerere_dir_alloc);
		if (0 <= id->variant && id->variant != variant)
							 &size);
			if (handle_conflict(&conflict, io, marker_size, NULL) < 0)
	/* some more stuff */
			continue; /* or should we remove e->d_name? */
			strbuf_addf(&buf, "%s\t%s%c",
			strbuf_addbuf(out, &two);

		goto out;
 * Try using the given conflict resolution "ID" to see
		mkdir_in_gitdir(rerere_path(id, NULL));
 * $GIT_DIR/MERGE_RR file is a collection of records, each of which is
	handle_file(istate, path, NULL, rerere_path(id, "preimage"));
		else
}
	*type = PUNTED;
			return;

		strbuf_release(&buf);

	int has_conflicts = 0;

			break;
			free_rerere_id(rr_item);

	int i;
};


}
			       istate, NULL);
int rerere_forget(struct repository *r, struct pathspec *pathspec)
				    strlen(it->string), 0, NULL, 0))
	remove_variant(id);
 * NEEDSWORK: we do not record or replay a previous "resolve by
	id->collection->status[id->variant] = 0;
			error(_("no remembered resolution for '%s'"), path);
		id = new_rerere_id(hash);
	struct string_list update = STRING_LIST_INIT_DUP;


	return isspace(*buf);
	len = ep - io->input.buf;
/*
	git_rerere_config();
	while ((e = readdir(dir))) {
	FILE *input;

	if (rr_dir->status_nr < variant) {
		return -1;


	repo_hold_locked_index(r, &index_lock, LOCK_DIE_ON_ERROR);
			rerere_io_putmem(out.buf, out.len, io);
	char *ep;
		return error(_("index file corrupt"));
 * if that recorded conflict resolves cleanly what we
		const int both = RR_HAS_PREIMAGE | RR_HAS_POSTIMAGE;
			mmfile[i].ptr = xstrdup("");
	strbuf_release(&io.input);
		die(_("unable to write rerere record"));
	if (flags & RERERE_READONLY)
		if (is_cmarker(buf.buf, '<', marker_size)) {
		       const char *path, unsigned char *hash, const char *output)

 * one side of the conflict, NUL, the other side of the conflict,

	int ret;
			rerere_strbuf_putconflict(out, '>', marker_size);
 * record their resolutions.  And drop $GIT_DIR/MERGE_RR.
		else
 * by (1) discarding the common ancestor version in diff3-style,
		rr_dir->status = NULL;
				   path);

	if (output) {
	if (!in)

			continue;
					       git_path_merge_rr(r),
		*type = RESOLVED;
			id->collection->status[variant] |= RR_HAS_POSTIMAGE;
			break;
		if (now_empty)
/*
	struct string_list merge_rr = STRING_LIST_INIT_DUP;
}
	int marker_size = ll_merge_marker_size(istate, path);
		if (output)
		const char *path = conflict.items[i].string;
	io.io.getline = rerere_file_getline;
 */
		ep = io->input.buf + io->input.len;
 */
	id->variant = -1; /* not known yet */
			has_conflicts = handle_conflict(&out, io, marker_size,
	mmfile_t cur = {NULL, 0};
		 * There may be other variants that can cleanly

}
{
	else
			; /* discard */
		} else if (is_cmarker(buf.buf, '>', marker_size)) {

	if (pos < 0) {
		if (add_file_to_index(r->index, item->string, 0))
			it = string_list_lookup(merge_rr, (const char *)e->name);
	}
		struct string_list_item *it = &conflict.items[i];
{
		*err = errno;
	strbuf_release(&two);
};
	if (!is_rerere_enabled())

		string_list_insert(rr, path)->util = id;

	/* ... and then remove the empty directories */
			die_errno(_("cannot unlink stray '%s'"), path);
			if (has_conflicts < 0)


		if (merge(istate, &vid, path))

static void do_rerere_one_path(struct index_state *istate,
	return -1;
	if (!f)
			break;
	read_rr(r, merge_rr);
 * needs to be recorded as a resolution in a postimage file.
	free_rerere_id(item);
		scan_rerere_dir(rr_dir);
			fit_variant(rr_dir, variant);
		return 1;

 *   by storing RERERE_RESOLVED to .util field (where conflict ID
}
	if (has_conflicts < 0) {
	if (fwrite(p, count, 1, fp) != 1)
 * - Conflicted paths that rerere does not handle are added


}
static int rerere_forget_one_path(struct index_state *istate,
static inline void ferr_puts(const char *s, FILE *fp, int *err)

 * "preimage" (i.e. a previous contents with conflict markers) and its
	errno = 0;
	free(result.ptr);
{
/* automatically update cleanly resolved paths to the index */
	ret = try_merge(istate, id, path, &cur, &result);
			      rerere_path(id, "postimage"));
	DIR *dir;
{
 */
		}

static timestamp_t rerere_created_at(struct rerere_id *id)
 * - Conflicted paths that have been resolved are marked as such
		      timestamp_t cutoff_resolve, timestamp_t cutoff_noresolve)
	}
	return has_conflicts;
		if (rerere_autoupdate)
	mmfile_t mmfile[3] = {{NULL}};
	if (unlink(filename)) {
	return id;
	size_t len;
	closedir(dir);
	 * Recreate the original conflict from the stages in the
/*
}
	fprintf_ln(stderr, _("Recorded preimage for '%s'"), path);
	}
	if (io.io.output)
		memset(rr_dir->status + rr_dir->status_nr,
	 * conflict when the user is done.
	struct rerere_io_mem io;
static int rerere_file_getline(struct strbuf *sb, struct rerere_io *io_)
}
{
	if (!ce_stage(e)) {
			unlink_or_warn(output);
	if (commit_lock_file(&write_lock) != 0)
		 * low-level merge driver settings.
	free(other.ptr);
	for (i = 0; i < r->index->cache_nr;) {
		int now_empty;
	struct rerere_dir *rr_dir;
	}
#include "cache.h"
	if (!file)
static int check_one_conflict(struct index_state *istate, int i, int *type)
	/*
	strbuf_release(&one);
	/* Does any existing resolution apply cleanly? */
			continue;
		io.io.output = NULL;

	return status;
static void scan_rerere_dir(struct rerere_dir *rr_dir)
 */

			error_errno(_("could not write '%s'"), output);

static struct rerere_id *new_rerere_id(unsigned char *hash)
	if (repo_read_index(r) < 0)
		if ((rr_dir->status[variant] & both) != both)
	 */

static void fit_variant(struct rerere_dir *rr_dir, int variant)
 * return the number of conflict hunks found.
			struct string_list_item *it;
 * Return the cache index to be looked at next, by skipping the
		     const struct rerere_id *id, const char *path,
	 * find the conflicted paths.

	struct rerere_io_mem *io = (struct rerere_io_mem *)io_;
{
 * Returns 0 for successful replay of recorded resolution, or non-zero
}

}
 * "getline()" method, and optionally can write it out after
 * Find the conflict identified by "id"; the change between its
		rerere_dir_nr++;
 * (2) reordering our side and their side so that whichever sorts
		die_errno(_("unable to open rr-cache directory"));
	int has_conflicts = 0;

}
			error(_("failed to update conflicted state in '%s'"), path);

	}
	ferr_write(s, strlen(s), fp, err);
			die(_("unable to write rerere record"));
	if (!dir)
struct rerere_io {
		const struct cache_entry *e = r->index->cache[i];
	if (io->output)
#include "resolve-undo.h"
	pos = index_name_pos(istate, path, len);
	 * The paths may have been resolved (incorrectly);
/*
void *RERERE_RESOLVED = &RERERE_RESOLVED;

 */
		mmfile_t cur = { NULL, 0 };

 * NEEDSWORK: we may want to fix the caller that implements "rerere
 * are identical to the previous round, might want to be handled,
	if (io->output)
#include "rerere.h"
	 * A successful replay of recorded resolution.
			continue; /* failed to replay */
	 * recover the original conflicted state and then
			continue;
		id = new_rerere_id_hex(buf.buf);

	struct strbuf buf = STRBUF_INIT, out = STRBUF_INIT;
		mmbuffer_t result = {NULL, 0};
	strbuf_release(sb);
		i = check_one_conflict(r->index, i, &conflict_type);
static void free_rerere_dirs(void)
		rr_dir->status_nr = 0;
	ALLOC_GROW(rr_dir->status, variant, rr_dir->status_alloc);
	rr_cache_exists = is_directory(git_path_rr_cache());
			return 0;
	 * MERGE_RR records paths with conflicts immediately after
		       '\0', variant - rr_dir->status_nr);
 */
	const int both = RR_HAS_POSTIMAGE|RR_HAS_PREIMAGE;
	mmbuffer_t result = {NULL, 0};
		rr_item->util = NULL;
	struct string_list to_remove = STRING_LIST_INIT_DUP;
	else if (*ep == '\n')
		hashcpy(rr_dir->hash, hash);
	}
	}
		/*
	}
			strbuf_addf(&buf, "%s.%d\t%s%c",
	int i;
			if (id.collection->status[id.variant])
	struct strbuf one = STRBUF_INIT, two = STRBUF_INIT;

		const unsigned hexsz = the_hash_algo->hexsz;
	return ((id->collection->status[variant] & both) == both);
	for (i = 0; i < rr->nr; i++)
	return ret;
	int i;
				break;
	while (i < istate->cache_nr && ce_stage(istate->cache[i]) == 1)
static int merge(struct index_state *istate, const struct rerere_id *id, const char *path)
	if (io.io.wrerror)
 * The merge_rr list is meant to hold outstanding conflicted paths
 *
}
	if (utime(rerere_path(id, "postimage"), NULL) < 0)
	 * merge.renormalize set, too?
	int i;

	 */
 * Subclass of rerere_io that reads from an on-disk file
	}
	free(item->util);
{
	}
	if (setup_rerere(r, rr, 0) < 0)
	timestamp_t cutoff_resolve = now - 60 * 86400;
		/* ... and add it in. */
		const struct cache_entry *e = r->index->cache[i];
{
		if (cleanly_resolved)
	}
/*
 * rerere" during the current conflict resolution session).
{
	struct stat st;


static int is_rr_file(const char *name, const char *filename, int *variant)
	FREE_AND_NULL(rerere_dir);
}
	fd = setup_rerere(r, &merge_rr, RERERE_NOAUTOUPDATE);
	return i;
static const char *rerere_id_hex(const struct rerere_id *id)

			die(_("corrupt MERGE_RR"));
	strbuf_release(&buf);
	const struct cache_entry *e = istate->cache[i];
	return has_conflicts;
 * Look at a cache entry at "i" and see if it is not conflicting,

	strbuf_remove(&io->input, 0, len);

			rr_dir->status[variant] |= RR_HAS_POSTIMAGE;
};
			continue;

	if (variant < 0)
	closedir(dir);
	git_config(git_default_config, NULL);
	 */
		return;
	 * hence we set want_sp for them.  Note that the version from
	for (i = 0; i < rerere_dir_nr; i++) {
/*
		 * replay.  Try them and update the variant number for
}
	for (i = 0; i < conflict.nr; i++) {
	}
			if (hunk != RR_SIDE_1)
 * and NUL concatenated together.
	if (setup_rerere(r, merge_rr, RERERE_READONLY))
	/*
		return;
static int handle_path(unsigned char *hash, struct rerere_io *io, int marker_size)

			   rerere_dir_nr - pos - 1);
	 */
	     id->variant++) {
static void remove_variant(struct rerere_id *id)
				strbuf_addbuf(&one, &conflict);

 * Read contents a file with conflicts, normalize the conflicts
 * work on (i.e. what is left by the previous invocation of "git
	 * index and compute the conflict ID
	free(cur.ptr);
{
{
		handle_cache(istate, path, hash, rerere_path(id, "thisimage"));
		} else if (is_cmarker(buf.buf, '=', marker_size)) {
							 one.len + 1);
		return error_errno(_("could not open '%s'"), path);
			if (!rr_dir->status[variant])
		rerere_autoupdate = !!(flags & RERERE_AUTOUPDATE);
{


	/*
 */
}
				it->util = RERERE_RESOLVED;
} **rerere_dir;
					       LOCK_DIE_ON_ERROR);
	if (update.nr)
				strbuf_swap(&one, &two);
out:
	if (repo_read_index(r) < 0)
	struct rerere_id *id;
		error(_("no remembered resolution for '%s'"), path);
	if (repo_read_index(r) < 0)

}
void rerere_gc(struct repository *r, struct string_list *rr)

		if (!match_pathspec(r->index, pathspec, it->string,
	struct rerere_io_file *io = (struct rerere_io_file *)io_;

	/*
}
	variant = id->variant;
	return stat(rerere_path(id, "preimage"), &st) ? (time_t) 0 : st.st_mtime;
		if (!io.io.output) {
		free(rerere_dir[i]);
 * Return 1 if conflict hunks are found, 0 if there are no conflict
		if (!mmfile[i].ptr) {
		ret = 1;
#define THREE_STAGED 2
	}
{
	has_conflicts = handle_path(hash, (struct rerere_io *)&io, marker_size);
{
		update_paths(r, &update);
	const char *suffix;

}

		fd = hold_lock_file_for_update(&write_lock,

		if (ce_stage(e2) == 2 &&
/*
 * have a recorded resolution, in which case replay it and optionally
		/*
	fit_variant(rr_dir, variant);
		int ret;
		goto out;
			rerere_io_putstr(buf.buf, io);
static void unlink_rr_item(struct rerere_id *id)
				break;
{

	 * Mark that "postimage" was used to help gc.
	strbuf_add(sb, io->input.buf, len);
							 one.buf : "",
	if (flags & (RERERE_AUTOUPDATE|RERERE_NOAUTOUPDATE))

}
	memset(&io, 0, sizeof(io));
	unsigned char hash[GIT_MAX_RAWSZ];
	 * merge failed.  Some of the conflicted paths might have been
		ferr_write(mem, sz, io->output, &io->wrerror);
			}
 * Scan the index and find paths that have conflicts that rerere can
	rerere_dir_nr = rerere_dir_alloc = 0;
		else if (conflict_type == RESOLVED) {
		}
	struct string_list conflict = STRING_LIST_INIT_DUP;
			}
	 * The beginning of our version and the end of their version
				  struct string_list *rr)
		if (buf.len < hexsz + 2 || get_sha1_hex(buf.buf, hash))
	return git_path("rr-cache/%s/%s.%d",
	while (pos < istate->cache_nr) {
	for (variant = 0; variant < rr_dir->status_nr; variant++) {
 */
	while (i < istate->cache_nr && ce_same_name(e, istate->cache[i]))
			rmdir(rerere_path(id, NULL));
	find_conflict(r, &conflict);
{
	io.io.getline = rerere_mem_getline;

	fd = setup_rerere(r, &merge_rr, flags);
	 * Update the preimage so that the user can resolve the
{
{
	int rr_cache_exists;
	strbuf_release(&buf);
 * rerere_io embed this structure at the beginning of their own
		    ce_same_name(e, e3) &&
	 * alone is also valid), so we do not set want_sp.


	assign_variant(id);
	struct string_list conflict = STRING_LIST_INIT_DUP;
		free(cur.ptr);
 * Scan the path for conflicts, do the "handle_path()" thing above, and

{
	strbuf_addchars(buf, ch, size);
		rmdir(git_path("rr-cache/%s", to_remove.items[i].string));
		if (ce_namelen(ce) != len || memcmp(ce->name, path, len))
 *
			strbuf_addbuf(&two, &buf);
		free_rerere_id(rr_item);
		return error(_("index file corrupt"));
	if (fd < 0)
	if (get_sha1_hex(hex, hash))
				now_empty = 0;
		the_hash_algo->init_fn(&ctx);
 * that rerere could handle.  Abuse the list by adding other types of
}
static struct lock_file write_lock;

		return 0;
		free(rerere_dir[i]->status);
fail_exit:
		     id.variant++) {
			rr_dir->status[variant] |= RR_HAS_PREIMAGE;
	return ret;
	 */
 * deletion" for a delete-modify conflict, as that is inherently risky
	 * conflict in the working tree, run us again to record
			       struct string_list *update)
static int rerere_mem_getline(struct strbuf *sb, struct rerere_io *io_)
{
	}
		if (is_cmarker(buf.buf, '<', marker_size)) {
	status = do_plain_rerere(r, &merge_rr, fd);
	id->collection->status[variant] |= RR_HAS_PREIMAGE;
 *
	/* Collect stale conflict IDs ... */
	int (*getline)(struct strbuf *, struct rerere_io *);


{

	git_config(git_default_config, NULL);

	string_list_clear(&to_remove, 0);

		} else if (hunk == RR_SIDE_1)
		struct rerere_id *id;
							 two.len + 1);
#include "config.h"
		 * conflict ID.  No need to write anything out
 * "rerere" interacts with conflicted file contents using this I/O
{
		if (errno == ENOENT)
 * conflicting and we are willing to handle, or conflicting and
	}
}
	ep = memchr(io->input.buf, '\n', io->input.len);
		if (is_dot_or_dotdot(e->d_name))

