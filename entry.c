		/*
		wrote = write_in_full(fd, new_blob, size);
					continue;
			die_errno("cannot create directory at '%s'", buf);
	    state->refresh_cache && !state->base_dir_len) {
	}
	case S_IFLNK:
	}
	}

}
	char *buf = xmallocz(path_len);
	void *blob_data = read_object_file(&ce->oid, &type, size);



		if (ret) {
	*fstat_done = fstat_output(fd, state, statbuf);
	struct dirent *de;

	int symlink = (ce->ce_mode & S_IFMT) != S_IFREG;
			ret = convert_to_working_tree(state->istate, ce->name, new_blob, size, &buf, &meta);
					      "is now available although it has not been "
						       strlen(path->string), 0);
					die(_("could not stat file '%s'"), ce->name);
		if (ret)
		 * point. If the error would have been fatal (e.g.
			die_errno("cannot unlink '%s'", path->buf);
	string_list_clear(&dco->paths, 0);

	struct string_list_item *filter, *path;

		fd = open_output_fd(path, ce, to_tempfile);
		    (!trust_ino && !fspathcmp(ce->name, dup->name))) {
		 * as the possibly empty directory was not changed
		 * No "else" here as errors from convert are OK at this
		fstat(fd, st);
			continue;
			return 0;
		new_blob = read_blob_entry(ce, &size);
	}
}

					 * Do not ask the filter for available blobs,
		string_list_init(&state->delayed_checkout->paths, 0);
			}
			free(new_blob);
				}
		}
		ce->ce_flags |= CE_UPDATE_IN_BASE;

}
	enum object_type type;
{
		 * right permissions (including umask, which is nasty
		 * allowed to be a symlink to an existing directory,

		break;
		    !streaming_write_entry(ce, path, filter,
#include "progress.h"

		if (mkdir(buf, 0777)) {
		}
}

	if (!state->delayed_checkout)

		 * we test the path components of the prefix with the
				if (ce) {
		unsigned changed = ie_match_stat(state->istate, ce, &st,
	struct checkout_metadata meta;
					/*
	strbuf_add(&path, state->base_dir, state->base_dir_len);
 * This is like 'lstat()', except it refuses to follow symlinks
			fstat_done = fstat_output(fd, state, &st);
				 int *fstat_done, struct stat *statbuf)
		struct stat st;
							    size, &buf, &meta, dco);
				   struct cache_entry *ce, struct stat *st)
{
	if (!check_leading_path(ce->name, ce_namelen(ce)))
		errno = ENOENT;
					errs = 1;
	state->delayed_checkout = NULL;
			if (errno == EEXIST && state->force &&
	return lstat(path, st);

		free(blob_data);
					NULL, oid_to_hex(&ce->oid), 0);
			size = 0;
{
		if (!has_symlinks || to_tempfile)
	ce->ce_flags |= CE_MATCHED;

	if (remove_or_warn(ce->ce_mode, ce->name))
		if ((trust_ino && !match_stat_data(&dup->ce_stat_data, st)) ||
		 * bother reading it at all.
		} while (len < path_len && path[len] != '/');
	return !available;
	if (nr_checkouts)
	if (state->refresh_cache) {
	struct strbuf buf = STRBUF_INIT;
	while (path < slash && *slash != '/')
			break;

		 * If this mkdir() would fail, it could be that there
	if (ce->ce_flags & CE_WT_REMOVE) {
	if (result)
#include "blob.h"
				return error("%s is a directory", path.buf);
	closedir(dir);
		 * with the symlink destination as its contents.
		unlink_entry(ce);
	}
				free(new_blob);
		strbuf_addch(path, '/');
		/*
			return blob_data;
	create_directories(path.buf, path.len, state);
		slash--;
{
	for_each_string_list_item(path, &dco->paths) {
				errs = 1;
		strbuf_setlen(path, origlen);

	DIR *dir = opendir(path->buf);
}
	const char *slash = path + len;
					state->force ? SUBMODULE_MOVE_HEAD_FORCE : 0);

}
static int create_file(const char *path, unsigned int mode)
	ssize_t wrote;
		/*
		} else {
		if (!to_tempfile)
		ret = symlink(new_blob, path);
	write_file_entry:

	if (rmdir(path->buf))
		if (dco && dco->state == CE_RETRY) {
		available->util = (void *)item->string;
{
static void remove_subtree(struct strbuf *path)

				 */
		if (filter &&
					filter->string = "";
			goto write_file_entry;
			BUG("Can't remove entry to a path");
				return submodule_move_head(ce->name,
			buf[len] = path[len];
	}
static void create_directories(const char *path, int path_len,
	int fd;
		fill_stat_cache_info(state->istate, ce, &st);
			    !unlink_or_warn(buf) && !mkdir(buf, 0777))
	if (to_tempfile) {

		if (len >= path_len)
	return write_entry(ce, path.buf, state, 0);
	struct delayed_checkout *dco = state->delayed_checkout;
		 * stat() function instead of the lstat() function.

		const struct submodule *sub;
	if (fstat_is_reliable() &&
				continue;
			}
			/*
		 * to emulate by hand - much easier to let the system
				 * the filter is done and we can remove the
			new_blob = NULL;

	int origlen = path->len;
 * least TEMPORARY_FILENAME_LENGTH bytes long.
	}
		return;
static int check_path(const char *path, int len, struct stat *st, int skiplen)
		if (lstat(path->buf, &st))
			       const struct checkout *state)
		return -1;
				continue;
		break;
	off_t filtered_bytes = 0;
		unlink(path);
	struct string_list *available_paths = cb_data;
	/* use fstat() only when path == ce->name */
		 */
		 * one more time to create the directory.
		string_list_remove_empty_items(&dco->filters, 0);
				 const struct checkout *state, int to_tempfile,
					unlink_or_warn(ce->name);
		submodule_move_head(ce->name, "HEAD", NULL,
			/*
	unsigned long size;
				    SUBMODULE_MOVE_HEAD_FORCE);
			 * no pathname to return.

	strbuf_reset(&path);

		state->delayed_checkout->state = CE_CAN_DELAY;
		 * We do not send the blob in case of a retry, so do not
{
			new_blob = strbuf_detach(&buf, &newsize);

		/* state.force is set at the caller. */
	available = string_list_lookup(available_paths, item->string);
		}
				goto delayed;
void unlink_entry(const struct cache_entry *ce)
finish:
int checkout_entry(struct cache_entry *ce, const struct checkout *state,
	if (!state->delayed_checkout) {
		if (dup->ce_flags & (CE_MATCHED | CE_VALID | CE_SKIP_WORKTREE))

 * file named by ce, a temporary file is created by this function and
		return error("unknown file mode for %s in index", path);
	case S_IFREG:
			free(new_blob);
		if (topath)
			len++;
				NULL, oid_to_hex(&ce->oid),
		sub = submodule_from_ce(ce);
#include "object-store.h"
				return 0;
			if (lstat(ce->name, &st) < 0)
	return 0;
		return 1;
{
	struct stat st;
	const struct submodule *sub = submodule_from_ce(ce);
		}

				filter->string = "";
	if (!has_dirs_only_path(path, slash - path, skiplen)) {
	while (dco->filters.nr > 0) {
			 * In dco->paths we store a list of all delayed paths.

		(*nr_checkouts)++;

		return 0;

				return error("unable to read sha1 file of %s (%s)",
		return 0;
		else if (unlink(path->buf))

 * Write the contents from ce out to the working tree.
		struct stream_filter *filter = get_stream_filter(state->istate, ce->name,
	size_t newsize = 0;
		 * and we set 'state->base_dir_len' below, such that
{
	char *new_blob;
			size = newsize;
		 * We unlink the old file, to get the new one with the
			if (S_ISGITLINK(ce->ce_mode))
	int errs = 0;
	schedule_dir_for_removal(ce->name, ce_namelen(ce));
	}
				if (lstat(ce->name, &sb))
		 */
			return error_errno("unable to unlink old '%s'", path.buf);
	/* At this point we should not have any delayed paths anymore. */
	result |= close(fd);


			}

	return 0;
					errs |= 1;

	progress = start_delayed_progress(_("Filtering content"), delayed_object_count);
		return mkstemp(path);
		state->delayed_checkout = xmalloc(sizeof(*state->delayed_checkout));
	}

	if (!check_path(path.buf, path.len, &st, state->base_dir_len)) {
static void mark_colliding_entries(const struct checkout *state,
		 */
				if (!(st.st_mode & S_IFDIR))
			int err;
		do {
					errs |= checkout_entry(ce, state, NULL, nr_checkouts);

	errs |= dco->paths.nr;
	} else if (state->not_new)
	while ((de = readdir(dir)) != NULL) {
	}

	string_list_clear(&dco->filters, 0);
	}

				     path, oid_to_hex(&ce->oid));
					   state, to_tempfile,
	struct delayed_checkout *dco = state->delayed_checkout;
			return error("unable to write file %s", path);
			return error_errno("unable to create symlink %s", path);
}
			 */
					display_throughput(progress, filtered_bytes);
		} else if (unlink(path.buf))
	int i, trust_ino = check_stat;

		sub = submodule_from_ce(ce);
			break;
	int fd, ret, fstat_done = 0;
	free(dco);
	if (ce_mode_s_ifmt == S_IFREG) {
					"%s already exists, no checkout\n",
			return -1;
		if (is_dot_or_dotdot(de->d_name))
	}
		return;
}
		for_each_string_list_item(filter, &dco->filters) {
			if (available_paths.nr <= 0) {
	stop_progress(&progress);
		if (fd < 0) {
{
		return write_entry(ce, topath, state, 1);

		 * is already a symlink or something else exists

		 */
		if (has_dirs_only_path(buf, len, state->base_dir_len))
				 * "string_list_remove_empty_items" call below).
	const struct submodule *sub;
					error("external filter '%s' signaled that '%s' "
	while (len < path_len) {
}
			/* If it is a gitlink, leave it alone! */
		} else
	struct stat st;
		if (sub) {
}
				 * filter from the list (see
}
			for_each_string_list_item(path, &available_paths) {
	switch (ce_mode_s_ifmt) {
		free(new_blob);
						 CE_MATCH_IGNORE_VALID | CE_MATCH_IGNORE_SKIP_WORKTREE);
			}
	delayed_object_count = dco->paths.nr;
		 * Convert from git internal format to working tree format
#include "cache.h"

		xsnprintf(path, TEMPORARY_FILENAME_LENGTH, "%s",
#include "dir.h"

static int open_output_fd(char *path, const struct cache_entry *ce, int to_tempfile)
/*


 * in the path, after skipping "skiplen".
			goto finish;
		if (S_ISDIR(st.st_mode)) {
			filter_string_list(&dco->paths, 0,
		return create_file(path, !symlink ? ce->ce_mode : 0666);
		 */
		die_errno("cannot rmdir '%s'", path->buf);
								 &ce->oid);

				state->force ? SUBMODULE_MOVE_HEAD_FORCE : 0);
static int streaming_write_entry(const struct cache_entry *ce, char *path,
	struct progress *progress;

				struct stat sb;
			continue; /* ok, it is already a directory. */
	if (topath)
	free(buf);
			return error("cannot create submodule directory %s", path);
		/*
#include "streaming.h"
{

				continue;
		 * We can't make a real symlink; write out a regular file entry
				return submodule_move_head(ce->name,
		 */
	result |= stream_blob_to_fd(fd, &ce->oid, filter, 1);
}

				 struct stream_filter *filter,
			if (!state->force)
 *
	}
	if (blob_data) {
		 * Needs to be checked before !changed returns early,
int finish_delayed_checkout(struct checkout *state, int *nr_checkouts)

			 */
					      filter->string, path->string);
			ret = async_convert_to_working_tree(state->istate, ce->name, new_blob,
	int len = 0;
			return submodule_move_head(ce->name,
		if (type == OBJ_BLOB)
#if defined(GIT_WINDOWS_NATIVE) || defined(__CYGWIN__)
					   &fstat_done, &st))
{
static int write_entry(struct cache_entry *ce,
		 * just do the right thing)
	} else {
		   char *topath, int *nr_checkouts)
	if (!dir)
					path.buf);
 */
				filter->string = "";
		state->istate->cache_changed |= CE_ENTRY_CHANGED;
			return error_errno("unable to create file %s", path);
						   ce->name);
	return open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
	mode = (mode & 0100) ? 0777 : 0666;
	if (available)
			  symlink ? ".merge_link_XXXXXX" : ".merge_file_XXXXXX");
		break;
			if (ret && string_list_has_string(&dco->paths, ce->name)) {
					filtered_bytes += ce->ce_stat_data.sd_size;
{
					 * again, as the filter is likely buggy.
					 */
		die_errno("cannot opendir '%s'", path->buf);
	if (sub) {
	for (i = 0; i < state->istate->cache_nr; i++) {
			new_blob = read_blob_entry(ce, &size);
	}
	strbuf_add(&path, ce->name, ce_namelen(ce));


	int result = 0;
				return error_errno("unable to stat just-written file %s",
	return errs;
		if (dup == ce)
	clone_checkout_metadata(&meta, &state->meta, &ce->oid);
static void *read_blob_entry(const struct cache_entry *ce, unsigned long *size)
		 */


		return errs;
{
	unsigned int ce_mode_s_ifmt = ce->ce_mode & S_IFMT;

		error("'%s' was not filtered properly", path->string);
	unsigned delayed_object_count;
 * its name is returned in topath[], which must be able to hold at
					      "delayed earlier",
 */
/*
		}
		close(fd);
			remove_subtree(&path);
{
				struct cache_entry* ce;
	}
		 */
			 * No content and thus no path to create, so we have
		buf[len] = 0;
		if (!state->force) {
	case S_IFGITLINK:

		       char *path, const struct checkout *state, int to_tempfile)
		if (to_tempfile)

				 * Filter responded with no entries. That means
		/*

		if (!fstat_done)
}
			} else
			 * Remove them from the list.
		if (S_ISDIR(st.st_mode))
		}
	default:
		free(new_blob);
			die_errno("cannot lstat '%s'", path->buf);
				/* Filter reported an error */
			remove_subtree(path);
		assert(state->istate);
#include "submodule.h"
		}
		if (mkdir(path, 0777) < 0)
			display_progress(progress, delayed_object_count - dco->paths.nr);

	dco->state = CE_RETRY;
static int remove_available_paths(struct string_list_item *item, void *cb_data)
		if (dco && dco->state != CE_NO_DELAY) {
	static struct strbuf path = STRBUF_INIT;
			dup->ce_flags |= CE_MATCHED;
		/*
		strbuf_addstr(path, de->d_name);
#endif
		/*
		/*
	if (fd < 0)
			return error("cannot create temporary submodule %s", path);
		struct cache_entry *dup = state->istate->cache[i];
				&remove_available_paths, &available_paths);
		string_list_init(&state->delayed_checkout->filters, 0);
	trust_ino = 0;
		if (wrote < 0)

	return result;
			mark_colliding_entries(state, ce, &st);
 * When topath[] is not NULL, instead of writing to the working tree
				} else
	return NULL;
{
				if (!path->util) {
		if (state->clone)
		if (!new_blob)
	fd = open_output_fd(path, ce, to_tempfile);
			continue;
					"HEAD", oid_to_hex(&ce->oid),
		 * For 'checkout-index --prefix=<dir>', <dir> is
			return error("unable to read sha1 file of %s (%s)",
delayed:
void enable_delayed_checkout(struct checkout *state)

		return -1;
			if (!new_blob)
		if (!changed)
}
		 * filter is required), then we would have died already.
			if (!async_query_available_blobs(filter->string, &available_paths)) {
				fprintf(stderr,
static int fstat_output(int fd, const struct checkout *state, struct stat *st)
			break;
				ce = index_file_exists(state->istate, path->string,
					     path, oid_to_hex(&ce->oid));
		}
}
			if (!is_submodule_populated_gently(ce->name, &err)) {
			struct string_list available_paths = STRING_LIST_INIT_NODUP;
		mark_fsmonitor_invalid(state->istate, ce);

			 * The filter just send us a list of available paths.
			if (!state->quiet)
		 * there, therefore we then try to unlink it and try
		if (sub)
	struct string_list_item *available;

#include "fsmonitor.h"
				/*
