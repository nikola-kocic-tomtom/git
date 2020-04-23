	ALLOC_GROW(iter->levels, 10, iter->levels_alloc);
	level->dir = NULL;
}
static int prepare_next_entry_data(struct dir_iterator_int *iter,
	 */

	if (S_ISDIR(iter->base.st.st_mode) && push_level(iter)) {
static int push_level(struct dir_iterator_int *iter)
 */
		struct dir_iterator_level *level =
	/* Combination of flags for this dir-iterator */
	DIR *dir;
	 */
	 * that will be included in this iteration.

				warning_errno("error reading directory '%s'",
		struct dirent *de;
	level->dir = opendir(iter->base.path.buf);
	iter->flags = flags;
			if (errno != ENOENT && iter->flags & DIR_ITERATOR_PEDANTIC)
				goto error_out;
			goto error_out;
	struct dir_iterator_level *levels;
	else

	free(iter->levels);
	return --iter->levels_nr;
		return -1;
	ALLOC_GROW(iter->levels, iter->levels_nr + 1, iter->levels_alloc);
		struct dir_iterator_level *level =
 * the directory pointed by iter->base->path. It is assumed that this
	/* The number of levels that have been allocated on the stack */
	/*
	 * inexistent paths.
int dir_iterator_abort(struct dir_iterator *dir_iterator)
		strbuf_addch(&iter->base.path, '/');

	int saved_errno;
			      iter->base.path.buf);
	/*

 * iteration state. It includes members that are not part of the
			if (errno) {
	 * A stack of levels. levels[0] is the uppermost directory
 */

			}
		err = lstat(iter->base.path.buf, &iter->base.st);
	struct dir_iterator_level *level =
				      iter->base.path.buf);
		strbuf_setlen(&iter->base.path, level->prefix_len);
		if (level->dir && closedir(level->dir)) {
			strbuf_setlen(&iter->base.path, level->prefix_len);
 * otherwise, setting errno accordingly.
int dir_iterator_advance(struct dir_iterator *dir_iterator)
	for (; iter->levels_nr; iter->levels_nr--) {
{
error_out:


#include "iterator.h"
	struct dir_iterator base;
		return ITER_OK;
	return NULL;

	 */

	size_t levels_alloc;
	level->prefix_len = iter->base.path.len;

	iter->base.relative_path = iter->base.path.buf +
	level = &iter->levels[iter->levels_nr++];
	}
		err = stat(iter->base.path.buf, &iter->base.st);
	 * (including a trailing '/'):

					      iter->base.path.buf);
	return err;
		if (iter->levels_nr == 0)
			errno = saved_errno;
		&iter->levels[iter->levels_nr - 1];
 * otherwise, setting errno accordingly and leaving the stack unchanged.
			goto error_out;
 * The full data structure used to manage the internal directory
		goto error_out;
	}
		}

	strbuf_addstr(&iter->base.path, path);

	/* Loop until we find an entry that we can give back to the caller. */
				   iter->levels[0].prefix_len;
			int saved_errno = errno;
				if (iter->flags & DIR_ITERATOR_PEDANTIC)
	 * The length of the directory part of path at this level
#include "dir.h"
	 * The number of levels currently on the stack. After the first

 * Populate iter->base with the necessary information on the next iteration
 * Push a level in the iter stack and initialize it with information from


			&iter->levels[iter->levels_nr - 1];

	struct dir_iterator_level *level;

			warning_errno("error closing directory '%s'",
		(struct dir_iterator_int *)dir_iterator;

		saved_errno = errno;
		goto error_out;
	errno = saved_errno;
			      iter->levels[iter->levels_nr - 1].prefix_len;
}
		int saved_errno = errno;
		iter->levels_nr--;
			&iter->levels[iter->levels_nr - 1];

	free(iter);
		de = readdir(level->dir);
	size_t levels_nr;
	struct dir_iterator_int *iter = xcalloc(1, sizeof(*iter));
				return dir_iterator_abort(dir_iterator);

			warning_errno("error opening directory '%s'",
	strbuf_addstr(&iter->base.path, de->d_name);
	dir_iterator_abort(dir_iterator);


				   struct dirent *de)
		errno = saved_errno;
			continue;

	unsigned int flags;

	}
		}
		if (is_dot_or_dotdot(de->d_name))
}
	if (stat(iter->base.path.buf, &iter->base.st) < 0) {
	if (!S_ISDIR(iter->base.st.st_mode)) {
#include "cache.h"
	strbuf_release(&iter->base.path);
	 */
{
 * with it. Return the new value of iter->levels_nr.
	struct dir_iterator_int *iter =
 * entry, represented by the given dirent de. Return 0 on success and -1
 */
}
	return dir_iterator;
		}
		if (!de) {
}
			continue;
{


	if (level->dir && closedir(level->dir))
		saved_errno = ENOTDIR;
	/*
	/*
			} else if (pop_level(iter) == 0) {

}



		warning_errno("error closing directory '%s'",
	if (iter->flags & DIR_ITERATOR_FOLLOW_SYMLINKS)
	iter->levels_nr = 0;
	}
error_out:

	}
	if (err && errno != ENOENT)
	struct dir_iterator *dir_iterator = &iter->base;

	return 0;
 * Pop the top level on the iter stack, releasing any resources associated
 * public interface.
	 * We have to reset these because the path strbuf might have
{
	saved_errno = errno;
{
	 * struct is freed.
	int err, saved_errno;
		if (errno != ENOENT) {
/*
	strbuf_init(&iter->base.path, PATH_MAX);
	 */
};


	 * first level's dir, this will always be at least 1. Then,

	}
		if (prepare_next_entry_data(iter, de)) {
	errno = saved_errno;
	 * call to dir_iterator_begin(), if it succeeds to open the
{
	/*

				      iter->base.path.buf);
/*
static int pop_level(struct dir_iterator_int *iter)
struct dir_iterator *dir_iterator_begin(const char *path, unsigned int flags)

					goto error_out;
struct dir_iterator_int {
/*
		if (errno != ENOENT && iter->flags & DIR_ITERATOR_PEDANTIC)
struct dir_iterator_level {
	if (!level->dir) {
	return ITER_DONE;
			continue;
	return ITER_ERROR;
		errno = 0;
	struct dir_iterator_int *iter = (struct dir_iterator_int *)dir_iterator;
	iter->base.basename = iter->base.path.buf +

	 * when it comes to zero the iteration is ended and this
 * strbuf points to a valid directory path. Return 0 on success and -1
	if (!is_dir_sep(iter->base.path.buf[iter->base.path.len - 1]))
	size_t prefix_len;
};
/*
		warning_errno("failed to stat '%s'", iter->base.path.buf);
	dir_iterator_abort(dir_iterator);
	 * Note: stat already checks for NULL or empty strings and
		}
	 * been realloc()ed at the previous strbuf_addstr().
	while (1) {
 */
#include "dir-iterator.h"
