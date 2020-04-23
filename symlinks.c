	 */
}
	*previous_slash = match_len_prev;
 * directory.  If prefix_len > 0, we will test with the stat()
		i++;
	}
/*
}

	else
{
	 * Okay, no match from the cache so far, so now we have to
		removal.buf[removal.len] = '\0';
	 * remove possible empty directories as we go upwards.
	if (match_len < last_slash)
	}
static struct strbuf removal = STRBUF_INIT;
		reset_lstat_cache(cache);
#define FL_FULLPATH (1 << 5)
	int flags;
		*ret_flags = cache->flags & track_flags & (FL_NOENT|FL_SYMLINK);
		} while (match_len < len && name[match_len] != '/');
		if (name[i] == '/')
 * instead of the lstat() function to test each path component.
	int max_len, match_len = 0, match_len_prev = 0, i = 0;
			*ret_flags = FL_LSTATERR;
#include "cache.h"
	while (i < max_len && name_a[i] == name_b[i]) {
/*
			prefix_len_stat_func);
		 * the 2 "excluding" path types.

static int threaded_has_dirs_only_path(struct cache_def *cache, const char *name, int len, int prefix_len);
		 * non-existing directory and the track_flags says
			break;
 * Return path length if leading path exists and is neither a
 * Return path length if leading path exists and is neither a
	return flags;
	(void)lstat_cache_matchlen(cache, name, len, &flags, track_flags,
		}
		cache->path.len = last_slash;
		else
 * long as those points to real existing directories.
		cache->flags = save_flags;

	 */
			continue;

/*
	 * path types, FL_NOENT, FL_SYMLINK and FL_DIR, can be cached
	return lstat_cache(cache, name, len, FL_SYMLINK|FL_DIR, USE_ONLY_LSTAT) & FL_SYMLINK;
			break;
{
		 * the matched part will always be a directory.
}
		 * we can return immediately.
			return match_len;
	while (removal.len > new_len) {
}
 *
	int match_len = lstat_cache_matchlen(cache, name, len, &flags,
static int threaded_check_leading_path(struct cache_def *cache, const char *name, int len)
 * 'prefix_len', thus we then allow for symlinks in the prefix part as
			*ret_flags = FL_SYMLINK;
 */
		return match_len;
	struct stat st;
		if (match_len >= len && !(track_flags & FL_FULLPATH))
			last_slash = i;
	if (match_len < last_slash && match_len < removal.len)
		match_len = last_slash = 0;
			match_len = last_slash = previous_slash;
	match_len = last_slash = i =
 * The 'prefix_len_stat_func' parameter can be used to set the length
{
	}
		reset_lstat_cache(cache);
	 * for the moment!
	}
 * 'prefix_len', thus we then allow for symlinks in the prefix part as
 * Return non-zero if path 'name' has a leading symlink component
	 * save the new path components as we go down.
}
	/*
 * common prefix match of 'name_a' and 'name_b'.
 * if some leading path component does not exists.

	return threaded_has_dirs_only_path(&default_cache, name, len, prefix_len);

		 * that we cannot cache this fact, so the cache would
 * Return non-zero if path 'name' has a leading symlink component


		cache->path.buf[last_slash] = '\0';
	while (i < len) {
{
static int longest_path_match(const char *name_a, int len_a,
		i++;
 * Return non-zero if all path components of 'name' exists as a
static struct cache_def default_cache = CACHE_DEF_INIT;

			     (len_a < len_b && name_b[len_a] == '/') ||

		 */
			removal.len--;
	/*
	last_slash_dir = last_slash;

		 * since it could be that we have found a symlink or a


	}
/*
 */
	removal.len = new_len;
		return -1;
	 * or is 'name_a' and 'name_b' the exact same string?
			   FL_DIR|FL_FULLPATH, prefix_len) &
{
		cache->flags = FL_DIR;
	 * If we go deeper down the directory tree, we only need to
}
			ret = stat(cache->path.buf, &st);
		do {

		break;
int threaded_has_symlink_leading_path(struct cache_def *cache, const char *name, int len)
			      const char *name_b, int len_b,
				   &previous_slash);
}
		if (name_a[i] == '/') {
		 * can still cache the path components before the last
 * Return -1 if leading path exists and is a directory.
		 * does not match with the last supplied values.
	 * we must first go upwards the tree, such that we then can
		} else if (S_ISLNK(st.st_mode)) {
		 * But if we are allowed to track real directories, we
	if (len > cache->path.len)
		cache->prefix_len_stat_func = prefix_len_stat_func;
		cache->path.len = last_slash_dir;
					   cache->path.len, &previous_slash);
		 * then have been left empty in this case.
		longest_path_match(name, len, removal.buf, removal.len,
 */
{
 * To speed up the check, some information is allowed to be cached.
	do_remove_scheduled_dirs(0);
	 */
 * function instead of the lstat() function for a prefix length of
		 *
 */
		} else if (S_ISDIR(st.st_mode)) {
 * function instead of the lstat() function for a prefix length of
	if (save_flags && last_slash > 0) {
		 */
	} else {
}
		} else {
{
	/*
			return match_len;
		if (rmdir(removal.buf))
	 * If we are about to go down the directory tree, we check if
}
 * be used to indicate that we should check the full path.
		*ret_flags = track_flags & FL_DIR;

	int match_len, last_slash, i, previous_slash;
		 * If we now have match_len > 0, we would know that
#define FL_SYMLINK  (1 << 2)
		strbuf_add(&removal, &name[match_len], last_slash - match_len);
	max_len = len_a < len_b ? len_a : len_b;
#define FL_DIR      (1 << 0)
		/*
		do_remove_scheduled_dirs(match_len);
				const char *name, int len,
	int flags;
#define FL_NOENT    (1 << 1)
			      int *previous_slash)
	 */
static int threaded_check_leading_path(struct cache_def *cache, const char *name, int len);
	 * check the rest of the path components.
			cache->path.buf[match_len] = name[match_len];
static void do_remove_scheduled_dirs(int new_len)
				int *ret_flags, int track_flags,
	/*
static int lstat_cache_matchlen(struct cache_def *cache,

	 * Is 'name_b' a substring of 'name_a', the other way around,
		 */
 */
 * directory.  If prefix_len > 0, we will test with the stat()
 */
static int threaded_has_dirs_only_path(struct cache_def *cache, const char *name, int len, int prefix_len)
	else if (flags & FL_DIR)
int check_leading_path(const char *name, int len)
 * long as those points to real existing directories.
	} else if ((track_flags & FL_DIR) && last_slash_dir > 0) {
/*
		if (last_slash <= prefix_len_stat_func)
		cache->path.buf[last_slash_dir] = '\0';
{
	 */
			match_len = i;
				int prefix_len_stat_func)
		if (ret) {
		match_len = i;
	return threaded_check_leading_path(&default_cache, name, len);
void remove_scheduled_dirs(void)
	/*
 *
 * Return zero if path 'name' has a leading symlink component or
	return match_len;

 * component, or if the directory exists and is real, or not.
	 * The track_flags and prefix_len_stat_func members is only
static int lstat_cache(struct cache_def *cache, const char *name, int len,

	 */
 *
/*
			match_len++;
	if (cache->track_flags != track_flags ||
 * Returns the length (on a path component basis) of the longest
	cache->flags = 0;
	if (i >= max_len && ((len_a > len_b && name_a[len_b] == '/') ||
	 * At the end update the cache.  Note that max 3 different
			last_slash_dir = last_slash;
	strbuf_reset(&cache->path);
		if (*ret_flags && match_len == cache->path.len)
}
		 * As a safeguard rule we clear the cache if the

	/*
		cache->track_flags = track_flags;
	int match_len, last_slash, last_slash_dir, previous_slash;
		if (!(track_flags & FL_FULLPATH) && match_len == len)
		/*

/*
		cache->path.buf[last_slash] = '\0';
		} while (removal.len > new_len &&
void schedule_dir_for_removal(const char *name, int len)
		 * Also, if we are tracking directories and 'name' is

#define FL_LSTATERR (1 << 3)
	} else {
	int save_flags, ret;
	return threaded_has_symlink_leading_path(&default_cache, name, len);
 * directory nor a symlink.
static inline void reset_lstat_cache(struct cache_def *cache)
#define FL_ERR      (1 << 4)
		/*
		 *
 * directory nor a symlink.
 * Return zero if path 'name' has a leading symlink component or

	if (flags & FL_NOENT)
	}
#define USE_ONLY_LSTAT  0

	    cache->prefix_len_stat_func != prefix_len_stat_func) {
		match_len = last_slash =
 *
		 * a substring of the cache on a path component basis,
}
{
/*
{
	save_flags = *ret_flags & track_flags & (FL_NOENT|FL_SYMLINK);
	 * set by the safeguard rule inside lstat_cache()
		do {
}

		return 0;
			   FL_SYMLINK|FL_NOENT|FL_DIR, USE_ONLY_LSTAT);
	return match_len;
 *
			longest_path_match(name, len, cache->path.buf,
int has_symlink_leading_path(const char *name, int len)
		match_len_prev = match_len;
		strbuf_grow(&cache->path, len - cache->path.len);
			     (len_a == len_b))) {
	/* Find last slash inside 'name' */
	while (match_len < len) {
int has_dirs_only_path(const char *name, int len, int prefix_len)
			*ret_flags = FL_ERR;
 */
		 * values of track_flags and/or prefix_len_stat_func
			ret = lstat(cache->path.buf, &st);

 * if some leading path component does not exists.
 * This can be indicated by the 'track_flags' argument, which also can

		if (*ret_flags && len == match_len)
 */
		last_slash = match_len;
			match_len_prev = match_len;
		 * one (the found symlink or non-existing component).
{
 * Return non-zero if all path components of 'name' exists as a
		       int track_flags, int prefix_len_stat_func)


		FL_DIR;
	*ret_flags = FL_DIR;
		 */
{
{
}
		 * Check to see if we have a match from the cache for
			if (errno == ENOENT)
	}
 * of the prefix, where the cache should use the stat() function
		 * We have a separate test for the directory case,
			 removal.buf[removal.len] != '/');
		}
 *
 * Return -1 if leading path exists and is a directory.
				*ret_flags |= FL_NOENT;
 * Check if name 'name' of length 'len' has a symlink leading
	return lstat_cache(cache, name, len,
		/*
