static enum path_treatment treat_directory(struct dir_struct *dir,

			cdir->d_type = DT_UNKNOWN;
	}

	const unsigned hashsz = the_hash_algo->rawsz;
 *  (c) otherwise, we recurse into it.
				oidcpy(&oid_stat->oid, the_hash_algo->empty_blob);
	pl->src = src;
		     /*
	strbuf_release(&str_buf);
			 * only if it matches an exclude pattern).
}
		if (!ce_uptodate(ce))
	int offset = 0;
		prefix--;
		/*
		 */
{
	ud->valid = 1;
	/*
	struct pattern_list *pl;
	}
	/* treat_one_path() does this before it calls treat_directory() */
static int do_read_blob(const struct object_id *oid, struct oid_stat *oid_stat,
			if (oid_stat->valid &&
	}
	cwd = xgetcwd();
clear_hashmaps:
	} else if (flags & PATTERN_FLAG_ENDSWITH) {
				break;
	const unsigned char *end;
}
	int i, lineno = 1;
	dir->untracked_nr = 0;
		goto done;
	to->sd_ino	  = ntohl(to->sd_ino);
		return 0;
	return rc;

 * Case 1: If we *already* have entries in the index under that
		string += prefix;
static void do_invalidate_gitignore(struct untracked_cache_dir *dir)
 *
				      basename, basenamelen,
	strbuf_setlen(buffer, 0);
				 struct untracked_cache_dir *dir)
#include "ewah/ewok.h"
		if (pathspec->items[n].magic & PATHSPEC_ICASE)
			add_untracked(untracked, path->buf + baselen);
	if (!pl->use_cone_patterns)
				      struct cached_dir *cdir,
int remove_path(const char *name)
int match_pathspec(const struct index_state *istate,
	 * prefix. If the pathspec is abc/foo abc/bar, running in
		if (kept_up)
	untracked = validate_untracked_cache(dir, len, pathspec);
		return wildmatch(pattern, string,
		subdir++;
	if (hashmap_get_entry(&pl->parent_hashmap, translated, ent, NULL)) {
			    struct strbuf *buffer)
	return negative ? 0 : positive;
 *
			return 0;
struct cached_dir {
	set = result;
	/* If the submodule has no working tree, we can ignore it. */
{
				dir->entries[i++] = dir->entries[j];
		if (prefix > namelen)
 *          ------+-----------+-----------+------------
	struct untracked_cache_dir *untracked,
	/*
			if (pattern)
		 */
	}

	pos = index_name_pos(istate, dirname, len);
				continue;
		return MATCHED;
	 * long, maybe change it to
			else
	to->sd_gid	  = ntohl(to->sd_gid);
		free(dirs);
		if (len == pathlen &&
}
			current = 0;

{
	    !has_path_in_index &&
		 * NEEDSWORK: when untracked cache is enabled, prep_exclude()
 */
	case DT_REG:
		return -1;

	git_config_set_in_file(cfg_sb.buf, "core.worktree",
 */
	QSORT(dir->entries, dir->nr, cmp_dir_entry);
		patternlen--;

	 * index.
	memcpy(untracked, &ud, sizeof(ud));

	return errors;
		     * been executed and set untracked->valid) ..
				 * returning `path_excluded`. This is
		free_untracked_cache(uc);
		 * pathspec so return.
int pl_hashmap_cmp(const void *unused_cmp_data,
		   &dir->untracked->ss_info_exclude.oid)) {
	rd.data = next + len;
 * undecided.

 * Also, we ignore the name ".git" (even if it is not a directory).
	ud.dirs_alloc = ud.dirs_nr = decode_varint(&data);
static struct dir_entry *dir_entry_new(const char *pathname, int len)
	const unsigned char *data;
	len = decode_varint(&next);
			return d;
		if (r != 1)
	if (flags & PATTERN_FLAG_MUSTBEDIR) {
				how = 0;

 * Frees memory within dir which was allocated for exclude lists and
	rd->ucd[rd->index++] = untracked;

	strbuf_init(&uc->ident, 100);
				 "gitignore invalidation: %u\n"
				/*
	struct strbuf sub_gd = STRBUF_INIT;
	struct repository subrepo;
 * If "name" has the trailing slash, it'll be excluded in the search.
				     flags | DO_MATCH_EXCLUDE);
		return 0;
	char *slash;
	unsigned flags;
{
	if (untracked->valid) {
	int index;	   /* number of written untracked_cache_dir */
			continue;
					dir_state = path_excluded;
	while (*s)
}
			if (dir->pattern &&

		result = MATCHED_RECURSIVE;
	ALLOC_GROW(dir->ignored, dir->ignored_nr+1, dir->ignored_alloc);
		 * The caller might have fed identical pathspec
	ewah_each_bit(rd.sha1_valid, read_oid, &rd);
	    !strcmp(given->pattern, "/*")) {
	if (unlink(name) && !is_missing_file_error(errno))
			/* Not a cone pattern. */
		istate->cache_changed |= UNTRACKED_CHANGED;
	if (slash_pos == parent_pathname.buf) {

		if (state == path_untracked &&
			     unsigned flags)
	unsigned int value;
			   do_match_pathspec(istate, pathspec, path.buf, path.len,
		*(set - 2) = 0;
	 */
					    0 /* do NOT special case dirs */))
		memset(dir->untracked->root, 0, len);
					   struct index_state *istate,
	if (untracked)
	int i, j;
	 */


	const char *cp = name, *cpe = name + namelen;
		if (dir->flags & DIR_SHOW_IGNORED)
		      */
		    !fspathncmp(pattern, basename, basenamelen))
		pattern++;
 * day.
static void add_path_to_appropriate_result_list(struct dir_struct *dir,
	if (!safe_path && !verify_path(path, 0))
		/*
	FLEX_ALLOC_MEM(ent, name, pathname, len);
	trace_performance_enter();
				continue;

	return lstat(f, &sb) == 0;
}
 * whether an untracked or exluded path was encountered first.
	to->sd_mtime.sec  = htonl(from->sd_mtime.sec);

	 * prep_exclude() is designed.
	 * use cache on just a subset of the worktree. pathspec
		/*
				seen[i] = how;
}

	memset(pl, 0, sizeof(*pl));
		   const char *path, int len, const struct pathspec *pathspec)
}
		if (strncmp(ce->name, path, len))
		    *cur == '*' &&
	}
				 * file disappeared, which is what we
			cnt++;
	closedir(dir);
		next++;
		} else {
static int get_index_dtype(struct index_state *istate,
		clear_pattern_list(pl);

 * search the subdir in "dir" and return it, or create a new one if it

	}
		if (endchar > '/')
		 * If the whole pattern did not have a wildcard,
	ce = index_file_exists(istate, dirname, len, ignore_case);
	}
		return -1;
}
}
{
	if (len < 0)
	int keep_toplevel = (flag & REMOVE_DIR_KEEP_TOPLEVEL);
		/* But allow the initial '\' */
{
		/* Watch for glob characters '*', '\', '[', '?' */
	istate->cache_changed |= UNTRACKED_CHANGED;
		/* name is a literal prefix of the pathspec */
	 *
{
	r = do_read_blob(oid, NULL, &size, &buf);
		last_matching_pattern(dir, istate, pathname, dtype_p);
		}
				      const struct pathspec *pathspec)
		strbuf_setlen(path, path->len - 1);
	wd.check_only = ewah_new();
	struct ewah_bitmap *check_only;
		return NULL;


	return ignore_case ? strcasecmp(a, b) : strcmp(a, b);
					  struct strbuf *path,
		cdir.d_name = subdir.buf;
	 *    * <anything else> for some intermediate component, we make sure

		}

		}

	char *data = NULL;
	if (S_ISREG(st.st_mode))
	 * wildcard. In other words, only prefix is considered common
	if (!dir)
		   unsigned flags)
	path_recurse,
	 * use that to optimize the directory walk
 * the files it contains) will sort with the '/' at the

}
				      int *dtype_p)
			if (c == '/')
}
	if (*p == '!') {
		pl = add_pattern_list(dir, EXC_DIRS, NULL);
		const struct cache_entry *ce = istate->cache[pos++];
						       oid_stat);
			/* fall through */
	const struct pattern_entry *ee1 =
 * This handles recursive filename detection with exclude
	GUARD_PATHSPEC(pathspec,

	return 1;
		if (*cp++ != '/')
	}
					   int baselen,
		 * Here is where we would perform a wildmatch to check if
		strbuf_addch(path, '/');
	size_t max = 0;

	return untracked->valid;
	strbuf_add(&parent_pathname, pathname, pathlen);
		goto done;
				dir->exclude_stack = stk;
		de = readdir(cdir->fdir);
			given->pattern);
	if (S_ISLNK(st.st_mode))
			    int check_only)
	}
/*
	if (!ps->nr) {
	strbuf_release(&sb);
		 * not match an exclude pattern but all of its
	/*
		       PATHSPEC_MAXDEPTH |
	     */
 * can be used as relative path to dir.
	if (sb.len)
	/* foo[/]bar vs foo[] */
char *common_prefix(const struct pathspec *pathspec)
	}
			if (other == num || !ps_matched[other])
	if (!dir->untracked->root) {

			return 0;
						     untracked, 1, 1, pathspec) == path_excluded)
		}

static char *dup_and_filter_pattern(const char *pattern)
}
 * Case 2: If we *already* have that directory name as a gitlink,
				 * wanted anyway

			int dt = DT_DIR;
		 */

	}
 *
		return positive;
			lineno++;
					  int dtype)
	strbuf_addch(&uc->ident, 0);
	 *
{
	/*
			free(buf);
		pattern += prefix;
		int how;
	for (i = 0; i < untracked->untracked_nr; i++) {
 *
		return exclude ? path_excluded : path_untracked;

	int pos;
		sub = submodule_from_path(&subrepo, &null_oid, ce->name);
			FREE_AND_NULL(dir->untracked);


	return strncmp(ee1->pattern, ee2->pattern, min_len);
		len--;
	 */
	next += ident_len;
	/*

	int namelen;
	if (simplify_away(path->buf, path->len, pathspec))
		pl = &group->pl[dir->exclude_stack->exclude_ix];
		unsigned char endchar;
	pattern->baselen = baselen;
	}
enum path_treatment {
}
			break;

}
		cdir->d_name = de->d_name;

		return dir->nr;
		closedir(cdir->fdir);
		const char *cp;
			   int *nowildcardlen)
 * outside dir, return -1.  Otherwise return the offset in subdir that
		if (item->nowildcard_len == item->len)
	strbuf_add(out, varbuf, varint_len);
		}
	to->sd_size	  = htonl(from->sd_size);
	}
	}
		return path_recurse;

/*
{

	if (dir->untracked) {
		return path_none;
			 * is unreadable:
	strbuf_complete(path, '/');
struct write_data {
	/* per repository user preference */
		struct stat st;
	if (dir->exclude_list_group[EXC_CMDL].nr)
	if (!untracked)
	if (item->prefix && (item->magic & PATHSPEC_ICASE) &&
		}

				free((char *)pl->src);
		patternlen -= prefix;
		 * "pathspec ':(exclude)foo' matches no files"
	translated->patternlen = given->patternlen;
	cdir->ucd = NULL;
		   const char *base, int baselen,
		goto clear_hashmaps;
	uc->dir_flags = DIR_SHOW_OTHER_DIRECTORIES | DIR_HIDE_EMPTY_DIRECTORIES;
	int rc;

	size_t min_len = ee1->patternlen <= ee2->patternlen
	 * EXC_CMDL is not considered in the cache. If people set it,
static void add_patterns_from_file_1(struct dir_struct *dir, const char *fname,
	if (!dir) {
			 * need fname to remain unchanged to ensure the src
		       PATHSPEC_MAXDEPTH |
		free_untracked(ucd->dirs[i]);
	int ident_len;
	 *
						       struct pattern_list *pl,
			  const unsigned char *sha1)
}

				 dir->untracked->gitignore_invalidated,
				      struct index_state *istate,
		       PATHSPEC_LITERAL |

	 *    .git/info/
				 * files will be excluded.

			baselen = len;
	 * the working tree needs to go when P is checked out from the
		    ps_strncmp(item, match, name,

	}
	ewah_each_bit(rd.valid, read_stat, &rd);
	return ent;
			goto clear_hashmaps;
		if (nested_repo)
					 dir->untracked ? &dir->ss_excludes_file : NULL);
}
				    const char *base, int baselen,

			oidcpy(&untracked->exclude_oid, &oid_stat.oid);
	/*

	} else
				const char *basename, int *dtype,

			continue;
	    (baselen && pathname[baselen] != '/') ||
	if (rest) {

		istate->untracked = NULL;
 * It may be instructive to look at a small table of concrete examples


			if (!match_pathspec(istate, pathspec, sb.buf, sb.len,
			   struct dir_struct *dir,
 * directory any more (because "bar" is managed by foo as an untracked
		static struct trace_key trace_untracked_stats = TRACE_KEY_INIT(UNTRACKED_STATS);

	if (data[sz - 1] != '\n') {
}
		return 0;

	    !strcmp(given->pattern + given->patternlen - 2, "/*")) {
				   ignore_case ?
		varint_len = encode_varint(0, varbuf);
 * Scan the list of patterns to determine if the ordered list
 *  (a) if "show_other_directories" is true, we show it as
		strbuf_reset(&sb);
		die(_("could not create directories for %s"), cfg_sb.buf);
	if (cdir->fdir)
	const struct dir_entry *e1 = *(const struct dir_entry **)p1;
		return;


		if (len > pathlen)
	struct cached_dir *cdir,
	to->sd_uid	  = ntohl(to->sd_uid);


		return DT_DIR;
		ewah_set(wd->valid, i);

static int resolve_dtype(int dtype, struct index_state *istate,
 */
				dir->basebuf.buf + current, &dt);
{

		return;

		if (dir->flags & DIR_SHOW_IGNORED)
	hashcpy(oid_stat->oid.hash, sha1);
			item_len = pathspec->items[n].nowildcard_len;
static void write_one_dir(struct untracked_cache_dir *untracked,
		len--;
				lookup_untracked(dir->untracked, untracked,
		 * recurse into this directory (instead of marking the
	/* add the path to the appropriate result list */
	}
	struct strbuf rel_path = STRBUF_INIT;
			       relative_path(work_tree, git_dir, &rel_path));
		d = dir->dirs[next];

			/* We did not see the "parent" included */

		 * contents are excluded, then indicate that we should

 */
int check_dir_entry_contains(const struct dir_entry *out, const struct dir_entry *in)
		/* But only if *prev != '\\' */
	/* If the match was just the prefix, we matched */
	memcpy(untracked->name, data, eos - data + 1);
 * This is an inexact early pruning of any recursive directory
	if (ignore_case)
				 !would_convert_to_git(istate, fname))
 *          a/b   |  EXACT    |  EXACT[1] | LEADING[2]
	len = ewah_read_mmap(rd.check_only, next, end - next);
	if (item->flags & PATHSPEC_ONESTAR) {
		/*
 */
		dir->dirs[i]->recurse = 0;
	return root;
	 * (e.g. from command line) invalidate the cache. This
	return 0;
	struct untracked_cache_dir *ud = rd->ucd[pos];
	next += len;
	}
	if (repo != the_repository)


	struct strbuf sb_sha1;
	return add_patterns(fname, base, baselen, pl, istate, NULL);
static void add_untracked(struct untracked_cache_dir *dir, const char *name)
	memset(pl, 0, sizeof(*pl));
	fd = open(fname, O_RDONLY);
		how = match_pathspec_item(istate, ps->items+i, prefix, name,
	const struct pathspec *pathspec,
		if (lstat(path->buf, &st)) {
 *
		if ((dir->flags & DIR_SKIP_NESTED_GIT) ||
		    how && how != MATCHED_FNMATCH) {
							 check_only, stop_at_first_file, pathspec);
	 * Lazy initialization. All call sites currently just
		if (!hashmap_get_entry(&pl->recursive_hashmap,
}
			((dir->flags & DIR_COLLECT_IGNORED) &&
	if (!untracked)
	untracked = lookup_untracked(dir->untracked, untracked,

static struct dir_entry *dir_add_name(struct dir_struct *dir,

	 *        to add that path to the relevant list but return false
	    strncmp(item->match, name - prefix, item->prefix))
	 * subdir xyz, the common prefix is still xyz, not xyz/abc as
			state = path_recurse;
	pos = index_name_pos(istate, path, len);
	    /*
	to->sd_ino	  = htonl(from->sd_ino);

	oid_stat->valid = 1;
	if (given->patternlen > 2 &&
	struct untracked_cache_dir *ud = rd->ucd[pos];
	struct dir_entry *ent;
	if (untracked_cache_disabled < 0)
static int ident_in_untracked(const struct untracked_cache *uc)
	if (recurse_into_nested)
{

void setup_standard_excludes(struct dir_struct *dir)
				 * If stopping at first file, then
				   strihash(translated->pattern) :
		warning(_("unrecognized negative pattern: '%s'"),
	uc->dir_created++;
static int read_cached_dir(struct cached_dir *cdir)
	ouc = xcalloc(1, sizeof(*ouc));
		return 0;
	/*
		free(data);
}
			add_patterns_from_file_1(dir, path,
 * (e.g. entries from the index) and is interested in seeing if and
void free_untracked_cache(struct untracked_cache *uc)
	    *given->pattern == '*' ||
/*
	 * Make sure all pathspec matched; otherwise it is an error.
				FREE_AND_NULL(dir->entries[j]);

	stat_data_to_disk(&ouc->info_exclude_stat, &untracked->ss_info_exclude.stat);
				       translated, ent, NULL)) {
	 * Optimize for the main use case only: whole-tree git
	wd.valid      = ewah_new();
	struct stat sb;
	if (dir->pattern)
	ewah_each_bit(rd.check_only, set_check_only, &rd);
static void connect_wt_gitdir_in_nested(const char *sub_worktree,
			   unsigned *flags,
		result = MATCHED;
	if (*nowildcardlen > len)
	/*

{
		data = eos + 1;
		       PATHSPEC_EXCLUDE |

}
		int len = item->nowildcard_len;
	/*
				      const char *pathname,
	if (path[0] != '/')
	char *set, *read;


	hashmap_free_entries(&pl->recursive_hashmap, struct pattern_entry, ent);
		stk->prev = dir->exclude_stack;
		if (depth > max_depth)

		       PATHSPEC_LITERAL |

			if (c != pathspec->items[0].match[i])
	 * P/Q in the working tree to be killed, so we need to recurse.
				 * encountered 1st.

		}
		    (dir->flags & DIR_SHOW_IGNORED_TOO_MODE_MATCHING))
int match_basename(const char *basename, int basenamelen,

	/*
	free(pl->filebuf);
{
			    !match_pathspec(istate, pathspec, path.buf, path.len,
 * and which one we choose depends on a combination of existing

						cdir->ucd, 1, 0, pathspec);
		/* recurse into subdir if instructed by treat_path */

	return max;
 * seen[n] remains zero after multiple invocations, that means the nth
	path_none = 0,
	}
		if (errno == ENOENT)


		/* Abort if the directory is excluded */
			return MATCHED_RECURSIVELY;
#include "wildmatch.h"
void untracked_cache_remove_from_index(struct index_state *istate,
	for (i = 0; i < dir->dirs_nr; i++)

				return pattern;
			int len = ps->items[i].len;

	if (untracked->check_only != !!check_only)
		cdir->nr_dirs++;
				const char *pathname, int pathlen,
	return 0;
		dir->untracked->root = xmalloc(len);
	struct ondisk_untracked_cache *ouc;
#include "submodule-config.h"

	 * recursing.
void untracked_cache_invalidate_path(struct index_state *istate,
	cur = given->pattern + 1;
		       PATHSPEC_GLOB |
{
		r = read_skip_worktree_file_from_index(istate, fname,
		strbuf_add(&str_buf, string, stringlen);
	struct index_state *istate, const char *base, int baselen,
			if (pathspec &&
	const unsigned char *data = rd->data, *end = rd->end;
		invalidate_gitignore(dir->untracked, root);
	/*
				dir->basebuf.buf, stk->baselen - 1,
/*

		cur++;
				   int baselen, struct pattern_list *pl,

						       &size, &buf,
 * The index sorts alphabetically by entry name, which
		free(ucd->untracked[i]);
		return -1;
			last_space = NULL;
	ALLOC_GROW(dir->entries, dir->nr+1, dir->alloc);
			return 0;
int is_empty_dir(const char *path)
static enum path_treatment treat_path_fast(struct dir_struct *dir,
			fill_stat_data(&oid_stat->stat, &st);

 * was the last untracked entry in the entire "foo", we should show
				/*
			warning(_("unrecognized negative pattern: '%s'"),

		/* Do not descend and nuke a nested git work tree. */
			   strhash(translated->pattern));
 * directory hash.
		if (*s++ == '/')
 */
		}

	strbuf_release(&sub_wt);

}
}
			free(truncated);

		if (*cur == '\\' &&
	strbuf_init(&wd.out, 1024);
		      next + offset + hashsz);
		strbuf_add(&wd->sb_sha1, untracked->exclude_oid.hash,
	uc = xcalloc(1, sizeof(*uc));
	if (rd->data + the_hash_algo->rawsz > rd->end) {

	}
	int len = -1;
	to->sd_mtime.sec  = ntohl(to->sd_mtime.sec);
	}
	strbuf_release(&wd.out);
 * the directory name; instead, use the case insensitive

{
	if (pl->full_cone)
	 */
		stat_data_to_disk(&stat_data, &untracked->stat_data);
	int result = NOT_MATCHED;


					    0 /* prefix */, NULL,
				    struct pattern_list *pl);
};
			return 1;

{
{
						       struct index_state *istate)

	if (*p == '*' && no_wildcard(p + 1))
		   const struct hashmap_entry *a,
 *
	if (!(dir->untracked->use_fsmonitor && untracked->valid)) {
		uc->dir_invalidated++;
		   const char *pattern, int prefix, int patternlen,
	strbuf_init(&uc->ident, ident_len);
			continue;


		if (seen && seen[i] == MATCHED_EXACTLY)

enum pattern_match_result path_matches_pattern_list(
	int exclude;
		else if (errno == EACCES && !keep_toplevel)
	int pos, len;
	while (*cur) {
	parse_path_pattern(&string, &patternlen, &flags, &nowildcardlen);
	ssize_t len;

		strbuf_setlen(path, len);
	 * path. The next calls will be nearly no-op, the way
			   int check_only)
 *                |    a/b    |   a/b/    |   a/b/c
	} else {
{
		warning(_("untracked cache is disabled on this system or location"));
};
	p.patternlen = pattern->len;
	next += exclude_per_dir_offset + strlen(exclude_per_dir) + 1;
	read = result;
		if (oid_stat) {
		if (match[matchlen-1] == '/' || name[matchlen] == '/')
	ewah_serialize_strbuf(wd.check_only, out);
	char *buf;
		if (matchlen == namelen)
	/*
}
				  struct index_state *istate,
			 */
{
		depth++;
		 * Make exclude patterns optional and never report

		translated->pattern = truncated;
	baselen = 0;
		    (ps->magic & PATHSPEC_MAXDEPTH) &&
			if (!*p)
	default:
 * Frees memory within pl which was allocated for exclude patterns and
		 * used, last_matching_pattern() will not be called and
	const unsigned hashsz = the_hash_algo->rawsz;
	if (!pathspec || !pathspec->nr)
		return toupper(a) - toupper(b);
}
		connect_work_tree_and_git_dir(sub_wt.buf, sub_gd.buf, 1);
		return strncasecmp(ee1->pattern, ee2->pattern, min_len);
	if (exclude && !(dir->flags & (DIR_SHOW_IGNORED|DIR_SHOW_IGNORED_TOO)))
	 * skip the cache.
			/* skip the dir_add_* part */
	size_t size;
	if (i == len)
			dir_state = state;

/*
		}
	enum path_treatment state)
	    (dir->flags & (DIR_SHOW_IGNORED | DIR_SHOW_IGNORED_TOO |
	    (directory_exists_in_index(istate, path->buf, path->len) == index_nonexistent))
			continue;

		die(_("could not create directories for %s"), gitfile_sb.buf);
		return -1;
	if (item->nowildcard_len < item->len &&

		   const struct pathspec *pathspec)
{
		eos = memchr(data, '\0', end - data);
 */

	 * differently when dir->untracked is non-NULL.
int hashmap_contains_parent(struct hashmap *map,
	int i;
			if (retval < how)
	}
		return NULL;
	for (i = ps->nr - 1; i >= 0; i--) {
int is_excluded(struct dir_struct *dir, struct index_state *istate,
		return dir->pattern;
		 *
}
void add_untracked_cache(struct index_state *istate)
	}
}
	rd.valid      = ewah_new();
	}
	}
	while (*dir && *subdir && !cmp_icase(*dir, *subdir)) {
	ALLOC_ARRAY(ud.dirs, ud.dirs_nr);
		pl->full_cone = 1;
}
			entry = buf + i + 1;
{

		/* path too long, stat fails, or non-directory still exists */
	istate->untracked = uc;
	int baselen,
	 * strings in the "ident" field, but it is insane to manage
		return NULL;


		if (!eos || eos == end)
	if (open_cached_dir(&cdir, dir, untracked, istate, &path, check_only))
			return 0;
#define DO_MATCH_DIRECTORY (1<<1)
	}
{
	for (n = 0; n < pathspec->nr; n++) {
			container_of(b, struct pattern_entry, ent);
				add_pattern(entry, base, baselen, pl, lineno);
	 */
				buf[i - (i && buf[i-1] == '\r')] = 0;
	struct strbuf parent_pathname = STRBUF_INIT;
		      * ENOENT anyway.


		ret = -1;
	 * then we will ask treat_path() whether we should go into foo, then
		strbuf_reset(&sub_wt);
				 * an exclude pattern, so any found
{
				       &istate->cache[pos]->oid);
	 */
				   int recurse_into_nested)

}
}
				fill_stat_data(&oid_stat->stat, &st);
			len = pathlen;
			      const struct pathspec *pathspec)
	case path_untracked:
		 */
		return NULL;
		else

		offset++;
	}
					      size_t *size_out, char **data_out,


	 * may not end with a trailing slash though.
	GUARD_PATHSPEC(pathspec,
	 * to require P to be a directory, either.  Only in this case, we
	strbuf_addbuf(out, &wd.sb_sha1);
	ewah_free(rd.check_only);
	if ((flag & REMOVE_DIR_KEEP_NESTED_GIT) &&
		if (read_one_dir(untracked->dirs + i, rd) < 0)
	ce = index_file_exists(istate, path, len, 0);
	if (ud.untracked_nr)
	 */
			return -1;
	 * Excluded? If we don't explicitly want to show
		trace_performance_leave("read directory %.*s", len, path);

			   strihash(translated->pattern) :
			   struct index_state *istate,
		 * .gitignore SHA-1 from the index (i.e. .gitignore is not
		   namelen == matchlen - 1 &&
int git_fnmatch(const struct pathspec_item *item,
	return result;
	struct strbuf str_buf = STRBUF_INIT;
	ucd->valid = 0;
{
	if (is_dot_or_dotdot(cdir->d_name) || !fspathcmp(cdir->d_name, ".git"))
	 * of the index, but we do not know yet if there is a directory
int fill_directory(struct dir_struct *dir,
		return DT_LNK;
	index_directory,
	enum path_treatment state = path_none;
	struct exclude_list_group *group;
		return path_recurse;
	return is_dir_sep(*subdir) ? offset + 1 : -1;
	int patternlen;
/*

	strbuf_release(&path);
					      path.len - baselen);
		!memcmp(out->name, in->name, out->len);
	if (valid_cached_dir(dir, untracked, istate, path, check_only))

		    path_treatment == path_excluded &&

static void invalidate_one_directory(struct untracked_cache *uc,
		return MATCHED_FNMATCH;
	return !!hashmap_get_entry(map, &p, ent, NULL);
						       int *dtype,
};
		 * check_only is set as a result of treat_directory() getting
	if (!len || treat_leading_path(dir, istate, path, len, pathspec))
			/*
		 */
	rd->data = data;
}
	 */
 *  - ignore it
	name = pathname + pathlen - namelen;
					   exclude, prefix, pattern->patternlen,
	dir->valid = 0;
	eos = memchr(data, '\0', end - data);
	strbuf_addstr(&uc->ident, get_ident_string());
				     const char *path, int safe_path)
	 * Pop the exclude lists from the EXCL_DIRS exclude_list_group
			break;

{
		 * with check_only set.
void untracked_cache_add_to_index(struct index_state *istate,
}

		    !ps_strncmp(item, item->match, path, pathlen))
		translated = xmalloc(sizeof(struct pattern_entry));

{
	if (pos >= 0)


		   const char *name, int namelen,
				return path_excluded;
	rc = (dir_inside_of(cwd, dir) >= 0);
	return read_directory_recursive(dir, istate, dirname, len,
	 */
	int varint_len;
static void trim_trailing_spaces(char *buf)
			invalidate_gitignore(dir->untracked, untracked);
			   strlen(untracked->untracked[i]) + 1);

	if (!is_null_oid(&untracked->exclude_oid)) {
	 */
	memset(&cdir, 0, sizeof(cdir));
	case DT_LNK:
 * "file").
			    struct untracked_cache_dir *untracked,
	 *
		return NULL;
 * Used to set up core.excludesfile and .git/info/exclude lists.
		goto out;
	const unsigned offset = sizeof(struct ondisk_untracked_cache);
	 * If this is an excluded directory, then we only need to check if
	if (len < 0)
		    resolve_dtype(cdir.d_type, istate, sb.buf, sb.len) == DT_DIR &&
						    const char *name, int len)
		}
			return 0;
struct untracked_cache *read_untracked_extension(const void *data, unsigned long sz)
			nested_repo = is_nonbare_repository_dir(&sb);
	if (index_dir_exists(istate, dirname, len))
 *    -1 when the OID is invalid or unknown or does not refer to a blob.
	 */
		/* name doesn't match up to the first wild character */
int dir_inside_of(const char *subdir, const char *dir)
/*
 *
		    !fspathncmp(pattern + 1,

	if (!ce_skip_worktree(istate->cache[pos]))
	rd->data += the_hash_algo->rawsz;
		}
		if (current < 0) {
	if (untracked->check_only)
			 const struct pathspec *pathspec)

 */
{
}
	wd.index      = 0;
	ewah_free(wd.check_only);
	 * which originate from directories not in the prefix of the
 * Given two normalized paths (a trailing slash is ok), if subdir is
static int fnmatch_icase_mem(const char *pattern, int patternlen,
	ident_len = decode_varint(&next);
	hashcpy(ud->exclude_oid.hash, rd->data);
	DIR *fdir;
int count_slashes(const char *s)
{
}
 *                              Pathspecs
			break;
		if (pattern->flags & PATTERN_FLAG_NODIR) {
}

		do_invalidate_gitignore(dir->dirs[i]);
				break;
	/* Skip traversing into sub directories if the parent is excluded */
		group = &dir->exclude_list_group[i];
	if (string[stringlen]) {
{
}

static int cmp_icase(char a, char b)
				; /* no content change, ss->sha1 still good */
				    pathspec);

	wd.sha1_valid = ewah_new();
	 * to check that part. Be defensive and check it anyway, in
	}
			goto clear_hashmaps;
	strbuf_complete(path, '/');
{

	    !match_pathspec_attrs(istate, name, namelen, item))
			return rmdir(path->buf);
			/*
		 * order, though, if you do that.
 * untracked_cache_dir of "foo" that "bar/" is not an untracked
		       PATHSPEC_MAXDEPTH |
	struct untracked_cache_dir *untracked;

		 * match an exclude pattern and 2) this directory does
		strbuf_add(&sb, path, baselen);
		strbuf_addf(&sub_wt, "%s/%s", sub_worktree, sub->path);
	stat_data_from_disk(&ud->stat_data, rd->data);
	 */
	 * Calculate common prefix for the pathspec, and
	 * support could make the matter even worse.
#include "pathspec.h"
 * checking for the untracked entry named "bar/" in "foo", but for now
		strbuf_add(&subdir, path+prevlen, baselen-prevlen);
	struct exclude_stack *stk;
{
		   const char *pattern, int prefix, int patternlen,
					strlen(submodule_name),
		if (!ps_strncmp(item, item->match, path, len))
	/* should be the same flags used by git-status */
	 */
	const char *rest = strchr(path, '/');
		if (fd < 0)
			goto increment;
		 int baselen, struct pattern_list *pl, int srcpos)
		int cmp, next = first + ((last - first) >> 1);
		     * If we know that no files have been added in
	struct strbuf subdir = STRBUF_INIT;
static void set_check_only(size_t pos, void *cb)
	pattern->flags = flags;
				last_space = p;

{
	if (!ucd)
				 !ce_stage(istate->cache[pos]) &&
	return res;
				res = pattern;



	int nr_files;
		    !(dir->flags & DIR_NO_GITLINKS)) {
}
		prep_exclude(dir, istate, path->buf, path->len);
	int pathlen = strlen(pathname);
}
			 * This path will either be 'path_excluded`
		if ((namelen < matchlen) &&
	for (i = EXC_CMDL; i <= EXC_FILE; i++) {
	group = &dir->exclude_list_group[EXC_DIRS];
	/* Validate $GIT_DIR/info/exclude and core.excludesfile */
{
	}
			if (i &&
	struct index_state *istate, const char *path, int len,
			exclude_matches_pathspec(path->buf, path->len,
			dir_add_ignored(dir, istate, path->buf, path->len);

			}
		free(stk);
	}
 * with.  A mark is left in the seen[] array for each pathspec element
		/* include every file in root */

{
		pattern = xmalloc(sizeof(*pattern));
					   const struct pathspec *pathspec)
	dir = opendir(path->buf);
		 * difference between DT_LNK and DT_REG
	int fd;

	strbuf_release(&pat_buf);
		 * twice.  Do not barf on such a mistake.
	free(cwd);
	strbuf_addbuf(out, &untracked->ident);
			break;
	while ((e = readdir(dir)) != NULL) {
	if (safe_create_leading_directories_const(gitfile_sb.buf))

				   strhash(translated->pattern));
	/* Update core.worktree setting */
	struct untracked_cache_dir *untracked;
	/*
			new_untracked_cache(istate);
				    struct pattern_list *pl)
 * which has a char length of baselen.
	const char *prev, *cur, *next;
		hashmap_remove(&pl->parent_hashmap, &translated->ent, &data);
 * Say the "foo/bar/file" has become untracked, we need to tell the
	}
		}
	if (data > end)
 *
	int i;
		free_untracked_cache(istate->untracked);
				how = MATCHED_EXACTLY;
}
		slash_pos = strrchr(buffer->buf, '/');
		return UNDECIDED;
	 * user does not want XYZ/foo, only the "foo" part should be

		buf[size++] = '\n';
	 * dir->untracked is assigned. That function behaves
		free(pl->patterns[i]);
	 * many locations, so just take care of the first one.
	 * introduced that does not use common_prefix_len.
{
			*slash = '\0';
	 * ":(icase)path" is treated as a pathspec full of
	if (ignore_case)
		unsigned char c = *match++;

			return 1;

	if (is_dir_sep(dir[-1]))
}

		const struct pathspec_item *item = &pathspec->items[i];

				oid_stat->valid = 1;
		if (item->nowildcard_len < item->len &&
	/* Prepare .git file */
		       PATHSPEC_ICASE |
	if (path->len && path->buf[path->len - 1] != '/') {
	char *git_dir, *work_tree;
				 * `stop_at_first_file` is passed when
		cdir->d_type = DTYPE(de);


		if (len > pathlen &&
	 * (2) P does not exist in the index, but there is P/Q in the index.
/**
		goto done;
	strbuf_addstr(buffer, path);
				hash_object_file(the_hash_algo, buf, size,
	 */

			    !match_stat_data_racy(istate, &oid_stat->stat, &st))
				return;

	strbuf_release(&sub_gd);
	 */
		if (read_in_full(fd, buf, size) != size) {
	}
 *		 Junio Hamano, 2005-2006

							 path.len, ud,
{
	/*
static size_t common_prefix_len(const struct pathspec *pathspec)

		break;

	to->sd_dev	  = htonl(from->sd_dev);
 *
		if (!S_ISGITLINK(ce->ce_mode))
}
	group = &dir->exclude_list_group[group_type];
	return pl;
{
	struct strbuf out;
	    *(set - 1) == '*' &&
	struct path_pattern *pattern =
		return NULL;
	free(pl->patterns);
	exclude_per_dir = (const char *)next + exclude_per_dir_offset;
};


				 * Ok, we have a match already.
		assert(stk->baselen == dir->basebuf.len);
 * Scan the given exclude list in reverse to see whether pathname
			free(translated);
	if (!dir)
		rd->data = rd->end + 1;
	return NULL;
		prev++;
		free(data);

		int other, found_dup;
			       const struct pathspec_item *item, int prefix,

			dir->pattern = last_matching_pattern_from_lists(dir,

	 * updates in read_directory_recursive().  See 777b420347 (dir:
{
				      int baselen,
	if (istate->untracked) {
	struct strbuf *path,

	close_cached_dir(&cdir);
 * should be ignored.  The first match (i.e. the last on the list), if

				 struct strbuf *pattern)
{

	}
		       pattern->base[pattern->baselen - 1] == '/');
				  string + string_len - pattern_len);

 * Return the length of the "simple" part of a path match limiter.
			struct pattern_list *pl, struct index_state *istate,
			goto increment;
void parse_path_pattern(const char **pattern,
 * Loads the exclude lists for the directory containing pathname, then
		     !(dir->flags & DIR_KEEP_UNTRACKED_CONTENTS)) {
		if (fspathncmp(pattern, name, prefix))
			return MATCHED_EXACTLY;
}
 */
					  struct index_state *istate,
		strbuf_addstr(path, e->d_name);
	}
			   struct untracked_cache_dir *untracked,
	if (prefix) {
			return -1;
	struct read_data *rd = cb;
static int do_match_pathspec(const struct index_state *istate,
	/* This is the "show_other_directories" case */
	 *
	for (i = EXC_CMDL; i <= EXC_FILE; i++) {
	if (len && name[len - 1] == '/')
	}
}
	if (base_len || (pathspec && pathspec->nr))
 *
						    pathspec, state);
		       PATHSPEC_LITERAL |
			 * Skip entries with the same name in different stages
			(dir->flags & DIR_SHOW_IGNORED_TOO) &&
		if (strncmp(ce->name, dirname, len))
{
	to->sd_ctime.nsec = htonl(from->sd_ctime.nsec);
	struct object_id *oid,
 * Given a name and a list of pathspecs, returns the nature of the

 *

		dir->untracked->ss_excludes_file = dir->ss_excludes_file;
		if (!is_directory(sb.buf))
				 * an ancestor directory has matched
	 * baselen does not count the trailing slash. base[] may or
			break;	/* continue? */
		     dir->untracked->dir_invalidated))
			 * This is an excluded directory and we are
		return;
		pattern += prefix;
	git_dir = real_pathdup(git_dir_, 1);
{
			continue;
	/* Prepare config file */
	strbuf_addch(&parent_pathname, '/');
int fspathncmp(const char *a, const char *b, size_t count)
	size_t size = 0;
	 * Previous git versions may have saved many NUL separated
	return treat_one_path(dir, untracked, istate, path, baselen, pathspec,
			return -1;
 *
		}
{
		}

	if (dir->untracked)
}
	for (i = 0; i < size; i++) {
			close(fd);
	return 0;
				  &parent_pathname)) {
		       PATHSPEC_GLOB |
		if (!(given->flags & PATTERN_FLAG_NEGATIVE)) {
		dir->exclude_stack = stk;
	/* Write .git file */
 * of patterns matches on 'pathname'.
	 *
			struct oid_stat *oid_stat)
				struct index_state *istate)
 * does not exist in "dir".

 *  - recurse into it
 * pathspec and seen[] array but with different name/namelen

	struct ewah_bitmap *sha1_valid; /* set if exclude_sha1 is not null */

					    0 /* do NOT special case dirs */))
{
		return dtype;
	 *    foo/bar/baz/

{
	if (hashmap_contains_parent(&pl->recursive_hashmap,
		strbuf_setlen(buffer, slash_pos - buffer->buf);
						    istate, &path, baselen,
		strbuf_reset(&sub_gd);
					  int baselen,
 *
			return -1;
	if (!cdir->fdir)


	 * 1. prefix = common_prefix_len(ps);
			cp++;
				die("oops in prep_exclude");
				len++;
	strbuf_add(&uc->ident, ident, ident_len);

	if (cdir->nr_files < cdir->untracked->untracked_nr) {


{
		if (!cp)
			res = pattern;
	struct utsname uts;

	strbuf_addstr(path, cdir->d_name);
						 "blob", &oid_stat->oid);
	 * WARNING WARNING WARNING:
	int ret = 0, original_len = path->len, len, kept_down = 0;
		if (!de) {
	if (ce && S_ISGITLINK(ce->ce_mode))
		*flags |= PATTERN_FLAG_NODIR;
	pattern->nowildcardlen = nowildcardlen;
		return NULL;
	while (stk) {

	c_path = path->len ? path->buf : ".";
	char *entry;
	const struct pattern_entry *ee2 =
		   &dir->untracked->ss_excludes_file.oid)) {
	struct strbuf sub_wt = STRBUF_INIT;
			seen[i] = MATCHED_FNMATCH;
	/*
		     other++) {
	struct ewah_bitmap *valid;
				    const char *base, int baselen,
	ewah_free(wd.valid);
	prep_exclude(dir, istate, pathname, basename-pathname);
		if (ps->recursive &&
		return path_none;
		if (is_dot_or_dotdot(e->d_name))
				   struct index_state *istate)
}
		    (dir->untracked->dir_opened ||
				      struct untracked_cache_dir *untracked,
	cdir->untracked = untracked;
		goto done2;
 */
}
}
			    check_dir_entry_contains(dir->entries[i - 1], dir->entries[j])) {
 out:
	MOVE_ARRAY(dir->dirs + first + 1, dir->dirs + first,
			dir->basebuf.buf[stk->baselen - 1] = '/';
		read++;
	if (repo_read_index(&subrepo) < 0)
	strbuf_addbuf(out, &wd.sb_stat);
			     const char *name, int namelen,
 */
				   pattern->base,

				     prefix, seen, flags);
	struct object_id submodule_head;
		oidclr(&oid_stat.oid);
			continue;
	return -1;
{
			if (!strcmp(pathspec->items[other].original,
	varint_len = encode_varint(wd.index, varbuf);
	}
		}
		warning(_("unrecognized pattern: '%s'"), given->pattern);
	struct strbuf path = STRBUF_INIT;
			if (!(dir->flags & DIR_HIDE_EMPTY_DIRECTORIES))
	 * path being checked.
				 "opendir: %u\n",
	strbuf_addf(&cfg_sb, "%s/config", git_dir_);
 *       when successful.
 *
	closedir(dir);
	for (i = 0; i < untracked->dirs_nr; i++)
#include "object-store.h"
	return d;
}
		ret = (!rmdir(path->buf) || errno == ENOENT) ? 0 : -1;
	 * prep_exclude will be called eventually on this directory,
	dtype = get_index_dtype(istate, path, len);

	const char *use_str = string;
	}
	}
			   ignore_case ?
	struct stat st;
	int i;
 * The caller typically calls this multiple times with the same
		if (ce->name[len] > '/')
			 */
 * have three distinct cases:
	invalidate_one_directory(uc, dir);
static void invalidate_gitignore(struct untracked_cache *uc,
	return path_recurse;
static enum path_treatment read_directory_recursive(struct dir_struct *dir,
	pl->patterns[pl->nr++] = pattern;
	char *truncated;
	 * untracked_nr or any of dirs[].recurse is non-zero, we
		 * did not rmdir() our directory.
			   the_hash_algo->rawsz);

	translated = xmalloc(sizeof(struct pattern_entry));
		}
	/* Always exclude indexed files */

static void stat_data_to_disk(struct stat_data *to, const struct stat_data *from)
	struct index_state *istate,
		for (j = 0; j < group->nr; j++) {
	 * Normally the caller (common_prefix_len() in fact) does
			if (name[len] == '/')
			goto increment;
		}
	name += prefix;

				oidcpy(&oid_stat->oid,
 */
 * That likely will not change.
		strbuf_addch(buffer, '/');
	}
	 * to "../". We may have xyz/foo _and_ XYZ/foo after #2. The
 * there is an actual git directory there or not (it might not
	invalidate_one_component(istate->untracked, istate->untracked->root,
	if (data > end)
		   dir->untracked_alloc);

		if (dir->exclude_per_dir &&
 *
/*

 * Check if a submodule is a superset of the pathspec
	}
}
	if (!istate->untracked) {
	 * are sure that new changes in the index does not impact the
 * detect these cases and avoid unnecessary invalidation, for example,
 * Optionally updates the given oid_stat with the given OID (when valid).
	} else {
				     untracked ? &oid_stat : NULL);
	if (cdir->ucd->check_only)
			return DT_UNKNOWN;
	char *p, *last_space = NULL;
		   const void *key)

static int treat_leading_path(struct dir_struct *dir,
	if (dir->exclude_per_dir != dir->untracked->exclude_per_dir &&
		if (!sub || !is_submodule_active(&subrepo, ce->name))
static void close_cached_dir(struct cached_dir *cdir)
{
{
	if (pattern[patternlen]) {
		}
	int check_only, int stop_at_first_file, const struct pathspec *pathspec);
				    pathspec->items[num].original))
		const char *path = git_path_info_exclude();
	for (i = pl->nr - 1; 0 <= i; i--) {
static int invalidate_one_component(struct untracked_cache *uc,
{
}
			item_len = pathspec->items[n].prefix;
		}
 */
{
	 * before setting dir->untracked!
void connect_work_tree_and_git_dir(const char *work_tree_,
{
		if (within_depth(name, namelen, 0, ps->max_depth))
				 dir->untracked->dir_invalidated,
	 * in front of it.
		data = xrealloc(data, st_add(sz, 1));
	int only_empty = (flag & REMOVE_DIR_EMPTY_ONLY);
	 *
		*nowildcardlen = len;

	else
			oid_stat->valid = 1;
 * significant path_treatment value that will be returned.
	}
			container_of(a, struct pattern_entry, ent);
	return do_read_blob(&istate->cache[pos]->oid, oid_stat, size_out, data_out);
	struct untracked_cache_dir **ucd;
	const char *base, int baselen,
		if (!d->recurse) {
		pattern = last_matching_pattern_from_list(pathname, pathlen, basename,
static int valid_cached_dir(struct dir_struct *dir,
	int nr_dirs;
	return match_status;
		untracked->untracked[i] = xmemdupz(data, eos - data);

		strbuf_add(&pat_buf, pattern, patternlen);
		return 1;
{
	next = given->pattern + 2;
}
			if (dir_state == path_untracked) {
{
{
	return 0;
		return exclude ? path_excluded : path_untracked;
	int i, j;
 */
	 * If we use .gitignore in the cache and now you change it to
	strbuf_addch(out, '\0'); /* safe guard for string lists */
	return uc;

	if (next != end) {
	ALLOC_GROW(group->pl, group->nr + 1, group->alloc);
{
			return index_gitdir;
static enum exist_status directory_exists_in_index(struct index_state *istate,

 * Return 1 for a match, 0 for not matched and -1 for undecided.
		/*
			}
			return 1;

		state = treat_path(dir, untracked, &cdir, istate, &path,
	memcpy(to, data, sizeof(*to));
		if (!ident_in_untracked(istate->untracked)) {
			if (stop_at_first_file) {

		     */
		/* Not a cone pattern. */
 * indicating the closest type of match that element achieved, so if
}

	int positive, negative;


	ud.recurse	   = 1;
			untracked =
	/*
		dir->nr = i;
		 * remaining pathname, surely it cannot match.
}
	}
	current = stk ? stk->baselen : -1;
	struct strbuf *out = &wd->out;
		    (!untracked || !untracked->valid ||
					    state);
		if (lstat(path->len ? path->buf : ".", &st)) {
		add_path_to_appropriate_result_list(dir, untracked, &cdir,
		return r;
			    struct strbuf *path,
				 * excluded file happened to be
 * return true, and we'll skip it early.
	repo_clear(&subrepo);
	pattern->patternlen = patternlen;

	return matched;
			istate->cache_changed |= UNTRACKED_CHANGED;
			continue;
static int add_patterns_from_buffer(char *buf, size_t size,
static int read_skip_worktree_file_from_index(const struct index_state *istate,
	struct read_data *rd = cb;
				if (cdir.fdir)
struct ondisk_untracked_cache {
		int prefix)
	/* Try to look it up as a directory */
	if (add_patterns(fname, "", 0, pl, NULL, oid_stat) < 0)
	char *buf;
	pos = -pos-1;
static enum path_treatment read_directory_recursive(struct dir_struct *dir,
	struct ewah_bitmap *check_only; /* from untracked_cache_dir */
		free(data);
{
	if (!dir)
			   (!unlink(path->buf) || errno == ENOENT)) {
	 */
				     prefix, seen,
		struct untracked_cache_dir *d = cdir->untracked;
			 * dir->basebuf gets reused by the traversal, but we
 * invalidating that directory is enough. No need to touch its
		group = &dir->exclude_list_group[i];
		if (found_dup)
			pl = &group->pl[j];
	hashmap_entry_init(&translated->ent,
 * user mistyped the nth pathspec.
	for (num = 0; num < pathspec->nr; num++) {
		}
			   strihash(p.pattern) :

		return wildmatch(pattern, string,
	}
		strbuf_addf(&sub_gd, "%s/modules/%s", sub_gitdir, sub->name);
	int n;
	 * commit adding this warning as well as the commit preceding it


		if (hashmap_contains_path(map, buffer))

	strbuf_add(out, untracked->exclude_per_dir, strlen(untracked->exclude_per_dir) + 1);
	if (flags & DO_MATCH_LEADING_PATHSPEC) {

			} else {
static void read_stat(size_t pos, void *cb)
	ouc->dir_flags = htonl(untracked->dir_flags);
		if (stk->baselen <= baselen &&
	*size_out = xsize_t(sz);

 *  (b) if it looks like a git directory, and we don't have
		/*
		pl->full_cone = 0;
		return -1;
{
	if (next + ident_len > end)
				  const char *pathname, int len)
 * to root. Otherwise we just invalidate the leaf. There may be a more
	*flags = 0;
	if (startup_info->have_repository) {
 * closest (i.e. most specific) match of the name to any of the
	to->sd_mtime.nsec = htonl(from->sd_mtime.nsec);
	 * the directory contains any files.
	}
		return;
					break;
		}
		use_pat = pat_buf.buf;
	int r;
		return dtype;
}

	for (i = 0; i < pathspec->nr; i++) {
	match_status = wildmatch(use_pat, use_str, flags);
	read_directory(dir, istate, prefix, prefix_len, pathspec);
 * Tells read_directory_recursive how a file or directory should be treated.
		   unsigned flags)
{
		       PATHSPEC_GLOB |
		      next + ouc_offset(info_exclude_stat),
	    fspathncmp(pathname, base, baselen))
	}

	rd.end	      = end;
 * (2) the pathspec string has a leading part matching 'name' ("LEADING"), or
{
	return dir_state;
		       PATHSPEC_EXCLUDE |

				 */
	strbuf_addstr(path, cdir->ucd->name);
				 (pos = index_name_pos(istate, fname, strlen(fname))) >= 0 &&
		return treat_path_fast(dir, untracked, cdir, istate, path,

 * "foo".
		return 0;
				found_dup = 1;
					   struct untracked_cache_dir *untracked,
int submodule_path_match(const struct index_state *istate,
	strbuf_setlen(&dir->basebuf, baselen);
	struct cached_dir cdir;
static int simplify_away(const char *path, int pathlen,
	struct strbuf pat_buf = STRBUF_INIT;
		/*
	 * but that's one more allocation. Instead just make sure
				read_directory_recursive(dir, istate, path.buf,
	return dir->entries[dir->nr++] = dir_entry_new(pathname, len);
 * Migrate the git directory of the given path from old_git_dir to new_git_dir.
{

	    strstr(given->pattern, "**")) {
		return DT_UNKNOWN;
	case index_directory:

				state = path_none;
		trace_printf_key(&trace_untracked_stats,
	stat_data_to_disk(&ouc->excludes_file_stat, &untracked->ss_excludes_file.stat);
		if (size == 0) {
	}
static enum path_treatment treat_path(struct dir_struct *dir,
	 */
{
	for (i = 0; i < untracked->untracked_nr; i++)
	const char *match = item->match + prefix;
 *   1. the path is mentioned explicitly in the pathspec
{
			 * the directory is not empty), or will be

	 * we should have excluded the trailing slash from 'p' too,
	unsigned int intlen, value;
		   const struct pathspec *ps,
	if (dir->pattern)
 * exclude rules in "pl".
	if (!given->flags && !strcmp(given->pattern, "/*")) {
				state = path_none;

	}
							    pathspec, state);
	return !strcmp(uc->ident.buf, get_ident_string());
			match_stat_data_racy(istate, &untracked->stat_data, &st)) {
	const unsigned char *next = data, *end = (const unsigned char *)data + sz;
			return MATCHED_RECURSIVELY_LEADING_PATHSPEC;
			struct strbuf sb = STRBUF_INIT;
	}
/*
	 * but it's called much later in last_matching_pattern(). We
static void free_untracked(struct untracked_cache_dir *ucd)
	 * also pick up untracked contents of untracked dirs; by default
	return cnt;
	while (current < baselen) {

	ud.untracked_alloc = value;
	ALLOC_GROW(pl->patterns, pl->nr + 1, pl->alloc);
		       PATHSPEC_ICASE |

		goto done;

							dtype, pl, istate);

			      cdir->d_type);

	const char *slash_pos;
	root = dir->untracked->root;
	struct pattern_list *pl;
 */
		if (pattern->flags & PATTERN_FLAG_MUSTBEDIR) {

	if (sz <= 1 || end[-1] != '\0')

	if (S_ISDIR(st.st_mode))
	 */
		*flags |= PATTERN_FLAG_MUSTBEDIR;
 * files, index knowledge etc..
	char *slash_pos;
#define DO_MATCH_LEADING_PATHSPEC (1<<2)
				given->pattern);
		cmp = strncmp(name, d->name, len);
					add_untracked(untracked, path.buf + baselen);
	    !git_fnmatch(item, match, name,
	 * 3. match_pathspec()
	struct untracked_cache_dir *ud = rd->ucd[pos];
		/*
		if (ps_matched[num])
	root->recurse = 1;

{
	int r;
					  const struct pathspec *pathspec,
	GUARD_PATHSPEC(ps,
	while (*read) {
			if (!max)
{
	struct pattern_entry p;
	to->sd_size	  = ntohl(to->sd_size);
	strbuf_init(&wd.sb_sha1, 1024);
		return;
	int match_status;
 * the exclude_stack.  Does not free dir itself.
	for (i = 0; i < pl->nr; i++)
	return name_compare(e1->name, e1->len, e2->name, e2->len);
			return 1;
		/* remove from dir->entries untracked contents of untracked dirs */
						 base + current,
			struct strbuf sb = STRBUF_INIT;


	    /* We don't support collecting ignore files */
	struct path_pattern *pattern;
				    const struct pathspec *pathspec)
				continue;
	namelen -= prefix;
{
	return retval;
	 */
	}
	 * Any updates to the traversal logic here may need corresponding

 *      untracked and / or ignored files.
 * ss_valid is non-zero, "ss" must contain good value as input.

	} else {

	char *result = xstrdup(pattern);
	if (rename(old_git_dir, new_git_dir) < 0)
		return;
		default:
			cp = strchr(base + current + 1, '/');
			 const struct pathspec *ps,
		       PATHSPEC_MAXDEPTH |
/* check if *out lexically strictly contains *in */
		      pathspec->items[num].original);
	for (i = 0; i < untracked->dirs_nr; i++) {

		       PATHSPEC_FROMTOP |
			if (read_directory_recursive(dir, istate, dirname, len,
	strbuf_release(&subdir);

		dir->untracked->ss_info_exclude = dir->ss_info_exclude;
	if (item->magic & PATHSPEC_GLOB)
#include "attr.h"
		 * .gitignore content until we absolutely need it in
 * When we find a directory when traversing the filesystem, we
}

	return len ? xmemdupz(pathspec->items[0].match, len) : NULL;
/*

					0, seen,

	to->sd_ctime.sec  = ntohl(to->sd_ctime.sec);
	exclude = is_excluded(dir, istate, path->buf, &dtype);
	struct dirent *e;
					      const char *path,
			   struct strbuf *path,
	const char *basename = strrchr(pathname, '/');
		*flags |= PATTERN_FLAG_ENDSWITH;
 * (3) the pathspec string is a wildcard and matches 'name' ("WILDCARD"), or
{
	if (!oideq(&dir->ss_info_exclude.oid,
	}
static void read_oid(size_t pos, void *cb)

	return result;
{
			break;

	strbuf_setlen(&parent_pathname, slash_pos - parent_pathname.buf);
				return NOT_MATCHED;
		break;
	size_t count  = 0;
			    struct index_state *istate,
	 *    * path_recurse, for all path components, we return true


			max = len;
				 struct untracked_cache_dir *dir)
struct pattern_list *add_pattern_list(struct dir_struct *dir,
	stat_data_from_disk(&oid_stat->stat, data);
	add_path_to_appropriate_result_list(dir, NULL, &cdir, istate,
	for (i = 0; i < ucd->dirs_nr; i++)

	dir->dirs_nr++;
 * an index if 'istate' is non-null), parse it and store the
		return NULL;
			value++;
 * reading - if the path cannot possibly be in the pathspec,
	case index_gitdir:
		ewah_set(wd->sha1_valid, i);

		return -1;
	rd.data	      = next;
}
		       PATHSPEC_FROMTOP |
}
	return (out->len < in->len) &&
		FLEXPTR_ALLOC_MEM(pattern, pattern, string, patternlen);
		ewah_set(wd->check_only, i);

	*size_out = 0;
	const char *exclude_per_dir;
	write_file(gitfile_sb.buf, "gitdir: %s",


 * how each pathspec matches all the names it calls this function
	 * (3) P does not exist in the index, and there is no P/Q in the index
			if (pattern->flags & PATTERN_FLAG_NEGATIVE)
			if (oid_stat) {
	if (ignore_case)
	if (lstat(path, &st))
		return ret;

			if (!last_space)
		}
		} else if (S_ISDIR(st.st_mode)) {

			return -1;
		return 0;
		const char *exclude = pattern->pattern;

	unsigned flags = is_dir ? DO_MATCH_DIRECTORY : 0;

		   relative_path(git_dir, work_tree, &rel_path));
	struct exclude_stack *stk = NULL;
	 * expensive to do.
					  struct untracked_cache_dir *untracked,
					  namelen, flags);

int is_inside_dir(const char *dir)
				  const char *path)
 */
	 * WARNING WARNING WARNING:

		current = stk->baselen;

		/* check how the file or directory should be treated */
		return path_none;
		if (dir->flags & DIR_SHOW_OTHER_DIRECTORIES)

	if (oid_stat) {
 * Returns the exclude_list element which matched, or NULL for
	if (ce) {
		    ps->max_depth == -1)
	struct strbuf sb_stat;
 * to understand the differences between 1, 2, and 4:
	int i;
	return 1;

{
					untracked, 1, exclude, pathspec);

	switch (directory_exists_in_index(istate, dirname, len-1)) {
		errors++;
		for (j = group->nr - 1; j >= 0; j--) {

		       PATHSPEC_ICASE |
}
	while ((stk = dir->exclude_stack) != NULL) {
	entry = buf;
		       PATHSPEC_EXCLUDE |
void write_untracked_extension(struct strbuf *out, struct untracked_cache *untracked)
}
				   pattern->flags)) {
	 * strings, so save NUL too for backward compatibility.
			break;
 * stat data from disk (only valid if add_patterns returns zero). If
				 * to return a consistent value
	if (hashmap_contains_path(&pl->parent_hashmap, &parent_pathname)) {
	if (!pathspec || !pathspec->nr)
		 * at the present we have to punt and say that it is a match,
	/* Different set of flags may produce different results */
 * [1] Only if DO_MATCH_DIRECTORY is passed; otherwise, this is NOT a match.
	switch (state) {
	*nowildcardlen = simple_length(p);
	increment:

		if (*read == '\\')
		 * the pathspec.  Since wildmatch doesn't have this capability
		cdir->untracked->recurse = 1;
	if (len && p[len - 1] == '/') {
	const struct dir_entry *e2 = *(const struct dir_entry **)p2;
	return string[simple_length(string)] == '\0';
{
			}
		   struct index_state *istate,
		 * Nobody actually cares about the
 * If "ss" is not NULL, compute SHA-1 of the exclude file and fill
		strbuf_addstr(path, cdir->file);
/*
	rd.index      = 0;
{
	else
		/* But a trailing '/' then '*' is fine */
			add_patterns(pl->src, pl->src, stk->baselen, pl, istate,

}
#include "refs.h"
		return path_untracked;
	ewah_serialize_strbuf(wd.valid, out);

 * git index contents and the flags passed into the directory
		/* skip escape characters (once) */
	static struct strbuf sb = STRBUF_INIT;
	}
 * Do not use the alphabetically sorted index to look up
 *      'no_gitlinks' set we treat it as a gitlink, and show it
};
}
/*
}
		       PATHSPEC_ATTR);
							    istate,
						 len - (component_len + 1));
	len = path->len;
	hashmap_free_entries(&pl->parent_hashmap, struct pattern_entry, ent);
	switch (dtype) {
			ret = 0;
{
		 */
	}
	pattern->pl = pl;
		return 0;
	 * as the global ignore rule files. Any other additions
		return 0;
	if (prefix > 0) {
	const unsigned char *eos;
	ALLOC_GROW(dir->untracked, dir->untracked_nr + 1,
	}
	enum path_treatment state, subdir_state, dir_state = path_none;

		else if ((dir->flags & DIR_SHOW_IGNORED_TOO) ||
				 path, strlen(path));
}
	struct untracked_cache *uc;
			strbuf_addstr(&sb, dir->exclude_per_dir);
	    strcmp(dir->exclude_per_dir, dir->untracked->exclude_per_dir))
	free(ucd);
	if (next + exclude_per_dir_offset + 1 > end)
		 * accurate matching to determine if the pathspec matches.
				    &parent_pathname))
	hashmap_entry_init(&p.ent,
	intlen = encode_varint(value, intbuf);
	namelen = baselen ? pathlen - baselen - 1 : pathlen;
			   DIR_COLLECT_IGNORED)))
		       PATHSPEC_ATTR);
	if (!ret && !keep_toplevel && !kept_down)
	strbuf_release(&cfg_sb);
	const char *c_path;
 * directory name, we always recurse into the directory to see
				struct pattern_list *pl,
		return 0;
		return 0;
		if (!exclude &&
	 * _exact_ matching on name[-prefix+1..-1] and we do not need
		stk->exclude_ix = group->nr;
	}
		set++;
			continue; /* happy, too */
	 * condition also catches running setup_standard_excludes()
				return;
		if (*prev == '\\')
		 * last_matching_pattern(). Be careful about ignore rule
struct dir_entry *dir_add_ignored(struct dir_struct *dir,
 * pathspecs.
		 * name has no wildcard, and it didn't match as a leading
			continue;
	/*
		return MATCHED_RECURSIVELY;
		invalidate_gitignore(dir->untracked, root);
{
				 ce_uptodate(istate->cache[pos]) &&
		return pattern->flags & PATTERN_FLAG_NEGATIVE ? 0 : 1;
{
static enum exist_status directory_exists_in_index_icase(struct index_state *istate,
	}
		}
		if (fnmatch_icase_mem(pattern, patternlen,
		int offset = name[namelen-1] == '/' ? 1 : 0;


		       PATHSPEC_FROMTOP |
	return a - b;
		else
	dir->dirs[first] = d;
		 * reading .gitignore content will be a waste.

	return dir->nr;
		struct path_pattern *pattern = pl->patterns[i];
		result = MATCHED_RECURSIVE;
		return path_none;
			subdir_state =
 *  - see it as a directory
	strbuf_setlen(path, baselen);
 */
	ewah_free(rd.valid);
		if (!endchar && S_ISGITLINK(ce->ce_mode))
	 * trimmed at #3.
int add_patterns_from_file_to_list(const char *fname, const char *base,

 * [2] Only if DO_MATCH_LEADING_PATHSPEC is passed; otherwise, not a match.
				trim_trailing_spaces(entry);
	len = strlen(path);
			continue;
	struct pattern_entry *translated;
	path_excluded,
}
		     dir->untracked->gitignore_invalidated ||
					   struct strbuf *path,
	int current;

				      struct strbuf *path,
		size_t i = 0, len = 0, item_len;
 * list of "interesting" pathspecs. That is, whether a path matched


	if (!ident_in_untracked(dir->untracked)) {
					const char *sub_gitdir)
		struct untracked_cache_dir *d = cdir->untracked->dirs[cdir->nr_dirs];
		cdir->file = d->untracked[cdir->nr_files++];
	free(git_dir);
	int i;
 * Case 3: if we didn't have it in the index previously, we
		/*
		*flags |= PATTERN_FLAG_NEGATIVE;
	return file_exists(path);
	load_oid_stat(&uc->ss_info_exclude,
						 pathspec)))
			    dir->pattern->flags & PATTERN_FLAG_NEGATIVE)
	struct exclude_list_group *group;
			char c = pathspec->items[n].match[i];
	strbuf_setlen(&dir->basebuf, current < 0 ? 0 : current);
		const struct cache_entry *ce = subrepo.index->cache[i];
		stk = prev;
		struct untracked_cache_dir *d =
		    uts.sysname);
/*
				 (item->magic & PATHSPEC_ICASE ? WM_CASEFOLD : 0));

	/* core.excludesfile defaulting to $XDG_CONFIG_HOME/git/ignore */

			read++;
	 */
				    struct untracked_cache_dir *dir,
		new_untracked_cache(istate);

int read_directory(struct dir_struct *dir, struct index_state *istate,
			last = next;
	dir->untracked_nr = 0;
			 * back-references its source file.  Other invocations
		return 0;
									istate,
	const struct pathspec *pathspec)
/*
					      path.buf + baselen,
	strbuf_add(out, untracked->ss_excludes_file.oid.hash, hashsz);

		return;
	size_t i, len;
		    !ps_strncmp(item, match, name, namelen))
		oidcpy(&oid_stat->oid, oid);
 */
	 */
static void set_untracked_ident(struct untracked_cache *uc)
	 */
{
	slash_pos = strrchr(parent_pathname.buf, '/');

{
	cdir.d_type = DT_DIR;

/*
		/* wildmatch has not learned no FNM_PATHNAME mode yet */
	}
		if ((state == path_recurse) ||
		 */
	struct strbuf cfg_sb = STRBUF_INIT;


		      * .. and .gitignore does not exist before
		stk = xcalloc(1, sizeof(*stk));
		break;
		endchar = ce->name[len];

	struct pattern_list *pl;
	case index_nonexistent:
	if (index_file_exists(istate, pathname, len, ignore_case))
	 * status. More work involved in treat_leading_path() if we
	return 0;
						      const struct pathspec *pathspec)

		 * directory itself as an ignored path).
	DIR *dir = opendir(path);

	 * directory_exists_in_index() returns index_nonexistent. We

		ce = istate->cache[pos++];
static void stat_data_from_disk(struct stat_data *to, const unsigned char *data)
int within_depth(const char *name, int namelen,
	to->sd_mtime.nsec = ntohl(to->sd_mtime.nsec);
			}
	if (!pl->nr)

	 * 2. prune something, or fill_directory
}
			if (seen && seen[i] < how)
				len = i + 1;
		return is_dir_sep(subdir[-1]) ? offset : -1;
	struct untracked_cache_dir *untracked;
		dir->exclude_stack = stk->prev;
	struct pattern_list *pl;
}

	if (dir->untracked) {
			memset(&untracked->stat_data, 0, sizeof(untracked->stat_data));
		if (pathspec->items[n].magic & PATHSPEC_EXCLUDE)
 *  Names   a/b/  | RECURSIVE |   EXACT   | LEADING[2]
			 * pattern.  (e.g. show directory as ignored
 * the specified path. This can happen if:
		    /*

static void new_untracked_cache(struct index_state *istate)
	slash_pos = strrchr(buffer->buf, '/');

			     int prefix, char *seen,
{
		strbuf_reset(&subdir);
			break;
	GUARD_PATHSPEC(pathspec,
{

}
 * have a few sub-cases:
	if (hashmap_contains_path(&pl->recursive_hashmap,
	if (!dir->basebuf.buf)

		if (cdir->fdir)
 * the file buffer.  Does not free pl itself.
 * Returns 1 if true, otherwise 0.
		first = next+1;
							    &sb, baselen,
	return prefix_len;
			 const char *path, int len)

		dir++;
		untracked->untracked_nr = 0;
#include "fsmonitor.h"
	struct read_data rd;
	const char *ident;
	free(work_tree);
	}
 * however, deleting or adding an entry may have cascading effect.
	to->sd_uid	  = htonl(from->sd_uid);
	if (pos < 0)

				       baselen, NULL, DO_MATCH_LEADING_PATHSPEC) == MATCHED_RECURSIVELY_LEADING_PATHSPEC)) {
	if (!data || type != OBJ_BLOB) {
	last = dir->dirs_nr;

	struct stat_data excludes_file_stat;
{
		return DT_REG;
	if (fd < 0 || fstat(fd, &st) < 0) {
	if (!cdir->d_name)
	     * for the resolve_gitlink_ref() call, which we don't.
		/*
		       PATHSPEC_FROMTOP |
		while (i < item_len && (n == 0 || i < max)) {
	memset(&ud, 0, sizeof(ud));
		free((char *)pl->src); /* see strbuf_detach() below */
			 * showing ignored paths that match an exclude
			add_path_to_appropriate_result_list(dir, NULL, &cdir,
	for (;;) {
	prefix_len = common_prefix_len(pathspec);
	first = 0;

int no_wildcard(const char *string)

static const char *get_ident_string(void)
			if (entry != buf + i && entry[0] != '#') {
}
			return MATCHED_RECURSIVELY;
		cp = path + prevlen;
			}
	if (a == b)
			strbuf_addstr(&sb, dirname);
	 */
	hashmap_init(&pl->parent_hashmap, pl_hashmap_cmp, NULL, 0);
 *
					     baselen, NULL, DO_MATCH_LEADING_PATHSPEC) == MATCHED_RECURSIVELY_LEADING_PATHSPEC)))) {
		strbuf_init(&dir->basebuf, PATH_MAX);
				       baselen, pathspec);
{
{
	 * This strbuf used to contain a list of NUL separated
		}
		int pattern_len = strlen(++pattern);
			/*
	if (pathlen < baselen + 1 ||
		translated->patternlen = given->patternlen - 2;
						       int pathlen,
			i++;
	ewah_free(rd.sha1_valid);
 * Returns the most significant path_treatment value encountered in the scan.
int cmp_dir_entry(const void *p1, const void *p2)
	 */
	struct untracked_cache_dir *ucd;
}
	char *cwd;
	ud.untracked_nr	   = value;
	 * 2019-12-19) and its parent commit for details.
	const struct submodule *sub;
		const struct pathspec_item *item = &pathspec->items[i];
	}
		prevlen = baselen + !!baselen;
	uint32_t dir_flags;
 * Normally when an entry is added or removed from a directory,
	 * prefix part when :(icase) is involved. We do exact
		/* we already included this at the parent level */
	 * whether we should go into bar, then whether baz is relevant.
	for (i = 0, value = 0; i < untracked->dirs_nr; i++)
{
	}
		}
		dir->untracked->dir_opened++;
	enum object_type type;
		if (buf[i] == '\n') {
	*untracked_ = untracked = xmalloc(st_add3(sizeof(*untracked), eos - data, 1));

	struct untracked_cache_dir *root;
	len = ewah_read_mmap(rd.valid, next, end - next);
	return 0;
		struct exclude_stack *prev = stk->prev;

	if (!eos || eos == end)
{
		die_errno(_("failed to get kernel name and information"));

	while (len && path[len - 1] == '/')
	strbuf_reset(&uc->ident);
			struct read_data *rd)
		int i, j;
		namelen -= prefix;
		if (S_ISGITLINK(ce->ce_mode))
	 * .gitexclude, everything will go wrong.

	struct exclude_list_group *group;
	 * outcome. Return now.
{
		if (*prev == '/' &&
 *      as a directory.

		return;
	return remove_dir_recurse(path, flag, NULL);
}

	strbuf_setlen(path, original_len);
			if (*dtype != DT_DIR)
			else
static struct untracked_cache_dir *validate_untracked_cache(struct dir_struct *dir,
	rd->data += sizeof(struct stat_data);
			 * member of each struct path_pattern correctly

	if (uname(&uts) < 0)
	     * this flag, we may need to also cache .git file content
				dir_state = subdir_state;
	else if (kept_up)
	struct strbuf sb = STRBUF_INIT;
 */
		untracked = stk ? stk->ucd : dir->untracked->root;
			   ignore_case ?
				     struct oid_stat *oid_stat)


		 */
	positive = do_match_pathspec(istate, ps, name, namelen,
			      struct index_state *istate,
	}
	struct dirent *de;
				   baselen, pathspec);
	untracked_cache_invalidate_path(istate, path, 1);
		goto clear_hashmaps;
		for (i = j = 0; j < dir->nr; j++) {
	}
			 * to make sure an entry is returned only once.
			break;
	struct write_data wd;
		 * if the non-wildcard part is longer than the
		strbuf_addch(path, '/');
	struct stat st;
	return 0;
		} while (rmdir(dirs) == 0 && (slash = strrchr(dirs, '/')));
{


				      struct index_state *istate,
{
/*
 *      just a directory, unless "hide_empty_directories" is
 */
			 * of add_pattern_list provide stable strings, so we
		    *next == 0)
	const char *dirname, int len, int baselen, int exclude,
			ps_strcmp(item, pattern,
		    (match[namelen-offset] == '/') &&

			close(fd);
	set_untracked_ident(uc);
						   const char *dirname, int len)
	enum path_treatment path_treatment;
	if (matchlen <= namelen && !ps_strncmp(item, match, name, matchlen)) {
	 * other words, we do not trust the caller on comparing the
	int i;
/*
void add_pattern(const char *string, const char *base,
		if (!cmp && strlen(d->name) > len)
		die(_("index file corrupt in repo %s"), subrepo.gitdir);
		return dtype;
	ident = (const char *)next;
	 */
		 * will first be called in valid_cached_dir() then maybe many
	 * in non-:(icase).
{
	int i, retval = 0, exclude = flags & DO_MATCH_EXCLUDE;
		if (!is_dot_or_dotdot(e->d_name)) {
	struct untracked_cache_dir ud, *untracked;
					DO_MATCH_DIRECTORY |
static int resolve_dtype(int dtype, struct index_state *istate,
 * Loads the exclude lists for the directory containing pathname, then
	while (1) {
/*
				dir->pattern = NULL;
	 * We get path_recurse in the first run when
		   match[matchlen - 1] == '/' &&
{
				break;
	translated->pattern = dup_and_filter_pattern(given->pattern);
static void invalidate_directory(struct untracked_cache *uc,
 * Copyright (C) Linus Torvalds, 2005-2006
{
		if (endchar == '/')
/*
	int ret = 1;
			if (subdir_state > dir_state)
				/*
	}
 *

		return 0;
		close(fd);
		 * to its bottom. Verify again the same set of directories
	pl = add_pattern_list(dir, EXC_FILE, fname);

}
	/* Read from the parent directories and push them down. */
	int i;
	if (dir->unmanaged_exclude_files)
		   !ps_strncmp(item, match, name, namelen))
	if (*dir && *subdir)
	const char *use_pat = pattern;

		warning_errno(_("could not open directory '%s'"), c_path);
}
	return DT_UNKNOWN;
			dir_add_name(dir, istate, path->buf, path->len);
		if (exclude &&
				return MATCHED;
		if (seen && ps->items[i].magic & PATHSPEC_EXCLUDE)
			return 1;
 * indicates that a file was encountered that does not depend on the order of


		      next + ouc_offset(excludes_file_stat),

		path_treatment = treat_directory(dir, istate, untracked,
{
	 * case common_prefix_len is changed, or a new caller is
	load_oid_stat(&uc->ss_excludes_file,
	struct cached_dir cdir;
	stk = dir->exclude_stack;
	dir->exclude_per_dir = ".gitignore";
	if (ignore_case)
		return NULL;
		strbuf_reset(&sb);
		if (ce->name[len] < '/')
	/* NUL after exclude_per_dir is covered by sizeof(*ouc) */
static struct path_pattern *last_matching_pattern_from_list(const char *pathname,
				retval = how;


		const int len = sizeof(*dir->untracked->root);
		for (found_dup = other = 0;
						       const char *basename,
				 WM_PATHNAME |

		      next + offset);
		connect_wt_gitdir_in_nested(work_tree, git_dir);
	if (!excludes_file)
		}

		const char *pathname, int pathlen,
			if (match_basename(basename,
		    ( exclude && !(ps->items[i].magic & PATHSPEC_EXCLUDE)))
		/*
	 */
	FLEX_ALLOC_MEM(d, name, name, len);
}
		}

		if (untracked->dirs[i]->recurse)
}
			 item->nowildcard_len - prefix))
		strbuf_add(out, untracked->untracked[i],
	 * entries. Mark it valid.
				   exclude, prefix, pattern->patternlen,

	strbuf_add(out, intbuf, intlen);
int file_exists(const char *f)
		BUG("do not know how to check file existence in arbitrary repo");
	int matchlen = item->len - prefix;
	dtype = resolve_dtype(dtype, istate, path->buf, path->len);
/*
		p++;
{

		}
		ALLOC_ARRAY(ud.untracked, ud.untracked_nr);
		return NULL;
						 path->buf, path->len,
							 const char *dirname, int len)
				 * signal that a file was found by
		const char *basename, int *dtype_p)
#include "config.h"
int add_patterns_from_blob_to_list(
}

static void prep_exclude(struct dir_struct *dir,
 * (1) the pathspec string is leading directory of 'name' ("RECURSIVELY"), or
	for (i = 0; i < pathspec->nr; i++) {
			 */

	index_nonexistent = 0,
	const char *file;
		return MATCHED_RECURSIVELY_LEADING_PATHSPEC;
/*
 * Given a file with name "fname", read it (either from disk, or from
				     struct untracked_cache_dir *ucd)
static void add_pattern_to_hashsets(struct pattern_list *pl, struct path_pattern *given)
		flags |= WM_CASEFOLD;
		if (dir->untracked != istate->untracked) {

	int nested_repo = 0;
			 * not showing empty directories).
		 * make sure untracked cache code path is disabled,
			 ((dir->flags & DIR_SHOW_IGNORED_TOO) ||
	if (!dir)
	to->sd_ctime.sec  = htonl(from->sd_ctime.sec);
 * Append a trailing LF to the end if the last line doesn't have one.
			lookup_untracked(uc, dir, path, component_len);

		 * e.g. prep_exclude()
			/* abort early if maximum state has been reached */
done:
}
			return 0;

			}
	/*

 * Read the contents of the blob with the given OID into a buffer.
	int stop_at_first_file, const struct pathspec *pathspec)
	 * We have gone through this directory and found no untracked
	pattern->srcpos = srcpos;
		invalidate_directory(dir->untracked, untracked);
	next = rd.data;
static int match_pathspec_item(const struct index_state *istate,
				       const char *path)
	strbuf_add(out, ouc, sizeof(*ouc));
				   patternlen - 1))
}
	case DT_DIR:
	     * See treat_directory(), case index_nonexistent. Without
	prevlen = 0;
		cdir->ucd = d;
			continue;

		     !found_dup && other < pathspec->nr;
	strbuf_add(out, untracked->name, strlen(untracked->name) + 1);
	 * If the return from treat_path() is:
 * Read a directory tree. We currently ignore anything but
	 */
	struct pattern_list *pl)
 *
		    (dir->flags & DIR_SHOW_IGNORED_TOO ||
	int prevlen, baselen;
			return -1;
		case '\\':
	}
	path_untracked
		return;
}
	if (repo_init(&subrepo, sub_gitdir, sub_worktree))
 * to signal that a file was found. This is the least significant value that
	}
	if (!dir->untracked)
		truncated = dup_and_filter_pattern(given->pattern);
	struct path_pattern *pattern;
 */
			i++;
	 * Invalidation increment here is just roughly correct. If
	/*
	if (pattern)
		 */
	 * there are three cases:
 * scans all exclude lists to determine whether pathname is excluded.
				 WM_PATHNAME) == 0;
 * This function traverses all directories from root to leaf. If there
	hashmap_init(&pl->recursive_hashmap, pl_hashmap_cmp, NULL, 0);
}
int simple_length(const char *match)

	struct stat_data stat_data;
	while (slash_pos > buffer->buf) {
		if (force_untracked_cache < 0)

			return 0;
			 */
	len = strlen(p);
		}
	} else if ((flags & DO_MATCH_DIRECTORY) &&

	return index_nonexistent;
		if (force_untracked_cache &&
	 * For each directory component of path, we are going to check whether
		       PATHSPEC_ATTR);
static int exclude_matches_pathspec(const char *path, int pathlen,
			return path_recurse;
{
					    &sb, baselen, pathspec,
		 */
			strbuf_release(&sb);
			cdir->d_name = NULL;
			close(fd);
	struct exclude_list_group *group;
		break;
		      * loading .gitignore, which would result in

	/*
	 * memset(dir, 0, sizeof(*dir)) before use. Changing all of
 *
		return;
			     const char *string, int stringlen,
	if (next > end || len == 0)
	 * If the penalty turns out too high when prefix is really
		if (len <= baselen)
		 */
			if (!cp)
			if (dir->pattern) {
		goto done2;
	}
			int pos;
		      * (i.e. null exclude_oid). Then we can skip
		case ' ':
}
	struct read_data *rd = cb;
					   struct cached_dir *cdir,
		return string_len < pattern_len ||
{
	if (safe_create_leading_directories_const(cfg_sb.buf))
		    item->match[pathlen] == '/' &&
			*kept_up = 1;
		       PATHSPEC_EXCLUDE);
	char *data;
				   basename + basenamelen - (patternlen - 1),
		strbuf_add(&sb, path, prevlen);



 *
{
 * doesn't handle them at all yet. Maybe that will change some
	}

	return sb.buf;
		free(data);
	add_patterns_from_buffer(buf, size, base, baselen, pl);

	}
		hashmap_entry_init(&translated->ent,
int match_pathname(const char *pathname, int pathlen,
			old_git_dir, new_git_dir);
				 name, namelen,
		}
	unsigned long sz;
	int i = wd->index++;
	struct stat st;
				 dir->untracked->dir_opened);

	int nowildcardlen;

		(out->name[out->len - 1] == '/') &&
	 * The normal call pattern is:
	int first, last;
	struct untracked_cache_dir *untracked,
{
	while (pos < istate->cache_nr) {
		return sb.buf;
 * all the files.

				return path_excluded;
	intlen = encode_varint(untracked->untracked_nr, intbuf);
		    !strncmp(dir->basebuf.buf, base, stk->baselen))
		/* Not a cone pattern. */
static struct path_pattern *last_matching_pattern_from_lists(
				      const char *pathname, int len)
						      int base_len,
void clear_directory(struct dir_struct *dir)
	    given->flags & PATTERN_FLAG_MUSTBEDIR &&
	if (read_one_dir(&uc->root, &rd) || rd.index != len)
		untracked->check_only = 0;
	 * know that everything inside P will not be killed without
 * a directory (which is defined not as an entry, but as
		if (!ps->recursive ||
	while (pos < istate->cache_nr) {
		}
		if (patternlen == basenamelen &&

	 * strncmp(match, name, item->prefix - prefix)
	/* hel[p]/me vs hel[l]/yeah */
 * If 'stop_at_first_file' is specified, `path_excluded` is the most
	if (dtype != DT_UNKNOWN)
				git_env_bool("GIT_FORCE_UNTRACKED_CACHE", 0);
}
 *     0 when the blob is empty.
 * pathspecs.
	uc->exclude_per_dir = xstrdup(exclude_per_dir);
		 * do not need to call fnmatch at all.
	for (i = 0; i < ucd->untracked_nr; i++)
	free(rd.ucd);
	while (last > first) {
	struct untracked_cache_dir *d;
 * "foo/" instead. Which means we have to invalidate past "bar" up to
		add_patterns_from_file_1(dir, excludes_file,
#include "cache.h"
	}
	if (untracked_cache_disabled)
 * matched, or NULL for undecided.
		return 0;

{

 */
			   strhash(p.pattern));
	trace_performance_leave("read directory %.*s", len, path);
			return index_directory;
#include "dir.h"

		   dir->dirs_nr - first);
done2:
	struct untracked_cache_dir *untracked, int check_only,

	 *    * path_none, for any path, we return false.
	while (!read_cached_dir(&cdir)) {
			cdir->nr_dirs++;
		return 0;
		if (!istate)
	prefix = prefix_len ? pathspec->items[0].match : "";
	untracked_cache_invalidate_path(istate, path, 1);
			       item->nowildcard_len - prefix))
			break;
			return keep_toplevel ? -1 : 0;
	if (*pattern == '/') {
		    is_glob_special(*next))
		memset(&oid_stat->stat, 0, sizeof(oid_stat->stat));
		cdir->untracked->valid = 1;
	if (dtype != DT_UNKNOWN)
	}
{
	pl->filebuf = buf;
		dir->unmanaged_exclude_files++;
		return directory_exists_in_index_icase(istate, dirname, len);
		die_errno(_("could not migrate git directory from '%s' to '%s'"),
	int cnt = 0;
}
	len = ewah_read_mmap(rd.sha1_valid, next, end - next);
				   pattern->baselen ? pattern->baselen - 1 : 0,
}
						 dir->untracked ? &dir->ss_info_exclude : NULL);
		if (untracked &&
			return ((dir->flags & DIR_SKIP_NESTED_GIT) ? path_none :
/*
	 *        signifying that we shouldn't recurse into it.
	int num, errors = 0;
				 * In current usage, the
{
		 * potentially returning a false positive
 * any, determines the fate.  Returns the exclude_list element which
		return 0;

		if (!patternlen && !namelen)
{
	pos = index_name_pos(istate, path, len);
 */
	pattern->base = base;

	const char *d_name;
		while (i + 1 < subrepo.index->cache_nr &&
	free(ucd->dirs);
		return index_gitdir;
		return DT_REG;
 *   2. the path is a directory prefix of some element in the
		 * modified on work tree), we could delay reading the

	/*
		read_directory_recursive(dir, istate, path, len, untracked, 0, 0, pathspec);
	 * catch setup_standard_excludes() that's called before
	if (given->flags & PATTERN_FLAG_NEGATIVE &&
		hashmap_add(&pl->parent_hashmap, &translated->ent);
	uc->gitignore_invalidated++;
		if (!cmp)
	struct dirent *e;
}

	static int untracked_cache_disabled = -1;
		return path_none;
			 * An empty dir could be removable even if it
		int prefix = pattern->nowildcardlen;
				      int group_type, const char *src)
	}

 *
		rd->data = rd->end + 1;
		       PATHSPEC_ICASE |
		   const struct hashmap_entry *b,
	if (!istate->untracked || !istate->untracked->root)

	}
	return 1;
					   pattern->flags)) {
		state = treat_path(dir, NULL, &cdir, istate, &sb, prevlen,
	const char *cp;
		 * So when it's called by valid_cached_dir() and we can get

		error(_("pathspec '%s' did not match any file(s) known to git"),

	}
		if (!untracked->valid ||
		pattern->pattern = string;
	return ret;
				&group->pl[j], istate);
 *     1 along with { data, size } of the (possibly augmented) buffer
	 * case-insensitive. We need to filter out XYZ/foo here. In
	*data_out = data;
	}

	if ((dir->flags & DIR_COLLECT_KILLED_ONLY) &&

 */
			free_untracked_cache(istate->untracked);
{
	struct strbuf gitfile_sb = STRBUF_INIT;
static GIT_PATH_FUNC(git_path_info_exclude, "info/exclude")
	strbuf_release(&dir->basebuf);
			invalidate_one_component(uc, d, rest + 1,
	return ret;
		const char *pattern, const char *string,
 *
	add_patterns_from_buffer(buf, size, base, baselen, pl);
	/*
		oid_stat.valid = 0;
}
int remove_dir_recursively(struct strbuf *path, int flag)
		return NULL;

		hashmap_remove(&pl->recursive_hashmap, &translated->ent, &data);
	ALLOC_GROW(dir->dirs, dir->dirs_nr + 1, dir->dirs_alloc);
	if (cdir->fdir) {
			    const char *path,
	 */
 * sophisticated way than checking for SHOW_OTHER_DIRECTORIES to

static int add_patterns_from_buffer(char *buf, size_t size,
	if (!pl->use_cone_patterns) {
	}

static int remove_dir_recurse(struct strbuf *path, int flag, int *kept_up)
	index_gitdir
{


	FREE_AND_NULL(ouc);
		/*
	add_pattern_to_hashsets(pl, pattern);
		return -1;


	for (i = 0; i < dir->dirs_nr; i++)
/*
static int read_one_dir(struct untracked_cache_dir **untracked_,
 *
			return DT_DIR;
		       PATHSPEC_GLOB |
		if (patternlen - 1 <= basenamelen &&
	return last_matching_pattern_from_lists(dir, istate, pathname, pathlen,
		return NULL;
{
	next += len;
			break;
		}
	uc->dir_flags = get_be32(next + ouc_offset(dir_flags));
 */

	free(ucd->untracked);
	 *
#include "utf8.h"
	return dtype;
			 ? ee1->patternlen
 * Returns:
		    ps->max_depth != -1 &&
		pos = -pos-1;
			     const struct pathspec *ps,
		}
		 * The submodules themselves will be able to perform more
		if (stk->baselen) {
		if (cmp < 0) {
		goto done;
	struct untracked_cache *uc = xcalloc(1, sizeof(*uc));
{
		else
		return NULL;
	 * 'prefix' at #1 may be shorter than the command's prefix and
				     dirname + baselen, len - baselen);
	if (!index_name_is_other(istate, pathname, len))
	int matched = do_match_pathspec(istate, ps, submodule_name,
	const char *name;
}
		if (ret)

	varint_len = encode_varint(untracked->ident.len, varbuf);
	if (pos < 0)
	 * need it now to determine the validity of the cache for this
			int depth, int max_depth)
	ud->check_only = 1;
int report_path_error(const char *ps_matched,
		assert(pattern->baselen == 0 ||
	struct stat_data info_exclude_stat;
	size_t prefix_len;
}
/*

	ewah_free(wd.sha1_valid);
/*
		int len = item->nowildcard_len;
			return MATCHED_EXACTLY;
 *
	for (p = buf; *p; p++)
				pathname, pathlen, basename, dtype_p,
	 * them seems lots of work for little benefit.
{

}
		use_str = str_buf.buf;
 * by any of the pathspecs could possibly be ignored by excluding
				 "directory invalidation: %u\n"
	if (dir->flags != dir->untracked->dir_flags ||
 * Loads the per-directory exclude list for the substring of base
	dir->untracked[dir->untracked_nr++] = xstrdup(name);
	 * synchronize treat_leading_path() and read_directory_recursive(),
			  struct write_data *wd)


	/*
		    (dir->flags & DIR_SHOW_IGNORED_TOO) &&
	return 0;
	if (rd->data + sizeof(struct stat_data) > rd->end) {
			 : ee2->patternlen;
	/* Make sure this directory is not dropped out at saving phase */
	struct ewah_bitmap *sha1_valid;
	}
}
				 item->magic & PATHSPEC_ICASE ? WM_CASEFOLD : 0);
	strbuf_add(out, intbuf, intlen);
	pl = &group->pl[group->nr++];
	hashmap_add(&pl->recursive_hashmap, &translated->ent);
		 * If 1) we only want to return directories that
		}
 *          a/b/c | RECURSIVE | RECURSIVE |   EXACT
}
	/* The "len-1" is to strip the final '/' */

	const unsigned exclude_per_dir_offset = offset + 2 * hashsz;

		return;
	 * then we need to check .git to know we shouldn't traverse it.
			force_untracked_cache =
		uc = NULL;
			return 1;
			continue;
	}
}
		if (!ce_uptodate(ce))
static struct untracked_cache_dir *lookup_untracked(struct untracked_cache *uc,
	if (!len)
				 "node creation: %u\n"
		dir->untracked = NULL;
	return 0;
		if ((!exclude &&   ps->items[i].magic & PATHSPEC_EXCLUDE) ||
		return NULL;	/* undefined */
enum exist_status {
done:
#define ouc_offset(x) offsetof(struct ondisk_untracked_cache, x)

			/* fallthrough */
		*last_space = '\0';
static int add_patterns(const char *fname, const char *base, int baselen,
	if (count > 2 &&
		do {
				}
		 * duplicate pathspec.
	    *(set - 2) == '/')
		return read_directory_recursive(dir, istate, path->buf, path->len,
	int index;

{
	while (cdir->nr_dirs < cdir->untracked->dirs_nr) {
	}
		return !*dir ? offset : -1; /* same dir */

	if ((dir->flags & DIR_SHOW_IGNORED_TOO) &&

 * Returns a copy of the longest leading path common among all
 * Similarly, if "foo/bar/file" moves from untracked to tracked and it
		if (pattern) {
			if (errno == ENOENT)
 * traversal routine.
						 cp - base - current);
	strbuf_release(&wd.sb_sha1);
		if (c == '\0' || is_glob_special(c))
	 * We only support $GIT_DIR/info/exclude and core.excludesfile
	}
		return NULL;
			return 0;
		strbuf_add(out, varbuf, varint_len);
	strbuf_add(out, untracked->ss_info_exclude.oid.hash, hashsz);
	 * subdir 'xyz'. The common prefix at #1 will be empty, thanks
	if (!cdir->ucd) {
	struct path_pattern *res = NULL; /* undecided */
	default:
				 *
		free(group->pl);
 * If 'stop_at_first_file' is specified, 'path_excluded' is returned
	struct path_pattern *pattern;
 * Given a subdirectory name and "dir" of the current directory,
	value = decode_varint(&data);
 * means that a gitlink sorts as '\0' at the end, while

	do_invalidate_gitignore(dir);
void clear_pattern_list(struct pattern_list *pl)
	add_patterns_from_file_1(dir, fname, NULL);
		if (check_only) {
void relocate_gitdir(const char *path, const char *old_git_dir, const char *new_git_dir)
	if (prefix == patternlen) {
	 * ignored files, ignore it
}
		if (!is_glob_special(*cur))

	 * it's ok for #2 to match extra files. Those extras will be
	if (item->attr_match_nr &&

	if (excludes_file && !access_or_warn(excludes_file, R_OK, 0))
		return -1;
		static int force_untracked_cache = -1;

	rd.check_only = ewah_new();
	free(uc);
			 * 'path_none' (empty directory, and we are
		size -= buf - pl->filebuf;

	strbuf_addf(&sb, "Location %s, system %s", get_git_work_tree(),

 * Support data structure for our opendir/readdir/closedir wrappers
	slash = strrchr(name, '/');

			continue;
	/*
	if (!cdir->fdir)
		else
		} else if (!only_empty &&
	p.pattern = pattern->buf;
	to->sd_dev	  = ntohl(to->sd_dev);
			 (resolve_dtype(cdir.d_type, istate, path.buf, path.len) == DT_DIR) &&
		slash = dirs + (slash - name);
	if (!untracked->root) {

		return;
	 * match with FNM_PATHNAME; the pattern has base implicitly
	 * When we are looking at a directory P in the working tree,
 * is a chance of one of the above cases happening, we invalidate back
				break;
	if (dir->valid)
		dir->pattern = NULL;

				      0) == 0)
	 * for details.
			return 0;
	    (dtype == DT_DIR) &&

		return path_none;
			return WM_NOMATCH;
 * Does the given pathspec match the given name?  A match is found if
	return dir->ignored[dir->ignored_nr++] = dir_entry_new(pathname, len);
			 const char *path, int len);
		group->nr--;
	if (cdir->untracked) {
struct path_pattern *last_matching_pattern(struct dir_struct *dir,
	prev = given->pattern;
		 * "name" can be matched as a directory (or a prefix) against
			pl->src = strbuf_detach(&sb, NULL);
	warning(_("disabling cone pattern matching"));
	if (skip_utf8_bom(&buf, size))
		stk->baselen = cp - base;
	*patternlen = len;
			warning(_("unrecognized pattern: '%s'"), given->pattern);

	struct index_state *istate,
	if (len < 0)

		dir_add_name(dir, istate, path->buf, path->len);

			break; /* finished checking */
	end--;
{
}
		data[sz++] = '\n';
	DIR *dir;
	unsigned char varbuf[16];
			basename, dtype_p);
				   const char *git_dir_,
	while (cp < cpe) {
		return DT_DIR;
	int pos;

		else
		return 0;
	strbuf_setlen(path, baselen);
			goto increment;
	if (slash) {
					    0 /* prefix */, NULL,
	/*
		struct dir_struct *dir, struct index_state *istate,
		name    += prefix;
	if (next >= end)
	next = rd.data;
	/*
			dir->basebuf.buf[stk->baselen - 1] = 0;
int repo_file_exists(struct repository *repo, const char *path)
			return path_none;
static enum path_treatment treat_one_path(struct dir_struct *dir,
	if (!dir->untracked)
	ALLOC_ARRAY(rd.ucd, len);
 *      pathspec

			*dtype = resolve_dtype(*dtype, istate, pathname, pathlen);
	strbuf_addf(&gitfile_sb, "%s/.git", work_tree_);
		goto clear_hashmaps;
	basename = (basename) ? basename+1 : pathname;
	strbuf_init(&wd.sb_stat, 1024);
}
	int i;
	if (r != 1)

	pl->use_cone_patterns = 0;

	struct ewah_bitmap *valid;	/* from untracked_cache_dir */
		len--;
		 */
	ucd->untracked_nr = 0;
		free(stk);
		untracked_cache_disabled = git_env_bool("GIT_DISABLE_UNTRACKED_CACHE", 0);
	    !(dir->flags & DIR_SHOW_OTHER_DIRECTORIES) ||
		buf = xmallocz(size);

	const char *p = *pattern;
static int open_cached_dir(struct cached_dir *cdir,
		     * this directory (i.e. valid_cached_dir() has
			write_one_dir(untracked->dirs[i], wd);
				    const char *path, int len)
	if (sz == 0) {
	/* Check straight mapping */


	 * untracked_nr should be reset whenever valid is clear, but
			else
	/* Perform checks to see if "name" is a leading string of the pathspec */
 * This function tells us whether an excluded path matches a
	return 0;

						 baselen, exclude, pathspec);
	/* name/namelen has prefix cut off by caller */
		    !(ps->magic & PATHSPEC_MAXDEPTH) ||
#include "varint.h"
		untracked->check_only = !!check_only;
	if (dtype != DT_DIR && has_path_in_index)
}
			strbuf_addbuf(&sb, &dir->basebuf);
	case path_excluded:
				 * regardless of whether an ignored or
	    !resolve_gitlink_ref(path->buf, "HEAD", &submodule_head)) {
		 * then our prefix match is all we need; we
		const char *pathname, int *dtype_p)
			p++;
	 * Suppose the pathspec is 'foo' and '../bar' running from

			return r;
	if (uc)

			return 1;
		result = MATCHED;
		 * report the uplevel that it is not an error that we
				 */
		   int prefix, char *seen, int is_dir)
	 * We know P will stay a directory when we check out the contents

	cdir->fdir = opendir(c_path);
		strbuf_add(&dir->basebuf, base + current, stk->baselen - current);
}
void add_patterns_from_file(struct dir_struct *dir, const char *fname)
			if (within_depth(name+len, namelen-len, 0, ps->max_depth))
		    !oideq(&oid_stat.oid, &untracked->exclude_oid)) {


	flag &= ~REMOVE_DIR_KEEP_TOPLEVEL;
	}
			ud = lookup_untracked(dir->untracked, untracked,

			 * (if we are showing empty directories or if
	memset(cdir, 0, sizeof(*cdir));
 * (4) the pathspec string is exactly the same as 'name' ("EXACT").
}
	return;
}
 *
int fspathcmp(const char *a, const char *b)
				 */
			(dir->flags & DIR_SHOW_IGNORED_TOO_MODE_MATCHING)) {
	if (!(ps->magic & PATHSPEC_EXCLUDE) || !positive)
	unsigned char intbuf[16];
	/*
			  (pathspec &&
	if (!*match)
		prep_exclude(dir, istate, path->buf, path->len);
	}
 * pathspec did not match any names, which could indicate that the
	int has_path_in_index = !!index_file_exists(istate, path->buf, path->len, ignore_case);

		strbuf_add(&wd->sb_stat, &stat_data, sizeof(stat_data));

	struct cache_entry *ce;
	to->sd_gid	  = htonl(from->sd_gid);
		    !ps_strncmp(item, item->match, path, pathlen))
			/* .gitmodules broken or inactive sub */
						    struct untracked_cache_dir *dir,
			given->pattern);
	}
	}
	int i;
				continue; /* happy */
	work_tree = real_pathdup(work_tree_, 1);
		*kept_up = !ret;


	return fnmatch_icase_mem(pattern, patternlen,
			 struct index_state *istate,
 * excluded and untracked files, it is listed as untracked because
	strbuf_release(&parent_pathname);
		warning(_("unrecognized pattern: '%s'"), given->pattern);

	if (!*subdir)
 * ancestors. When a directory is shown as "foo/bar/" in git-status
			invalidate_one_directory(uc, dir);
			else if (istate &&
		if (ps_strncmp(item, pattern, string, prefix))
	/* Read the directory and prune it */
					DO_MATCH_LEADING_PATHSPEC);
static void load_oid_stat(struct oid_stat *oid_stat, const unsigned char *data,
			cp = base;
		size = xsize_t(st.st_size);
	 * With fsmonitor, we can trust the untracked cache's valid field.
			       const char *name, int namelen, unsigned flags)
			}
	QSORT(dir->ignored, dir->ignored_nr, cmp_dir_entry);
		switch (*p) {
	 * updates in treat_leading_path().  See the commit message for the

	strbuf_release(&gitfile_sb);
 * path_untracked > path_excluded.
 */
	 * If DIR_SHOW_IGNORED_TOO is set, read_directory_recursive() will
	if (!oideq(&dir->ss_excludes_file.oid,
struct read_data {

		untracked = NULL;


{
		stk->ucd = untracked;
			dir->untracked == istate->untracked &&
		excludes_file = xdg_config_home("ignore");
			     int flags)

			pattern = last_matching_pattern_from_list(
		}
}
		goto done;
			baselen = cp - path;

 */
	return 0;
	uc->exclude_per_dir = ".gitignore";

		     !is_null_oid(&untracked->exclude_oid))) {
			((state == path_untracked) &&
		*set = *read;
	refresh_fsmonitor(istate);

		len++;
	ent->len = len;
		if (n == 0 || len < max) {



 * end.
 *
	assert(dir && subdir && *dir && *subdir);
	strbuf_add(out, varbuf, varint_len);
		if (p[i] == '/')
	} else {
	*pattern = p;
			struct untracked_cache_dir *ud;
	*set = 0;
		goto done;

	 *
		free(translated);
	}

			break;
		cp = memchr(cp, '/', path + len - cp);
}
	 * for safety..
		return;
	*data_out = NULL;
		 * FIXME: parse_pathspec should have eliminated
			 * strbuf_detach() and free() here in the caller.
	const char *prefix;
	return ignore_case ? strncasecmp(a, b, count) : strncmp(a, b, count);
		if (state != path_recurse)
				    pathname,
		return path_treatment;
 *      also true, in which case we need to check if it contains any
			   int *patternlen,
			/*
	}
	if (given->flags & PATTERN_FLAG_NEGATIVE) {
};
	write_one_dir(untracked->root, &wd);
		struct oid_stat oid_stat;

	}

	to->sd_ctime.nsec = ntohl(to->sd_ctime.nsec);

	 * Any updates to the traversal logic here may need corresponding
 * scans all exclude lists to determine whether pathname is excluded.
#define DO_MATCH_EXCLUDE   (1<<0)

			return len;
		/* Try to read per-directory file */
 * we always continue to see it as a gitlink, regardless of whether

void remove_untracked_cache(struct index_state *istate)

	 * that path is relevant given the pathspec.  For example, if path is
		int component_len = rest - path;
}
 * be checked out as a subproject!)
	strbuf_add(&path, base, baselen);

	return index_nonexistent;
		die(_("cannot use %s as an exclude file"), fname);
}
}
	}
}
	 */
	while ((e = readdir(dir)) != NULL)
	 * we discard these, but given DIR_KEEP_UNTRACKED_CONTENTS we do not.
	strbuf_addbuf(out, &wd.out);
			 const char *submodule_name,

		count++;
	 * (1) P exists in the index.  Everything inside the directory P in
	struct untracked_cache_dir *untracked,
			 char *seen)
			size_t *size_out, char **data_out)
	dir->valid = 0;
		int string_len = strlen(string);

	unsigned long len = common_prefix_len(pathspec);
/*
	/* hopefully prep_exclude() haven't invalidated this entry... */
			 const char *base, int baselen)
		char *dirs = xstrdup(name);
	if (has_symlink_leading_path(path, len)) {
		if (how) {
				(exclude ? path_excluded : path_untracked));
		}
	const struct cache_entry *ce;
		return MATCHED_EXACTLY;
		/* "*literal" matching against "fooliteral" */
			if (i == EXC_DIRS)
	return state == path_recurse;
	strbuf_release(&rel_path);
	strbuf_release(&wd.sb_stat);


	 * comparison ourselves.
	if (last_space)
	 * should increment dir_invalidated too. But that's more
	}
			clear_pattern_list(pl);

	uc->dir_invalidated++;
	/*
	 * Checking each is important because e.g. if path is
			break;
static int hashmap_contains_path(struct hashmap *map,
	dir->unmanaged_exclude_files++; /* see validate_untracked_cache() */
		if (state > dir_state)
			continue;
		return path_excluded;
		if (untracked->dirs[i]->recurse)
	rd.sha1_valid = ewah_new();
			break; /* do not recurse into it */
		}
			warn_on_fopen_errors(fname);
		      const struct pathspec *pathspec)
				 dir->untracked->dir_created,

	for (i = 0; i < subrepo.index->cache_nr; i++) {
		     do_match_pathspec(istate, pathspec, sb.buf, sb.len,
{
}
	for (i = 0; i < len; i++) {
}
		return -1;
		int ret =

}
			continue;
 * directories, regular files and symlinks. That's because git
	data = eos + 1;
					   pathlen - (basename - pathname),
/*
			cmp = -1;
 * Values are ordered by significance, e.g. if a directory contains both
		       PATHSPEC_LITERAL |
	/*
	if (!untracked->valid) {

	if (!(dir->flags & DIR_HIDE_EMPTY_DIRECTORIES))
		warning(_("your sparse-checkout file may have issues: pattern '%s' is repeated"),

			fill_stat_data(&untracked->stat_data, &st);
				if (dir_state >= path_excluded) {
			if (!remove_dir_recurse(path, flag, &kept_down))
 * Return value tells which case it was (1-4), or 0 when there is no match.
			return 0;
		if (!access_or_warn(path, R_OK, 0))
	return uc->dir_flags & DIR_SHOW_OTHER_DIRECTORIES;
	negative = do_match_pathspec(istate, ps, name, namelen,
{
		return index_directory;
		       !strcmp(ce->name, subrepo.index->cache[i + 1]->name))
			      const char *path, int len,
}
		 * times more in last_matching_pattern(). When the cache is


	/* skip non-recurse directories */
		if (match_pathname(pathname, pathlen,
	connect_work_tree_and_git_dir(path, new_git_dir, 0);
	data = read_object_file(oid, &type, &sz);
	}
					      struct oid_stat *oid_stat)
}
	/* foo/[b]ar vs foo/[] */
	int d_type;
			   const char *path, int len)
	if (given->patternlen < 2 ||
 * stick to something safe and simple.

 */
	ewah_serialize_strbuf(wd.sha1_valid, out);
		free_untracked(uc->root);
				      struct index_state *istate,
	 * nowildcardlen does not exceed real patternlen
