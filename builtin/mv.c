		destination = dest_path;
	}
		} else if (string_list_has_string(&src_for_dst, dst))

			}
			else if (index_range_of_same_dir(src, length,
			printf(_("Checking rename of '%s' to '%s'\n"), src, dst);
		}
		if (flags & DUP_BASENAME) {
			bad = _("cannot move directory over file");
	flags = KEEP_TRAILING_SLASH;
#define DUP_BASENAME 1

		const char *src = source[i], *dst = destination[i];

	*submodule_gitfile = read_gitfile(submodule_dotgit.buf);
	}
				(dst[length] == 0 || dst[length] == '/')) {
{

					modes[argc + j] = INDEX;
					     const char **pathspec,
					const char *path = active_cache[first + j]->name;
						       submodule_gitfile + i);
		if (!ignore_errors)
#include "lockfile.h"
	}
		with_slash[len++] = '/';
		return with_slash;
static const char * const builtin_mv_usage[] = {
	size_t len = strlen(path);
	for (i = 0; i < argc; i++) {
	submodule_gitfile = xcalloc(argc, sizeof(char *));
			int first = cache_name_pos(src, length), last;
		}
		if (submodule_gitfile[i]) {
		if (show_only || verbose)
	 * Keep trailing slash, needed to let
				n * sizeof(char *));
				&& lstat(dst, &st) == 0)
		length = strlen(src);
				dst_len = strlen(dst);
			else { /* last - first >= 1 */
	if (first >= 0)
	for (i = 0; i < count; i++) {
			 (!ignore_case || strcasecmp(src, dst))) {
int cmd_mv(int argc, const char **argv, const char *prefix)

	dest_path = internal_prefix_pathspec(prefix, argv + argc, 1, flags);
{
		if (argc != 1)
		char *it;

			memmove(modes + i, modes + i + 1,
				REALLOC_ARRAY(destination, n);
				 * only files can overwrite each other:


}
		die(_("%.*s is in index"), len_w_slash, src_w_slash);
		if (mode != INDEX && rename(src, dst) < 0) {
		if (lstat(src, &st) < 0)

		memcpy(with_slash, path, len);
		if (!bad)
		}
		die(_("Directory %s is in index and no submodule?"), src);
		} else if (cache_name_pos(src, length) < 0)
	struct option builtin_mv_options[] = {
	/*
		assert(pos >= 0);
				 */
	if (write_locked_index(&the_index, &lock_file,
			die(_("%s, source=%s, destination=%s"),

			int n = argc - i;
		OPT__DRY_RUN(&show_only, N_("dry run")),
	strbuf_addf(&submodule_dotgit, "%s/.git", src);
	N_("git mv [<options>] <source>... <destination>"),

			bad = _("bad source");
	if (dest_path[0][0] == '\0')
	if (path[len - 1] != '/') {
	if (--argc < 1)

			break;
						warning(_("overwriting '%s'"), dst);
		else if (lstat(dst, &st) == 0 &&
		result[i] = match;
	first = -1 - first;
				} else
			bad = _("multiple sources for the same target");
	struct strbuf submodule_dotgit = STRBUF_INIT;
							      submodule_gitfile[i],
#include "parse-options.h"
#define USE_THE_INDEX_COMPATIBILITY_MACROS
				modes[i] = WORKING_DIRECTORY;
}
		const char *bad = NULL;
				gitmodules_modified = 1;
					if (verbose)

 * "git mv" builtin command

		OPT_END(),

		else if (src_is_dir) {
		else
}
			i--;
			memmove(submodule_gitfile + i, submodule_gitfile + i + 1,

	int first, last, len_w_slash = length + 1;
		usage_with_options(builtin_mv_usage, builtin_mv_options);
	const char **result;
#include "dir.h"
			if (!update_path_in_gitmodules(src, dst))
							      1);
	for (i = 0; i < argc; i++) {
/*
		int to_copy = length;
			printf(_("Renaming %s to %s\n"), src, dst);
		char *with_slash = xmalloc(st_add(len, 2));
	result[count] = NULL;
			free(it);
		enum update_mode mode = modes[i];
				if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
							 &first, &last) < 1)
		*submodule_gitfile = xstrdup(*submodule_gitfile);
				bad = _("source directory is empty");
			if (force) {
		/* special case: "." was normalized to "" */
		while (!(flags & KEEP_TRAILING_SLASH) &&
	*first_p = first;
		else if (!strncmp(src, dst, length) &&
			       COMMIT_LOCK | SKIP_IF_UNCHANGED))
			die_errno(_("renaming '%s' failed"), src);
			die(_("destination '%s' is not a directory"), dest_path[0]);
	struct string_list src_for_dst = STRING_LIST_INIT_NODUP;

static const char *add_slash(const char *path)
		die(_("Please stage your changes to .gitmodules or stash them to proceed"));
		dest_path[0] = add_slash(dest_path[0]);
#define KEEP_TRAILING_SLASH 2
		destination = internal_prefix_pathspec(dest_path[0], argv, argc, DUP_BASENAME);
	git_config(git_default_config, NULL);
				connect_work_tree_and_git_dir(dst,
	int prefixlen = prefix ? strlen(prefix) : 0;

	enum update_mode { BOTH = 0, WORKING_DIRECTORY, INDEX } *modes;
				REALLOC_ARRAY(modes, n);
};
			bad = _("destination exists");

	}
				prepare_move_submodule(src, first,
					bad = NULL;
		int length = strlen(pathspec[i]);
		if (show_only)
			if (ignore_errors)
			continue;
		*submodule_gitfile = SUBMODULE_WITH_GITDIR;
		else if (is_dir_sep(dst[strlen(dst) - 1]))
 * Copyright (C) 2006 Johannes Schindelin
static const char **internal_prefix_pathspec(const char *prefix,
	struct stat st;

	else if (!lstat(dest_path[0], &st) &&
	int i;
		stage_updated_gitmodules(&the_index);
	modes = xcalloc(argc, sizeof(enum update_mode));
	for (i = 0; i < count; i++) {
	struct lock_file lock_file = LOCK_INIT;
			     bad, src, dst);
			   PARSE_OPT_NOCOMPLETE),

	if (*submodule_gitfile)
	int verbose = 0, show_only = 0, force = 0, ignore_errors = 0;
#include "string-list.h"
{
					     int count, unsigned flags)
			     builtin_mv_usage, 0);
	/* Create an intermediate copy of the pathspec based on the flags */

		die(_("index file corrupt"));

	NULL
		die(_("Unable to write new index file"));
#include "pathspec.h"
			if (first >= 0)
static int index_range_of_same_dir(const char *src, int length,
}
	}
				n * sizeof(enum update_mode));
	int i, flags, gitmodules_modified = 0;
					destination[argc + j] =
		free((char *) result[i]);
				   int *first_p, int *last_p)
		if (show_only)
				argc += last - first;
				continue;
			}
	return last - first;
		const char *path = active_cache[last]->name;
			to_copy--;
			result[i] = it;
		if (--argc > 0) {
		free((char *)src_w_slash);
				/*
	const char **source, **destination, **dest_path, **submodule_gitfile;
	if (!is_staging_gitmodules_ok(&the_index))
	}
			S_ISDIR(st.st_mode)) {
				 * check both source and destination
						prefix_path(dst, dst_len, path + length + 1);
	/* Prefix the pathspec and free the old intermediate strings */

	/* Checking */

	return result;
 *
#include "cache-tree.h"
#include "builtin.h"
		} else if ((src_is_dir = S_ISDIR(st.st_mode))

	 */
					bad = _("Cannot overwrite");
{
	 * "git mv file no-such-dir/" error out, except in the case
	const char *src_w_slash = add_slash(src);
				n * sizeof(char *));

				REALLOC_ARRAY(submodule_gitfile, n);
	ALLOC_ARRAY(result, count + 1);
					submodule_gitfile[argc + j] = NULL;
		flags = 0;
		const char *match = prefix_path(prefix, prefixlen, result[i]);
	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);
			bad = _("can not move directory into itself");
static void prepare_move_submodule(const char *src, int first,
			result[i] = xstrdup(basename(it));
	for (last = first; last < active_nr; last++) {
				REALLOC_ARRAY(source, n);

		destination = internal_prefix_pathspec(dest_path[0], argv, argc, DUP_BASENAME);
				for (j = 0; j < last - first; j++) {


		       to_copy > 0 && is_dir_sep(pathspec[i][to_copy - 1]))
			continue;
{
			bad = _("not under version control");
	return 0;
 */
			continue;
		it = xmemdupz(pathspec[i], to_copy);
				   const char **submodule_gitfile)
		if (strncmp(path, src_w_slash, len_w_slash))
#define SUBMODULE_WITH_GITDIR ((const char *)1)
					source[argc + j] = path;
		int pos;
				}
		OPT__VERBOSE(&verbose, N_("be verbose")),
	return path;
		with_slash[len] = 0;
	 * "git mv directory no-such-dir/".
	first = cache_name_pos(src_w_slash, len_w_slash);
	}
				dst = add_slash(dst);
	};
	source = internal_prefix_pathspec(prefix, argv, argc, 0);
}
	*last_p = last;
		}
			memmove(source + i, source + i + 1,
	if (src_w_slash != src)
		const char *src = source[i], *dst = destination[i];

		rename_cache_entry_at(pos, dst);

		OPT_BOOL('k', NULL, &ignore_errors, N_("skip move/rename errors")),
		} else {
		if (mode == WORKING_DIRECTORY)
	} else {
#include "submodule.h"
	else
	if (gitmodules_modified)
	argc = parse_options(argc, argv, prefix, builtin_mv_options,
	if (read_cache() < 0)
	if (!S_ISGITLINK(active_cache[first]->ce_mode))
			bad = _("destination directory does not exist");
			string_list_insert(&src_for_dst, dst);
				n * sizeof(char *));
				n = argc + last - first;
		OPT__FORCE(&force, N_("force move/rename even if target exists"),
#include "config.h"
			memmove(destination + i, destination + i + 1,
		pos = cache_name_pos(src, strlen(src));
		int length, src_is_dir;
			if (submodule_gitfile[i] != SUBMODULE_WITH_GITDIR)
	if (argc == 1 && is_directory(argv[0]) && !is_directory(argv[1]))
				int j, dst_len, n;
	strbuf_release(&submodule_dotgit);

