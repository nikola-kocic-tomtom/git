		submodules_absorb_gitdir_if_needed();
static struct option builtin_rm_options[] = {
	}
		     bad_to_remove_submodule(ce->name,
	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);
		i++;
			return i;
			if (!S_ISGITLINK(active_cache[pos]->ce_mode) ||
			if (!is_missing_file_error(errno))

	struct {
				continue;
		 * tree and if it does not match the HEAD commit
	return errs;
{
 */
		if (ce_match_stat(ce, &st, 0) ||
	/*
		}
		 * "intent to add" entry.
			continue;
	}
				    files_list->items[i].string);
			     "staged in the index:",
					    original);
				    "\n    %s",
		if (lstat(ce->name, &st) < 0) {
	}
		ce = active_cache[pos];
	print_error_files(&files_cached,

		if (check_local_mod(&oid, index_only))
	seen = xcalloc(pathspec.nr, 1);
} list;
		unsigned short mode;
			/* It already vanished from the working tree */
			}
			  _("\n(use --cached to keep the file,"
					die(_("pathspec '%s' did not match any files"),
	 * any file at all, we'll go ahead and commit to it all:
		int staged_changes = 0;
			 * Skip unmerged entries except for populated submodules

		 * lose information unless it is about removing an
		 * Is the index different from the file in the work tree?
static struct {
static void submodules_absorb_gitdir_if_needed(void)
	} *entry;
		list.entry[list.nr].is_submodule = S_ISGITLINK(ce->ce_mode);
		    !is_staging_gitmodules_ok(&the_index))
		     || ce->ce_mode != create_ce_mode(mode)
				    PATHSPEC_PREFER_CWD,
static char *pathspec_from_file;
			if (pos < 0)
	if (!index_only)
				continue;
			exit(1);
{
	 * must match; but the file can already been removed, since

	int i;
		const struct cache_entry *ce;
			if (!S_ISGITLINK(ce->ce_mode))

			    " or -f to force removal)"),
		const char *path = list.entry[i].name;
	 */
	 * the workspace. If we fail to remove the first one, we
		 * the user staged a content that is different from
static int check_local_mod(struct object_id *head, int index_only)
	int nr, alloc;
#include "pathspec.h"
	 * in the middle)
		die(_("Unable to write new index file"));
#include "config.h"
		struct strbuf err_msg = STRBUF_INIT;
	OPT_END(),
			if (staged_changes)
		if (pos < 0) {
	/*
#include "cache-tree.h"
	 * tree_desc based traversal if we wanted to, but I am
		    (S_ISGITLINK(ce->ce_mode) &&
			  Q_("the following file has local modifications:",
			  Q_("the following file has staged content different "
			continue;
	no_head = is_null_oid(head);
	for (i = 0; i < list.nr; i++) {

			     "the following files have changes "

		}
	string_list_clear(&files_cached, 0);

		 */

{
				warning_errno(_("failed to stat '%s'"), ce->name);
		     || get_tree_entry(the_repository, head, name, &oid, &mode)
			 * far as git is concerned; we do not track
	 * this sequence is a natural "novice" way:
		const char *name;

	 * by then we've already committed ourselves and can't fail
	int i;
	OPT__FORCE(&force, N_("override the up-to-date check"), PARSE_OPT_NOCOMPLETE),

	string_list_clear(&files_staged, 0);
#include "builtin.h"
		struct object_id oid;

	 * slower than the theoretical maximum speed?
			strbuf_addstr(&err_msg, hints_msg);

	 * Further, if HEAD commit exists, "diff-index --cached" must
		int pos;

		 * way as changed from the HEAD.
	int i, no_head;
	if (!index_only) {
	 * report no changes unless forced.
	OPT_BOOL( 0 , "ignore-unmatch", &ignore_unmatch,
	N_("git rm [<options>] [--] <file>..."),
			     files_local.nr),
	NULL
			    " or -f to force removal)"),
			pos = get_ours_cache_pos(name, pos);
static const char * const builtin_rm_usage[] = {
			absorb_git_dir_into_superproject(name,
				continue;
		struct stat st;
	}
		die(_("index file corrupt"));
		strbuf_addstr(&err_msg, main_msg);
		/*
		ce = active_cache[pos];
			     " from both the\nfile and the HEAD:",
				strbuf_reset(&buf);
	OPT_BOOL( 0 , "cached",         &index_only, N_("only remove from the index")),
};
		for (i = 0; i < list.nr; i++) {
		     || !oideq(&ce->oid, &oid))
		if (gitmodules_modified)
			die(_("--pathspec-from-file is incompatible with pathspec arguments"));
	OPT_BOOL('r', NULL,             &recursive,  N_("allow recursive removal")),
	char *seen;
		if (!ce_path_match(&the_index, ce, &pathspec, seen))
		pos = cache_name_pos(name, strlen(name));
		if (ce_stage(active_cache[i]) == 2)

			  _("\n(use --cached to keep the file,"
			else {
	int i = -pos - 1;

{

				seen_any = 1;
				continue;
		int local_changes = 0;
		 *
				    prefix, pathspec_from_file, pathspec_file_nul);
			     "the following files have staged content different"
		 * In such a case, you would need to --force the
	 * abort the "git rm" (but once we've successfully removed
		if (!S_ISGITLINK(ce->ce_mode) ||

		 * carefully not to allow losing local changes
			strbuf_addf(&err_msg,
	 * If not forced, the file, the index and the HEAD (if exists)
	OPT_PATHSPEC_FILE_NUL(&pathspec_file_nul),
 *
		 * the content being removed is available elsewhere.
		/*
		 * the work tree or the HEAD commit, as it means that
		       PATHSPEC_PREFER_CWD,
		const struct cache_entry *ce;
	if (write_locked_index(&the_index, &lock_file,
#include "string-list.h"
		 * the current commit in the index.
				ABSORB_GITDIR_RECURSE_SUBMODULES);
	}
	for (i = 0; i < list.nr; i++) {
#include "parse-options.h"

		 * "rm" of a path that has changes need to be treated
#include "lockfile.h"

		 * If it's a submodule, is its work tree modified?
		 * the index) is safe if the index matches the file in
		ALLOC_GROW(list.entry, list.nr + 1, list.alloc);
			     "from both the\nfile and the HEAD:",
	if (pathspec.nr) {
		 * removal.  However, "rm --cached" (remove only from
static int get_ours_cache_pos(const char *path, int pos)
			  &errs);
		char is_submodule;
		setup_work_tree();
		for (i = 0; i < pathspec.nr; i++) {
			oidclr(&oid);
		int removed = 0, gitmodules_modified = 0;
			     builtin_rm_usage, 0);
			 * directories unless they are submodules.
		const char *name = list.entry[i].name;
#include "dir.h"
	 * so we could do this a lot more efficiently by using
	}
		parse_pathspec_file(&pathspec, 0,
static int show_only = 0, force = 0, index_only = 0, recursive = 0, quiet = 0;
	 *

	git_config(git_default_config, NULL);
					gitmodules_modified = 1;
			if (!index_only || !ce_intent_to_add(ce))
		/*
		int i;
			    is_empty_dir(name))
		strbuf_release(&err_msg);
		return 0;
	/*
			if (!removed)
		die(_("No pathspec was given. Which files should I remove?"));
		}
			     "the following files have local modifications:",
	while ((i < active_nr) && !strcmp(active_cache[i]->name, path)) {
			printf("rm '%s'\n", path);
			}
	return -1;
	/*
		 * anything staged in the index is treated by the same
				removed = 1;
	if (!force) {
	return 0;
		const char *original;
 * Copyright (C) Linus Torvalds 2006
			if (!recursive && seen[i] == MATCHED_RECURSIVELY)
}
			 */
		}
			     "staged in the index:", files_cached.nr),
		int seen_any = 0;
			      const char *hints_msg,
#include "tree-walk.h"
 * "git rm" builtin command
	 *	rm F; git rm F
			if (pos < 0)

		}
	refresh_index(&the_index, REFRESH_QUIET|REFRESH_UNMERGED, &pathspec, NULL, NULL);
		if (pos < 0) {
	 * lazy, and who cares if removal of files is a tad

		if (remove_file_from_cache(path))
		}
	for (i = 0; i < list.nr; i++) {
	struct string_list files_staged = STRING_LIST_INIT_NODUP;
		       prefix, argv);
				string_list_append(&files_local, name);
			die(_("git rm: unable to remove %s"), path);
	struct string_list files_local = STRING_LIST_INIT_NODUP;
				}
		/*
		const char *name = list.entry[i].name;
		 * work tree is different since the index; and/or (2)

			if (!remove_path(path)) {
	 *
			pos = get_ours_cache_pos(name, pos);
	parse_pathspec(&pathspec, 0,
			     files_staged.nr),

	struct lock_file lock_file = LOCK_INIT;
			/* if a file was removed and it is now a
int cmd_rm(int argc, const char **argv, const char *prefix)
			  Q_("the following file has changes "
	struct pathspec pathspec;
		 */
			 * that could lose history when removed.
		if (!seen_any)
			if (local_changes)
}
static void print_error_files(struct string_list *files_list,
			}
				continue;
			       COMMIT_LOCK | SKIP_IF_UNCHANGED))
	print_error_files(&files_staged,

		 * will lose information; (2) "git rm --cached" will
	 * the index unless all of them succeed.
				strbuf_addstr(&buf, path);


		list.entry[list.nr].name = xstrdup(ce->name);
	} else if (pathspec_file_nul) {
			original = pathspec.items[i].original;
{
	OPT_PATHSPEC_FROM_FILE(&pathspec_from_file),

		if (pathspec.nr)
		const struct cache_entry *ce = active_cache[i];
		for (i = 0; i < files_list->nr; i++)
		    !file_exists(ce->name) ||
		}
		 * If the index does not match the file in the work
			if (list.entry[i].is_submodule) {


	argc = parse_options(argc, argv, prefix, builtin_rm_options,
		 */
	 * First remove the names from the index: we won't commit
/*
			 * directory, that is the same as ENOENT as
		strbuf_release(&buf);
		int pos;
	if (!index_only)
static int ignore_unmatch = 0, pathspec_file_nul;
	}
	if (show_only)

			die(_("please stage your changes to .gitmodules or stash them to proceed"));
	 * Then, unless we used "--cached", remove the filenames from
	if (pathspec_from_file) {
}
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		if (!submodule_uses_gitfile(name))
		if (!quiet)


		*errs = error("%s", err_msg.buf);
	OPT__QUIET(&quiet, N_("do not list removed files")),
		die(_("--pathspec-file-nul requires --pathspec-from-file"));
		if (local_changes && staged_changes) {
		pos = cache_name_pos(name, strlen(name));
			  &errs);
	print_error_files(&files_local,
		    is_empty_dir(name))
	if (!pathspec.nr)
			      const char *main_msg,

	int errs = 0;

				removed = 1;
				continue;
			const char *path = list.entry[i].name;
			  &errs);
		else if (S_ISDIR(st.st_mode)) {
};
			 */

}
				string_list_append(&files_staged, name);

	 */
				N_("exit with a zero status even if nothing matched")),
			continue;
	OPT__DRY_RUN(&show_only, N_("dry run")),
				if (remove_dir_recursively(&buf, 0))
			}
				SUBMODULE_REMOVAL_IGNORE_IGNORED_UNTRACKED)))

		 */
		if (list.entry[list.nr++].is_submodule &&
		}

	 */
				string_list_append(&files_cached, name);
				if (!ignore_unmatch) {
	}
				die_errno("git rm: '%s'", path);
			staged_changes = 1;
	 */


	 * Items in list are already sorted in the cache order,
				if (!remove_path_from_gitmodules(path))
#include "submodule.h"

}
			/*

			local_changes = 1;
		 * definition, before the very initial commit,

				die(_("not removing '%s' recursively without -r"),
		if (advice_rm_hints)
	}
	}
			  _("\n(use -f to force removal)"),
			      int *errs)

					die(_("could not remove '%s'"), path);
		 * Is the index different from the HEAD commit?  By
				    *original ? original : ".");
			exit(0);
			stage_updated_gitmodules(&the_index);

		 * either, (1) "git rm" without --cached definitely
		struct object_id oid;
	string_list_clear(&files_local, 0);
		else if (!index_only) {
	if (files_list->nr) {
	struct string_list files_cached = STRING_LIST_INIT_NODUP;
	if (read_cache() < 0)
		struct strbuf buf = STRBUF_INIT;
	for (i = 0; i < active_nr; i++) {
		 * accidentally.  A local change could be (1) file in
				SUBMODULE_REMOVAL_DIE_ON_ERROR |
		if (no_head
			if (!seen[i]) {
		if (get_oid("HEAD", &oid))
