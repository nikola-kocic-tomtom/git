"	git submodule add <url> %s\n"
static void chmod_pathspec(struct pathspec *pathspec, char flip)
	struct update_callback_data *data = cbdata;
	free(file);
#include "revision.h"

	while (--i >= 0) {

		exit_status |= renormalize_tracked_files(&pathspec, flags);
					if (is_excluded(&dir, &the_index, path, &dtype))
		 (intent_to_add ? ADD_CACHE_INTENT : 0) |

		 * file_exists() assumes exact match
		 */
		if (!seen[i])
};
"You've added another git repository inside your current repository.\n"
		GUARD_PATHSPEC(&pathspec,
}
		struct cache_entry *ce = active_cache[i];
			continue;
	die_path_inside_submodule(&the_index, &pathspec);
		return run_add_interactive(NULL, "--patch=stash", &pathspec);
			fprintf(stderr, "cannot chmod %cx '%s'\n", flip, ce->name);
	OPT_BOOL( 0 , "refresh", &refresh_only, N_("don't add, only refresh the index")),
			if (data->flags & ADD_CACHE_IGNORE_REMOVAL)
				if (ignore_missing) {
		die(_("index file corrupt"));
	/*

	return exit_status;
		advise(embedded_advice, name.buf, name.buf);
	}
#include "builtin.h"
	int flags;
	if (!ends_with(path, "/"))
			       PATHSPEC_FROMTOP |

		else
		if (!patch_mode)
	OPT_BOOL( 0 , "ignore-missing", &ignore_missing, N_("check if - even missing - files are ignored in dry run")),
		struct pathspec pathspec;
	if (dir->ignored_nr) {
			mode = ADD_P_STASH;
"If you added this path by mistake, you can remove it from the\n"
			break;


"See \"git help submodule\" for more information."
	rev.diffopt.output_format = DIFF_FORMAT_CALLBACK;
				"\"git config advice.addEmptyPathspec false\""));
	if (pathspec_from_file) {
		fprintf(stderr, _(ignore_error));
			if (!(data->flags & ADD_CACHE_PRETEND))
	int status, i;

}
	if (stat(file, &st))
	OPT_HIDDEN_BOOL(0, "legacy-stash-p", &legacy_stash_p,
		 (show_only ? ADD_CACHE_PRETEND : 0) |

		case DIFF_STATUS_MODIFIED:

		/* pass original pathspec, to be re-parsed */
	if (use_builtin_add_i == 1) {


		ignore_add_errors = git_config_bool(var, value);
			seen = prune_directory(&dir, &pathspec, baselen);

		die(_("--chmod param '%s' must be either -x or +x"), chmod_arg);

		default:
		exit(interactive_add(argc - 1, argv + 1, prefix, patch_interactive));
				"Turn this message off by running\n"
		for (i = 0; i < dir->ignored_nr; i++)
	if (chmod_arg && ((chmod_arg[0] != '-' && chmod_arg[0] != '+') ||
#include "parse-options.h"

static char *chmod_arg;
		else if (!strcmp(patch_mode, "--patch=stash"))
static int ignore_add_errors, intent_to_add, ignore_missing;
	struct strbuf name = STRBUF_INIT;
		return(edit_patch(argc, argv, prefix));
	OPT_GROUP(""),
				   &pathspec);
	struct pathspec pathspec;
	 */
{
	if (add_renormalize)
	return run_add_interactive(NULL,
			if (!seen[i] && path[0] &&
}
static int edit_patch(int argc, const char **argv, const char *prefix)

"\n"
	int out;
	strbuf_release(&name);
		      pathspec, seen, _("Unstaged changes after refreshing the index:"));
					int dtype = DT_UNKNOWN;
	for (i = 0; i < pathspec->nr; i++) {

		       PATHSPEC_SYMLINK_LEADING_PATH |

		return;

		 * in the working tree.  An attempt to explicitly
	die_in_unpopulated_submodule(&the_index, prefix);
	if (p->status != DIFF_STATUS_UNMERGED)
		if (add_file_to_index(&the_index, dir->entries[i]->name, flags)) {
	else
	OPT_BOOL('u', "update", &take_worktree_changes, N_("update tracked files")),
	OPT_BOOL( 0 , "ignore-errors", &ignore_add_errors, N_("just skip files which cannot be added because of errors")),
	}
#include "exec-cmd.h"
			die(_("--pathspec-from-file is incompatible with pathspec arguments"));
static int verbose, show_only, ignored_too, refresh_only;
}

	plug_bulk_checkin();
	  N_("ignore paths removed in the working tree (same as --no-all)"),
	add_pathspec_matches_against_index(pathspec, &the_index, seen);
			break;
		exit_status = 1;
{
			continue;
			       PATHSPEC_ICASE |
	}
			advise( _("Maybe you wanted to say 'git add .'?\n"
int add_files_to_cache(const char *prefix,

	if (add_new_files) {
			    pathspec->items[i].match);
		 (!(addremove || take_worktree_changes)
	int i, exit_status = 0;
	N_("git add [<options>] [--] <pathspec>..."),
		       prefix, argv);

				continue;
	struct update_callback_data data;
		git_config_get_bool("add.interactive.usebuiltin",
#include "add-interactive.h"
	struct dir_struct dir;
	refresh_index(&the_index, verbose ? REFRESH_IN_PORCELAIN : REFRESH_QUIET,

	if (chmod_arg && pathspec.nr)
	apply_argv[3] = file;

	return exit_status;
	if (patch_interactive)
		return DIFF_STATUS_DELETED;
	if (!strcmp(var, "add.ignoreerrors") ||
	int require_pathspec;
					    pathspec.items[i].original);
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		 */
static int ignore_removal_cb(const struct option *opt, const char *arg, int unset)
			       PATHSPEC_LITERAL |
	return git_default_config(var, value, cb);
#include "config.h"

		argv_array_push(&argv, patch_mode);
	if (use_builtin_add_i < 0)
			const char *path = pathspec.items[i].match;
			fprintf(stderr, "%s\n", dir->ignored[i]->name);
	OPT__DRY_RUN(&show_only, N_("dry run")),
	parse_pathspec(&pathspec, 0,
				die(_("adding files failed"));
{
	}
static int warn_on_embedded_repo = 1;
		die(_("editing patch failed"));
	OPT_END(),
	if (!(data->flags & ADD_CACHE_IGNORE_REMOVAL) && !p->two->mode)
		if (pathspec.nr)
	int i;
	if (pathspec)
	if (refresh_only) {

		return 0;
{
	OPT__FORCE(&ignored_too, N_("allow adding otherwise ignored files"), 0),
		exit_status |= add_files(&dir, flags);
	const char *apply_argv[] = { "apply", "--recount", "--cached",
				if (!(data->flags & ADD_CACHE_IGNORE_ERRORS))
		 * add a path that does not exist in the working tree
	run_diff_files(&rev, DIFF_RACY_IS_MODIFIED);
	rev.diffopt.format_callback_data = &data;
			*dst++ = entry;
	NULL
	int add_errors;
			die("'%s' not supported", patch_mode);

	rev.diffopt.use_color = 0;

		die(_("--pathspec-file-nul requires --pathspec-from-file"));
		struct diff_filepair *p = q->queue[i];
	if (!show_only && ignore_missing)
static int add_files(struct dir_struct *dir, int flags)
	return 0;
	}
		argv_array_push(&argv, revision);
			  chmod_arg[1] != 'x' || chmod_arg[2]))
		die(_("Could not open '%s' for writing."), file);
		       PATHSPEC_SYMLINK_LEADING_PATH,
int interactive_add(int argc, const char **argv, const char *prefix, int patch)
	rev.diffopt.flags.ignore_dirty_submodules = 1;
	  NULL /* takes no arguments */,
	}
			setup_standard_excludes(&dir);
			       COMMIT_LOCK | SKIP_IF_UNCHANGED))
}
	if (out < 0)
	}

	*(int *)opt->value = !unset ? 0 : 1;
}
);
		 * will be caught as an error by the caller immediately.
	argv_array_clear(&argv);
static int fix_unmerged_status(struct diff_filepair *p,
	  PARSE_OPT_NOARG, ignore_removal_cb },
		       const struct pathspec *pathspec, int flags)
	clear_pathspec(&rev.prune_data);
		 * Either an explicit add request, or path exists
			mode = ADD_P_ADD;
		free(seen);
	OPT_BOOL(0, "renormalize", &add_renormalize, N_("renormalize EOL of tracked files (implies -u)")),

	struct dir_entry **src, **dst;
		NULL, NULL };
	UNLEAK(dir);
#include "submodule.h"
	if (add_new_files)

		       PATHSPEC_PREFIX_ORIGIN,
	rev.diffopt.close_file = 1;
	if (add_interactive) {
{
	argc--;
		}

		die(_("Unable to write new index file"));
		if (ce_stage(ce))

}
			die(_("unexpected diff status %c"), p->status);
			       PATHSPEC_GLOB |
	}
	src = dst = dir->entries;

	OPT__VERBOSE(&verbose, N_("be verbose")),
	for (i = 0; i < active_nr; i++) {
	if (write_locked_index(&the_index, &lock_file,
		 * path is missing from the working tree (deleted)
		die(_("Could not read the index"));
		}
		retval |= add_file_to_cache(ce->name, flags | ADD_CACHE_RENORMALIZE);

			advise(_("Use -f if you really want to add them.\n"
	OPT_STRING(0, "chmod", &chmod_arg, "(+|-)x",
	if (addremove && take_worktree_changes)
		if (advice_add_ignored_file)
"\n"
		if (pathspec && !ce_path_match(&the_index, ce, pathspec, NULL))
}
			    ((pathspec.items[i].magic &
		for (i = 0; i < pathspec.nr; i++) {
	flags = ((verbose ? ADD_CACHE_VERBOSE : 0) |
	}

{
{

int run_add_interactive(const char *revision, const char *patch_mode,

		return;
		return !!run_add_p(the_repository, mode, revision, pathspec);
#include "diff.h"

	child.argv = apply_argv;
	setup_revisions(0, NULL, &rev, NULL);
{
	 * below before enabling new magic.
		 */
	else
		advice_add_embedded_repo = 0;


	if (run_command(&child))
	}
		if (advice_add_empty_pathspec)
		addremove = addremove_explicit;
				    &use_builtin_add_i);
	unlink(file);
	for (i = 0; i < q->nr; i++) {
static void refresh(int verbose, const struct pathspec *pathspec)
	OPT_BOOL('A', "all", &addremove_explicit, N_("add changes from all tracked and untracked files")),
	int i;
	if (read_cache() < 0)
	}
		if (pathspec_from_file)
		}
{
		return 0;

		die(_("Could not apply '%s'"), file);
#include "lockfile.h"
struct update_callback_data {
			N_("warn when adding an embedded repository")),

}
	git_config(add_config, NULL);
			}
		enum add_p_mode mode;


		/*
	struct rev_info rev;
	if (pathspec.nr) {
	data.flags = flags;
	if (revision)
{

	int use_builtin_add_i =

		  ? ADD_CACHE_IGNORE_REMOVAL : 0));
	int i;
		copy_pathspec(&rev.prune_data, pathspec);
	if (launch_editor(file, NULL, NULL))
			mode = ADD_P_RESET;
	i = dir->nr;
	OPT_PATHSPEC_FILE_NUL(&pathspec_file_nul),
			  builtin_add_usage, PARSE_OPT_KEEP_ARGV0);
		 * This is not an explicit add request, and the
		else if (!strcmp(patch_mode, "--patch=worktree"))
	OPT_BOOL('p', "patch", &patch_interactive, N_("select hunks interactively")),
};
/*
						dir_add_ignored(&dir, &the_index,
		if (!S_ISREG(ce->ce_mode) && !S_ISLNK(ce->ce_mode))
	if (legacy_stash_p) {
	unplug_bulk_checkin();
	OPT_BOOL('e', "edit", &edit_interactive, N_("edit current diff and apply")),
			dir.flags |= DIR_COLLECT_IGNORED;

	char *seen = NULL;
 * "git add" builtin command
	char *seen;
static int patch_interactive, add_interactive, edit_interactive;
	add_new_files = !take_worktree_changes && !refresh_only && !add_renormalize;
		if (dir_path_match(&the_index, entry, pathspec, prefix, seen))
	}
static void check_embedded_repo(const char *path)
static const char embedded_advice[] = N_(
		if (pathspec.nr)
		die(_("Empty patch. Aborted."));
	if (!st.st_size)
	struct argv_array argv = ARGV_ARRAY_INIT;
	rev.diffopt.flags.override_submodule_config = 1;
static int take_worktree_changes;
	if (read_cache_preload(&pathspec) < 0)
static int addremove_explicit = -1; /* unspecified */
		int baselen;
	 * Check the "pathspec '%s' did not match any files" block
	if (0 <= addremove_explicit)
		memset(&dir, 0, sizeof(dir));
	dir->nr = dst - dir->entries;

	}
		baselen = fill_directory(&dir, &the_index, &pathspec);


	repo_init_revisions(the_repository, &rev, prefix);
		/*

"If you meant to add a submodule, use:\n"
				data->add_errors++;
		int i;
#include "bulk-checkin.h"
			seen = find_pathspecs_matching_against_index(&pathspec, &the_index);
		fprintf(stderr, _("Nothing specified, nothing added.\n"));

{
	OPT_BOOL('i', "interactive", &add_interactive, N_("interactive picking")),
				break;
			continue; /* do not touch unmerged paths */
	for (i = 0; i < pathspec->nr; i++)

				    PATHSPEC_SYMLINK_LEADING_PATH,
		} else {
"index with:\n"
								path, pathspec.items[i].len);


				} else

			if (add_file_to_index(&the_index, path,	data->flags)) {
				printf(_("remove '%s'\n"), path);
			      (PATHSPEC_GLOB | PATHSPEC_ICASE)) ||

		   N_("override the executable bit of the listed files")),

		       PATHSPEC_PREFER_FULL |
				"\"git config advice.addIgnoredFile false\""));
finish:
}
		if (pathspec_from_file)
	if (require_pathspec && pathspec.nr == 0) {
		addremove = 1;

static struct option builtin_add_options[] = {
	struct rev_info rev;
		die_errno(_("Could not stat '%s'"), file);
	git_config(git_diff_basic_config, NULL); /* no "diff" UI options */

}
		/* Turn "git add pathspec..." to "git add -A pathspec..." */
	rev.diffopt.output_format = DIFF_FORMAT_PATCH;
}
#include "cache-tree.h"
	OPT_PATHSPEC_FROM_FILE(&pathspec_from_file),
	seen = xcalloc(pathspec->nr, 1);
{
#include "run-command.h"
	}
"	git rm --cached %s\n"
	strbuf_strip_suffix(&name, "/");
	return status;
#include "dir.h"
"Clones of the outer repository will not contain the contents of\n"
		if (pathspec && !ce_path_match(&the_index, ce, pathspec, NULL))

	for (i = 0; i < dir->nr; i++) {
	return 0;

	return seen;
	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);
 * Copyright (C) 2006 Linus Torvalds
"\n"
	/* if we are told to ignore, we are not adding removals */
	argc = parse_options(argc, argv, prefix, builtin_add_options,
		struct dir_entry *entry = *src++;
		die(_("-A and -u are mutually incompatible"));
};
				   patch ? "--patch" : NULL,
	return !!data.add_errors;
	OPT_BOOL('N', "intent-to-add", &intent_to_add, N_("record only the fact that the path will be added later")),
}
		else if (!strcmp(patch_mode, "--patch=checkout"))
{

			N_("backend for `git stash -p`")),
		refresh(verbose, &pathspec);
	parse_pathspec(&pathspec, PATHSPEC_ATTR,
	rev.max_count = 0; /* do not compare unmerged paths with stage #2 */
		/*
	    !strcmp(var, "add.ignore-errors")) {
			die(_("--pathspec-from-file is incompatible with --edit"));
	require_pathspec = !(take_worktree_changes || (0 < addremove_explicit));
	struct stat st;
static const char ignore_error[] =

	argv_array_push(&argv, "add--interactive");
		else if (!strcmp(patch_mode, "--patch=reset"))
	}
			continue; /* do not touch non blobs */
			prefix, argv);
		switch (fix_unmerged_status(p, data)) {


	int add_new_files;
		die(_("Option --ignore-missing can only be used together with --dry-run"));
		/* This picks up the paths that are not tracked */

	else if (take_worktree_changes && ADDREMOVE_DEFAULT)
static const char * const builtin_add_usage[] = {
	struct child_process child = CHILD_PROCESS_INIT;
	for (i = 0; i < active_nr; i++) {
		       PATHSPEC_PREFER_FULL |

"the embedded repository and will not know how to obtain it.\n"


static int add_config(const char *var, const char *value, void *cb)
int cmd_add(int argc, const char **argv, const char *prefix)
	if (edit_interactive) {
"\n"
	rev.diffopt.context = 7;

	int exit_status = 0;
	strbuf_addstr(&name, path);
	argc = setup_revisions(argc, argv, &rev, NULL);
static int addremove = ADDREMOVE_DEFAULT;
	struct pathspec pathspec;

				    PATHSPEC_PREFER_FULL |

				"Turn this message off by running\n"
	/* Drop trailing slash for aesthetics */

		if (!seen)
			PATHSPEC_PREFIX_ORIGIN,


{
	}
			mode = ADD_P_CHECKOUT;

		/* there may be multiple entries; advise only once */
		       prefix, argv);

	if (!take_worktree_changes && addremove_explicit < 0 && pathspec.nr)
	free(seen);

	seen = xcalloc(pathspec->nr, 1);
	rev.diffopt.format_callback = update_callback;
		chmod_pathspec(&pathspec, chmod_arg[0]);

			die(_("--pathspec-from-file is incompatible with --interactive/--patch"));
	warning(_("adding embedded git repository: %s"), name.buf);
			PATHSPEC_PREFER_FULL |
		exit_status |= add_files_to_cache(prefix, &pathspec, flags);
			exit_status = 1;
 *
{
 */
	child.git_cmd = 1;
	if (!warn_on_embedded_repo)
		die(_("Could not write patch"));
	argv_array_push(&argv, "--");
static int renormalize_tracked_files(const struct pathspec *pathspec, int flags)
#include "cache.h"
	struct lock_file lock_file = LOCK_INIT;
	int flags;
		 (ignore_add_errors ? ADD_CACHE_IGNORE_ERRORS : 0) |
		/* Set up the default git porcelain excludes */
		if (chmod_cache_entry(ce, flip) < 0)
	char *seen;
	}
static int legacy_stash_p; /* support for the scripted `git stash` */
#include "argv-array.h"
		argv_array_push(&argv, pathspec->items[i].original);
	if (run_diff_files(&rev, 0))

static int add_renormalize;


		return DIFF_STATUS_MODIFIED;
		add_interactive = 1;
static int pathspec_file_nul;
			     !file_exists(path))) {
	char *file = git_pathdup("ADD_EDIT.patch");
	memset(&data, 0, sizeof(data));
		goto finish;

	out = open(file, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	argv++;

		if (!strcmp(patch_mode, "--patch"))
	repo_init_revisions(the_repository, &rev, prefix);
		return p->status;
		git_env_bool("GIT_TEST_ADD_I_USE_BUILTIN", -1);
			PATHSPEC_SYMLINK_LEADING_PATH |
		case DIFF_STATUS_TYPE_CHANGED:
	int i, retval = 0;

#include "pathspec.h"
static const char *pathspec_from_file;
			    struct diff_options *opt, void *cbdata)
static char *prune_directory(struct dir_struct *dir, struct pathspec *pathspec, int prefix)
		parse_pathspec(&pathspec, 0,

			if (data->flags & (ADD_CACHE_PRETEND|ADD_CACHE_VERBOSE))
		addremove = 0; /* "-u" was given but not "-A" */
static void update_callback(struct diff_queue_struct *q,
	if (advice_add_embedded_repo) {
	return retval;
}
#include "diffcore.h"
	} else if (pathspec_file_nul) {
}
					die(_("pathspec '%s' did not match any files"),
	status = run_command_v_opt(argv.argv, RUN_GIT_CMD);
		const char *path = p->one->path;
			die(_("pathspec '%s' did not match any files"),
			       PATHSPEC_EXCLUDE);
			const struct pathspec *pathspec)
	int i;
N_("The following paths are ignored by one of your .gitignore files:\n");
				    prefix, pathspec_from_file, pathspec_file_nul);
		struct cache_entry *ce = active_cache[i];

			if (!ignore_add_errors)
		case DIFF_STATUS_DELETED:

#define ADDREMOVE_DEFAULT 1
	}

			mode = ADD_P_WORKTREE;
			if (pathspec.items[i].magic & PATHSPEC_EXCLUDE)
			       struct update_callback_data *data)
		if (!ignored_too) {
	UNLEAK(pathspec);
			}
				remove_file_from_index(&the_index, path);
			check_embedded_repo(dir->entries[i]->name);
		parse_pathspec_file(&pathspec, PATHSPEC_ATTR,
	if (patch_mode)
		}
			return !!run_add_i(the_repository, pathspec);

	OPT_HIDDEN_BOOL(0, "warn-embedded-repo", &warn_on_embedded_repo,
	{ OPTION_CALLBACK, 0, "ignore-removal", &addremove_explicit,
	rev.diffopt.file = xfdopen(out, "w");

					die(_("updating files failed"));
