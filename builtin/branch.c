
				name, reference_name);
		struct branch *branch = branch_get(name);
	}
		strbuf_addf(&remote, "%%(align:%d,left)%s%%(refname:lstrip=2)%%(end)%s"
		}
	};
	filter.ignore_case = icase;
	strbuf_reset(&buf);
	if (force) {

		setup_auto_pager("branch", 1);

	return strbuf_detach(&fmt, NULL);
		parse_ref_sorting(sorting_tail, value);
};
	} else
		if (s < ep)
			warning(_("deleting branch '%s' that has been merged to\n"

	 * branch, which means that the branch has already been merged
		/* For subsequent UI messages */
#include "string-list.h"
		strbuf_addstr(&local, branch_get_color(BRANCH_COLOR_RESET));
	if (!skip_prefix(oldref.buf, "refs/heads/", &interpreted_oldname) ||

	int show_current = 0;
	if (want_color(branch_use_color))
		else if (!filter->abbrev)
	read_branch_desc(&buf, branch_name);
	strbuf_addf(&name, "branch.%s.description", branch_name);
				continue;
	strbuf_commented_addf(&buf,
		if (copy)
	const char *remote_prefix = "";
		OPT_REF_SORT(sorting_tail),
	if (skip_prefix(var, "color.branch.", &slot_name)) {
		OPT__FORCE(&force, N_("force creation, move/rename, deletion"), PARSE_OPT_NOCOMPLETE),
	unsigned allowed_interpret;

				interpreted_oldname);
		usage_with_options(builtin_branch_usage, options);
		if (*ep == '%') {
	void *reference_name_to_free = NULL;
		create_branch(the_repository,
	for (i = 0; i < array.nr; i++) {
	 * cause the worktree to become inconsistent with HEAD, so allow it.



		OPT_STRING('u', "set-upstream-to", &new_upstream, N_("upstream"), N_("change the upstream info")),
			putchar('\n');
		OPT_GROUP(N_("Specific git-branch actions:")),
#include "remote.h"
		return -1;
	}
	while (*s) {
	merged = in_merge_bases(rev, reference_rev);
static unsigned int colopts;
			    "%%(else) %s %%(contents:subject)%%(end)",
		else
	filter.abbrev = -1;
		OPT_BOOL(0, "create-reflog", &reflog, N_("create the branch's reflog")),
			reference_rev = lookup_commit_reference(the_repository,
		strbuf_release(&out);
	BRANCH_COLOR_LOCAL = 3,
		}
		      "If you are sure you want to delete it, "

	if (kind == FILTER_REFS_BRANCHES) {
		if (!argc)
			die(_("Couldn't look up commit object for HEAD"));
	}
 * Based on git-branch.sh by Junio C Hamano.
}
				find_shared_symref("HEAD", name);
int cmd_branch(int argc, const char **argv, const char *prefix)
	int merged;
	 * then remote branches will have a "remotes/" prefix.

	/*
		} else if (argc == 1)
		if (!(flags & (REF_ISSYMREF|REF_ISBROKEN)) &&
				    &oid, NULL)) != NULL)
		string_list_clear(&output, 0);
		else if (argc == 1)
static char branch_colors[][COLOR_MAXLEN] = {
	if (copy && copy_existing_ref(oldref.buf, newref.buf, logmsg.buf))
			max = w;
}
	N_("git branch [<options>] [-l] [-f] <branch-name> [<start-point>]"),
		OPT__COLOR(&branch_use_color, N_("use colored output")),
	return buf.buf;
{
		OPT_WITHOUT(&filter.no_commit, N_("print only branches that don't contain the commit")),
		if (!argc)
		OPT_NO_CONTAINS(&filter.no_commit, N_("print only branches that don't contain the commit")),
			die(_("cannot edit description of more than one branch"));
	} else if (new_upstream) {

		if (slot < 0)
		else
static int delete_branches(int argc, const char **argv, int force, int kinds,

		/*
		if (delete_ref(NULL, name, is_null_oid(&oid) ? NULL : &oid,
			w += remote_bonus;
			die(_("the '--set-upstream' option is no longer supported. Please use '--track' or '--set-upstream-to' instead."));
		     resolve_refdup(upstream, RESOLVE_REF_READING,
		if (upstream &&
		OPT_STRING(  0 , "format", &format.format, N_("format"), N_("format to use for the output")),
		else
		    branch_get_color(BRANCH_COLOR_REMOTE));
#include "diff.h"
	struct strbuf buf = STRBUF_INIT;
	if (!delete && !rename && !copy && !edit_description && !new_upstream &&
			die(_("cannot rename the current branch while not on any."));
#include "ref-filter.h"
		const char *desc = it->refname;
		return -1;
	}
	} else {
		BUG("expected prefix missing for refs");


		{
		struct branch *branch = branch_get(argv[0]);
	default:
	if (!refname)
#include "cache.h"

	N_("git branch [<options>] (-c | -C) [<old-branch>] <new-branch>"),
#include "worktree.h"
#include "color.h"
		if (!branch_has_merge_config(branch))
			strbuf_addf(&obname, "%%(objectname)");
}
{
	int i, max = 0;
		else
		break;

			die(_("Invalid branch name: '%s'"), oldname);
		OPT_CONTAINS(&filter.with_commit, N_("print only branches that contain the commit")),


#include "utf8.h"
	}
			 N_("edit the description for the branch")),
		if (merged)
			    target, wt->path);

		return color_parse(value, branch_colors[slot]);
			die(_("cannot copy the current branch while not on any."));
		force = 1;
			error(remote_branch
		    _("Please edit the description for the branch\n"
		if (is_worktree_being_rebased(wt, target))
	strbuf_addf(&local, "%%(if)%%(HEAD)%%(then)* %s%%(else)%%(if)%%(worktreepath)%%(then)+ %s%%(else)  %s%%(end)%%(end)",
	memset(&filter, 0, sizeof(filter));
	if (git_config_rename_section(buf.buf, NULL) < 0)

			FILTER_REFS_REMOTES | FILTER_REFS_BRANCHES),
	return merged;

			    branch_get_color(BRANCH_COLOR_RESET));
	strbuf_release(&oldsection);
	argc = parse_options(argc, argv, prefix, options, builtin_branch_usage,
	}
			die("%s", err.buf);
	}
enum color_branch {
	free(reference_name_to_free);
		struct object_id oid;
#include "help.h"
			ret = 1;
static void copy_or_rename_branch(const char *oldname, const char *newname, int copy, int force)
	case FILTER_REFS_BRANCHES:
			    oldref.buf, newref.buf);
		remote_prefix = "remotes/";
	NULL
			      : _("Error deleting branch '%s'"),
			N_("print only branches of the object"), 0, parse_opt_object_name
				die(_("could not unset upstream of HEAD when "
		target = resolve_refdup(name,
		strbuf_addf(&local, " %s ", obname.buf);
	if (launch_editor(edit_description(), &buf, NULL)) {

		return delete_branches(argc, argv, delete > 1, filter.kind, quiet);
	}
static const char *color_branch_slots[] = {
		 */
	} else if (edit_description) {
		free(target);
		fmt = "refs/remotes/%s";
	 */
/*
	for (i = 0; worktrees[i]; i++) {
		head_rev = lookup_commit_reference(the_repository, &head_oid);
			       : _("Deleted branch %s (was %s).\n"),
	static struct ref_sorting *sorting = NULL, **sorting_tail = &sorting;
	strbuf_release(&newsection);
	}
	/*
					     branch_name);

	enum branch_track track;
				return error(_("No commit on branch '%s' yet."),
		if (!branch) {
	[BRANCH_COLOR_WORKTREE] = "worktree",
	struct worktree **worktrees = get_worktrees(0);

		skip_prefix(it->refname, "refs/remotes/", &desc);
	GIT_COLOR_NORMAL,       /* PLAIN */
		OPT_SET_INT('a', "all", &filter.kind, N_("list both remote-tracking and local branches"),
	if (recovery) {


		usage_with_options(builtin_branch_usage, options);
	int delete = 0, rename = 0, copy = 0, force = 0, list = 0;
	ref_array_sort(sorting, &array);


			if (filter.detached)
			strbuf_addf(&obname, "%%(objectname:short=%d)", filter->abbrev);
	GIT_COLOR_BLUE,         /* UPSTREAM */
#include "builtin.h"
				die(_("Cannot give description to detached HEAD"));

	if (!copy && git_config_rename_section(oldsection.buf, newsection.buf) < 0)
	strbuf_addf(&newsection, "branch.%s", interpreted_newname);
	if (!copy &&
		OPT_END(),

		}
		print_ref_list(&filter, sorting, &format);
			sorting = ref_default_sorting();
			die(_("Branch %s is being bisected at %s"),
	const char *reference_name = NULL;
	strbuf_release(&local);
			ret = 1;
		error(_("Couldn't look up commit object for '%s'"), refname);
	struct strbuf name = STRBUF_INIT;

		colopts = 0;
{

			die(_("too many arguments for a rename operation"));

		if (!head_rev)
	strbuf_addf(&buf, "branch.%s", branchname);
		die(_("could not resolve HEAD"));
			      bname.buf);
		return git_column_config(var, value, "branch", &colopts);
			string_list_append(&output, out.buf);
	int reflog = 0, edit_description = 0;
 * Copyright (c) 2006 Kristian Høgsberg <krh@redhat.com>
}

		}

	N_("git branch [<options>] [-r] (-d | -D) <branch-name>..."),
		if (argc > 1)
		struct strbuf obname = STRBUF_INIT;
		if (!branch) {
		strbuf_release(&branch_ref);
		 */
	[BRANCH_COLOR_CURRENT]	= "current",
		if (!ref_exists(branch_ref.buf)) {

				name, reference_name);

	struct commit *head_rev = NULL;
			recovery = 1;

	} else if (copy) {
	char *to_free = NULL;
		strbuf_addf(&buf, "branch.%s.remote", branch->name);
			    quote_literal_for_format(remote_prefix),
		return -1;
	int ret = 0;

static void reject_rebase_or_bisect_branch(const char *target)
		OPT_SET_INT('r', "remotes",     &filter.kind, N_("act on remote-tracking branches"),

	ref_array_clear(&array);
		OPT_SET_INT('t', "track",  &track, N_("set up tracking mode (see git-pull(1))"),
		allowed_interpret = INTERPRET_BRANCH_LOCAL;
	if (filter.abbrev == -1)
		die(_("Branch copy failed"));
		 * array with the 'HEAD' ref at the beginning followed by
	}
			fwrite(out.buf, 1, out.len, stdout);
	filter.kind = FILTER_REFS_BRANCHES;
			filter.kind |= FILTER_REFS_DETACHED_HEAD;
			w = utf8_strwidth(desc);
static int check_branch_commit(const char *branchname, const char *refname,
{
		if (!quiet) {
		fmt = "refs/heads/%s";
		struct strbuf branch_ref = STRBUF_INIT;
static int calc_maxwidth(struct ref_array *refs, int remote_bonus)
	    !show_current && !unset_upstream && argc == 0)
	} else if (show_current) {
			strbuf_addf(&local, "%%(if:notequals=*)%%(HEAD)%%(then)%%(if)%%(worktreepath)%%(then)(%s%%(worktreepath)%s) %%(end)%%(end)",
	}
		OPT__QUIET(&quiet, N_("suppress informational messages")),
		git_config_set_multivar(buf.buf, NULL, NULL, 1);
		if (!sorting)
			die(_("too many arguments to unset upstream"));
		if (!wt->is_detached)
			    oldref.buf, newref.buf);
		if (filter.kind != FILTER_REFS_BRANCHES)
		/*
	filter_refs(&array, filter, filter->kind | FILTER_REFS_INCLUDE_BROKEN);
		OPT__VERBOSE(&filter.verbose,
			if (!argc || !strcmp(argv[0], "HEAD"))
static void print_ref_list(struct ref_filter *filter, struct ref_sorting *sorting, struct ref_format *format)


		int w;
#include "branch.h"
			die(_("no such branch '%s'"), argv[0]);
					     branch_name);
		return 0;
{
	switch (kinds) {
	    list + unset_upstream > 1)
		return 0;
	strbuf_addf(&oldsection, "branch.%s", interpreted_oldname);

	return "";
		format->format = to_free = build_format(filter, maxwidth, remote_prefix);
		if (it->kind == FILTER_REFS_DETACHED_HEAD) {
		strbuf_branchname(&bname, argv[i], allowed_interpret);
			die(_("Branch %s is being rebased at %s"),
			    branch_get_color(BRANCH_COLOR_RESET));

	if (!format->format)
			copy_or_rename_branch(head, argv[0], 1, copy > 1);
			       REF_NO_DEREF)) {
		OPT_BIT('d', "delete", &delete, N_("delete fully merged branch"), 1),
	}
		OPT_BIT('M', NULL, &rename, N_("move/rename a branch, even if target exists"), 2),
			return 0;
	[BRANCH_COLOR_PLAIN]	= "plain",
				    branch_get_color(BRANCH_COLOR_WORKTREE), branch_get_color(BRANCH_COLOR_RESET));

	else
		if (!argc)


		rename *= 2;
			die(_("--column and --verbose are incompatible"));
		}
			       (flags & REF_ISBROKEN) ? "broken"
	return git_color_default_config(var, value, cb);
	const char *slot_name;
		struct strbuf err = STRBUF_INIT;

		char *target = NULL;

		else if (argc == 1)
	[BRANCH_COLOR_REMOTE]	= "remote",
			      : _("branch '%s' not found."), bname.buf);
			s = ep;
		if (is_worktree_being_bisected(wt, target))
{
#include "commit-reach.h"
	struct strbuf fmt = STRBUF_INIT;
		remote_branch = 1;
	setup_ref_filter_porcelain_msg();
		}
		const char *branch_name;

}
	N_("git branch [<options>] [-r | -a] [--merged | --no-merged]"),
			strbuf_addstr(&buf, "%%");
#include "parse-options.h"
				      "it does not point to any branch."),
			     0);
	if (!buf.len || buf.buf[buf.len-1] != '\n')
			   int quiet)
								&oid);
		die(_("Failed to resolve HEAD as a valid ref."));
		if (!value)
		if (!target) {
	const char *fmt;
	if (!reference_rev)
		 * If no sorting parameter is given then we default to sorting
				      "it does not point to any branch."));
		OPT_BOOL(0, "edit-description", &edit_description,

	struct strbuf oldref = STRBUF_INIT, newref = STRBUF_INIT, logmsg = STRBUF_INIT;
			warning(_("not deleting branch '%s' that is not yet merged to\n"
	[BRANCH_COLOR_LOCAL]	= "local",
 * Builtin "git branch"
	if (!strcmp(oldname, newname))
		OPT_SET_INT_F(0, "set-upstream", &track, N_("do not use"),
			}

			       ? _("Deleted remote-tracking branch %s (was %s).\n")
	if (delete) {
			 /* format to a string_list to let print_columns() do its job */
		const char *ep = strchrnul(s, '%');
static int branch_use_color = -1;
		      "run 'git branch -D %s'."), branchname, branchname);
			FILTER_REFS_REMOTES),
	GIT_COLOR_NORMAL,       /* LOCAL */
		else
	}

};
		break;
			branch_get_color(BRANCH_COLOR_CURRENT),
	    filter.no_commit)
 */
			goto next;
		strbuf_addf(&local, "%%(align:%d,left)%%(refname:lstrip=2)%%(end)", maxwidth);
	if (argc == 2 && !strcmp(argv[1], "-h"))

	strbuf_addf(&remote, "  %s",
		die(_("Branch rename failed"));

			die(_("no such branch '%s'"), argv[0]);
	N_("git branch [<options>] (-m | -M) [<old-branch>] <new-branch>"),
static const char *branch_get_color(enum color_branch ix)
	 */
			assert(!filter->verbose && "--column and --verbose are incompatible");
			       int kinds, int force)
static int git_branch_config(const char *var, const char *value, void *cb)
{
}

		struct ref_array_item *it = refs->items[i];



	GIT_COLOR_RED,          /* REMOTE */

		struct branch *branch = branch_get(argv[0]);
	} else if (argc > 0 && argc <= 2) {
	free(to_free);
			branch_get_color(BRANCH_COLOR_WORKTREE),
	if (list)

		die(_("unable to parse format string"));
	    replace_each_worktree_head_symref(oldref.buf, newref.buf, logmsg.buf))

		sorting->ignore_case = icase;
static struct object_id head_oid;
		    (reference_name = reference_name_to_free =
	strbuf_release(&name);
	int remote_branch = 0;
	/*
			die(_("too many branches for a copy operation"));

}
		if (explicitly_enable_column(colopts))
		OPT_NO_MERGED(&filter, N_("print only branches that are not merged")),
		      "Lines starting with '%c' will be stripped.\n"),
	if (copy)
	}
		name = mkpathdup(fmt, bname.buf);
	if (filter.with_commit || filter.merge != REF_FILTER_MERGED_NONE || filter.points_at.nr ||

	if (strbuf_check_branch_ref(&oldref, oldname)) {
	 * After the safety valve is fully redefined to "check with
	finalize_colopts(&colopts, -1);
			printf(remote_branch
				    branch_get_color(BRANCH_COLOR_UPSTREAM), branch_get_color(BRANCH_COLOR_RESET));

	int i;
	strbuf_reset(&buf);
	 * If we are listing more than just remote branches,
			BRANCH_TRACK_EXPLICIT),
	N_("git branch [<options>] [-r | -a] [--format]"),
		else

static struct string_list output = STRING_LIST_INIT_DUP;
		validate_branchname(newname, &newref);
	struct strbuf bname = STRBUF_INIT;
	git_config_set(name.buf, buf.len ? buf.buf : NULL);

		skip_prefix(it->refname, "refs/heads/", &desc);


	strbuf_release(&logmsg);
	else
		int slot = LOOKUP_CONFIG(color_branch_slots, slot_name);
			OPTION_CALLBACK, 0, "points-at", &filter.points_at, N_("object"),
		OPT_BIT('D', NULL, &delete, N_("delete branch (even if not merged)"), 2),
	int quiet = 0, unset_upstream = 0;
		if ((filter.kind & FILTER_REFS_BRANCHES) && filter.detached)
			copy_or_rename_branch(argv[0], argv[1], 1, copy > 1);
		}
	} else if (unset_upstream) {
{

	struct strbuf remote = STRBUF_INIT;
static GIT_PATH_FUNC(edit_description, "EDIT_DESCRIPTION")
	/*
	}

		if (column_active(colopts)) {
		if (argc > 1)
		if (ref_exists(oldref.buf))
	BRANCH_COLOR_RESET = 0,
				    new_upstream);
	free_worktrees(worktrees);
		branch_use_color = git_config_colorbool(var, value);
		strbuf_release(&buf);
		return branch_colors[ix];
		die(_("Branch is renamed, but update of config-file failed"));


	const char *shortname;
		strbuf_addf(&remote, "%s%%(refname:lstrip=2)%s%%(if)%%(symref)%%(then) -> %%(symref:short)%%(end)",

	struct strbuf local = STRBUF_INIT;
			copy_or_rename_branch(head, argv[0], 0, rename > 1);
		list = 1;
}
static const char *quote_literal_for_format(const char *s)
				error(_("Cannot delete branch '%s' "

	BRANCH_COLOR_UPSTREAM = 5,
		}
		else

				"         '%s', even though it is merged to HEAD."),
	return max;
		git_config_set_multivar(buf.buf, NULL, NULL, 1);
	}
	struct strbuf buf = STRBUF_INIT;
			       : find_unique_abbrev(&oid, DEFAULT_ABBREV));
			      0, 0, 0, quiet, BRANCH_TRACK_OVERRIDE);
		die(_("Branch renamed to %s, but HEAD is not updated!"), newname);
	return 0;

	if (!!delete + !!rename + !!copy + !!new_upstream + !!show_current +

	if (filter->kind != FILTER_REFS_REMOTES)
}
				interpreted_oldname);
			branch_get_color(BRANCH_COLOR_LOCAL));
		die(_("Branch is copied, but update of config-file failed"));
	}
			branch_name = argv[0];
	struct object_id oid;
	struct ref_sorting **sorting_tail = (struct ref_sorting **)cb;
}
					| RESOLVE_REF_NO_RECURSE
		    check_branch_commit(bname.buf, name, &oid, head_rev, kinds,

			      argv[0], (argc == 2) ? argv[1] : head,
			return config_error_nonbool(var);
			continue;
	track = git_branch_track;
	if (!force && !branch_merged(kinds, branchname, rev, head_rev)) {
		/*
					&oid, &flags);

		} else {
	format->use_color = branch_use_color;
	}

	    in_merge_bases(rev, head_rev) != merged) {
	strbuf_release(&oldref);
		strbuf_addf(&buf, "branch.%s.merge", branch->name);
static void delete_branch_config(const char *branchname)

		OPT_BIT('m', "move", &rename, N_("move/rename a branch and its reflog"), 1),
		},
			 struct commit *rev, struct commit *head_rev)
		OPT_WITH(&filter.with_commit, N_("print only branches that contain the commit")),
	if (filter->verbose)
		 */
		 * ref that we used to allow to be created by accident.
			const struct worktree *wt =
		OPT_BOOL('l', "list", &list, N_("list branch names")),
		allowed_interpret = INTERPRET_BRANCH_REMOTE;
	for (i = 0; i < refs->nr; i++) {
		strbuf_addf(&logmsg, "Branch: renamed %s to %s",
		OPT_BOOL(0, "show-current", &show_current, N_("show current branch name")),
	const char *refname = resolve_ref_unsafe("HEAD", 0, NULL, &flags);

 *
	if (!head)
		OPT_COLUMN(0, "column", &colopts, N_("list branches in columns")),
		filter.name_patterns = argv;
			BRANCH_TRACK_OVERRIDE, PARSE_OPT_HIDDEN),

	    !skip_prefix(newref.buf, "refs/heads/", &interpreted_newname)) {
	[BRANCH_COLOR_UPSTREAM] = "upstream",
	GIT_COLOR_GREEN,        /* CURRENT */
#include "commit.h"
		warning(_("Update of config-file failed"));
			strbuf_release(&branch_ref);
	 * This checks whether the merge bases of branch and HEAD (or

	for (i = 0; i < argc; i++, strbuf_reset(&bname)) {
		    branch_name, comment_line_char);
			    "%%(if)%%(symref)%%(then) -> %%(symref:short)"
		if (edit_branch_description(branch_name))
		}
			       bname.buf,
}
#include "revision.h"
static int edit_branch_description(const char *branch_name)
	else
	case FILTER_REFS_REMOTES:
			char *head_desc = get_head_description();
		int flags = 0;
		create_branch(the_repository, branch->name, new_upstream,
		error(_("The branch '%s' is not fully merged.\n"
		delete *= 2;
		free(name);
	 * return the result of the in_merge_bases() above without
		return;
				die(_("could not set upstream of HEAD to %s when "
	struct strbuf oldsection = STRBUF_INIT, newsection = STRBUF_INIT;
	if (!strcmp(var, "branch.sort")) {
		print_columns(&output, colopts, NULL);
#include "wt-status.h"
	N_("git branch [<options>] [-r | -a] [--points-at]"),
	BRANCH_COLOR_WORKTREE = 6
	 * upstream, if any, otherwise with HEAD", we should just
			die(_("too many arguments to set new upstream"));
		      "  %s\n"
			if (wt) {
		strbuf_addf(&branch_ref, "refs/heads/%s", branch_name);

	 * a gentle reminder is in order.
			w = utf8_strwidth(head_desc);
		OPT_GROUP(N_("Generic options")),
static const char *head;
		if (format_ref_array_item(array.items[i], format, &out, &err))
	return 0;

	const char *interpreted_newname = NULL;
		list = 1;
	if (verify_ref_format(format))
		} else {
		if (w > max)

	int maxwidth = 0;
				      bname.buf, wt->path);
	}

static int branch_merged(int kind, const char *name,
			branch_name = head;
	strbuf_release(&buf);
					force)) {
		const char *upstream = branch_get_upstream(branch, NULL);
			error(remote_branch
	write_file_buf(edit_description(), buf.buf, buf.len);
		filter.abbrev = DEFAULT_ABBREV;
		}
		strbuf_addf(&local, "%%(refname:lstrip=2)%s%%(if)%%(symref)%%(then) -> %%(symref:short)%%(end)",

	else if (!(flags & REF_ISSYMREF))
		puts(shortname);
}
		if (!value)
	strbuf_release(&buf);
	 */
			die(_("branch name required"));
			N_("show hash and subject, give twice for upstream branch")),
			       const struct object_id *oid, struct commit *head_rev,
	GIT_COLOR_CYAN,         /* WORKTREE */
		filter.detached = 1;
		return 0;
	int i;
			die(_("branch '%s' does not exist"), branch->name);
	if (filter.verbose) {
		if (filter->abbrev < 0)

			return 1;
	const char *interpreted_oldname = NULL;
		validate_new_branchname(newname, &newref, force);
	else if (skip_prefix(refname, "refs/heads/", &shortname))
		OPT_BOOL('i', "ignore-case", &icase, N_("sorting and filtering are case insensitive")),
		else if (argc == 2)
	return ret;
		OPT_BOOL(0, "unset-upstream", &unset_upstream, N_("unset the upstream info")),
		strbuf_release(&err);
		 * branches 'refs/remotes/...'.
}
	int icase = 0;

			    branch_get_color(BRANCH_COLOR_RESET), obname.buf);
		 * info and making sure new_upstream is correct
			continue;
	head = resolve_refdup("HEAD", 0, &head_oid, NULL);

				  "Did you mean to use: -a|-r --list <pattern>?"));
			die(_("branch name required"));
		{
	if (!force) {
	if (copy && strcmp(oldname, newname) && git_config_copy_section(oldsection.buf, newsection.buf) < 0)
		usage_with_options(builtin_branch_usage, options);
	[BRANCH_COLOR_RESET]	= "reset",
{
	int recovery = 0;
static void print_current_branch_name(void)
			return config_error_nonbool(var);
			if (!argc)
	GIT_COLOR_RESET,
		strbuf_addf(&logmsg, "Branch: copied %s to %s",
	}
		struct worktree *wt = worktrees[i];
		} else
	 */
		copy *= 2;
	if (!strcmp(var, "color.branch")) {
		return 0;
	if (!copy && rename_ref(oldref.buf, newref.buf, logmsg.buf))

	next:
			if (!argc || !strcmp(argv[0], "HEAD"))
			ret = 1;
			       : (flags & REF_ISSYMREF) ? target
#include "config.h"

		if (copy)
#include "refs.h"
		delete_branch_config(bname.buf);
	static struct strbuf buf = STRBUF_INIT;
	}
	const char *new_upstream = NULL;
};
		 * by 'refname'. This would give us an alphabetically sorted
static char *build_format(struct ref_filter *filter, int maxwidth, const char *remote_prefix)

	struct ref_array array;

		strbuf_release(&buf);
		if (it->kind == FILTER_REFS_REMOTES)
			copy_or_rename_branch(argv[0], argv[1], 0, rename > 1);
			strbuf_add(&buf, s, ep - s);
			goto next;
			die(_("branch name required"));
{
	if (!strcmp(head, "HEAD"))
	strbuf_stripspace(&buf, 1);
			free(head_desc);
		die(_("HEAD (%s) points outside of refs/heads/"), refname);
		maxwidth = calc_maxwidth(&array, strlen(remote_prefix));
		else
		else
				"         '%s', but not yet merged to HEAD."),
		if (!ref_exists(branch->refname))
	int i;
	int flags;
		if (!argc) {
	struct commit *rev = lookup_commit_reference(the_repository, oid);
#include "column.h"
			else
		 * Bad name --- this could be an attempt to rename a
	} else if (list) {
			strbuf_addf(&local, "%%(if)%%(upstream)%%(then)[%s%%(upstream:short)%s%%(if)%%(upstream:track)"
	if ((head_rev != reference_rev) &&
	if (!oldname) {
		 * local branches 'refs/heads/...' and finally remote-tracking
			s = ep + 1;
		OPT__ABBREV(&filter.abbrev),
	}
		strbuf_release(&obname);
		strbuf_addch(&buf, '\n');
	else if (!skip_prefix(head, "refs/heads/", &head))
		reference_rev = head_rev;
	 * the other branch this branch builds upon) contains the

	 * We need to account for this in the width.
			warning(_("Renamed a misnamed branch '%s' away"),

		struct strbuf out = STRBUF_INIT;
{
{

		struct strbuf buf = STRBUF_INIT;
		/*  git branch --local also shows HEAD when it is detached */
	if (!rev) {
		if (kinds == FILTER_REFS_BRANCHES) {

			      ? _("remote-tracking branch '%s' not found.")
static const char * const builtin_branch_usage[] = {

	 * safely to HEAD (or the other branch).
	strbuf_addf(&fmt, "%%(if:notequals=refs/remotes)%%(refname:rstrip=-2)%%(then)%s%%(else)%s%%(end)", local.buf, remote.buf);
define_list_config_array(color_branch_slots);

	if (filter->verbose) {
					| RESOLVE_REF_ALLOW_BAD_NAME,
	BRANCH_COLOR_REMOTE = 2,
	struct commit *reference_rev = NULL;
		die(_("cannot use -a with -d"));

}
	struct ref_format format = REF_FORMAT_INIT;
{
			die(_("Branch '%s' has no upstream information"), branch->name);
					RESOLVE_REF_READING
	return 0;

	 * any of the following code, but during the transition period,
				ret = 1;
			    maxwidth, quote_literal_for_format(remote_prefix),
	 * A command like "git branch -M currentbranch currentbranch" cannot
	strbuf_release(&remote);
		die(_("HEAD not found below refs/heads!"));
			warning(_("Created a copy of a misnamed branch '%s'"),
			strbuf_addf(&local, "%%(if)%%(upstream:track)%%(then)%%(upstream:track) %%(end)%%(contents:subject)");
		OPT_BIT('c', "copy", &copy, N_("copy a branch and its reflog"), 1),
	free(name);
	strbuf_release(&bname);
	memset(&array, 0, sizeof(array));

	BRANCH_COLOR_CURRENT = 4,
		OPT_BIT('C', NULL, &copy, N_("copy a branch, even if target exists"), 2),
					"checked out at '%s'"),
			    target, wt->path);

}
			strbuf_addf(&obname, "%%(objectname:short)");

	struct ref_filter filter;
		OPT_MERGED(&filter, N_("print only branches that are merged")),
			      ? _("Error deleting remote-tracking branch '%s'")
		strbuf_reset(&buf);
		}
		 * create_branch takes care of setting up the tracking
	if (starts_with(var, "column."))
	struct option options[] = {
	char *name = NULL;

				return error(_("No branch named '%s'."),
	} else if (rename) {
{
			      force, 0, reflog, quiet, track);
		print_current_branch_name();
};
		if (track == BRANCH_TRACK_OVERRIDE)
	strbuf_release(&newref);
		if (filter->verbose > 1)


	git_config(git_branch_config, sorting_tail);
			die(_("The -a, and -r, options to 'git branch' do not take a branch name.\n"
				    "%%(then): %%(upstream:track,nobracket)%%(end)] %%(end)%%(contents:subject)",
	BRANCH_COLOR_PLAIN = 1,
		else if (argc == 2)
	reject_rebase_or_bisect_branch(oldref.buf);
{
