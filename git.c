		/*
	{ "whatchanged", cmd_whatchanged, RUN_SETUP },
	{ "remote-fd", cmd_remote_fd, NO_PARSEOPT },
			(*argv)++;
	}
			struct child_process child = CHILD_PROCESS_INIT;
	if (!cmd)
			if (*argc < 2) {
static int handle_alias(int *argcp, const char ***argv)
			strbuf_add(&sb, spec + 5, len - 5);
		setup_work_tree();
	{ "write-tree", cmd_write_tree, RUN_SETUP },
			    _(split_cmdline_strerror(count)));
	if (use_pager == -1)
static int list_cmds(const char *spec)


	 */
	 * If we fail because the command is not found, it is
	/*
	{ "fetch-pack", cmd_fetch_pack, RUN_SETUP | NO_PARSEOPT },
		else if (p->option & RUN_SETUP_GENTLY) {
	return !!get_builtin(s);
	if (fflush(stdout))
			 * and exiting.  Log a generic string as the trace2
	return 1;

	{ "check-attr", cmd_check_attr, RUN_SETUP },
		} else if (!strcmp(cmd, "--man-path")) {
		} else if (!strcmp(cmd, "-c")) {
			i = run_command_v_opt_tr2(args.argv, RUN_SILENT_EXEC_FAILURE |
{

	if (fclose(stdout))
	{ "read-tree", cmd_read_tree, RUN_SETUP | SUPPORT_SUPER_PREFIX},
				usage(git_usage_string);

	N_("'git help -a' and 'git help -g' list available subcommands and some\n"
		exit(1);

	cmd = argv[0];
			      "You can use '!git' in the alias to do this"),
	*/
}
		if (exclude_option &&
			setenv(GIT_OPTIONAL_LOCKS_ENVIRONMENT, "0", 1);
					strbuf_addstr(&sb, " <==");
		/* insert after command name */
	struct argv_array args = ARGV_ARRAY_INIT;
	{ "cherry-pick", cmd_cherry_pick, RUN_SETUP | NEED_WORK_TREE },
			struct argv_array args = ARGV_ARRAY_INIT;
	{ "name-rev", cmd_name_rev, RUN_SETUP },
			if (envchanged)
	 */
			if (*argc < 2) {
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
	const char *cmd;
		if (alias_string[0] == '!') {
	}
	int status, help;
			done_help = 1;
	{ "archive", cmd_archive, RUN_SETUP_GENTLY },

			struct strbuf sb = STRBUF_INIT;


	argv++;

			spec++;
	int i = 0;

		trace2_cmd_alias(alias_command, new_argv);
	{ "revert", cmd_revert, RUN_SETUP | NEED_WORK_TREE },
	setup_git_directory_gently(&nongit);
			if (*argc < 2) {
			trace2_cmd_list_config();
			strbuf_release(&sb);
		else if (len > 5 && !strncmp(spec, "list-", 5)) {
					*envchanged = 1;
	* completion.commands).
	{ "describe", cmd_describe, RUN_SETUP },
	if (builtin)
		die_errno(_("write failure on standard output"));
			die(_("alias loop detected: expansion of '%s' does"
	{ "show-ref", cmd_show_ref, RUN_SETUP },
	int i;
		new_argv -= option_count;

				*envchanged = 1;
			exit(0);
	}
		if (cmd[0] != '-')
	{ "remote-ext", cmd_remote_ext, NO_PARSEOPT },
				struct string_list_item *item = &cmd_list.items[i];
			child.use_shell = 1;
				puts(git_exec_path());
		die(_("unknown write failure on standard output"));
	{ "merge-recursive", cmd_merge_recursive, RUN_SETUP | NEED_WORK_TREE | NO_PARSEOPT },
	int done_alias = 0;
		trace_argv_printf(new_argv,
	{ "column", cmd_column, RUN_SETUP_GENTLY },
}
	return 0;
	trace2_cmd_list_env_vars();
	trace2_cmd_name(p->cmd);
}
			trace2_cmd_name("_query_");
	{ "fmt-merge-msg", cmd_fmt_merge_msg, RUN_SETUP },
		 */
			break;
#ifdef STRIP_EXTENSION
	{ "send-pack", cmd_send_pack, RUN_SETUP },


	{ "add", cmd_add, RUN_SETUP | NEED_WORK_TREE },
			trace2_cmd_alias(alias_command, child.args.argv);
		RUN_SETUP | NEED_WORK_TREE},
	 * If the child process ran and we are now going to exit, emit a
	{ "patch-id", cmd_patch_id, RUN_SETUP_GENTLY | NO_PARSEOPT },
				exit(i);
	} else {
			int i;
		argv[0] = xmemdupz(argv[0], len);
#define USE_PAGER		(1<<2)
			argv_array_push(&child.args, alias_string + 1);
	return 0;

		} else if (!strcmp(cmd, "-C")) {
	{ "interpret-trailers", cmd_interpret_trailers, RUN_SETUP_GENTLY },

				*envchanged = 1;
	}
	}
				fprintf(stderr, _("no directory given for -C\n" ));
		MOVE_ARRAY(new_argv - option_count, new_argv, count);
			setenv(GIT_WORK_TREE_ENVIRONMENT, (*argv)[1], 1);
int is_builtin(const char *s)
			if (envchanged)
			list_cmds_by_category(&list, sb.buf);
	}
static void handle_builtin(int argc, const char **argv)
	trace2_cmd_list_config();
		argc++;
			if (envchanged)
			    alias_command);
	{ "merge-index", cmd_merge_index, RUN_SETUP | NO_PARSEOPT },
			list_all_other_cmds(&list);
	{ "unpack-objects", cmd_unpack_objects, RUN_SETUP | NO_PARSEOPT },
		} else if (skip_prefix(cmd, "--namespace=", &cmd)) {

					die_errno("cannot change to '%s'", (*argv)[1]);
		if (seen) {

				string_list_clear(&list, 0);
				exit(ret);
		} else if (skip_prefix(cmd, "--git-dir=", &cmd)) {

			(*argv)++;
			(*argc)--;
	{ "cherry", cmd_cherry, RUN_SETUP },
	commit_pager_choice();
		count = split_cmdline(alias_string, &new_argv);
			return p;
	argc--;
		const char *sep = strchrnul(spec, ',');
	{ "annotate", cmd_annotate, RUN_SETUP | NO_PARSEOPT },
	if (ferror(stdout))
			trace2_cmd_name("_query_");

	{ "count-objects", cmd_count_objects, RUN_SETUP },
	int count, option_count;
	}
			break;
		else if (match_token(spec, len, "alias"))
				*envchanged = 1;
			 * process will log the actual verb when it runs.
			if (*argc < 2) {
		ret = 1;
#define SUPPORT_SUPER_PREFIX	(1<<4)
		string_list_append(&cmd_list, *argv[0]);
		const char *cmd = (*argv)[0];
};
		break;
	{ "verify-tag", cmd_verify_tag, RUN_SETUP },
		*argcp += count - 1;
	{ "merge-recursive-ours", cmd_merge_recursive, RUN_SETUP | NEED_WORK_TREE | NO_PARSEOPT },
	{ "cat-file", cmd_cat_file, RUN_SETUP },
		done_alias = 1;
		return 0;
		if (strstr(list->items[i].string, "--"))
const char git_usage_string[] =
		argv[0] = cmd;
			prefix = setup_git_directory_gently(&nongit_ok);
		if (match_token(spec, len, "builtins"))

			 * command verb to indicate this.  Note that the child
	{ "rebase--interactive", cmd_rebase__interactive, RUN_SETUP | NEED_WORK_TREE },
void setup_auto_pager(const char *cmd, int def)
	{ "show-branch", cmd_show_branch, RUN_SETUP },
				argv_array_push(&args, (*argv)[i]);
	strip_extension(argv);
			i++;
#define strip_extension(cmd)
		 * general.  We have to spawn them as dashed externals.
	{ "shortlog", cmd_shortlog, RUN_SETUP_GENTLY | USE_PAGER },
		exit(status);
		} else if (!strcmp(cmd, "--glob-pathspecs")) {
	if (argc > 0) {
			puts(system_path(GIT_HTML_PATH));
	{ "upload-archive--writer", cmd_upload_archive_writer, NO_PARSEOPT },
				fprintf(stderr, _("no namespace given for --namespace\n" ));
		execv_dashed_external(*argv);
		 * alias.log = show
			unsorted_string_list_delete_item(list, i, 0);
			if (get_super_prefix())
	   "           [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]\n"
		die_errno(_("close failed on standard output"));
		if (!handle_alias(argcp, argv))
		 * If we tried alias and futzed with our environment,
	size_t len;
		int was_alias = run_argv(&argc, &argv);
	case 1:

	{ "diff-files", cmd_diff_files, RUN_SETUP | NEED_WORK_TREE | NO_PARSEOPT },
	{ "switch", cmd_switch, RUN_SETUP | NEED_WORK_TREE },
			die(_("empty alias for %s"), alias_command);
		(*argv)++;

	{ "stripspace", cmd_stripspace },


	{ "prune-packed", cmd_prune_packed, RUN_SETUP },
	while (1) {
}

#include "config.h"
		if (count < 0)
		for (i = 0; i < argc; i++) {
			setenv(GIT_NOGLOB_PATHSPECS_ENVIRONMENT, "1", 1);
	int token_len = strlen(token);
	const char *alias_command;
const char git_more_info_string[] =
	{ "stage", cmd_add, RUN_SETUP | NEED_WORK_TREE },

	{ "worktree", cmd_worktree, RUN_SETUP | NO_PARSEOPT },
			(*argv)++;
			exit(0);
		} else if (!strcmp(cmd, "-P") || !strcmp(cmd, "--no-pager")) {
			int nongit_ok;

	struct stat st;
	/* Ignore write errors for pipes and sockets.. */
		use_pager = def;
	for (i = 0; i < list.nr; i++)
	const char *prefix;
#define RUN_SETUP		(1<<0)
		skip_prefix(argv[0], "--", &argv[0]);
	{ "clean", cmd_clean, RUN_SETUP | NEED_WORK_TREE },
		printf("\n%s\n", _(git_more_info_string));
}

		(*argc)--;
		 *

{
	}
	trace_argv_printf(argv, "trace: built-in: git");
	{ "var", cmd_var, RUN_SETUP_GENTLY | NO_PARSEOPT },
{

			int nongit_ok;
	case 0:
			usage(git_usage_string);
		} else if (!strcmp(cmd, "--icase-pathspecs")) {
	use_pager = check_pager_config(cmd);

	{ "help", cmd_help },
	/*
		    !(p->option & DELAY_PAGER_CONFIG))
}
			(*argv)++;
	   "concept guides. See 'git help <command>' or 'git help <concept>'\n"
			argv_array_pushv(&child.args, (*argv) + 1);
	 */
		if (envchanged)
	if (use_pager != -1 || pager_in_use())
			list_cmds_by_config(&list);
		} else if (!strcmp(cmd, "--literal-pathspecs")) {
		const char *slash = find_last_dir_sep(cmd);
			die(_("bad alias.%s string: %s"), alias_command,
		seen = unsorted_string_list_lookup(&cmd_list, *argv[0]);
	alias_command = (*argv)[0];
			setenv(GIT_DIR_ENVIRONMENT, cwd, 0);
	int done_help = 0;

	{ "update-server-info", cmd_update_server_info, RUN_SETUP },
	if (use_pager == -1 && !is_builtin(argv[0]))
	 * time.


	{ "merge-tree", cmd_merge_tree, RUN_SETUP | NO_PARSEOPT },
	{ "merge-recursive-theirs", cmd_merge_recursive, RUN_SETUP | NEED_WORK_TREE | NO_PARSEOPT },
	if (argc > 1 && !strcmp(argv[1], "--help")) {
				struct string_list list = STRING_LIST_INIT_DUP;
	{ "difftool", cmd_difftool, RUN_SETUP_GENTLY },
	return ret;
		option_count = handle_options(&new_argv, &count, &envchanged);
		}

		exit(run_builtin(builtin, argc, argv));

	   "           <command> [<args>]");
	{ "rebase", cmd_rebase, RUN_SETUP | NEED_WORK_TREE },
		} else if (skip_prefix(cmd, "--super-prefix=", &cmd)) {

				if (item == seen)
	{ "remote", cmd_remote, RUN_SETUP },
	help = argc == 2 && !strcmp(argv[1], "-h");

		argv[1] = argv[0];
		 * commands can be written with "--" prepended
	{ "pack-redundant", cmd_pack_redundant, RUN_SETUP | NO_PARSEOPT },
			use_pager = 1;
	/* Turn "git cmd --help" into "git help --exclude-guides cmd" */
	{ "rm", cmd_rm, RUN_SETUP },
	{ "format-patch", cmd_format_patch, RUN_SETUP },
	 * the program.
static void execv_dashed_external(const char **argv)
		} else if (!strcmp(cmd, "--shallow-file")) {
	return NULL;

	if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode))
	{ "clone", cmd_clone },
	validate_cache_entries(the_repository->index);
	const char *cmd;
	errno = saved_errno;
	{ "merge-file", cmd_merge_file, RUN_SETUP_GENTLY },
static void strip_extension(const char **argv)
				exit(list_cmds(cmd));
			setenv(GIT_NAMESPACE_ENVIRONMENT, (*argv)[1], 1);
	}
				fprintf(stderr, _("no directory given for --git-dir\n" ));
	{ "apply", cmd_apply, RUN_SETUP_GENTLY },
	{ "diff-tree", cmd_diff_tree, RUN_SETUP | NO_PARSEOPT },
	 * launched a dashed command.
	}
		cmd, strerror(errno));
#define NEED_WORK_TREE		(1<<3)

	}
	if (status >= 0)
				usage(git_usage_string);
			if ((*argv)[1][0]) {
			}
				*envchanged = 1;

		break;
			if (envchanged)
				die("%s doesn't support --super-prefix", **argv);
				usage(git_usage_string);
		setup_pager();
			die_errno(_("while expanding alias '%s': '%s'"),
				*envchanged = 1;
			(*argv)++;
{
		else if (match_token(spec, len, "config"))
		}
#define DELAY_PAGER_CONFIG	(1<<5)
{
		if (!strcmp(cmd, "--help") || !strcmp(cmd, "--version"))
		trace2_cmd_list_env_vars();
	else {
	switch (use_pager) {

			struct strbuf sb = STRBUF_INIT;
			for (i = 0; i < *argcp; i++)
	if (!help && p->option & NEED_WORK_TREE)
		} else if (!strcmp(cmd, "--super-prefix")) {
#define RUN_SETUP_GENTLY	(1<<1)

			setenv(GIT_LITERAL_PATHSPECS_ENVIRONMENT, "1", 1);
			if (envchanged)
	{ "reset", cmd_reset, RUN_SETUP },
		spec += len;
	return done_alias;
				trace2_cmd_name("_query_");

};
		if (was_alias) {
{
				*envchanged = 1;
{
	{ "update-ref", cmd_update_ref, RUN_SETUP },
			 * child process to run the command named in (**argv)
		if (!done_alias)

#define NO_PARSEOPT		(1<<6) /* parse-options is not used */

	{ "version", cmd_version },
	 * generic string as our trace2 command verb to indicate that we
			git_config_push_parameter((*argv)[1]);
	{ "show", cmd_show, RUN_SETUP },
		if (!(p->option & SUPPORT_SUPER_PREFIX))
	{ "checkout", cmd_checkout, RUN_SETUP | NEED_WORK_TREE },

	{ "diff", cmd_diff, NO_PARSEOPT },
		 */
	{ "env--helper", cmd_env__helper },
		} else if (!strcmp(cmd, "--work-tree")) {
	while (*argc > 0) {
static int use_pager = -1;
			/* Aliases expect GIT_PREFIX, GIT_DIR etc to be set */
			(*argc)--;
				if (envchanged)
	int i;
 */

#else
	{ "gc", cmd_gc, RUN_SETUP },
	alias_string = alias_lookup(alias_command);
			handle_builtin(*argcp, *argv);
				fprintf(stderr, _("no prefix given for --super-prefix\n" ));
	const char *cmd;
				list_builtins(&list, NO_PARSEOPT);
	commit_pager_choice();
		if (errno != ENOENT)
{

	if (status)
			if (*cmd == '=')
	cmd = argv[0];
				*envchanged = 1;
}
	{ "grep", cmd_grep, RUN_SETUP_GENTLY },
		puts(list.items[i].string);
			fprintf(stderr, _("unknown option: %s\n"), cmd);
 * require working tree to be present -- anything uses this needs
			if (envchanged)
	if (!help) {
			cmd = slash + 1;
					  "'%s' is not a git command\n"),
			if (envchanged)
		COPY_ARRAY(new_argv + count, *argv + 1, *argcp);
			if (envchanged)
			if (!i)
				if (chdir((*argv)[1]))
	}
		 * it no longer is safe to invoke builtins directly in
}
			}
		die(_("cannot handle %s as a builtin"), cmd);
	fprintf(stderr, _("failed to run command '%s': %s\n"),
		argv[0] = cmd = "help";
			break;

	commit_pager_choice();
			list_builtins(&list, 0);
			commit_pager_choice();

				*envchanged = 1;
	argv_array_clear(&args);

		if (use_pager == -1 && p->option & (RUN_SETUP | RUN_SETUP_GENTLY) &&
			trace_argv_printf(args.argv, "trace: exec:");

		if (!strcmp(s, p->cmd))
			if (envchanged)
			trace2_cmd_list_env_vars();
	struct string_list_item *seen;
	 * The code in run_command() logs trace2 child_start/child_exit

		/* The user didn't specify a command; give them help */

static void exclude_helpers_from_list(struct string_list *list)
			if (envchanged)
	{ "mktree", cmd_mktree, RUN_SETUP },

	 * environment, and the $(gitexecdir) from the Makefile at build
	{ "fast-export", cmd_fast_export, RUN_SETUP },
	{ "bundle", cmd_bundle, RUN_SETUP_GENTLY | NO_PARSEOPT },
	{ "upload-archive", cmd_upload_archive, NO_PARSEOPT },
	{ "am", cmd_am, RUN_SETUP | NEED_WORK_TREE },
	/*
		/* translate --help and --version into commands */
				argv_array_push(&args, "--exclude-guides");
			 */
			trace2_cmd_name("_query_");
	cmd = argv[0];
#include "alias.h"
						  RUN_CLEAN_ON_EXIT, "git_alias");
	{ "sparse-checkout", cmd_sparse_checkout, RUN_SETUP | NEED_WORK_TREE },
	{ "init", cmd_init_db },
	{ "range-diff", cmd_range_diff, RUN_SETUP | USE_PAGER },
			if (*argc < 2) {
	string_list_clear(&list, 0);
			(*argc)--;
				   alias_command, alias_string);
		argv = args.argv;
			      " not terminate:%s"), cmd_list.items[0].string, sb.buf);
	{ "log", cmd_log, RUN_SETUP },
		 * Check remaining flags.
	{ "diff-index", cmd_diff_index, RUN_SETUP | NO_PARSEOPT },
	cmd.silent_exec_failure = 1;
	struct child_process cmd = CHILD_PROCESS_INIT;
	{ "merge-base", cmd_merge_base, RUN_SETUP },
			if (envchanged)
	/* Somebody closed stdout? */

				*envchanged = 1;
				  alias_command, alias_string + 1);
	{ "bisect--helper", cmd_bisect__helper, RUN_SETUP },
			} else {
	 * "git-xxxx" is the same as "git xxxx", but we obviously:
	{ "merge-ours", cmd_merge_ours, RUN_SETUP | NO_PARSEOPT },
		} else if (!strcmp(cmd, "-p") || !strcmp(cmd, "--paginate")) {
			ret = run_command(&child);
	default:
		} else if (skip_prefix(cmd, "--list-cmds=", &cmd)) {
		printf(_("usage: %s\n\n"), git_usage_string);
	handle_options(&argv, &argc, NULL);
	int nongit;
	const char **orig_argv = *argv;

	return (*argv) - orig_argv;
				usage(git_usage_string);
				int i;
}
		else if (match_token(spec, len, "nohelpers"))

		else if (match_token(spec, len, "main"))
	while (i < list->nr) {
			cmd = argv[0] = help_unknown_cmd(cmd);
	 *  - cannot take flags in between the "git" and the "xxxx".
			read_replace_refs = 0;
	{ "mailsplit", cmd_mailsplit, NO_PARSEOPT },
	unsigned int option;
/*
	const char **new_argv;
	trace_argv_printf(cmd.args.argv, "trace: exec:");
			setenv(GIT_DIR_ENVIRONMENT, (*argv)[1], 1);
			exclude_helpers_from_list(&list);
	/*
	{ "config", cmd_config, RUN_SETUP_GENTLY | DELAY_PAGER_CONFIG },
	{ "commit-graph", cmd_commit_graph, RUN_SETUP },

	{ "pack-objects", cmd_pack_objects, RUN_SETUP },
	if (skip_prefix(cmd, "git-", &cmd)) {

	{ "check-mailmap", cmd_check_mailmap, RUN_SETUP },
}
			commit_pager_choice();
{

			setenv(GIT_ICASE_PATHSPECS_ENVIRONMENT, "1", 1);
#include "help.h"
static int handle_options(const char ***argv, int *argc, int *envchanged)
				*envchanged = 1;
	argv_array_pushv(&cmd.args, argv + 1);
		}
			trace2_cmd_name("_query_");
		} else if (!strcmp(cmd, "--git-dir")) {
	int (*fn)(int, const char **, const char *);
			setup_git_directory_gently(&nongit_ok);
			die(_("%s doesn't support --super-prefix"), p->cmd);
{
			if (i >= 0 || errno != ENOENT)
		if (p->option & RUN_SETUP)
				*envchanged = 1;
		 * For legacy reasons, the "version" and "help"
	cmd.wait_after_clean = 1;


			}
			}
			(*argc)--;
	   "           [--git-dir=<path>] [--work-tree=<path>] [--namespace=<name>]\n"
	   "to read about a specific subcommand or concept.\n"
	return len == token_len && !strncmp(spec, token, token_len);
			child.trace2_child_class = "shell_alias";
		/*
		else if (get_builtin(**argv)) {
static void commit_pager_choice(void)
	{ "tag", cmd_tag, RUN_SETUP | DELAY_PAGER_CONFIG },
	 */
	setup_path();
	/* Look for flags.. */
				*envchanged = 1;
					strbuf_addstr(&sb, " ==>");
		 * NEEDSWORK: if we can figure out cases
				  "trace: alias expansion: %s =>",
	else if (errno != ENOENT)
#include "builtin.h"
				*envchanged = 1;
		int i;
{

				fprintf(stderr, _("-c expects a configuration string\n" ));
		cmd = "git-help";
			(*argv)++;
	{ "init-db", cmd_init_db },
			argv_array_push(&args, "git");
		if (slash)
	 * OK to return. Otherwise, we just pass along the status code,
		} else if (!strcmp(cmd, "--no-literal-pathspecs")) {
			 * The current process is committed to launching a
}
	int envchanged = 0, ret = 0, saved_errno = errno;
				exit(0);
			if (envchanged)
			 * OK to return. Otherwise, we just pass along the status code.
		*argv = new_argv;
	{ "verify-pack", cmd_verify_pack },
	{ "pack-refs", cmd_pack_refs, RUN_SETUP },

	{ "rev-parse", cmd_rev_parse, NO_PARSEOPT },
		REALLOC_ARRAY(new_argv, count + *argcp);
			char *cwd = xgetcwd();
			(*argv)++;
			if (!strcmp(cmd, "parseopt")) {
	{ "for-each-ref", cmd_for_each_ref, RUN_SETUP },
		 */
static struct cmd_struct commands[] = {

			puts(system_path(GIT_INFO_PATH));
	* Set up the repository so we can pick up any repo-level config (like
			setenv(GIT_GLOB_PATHSPECS_ENVIRONMENT, "1", 1);
			exit(0);
	 * or our usual generic code if we were not even able to exec
			/*
	{ "receive-pack", cmd_receive_pack },
	{ "show-index", cmd_show_index },
	cmd.trace2_child_class = "dashed";
	 * So we just directly call the builtin handler, and die if
			setenv(GIT_SUPER_PREFIX_ENVIRONMENT, cmd, 1);
		string_list_append(out, commands[i].cmd);
	int status;

				*envchanged = 1;
		} else if (!strcmp(cmd, "--bare")) {
{

				for (i = 0; i < list.nr; i++)
		} else if (!strcmp(cmd, "--no-optional-locks")) {
		int len = sep - spec;
			 */
	{ "check-ref-format", cmd_check_ref_format, NO_PARSEOPT  },
	{ "get-tar-commit-id", cmd_get_tar_commit_id, NO_PARSEOPT },
			fprintf_ln(stderr, _("'%s' is aliased to '%s'"),
	struct string_list cmd_list = STRING_LIST_INIT_NODUP;
	{ "multi-pack-index", cmd_multi_pack_index, RUN_SETUP_GENTLY },

static int match_token(const char *spec, int len, const char *token)

	{ "check-ignore", cmd_check_ignore, RUN_SETUP | NEED_WORK_TREE },
		commit_pager_choice();
	trace2_cmd_name("_run_dashed_");
		}

	{ "fsck", cmd_fsck, RUN_SETUP },
			setenv(NO_REPLACE_OBJECTS_ENVIRONMENT, "1", 1);
	status = run_command(&cmd);
		handle_builtin(argc, argv);
			die(_("unsupported command listing type '%s'"), spec);
	N_("git [--version] [--help] [-C <path>] [-c <name>=<value>]\n"
			setenv(GIT_NAMESPACE_ENVIRONMENT, cmd, 1);

			int i;
			for (i = 0; i < cmd_list.nr; i++) {
	 * precedence paths: the "--exec-path" option, the GIT_EXEC_PATH

	{ "branch", cmd_branch, RUN_SETUP | DELAY_PAGER_CONFIG },
		list_common_cmds_help();

	/*


			setenv(GIT_DIR_ENVIRONMENT, cmd, 1);
			setenv(GIT_SUPER_PREFIX_ENVIRONMENT, (*argv)[1], 1);
	{ "mailinfo", cmd_mailinfo, RUN_SETUP_GENTLY | NO_PARSEOPT },
			if (ret >= 0)   /* normal exit */
	while (*spec) {
				fprintf(stderr, _("no directory given for --work-tree\n" ));
	{ "rev-list", cmd_rev_list, RUN_SETUP | NO_PARSEOPT },
		} else if (!strcmp(cmd, "--namespace")) {
		exit(128);
		use_pager = check_pager_config(argv[0]);
	{ "replace", cmd_replace, RUN_SETUP },
{
	while (1) {
	{ "rerere", cmd_rerere, RUN_SETUP },
	{ "fetch", cmd_fetch, RUN_SETUP },
		 * to make them look like flags.
			if (envchanged)
	{ "index-pack", cmd_index_pack, RUN_SETUP_GENTLY | NO_PARSEOPT },
		}
				git_set_exec_path(cmd + 1);

	   "See 'git help git' for an overview of the system.");
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
	{ "hash-object", cmd_hash_object },
	{ "pickaxe", cmd_blame, RUN_SETUP },
				*envchanged = 1;
		} else if (!strcmp(cmd, "--no-replace-objects")) {
			/*
			if (envchanged)


		} else if (!strcmp(cmd, "--info-path")) {
		if ((p->option & (RUN_SETUP | RUN_SETUP_GENTLY)) &&
			setenv(GIT_IMPLICIT_WORK_TREE_ENVIRONMENT, "0", 1);
	/*
		} else if (skip_prefix(cmd, "--work-tree=", &cmd)) {

		if (use_pager == -1 && p->option & USE_PAGER)
	{ "blame", cmd_blame, RUN_SETUP },
		} else {
		else
	{ "ls-remote", cmd_ls_remote, RUN_SETUP_GENTLY },
		 */
			if (envchanged)
		}
			}
		trace2_cmd_list_config();
	}

	if (fstat(fileno(stdout), &st))
}
			list_all_main_cmds(&list);
			setenv(GIT_LITERAL_PATHSPECS_ENVIRONMENT, "0", 1);
				else if (i == cmd_list.nr - 1)
			break;
			(*argc)--;
static void list_builtins(struct string_list *list, unsigned int exclude_option);
			if (envchanged)
			argv_array_push(&args, argv[i]);
	validate_cache_entries(the_repository->index);
				usage(git_usage_string);
	trace_command_performance(argv);
	char *alias_string;
				exit(0);

	if (alias_string) {
	{ "status", cmd_status, RUN_SETUP | NEED_WORK_TREE },
	prefix = NULL;
		/*
			trace2_cmd_name("_run_git_alias_");
 * RUN_SETUP for reading from the configuration file.
	{ "commit", cmd_commit, RUN_SETUP | NEED_WORK_TREE },
	{ "notes", cmd_notes, RUN_SETUP },
	{ "mktag", cmd_mktag, RUN_SETUP | NO_PARSEOPT },
	{ "checkout-index", cmd_checkout_index,
	{ "push", cmd_push, RUN_SETUP },
		}
	 * We use PATH to find git commands, but we prepend some higher
	 */
struct cmd_struct {
static int run_builtin(struct cmd_struct *p, int argc, const char **argv)
	{ "stash", cmd_stash, RUN_SETUP | NEED_WORK_TREE },
		if (!done_help) {
	struct string_list list = STRING_LIST_INIT_DUP;

	if (get_super_prefix())
				usage(git_usage_string);
			use_pager = 0;
		    (commands[i].option & exclude_option))
		} else
			break;
					printf("%s ", list.items[i].string);
		} else if (!strcmp(cmd, "--html-path")) {
		die(_("%s doesn't support --super-prefix"), argv[0]);
		 * It could be an alias -- this works around the insanity
}
			is_bare_repository_cfg = 1;
			if (envchanged)
#include "run-command.h"

	   "           [-p | --paginate | -P | --no-pager] [--no-replace-objects] [--bare]\n"
			list_aliases(&list);
	{ "ls-tree", cmd_ls_tree, RUN_SETUP },
				*envchanged = 1;
	cmd.clean_on_exit = 1;
			if (*argc < 2) {
			 * if we fail because the command is not found, it is
		} else if (!strcmp(cmd, "--noglob-pathspecs")) {
	{ "credential", cmd_credential, RUN_SETUP_GENTLY | NO_PARSEOPT },
			}
static void list_builtins(struct string_list *out, unsigned int exclude_option)
int cmd_main(int argc, const char **argv)
	}


		/* .. then try the external ones */
	{ "merge-subtree", cmd_merge_recursive, RUN_SETUP | NEED_WORK_TREE | NO_PARSEOPT },
	{ "commit-tree", cmd_commit_tree, RUN_SETUP | NO_PARSEOPT },
	{ "restore", cmd_restore, RUN_SETUP | NEED_WORK_TREE },
			die(_("alias '%s' changes environment variables.\n"
	int i;
	if (!help && get_super_prefix()) {

				  alias_command);
{
	if (strip_suffix(argv[0], STRIP_EXTENSION, &len))
	{ "ls-files", cmd_ls_files, RUN_SETUP },
			}
		/*
}
			fprintf(stderr, _("expansion of alias '%s' failed; "
	{ "update-index", cmd_update_index, RUN_SETUP },
}
	{ "repack", cmd_repack, RUN_SETUP },

			exit(1);
	argv_array_pushf(&cmd.args, "git-%s", argv[0]);
	}
		return status;
		 * of overriding "git log" with "git show" by having
		setenv("GIT_PAGER", "cat", 1);
		return;
	struct cmd_struct *builtin;
	 * events, so we do not need to report exec/exec_result events here.
			use_pager = check_pager_config(p->cmd);
	{ "upload-pack", cmd_upload_pack },

		else
	 * that one cannot handle it.
	{ "symbolic-ref", cmd_symbolic_ref, RUN_SETUP },
				cmd, argv[0]);
	/* Check for ENOSPC and EIO errors.. */
{
			}
		if (*argcp > 1 && !strcmp((*argv)[1], "-h"))
	{ "verify-commit", cmd_verify_commit, RUN_SETUP },
			trace_repo_setup(prefix);
			(*argc)--;
	 *
				*envchanged = 1;
	{ "merge", cmd_merge, RUN_SETUP | NEED_WORK_TREE },
			continue;

	 *  - cannot execute it externally (since it would just do
			puts(system_path(GIT_MAN_PATH));
		break;
static struct cmd_struct *get_builtin(const char *s)
			trace2_cmd_name("_run_shell_alias_");
	 *
		return 0;
	{ "prune", cmd_prune, RUN_SETUP },
}
				strbuf_addf(&sb, "\n  %s", item->string);
	{ "pull", cmd_pull, RUN_SETUP | NEED_WORK_TREE },
			set_alternate_shallow_file(the_repository, (*argv)[0], 1);
{
			(*argc)--;
		if (count < 1)
			prefix = setup_git_directory();
		}
	{ "submodule--helper", cmd_submodule__helper, RUN_SETUP | SUPPORT_SUPER_PREFIX | NO_PARSEOPT },
	{ "unpack-file", cmd_unpack_file, RUN_SETUP | NO_PARSEOPT },
		 * process.
			die(_("recursive alias: %s"), alias_command);
		struct cmd_struct *p = commands + i;
#endif
		    startup_info->have_repository) /* get_git_dir() may set up repo, avoid that */
			die("could not execute builtin %s", **argv);
	builtin = get_builtin(cmd);
	{ "fsck-objects", cmd_fsck, RUN_SETUP },
	{ "reflog", cmd_reflog, RUN_SETUP },

			setenv(GIT_WORK_TREE_ENVIRONMENT, cmd, 1);
	string_list_clear(&cmd_list, 0);
		if (!strcmp(alias_command, new_argv[0]))
	 *    the same thing over again)
				*envchanged = 1;

			free(cwd);
	{ "mv", cmd_mv, RUN_SETUP | NEED_WORK_TREE },
static int run_argv(int *argcp, const char ***argv)

		else if (match_token(spec, len, "others"))
			use_pager = 1;
		 * where it is safe to do, we can avoid spawning a new
			}
			}

		if (skip_prefix(cmd, "--exec-path", &cmd)) {
		if (*spec == ',')
	status = p->fn(argc, argv, prefix);
#include "exec-cmd.h"
			else {
			if (envchanged)
