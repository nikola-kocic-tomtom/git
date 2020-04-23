#include "exec-cmd.h"
		 * "cmd arg", where "cmd" is a very limited subset of git
		struct strbuf line = STRBUF_INIT;
		} else {
			user_argv[0] = prog;
		}
		fprintf(stderr, "git> ");
}
#define NOLOGIN_COMMAND COMMAND_DIR "/no-interactive-login"
	static const char *help_argv[] = { HELP_COMMAND, NULL };

	/* Test command contains no . or / characters */
	return cmd[strcspn(cmd, "./")] == '\0';
		/* Interactive login disabled. */
	/*
#include "strbuf.h"
		if (status < 0)

		/*
#define COMMAND_DIR "git-shell-commands"
#include "alias.h"
		/* Allow the user to run an interactive shell */
	}
		die("bad argument");
	my_argv[1] = arg;
		if (is_valid_cmd_name(user_argv[0])) {
		free(argv);
		if (access(COMMAND_DIR, R_OK | X_OK) == -1) {
{
		count = split_cmdline(split_args, &argv);
		char *arg;
		argv--;
		} else if (is_valid_cmd_name(prog)) {

	if (count >= 0) {
		die("unrecognized command '%s'", argv[2]);
		 * We do not accept any other modes except "-c" followed by
#include "quote.h"
	my_argv[2] = NULL;
static char *make_cmd(const char *prog)
	if (!skip_prefix(me, "git-", &me))
	{ "git-upload-archive", do_generic_cmd },
		char *rawargs;
}
		const char *argv[] = { NOLOGIN_COMMAND, NULL };
	} else if (argc == 1) {
		cd_to_homedir();
			if (code == -1 && errno == ENOENT) {
		int code;
		switch (prog[len]) {
		die("could not determine user's home directory; HOME is unset");
	cd_to_homedir();
}
		if (strncmp(cmd->name, prog, len))
		}
		case '\0':
		prog = argv[0];

	if (!arg || !(arg = sq_dequote(arg)) || *arg == '-')
static int is_valid_cmd_name(const char *cmd)
		split_args = xstrdup(rawargs);
	int done = 0;

			strbuf_release(&line);
			break;
		run_shell();
	{ NULL },
			continue;
		if (count < 0) {
{

	}
		int status;
int cmd_main(int argc, const char **argv)
	} else {
		free(user_argv);

	char *prog;
			code = run_command_v_opt(argv, RUN_SILENT_EXEC_FAILURE);


			continue;
	return execv_git_cmd(my_argv);
	 * Special hack to pretend to be a CVS server
		 * commands or a command in the COMMAND_DIR
	if (argc == 2 && !strcmp(argv[1], "cvs server")) {
	}
		die("could not chdir to user's home directory");
}
		free(rawargs);
	const char *my_argv[4];
		}
			   !strcmp(prog, "exit") || !strcmp(prog, "bye")) {

{
		int count;
		int len = strlen(cmd->name);
			done = 1;
static int do_generic_cmd(const char *me, char *arg)
			exit(127);
			free(split_args);

		status = run_command_v_opt(argv, 0);
		 */

		die("bad command");
	if (chdir(home) == -1)
static struct commands {
	struct commands *cmd;
			free(full_cmd);
	} while (!done);
	count = split_cmdline(prog, &user_argv);
	int count;
#include "run-command.h"
#include "prompt.h"
			prog = make_cmd(user_argv[0]);
			}
		die("invalid command format '%s': %s", argv[2],
			execv(user_argv[0], (char *const *) user_argv);
		free(prog);
static void cd_to_homedir(void)
	if (!access(NOLOGIN_COMMAND, F_OK)) {
		exit(0);
	return xstrfmt("%s/%s", COMMAND_DIR, prog);
	const char **user_argv;
	{ "git-receive-pack", do_generic_cmd },
{
			arg = prog + len + 1;
			fprintf(stderr, "\n");
		} else if (!strcmp(prog, "quit") || !strcmp(prog, "logout") ||
		    split_cmdline_strerror(count));
		if (!strcmp(prog, "")) {
			break;
		/* Accept "git foo" as if the caller said "git-foo". */
		const char *prog;
} cmd_list[] = {

			die("Interactive git shell is not enabled.\n"
	my_argv[0] = me;
	if (!strncmp(prog, "git", 3) && isspace(prog[3]))
#define HELP_COMMAND COMMAND_DIR "/help"
		rawargs = strbuf_detach(&line, NULL);
	int (*exec)(const char *me, char *arg);
		char *full_cmd;
			continue;
		die("Run with no arguments or with -c cmd");
			fprintf(stderr, "invalid command format '%s': %s\n", rawargs,
			    "and have read and execute access.");
	const char *home = getenv("HOME");
		case ' ':
	}
		}
			arg = NULL;
			fprintf(stderr, "invalid command format '%s'\n", prog);
	/* Print help if enabled */
	{ "git-upload-pack", do_generic_cmd },
}

		exit(cmd->exec(cmd->name, arg));
			full_cmd = make_cmd(prog);
{
		if (git_read_line_interactively(&line) == EOF) {
static void run_shell(void)
		prog[3] = '-';
		exit(status);
};

			free(rawargs);
				split_cmdline_strerror(count));
	const char *name;
		free(prog);
#include "cache.h"
	setup_path();
		const char **argv;
		}
		arg = NULL;
	prog = xstrdup(argv[2]);

	 */
		default:
			    "hint: ~/" COMMAND_DIR " should exist "


		char *split_args;
				fprintf(stderr, "unrecognized command '%s'\n", prog);
	} else if (argc != 3 || strcmp(argv[1], "-c")) {
	for (cmd = cmd_list ; cmd->name ; cmd++) {

			break;
{
		}
	run_command_v_opt(help_argv, RUN_SILENT_EXEC_FAILURE);

	do {
			argv[0] = full_cmd;
}


	if (!home)
