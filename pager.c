	return 0;
	int n_cols;
static int pager_command_config(const char *var, const char *value, void *vdata)
	setup_pager_env(&pager_process->env_array);

	if (!in_signal) {
/* returns 0 for "no pager", 1 for "use pager", and -1 for "not specified" */

			argv_array_push(env, argv[i]);
const char *git_pager(int stdout_is_tty)
 * How many columns do we need to show this number in decimal?
		struct winsize ws;
		setenv("COLUMNS", buf, 0);
 */

}
	for (i = 0; i < n; i++) {
	if (!pager)
	data.want = -1;
	if (!pager)
	dup2(pager_process.in, 1);
		else {
	}

void prepare_pager_args(struct child_process *pager_process, const char *pager)
		char *cp = strchr(argv[i], '=');
	return width;
static void wait_for_pager_signal(int signo)
	/*
struct pager_command_config_data {
#include "alias.h"
int decimal_width(uintmax_t number)
}
static int core_pager_config(const char *var, const char *value, void *data)
		pager = getenv("PAGER");

}
 */
		}
int check_pager_config(const char *cmd)
	const char *pager = git_pager(isatty(1));
{
	if (!stdout_is_tty)
	struct pager_command_config_data *data = vdata;
		int b = git_parse_maybe_bool(value);
	pager_process->trace2_child_class = "pager";

		pager_program = data.value;
	char *value;
 */

	wait_for_pager(1);
}


		 * Fall back to print a terminal width worth of space

		if (!getenv(argv[i])) {
static void wait_for_pager_atexit(void)
	return data.want;
static void wait_for_pager(int in_signal)
		fprintf(stderr, "\r%*s\r", term_columns(), "");
		if (b >= 0)
	close(pager_process.in);
		return term_columns_at_startup;
	if (!pager) {
{
		finish_command(&pager_process);
}
	pager_process.in = -1;
static void setup_pager_env(struct argv_array *env)
	}
			split_cmdline_strerror(n));
	char *col_string;
 * set and positive) or ioctl(1, TIOCGWINSZ).ws_col (if positive),

	if (!*pager || !strcmp(pager, "cat"))
{
		 */
		/*
	free(argv);

	data.cmd = cmd;
	read_early_config(pager_command_config, &data);
	return term_columns_at_startup;

			term_columns_at_startup = ws.ws_col;
{
#ifndef DEFAULT_PAGER
		 * characters (hoping that the terminal is still as wide
		pager = pager_program;
	/* signal EOF to pager */


	if (n < 0)
		/*
		fflush(stdout);

		pager = DEFAULT_PAGER;
	}
	int i;
}
}
{
	/* original process continues, but writes to the pipe */
			read_early_config(core_pager_config, NULL);
	{
	if (data.value)
	if (start_command(&pager_process))

	if (term_columns_at_startup)
	return pager;
/*
#include "cache.h"
	sigchain_pop(signo);
	else {
			*cp = '=';
 * Clear the entire line, leave cursor in first column.

#include "run-command.h"

}
	const char *cmd;
	sigchain_push_common(wait_for_pager_signal);
	close(1);


	free(pager_env);
{

	wait_for_pager(0);
}
	if (is_terminal_dumb())
	/* spawn the pager */
		 * the whole line, no matter how wide the terminal.

	close(2);
#endif
		if (!ioctl(1, TIOCGWINSZ, &ws) && ws.ws_col)

	int want;
			data->want = b;
		char buf[64];
		fflush(stderr);
void setup_pager(void)

	struct pager_command_config_data data;
{
		dup2(pager_process.in, 2);

/*

		pager = NULL;

		term_columns_at_startup = n_cols;
}
		return;
{
	return git_env_bool("GIT_PAGER_IN_USE", 0);
{
	}
};
	static int term_columns_at_startup;
{
{
		xsnprintf(buf, sizeof(buf), "%d", term_columns());
			data->value = xstrdup(value);
}

{
	 * After we redirect standard output, we won't be able to use an ioctl
		 */
	pager = getenv("GIT_PAGER");
#include "sigchain.h"
		return git_config_string(&pager_program, var, value);
 * Return cached value (if set) or $COLUMNS environment variable (if

		finish_command_in_signal(&pager_process);
static const char *pager_program;
		return NULL;
	else
	term_columns_at_startup = 80;

		number /= 10;
	int n = split_cmdline(pager_env, &argv);
		if (!cp)
	return 0;
	const char *cmd;
#endif
		return;
{
{
	if (!strcmp(var, "core.pager"))
int pager_in_use(void)
	 * to communicate it to any sub-processes.
		}
	argv_array_push(&pager_process.env_array, "GIT_PAGER_IN_USE");
	 * to get the terminal size. Let's grab it now, and then set $COLUMNS
		 * On non-dumb terminals use an escape sequence to clear

	int width;
void term_clear_line(void)
	prepare_pager_args(&pager_process, pager);
			die("malformed build-time PAGER_ENV");

}
int term_columns(void)
}
	atexit(wait_for_pager_atexit);
		*cp = '\0';
	argv_array_push(&pager_process->args, pager);
	raise(signo);
	if (in_signal)
	col_string = getenv("COLUMNS");

	pager_process->use_shell = 1;
static struct child_process pager_process = CHILD_PROCESS_INIT;
		if (!pager_program)
	data.value = NULL;
			data->want = 1;

	if (col_string && (n_cols = atoi(col_string)) > 0)
		die("malformed build-time PAGER_ENV: %s",

	}
 * and default to 80 if all else fails.
	for (width = 1; number >= 10; width++)
		 * as it was upon the first call to term_columns()).
	if (!pager)
	const char **argv;
/*
	/* this makes sure that the parent terminates after the pager */


	char *pager_env = xstrdup(PAGER_ENV);
	if (isatty(2))
		fputs("\r\033[K", stderr);
#include "config.h"
	if (skip_prefix(var, "pager.", &cmd) && !strcmp(cmd, data->cmd)) {
}

	else
	 */
#define DEFAULT_PAGER "less"
	setenv("GIT_PAGER_IN_USE", "true", 1);
#ifdef TIOCGWINSZ

	const char *pager;
	}

