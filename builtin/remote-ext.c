		size_t i;
	while (1) {
	if (**next == ' ')
					str[rpos]);
{
			default:
{
static char *git_req_vhost;
 *		Argument to command, instead send this as name of repository


			printf("*connect\n\n");
	}
	default:
				strbuf_addstr(&ret, service_noprefix);
	if (escape && !str[rpos])
		return NULL;
{
		return strbuf_detach(&ret, NULL);
				strbuf_addstr(&ret, service);
	/* Pass the service to command. */
	skip_prefix(service_noprefix, "git-", &service_noprefix);
	escape = 0;
 *	'%G': Only allowed as first 'character' of argument. Do not pass this
	switch (special) {
				break;

	setenv("GIT_EXT_SERVICE_NOPREFIX", service_noprefix, 1);
			case '%':
	}
			}
				break;
#include "builtin.h"

}
	if (git_req)
		git_req = strbuf_detach(&ret, NULL);
		}
	const char **next)
 */
			case 's':
static int run_child(const char *arg, const char *service)
		die("remote-ext command has incomplete placeholder");
			case '%':
				strbuf_addch(&ret, str[rpos]);
			case 'G':
		if (!strcmp(buffer, "capabilities")) {
				break;
 *	Special characters:
static void send_git_request(int stdin_fd, const char *serv, const char *repo,
		usage(usage_msg);
	int r;
 *	'command [arg1 [arg2 [...]]]'	Invoke command with given arguments.
	while (str[rpos] && (escape || str[rpos] != ' ')) {
			argv_array_push(out, expanded);
	while (*arg) {
	if (!r)
			}
		send_git_request(child.in, service, git_req, git_req_vhost);
#include "run-command.h"
	while (str[rpos] && (escape || str[rpos] != ' ')) {
		}
				escape = 1;
		if (escape) {
 *		conjunction with '%G': Do not pass this argument to command,

 *		not activate sending git:// style request).

			fflush(stdout);
	child.in = -1;
	}
 *	'%V': Only allowed as first 'character' of argument. Used in
#include "transport.h"
				/* fallthrough */

	if (argc != 3)
			case '%':
		return NULL;
			}
			switch (str[rpos]) {
			escape = 0;
	else
			case 'S':
	rpos = special ? 2 : 0;		/* Skip first 2 bytes in specials. */
	 */
			case ' ':
			return 1;
	}
			fflush(stdout);
				die("Command input error");
				break;
		if (!fgets(buffer, MAXCOMMAND - 1, stdin)) {
	*next = str + rpos;
 *	'%S': Name of service (git-upload-pack/git-upload-archive/
	 * Do the actual placeholder substitution. The string will be short
	child.err = 0;
				special = str[rpos];
}

			if (ferror(stdin))

 *		in in-line git://-style request (also activates sending this
		if (escape) {
	else
}
			     vhost, 0);
			return run_child(child, buffer + 8);
			printf("\n");
			exit(0);
	if (start_command(&child) < 0)
				break;
int cmd_remote_ext(int argc, const char **argv, const char *prefix)
static void parse_argv(struct argv_array *out, const char *arg, const char *service)

	return r;
	return command_loop(argv[2]);
		} else {
		free(expanded);
	}
 *	'%s': Same as \s, but with possible git- prefix stripped.
	if (!vhost)
	setenv("GIT_EXT_SERVICE", service, 1);
 *	'% ': Literal space in argument.
		rpos++;

		char *expanded = strip_escapes(arg, service, &arg);
		} else
	 * enough not to overflow integers.
			buffer[--i] = 0;
	int escape = 0;
	parse_argv(&child.args, arg, service);
/*
		/* Strip end of line characters. */
}
	child.out = -1;

}
		finish_command(&child);
	struct child_process child = CHILD_PROCESS_INIT;
			case 'S':
			escape = 0;
			escape = (str[rpos] == '%');
	/*
#define MAXCOMMAND 4096
					break;
				die("Bad remote-ext placeholder '%%%c'.",


 *	'%%': Literal percent sign.
			switch (str[rpos]) {

	case 'G':
	r = bidirectional_transfer_loop(child.out, child.in);
	"git remote-ext <remote> <url>";
			case 'V':
		packet_write_fmt(stdin_fd, "%s %s%c", serv, repo, 0);
		packet_write_fmt(stdin_fd, "%s %s%chost=%s%c", serv, repo, 0,
		r = finish_command(&child);
		while (i > 0 && isspace(buffer[i - 1]))
	const char *vhost)
		if (expanded)
	size_t rpos = 0;
				break;
			default:
static char *strip_escapes(const char *str, const char *service,
#include "pkt-line.h"
				if (rpos == 1)
		i = strlen(buffer);
	const char *service_noprefix = service;
			case 's':

 *		instead send this as vhost in git://-style request (note: does
static int command_loop(const char *child)
 * URL syntax:
 *		style of request).
	char special = 0;

			switch (str[rpos]) {
static const char usage_msg[] =

		git_req_vhost = strbuf_detach(&ret, NULL);
		} else if (!strncmp(buffer, "connect ", 8)) {
static char *git_req;
 *		git-receive-pack.
	char buffer[MAXCOMMAND];

}
				strbuf_addch(&ret, str[rpos]);
{

		++*next;	/* Skip over space */
{
	case 'V':
	/* Scan the length of argument. */
			fprintf(stderr, "Bad command");
		die("Can't run specified command");
		} else
		rpos++;
{

	struct strbuf ret = STRBUF_INIT;
			case ' ':
