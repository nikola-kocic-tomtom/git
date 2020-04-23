	argv[1] = socket;
		socket = xdg_cache_home("credential/socket");
}
	else
static int send_request(const char *socket, const struct strbuf *out)
#include "run-command.h"
	strbuf_addf(&buf, "action=%s\n", action);

		die("cache daemon did not start: %.*s", r, buf);
		if (errno != ENOENT && errno != ECONNREFUSED)
	if (!socket_path)
#define FLAG_RELAY 0x2

		char in[1024];
			break;
	int timeout = 900;
	r = read_in_full(daemon.out, buf, sizeof(buf));
	daemon.no_stdin = 1;
	else if (!strcmp(op, "store"))
#include "parse-options.h"
	close(fd);
			   "path of cache-daemon socket"),
		die_errno("unable to read result code from cache daemon");
#include "credential.h"
	if (send_request(socket, &buf) < 0) {
		do_cache(socket_path, op, timeout, FLAG_RELAY);
		die_errno("unable to start cache daemon");
		die("unable to find a suitable socket path; use --socket");
{
	return socket;
	close(daemon.out);
	daemon.out = -1;

	const char *op;
#include "string-list.h"
	if (r != 3 || memcmp(buf, "ok\n", 3))
		die_errno("unable to write to cache daemon");
	strbuf_release(&buf);
#include "cache.h"
}
		socket = xstrfmt("%s/socket", old_dir);
	old_dir = expand_user_path("~/.git-credential-cache", 0);
	}
	argc = parse_options(argc, argv, NULL, options, usage, 0);
			spawn_daemon(socket);
			if (send_request(socket, &buf) < 0)
	return got_data;
	if (write_in_full(fd, out->buf, out->len) < 0)
	char *socket_path = NULL;
}
	struct stat sb;
	int fd = unix_stream_connect(socket);
		socket_path = get_socket_path();
		     int flags)


		NULL
#include "unix-socket.h"
	if (fd < 0)
		"git credential-cache [<options>] <action>",
	char *old_dir, *socket;
	if (old_dir && !stat(old_dir, &sb) && S_ISDIR(sb.st_mode))
			    "number of seconds to cache credentials"),
	char buf[128];
	if (!socket_path)
static char *get_socket_path(void)
	int got_data = 0;
	return 0;
{
		OPT_STRING(0, "socket", &socket_path, "path",

		write_or_die(1, in, r);


	struct option options[] = {

static void spawn_daemon(const char *socket)
static void do_cache(const char *socket, const char *action, int timeout,
	};
}
	if (!strcmp(op, "exit"))
	if (flags & FLAG_RELAY) {
		if (r < 0)
{
	}

	struct strbuf buf = STRBUF_INIT;

	else
	}
	argv[0] = "git-credential-cache--daemon";
	else if (!strcmp(op, "get") || !strcmp(op, "erase"))
	free(old_dir);
		if (strbuf_read(&buf, 0, 0) < 0)
	struct child_process daemon = CHILD_PROCESS_INIT;

	daemon.argv = argv;
			die_errno("unable to connect to cache daemon");
		OPT_INTEGER(0, "timeout", &timeout,

		; /* ignore unknown operation */
	if (!argc)
	};
		do_cache(socket_path, op, timeout, 0);
	op = argv[0];

{
	while (1) {
		if (r == 0 || (r < 0 && errno == ECONNRESET))
		r = read_in_full(fd, in, sizeof(in));
				die_errno("unable to connect to cache daemon");
		return -1;
	shutdown(fd, SHUT_WR);
	if (r < 0)
		int r;

	int r;
		OPT_END()
	const char * const usage[] = {
		got_data = 1;
		usage_with_options(usage, options);

#define FLAG_SPAWN 0x1
			die_errno("read error from cache daemon");
		if (flags & FLAG_SPAWN) {
		}
	if (start_command(&daemon))
		do_cache(socket_path, op, timeout, FLAG_RELAY|FLAG_SPAWN);
{


int cmd_main(int argc, const char **argv)
			die_errno("unable to relay credential");
	strbuf_addf(&buf, "timeout=%d\n", timeout);
	const char *argv[] = { NULL, NULL, NULL };
}
