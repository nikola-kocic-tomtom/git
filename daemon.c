	pfd = xcalloc(socklist->nr, sizeof(struct pollfd));
			return rc;

	if (addr->sa_family == AF_INET) {
		openlog("git-daemon", LOG_PID, LOG_DAEMON);
			return 2;
	strbuf_release(&hi->hostname);
		strbuf_setlen(out, out->len - 1);

		inet_ntop(addr->sa_family, &sin_addr->sin_addr, buf, sizeof(buf));
struct socketlist {
			continue;
};
	if (*hostport == '[') {
#endif
static void add_child(struct child_process *cld, struct sockaddr *addr, socklen_t addrlen)
			continue;

			informative_errors = 0;
			detach = 1;

		loginfo("Connection from %s:%s", addr, port);
		if (rlen >= sizeof(rpath)) {
		die("unable to allocate any listen sockets on port %u",
			return;
		/* avoid splitting a message in the middle */

		}
			/* remove the child */
		if (sockfd < 0)
		if (skip_prefix(arg, "--user-path=", &v)) {
	socklist->list[socklist->nr++] = sockfd;
		if (skip_prefix(arg, "--max-connections=", &v)) {
static int set_reuse_addr(int sockfd)
	strbuf_release(&hi->tcp_port);
		}
		}
#ifdef NO_INITGROUPS
	cld->err = -1;
			}
		if (!strict_paths)
				 ntohs(sin6_addr->sin6_port));
}
	int i;
		}
	c.pass = getpwnam(user_name);


/* Timeout, and initial timeout */
	copy_to_log(cld->err);
				socklen_t sslen = sizeof(ss);

				continue;
					      &hi->ip_address);
static void logreport(int priority, const char *err, va_list params)
	}
	else
			logerror("Could not set SO_REUSEADDR: %s", strerror(errno));
}
		if (skip_prefix(arg, "--timeout=", &v)) {
	 *
	strbuf_release(&line);
static int service_loop(struct socketlist *socklist)
		    *arg++ == ' ') {
	else {
			return NULL;
	struct argv_array env = ARGV_ARRAY_INIT;
		char buf[1024];
		argv_array_pushf(&cld.env_array, "REMOTE_ADDR=[%s]", buf);
	int vallen;
		return 0;

}

	close(0);

		vsnprintf(buf, sizeof(buf), err, params);
	cld.in = incoming;
			n = strtoul(v, &end, 0);
		if (inet_pton(AF_INET, listen_addr, &sin.sin_addr.s_addr) <= 0)
		return daemon_error(dir, "service not enabled");
	strbuf_release(&hi->ip_address);
{
 * argument, or 'extra_args' if there is no host argument.

}
		logerror("getaddrinfo() for %s failed: %s", listen_addr, gai_strerror(gai));
			 ip2str(AF_INET, (struct sockaddr *)&sin, sizeof(sin)),
"           [--interpolated-path=<path>]\n"



			continue;
			ok_paths = &argv[i];

	int i;
	argv_array_clear(&env);
			}
 * This gets called if the number of connections grows
		logerror("%s", line.buf);
		line[len-1] = 0;
				if (port)
	{ "upload-pack", "uploadpack", upload_pack, 1, 1 },
				continue;
		c.gid = c.pass->pw_gid;
		 * do not have to say /mnt/pub.
	if (!enabled && !service->overridable) {
				 ip2str(ai->ai_family, ai->ai_addr, ai->ai_addrlen),
	return ip;
	socksetup(listen_addr, listen_port, &socklist);

			 service->name, path);
	 * We'll ignore SIGTERM from now on, we have a
					}
 */
		die("option --strict-paths requires a whitelist");
	return 1;

	if (sa1->sa_family == AF_INET6)
		if (*dir != '/') {
			*port = end + 2;
			logerror("'%s': Non-absolute path denied (interpolated-path active)", dir);
			} else if (!strcmp(v, "stderr")) {
			if (rlen >= sizeof(rpath)) {
		const char *arg;
		argv_array_pushf(env, GIT_PROTOCOL_ENVIRONMENT "=%s",
			memcpy(&sa.sin_addr, *ap, hent->h_length);
			continue;
	long flags;
}
}
		argv_array_push(&cld_argv, argv[i]);

		 * a symlink to /mnt/pub, you can whitelist /pub and
	struct child_process cld = CHILD_PROCESS_INIT;
	alarm(0);
			continue;
{
			if (!strcmp(v, "syslog")) {
		struct addrinfo *ai;
static void sanitize_client(struct strbuf *out, const char *in)
					default:
static int run_access_hook(struct daemon_service *service, const char *dir,
		}
	if (!path && base_path && base_path_relaxed) {
		 */

	va_start(params, err);
		return;

	for (cradle = &firstborn; *cradle; cradle = &(*cradle)->next)
		char buf[128] = "";
static void make_service_overridable(const char *name, int ena)
	/*
	const char *end = extra_args + buflen;

	const char *path;
}
	if (cred && (initgroups(cred->pass->pw_name, cred->gid) ||
		else if (end[1] == ':')
			make_service_overridable(v, 0);
{
		setvbuf(stderr, NULL, _IOFBF, 4096);

{
		if (!user_path) {
		parse_extra_args(&hi, &env, line + len + 1, pktlen - len - 1);

		seen_errors = 1;
			export_all_trees = 1;
		/*

				log_destination = LOG_DESTINATION_NONE;
	if (flags >= 0)
		} else if (arg[0] != '-') {
		die("user not found - %s", user_name);
				logerror("unable to allocate any listen sockets for host %s on port %u",
static struct daemon_service daemon_service[] = {
	hints.ai_socktype = SOCK_STREAM;
	case 'H':
{

		hints.ai_flags = AI_CANONNAME;

"           [--reuseaddr] [--pid-file=<file>]\n"
	if (start_command(&child)) {
		if (placeholder[1] == 'P') {
	newborn = xcalloc(1, sizeof(*newborn));
}
		if (!strcmp(arg, "--verbose")) {
	return run_service_command(&cld);
	struct child **cradle, *blanket;
			if (*v && !*end) {
		}
};
	return 0;
				log_destination = LOG_DESTINATION_SYSLOG;
		struct addrinfo hints;
	struct strbuf tcp_port;
#else /* NO_IPV6 */
	 * We only need to make sure the repository is exported.
			continue;
		}
	unsigned int hostname_lookup_done:1;
	 */
}

				 ntohs(sin_addr->sin_port));
		dir = rpath;
		struct hostent *hent;
 * after ~user/.  E.g. a request to git://host/~alice/frotz would
	if (sockfd < 0)
		die("base-path '%s' does not exist or is not a directory",
	}

		listen_port = DEFAULT_GIT_PORT;
	int detach = 0;
#endif
	return -1;
		struct sockaddr_in *sin_addr = (void *) addr;
		vfprintf(stderr, err, params);
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka)) < 0) {
				 git_protocol.buf);
	 * Security on the cheap.

			return;
		    listen_port);
struct daemon_service {
		}
		}
		}
	if (!enabled) {
		BUG("log destination not initialized correctly");
		if (set_reuse_addr(sockfd)) {
		if (strncasecmp("host=", extra_args, 5) == 0) {
}
static int export_all_trees;
}
		return 0;
static void hostinfo_clear(struct hostinfo *hi)
		}
}
		if (bind(sockfd, ai->ai_addr, ai->ai_addrlen) < 0) {
	if (strbuf_read(&buf, child.out, 0) < 0) {
		char *end;
	}

	return -1;
		}
{
					case ECONNABORTED:
	sin.sin_family = AF_INET;
{
#include "string-list.h"
			if (git_protocol.len > 0)
		if (skip_prefix(arg, "--interpolated-path=", &v)) {
		fputc('\n', stderr);
			group_name = v;

	unsigned int saw_extended_args:1;
	 *

		const char *arg = argv[i];

static int max_connections = 32;
		 * prefixing the base path
	struct strbuf git_protocol = STRBUF_INIT;
			return 0;

}
	die("--user not supported on this platform");
	hints.ai_flags = AI_PASSIVE;
			continue;
		 * which will be used to set the 'GIT_PROTOCOL' envvar in the
	if (inetd_mode || serve_mode)
static void NORETURN daemon_die(const char *err, va_list params)
}
		}
		const char **pp;
	/* nothing */

		if (errno != ENOTSOCK)
				}
		if (!strcmp(arg, "--strict-paths")) {
static int run_service_command(struct child_process *cld)
	argv_array_push(&cld_argv, "--serve");
		}
			user_path = v;
		syslog(priority, "%s", buf);
			continue;	/* not fatal */
		       struct hostinfo *hi, const struct argv_array *env)
#endif
#include "config.h"
		if (!strcmp(arg, "--detach")) {
		}
	case LOG_DESTINATION_UNSET:
			kill(blanket->cld.pid, SIGTERM);
			die("group not found - %s", group_name);
	gai = getaddrinfo(listen_addr, pbuf, &hints, &ai0);

			logerror("interpolated path too large: %s",
		}
static void drop_privileges(struct credentials *cred)
				slash = dir + restlen;

				strerror(errno));
	struct child_process child = CHILD_PROCESS_INIT;
#else
		if (skip_prefix(arg, "--log-destination=", &v)) {
	}
			cradle = &blanket->next;
	newborn->next = *cradle;
	strbuf_tolower(out);
			close(sockfd);
		return 0;
{
static int daemon_error(const char *dir, const char *msg)
	}
	if (eol)
		/* be backwards compatible */
{
	static char ip[INET_ADDRSTRLEN];
static void parse_extra_args(struct hostinfo *hi, struct argv_array *env,

		logerror("unable to fork");
		for (i = 0; i < listen_addr->nr; i++) {
		}
			die("Garbage after end of host part");
"           [--log-destination=(stderr|syslog|none)]\n"
			if (pfd[i].revents & POLLIN) {
	 * path_ok() uses enter_repo() and does whitelist checking.
	}
				continue;
    const char *group_name)
	/*
	char **port)

	sin.sin_port = htons(listen_port);
			loginfo("Extended attribute \"host\": %s", val);

	xsnprintf(pbuf, sizeof(pbuf), "%d", listen_port);
{
	va_end(params);
			const char *slash = strchr(dir, '/');
	hints.ai_family = AF_UNSPEC;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	strbuf_init(&hi->ip_address, 0);
			log_destination = LOG_DESTINATION_STDERR;
	loginfo("Ready to rumble");

			access_hook = v;
		if (*user_path) {
	if (base_path && !is_directory(base_path))
		if (skip_prefix(arg, "--port=", &v)) {
static char *parse_host_arg(struct hostinfo *hi, char *extra_args, int buflen)
		strbuf_addf(&var, "daemon.%s", service->config_name);
	/* parse additional args hidden behind a NUL byte */
	die("No such service %s", name);
	packet_write_fmt(1, "ERR %s: %s", msg, dir);
		}
__attribute__((format (printf, 1, 2)))
			/* On to the next one */
					case EINTR:
		}
	for (; extra_args < end; extra_args += strlen(extra_args) + 1) {
		if (!strcmp(daemon_service[i].name, name)) {
		}
					struct sockaddr sa;

static unsigned int live_children;
				continue;
			break;
			interpolated_path = v;

		 */

			close(incoming);
			}
	}
		if (!group)
	path = enter_repo(dir, strict_paths);
 * Like sanitize_client, but we also perform any canonicalization
{
			 * rewrite them to "~alice/%s" or
	if (access_hook && run_access_hook(service, dir, path, hi))
				} ss;
	struct sockaddr_storage address;
/*
	 * We want a readable HEAD, usable "objects" directory, and
{
			if (len <= pathlen &&
		for (i = 0; i < socklist->nr; i++) {
	argv_array_pushl(&cld.args, "upload-pack", "--strict", NULL);
	}
		loginfo("Extended attribute \"protocol\": %s", git_protocol.buf);
		logerror("'%s': service not enabled.", service->name);

		sleep(1);  /* give it some time to die */
	argv_array_pushf(&cld.args, "--timeout=%u", timeout);
		break;
 * Sanitize a string from the client so that it's OK to be inserted into a
#define initgroups(x, y) (0) /* nothing */
		for ( pp = ok_paths ; *pp ; pp++ ) {
		 */
	}
	int overridable;
			 strerror(errno));
"           [--access-hook=<path>]\n"
	}
		end = strchr(hostport, ']');
struct credentials;
	}
		}
			make_service_overridable(v, 1);
#endif
	}

 */
		if (!strcmp(arg, "--informative-errors")) {

		*host = hostport + 1;
	    setgid (cred->gid) || setuid(cred->pass->pw_uid)))
		logerror("fdopen of error channel failed");
	if (pid_file)
		}
		}
	} else
			logerror("unable to set SO_KEEPALIVE on socket: %s",
	cld->git_cmd = 1;
		strbuf_release(&var);
	*arg++ = access_hook;
		}
	argv_array_push(&cld.args, "upload-archive");

	return hi->ip_address.buf;
			informative_errors = 1;
		if (!strcmp(arg, "--reuseaddr")) {

		return 0;
					struct sockaddr_in sai;
		 * appends optional {.git,.git/.git} and friends, but
		add_child(&cld, addr, addrlen);
	extra_args = parse_host_arg(hi, extra_args, buflen);
	exit(1);
 * go to /home/alice/pub_git/frotz with --user-path=pub_git.

			continue;
			sanitize_client(&hi->canon_hostname, hent->h_name);
		}
				char *port;
	return finish_command(cld);
			continue;	/* not fatal */
		if (*arg) {

			continue;
	freeaddrinfo(ai0);

			return path;
	argv_array_pushv(&cld.env_array, env->argv);
			continue;
	 * Otherwise empty handler because systemcalls will get interrupted
	static char rpath[PATH_MAX];
static void hostinfo_init(struct hostinfo *hi)

				hi->hostname_lookup_done = 0;
		/* The validation is done on the paths after enter_repo
		}
			enable_service(v, 0);
			logerror("Socket descriptor too large");
			reuseaddr = 1;

	if (service->overridable) {

		int pathlen = strlen(path);
		if (*dir != '/') {
	if (group_name && !user_name)
		*port = strrchr(hostport, ':');
	if (log_destination == LOG_DESTINATION_SYSLOG) {
			init_timeout = atoi(v);
			strbuf_addstr(sb, get_ip_address(hi));
			     char *extra_args, int buflen)
	argv_array_push(&cld->args, ".");
{
	}
				return NULL;
}
			namlen = slash - dir;
static int upload_pack(const struct argv_array *env)
	case LOG_DESTINATION_STDERR:
static int execute(void)
		const char *arg = extra_args;
		return 0;
	}
			char *end;
{

		if (!strcmp(arg, "--export-all")) {
{
			fcntl(sockfd, F_SETFD, flags | FD_CLOEXEC);

			return NULL;
			if (!slash)
static const char *user_path;
"           [--timeout=<n>] [--init-timeout=<n>] [--max-connections=<n>]\n"
	return 0;
		logerror("failed to close pipe to daemon access hook '%s'",
			continue;

		return daemon_error(dir, "repository not exported");
		errno = EACCES;
	 */
		c.gid = group->gr_gid;
		 * if we fail and base_path_relaxed is enabled, try without
#endif
 * past "max_connections".

		}
		git_config_get_bool(var.buf, &enabled);
	drop_privileges(cred);
		setup_named_sock(NULL, listen_port, socklist);
static struct child {
	hostinfo_clear(&hi);
	static char interp_path[PATH_MAX];
static void child_handler(int signo)
			continue;
	*arg++ = hi->hostname.buf;

static int informative_errors;
struct hostinfo {
			     (!strict_paths && path[len] == '/')))
		rlen = strlcpy(interp_path, expanded_path.buf,
		die("--listen= and --port= are incompatible with --inetd");
static int run_service(const char *dir, struct daemon_service *service,
 */

typedef int (*daemon_service_fn)(const struct argv_array *env);
	child.out = -1;
		}
				dead = " (with error)";
	}
			logerror("Could not listen to %s: %s",
		ALLOC_GROW(socklist->list, socklist->nr + 1, socklist->alloc);
		msg = "access denied or repository not exported";
		logerror("'%s': aliased", dir);
	if (fp == NULL) {
	if (!buf.len)
		}
		return daemon_error(dir, "no such repository");
		rlen = snprintf(rpath, sizeof(rpath), "%s%s", base_path, dir);
	fclose(fp);
    struct credentials *cred)
}
static void loginfo(const char *err, ...)
			/* Allow only absolute */
		int i;
		close(sockfd);

{
		return daemon_error(dir, "service not enabled");

		if (skip_prefix(arg, "--group=", &v)) {
	if (inetd_mode && (detach || group_name || user_name))
	if (!reuseaddr)
	int ka = 1;
	}
	eol = strchr(buf.buf, '\n');
	}

		int sockfd;
static int upload_archive(const struct argv_array *env)
		*end = '\0';
			pid_file = v;
	 */
		if (skip_prefix(arg, "--user=", &v)) {
	sanitize_client(out, in);
		break;
		check_dead_children();
			 ip2str(AF_INET, (struct sockaddr *)&sin, sizeof(sin)),
	if (socklist.nr == 0)
		static char addrbuf[HOST_NAME_MAX + 1];
		const char *v;
		break;

	memset(&sin, 0, sizeof sin);
			 * and might depend on the actual service being performed.

}
		strbuf_expand(&expanded_path, interpolated_path,
		}

static void kill_some_child(void)
			}


	die("No such service %s", name);
	case LOG_DESTINATION_NONE:

		if (skip_prefix(arg, "--access-hook=", &v)) {

{
 * Read the host as supplied by the client connection.
				char *host;
		}
				return path;
	}
}
	const char *path;
		 * it does not use getcwd().  So if your /pub is
			verbose = 1;
			continue;
struct expand_path_context {
 */
		}
	 * a "git-daemon-export-ok" flag that says that the other side
		if (!end)
	}

		if (sockfd >= FD_SETSIZE) {
			freeaddrinfo(ai);
 * Returns a pointer to the character after the NUL byte terminating the host
"           [--strict-paths] [--base-path=<path>] [--base-path-relaxed]\n"
			ok_paths = &argv[i+1];
	LOG_DESTINATION_NONE = 0,
};
			string_list_append(&listen_addr, xstrdup_tolower(v));
		break;
		struct sockaddr_in6 *sin6_addr = (void *) addr;
	size_t rlen;
		pfd[i].fd = socklist->list[i];
			base_path_relaxed = 1;
static int base_path_relaxed;

	int on = 1;
			/*
		hi->hostname_lookup_done = 1;
#ifndef NO_IPV6
static void lookup_hostname(struct hostinfo *hi)
			else
{
#endif
}
	struct child_process cld = CHILD_PROCESS_INIT;
	return -1;
	}
	/* prepare argv for serving-processes */
			continue;
static int serve(struct string_list *listen_addr, int listen_port,
static int setup_named_sock(char *listen_addr, int listen_port, struct socketlist *socklist)
	} else {
		path = enter_repo(dir, strict_paths);
			} else if (!strcmp(v, "none")) {
	LOG_DESTINATION_SYSLOG = 2,
		return execute();
#include "cache.h"
static void copy_to_log(int fd)
	for (; (next = blanket->next); blanket = next)

	logerror("Protocol error: '%s'", line);
static void socksetup(struct string_list *listen_addr, int listen_port, struct socketlist *socklist)
	else if (base_path) {
	*arg = NULL;
 * trailing and leading dots, which means that the client cannot escape
	const char *dir;
	}
		if (!strcmp(arg, "--base-path-relaxed")) {
static size_t expand_path(struct strbuf *sb, const char *placeholder, void *ctx)
			ap = hent->h_addr_list;

			logerror("'%s': User-path not allowed", dir);
			inetd_mode = 1;
		argv_array_pushf(&cld.env_array, "REMOTE_PORT=%d",
	}
#else

			log_destination = LOG_DESTINATION_SYSLOG;
	 * Optionally, a hook can choose to deny access to the
			enable_service(v, 1);

};
			serve_mode = 1;
{
{
};
{
	for (i = 1; i < argc; i++) {
	*arg++ = service->name;
}
	for (;;) {
	while (strbuf_getline_lf(&line, fp) != EOF) {
{

		strbuf_addbuf(sb, &hi->hostname);
			 strerror(errno));
			continue;
	else if (listen_port == 0)

{
	case 'C':
	signal(SIGTERM, SIG_IGN);
		cred = prepare_credentials(user_name, group_name);
/* List of acceptable pathname prefixes */
	switch (placeholder[0]) {
		/*
		    skip_prefix(arg, s->name, &arg) &&
			child_process_clear(&blanket->cld);
	const struct child *blanket, *next;
	int *list;
				logerror("user-path too large: %s", rpath);
	logreport(LOG_INFO, err, params);
		return sa1->sa_family - sa2->sa_family;
		if (poll(pfd, socklist->nr, -1) < 0) {
		return 0;
			logerror("Too many children, dropping connection");
static unsigned int init_timeout;
}
	}

		die("--detach, --user and --group are incompatible with --inetd");
static int addrcmp(const struct sockaddr_storage *s1,
}
	} else if (addr->sa_family == AF_INET6) {
	child.argv = argv;
		errno = EACCES;
	int i;
}
		}

	strbuf_init(&hi->hostname, 0);
	int listen_port = 0;
	case 'D':

	/* Look for additional arguments places after a second NUL byte */
static int strict_paths;
		return 1;
			strbuf_addstr(&hi->ip_address, addrbuf);
	cld.argv = cld_argv.argv;
			return NULL;

	errno = EACCES;
	return setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		 *
	int serve_mode = 0, inetd_mode = 0;
static struct credentials *prepare_credentials(const char *user_name,

/* Take all paths relative to this one if non-NULL */
	if (close(child.out) < 0) {
 */


		}
	if (git_protocol.len > 0) {
			break;
		loginfo("Interpolated dir '%s'", interp_path);
		break;
				 strerror(errno));
	}
			 access_hook);
#ifndef NO_IPV6


			close(sockfd);
			continue;

	}

	struct strbuf var = STRBUF_INIT;
					switch (errno) {
/*
	pid_t pid;
			 */
static void lookup_hostname(struct hostinfo *hi);
	if (set_reuse_addr(sockfd)) {
		}
		struct daemon_service *s = &(daemon_service[i]);
		set_keep_alive(sockfd);
	if (len != pktlen)
		context.directory = directory;
static const char *interpolated_path;
	if (!listen_addr->nr)
			logerror("'%s': Non-absolute path denied (base-path active)", dir);
static const char *access_hook;
		 * If there ends up being a particular arg in the future that
	*cradle = newborn;

			continue;
	struct child_process cld = CHILD_PROCESS_INIT;
			strbuf_addstr(&git_protocol, arg);
	}
	dir = directory;
{
	struct child_process cld = CHILD_PROCESS_INIT;
	}
	long flags;
	struct strbuf buf = STRBUF_INIT;
#include "strbuf.h"
		logerror("Could not set SO_REUSEADDR: %s", strerror(errno));
		strbuf_release(&expanded_path);
			int on = 1;
	}
		char buf[128] = "";
	memset(hi, 0, sizeof(*hi));
}
}
static void canonicalize_client(struct strbuf *out, const char *in)
}

				strbuf_addch(&git_protocol, ':');
	struct pollfd *pfd;
		if (!strcmp(arg, "--user-path")) {
}

    const char *group_name)
static const char *get_ip_address(struct hostinfo *hi)
	const char *directory;
	for (i = 0; i < ARRAY_SIZE(daemon_service); i++) {
			die("--detach not supported on this platform");
"           [<directory>...]";
/* If this is set, git-daemon-export-ok is not required */



}
	LOG_DESTINATION_STDERR = 1,
			base_path = v;
			setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,

	struct addrinfo hints, *ai0, *ai;
	struct child *newborn, **cradle;
			    (path[len] == '\0' ||

static enum log_destination {
	signal(SIGCHLD, child_handler);
		    &((struct sockaddr_in6 *)s2)->sin6_addr,
		flags = fcntl(sockfd, F_GETFD, 0);

		logerror("Could not bind to %s: %s",
			continue;
}
		seen_errors = 1;
	else {

		if (skip_prefix(line, "git-", &arg) &&
		if (skip_prefix(arg, "--pid-file=", &v)) {
			int namlen, restlen = strlen(dir);
						ai->ai_canonname);
		return memcmp(&((struct sockaddr_in *)s1)->sin_addr,
		fprintf(stderr, "[%"PRIuMAX"] ", (uintmax_t)getpid());
					case EAGAIN:
	 * SysV needs the handler to be rearmed
	for (ai = ai0; ai; ai = ai->ai_next) {

			hostinfo_clear(&hi);
	if (inetd_mode && (listen_port || (listen_addr.nr > 0)))
{
		    sizeof(struct in6_addr));
		if (flags >= 0)
	child.no_stderr = 1;
			 * "~alice/%s/foo".
			val = extra_args + 5;
					namlen, dir, user_path, restlen, slash);
	*arg++ = hi->tcp_port.buf;
	struct sockaddr_in sin;
			return;
			return NULL;
		 * service that will be run.
		socklist->list[socklist->nr++] = sockfd;

	if (!seen_errors) {
		}
			continue;
/* If defined, ~user notation is allowed and the string is inserted
	if (!(blanket = firstborn))
			*port = NULL;
		strbuf_addstr(sb, context->directory);
		return;
/*
	}
	char *end = extra_args + buflen;

		}
	argv_array_pushv(&cld.env_array, env->argv);
		}

		if (skip_prefix(arg, "--base-path=", &v)) {
			logerror("base-path too large: %s", rpath);

	if (extra_args < end && *extra_args) {
		usage(daemon_usage);
		    sizeof(struct in_addr));
		struct sockaddr_in sa;
		if (!strcmp(arg, "--inetd")) {
	const char *name;
static void parse_host_and_port(char *hostport, char **host,


{
	if (log_destination == LOG_DESTINATION_UNSET) {
#include "pkt-line.h"

			if (status)
			continue;
static struct argv_array cld_argv = ARGV_ARRAY_INIT;
						   listen_port, socklist);
		if (skip_prefix(arg, "--allow-override=", &v)) {
					sanitize_client(&hi->tcp_port, port);
		if (daemonize())
	struct strbuf hostname;

		if (!addrcmp(&blanket->address, &next->address)) {
	static char ip[INET6_ADDRSTRLEN];
#endif

		strbuf_addch(out, *in);

		}
		}
		}
				log_destination = LOG_DESTINATION_STDERR;
	int enabled = service->enabled;
		fflush(stderr);
	memset(&hints, 0, sizeof(hints));
{
		return NULL;
	}
		}
		struct strbuf expanded_path = STRBUF_INIT;
	int pktlen, len, i;
				union {
{


	strbuf_release(&git_protocol);
			 * Note: The directory here is probably context sensitive,

			daemon_service[i].overridable = ena;
			die_errno("failed to redirect stderr to /dev/null");
		memset(&hints, 0, sizeof(hints));
			continue;

			inet_ntop(hent->h_addrtype, &sa.sin_addr,
	if (start_command(cld))

	} else {
#ifndef NO_IPV6

	char *addr = getenv("REMOTE_ADDR"), *port = getenv("REMOTE_PORT");
		return;
};
	return hi->canon_hostname.buf;
				handle(incoming, &ss.sa, sslen);

		int i, socknum;
	struct strbuf canon_hostname;

			close(sockfd);
			   const char *path, struct hostinfo *hi)
	return run_service_command(&cld);
	size_t nr;
	child.use_shell = 1;
		context.hostinfo = hi;
		if (skip_prefix(arg, "--forbid-override=", &v)) {
		inet_ntop(family, &((struct sockaddr_in*)sin)->sin_addr, ip, len);
				/* Split <host>:<port> at colon. */

{
/*
			continue;
{
	struct credentials *cred = NULL;
		 * unless they overflow the (rather big) buffers.

			close(sockfd);
 * filesystem path. Specifically, we disallow slashes, runs of "..", and
	loginfo("Request %s for '%s'", service->name, dir);
	memcpy(&newborn->cld, cld, sizeof(*cld));

		if (*port) {
	int gai;
	}
			struct sockaddr_in *sin_addr = (void *)ai->ai_addr;
		}


{
	if (!informative_errors)

	struct expand_path_context *context = ctx;
	daemon_error(dir, buf.buf);
			continue;

static const char *base_path;

						continue;
		*host = hostport;
		} else
	}
}
	fp = fdopen(fd, "r");
#ifdef NO_IPV6

{


	logerror("'%s': not in whitelist", path);
			daemon_service[i].enabled = ena;
"                      [--detach] [--user=<user> [--group=<group>]]\n"
			strict_paths = 1;

		int gai;

			return 2;
	live_children++;
		 * Parse the extra arguments, adding most to 'git_protocol'

		gai = getaddrinfo(hi->hostname.buf, NULL, &hints, &ai);
			} else
	*arg++ = get_ip_address(hi);
__attribute__((format (printf, 1, 2)))
		fcntl(sockfd, F_SETFD, flags | FD_CLOEXEC);
	}
	if (listen_addr) {
/*

	argv_array_push(&cld_argv, argv[0]); /* git-daemon */
	}
		if (!strcmp(arg, "--syslog")) {
		    base_path);
				canonicalize_client(&hi->hostname, host);
		return 0;
		}
			break;
#else
			continue;
	memcpy(&newborn->address, addr, addrlen);
	if (!hi->hostname_lookup_done && hi->hostname.len) {
			restlen -= namlen;
	const struct sockaddr *sa2 = (const struct sockaddr*) s2;
			**port = '\0';
		argv_array_pushf(&cld.env_array, "REMOTE_PORT=%d",
	struct child_process cld;
	return &c;


		errno = EACCES;
		if (extra_args < end && *extra_args)
	if (!c.pass)


	if (sa1->sa_family != sa2->sa_family)
	const struct sockaddr *sa1 = (const struct sockaddr*) s1;

}

			loginfo("userpath <%s>, request <%s>, namlen %d, restlen %d, slash <%s>", user_path, dir, namlen, restlen, slash);
			continue;
		 * then it can be parsed here and not added to 'git_protocol'.
				logerror("Poll failed, resuming: %s",
 * Locate canonical hostname and its IP address.
	if (*dir == '~') {
				   &on, sizeof(on));
		else
		/* Well, host better be an IP address here. */
			break;
		close(sockfd);
	}
		return -1;
			}
		dir = directory;
	/*
		static char addrbuf[HOST_NAME_MAX + 1];
			log_destination = LOG_DESTINATION_SYSLOG;
		seen_errors = 1;
#endif
		if (inetd_mode || detach)
			live_children--;
						die_errno("accept returned");
		}

	case 'I':
	if (gai) {
#ifdef NO_POSIX_GOODIES
	struct strbuf line = STRBUF_INIT;
					struct sockaddr_in6 sai6;
}
		if (!addrcmp(&(*cradle)->address, &newborn->address))
	for (i = 0; i < ARRAY_SIZE(daemon_service); i++) {


	struct strbuf ip_address;
	argv_array_push(&cld.args, "receive-pack");

	return service_loop(&socklist);

			sa.sin_port = htons(0);

				 ip2str(ai->ai_family, ai->ai_addr, ai->ai_addrlen),
		return 1;
 */
		if (placeholder[1] == 'H') {
	child.no_stdin = 1;
			    !memcmp(*pp, path, len) &&
		else
				      strerror(errno));
			inet_ntop(AF_INET, &sin_addr->sin_addr,
		 * logging of different processes will not overlap
{

	}
	struct hostinfo hi;
		}
	set_keep_alive(0);
		/*
	const char *pid_file = NULL, *user_name = NULL, *group_name = NULL;
	const char **arg = argv;
	if (max_connections && live_children >= max_connections) {
		logerror("failed to read from pipe to daemon access hook '%s'",
	 * repository depending on the phase of the moon.
			if (socknum == 0)

static const char *get_canon_hostname(struct hostinfo *hi)
	if (!(path = path_ok(dir, hi)))
static int receive_pack(const struct argv_array *env)
	va_list params;
	flags = fcntl(sockfd, F_GETFD, 0);
		pfd[i].events = POLLIN;

} log_destination = LOG_DESTINATION_UNSET;
	pktlen = packet_read(0, NULL, NULL, packet_buffer, sizeof(packet_buffer), 0);
		strbuf_release(&buf);
 *

		close(sockfd);
	strbuf_ltrim(&buf);
		inet_ntop(AF_INET6, &sin6_addr->sin6_addr, buf, sizeof(buf));
	default:
	ALLOC_GROW(socklist->list, socklist->nr + 1, socklist->alloc);
			  &on, sizeof(on));

		if (!strcmp(daemon_service[i].name, name)) {

				sleep(1);
		if (!freopen("/dev/null", "w", stderr))
	struct string_list listen_addr = STRING_LIST_INIT_NODUP;
	if (sa1->sa_family == AF_INET)
	if (!path) {
	else if (interpolated_path && hi->saw_extended_args) {


{
		    &((struct sockaddr_in *)s2)->sin_addr,
static void handle(int incoming, struct sockaddr *addr, socklen_t addrlen)

	return serve(&listen_addr, listen_port, cred);
		 * Since stderr is set to buffered mode, the
	if (!export_all_trees && access("git-daemon-export-ok", F_OK)) {
#include "run-command.h"
	/* First look for the host argument */
 * We kill the newest connection from a duplicate IP.
		}
		hi->saw_extended_args = 1;
	else {

		 * Do not say /pub/.
		if (!strcmp(arg, "--")) {
		strbuf_addstr(&buf, "service rejected");
	if (!group_name)

	int socknum = 0;
	argv_array_pushv(&cld.env_array, env->argv);
	hostinfo_init(&hi);
	}
			free(blanket);
			 access_hook);
			/* Allow only absolute */

			rlen = snprintf(rpath, sizeof(rpath), "%.*s/%s%.*s",

			continue;
	*arg++ = get_canon_hostname(hi);
{
	int sockfd;
		socknum++;
	}
#ifndef NO_IPV6
	strbuf_release(&hi->canon_hostname);
}

 * to make life easier on the admin.
{
	signal(SIGCHLD, child_handler);
{
	struct passwd *pass;
	va_end(params);
		logerror("'%s': repository not exported.", path);
		 */
		if (!strcmp(arg, "--no-informative-errors")) {

	}
	logreport(LOG_ERR, err, params);
{
	if (finish_command(&child))
	cld.out = dup(incoming);

}
			if (max_connections < 0)
} *firstborn;
		close(fd);
		check_dead_children();


		return memcmp(&((struct sockaddr_in6 *)s1)->sin6_addr,

static int setup_named_sock(char *listen_addr, int listen_port, struct socketlist *socklist)
	for (cradle = &firstborn; (blanket = *cradle);)

		sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		logerror("daemon access hook '%s' failed to start",
	gid_t gid;
	strbuf_init(&hi->tcp_port, 0);

		char **ap;
	char *line = packet_buffer;
		}
		die("--group supplied without --user");

}
	if (!verbose)

	lookup_hostname(hi);
		dir = interp_path;
			continue;

{
			socknum = setup_named_sock(listen_addr->items[i].string,
	if ( ok_paths && *ok_paths ) {
		if (listen(sockfd, 5) < 0) {
	const char *config_name;
		if (rlen >= sizeof(interp_path)) {
static void check_dead_children(void)
	}
		}

	struct socketlist socklist = { NULL, 0, 0 };
	struct hostinfo *hi = context->hostinfo;
			unsigned long n;
	/*
			user_name = v;
 * our base path via ".." traversal.
		if (live_children >= max_connections) {
			if (*val) {
		write_file(pid_file, "%"PRIuMAX, (uintmax_t) getpid());
	const char *argv[8];
}
"           [--user-path | --user-path=<path>]\n"
	if (addr)
		}
	if ( bind(sockfd, (struct sockaddr *)&sin, sizeof sin) < 0 ) {
static void drop_privileges(struct credentials *cred)
		die("cannot drop privileges");
		break;
int cmd_main(int argc, const char **argv)
				  addrbuf, sizeof(addrbuf));
		return 1;
				  addrbuf, sizeof(addrbuf));
	}
			argv_array_clear(&env);
		}
		xsnprintf(ip, sizeof(ip), "<unknown>");
			memset(&sa, 0, sizeof sa);
		inet_ntop(family, &((struct sockaddr_in6*)sin)->sin6_addr, ip, len);

			die("Invalid request ('[' without ']')");
			loginfo("[%"PRIuMAX"] Disconnected%s", (uintmax_t)pid, dead);
		if (*in == '.' && (!out->len || out->buf[out->len - 1] == '.'))
error_return:
			sa.sin_family = hent->h_addrtype;


	struct child *next;
}
				parse_host_and_port(val, &host, &port);
	return socknum;
	lookup_hostname(hi);
"git daemon [--verbose] [--syslog] [--export-all]\n"

		argv_array_pushf(&cld.env_array, "REMOTE_ADDR=%s", buf);
	if (user_name)
	logreport(LOG_ERR, err, params);
"           [--(enable|disable|allow-override|forbid-override)=<service>]\n"
	va_list params;
    const struct sockaddr_storage *s2)

		}
static void set_keep_alive(int sockfd)
			int len = strlen(*pp);
	}
	return run_service_command(&cld);
#ifdef IPV6_V6ONLY
	int enabled;
			/* Got either "~alice" or "~alice/foo";
		struct expand_path_context context;
			continue;
		if (!end[1])
	return NULL;		/* Fallthrough. Deny by default */
		break;
			if (errno != EINTR) {
	if (strict_paths && (!ok_paths || !*ok_paths))
	daemon_service_fn fn;

	FILE *fp;
	char pbuf[NI_MAXSERV];
		if (ai->ai_family == AF_INET6) {
	case AF_INET:
static const char **ok_paths;
	int status;

		return NULL;
struct credentials {
		if ((pid = waitpid(blanket->cld.pid, &status, WNOHANG)) > 1) {
				strbuf_addbuf(&hi->canon_hostname,

	 */
}


		if (skip_prefix(arg, "--init-timeout=", &v)) {
			continue;
		strbuf_setlen(&line, 0);
	{ "upload-archive", "uploadarch", upload_archive, 0, 1 },
}
				 strerror(errno));

			continue;
			int rc = run_service(arg, s, &hi, &env);
	return service->fn(env);

	case 'P':
	hints.ai_protocol = IPPROTO_TCP;
	switch (log_destination) {
		strbuf_reset(&buf);
		goto error_return;
{
}
			timeout = atoi(v);
{
			if (ai->ai_canonname)
		logerror("'%s' does not appear to be a git repository", dir);
			extra_args = val + vallen;
	for (i = 0; i < ARRAY_SIZE(daemon_service); i++) {
static void enable_service(const char *name, int ena)
#ifndef NO_IPV6

	}
			strbuf_addstr(sb, get_canon_hostname(hi));
	 * upon signal receipt
	}
			/* Note: error is not fatal */

		if (skip_prefix(arg, "--enable=", &v)) {
{
	for (; *in; in++) {

			vallen = strlen(val) + 1;

{
static unsigned int timeout;


	struct hostinfo *hostinfo;
			strbuf_addstr(&hi->ip_address, addrbuf);
{
static struct credentials *prepare_credentials(const char *user_name,
		}
static const char daemon_usage[] =
		if (!strcmp(arg, "--serve")) {
		return -1;
	*arg++ = path;
			*cradle = blanket->next;

			continue;
	while (out->len && out->buf[out->len - 1] == '.')
	set_keep_alive(sockfd);
static void logerror(const char *err, ...)
	}
		strbuf_addbuf(sb, &hi->tcp_port);
		if (hent) {
			      expand_path, &context);
	{ "receive-pack", "receivepack", receive_pack, 0, 1 },


			continue;
		}
	if (len && line[len-1] == '\n')
				 interp_path);
}

#endif
	LOG_DESTINATION_UNSET = -1,
}
	char *eol;
		if (!gai) {
		if (skip_prefix(arg, "--disable=", &v)) {




}
					 listen_addr->items[i].string, listen_port);
	alarm(init_timeout ? init_timeout : timeout);
		hent = gethostbyname(hi->hostname.buf);
		logerror("Could not listen to %s: %s",
	switch (family) {
	strbuf_release(&buf);
	}
	char *val;
			const char *dead = "";
"           [--inetd | [--listen=<host_or_ipaddr>] [--port=<n>]\n"
		}
				sanitize_client(&hi->canon_hostname,
	case LOG_DESTINATION_SYSLOG: {

	len = strlen(line);
			dir = rpath;
	int seen_errors = 0;
			logerror("Could not bind to %s: %s",
				listen_port = n;
		 * git-daemon needs to parse specifically (like the 'host' arg)
 *
			++*port;
			die("Invalid request");
	 * good client.
	if (log_destination != LOG_DESTINATION_STDERR) {
	va_start(params, err);
	for (i = 1; i < argc; ++i)
	strbuf_init(&hi->canon_hostname, 0);
			       sizeof(interp_path));
		}
	if (detach) {
static int reuseaddr;
}
			return NULL;
static const char *path_ok(const char *directory, struct hostinfo *hi)
}
	close(1);

				int incoming = accept(pfd[i].fd, &ss.sa, &sslen);
			continue;

		}
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
	for (i = 0; i < socklist->nr; i++) {
	if (daemon_avoid_alias(dir)) {
#endif
static int verbose;
	 * is ok with us doing this.
static const char *ip2str(int family, struct sockaddr *sin, socklen_t len)
	case AF_INET6:
			 access_hook);
		struct group *group = getgrnam(group_name);
	static struct credentials c;

				die("unknown log destination '%s'", v);
			max_connections = atoi(v);
	if (start_command(&cld))
			 */
}
	int i;
	return extra_args;
		set_die_routine(daemon_die);
				max_connections = 0;	        /* unlimited */
	}
			user_path = "";
		logerror("'%s': service not enabled for '%s'",
		kill_some_child();
#ifndef NO_IPV6
	size_t alloc;
{
	if (listen(sockfd, 5) < 0) {
		if (*in == '/')
{
		if (skip_prefix(arg, "--listen=", &v)) {

				if (incoming < 0) {
		*eol = '\0';
