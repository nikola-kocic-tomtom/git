				ai->ai_socktype, ai->ai_protocol);
	return end;
	item = string_list_append_nodup(symref, sym);

		detect.use_shell = conn->use_shell;
	if (!git_config_get_string_const("core.sshcommand", &ssh))
	char **ap;

	strbuf_addf(&request,
		break;
			/* core.gitproxy = none for kernel.org */
		if (flags & CONNECT_VERBOSE)
		int hostlen;
			continue;
	} else {
	child_process_init(proxy);
		struct servent *se = getservbyname(port,"tcp");
	get_host_and_port(&host, &port);
}
		for_pos = strstr(value, " for ");
	}
	argv_array_push(&proxy->args, host);
}
			if (0 <= sockfd)
			oidcpy(&peeled->old_oid, &peeled_oid);
	packet_write(fd[1], request.buf, request.len);

	if (p) {
		goto reject;
			if (matchlen == 4 &&

			if (process_dummy_ref(reader->line)) {
	int sockfd = -1;
	char *end;
		return 0;
		case VARIANT_PLINK:
		packet_write_fmt(fd_out, "peel\n");
}
		}
		case PROTO_GIT:
	/*
	 * means that it is unexpected, as we know the other end is

	if (string_list_split(&line_sections, line, ' ', -1) < 2) {
					      int is_cmdline)
		die(_("strange port '%s' blocked"), port);

	const char *slash = strchr(url, '/');
	**list = ref;
		if (!val)
/*
	for (cnt = 0, ap = he->h_addr_list; *ap; ap++, cnt++) {
}
	argv_array_push(&proxy->args, port);

			peeled = alloc_ref(peeled_name);
		**list = ref;
		conn = git_tcp_connect(fd, hostandport, flags);
	}
		*ssh_variant = VARIANT_AUTO;
 */
			die(_("ssh variant 'simple' does not support setting port"));
	EXPECTING_REF,
}
			  const char *port, enum protocol_version version,


				state = EXPECTING_SHALLOW;
}
	return proxy;

		child_process_init(conn);
	enum protocol protocol;
	if (unexpected)
}
		case PROTO_FILE:
	struct sockaddr_in sa;
		 !strcasecmp(variant, "tortoiseplink.exe"))
	VARIANT_TORTOISEPLINK,
#include "pkt-line.h"
	VARIANT_SIMPLE,
	target = strchr(sym, ':');
		if (!process_ref_v2(reader->line, &list))
	}
		conn->use_shell = 0;
		version = protocol_v0;
		*host = '\0';
	 * willing to talk to us.  A hang-up before seeing any
				       char **ret_path)
#else /* NO_IPV6 */
	struct child_process *proxy;
				return value;
				free(conn);
		int rhost_len = strlen(rhost_name);
		}
	*list = &ref->next;
			    int die_on_error)
	case PACKET_READ_EOF:
static void enable_keepalive(int sockfd)
 */
}
			git_proxy_command = xmemdupz(value, matchlen);
		case EXPECTING_SHALLOW:
{
	return check_ref(ref->name, flags);
	if (variant == VARIANT_SSH &&
		case VARIANT_AUTO:

 * will hopefully be changed in a libification effort, to return NULL when
		return ssh;
			*list = &peeled->next;
 *
	 */
		switch (variant) {
	if (!strcmp(name, "ssh"))
			free(peeled_name);
	for (ai0 = ai; ai; ai = ai->ai_next, cnt++) {
	}
	/* When pushing we don't want to request the peeled tags */
				 ref_prefixes->argv[i]);

	const char *name;
		argv_array_push(args, "-o");
			BUG("VARIANT_AUTO passed to push_ssh_options");
	return (git_proxy_command && *git_proxy_command);
}

	return 1;
				end++;

static int git_tcp_connect_sock(char *host, int flags)
	} else if (check_ref(name, flags)) {
	const char *end;
 * The caller is responsible for freeing hostandport, but this function may
		 * gitproxy = netcatter-1 for kernel.org
		const char *out;
		argv_array_push(args, "SendEnv=" GIT_PROTOCOL_ENVIRONMENT);
	return 1;
	return &no_fork;
static void get_host_and_port(char **host, const char **port)
	unsigned int nport;
			      struct oid_array *shallow_points)
		}
	if (!skip_prefix(line, "shallow ", &arg))
			return "file";
			}
			break;
		warning(_("ignoring capabilities after first line '%s'"),

		if ( !se )

static struct argv_array server_capabilities_v2 = ARGV_ARRAY_INIT;
		port = "<none>";
				free(hostandport);
		argv_array_pushf(env, GIT_PROTOCOL_ENVIRONMENT "=version=%d",
		const char **ssh_argv;
	 * from extended host header with a NUL byte.

/* Prepare a child_process for use by Git's SSH-tunneled transport. */

				free(path);
	free(conn);
	path = xstrdup(path);
		} else if (!colon[1]) {
	if (!path || !*path)

	struct ref **orig_list = list;

		BUG("unknown protocol version");

				break;
		const char *const *var;
	struct string_list symref = STRING_LIST_INIT_DUP;
		return PROTO_SSH;
/*

		argv_array_push(&detect.args, ssh_host);
				if (lenp)
		struct child_process detect = CHILD_PROCESS_INIT;
		case EXPECTING_DONE:
		return PROTO_GIT;
	 *


}
		} else {
		for (var = local_repo_env; *var; var++)
	case PACKET_READ_DELIM:

	 * Peek the first line of the server's response to
{
 * Append the appropriate environment variables to `env` and options to
{
			conn->trace2_child_class = "transport/ssh";

		start = host;
	}
		break;
	if (!variant && git_config_get_string_const("ssh.variant", &variant))
{
			else

	if (!skip_prefix(name, "refs/", &name))
		}
	if (!strcmp(var, "core.gitproxy")) {
	char *target_host = getenv("GIT_OVERRIDE_VIRTUAL_HOST");
	if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka)) < 0)
		path = strchr(end, separator);
	const char *feature_list = server_capabilities_v1;
			}

			sockfd = -1;
	else if (!strcmp(variant, "tortoiseplink"))

			die(_("unknown port %s"), port);
	end = host_end(host, 1);
#include "git-compat-util.h"
		feature_list = found + 1;
	    version > 0) {
		case VARIANT_SSH:
	}

}
{

				  const char *prog, int flags)
			peeled_name = xstrfmt("%s^{}", ref->name);
		}

	for (i = 0; i < server_capabilities_v2.argc; i++) {
			if (removebrackets) {
	struct object_id oid;

	die(_("protocol '%s' is not supported"), name);
		case EXPECTING_REF:
			break;
			/* feature with a value (e.g., "agent=git/1.2.3") */
					     int flags)
					  rhost_name + rhost_len - hostlen,
	 * null-terminate hostname and point path to ~ for URL's like this:
	strbuf_release(&request);
	int sockfd = git_tcp_connect_sock(host, flags);
}
			argv_array_push(&conn->env_array, *var);
	else if (!strcasecmp(variant, "tortoiseplink") ||
	return git_default_config(var, value, cb);
			fill_ssh_args(conn, ssh_host, port, version, flags);
	free(target_host);
		/* just "symref=something" */
		push_ssh_options(&detect.args, &detect.env_array,
	nport = strtoul(port, &ep, 10);
	if (!conn || git_connection_is_socket(conn))
	PROTO_LOCAL = 1,
	git_config(git_proxy_command_options, (void*)host);


			     const struct argv_array *ref_prefixes,
	} else if (!strcmp(name, "capabilities^{}")) {
		hints.ai_family = AF_INET6;
			separator = ':';
static void check_no_capabilities(const char *line, int len)
	}
}
	int sockfd = -1;
		switch (packet_reader_read(reader)) {
					  hostlen) &&
	code = finish_command(conn);

		if (0 <= matchlen) {
		if (skip_prefix(arg, "symref-target:", &arg))
int server_supports_v2(const char *c, int die_on_error)
{
			*port = colon + 1;
};
				return NULL;
	enum ssh_variant ssh_variant = VARIANT_AUTO;
}
	case protocol_v0:

	EXPECTING_DONE,
			/* matches everybody */
static const char *prot_name(enum protocol protocol)
		conn->use_shell = 1;
	else
	argv_array_push(&proxy->args, git_proxy_command);
		return; /* just "symref" */

		fd[0] = conn->out; /* read from child's stdout */
		break;
	git_proxy_command = getenv("GIT_PROXY_COMMAND");
	if (flags & CONNECT_VERBOSE)
	end = path; /* Need to \0 terminate host here */
		return;
}
	else if (!strcmp(variant, "putty"))
	const char *arg;
		strbuf_addch(&cmd, ' ');
			**list = peeled;
	}
		case VARIANT_SSH:
	if (is_url(url_orig))

		path++; /* path starts after ':' */
#include "transport.h"

			if (version > 0) {
	    check_refname_format(target, REFNAME_ALLOW_ONELEVEL))
	char *host, *path;

			matchlen = strlen(value);
/* Returns 1 when a valid ref has been added to `list`, 0 otherwise */
	switch (version) {
		ssh_variant = VARIANT_SSH;
		const char *val;
 * The caller must free() the returned strings.
#include "run-command.h"
	EXPECTING_SHALLOW,
	if (!feature_list)
		oid_array_append(extra_have, &old_oid);
	}
		if (path[1] == '~')
			BUG("VARIANT_AUTO passed to push_ssh_options");
	return NULL;
				inet_ntoa(*(struct in_addr *)&sa.sin_addr),
			char *peeled_name;
	}

		xsnprintf(addr, sizeof(addr), "(unknown)");
	return list;
	return conn == &no_fork;
		    (!*out || *(out++) == '=')) {
		strbuf_addf(&request, "version=%d%c",
	 */
	if (variant == VARIANT_AUTO) {
 *
	if (colon) {
		int matchlen = -1;
		goto out;
			if (0 <= sockfd)
const char *server_feature_value(const char *feature, int *len)
	if (looks_like_command_line_option(ssh_host))
			argv_array_push(args, "-P");
static void annotate_refs_with_symref_info(struct ref *ref)
			process_capabilities(reader->line, &len);

			}

	}
	if (flags & CONNECT_IPV4) {
	int i;
	/*
{

			 * any longer.

	int ka = 1;
{
		return 0;
		die(_("expected flush after capabilities"));
		(has_dos_drive_prefix(url) && is_valid_path(url));
	fd[0] = sockfd;
			if (process_ref(reader->line, len, &list, flags, extra_have))

	 * '[]' unwrapping in get_host_and_port()
			*colon = 0;
	free(path);
			char *ssh_host = hostandport;
		case VARIANT_SIMPLE:
	int i;
		*ssh_variant = VARIANT_SIMPLE;
		switch (state) {
	} else if (protocol == PROTO_GIT) {
	if (protocol == PROTO_GIT || protocol == PROTO_SSH) {
		fprintf_ln(stderr, _("done."));
static enum ssh_variant determine_ssh_variant(const char *ssh_command,
	string_list_clear(&symref, 0);

	}
	struct string_list_item *item;
		/* remove repo-local variables from the environment */
	return !(flags & ~REF_NORMAL);
		printf("Diag: path=%s\n", path ? path : "NULL");
	hints.ai_protocol = IPPROTO_TCP;
		process_capabilities_v2(reader);
#define STR(s)	STR_(s)
		die(_("unable to look up %s (port %s) (%s)"), host, port, gai_strerror(gai));

		path = host - 2; /* include the leading "//" */
	free(hostandport);
					     const char *path, const char *prog,
static const char *get_ssh_command(void)
 * modify it (for example, to truncate it to remove the port part).
		       unsigned int flags, struct oid_array *extra_have)
	}
}

	get_host_and_port(&host, &port);
			strbuf_addf(&error_message, "%s[%d: %s]: errno=%s\n",
			 * otherwise we matched a substring of another feature;
{
/*
	} else {
}
			if (flags & CONNECT_DIAG_URL) {
		variant = run_command(&detect) ? VARIANT_SIMPLE : VARIANT_SSH;

	/*
	return !!server_feature_value(feature, NULL);
	*len = nul_location;
	 * will cause older git-daemon servers to crash.
	/*
	if (git_use_proxy(hostandport))
		variant = basename(p);
		parse_one_symref_info(&symref, val, len);
		detect.no_stdin = detect.no_stdout = detect.no_stderr = 1;
{
	/* Without this we cannot rely on waitpid() to tell
		const char *out;
		conn->in = conn->out = -1;
	} else
{
	for (i = 0; ref_prefixes && i < ref_prefixes->argc; i++) {

	 * A hang-up after seeing some response from the other end
	else
		}

int parse_feature_request(const char *feature_list, const char *feature)
			transport_check_allowed("ssh");
	enable_keepalive(sockfd);
		target_host = xstrdup(target_host);

	char *end;

			BUG("VARIANT_AUTO passed to push_ssh_options");
			get_host_and_port(&ssh_host, &port);
	if (check_refname_format(sym, REFNAME_ALLOW_ONELEVEL) ||

	 * don't have a particular order.
	int gai;
{
	/* REF_HEADS means that we want regular branch heads */
{
{
	char *p = strchr(host, ':');
			      struct oid_array *extra_have,
 * Read all the refs from the other end
	enable_keepalive(sockfd);
{
		    prog, path, 0,
		die(_("unable to look up %s (%s)"), host, hstrerror(h_errno));

			fprintf(stderr, "%s ",
	enum ssh_variant variant;


	if (!target)
			return config_error_nonbool(var);

	/*

		return PROTO_FILE;

			     struct ref **list, int for_push,

			conn->trace2_child_class = "transport/file";
/*
		printf("Diag: hostandport=%s\n", hostandport ? hostandport : "NULL");
	if (flags & CONNECT_VERBOSE)
			end = host;
		for (i = 0; i < server_options->nr; i++)

			/*
	} else {
	/*
			state = EXPECTING_SHALLOW;
	const char *port = STR(DEFAULT_GIT_PORT);
		die(_("Could not read from remote repository.\n\n"

	return 0;
		end = strchr(start + 1, ']');
		return 0;
		packet_reader_read(reader);
		url = url_decode(url_orig);
		default:
	if (die_on_error)
		const char *for_pos;
	const char *ssh;
		case VARIANT_TORTOISEPLINK:
	check_no_capabilities(line, len);

		ssh_variant = VARIANT_TORTOISEPLINK;
	item->util = target;


			else if (!strncmp(for_pos + 5,
	if (get_oid_hex(arg, &old_oid))
		      "Please make sure you have the correct access rights\n"
			return "ssh";
	}
	gai = getaddrinfo(host, port, &hints, &ai);
		switch (variant) {
	return NULL;
	char *p = NULL;
	 */
struct child_process *git_connect(int fd[2], const char *url,
		long port = strtol(p + 1, &end, 10);
	if (looks_like_command_line_option(port))
{
	free(url);
		return 0;

		fprintf_ln(stderr, _("done."));
 * `args` for running ssh in Git's SSH-tunneled transport.
	packet_flush(fd_out);
	return ssh_variant;
int check_ref_type(const struct ref *ref, int flags)

				inet_ntoa(*(struct in_addr *)&sa.sin_addr));
		case VARIANT_PUTTY:
	}
	PROTO_SSH,
	int len = 0;
 * This returns the dummy child_process `no_fork` if the transport protocol
		goto reject;

		*ssh_variant = VARIANT_TORTOISEPLINK;
	server_capabilities_v1 = xstrdup(line + nul_location + 1);

		/* TRANSLATORS: this is the end of "Connecting to %s (port %s) ... " */
		case VARIANT_SIMPLE:
		argv_array_push(&detect.args, "-G");
	return code;
				printf("Diag: protocol=%s\n", prot_name(protocol));
	return addr;
/*
					*lenp = strcspn(value, " \t\n");

	packet_write_fmt(fd_out, "symrefs\n");

	annotate_refs_with_symref_info(*orig_list);

		}
		packet_write_fmt(fd_out, "ref-prefix %s\n",
		}

}
		}
	return sockfd;

{
		variant = determine_ssh_variant(ssh, 0);
			break;
}
		fprintf(stderr, _("done.\nConnecting to %s (port %s) ... "), host, port);
	switch (packet_reader_peek(reader)) {
				close(sockfd);
		die(_("server doesn't support '%s'"), c);
	free(sym);
			return "unknown protocol";
				*end = 0;
			const char *port = NULL;
	if (flags & CONNECT_VERBOSE)
		if (start_command(conn))
		ret = 0;
			}
		    connect(sockfd, (struct sockaddr *)&sa, sizeof sa) < 0) {
	 */
		case VARIANT_PLINK:
	 * connect, unless the user has overridden us in
		die(_("unable to connect to %s:\n%s"), host, error_message.buf);
	return NULL;
	int i;
}
		/* Read the peeked version line */
			     const struct string_list *server_options)

		} else {
	const char *name;
		die(_("repository on the other end cannot be shallow"));
	if ((flags & REF_NORMAL) && check_refname_format(name, 0))
	struct ref *ref;
		break;
	else if (!strcmp(variant, "plink"))
			break;
		    "%s %s%chost=%s%c",
			free(p);
static void override_ssh_variant(enum ssh_variant *ssh_variant)


	freeaddrinfo(ai0);
		case VARIANT_TORTOISEPLINK:
		case VARIANT_SSH:
{
}
	}
		case VARIANT_AUTO:

		url = xstrdup(url_orig);
		sa.sin_port = htons(nport);
	char *sym, *target;
	if (!he)
	free(p);
{


		switch (variant) {
		/*
	char *start = strstr(host, "@[");
	return oideq(&null_oid, &oid) && !strcmp(name, "capabilities^{}");
	/* If using a new version put that stuff here after a second null byte */
		*ssh_variant = VARIANT_PLINK;

		ret = 0;
				 version);

		 offset_1st_component(host - 2) > 1)
 */
static char *server_capabilities_v1;
				goto out;
			variant = basename((char *)ssh_argv[0]);
		printf("Diag: url=%s\n", url ? url : "NULL");
	case protocol_unknown_version:
	else if (protocol == PROTO_FILE && *host != '/' &&

	case PACKET_READ_FLUSH:
		if (git_proxy_command)

	if (*name != ' ')

	if (strlen(line) != len)

}
		hints.ai_family = AF_INET;

	if (!for_push)
 */
		*list = &ref->next;
			protocol = PROTO_SSH;
	push_ssh_options(&conn->args, &conn->env_array, variant, port, version, flags);
	if (!is_cmdline) {
			die(_("invalid ls-refs response: %s"), reader->line);
		}
			strbuf_addf(&error_message, "%s[%d: %s]: errno=%s\n",
	*ret_path = path;
		case VARIANT_SIMPLE:
		else {


	if (separator == ':')
enum protocol {
		strbuf_addch(&request, '\0');
	}
 * Returns a connected socket() fd, or else die()s.
	}
		return NULL;
#include "protocol.h"
static enum protocol parse_connect_url(const char *url_orig, char **ret_host,
		if (!found)
	if (!*port)
{
static struct child_process *git_connect_git(int fd[2], char *hostandport,
		return 0;
	proxy = xmalloc(sizeof(*proxy));
			    version, '\0');
		 */
			     enum ssh_variant variant, const char *port,
	} else {
	const char *colon = strchr(url, ':');


#include "cache.h"
	while (*feature_list) {
}

	else if (!strcasecmp(variant, "plink") ||
	string_list_sort(&symref);

		argv_array_push(&conn->args, cmd.buf);
		/* [core]
		die(_("unable to connect to %s:\n%s"), host, error_message.buf);
	if (!strcmp(name, "git+ssh")) /* deprecated - do not use */
	if ( ep == port || *ep ) {
			sockfd = -1;
	return conn;
		return PROTO_SSH;
enum protocol_version discover_version(struct packet_reader *reader)
		if (skip_prefix(server_capabilities_v2.argv[i], c, &out) &&
		void *cb)
	if (parse_oid_hex(line, &oid, &name))
		long portnr = strtol(colon + 1, &end, 10);
	switch (protocol) {
	if ((flags & REF_TAGS) && starts_with(name, "tags/"))
		nport = se->s_port;
	if ((flags & CONNECT_DIAG_URL) && (protocol != PROTO_SSH)) {
	/* REF_TAGS means that we want tags */
		if (!for_pos)

/*
			    !memcmp(value, "none", 4))
				return 1;
static const char *parse_feature_value(const char *, const char *, int *);
				matchlen = -1;
	override_ssh_variant(&ssh_variant);
			die(_("unable to fork"));
			return ssh_variant;


				matchlen = 0;
{

}
	return conn;
		struct string_list_item *item;
	const char *port = STR(DEFAULT_GIT_PORT);

{
			if (!*value || isspace(*value)) {
}
}
		case EXPECTING_FIRST_REF:
	else
					*lenp = 0;
		ref->symref = xstrdup((char *)item->util);
{
	if (reader->status != PACKET_READ_FLUSH)
	PROTO_FILE,
	host = strstr(url, "://");

			/*

			}
	return 0;

		variant = determine_ssh_variant(ssh, 1);
}
	fd[1] = proxy->in;  /* write to proxy stdin */
			state = EXPECTING_REF;
	} else if (flags & CONNECT_IPV6) {
	if (version > 0) {
			transport_check_allowed("file");
	 * Set up virtual host information based on where we will

	VARIANT_AUTO,
	check_no_capabilities(line, len);
	const char *variant;
{
			struct ref *peeled;

static char *host_end(char **hoststart, int removebrackets)
	if (start)
		case PACKET_READ_EOF:
		return 0;
	case protocol_v1:
static int git_proxy_command_options(const char *var, const char *value,

						 version);
	 * Ref lines have a number of fields which are space deliminated.  The
			if (!port)
	int cnt;
	}
		return 1;
		/* TRANSLATORS: this is the end of "Looking up %s ... " */
#ifndef NO_IPV6
	 * NEEDSWORK: If we are trying to use protocol v2 and we are planning
		sa.sin_family = he->h_addrtype;
{
		const char *found = strstr(feature_list, feature);
		}
		p = xstrdup(ssh_command);
	if (server_options && server_options->nr &&
	if (parse_oid_hex(line, &old_oid, &name))
			}

	len = strlen(feature);
			*p = '\0';
					 server_options->items[i].string);
			packet_write_fmt(fd_out, "server-option=%s",
		sockfd = socket(ai->ai_family,

	/* All type bits clear means that we are ok with anything */
			return 0;
				ret = 0;
};
				memmove(start, start + 1, end - start);
	int separator = '/';
	}


		item = string_list_lookup(&symref, ref->name);
}
 * does not need fork(2).

		case VARIANT_PUTTY:

		}
	    server_supports_v2("server-option", 1))
	*end = '\0';
	struct object_id old_oid;
{
{
		} else
			   struct oid_array *shallow_points)

	return;
			 * referenced by p, hence we do not need ssh_argv

		packet_write_fmt(fd_out, "command=ls-refs\n");

 * Open a connection using Git's native protocol.
		argv_array_push(args, "-batch");
 * support the former case).
		die(_("protocol error: expected shallow sha-1, got '%s'"), arg);
	if (getnameinfo(ai->ai_addr, ai->ai_addrlen, addr, sizeof(addr), NULL, 0,
		    (connect(sockfd, ai->ai_addr, ai->ai_addrlen) < 0)) {
}
	 * what happened to our children.
		printf("Diag: protocol=%s\n", prot_name(protocol));
				host,

	return sockfd;
			state = EXPECTING_DONE;
{
#include "refs.h"
		case VARIANT_PLINK:


	protocol = parse_connect_url(url, &hostandport, &path);

				 ((rhost_len == hostlen) ||
	ssh = get_ssh_command();
	else
 */

	 * Note: Do not add any other headers here!  Doing so
	for (; i < line_sections.nr; i++) {
	if (target_host)
		die(_("server doesn't support feature '%s'"), feature);
			/* fallthrough */
		 !strcasecmp(variant, "plink.exe"))
			return 1;
{
		      "and the repository exists."));
		error_errno(_("unable to set SO_KEEPALIVE on socket"));
				printf("Diag: url=%s\n", url ? url : "NULL");
			if (rhost_len < hostlen)
}
		return ssh_variant;

			argv_array_push(args, "-6");

		protocol = get_protocol(url);
		if (end != colon + 1 && *end == '\0' && 0 <= portnr && portnr < 65536) {
		const char *rhost_name = cb;
 */
				printf("Diag: path=%s\n", path ? path : "NULL");
	if (reader->status != PACKET_READ_FLUSH)
			die(_("protocol error: unexpected '%s'"), reader->line);

static const char *parse_feature_value(const char *feature_list, const char *feature, int *lenp)
	if (parse_oid_hex(line_sections.items[i++].string, &old_oid, &end) ||
		}
 */
			argv_array_push(args, "-4");
		if (skip_prefix(server_capabilities_v2.argv[i], c, &out) &&
	return ret;
		return;
	/*
	struct strbuf error_message = STRBUF_INIT;
				printf("Diag: userandhost=%s\n", ssh_host ? ssh_host : "NULL");
	 * These underlying connection commands die() if they
/*
			  int flags)
	case protocol_v2:
static int git_use_proxy(const char *host)

	}
		*ssh_variant = VARIANT_PUTTY;
	    *end) {
				strerror(errno));
static struct child_process *git_proxy_connect(int fd[2], char *host)
		path = end; /* "file://$(pwd)" may be "file://C:/projects/repo" */
		target_host = xstrdup(hostandport);
	char *end;
			 * At this point, variant points into the buffer

{
	string_list_clear(&line_sections, 0);
}
	 * Separate original protocol components prog and path
			      struct ref **list, unsigned int flags,
	struct hostent *he;
		return 0;

		conn = git_proxy_connect(fd, hostandport);
static void process_capabilities_v2(struct packet_reader *reader)

			 */
		int len;

	ref = alloc_ref(line_sections.items[i++].string);
				return value;
{
				cnt,
	oidcpy(&ref->old_oid, &old_oid);


	if (!strcmp(variant, "auto"))

{

				strbuf_release(&cmd);
	 * the environment.

		conn = NULL;
	while (packet_reader_read(reader) == PACKET_READ_NORMAL)
int server_supports_feature(const char *c, const char *feature,
}
	if (start_command(proxy))
		    target_host, 0);
	if (server_supports_v2("ls-refs", 1))

	/* e.g. "symref=HEAD:refs/heads/master" */
	hints.ai_socktype = SOCK_STREAM;

}

		ssh = getenv("GIT_SSH");
		strbuf_addstr(&cmd, prog);
	if ((flags & REF_HEADS) && starts_with(name, "heads/"))
		if ((sockfd < 0) ||
	proxy->out = -1;
{
static int git_tcp_connect_sock(char *host, int flags)


		ssh_variant = VARIANT_PLINK;
	if (flags & CONNECT_VERBOSE)
	if (ssh) {
			line + strlen(line));
	name++;
#include "config.h"
	 */
static int process_ref(const char *line, int len, struct ref ***list,
	 *    ssh://host.xz/~user/repo
				    host, cnt, ai_name(ai), strerror(errno));
			return "git";
	if (flags & CONNECT_IPV4)
	if (looks_like_command_line_option(host))
}
	if (sockfd < 0)
 * If it returns, the connect is successful; it just dies on errors (this
			free(ssh_argv);
		return 1;
{
static enum protocol get_protocol(const char *name)
	EXPECTING_FIRST_REF = 0,
	/* REF_NORMAL means that we don't want the magic fake tag refs */
	for (; ref; ref = ref->next) {

			argv_array_push(args, "-p");
	PROTO_GIT
	return version;
	 * how to push yet using v2.
	static char addr[NI_MAXHOST];
			ref->symref = xstrdup(arg);
		return 0;
	 */
	argv_array_push(&conn->args, ssh_host);
	 * Don't do destructive transforms as protocol code does
		if (protocol == PROTO_SSH) {
		 !has_dos_drive_prefix(host) &&
	*list = NULL;
			/* feature with no value (e.g., "thin-pack") */
		case PROTO_LOCAL:
	 * to perform a push, then fallback to v0 since the client doesn't know
		conn = xmalloc(sizeof(*conn));
		host = url;
	fd[1] = dup(sockfd);

	fd[0] = proxy->out; /* read from proxy stdout */
{
	 * response does not necessarily mean an ACL problem, though.
	*ret_host = xstrdup(host);
		case VARIANT_AUTO:
	if (!strcasecmp(variant, "ssh") ||
 * done, finish the connection with finish_connect() with the value returned
{
int finish_connect(struct child_process *conn)
#include "alias.h"
{
			else
		argv_array_push(&detect.args, ssh);
{
				if (lenp)
	transport_check_allowed("git");
	if (nul_location == *len)
	const char *variant = getenv("GIT_SSH_VARIANT");

}
static int check_ref(const char *name, unsigned int flags)
	int nul_location = strlen(line);

#include "quote.h"
	    !strcasecmp(variant, "ssh.exe"))

static int process_dummy_ref(const char *line)

			else if (*value == '=') {
	else if (flags & CONNECT_IPV6)
		 * GIT_SSH is the no-shell version of
	for (i = 0; i < server_capabilities_v2.argc; i++) {

		    (!*out || *out == '='))
				argv_array_pushf(&conn->env_array, GIT_PROTOCOL_ENVIRONMENT "=version=%d",
				 VARIANT_SSH, port, version, flags);

	}
		die(_("no path specified; see 'git help pull' for valid url syntax"));
			}
	if (server_supports_v2("agent", 0))
int url_is_local_not_ssh(const char *url)
		die(_("strange hostname '%s' blocked"), host);
	return list;
	get_host_and_port(&host, &port);
		if ((sockfd < 0) ||
	signal(SIGCHLD, SIG_DFL);
}
		break;
	struct object_id old_oid;
	}
	argv_array_push(&conn->args, ssh);


	enum protocol_version version = protocol_unknown_version;
	else

			len = reader->pktlen;
	if (variant == VARIANT_TORTOISEPLINK)
		case PACKET_READ_NORMAL:
		return 0;
		if (end) {
		p = xstrdup(ssh_command);
		return ssh;


		val = parse_feature_value(feature_list, "symref", &len);
	colon = strchr(end, ':');
			break;
enum get_remote_heads_state {

					     enum protocol_version version,
{
	if (!flags)
	if (flags & CONNECT_VERBOSE)
static void parse_one_symref_info(struct string_list *symref, const char *val, int len)
		case PACKET_READ_DELIM:
				printf("Diag: port=%s\n", port ? port : "NONE");
			     enum protocol_version version, int flags)
		fprintf(stderr, _("done.\nConnecting to %s (port %s) ... "), host, port);
	packet_delim(fd_out);
				matchlen = -1;
		sockfd = socket(he->h_addrtype, SOCK_STREAM, 0);
		path = end;
	if (!len)


				break;
	struct string_list line_sections = STRING_LIST_INIT_DUP;
	/*

	return !colon || (slash && slash < colon) ||
			 */

		conn = git_connect_git(fd, hostandport, path, prog, version, flags);
	while (feature_list) {
		die(_("the remote end hung up upon initial contact"));
		if (looks_like_command_line_option(path))
	 * name.  Subsequent fields (symref-target and peeled) are optional and

struct ref **get_remote_heads(struct packet_reader *reader,
	return;
	if (version == protocol_v2 && !strcmp("git-receive-pack", prog))
	while (state != EXPECTING_DONE) {
}
		die(_("expected flush after ref listing"));
	if (host) {
		die(_("strange hostname '%s' blocked"), ssh_host);
	he = gethostbyname(host);

		if (skip_prefix(arg, "peeled:", &arg)) {
		 * GIT_SSH_COMMAND (and must remain so for

	const char *ssh;

				matchlen = for_pos - value;
reject:
	/* Process response from server */
static char *git_proxy_command;
			 * keep looking
		packet_write_fmt(fd_out, "agent=%s", git_user_agent_sanitized());
	enum protocol protocol = PROTO_LOCAL;
		return PROTO_SSH;
	if ((ssh = getenv("GIT_SSH_COMMAND")))
	if (!strcmp(name, "git"))
		/* "symref=bogus:pair */

{
		/* Not numeric */
		 */
}

		}

		struct ref *ref = alloc_ref(name);



		fd[1] = conn->in;  /* write to child's stdin */
			*colon = 0;
			continue;
/*
static void push_ssh_options(struct argv_array *args, struct argv_array *env,
	struct object_id old_oid;
static int process_shallow(const char *line, int len,
	if (gai)

		if (!ssh)
{
		 * ;# matches www.kernel.org as well
	}
		if (!value)
		host += 3;
		sq_quote_buf(&cmd, path);
	char *url;
		*ssh_variant = VARIANT_SSH;
		struct strbuf cmd = STRBUF_INIT;
	if (sockfd < 0)
	struct strbuf error_message = STRBUF_INIT;
	 */
				break;
#endif /* NO_IPV6 */
 * the connection failed).
 * from this function (it is safe to call finish_connect() with NULL to

	enum get_remote_heads_state state = EXPECTING_FIRST_REF;
	}
	char *hostandport, *path;
		version = determine_protocol_version_client(reader->line);
	}
 * Dummy child_process returned by git_connect() if the transport protocol
	if (port) {
	const char *port = STR(DEFAULT_GIT_PORT);
		memset(&sa, 0, sizeof sa);
	*list = NULL;
	enum protocol_version version = get_protocol_version_config();
#include "oid-array.h"
static struct child_process *git_tcp_connect(int fd[2], char *host, int flags)
			struct object_id peeled_oid;
{
#define STR_(s)	# s
	if (protocol == PROTO_LOCAL)
	VARIANT_SSH,
	char *host = *hoststart;
			path++;
		if (end != p + 1 && *end == '\0' && 0 <= port && port < 65536) {
		if (split_cmdline(p, &ssh_argv) > 0) {
		if (!item)
	}
			if (parse_oid_hex(arg, &peeled_oid, &end) || *end) {
	memset(&hints, 0, sizeof(hints));
		if (feature_list == found || isspace(found[-1])) {
	 * determine the protocol version the server is speaking.
}

		break;
#include "url.h"
		oidcpy(&ref->old_oid, &old_oid);

		goto out;

	 * first field is the OID of the ref.  The second field is the ref
 */
		 * gitproxy = netcatter-default
		version = protocol_v0;
	int len;

	struct child_process *conn;
}
}
	int cnt = 0;
static void fill_ssh_args(struct child_process *conn, const char *ssh_host,
};
		argv_array_push(&server_capabilities_v2, reader->line);

	 */
	if (die_on_error)

		case PROTO_SSH:
				break;
		break;
	 */
{
	else if (!strcmp(variant, "simple"))
	if (flags & CONNECT_VERBOSE)
	proxy->in = -1;
			hostlen = strlen(for_pos + 5);
}
			die(_("strange pathname '%s' blocked"), path);
	while (packet_reader_read(reader) == PACKET_READ_NORMAL) {
	else if (protocol == PROTO_FILE && has_dos_drive_prefix(end))
			if (parse_feature_request(out, feature))
	return protocol;
#include "version.h"
		/* TRANSLATORS: this is the end of "Connecting to %s (port %s) ... " */
		}
	name++;
		if (flags & CONNECT_VERBOSE)

	end = host_end(&host, 0);
			die(_("invalid packet"));
		die(_("protocol error: unexpected capabilities^{}"));
		end = host;
		case VARIANT_TORTOISEPLINK:
		const char *arg = line_sections.items[i].string;
struct ref **get_remote_refs(int fd_out, struct packet_reader *reader,
			/* fallthrough */
		conn->trace2_child_class = "transport/git";
#include "string-list.h"
#include "remote.h"
	}
	}
			continue;
/* Checks if the server supports the capability 'c' */

	return !!parse_feature_value(feature_list, feature, NULL);
	strbuf_release(&error_message);
 * Extract protocol and relevant parts from the specified connection URL.
		fprintf(stderr, _("Looking up %s ... "), host);
int git_connection_is_socket(struct child_process *conn)
	if (extra_have && !strcmp(name, ".have")) {
static NORETURN void die_initial_contact(int unexpected)
	else

	struct child_process *conn;
static void process_capabilities(const char *line, int *len)

		feature_list = val + 1;
				port = get_port(ssh_host);
{


		argv_array_push(args, port);
		strbuf_release(&cmd);
			return p+1;
	if (*name != ' ')
	if (!strcmp(name, "ssh+git")) /* deprecated - do not use */


out:
	*(target++) = '\0';
		 * gitproxy = netcatter-2 for sample.xz
static int process_ref_v2(const char *line, struct ref ***list)
{
		case PACKET_READ_FLUSH:
	 * cannot connect.
		fprintf(stderr, _("Looking up %s ... "), host);
	struct strbuf request = STRBUF_INIT;
	struct addrinfo hints, *ai0, *ai;
	int i = 0;
	if (ssh_variant != VARIANT_AUTO)
	sym = xmemdupz(val, len);
		memcpy(&sa.sin_addr, *ap, he->h_length);
}
}
		start++; /* Jump over '@' */
			ssh = "ssh";
			return NULL;

				close(sockfd);
static struct child_process no_fork = CHILD_PROCESS_INIT;

	VARIANT_PLINK,
			die(_("ssh variant 'simple' does not support -4"));
static const char *ai_name(const struct addrinfo *ai)
	int code;

			die(_("ssh variant 'simple' does not support -6"));
			fprintf(stderr, "%s ", ai_name(ai));
 * Returns a connected socket() fd, or else die()s.

		die_initial_contact(0);
	oid_array_append(shallow_points, &old_oid);
	if (!shallow_points)

	if (!strcmp(name, "file"))
static char *get_port(char *host)
}
	int ret = 1;
			die_initial_contact(1);
			const char *value = found + len;
enum ssh_variant {
		die(_("cannot start proxy %s"), git_proxy_command);
	char *colon, *end;

	return parse_feature_value(server_capabilities_v1, feature, len);
	char *ep;
		return 1;
	case PACKET_READ_NORMAL:
		}
			if (process_shallow(reader->line, len, shallow_points))
 * does not need fork(2), or a struct child_process object if it does.  Once
	VARIANT_PUTTY,
	/*
		case VARIANT_PUTTY:
int server_supports(const char *feature)
				value++;
	if (start[0] == '[') {
	}
	else
		 * historical compatibility).
#include "connect.h"
		/* TRANSLATORS: this is the end of "Looking up %s ... " */
	}
	 */
			NI_NUMERICHOST) != 0)
		if (!url_is_local_not_ssh(url)) {
				  rhost_name[rhost_len - hostlen -1] == '.'))
		}

#include "strbuf.h"
