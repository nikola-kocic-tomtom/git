				return RESP_BAD;
		if (!server.tunnel) {
 *
		fprintf(stderr, "%4u%% (%d/%d) done\r", percent, n, total);
	int port;
#include "exec-cmd.h"
}
static int imap_exec(struct imap_store *ctx, struct imap_cmd_cb *cb,
	int n, resp, resp2, tag;
#ifdef NO_OPENSSL

	do {
	return n;
static const char *cap_list[] = {
#endif
#define DRV_OK          0
	NULL,	/* user */

	int r;

	if (sock->ssl) {
	char *p = all_msgs->buf;
		return 1;
	struct imap_cmd *cmd;
	response_64 = xmallocz(ENCODED_SIZE(resp_len));

		break;
		if (*arg == '*') {
static struct option imap_send_options[] = {
	NULL,	/* name */
#define CHUNKSIZE 0x1000
 * Copy the next message from all_msgs, starting at offset *ofs, to
			fputs("Error: unable to connect to server.\n", stderr);
	curl_easy_cleanup(curl);
	UIDPLUS,
struct imap_socket {
	die("If you want to use CRAM-MD5 authenticate method, "
		int prev_len;
		die("Fatal: Out of memory");
			}
	s++;
#define RESP_OK    0

	if (!strcmp("PREAUTH", arg))
	CURL *curl;
				return -1;
	char *uri_encoded_folder;
			fprintf(stderr, "IMAP error: unexpected reply: %s %s\n", arg, cmd ? cmd : "");
	hex[32] = 0;
	{
	 * length of challenge_64 (i.e. base-64 encoded string) is a good

	int n, bufl;
	struct imap *imap;

	resp_len = strlen(response);
		while (isspace((unsigned char)*s))
		if (level && *s == ')') {
			return RESP_BAD;
	git_config_get_bool("imap.sslverify", &server.ssl_verify);
	if (0 < verbosity) {
		return -1;
#ifdef NO_OPENSSL
		}
	cmdp = issue_imap_cmd(ctx, cb, fmt, ap);
		close(sock->fd[1]);
			else if (starts_with(val, "imaps:")) {
		warning("--curl not supported in this build");

			    socket_write(&imap->buf.sock, "\r\n", 2) != 2) {
	int uidvalidity;
#ifndef USE_CURL_FOR_IMAP_SEND
	}
		SSL_shutdown(sock->ssl);
				   * and '<num> RECENT' but as a probably-unintended side
	return len;
	va_list va;
			free(cmdp->cb.data);
			}

			    strlen((const char *)subj_alt_name->d.ia5->data) == (size_t)subj_alt_name->d.ia5->length &&
#if LIBCURL_VERSION_NUM >= 0x070d01
			s = socket(ai->ai_family, ai->ai_socktype,
	strbuf_add(msg, data, len);
			assert(b->offset + 1 < b->bytes);
#include "config.h"
	p = strstr(data, "\nFrom ");
/*

	for (i = 0; i < 16; i++) {
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

		}


	void *ctx;
	int i, found;
		return -1;
	if (cred.username) {
	if (!cmdp)
#ifndef NO_IPV6
	struct strbuf all_msgs = STRBUF_INIT;
			char addr[NI_MAXHOST];

#endif
				if (0 < verbosity)
	} else if (cmd->cb.cont)
/* We don't have curl, so continue to use the historical implementation */
	}

			return RESP_BAD;
	char *s = *sp;
static int get_cmd_result(struct imap_store *ctx, struct imap_cmd *tcmd)
#include "credential.h"
	"STARTTLS",

		goto bail;
			}
	if (!(subj = X509_get_subject_name(cert)))
	NULL,	/* tunnel */



static int split_msg(struct strbuf *all_msgs, struct strbuf *msg, int *ofs)
			free(cmdp->cmd);
}

struct imap_cmd {
		tunnel.out = -1;
 *  it under the terms of the GNU General Public License as published by
					return RESP_BAD;
	struct imap_store *ctx = NULL;
}
			if (!p) break;
}
{
	}
static char *cram(const char *challenge_64, const char *user, const char *pass)
	}
	ctx = imap_open_store(server, server->folder);
}


		if (res == CURLE_OK)
	imap->caps = 0x80000000;
				   * Ignore it.
			if (n <= 0)
	curl_easy_setopt(curl, CURLOPT_URL, path.buf);
	if (server.tunnel)
static void ssl_socket_perror(const char *func)
}
}
static int imap_store_msg(struct imap_store *ctx, struct strbuf *msg)
#else
		return -1;
	int nongit_ok;
	/* check the target mailbox exists */
#define RESP_BAD   2
		}
	/* not reached */
			if (!strcmp(cap_list[i], arg))
			break;
}
	return 0;
struct imap_buffer {
/*
{
		hints.ai_protocol = IPPROTO_TCP;
		/* ok */
			die("cannot start proxy %s", srvc->tunnel);
		}
			if (!arg)
	parse_response_code(ctx, NULL, rsp);
				continue;
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, server.ssl_verify);
			break;
	va_list va;

			for (; *s && !isspace((unsigned char)*s); s++)
					break;
	return res != CURLE_OK;
static int append_msgs_to_imap(struct imap_server_conf *server,
			b->bytes += n;
typedef void *SSL;
		if (verify_hostname(cert, server.host) < 0)
		gai = getaddrinfo(srvc->host, portstr, &hints, &ai);
	struct imap *imap = ctx->imap;
		if (!(arg = next_arg(&s)) || !(ctx->uidvalidity = atoi(arg)) ||


}
	if (!body)
#endif
static char hexchar(unsigned int b)
	if (use_curl) {
				 (curl_off_t)(msgbuf.buf.len-prev_len));
	if (!total) {
	if (cmd->cb.data) {
		preauth = 1;

		return 0;
	return b < 10 ? '0' + b : 'a' + (b - 10);


	close(sock->fd[1]);

	return get_cmd_result(ctx, cmdp);
		}
	}
#define CAP(cap) (imap->caps & (1 << (cap)))

	/* response: "<user> <digest in hex>" */
			fprintf(stderr, "IMAP error: could not create missing mailbox\n");
static void imap_info(const char *, ...);
static char *cram(const char *challenge_64, const char *user, const char *pass)
				b->bytes = n;
	}
				   * responses.  imap-send doesn't ever try to read

}
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
			GENERAL_NAME *subj_alt_name = sk_GENERAL_NAME_value(subj_alt_names, i);
		if (r != DRV_OK)


	int s = -1, preauth;
 * Insert CR characters as necessary in *msg to ensure that every LF
		parse_capability(imap, s);
			s++;
			goto out;
		credential_reject(&cred);
			free(cmd->cb.data);
		int gai;
				return RESP_BAD;
#elif defined(NO_OPENSSL)
	}
	for (i = j = 0, lastc = '\0'; i < msg->len; i++) {
#ifndef NO_OPENSSL
				fprintf(stderr, "IMAP error: unable to parse untagged response\n");
				fprintf(stderr, "IMAP error: LOGIN failed\n");
			}

#include "cache.h"
		}
		fprintf(stderr, "no messages to send\n");
		if (buffer_gets(&imap->buf, &cmd))
				val += 6;

		imap_info("Logging in...\n");
{
		    !(arg = next_arg(&s)) || !(*(int *)cb->ctx = atoi(arg))) {
};
			if (imap_exec(ctx, NULL, "STARTTLS") != RESP_OK)

	if (!cmdp)
{
		} else
		p++;
		if (!split_msg(all_msgs, &msg, &ofs))
}

	0,   	/* use_ssl */
		imap->buf.sock.fd[0] = tunnel.out;

					return resp;
		fprintf(stderr, "error reading input\n");
	struct strbuf buf = STRBUF_INIT;
			credential_reject(&cred);
					!starts_with(cmdp->cmd, "LOGIN") ?
		hints.ai_socktype = SOCK_STREAM;
	curl_free(uri_encoded_folder);
		char portstr[6];
				    sizeof(addr), NULL, 0, NI_NUMERICHOST);

			if (imap_exec(ctx, NULL, "CAPABILITY") != RESP_OK)
{
		imap_info("ok\n");
	if (cb)
{
	1,   	/* ssl_verify */

	ret = SSL_connect(sock->ssl);
			if (s < 0)
					srvc->user, srvc->host);
	if (0 <= verbosity) {
{
	len = all_msgs->len - *ofs;
	SSL_METHOD *meth;
			if (!strcmp("NAMESPACE", arg)) {
	return append_msgs_to_imap(&server, &all_msgs, total);
				fprintf(stderr, "Unknown authentication method:%s\n", srvc->host);
static void imap_close_store(struct imap_store *ctx)
		return curl_append_msgs_to_imap(&server, &all_msgs, total);
static int socket_write(struct imap_socket *sock, const char *buf, int len)
			if (!tcmd || tcmd == cmdp)

#endif
	}
		goto bail;

	    "you have to build git-imap-send with OpenSSL library.");
#ifdef USE_CURL_FOR_IMAP_SEND

		} else if (!imap->in_progress) {
			fprintf(stderr, "no imap host specified\n");
 *  the Free Software Foundation; either version 2 of the License, or
		tunnel.use_shell = 1;
			       char *s)
			break;

			} else if (cmdp->cb.cont) {
		}
		sock->fd[0] = sock->fd[1] = -1;
		fprintf(stderr, "IMAP error: unknown greeting response\n");
	if (cred.username)
	curl = setup_curl(server, &cred);
#else
	strbuf_release(&path);
}
						"CRAM-MD5 as authentication method, "
			count++;
		ssl_socket_perror("SSL_CTX_new");
};

			fprintf(stderr, "IMAP error: malformed UIDVALIDITY status\n");
				   * Unhandled response-data with at least two words.
	static char *pre_open = "<pre>\n";

	if (strlen(cname) == (size_t)len && host_matches(hostname, cname))
	ctx->prefix = "";
}
	}
		}
		struct addrinfo hints, *ai0, *ai;

#ifdef USE_CURL_FOR_IMAP_SEND

static int count_messages(struct strbuf *all_msgs)
	struct imap_buffer buf; /* this is BIG, so put it last */
	}
	}
	fprintf(stderr, "sending %d message%s\n", total, (total != 1) ? "s" : "");
		BUG("buffer too small. Please report a bug.");

			goto bail;
			(*s)++;
	p = strchr(data, '\n');
			} else {
}
			server.host = xstrdup(val);
		return 0;
	sock->ssl = SSL_new(ctx);
		++*s;

	if (!curl)

			fprintf(stderr, "IMAP error: unexpected tag %s\n", arg);
			if (!p) break;

	*ofs += len;
		return ret;
	/* read the messages */
			credential_approve(&cred);
	int count = 0;
		ssl_socket_perror("SSL_CTX_set_default_verify_paths");
{
	}
static int host_matches(const char *host, const char *pattern)
	if (!strcmp("UIDVALIDITY", arg)) {
#define DRV_STORE_BAD   -3
}


	if (p) {
	default: return DRV_OK;
	}
	ret = socket_write(&ctx->imap->buf.sock, response, strlen(response));

	}
			if (cmdp->cb.done)
int cmd_main(int argc, const char **argv)
	imap->in_progress_append = &imap->in_progress;


				cb.cont = auth_cram_md5;
					return RESP_BAD;
		close(sock->fd[0]);
	int ofs = 0;
#else
					memmove(b->buf, b->buf + start, n);
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
							cmdp->cmd : "LOGIN <user> <pass>",
{
 */
		if (!cert)

	struct strbuf path = STRBUF_INIT;
#define DRV_BOX_BAD     -2
		imap->buf.sock.fd[1] = dup(s);
	0,	/* port */

		if (msg->buf[i] == '\n' && lastc != '\r')
	cred->username = xstrdup_or_null(srvc->user);
static void imap_warn(const char *, ...);
	char *pass;

			return error("unable to get peer certificate.");
	const char *body = strstr(msg->buf, "\n\n");
				if ((resp = parse_response_code(ctx, NULL, cmd)) != RESP_OK)
	while (1) {
	curl_easy_setopt(curl, CURLOPT_PASSWORD, server.pass);
	X509 *cert;
static int verbosity;
	int use_html;
	SSL_load_error_strings();
			free(cmdp);
	if (len < 0)

static char *next_arg(char **);
	}
	}
static int ssl_socket_connect(struct imap_socket *sock, int use_tls_only, int verify)

		die("invalid challenge %s", challenge_64);
	if (socket_write(&imap->buf.sock, buf, bufl) != bufl) {
	int n = 0;
/*
		cert = SSL_get_peer_certificate(sock->ssl);
				cmdp->cb.done(ctx, cmdp, resp);
		     const char *fmt, ...)
	strbuf_add(&buf, msg->buf, body - msg->buf - 1);
		}
	case RESP_OK:
	CURLcode res = CURLE_OK;
}
		}
			if (!imap->buf.sock.ssl)
			} else {

{
	char *tunnel;
#ifndef NO_OPENSSL
	setup_git_directory_gently(&nongit_ok);
	if (verify) {
#endif

	struct imap_cmd_cb cb;
	strbuf_addstr(&path, server.use_ssl ? "imaps://" : "imap://");
	imap->buf.sock.fd[0] = imap->buf.sock.fd[1] = -1;
		} else if (*s == '"') {
static int nfvasprintf(char **strp, const char *fmt, va_list ap)
		srvc->pass = xstrdup(cred->password);

	imap->rcaps = imap->caps;
				assert(start <= b->bytes);

	cmdp = issue_imap_cmd(ctx, cb, fmt, ap);
#if defined(USE_CURL_FOR_IMAP_SEND)
	}
/* Always default to curl if it's available. */
	if (!HMAC(EVP_md5(), pass, strlen(pass), (unsigned char *)challenge, decoded_len, hash, NULL))
#endif

#endif


			arg = next_arg(&cmd);


	*p++ = 0;
	preauth = 0;
		 * to the user
}
	challenge = xmalloc(encoded_len);
				memset(&cb, 0, sizeof(cb));
		unsigned percent = n * 100 / total;
	if (!meth) {

	if (!arg) {
	ctx = xcalloc(1, sizeof(*ctx));
{
};
		if (cb)
		for (i = 0; i < ARRAY_SIZE(cap_list); i++)
			new_msg[j++] = '\r';
	}
				   * effect it ignores other unrecognized two-word
			cmdp = (struct imap_cmd *)((char *)imap->in_progress_append -
		if (server->use_html)
static int use_curl = USE_CURL_DEFAULT;
	box = ctx->name;

		return -1;
{
				goto bail;
		if (!(arg = next_arg(&s)) || !(ctx->uidvalidity = atoi(arg))) {
		b->offset++;
#if LIBCURL_VERSION_NUM < 0x072200
			if (starts_with(val, "imap:"))
			       offsetof(struct imap_cmd, next));
static const char * const imap_send_usage[] = { "git imap-send [-v] [-q] [--[no-]curl] < <mbox>", NULL };
		die("imap command overflow!");
		} else {
#endif

	cred->host = xstrdup(srvc->host);
 *
	credential_clear(&cred);
			break;
		s = socket(PF_INET, SOCK_STREAM, 0);
		imap_info("ok\n");
		return RESP_BAD;
	}
		for (ai0 = ai; ai; ai = ai->ai_next) {
	struct imap_cmd *in_progress, **in_progress_append;
	int fd[2];

struct imap {
			if (!cmdp->cb.cont)
		if (b->offset + 1 >= b->bytes) {
		memset(&hints, 0, sizeof(hints));
				/* rfc2342 NAMESPACE response. */
			close(s);
	if (!s || !*s)
			perror("SSL_connect");

	free(imap);
	while ((arg = next_arg(&cmd)))
			} else {
	if (srvc->tunnel) {
	imap->num_in_progress++;

	cred->protocol = xstrdup(srvc->use_ssl ? "imaps" : "imap");
	strbuf_addstr(&buf, pre_close);
			if (!strcmp(srvc->auth_method, "CRAM-MD5")) {
	if (!**s) {
{
	if (pattern[0] == '*' && pattern[1] == '.') {

	int ret;

	cmd = xmalloc(sizeof(struct imap_cmd));
			break;

#ifdef USE_CURL_FOR_IMAP_SEND
	setup_curl_trace(curl);
	char *arg;
		if (imap_exec(ctx, NULL, "CREATE \"%s\"", ctx->name) == RESP_OK) {
	int start = b->offset;
	return n;
	 * OpenSSL does not document this function, but the implementation
	va_end(va);
	int tag;
				   */

bail:
			printf(">>> %d LOGIN <user> <pass>\n", cmd->tag);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	struct imap_cmd *next;
	int len;
}

	if (!SSL_CTX_set_default_verify_paths(ctx)) {
		return error("IMAP error: sending response failed");

	return curl;
	memset(&cb, 0, sizeof(cb));
	}

		return DRV_STORE_BAD;
	if (-2 < verbosity) {
		if (srvc->use_ssl &&

}

		struct hostent *he;
	}
					puts(*s);
	imap_close_server(ctx);
		fprintf(stderr, "nothing to send\n");
	imap_close_store(ctx);
	/* read the greeting string */
					fprintf(stderr, "You specified "
			if (start) {
		va_end(va);

	if (verify)
	strbuf_addstr(&buf, content_type);
		goto bail;
	} else if (!strcmp("ALERT", arg)) {
	encoded_len = strlen(challenge_64);
}
#else /* NO_IPV6 */
	if (!ctx) {
	 * Second pass: write the new_msg string.  Note that this loop is

}
					resp = RESP_BAD;
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 *  This program is distributed in the hope that it will be useful,
		default:

bail:
		fprintf(stderr, "IMAP error: could not check mailbox\n");
		curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_TRY);
			return RESP_BAD;

	response = xstrfmt("%s %s", user, hex);
		if (!srvc->use_ssl && CAP(STARTTLS)) {
	if (*s) {
#endif

 *  (at your option) any later version.
	int i, resp_len, encoded_len, decoded_len;
		freeaddrinfo(ai0);
			*s = NULL;
		lf_to_crlf(&msgbuf.buf);
				if (level && *s == ')')
				goto bail;
{
					goto bail;
	}
{
			if (ssl_socket_connect(&imap->buf.sock, 1,
	curl_global_cleanup();
			perror("gethostbyname");
		len = &p[1] - data;
	new_msg = xmallocz(j);
			if (!arg) {

	SSL_library_init();
	char lastc;
		if (connect(s, (struct sockaddr *)&addr, sizeof(addr))) {
	cb.dlen = msg->len;
}
	imap_close_store(ctx);
		return RESP_OK;		/* no response code */
	char *cmd;
				else /*if (!strcmp("BAD", arg))*/

		else if (res == CURLE_LOGIN_DENIED)
		fprintf(stderr, "IMAP error: malformed response code\n");

	if (!path.len || path.buf[path.len - 1] != '/')

	curl = curl_easy_init();
		}
				if (!strcmp("NO", arg))

		} else {
	credential_fill(cred);
				   !strcmp("NO", arg) || !strcmp("BYE", arg)) {

	if (**s == '"') {
	return count;
				free(cmd->cmd);
#else
};
#endif
	NAMESPACE,
		case SSL_ERROR_SYSCALL:
	}
		fprintf(stderr, "IMAP error: invalid greeting response\n");
{
		return error("cannot get certificate common name");
				/* CRAM-MD5 */
#include "http.h"
 * character in *msg is preceded by a CR.

	else

}
	 * SNI (RFC4366)
	for (;;) {
		if (CAP(LITERALPLUS)) {
		}

	meth = SSLv23_method();
	switch (get_cmd_result(ctx, cmdp)) {
			for (pcmdp = &imap->in_progress; (cmdp = *pcmdp); pcmdp = &cmdp->next)
		addr.sin_addr.s_addr = *((int *) he->h_addr_list[0]);
			ssl_socket_perror("SSL_connect");

		if (*s == '(') {
		return RESP_BAD;
		}
		else
	git_imap_config();
		imap_exec(ictx, NULL, "LOGOUT");
				return NULL;
			/* This can happen only with the last command underway, as
	nfvasprintf(&cmd->cmd, fmt, ap);
}
static int parse_response_code(struct imap_store *ctx, struct imap_cmd_cb *cb,
		r = imap_store_msg(ctx, &msg);
		}

				  CAP(LITERALPLUS) ? "+" : "");
		use_curl = 1;

	}
		lastc = new_msg[j++] = msg->buf[i];
	argc = parse_options(argc, (const char **)argv, "", imap_send_options, imap_send_usage, 0);
				*s = b->buf;
	server_fill_credential(&server, cred);
		(*s)++;
		return; /* Headers but no body; no wrapping needed */
 * Copyright (C) 2006 Mike McCormack

	} else {
		imap_info("ok\n");
};
	unsigned i;
			goto bail;
	"UIDPLUS",


	int ret;

 *  This program is free software; you can redistribute it and/or modify
	NOLOGIN = 0,
#ifndef NO_OPENSSL

	switch (imap_exec(ctx, NULL, "EXAMINE \"%s\"", ctx->name)) {
			perror(func);
{
	fprintf(stderr, "SSL requested but SSL support not compiled in\n");
		fprintf(stderr, "*** IMAP ALERT *** %s\n", p);
				; /*
static int nfsnprintf(char *buf, int blen, const char *fmt, ...);
	else if (strcmp("OK", arg) != 0) {
static void socket_shutdown(struct imap_socket *sock)
	"NAMESPACE",

	return ctx;

			break;
			for (; *s != '"'; s++)
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
	if (imap->buf.sock.fd[0] != -1) {
}
	while (1) {
	strbuf_release(msg);
		die("EVP_EncodeBlock error");
	}
		goto out;

	STACK_OF(GENERAL_NAME) *subj_alt_names;

		bufl = nfsnprintf(buf, sizeof(buf), "%d %s\r\n", cmd->tag, cmd->cmd);
	/*
	while (isspace((unsigned char) **s))
	ctx->name = server->folder;
			if (!(*pcmdp = cmdp->next))
			if (socket_write(&imap->buf.sock, "\r\n", 2) != 2)
		}

__attribute__((format (printf, 1, 2)))

					goto bail;
 *  GNU General Public License for more details.
		strbuf_release(&auth);
 * true iff a message was successfully copied.
				       const char *fmt, va_list ap)

		if (s < 0) {


			imap_info("Connecting to [%s]:%s... ", addr, portstr);

	struct credential cred = CREDENTIAL_INIT;
		if(res != CURLE_OK) {

	fprintf(stderr, "\n");
	case RESP_BAD: return DRV_STORE_BAD;
				skip_list(&cmd); /* Personal mailboxes */
		if (!he) {
		use_curl = 0;
			}
	if (!git_config_get_value("imap.host", &val)) {

{

		bufl = nfsnprintf(buf, sizeof(buf), "%d %s{%d%s}\r\n",
	lf_to_crlf(msg);
		if (!split_msg(all_msgs, &msgbuf.buf, &ofs))
			break;

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
#endif
				if (cmdp->cb.cont(ctx, cmdp, cmd))
	struct strbuf msg = STRBUF_INIT;
	}
		if (b->buf[b->offset] == '\r') {
	int ssl_verify;
static void wrap_in_html(struct strbuf *msg)
	}
		if (srvc->auth_method) {
	response = cram(prompt, server.user, server.pass);

		arg = next_arg(&cmd);
	char *ret;
#else
	int ofs = 0;

	return ret;
				imap->in_progress_append = pcmdp;
		socket_perror("read", sock, n);
		else
	if (!server.port)
			arg = next_arg(&cmd);
		imap_info("Starting tunnel '%s'... ", srvc->tunnel);
					goto gottag;
	return *host && *pattern && !strcasecmp(host, pattern);

	/* open connection to IMAP server */
 * msg.  Update *ofs to the start of the following message.  Return
				resp = resp2;
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
			fprintf(stderr, "curl_easy_perform() failed: %s\n",

				fprintf(stderr, "IMAP error: unexpected command continuation request\n");
				fprintf(stderr, "Skipping account %s@%s, server forbids LOGIN\n",
}
			return RESP_BAD;
 */
	va_start(ap, fmt);

				continue;
				      (unsigned char *)response, resp_len);
		prev_len = msgbuf.buf.len;
enum CAPABILITY {
		}
			/* capabilities may have changed, so get the new capabilities */
		warning("SSL_set_tlsext_host_name(%s) failed.", server.host);
			p = strstr(p+7, "\nSubject: ");
	if (!imap->caps && imap_exec(ctx, NULL, "CAPABILITY") != RESP_OK)
	struct imap_store *ctx;
#define ENCODED_SIZE(n) (4 * DIV_ROUND_UP((n), 3))
		return NULL;

	struct imap *imap;
}
			       struct strbuf* all_msgs, int total)

	git_config_get_string("imap.authmethod", &server.auth_method);
	}

		va_start(va, msg);
	if (n <= 0) {
	char *cmd;
	if (!uri_encoded_folder)
		vprintf(msg, va);
	va_start(va, fmt);
static void skip_list(char **sp)


	char tmp[8192];
				b->offset += 2; /* next line */
		} else {
			}
}
		p++;
	free(response);
	if (found)
	for (;;) {
	if (!s || *s != '[')
 * git-imap-send - drops patches into an imap Drafts folder
	skip_imap_list_l(sp, 0);

	decoded_len = EVP_DecodeBlock((unsigned char *)challenge,
 * Copyright (C) 2002-2004 Oswald Buddenhagen <ossi@users.sf.net>
				if (cmdp->tag == tag)
	NULL,	/* pass */
	strbuf_attach(msg, new_msg, j, j + 1);
			/* quoted string */
				return RESP_BAD;
		fprintf(stderr, "IMAP error: no greeting response\n");
		for (i = 0; !found && i < num_subj_alt_names; i++) {
				b->buf[b->offset] = 0;  /* terminate the string */
/* simple line buffering */
				FREE_AND_NULL(cmdp->cb.data);
		if (ret < 0)
			}
		socket_perror("SSL_connect", sock, ret);
	} else if (!strcmp("CAPABILITY", arg)) {
{
				goto bail;


#define DRV_MSG_BAD     -1
		case SSL_ERROR_NONE:
	if (!(p = strchr(s, ']'))) {
	found = 0;
		p = strstr(p+5, "\nFrom ");
static int get_cmd_result(struct imap_store *ctx, struct imap_cmd *tcmd);
			} else if (!strcmp("OK", arg) || !strcmp("BAD", arg) ||
			else {

		unsigned percent = n * 100 / total;
		switch (sslerr) {
		ret = *s;
	ssize_t n;
			struct imap_cmd_cb cb;
			return RESP_BAD;
		n = SSL_read(sock->ssl, buf, len);
		warning("--no-curl not supported in this build");
	/* try the common name */
			return RESP_BAD;
	 */
		if (!(arg = next_arg(&s)) || !(imap->uidnext = atoi(arg))) {
#ifndef NO_OPENSSL

	if (!arg || *arg != '*' || (arg = next_arg(&rsp)) == NULL) {
				arg = "";
		vfprintf(stderr, msg, va);
	git_config_get_int("imap.port", &server.port);
		else
		server.port = server.use_ssl ? 993 : 143;
	return -1;
		for (; isspace((unsigned char)*p); p++);
static CURL *setup_curl(struct imap_server_conf *srvc, struct credential *cred)


	*sp = s;

		imap->buf.sock.fd[1] = tunnel.in;
				       struct imap_cmd_cb *cb,
static struct imap_store *imap_open_store(struct imap_server_conf *srvc, char *folder)
	char *arg, *rsp;

#endif
	struct imap_cmd *cmdp;
	int dlen;
	return RESP_OK;
{
				}
	cb.data = strbuf_detach(msg, NULL);
		if (!level)
	ctx->name = folder;
				b->offset -= start;
/*
static int skip_imap_list_l(char **sp, int level)
{
	int use_ssl;

				if (n)

			break;
			free(cb->data);
	if (n != len) {
	} else {
	close(sock->fd[0]);
}
	int bytes;

		pattern += 2;

	*s = b->buf + start;


	char hex[33];
			p = strstr(p+7, "\nDate: ");
	strbuf_addstr(&path, uri_encoded_folder);
	if (!SSL_set_rfd(sock->ssl, sock->fd[0])) {
 *                 derived from isync/mbsync - mailbox synchronizer
	 * enough upper bound for challenge (decoded result).
	}
	const char *val = NULL;
}
	strbuf_addch(&buf, '\n');
		hex[2 * i] = hexchar((hash[i] >> 4) & 0xf);
{
	return ret;
	return -1;
			if (CAP(NOLOGIN)) {
		va_start(va, msg);
		gottag:
	cmd->next = NULL;
		} else {
		server.host = "tunnel";
	while (imap->literal_pending)
static int read_message(FILE *f, struct strbuf *all_msgs)
				goto bail;

	const char *name; /* foreign! maybe preset? */
		close(sock->fd[0]);
static struct imap_server_conf server = {
	credential_clear(&cred);
		struct sockaddr_in addr;
	}
		if (strbuf_fread(all_msgs, CHUNKSIZE, f) <= 0)
			goto bail;
	case RESP_NO:
					fprintf(stderr, "IMAP error: AUTHENTICATE CRAM-MD5 failed\n");
__attribute__((format (printf, 3, 4)))

 *  You should have received a copy of the GNU General Public License


		if (starts_with(p, "From ")) {
#ifndef NO_OPENSSL
		if (!*s)
	if (srvc->user && srvc->pass)
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
}
	return ferror(f) ? -1 : 0;
	CURL *curl;
	else
	if (!srvc->pass)
	}
#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
				return resp;
			if (imap_exec(ctx, NULL, "LOGIN \"%s\" \"%s\"", srvc->user, srvc->pass) != RESP_OK) {
	if (ret != DRV_OK)
			imap->num_in_progress--;
	}
		break;
	ret = SSL_set_tlsext_host_name(sock->ssl, server.host);
	X509_NAME *subj;
#ifndef NO_OPENSSL
	if (!server.use_ssl)

		data = p;
				free(cmd);
		} else if (*arg == '+') {
		return -1;
			if (!tcmd)
	const SSL_METHOD *meth;
	if (all_msgs.len == 0) {
	if (len >= sizeof(tmp))
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,

	}

};

			return -1;
	OPT__VERBOSITY(&verbosity),
		return -1;


	int uid;
static int auth_cram_md5(struct imap_store *ctx, struct imap_cmd *cmd, const char *prompt)
	git_config_get_string("imap.folder", &server.folder);
	strbuf_addstr(&buf, pre_open);
{
	STARTTLS,
}
			if (cmdp->cb.cont || cmdp->cb.data)
__attribute__((format (printf, 1, 2)))
				skip_list(&cmd); /* Others' mailboxes */
	if (!srvc->user)

		ssl_socket_perror("SSL_set_wfd");
		while (**s && !isspace((unsigned char) **s))
	char *response;
static void imap_warn(const char *msg, ...)
		return;
			fprintf(stderr, "IMAP error: malformed APPENDUID status\n");
#endif
	SSL_CTX *ctx;
		ssl_socket_perror("SSL_new");

	return NULL;

				n = b->bytes - start;
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
		int num_subj_alt_names = sk_GENERAL_NAME_num(subj_alt_names);
static void git_imap_config(void)


		cmd->cb = *cb;
		return 1;
	if (use_tls_only)
	const char *prefix;
	}
 * hexchar() and cram() functions are based on the code from the isync
	OPT_END()
static struct imap_cmd *issue_imap_cmd(struct imap_store *ctx,
				      (unsigned char *)challenge_64, encoded_len);
		ret = *s;




				imap_warn("*** IMAP Warning *** Password is being "
					       srvc->ssl_verify))

	char buf[1024];
				}
				   * messages or mailboxes these days, so consider
	0,   	/* use_html */
	char *folder;
{
#include "run-command.h"
	}
		fprintf(stderr, "failed to open store\n");
	total = count_messages(&all_msgs);
{

	char *data;
	encoded_len = EVP_EncodeBlock((unsigned char *)response_64,

		if (!p)
	}
	if (!ctx) {
		return error("cannot get certificate subject");
		*s = NULL;
				found = 1;
	char *response, *response_64, *challenge;
			close(s);
{
				val += 2;
			if (starts_with(val, "//"))
	va_list ap;
				fprintf(stderr, "IMAP error: unable to parse untagged response\n");
	char *name;
#endif
#endif
	va_list ap;
	data = &all_msgs->buf[*ofs];
{
		if (!(host = strchr(host, '.')))

 out:
				skip_list(&cmd); /* Shared mailboxes */
				if (!*s)
						"but %s doesn't support it.\n", srvc->host);
		fflush(stdout);
					goto bail;
			if ((resp2 = parse_response_code(ctx, &cmdp->cb, cmd)) > resp)
	int (*cont)(struct imap_store *ctx, struct imap_cmd *cmd, const char *prompt);
	else
	unsigned char hash[16];
	}
{
			}
			if (n != cmd->cb.dlen ||
	OPT_BOOL(0, "curl", &use_curl, "use libcurl to communicate with the IMAP server"),
				  cmd->tag, cmd->cmd, cmd->cb.dlen,
		}
		n++;
	if (sock->ssl) {
{


		sk_GENERAL_NAME_pop_free(subj_alt_names, GENERAL_NAME_free);
	/* command queue */
	curl_easy_setopt(curl, CURLOPT_PORT, server.port);

	if (sock->ssl)
	case RESP_BAD:
	if (*ofs >= all_msgs->len)

		}
		die("curl_easy_init failed");

		if (gai) {
		server_fill_credential(srvc, &cred);
	struct imap_socket sock;
static int ssl_socket_connect(struct imap_socket *sock, int use_tls_only, int verify)
{
			return 1;
{
		ssl_socket_perror("SSLv23_method");


				parse_capability(imap, cmd);
struct imap_cmd;
 *
	"LITERAL+",
	}



	cmd->tag = ++imap->nexttag;
		       const char *fmt, ...)
	/* not reached */
	NULL,	/* host */
static int verify_hostname(X509 *cert, const char *hostname)
	char cname[1000];
				n = socket_write(&imap->buf.sock, cmdp->cb.data, cmdp->cb.dlen);
		}

	git_config_get_string("imap.tunnel", &server.tunnel);
	return 1;
	git_config_get_string("imap.user", &server.user);
			p = strstr(p+5, "\nFrom: ");
	if (sock->ssl)
	if (ret != strlen(response))
			printf("(%d in progress) ", imap->num_in_progress);
	for (i = j = 0, lastc = '\0'; i < msg->len; i++) {
				   * eliminating this case.
			*(*s)++ = 0;
	va_end(ap);
			wrap_in_html(&msg);
	char *new_msg;
		     cname, hostname);
		n = write_in_full(sock->fd[1], buf, len);
};

	} else if (cb && cb->ctx && !strcmp("APPENDUID", arg)) {
		}
		SSL_free(sock->ssl);
			wrap_in_html(&msgbuf.buf);
	ctx->imap = imap = xcalloc(1, sizeof(*imap));
	/* currently open mailbox */
static void imap_close_server(struct imap_store *ictx)
					resp = RESP_NO;
	return (char *)response_64;
	}
#else
static int buffer_gets(struct imap_buffer *b, char **s)
		credential_approve(&cred);
	va_list va;
{

}

				start = 0;

	uri_encoded_folder = curl_easy_escape(curl, server.folder, 0);
			if (skip_imap_list_l(&s, level + 1))
__attribute__((format (printf, 3, 4)))
	if (ret != 1)
	if (decoded_len < 0)
	if ((len = X509_NAME_get_text_by_NID(subj, NID_commonName, cname, sizeof(cname))) < 0)
	int ret;
	va_start(ap, fmt);
 */
			} else if ((arg1 = next_arg(&cmd))) {
{
	ret = imap_exec_m(ctx, &cb, "APPEND \"%s%s\" ", prefix, box);
	*msg = buf;
			break;
	}
		addr.sin_port = htons(srvc->port);
};
	/*
	body += 2;
		return 0;
			cmd->cb.data = NULL;
			tag = atoi(arg);
		n = xread(sock->fd[0], buf, len);
	} /* !preauth */
				s = -1;
				server.use_ssl = 1;
		return 0;
	return 0;
{
	struct imap_cmd *cmdp, **pcmdp;
		die("failed to encode server folder");

#endif
							arg, cmd ? cmd : "");
		n = SSL_write(sock->ssl, buf, len);
	if (use_curl)
 * leaving msg->data empty.
		curl_easy_setopt(curl, CURLOPT_LOGIN_OPTIONS, auth.buf);
				goto bail;
	if (blen <= 0 || (unsigned)(ret = vsnprintf(buf, blen, fmt, va)) >= (unsigned)blen)
	}
	const char *arg, *arg1;
		strbuf_addstr(&auth, server.auth_method);
	if (server.auth_method) {
	/* write it to the imap server */
static void server_fill_credential(struct imap_server_conf *srvc, struct credential *cred)
		usage_with_options(imap_send_usage, imap_send_options);
	}
		return NULL;
				fprintf(stderr, "IMAP command '%s' returned response (%s) - %s\n",
			j++; /* a CR will need to be added here */
	fprintf(stderr, "\n");
struct imap_store {
#ifndef NO_OPENSSL
	size_t len;
{
		goto bail;
	git_config_get_bool("imap.preformattedhtml", &server.use_html);


#endif
	char *auth_method;
}
		 */
		imap_info("Resolving %s... ", srvc->host);
	strbuf_addstr(&path, server.host);


	int ret;
		addr.sin_family = AF_INET;
#define USE_CURL_DEFAULT 1

	if (!preauth) {
	struct imap_cmd_cb cb;
		if (start_command(&tunnel))
		}
		imap->literal_pending = 1;
		return NULL;
			break;

		close(sock->fd[1]);
		return 1;
		    ssl_socket_connect(&imap->buf.sock, 0, srvc->ssl_verify)) {
				if (imap_exec(ctx, &cb, "AUTHENTICATE CRAM-MD5") != RESP_OK) {
		xsnprintf(portstr, sizeof(portstr), "%d", srvc->port);

			p += 10;
 * project (http://isync.sf.net/).
	void (*done)(struct imap_store *ctx, struct imap_cmd *cmd, int response);
	cred->password = xstrdup_or_null(srvc->pass);
				goto bail;

	 * returns 1 on success, 0 on failure after calling SSLerr().
	int n = 0;

		tunnel.in = -1;

		len -= p - data;
	return 0;
				imap->caps |= 1 << i;
{

		} else {
		/* RFC2060 says that these messages MUST be displayed
}
{
	unsigned caps, rcaps; /* CAPABILITY results */
	imap->in_progress_append = &cmd->next;
	size_t i, j;
		va_end(va);
 * Store msg to IMAP.  Also detach and free the data from msg->data,
}
			fprintf(stderr, "%s: unexpected EOF\n", func);
			}
		warning("No LOGIN_OPTIONS support in this cURL version");

	}
	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK)
static void lf_to_crlf(struct strbuf *msg)

		fprintf(stderr, "no imap store specified\n");
		int sslerr = SSL_get_error(sock->ssl, ret);
	"LOGINDISABLED",
		n++;
	free(ctx);
				return DRV_OK;
		imap_info("Connecting to %s:%hu... ", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	struct credential cred = CREDENTIAL_INIT;
#define USE_CURL_DEFAULT 0
	ctx = SSL_CTX_new(meth);
			perror("connect");
			fprintf(stderr, "IMAP error: empty response\n");
				perror("connect");
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, server.ssl_verify);
	if ((subj_alt_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL))) {
				    struct strbuf* all_msgs, int total)
				if (n != (int)cmdp->cb.dlen)
};
			fprintf(stderr, "IMAP error: malformed NEXTUID status\n");
			goto bail;
	 * otherwise identical to the first pass.
			s++;
		memset(&cmd->cb, 0, sizeof(cmd->cb));
	LITERALPLUS,
static char *next_arg(char **s)
	char *arg, *p;
		socket_shutdown(&imap->buf.sock);
	char *user;
				   *

	if (0 < verbosity || getenv("GIT_CURL_VERBOSE"))
	} while (!feof(f));


	static char *content_type = "Content-Type: text/html;\n";
			n = socket_read(&b->sock, b->buf + b->bytes,
		/* make sure the hostname matches that of the certificate */
	if (encoded_len < 0)
	curl_easy_setopt(curl, CURLOPT_READDATA, &msgbuf);
	if (!server.folder) {
		argv_array_push(&tunnel.args, srvc->tunnel);
	if (cred.username)
static int socket_read(struct imap_socket *sock, char *buf, int len)

	arg = next_arg(&s);
			break;
#undef DRV_OK
	char *p, *data;

					 sizeof(b->buf) - b->bytes);
	return 0;
 *

	if (read_message(stdin, &all_msgs)) {
struct imap_server_conf {
	int uidnext; /* from SELECT responses */
		sock->fd[0] = sock->fd[1] = -1;
	}
	*strp = xmemdupz(tmp, len);
	*imap->in_progress_append = cmd;
	}
		return append_msgs_to_imap(&server, &all_msgs, total);
			imap_info("Created missing mailbox\n");

	}
{
	AUTH_CRAM_MD5

	curl_easy_setopt(curl, CURLOPT_READFUNCTION, fread_buffer);

			printf(">>> %s", buf);
 * Copyright (C) 2004 Theodore Y. Ts'o <tytso@mit.edu>
		free(cmd);
	arg = next_arg(&rsp);
struct imap_cmd_cb {
{
	int offset;
		imap->buf.sock.fd[0] = s;
	}
		}
		if (!starts_with(cmd->cmd, "LOGIN"))
	int n;
	curl_easy_setopt(curl, CURLOPT_USERNAME, server.user);
	len = vsnprintf(tmp, sizeof(tmp), fmt, ap);
			if (subj_alt_name->type == GEN_DNS &&
		memset(&addr, 0, sizeof(addr));
	int nexttag, num_in_progress, literal_pending;
				close(s);
		strbuf_addstr(&auth, "AUTH=");

		fprintf(stderr, "%4u%% (%d/%d) done\r", percent, n, total);

	}

{
static int imap_exec_m(struct imap_store *ctx, struct imap_cmd_cb *cb,
			if (!strcmp("OK", arg))
		if (imap->num_in_progress)
	if (ret <= 0) {
	if (!cmd->cb.data)
	static char *pre_close = "</pre>\n";
};
	} else
	return cmd;
	char buf[1024];
}
		}

				return RESP_BAD;

	}
			}
			break;


	const char *prefix, *box;
	for (;;) {
	/* try the DNS subjectAltNames */
	else
	va_end(ap);
			    host_matches(hostname, (const char *)(subj_alt_name->d.ia5->data)))
	if (!use_curl) {
		j++;
	if (!server.host) {
		if (msg->buf[i] == '\n' && lastc != '\r')
	int total;
	prefix = !strcmp(box, "INBOX") ? "" : ctx->prefix;
	"AUTH=CRAM-MD5",

	char *host;
	struct imap *imap = ictx->imap;
	if (buffer_gets(&imap->buf, &rsp)) {
	imap->caps = imap->rcaps;
	}
			return RESP_BAD;

		get_cmd_result(ctx, NULL);
	int n;
			if (cmdp->cb.data) {
static void imap_info(const char *msg, ...)

			}
#endif
			return 0;

				   * NEEDSWORK: Previously this case handled '<num> EXISTS'
				/* shift down used bytes */
	struct imap *imap = ctx->imap;

#include "parse-options.h"
	struct imap_cmd *cmdp;
			s++;
		srvc->user = xstrdup(cred->username);
 */
		fprintf(stderr, "IMAP error: empty response code\n");
			imap->literal_pending = 1;
	if (p)
	if (!SSL_set_wfd(sock->ssl, sock->fd[1])) {
		*ofs += p - data;
		if (server->use_html)
	return DRV_OK;
static void socket_perror(const char *func, struct imap_socket *sock, int ret)
	fprintf(stderr, "%s: %s\n", func, ERR_error_string(ERR_get_error(), NULL));
			getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
	case RESP_NO: return DRV_MSG_BAD;
static int curl_append_msgs_to_imap(struct imap_server_conf *server,
	struct imap *imap = ctx->imap;
static void parse_capability(struct imap *imap, char *cmd)
			n = socket_write(&imap->buf.sock, cmd->cb.data, cmd->cb.dlen);

	SSL *ssl;
	} else if (!strcmp("UIDNEXT", arg)) {
	strbuf_addstr_xml_quoted(&buf, body);
		die("curl_global_init failed");
	NULL,	/* folder */

	 */
	credential_clear(&cred);
		return -1;
			/* sublist */
			s++;
	/* First pass: tally, in j, the size of the new_msg string: */
		return 1;
	while (1) {
			}
				goto bail;
		if (!**s)
		hex[2 * i + 1] = hexchar(hash[i] & 0xf);
		}
		struct strbuf auth = STRBUF_INIT;
					  "sent in the clear\n");
	 */
}
				imap->literal_pending = 0;
			/* atom */
				imap->literal_pending = 0;
				   ai->ai_protocol);
				return 0;
		imap_info("ok\n");
static int nfsnprintf(char *buf, int blen, const char *fmt, ...)

__attribute__((format (printf, 3, 4)))
			   it enforces a round-trip. */
		*s = strchr(*s, '"');
};
		socket_perror("write", sock, n);
	}
 */
		lastc = msg->buf[i];
}
		struct child_process tunnel = CHILD_PROCESS_INIT;
		return 1;

}
{
	struct buffer msgbuf = { STRBUF_INIT, 0 };
	git_config_get_string("imap.pass", &server.pass);
	fprintf(stderr, "sending %d message%s\n", total, (total != 1) ? "s" : "");
			if (b->buf[b->offset + 1] == '\n') {
			goto bail;
			git_die_config("imap.host", "Missing value for 'imap.host'");
		res = curl_easy_perform(curl);
{
		if (**s)
		/* make sure we have enough data to read the \r\n sequence */
				if (!CAP(AUTH_CRAM_MD5)) {
	if (argc)
		strbuf_addch(&path, '/');
	if (len < 5 || !starts_with(data, "From "))
	return error("certificate owner '%s' does not match hostname '%s'",
		imap_info("Resolving %s... ", srvc->host);
#define RESP_NO    1

/*
				val += 5;
#endif
	if (!sock->ssl) {
			s++;
		return RESP_BAD;
		if (!val) {
		ssl_socket_perror("SSL_set_rfd");
	}
		host++;
	struct imap *imap = ctx->imap;
			if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
	/*
	int len;
			s = -1;
		die("HMAC error");

			} else if (!strcmp("CAPABILITY", arg)) {
}
		free(cmd->cmd);
			if (!p) break;

					curl_easy_strerror(res));
	NULL,	/* auth_method */
				resp = DRV_OK;
		if (!arg) {
}

		he = gethostbyname(srvc->host);
