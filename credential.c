		if (!strcmp(key, "username")) {
#include "config.h"
	c->configured = 1;


	credential_apply_config(c);
void credential_write(const struct credential *c, FILE *fp)
{
	}
			    c->helpers.items[i].string);

		strbuf_addstr(out, c->host);
		credential_do(c, c->helpers.items[i].string, "get");

			free(c->username);
	strbuf_release(&prompt);
		c->username = credential_ask_one("Username", c,
		if (r < 0) {
		return;
	if (want_output) {
#undef CHECK
	free(c->password);
}

	/* Trim leading and trailing slashes from path */
	if (!strchr(value, '\n'))
			       const char *name, const char *value)
	if (!c->use_http_path && proto_is_http(c->protocol)) {
	config.section = "credential";
		*value++ = '\0';
			die("credential helper '%s' told us to quit",

}
	for (i = 0; i < c->helpers.nr; i++)
	if (c->path)


	helper.use_shell = 1;
	}
		c->password = url_decode_mem(colon + 1, at - (colon + 1));
}
	else if (!strcmp(key, "usehttppath"))
			c->username_from_proto = 1;
int credential_from_url_gently(struct credential *c, const char *url,

		strbuf_addstr(out, c->host);
			c->username = xstrdup(value);


{
#include "run-command.h"
static int credential_do(struct credential *c, const char *helper,
		strbuf_addf(&cmd, "git credential-%s", helper);
	credential_format(c, &url);

}
	strbuf_release(&cmd);
	 * A query or fragment marker before the slash ends the host portion.
	}
			c->password = xstrdup(value);
}
static void credential_format(struct credential *c, struct strbuf *out)
		} else if (!strcmp(key, "url")) {
}
	struct urlmatch_config config = { STRING_LIST_INIT_DUP };
			free(c->username);
}


	if (c->approved)

void credential_init(struct credential *c)
	colon = strchr(cp, ':');
	}
		if (!c->username_from_proto) {
	if (desc.len)
		} else if (!strcmp(key, "password")) {
	strbuf_addf(out, "%s://", c->protocol);

	return CHECK(protocol) &&
		host = at + 1;
static int run_credential_helper(struct credential *c,
	FREE_AND_NULL(c->password);
static void credential_write_item(FILE *fp, const char *key, const char *value,
		return;

	return 0;

{
						 PROMPT_ASKPASS|PROMPT_ECHO);
	struct strbuf prompt = STRBUF_INIT;
			string_list_clear(&c->helpers, 0);
		credential_do(c, c->helpers.items[i].string, "erase");
		slash++;
	int i;
	credential_clear(c);
	credential_write_item(fp, "password", c->password, 0);

{
	memset(c, 0, sizeof(*c));
	if (!skip_prefix(var, "credential.", &key))
{
	 *   (1) proto://<host>/...
void credential_clear(struct credential *c)
	slash = cp + strcspn(cp, "/?#");

{
		host = at + 1;
		 */
	credential_write(c, fp);
	credential_apply_config(c);
static int check_url_component(const char *url, int quiet,
	c->approved = 0;
	return xstrdup(r);

		fclose(fp);
static int proto_is_http(const char *s)
			return -1;
	       CHECK(host) &&
}
	FREE_AND_NULL(c->username);
			free(c->path);
			c->path = xstrdup(value);
		return;
			free(c->host);
			 const char *operation)
	       CHECK(path) &&
		strbuf_addf(&prompt, "%s: ", what);
void credential_from_url(struct credential *c, const char *url)

	c->approved = 1;
	return 0;

	} else if (!strcmp(key, "username")) {
}
		      const struct urlmatch_item *b)
}
		strbuf_add_percentencode(out, c->path);

		return -1;


int credential_read(struct credential *c, FILE *fp)
	int r;
}

	if (!c->protocol)
	if (!c->username || !c->password)
	if (!c->protocol)
void credential_reject(struct credential *c)
	c->host = url_decode_mem(host, slash - host);
		strbuf_addf(out, "%s@", c->username);
int credential_match(const struct credential *want,
						 PROMPT_ASKPASS);
{
	struct child_process helper = CHILD_PROCESS_INIT;
	git_config(urlmatch_config_entry, &config);
			name, url);
	struct strbuf desc = STRBUF_INIT;
	if (!c->password)
{
	for (i = 0; i < c->helpers.nr; i++)
}

	if (check_url_component(url, quiet, "username", c->username) < 0 ||
		 * this future-proofs us when later versions of git do
		return config_error_nonbool(var);
	free(c->protocol);
	r = git_prompt(prompt.buf, flags);
	return !strcmp(s, "https") || !strcmp(s, "http");
			c->username = xstrdup(value);
		return -1;
			credential_from_url(c, value);
				 const char *cmd,
		return 0;
			free(c->password);
	return r;
	    check_url_component(url, quiet, "path", c->path) < 0)

	if (!value)
	config.cb = c;
	if (c->path) {
#include "prompt.h"

			warning("invalid credential line: %s", key);
	config.collect_fn = credential_config_callback;
	if (!s)
	credential_write_item(fp, "protocol", c->protocol, 1);
		/* Case (1) */
}
	if (c->username && c->password)

		FREE_AND_NULL(c->path);
static void credential_describe(struct credential *c, struct strbuf *out);
	}
#include "sigchain.h"
#include "urlmatch.h"

			free(c->protocol);
		/*


	strbuf_release(&line);


	/*

	struct credential *c = data;
		helper.no_stdout = 1;
#include "string-list.h"

	const char *argv[] = { NULL, NULL };
{

	fclose(fp);
{

		BUG("credential value for %s is missing", key);

	if (helper[0] == '!')
	strbuf_release(&url);
		return -1;
		while (p > c->path && *p == '/')
		if (!quiet)


	sigchain_pop(SIGPIPE);

	free(normalized_url);
		} else if (!strcmp(key, "protocol")) {

		c->username = url_decode_mem(cp, at - cp);
}
	int i;
	else if (is_absolute_path(helper))
	struct strbuf url = STRBUF_INIT;
}
	fp = xfdopen(helper.in, "w");
	c->helpers.strdup_strings = 1;
		return;
	       CHECK(username);
		}
	int i;
	free(c->host);
	if (!value && required)
	if (!c->protocol)
	if (!value)
	if (!at || slash <= at) {
		strbuf_addch(out, '@');

		if (c->username && c->password)
}
	const char *key;

	normalized_url = url_normalize(url.buf, &config.url);
		} else if (!strcmp(key, "path")) {
			return;
	credential_write_item(fp, "path", c->path, 0);
	if (start_command(&helper) < 0)
	struct strbuf cmd = STRBUF_INIT;
	r = run_credential_helper(c, cmd.buf, !strcmp(operation, "get"));
	if (c->configured)
		die(_("refusing to work with credential missing host field"));
	if (!c->username && !c->password)
	 * "trim leading slashes" part won't skip over this part of the path,
		die("credential value for %s contains newline", key);
		if (c->username && *c->username)
	if (c->username && *c->username) {
{
	struct strbuf line = STRBUF_INIT;
			c->quit = !!git_config_bool("quit", value);
	}
			return -1;
	if (strchr(value, '\n'))

#define CHECK(x) (!want->x || (have->x && !strcmp(want->x, have->x)))
{
{
static char *credential_ask_one(const char *what, struct credential *c,
	credential_write_item(fp, "host", c->host, 1);
	}
		}
		return;

		helper.out = -1;
		char *p;
	char *r;
	argv[0] = cmd;
	config.key = NULL;
	fprintf(fp, "%s=%s\n", key, value);
	const char *at, *colon, *cp, *slash, *host, *proto_end;

	if (c->host)
	return -1;
	else
		} else if (!strcmp(key, "quit")) {

	if (!c->host)
	free(c->username);
	    check_url_component(url, quiet, "protocol", c->protocol) < 0 ||
{
			c->host = xstrdup(value);
		strbuf_addstr(&cmd, helper);

		c->password = credential_ask_one("Password", c,
	else
		c->path = url_decode(slash);
	    check_url_component(url, quiet, "password", c->password) < 0 ||
		return 0;
				 int want_output)
		strbuf_addstr(&cmd, helper + 1);
		strbuf_addch(out, '/');
	free(c->path);
		strbuf_add_percentencode(out, c->username);
		fp = xfdopen(helper.out, "r");
		if (c->quit)
			*p-- = '\0';

	if (c->host)
void credential_approve(struct credential *c)
			string_list_append(&c->helpers, value);
		else
		} else if (!strcmp(key, "host")) {
#include "credential.h"
	if (!proto_end || proto_end == url) {
				      void *data)
	if (credential_from_url_gently(c, url, 0) < 0)
		host = cp;
	/*
	} else {
	string_list_clear(&c->helpers, 0);

		c->use_http_path = git_config_bool(var, value);

		     const struct credential *have)
	strbuf_addf(&cmd, " %s", operation);
		return 0;
}
static int select_all(const struct urlmatch_item *a,
	 */
		if (c->username && *c->username)
		c->username = url_decode_mem(cp, colon - cp);
		strbuf_addf(&prompt, "%s for '%s': ", what, desc.buf);
			break;

		char *value = strchr(key, '=');
	if (!strcmp(key, "helper")) {
		return;
				int flags)
		return;
	}
		die(_("credential url cannot be parsed: %s"), url);
	while (*slash == '/')
	config.cascade_fn = NULL;
static int credential_config_callback(const char *var, const char *value,
	credential_init(c);

		 * learn new lines, and the helpers are updated to match.
	if (!quiet)
	credential_apply_config(c);
	else if (!colon || at <= colon) {
	proto_end = strstr(url, "://");

	credential_write_item(fp, "username", c->username, 0);
	}
		if (*value)
		strbuf_addf(out, "/%s", c->path);
	    check_url_component(url, quiet, "host", c->host) < 0 ||

	 */
	char *normalized_url;
	FILE *fp;
}
	for (i = 0; i < c->helpers.nr; i++) {
static void credential_apply_config(struct credential *c)
			c->username_from_proto = 1;
	}
	else
	credential_getpass(c);
				  int required)
		/* Case (3) */
		int r;
	credential_describe(c, &desc);
	 * Match one of:
		warning(_("url contains a newline in its %s component: %s"),

static void credential_format(struct credential *c, struct strbuf *out);

	while (strbuf_getline_lf(&line, fp) != EOF) {
	strbuf_addf(out, "%s://", c->protocol);
{
	if (!value)

#include "url.h"
	}
{
	sigchain_push(SIGPIPE, SIG_IGN);
	return 0;
		credential_do(c, c->helpers.items[i].string, "store");
static void credential_describe(struct credential *c, struct strbuf *out)
{
{
	 * but that's what we'd want.
	if (want_output)
	if (c->username && *c->username)
	if (finish_command(&helper))

	c->protocol = xmemdupz(url, proto_end - url);
		if (!line.len)
			strbuf_release(&line);
		}
		}
static void credential_getpass(struct credential *c)

		char *key = line.buf;
	if (*slash) {
		die("unable to get password from user");
}
	 *   (2) proto://<user>@<host>/...

		r = credential_read(c, fp);
		return 0;
		return -1;
			c->username_from_proto = 1;
			c->protocol = xstrdup(value);
		p = c->path + strlen(c->path) - 1;

		if (!value) {
			finish_command(&helper);
}
{
	helper.in = -1;
			warning(_("url has no scheme: %s"), url);
	at = strchr(cp, '@');
	 * We'll just continue to call this "slash" for simplicity. Notably our
{
{
void credential_fill(struct credential *c)
	helper.argv = argv;
	cp = proto_end + 3;

			       int quiet)
}
	strbuf_release(&desc);
	return 0;

}
		 * Ignore other lines; we don't know what they mean, but

	if (!c->username)
		/* Case (2) */
	return 0;
		die(_("refusing to work with credential missing protocol field"));
	config.select_fn = select_all;
{
	 *   (3) proto://<user>:<pass>@<host>/...
#include "cache.h"
