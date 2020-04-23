	 */
	 * so technically a blank credential means "erase everything".
}
			found_credential = 1;

			other_cb(&line);
	struct string_list_item *fn;
	 */
	 * to empty input. So explicitly disallow it, and require that the
	};
			die_errno("unable to open %s", fn);
		if (!access(fn->string, F_OK)) {
		return;
				    struct strbuf *extra)

	 * we have no primary key. And without a username and password,
		remove_credential(&fns, &c);
		strbuf_addstr_urlencode(&buf, c->path,
	 * Without either a host or pathname (depending on the scheme),
	/*
	return found_credential;

	 * But it is too easy to accidentally send this, since it is equivalent
	struct credential entry = CREDENTIAL_INIT;
static void print_line(struct strbuf *buf)
			return;

		die_errno("unable to write credential store");
	credential_clear(&entry);
	write_or_die(get_lock_file_fd(&credential_lock), buf->buf, buf->len);
		store_credential(&fns, &c);

	while (strbuf_getline_lf(&line, fh) != EOF) {
	strbuf_addstr_urlencode(&buf, c->password, is_rfc3986_unreserved);
#include "credential.h"
#include "cache.h"
{

static void store_credential_file(const char *fn, struct credential *c)
	struct credential c = CREDENTIAL_INIT;
}
	strbuf_addch(&buf, ':');
	struct option options[] = {
		if (file)

}
	 * pattern have some actual content to match.
	struct string_list_item *fn;
			return; /* Found credential */
				  void (*match_cb)(struct credential *),
			string_list_append_nodup(&fns, file);
	strbuf_addstr_urlencode(&buf, c->username, is_rfc3986_unreserved);
	struct strbuf buf = STRBUF_INIT;
static void rewrite_credential_file(const char *fn, struct credential *c,
	if (fns->nr)

		if ((file = expand_user_path("~/.git-credentials", 0)))
	argc = parse_options(argc, (const char **)argv, NULL, options, usage, 0);

		}
	op = argv[0];
	char *file = NULL;
		OPT_END()
static void store_credential(const struct string_list *fns, struct credential *c)
			}
		if (!access(fn->string, F_OK))
	 */
			if (match_cb) {

	if (!c->protocol && !c->host && !c->path && !c->username)
	 * against. The input we get is a restrictive pattern,
	else if (!strcmp(op, "erase"))
static struct lock_file credential_lock;

	const char *op;
	const char * const usage[] = {
	}
		print_line(extra);
	};
			   "fetch and store credentials in <path>"),
	 * Write credential to the filename specified by fns->items[0], thus
		"git credential-store [<options>] <action>",

		    credential_match(c, &entry)) {
	/*
		credential_from_url(&entry, line.buf);
	printf("password=%s\n", c->password);
	if (c->host)
	int found_credential = 0;
	else if (!strcmp(op, "store"))
	if (c->path) {
	string_list_clear(&fns, 0);
	fclose(fh);
	} else {
	 * creating it
	 * we are not actually storing a credential.

	parse_credential_file(fn, c, NULL, print_line);

static void lookup_credential(const struct string_list *fns, struct credential *c)

	if (credential_read(&c, stdin) < 0)
	struct string_list fns = STRING_LIST_INIT_DUP;
{
		strbuf_addstr_urlencode(&buf, c->host, is_rfc3986_unreserved);
}
	}
	struct string_list_item *fn;
		die("unable to read credential");
{
	if (extra)
{

		else if (other_cb)
		die_errno("unable to get credential storage lock");
}
		NULL
	printf("username=%s\n", c->username);
				  void (*other_cb)(struct strbuf *))
{
}
	strbuf_release(&line);
	for_each_string_list_item(fn, fns)
	if (file) {
#include "parse-options.h"
	 * Sanity check that we actually have something to match
{
		OPT_STRING(0, "file", &file, "path",
	return 0;
		}
		usage_with_options(usage, options);
	 * In particular, we can't make a URL without a protocol field.
{

	}
	umask(077);
		return found_credential;
			string_list_append_nodup(&fns, file);
	 * Sanity check that what we are storing is actually sensible.
	if (argc != 1)
static void print_entry(struct credential *c)
		file = xdg_config_home("credentials");
#include "string-list.h"
		lookup_credential(&fns, &c);
	else
		die("unable to set up default path; use --file");
	}
				match_cb(&entry);
int cmd_main(int argc, const char **argv)
	fh = fopen(fn, "r");

	/*
}
		; /* Ignore unknown operation. */
		string_list_append(&fns, file);

				break;

}
	if (!c->protocol || !(c->host || c->path) || !c->username || !c->password)
	if (commit_lock_file(&credential_lock) < 0)
	for_each_string_list_item(fn, fns)
#include "lockfile.h"
	strbuf_addf(&buf, "%s://", c->protocol);
	struct strbuf line = STRBUF_INIT;
	if (!strcmp(op, "get"))

		if (parse_credential_file(fn->string, c, print_entry, NULL))
	strbuf_addch(buf, '\n');
{
		strbuf_addch(&buf, '/');
		if (entry.username && entry.password &&

	strbuf_addch(&buf, '@');

	FILE *fh;
{
	for_each_string_list_item(fn, fns)
	if (hold_lock_file_for_update(&credential_lock, fn, 0) < 0)
	if (!fns.nr)
	strbuf_release(&buf);

	if (!fh) {
			store_credential_file(fn->string, c);
	rewrite_credential_file(fn, c, &buf);
		if (errno != ENOENT && errno != EACCES)
static int parse_credential_file(const char *fn,
static void remove_credential(const struct string_list *fns, struct credential *c)
		store_credential_file(fns->items[0].string, c);
				  struct credential *c,

		return;
					is_rfc3986_reserved_or_unreserved);
			rewrite_credential_file(fn->string, c, NULL);
}
