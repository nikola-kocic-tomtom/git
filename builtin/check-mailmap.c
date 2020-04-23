		check_mailmap(&mailmap, argv[i]);

static const struct option check_mailmap_options[] = {
	int i;
static void check_mailmap(struct string_list *mailmap, const char *contact)
	read_mailmap(&mailmap, NULL);

	for (i = 0; i < argc; ++i)
	printf("<%.*s>\n", (int)maillen, mail);

		strbuf_release(&buf);
			     check_mailmap_usage, 0);
	size_t namelen, maillen;
#include "string-list.h"
	if (argc == 0 && !use_stdin)
}
			maybe_flush_or_die(stdout, "stdout");
static const char * const check_mailmap_usage[] = {
	OPT_BOOL(0, "stdin", &use_stdin, N_("also read contacts from stdin")),

#include "builtin.h"

static int use_stdin;
		}
	OPT_END()
	if (use_stdin) {

		die(_("unable to parse contact: %s"), contact);
		printf("%.*s ", (int)namelen, name);
	}

		die(_("no contacts specified"));
	map_user(mailmap, &mail, &maillen, &name, &namelen);
	if (namelen)
};
	name = ident.name_begin;
N_("git check-mailmap [<options>] <contact>..."),
#include "parse-options.h"
	mail = ident.mail_begin;



#include "config.h"
	maybe_flush_or_die(stdout, "stdout");
	struct ident_split ident;
	git_config(git_default_config, NULL);
}
	struct string_list mailmap = STRING_LIST_INIT_NODUP;
{
	if (split_ident_line(&ident, contact, strlen(contact)))
NULL
	argc = parse_options(argc, argv, prefix, check_mailmap_options,

		while (strbuf_getline_lf(&buf, stdin) != EOF) {
	maillen = ident.mail_end - ident.mail_begin;
			check_mailmap(&mailmap, buf.buf);
		struct strbuf buf = STRBUF_INIT;

	namelen = ident.name_end - ident.name_begin;
int cmd_check_mailmap(int argc, const char **argv, const char *prefix)
	clear_mailmap(&mailmap);
{
#include "mailmap.h"
};

	const char *name, *mail;
	return 0;
