		parse_revision_opt(&rev, &ctx, options, shortlog_usage);
	if (log->wrap < 0 || log->in1 < 0 || log->in2 < 0)
	git_config(git_default_config, NULL);
					strbuf_reset(&sb);

	size_t namelen, maillen;

					int taillen = strlen(p) - dot3len;
	log->in2 = parse_uint(&arg, '\0', DEFAULT_INDENT2);

	}
		while (strbuf_getline_lf(&oneline, stdin) != EOF &&
static const char wrap_arg_usage[] = "-w[<width>[,<indent1>[,<indent2>]]]";
		if (log->user_format)
			 N_("Show the email address of each author")),
#include "mailmap.h"
static char const * const shortlog_usage[] = {
	return 0;
	ctx.fmt = CMIT_FMT_USERFORMAT;
	struct strbuf oneline = STRBUF_INIT;
			free(onelines);
				else
			exit(129);

 *   - if --summary is in use, we don't need that list; we only need to know
			if (eob && (!eol || eob < eol))
static void add_wrapped_shortlog_msg(struct strbuf *sb, const char *s,
			exit(0);
{
	const struct string_list *l1 = i1->util, *l2 = i2->util;
	struct pretty_print_context ctx = {0};
		return -1;
	else
}
			format_commit_message(commit, "%s", &oneline, &ctx);
	/* assume HEAD if from a tty */
	log.file = rev.diffopt.file;
static int parse_uint(char const **arg, int comma, int defval)
	struct strbuf author = STRBUF_INIT;
	log->in2 = DEFAULT_INDENT2;
static int compare_by_list(const void *a1, const void *a2)
	if (setup_revisions(argc, argv, &rev, NULL) != 1) {
		eol = strchr(oneline, '\n');
		}
	else
				}
};
	}
	char *endp;
		/* Skip any leading whitespace, including any blank lines. */
	strbuf_add(out, namebuf, namelen);
	item = string_list_insert(&log->list, author);
		error(_("unrecognized argument: %s"), argv[1]);
	struct shortlog log = { STRING_LIST_INIT_NODUP };
		item->util = (void *)(UTIL_TO_INT(item) + 1);
		fclose(log.file);
			if (dot3len > 5) {

#include "commit.h"
	log->wrap = parse_uint(&arg, ',', DEFAULT_WRAPLEN);


#include "string-list.h"
	if (log->summary)
	};
	const struct string_list_item *i1 = a1, *i2 = a2;
	NULL

			fprintf(log->file, "%6d\t%s\n",
		OPT_BOOL('c', "committer", &log.committer,
		OPT_END(),
#include "cache.h"
			 N_("Group by committer rather than author")),
	}
static void insert_one_record(struct shortlog *log,
			      const char *author,
				(int)UTIL_TO_INT(item), item->string);
		return -1;
{

		log->in1 = DEFAULT_INDENT1;
			       struct strbuf *out, const char *in)
			fprintf(stderr, _("(reading log message from standard input)\n"));
	if (*endp && *endp != comma)
	}
			string_list_clear(onelines, 0);

		OPT_BOOL('n', "numbered", &log.sort_by_number,
	else {


	if (!arg) {
{
		}
	N_("git log --pretty=short | git shortlog [<options>]"),
	N_("git shortlog [<options>] [<revision-range>] [[--] <path>...]"),
			; /* discard blanks */
}


	log->wrap_lines = !unset;
	struct parse_opt_ctx_t ctx;
#define UTIL_TO_INT(x) ((intptr_t)(x)->util)
	if (ul > INT_MAX)
		buffer = strbuf_detach(&subject, NULL);
		OPT_BOOL('e', "email", &log.email,
	if (nongit && argc > 1) {
	const char **match;
{
		char *buffer, *p;
			item->util = xcalloc(1, sizeof(struct string_list));

		get_from_rev(&rev, &log);
	}

#include "builtin.h"
		if (!skip_prefix(author.buf, match[0], &v) &&



	int ret;
				     const struct shortlog *log)
#define DEFAULT_INDENT1 6
		       !oneline.len)
{
	struct ident_split ident;
				item->string, onelines->nr);
	argc = parse_options_end(&ctx);
	struct strbuf mapped_author = STRBUF_INIT;
		case PARSE_OPT_ERROR:

		if (isatty(0))
	fmt = log->committer ?

}
	const char *mailbuf, *namebuf;
		{ OPTION_CALLBACK, 'w', NULL, &log, N_("<w>[,<i1>[,<i2>]]"),

	const struct option options[] = {

#include "diff.h"
	if (!nongit && !rev.pending.nr && isatty(0))
static int parse_stdin_author(struct shortlog *log,

{
	while (strbuf_getline_lf(&author, stdin) != EOF) {
		insert_one_record(log, mapped_author.buf, oneline.buf);

			putc('\n', log->file);
	if (log->email)
	else if (l1->nr == l2->nr)
	ctx.abbrev = log->abbrev;
				oneline = eob + 1;
	strbuf_release(&oneline);
{

{
{


parse_done:
	ret = *arg == endp ? defval : (int)ul;
	ctx.print_email_subject = 1;
			&parse_wrap_args },
 *
	ctx.date_mode.type = DATE_NORMAL;
void shortlog_output(struct shortlog *log)

	if (log->wrap &&


		(log->email ? "%aN <%aE>" : "%aN");
	namebuf = ident.name_begin;
 *     its size. So we abuse the pointer slot to store our integer counter.

	strbuf_release(&author);
	log->in1 = DEFAULT_INDENT1;
	return 0;
#include "shortlog.h"
	read_mailmap(&log->mailmap, &log->common_repo_prefix);
		const struct string_list_item *item = &log->list.items[i];
	if (rev.pending.nr == 0) {
	static const char *committer_match[2] = { "Commit: ", "committer " };
		if (item->util == NULL)
	log->in1 = parse_uint(&arg, ',', DEFAULT_INDENT1);
		switch (parse_options_step(&ctx, options, shortlog_usage)) {
 */
		return 1;
		case PARSE_OPT_DONE:

static void get_from_rev(struct rev_info *rev, struct shortlog *log)
#define DEFAULT_WRAPLEN 76
 *
		return -1;
		       oneline.len)
			    PARSE_OPT_KEEP_DASHDASH | PARSE_OPT_KEEP_ARGV0);
		string_list_append(item->util, buffer);
	int i, j;
	static const char *author_match[2] = { "Author: ", "author " };

}

	const char *fmt;

	struct rev_info rev;
		shortlog_add_commit(log, commit);
	struct strbuf oneline = STRBUF_INIT;
		return error(wrap_arg_usage);
	return 0;
	const struct string_list_item *i1 = a1, *i2 = a2;
				while ((p = strstr(buffer, dot3)) != NULL) {
	    ((log->in1 && log->wrap <= log->in1) ||

		format_subject(&subject, oneline, " ");
	mailbuf = ident.mail_begin;
			}
		log->in2 = DEFAULT_INDENT2;
			eol = oneline + strlen(oneline);
	if (l1->nr < l2->nr)
		struct strbuf subject = STRBUF_INIT;

	struct shortlog *log = opt->value;
 *     oneline subjects assigned to this author
					memcpy(p, "/.../", 5);
}
		while (strbuf_getline_lf(&oneline, stdin) != EOF &&
			 N_("sort output according to the number of commits per author")),
	shortlog_init(&log);
}
	return ret;
		usage_with_options(shortlog_usage, options);
	struct strbuf author = STRBUF_INIT;
	if (log->sort_by_number)
	struct commit *commit;
			continue;
		}

	for (i = 0; i < log->list.nr; i++) {
}
					fprintf(log->file, "      %s\n", msg);
		while (*oneline && isspace(*oneline))
			continue;
		if (starts_with(oneline, "[PATCH")) {
			goto parse_done;
static int parse_wrap_args(const struct option *opt, const char *arg, int unset)
	}
/*
			struct string_list *onelines = item->util;
		die(_("revision walk setup failed"));
	struct string_list_item *item;
				if (log->wrap_lines) {
			oneline++;
		usage_with_options(shortlog_usage, options);
		log->list.items[i].util = NULL;
	log->list.strdup_strings = 1;
		error(_("too many arguments given outside repository"));
}
#define DEFAULT_INDENT2 9
				}
	strbuf_release(&oneline);
	ctx.output_encoding = get_log_output_encoding();
	log->wrap = DEFAULT_WRAPLEN;
	namelen = ident.name_end - ident.name_begin;
	if (log.file != stdout)

	for (;;) {
	match = log->committer ? committer_match : author_match;
		else
{
		case PARSE_OPT_COMPLETE:
			oneline++;
			; /* discard headers */


	unsigned long ul;
	repo_init_revisions(the_repository, &rev, prefix);
	int nongit = !startup_info->have_repository;
		if (log->summary) {
			pretty_print_commit(&ctx, commit, &oneline);
		const char *eol;
	log.user_format = rev.commit_format == CMIT_FMT_USERFORMAT;
		return -1;
	strbuf_release(&sb);
			onelines->strdup_strings = 1;
	string_list_clear(&log->list, 1);
	strbuf_add_wrapped_text(sb, s, log->in1, log->in2, log->wrap);
		case PARSE_OPT_HELP:
	struct strbuf sb = STRBUF_INIT;
{
	log->list.strdup_strings = 1;

		      log->summary ? compare_by_counter : compare_by_list);
					add_wrapped_shortlog_msg(&sb, msg, log);
		log->wrap = DEFAULT_WRAPLEN;
	}
	ul = strtoul(*arg, &endp, 10);
#include "utf8.h"
		if (!eol)
void shortlog_init(struct shortlog *log)
		} else {
		}
	log.abbrev = rev.abbrev;
		return 0;
		if (parse_stdin_author(log, &mapped_author, v) < 0)
			      const char *oneline)
		if (dot3) {
	}
			for (j = onelines->nr - 1; j >= 0; j--) {
	if (!log->summary) {
int cmd_shortlog(int argc, const char **argv, const char *prefix)
	clear_mailmap(&log->mailmap);

{
 *
	memset(log, 0, sizeof(*log));
			N_("Linewrap output"), PARSE_OPT_OPTARG,
			 N_("Suppress commit descriptions, only provides commit count")),


	if (unset)
		read_from_stdin(&log);
 *   - if --summary is not in use, it will point to a string list of the
		add_head_to_pending(&rev);
	}
		const char *v;
{

		    !skip_prefix(author.buf, match[1], &v))
	maillen = ident.mail_end - ident.mail_begin;
	format_commit_message(commit, fmt, &author, &ctx);
 *  This macro accesses the latter.

		return 0;
	strbuf_release(&mapped_author);
					memmove(p + 5, p + dot3len, taillen + 1);
	strbuf_addch(sb, '\n');
	while ((commit = get_revision(rev)) != NULL)
		OPT_BOOL('s', "summary", &log.summary,
}

static int compare_by_counter(const void *a1, const void *a2)
	shortlog_output(&log);
		return error(wrap_arg_usage);
}
	strbuf_release(&author);

 * The util field of our string_list_items will contain one of two things:
void shortlog_add_commit(struct shortlog *log, struct commit *commit)
			}
		const char *dot3 = log->common_repo_prefix;
}
				const char *msg = onelines->items[j].string;
		while (*oneline && isspace(*oneline) && *oneline != '\n')
		strbuf_reset(&mapped_author);
			fprintf(log->file, "%s (%d):\n",
		strbuf_addf(out, " <%.*s>", (int)maillen, mailbuf);
		return 0;
			char *eob = strchr(oneline, ']');
	parse_options_start(&ctx, argc, argv, prefix, options,
	if (split_ident_line(&ident, in, strlen(in)))
#include "parse-options.h"
	if (prepare_revision_walk(rev))
	insert_one_record(log, author.buf, oneline.len ? oneline.buf : "<none>");
	map_user(&log->mailmap, &mailbuf, &maillen, &namebuf, &namelen);
			int dot3len = strlen(dot3);
		(log->email ? "%cN <%cE>" : "%cN") :

					fwrite(sb.buf, sb.len, 1, log->file);
	*arg = *endp ? endp + 1 : endp;
#include "config.h"
}

}
	return UTIL_TO_INT(i2) - UTIL_TO_INT(i1);
static void read_from_stdin(struct shortlog *log)

#include "revision.h"
		QSORT(log->list.items, log->list.nr,
	     (log->in2 && log->wrap <= log->in2)))
