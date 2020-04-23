				}
	prio_queue_put(&sb.commits, o->commit);
			}
	else
	return 1;
				usage_with_options(blame_opt_usage, options);
 * Show it in incremental output.
#endif
		*time = 0;
		sb.move_score = blame_move_score;

		case PARSE_OPT_HELP:
		return 0;

		*opt |= PICKAXE_BLAME_COPY_HARDEST;
	case DATE_RELATIVE:
	*opt |= PICKAXE_BLAME_MOVE;

{
	revs.disable_stdin = 1;
				       format_time(ci.author_time,
		if (ret)
static void sanity_check_on_fail(struct blame_scoreboard *sb, int baa)
			oidset_parse_file(&sb->ignore_list, i->string);
static int longest_author;
	strbuf_release(&ci->committer_tz);
	 *       when blaming a new file;
	const char *contents_from = NULL;

			die(_("--progress can't be used with --incremental or porcelain formats"));
{
{

	struct rev_info revs;
					name = ci.author.buf;
	printf("%s %d %d %d\n",
			putchar('?');

int cmd_blame(int argc, const char **argv, const char *prefix)
	maillen = ident.mail_end - ident.mail_begin;
		    &ret->committer_time, &ret->committer_tz);
			usage_with_options(blame_opt_usage, options);


		OPT_BIT('l', NULL, &output_option, N_("Show long commit SHA1 (Default: off)"), OUTPUT_LONG_OBJECT_NAME),
				    nth_line_cb, &sb, lno, anchor,
	if (ident.date_begin && ident.date_end)
	size_t len, maillen, namelen;
	range_set_init(&ranges, range_list.nr);
		strbuf_addf(&ret->summary, "(%s)", oid_to_hex(&commit->object.oid));

			coloring_mode |= OUTPUT_COLOR_LINE;
			next = EXPECT_COLOR;
		break;
	NULL
							     &head_oid, 1)))
}
		OPT_BIT(0, "minimal", &xdl_opts, N_("Spend extra cycles to find better match"), XDF_NEED_MINIMAL),
		tmp = "(unknown)";
	}
	if (blame_copy_score)
		if (longest_src_lines < num)
			if (opt & OUTPUT_SHOW_NUMBER)
	oidset_init(&sb->ignore_list, 0);
		break;
static int colorfield_nr, colorfield_alloc;
		int ret;
{
		return 0;

	strbuf_release(&ci->committer_mail);
		printf("previous %s ", oid_to_hex(&prev->commit->object.oid));

}
	int cnt;
	int *opt = option->value;
	write_name_quoted(suspect->path, stdout, '\n');
		struct blame_entry *e = ent->next;
static void commit_info_destroy(struct commit_info *ci)
	if (!detailed) {
}
	struct blame_scoreboard sb;

	 * want the path pruning but we may want "bottom" processing.
	blame_coalesce(&sb);

static int blame_copy_callback(const struct option *option, const char *arg, int unset)
		OPT_BIT('t', NULL, &output_option, N_("Show raw timestamp (Default: off)"), OUTPUT_RAW_TIMESTAMP),
	 */
static struct string_list mailmap = STRING_LIST_INIT_NODUP;


		if (opt & OUTPUT_ANNOTATE_COMPAT) {
			} else  {
#include "userdiff.h"
	if (next == EXPECT_COLOR)
	}
	sb.no_whole_file_rename = no_whole_file_rename;
		OPT_BIT('p', "porcelain", &output_option, N_("Show in a format designed for machine consumption"), OUTPUT_PORCELAIN),
		OPT_BIT(0, "color-by-age", &output_option, N_("color lines by age"), OUTPUT_SHOW_AGE_WITH_COLOR),
	 * -C -C enables copy from existing files, but only
	int longest_dst_lines = 0;
	case DATE_SHORT:
	struct ident_split ident;
		char ch;
	revs.diffopt.flags.allow_textconv = 1;
static int reverse;
	else
	pi->blamed_lines += ent->num_lines;

}
static void get_ac_line(const char *inbuf, const char *what,
		struct blame_origin *suspect = ent->suspect;
		add_pending_object(&revs, &head_commit->object, "HEAD");
		 * "git blame" output.  For C locale, "4 years, 11
		int length = (opt & OUTPUT_LONG_OBJECT_NAME) ? the_hash_algo->hexsz : abbrev;
		case PARSE_OPT_DONE:
		default:
			     struct string_list *ignore_revs_file_list,
	find_alignment(sb, &opt);
	if (0 < abbrev && abbrev < hexsz)
			*output_option |= OUTPUT_SHOW_EMAIL;
		if (!value)
	map_user(&mailmap, &mailbuf, &maillen,
	const char *subject, *encoding;

	struct strbuf committer;
}
	struct string_list_item *item;
	}
 * handled separately from emit_one_suspect_detail(), because a given commit
	while (!strbuf_getwholeline(&buf, fp, '\n')) {
	o->suspects = ent;

		/* The format is just "Commit Parent1 Parent2 ...\n" */
			colorfield[colorfield_nr].hop = approxidate(item->string);
	/*
		OPT_STRING_LIST(0, "ignore-rev", &ignore_rev_list, N_("rev"), N_("Ignore <rev> when blaming")),
	if (!strcmp(var, "blame.showroot")) {
			for (suspect = get_blame_suspects(commit); suspect; suspect = suspect->next) {
}
static int xdl_opts;
/*
				die("missing <path> to blame");
	struct strbuf *name, struct strbuf *mail,
			path = add_prefix(prefix, argv[--argc]);
	if (opt & OUTPUT_SHOW_AGE_WITH_COLOR) {
		*opt |= PICKAXE_BLAME_COPY_HARDER;


	printf("committer-mail %s\n", ci.committer_mail.buf);
#include "config.h"
	return 0;
			warning(_("invalid color '%s' in color.blame.repeatedLines"),
	strbuf_init(&ci->summary, 0);
	}
		break;
	return time_buf.buf;

		blame_date_width = sizeof("Thu Oct 19 16:00");
	cp = blame_nth_line(sb, ent->lno);
		OPT_BIT('c', NULL, &output_option, N_("Use the same output mode as git-annotate (Default: off)"), OUTPUT_ANNOTATE_COMPAT),
	for (ent = sb.ent; ent; ) {
			fputs(color, stdout);
static void write_filename_info(struct blame_origin *suspect)
		OPT_BIT('f', "show-name", &output_option, N_("Show original filename (Default: auto)"), OUTPUT_SHOW_NAME),
#include "utf8.h"
#include "diff.h"

{
	for_each_string_list_item(i, ignore_revs_file_list) {
				if (suspect->guilty && count++) {
		 */
		} else if (!strcmp(value, "none")) {
	const char *default_color = NULL, *color = NULL, *reset = NULL;

			if (argc != 4)
	len = find_commit_subject(message, &subject);
			longest_dst_lines = num;
	string_list_clear(&range_list, 0);
static struct string_list ignore_revs_file_list = STRING_LIST_INIT_NODUP;
		}
 */
				putchar('^');
static void emit_other(struct blame_scoreboard *sb, struct blame_entry *ent, int opt)
		range_set_append_unsafe(&ranges, bottom, top);
	return OBJ_NONE < oid_object_info(the_repository, &oid, NULL);
	strbuf_addf(mail, "<%.*s>", (int)maillen, mailbuf);
 * Parse author/committer line in the commit object buffer
{
		case 2: /* (1b) */
static char repeated_meta_color[COLOR_MAXLEN];
#define DEBUG_BLAME 0
	if (sb->final_buf_size && cp[-1] != '\n')
/*
		}
	if (!strcmp(var, "blame.ignorerevsfile")) {

				if (opt & OUTPUT_SHOW_EMAIL)
		if (color_parse_mem(value, strlen(value), repeated_meta_color))
		blame_copy_score = parse_score(arg);
		goto error_out;

		tz = atoi(tz_str);
			/* reorder for the new way: <rev> -- <path> */

	if (!strcmp(var, "blame.showemail")) {
		return 0;
static int show_root;
#include "prio-queue.h"
			}
	};
		blame_move_score = parse_score(arg);
static int mark_unblamable_lines;
		case PARSE_OPT_COMPLETE:
		string_list_append(&range_list, "1");
			longest_file = num;
	strbuf_add(name, namebuf, namelen);
			   int opt)
		}
	int i = 0;
{
			if (!(opt & OUTPUT_NO_AUTHOR)) {
		if (mark_ignored_lines && ent->ignored) {

		return 0;
	} else if (show_progress < 0)
			*option |= OUTPUT_SHOW_NAME;
		maybe_flush_or_die(stdout, "stdout");

	const char *namebuf, *mailbuf;
{
	}

		OPT_STRING_LIST('L', NULL, &range_list, N_("n,m"), N_("Process only line range n,m, counting from 1")),
	/*

		 * maximum display width for a relative timestamp in
	static struct strbuf time_buf = STRBUF_INIT;

	if (*opt & PICKAXE_BLAME_COPY_HARDER)


		 * columns.
static int max_orig_digits;
static void setup_default_color_by_age(void)
	if (output_option & OUTPUT_ANNOTATE_COMPAT)
	case DATE_ISO8601_STRICT:
		pi.progress = start_delayed_progress(_("Blaming lines"), sb.num_lines);
		switch (parse_options_step(&ctx, options, blame_opt_usage)) {
 * Information on commits, used for output.
				printf(" %-*.*s", longest_file, longest_file,
		return;

			emit_porcelain(sb, ent, option);
		abbrev = auto_abbrev + 1;
	int len = strlen(uniq);
			die("no such ref: HEAD");
		{ OPTION_CALLBACK, 'M', NULL, &opt, N_("score"), N_("Find line movements within and across files"), PARSE_OPT_OPTARG, blame_move_callback },
				    &bottom, &top, sb.path,
		if (!strcmp(i->string, ""))
		return 0;
	case DATE_NORMAL:
		OPT_STRING(0, "contents", &contents_from, N_("file"), N_("Use <file>'s contents as the final image")),
		}
		return len;
static int max_score_digits;
static int incremental;
		    !(head_commit = lookup_commit_reference_gently(revs.repo,
		}


}
}
	}
}
			argv[2] = "--";
	case DATE_HUMAN:
		     time_width < blame_date_width;
			path = add_prefix(prefix, argv[argc - 1]);
	struct string_list range_list = STRING_LIST_INIT_NODUP;

	while (i < colorfield_nr && ci.author_time > colorfield[i].hop)
		OPT_BIT(0, "line-porcelain", &output_option, N_("Show porcelain format with per-line commit information"), OUTPUT_PORCELAIN|OUTPUT_LINE_PORCELAIN),
	/* Ideally this would be stripped and split at the same time? */
		time_str = show_date(time, tz, &blame_date_mode);
	char hex[GIT_MAX_HEXSZ + 1];
			if (opt & OUTPUT_SHOW_NAME)
	output(&sb, output_option);

	}
		blame_date_width = utf8_strwidth(_("4 years, 11 months ago")) + 1; /* add the null */
		/* one more abbrev length is needed for the boundary commit */
			       ent->lno + 1 + cnt);
		if (opt & OUTPUT_COLOR_LINE) {
 * The blame_entry is found to be guilty for the range.
	switch (blame_date_mode.type) {
#include "line-log.h"
			else
			if (*option & OUTPUT_SHOW_EMAIL)
		int num;
		oidset_insert(&sb->ignore_list, &oid);

				die(_("expecting a color: %s"), item->string);
		break;
	for (ent = sb->ent; ent; ent = ent->next) {
static int mark_ignored_lines;
#define OUTPUT_SHOW_EMAIL           (1U<<8)
		blame_date_width = sizeof("2006-10-19");
	 */
		return -1;
		switch (argc - dashdash_pos - 1) {

				longest_author = num;
	strbuf_init(&ci->committer_mail, 0);
/*
		len = endp - tmp;

		num = strlen(suspect->path);
	struct progress_info pi = { NULL, 0 };
	int auto_abbrev = DEFAULT_ABBREV;
			oidset_clear(&sb->ignore_list);
				       ent->suspect->refcnt);
		abbrev = hexsz;
		output_option |= coloring_mode;
					    OUTPUT_SHOW_AGE_WITH_COLOR);
	case DATE_RFC2822:
			       format_time(ci.author_time, ci.author_tz.buf,
		printf("num commits: %d\n", sb.num_commits);
 * we mention a new group.
		struct commit_graft *graft = read_graft_line(&buf);
	return git_default_config(var, value, cb);

static int no_whole_file_rename;
	struct strbuf author_mail;
 * Add phony grafts for use with -S; this is primarily to
			struct blame_origin *suspect;
		blame_date_width = sizeof("2006-10-19T16:00:04-07:00");
			auto_abbrev = update_auto_abbrev(auto_abbrev, suspect);
		putchar('\n');
static char blame_usage[] = N_("git blame [<options>] [<rev-opts>] [<rev>] [--] <file>");

		num = e->lno + e->num_lines;
		}
		break;
		if (largest_score < blame_entry_score(sb, e))
			emit_other(sb, ent, option);
	string_list_split(&l, s, ',', -1);
}
		strbuf_addstr(tz, tmp);
	read_mailmap(&mailmap, NULL);
	struct strbuf summary;
#include "object-store.h"


	struct commit_info ci;


	struct object_id oid;
		if (argc < 2)
			if (opt & OUTPUT_SHOW_SCORE)
static void output(struct blame_scoreboard *sb, int option)
		}
				       name, pad, "",
	for_each_string_list_item(item, &l) {
		printf("%s %d %d %d\n",

	else
	fclose(fp);
			if (color_parse(item->string, colorfield[colorfield_nr].col))
#include "parse-options.h"
	max_score_digits = decimal_width(largest_score);
	colorfield_nr = 0;
	 *     "blame [revisions] -- <path>" or
	strbuf_reset(&time_buf);
	for (range_i = 0; range_i < range_list.nr; ++range_i) {
	unsigned largest_score = 0;
	for (range_i = ranges.nr; range_i > 0; --range_i) {
				  sizeof(repeated_meta_color),

}
		if (longest_file < num)
	suspect->commit->object.flags |= METAINFO_SHOWN;
	string_list_clear(&ignore_revs_file_list, 0);
	printf("committer-time %"PRItime"\n", ci.committer_time);
				reset = default_color ? GIT_COLOR_RESET : NULL;
	if (incremental) {
struct progress_info {

	struct blame_origin *suspect = ent->suspect;
	blame_usage,
	get_commit_info(ent->suspect->commit, &ci, 1);
#include "dir.h"
static int abbrev = -1;
	 * The remaining are:
		OPT_BOOL(0, "incremental", &incremental, N_("Show blame entries as we find them, incrementally")),
	for (cnt = 0; cnt < ent->num_lines; cnt++) {
	if (!strcmp(var, "blame.coloring")) {
	long dashdash_pos, lno;
		OPT__ABBREV(&abbrev),
	tmp = strstr(inbuf, what);
		sb.copy_score = blame_copy_score;
		blank_boundary = git_config_bool(var, value);
	}

	case DATE_UNIX:
	return blame_nth_line((struct blame_scoreboard *)data, lno);
static int emit_one_suspect_detail(struct blame_origin *suspect, int repeat)
	sb.path = path;

			argv[3] = argv[2];
		/* Ugh */
		i++;
	if (!strcmp(var, "color.blame.highlightrecent")) {
			    int detailed)
	 * going to do the "bottom" processing.

		else
		}
	get_ac_line(message, "\ncommitter ",

 * Write out any suspect information which depends on the path. This must be
	 *          everybody
		die(_("must end with a color"));
#include "builtin.h"
{
	       hex,
			printf(" %*d) ",
	if (get_oid(name, &oid))
	sb.on_sanity_fail = &sanity_check_on_fail;
	endp = strchr(tmp, '\n');
 * user has specifically asked for us to repeat).
		setup_pager();

	       ent->lno + 1,
	return score;
		reset = GIT_COLOR_RESET;
		OPT_BOOL(0, "progress", &show_progress, N_("Force progress reporting")),
	if (auto_abbrev < len)

	}


#include "repository.h"
	 * which are to be passed to revision machinery if we are
		*time = strtoul(ident.date_begin, NULL, 10);
		else
	timestamp_t hop;
		 * your language may need more or fewer display

			if (ctx.argv[0])
static void parse_color_fields(const char *s)
			    struct commit_info *ret,
	}
		for (time_width = utf8_strwidth(time_str);
static int git_blame_config(const char *var, const char *value, void *cb)
		do {
			struct commit_info ci;
		} while (ch != '\n' &&
{
	struct strbuf committer_tz;
	if (suspect->commit->object.flags & UNINTERESTING)
	strbuf_init(&ci->author, 0);
			PICKAXE_BLAME_COPY_HARDER);
static int read_ancestry(const char *graft_file)
		 * string, and use time_width for display width calibration.
	int repeat = opt & OUTPUT_LINE_PORCELAIN;
		if (!strcmp(value, "repeatedLines")) {
	if (!fp)

		if (compute_auto_abbrev)
	strbuf_release(&ci->author_tz);
	oid_to_hex_r(hex, &suspect->commit->object.oid);
	*dest_color = colorfield[i].col;
	 * -C enables copy from removed files;
	 *     "blame [revisions] <path>"
		write_filename_info(suspect);
		return 0;
		}
				printf(" %*d", max_orig_digits,
	return 0;
	die("Baa %d!", baa);
			fputs(reset, stdout);
	namelen = ident.name_end - ident.name_begin;

					commit->object.flags |= MORE_THAN_ONE_PATH;
		strbuf_addstr(name, tmp);
		if (bottom < 1)
	if (split_ident_line(&ident, tmp, len)) {

	}
static int blank_boundary;
		if (color)
	 * (1) if dashdash_pos != 0, it is either
	/* The maximum width used to show the dates */

	if (compute_auto_abbrev)
			commit_info_destroy(&ci);
	setup_scoreboard(&sb, path, &o);
		int tz;
				       suspect->path);
	cp = blame_nth_line(sb, ent->lno);

	 * Now, convert both name and e-mail using mailmap
	}

		show_root = git_config_bool(var, value);
			suspect->commit->object.flags |= METAINFO_SHOWN;

	strbuf_init(&ci->author_mail, 0);
		long bottom, top;
	if (suspect->previous) {

		do {
{
};
		if (!resolve_ref_unsafe("HEAD", RESOLVE_REF_READING,
	struct string_list ignore_rev_list = STRING_LIST_INIT_NODUP;
	case DATE_RAW:
	} else {
	if (!incremental)

	init_scoreboard(&sb);
	if (*end)
					break;
		case PARSE_OPT_ERROR:
			if (repeat)
				pad = longest_author - utf8_strwidth(name);
		if (!(suspect->commit->object.flags & METAINFO_SHOWN)) {
		 &namebuf, &namelen);
{
	unuse_commit_buffer(commit, message);
	 */
				color = default_color ? default_color : NULL;
		/* one more abbrev length is needed for the boundary commit */
			return config_error_nonbool(var);
	sb.debug = DEBUG_BLAME;
				else
	}
}
	if (arg)
	for (;;) {
	display_progress(pi->progress, pi->blamed_lines);
	 *
static int max_digits;
		find_alignment(&sb, &output_option);
		printf("%.*s", length, hex);
		}
	struct commit_info ci;
	max_digits = decimal_width(longest_dst_lines);
		abbrev++;
			 cp < sb->final_buf + sb->final_buf_size);
			 cp < sb->final_buf + sb->final_buf_size);
 */
{

}
			putchar(ch);
static void commit_info_init(struct commit_info *ci)

	int len;
 */
	struct blame_entry *ent = NULL;
 * See COPYING for licensing conditions
	struct progress_info *pi = (struct progress_info *)data;
	return prefix_path(prefix, prefix ? strlen(prefix) : 0, path);
/*
				printf(" (%s%*s %10s",
	 * (2) otherwise, it is one of the two:

	if (revs_file && read_ancestry(revs_file))
	 *     "blame <path> <rev>"
 *

	       ent->s_lno + 1,
 */
static void emit_porcelain(struct blame_scoreboard *sb, struct blame_entry *ent,
{
	show_progress = -1;
		break;
	struct strbuf buf = STRBUF_INIT;


	commit_info_destroy(&ci);
	}

		emit_one_suspect_detail(suspect, 0);
	build_ignorelist(&sb, &ignore_revs_file_list, &ignore_rev_list);
			usage_with_options(blame_opt_usage, options);
	}

			break;
		    &ret->committer, &ret->committer_mail,
	printf("committer-tz %s\n", ci.committer_tz.buf);
	 * -C -C -C enables copy from existing files for
		OPT_BOOL('b', NULL, &blank_boundary, N_("Show blank SHA-1 for boundary commits (Default: off)")),
		{ OPTION_CALLBACK, 'C', NULL, &opt, N_("score"), N_("Find line copies within and across files"), PARSE_OPT_OPTARG, blame_copy_callback },
		strbuf_addstr(mail, tmp);
		 */
};
#include "color.h"
		       ent->s_lno + 1, ent->lno + 1, ent->num_lines);
	parse_options_start(&ctx, argc, argv, prefix, options,
			die(_("cannot find revision %s to ignore"), i->string);
	printf("summary %s\n", ci.summary.buf);

			       int show_raw_time)
		OPT_END()
		OPT_STRING_LIST(0, "ignore-revs-file", &ignore_revs_file_list, N_("file"), N_("Ignore revisions from <file>")),
 * support git's cvsserver that wants to give a linear history
		if (graft)
static int update_auto_abbrev(int auto_abbrev, struct blame_origin *suspect)
	get_ac_line(message, "\nauthor ",
#define OUTPUT_SHOW_NUMBER          (1U<<5)
		blame_date_width = sizeof("Thu Oct 19 16:00:04 2006 -0700");
	}
		}
		return 0;
		OPT_BOOL(0, "root", &show_root, N_("Do not treat root commits as boundaries (Default: off)")),
	for (cnt = 0; cnt < ent->num_lines; cnt++) {
	char col[COLOR_MAXLEN];
		parse_date_format(value, &blame_date_mode);
		for (ent = sb->ent; ent; ent = ent->next) {
		}
	strbuf_release(&ci->author);
	range_set_release(&ranges);
			putchar('*');
	printf("committer %s\n", ci.committer.buf);
						   show_raw_time));
		blame_date_width = sizeof("2006-10-19 16:00:04 -0700");
	if (option & OUTPUT_PORCELAIN) {
/* Remember to update object flag allocation in object.h */
static int blame_move_callback(const struct option *option, const char *arg, int unset)
 * may have changes in multiple paths. So this needs to appear each time
	struct parse_opt_ctx_t ctx;
{

	 *     "blame -- <path> <rev>"



	if (!strcmp(var, "blame.date")) {
			printf("%s %d %d\n", hex,

	strbuf_release(&ci->summary);
	/*
	sb.ent = NULL;
			goto parse_done;
	for (e = sb->ent; e; e = e->next) {
			return ret;
		color = default_color;
#define OUTPUT_SHOW_SCORE           (1U<<6)

	 *
		return 0;
#include "string-list.h"

	setup_default_color_by_age();
			ctx.argv[0] = "--children";
#define OUTPUT_NO_AUTHOR            (1U<<7)

	strbuf_release(&buf);
	}
		else {
}

/*
	if (*opt & PICKAXE_BLAME_COPY)
		 * months ago", which takes 22 places, is the longest
			argv[1] = argv[3];
	if (ident.tz_begin && ident.tz_end)
	struct commit_info ci;
		}
	unsigned int range_i;
		struct blame_origin *prev = suspect->previous;
	tmp += strlen(what);
		if (reset)
			usage(blame_usage);
	if (!revs.pending.nr && is_bare_repository()) {
	blame_origin_decref(o);
		if (!*repeated_meta_color &&
#include "commit.h"
			die(Q_("file %s has only %lu line",

				  "%s", GIT_COLOR_CYAN);
	} else {
	struct blame_entry *e;
				       max_score_digits, ent->score,
static void determine_line_heat(struct blame_entry *ent, const char **dest_color)
		return -1;
	 * We have collected options unknown to us in argv[1..unk]
	for_each_string_list_item(i, ignore_rev_list) {
}
	sb.show_root = show_root;
}
			/* FALLTHROUGH */
			else if (!(opt & OUTPUT_ANNOTATE_COMPAT)) {
		    &ret->author_time, &ret->author_tz);
			colorfield_nr++;
		const struct range *r = &ranges.ranges[range_i - 1];
	FILE *fp = fopen_or_warn(graft_file, "r");
 * Porcelain/Incremental format wants to show a lot of details per
	}

			if (argc == 2 && is_a_rev(argv[1]) && !get_git_work_tree())
static void find_alignment(struct blame_scoreboard *sb, int *option)
		ent = blame_entry_prepend(ent, r->start, r->end, o);
	stop_progress(&pi.progress);
	timestamp_t committer_time;
	struct progress *progress;
	if (!tmp)
static const char *add_prefix(const char *prefix, const char *path)
 */
			coloring_mode &= ~(OUTPUT_COLOR_LINE |
		    &ret->author, &ret->author_mail,
static size_t blame_date_width;
	get_commit_info(suspect->commit, &ci, 1);
parse_done:
 * To allow LF and other nonportable characters in pathnames,

	struct strbuf author;
	}
			ALLOC_GROW(colorfield, colorfield_nr + 1, colorfield_alloc);
 */
/*

	if (!repeat && (suspect->commit->object.flags & METAINFO_SHOWN))
			else
	else

	setup_revisions(argc, argv, &revs, NULL);
	if (show_stats) {
#define OUTPUT_SHOW_NAME            (1U<<4)
				printf(" %*d %02d",
	xdl_opts |= revs.diffopt.xdl_opts & XDF_INDENT_HEURISTIC;
	ALLOC_GROW(colorfield, colorfield_nr + 1, colorfield_alloc);
	struct range_set ranges;
	if (git_diff_heuristic_config(var, value, cb) < 0)

	/* filled only when asked for details */
	else

#define OUTPUT_LINE_PORCELAIN       (1U<<9)
{
{
	save_commit_buffer = 0;
		blame_date_mode = revs.date_mode;
}
			    PARSE_OPT_KEEP_DASHDASH | PARSE_OPT_KEEP_ARGV0);
			const char *name;
static const char *nth_line_cb(void *data, long lno)
	}
	string_list_clear(&l, 0);
		struct commit *head_commit;
}
		if (show_progress > 0)
		struct blame_origin *suspect = e->suspect;

#include "progress.h"
	if (!strcmp(var, "blame.markunblamablelines")) {
	    (suspect->commit->object.flags & MORE_THAN_ONE_PATH))
		if (!strcmp(ctx.argv[0], "--reverse")) {
	const char *message;
	}
	sb.contents_from = contents_from;

 * Blame
		OPT_BIT(0, "color-lines", &output_option, N_("color redundant metadata from previous line differently"), OUTPUT_COLOR_LINE),
			path = add_prefix(prefix, argv[1]);
	struct string_list_item *i;
/*
	}
		return -1;

			coloring_mode |= OUTPUT_SHOW_AGE_WITH_COLOR;
			     struct string_list *ignore_rev_list)
	no_whole_file_rename = !revs.diffopt.flags.follow_renames;
static void found_guilty_entry(struct blame_entry *ent, void *data)
	sb.found_guilty_entry = &found_guilty_entry;
}
	enum { EXPECT_DATE, EXPECT_COLOR } next = EXPECT_COLOR;
			if (longest_author < num)
		return 0;
	if (len)
	}

			putchar(ch);
	revs.date_mode = blame_date_mode;
		break;
		putchar('\n');
		*time = 0;
	strbuf_init(&ci->committer, 0);
			       max_digits, ent->lno + 1 + cnt);
		if (mark_unblamable_lines && ent->unblamable) {
			*output_option &= ~OUTPUT_SHOW_EMAIL;
{
	BUG_ON_OPT_NEG(unset);

}

	return auto_abbrev;
				num = utf8_strwidth(ci.author.buf);
			length--;

	printf("filename ");
	}
		if (longest_dst_lines < num)
			xsnprintf(repeated_meta_color,
		/*
	namebuf = ident.name_begin;
	if (!endp)
		die_errno("reading graft file '%s' failed", revs_file);
		}
	       ent->num_lines);
	int blamed_lines;
	emit_porcelain_details(suspect, repeat);
	if (lno && !range_list.nr)
{
			argv[1] = argv[2];
		if (strcmp(suspect->path, sb->path))
		     time_width++)
	assign_blame(&sb, opt);


#define OUTPUT_ANNOTATE_COMPAT      (1U<<0)
	if (!strcmp(var, "blame.blankboundary")) {
		} while (ch != '\n' &&
static int longest_file;
{
	}
			reverse = 1;
					      auto_abbrev);
			longest_src_lines = num;
	unsigned long score = strtoul(arg, &end, 10);
	const int hexsz = the_hash_algo->hexsz;
		break;
		} else {
}
		show_progress = 0;
		strbuf_add(&ret->summary, subject, len);
			length--;

	strbuf_init(&ci->committer_tz, 0);

		output_option &= ~(OUTPUT_COLOR_LINE | OUTPUT_SHOW_AGE_WITH_COLOR);
	printf("author-tz %s\n", ci.author_tz.buf);
		blame_date_width = sizeof("Thu, 19 Oct 2006 16:00:04 -0700");
	if (!strcmp(var, "blame.markignoredlines")) {
} *colorfield;
				reset = GIT_COLOR_RESET;
		if (suspect->commit->object.flags & UNINTERESTING) {
}
	}
	}
static int show_progress;
			exit(0);
{
 * commit.  Instead of repeating this every line, emit it only once,
	git_config(git_blame_config, &output_option);
			get_commit_info(suspect->commit, &ci, 1);
	BUG_ON_OPT_NEG(unset);
#include "revision.h"
#define OUTPUT_COLOR_LINE           (1U<<10)
		size_t time_width;
static const char *blame_opt_usage[] = {
			return 0;
		const char *time_str;


		struct object_id head_oid;
	}
				continue;
				length--;
	return 0;
	printf("author-mail %s\n", ci.author_mail.buf);
		OPT_BIT('w', NULL, &xdl_opts, N_("Ignore whitespace differences"), XDF_IGNORE_WHITESPACE),
		return 0;
		strbuf_addf(&time_buf, "%"PRItime" %s", time, tz_str);
		}
{
{
			largest_score = blame_entry_score(sb, e);
	strbuf_release(&ci->committer);
		case EXPECT_DATE:
	char hex[GIT_MAX_HEXSZ + 1];

				int pad;
		printf("num read blob: %d\n", sb.num_read_blob);

		break;
		write_filename_info(suspect);
	sb.revs = &revs;
	if (!(output_option & OUTPUT_PORCELAIN)) {
	const char *uniq = find_unique_abbrev(&suspect->commit->object.oid,
		return 0;
		case EXPECT_COLOR:
	struct blame_origin *suspect = ent->suspect;
	const char *path;
}
#define METAINFO_SHOWN		(1u<<12)
			int count = 0;
	return 0;
		if ((!lno && (top || bottom)) || lno < bottom)

				num = utf8_strwidth(ci.author_mail.buf);
	}
		determine_line_heat(ent, &default_color);
			}

	struct object_id oid;
		write_name_quoted(prev->path, stdout, '\n');

	commit_info_destroy(&ci);
#include "mailmap.h"
	if (incremental || (output_option & OUTPUT_PORCELAIN)) {
		int *output_option = cb;
		argv[argc - 1] = "--";
}
		return 0;
			       ent->lno + 1 + cnt);
				    the_repository->index))
		blame_date_width = sizeof("1161298804");
 * they are c-style quoted as needed.
			top = lno;
 */
		parse_color_fields(value);
			next = EXPECT_DATE;
			register_commit_graft(the_repository, graft, 0);
	dashdash_pos = 0;
			       "file %s has only %lu lines",
static int coloring_mode;
			ch = *cp++;
	int cmd_is_annotate = !strcmp(argv[0], "annotate");
	repo_init_revisions(the_repository, &revs, NULL);
		len = strlen(tmp);
		 * among various forms of relative timestamps, but
		mark_ignored_lines = git_config_bool(var, value);
		OPT_BIT(0, "score-debug", &output_option, N_("Show output score for blame entries"), OUTPUT_SHOW_SCORE),
			ch = *cp++;
	 *
		num = e->s_lno + e->num_lines;
	}
	lno = sb.num_lines;
{
		OPT_STRING('S', NULL, &revs_file, N_("file"), N_("Use revisions from <file> instead of calling git-rev-list")),
		 * Add space paddings to time_buf to display a fixed width
			if (opt & OUTPUT_SHOW_EMAIL)
	*opt |= PICKAXE_BLAME_COPY | PICKAXE_BLAME_MOVE;

		} else {	/* (2a) */
		if (parse_range_arg(range_list.items[range_i].string,
		strbuf_addstr(tz, "(unknown)");
		/*
	char *tmp, *endp;
				memset(hex, ' ', length);
}

static void get_commit_info(struct commit *commit,
				color = repeated_meta_color;
		} else {
#define OUTPUT_PORCELAIN            (1U<<3)
			exit(129);
	error_out:

		strbuf_addstr(&time_buf, time_str);
	printf("author-time %"PRItime"\n", ci.author_time);
{
				name = ci.author_mail.buf;
	sb.reverse = reverse;
		output_option |= OUTPUT_ANNOTATE_COMPAT;
	char *end;
			if (blank_boundary)
{

	struct blame_entry *ent;

		    (output_option & OUTPUT_COLOR_LINE))
		/* If the year is shown, no time is shown */
	if (!strcmp(var, "color.blame.repeatedlines")) {
		OPT_BIT('e', "show-email", &output_option, N_("Show author email instead of name (Default: off)"), OUTPUT_SHOW_EMAIL),
#include "cache.h"
	else if (!abbrev)
				const char *name;
		if (git_config_bool(var, value))
	if (blame_move_score)

		if (cnt) {
	int opt = OUTPUT_SHOW_SCORE | OUTPUT_SHOW_NUMBER | OUTPUT_SHOW_NAME;
#include "blame.h"
	"",

	}
#include "refs.h"
	anchor = 1;
	if (arg)
		show_progress = isatty(2);
	if (!(output_option & (OUTPUT_COLOR_LINE | OUTPUT_SHOW_AGE_WITH_COLOR)))
			if (cnt > 0) {
	if (show_progress)
		return;

		bottom--;
				dashdash_pos = ctx.cpidx;
 * the first time each commit appears in the output (unless the
#define MORE_THAN_ONE_PATH	(1u<<13)
		opt |= (PICKAXE_BLAME_COPY | PICKAXE_BLAME_MOVE |
	max_orig_digits = decimal_width(longest_src_lines);
	int cnt;
	strbuf_release(&ci->author_mail);
						   ci.author_tz.buf,
	timestamp_t author_time;

		if (argc == 3 && is_a_rev(argv[argc - 1])) { /* (2b) */
	printf("author %s\n", ci.author.buf);
	blame_date_width -= 1; /* strip the null */
	struct strbuf committer_mail;
					   show_raw_time),
 * Copyright (c) 2006, 2014 by its authors
static struct date_mode blame_date_mode = { DATE_ISO8601 };
		if (get_oid_committish(i->string, &oid))
	if (userdiff_config(var, value) < 0)
	string_list_clear(&ignore_rev_list, 0);
static int is_a_rev(const char *name)
	case DATE_ISO8601:

	int show_raw_time = !!(opt & OUTPUT_RAW_TIMESTAMP);
	struct strbuf author_tz;
		return 0;
	}

	encoding = get_log_output_encoding();
		switch (next) {
		blame_date_width = sizeof("1161298804 -0700");

	 *
static struct color_field {
		} else if (!strcmp(value, "highlightRecent")) {

			}
 *

			strbuf_addch(&time_buf, ' ');
			warning(_("invalid value for blame.coloring"));
		anchor = top + 1;
static void build_ignorelist(struct blame_scoreboard *sb,
	sb.found_guilty_entry_data = &pi;
	const char *revs_file = NULL;
	const char *cp;
			printf("\t(%10s\t%10s\t%d)", name,

	commit_info_init(ret);
	}
}

	revs.diffopt.flags.follow_renames = 0;
		const char *str;
		string_list_insert(&ignore_revs_file_list, str);
#include "quote.h"
		OPT_BIT('n', "show-number", &output_option, N_("Show original linenumber (Default: off)"), OUTPUT_SHOW_NUMBER),
	case DATE_STRFTIME:
	if (sb->final_buf_size && cp[-1] != '\n')
	const struct option options[] = {
			argv[argc] = NULL;

		strbuf_add(tz, ident.tz_begin, ident.tz_end - ident.tz_begin);
				value);
			       lno), path, lno);
			bottom = 1;
		char ch;
	int *opt = option->value;

		mark_unblamable_lines = git_config_bool(var, value);
static unsigned parse_score(const char *arg)

		ent = e;

	}

	revs.diffopt.flags.follow_renames = 1;


}
	strbuf_init(&ci->author_tz, 0);
	blame_sort_final(&sb);

	int compute_auto_abbrev = (abbrev < 0);
		case 1: /* (1a) */
static const char *format_time(timestamp_t time, const char *tz_str,
static unsigned blame_copy_score;
	sb.repo = the_repository;
		blame_date_mode.type = DATE_ISO8601;
	if (show_raw_time) {
		OPT_BOOL(0, "show-stats", &show_stats, N_("Show work cost statistics")),

		parse_revision_opt(&revs, &ctx, options, blame_opt_usage);

	}
}
	sort_and_merge_range_set(&ranges);

	if (emit_one_suspect_detail(suspect, repeat) ||
{
		unuse_commit_buffer(commit, message);
		ret = git_config_pathname(&str, var, value);

					name = ci.author_mail.buf;
	sb.xdl_opts = xdl_opts;
	message = logmsg_reencode(commit, NULL, encoding);
struct commit_info {
		if (option & OUTPUT_PORCELAIN)
	get_commit_info(suspect->commit, &ci, 1);
 * and filenames?
		break;
	else {
	free((void *)sb.final_buf);
#define OUTPUT_LONG_OBJECT_NAME     (1U<<1)
#define OUTPUT_RAW_TIMESTAMP        (1U<<2)
	 * Note that we must strip out <path> from the arguments: we do not
			break;
	struct blame_origin *o;
			struct commit *commit = ent->suspect->commit;
	N_("<rev-opts> are documented in git-rev-list(1)"),
		printf("num get patch: %d\n", sb.num_get_patch);
	mailbuf = ident.mail_begin;
		printf("boundary\n");
				       ent->s_lno + 1 + cnt);
	output(sb, opt);
	if (dashdash_pos) {
	int longest_src_lines = 0;
	int show_stats = 0;
		if (top < 1 || lno < top)
};
#ifndef DEBUG_BLAME
#define OUTPUT_SHOW_AGE_WITH_COLOR  (1U<<11)
#include "line-range.h"
static unsigned blame_move_score;
	oid_to_hex_r(hex, &suspect->commit->object.oid);
 */
				name = ci.author.buf;
		free(ent);
	if (cmd_is_annotate) {
 * How many columns do we need to show line numbers, authors,
	const char *cp;
			       ent->s_lno + 1 + cnt,
		blame_date_width = strlen(show_date(0, 0, &blame_date_mode)) + 1; /* add the null */

	if (revs.diffopt.flags.find_copies_harder)

{
		OPT_BIT('s', NULL, &output_option, N_("Suppress author name and timestamp (Default: off)"), OUTPUT_NO_AUTHOR),
	colorfield[colorfield_nr].hop = TIME_MAX;
 * to its clients.
/*
					&head_oid, NULL) ||
	long anchor;
	}
			if (commit->object.flags & MORE_THAN_ONE_PATH)
	parse_color_fields("blue,12 month ago,white,1 month ago,red");
static void emit_porcelain_details(struct blame_origin *suspect, int repeat)
				emit_porcelain_details(suspect, 1);
		 * TRANSLATORS: This string is used to tell us the
		putchar('\t');
	int output_option = 0, opt = 0;
			break;
		       oid_to_hex(&suspect->commit->object.oid),
	argc = parse_options_end(&ctx);
	struct string_list l = STRING_LIST_INIT_DUP;
	timestamp_t *time, struct strbuf *tz)
