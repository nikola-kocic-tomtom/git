		    opt->verbose_header &&

					 abbrev_commit),



void format_decorations_extended(struct strbuf *sb,
		diff_setup(&opts);

		      opt->diffopt.file);
	if (starts_with(refname, "refs/heads/"))
	if (extra->len > payload_size) {
		obj = parse_object(the_repository, &original_oid);
		return;
		for_each_commit_graft(add_graft_decoration, filter);
	}
		if (list->type == DECORATION_REF_HEAD) {
	 */
	size_t payload_size;

	else
		memcpy(&dq, &diff_queued_diff, sizeof(diff_queued_diff));
#include "object-store.h"
			       find_unique_abbrev(&parent->object.oid, abbrev_commit));
		return 0;
	decorate_get_color((o)->use_color, ix)
		}
	fmt_output_subject(filename, subject.buf, info);
	if (opt->message_id) {
	}
		 * should look human-readable.  If the last entry ended

		strbuf_reset(&buffer);
		graph_show_oneline(opt->graph);
			int use_color,
				      &null_oid : &commit->object.oid);

{
		if (filter) {
			/*
		fprintf_ln(opt->diffopt.file, "%s", opt->idiff_title);
		 * line and will look like a gap in the graph.
{
/*
			 mime_boundary_leader, opt->mime_boundary,
	if (!branch_name || !(rru_flags & REF_ISSYMREF))
			 "--%s%s\n"

{
	}
			 * parent, showing summary diff of the others
			    *opt->subject_prefix ? " " : "",
	} else {
	}
		log_write_email_headers(opt, commit, &extra_headers,
		if (opt->diffopt.line_termination == '\n' &&
	struct object_id oid;
		putc(opt->diffopt.line_termination, opt->diffopt.file);
		ctx.print_email_subject = 1;
		int i, n;

			    opt->subject_prefix);
	}
		strbuf_addf(sb, "Subject: [%s%s%0*d/%d] ",
			 type_name(OBJ_TAG), &oid);
	strbuf_addstr(sb, color_reset);
					    opt->date_mode_explicit);
			return 0;
	format_commit_message(commit, "%f", &subject, &ctx);
			 * after the three-dashes line.
			if (opt->diffopt.output_prefix) {
	if (status && !sigc.gpg_output)

{
	struct strbuf verify_message;
	parents = get_saved_parents(opt, commit);
		type = DECORATION_REF_LOCAL;
		/* If we show individual diffs, show the parent info */
			add_name_decoration(DECORATION_GRAFTED, "replaced", obj);
	GIT_COLOR_BOLD_BLUE,	/* GRAFTED */
		log.parent = NULL;
	const struct name_decoration *list, *head = NULL;
	 * print the graph, up to this commit's line
	current_and_HEAD = current_pointed_by_HEAD(decoration);
/*
				normalize_glob_ref(item, NULL, item->string);
				fwrite(msg->buf, msg->len, 1, opt->diffopt.file);
	free(ctx.notes_message);
{

	int nr = info->nr;
		fprintf(opt->diffopt.file, "Message-Id: <%s>\n", opt->message_id);
	strbuf_addstr(sb, suffix);
const struct name_decoration *get_name_decoration(const struct object *obj)

	const char *extra_headers = opt->extra_headers;
		fprintf(opt->diffopt.file, "In-Reply-To: <%s>\n", opt->ref_message_ids->items[n-1].string);
static void show_sig_lines(struct rev_info *opt, int status, const char *bol)
				strbuf_addstr(sb, " -> ");
	 * If the history graph was requested,
};

	status = check_signature(payload.buf, payload.len, signature.buf,
	}
		strbuf_addf(&verify_message,
	if (sb)
			 * and opt->graph cannot both be set,
	strbuf_release(&verify_message);
		/*
}
	return -1;
	tag = lookup_tag(the_repository, &oid);
	color = diff_get_color_opt(&opt->diffopt,
		opt->missing_newline = 0;
	if (0 < info->reroll_count)
	else
	}
	strbuf_addf(filename, "%04d-%s", nr, subject);
				     get_log_output_encoding(), raw);
	opt->loginfo = &log;
		show_signature(opt, commit);
	if (cmit_fmt_is_mail(opt->commit_format)) {
		fputs(x, opt->diffopt.file);
	while (i <= number) {
			 mime_boundary_leader, opt->mime_boundary,
			    "parent #%d, tagged '%s'\n", nth + 1, tag->tag);
	if (!opt->show_decorations)
{
}

	struct log_info *log = opt->loginfo;
#include "diff.h"
			strbuf_addf(&filename, "%d", opt->nr);
	struct name_decoration *res;
			 * between generated commentary (notes, etc.)
	if (opt->shown_one && !opt->use_terminator) {
		}
int log_tree_diff_flush(struct rev_info *opt)
		       struct rev_info *info)
	 */
			 "Content-Type: text/plain; "
			parse_object(the_repository, &obj->oid);
	struct commit *commit = lookup_commit(the_repository, &graft->oid);
	res->type = type;

		if (cmit_fmt_is_mail(ctx.fmt))
		return 0;
	ctx.color = opt->diffopt.use_color;
	while (obj->type == OBJ_TAG) {
	if (decoration_flags == DECORATE_SHORT_REFS)
			 " filename=\"%s\"\n\n",
				   status ? DIFF_WHITESPACE : DIFF_FRAGINFO);
void fmt_output_commit(struct strbuf *filename,
#include "gpg-interface.h"
}
 */

		return 0;
{
		else if (opt->first_parent_only) {
	struct commit_list *p = lookup_decoration(&opt->children, &commit->object);
		opt->missing_newline = 1;
		graph_show_oneline(opt->graph);
	return 0;
			fprintf(opt->diffopt.file, " (from %s)",
		diff_get_color(use_color, DIFF_COMMIT);
	if (opt->graph)
}
	    ctx.notes_message && *ctx.notes_message) {
		n = opt->ref_message_ids->nr;
	/* Root commit? */


#include "range-diff.h"
			    "merged tag '%s'\n", tag->tag);
			 mime_boundary_leader, opt->mime_boundary);
	if (opt->show_notes) {
		if (!obj->parsed)

	if (!tag)
	ctx.output_encoding = get_log_output_encoding();
		if (sigc.gpg_output)

			 "MIME-Version: 1.0\n"
{
			fprintf(opt->diffopt.file, "%s<%s>\n", (i > 0 ? "\t" : "References: "),
			 " boundary=\"%s%s\"\n"
		strbuf_reset(&subject_buffer);
};
	if (slot < 0)

		return decoration_colors[ix];
		return;
			return !opt->loginfo;

}
		       struct commit *commit,
			/*
		return 0;
		opt->diffopt.output_format = DIFF_FORMAT_NO_OUTPUT;

			log_tree_diff_flush(opt);
		decoration_loaded = 1;
		return 0;
			const struct commit *commit,
			 "This is a multi-part message in MIME "
			 "Content-Disposition: %s;"

 */
			 * so we don't need to worry about printing the
		 * never want the extra graph output before the entry
	int start_len = filename->len;
		fclose(opt->diffopt.file);
		type = DECORATION_REF_REMOTE;
{
	if (!obj)

static struct decoration name_decoration = { "object names" };
	struct strbuf payload = STRBUF_INIT;
	}
#define decorate_get_color_opt(o, ix) \
	if (cmit_fmt_is_mail(ctx.fmt) && opt->rdiff1) {
	if (opt->use_terminator && !commit_format_is_empty(opt->commit_format)) {
	ctx.rev = opt;
	showed_log = 0;
{

	if (!msgbuf.len || msgbuf.buf[msgbuf.len - 1] != '\n')

		eol = strchrnul(bol, '\n');
	}
		}


		decorate_get_color(use_color, DECORATION_NONE);
	}
	 * If use_terminator is set, we already handled any record termination
		i *= 10;
		 * can be added later if deemed desirable.

{
				return;
	}
	obj = parse_object(the_repository, oid);
		obj = ((struct tag *)obj)->tagged;

				msg = opt->diffopt.output_prefix(&opt->diffopt,
	if (parse_signed_commit(commit, &payload, &signature) <= 0)
}
		opts.file = opt->diffopt.file;
}
					 extra->len - payload_size, &sigc);
	struct commit *commit = log->commit, *parent = log->parent;
	strbuf_release(&subject);
	for (list = decoration; list; list = list->next)
			 * we are showing the patch with diffstat, but
		if (!parents)
		fputs(diff_get_color_opt(&opt->diffopt, DIFF_COMMIT), opt->diffopt.file);
	struct signature_check sigc = { 0 };
				fprintf(opt->diffopt.file, "---");
		memcpy(&diff_queued_diff, &dq, sizeof(diff_queued_diff));

	}
		if (opt->show_root_diff) {
	 * Print header line of header..
		fprintf(opt->diffopt.file, "log size %i\n", (int)msgbuf.len);
}
			     struct commit_extra_header *extra,
	const struct name_decoration *decoration;
{
	unsigned int i = 10, result = 1;
static int show_mergetag(struct rev_info *opt, struct commit *commit)
	ctx.date_mode = opt->date_mode;
	if (opt->from_ident.mail_begin && opt->from_ident.name_begin)
			graph_show_padding(opt->graph);
		DIFF_QUEUE_CLEAR(&diff_queued_diff);
	strbuf_init(&verify_message, 256);
			if (!opt->shown_dashes &&
	graph_show_oneline(opt->graph);
	if (opt->ref_message_ids && opt->ref_message_ids->nr > 0) {
	int nth;
	const char *x = opt->shown_dashes ? "\n" : "---\n";
		}
	pretty_print_commit(&ctx, commit, &msgbuf);
	[DECORATION_REF_HEAD]	= "HEAD",
	/* OK, do we have that ref in the list? */
			prefix = separator;
		struct strbuf notebuf = STRBUF_INIT;

			 opt->no_inline ? "attachment" : "inline",
 * Do we have HEAD in the output, and also the branch it points at?
		else if (opt->combine_merges)
			break;
		strbuf_release(&filename);
			      oid, "", &opt->diffopt);
		strbuf_addstr(sb, "Subject: ");
	for (;;) {
		graph_show_oneline(opt->graph);
			putc(' ', opt->diffopt.file);
{
		strbuf_addstr(&msgbuf, ctx.notes_message);
	strbuf_release(&sb);
	branch_name = resolve_ref_unsafe("HEAD", 0, NULL, &rru_flags);

	}

				 signature.len, &sigc);
			diff_root_tree_oid(oid, "", &opt->diffopt);
			strbuf_addstr(sb, decorate_get_color(use_color, decoration->type));
	while (decoration) {
	if (parse_tag_buffer(the_repository, tag, extra->value, extra->len))
{
	return (commit->parents
		if (opt->reflog_info) {
			 */
{

}
	 */
#include "repository.h"
		for_each_ref(add_ref_decoration, filter);

		*need_8bit_cte_p = -1; /* NEVER */
}
		}
			 extra_headers ? extra_headers : "",
static int which_parent(const struct object_id *oid, const struct commit *commit)
		if (opt->graph && !graph_is_commit_finished(opt->graph)) {


			}
#include "graph.h"
	struct tag *tag;
	struct pretty_print_context ctx = {0};

	opt->diffopt.close_file = 0;
		fputs(find_unique_abbrev(&commit->object.oid,
	else
void show_decorations(struct rev_info *opt, struct commit *commit)
	struct decoration_filter *filter = (struct decoration_filter *)cb_data;
		int raw;
static void show_children(struct rev_info *opt, struct commit *commit, int abbrev)
	diff_tree_combined_merge(commit, opt->dense_combined_merges, opt);
	[DECORATION_REF_TAG]	= "tag",
}
	else if ((nth = which_parent(&tag->tagged->oid, commit)) < 0)
			 */
	/*
			graph_show_oneline(opt->graph);

{
		if (!opt->missing_newline)
			 "\n"
	else
 * for showing the commit sha1, use the same check for --decorate
	GIT_COLOR_BOLD_CYAN,	/* REF_HEAD */
	if (parents && parents->next) {
	ctx.encode_email_headers = opt->encode_email_headers;
	const char *color_reset =
static const char *color_decorate_slots[] = {
	if (opt->sources) {
		if (opt->print_parents)
	}
		nth++;
		strbuf_addf(&subject_buffer,
		 * primarily intended for programmatic consumption, and we
		 *
		if (!opt->graph)
				    tag->tag, oid_to_hex(&tag->tagged->oid));
			show_parents(commit, abbrev_commit, opt->diffopt.file);
	const char *extra_headers = opt->extra_headers;

define_list_config_array(color_decorate_slots);
	*need_8bit_cte_p = 0; /* unknown */
		fprintf(opt->diffopt.file, "\n%s\n", opt->break_bar);
		 oideq(&tag->tagged->oid,
		}

	struct commit_list *parents;
					opt->diffopt.output_prefix_data);
			 * Generate merge log entry only for the first
	graph_show_commit_msg(opt->graph, opt->diffopt.file, &msgbuf);

			       opt->ref_message_ids->items[i].string);
		DIFF_QUEUE_CLEAR(&diff_queued_diff);
			     const char **extra_headers_p,
		showed_log |= !opt->loginfo;
	 * And then the pretty-printed message itself

	}

	if (filter && !ref_filter_match(refname,

			    digits_in_number(opt->total),
	}
		show_sig_lines(opt, status, "No signature\n");

			for_each_string_list_item(item, filter->include_ref_pattern) {
			/*
	/* More than one parent? */

		 * Pass minimum required diff-options to range-diff; others
		strbuf_addstr(sb, x);
		decoration_flags = flags;
	return 1;
			return 0;
		if (opt->children.name)
		if (opt->commit_format == CMIT_FMT_ONELINE) {
	show_sig_lines(opt, status, verify_message.buf);
			graph_show_padding(opt->graph);
	GIT_COLOR_BOLD_MAGENTA,	/* REF_STASH */
#include "log-tree.h"
void show_log(struct rev_info *opt)
			putc('\n', opt->diffopt.file);
 * Return true if we printed any log info messages
}
	log.parent = NULL;
	strbuf_release(&msgbuf);
			has_non_ascii(fmt_name(WANT_COMMITTER_IDENT));
{
	const char *suffix = info->patch_suffix;
static int is_common_merge(const struct commit *commit)

	if (close_file)
		diff_setup_done(&opts);

			break;
static char decoration_colors[][COLOR_MAXLEN] = {
	if (opt->track_linear && !opt->linear && !opt->reverse_output_stage)
			strbuf_addstr(&verify_message, "No signature\n");
	ctx.expand_tabs_in_log = opt->expand_tabs_in_log;
void add_name_decoration(enum decoration_type type, const char *name, struct object *obj)
		if (!read_replace_refs)
		strbuf_addstr(&verify_message, "malformed mergetag\n");

		 * separator.
	ctx.after_subject = extra_headers;
			 filename.buf,
	int abbrev_commit = opt->abbrev_commit ? opt->abbrev : the_hash_algo->hexsz;
	return showed_log;
				show_name(sb, current_and_HEAD);
void fmt_output_email_subject(struct strbuf *sb, struct rev_info *opt)
{
	[DECORATION_REF_REMOTE] = "remoteBranch",
	struct strbuf msgbuf = STRBUF_INIT;
	maybe_flush_or_die(opt->diffopt.file, "stdout");
	return NULL;
	struct object *obj;
	if (opt->track_linear && !opt->linear && opt->reverse_output_stage)
	if (opt->add_signoff)
		}
		strbuf_addf(sb, "Subject: [%s] ",
static unsigned int digits_in_number(unsigned int number)
	return lookup_decoration(&name_decoration, obj);
		parse_commit_or_die(parent);
			 * Otherwise, we show the three-dashes line if
		}

			const char *separator,
	fprintf(opt->diffopt.file, "From %s Mon Sep 17 00:00:00 2001\n", name);
}
}
static int decoration_flags;
	const struct commit_list *parent;
		next_commentary_block(opt, NULL);
		 * If the entry separator is not a newline, the output is
			diff_tree_oid(get_commit_tree_oid(parents->item),
			show_children(opt, commit, abbrev_commit);
		type = DECORATION_REF_STASH;
	}
 */


			strbuf_addstr(sb, color_reset);
		if (slot && *slot)

	strbuf_release(&signature);

	if (!parents) {
			 * and the log message, in which case we only
{
		return NULL;
		strbuf_addstr(sb, decoration->name);
		if ((opt->diffopt.output_format & ~DIFF_FORMAT_NO_OUTPUT) &&
	GIT_COLOR_RESET,
	 */
	shown = log_tree_diff(opt, commit, &log);
#include "color.h"
		show_interdiff(opt, 2);
	strbuf_addstr(filename, suffix);
	struct commit_list *p;

		}
		memcpy(&dq, &diff_queued_diff, sizeof(diff_queued_diff));
static int add_ref_decoration(const char *refname, const struct object_id *oid,
	if (!head)
			put_revision_mark(opt, commit);
}
	for (nth = 0, parent = commit->parents; parent; parent = parent->next) {
		show_decorations(opt, commit);
			     void *data)
{
			head = list;
			int pch = DIFF_FORMAT_DIFFSTAT | DIFF_FORMAT_PATCH;


		struct commit *parent = p->item;
 * The caller makes sure there is no funny color before calling.
 * log-tree.c uses DIFF_OPT_TST for determining whether to use color
}
			 "Content-Transfer-Encoding: 8bit\n"

		struct object_id original_oid;
	int rru_flags;

		struct diff_options opts;
	 * Set opt->missing_newline if msgbuf doesn't
	 */
	res->next = add_decoration(&name_decoration, obj, res);
	ctx.mailmap = opt->mailmap;
		return !opt->loginfo;
void load_ref_decorations(struct decoration_filter *filter, int flags)

		 * If entries are separated by a newline, the output
			 "charset=UTF-8; format=fixed\n"
void log_write_email_headers(struct rev_info *opt, struct commit *commit,
		&& !commit->parents->next->next);

		if (opt->numbered_files)
			    opt->subject_prefix,
		} else {
			parse_commit_or_die(parents->item);
static const char *decorate_get_color(int decorate_use_color, enum decoration_type ix)
	fputs(sb.buf, opt->diffopt.file);
			fputs("commit ", opt->diffopt.file);

}
				strbuf_addstr(sb, "tag: ");
			 "\n--%s%s\n"
#include "reflog-walk.h"

	diffcore_std(&opt->diffopt);
			}
			 "%s"
	return 0;

	payload_size = parse_signature(extra->value, extra->len);
	if (!decoration)
	return !opt->loginfo;
			putc('\n', opt->diffopt.file);
	opt->shown_one = 1;
			 * want a blank line after the commentary
			fprintf(opt->diffopt.file, "\t%s", *slot);
}
		if (oideq(&parent->item->object.oid, oid))

			/*
		/* Set up the log info for the next parent, if any.. */
			      int flags, void *cb_data)
		 * show HEAD->current where HEAD would have
	const struct name_decoration *current_and_HEAD;
		fprintf_ln(opt->diffopt.file, "%s", opt->rdiff_title);
			log_tree_diff_flush(opt);
			if (current_and_HEAD &&
	if ((ctx.fmt != CMIT_FMT_USERFORMAT) &&
#include "commit.h"
	}
		else
	add_name_decoration(type, refname, obj);
		ctx.graph_width = graph_width(opt->graph);
	int max_len = start_len + FORMAT_PATCH_NAME_MAX - (strlen(suffix) + 1);
			show_reflog_message(opt->reflog_info,


{
		fprintf(opt->diffopt.file, " %s", find_unique_abbrev(&p->item->object.oid, abbrev));

		struct commit *parent = parents->item;
		else
		result++;
		fprintf(opt->diffopt.file, "\n%s\n", opt->break_bar);
}
		&& commit->parents->next
		return;
		strbuf_setlen(filename, max_len);
	else if (starts_with(refname, "refs/remotes/"))
static void show_name(struct strbuf *sb, const struct name_decoration *decoration)
}
			putc('\n', opt->diffopt.file);
}
		int saved_fmt = opt->diffopt.output_format;
 */
	else if (is_common_merge(commit) &&
	ctx.preserve_subject = opt->preserve_subject;
 out:
		/* otherwise we couldn't verify, which is shown as bad */
			      filter->include_ref_pattern,
	if (opt->loginfo && !opt->no_commit_id) {
	reset = diff_get_color_opt(&opt->diffopt, DIFF_RESET);
	GIT_COLOR_BOLD_RED,	/* REF_REMOTE */
		if (opt->commit_format != CMIT_FMT_ONELINE)
	int showed_log;
	}
			    opt->nr, opt->total);
	if (opt->show_signature) {
			struct string_list_item *item;
				struct strbuf *msg = NULL;
				      oid, "", &opt->diffopt);
			next_commentary_block(opt, &msgbuf);
		static struct strbuf subject_buffer = STRBUF_INIT;

	/*
	graph_show_commit(opt->graph);
		if (obj)
			warning("invalid replace ref %s", refname);
			strbuf_addstr(sb, prefix);
		shown = 1;
	if (!decoration_loaded) {
			strbuf_addstr(&verify_message, sigc.gpg_output);
	}
		show_decorations(opt, commit);

		/* could have a good signature */
{
	if (opt->total > 0) {
		putc(opt->diffopt.line_termination, opt->diffopt.file);
			 * and not in --pretty=oneline format, we would want
		/*

		 * When both current and HEAD are there, only

		if (opt->ignore_merges)
		}
		if (opt->print_parents)
	}
	*extra_headers_p = extra_headers;
	if (max_len < filename->len)

		next_commentary_block(opt, NULL);
	}
}
		 */
	signature_check_clear(&sigc);

 *
	struct strbuf subject = STRBUF_INIT;


	if (want_color(decorate_use_color))
{
		show_mergetag(opt, commit);
		add_name_decoration(DECORATION_REF_TAG, refname, obj);
#include "cache.h"
			show_children(opt, commit, abbrev_commit);
	else if (!strcmp(refname, "refs/stash"))
			show_name(sb, decoration);
	if (ctx.need_8bit_cte >= 0 && opt->add_signoff)
		goto out;
		struct diff_queue_struct dq;

	opt->loginfo = NULL;
			const char *prefix,
	} else if (opt->total == 0 && opt->subject_prefix && *opt->subject_prefix) {
	struct signature_check sigc = { 0 };
		log->parent = parents->item;
			    (pch & opt->diffopt.output_format) == pch)
		append_signoff(&msgbuf, 0, APPEND_SIGNOFF_DEDUP);
	const char *color_commit =
	if (!opt->diff && !opt->diffopt.flags.exit_with_status)
	if (opt->mime_boundary && maybe_multipart) {
			return do_diff_combined(opt, commit);
	ctx.reflog_info = opt->reflog_info;
#include "config.h"
	status = -1;
		if (parent)
}
			if (opt->commit_format == CMIT_FMT_ONELINE)
		opt->loginfo = log;
		bol = (*eol) ? (eol + 1) : eol;
 * format_decorations_extended makes sure the same after return.
			 * When showing a verbose header (i.e. log message),
		graph_show_oneline(opt->graph);
	for (p = commit->parents; p ; p = p->next) {
			 filename.buf);
	const char *name = oid_to_hex(opt->zero_commit ?
	return 0;



	}
{
		graph_show_commit(opt->graph);
			 "Content-Type: text/x-patch;"
	}
 * If so, find that decoration entry for that current branch.
			 * diff/diffstat output for readability.
		fputs(find_unique_abbrev(&commit->object.oid, abbrev_commit), opt->diffopt.file);
static int show_one_mergetag(struct commit *commit,
	for (list = decoration; list; list = list->next)
	format_decorations(&sb, commit, opt->diffopt.use_color);
	if (opt->line_level_traverse)
	for ( ; p; p = p->next) {
					    opt->commit_format == CMIT_FMT_ONELINE,
	struct object_id *oid;
		    opt->commit_format != CMIT_FMT_ONELINE &&
	if (!opt->verbose_header) {
	/* Now resolve and find the matching current branch */

			break;
}
		ctx.need_8bit_cte =
	log.commit = commit;
	}
		       *eol ? "\n" : "");
		show_range_diff(opt->rdiff1, opt->rdiff2,

			show_parents(commit, abbrev_commit, opt->diffopt.file);
		opt->diffopt.output_format = saved_fmt;
		/*
/*
{
{
static int do_diff_combined(struct rev_info *opt, struct commit *commit)
	}
#include "line-log.h"
	strbuf_release(&payload);
	while (*bol) {
		       &commit->parents->next->item->object.oid))
			return 0;
	struct strbuf signature = STRBUF_INIT;
		raw = (opt->commit_format == CMIT_FMT_USERFORMAT);
		parents = parents->next;
	const char *color, *reset, *eol;
		if (decoration != current_and_HEAD) {
	return shown;
	strbuf_addstr(sb, color_commit);
	load_ref_decorations(NULL, DECORATE_SHORT_REFS);
			     int maybe_multipart)
			return nth;
			graph_show_remainder(opt->graph);
	}
 * Show the diff of a commit.
			      filter->exclude_ref_pattern))
		struct diff_queue_struct dq;
			 * we merged _in_.


	}
		ctx.from_ident = &opt->from_ident;
		if (get_oid_hex(refname + strlen(git_replace_ref_base),
			const char *subject,

static int add_graft_decoration(const struct commit_graft *graft, void *cb_data)

static const struct name_decoration *current_pointed_by_HEAD(const struct name_decoration *decoration)
}
	ctx.date_mode_explicit = opt->date_mode_explicit;
		diff_flush(&opt->diffopt);
	GIT_COLOR_BOLD_GREEN,	/* REF_LOCAL */
static int decoration_loaded;
			 * We may have shown three-dashes line early
			 * without (an extra) three-dashes line.

		 * with a newline, print the graph output before this
	oid = get_commit_tree_oid(commit);
				opt->creation_factor, 1, &opts, NULL);
				&original_oid)) {
		    !opt->missing_newline)
		fprintf(opt->diffopt.file, "%s%.*s%s%s", color, (int)(eol - bol), bol, reset,
		format_display_notes(&commit->object.oid, &notebuf,
		return config_error_nonbool(var);
#include "refs.h"
					&ctx.need_8bit_cte, 1);

			strbuf_addstr(sb, color_reset);
		strbuf_addf(&buffer,
{
	if (!shown && opt->loginfo && opt->always_show_header) {
	ctx.abbrev = opt->diffopt.abbrev;
	if (cmit_fmt_is_mail(ctx.fmt) && opt->idiff_oid1) {
}
	struct pretty_print_context ctx = {0};
	if (diff_queue_is_empty()) {
			struct rev_info *info)
		struct strbuf filename =  STRBUF_INIT;
void fmt_output_subject(struct strbuf *filename,
static int log_tree_diff(struct rev_info *opt, struct commit *commit, struct log_info *log)
		}
		extra_headers = subject_buffer.buf;
	[DECORATION_REF_LOCAL]	= "branch",
		return 0;
		signature_check_clear(&sigc);
	else
	return result;
		ctx.notes_message = strbuf_detach(&notebuf, NULL);
		if (!opt->graph)
		fprintf(file, " %s", find_unique_abbrev(&parent->object.oid, abbrev));
		diff_tree_oid(get_commit_tree_oid(parent),
				normalize_glob_ref(item, NULL, item->string);
	}
		opts.use_color = opt->diffopt.use_color;
		 * appeared, skipping the entry for current.
	 * end in a newline (including if it is empty)
static void next_commentary_block(struct rev_info *opt, struct strbuf *sb)
		strbuf_addf(filename, "v%d-", info->reroll_count);
#include "interdiff.h"
	}

	else if (!strcmp(refname, "HEAD"))
		if (!obj)
				strbuf_addstr(sb, decorate_get_color(use_color, current_and_HEAD->type));
	if (!commit)
#include "sequencer.h"
{
		return line_log_print(opt, commit);
	} else if (opt->commit_format != CMIT_FMT_USERFORMAT) {
		char **slot = revision_sources_peek(opt->sources, commit);
		show_log(opt);
		return NULL;
		if (opt->children.name)
	struct strbuf sb = STRBUF_INIT;
	opt->shown_dashes = 0;
	parse_commit_or_die(commit);
	if (!value)
{
			 * graph info here.
		strbuf_addstr(sb, prettify_refname(decoration->name));
#include "string-list.h"
	int shown, close_file = opt->diffopt.close_file;
	[DECORATION_GRAFTED]	= "grafted",
		status = check_signature(extra->value, payload_size,
	 * Otherwise, add a diffopt.line_termination character before all
		putc(opt->diffopt.line_termination, opt->diffopt.file);
int log_tree_commit(struct rev_info *opt, struct commit *commit)

		show_log(opt);
		return -1; /* error message already given */

			 " name=\"%s\"\n"

			strbuf_addstr(sb, color_commit);
	return "";
	opt->shown_dashes = 1;
	int status, nth;
	enum decoration_type type = DECORATION_NONE;
	[DECORATION_REF_STASH]	= "stash",
		show_sig_lines(opt, status, sigc.gpg_output);
		decoration = decoration->next;
		memcpy(&diff_queued_diff, &dq, sizeof(diff_queued_diff));

		strbuf_addf(&verify_message,
		fputs(diff_get_color_opt(&opt->diffopt, DIFF_RESET), opt->diffopt.file);
	ctx.fmt = opt->commit_format;
		type = DECORATION_REF_TAG;
			 "format.\n"
	diff_flush(&opt->diffopt);
		ctx.rev = opt;
	if (starts_with(refname, git_replace_ref_base)) {
	if (opt->show_log_size) {
			     int *need_8bit_cte_p,
	}
		 * newline.  Otherwise it will end up as a completely blank
	struct rev_info *opt = (struct rev_info *)data;
			if (decoration->type == DECORATION_REF_TAG)
	GIT_COLOR_BOLD_YELLOW,	/* REF_TAG */
}
			 */

	struct log_info log;
}
	if (!starts_with(branch_name, "refs/"))
		    !strcmp(branch_name, list->name)) {



	 * entries but the first.  (IOW, as a separator between entries)

}
		static struct strbuf buffer = STRBUF_INIT;
			 "Content-Transfer-Encoding: 8bit\n\n",

		head_ref(add_ref_decoration, filter);
			fmt_output_commit(&filename, commit, opt);

	 * at the end of the last record.
static void show_signature(struct rev_info *opt, struct commit *commit)

					    &opt->date_mode,

	/* First find HEAD */
				strbuf_addstr(sb, color_reset);
/*
static void show_parents(struct commit *commit, int abbrev, FILE *file)
		log->parent = parents->item;
		if ((list->type == DECORATION_REF_LOCAL) &&
	FLEX_ALLOC_STR(res, name, name);
		return 0;
			return list;
	/*
			for_each_string_list_item(item, filter->exclude_ref_pattern) {
		    !commit_format_is_empty(opt->commit_format)) {
		return NULL;
					 extra->value + payload_size,
#include "tag.h"
}
		 */
		log_tree_diff_flush(opt);

			 * in that case, there is no extra blank line
			 * setup_revisions() ensures that opt->reflog_info
			    decoration->type == DECORATION_REF_HEAD) {

			 */
#include "help.h"
	int slot = LOOKUP_CONFIG(color_decorate_slots, slot_name);
		strbuf_addf(&verify_message, "tag %s names a non-parent %s\n",
	add_name_decoration(DECORATION_GRAFTED, "grafted", &commit->object);

			}
{
	const char *branch_name = NULL;
	/*
		 */
	hash_object_file(the_hash_algo, extra->value, extra->len,
			put_revision_mark(opt, commit);
	return color_parse(value, decoration_colors[slot]);
		opt->diffopt.stat_sep = buffer.buf;
		type = DECORATION_REF_HEAD;
int parse_decorate_color_config(const char *var, const char *slot_name, const char *value)
			}
	opt->loginfo = NULL;
	else if (starts_with(refname, "refs/tags/"))
			 * an extra newline between the end of log and the
		for (i = 0; i < n; i++)
	int status;
			 "Content-Type: multipart/mixed;"
	/*
	decoration = get_name_decoration(&commit->object);
			const char *suffix)
	return for_each_mergetag(show_one_mergetag, commit, opt);
