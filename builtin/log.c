	while (list) {
	}
	}
{
		return git_config_string(&signature, var, value);
	char *cover_from_description_arg = NULL;
	if (!strncasecmp(value, "to: ", 4)) {
		thread = git_config_bool(var, value) ? THREAD_SHALLOW : THREAD_UNSET;
	return branch;
				  output_directory);
{
static int rfc_callback(const struct option *opt, const char *arg, int unset)
		opts.use_color = rev->diffopt.use_color;
{
		string_list_append(&extra_cc, arg);
	int i = 0, rev_nr = 0;
static int numbered_cmdline_opt = 0;
				 * For shallow threading:
	if (base_commit) {

	}
			enable_default_display_notes(&notes_opt, &show_notes);
	else if (!strcmp(value, "auto"))
			 subject_sb.len > COVER_FROM_AUTO_MAX_SUBJECT_LEN))
			 * We decremented max_count in get_revision,
	strbuf_addf(&buf, "%s.%"PRItime".git.%s", base,
	char *branch_name = NULL;
			break;
			check_head = 1;
	free(objects);

		creation_factor = RANGE_DIFF_CREATION_FACTOR_DEFAULT;
{
		if (!isspace(ch) && (ch != '>'))
	if (!strcmp(var, "format.cc")) {
	return git_diff_ui_config(var, value, cb);
static void early_output(int signal)

static int parse_decoration_style(const char *value)
		if (shown) {
{
			if (!base_list || base_list->next)
	if (!strcmp(var, "format.encodeemailheaders")) {
	else if (commit)
		argv_array_clear(&other_arg);
{

static int keep_callback(const struct option *opt, const char *arg, int unset)
		print_signature(rev.diffopt.file);
		    !rev->notes_opt.extra_notes_refs.nr)) {
				putchar('\n');
	default:
			    oid_to_hex(&origin->object.oid), head_oid);
			if (!o)
	 * Get merge base through pair-wise computations
			config_cover_letter = COVER_AUTO;
	}
	 * when you add new options.
	return 0;
	flags2 = o2->flags;
		if (decoration_style < 0)
	if (!strcmp(var, "log.showroot")) {
	int n = 0;
				 * a reply to the previous one, no

	 * retain that state information if replacing rev->diffopt in this loop
	static struct string_list decorate_refs_include = STRING_LIST_INIT_NODUP;
{
				die(_("failed to resolve '%s' as a valid ref"), upstream);

	pp.date_mode = rev->date_mode;
			 struct rev_info *rev, struct setup_revision_opt *opt)
		rev.ref_message_ids = xcalloc(1, sizeof(struct string_list));
	pp.rev = rev;
		die(_("revision walk setup failed"));
}
		if (mkdir(output_directory, 0777) < 0 && errno != EEXIST)
static int decoration_given;


	else if (arg)
{
	return 0;
}
	else if (!strcmp(value, "short"))
{
		return 0;
		numbered = git_config_bool(var, value);
	sort_in_topological_order(&list, revs->sort_order);
			struct commit_list *merge_base;
		rev.rdiff2 = rdiff2.buf;
};
		read_mailmap(rev->mailmap, NULL);
	early_output_timer.it_value.tv_sec = 0;
			 struct rev_info *rev, struct setup_revision_opt *opt)
		load_display_notes(&rev.notes_opt);
	stop_progress(&progress);
	git_config(git_log_config, NULL);
		die(_("not a range"));
		branch_name = find_branch_name(rev);


		argv_array_push(arg, "--notes");
static void log_show_early(struct rev_info *revs, struct commit_list *list)
		if (oideq(&o[0].item->oid, &o[1].item->oid))
	z = NULL;
	rev.subject_prefix = fmt_patch_subject_prefix;
		fprintf_ln(rev->diffopt.file, "%s", rev->idiff_title);
	else if (!strcmp(arg, "message"))
	}
	if (output_directory) {

{

	return numbered_callback(opt, arg, 1);
		if (value && !strcasecmp(value, "deep")) {
	rev.commit_format = CMIT_FMT_ONELINE;
	log.file = rev->diffopt.file;

int cmd_log_reflog(int argc, const char **argv, const char *prefix)
{
	rev.max_parents = 1;
	char ch;
	if (!strcmp(var, "log.date"))

		return DECORATE_FULL_REFS;

	setitimer(ITIMER_REAL, &early_output_timer, NULL);
	rev.diff = 1;
		return -1;
static const char * const builtin_log_usage[] = {

		putc('\n', file);
		struct argv_array other_arg = ARGV_ARRAY_INIT;
		return 02;
 * (C) Copyright 2006 Linus Torvalds
			fprintf(rev.diffopt.file, "%stree %s%s\n\n",
	NULL

	if ((rev->diffopt.pickaxe_opts & DIFF_PICKAXE_KINDS_MASK) ||
	s_r_opt.def = "HEAD";

	fprintf(rev->diffopt.file, _("Final output: %d %s\n"), nr, stage);
	if (!strcmp(value, "full"))
		if (rev.max_count < 0 && !rev.show_root_diff) {
	}
	if (!strcmp(var, "format.signoff")) {

}
	}


		if (!base)
	if (creation_factor < 0)

				 * reply to the one before.
		}
		for_each_string_list(&rev->notes_opt.extra_notes_refs, get_notes_refs, arg);
		strbuf_addstr(&buf, extra_cc.items[i].string);
}
		return stream_blob_to_fd(1, oid, NULL, 0);
	return prefix_filename(prefix, output_directory);
		return DECORATE_SHORT_REFS;
		break;
		{ OPTION_CALLBACK, 0, "from", &from, N_("ident"),
	data->rev->line_level_traverse = 1;
	revs.topo_order = 1;

			if (!merge_base || merge_base->next)
static void cmd_log_init(int argc, const char **argv, const char *prefix,
	rev->abbrev_commit = default_abbrev_commit;
			strbuf_addch(&buf, ',');
		else
	const struct object_id *tip_oid;

	if (unset)
	if (!strcmp(var, "format.notes")) {
	}

		{ OPTION_CALLBACK, 'n', "numbered", &numbered, NULL,
		; /* --no-signature inhibits all signatures */
	 * Please update _git_log() in git-completion.bash when you
		rev.creation_factor = creation_factor;

		body = description_sb.buf;
			die(_("failed to get upstream, if you want to record base commit automatically,\n"

	};
	if (keep_subject && subject_prefix)
	free(rev);
}
	fprintf(file, "\nbase-commit: %s\n", oid_to_hex(&bases->base_commit));
					     _("Interdiff against v%d:"));
	prepare_cover_text(&pp, branch_name, &sb, encoding, need_8bit_cte);
				 * to the cover letter.  The cover
			 struct rev_info *rev, int quiet)
		rev->diffopt.flags.default_follow_renames = 1;
		return parse_decorate_color_config(var, slot_name, value);
	case 0:
		 * get_revision() to do the usual traversal.
				putchar('\n');
			strbuf_addstr(&buf, "    ");

	strbuf_release(&sb);
	rev.expand_tabs_in_log_default = 0;
		shown = log_tree_commit(&rev, commit);
		strbuf_addstr(sb, generic);
				else
			rev[i] = merge_base->item;
{
	diff_tree_oid(get_commit_tree_oid(origin),
	const char *a, *z, *m;
	add_pending_object(&revs, &base->object, "base");
		fmt_output_commit(&filename, commit, rev);
	cmd_log_init_finish(argc, argv, prefix, rev, opt);
		read_branch_desc(&description_sb, branch_name);
		return 0;
			return 0;
	} else {
		OPT_STRING_LIST(0, "decorate-refs", &decorate_refs_include,
	if (rev->pending.nr != 2)

			ref = resolve_ref_unsafe("HEAD", RESOLVE_REF_READING,
	oidclr(&bases->base_commit);
/*
		if (close_file)
	memset(&opt, 0, sizeof(opt));
		case commit_show:
			 */
	int just_numbers = 0;
		/*
		case SCLD_EXISTS:
		else
static int use_mailmap_config = 1;
	if (!use_patch_format &&
{
	struct strbuf rdiff2 = STRBUF_INIT;
	/* Show the prerequisite patches */
	return 0;
	int boundary_count = 0;
	free_patch_ids(&ids);
		progress = start_delayed_progress(_("Generating patches"), total);
	const char *slot_name;
			add_pending_object(revs, &commit->object, arg);
	if (!strcmp(var, "format.suffix"))
	struct commit *origin = NULL;
		goto done;
	if (!rev->diffopt.flags.textconv_set_via_cmdline ||
		*thread = THREAD_DEEP;
	rev.verbose_header = 1;
	if (skip_prefix(var, "color.decorate.", &slot_name))

		if (value && !strcasecmp(value, "shallow")) {
		char sign = '+';
	BUG_ON_OPT_NEG(unset);
		limit = argv[2];
}
	else if (arg)
	struct setup_revision_opt opt;

	repo_init_revisions(the_repository, &check_rev, rev->prefix);
	struct rev_info rev;
	memset(&opt, 0, sizeof(opt));
{
		{ OPTION_CALLBACK, 0, "to", NULL, N_("email"), N_("add To: header"),
static int subject_prefix = 0;
static int show_tree_object(const struct object_id *oid,
			    N_("use [PATCH] even with multiple patches"),
		}
}
		die(_("cover letter needs email format"));
	} else {
	pp.print_email_subject = 1;
	if (!strcmp(var, "format.attach")) {
	if (rdiff_prev) {
	 */
				 * With --in-reply-to but no
static const char *diff_title(struct strbuf *sb, int reroll_count,

	 * For --check and --exit-code, the exit code is based on CHECK_FAILED
		/* interdiff/range-diff in cover-letter; omit from patches */
		    (timestamp_t) time(NULL),
	if (extra_to.nr)
			ret = cmd_log_walk(&rev);
static void prepare_bases(struct base_tree_info *bases,
	sigemptyset(&sa.sa_mask);
		if (commit->object.flags & BOUNDARY) {
		goto do_pp;
					diff_get_color_opt(&rev.diffopt, DIFF_COMMIT),
	}

	if (numbered && keep_subject)
			continue;
	pp.date_mode.type = DATE_RFC2822;
			      1, PARSE_OPT_NONEG),
			   N_("show changes against <refspec> in cover letter or single patch")),
	rev.encode_email_headers = default_encode_email_headers;
	a = m;
	COVER_FROM_AUTO
	}
	if (rev.pending.nr == 1) {
	m = msg_id;
	cmd_log_init_defaults(&rev);
			    N_("Use [<prefix>] instead of [PATCH]"),

#include "config.h"
	struct line_opt_callback_data *data = option->value;
					" remote branch, please"
static void finish_early_output(struct rev_info *rev)
			break;
}
		 * "log --pretty=raw" is special; ignore UI oriented
	if (rev->diffopt.output_format & DIFF_FORMAT_CHECKDIFF &&
	 * and store it in rev[0].
		start_number--;
		OPT_END()
}
 */
			    N_("set From address to <ident> (or committer ident if absent)"),
	 */
}
	struct rev_info *rev;
			    0, cc_callback },
		/* FALLTHROUGH */
			fclose(revs->diffopt.file);
	else
	}
		bases->nr_patch_id++;
				       mime_boundary_leader,
		decoration_style = 0;
	enum thread_level *thread = (enum thread_level *)opt->value;
	BUG_ON_OPT_NEG(unset);
	int i;
	struct object_context obj_context;
	/*
			fprintf(rev.diffopt.file, "%stag %s%s\n",
{
	return 0;
		set_shared_repository(0);
	int no_binary_diff = 0;
	    skip_prefix(full_ref, "refs/heads/", &v) &&
	struct commit *commit;
	}

				    struct commit *head)
		return -1;
	strbuf_release(&rdiff1);
	rev.diffopt.flags.recursive = 1;
	if (reroll_count <= 0)
}
	argc = parse_options(argc, argv, prefix,
	struct decoration_filter decoration_filter = {&decorate_refs_include,
struct base_tree_info {

	diff_flush(&opts);
				 * letter is a reply to the
	unsigned flags1, flags2;
	memset(&match_all, 0, sizeof(match_all));
		}
	free(bases->patch_id);

		return prefix;
		die(_("--subject-prefix/--rfc and -k are mutually exclusive"));
	}

	argc = parse_options(argc, argv, prefix, builtin_format_patch_options,
		signature = strbuf_detach(&buf, NULL);
 */
static void setup_early_output(void)
	*(int *)opt->value = numbered_cmdline_opt = unset ? 0 : 1;
		if (config_cover_letter == COVER_AUTO)
		return 0;
		strbuf_addf(&sprefix, "%s v%d",
					     _("Range-diff:"),
		base = lookup_commit_reference_by_name(base_commit);
{

		return;
	rev->diffopt.stat_graph_width = -1; /* respect statGraphWidth config */
	COVER_AUTO
		rev.rdiff1 = NULL;
	struct diff_options opts;
		{ OPTION_CALLBACK, 'o', "output-directory", &output_directory,
{
	line_cb.prefix = prefix;
	diffopt.flags.recursive = 1;
			die(_("--interdiff requires --cover-letter or single patch"));

		init_revision_sources(&revision_sources);
	COVER_FROM_MESSAGE,
#include "interdiff.h"
}
	 */
		if (rev->cmdline.rev[i].flags & UNINTERESTING)
	/*
		decoration_style = parse_decoration_style(value);
		 * configuration variables such as decoration.
			strbuf_addstr(&buf, "    ");


};
		switch (o->type) {
			    N_("add email header"), 0, header_callback },
#include "revision.h"
	 */
			return config_error_nonbool(var);
		if (!cover_letter && total != 1)
			      N_("show patch format instead of default (patch + stat)"),

	string_list_append(&data->args, arg);
		return -1;
	return 0;
	rev.patch_suffix = fmt_patch_suffix;

static int git_log_config(const char *var, const char *value, void *cb)
		commit = list[nr];
	memset(&bases, 0, sizeof(bases));
			return 0;
	if (positive < 0)
				 * mail but the cover letter a reply
		numbered = 0;
					diff_get_color_opt(&rev.diffopt, DIFF_RESET));
	const char *encoding = "UTF-8";
	if (!strcmp(var, "format.outputdirectory"))
static void get_notes_args(struct argv_array *arg, struct rev_info *rev)
static int do_signoff;
{
	return isatty(1) || pager_in_use();
		output_directory = config_output_directory;
		return 0;
static const char * const builtin_format_patch_usage[] = {
		rev->show_notes = 1;
		item = string_list_append(&extra_hdr, value);
		}
	if (rev->early_output)
	git_config(git_log_config, NULL);
	add_pending_object(&check_rev, o1, "o1");
	if (*dir)
			die(_("could not create leading directories "

	static struct revision_sources revision_sources;
	return ret;
	free(*from);
	struct strbuf filename = STRBUF_INIT;
				branch_name = xstrdup(v);
	if (limit && add_pending_commit(limit, &revs, UNINTERESTING))
static void add_header(const char *value)
	COVER_OFF,
		default_abbrev_commit = git_config_bool(var, value);
		rev.subject_prefix = strbuf_detach(&sprefix, NULL);
			    PARSE_OPT_NOARG | PARSE_OPT_NONEG, keep_callback },
	}
		if (thread)

	 * do.

	init_patch_ids(the_repository, ids);
{

			 * but we didn't actually show the commit.
	if (!strcmp(var, "format.subjectprefix"))
		if (i)
{
		default_show_root = git_config_bool(var, value);
enum cover_from_description {
		int shown;
	if (!rev->diffopt.output_format)
int cmd_log(int argc, const char **argv, const char *prefix)
		struct strbuf *base,
		die(_("revision walk setup failed"));
	if (rev->numbered_files)
	strbuf_release(&filename);
		strbuf_addstr(&buf, extra_to.items[i].string);
	ALLOC_ARRAY(rev, total);
		default_follow = git_config_bool(var, value);
			     obj_context.mode, &oidc, 1, &buf, &size)) {

		rev->mime_boundary = NULL;
static int keep_subject = 0;
	if (ignore_if_in_upstream) {
	free(obj_context.path);
done:
	else if (!strcmp(arg, "none"))
		argv_array_push(arg, "--no-notes");
	rev.commit_format = CMIT_FMT_EMAIL;

	free(branch_name);
				      struct commit **list,
	if (++z == m)
do_pp:
		if (thread) {
	diffcore_std(&opts);
			if (oideq(&o[0].item->oid, &o[1].item->oid))
		       find_unique_abbrev(&commit->object.oid, abbrev),
				fclose(revs->diffopt.file);
	if (rev->pretty_given && rev->commit_format == CMIT_FMT_RAW) {
{

			log_tree_commit(revs, commit);

	o1->flags = flags1;
		body = format_subject(&subject_sb, description_sb.buf, " ");
static int decorate_callback(const struct option *opt, const char *arg, int unset)
			; /* do nothing */
	if (rev->line_level_traverse)
		strbuf_addch(&buf, '\n');

static int inline_callback(const struct option *opt, const char *arg, int unset)
		OPT_STRING(0, "suffix", &fmt_patch_suffix, N_("sfx"),
		load_ref_decorations(&decoration_filter, decoration_style);
static struct display_notes_opt notes_opt;
		return 0;
		; /* non-default signature already set */
	}
	char *full_ref, *branch = NULL;
			auto_number = 1;

	}
static int numbered_callback(const struct option *opt, const char *arg,
			add_head_to_pending(&rev);
	}
		die(_("not a valid object name %s"), obj_name);
		string_list_append(rev.ref_message_ids, msgid);
	rev->no_inline = unset ? 0 : 1;
	rev.diff = 1;
			 N_("don't output binary diffs")),
	userformat_find_requirements(NULL, &w);
static void cmd_log_init_finish(int argc, const char **argv, const char *prefix,
			   N_("add prerequisite tree info to the patch series")),
	string_list_clear(&extra_hdr, 0);
	struct strbuf idiff_title = STRBUF_INIT;
	for (i = 0; i < total; i++) {
	objects = rev.pending.objects;
	if (!signature) {
			die_errno(_("unable to read signature file '%s'"), signature_file);
	int creation_factor = -1;
	}
static int base_auto;
	    rev->diffopt.filter || rev->diffopt.flags.follow_renames)
		case OBJ_COMMIT:
	if ((flags1 & UNINTERESTING) == (flags2 & UNINTERESTING))
	rev.boundary = 1;
	struct object_id oid;
	if (!rev.diffopt.output_format)
		free_patch_ids(&ids);
			/*
			die(_("--range-diff requires --cover-letter or single patch"));


	free(buf);
}
	return 0;
static enum cover_from_description cover_from_description_mode = COVER_FROM_MESSAGE;
	}
	if (rev->shown_one) {
	shortlog_output(&log);
	else if (arg)
static int auto_number = 1;
		diff_setup(&opts);

	cmd_log_init_defaults(rev);
		OPT_STRING(0, "cover-from-description", &cover_from_description_arg,
{
		 * patches and this flag is used by log-tree code
			rev[i] = rev[2 * i];
		}
static enum thread_level thread;
					free(rev.message_id);
		add_commit_patch_id(commit, ids);
		}
		current_branch = branch_get(NULL);

{
}
			      struct commit *origin,
				  origin, nr, list, branch_name, quiet);
		total++;
	return 0;
		if (output_directory)
int cmd_cherry(int argc, const char **argv, const char *prefix)
		die(_("--name-status does not make sense"));
	 */
	if (!obj_context.path ||
	BUG_ON_OPT_ARG(arg);
			positive = i;

#include "commit-reach.h"
	/*
		}
			    N_("use [PATCH n/m] even with a single patch"),
		}
#include "remote.h"
	if (prepare_revision_walk(&rev))

{
	}
		  PARSE_OPT_OPTARG, decorate_callback},
		rev.nr = total - nr + (start_number - 1);

	/* Show the base commit */
static const char *output_directory = NULL;
		rev.diffopt.output_format = DIFF_FORMAT_DIFFSTAT | DIFF_FORMAT_SUMMARY;
#define COVER_FROM_AUTO_MAX_SUBJECT_LEN 100
		OPT__ABBREV(&abbrev),
static int default_encode_email_headers = 1;
	const char *prefix;
				       rev.mime_boundary);
	repo_init_revisions(the_repository, &rev, prefix);
			    PARSE_OPT_OPTARG, from_callback },
		numbered = 1;
	if (!strcmp(var, "log.mailmap")) {
	struct rev_info rev;
	strbuf_release(&subject_sb);
	struct string_list_item *item;
}
			cover_from_description_mode == COVER_FROM_AUTO)
	line_cb.rev = rev;
	sa.sa_handler = early_output;
		const char *name = objects[i].name;
		return 0;
	char *base_commit = NULL;
		if (!strcmp(rev.pending.objects[0].name, "HEAD"))

	return 0;
	if (prepare_revision_walk(&revs))
	int i;
		strbuf_addf(r2, "%s..%s", prev, head_oid);
	if (grep_config(var, value, cb) < 0)

	unsigned long size;
		if (saved_nrl < rev->diffopt.needed_rename_limit)
		return cmd_log_walk(&rev);
	BUG_ON_OPT_ARG(arg);
		die(_("revision walk setup failed"));
	info->message_id = strbuf_detach(&buf, NULL);
		rev->mime_boundary = arg;
				   commit);
		die(_("unknown commit %s"), upstream);
	init_log_defaults();
	repo_diff_setup(the_repository, &diffopt);
	argv_array_pushf(arg, "--notes=%s", item->string);
	int quiet = 0;
	/*
	fprintf(rev->diffopt.file, "%s", out.buf);
	struct commit **rev;
	while (rev_nr > 1) {
			  struct commit *base,
			      int unset)


}
	o2->flags ^= UNINTERESTING;
	c2 = lookup_commit_reference(the_repository, &o2->oid);
	revs.max_parents = 1;
		*from = xstrdup(git_committer_info(IDENT_NO_DATE));
				 *
	for (i = 0; i < extra_cc.nr; i++) {
		if (rev.pending.nr == 2) {
}
	struct rev_info revs;
	int i, count, ret = 0;
			free_commit_buffer(the_repository->parsed_objects,
		error_errno(_("cannot open patch file %s"), filename.buf);
	if (!strcmp(var, "format.signature"))
#include "line-log.h"
};
		rev->mime_boundary = NULL;
			struct commit_list *base_list;
};
			  int total)
	const char *head = "HEAD";
		OPT_INTEGER(0, "creation-factor", &creation_factor,
				/*
		if (!rev->first_parent_only && !rev->combine_merges) {
	extra_cc.strdup_strings = 1;
		break;
		default:
	}
	rev.numbered_files = just_numbers;
		set_shared_repository(saved);
		return stream_blob_to_fd(1, oid, NULL, 0);
		rev.rdiff_title = diff_title(&rdiff_title, reroll_count,
}
	if (rev->rdiff1) {
	while ((commit = get_revision(&revs)) != NULL) {
	o2->flags = flags2;
	}
	else
	strbuf_release(&rdiff_title);
		OPT_CALLBACK('L', NULL, &line_cb, "n,m:file",
	rev.always_show_header = 1;
		outdir_offset = 2;
	COVER_FROM_SUBJECT,
	setitimer(ITIMER_REAL, &early_output_timer, NULL);

	int i;
		if (has_commit_patch_id(commit, &ids))
			fclose(rev.diffopt.file);

	rev.zero_commit = zero_commit;
	while ((commit = get_revision(&rev)) != NULL) {
			putchar(rev->diffopt.line_termination);
		case commit_ignore:
	while ((commit = get_revision(rev)) != NULL) {
		if (i)
		rev->always_show_header = 0;
		OPT__VERBOSE(&verbose, N_("be verbose")),
	pp.fmt = rev->commit_format;
		die(_("-n and -k are mutually exclusive"));

		OPT_BOOL('s', "signoff", &do_signoff, N_("add Signed-off-by:")),
		rev->ignore_merges = 0;
		string_list_append(&extra_to, value);
		strbuf_addstr(&buf, "To: ");
	}
};
{
			     N_("Process line range n,m in file, counting from 1"),
int cmd_whatchanged(int argc, const char **argv, const char *prefix)
		rev.idiff_oid1 = NULL;
		OPT_FILENAME(0, "signature-file", &signature_file,
	return subject_prefix_callback(opt, "RFC PATCH", unset);
{
#include "patch-ids.h"

	if (git_gpg_config(var, value, cb) < 0)
static int header_callback(const struct option *opt, const char *arg, int unset)
		OPT_BOOL(0, "use-mailmap", &mailmap, N_("Use mail map file")),
	early_output_timer.it_value.tv_sec = 0;
	log.in1 = 2;

	if (!strcmp(var, "format.to")) {
		if (split_ident_line(&rev.from_ident, from, strlen(from)))
{
		switch (safe_create_leading_directories_const(output_directory)) {
	rev->no_inline = 0;
		switch (simplify_commit(revs, commit)) {
		die(_("invalid --decorate option: %s"), arg);
	struct strbuf buf = STRBUF_INIT;
	return 0;
	struct oid_array idiff_prev = OID_ARRAY_INIT;
	} else {
				if (thread == THREAD_SHALLOW
	struct commit *commit;
		return 0;
	if (!verbose) {

	 * Set up the signal handler, minimally intrusively:
	THREAD_UNSET,
	struct setup_revision_opt s_r_opt;
			return NULL;
{
static int cmd_log_walk(struct rev_info *rev)
			/* There should be one and only one merge base. */
		 * not want the extra blank line.
		offset = new_offset;
	return cmd_log_walk(&rev);
	fprintf(file, "-- \n%s", signature);


	decoration_given = 1;
		config_cover_letter = git_config_bool(var, value) ? COVER_ON : COVER_OFF;
	if (!use_stdout &&
#include "range-diff.h"
	 * and stuff them in bases structure.
		free(obj_context.path);
	if (!strstr(prev, "..")) {
				break;
	 * possibly a valid SHA1.
	}
	rev.diffopt.output_format |= DIFF_FORMAT_PATCH;
	if (quiet)
			    PARSE_OPT_OPTARG, thread_callback },
	 * and it would conflict with --keep-subject (-k) from the
}
/*
			sign = '-';
		/*
			    PARSE_OPT_OPTARG | PARSE_OPT_NONEG,
	int use_patch_format = 0;
	struct commit *base = NULL;
			base_list = get_merge_bases_many(commit, total, list);
static const char *fmt_patch_subject_prefix = "PATCH";
	 * tenth of a second, don't even bother doing the
	}
			thread = THREAD_DEEP;
		      get_commit_tree_oid(head),
	}

				ret = error(_("could not read object %s"),
		upstream = argv[0];
		OPT_STRING(0, "in-reply-to", &in_reply_to, N_("message-id"),
	if (numbered)
	case 3:
	fprintf(file, "%s%s\n", pathname, S_ISDIR(mode) ? "/" : "");

			     int unset)
		if (base == list[i])
#include "run-command.h"
			    PARSE_OPT_NONEG, subject_prefix_callback },
		if (!value)

	}
		ALLOC_GROW(bases->patch_id, bases->nr_patch_id + 1, bases->alloc_patch_id);
	struct commit *head = list[0];
		string_list_clear(&extra_cc, 0);
	if (!strcmp(var, "format.pretty"))
		return a;
			continue;
	/*
		output_directory = set_outdir(prefix, output_directory);
static const char *set_outdir(const char *prefix, const char *output_directory)
		return 0;
}
	if (cover_from_description_mode == COVER_FROM_SUBJECT ||
	else /* RFC may be v0, so allow -v1 to diff against v0 */
		return -1;
	if (base_auto)
		setup_pager();


}
	}
			 */
		die(_("unknown commit %s"), head);
		 * "format-patch --root HEAD".  The user wants
}
		 * applying adjust_shared_perm in s-c-l-d.
		OPT_BOOL(0, "zero-commit", &zero_commit,
		rev.diffopt.stat_width = MAIL_DEFAULT_WRAP;
	 * using sigatomic_t - trying to avoid unnecessary
			     builtin_format_patch_usage,
		/* nothing to do */
	if (!rev->diffopt.output_format && rev->combine_merges)

		return git_config_string(&fmt_pretty, var, value);
		if (filename.len >=
		}
static const char *signature_file;
{
			       const char *branch_name,
			    N_("print patches to standard out")),
			/*
	memset(&sa, 0, sizeof(sa));
		unsigned int flags = commit->object.flags;
	git_config(git_format_config, NULL);
}
	pp.fmt = CMIT_FMT_EMAIL;
	if (source || w.source) {
{
	}
		 * Pass minimum required diff-options to range-diff; others
{
	if (!strcmp(var, "format.thread")) {
	int saved_nrl = 0;
			     log_line_range_callback),
		rev->mime_boundary = git_version_string;
{
		list = list->next;

	((struct rev_info *)opt->value)->subject_prefix = arg;
			rev.shown_one = 1;
		{ OPTION_CALLBACK, 0, "subject-prefix", &rev, N_("prefix"),
	}

		finish_early_output(rev);
	/*
			}
			break;
	return diff_result_code(&rev->diffopt, 0);
			 N_("show progress while generating patches")),
}

		OPT_BOOL(0, "stdout", &use_stdout,
			struct object_array_entry *o = rev.pending.objects;
	repo_init_revisions(the_repository, &rev, prefix);
#include "mailmap.h"
	BUG_ON_OPT_NEG(unset);
	N_("git cherry [-v] [<upstream> [<head> [<limit>]]]"),
			return;
	struct setup_revision_opt opt;
				 &oidc, &obj_context))
	if (!arg)
					   commit);
static int to_callback(const struct option *opt, const char *arg, int unset)
	struct commit *commit;
	if (numbered && keep_subject && !numbered_cmdline_opt)


static int estimate_commit_count(struct commit_list *list)
			    int unset)
	init_log_defaults();
	while (len && value[len - 1] == '\n')
	}
			continue;

		OPT_INTEGER(0, "start-number", &start_number,
					     _("Range-diff against v%d:"));
	opt.def = "HEAD";
	}

	if (!in_merge_bases(base, rev[0]))
static void show_early_header(struct rev_info *rev, const char *stage, int nr)


#include "cache.h"

		if (!rev->abbrev_commit_given)
	}
{

	unsigned long size;
	git_config(git_log_config, NULL);
	THREAD_SHALLOW,
		    PATH_MAX - FORMAT_PATCH_NAME_MAX - suffix_len) {
		int new_offset = offset + 1;

	int quiet = 0, source = 0, mailmap;
					diff_get_color_opt(&rev.diffopt, DIFF_RESET));
		unuse_commit_buffer(list[i], buf);
	if (!strcmp(var, "log.follow")) {
{
	return git_log_config(var, value, cb);
}
		strbuf_addch(&buf, '\n');

	if (get_oid_with_context(the_repository, obj_name,
	revs.max_parents = 1;
			read_tree_recursive(the_repository, (struct tree *)o, "",
	const char *rdiff_prev = NULL;
	}

	rev.extra_headers = strbuf_detach(&buf, NULL);
{
			return 0;

		return git_config_string(&fmt_patch_suffix, var, value);
		load_display_notes(&rev->notes_opt);
	const char *subject = "*** SUBJECT HERE ***";

	    rev->prune_data.nr == 1)
	mailmap = use_mailmap_config;
		{ OPTION_CALLBACK, 0, "attach", &rev, N_("boundary"),
		{ OPTION_CALLBACK, 0, "inline", &rev, N_("boundary"),

		return 0;
			  struct commit *origin, struct commit *head)
	if (decoration_style < 0)


	rev->diffopt.flags.allow_textconv = 1;
		rev.no_inline = 1;
	int use_stdout = 0;
static void infer_range_diff_ranges(struct strbuf *r1,
	/* Any arguments at this point are not recognized */
		      "", &opts);

	if (rev->early_output)
			gen_message_id(&rev, "cover");
				 *
	struct rev_info check_rev;
		oidcpy(patch_id, &oid);

		    open_next_file(rev.numbered_files ? NULL : commit, NULL, &rev, quiet))
	if (unset)
{
static int show_tag_object(const struct object_id *oid, struct rev_info *rev)
		return "./";
		 */
	for (i = 0; i < total; i++) {
		list = list->next;
	struct rev_info rev;
	if (dwim_ref(ref, strlen(ref), &branch_oid, &full_ref) &&

		len -= 4;
		rev->diffopt.output_format |= DIFF_FORMAT_NO_OUTPUT;
		return 0;
			die_errno(_("could not create directory '%s'"),
	N_("git format-patch [<options>] [<since> | <revision-range>]"),
		string_list_append(&extra_cc, value);
			      int nr, struct commit **list,
	struct pretty_print_context pp = {0};
	const struct option builtin_format_patch_options[] = {
				 * reply to the <reply-to>.
	/*

		display_progress(progress, total - nr);
	}
}
	if (rev->diffopt.flags.default_follow_renames &&
	} else {


			    PARSE_OPT_NOARG | PARSE_OPT_NONEG, no_numbered_callback },
		make_cover_letter(&rev, use_stdout,
	for (i = 0; !need_8bit_cte && i < nr; i++) {
	}
	if (mailmap) {
{
			    N_("start numbering patches at <n> instead of 1")),
				int unset)
	if (!strcmp(var, "format.numbered")) {
{
	tip_oid = &rev->cmdline.rev[positive].item->oid;

		strbuf_release(&buf);
	}
	switch (git_parse_maybe_bool(value)) {
		if (value && !strcasecmp(value, "auto")) {
	repo_init_revisions(the_repository, &rev, prefix);
	}

		use_mailmap_config = git_config_bool(var, value);

			    N_("cover-from-description-mode"),
		return COVER_FROM_SUBJECT;
	else if (!strcmp(arg, "subject"))
#include "diff.h"
			if (rev.shown_one)
	strbuf_release(&out);
	if (rev->combine_merges)
		die(_("revision walk setup failed"));
	/*
	struct commit *commit;
	init_display_notes(&notes_opt);
				 */
				goto done;
		 * to see if it needs to emit a LF before showing
		die(_("%s: invalid cover from description mode"), arg);
	int len = strlen(value);
	} else if ((base_commit && !strcmp(base_commit, "auto"))) {
	struct rev_info revs;
	if (base_commit && strcmp(base_commit, "auto")) {

		strbuf_addf(r1, "%s..%s", head_oid, prev);
	struct pretty_print_context pp = {0};
	}
		 */
	} else if (signature_file) {
	extra_to.strdup_strings = 1;
				      int total)
	int start_number = -1;
	rev.simplify_history = 0;
		struct strbuf sprefix = STRBUF_INIT;
	return -1;
static int show_notes;

		return 0;
{
		decoration_style = DECORATE_SHORT_REFS;

		add_header(value);
	if (unset)
	if (offset < size)
{
			  struct commit **list,
	if (argc > 1)
		rev->mime_boundary = git_version_string;
	}
		const char *buf = get_commit_buffer(list[i], NULL);
		return 0;
		list[i]->object.flags &= ~UNINTERESTING;
#include "commit.h"
				die(_("failed to find exact merge base"));
	struct commit **list = NULL;
		fprintf(file, "prerequisite-patch-id: %s\n", oid_to_hex(&bases->patch_id[i]));
			 * We may show a given commit multiple times when
			       struct strbuf *sb,
			if (rev.shown_one)
}

	if (unset)
#include "progress.h"
static void print_commit(char sign, struct commit *commit, int verbose,
	char *buf;
			add_object_array(o, name, &rev.pending);

		else if (b)
	}
	if (extra_cc.nr)
	opt.def = "HEAD";
		do_signoff = git_config_bool(var, value);
}
	}
	else if (!strcmp(arg, "auto"))
		strbuf_complete(&filename, '/');
			if (get_oid(upstream, &oid))
			    N_("use <sfx> instead of '.patch'")),
static const char *default_date_mode = NULL;
	if (!output_directory && !use_stdout)
	show_early_header(rev, "done", n);

	add_pending_object(&check_rev, o2, "o2");
	 * reader isn't listening, we want our output to be

		}
static void gen_message_id(struct rev_info *info, char *base)
		const char *ident;
		 */
		return 0;

	int cover_letter = -1;

}
		item = string_list_append(&extra_to, value + 4);
	struct commit *commit, *c1, *c2;

				       struct setup_revision_opt *opt)

	}
		return git_config_pathname(&signature_file, var, value);
			break;
	opt.tweak = log_setup_revisions_tweak;
					     _("Interdiff:"),
		if (skip_prefix(buf + offset, "tagger ", &ident))
		rev.idiff_oid2 = get_commit_tree_oid(list[0]);
		if (value && *value)

	int nr_patch_id, alloc_patch_id;


		string_list_clear(&extra_cc, 0);

		die(_("--creation-factor requires --range-diff"));
	}
		list[nr - 1] = commit;


	if (decoration_style) {
	clear_commit_marks(c2, SEEN | UNINTERESTING | SHOWN | ADDED);
	repo_init_revisions(the_repository, &rev, prefix);
			die(_("format.headers without value"));
	if (in_reply_to) {
		case OBJ_TREE:
		rev->mailmap = xcalloc(1, sizeof(struct string_list));
	pp_title_line(pp, &subject, sb, encoding, need_8bit_cte);

	if (!i) {
		len -= 4;
		}
	if (!strcmp(var, "log.abbrevcommit")) {
		die(_("failed to infer range-diff ranges"));

		}
		int check_head = 0;
	sa.sa_flags = SA_RESTART;
static int session_is_interactive(void)
	    !rev->diffopt.flags.allow_textconv)
}

	char **from = opt->value;
	 * throttled by the writing, and not have the timer
	if (!strcmp(var, "format.from")) {
	N_("git show [<options>] <object>..."),
};
}
		rev->diffopt.output_format = DIFF_FORMAT_PATCH;
	clear_commit_marks(c1, SEEN | UNINTERESTING | SHOWN | ADDED);
{
	};
		if (value && !strcasecmp(value, "auto")) {
		struct strbuf buf = STRBUF_INIT;
		pp_commit_easy(CMIT_FMT_ONELINE, commit, &buf);

enum cover_setting {
{
			rev.shown_one = 1;

static int attach_callback(const struct option *opt, const char *arg, int unset)
	for (i = 0; i < extra_hdr.nr; i++) {
static void cmd_log_init_defaults(struct rev_info *rev)
			o = parse_object(the_repository, oid);
	const char *head_oid = oid_to_hex(&head->object.oid);

	struct patch_ids ids;
	 * early-output thing..
		auto_number = auto_number && numbered;
	return cmd_log_walk(&rev);
		default_show_signature = git_config_bool(var, value);
	if (cover_letter) {
		return output_directory;
		print_bases(&bases, rev.diffopt.file);
	rev.no_walk = REVISION_WALK_NO_WALK_SORTED;
{
				die(_("could not find exact merge base"));
}
			(cover_from_description_mode == COVER_FROM_AUTO &&
static int from_callback(const struct option *opt, const char *arg, int unset)
	else
		while (new_offset < size && buf[new_offset++] != '\n')
	if (default_attach) {
		default:
		return 1;
	sigaction(SIGALRM, &sa, NULL);


	 * We cannot move this anywhere earlier because we do want to
	if (unset)
		rev.diffopt.flags.binary = 1;
			objects[i].item = o;
	struct sigaction sa;
	memcpy(&opts, &rev->diffopt, sizeof(opts));
		return git_config_string(&config_output_directory, var, value);
 * This is equivalent to "git log -g --abbrev-commit --pretty=oneline"
	if (start_number < 0)
	 * ..if no, then repeat it twice a second until we
	case 2:

	else
	struct string_list args;
	if (!cmit_fmt_is_mail(rev->commit_format))
		return git_config_string(&fmt_patch_subject_prefix, var, value);
}

				    const char *prev,

		decoration_style = parse_decoration_style(arg);
	switch (argc) {
}
		fwrite(buf + offset, size - offset, 1, rev->diffopt.file);
			rev.pending.objects = NULL;
static char *from;

	BUG_ON_OPT_ARG(arg);
		if (rev->commit_format != CMIT_FMT_ONELINE)
	if (fmt_pretty)
			/* Have we already had a message ID? */
	while (list && i) {
	if (in_reply_to || thread || cover_letter)
		else if (b)

		start_number = 1;
	return 0;
	rev->diffopt.stat_width = -1; /* use full terminal width */
		(!rev.diffopt.output_format ||
	}
	rev_nr = total;
	rev->diffopt.degraded_cc_to_c = saved_dcctc;
	} else if (!strncasecmp(value, "cc: ", 4)) {
	 *
	}
	else if (!rdiff_prev)

	const char *upstream;
	if (unset)
			rev.shown_one = 0;
		return;

		if (b < 0)
	if (!strcmp(var, "format.signaturefile"))
		infer_range_diff_ranges(&rdiff1, &rdiff2, rdiff_prev,
		die(_("git show %s: bad file"), obj_name);

	int need_8bit_cte = 0;
			     PARSE_OPT_KEEP_ARGV0 | PARSE_OPT_KEEP_UNKNOWN |
	 * we only set a single volatile integer word (not
static struct itimerval early_output_timer;
		line_log_init(rev, line_cb.prefix, &line_cb.args);
 * This gives a rough estimate for how many commits we
						      &decorate_refs_exclude};
			ret = show_blob_object(&o->oid, &rev, name);
			      const char *branch_name,
		return COVER_FROM_MESSAGE;
		OPT_STRING_LIST(0, "decorate-refs-exclude", &decorate_refs_exclude,
	struct strbuf sb = STRBUF_INIT;
		OPT__QUIET(&quiet, N_("suppress diff output")),
	clear_commit_base(&commit_base);
		auto_number =  0;
				 * Without --cover-letter and

		if (b < 0)
	else
		const char *pathname, unsigned mode, int stage, void *context)
static int cc_callback(const struct option *opt, const char *arg, int unset)
			gen_message_id(&rev, oid_to_hex(&commit->object.oid));
			free_commit_list(commit->parents);
	write_or_die(1, buf, size);
	const char *ref, *v;

		die(_("unrecognized argument: %s"), argv[1]);
static int auto_decoration_style(void)
	struct strbuf description_sb = STRBUF_INIT;

static struct string_list extra_hdr = STRING_LIST_INIT_NODUP;

		if (!decoration_given)
 *		 2006 Junio Hamano
	/* reset for next revision walk */
	if (!buf)
			ret = error(_("unknown type: %d"), o->type);

		case SCLD_OK:
		rev->sources = &revision_sources;
		if (!rev->reflog_info) {
	/*
		OPT_STRING(0, "base", &base_commit, N_("base-commit"),
	rev.always_show_header = 1;
 */
		struct strbuf buf = STRBUF_INIT;
static void print_signature(FILE *file)
	pp_remainder(pp, &body, sb, 0);
		OPT_GROUP(N_("Messaging")),

	setup_pager();

	if (!strcmp(var, "log.showsignature")) {
	argc = setup_revisions(argc, argv, &rev, &s_r_opt);
	oid_array_clear(&idiff_prev);

				    && rev.ref_message_ids->nr > 0

	}
		 rev.diffopt.output_format == DIFF_FORMAT_PATCH))

	strbuf_release(&description_sb);
	struct base_tree_info bases;
#include "string-list.h"
			i--;
			struct object_id *oid = get_tagged_oid(t);
		string_list_clear(&extra_hdr, 0);
}
	}

		struct branch *curr_branch = branch_get(NULL);
	}
	opt.revarg_opt = REVARG_COMMITTISH;
			from = xstrdup(git_committer_info(IDENT_NO_DATE));
/*
	if (is_null_oid(&bases->base_commit))
	fprintf(rev->diffopt.file, "%s\n", sb.buf);
		OPT_END()
		if (!upstream) {
		saved = get_shared_repository();
		{ OPTION_CALLBACK, 0, "decorate", NULL, NULL, N_("decorate options"),

			die(_("failed to create output files"));
	if (!strcmp(var, "format.useautobase")) {
		die(_("base commit should be the ancestor of revision list"));
static char *default_attach = NULL;
		cover_from_description_mode = parse_cover_from_description(cover_from_description_arg);
	return 0;
	 */

	if (rev.show_notes)
				branch_name = xstrdup(""); /* no branch */
		default_encode_email_headers = git_config_bool(var, value);
		die(_("--name-only does not make sense"));
	return 0;
	while ((commit = get_revision(&check_rev)) != NULL) {
		m++;
		printf("%s\n", filename.buf + outdir_offset);

};
		}
	opts.output_format = DIFF_FORMAT_SUMMARY | DIFF_FORMAT_DIFFSTAT;
		OPT_BOOL(0, "cover-letter", &cover_letter,
	if (show_progress)
		*thread = THREAD_UNSET;


						 NULL, NULL);
	memset(&s_r_opt, 0, sizeof(s_r_opt));
			      int quiet)
{
	int saved_dcctc = 0, close_file = rev->diffopt.close_file;
	}
				show_early_header(revs, "incomplete", n);
static const char * const cherry_usage[] = {
	strbuf_release(&rdiff2);
		rev->shown_one = 0;
		die(_("unknown commit %s"), limit);
	if (add_pending_commit(head, &revs, 0))
#define MAIL_DEFAULT_WRAP 72
		if (has_non_ascii(buf))
		}

	else
		}
		rev.reroll_count = reroll_count;
		       buf.buf);

			break;
	struct progress *progress = NULL;
		if (commit) {
	 */
	if (!strcmp(var, "format.coverfromdescription")) {
	diff_setup_done(&diffopt);
			 * origin" that prepares what the origin side still
	rev->diffopt.flags.recursive = 1;
	early_output_timer.it_value.tv_usec = 500000;
	struct userformat_want w;
				 * --cover-letter, make every mail a
		if (!use_stdout &&
			disable_display_notes(&notes_opt, &show_notes);
	if (get_oid(arg, &oid) == 0) {
		cover_from_description_mode = parse_cover_from_description(value);
	strbuf_release(&idiff_title);
		/* FALLTHROUGH */
	 * SA_RESTART.
}

	if (nr == 0)
static const char *fmt_pretty;
		struct object *o = objects[i].item;
	if (rev->show_notes)
	 */
	 * add new decoration styles.
static int default_show_root = 1;
	/* Did we already get enough commits for the early output? */
	 * Please update _git_formatpatch() in git-completion.bash
	struct object_id branch_oid;
	int show_header = 1;
			    N_("enable message threading, styles: shallow, deep"),
}

	}

			return error(_("name of output directory is too long"));
	rev.verbose_header = 1;
			n++;
		die(_("need exactly one range"));
	struct setup_revision_opt opt;
		rev_nr = DIV_ROUND_UP(rev_nr, 2);
	struct shortlog log;
	 */
	return session_is_interactive() ? DECORATE_SHORT_REFS : 0;
	int zero_commit = 0;
	git_config(git_log_config, NULL);

			    N_("generate parts of a cover letter based on a branch's description")),
	}

								&oid);
#include "repository.h"
		return COVER_FROM_AUTO;
		return COVER_FROM_MESSAGE;
		 * Otherwise, it is "format-patch -22 HEAD", and/or
	}
	while (offset < size && buf[offset] != '\n') {
	return 0;
		return 0;
		goto do_pp;
			die(_("standard output, or directory, which one?"));
	}

			strbuf_release(&filename);
	if (!description_sb.len)
{
		{ OPTION_CALLBACK, 0, "cc", NULL, N_("email"), N_("add Cc: header"),
}

	 * command line, reset "numbered".
		subject = subject_sb.buf;
				N_("add a signature from a file")),
		struct diff_options opts;
	struct option options[] = {
		OPT_BOOL(0, "progress", &show_progress,

	count = rev.pending.nr;
	 * trigger every second even if we're blocked on a
		if (positive < 0)
			      "of '%s'"), output_directory);
	o1 = rev->pending.objects[0].item;
				fprintf(rev.diffopt.file, "\n--%s%s--\n\n\n",

			     builtin_log_options, builtin_log_usage,
#include "shortlog.h"
			    N_("mark the series as Nth re-roll")),
	COVER_ON,
	 */
{

			rev.pending.nr = rev.pending.alloc = 0;
	if ((rev->diffopt.file = fopen(filename.buf, "w")) == NULL) {
		int b = git_parse_maybe_bool(value);
	init_grep_defaults(the_repository);
	if (cover_letter == -1) {
		strbuf_addstr(&buf, "Cc: ");

{
			if (rev.message_id) {
	rev.show_root_diff = 1;
					diff_get_color_opt(&rev.diffopt, DIFF_COMMIT),
	 * If we can get the whole output in less than a
			cover_letter = (total > 1);
	}
	if (rev.diffopt.output_format & DIFF_FORMAT_NAME_STATUS)
		OPT_SET_INT_F('p', "no-stat", &use_patch_format,
	} else {
	if (cover_from_description_mode == COVER_FROM_MESSAGE ||
		rev.total = total + start_number - 1;
			else
		struct commit *commit = list->item;
			    PARSE_OPT_NONEG, output_directory_callback },
			base = base_list->item;
			default_attach = xstrdup(git_version_string);

			    N_("Use [RFC PATCH] instead of [PATCH]"),
{
	}
	init_diff_ui_defaults();
	struct setup_revision_opt opt;
	init_log_defaults();
				      struct setup_revision_opt *opt)
			    N_("attach the patch"), PARSE_OPT_OPTARG,
		/* The user did not explicitly ask for "./" */
		rev->mime_boundary = arg;
	while (0 <= --nr) {
static void print_bases(struct base_tree_info *bases, FILE *file)
		shortlog_add_commit(&log, list[i]);
	struct rev_info *rev = (struct rev_info *)opt->value;
	*dir = arg;
		}
	if (!rev->show_notes_given && (!rev->pretty_given || w.notes))
	log.wrap_lines = 1;
			rev->dense_combined_merges = 1;
		head = argv[1];
static void init_log_defaults(void)

}
		return 0;
	if (branch_name && *branch_name)
		string_list_clear(&extra_to, 0);
	}
		m++;
	}
static int git_format_config(const char *var, const char *value, void *cb)

		return 0;
		 */
			else
					" specify <upstream> manually.\n"));

	revs->diffopt.close_file = 0;
				N_("pattern"), N_("do not decorate refs that match <pattern>")),

static int decoration_style;
#include "log-tree.h"
	bases->alloc_patch_id = 0;
					string_list_append(rev.ref_message_ids,
	init_log_defaults();
	struct rev_info rev;
			fprintf(stderr, _("Could not find a tracked"
		get_notes_args(&other_arg, rev);
	total = nr;
		return error(_("could not read object %s"), oid_to_hex(oid));
		} else {
		struct object_id *patch_id;
	enum object_type type;

	fflush(rev->diffopt.file);
		free_commit_buffer(the_repository->parsed_objects,
	repo_init_revisions(the_repository, &revs, prefix);
		struct commit *base = get_base_commit(base_commit, list, nr);
}
			    PARSE_OPT_NOARG, numbered_callback },
	if (!rev->show_notes) {
	} else if (rev->notes_opt.use_default_notes > 0 ||
	opt.def = "HEAD";
					    0, 0, &match_all, show_tree_object,
		rev.diffopt.output_format = DIFF_FORMAT_RAW;
		{ OPTION_CALLBACK, 0, "rfc", &rev, NULL,
	if (rev.diffopt.output_format & DIFF_FORMAT_NAME)
}
	struct object_id *patch_id;
		strbuf_addstr(&buf, extra_hdr.items[i].string);

		patch_id = bases->patch_id + bases->nr_patch_id;
			    N_("add a signature")),
		strbuf_addch(&buf, '\n');
	if (unset)
			       const char *encoding,
	const char *committer;
	bases->nr_patch_id = 0;
		else
	if (argc > 1)
	opt.tweak = show_setup_revisions_tweak;
		add_pending_object(&revs, &list[i]->object, "rev_list");
			     parse_opt_object_name),
	/* Only do this once, either for the cover or for the first one */

		nr++;
static int add_pending_commit(const char *arg, struct rev_info *revs, int flags)
	for (i = 0; i < extra_to.nr; i++) {
		die(_("revision walk setup failed"));
		return git_config_string(&default_date_mode, var, value);
			show_tagger(ident, rev);
	if (output_directory && is_absolute_path(output_directory))
	 * know if --root was given explicitly from the command line.
		if (!use_stdout)
	init_commit_base(&commit_base);
		 * the log; when using one file per patch, we do

 *
	    oideq(tip_oid, &branch_oid))
	/* We can only do diffstat with a unique reference point */
			const char *ref, *v;
			commit->object.flags |= flags;
				rev->creation_factor, 1, &opts, &other_arg);
		show_interdiff(rev, 0);
#include "commit-slab.h"

			struct commit *commit;
{
			if (show_header) {

	rev->diffopt.needed_rename_limit = saved_nrl;
	    rev->diffopt.flags.check_failed) {
#include "tag.h"
	rev->diffopt.close_file = 0;
	if (from) {
		rev->show_decorations = 1;
static int subject_prefix_callback(const struct option *opt, const char *arg,
		/* Don't say anything if head and upstream are the same. */
		rev->ignore_merges = 0;
	subject_prefix = 1;
			merge_base = get_merge_bases(rev[2 * i], rev[2 * i + 1]);

		die(_("failed to create cover-letter file"));
{
}
	 * like "git format-patch -o a123 HEAD^.." may fail; a123 is
	case 1:
static int outdir_offset;
	}
		    git_committer_info(IDENT_NO_NAME|IDENT_NO_DATE|IDENT_STRICT));
			     PARSE_OPT_KEEP_DASHDASH);
	oidcpy(&bases->base_commit, &base->object.oid);
			    0, to_callback },
		struct commit *commit = lookup_commit_reference(the_repository,
				print_signature(rev.diffopt.file);
		for (i = 0; i < rev_nr / 2; i++) {
	return 0;
		prepare_bases(&bases, base, list, nr);
					    rev.diffopt.file);
	const struct option builtin_log_options[] = {
	item->string[len] = '\0';

	if (!strcmp(var, "log.decorate")) {
		/* Make the second and subsequent mails replies to the first */
				 *
		rev->diffopt.flags.follow_renames = 1;
					origin, list[0]);
				 * matter what other options are set.

}

		strbuf_addf(sb, rerolled, reroll_count - 1);
		diff_setup_done(&opts);
			    N_("generate a cover letter")),


		if (!(flags & (TREESAME | UNINTERESTING)))
static struct string_list extra_cc = STRING_LIST_INIT_NODUP;
		}
			 */
			commit->parents = NULL;

}
		rev[i] = list[i];
	rev.abbrev_commit = 1;
		const char *msgid = clean_message_id(in_reply_to);
static int no_numbered_callback(const struct option *opt, const char *arg,
	pp_user_info(&pp, "Tagger", &out, buf, get_log_output_encoding());
		OPT__QUIET(&quiet, N_("don't print the patch filenames")),
	int offset = 0;
			need_8bit_cte = 1;
#include "branch.h"
	 * Parse the arguments before setup_revisions(), or something
	int show_progress = 0;
	outdir_offset = strlen(prefix);
	putc('\n', file);
	rev.add_signoff = do_signoff;

		item = string_list_append(&extra_cc, value + 4);
	else
	if (!z)


			 N_("don't include a patch matching a commit upstream")),
static void show_setup_revisions_tweak(struct rev_info *rev,
		else
/* Set a default date-time format for git log ("log.date" config variable) */

				show_header = 0;
		free(from);
#include "builtin.h"

		list = list->next;
		die(_("--check does not make sense"));
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		if (!log_tree_commit(rev, commit) && rev->max_count >= 0)
static const char *config_output_directory;
	const char *in_reply_to = NULL;
static void make_cover_letter(struct rev_info *rev, int use_stdout,
		fmt_output_subject(&filename, subject, rev);
			if (ret)


		{ OPTION_CALLBACK, 'k', "keep-subject", &rev, NULL,
		if (i + 1 < extra_to.nr)
	char *buf = read_object_file(oid, &type, &size);

		base_auto = git_config_bool(var, value);
	 * This is a one-time-only trigger.
			/*
		rev.idiff_oid1 = &idiff_prev.oid[idiff_prev.nr - 1];
			boundary_count++;
	rev->verbose_header = 1;

	if (!use_stdout)
{
			    N_("percentage by which creation is weighted")),
			free_commit_list(base_list);
		const char *upstream = branch_get_upstream(curr_branch, NULL);
		if (!use_stdout)
			from = xstrdup(value);
		*thread = THREAD_SHALLOW;

	if (0 < reroll_count) {
{
define_commit_slab(commit_base, int);
	/* Don't say anything if head and upstream are the same. */
					name,
	if (revs.pending.nr == 2) {
static struct string_list extra_to = STRING_LIST_INIT_NODUP;
	struct commit_base commit_base;
	early_output_timer.it_value.tv_usec = 100000;
		REALLOC_ARRAY(list, nr);

	}
	const char **dir = (const char **)opt->value;
	struct diff_options diffopt;
{
			if (ref && skip_prefix(ref, "refs/heads/", &v))
	struct strbuf subject_sb = STRBUF_INIT;
	return 0;
	return 0;
static void prepare_cover_text(struct pretty_print_context *pp,
}
}

{
	pp_user_info(&pp, NULL, &sb, committer, encoding);
					    oid_to_hex(oid));

				    && (!cover_letter || rev.nr > 1))
		setup_early_output();
	}


			print_bases(&bases, rev.diffopt.file);
	if (!signature || !*signature)
	extra_hdr.strdup_strings = 1;
		opts.file = rev->diffopt.file;
	int i, positive = -1;
	if (add_pending_commit(upstream, &revs, UNINTERESTING))
			rev->combine_merges = 1;
		rev.idiff_title = diff_title(&idiff_title, reroll_count,
{
static int default_show_signature;

	c1 = lookup_commit_reference(the_repository, &o1->oid);
		OPT_STRING(0, "range-diff", &rdiff_prev, N_("refspec"),
		return 0;
	else
	/* Turn -m on when --cc/-c was given */
	if (!rev.diffopt.flags.text && !no_binary_diff)
	}
	/* Turn --cc/-c into -p --cc/-c when -p was not given */
			return 0;
	memcpy(&rev.notes_opt, &notes_opt, sizeof(notes_opt));
static int log_line_range_callback(const struct option *option, const char *arg, int unset)
		return COVER_FROM_NONE;
		fclose(rev->diffopt.file);
	argc = parse_options(argc, argv, prefix, options, cherry_usage, 0);
			check_head = 1;
	((struct rev_info *)opt->value)->total = -1;
	 * system dependencies and headers), and using
	}
				 GET_OID_RECORD_PATH,
};
int cmd_format_patch(int argc, const char **argv, const char *prefix)

}
#include "refs.h"
		base_commit = "auto";
		fprintf(file, "%c %s %s\n", sign,
	COVER_UNSET,
		OPT_BOOL(0, "no-binary", &no_binary_diff,
	fprintf(rev->diffopt.file, "\n");
#include "reflog-walk.h"
				 * --in-reply-to, if specified.
		       find_unique_abbrev(&commit->object.oid, abbrev));
static void log_setup_revisions_tweak(struct rev_info *rev,
	if (cover_from_description_mode == COVER_FROM_NONE)
		{ OPTION_CALLBACK, 0, "add-header", NULL, N_("header"),
	if (!keep_subject && auto_number && (total > 1 || cover_letter))
	memset(&opt, 0, sizeof(opt));
}
	default:
			default_attach = xstrdup(value);
{
	NULL
	else if (!arg || !strcmp(arg, "shallow"))
	else
	if (rev->ignore_merges) {
			struct tag *t = (struct tag *)o;
			 * does not have.
		}
	return -1;
	signal(SIGALRM, SIG_IGN);
static int default_abbrev_commit;
#include "object-store.h"
	ref = rev->cmdline.rev[positive].name;
		 */
	};
	get_patch_ids(&revs, &ids);

	}
			die(_("unknown commit %s"), base_commit);
		strbuf_addstr(&filename, output_directory);
	if (!strcmp(var, "diff.color") || !strcmp(var, "color.diff") ||
		die(_("insane in-reply-to: %s"), msg_id);
	rev.show_notes = show_notes;

	 *
	if (unset)
	return 0;

				 * --in-reply-to, make every mail a
enum thread_level {
	if (prepare_revision_walk(&check_rev))
		add_header(arg);


static enum cover_from_description parse_cover_from_description(const char *arg)
struct line_opt_callback_data {

static int thread_callback(const struct option *opt, const char *arg, int unset)

			    attach_callback },
			origin = (boundary_count == 1) ? commit : NULL;
		 * can be added later if deemed desirable.
			decoration_style = 0;
		string_list_clear(&extra_to, 0);
	/*
	}
	static struct line_opt_callback_data line_cb = {NULL, NULL, STRING_LIST_INIT_DUP};
		if (upstream) {
		/*
	if (unset) {

}
}
		reset_revision_walk();
		int b = git_parse_maybe_bool(value);
static const char *clean_message_id(const char *msg_id)
			     PARSE_OPT_KEEP_ARGV0 | PARSE_OPT_KEEP_UNKNOWN |
			i--;
		OPT_BOOL(0, "source", &source, N_("show source")),
#include "gpg-interface.h"
		if (!value)
		strbuf_release(&filename);
		}
{
	if (!buf)

static int open_next_file(struct commit *commit, const char *subject,

	}

	diff_setup_done(&opts);
	if (!branch_name)
	if (origin)
	show_early_output = log_show_early;
	while ((ch = *m)) {
static int show_blob_object(const struct object_id *oid, struct rev_info *rev, const char *obj_name)
			    N_("make first mail a reply to <message-id>")),

		print_commit(sign, commit, verbose, abbrev, revs.diffopt.file);
	keep_subject = 1;
	BUG_ON_OPT_NEG(unset);
		show_range_diff(rev->rdiff1, rev->rdiff2,
	/* given a range a..b get all patch ids for b..a */

		return 0;
	rev->show_root_diff = default_show_root;
		if (commit_patch_id(commit, &diffopt, &oid, 0, 1))
	} else if (!origin) {
	struct patch_ids ids;
	o1->flags ^= UNINTERESTING;
		commit = list->item;

	if (!strcmp(var, "format.coverletter")) {

	return n;

		if (use_stdout)
	else
		int saved;
			rev.diffopt.use_color = GIT_COLOR_NEVER;
}
/* format-patch */
			return 0;
	 * If numbered is set solely due to format.numbered in config,
	for (i = 0; i < count && !ret; i++) {
	memset(&opt, 0, sizeof(opt));
			decoration_style = 0; /* maybe warn? */
		if (strbuf_read_file(&buf, signature_file, 128) < 0)
		return NULL;
	struct rev_info rev;
	if (prepare_revision_walk(&revs))
	if (rev.diffopt.output_format & DIFF_FORMAT_CHECKDIFF)
	const char *limit = NULL;
	if (idiff_prev.nr) {

		if (rev_nr % 2)
	struct strbuf out = STRBUF_INIT;
		else
		struct object_array_entry *o = revs.pending.objects;

	free(list);
	if (!rev.no_walk)
	cmd_log_init_finish(argc, argv, prefix, &rev, &opt);
	for (i = 0; i < total; i++)
			z = m;
static int numbered = 0;
		if (rev->diffopt.degraded_cc_to_c)

	if (output_directory) {
	free(full_ref);

	/* Always generate a patch */

			    N_("don't strip/add [PATCH]"),
static int output_directory_callback(const struct option *opt, const char *arg,
	struct strbuf rdiff_title = STRBUF_INIT;
		return 0;

	    open_next_file(NULL, rev->numbered_files ? NULL : "cover-letter", rev, quiet))
		return DECORATE_SHORT_REFS;
			rev->max_count++;
	while ((commit = get_revision(&revs)) != NULL) {
 * will print out in the list.
			    rev.subject_prefix, reroll_count);
	string_list_clear(&extra_cc, 0);

	}

					t->tag,
	assert(type == OBJ_TAG);
	N_("git log [<options>] [<revision-range>] [[--] <path>...]"),
	int suffix_len = strlen(rev->patch_suffix) + 1;
		rev.mime_boundary = default_attach;
		commit_list_insert(commit, &list);
	}
		get_commit_format(fmt_pretty, rev);
	COVER_FROM_NONE,
	static struct string_list decorate_refs_exclude = STRING_LIST_INIT_NODUP;
static void get_patch_ids(struct rev_info *rev, struct patch_ids *ids)
			ret = show_tag_object(&o->oid, &rev);
			     N_("show changes against <rev> in cover letter or single patch"),
	log_write_email_headers(rev, head, &pp.after_subject, &need_8bit_cte, 0);
}


		strbuf_addf(&filename, "%d", rev->nr);
			     PARSE_OPT_KEEP_DASHDASH);
}


	o2 = rev->pending.objects[1].item;
static char *find_branch_name(struct rev_info *rev)
	int reroll_count = -1;
			 * This is traditional behaviour of "git format-patch
	return 0;
		die(_("unrecognized argument: %s"), argv[1]);
	int n = estimate_commit_count(rev->commits);
		die(_("two output directories?"));
static enum cover_setting config_cover_letter;
				    struct commit *origin,
	if (cover_from_description_arg)
	 */
	rev.always_show_header = 1;
			return output_directory;
	struct strbuf buf = STRBUF_INIT;
		if (!value)
		if (i + 1 < extra_cc.nr)

		*from = xstrdup(arg);
	 * and HAS_CHANGES being accumulated in rev->diffopt, so be careful to
	struct object_array_entry *objects;

		fprintf_ln(rev->diffopt.file, "%s", rev->rdiff_title);
	repo_init_revisions(the_repository, &rev, prefix);

		if (!cover_letter && total != 1)
	if (close_file)
	cmd_log_init(argc, argv, prefix, &rev, &opt);
			    N_("dir"), N_("store resulting files in <dir>"),
	for (i = bases->nr_patch_id - 1; i >= 0; i--)
	struct commit_list *list = NULL;
	if (prepare_revision_walk(rev))
	struct rev_info *rev = (struct rev_info *)opt->value;
	NULL
			      "please use git branch --set-upstream-to to track a remote branch.\n"
}
 * Builtin "git log" and related commands (show, whatchanged)
			}
static struct commit *get_base_commit(const char *base_commit,
	cmd_log_init(argc, argv, prefix, &rev, &opt);
	init_reflog_walk(&rev.reflog_info);
	 * NOTE! We don't use "it_interval", because if the
		case OBJ_TAG: {
			die(_("cannot get patch id"));
	rev.use_terminator = 1;
			thread = THREAD_SHALLOW;
		case OBJ_BLOB:
			if (rev.mime_boundary)
	flags1 = o1->flags;
	for (i = 0; i < rev->cmdline.nr; i++) {
		rev.rdiff1 = rdiff1.buf;
				    struct strbuf *r2,
	struct object *o1, *o2;
		if (*commit_base_at(&commit_base, commit))
	if (!output_directory)

			    PARSE_OPT_NOARG | PARSE_OPT_NONEG, rfc_callback },
			die(_("invalid ident line: %s"), from);
		OPT_BOOL(0, "numbered-files", &just_numbers,

{
		struct commit *commit = list->item;
		}
{
			saved_dcctc = 1;
	int nr = 0, total, i;
static int default_follow;

	int i = revs->early_output, close_file = revs->diffopt.close_file;
			from = NULL;
#include "parse-options.h"
			strbuf_addch(&buf, ',');
			      "Or you could specify base commit by --base=<base-commit-id> manually"));
	}
	if (rev->idiff_oid1) {
{
			       int need_8bit_cte)
	if (!rev.diffopt.stat_width)
		OPT_STRING(0, "signature", &signature, N_("signature"),
		return;
	shortlog_init(&log);
		clear_object_flags(UNINTERESTING);
}
	rev.preserve_subject = keep_subject;
			 N_("output all-zero hash in From header")),
	if (!arg || !strcmp(arg, "default"))
}

		if (check_head) {
static void show_tagger(const char *buf, struct rev_info *rev)

	struct pathspec match_all;


	if (ignore_if_in_upstream)
		   (rev->notes_opt.use_default_notes == -1 &&
			    N_("use simple number sequence for output file names")),
		 * We consider <outdir> as 'outside of gitdir', therefore avoid
}
		{ OPTION_CALLBACK, 0, "thread", &thread, N_("style"),
static void show_diffstat(struct rev_info *rev,
			    inline_callback },
	else
{
static const char *signature = git_version_string;

		/* We put one extra blank line between formatted
				int n = estimate_commit_count(list);
int cmd_show(int argc, const char **argv, const char *prefix)
	struct branch *current_branch;
	s_r_opt.revarg_opt = REVARG_COMMITTISH;
			rev->abbrev_commit = 0;
	if (!base)
	}
	struct strbuf rdiff1 = STRBUF_INIT;
	rev.diff = 1;
		OPT_INTEGER('v', "reroll-count", &reroll_count,
	else if (!strcmp(arg, "deep"))
	else if (arg)
	struct object_id base_commit;
}
			commit = lookup_commit_or_die(&oid, "upstream base");
				 *
	return 0;

{
		*from = NULL;

}
	return 0;
	if (signature[strlen(signature)-1] != '\n')
		/*
	log.in2 = 4;
	/* reverse the list of commits */
			enable_ref_display_notes(&notes_opt, &show_notes, value);
	}
	}
			rev.pending.objects[0].item->flags |= UNINTERESTING;

	opt.def = "HEAD";
		}
	BUG_ON_OPT_NEG(unset);
	}
}
	repo_init_revisions(the_repository, &revs, NULL);
#include "version.h"
			continue;
			usage_with_options(cherry_usage, options);
			saved_nrl = rev->diffopt.needed_rename_limit;

	while (list) {

				N_("pattern"), N_("only decorate refs that match <pattern>")),
	rev.diffopt.stat_width = -1; 	/* Scale to real terminal size */
			 int abbrev, FILE *file)
{
	if (default_follow)
	int ignore_if_in_upstream = 0;
	}
			    N_("inline the patch"),
		       const char *generic, const char *rerolled)
			return 0;
	/*
static const char *fmt_patch_suffix = ".patch";

		branch = xstrdup(v);
		rev->diffopt.output_format = DIFF_FORMAT_PATCH;
#include "color.h"
	for (i = 0; i < nr; i++)
#include "streaming.h"
}
	committer = git_committer_info(0);
	} else if (signature && signature != git_version_string) {

		return 0;
	const char *body = "*** BLURB HERE ***";
	decoration_style = auto_decoration_style();
			 * walking the reflogs.
}

		strbuf_addstr(r1, prev);
	BUG_ON_OPT_NEG(unset);
	FILE *file = context;
	string_list_clear(&extra_to, 0);

	 * Traverse the commits list, get prerequisite patch ids
		fprintf(file, "%c %s\n", sign,
	return cmd_log_walk(&rev);
		OPT_CALLBACK(0, "interdiff", &idiff_prev, N_("rev"),
	if (!quiet)

			/* No "--first-parent", "-c", or "--cc" */
	 * reader!
}
			break;
		/* There was no "-m" on the command line */
{
				 * For deep threading: make every mail
	}
							   rev.message_id);

		if (rev.diffopt.use_color != GIT_COLOR_ALWAYS)
	while ((ch = *m) && (isspace(ch) || (ch == '<')))
	memset(&w, 0, sizeof(w));
		return;
		*commit_base_at(&commit_base, list[i]) = 1;
	    !strcmp(var, "color.ui") || !strcmp(var, "diff.submodule")) {
		upstream = branch_get_upstream(current_branch, NULL);

		string_list_append(&extra_to, arg);

		if (ignore_if_in_upstream && has_commit_patch_id(commit, &ids))
			return config_error_nonbool(var);

	if (default_date_mode)
	return base;
	return sb->buf;

}
		{ OPTION_CALLBACK, 'N', "no-numbered", &numbered, NULL,
		show_diffstat(rev, origin, head);
	if (!prefix || !*prefix) {
		get_patch_ids(&rev, &ids);
	int verbose = 0, abbrev = 0;

		return auto_decoration_style();

	case 1:
	rev->show_signature = default_show_signature;
	log.wrap = MAIL_DEFAULT_WRAP;
	}
	argc = setup_revisions(argc, argv, rev, opt);
	struct object_id oidc;
			cover_letter = (config_cover_letter == COVER_ON);
		return 0;

		parse_date_format(default_date_mode, &rev->date_mode);
		strbuf_addf(r2, "%s..%s",
	check_rev.max_parents = 1;

	init_log_defaults();

	if (!strcmp(var, "format.headers")) {
	rev->encode_email_headers = default_encode_email_headers;
		struct object_id oid;
		OPT_END()

	THREAD_DEEP
		len--;
		case commit_error:

	cmd_log_init(argc, argv, prefix, &rev, &opt);
		OPT_BOOL(0, "ignore-if-in-upstream", &ignore_if_in_upstream,
				 * With --cover-letter, make every
			if (close_file)

	return xmemdupz(a, z - a);
	}
			break;
			struct object_id oid;
	opt.revarg_opt = REVARG_COMMITTISH;
	rev->subject_prefix = fmt_patch_subject_prefix;
			die(_("base commit shouldn't be in revision list"));

	    !textconv_object(the_repository, obj_context.path,
	base->object.flags |= UNINTERESTING;
static int get_notes_refs(struct string_list_item *item, void *arg)
