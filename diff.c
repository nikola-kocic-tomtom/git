	if (degraded_cc)

 * Shall changes to this submodule be ignored?
				   const char *func, long funclen)

		}
	} else {
			return;
			if (errno == ENOENT)
	 */
		/* See try_to_follow_renames() in tree-diff.c */
		emit_diff_symbol(o, DIFF_SYMBOL_CONTEXT_INCOMPLETE,
	}
	int val = parse_ws_error_highlight(arg);
	if (ecbdata->opt->flags.suppress_hunk_header_line_count)
		xsnprintf(temp->mode, sizeof(temp->mode), ".");
		 ((p->score &&
	}
		case DIFF_SYMBOL_MINUS:
				&one->oid, &two->oid,
	GIT_COLOR_NORMAL,	/* FUNCINFO */

			strbuf_addstr(&out, " Unmerged\n");
	strbuf_release(&out);
		    (prev->flags & DIFF_SYMBOL_MOVED_LINE_ALT) !=
{
	 */
	 * feeding "there are unchanged files which should
	const char *reset, *add_c, *del_c;
	 * Before the final output happens, they are pruned after
	if (options->skip_stat_unmatch)
		 * As there is not specific white space config given,
	df = alloc_filespec(path);
			sfx_length = len_a - (old_name - a);
			   PARSE_OPT_KEEP_UNKNOWN |
						 NULL, 0, 0);
static int diff_opt_binary(const struct option *opt,
	}
	 * We don't report dirstat's for
{
			diff_free_filespec_data(p->two);
		diffopts = getenv("GIT_DIFF_OPTS");
		 * so we force all entries to have damage > 0.

	options->color_moved = diff_color_moved_default;
			diff_free_filepair(p);
			continue;
			/* This is a "no-change" entry and should not
	if (S_ISLNK(p->one->mode) && !S_ISLNK(p->two->mode))
	if (diff_populate_filespec(r, two, 0))
	diff_words->last_minus = minus_first;
	out->size = 0;
static void diff_summary(struct diff_options *opt, struct diff_filepair *p)
		if (s[off] == ' ') {
	if (options->flags.ignore_submodules)
				diff_free_filepair(p);

	}
void diff_free_filespec_blob(struct diff_filespec *s)
				 const char *arg, int unset)

		if (cm & COLOR_MOVED_WS_ERROR)
		return;
	fprintf(opt->file, "%s", diff_line_prefix(opt));
}
	fprintf(stderr, "score %d, status %c rename_used %d broken %d\n",
	sfx_length = 0;
	free_filespec(df);

				  checkdiff_consume, &data,
			struct strbuf sb = STRBUF_INIT;
#include "string-list.h"
			scale = 1;
			  DIFF_FORMAT_PATCH | DIFF_FORMAT_RAW,
{
}
	 * is MAX_SCORE * num / scale.
	    && len == 2 && line[0] == ' ' && line[1] == '\n') {

	 * detection you would need them, so here they are"
	if (ecbdata->diff_words->minus.text.size ||
					    DIFF_FORMAT_NUMSTAT |
	diff_free_filespec_data(two);
		    (next->flags & DIFF_SYMBOL_MOVED_LINE_ZEBRA_MASK) ==
		if (options->stat_graph_width &&
			break;
	return ws_blank_line(line, len, ecbdata->ws_rule);
		return;
	 * with something like '=' or '*' (I haven't decided

		} else {
{
			    line_prefix, set, similarity_index(p));
		if (diff_interhunk_context_default < 0)
		strbuf_add(name, a, pfx_length);
			hashmap_init(&add_lines, moved_entry_cmp, o, 0);
static int check_pair_status(struct diff_filepair *p)
	if (insertions || deletions == 0) {
	*fmt |= DIFF_FORMAT_PATCH;
	pprint_rename(&names, p->one->path, p->two->path);
		} else {
		/* lp points at the first NULL now */
	dp->two = two;
	dir.permille = options->dirstat_permille;
struct checkdiff_t {
		if (sum_changes) {
			       N_("ignore changes to submodules in the diff generation"),
		if (o->color_moved_ws_handling &


#define DIFF_SYMBOL_MOVED_LINE_UNINTERESTING	(1<<19)
		result |= 02;

	int delta;
		ecbdata->lno_in_postimage++;
	options->diff_path_counter = 0;

#define FAST_WORKING_DIRECTORY 0

}
	}
		default:
			if (match_filter(options, q->queue[i]))
				emit_diff_symbol(options, DIFF_SYMBOL_STATS_LINE,
		} else if (!strcmp(p, "lines")) {
		return; /* cannot happen */
	the_hash_algo->final_fn(hash, ctx);
	} else if (!o->flags.text &&
	dot = 0;
			 int must_show_header,
	/* Strip the prefix but do not molest /dev/null and absolute paths */
	return strcmp(a->name, b->name);
		options->b_prefix = "b/";
		/*
	*arg = NULL;
	options->output_format |= DIFF_FORMAT_DIRSTAT;
			break;
	queue->queue[queue->nr++] = dp;
			pmb[i].match = cur;
	 * First assign sizes that are wanted, ignoring available width.
	if (options->stat_graph_width &&
static void fn_out_diff_words_aux(void *priv,
{
	return cnt;
static int diff_populate_gitlink(struct diff_filespec *s, int size_only)
	int i, adds = 0, dels = 0, total_files = data->nr;
		dir.files[dir.nr].changed = damage;
		OPT_STRING_F(0, "src-prefix", &options->a_prefix, N_("<prefix>"),
	emit_diff_symbol(o, DIFF_SYMBOL_BINARY_DIFF_HEADER, NULL, 0, 0);
	    fill_mmfile(o->repo, &mf2, two) < 0)
	dir.alloc = 0;
		 * function, but first clear the current entries
		ptr--; /* skip the last LF */

	else if (s->should_munmap)
				 int n)
	} else if (!strcmp(opt->long_name, "stat-width")) {
	struct diff_options *opt = option->value;
				int pmb_nr)
	int *break_opt = opt->value;
		 * know that there must have been _some_ kind of change,
		options->flags.recursive = 1;
	if (!it)
		options->flags.dirty_submodules = 1;

		bit = (0 <= optch && optch <= 'Z') ? filter_bit[optch] : 0;
{
			    p->one->mode, p->two->mode);
}
static int diff_get_patch_id(struct diff_options *options, struct object_id *oid, int diff_header_only, int stable)

	const char *rest;
	 * instead of the change count and graph. This part is treated

out:
	/* check if this line is blank */
		notes_cache_write(driver->textconv_cache);
	run_diff(p, o);
		return;
			       PARSE_OPT_NONEG, diff_opt_char),

		OPT_CALLBACK_F(0, "diff-algorithm", options, N_("<algorithm>"),

}
	 * underrun the input strings.
			diff_words_append(line, len,
		return 0;
	if (data->nr == 0)
};
			*dst++ = c;
	struct diff_options *options = opt->value;
			 p->two->dirty_submodule ||
}
		 const struct object_id *old_oid,
				   const char *arg, int unset)
			     diff_filespec_is_binary(o->repo, one)) ||
{
	/* fake an empty "0th" word */
	argv_array_clear(&env);
	    diff_filespec_is_binary(o->repo, two)) {
}
		return;
	struct child_process child = CHILD_PROCESS_INIT;

			 struct diff_filepair *p)


			       "\"minimal\", \"patience\" and \"histogram\""));
}
	free(q->queue);
		set = diff_get_color_opt(o, DIFF_FILE_NEW);
				fprintf(opt->file, "%s%4d.%01d%% %.*s\n", line_prefix,
			last_symbol = l->s;
 */
	opt1 = parse_rename_score(&arg);
			struct moved_entry *cur = (prev && prev->next_line) ?
		strbuf_addch(&out, '\n');
	textconv = get_textconv(r, df);
		quote_c_style(two, &res, NULL, 1);
		 */


	dir.nr = 0;
	opt->flags.tree_in_recursive = 1;
	if (unset) {
/* Check whether two filespecs with the same mode and size are identical */
			diff_free_filespec_data(p->two);
		OPT_BITOP('p', "patch", &options->output_format,

		OPT_BIT_F('b', "ignore-space-change", &options->xdl_opts,

		break;
		      options->stat_name_width < max_len) ?
static void free_diff_words_data(struct emit_callback *ecbdata)

	int l1, l2, at;
	case DIFF_SYMBOL_BINARY_DIFF_HEADER:
	}

		/* See try_to_follow_renames() in tree-diff.c */
	if (unset) {
			 */
				struct moved_block *pmb,
			regfree(ecbdata->diff_words->word_regex);
		emit_line(o, "", "", " ...\n", strlen(" ...\n"));
	int conv_flags = global_conv_flags_eol;
			return error(_("%s expects a numerical value"),
	}
	}
		options->use_color = GIT_COLOR_NEVER;
			 * multiple renames, in which case we decrement

		if (*arg)
	if (data->nr == 0)
	return 0;
				file->added, file->deleted);
	const char *cp;
			       N_("specify the character to indicate an old line instead of '-'"),
	int qlen_a = quote_c_style(a, NULL, NULL, 0);
				 sb.buf, sb.len, 0);
		xpp.anchors = o->anchors;
		       (l->flags & DIFF_SYMBOL_MOVED_LINE_ALT))
	int lno_in_preimage;
	int len = eds->len;
	strbuf_release(&sb);
	return 0;
}

	int patchlen;
		return abbrev;
	not_a_valid_file:
	if (!len && !first)
				strbuf_addf(errmsg, _("  Failed to parse dirstat cut-off percentage '%s'\n"),

			diff_populate_filespec(options->repo, p->one, CHECK_SIZE_ONLY);
		OPT_CALLBACK_F(0, "stat-count", options, N_("<count>"),
	if (output_format & (DIFF_FORMAT_DIFFSTAT|DIFF_FORMAT_SHORTSTAT|DIFF_FORMAT_NUMSTAT) ||
	struct diff_options *options = opt->value;
			lbl[0] = NULL;
	options->change = diff_change;
	long value = parse_algorithm_value(arg);
				      DIFF_FORMAT_SHORTSTAT |
		int len;
	}
			break;
	if (word_regex && *begin < buffer->size) {

	b = container_of(entry_or_key, const struct moved_entry, ent);
				      DIFF_FORMAT_NAME_STATUS |
	return 1;

{
	/* We want to avoid the working directory if our caller
			max_change = change;
	GIT_COLOR_RESET,
	/* calculate the visual width of indentation */
				} else {
		ecbdata.color_diff = want_color(o->use_color);


		return 0;
		diffcore_pickaxe(options);
{
struct diff_words_style_elem {
}
		memset(&xpp, 0, sizeof(xpp));
	count = i; /* where we can stop scanning in data->files[] */

		return 0;
		{ OPTION_CALLBACK, 0, "output", options, N_("<file>"),
		    (!data->files[i]->is_interesting && (added + deleted == 0))) {
};
		options->flags.stat_with_summary = 1;
		SWAP(old_oid, new_oid);
	struct diff_options *o = ecbdata->opt;
				fprintf(o->file, "%s:%d: %s.\n",
	strbuf_release(&tempfile);
			diff_words->plus.text.ptr + diff_words->plus.text.size
	int indent_width; /* The visual width of the indentation */
				 buffer->size - *begin, 1, match, 0)) {
			      struct diff_options *o)
	 * however we need to check if the indent changes of the current line
		return 0;
	 */
			return error("unable to generate patch-id diff for %s",
	while (mf->ptr < ptr) {
	 * worth the effort to change it now.  Note that this would
		diff_stat_graph_width = git_config_int(var, value);
		show_graph(&out, '+', add, add_c, reset);
			emit_diff_symbol(opt, DIFF_SYMBOL_SUMMARY,
	char *path_dup = xstrdup(path);
		}

		if (**otherp == '/')
	if (minus_len) {
		OPT_BIT_F(0, "name-status", &options->output_format,
	int lc_a, lc_b;

	struct strbuf header = STRBUF_INIT;
	unsigned val = 0;
	}
	size_one = fill_textconv(o->repo, textconv_one, one, &data_one);
static void emit_binary_diff_body(struct diff_options *o,
			 */
	child.argv = argv;
		SWAP(old_oid_valid, new_oid_valid);

	struct diff_options *options = opt->value;

static int color_words_output_graph_prefix(struct diff_words_data *diff_words)
		if (next && (next->flags & DIFF_SYMBOL_MOVED_LINE) &&

	DIFF_STATUS_FILTER_AON,

		return;
			continue;
	    b_width = b->indent_width;
				 line, len, 0);
	BUG_ON_OPT_NEG(unset);
	}
}
	}
			len -= 3;
		return;
	if (ecbdata->diff_words) {
	if (o->word_regex) {

	regex_t *word_regex;
	}
	strbuf_addstr(&out, " +");
void diff_emit_submodule_modified(struct diff_options *o, const char *path)
			   void *blob,
		fputs(line_prefix, diff_words->opt->file);
		     struct diff_filespec *df,
			  XDF_IGNORE_WHITESPACE_AT_EOL, PARSE_OPT_NONEG),
		mf1.size = fill_textconv(o->repo, textconv_one, one, &mf1.ptr);
	 * pager with --exit-code. But since we have not done so historically,
}
		fputc('\n', o->file);
			max_len = len;
	name_b = DIFF_FILE_VALID(two) ? name_b : name_a;
		return 0;
	if (a->s == DIFF_SYMBOL_PLUS)

		if (file->is_binary)

	if (ecbdata->opt->flags.dual_color_diffed_diffs)
	strbuf_release(&buf);
		fputs(set, file);
			      struct diff_options *o)
		strbuf_addstr(&msgbuf, reverse);
				set = diff_get_color_opt(o, DIFF_FILE_OLD_BOLD);
	const char *xfrm_msg = NULL;
			 * identical. We can therefore skip looking at the
	}

	strbuf_release(&sb);
	if (*namep && !is_absolute_path(*namep)) {
		/*
		for (i = 0; (optch = optarg[i]) != '\0'; i++) {
	    (p->one->mode != p->two->mode) ||

	}
static void run_diff(struct diff_filepair *p, struct diff_options *o)


		s->should_munmap = 1;
	}
			off++;

	}
		OPT_BOOL('W', "function-context", &options->flags.funccontext,
static void moved_block_clear(struct moved_block *b)
	for (i = 0; i < pmb_nr; i++) {
			strbuf_addstr(&sb, diff_line_prefix(o));
	argv_array_push(argv, temp->mode);
	}
{
		one->driver = userdiff_find_by_name("default");

struct emitted_diff_symbol {
		return error(_("option diff-algorithm accepts \"myers\", "
	if (diff_unmodified_pair(p))
	if (cur->es->s == DIFF_SYMBOL_PLUS)
		OPT_BOOL('a', "text", &options->flags.text,
static int diff_opt_submodule(const struct option *opt,

		len = strlen(line);
	graph_setup_line_prefix(options);
	 * line; allow it to say "return this_function();"
	int blank_at_eof_in_preimage;
		if (xfrm_msg)
		err = error("error reading from textconv command '%s'", pgm);
	if (ep != cp) {
	case DIFF_SYMBOL_REWRITE_DIFF:
		}
	while (data_size) {
	pair->is_unmerged = 1;
	DIFF_SYMBOL_STATS_SUMMARY_INSERTS_DELETES,
		return diff_colors[ix];
		OPT_SET_INT_F(0, "ita-invisible-in-index", &options->ita_invisible_in_index,
	const struct emitted_diff_symbol *es;
	/* Are we looking at the work tree? */
			      const char *attr_path,
	emit_diff_symbol(o, DIFF_SYMBOL_SUBMODULE_ERROR, err, strlen(err), 0);
	if (pfx_length + sfx_length) {

	int size_only = flags & CHECK_SIZE_ONLY;
	if (!strcasecmp(value, "copies") || !strcasecmp(value, "copy"))
		if (!diff_unmodified_pair(q->queue[i]))
		}
	/* blank before the func header */
		return 0;
		else if (DIFF_PAIR_TYPE_CHANGED(p))

		strbuf_addf(msg, "%s\n%s%scopy to ", reset, line_prefix, set);
	 * file.  Practically, this code only helps when we are used

}
		 * diff_suppress_blank_empty, there may be
	QSORT(dir.files, dir.nr, dirstat_compare);

		addremove = (addremove == '+' ? '-' :
				return "new +l";
	if (startup_info->have_repository)
			      1, PARSE_OPT_NONEG),
		if (abbrev)
		return;
	 * after the indentation match.
				diffopt->skip_stat_unmatch++;
			if (one->is_stdin) {
		ecbdata->header = NULL;
	diff_queue(&diff_queued_diff, one, two);
		oidclr(&one->oid);
		strbuf_reset(&header);


}
			  int use_color)
	struct strbuf res = STRBUF_INIT;
	struct diff_filespec *one, *two;

				      const char *arg, int unset)
	if (WSEH_NEW & WS_RULE_MASK)
		x, one ? one : "",
				emit_diff_symbol(options, DIFF_SYMBOL_STAT_SEP,
		diff_free_filepair(q->queue[i]);
		check_blank_at_eof(&mf1, &mf2, &ecbdata);


	if (!strcmp(var, "diff.statgraphwidth")) {
	if (addremove != '-') {
	return ret;
			fprintf(data->o->file,
		break;
		diff_use_color_default = git_config_colorbool(var, value);
		    graph_width > options->stat_graph_width)
		slash = strchr(f->name + baselen, '/');
{
	const struct moved_entry *a, *b;
			scale = dot ? scale*100 : 100;
			die("unable to read files to diff");

			options->color_moved = diff_color_moved_default;
}
	case DIFF_SYMBOL_BINARY_DIFF_HEADER_LITERAL:
			emit_diff_symbol(diff_words->opt, DIFF_SYMBOL_WORD_DIFF,

		if (!file->is_interesting && (added + deleted == 0))
void free_diffstat_info(struct diffstat_t *diffstat)
	switch (line[0]) {

		 */
	 * diff_addremove/diff_change does not set the bit when
					 out.buf, out.len, 0);
		free (ecbdata->diff_words->opt);
			emit_diff_symbol(o, DIFF_SYMBOL_HEADER,
		return -1;
}
	return 1;
	 * initialized the filter field with another --diff-filter, start
	line_prefix = diff_line_prefix(data->o);
			/* Display change counts aligned with "Bin" */
	if (a_len - a_off != b_len - b_off ||
			 * one->mode.  mode is trustworthy even when

		must_show_header = 1;
{
		xdemitconf_t xecfg;
	if (has_trailing_newline)
		diff_words_show(ecbdata->diff_words);
	if (options->stat_graph_width == -1)

	if (msg)
	DIFF_STATUS_COPIED,
		}
	if (skip_prefix(*arg, token, &rest) && (!*rest || *rest == ',')) {
	 * Report the content-level differences with HAS_CHANGES;

		else
				   struct diff_filespec *df)
	string_list_split(&l, arg, ',', -1);
	if (output_format & DIFF_FORMAT_CALLBACK)
static unsigned filter_bit_tst(char status, const struct diff_options *opt)
		fprintf(o->file, "%s%s--- %s%s%s\n", diff_line_prefix(o), meta,
	int i;
			    const char *arg, int unset)
		return error(_("invalid argument to %s"), opt->long_name);
		int show_name)
		const char *c = o->emitted_symbols->buf[n - i].line;
			continue;
	opt->ws_error_highlight = val;
	return 0;
		width = term_columns() - strlen(line_prefix);
static const char *diff_abbrev_oid(const struct object_id *oid, int abbrev)
			       N_("generate compact summary in diffstat"),
			 * look at the actual file contents at all.
static int reuse_worktree_file(struct index_state *istate,
	int n;
	}

 * into the pre/post image file. This pointer could be a union with the
}
	has_trailing_newline = (len > 0 && line[len-1] == '\n');
			      N_("disable rename detection"),
	data->patchlen += new_len;

		s->data = xmmap(NULL, s->size, PROT_READ, MAP_PRIVATE, fd, 0);

		strbuf_addch(&sb, '\n');
	struct userdiff_driver *textconv_one = NULL;
		enum object_type type;
#include "userdiff.h"
		options->color_moved = 0;
		char *s = xstrfmt("%lu", two->size);
		if (DIFF_FILE_VALID(p->one) && DIFF_FILE_VALID(p->two)) {


			if (oideq(&one->oid, &two->oid)) {
		OPT_BOOL(0, "find-copies-harder", &options->flags.find_copies_harder,
	int width = options->stat_width;
			  N_("ignore carrier-return at the end of line"),
}
	int alloc, nr, permille, cumulative;
			diff_line_prefix(o),

	int last_minus;
	while (*old_name && *new_name && *old_name == *new_name) {
		fprintf(o->file, "%sdelta %s\n", diff_line_prefix(o), line);

 * 16 is marking if the line is blank at EOF
}
			if (match_filter(options, p))
		if (o->color_moved) {

		return error(_("%s expects a character, got '%s'"),
	git_hash_ctx ctx;
	enum diff_symbol s = eds->s;
			/*
	}
		quote_c_style(one, &res, NULL, 1);
	if (HAS_MULTI_BITS(options->pickaxe_opts & DIFF_PICKAXE_KINDS_MASK))

			goto err_empty;
				   long ob, long on, long nb, long nn,
	}
	for (i = 0; i < data->nr; i++) {
	struct diff_words_style *style = diff_words->style;
					emit_diff_symbol(o, DIFF_SYMBOL_HEADER,
				const char *arg, int unset)
	 * just check the lengths. We delay calling memcmp() to check
		 * white space. The setup of the white space
void diff_setup_done(struct diff_options *options)
{
			write_name_quoted(file->name, options->file, '\0');
		}
	struct strbuf names = STRBUF_INIT;
	/* Fallback to default settings */
static void print_stat_summary_inserts_deletes(struct diff_options *options,
						  options->line_termination);
 * which we should output the prefix.
	emit_diff_symbol(o, DIFF_SYMBOL_REWRITE_DIFF, out.buf, out.len, 0);
	run_checkdiff(p, o);
	}

		*must_show_header = 0;
	return (((p->status == DIFF_STATUS_MODIFIED) &&

	const char *ws = NULL;
static void builtin_diff(const char *name_a,


	for_each_string_list_item(i, &l) {
			const char *set_sign, const char *set, unsigned reverse, const char *reset,

free_queue:
static int diff_opt_color_moved_ws(const struct option *opt,
	 */
	enum diff_symbol s;

 * we can decrease the memory footprint for the buffered output. At first we

		o->found_changes = 1;
		delta = diff_delta(one->ptr, one->size,
				 DIFF_SYMBOL_MOVED_LINE_UNINTERESTING)) {
		  N_("Output to a specific file"),

	unsigned flags = WSEH_OLD | ecbdata->ws_rule;
	if (file->comments)
	DIFF_SYMBOL_PLUS,
	if (!strcmp(opt->long_name, "stat")) {
 * Returns 0 if the last block is empty or is unset by this function, non zero

			if (*end == '.' && isdigit(*++end)) {
	 * same slash.
		return 0;
	options->flags.relative_name = 1;
int diff_can_quit_early(struct diff_options *opt)
		options->format_callback(q, options, options->format_callback_data);
{
			hm = add_lines;

	else
			 const char *attr_path,

			emit_del_line(ecb, data, len);
	close(child.out);
	if (!strcmp(var, "diff.autorefreshindex")) {

				return "new +x";
	struct diff_queue_struct *q = &diff_queued_diff;
		mf2.ptr = (char *)data_two;
	/*

				 strlen(ecbdata->label_path[0]), 0);


}
{
			hashmap_for_each_entry_from(hm, match, ent) {

	 * If this diff_tempfile instance refers to a temporary file,
	else
		p->score, p->status ? p->status : '?',
			}
		memset(&xecfg, 0, sizeof(xecfg));
	return val;
		}
		return 0;
			if (permille >= dir->permille) {
	return size;
	else {
	emit_diff_symbol(o, DIFF_SYMBOL_BINARY_DIFF_FOOTER, NULL, 0, 0);
		else {

int diff_auto_refresh_index = 1;
	}
	diff_filespec_load_driver(one, istate);
	else

				      DIFF_FORMAT_NO_OUTPUT))
	ecbdata.color_diff = want_color(o->use_color);
		return COLOR_MOVED_ZEBRA_DIM;
	if (one->size && two->size) {
	    DIFF_PAIR_MODE_CHANGED(p) ||

		options->detect_rename = DIFF_DETECT_COPY;
		break;
{
	unsigned flags = WSEH_NEW | ecbdata->ws_rule;
	GIT_COLOR_NORMAL,	/* CONTEXT */
		xdemitconf_t xecfg;
	default:
		null = alloc_filespec(one->path);
	 */

			return error(_("unknown change class '%c' in --diff-filter=%s"),

				break;
	b_two = quote_two(b_prefix, name_b + (*name_b == '/'));
			if (lstat(one->path, &st) < 0)
		if (is_conflict_marker(line + 1, marker_size, len - 1)) {
		*namep += prefix_length;
	if (val < 0)
		 */
			/*
	}
static void run_diff_cmd(const char *pgm,
	options->objfind = NULL;
		string_list_split_in_place(&params, params_copy, ',', -1);
	if (!changed)
	strbuf_grow(name, pfx_length + a_midlen + b_midlen + sfx_length + 7);
	if (len < 10 ||

			char *p = memchr(buffer->ptr + *begin + match[0].rm_so,
	else if (!strcmp(value, "diff"))
		name_a = p->two->path;
	xpp.flags = 0;


		return;
	if (options->flags.follow_renames && options->pathspec.nr != 1)
 * These are to give UI layer defaults.

	 * only by checking if there are changed paths, but
			val |= WSEH_OLD;
	struct diff_tempfile *temp = claim_diff_tempfile();
{
	QSORT(dir.files, dir.nr, dirstat_compare);
		}
			    deletions);
		compute_diffstat(options, &diffstat, q);
		if (memcmp(f->name, base, baselen))
		 */
		break;
			       const struct object_id *oid,
{
		show_submodule_summary(o, one->path ? one->path : two->path,

	 * specified.
	}
	if (textconv_one)
	options->dirstat_permille = diff_dirstat_permille_default;
	    close_tempfile_gently(temp->tempfile))

			       N_("<char>"),

		strbuf_release(&msg);
	 */
void init_diff_ui_defaults(void)
			  const char *other,
		  PARSE_OPT_NONEG, NULL, 0, diff_opt_output },
	options->use_color = diff_use_color_default;
	emit_binary_diff_body(o, two, one);
{
				     OBJECT_INFO_FOR_PREFETCH))
	return 0;
void compute_diffstat(struct diff_options *options,
{

	    oid_object_info_extended(r, &filespec->oid, NULL,
	if (!argv[1])
		OPT_BOOL(0, "full-index", &options->flags.full_index,
			       0, diff_opt_pickaxe_string),
			strbuf_addstr(&header, xfrm_msg);
			    diff_abbrev_oid(&one->oid, abbrev),
		options->prefix = arg;
			char c = !len ? 0 : line[0];
	fill_filespec(one, old_oid, old_oid_valid, old_mode);
 *
	else if (!strcmp(arg, "default"))
		show_dirstat(options);

		 * pretend they don't exist
	    (!one->mode || S_ISGITLINK(one->mode)) &&
		return;
		b_prefix = o->a_prefix;
	int dirstat_by_line = 0;

	for (i = 0; i < params.nr; i++) {
	    b_len = b->len,
 * While doing rename detection and pickaxe operation, we may need to
		} else {
			     N_("show the given source prefix instead of \"a/\""),
	/* Do we want all 40 hex characters? */
  (DIFF_SYMBOL_MOVED_LINE | DIFF_SYMBOL_MOVED_LINE_ALT)
	    diff_populate_filespec(r, p->two, CHECK_SIZE_ONLY) ||


		return 1;
		return 0;
	handle_ignore_submodules_arg(options, arg);
			continue;
		struct hashmap *hm = NULL;
			if (!isalnum(*c))
	}
static int diff_opt_diff_filter(const struct option *option,
		o->emitted_symbols = &esm;
	}
			if (o->color_moved == COLOR_MOVED_ZEBRA_DIM)
void diff_debug_filepair(const struct diff_filepair *p, int i)
	diff_words_fill(&diff_words->minus, &minus, diff_words->word_regex);
		new_name++;
		struct diff_words_style *st = ecbdata->diff_words->style;
static void patch_id_add_string(git_hash_ctx *ctx, const char *str)
		if (ch == '\n') {
static int diff_opt_dirstat(const struct option *opt,

	if (!driver->textconv)
		strbuf_addf(&out, " %*"PRIuMAX"%s",
		line[0] = '\n';
	struct moved_entry *prev_line = NULL;
		fprintf(opt->file, "%s ",
		 * Skip the prefix character, if any.  With
}
	if (l2 <= l1) {
			strbuf_release(&sb);
		return 0;
			strbuf_addf(&out, " %s%-*s |", prefix, len, name);
	 */
	 * former case, as we will generate no output. Since we still properly
	return (int)((num >= scale) ? MAX_SCORE : (MAX_SCORE * num / scale));
		options->submodule_format = DIFF_SUBMODULE_INLINE_DIFF;
		OPT_SET_INT_F(0, "no-renames", &options->detect_rename,
		es->indent_off = len;
		if (S_ISLNK(st.st_mode)) {
		 (p->two->mode & 0777) == 0644)
 * refers to a temporary file, sometimes to an existing file, and
	if (filespec && filespec->oid_valid &&
{
		 * we could save up changes and flush them all at the end,
		strbuf_addf(msg, "%s%ssimilarity index %d%%",
		break;
	changed = 0;
		}

		pgm = NULL;

		else {
		uintmax_t change = file->added + file->deleted;

	fputs(diff_line_prefix(o), file);
		if (!value)
static void prep_parse_options(struct diff_options *options);
	case DIFF_STATUS_MODIFIED:
	 * objects however would tend to be slower as they need
			break;
			     const char *line, int len)
		arg = "log";
		delta = c_width - a_width;

		if (val < 0)
	return ret;
		mf2.size = fill_textconv(o->repo, textconv_two, two, &mf2.ptr);
	return strbuf_detach(&res, NULL);
		if (line[0] != '\n') {
{
long parse_algorithm_value(const char *value)
	GIT_COLOR_CYAN,		/* FRAGINFO */
			break;
			diff_q(&outq, p);
		OPT_CALLBACK_F('B', "break-rewrites", &options->break_opt, N_("<n>[/<m>]"),
{
			if (one->is_binary == -1 && one->data)
{
	struct diff_options *wo = ecbdata->diff_words->opt;
		return git_config_string(&external_diff_cmd_cfg, var, value);
		free((char *)data_two);

	BUG_ON_OPT_NEG(unset);

		return 0;
			graph_width = width * 3/8 - number_width - 6;
	git_deflate_init(&stream, zlib_compression_level);
}
			slash = strchr(name, '/');
static int diff_opt_word_diff_regex(const struct option *opt,
}
			  struct diff_options *o,
	    (!two->mode || S_ISGITLINK(two->mode))) {
			diff_free_filespec_data(p->one);
			name += name_len - len;

	unsigned long deflate_size;
	 */
	remove_tempfile();
		if (o->flags.funccontext)
				putc('\0', options->file);
		blob = buf.buf;
		spec->mode = canon_mode(mode);
			patch_id_add_string(&ctx, "+++/dev/null");
			     o, complete_rewrite);
				options->dirstat_permille = permille;


		break;
	}
	struct strbuf buf = STRBUF_INIT;
			       const char *name,
		patch_id_add_string(&ctx, "a/");

		struct diffstat_file *file = data->files[i];
		} else if (p->two->mode == 0) {

/*
						 header.buf, header.len, 0);
}
	 */

	int must_show_header = 0;


}
		emit_line_ws_markup(o, set_sign, set, reset,
	while (s[off] == '\f' || s[off] == '\v' ||
 *
	DIFF_STATUS_TYPE_CHANGED,
	memset(&data, 0, sizeof(struct patch_id_t));
	default:
	if (!p)
	char *value = opt->value;
		}
		diff_free_filespec_data(spec);
				width += tab_width;
			       PARSE_OPT_NOARG, diff_opt_textconv),
static void diff_flush_patch(struct diff_filepair *p, struct diff_options *o)
	fprintf(stderr, "q->nr = %d\n", q->nr);
	if (!prefix)
		mmfile_t mf1, mf2;
		ecbdata.ws_rule = whitespace_rule(o->repo->index, name_b);
			free(mf2.ptr);
			o->found_changes = 1;
				o->color_moved_ws_handling |= XDF_IGNORE_WHITESPACE;

	if (!S_ISGITLINK(one->mode) &&
			 * The current line is the start of a new block.
	if (!filter_bit[DIFF_STATUS_ADDED]) {
		 * none.
	else {
	remove_tempfile();
			      struct diff_options *o)
	enable_patch_output(&options->output_format);
		mf1.ptr = (char *)data_one;
	int i;
		xecfg.interhunkctxlen = o->interhunkcontext;
	while (dir->nr) {
	 * must be checked for dirtiness too so it can be shown in the output
				value);

	 * that case we let this loop run 1 into the prefix to see the
}
		separator++;
			if (p->score)
			 *
	    memcmp(line, atat, 2) ||
		}
			       PARSE_OPT_NONEG, diff_opt_line_prefix),
	if (o->flags.stat_with_summary)
		write_name_quoted(name_a, opt->file, opt->line_termination);
		len = strlen(file->print_name);
			      struct diff_filespec *two,
void diffcore_std(struct diff_options *options)
			arg++;
			struct hashmap add_lines, del_lines;
	 * Find the longest filename and max number of changes
	if (git_color_config(var, value, cb) < 0)
		fprintf(opt->file, "%c%c", p->status, inter_name_termination);

				del_c, deleted, reset);
		set_sign = NULL;
	DIFF_SYMBOL_STATS_LINE,
			if (!one->data && DIFF_FILE_VALID(one))
			struct strbuf sb = STRBUF_INIT;
		append_emitted_diff_symbol(o, &e);
		struct moved_entry *cur = (prev && prev->next_line) ?
{
		options->submodule_format = DIFF_SUBMODULE_SHORT;
			       PARSE_OPT_NONEG | PARSE_OPT_NOARG,
		if (!bit)
				  long plus_first, long plus_len,
	while (0 < size) {
			diff_aligned_abbrev(&p->two->oid, opt->abbrev));
	const char *context = diff_get_color(ecbdata->color_diff, DIFF_CONTEXT);
	}
	if (plus_len) {


		options->prefix = NULL;
static const char *external_diff_cmd_cfg;
			argv_array_push(&argv, other);
	}
		 * so this line is not interesting as a whole
			else if (c == '@')
#define DIFF_SYMBOL_MOVED_LINE_ZEBRA_MASK \
			       PARSE_OPT_NOARG, diff_opt_compact_summary),
		if (graph_width <= max_change) {
		 * don't use colors when the header is intended for an
		OPT_CALLBACK_F(0, "color-moved-ws", options, N_("<mode>"),

		default:
	if (hexsz < options->abbrev)
			++*namep;
	struct diff_options *options = opt->value;
#define DIFF_SYMBOL_CONTENT_WS_MASK (WSEH_NEW | WSEH_OLD | WSEH_CONTEXT | WS_RULE_MASK)
		strbuf_addstr(&msgbuf, reset);
		context = diff_get_color_opt(o, DIFF_CONTEXT);
		fputs(set_sign, file);
	int conflict_marker_size;
	b_midlen = len_b - pfx_length - sfx_length;
			/* Even though we may sometimes borrow the
}
			emit_rewrite_diff(name_a, name_b, one, two,
	new_len = remove_space(line, len);
			  struct diff_filepair *p,

			set = diff_get_color_opt(o, DIFF_FILE_OLD_MOVED);
				 const struct moved_entry *cur,
		fn_out_diff_words_write_helper(diff_words->opt,
		return;
		OPT_BOOL(0, "rename-empty", &options->flags.rename_empty,
		width = strtoul(value, &end, 10);
	}
	if (write_in_full(temp->tempfile->fd, blob, size) < 0 ||

{

	const char *line_prefix = diff_line_prefix(opt);

		if (same_contents) {
	if (name_b) {
	strbuf_release(&header);
	if (!strcmp(var, "diff.submodule")) {
	else if (complete_rewrite) {
		struct emitted_diff_symbol *next =

		return 0;
		return;
		 * options->file to /dev/null should be safe, because we
	return ret;
		/* /dev/null */
	}
}
		 unsigned old_dirty_submodule, unsigned new_dirty_submodule)
	options->orderfile = diff_order_file_cfg;
		strbuf_add(&msgbuf, line, ep - line);

static int diff_mnemonic_prefix;
	 * and 5/8*16==10 for the filename part
	unsigned long alloc;
		mf1.size = size_one;
		return;
		const char *p = params.items[i].string;
		options->prefix_length = strlen(options->prefix);
			data->status |= 1;
end_of_line:
		}
			strbuf_reset(&out);
	same_contents = oideq(&one->oid, &two->oid);

	 * This is not the sha1 we are looking for, or
		if (xdi_diff_outf(&mf1, &mf2, discard_hunk_line,
		if (prev && prev->s != DIFF_SYMBOL_PLUS &&
	if (a_midlen < 0)


	} else {
{
 * 13-15 are WSEH_NEW | WSEH_OLD | WSEH_CONTEXT
			if (add < del) {
					 int line_no)
	 *  - or cases where everything came from a single directory
	options->xdl_opts &= ~XDF_DIFF_ALGORITHM_MASK;
		if (got_match[i]) {
	 * {pfx-a => pfx-b}sfx
	 * there is any change to this path. The easiest way is to
		carry >>= 8;
		 * scale the add/delete
	name_width = (options->stat_name_width > 0 &&
}
					 sb.buf, sb.len, 0);
	 * entry is currently not in use:
			changes = gather_dirstat(opt, dir, changed, f->name, newbaselen);

		BUG("fill_textconv called with non-textconv driver");
	options->xdl_opts |= value;
		while (rp > -1 && !pmb[rp].match)
	case DIFF_SYMBOL_CONTEXT_MARKER:
			if (alnum_count >= COLOR_MOVED_MIN_ALNUM_COUNT)
	return 0;
			continue;
	case DIFF_SYMBOL_BINARY_FILES:
	struct diff_options *opt = diff_words->opt;
	for (;;) {
		add = added;
	 * If there is no common prefix, we cannot do this as it would
		reset = diff_get_color_opt(o, DIFF_RESET);

			if (must_show_header)
		strip_prefix(o->prefix_length, &name, &other);
	}
	default:
	diff_set_mnemonic_prefix(o, "a/", "b/");
		options->flags.diff_from_contents = 0;
	[DIFF_FRAGINFO]		      = "frag",
	struct diff_queue_struct *q = &diff_queued_diff;

		xpp.anchors_nr = o->anchors_nr;
		    (DIFF_FILE_VALID(p->two) && S_ISDIR(p->two->mode)))
	return 0;
		if (!one->oid_valid) {
	for (cnt = 1; cnt < marker_size; cnt++)

	int i;
	 * Please update $__git_diff_algorithms in git-completion.bash
	 */
	else {
	if (!one || !two) {

		} else {
					    DIFF_FORMAT_DIRSTAT |
	if (s->should_free)
			completely_empty = 0;
	 * only a small number of files, while reading the cache is
	 * where abblen < 37); when the actual abbreviated result is a
			s->size = 0;
	}
		case DIFF_SYMBOL_MOVED_LINE:
			return error(_("bad --word-diff argument: %s"), arg);
	p = diff_queue(&diff_queued_diff, one, two);
		return 0;
		if (*s)
	if (fmt & DIFF_FORMAT_CHECKDIFF)
	}
			 * to determine how many paths were dirty only
			     const char *arg, int unset)
	struct diff_options *options = opt->value;
}
 * never be affected by the setting of diff.renames

				/* only use first digit */
		diff_resolve_rename_copy();
{
	strbuf_addstr(out, reset);

			diffcore_rename(options);
	struct diff_words_data *diff_words = priv;
	options->stat_graph_width = graph_width;
			       N_("specify the character to indicate a new line instead of '+'"),
	BUG_ON_OPT_NEG(unset);
	options->interhunkcontext = diff_interhunk_context_default;
	switch (count) {
}
	/* like GNU diff's --suppress-blank-empty option  */

			(const char *)blob, (size_t)size, &buf, &meta)) {
	struct diff_options *options = opt->value;
	one = alloc_filespec(path);
			for(i = 0; i < pmb_nr; i++)
		return;
			int newbaselen = slash + 1 - f->name;
	strbuf_addf(&buf, "Subproject commit %s%s\n",
{
	options->break_opt = -1;
		else if (parse_one_token(&arg, "context"))
			}
			copied = added = 0;
{
	 * savings we get by not inflating the object to a temporary
	ep += 2; /* skip over @@ */
					 header.buf, header.len, 0);

	if (has_trailing_newline)
		    int oid_valid,
		}
	case DIFF_SYMBOL_SUBMODULE_ADD:
	 * by diff-cache --cached, which does read the cache before
		options->output_format &= ~(DIFF_FORMAT_RAW |

		memcpy(out->ptr + out->size, buffer->text.ptr + i, j - i);
		cp++;
			     DIFF_FORMAT_NAME_STATUS |

		diff_auto_refresh_index = git_config_bool(var, value);
	BUG_ON_OPT_NEG(unset);
}
			  DIFF_FORMAT_PATCH, DIFF_FORMAT_NO_OUTPUT),
	cm = parse_color_moved_ws(arg);
	/*
	[DIFF_FILE_OLD_MOVED_DIM]     = "oldMovedDimmed",
			      struct diff_filespec *one,
			return;
	struct moved_entry *next_line;
	return one->driver->funcname.pattern ? &one->driver->funcname : NULL;
	diff_fill_oid_info(p->two, o->repo->index);
{
			     const char *line, int len, unsigned flags)
	const char *endp = NULL;
		}

static char *quote_two(const char *one, const char *two)
}
}
	if (!options->b_prefix)
static void prepare_filter_bits(void)
			s->size = size;
		p->one->rename_used, p->broken_pair);
	 * length by more than three, we give up on aligning, and add
}

	 */
		if (cur && !hm->cmpfn(o, &cur->ent, &match->ent, NULL)) {
			diff_summary(options, q->queue[i]);
		emit_diff_symbol(o, DIFF_SYMBOL_BINARY_DIFF_HEADER_LITERAL,
/*
	struct diff_options *options = opt->value;
			       diff_opt_dirstat),
	const char *argv[3];
	struct diff_filepair *p;
	DIFF_SYMBOL_CONTEXT_FRAGINFO,
static int count_trailing_blank(mmfile_t *mf, unsigned ws_rule)
			if (graph_width < 6)
			  XDF_IGNORE_WHITESPACE, PARSE_OPT_NONEG),
		 * configuration for the next block is done else where
static void emit_line(struct diff_options *o, const char *set, const char *reset,
	strbuf_addstr(&msgbuf, frag);
		diff_flush_raw(p, opt);
	BUG_ON_OPT_NEG(unset);
	if (diff_unmodified_pair(p))

			sources++;
		run_diff_cmd(pgm, name, NULL, attr_path,
{
			       0, diff_opt_color_moved_ws),

{
		else if (parse_one_token(&arg, "default"))

		if (abbrev < 0)
	}
{
		else if (DIFF_PAIR_RENAME(p)) {


			added + deleted ? " " : "");
static void emit_context_line(struct emit_callback *ecbdata,

	stream.next_out = deflated;
	int i, alnum_count = 0;
				&style->ctx, style->newline,
	/* This can happen even with many files, if everything was renames */
	}
		ALLOC_GROW(dir.files, dir.nr + 1, dir.alloc);

	int err = 0;
	ecbdata.lno_in_preimage = 1;

	 * but nothing about added/removed lines? Is this a bug in Git?").
				      struct diff_filespec *one,
		/* Check if we are at an interesting bound: */
				l->flags |= DIFF_SYMBOL_MOVED_LINE_ALT;
				set = diff_get_color_opt(o, DIFF_FRAGINFO);
				    diff_line_prefix(o), lbl[0], lbl[1]);
		patch_id_add_string(&ctx, "diff--git");
		opt->objfind = xcalloc(1, sizeof(*opt->objfind));
	mmfile_t mf1, mf2;
	if (!FAST_WORKING_DIRECTORY && !want_file && has_object_pack(oid))
	unsigned int off = 0, i;
	if (!strcmp(var, "diff.colormovedws")) {
				unsigned ws_rule, int blank_at_eof)
		if (size_only || (flags & CHECK_BINARY)) {
		 * not be the true size of the blob after it goes
	BUG_ON_OPT_NEG(unset);
		die("unable to read files to diff");
		OPT_CALLBACK_F(0, "follow", options, NULL,
#define DIFF_SYMBOL_CONTENT_BLANK_LINE_EOF	(1<<16)
	else
	return (opt->flags.quick &&
{
			lp++;

int parse_rename_score(const char **cp_p)
			if (!added && !deleted) {
			break;
	/* POSIX requires that first be decremented by one if len == 0... */
			ret |= XDF_IGNORE_WHITESPACE_AT_EOL;


	strbuf_init(msg, PATH_MAX * 2 + 300);
{
				    OUTPUT_INDICATOR_CONTEXT, line, len,
		a_prefix = o->a_prefix;
	/* An abbreviated value is fine, possibly followed by an ellipsis. */
		else
			 */
static unsigned long sane_truncate_line(char *line, unsigned long len)
	return 0;
			diff_words_append(line, len,

	return 0;
		return 0;

	int total_files = data->nr, count;
	 * whichever is smaller.
	static struct strbuf a_name = STRBUF_INIT, b_name = STRBUF_INIT;
	prep_parse_options(options);
	git_zstream stream;
	}
			width += tab_width - (width % tab_width);
	if (!strcmp(var, "diff.colormoved")) {
{
	const char *s = es->line;

		options->word_diff = DIFF_WORDS_PLAIN;

					    DIFF_FORMAT_PATCH);
		else if (file->is_unmerged) {
static const char *diff_order_file_cfg;
	if (delta && delta_size < deflate_size) {
		fprintf(opt->file, "%s", diff_line_prefix(opt));
		       (l->flags & DIFF_SYMBOL_MOVED_LINE_ALT))
	return strbuf_detach(&buf, outsize);
}
 *
}
		/* Emit just the prefix, then the rest. */
			 struct diff_filespec *two,
static int compute_ws_delta(const struct emitted_diff_symbol *a,
	return oid_to_hex(oid);

		separator++;
			return 0;

static void fill_metainfo(struct strbuf *msg,
static int diff_no_prefix;
		die("internal error: asking to populate invalid file.");
		s->path,

	/* Use already-loaded driver */
		s->mode,
		xecfg.ctxlen = 1; /* at least one context line */
	int i;
	struct diff_options *options = opt->value;
	const char *reset = diff_get_color(ecbdata->color_diff, DIFF_RESET);
#endif
	options->xdl_opts |= diff_algorithm;
		memset(&xpp, 0, sizeof(xpp));
		static char hex[GIT_MAX_HEXSZ + 1];
		   ( (!textconv_one && diff_filespec_is_binary(o->repo, one)) ||
		if ((flags & CHECK_BINARY) &&
	add_line_count(&out, lc_b);
		}
		if (ecbdata->diff_words)

struct emitted_diff_symbols {
		return XDF_PATIENCE_DIFF;
	diff_populate_filespec(r, one, CHECK_SIZE_ONLY);
	line_prefix = diff_line_prefix(opt);
}
}
		} else {
	int i, optch;
		((p->status != DIFF_STATUS_MODIFIED) &&
	int color_diff;
void print_stat_summary(FILE *fp, int files,
	if (!strcmp(var, "diff.indentheuristic"))
	 */

	int a_midlen, b_midlen;
				  const char *func, long funclen)
	case DIFF_SYMBOL_NO_LF_EOF:
	if (!options->use_color || external_diff())
			if (strbuf_readlink(&sb, name, st.st_size) < 0)
	case DIFF_SYMBOL_STATS_SUMMARY_NO_FILES:
			return -1;
		count -= p + 1 - buf;
	case '-':
		set_diffopt_flags_from_submodule_config(options, path);
	int i, j;
	if (output_format & DIFF_FORMAT_NO_OUTPUT &&
	 */
static unsigned char *deflate_it(char *data,
			continue;
	FREE_AND_NULL(options->parseopts);
	len = strlen(name);
		len = endp ? (endp - data + 1) : size;
	/* line[1] through line[marker_size-1] are same as firstchar */
		data_size = deflate_size;
{
	allot = l;
	diff_debug_filespec(p->two, i, "two");
{
				return;
		if (file->is_binary)
		return COLOR_MOVED_ZEBRA;
				    oid_to_hex(&s->oid));
	DIFF_SYMBOL_BINARY_DIFF_HEADER,

		const struct diff_filepair *p = q->queue[i];
			set = diff_get_color_opt(o, DIFF_FILE_NEW);

	oid_to_hex_r(temp->hex, oid);
	 * is rather slow with its stat/open/mmap/close syscalls,
			continue;
	emit_diff_symbol(ecbdata->opt, DIFF_SYMBOL_CONTEXT, line, len, flags);

	 * For binary diff, the caller may want to print "x files
}
	/*
	 * internally, so remove any anchors previously
const char mime_boundary_leader[] = "------------";
			p->status = DIFF_STATUS_ADDED;
}
static const char *color_diff_slots[] = {
		x->is_renamed = 1;
			 struct diff_filespec *two,
			      DIFF_FORMAT_CHECKDIFF |
	}
			const char *reset = st_el->color && *st_el->color ?

		 * whose both sides are valid and of the same type, i.e.
		if (prev_line && prev_line->es->s == o->emitted_symbols->buf[n].s)
#include "attr.h"
	static struct emitted_diff_symbols esm = EMITTED_DIFF_SYMBOLS_INIT;

	    options->flags.diff_from_contents) {
	}
	}
	case 0:
		diff_flush_checkdiff(p, opt);
			one->is_binary = one->driver->binary;

{
		len2 = remove_space(p->two->path, strlen(p->two->path));

		struct strbuf sb = STRBUF_INIT;
	case DIFF_SYMBOL_BINARY_DIFF_FOOTER:
	    (!lstat(name, &st) && !ie_match_stat(istate, ce, &st, 0)))
				diff_q(&outq, p);
	return 0;
{
			line, reset,
		ptr = prev_eol - 1;
	enum diff_words_type type;
			 N_("allow an external diff helper to be executed")),
}
		if (lp < pmb_nr && rp > -1 && lp < rp) {
		return 0;
			die("unable to generate diffstat for %s", one->path);
	const char *minus_begin, *minus_end, *plus_begin, *plus_end;

		/* from this point on, we are dealing with a pair
			       N_("equivalent to --word-diff=color --word-diff-regex=<regex>"),
	}
{
			adds += added;
	/* Shrink the set of potential block to the remaining running */
		switch (p->status) {
	 * abbreviation length is used--we would be fed -1 in "len" in
			return config_error_nonbool(var);
			  const char *line, int len)
	GIT_COLOR_FAINT,	/* NEW_MOVED_DIM */
		return "";
	struct diff_flags orig_flags = options->flags;
 *
		emit_diff_symbol(o, DIFF_SYMBOL_FILEPAIR_MINUS,
			  N_("suppress diff output"),
		return;
		options->context = strtol(arg, &s, 10);
			break;
		emit_diff_symbol(o, DIFF_SYMBOL_WORD_DIFF,
	FLEXPTR_ALLOC_STR(spec, path, path);
	*q = outq;
 *               infile2 infile2-sha1 infile2-mode [ rename-to ]
		if (!pe)
			p->status = DIFF_STATUS_DELETED;
	/* pathchange left =NULL by default */
	show_mode_change(opt, p, 0);
	struct strbuf msg;
	else
	diff_detect_rename_default = DIFF_DETECT_RENAME;
		}
	}
			free(to_free);
	if (one && two) {
{

	firstchar = line[0];
				continue;
	}
	free(p);
 *      word printed, a graph prefix must be printed.
			 * and return without diff_words_flush() to
				struct moved_entry *match,
	 * same as the requested length, append three dots after the
	if (0 < needed)
			return;
		     DIFF_SYMBOL_MOVED_LINE_ALT:
	struct diff_queue_struct *q = &diff_queued_diff;
		strbuf_addf(&sb,
}
			continue;
	}
	} else {
		/*
	/* user says num divided by scale and we say internally that
		reset = diff_get_color_opt(o, DIFF_RESET);

}
		if ((one->mode ^ two->mode) & S_IFMT)
 */
	options->abbrev = DEFAULT_ABBREV;
			       diff_opt_relative),
	return 0;
			ecbdata.header = &header;

 * line pointer. By storing an offset into the file instead of the literal line,
		options->flags.has_changes = 1;
	struct dirstat_dir dir;
	 * instead of refusing.
	 * All the other codepaths check both sides, but not checking

	       (s[off] == '\r' && off < len - 1))
	 * uniqueness across all objects (statistically speaking).
}
		return;
					struct hashmap *del_lines)
	for (i = 0; i < q->nr; i++) {
		if ((DIFF_FILE_VALID(p->one) && S_ISDIR(p->one->mode)) ||
			 N_("swap two inputs, reverse the diff")),
	}
		new_name--;
static struct moved_entry *prepare_entry(struct diff_options *o,
};
static int diff_suppress_blank_empty;
	GIT_COLOR_FAINT_GREEN,	/* NEW_DIM */
		if (header.len && !o->flags.suppress_diff_headers)


	if (line[0] == '+') {

			emit_diff_symbol(o, DIFF_SYMBOL_HEADER,
	}
	options->word_diff = DIFF_WORDS_COLOR;
{

				  mmfile_t *one, mmfile_t *two)
{
		emit_diff_symbol(options, DIFF_SYMBOL_STATS_SUMMARY_NO_FILES,
	int err = 0;

				   const char *name,
	case DIFF_STATUS_DELETED:

	}
	p->done_skip_stat_unmatch = 1;
	 * is probably already open and will be faster to obtain
		emit_diff_symbol(opt, DIFF_SYMBOL_SUMMARY,
	} else if (!strcmp(opt->long_name, "stat-count")) {
			  N_("ignore changes in whitespace at EOL"),
		unsigned bad;
	DIFF_SYMBOL_STAT_SEP,
			      PARSE_OPT_NONEG),
static enum parse_opt_result diff_opt_output(struct parse_opt_ctx_t *ctx,
	*buf_size = fill_textconv(r, textconv, df, buf);
N_("inexact rename detection was skipped due to too many files.");
static void append_emitted_diff_symbol(struct diff_options *o,

		fprintf(o->file, "%s%c",
		regmatch_t match[1];
	if (S_ISGITLINK(mode) && is_submodule_ignored(concatpath, options))
			  N_("condensed summary such as creations, renames and mode changes"),
				 s, strlen(s), 0);
}
	for (i = 1; i < block_length + 1; i++)

		run_diff_cmd(NULL, name, other, attr_path,

	BUG_ON_OPT_NEG(unset);
			goto empty;
			continue;
			       N_("continue listing the history of a file beyond renames"),
	buffer->orig[0].begin = buffer->orig[0].end = buffer->text.ptr;
}
	return 0;
	if (!strcmp(var, "diff.suppressblankempty") ||
		strbuf_addf(&sb, " %s mode %06o ", newdelete, fs->mode);
}

	case DIFF_STATUS_RENAMED:

		if (!p)
		}
		diff_q(queue, dp);
		struct diffstat_file *file = data->files[i];
	int ignored = 0;
	unsigned long orig_size;
	/*
}


		for (i = 0; i < esm.nr; i++)
	 */

				 line, len, 0);
		return;
{
	diffcore_apply_filter(options);
	memcpy(options, &default_diff_options, sizeof(*options));
			strbuf_addf(&out, " %s%-*s |", prefix, len, name);
		int negate;
		return 0;
		for (i = 0; i < q->nr; i++) {
#define FAST_WORKING_DIRECTORY 1
			int first, const char *line, int len)
		s->should_free = s->should_munmap = 0;
	if (one->is_binary == -1) {

	switch (firstchar) {
		return find_unique_abbrev(oid, abbrev);
	adjust_last_block(o, n, block_length);
	line++;
		 * Since generating a cache entry is the slow path anyway,



			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG,
struct diff_queue_struct diff_queued_diff;

#include "submodule-config.h"

			 const char *arg, int unset)
						   to_fetch.oid, to_fetch.nr);
			ecbdata.ws_rule = data.ws_rule;
	else if (fmt & DIFF_FORMAT_NAME) {
		len--;

}
	spec->is_binary = -1;
	const char *abbrev;
			  N_("synonym for '-p --raw'"),
		/*
		reset = diff_get_color_opt(o, DIFF_RESET);
	BUG_ON_OPT_NEG(unset);
	if (!arg)
		   *b = match->es->line,
				 unsigned long size,
	}
		OPT_CALLBACK_F(0, "stat-width", options, N_("<width>"),

			       N_("highlight whitespace errors in the 'context', 'old' or 'new' lines in the diff"),
	dir.permille = options->dirstat_permille;
			break;
	struct diff_queue_struct *q = &diff_queued_diff;
	} else {
		OPT_BIT_F(0, "check", &options->output_format,
				putc(options->line_termination, options->file);
			continue;
	 * match those of the current block and that the text of 'l' and 'cur'
		strip_prefix(o->prefix_length, &name, &other);
{
	temp->tempfile = mks_tempfile_ts(tempfile.buf, strlen(base) + 1);

		else {
		default:

	 * If ce matches the file in the work tree, we can reuse it.
static int parse_one_token(const char **arg, const char *token)


	const char *attr_path;
		free (ecbdata->diff_words->opt->emitted_symbols);
	return 0;
			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG, diff_opt_word_diff),
	if (DIFF_PAIR_UNMERGED(p)) {
		putc('\n', o->file);
	if (!q->nr)
		*outbuf = notes_cache_get(driver->textconv_cache,
	if (options->word_diff == DIFF_WORDS_NONE)

{
		len--;
	builtin_diffstat(name, other, p->one, p->two,
		OPT_CALLBACK_F('U', "unified", options, N_("<n>"),
		emit_diff_symbol(o, DIFF_SYMBOL_HEADER,
	int line_termination = opt->line_termination;

{
			return -1;
	if (diffopt->color_moved_ws_handling &
		for (i = 0; i < wol->nr; i++)
		emit_diff_symbol_from_struct(o, &e);
			continue;
static int moved_entry_cmp(const void *hashmap_cmp_fn_data,
	    options->stat_graph_width < graph_width)
	if (unset) {
	 * filename external diff should read from, or NULL if this
		options->b_prefix = b;
				add = scale_linear(add, graph_width, max_change);
			/* for backwards compatibility */

			block_length = 0;
		diff_flush_patch_all_file_pairs(options);
static struct diff_tempfile {
		/*
static int diff_opt_stat(const struct option *opt, const char *value, int unset)
	struct emit_callback *ecbdata = priv;
}
	if (options->detect_rename == DIFF_DETECT_COPY)
	 */

	GIT_COLOR_FAINT_ITALIC,	/* OLD_MOVED_ALTERNATIVE_DIM */
		/* A '-' entry produces this for file-2, and
}
static void run_diffstat(struct diff_filepair *p, struct diff_options *o,
	GIT_COLOR_RED,		/* OLD */
{
	    oideq(&one->oid, &two->oid) &&
		}
	/*
	int extra_shown = 0;
static int diff_opt_find_object(const struct option *option,
					the_hash_algo->hexsz);
			options->flags.dirstat_by_file = 0;
			      const char *name_b,
/*
		OPT_CALLBACK_F(0, "dirstat-by-file", options, N_("<param1,param2>..."),
	 * We need to check if 'cur' is equal to 'match'.  As those
		}
	unsigned long sum_changes = 0;
	char *dirty = "";
		return 1; /* both look at the same file on the filesystem. */
}
			XDF_INDENT_HEURISTIC),
		OPT_INTEGER('l', NULL, &options->rename_limit,
 * NEEDSWORK: Instead of storing a copy of the line, add an offset pointer
				   &delta_size, deflate_size);
		if (o->color_moved == COLOR_MOVED_PLAIN) {
		/* Inside a block? */
			return;
	const char *reset = diff_get_color(data->o->use_color, DIFF_RESET);
		emit_context_line(ecbdata, line + 1, len - 1);
		OPT_BOOL(0, "quiet", &options->flags.quick,
	add_c = diff_get_color_opt(options, DIFF_FILE_NEW);
	int lno_in_postimage;
}
		free(f->print_name);
	if (o->prefix_length)
		remove_tempfile();
			options->word_diff = DIFF_WORDS_PLAIN;
			xsnprintf(temp->mode, sizeof(temp->mode), "%06o", one->mode);
		if (!one->data && !two->data &&
	 * stat_name_width fixes the maximum width of the filename,
		/* store original boundaries */
	 * DIFF_FROM_CONTENTS is in effect (e.g. with -w).
	return 0;
	for (i = 0; i < data->nr; i++) {
	 * Similarly, if we'd have to convert the file contents anyway, that
			free(mf1.ptr);
	free_filespec(p->two);

			break;
		else {
		ret |= COLOR_MOVED_WS_ERROR;
	else if ((p->one->mode & 0777) == 0755 &&

	}
			  int *must_show_header,
	 * and c fails we can avoid the call all together.
		OPT_CALLBACK_F(0, "no-prefix", options, NULL,
{
		if (one->mode == two->mode)
	options->detect_rename = DIFF_DETECT_RENAME;
			  XDF_IGNORE_WHITESPACE_CHANGE, PARSE_OPT_NONEG),
			    reset, line_prefix, set);
	int n, flipped_block = 0, block_length = 0;
	if (filter_bit_tst(DIFF_STATUS_FILTER_AON, options)) {
			struct strbuf sb = STRBUF_INIT;

			free(ecbdata->diff_words->word_regex);
{
	two = alloc_filespec(concatpath);

			struct stat st;
	options->detect_rename = diff_detect_rename_default;
			if (file->is_renamed) {
			append_emitted_diff_symbol(o, &wol->buf[i]);

	lbl[1] = DIFF_FILE_VALID(two) ? b_two : "/dev/null";
	 * the currently implemented transformers, but the idea is to
		context = diff_get_color_opt(o, DIFF_CONTEXT);
	options->line_prefix_length = strlen(options->line_prefix);
		p = q->queue[i];
	 * trailing "\r\n"
	/* Never use a non-valid filename anywhere if at all possible */
	the_hash_algo->init_fn(&ctx);
	if (unset) {

	struct tempfile *tempfile;
		return 0;
		} else {
	DIFF_SYMBOL_SUBMODULE_HEADER,

	if (pgm) {
	}
		if (!match) {
			count++; /* not shown == room for one more */
		data_size = delta_size;
		}
	if (!strcmp(var, "diff.ignoresubmodules"))
{
			s->data = strbuf_detach(&sb, NULL);
	[DIFF_FILE_OLD_DIM]	      = "oldDimmed",
}
			changes = f->changed;
			emit_diff_symbol(options, DIFF_SYMBOL_SEPARATOR, NULL, 0, 0);
	 * of dots so that they match the well-behaved ones.  However,
	if (parse_dirstat_params(options, params, &errmsg))
{
		graph_width = strtoul(value, &end, 10);
	struct diff_options *opt;
	}
		name_b = NULL;
}
	 * changed" with insertions == 0 && deletions == 0.
	if (!strcmp(var, "diff.dirstat")) {

			    prev->s != DIFF_SYMBOL_MINUS)
	else if (diff_populate_filespec(r, one, 0))
	const char **arg = argv;
	struct diff_queue_struct *q = &diff_queued_diff;
	attr_path = other ? other : name;
		die(_("-G, -S and --find-object are mutually exclusive"));
		     DIFF_SYMBOL_MOVED_LINE_ALT |
/* like fill_mmfile, but only for size, so we can avoid retrieving blob */
	}
	return 0;
		o->emitted_symbols->buf[n - i].flags &= ~DIFF_SYMBOL_MOVED_LINE;
					 header.buf, header.len, 0);
			    next->s != DIFF_SYMBOL_MINUS)
		OPT_SET_INT_F('D', "irreversible-delete", &options->irreversible_delete,
	 */
		assert(insertions == 0 && deletions == 0);
		empty:

		if (lstat(name, &st) < 0) {
			  N_("treat <string> in -S as extended POSIX regular expression"),
		spec->oid_valid = oid_valid;
	options->use_color = 1;
			else
	strbuf_addstr(name, " => ");

			p->status = DIFF_STATUS_UNMERGED;
	diff_words->current_plus = plus_end;
	 * entries to the diff-core.  They will be prefixed
	char buf[12];
		options->detect_rename = DIFF_DETECT_COPY;
		}
				      struct index_state *istate)
		if (options->found_changes)
}
			      N_("treat 'git add -N' entries as real in the index"),
					 DIFF_SYMBOL_STATS_SUMMARY_ABBREV,
			  struct diff_filespec *one,
	gather_dirstat(options, &dir, changed, "", 0);
		return;
{
		OPT_GROUP(N_("Diff algorithm options")),
{
			char *end;
{
	options->add_remove = diff_addremove;

				      DIFF_FORMAT_NUMSTAT |
};
		}
		/*
}
	if (options->stat_width == -1)
	if (!strcmp(var, "diff.mnemonicprefix")) {
			       &options->output_indicators[OUTPUT_INDICATOR_NEW],
		char *name = file->print_name;
	GIT_COLOR_FAINT_ITALIC,	/* NEW_MOVED_ALTERNATIVE_DIM */
	options->rename_score = parse_rename_score(&arg);
		write_name_quoted(name_b, opt->file, line_termination);
	if (diff_queued_diff.nr && !options->flags.diff_from_contents)
					 line_prefix, strlen(line_prefix), 0);

	}
			s->data = (char *)"";
				       struct emitted_diff_symbol *e)
			if (p->one->mode && p->two->mode &&

	strbuf_reset(&b_name);
			return err;
	 * Adjust adjustable widths not to exceed maximum width
		if (find_word_boundaries(&buffer->text, word_regex, &i, &j))

			       diff_opt_dirstat),
	diff_words->minus.text.size = diff_words->plus.text.size = 0;
			strbuf_addf(msg, " %06o", one->mode);
	BUG_ON_OPT_NEG(unset);
	}
	GIT_COLOR_FAINT,	/* CONTEXT_DIM */
	dp->one = one;
		l->flags |= DIFF_SYMBOL_MOVED_LINE_UNINTERESTING;
				&style->new_word, style->newline,
				flipped_block = (flipped_block + 1) % 2;
	/*

		OPT_BITOP(0, "histogram", &options->xdl_opts,
	mmfile_t mf1, mf2;
	*out = delta;
	if (want_color(diff_use_color))

				 unsigned long *result_size)
	 * this tempfile object is used to manage its lifetime.
				 const struct moved_entry *match,
		return df->size;
			sources += 2;
	return temp;
			lp++;
			     const char *arg, int unset)
			  XDF_HISTOGRAM_DIFF, XDF_DIFF_ALGORITHM_MASK),

	const char *name_a, *name_b;

				const char *set_sign, const char *set,
	ecbdata->lno_in_preimage = strtol(p + 1, NULL, 10);
	}
	default:
				while (isdigit(*++end))
		break;
		the_hash_algo->update_fn(&ctx, p->one->path, len1);
		pmb->wsd = delta;
		int len;
	}
			strbuf_reset(&header);
}
	struct strbuf out = STRBUF_INIT;
		}
	}
	    b_off = b->indent_off,
	diff_words->current_plus = diff_words->plus.text.ptr;
	diff_debug_queue("resolve-rename-copy", q);
				abbrev = hexsz;
					 out.buf, out.len, 0);
			flipped_block = 0;
	for (i = 0; i < ARRAY_SIZE(diff_words_styles); i++) {
				oid_to_hex_r(temp->hex, &null_oid);
	for (i = 0; i < q->nr; i++) {
	other = (strcmp(name, two->path) ? two->path : NULL);
		if (complete_rewrite &&
		quote_c_style(name, msg, NULL, 0);


	 * exit code in such a case either.
		struct moved_entry *prev = pmb[i].match;
	} else {

	else {
			       diff_opt_find_copies),

	ecbdata->lno_in_postimage = strtol(p + 1, NULL, 10);
	struct diff_options *opt = option->value;

		switch (flags & (DIFF_SYMBOL_MOVED_LINE |

		if (!file->is_binary) {
				plus_end - plus_begin, plus_begin);
		strbuf_add(&msgbuf, cp, ep - cp);
			int insertions, int deletions)
			}
		return error(_("invalid argument to %s"), opt->long_name);
			else if (--p->one->rename_used > 0)


		} else {
		 * we'd need to check for a new block, so ignore all

			     opt->long_name, arg);
	else if (!strcasecmp(value, "minimal"))
			XDF_NEED_MINIMAL),
		 * aren't supposed to produce any output anyway.
	free(pmb);
{

			break;
				total = 2;
{
	argv_array_push(&argv, pgm);
int diff_populate_filespec(struct repository *r,
	 * merged into rename/copy pairs as appropriate.
						pmb[pmb_nr++].match = match;

	}
		return;
		/* Quite common confusing case */
};


static int parse_diff_color_slot(const char *var)
#endif

	if (!endp)
}
			       diff_opt_dirstat),
	DIFF_SYMBOL_SUBMODULE_UNTRACKED,
	DIFF_STATUS_UNMERGED,
	 * If there is a negation e.g. 'd' in the input, and we haven't
		xdiff_clear_find_func(&xecfg);
static int similarity_index(struct diff_filepair *p)
	if (!DIFF_FILE_VALID(one)) {
		break;
			set = diff_get_color_opt(o, DIFF_FILE_OLD_MOVED_ALT);
	} else if (!strcmp(opt->long_name, "stat-graph-width")) {
			   const void *keydata)
	 *    one side of the object name is unknown, with
		flags |= DIFF_SYMBOL_CONTENT_BLANK_LINE_EOF;
				die("cannot hash %s", one->path);
			 * add this file to the list of results
			diffcore_count_changes(options->repo,
	free(got_match);
	case DIFF_SYMBOL_SUBMODULE_UNTRACKED:
					err = whitespace_error_string(WS_BLANK_AT_EOF);
	}
		diffcore_skip_stat_unmatch(options);
	new_name = b + len_b;
{
	if (need_one + need_two) {
			if (blank_at_eof) {
				p->status = DIFF_STATUS_RENAMED;
	 */
		name = p->two->path ? p->two->path : p->one->path;
static int diff_dirstat_permille_default = 30;

		OPT_CALLBACK_F('S', NULL, options, N_("<string>"),
	const struct diff_filepair *a = *((const struct diff_filepair **)a_);
	}
	ecbdata->blank_at_eof_in_postimage = (at - l2) + 1;
void setup_diff_pager(struct diff_options *opt)
static void fill_print_name(struct diffstat_file *file)
		if (fill_mmfile(o->repo, &mf1, one) < 0 ||
	 * report our exit code even when a pager is run, we _could_ run a
}
	 * We have width = stat_width or term_columns() columns total.
		die(_("--name-only, --name-status, --check and -s are mutually exclusive"));
	}
		if (!isspace((c = line[i])))
		}


				goto free_ab_and_return;
#include "graph.h"
	return result;
{

{
		strbuf_release(&buf);
			- diff_words->current_plus, diff_words->current_plus);
	argv_array_clear(&argv);
		emit_diff_symbol(o, DIFF_SYMBOL_FILEPAIR_PLUS,
			diff_flush_stat(p, options, diffstat);
		else if (!oideq(&p->one->oid, &p->two->oid) ||
				 struct diff_filespec *two)
	 *

		ALLOC_GROW(out->ptr, out->size + j - i + 1, alloc);
			  DIFF_PICKAXE_REGEX, PARSE_OPT_NONEG),
		if (o->flags.binary)
					pmb[pmb_nr].wsd = 0;
		/* Not a moved line? */
	if (!(opt->output_format & DIFF_FORMAT_NAME_STATUS)) {
		 * through convert_to_git().  This may not strictly be

};
	if ((ce->ce_flags & CE_VALID) || ce_skip_worktree(ce))
				      struct diff_filespec *two)
	 * pfx{sfx-a => sfx-b}
	 * git-completion.bash when you add new formats.
		count = strtoul(value, &end, 10);

	int i;
			     addremove == '-' ? '+' : addremove);


	/*
	for (i = 0; i < len; i++)
	struct diff_words_orig {
			diff_line_prefix(o), line);

		enum diff_symbol s =
	else if ((p->one->mode & 0777) == 0644 &&
		for (i = 0; i < q->nr; i++) {
static void remove_tempfile(void)
			  N_("ignore changes whose lines are all blank"),
			diff_words->minus.text.size,
		diff_color_moved_ws_default = cm;
	if (!((ecbdata->ws_rule & WS_BLANK_AT_EOF) &&
	 */
			     const char *arg, int unset)
		else if (!strcmp(arg, "color")) {
	options->pickaxe = arg;
	*optarg = argv[1];
			free_diff_words_data(&ecbdata);
		fprintf(o->file, "%sSubmodule %s contains modified content\n",
		   const char **optarg)
	if (one && two && !oideq(&one->oid, &two->oid)) {
			ecb->lno_in_postimage++;
		strbuf_addstr(name, " => ");
		 */
			promisor_remote_get_direct(options->repo,
			if (!cur)
							 header.buf, header.len,
		if (set_sign && set != set_sign)
	const int len = es->len;

	int nr, alloc;
};
		} else {
		reset = diff_get_color_opt(o, DIFF_RESET);

			if (c == '+')
	unsigned long data_size;
/* Find blocks of moved code, delegate actual coloring decision to helper */
{
	int fmt = opt->output_format;
		emit_line(o, context, reset, line, len);
	 * guaranteed minimum width of the filename part and the
	 * or --exit-code. We should definitely not bother with a pager in the
	if (arg[1])
static void emit_diff_symbol(struct diff_options *o, enum diff_symbol s,
	if (!len)
		return -1;

	const char **label_path;

		if (xdi_diff_outf(&mf1, &mf2, discard_hunk_line,
			       &options->output_indicators[OUTPUT_INDICATOR_CONTEXT],
	const char *line_prefix = diff_line_prefix(o);
			xmalloc(sizeof(regex_t));
	}
	data.o = o;
		show_submodule_inline_diff(o, one->path ? one->path : two->path,
	struct dirstat_file *files;
	 * demote FAIL to WARN to allow inspecting the situation
	/*
	}

#include "packfile.h"


static int diff_opt_color_moved(const struct option *opt,
		patch_id_add_string(&ctx, "b/");
				&o->emitted_symbols->buf[n - 1] : NULL;
		name_len = strlen(name);
	options->ws_error_highlight = ws_error_highlight_default;
	/* This can happen even with many files, if everything was renames */
			       PARSE_OPT_NONEG, diff_opt_stat),
	char *ptr = mf->ptr;
	 * makes the optimization not worthwhile.
	else {
{
			return 0;
			options->flags.dirstat_by_line = 0;
	}
	 * make sure that at least one '-' or '+' is printed if
	for (i = 0; i < q->nr; i++) {
	    strcmp(one->path, two->path))
static int shrink_potential_moved_blocks(struct moved_block *pmb,
	default:


	pfx_adjust_for_slash = (pfx_length ? 1 : 0);
	long alloc = 0;
		run_external_diff(pgm, name, other, one, two, xfrm_msg, o);
		return 0;
			}
		 * made to the preimage.
	diff_free_filespec_data(one);
		struct diff_options *o)

	}

	if (ce_uptodate(ce) ||
		return oid_to_hex(oid);
		return 0;
	options->b_prefix = "";

		options->color_moved = cm;
					  const char *name_b)
static void diff_words_flush(struct emit_callback *ecbdata)
	}
			hm = add_lines;
				one->is_binary = buffer_is_binary(one->data,
	struct diff_options *o;
		if (max_len < len)
	if (diff_unmodified_pair(p))
	else if (!strcmp(arg, "blocks"))

	git_hash_ctx *ctx;
		width = options->stat_width ? options->stat_width : 80;
	[DIFF_FILE_OLD_BOLD]	      = "oldBold",
{
	}
		     (!textconv_two && diff_filespec_is_binary(o->repo, two)) )) {
			break;
			 sb.buf, sb.len, 0);
			return "gone";
	strbuf_add(&msgbuf, line + len, org_len - len);

	int i;
			int permille = strtoul(p, &end, 10) * 10;
			     one, two, xfrm_msg, must_show_header,
}
	case ' ':
		pmb_nr = shrink_potential_moved_blocks(pmb, pmb_nr);
	case 1:
		return;
		}
		}
	/*
			       diff_opt_patience),

	return p->skip_stat_unmatch_result;
}
	struct patch_id_t data;
int diff_flush_patch_id(struct diff_options *options, struct object_id *oid, int diff_header_only, int stable)
	 */
}
	xecfg.ctxlen = 0;
		add_line_count(&out, lc_a);
	int width, name_width, graph_width, number_width = 0, bin_width = 0;
		break;
	 * introduced changes, and as long as the "new" side is text, we
		case DIFF_SYMBOL_MOVED_LINE |
			ret++;
	if (strbuf_read(&buf, child.out, 0) < 0)
		break;


		buffer->orig[buffer->orig_nr].end = buffer->text.ptr + j;
				    flags & DIFF_SYMBOL_CONTENT_WS_MASK,
	    (p->one->oid_valid && p->two->oid_valid) ||
	if (!one->oid_valid && !two->oid_valid)
		       const char *set, const char *reset)
		OPT_CALLBACK_F(0, "ws-error-highlight", options, N_("<kind>"),
		return "mode -x";

			delete_tempfile(&diff_temp[i].tempfile);
			    const struct emitted_diff_symbol *b,
		set = diff_get_color_opt(o, DIFF_CONTEXT);
	emit_diff_symbol(o, DIFF_SYMBOL_SUBMODULE_DEL, line, strlen(line), 0);
			     struct diff_filespec *two,
			  N_("warn if changes introduce conflict markers or whitespace errors"),
 * prepare_temp_file() does not have to inflate and extract.
			BUG("how come --cumulative take a value?");
	case DIFF_SYMBOL_WORDS:
		    s->size > big_file_threshold && s->is_binary == -1) {
			fprintf(options->file, "-\t-\t");
			       N_("<char>"),
			options->word_diff = DIFF_WORDS_NONE;
			/*
		arg = "";
		OPT_CALLBACK_F(0, "relative", options, N_("<prefix>"),
	if (*begin >= buffer->size)
{



	int qlen_b = quote_c_style(b, NULL, NULL, 0);
	if (!temp->tempfile)
		quote_c_style(file->name, &pname, NULL, 0);

		return status;
	else if (lbl[1][0] == '/') {
	options->line_termination = '\n';
			block_length++;
{
	GIT_COLOR_BOLD,		/* METAINFO */
	ecbdata->blank_at_eof_in_preimage = (at - l1) + 1;
	if (output_format & (DIFF_FORMAT_RAW |
	int n;
			}
		return COLOR_MOVED_DEFAULT;
{
}
	else if (!strcmp(arg, "dimmed_zebra"))
	strbuf_release(&sb);
		if (p->status == DIFF_STATUS_ADDED) {
	if (want_color(o->use_color)) {
		 * is probably fine.
			/*

	if (!opt->objfind)
	size_t size;
	if (!--spec->count) {
			;
		   filter_bit_tst(DIFF_STATUS_FILTER_BROKEN, options)) ||
			  DIFF_FORMAT_PATCH | DIFF_FORMAT_DIFFSTAT,
			patch_id_add_mode(&ctx, p->one->mode);
	int orig_nr, orig_alloc;
		fputc('\n', file);

}
	return 0;
	git_deflate_end(&stream);
}
			       N_("output a binary diff that can be applied"),
		return 0;
			prev = NULL;

	} *orig;
		find_lno(line, ecbdata);
}

{
	ecbdata->diff_words->opt = o;


static int diff_opt_anchored(const struct option *opt,
	}
	struct checkdiff_t data;
static const char degrade_cc_to_c_warning[] =
	return !memcmp(one->data, two->data, one->size);
	}
	 * This must be signed because we're comparing against a potentially
	 */
				return "new";
		name_width = strtoul(value, &end, 10);
static int diff_opt_textconv(const struct option *opt,

static int match_filter(const struct diff_options *options, const struct diff_filepair *p)
		xecfg.flags = 0;
				    const char *arg, int unset)
		emit_line(o, context, reset, line, len);
 *      that is: the plus text must start as a new line, and if there is no minus
	}
	if (addremove != '+')
		OPT_BIT_F(0, "ignore-space-at-eol", &options->xdl_opts,
}
	ecbdata->diff_words->type = o->word_diff;
	if (mode) {
	 * inside contents.
			if (!one->oid_valid)
#include "delta.h"

		if (o->word_diff == diff_words_styles[i].type) {
	 * tree.  This is because most diff-tree comparisons deal with


static void show_stats(struct diffstat_t *data, struct diff_options *options)
		xdemitconf_t xecfg;
	if (o->color_moved)
	return 0;
	} else {
		return error(_("%s expects <n>/<m> form"), opt->long_name);
	int opt1, opt2;

			if (type < 0)

{
 */
				       const char *arg, int unset)
					 struct emitted_diff_symbol *eds)
{
						one->size);
						ent);
	const char *other;
		xecfg.interhunkctxlen = o->interhunkcontext;
				 s, strlen(s), 0);
	struct diff_options *options = opt->value;
			adds += added;
			  const char *line, int len)
	DIFF_SYMBOL_FILEPAIR_PLUS,
		 * we do not run diff between different kind
		s->data = NULL;
	    skip_prefix(var, "color.diff.", &name)) {
	const char *meta = diff_get_color_opt(o, DIFF_METAINFO);
	if (data.status)
}

		 * opening the file and inspecting the contents, this
	 * We want a maximum of min(max_len, stat_name_width) for the name part.
		plus_end = diff_words->plus.orig[plus_first + plus_len - 1].end;
		return;

		   options->anchors_alloc);
	DIFF_STATUS_MODIFIED,
			show_dirstat_by_line(&diffstat, options);
		xpp.anchors_nr = o->anchors_nr;
			strbuf_addf(&sb, " (%d%%)\n", similarity_index(p));
	int sign = o->output_indicators[sign_index];
	    !(opt->output_format & DIFF_FORMAT_CHECKDIFF))
 * If o->color_moved is COLOR_MOVED_PLAIN, this function does nothing.

static void add_lines_to_move_detection(struct diff_options *o,
			damage = 1;
	ALLOC_GROW(options->anchors, options->anchors_nr + 1,
			      data->o->file, set, reset, ws);
				 ecbdata->label_path[0],
	DIFF_SYMBOL_SUBMODULE_MODIFIED,
	int blank_at_eof_in_postimage;
	for (i = 0; i < q->nr; i++) {
		return DIFF_DETECT_RENAME;
 * Submodule changes can be configured to be ignored separately for each path,
		two->dirty_submodule = dirty_submodule;
struct diff_filepair *diff_unmerge(struct diff_options *options, const char *path)
	if ((output_format & DIFF_FORMAT_DIRSTAT) && !dirstat_by_line)
	else
			break;
		for (i = 0; i < q->nr; i++) {

			diff_free_filepair(q->queue[i]);
			dels += deleted;
	struct diff_options *options = opt->value;
{
	if (!arg)
			     DIFF_FORMAT_NAME |
	options->output_indicators[OUTPUT_INDICATOR_CONTEXT] = ' ';
		strbuf_addf(&out, " %s%-*s |", prefix, len, name);
		    unsigned long *buf_size)
		if (options->flags.dirstat_by_file) {
		es->indent_width = width;
	switch (git_parse_maybe_bool(arg)) {
		data->lineno++;
	return 0;
	struct strbuf *header;
		/* rp points at the last non-NULL */
				     opt->long_name);
		if (o->flags.dual_color_diffed_diffs) {
	if (deletions || insertions == 0) {
	return 1;
{
					    int pmb_nr, int n)
			next = NULL;
	a = container_of(eptr, const struct moved_entry, ent);
		oidcpy(&spec->oid, oid);

			fputs(reset, file);
	struct emitted_diff_symbol *f;
	}
	    a_width = a->indent_width,
	free(path_dup);
		     DIFF_SYMBOL_MOVED_LINE_ALT:

 *
		xecfg.ctxlen = o->context;
	     reuse_worktree_file(r->index, name, &one->oid, 1))) {
	if (!value)
			char *slash;
		int len1, len2;
		else if (parse_one_token(&arg, "new"))
}
	struct diff_options *options = opt->value;
					if (compute_ws_delta(l, match->es,
	struct diff_options *options = opt->value;
	if (*arg != 0)
		}
}
	options->output_format |= DIFF_FORMAT_DIFFSTAT;
	emit_diff_symbol(o, DIFF_SYMBOL_SUBMODULE_PIPETHROUGH, line, len, 0);
static void emit_rewrite_diff(const char *name_a,
		conv_flags = CONV_EOL_RNDTRP_WARN;
		 * If prev or next are not a plus or minus line,
			continue;
			       N_("run external text conversion filters when comparing binary files"),
			 * This is stupid and ugly, but very cheap...
static const char *diff_word_regex_cfg;
 *
		 * in the queue.
	 * bit longer than the requested length, we reduce the number

		OPT_SET_INT_F(0, "ita-visible-in-index", &options->ita_invisible_in_index,

	if (o->irreversible_delete && lbl[1][0] == '/') {
}
	strbuf_complete_line(&msgbuf);
			       N_("generate diffs with <n> lines context"),
	emit_diff_symbol(options, DIFF_SYMBOL_STATS_SUMMARY_INSERTS_DELETES,
		for (i = 0; i < q->nr; i++)
			  N_("show only names and status of changed files"),
	}
			int total = scale_linear(add + del, graph_width, max_change);
		free(f);
		fputc(first, file);
	DIFF_SYMBOL_SUBMODULE_PIPETHROUGH,
	struct diff_filespec *one = p->one;
	/*
		len = sane_truncate_line(line, len);
	}
		diff_populate_filespec(o->repo, one, 0);
	return dp;
			if (*end == ',')
			 struct diff_filespec *one,
		return 1;
	if (reverse && want_color(o->use_color)) {
	struct diff_options *options = opt->value;
		return error(_("invalid mode '%s' in --color-moved-ws"), arg);

			/* "Bin XXX -> YYY bytes" */
	if (queue)
		    (textconv_one || !diff_filespec_is_binary(o->repo, one)) &&
				add_c, added, reset);
	struct diff_filespec *df;
}
	    memcmp(a->line + a_off, b->line + b_off, a_len - a_off))
	 * If ce is marked as "assume unchanged", there is no
			moved_block_clear(&pmb[i]);
		key = prepare_entry(o, n);
	}
			hashmap_free_entries(&del_lines, struct moved_entry,
			goto out;
		goto end_of_line;
			goto free_ab_and_return;
	}
	if (o->emitted_symbols)
		else
	 */
}
	[DIFF_CONTEXT_DIM]	      = "contextDimmed",
static void diff_flush_raw(struct diff_filepair *p, struct diff_options *opt)
}
}
	if (wo->emitted_symbols) {
			 N_("show full pre- and post-image object names on the \"index\" lines")),

	}
			  N_("output only the last line of --stat"),
			line[0] = bytes + 'A' - 1;
#define EMITTED_DIFF_SYMBOLS_INIT {NULL, 0, 0}
}
		/*
		struct oid_array to_fetch = OID_ARRAY_INIT;
		/*
}
{
	struct patch_id_t *data = priv;
			      struct userdiff_driver *textconv_one,
			 path, strlen(path), 0);
			options->flags.has_changes = 1;
		return hex;
		else if (!strcmp(sb.buf, "allow-indentation-change"))
		goto free_ab_and_return;
		OPT_BITOP(0, "patch-with-raw", &options->output_format,
			negate = 0;

		}


		for (i = 0; i < esm.nr; i++)
	diff_fill_oid_info(p->two, o->repo->index);
		break;
	l1 = count_trailing_blank(mf1, ws_rule);
		struct diffstat_file *file = data->files[i];
			prep_temp_blob(r->index, name, temp, sb.buf, sb.len,
	}
	spec->count = 1;
	s->size = buf.len;
{
	diff_fill_oid_info(p->one, o->repo->index);
			  DIFF_FORMAT_NAME_STATUS, PARSE_OPT_NONEG),
	for (i = 0; i < q->nr; i++) {
	/*

		return 1;
	else
 *
	emit_diff_symbol(opt, DIFF_SYMBOL_SUMMARY,
		else if (parse_one_token(&arg, "old"))
				die_errno("readlink(%s)", name);

		if (prefix != '+') {
	[DIFF_FILE_NEW_MOVED_DIM]     = "newMovedDimmed",
	other = (strcmp(name, p->two->path) ? p->two->path : NULL);
		return; /* cannot happen */

	buffer->orig_nr = 1;
 * '--color-words' algorithm can be described as:
{
	if (options->output_format & (DIFF_FORMAT_NAME |
			key = prepare_entry(o, n);
			 * The fact that the SHA1 changed is enough for us to
		return 0;
	default:
	 * is probably less confusing (i.e skip over "2 files changed
		st->old_word.color = diff_get_color_opt(o, DIFF_FILE_OLD);
			 struct strbuf *msg,
			patch_id_add_string(&ctx, "+++b/");
	} else {
	if (!strcmp(var, "diff.wordregex"))
		if (parse_one_token(&arg, "none"))
}
	}
	DIFF_SYMBOL_BINARY_FILES,



		external_diff_cmd = external_diff_cmd_cfg;
		fn_out_diff_words_write_helper(diff_words->opt,
	xpparam_t xpp;
	DIFF_SYMBOL_HEADER,
		data->is_binary = 1;

	unsigned flags = WSEH_CONTEXT | ecbdata->ws_rule;
	const char *line;
			     diff_filespec_is_binary(o->repo, two)))


	if (first)
static int diff_opt_unified(const struct option *opt,
	len--;
	one = alloc_filespec(concatpath);
}
				&style->old_word, style->newline,
	}
		case DIFF_STATUS_COPIED:
		carry += result->hash[i] + hash[i];
int git_config_rename(const char *var, const char *value)

		if (!DIFF_FILE_VALID(df)) {
	}
			return error("internal diff status error");
	/*
{
	int wsd; /* The whitespace delta of this block */
	data.ws_rule = whitespace_rule(o->repo->index, attr_path);
		return "mode +l";
		    (textconv_two || !diff_filespec_is_binary(o->repo, two))) {
			  DIFF_FORMAT_CHECKDIFF, PARSE_OPT_NONEG),
{
					struct hashmap *add_lines,
		ecbdata->blank_at_eof_in_postimage = 0;
		emit_diff_symbol(o, DIFF_SYMBOL_BINARY_DIFF_HEADER_DELTA,
	for ( ; i < 3; i++)
{
			       opt->degraded_cc_to_c);
		mf->size = 0;
				    flags & DIFF_SYMBOL_CONTENT_WS_MASK, 0);
static void diff_resolve_rename_copy(void)
};
			l->flags |= DIFF_SYMBOL_MOVED_LINE;
	parse_dirstat_opt(options, arg ? arg : "");
	else
}
	a_midlen = len_a - pfx_length - sfx_length;
		/*
			options->color_moved = COLOR_MOVED_DEFAULT;


			   const struct diff_filespec *filespec)
		 */

	for (i = 0; i < diffstat->nr; i++) {
		xpp.flags = 0;
			emit_diff_symbol(options,
static const char diff_status_letters[] = {
	 * are from the same (+/-) side, we do not need to adjust for
	 * pfx{mid-a => mid-b}sfx
	if (output_format & DIFF_FORMAT_PATCH) {
	[DIFF_FILE_NEW_DIM]	      = "newDimmed",
static void enable_patch_output(int *fmt)
	two = alloc_filespec(concatpath);
{
}
		if (output_format & DIFF_FORMAT_DIFFSTAT)
	name_b = b->one ? b->one->path : b->two->path;
				return 0;
		error(_("color-moved-ws: allow-indentation-change cannot be combined with other whitespace modes"));
			 struct diffstat_t *diffstat)
	}
		OPT_BOOL(0, "exit-code", &options->flags.exit_with_status,
		if (lstat(s->path, &st) < 0) {
		emit_line(data->o, set, reset, line, 1);
	FREE_AND_NULL(s->cnt_data);
			}


	 * from full set of bits, except for AON.
	needs_reset = 1; /* 'line' may contain color codes. */
	switch (p->status) {
	return 0;
}
			xecfg.ctxlen = strtoul(v, NULL, 10);
			 */

		SWAP(old_dirty_submodule, new_dirty_submodule);
{

	}
	 * If there is a common prefix, it must end in a slash.  In

			options->flags.dirstat_by_file = 0;

		*arg = rest;
			patch_id_add_mode(&ctx, p->two->mode);
			    int *out)

	'\0',
	if ((ret & COLOR_MOVED_WS_ALLOW_INDENTATION_CHANGE) &&
static void check_blank_at_eof(mmfile_t *mf1, mmfile_t *mf2,
				strbuf_addch(&out, '\n');
	const struct diff_filepair *b = *((const struct diff_filepair **)b_);
int diff_result_code(struct diff_options *opt, int status)
		if ( !dot && ch == '.' ) {
				plus_begin - diff_words->current_plus,
	GIT_COLOR_FAINT_RED,	/* OLD_DIM */
		    (next &&

		    oideq(&p->one->oid, &p->two->oid)) {
	} else {

	}
unsigned diff_filter_bit(char status)
	if (diff_words->current_plus != diff_words->plus.text.ptr +
					prev->next_line : NULL;
		     DIFF_SYMBOL_MOVED_LINE_UNINTERESTING:
			 * Otherwise, see if this source was used for
static int diff_filespec_is_identical(struct repository *r,
	 */
	if (b_midlen < 0)
	if (driver->textconv_cache && df->oid_valid) {
}
		wol->nr = 0;
	 *
		arg = "cumulative";
			       N_("generate diffstat with a given graph width"),

			patch_id_add_string(&ctx, "---a/");
		diff_algorithm = parse_algorithm_value(value);
		return diff_populate_gitlink(s, size_only);
	while (count) {
			 * A rename might have re-connected a broken
	strbuf_addstr(&out, "@@ -");
}
			strbuf_addf(&sb, "%sBinary files %s and %s differ\n",
		int cm = parse_color_moved(arg);
static void show_rename_copy(struct diff_options *opt, const char *renamecopy,

				/* attach patch instead of inline */
}
		handle_ignore_submodules_arg(&default_diff_options, value);
	if (!skip_prefix(arg, "--", &arg))
		}
	if (*arg == '=') { /* stuck form: --option=value */
		const char *name_a, *name_b;
			       N_("synonym for --dirstat=files,param1,param2..."),
		OPT_CALLBACK_F(0, "diff-filter", options, N_("[(A|C|D|M|R|T|U|X|B)...[*]]"),
#define DIFF_SYMBOL_MOVED_LINE_ALT		(1<<18)

			fill_es_indent_data(&o->emitted_symbols->buf[n]);
		free_diffstat_info(&diffstat);
	count = 0;

				line_prefix, data->filename, data->lineno);
	struct diff_options *o = xmalloc(sizeof(struct diff_options));
	return "";
}
		diff_context_default = git_config_int(var, value);
			       PARSE_OPT_NONEG, diff_opt_word_diff_regex),
				     struct diff_filespec *one)
	if (o->prefix_length)
}
static int diff_color_moved_ws_default;
}
	if (options->flags.quick) {
	BUG_ON_OPT_NEG(unset);
		strbuf_release(&errmsg);
	 */

	if (a_width == INDENT_BLANKLINE && b_width == INDENT_BLANKLINE) {
		int deleted = data->files[i]->deleted;

		} else if (line[0] == '+') {
		reset = diff_get_color_opt(o, DIFF_RESET);
{
		builtin_diff(name, other ? other : name,

	} else {
	if (!options->found_follow) {
	const char *color; /* NULL; filled in by the setup code if
	if (fill_mmfile(o->repo, &mf1, one) < 0 ||
}
		if (check_pair_status(p))
		options->color_moved_ws_handling = 0;
		; /* incomplete line */
				set = diff_get_color_opt(o, DIFF_FRAGINFO);
		return 0;
				&diff_words_styles[i];
			       opt->needed_rename_limit,
				if (!err)
	options->rename_score = parse_rename_score(&arg);
			/* "Unmerged" is 8 characters */
	int i, output_format = options->output_format;
	data->lineno = nb - 1;

	enable_patch_output(&options->output_format);
	GIT_COLOR_BOLD_CYAN,	/* NEW_MOVED */
	if (DIFF_FILE_VALID(one)) {
	return 0;
				diff_words->current_plus);
}
			 * saw a "+" or "-" line with nothing on it,
static int parse_color_moved(const char *arg)
	 * From here name_width is the width of the name area,
			return diff_temp + i;
	if ((DIFF_FILE_VALID(p->one) && S_ISDIR(p->one->mode)) ||
	} else if (blank_at_eof)

		} else {
		return -1;
		if (stable)
		if (separator) {
		return error(_("failed to parse --submodule option parameter: '%s'"),
		struct diff_filepair *p = q->queue[i];
			return 0;
	if (conv_flags & CONV_EOL_RNDTRP_DIE)
		return 1;
static int parse_ws_error_highlight(const char *arg)
		if (p->status == DIFF_STATUS_UNKNOWN)
			show_numstat(&diffstat, options);
static void strip_prefix(int prefix_length, const char **namep, const char **otherp)
}
	GIT_COLOR_BOLD_MAGENTA,	/* OLD_MOVED */
		xsnprintf(temp->hex, sizeof(temp->hex), ".");
		}
	}
	DIFF_SYMBOL_BINARY_DIFF_BODY,
static const char rename_limit_warning[] =
	    !DIFF_FILE_VALID(p->two) ||
			    pmb_nr && last_symbol != l->s)
{
	}
}
	char *a_one, *b_two;
		}
			set = diff_get_color_opt(o, DIFF_FILE_NEW_MOVED_ALT);
	if (lc_a && !o->irreversible_delete)
	const char *orig_arg = arg;
	const char *name;
		if (diff_filespec_is_binary(options->repo, p->one) ||
		fputs(diff_line_prefix(o), o->file);

		OPT_GROUP(N_("Other diff options")),
	/*
		 filter_bit_tst(p->status, options)));
	}
	if ((diff_words->last_minus == 0 &&

{
{
 *   3. use xdiff to run diff on the two mmfile_t to get the words level diff;
	options->repo = r;
			continue;
			if (flipped_block && o->color_moved != COLOR_MOVED_BLOCKS)
		}
			       diff_opt_submodule),

	unsigned long changed;
		}

}
		}

	 * expensive for a large project, and its cost outweighs the
		int val = parse_ws_error_highlight(value);
}
			   PARSE_OPT_STOP_AT_NON_OPTION);
		*outbuf = df->data;
		char *slash;
		   (!two->mode || S_ISGITLINK(two->mode))) {
			  DIFF_FORMAT_SHORTSTAT, PARSE_OPT_NONEG),
	for (i = 0; (i < count) && (i < data->nr); i++) {
			*outbuf = "";
		ecbdata->lno_in_preimage++;

			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG,
	data = diffstat_add(diffstat, name_a, name_b);
	abblen = strlen(abbrev);
	if (color_words_output_graph_prefix(diff_words)) {
	}
	if (!p)
			   const struct hashmap_entry *eptr,
		struct diff_filepair *p = q->queue[i];
				data.status = 1; /* report errors */
	}
	if (!arg)
		options->flags.textconv_set_via_cmdline = 1;
		return 0;
		for (i = 0; i < wol->nr; i++)
		return COLOR_MOVED_BLOCKS;
		st->new_word.color = diff_get_color_opt(o, DIFF_FILE_NEW);
			    o->word_regex,
	if (diff_populate_filespec(r, one, 0))

			else if (c == '-')
	int lineno;
		break;
			fclose(options->file);

{
	while (git_deflate(&stream, Z_FINISH) == Z_OK)

	if (ecbdata.ws_rule & WS_BLANK_AT_EOF) {
			return 0;
{
		buffer->orig[buffer->orig_nr].begin = buffer->text.ptr + i;

}
	 * matching so we do have to check if they are equal. Here we
		for (i = 0; i < q->nr; i++) {
	if (finish_command(&child) || err) {

		if (pmb_nr) {
			      struct userdiff_driver *textconv_two,
		OPT_STRING_F(0, "dst-prefix", &options->b_prefix, N_("<prefix>"),
		if (cm < 0)
			the_hash_algo->update_fn(&ctx, p->two->path, len2);
				strbuf_reset(&out);
	emit_diff_symbol(opt, DIFF_SYMBOL_SUMMARY,
	options->color_moved_ws_handling = cm;
		regex_t *word_regex)

	 * --exit-code" in hooks and other scripts, we do not do so.
	options->file = stdout;
		struct moved_entry *key;
		old_name--;
		 const struct object_id *new_oid,
				set = diff_get_color_opt(o, DIFF_CONTEXT_BOLD);
		 * Convert from working tree format to canonical git format
		break;
}
	const char *ws = diff_get_color(data->o->use_color, DIFF_WHITESPACE);
	init_checkout_metadata(&meta, NULL, NULL, oid);
			 diffstat, o, p);
		write_name_quoted(name_a, opt->file, line_termination);
	strbuf_add(name, b + pfx_length, b_midlen);
static void diff_flush_stat(struct diff_filepair *p, struct diff_options *o,
		break;
					       &copied, &added);
static void pmb_advance_or_null(struct diff_options *o,
	int bound;
		    (next->flags & DIFF_SYMBOL_MOVED_LINE_ALT) !=
	struct strbuf tempfile = STRBUF_INIT;

		uintmax_t added = file->added;
							 0);
		emit_diff_symbol(options, DIFF_SYMBOL_STATS_LINE,
	FILE *file = o->file;
	}
	 * similarly to the graph part, except that it is not
	 * If there's not enough space, we will use the smaller of
		needs_reset = 1;
	dir.nr = 0;
	 */
}
		OPT_CALLBACK_F(0, "word-diff", options, N_("<mode>"),
	    c_width = l->indent_width;
	int len;
		return 0;
	case DIFF_SYMBOL_FILEPAIR_MINUS:
				return 0;
	}
		p->skip_stat_unmatch_result = 1;
#include "run-command.h"
	if (new_blank_line_at_eof(ecbdata, line, len))
	options->line_prefix = optarg;
					 sb.buf, sb.len, 0);
			strbuf_release(&sb);
			    COLOR_MOVED_WS_ALLOW_INDENTATION_CHANGE)
{
		return 0;
	ac = parse_options(ac, av, prefix, options->parseopts, NULL,
 */
static void flush_one_pair(struct diff_filepair *p, struct diff_options *opt)
		reset = diff_get_color_opt(o, DIFF_RESET);
	if (size_only) {
	 * 2. At this point, the file is known to be modified,
		OPT_CALLBACK_F('C', "find-copies", options, N_("<n>"),
	return x;
	argv_array_push(argv, temp->hex);
	memset(&data, 0, sizeof(data));
		data_size -= bytes;
	struct diff_tempfile *temp;

			 * Setup the set of potential blocks.
	 * 1. Entries that come from stat info dirtiness
	[DIFF_FILE_NEW_BOLD]	      = "newBold",
	mmfile_t minus, plus;
		diff_fill_oid_info(p->two, options->repo->index);
	return 0;
}
 *   2. diff_words->current_plus > diff_words->plus.text.ptr &&
	if (!strcmp(var, "diff.interhunkcontext")) {
{
	static const char atat[2] = { '@', '@' };
	if (options->prefix &&
			      struct diff_filespec *one,
	if (sb.len)
		return;
		fprintf(o->file, "%sGIT binary patch\n", diff_line_prefix(o));
		if (textconv_two)
			 N_("disable all output of the program")),
			prev_line->next_line = key;
		/*
				num = (num*10) + (ch-'0');
			       N_("how white spaces are ignored in --color-moved"),
 free_ab_and_return:
	else if (fmt & (DIFF_FORMAT_RAW | DIFF_FORMAT_NAME_STATUS))
	}

	} else
			  N_("show only names of changed files"),

	}


		}
	the_hash_algo->init_fn(ctx);
	temp->name = get_tempfile_path(temp->tempfile);
		      const char *line, int len)
	name  = one->path;
		diff_words->minus.text.size = 0;
			if (reset)
	return LOOKUP_CONFIG(color_diff_slots, var);
			       N_("synonym for --dirstat=cumulative"),
	two->dirty_submodule = new_dirty_submodule;

static void init_diff_words_data(struct emit_callback *ecbdata,
	/*
		show_file_mode_name(opt, "delete", p->one);
		if (!other)
	/* emit data encoded in base85 */
{
static int fill_mmfile(struct repository *r, mmfile_t *mf,
		return COLOR_MOVED_DEFAULT;
		name_a = p->one->path;
void diff_emit_submodule_header(struct diff_options *o, const char *header)
	DIFF_SYMBOL_SUBMODULE_ADD,
}
	struct diff_options *options = opt->value;
		if (!extra_shown)

		    int addremove, unsigned mode,
		if (found)
		struct diff_words_buffer *buffer)
void fill_filespec(struct diff_filespec *spec, const struct object_id *oid,
			die("unable to read files to diff");

		ecbdata->blank_at_eof_in_preimage = 0;
		diff_color_moved_default = cm;
 * This struct is used when we need to buffer the output of the diff output.
				 DIFF_SYMBOL_MOVED_LINE_UNINTERESTING)) {
			dir->files++;
	options->xdl_opts = DIFF_WITH_ALG(options, PATIENCE_DIFF);

	if (!oideq(oid, &ce->oid) || !S_ISREG(ce->ce_mode))
				      DIFF_FORMAT_DIRSTAT |
	int lp, rp;
			goto free_ab_and_return;
		 */
		   o->emitted_symbols->nr + 1,
	for (i = 0; i < q->nr; i++) {
			width = strtoul(value, &end, 10);
		struct emitted_diff_symbol *l = &o->emitted_symbols->buf[n];
		return "mode -l";
	diff_fill_oid_info(two, o->repo->index);
	 * calling us.
			break;


	else
	if (diff_suppress_blank_empty
		delta = a_width - b_width;
	number_width = decimal_width(max_change) > number_width ?
		notes_cache_put(driver->textconv_cache, &df->oid, *outbuf,
	 * two linux-2.6 kernel trees in an already checked out work
		  (!p->score &&
	options->flags.override_submodule_config = 1;
static int diff_interhunk_context_default;
		 */
	return git_config_bool(var,value) ? DIFF_DETECT_RENAME : 0;
	cp = line;
 *   1. diff_words->last_minus == 0 &&
	 * to have found.  It does not make sense not to return with
	if (line[0] == '@') {
			width++;
	options->color_moved_ws_handling = diff_color_moved_ws_default;
			nl_just_seen = 1;

	}
	DIFF_SYMBOL_WORDS_PORCELAIN,
}
		OPT_BOOL('R', NULL, &options->flags.reverse_diff,
		FREE_AND_NULL(ecbdata->diff_words);
static void emit_hunk_header(struct emit_callback *ecbdata,
void diff_debug_filespec(struct diff_filespec *s, int x, const char *one)
	for (i = 0; i < q->nr; i++)
	unsigned long num, scale;
				set = diff_get_color_opt(o, DIFF_FILE_OLD);
	} else if (line[0] == ' ') {
			opt->filter |= bit;
	BUG_ON_OPT_NEG(unset);
		SWAP(old_mode, new_mode);
			bin_width = bin_width < w ? w : bin_width;
		pprint_rename(&pname, file->from_name, file->name);
	const char *reverse = ecbdata->color_diff ? GIT_COLOR_REVERSE : "";
			   unsigned int flags)
	options->found_follow = 0;
		 * this extra overhead probably isn't a big deal.
		options->flags.exit_with_status = 1;
		die("unable to generate word diff");
		xecfg.ctxlen = o->context;
		}
	assert(opt);
			flags &= ~DIFF_SYMBOL_CONTENT_WS_MASK;
				diff_populate_filespec(r, one, CHECK_BINARY);
static const char rename_limit_advice[] =
	struct argv_array argv = ARGV_ARRAY_INIT;
	if (set_sign) {
			return -1 - (int)(arg - orig_arg);
			return 0;
	path = prefix_filename(ctx->prefix, arg);
	DIFF_SYMBOL_SUBMODULE_DEL,
	int org_len = len;
		      struct diffstat_t *diffstat,
static int adjust_last_block(struct diff_options *o, int n, int block_length)


	int pfx_adjust_for_slash;
	 * dealing with a change.
		out->ptr[out->size + j - i] = '\n';
				add = total - del;
			  DIFF_FORMAT_PATCH, DIFF_FORMAT_NO_OUTPUT),
			die_errno("stat(%s)", name);
{
	BUG_ON_OPT_NEG(unset);
static int diff_opt_color_words(const struct option *opt,
	else if (!strcmp(arg, "zebra"))
		    diff_filespec_is_binary(options->repo, p->two)) {
	if (ep < line + len) {
	if (!opt->filter) {
		if (regcomp(ecbdata->diff_words->word_regex,
	int i;
	return 1;
		strbuf_addf(&header, "%s%sdeleted file mode %06o%s\n", line_prefix, meta, one->mode, reset);
		 * by copying the empty outq at the end of this
}

	int complete_rewrite = 0;
	/* both are valid and point at the same path.  that is, we are
				del = scale_linear(del, graph_width, max_change);
	GIT_COLOR_BOLD,		/* CONTEXT_BOLD */
	struct diffstat_file *x;
static int count_lines(const char *data, int size)
				fputs(file->print_name, options->file);
 * And for the common parts of the both file, we output the plus side text.
		options->flags.allow_textconv = 1;
	DIFF_SYMBOL_WORD_DIFF,
	if (!strcmp(opt->long_name, "cumulative")) {
		const char *name_a, *name_b;
		OPT_CALLBACK_F(0, "submodule", options, N_("<format>"),
		} else if (!data->files[i]->is_binary) { /* don't count bytes */
{
}
			options->flags.has_changes = 0;
	} else if (o->submodule_format == DIFF_SUBMODULE_INLINE_DIFF &&
						ent);
#include "submodule.h"
	return 0;

		free(null);
			*end = p ? p - buffer->ptr : match[0].rm_eo + *begin;
			       N_("choose a diff algorithm"),
		emit_diff_symbol(o, DIFF_SYMBOL_BINARY_DIFF_BODY,
			void *to_free = delta;
			set = diff_get_color_opt(o, DIFF_FILE_OLD);
				/* width >= 2 due to the sanity check */
	if (!DIFF_FILE_VALID(one)) {
		strbuf_addf(msg, "%s\n%s%scopy from ",

			     NULL, NULL, NULL, o, p);
	int needs_reset = 0; /* at the end of the line */
	 * and the rest for constant elements + graph part, but no more
		strbuf_addstr(out, "0,0");
						 out.buf, out.len, 0);
				    flags);
				struct hashmap *hm,
struct diff_filespec *alloc_filespec(const char *path)
			    * color is enabled */
			set = diff_get_color_opt(o, DIFF_FILE_NEW_MOVED_DIM);
		int cm = parse_color_moved(value);
#include "hashmap.h"
	}
}

 * Otherwise, if the last block has fewer alphanumeric characters than
				size);
#else
			xdiff_set_find_func(&xecfg, pe->pattern, pe->cflags);
	    COLOR_MOVED_WS_ALLOW_INDENTATION_CHANGE)
		}
		if (p->status == DIFF_STATUS_MODIFIED && p->score)
{
	unsigned check_mask = DIFF_FORMAT_NAME |


	}
					data.filename, blank_at_eof, err);
int git_diff_basic_config(const char *var, const char *value, void *cb)
	int al = cur->es->len, bl = match->es->len, cl = l->len;
	}
};
		if (convert_to_git(r->index, s->path, s->data, s->size, &buf, conv_flags)) {

	if (options->flags.reverse_diff)
			    const char *arg, int unset)
		i = j - 1;
	}
		data = deflated;
	 */
		options->flags.find_copies_harder = 1;
			emit_diff_symbol(o, DIFF_SYMBOL_HEADER,

		struct hashmap *hm;
	p = strchr(p, '+');
			else if (c == '@')
			      0, PARSE_OPT_NONEG),
	if ((options->xdl_opts & XDF_WHITESPACE_FLAGS))
	if (HAS_MULTI_BITS(options->output_format & check_mask))
			}
			       PARSE_OPT_NONEG, diff_opt_ws_error_highlight),
				     optarg[i], optarg);
		case DIFF_SYMBOL_PLUS:
		strbuf_addstr(&msgbuf, reset);
			  const char *name,
	return deflated;
		if (ecbdata.ws_rule & WS_BLANK_AT_EOF)
static int diff_opt_find_copies(const struct option *opt,


	diff_free_filespec_data(two);
int textconv_object(struct repository *r,
{


	}
			free(key);
		if (namelen < baselen)
			if (!cmp_in_block_with_wsd(o, cur, match, &pmb[i], n))
			options->flags.dirstat_cumulative = 0;
	for (i = 0; i < buffer->text.size; i++) {
	if (unset) {
			free((void *)esm.buf[i].line);
			       N_("detect renames"),
	}

			    (!fill_mmfile(o->repo, &mf, two) &&
		    (prev->flags & DIFF_SYMBOL_MOVED_LINE_ZEBRA_MASK) ==
		int files, int insertions, int deletions)
			patch_id_add_string(&ctx, "---/dev/null");
			else
		}
			     -1 - val, arg);
	case DIFF_SYMBOL_SUBMODULE_MODIFIED:
		if (one->driver->binary != -1)
		if (options->break_opt != -1)
	[DIFF_FILE_OLD]		      = "old",
void diff_set_mnemonic_prefix(struct diff_options *options, const char *a, const char *b)
		/* Blank line at EOF - paint '+' as well */

	    (DIFF_FILE_VALID(p->two) && S_ISDIR(p->two->mode)))
		if (diff_unmodified_pair(p))
}
			check_blank_at_eof(&mf1, &mf2, &ecbdata);
	if (options->close_file)
static int is_submodule_ignored(const char *path, struct diff_options *options)
	for (i = off; i < len; i++)
		}
	unsigned int sources = 0;

					; /* nothing */

		free (ecbdata->diff_words->plus.text.ptr);
	const char *suffix;
		}
		const unsigned hexsz = the_hash_algo->hexsz;
#include "promisor-remote.h"
		st->ctx.color = diff_get_color_opt(o, DIFF_CONTEXT);
			hashmap_init(&del_lines, moved_entry_cmp, o, 0);
	diff_fill_oid_info(one, o->repo->index);
			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG,

		quote_c_style(other, msg, NULL, 0);
		struct emitted_diff_symbol *l = &o->emitted_symbols->buf[n];

		data->is_unmerged = 1;
		else
	/* Find common prefix */
	if (convert_to_working_tree(istate, path,
 * on each line of color words output. Generally, there are two conditions on
			       0, diff_opt_pickaxe_regex),
		if (l->s != DIFF_SYMBOL_PLUS && l->s != DIFF_SYMBOL_MINUS)
			if (check_pair_status(p))
			if (adjust_last_block(o, n, block_length) &&
	int i;
			      const char *line, int len)
			hashmap_free_entries(&add_lines, struct moved_entry,
			       N_("look for differences that change the number of occurrences of the specified object"),
		if (print)
		break;
	int len_a = strlen(a);
			   const char *arg, int unset)
		the_hash_algo->final_fn(oid->hash, &ctx);
{
	[DIFF_FILE_OLD_MOVED]	      = "oldMoved",
	name = p->one->path;
		dir.files[dir.nr].name = file->name;
	changed = 0;
					    DIFF_FORMAT_SHORTSTAT |
	}
		}
	return 0;
#include "help.h"
	if (one->oid_valid && two->oid_valid &&
			/* we can borrow from the file in the work tree */
			strbuf_addf(&header, "%s%sold mode %06o%s\n", line_prefix, meta, one->mode, reset);
		s->oid_valid ? oid_to_hex(&s->oid) : "");
int diff_unmodified_pair(struct diff_filepair *p)
				got_match[i] |= 1;
	if (lc_b)
				&o->emitted_symbols->buf[n + 1] : NULL;
		if (drv && drv->external)
		mmfile_t mf1, mf2;
		a_prefix = o->b_prefix;
			total_files--;
	run_diffstat(p, o, diffstat);
			 const char *xfrm_msg,
	}
			 * In --dirstat-by-file mode, we don't really need to
		arg = "all";
{
			       diff_opt_break_rewrites),
			 * happen anymore, but prepare for broken callers.
		}
 *
		return 0;
	else
	/*
			val |= WSEH_CONTEXT;
					       struct diff_filespec *one)
		OPT_BIT_F(0, "ignore-blank-lines", &options->xdl_opts,
	DIFF_STATUS_DELETED,
		a_prefix = o->a_prefix;
			block_length = 0;
	 * scale linearly as if the allotted width is one column shorter
	case DIFF_SYMBOL_BINARY_DIFF_HEADER_DELTA:
	}
		oid_array_clear(&to_fetch);
			strbuf_addstr(&sb, st_el->suffix);

		default:
			pfx_length = old_name - a + 1;
	/*
	}
		fprintf(o->file, "%.*s", len, line);
	/*

			graph_width = width - number_width - 6 - name_width;
	}
	int len = xsnprintf(buf, sizeof(buf), "%06o", mode);
		if (options->color_moved == COLOR_MOVED_NO)

	}
{
	if (options->pickaxe_opts & DIFF_PICKAXE_KINDS_MASK)
			abbrev = FALLBACK_DEFAULT_ABBREV;

	int has_trailing_newline, has_trailing_carriage_return;
		emit_line(o, "", "", line, len);
				if (!dir->cumulative)
static const char *userdiff_word_regex(struct diff_filespec *one,
		emit_diff_symbol(o, s, line, len, 0);
	 * and graph_width is the width of the graph area.
			dir->nr--;
			diff_words->minus.orig[minus_first + minus_len - 1].end;
					  size_t count, const char *buf)
		if (xdi_diff_outf(&mf1, &mf2, NULL, fn_out_consume,
		}
		o->flags.check_failed = 1;
			s->should_free = 1;
	 * and is also used to divide available columns if there
			complete_rewrite = 1;
#include "diffcore.h"

					 sb.buf, sb.len, 0);
		opt->flags.has_changes);
	struct emit_callback ecbdata;
			      struct diff_filespec *one,
	}
			       PARSE_OPT_NONEG, diff_opt_anchored),
			continue;
}
	for (n = 0; n < o->emitted_symbols->nr; n++) {
	int pfx_length, sfx_length;
{
void diff_emit_submodule_pipethrough(struct diff_options *o,
		 * added is the new material.  They are both damages
		if (diff_filespec_check_stat_unmatch(diffopt->repo, p))
			strbuf_addstr(&out, " -> ");
}
		fn_out_diff_words_write_helper(diff_words->opt,
	free(path);
	struct object_id oid;
	return rp + 1;
}
			add_external_diff_name(o->repo, &argv, name, two);

	return ignored;
		return error(_("color moved setting must be one of 'no', 'default', 'blocks', 'zebra', 'dimmed-zebra', 'plain'"));

		last_symbol = l->s;
			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG,

	}
				 DIFF_SYMBOL_MOVED_LINE_ALT |
		break;
void diff_emit_submodule_del(struct diff_options *o, const char *line)
#ifdef NO_FAST_WORKING_DIRECTORY
	int i;
 * the user happens to have in the configuration file.
	 * shows that it makes things worse for diff-tree comparing
		OPT_BITOP('u', NULL, &options->output_format,
			strbuf_release(&sb);
static int diff_detect_rename_default;
struct dirstat_dir {
	name_b += (*name_b == '/');
	int a_off = cur->es->indent_off,
	const char *pgm = external_diff();
	line_prefix = diff_line_prefix(opt);
	buffer->text.ptr[buffer->text.size] = '\0';
		break;
		return XDF_HISTOGRAM_DIFF;
	struct diff_queue_struct *q = &diff_queued_diff;
/* This function starts looking at *begin, and returns 0 iff a word was found. */
static void emit_rewrite_lines(struct emit_callback *ecb,
void diff_emit_submodule_error(struct diff_options *o, const char *err)
		break;
		if (mf1.size == mf2.size &&
		 * external diff driver
struct diff_words_buffer {
		if (i < count)

{
	 */
		if (output_format & DIFF_FORMAT_SHORTSTAT)
}
	DIFF_SYMBOL_NO_LF_EOF,
	[DIFF_METAINFO]		      = "meta",
	 *    under this directory (sources == 1).

		break;
static void show_dirstat_by_line(struct diffstat_t *data, struct diff_options *options)
	mf->ptr = one->data;
		struct strbuf buf = STRBUF_INIT;
	dir.files = NULL;
		if (diff_populate_filespec(r, one, 0))
		BUG("unknown diff symbol");

		strbuf_addf(msg, "%s\n", reset);
		break;


			 N_("use empty blobs as rename source")),
		if (file->is_unmerged ||
		break;
			int i;
		free (ecbdata->diff_words->minus.text.ptr);
	int i;
	if (p->one->mode && p->two->mode && p->one->mode != p->two->mode) {
	if (!strcmp(value, "log"))

		ALLOC_GROW(buffer->orig, buffer->orig_nr + 1,
		emit_rewrite_lines(&ecbdata, '+', data_two, size_two);
			 */
		result |= 01;
	int flags;
			diff_words->minus.orig[minus_first].end;
{
	unsigned long delta_size;
	child.use_shell = 1;
			       N_("moved lines of code are colored differently"),
	dir.alloc = 0;
	if (pos < 0)
	prepare_filter_bits();
	return userdiff_get_textconv(r, one->driver);
			data->added = 0;

 * The core-level commands such as git-diff-files should
	case DIFF_SYMBOL_SUBMODULE_HEADER:
			       N_("<char>"),
		return 0;
}
	    strncmp(path, options->prefix, options->prefix_length))
/*
			 * same again. If so, that's not a rename at
		if (arg)
	const char *line_prefix = diff_line_prefix(options);

	ret->es = l;
static long diff_algorithm;
			return 0;
	/* deletion, addition, mode or type change
		}
		 * Even if the caller would be happy with getting
}
	char *got_match = xcalloc(1, pmb_nr);
	struct strbuf sb = STRBUF_INIT;
#define DIFF_SYMBOL_MOVED_LINE			(1<<17)

	}
	diff_warn_rename_limit("diff.renameLimit",
	unsigned flags = o->color_moved_ws_handling & XDF_WHITESPACE_FLAGS;
				     opt->long_name);

	}

				set = diff_get_color_opt(o, DIFF_FILE_NEW_DIM);
	DIFF_SYMBOL_SEPARATOR
		struct diff_filespec *null = alloc_filespec(two->path);
				continue;
			break;
			 * the count, and call it a copy.
	attr_path = name;
}
	diff_free_filespec_data(one);
static struct diff_tempfile *prepare_temp_file(struct repository *r,
		    files);
				  const char *arg, int unset)
int git_diff_heuristic_config(const char *var, const char *value, void *cb)
}

		dir.nr++;
		}
			       PARSE_OPT_NONEG, diff_opt_char),
/* An external diff command takes:
			strchr(line, ' ') ? "\t" : "");
	print_stat_summary_inserts_deletes(options, total_files, adds, dels);
		o->word_regex = diff_word_regex_cfg;
	case DIFF_SYMBOL_MINUS:

		const char *name_a, *name_b;
}
		name_b = NULL;
#define EMITTED_DIFF_SYMBOL_INIT {NULL}
			the_hash_algo->update_fn(&ctx, p->two->path, len2);
	 *
	struct diffstat_file *x = diffstat->files[diffstat->nr - 1];

}
	}
	 *    always have both sides (iow, not create/delete),
		}
			continue;
		if (graph_width > width * 3/8 - number_width - 6) {
	struct string_list params = STRING_LIST_INIT_NODUP;
	 *    with the same mode and size, and the object
	*fmt &= ~DIFF_FORMAT_NO_OUTPUT;
			l->flags |= DIFF_SYMBOL_MOVED_LINE;
		/* unmerged */

		}
	int print = 0;
		}
		if (output_format & DIFF_FORMAT_NUMSTAT)
		fputc('\r', file);
	if (!print_sha1_ellipsis())
		parse_dirstat_opt(options, "files");
	const char *line_prefix;
		write_name_quoted(name_a, opt->file, inter_name_termination);
	int complete_rewrite = (p->status == DIFF_STATUS_MODIFIED) && p->score;
			show_stats(&diffstat, options);
			       N_("look for differences that change the number of occurrences of the specified string"),
		OPT_CALLBACK_F(0, "compact-summary", options, NULL,


{
	}
				 ecbdata->header->buf, ecbdata->header->len, 0);

	*value = arg[0];

	pfx_length = 0;
static int diff_opt_find_renames(const struct option *opt,
				       (one->oid_valid ?
	int inter_name_termination = line_termination ? '\t' : '\0';
			       &options->output_indicators[OUTPUT_INDICATOR_OLD],
		free(s);
			       PARSE_OPT_NONEG, diff_opt_stat),
		}
		memset(&xecfg, 0, sizeof(xecfg));
	DIFF_SYMBOL_REWRITE_DIFF,
				  diffstat_consume, diffstat, &xpp, &xecfg))
{
			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG,
				goto err_empty;
	}

	struct userdiff_driver *textconv;
static void emit_add_line(struct emit_callback *ecbdata,
	if (completely_empty)
	 * whitespace delta.
		if (o->flags.binary) {
	/* If 'l' and 'cur' are both blank then they match. */
			continue;
	if (done_preparing)

		prefix = "";
					permille / 10, permille % 10, baselen, base);
	if (!pgm &&

				    OUTPUT_INDICATOR_OLD, line, len,
	 * guarantee that work tree matches what we are looking for.
			     DIFF_FORMAT_CHECKDIFF)) {
}
	 */

		fprintf(o->file, "%s%s+++ %s%s%s\n", diff_line_prefix(o), meta,
			}
	return 0;
			     one, two, &msg, o, p);
	[DIFF_FILE_NEW_MOVED_ALT_DIM] = "newMovedAlternativeDimmed",
	BUG("diff is failing to clean up its tempfiles");
		OPT_CALLBACK_F(0, "stat-graph-width", options, N_("<width>"),
			 * The caller can subtract 1 from skip_stat_unmatch
			match = hashmap_get_entry(hm, key, ent, NULL);
static void checkdiff_consume(void *priv, char *line, unsigned long len)
	const char *line_prefix = diff_line_prefix(o);
			warning(_("Found errors in 'diff.dirstat' config variable:\n%s"),

	file->print_name = strbuf_detach(&pname, NULL);
	memset(diffstat, 0, sizeof(struct diffstat_t));
	ecbdata.lno_in_postimage = 1;
			       PARSE_OPT_NONEG, diff_opt_diff_filter),

	case DIFF_SYMBOL_SUMMARY:
		return -1;
				&one->oid, &two->oid,
			 * bytes per "line".
	diff_free_filespec_data(two);
		ecbdata->label_path[0] = ecbdata->label_path[1] = NULL;
		struct diffstat_file *file = data->files[i];
	/* separate form: --option value */
	int i;
	    !one->dirty_submodule && !two->dirty_submodule)
	}
				 header.len, 0);
			die("invalid regular expression: %s",
	const struct cache_entry *ce;
static int diff_indent_heuristic = 1;
					 NULL, 0, 0);

			       N_("generate diffstat with a given width"),
				const char *arg, int unset)
	options->anchors[options->anchors_nr++] = xstrdup(arg);
	char firstchar;
{
			if (S_ISLNK(p->two->mode))
		}
 * grab the data for the blob (or file) for our own in-core comparison.
		fprintf(opt->file, "%c%03d%c", p->status, similarity_index(p),
			strbuf_addstr(&sb, " rewrite ");
			struct diff_filepair *p = q->queue[i];

			/* Advance to the next line */
		 * be identical, but since the oid changed, we
			the_hash_algo->update_fn(&ctx, oid_to_hex(&p->one->oid),
	/*
		struct stat st;
	out->ptr = NULL;
static int diff_opt_ignore_submodules(const struct option *opt,
}
		    unsigned mode,

	if (set) {
	ALLOC_ARRAY(options->parseopts, ARRAY_SIZE(parseopts));
	hashmap_for_each_entry_from(hm, match, ent) {
 *
	int i;
};
	}
	GIT_COLOR_BG_RED,	/* WHITESPACE */
	/*
	int count = options->stat_count;
	if (!strcmp(arg, "no"))
		prev_line = key;
	DIFF_SYMBOL_BINARY_DIFF_FOOTER,
		xecfg.ctxlen = 3;


	BUG_ON_OPT_ARG(optarg);
	else
			diffcore_break(options->repo,

		if (xfrm_msg)
			continue;
	 * benchmark with my previous version that always reads cache
{
{
			 int complete_rewrite)
				break;
		return block_length;

			      const char *arg, int unset)
			continue;
		textconv_two = get_textconv(o->repo, two);
		break;

			opt->filter &= ~filter_bit[DIFF_STATUS_FILTER_AON];
				oidclr(&one->oid);
		}
{
	struct checkdiff_t *data = priv;

	struct option parseopts[] = {
	const char *attr_path;
	ecbdata->lno_in_preimage = 0;
	    (!one->oid_valid ||
			emit_diff_symbol(o, DIFF_SYMBOL_WORD_DIFF,
		options->flags.follow_renames = 0;
				    const char *arg, int unset)
					one->mode : S_IFLNK));

		strbuf_add(&msgbuf, ep, line + len - ep);
	 */


static void show_mode_change(struct diff_options *opt, struct diff_filepair *p,
		break;

		DIFF_XDL_SET(options, INDENT_HEURISTIC);
		return 1;
	return 0;
			diff_line_prefix(o), line);
	return !xdiff_compare_lines(a->es->line, a->es->len,
		diff_free_filepair(q->queue[i]);

		show_rename_copy(opt, "copy", p);
{
		if (line[cnt] != firstchar)
		free (ecbdata->diff_words->plus.orig);

		strbuf_addf(out, "1,%d", count);
		else {
	for (i = 0; i < pmb_nr; i++) {
			  N_("generate diff using the \"histogram diff\" algorithm"),
 * COLOR_MOVED_MIN_ALNUM_COUNT, unset DIFF_SYMBOL_MOVED_LINE on all lines in
				strbuf_addstr(&sb, st_el->color);
			     struct diff_options *o,
{
			hm = del_lines;
 free_and_return:
		(*end)++;

		options->abbrev = hexsz; /* full */
			opt->filter = (1 << (ARRAY_SIZE(diff_status_letters) - 1)) - 1;
			ret |= XDF_IGNORE_WHITESPACE_CHANGE;
	[DIFF_CONTEXT_BOLD]	      = "contextBold",
	stream.avail_in = size;
	struct diff_options *options = opt->value;
		reset = diff_get_color_opt(o, DIFF_RESET);
static void patch_id_consume(void *priv, char *line, unsigned long len)
	int i;

	return 0;
	if (!o->word_regex)
			else
static void diffstat_consume(void *priv, char *line, unsigned long len)
	if (!opt->flags.exit_with_status &&
}
		if (data->files[i]->is_unmerged ||
	return;
static int diff_opt_pickaxe_string(const struct option *opt,
	other = (strcmp(name, p->two->path) ? p->two->path : NULL);
 *      diff_words->current_plus == diff_words->plus.text.ptr
	if (!arg)
{
		return 0;
	 * also has the same effect.
	 * the "old" side here is deliberate.  We are checking the newly
		return error(_("unknown value after ws-error-highlight=%.*s"),
	 */
static int diff_opt_no_prefix(const struct option *opt,
		return -1;
}
{
static int diff_filespec_check_stat_unmatch(struct repository *r,
		die(_("external diff died, stopping at %s"), name);
		char line[71];
	struct hashmap_entry ent;
	int i;
			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG, diff_opt_stat),
	 * Guarantee 3/8*16==6 for the graph part
	}
		goto end_of_line;
			      0, PARSE_OPT_NONEG),
			strbuf_addch(&sb, ' ');
	if (DIFF_PAIR_UNMERGED(p)) {

		diff_temp[i].name = NULL;

{
			       PARSE_OPT_NOARG, diff_opt_follow),
		size = buf.len;
			if (slash)


		} else if (DIFF_FILE_VALID(p->two)) {
}
		break;
		strbuf_addf(msg, "%s\n%s%srename to ",
}
	for (i = 0; i < ARRAY_SIZE(diff_temp); i++) {
			  struct diff_filespec *spec,
		/*
		int added = data->files[i]->added;
	/*
	}

{
	if (arg)
	quote_two_c_style(&a_name, a_prefix, name_a, 0);
			goto free_ab_and_return;
	/*
		switch (o->emitted_symbols->buf[n].s) {
struct userdiff_driver *get_textconv(struct repository *r,

		name_a = p->one->mode ? p->one->path : p->two->path;
	memcpy(buffer->text.ptr + buffer->text.size, line, len);
	}
		fill_metainfo(msg, name, other, one, two, o, p,
	int new_len;
 *
	 */
	if (!skip_prefix(arg, opt, &arg))
	int count, ch, completely_empty = 1, nl_just_seen = 0;

		dir.files[dir.nr].name = name;
	size_t size_one, size_two;
		OPT_INTEGER_F(0, "inter-hunk-context", &options->interhunkcontext,
	}
	free(minus.ptr);
		fill_print_name(file);

	/* find the next word */
static int diffnamecmp(const void *a_, const void *b_)
			  N_("ignore changes in amount of whitespace"),
	emit_diff_symbol(ecbdata->opt, DIFF_SYMBOL_PLUS, line, len, flags);
		 * The boundary to prev and next are not interesting,
	if (data->nr == 0)
	enum diff_words_type type;
		unsigned long changes;
	memcpy(options->parseopts, parseopts, sizeof(parseopts));
	if (!strcasecmp(var, "plain"))
		OPT_CALLBACK_F(0, "word-diff-regex", options, N_("<regex>"),
			 p->one->mode != p->two->mode ||
		   int oid_valid, unsigned short mode)
		dir.nr++;
 *   2. break both minus-lines and plus-lines into words and
	 * likely to work fine when the automatic sizing of default
			diff_populate_filespec(options->repo, p->one, 0);
				diff_flush_patch(p, options);
		OPT_BIT_F(0, "shortstat", &options->output_format,
	options->output_indicators[OUTPUT_INDICATOR_OLD] = '-';
			name_width = width - number_width - 6 - graph_width;
			     struct diff_filepair *p)
	case DIFF_STATUS_COPIED:
		else {
{
	else if (!strcasecmp(value, "myers") || !strcasecmp(value, "default"))
	return git_diff_basic_config(var, value, cb);
		return error(_("%s expects <n>/<m> form"), opt->long_name);
	print_stat_summary_inserts_deletes(&o, files, insertions, deletions);

		xecfg.flags = XDL_EMIT_FUNCNAMES;
	argv_array_pushf(&env, "GIT_DIFF_PATH_TOTAL=%d", q->nr);
	int name_width = options->stat_name_width;
	}

	int i;
		options->set_default(options);
	emit_diff_symbol(o, DIFF_SYMBOL_SUBMODULE_UNTRACKED,
			diff_words->minus.text.ptr);
	*result_size = stream.total_out;
	if (start_command(&child)) {

					  &ecbdata->diff_words->minus);
		 * run diff_flush_patch for the exit status. setting
	 * 6 + decimal_width(max_change).
	if (fs->mode)
	}
	case DIFF_SYMBOL_WORDS_PORCELAIN:
			    o->word_regex);
	if (name_width + number_width + 6 + graph_width > width) {
	if (s->should_free || s->should_munmap) {

		char *hex = oid_to_hex(oid);
static void diff_words_fill(struct diff_words_buffer *buffer, mmfile_t *out,
	if (options->flags.diff_from_contents)

			patch_id_add_string(&ctx, "---a/");
	if (options->pickaxe_opts & DIFF_PICKAXE_KINDS_MASK)
	const char *a_prefix, *b_prefix;
					     const struct option *opt,
		unsigned long damage = file->added + file->deleted;
	fill_filespec(df, oid, oid_valid, mode);
		x->deleted++;
		if (o->word_diff)
			if (o->color_moved_ws_handling &
	if (options->detect_rename && options->rename_limit < 0)

	return 0;
static void checkdiff_consume_hunk(void *priv,
		b_midlen = 0;
	 */
		if (options->close_file)
	diff_words->last_minus = 0;
		fputs(o->stat_sep, o->file);

		}
			strbuf_addf(&header, "%s%snew mode %06o%s\n", line_prefix, meta, two->mode, reset);
}
			 b_name.buf, b_name.len, 0);
{
		del = deleted;
{
	if (!opt->output_prefix)
			}
{
	}

			    nneof, strlen(nneof));
	argv_array_pushf(&env, "GIT_DIFF_PATH_COUNTER=%d", ++o->diff_path_counter);
			set = diff_get_color_opt(o, DIFF_FILE_OLD_MOVED_DIM);
		if (p->score) {
	child.out = -1;
		} else if (!strcmp(p, "noncumulative")) {
	 * three dots anyway, to indicate that the output is not the
#include "cache.h"
 */
	if (driver->textconv_cache && df->oid_valid) {
{
			patch_id_add_string(&ctx, "deletedfilemode");
		if (*old_name == '/')
	case 1:

	 * --ignore-whitespace* options force us to look
		strbuf_add(name, a + len_a - sfx_length, sfx_length);
					     const char *arg, int unset)
		return; /* nothing to check in tree diffs */
		for (i = found = 0; !found && i < q->nr; i++) {
static int parse_dirstat_opt(struct diff_options *options, const char *params)
		data->lineno++;
	case 0:
	struct diff_filespec *one, *two;
			mmfile_t mf;
	lc_b = count_lines(data_two, size_two);
		/*
			p->status = DIFF_STATUS_UNKNOWN;
		}
	return pair;
		emit_diff_symbol(ecbdata->opt,
		       struct diff_filespec *one)
				permille += *end - '0';
			  DIFF_PICKAXE_ALL, PARSE_OPT_NONEG),
static int is_conflict_marker(const char *line, int marker_size, unsigned long len)
		minus_end =
			      struct diff_filespec *two,
				  long minus_first, long minus_len,
			add_if_missing(options->repo, &to_fetch, p->one);
}
	}
	at = count_lines(mf2->ptr, mf2->size);
					 int pmb_nr)
			bin_width = bin_width < 8 ? 8 : bin_width;
{
	for (n = 0; n < o->emitted_symbols->nr; n++) {

	 *    the same mode and size.  Keep the ones that
		}

		return;
			   int mode)
			  N_("ignore whitespace when comparing lines"),
		options->flags.has_changes = 0;
		else if (skip_prefix(diffopts, "-u", &v))
			continue;
	if (!options->flags.diff_from_contents)
{
		print = 1;
			   const struct object_id *oid,
			blank_at_eof = ecbdata.blank_at_eof_in_postimage;

	if (p->status == DIFF_STATUS_COPIED ||
		/*
/* this executes the word diff on the accumulated buffers */

{
 * and then the output can be constructed later on depending on state.

	const char *set = diff_get_color(data->o->use_color, DIFF_FILE_NEW);

			 */
	if (!value)
		options->color_moved = COLOR_MOVED_NO;
		else if (!strcmp(sb.buf, "ignore-space-change"))
		ws_check_emit(line + 1, len - 1, data->ws_rule,
	}
				 line_prefix, strlen(line_prefix), 0);
		/* Crazy xdl interfaces.. */
 * Copyright (C) 2005 Junio C Hamano
	struct diffstat_file *data;
	if (*arg == 0)
		options->rename_limit = diff_rename_limit_default;

		run_diff_cmd(NULL, name, other, attr_path,
	const char *name;
	    is_submodule_ignored(concatpath, options))
		OPT_CALLBACK_F(0, "line-prefix", options, N_("<prefix>"),
			val |= WSEH_NEW;
		if (next && next->s != DIFF_SYMBOL_PLUS &&
	return -1;
	if (*params_copy)
	struct dirstat_dir dir;
		must_show_header = 1;
	}
	}
}
		if (options->word_diff == DIFF_WORDS_NONE)
{
const char *diff_get_color(int diff_use_color, enum color_diff ix)
static int diff_opt_diff_algorithm(const struct option *opt,

		return XDF_NEED_MINIMAL;
	 */
			if (strbuf_readlink(&sb, s->path, s->size))
static void pprint_rename(struct strbuf *name, const char *a, const char *b)
	memset(&xecfg, 0, sizeof(xecfg));
	memset(&ecbdata, 0, sizeof(ecbdata));
			 sb.buf, sb.len, 0);
		if (check_pair_status(p))
			       PARSE_OPT_NONEG, diff_opt_diff_algorithm),
	int i;

		if (name_width > width - number_width - 6 - graph_width)
		quote_c_style(name, msg, NULL, 0);

		return git_config_string(&diff_word_regex_cfg, var, value);
void diffcore_fix_diff_index(void)
				 ecbdata->label_path[1],



		OPT_BIT_F(0, "ignore-cr-at-eol", &options->xdl_opts,
	 */
		return hex;
			s->is_binary = 1;
			if (*prev_eol == '\n')
	 * Not omitting "0 insertions(+), 0 deletions(-)" in this case
				   const char *arg, int unset)
 * newline separator into out, and saves the offsets of the original words
		return NULL;
	    strncmp(concatpath, options->prefix, options->prefix_length))
		close(fd);
		name_b = p->two->path;
		strbuf_addf(&sb, " mode change %06o => %06o",
		strbuf_addch(name, '{');
	lbl[0] = DIFF_FILE_VALID(one) ? a_one : "/dev/null";

			die("unable to read %s", oid_to_hex(&s->oid));
		case DIFF_STATUS_RENAMED:
			 * way to normalize binary bytes vs. textual lines.
	DIFF_STATUS_ADDED,

	}
		if (options->break_opt != -1)
					       p->one, p->two, NULL, NULL,
		}
			return error(_("%s expects a numerical value"),

	    c_off = l->indent_off,
				name_width = strtoul(end+1, &end, 10);
		xpparam_t xpp;
	 * when you add new algorithms.
	}
			 struct diff_options *o,
		strbuf_addf(&sb,
	options->flags = orig_flags;
 *
			emit_diff_symbol(o, DIFF_SYMBOL_BINARY_FILES,
		return COLOR_MOVED_NO;
		    fill_mmfile(o->repo, &mf2, two) < 0)


		   (!one->mode || S_ISGITLINK(one->mode)) &&
	/* Generate "XXXXXX_basename.ext" */
			pmb_nr = 0;
	GIT_COLOR_BOLD_RED,	/* OLD_BOLD */
	DIFF_SYMBOL_SUMMARY,
	}
		OPT_BIT_F(0, "summary", &options->output_format,
			      N_("show context between diff hunks up to the specified number of lines"),
			val = 0;
		 * NEEDSWORK:

	struct diff_queue_struct *q = &diff_queued_diff;
			N_("heuristic to shift diff hunk boundaries for easy reading"),
{
	emit_line_0(o, set, NULL, 0, reset, 0, line, len);
			if (total < 2 && add && del)

				const char *arg, int unset)
			damage = 1;
		/*
				set = diff_get_color_opt(o, DIFF_FILE_NEW_BOLD);
		OPT_GROUP(N_("Diff rename options")),
	strbuf_release(&out);
	if (!o->word_regex)
	free(q->queue);
	for (i = 0; i < q->nr; i++)
	}
	l2 = count_trailing_blank(mf2, ws_rule);
	char hex[GIT_MAX_HEXSZ + 1];
	int indent_off;   /* Offset to first non-whitespace character */
		xpp.anchors = o->anchors;
			    struct diffstat_t *diffstat)
	} else {
				prev->next_line : NULL;
	struct diff_options *opt = diff_words->opt;
	done_preparing = 1;
		if ((prev &&
}
			      const char *name,
		(diff_words->current_plus > diff_words->plus.text.ptr &&
	fill_filespec(two, new_oid, new_oid_valid, new_mode);
		if (diff_populate_filespec(r, df, 0))
	}

	case DIFF_SYMBOL_SEPARATOR:
				continue;
			size_t size = 0;
		if (ecbdata->diff_words->word_regex) {
	}
	/* NOTE please keep the following in sync with diff_tree_combined() */
			argv_array_push(&argv, xfrm_msg);

		fprintf(o->file, "%sliteral %s\n", diff_line_prefix(o), line);
	if (textconv_two)
		arg = "";
		return 0;
		emit_add_line(ecbdata, line + 1, len - 1);
	name = p->one->path;
		return  DIFF_DETECT_COPY;
}
	if (options->prefix &&
	struct string_list l = STRING_LIST_INIT_DUP;
	 * indent changes. However these were found using fuzzy
{
	if (msg) {
static int diff_opt_char(const struct option *opt,

			if ((!fill_mmfile(o->repo, &mf, one) &&


	if (!options->found_follow)
	return sum_changes;
		plus_begin = plus_end = diff_words->plus.orig[plus_first].end;
				       options->break_opt);

{

}
 */
	if (!strcmp(var, "diff.algorithm")) {
		if (diff_color_moved_default)


		b_prefix = o->a_prefix;
		diff_rename_limit_default = git_config_int(var, value);
		 */
	if (S_ISGITLINK(s->mode))
const char *diff_aligned_abbrev(const struct object_id *oid, int len)

	free(a_one);
}
{
		break;
		strip_prefix(o->prefix_length, &name, &other);
	const char *other;
			 * Eat the "no newline at eof" marker as if we
	    opt->flags.has_changes)
	diff_free_filespec_blob(s);
				p->status = DIFF_STATUS_MODIFIED;
	options->pickaxe = arg;

static int scale_linear(int it, int width, int max_change)

struct diff_words_style {
		enum diff_symbol last_symbol = 0;
			rp--;
		if (!diffopts)
				found++;
 * Given a name and sha1 pair, if the index tells us the file in

	}
					    struct diff_filepair *p)
		bad = ws_check(line + 1, len - 1, data->ws_rule);
		switch (flags & (DIFF_SYMBOL_MOVED_LINE |
	if (i == len) {
		reset = diff_get_color_opt(o, DIFF_RESET);
	 *
		    COLOR_MOVED_WS_ALLOW_INDENTATION_CHANGE)
		OPT_BIT_F('s', "no-patch", &options->output_format,
	if (pmb->wsd == INDENT_BLANKLINE)
{

		if (!file->is_interesting && (change == 0)) {
				      DIFF_FORMAT_DIFFSTAT |
	if (s->data)
	oidclr(oid);
		OPT_BIT_F('w', "ignore-all-space", &options->xdl_opts,
			 * pair up, causing the pathnames to be the
 * which printed. diff_words->last_minus is used to trace the last minus word
				  &ecbdata, &xpp, &xecfg))

			 header, strlen(header), 0);
		return 0;

	return 0;
		emit_line_0(o, set_sign, set, !!set_sign, reset, sign, line, len);
		else
{
	emit_diff_symbol(o, DIFF_SYMBOL_FILEPAIR_PLUS,
	msgbuf = opt->output_prefix(opt, opt->output_prefix_data);
	return msgbuf->buf;
	options->stat_name_width = name_width;

			options->use_color = 1;
			strbuf_addf(errmsg, _("  Unknown dirstat parameter '%s'\n"), p);
static void emit_del_line(struct emit_callback *ecbdata,
 * diff_words->current_plus is used to trace the current position of the plus file
}
	BUG_ON_OPT_ARG(arg);
	} else {
		return 1;

		diff_interhunk_context_default = git_config_int(var, value);
			/*


	p->skip_stat_unmatch_result = 0;
		 */


	const char *a = cur->es->line,
		fprintf(o->file, "* Unmerged path %s\n", name);
			flipped_block = 0;
		}
		strbuf_add(&msgbuf, atat, sizeof(atat));
		plus_begin = diff_words->plus.orig[plus_first].begin;
	a_one = quote_two(a_prefix, name_a + (*name_a == '/'));
	size_two = fill_textconv(o->repo, textconv_two, two, &data_two);
		strbuf_addf(msg, "%s\n", reset);
			int permille = sum_changes * 1000 / changed;
				two->dirty_submodule);
		extra_shown = 1;
		if (o->flags.suppress_diff_headers)
		    renamecopy, names.buf, similarity_index(p));
		warning(_(rename_limit_advice), varname, needed);
	unsigned flags = diffopt->color_moved_ws_handling
}
			ecb->lno_in_preimage++;
	int i;
		reset = diff_get_color_opt(o, DIFF_RESET);
			if (*end)
	print_stat_summary_inserts_deletes(options, total_files, adds, dels);
			pmb[i].match = NULL;
		break;
	for (i = 0; i < count; i++) {
			 N_("exit with 1 if there were differences, 0 otherwise")),
		return;
			/*
}
		xpp.flags = o->xdl_opts;
 * NEEDSWORK: This uses the same heuristic as blame_entry_score() in blame.c.
			strbuf_release(&sb);
		width = 16 + 6 + number_width;
		case DIFF_SYMBOL_MOVED_LINE |
	the_hash_algo->update_fn(ctx, buf, len);
	/*
		break;
		diff_words_flush(ecbdata);
	default:
void repo_diff_setup(struct repository *r, struct diff_options *options)
		err = whitespace_error_string(bad);
	}
	if (options->flags.find_copies_harder)
			  DIFF_FORMAT_NO_OUTPUT, PARSE_OPT_NONEG),
	}
			emit_add_line(ecb, data, len);
	while (a + pfx_length - pfx_adjust_for_slash <= old_name &&
		free(null);
}
		 * Prefetch the diff pairs that are about to be flushed.

	[DIFF_FILE_NEW]		      = "new",
}
static void show_graph(struct strbuf *out, char ch, int cnt,
		if (!s->size)
		free(spec);
		es->indent_width = INDENT_BLANKLINE;
			completely_empty = 0;
		if (options->detect_rename)
	 * and the object is contained in a pack file.  The pack
				if (o->color_moved_ws_handling &
		xdemitconf_t xecfg;
	diff_free_filespec_data(one);
			struct diff_filepair *p = q->queue[i];

	strbuf_addstr(&out, " @@\n");
		break;
			 */
	const char *func = diff_get_color(ecbdata->color_diff, DIFF_FUNCINFO);
	void *deflated;

		else {
		    COLOR_MOVED_WS_ALLOW_INDENTATION_CHANGE)
			if (one->is_binary == -1)
		strip_prefix(opt->prefix_length, &name_a, &name_b);
			 const char *other,
	 * We also need 1 for " " and 4 + decimal_width(max_change)

		emit_rewrite_lines(&ecbdata, '-', data_one, size_one);
static void fn_out_consume(void *priv, char *line, unsigned long len)
		uintmax_t deleted = file->deleted;
	};
			else {
	if (lbl[0][0] == '/') {
		fn_out_diff_words_write_helper(diff_words->opt,
	/*
	int separator = 0;
				(n < o->emitted_symbols->nr - 1) ?
static unsigned parse_color_moved_ws(const char *arg)
	 */
	int i;
{
		diff_detect_rename_default = git_config_rename(var, value);
	    !S_ISGITLINK(filespec->mode) &&
	else
		    !memcmp(mf1.ptr, mf2.ptr, mf1.size)) {
		 unsigned old_mode, unsigned new_mode,
/*
	    (p->one->size != p->two->size) ||

	char *s;
	 * strlen("Bin XXX -> YYY bytes") == bin_width, and the part
			add_external_diff_name(o->repo, &argv, other, two);
		}
		for (i = 0; i < q->nr; i++) {
	else if (!strcasecmp(value, "histogram"))
		s->should_free = 1;
	const char *reset = diff_get_color(use_color, DIFF_RESET);
		 * a '+' entry produces this for file-1.
	const char *old_name = a;
		}

}
			err = -1;
	o->found_changes = 1;
	stream.next_in = (unsigned char *)data;

 *

		if (prev && (prev->flags & DIFF_SYMBOL_MOVED_LINE) &&
	}
}
const char *diff_line_prefix(struct diff_options *opt)
		OPT_CALLBACK_F(0, "cumulative", options, NULL,
			struct diff_filepair *p = q->queue[i];
	options->word_regex = arg;
			       PARSE_OPT_NONEG, diff_opt_stat),
		}
}
	int ret = 0;

		strbuf_reset(&out);
		}
		return;
		 * and is_binary check being that we want to avoid
	struct emitted_diff_symbol *l = &o->emitted_symbols->buf[line_no];
	return 1;
				}
{
	memset(b, 0, sizeof(*b));
{
			if (optch < 'a' || 'z' < optch)
	GIT_COLOR_GREEN,	/* NEW */
			goto found_damage;
	struct diff_queue_struct *q = &diff_queued_diff;
		if (delta) {
struct diff_words_data {
		return;
	const char *line_prefix;
		return 0;
	if (!DIFF_PAIR_UNMERGED(p)) {
 * may want to only have indirection for the content lines, but we could also
		emit_line(o, "", "", " 0 files changed\n",
		emit_del_line(ecbdata, line + 1, len - 1);
	graph_width = max_change + 4 > bin_width ? max_change : bin_width - 4;
/*
		OPT_CALLBACK_F(0, "stat", options, N_("<width>[,<name-width>[,<count>]]"),
		}
	free_filespec(p->one);
			pmb_advance_or_null(o, match, hm, pmb, pmb_nr);
		return NULL;
	 * As a hunk header must begin with "@@ -<old>, +<new> @@",

	else if (!strcmp(arg, "dimmed-zebra"))
		strbuf_addch(name, '}');

	struct userdiff_driver *textconv_two = NULL;
	/*

		encode_85(line + 1, cp, bytes);
	struct diff_options *options = opt->value;
			       int want_file)
	 * than stat_graph_width for the graph part.
 * For '--graph' to work with '--color-words', we need to output the graph prefix
	free(q->queue);

		const char *diffopts;
	if (!strcmp(var, "diff.renames")) {
			prefix = "...";
	memset(&xpp, 0, sizeof(xpp));

		arg++;
				 strlen(ecbdata->label_path[1]), 0);
		emit_line(o, set, reset, line, len);
			break;

		int namelen = strlen(f->name);
			options->flags.dirstat_by_line = 1;
	free(q->queue);
	int same_contents;
struct emit_callback {
	 * In well-behaved cases, where the abbreviated result is the
	if (DIFF_PAIR_UNMERGED(p))
					  &ecbdata->diff_words->plus);

					       const char *name,
static struct diff_words_style diff_words_styles[] = {
	options->flags.has_changes = 1;
	return dst - line;

			val = WSEH_NEW;
{
	if (ecbdata->header) {
			xecfg.ctxlen = strtoul(v, NULL, 10);
				graph_width = 6;
			else
		strbuf_addstr(out, "1");
		    break;
			strbuf_addf(&sb, "%sBinary files %s and %s differ\n",
	else if (!ws) {
	if (value < 0)
	while (*arg) {
			 a_name.buf, a_name.len, 0);
void diff_q(struct diff_queue_struct *queue, struct diff_filepair *dp)
 *
		return temp;
		diff_filespec_load_driver(one, r->index);
	*must_show_header = 1;
	struct strbuf sb = STRBUF_INIT;
		struct emit_callback ecbdata;
			number_width = 3;


	if ((opt->output_format & DIFF_FORMAT_CHECKDIFF) &&
		if (!damage)

	 */
		goto free_queue;
		if (o->color_moved_ws_handling &
		len = 1;
	opt->pickaxe_opts |= DIFF_PICKAXE_KIND_OBJFIND;
	strbuf_addstr(&msgbuf, reset);
{
				      DIFF_FORMAT_CHECKDIFF))
		for (i = 0; diff_status_letters[i]; i++)
	options->stat_count = count;
	string_list_clear(&l, 0);
		break;
				minus_end - minus_begin, minus_begin);
{
	struct diff_options *opt;
			   const char *path, struct diff_tempfile *temp,
	BUG_ON_OPT_ARG(arg);
		warning(_(degrade_cc_to_c_warning));
#include "object-store.h"
{
		b_prefix = o->b_prefix;
		case DIFF_SYMBOL_MOVED_LINE:
			       int prefix, const char *data, int size)
			if (st_el->color && *st_el->color)
		return DIFF_CONTEXT;
	strbuf_addchars(out, ch, cnt);
	else {
	free(b_two);
	else
			dot = 1;
	const struct diff_options *diffopt = hashmap_cmp_fn_data;
		strbuf_addf(msg, "%s\n", reset);
	}
	struct diff_words_buffer minus, plus;
	 * These cases always need recursive; we do not drop caller-supplied
		OPT_CALLBACK_F(0, "output-indicator-new",
			diff_words->plus.text.size) {
			die("unable to read files to diff");
{
	mmfile_t mf1, mf2;
	/* This function is written stricter than necessary to support
			strbuf_addstr(&header, xfrm_msg);
	cp = data;
	options->a_prefix = "";
	struct diff_filespec *one = p->one, *two = p->two;
	if (userdiff_config(var, value) < 0)
		emit_line(o, set, reset, line, len);
		    fill_mmfile(o->repo, &mf2, two) < 0)
	if (o->flags.allow_textconv) {
	 * The indent changes of the block are known and stored in pmb->wsd;
	if (run_command_v_opt_cd_env(argv.argv, RUN_USING_SHELL, NULL, env.argv))
			fill_print_name(file);
	int i;
		delta = b_width - a_width;
			 & XDF_WHITESPACE_FLAGS;

		changed += damage;
}
	*end = *begin + 1;
		break;
	if (arg) {
	}
		xpp.flags = 0;
}
		return 0;
			  N_("generate patch"),
	 *    name of one side is unknown.  Need to inspect
			  strlen(" 0 files changed\n"));
	struct moved_entry *match;
}
	return git_default_config(var, value, cb);
		struct userdiff_driver *drv;
	if (o->flags.allow_external) {
static int diff_stat_graph_width;
	struct diff_queue_struct *q = &diff_queued_diff;
		if (data.ws_rule & WS_BLANK_AT_EOF) {
			error(_("unknown color-moved-ws mode '%s', possible values are 'ignore-space-change', 'ignore-space-at-eol', 'ignore-all-space', 'allow-indentation-change'"), sb.buf);
	case 0:
	if (!is_renamed) {

	 * if the actual abbreviation is longer than the requested
		const char *v;
				 struct moved_block *pmb,
	GIT_COLOR_FAINT,	/* OLD_MOVED_DIM */
{
			       N_("detect copies"),
	prepare_filter_bits();
	*outbuf = run_textconv(r, driver->textconv, df, &size);
	unsigned ws_rule;
				 struct diff_filespec *one,
			patch_id_add_string(&ctx, "newfilemode");
	diff_free_filespec_data(two);
	const struct dirstat_file *a = _a;
		OPT_CALLBACK_F('M', "find-renames", options, N_("<n>"),
{

	BUG_ON_OPT_NEG(unset);
	}
static void run_external_diff(const char *pgm,
			  N_("machine friendly --stat"),
			    N_("do not munge pathnames and use NULs as output field terminators in --raw or --numstat"),
		 */
			continue;
		if (p->one->oid_valid && p->two->oid_valid &&
		OPT_CALLBACK_F(0, "ignore-submodules", options, N_("<when>"),
	    a_width = cur->es->indent_width,
diff_funcname_pattern(struct diff_options *o, struct diff_filespec *one)
static void find_lno(const char *line, struct emit_callback *ecbdata)
			munmap(s->data, s->size);
}
			options->flags.dirstat_by_file = 1;
		b_prefix = o->b_prefix;
				 struct diff_filespec *one,

			ret = 0;
					pmb[pmb_nr++].match = match;
			show_shortstats(&diffstat, options);
		OPT_CALLBACK_F(0, "find-object", options, N_("<object-id>"),
				      DIFF_FORMAT_SUMMARY |
	DIFF_SYMBOL_BINARY_DIFF_HEADER_LITERAL,
	BUG_ON_OPT_NEG(unset);
 */
	 *    do not match these criteria.  They have real
	 * Most of the time we can say "there are changes"
		memset(&xpp, 0, sizeof(xpp));
			 struct diff_filespec *one,
		else if (parse_one_token(&arg, "all"))

			p->status = DIFF_STATUS_MODIFIED;
			free((void *)wol->buf[i].line);
}
		if (abbrev > the_hash_algo->hexsz)
		for (; *c; c++) {

	free(params_copy);
	if (!arg)
	 * the data through than the working directory.  Loose
		emit_hunk_header(ecbdata, line, len);
		if (diff_context_default < 0)
	data.filename = name_b ? name_b : name_a;
			hm = del_lines;
struct moved_block {
				return 1;
#include "parse-options.h"
	if ((DIFF_FILE_VALID(p->one) && S_ISDIR(p->one->mode)) ||
			continue;
			 * all, just a modification..
			ecbdata->diff_words->style =

			match = hashmap_get_entry(hm, key, ent, NULL);
	int cnt = 0;
		o->word_regex = userdiff_word_regex(one, o->repo->index);
		OPT_CALLBACK_F(0, "output-indicator-context",
		     struct userdiff_driver *driver,
		}
				struct hashmap *add_lines,
		emit_line_0(o, context, NULL, 0, reset, '\\',
		struct diff_filepair *p = q->queue[i];
	else {
/* In "color-words" mode, show word-diff of words accumulated in the buffer */
	ecbdata.opt = o;
{
				 sb.buf, sb.len, 0);
	if (p->score) {
	count = options->stat_count ? options->stat_count : data->nr;
	if (o->emitted_symbols) {
	return 0;
	 * unreusable because it is not a regular file.

			break;
};
			else
		set = diff_get_color_opt(o, DIFF_FILE_OLD);
	}
			       PARSE_OPT_NONEG | PARSE_OPT_NOARG, diff_opt_binary),
{
			if (c == '+')
	unsigned long changed;
		free(s);
		if (!*ws)
			       &one->oid, one->mode);
void diff_debug_queue(const char *msg, struct diff_queue_struct *q)
	diff_free_filespec_data(one);
	ce = istate->cache[pos];
	if (!o->irreversible_delete)
/*
	static int done_preparing = 0;

			key = prepare_entry(o, n);
		(void) utf8_width(&cp, &l);
	num = 0;
	int i;

		decimal_width(max_change) : number_width;
		}
		strbuf_addstr(&sb, i->string);
	}
		 * point if the path requires us to run the content
				 DIFF_SYMBOL_MOVED_LINE_ALT |
			strbuf_reset(&out);
	}
		    (files == 1) ? " %d file changed" : " %d files changed",
 *      that is: a graph prefix must be printed following a '\n'
	assert(opt);
	 *
	return p->score * 100 / MAX_SCORE;
		len = name_width;
	options->anchors_nr = 0;
	else
		s->data = repo_read_object_file(r, &s->oid, &type, &s->size);
		/* Not a plus or minus line? */
		 * Note: this check uses xsize_t(st.st_size) that may
		OPT_BIT_F(0, "raw", &options->output_format,
	deflated = xmalloc(bound);
			line[0] = bytes - 26 + 'a' - 1;
		struct strbuf sb = STRBUF_INIT;
{
};
		if (!ws_blank_line(prev_eol + 1, ptr - prev_eol, ws_rule))

 *
	f->line = e->line ? xmemdupz(e->line, e->len) : NULL;
{
		len1 = remove_space(p->one->path, strlen(p->one->path));

	int need_two = quote_c_style(two, NULL, NULL, 1);
	ALLOC_GROW(buffer->text.ptr, buffer->text.size + len, buffer->alloc);

			if (s->size > big_file_threshold && s->is_binary == -1) {
		if (diff_algorithm < 0)
void diff_free_filepair(struct diff_filepair *p)
	return filter_bit[(int) status];
	}
int git_diff_ui_config(const char *var, const char *value, void *cb)
	if (options->set_default)
		strbuf_reset(&header);

}


				write_name_quoted(file->from_name, options->file, '\0');

	xdemitconf_t xecfg;
		goto free_and_return;
{
		fill_filespec(one, oid, oid_valid, mode);
{
	scale = 1;

		moved_block_clear(&pmb[n]);
	options->context = diff_context_default;
	}
			  DIFF_FORMAT_SUMMARY, PARSE_OPT_NONEG),

}
			int w = 14 + decimal_width(file->added)
				strbuf_addstr(&sb, reset);
{
			      const char *xfrm_msg,
static struct diff_tempfile *claim_diff_tempfile(void)
	struct strbuf msgbuf = STRBUF_INIT;

			strchr(line, ' ') ? "\t" : "");
{
static int is_summary_empty(const struct diff_queue_struct *q)
		int abbrev = o->flags.full_index ? hexsz : DEFAULT_ABBREV;
		one->driver = userdiff_find_by_path(istate, one->path);
		fputs("~\n", o->file);
	if (diff_no_prefix) {
		   const char **av, int ac, const char *prefix)
		 (p->two->mode & 0777) == 0755)
		free (ecbdata->diff_words->minus.orig);
	options->close_file = 1;
			       diff_opt_ignore_submodules),
		strbuf_addf(&sb, " %s ", newdelete);
	} else
	const char *cp, *ep;

		out->size += j - i + 1;
		OPT_COLOR_FLAG(0, "color", &options->use_color,

	if (*ptr != '\n')
			return *begin >= *end;
		memset(&ecbdata, 0, sizeof(ecbdata));
	}
	memcpy(o, orig_opts, sizeof(struct diff_options));
		options->submodule_format = DIFF_SUBMODULE_LOG;
					    struct moved_entry *match,
		emit_diff_symbol(ecb->opt, DIFF_SYMBOL_NO_LF_EOF, NULL, 0, 0);

	 */
			die("unable to generate checkdiff for %s", one->path);
	    (DIFF_FILE_VALID(p->two) && S_ISDIR(p->two->mode)))
		OPT_CALLBACK_F(0, "color-words", options, N_("<regex>"),
{
		if (cm < 0)

		const char *prefix = "";
		OPT_GROUP(N_("Diff output format options")),
		break;
	 * The caller knows a dirstat-related option is given from the command
	if (!stable)
	strbuf_addf(&header, "%s%sdiff --git %s %s%s\n", line_prefix, meta, a_one, b_two, reset);
		 * only the size, we cannot return early at this
}
				 struct diff_options *orig_opts,
	 */
	if (orig_opts->emitted_symbols)
}
	emit_diff_symbol(o, DIFF_SYMBOL_SUBMODULE_ADD, line, strlen(line), 0);
	/* Find common suffix */
					&one->oid : &null_oid),
	for(n = 0; n < pmb_nr; n++)


			       N_("output the distribution of relative amount of changes for each sub-directory"),
 *
		ecbdata->diff_words->word_regex = (regex_t *)

static void mark_color_as_moved(struct diff_options *o,
	strbuf_release(&errmsg);
		return "mode +x";
	if (cm & COLOR_MOVED_WS_ERROR)
		return;
}
				const char *optarg, int unset)

	case DIFF_SYMBOL_CONTEXT_FRAGINFO:
	oidset_insert(opt->objfind, &oid);
			len--;
static void diff_filespec_load_driver(struct diff_filespec *one,
			patch_id_add_string(&ctx, "+++b/");
			optch = toupper(optch);
	unsigned char *deflated;
			       PARSE_OPT_NONEG, diff_opt_char),
	options->output_indicators[OUTPUT_INDICATOR_NEW] = '+';
}
			       N_("break complete rewrite changes into pairs of delete and create"),
			N_("produce the smallest possible diff"),

		char *p = memchr(buf, '\n', count);
			options->flags.dirstat_by_line = 0;
	string_list_clear(&params, 0);

	DIFF_QUEUE_CLEAR(&outq);



		p->status = 0; /* undecided */
			 struct diff_options *o,
		    errmsg.buf);
			the_hash_algo->update_fn(&ctx, oid_to_hex(&p->two->oid),
	p = strchr(line, '-');
{

				/* .. and ignore any further digits */
	name_a = a->one ? a->one->path : a->two->path;
			line_prefix, data->filename, data->lineno, err);
			     mmfile_t *one, mmfile_t *two)
int diff_queue_is_empty(void)
		graph_width = options->stat_graph_width;
		} else if (!strcmp(p, "files")) {
	}
	if (DIFF_FILE_VALID(one) != DIFF_FILE_VALID(two) ||
	/*
				continue;
		quote_c_style(a, name, NULL, 0);
}
		return NULL;
		die_errno("unable to create temp-file");
	/* 20-byte sum, with carry */
		    int oid_valid,
	/*
	options->file = xfopen(path, "w");
				static char *err;

			s->should_free = 1;
static void diffcore_apply_filter(struct diff_options *options)
		strip_prefix(opt->prefix_length, &name_a, &name_b);
}
			mark_color_as_moved(o, &add_lines, &del_lines);
	struct argv_array env = ARGV_ARRAY_INIT;
		emit_diff_symbol(diff_words->opt, DIFF_SYMBOL_WORD_DIFF,
			char c = !len ? 0 : line[0];
		default_diff_options.dirstat_permille = diff_dirstat_permille_default;
			if (!strcmp(p->one->path, p->two->path))

	if (!ws && !set_sign)
		}
		if (!diff_temp[i].name)
{

			 * The following heuristic assumes that there are 64
	if (!DIFF_FILE_VALID(one))
		if (negate)
				   const char *arg, int unset)

	case DIFF_SYMBOL_CONTEXT_INCOMPLETE:
		flags |= XDF_IGNORE_WHITESPACE;
 * including the nth line.
			s->data = strbuf_detach(&buf, &size);
		struct moved_entry *key;
	GIT_COLOR_YELLOW,	/* COMMIT */
	unsigned short carry = 0;
void diff_free_filespec_data(struct diff_filespec *s)
		if (!strcmp(sb.buf, "no"))
		fd = open(s->path, O_RDONLY);
	stream.avail_out = bound;
			else if (c == '+')
	char *end;
	struct diff_options *options = opt->value;
			   struct oid_array *to_fetch,
}
	if (cnt <= 0)
	 */
	struct strbuf out = STRBUF_INIT;
			return -1;
		    oid_to_hex(&s->oid), dirty);
	const char *lbl[2];
		for (prev_eol = ptr; mf->ptr <= prev_eol; prev_eol--)
			return error(_("%s expects a numerical value"), "--unified");
	if (p->done_skip_stat_unmatch)
	    !diff_filespec_is_identical(r, p->one, p->two)) /* (2) */
	DIFF_SYMBOL_CONTEXT_MARKER,
		    !o->flags.binary) {
		warning(_(rename_limit_warning));
}
		}
	 * not produce diffs, but when you are doing copy
	fwrite(line, len, 1, file);
	emit_diff_symbol(ecbdata->opt,
static int diff_opt_compact_summary(const struct option *opt,
	if (ecbdata->label_path[0]) {
	}
	 * starting from "XXX" should fit in graph_width.
				buffer->orig_alloc);
		default:
		strbuf_addf(msg, "%s%ssimilarity index %d%%",
		if (len < abblen && abblen <= len + 2)


	if (parse_submodule_params(options, arg))
}
	return ac;
			set_sign = set;
			       PARSE_OPT_NONEG | PARSE_OPT_NOARG, diff_opt_no_prefix),
};
		 */
}
	case '=': case '>': case '<': case '|':
			break;
{
		setup_pager();
	lc_a = count_lines(data_one, size_one);
	if (diff_words->current_plus != plus_begin) {
	int result = 0;

		OPT_BITOP(0, "patch-with-stat", &options->output_format,
				 NULL, 0, 0);
		} else if (!strcmp(p, "cumulative")) {
	if (qlen_a || qlen_b) {
	 */
}
	const char *set = diff_get_color(use_color, DIFF_METAINFO);

	case DIFF_SYMBOL_HEADER:
			DIFF_SYMBOL_WORDS_PORCELAIN : DIFF_SYMBOL_WORDS;

		strbuf_addf(msg, "%s\n%s%srename from ",
		mf2.size = size_two;
	 * recursive bits for other formats here.
			die("cannot read data blob for %s", one->path);
	DIFF_SYMBOL_STATS_SUMMARY_ABBREV,
	if (one->driver)
	char *path;
	options->pickaxe_opts |= DIFF_PICKAXE_KIND_G;
	 * If the previous lines of this block were all blank then set its
		strbuf_addstr(&sb, newline);
	 * and because it is easy to find people oneline advising "git diff
		options->a_prefix = options->b_prefix = "";
			   PARSE_OPT_NO_INTERNAL_HELP |
				flipped_block = 0;
		break;
		temp->name = "/dev/null";
} diff_temp[2];
		needs_reset = 1;
			  XDF_IGNORE_CR_AT_EOL, PARSE_OPT_NONEG),
{
	int marker_size = data->conflict_marker_size;
		data += len;
	data.ctx = &ctx;
	unsigned ws_rule = ecbdata->ws_rule;
		o->emitted_symbols =
{
	}
			len--;
		/*
	size_t l = len;
		fn_out_diff_words_write_helper(diff_words->opt,


		return COLOR_MOVED_ZEBRA_DIM;
}
		case DIFF_SYMBOL_MOVED_LINE |
static char *get_compact_summary(const struct diff_filepair *p, int is_renamed)

	if (a_width == INDENT_BLANKLINE && c_width == INDENT_BLANKLINE)
			 * preimage, more "+" lines may come after it.
			pmb_advance_or_null_multi_match(o, match, hm, pmb, pmb_nr, n);
	else {
	the_hash_algo->update_fn(ctx, str, strlen(str));

	if (options->use_color != GIT_COLOR_ALWAYS)
	    dirstat_by_line) {
		quote_c_style(other, msg, NULL, 0);
		OPT__ABBREV(&options->abbrev),
{
		diff_populate_filespec(o->repo, two, 0);
static int find_word_boundaries(mmfile_t *buffer, regex_t *word_regex,
		x->name = xstrdup(name_b);
	 */


{
			set_sign = set;
 * the work tree has that object contents, return true, so that

		if (S_ISLNK(st.st_mode)) {
	    ecbdata->diff_words->plus.text.size)
			       struct emit_callback *ecbdata)
	strbuf_release(&names);
		result->hash[i] = carry;
			  diff_words, &xpp, &xecfg))
			set = diff_get_color_opt(o, DIFF_FILE_NEW_MOVED);
			break; /* truncated in the middle? */
		if (one->mode != two->mode) {
	} else if (!strcmp(opt->long_name, "dirstat-by-file"))
		sum_changes += changes;
			 N_("treat all files as text")),
static int diff_context_default = 3;
	[DIFF_FILE_OLD_MOVED_ALT]     = "oldMovedAlternative",
	const char *a_prefix, *b_prefix;
	return 0;
		data->status |= bad;
{
		} else {
	int i, len, add, del, adds = 0, dels = 0;


		}
			set = diff_get_color_opt(o, DIFF_FILE_OLD_MOVED_ALT_DIM);
	case DIFF_SYMBOL_SUBMODULE_DEL:
		 */
		break;
		options->close_file = 1;
	for (i = 0; i < the_hash_algo->rawsz; ++i) {

	 */
static int parse_submodule_params(struct diff_options *options, const char *value)
				     p->one->path);
		free_filespec(df);


		else if (!strcmp(arg, "porcelain"))
			diffcore_merge_broken();
	int result = diff_get_patch_id(options, oid, diff_header_only, stable);
		emit_line_ws_markup(o, set_sign, set, reset,
	    (S_IFMT & one->mode) != (S_IFMT & two->mode)) {
			xecfg.flags |= XDL_EMIT_FUNCCONTEXT;
		o->emitted_symbols = NULL;
	gather_dirstat(options, &dir, changed, "", 0);

		}
static void prep_parse_options(struct diff_options *options)
	else {
			opt->filter &= ~bit;
	assert(data->o);

	int i;
	 * and rename are all interesting.

	 * (5/8 gives 50 for filename and 30 for the constant parts + graph
{
	struct strbuf sb = STRBUF_INIT;
{
			continue;
		}
			if (check_pair_status(p))
				p->status = DIFF_STATUS_COPIED;
	builtin_checkdiff(name, other, attr_path, p->one, p->two, o);
	/*
			if (options->found_changes)
static void builtin_checkdiff(const char *name_a, const char *name_b,
	if (!nl_just_seen)
static struct diffstat_file *diffstat_add(struct diffstat_t *diffstat,
	 * stat_name_width (if set) and 5/8*width for the filename,
		} else
		emit_diff_symbol(o, DIFF_SYMBOL_HEADER, header.buf,
	if (s->dirty_submodule)
			struct moved_entry *prev = pmb[i].match;
	return 0;

			      const char *optarg, int unset)
			 * DIFF_FILE_VALID(one).
		int i;
static int diff_use_color_default = -1;
		/* Only the matching ones */
			strbuf_addf(&out, " %s%"PRIuMAX"%s",
			  const char *pgm,
}
		x->from_name = xstrdup(name_a);
	unsigned long allot;
			hex[abbrev] = '\0';
static const struct userdiff_funcname *
	for (i = 0; i < data->nr; i++) {
	} else {
			if ( scale < 100000 ) {
			      const char *other,

}
	while (0 < size--) {
					    DIFF_FORMAT_SUMMARY |
			       N_("prepend an additional prefix to every line of output"),
				dim_moved_lines(o);
			       N_("generate diffstat with limited lines"),
	if (!istate->cache)

	else if (needed)

		if (bytes <= 26)
			 */
	 * the contents until later as if the length comparison for a
	free(diffstat->files);
	DIFF_SYMBOL_FILEPAIR_MINUS,
	if (!want_file && would_convert_to_git(istate, name))
	if (!options->filter)
	else if (!same_contents) {
				     opt->long_name);

			 N_("use unmodified files as source to find copies")),
	ALLOC_GROW(diffstat->files, diffstat->nr + 1, diffstat->alloc);
{
	const char *name;
	struct diff_filepair *dp = xcalloc(1, sizeof(*dp));
	diff_words_fill(&diff_words->plus, &plus, diff_words->word_regex);
	free(data);
			    (deletions == 1) ? ", %d deletion(-)" : ", %d deletions(-)",
	    (ret & XDF_WHITESPACE_FLAGS)) {
	if (!options->flags.relative_name)
	const char *reset = diff_get_color_opt(o, DIFF_RESET);
}
struct patch_id_t {

			if (index_path(istate, &one->oid, one->path, &st, 0))
				set = diff_get_color_opt(o, DIFF_FILE_NEW);
		if (DIFF_PAIR_UNMERGED(p))
	}
	return allot - l;
		endp = memchr(data, '\n', size);
	struct diff_filepair *pair;
	 * doesn't need the data in a normal file, this system
			return -1;

	}
			s->size = sb.len;
	strbuf_addf(&sb, " %s %s (%d%%)\n",
		cnt++;
	if (baselen && sources != 1) {
	unsigned char hash[GIT_MAX_RAWSZ];
	if (!*outbuf)
		diff_mnemonic_prefix = git_config_bool(var, value);
		OPT_BIT_F(0, "numstat", &options->output_format,
		BUG("WS rules bit mask overlaps with diff symbol flags");
}
}
	struct moved_block *pmb = NULL; /* potentially moved blocks */
	int width = 0, tab_width = es->flags & WS_TAB_WIDTH_MASK;
		     char **outbuf)
				s->is_binary = 1;
		ws = diff_get_color_opt(o, DIFF_WHITESPACE);
	if (len < marker_size + 1)
{
		if (o->word_diff)
	case DIFF_SYMBOL_SUBMODULE_PIPETHROUGH:
	ecbdata->diff_words =

	strbuf_addch(&sb, '\n');
{
			   const struct hashmap_entry *entry_or_key,
	}
{
	for (i = 0; i < ARRAY_SIZE(diff_temp); i++)
	}
			  DIFF_FORMAT_NAME, PARSE_OPT_NONEG),
		return 0;
	struct diff_queue_struct *q = &diff_queued_diff;
			s->should_munmap = 0;
		} else if (DIFF_FILE_VALID(p->one)) {
		OPT_BOOL(0, "ext-diff", &options->flags.allow_external,
	return 0;


	char *dst = line;
}
	       *old_name == *new_name) {
			add_lines_to_move_detection(o, &add_lines, &del_lines);
					'\n', match[0].rm_eo - match[0].rm_so);
					the_hash_algo->hexsz);
}
		if (p->status == 0)
	case DIFF_SYMBOL_CONTEXT:
	if (skip_prefix(var, "diff.color.", &name) ||
		options->flags.allow_textconv = 0;
 *      *(diff_words->current_plus - 1) == '\n'
			 * file contents altogether.
		 * If the resulting damage is zero, we know that
		return external_diff_cmd;
	argv_array_push(argv, temp->name);

static int diff_rename_limit_default = 400;
	return 0;
		free(deflated);

{
		if (name_width < name_len) {
{

		struct strbuf sb = STRBUF_INIT;
 */
{
	const char *arg = argv[0];
		struct dirstat_file *f = dir->files;
				set = diff_get_color_opt(o, DIFF_FILE_OLD_DIM);
			return 0;
		if (!isspace(s[i]))
		else {
				die("unable to read %s",
	if (diff_mnemonic_prefix && o->flags.reverse_diff) {
			strbuf_addstr(&sb, st_el->prefix);

		 * Instead of appending each, concat all words to a line?
	while (*begin < buffer->size && isspace(buffer->ptr[*begin]))
			else
		/* otherwise we will clear the whole queue
		char *prev_eol;
{

}
	if (!o->word_regex)
		return 0;
	/*
	DIFF_SYMBOL_STATS_SUMMARY_NO_FILES,
   "%d and retry the command.");
		fraginfo = diff_get_color(o->use_color, DIFF_FRAGINFO);
	*q = outq;
	if (*arg != 0)
			    sign, "", 0);
};
	struct strbuf buf = STRBUF_INIT;
	 * for the standard terminal size).
	 */
		s->size);
		if (!regexec_buf(word_regex, buffer->ptr + *begin,

			delta = deflate_it(delta, delta_size, &delta_size);
			  DIFF_FORMAT_NUMSTAT, PARSE_OPT_NONEG),
		remove_tempfile();
				const char *optarg, int unset)
void diff_addremove(struct diff_options *options,
	DIFF_QUEUE_CLEAR(q);

	abbrev = diff_abbrev_oid(oid, len);
		die("internal error in diff-resolve-rename-copy");

#if DIFF_DEBUG
	 * appears only in "diff --raw --abbrev" output and it is not
		break;
	if (!diff_words->plus.text.size) {

	strbuf_release(&msg);
{

		    const char *path,
			 */
	external_diff_cmd = xstrdup_or_null(getenv("GIT_EXTERNAL_DIFF"));
	if (opt->flags.exit_with_status &&
		x->from_name = NULL;
		struct diffstat_file *file = data->files[i];
		esm.nr = 0;
		if (DIFF_PAIR_UNMERGED(p))
	return count;
	int i;
		free(s->data);

			 * The SHA1 has not changed, so pre-/post-content is

{

			if (c == '-')
	BUG_ON_OPT_NEG(unset);
static void add_line_count(struct strbuf *out, int count)
			diff_aligned_abbrev(&p->one->oid, opt->abbrev));
		case DIFF_SYMBOL_MOVED_LINE |
	mf->size = one->size;
	return 0;
	DIFF_STATUS_RENAMED,
	BUG_ON_OPT_ARG(arg);
		textconv_one = get_textconv(o->repo, one);
		 * a filepair that changes between file and symlink
			options->word_diff = DIFF_WORDS_PLAIN;
			       N_("use <regex> to decide what a word is"),
			strbuf_addf(msg, "%s%sdissimilarity index %d%%%s\n",
		strbuf_addch(&res, '"');
	quote_c_style(fs->path, &sb, NULL, 0);
	unsigned long changed;
			  DIFF_FORMAT_NO_OUTPUT),
		show_graph(&out, '-', del, del_c, reset);
		}
		case DIFF_STATUS_ADDED:
		 */
		emit_line(o, fraginfo, reset, line, len);

		if (!cp)

				       (one->oid_valid ?

static void emit_line_0(struct diff_options *o,


		if (!(l->flags & DIFF_SYMBOL_MOVED_LINE))
	argv_array_push(&argv, name);
	}
static void pmb_advance_or_null_multi_match(struct diff_options *o,
		else if (!strcmp(sb.buf, "ignore-all-space"))
		*optarg = arg + 1;
		es->indent_off = off;
		strbuf_addstr(&msgbuf, func);

		ALLOC_GROW(dir.files, dir.nr + 1, dir.alloc);
	if (!strcmp(var, "diff.wserrorhighlight")) {
	dir.cumulative = options->flags.dirstat_cumulative;
		ch = *data++;
	one->dirty_submodule = old_dirty_submodule;
}
		OPT_BIT_F(0, "pickaxe-regex", &options->pickaxe_opts,
{
	if (!strcmp(var, "diff.renamelimit")) {
		fprintf(o->file, "%s", line);
	DIFF_QUEUE_CLEAR(&outq);
	for (i = 0; i < q->nr; i++) {

	GIT_COLOR_BOLD_BLUE,	/* OLD_MOVED ALTERNATIVE */
			 p->one->dirty_submodule ||
		return 1; /* no change */
		unsigned int bit;


}
			     N_("control the order in which files appear in the output")),
		return 0;
		}
			 const char *name_b,
	/* find the end of the word */
	case DIFF_SYMBOL_SUBMODULE_ERROR:
		old_name++;
		s->should_free = 1;
	const char *cp = *cp_p;
		 * correct, but the whole point of big_file_threshold
}
	struct diff_tempfile *temp = prepare_temp_file(r, name, df);
			  size_t *outsize)
				die_errno("stat '%s'", one->path);
			    struct diff_filespec *one)
		     DIFF_SYMBOL_MOVED_LINE_UNINTERESTING:

			       PARSE_OPT_NONEG, diff_opt_find_object),
			diff_populate_filespec(options->repo, p->two, CHECK_SIZE_ONLY);
	const char *prefix;
			break;
	int ch, dot;
		changed += damage;
		 * of objects.
	dir.files = NULL;
				one->is_binary = 0;
}

	    reuse_worktree_file(r->index, s->path, &s->oid, 0)) {
		 memcmp(a + a_off, c + c_off, al - a_off));

	if (!size)
				const char *reset,
		    fill_mmfile(options->repo, &mf2, p->two) < 0)
	delta = NULL;
#include "argv-array.h"

			ret |= XDF_IGNORE_WHITESPACE;
	DIFF_SYMBOL_SUBMODULE_ERROR,
	if (o->color_moved == COLOR_MOVED_PLAIN)
{
	return one->size;
		if (p != buf) {
define_list_config_array_extra(color_diff_slots, {"plain"});
		memset(&xecfg, 0, sizeof(xecfg));


		emit_line_0(o, set_sign ? set_sign : set, NULL, !!set_sign, reset,
		if (size_only && !would_convert_to_git(r->index, s->path))


	static const char *nneof = " No newline at end of file\n";

void diff_change(struct diff_options *options,
 */
			++*otherp;
void diff_emit_submodule_untracked(struct diff_options *o, const char *path)
		return;
		else if (!strcmp(arg, "none"))
		 * "scale" the filename
	struct diff_options *options = opt->value;
			set = diff_get_color_opt(o, DIFF_FILE_NEW_MOVED_ALT_DIM);
		return -1;
	fflush(stdout);
	void *cp;
		if (must_show_header) {
		else

			       PARSE_OPT_OPTARG, diff_opt_color_moved),
	const char *filename;
		minus_begin = diff_words->minus.orig[minus_first].begin;


		/*
	 * and filter and clean them up here before producing the output.
	 * negative value.
	*break_opt = opt1 | (opt2 << 16);
size_t fill_textconv(struct repository *r,
		size -= len;
	struct diff_options *options = opt->value;
	struct diff_filespec *two = p->two;

		}
	if (git_diff_heuristic_config(var, value, cb) < 0)

				  patch_id_consume, &data, &xpp, &xecfg))
static void dim_moved_lines(struct diff_options *o)
	const char *base = basename(path_dup);
}
	struct strbuf sb = STRBUF_INIT;
	strbuf_addstr(&tempfile, base);
	fprintf(stderr, "queue[%d] %s size %lu\n",
			options->word_diff = DIFF_WORDS_COLOR;
}
	}
			damage = DIV_ROUND_UP(damage, 64);
		OPT_CALLBACK_F(0, "color-moved", options, N_("<mode>"),
		return -1;
		hashmap_add(hm, &key->ent);
		fprintf(options->file, "%s", diff_line_prefix(options));
	diff_debug_filespec(p->one, i, "one");
{
	if (!DIFF_FILE_VALID(one))
 * Think of a way to unify them.
			      DIFF_FORMAT_NO_OUTPUT;
			count++;
	 * Please update $__git_diff_submodule_formats in
			       one->data, one->size,
}
		return 0;

		fprintf(data->o->file, "%s%s:%d: %s.\n",
	}
			    REG_EXTENDED | REG_NEWLINE))
	emit_diff_symbol(ecbdata->opt, DIFF_SYMBOL_MINUS, line, len, flags);
		if (*end)
	if (!strcmp(var, "diff.color") || !strcmp(var, "color.diff")) {
static void diff_words_append(char *line, unsigned long len,
	static const char *external_diff_cmd = NULL;
	else if (!strcasecmp(value, "patience"))
	if (o->submodule_format == DIFF_SUBMODULE_LOG &&
		damage = (p->one->size - copied) + added;
		options->flags.default_follow_renames = 0;
	case DIFF_STATUS_UNKNOWN:
	default:
				      DIFF_FORMAT_CHECKDIFF |

			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG,
	options->word_regex = arg;
			       N_("generate diff using the \"patience diff\" algorithm"),
	ALLOC_GROW(o->emitted_symbols->buf,
		}
			    (insertions == 1) ? ", %d insertion(+)" : ", %d insertions(+)",
		die(_("--follow requires exactly one pathspec"));
}
	bound = git_deflate_bound(&stream, size);
	}
		a_prefix = o->b_prefix;
	} else
	struct moved_entry *ret = xmalloc(sizeof(*ret));
		ignored = 1;
	const char *name;
{
}
				    diff_line_prefix(o), lbl[0], lbl[1]);
	if (!one->driver)
			quote_c_style(p->two->path, &sb, NULL, 0);

		 */
	for (lp = 0, rp = pmb_nr - 1; lp <= rp;) {

		diff_words_flush(ecbdata);
		oid_array_append(to_fetch, &filespec->oid);
	if (*otherp && !is_absolute_path(*otherp)) {
	unsigned int hash = xdiff_hash_string(l->line, l->len, flags);
	BUG_ON_OPT_NEG(unset);
	if (o->flags.reverse_diff) {
	diffstat->files[diffstat->nr++] = x;
			 is_null_oid(&p->one->oid))
		case DIFF_SYMBOL_MOVED_LINE |

	case DIFF_SYMBOL_STAT_SEP:
		buf = p + 1;
			strbuf_addf(&out, " %*s", number_width, "Bin");

				write_name_quoted(file->name, options->file,
	 * Order: raw, stat, summary, patch
			set_sign = NULL;
	options->stat_width = width;
		/* ignore errors, as we might be in a readonly repository */
	if (S_ISREG(one->mode))
	 * full object name.  Yes, this may be suboptimal, but this
		dirstat_by_line = 1;
		 * needs to be split into deletion and creation.
				 out.buf, out.len, 0);
}
	else

		    (l->flags & DIFF_SYMBOL_MOVED_LINE_ZEBRA_MASK)) &&
		strbuf_addf(&header, "%s%snew file mode %06o%s\n", line_prefix, meta, two->mode, reset);
	struct diffstat_t *diffstat = priv;
			ret |= COLOR_MOVED_WS_ALLOW_INDENTATION_CHANGE;
			 * contents from the work tree, we always want
	}
static void show_dirstat(struct diff_options *options)


			       N_("show colored diff")),
			     PARSE_OPT_NONEG),
	/* large enough for 2^32 in octal */
					  &size);
			} else {
		strbuf_release(&sb);
	const char *other;
	    (DIFF_FILE_VALID(p->two) && S_ISDIR(p->two->mode)))
				del = total - add;
		BUG("%s should not get here", opt->long_name);
	free(plus.ptr);
		free(err);
	 */
					    struct hashmap *hm,
			  N_("synonym for '-p --stat'"),
	 * If the user asked for our exit code, then either they want --quiet
	/*
	emit_diff_symbol(o, DIFF_SYMBOL_SUBMODULE_HEADER,
			  DIFF_FORMAT_RAW, PARSE_OPT_NONEG),
	struct string_list_item *i;

			emit_diff_symbol(o, DIFF_SYMBOL_BINARY_FILES,
	strbuf_addch(&sb, '\n');
}
	strbuf_addstr(&tempfile, "XXXXXX_");
	dir.cumulative = options->flags.dirstat_cumulative;
	      ecbdata->blank_at_eof_in_preimage <= ecbdata->lno_in_preimage &&
{
	if (needs_reset)
			memset(&pmb[rp], 0, sizeof(pmb[rp]));
	struct stat st;
					  const char *newline,
		if (pmb_nr == 0) {
			/*
	struct strbuf *msgbuf;
	struct strbuf sb = STRBUF_INIT;
void diff_flush(struct diff_options *options)
	/* Remember the number of running sets */
};
	unsigned ws_rule;
	return 0;
		o->word_regex = userdiff_word_regex(two, o->repo->index);
	/* This may look odd, but it is a preparation for
	}
			emit_diff_symbol(options, DIFF_SYMBOL_STATS_LINE,
		line[len++] = '\n';
static unsigned int filter_bit['Z' + 1];
			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG, diff_opt_color_words),
	case DIFF_SYMBOL_PLUS:
 * The last block consists of the (n - block_length)'th line up to but not
}
	    p->status == DIFF_STATUS_RENAMED) {
	if (minus_begin != minus_end) {
			nl_just_seen = 0;
}
			struct diff_filepair *p = q->queue[i];
		if (!s->data)
static int diff_opt_patience(const struct option *opt,
		*(diff_words->current_plus - 1) == '\n')) {
		cp = (char *) cp + bytes;
			fprintf(options->file,
	del_c = diff_get_color_opt(options, DIFF_FILE_OLD);
	return 0;
	struct diff_filespec *spec;
{
			ecbdata->diff_words->type == DIFF_WORDS_PORCELAIN ?
	if (!textconv) {
		break;
			if (*end == ',')
}
			else if ((p->two->mode & 0777) == 0755)
			    line_prefix, set, similarity_index(p));
		xpp.flags = o->xdl_opts;
			       N_("generate diffstat"),
	[DIFF_FUNCINFO]		      = "func",
	while (*end < buffer->size && !isspace(buffer->ptr[*end]))
	const struct dirstat_file *b = _b;
		if (pe)
			     o, p);
		OPT_BIT_F(0, "pickaxe-all", &options->pickaxe_opts,

	}
				+ decimal_width(file->deleted);
{
		separator++;
			     struct diff_filespec *one,
			 * binary files counts bytes, not lines. Must find some
		return 0;
	/*
			return error(_("%s expects a numerical value"),
		s->data = strbuf_detach(&buf, NULL);
}
			if (size_only)
	 */
		if (slot < 0)
 *   1. collect the minus/plus lines of a diff hunk, divided into
		struct diff_queue_struct *q = &diff_queued_diff;
				    OUTPUT_INDICATOR_NEW, line, len,
	mmfile_t text;
			       N_("when run from subdir, exclude changes outside and show relative paths"),

			emit_binary_diff(o, &mf1, &mf2);
	 *    the identical contents.
		free((char *)data_one);
		if (*old_name == '/')
			copied = 0;
}
		 !memcmp(a, b, al) && !
					 sb.buf, sb.len, 0);
		int fd;
		dirty = "-dirty";
static int diff_opt_line_prefix(const struct option *opt,

			alnum_count++;
				    flags & (DIFF_SYMBOL_CONTENT_WS_MASK), 0);
		emit_line_0(o, set, NULL, 0, reset, sign, line, len);
	diff_debug_queue("resolve-rename-copy done", q);
		if (**namep == '/')
			diff_words_flush(ecbdata);
	switch (s) {
		fprintf(o->file, "%sSubmodule %s contains untracked content\n",
			*begin += match[0].rm_so;

		return;



}
		return;
		char *s = xstrfmt("%"PRIuMAX , (uintmax_t)orig_size);
		x->added++;
			      o->file, set, reset, ws);
			inter_name_termination);
		OPT_CALLBACK_F(0, "stat-name-width", options, N_("<width>"),
	BUG_ON_OPT_NEG(unset);
		}
	return spec;
			!strcmp(var, "diff.suppress-blank-empty")) {
	if ((DIFF_FILE_VALID(p->one) && S_ISDIR(p->one->mode)) ||
	struct emitted_diff_symbol e = {line, len, flags, 0, 0, s};
		OPT_CALLBACK_F(0, "output-indicator-old",

	diff_filespec_load_driver(one, o->repo->index);
			 path, strlen(path), 0);
	if (DIFF_PAIR_UNMERGED(p)) {
	struct diff_words_style_elem new_word, old_word, ctx;
 * score line or hunk/file headers would only need to store a number or path

	if (!options->a_prefix)
		x->name = xstrdup(name_a);
{
		break;
			rp--;

	 *
		line[len] = '\0';
		const struct userdiff_funcname *pe;
			added = p->two->size;
			    reset, line_prefix, set);
	if (output_format & DIFF_FORMAT_SUMMARY && !is_summary_empty(q)) {
		return 0;
			  N_("show all changes in the changeset with -S or -G"),
		free(f->from_name);
	case DIFF_STATUS_COPIED:
	[DIFF_FILE_NEW_MOVED]	      = "newMoved",
		strbuf_trim(&sb);
		options->stat_graph_width = diff_stat_graph_width;
		data = delta;

	} else {
		if (textconv_one)
static void run_checkdiff(struct diff_filepair *p, struct diff_options *o)
	 * Both --patience and --anchored use PATIENCE_DIFF
			     N_("show the given destination prefix instead of \"b/\""),
	[DIFF_CONTEXT]		      = "context",
			   unsigned long size,
	 * it always is at least 10 bytes long.
	 * name-a => name-b
	struct diff_options *options = opt->value;
	}
			pmb[lp] = pmb[rp];
			      p->one->path);
		strbuf_addstr(&out, "?,?");
			graph_width = options->stat_graph_width;
		const char *begin, *end;

static int cmp_in_block_with_wsd(const struct diff_options *o,
	while(1) {
		break;
			return -1;
		return;
	if (arg) {
		 */
		if (fd < 0)
}
static int diff_opt_follow(const struct option *opt,
		 * but we would need an extra call after all diffing is done.
 *      place them into two mmfile_t with one word for each line;

	return one->driver->word_regex;
			    0),
		return color_parse(value, diff_colors[slot]);
	 * We do not read the cache ourselves here, because the
		    (l->flags & DIFF_SYMBOL_MOVED_LINE_ZEBRA_MASK))) {
	options->flags.binary = 1;
	for (n = 0; n < o->emitted_symbols->nr; n++) {
		return 0;
static void builtin_diffstat(const char *name_a, const char *name_b,
	/* Show all directories with more than x% of the changes */
			 const char *name,
	int cnt;
		if (p->one->mode == 0) {
		if (is_tempfile_active(diff_temp[i].tempfile))
			strbuf_addstr(&header, xfrm_msg);
}
		options->a_prefix = "a/";
		OPT_FILENAME('O', NULL, &options->orderfile,
					  struct diff_words_style_elem *st_el,
	else if (!strcmp(arg, "plain"))
				    set, similarity_index(p), reset);
	int ret = 0;
			&style->old_word, style->newline,
{
	struct diff_options *options = opt->value;
			 DIFF_SYMBOL_CONTEXT_FRAGINFO, msgbuf.buf, msgbuf.len, 0);
static long gather_dirstat(struct diff_options *opt, struct dirstat_dir *dir,
		}
			 * defer processing. If this is the end of
			else {
found_damage:

	}

	if (!driver) {
			set_sign = NULL;

	struct checkdiff_t *data = priv;

	}
	 * which but should not make any difference).
}
		return;
	return 0;
		data->comments = get_compact_summary(p, data->is_renamed);
	}

		struct diff_filepair *p = q->queue[i];
	}

	return opt->filter & filter_bit[(int) status];
{
		mf->ptr = (char *)""; /* does not matter */
{
static void diff_flush_patch_all_file_pairs(struct diff_options *o)
{

	}
struct dirstat_file {
	char *err;
		}
					struct diff_filespec *one)
				 struct diff_filespec *two)
{
			type = oid_object_info(r, &s->oid, &s->size);
		return COLOR_MOVED_NO;
		return error(_("unable to resolve '%s'"), arg);
N_("only found copies from modified paths due to too many files.");
		return 0;
	 * the automatic sizing is supposed to give abblen that ensures
		return 1;

		}
		struct diff_filepair *p = q->queue[i];
		struct diffstat_file *f = diffstat->files[i];
				name = slash;

		struct emitted_diff_symbol *prev = (n != 0) ?
	{ DIFF_WORDS_PORCELAIN, {"+", "\n"}, {"-", "\n"}, {" ", "\n"}, "~\n" },


{
				int sign_index, const char *line, int len,
	strbuf_reset(&a_name);
	DIFF_QUEUE_CLEAR(q);

			       N_("generate diff using the \"anchored diff\" algorithm"),
		die_errno("unable to write temp-file");
			else if (c == '@')
	else
	f = &o->emitted_symbols->buf[o->emitted_symbols->nr++];
		return -1;
		if (slash) {
		int name_len;
		struct diff_filepair *p)
	int i = 1;


					  textconv_one, textconv_two, o);
		    S_ISREG(one->mode) && S_ISREG(two->mode) &&

				  &xpp, &xecfg))
	}
{
	if (line[0] == '+')
		int slot = parse_diff_color_slot(name);
			      1, PARSE_OPT_NONEG),
		   o->emitted_symbols->alloc);
			continue;
		context = diff_get_color_opt(o, DIFF_CONTEXT);
	BUG_ON_OPT_ARG(arg);
			 N_("generate diffs with <n> lines context")),
	case DIFF_SYMBOL_STATS_LINE:

	strbuf_add(name, a + pfx_length, a_midlen);
	case DIFF_SYMBOL_FILEPAIR_PLUS:
	if (!o->flags.allow_external)

		emit_diff_symbol(o, DIFF_SYMBOL_HEADER, header.buf, header.len, 0);
	return external_diff_cmd;
		strbuf_release(&sb);
		else
		ecbdata.label_path = lbl;
	for (i = 0; i < data->nr; i++) {
static void diff_words_show(struct diff_words_data *diff_words)
	ALLOC_GROW(queue->queue, queue->nr + 1, queue->alloc);
			return error("unable to read files to diff");
/*
static void emit_diff_symbol_from_struct(struct diff_options *o,
	}
	 * It does not make sense to show the first hit we happened
	if (file->print_name)

	quote_two_c_style(&b_name, b_prefix, name_b, 0);
{

	char *params_copy = xstrdup(params_string);
		}

	struct emitted_diff_symbol *l = &o->emitted_symbols->buf[n];
	strbuf_addstr(out, set);
				return error(_("invalid --stat value: %s"), value);
static char diff_colors[][COLOR_MAXLEN] = {
	 * aren't enough.
			     const char *arg, int unset)
	    opt->flags.check_failed)

{
	return NULL;
		break;
		arg = "";
			pmb[i].match = pmb[i].match->next_line;
			strbuf_addf(&out, "%s%"PRIuMAX"%s",
	/*
			strbuf_addstr(&out, " bytes\n");
		return cnt;
}
	if (has_trailing_carriage_return)
			   struct diff_filespec *s,

		options->stat_name_width : max_len;
	    DIFF_FILE_VALID(one) && DIFF_FILE_VALID(two) &&
		run_diff_cmd(pgm, name, other, attr_path,
	for (i = 0; i < q->nr; i++) {
			}
{
	/*
		if (file->is_unmerged) {
		free(f->name);
	struct diff_queue_struct outq;

		else

	} else if (!arg) {
	case DIFF_STATUS_ADDED:
#include "tempfile.h"
			return 0;

{
		/* store one word */
		struct stat st;
			      struct diff_filespec *two,
{
	ptr += size - 1; /* pointing at the very end */
	    strncmp(concatpath, options->prefix, options->prefix_length))
};
	int need_one = quote_c_style(one, NULL, NULL, 1);

	if (*arg != '\0')
}
{
	/*
	BUG_ON_OPT_NEG(unset);
	BUG_ON_OPT_NEG(unset);
	options->xdl_opts = DIFF_WITH_ALG(options, PATIENCE_DIFF);
			char c = !len ? 0 : line[0];
			  N_("generate the diff in raw format"),
			damage = 0;
	}
		struct strbuf errmsg = STRBUF_INIT;
		opt2 = parse_rename_score(&arg);
		OPT_CALLBACK_F(0, "anchored", options, N_("<text>"),
	    a_off = a->indent_off,
	      ecbdata->blank_at_eof_in_preimage &&
			       N_("show word diff, using <mode> to delimit changed words"),
void diff_warn_rename_limit(const char *varname, int needed, int degraded_cc)
	    diff_populate_filespec(r, p->one, CHECK_SIZE_ONLY) ||
		options->flags.diff_from_contents = 1;
		}
		OPT_CALLBACK_F(0, "textconv", options, NULL,
{
	 */
}
{
		ch = *cp;
 * sometimes to "/dev/null".
	has_trailing_carriage_return = (len > 0 && line[len-1] == '\r');
			break;
}
				emit_diff_symbol(o, DIFF_SYMBOL_HEADER,
	struct diff_options *opt = option->value;
	      ecbdata->blank_at_eof_in_postimage <= ecbdata->lno_in_postimage))
			options->word_diff = DIFF_WORDS_PORCELAIN;
	if (file->is_renamed)
			if (!*end)

	if (!s->oid_valid ||
		if (value) {
		if (!bad)
	struct diff_options *options = opt->value;

	/*
 *
	/*

		memset(&xpp, 0, sizeof(xpp));
{
			    diff_abbrev_oid(&two->oid, abbrev));
	one = alloc_filespec(concatpath);
	struct diff_options *options = opt->value;
			     arg);
		options->a_prefix = a;
		die("unable to read files to diff");
enum diff_symbol {
			line, reset,
		OPT_END()
	case DIFF_STATUS_RENAMED:

	deflated = deflate_it(two->ptr, two->size, &deflate_size);

			  DIFF_FORMAT_NO_OUTPUT),
	/*

	for (cp = ep; ep - line < len; ep++)
};
	if (!DIFF_FILE_VALID(p->one) || /* (1) */
void diff_emit_submodule_add(struct diff_options *o, const char *line)
		}
			ret |= COLOR_MOVED_WS_ERROR;
	long size = mf->size;
		diff_debug_filepair(p, i);
		struct diff_filepair *p = q->queue[i];
	 * that case, and will end up always appending three-dots, but

	case DIFF_SYMBOL_BINARY_DIFF_BODY:
		show_rename_copy(opt, "rename", p);
		} else if (starts_with(line, "\\ ")) {
		emit_line_0(o, ws, NULL, 0, reset, sign, line, len);
	if (get_oid(arg, &oid))
 * This function splits the words in buffer->text, stores the list with
		} else if (p->status == DIFF_STATUS_DELETED)
}
}
	const char *line = eds->line;
			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG,
					 header.buf, header.len, 0);
	char mode[10];
	DIFF_SYMBOL_BINARY_DIFF_HEADER_DELTA,
{
		xpparam_t xpp;
	}

	if (abblen < the_hash_algo->hexsz - 3) {
static void diff_flush_checkdiff(struct diff_filepair *p,
		else if (!DIFF_FILE_VALID(p->two))
		}
}
			strbuf_reset(&sb);
	if (len < marker_size + 1 || !isspace(line[marker_size]))
		if (!o->flags.dual_color_diffed_diffs)
		 */
		ecbdata->lno_in_preimage++;
		if (max_change < change)
	{ DIFF_WORDS_COLOR, {"", ""}, {"", ""}, {"", ""}, "\n" }
static void add_if_missing(struct repository *r,
int diff_opt_parse(struct diff_options *options,



	reset = diff_get_color_opt(options, DIFF_RESET);
		prep_temp_blob(r->index, name, temp,
	if (options->output_format & (DIFF_FORMAT_PATCH |
	DIFF_SYMBOL_CONTEXT,
	return one->is_binary;
				     opt->long_name);
	/* skip any \v \f \r at start of indentation */
	return 0;
		if (fill_mmfile(options->repo, &mf1, p->one) < 0 ||
	 * or:    name/name-status/checkdiff (other bits clear)
		}
		reset = diff_get_color_opt(o, DIFF_RESET);
			      const char *arg, int unset)
		int i;
 *      minus-lines and plus-lines;
				 diffstat, o, p);
				    COLOR_MOVED_WS_ALLOW_INDENTATION_CHANGE) {
{
	o.file = fp;
	pos = index_name_pos(istate, name, len);
		options->output_format |= DIFF_FORMAT_DIFFSTAT;
static const char *external_diff(void)
	}

				    line_prefix,
		if (file->is_binary) {
		fill_filespec(two, oid, oid_valid, mode);
				"%"PRIuMAX"\t%"PRIuMAX"\t",
			 * (with each file contributing equal damage).
		return NULL;
	}
		else if (!strcmp(sb.buf, "ignore-space-at-eol"))

		if (count) {
	}
	emit_binary_diff_body(o, one, two);
			check_blank_at_eof(&mf1, &mf2, &ecbdata);
#include "ll-merge.h"
		ws_check_emit(line, len, ws_rule,
			must_show_header = 1;
	options->rename_limit = -1;
	data->is_interesting = p->status != DIFF_STATUS_UNKNOWN;
	*arg++ = pgm;
}


			negate = 1;
	}
	struct strbuf buf = STRBUF_INIT;
	ALLOC_GROW(buffer->orig, 1, buffer->orig_alloc);
	/* clear out previous settings */
			       N_("specify the character to indicate a context instead of ' '"),
			break;
struct diff_filepair *diff_queue(struct diff_queue_struct *queue,
	/* Show all directories with more than x% of the changes */
		    char **buf,
			      N_("omit the preimage for deletes"),

			strbuf_add(&sb, buf, p ? p - buf : count);

}
		diff_no_prefix = git_config_bool(var, value);
	} else if (!strcmp(opt->long_name, "stat-name-width")) {
static void emit_line_ws_markup(struct diff_options *o,
{
	pair = diff_queue(&diff_queued_diff, one, two);
		ecbdata->lno_in_postimage++;
		if (xdi_diff_outf(&mf1, &mf2, checkdiff_consume_hunk,
	const int hexsz = the_hash_algo->hexsz;

	BUG_ON_OPT_NEG(unset);
		}
	return 0;
				     const char *line, int len)
{
	/* The hunk header in fraginfo color */
			if (options->stat_sep)
		     DIFF_SYMBOL_MOVED_LINE_UNINTERESTING:
		struct moved_entry *match = NULL;
/*
	memset(&o, 0, sizeof(o));
							     &pmb[pmb_nr].wsd))
					    struct moved_block *pmb,
		case DIFF_SYMBOL_PLUS:
		if (p->score) {

	/*

		int found;
static unsigned long diff_filespec_size(struct repository *r,
	if (width < 16 + 6 + number_width)
		return;
			}
			   PARSE_OPT_ONE_SHOT |

}
	if (!opt->flags.exit_with_status &&
	options->flags.rename_empty = 1;
}
	if (!external_diff_cmd)
		OPT_BIT(0, "minimal", &options->xdl_opts,
			adjust_last_block(o, n, block_length);
static int diff_opt_word_diff(const struct option *opt,
	const char *context, *reset, *set, *set_sign, *meta, *fraginfo;
static int new_blank_line_at_eof(struct emit_callback *ecbdata, const char *line, int len)

}
			add_if_missing(options->repo, &to_fetch, p->two);
		 */

 * diff-cmd name infile1 infile1-sha1 infile1-mode \
			val = WSEH_NEW | WSEH_OLD | WSEH_CONTEXT;
		die(_("Failed to parse --dirstat/-X option parameter:\n%s"),
			p->status = DIFF_STATUS_TYPE_CHANGED;
 */
static struct diff_options default_diff_options;
		}
	if (!two)
			while (s[++off] == '\t')
	/*
		return;
			      want_color(o->use_color) && !pgm);
	ret->next_line = NULL;
 * but that configuration can be overridden from the command line.

		strbuf_addstr(&res, one);
	 *    differences.
		DIFF_FILE_VALID(s) ? "valid" : "invalid",
		unsigned cm = parse_color_moved_ws(value);
		options->color_moved = 0;
	else if (!S_ISLNK(p->one->mode) && S_ISLNK(p->two->mode))
	return strcmp(name_a, name_b);
	const char *current_plus;
	return 1;
		delta = a_width - c_width;
			options->flags.dirstat_cumulative = 1;
static void show_file_mode_name(struct diff_options *opt, const char *newdelete, struct diff_filespec *fs)
		OPT_CALLBACK_F('X', "dirstat", options, N_("<param1,param2>..."),
					    DIFF_FORMAT_DIFFSTAT |
		OPT_BIT_F(0, "name-only", &options->output_format,

		*otherp += prefix_length;
					  &df->oid,
		drv = userdiff_find_by_path(o->repo->index, attr_path);
		diff_words->current_plus == diff_words->plus.text.ptr) ||
	struct diff_queue_struct outq;
static int dirstat_compare(const void *_a, const void *_b)
			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG, diff_opt_unified),
	return 0;
		      struct diff_queue_struct *q)
	name_a = DIFF_FILE_VALID(one) ? name_a : name_b;
	if (output_format & DIFF_FORMAT_DIRSTAT && options->flags.dirstat_by_line)
	if (!strcmp(var, "diff.context")) {
	const char *p;
		if (!strcmp(p, "changes")) {
			data->deleted = diff_filespec_size(o->repo, one);
		if (line[len - i] == '\r' || line[len - i] == '\n')
		OPT_CALLBACK_F(0, "binary", options, NULL,
	int pos, len;
	}
	struct diff_words_style *style;
		minus_begin = minus_end =
		return;
	strbuf_release(&msgbuf);
	switch (p->status) {
	 * Feeding the same new and old to diff_change()
#include "color.h"
}

		else if (!DIFF_FILE_VALID(p->one))
	const char *name;
		s->size = xsize_t(st.st_size);
				struct strbuf *errmsg)
				struct hashmap *del_lines)
		OPT_BIT(0, "indent-heuristic", &options->xdl_opts,

	 * can and should check what it introduces.
			pe = diff_funcname_pattern(o, two);

			}
	 * abbreviation (hence the whole logic is limited to the case
 * printed.
	emit_diff_symbol(o, DIFF_SYMBOL_SUBMODULE_MODIFIED,
static int diff_opt_relative(const struct option *opt,
	BUG_ON_OPT_NEG(unset);

				flush_one_pair(p, options);
	return 2;
			error("feeding unmodified %s to diffcore",
	for (i = 0; (optch = optarg[i]) != '\0'; i++) {
		context = diff_get_color_opt(o, DIFF_CONTEXT);
	memcpy(f, e, sizeof(struct emitted_diff_symbol));
		 * Original minus copied is the removed material,

		if (*end)
		return 0; /* unmerged is interesting */
	if (!changed)
#include "config.h"
		if (diff_header_only)
		return 0;
	 * for " | NNNN " and one the empty column at the end, altogether

			init_diff_words_data(&ecbdata, o, one, two);
	return !(delta == pmb->wsd && al - a_off == cl - c_off &&

		strbuf_addch(&res, '"');
					return 0;
	case DIFF_SYMBOL_WORD_DIFF:

			temp->name = name;
	}
#include "diff.h"

	BUG_ON_OPT_NEG(unset);
			}
		for (i = 0; i < pmb_nr; i++) {
			      N_("hide 'git add -N' entries from the index"),
static int parse_dirstat_params(struct diff_options *options, const char *params_string,
		}
			/*
	 * "scaled". If total width is too small to accommodate the
		 * conversion.
			    p->one->mode != p->two->mode)

	for (i = 0; i < q->nr; i++)
		case DIFF_SYMBOL_MINUS:
}
	x = xcalloc(1, sizeof(*x));
			dels += deleted;
		if (parse_dirstat_params(&default_diff_options, value, &errmsg))
	int abblen;
{
 */
	for (i = 1; i < block_length + 1; i++) {
			line++;
		return temp;
		else if (skip_prefix(diffopts, "--unified=", &v))
}
	DIFF_XDL_CLR(options, NEED_MINIMAL);
				       struct index_state *istate)

		return 0;
		unsigned long changed, const char *base, int baselen)
		xpparam_t xpp;
static void diffcore_skip_stat_unmatch(struct diff_options *diffopt)
	if (options->flags.quick && options->skip_stat_unmatch &&
			    insertions);
		return; /* no useful stat for tree diffs */
		diff_dirstat_permille_default = default_diff_options.dirstat_permille;
		if (xfrm_msg)

	    check_pager_config("diff") != 0)
	int i;
	if (options->output_format & DIFF_FORMAT_PATCH)
				set = diff_get_color_opt(o, DIFF_CONTEXT_DIM);
	}
		case DIFF_STATUS_DELETED:
	}
		    const struct object_id *oid,
}
	return 0;
		return;
	else
	if (S_ISGITLINK(old_mode) && S_ISGITLINK(new_mode) &&
		if (options->line_termination) {
			break;
		options->flags.follow_renames = 1;
		/* incomplete line at the end */
		OPT_SET_INT('z', NULL, &options->line_termination,

	const char *frag = diff_get_color(ecbdata->color_diff, DIFF_FRAGINFO);

			struct emit_callback ecbdata;
	GIT_COLOR_BOLD_GREEN,	/* NEW_BOLD */
}
	if (!options->flags.override_submodule_config)
 * 0..12 are whitespace rules

			ws = NULL;
	 *  - the top level
		show_file_mode_name(opt, "create", p->two);

	hashmap_entry_init(&ret->ent, hash);
		meta = diff_get_color_opt(o, DIFF_METAINFO);
	 * In other words: stat_width limits the maximum width, and
		} else if ( ch == '%' ) {
{

			return error(_("bad --color-moved argument: %s"), arg);
	if (options->orderfile)
			return error(_("%s expects a numerical value"),
	for (i = 0; i < options->anchors_nr; i++)
#include "utf8.h"
	void *data;
				    b->es->line, b->es->len,
		; /* nothing */
 * in buffer->orig.
	if (o->prefix_length)
	if (data->nr == 0)

		return 0;
	[DIFF_FILE_OLD_MOVED_ALT_DIM] = "oldMovedAlternativeDimmed",
		} else if (s[off] == '\t') {
	[DIFF_FILE_NEW_MOVED_ALT]     = "newMovedAlternative",
	strbuf_release(&sb);
}
			return;

		} else {
			 */
	DIFF_STATUS_UNKNOWN,
		if (parse_submodule_params(&default_diff_options, value))
		else {
	if (o->ws_error_highlight & ws_rule) {

			int blank_at_eof;
		return; /* no tree diffs in patch format */
{
	if (!strcmp(var, "diff.external"))
					  const char *name_a,
{
	if (*arg != 0)
			 * !(one->oid_valid), as long as
		}
			the_hash_algo->update_fn(&ctx, p->one->path, len1);
	      ecbdata->blank_at_eof_in_postimage &&
static void show_shortstats(struct diffstat_t *data, struct diff_options *options)
}
		switch (l->s) {
static int diff_opt_break_rewrites(const struct option *opt,
	DIFF_SYMBOL_CONTEXT_INCOMPLETE,
		    const char *concatpath, unsigned dirty_submodule)
}
	return 0;
		int *begin, int *end)
	}
	}

				errmsg.buf);
			&style->ctx, style->newline,
			l->flags |= DIFF_SYMBOL_MOVED_LINE_UNINTERESTING;
		} else if ( ch >= '0' && ch <= '9' ) {
	    options->flags.exit_with_status &&
	*arg++ = temp->name;
		unsigned long copied, added, damage;
		diff_suppress_blank_empty = git_config_bool(var, value);

			    N_("prevent rename/copy detection if the number of rename/copy targets exceeds given limit")),

			xcalloc(1, sizeof(struct emitted_diff_symbols));
	struct diff_filepair *p;
	if (!files) {

				"%s%s:%d: leftover conflict marker\n",
}
			data->added = diff_filespec_size(o->repo, two);
	if (!strcmp(var, "diff.orderfile"))
		xfrm_msg = msg->len ? msg->buf : NULL;
}
	 * Also pickaxe would not work very well if you do not say recursive
		strbuf_addstr(&msgbuf, context);
static void fill_es_indent_data(struct emitted_diff_symbol *es)
			    reset,  line_prefix, set);
	temp = prepare_temp_file(r, spec->path, spec);
{
		if (*outbuf)
	diff_filespec_load_driver(one, r->index);


{
				   two->ptr, two->size,
			       diff_opt_find_renames),
		meta = diff_get_color_opt(o, DIFF_METAINFO);

		if (*ep != ' ' && *ep != '\t')
int diff_filespec_is_binary(struct repository *r,

	 * max_change is used to scale graph properly.
	fprintf(stderr, "queue[%d] %s (%s) %s %06o %s\n",
			goto free_ab_and_return;
			diff_populate_filespec(options->repo, p->two, 0);
			orig_size = delta_size;


	GIT_COLOR_BOLD_YELLOW,	/* NEW_MOVED ALTERNATIVE */
			pgm = drv->external;
		if (output_format & DIFF_FORMAT_DIRSTAT && dirstat_by_line)
		fprintf(opt->file, ":%06o %06o %s ", p->one->mode, p->two->mode,
		s->data = NULL;
#define INDENT_BLANKLINE INT_MIN
static int fn_out_diff_words_write_helper(struct diff_options *o,
		memset(&xecfg, 0, sizeof(xecfg));
		if (line[0] == '-') {
			free(key);
	 * making the line longer than the maximum width.
		reset = diff_get_color_opt(o, DIFF_RESET);
	struct emitted_diff_symbol *buf;
		return 0;
	else if (!strcmp(value, "short"))
		fclose(options->file);
		if (*end)
				set = diff_get_color_opt(o, DIFF_FRAGINFO);
		(*begin)++;
	/* special case: only removal */
	} else if (!diff_mnemonic_prefix) {
		if (fill_mmfile(o->repo, &mf1, one) < 0 ||
static void emit_binary_diff(struct diff_options *o,
			break;
static void patch_id_add_mode(git_hash_ctx *ctx, unsigned mode)
		data->deleted = count_lines(one->data, one->size);
	uintmax_t max_change = 0, max_len = 0;
	    !(ep = memmem(line + 2, len - 2, atat, 2))) {
{
		break;
				goto not_a_valid_file;
		/*
		return 0;
	else

	if (diff_filespec_is_binary(o->repo, two))
				if (must_show_header)
		}
		 */

		int bytes = (52 < data_size) ? 52 : data_size;
	if (!strcmp(var, "diff.noprefix")) {
		data->added = count_lines(two->data, two->size);
		free(delta);
		strbuf_addstr(&res, two);
		return 0;
	strbuf_release(&sb);
	QSORT(q->queue, q->nr, diffnamecmp);
/*
		    const struct object_id *oid,
	opt->flags.recursive = 1;
					    GIT_COLOR_RESET : NULL;
{
	case DIFF_SYMBOL_STATS_SUMMARY_ABBREV:
	struct diff_options *options = opt->value;
				scale *= 10;
	if (S_ISGITLINK(one->mode))
	/* We could do deflated delta, or we could do just deflated two,
		const char *name;
			the_hash_algo->update_fn(&ctx, p->one->path, len1);
			xsnprintf(hex, sizeof(hex), "%s%.*s", abbrev, len+3-abblen, "..");
{
	}
	if (one && two)
}
		struct diff_options *o = ecbdata->opt;
	}
	*cp_p = cp;
		quote_c_style(b, name, NULL, 0);
}
			emit_diff_symbol(options, DIFF_SYMBOL_STATS_LINE,
	if (ecbdata->diff_words) {
		needs_reset = 1;
	struct diff_words_style *style = diff_words->style;
		munmap(s->data, s->size);

	}
	 * than it is, and then add 1 to the result.

int parse_long_opt(const char *opt, const char **argv,
	struct diff_words_data *diff_words;
			     one, null, &msg,
		*out = INDENT_BLANKLINE;
		if (!o->flags.dual_color_diffed_diffs)
		    (!file->is_interesting && (added + deleted == 0))) {
		}
		strbuf_reset(ecbdata->header);
	struct diff_options o;
				oid_to_hex_r(temp->hex, &one->oid);
			xsnprintf(hex, sizeof(hex), "%s...", abbrev);
		if (to_fetch.nr)
{
 * Keep track of files used for diffing. Sometimes such an entry
		free(options->anchors[i]);
	if (options->prefix)
			     null, two, &msg, o, p);
{
}
		return p->skip_stat_unmatch_result;
			       N_("look for differences that change the number of occurrences of the specified regex"),
	if (!DIFF_FILE_VALID(s))
	data.lineno = 0;
			BUG("oid abbreviation out of range: %d", abbrev);
		while (lp < pmb_nr && pmb[lp].match)

		options->output_format = DIFF_FORMAT_NO_OUTPUT;
	struct strbuf pname = STRBUF_INIT;
	DIFF_SYMBOL_MINUS,
			  N_("generate patch"),
		/* Crazy xdl interfaces.. */
			emit_diff_symbol_from_struct(o, &esm.buf[i]);

		options->prefix_length = 0;
{
	if (diff_indent_heuristic)

	BUG_ON_OPT_NEG(unset);
	if (has_trailing_carriage_return)
void free_filespec(struct diff_filespec *spec)



		     DIFF_SYMBOL_MOVED_LINE_UNINTERESTING:
		else {
	}
			       N_("generate diffstat with a given name width"),
	[DIFF_COMMIT]		      = "commit",
	}
		if (*end)
	const char *newline;
}
	const char *name;
		xpparam_t xpp;
	buffer->text.size += len;
 */
		emit_line(o, context, reset, line, len);
{
		else {
static unsigned ws_error_highlight_default = WSEH_NEW;
		options->flags.recursive = 1;
		show_mode_change(opt, p, !p->score);
/*

		diff_indent_heuristic = git_config_bool(var, value);
		}
{
		}
				count = strtoul(end+1, &end, 10);
		OPT_CALLBACK_F('G', NULL, options, N_("<regex>"),
		}
		 * either in-place edit or rename/copy edit.
		     DIFF_SYMBOL_MOVED_LINE_ALT |
				moved_block_clear(&pmb[i]);
	DIFF_SYMBOL_WORDS,
}
}
{
		reset = diff_get_color_opt(o, DIFF_RESET);
				 DIFF_SYMBOL_CONTEXT_MARKER, line, len, 0);
 * Flags for content lines:
				two->dirty_submodule);
			   PARSE_OPT_KEEP_DASHDASH |
		diff_fill_oid_info(p->one, options->repo->index);
	if (diff_filespec_is_binary(o->repo, one) ||
				const char *arg, int unset)
		options->flags.stat_with_summary = 0;
		strbuf_release(&buf);
	options->pickaxe_opts |= DIFF_PICKAXE_KIND_S;
	}
	else if (line[0] == '-')
		xcalloc(1, sizeof(struct diff_words_data));

	struct diff_queue_struct *q = &diff_queued_diff;
				 sb.buf, sb.len, 0);
			goto found_damage;
			number_width, added + deleted,
				return 0;
};
			      &must_show_header,
			die("unable to generate diff for %s", one->path);
			data->deleted = 0;
		ecbdata.opt = o;
	emit_diff_symbol(o, DIFF_SYMBOL_FILEPAIR_MINUS,
		break;
	if (plus_begin != plus_end) {
}
	case '+':
			       N_("specify how differences in submodules are shown"),
			quote_c_style(p->two->path, &sb, NULL, 0);
	/*
}
	int graph_width = options->stat_graph_width;

	ecbdata.ws_rule = whitespace_rule(o->repo->index, name_b);
	int a_len = a->len,
	struct diff_options *options = opt->value;

			return;
}



	strbuf_addf(&sb,
{

	if (S_ISDIR(s->mode))
	unsigned char c;
	unsigned flags = eds->flags;
N_("you may want to set your %s variable to at least "
	old_name = a + len_a;


#include "quote.h"
			       PARSE_OPT_NONEG | PARSE_OPT_NOARG,
 * that block.
struct moved_entry {
			warning(_("Unknown value for 'diff.submodule' config variable: '%s'"),
			o->line_termination);

	const char *new_name = b;
static int diff_color_moved_default;
		strip_prefix(opt->prefix_length, &name_a, &name_b);
 * diff_filespec has data and size fields for this purpose.
		} else if (isdigit(*p)) {
		if (!strcmp(arg, "plain"))
	if (options->prefix &&


		off++;
/* returns 0 upon success, and writes result into oid */
		   filter_bit_tst(DIFF_STATUS_MODIFIED, options)))) ||
	at = count_lines(mf1->ptr, mf1->size);
	BUG_ON_OPT_ARG(arg);
			else
				   const char *arg, int unset)

		x, one ? one : "",
		options->file = xfopen("/dev/null", "w");
		count++; /* no trailing newline */
 *
			if (!diffopt->flags.no_index)
	{ DIFF_WORDS_PLAIN, {"{+", "+}"}, {"[-", "-]"}, {"", ""}, "\n" },
	two = alloc_filespec(path);
static void show_numstat(struct diffstat_t *data, struct diff_options *options)
		ws_error_highlight_default = val;
static int remove_space(char *line, int len)
	unsigned status;

			       PARSE_OPT_NONEG | PARSE_OPT_OPTARG,
	char *data_one, *data_two;
	 * let transformers to produce diff_filepairs any way they want,
	if (options->flags.reverse_diff) {
			last_symbol = l->s;
		uintmax_t added = file->added;
	 * When patches are generated, submodules diffed against the work tree
				   struct argv_array *argv,
		ecbdata->lno_in_preimage++;
				ALLOC_GROW(pmb, pmb_nr + 1, pmb_alloc);
		/* unmerged */
	if (options->flags.diff_from_contents) {
	struct strbuf errmsg = STRBUF_INIT;
		return -1;
	if (al != bl)

		break;
	struct diff_filespec *one, *two;
	[DIFF_WHITESPACE]	      = "whitespace",

	int pmb_nr = 0, pmb_alloc = 0;
		a_midlen = 0;

static char *run_textconv(struct repository *r,
			     PARSE_OPT_NONEG),

}
		struct diffstat_t diffstat;
		/* fallthru */
			else if (c == '-')
			       N_("do not show any source or destination prefix"),
	data.conflict_marker_size = ll_merge_marker_size(o->repo->index, attr_path);
{
		OPT_CALLBACK_F(0, "patience", options, NULL,
	 * We want a maximum of min(max_change, stat_graph_width) for the +- part.
		fputs(GIT_COLOR_REVERSE, file);
	    !diff_filespec_check_stat_unmatch(options->repo, p))
	if (len == the_hash_algo->hexsz)
		   *c = l->line;
static int diff_opt_pickaxe_regex(const struct option *opt,
	return 0;
#include "xdiff-interface.h"
	}
	name_a += (*name_a == '/');
	while (0 < l) {
	int delta;
		 int old_oid_valid, int new_oid_valid,
	 */
	BUG_ON_OPT_NEG(unset);

		!opt->filter &&

 * enhance the state for emitting prefabricated lines, e.g. the similarity
	diff_fill_oid_info(p->one, o->repo->index);
	}
			filter_bit[(int) diff_status_letters[i]] = (1 << i);
			     struct diffstat_t *diffstat,
static void add_external_diff_name(struct repository *r,


static void diff_fill_oid_info(struct diff_filespec *one, struct index_state *istate)
				    flags & DIFF_SYMBOL_CONTENT_BLANK_LINE_EOF);
static void prep_temp_blob(struct index_state *istate,
	if (xdi_diff_outf(&minus, &plus, fn_out_diff_words_aux, NULL,
		uintmax_t deleted = file->deleted;


		if (file->is_binary) {
		dir.files[dir.nr].changed = damage;
	/*
	case DIFF_SYMBOL_STATS_SUMMARY_INSERTS_DELETES:
	/* as only the hunk header will be parsed, we need a 0-context */
		 */
			      DIFF_FORMAT_NAME_STATUS |
			flush_one_hunk(oid, &ctx);
		err_empty:
			       PARSE_OPT_NONEG, diff_opt_stat),
		pe = diff_funcname_pattern(o, one);
		/* Crazy xdl interfaces.. */
		fprintf(stderr, "%s\n", msg);
			if (!file->is_renamed)
		return COLOR_MOVED_PLAIN;
			diff_flush_patch(p, o);
	} else {
		builtin_diffstat(p->one->path, NULL, NULL, NULL,
			diff_free_filespec_data(p->one);
	 * separators and this message, this message will "overflow"
					    p);
			cp++;	/* % is always at the end */
		strbuf_addf(msg, "%s%sindex %s..%s", line_prefix, set,
		case DIFF_SYMBOL_MOVED_LINE |
	return 1 + (it * (width - 1) / max_change);
	else
		die("Option '--%s' requires a value", opt);
	} else {
	 */
			break;
		add_external_diff_name(o->repo, &argv, name, one);

			   const char *arg, int unset)
			return size;
	 */
		buffer->orig_nr++;
	int i;
	       b + pfx_length - pfx_adjust_for_slash <= new_name &&
 * otherwise.
		the_hash_algo->update_fn(&ctx, p->two->path, len2);
	struct checkout_metadata meta;
	ecbdata->lno_in_postimage = 0;
			  XDF_IGNORE_BLANK_LINES, PARSE_OPT_NONEG),
	return result;
	switch(p->status) {
	DIFF_STATUS_FILTER_BROKEN,
		fputs(reset, file);

	if (options->repo == the_repository && has_promisor_remote()) {
		options->flags.has_changes = 1;
		struct emitted_diff_symbols *wol = wo->emitted_symbols;
	if (pfx_length + sfx_length) {
		if ('a' <= optch && optch <= 'z') {
	void *delta;
			strbuf_reset(&header);
		if (color_words_output_graph_prefix(diff_words))
		}
	 * to be individually opened and inflated.

		if (show_name) {
		 const char *concatpath,
			prev_line = NULL;
{
		 * diffcore_count_changes() considers the two entries to
		return git_config_pathname(&diff_order_file_cfg, var, value);
{
	}
	else if (*arg != '/')
	}
		}
	const char *line_prefix;

	unsigned cm;
			 * due to stat info mismatch.
		diffcore_order(options->orderfile);
{
	/*
				ret++;
	if (size_only && 0 < s->size)
		emit_line_ws_markup(o, set_sign, set, reset,
	 * Binary files are displayed with "Bin XXX -> YYY bytes"


	int len_b = strlen(b);
		strbuf_addf(&pname, " (%s)", file->comments);
		opt2 = 0;
	the_hash_algo->update_fn(data->ctx, line, new_len);
void flush_one_hunk(struct object_id *result, git_hash_ctx *ctx)
	BUG_ON_OPT_NEG(unset);
			  struct diff_filespec *two,
	xsnprintf(temp->mode, sizeof(temp->mode), "%06o", mode);
static int diff_opt_ws_error_highlight(const struct option *option,
	}
			total_files--;
				return 0;
			return -1;
			 * NEEDSWORK: Consider deduplicating the OIDs sent.

			       N_("select files by diff type"),
{
{
