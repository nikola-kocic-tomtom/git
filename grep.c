		 * either end of the line, or at word boundary
	case GREP_SOURCE_BUF:
	if (opt->null_following_name)
		      !word_char(bol[pmatch[0].rm_eo])) )
		die("%s", error);
	while (bol > gs->buf && cur > from) {
static void pcre2_free(void *pointer, MAYBE_UNUSED void *memory_data)

	switch (x->node) {


	*tail = &p->next;
static char *end_of_line(char *cp, unsigned long *left)
			die("--and not followed by pattern expression");
static NORETURN void compile_regexp_failed(const struct grep_pat *p,
		h = compile_pattern_atom(&pp);
			die("--not followed by non pattern expression");
	free(x);


	    opt->funcbody) {
	opt->color = -1;
			 * line, and the first match might not be
#ifdef USE_LIBPCRE2
							 opt->pattern_expression);
		return z;
		ovector = pcre2_get_ovector_pointer(p->pcre2_match_data);
	switch (x->node) {
		indent(in);

#include "diff.h"
	else if (!strcmp(arg, "basic"))
	gs->buf = read_object_file(gs->identifier, &type, &gs->size);
				cur++;
	obj_read_unlock();
			p->pcre2_jit_on = 0;

static struct grep_expr *compile_pattern_atom(struct grep_pat **list)
	case GREP_PATTERN_TYPE_UNSPECIFIED:
			 */
	PCRE2_SIZE erroffset;
			 * Trailing empty lines are not interesting.
				opt->output(opt, " matches\n", 9);
		if (!header_group[fld])
		return x;

			BUG("unknown header field %d", p->field);
				}
static pcre2_general_context *pcre2_global_context;
		FREE_AND_NULL(gs->buf);
static int is_empty_line(const char *bol, const char *eol);
				show_function = 1;
}
	opt->relative = def->relative;
			strbuf_release(&sb);

	if (eflags & REG_NOTBOL)
	if (!opt->status_only && gs->name == NULL)
{
{
#endif
		if (!opt->ignore_locale && has_non_ascii(p->pattern))
			if (opt->pre_context || opt->funcbody)
	for (sp = bol + earliest; bol < sp && sp[-1] != '\n'; sp--)

			return -1;
		 * (post PCRE2 10.31)

		}
void compile_grep_patterns(struct grep_opt *opt)
	}

}

}
{
		    GREP_HEADER_FIELD_MAX <= p->field)
	}
#ifdef PCRE_CONFIG_JIT
			die("Couldn't allocate PCRE2 match data");
		opt->extended = 1;
				  collect_hits);
{


		options |= PCRE2_CASELESS;

	opt->pattern_type_option = def->pattern_type_option;
	 * make it another option?  For now suppress them.
				break;
		return;
		fprintf(stderr, "true\n");
}
		char *next_bol = bol;
	}
		}
	return ret;
		size_t len;
		if (lno <= opt->last_shown)
static int chk_hit_marker(struct grep_expr *x)
	enum object_type type;
				free_pcre2_pattern(p);
		}
		if (match_funcname(opt, gs, bol, eol)) {
		dump_grep_expression_1(x->u.binary.left, in+1);
	char *eol = *eol_p;
	}
		default:
	/*
} header_field[] = {
	struct grep_pat *p;
#ifdef USE_LIBPCRE2
				 * to 0 to suggest the whole line matches.
		regflags |= REG_EXTENDED;
	p = *list;
		return 0;
			continue;
static struct grep_expr *compile_pattern_expr(struct grep_pat **list)
		*left_p = 0;
		case GREP_BINARY_NOMATCH:

void init_grep_defaults(struct repository *repo)
	[GREP_COLOR_FILENAME]	    = "filename",
	enum grep_header_field fld;
	xdiff_clear_find_func(&xecfg);
 * Initialize one instance of grep_opt and copy the
static void compile_regexp(struct grep_pat *p, struct grep_opt *opt)
	/*
		return 0;
		h |= match_expr_eval(opt, x->u.binary.right, bol, eol, ctx, col,
	switch (x->node) {
			earliest = m.rm_so;
	grep_source_1(opt, gs, 1);
static void *pcre2_malloc(PCRE2_SIZE size, MAYBE_UNUSED void *memory_data)
{
			show_line(opt, bol, eol, gs->name, lno, 0, '=');
		*bol_p = bol + *left_p;
static void show_name(struct grep_opt *opt, const char *name)
		options |= PCRE_CASELESS;
				match_color = opt->colors[GREP_COLOR_MATCH_CONTEXT];
	else if (!opt->extended && !opt->debug)

static void compile_pcre2_pattern(struct grep_pat *p, const struct grep_opt *opt)
	return 1;
	 * When committing to the pattern type by setting the relevant
				output_color(opt, bol, match.rm_so, line_color);
 * Initialize the grep_defaults template with hardcoded defaults.
		show_name(opt, gs->name);
		output_color(opt, &sign, 1, opt->colors[GREP_COLOR_SEP]);
	if (grep_use_locks)
	ret->pattern_tail = &ret->pattern_list;
}
	if (opt->unmatch_name_only) {

		grep_source_load_driver(gs, opt->repo->index);
		opt->output = std_output;
		}
	if (hit) {
	 */
	}
 * not thread-safe.
			 * pattern being restored.
{
		opt->output(opt, color, strlen(color));
			 * body of the current function.
			else
		output_color(opt, name, strlen(name), opt->colors[GREP_COLOR_FILENAME]);
}

#include "xdiff-interface.h"
void free_grep_patterns(struct grep_opt *opt)
		die(_("given pattern contains NULL byte (via -f <file>). This is only supported with -P under PCRE v2"));
	next_line:
	free((void *)p->pcre2_tables);
	pmatch->rm_so = pmatch->rm_eo = -1;
	if (gs->path)
							  pmatch, eflags);
	return !!last_hit;

		      const void *identifier)
	}
				/*
static void show_line_header(struct grep_opt *opt, const char *name,
			break;
			funcname_lno = cur;
			 */
	if (grep_use_locks)
	 */
}
}
		regflags |= REG_ICASE;
			      struct grep_source *gs)
	}

	if (ret < 0 && ret != PCRE2_ERROR_NOMATCH) {
		show_line_header(opt, name, lno, cno, sign);
			p->pattern = sb.buf;
{
{

 *
	int ch;
	for (p = opt->pattern_list; p; p = n) {
	if (want_color(opt->color) && color && color[0]) {
		return GREP_PATTERN_TYPE_UNSPECIFIED;
	case GREP_PATTERN_HEAD: fprintf(stderr, "pattern_head"); break;
	char *bol;
		return grep_source_load_oid(gs);
	else
static struct grep_opt grep_defaults;
{
}
		      enum grep_context ctx, regmatch_t *pmatch, int eflags)
		return x;

			/*
		regerror(err, &p->regexp, errbuf, sizeof(errbuf));
		case GREP_HEADER_AUTHOR:
	opt->repo = repo;
		break;
		break;
	*lno_p = lno;
		output_color(opt, buf, strlen(buf), opt->colors[GREP_COLOR_COLUMNNO]);
				match_color = opt->colors[GREP_COLOR_MATCH_SELECTED];
	struct grep_pat *p;
	gs->buf = NULL;

			from = orig_from;
	}
		case GREP_BINARY_TEXT:

			     lno <= last_hit + opt->post_context))
			break;
		goto err_ret;


		regmatch_t *match, int eflags)
	opt->priv = &xecfg;

{
				break;
		patinforet = pcre2_pattern_info(p->pcre2_pattern, PCRE2_INFO_JITSIZE, &jitsizearg);
	pmatch->rm_so = match.rm_so;
	int err;
		die("Not a valid grep expression");
	if (!gs->buf)
	 * grep code passes around a grep_source and assumes that its "buf"

	}
		pmatch[0].rm_so += bol - start;
		return grep_source_load(gs);
					nl = cp;
		 * Upon visiting a GREP_NODE_NOT, col and icol become swapped.
		opt->output(opt, data, size);
		    x->u.binary.right->node == GREP_NODE_TRUE) {
		break;
		opt->fixed = 1;
			return;
		if (jitsizearg == 0) {
	case GREP_PATTERN:
	while (bol < eol && isspace(*bol))
	 */
			continue;
				      p->pcre1_tables);

	PCRE2_UCHAR errbuf[256];
		hit = patmatch(p, bol, bol + *left_p, &m, 0);
}
void grep_commit_pattern_type(enum grep_pattern_type pattern_type, struct grep_opt *opt)
			if (opt->count)
	else
		*list = (*list)->next;
	struct grep_opt *opt = &grep_defaults;
			     struct index_state *istate)
	z->u.binary.right = right;
	unsigned lno = *lno_p;
	const char *filename = gs->identifier;
	if (!textconv) {
						ctx, col, icol, 0) ||
		break;
			return 0;
{
		z->u.binary.left = x;
		char buf[32];
		opt->output(opt, GIT_COLOR_RESET, strlen(GIT_COLOR_RESET));

		fprintf(stderr, ")\n");
	struct grep_pat *p;
		if (!x->u.unary)

		 */
					pat->origin, pat->no, pat->token);
		if (match.rm_so == pmatch->rm_so && match.rm_eo < pmatch->rm_eo)
		 * has the next hit; don't call it if we need to do
				   eflags);
			default:
{
 */
	}
		fprintf(stderr, "<head %d>", p->field); break;

		x->u.unary = compile_pattern_not(list);
	if (opt->columnnum && cno) {
	}
{
 *
				 * to find the earliest.
	opt->color = def->color;
}
	df = alloc_filespec(gs->path);
				line_color = opt->colors[GREP_COLOR_FUNCTION];
		field = header_field[p->field].field;
#include "grep.h"
		}
		return;
}
	if (!opt->output)
	int hit;

		char *eol = bol, sign = (cur == funcname_lno) ? '=' : '-';
	}
{
	    !(!opt->ignore_case && (p->fixed || p->is_fixed)))

		 */
static void clr_hit_marker(struct grep_expr *x)
	if (ret > 0) {
	}
			cno = opt->invert ? icol : col;
		x->u.atom = p;
}
		return buffer_is_binary(gs->buf, gs->size);
}
		/* fall through */
			if (!p->next)
	struct grep_pat *pat;
	if (opt->pcre1) {
		show_line(opt, bol, eol, gs->name, cur, 0, sign);
		return 0;

		if (!left)
		return 0;
				     opt->colors[GREP_COLOR_FILENAME]);
}
	}
		break;
		if (collect_hits)
		if (!header_group[p->field]) {
		fill_filespec(df, &null_oid, 0, 0100644);
			continue;
	}

	gs->path = xstrdup_or_null(path);
	}
	/*
		      enum grep_context ctx, int collect_hits)
		}

static int next_match(struct grep_opt *opt, char *bol, char *eol,
		fill_filespec(df, gs->identifier, 1, 0100644);
			append_header_grep_pattern(ret, pat->field,
		 * (*NO_JIT) verb (see pcre2syntax(3))

			 * E.g. t7811-grep-open.sh relies on the
		if (x->node != GREP_NODE_OR)
		ret = 0;
				 * Without --column, any single match on a line
			BUG("pcre2_pattern_info() failed: %d", patinforet);

		case GREP_PATTERN_BODY:
	p->origin = origin;
	}
		regmatch_t *match, int eflags)
	return 0;
			break;
		die("incomplete pattern expression: %s", p->pattern);
			/* If the last hit is within the post context,
	/*
		bol = eol + 1;
				output_color(opt, gs->name, strlen(gs->name),
static int grep_source_load_oid(struct grep_source *gs)
		case GREP_HEADER_COMMITTER:
			      enum grep_context ctx,

		header_group[p->field] = grep_or_expr(h, header_group[p->field]);
		 * We might set up the shared textconv cache data here, which
		return color_parse(value, color);
		if (try_lookahead
			if (sign == ':')
	return 0;
	int regflags = REG_NEWLINE;
		if (!h || pp != p->next)
		obj_read_unlock();
			p->patternlen = sb.len;
}
		x = x->u.binary.right;
	run_once++;
		options |= PCRE_UTF8;
		break;
		ret = 0;
		close(i);
	/* Rewind. */

	    opt->extended_regexp_option)
static void output_color(struct grep_opt *opt, const void *data, size_t size,
		pmatch[0].rm_eo += bol - start;
		int ch = *eol;
}
		gs->driver = userdiff_find_by_path(istate, gs->path);

}
			return 0; /* punt for "header only" and stuff */
	gs.buf = buf;
}


		h = !match_expr_eval(opt, x->u.unary, bol, eol, ctx, icol, col,
	opt->pattern_tail = &opt->pattern_list;
		*eol_p = ++eol;
	pcre_config(PCRE_CONFIG_JIT, &p->pcre1_jit_on);
	struct grep_pat *p = create_grep_pat(pat, strlen(pat), "header", 0,
		fprintf(stderr, "fixed %s\n", sb.buf);
	return hit;
			return config_error_nonbool(var);
/*
		}
	 * have to pretend to be one. If we could unify the grep_source
}
	if (!driver || !driver->textconv)
	 * must ensure mutual exclusion between this call and the object reading
			new_pat->next = p->next;

		      ssize_t *icol, int collect_hits)


		lno++;
	if (field == GREP_HEADER_REFLOG)

			return 0;
	opt->all_match = 1;

		if (errno != ENOENT)
	 * diff tempfile structure, writes to the_repo's odb and might
#include "cache.h"
				opt->output(opt, "Binary file ", 12);
	int saved_ch = 0;
{
	else if (p->origin)
		      unsigned long *left_p,
static void indent(int in)
	memset(opt, 0, sizeof(*opt));
	default: break;
 * This lock protects access to the gitattributes machinery, which is
	case GREP_NODE_NOT:
{

			BUG("a non-header pattern in grep header list.");
static void grep_set_pattern_type_option(enum grep_pattern_type pattern_type, struct grep_opt *opt)
}

		 * even when there's no USE_LIBPCRE* defined. We still

	char *peek_bol = NULL;
		    "grep_source.name be non-NULL");
	case GREP_NODE_TRUE:
			}
			output_color(opt, bol + match.rm_so,

			bol--;
	}
			opt->extended = 1;
#ifdef USE_LIBPCRE2
		cur--;
 * the grep_defaults template.
		}

static int pcre2match(struct grep_pat *p, const char *line, const char *eol,
	z->node = GREP_NODE_TRUE;
	append_grep_pat(opt, pat, strlen(pat), origin, no, t);

		if (p->token != GREP_PATTERN_HEAD)
	 * compiling an ERE. It must be unset if that's not actually
		z = xcalloc(1, sizeof (struct grep_expr));
			die("regexp returned nonsense");
{
	struct grep_opt *ret = xmalloc(sizeof(struct grep_opt));
{
			   ssize_t *icol, int collect_hits)
}
			}
		x->hit |= h;
	while (bol > gs->buf) {
				return 0; /* Assume unmatch */
			 */
	color_set(opt->colors[GREP_COLOR_MATCH_SELECTED], GIT_COLOR_BOLD_RED);


	fputc('\n', stderr);
	}
	 * about binary handling if we are not using it.
static void free_pcre2_pattern(struct grep_pat *p)

	}
		else

		dump_grep_expression_1(x->u.binary.left, in+1);
		indent(in);
	int hit = 0;
		return 0;
		return 0;
			break;
		/*
	opt->priv = NULL;
	p->field = field;
	}
			*nl = '\0';

		free(data);
{
		y = compile_pattern_and(list);
			 */
	default: break;
		pcre_free(p->pcre1_extra_info);
	if (p->fixed || p->is_fixed) {
		if (is_regex_special(s[i]))
	{

	if (!strcmp(var, "grep.patterntype")) {
	}
			x->u.binary.right = y;
	else if (!strcmp(arg, "perl"))
{
		compile_pcre1_regexp(p, opt);
			 * next position following a non-word char.
					break;
	if (ret > 0) {
		if (opt->unmatch_name_only) {
	p->ignore_case = opt->ignore_case;
	grep_source_clear(&gs);
		 * call the PCRE stub function, it just dies with
			*/
};
				binary_match_only = 1;

static void std_output(struct grep_opt *opt, const void *buf, size_t size)
		 * tells us whether the library itself supports JIT,
	}
static void compile_fixed_regexp(struct grep_pat *p, struct grep_opt *opt)
	const char *line_color = NULL;
			else if (sign == '=')

		ch = *eol;
	int h = 0;
}
				return 0;
static void compile_grep_patterns_real(struct grep_opt *opt)
			output_color(opt, "--", 2, opt->colors[GREP_COLOR_SEP]);
	assert(opt->pcre2);
		 * "cannot use Perl-compatible regexes[...]".
			break;
			compile_pcre2_pattern(p, opt);
	 * Treat 'cno' as the 1-indexed offset from the start of a non-context
	else if (opt->pattern_type_option != GREP_PATTERN_TYPE_UNSPECIFIED)
		else


	int i;
		fprintf(stderr, "(or\n");
		      const char *name, const char *path,
}
{
		grep_source_load_driver(gs, opt->repo->index);
		if (collect_hits)
	 * The real "grep -c foo *.c" gives many "bar.c:0" lines,
			while (++len <= p->patternlen) {
#ifdef USE_LIBPCRE1
#if defined(USE_LIBPCRE2)
		else
/*
		cp++;
		regmatch_t match;
	 */

		return 0;
{
	 * only exception to this.
		xsnprintf(buf, sizeof(buf), "%"PRIuMAX, (uintmax_t)cno);
	}

	if (i < 0)
		pthread_mutex_unlock(&grep_attr_mutex);
		if (opt->show_hunk_mark)
		if (earliest < 0 || m.rm_so < earliest)
		 * parse_object() might be internally called. As they are not

	       const char *no_jit = "(*NO_JIT)";
		 * opt->pattern_type_option above, we don't want
#include "help.h"
	if (!opt->only_matching) {
		free_pattern_expr(x->u.unary);
	case GREP_NODE_AND:
		break;
	 */
		x = compile_pattern_or(list);
	p = *list;
#endif
		fprintf(stderr, "(and\n");
	switch (p->token) {
			;
	if (xecfg && !xecfg->find_func) {
	case GREP_NODE_OR:
			break;
	}
	return 1;
		 * line, or at word boundary (i.e. the last char must
				line_color = opt->colors[GREP_COLOR_SELECTED];
	if (p->pcre2_jit_on)
	switch (gs->type) {
			size_t old_patternlen = p->patternlen;
	return 1;
		if (*sp == '\n')
	const char *field;
		 * The pcre2_config(PCRE2_CONFIG_JIT, ...) call just
	case GREP_NODE_NOT:
		indent(in);
	case GREP_PATTERN: /* atom */
			     enum grep_context ctx,
	struct grep_expr *x;
{

#else /* !USE_LIBPCRE2 */
		header_expr = grep_or_expr(header_group[fld], header_expr);
	return cp;
		jitret = pcre2_jit_compile(p->pcre2_pattern, PCRE2_JIT_COMPLETE);
	if (fill_textconv_grep(opt->repo, textconv, gs) < 0)
			else

	unsigned cur = lno, from = 1, funcname_lno = 0, orig_from;
	if (err) {
			last_hit = lno;
	}
	return ret;
		match->rm_so = (int)ovector[0];
}


	if (lstat(filename, &st) < 0) {


	if (p->pcre2_pattern) {
{
	size_t i;
}
		options |= PCRE2_UTF;
					     ctx, col, icol, 0);
 * Read the configuration file once and store it in
			while (word_char(bol[-1]) && bol < eol)
			die("--not not followed by pattern expression");

	int patinforet;


}
	opt->extended_regexp_option = def->extended_regexp_option;
			comment_needed = 0;
		 * inside a post-context window, we will show the current
			strbuf_add(&sb, "\\Q", 2);
	color_set(opt->colors[GREP_COLOR_FILENAME], "");
	gs->type = type;
	 * set by anything. The extended_regexp_option field is the
		}
}
		/*
	if (opt->debug)
	case GREP_NODE_TRUE:
void append_grep_pat(struct grep_opt *opt, const char *pat, size_t patlen,
	 * install our textconv'd version into the grep_source, taking care not
	size_t size;
		if (match_one_pattern(p, bol, eol, ctx, &tmp, 0)) {
#else /* !USE_LIBPCRE2 */
		ssize_t cno;
		      ssize_t *col, ssize_t *icol,
		if (pmatch->rm_so == pmatch->rm_eo)
		eol = end_of_line(bol, &left);
static int match_line(struct grep_opt *opt, char *bol, char *eol,
	char *data;
	if (!p->pcre1_regexp)

			 const char *color)
	}
			if (opt->only_matching)
		if (*eol != '>')

	if (p->pcre1_regexp)
	char *bol = *bol_p;
	while (in-- > 0)
	} else
		flags |= PCRE2_NOTBOL;
	case GREP_NOT: fprintf(stderr, "*not*"); break;
	 *
	 * reading operations might increase performance in the multithreaded
			show_line(opt, bol, eol, gs->name, lno, cno + 1, ':');
	color_set(opt->colors[GREP_COLOR_COLUMNNO], "");
		if (!value)
	opt->only_matching = def->only_matching;
		obj_read_lock();
		 */
	for (p = opt->header_list; p; p = p->next) {
				show_name(opt, gs->name);
	fwrite(buf, size, 1, stdout);
		}
static int match_next_pattern(struct grep_pat *p, char *bol, char *eol,
}

		opt->columnnum = git_config_bool(var, value);

	opt->prefix_length = (prefix && *prefix) ? strlen(prefix) : 0;
	case GREP_NOT:
				     0);
static void dump_grep_expression_1(struct grep_expr *x, int in)
		len = header_field[p->field].len;
	if (opt->extended_regexp_option)

		hit = !regexec_buf(&p->regexp, line, eol - line, 1, match,
	opt->max_depth = def->max_depth;
		return NULL;
	return 0;
{
		grep_attr_lock();
	case GREP_NODE_AND:
		char errbuf[1024];
static struct {
	}
			goto next_line;
	int show_function = 0;
		gs->size = 0;
	struct strbuf sb = STRBUF_INIT;
}
		case GREP_PATTERN: /* atom */
}

	return isalnum(ch) || ch == '_';
	unsigned long l = *left;
			if (*col < 0 || tmp.rm_so < *col)
}
	/* pcre2_global_context is initialized in append_grep_pattern */
			die("Couldn't JIT the PCRE2 pattern '%s', got '%d'\n", p->pattern, jitret);
			rest -= match.rm_eo;
}
		*eol = '\0';

	[GREP_COLOR_MATCH_SELECTED] = "matchSelected",
	try_lookahead = should_lookahead(opt);
	if (err) {
static int look_ahead(struct grep_opt *opt,
	/*

	**tail = p;
			saved_ch = strip_timestamp(bol, &eol);
	case GREP_PATTERN_HEAD:
{

	return match_expr_eval(opt, x, bol, eol, ctx, col, icol, collect_hits);

			return -1;
{
			 */

static void output_sep(struct grep_opt *opt, char sign)
	for (p = opt->header_list; p; p = p->next) {
{
			else if (sign == '-')
}
	opt->columnnum = def->columnnum;
	regoff_t earliest = -1;

	default:
			p->next = new_pat;
}

		 */
}
		ret = pcre2_jit_match(p->pcre2_pattern, (unsigned char *)line,
					 p->pcre2_compile_context);
		default:
		 */
		opt->output(opt, "\n", 1);

						eol, ctx, col, icol, 0));
	case GREP_NODE_ATOM:
	return hit;
		opt->linenum = git_config_bool(var, value);
	if (opt->debug)
}
	 * The normal fill_textconv usage by the diff machinery would just keep
		if(pat->token == GREP_PATTERN_HEAD)
				enum grep_header_field field, const char *pat)
	if (p->ignore_case)
	int try_lookahead = 0;
		if (!hit && pmatch[0].rm_so + bol + 1 < eol) {
static void dump_grep_expression(struct grep_opt *opt)
		show_funcname_line(opt, gs, bol, cur);
}
		    errbuf);
	p->pcre2_pattern = pcre2_compile((PCRE2_SPTR)p->pattern,

			     char *bol, char *end, unsigned lno)
		return 0;
	color_set(opt->colors[GREP_COLOR_SELECTED], "");
				if (*(--cp) == '\n') {
	p->pcre1_regexp = pcre_compile(p->pattern, options, &error, &erroffset,
			if (sign == ':')
	[GREP_COLOR_FUNCTION]	    = "function",
		if (patinforet)
			header_expr = grep_true_expr();

		if (show_function ||
static inline void grep_attr_lock(void)
		opt->output(opt, "\n", 1);
/*
		regmatch_t *match, int eflags)
		opt->pattern_expression = compile_pattern_expr(&p);
	if (opt->all_match || header_expr)

			append_grep_pat(ret, pat->pattern, pat->patternlen,
			}
	size_t jitsizearg;
		n = p->next;

		case GREP_BINARY_DEFAULT:
}
		int eflags = 0;
	case GREP_NODE_NOT:
static struct grep_expr *prep_header_patterns(struct grep_opt *opt)

			regmatch_t tmp;
		output_sep(opt, sign);
static int parse_pattern_type_arg(const char *opt, const char *arg)
	[GREP_COLOR_SEP]	    = "separator",
	for (p = opt->pattern_list; p; p = p->next) {
		opt->output(opt, "\0", 1);
	switch (p->token) {
		opt->relative = !git_config_bool(var, value);
{
			opt->show_hunk_mark = 1;
	unsigned count = 0;
		return -1;
		const char *field;
		char errbuf[1024];
{
					     opt->colors[GREP_COLOR_FILENAME]);
	}
	opt->last_shown = lno;
	opt->output(opt, opt->null_following_name ? "\0" : "\n", 1);
	 */
static int patmatch(struct grep_pat *p, char *line, char *eol,
	if (pmatch->rm_so >= 0 && pmatch->rm_eo >= 0) {
	}
		return -1;

	color_set(opt->colors[GREP_COLOR_CONTEXT], "");

	while (1) {
		return 1;


	struct stat st;
		return gs->driver->binary;
	 * the fields we're not choosing, since they won't have been

{

 */
				goto again;
	 * being called with a context line.
	       const int no_jit_len = strlen(no_jit);
	if (!opt->heading && opt->pathname) {
				opt->output(opt, "\n", 1);
			if (h && (*col < 0 || tmp.rm_so < *col))
				 * printed. With --column, scan _all_ patterns
						  p->no, p->token, p->field);
	struct grep_pat *p;
	struct grep_pat *p;
		return 0;

			break;
{
	opt->output = std_output;
	       if (starts_with(p->pattern, no_jit) &&
 * the code gets unwieldy and unreadable, so...
		}
	if (opt->pre_context || opt->post_context || opt->file_break ||
		int hit;
};
	if (!S_ISREG(st.st_mode))
static int is_fixed(const char *s, size_t len)
	if (!x)
	return compile_pattern_or(list);
				from = orig_from;
	switch (p->token) {
		dump_grep_expression_1(x->u.binary.right, in+1);


	int study_options = 0;
{
			p->pcre2_tables = pcre2_maketables(pcre2_global_context);
	/*
	for (i = 0; i < len; i++) {
	if (!opt->header_list)
static void compile_pcre2_pattern(struct grep_pat *p, const struct grep_opt *opt)

		switch (p->field) {
}
static int is_empty_line(const char *bol, const char *eol)
			   char *eol, enum grep_context ctx, ssize_t *col,
		fprintf(stderr, "%.*s", (int)p->patternlen, p->pattern);
 * We could let the compiler do this, but without C99 initializers
	if (!p)
			if (match.rm_so == match.rm_eo)
	else if (!strcmp(arg, "extended"))

		bol = eol + 1;
	int hit = 0;
#ifdef USE_LIBPCRE2
	opt->linenum = def->linenum;
	/* Top level nodes have hit markers.  See if they all are hits */
		    (last_hit && lno <= last_hit + opt->post_context)) {
	pcre2_general_context_free(pcre2_global_context);
		if ((ctx == GREP_CONTEXT_HEAD) && (eol == bol))
		xsnprintf(where, sizeof(where), "In '%s' at %d, ", p->origin, p->no);
	case GREP_SOURCE_FILE:

		}
	}
		if (jitret)
{
			die("not a pattern expression %s", p->pattern);
					const char *origin, int no,

int grep_source(struct grep_opt *opt, struct grep_source *gs)
		break;
				peek_eol = end_of_line(peek_bol, &peek_left);
		break;
		/*
			/* Hit at this line.  If we haven't shown the
}
			 * ifdef our way around that and dealing with
		compile_regexp_failed(p, error);
			return 1;
			break;


	case GREP_PATTERN: /* atom */
	return x;
#endif /* !USE_LIBPCRE2 */
		output_sep(opt, sign);
		opt->pcre1 = 1;
	if (hit && p->word_regexp) {
static int grep_source_load(struct grep_source *gs);
int grep_buffer(struct grep_opt *opt, char *buf, unsigned long size)
		break;
#include "object-store.h"
	case GREP_PATTERN_BODY:
{

		hit = match_line(opt, bol, eol, &col, &icol, ctx, collect_hits);
	opt->pattern_type_option = GREP_PATTERN_TYPE_UNSPECIFIED;
	pcre2_code_free(p->pcre2_pattern);
		if (show_function && (!peek_bol || peek_bol < bol)) {
		p->pcre2_match_data = pcre2_match_data_create_from_pattern(p->pcre2_pattern, NULL);
		fputc(' ', stderr);
#ifdef USE_LIBPCRE2
	if (opt->funcbody) {
	if (opt->ignore_case) {
	}
		char *eol = --bol;
				      eol - line, 0, flags, p->pcre2_match_data,
	case GREP_NODE_ATOM:
	pcre_free(p->pcre1_regexp);
	case GREP_PATTERN_TYPE_ERE:
	case GREP_PATTERN_TYPE_FIXED:
		regmatch_t m;

			/* There could be more than one match on the


	if (p && p->token == GREP_AND) {

	default:
		compile_regexp_failed(p, (const char *)&errbuf);
			if (!pcre2_global_context)
			 * only in PCRE v2 10.30 and later. Needing to
		hit = !pcre2match(p, line, eol, match, eflags);
			hit = 0;
		x = xcalloc(1, sizeof (struct grep_expr));

	} else if (skip_prefix(var, "color.grep.", &slot)) {

	case GREP_SOURCE_FILE:
			else
static int grep_source_load_file(struct grep_source *gs)
		return;
				cno = 0;
		where[0] = 0;
		if (strncmp(bol, field, len))
	die("bad %s argument: %s", opt, arg);
		return 1;
			      regmatch_t *pmatch, int eflags)
		if (opt->last_shown)
	struct grep_expr *header_expr;
		if (!header_expr)
	}
{
			 * we need to show this line.
					pcre2_malloc, pcre2_free, NULL);
	if (!opt->all_match)

			}
	if (ret < 0 && ret != PCRE_ERROR_NOMATCH)
static int strip_timestamp(char *bol, char **eol_p)
		return 0; /* punt for too complex stuff */
	case GREP_OR: fprintf(stderr, "*or*"); break;
			p->pcre2_compile_context = pcre2_compile_context_create(NULL);
void grep_init(struct grep_opt *opt, struct repository *repo, const char *prefix)


			 * Peek past them to see if they belong to the
				peek_bol = peek_eol + 1;
	 * fields in grep_opt it's generally not necessary to zero out

		output_color(opt, bol, rest, line_color);
		match->rm_eo = (int)ovector[1];
	else if (p->pcre2_pattern)
#endif
				line_color = opt->colors[GREP_COLOR_CONTEXT];
static int pcre1match(struct grep_pat *p, const char *line, const char *eol,
 */

	 * USE_LIBPCRE. See the sibling comment in
		} else {
		return;

	indent(in);

	free_pattern_expr(opt->pattern_expression);
			eol - line, 0, flags, ovector,
			 * complex than just quoting this ourselves.

		z->u.binary.right = y;
		if (match_funcname(opt, gs, bol, end))
				 */

		dump_grep_pat(x->u.atom);
	}
{
		} else if (lno > opt->last_shown + 1) {
		gs->identifier = NULL;
			bol = pmatch[0].rm_so + bol + 1;
		 * in response to an unmatch for the current line.  E.g.
{
			hit = 0;
	if (opt->pcre2) {
{
	if (p)
		       p->is_fixed = 1;
			bol += match.rm_eo;
	case GREP_NODE_OR:
	opt->output = def->output;
			/*
	else
			/*
	}
	}
		 * one match, leave printing each header to the loop below.
			struct strbuf sb = STRBUF_INIT;
	}
			eflags |= REG_NOTBOL;
}
					enum grep_header_field field)
			BUG("malformed header expr");
}
	if (p->pcre1_jit_on)
		     ((pmatch[0].rm_eo == (eol-bol)) ||
	/* NEEDSWORK:
int grep_config(const char *var, const char *value, void *cb)

	 * we do not have to do the two-pass grep when we do not check
	p->pcre2_compile_context = NULL;
	return 0;
		}
			die("unmatched parenthesis");
		if (grep_config("color.grep.matchcontext", value, cb) < 0)
			goto next_line;
	int erroffset;
		switch (p->token) {
	return 1;
				     match.rm_eo - match.rm_so, match_color);


	case GREP_SOURCE_OID:

static void free_pattern_expr(struct grep_expr *x)
	struct diff_filespec *df;
		opt->extended_regexp_option = 1;
	else
static int pcre2match(struct grep_pat *p, const char *line, const char *eol,
		break;
		color_set(opt->colors[i], def->colors[i]);
	size_t len;
	die("cannot use Perl-compatible regexes when not compiled with USE_LIBPCRE");
	fflush(NULL);
	if (!strcmp(var, "grep.column")) {
		regmatch_t *match, int eflags)
}


void append_header_grep_pattern(struct grep_opt *opt,
	*ret = *opt;
		enum grep_context ctx = GREP_CONTEXT_BODY;
			BUG("unknown binary handling mode");
	while (l && *cp != '\n') {
	if (opt->allow_textconv) {
			if (opt->debug)
	case GREP_CLOSE_PAREN: fprintf(stderr, "*)*"); break;
			/*
		if (opt->invert)
		}
	opt->pathname = def->pathname;
			ctx = GREP_CONTEXT_BODY;
	const char *match_color = NULL;
{
	p = opt->pattern_list;
	int funcname_needed = !!opt->funcname, comment_needed = 0;
			 * There is the PCRE2_LITERAL flag, but it's
		return grep_source_1(opt, gs, 0);
	 * This is because in the process of parsing grep.patternType
		 * that do not have either, so inversion should
	gs->driver = NULL;
		return 0;
		return 0;
		/*
		 *
		/*

	if (pattern_type != GREP_PATTERN_TYPE_ERE &&

		 */
	if (!header_expr)

}
		*list = p->next;
{
{
	grep_attr_unlock();
static struct grep_expr *compile_pattern_or(struct grep_pat **list)
	}
	if (!pcre2_global_context)
		if (p->token != GREP_PATTERN)
			xdiff_set_find_func(xecfg, pe->pattern, pe->cflags);
	}
			switch (p->token) {
{
			else if (p->pcre2_pattern)
		assert(x->node == GREP_NODE_OR);
		l--;
	BUG("invalid grep_source type to load");
			output_color(opt, gs->name, strlen(gs->name),
	}
		 * JIT we need to extract PCRE2_INFO_JITSIZE from the
			}
			unsigned long peek_left = left;
		z->node = GREP_NODE_OR;
		int hit;

				opt->output(opt, "\n", 1);
	opt->last_shown = 0;
		compile_regexp_failed(p, errbuf);
	if (bol < eol) {

	if (!opt->pattern_expression)
		h = match_expr_eval(opt, x->u.binary.left, bol, eol, ctx, col,
{
}
	 * Unreachable until USE_LIBPCRE2 becomes synonymous with

		return;
	} else {
	if (earliest < 0) {
			if (cno < 0) {
		gs->driver = userdiff_find_by_name("default");
{
	return x;
		 * not be a word char).  Similarly, match end must be
}
		    (pmatch[0].rm_eo < 0) ||
	if (run_once)
		from = opt->last_shown + 1;
void grep_source_init(struct grep_source *gs, enum grep_source_type type,
pthread_mutex_t grep_attr_mutex;
		if (i < 0)
}
		z = xcalloc(1, sizeof (struct grep_expr));
static int grep_source_is_binary(struct grep_source *gs,
	}
		{
		opt->output(opt, buf, strlen(buf));

	default:
{
	color_set(opt->colors[GREP_COLOR_FUNCTION], "");
	}
static void compile_pcre1_regexp(struct grep_pat *p, const struct grep_opt *opt)
	if ((p->token != GREP_PATTERN) &&

	case GREP_SOURCE_OID:
			peek_bol = bol;
{
			if (cur < from) {
		 * segfault (pre PCRE 10.31) or run into a fatal error
		if (opt->output != std_output)
int grep_use_locks;

	return header_expr;
	xdemitconf_t *xecfg = opt->priv;
				bol++;
		      enum grep_context ctx, ssize_t *col,
		    (eol - bol) < pmatch[0].rm_eo)
		regmatch_t tmp;
				  NULL);
	die("cannot use Perl-compatible regexes when not compiled with USE_LIBPCRE");
		char *eol = --bol;
		/* We did not see any hit, so we want to show this */
						   pat->pattern);
		*list = p->next;
			funcname_needed = 0;
}
	else if (!strcmp(arg, "fixed"))
	*bol_p = last_bol;
		 * look_ahead() skips quickly to the line that possibly
	if (opt->count && count) {
						       header_expr);
		compile_fixed_regexp(p, opt);
}
{
		 * pcre2_jit_compile() will exit early with 0. If we
		break;
		if (!y)
static void show_pre_context(struct grep_opt *opt, struct grep_source *gs,
		/* Show hunk marks, except for the first file. */
	PCRE2_UCHAR errbuf[256];
		 * It's important that pcre1 always be assigned to
			break;
	for (p = opt->pattern_list; p; p = p->next) {
	output_color(opt, name, strlen(name), opt->colors[GREP_COLOR_FILENAME]);
		 * obj_read_lock() must be called.

		}
			return 1;
	case GREP_SOURCE_OID:
		/*
			h &= match_expr_eval(opt, x->u.binary.right, bol, eol,
		case GREP_PATTERN: /* atom */
		   is_fixed(p->pattern + no_jit_len,
		if (gs->driver->funcname.pattern) {
{
	}

				 * being asked to show all lines that _don't_
	if (opt->ignore_case) {
		}
			 * it + PCRE2_MULTILINE being an error is more
					p->pcre2_jit_on);
			if (binary_match_only) {
		break;
	p->no = no;
	}
{
		opt->use_reflog_filter = 1;

{
	p->patternlen = patlen;

				output_color(opt, "--", 2, opt->colors[GREP_COLOR_SEP]);
			}
	last_bol = sp;
		x->hit = 0;
	while (1) {
	size = xsize_t(st.st_size);

		if (h || opt->columnnum) {
	data = xmallocz(size);
		 * then proceed to call pcre2_jit_match() further down
}
		z->u.binary.left = x;
	FREE_AND_NULL(gs->path);
	if (bol == eol)
	}
			struct grep_pat *new_pat;
	return p;
}

	 */
		if (!y)
		*eol = '\0';
	switch (gs->type) {
	struct grep_expr *header_expr = prep_header_patterns(opt);
		die("pcre_exec failed with error code %d", ret);
		ssize_t col = -1, icol = -1;
		study_options = PCRE_STUDY_JIT_COMPILE;
		return z;
		opt->pattern_type_option = parse_pattern_type_arg(var, value);
{
	bol = gs->buf;
		error_errno(_("'%s': short read"), filename);
	case GREP_PATTERN_BODY: fprintf(stderr, "pattern_body"); break;
	int options = PCRE2_MULTILINE;
			ARRAY_SIZE(ovector));

{
			if (grep_source_is_binary(gs, opt->repo->index))
	 * non-worktreee git-grep with --textconv.
		hit = !pcre1match(p, line, eol, match, eflags);
		return GREP_PATTERN_TYPE_FIXED;
	if (opt->file_break && opt->last_shown == 0) {
	switch (type) {
}
}
			hit = !hit;
	}

{
	if (x && p && p->token != GREP_CLOSE_PAREN) {
	}
	return 0;
}
static void show_funcname_line(struct grep_opt *opt, struct grep_source *gs,
			goto next_line;
	struct grep_expr *x;
		case GREP_PATTERN_HEAD:
		while (next_match(opt, bol, eol, ctx, &match, eflags)) {
		gs->identifier = oiddup(identifier);
	size = fill_textconv(r, driver, df, &buf);
	case GREP_OPEN_PAREN:

	do_append_grep_pat(&opt->pattern_tail, p);
static void free_pcre2_pattern(struct grep_pat *p)
static void dump_grep_pat(struct grep_pat *p)
		output_color(opt, name, strlen(name), opt->colors[GREP_COLOR_FILENAME]);
	struct grep_expr *z = xcalloc(1, sizeof(*z));

static struct grep_expr *grep_true_expr(void)
	if (!opt->extended)
	if (!opt->only_matching) {
	 */

	}

		if (comment_needed && (is_empty_line(bol, eol) ||
	return 1;
					      &tmp, 0);
		 */
		/* Words consist of at least one character. */

		if (!x->u.binary.left->hit)
	 * The textconv interface is intimately tied to diff_filespecs, so we

{
	z->node = GREP_NODE_OR;
		     const char *origin, int no, enum grep_pat_token t)
	[GREP_COLOR_MATCH_CONTEXT]  = "matchContext",
		    && look_ahead(opt, &left, &lno, &bol))
{
				comment_needed = 1;
		if ((pmatch[0].rm_so < 0) ||
		compile_regexp_failed(p, errbuf);
			break;
	 * We know the result of a textconv is text, so we only have to care
	if (opt->pre_context < lno)

			       char *bol, unsigned lno)
			if (!opt->columnnum) {
		if (opt->pathname) {

		break;
{
		return;
		compile_regexp(p, opt);
static void free_pcre1_regexp(struct grep_pat *p)
		    (p->pcre2_jit_on ? "pcre2_jit_match" : "pcre2_match"), ret,
			 */
		pcre_free_study(p->pcre1_extra_info);
	if (!strcmp(var, "grep.fullname")) {
	case GREP_PATTERN: fprintf(stderr, "pattern"); break;
		; /* find the beginning of the line */

	int jitret;
	case GREP_PATTERN_HEAD:
		h = match_expr_eval(opt, x->u.binary.left, bol, eol, ctx, col,
	if (!strcmp(arg, "default"))
static int grep_source_is_binary(struct grep_source *gs,
			xecfg = opt->priv = NULL;

		}
{
	if (opt->extended)
			p->patternlen = old_patternlen;
	strbuf_release(&sb);

			 && (show_function ||

}

		cur++;
				       match_funcname(opt, gs, bol, eol))) {
		match->rm_eo = ovector[1];
	p = *list;
		return GREP_PATTERN_TYPE_ERE;
		if (p->field < GREP_HEADER_FIELD_MIN ||
	obj_read_lock();
	int hit = 0;
		 * grep.extendedRegexp to override grep.patternType!
{
	{ "committer ", 10 },
			compile_pcre2_pattern(p, opt);
		fprintf(stderr, ")\n");
{
		BUG("grep call which could print a name requires "
	return h;
}
	 * line to its first match. Otherwise, 'cno' is 0 indicating that we are
		xsnprintf(where, sizeof(where), "%s, ", p->origin);
		dump_grep_expression(opt);
static struct grep_expr *grep_splice_or(struct grep_expr *x, struct grep_expr *y)
				 * match a given expression. Therefore, set cno
static const char *color_grep_slots[] = {
	grep_source_clear_data(gs);
			return (match_expr_eval(opt, x->u.binary.left, bol, eol,
/*
			p->pattern = old_pattern;
}
	size_t size;
					xecfg->find_func_priv) >= 0;
{
			if (!nl)
	clr_hit_marker(opt->pattern_expression);
				match_expr_eval(opt, x->u.binary.right, bol,

		fprintf(stderr, "[all-match]\n");
		    regmatch_t *match, int eflags)
		break;
}
	FREE_AND_NULL(gs->name);

	do_append_grep_pat(&opt->header_tail, p);
}
	}
	 * We first clear hit markers from them.
	if (!grep_source_load(gs))
			}
void append_grep_pattern(struct grep_opt *opt, const char *pat,

		opt->color = git_config_colorbool(var, value);
static void do_append_grep_pat(struct grep_pat ***tail, struct grep_pat *p)
	for (p = opt->pattern_list; p; p = p->next) {

			header_group[p->field] = h;
			 * child that would produce an earlier match.
		break;
	struct grep_opt *opt = &grep_defaults;
{
#endif
	}
		opt->pcre2 = 1;
static void color_set(char *dst, const char *color_bytes)
	if (!p->pcre1_extra_info && error)
	int binary_match_only = 0;
	p->pattern = xmemdupz(pat, patlen);
	basic_regex_quote_buf(&sb, p->pattern);
 * If using PCRE, make sure that the library is configured
	if (isalpha(*bol) || *bol == '_' || *bol == '$')
		h = 1;
		regerror(err, &p->regexp, errbuf, 1024);
				return 1;
		opt->extended_regexp_option = git_config_bool(var, value);

	 * the textconv'd buf separate from the diff_filespec. But much of the
				fprintf(stderr, "pcre2_jit_on=%d: (*NO_JIT) in regex\n",
				 * is enough to know that it needs to be
	 * API, thus we use obj_read_lock() here.
	if (opt->ignore_case)
	p->token = t;
#else /* !USE_LIBPCRE1 */
	/*
	int rest = eol - bol;
	dump_grep_expression_1(x, 0);
	if (memchr(p->pattern, 0, p->patternlen) && !opt->pcre2)
static int fill_textconv_grep(struct repository *r,
	p = *list;
		break;
	return hit;
		return ch;
			 const char *origin, int no, enum grep_pat_token t)
		}
	}
			 * Don't short-circuit OR when given --column (or
static void free_pcre1_regexp(struct grep_pat *p)
		grep_set_pattern_type_option(GREP_PATTERN_TYPE_ERE, opt);
		if (grep_config("color.grep.matchselected", value, cb) < 0)
		opt->pcre2 = 1;
	return z;

			const struct userdiff_funcname *pe = &gs->driver->funcname;

		opt->output(opt, data, size);
		return opt->unmatch_name_only;
				  eol - line, 0, flags, p->pcre2_match_data,
	}
		fprintf(stderr, "(not\n");
			p->patternlen -= len;
	err = regcomp(&p->regexp, sb.buf, regflags);
		return 1;
	color_set(opt->colors[GREP_COLOR_SEP], GIT_COLOR_CYAN);
		return 0;

	}
	struct grep_pat *p = create_grep_pat(pat, patlen, origin, no, t, 0);

	 * and diff_filespec structs, this mess could just go away.
		if (!p->next)
	err = regcomp(&p->regexp, p->pattern, regflags);
			 * collecting hits) to ensure we don't skip a later
	struct grep_pat *p;
		 * pattern *after* we do pcre2_jit_compile() above.

		BUG("attempt to textconv something without a path?");
			 * Forward to the next possible start, i.e. the

	grep_attr_lock();
	gs->buf = buf;
}
			if (opt->funcbody)
#endif /* !USE_LIBPCRE1 */
	/* we do not call with collect_hits without being extended */
			if (p->pcre1_regexp)

			while (is_empty_line(peek_bol, peek_eol)) {
							p->pcre2_tables);

		assert(p->field < ARRAY_SIZE(header_field));
	p->is_fixed = is_fixed(p->pattern, p->patternlen);
	regmatch_t match;
	struct grep_expr *z = xcalloc(1, sizeof(*z));
		 * (i.e. the next char must not be a word char).
	int error;

		return NULL;
{
	gs->size = 0;
		struct grep_pat *pp = p;
			break;
	header_expr = NULL;
	while (left) {
		if (!(collect_hits || opt->columnnum)) {
				show_line_header(opt, name, lno, cno, sign);
	if (xecfg) {
	 * buffer-wide "all-match".
	die("%s'%s': %s", where, p->pattern, error);
	for (fld = 0; fld < GREP_HEADER_FIELD_MAX; fld++)
				free_pcre1_regexp(p);
			if (match_funcname(opt, gs, peek_bol, peek_eol))
	if (p->pcre1_jit_on)
		return xecfg->find_func(bol, eol - bol, buf, 1,
#endif

		 */
	grep_source_init(&gs, GREP_SOURCE_BUF, NULL, NULL, NULL);


		xsnprintf(buf, sizeof(buf), "%u\n", count);
	if (eflags & REG_NOTBOL)
			     unsigned lno, ssize_t cno, char sign)
	gs.size = size;
	hit = patmatch(p, bol, eol, pmatch, eflags);
		 * and skip the very first one later in work_done().
		free_pattern_expr(x->u.binary.left);
#endif
			if (opt->only_matching)
{
			x->u.binary.left->hit |= h;
	case GREP_NODE_TRUE:
#if defined(PCRE_CONFIG_JIT) && !defined(NO_LIBPCRE1_JIT)
	case GREP_PATTERN_BODY:
	int err;
	pcre2_compile_context_free(p->pcre2_compile_context);
		ret = pcre2_match(p->pcre2_pattern, (unsigned char *)line,
				break;
}
static struct grep_expr *compile_pattern_and(struct grep_pat **list)
		dump_grep_expression_1(x->u.unary, in+1);
	 */

	return hit;
{
			size_t len = 0;
	char *buf;

}
		grep_set_pattern_type_option(pattern_type, opt);
 * information in an earlier call to git_config(grep_config).
	if (opt->status_only)
	if (opt->funcname && funcname_needed)
		if (!*list || (*list)->token != GREP_CLOSE_PAREN)
		gs->identifier = xstrdup(identifier);
		fprintf(stderr, "pcre2_jit_on=%d\n", p->pcre2_jit_on);
}
			if (hit)
		break;
		/* leave user-provided buf intact */
	if (!gs->driver)
	}
	if (!strcmp(var, "grep.extendedregexp")) {
static struct grep_pat *create_grep_pat(const char *pat, size_t patlen,
	return r;
       if (!p->fixed && !p->is_fixed) {
			char *cp = p->pattern + p->patternlen, *nl = NULL;
	for (sp = bol; sp < last_bol; sp++) {
			 * NOT earlier in the tree may turn this into an OR. In
		if (hit) {
			 * this case, see the below comment.
		textconv = userdiff_get_textconv(opt->repo, gs->driver);
	for (i = 0; i < NR_GREP_COLORS; i++)
			}
	if (!match_one_pattern(p, bol, eol, ctx, &match, eflags))
{
}
	const char *start = bol;
	const char *slot;
				    icol, 0);
			compile_regexp(p, opt);
	}
#include "diffcore.h"
	}
			if (opt->funcbody)
			h = match_one_pattern(x->u.atom, bol, eol, ctx,
	p->word_regexp = opt->word_regexp;
	for (p = opt->pattern_list; p; p = p->next) {
		*list = p->next;

	pcre_malloc = malloc;
	if (gs->driver)
		 * currenty thread-safe and might be racy with object reading,
		char buf[32];
static void show_line(struct grep_opt *opt, char *bol, char *eol,
		 * If we're using threads then we can't easily identify
				goto next_line;
	 * the case.

	case GREP_NODE_ATOM:
		      unsigned *lno_p,
	struct grep_pat *p;
		x->node = GREP_NODE_NOT;
	struct grep_opt *def = &grep_defaults;

	int regflags = 0;
}
	memset(&xecfg, 0, sizeof(xecfg));
			      struct userdiff_driver *driver,
	[GREP_COLOR_COLUMNNO]	    = "column",
	/* We need to look even further back to find a function signature. */
}
			free(p->pattern);
		struct grep_expr *h;
static struct grep_expr *grep_or_expr(struct grep_expr *left, struct grep_expr *right)

		return;
		 * This is because if the pattern contains the
	struct grep_pat *p;
}
static int grep_source_1(struct grep_opt *opt, struct grep_source *gs, int collect_hits)

		    && !(last_hit
		break;
	int ret, flags = 0;
	default:

		break;
#include "quote.h"
	case GREP_NODE_AND:
	while (cur < lno) {
		match->rm_so = ovector[0];
				return 1;
				hit |= match_next_pattern(p, bol, eol, ctx,
	int i;
		grep_attr_unlock();
	struct grep_expr *x = opt->pattern_expression;
	pcre2_config(PCRE2_CONFIG_JIT, &p->pcre2_jit_on);
	return malloc(size);
			if (opt->name_only) {
	struct grep_pat *p;
	return 0;
		for (;;) {
		/*
		return NULL;
	}
			new_pat = create_grep_pat(nl + 1, len - 1, p->origin,
		bol += len;
}
		return -1;
	case GREP_SOURCE_BUF:
	if (opt->color || opt->only_matching) {
		 */
		bol++;
			break;
	if (from <= opt->last_shown)
}
			return -1;
		flags |= PCRE_NOTBOL;
		case GREP_PATTERN_BODY:
	opt->only_matching = 0;
	int options = PCRE_MULTILINE;
}
	switch (p->token) {
				break;
		if (p->is_fixed) {
		break;
		break;
			strbuf_add(&sb, "\\E", 2);
		 * but to see whether we're going to be actually using
 */
			if (opt->status_only)

				    icol, 0);
		if (opt->last_shown == 0) {
		/* "grep -v -e foo -e bla" should list lines
static int match_one_pattern(struct grep_pat *p, char *bol, char *eol,
			break;
		}
	case GREP_SOURCE_FILE:

	case GREP_PATTERN_TYPE_BRE:
			count++;
		 */
			comment_needed = 1;
		 * In case the line we're being called with contains more than
{
	case GREP_PATTERN_TYPE_PCRE:
	if (!chk_hit_marker(opt->pattern_expression))
	if (gs->buf)

struct grep_opt *grep_opt_dup(const struct grep_opt *opt)
	}
	 * to leak any existing buffer.

	return z;
				return 1;
		}
					enum grep_pat_token t,

				show_funcname_line(opt, gs, bol, lno);
			if (bol < eol)
	} else if (opt->pre_context || opt->post_context || opt->funcbody) {
static int match_funcname(struct grep_opt *opt, struct grep_source *gs, char *bol, char *eol)
	}
	if (gs->driver->binary != -1)

		x->node = GREP_NODE_ATOM;
	if (pattern_type != GREP_PATTERN_TYPE_UNSPECIFIED)
{

		 * doesn't hit.
		}
{
			opt->show_hunk_mark = 1;
	opt->pathname = 1;
	[GREP_COLOR_CONTEXT]	    = "context",
	 * & grep.extendedRegexp we set opt->pattern_type_option and

		*eol = 0;
	while (bol < --eol) {
{
	}
	case GREP_PATTERN_BODY:
}

	}
				      NULL);

		switch (opt->binary) {
	}
	memset(opt, 0, sizeof(*opt));
		return compile_pattern_atom(list);
		return 1;
	switch (p->token) {
#endif /* !USE_LIBPCRE2 */
	 * internally call thread-unsafe functions such as the
	switch (gs->type) {
	}
void grep_source_load_driver(struct grep_source *gs,
		y = compile_pattern_or(list);
	if (p->no)
	/*
	int ovector[30], ret, flags = PCRE_NO_UTF8_CHECK;
		 * something more than just skipping the current line
static struct grep_expr *compile_pattern_or(struct grep_pat **);

	if (!opt->ignore_locale && is_utf8_locale() && has_non_ascii(p->pattern) &&
	}
				bol = next_bol;
		pcre2_get_error_message(ret, errbuf, sizeof(errbuf));
	xsnprintf(dst, COLOR_MAXLEN, "%s", color_bytes);
	opt->repo = repo;
	unsigned long left;

	 * fill_textconv is not remotely thread-safe; it modifies the global
	p->next = NULL;
void grep_destroy(void)
	p->pcre1_extra_info = pcre_study(p->pcre1_regexp, study_options, &error);
	default:
	struct grep_pat *p = xcalloc(1, sizeof(*p));
		break;
	}

		z->node = GREP_NODE_AND;
		opt->extended_regexp_option = 0;
			case GREP_PATTERN: /* atom */
		}
				BUG("pcre2_global_context uninitialized");
	err_ret:
		left--;
	gs->size = size;
	}
	if (collect_hits)
				 * match on the line. We are thus inverted and

		x = x->u.binary.right;
	if (!strcmp(var, "color.grep.match")) {
	/* Back forward. */
static int word_char(char ch)

				show_function = 0;
	}

	}
	if (st.st_size != read_in_full(i, data, size)) {
	case GREP_SOURCE_BUF:
		pthread_mutex_lock(&grep_attr_mutex);
		 * line as a context around the previous hit when it
	case GREP_SOURCE_OID:
	pmatch->rm_eo = match.rm_eo;
					     GREP_PATTERN_HEAD, field);
static int match_expr_eval(struct grep_opt *opt, struct grep_expr *x, char *bol,
		if (!p->pcre2_match_data)
		char buf[1];
}
			/*
	 * internally use opt->extended_regexp_option to see if we're
		*eol = saved_ch;
	case GREP_OPEN_PAREN: fprintf(stderr, "*(*"); break;
}
			opt->output(opt, "\n", 1);
	else
			case GREP_PATTERN_BODY:
		int i = LOOKUP_CONFIG(color_grep_slots, slot);
	pcre2_match_data_free(p->pcre2_match_data);
		header_group[fld] = NULL;
	 */
			    p->patternlen - no_jit_len))
#ifdef USE_LIBPCRE2
	case GREP_PATTERN_BODY:
	color_set(opt->colors[GREP_COLOR_LINENO], "");
	if (opt->invert)

	close(i);
define_list_config_array_extra(color_grep_slots, {"match"});
			return;
{
		return GREP_PATTERN_TYPE_PCRE;
			 * Don't short-circuit AND when given --column, since a
		z->u.binary.right = y;
 * default values from the template we read the configuration
		if (funcname_needed && match_funcname(opt, gs, bol, eol)) {

		fprintf(stderr, "pcre1_jit_on=%d\n", p->pcre1_jit_on);
		}
		pcre2_global_context = pcre2_general_context_create(
	compile_grep_patterns_real(opt);
			else if (opt->funcname)
	[GREP_COLOR_LINENO]	    = "lineNumber",
		break;
	free_filespec(df);
	if (opt->linenum) {
		x = x->u.binary.right;
				show_pre_context(opt, gs, bol, eol, lno);
				 struct index_state *istate)
	*left = l;

		while (bol > gs->buf && bol[-1] != '\n')
		while (bol > gs->buf && bol[-1] != '\n')
	 * TODO: allowing text conversion to run in parallel with object
		const char *error)

		/* Match beginning must be either beginning of the

		return;
	return 0;
	 * which feels mostly useless but sometimes useful.  Maybe
	 */
	}
			die("--and not followed by pattern expression");
	left = gs->size;
	return 0;
{
	if (p->token == GREP_PATTERN_HEAD) {
	if (userdiff_config(var, value) < 0)
		}
		char buf[32];

				*col = tmp.rm_so;
				/*
			strbuf_add(&sb, p->pattern, p->patternlen);
				*col = tmp.rm_so;
			 * pre-context lines, we would need to show them.
static inline void grep_attr_unlock(void)
		opt->pattern_expression = header_expr;
	switch (p->token) {

		case GREP_PATTERN_HEAD:
		from = lno - opt->pre_context;
	enum grep_context ctx = GREP_CONTEXT_HEAD;
		return 0;
#ifdef USE_LIBPCRE1
}
		default:
		if (!hit || m.rm_so < 0 || m.rm_eo < 0)
			}
	struct grep_pat *p, *n;
static int should_lookahead(struct grep_opt *opt)
	case GREP_PATTERN_HEAD:

	if (opt->heading && opt->last_shown == 0) {
		 * be done outside.
	struct grep_expr *x, *y, *z;
		return match_expr(opt, bol, eol, ctx, col, icol,
			 * strict word match.  But later ones could be!
				*tail = &new_pat->next;
		return -1;
		if (x->u.binary.right &&
	}
}

		while (*eol != '\n')
		}
				 * A negative cno indicates that there was no
	 * opt->extended_regexp_option, respectively. We then
			continue;
	case GREP_SOURCE_FILE:
		return GREP_PATTERN_TYPE_BRE;
	if (opt->debug)
	pcre_free = free;
{
	static int run_once;
		fprintf(stderr, "<body>"); break;
	orig_from = from;
			opt->output(opt, "\n", 1);
	}
	x = compile_pattern_and(list);
	*left_p -= last_bol - bol;
		free(p);
}
}
#endif
	const char *error;
		die("Unexpected node type (internal error) %d", x->node);
{

}
	i = open(filename, O_RDONLY);
			break;

		    (eol - bol) < pmatch[0].rm_so ||
		}

	unsigned lno = 1;
			bol--;
		break;
	p->fixed = opt->fixed;
			output_sep(opt, ':');
void grep_source_clear(struct grep_source *gs)
}
		compile_pcre2_pattern(p, opt);
		default:
}
static struct grep_expr *compile_pattern_not(struct grep_pat **list)

		free_pattern_expr(x->u.binary.right);
 again:
	if (!strcmp(var, "color.grep"))
{
	return bol == eol;
				 */
	 *
		if (!p->next)
		fprintf(stderr, ")\n");
	opt->header_tail = &opt->header_list;
		color = opt->colors[i];
			char *peek_eol = eol;
	grep_source_clear_data(gs);
}
	return ret;
	z->u.binary.left = left;
	struct grep_expr *(header_group[GREP_HEADER_FIELD_MAX]);

{
	color_set(opt->colors[GREP_COLOR_MATCH_CONTEXT], GIT_COLOR_BOLD_RED);
			case GREP_PATTERN_HEAD:
	char *sp, *last_bol;

	else if (opt->all_match)
		output_sep(opt, sign);
	if (match.rm_so < 0 || match.rm_eo < 0)
				break;
		break;


			else
	}
			return 0;
#endif
		 * is not thread-safe. Also, get_oid_with_context() and

			lno++;
	grep_source_load_driver(gs, istate);
			     regmatch_t *pmatch, int eflags)
	case GREP_AND: fprintf(stderr, "*and*"); break;
}
	}

#include "config.h"
			error_errno(_("failed to stat '%s'"), filename);


	struct userdiff_driver *textconv = NULL;
{
					 p->patternlen, options, &error, &erroffset,
	if (p)
	    ((p->token == GREP_PATTERN_HEAD) != (ctx == GREP_CONTEXT_HEAD)))

		}
}
		 * the line instead of pcre2_match() we'll either
		x = xcalloc(1, sizeof (struct grep_expr));

		opt->pattern_expression = grep_splice_or(header_expr,
		      !word_char(bol[pmatch[0].rm_so-1])) &&
			if (grep_source_is_binary(gs, opt->repo->index))
	if (collect_hits)
		      char **bol_p)
		} else {
		pcre2_get_error_message(error, errbuf, sizeof(errbuf));
			funcname_needed = 1;
	 * OR node.
	r = grep_source(opt, &gs);
		for (p = opt->pattern_list; p; p = p->next) {
			cno += match.rm_eo;
static void compile_pcre1_regexp(struct grep_pat *p, const struct grep_opt *opt)
	/* Otherwise the toplevel "or" terms hit a bit differently.
	ret->pattern_list = NULL;
		      const char *name, unsigned lno, ssize_t cno, char sign)
 * to use the same allocator as Git (e.g. nedmalloc on Windows).
{
	char where[1024];
				     icol, collect_hits);
	ret = pcre_exec(p->pcre1_regexp, p->pcre1_extra_info, line,
		return error(_("'%s': unable to read %s"),
			show_line(opt, bol, eol, gs->name, lno, col + 1, '-');
			     gs->name,
			 */
	x = compile_pattern_not(list);
       }
		switch (p->token) {
		 * the first file.  Always put hunk marks in that case
static int grep_source_load(struct grep_source *gs)

	xdemitconf_t xecfg;
			char *old_pattern = p->pattern;
		if (!opt->ignore_locale && has_non_ascii(p->pattern)) {
{
	 * grep_set_pattern_type_option().
		if (x->node != GREP_NODE_OR)
{
{
	opt->max_depth = -1;
	struct grep_expr *x = opt->pattern_expression;
			hit |= 1;
		lno--;
		from = opt->last_shown + 1;

	return z;
	if (p->pcre2_jit_on) {
			pcre2_set_character_tables(p->pcre2_compile_context,
{
		ch = *eol;
		x->u.binary.left->hit = 0;
	switch (pattern_type) {
	if (opt->extended)
		*list = p->next;
	gs->size = size;
	int r;
			     oid_to_hex(gs->identifier));
	}
static int match_expr(struct grep_opt *opt, char *bol, char *eol,
		grep_set_pattern_type_option(opt->pattern_type_option, opt);

	case GREP_NODE_OR:
	}
		*eol = ch;
		return 0;

{

	for(pat = opt->pattern_list; pat != NULL; pat = pat->next)


				regfree(&p->regexp);
		opt->pattern_expression = grep_or_expr(opt->pattern_expression,
#include "commit.h"
}
	unsigned last_hit = 0;
	else
		return NULL;
		dump_grep_expression_1(x->u.binary.right, in+1);
		char *color;
	for (fld = 0; fld < GREP_HEADER_FIELD_MAX; fld++) {
	free(pointer);

	/* All-hit markers are meaningful only at the very top level

		return gs->buf ? 0 : -1;
		 * This branch *must* happen after setting from the
 * Any allocated memory needs to be released in grep_destroy().
				 struct index_state *istate);
	}
		if (match.rm_so > pmatch->rm_so)
	{ "author ", 7 },
		/*
#else
	struct grep_source gs;
	 * prepare_packed_git() lazy-initializator. Because of the last two, we
		die("%s failed with error code %d: %s",
}
		*eol = ch;
{
	gs->buf = data;

{

		output_color(opt, buf, strlen(buf), opt->colors[GREP_COLOR_LINENO]);
	if (p->token == GREP_PATTERN_HEAD && saved_ch)
	if (!opt->ignore_locale && is_utf8_locale() && has_non_ascii(p->pattern))
	PCRE2_SIZE *ovector;
	struct grep_expr *z = x;
		if (opt->color) {
	 * pointer is the beginning of the thing we are searching. So let's

	[GREP_COLOR_SELECTED]	    = "selected",
	else if (opt->extended_regexp_option)
		xsnprintf(buf, sizeof(buf), "%d", lno);
		break;

			eol++;
		return grep_source_load_file(gs);
			if (opt->show_hunk_mark) {
			p->pcre1_tables = pcre_maketables();

static int pcre1match(struct grep_pat *p, const char *line, const char *eol,
	opt->relative = 1;
	case GREP_PATTERN_HEAD:
		if ( ((pmatch[0].rm_so == 0) ||
	if (!strcmp(var, "grep.linenumber")) {
	FREE_AND_NULL(gs->identifier);
}
	gs->name = xstrdup_or_null(name);
			eflags = REG_NOTBOL;
	{ "reflog ", 7 },
		}
	if (opt->debug)

	while (x) {
	if (!p)
				break;
	pcre_free((void *)p->pcre1_tables);
	}
			return x->hit;
void grep_source_clear_data(struct grep_source *gs)
{
	struct grep_pat *p;
		regflags |= REG_ICASE;
		return x;
	return grep_source_1(opt, gs, 0);

	opt->prefix = prefix;
	}
		char *eol, ch;
#include "userdiff.h"


	if (opt->all_match)
{
	struct grep_expr *x, *y, *z;
