			/* negation allowed? */
is_abbreviated:
{
			nr_aliases++;
				printed_dashdash = 1;
		return ctx->total - ctx->argc;
		usage_with_options(usagestr, options);
	fputc('\n', outfile);

	ctx->cpidx = ((flags & PARSE_OPT_KEEP_ARGV0) != 0);
			/*
{
				       " with an optional k/m/g suffix"),
#define OPT_SHORT 1
			newopt[i].short_name = short_name;
		if (ctx.argv[0][1] == '-') {
		if (opt->flags & PARSE_OPT_OPTARG && !p->opt) {
					break;
	for (; opts->type != OPTION_END; opts++) {
	int printed_dashdash = 0;
		return opt->ll_callback(p, opt, NULL, unset);
			case PARSE_OPT_UNKNOWN:
static enum parse_opt_result opt_command_mode_error(
	for (; options->type != OPTION_END; options++) {
				pos += fprintf(outfile, "%c", opts->short_name);
				printf(" --%s", name);
	case OPTION_NEGBIT:
	if (starts_with(arg, "no-")) {
			*(unsigned long *)opt->value = opt->defval;
			return 0;

	if (opts->flags & PARSE_OPT_OPTARG)

			pos += utf8_fprintf(outfile, _("-NUM"));
		if (!arg[2] /* "--" */ ||
		short_name = newopt[i].short_name;
}
		switch (opts->type) {

{
		}
			pad = USAGE_OPTS_WIDTH - pos;
			if (!opts->ll_callback)
		if (that->long_name)

		strbuf_addf(&sb, "option `no-%s'", opt->long_name);
{

		if (unset)
		}
		if (opts->argh &&
}
			*(int *)opt->value = 0;

		    strcspn(opts->argh, " _") != strlen(opts->argh))
				if (ctx->opt)
			continue;
			if (opts->callback && opts->ll_callback)
	{
		int flags = 0, opt_flags = 0;
				case PARSE_OPT_COMPLETE:
static struct option *preprocess_options(struct parse_opt_ctx_t *ctx,
			p_unset = 0;
			err = get_arg(p, opt, flags, (const char **)opt->value);
				     opt->short_name, opt->long_name, reason);
			*(const char **)opt->value = (const char *)opt->defval;
int parse_options(int argc, const char **argv, const char *prefix,
				case PARSE_OPT_NON_OPTION:

		else
	for (that = all_opts; that->type != OPTION_END; that++) {
		return opt_command_mode_error(opt, all_opts, flags);
			return error(_("%s expects a numerical value"),
	else
	case OPTION_BITOP:
}
			break;
				       const char * const *usagestr,
			return PARSE_OPT_UNKNOWN;
static int disallow_abbreviated_options;
				continue;
				BUG("OPTION_CALLBACK needs one callback");
			}
		case OPTION_INTEGER:
	usage_with_options_internal(NULL, usagestr, opts, 0, 1);
		default:

	}
					p->opt = arg_end + 1;
				ctx->argv++;

	}
	} else if (p->argc > 1) {
					*(char *)ctx->argv[0] = '-';
	struct option *newopt;



			fputc('\n', outfile);
	return error("BUG: switch '%c' %s", opt->short_name, reason);
}
		if (*arg != '-' || !arg[1]) {
			rc = (*numopt->ll_callback)(p, numopt, arg, 0);
		case PARSE_OPT_COMPLETE:
				BUG("No please. Nested aliases are not supported.");
					opt_flags |= OPT_UNSET;
			suffix = "=";

		   const char * const *usagestr,
		fprintf(outfile, "cat <<\\EOF\n");
		if (newopt[i].type != OPTION_ALIAS)
				break;
			break;
			case PARSE_OPT_HELP:
			fputc('\n', outfile);
			break;
		/*
			continue;
		int rc;
		p->argc--;
	if (opt->long_name) {
		if (internal_help && !strcmp(arg + 2, "help-all"))


				     optname(opt, flags));
	free(ctx.alias_groups);
		case OPTION_COUNTUP:
	exit(129);
					check_typos(arg + 1, options);
		if (opts->flags & PARSE_OPT_NONEG)
			}
	if ((opt->flags & PARSE_OPT_CMDMODE) &&
		free(arg);

{
		case OPTION_FILENAME:
	for (; opts->type != OPTION_END; opts++) {
		case OPTION_ALIAS:
				       const struct option *, int, int);
	if (!err && ctx && ctx->flags & PARSE_OPT_SHELL_EVAL)


					goto unknown;
	int i, nr, alias;
					 * error out.
}
{
					ambiguous_option = abbrev_option;
void parse_options_start(struct parse_opt_ctx_t *ctx,
			if (*rest)
		usagestr++;
	ctx->out   = argv;
		*(int *)opt->value = strtol(arg, (char **)&s, 10);
		if (opts->long_name)
					"LASTARG_DEFAULT and OPTARG");
		}
		if (!rest) {
			abbrev_option->long_name);

				       const struct option *all_opts,
		case OPTION_NEGBIT:
}
}
		/* it and other are from the same family? */

		case PARSE_OPT_NON_OPTION:
		    that->value != opt->value ||
		if (!(ctx->flags & PARSE_OPT_KEEP_UNKNOWN))
				check_typos(arg + 1, options);
			return get_value(p, options, all_opts, OPT_SHORT);
 * OPTION_ALIAS.
			BUG("OPT_ALIAS() should not remain at this point. "
		case OPTION_BIT:
			fputc('\n', outfile);
	if (abbrev_option)
		if (unset)

				       const char * const *,
			/* abbreviated? */

			return usage_with_options_internal(ctx, usagestr, options, 1, 0);
			p_unset = 1;
	struct parse_opt_ctx_t *p, const char *arg,
				if (!(flags & OPT_UNSET) && *arg_end)
	for (; options->type != OPTION_END; options++) {
	char short_opts[128];
		arg = xmemdupz(p->opt, len);
		if (opt->flags & PARSE_OPT_OPTARG && !p->opt) {
			 */
		else {

	return PARSE_OPT_DONE;
		if (ctx->total == 1 && !strcmp(arg + 1, "-git-completion-helper"))
{
	memset(&ctx, 0, sizeof(ctx));
			continue;
		if (opts->flags & PARSE_OPT_NODASH &&
	for (; opts->type != OPTION_END; opts++) {
	return PARSE_OPT_UNKNOWN;
void NORETURN usage_with_options(const char * const *usagestr,
	precompose_argv(argc, argv);
			fix_filename(p->prefix, (const char **)opt->value);
		alias++;
					     optname(options, flags));
			memcpy(newopt + i, options + j, sizeof(*newopt));
	need_newline = 1;
			/* negated and abbreviated very much? */
			if (!name || strcmp(name, source))
	case OPTION_FILENAME:
			/* negated? */
			continue;
				return PARSE_OPT_NON_OPTION;

		if (has_string(one_opt->long_name, group) &&
		case PARSE_OPT_DONE:
	case OPTION_COUNTUP:
		} else if (nr_noopts >= 0) {
{
			break;

		if (!err)
		case OPTION_COUNTUP:
		       const char * const usagestr[])
		if (ctx->flags & PARSE_OPT_ONE_SHOT &&
			*(int *)opt->value |= opt->defval;
}
			fputc('\n', outfile);
			return (*opt->ll_callback)(p, opt, p_arg, p_unset);
		else if (opt->flags & PARSE_OPT_OPTARG && !p->opt)
				fprintf(outfile, "%s\n", _(opts->help));
				return error(_("%s takes no value"),
		else if (opt->flags & PARSE_OPT_OPTARG && !p->opt)
			 * print the original help string.
}
			break;
			const struct option *opts)
		if (!options->long_name)
		}
			if (!rest)
		 * Handle the numerical option later, explicit one-digit
			need_newline = 0;
		if (opts->type == OPTION_ALIAS) {
	default:
			if (options[j].type == OPTION_ALIAS)
	}
static void parse_options_check(const struct option *opts)
			return -1;
	case OPTION_MAGNITUDE:
	const struct option *abbrev_option = NULL, *ambiguous_option = NULL;

	}
					 * This is leaky, too bad.
	const struct option *all_opts,
			fprintf_ln(outfile, _("    %s"), _(*usagestr));

	}
					 */
				  const struct option *options, int flags)
		switch (opts->type) {
static int usage_with_options_internal(struct parse_opt_ctx_t *ctx,
}

			fprintf(outfile, "%*s", pad + USAGE_GAP, "");
	struct strbuf that_name = STRBUF_INIT;
}


				break;
	}
				err |= optbug(opts, "invalid short name");
	if (numopt && isdigit(*p->opt)) {
		const char *suffix = "";
		if (opt->short_name)
		fprintf_ln(outfile, _("   or: %s"), _(*usagestr++));
			if (*opts->help)
	for (; options->type != OPTION_END; options++) {
		}
			if (starts_with("no-", arg)) {
		}


					     const struct option *options)
	case OPTION_INTEGER:
				goto is_abbreviated;
				}
	const char *s, *arg;
		if (unset) {
			break;
		}
	}
		else
			len++;
			*(const char **)opt->value = NULL;
	const char *s;
		}
				if (abbrev_option &&
		case OPTION_SET_INT:
		}
		if (*rest) {
			rc = (*numopt->callback)(numopt, arg, 0) ? (-1) : 0;
#include "config.h"


			ctx->opt = arg + 1;
unknown:
	}
		git_env_bool("GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS", 0);
		options = real_options;
			if (ctx->flags & PARSE_OPT_STOP_AT_NON_OPTION)
}


			if (!starts_with(arg, "no-")) {
				       int flags)
		return 0;
	if (!ctx->alias_groups)
				continue;
	int err = 0;

		for (j = 0; j < nr; j++) {
{
		if (unset) {
		if (get_arg(p, opt, flags, &arg))

		  int flags)
	int err;
	if (flags & OPT_SHORT)
	if (!file || !*file || !prefix || is_absolute_path(*file)
	for (nr = 0; options[nr].type != OPTION_END; nr++) {
	ctx->argc = argc;
		if (get_arg(p, opt, flags, &arg))
		if (arg[1] != '-') {
			return 1;
	}
		if (internal_help && !strcmp(arg + 2, "help"))
		*(int *)opt->value &= ~opt->extra;
				else
	fprintf(stderr, "fatal: %s\n\n", msg);
int optbug(const struct option *opt, const char *reason)
}
	case PARSE_OPT_COMPLETE:
		}
		strbuf_addf(&sb, "switch `%c'", opt->short_name);
			if (opts->callback)
	int nr_noopts = 0;
	ctx->prefix = prefix;
			const char *name = options[j].long_name;
	parse_options_start_1(&ctx, argc, argv, prefix, options, flags);
		}

			rest = NULL;
		int has_unset_form = 0;
			*(int *)opt->value &= ~opt->defval;
			break;
				     const struct option *opt,

		case OPTION_CALLBACK:
	ctx->flags = flags;
			goto show_usage;
	for (; options->type != OPTION_END; options++) {
{
		exit(129);
		ctx->alias_groups[alias * 3 + 1] = options[j].long_name;
			 * NEEDSWORK: this is a bit inconsistent because
			case PARSE_OPT_ERROR:
	memset(short_opts, '\0', sizeof(short_opts));
		case OPTION_CALLBACK:
	else
		}
	return ctx->cpidx + ctx->argc;
			case PARSE_OPT_COMPLETE:
		if (opts->long_name && opts->short_name)
		char *arg;
		if (**usagestr)
		p->opt = p->opt[len] ? p->opt + len : NULL;
			 * help string as "alias of %s" but "git cmd -h" will
}
	/*
		if (skip_prefix(opts->long_name, "no-", &name)) {
/*
		return 0;
		if (!strcmp(it, *(array++)))
	int internal_help = !(ctx->flags & PARSE_OPT_NO_INTERNAL_HELP);
			break;
	return newopt;
{
			p_arg = arg;
			goto show_usage;
	if (!err && ctx && ctx->flags & PARSE_OPT_SHELL_EVAL)
		}


		size_t pos;
static enum parse_opt_result get_value(struct parse_opt_ctx_t *p,
	 * is not a grave error, so let it pass.
	    (flags & PARSE_OPT_STOP_AT_NON_OPTION) &&
	switch (parse_options_step(&ctx, options, usagestr)) {
		if (unset)
			p_unset = 0;
		BUG("opt->type %d should not happen", opt->type);
				}
					 */
			BUG("An alias must have long option name");
	return 0;
	case PARSE_OPT_NON_OPTION:
		if (options[nr].type == OPTION_ALIAS)
		if (!long_name)
	fputc('\n', stdout);
		    (int)(arg_end - arg), arg);
		else
			if (!opts->callback && !opts->ll_callback)

					 * exact match later, we need to
#include "color.h"
		const char *arg = ctx->argv[0];
	if (unset && p->opt)

		}
			return error(_("%s expects a numerical value"),
			return (*opt->callback)(opt, p_arg, p_unset) ? (-1) : 0;
	return PARSE_OPT_HELP;
	const struct option *options)
		ctx->opt = NULL;

			err |= optbug(opts, "multi-word argh should use dash to separate words");
		if (pos <= USAGE_OPTS_WIDTH)
	if (ctx->flags & PARSE_OPT_ONE_SHOT)


			while (ctx->opt) {

	return -2;
		       const struct option *options,

		return 0;
			continue;
		if (need_newline) {
	const struct option *that;
		}
{
void NORETURN usage_msg_opt(const char *msg,
		 * TRANSLATORS: the colon here should align with the
#include "parse-options.h"
	case PARSE_OPT_DONE:
		if (!full && (opts->flags & PARSE_OPT_HIDDEN))
			nr_noopts++;
	const struct option *all_opts = options;
					/*

		}

		if (opts->short_name) {
	}
			p->out[p->cpidx++] = arg - 2;
		return 0;
			else if (short_opts[opts->short_name]++)
		if (unset)
		    that->defval != *(int *)opt->value)
	int flags)
				    !is_alias(p, abbrev_option, options)) {
		ctx->argc--;
{
		while (isdigit(p->opt[len]))
		case PARSE_OPT_HELP:
	}
	COPY_ARRAY(newopt, options, nr + 1);
		     opts->long_name))
		case OPTION_LOWLEVEL_CALLBACK:
	return 0;
	const int unset = flags & OPT_UNSET;
		return;
		*arg = *++p->argv;
			else
						goto show_usage;
			ambiguous_option->long_name,
	}
 * Right now this is only used to preprocess and substitute
					goto show_usage;
			nr_noopts++;
	const struct option *numopt = NULL;
			flags |= OPT_UNSET;
			}
				if (starts_with(long_name, arg + 3))
		else
		return get_value(p, options, all_opts, flags ^ opt_flags);
		    !strcmp(arg + 2, "end-of-options")) {
	if (!(flags & OPT_SHORT) && p->opt && (opt->flags & PARSE_OPT_NOARG))
			if (*rest != '=')
static int has_string(const char *it, const char **array)
		     !(opts->flags & PARSE_OPT_NONEG) ||
		if (options->type == OPTION_NUMBER)
		if (j == nr)
		source = newopt[i].value;
#define OPT_UNSET 2
		default:
		switch (parse_long_opt(ctx, arg + 2, options)) {
					BUG("parse_short_opt() cannot return these");
		else {
	int need_newline;
	while (*array)
{
			if (nr_noopts && !printed_dashdash) {
		/* lone -h asks for help */
	if ((flags & PARSE_OPT_ONE_SHOT) &&
	/*

				switch (parse_short_opt(ctx, options)) {
int parse_options_step(struct parse_opt_ctx_t *ctx,
	 * already, and report that this is not compatible with it.
	const struct option *original_opts = opts;
		const char *name;
		const char *long_name;
		if (unset)

#define USAGE_OPTS_WIDTH 24
	const struct option *all_opts = options;

const char *optname(const struct option *opt, int flags)
					return PARSE_OPT_ERROR;
					 const struct option *options)
}
			BUG("BITOP can't have unset form");
		}
			pos += usage_argh(opts, outfile);
		if (!long_name)
				  int argc, const char **argv, const char *prefix,

static enum parse_opt_result get_arg(struct parse_opt_ctx_t *p,
{
		return 0;
		exit(129);
			if ((opts->flags & PARSE_OPT_OPTARG) ||
			return 0;
	ctx->argv = argv;
{
		long_name = newopt[i].long_name;

			need_newline = 0;
			continue;


{
		case OPTION_MAGNITUDE:

		}
	/* we must reset ->opt, unknown short option leave it dangling */
				break;
				     optname(opt, flags));
					if (internal_help && *ctx->opt == 'h')

		      optname(opt, flags), that_name.buf);

	if (!(flags & PARSE_OPT_ONE_SHOT)) {
		case OPTION_NEGBIT:
		switch (opts->type) {

	memset(ctx, 0, sizeof(*ctx));
			if (parse_nodash_opt(ctx, arg, options) == 0)
		/*
		    const struct option *another_opt)
			break;
			    source, newopt[i].long_name);
			return get_arg(p, opt, flags, (const char **)opt->value);
			}

	struct option *real_options;
	MOVE_ARRAY(ctx->out + ctx->cpidx, ctx->argv, ctx->argc);
			; /* ok. (usually accepts an argument) */
	    *(int *)opt->value && *(int *)opt->value != opt->defval)
			if (!skip_prefix(arg + 3, long_name, &rest)) {
			}
		case OPTION_BIT:
	ctx->total = ctx->argc;
				case PARSE_OPT_DONE:
		p->opt = NULL;
		err = 0;
		fputs("EOF\n", outfile);
	for (group = ctx->alias_groups; *group; group += 3) {
		}
				break;
			if (ctx->opt)

			continue;
			has_unset_form = 1;
			ctx->out[ctx->cpidx++] = ctx->argv[0];
		return 0;
		exit(0);
		ctx->alias_groups[alias * 3 + 2] = NULL;
		else

		}
			 int argc, const char **argv, const char *prefix,
			return error(_("%s expects a non-negative integer value"
			*(const char **)opt->value = (const char *)opt->defval;
				case PARSE_OPT_UNKNOWN:
					 * ambiguous. So when there is no
	return 0;
	if (ambiguous_option) {
			return PARSE_OPT_DONE;
		}
				BUG("parse_short_opt() cannot return these");
		return error("BUG: option '%s' %s", opt->long_name, reason);
			continue;
		 */
				continue;
	}
		int j;
	if (real_options)
			continue;
		*(int *)opt->value |= opt->defval;
			strbuf_addf(&that_name, "-%c", that->short_name);

			return show_gitcomp(options);
	if (!usagestr)
#include "git-compat-util.h"
		case OPTION_STRING:
		}
					goto is_abbreviated;
	switch (opt->type) {
			*(const char **)opt->value = NULL;


		printf(" --%s%s", opts->long_name, suffix);
}
}
			err |= optbug(opts, "uses incompatible flags "
		if (options->short_name == *p->opt) {

		if (options->type == OPTION_ARGUMENT) {
		return NULL;
		if (!skip_prefix(arg, long_name, &rest))
			error(_("unknown non-ascii option in string: `%s'"),
		return get_value(p, abbrev_option, all_opts, abbrev_flags);
		return;
}
	if (strlen(arg) < 3)
		 * options take precedence over it.
}

			if (opts->flags & PARSE_OPT_OPTARG)
			return -1;
		if (!opts->long_name)

			fprintf_ln(outfile, _("alias of --%s"),
	int nr_aliases = 0;
		ctx->argv++;
		if (ctx->flags & PARSE_OPT_ONE_SHOT)
#include "commit.h"
int parse_options_end(struct parse_opt_ctx_t *ctx)
			suffix = "=";
}
				}
		else
			    !(opts->flags & PARSE_OPT_NOARG))
			pos += fprintf(outfile, ", ");
				abbrev_option = options;
			if (!(p->flags & PARSE_OPT_KEEP_UNKNOWN) &&
	for (; ctx->argc; ctx->argc--, ctx->argv++) {
	return utf8_fprintf(outfile, s, opts->argh ? _(opts->argh) : _("..."));
{
	return PARSE_OPT_COMPLETE;

				goto unknown;
					 * If this is abbreviated, it is
#include "utf8.h"

	for (; opts->type != OPTION_END; opts++) {
			if (*rest == '=')
		if (!git_parse_ulong(arg, opt->value))
			case PARSE_OPT_NON_OPTION:
		exit(128);
	real_options = preprocess_options(&ctx, options);
	parse_options_start_1(ctx, argc, argv, prefix, options, flags);
		}
			return 0;
 show_usage:
			case PARSE_OPT_DONE:
			return PARSE_OPT_ERROR;
	case OPTION_BIT:
			error(_("unknown option `%s'"), ctx.argv[0] + 2);
		default:
}
		return PARSE_OPT_HELP;
		ctx->out[ctx->cpidx++] = ctx->argv[0];
		if (opts->long_name)
			*(int *)opt->value = opt->defval;
			}
		     !(opts->flags & PARSE_OPT_NOARG) ||
}
		case PARSE_OPT_ERROR:
		    !(opts->flags & PARSE_OPT_NOARG))
 */

			pad = USAGE_OPTS_WIDTH;
		break;

	}
		}
static int usage_with_options_internal(struct parse_opt_ctx_t *,

}
{
				     int flags, const char **arg)
}
static void check_typos(const char *arg, const struct option *options)
		if (starts_with(options->long_name, arg)) {
	case PARSE_OPT_HELP:
		!opts->argh || !!strpbrk(opts->argh, "()<>[]|");
				continue;
	}


	else if (flags & OPT_UNSET)
		if (!opts->long_name)
		} else {
	/* each alias has two string pointers and NULL */

}
	}
			    const struct option *options)
	default: /* PARSE_OPT_UNKNOWN */
{
		s = literal ? " %s" : " <%s>";
			*(unsigned long *)opt->value = 0;
				flags |= OPT_UNSET;

{

			      ctx.argv[0]);
			continue;

{

					 * started to parse aggregated stuff
	FILE *outfile = err ? stderr : stdout;
			continue;
		*(int *)opt->value = unset ? 0 : *(int *)opt->value + 1;
		if (opts->flags & (PARSE_OPT_HIDDEN | PARSE_OPT_NOCOMPLETE))

	}
			*(int *)opt->value = 0;

				       const struct option *opts, int full, int err)
		BUG("Can't keep argv0 if you don't have it");
		    ctx->argc != ctx->total)

		error(_("ambiguous option: %s "
		    has_string(another_opt->long_name, group))



	if (unset && (opt->flags & PARSE_OPT_NONEG))
			error(_("did you mean `--%s` (with two dashes)?"), arg);
		if ((opts->flags & PARSE_OPT_LASTARG_DEFAULT) &&
		*arg = (const char *)opt->defval;
		fprintf(outfile, "%*s%s\n", pad + USAGE_GAP, "", _(opts->help));
{
 * instead of the original 'options'.
		BUG("STOP_AT_NON_OPTION and KEEP_UNKNOWN don't go together");
 * Scan and may produce a new option[] array, which should be used
		int short_name;
		case OPTION_FILENAME:
	if (!nr_aliases)
		*arg = p->opt;

		  const struct option *options, const char * const usagestr[],
		    !(that->flags & PARSE_OPT_CMDMODE) ||
		else
		    ((opts->flags & PARSE_OPT_OPTARG) ||
			if (nr_noopts < 0)
static int is_alias(struct parse_opt_ctx_t *ctx,
		case OPTION_SET_INT:
		else if (opt->flags & PARSE_OPT_NOARG)
	case OPTION_SET_INT:
			break;
		if (opt->callback)
		*(int *)opt->value = unset ? 0 : opt->defval;
			pos += fprintf(outfile, "--%s", opts->long_name);
		}
 *
				abbrev_flags = flags ^ opt_flags;
	const char *arg_end = strchrnul(arg, '=');
				if (skip_prefix(long_name, "no-", &long_name)) {
		case PARSE_OPT_UNKNOWN:

static int parse_nodash_opt(struct parse_opt_ctx_t *p, const char *arg,
				continue;
			continue;
			p_unset = 0;
	if (disallow_abbreviated_options && (ambiguous_option || abbrev_option))
		else if (opt->flags & PARSE_OPT_OPTARG && !p->opt)
			continue;
			(abbrev_flags & OPT_UNSET) ?  "no-" : "",

			continue;
		size_t len = 1;
				/* abbreviated and negated? */
				err |= optbug(opts, "should not accept an argument");
			exit(129);

		error(_("%s is incompatible with %s"),
		return PARSE_OPT_ERROR;
				       const struct option *opt,
			return -1;
#define USAGE_GAP         2
		return 0;

		if (*s)
		strbuf_release(&that_name);
		return 0;
			BUG("parse_long_opt() cannot return these");
			    "That case is not supported yet.");
		return PARSE_OPT_HELP;
	if (err)
					 *
			p->opt = p->opt[1] ? p->opt + 1 : NULL;
	} else
		} else if (isascii(*ctx.opt)) {
		else

		if (!*arg)
		else if (get_arg(p, opt, flags, &arg))
				*(int *)options->value = options->defval;
		const char *rest, *long_name = options->long_name;
			error(_("unknown switch `%c'"), *ctx.opt);
	int abbrev_flags = 0, ambiguous_flags = 0;
	}
#include "cache.h"
		case OPTION_CALLBACK:
	const char **group;

				   (const char *)opts->value);
			if (opts->flags & PARSE_OPT_NODASH)
			if (opts->flags & PARSE_OPT_NOARG)
		 * one in "usage: %s" translation.
		if (unset)
		else
		   const struct option *options)
				ctx->argc--;
	 * Find the other option that was used to set the variable

	    || !strcmp("-", *file))
			return get_value(p, options, all_opts, OPT_SHORT);
			*(int *)opt->value &= ~opt->defval;

			newopt[i].long_name = long_name;
				BUG("OPTION_LOWLEVEL_CALLBACK needs a callback");
			if (opts->flags & PARSE_OPT_LASTARG_DEFAULT)
	 * Giving the same mode option twice, although unnecessary,
again:

	fprintf_ln(outfile, _("usage: %s"), _(*usagestr++));
	    !(flags & PARSE_OPT_ONE_SHOT))

static void show_negated_gitcomp(const struct option *opts, int nr_noopts)
				BUG("OPTION_LOWLEVEL_CALLBACK needs no high level callback");
		int pad;
	} else if (p->argc == 1 && (opt->flags & PARSE_OPT_LASTARG_DEFAULT)) {
	return sb.buf;
			BUG("could not find source option '%s' of alias '%s'",
static int show_gitcomp(const struct option *opts)
	case OPTION_CALLBACK:
{
		case OPTION_INTEGER:
	show_negated_gitcomp(original_opts, nr_noopts);
			 const struct option *options, int flags)
			return 1;
{
		error(_("did you mean `--%s` (with two dashes)?"), arg);
	show_negated_gitcomp(original_opts, -1);
		if (!(options->flags & PARSE_OPT_NODASH))
		return 0;
			return 0;
	    (flags & PARSE_OPT_KEEP_ARGV0))
		return rc;
		if (!has_unset_form)

		case OPTION_NUMBER:
	 */
				if (internal_help && *ctx->opt == 'h')
		if (that == opt ||
			break;

		if (numopt->callback)
			continue;
	CALLOC_ARRAY(ctx->alias_groups, 3 * (nr_aliases + 1));
			if (options->value)
	for (alias = 0, i = 0; i < nr; i++) {
				printf(" --");
		if (*(int *)opt->value < 0)
		case OPTION_MAGNITUDE:
			 * usage_with_options() on the original options[] will print
			return error("BUG: switch '%c' (--%s) %s",
	usage_with_options(usagestr, options);
		if (opts->flags & (PARSE_OPT_HIDDEN | PARSE_OPT_NOCOMPLETE))
			continue;
		if ((opts->flags & PARSE_OPT_LITERAL_ARGHELP) ||
					ambiguous_flags = abbrev_flags;
		return err;
				case PARSE_OPT_ERROR:

		continue;
		return error(_("%s isn't available"), optname(opt, flags));
		if (opts->type == OPTION_NUMBER)
			"(could be --%s%s or --%s%s)"),
				return PARSE_OPT_ERROR;
	int literal = (opts->flags & PARSE_OPT_LITERAL_ARGHELP) ||
		const char *p_arg = NULL;
		    const struct option *one_opt,
	return PARSE_OPT_UNKNOWN;
	case OPTION_LOWLEVEL_CALLBACK:

		pos = fprintf(outfile, "    ");
static void fix_filename(const char *prefix, const char **file)
		/* lone --git-completion-helper is asked by git-completion.bash */
			if (options->flags & PARSE_OPT_NONEG)
			arg,

	return usage_with_options_internal(ctx, usagestr, options, 0, 0);
		return error(_("%s takes no value"), optname(opt, flags));
					continue;
			printf(" --no-%s", opts->long_name);
				continue;
	 */
	const struct option *all_opts = options;


				continue;
	}
		if (options->short_name == arg[0] && arg[1] == '\0')
		    (opts->flags & PARSE_OPT_OPTARG))
			break;
static enum parse_opt_result parse_short_opt(struct parse_opt_ctx_t *p,
				err |= optbug(opts, "short name already used");
	return parse_options_end(&ctx);
		ctx->alias_groups[alias * 3 + 0] = newopt[i].long_name;
static int usage_argh(const struct option *opts, FILE *outfile)
	}
				pos += fprintf(outfile, "-%c", opts->short_name);
					goto again;
	if (p->opt) {
	ctx->out[ctx->cpidx + ctx->argc] = NULL;
	disallow_abbreviated_options =
		return error(_("%s requires a value"), optname(opt, flags));
		const char *source;
	struct parse_opt_ctx_t ctx;
	ALLOC_ARRAY(newopt, nr + 1);
			    !strncmp(long_name, arg, arg_end - arg)) {
	if (!one_opt->long_name || !another_opt->long_name)
	}
	case OPTION_STRING:
			}
		}
					/* fake a short option thing to hide the fact that we may have
				case PARSE_OPT_HELP:
		case OPTION_GROUP:
	while (*usagestr) {
					"not supported for dashless options");
	free(real_options);
			    "Are you using parse_options_step() directly?\n"
	const struct option *opt,
	*file = prefix_filename(prefix, *file);
		     optname(opt, flags));
			continue;
	while (*usagestr && **usagestr)
			p->opt = rest + 1;

		if (opts->type == OPTION_GROUP) {
			err |= optbug(opts, "uses feature "
		if (internal_help && ctx->total == 1 && !strcmp(arg + 1, "h"))
			goto unknown;
		die("disallowed abbreviated or ambiguous option '%.*s'",
				     optname(opt, flags));
			}
			if (!(ctx->flags & PARSE_OPT_KEEP_DASHDASH)) {
		if (opts->short_name) {

			switch (parse_short_opt(ctx, options)) {
	return error(_("%s : incompatible with something else"),
			s = literal ? "[%s]" : "[<%s>]";
		 */
				BUG("OPTION_CALLBACK can't have two callbacks");
	}
		int p_unset;
					ctx->argv[0] = xstrdup(ctx->opt - 1);
			if (0x7F <= opts->short_name)
	strbuf_reset(&sb);
static void parse_options_start_1(struct parse_opt_ctx_t *ctx,
		if (opts->flags & PARSE_OPT_COMP_ARG)
			s = literal ? "[=%s]" : "[=<%s>]";
	static struct strbuf sb = STRBUF_INIT;
	case PARSE_OPT_ERROR:
		return error(_("%s takes no value"), optname(opt, flags));

	if ((flags & PARSE_OPT_KEEP_UNKNOWN) &&
			strbuf_addf(&that_name, "--%s", that->long_name);
	parse_options_check(options);
				continue;
			goto show_usage;
		case OPTION_STRING:
		strbuf_addf(&sb, "option `%s'", opt->long_name);
			*(int *)opt->value |= opt->defval;
		return 0;
			(ambiguous_flags & OPT_UNSET) ?  "no-" : "",
	ctx->opt = NULL;
			numopt = options;
static enum parse_opt_result parse_long_opt(
		if (starts_with(opts->long_name, "no-"))
