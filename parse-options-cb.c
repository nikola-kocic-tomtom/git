#include "color.h"
	int value;
		else
 * For an option opt, recreates the command-line option in opt->value which
		n++;
 * command.
	return 0;
	}
}
	struct object_id oid;
	*target = unset ? 2 : 1;
{
	} else if (opt->short_name && !unset) {
	return 0;
			(*target)++;
	size_t b_len = parse_options_count(b);
		else
 * Recreates the command-line option in the strbuf.
			return error(_("option `%s' expects a numerical value"),

}
	string_list_append(v, arg);
	if (!arg)


{
{

	int *target = opt->value;
		return 0;
	size_t n = 0;
		strbuf_addch(sb, '-');


}

		return 0;
	BUG_ON_OPT_ARG(arg);
		return -1;
		arg = unset ? "never" : (const char *)opt->defval;
	struct string_list *v = opt->value;
{
	return 0;
}
/**

	} else
			strbuf_addstr(sb, arg);
		return -1;
	if (!arg)
 * the command-line option, which can be specified multiple times, to another
static int recreate_opt(struct strbuf *sb, const struct option *opt,
	return 0;
		*target = null_oid;
	return 0;
	return 0;
		return error("malformed object name %s", arg);
	char **opt_value = opt->value;
	return 0;

				    const struct option *b)
/**
{
}
{
 * "-h" output even if it's not being handled directly by
struct option *parse_options_dup(const struct option *o)
	if (get_oid(arg, &oid))
 * it. This can be used as a callback together with
	struct object_id oid;
			     int unset)
	if (!arg)
	return 0;
{
	struct object_id oid;
		return 0;
	struct option *ret;
}
		if (*target <= 0)
}
{
{
 * For an option opt, recreate the command-line option, appending it to
			     opt->long_name);
	} else {

	return ret;
	}
	return 0;
}

	int v;
int parse_opt_verbosity_cb(const struct option *opt, const char *arg,

	argv_array_push(opt_value, sb.buf);
		strbuf_addch(sb, opt->short_name);
	struct commit **target = opt->value;
	if (recreate_opt(&sb, opt, arg, unset) < 0)

}
 * one wins.
		else if (v > the_hash_algo->hexsz)
		if (*target >= 0)
	return 0;

					   const struct option *opt,
		oid_array_clear(opt->value);
struct option *parse_options_concat(const struct option *a,
{
		arg = "never";
			*target = -1;


	return 0;

	if (unset) {
	return parse_options_concat(o, no_options);


	else if (opt->short_name == 'v') {

	if (!commit)
#include "commit.h"

	*target = oid;
		return -1;
					   const char *arg, int unset)
/**
	if (!commit)
		v = unset ? 0 : DEFAULT_ABBREV;
	commit = lookup_commit_reference(the_repository, &oid);

 * the command-line option to another command. Since any previous value will be
}
int parse_opt_commits(const struct option *opt, const char *arg, int unset)
	size_t a_len = parse_options_count(a);


int parse_opt_commit(const struct option *opt, const char *arg, int unset)
		*target = 0;
{
int parse_opt_object_id(const struct option *opt, const char *arg, int unset)
	return 0;


	oid_array_append(opt->value, &oid);
{
 * overwritten, this callback should only be used for options where the last

		if (!*arg)
		strbuf_addstr(sb, unset ? "--no-" : "--");

		string_list_clear(v, 0);
		return error(_("malformed object name '%s'"), arg);


}
	if (unset) {
	struct commit *commit;
	struct commit *commit;
	int *target = opt->value;
		return -1;
	static struct strbuf sb = STRBUF_INIT;

 */
		return -1;
			return error(_("option `%s' expects a numerical value"),
		/* --no-quiet, --no-verbose */
	if (!arg) {
	if (!arg)
		return error("no such commit %s", arg);
	struct object_id *target = opt->value;
{
int parse_opt_object_name(const struct option *opt, const char *arg, int unset)

}
#include "oid-array.h"

	struct option no_options[] = { OPT_END() };
/**
 */
	if (value < 0)
int parse_opt_string_list(const struct option *opt, const char *arg, int unset)
				     opt->long_name);
 */
}
	*opt_value = strbuf_detach(&sb, NULL);
int parse_opt_passthru(const struct option *opt, const char *arg, int unset)
	commit = lookup_commit_reference(the_repository, &oid);
	}

	if (!arg)
			(*target)--;
#include "git-compat-util.h"
{
	BUG_ON_OPT_ARG(arg);

}
	commit_list_insert(commit, opt->value);
		if (v && v < MINIMUM_ABBREV)
		if (arg) {
{


int parse_opt_abbrev_cb(const struct option *opt, const char *arg, int unset)
	if (unset)
	*(int *)(opt->value) = v;
#include "cache.h"
		return -1;
static size_t parse_options_count(const struct option *opt)
	COPY_ARRAY(ret + a_len, b, b_len + 1); /* + 1 for final OPTION_END */
int parse_opt_expiry_date_cb(const struct option *opt, const char *arg,
		return error(_("malformed object name '%s'"), arg);
{

	}
	free(*opt_value);
	strbuf_reset(sb);
	} else {
	ALLOC_ARRAY(ret, st_add3(a_len, b_len, 1));
int parse_opt_passthru_argv(const struct option *opt, const char *arg, int unset)
	*(int *)opt->value = value;
	if (parse_expiry_date(arg, (timestamp_t *)opt->value))

}
	COPY_ARRAY(ret, a, a_len);
	if (get_oid(arg, &oid))

	if (get_oid(arg, &oid))
	BUG_ON_OPT_ARG(arg);
	BUG_ON_OPT_NEG(unset);
		return -1;

#include "string-list.h"
	static struct strbuf sb = STRBUF_INIT;

}
		return error("no such commit %s", arg);
			    int unset)
 * must be an char* initialized to NULL. This is useful when we need to pass
		die(_("malformed expiration date '%s'"), arg);
	}
		const char *arg, int unset)
		if (*arg)
#include "argv-array.h"
	value = git_config_colorbool(NULL, arg);
		v = strtol(arg, (char **)&arg, 10);
}
 * parse_options().
	return PARSE_OPT_UNKNOWN;
int parse_opt_tertiary(const struct option *opt, const char *arg, int unset)
			strbuf_addstr(sb, arg);
#include "parse-options.h"
			   int unset)
		strbuf_addstr(sb, opt->long_name);
	return 0;
			*target = 1;

{
		}
	if (recreate_opt(&sb, opt, arg, unset) < 0)
		return -1;
 * Report that the option is unknown, so that other code can handle
	return n;
				     opt->long_name);
 * opt->value which must be a argv_array. This is useful when we need to pass
		return error("malformed object name %s", arg);
	if (unset) {
	*target = commit;
}
		if (arg)
	return 0;
 */
			v = MINIMUM_ABBREV;
	if (unset)
	if (get_oid(arg, &oid))
 * OPTION_LOWLEVEL_CALLBACK to allow an option to be documented in the
int parse_opt_noop_cb(const struct option *opt, const char *arg, int unset)

	if (!arg)
{

			strbuf_addch(sb, '=');
/*----- some often used options -----*/

	for (; opt && opt->type != OPTION_END; opt++)
	if (opt->long_name) {
		return error(_("option `%s' expects \"always\", \"auto\", or \"never\""),
	struct argv_array *opt_value = opt->value;
int parse_opt_color_flag_cb(const struct option *opt, const char *arg,
	struct object_id oid;
			v = the_hash_algo->hexsz;
enum parse_opt_result parse_opt_unknown_cb(struct parse_opt_ctx_t *ctx,
