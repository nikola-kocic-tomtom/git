	new_trailers_clear(&trailers);
{
	NULL
		new_trailers_clear(trailers);
static int option_parse_trailer(const struct option *opt,
	if (argc) {
		OPT_BOOL(0, "no-divider", &opts.no_divider, N_("do not treat --- specially")),
	if (unset) {

	item->if_missing = if_missing;
			   int unset)
			PARSE_OPT_NOARG | PARSE_OPT_NONEG, parse_opt_parse },
	}
	return 0;
				   const char *arg, int unset)


		OPT_CALLBACK(0, "where", NULL, N_("action"),
			git_interpret_trailers_usage,
	return 0;
	git_config(git_default_config, NULL);
	return 0;
static int option_parse_if_exists(const struct option *opt,
	item->text = arg;

 * Copyright (c) 2013, 2014 Christian Couder <chriscool@tuxfamily.org>
static const char * const git_interpret_trailers_usage[] = {
			_("--trailer with --only-input does not make sense"),
#include "builtin.h"
			options);
		OPT_BOOL(0, "unfold", &opts.unfold, N_("join whitespace-continued values")),
				N_("trailer(s) to add"), option_parse_trailer),
}

static void new_trailers_clear(struct list_head *trailers)
static int parse_opt_parse(const struct option *opt, const char *arg,
		OPT_CALLBACK(0, "if-missing", NULL, N_("action"),
 * Builtin "git interpret-trailers"
	struct option options[] = {
#include "cache.h"

int cmd_interpret_trailers(int argc, const char **argv, const char *prefix)
		int i;
 */
	if (!arg)
	item->if_exists = if_exists;
			     git_interpret_trailers_usage, 0);
	}
	BUG_ON_OPT_NEG(unset);
 *
{
	struct new_trailer_item *item;
	if (opts.only_input && !list_empty(&trailers))
	return trailer_set_if_exists(&if_exists, arg);
static enum trailer_if_exists if_exists;
#include "string-list.h"


	struct process_trailer_options opts = PROCESS_TRAILER_OPTIONS_INIT;
	struct list_head *pos, *tmp;
	struct list_head *trailers = opt->value;
		item = list_entry(pos, struct new_trailer_item, list);
}
static int option_parse_if_missing(const struct option *opt,

	N_("git interpret-trailers [--in-place] [--trim-empty] [(--trailer <token>[(=|:)<value>])...] [<file>...]"),
			die(_("no input file given for in-place editing"));
/*
}

	struct new_trailer_item *item;
#include "config.h"
 *

		process_trailers(NULL, &opts, &trailers);
#include "trailer.h"
	list_add_tail(&item->list, trailers);
	v->only_input = 1;
		{ OPTION_CALLBACK, 0, "parse", &opts, NULL, N_("set parsing options"),
			process_trailers(argv[i], &opts, &trailers);
				   const char *arg, int unset)
	v->only_trailers = 1;
}
static int option_parse_where(const struct option *opt,
			      const char *arg, int unset)
{
	return trailer_set_if_missing(&if_missing, arg);



	}
		list_del(pos);
	};
		OPT_BOOL(0, "in-place", &opts.in_place, N_("edit files in place")),

static enum trailer_where where;
}
	item = xmalloc(sizeof(*item));
	list_for_each_safe(pos, tmp, trailers) {
	return trailer_set_where(&where, arg);


			     N_("action if trailer is missing"), option_parse_if_missing),
		OPT_CALLBACK(0, "trailer", &trailers, N_("trailer"),

{
}
		OPT_BOOL(0, "only-input", &opts.only_input, N_("do not apply config rules")),
#include "parse-options.h"
{
{
}
		return 0;
	item->where = where;
		if (opts.in_place)
		OPT_BOOL(0, "trim-empty", &opts.trim_empty, N_("trim empty trailers")),
			     N_("where to place the new trailer"), option_parse_where),
		return -1;


	argc = parse_options(argc, argv, prefix, options,
		OPT_BOOL(0, "only-trailers", &opts.only_trailers, N_("output only the trailers")),

			     N_("action if trailer already exists"), option_parse_if_exists),
	BUG_ON_OPT_ARG(arg);
	struct process_trailer_options *v = opt->value;
				  const char *arg, int unset)
	LIST_HEAD(trailers);
	} else {

{
		for (i = 0; i < argc; i++)
	v->unfold = 1;
		usage_msg_opt(
};
		OPT_END()
static enum trailer_if_missing if_missing;

		OPT_CALLBACK(0, "if-exists", NULL, N_("action"),
		free(item);
