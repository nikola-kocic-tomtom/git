	ref_array_clear(&array);
	};
};
	if (verify_ref_format(&format))
	struct ref_filter filter;
	if (maxcount < 0) {
	memset(&array, 0, sizeof(array));
	format.format = "%(objectname) %(objecttype)\t%(refname)";
		OPT_BOOL(0, "ignore-case", &icase, N_("sorting and filtering are case insensitive")),
		OPT_NO_CONTAINS(&filter.no_commit, N_("print only refs which don't contain the commit")),
	ref_array_sort(sorting, &array);
#include "cache.h"

	int i;
		OPT_BIT(0 , "tcl",  &format.quote_style,
			N_("quote placeholders suitably for Tcl"), QUOTE_TCL),

		OPT_INTEGER( 0 , "count", &maxcount, N_("show only <n> matched refs")),
	struct ref_array array;
		error("more than one quoting style?");
		show_ref_array_item(array.items[i], &format);

			N_("quote placeholders suitably for perl"), QUOTE_PERL),
	if (!maxcount || array.nr < maxcount)
	memset(&filter, 0, sizeof(filter));
	filter.ignore_case = icase;
		OPT_BIT('p', "perl",  &format.quote_style,
	N_("git for-each-ref [--points-at <object>]"),
	N_("git for-each-ref [--contains [<commit>]] [--no-contains [<commit>]]"),
	int maxcount = 0, icase = 0;
	struct ref_format format = REF_FORMAT_INIT;
	filter_refs(&array, &filter, FILTER_REFS_ALL | FILTER_REFS_INCLUDE_BROKEN);

	filter.match_as_path = 1;
		OPT_GROUP(""),
#include "builtin.h"
int cmd_for_each_ref(int argc, const char **argv, const char *prefix)
		error("invalid --count argument: `%d'", maxcount);
	filter.name_patterns = argv;
	if (!sorting)
	for (i = 0; i < maxcount; i++)
	struct ref_sorting *sorting = NULL, **sorting_tail = &sorting;
		OPT_MERGED(&filter, N_("print only refs that are merged")),
#include "config.h"
		usage_with_options(for_each_ref_usage, opts);
		OPT_END(),
	N_("git for-each-ref [(--merged | --no-merged) [<commit>]]"),
		OPT_NO_MERGED(&filter, N_("print only refs that are not merged")),
	struct option opts[] = {
	parse_options(argc, argv, prefix, opts, for_each_ref_usage, 0);
}
		maxcount = array.nr;

		OPT_CALLBACK(0, "points-at", &filter.points_at,

		usage_with_options(for_each_ref_usage, opts);
#include "refs.h"
			N_("quote placeholders suitably for shells"), QUOTE_SHELL),
{
	}
			     N_("object"), N_("print only refs which points at the given object"),
		OPT__COLOR(&format.use_color, N_("respect format colors")),
	sorting->ignore_case = icase;

	return 0;
	if (HAS_MULTI_BITS(format.quote_style)) {
			N_("quote placeholders suitably for python"), QUOTE_PYTHON),
		OPT_BIT(0 , "python", &format.quote_style,
	git_config(git_default_config, NULL);
			     parse_opt_object_name),

		OPT_STRING(  0 , "format", &format.format, N_("format"), N_("format to use for the output")),
		usage_with_options(for_each_ref_usage, opts);

	NULL
#include "object.h"

#include "parse-options.h"

static char const * const for_each_ref_usage[] = {
		OPT_CONTAINS(&filter.with_commit, N_("print only refs which contain the commit")),
		sorting = ref_default_sorting();
	}
	N_("git for-each-ref [<options>] [<pattern>]"),
		OPT_BIT('s', "shell", &format.quote_style,
#include "ref-filter.h"
		OPT_REF_SORT(sorting_tail),
