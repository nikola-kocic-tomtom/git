		setup_work_tree();
	check = attr_check_alloc();
	}

static void check_attr_stdin_paths(const char *prefix,
	if (stdin_paths) {
	/* Check file argument(s): */
	}
		else if (ATTR_UNSET(value))

		if (!nul_term_line && buf.buf[0] == '"') {
	} else {
			value = "unspecified";
	OPT_BOOL('z', NULL, &nul_term_line,
		prefix_path(prefix, prefix ? strlen(prefix) : 0, file);
		cnt = 0;
#include "cache.h"

	strbuf_getline_fn getline_fn;

		       int collect_all,

		check_attr(prefix, check, collect_all, buf.buf);

}
		}


	attr_check_free(check);
			/* Treat all arguments as attribute names. */
		} else {
			cnt = 1;
		filei = doubledash + 1;
			       "%s%c" /* attrvalue */,
#include "builtin.h"
	OPT_BOOL(0 , "stdin", &stdin_paths, N_("read file names from stdin")),
	if (collect_all) {
	argc = parse_options(argc, argv, prefix, check_attr_options,
		 N_("terminate input and output records by a NUL character")),
	}
		if (!argc)
N_("git check-attr [-a | --all | <attr>...] [--] <pathname>..."),
		if (nul_term_line) {

	while (getline_fn(&buf, stdin) != EOF) {
}
	if (!all_attrs) {
		} else {
	struct strbuf unquoted = STRBUF_INIT;
	} else if (doubledash < 0) {
			if (unquote_c_style(&unquoted, buf.buf, NULL))
		git_check_attr(&the_index, full_path, check);
			error_with_usage("Attributes and --all both specified");
	for (j = 0; j < cnt; j++) {

	free(full_path);
			filei = 1;
	struct attr_check *check;
			check_attr(prefix, check, all_attrs, argv[i]);
	if (all_attrs) {
#include "attr.h"
			       git_attr_name(check->items[j].attr), value);
	} else {
int cmd_check_attr(int argc, const char **argv, const char *prefix)
			error_with_usage("No file specified");
	/* Process --all and/or attribute arguments: */
		}
#include "config.h"
	int j;
static void check_attr(const char *prefix,


	git_config(git_default_config, NULL);


static void output_attr(struct attr_check *check, const char *file)
		cnt = doubledash;
};
	OPT_BOOL('a', "all", &all_attrs, N_("report all attributes set on file")),
			printf("%s%c" /* path */
		if (filei >= argc)
};
	strbuf_release(&buf);
		maybe_flush_or_die(stdout, "attribute to stdout");
}

			filei = argc;
			if (!a)
		if (doubledash >= 1)
{
static const struct option check_attr_options[] = {
	OPT_END()
	}
static int all_attrs;

{
{
		check_attr_stdin_paths(prefix, check, all_attrs);
	}
		if (!strcmp(argv[i], "--"))
	int cnt = check->nr;
static int stdin_paths;
	} else if (doubledash == 0) {
			       "%s%c" /* attrname */

N_("git check-attr --stdin [-z] [-a | --all | <attr>...]"),
	}
			strbuf_swap(&buf, &unquoted);
	for (i = 0; doubledash < 0 && i < argc; i++) {

					     argv[i]);

	output_attr(check, file);
				   int collect_all)
		die("invalid cache");
}

	return 0;
	OPT_BOOL(0,  "cached", &cached_attrs, N_("use .gitattributes only from the index")),
		git_all_attrs(&the_index, full_path, check);
			quote_c_style(file, NULL, stdout, 0);
	int cnt, i, doubledash, filei;
		if (ATTR_TRUE(value))
		const char *value = check->items[j].value;
}
{
		if (filei < argc)
		git_attr_set_direction(GIT_ATTR_INDEX);
			doubledash = i;

		for (i = filei; i < argc; i++)
{
	else {
	if (cached_attrs)
			error_with_usage("Can't specify files with --stdin");
		}
	if (read_cache() < 0) {
			     check_attr_usage, PARSE_OPT_KEEP_DASHDASH);
			attr_check_append(check, a);
		error_with_usage("No attribute specified");
		for (i = 0; i < cnt; i++) {
				   struct attr_check *check,
		if (stdin_paths) {
	error("%s", msg);
	usage_with_options(check_attr_usage, check_attr_options);
		else if (ATTR_FALSE(value))
	}
	if (stdin_paths)
	char *full_path =

			printf(": %s: %s\n",

static int nul_term_line;
	doubledash = -1;
				die("line is badly quoted");
#include "quote.h"
				return error("%s: not a valid attribute name",
			       git_attr_name(check->items[j].attr), 0, value, 0);

static const char * const check_attr_usage[] = {
			cnt = argc;

	} else {
static int cached_attrs;
		       struct attr_check *check,
		       const char *file)

		}
			       file, 0,
	}
	if (!is_bare_repository())
		maybe_flush_or_die(stdout, "attribute to stdout");
			const struct git_attr *a = git_attr(argv[i]);
	strbuf_release(&unquoted);
			error_with_usage("No attribute specified");
#include "parse-options.h"
			value = "set";
			/* Treat exactly one argument as an attribute name. */
#define USE_THE_INDEX_COMPATIBILITY_MACROS
NULL
	}
		filei = doubledash + 1;
static NORETURN void error_with_usage(const char *msg)

	getline_fn = nul_term_line ? strbuf_getline_nul : strbuf_getline_lf;

			strbuf_reset(&unquoted);
	struct strbuf buf = STRBUF_INIT;
			value = "unset";
