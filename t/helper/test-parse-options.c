
#include "test-tool.h"
static int number_callback(const struct option *opt, const char *arg, int unset)
	show(&expect, &ret, "boolean: %d", boolean);
		}
		OPT_BOOL(0, "yes", &boolean, "get a boolean"),

		{ OPTION_COUNTUP, '+', NULL, &boolean, NULL, "same as -b",
	show(&expect, &ret, "timestamp: %"PRItime, timestamp);
	item->util = (void *)arg;
			; /* not among entries being checked */
		OPT_GROUP("Alias"),
#include "cache.h"

		     (arg ? arg : "not set"), unset);

{
static int boolean = 0;
		OPT_MAGNITUDE('m', "magnitude", &magnitude, "get a magnitude"),
		OPT_STRING(0, "st", &string, "st", "get another string (pervert ordering)"),
	if (unset)
}
		OPT_END(),
}
		OPT_NOOP_NOARG(0, "obsolete"),
	const char *colon;
		OPT_SET_INT(0, "set23", &integer, "set integer to 23", 23),
				*status = 1;
		die("malformed --expect option");
		OPT_INTEGER('i', "integer", &integer, "get a integer"),
	return 0;
{
	else {
	strbuf_vaddf(&buf, fmt, args);
	struct option options[] = {
		  "negative ambiguity", PARSE_OPT_NOARG | PARSE_OPT_NONEG },
		  PARSE_OPT_NOARG | PARSE_OPT_NONEG | PARSE_OPT_NODASH },
	return ret;
			die("malformed output format, output lacking colon: %s", fmt);
		else {
static int collect_expect(const struct option *opt, const char *arg, int unset)
	BUG_ON_OPT_NEG(unset);
}
	return 0;
		show(&expect, &ret, "list: %s", list.items[i].string);
	length_cb.unset = unset;

static int dry_run = 0, quiet = 0;
		OPT_NEGBIT(0, "neg-or4", &boolean, "same as --no-or4", 4),
		OPT_STRING_LIST(0, "list", &list, "str", "add str to list"),

static void show(struct string_list *expect, int *status, const char *fmt, ...)
		OPT_BIT('4', "or4", &boolean,
	struct strbuf label = STRBUF_INIT;
		OPT_BOOL('D', "no-doubt", &boolean, "begins with 'no-'"),
		{ OPTION_COUNTUP, 0, "ambiguous", &ambiguous, NULL,


		  "positive ambiguity", PARSE_OPT_NOARG | PARSE_OPT_NONEG },
		if (!colon)
	struct string_list expect = STRING_LIST_INIT_NODUP;
		const char *arg = length_cb.arg;
int cmd__parse_options(int argc, const char **argv)
		OPT_CALLBACK(0, "expect", &expect, "string",
			     "expected output in the variable dump",
#include "parse-options.h"
	if (!arg || unset)
	expect = (struct string_list *)opt->value;
	};
		OPT__DRY_RUN(&dry_run, "dry run"),
		printf("%s\n", buf.buf);
	const char *prefix = "prefix/";
		OPT_STRING('o', NULL, &string, "str", "get another string"),

static char *file = NULL;
	for (i = 0; i < argc; i++)
}

static unsigned long magnitude = 0;
				printf("+%s\n", buf.buf);
		item = string_list_lookup(expect, buf.buf);
			     collect_expect),
		OPT_INTEGER('j', NULL, &integer, "get a integer, too"),
		int unset = length_cb.unset;
				printf("-%s\n", (char *)item->util);
	show(&expect, &ret, "quiet: %d", quiet);
		OPT__QUIET(&quiet, "be quiet"),
static timestamp_t timestamp;
			number_callback),
	strbuf_release(&buf);
	trace2_cmd_name("_parse_");
	const char *usage[] = {
	if (!expect->nr)
	show(&expect, &ret, "dry run: %s", dry_run ? "yes" : "no");
		OPT_CMDMODE(0, "mode2", &integer, "set integer to 2 (cmdmode option)", 2),
		OPT_STRING('s', "string", &string, "string", "get a string"),
	const char *arg;
		char *colon = strchr(buf.buf, ':');
	length_cb.arg = arg;
		OPT_COUNTUP('b', "boolean", &boolean, "increment by one"),
		OPT__ABBREV(&abbrev),
		"",
		OPT_GROUP("String options"),
		"A helper function for the parse-options API.",
#include "string-list.h"
	struct string_list *expect;
static struct {
	struct strbuf buf = STRBUF_INIT;
			"get length of <str>", length_callback),

{
		  "be brave", PARSE_OPT_NOARG | PARSE_OPT_NONEG, NULL, 1 },
	colon = strchr(arg, ':');
	show(&expect, &ret, "magnitude: %lu", magnitude);
			}
	show(&expect, &ret, "file: %s", file ? file : "(not set)");
	return 0;
	int unset;
static int ambiguous;
{
		show(&expect, &ret, "Callback: \"%s\", %d",
	va_list args;
		OPT_STRING('A', "alias-source", &string, "string", "get a string"),
	};
	show(&expect, &ret, "string: %s", string ? string : "(not set)");
static int abbrev = 7;
	va_start(args, fmt);
	int called;
		OPT_ALIAS('Z', "alias-target", "alias-source"),
	*(int *)opt->value = strtol(arg, NULL, 10);
	int ret = 0;
		OPT_CMDMODE(0, "mode1", &integer, "set integer to 1 (cmdmode option)", 1),
			if (strcmp((const char *)item->util, buf.buf)) {
	item = string_list_insert(expect, strbuf_detach(&label, NULL));
	struct string_list_item *item;
static int integer = 0;
static char *string = NULL;
	show(&expect, &ret, "verbose: %d", verbose);
		OPT_GROUP(""),
		OPT_GROUP("Magic arguments"),
	strbuf_add(&label, arg, colon - arg);
	show(&expect, &ret, "integer: %d", integer);
		die("malformed --expect option, lacking a colon");
#include "trace2.h"
		NULL
			"bitwise-or boolean with ...0100", 4),
	for (i = 0; i < list.nr; i++)
		"test-tool parse-options <options>",
}
static struct string_list list = STRING_LIST_INIT_NODUP;
	if (length_cb.called) {

{
	show(&expect, &ret, "abbrev: %d", abbrev);

__attribute__((format (printf,3,4)))



		{ OPTION_COUNTUP, 0, "no-ambiguous", &ambiguous, NULL,

	}
	struct string_list_item *item;
	int i;
		show(&expect, &ret, "arg %02d: %s", i, argv[i]);
		OPT__VERBOSE(&verbose, "be verbose"),

	va_end(args);
	argc = parse_options(argc, (const char **)argv, prefix, options, usage, 0);
	if (item->util)
		return 1; /* do not support unset */
		OPT_ARGUMENT("quux", NULL, "means --quux"),
		*colon = ':';
		OPT_GROUP("Standard options"),
	if (!colon)
		OPT_NUMBER_CALLBACK(&integer, "set integer to NUM",
} length_cb;
	*(int *)opt->value = strlen(arg);
		*colon = '\0';
		if (!item)
		OPT_CALLBACK('L', "length", &integer, "str",
	}

static int length_callback(const struct option *opt, const char *arg, int unset)
static int verbose = -1; /* unspecified */
	length_cb.called = 1;
		OPT_FILENAME('F', "file", &file, "set file to <file>"),
		OPT_STRING(0, "string2", &string, "str", "get another string"),
		die("malformed --expect option, duplicate %s", label.buf);
		{ OPTION_SET_INT, 'B', "no-fear", &boolean, NULL,
