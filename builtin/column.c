		command = argv[1] + 10;
		OPT_END()
		OPT_STRING(0, "command", &real_command, N_("name"), N_("lookup config vars")),
	/* This one is special and must be the first one */
#include "parse-options.h"
	};
		OPT_COLUMN(0, "mode", &colopts, N_("layout to use")),
	return 0;
		OPT_INTEGER(0, "padding", &copts.padding, N_("Padding space between columns")),

int cmd_column(int argc, const char **argv, const char *prefix)
		OPT_INTEGER(0, "nl", &copts.nl, N_("Padding space on right border")),
		git_config(column_config, (void *)command);
}
#include "strbuf.h"
	N_("git column [<options>]"),
	return git_column_config(var, value, cb, &colopts);

	argc = parse_options(argc, argv, prefix, options, builtin_column_usage, 0);
		OPT_INTEGER(0, "width", &copts.width, N_("Maximum width")),
	struct strbuf sb = STRBUF_INIT;
	struct column_options copts;
static int column_config(const char *var, const char *value, void *cb)
		usage_with_options(builtin_column_usage, options);
	const char *command = NULL, *real_command = NULL;
	}
	NULL
	print_columns(&list, colopts, &copts);
		string_list_append(&list, sb.buf);
		git_config(column_config, NULL);

	memset(&copts, 0, sizeof(copts));
		if (!real_command || !command || strcmp(real_command, command))
{
	copts.padding = 1;
#include "column.h"
		OPT_INTEGER(0, "raw-mode", &colopts, N_("layout to use")),

	if (real_command || command) {

#include "builtin.h"
	struct option options[] = {
static unsigned int colopts;
	if (argc > 1 && starts_with(argv[1], "--command=")) {
#include "cache.h"
	finalize_colopts(&colopts, -1);
#include "config.h"
{
}
	struct string_list list = STRING_LIST_INIT_DUP;
	} else
	while (!strbuf_getline(&sb, stdin))
#include "string-list.h"
	if (argc)
static const char * const builtin_column_usage[] = {

		OPT_STRING(0, "indent", &copts.indent, N_("string"), N_("Padding space on left border")),
			die(_("--command must be the first argument"));
};
