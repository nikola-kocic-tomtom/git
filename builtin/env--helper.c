	N_("git env--helper --type=[bool|ulong] <options> <env-var>"),
	case ENV_HELPER_TYPE_BOOL:
	else if (!strcmp(arg, "ulong"))
}
			puts(ret_int ? "true" : "false");
			printf("%lu\n", ret_ulong);
#include "config.h"
		if (!exit_code)
			default_int = git_parse_maybe_bool(env_default);
	}
#include "builtin.h"

		OPT_STRING(0, "default", &env_default, N_("value"),
} cmdmode = 0;
	if (argc != 1)
	case ENV_HELPER_TYPE_ULONG:
	const char *env_variable = NULL;
	return 0;

		if (env_default) {
	ENV_HELPER_TYPE_BOOL = 1,
		break;
				      env_default);
		cmdmode = ENV_HELPER_TYPE_BOOL;
	const char *env_default = NULL;
			       option_parse_type),
{
}
	int exit_code = 0;
static char const * const env__helper_usage[] = {
			     int unset)

		break;
				usage_with_options(env__helper_usage, opts);
				error(_("option `--default' expects an unsigned long value with `--type=ulong`, not `%s`"),
int cmd_env__helper(int argc, const char **argv, const char *prefix)
};
{
		} else {
#include "parse-options.h"
			     PARSE_OPT_KEEP_UNKNOWN);
		break;
			default_ulong = 0;
		ret = ret_int;
	NULL
	default:
			}
		OPT_BOOL(0, "exit-code", &exit_code,
		ret = ret_ulong;


		}
		usage_with_options(env__helper_usage, opts);
		BUG("unknown <type> value");
		OPT_END(),
	};

	argc = parse_options(argc, argv, prefix, opts, env__helper_usage,
		usage_with_options(env__helper_usage, opts);
	else
		if (!exit_code)
			       N_("value is given this type"), PARSE_OPT_NONEG,
	switch (cmdmode) {
			if (!git_parse_ulong(env_default, &default_ulong)) {

		die(_("unrecognized --type argument, %s"), arg);
static int option_parse_type(const struct option *opt, const char *arg,
				usage_with_options(env__helper_usage, opts);
			   N_("default for git_env_*(...) to fall back on")),
	struct option opts[] = {
	if (!strcmp(arg, "bool"))
	int ret_int, default_int;

			 N_("be quiet only use git_env_*() value as exit code")),
				      env_default);
		} else {
		}
	env_variable = argv[0];
	ENV_HELPER_TYPE_ULONG
				error(_("option `--default' expects a boolean value with `--type=bool`, not `%s`"),
			default_int = 0;
		ret_ulong = git_env_ulong(env_variable, default_ulong);
	return !ret;
static enum {
		cmdmode = ENV_HELPER_TYPE_ULONG;
	int ret;
	unsigned long ret_ulong, default_ulong;
		if (env_default) {
	if (!cmdmode)
		ret_int = git_env_bool(env_variable, default_int);
			if (default_int == -1) {
		usage_with_options(env__helper_usage, opts);
	if (env_default && !*env_default)
			}
		OPT_CALLBACK_F(0, "type", &cmdmode, N_("type"),
