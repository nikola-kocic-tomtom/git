
		BUG("tr2_sysenv_get invalid var '%d'", var);
		if (v && *v) {
	for (k = 0; k < ARRAY_SIZE(tr2_sysenv_settings); k++) {
	if (var >= TR2_SYSENV_MUST_BE_LAST)
struct tr2_sysenv_entry {
	[TR2_SYSENV_DST_DEBUG]     = { "GIT_TRACE2_DST_DEBUG",

		free(tr2_sysenv_settings[k].value);
	[TR2_SYSENV_PERF]          = { "GIT_TRACE2_PERF",
}
}
		if (!strcmp(key, tr2_sysenv_settings[k].git_config_name)) {
{
				       "trace2.configparams" },
	if (!starts_with(key, "trace2."))
 * The strings in this table are constant and must match the published
};
		const char *v = getenv(tr2_sysenv_settings[var].env_var_name);
 * Return a friendly name for this setting that is suitable for printing
		}

 * define the default values for Trace2 as requested by the administrator.
	if (ARRAY_SIZE(tr2_sysenv_settings) != TR2_SYSENV_MUST_BE_LAST)


/*
	[TR2_SYSENV_NORMAL]        = { "GIT_TRACE2",
 *

 */
	int k;
 * Then override with the Trace2 settings from the global config.
void tr2_sysenv_load(void)

	[TR2_SYSENV_MAX_FILES]     = { "GIT_TRACE2_MAX_FILES",
 */

	return 0;
				       "trace2.maxfiles" },
	}
 * variables because they are transient and used to pass information
 *

		BUG("tr2_sysenv_get invalid var '%d'", var);
 * This table must match "enum tr2_sysenv_variable" in tr2_sysenv.h.
 */
 * in an error messages.
/* clang-format on */
{
	char *value;

			tr2_sysenv_settings[k].value = xstrdup(value);
				       "trace2.normalbrief" },
static struct tr2_sysenv_entry tr2_sysenv_settings[] = {
	if (!tr2_sysenv_settings[var].getenv_called) {
void tr2_sysenv_release(void)
const char *tr2_sysenv_display_name(enum tr2_sysenv_variable var)
				       "trace2.perfbrief" },
	[TR2_SYSENV_ENV_VARS]      = { "GIT_TRACE2_ENV_VARS",
	read_very_early_config(tr2_sysenv_cb, NULL);
		BUG("tr2_sysenv_settings size is wrong");
	return tr2_sysenv_settings[var].env_var_name;
/* clang-format off */


			free(tr2_sysenv_settings[var].value);
	if (var >= TR2_SYSENV_MUST_BE_LAST)

#include "config.h"
	return tr2_sysenv_settings[var].value;
			free(tr2_sysenv_settings[k].value);
				       "trace2.eventtarget" },
 * config and environment variable names as described in the documentation.
 * Load Trace2 settings from the system config (usually "/etc/gitconfig"
	}
 */
		tr2_sysenv_settings[var].getenv_called = 1;
 * from parent to child git processes, rather than settings.
 * Return the value for the requested Trace2 setting from these sources:
#include "dir.h"

	const char *env_var_name;
 * Each entry represents a trace2 setting.
/*

		return 0;
/*
 * We do not define entries for the GIT_TRACE2_PARENT_* environment
		}
 *
 * unless we were built with a runtime-prefix).  These are intended to
	unsigned int getenv_called : 1;
 * the system config, the global config, and the environment.
/*
	[TR2_SYSENV_NORMAL_BRIEF]  = { "GIT_TRACE2_BRIEF",

				       "trace2.perftarget" },

}
	const char *git_config_name;
}
				       "trace2.eventbrief" },
	[TR2_SYSENV_PERF_BRIEF]    = { "GIT_TRACE2_PERF_BRIEF",
			tr2_sysenv_settings[var].value = xstrdup(v);
#include "tr2_sysenv.h"
				       "trace2.normaltarget" },
}

const char *tr2_sysenv_get(enum tr2_sysenv_variable var)
{
				       "trace2.envvars" },
#include "cache.h"
	[TR2_SYSENV_EVENT_BRIEF]   = { "GIT_TRACE2_EVENT_BRIEF",
/*
};
{

				       "trace2.destinationdebug" },
	for (k = 0; k < ARRAY_SIZE(tr2_sysenv_settings); k++)

 * See Documentation/technical/api-trace2.txt
{

 */
	[TR2_SYSENV_CFG_PARAM]     = { "GIT_TRACE2_CONFIG_PARAMS",
static int tr2_sysenv_cb(const char *key, const char *value, void *d)
	[TR2_SYSENV_EVENT]         = { "GIT_TRACE2_EVENT",
	[TR2_SYSENV_EVENT_NESTING] = { "GIT_TRACE2_EVENT_NESTING",
			return 0;
	int k;
				       "trace2.eventnesting" },
