
 *
 * Parses textual value for pull.rebase, branch.<name>.rebase, etc.
	if (!v)
 * Unrecognised value yields REBASE_INVALID, which traditionally is
 */
	int v = git_parse_maybe_bool(value);
 * The callers that care if (any) rebase is requested should say
	 * Please update _git_config() in git-completion.bash when you
 *
		return REBASE_TRUE;
enum rebase_type rebase_parse_value(const char *value)
	else if (!strcmp(value, "interactive") || !strcmp(value, "i"))
 * treated the same way as REBASE_FALSE.

		return REBASE_FALSE;
#include "config.h"

		return REBASE_MERGES;
 *   if (REBASE_TRUE <= rebase_parse_value(string))
/*
	else if (!strcmp(value, "preserve") || !strcmp(value, "p"))
#include "rebase.h"
 * false can do so by treating _INVALID and _FALSE differently.
{
	return REBASE_INVALID;
 * The callers that want to differenciate an unrecognised value and
	else if (v > 0)
}
		return REBASE_INTERACTIVE;
	else if (!strcmp(value, "merges") || !strcmp(value, "m"))
	 */
	 * add new rebase modes.
		return REBASE_PRESERVE;
	/*
