		} else {
	struct config_alias_data data = { alias, NULL };
}
			return git_config_string((const char **)&data->v,
	ALLOC_GROW(*argv, count + 1, size);
	}
char *alias_lookup(const char *alias)
	cmdline[dst] = 0;
						 key, value);


	ALLOC_ARRAY(*argv, size);

	if (!skip_prefix(key, "alias.", &p))
			if (c == '\\' && quoted != '\'') {
			src++;
struct config_alias_data {
		if (!strcasecmp(p, data->alias))
				if (!c) {
			}
#include "config.h"
#include "alias.h"
	return split_cmdline_errors[-split_cmdline_errno - 1];
		char c = cmdline[src];
	struct config_alias_data data = { NULL, NULL, list };
static const char *split_cmdline_errors[] = {
		return -SPLIT_CMDLINE_UNCLOSED_QUOTE;
#include "cache.h"

				src++;
	int src, dst, count = 0, size = 16;
	return 0;
int split_cmdline(char *cmdline, const char ***argv)
{
		} else if (!quoted && (c == '\'' || c == '"')) {
	read_early_config(config_alias_cb, &data);

			src++;

#include "string-list.h"
				; /* skip */

}
	const char *alias;
	char *v;
				c = cmdline[src];
	struct config_alias_data *data = d;
	(*argv)[count] = NULL;
	}
	return count;

}
void list_aliases(struct string_list *list)

	/* split alias_string */
#define SPLIT_CMDLINE_BAD_ENDING 1
{

}
	read_early_config(config_alias_cb, &data);
			src++;
			while (cmdline[++src]

			quoted = c;
const char *split_cmdline_strerror(int split_cmdline_errno)
static int config_alias_cb(const char *key, const char *value, void *d)
};
				}

					&& isspace(cmdline[src]))
		}
		if (!quoted && isspace(c)) {
	if (quoted) {
#define SPLIT_CMDLINE_UNCLOSED_QUOTE 2


	}
}
	if (data->alias) {


	const char *p;
{
			ALLOC_GROW(*argv, count + 1, size);
	(*argv)[count++] = cmdline;
{
};
			quoted = 0;
	return data.v;

	N_("cmdline ends with \\"),
		return 0;
					FREE_AND_NULL(*argv);
					return -SPLIT_CMDLINE_BAD_ENDING;
	N_("unclosed quote")

	for (src = dst = 0; cmdline[src];) {
			cmdline[dst++] = c;
		FREE_AND_NULL(*argv);

	char quoted = 0;
	} else if (data->list) {
{
			(*argv)[count++] = cmdline + dst;
		string_list_append(data->list, p);
			cmdline[dst++] = 0;
	struct string_list *list;
		} else if (c == quoted) {
