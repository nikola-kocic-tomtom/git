	const char *varlist;
}
		struct strbuf *buf = *s;
static int tr2_cfg_count_patterns;
	}

		return tr2_cfg_count_patterns;


{
}
 */
	const char *file;
	tr2_cfg_count_patterns = 0;
{
	struct strbuf **s;
		return tr2_cfg_count_patterns;
	if (!envvar || !*envvar)
		strbuf_trim(*s);
	varlist = tr2_sysenv_get(TR2_SYSENV_ENV_VARS);
	tr2_cfg_loaded = 1;
	if (tr2_cfg_env_vars_loaded)
 */
	}
			trace2_def_param_fl(data->file, data->line, key, value);
static int tr2_cfg_loaded;
}
	return tr2_cfg_env_vars_count;
}
	tr2_cfg_env_vars = strbuf_split_buf(varlist, strlen(varlist), ',', -1);

	return 0;
		if (buf->len && buf->buf[buf->len - 1] == ',')
		strbuf_list_free(tr2_cfg_patterns);
	struct strbuf **s;
void tr2_cfg_free_patterns(void)
		strbuf_trim_trailing_newline(*s);
	for (s = tr2_cfg_env_vars; *s; s++) {
	tr2_cfg_loaded = 0;
static struct strbuf **tr2_cfg_env_vars;
	if (tr2_cfg_load_patterns() > 0)
}

		if (buf->len && buf->buf[buf->len - 1] == ',')
};

	envvar = tr2_sysenv_get(TR2_SYSENV_CFG_PARAM);
	struct tr2_cfg_data *data = (struct tr2_cfg_data *)d;
		if (wm == WM_MATCH) {

			return 0;
/*
		strbuf_list_free(tr2_cfg_env_vars);
		strbuf_trim_trailing_newline(*s);
		    const char *value)
		}

	for (s = tr2_cfg_env_vars; *s; s++) {
struct tr2_cfg_data {
}
	struct tr2_cfg_data data = { file, line };
	struct tr2_cfg_data data = { file, line };


	int line;
/*
void tr2_list_env_vars_fl(const char *file, int line)

static int tr2_cfg_load_patterns(void)

	tr2_cfg_env_vars_count = s - tr2_cfg_env_vars;
#include "config.h"


		return tr2_cfg_env_vars_count;
static int tr2_load_env_vars(void)
			strbuf_setlen(buf, buf->len - 1);
			strbuf_setlen(buf, buf->len - 1);
	struct strbuf **s;
		struct strbuf *buf = *s;
		strbuf_trim(*s);
 */
	if (!varlist || !*varlist)
#include "trace2/tr2_sysenv.h"

{
}

	tr2_cfg_patterns = strbuf_split_buf(envvar, strlen(envvar), ',', -1);

	tr2_cfg_env_vars_count = 0;
	if (tr2_cfg_env_vars)
#include "cache.h"


	}
/*

	if (tr2_load_env_vars() <= 0)
static int tr2_cfg_env_vars_loaded;

		read_early_config(tr2_cfg_cb, &data);
 * Parse a string containing a comma-delimited list of config keys
	struct strbuf **s;

	if (tr2_cfg_load_patterns() > 0)
	for (s = tr2_cfg_patterns; *s; s++) {

		tr2_cfg_cb(key, value, &data);
	const char *envvar;
 * See if the given config key matches any of our patterns of interest.
}
	}

		struct strbuf *buf = *s;

{
void tr2_cfg_free_env_vars(void)
	for (s = tr2_cfg_patterns; *s; s++) {
		struct strbuf *buf = *s;
static int tr2_cfg_cb(const char *key, const char *value, void *d)
		int wm = wildmatch(buf->buf, key, WM_CASEFOLD);

{
void tr2_cfg_list_config_fl(const char *file, int line)
 * Parse a string containing a comma-delimited list of environment variable
	if (tr2_cfg_patterns)
	return tr2_cfg_count_patterns;
{
	if (tr2_cfg_loaded)
{
static int tr2_cfg_env_vars_count;
#include "trace2/tr2_cfg.h"

		const char *val = getenv(buf->buf);
 * names into a list of strbufs.
	tr2_cfg_env_vars_loaded = 0;
{
	tr2_cfg_count_patterns = s - tr2_cfg_patterns;
		return tr2_cfg_env_vars_count;
 * or wildcard patterns into a list of strbufs.
void tr2_cfg_set_fl(const char *file, int line, const char *key,
static struct strbuf **tr2_cfg_patterns;
			trace2_def_param_fl(file, line, buf->buf, val);
		if (val && *val)
		return;
	tr2_cfg_env_vars_loaded = 1;
