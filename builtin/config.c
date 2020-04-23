	if (get_colorbool_found < 0) {
	to_type = opt->value;
	ret = !values.nr;
	else if (actions == ACTION_ADD) {
	{ OPTION_CALLBACK, (s), (l), (v), NULL, (h), PARSE_OPT_NOARG | \

			error(_("invalid key pattern: %s"), key_);
		 * This allows for combinations like '--int --type=int' and
		      "#	name = %s\n"
#include "color.h"
	get_colorbool_found = -1;
							      argv[0], value, argv[2], 1);
{

		else if (!strcmp(arg, "path"))
		given_config_source.scope = CONFIG_SCOPE_COMMAND;
	}

		 * Also don't do normalization for expiry dates.
#define TYPE_COLOR		6
				git_pathdup("config");
		}
	return ret;
		else if (!strcmp(arg, "bool-or-int"))
static struct git_config_source given_config_source;
		if (!is_bool)

			      "section in \"git help worktree\" for details"));
		if (git_config_parse_key(key_, &key, NULL)) {
			config_error_nonbool(var);
		if (type == TYPE_INT)
	int i;
static const char *const builtin_config_usage[] = {
	}
	}
	if (min == max)
			strbuf_addstr(buf, v);
				strbuf_addstr(buf, v ? "true" : "false");
		return git_config_set_multivar_in_file_gently(given_config_source.file,
	OPT_GROUP(N_("Other")),
static int show_scope;
		}
		format_config(&buf, item->string,
static regex_t *key_regexp;
#define ACTION_REMOVE_SECTION (1<<8)
{
			free(xdg_config);
	usage_with_options(builtin_config_usage, builtin_config_options);

		die(_("not in a git directory"));
		char *tl;
		    ident_default_email());
static char key_delim = ' ';
#define OPT_CALLBACK_VALUE(s, l, v, h, i) \
	} else if (use_worktree_config) {

	if (given_config_source.blob && nongit)
{
		check_write();
	if (*to_type && *to_type != new_type) {

		    xdg_config && !access_or_warn(xdg_config, R_OK, 0)) {
static void check_argc(int argc, int min, int max)
	else if (actions == ACTION_GET) {
		} else if (type == TYPE_EXPIRY_DATE) {
static int show_origin;
		return ret;
		check_argc(argc, 1, 2);
	const char term = end_nul ? '\0' : '\t';
		free(config_file);
				      "true" : "false");
		die("%s", config.url.err);
	}
		}
	struct strbuf value;
	}
		given_config_source.file = NULL;
	if (use_global_config + use_system_config + use_local_config +

		UNLEAK(value);
	}

}
};

		if (regcomp(regexp, regex_, REG_EXTENDED)) {
	strbuf_init(&values->items[values->nr], 0);
	if (regexp != NULL &&
		item = &values.items[values.nr++];
	OPT_BOOL(0, "local", &use_local_config, N_("use repository config file")),

}
		return 0;

static NORETURN void usage_builtin_config(void)
}
}

		    _("# This is Git's per-user configuration file.\n"
			ret = CONFIG_INVALID_PATTERN;
	OPT_BIT(0, "rename-section", &actions, N_("rename section: old-name new-name"), ACTION_RENAME_SECTION),
		check_argc(argc, 0, 0);
		for (tl = key; *tl && *tl != '.'; tl++)
	usage_builtin_config();
	OPT_BIT(0, "get-all", &actions, N_("get all values: key [value-regex]"), ACTION_GET_ALL),
		usage_builtin_config();
		strbuf_reset(&matched->value);
							      argv[0], value,
			return git_config_set_multivar_in_file_gently(given_config_source.file,
	else if (actions == ACTION_GET_COLORBOOL) {
	if (regexp) {

	if (!use_key_regexp && strcmp(key_, key))
#define TYPE_BOOL		1
		UNLEAK(value);
	struct strbuf *items;
		else if (type == TYPE_BOOL_OR_INT) {
	}
#define ACTION_GET_ALL (1<<1)
	int nr;
		 * We don't do normalization for TYPE_PATH here: If
		if (ret == 0)
	OPT_GROUP(N_("Type")),
	int ret;
	if (regex_) {
			     builtin_config_usage,
	OPT_BIT(0, "get-colorbool", &actions, N_("find the color setting: slot [stdout-is-tty]"), ACTION_GET_COLORBOOL),
	else if (actions == ACTION_GET_REGEXP) {
			 * is set and points at a sane location.
static struct option builtin_config_options[] = {
		fwrite(buf.buf, 1, buf.len, stdout);
static int get_color_found;
free_strings:
		return 0;
#define PAGING_ACTIONS (ACTION_LIST | ACTION_GET_ALL | \

				return -1;
	OPT_STRING(0, "blob", &given_config_source.blob, N_("blob-id"), N_("read config from given blob object")),
		return git_config_set_multivar_in_file_gently(given_config_source.file,
	free(values.items);
static int do_all;

		regfree(regexp);

		if (!user_config)
			      "extension worktreeConfig is enabled. "
	struct string_list_item *item;
		if (color_parse(value, parsed_color) < 0)
	OPT_END(),

			die(_("failed to format default config value: %s"),
		if (git_config_color(v, key, value))
		get_color(argv[0], argv[1]);
		if (show_origin)
	if (actions == 0)
	else if (actions == ACTION_GET_ALL) {
	if (!given_config_source.file && !startup_info->have_repository)
#define ACTION_GET (1<<0)
	int new_type, *to_type;
			strbuf_addf(buf, "%"PRItime, t);
		show_keys = 1;
	return strbuf_detach(&buf, NULL);
	if (default_value && !(actions & ACTION_GET)) {
		do_all = 1;

	}
	}
		 * sequence, not suitable for including within a
	}

#define ACTION_ADD (1<<4)
#define TYPE_INT		2

			int is_bool, v;
		      "# Please adapt and uncomment the following lines:\n"
			die(_("editing stdin is not supported"));
		given_config_source.file = git_pathdup("config");
	get_colorbool_found = want_color(get_colorbool_found);
	if (show_origin || show_scope) {
	    !(actions == ACTION_LIST || actions == ACTION_GET_REGEXP)) {
#define ACTION_REPLACE_ALL (1<<3)
{
		struct strbuf buf = STRBUF_INIT;
		error(_("wrong number of arguments, should be %d"), min);
	return format_config(&values->items[values->nr++], key_, value_);
static char *default_value;
	if (actions == ACTION_LIST) {

	section_tail = strchr(config.section, '.');
	}
		/*
	if (use_local_config && nongit)
		given_config_source.file = git_etc_gitconfig();
	get_color_ui_found = -1;
			timestamp_t t;
		strbuf_release(&matched->value);
		if (given_config_source.blob)
	config_with_options(urlmatch_config_entry, &config,
#include "worktree.h"
		else
	int ret = CONFIG_GENERIC_ERROR;

	strbuf_addstr(buf, N_(scope));


	parsed_color[0] = '\0';
		regfree(key_regexp);
static void check_write(void)


		error(_("--get-color and variable type are incoherent"));
		check_argc(argc, 2, 2);
			return xstrdup(v ? "true" : "false");
	OPT_BOOL(0, "worktree", &use_worktree_config, N_("use per-worktree config file")),
			    &given_config_source, &config_options);
		 * "sanity-check", and return the given value, which we
	OPT_BIT(0, "remove-section", &actions, N_("remove a section: name"), ACTION_REMOVE_SECTION),
		if (ret == CONFIG_NOTHING_SET)
		return get_urlmatch(argv[0], argv[1]);
	} else
	string_list_clear(&values, 1);
static struct config_options config_options;
		*section_tail = '\0';
	config.cascade_fn = NULL;
		int ret;
			regex_++;
	else
			"--get-regexp, and --list"));
		else
		item->util = matched;
		config_options.respect_includes = !given_config_source.file;
{
#define ACTION_EDIT (1<<10)
	config.cb = &values;
	}
static int get_urlmatch(const char *var, const char *url)
}
		default:
	}
				return -1;
	}
		check_argc(argc, 2, 3);

		do_all = 1;
			 * It is unknown if HOME/.gitconfig exists, so
	}
	OPT_BOOL(0, "show-origin", &show_origin, N_("show origin of config (file, standard input, blob, command line)")),
	if (!matched) {
		char *config_file;
	struct urlmatch_current_candidate_value *matched = item->util;
{
		return;
		show_keys = 0;
	else if (actions == ACTION_GET_COLOR) {
	if (!strcmp(var, get_colorbool_slot))
static int get_color_ui_found;
		    ident_default_name(),
		error(_("--show-origin is only applicable to --get, --get-all, "
		check_argc(argc, 1, 2);
	argc = parse_options(argc, argv, prefix, builtin_config_options,
		 * when retrieving the value.
		value = normalize_value(argv[0], argv[1]);
	char *value;
static void show_config_origin(struct strbuf *buf)
	struct strbuf_list values = {NULL};
	if (type == 0 || type == TYPE_PATH || type == TYPE_EXPIRY_DATE)
{
/*

	OPT_BIT('e', "edit", &actions, N_("open an editor"), ACTION_EDIT),
		if (given_config_source.use_stdin)
		if (repository_format_worktree_config)
	OPT_GROUP(N_("Config file location")),
		case 2: actions = ACTION_SET; break;

	if (type == TYPE_BOOL_OR_INT) {
		 * NEEDSWORK: this naive pattern lowercasing obviously does not
		 */
		free_worktrees(worktrees);
		if (!strcmp(arg, "bool"))
		(ACTION_GET|ACTION_GET_ALL|ACTION_GET_REGEXP|ACTION_LIST))) {
		if (argc == 2)
			goto free_strings;

			if (show_keys)
			      "working trees unless the config\n"
				die_errno(_("unable to read config file '%s'"),
		}
		if (!value)
		regexp = (regex_t*)xmalloc(sizeof(regex_t));
			if (git_config_color(v, key_, value_) < 0)
		} else if (type == TYPE_PATH) {
			strbuf_addstr(buf, git_config_bool(key_, value_) ?

	    (do_not_match ^ !!regexec(regexp, (value_?value_:""), 0, NULL, 0)))
		check_argc(argc, 2, 2);
		error(_("only one config file at a time"));
				close(fd);
		 * The contents of `v` now contain an ANSI escape

	OPT_BOOL('z', "null", &end_nul, N_("terminate values with NUL byte")),
	if (given_config_source.file &&
		get_colorbool_found = GIT_COLOR_AUTO;
		 * --type=int'.
	}
		die(_("writing config blobs is not supported"));
	const char term = end_nul ? '\0' : '\t';
		return 0;
		UNLEAK(value);
	const char *scope = config_scope_name(current_config_scope());
		return git_config_set_multivar_in_file_gently(given_config_source.file,
	}
		if (use_global_config) {
{
		check_argc(argc, 2, 2);
			/*
static int use_worktree_config;
		if (regex_[0] == '!') {
	} else {
	OPT_BOOL(0, "system", &use_system_config, N_("use system config file")),
#define ACTION_GET_COLOR (1<<13)
	struct strbuf buf = STRBUF_INIT;
static int format_config(struct strbuf *buf, const char *key_, const char *value_)
			given_config_source.file = user_config;
		 * '--type=int --type=int', but disallows ones like '--type=bool
		if (color_parse(def_color, parsed_color) < 0)
		strbuf_addstr(buf, key_);
	if (get_colorbool_found < 0)
	if (show_origin && !(actions &
				free(content);
		else
			FREE_AND_NULL(key_regexp);

#include "cache.h"
static regex_t *regexp;
#define ACTION_GET_COLORBOOL (1<<14)
		return 0;
}

	OPT_CALLBACK_VALUE(0, "bool-or-int", &type, N_("value is --bool or --int"), TYPE_BOOL_OR_INT),
	return 0;
		if (config_with_options(show_all_config, NULL,
	if (argc >= min && argc <= max)



#define ACTION_GET_REGEXP (1<<2)
	free((void *)config.section);
	char *section_tail;
	if (end_nul)
		ret = git_config_set_in_file_gently(given_config_source.file, argv[0], value);
	OPT_BIT(0, "replace-all", &actions, N_("replace all matching variables: name value [value_regex]"), ACTION_REPLACE_ALL),
	int alloc;
		error(_("wrong number of arguments, should be from %d to %d"),
}
			die(_("not in a git directory"));

		free(key_regexp);
#include "builtin.h"

		get_color_found = 1;
		if (get_colorbool_found < 0)
	struct strbuf_list *values = cb;
				strbuf_addf(buf, "%d", v);
		struct worktree **worktrees = get_worktrees(0);
static char *normalize_value(const char *key, const char *value)

static int use_global_config, use_system_config, use_local_config;

		 */
							argv[0], argv[1]);
	if (given_config_source.use_stdin)
			     PARSE_OPT_STOP_AT_NON_OPTION);

		die(_("writing to stdin is not supported"));
							      argv[0], value, argv[2], 0);
		*((int *) opt->value) = 0;
		quote_c_style(current_config_name(), buf, NULL, 0);
			    &given_config_source, &config_options);
	if (!strcmp(var, get_color_slot)) {
		strbuf_addstr(buf, current_config_name());
		else if (worktrees[0] && worktrees[1])
		check_argc(argc, 2, 2);
		return 0;
		given_config_source.use_stdin = 1;
		term = '\0';
}
	OPT_BOOL(0, "name-only", &omit_values, N_("show variable names only")),
		if (show_keys)
#define TYPE_PATH		4
			ret = CONFIG_INVALID_PATTERN;
	OPT_BIT(0, "get-urlmatch", &actions, N_("get value specific for the URL: section[.var] URL"), ACTION_GET_URLMATCH),
			error(_("invalid pattern: %s"), regex_);
		ret = git_config_rename_section_in_file(given_config_source.file,
static char term = '\n';
		char *xdg_config = xdg_config_home("config");
			return ret;
		config_options.respect_includes = respect_includes_opt;
	OPT_BOOL(0, "includes", &respect_includes_opt, N_("respect include directives on lookup")),
	}
	else if (actions == ACTION_EDIT) {
			"       Use a regexp, --add or --replace-all to change %s."), argv[0]);
	}
			      matched->value_is_null ? NULL : matched->value.buf);

	}
		config.key = NULL;
#define ACTION_UNSET (1<<5)
		}
		/* default value if none found in config */
			}
			new_type = TYPE_BOOL;
	BUG("cannot normalize type %d", type);
		show_keys = 1;
		key_regexp = (regex_t*)xmalloc(sizeof(regex_t));
	get_diff_color_found = -1;
static int git_get_colorbool_config(const char *var, const char *value,
	struct string_list *values = cb;
		show_config_scope(buf);
	else if (actions == ACTION_UNSET) {
static int get_value(const char *key_, const char *regex_)
			get_colorbool_found = get_color_ui_found;
		char *user_config = expand_user_path("~/.gitconfig", 0);
		fwrite(buf.buf, 1, buf.len, stdout);

		given_config_source.scope = CONFIG_SCOPE_COMMAND;
			die(_("$HOME not set"));
		matched->value_is_null = 0;
			int fd = open(config_file, O_CREAT | O_EXCL | O_WRONLY, 0666);
	OPT_BIT(0, "get-color", &actions, N_("find the color configured: slot [default]"), ACTION_GET_COLOR),
		die(_("--local can only be used inside a git repository"));
		check_argc(argc, 1, 2);
	}
	OPT_GROUP(N_("Action")),
		check_argc(argc, 1, 1);
			!strcmp(given_config_source.file, "-")) {
			new_type = TYPE_BOOL_OR_INT;
struct urlmatch_current_candidate_value {
	if (respect_includes_opt == -1)
		return get_value(argv[0], argv[1]);
	}
		check_write();
		case 3: actions = ACTION_SET_ALL; break;
		}
	else if (actions == ACTION_RENAME_SECTION) {

		if (argc == 2)
{

		/*
	struct string_list_item *item = string_list_insert(values, var);
			ACTION_GET_REGEXP | ACTION_GET_URLMATCH)
		config_options.commondir = get_git_common_dir();
	}
			die(_("no such section: %s"), argv[0]);
		check_write();
			show_config_scope(&buf);
	OPT_CALLBACK('t', "type", &type, "", N_("value is given this type"), option_parse_type),
		check_write();
		printf("%s\n", get_colorbool_found ? "true" : "false");
static int option_parse_type(const struct option *opt, const char *arg,
	if (!get_color_found && def_color) {
	fputs(parsed_color, stdout);
	if (use_global_config) {
	strbuf_addch(buf, term);
			given_config_source.file =
	    use_worktree_config +
}
		}
	if (key_regexp) {
		launch_editor(config_file, NULL, NULL);
		void *cb)
	new_type = opt->defval;
		given_config_source.scope = CONFIG_SCOPE_SYSTEM;
	}
		strbuf_release(buf);
		return git_config_set_multivar_in_file_gently(given_config_source.file,
							      CONFIG_REGEX_NONE, 0);
	} else if (given_config_source.blob) {

		 */
static int omit_values;
		v = git_config_bool_or_int(key, value, &is_bool);

	ALLOC_GROW(values->items, values->nr + 1, values->alloc);
	given_config_source.file = xstrdup_or_null(getenv(CONFIG_ENVIRONMENT));
	return 0;
			die(_("cannot parse color '%s'"), value);
{
{
			free(user_config);
				write_str_in_full(fd, content);

			free((char *)v);
	if (!value)
#include "quote.h"
	OPT_BIT('l', "list", &actions, N_("list all"), ACTION_LIST),
			*tl = tolower(*tl);
	}
	if (!values.nr && default_value) {
		value = normalize_value(argv[0], argv[1]);
		     tl--)
			ret = CONFIG_INVALID_KEY;
			return xstrfmt("%d", v);

	}
static char parsed_color[COLOR_MAXLEN];
	}
{

		/*

		use_key_regexp = 1;
		int ret;
			error(_("cannot overwrite multiple values with a single value\n"

};
	strbuf_addf(&buf,

static int urlmatch_collect_fn(const char *var, const char *value, void *cb)
	strbuf_addch(buf, term);
#define TYPE_EXPIRY_DATE	5
		if (ret < 0)

static int get_colorbool(const char *var, int print)
		get_color_ui_found = git_config_colorbool(var, value);
	}
				die_errno(_("cannot create configuration file %s"), config_file);
	if (show_scope)
	config.section = xstrdup_tolower(var);
				prefix_filename(prefix, given_config_source.file);
	strbuf_addch(buf, term);
	}
			     int unset)
		return get_value(argv[0], argv[1]);
	return 0;
			if (given_config_source.file)

				strbuf_setlen(buf, buf->len - 1);
	OPT_BIT(0, "unset-all", &actions, N_("remove all matches: name [value-regex]"), ACTION_UNSET_ALL),
	else if (actions == ACTION_SET) {
			die(_("no such section: %s"), argv[0]);
			 */
	}
			do_not_match = 1;
	}
			new_type = TYPE_INT;
	ret = !values.nr;
	OPT_BIT(0, "get-regexp", &actions, N_("get values for regexp: name-regex [value-regex]"), ACTION_GET_REGEXP),
		 * Complain when there is a new type not equal to the old type.
							      argv[0], NULL, argv[1], 1);
		return NULL;
		struct urlmatch_current_candidate_value *matched = item->util;
		if (access_or_warn(user_config, R_OK, 0) &&
		usage_builtin_config();
		check_argc(argc, 2, 3);

	N_("git config [<options>]"),
	if (!url_normalize(url, &config.url))
		int ret;
	}
static int collect_config(const char *key_, const char *value_, void *cb)
static int do_not_match;
	} else if (use_local_config) {
			else if (errno != EEXIST)
	if (use_key_regexp && regexec(key_regexp, key_, 0, NULL, 0))
	} else {
					&config_options) < 0) {

	return 0;
		return xstrdup(value);
	get_color_found = 0;
		git_config(git_default_config, NULL);
	struct urlmatch_config config = { STRING_LIST_INIT_DUP };
	if (type == TYPE_INT)
	if (use_key_regexp) {
}
			    &given_config_source, &config_options);



			strbuf_addf(buf, "%"PRId64,
			given_config_source.file = xdg_config;
}
	if (print) {
			if (git_config_expiry_date(&t, key_, value_) < 0)
		error(_("--default is only applicable to --get"));
	OPT_BOOL(0, "show-scope", &show_scope, N_("show scope of config (worktree, local, global, system, command)")),
	}
#include "parse-options.h"
	return 0;
#define TYPE_BOOL_OR_INT	3

			else
		value = normalize_value(argv[0], argv[1]);
	if (!omit_values) {
			goto free_strings;


	if (HAS_MULTI_BITS(actions)) {
		check_write();
								      argv[0], NULL, argv[1], 0);

static int get_colorbool_found;
			color_stdout_is_tty = git_config_bool("command line", argv[1]);
			char v[COLOR_MAXLEN];
	else if (actions == ACTION_REPLACE_ALL) {
	return ret;
		 * --int' and '--type=bool
	}
};
	int nongit = !startup_info->have_repository;
 * one line of output and which should therefore be paged.
			 * we do not know if we should write to XDG
		for (tl = key + strlen(key) - 1;
				char *content = default_user_config();
static void get_color(const char *var, const char *def_color)
	}
	if (type == TYPE_COLOR) {
		if (do_all || i == values.nr - 1)
	if (type == TYPE_BOOL)
			die(_("unrecognized --type argument, %s"), arg);

		given_config_source.scope = CONFIG_SCOPE_GLOBAL;
	else
static char delim = '=';
	free(config.url.url);
	if (omit_values &&
	}

				return -1;
		switch (argc) {
		UNLEAK(value);
			if (git_config_pathname(&v, key_, value_) < 0)
	if (section_tail) {
		config_file = given_config_source.file ?
		check_write();
		value = normalize_value(argv[0], argv[1]);
				    git_config_int64(key_, value_ ? value_ : ""));
}
		if (ret < 0)
		check_argc(argc, 1, 2);

		strbuf_release(&buf);

		config_options.git_dir = get_git_dir();
			new_type = TYPE_COLOR;
		/*
	if (actions & PAGING_ACTIONS)
	strbuf_addstr(buf, current_config_origin_type());
	OPT_BIT(0, "get", &actions, N_("get value: name [value-regex]"), ACTION_GET),
		else if (!strcmp(arg, "int"))
		usage_builtin_config();
	OPT_STRING(0, "default", &default_value, N_("value"), N_("with --get, use default value when missing entry")),
		 * Perhaps we should deprecate this altogether someday.
	if (value) {
{
		 * work for more complex patterns like "^[^.]*Foo.*bar".
	 * To support '--<type>' style flags, begin with new_type equal to
static const char *get_color_slot;

				die(_("error processing config file(s)"));
		else if (type == TYPE_BOOL)
		key = xstrdup(key_);
	for_each_string_list_item(item, &values) {
		error(_("--name-only is only applicable to --list or --get-regexp"));
			die(_("--worktree cannot be used with multiple "
	struct string_list values = STRING_LIST_INIT_DUP;
#define ACTION_UNSET_ALL (1<<6)
		return xstrdup(value);

		error(_("only one action at a time"));
		die(_("--blob can only be used inside a git repository"));
		usage_builtin_config();
		if (!given_config_source.file && nongit)
		char v[COLOR_MAXLEN];
		delim = '\n';
{
		struct strbuf buf = STRBUF_INIT;
{
#define ACTION_RENAME_SECTION (1<<7)
		get_diff_color_found = git_config_colorbool(var, value);
			die(_("editing blobs is not supported"));
		 * the path is like ~/foobar/, we prefer to store
		printf("%s%c%s%c", key_, delim, value_, term);

		error(_("only one type at a time"));
int cmd_config(int argc, const char **argv, const char *prefix)
}
		} else {
{
		      "[user]\n"
	} else {
		given_config_source.scope = CONFIG_SCOPE_LOCAL;
			if (is_bool)

			else
		return xstrfmt("%"PRId64, git_config_int64(key, value));
			/* Just show the key name; back out delimiter */
	OPT_CALLBACK_VALUE(0, "expiry-date", &type, N_("value is an expiry date"), TYPE_EXPIRY_DATE),
		/* Use fwrite as "buf" can contain \0's if "end_null" is set. */

static int get_diff_color_found;
	 * opt->defval.
}
			return ret;
{
	get_color_slot = var;
		strbuf_addstr(&matched->value, value);
	}
		usage_builtin_config();
	}
		given_config_source.scope = CONFIG_SCOPE_COMMAND;

	string_list_clear(&config.vars, 1);
		printf("%s%c", key_, term);

		if (ret == 0)
			usage_builtin_config();
	if (show_origin)
		} else if (type == TYPE_COLOR) {
		 * "~/foobar/" in the config file, and to expand the ~
#define ACTION_SET_ALL (1<<12)
		struct strbuf *item;
	NULL
	config_with_options(git_get_colorbool_config, NULL,
					  given_config_source.file);
			goto free_strings;
};
	return 0;
			FREE_AND_NULL(regexp);
		return get_value(argv[0], argv[1]);
		check_argc(argc, 1, 2);
	if (show_keys)
	if ((actions & (ACTION_GET_COLOR|ACTION_GET_COLORBOOL)) && type) {
		return get_colorbool(argv[0], argc == 2);
		if (format_config(item, key_, default_value) < 0)
		given_config_source.scope = CONFIG_SCOPE_LOCAL;
			*tl = tolower(*tl);
		matched = xmalloc(sizeof(*matched));

		matched->value_is_null = 1;
				xstrdup(given_config_source.file) :
static const char *get_colorbool_slot;
	get_colorbool_slot = var;


		free(regexp);
	}

static int end_nul;
		}
		} else {
	}
	OPT_BIT(0, "unset", &actions, N_("remove a variable: name [value-regex]"), ACTION_UNSET),


			if (fd >= 0) {
		     tl >= key && *tl != '.';
	config_with_options(git_get_color_config, NULL,
		get_colorbool_found = git_config_colorbool(var, value);
	strbuf_addch(buf, ':');

		usage_builtin_config();

		key_delim = '\n';
			new_type = TYPE_EXPIRY_DATE;
	}
	PARSE_OPT_NONEG, option_parse_type, (i) }
}
		}
			v = git_config_bool_or_int(key_, value_, &is_bool);
static void show_config_scope(struct strbuf *buf)

		else if (!strcmp(arg, "color"))
		if (!is_absolute_path(given_config_source.file) && prefix)
			const char *v;
	}
	config_with_options(collect_config, &values,
		int is_bool, v;
	} else {
		else if (!strcmp(arg, "expiry-date"))
	for (i = 0; i < values.nr; i++) {
#include "config.h"
	else if (use_system_config) {
							     argv[0], NULL);

	else if (actions == ACTION_UNSET_ALL) {
			new_type = TYPE_PATH;
	if (!omit_values && value_)
							argv[0], NULL);
		show_config_origin(buf);
static int git_get_color_config(const char *var, const char *value, void *cb)
	char value_is_null;

	    !!given_config_source.file + !!given_config_source.blob > 1) {
		ret = git_config_rename_section_in_file(given_config_source.file,
static int use_key_regexp;
		strbuf_init(&matched->value, 0);
	else
	}
			 * location; error out even if XDG_CONFIG_HOME
		 * configuration file. Treat the above as a
		if (regcomp(key_regexp, key, REG_EXTENDED)) {
		check_argc(argc, 1, 2);
	if (end_nul) {
		 */

			fwrite(buf->buf, 1, buf->len, stdout);
	if (!nongit) {
		} else if (value_) {
static int show_all_config(const char *key_, const char *value_, void *cb)
		struct strbuf *buf = values.items + i;
	else
			given_config_source.file = git_pathdup("config");
	*to_type = new_type;
	return 0;
		check_write();
		if (show_scope)

	free(key);
			return -1;
	OPT_CALLBACK_VALUE(0, "path", &type, N_("value is a path (file or directory name)"), TYPE_PATH),
			die(_("unable to parse default color value"));
}
static int actions, type;
	else if (actions == ACTION_REMOVE_SECTION) {
#define ACTION_SET (1<<11)

		      "#	email = %s\n"),

#define ACTION_LIST (1<<9)
	config.collect_fn = urlmatch_collect_fn;
		check_argc(argc, 1, 2);
				default_value);
		usage_builtin_config();
		case 1: actions = ACTION_GET; break;
					&given_config_source,
	}
		check_write();
static char *default_user_config(void)

	else if (actions == ACTION_SET_ALL) {
		check_argc(argc, 0, 0);
static int show_keys;
		config.key = section_tail + 1;
}
static char *key;
		 * know is representable as valid color code.
		return get_colorbool_found ? 0 : 1;
	OPT_CALLBACK_VALUE(0, "int", &type, N_("value is decimal number"), TYPE_INT),
	if (given_config_source.blob)
			show_config_origin(&buf);
			strbuf_addstr(buf, v);
	}
		if (!strcmp(get_colorbool_slot, "color.diff"))
	if (unset) {
	OPT_BOOL(0, "global", &use_global_config, N_("use global config file")),
			return git_config_set_in_file_gently(given_config_source.file,
	else if (actions == ACTION_GET_URLMATCH) {
			given_config_source.file = git_pathdup("config.worktree");
	/*
			      "Please read \"CONFIGURATION FILE\"\n"
	if (!new_type) {
static int respect_includes_opt = -1;
			strbuf_addch(buf, key_delim);
	OPT_CALLBACK_VALUE(0, "bool", &type, N_("value is \"true\" or \"false\""), TYPE_BOOL),
		ALLOC_GROW(values.items, values.nr + 1, values.alloc);
		else
}
		return xstrdup(git_config_bool(key, value) ?  "true" : "false");
{
	else if (!strcmp(var, "diff.color"))
			strbuf_addstr(buf, value_);
}
		      min, max);

#define ACTION_GET_URLMATCH (1<<15)
	else if (!strcmp(var, "color.ui"))

 */
	}
#include "urlmatch.h"
	} else if (given_config_source.file) {
{

	}
	OPT_BIT(0, "add", &actions, N_("add a new variable: name value"), ACTION_ADD),
			get_colorbool_found = get_diff_color_found;
	 */
struct strbuf_list {
		setup_auto_pager("config", 1);
		strbuf_init(item, 0);
	OPT_STRING('f', "file", &given_config_source.file, N_("file"), N_("use given config file")),
			    &given_config_source, &config_options);
		strbuf_release(&buf);
static NORETURN void usage_builtin_config(void);
 * The actions "ACTION_LIST | ACTION_GET_*" which may produce more than
