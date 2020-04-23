		!strncasecmp("woman", name, len) ||
static const char *get_man_viewer_info(const char *name)
			return 0;
	struct child_process ec_process = CHILD_PROCESS_INIT;
			size_t len;
		strbuf_addstr(&new_path, old_path);
	switch (help_format) {
static int exclude_guides;
	}
			return viewer->info;
	OPT_HIDDEN_BOOL(0, "exclude-guides", &exclude_guides, N_("exclude guides")),
}
{
	for (viewer = man_viewer_info_list; viewer; viewer = viewer->next)
		exec_man_konqueror(info, page);
		strbuf_release(&buffer);
				path = xstrfmt("%.*s/kfmclient", (int)len, path);
 */
		do_add_man_viewer_info(name, len, value);
	if (!strcmp(var, "man.viewer")) {
		return cmd;
#include "run-command.h"
{
{
#include "alias.h"
			  "Please consider using 'man.<tool>.path' instead."),

			name);
			return config_error_nonbool(var);
	}
		return 0;
			list_all_cmds_help();
	struct strbuf new_path = STRBUF_INIT;
		!strncasecmp("konqueror", name, len));
	parsed_help_format = help_format;
	OPT_SET_INT('m', "man", &help_format, N_("show man page"), HELP_FORMAT_MAN),
}
		strbuf_release(&man_page);
	 * system-wide paths after ours to find the manual page. If
}

	 * there is old_path, we need ':' as delimiter. */
	if (supported_man_viewer(name, len))
}
		load_command_list("git-", &main_cmds, &other_cmds);
}
	}
	get_html_page_path(&page_path, page);
			version);
static struct man_viewer_list {

	finish_command(&ec_process);

	ec_process.stdout_to_stderr = 1;
{
/*
}
	struct man_viewer_list *next;
	if (is_git_command(cmd))
			printf_ln(_("'%s' is aliased to '%s'"), cmd, alias);

	}
	struct man_viewer_info_list *viewer;
	for (viewer = man_viewer_list; viewer; viewer = viewer->next)
		return alias;
static int show_guides = 0;
	if (starts_with(var, "column."))
			       size_t len,
		 * "git help cmd". In the latter case, or if cmd is an
	setup_git_directory_gently(&nongit);
	new_man_viewer->info = xstrdup(value);
	while (*p)
		warning_errno(_("failed to exec '%s'"), path);
{
	case HELP_FORMAT_WEB:
			    split_cmdline_strerror(count));
{
	load_command_list("git-", &main_cmds, &other_cmds);
	const char *page = cmd_to_page(git_cmd);
static void show_man_page(const char *git_cmd)
		struct strbuf man_page = STRBUF_INIT;

		fprintf_ln(stderr, _("'%s' is aliased to '%s'"), cmd, alias);
			return config_error_nonbool(var);
		git_config(git_help_config, NULL);
static const char * const builtin_help_usage[] = {
static void get_html_page_path(struct strbuf *page_path, const char *page)
		return git_column_config(var, value, "help", &colopts);
	exec_viewer("man", page);

		if (!for_human) {


	}
		show_info_page(argv[0]);
	strbuf_addf(page_path, "%s/%s.html", html_path, page);
		return 0;
	struct strbuf page_path; /* it leaks but we exec bellow */
};
	if (!path)
	if (!strcmp(subkey, "cmd")) {
	strbuf_addf(&shell_cmd, "%s %s", cmd, page);
		    || !S_ISREG(st.st_mode))

#include "parse-options.h"
		if (count < 0)
static const char *html_path;
	man_viewer_info_list = new_man_viewer;
}
static void show_html_page(const char *git_cmd)
		execlp(path, "emacsclient", "-e", man_page.buf, (char *)NULL);
	FLEX_ALLOC_STR(*p, name, name);
	argv[0] = check_git_cmd(argv[0]);
	else
			setup_pager();
		exec_man_cmd(info, page);
	execlp("info", "info", "gitman", page, (char *)NULL);

static int add_man_viewer_cmd(const char *name,
static struct man_viewer_info_list {
	ec_process.argv = argv_ec;
			return config_error_nonbool(var);
			path = "emacsclient";
		return HELP_FORMAT_WEB;
	if (display && *display) {
	struct man_viewer_list *viewer;
	strbuf_release(&shell_cmd);

	if (!strcmp(subkey, "path")) {
	HELP_FORMAT_WEB

		execlp(path, filename, "newTab", man_page.buf, (char *)NULL);
	close(ec_process.err);

		return HELP_FORMAT_INFO;
	}
	{
	if (old_path)
			list_config_help(for_human);

	return 0;
		list_config_help(for_human);
		return xstrfmt("git%s", git_cmd);
		help_format = parse_help_format(value);
		is_in_cmdlist(&other_cmds, s);
	setup_man_path();
		free(argv);
}
	char *to_free = NULL;
		return error(_("Failed to parse emacsclient version."));


	const char *display = getenv("DISPLAY");
		if (!path)

		 * Otherwise, we pretend that the command was "git
		break;
	{
{
	enum help_format parsed_help_format;
			filename = basename((char *)path);
} *man_viewer_info_list;
		list_common_cmds_help();
		list_common_guides_help();
}
		return git_cmd;
	/*
{

		 * exclude_guides to distinguish "git cmd --help" from
		} else
		p = &((*p)->next);
	if (parsed_help_format != HELP_FORMAT_NONE)
	}
	if (!check_emacsclient_version()) {
	strbuf_init(page_path, 0);
	else
enum help_format {
{
	OPT_END(),
static int check_emacsclient_version(void)
		add_man_viewer(value);
	 */
	else if (starts_with(git_cmd, "git"))
	strbuf_release(&buffer);
static void open_html(const char *path)
		}
		/*
	if (!strstr(html_path, "://")) {
			die("'%s': not a documentation directory.", html_path);
	OPT_BOOL('a', "all", &show_all, N_("print all available commands")),
	}


			return config_error_nonbool(var);
	}
	if (!argv[0]) {
		return "git";
		if (!exclude_guides || alias[0] == '!') {
	}
		return HELP_FORMAT_MAN;
}

	OPT_SET_INT_F(0, "config-for-completion", &show_config, "", 2, PARSE_OPT_HIDDEN),


	return 0;
	N_("git help [--all] [--guides] [--man | --web | --info] [<command>]"),
		warning(_("'%s': cmd for supported man viewer.\n"
	/* We should always put ':' after our path. If there is no
	NULL
} *man_viewer_list;
			free(alias);
	}
	if (!html_path)
	OPT_BOOL('g', "guides", &show_guides, N_("print list of useful guides")),
	if (show_config) {
	const char *fallback = getenv("GIT_MAN_VIEWER");
	}
#include "config.h"
static void exec_man_konqueror(const char *path, const char *page)
	open_html(page_path.buf);

	execlp(path, "man", page, (char *)NULL);
{
static int show_all = 0;

	char *git_man_path = system_path(GIT_MAN_PATH);

	}
	else if (info)

}
			if (strip_suffix(path, "/konqueror", &len))
		break;
	 * Please update _git_config() in git-completion.bash when you


	setenv("INFOPATH", system_path(GIT_INFO_PATH), 1);
	free(git_man_path);
static int git_help_config(const char *var, const char *value, void *cb)

	if (show_all) {
			die(_("bad alias.%s string: %s"), cmd,
		break;
{
}
		}
	die(_("no info viewer handled the request"));
	else
}
{
		if (verbose) {

		 */
	else if (!strcasecmp(name, "konqueror"))
	if (show_all || show_guides) {

		if (!value)
	if (start_command(&ec_process))
		html_path = to_free = system_path(GIT_HTML_PATH);
	warning_errno(_("failed to exec '%s'"), path);
		return add_man_viewer_info(var, value);
		 * word0 --help". We use split_cmdline() to get the

		return 0;
static const char *cmd_to_page(const char *git_cmd)
			HELP_FORMAT_WEB),
		path = "man";
		warning(_("'%s': path for unsupported man viewer.\n"
	if (!strcmp(format, "info"))

	git_config(git_help_config, NULL);
	if (starts_with(var, "man."))
	OPT__VERBOSE(&verbose, N_("print command description")),

	HELP_FORMAT_INFO,
	if (!strcmp(var, "help.htmlpath")) {
	}
	die(_("unrecognized help format '%s'"), format);
	argc = parse_options(argc, argv, prefix, builtin_help_options,

		printf("%s\n", _(git_more_info_string));
static void exec_man_man(const char *path, const char *page)
	struct strbuf buffer = STRBUF_INIT;
	execl_git_cmd("web--browse", "-c", "help.browser", path, (char *)NULL);
	return git_default_config(var, value, cb);
		* We're done. Ignore any remaining args
{
		if (!value)
	const char *info = get_man_viewer_info(name);
{
	return 0;
	strbuf_read(&buffer, ec_process.err, 20);
	die(_("no man viewer handled the request"));
static struct cmdnames main_cmds, other_cmds;
#include "exec-cmd.h"
int cmd_help(int argc, const char **argv, const char *prefix)
		strbuf_release(&man_page);

		setup_pager();
	else if (is_git_command(git_cmd))
			return config_error_nonbool(var);
static int supported_man_viewer(const char *name, size_t len)
{

			name);
{
	if (!strcasecmp(name, "man"))
	return 0;
			      const char *value)
	else
		printf("\n%s\n", _("'git help config' for more information"));
		*/
		return error(_("Failed to start emacsclient."));

		 * handle_builtin() in git.c rewrites "git cmd --help"
	OPT_SET_INT('i', "info", &help_format, N_("show info page"),
	if (alias) {
		struct strbuf man_page = STRBUF_INIT;
static enum help_format parse_help_format(const char *format)
		help_format = parsed_help_format;
		return 0;

		return error(_("emacsclient version '%d' too old (< 22)."),
			HELP_FORMAT_INFO),
	if (version < 22) {

	const char *name, *subkey;
		strbuf_release(&buffer);
}
		count = split_cmdline(alias, &argv);
	case HELP_FORMAT_INFO:
	}
	new_man_viewer->next = man_viewer_info_list;
			       const char *value)
		exec_man_man(info, page);
		return add_man_viewer_path(name, namelen, value);
		strbuf_addf(&man_page, "(woman \"%s\")", page);
{


		return add_man_viewer_cmd(name, namelen, value);
}
	strbuf_addch(&new_path, ':');
	if (!git_cmd)
};

	return is_in_cmdlist(&main_cmds, s) ||



		exec_viewer(viewer->name, page); /* will return when unable */
	struct stat st;
	 * add new help formats.
	const char *info;
			exit(0);
#include "help.h"
static int add_man_viewer_info(const char *var, const char *value)
	}
			builtin_help_usage, 0);

static enum help_format help_format = HELP_FORMAT_NONE;
	/*
}
}
#ifndef DEFAULT_HELP_FORMAT
		if (stat(mkpath("%s/git.html", html_path), &st)
		printf(_("usage: %s%s"), _(git_usage_string), "\n\n");
			  "Please consider using 'man.<tool>.cmd' instead."),
	strbuf_addstr(&new_path, git_man_path);

}
{
static void add_man_viewer(const char *name)
	int namelen;
	free(to_free);
		return 0;
	if (show_guides)
	if (!strcmp(format, "man"))

		exec_viewer(fallback, page);

		exec_woman_emacs(info, page);
		printf("\n%s\n", _(git_more_info_string));
}
		warning_errno(_("failed to exec '%s'"), path);

static const char *check_git_cmd(const char* cmd)
	 * Don't bother checking return value, because "emacsclient --version"



};
static void exec_woman_emacs(const char *path, const char *page)


	FLEX_ALLOC_MEM(new_man_viewer, name, name, len);
				   const char *value)
	if (supported_man_viewer(name, len))
		 */
		const char *filename = "kfmclient";
	const char *page = cmd_to_page(git_cmd);
	struct strbuf shell_cmd = STRBUF_INIT;
		return 0;
	if (!strcmp(format, "web") || !strcmp(format, "html"))
		return 0;
	return cmd;
}
	return 0;

	 * seems to always exits with code 1.
			return 0;
	alias = alias_lookup(cmd);
}

	int version;
	char *alias;
	struct man_viewer_info_list *next;
{
	const char *page = cmd_to_page(git_cmd);
static void exec_viewer(const char *name, const char *page)
	 */
	if (is_builtin(s))
	warning(_("failed to exec '%s'"), cmd);
	strbuf_remove(&buffer, 0, strlen("emacsclient"));
		}
	ec_process.err = -1;

static void setup_man_path(void)

	/* Check that we have a git documentation directory. */
		/* This works only with emacsclient version >= 22. */
		show_man_page(argv[0]);
			      size_t len,
	/* emacsclient prints its version number on stderr */
		printf(_("usage: %s%s"), _(git_usage_string), "\n\n");
		html_path = xstrdup(value);
static int is_git_command(const char *s)

		list_commands(colopts, &main_cmds, &other_cmds);
		warning(_("'%s': unknown man viewer."), name);
{
			path = "kfmclient";
{

static void exec_man_cmd(const char *cmd, const char *page)
{
		int for_human = show_config == 1;


		 * same rules as when the alias is actually

		if (!value)
		if (!strcasecmp(name, viewer->name))
}
		show_html_page(argv[0]);
	}
	version = atoi(buffer.buf);
		const char **argv;
		return xstrfmt("git-%s", git_cmd);

}
	if (!strcmp(var, "help.format")) {

static int verbose = 1;
	strbuf_release(&new_path);
{
#define DEFAULT_HELP_FORMAT "man"

	struct man_viewer_list **p = &man_viewer_list;

		help_format = parse_help_format(DEFAULT_HELP_FORMAT);
		 * first word of the alias, to ensure that we use the
	if (parse_config_key(var, "man", &name, &namelen, &subkey) < 0 || !name)
		UNLEAK(alias);
		if (path) {
	if (help_format == HELP_FORMAT_NONE)
	struct man_viewer_info_list *new_man_viewer;
	int nongit;
		/* It's simpler to launch konqueror using kfmclient. */
	char name[FLEX_ARRAY];
	if (exclude_guides)
		if (!value)
	 * old_path, the ':' at the end will let 'man' to try
	OPT_BOOL('c', "config", &show_config, N_("print all configuration variable names")),
	HELP_FORMAT_MAN,
	}
}
static void show_info_page(const char *git_cmd)
{
		return help_unknown_cmd(cmd);
	return (!strncasecmp("man", name, len) ||
	case HELP_FORMAT_MAN:

				   size_t len,
		strbuf_addf(&man_page, "man:%s(1)", page);
		 * alias for a shell command, just print the alias
#include "cache.h"
	OPT_SET_INT('w', "web", &help_format, N_("show manual in web browser"),
static int show_config;

 * Builtin help command
		do_add_man_viewer_info(name, len, value);
	HELP_FORMAT_NONE,

static int add_man_viewer_path(const char *name,
#include "column.h"
	else if (!strcasecmp(name, "woman"))
	if (fallback)
		 * definition.
}
	char name[FLEX_ARRAY];
	const char *argv_ec[] = { "emacsclient", "--version", NULL };
	execl(SHELL_PATH, SHELL_PATH, "-c", shell_cmd.buf, (char *)NULL);
static unsigned int colopts;
static void do_add_man_viewer_info(const char *name,
	if (!starts_with(buffer.buf, "emacsclient")) {
	case HELP_FORMAT_NONE:
		/*
	return NULL;
		int count;
static struct option builtin_help_options[] = {
	setenv("MANPATH", new_path.buf, 1);
		return 1;
#endif

#include "builtin.h"
		 * used. split_cmdline() modifies alias in-place.
	const char *old_path = getenv("MANPATH");
		 * to "git help --exclude-guides cmd", so we can use

		/*
		if (!value)

{

