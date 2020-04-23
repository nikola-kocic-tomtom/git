	{ "GIT_PAGER", pager },
	{ "GIT_EDITOR", editor },
int cmd_var(int argc, const char **argv, const char *prefix)
	else
	if (value)

	if (!pgm && flag & IDENT_STRICT)

	return pgm;
	return git_default_config(var, value, cb);
	const char *(*read)(int);
	{ "GIT_AUTHOR_IDENT",   git_author_info },
	if (!pgm)
	const char *val = NULL;
	struct git_var *ptr;
	const char *pgm = git_editor();
{
		if (strcmp(var, ptr->name) == 0) {
	return pgm;
 * GIT - The information manager from hell
static const char *read_var(const char *var)
	const char *val;


}
	{ "", NULL },

	git_config(git_default_config, NULL);
		}
		printf("%s\n", var);
#include "builtin.h"
}
	val = NULL;
	printf("%s\n", val);
};
	for (ptr = git_vars; ptr->read; ptr++) {
{

	for (ptr = git_vars; ptr->read; ptr++)
}
		usage(var_usage);
	struct git_var *ptr;
{
	const char *val;
		printf("%s=%s\n", var, value);
 * Copyright (C) Eric Biederman, 2005
			val = ptr->read(IDENT_STRICT);
	val = read_var(argv[1]);


			printf("%s=%s\n", ptr->name, val);
static struct git_var git_vars[] = {
		if ((val = ptr->read(0)))
	return val;
	return 0;
/*
	const char *pgm = git_pager(1);

	if (argc != 2)
static const char var_usage[] = "git var (-l | <variable>)";
	}
		list_vars();
};
		usage(var_usage);
struct git_var {
{
	const char *name;
static int show_config(const char *var, const char *value, void *cb)
		return 0;

		die("Terminal is dumb, but EDITOR unset");
#include "config.h"

	{ "GIT_COMMITTER_IDENT", git_committer_info },
}
{
			break;
	}

		git_config(show_config, NULL);

 *
 */
static const char *pager(int flag)
	if (strcmp(argv[1], "-l") == 0) {
static const char *editor(int flag)
	if (!val)

static void list_vars(void)
		pgm = "cat";
}

}
{
