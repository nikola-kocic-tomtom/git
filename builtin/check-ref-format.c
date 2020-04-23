 */
	if (strbuf_check_branch_ref(&sb, arg) ||
	return 0;
	int nongit;




			normalize = 1;
	const char *name;
	const char *refname;
		usage(builtin_check_ref_format_usage);

	char ch;
 * of adjacent slashes replaced with single slashes.
	char *ret = xmallocz(strlen(refname));
{
	for (i = 1; i < argc && argv[i][0] == '-'; i++) {

		return 1;
#include "refs.h"
}
 * GIT - The information manager from hell
	return ret;
	    !skip_prefix(sb.buf, "refs/heads/", &name))

		if (prev == '/' && ch == prev)
{
	}
			flags &= ~REFNAME_ALLOW_ONELEVEL;
}
"   or: git check-ref-format --branch <branchname-shorthand>";
int cmd_check_ref_format(int argc, const char **argv, const char *prefix)
static int check_ref_format_branch(const char *arg)
#include "strbuf.h"
		if (!strcmp(argv[i], "--normalize") || !strcmp(argv[i], "--print"))
 * This function is similar to normalize_path_copy(), but stripped down
 *
	}
	refname = argv[i];
	return 0;
/*
 */
 * to meet check_ref_format's simpler needs.
		refname = collapse_slashes(refname);
		else if (!strcmp(argv[i], "--refspec-pattern"))
		else
	int i;
static const char builtin_check_ref_format_usage[] =
	if (normalize)
{
	char prev = '/';

		usage(builtin_check_ref_format_usage);
	int normalize = 0;
	if (! (i == argc - 1))
		*cp++ = ch;
	int flags = 0;
 * Return a copy of refname but with leading slashes removed and runs
"git check-ref-format [--normalize] [<options>] <refname>\n"
	char *cp = ret;
		return check_ref_format_branch(argv[2]);
	struct strbuf sb = STRBUF_INIT;
			usage(builtin_check_ref_format_usage);

		die("'%s' is not a valid branch name", arg);
	strbuf_release(&sb);
	if (argc == 3 && !strcmp(argv[1], "--branch"))
	*cp = '\0';
}
	while ((ch = *refname++) != '\0') {
	if (argc == 2 && !strcmp(argv[1], "-h"))
		printf("%s\n", refname);

		prev = ch;
static char *collapse_slashes(const char *refname)
			flags |= REFNAME_REFSPEC_PATTERN;
	if (check_refname_format(refname, flags))
	setup_git_directory_gently(&nongit);
	if (normalize)
			continue;
		else if (!strcmp(argv[i], "--no-allow-onelevel"))
	printf("%s\n", name);

			flags |= REFNAME_ALLOW_ONELEVEL;

/*

#include "builtin.h"
		else if (!strcmp(argv[i], "--allow-onelevel"))
#include "cache.h"
