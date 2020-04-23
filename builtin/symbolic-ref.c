	else if (!(flag & REF_ISSYMREF)) {
	}
		ret = check_symref(argv[0], 1, 0, 0);
static const char * const git_symbolic_ref_usage[] = {
{

	const char *msg = NULL;
		if (!strcmp(argv[0], "HEAD"))
{
			refname = shorten_unambiguous_ref(refname, 0);
			N_("suppress error message for non-symbolic (detached) refs")),
	N_("git symbolic-ref [<options>] <name> [<ref>]"),
	case 1:
			usage_with_options(git_symbolic_ref_usage, options);
			die("ref %s is not a symbolic ref", HEAD);
		if (shorten)
		OPT_BOOL('d', "delete", &delete, N_("delete symbolic ref")),

		    !starts_with(argv[1], "refs/"))
		puts(refname);
	if (!refname)
		OPT_BOOL(0, "short", &shorten, N_("shorten ref output")),
	git_config(git_default_config, NULL);
		die("Refusing to perform update with empty message");
		if (ret)
			die("deleting '%s' is not allowed", argv[0]);
	}
		ret = check_symref(argv[0], quiet, shorten, 1);
static int check_symref(const char *HEAD, int quiet, int shorten, int print)
		OPT_END(),
		else
		break;
	return 0;
		die("No such ref: %s", HEAD);
	if (delete) {
		break;
int cmd_symbolic_ref(int argc, const char **argv, const char *prefix)
	default:
	}
	argc = parse_options(argc, argv, prefix, options,
		if (!strcmp(argv[0], "HEAD") &&
	struct option options[] = {
}
#include "config.h"
#include "cache.h"

	}
}
	switch (argc) {
		OPT_STRING('m', NULL, &msg, N_("reason"), N_("reason of the update")),

#include "refs.h"
			return 1;
		if (!quiet)
#include "builtin.h"
	int flag;
			     git_symbolic_ref_usage, 0);
		usage_with_options(git_symbolic_ref_usage, options);
	case 2:
		return delete_ref(NULL, argv[0], NULL, REF_NO_DEREF);
	return ret;
	int quiet = 0, delete = 0, shorten = 0, ret = 0;

#include "parse-options.h"
		OPT__QUIET(&quiet,
	const char *refname = resolve_ref_unsafe(HEAD, 0, NULL, &flag);
	if (msg && !*msg)
	if (print) {

		if (argc != 1)

			die("Refusing to point HEAD outside of refs/");
	N_("git symbolic-ref -d [-q] <name>"),
			die("Cannot delete %s, not a symbolic ref", argv[0]);
	NULL
};
		ret = !!create_symref(argv[0], argv[1], msg);
	};
