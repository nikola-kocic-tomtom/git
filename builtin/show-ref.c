 * (5) otherwise output the line.
			int reflen = buf + len - ref;
	if (show_head)
	if (!found_match) {
	char buf[1024];
			struct object_id oid;
	const char *hex;
			int len = strlen(m);
	   quiet, hash_only, abbrev, exclude_arg;
		die("git show-ref: bad ref %s (%s)", refname,
				goto match;
	if (!peel_ref(refname, &peeled)) {

}
			die("--verify requires a reference");
static int exclude_existing(const char *match)
	}
	OPT_BOOL(0, "verify", &verify, N_("stricter reference checking, "
	  PARSE_OPT_OPTARG | PARSE_OPT_NONEG, exclude_existing_callback },
{
			if ((starts_with(*pattern, "refs/") || !strcmp(*pattern, "HEAD")) &&
	if (pattern) {

	OPT_BOOL(0, "heads", &heads_only, N_("only show heads (can be combined with tags)")),
}
			if (len > reflen)
		int len = strlen(buf);
	string_list_insert(list, refname);

		if (!string_list_has_string(&existing_refs, ref)) {
		while ((m = *p++) != NULL) {
		printf("%s %s^{}\n", hex, refname);
 * and
}
	NULL
		}
#include "tag.h"

			else if (!quiet)
/*
	int matchlen = match ? strlen(match) : 0;

		match |= tags_only && starts_with(refname, "refs/tags/");
 * (1) strip "^{}" at the end of line if any;
	OPT_BOOL(0, "head", &show_head,
		head_ref(show_ref, NULL);
			warning("ref '%s' ignored", ref);
		return 0;
			buf[len] = '\0';
		goto match;

 * read "^(?:<anything>\s)?<refname>(?:\^\{\})?$" from the standard input,
int cmd_show_ref(int argc, const char **argv, const char *prefix)
				continue;
 * (3) warn if refname is not a well-formed refname and skip;
	/* Use full length SHA1 if no argument */
	BUG_ON_OPT_NEG(unset);


	  N_("pattern"), N_("show refs from stdin that aren't in local repository"),
	while (fgets(buf, sizeof(buf), stdin)) {
	  N_("only show SHA1 hash using <n> digits"),
			if (reflen < matchlen)
			printf("%s\n", buf);
	return parse_opt_abbrev_cb(opt, arg, unset);
	N_("git show-ref [-q | --quiet] [--verify] [--head] [-d | --dereference] [-s | --hash[=<n>]] [--abbrev[=<n>]] [--tags] [--heads] [--] [<pattern>...]"),
	if (hash_only)
static int deref_tags, show_head, tags_only, heads_only, found_match, verify,
		char *ref;
			if (len == reflen)
}
	static struct string_list existing_refs = STRING_LIST_INIT_DUP;
{
{
		if (!match)
	for_each_ref(show_ref, NULL);
		printf("%s\n", hex);
	if (!has_object_file(oid))
				break;

				goto match;
	OPT_BOOL(0, "tags", &tags_only, N_("only show tags (can be combined with heads)")),
		}
static int add_existing(const char *refname, const struct object_id *oid,
#include "config.h"
				continue;
			buf[--len] = '\0';
				continue;
	if (tags_only || heads_only) {
		if (match) {
#include "object.h"
#include "cache.h"
	hex = find_unique_abbrev(oid, abbrev);
		}


			}
	OPT_END()
		if (len > 0 && buf[len - 1] == '\n')
				     int unset)
	return 0;
	return 0;

	if (exclude_arg)

			int flag, void *cbdata)
 * (4) ignore if refname is a ref that exists in the local repository;
		if (!pattern)
	OPT__QUIET(&quiet,
		if (check_refname_format(ref, 0)) {
		match = heads_only && starts_with(refname, "refs/heads/");
			if (strncmp(ref, match, matchlen))

};
static int exclude_existing_callback(const struct option *opt, const char *arg,
			    !read_ref(*pattern, &oid)) {

				continue;
			len -= 3;
		    N_("dereference tags into object IDs")),
		while (*pattern) {
	  N_("show the HEAD reference, even if it would be filtered out")),
	{ OPTION_CALLBACK, 's', "hash", &abbrev, N_("n"),
		return exclude_existing(exclude_existing_arg);
	  PARSE_OPT_OPTARG, &hash_callback },
		int match;
	OPT_HIDDEN_BOOL('h', NULL, &show_head,
	struct object_id peeled;
	N_("git show-ref --exclude-existing[=<pattern>]"),
#include "string-list.h"
{
 */
		return 0;

		return;
#include "object-store.h"
}
	if (!arg)
{
		return 1;
	return 0;

	}

	if (!deref_tags)
		    oid_to_hex(oid));
			continue;
	if (verify) {


			else
	*(const char **)opt->value = arg;
	}
	show_one(refname, oid);
		pattern = NULL;
{
	if (show_head && !strcmp(refname, "HEAD"))
		const char **p = pattern, *m;
	if (quiet)

#include "builtin.h"
		}
	}
				show_one(*pattern, &oid);
static int show_ref(const char *refname, const struct object_id *oid,
	return 0;
		}
			if (memcmp(m, refname + reflen - len, len))
		printf("%s %s\n", hex, refname);
		}
		if (verify && !quiet)
			     show_ref_usage, 0);
	return 0;
#include "parse-options.h"
static const char **pattern;
	git_config(git_default_config, NULL);
				return 1;
static const char * const show_ref_usage[] = {
		return 0;
		for (ref = buf + len; buf < ref; ref--)

			if (isspace(ref[-1]))
static void show_one(const char *refname, const struct object_id *oid)
	else
			N_("show the HEAD reference, even if it would be filtered out")),
		   N_("do not print results to stdout (useful with --verify)")),
static const char *exclude_existing_arg;
	pattern = argv;
{
				die("'%s' - not a valid ref", *pattern);
		hex = find_unique_abbrev(&peeled, abbrev);

	}
 * (2) ignore if match is provided and does not head-match refname;
}
	{ OPTION_CALLBACK, 0, "exclude-existing", &exclude_existing_arg,
#include "refs.h"
	found_match++;
};
		    int flag, void *cbdata)
	hash_only = 1;

			if (refname[reflen - len - 1] == '/')
}
static const struct option show_ref_options[] = {
	OPT__ABBREV(&abbrev),
	if (!*pattern)
			return 0;
		    "requires exact ref path")),
		if (3 <= len && !strcmp(buf + len - 3, "^{}")) {
	exclude_arg = 1;
	}
	struct string_list *list = (struct string_list *)cbdata;
static int hash_callback(const struct option *opt, const char *arg, int unset)
		int reflen = strlen(refname);
	for_each_ref(add_existing, &existing_refs);

match:
	OPT_BOOL('d', "dereference", &deref_tags,


	argc = parse_options(argc, argv, prefix, show_ref_options,

			die("No match");
			pattern++;
		return;
