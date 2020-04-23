	argc = parse_options(argc, argv, prefix, options, ls_remote_usage,
			   PARSE_OPT_HIDDEN },
			   N_("path of git-upload-pack on the remote host"),
	   "                     [-q | --quiet] [--exit-code] [--get-url]\n"
	memset(&ref_array, 0, sizeof(ref_array));
	for ( ; ref; ref = ref->next) {
	struct remote *remote;

	int i;


	if (server_options.nr)
	}
	if (!remote) {
	if (get_url) {

	ref_array_clear(&ref_array);
}
		UNLEAK(sorting);
		printf("%s\n", *remote->url);
		OPT_STRING(0, "upload-pack", &uploadpack, N_("exec"),
	int show_symref_target = 0;
	if (!remote->url_nr)
	if (flags & REF_HEADS)
		ref_array_sort(sorting, &ref_array);
	static struct ref_sorting *sorting = NULL, **sorting_tail = &sorting;
		for (i = 1; i < argc; i++) {
			continue;
			 N_("take url.<base>.insteadOf into account")),
	UNLEAK(sorting);
		OPT_END()
		die("No remote configured to list refs from.");
	struct option options[] = {
		argv_array_push(&ref_prefixes, "refs/heads/");
		OPT_BOOL(0, "get-url", &get_url,
 * of the path?
	pathbuf = xstrfmt("/%s", path);
		const struct ref_array_item *ref = ref_array.items[i];

	dest = argv[0];

	NULL
	int status = 0;
		OPT_STRING_LIST('o', "server-option", &server_options, N_("server-specific"), N_("option to transmit")),
		status = 0; /* we found something */
	struct argv_array ref_prefixes = ARGV_ARRAY_INIT;
/*
static const char * const ls_remote_usage[] = {
	};
	}
#include "transport.h"
	N_("git ls-remote [--heads] [--tags] [--refs] [--upload-pack=<exec>]\n"
		if (!check_ref_type(ref, flags))
#include "ref-filter.h"
{
	free(pathbuf);
	   "                     [--symref] [<repository> [<refs>...]]"),
	const char *p;
		OPT_SET_INT_F(0, "exit-code", &status,
#include "remote.h"
int cmd_ls_remote(int argc, const char **argv, const char *prefix)
			 N_("show underlying ref in addition to the object pointed by it")),
	if (sorting)
		die("remote %s has no configured URL", dest);
		return 0;
			continue;
	if (flags & REF_TAGS)
	const char *uploadpack = NULL;
	struct string_list server_options = STRING_LIST_INIT_DUP;
	}

	unsigned flags = 0;
		OPT_REF_SORT(sorting_tail),
		item = ref_array_push(&ref_array, ref->name, &ref->old_oid);
	if (argc > 1) {
		printf("%s\t%s\n", oid_to_hex(&ref->objectname), ref->refname);


		if (dest)
			      2, PARSE_OPT_NOCOMPLETE),
static int tail_match(const char **pattern, const char *path)
		if (show_symref_target && ref->symref)
	int get_url = 0;
		transport->server_options = &server_options;
		fprintf(stderr, "From %s\n", *remote->url);

		{ OPTION_STRING, 0, "exec", &uploadpack, N_("exec"),

			   N_("path of git-upload-pack on the remote host")),
		argv_array_push(&ref_prefixes, "refs/tags/");
			pattern[i - 1] = xstrfmt("*/%s", argv[i]);
	if (!dest && !quiet)

	const struct ref *ref;
	return 0;
		OPT_BOOL(0, "symref", &show_symref_target,
	for (i = 0; i < ref_array.nr; i++) {
	ref = transport_get_remote_refs(transport, &ref_prefixes);
	const char **pattern = NULL;
	}
	}
		int i;
	int quiet = 0;
};
	remote = remote_get(dest);

		return 1;
#include "cache.h"

			free(pathbuf);
#include "builtin.h"
		if (!wildmatch(p, pathbuf, 0)) {
	}
			printf("ref: %s\t%s\n", ref->symref, ref->refname);
}
		transport_set_option(transport, TRANS_OPT_UPLOADPACK, uploadpack);

		return 1; /* no restriction */
			return 1;
 * Is there one among the list of patterns that match the tail part
	transport = transport_get(remote, NULL);
			     PARSE_OPT_STOP_AT_NON_OPTION);
 */
			      N_("exit with exit code 2 if no matching refs are found"),
		OPT__QUIET(&quiet, N_("do not print remote URL")),
		item->symref = xstrdup_or_null(ref->symref);
		}
			die("bad repository '%s'", dest);
		}
	char *pathbuf;
	return status;
		OPT_BIT(0, "refs", &flags, N_("do not show peeled tags"), REF_NORMAL),
		OPT_BIT('h', "heads", &flags, N_("limit to heads"), REF_HEADS),
		if (!tail_match(pattern, ref->name))
		struct ref_array_item *item;
	while ((p = *(pattern++)) != NULL) {


	struct ref_array ref_array;
#include "refs.h"
	if (uploadpack != NULL)
		OPT_BIT('t', "tags", &flags, N_("limit to tags"), REF_TAGS),
	if (transport_disconnect(transport)) {
	const char *dest = NULL;

	if (!pattern)
		UNLEAK(sorting);
	struct transport *transport;
{

	}
		pattern = xcalloc(argc, sizeof(const char *));
