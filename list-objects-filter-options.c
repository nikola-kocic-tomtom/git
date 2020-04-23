{
			&filter->filter_spec, strbuf_detach(&concatted, NULL));
		return;
	const char *remote,
	struct list_objects_filter_options *filter_options)
	/* Make sure the config info are reset */
	if (!subspecs[0]) {
 * On the command line this looks like:
		strbuf_add_separated_string_list(
	const char *arg,
		string_list_append(

	} else if (skip_prefix(arg, "blob:limit=", &v0)) {
	return filter->filter_spec.items[0].string;
	struct strbuf *subspec,
static int parse_combine_filter(
	memset(filter_options, 0, sizeof(*filter_options));
				errbuf,
		return 0;
	if (result) {
	return !strchr(RESERVED_NON_WS, ch);
		result = 1;
	struct strbuf *errbuf);
	string_list_append(&filter->filter_spec, strbuf_detach(&buf, NULL));
		filter_options->sparse_oid_name = xstrdup(v0);
	struct list_objects_filter_options *filter_options)
	string_list_clear(&filter_options->sub[0].filter_spec, /*free_util=*/0);
		struct strbuf concatted = STRBUF_INIT;
		die("%s", errbuf.buf);
		return 0;
			/*
		filter_options->sub = sub_array;
}
	struct strbuf *errbuf)

	 * Parse default value, but silently ignore it if it is invalid.
	free(filter_name);
 * convenience of the current command.

	/*
	struct list_objects_filter_options *filter)
	 */
		const int initial_sub_alloc = 2;
	/* NEEDSWORK: 'expand' result leaking??? */
		      filter_options->sub_alloc);

	for (sub = 0; sub < filter_options->sub_nr; sub++)
	/*
				*c);
		git_config_set("core.repositoryformatversion", "1");
			assert(subspecs[sub]->buf[last] == '+');
static int gently_parse_list_objects_filter(
	}
		gently_parse_list_objects_filter(
	} else if (skip_prefix(arg, "combine:", &v0)) {
}
	 * add new filters
	const char *remote)
		}
{
static void filter_spec_append_urlencode(
		 * Make filter_options an LOFC_COMBINE spec so we can trivially
		 */
 *
	struct strbuf errbuf = STRBUF_INIT;
}
	if (filter_options->choice == LOFC_COMBINE)
	if (!filter_options)
		if (git_parse_ulong(v0, &filter_options->blob_limit_value)) {
{

	ALLOC_GROW_BY(filter_options->sub, filter_options->sub_nr, 1,
			return 1;
	struct list_objects_filter_options *filter_options,
		/*
{
	struct list_objects_filter_options *filter_options,

		return parse_combine_filter(filter_options, v0, errbuf);
	struct strbuf *errbuf)
			 */
			&concatted, "", &filter->filter_spec);
		return 0;

static const char *RESERVED_NON_WS = "~`!@#$^&*()[]{}\\;'\",<>?";
		transform_to_combine_type(filter_options);
	if (!filter_options->choice) {
	trace_printf("Add to combine filter-spec: %s\n", buf.buf);
		parse_error = gently_parse_list_objects_filter(
		return;

		parse_list_objects_filter(filter_options, arg);
	{
/*
	const char *arg)
}
		filter_options->choice = LOFC_SPARSE_OID;
cleanup:
	free(filter_options->sparse_oid_name);
{
	}
		die(_("multiple filter-specs cannot be combined"));
	if (unset || !arg)
	struct list_objects_filter_options *filter_options)
 * instance. Does not do anything if filter_options is already LOFC_COMBINE.

void parse_list_objects_filter(
#include "list-objects-filter.h"
const char *expand_list_objects_filter_spec(
}

	if (filter_options->choice)
		BUG("no filter_spec available for this filter");
	}
	 * the default for subsequent fetches from this remote.
				errbuf,
			return 1;
	if (!arg)
	string_list_append(&filter_options->filter_spec, xstrdup("combine:"));
			strbuf_addstr(errbuf, _("expected 'tree:<depth>'"));

	struct strbuf errbuf = STRBUF_INIT;
		list_objects_filter_set_no_filter(filter_options);
			filter_options->choice = LOFC_BLOB_LIMIT;
	struct list_objects_filter_options *filter_options = opt->value;
#include "argv-array.h"
		return 0;
	}
int opt_parse_list_objects_filter(const struct option *opt,
		return;
	if (!promisor)
	} else if (skip_prefix(arg, "tree:", &v0)) {
#include "commit.h"
	return list_objects_filter_spec(filter);
{
	strbuf_addf(errbuf, _("invalid filter-spec '%s'"), arg);
		memset(filter_options, 0, sizeof(*filter_options));
	return 1;
	const char *arg,
void partial_clone_get_default_filter_spec(
	size_t sub;
	return result;
	promisor_remote_reinit();
	} else {

	 * top level.

/*
	struct list_objects_filter_options *filter_options,
		/* Add promisor config for the remote */

	struct strbuf buf = STRBUF_INIT;

	size_t new_index = filter_options->sub_nr;
		goto cleanup;


}
 *       --filter=<arg>
		}
	const char *c = sub_spec->buf;
	int parse_error;
		string_list_clear(&filter->filter_spec, /*free_util=*/0);
	}

{
	assert(filter_options->choice);

	decoded = url_percent_decode(subspec->buf);
		struct strbuf expanded_spec = STRBUF_INIT;
	char *decoded;
			   promisor->partial_clone_filter);
	filter_spec_append_urlencode(

	 */
	const char *arg,
#include "url.h"
	string_list_clear(&filter_options->filter_spec, /*free_util=*/0);
{
	}
			return 0;

}
	}

			strbuf_addstr(
	if (filter->filter_spec.nr != 1) {
	/*
		git_config_set(cfg_name, "true");
	/* Check if it is already registered */
			&filter->filter_spec,
		if (subspecs[sub + 1]) {

		filter_options->choice = LOFC_BLOB_NONE;

		if (!git_parse_ulong(v0, &filter_options->tree_exclude_depth)) {
		}
{
	}
	for (sub = 0; subspecs[sub] && !result; sub++) {
		       expand_list_objects_filter_spec(filter_options));
 * Changes filter_options into an equivalent LOFC_COMBINE filter options
				_("must escape char in sub-filter-spec: '%c'"),
		filter_options,
{
#include "revision.h"
		cfg_name = xstrfmt("remote.%s.promisor", remote);
	filter_options->choice = LOFC_COMBINE;
	return result;
	struct list_objects_filter_options *filter_options,
	return 0;
		c++;
	 * We don't need the filter_spec strings for subfilter specs, only the
			    filter->blob_limit_value);
		list_objects_filter_release(&filter_options->sub[sub]);
		}
	git_config_set(filter_name,
 * The filter keyword will be used by many commands.
		string_list_clear(&filter->filter_spec, /*free_util=*/0);
		 * add subspecs to it.
void list_objects_filter_release(

}
			&filter_options->sub[filter_options->sub_nr - 1], arg,
	struct strbuf **subspecs = strbuf_split_str(arg, '+', 0);
 * and in the pack protocol as:
	char *filter_name;

		strbuf_addstr(errbuf, _("expected something after combine:"));
	struct list_objects_filter_options *filter_options)
#include "config.h"
 * expand_list_objects_filter_spec() first).  We also "intern" the arg for the
					 promisor->partial_clone_filter,
		parse_error = gently_parse_list_objects_filter(
		}
		result = parse_combine_subfilter(
static int has_reserved_character(
	size_t sub;
	 * Please update _git_fetch() in git-completion.bash when you

			      filter_options->sub_alloc);

			filter_options, subspecs[sub], errbuf);
	strbuf_list_free(subspecs);
#include "list-objects-filter-options.h"
}
	if (ch <= ' ' || ch == '%' || ch == '+')



static int parse_combine_filter(
		string_list_append(&filter_options->filter_spec, xstrdup("+"));
	string_list_append(&filter_options->filter_spec,
 * Capture the given arg as the "filter_spec".  This can be forwarded to
		filter_spec_append_urlencode(filter_options, arg);
			&errbuf);
 *       "filter" SP <arg>
#include "promisor-remote.h"
	if (parse_error)
}
			&filter_options->sub[new_index], decoded, errbuf);

	return 0;
 * subordinate commands when necessary (although it's better to pass it through
	struct list_objects_filter_options *filter_options,
	} else if (skip_prefix(arg, "sparse:oid=", &v0)) {

			 * This is not the last subspec. Remove trailing "+" so
	 */
static void transform_to_combine_type(
#include "list-objects.h"
 */

	 * Record the initial filter-spec in the config as
 */
	filter_options->choice = LOFC_COMBINE;
	memset(filter_options, 0, sizeof(*filter_options));
	struct list_objects_filter_options *filter, const char *raw)
		return 1;
		BUG("filter_options already populated");

	}
{

			xcalloc(initial_sub_alloc, sizeof(*sub_array));

			filter_options, arg, &errbuf);
	if (!filter->filter_spec.nr)
void list_objects_filter_die_if_populated(
	if (filter->choice == LOFC_BLOB_LIMIT) {
		list_objects_filter_spec(&filter_options->sub[0]));

	int result = 0;
				  const char *arg, int unset)
#include "cache.h"

 * See Documentation/rev-list-options.txt for allowed values for <arg>.


		if (*c <= ' ' || strchr(RESERVED_NON_WS, *c)) {
			strbuf_addf(
		filter_options->sub_alloc = initial_sub_alloc;
	filter_name = xstrfmt("remote.%s.partialclonefilter", remote);
					 &errbuf);
	 */
		return 0;
		sub_array[0] = *filter_options;
	} else if (skip_prefix(arg, "sparse:path=", &v0)) {
}
	else
				_("sparse:path filters support has been dropped"));
}

			 * we can parse it.
	strbuf_addstr_urlencode(&buf, raw, allow_unencoded);

static int allow_unencoded(char ch)
}
#include "trace.h"
	strbuf_release(&errbuf);
}
	if (!promisor_remote_find(remote)) {
{
		memset(filter_options, 0, sizeof(*filter_options));
	free(filter_options->sub);
	filter_options->sub_nr = 1;
		strbuf_addf(&expanded_spec, "blob:limit=%lu",
			strbuf_detach(&expanded_spec, NULL));
 *
	int result;
		filter_options->choice = LOFC_TREE_DEPTH;
		string_list_append(&filter_options->filter_spec, xstrdup(arg));
	result = has_reserved_character(subspec, errbuf) ||
			size_t last = subspecs[sub]->len - 1;
	struct promisor_remote *promisor = promisor_remote_find(remote);
	gently_parse_list_objects_filter(filter_options,
	free(decoded);
	const char *v0;
	struct list_objects_filter_options *filter_options,

	while (*c) {
	char *cfg_name;
			strbuf_remove(subspecs[sub], last, 1);
}
	}
		struct list_objects_filter_options *sub_array =
void partial_clone_register(
static int parse_combine_subfilter(
		list_objects_filter_release(filter_options);


 * Parse value of the argument to the "filter" keyword.

	/*
{
const char *list_objects_filter_spec(struct list_objects_filter_options *filter)
		if (errbuf) {
{
{
	if (!strcmp(arg, "blob:none")) {


		free(cfg_name);
	if (filter_options->choice)
		ALLOC_GROW_BY(filter_options->sub, filter_options->sub_nr, 1,
		string_list_append(
	struct strbuf *sub_spec, struct strbuf *errbuf)

	struct strbuf *errbuf)

