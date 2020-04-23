		 */
int refspec_item_init(struct refspec_item *item, const char *refspec, int fetch)
	rs->alloc = 0;
			prefix = item->src;
	}
		else
	struct refspec_item item;
{
			  struct argv_array *ref_prefixes)
	}
		else if (!*item->dst)
	rs->raw_nr = 0;
		 * - when wildcarded, it must be a valid looking ref.
void refspec_init(struct refspec *rs, int fetch)
		}
		 * - empty is allowed; it means delete.
}
			item->exact_sha1 = 1; /* ok */
	for (i = 0; i < rs->raw_nr; i++)

			; /* valid looking ref is ok */
		} else {
			} else {
		else if (!check_refname_format(item->src, flags))
		/*
				return 0;
	0,

		 * - empty is not allowed.
			return 0;

	for (i = 0; i < rs->nr; i++) {

	 * Before going on, special case ":" (or "+:") as a refspec
			prefix = item->src;
{

}
}
		 * - otherwise it must be a valid looking ref.
		 * RHS
}
	is_glob = 0;

	item->matching = 0;
	FREE_AND_NULL(item->dst);

#include "cache.h"
{
	FREE_AND_NULL(rs->items);

		die(_("invalid refspec '%s'"), refspec);
	FREE_AND_NULL(item->src);
	rs->fetch = fetch;

	return 1;

	/*
	} else if (rhs && is_glob) {
{
			return 0;
		}
		refspec_append(rs, refspecs[i]);
/* See TAG_REFSPEC for the string version */
	0,

				return 0;
			; /* anything goes, for now */
	if (!fetch && rhs == lhs && rhs[1] == '\0') {
	 */
			if (check_refname_format(item->src, flags))
			return 0;
{
		if (!item->dst)
		 * - missing is allowed, but LHS then must be a
			; /* empty is ok; it means "do not store" */

	}

{
void refspec_appendn(struct refspec *rs, const char **refspecs, int nr)
				expand_ref_prefix(ref_prefixes, prefix);
			prefix = item->dst;
	for (i = 0; i < rs->nr; i++)
 */
		else if (item->dst)
	item->force = 0;
}
	struct refspec_item refspec;
	llen = (rhs ? (rhs - lhs - 1) : strlen(lhs));
			continue;
	}
}
		item->force = 1;
			}
		else if (llen == the_hash_algo->hexsz && !get_oid_hex(item->src, &unused))
			if (check_refname_format(item->src, flags))
	ALLOC_GROW(rs->items, rs->nr + 1, rs->alloc);
				const char *glob = strchr(prefix, '*');
	rs->items[rs->nr++] = item;
		else if (is_glob) {
#include "refspec.h"
			      int fetch)

		return 1;
		/*
		free((char *)rs->raw[i]);

{
	flags = REFNAME_ALLOW_ONELEVEL | (is_glob ? REFNAME_REFSPEC_PATTERN : 0);
			if (check_refname_format(item->dst, flags))
static struct refspec_item s_tag_refspec = {
						 prefix);
	} else {
		if (!*item->src)

{
	if (fetch) {
			return 0;
	int i;
	1,
		 *   valid looking ref.
	rs->raw_alloc = 0;
		const struct refspec_item *item = &rs->items[i];
	return parse_refspec(item, refspec, fetch);
		lhs++;
			; /* empty is ok */
	for (i = 0; i < nr; i++)
 * Returns 1 if successful and 0 if the refspec is invalid.
		 *   there is no existing way to validate this.
{
	rs->nr = 0;
		 * - otherwise, it must be an extended SHA-1, but
		const char *prefix = NULL;
			if (item->pattern) {
		return 0;
	return ret;

	if (*lhs == '+') {
	lhs = refspec;
	0,
		else if (!check_refname_format(item->dst, flags))
		else if (item->src && !item->exact_sha1)
		item->dst = NULL;
	int i;
void refspec_ref_prefixes(const struct refspec *rs,
	item->pattern = 0;
		is_glob = 1;
void refspec_clear(struct refspec *rs)
	item->pattern = is_glob;
		if (rs->fetch == REFSPEC_FETCH)
}

		else
		 * LHS
			; /* missing is ok; it is the same as empty */
int valid_fetch_refspec(const char *fetch_refspec_str)
	item->src = xstrndup(lhs, llen);
	refspec_item_clear(&refspec);
		is_glob = (1 <= rlen && strchr(rhs, '*'));
	if (1 <= llen && memchr(lhs, '*', llen)) {
		item->matching = 1;
void refspec_append(struct refspec *rs, const char *refspec)

	ALLOC_GROW(rs->raw, rs->raw_nr + 1, rs->raw_alloc);
	int ret = refspec_item_init(&refspec, fetch_refspec_str, REFSPEC_FETCH);
	item->exact_sha1 = 0;
	size_t llen;
	rs->raw[rs->raw_nr++] = xstrdup(refspec);
	if (rhs) {
		 */
				argv_array_pushf(ref_prefixes, "%.*s",
	rs->fetch = 0;
		size_t rlen = strlen(++rhs);

		if (item->exact_sha1)
void refspec_item_init_or_die(struct refspec_item *item, const char *refspec,
			; /* empty is ok; it means "HEAD" */



void refspec_item_clear(struct refspec_item *item)
		if (prefix) {

/*
		if (!item->dst) {

	int i;
#include "argv-array.h"
	int is_glob;
		refspec_item_clear(&rs->items[i]);


	int flags;
#include "refs.h"
	memset(rs, 0, sizeof(*rs));
	"refs/tags/*",
				return 0;
	rhs = strrchr(lhs, ':');
						 (int)(glob - prefix),
		/* LHS */
	 * for pushing matching refs.
}
}
		if ((rhs && !is_glob) || (!rhs && fetch))
{

		if (!*item->src)
		}
	}


		} else if (!*item->dst) {

	memset(item, 0, sizeof(*item));
		/* RHS */
	refspec_item_init_or_die(&item, refspec, rs->fetch);
			; /* valid looking ref is ok */
		struct object_id unused;
}
	"refs/tags/*"
static int parse_refspec(struct refspec_item *item, const char *refspec, int fetch)
	FREE_AND_NULL(rs->raw);
		else
	const char *lhs, *rhs;
	}
};
	if (!refspec_item_init(item, refspec, fetch))
const struct refspec_item *tag_refspec = &s_tag_refspec;
		item->dst = xstrndup(rhs, rlen);
 * Parses the provided refspec 'refspec' and populates the refspec_item 'item'.
	} else {
