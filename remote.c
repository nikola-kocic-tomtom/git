#include "remote.h"
		 * branch.
	/* If no refspec is provided, use the default ":" */
enum map_direction { FROM_SRC, FROM_DST };
 * The name of the tracking branch (or NULL if it is not defined) is
				reject_reason = REF_STATUS_REJECT_NONFASTFORWARD;
			 "'%s:refs/tags/%s'?"),

	ALLOC_GROW(remotes, remotes_nr + 1, remotes_alloc);
		if (best_score < score) {
			continue;
		if (match)
	struct ref **tail = &ret;
{
		if (!force_ref_update)
	int i;

	return branch && !!branch->merge;
		free_commit_list(found_commits);
 * but we can catch some errors early before even talking to the
}
static struct branch *current_branch;

	if (pat->matching) {
			ret->merge[i]->dst = ref;
	struct string_list dst_tag = STRING_LIST_INIT_NODUP;
}


	struct refspec_item query;
			return 0;
	alias_all_urls();
		goto clean_exit; /* No matches */
	remote->fetch_tags = 1; /* always auto-follow */
 * set to zero).
		if (git_config_string(&v, key, value))
		if (!dst_ref_index.nr)
				continue;
	int send_all = flags & MATCH_REFS_ALL;

	free(sent_tips.tip);
{
		 * ambiguity between remotes/origin/master and heads/master
}
int for_each_remote(each_remote_fn fn, void *priv)
	if (loaded)
			name);
static struct branch **branches;
			commit = lookup_commit_reference_gently(the_repository,
			   const struct refspec_item **ret_pat)
		strbuf_addstr(&buf, "refs/heads/");
	}
		remote->skip_default_update = git_config_bool(key, value);


static struct ref *make_linked_ref(const char *name, struct ref ***tail)
{
		    starts_with(r->name, "refs/heads/") &&
}
	struct ref *ref = alloc_ref("(delete)");
#include "refs.h"
	/* pick the remainder */


 *
		advise(_("The <src> part of the refspec is a commit object.\n"
	if (!ref)
	b = container_of(entry_or_key, const struct remote, ent);
	FILE *f = fopen_or_warn(git_path("branches/%s", remote->name), "r");
}
	ret->prune = -1;  /* unspecified */
			struct ref *dst_ref;
		return 0;
		      dst_value);
		BUG("stat_branch_pair: invalid abf '%d'", abf);
		oidclr(&ref->old_oid_expect);
	struct string_list ref_names = STRING_LIST_INIT_NODUP;
			die(_("Cannot fetch both %s and %s to %s"),
	const struct refspec_item *pat;
 * Compare-and-swap
	const char *needle = find_src ? query->dst : query->src;
int query_refspecs(struct refspec *rs, struct refspec_item *query)
		 * not a reference name.  :refs/other is a

				      (*rmp)->peer_ref->name);
	return 0;
}
	query.src = (char *)name;
	remote->origin = REMOTE_BRANCHES;
struct ref *get_remote_ref(const struct ref *remote_refs, const char *name)
				continue;
			if (add_pushurl_aliases)
	oidclr(&ref->new_oid);
					 remote->name, branch->name);
			}
}
	struct ref *ret = alloc_ref(name);
		ret->name = xstrdup(name);
{
 *

		    !ignore_symref_update(expn_name)) {
	string_list_clear(&matches, 0);

			ret->merge[i]->dst = xstrdup(ret->merge_name[i]);
				free(src_name);
			 "Did you mean to create a new branch by pushing to\n"
 *
	klen = kstar - key;
		}
	memset(cas, 0, sizeof(*cas));

		}
		    ((flag & REF_ISSYMREF) &&
{
				reject_reason = REF_STATUS_REJECT_FETCH_FIRST;
		"\n"

		 */
	}
#include "cache.h"
			if (match) {
		return;
	return 0;
		string_list_clear(&src_ref_index, 0);
	case 0:
	}
		}
		return 0;
		return NULL;
		return 0;
	entry = &cas->entry[cas->nr++];
	struct remote *remote;
 *
			 "Did you mean to tag a new blob by pushing to\n"
{
		add_pushurl_aliases = remotes[i]->pushurl_nr == 0;
static void set_merge(struct branch *ret)
static void apply_cas(struct push_cas_option *cas,
	const struct remote *a, *b;
				continue;
		if (strchr(ref->name, '^'))
			}
	else {
}
		return error(_("src refspec %s matches more than one"), rs->src);

		const char *v;
		const char *name = refspec->src[0] ? refspec->src : "HEAD";
		int namelen = strlen(name);
/*
		char **result = find_src ? &query->src : &query->dst;

	const struct ref *a = va, *b = vb;
	while (isspace(*s))
static const char *skip_spaces(const char *s)
		return;
		for_each_string_list_item(item, &src_tag) {
	r->rewrite[r->rewrite_nr++] = ret;


	/* Run "rev-list --left-right ours...theirs" internally... */
}
static struct remote *remote_get_1(const char *name,
			oidcpy(&dst_ref->new_oid, &ref->new_oid);
}
	ours = lookup_commit_reference(the_repository, &oid);
		if (!dst_value ||
	if (match) {
	strbuf_addstr(&buf, name);
		if (!entry->use_tracking)
{
{
	if (!valid_remote(ret))
 * upstream defined, or ref does not exist).  Returns 0 if the commits are
	((struct ref *)a)->next = next;
 * compute the commit ahead/behind values for the pair.
	int find_src = !query->src;
		BUG("'%s' should be commit/tag/tree/blob, is '%d'",
	/* remote nicknames cannot contain slashes */
		 */
#include "commit-reach.h"
		return -1; /* no tracking ref for refname at remote */
			weak_match++;
	struct ref *ref;
	remote->configured_in_repo = 1;
	free(ref2);
	 */
				 branch->merge[0]->src);
	int ours, theirs, sti;
}

	struct push_cas *entry;
{
		if (explicit)

			strbuf_addstr(sb,
	/* Handle remote.<name>.* variables */
static int match_explicit_refs(struct ref *src, struct ref *dst,
				free(ignore->peer_ref);
			return error(_("src refspec %s does not match any"), rs->src);
{
	struct ref *local_refs = NULL, **local_tail = &local_refs;
	}
	struct argv_array argv = ARGV_ARRAY_INIT;

	for (i = 0; i < rs->nr; i++) {
	clear_commit_marks(theirs, ALL_REV_FLAGS);
	 * If we did find a suitable refspec and it's not a symref and
}
		  int missing_ok)
		const char *key = find_src ? refspec->dst : refspec->src;
			if (remote && remote->push.nr &&
	struct refspec_item query;
			oidcpy(&ref->old_oid_expect, &entry->expect);
	const struct ref *ref = find_ref_by_name_abbrev(remote_refs, name);
			string_list_append(results, value);
	 * The branches file would have URL and optionally
				longest_i = i;
		} else {
			if (starts_with(url, r->rewrite[i]->instead_of[j].s) &&
	for (i = 0; i < rs->nr; i++) {

	int i;
	colon = strchrnul(arg, ':');
		if (item->pattern) {
	while (ref_map) {
}
		 * If the update isn't already rejected then check


	int i;
		else if (!strcmp(value, "--tags"))
			matched = refs;
 * dst (e.g. pushing to a new branch, done in match_explicit_refs).
		if (!r->rewrite[i])
		else if (reject_reason)
		if (!ref->deletion &&
	}
				/* Entry already existed */
			     longest->len < r->rewrite[i]->instead_of[j].len)) {
};
/*
				string_list_append_nodup(results, *result);
}

	}
	}
			warning(_("%s usually tracks %s, not %s"),

 * Look at remote.fetch refspec and see if we have a remote
	if (matched_dst->peer_ref)
	}
	int instead_of_alloc;
		    strcmp(ret->remote_name, "."))
		if (!reject_reason && !ref->deletion && !is_null_oid(&ref->old_oid)) {
{
		if (dst_peer) {
				if (!src_ref_index.nr)
	if (tracking_name)
}
	if (!resolve_ref_unsafe(refname, 0, NULL, &flag))
	}
	switch (push_default) {
	add_url_alias(remote, strbuf_detach(&buf, NULL));
}
		} else {
	if (upstream_is_gone) {
	struct remote *remote;
		}
			struct ref *ref = item->util;
	 * Some transports support directly peeking at
			return (struct ref *)list;
		"starting with \"refs/\"). We tried to guess what you meant by:\n"
{
		const char *v;
 */
void set_ref_status_for_push(struct ref *remote_refs, int send_mirror,
	if (!branch)

		return 0;
static int get_stale_heads_cb(const char *refname, const struct object_id *oid,
		 * (4) it is forced using the +A:B notation, or by
			 enum ahead_behind_flags abf)
	if (head->symref)
		ret->baselen = len;
		 * following are true:
		return strcmp(a->name, b->name);




	else if (!strcmp(subkey, "skipfetchall"))
			   ours),
			strbuf_addstr(sb,
	if (startup_info->have_repository) {
		}
{

		if (allocated_match)


{
		}
	ref = alloc_ref(refname);
				/* not pushing a commit, which is not an error */
			       "and can be fast-forwarded.\n",
{
			}
			return 0;
	}
	return errs;
		int add_pushurl_aliases;
		/*

			oidcpy(&dst_peer->new_oid, &ref->new_oid);
	}
	if (!commit || (commit->object.flags & TMP_MARK))

{
__attribute__((format (printf,2,3)))
		} else {
		strbuf_addstr(&buf, "refs/tags/");
						 const char *matched_src_name)
}
	strbuf_trim(&buf);


	/*
		    patlen != namelen - 5 &&
		return;
			continue; /* not a tag */
		if (namelen != patlen &&
	tail_link_ref(ret, tail);
	memset(&sent_tips, 0, sizeof(sent_tips));
static const char *branch_get_push_1(struct branch *branch, struct strbuf *err)
int match_push_refs(struct ref *src, struct ref **dst,
			if (!up)
	if (!arg) {
		    ref2->fetch_head_status != FETCH_HEAD_IGNORE) {
			     colon + 1);
	} else if (!strcmp(subkey, "tagopt")) {
}
	read_config();
	string_list_clear(&dst_tag, 0);
{
			/*
			best_score = score;

			    const struct hashmap_entry *entry_or_key,
			ref_map->peer_ref = get_local_ref(refspec->dst);
				query->force = refspec->force;
	ret->name = xstrndup(name, len);
		 * to expect, but we did not have such a tracking
		if (!strcmp(subkey, "insteadof")) {
			string_list_insert(&dst_ref_index,

	ret = xcalloc(1, sizeof(struct rewrite));
			oidcpy(&ref->new_oid, &ref->peer_ref->new_oid);
			ref->status = reject_reason;


		if (matched_ref)
		die(_("revision walk setup failed"));
struct stale_heads_info {

	}
	for (i = errs = 0; i < rs->nr; i++)

			      int *allocated_match)
		if (!ref->peer_ref) {
 * set to zero).
		struct remote *r = remotes[i];

	const char *base;
			continue;
		for_each_string_list_item(item, &src_tag) {
			oideq(&ref->old_oid, &ref->new_oid)) {
	char *ret;


			add_merge(branch, xstrdup(value));
			       "and have %d and %d different commit each, "
		dst_value = resolve_ref_unsafe(matched_src->name,

}
	 * overlapping refspecs, we need to go over all of the

 * Compute the commit ahead/behind values for the pair branch_name, base.
	if (!name[0] || is_dot_or_dotdot(name))

				force_ref_update = 1;
const char *remote_ref_for_branch(struct branch *branch, int for_push)
		    frag, remote->name);
void sort_ref_list(struct ref **l, int (*cmp)(const void *, const void *))

			/* Create a new one and link it */
		  const struct refspec_item *refspec,
				ref_map->peer_ref->force = 1;
	} else if (!strcmp(subkey, "proxyauthmethod")) {
			continue;
	 * (master if missing)
}
 * which they map.  Omit any references that would map to an existing
		return 0;
				ref2->peer_ref->name, ref2->name, ref1->name);
	cpy->symref = xstrdup_or_null(ref->symref);
		advise(_("The <src> part of the refspec is a tag object.\n"
		int nr_src_commits = 0, alloc_src_commits = 16;
		}
			if (strcmp(cur, up))
		const char *v;
		return error_buf(err, _("push has no destination (push.default is 'nothing')"));
			 oid_to_hex(&theirs->object.oid));
	struct counted_string *instead_of;
		}
		}
		    struct remote *remote,
		return -1;
{

				reject_reason = REF_STATUS_REJECT_NEEDS_FORCE;

	for (i = 0; i < remote->url_nr; i++) {
	if (!remote)
		if (advice_status_hints)
		if (explicit)
	branch->merge_name[branch->merge_nr++] = name;
}
			p = &ref->next;

	}
			ref_map->exact_oid = 1;
			tail = &((*tail)->next);
	if (matches.nr == 0)
	int flag;
	}
				goto free_name;
{
	int send_prune = flags & MATCH_REFS_PRUNE;
		if (ref->peer_ref &&
		} else {
	const struct ref *ref;
 * Returns -1 if num_ours and num_theirs could not be filled in (e.g., ref
struct ref *find_ref_by_name(const struct ref *list, const char *name)
	return ref;
		strbuf_addf(sb,


int get_fetch_map(const struct ref *remote_refs,
		return git_config_string(&remote->foreign_vcs, key, value);
				 * --all or --mirror.
	return query_refspecs(&remote->fetch, refspec);
		return pushremote_name;
		else
struct branch *branch_get(const char *name)

	return ret;
		add_pushurl(remote, v);
{
	for (ref = *dst; ref; ref = ref->next) {

	**local_tail = ref;
		next = ref->next;
	char *name;
	 * <remote> <src>:<dst>" push, and "being pushed ('%s')" is
	int i;
	}
		if (!ref_exists(branch->refname))
	for (i = 0; i < remotes_nr && !result; i++) {
	} else if (type == OBJ_TAG) {
		    "match_explicit_lhs() should catch this!",
	return "origin";
	if (pushremote_name) {
		if (refspec->pattern) {
		if (!send_mirror && !starts_with(ref->name, "refs/heads/"))
}
	if (remote_tracking(remote, ref->name, &ref->old_oid_expect))
		const char *vstar = strchr(value, '*');
		if (!remote->uploadpack)
		}
	int i, stale = 1;


	struct stale_heads_info info;
 * peer_ref (which object is being pushed) and force (if the push is
		BUG("query_refspecs_multiple: need either src or dst");
		return alloc_ref_with_prefix("refs/", 5, name);
static char *get_ref_match(const struct refspec *rs, const struct ref *ref,
static struct ref *get_expanded_map(const struct ref *remote_refs,

			}
static void add_pushurl_alias(struct remote *remote, const char *url)
	return ret;


	 */
	ALLOC_GROW(remote->pushurl, remote->pushurl_nr + 1, remote->pushurl_alloc);
		 *
			*tail = cpy;
	if (prepare_revision_walk(&revs))
		*result = strbuf_detach(&sb, NULL);
		else {
		char *dst_name;

}

	free(ref->remote_status);

			 * are acceptable as a unique match.
		    !starts_with(name, "refs/tags/")) {
	strbuf_reset(&buf);
};
	 */
		const char *needle = find_src ? query->dst : query->src;
		if (starts_with(ref->name, "refs/tags/"))
{
	for (i = 0; i < rs->nr; i++) {
	for (; list; list = list->next)
	int patlen = strlen(pattern);
			const char *dst_side = item->dst ? item->dst : item->src;
		"Neither worked, so we gave up. You must fully qualify the ref."),
	remote = make_remote(name, namelen);
		remote->configured_in_repo = 1;
	return copy_ref(ref);
{
		return;
		else if (!send_mirror)
	}
				   const char *(*get_default)(struct branch *, int *))
{

		const char *v;
		}
					 _("push refspecs for '%s' do not include '%s'"),

	 * this push, and collect all tags they have.
}
};
		if (!dst_name)
	return result;
		char *dst;
	for (i = 0; i < branches_nr; i++) {
		if (explicit)

}

				_("  (use \"git branch --unset-upstream\" to fixup)\n"));
	size_t baselen;
		/*

	if (remote->mirror)
 * If abf is AHEAD_BEHIND_FULL, compute the full ahead/behind and return the
		if (!refname_match(pattern, name))
			struct string_list_item *item =
			if (match_name_with_pattern(key, needle, value, result)) {
			dst_peer = make_linked_ref(dst_name, &dst_tail);
	if (theirs == ours)
		 * otherwise "git push $URL master" would result in
	return stale_refs;
		return 0;
		dst_peer = dst_item ? dst_item->util : NULL;
				return branch->merge_name[0];

#include "config.h"
			*explicit = 1;


		return NULL;
	/* ... and count the commits on each side. */
	add_url(remote, alias_url(url, &rewrites));
 * local symbolic ref.
	case 1:
	/*
	for (i = 0; stale && i < matches.nr; i++)
					       NULL, &flag);

			return r->rewrite[i];
#include "diff.h"
	FILE *f = fopen_or_warn(git_path("remotes/%s", remote->name), "r");
		clear_cas_option(cas);

		return error(_("cannot parse expected object name '%s'"),
	remotes[remotes_nr++] = ret;
}
	for (i = 0; i < ret->merge_nr; i++) {
		return 1;
		if (item->pattern || item->matching)
	ALLOC_GROW(r->rewrite, r->rewrite_nr + 1, r->rewrite_alloc);
		dst_item = string_list_lookup(&dst_ref_index, dst_name);
#include "mergesort.h"
	if (current_config_scope() == CONFIG_SCOPE_LOCAL ||

		if (git_config_string(&v, key, value))
		    oideq(&r->old_oid, &head->old_oid)) {
	rewrite->instead_of[rewrite->instead_of_nr].len = strlen(instead_of);
	if (flags & REF_ISSYMREF)
		/* A match is "weak" if it is with refs outside
	struct branch *ret;
	pat = &rs->items[matching_refs];
static void alias_all_urls(void)
	lookup.str = name;

			}
				 _("push destination '%s' on remote '%s' has no local tracking branch"),
}
		if (!strcmp(list->name, name))

			 int flag, void *cb_data)
	size_t klen;
			if (!commit)
int count_refspec_match(const char *pattern,
			*allocated_match = 1;
	*tail = &ref->next;
	else if (!strcmp(subkey, "url")) {
static void add_merge(struct branch *branch, const char *name)
		 * in full (e.g. "refs/remotes/origin/master") or at

		else if (skip_prefix(buf.buf, "Push:", &v))
struct rewrite {
 */
	lookup.len = len;
	ALLOC_GROW(remote->url, remote->url_nr + 1, remote->url_alloc);
	refspec_append(&remote->push, buf.buf);
	argv_array_push(&argv, ""); /* ignored */
				    struct refspec_item *query,
{
	if (!len)

		return 0;
static struct remote **remotes;
			 * matches are found and there are multiple
	remote->configured_in_repo = 1;

}
{
#include "object-store.h"
	struct remotes_hash_key lookup;

static void clear_cas_option(struct push_cas_option *cas)

		int score = refname_match(name, ref->name);
	free(ref);
			BUG("Internal error");
	int ret;
	if (branch && branch->pushremote_name) {
	return branch->push_tracking_ref;
			 * any of the commits we are sending?

		if (!refname_match(entry->refname, ref->name))
	enum object_type type;
	remote->origin = REMOTE_CONFIG;
	return NULL;
				return 0;
	return 0;

	    starts_with(name, "tags/") ||
		strbuf_release(&buf);
	} else if (type == OBJ_TREE) {
{
	} else if (!theirs) {
		 * no merge config; is it because the user didn't define any,
				*rmp = (*rmp)->next;
			if (match_name_with_pattern(key, needle, value, result))
			    ref1->name, ref2->name, ref2->peer_ref->name);
	entry->refname = xmemdupz(refname, refnamelen);
	struct object_id oid;
						  branch->refname))) {
{
static struct push_cas *add_cas_entry(struct push_cas_option *cas,

		struct ref *dst_peer;
{
	if (!longest)
	commit->object.flags |= TMP_MARK;
		for (j = 0; j < r->rewrite[i]->instead_of_nr; j++) {
			Q_("Your branch is behind '%s' by %d commit, "
		 * with the remote-tracking branch to find the value
		                 const char *refname)
		}
	}
		return NULL;
}
 */
	case PUSH_DEFAULT_NOTHING:
{
	 */
		if (advice_status_hints)


		const char *v;
			return git_config_string(&branch->pushremote_name, key, value);
struct counted_string {

	}
	if (get_oid(matched_src_name, &oid))
static int stat_branch_pair(const char *branch_name, const char *base,
 * value in sha1[].
			return error_buf(err,

		break;
			struct ref *cpy = copy_ref(ref);
			*allocated_match = 0;
				string_list_insert(&refs, ref->peer_ref->name);
	switch (count_refspec_match(rs->src, src, match)) {
	rewrite->instead_of[rewrite->instead_of_nr].s = instead_of;
			refspec_append(&remote->fetch, skip_spaces(v));
	strbuf_release(&buf);
	else if (!colon[1])
		    !starts_with(name, "refs/heads/") &&
			(*num_ours)++;
			 * strong match with zero or more weak matches
		*explicit = 0;
			cur = tracking_for_push_dest(remote, branch->refname, err);
{

			}
				return config_error_nonbool(key);


			remotes[i]->url[j] = alias_url(remotes[i]->url[j], &rewrites);
		if (advice_status_hints)
			remote->receivepack = v;
}
			*tail = copy_ref(r);
	memcpy(ref->name + prefixlen, name, len);
		} else if (!strcmp(subkey, "pushinsteadof")) {
		if (!remotes[i])
					    refspec->dst, &expn_name) &&
	int i, j;
		const char *v;
	for (i = 0; i < r->rewrite_nr; i++) {
/*
		strbuf_vaddf(err, fmt, ap);

		return error_buf(err,
struct remote *remote_get(const char *name)
	if (strcmp(ref1->name, ref2->name)) {
	struct ref *ret = NULL;
		strbuf_add(&sb, name + klen, namelen - klen - ksuffixlen);
	    starts_with(name, "remotes/"))
			ref_map = get_remote_ref(remote_refs, name);
	info.stale_refs_tail = &stale_refs;


		r = find_ref_by_name(refs, "refs/heads/master");
}
		if (match_name_with_pattern(refspec->src, ref->name,
	}
			continue; /* they already have it */
		if (!strcmp(ref->symref, list->name)) {
		return;
			die(_("%s cannot be resolved to branch"),
	}
			       "and can be fast-forwarded.\n",
				 _("upstream branch '%s' not stored as a remote-tracking branch"),
		return error(_("dst ref %s receives from more than one src"),
	for (ref = remote_refs; ref; ref = ref->next)
}
			ref_map = alloc_ref(name);
		return alloc_ref(name);
}
	struct ref ***local_tail = cb_data;
			string_list_append(&dst_tag, ref->name);
		return NULL;
		if (!full_base)
}
	namelen = strlen(name);
	 * dst, and sent_tips lists the tips we are pushing or those
		}
	}
 * does not exist).  Returns 0 if the commits are identical.  Returns 1 if
			continue;
	ret->prune_tags = -1;  /* unspecified */
}
clean_exit:
		string_list_append_nodup(ref_index, ref->name)->util = ref;
			struct ref **matched_ref)
	      dst_value, matched_src_name);
	int i;

			 "'%s:refs/heads/%s'?"),

			 */

	if (!*name) {
	int i;
	case PUSH_DEFAULT_UNSPECIFIED:
		}
				return NULL;
			struct commit *commit;
		 * least from the toplevel (e.g. "remotes/origin/master");
		return;
	if (pushurl != url)
	if (len) {
	 * that we know they already have. An element in the src_tag
 * remote side.
		return 0;

	if (name)
	if (!branch || i < 0 || i >= branch->merge_nr)
{
		branch = make_branch(name, namelen);
static void prepare_ref_index(struct string_list *ref_index, struct ref *ref)

static void add_instead_of(struct rewrite *rewrite, const char *instead_of)
	}
	return !cas->use_tracking_for_rest && !cas->nr;
		"- Looking for a ref that matches '%s' on the remote side.\n"
			return git_config_string(&branch->remote_name, key, value);
	sti = stat_tracking_info(branch, &ours, &theirs, &full_base, 0, abf);
	argv_array_clear(&argv);
}
	}
		if (refspec->pattern) {
 * refspecs. We can't catch all errors that match_push_refs would,
		return branch_get_upstream(branch, err);

	return ret;
	if (!name || name[0] == '\0')
 * each remote_ref that matches refspec.  refspec must be a pattern.
		return; /* no branch */
	longest_i = -1;
{
struct remote *pushremote_get(const char *name)
	else {
			if (dst_peer->peer_ref)
			dst_ref->peer_ref = copy_ref(ref);
	const struct ref *ref;
			char *src_name;
	ret->merge = xcalloc(ret->merge_nr, sizeof(*ret->merge));
	return ret;


const char *branch_get_upstream(struct branch *branch, struct strbuf *err)

static int parse_push_cas_option(struct push_cas_option *cas, const char *arg, int unset)
	string_list_clear(&ref_names, 0);
static int remotes_alloc;
	strbuf_addf(&buf, "HEAD:refs/heads/%s", frag);
static void show_push_unqualified_ref_name_error(const char *dst_value,
		ref_map = get_expanded_map(remote_refs, refspec);

	if (abf == AHEAD_BEHIND_QUICK)
		free(src_commits);
	struct string_list matches = STRING_LIST_INIT_DUP;
			     matched_dst->name);
		break;
	e = hashmap_get(&remotes_hash, &lookup_entry, &lookup);

			base);
				return NULL;
	remote->origin = REMOTE_REMOTES;
			      int all)
			error(_("more than one uploadpack given, using the first"));
	strbuf_release(&buf);
	if (is_null_oid(oid))
	return strbuf_detach(&buf, NULL);
	if (name_given && !valid_remote(ret))
		refspec_append(rs, ":");
	 * #branch specified.  The "master" (or specified) branch is
	if (!ours)
			read_branches_file(ret);
	struct string_list *ref_names;
static struct branch *make_branch(const char *name, int len)
	int allocated_src;
			if (branch->merge_nr) {
}
	 * the <src>.
{
					prepare_ref_index(&src_ref_index, src);
		else
struct ref *copy_ref(const struct ref *ref)
				break;
		if (git_config_string(&v, key, value))

	clear_commit_marks(ours, ALL_REV_FLAGS);
/*
	return stat_branch_pair(branch->refname, base, num_ours, num_theirs, abf);
}

			break;
}
	 * TRANSLATORS: "matches '%s'%" is the <dst> part of "git push

}
		    ? (len == r->rewrite[i]->baselen &&
	static int loaded;
		return;
					 key, value);
		return;
			continue;
			error(_("unable to delete '%s': remote ref does not exist"),
	cpy->next = NULL;
	return 0;

			 "Did you mean to tag a new tree by pushing to\n"
{
				match = match_name_with_pattern(item->src, ref->name, dst_side, &name);
}
			continue;

		return; /* already run */
	commit = lookup_commit_reference_gently(the_repository, oid, 1);
		frag = "master";
{


	 * that is an ancestor of any of the sent_tips needs to be
			matching_refs = i;
}
		 * Decide whether an individual refspec A:B can be
	struct push_cas *entry;
	struct ref *ref, **dst_tail = tail_ref(dst);
	int i, j;

 * Return true when there is anything to report, otherwise false.
	for ( ; ref; ref = ref->next)
	for ( ; list; list = list->next)
		} else {
			if (!value)
	}
	base = shorten_unambiguous_ref(full_base, 0);
	if (len)



			     int *num_ours, int *num_theirs,
		 */
	return alloc_ref_with_prefix("", 0, name);
						     src_commits, nr_src_commits,
	setup_revisions(argv.argc, argv.argv, &revs, NULL);
{

	if (matching_refs == -1)
		       matched_src_name, dst_value);
	return (flag & REF_ISSYMREF);
				 * explicit pattern, and we don't have
		 */
		}
static int match_explicit(struct ref *src, struct ref *dst,

{
	return parse_push_cas_option(opt->value, arg, unset);
			continue;
#include "string-list.h"
void free_refs(struct ref *ref)
{
static struct rewrite *make_rewrite(struct rewrites *r, const char *base, int len)
	return ref;
		ret = tracking_for_push_dest(remote, dst, err);
			if (ref->peer_ref)
	for (rmp = &ref_map; *rmp; ) {
				      size_t refnamelen)
			return -1;
		if (try_explicit_object_name(rs->src, match) < 0)
		ret->name = xstrndup(name, len);

static const char *error_buf(struct strbuf *err, const char *fmt, ...)
	/*
			dst_ref = make_linked_ref(ref->name, dst_tail);
			oidclr(&ref->old_oid_expect);
{
				if (!string_list_has_string(&src_ref_index,
		 *
		return tracking_for_push_dest(remote, branch->refname, err);
 * identical.  Returns 1 if commits are different.
		ret->merge[i]->src = xstrdup(ret->merge_name[i]);
	const struct remotes_hash_key *key = keydata;
	}
	}
	int ret = 0;
			add_to_tips(&sent_tips, &ref->peer_ref->new_oid);
	return name;
}
 * remote repository has, and the refspec used for push, determine
	struct ref **tail = head;
				    const struct refspec_item *refspec)
	remote->pushurl[remote->pushurl_nr++] = pushurl;
		int reject_reason = 0;
			matched_dst = make_linked_ref(dst_guess, dst_tail);
		       enum ahead_behind_flags abf)
	strbuf_addf(&buf, "refs/heads/%s:refs/heads/%s",
/*
	memset(&query, 0, sizeof(struct refspec_item));
		struct rewrite *rewrite;
			_("Your branch is based on '%s', but the upstream is gone.\n"),
	char **result = find_src ? &query->src : &query->dst;
	ALLOC_GROW(rewrite->instead_of, rewrite->instead_of_nr + 1, rewrite->instead_of_alloc);
	struct rev_info revs;
	return 1;

		strbuf_rtrim(&buf);
static int remotes_hash_cmp(const void *unused_cmp_data,
	int i, errs;
	if (!ret)
		return match;
		return error_buf(err, _("HEAD does not point to a branch"));
		}
		add_url_alias(ret, name);
}
	argv_array_push(&argv, "--left-right");
	}
	return ret;
	if (check_refname_format(refname + 5, 0))
	} else if (!strcmp(subkey, "proxy")) {
		 * "--force" will defeat any rejection implemented
	/* we already know it starts with refs/ to get here */
			refspec_append(&remote->push, skip_spaces(v));
{

		ref = next;
	}
	if (sent_tips.nr) {
	read_config();
	int namelen;
}
		return -1;
}
	struct ref **tail = &ret;
			return -1;
void free_one_ref(struct ref *ref)
	}
			die(_("value '%s' of pattern has no '*'"), value);
	for (i = 0; i < rs->nr; i++) {
}
	return list;


const char *branch_get_push(struct branch *branch, struct strbuf *err)
		}
								&ref->new_oid,
{
int branch_has_merge_config(struct branch *branch)
		 *
		return NULL;

		ret |= match_explicit_lhs(src, item, NULL, NULL);
		/*
{
	argv_array_push(&argv, "--");

	if (find_src && !query->dst)
 * the (potentially expensive) a/b computation (*num_ours and *num_theirs are
	ksuffixlen = strlen(kstar + 1);
	rewrite->instead_of_nr++;
 */
static void add_to_tips(struct tips *tips, const struct object_id *oid)
}
		errs += match_explicit(src, dst, dst_tail, &rs->items[i]);
		tail = &((*tail)->next);
			base);
		}
		!memcmp(name + namelen - ksuffixlen, kstar + 1, ksuffixlen);


			   "Your branch and '%s' have diverged,\n"
		}
			continue;
			rewrite = make_rewrite(&rewrites, name, namelen);
			   !branches[i]->name[len]) :
	default:
		/* The source could be in the get_sha1() format
	struct ref *matched_weak = NULL;

	return ret;
	memset(entry, 0, sizeof(*entry));
		    matched_src_name);
	} else if (!strcmp(subkey, "vcs")) {
	if (frag)
	struct tips sent_tips;
static void *ref_list_get_next(const void *a)
			*explicit = 1;
					 branch->name);
		}
		strbuf_add(&sb, value, vstar - value);
				return error_buf(err,
	const char *subkey;

	size_t namelen;
		if (!strcmp(remote->url[i], url))
	}
	else if (!strcmp(subkey, "prunetags"))
		struct refspec_item *refspec = &rs->items[i];
		return 0;
				item->util = ref;
	refspec_init(&ret->push, REFSPEC_PUSH);
	struct stale_heads_info *info = cb_data;
		if (git_config_string(&v, key, value))

	if (!ref->symref)
			if (!value)
		 *
}
	return xstrfmt("%s%s", r->rewrite[longest_i]->base, url + longest->len);

 *
			return 0;
		const int reachable_flag = 1;
			commit = lookup_commit_reference_gently(the_repository,

				_("  (use \"git pull\" to update your local branch)\n"));
	}

	} else if (starts_with(r, "refs/tags/")) {
		const char *value = find_src ? refspec->src : refspec->dst;
		if (!valid_remote(ret))
	return 0;
}
	}
	struct ref *ref = xcalloc(1, st_add4(sizeof(*ref), prefixlen, len, 1));
	string_list_clear(&refs, 0);

}
	branches[branches_nr++] = ret;
	if (!r)
	if (!ret->remote_name || !ret->merge_nr) {
				continue;
	}
				    struct string_list *results)

	int i;

		    : !strcmp(base, r->rewrite[i]->base))
int branch_merge_matches(struct branch *branch,

		return -1;
 * commits are different.

		struct commit **src_commits;
	int best_score = 0;
	return local_refs;
 * If for_push is true, the tracking branch refers to the push branch,
	int i;

		if (starts_with(dst_value, "refs/")) {
	matched_src = matched_dst = NULL;
	case PUSH_DEFAULT_UPSTREAM:
		 * (3) the destination is not under refs/tags/, and
		if (!dst)
		return;
			   struct object_id *oid)
	}
struct ref *copy_ref_list(const struct ref *ref)
static int one_local_ref(const char *refname, const struct object_id *oid,
static int branches_nr;
			else if (!ref_newer(&ref->new_oid, &ref->old_oid))

#include "tag.h"
	if (!cas->use_tracking_for_rest)
	for (ref = refs; ref; ref = ref->next) {
	if (explicit)
static int try_explicit_object_name(const char *name,
	case PUSH_DEFAULT_MATCHING:



}
	if (ret && value) {

	int longest_i;
	if (valid_remote_nick(name) && have_git_dir()) {
{
	struct ref *ref, *stale_refs = NULL;
		free(expn_name);

{
			    const void *keydata)
}
		struct string_list src_ref_index = STRING_LIST_INIT_NODUP;
{
		return ret;
	string_list_clear(&dst_ref_index, 0);
		return git_config_string((const char **)&remote->http_proxy_authmethod,
	/* Cannot stat if what we used to build on no longer exists */
	}
								1);
	if (*name == '/') {
}
				    "git status --ahead-behind");
		 *     is a descendant of the old.

		cas->use_tracking_for_rest = 1;

 * what remote refs we will update and with what value by setting
	int upstream_is_gone = 0;
		*tail = copy_ref(ref);
	if (send_prune) {
			query->force = refspec->force;
				reject_reason = REF_STATUS_REJECT_ALREADY_EXISTS;
}
}
	ret = make_remote(name, 0);

{
			stale = 0;
	struct ref *ref_map, **rmp;
	struct object_id oid;

			return cur;
	else
{
						     reachable_flag);
		if (!valid_remote(ret))
	struct ref *list = NULL;
			      struct ref **match,
	struct object_id oid;
static void handle_duplicate(struct ref *ref1, struct ref *ref2)
	ret = !strncmp(name, key, klen) && namelen >= klen + ksuffixlen &&
	struct strbuf buf = STRBUF_INIT;
	return ret;
	if (!rs->nr)
		else
static struct ref **tail_ref(struct ref **head)
			ref->status = REF_STATUS_UPTODATE;
	int send_mirror = flags & MATCH_REFS_MIRROR;
	struct remote *remote;
	*l = llist_mergesort(*l, ref_list_get_next, ref_list_set_next, cmp);
}
		dst_name = get_ref_match(rs, ref, send_mirror, FROM_SRC, &pat);
		strbuf_addf(sb,
			add_url_alias(remote, xstrdup(skip_spaces(v)));
/*
struct remotes_hash_key {
struct rewrites {
		*match = alloc_ref(name);
	ALLOC_GROW(branches, branches_nr + 1, branches_alloc);
	read_config();
				break;
	BUG("unhandled push situation");
	set_merge(ret);
	}
			 oid_to_hex(&ours->object.oid),
	while (ref->next)

			tail = &cpy->next;
	return retval;
	memset(&query, 0, sizeof(struct refspec_item));
static void query_refspecs_multiple(struct refspec *rs,
		name = get_default(current_branch, &name_given);
			struct ref *refs,

	/*
	struct strbuf buf = STRBUF_INIT;
		return 0;
void apply_push_cas(struct push_cas_option *cas,
		 *     passing the --force argument
	struct ref **stale_refs_tail;
{
	*num_theirs = *num_ours = 0;
	size_t len;
	}
			die(_("%s tracks both %s and %s"),
 * tracking branch for the refname there.  Fill its current
	if (query_refspecs(rs, &query))

			return 0;
 * forced) in elements of "dst". The function may add new elements to
			continue;
			continue; /* a dereference item */
		ref->expect_old_sha1 = 1;
		ref = ref->next;

	const char *base;
	tips->tip[tips->nr++] = commit;
			best_match = ref;
	add_pushurl_alias(remote, url);
			/* We want to catch the case where only weak
}
	struct string_list dst_ref_index = STRING_LIST_INIT_NODUP;

				cpy->peer_ref->force = 1;
	struct counted_string *longest;
		free_one_ref(ref);
		} else if (!strcmp(needle, key)) {
			return 0;
}
{
	} else {
	if (rs->pattern || rs->matching)
			prepare_ref_index(&dst_ref_index, *dst);

{
int ref_compare_name(const void *va, const void *vb)

static struct ref *alloc_ref_with_prefix(const char *prefix, size_t prefixlen,
		for (j = 0; j < remotes[i]->pushurl_nr; j++) {

	assert(replaced == NULL);  /* no previous entry overwritten */
	else
		tail = &((*tail)->next);


}
		} else {
			Q_("Your branch is ahead of '%s' by %d commit.\n",
		    struct ref *remote_refs)
				return config_error_nonbool(key);
		}
int remote_has_url(struct remote *remote, const char *url)
		strbuf_addf(sb,
	}
		return error_buf(err,
}

	/* are we the same? */
			src_name = get_ref_match(rs, ref, send_mirror, FROM_DST, NULL);
	const char *name;
{

			return 1;
		ref = ref->next;

			 * This last possibility doesn't occur because

struct ref *get_local_heads(void)
	const char *str;
	if (!ref)
				free(ignore);
{
	if (parse_config_key(key, "url", &name, &namelen, &subkey) >= 0) {
					  const char *refname,
		if (!c)
static int remotes_nr;

	if (!remotes_hash.cmpfn)
static char *guess_ref(const char *name, struct ref *peer)
	}
	return strcmp(a->name, b->name);
 * If abf is AHEAD_BEHIND_FULL, compute the full ahead/behind and return the
		result = fn(r, priv);
		} else if (is_null_oid(&matched_src->new_oid)) {
{
		struct strbuf sb = STRBUF_INIT;
		return NULL;
			const char *dst, *remote_name =
	} else if (type == OBJ_BLOB) {
	free_name:
		for (j = 0; j < remotes[i]->url_nr; j++) {
		} else if ((dst_guess = guess_ref(dst_value, matched_src))) {

 *
		add_missing_tags(src, dst, &dst_tail);
	ALLOC_GROW(cas->entry, cas->nr + 1, cas->alloc);
			*explicit = 1;
		add_pushurl(remote, pushurl);
	if (e)
		remote->prune = git_config_bool(key, value);
	struct commit **tip;
	struct ref *retval = NULL;
	string_list_sort(&dst_tag);
	if (!name && !strcmp(subkey, "pushdefault"))
		}
			       struct ref ***dst_tail, struct refspec *rs)
#include "revision.h"
		else if (remote_tracking(remote, ref->name, &ref->old_oid_expect))

}
			       "respectively.\n",
		*ret_pat = pat;
	error(_("The destination you provided is not a full refname (i.e.,\n"
				 refname, remote->name);
	}
		 * the usual "must fast-forward" rules.
 */

		char *name = refs->name;

			if (ref_map->peer_ref && refspec->force)
			continue;
			 */
	for (i = 0; i < cas->nr; i++)
			  struct ref ***dst_tail,
	return ((const struct ref *)a)->next;
	}
			if (!cur)
	return query.dst;
		ret->merge[i] = xcalloc(1, sizeof(**ret->merge));
	strbuf_getline_lf(&buf, f);
	free(ref->symref);
	}
	return remote_get_1(name, pushremote_for_branch);
			free(dst_guess);

			*match = alloc_delete_ref();
			get_oid_hex(name, &ref_map->old_oid);
				longest = &(r->rewrite[i]->instead_of[j]);

		 * from what we expect, reject any push.
		return error_buf(err,
			src_commits[nr_src_commits++] = commit;
		return NULL;

		struct commit *c = get_revision(&revs);

		if (oid_object_info(the_repository, &ref->new_oid, NULL) != OBJ_TAG)
	 * where HEAD points; if that is the case, then
}
				error(_("* Ignoring funny ref '%s' locally"),
					       RESOLVE_REF_READING,
}
		return copy_ref(find_ref_by_name(refs, head->symref));
int resolve_remote_symref(struct ref *ref, struct ref *list)
			if (is_null_oid(&ref->new_oid))
		/*
/*

		error(_("dst refspec %s matches more than one"),
	else {
	/*
		va_start(ap, fmt);
 * Returns -1 if num_ours and num_theirs could not be filled in (e.g., no
				 */

 */
	init_remotes_hash();

	int name_given = 0;
	refspec_append(&remote->fetch, buf.buf);
	return cpy;
		name = xstrdup(ref->name);
		dst_peer->force = pat->force;
	return 0;
		struct refspec_item *refspec = &rs->items[i];
				/*
			       "respectively.\n",
	if (!dst)
			ref->forced_update = 1;

		 * with a non-zero merge_nr but a NULL merge
	string_list_sort(ref_index);
	}
static int remote_tracking(struct remote *remote, const char *refname,
	if (!ret)
	free(cas->entry);
	if (abf != AHEAD_BEHIND_FULL)
				dst_peer->name)->util = dst_peer;
{

		return 0;
				 _("branch '%s' has no remote for pushing"),
const char *pushremote_for_branch(struct branch *branch, int *explicit)
		if (!for_push) {
	if (flags & MATCH_REFS_FOLLOW_TAGS)
	if (!dst_value) {
	/* Collect tags they do not have. */
				p = &ref->next;
		hashmap_init(&remotes_hash, remotes_hash_cmp, NULL, 0);
		if (!missing_ok && !ref_map)
	struct rewrite *ret;
	return best_match;
			   ref2->fetch_head_status == FETCH_HEAD_IGNORE) {
		return git_config_string(&pushremote_name, key, value);
			    _("Your branch and '%s' refer to different commits.\n"),
	if (!matched) {
	struct ref *ret = NULL;
	struct ref **p = &retval;
static struct rewrites rewrites;

		struct refspec_item *item = &rs->items[i];
	type = oid_object_info(the_repository, &oid, NULL);
	/* Handle remote.* variables */
					copy_ref(matched_src);
	char *frag;
	errs = match_explicit_refs(src, *dst, &dst_tail, rs);
	if (starts_with(name, "heads/") ||
	for (i = 0; i < cas->nr; i++) {
 * counts in *num_ours and *num_theirs.  If abf is AHEAD_BEHIND_QUICK, skip
 * counts in *num_ours and *num_theirs.  If abf is AHEAD_BEHIND_QUICK, skip
		return url;
			    matched_src->name);
{
								&ref->new_oid,
	struct hashmap_entry lookup_entry, *e;
	info.ref_names = &ref_names;
		"  is a ref in \"refs/{heads,tags}/\". If so we add a corresponding\n"
		*(frag++) = '\0';
	const char *colon;
static int handle_config(const char *key, const char *value, void *cb)
	if (remote->push.nr) {

		/*
			    (dst = apply_refspecs(&remote->push,
	}
			struct remote *remote = remote_get(remote_name);
		if (!strcmp(subkey, "remote")) {
	if (match_explicit_lhs(src, rs, &matched_src, &allocated_src) < 0)
			   "Your branch is ahead of '%s' by %d commits.\n",
	if (branch && branch->remote_name) {
				_("  (use \"git push\" to publish your local commits)\n"));

			up = branch_get_upstream(branch, err);
		 * that does not make much sense these days.
		 * way to delete 'other' ref at the remote end.

	if (branch) {
	info.rs = rs;
	 * Collect everything we know they would have at the end of
	return refname_match(branch->merge[i]->src, refname);
		if (r != head &&

			base, ours, theirs);
 */
		return -1;
				/* If the ref isn't stale then force the update. */
}
	int flag;
	struct branch *ret;
	struct object_id oid;
}
	} else if (!strcmp(subkey, "pushurl")) {
		ret->merge_nr = 0;


		if (advice_status_hints)
	for (r = refs; r; r = r->next) {

}
		 * pushed.  The push will succeed if any of the
	if (!*colon)
	return NULL;
		return 0;

	refspec_init(&ret->fetch, REFSPEC_FETCH);
		add_url(remote, v);
		return weak_match;
	remote = remote_get(pushremote_for_branch(branch, NULL));
	else
	} else if (!strcmp(subkey, "uploadpack")) {
		 * no merge config; let's make sure we don't confuse callers
		else if (skip_prefix(buf.buf, "Pull:", &v))
			int match;
		/* just "--<option>" */
		if (!refspec->dst)
				 !lookup_commit_reference_gently(the_repository, &ref->new_oid, 1))
	case PUSH_DEFAULT_SIMPLE:
static void add_url(struct remote *remote, const char *url)
		}
static void read_branches_file(struct remote *remote)
 * Lookup the tracking branch for the given branch and if present, optionally

	int nr, alloc;
	return alloc_ref_with_prefix("refs/heads/", 11, name);
	}
					    src_name))
static struct rewrites rewrites_push;
	}
		}
#include "advice.h"
		return tracking_for_push_dest(remote, branch->refname, err);
		free((char *)v);
			rewrite = make_rewrite(&rewrites_push, name, namelen);

		}
}
			 "'%s:refs/tags/%s'?"),
static void read_remotes_file(struct remote *remote)
{
	}
#include "argv-array.h"
		}
		const struct refspec_item *item = &rs->items[i];
	git_config(handle_config, NULL);
				continue;
{
		struct string_list_item *dst_item;


		if (advice_status_hints)

		if (string_list_has_string(&dst_tag, ref->name))

	}
	if (!remote)
		return -1;

	if (!f)
}
	}

	free_one_ref(ref->peer_ref);
		if (!strcmp(value, "--no-tags"))
		 */
{
			if (is_null_oid(&ref->new_oid))
		*tracking_name = base;
}

static int valid_remote(const struct remote *remote)
		string_list_append(&ref_names, ref->name);
 * the (potentially expensive) a/b computation (*num_ours and *num_theirs are
	*local_tail = &ref->next;
		const char *v;
		found_commits = get_reachable_subset(sent_tips.tip, sent_tips.nr,
	hashmap_entry_init(&ret->ent, lookup_entry.hash);
			struct commit *commit;
	}
	if (!base)
	if (!ref)
		    !is_null_oid(&ref->peer_ref->new_oid))
			*matched_ref = matched;
{
	struct rewrite **rewrite;
	if (!branch)
	 */

}
	}
		if (!refspec->dst)
		 * at the remote site.
	string_list_clear(&src_tag, 0);
{
		/* check for missing refs on the remote */
	int weak_match = 0;
		ref->deletion = is_null_oid(&ref->new_oid);
		  struct ref ***tail,


}
int remote_find_tracking(struct remote *remote, struct refspec_item *refspec)
		return -1;
		return git_config_string((const char **)&remote->http_proxy,
		   branch->merge_alloc);

		if (ref->expect_old_sha1) {
 * Create and return a list of (struct ref) consisting of copies of

		remote->mirror = git_config_bool(key, value);
			if (!oideq(&ref->old_oid, &ref->old_oid_expect))
	ret = xcalloc(1, sizeof(struct branch));
	}

		}

}
	if (!branch->push_tracking_ref)
			 * matches are found, as ambiguous.  One
struct ref *get_stale_heads(struct refspec *rs, struct ref *fetch_map)
}
static void ref_list_set_next(void *a, void *next)
}
		entry->use_tracking = 1;
	const char *r = resolve_ref_unsafe(peer->name, RESOLVE_REF_READING,
			base, ours);
			die(_("couldn't find remote ref %s"), name);
	return remote_for_branch(branch, explicit);
	/* If refs/heads/master could be right, it is. */
			 */
		if (!remote->receivepack)
	if (stale) {
	if (!kstar)
	} else if (!sti) {
		free(dst_name);
}
		if (dwim_ref(ret->merge_name[i], strlen(ret->merge_name[i]),
static int valid_remote_nick(const char *name)
		return -1;
	}
			    (!longest ||

	current_branch = NULL;
	int i;
	}
static void tail_link_ref(struct ref *ref, struct ref ***tail)
		goto clean_exit;
		       matched_src_name, dst_value);
static const struct ref *find_ref_by_name_abbrev(const struct ref *refs, const char *name)
	if (starts_with(name, "refs/"))
			   int send_mirror, int direction,
	fclose(f);
		 * or because it is not a real branch, and get_branch
	char *dst;
	 */
	**tail = ref;
		remote->prune_tags = git_config_bool(key, value);

	struct ref *ref;
}
		 * "matching refs"; traditionally we pushed everything
			      const struct ref *refs,
			} else {
};
			  struct refspec_item *rs)
		if (ref1->fetch_head_status != FETCH_HEAD_IGNORE &&
{
 * returned via *tracking_name, if it is not itself NULL.

				 * Remote doesn't have it, and we have no

};
	if (sti < 0) {
			   "Your branch is behind '%s' by %d commits, "
	if (!strcmp(subkey, "mirror"))
	int errs;
	if (refspec->pattern) {
	ret = apply_refspecs(&remote->fetch, refname);
		const struct refspec_item *pat = NULL;
		if (!remote_find_tracking(remote, ret->merge[i]) ||
		 * If the remote ref has moved and is now different
}

			if (pat->matching && !(send_all || send_mirror))
				continue;
	replaced = hashmap_put_entry(&remotes_hash, ret, ent);
static struct ref *alloc_delete_ref(void)
	for_each_ref(get_stale_heads_cb, &info);
			if (!value)
		if (len ? (!strncmp(name, branches[i]->name, len) &&
		warning(_("config remote shorthand cannot begin with '/': %s"),
	char *ref;
	ref->expect_old_sha1 = 1;

		return 0;

	oidcpy(&ref->new_oid, oid);
	struct ref *cpy;
			const char *up, *cur;
		ret->baselen = strlen(base);
{
	 * remote, we consider it to be stale. In order to deal with

			return 0;
		      struct remote *remote,
	frag = strchr(buf.buf, '#');
static void read_config(void)
	}
				add_pushurl_alias(remotes[i], remotes[i]->url[j]);
			      dst_value);
int check_push_refs(struct ref *src, struct refspec *rs)
			if (refspec->force)
		ALLOC_ARRAY(src_commits, alloc_src_commits);
		       !strncmp(base, r->rewrite[i]->base, len))
}
	if (parse_config_key(key, "branch", &name, &namelen, &subkey) >= 0) {


			add_instead_of(rewrite, xstrdup(value));
	}
		    !strcmp(name, branches[i]->name))
	}
	return ret;
		die(_("key '%s' of pattern had no '*'"), key);
	case 0:
{
					ref->peer_ref = alloc_delete_ref();
{
 * Fill in the copies' peer_ref to describe the local tracking refs to
			     enum ahead_behind_flags abf)
	for (i = 0; i < r->rewrite_nr; i++) {

		if (item->matching &&
		 *
	/* Are we using "--<option>" to cover all? */
	return tail;
		advise(_("The <src> part of the refspec is a tree object.\n"
		return branch->pushremote_name;
	if (in_repo)
{
			error(_("more than one receivepack given, using the first"));

		if (!name)
		const char *key = find_src ? refspec->dst : refspec->src;
	if (!branch->merge[0]->dst)
	return -1;
		 * (1) the remote reference B does not exist
	if (ref_map)
#include "refspec.h"
		    (matching_refs == -1 || item->force)) {

	return remote_get_1(name, remote_for_branch);
	int len;
			cpy->peer_ref = alloc_ref(expn_name);
		    matched_src_name, type);

				 _("no upstream configured for branch '%s'"),
		if (git_config_string(&v, key, value))
		 * (2) the remote reference B is being removed (i.e.,
	dst = apply_refspecs(&remote->fetch, refname);
				      const char *refname,
	return s;

		refspec_append(&remote->fetch, v);
}

				/* not pushing a commit, which is not an error */


{


{
	while (ref) {
static int match_explicit_lhs(struct ref *src,
		free((char *)v);
		ret = current_branch;
			 * matches, and where more than one strong
		return strncmp(a->name, key->str, key->len) || a->name[key->len];
	/* "--<option>=refname" or "--<option>=refname:value" */
		return container_of(e, struct remote, ent);
			/* Add it in */
			*matched_ref = matched_weak;
static int ignore_symref_update(const char *refname)
			   theirs),
	cpy = xmalloc(len);
			 * the end of the list.
static struct remote *make_remote(const char *name, int len)
}
struct tips {
const char *remote_for_branch(struct branch *branch, int *explicit)
	return 1;
		      struct ref *ref)
		for (ref = *dst; ref; ref = ref->next) {
		else
static void add_url_alias(struct remote *remote, const char *url)
			struct ref *ref = item->util;
{
{
				match = match_name_with_pattern(dst_side, ref->name, item->src, &name);
}
	}
	char *base;
					  struct strbuf *err)

				 branch->name);
			remote->fetch_tags = 2;
		oidcpy(&(*match)->new_oid, &oid);

	} else {
		rmp = &((*rmp)->next);
		} else if (!strcmp(needle, key)) {
	 * Cogito compatible push: push current HEAD to remote #branch
		refspec_append(&remote->push, v);
	if (read_ref(dst, oid))
{
			if (direction == FROM_SRC)
				 branch->name);
}
					 key, value);
int parseopt_push_cas_option(const struct option *opt, const char *arg, int unset)

	for (ref = src; ref; ref = ref->next) {
		struct ref *ref = ref_map;
	else if (get_oid(colon + 1, &entry->expect))
 */
	 */
			return error_buf(err, _("no such branch: '%s'"),

	struct ref *ref;
}
int format_tracking_info(struct branch *branch, struct strbuf *sb,
			Q_("Your branch and '%s' have diverged,\n"
	if (err) {
	int i;
}

	return 0;
	return ret;
				/* We're already sending something to this ref. */
	}
			if (!(commit->object.flags & reachable_flag))
	const char *dst_value = rs->dst;
			remote->uploadpack = v;
	else if (!strcmp(subkey, "prune"))
		strbuf_addf(sb,
	return NULL;

			*p = ref;
	struct branch *branch;
	/* clear object flags smudged by the above traversal */
			remotes[i]->pushurl[j] = alias_url(remotes[i]->pushurl[j], &rewrites);
#include "dir.h"
		if (!r)

	int rewrite_nr;
	memcpy(cpy, ref, len);
	if (key)
	return !!remote->origin;
	const char *full_base;
	} else if (!ours) {
static inline void init_remotes_hash(void)
	while (strbuf_getline(&buf, f) != EOF) {
	int i, result = 0;
}
	}
{
		oidclr(&entry->expect);

	remote = remote_get(ret->remote_name);
	for (i = 0; i < remotes_nr; i++) {
	longest = NULL;
		int flag;
			strbuf_addstr(sb,
	while (ref) {
 * otherwise it refers to the upstream branch.
	 * it's not in the list of refs that currently exist in that
	struct ref *matched = NULL;
		return NULL;
			}
{
static int match_name_with_pattern(const char *key, const char *name,


		     !starts_with(dst_value, "refs/heads/")))
}
		}
		matched_dst->peer_ref = allocated_src ?
	}
		return 0; /* non-existing refs are OK */
	current_config_scope() == CONFIG_SCOPE_WORKTREE)
	else if (!strcmp(subkey, "skipdefaultupdate"))
		BUG("query_refspecs: need either src or dst");
	memcpy(ref->name, prefix, prefixlen);
			 * FETCH_HEAD_IGNORE entries always appear at
{
				reject_reason = REF_STATUS_REJECT_STALE;
struct ref *ref_remove_duplicates(struct ref *ref_map)
};
		return branch->remote_name;
		strbuf_addf(sb,
	struct refspec *rs;
{

	} else if (!strcmp(subkey, "receivepack")) {

		 * It also is an error if the user told us to check
int stat_tracking_info(struct branch *branch, int *num_ours, int *num_theirs,
 * Given the set of refs the local repository has, the set of refs the
			if (starts_with(ref->name, "refs/tags/"))
		return 0;
	if (!buf.len) {
			else
		const char *value = find_src ? refspec->src : refspec->dst;
			_("Your branch is up to date with '%s'.\n"),
	else
				struct ref *ignore = *rmp;
		"\n"
		"- Checking if the <src> being pushed ('%s')\n"
	size_t len = strlen(name);
		item = string_list_append(&src_tag, ref->name);
static void add_missing_tags(struct ref *src, struct ref **dst, struct ref ***dst_tail)
						 _("cannot resolve 'simple' push to a single destination"));
		 * heads or tags, and did not specify the pattern
{
			     int force_update)
		strbuf_addf(sb,
		if (string_list_has_string(info->ref_names, matches.items[i].string))
	cpy->peer_ref = copy_ref(ref->peer_ref);
			*result = xstrdup(value);
	if (read_ref(branch_name, &oid))
			return NULL;
	if (!name || !*name || !strcmp(name, "HEAD"))
					   NULL, NULL);
			if (!all)
							     matched_src->name);
				handle_duplicate((struct ref *)item->util, ref);
		return -1;
			      struct refspec_item *rs,

		branch->push_tracking_ref = branch_get_push_1(branch, err);

		}
		BUG("'%s' is not a valid object, "
			oidcpy(&ref->old_oid, &list->old_oid);
		if (!vstar)
			}
}
	theirs = lookup_commit_reference(the_repository, &oid);
			return branches[i];
	return 0;
{
			 * Is this tag, which they do not have, reachable from
}
{
		if (skip_prefix(buf.buf, "URL:", &v))
	while (1) {
	len = st_add3(sizeof(struct ref), strlen(ref->name), 1);
		} else if (ref1->fetch_head_status == FETCH_HEAD_IGNORE &&
	const char *s;
	struct ref *matched_src, *matched_dst;
		if (r && oideq(&r->old_oid, &head->old_oid))
		{
		 */
			matched_dst = make_linked_ref(dst_value, dst_tail);
				matching_refs = i;
	default:
	 * remote name.
				return dst;

{
		name_given = 1;
		}
	if (parse_config_key(key, "remote", &name, &namelen, &subkey) < 0)
			continue; /* be conservative */
	for (ref = remote_refs; ref; ref = ref->next) {
		 */
		matched_dst = NULL;
		 *     pushing :B where no source is specified)
				    struct ref **match)
				goto free_name;
	const char *kstar = strchr(key, '*');
	return branch->merge[0]->dst;

	 * fetched and stored in the local branch matching the
/*

	switch (count_refspec_match(dst_value, dst, &matched_dst)) {
	} else if (!strcmp(subkey, "fetch")) {
		return 0;
	case PUSH_DEFAULT_CURRENT:
	int instead_of_nr;
		if (len
		return 0;
	}
		clear_commit_marks_many(nr_src_commits, src_commits, reachable_flag);
	for (weak_match = match = 0; refs; refs = refs->next) {


		if (git_config_string(&v, key, value))
		dst = apply_refspecs(&remote->push, branch->refname);
		if (is_dir_sep(*name++))
		if (allocated_match)
	/* Cannot stat unless we are marked to build on top of somebody else. */
{
	base = for_push ? branch_get_push(branch, NULL) :
	} else if (abf == AHEAD_BEHIND_QUICK) {
	struct string_list refs = STRING_LIST_INIT_NODUP;
		}
			matched_weak = refs;
	const struct ref *best_match = NULL;
	int matching_refs = -1;
		advise(_("The <src> part of the refspec is a blob object.\n"
}
			(*num_theirs)++;
	char *dst_guess;
	const char *pushurl = alias_url(url, &rewrites_push);
int is_empty_cas(const struct push_cas_option *cas)
		len = strlen(name);
}
		matched_dst->force = rs->force;
			else
		char *expn_name = NULL;
		return;
		const char *ret;
	}
	if (find_src && !query->dst)
		struct push_cas *entry = &cas->entry[i];
	query.dst = (char *)refname;
 * If we cannot do so, return negative to signal an error.
	struct commit *ours, *theirs;
			match++;
		return remote->configured_in_repo;
}
		const char *head_ref = resolve_ref_unsafe("HEAD", 0, NULL, &flag);
		upstream_is_gone = 1;

			   ours + theirs),
	if (errs)
			return -1;
			continue;
	}
{

			     &oid, &ref) == 1)
	free(ref2->peer_ref);
		ref->next = NULL;
	else
			show_push_unqualified_ref_name_error(dst_value,
	 * sent to the other side.
{
	return (!!remote->url) || (!!remote->foreign_vcs);

struct ref *alloc_ref(const char *name)
	if (ret->merge)
			else if (!lookup_commit_reference_gently(the_repository, &ref->old_oid, 1) ||
 * Given only the set of local refs, sanity-check the set of push
	return 1;
		struct ref *ref = make_linked_ref(refname, &info->stale_refs_tail);
		} else if (!strcmp(subkey, "merge")) {
{
			if (item->util) {
{
	if (!all) {
	 * matching refs.

			    base);
		if (c->object.flags & SYMMETRIC_LEFT)

		if (!name)
		"  refs/{heads,tags}/ prefix on the remote side.\n"
	string_list_sort(&ref_names);
	if (!head)
	}
			continue;
	fclose(f);
static struct ref *get_local_ref(const char *name)


		ret = make_branch(name, 0);

		/* "--no-<option>" */
{
	ALLOC_GROW(branch->merge_name, branch->merge_nr + 1,
			      int flags, void *cb_data)
}

	a = container_of(eptr, const struct remote, ent);
		if (ref->peer_ref)
	 * At this point, src_tag lists tags that are missing from
	int match = 0;
	clear_commit_marks_many(sent_tips.nr, sent_tips.tip, TMP_MARK);
		if (head_ref && (flag & REF_ISSYMREF) &&
		if ((*rmp)->peer_ref) {
		    skip_prefix(head_ref, "refs/heads/", &head_ref)) {
		} else if (ref1->fetch_head_status != FETCH_HEAD_IGNORE &&

				return config_error_nonbool(key);


	return 0;
		 */
		tail_link_ref(ref_map, tail);
		if (ref_map) {


				   const char *value, char **result)
		s++;


		ref_map = ref_map->next;
	} else if (!strcmp(subkey, "push")) {
		va_end(ap);
				pushremote_for_branch(branch, NULL);
	size_t ksuffixlen;
static const char *pushremote_name;
		return -1;
int remote_is_configured(struct remote *remote, int in_repo)
			    check_refname_format((*rmp)->peer_ref->name, 0)) {
	if (!theirs)
	ALLOC_GROW(tips->tip, tips->nr + 1, tips->alloc);
			current_branch = make_branch(head_ref, 0);
	} else {
			return copy_ref(r);
	ret->refname = xstrfmt("refs/heads/%s", ret->name);
		strbuf_addstr(&sb, vstar + 1);

		       const char **tracking_name, int for_push,
	for_each_ref(one_local_ref, &local_tail);
				_("  (use \"git pull\" to merge the remote branch into yours)\n"));
	return entry;
#include "commit.h"
{
		const char *name)
		branch_get_upstream(branch, NULL);
{

		return NULL;
	struct ref *next;
	free(base);
		va_list ap;
		return -1; /* we know what the tracking ref is but we cannot read it */
		                 int i,

	query_refspecs_multiple(info->rs, &query, &matches);
static const char *alias_url(const char *url, struct rewrites *r)
{
static void add_pushurl(struct remote *remote, const char *pushurl)

char *apply_refspecs(struct refspec *rs, const char *name)
		 *
			if (!starts_with((*rmp)->peer_ref->name, "refs/") ||
			return -1;
			return -1;
		if (matched_ref)
			return -1;
	if (type == OBJ_COMMIT) {
		 *     if the old and new value is a commit, the new
	return ret;
		return;

{
{
	if (!f)
{
{
	}
static struct hashmap remotes_hash;
struct ref *guess_remote_head(const struct ref *head,
		apply_cas(cas, remote, ref);
			remote->fetch_tags = -1;
	/*
	/* Find an explicit --<option>=<name>[:<value>] entry */
		 * by the rules above.

	while (*name)
		free(dst);
			strbuf_addf(sb, _("  (use \"%s\" for details)\n"),
		    struct refspec *rs, int flags)
	struct strbuf buf = STRBUF_INIT;
	if (read_ref(base, &oid))
			add_to_tips(&sent_tips, &ref->old_oid);
	struct ref *ref;
				*p = ref;
	return ret;
	struct remote *ret, *replaced;

	} else {
			 "Did you mean to create a new tag by pushing to\n"
	if (ret_pat)
		struct commit_list *found_commits;

	if (!matched_dst)
			else if (!has_object_file(&ref->old_oid))
		if (!starts_with(ref->name, "refs/tags/"))

}
{

			 "'%s:refs/tags/%s'?"),
		} else if (!strcmp(subkey, "pushremote")) {
	hashmap_entry_init(&lookup_entry, memhash(name, len));

{

	for (ref = src; ref; ref = ref->next) {
}
			continue;
		/*

	return 0;
	/*
		if (refspec->exact_sha1) {

			if (src_name) {
			base, theirs);
	if (!advice_push_unqualified_ref_name)
	repo_init_revisions(the_repository, &revs, NULL);
	for (ref = remote_refs; ref; ref = ref->next) {
	struct string_list_item *item;
			       "and have %d and %d different commits each, "
	if (unset) {
	/* Look for another ref that points there */
	 * we don't have to guess.
{
		return error_buf(err, _("HEAD does not point to a branch"));
		int force_ref_update = ref->force || force_update;
		       matched_src_name, dst_value);
		break;
		ret->base = xstrndup(base, len);
		 * auto-vivified it?
	entry = add_cas_entry(cas, arg, colon - arg);

	struct ref **tail = &list;
								1);
	argv_array_pushf(&argv, "%s...%s",
	if (starts_with(r, "refs/heads/")) {



			/*
		       matched_src_name, dst_value);


	struct remote *ret;
	for (ref = fetch_map; ref; ref = ref->next)
	ret = xcalloc(1, sizeof(struct remote));
		remote->skip_default_update = git_config_bool(key, value);
	if (!branch->merge || !branch->merge[0]) {
	size_t len;
			if (!commit)
		else
}
			read_remotes_file(ret);

			add_instead_of(rewrite, xstrdup(value));
	struct commit *commit;
		free(cas->entry[i].refname);
				/* We're already sending something to this ref. */
	return 1;
			   ref2->fetch_head_status == FETCH_HEAD_IGNORE) {
}
{
			strbuf_addstr(sb,

			    const struct hashmap_entry *eptr,
			    ref2->peer_ref->name, ref1->name, ref2->name);
				continue;
	const struct ref *r;
	int find_src = !query->src;
		return error_buf(err,

{
	if (get_oid(name, &oid))
	remote->url[remote->url_nr++] = url;

{
					matched_src :
	struct string_list src_tag = STRING_LIST_INIT_NODUP;
		 * including refs outside refs/heads/ hierarchy, but
	if (!name)
	cpy->remote_status = xstrdup_or_null(ref->remote_status);
	int rewrite_alloc;
static int branches_alloc;
	loaded = 1;
		oidcpy(&ref->new_oid, oid);
		dst_peer->peer_ref = copy_ref(ref);
			ALLOC_GROW(src_commits, nr_src_commits + 1, alloc_src_commits);
	case 1:
		item->util = ref;

	while (*tail)

static const char *tracking_for_push_dest(struct remote *remote,
		ret->base = xstrdup(base);
