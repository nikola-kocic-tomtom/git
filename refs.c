	case REF_TRANSACTION_OPEN:
int read_ref_at(struct ref_store *refs, const char *refname,
	timestamp_t at_time;

	return repo_dwim_log(the_repository, str, len, oid, log);
	if (old_oid) {
		}
	 * *do* conflict.
char *shorten_unambiguous_ref(const char *refname, int strict)
		return 0;
		    ref_transaction_update(t, refname, new_oid, old_oid,
}
{
	}
	 * name, because a refname isn't considered to conflict with
				    pseudoref);
				      flags, msg, err);

{
}
int refs_for_each_ref_in(struct ref_store *refs, const char *prefix,
{
	void *cb_data;
		/*
{
		if (flags & GET_OID_QUIETLY)
	struct ref_store *refs;
	strbuf_addf(&buf, "%s\n", oid_to_hex(oid));

static void register_ref_store_map(struct hashmap *map,
/* backend functions */
	struct read_ref_at_cb *cb = cb_data;
}

int head_ref_namespaced(each_ref_fn fn, void *cb_data)
	default:
				  const struct object_id *oid,
			die(_("log for %s is empty"), refname);
			break;
	}
		int rules_to_fail = i;

		if (r) {
	"%.*s",
int resolve_gitlink_ref(const char *submodule, const char *refname,
	if (extra_refname)
				sanitized->buf[sanitized->len-1] = '-';
			 const struct ref_storage_be *be)
	if (exclude_patterns && exclude_patterns->nr) {
	1, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
int ref_resolves_to_object(const char *refname,

	if (cb->cnt > 0)
		int j;
		}
}
}
}
			if (*flags & REF_BAD_NAME) {
		ret = ref_transaction_prepare(transaction, err);
	if (is_pseudoref_syntax(refname))
void base_ref_store_init(struct ref_store *refs,
	int ret = 0;
	struct ref_store *refs = transaction->ref_store;

}
			ref[--len] = '\0';
int head_ref(each_ref_fn fn, void *cb_data)
			continue;
	4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 2, 1,
		char *ref;
	case LOG_REFS_NORMAL:
	assert(err);
				strbuf_addf(err, _("could not read ref '%s'"),
	if (check_refname_format(refname, REFNAME_ALLOW_ONELEVEL)) {
 * Given a 'prefix' expand it by the rules in 'ref_rev_parse_rules' and add
		/* It's initialized on demand in register_ref_store(). */
			   struct strbuf *err)

		for (nr_rules = 0; ref_rev_parse_rules[nr_rules]; nr_rules++)
		if (!wildmatch(item->string, refname, 0))
	return !strcmp(refname, "HEAD") ||
 */
{
		/* Need to prepare first. */
			    errno != ENOTDIR)
				    dirname.buf, refname);
	r->refs_private = ref_store_init(r->gitdir, REF_STORE_ALL_CAPS);
			   const struct object_id *old_oid,
{
	case REF_TRANSACTION_OPEN:
		struct object_id *oid, char **msg,

				    filename);
	cb.refname = refname;
{
}
}
			strbuf_addch(sanitized, ch);
		BUG("prepare called on a closed reference transaction");

{
		timestamp_t *cutoff_time, int *cutoff_tz, int *cutoff_cnt)
char *refs_resolve_refdup(struct ref_store *refs,
 * the refname to fn. flags can be DO_FOR_EACH_INCLUDE_BROKEN to
					   flags, msg, &err) ||
{
	/*
			      _("ref updates forbidden inside quarantine environment"));
};
/*
}

		if (!warn_ambiguous_refs)
}
	short_name = xstrdup(refname);

		if (cb->cutoff_cnt)
			const char *rule = ref_rev_parse_rules[j];

}
	ret = 0;
 * - it ends with a "/", or
		 * For example: refs/foo/../bar is safe but refs/foo/../../bar
int refs_peel_ref(struct ref_store *refs, const char *refname,
			 */
			die(str, refname, err.buf);
};
		if (check_refname_format(refname, REFNAME_ALLOW_ONELEVEL)) {
			oidclr(oid);
	if (broken)
	struct ref_iterator *iter;
	char *last_branch = substitute_branch_name(r, &str, &len);


{

int peel_ref(const char *refname, struct object_id *oid)
	struct strbuf err = STRBUF_INIT;
			strbuf_addf(&resolved_buf, rule,
	return ret;
	int i;
	char name[FLEX_ARRAY];
		    const char *newref, const char *logmsg)
	struct ref_store_hash_entry *entry;
		BUG("illegal flags 0x%x passed to ref_transaction_update()", flags);

				      NULL, old_oid,
		}
		/*

}
	struct strbuf buf = STRBUF_INIT;
	struct object_id base;
	const char *id;
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 4, 0,

{
}
		strbuf_addf(err, _("refusing to update ref with bad name '%s'"),
	if (!nr_rules)
{
}
			   const char *refname,
				  const char *refname,
	return refs->be->reflog_expire(refs, refname, oid, flags,
	len = strlen(submodule);
	default:
	unsigned int hash;
	}
				     struct strbuf *sanitized)
		return -1;

 * refname begins with prefix. If trim is non-zero, then trim that
	const char **p;
		return 0;
static struct string_list *hide_refs;
		for (i = 0; i < nr_rules; i++) {
		/* No need to abort explicitly. */
			*flags |= REF_ISBROKEN | REF_BAD_NAME;
		}
	 * names are in the "refs/foo/bar/" namespace, because they
}
{
	if (cp == refname)
				rollback_lock_file(&lock);
		iter = prefix_ref_iterator_begin(iter, "", trim);
static int ref_store_hash_cmp(const void *unused_cmp_data,
{
				  force_create, err);
				   flags, msg, &err) ||
int initial_ref_transaction_commit(struct ref_transaction *transaction,

}
		ref_paranoia = git_env_bool("GIT_REF_PARANOIA", 0);
#include "cache.h"
		       const char *refname, const struct object_id *oid,
	struct strbuf buf = STRBUF_INIT;

 * gitdir.
	struct strbuf err = STRBUF_INIT;
	if (refs)
			    refname, extra_refname);
	}
		git_config_get_int("core.filesreflocktimeout", &timeout_ms);
		}
{
{
	return refs_create_reflog(get_main_ref_store(the_repository), refname,
	return 0;
	data.msg_fmt = msg_fmt;
	filename = git_path("%s", pseudoref);
			 * may show errors besides ENOENT if there are
static int do_for_each_repo_ref(struct repository *r, const char *prefix,



		/* We need to strip off one or more trailing slashes */
struct ref_transaction *ref_store_transaction_begin(struct ref_store *refs,
		while (len && ref[len - 1] == '/')
		 */
			return -1;
/*
		if (sanitized && disp != 1)
{
	refs_for_each_reflog_ent(refs, refname, read_ref_at_ent_oldest, &cb);
int refs_delete_ref(struct ref_store *refs, const char *msg,
	static int configured = 0;

}
		break;
	char *last_branch = substitute_branch_name(r, &str, &len);
		/*
	}
		/* the rule list is NULL terminated, count them first */
int for_each_reflog(each_ref_fn fn, void *cb_data)
}
		return 0;
}
	return refs_update_ref(get_main_ref_store(the_repository), msg, refname, new_oid,
				  const struct string_list *extras,
int refs_verify_refname_available(struct ref_store *refs,


		/* Skip to next component. */

int ref_is_hidden(const char *refname, const char *refname_full)
	return refs;
	struct warn_if_dangling_data *d = cb_data;
	if (filter->prefix)
	int matched = 0;
 * non-zero value, stop the iteration and return that value;
			   const char *refname,
			*cb->msg = xstrdup(message);
{
	do {
	ret = for_each_ref(filter_refs, &filter);
			starts_with(refname, "refs/notes/") ||
		return refs;


		if (!value)
	int tz;
	return 0;
				 refnames->items[i].string);
				       refs, id);

}
{
	}
	struct object *o = lookup_unknown_object(name);
				   const char *type,
	return refs->be->for_each_reflog_ent(refs, refname, fn, cb_data);

	return 1;
{
			if (i == j)
	return 0;
			if (errno != ENOENT &&
}
static int filter_refs(const char *refname, const struct object_id *oid,


	struct strbuf submodule_sb = STRBUF_INIT;
			break;
		rollback_lock_file(&lock);
{
		if (ref_iterator_peel(current_ref_iter, &peeled))
}
}
				  const struct string_list *skip,
			return refname;
	} else {
int refs_for_each_remote_ref(struct ref_store *refs, each_ref_fn fn, void *cb_data)
	"refs/remotes/%.*s/HEAD",
	    check_refname_format(refname, REFNAME_ALLOW_ONELEVEL) :

		BUG("error while iterating over references");

		    enum action_on_err onerr)

		    (!*p || *p == '/'))

			}

			warning(_("log for ref %s unexpectedly ended on %s"),
			total_len += strlen(ref_rev_parse_rules[nr_rules]) - 2 + 1;
		len = strlen(ref);
				   struct ref_store *refs,
		 * We don't know whether the ref exists, so don't set
	struct ref_store *refs = transaction->ref_store;
		const char *name, struct ref_store *refs)
		r = refs_resolve_ref_unsafe(get_main_ref_store(repo),
 */

	}
		refs = ref_store_init(get_git_common_dir(),
		if (sanitized)
			match++;
}
		/* OK */
{
	return refs_peel_ref(get_main_ref_store(the_repository), refname, oid);
	return refs_found;
}
	}
	return refs_for_each_ref_in(refs, "refs/remotes/", fn, cb_data);
				     const char *refname,
	return name;
		unsigned int read_flags = 0;
	unsigned int flag = 0;
			strbuf_addf(err, _("cannot process '%s' and '%s' at the same time"),
				      &null_oid, old_oid,
		*cb->msg = xstrdup(message);
		if (sanitized && sanitized->len)
int for_each_replace_ref(struct repository *r, each_repo_ref_fn fn, void *cb_data)
		short_name_len = strlen(short_name);
	struct ref_iterator *iter;
		strbuf_addstr(&real_pattern, "refs/");
}
static struct ref_storage_be *refs_backends = &refs_be_files;
 */
			return NULL;
{
	while ((ok = ref_iterator_advance(iter)) == ITER_OK) {

struct ref_store *get_submodule_ref_store(const char *submodule)


		const struct object_id *old_oid,

{
	strbuf_release(&normalized_pattern);
	return do_for_each_repo_ref(r, git_replace_ref_base, fn,
	if (refs)
int copy_existing_ref(const char *oldref, const char *newref, const char *logmsg)
{
	size_t component_start = 0; /* garbage - not a reasonable initial value */
}
		 * ref_rev_parse_rules rule by interpolating "%s" at the
			return -1;
		if (!hide_refs) {
int refs_head_ref(struct ref_store *refs, each_ref_fn fn, void *cb_data)
					    this_result, &flag);
		size_t restlen = strlen(rest);
int delete_reflog(const char *refname)

		break;
					    refname, strict);
}
	const char *prefix, void *cb_data)
	for (p = ref_rev_parse_rules; *p; p++)
	return refs;
		error("%s", err.buf);
{
	tr->ref_store = refs;
{

	return do_for_each_ref(get_main_ref_store(the_repository),
				   const char *refname, int strict)
	return ok;
			oidcpy(cb->oid, noid);

{
	const int num_rules = NUM_REV_PARSE_RULES;
 * Look up a ref store by name. If that ref_store hasn't been
	}
}
		return 1;
				break;


	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,

	if (flags & REF_ISBROKEN)
{
	iter = refs->be->iterator_begin(refs, prefix, flags);
			rules_to_fail = nr_rules;
{

			strbuf_reset(&resolved_buf);
	struct ref_store *refs;

{
		starts_with(refname, "refs/rewritten/");
}
		if (refs_reflog_exists(refs, path.buf))
				errno = EINVAL;
	if (!skip_prefix(refname, "worktrees/", &refname))
					    NULL, &skip, &err);

	if (!map->tablesize)
	assert(err);
	return refs->be->create_symref(refs, ref_target,
}
		string_list_append(hide_refs, ref);
	for_each_rawref(warn_if_dangling_symref, &data);
	return refs_found;
	return 1;
		strbuf_addf(err, _("could not open '%s' for writing: %s"),

{
		len--;
				   new_oid, old_oid, msg);
	assert(err);



{

		/* refname can be NULL when namespaces are used. */
	assert(err);
			break;
	if (is_null_oid(cb->oid))


		 * but use only rules prior to the matched one
			 * the short name is ambiguous, if it resolves
		strbuf_reset(&path);
 * later free()ing) if the string passed in is a magic short-hand form
		if (refs_read_raw_ref(refs, refname,
		/* We are at the start of a path component. */
			BUG("ref_update_reject_duplicates() received unsorted list");
			      const struct hashmap_entry *entry_or_key,


static int refs_ref_exists(struct ref_store *refs, const char *refname)
	extra_refname = find_descendant_ref(dirname.buf, extras, skip);

		goto done;

		*flags |= REF_BAD_NAME;
			   const struct object_id *new_oid,
	return -1;

		    !refname_is_safe(refname)) {
	}

			       struct object_id *oid, int *flags)
	    !refname_is_safe(refname)) {
	fprintf(d->fp, d->msg_fmt, refname);
	hash = strhash(name);

	filter.fn = fn;
int refs_for_each_rawref(struct ref_store *refs, each_ref_fn fn, void *cb_data)
{
{

struct read_ref_at_cb {
		} else if (!oideq(&actual_old_oid, old_oid)) {
struct ref_filter {

		strbuf_addf(&fullref, *p, len, str);
{
	if (getenv(GIT_QUARANTINE_ENVIRONMENT)) {
	    skip_prefix(name, "refs/remotes/", &name))
		if (!logs_found++) {

#include "repository.h"
	*ref = NULL;
	case REF_TRANSACTION_CLOSED:
	return peel_object(&base, oid);
		flags = &unused_flags;
 */

	if (broken)
			break;
	char c;

			warning(_("ignoring dangling symref %s"), fullref.buf);
		strbuf_reset(&fullref);
	return hp->fn(refname, oid, flags, hp->cb_data);
		return 0;
		}

	return refs_shorten_unambiguous_ref(get_main_ref_store(the_repository),
		       const char *refs_heads_master,
	struct ref_store *refs = get_main_ref_store(r);
}

	const char *extra_refname;
/*
			return refname;
	if (cb->cutoff_tz)
			void *cb_data)
	struct ref_store *refs = transaction->ref_store;
}
			   struct strbuf *err)

}
		}
/*

	strbuf_addch(&dirname, '/');
			 * a single asterisk for one side of refspec.
#include "refs/refs-internal.h"
}

	int logs_found = 0;
			/* In reading mode, refs must eventually resolve */
int refs_for_each_branch_ref(struct ref_store *refs, each_ref_fn fn, void *cb_data)

			hide_refs->strdup_strings = 1;
/*
	data.msg_fmt = msg_fmt;
int refs_init_db(struct strbuf *err)
					unsigned int flags)
			*cb->cutoff_time = timestamp;
void warn_dangling_symref(FILE *fp, const char *msg_fmt, const char *refname)

		 * missing refs and refs that were present but invalid,
	const char **p;
		cb->cnt--;
		*flags |= read_flags;
	case REF_TRANSACTION_PREPARED:
{
		return 0;
	return do_for_each_repo_ref_iterator(r, iter, fn, cb_data);
	*flags = 0;
		struct ref_transaction *transaction,
}
		case 1:
		    const char *refname,
const char *find_descendant_ref(const char *dirname,
			if (!(resolve_flags & RESOLVE_REF_ALLOW_BAD_NAME) ||

		  unsigned int flags,
				return 0;
static int is_pseudoref_syntax(const char *refname)
		 * short name is non-ambiguous if all previous rules
			   struct strbuf *err)
				return NULL;

int ref_transaction_abort(struct ref_transaction *transaction,
		 */
 * If so return a non-zero value to signal "yes"; the magnitude of
	if (ref_paranoia < 0)
	return NULL;
int create_symref(const char *ref_target, const char *refs_heads_master,




	strbuf_release(&submodule_sb);
}
			; /* OK, omit empty component */
	 */
	if (!refs_resolve_ref_unsafe(refs, refname, 0, oid, &flags) ||
				       refs_heads_master,
			 refs_reflog_exists(refs, ref))
int refs_create_reflog(struct ref_store *refs, const char *refname,
int refs_delete_reflog(struct ref_store *refs, const char *refname)
}
long get_files_ref_lock_timeout_ms(void)
	return do_for_each_ref(refs, prefix, fn, 0, flag, cb_data);
		break;
	case LOG_REFS_ALWAYS:
		return -1;
}
		unsigned int flags, timestamp_t at_time, int cnt,
	static int timeout_ms = 100;
/*
		offset = 0;
				    struct object_id *oid, int *flags)
		/* Refname ends with ".lock". */
	return refs_ref_exists(get_main_ref_store(the_repository), refname);
		if (!oideq(&actual_old_oid, old_oid)) {
	int component_len, component_count = 0;
	filter.prefix = prefix;
				const struct string_list *extras,
	if (!refname || !refname[1])
				  struct strbuf *err)
			break;
	if (!has_glob_specials(pattern)) {
				return NULL;
					do_for_each_ref_helper, &hp);

			/*
		strbuf_addstr(&normalized_pattern, "refs/");
		     const struct string_list *exclude_patterns)
			struct object_id *oid)
			strbuf_addf(err, _("ref '%s' already exists"),
 * - it has ":", "?", "[", "\", "^", "~", SP, or TAB anywhere, or
 */

int for_each_glob_ref(each_ref_fn fn, const char *pattern, void *cb_data)
{
}
int parse_hide_refs_config(const char *var, const char *value, const char *section)

	strbuf_release(&referent);
	return 0;
int rename_ref(const char *oldref, const char *newref, const char *logmsg)
	}

		       int force_create, struct strbuf *err)
	return for_each_glob_ref_in(fn, pattern, NULL, cb_data);
		if (cb->cutoff_time)

	int   refs_found  = expand_ref(r, str, len, oid, ref);
						     fn, cb_data);


	if (check_or_sanitize_refname(refname, REFNAME_ALLOW_ONELEVEL, out))
			   const struct object_id *old_oid,

	strbuf_release(&resolved_buf);
		if (!refs_read_raw_ref(refs, dirname.buf, &oid, &referent, &type)) {
{
	memset(&cb, 0, sizeof(cb));
 * The backend-independent part of the reference module.
	strbuf_release(&real_pattern);
	int len = strlen(prefix);
	const char **p;

 * function twice for the same name.
			 * Unset the pattern flag so that we only accept
		     struct string_list *refnames, unsigned int flags)

					      &hash, NULL);
			   unsigned int flags)
	}
	return repo_dwim_ref(the_repository, str, len, oid, ref);

	if (refs_read_ref_full(refs, refname,
		 * must fail to resolve to a valid non-ambiguous ref
	void *cb_data;
	return logs_found;
 */
			goto cleanup;
}

		struct object_id oid_from_ref;
			      const void *keydata)
		strbuf_addch(sb, c);
		if (sanitized)
	for (pos = string_list_find_insert_index(extras, dirname, 0);

 */
	 * For the sake of comments in this function, suppose that
			       DO_FOR_EACH_INCLUDE_BROKEN, cb_data);

	int ret = 0;
		return 0;
static struct ref_store *ref_store_init(const char *gitdir,
static unsigned char refname_disposition[256] = {
	while ((c = *msg++)) {
struct warn_if_dangling_data {

cleanup:
					return -1;
		}
int delete_refs(const char *msg, struct string_list *refnames,
{
					 oid, flags);
			return refname;
		}
	return refs->be->reflog_exists(refs, refname);
		if (!(resolve_flags & RESOLVE_REF_ALLOW_BAD_NAME) ||
	return refs->be->delete_refs(refs, msg, refnames, flags);
	if (!refs)
		result = !normalize_path_copy(buf, rest) && !strcmp(buf, rest);
int for_each_namespaced_ref(each_ref_fn fn, void *cb_data)
	struct strbuf buf = STRBUF_INIT;
	unsigned int flag = 0;
	oidcpy(cb->oid, ooid);
	    !memcmp(cp - LOCK_SUFFIX_LEN, LOCK_SUFFIX, LOCK_SUFFIX_LEN)) {


	struct ref_transaction *transaction;
}


			break;
		return 0;
		} else if (cmp > 0) {
	return 0;
int ref_filter_match(const char *refname,
		return 0; /* Component has zero length. */
		}
	flags |= (new_oid ? REF_HAVE_NEW : 0) | (old_oid ? REF_HAVE_OLD : 0);
		goto cleanup;
int refname_is_safe(const char *refname)
	struct ref_transaction *t = NULL;

		return 1;
		break;
			; /* omit ending dot */

	struct warn_if_dangling_data data;
	 * Look at the place where dirname would be inserted into
	string_list_insert(&skip, old_refname);
			    iter->refname, refname);
}
	return refs->be->for_each_reflog_ent_reverse(refs, refname,
	}

 * - it begins with ".", or
	refs->be = be;
			*cb->cutoff_tz = tz;



}
			 each_ref_fn fn, void *cb_data)
	strbuf_rtrim(sb);
		}

	if (t)
	return ret;
/*
{
	string_list_clear(&skip, 0);
		else if (cb->date == cb->at_time)
static int match_ref_pattern(const char *refname,
	for (i = nr_rules - 1; i > 0 ; --i) {

{
		free(transaction->updates[i]->msg);
	return timeout_ms;
		int neg = 0;
		    const struct object_id *old_oid, unsigned int flags,
}
		*len = size;
int ref_transaction_delete(struct ref_transaction *transaction,
}
struct ref_transaction *ref_transaction_begin(struct strbuf *err)
	int wasspace = 1;
			 * Otherwise a missing ref is OK. But the files backend
{
	if (!be)

	return do_for_each_ref(refs, prefix, fn, strlen(prefix), 0, cb_data);
	return refs_for_each_reflog_ent(get_main_ref_store(the_repository), refname,
		for_each_string_list_item(item, exclude_patterns) {
			matched = 1;
 * refname in it.
	/* skip first rule, it will always match */
		else
		       const char *ref_target,

					struct ref_store_hash_entry, ent);
				 struct strbuf *err)
#include "lockfile.h"
		BUG("free called on a prepared reference transaction");
	cb.cutoff_tz = cutoff_tz;
{
	return do_for_each_repo_ref_iterator(the_repository, iter,

		if (!restlen || *rest == '/' || rest[restlen - 1] == '/')
		goto done;
	const struct string_list *refnames;
		while (strbuf_strip_suffix(sanitized, LOCK_SUFFIX)) {
		return r->refs_private;
	if (!extras)
		/*
	    skip_prefix(name, "refs/tags/", &name) ||
{

			return -1;
		if (!is_null_oid(&cb->ooid)) {
 * the returned value gives the precedence used for disambiguation.
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 4, 4

		 */
	if (trim)
	case REF_TRANSACTION_PREPARED:
	for (i = 0; i < transaction->nr; i++) {
int refname_match(const char *abbrev_name, const char *full_name)
struct do_for_each_ref_help {
	}
		component_start = sanitized->len;
			subject = refname;
			goto done;
		component_len = check_refname_component(refname, &flags,
							sanitized);
		goto done;
	int flag;
	if (wt->is_current)
	const char *name;

						refname, fn, cb_data);
}
	if (!map->tablesize)
	const char *slash;
	struct object_id *oid;
				    _("multiple updates for ref '%s' not allowed"),
	resolves_to = resolve_ref_unsafe(refname, 0, NULL, NULL);
		 * is not.
	for (be = refs_backends; be; be = be->next)
	}
			return -1;
	return iter;
			exit(128);
				  refs_heads_master, logmsg);

		case UPDATE_REFS_DIE_ON_ERR:
	timestamp_t *cutoff_time;
	for (symref_count = 0; symref_count < SYMREF_MAXDEPTH; symref_count++) {
					/* collapse ".." to single "." */
				      oid, &sb_refname, &read_flags)) {

	return refs_for_each_rawref(get_main_ref_store(the_repository), fn, cb_data);

	strbuf_addstr(&real_pattern, pattern);
		cb->found_it = 1;
		if (!skip || !string_list_has_string(skip, extra_refname))
	strbuf_release(&fullref);
	cb.at_time = at_time;
	return do_for_each_ref(refs, "", fn, 0, 0, cb_data);
static char *substitute_branch_name(struct repository *r,
	case REF_TRANSACTION_CLOSED:
	struct ref_store *refs;
		/* Refname ends with '.'. */
		if (!sanitized)
char *resolve_refdup(const char *refname, int resolve_flags,
		}
const char *refs_resolve_ref_unsafe(struct ref_store *refs,
			break;
int update_ref(const char *msg, const char *refname,
	return cp - refname;
}
	update->msg = xstrdup_or_null(msg);
	struct ref_store_hash_entry *entry;

	if (!oid)
		BUG("%s ref_store '%s' initialized twice", type, name);
		t = ref_store_transaction_begin(refs, &err);
struct ref_store_hash_entry
	return do_for_each_repo_ref_iterator(the_repository, iter,
		 * Generate a format suitable for scanf from a
{
	struct hashmap_entry ent;
		const char *p;
{

		       int resolve_flags, struct object_id *oid, int *flags)
}
		return PEEL_INVALID;
	if (refname[0] == '.') { /* Component starts with '.'. */
{
			return be;
#include "tag.h"
	if (wt->id)
	if (!refs)
 * Try to read one refname component from the front of refname.
	id = wt->id ? wt->id : "/";
			if (!refs_found++)
		struct object_id actual_old_oid;

		struct ref_store *refs,
		else
		 * hold the values for the previous record.
	}
		size_t offset = 0;
/* This function needs to return a meaningful errno on failure */
					return -1;
	return refs->be->transaction_prepare(refs, transaction, err);
	fputc('\n', d->fp);
	strbuf_addstr(&submodule_sb, submodule);

}
{
	return NULL;
	fd = hold_lock_file_for_update_timeout(&lock, filename, 0,
	cb.msg = msg;
	if (refname[component_len - 1] == '.') {
/*
	if (old_oid && !is_null_oid(old_oid)) {
	free(last_branch);
{
{
enum peel_status peel_object(const struct object_id *name, struct object_id *oid)
	FILE *fp;
		return starts_with(refname, "refs/heads/") ||
	int fd;

			   unsigned int flags, const char *msg,
	struct ref_store *refs = get_main_ref_store(r);
	data.refnames = refnames;
		struct object_id hash;
		strbuf_addf(&path, *p, len, str);
{
				void *cb_data)
			return 0;
}
			return short_name;
	entry->refs = refs;
		if (!strcmp(be->name, name))

}
		return -1;
{
int expand_ref(struct repository *repo, const char *str, int len,

	else if (prefix)
		return 0;

	if (include_patterns && include_patterns->nr) {
{
		for (j = 0; j < rules_to_fail; j++) {
done:
	each_ref_fn *fn;
}

	return refs_for_each_reflog_ent_reverse(get_main_ref_store(the_repository),

			if (*flags & REF_BAD_NAME)
int refs_read_ref_full(struct ref_store *refs, const char *refname,
			      const char *old_refname,
		       reflog_expiry_should_prune_fn should_prune_fn,
	int ret = -1;
	else if (!starts_with(pattern, "refs/"))

{

		/*
	return refs_for_each_tag_ref(get_main_ref_store(the_repository), fn, cb_data);
		BUG("attempting to get main_ref_store outside of repository");
	}
	}
	FLEX_ALLOC_STR(entry, name, name);
		if (read_ref(pseudoref, &actual_old_oid)) {
	 * slash) and is not in skip, then we have a conflict.
	struct object_id oid;
	if (is_main_pseudoref_syntax(refname))
			}

		}
		fd = hold_lock_file_for_update_timeout(
}
int refs_create_symref(struct ref_store *refs,



					    pseudoref);

			return 0;
{
		return 0;
			ret = 1;
	if (!strcmp("transfer.hiderefs", var) ||

	if (o->type == OBJ_NONE) {
	default:
	if (cb->cutoff_cnt)
		flags |= DO_FOR_EACH_INCLUDE_BROKEN;
{

		; /* nothing */
			 * similarly-named refs.
int refs_rename_ref(struct ref_store *refs, const char *oldref,
			continue;
			   const char *refname,
}
	cb.cutoff_time = cutoff_time;
	return do_for_each_ref(refs, "", fn, 0,
	int *cutoff_tz;

		refname = sb_refname.buf;
}
		switch (disp) {
		 */
	struct object_id oid;
			return 1;
	oidcpy(&cb->noid, noid);
		if (refname[component_len] == '\0')
					      RESOLVE_REF_READING,

	struct ref_filter filter;
}

	*log = NULL;
	}
	entry = hashmap_get_entry_from_hash(map, hash, name,
}
		/*
		BUG("update called for transaction that is not open");


{
	/*
{
int refs_for_each_ref(struct ref_store *refs, each_ref_fn fn, void *cb_data)
	return ret;
	if (flags & REF_HAVE_OLD)
		case UPDATE_REFS_MSG_ON_ERR:
}
	}
		BUG("unexpected reference transaction state");
	size_t len;
{

	"refs/tags/%.*s",
	else
static int check_refname_component(const char *refname, int *flags,
	return 1;
	if (ref_type(refname) == REF_TYPE_PSEUDOREF) {
		const char *refname, unsigned int flags,
	return ref_transaction_update(transaction, refname,
		BUG("unexpected reference transaction state");
	return refs_resolve_ref_unsafe(get_main_ref_store(the_repository), refname,
		*cb->cutoff_time = timestamp;

	if (write_in_full(fd, buf.buf, buf.len) < 0) {
		     struct object_id *oid, int *flags)



			  struct object_id *oid, int *flags)
	return refs_for_each_reflog(get_main_ref_store(the_repository), fn, cb_data);
		starts_with(refname, "refs/bisect/") ||
					    fullref.buf, RESOLVE_REF_READING,
}
		return 1;
}
{

		    ref_transaction_commit(t, &err)) {
		oidcpy(&update->old_oid, old_oid);
			ref_transaction_free(t);
		if (skip_prefix(refname, item->string, &rest) &&

}
			if (!oideq(&cb->ooid, noid))
/* backend functions */
int refs_for_each_reflog(struct ref_store *refs, each_ref_fn fn, void *cb_data)
	if (flags & ~REF_TRANSACTION_UPDATE_ALLOWED_FLAGS)
	for (p = ref_rev_parse_rules; *p; p++)
	return 0;

	}
	if (!resolves_to
	o = deref_tag_noverify(o);
	tr = xcalloc(1, sizeof(struct ref_transaction));
#include "argv-array.h"
		}
					fn, cb_data);
		  void *policy_cb_data)
				*flags |= REF_ISBROKEN;
	strbuf_addstr(&dirname, refname + dirname.len);
		const char *ref, *it;
#include "config.h"
		else if (strcmp(ref, path.buf) &&
				continue;
		error("%s", err.buf);
			break;
		break;



			scanf_fmts[i] = (char *)&scanf_fmts[nr_rules] + offset;
}
	filter.pattern = real_pattern.buf;
	cb->date = timestamp;
		BUG("reference iterator is not ordered");
}
}
		}
	/* buffer for scanf result, at most refname must fit */

/*
}
 *    ":", "?", "[", "\", "^", "~", SP, or TAB
		unsigned char disp = refname_disposition[ch];
int for_each_ref(each_ref_fn fn, void *cb_data)
 * - it has "*" anywhere unless REFNAME_REFSPEC_PATTERN is set, or
	refs = ref_store_init(submodule_sb.buf,
						       DATE_MODE(RFC2822)));
		if (cb->cutoff_tz)
				oidclr(oid);
 * Associate a ref store with a name. It is a fatal error to call this
	if (!transaction ||
int for_each_glob_ref_in(each_ref_fn fn, const char *pattern,
		const char *rest;
		    string_list_has_string(skip, iter->refname))

		if (ret)

		}
 * Is it possible that the caller meant full_name with abbrev_name?
int reflog_expire(const char *refname, const struct object_id *oid,
			const char *pattern)
	if (!oid)
	int symref_count;
int ref_exists(const char *refname)
		goto done;
			   const char *refname,
	/*
		if (wasspace)
	case REF_TRANSACTION_OPEN:
	return refs_delete_ref(get_main_ref_store(the_repository), msg, refname,
	int cnt;
{
	return PEEL_PEELED;

{
	}
		starts_with(refname, "refs/worktree/") ||
 */
			if (!is_null_oid(old_oid)) {
{
	strbuf_release(&buf);
		*cb->cutoff_cnt = cb->reccnt;

	}
	if (wildmatch(filter->pattern, refname, 0))
}
	return ref_store->be->read_raw_ref(ref_store, refname, oid, referent, type);

	const char *result;
	}
{
	strbuf_release(&buf);
	if (skip_prefix(name, "refs/heads/", &name) ||
/* A hashmap of ref_stores, stored by worktree id: */
			strbuf_addf(err,

#include "worktree.h"
			return extra_refname;
#include "submodule.h"
 * Return true if refname, which has the specified oid and flags, can
int read_ref(const char *refname, struct object_id *oid)
}

}
				  void *cb_data)
		 */
		strbuf_addf(err, _("could not write to '%s'"), filename);
{
			      buf.buf, fn, 0, 0, cb_data);

{
	}
	strbuf_release(&path);
	if (!refs)
	struct ref_storage_be *be;
		strbuf_release(&err);

			       refs, submodule);
		BUG("abort called on a closed reference transaction");
		int type = oid_object_info(the_repository, name, NULL);
				  refname, oid, flags,
	register_ref_store_map(&submodule_ref_stores, "submodule",

	return 0;
int ref_transaction_prepare(struct ref_transaction *transaction,
		const char *email, timestamp_t timestamp, int tz,
		this_result = refs_found ? &oid_from_ref : oid;

	return NULL;


	if (!read_ref_full(buf.buf, RESOLVE_REF_READING, &oid, &flag))
}
static struct ref_store *lookup_ref_store_map(struct hashmap *map,


		    (!*rest || *rest == '/'))
}
		ret = 0;
				  int tz, const char *message, void *cb_data)
int refs_for_each_reflog_ent(struct ref_store *refs, const char *refname,

			*log = xstrdup(it);

			 */
{
		const char *prefix, int trim, int flags)
			error_errno(_("could not open '%s' for writing"),

	struct string_list_item *item;
			else
			*flags |= read_flags;
			   unsigned int flags,
	struct object_id ooid;
		else if (component_len <= 0)
	if (fd < 0) {
		const struct object_id *new_oid,
		unlink(filename);

	return find_ref_storage_backend(name) != NULL;
	"refs/remotes/%.*s",
 *
	if (skip_prefix(refname, "refs/", &rest)) {
			if (sanitized)
{
		       unsigned int flags,
	if (old_oid && is_null_oid(old_oid))
	return xstrdup(refname);
	/* bail out if there are no rules */
		case 2:
{
		return NULL;
int for_each_branch_ref(each_ref_fn fn, void *cb_data)
{
		refs = ref_store_init(git_common_path("worktrees/%s", wt->id),
	 * refname is "refs/foo/bar".
		return delete_pseudoref(refname, old_oid);
	}
	if (is_other_pseudoref_syntax(refname))
			   const struct object_id *old_oid,
	return refs_delete_refs(get_main_ref_store(the_repository), msg, refnames, flags);
	return refs->be->init_db(refs, err);
					     do_for_each_ref_helper, &hp);
		 */
		wasspace = isspace(c);
	    ref_transaction_commit(transaction, &err)) {

int should_autocreate_reflog(const char *refname)
	return NULL;

	 * We are at the leaf of our refname (e.g., "refs/foo/bar").
		BUG("commit called on a closed reference transaction");
			 * (with this previous rule) to a valid ref
			offset += xsnprintf(scanf_fmts[i], total_len - offset,
			}
	/* NUL-terminated identifier of the ref store: */
	if (o->type != OBJ_TAG)
				    DO_FOR_EACH_INCLUDE_BROKEN, cb_data);
		: !string_list_has_string(d->refnames, resolves_to))) {
	if (r->refs_private)
	}
	return ret;
}
}

		if (!isupper(*refname) && *refname != '_')
				  int flags,
	if (cb->cutoff_time)
static int do_for_each_ref(struct ref_store *refs, const char *prefix,
	return refs_reflog_expire(get_main_ref_store(the_repository),

 * How to handle various characters in refnames:
}
		strbuf_release(&err);
int refs_reflog_expire(struct ref_store *refs,
	for_each_rawref(warn_if_dangling_symref, &data);
		strbuf_addstr(&real_pattern, prefix);
	update->flags = flags;



 *
{
	if (!old_oid)
	iter = refs_ref_iterator_begin(refs, prefix, trim, flags);

		 * it is a conflict, *unless* it is in skip.
{
			  struct strbuf *err)
	int reccnt;
		size_t total_len = 0;
		if (subject &&
			errno = EINVAL;
		break;
		 * haven't resolved to a valid ref
enum ref_type ref_type(const char *refname)
{
	if (*pattern == '/')
static int warn_if_dangling_symref(const char *refname, const struct object_id *oid,
	if (!hide_refs)

		if (!starts_with(extra_refname, dirname))
			return ret;
		}
};
		buf = xmallocz(restlen);
			     each_ref_fn fn, void *cb_data,


	return ret;
				    short_name_len, short_name);
			sanitized->buf[component_start] = '-';
}
				cb->refname, show_date(cb->date, cb->tz,
		return REF_TYPE_MAIN_PSEUDOREF;
	cb->tz = tz;
	struct do_for_each_ref_help *hp = cb_data;
			    refname);
	char *short_name;
 * 2: ., look for a preceding . to reject .. in refs
		 * We are still at a leading dir of the refname (e.g.,
	/*
}
	case REF_TRANSACTION_PREPARED:
					       get_files_ref_lock_timeout_ms());
	case REF_TRANSACTION_OPEN:
int dwim_ref(const char *str, int len, struct object_id *oid, char **ref)
			}
{
		assert(refs == get_main_ref_store(the_repository));
		  struct object_id *oid, char **ref)
		/* No need to check for '*', there is none. */
void expand_ref_prefix(struct argv_array *prefixes, const char *prefix)
{
	iter = refs_ref_iterator_begin(refs, dirname.buf, 0,
static int is_other_pseudoref_syntax(const char *refname)
}

int for_each_ref_in(const char *prefix, each_ref_fn fn, void *cb_data)
		return -1;
				       logmsg);
	int *cutoff_cnt;
	e2 = container_of(entry_or_key, const struct ref_store_hash_entry, ent);
		struct object_id peeled;
	if (!transaction)
static int is_main_pseudoref_syntax(const char *refname)

}
		return NULL;
const char *resolve_ref_unsafe(const char *refname, int resolve_flags,
	const struct ref_store_hash_entry *e1, *e2;
		skip_prefix(refname, filter->prefix, &refname);
		if (!strcmp(full_name, mkpath(*p, abbrev_name_len, abbrev_name)))

		} else if ((flag & REF_ISBROKEN) && strchr(fullref.buf, '/')) {
	 * with dirname (remember, dirname includes the trailing
{

		      struct strbuf *referent, unsigned int *type)

	}


	static int nr_rules;
				goto done;
	       const struct object_id *new_oid,
		}



	return 0;
{
 * include broken references in the iteration. If fn ever returns a
}
{
		if (sanitized)
			/*
		ref_transaction_free(transaction);
	return REF_TYPE_NORMAL;
	return refs_resolve_refdup(get_main_ref_store(the_repository),
}
}
		 * dwim_ref() uses REF_ISBROKEN to distinguish between
	for (c = refname; *c; c++) {
			}
		unsigned int flags)
static int do_for_each_ref_helper(struct repository *r,
{
		component_count++;
int refs_for_each_fullref_in(struct ref_store *refs, const char *prefix,
			   unsigned int flags, const char *msg,
}
int refs_rename_ref_available(struct ref_store *refs,
	int unused_flags;
	if (!(flags & REFNAME_ALLOW_ONELEVEL) && component_count < 2)
		if (j == rules_to_fail) {
}
/*

	 */
		if (!isupper(*c) && *c != '-' && *c != '_')
		return xstrdup(refname);
			it = ref;
	data.fp = fp;
	}
	}

	 */
	struct ref_store *refs;
		return -1;
			return config_error_nonbool(var);

int refs_update_ref(struct ref_store *refs, const char *msg,
		*refname &&


		}
	struct read_ref_at_cb cb;
{
		break;
			if (match_ref_pattern(refname, item)) {
			return -1;
		oidcpy(&update->new_oid, new_oid);
	if (prefix) {
		strbuf_addf(err, _("cannot process '%s' and '%s' at the same time"),
int ref_transaction_verify(struct ref_transaction *transaction,
}
			warning(_("ignoring broken ref %s"), fullref.buf);
	if (cb->msg)
	if (!nr_rules) {
{
		} else if ((flag & REF_ISSYMREF) && strcmp(fullref.buf, "HEAD")) {
	if (!o)
	default:
			die(_("could not read ref '%s'"), pseudoref);
		scanf_fmts = xmalloc(st_add(st_mult(sizeof(char *), nr_rules), total_len));
	refs = get_submodule_ref_store(submodule);
{
		 * Does the refname try to escape refs/?
}

	return refs_create_symref(get_main_ref_store(the_repository), ref_target,
		else
		 * "refs/foo"; if there is a reference with that name,
{
	}
void copy_reflog_msg(struct strbuf *sb, const char *msg)
		if (resolve_flags & RESOLVE_REF_NO_RECURSE) {
				else
				  cleanup_fn, policy_cb_data);
	if (!cb.reccnt) {
		BUG("unexpected reference transaction state");
			return PEEL_INVALID;
	if (is_per_worktree_ref(refname))
#define NUM_REV_PARSE_RULES (ARRAY_SIZE(ref_rev_parse_rules) - 1)
					cb->refname, show_date(cb->date, cb->tz, DATE_MODE(RFC2822)));
		if (strict)
				else
		argv_array_pushf(prefixes, *p, len, prefix);
};
	cb->reccnt++;
			matched = 1;
		strbuf_addf(err, _("'%s' exists; cannot create '%s'"),
int refs_reflog_exists(struct ref_store *refs, const char *refname)
int refs_copy_existing_ref(struct ref_store *refs, const char *oldref,
				return -1;

}

	 * might need to do some trimming:
		size_t size;
		    skip_prefix(subject, match, &p) &&
	item->string = strbuf_detach(&normalized_pattern, NULL);
	e1 = container_of(eptr, const struct ref_store_hash_entry, ent);
		  struct object_id *oid)
	       const struct object_id *old_oid, unsigned int flags)


	switch (transaction->state) {
	oidcpy(&cb->ooid, ooid);
	int ret = 0;

		int flag;
			break;
						    struct strbuf *err)


			strbuf_complete(sanitized, '/');
			goto done;
	}
			*flags &= ~ REFNAME_REFSPEC_PATTERN;
 */
			   const struct object_id *old_oid, struct strbuf *err)
	return check_or_sanitize_refname(refname, flags, NULL);
}
void sanitize_refname_component(const char *refname, struct strbuf *out)
	size_t i, n = refnames->nr;
				    int resolve_flags,
}

	return 1;
			assert(offset < total_len);
	int ret = repo_interpret_branch_name(r, *string, *len, &buf, 0);
}
	struct string_list skip = STRING_LIST_INIT_NODUP;
	entry = alloc_ref_store_hash_entry(name, refs);


			goto cleanup;
			return -1;
	return entry ? entry->refs : NULL;
	ref_transaction_add_update(transaction, refname, flags,
	return tr;

	return 0;
				       cleanup_fn, policy_cb_data);
	return refs->be->rename_ref(refs, oldref, newref, logmsg);
			 * read_ref() returns 0 on success
	if (ok != ITER_DONE)

int for_each_tag_ref(each_ref_fn fn, void *cb_data)
			rollback_lock_file(&lock);
		struct object_id actual_old_oid;
				break;
	switch (transaction->state) {
			/* try again in case we have .lock.lock */
		ref = refs_resolve_ref_unsafe(refs, path.buf,
		}


	if (!flags)
				  prepare_fn, should_prune_fn,
	const char *filename;

	return 0;
int read_ref_full(const char *refname, int resolve_flags, struct object_id *oid, int *flags)

			   const struct object_id *new_oid,
		for_each_string_list_item(item, include_patterns) {
	struct object_id unused_oid;
/*
static int read_ref_at_ent_oldest(struct object_id *ooid, struct object_id *noid,
			subject = refname_full;

	struct object_id noid;
	data.refname = NULL;
		is_pseudoref_syntax(refname);
	strbuf_release(&err);
	}
{
			       old_oid, flags);
	}
	if (submodule[len])
}
				else
		return REF_TYPE_OTHER_PSEUDOREF;
		break;
	iter = refs_ref_iterator_begin(refs, prefix, trim, flags);
{

		break;
			}
	refs = lookup_ref_store_map(&submodule_ref_stores, submodule);
}
		       const char *logmsg)
				   refname, resolve_flags,

	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
{
			/* forbidden char */
	const char *filename;
	strbuf_strip_suffix(&normalized_pattern, "/");
	/* The default timeout is 100 ms: */

 * be resolved to an object in the database. If the referred-to object
	struct read_ref_at_cb *cb = cb_data;
{
				  const char *email, timestamp_t timestamp,
	 * itself. But we still need to check for references whose
}
{
			       prefix, fn, 0, flag, cb_data);
		int ch = *cp & 255;
		register_ref_store_map(&worktree_ref_stores, "worktree",

			strbuf_release(&resolved_buf);

		break;
		unlink(filename);
}
	return 0;
	int found_it;
		return result;
		if (wasspace && isspace(c))
		return 0;
		const char *str = _("update_ref failed for ref '%s': %s");
		       reflog_expiry_cleanup_fn cleanup_fn,
	if (timestamp <= cb->at_time || cb->cnt == 0) {
void normalize_glob_ref(struct string_list_item *item, const char *prefix,
{

	if (!r->gitdir)
				get_files_ref_lock_timeout_ms());
		 *
			 */
	       unsigned int flags, enum action_on_err onerr)
 */
char *refs_shorten_unambiguous_ref(struct ref_store *refs,
		case 3:

	}
		return fn("HEAD", &oid, flag, cb_data);
		 * location of the "%.*s".
		ret = fn(buf.buf, &oid, flag, cb_data);
		configured = 1;
	hashmap_entry_init(&entry->ent, strhash(name));
 * Call fn for each reference in the specified submodule for which the
static struct hashmap submodule_ref_stores;
		break;
	if (!submodule)
}
	if (item->util == NULL) {
		  reflog_expiry_cleanup_fn cleanup_fn,
}
			return -1;
		submodule = to_free = xmemdupz(submodule, len);
			if (last == '.') { /* Refname contains "..". */
	refs = lookup_ref_store_map(&worktree_ref_stores, id);
}
	struct ref_filter *filter = (struct ref_filter *)data;
	for (i = 1; i < n; i++) {
		case UPDATE_REFS_QUIET_ON_ERR:
		case 5:
}

	if (refs_resolve_ref_unsafe(refs, refname, resolve_flags, oid, flags))
	filename = git_path("%s", pseudoref);
		ret = refs->be->transaction_abort(refs, transaction, err);
		BUG("verify called with old_oid set to NULL");
		return 0;
	return xstrdup_or_null(result);
	return refs_delete_reflog(get_main_ref_store(the_repository), refname);
	strbuf_release(&dirname);

		BUG("prepare called twice on reference transaction");
	if (!is_nonbare_repository_dir(&submodule_sb))
		if (cb->msg)
		const char *msg)
{
	/* assume that add_submodule_odb() has been called */
	return refs_head_ref(get_main_ref_store(the_repository), fn, cb_data);
				warning(_("log for ref %s has gap after %s"),
	const char *resolves_to;
				&lock, filename, 0,

	int ret = -1;
{
			/*
	return refs->be->create_reflog(refs, refname, force_create, err);
 */
{
	}
			    struct strbuf *err)
	while (1) {

}
 * List of all available backends
		       void *policy_cb_data)
	free(last_branch);
		/* Fall through to finish. */
			continue;


			if (last == '@') { /* Refname contains "@{". */
			     unsigned int broken)
	return refs_read_ref_full(get_main_ref_store(the_repository), refname,
		}
/* The argument to filter_refs */

		if (skip &&

				return NULL;
		break;


};
				  resolve_flags, oid, flags);
	switch (log_all_ref_updates) {
		strbuf_add(&dirname, refname + dirname.len, slash - refname - dirname.len);
		} else if (is_null_oid(old_oid)) {
		refname++;
}
		oidcpy(cb->oid, noid);
}
{
	case REF_TRANSACTION_CLOSED:

		oidcpy(&cb->ooid, ooid);
/* A hashmap of ref_stores, stored by submodule name: */

				/* refspec can't be a pattern */
static struct ref_store_hash_entry *alloc_ref_store_hash_entry(

}
	return refs->be->transaction_finish(refs, transaction, err);
	struct do_for_each_ref_help hp = { fn, cb_data };
}
			error(str, refname, err.buf);
{
		int short_name_len;
		const char *extra_refname = extras->items[pos].string;
				    refname, dirname.buf);
	item->util = has_glob_specials(pattern) ? NULL : item->string;

		  reflog_expiry_should_prune_fn should_prune_fn,
		       struct strbuf *err)
}

		BUG("create called without valid new_oid");
	const char *c;
	}
#include "object-store.h"
			    filename, strerror(errno));
	commit_lock_file(&lock);
 * ".git/refs/"; We do not like it if:

	}
	if (current_ref_iter && current_ref_iter->refname == refname) {

	} while (*refname);
	/* Sanity check for subclasses: */
	data.fp = fp;
}
	if (!refs_read_ref_full(refs, "HEAD", RESOLVE_REF_READING,
	if (!len)
{

	if (!(flags & REF_ISSYMREF))
int refs_delete_refs(struct ref_store *refs, const char *msg,

		return REF_TYPE_PSEUDOREF;
			  const char *refname, int resolve_flags,
}


				if (sanitized)
	strbuf_release(&buf);

	strbuf_grow(&dirname, strlen(refname) + 1);
	switch (transaction->state) {
static int check_or_sanitize_refname(const char *refname, int flags,
{


	struct ref_iterator *iter;
 * - it has double dots "..", or
		struct lock_file lock = LOCK_INIT;
	}
		else
		return PEEL_NON_TAG;

	return refs_for_each_ref_in(refs, "refs/heads/", fn, cb_data);
	int pos;
struct ref_update *ref_transaction_add_update(
	iter = refs->be->reflog_iterator_begin(refs);
static struct hashmap worktree_ref_stores;
	struct ref_iterator *iter;
 * Return the length of the component found, or -1 if the component is
 * the results to 'prefixes'
			if (resolve_flags & RESOLVE_REF_READING)

			return !neg;


	while (len && is_dir_sep(submodule[len - 1]))

}
	if (flags & REF_HAVE_NEW)

}
	cb.oid = oid;
	} else {
		    const char *newref, const char *logmsg)
	} else {
	int ok;
		int fd;
		       reflog_expiry_prepare_fn prepare_fn,
	unsigned int type;
	data.refnames = NULL;
	ref_transaction_free(transaction);
}
				    refnames->items[i].string);


	const char **p, *r;

		char *buf;


			   struct strbuf *err)
	free(to_free);
					      const char *name)
				      flags, NULL, err);
{
	return 0;
				  const char *refname,

	struct strbuf resolved_buf = STRBUF_INIT;
			rollback_lock_file(&lock);
	struct strbuf path = STRBUF_INIT;
	cb.cutoff_cnt = cutoff_cnt;



	return refs->be->initial_transaction_commit(refs, transaction, err);

				&oid, &flag))
 * 1: End-of-component
			/* -2 for strlen("%.*s") - strlen("%s"); +1 for NUL */
	return refs_for_each_ref_in(get_main_ref_store(the_repository), prefix, fn, cb_data);
	    is_null_oid(oid))
			     each_reflog_ent_fn fn, void *cb_data)
			match++;
}
 * When sanitized is not NULL, instead of rejecting the input refname


	}
	 * extras. If there is an entry at that position that starts
	return matched;
		switch (onerr) {

{
}
	return refs_copy_existing_ref(get_main_ref_store(the_repository), oldref, newref, logmsg);
			    !refname_is_safe(refname)) {
	return 1;
	/* We just want the first entry */
	struct strbuf buf = STRBUF_INIT;
		const char *match = hide_refs->items[i].string;
		hashmap_init(map, ref_store_hash_cmp, NULL, 0);
		}
		 * to complain about the latter to stderr.
int refs_for_each_reflog_ent_reverse(struct ref_store *refs,

		/*
 * - it has ASCII control characters, or

				*flags |= REF_ISBROKEN;

	const char *rest;
		strbuf_addstr(err,
		/* Refname is a single character '@'. */
}
	static struct strbuf sb_refname = STRBUF_INIT;
struct ref_iterator *refs_ref_iterator_begin(

	struct ref_store *refs = transaction->ref_store;
		/* Good. */
}
	strbuf_addf(&buf, "%srefs/", get_git_namespace());
	ret = do_for_each_ref(get_main_ref_store(the_repository),
		  reflog_expiry_prepare_fn prepare_fn,
	if (!ok)

		BUG("sanitizing refname '%s' check returned error", refname);
		/* Expand dirname to the new prefix, not including the trailing slash: */
 * not legal.  It is legal if it is something reasonable to have under
{
}
		ref_transaction_free(t);
}
}
	return refs_for_each_remote_ref(get_main_ref_store(the_repository), fn, cb_data);
		if (*match == '!') {
			      REF_STORE_READ | REF_STORE_ODB);
	     !strcmp(key, "hiderefs"))) {
				     each_reflog_ent_fn fn,

{

		if (*match == '^') {
	struct lock_file lock = LOCK_INIT;
	oidcpy(oid, &o->oid);
	timestamp_t date;
	       struct object_id *oid, char **ref)
	free(short_name);
		strbuf_complete(&real_pattern, '/');
{
 * otherwise, return 0.
		if (!ref)
	strbuf_addf(&buf, "%sHEAD", get_git_namespace());
			rollback_lock_file(&lock);
		flag = DO_FOR_EACH_INCLUDE_BROKEN;



	transaction->updates[transaction->nr++] = update;

	int refs_found = 0;

	return ref_store_transaction_begin(get_main_ref_store(the_repository), err);
		int result;
		}
		    unsigned int flags)
 * does not exist, emit a warning and return false.
	NULL
				      REF_STORE_ALL_CAPS);
		if (skip && string_list_has_string(skip, dirname.buf))
		/* Append implied '/' '*' if not present. */
{
#include "hashmap.h"
	    (!parse_config_key(var, section, NULL, NULL, &key) &&
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4,
	return is_pseudoref_syntax(refname + 1);
				   int flags, void *cb_data)
	each_ref_fn *fn;
				found = 1;
			continue;
			   const struct object_id *oid,
		return (char *)*string;
	data.refname = refname;
{
	name = keydata ? keydata : e2->name;
	int flags;
	filter.cb_data = cb_data;
	if (!configured) {
}
		/* rest must not be empty, or start or end with "/" */


{
		BUG("pattern must not start with '/'");
		case 4:
	for (p = ref_rev_parse_rules; *p; p++) {
int ref_update_reject_duplicates(struct string_list *refnames,
		if (!t ||
	}
}
	"refs/heads/%.*s",
			return 0;
			starts_with(refname, "refs/remotes/") ||
		free(buf);

	int ret;
		BUG("reference backend %s is unknown", be_name);
		/*

{
		*string = strbuf_detach(&buf, &size);

{
				   struct strbuf *err)
		oidcpy(&cb->noid, noid);
int for_each_fullref_in(const char *prefix, each_ref_fn fn, void *cb_data, unsigned int broken)
				    pseudoref);
		    const char *refname, const struct object_id *new_oid,
			       RESOLVE_REF_READING, &base, &flag))
{
				    strlen(git_replace_ref_base),
	char **msg;
	if ((new_oid && !is_null_oid(new_oid)) ?
		free(transaction->updates[i]);
				const struct string_list *skip)
{
done:
{
		rollback_lock_file(&lock);
			neg = 1;
		*cb->cutoff_tz = tz;
	return refs_for_each_ref_in(refs, "refs/tags/", fn, cb_data);
{
			      pseudoref);
{
 */
			continue;
	const char *refname;
const char *prettify_refname(const char *name)
	}
int reflog_exists(const char *refname)
	return r->refs_private;
		 * we have not yet updated cb->[n|o]oid so they still
				void *cb_data)
			return 0;
		break;
static const char *ref_rev_parse_rules[] = {
int refs_read_raw_ref(struct ref_store *ref_store,
{
	size_t i;

		int found = 0;
static int delete_pseudoref(const char *pseudoref, const struct object_id *old_oid)

			return &ref_rev_parse_rules[num_rules] - p;
	}

	struct ref_store_hash_entry *entry;
	}
	refs = be->init(gitdir, flags);

	return ref_transaction_update(transaction, refname, new_oid,
					sanitized->buf[sanitized->len-1] = '-';
	ALLOC_GROW(transaction->updates, transaction->nr + 1, transaction->alloc);
		} else {
#include "refs.h"
	return read_ref_full(refname, RESOLVE_REF_READING, oid, NULL);
#include "iterator.h"
	return !strcmp(refname, "HEAD") || starts_with(refname, "refs/heads/");

}


}


 * to name a branch.

{
	if (ref_type(refname) == REF_TYPE_PSEUDOREF) {
		last = ch;
		return NULL;

	return 1;
		if (extras && string_list_has_string(extras, dirname.buf)) {
	}
	int i;

	return !!refs_resolve_ref_unsafe(refs, refname, RESOLVE_REF_READING, NULL, NULL);
		strbuf_addstr(&normalized_pattern, prefix);
	return ref_transaction_update(transaction, refname,
	return entry;
{
int refs_for_each_tag_ref(struct ref_store *refs, each_ref_fn fn, void *cb_data)
				       DO_FOR_EACH_INCLUDE_BROKEN);
 * 5: *, reject unless REFNAME_REFSPEC_PATTERN is set
		 * check if the short name resolves to a valid ref,
	FLEX_ALLOC_STR(update, refname, refname);
 * - it contains a "@{" portion
 * 0: An acceptable character for refs

			   int flags, void *data)
		}

		return 0;
		else if (!oideq(noid, cb->oid))
	return update;

			break;
	struct ref_store *refs = get_main_ref_store(the_repository);
void ref_transaction_free(struct ref_transaction *transaction)

			*cb->cutoff_cnt = cb->reccnt - 1;
int ref_transaction_commit(struct ref_transaction *transaction,

{

struct ref_store *get_worktree_ref_store(const struct worktree *wt)
	int flag;
			oidcpy(cb->oid, noid);
	const char *be_name = "files";
				    const char *refname,
	char *to_free = NULL;
	    ref_transaction_delete(transaction, refname, old_oid,
	return refs_reflog_exists(get_main_ref_store(the_repository), refname);
int refs_pack_refs(struct ref_store *refs, unsigned int flags)
int for_each_reflog_ent_reverse(const char *refname, each_reflog_ent_fn fn,
		oidcpy(oid, &peeled);
	static char **scanf_fmts;
			     const struct string_list_item *item)
 * registered yet, return NULL.
{
	int ret;
		return -1; /* Refname has only one component. */
	"refs/%.*s",
int ref_transaction_update(struct ref_transaction *transaction,
 * If abbrev_name cannot mean full_name, return 0.
			    errno != EISDIR &&
	if (ret == *len) {
		return 0;

	struct ref_store *refs;

		if (fd < 0) {
					return -1;
		return 0;
	struct ref_iterator *iter;
	       const struct object_id *old_oid,
				       resolve_flags, oid, flags);
		return NULL;
}
		struct object_id *this_result;
	const char *key;
 * 4: A bad character: ASCII control characters, and
		if (sanitized && component_len == 0)


/*
		flag = DO_FOR_EACH_INCLUDE_BROKEN;
	int flag;
	char last = '\0';
		oid = &unused_oid;
			error(_("unexpected object ID when deleting '%s'"),
static int is_per_worktree_ref(const char *refname)
	if (ref_paranoia)
};
		assert(refs == get_main_ref_store(the_repository));
}
 * 3: {, look for a preceding @ to reject @{ in refs
int ref_transaction_create(struct ref_transaction *transaction,
			      const struct hashmap_entry *eptr,
		? strcmp(resolves_to, d->refname)
		break;

			       old_oid, flags, onerr);
int check_refname_format(const char *refname, int flags)
	struct object_id oid;
					    ref_rev_parse_rules[i], 2, "%s") + 1;
	transaction = ref_store_transaction_begin(refs, &err);


			hide_refs = xcalloc(1, sizeof(*hide_refs));
			strbuf_addch(sanitized, '-');
int for_each_remote_ref(each_ref_fn fn, void *cb_data)
	struct do_for_each_ref_help hp = { fn, cb_data };

	const char *refname;
	if (!strcmp(refname, "@")) {
		ref_iterator_abort(iter);


			      const char *new_refname)
		ret = write_pseudoref(refname, new_oid, old_oid, &err);
	for (slash = strchr(refname, '/'); slash; slash = strchr(slash + 1, '/')) {
}
	}
		goto done;
	return refs->be->delete_reflog(refs, refname);
		refname += component_len + 1;
			oidclr(oid);

	if (transaction->state != REF_TRANSACTION_OPEN)
			if (!warn_ambiguous_refs)
{
	for (cp = refname; ; cp++) {
}

{
	return 0;
				if (sanitized)
	return skip_prefix(refname, "main-worktree/", &refname) &&
	int ret;

	strbuf_addstr(&normalized_pattern, pattern);
	ref_transaction_free(transaction);
		}
	struct strbuf err = STRBUF_INIT;
			!strcmp(refname, "HEAD");
	return refs;
				   oid, flags);
					strbuf_setlen(sanitized, sanitized->len - 1);

		if (1 != sscanf(refname, scanf_fmts[i], short_name))
			   each_ref_fn fn, int trim, int flags, void *cb_data)
int repo_dwim_log(struct repository *r, const char *str, int len,
		const char *message, void *cb_data)
			/* skip matched rule */

{

	else
	if (cb.found_it)
				each_repo_ref_fn fn, int trim, int flags,


{
 *
	}
	free(transaction);
		if (!cmp) {
				      REF_STORE_ALL_CAPS);
int ref_storage_backend_exists(const char *name)
	    || (d->refname
		      const char *refname, struct object_id *oid,


	     pos < extras->nr; pos++) {
		    const struct object_id *old_oid,
	struct ref_update *update;
	strbuf_release(&err);
	const char *cp;
{
static int read_ref_at_ent(struct object_id *ooid, struct object_id *noid,
	refname = strchr(refname, '/');
	struct strbuf normalized_pattern = STRBUF_INIT;
				*ref = xstrdup(r);
		int cmp = strcmp(refnames->items[i - 1].string,
		 * REF_ISBROKEN yet.
		return get_main_ref_store(the_repository);
			strbuf_addf(err, _("'%s' exists; cannot create '%s'"),
int repo_dwim_ref(struct repository *r, const char *str, int len,
	if (hashmap_put(map, &entry->ent))
}
int for_each_reflog_ent(const char *refname, each_reflog_ent_fn fn,

{
	if (submodule_to_gitdir(&submodule_sb, submodule))



	struct strbuf fullref = STRBUF_INIT;
	return refs->be->copy_ref(refs, oldref, newref, logmsg);
int delete_ref(const char *msg, const char *refname,
	for (p = ref_rev_parse_rules; *p; p++) {
	if (refs)
	refs_for_each_reflog_ent_reverse(refs, refname, read_ref_at_ent, &cb);
			   struct strbuf *err)
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
static struct ref_storage_be *find_ref_storage_backend(const char *name)
			if (!(*flags & REFNAME_REFSPEC_PATTERN)) {
void warn_dangling_symrefs(FILE *fp, const char *msg_fmt, const struct string_list *refnames)
		strbuf_addch(&real_pattern, '*');
			return -1;
	struct strbuf referent = STRBUF_INIT;
			}
		ref = xstrdup(value);
		break;
};
		 * in strict mode, all (except the matched one) rules
}
 * many characters off the beginning of each refname before passing
		const char *subject;
		error(_("%s does not point to a valid object!"), refname);
	if (sanitized)
	return ret;
		  const char *logmsg)
{
	if (!has_object_file(oid)) {
		return 0;
	const char *pattern;

{
out:

int dwim_log(const char *str, int len, struct object_id *oid, char **log)
			it = path.buf;
				   struct strbuf *sanitized)
int safe_create_reflog(const char *refname, int force_create,
		int len;
		if (!(read_flags & REF_ISSYMREF)) {

	strbuf_addch(sb, '\t');
	struct warn_if_dangling_data data;
		     const struct string_list *include_patterns,
}
			oidcpy(oid, &hash);
	struct ref_transaction *tr;

	const char *msg_fmt;
}
			   unsigned int flags, const char *msg,
	if (!new_oid || is_null_oid(new_oid))
		BUG("unexpected reference transaction state");
	return refs_for_each_ref(get_main_ref_store(the_repository), fn, cb_data);
int for_each_rawref(each_ref_fn fn, void *cb_data)
		  struct object_id *oid, char **log)
 * Create, record, and return a ref_store instance for the specified
}
struct ref_store *get_main_ref_store(struct repository *r)
	struct strbuf dirname = STRBUF_INIT;
}


	const int abbrev_name_len = strlen(abbrev_name);
	struct strbuf real_pattern = STRBUF_INIT;

}
				    const char **string, int *len)

				      &null_oid, flags, msg, err);
	const char *prefix;
	}
{

				       prepare_fn, should_prune_fn,
	if (ret) {
		 */

	 * There is no point in searching for a reference with that
	free(transaction->updates);
{
	 */
	return refs_rename_ref(get_main_ref_store(the_repository), oldref, newref, logmsg);

{
	return refs->be->pack_refs(refs, flags);
	return refs_for_each_branch_ref(get_main_ref_store(the_repository), fn, cb_data);
	return filter->fn(refname, oid, flags, filter->cb_data);
	if (!prefix && !starts_with(pattern, "refs/"))
}
	cb.cnt = cnt;
		return;
	 * `iterator_begin()` already takes care of prefix, but we
{
		 */
				break;
static int write_pseudoref(const char *pseudoref, const struct object_id *oid,


		 * Pre-generate scanf formats from ref_rev_parse_rules[].
			goto out;

	}
}
			c = ' ';
{
	if (cp - refname >= LOCK_SUFFIX_LEN &&
#include "object.h"
		return REF_TYPE_PER_WORKTREE;
	struct ref_storage_be *be = find_ref_storage_backend(be_name);
}
				     void *cb_data)
	case REF_TRANSACTION_CLOSED:
			continue;

		if (read_ref(pseudoref, &actual_old_oid))
	return strcmp(e1->name, name);

	ok = !refs_verify_refname_available(refs, new_refname,

int is_branch(const char *refname)
		BUG("delete called with old_oid set to zeros");
		return 1;
	switch (transaction->state) {
	errno = ELOOP;
{
 * as an error, try to come up with a usable replacement for the input
 * - it ends with ".lock", or
		if (!found)

		if (type < 0 || !object_as_type(the_repository, o, type, 0))
{
	default:
{
					sanitized->buf[sanitized->len-1] = '-';
				   const char *name)

	result = refs_resolve_ref_unsafe(refs, refname, resolve_flags,
	case REF_TRANSACTION_PREPARED:
			if (match_ref_pattern(refname, item))
	int ok;


	if (!iter->ordered)
{
				if (sanitized)
		}
	}
			if (refs_ref_exists(refs, resolved_buf.buf))

			strbuf_addf(err, _("unexpected object ID when writing '%s'"),
 * *string and *len will only be substituted, and *string returned (for
{
	strbuf_release(&err);
		else
	for (i = hide_refs->nr - 1; i >= 0; i--) {
