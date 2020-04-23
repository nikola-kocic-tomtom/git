	if (!ds->fn) {
	}
}
	nth = strtol(name + 3, &num_end, 10);
	struct strbuf err = STRBUF_INIT;
	while (generation--) {
		int ch = *sp;
	const char *match = NULL, *target = NULL;
		if (!ds.ambiguous)
		 */

		if (matches) {
	struct packed_git *p;
	}
	struct object_id candidate;
				      const char *filename,
		if (!(i & 1))
	if (kind != OBJ_TAG)
	struct repository *sort_ambiguous_repo = ctx;
	if (!namelen)
		die(_("path '%s' exists on disk, but not in '%.*s'"),
{
		 *
		if (has_suffix == '^')
struct handle_one_ref_cb {
		return -1;
		 * more than one objects that match the short name
		int ch = *cp;
	const char *suffix[] = { "@{push}" };
				      const struct object_id *tree_oid,
		 */
	int ret;

		mad->cur_len = i + 1;
	if (reflog_len) {
	int i;
	unsigned namelen = strlen(filename);
	} hints[] = {
	else if (starts_with(sp, "object}"))
		return;
	/*
 *
	if (len == r->hash_algo->hexsz && !get_oid_hex(str, oid)) {
	struct packed_git *p;
			negative = 1;
			len = interpret_empty_at(name, namelen, at - name, buf);
		for (i = nth = 0; 0 <= nth && i < reflog_len; i++) {
		return MISSING_OBJECT;
 * through history and returning the first commit whose message starts

	struct object_id outer;
	return 0;
	else {

	for (p = get_packed_git(ds->repo); p && !ds->ambiguous;
			return 0;
	int kind = oid_object_info(r, oid, NULL);
	if (has_suffix) {
			struct pretty_print_context pp = {0};

	}
	 * nearby for the abbreviation length.

static void unique_in_midx(struct multi_pack_index *m,
		b++;
		return -1;

#include "dir.h"
	} while (len > 1);
		len = target - match;
}
		return 0;
static void update_candidates(struct disambiguate_state *ds, const struct object_id *current)
		const struct cache_entry *ce;
		int stage = 0;
							 struct strbuf *),
		if (!match_sha(ds->len, ds->bin_pfx.hash, oid.hash))
	ds.cb_data = (void *)&mad;
			return MISSING_OBJECT;
		}

	 * to see what the name expanded to so that "branch -m" can be
	else if (flags & GET_OID_COMMITTISH)
			return get_parent(r, name, len1, oid, num);
	else {
}
	if (skip_prefix(message, "checkout: moving from ", &match))
	int quietly = !!(flags & GET_OID_QUIETLY);
 * machinery.
			    fullname,
		}

				    oid, &unused);
				if (flags & GET_OID_QUIETLY) {
			if (len > 0)
			    const char *name,
		    name[1] < '0' || '3' < name[1])
		return 0;

					    allowed);
	/* We need to do this the hard way... */
		 */
	 * If we didn't find it, do the usual reprepare() slow-path,

				ret = get_tree_entry(repo, &tree_oid, filename, oid,
			return get_oid_oneline(repo, name + 2, oid, list);
		branch = branch_get(name_str);
	find_short_object_filename(&ds);
	int b_type_sort;

			val = c - 'A' + 10;
	bufno = (bufno + 1) % ARRAY_SIZE(hexbuffer);
			extend_abbrev_len(&oid, mad);
		/* Is it asking for N-th entry, or approxidate? */
	strbuf_add(buf, name + len, namelen - len);
}

	int namelen = strlen(name);
		die(_("path '%s' does not exist (neither on disk nor in the index)"),
		if (nth_midxed_object_oid(&oid, m, first - 1))
static int sort_ambiguous(const void *a, const void *b, void *ctx)
	 * top-level tree of the given commit.
}

	       desc.buf);
	if (!one)
	 * cleverly) do that with modulus, since the enum assigns 1 to

		if (commit) {
		retval = 0;
	for (sp = name + len - 1; name <= sp; sp--) {
								   &tree_oid,
	strbuf_reset(buf);
		timestamp_t at_time;
	int used = buf->len;
	ret = peel_onion(r, name, len, oid, lookup_flags);
			cp = new_path;
		}
		expected_type = OBJ_COMMIT;
		if ('0' <= ch && ch <= '9')

		lookup_flags |= GET_OID_COMMITTISH;
static enum get_oid_result get_short_oid(struct repository *r,
	int cnt;
		update_candidates(ds, current);
		else
				len -= cp - name;

{

		expected_type = OBJ_TREE;
					void *cb_data_unused)
	}

int repo_get_oid_commit(struct repository *r,
		return MISSING_OBJECT;
		branch = branch_get(NULL);
	if (!m->num_objects)
			return 0;
		if (!o || (!o->parsed && !parse_object(r, &o->oid)))
int repo_get_oid_blob(struct repository *r,
 * Note that this does NOT error out when the named object is not a
		 * replaced an earlier candidate that did _not_ pass
{
				if (!(flags & GET_OID_QUIETLY)) {
	strbuf_reset(buf);
{
	bsearch_midx(&ds->bin_pfx, m, &first);

static int disambiguate_commit_only(struct repository *r,
	else if (reflog_len)
		/*
			return ret;
	ret = get_oid_1(r, name, len, &oid, GET_OID_COMMITTISH);
{
 * Call this function when you know "name" given by the end user must
		ds->candidate_exists = 1;
/* parse @something syntax, when 'something' is not {.*} */
			free(tmp);


	return get_oid_with_context(r, name, GET_OID_TREEISH,
		disambiguate_hint_fn fn;
}

		ds.fn = disambiguate_treeish_only;
	}
			    ce_stage(ce), filename);
		    filename);
	 * commit, so tag becomes 0.

	strbuf_addstr(&fullname, filename);
	if (ret)
		}
	 *
			   startup_info->prefix ? strlen(startup_info->prefix) : 0,
	struct strbuf tmp = STRBUF_INIT;

		}
	int i;
			return 0;
				if (!skip_prefix(real_ref, "refs/heads/", &str))
					struct strbuf *buf)
#include "oid-array.h"
static int grab_nth_branch_switch(struct object_id *ooid, struct object_id *noid,

			const char *name,
	if (!num)
	struct handle_one_ref_cb *cb = cb_data;
			}
static unsigned msb(unsigned long val)
	find_short_packed_object(&ds);
	if ((allowed & INTERPRET_BRANCH_REMOTE) &&
	if (warn_ambiguous_refs && !(flags & GET_OID_QUIETLY) &&
	if (!ds->candidate_checked) {
	 * :path -> object name of absolute path in index
	/* otherwise, current can be discarded and candidate is still good */
static int disambiguate_blob_only(struct repository *r,
	has_suffix = 0;
	if (!branch_interpret_allowed(value, allowed))
	sp++; /* beginning of type name, or closing brace for empty */
			ce = repo->index->cache[pos];

	a_type_sort = a_type % 4;
	} else
		cp++;
	 */
	if (!match || !target)
	struct object_id oid_ret;
	strbuf_vaddf(&sb, fmt, ap);
{
	unsigned candidate_checked:1;
		return;
		char *new_path = NULL;
			return -1;
	if (!ret)
	if (num_end != brace)
}
};
		if (!isxdigit(ch)) {
}
	while (list) {
	}
		if (!get_tree_entry(r, tree_oid, fullname, &oid, &mode)) {

}
		oidcpy(&ds->candidate, current);
		if (!nth_packed_object_id(&oid, p, first - 1))
			    fullname,
			}
		return FOUND;
	else
	return get_oid_with_context(r, name, GET_OID_COMMITTISH,
					    allowed);
 * the given regular expression.
			if (flags & GET_OID_FOLLOW_SYMLINKS) {
		strbuf_release(&sb);
#include "midx.h"
		return 0;
	}
			extend_abbrev_len(&oid, mad);

	const struct object_id *oid;
}
		}
	return get_short_oid(r, name, len, oid, lookup_flags);
	 * 0, 1 or more objects that actually match(es).
			    "hint: Did you mean ':%d:%s'?"),
{
	else if (flags & GET_OID_TREE)
			return NULL;
		if (read_ref_at(get_main_ref_store(r),
	const char *brace;
				      const char *name, int len,
		p = strstr(buf, "\n\n");
		ce = istate->cache[pos];
		if (*a != *b)

static int disambiguate_committish_only(struct repository *r,
	else if (starts_with(sp, "blob}"))


	strbuf_release(&sb);
			} else {
				return -1;
				die(_("log for '%.*s' only has %d entries"),
{
}
		free(prefix);
}
	/* basic@{time or number or -number} format to query ref-log */
	return get_oid_with_context(r, name, 0, oid, &unused);
		if (warn_ambiguous_refs && warn_on_object_refname_ambiguity) {
}
static void find_abbrev_len_for_pack(struct packed_git *p,
}
		i++;
	struct strbuf *sb;
			if (refs_found > 0) {
			len = FALLBACK_DEFAULT_ABBREV;

			if (len == namelen)
			refs_for_each_ref(get_main_ref_store(repo), handle_one_ref, &cb);
 * This returns a non-zero value if the string (built using printf

		unsigned long count = repo_approximate_object_count(r);
				  const char *prefix,
		return -1;
}
static int handle_one_ref(const char *path, const struct object_id *oid,
	if (first > 0) {
	return kind == OBJ_COMMIT;
		return 1;
	char *hex;
				     void *cb_data_unused)
	struct strbuf sb = STRBUF_INIT;
		}
{
		if (ce_namelen(ce) == namelen &&
						     cp, len, oid, flags);
	return MISSING_OBJECT;
{
				  void *cb_data)
	}
		}
		 * that we previously discarded in the reverse order,
	if (!prefix)

	else

			pos++;

static enum get_oid_result get_nth_ancestor(struct repository *r,

	struct disambiguate_state ds;
	}
	struct repository *repo;
			 struct object_id *oid)
	return 0;
{
				    len, str, co_cnt);
		return;
		return -1;
 * you have a chance to diagnose the error further.
			detached = (buf.len == r->hash_algo->hexsz && !get_oid_hex(buf.buf, oid));

		else if (c >= 'A' && c <='F') {
			bracket_depth--;
				break;
{
			struct commit_list *list = NULL;
			return 0;
 */
	return retval;
		return ret;
/*
		 * not including the value of all the _other_ bits (so "15"
	if (!ds->candidate_ok) {
	find_abbrev_len_packed(&mad);
static int finish_object_disambiguation(struct disambiguate_state *ds,
		ds->ambiguous = ds->fn(ds->repo, current, ds->cb_data) ? 1 : 0;
			struct handle_one_ref_cb cb;
	}
{
	int ret, bracket_depth;

	/*
/*

	if (ds->fn(ds->repo, current, ds->cb_data)) {
		 */
		oidcpy(&ds->candidate, current);
	unsigned disambiguate_fn_used:1;
		} else {
			}
	       repo_find_unique_abbrev(ds->repo, oid, DEFAULT_ABBREV),
	return FOUND;
};
	struct object_id oid_tmp;
	if (!object)


/* Must be called only when :stage:filename doesn't exist. */
		{ "committish", disambiguate_committish_only },


static int branch_interpret_allowed(const char *refname, unsigned allowed)
			    filename, stage,

	if (next != name + 1)
	int at, reflog_len, nth_prior = 0;
			new_filename = resolve_relative_path(repo, filename);

		commit_list_insert(l->item, &backup);
				real_ref, flags, at_time, nth, oid, NULL,
	strbuf_release(&desc);
{
	return ret;

	 */
	for (m = get_multi_pack_index(mad->repo); m; m = m->next)

/*
		if (!len) {
			else

}
			oidcpy(oid, &commit->object.oid);
}
		 * disambiguate.
	return a_type_sort > b_type_sort ? 1 : -1;
				cp++;
	struct object_id oid;
		error(_("short SHA1 %s is ambiguous"), ds.hex_pfx);
	 */
/*
			if (only_to_die)
int repo_for_each_abbrev(struct repository *r, const char *prefix,
					 unsigned flags)
{
		return ret;

	struct object_id oid;
	int only_to_die = flags & GET_OID_ONLY_TO_DIE;
			}
	if (regcomp(&regex, prefix, REG_EXTENDED))
	if (!o)
		next = name + namelen;
		    !memcmp(ce->name, filename, namelen))
		return -1;
			BUG("show_ambiguous_object shouldn't return non-zero");
	struct object_context unused;
	if (pos < istate->cache_nr) {
	int a_type_sort;
				break;
			return -1;
	if (HAS_MULTI_BITS(flags & GET_OID_DISAMBIGUATORS))
						     &oc->mode);
}
 * probably not a big deal here.
	unsigned int init_len;
	oidcpy(result, &commit->object.oid);
		return;
					const struct object_id *oid,
				      struct object_id *result, int idx)
static int interpret_nth_prior_checkout(struct repository *r, const char *name, int namelen, struct strbuf *buf);

		find_short_object_filename(&ds);
		else {
			break;
			default_disambiguate_hint = hints[i].fn;
		else if (o->type == OBJ_COMMIT)
		if (!parse_tag(tag) && tag->tag)
	 * name; builtin/branch.c::copy_or_rename_branch() still wants
}
		default:
		} else {
		return;
			refs_head_ref(get_main_ref_store(repo), handle_one_ref, &cb);
				  struct object_context *oc)
int repo_get_oid_committish(struct repository *r,
		if (expected_type == OBJ_ANY || o->type == expected_type)
 * commit-ish. It is merely to give a hint to the disambiguation
		return st;
	ret = get_describe_name(r, name, len, oid);
typedef int (*disambiguate_hint_fn)(struct repository *, const struct object_id *, void *);
		struct commit *commit;
			}
		if (interpret_nth_prior_checkout(r, str, len, &buf) > 0) {
	} else if (type == OBJ_TAG) {
	/*
		expected_type = OBJ_COMMIT;


	}
		return SHORT_NAME_AMBIGUOUS;
	 * barf.

	int remaining;
{
{
		 * We now know we have on the order of 2^len objects, which

			o = &(repo_get_commit_tree(r, ((struct commit *)o))->object);

				      struct disambiguate_state *ds)
	/* make sure it's a single @, or @@{.*}, not @foo */
				if (str[at+2] == '-') {
 * abbreviated object names between commit-ish and others.
	/* Accept only unambiguous ref paths. */
	}
{
		    struct object_id *oid)
static void unique_in_pack(struct packed_git *p,
		if (!new_path) {
	return 0;
			if (str[at] == '@' && str[at+1] == '{') {
			 const char *name,
	struct strbuf fullname = STRBUF_INIT;

{
		ds->disambiguate_fn_used = 1;
					    upstream_mark, branch_get_upstream,
		ds.fn = disambiguate_tree_only;
	 * :/foo -> recent commit matching foo
		char *name_str = xmemdupz(name, at);
			if (at_time) {
	}
	if (parse_commit(commit))
		st = repo_get_oid(r, "HEAD", &oid_tmp);
#include "repository.h"
				  void *data)
{
	obj = deref_tag(r, parse_object(r, oid), NULL, 0);


	 * oid_array_for_each_unique() would do.
	free_commit_list(list);
		 * Add one because the MSB only tells us the highest bit set,
	 * dereference anymore, or you get an object of given type,
	num = m->num_objects;
				      "dereferences to %s type",
};

			char *tmp = xstrndup(str + at + 2, reflog_len);
	if (!starts_with(rel, "./") && !starts_with(rel, "../"))
		while (!ds->ambiguous && pos < loose_objects->nr) {
	}
	}

	mbs = repo_get_merge_bases(r, one, two);
		/* the same as what we already have seen */
	"running \"git config advice.objectNameWarning false\"");
			die(_("path '%s' exists, but not '%s'\n"
	one = lookup_commit_reference_gently(r, &oid_tmp, 0);

{
	strbuf_reset(buf);
 * Return the slot of the most-significant bit set in "val". There are various
	if (!len)
	}
	type = oid_object_info(ds->repo, oid, NULL);
				return 0;
	match = bsearch_midx(mad_oid, m, &first);
	     (at = memchr(start, '@', namelen - (start - name)));
				  const struct object_id *oid,

 *
	const char *cp;
	if (i < GIT_MAX_RAWSZ && i >= mad->cur_len)
	if ((pos & 1) == 0)
			stage = name[1] - '0';

			if (name)
#include "tag.h"
{
	get_oid_with_context_1(r, name, GET_OID_ONLY_TO_DIE,
	if (only_to_die)
			char *new_filename = NULL;

			    object_name_len, object_name,
static int get_oid_oneline(struct repository *r,
	status = finish_object_disambiguation(&ds, oid);
		unique_in_pack(p, ds);
			continue;

	lookup_flags &= ~GET_OID_DISAMBIGUATORS;
		{ "treeish", disambiguate_treeish_only },
	int st;
	if (!brace)
		struct commit_list *list = NULL;
		if (flags & GET_OID_RECORD_PATH)

		strbuf_addstr(sb, name);
	 * The object_type enum is commit, tree, blob, tag, but we

			  const char **suffix, int nr)
	if (object->type == OBJ_TAG) {
	/* It could be describe output that is "SOMETHING-gXXXX" */
			die(_("path '%s' is in the index, but not at stage %d\n"

		find_short_packed_object(&ds);
	pos = index_name_pos(istate, filename, namelen);
	 */
		int ret;
	struct object *obj;
	const char *value;
	 * with an object name that could match "bin_pfx".  See if we have
	next = memchr(name + len + 1, '@', namelen - len - 1);
			oidcpy(result, &p->item->object.oid);
		expected_type = OBJ_ANY;
	if (0 < retval) {
		return -1;
		strbuf_branchname(sb, name, INTERPRET_BRANCH_LOCAL);
	 * At this point, "first" is the location of the lowest object
				    oid, &unused);
	uint32_t num, first = 0;

{
	 * "name~3" is "name^^^", "name~" is "name~1", and "name^" is "name^1".
			     const char *name, int len,
/* Remember to update object flag allocation in object.h */
		int co_tz, co_cnt;
	else if (sp[0] == '/')
	return 0;
}
		warning(warn_msg, len, str);
						   allowed);


		prefix++;
		    && !strncasecmp(string, suffix[i], suffix_len))
				 const char *(*get_data)(struct branch *,

		      const char *name,

			val = c - '0';
	/* that data was not interpreted, remove our cruft */
	mad.init_len = len;
{
}




			continue;
	int refs_found = 0;
	int match = 0;
		oidcpy(oid, &mbs->item->object.oid);
		 * given, so we should make sure this one matches;
		return 1;
static void sort_ambiguous_oid_array(struct repository *r, struct oid_array *a)
		int len = cp - name;
#include "submodule.h"
			break;
		if (ch == '{' && name < sp && sp[-1] == '^')
	static const char hex[] = "0123456789abcdef";
	return 0;
	int negative = 0;
		}
		else if (c >= 'a' && c <= 'f')
				 unsigned allowed)
	return slash;
	}
	if (flags & GET_OID_COMMIT)
	free_commit_list(mbs);
	if (object->type != OBJ_COMMIT)
	const char *sp;
		}
	repo_find_unique_abbrev_r(r, hex, oid, len);
	if (!idx) {
		if (!nth_packed_object_id(&oid, p, first + 1))
	 */
			free(new_filename);
				oc->path = xstrdup(filename);

void maybe_die_on_misspelt_object_name(struct repository *r,
	if (!quietly && (status == SHORT_NAME_AMBIGUOUS)) {
					if (at != 0)
	oid_to_hex_r(hex, oid);
								   name, len);
		return -1;
	unsigned always_call_fn:1;
	if (ds->ambiguous)
					const char *name, int namelen,
	find_short_object_filename(&ds);
	 * 0, 1 or more objects that actually match(es).
	struct object_context unused;
	int ret, has_suffix;

		r++;
	if (*name == '-' ||

#include "tree-walk.h"
	} else if (first < num - 1) {
			num *= 10;
 */

int get_oidf(struct object_id *oid, const char *fmt, ...)
		st = 0;


	 * first is now the position in the packfile where we would insert
		unsigned sub_flags = flags;
	}
		return -1;

	struct object_id oid;
	 * mad->hash if it does not exist (or the position of mad->hash if



	"\n"
	}

static int interpret_nth_prior_checkout(struct repository *r,
	if (!ds->candidate_exists) {
	struct commit *one, *two;
	enum get_oid_result ret = get_oid_1(r, name, len, &oid,
				  const char *email, timestamp_t timestamp, int tz,
#include "commit-reach.h"
		/* cannot disambiguate between ds->candidate and current */
	}
{
	 */
		loose_objects = odb_loose_cache(odb, &ds->bin_pfx);
	 * if we do not get the needed object, we should

		timestamp_t co_time;
	/* we have extra data, which might need further processing */

		unique_in_midx(m, ds);
		unsigned char c = name[i];
}
	if (p->multi_pack_index)
			commit_list_sort_by_date(&list);
		      struct object_id *oid)
		return 0;
	if (init_object_disambiguation(r, name, len, &ds) < 0)

		st = -1;
		if (len > 0)
		ret = get_oid_oneline(r, prefix, oid, list);
struct disambiguate_state {
					exit(128);
		 * expects a collision at 2^(len/2). But we also care about hex
 * notably "xyz^" for "parent of xyz"
		struct object_id oid;

 */


}
		commit = commit->parents->item;
		struct object_id oid;
			prefix++;
}
	else if (flags & GET_OID_TREEISH)
		return 1;
	if (sp <= name)
	}
		expected_type = OBJ_TAG;
		refs_found = repo_dwim_ref(r, "HEAD", 4, oid, &real_ref);
				free(real_ref);
		char *prefix;
		      const char *name,
				break;
			   const char *prefix, struct object_id *oid,
					 struct object_id *oid,

			struct object_id *oid)
		return -1;
		return FOUND;
			/* We must be looking at g in "SOMETHING-g"
static inline int at_mark(const char *string, int len,

	const char *cp;
	len = get_mark(name + at, namelen - at);
			unsigned int digit = *cp++ - '0';
					    int generation)
	if (at) {
		return -1;
	unsigned int i = mad->init_len;
		return ret;
				return len; /* consumed all */
		return;
	return mad.cur_len;
	int slash = 1;
	int len; /* length of prefix in hex chars */
			     struct object_id *oid)

				  const struct object_id *oid,
static void diagnose_invalid_index_path(struct repository *r,
	const struct disambiguate_state *ds = data;
{

	}
		return -1;
	"examine these refs and maybe delete them. Turn this message off by\n"
				}
 * For a literal '!' character at the beginning of a pattern, you have to repeat
					 struct object_context *oc)
 * if successful; otherwise signal an error with negative value.
					    struct object_id *result,
			cp = name + 3;
	unsigned int expected_type = 0;
			}
		prefix = xstrndup(sp + 1, name + len - 1 - (sp + 1));
	}
		return -1;


	for (l = backup; l; l = l->next)
static inline char get_hex_char_from_oid(const struct object_id *oid,
			 each_abbrev_fn fn, void *cb_data)
{
		return hex[oid->hash[pos >> 1] & 0xf];
	 * used as a tool to correct earlier mistakes.
				  void *cb_data_unused)

		sub_flags &= ~GET_OID_DISAMBIGUATORS;
		ds->candidate_checked = 1;
		len = interpret_nth_prior_checkout(r, name, namelen, buf);
	struct min_abbrev_data *mad = cb_data;
			extend_abbrev_len(&oid, mad);
	mad.hex = hex;
		/*
			namelen = namelen - (cp - name);
int repo_find_unique_abbrev_r(struct repository *r, char *hex,
				      namelen, name, type_name(expected_type),

	if (is_missing_file_error(errno)) {

		struct strbuf buf = STRBUF_INIT;
	if (ret < 0) {
	if (first > 0) {
static enum get_oid_result get_oid_with_context_1(struct repository *repo,
	 * :./path -> object name of path relative to cwd in index
	if (len && ambiguous_path(str, len))
		refs_found = repo_dwim_log(r, str, len, oid, &real_ref);
	if (--(cb->remaining) == 0) {

		    name[2] != ':' ||
			strbuf_release(&buf);
		    filename, object_name_len, object_name);
}

	}
		      struct object_id *oid, unsigned lookup_flags)

	/*
		oidcpy(oid, &o->oid);
{
		}
				free(new_path);
{
	else if (starts_with(sp, "tree}"))
			return FOUND;
					&oc->mode);
		ds->bin_pfx.hash[i >> 1] |= val;


		/*
struct min_abbrev_data {
		if (o->type == OBJ_TAG)
		return -1;
{
	if (p->multi_pack_index)
					filename, oid, &oc->symlink_path,
/*

		return 0;
	const struct object_id *mad_oid;
			   struct disambiguate_state *ds)
		if (!allowed || (allowed & INTERPRET_BRANCH_HEAD)) {
		st = repo_get_oid_committish(r, sb.buf, &oid_tmp);
	strbuf_init(&oc->symlink_path, 0);
	commit_list_insert((struct commit *)object, list);
}
	ds.fn = repo_collect_ambiguous;
				  const char *name,
	 * sha1:path --> object name of path in ent sha1
	hex[mad.cur_len] = 0;
}
		return SHORT_NAME_AMBIGUOUS;
	int len = strlen(name);
}
	mad->init_len = mad->cur_len;
				return 0;
			continue;
	strbuf_release(&tmp);
	int kind;
}
			if (slash)
		expected_type = OBJ_BLOB;
		return;
	static const char *object_name_msg = N_(

		len = interpret_branch_mark(r, name, namelen, at - name, buf,
	if (!o)

	return extend_abbrev_len(oid, cb_data);
			diagnose_invalid_index_path(repo, stage, prefix, cp);
				break;
		if (oid_array_for_each(&collect, show_ambiguous_object, &ds))
	/*
		       const char *name, int namelen, int len,
				filename = new_filename;

	if (get_oid_1(r, name, sp - name - 2, &outer, lookup_flags))
	return get_oid_with_context(r, name, GET_OID_TREE,
		return 0;
	return 1;
			format_commit_message(commit, " %ad - %s", &desc, &pp);
			 struct object_id *oid, unsigned int flags)
				}
	if (len < 0) {
	 * it does exist). Hence, we consider a maximum of two objects

				}
		o = deref_tag(r, o, name, sp - name - 2);
		return NULL;
		refs_found = repo_dwim_ref(r, str, len, oid, &real_ref);
			strbuf_addf(&desc, " %s", tag->tag);
		struct strbuf sb;

	return 0;
{
{
{
	kind = oid_object_info(r, oid, NULL);

			    object_name_len, object_name,

		object = deref_tag(cb->repo, object, path,
{
	 * :[0-3]:path -> object name of path in index at stage
		int suffix_len = strlen(suffix[i]);
			num += digit;
			return NULL;
				    const struct object_id *oid,
#include "packfile.h"
	 * At this point, "first" is the location of the lowest object
	struct object_id oid;
	return at_mark(string, len, suffix, ARRAY_SIZE(suffix));
	while (p) {
	}
	strbuf_addstr(buf, s);
static int match_sha(unsigned, const unsigned char *, const unsigned char *);
	if (!value)
	if (pos < 0)
		}
				    int len)
	if (obj && obj->type == OBJ_COMMIT)
		 * function entirely.
		unuse_commit_buffer(commit, buf);
	kind = oid_object_info(r, oid, NULL);
	 * it does exist). Hence, we consider a maximum of two objects
		free(name_str);
	struct branch *branch;
	const char *start;

	int ret;
		unsigned int num = 0;
		char ch = *cp;
		return 1;
	else
			    filename,
		int pos;
		namelen = strlen(name);
{

#include "config.h"
		ds->candidate_ok = (!ds->disambiguate_fn_used ||
		return -1;
		/*
	return ret;

		 * the disambiguation hint callback, then we do have
		return FOUND;
		ds.fn = disambiguate_blob_only;
{
				&co_time, &co_tz, &co_cnt)) {

		/* "$commit^{/foo}" */

		strbuf_reset(cb->sb);
	long nth;
	(void)finish_object_disambiguation(&ds, &oid_ret);
}
	"\n"
	if (!next)

	return 0;
static enum get_oid_result get_oid_1(struct repository *r,
	for (i = 0; i < ARRAY_SIZE(hints); i++) {
	    starts_with(refname, "refs/heads/"))
	for (i = first; i < num && !ds->ambiguous; i++) {
		struct object_id tree_oid;
			oid = loose_objects->oid + pos;
	struct object_context unused;
	for (cp = name + len - 1; name + 2 <= cp; cp--) {

int repo_get_oid_tree(struct repository *r,
				oc->mode = ce->ce_mode;
}
	if (prefix[0] == '!') {
		flags |= GET_OID_QUIETLY;
			pos++;
	if (startup_info->have_repository)
				}
}
		return 1; /* we are done */
	}
				       const char *prefix)
	 * "ref^{commit}".  "commit^{tree}" could be used to find the
					nth_prior = 1;
	     start = at + 1) {

		 * For very small repos, we stick with our regular fallback.
 * function allows the machinery to disambiguate shorter-than-unique
			    "hint: Did you mean '%.*s:%s' aka '%.*s:./%s'?"),
	return prefix_path(startup_info->prefix,
{
		if (100000000 <= nth) {

		if (ce_namelen(ce) == fullname.len &&
{
		update_candidates(ds, &oid);
	int kind = oid_object_info(r, oid, NULL);
	for (cp = name, bracket_depth = 0; *cp; cp++) {
	if (kind != OBJ_TAG)
	 */

				  const struct object_id *oid,
					 const char *name, int len,
	o = repo_peel_to_type(r, name, len, o, expected_type);
		return -1;

			cb.list = &list;
};
static enum get_oid_result get_oid_1(struct repository *r, const char *name, int len, struct object_id *oid, unsigned lookup_flags);
	}
	struct disambiguate_state ds;
{
	mad_oid = mad->oid;
				oidcpy(oid, &ce->oid);
		int pos;
}

	if (!ret)
	if (!allowed || (allowed & INTERPRET_BRANCH_LOCAL)) {
		return -1;
	strbuf_splice(sb, 0, 0, "refs/heads/", 11);
static char *resolve_relative_path(struct repository *r, const char *rel)



	 */
			at_time = approxidate_careful(tmp, &errors);
			extend_abbrev_len(&oid, mad);

	if (kind == OBJ_TREE || kind == OBJ_COMMIT)
	if (!value)
		char *fullname = xstrfmt("%s%s", prefix, filename);
		if (pos < 0)
			bracket_depth++;
 * name an object but it doesn't; the function _may_ die with a better
		strbuf_init(&sb, dots - name);
	struct object_directory *odb;
}
			   rel);
	}
		int nth, i;
				error("%.*s: expected %s type, but the object "
				      const char *name, int len,
		find_abbrev_len_for_pack(p, mad);
	size_t len;

		}
		    const char *name,

		return -1;
			       prefix, &oid, &oc);

	if (ds->always_call_fn) {
	uint32_t num, first = 0;

				  const struct object_id *oid,
		/* allow "@{...}" to mean the current branch reflog */
				nth = -1;
static void find_abbrev_len_packed(struct min_abbrev_data *mad)
	struct grab_nth_branch_switch_cbdata cb;
		nth_packed_object_id(&oid, p, i);
	set_shortened_ref(r, buf, value);
static int ambiguous_path(const char *path, int len)

			return len;
					    const char *name, int len,
	if (!match) {
	for (cnt = 0; cnt < len; cnt++) {
	ret = oid_array_for_each_unique(&collect, fn, cb_data);

	else if (flags & GET_OID_BLOB)
/*

		case '\0':
	}
		/*

	/*
 * Parse @{-N} syntax, return the number of characters parsed

{

	if (!mbs || mbs->next)
 * diagnostic message than "no such object 'name'", e.g. "Path 'doc' does not
		if (!repo->index || !repo->index->cache)
 * For future extension, all other sequences beginning with ':/!' are reserved.
{

		}

	b_type_sort = b_type % 4;
		new_path = resolve_relative_path(repo, cp);
		else {
		{ "blob", disambiguate_blob_only }
static inline int upstream_mark(const char *string, int len)
		/*
		prefix = "";

						/* @{-N} not at start */

	struct object_id tmp_oid;
			   struct disambiguate_state *ds)
	uint32_t num, i, first = 0;
{
			if (ce_stage(ce) == stage) {
				     struct min_abbrev_data *mad)
	if (!ds->candidate_exists)
		} else if (prefix[0] != '!') {
		BUG("incompatible flags for get_sha1_with_context");
		return get_nth_ancestor(r, name, len1, oid, num);
	int used = interpret_branch_name(name, len, sb, allowed);
		len = DIV_ROUND_UP(len, 2);
const char *repo_find_unique_abbrev(struct repository *r,
	if (!ds->candidate_checked)
	return ret - used + len;
	strbuf_add(buf, "HEAD", 4);
}
		if (c >= '0' && c <= '9')
			if (detached)
	struct object *o;
static void find_abbrev_len_for_midx(struct multi_pack_index *m,
{
		clear_commit_marks(l->item, ONELINE_SEEN);

		die("%s", err.buf);
	else if (sp[0] == '}')
	return 0;
	struct commit_list *mbs;
static int interpret_empty_at(const char *name, int namelen, int len, struct strbuf *buf)
			break;
	 */
					str = "HEAD";

{
		} else if (0 <= nth)
#include "cache.h"
}
		BUG("multiple get_short_oid disambiguator flags");
	if (dots == name)

	 */
	"may be created by mistake. For example,\n"
		}

	if (len || name[1] == '{')
	mad.oid = oid;
	const char *cp;


	num = p->num_objects;

			break;
	do {
	unsigned candidate_exists:1;
	commit = lookup_commit_reference(r, &oid);
				  struct object_id *oid,
int repo_get_oid(struct repository *r, const char *name, struct object_id *oid)
			refs_found = repo_dwim_ref(r, str, len, &tmp_oid, &real_ref);
		if (ch == '~' || ch == '^')
	if (!match) {
	if (r != the_repository || !is_inside_work_tree())
			if (unsigned_mult_overflows(num, 10))
	struct index_state *istate = r->index;
		struct oid_array collect = OID_ARRAY_INIT;

	if (*cp == ':') {
		 * If this is the only candidate, there is no point
	while (val >>= 1)
				warning(warn_msg, len, str);
				      type_name(o->type));

		struct commit *commit = lookup_commit(ds->repo, oid);
				     struct object_id *oid,
	 * nearby for the abbreviation length.
	if (a_type == b_type)
		return 0;
	const char *dots;

			at_time = nth;

				     const struct object_id *oid,
					 unsigned flags,
	 * At this point, the syntax look correct, so
	}
					reflog_len = (len-1) - (at+2);
	 * This splice must be done even if we end up rejecting the
	if (nth_prior) {

					len = at;
		/*
		 * candidates that did not satisfy our hint function. In
					diagnose_invalid_oid_path(repo, prefix,
struct grab_nth_branch_switch_cbdata {
	if (name[0] != '@' || name[1] != '{' || name[2] != '-')
			int errors = 0;
				return reinterpret(r, name, namelen, len, buf, allowed);
			o = ((struct tag*) o)->tagged;
	retval = refs_for_each_reflog_ent_reverse(get_main_ref_store(r),
 * This is like "get_oid_basic()", except it allows "object ID expressions",
static int reinterpret(struct repository *r,

				     const char *name, int len,
	unsigned candidate_ok:1;
		ds->ambiguous = 1;
	if (init_object_disambiguation(r, hex, mad.cur_len, &ds) < 0)

		if ((*a ^ *b) & 0xf0)
		    !memcmp(ce->name, fullname.buf, fullname.len))
		const char *name;
		return -1;
 *
	struct object_id bin_pfx;
}
		/* else if (has_suffix == '~') -- goes without saying */

	char *at;
	};
	return -1;
	obj = deref_tag(r, parse_object(r, oid), NULL, 0);
				 const char *name, int namelen,
		return hexsz;
	unsigned int cur_len;
		int detached;
}
	if (!two)
	find_short_packed_object(&ds);
		prefix = "";
		if (!only_to_die && namelen > 2 && name[1] == '/') {
/* Must be called only when object_name:filename doesn't exist. */
	return found ? 0 : -1;
			if (ce_namelen(ce) != namelen ||
	/*
	int ret;
				    oid, &unused);
			return suffix_len;
{
	p = commit->parents;
		 * otherwise, if we discovered this one and the one
	if (next && next[1] != '{')
		while (pos < repo->index->cache_nr) {

	if (init_object_disambiguation(r, prefix, strlen(prefix), &ds) < 0)

	free_commit_list(backup);
	return len + at;
	 * want tag, commit, tree blob. Cleverly (perhaps too
				       const char *name,

		switch (*path++) {
			at_time = 0;
	mad.repo = r;
}
{
		return -1;
	return kind == OBJ_TREE;
		find_abbrev_len_for_midx(m, mad);

			    ce_stage(ce), filename);
		return 1;

	struct multi_pack_index *m;
static enum get_oid_result get_parent(struct repository *r,
		 * if both current and candidate satisfy fn, we cannot
			continue;
					 unsigned int pos)
	if (status == MISSING_OBJECT) {
	if (len < MINIMUM_ABBREV || len > the_hash_algo->hexsz)
{
		if (!num && len1 == len - 1)

	if (!refs_found)
			cb.repo = repo;

}
}
static int match_sha(unsigned len, const unsigned char *a, const unsigned char *b)
		pos = oid_array_lookup(loose_objects, &ds->bin_pfx);
#include "object-store.h"
		return -1;
	 * tags until you get a non-tag.  "ref^0" is a shorthand for

		strbuf_add(cb->sb, match, len);
			       unsigned allowed)
	}
	int b_type = oid_object_info(sort_ambiguous_repo, b, NULL);
	struct commit *commit;
			} else {
static int get_oid_basic(struct repository *r, const char *str, int len,
	regfree(&regex);
	if (ds->fn && !ds->fn(ds->repo, oid, ds->cb_data))
	static int bufno;
		matches = negative ^ (p && !regexec(&regex, p + 2, 0, NULL, 0));
{
		if (!o || (!o->parsed && !parse_object(r, &o->oid)))

	strbuf_add(sb, name + used, len - used);
	 */
			extend_abbrev_len(&oid, mad);
		expected_type = OBJ_NONE;
		ds->candidate_ok = ds->fn(ds->repo, &ds->candidate, ds->cb_data);
	/* Confusion between relative and absolute filenames? */
	}
	}
	disambiguate_hint_fn fn;
			extend_abbrev_len(&oid, mad);
		p = p->next;
	int ret;
		ds.fn = disambiguate_commit_only;

		if (!match_sha(ds->len, ds->bin_pfx.hash, current->hash))
		return -1;
		return FOUND;
		if (!parse_object(r, &commit->object.oid))
	return -1;
int repo_interpret_branch_name(struct repository *r,
		strbuf_add(&sb, name, dots - name);

	"  git switch -c $br $(git rev-parse ...)\n"
	match = bsearch_pack(mad_oid, p, &first);
			found = 1;
		if (nth_midxed_object_oid(&oid, m, first + 1))
	 * or migrated from loose to packed.
{
	 * whichever comes first.  "ref^{}" means just dereference
	}
	return hex;
			continue;

	const char *suffix[] = { "@{upstream}", "@{u}" };
	int found = 0;

					const char *filename)
	/* tweak for size of {-N} versus expanded ref name */
		free(new_path);
		}
						show_date(co_time, co_tz, DATE_MODE(RFC2822)));
	struct object_context unused;
	return check_refname_format(sb->buf, 0);

}
		if (*cp == '{')
	if (st)
	if (!len && reflog_len)
{
{
				    oid, &unused);
			val = c - 'a' + 10;
	}
		commit = pop_most_recent_commit(&list, ONELINE_SEEN);
	ds.cb_data = &collect;
			    ce_stage(ce), fullname.buf,
	}
static void find_short_packed_object(struct disambiguate_state *ds)
			die(_("path '%s' is in the index, but not '%s'\n"
	if (type == OBJ_COMMIT) {
		if (len < FALLBACK_DEFAULT_ABBREV)
	}
			    memcmp(ce->name, cp, namelen))
static inline int push_mark(const char *string, int len)
	/*
{

	char *hex = hexbuffer[bufno];
struct object *repo_peel_to_type(struct repository *r, const char *name, int namelen,
		len -= 2;
{
		return -1;
static int show_ambiguous_object(const struct object_id *oid, void *data)
}
	return get_oid_with_context_1(repo, str, flags, NULL, oid, oc);
	return status;

	}
		 * calling the disambiguation hint callback.
	return kind == OBJ_BLOB;
				if (advice_object_name_warning)
	int a_type = oid_object_info(sort_ambiguous_repo, a, NULL);
	if (namelen < 4)
	if (sp[0] == '/') {
enum get_oid_result get_oid_with_context(struct repository *repo,
	/*
	if (!allowed)
		return -1;
			if (unsigned_add_overflows(num, digit))
		return MISSING_OBJECT;
		 * that case, we still want to show them, so disable the hint
void strbuf_branchname(struct strbuf *sb, const char *name, unsigned allowed)
	while (mad->hex[i] && mad->hex[i] == get_hex_char_from_oid(oid, i))
	return get_oid_with_context(r, name, GET_OID_BLOB,
		die(_("relative path syntax can't be used outside working tree"));

	/* if we reach this point, we know ds->candidate satisfies fn */
static int repo_collect_ambiguous(struct repository *r,
	struct object *obj;
static void find_short_object_filename(struct disambiguate_state *ds)

			slash = 1;
			 * for it to be describe output.
	ret = repo_interpret_branch_name(r, buf->buf, buf->len, &tmp, allowed);

	if (open_pack_index(p) || !p->num_objects)
		} else if (len > 0) {

		else {
			  int flag, void *cb_data)
	va_end(ap);
	unsigned ambiguous:1;
		return repo_get_oid(r, name, oid);
		lookup_flags |= GET_OID_TREEISH;
	struct commit_list *p;
	if (len == hexsz || !len)
	ds.always_call_fn = 1;
			return len;
		commit_list_insert((struct commit *)o, &list);
		}
	int match = 0;
 * syntactical positions where the object name appears.  Calling this
	oid_array_clear(&collect);
	const struct object_id *current = NULL;
	 * first is now the position in the packfile where we would insert
			slash = 0;
		return -1;
	if (len && str[len-1] == '}') {
			if (ch == 'g' && cp[-1] == '-') {
 * Many callers know that the user meant to name a commit-ish by
	return r;
				nth = nth * 10 + ch - '0';

	ds->hex_pfx[len] = '\0';
			free(real_ref);
			"HEAD", grab_nth_branch_switch, &cb);
	dots = strstr(name, "...");
		/* discard the candidate; we know it does not satisfy fn */
	return error("unknown hint type for '%s': %s", var, value);
	else if (expected_type == OBJ_TREE)
	if (ret)
			val <<= 4;
	} else if (oideq(&ds->candidate, current)) {
}
	}
 */
			update_candidates(ds, oid);
		if (!--idx) {
			c -= 'A' - 'a';
					fprintf(stderr, "%s\n", _(object_name_msg));
		oidcpy(result, &commit->object.oid);
int strbuf_check_branch_ref(struct strbuf *sb, const char *name)
			return o;

	if (kind == OBJ_COMMIT)
		else if (num > INT_MAX)
					int stage,
			namelen = strlen(cp);
			    filename);
		reprepare_packed_git(r);
		ds.fn = default_disambiguate_hint;
	int kind;
	while (1) {
	cb.sb = buf;
				      const char *object_name,
		 * we would end up showing different results in the
		}
	struct strbuf desc = STRBUF_INIT;

{

	free(real_ref);
				return MISSING_OBJECT;
		return ret;
		return -1;
}
	memset(oc, 0, sizeof(*oc));
	return st;
		if (namelen < 3 ||
		pos = index_name_pos(repo->index, cp, namelen);
	if ((allowed & INTERPRET_BRANCH_LOCAL) &&
	va_list ap;
	 */
				     struct min_abbrev_data *mad)
 * ways to do this quickly with fls() or __builtin_clzl(), but speed is

					warning(_("log for '%.*s' only goes back to %s"),
		}
	bsearch_pack(&ds->bin_pfx, p, &first);
		 */
{
		if (prefix[0] == '-') {
	int kind = oid_object_info(r, oid, NULL);
	}
		 * $commit^{/}. Some regex implementation may reject.


static int init_object_disambiguation(struct repository *r,
int repo_get_oid_mb(struct repository *r,

		return -1;
	if (!ret)
	mad->init_len = 0;
	     !get_short_oid(r, str, len, &tmp_oid, GET_OID_QUIETLY)))
	}
	if (nth <= 0)
			       const char *name, int namelen,
	if (!commit)
			nth = -1;

				 struct object *o, enum object_type expected_type)
			 */
static int disambiguate_tree_only(struct repository *r,
		if (only_to_die && name[1] && name[1] != '/')
			}
	two = lookup_commit_reference_gently(r, &oid_tmp, 0);
		}
			oc->path = xstrdup(cp);
	advise("  %s %s%s",
	strbuf_addstr(&fullname, prefix);
		unsigned char val;
	const struct cache_entry *ce;
/*
		 * On the other hand, if the current candidate
	struct repository *repo;
}
 * that, like: ':/!!foo'
	oid_array_append(data, oid);
				  unsigned flags,
}
}
	struct repository *repo;
	return get_oid_with_context(r, name, GET_OID_COMMIT,
		 */
}
		return -1;
	/* Wrong stage number? */
		ce = istate->cache[pos];
	unsigned flags = GET_OID_QUIETLY | GET_OID_COMMIT;
		buf = get_commit_buffer(commit, NULL);
			char ch = str[at+2+i];
		ds->candidate_checked = 0;
	for (p = get_packed_git(mad->repo); p; p = p->next)
	commit = lookup_commit_reference(r, &oid);
				if (!upstream_mark(str + at, len - at) &&
		while (cp < name + len) {
				   strlen(path));
			repo_read_index(repo);
			const char *filename = cp+1;
		 * chars, not bits, and there are 4 bits per hex. So all
	for (m = get_multi_pack_index(ds->repo); m && !ds->ambiguous;
		 */
		if (suffix_len <= len
	va_start(ap, fmt);
static int get_oid_oneline(struct repository *r, const char *, struct object_id *, struct commit_list *);
	const unsigned hexsz = r->hash_algo->hexsz;
		return config_error_nonbool(var);
	ret = get_oid_basic(r, name, len, oid, lookup_flags);
	int retval;

		return;
		return;
	    (refs_found > 1 ||
	}

		advise(_("The candidates are:"));


	int pos;
int set_disambiguate_hint_config(const char *var, const char *value)
	ds.always_call_fn = 1;
		ds->hex_pfx[i] = c;
		used = 0;
	if (pos < 0)
	if (obj && (obj->type == OBJ_TREE || obj->type == OBJ_COMMIT))
			const struct object_id *oid;
				    !push_mark(str + at, len - at)) {
				die(_("invalid object name '%.*s'."), len, name);
	num = m->num_objects;
static void set_shortened_ref(struct repository *r, struct strbuf *buf, const char *ref)
}
				  void *cb_data_unused)
	struct commit_list *backup = NULL, *l;




		die(_("path '%s' does not exist in '%.*s'"),
	    starts_with(refname, "refs/remotes/"))
					    GET_OID_COMMITTISH);
		else if (bracket_depth && *cp == '}')
		const char *p, *buf;
	struct object_context unused;
		if (nth_midxed_object_oid(&oid, m, first))
			if (new_filename)

		return len;
}
	if (pos < istate->cache_nr) {
	return 0;
}
	if (name[0] == ':') {
	ret = get_oid(sb.buf, oid);
	return collect_ambiguous(oid, data);
			if ('0' <= ch && ch <= '9')
	for (i = 0; i < len ;i++) {
								   filename,
	o = parse_object(r, &outer);

 *
	unsigned short mode;
	if (len < 4 || name[len-1] != '}')
}

	if (!prefix)
				 int (*get_mark)(const char *, int),
{
{
	if (len)
 */
	int i;
	struct disambiguate_state ds;
	for (i = 0; i < nr; i++) {
	}
		pos = -pos - 1;
	}

			return -1;
	char *s = refs_shorten_unambiguous_ref(get_main_ref_store(r), ref, 0);

}
{
		if (sp[1] == '}')
	} else if (first < num - 1) {
		ds.fn = disambiguate_committish_only;
	} else

		if (!object)
			if (errors) {
			    fullname.buf, filename,
	char *real_ref = NULL;
	if (!ret)
				    oid, &unused);
	regex_t regex;
{
		sort_ambiguous_oid_array(r, &collect);
	return 0;
			break;
	prepare_alt_odb(r);

			pos = -pos - 1;
		}
		repo_for_each_abbrev(r, ds.hex_pfx, collect_ambiguous, &collect);
	static char hexbuffer[4][GIT_MAX_HEXSZ + 1];
				if (ret && only_to_die) {
	struct grab_nth_branch_switch_cbdata *cb = cb_data;
		retval = brace - name + 1;
	uint32_t num, i, first = 0;
static int extend_abbrev_len(const struct object_id *oid, void *cb_data)
#define ONELINE_SEEN (1u<<20)
				}
	char *num_end;
	return 1;
		if (pos < 0)
	if (open_pack_index(p) || !p->num_objects)
	if (starts_with(sp, "commit}"))
		return 1;


	}

		if (!strcasecmp(value, hints[i].name)) {

	"Git normally never creates a ref that ends with 40 hex characters\n"
			}
}

 */
		target = strstr(match, " to ");
		int matches;
		struct tag *tag = lookup_tag(ds->repo, oid);
	 * Sorts by hash within the same object type, just as
	for (odb = ds->repo->objects->odb; odb && !ds->ambiguous; odb = odb->next) {
		return oidcmp(a, b);
		ds->ambiguous = 1;
		return;
				return get_short_oid(r,
	oidcpy(oid, &ds->candidate);
		return;
	 * with an object name that could match "bin_pfx".  See if we have

		 * We may still have ambiguity if we simply saw a series of
		if (parse_commit(commit) || !commit->parents)
			if (flags & GET_OID_RECORD_PATH)
	reflog_len = at = 0;
	     p = p->next)
	int len;
	ds->repo = r;

	strbuf_addbuf(buf, &tmp);
	else
				ret = get_tree_entry_follow_symlinks(repo, &tree_oid,
		l->item->object.flags |= ONELINE_SEEN;
	find_short_object_filename(&ds);
	struct object_id oid;
		return -1;
			pp.date_mode.type = DATE_SHORT;
		/* this is the first candidate */
{
}
	/*

static int get_describe_name(struct repository *r,
	struct object_id oid;
	free(s);
}
					 struct object_id *oid,
		struct oid_array *loose_objects;
			return 0;
			ds.fn = NULL;
}
		 * same repository!
	oc->mode = S_IFINVALID;
	}
{
		a++;
		namelen = strlen(name);


	mad_oid = mad->oid;
	struct object_context oc;

		}
	if (name && !namelen)

		 * together we need to divide by 2 and round up.
				      int object_name_len)
	 * trees and blobs.
	return ret;
	 * Between object types show tags, then commits, and finally
	const char *next;
}
{
static int peel_onion(struct repository *r, const char *name, int len,
				    ds->fn(ds->repo, &ds->candidate, ds->cb_data));
#include "refs.h"

	struct commit_list **list = cb->list;
		{ "tree", disambiguate_tree_only },

	/* We need to do this the hard way... */

static int repo_extend_abbrev_len(struct repository *r,
			   struct commit_list *list)
				  const char *message, void *cb_data)
				    void *cb_data_unused)
 * This interprets names like ':/Initial revision of "git"' by searching
 * exist in 'HEAD'" when given "HEAD:doc", or it may return in which case
	     m = m->next)
	brace = memchr(name, '}', namelen);
				      const char *prefix,
	void *cb_data;
		case '/':
			return len; /* syntax Ok, not enough switches */
	for (cp = name + len - 1; name <= cp; cp--) {
					const char *prefix,
		int len1 = cp - name;
#include "remote.h"
	ret = get_oid_1(repo, name, namelen, oid, flags);
	unsigned r = 0;
	int len;
	struct commit_list **list;

					    push_mark, branch_get_push,
}
			num = 1;
		oid_array_clear(&collect);
		 * We don't need regex anyway. '' pattern always matches.
	ds.fn = repo_extend_abbrev_len;
}
	int status;
#include "commit.h"
		    filename, object_name_len, object_name);
	return 0;
#include "blob.h"
 * For negative-matching, prefix the pattern-part with '!-', like: ':/!-WIP'.
		return 0;
}
	"where \"$br\" is somehow empty and a 40-hex ref is created. Please\n"
		return hex[oid->hash[pos >> 1] >> 4];
	if (!dots)
					struct object_id *oid)
		else if (!bracket_depth && *cp == ':')
			    struct object_id *oid)
	oidcpy(oid, &o->oid);

	if (flags & GET_OID_FOLLOW_SYMLINKS && flags & GET_OID_ONLY_TO_DIE)
					continue;
	 * "ref^{type}" dereferences ref repeatedly until you cannot

	return 0;

	if (is_missing_file_error(errno))
	QSORT_S(a->oid, a->nr, sort_ambiguous, r);
	static const struct {
		return 1;
	char hex_pfx[GIT_MAX_HEXSZ + 1];
	strbuf_release(&fullname);
	}
			return MISSING_OBJECT;
		status = finish_object_disambiguation(&ds, oid);
		if (!nth_packed_object_id(&oid, p, first))
				 int at, struct strbuf *buf,
		}
 * format and the given arguments) is not a valid object.
			else

	struct object *object = parse_object(cb->repo, oid);
	struct multi_pack_index *m;
	mad.cur_len = len;
static disambiguate_hint_fn default_disambiguate_hint;
	pos = index_name_pos(istate, fullname.buf, fullname.len);
	if (!ds->candidate_ok)
	mad->init_len = 0;
			has_suffix = ch;
	}

{
			    "hint: Did you mean ':%d:%s' aka ':%d:./%s'?"),
				     unsigned lookup_flags)
				    const struct object_id *oid,
	if (file_exists(filename))
		break;

	if (expected_type == OBJ_COMMIT)
	if (repo_file_exists(r, filename))
}

	else
{
		pos = -pos - 1;
int repo_get_oid_treeish(struct repository *r,
		sub_flags |= GET_OID_TREEISH;
	}
				return reinterpret(r, name, namelen, len, buf,
		if (!get_oid_1(repo, name, len, &tree_oid, sub_flags)) {
		       struct strbuf *buf, unsigned allowed)
		}
#include "tree.h"
}
		for (at = len-4; at >= 0; at--) {
		return -1;
	num = p->num_objects;

}
static int interpret_branch_mark(struct repository *r,
	struct commit *commit;
{
	"because it will be ignored when you just specify 40-hex. These refs\n"
	for (start = name;
}
		{ "none", NULL },
		 * is only one off of 2^4, but the MSB is the 3rd bit.
	ds->len = len;

					 const char *str,
						len, str,
	memset(ds, 0, sizeof(*ds));



		current = nth_midxed_object_oid(&oid, m, i);
	 * since the object may have recently been added to the repository
	return 0;
	if (used < 0)
	       type_name(type) ? type_name(type) : "unknown type",
	 * mad->hash if it does not exist (or the position of mad->hash if
				return MISSING_OBJECT;


	cb.remaining = nth;
		ds->candidate_ok = 0;
		die(_("path '%s' exists on disk, but not in the index"), filename);
		len = msb(count) + 1;
	if (memchr(name, ':', at))
		break;
		len = interpret_branch_mark(r, name, namelen, at - name, buf,
	/*
	/*

			       struct strbuf *buf,
static void diagnose_invalid_oid_path(struct repository *r,
			      const struct object_id *oid, int len)
	for (l = list; l; l = l->next) {
{
	return at_mark(string, len, suffix, ARRAY_SIZE(suffix));
			if (!match_sha(ds->len, ds->bin_pfx.hash, oid->hash))
}
	for (i = first; i < num && !ds->ambiguous; i++) {
	struct object_context unused;
		strbuf_setlen(buf, used);
			cp = name + 1;
			if (!len) {
	const struct object_id *mad_oid;
		      struct object_id *oid)
	static const char *warn_msg = "refname '%.*s' is ambiguous.";
				len = strlen(str);

		}
						return -1;
	struct oid_array collect = OID_ARRAY_INIT;
	/* die() inside prefix_path() if resolved path is outside worktree */
			pos = -1 - pos;
 */
static int collect_ambiguous(const struct object_id *oid, void *data)
	if (repo_get_oid_committish(r, dots[3] ? (dots + 3) : "HEAD", &oid_tmp))
	    !strcmp(sb->buf, "refs/heads/HEAD"))
		case '.':
	}

	if (!expected_type) {
			break;
	else if (starts_with(sp, "tag}"))
	mad->init_len = mad->cur_len;
	struct min_abbrev_data mad;
		{ "commit", disambiguate_commit_only },
{
	int type;
	}

	value = get_data(branch, &err);
		if (len > 0)
static int disambiguate_treeish_only(struct repository *r,
