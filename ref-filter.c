
		 * we can't handle case-insensitive comparisons,
		for (i = 0; p[i]; p[i] == '/' ? i++ : *p++)
		else if (atom->u.contents.option == C_LINES) {
		if (len == atom_len && !memcmp(valid_atom[i].name, sp, len))
#include "builtin.h"

} *used_atom;

		int plen = strlen(p);
			struct strbuf s = STRBUF_INIT;
			return -1;
};
}
	obj = parse_object(the_repository, oid);
		}
			return 0;
	for (i = 0; i < used_atom_cnt; i++) {
				       NULL, atom->u.remote_ref.push,
			strbuf_reset(&cur->output);

	while (i < nr) {
		if (trailers_atom_parser(format, atom, *arg ? arg : NULL, err))

	return 0;
}
			branch = branch_get(branch_name);
	{ "then", SOURCE_NONE },
		if (strtoul_ui(arg, 10, &atom->u.contents.nlines))
	argv_array_pushv(&sorted, patterns);
		if (name[wholen] == 0)
	}
			v->s = xstrdup(refname);
	}
	const char *arg;
				  const char *arg, struct strbuf *err)
			if (cp[1] == '%')
	else

			v->s = xstrdup(oid_to_hex(oid));



static struct ref_to_worktree_map {
	if (ref_to_worktree_map.worktrees) {
		if (deref)
	struct atom_value *va, *vb;
	free(item);
			return; /* no point looking for it */
{
		if (!ref->symref)
	if (state.rebase_in_progress ||

			break;
			v->s = xstrfmt("%s^{}", refname);
	{ "flag", SOURCE_NONE },
			break;
			if (patterns[i][prefix->len] != patterns[end][prefix->len])
				v->s = get_worktree_path(atom, ref);
		const char *remote = atom->u.remote_ref.push ?
			     struct strbuf *err)
			v->s = copy_line(wholine);

	if (if_then_else->cmp_status == COMPARE_EQUAL) {
		 * of components is one more than the no of '/').
		} else if (!strcmp(s, "remoteref")) {
		int len = strlen(valid_atom[i].name);
	s = xcalloc(1, sizeof(*s));
 * A pattern can be a literal prefix (e.g. a refname "refs/heads/master"
	align->width = width;
		int explicit;
static void pop_stack_element(struct ref_formatting_stack **stack)
	/*  Stack may have been popped within at_end(), hence reset the current pointer */
};
/*  If no sorting option is given, use refname to sort as default */
}

	unsigned long sublen = 0, bodylen = 0, nonsiglen = 0, siglen = 0;
			free((char *)to_free);
	if (!filter->name_patterns[0]) {
	}
	 * when you add new atoms
		v->atom = atom;
			return 1;
	kind = filter_ref_kind(filter, refname);
}
				v->s = xstrdup(buf + 1);
	if (!(kind & filter->kind))
{
	push_stack_element(&state->stack);

	push_stack_element(&state.stack);
		} else if (atom->u.contents.option == C_BARE)
		if (!!deref != (*name == '*'))
			v->s = xstrdup(type_name(oi->type));
			return;
#include "refs.h"
			     const char *color_value, struct strbuf *err)
			 * %( is the start of an atom;


	enum object_type type;
				       _("not a git repository, but the field '%.*s' requires access to object data"),

static int append_atom(struct atom_value *v, struct ref_formatting_state *state,
			   struct strbuf *final_buf,
	return NULL;
		else if (filter->kind & FILTER_REFS_ALL)
	*stack = s;
 * We parse given format string and sort specifiers, and make a list
		} else if (!strcmp(name, "deltabase"))
	}
	for_each_string_list_item(prefix, &prefixes) {
	if (type & FILTER_REFS_INCLUDE_BROKEN)

	if (!arg)
			v->s = xstrdup(type_name(tag->tagged->type));
		}
 * Allocate space for a new ref_array_item and copy the name and oid to it.
	return 0;
	 * about syntactically bogus color names even if they won't be used.

		oi.info.typep = &oi.type;
		if (!*arg) {
				       color_value);
	lazy_init_worktree_map();
{
		if (!strcmp(name, "objecttype"))
	while (*buf) {
	}
	{ "object", SOURCE_OBJ },
	/*
} oi, oi_deref;
	}
static void find_longest_prefixes_1(struct string_list *out,
	init_contains_cache(&ref_cbdata.no_contains_cache);
	return 0;
		if (r[i] == '\n')
		return get_head_description();
		else
{
		      const char *arg, struct strbuf *err);
			find_subpos(buf,
			}
#include "commit-reach.h"
		if (!obj) {
	atom->u.contents.option = C_TRAILERS;
 */
	return res;
};
	return 0;
 * Parse the object referred by ref, and grab needed value.
	}
		 * in this case, the patterns are applied after
		    commit_contains(filter, commit, filter->no_commit, &ref_cbdata->no_contains_cache))
	return at;
 */
 * filtered refs in the ref_array structure.
}
		char *head;
				strbuf_addf(err, _("unrecognized position:%s"), s);
	{ "numparent", SOURCE_OBJ, FIELD_ULONG },
 */
	if (!ref->value) {
	else
{
		} else if (atom->u.objectname.option == O_LENGTH) {
};
	int i, at, atom_len;
			name++;
	struct if_then_else *if_then_else = xcalloc(sizeof(struct if_then_else), 1);
		oi_deref.info.typep = &oi_deref.type;
		skip_prefix(arg, ":", &arg);
			 * %% is a quoted per-cent.
	int i;
		return tagged_oid;
	} else
		*sublen -= 1;
		if (!subpos)
	 * by maxcount logic.
		if (no_merged) {
	else if (!strcmp(arg, "body"))
		int deref = 0;
	if (get_object(ref, 0, &obj, &oi, err))
			return strbuf_addf_ret(err, -1, _("positive value expected objectname:short=%s"), arg);



		if (len == ep - atom && !memcmp(used_atom[i].name, atom, len))

 * when deref is false, (obj, buf, sz) is the object that is
		die("%s", error_buf.buf);
	for (cp = format->format; *cp && (sp = find_next(cp)); ) {



	return ret;
}
			if (!skip_prefix(ref->refname, "refs/heads/",
		if (*name == '*') {
	 * is good to deal with chains of trust, but
	return ref_kind_from_refname(refname);
#include "argv-array.h"
		else if (!strcmp(s, "remotename")) {
	if (*sp == '*' && sp < ep)
	if (if_then_else->else_atom_seen)

		at = parse_ref_filter_atom(format, sp + 2, ep, &err);

 */
	/*
		strbuf_addstr(s, str);
	case QUOTE_TCL:
			/*
	/*
		eol = strchrnul(buf, '\n');
	if (!arg) {
	free(state.branch);

			return cmp;
	 */
		if (starts_with(refname, ref_kind[i].prefix))
static void populate_worktree_map(struct hashmap *map, struct worktree **worktrees)
	for (i = 0; i < lines && sp < buf + size; i++) {
}
	else

	}
	/*
	if (filter->merge_commit)
				v->s = xstrdup("");
	while (*buf && *buf != '\n') {
	new_stack->at_end_data = if_then_else;
				     num_ours, num_theirs);
 * A call-back given to for_each_ref().  Filter refs and keep them for

	}
	{ "committername", SOURCE_OBJ },
	push_stack_element(&state->stack);
{
		grab_sub_body_contents(val, deref, buf);
	 * to do its job and the resulting list may yet to be pruned
			arg = NULL;
		else if (va->value == vb->value)
				return cp;
	if (len < 0) {
}
	{ "else", SOURCE_NONE },
	}
 */
	unsigned long size;
			       const char *arg, struct strbuf *err)
			continue;
		if (p == NULL) {

		return 0;
			if (atom->u.head && !strcmp(ref->refname, atom->u.head))
}
}
	else {

 * change this to account for multiple levels (e.g. annotated tags
		formatp++;
	struct ref_formatting_stack *stack;
	return 0;
				cp++; /* skip over two % */
		eol++;
			const char *s;

	} else if (atom->u.remote_ref.option == RR_TRACKSHORT) {
		die("filter_refs: invalid type");
 * Return 1 if the refname matches one of the patterns, otherwise 0.

	 * We do not open the object yet; sort may only need refname
	putchar('\n');
		int cmp = cmp_ref_sorting(s, a, b);
		/*
			ref->symref = xstrdup("");
{
	if (arg) {
		wholine = find_wholine(who, wholen, buf);
						 const struct object_id *oid)
		strbuf_setlen(prefix, prefix->len - 1);
			char buf[256], *cp = buf;
		buf = eol;
				return -1;
static void do_merge_filter(struct ref_filter_cbdata *ref_cbdata)
	 */
		free(oi->content);

		if (!strcmp(if_then_else->str, cur->output.buf))
	struct ref_formatting_stack *cur = state->stack;
}
{
			align->position = position;
	if (ep <= sp)

	char *r = xmemdupz(buf, len);
	 * If it is a tag object, see if we use a value that derefs
	lookup_result = container_of(e, struct ref_to_worktree_entry, ent);
	strbuf_release(&final_buf);
	strbuf_addch(&desc, ')');

	 * Please update $__git_ref_fieldlist in git-completion.bash
	"behind %d",
		int pos;
 * val is a list of atom_value to hold returned values.  Extract
	new_stack->at_end_data = &atomv->atom->u.align;
	if (*atom->name == '*')
		struct used_atom *atom = &used_atom[i];
{
{
		if (va->value < vb->value)
	int eaten = 1;
		strbuf_add(out, sp, len);
	 * A merge filter is applied on refs pointing to commits. Hence
		if (stat_tracking_info(branch, &num_ours, &num_theirs,
			continue;
{
		if (*eol == '\n')
			return 0;

			v->s = xstrfmt("%lu", (unsigned long)v->value);
#include "git-compat-util.h"
		return strbuf_addf_ret(err, -1, _("unrecognized %%(contents) argument: %s"), arg);
	i = 0;
		sp = cp + strlen(cp);
{
	return 0;
		 */
 * indexed with the "atom number", which is an index into this
	const char *eoemail;
		if (!wholine)
	revs.limited = 1;
	for (s = ref_sorting; s; s = s->next) {

	int (*parser)(const struct ref_format *format, struct used_atom *atom,
	struct string_list params = STRING_LIST_INIT_DUP;
	for (i = 0; i < ARRAY_SIZE(valid_atom); i++) {
	const char *eol = strchrnul(buf, '\n');
{
			return 0;
	if (oi->info.contentp) {
		if (at < 0)
{
			entry->wt = worktrees[i];
	if (!need_tagged || (obj->type != OBJ_TAG))
 */
	}
	} else
		*s = show_ref(&atom->u.remote_ref.refname, refname);
	strbuf_utf8_align(&s, align->position, align->width, cur->output.buf);

	if (state.stack->prev) {

				free(oi->content);
		int position;
static int get_object(struct ref_array_item *ref, int deref, struct object **obj,
	used_atom_cnt++;
		} else if (starts_with(name, "color:")) {
	struct strbuf *s = &state->stack->output;
 * pointing to annotated tags pointing to a commit.)
	struct rev_info revs;
	struct ref_array *array = ref_cbdata->array;
			atom->u.remote_ref.option = RR_TRACK;
	return -1;
		die("%s", err.buf);
			return xstrdup("");
	string_list_clear(&prefixes, 0);
{
			*s = xstrdup("=");
	struct ref_array_item *ref;
 * at one of the oids in the given oid array.
 * the used atoms.
static void find_subpos(const char *buf,
 * API for filtering a set of refs. Based on the type of refs the user
		grab_person("author", val, deref, buf);
	struct ref_array_item *b = *((struct ref_array_item **)b_);
				string_list_clear(&params, 0);
	struct ref_formatting_stack *current = state->stack;

struct ref_formatting_stack {
		return strbuf_addf_ret(err, -1, _("positive width expected with the %%(align) atom"));
{
	struct string_list params = STRING_LIST_INIT_DUP;
		if (filter->with_commit &&
{

		} else if (!strcmp(name, "else")) {
	/*
				      const char *refname,
}

			unsigned long *nonsiglen,
		return FILTER_REFS_DETACHED_HEAD;

		struct {
			const char **sig, unsigned long *siglen)
		const char *p = refname;
	 * for matching refs of tags and branches.

			else
		} else if (atom->u.remote_ref.push) {
	struct string_list prefixes = STRING_LIST_INIT_DUP;
char *get_head_description(void)
	*siglen = strlen(*sig);
		if (i)
	*body = buf;
 * pattern match, so the callback still has to match each ref individually.

	return 0;
	cmp_type cmp_type = used_atom[s->atom].type;
		else if (starts_with(name, "symref"))
	/* parse signature first; we might not even have a subject line */
		return strbuf_addf_ret(err, -1, _("malformed field name: %.*s"),
	}

		if (*eol)
 * array.
			       const char *arg, struct strbuf *err)
					 &branch_name)) {
 */

			v->s = strbuf_detach(&s, NULL);
				cp = copy_advance(cp, ",packed");

	return 0;
		}

		atom->u.if_then_else.cmp_status = COMPARE_UNEQUAL;
	 * shouldn't be used for checking against the valid_atom
	rf->merge_commit = lookup_commit_reference_gently(the_repository,
	ALLOC_GROW(array->items, array->nr + 1, array->alloc);
		if (skip_prefix(s, "position=", &s)) {
			cmp = -1;
		strbuf_reset(&cur->output);
	 * When no '--format' option is given we need to skip the prefix
		if (deref)

		size_t end;
		oi_deref.info.delta_base_oid = &oi_deref.delta_base_oid;
	return 0;
		return shorten_unambiguous_ref(refname, warn_ambiguous_refs);
}
}
		free_worktrees(ref_to_worktree_map.worktrees);
	struct used_atom *atom;
	const struct ref_to_worktree_entry *e, *k;
		struct atom_value *v = &ref->value[i];
	free(state.detached_from);
			const char *contents_end = bodylen + bodypos - siglen;
		pop_stack_element(&state.stack);
	int i;
			else
			else {
	return "";
	return 0;

	struct tag *tag = (struct tag *) obj;
		/*
				struct commit *parent = parents->item;
			}
	 */
			    state.branch);
		if (strtol_i(arg, 10, &atom->rstrip))
	state->stack->at_end_data = prev->at_end_data;
	unsigned flags = 0;
	if (timestamp == TIME_MAX)
			v->s = xstrfmt("%"PRIuMAX , (uintmax_t)oi->size);
		else
	unsigned int width;
		if_then_else->condition_satisfied = 1;
	}

			oi_deref.info.sizep = &oi_deref.size;
			ret = for_each_fullref_in("refs/remotes/", ref_filter_handler, &ref_cbdata, broken);
		} else

}
		struct atom_value *v = &val[i];
			 */
	return strcmp(e->wt->head_ref,
	string_list_clear(&params, 0);
		unsigned int kind;
			unsigned int length;

		break;
}
	case OBJ_TAG:
	for (i = 0; i < used_atom_cnt; i++)
		need_tagged = 1;
static int body_atom_parser(const struct ref_format *format, struct used_atom *atom,
			v->s = xstrdup("");
			*s = xstrdup(">");
		const char *s = params.items[i].string;
		else {
{
	const char *a = *(const char **)va;
		grab_person("tagger", val, deref, buf);
			return -1;

}
			if (ref->flag & REF_ISPACKED)
}
		return xstrdup("");
		return filter->kind;
	strbuf_swap(&cur->output, &s);
				       void *cb_data,
		if (!!deref != (*name == '*'))
static int contents_atom_parser(const struct ref_format *format, struct used_atom *atom,
		const char *name = used_atom[i].name;
				if (parents != commit->parents)
		cmp = versioncmp(va->s, vb->s);
			}
			oi_deref.info.disk_sizep = &oi_deref.disk_size;
{
	/*

	ref->kind = kind;
		if (*atom == '*')
		hashmap_free_entries(&(ref_to_worktree_map.map),

		    atom->u.objectname.length == 0)
	union {
 * Make sure the format string is well formed, and parse out
	int cmp;
	const char *str;
			const char **body, unsigned long *bodylen,
			pop_stack_element(&cur);
		strbuf_release(&err);

	struct ref_formatting_stack *prev = current->prev;
static struct ref_msg {
		else
			string_list_append(out, prefix->buf);
 */

		}
	size_t i;
	}
		 * sort it out.
	struct ref_formatting_stack *cur = *stack;
	return 0;
} msgs = {
	if (oid_object_info_extended(the_repository, &oi->oid, &oi->info,
			v->s = xstrdup("");
	for (i = 0; i < used_atom_cnt; i++) {
		s->reverse = 1;
	ref = ref_array_push(ref_cbdata->array, refname, oid);
			name++;
static int strbuf_addf_ret(struct strbuf *sb, int ret, const char *fmt, ...)
			die("%s", err.buf);
		atom->u.objectname.option = O_LENGTH;
		return strbuf_addf_ret(err, -1, _("unknown field name: %.*s"),

			continue;

				       (int)(ep-atom), atom);
	return 0;
			strbuf_addf(err, _("unrecognized %%(align) argument: %s"), s);
{
	const char *cp;
	 * If there is no atom that wants to know about tagged
		 skip_prefix(arg, "strip=", &arg)) {
			v->s = copy_line(wholine);
			v->handler = end_atom_handler;
	if (ref->kind & FILTER_REFS_DETACHED_HEAD)

	uintmax_t value; /* used for sorting when not FIELD_STR */
		int i;
}
	{ "taggerdate", SOURCE_OBJ, FIELD_TIME },
	if (strcmp(who, "tagger") && strcmp(who, "committer"))
	sorting->next = NULL;

static int then_atom_handler(struct atom_value *atomv, struct ref_formatting_state *state,
	if (!strcmp(s, "right"))
struct ref_formatting_state {
static void fill_missing_values(struct atom_value *val)
		 * prefixes like "refs/heads/" etc. are stripped off,
	 */
		return error(_("option `%s' must point to a commit"), opt->long_name);
	if (!obj)
 * 2. As the refs are cached we might know what refname peels to without
			strbuf_swap(&cur->output, &prev->output);
			strbuf_addf(&desc, _("no branch, rebasing %s"),
		if (deref)
			return 1;

			return ""; /* end of header */
			deref = 1;


	struct object_id oid;

		 * For common cases where we need only branches or remotes or tags,
		condition_satisfied : 1;
			v->s = copy_subject(subpos, sublen);
		*s = xstrdup(merge ? merge : "");
struct ref_filter_cbdata {
static void end_align_handler(struct ref_formatting_stack **stack)
		struct {


	struct ref_formatting_state state = REF_FORMATTING_STATE_INIT;
		if (strcmp(name, "subject") &&
		/* grab_tree_values(val, deref, obj, buf, sz); */
	 * element's entire output strbuf when the %(end) atom is
		if (!!deref != (*name == '*'))
	va_start(ap, fmt);
	string_list_clear(&params, 0);
				atom->u.contents.trailer_opts.unfold = 1;
	}
	} else if (skip_prefix(arg, "notequals=", &atom->u.if_then_else.str)) {
		tagged_oid = get_tagged_oid((struct tag *)obj);
{
	if (*atom == '*')
};
 * later object processing.
}
		/* no patterns; we have to look at everything */
	if (atom->option == R_SHORT)
	const char *cp, *sp;
	static struct {
	struct hashmap_entry ent;
	return 0;
/*
static void grab_person(const char *who, struct atom_value *val, int deref, void *buf)
		 * There is an %(else) atom: we need to drop one state from the
}
	if (get_ref_atom_value(a, s->atom, &va, &err))
	va_list ap;
		return xstrdup("");
static char *get_worktree_path(const struct used_atom *atom, const struct ref_array_item *ref)
		} else {
	 * string, since the description is used as a sort key and compared
		struct atom_value *v = &val[i];

		if (!ret && (filter->kind & FILTER_REFS_DETACHED_HEAD))
		atom->option = R_RSTRIP;
	}
	struct strbuf s = STRBUF_INIT;
{
	struct ref_formatting_stack *prev = cur->prev;

/*
	cmp_status cmp_status;
	QSORT(sorted.argv, sorted.argc, qsort_strcmp);
	struct object *obj;
#include "commit-graph.h"
	int lstrip, rstrip;
	int i;

	 * We check this after we've parsed the color, which lets us complain
	{ "parent", SOURCE_OBJ },

	{ "refname", SOURCE_NONE, FIELD_STR, refname_atom_parser },
				strbuf_addf(err, _("unknown %%(trailers) argument: %s"), s);
				       oid_to_hex(&oi->oid), ref->refname);
	 * If the atom name has a colon, strip it and everything after
	msgs.ahead_behind = _("ahead %d, behind %d");

	memset(&state, 0, sizeof(state));
#include "hashmap.h"
				const char *arg, struct strbuf *err)
	free((char *)to_free);
{
static void free_array_item(struct ref_array_item *item)
	cmp_type cmp_type;

			else
}
{
	struct ref_array_item *ref = new_ref_array_item(refname, oid);
	}
		const char *p = refname;
		eol = memchr(sp, '\n', size - (sp - buf));
	return strcmp(a, b);
		return refname_atom_parser_internal(&atom->u.remote_ref.refname,
				       NULL, atom->u.remote_ref.push,
	else if (skip_prefix(arg, "trailers", &arg)) {
			 const struct ref_format *format)
	int ret;
{
	} else if (!if_then_else->condition_satisfied) {
		else if (filter->kind == FILTER_REFS_REMOTES)
		return strbuf_addf_ret(err, -1, _("%%(body) does not take arguments"));
		    !starts_with(name + wholen, "date"))
	current->at_end(&state->stack);
		return strbuf_addf_ret(err, -1, _("%%(objecttype) does not take arguments"));
		if (*cp == '%') {
		else if (filter->kind == FILTER_REFS_TAGS)

	if (ref_to_worktree_map.worktrees)
			*s = xstrdup(msgs.gone);


{

		warning(_("ignoring broken ref %s"), refname);
		if (*atom->name == '*')
			grab_date(wholine, v, name);
	*nonsiglen = *sig - buf;
		} else if (skip_prefix(s, "width=", &s)) {
	v->s = xstrdup(show_date(timestamp, tz, &date_mode));
	return 0;
	if (!memcmp(&oi.info, &empty, sizeof(empty)) &&
		buf = eol;
		atom->u.objectname.option = O_SHORT;
		struct atom_value *v = &val[i];


static int for_each_fullref_in_pattern(struct ref_filter *filter,
	return 0;
	if (!rf->merge_commit)
		* Set "end" to the index of the element _after_ the last one
		const char *name = used_atom[i].name;
			/* only local branches may have an upstream */
		return -1;
		     p[plen-1] == '/'))
	 */
	if (!if_then_else)

		    strcmp(name + wholen, "email") &&
	struct ref_filter *filter = ref_cbdata->filter;
	BUG_ON_OPT_NEG(unset);
	}
	{ "symref", SOURCE_NONE, FIELD_STR, refname_atom_parser },
			v->s = xstrdup(subpos);
}
	/*
}
	return get_object(ref, 1, &obj, &oi_deref, err);
	return 0;
	/* Is the atom a valid one? */
					strbuf_addch(&s, ' ');
			v->s = xmemdupz(bodypos, nonsiglen);
			;
	new_stack->at_end = end_align_handler;
	 * actually care about the formatting details.
	else if (atom->u.remote_ref.option == RR_TRACK) {
	}
	long remaining = len;
		if (starts_with(name, "refname"))
	 * We got here because atomname ends in "date" or "date<something>";

		} else if (starts_with(name, "align")) {
		       struct strbuf *err);
	}

	if (item->value) {
		if (!c || is_glob_special(c)) {
	{ "push", SOURCE_NONE, FIELD_STR, remote_ref_atom_parser },
{
	int res = parse_ref_filter_atom(&dummy, atom, end, &err);
	static const char cstr_name[] = "refname";
static int trailers_atom_parser(const struct ref_format *format, struct used_atom *atom,
				      const struct hashmap_entry *kptr,
		die("%s", err.buf);
	{ "authordate", SOURCE_OBJ, FIELD_TIME },
 * only over the patterns we'll care about. Note that it _doesn't_ do a full
			oi_deref.info.contentp = &oi_deref.content;
	struct commit **to_clear = xcalloc(sizeof(struct commit *), array->nr);
		if (filter->no_commit &&


	 */

	struct date_mode date_mode = { DATE_NORMAL };
	*bodylen = strlen(buf);
}
		atom->option = R_NORMAL;
			v->s = xmemdupz(bodypos, bodylen);
	return sorting;
static void grab_values(struct atom_value *val, int deref, struct object *obj, void *buf)
			if_then_else->condition_satisfied = 1;
		if (cmp)
	 * object, we are done.
	 * it off - it specifies the format for this entry, and
{
	int i, old_nr;

		return strbuf_addf_ret(err, -1, _("missing object %s for %s"),
	return 0;
	pop_stack_element(&state->stack);
{
	else if (!strcmp(arg, "short"))

static int if_atom_parser(const struct ref_format *format, struct used_atom *atom,
static void grab_sub_body_contents(struct atom_value *val, int deref, void *buf)
			;
		v->handler = append_atom;
	return refname_atom_parser_internal(&atom->u.refname, arg, atom->name, err);
	}
static int populate_value(struct ref_array_item *ref, struct strbuf *err)

		grab_person("committer", val, deref, buf);
	int i;
	strbuf_release(&s);
	add_pending_object(&revs, &filter->merge_commit->object, "");
			enum { O_FULL, O_LENGTH, O_SHORT } option;
{
	 * strings satisfy the 'if' condition.
	if (!arg) {
		*obj = parse_object_buffer(the_repository, &oi->oid, oi->type, oi->size, oi->content, &eaten);
	if (!if_then_else)
		if (deref)
		return -1;
static struct ref_array_item *new_ref_array_item(const char *refname,
	show_ref_array_item(ref_item, format);
			branch = branch_get(branch_name);
		ep = strchr(sp, ')');
			enum { C_BARE, C_BODY, C_BODY_DEP, C_LINES, C_SIG, C_SUB, C_TRAILERS } option;
/*
	}

	size_t len;
}
	s->atom = parse_sorting_atom(arg);
				v->s = xstrdup("");
	const char **pattern = filter->name_patterns;
		struct {
	}
	new_stack->at_end = if_then_else_handler;
			return error(_("option `%s' is incompatible with --merged"),
	}
		if (!strcmp(name, "tree")) {
		die(_("malformed object at '%s'"), refname);
	QSORT_S(array->items, array->nr, compare_refs, sorting);
		eol = strchr(buf, '\n');
{

	struct commit *commit = (struct commit *) obj;
	/*
	 * it's not possible that <something> is not ":<format>" because
		atom->u.remote_ref.option = RR_REF;
	return 0;
			*s = xstrfmt(msgs.behind, num_theirs);
 * Callers can then fill in other struct members at their leisure.
		} else if (!strcmp(name, "flag")) {
{
		return match_name_as_path(filter, refname);
	if (arg)
	}
#include "remote.h"

#define REF_FORMATTING_STATE_INIT  { 0, NULL }
		}
	for (i = 0; i < ARRAY_SIZE(ref_kind); i++) {
	unsigned int broken = 0;
static const char *get_refname(struct used_atom *atom, struct ref_array_item *ref)
	const char *name;

		const char *prefix;
			v->value = oi->disk_size;
		return strbuf_addf_ret(err, -1, _("%%(deltabase) does not take arguments"));
		? REF_FILTER_MERGED_OMIT
	else if (state.detached_from) {
	while (*cp) {
		merge = remote_ref_for_branch(branch, atom->u.remote_ref.push);
		eol = strchrnul(buf, '\n');
	v->value = 0;
	old_nr = array->nr;
			 * Treat empty sub-arguments list as NULL (i.e.,
static int align_atom_parser(const struct ref_format *format, struct used_atom *atom,
			ret = for_each_fullref_in("refs/tags/", ref_filter_handler, &ref_cbdata, broken);
		free_array_item(array->items[i]);
		    !starts_with(name, "contents"))
	    skip_prefix(arg, "v:", &arg))
		const char *name = used_atom[i].name;
		/*
}
		oi.info.delta_base_oid = &oi.delta_base_oid;
		if (cp < sp)
		if (filter->kind == FILTER_REFS_BRANCHES)
 * more efficient alternative to obtain the pointee.
	msgs.gone = _("gone");


 * Given a ref, return the value for the atom.  This lazily gets value
	if (oid_array_lookup(points_at, oid) >= 0)
}
	 * requested, do something special.
	/* Do we have the atom already used elsewhere? */
/*
	int (*cmp_fn)(const char *, const char *);
		if (!eol)
}
static int parse_ref_filter_atom(const struct ref_format *format,

 * out of the object by calling populate value.
	    filter->kind == FILTER_REFS_TAGS)
	return 0;

}
	return 0;
/*

	} else if (cur->output.len && !is_empty(cur->output.buf))
		return strbuf_addf_ret(err, -1, _("format: %%(then) atom used after %%(else)"));
	info_source source;
		string_list_split(&params, arg, ',', -1);
	/*
			cmp = 1;




	while (remaining > 0) {
 * Allow to save few lines of code.
	if (tagged_oid && oid_array_lookup(points_at, tagged_oid) >= 0)
		for (i = 0; p[i]; p[i] == '/' ? i++ : *p++)
		need_symref = 1;
		return xstrdup("");
		if (!atom->u.remote_ref.nobracket && *s[0]) {
		return strbuf_addf_ret(err, -1, _("format: %%(then) atom used without an %%(if) atom"));
			}

	/*
	const char *sp;
	    filter->kind == FILTER_REFS_REMOTES ||

	wt_status_get_state(the_repository, &state, 1);
			} option;
		buf++;
{
			   struct strbuf *unused_err)
void pretty_print_ref(const char *name, const struct object_id *oid,
	if (!color_value)
	while (*s != '\0') {

/*
		if (!isspace(*s))
static void append_lines(struct strbuf *out, const char *buf, unsigned long size, int lines)
	 * For a tag or a commit object, if "creator" or "creatordate" is
	find_longest_prefixes_1(out, &prefix, sorted.argv, sorted.argc);
		}
		case '/':
#include "commit.h"
{
		/* We need to know that to use parse_object_buffer properly */
		if (!wildmatch(p, refname, flags))
				v->s = xstrdup(" ");
	return 0;
}
	default:
		 */
}
	if (!filter_pattern_match(filter, refname))
	case QUOTE_PYTHON:
		if (starts_with(name, "creatordate"))
static const struct object_id *match_points_at(struct oid_array *points_at,
	case QUOTE_NONE:
};
			return 1;
}
	unsigned int kind;
	return 0;
			struct strbuf s = STRBUF_INIT;
	long tz;

static void grab_tag_values(struct atom_value *val, int deref, struct object *obj)
			/*
			}
		free((char *)used_atom[i].name);
	FLEX_ALLOC_STR(ref, refname, refname);
};
	if (!if_then_else->then_atom_seen)
}
}
	} else
		} else if (!strtoul_ui(s, 10, &width))
 * NEEDSWORK:
			oi.info.disk_sizep = &oi.disk_size;
			v->value = oi->size;
		if_then_else = (struct if_then_else *)cur->at_end_data;
			continue;
			      struct atom_value **v, struct strbuf *err)
	oi_deref.oid = *get_tagged_oid((struct tag *)obj);
			v->s = xstrdup(atom->u.color);
		if (!!deref != (*name == '*'))
			refname = get_refname(atom, ref);
	align->position = ALIGN_LEFT;
	unsigned int i;
	if (filter->merge_commit || filter->with_commit || filter->no_commit || filter->verbose) {

	/*
		} else if (starts_with(name, "if")) {
}
	timestamp_t timestamp;
		break;
	} else if (atom->u.remote_ref.option == RR_REMOTE_REF) {
	REALLOC_ARRAY(used_atom, used_atom_cnt);
}
			unsigned int nlines;
typedef enum { SOURCE_NONE = 0, SOURCE_OBJ, SOURCE_OTHER } info_source;
			const char *s = params.items[i].string;
		else if (!strcmp(name, "type") && tag->tagged)
struct ref_to_worktree_entry {
		{ "refs/heads/" , FILTER_REFS_BRANCHES },
			return xmemdupz(buf, cp - buf);
		}
		if (!num_ours && !num_theirs)
	tz = strtol(zone, NULL, 10);
}
	 * with ref names.
		break;

			return error(_("malformed format string %s"), sp);


	if (valid_atom[i].parser && valid_atom[i].parser(format, &used_atom[at], arg, err))
static int if_atom_handler(struct atom_value *atomv, struct ref_formatting_state *state,
		/* Find total no of '/' separated path-components */
{
}
	if (res < 0)

		strbuf_addstr(&desc, _("no branch"));
	return xmemdupz(buf, eol - buf);

static int ref_to_worktree_map_cmpfnc(const void *unused_lookupdata,
	}
			continue;
}
		ref->symref = resolve_refdup(ref->refname, RESOLVE_REF_READING,
}

	FREE_AND_NULL(array->items);
		      struct expand_data *oi, struct strbuf *err)

		keydata_aka_refname ? keydata_aka_refname : k->wt->head_ref);
	for (i = 0; i < used_atom_cnt; i++) {
		atom->u.contents.option = C_SUB;
	if (!eoemail)
	state->stack->at_end = prev->at_end;
	{ "author", SOURCE_OBJ },
	{ "taggername", SOURCE_OBJ },
	e = container_of(eptr, const struct ref_to_worktree_entry, ent);
	if (!want_color(format->use_color))
	 * NEEDSWORK: We should probably clear the list in this case, but we've
static int refname_atom_parser_internal(struct refname_atom *atom, const char *arg,
	if (*sublen && (*sub)[*sublen - 1] == '\n')
	       skip_prefix(refname, "refs/heads/", &refname) ||
	}
			v->s = xstrfmt("%"PRIuMAX, (uintmax_t)oi->disk_size);
		buf++;
	const char *sp, *eol;
	 * ":" means no format is specified, and use the default.

					       oid_to_hex(&ref->objectname), ref->refname);
		grab_values(ref->value, deref, *obj, oi->content);
					       const char *refname)
	for (i = 0; i < old_nr; i++) {
	for (i = 0; i < used_atom_cnt; i++) {
			BUG("unknown %%(objectname) option");
			align->position = position;
		{ "refs/remotes/" , FILTER_REFS_REMOTES },
		else if (starts_with(name + wholen, "date"))
{
					cp += 3;
	array->items[array->nr++] = ref;
#include "worktree.h"
	int num_ours, num_theirs;
	if (!ref->symref)

{

		remaining = i + len + 1;
	strbuf_release(&current->output);
			v->handler = align_atom_handler;
			v->s = xstrdup(find_unique_abbrev(oid, DEFAULT_ABBREV));
		strbuf_addstr(&desc, state.detached_from);
 * In a format string, find the next occurrence of %(atom).
					       const struct object_id *oid,
		return strbuf_addf_ret(err, -1, _("unrecognized %%(objectsize) argument: %s"), arg);

		    strcmp(name + wholen, "name") &&
static int match_name_as_path(const struct ref_filter *filter, const char *refname)
}
{

	{ "upstream", SOURCE_NONE, FIELD_STR, remote_ref_atom_parser },
{
static struct expand_data {
{
			wholine = find_wholine(who, wholen, buf);
			string_list_clear(&params, 0);
	struct contains_cache no_contains_cache;
			else {

		perl_quote_buf(s, str);
			else {
	return 0;
			v->s = xstrdup(tag->tag);
			else if (cp[1] == '%')
#include "revision.h"
	struct worktree **worktrees;
	struct string_list params = STRING_LIST_INIT_DUP;
		}
#include "wildmatch.h"
	return start;
static int end_atom_handler(struct atom_value *atomv, struct ref_formatting_state *state,
		    !starts_with(name, "trailers") &&
 */
		break;
	/* subject is first non-empty line */
	return strbuf_detach(&desc, NULL);
	return 1;
}
static int subject_atom_parser(const struct ref_format *format, struct used_atom *atom,
	{ "committeremail", SOURCE_OBJ },
}
			free((char *)item->value[i].s);

	const char *subpos = NULL, *bodypos = NULL, *sigpos = NULL;
					strhash(worktrees[i]->head_ref));
			continue;
			r[i] = ' ';
	}
/* Return 1 if the refname matches one of the patterns, otherwise 0. */
static const char *show_ref(struct refname_atom *atom, const char *refname)

	k = container_of(kptr, const struct ref_to_worktree_entry, ent);
	if (format->need_color_reset_at_eol) {
static int ref_filter_handler(const char *refname, const struct object_id *oid, int flag, void *cb_data)
	/*
				  const char *arg, struct strbuf *err)
	struct strbuf s = STRBUF_INIT;
	}
			*s = xstrfmt("[%s]", *s);
		quote_formatting(&s, current->output.buf, state->quote_style);
struct refname_atom {
		return rstrip_ref_components(refname, atom->rstrip);
	int (*handler)(struct atom_value *atomv, struct ref_formatting_state *state,
	int i;
{
	if (!strcmp(atom->name, "push") || starts_with(atom->name, "push:"))
		return strbuf_addf_ret(err, -1, _("format: %%(else) atom used without a %%(then) atom"));
			break;
			head_ref(ref_filter_handler, &ref_cbdata);
	const char *start = xstrdup(refname);
	atom_len = (arg ? arg : ep) - sp;
		} else if (!strcmp(name, "objectsize")) {
}
							  &oid, 0);
	array->nr = 0;
	if (atom->u.remote_ref.option == RR_REF)
void parse_ref_sorting(struct ref_sorting **sorting_tail, const char *arg)
	return 0;
	 * This parses an atom using a dummy ref_format, since we don't
			return 1;
	s->next = *sorting_tail;

		return 0;
	clear_contains_cache(&ref_cbdata.no_contains_cache);
		{ "refs/tags/", FILTER_REFS_TAGS}
			free((char *)v->s);
	hashmap_entry_init(&entry, strhash(ref->refname));
	msgs.ahead = _("ahead %d");
/*
	}
static int compare_refs(const void *a_, const void *b_, void *ref_sorting)
					continue;
			return error(_("option `%s' is incompatible with --no-merged"),

		struct ref_array_item *item = array->items[i];
	filter->merge_commit->object.flags |= UNINTERESTING;
	{ "tagger", SOURCE_OBJ },
	free(if_then_else);
static void lazy_init_worktree_map(void)
static const char *copy_email(const char *buf)
	if (need_tagged)
	clear_commit_marks_many(old_nr, to_clear, ALL_REV_FLAGS);
	{ "authorname", SOURCE_OBJ },
				    state.branch);
	else
			name++;

}
 * 'buf' of length 'size' to the given strbuf.
		break;

	{ "objectname", SOURCE_OTHER, FIELD_STR, objectname_atom_parser },
		die("%s", err.buf);
	ref->value = xcalloc(used_atom_cnt, sizeof(struct atom_value));
{
static void grab_common_values(struct atom_value *val, int deref, struct expand_data *oi)
struct if_then_else {
		if (worktrees[i]->head_ref) {
		return 0;
{
	if (!*filter->name_patterns)
	if (!strcmp(refname, "HEAD"))
	struct argv_array sorted = ARGV_ARRAY_INIT;
			if (ref->kind == FILTER_REFS_BRANCHES)

		if (if_then_else->condition_satisfied) {
			return strbuf_addf_ret(err, -1, _("positive value expected contents:lines=%s"), arg);
	else

		struct refname_atom refname;
		/*

		 * so just return everything and let the caller
	} else if (if_then_else->cmp_status == COMPARE_UNEQUAL) {
	struct object_info empty = OBJECT_INFO_INIT;

	struct strbuf err = STRBUF_INIT;

		/*
		 * because we count the number of '/', but the number
					continue;
							 arg, atom->name, err)) {
	/* subject goes to first empty line */
		 * the total minus the components to be left (Plus one
}
	if (obj->type == OBJ_TAG)
	struct string_list_item *prefix;
 * If 'lines' is greater than 0, append that many lines from the given
	if (len < 0) {

			if (!skip_prefix(ref->refname, "refs/heads/",
		else if (atom->u.contents.option == C_BODY_DEP)
	strbuf_init(&s->output, 0);
	if (formatp != NULL) {
	}
		else if (atom->u.contents.option == C_SIG)

	init_contains_cache(&ref_cbdata.contains_cache);
		int i;
static int is_empty(const char *s)
	const char *to_free = start;
		fill_missing_values(ref->value);
		find_longest_prefixes_1(out, prefix, patterns + i, end - i);
	struct ref_sorting *s;
				      const void *keydata_aka_refname)
{
/*
	}
	int i;
			if (position < 0) {

		} else

	strbuf_addbuf(final_buf, &state.stack->output);
	} u;
			array->items[array->nr++] = array->items[i];
	 * element. Otherwise quote formatting is done on the
		break;

void show_ref_array_item(struct ref_array_item *info,
				fill_remote_ref_details(atom, refname, branch, &v->s);

	 * parse_ref_filter_atom() wouldn't have allowed it, so we can assume that no
		 * so we have to look at everything:
				string_list_clear(&params, 0);
				       AHEAD_BEHIND_FULL) < 0) {
{
	struct ref_formatting_stack *new_stack;
			continue;
/*
			*s = xstrfmt(msgs.ahead_behind,
	}
		}
	struct if_then_else *if_then_else = NULL;
 bad:
static align_type parse_align_position(const char *s)
		 */
							1);

	string_list_split(&params, arg, ',', -1);
	unsigned int then_atom_seen : 1,
		const char *color, *ep = strchr(sp, ')');
		}
	const char *behind;
	int i;
	 */
			fill_remote_ref_details(atom, refname, branch, &v->s);
			*s = xstrdup("");
	 */
{
	const char **patterns = filter->name_patterns;
	for (i = 0; i < used_atom_cnt; i++) {
	 * obtain the commit using the 'oid' available and discard all
	v->value = timestamp;
	}
	case OBJ_COMMIT:
			return strbuf_addf_ret(err, -1, _("missing object %s for %s"),
int filter_refs(struct ref_array *array, struct ref_filter *filter, unsigned int type)

			return xstrdup("");
		if (strtol_i(arg, 10, &atom->lstrip))
		case '\0':

 * Used to parse format string and sort specifiers
 */
			if (!eaten)
 * as per the given ref_filter structure and finally store the
/* See grab_values */
				 struct strbuf *err)
		BUG("Object size is less than zero.");
			atom->u.remote_ref.option = RR_TRACKSHORT;
}
	va_end(ap);
		return oid;
	for (i = 0; i < params.nr; i++) {
static void find_longest_prefixes(struct string_list *out,
				cp = copy_advance(cp, ",symref");
	strbuf_reset(&cur->output);
	free_array_item(ref_item);
				     opt->long_name);
			v->handler = if_atom_handler;

	}
	}
	struct align *align = &atom->u.align;
	if (format_ref_array_item(info, format, &final_buf, &error_buf))
}

		char color[COLOR_MAXLEN];
		return 0;
		const char *p = *pattern;
		if (strtoul_ui(arg, 10, &atom->u.objectname.length) ||
	else if (!strcmp(arg, "signature"))

	new_stack = state->stack;
static const char *rstrip_ref_components(const char *refname, int len)
	else {
	 */
{


	return 0;
					struct ref_to_worktree_entry, ent);
		} else if (!strcmp(name, "end")) {
	 * the object, and if we do grab the object it refers to.
	while (remaining-- > 0) {

		for (i = 0; i < params.nr; i++) {

				  const char *arg, struct strbuf *err)
static int objecttype_atom_parser(const struct ref_format *format, struct used_atom *atom,
		return for_each_fullref_in("", cb, cb_data, broken);
	void (*at_end)(struct ref_formatting_stack **stack);
				      const struct object_id *oid)
	int quote_style;
	       skip_prefix(refname, "refs/remotes/", &refname) ||
			else
		} else if (!num_ours && !num_theirs)
#include "ref-filter.h"
			remote_for_branch(branch, &explicit);
static int color_atom_parser(const struct ref_format *format, struct used_atom *atom,
	return 0;
			return ref_kind[i].kind;
	    !memcmp(&oi_deref.info, &empty, sizeof(empty)))
static const char *find_wholine(const char *who, int wholen, const char *buf)
			if_then_else->condition_satisfied = 1;
	if (arg) {
	enum { R_NORMAL, R_SHORT, R_LSTRIP, R_RSTRIP } option;
		    !strncmp(refname, p, plen) &&
		python_quote_buf(s, str);
{
		      const struct ref_format *format)
{
		atom->u.objectname.option = O_FULL;
}
		}
	{ "body", SOURCE_OBJ, FIELD_STR, body_atom_parser },
			v->s = xstrdup("");
		break;
		ret = for_each_fullref_in(prefix->string, cb, cb_data, broken);
		atom->u.contents.option = C_BARE;
			}
{
	if (!e)
		sp++; /* deref */
	grab_common_values(ref->value, deref, oi);
	atom->u.contents.option = C_SUB;
			return strbuf_addf_ret(err, -1, _("Integer value expected refname:lstrip=%s"), arg);
	*v = &ref->value[atom];
	/* skip any empty lines */
	atom->u.contents.trailer_opts.no_divider = 1;
}
			append_lines(&s, subpos, contents_end - subpos, atom->u.contents.nlines);
		int len = strlen(used_atom[i].name);
 *
			remaining--;
 * structure will hold an array of values extracted that can be
	if (filter->ignore_case)
	}
	free((char *)item->symref);
{
			return 0;
{
struct ref_array_item *ref_array_push(struct ref_array *array,
		atom->u.contents.option = C_SIG;
				if (0 <= ch) {
			/*  Size is the length of the message after removing the signature */
		}
}
	e = hashmap_get(&(ref_to_worktree_map.map), &entry, ref->refname);
		if (*eol)
	FREE_AND_NULL(used_atom);
			/* Format the trailer info according to the trailer_opts given */
			strbuf_addstr(&desc, HEAD_DETACHED_AT);
		strbuf_addbuf(&prev->output, &current->output);
 * of properties that we need to extract out of objects.  ref_array_item
	formatp = strchr(atomname, ':');
				string_list_clear(&params, 0);
			if (!strcmp(s, "unfold"))
	int i;
}
		if (atom->u.contents.option == C_SUB)
	struct contains_cache contains_cache;
	return 0;
	for (i = 0; i < used_atom_cnt; i++) {
			v->handler = else_atom_handler;
		return xstrdup("");
	struct hashmap_entry entry, *e;
		else if (!strcmp(name + wholen, "name"))
int format_ref_array_item(struct ref_array_item *info,
			v->s = copy_email(wholine);
	else if (!strcmp(s, "middle"))
static struct used_atom {
 * matches a pattern "refs/heads/" but not "refs/heads/m") or a
	struct if_then_else *if_then_else = (struct if_then_else *)cur->at_end_data;
			oi.info.sizep = &oi.size;
		} else if (!deref && grab_objectname(name, &ref->objectname, v, atom)) {
		do_merge_filter(&ref_cbdata);
			free((char *)to_free);
				RR_REF, RR_TRACK, RR_TRACKSHORT, RR_REMOTE_NAME, RR_REMOTE_REF
			v->handler = then_atom_handler;
		if (!wholine)
		*s = xstrdup(explicit ? remote : "");
			oi.info.contentp = &oi.content;
		const char *merge;
	const char *start = xstrdup(refname);
		return for_each_fullref_in("", cb, cb_data, broken);
#include "object-store.h"
			if (atom->u.remote_ref.push_remote)
			pop_stack_element(&cur);
		break;
		const char *refname;
		cmp = cmp_fn(va->s, vb->s);
	strbuf_release(&err);
			continue;

	{ "tree", SOURCE_OBJ },
	if (prepare_revision_walk(&revs))
			const char *branch_name;
				return -1;
	}
	{ "creator", SOURCE_OBJ },

	int no_merged = starts_with(opt->long_name, "no");
		s->version = 1;
	const char *name;
}
	if (flag & REF_BAD_NAME) {
		return strbuf_addf_ret(err, -1, _("format: %%(end) atom used without corresponding atom"));
	struct strbuf prefix = STRBUF_INIT;
	if (!arg)
		if (pos < 0 || get_ref_atom_value(info, pos, &atomv, error_buf) ||
	if (!current->at_end)
	struct object_id delta_base_oid;
			eol++;
	struct ref_filter *rf = opt->value;
		if (!deref)
				    state.detached_from);
	current = state->stack;
	for (i = 0; i < array->nr; i++)
	else if (!strcmp(s, "left"))
		struct atom_value *v = &val[i];
	for (i = 0; i < used_atom_cnt; i++) {

			break;
	ref->commit = commit;
		strbuf_addch(s, *cp);
		struct commit *commit = item->commit;
	else if (!strcmp(arg, "subject"))
		strbuf_addf(&desc, _("no branch, bisect started on %s"),
			v->s = xstrdup("");
		 * we only iterate through those refs. If a mix of refs is needed,
	if (!filter->match_as_path) {
			atom->u.remote_ref.nobracket = 1;
	cmp_type type;
	 * only on the topmost supporting atom.
	{ "objectsize", SOURCE_OTHER, FIELD_ULONG, objectsize_atom_parser },
			return;
			v->s = strbuf_detach(&s, NULL);
				atom->u.contents.trailer_opts.only_trailers = 1;
static const char *copy_line(const char *buf)
		else
		}
	if_then_else->cmp_status = atomv->atom->u.if_then_else.cmp_status;
	if_then_else->then_atom_seen = 1;
		    buf[wholen] == ' ')
			return -1;
	if (!filter->kind)
				 const char *arg, struct strbuf *err)
{
static int parse_sorting_atom(const char *atom)
	else if (skip_prefix(arg, "lstrip=", &arg) ||

		atom->u.contents.option = C_BODY;
			if (cp[1] == '(')
	}

	    state.rebase_interactive_in_progress) {
	void *content;

		else if (!strcmp(name, "parent")) {
struct ref_sorting *ref_default_sorting(void)
		i = end;
	eoemail = strchr(email, '>');
	}
	return xstrdup("");
			v->s = xstrdup(oid_to_hex(&tag->tagged->oid));
} valid_atom[] = {
		format->need_color_reset_at_eol = 0;
	"ahead %d",

	return xstrdup(lookup_result->wt->path);
		flags |= WM_CASEFOLD;
		return strbuf_addf_ret(err, -1, _("format: %%(else) atom used without an %%(if) atom"));
	case QUOTE_PERL:
	ref_cbdata.filter = filter;
		free(item->value);
	 * table.
		else if (!num_ours)
	if (filter->kind == FILTER_REFS_BRANCHES ||
	 * undone.
	 * already munged the global used_atoms list, which would need to be


	} else if (atom->u.remote_ref.option == RR_REMOTE_NAME) {
	{ "objecttype", SOURCE_OTHER, FIELD_STR, objecttype_atom_parser },
};
			v->s = xstrdup(oid_to_hex(&oi->delta_base_oid));

		else if (!strcmp(name, "object") && tag->tagged)
/*
		const char *name = used_atom[i].name;
			    const char *arg, struct strbuf *err)

	if (!arg)
			eol++;
	if (filter->points_at.nr && !match_points_at(&filter->points_at, oid, refname))
 * Given a ref (oid, refname), check if the ref belongs to the array
				       each_ref_fn cb,
	 * If the 'equals' or 'notequals' attribute is used then
				refname = branch_get_push(branch, NULL);
}

	free(to_clear);
	for (i = 0; i < len; i++)
		} else {
		strbuf_addstr(&state->stack->output, v->s);
			const char *str;
	align_type position;
			 */
 * wildcard (e.g. the same ref matches "refs/heads/m*", too).
			ret = for_each_fullref_in_pattern(filter, ref_filter_handler, &ref_cbdata, broken);
		else if (!strcmp(s, "nobracket"))
		 */
	if (skip_prefix(arg, "version:", &arg) ||
 */
	{ "worktreepath", SOURCE_NONE },
}
		resetv.s = GIT_COLOR_RESET;
	struct commit *commit = NULL;
		sq_quote_buf(s, str);
		 * of filter_ref_kind().
};
	for (i = 0; i < array->nr; i++) {

	const char *email = strchr(buf, '<');
{
}
	 * Perform quote formatting when the stack element is that of
		 */
		return strbuf_addf_ret(error_buf, -1, _("format: %%(end) atom missing"));
	if (oi->info.contentp) {
	}
	if (get_oid(arg, &oid))
				    struct branch *branch, const char **s)
			free((void *)to_free);
}

	for (i = 0; i < used_atom_cnt; i++) {

			format_trailers_from_commit(&s, subpos, &atom->u.contents.trailer_opts);
	}
		}
	/* drop trailing newline, if present */
	struct ref_formatting_stack *cur = *stack;
	return xmemdupz(email, eoemail + 1 - email);
}
			atom->u.remote_ref.push_remote = 1;
			continue;
static int cmp_ref_sorting(struct ref_sorting *s, struct ref_array_item *a, struct ref_array_item *b)
	}
	for (; *patterns; patterns++) {
			else {
/*
		return ALIGN_LEFT;

	struct strbuf desc = STRBUF_INIT;
	const char *wholine = NULL;
	strbuf_release(&err);
}
{
}
		add_pending_object(&revs, &item->commit->object, item->refname);
{

				 const char *atom, const char *ep,

		struct atom_value *v = &val[i];
		/* ...or for the `--no-contains' option */

		return strbuf_addf_ret(err, -1, _("format: %%(then) atom used more than once"));
			p[0] = '\0';
		} if_then_else;
		else if (!num_theirs)
{
		char c = patterns[i][prefix->len];
	int i;
	if (arg)

		else if (!strcmp(s, "trackshort"))
	struct ref_array_item *ref;

 * pointed at by the ref itself; otherwise it is the object the
		    (refname[plen] == '\0' ||
	v->s = xstrdup("");

	case OBJ_TREE:
	} else if (skip_prefix(arg, "lines=", &arg)) {
				v->s = xstrdup("*");

 */

{
	else if (!strcmp(arg, "short"))
	strbuf_addch(&desc, '(');
		strbuf_swap(&current->output, &s);
{
			     const char *arg, struct strbuf *err)
{
		struct atom_value *v = &ref->value[i];
static int filter_ref_kind(struct ref_filter *filter, const char *refname)
		} else if (atom->u.objectname.option == O_FULL) {
	const char *eol;
			const char *to_free = *s;
		for (end = i + 1; end < nr; end++) {
				string_list_clear(&params, 0);
}
		if (!strcmp(name, "tag"))
	}
	int i;
	if (!email)
}
		if (atom->u.objectname.length < MINIMUM_ABBREV)
		if (deref)
			continue;
 * the need to parse the object via parse_object(). peel_ref() might be a
	}
	long remaining = len;
	struct ref_array_item *ref_item;
	pop_stack_element(&state.stack);
		atom->u.if_then_else.cmp_status = COMPARE_NONE;
	const char *gone;
		/*
	struct ref_array *array;
{
		const char *s = params.items[i].string;

 * of oids. If the given ref is a tag, check if the given tag points
					     NULL, NULL);
	while (*buf == '\n')
		if (atom->u.objectname.option == O_SHORT) {

			continue;
	{ "taggeremail", SOURCE_OBJ },
	repo_init_revisions(the_repository, &revs, NULL);
	switch (quote_style) {
 * matches a pattern "refs/heads/mas") or a wildcard (e.g. the same ref
	clear_commit_marks(filter->merge_commit, ALL_REV_FLAGS);
	sp = atom;
				    &bodypos, &bodylen, &nonsiglen,
static int head_atom_parser(const struct ref_format *format, struct used_atom *atom,
	} else if (state.bisect_in_progress)
		}
	struct ref_filter_cbdata ref_cbdata;
			append_literal(cp, sp, &state);
				continue;
				  const char **patterns)
	}
 * that do not apply (e.g. "authordate" for a tag object)
			v->s = xstrdup(oid_to_hex(get_commit_tree_oid(commit)));
	if (!state->stack->prev)

		BUG("unhandled RR_* enum");
		/* Find total no of '/' separated path-components */

	s->prev = *stack;
	fwrite(final_buf.buf, 1, final_buf.len, stdout);
			   struct atom_value *v, struct used_atom *atom)
		return 0;
int parse_opt_merge_filter(const struct option *opt, const char *arg, int unset)

		else if (deref)

	/* parse_object_buffer() will set eaten to 0 if free() will be needed */

		struct align align;
static const char *lstrip_ref_components(const char *refname, int len)
	 * which peels the onion to the core.
	/*
	for (cp = buf; *cp && *cp != '\n'; cp++) {
}
		goto bad;
		atom->u.remote_ref.push = 1;

 * ref (which is a tag) refers to.
	if (used_atom[at].source == SOURCE_OBJ) {

static const char *get_symref(struct used_atom *atom, struct ref_array_item *ref)
	 /* Untranslated plumbing messages: */
	atom->u.head = resolve_refdup("HEAD", RESOLVE_REF_READING, NULL, NULL);
		}
	else if (cmp_type == FIELD_STR)

			pushremote_for_branch(branch, &explicit) :

	int i;
	strbuf_release(&prefix);
};
	ref->flag = flag;
			const char **sub, unsigned long *sublen,
}

	ref_item = new_ref_array_item(name, oid);
	}
			unsigned int nobracket : 1, push : 1, push_remote : 1;
		buf = eol;
		return strbuf_addf_ret(err, -1, _("unrecognized %%(objectname) argument: %s"), arg);
		oi.info.contentp = &oi.content;
		} contents;
			   const struct ref_format *format,


		return lstrip_ref_components(refname, atom->lstrip);
{
	{ "contents", SOURCE_OBJ, FIELD_STR, contents_atom_parser },

	const char *formatp;
			continue;

	struct object_id oid;
{
		break;
	else if (atom->option == R_RSTRIP)
}
			grab_objectname(name, &oi->oid, v, &used_atom[i]);
	 */
	 */
static int objectsize_atom_parser(const struct ref_format *format, struct used_atom *atom,
 * Expand string, append it to strbuf *sb, then return error code ret.
		     refname[plen] == '/' ||
		arg++;
		cp++;
	info_source source;
		if (v->s == NULL && used_atom[i].source == SOURCE_NONE)
	if (*arg == '-') {
	const char *cp, *sp, *ep;
	else
/* See grab_values */
			strbuf_addstr(out, "\n    ");
			struct ref_to_worktree_entry *entry;
	struct hashmap map;
		int at;

	}
		return ALIGN_MIDDLE;
	array->nr = array->alloc = 0;
		 * because we count the number of '/', but the number
	if (arg)
				const char *arg, struct strbuf *err)
	struct object *obj;

		len = eol ? eol - sp : size - (sp - buf);
				  const char *arg, struct strbuf *err)
		die(_("malformed object name %s"), arg);
{
{
		return;
				v->s = xstrdup(s);
			enum {
			entry = xmalloc(sizeof(*entry));
#include "commit-slab.h"

		else if (!strcmp(name, "creator"))

static char *copy_subject(const char *buf, unsigned long len)
{
		if (append_atom(&resetv, &state, error_buf)) {
				       int broken)
		const char *name = atom->name;
		pos = parse_ref_filter_atom(format, sp + 2, ep, error_buf);
{
	return ret;

		string_list_clear(&params, 0);

	if (oi->info.disk_sizep && oi->disk_size < 0)
{

	if (arg)
	}
/*  Free memory allocated for a ref_array_item */
		switch (*start++) {
	struct ref_formatting_stack *prev = state->stack;
			struct strbuf s = STRBUF_INIT;



			v->s = xmemdupz(sigpos, siglen);
		tcl_quote_buf(s, str);
}
}
static int ref_kind_from_refname(const char *refname)
	return (s->reverse) ? -cmp : cmp;
	case OBJ_BLOB:
			return -1;
	if (if_then_else->then_atom_seen)
	struct ref_filter *filter;
			continue;
		grab_sub_body_contents(val, deref, buf);
		else
	const char *eoemail = strstr(buf, "> ");
			*s = xstrfmt(msgs.ahead, num_ours);
	off_t disk_size;
static int used_atom_cnt, need_tagged, need_symref;
static void grab_date(const char *buf, struct atom_value *v, const char *atomname)

	oi.oid = ref->objectname;
	struct if_then_else *if_then_else = NULL;
		}
			if (strtoul_ui(s, 10, &width)) {
}
	}

#include "color.h"
		return; /* "author" for commit object is not wanted */
	/*
	ref_cbdata.array = array;
	/* Fill in specials first */
		const char *name = used_atom[i].name;
		atom->u.contents.option = C_LINES;
		struct branch *branch = NULL;
}
	if ((tz == LONG_MIN || tz == LONG_MAX) && errno == ERANGE)
	if (!eaten)
		struct ref_array_item *item = array->items[i];
{
static int grab_objectname(const char *name, const struct object_id *oid,
}
		struct used_atom *atom = &used_atom[i];
	sorting->atom = parse_sorting_atom(cstr_name);
				v->s = xstrdup("");
	msgs.behind = _("behind %d");
			strbuf_addstr(&desc, HEAD_DETACHED_FROM);
	state.quote_style = format->quote_style;
			grab_date(wholine, v, name);

{
	if (filter->ignore_case)
	string_list_split(&params, arg, ',', -1);
				int ch = hex2chr(cp + 1);
{
			const char *branch_name;

	struct ref_formatting_stack *new_stack;
	{ "trailers", SOURCE_OBJ, FIELD_STR, trailers_atom_parser },

			refname = get_symref(atom, ref);
	if (ARRAY_SIZE(valid_atom) <= i)
		struct strbuf err = STRBUF_INIT;
	if (s->version)
#include "trailer.h"
	struct ref_format dummy = REF_FORMAT_INIT;
}
	argv_array_clear(&sorted);
{
		return show_ref(&atom->u.refname, ref->symref);
{
}
	char *zone;
				if (!refname)
#include "cache.h"
				     OBJECT_INFO_LOOKUP_REPLACE))
			}
		}
		 * condition is not satisfied.
	}
/*
		 * No %(else) atom: just drop the %(then) branch if the

		} else if (atom->u.contents.option == C_TRAILERS) {
				continue;
			struct refname_atom refname;
		: REF_FILTER_MERGED_INCLUDE;
		else if (atom->u.contents.option == C_BODY)

{
			return 1;
	void *at_end_data;

	if (!arg)
	}
					strbuf_addch(s, ch);
			v->value = commit_list_count(commit->parents);
/*
	free(state.onto);
		return 0;
	} else if (skip_prefix(arg, "equals=", &atom->u.if_then_else.str)) {
		to_clear[i] = item->commit;
 */
		if (skip_prefix(used_atom[at].name, "color:", &color))
	struct wt_status_state state;
	used_atom[at].name = xmemdupz(atom, ep - atom);
				break;
	atom->u.contents.option = C_BODY_DEP;
	{ "end", SOURCE_NONE },
	*sub = buf;
	if (*atom->name == '*')

#include "quote.h"

/*
	format->need_color_reset_at_eol = 0;
	/* Add it in, including the deref prefix */
{
	int wholen = strlen(who);
	if (get_ref_atom_value(b, s->atom, &vb, &err))
void ref_array_clear(struct ref_array *array)
 * This is the same as for_each_fullref_in(), but it tries to iterate
}
			continue;
			if (skip_prefix(name, "if:", &s))
		} objectname;
			for (parents = commit->parents; parents; parents = parents->next) {
	struct ref_to_worktree_entry *lookup_result;
					       oid_to_hex(&oi->oid), ref->refname);

		atom->option = R_SHORT;
			    struct strbuf *err)
		color_parse("", atom->u.color);
		} else if (!strcmp(name, "HEAD")) {
			continue;
			*s = xstrdup("");
		if (state.detached_at)
	return 0;
				}

{
		}
 * A pattern can be path prefix (e.g. a refname "refs/heads/master"
				      const struct hashmap_entry *eptr,
			if (cp == buf)
		struct atom_value *atomv;

			hashmap_add(map, &entry->ent);
			name++;
				       AHEAD_BEHIND_FULL) < 0) {
static int else_atom_handler(struct atom_value *atomv, struct ref_formatting_state *state,
					 &branch_name))
		 * the total minus the components to be left (Plus one
		flags |= WM_CASEFOLD;
	struct ref_filter *filter = ref_cbdata->filter;
		}
	{ "tag", SOURCE_OBJ },
/* See grab_values */
{
	struct ref_formatting_stack *prev;
			name++;

	used_atom_cnt = 0;
			if (refname)
	}
		else
			else if (!strcmp(s, "only"))
/*
		return 0;
		atom->u.if_then_else.cmp_status = COMPARE_EQUAL;
			if (ref->flag & REF_ISSYMREF)
		oi->info.sizep = &oi->size;
				v->s = xstrdup("");
	 * encountered.
	const char *b = *(const char **)vb;


			continue;
#include "wt-status.h"
	}
	if (prev)
	 */
{
	start = xstrdup(start);
}
		struct atom_value resetv;
			return strbuf_addf_ret(err, -1, _("Integer value expected refname:rstrip=%s"), arg);
struct atom_value {
		 * The number of components we need to strip is now
 */
		broken = 1;
		    !commit_contains(filter, commit, filter->with_commit, &ref_cbdata->contains_cache))
			return "";
	if (!if_then_else->then_atom_seen)
	 * Quote formatting is only done when the stack has a single
	arg = memchr(sp, ':', ep - sp);
	}
}


		if (!strncmp(cp, " <", 2))
	const struct object_id *tagged_oid = NULL;
				strbuf_addstr(&s, oid_to_hex(&parent->object.oid));
	 */
			/* otherwise this is a singleton, literal % */
			}
		*/
		else if (!num_theirs)
 */
{
		parse_date_format(formatp, &date_mode);
static void push_stack_element(struct ref_formatting_stack **stack)
	for (i = 0; i < used_atom_cnt; i++) {
		char *p = strrchr(start, '/');
		else
			;
}
		if (populate_value(ref, err))


		return strbuf_addf_ret(err, -1, _("unrecognized color: %%(color:%s)"),
			pop_stack_element(&state.stack);

	struct strbuf final_buf = STRBUF_INIT;
 * has requested, we iterate through those refs and apply filters

				  struct strbuf *prefix,
			/* We will definitely re-init v->s on the next line. */
		       struct strbuf *unused_err)
static int filter_pattern_match(struct ref_filter *filter, const char *refname)
	if_then_else->else_atom_seen = 1;
		const char *name = used_atom[i].name;
	 */
	const char *ahead;
typedef enum { COMPARE_EQUAL, COMPARE_UNEQUAL, COMPARE_NONE } cmp_status;
	if (flag & REF_ISBROKEN) {
			return strbuf_addf_ret(err, -1, _("parse_object_buffer failed on %s for %s"),
		return 1; /* No pattern always matches */

	const char *ahead_behind;
		    strcmp(name, "body") &&
/* Free all memory allocated for ref_array */
				    &sigpos, &siglen);
}
static void if_then_else_handler(struct ref_formatting_stack **stack)
		if (strcmp(if_then_else->str, cur->output.buf))
	memset(&used_atom[at].u, 0, sizeof(used_atom[at].u));
{
	}
		return ALIGN_RIGHT;
	{ "align", SOURCE_NONE, FIELD_STR, align_atom_parser },
	} else if (!strcmp(arg, "disk")) {
 * Return 1 if the refname matches one of the patterns, otherwise 0.
	/*
	{ "committer", SOURCE_OBJ },
	}
		int is_merged = !!(commit->object.flags & UNINTERESTING);

			     struct strbuf *err)

	struct ref_array_item *a = *((struct ref_array_item **)a_);
	return r;
			struct commit_list *parents;
static int refname_atom_parser(const struct ref_format *format, struct used_atom *atom,
	*sublen = buf - *sub;
		return strbuf_addf_ret(err, -1, _("unrecognized %%(%s) argument: %s"), name, arg);
}

	string_list_clear(&params, 0);
	struct strbuf output;
				*cp = '\0';
{
	/*  Filters that need revision walking */
		die(_("revision walk setup failed"));
			*s = xstrdup("<>");
struct align {
{
	if (filter->match_as_path)
	/* Obtain the current ref kind from filter_ref_kind() and ignore unwanted refs. */
	} else
	int i;
			v->s = xstrdup(find_unique_abbrev(oid, atom->u.objectname.length));
		die(_("format: %%(if) atom used without a %%(then) atom"));
	 * NEEDSWORK: This derefs tag only once, which

	 * non-commits early. The actual filtering is done later.
		else
	/* skip past header until we hit empty line */
		struct {
	struct ref_sorting *sorting = xcalloc(1, sizeof(*sorting));
int verify_ref_format(struct ref_format *format)

		 */
	int ret = 0;
		else

	return dst;
		goto bad;

	if (!strcmp(valid_atom[i].name, "symref"))
		} else if (!strcmp(name, "then")) {

	} else

static const char *copy_name(const char *buf)
				       (int)(ep-atom), atom);
		return for_each_fullref_in("", cb, cb_data, broken);
	"gone",
		if ((plen <= namelen) &&
		warning(_("ignoring ref with broken name %s"), refname);
}
	{ "authoremail", SOURCE_OBJ },


int parse_opt_ref_sorting(const struct option *opt, const char *arg, int unset)
		grab_tag_values(val, deref, obj);
	struct align *align = (struct align *)cur->at_end_data;
	for (i = 0; i < used_atom_cnt; i++) {
{
	if (valid_atom[i].source != SOURCE_NONE && !have_git_dir())
			continue;
	else if (atom->option == R_LSTRIP)
		return strbuf_addf_ret(err, -1, _("format: %%(else) atom used more than once"));
		commit = lookup_commit_reference_gently(the_repository, oid,
void ref_array_sort(struct ref_sorting *sorting, struct ref_array *array)
		if (v->s == NULL)
	if (format->need_color_reset_at_eol && !want_color(format->use_color))
				strbuf_addf(err, _("unrecognized width:%s"), s);
	const char *to_free = start;
			format->need_color_reset_at_eol = !!strcmp(color, "reset");
				       (int)(ep-atom), atom);
		} remote_ref;
	sp = buf;
		for (i = 0; i < used_atom_cnt; i++)
	clear_contains_cache(&ref_cbdata.contains_cache);
		/* sp points at "%(" and ep points at the closing ")" */
		} else {
		grab_commit_values(val, deref, obj);
	if (!wholine)
static int align_atom_handler(struct atom_value *atomv, struct ref_formatting_state *state,
		if (strncmp(who, name, wholen))

			struct process_trailer_options trailer_opts;
	oidcpy(&ref->objectname, oid);
		*dst++ = *src++;
	if (!wholine)
		if (deref)
		/* grab_blob_values(val, deref, obj, buf, sz); */
	if (rf->merge) {
	BUG_ON_OPT_NEG(unset);

	} else
		else if (!strcmp(name, "numparent")) {



{
		struct atom_value *v = &val[i];
		return strbuf_addf_ret(err, -1, _("unrecognized %%(if) argument: %s"), arg);

	};
	parse_ref_sorting(opt->value, arg);
}
	{ "color", SOURCE_NONE, FIELD_STR, color_atom_parser },

	return show_ref(&atom->u.refname, ref->refname);
} ref_to_worktree_map;
			free_array_item(item);
	else if (skip_prefix(arg, "short=", &arg)) {

}

		 * of components is one more than the no of '/').
	switch (obj->type) {
	struct strbuf error_buf = STRBUF_INIT;
	{ "HEAD", SOURCE_NONE, FIELD_STR, head_atom_parser },

	if (cur->at_end == if_then_else_handler)
			return -1;
		 */
	if (need_symref && (ref->flag & REF_ISSYMREF) && !ref->symref) {
	while (*cp && (!ep || cp < ep)) {
		 * the %(then) branch if it isn't.
			continue;
	} ref_kind[] = {
		return strbuf_addf_ret(err, -1, _("%%(subject) does not take arguments"));
						    arg, atom->name, err);
			}
			return buf + wholen + 1;
	strbuf_vaddf(sb, fmt, ap);
	return;
#include "tag.h"

	}
	for (; *pattern; pattern++) {
		}
	}
			name++;
		if (is_merged == (filter->merge == REF_FILTER_MERGED_INCLUDE))
		strbuf_addch(prefix, patterns[i][prefix->len]);

{
		free((char *)refname);
 * An atom is a valid field atom listed below, possibly prefixed with
		/*
		if (!ep)
	ref_item->kind = ref_kind_from_refname(name);
		atom->option = R_LSTRIP;
	}
#include "version.h"
}
	{ "type", SOURCE_OBJ },

		else if ((position = parse_align_position(s)) >= 0)
		if (!!deref != (*name == '*'))
	case QUOTE_SHELL:
		return strbuf_addf_ret(err, -1, _("expected format: %%(align:<width>,<position>)"));
	if (filter->ignore_case) {
		arg = used_atom[at].name + (arg - atom) + 1;
typedef enum { FIELD_STR, FIELD_ULONG, FIELD_TIME } cmp_type;
static int remote_ref_atom_parser(const struct ref_format *format, struct used_atom *atom,
{
	const char *eol;
static int get_ref_atom_value(struct ref_array_item *ref, int atom,
				return -1;
		struct atom_value *v = &val[i];
	return ref;
	struct ref_formatting_stack *s = xcalloc(1, sizeof(struct ref_formatting_stack));
	while (*buf == '\n')
 * a "*" to denote deref_tag().


	const char *end = atom + strlen(atom);
		append_literal(cp, sp, &state);
#include "utf8.h"
			  const char *arg, struct strbuf *err)
	 */
	const char *s;
{
		else if (starts_with(name, "upstream")) {
	"ahead %d, behind %d"
	if (!eoemail)
	/*

static void append_literal(const char *cp, const char *ep, struct ref_formatting_state *state)
static struct {
			 * "%(atom:)" is equivalent to "%(atom)").
			hashmap_entry_init(&entry->ent,
			refname = branch_get_upstream(branch, NULL);
	return FILTER_REFS_OTHERS;

	for (i = 0; i < params.nr; i++) {
	 */
		if (!!deref != (*name == '*'))
		else_atom_seen : 1,
			   struct strbuf *error_buf)
}
		sp = eol + 1;
	       skip_prefix(refname, "refs/", &refname));
			atom->u.objectname.length = MINIMUM_ABBREV;
			atom->u.remote_ref.push_remote = 1;
	return ref;
 */
			v->s = strbuf_detach(&s, NULL);
		 * we iterate over all refs and filter out required refs with the help
		if_then_else = (struct if_then_else *)prev->at_end_data;
	free(current);
				return -1;
static inline char *copy_advance(char *dst, const char *src)
/*
static void grab_commit_values(struct atom_value *val, int deref, struct object *obj)

		ref_to_worktree_map.worktrees = NULL;
static void quote_formatting(struct strbuf *s, const char *str, int quote_style)
	 * is not consistent with what deref_tag() does

				cp++;
	(void)(skip_prefix(refname, "refs/tags/", &refname) ||
			strbuf_addf(&desc, _("no branch, rebasing detached HEAD %s"),
	return match_pattern(filter, refname);

	rf->merge = no_merged
	/* skip any empty lines */
 * 1. Only a single level of inderection is obtained, we might want to
		goto bad;
	{ "deltabase", SOURCE_OTHER, FIELD_STR, deltabase_atom_parser },
	for (cp = format->format; *cp && (sp = find_next(cp)); cp = ep + 1) {
		return 0;

 * matches "refs/heads/mas*", too).
static int match_pattern(const struct ref_filter *filter, const char *refname)
		}
	atom->u.remote_ref.nobracket = 0;

		return strbuf_addf_ret(err, -1, _("expected format: %%(color:<color>)"));
/* See grab_values */
		if (ret)
	 * a supporting atom. If nested then perform quote formatting
	struct ref_sorting *s;
		 * The number of components we need to strip is now
{
}
	}
	filter->kind = type & FILTER_REFS_KIND_MASK;
	struct worktree *wt; /* key is wt->head_ref */
			continue;
	while (buf < *sig && *buf && *buf != '\n') {
			v->s = xstrdup("");
			cmp_status cmp_status;
	return start;
	}
			atom->u.remote_ref.option = RR_REMOTE_REF;
		else if (!strcmp(name + wholen, "email"))
}
		cp = ep + 1;
			cmp = cmp_fn(a->refname, b->refname);
static int deltabase_atom_parser(const struct ref_format *format, struct used_atom *atom,
}
	}
static int qsort_strcmp(const void *va, const void *vb)
{
/*
		die("Eh?  Object of type %d?", obj->type);
	if (color_parse(color_value, atom->u.color) < 0)
		quote_formatting(&state->stack->output, v->s, state->quote_style);
			continue;


	if (starts_with(name, "objectname")) {
			continue;
	{ "subject", SOURCE_OBJ, FIELD_STR, subject_atom_parser },
		if (state.branch)
			*s = xstrdup("<");
static int objectname_atom_parser(const struct ref_format *format, struct used_atom *atom,

		} else
		else if (!num_ours)
	while (*src)
	{ "if", SOURCE_NONE, FIELD_STR, if_atom_parser },
	used_atom[at].type = valid_atom[i].cmp_type;
 * the values for atoms in used_atom array out of (obj, buf, sz).
#include "repository.h"
		cp++;
		return;
			return 1;
	{ "creatordate", SOURCE_OBJ, FIELD_TIME },
}
		if (name[wholen] != 0 &&
{

			ret = for_each_fullref_in("refs/heads/", ref_filter_handler, &ref_cbdata, broken);
		int i;
	return NULL;
	if (width == ~0U) {
	*sig = buf + parse_signature(buf, strlen(buf));
	used_atom[at].source = valid_atom[i].source;

static void fill_remote_ref_details(struct used_atom *atom, const char *refname,
}
		if (!strncmp(buf, who, wholen) &&
			    const char *arg, struct strbuf *unused_err)
			atom->u.remote_ref.option = RR_REMOTE_NAME;
				v->s = xstrdup("");
			atom->u.remote_ref.option = RR_REF;

	}
	if_then_else->str = atomv->atom->u.if_then_else.str;
		if (*cp == '%') {
	hashmap_init(&(ref_to_worktree_map.map), ref_to_worktree_map_cmpfnc, NULL, 0);
			name++;
	if (*cp) {
static const char *find_next(const char *cp)
	ref_to_worktree_map.worktrees = get_worktrees(0);
	} else if (skip_prefix(arg, "rstrip=", &arg)) {
	find_longest_prefixes(&prefixes, filter->name_patterns);
	strbuf_release(&error_buf);
		 * stack, either the %(else) branch if the condition is satisfied, or
	int i;
	return 0;
		if (*atom->name == '*')
		/*
	populate_worktree_map(&(ref_to_worktree_map.map), ref_to_worktree_map.worktrees);
	*sorting_tail = s;
		if (!strcmp(s, "track"))
			v->s = copy_name(wholine);
		/* We perform the filtering for the '--contains' option... */
#include "parse-options.h"
	new_stack = state->stack;

		if (!wildmatch(*patterns, refname, flags))


		else if (!strcmp(name, "worktreepath")) {
	/*  Simple per-ref filtering */
{
	unsigned int width = ~0U;
	for (i = 0; i < nr; i++) {
}
		if (!commit)
		if (stat_tracking_info(branch, &num_ours, &num_theirs,
	unsigned flags = WM_PATHNAME;
			return i;
	 */
				  const char **patterns, size_t nr)
{
 */
			continue;
			strbuf_reset(&cur->output);
	if (!current->prev->prev) {

		return xstrdup(refname);
		return strbuf_addf_ret(err, -1,
	if (!arg) {
			      struct strbuf *unused_err)
	{ "committerdate", SOURCE_OBJ, FIELD_TIME },
	push_stack_element(&state->stack);

	struct strbuf err = STRBUF_INIT;
}
	}

	return ret;

	if (if_then_else->else_atom_seen) {
	}
			position = parse_align_position(s);
					 const char *name, struct strbuf *err)
		oi->info.typep = &oi->type;
	*stack = prev;
	*stack = cur;
{
 * We want to have empty print-string for field requests
		else
}
	if (if_then_else->else_atom_seen)
	}
/* See grab_values */

	at = used_atom_cnt;
			if (refname_atom_parser_internal(&atom->u.remote_ref.refname,
		remaining = i + len + 1;
	return 0;
				    &subpos, &sublen,

				     opt->long_name);
 *
}
	return 0;
		* in our group.
	strbuf_release(&s);
	int namelen = strlen(refname);
	struct object_info info;
void setup_ref_filter_porcelain_msg(void)
			pop_stack_element(&state.stack);
		else if (!strcmp(name, "objectsize:disk")) {

				refname = NULL;
	for (i = 0; worktrees[i]; i++) {
	if (prev->at_end == if_then_else_handler)


	timestamp = parse_timestamp(eoemail + 2, &zone, 10);

	 * The ( character must be hard-coded and not part of a localizable
		s++;
			v->s = xstrdup("");
		    atomv->handler(atomv, &state, error_buf)) {

	/*
	}
		if (!eol)
	struct ref_filter_cbdata *ref_cbdata = cb_data;

	 * perform the required comparison. If not, only non-empty

	int i;
	struct ref_formatting_stack *current = *stack;

	cmp_fn = s->ignore_case ? strcasecmp : strcmp;
