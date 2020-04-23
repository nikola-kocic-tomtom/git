{
	unsigned num_matches;
static inline void vector_lock(void)
			len--;

		const struct git_attr *attr;
	}
		assert(a->attr_nr ==

	struct match_attr **attrs;

#include "cache.h"
struct attr_state {
	const char *cp, *last_slash = NULL;
	 * empty string.
		size_t n = check->items[i].attr->attr_nr;

	for (cp = states, i = 0; *cp; i++) {
static inline void hashmap_lock(struct attr_hashmap *map)
 * a macro needs to be expanded during the fill stage.
	}
				      pat->patternlen, pat->flags);
static const char *builtin_attr[] = {
	struct attr_check *check;
 * (3) $GIT_DIR/info/attributes, which overrides both of the above.
{
	/* system-wide frame */
}
			elem->originlen = originlen;
			cp++;
	}
void attr_check_reset(struct attr_check *check)

 * Retrieve the 'value' stored in a hashmap given the provided 'key'.
	struct attr_stack *res = NULL;
static void handle_attr_line(struct attr_stack *res,
};
}
	 * field), reallocate the provided attr_check instance's all_attrs
struct git_attr {
		e->attr = git_attr_internal(cp, len);
{

	 * When checking, we use entries from near the top of the
const char git_attr__false[] = "\0(builtin)false";
			       const char *path,
}
	struct attr_stack *res;
			       const void *unused_keydata)

/*

}
	FREE_AND_NULL(check->items);


				   name, src, lineno);
	} else if (!is_bare_repository()) {
 */
static void all_attrs_init(struct attr_hashmap *map, struct attr_check *check)
	struct attr_check **checks;
			       const struct hashmap_entry *eptr,
	char *buf, *sp;
}
	char name[FLEX_ARRAY]; /* attribute name */
{
	size_t keylen; /* length of the key */
			skip_utf8_bom(&bufp, strlen(bufp));
void attr_start(void)
#define debug_push(a) do { ; } while (0)
 */
{
}
		while (len < dirlen && !is_dir_sep(path[len]))
		int j;


		handle_attr_line(res, bufp, path, ++lineno, macro_ok);
static struct attr_stack *read_attr_from_array(const char **list)
	}
		/* Skip path-separator */
		const char *base = stack->origin ? stack->origin : "";
}

static void attr_hashmap_add(struct attr_hashmap *map,
void git_attr_set_direction(enum git_attr_direction new_direction)
	 * of $(prefix)/etc/gitattributes and a file specified by
{
static struct attr_stack *read_attr_from_index(const struct index_state *istate,

}
static void drop_all_attr_stacks(void)
 * of attributes.
					  const struct git_attr *attr)
	if (!attr_name_valid(name, namelen))
 * If check->check_nr is non-zero, only attributes in check[] are collected.
 *
	 */
 *
 * One rule, as from a .gitattributes file.
	for (i = a->num_attr - 1; rem > 0 && i >= 0; i--) {
	ret = attr_check_alloc();

 * another thread could potentially be calling into the attribute system.
#define ATTR__UNKNOWN git_attr__unknown
	return rem;
	NULL,
	int pathlen, rem, dirlen;
 * rule applies.
		/* Find the end of the next component */
}
	 * Re-initialize every entry in check->all_attrs.
	va_list params;
}
		const char **n = &(all_attrs[attr->attr_nr].value);
		return 0;
static int macroexpand_one(struct all_attrs_item *all_attrs, int nr, int rem);
	 *
			    check->nr, cnt);

} check_vector;
struct attr_check *attr_check_initl(const char *one, ...)
}
	/*
		*ep = '\0';
			else
	const char *cp, *name, *states;
	/* Build up to the directory 'path' is in */
			       const char *path, int dirlen,
			const struct pattern *pat,
static int attr_hash_entry_cmp(const void *unused_cmp_data,
	if (*cp == '"' && !unquote_c_style(&pattern, name, &states)) {


	for (i = 0; i < check->all_attrs_nr; i++) {
		check->all_attrs_nr = size;
}
			res = read_attr_from_file(path, macro_ok);
{
#define ATTR__UNSET NULL


		namelen = strcspn(name, blank);
		item = attr_check_append(check, git_attr(name));
					       const char *path,

	}
	return 1;
	if (!map->map.tablesize)
	unsigned alloc;
		if (!param)
{
	struct match_attr *res = NULL;
					 &a->u.pat, base, stack->originlen))
 * an insanely large number of attributes.
	va_end(params);
			return NULL;
static void determine_macros(struct all_attrs_item *all_attrs,
				res = read_attr_from_file(path, macro_ok);
	int is_macro;

	unsigned num_attr;
{
#if DEBUG_ATTR
	for (i = 0; i < check_vector.nr; i++)
	fprintf(stderr, "%s: %s => %s (%s)\n",

		}



			len--;
	return e ? e->value : NULL;
}
{
	int lineno = 0;
		check->all_attrs[i].macro = NULL;
{
static int attr_name_valid(const char *name, size_t namelen)
		int i;
		struct attr_stack *elem;
/*
	pthread_mutex_unlock(&map->mutex);

			     const char *src,
	for (i = 0; i < e->num_matches; i++) {
	char buf[2048];
	while ((*stack)->origin) {


			     int lineno,
#endif
static inline void vector_unlock(void)
	free(e->origin);
		char ch = *name++;
		}

	size = hashmap_get_size(&map->map);
		       ('a' <= ch && ch <= 'z') ||
static int macroexpand_one(struct all_attrs_item *all_attrs, int nr, int rem)

	const struct match_attr *macro;
		check_vector.checks[i] = check_vector.checks[i + 1];
/*
		for (i = stack->num_matches - 1; i >= 0; i--) {
	fprintf(stderr, "%s: %s\n", what, elem->origin ? elem->origin : "()");

				 */

		}
	check->nr = 0;
	va_start(params, one);
 * global list, we would have entries from info/attributes the earliest
 * If is_macro is true, then u.attr is a pointer to the git_attr being
	/*
	for (; stack; stack = stack->prev) {

{
		parse_path_pattern(&res->u.pat.pattern,
	 * Attribute name cannot begin with '-' and must consist of
		if (namelen <= dirlen &&
		if (!cp)
	struct attr_check *ret;
	 * the root one (whose origin is an empty string "") or the builtin

{
	res = xcalloc(1,
static void check_vector_remove(struct attr_check *check)
		if (pathbuf.len > 0)
		if (*cp == '-' || *cp == '!') {
	ALLOC_GROW(check_vector.checks,
	k.key = key;
	bootstrap_attr_stack(istate, stack);
			int basename_offset,
			      struct attr_state *e)
	}
	int lineno = 0;
		*stack = elem->prev;
	collect_some_attrs(istate, path, check);
static struct attr_stack *read_attr(const struct index_state *istate,
		}
	pthread_mutex_t mutex;
	hashmap_add(&map->map, &e->ent);
			}
	    starts_with(name, ATTRIBUTE_MACRO_PREFIX)) {
/*
		BUG("non-INDEX attr direction in a bare repo");

static void report_invalid_attr(const char *name, size_t len,
		char *ep;
	}
			value = ATTR__UNSET;
			goto fail_return;
	/* home directory */
	}
#include "utf8.h"

	struct attr_stack *res;
 * In the same file, later entries override the earlier match, so in the
}
{
	 */

 * Otherwise all attributes are collected.
{
		}
	return git_attr_internal(name, strlen(name));
	const char *param;
	ret->alloc = check->alloc;
		check->all_attrs[i].value = ATTR__UNKNOWN;
	cp = line + strspn(line, blank);
	int lineno = 0;

		struct attr_stack *elem = *stack;
/*
 *

}
	}
 * Handle git attributes.  See gitattributes(5) for a description of
	}

	pathlen = cp - path;
	} else {
	int cnt;
			       struct attr_stack **stack)
	struct attr_stack *prev;
 *
	res = xcalloc(1, sizeof(*res));
{
	if (!istate)
		}
struct attr_hashmap {
			     int macro_ok)
	all_attrs_init(&g_attr_hashmap, check);
		 * e == NULL in the first pass and then e != NULL in
		if (*n == ATTR__UNKNOWN) {
		value = "set";
{

	if (i >= check_vector.nr)
	attr_check_reset(check);
		hashmap_for_each_entry(&map->map, &iter, e,

}
	int patternlen;

 */


	 * set of attribute definitions, followed by the contents
};
			if (!res)
	}
				      &res->u.pat.patternlen,
			len++;
	 * and finally use the built-in set as the default.
	e = read_attr(istate, GITATTRIBUTES_FILE, 1);


}
	size_t originlen;
		name += strlen(ATTRIBUTE_MACRO_PREFIX);
		push_stack(stack, next, origin, len);
		free(a);
	char *origin;
	for (i = 0; i < check->nr; i++) {
	 * field and fill each entry with its corresponding git_attr.
		basename_offset = 0;
		res->u.pat.pattern = p;

	e->value = value;
#include "exec-cmd.h"
			rem--;

		elem->origin = origin;
void git_all_attrs(const struct index_state *istate,
 * defined.
	/* Second pass to fill the attr_states */
 * is a singleton object which is shared between threads.
{
	/* shift entries over */

		system_wide = system_path(ETC_GITATTRIBUTES);
{
	 */
 * If is_macro is false, then u.pat is the filename pattern to which the
/* What does a matched pattern decide? */
				 * There is no checked out .gitattributes file
		    struct attr_check *check)
		}
		      sizeof(struct attr_state) * num_attr +
	vector_lock();
{
		int more;
#endif /* DEBUG_ATTR */
	if (!*cp || *cp == '#')
 * the file syntax, and attr.h for a description of the API.


		sp = ep + more;
	vector_lock();
{
		;
	push_stack(stack, e, NULL, 0);
		struct pattern pat;
		}
/*

		/* Remove check from the check vector */
	rem = check->all_attrs_nr;
		/* reset the pathbuf to not include "/.gitattributes" */
static void attr_stack_free(struct attr_stack *e)
	*stack = info->prev;
	return !git_env_bool("GIT_ATTR_NOSYSTEM", 0);
		}
	strbuf_release(&pattern);
	else if (ATTR_UNSET(value))

	free(e);
		what, attr->name, (char *) value, match);
	 */
		char *p = (char *)&(res->state[num_attr]);
		attr_stack_free(elem);
	check->alloc = cnt;
	fprintf(stderr, "%s: %s:%d\n", err.buf, src, lineno);
	free(e->attrs);

	if (strlen(ATTRIBUTE_MACRO_PREFIX) < namelen &&
		 * the second pass, no need for attr_name_valid()
void attr_check_free(struct attr_check *check)
	ALLOC_GROW(res->attrs, res->num_matches + 1, res->alloc);
	int i;
 */
}
	struct attr_hash_entry *e;
	if (is_macro) {
 */

	strbuf_addstr(&pathbuf, (*stack)->origin);

				 * work tree, so read from it.
		res = xcalloc(1, sizeof(*res));
		if (check_vector.checks[i] == check)
 * (2) .gitattributes file of the parent directory if (1) does not have
}
	pthread_mutex_lock(&map->mutex);
	 */
void git_check_attr(const struct index_state *istate,

}
	FREE_AND_NULL(check->all_attrs);
		attr = git_attr(param);
	ret->nr = check->nr;
		attr_hashmap_init(map);
static void check_vector_add(struct attr_check *c)
};
		is_macro = 0;
	const struct attr_hash_entry *a, *b;
		if (len < dirlen && is_dir_sep(path[len]))
 */
}
static void bootstrap_attr_stack(const struct index_state *istate,
#define debug_pop(a) debug_info("pop", (a))
	} else {
			const struct git_attr *a = e->value;
};
	push_stack(stack, info, NULL, 0);
	 * above loop should have stopped before popping, the
static void attr_hashmap_init(struct attr_hashmap *map)
		return NULL;

	check_vector_add(c);
	if (item->macro && item->value == ATTR__TRUE)

	}
	vector_unlock();
		if (direction == GIT_ATTR_CHECKOUT) {
	buf = read_blob_data_from_index(istate, path, NULL);

	 */

	e = xmalloc(sizeof(struct attr_hash_entry));
		return NULL;
const char *git_attr_name(const struct git_attr *attr)
				const char *src, int lineno)
	res = xcalloc(1, sizeof(*res));

	int nowildcardlen;
	 * stack, preferring $GIT_DIR/info/attributes, then
};
	a = attr_hashmap_get(&g_attr_hashmap, name, namelen);
		struct all_attrs_item *all_attrs, int rem)

		const struct git_attr *attr = a->state[i].attr;
					       int macro_ok)
	if (is_bare_repository() && new_direction != GIT_ATTR_INDEX)
				rem = fill_one("fill", all_attrs, a, rem);

 */
	check->alloc = 0;
 * Like info/exclude and .gitignore, the attribute information can
	va_start(params, one);
		git_attributes_file = xdg_config_home("attributes");
	}
struct attr_hash_entry {
		return NULL;
	direction = new_direction;
{
	check->items[0].attr = git_attr(one);
#include "config.h"


	if (check) {
		cp = parse_attr(src, lineno, cp, NULL);
	for (i = 0; i < check_vector.nr; i++) {
	int basename_offset;
			if (ma->is_macro) {
	const char *ep, *equals;
			last_slash = cp;
		attr_hashmap_add(&g_attr_hashmap, a->name, namelen, a);
		struct attr_hash_entry *e;
	while (fgets(buf, sizeof(buf), fp)) {

	return system_wide;
		len = ep - cp;
 * the attribute collection process) in 'check' based on the global dictionary
	for (cnt = 1; (param = va_arg(params, const char *)) != NULL; cnt++)
 * Callers into the attribute system assume there is a single, system-wide
		const char *value = check->all_attrs[i].value;

	if ((pat->flags & PATTERN_FLAG_MUSTBEDIR) && !isdir)
			strbuf_addch(&pathbuf, '/');
				      pattern, prefix,

	 * At the bottom of the attribute stack is the built-in
			cp++;
		char *bufp = buf;
	int i;

		len = equals - cp;
	}
{
		 */

		elem = *stack;

	info = *stack;
/* Initialize an 'attr_hashmap' object */
	res->num_attr = num_attr;
		const char *value = check->all_attrs[n].value;
}
 * this rule, and state is an array listing them.  The attributes are

/*
	res->attrs[res->num_matches++] = a;
	void *value; /* the stored value */
		return NULL;
		   check_vector.alloc);
	 * to the stack.  Finally, at the very top of the stack
	}
#define ATTR__FALSE git_attr__false
 * Marks the attributes which are macros based on the attribute stack.
{
{
	if (size != check->all_attrs_nr) {
fail_return:
	for (i = 0; i < check->all_attrs_nr; i++) {
	if (ATTR_TRUE(value))
/*
	const char *setto;
				/*
	}
		if (*cp == '-' || *cp == '!') {
	return (a->keylen != b->keylen) || strncmp(a->key, b->key, a->keylen);
	vector_unlock();
	if (get_home_gitattributes()) {
	const struct git_attr *attr;
	check->nr = 0;

	e = read_attr_from_array(builtin_attr);
	}
	e->key = key;
	fill(path, pathlen, basename_offset, check->stack, check->all_attrs, rem);
	e = hashmap_get_entry(&map->map, &k, ent, NULL);
			res = read_attr_from_index(istate, path, macro_ok);

		if (! (ch == '-' || ch == '.' || ch == '_' ||
		a->attr_nr = hashmap_get_size(&g_attr_hashmap.map);
	char is_macro;

				;
	pthread_mutex_lock(&check_vector.mutex);
		       (hashmap_get_size(&g_attr_hashmap.map) - 1));
		attr_stack_free(elem);
	 * root to the ones in deeper directories are pushed
		REALLOC_ARRAY(check->all_attrs, size);
struct attr_check_item *attr_check_append(struct attr_check *check,


	union {
	for (cnt = 1; cnt < check->nr; cnt++) {
	}
 * (reading the file from top to bottom), .gitattributes of the root
		value = "unset";
{
	k.keylen = keylen;
		    (!namelen || path[namelen] == '/'))
struct attr_stack {
}
			     const char *key, size_t keylen,
	else




	hashmap_unlock(map);
	if (!buf)
		basename_offset = last_slash + 1 - path;
#include "dir.h"

{
			      const char *key, size_t keylen)

	check_vector.checks[check_vector.nr++] = c;


				    const char *path, int macro_ok)

};

		FLEX_ALLOC_MEM(a, name, name, namelen);
		 * As this function is always called twice, once with
	 * If 'macro' is non-NULL, indicates that 'attr' is a macro based on
	ALLOC_ARRAY(ret->items, ret->nr);
	drop_attr_stack(&check->stack);
	if (last_slash) {
	struct attr_hash_entry *e;
			       struct attr_check *check)
		states = name + namelen;
	assert((*stack)->origin);

		else if (!equals)
/*
 * If e is not NULL, write the results to *e.  Return a pointer to the

};
		strbuf_addf(&pathbuf, "/%s", GITATTRIBUTES_FILE);
	return c;
{
#include "attr.h"
	return rem;

 */
	}
	int num_attr, i;
		*attr_stack_p = elem;

static const char blank[] = " \t\r\n";
	struct git_attr *a;
 * attribute system will lazily read from the right place.  Since changing
	res = xcalloc(1, sizeof(*res));
	equals = strchr(cp, '=');

		e = read_attr_from_file(get_home_gitattributes(), 1);
		for (j = 0; j < a->num_attr; j++) {
	if (size < check->all_attrs_nr)
	 * the current attribute stack and contains a pointer to the match_attr
		if (!macro_ok) {
	 */
			     const char *line,
	 * Pop the "info" one that is always at the top of the stack.
	 * Finally push the "info" one at the top of the stack.


#else
	size_t alloc;

{
	return match_pathname(pathname, pathlen - isdir,
	vector_lock();
	hashmap_entry_init(&k.ent, memhash(key, keylen));
	/*

	}
	/*
			    setto == ATTR__UNSET ||
}

		if (res->u.pat.flags & PATTERN_FLAG_NEGATIVE) {
	for (sp = buf; *sp; ) {

	static const char *system_wide;
	if (!e) {
	if (new_direction != direction)
static int fill(const char *path, int pathlen, int basename_offset,
	/* Find entry */
	b = container_of(entry_or_key, const struct attr_hash_entry, ent);
	item = &check->items[check->nr++];

			       const struct hashmap_entry *entry_or_key,
};
	 * bootstrap_attr_stack() should have added, and the
	ALLOC_GROW(check->items, check->nr + 1, check->alloc);
{
	fclose(fp);
	if (git_attr_system()) {

static const char git_attr__unknown[] = "(builtin)unknown";
		      sizeof(*res) +
	if (!res)
		const struct git_attr *attr;
 */
static int path_matches(const char *pathname, int pathlen,
			     void *value)
	check->all_attrs_nr = 0;
			goto fail_return;
	return res;

}
static struct attr_hashmap g_attr_hashmap;

#include "thread-utils.h"
		attr_hashmap_init(map);
		size_t len = pathbuf.len;


 * come from many places.
	states += strspn(states, blank);
			    setto == ATTR__UNKNOWN)
	return check;
	 * root element whose attr_stack->origin is set to an
	name = cp;

{
		int i;
{
		} else if (direction == GIT_ATTR_CHECKIN) {
	int len;
	return res;


	}
	struct strbuf pathbuf = STRBUF_INIT;
			check->all_attrs[a->attr_nr].attr = a;
	struct match_attr *a;
		e = read_attr_from_file(git_etc_gitattributes(), 1);

		struct attr_check_item *item;
	FILE *fp = fopen_or_warn(path, "r");
		    !strncmp(elem->origin, path, namelen) &&
	const char *line;
				      &res->u.pat.flags,
}
 * This is exactly the same as what is_excluded() does in dir.c to deal with
	va_end(params);
{
static struct check_vector {
 * This prevents having to search through the attribute stack each time
		    const struct match_attr *a, int rem)
	 * (or this attr_check instance doesn't have an initialized all_attrs
	 * If the number of attributes in the global dictionary has increased
		drop_all_attr_stacks();
		const struct attr_stack *stack,
	const char *value = v;
#include "quote.h"
		param = va_arg(params, const char *);
 * If there is no matching entry, return NULL.
					ent /* member name */) {
{

	struct strbuf pattern = STRBUF_INIT;
				}
		namelen = strcspn(name, blank);
	int attr_nr; /* unique attribute number */
		push_stack(stack, e, NULL, 0);
/*
 * listed as they appear in the file (macros unexpanded).
}
		       ('A' <= ch && ch <= 'Z')) )
}
				continue;
	}
/* Add 'value' to a hashmap based on the provided 'key'. */
}
		dirlen = last_slash - path;

{
	unsigned int size;
		if (value == ATTR__UNKNOWN)

	 * .gitattributes in deeper directories to shallower ones,
			if (!res)
	free(buf);
{

 * Collect attributes for path into the array pointed to by check->all_attrs.
		namelen = pattern.len;
		ep = strchrnul(sp, '\n');
struct attr_check *attr_check_dup(const struct attr_check *check)
		*stack = elem->prev;
		check->items[i].value = value;
#define DEBUG_ATTR 0
	}
 * .gitignore file and info/excludes file as a fallback.
				 struct attr_stack **stack)

static const struct git_attr *git_attr_internal(const char *name, int namelen)


	return res;

static void debug_info(const char *what, struct attr_stack *elem)
 * Reallocate and reinitialize the array of all attributes (which is used in
	if (!system_wide)
static const char *git_etc_gitattributes(void)

			*n = v;
	check = attr_check_alloc();
		int namelen = (*stack)->originlen;
			if (a->is_macro)
	}
		dirlen = 0;
	size_t nr;
	return git_attributes_file;
{
}
		BUG("no entry found");
	int isdir = (pathlen && pathname[pathlen - 1] == '/');
}
}
	return res;
		equals = NULL;
static struct match_attr *parse_attr_line(const char *line, const char *src,
	e->keylen = keylen;
{
		const char *v = a->state[i].setto;
					  int lineno, int macro_ok)
	if (!a)
	const char *pattern;
	if (!check)
	pthread_mutex_init(&g_attr_hashmap.mutex, NULL);

	if (equals)
		value = "unspecified";
	pthread_mutex_t mutex;
		handle_attr_line(res, sp, path, ++lineno, macro_ok);
	 * Pop the ones from directories that are not the prefix of
 * directory (again, reading the file from top to bottom) down to the
		free(check);
		struct attr_stack *next;
	}
	return attr->name;
 *      any match; this goes recursively upwards, just like .gitignore.
{

		more = (*ep == '\n');

 * Access to this dictionary must be surrounded with a mutex.
	}
	else
			      base, baselen,
#ifndef DEBUG_ATTR
			warning(_("Negative patterns are ignored in git attributes\n"
	else
static enum git_attr_direction direction;
{
	 * core.attributesfile.  Then, contents from
}
			goto fail_return;
		}
		strbuf_setlen(&pathbuf, len);
}
			BUG("%s: not a valid attribute name", param);
void attr_check_clear(struct attr_check *check)
	struct attr_check *c = xcalloc(1, sizeof(struct attr_check));
			e->setto = ATTR__TRUE;
	const struct git_attr *attr;
		    (int) len, name);
	/*
	hashmap_unlock(&g_attr_hashmap);
			return 0;

	push_stack(stack, e, NULL, 0);
	struct attr_hash_entry k;
				  attr, v);
}
static int git_attr_system(void)
}
	while (*stack) {
	free(res);
		check_vector_remove(check);
	while (pathbuf.len < dirlen) {
{
		}
 * One basic design decision here is that we are not going to support
 */
	 * we always keep the contents of $GIT_DIR/info/attributes.

 * current directory, and then scan the list backwards to find the first match.
	else if (ATTR_FALSE(value))
		for (i = stack->num_matches - 1; 0 < rem && 0 <= i; i--) {
		item->value = value;
	const char *pattern = pat->pattern;
/* The container for objects stored in "struct attr_hashmap" */

		struct match_attr *a = e->attrs[i];
{
			continue;
				res = read_attr_from_index(istate, path, macro_ok);
			    setto == ATTR__FALSE ||
		res->u.attr = git_attr_internal(name, namelen);
	if (elem) {
};
		   check_vector.nr + 1,
{
struct match_attr {
 * (1) .gitattributes file of the same directory;
		return;
	determine_macros(check->all_attrs, check->stack);
	struct hashmap map;
}
		elem->prev = *attr_stack_p;
	if (direction == GIT_ATTR_INDEX) {
		e = read_attr_from_file(git_path_info_attributes(), 1);
{
{
	 */
	check->nr = cnt;
		return;
	for (; i < check_vector.nr - 1; i++)
static int fill_one(const char *what, struct all_attrs_item *all_attrs,
/*
		if (!attr)
const char git_attr__true[] = "(builtin)true";
{
static void prepare_attr_stack(const struct index_state *istate,
 * Parse a whitespace-delimited attribute state (i.e., "attr",
	check_vector.nr--;
	hashmap_init(&map->map, attr_hash_entry_cmp, NULL, 0);
	strbuf_release(&pattern);
{
	if (!e)
		if (*cp == '/' && cp[1])
static void push_stack(struct attr_stack **attr_stack_p,
			const char *base, int baselen)
		strbuf_add(&pathbuf, path + pathbuf.len, (len - pathbuf.len));
}
	int i;
	return item;
/* List of all attr_check structs; access should be surrounded by mutex */

	pthread_mutex_init(&check_vector.mutex, NULL);
	if (pat->flags & PATTERN_FLAG_NODIR) {

static void *attr_hashmap_get(struct attr_hashmap *map,


}
		check->items[cnt].attr = attr;
				  "Use '\\!' for literal leading exclamation."));
				      &res->u.pat.nowildcardlen);
struct pattern {

	 * the path we are checking. Break out of the loop when we see
		name = pattern.buf;
static GIT_PATH_FUNC(git_path_info_attributes, INFOATTRIBUTES_FILE)
		const char *name = check->all_attrs[i].attr->name;
 *
		       ('0' <= ch && ch <= '9') ||
		name += strspn(name, blank);
	hashmap_lock(&g_attr_hashmap);
const struct git_attr *git_attr(const char *name)

	int prefix = pat->nowildcardlen;
		origin = xstrdup(pathbuf.buf);
				 * there, but we might have it in the index.
}
static const char *get_home_gitattributes(void)
	if (namelen <= 0 || *name == '-')
	 * definition of the macro
	a = parse_attr_line(line, src, lineno, macro_ok);
	const char *key; /* the key; memory should be owned by value */

	a = container_of(eptr, const struct attr_hash_entry, ent);

		}
	return ep + strspn(ep, blank);
/* Iterate through all attr_check instances and drop their stacks */
	struct attr_stack *res;
	 * characters from [-A-Za-z0-9_.].
		return 0;
			rem = macroexpand_one(all_attrs, attr->attr_nr, rem);
	 * one (whose origin is NULL) without popping it.

	struct attr_stack *e;

 * The global dictionary of all interned attributes.  This



	collect_some_attrs(istate, path, check);

#define debug_set(a,b,c,d) do { ; } while (0)
			fprintf_ln(stderr, _("%s not allowed: %s:%d"),
	int i;
	while ((line = *(list++)) != NULL)
	}

 * dictionary.  If no entry is found, create a new attribute and store it in
		push_stack(stack, e, NULL, 0);
#define ATTR__TRUE git_attr__true
	check->items = xcalloc(cnt, sizeof(struct attr_check_item));
	hashmap_lock(map);

		BUG("interned attributes shouldn't be deleted");

static void collect_some_attrs(const struct index_state *istate,
	struct attr_check_item *item;
		if (!attr_name_valid(name, namelen)) {
	while (namelen--) {
					all_attrs[n].macro = ma;


	item->attr = attr;
		if (!lineno)
			debug_set(what,
		if (!attr_name_valid(cp, len)) {
	return NULL;
	 * the attribute dictionary is no longer being accessed.
		if (value == ATTR__UNSET || value == ATTR__UNKNOWN)
 * if there was an error.
	for (cp = states, num_attr = 0; *cp; num_attr++) {
			e->setto = xmemdupz(equals + 1, ep - equals - 1);
		 * check here.
			const struct match_attr *a = stack->attrs[i];
}
		return match_basename(pathname + basename_offset,
	prepare_attr_stack(istate, path, dirlen, &check->stack);
 * Given a 'name', lookup and return the corresponding attribute in the global
			if (setto == ATTR__TRUE ||
			break;

	if (!fp)
static void drop_attr_stack(struct attr_stack **stack)

	return res;
	vector_unlock();
		   const char *path, struct attr_check *check)
		cp = parse_attr(src, lineno, cp, &(res->state[i]));
 * the dictionary.
			report_invalid_attr(cp, len, src, lineno);
				      pathlen - basename_offset - isdir,
		e = xcalloc(1, sizeof(struct attr_stack));
			break;
	 */

 * remainder of the string (with leading whitespace removed), or NULL

	const char *value;

	push_stack(stack, e, xstrdup(""), 0);
	ep = cp + strcspn(cp, blank);
static struct attr_stack *read_attr_from_file(const char *path, int macro_ok)
	}
	 * .gitattributes files from directories closer to the
}
}
	hashmap_entry_init(&e->ent, memhash(key, keylen));
	return ret;
		is_macro = 1;

			const struct match_attr *ma = stack->attrs[i];
{

	}
{
			BUG("counted %d != ended at %d",
		      (is_macro ? 0 : namelen + 1));
		else {
}

			len++;
			e->setto = (*cp == '-') ? ATTR__FALSE : ATTR__UNSET;

}


		res = read_attr_from_index(istate, path, macro_ok);
	if (startup_info->have_repository)
	/*
	/* First pass to count the attr_states */
		    const char *path,
			     const struct attr_stack *stack)


static const char *parse_attr(const char *src, int lineno, const char *cp,
	strbuf_release(&err);
		e = NULL;
	res->is_macro = is_macro;

	if (!a) {
 *
}
		       struct attr_stack *elem, char *origin, size_t originlen)
	} u;
			report_invalid_attr(name, namelen, src, lineno);
	/*
	COPY_ARRAY(ret->items, check->items, ret->nr);
	pthread_mutex_unlock(&check_vector.mutex);
		struct hashmap_iter iter;
	int namelen;
#define debug_push(a) debug_info("push", (a))
	int i;
 * direction causes a global paradigm shift, it should not ever be called while
				  a->is_macro ? a->u.attr->name : a->u.pat.pattern,

	struct attr_stack *info;

				int n = ma->u.attr->attr_nr;
			goto fail_return;
	if (!map->map.tablesize)
	struct hashmap_entry ent;
		handle_attr_line(res, line, "[builtin]", ++lineno, 1);
	else
 * constructed need to be discarded so so that subsequent calls into the

{

		char *origin;
			const char *setto = a->state[j].setto;
		return fill_one("expand", all_attrs, item->macro, rem);

}
	for (cp = path; *cp; cp++) {
	return a;
	if (equals && ep < equals)
	const struct all_attrs_item *item = &all_attrs[nr];
	}
	 * This re-initialization can live outside of the locked region since
		return NULL;
/* attr_hashmap comparison function */
 */
	/* save pointer to the check struct */

 * calling git_attr_set_direction(), the stack frames that have been
		return NULL;
	}

	if (!git_attributes_file)
		return rem;
	struct attr_state state[FLEX_ARRAY];
 * global state where attributes are read from and when the state is flipped by
	/*
 * In either case, num_attr is the number of attributes affected by
		attr_check_clear(check);
	"[attr]binary -diff -merge -text",
static void debug_set(const char *what, const char *match, struct git_attr *attr, const void *v)

	/* builtin frame */
		next = read_attr(istate, pathbuf.buf, 0);
	int i;
 * "-attr", "!attr", or "attr=value") from the string starting at src.
	int i;
		}
		drop_attr_stack(&check_vector.checks[i]->stack);
		if (origin)
				free((char *) setto);

	if (*stack)
				if (!all_attrs[n].macro) {
	strbuf_addf(&err, _("%.*s is not a valid attribute name"),
	} else {

	} else {

	/* root directory */
	struct strbuf err = STRBUF_INIT;
	unsigned flags;		/* PATTERN_FLAG_* */
		/*
			      pattern, prefix, pat->patternlen, pat->flags);
	for (; rem > 0 && stack; stack = stack->prev) {
struct all_attrs_item {
				 * We allow operation in a sparsely checked out

}
			if (path_matches(path, pathlen, basename_offset,
		debug_pop(elem);
}

static inline void hashmap_unlock(struct attr_hashmap *map)
	strbuf_release(&pathbuf);
		memcpy(p, name, namelen);
#define debug_pop(a) do { ; } while (0)
	/* info frame */
{
}
struct attr_check *attr_check_alloc(void)
}
	/*
