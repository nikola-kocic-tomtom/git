	ALLOC_ARRAY(dst->items, dst->nr);

	if (isalnum(ch) || strchr(",-_", ch))

	char *seen = xcalloc(pathspec->nr, 1);
/*
	const char *entry = argv ? *argv : NULL;
				am->value = attr_value_unescape(v);

		match = xstrdup(copyfrom);
		    elem);
static struct pathspec_magic {
		/* Preserve the actual prefix length of each pattern */
		int plen = (!(flags & PATHSPEC_PREFER_CWD)) ? 0 : prefixlen;
			strbuf_swap(&buf, &unquoted);
			return 0;
			BUG("PATHSPEC_PREFER_CWD requires arguments");
	int i;

{
			continue;

		return parse_short_magic(magic, elem);
				    m->name, m->mnemonic);
}
			matched = (match_mode == MATCH_UNSPECIFIED);
 *
 *
		if (ARRAY_SIZE(pathspec_magic) <= i)

	return pos;
			strbuf_addf(&sb, _("'%s' (mnemonic: '%c')"),

	for (i = 0; i < ARRAY_SIZE(pathspec_magic); i++)
		global_magic |= PATHSPEC_LITERAL;
			am->match_mode = MATCH_UNSET;
			if (!src[1])
		d->original = xstrdup(s->original);
	{ PATHSPEC_EXCLUDE,  '!', "exclude" },
			unsupported_magic(entry, item[i].magic & magic_mask);

		}
		return parse_long_magic(magic, prefix_len, item, elem);

	n = 0;
	{ PATHSPEC_FROMTOP,  '/', "top" },
	static int noglob = -1;
	}
	item->attr_match = NULL;
			die(_("invalid attribute name %s"), attr_name);
	} else {
	if (*pos == ':')
	FILE *in;
			}
/*

static size_t strcspn_escaped(const char *s, const char *stop)
		return;
					    const struct index_state *istate)
		/* skip the escaped character */
			return;
				am->match_mode = MATCH_VALUE;
	 */
			parse_pathspec_attr_match(item, attr_body);
 * Magic pathspec
	return icase;
 * For each pathspec, sets the corresponding entry in the seen[] array

	const char *name;
		name = to_free = xmemdupz(name, namelen);
		if (!(magic & m->bit))
		free(pathspec->items[i].original);
/*
	}
	}

		for (i = 0; i < ARRAY_SIZE(pathspec_magic); i++) {
		}
		entry = argv[i];
	if (get_glob_global() && !(element_magic & PATHSPEC_LITERAL))
{
			free(attr_body);
	if (magic & PATHSPEC_LITERAL) {

	if (pathspec_prefix >= 0 &&
	    (flags & PATHSPEC_PREFER_FULL))

	return strcmp(a->match, b->match);
	if (pathspec->magic & PATHSPEC_MAXDEPTH) {
 */

			die("empty string is not a valid pathspec. "
				  "please use . instead if you meant to match all paths");
#include "cache.h"
	else if (elem[1] == '(')
		return elem; /* nothing to do */

 * Finds which of the given pathspecs match items in the index.
				    struct pathspec_item *item,
		 * pattern "* * / * . c"?
	struct pathspec_item *item;
	 * Since we are walking the index as if we were walking the directory,

		}


		if (ARRAY_SIZE(pathspec_magic) <= i)
		if (!is_pathspec_magic(ch))
 */
	}
	struct strbuf unquoted = STRBUF_INIT;
	 * mistakenly think that the user gave a pathspec that did not match
	return glob;

	for (pos = elem + 2; *pos && *pos != ')'; pos = nextat) {
		if (item[i].magic & PATHSPEC_EXCLUDE)

	 */
	argv_array_clear(&parsed_file);
			die("cannot use '%c' for value matching", *src);
	 */
		if (item[i].nowildcard_len < item[i].len)


	strbuf_release(&unquoted);
 * if prefix magic is used, save the prefix length in 'prefix_len'
			if (sb->buf[sb->len - 1] != '(')
static inline int invalid_value_char(const char ch)
	int i, n, prefixlen, nr_exclude = 0;
	pathspec->nr = n;
{

	item->attr_match = xcalloc(list.nr, sizeof(struct attr_match));
	for (i = 0; i < dst->nr; i++) {
		match = prefix_path_gently(prefix, prefixlen,

 * nature of the "closest" (i.e. most specific) matches which each of the
	/*
			matched = (match_mode == MATCH_UNSET);
{
			item->flags |= PATHSPEC_ONESTAR;
		    unsigned magic_mask, unsigned flags,
	for (i = 0; i < istate->cache_nr; i++) {
	 * that matches everything. We allocated an extra one for this.
}

		int j = item->attr_match_nr++;
		d->match = xstrdup(s->match);
 *
	strbuf_addstr(sb, ":(");
				hint_path = get_git_dir();
	item->match = match;
			attr++;
		attr_name = xmemdupz(attr, attr_len);
	}
 * (which should be specs items long, i.e. the same size as pathspec)
}

	strbuf_release(&buf);
		copyfrom = parse_element_magic(&element_magic,
		ALLOC_ARRAY(d->attr_match, d->attr_match_nr);

		size_t len = strcspn_escaped(pos, ",)");

		for (i = 0; i < ARRAY_SIZE(pathspec_magic); i++) {
			 const struct pathspec_item *item)
	COPY_ARRAY(dst->items, src->items, dst->nr);
	 */
			attr_check_free(pathspec->items[i].attr_check);
	pathspec->nr = 0;
		item->original = strbuf_detach(&sb, NULL);
			d->attr_match[j].value = xstrdup_or_null(value);

				die(_("invalid parameter for pathspec magic 'prefix'"));
		if (pathspec->items[i].attr_check)
		if (!seen[i])
		size_t attr_len;
		glob = git_env_bool(GIT_GLOB_PATHSPECS_ENVIRONMENT, 0);

		if (strchr(stop, *i))
			continue;
#include "quote.h"
	item->prefix = prefixlen;
	}
		die(_("global 'glob' and 'noglob' pathspec settings are incompatible"));
{
	const char *pos;
 *
			const char *value = s->attr_match[j].value;
	while (argv[n]) {
		/* longhand */
	ret = xmallocz(strlen(value));
	ALLOC_ARRAY(pathspec->items, n + 1);
static int get_global_magic(int element_magic)
		if (flags & PATHSPEC_KEEP_ORDER)
	item->attr_check = NULL;
	}
			}
/*
		pathspec->items = item = xcalloc(1, sizeof(*item));

		 * FIXME: should we enable ONESTAR in _GLOB for
			attr++;
{
	return pos;
		magic = PATHSPEC_LITERAL;
		BUG("'prefix' magic is supposed to be used at worktree's root");
{
			if (endptr - pos != len)
		argv_array_push(&parsed_file, buf.buf);

{
}
		item->nowildcard_len = item->len = strlen(prefix);
		return 0;

		}

				die(_("line is badly quoted: %s"), buf.buf);
				const char *v = &attr[attr_len + 1];
	    !get_literal_global()) {


	{ PATHSPEC_ATTR,    '\0', "attr" },
	if (get_glob_global() && get_noglob_global())
		/* Special case alias for '!' */
					       item,
static inline int get_icase_global(void)
	item->magic = magic;
	return global_magic;
		die(_("Only one 'attr:' specification is allowed."));
}
	if (get_icase_global())

	} else {
	} else if (magic & PATHSPEC_FROMTOP) {
		else if (ATTR_FALSE(value))

		item->nowildcard_len = item->len;
			matched = (match_mode == MATCH_VALUE &&

	static int literal = -1;
				       struct pathspec_item *item,
		prefixlen = 0;
	for (i = 0; i < n; i++) {
	if (!entry) {
			attr_len = strlen(attr);
	if (in != stdin)
		noglob = git_env_bool(GIT_NOGLOB_PATHSPECS_ENVIRONMENT, 0);


	if (noglob < 0)

			num_unmatched++;
{
	die(_("%s: pathspec magic not supported by this command: %s"),
		if ((flags & PATHSPEC_SYMLINK_LEADING_PATH) &&

	for (src = value, dst = ret; *src; src++, dst++) {

				break;
}
	/* No arguments with prefix -> prefix pathspec */
	item->len = strlen(item->match);
{
		global_magic |= PATHSPEC_LITERAL;
 *
			if (unquote_c_style(&unquoted, buf.buf, NULL))
static int pathspec_item_cmp(const void *a_, const void *b_)
 * Possible future magic semantics include stuff like:
	a = (struct pathspec_item *)a_;
		else
	 * anything.
 * which allocates, populates, and returns a seen[] array indicating the
{
				       const char *elem)
	char mnemonic; /* this cannot be ':'! */
{
	parse_pathspec(pathspec, magic_mask, flags, prefix, parsed_file.argv);
			die(_("Invalid pathspec magic '%.*s' in '%s'"),
		char ch = *pos;
#include "dir.h"
	/* Create match string which will be used for pathspec matching */
 * returns the position in 'elem' after all magic has been parsed
		case '-':

		icase = git_env_bool(GIT_ICASE_PATHSPECS_ENVIRONMENT, 0);

	}



		if (!match) {
		pathspec->nr++;
		struct attr_match *am = &item->attr_match[j];
		if (sb.len)
 * given pathspecs achieves against all items in the index.
					       elt);
	 * name. E.g. when add--interactive dies when running
	pos++;
		int i;
	{ PATHSPEC_LITERAL, '\0', "literal" },
	int num_unmatched = 0, i;
		      "with all other global pathspec settings"));

		/* shorthand */

		char *attr_name;
		pos++;
		switch (*attr) {
			char *endptr;

			*magic |= PATHSPEC_EXCLUDE;
	}
		if (!len)
						       strbuf_getline;
#include "argv-array.h"
			if (strlen(pathspec_magic[i].name) == len &&




	    (global_magic & ~PATHSPEC_LITERAL))
	for (i = s; *i; i++) {
		free(pathspec->items[i].match);
}
	}
	if (!value || !*value)
				      "last character in attr value"));
		COPY_ARRAY(d->attr_match, s->attr_match, d->attr_match_nr);
	if (flags & PATHSPEC_MAXDEPTH_VALID)
		if (*argv[n] == '\0')
		magic |= element_magic;
	}
 */
{
		item->original = xstrdup(prefix);
	if (!num_unmatched)
}
}
	 * We may want to substitute "this command" with a command
 */
		fclose(in);
		if (*src == '\\') {
			strbuf_addstr(sb, pathspec_magic[i].name);
	item->flags = 0;
	memset(pathspec, 0, sizeof(*pathspec));
{
	return ret;
				am->match_mode = MATCH_SET;
				*magic |= pathspec_magic[i].bit;
			const char *hint_path = get_git_work_tree();
	if (elem[0] != ':' || get_literal_global())

}
		}

 *
		struct pathspec_item *d = &dst->items[i];
	string_list_split(&list, value, ' ', -1);
	 * Prefix the pathspec (keep all magic) and assign to
			break;
}
	strbuf_addf(sb, ",prefix:%d)", prefixlen);
#include "config.h"
		pathspec->magic |= item[i].magic;
	if (!strcmp(file, "-"))
	return literal;
static void prefix_magic(struct strbuf *sb, int prefixlen, unsigned magic)
		    no_wildcard(item->match + item->nowildcard_len + 1))
};
	for (pos = elem + 1; *pos && *pos != ':'; pos++) {

	}
	for (i = 0; i < pathspec->nr; i++) {

			*prefix_len = strtol(pos + 7, &endptr, 10);

	const char *i;
			continue;
			continue;
void clear_pathspec(struct pathspec *pathspec)
	if (magic & PATHSPEC_GLOB) {
	char *to_free = NULL;
	} else {
					char *seen)
	unsigned bit;
	 * we have to mark the matched pathspec as seen; otherwise we will
 * returns the position in 'elem' after all magic has been parsed
	}
	}
		 */
		prefix_magic(&sb, prefixlen, element_magic);
}

	    item->prefix         > item->len) {

		else
			break;
	int i;
			nextat = pos + len + 1; /* handle ',' */
	if (item->attr_check || item->attr_match)
}
			die(_("Unimplemented pathspec magic '%c' in '%s'"),
static void init_pathspec_item(struct pathspec_item *item, unsigned flags,
		}


	char *match;

			break;
	if (icase < 0)
		die(_("attr spec must not be empty"));
			src++;

		BUG("PATHSPEC_PREFER_CWD and PATHSPEC_PREFER_FULL are incompatible");
		magic |= get_global_magic(element_magic);
		for (j = 0; j < d->attr_match_nr; j++) {
	if (pathspec_prefix >= 0) {

	struct pathspec_item *a, *b;
	*dst = '\0';
				   !strcmp(item->attr_match[i].value, value));
	item = pathspec->items;
		in = xfopen(file, "r");
			attr_len = strcspn(attr, "=");
			    copyfrom, absolute_path(hint_path));
				break;
			free(pathspec->items[i].attr_match[j].value);
	struct string_list list = STRING_LIST_INIT_DUP;
		    const char *prefix, const char **argv)
		*dst = *src;
		match = xstrdup(copyfrom);
}

		}
		default:
/*
	/* PATHSPEC_LITERAL_PATH ignores magic */
		const char *attr = si->string;

	if ((flags & PATHSPEC_PREFER_CWD) &&
		if (i[0] == '\\' && i[1]) {
	unsigned magic = 0, element_magic = 0;
	/* --noglob-pathspec adds :(literal) _unless_ :(glob) is specified */
		else
			    ch, elem);
		}
 * Parse the pathspec element looking for long magic
	return noglob;
	struct strbuf buf = STRBUF_INIT;
 *	{ PATHSPEC_REGEXP, '\0', "regexp" },
			break;
 *
			nr_exclude++;
	add_pathspec_matches_against_index(pathspec, istate, seen);


	if (glob < 0)

		}
	}
	}
		pathspec->magic |= PATHSPEC_MAXDEPTH;

		if (!matched)
			nextat = pos + len; /* handle ')' and '\0' */
		return;
		ce_path_match(istate, ce, pathspec, seen);
		BUG("should have same number of entries");
		int matched;
	return i - s;

 * to the nature of the "closest" (i.e. most specific) match found for
}
			 const char *name, int namelen,
	return -1;
		global_magic |= PATHSPEC_GLOB;
		item->original = xstrdup(elt);
					       &pathspec_prefix,

	/*
				    const char *elem)
		item->match = xstrdup(prefix);
static const char *parse_long_magic(unsigned *magic, int *prefix_len,
	free(to_free);
 * saves all magic in 'magic'
int match_pathspec_attrs(const struct index_state *istate,
				die(_("Escape character '\\' not allowed as "
			strbuf_addf(&sb, "'%s'", m->name);
	for (i = 0; i < item->attr_match_nr; i++) {
	struct strbuf sb = STRBUF_INIT;
			BUG("PATHSPEC_MAXDEPTH_VALID and PATHSPEC_KEEP_ORDER are incompatible");
		strbuf_reset(&buf);
		QSORT(pathspec->items, pathspec->nr, pathspec_item_cmp);
	const char *nextat;
		int i;



{
	    pattern, sb.buf);
			    (int) len, pos, elem);

	}

		init_pathspec_item(item + n, 0, prefix, plen, "");
		struct strbuf sb = STRBUF_INIT;
static const char *parse_element_magic(unsigned *magic, int *prefix_len,
	}
		match_mode = item->attr_match[i].match_mode;
#include "attr.h"
	for (i = 0; i < pathspec->nr; i++)
		if (item->nowildcard_len < item->len &&
	int i, j;
}
	} else {

	} else {
		if (starts_with(pos, "attr:")) {
		return;
}
		if (flags & PATHSPEC_PREFER_FULL)

 * This is a one-shot wrapper around add_pathspec_matches_against_index()

			 const char *file, int nul_term_line)
	    (prefixlen || (prefix && *prefix)))
		attr_check_append(item->attr_check, a);


		prefixlen = pathspec_prefix;

	*dst = *src;
	/*
#include "pathspec.h"
	item->attr_check = attr_check_alloc();
	string_list_clear(&list, 0);
	item->attr_match_nr = 0;
	if (get_literal_global())
}
			continue;
		literal = git_env_bool(GIT_LITERAL_PATHSPECS_ENVIRONMENT, 0);
	static int glob = -1;

		strbuf_addstr(&sb, match);
	int pathspec_prefix = -1;
	else

		const struct git_attr *a;
	const char *src;
		const char *value;

	/* --glob-pathspec is overridden by :(literal) */
	static int icase = -1;
 * saves all magic in 'magic'
		in = stdin;
 * If seen[] has not already been written to, it may make sense

			    !strncmp(pathspec_magic[i].name, pos, len)) {
static char *attr_value_unescape(const char *value)
 *	{ PATHSPEC_RECURSIVE, '*', "recursive" },

 * altogether if seen[] already only contains non-zero entries.
	 * original. Useful for passing to another command.
		if (item[i].magic & magic_mask)
	 * "checkout -p"

		if (!(flags & PATHSPEC_PREFER_CWD))
		if (starts_with(pos, "prefix:")) {
 */
	prefixlen = prefix ? strlen(prefix) : 0;
		item->nowildcard_len = simple_length(item->match);
		item->prefix = item->len;
		}
 *

	struct argv_array parsed_file = ARGV_ARRAY_INIT;
	while (getline_fn(&buf, in) != EOF) {
			*magic |= PATHSPEC_ATTR;
static void NORETURN unsupported_magic(const char *pattern,
char *find_pathspecs_matching_against_index(const struct pathspec *pathspec,
 * Parse the pathspec element looking for short magic
		free(attr_name);
		    has_symlink_leading_path(item[i].match, item[i].len)) {
{
 * that pathspec in the index, if it was a closer type of match than
		}
{
	{ PATHSPEC_GLOB,    '\0', "glob" },
			am->match_mode = MATCH_UNSPECIFIED;

		free(pathspec->items[i].attr_match);

		global_magic |= PATHSPEC_ICASE;
	if (!entry && !prefix)

	FREE_AND_NULL(pathspec->items);

	char *dst, *ret;


{
		if (!nul_term_line && buf.buf[0] == '"') {
			strbuf_reset(&unquoted);
			die(_("%s: '%s' is outside repository at '%s'"), elt,
		case '!':

					const struct index_state *istate,
{
	struct string_list_item *si;

		if (!a)
		die(_("global 'literal' pathspec setting is incompatible "
			strbuf_addstr(&sb, ", ");
 */
			       const char *elt)
		d->attr_check = attr_check_dup(s->attr_check);
	}
		const struct cache_entry *ce = istate->cache[i];
		value = item->attr_check->items[i].value;
/*

		if (item->nowildcard_len < prefixlen)
		n++;


		for (j = 0; j < pathspec->items[i].attr_match_nr; j++)

	if (item->attr_check->nr != item->attr_match_nr)
 * Finds which of the given pathspecs match items in the index.
void parse_pathspec_file(struct pathspec *pathspec, unsigned magic_mask,
		a = git_attr(attr_name);
	if ((flags & PATHSPEC_PREFIX_ORIGIN) &&
			continue;
void parse_pathspec(struct pathspec *pathspec,
 * to use find_pathspecs_matching_against_index() instead.
	/* sanity checks, pathspec matchers assume these are sane */
			attr_len = strlen(attr);
	string_list_remove_empty_items(&list, 0);
	if (item->nowildcard_len > item->len ||
			break;
				*magic |= pathspec_magic[i].bit;
	else
		else if (ATTR_UNSET(value))
		die(_("%s: 'literal' and 'glob' are incompatible"), elt);
				       unsigned magic)
		if (invalid_value_char(*src))
	return 1;
			i++;
			char *attr_body = xmemdupz(pos + 5, len - 5);
	if (nr_exclude == n) {
	{ PATHSPEC_ICASE,   '\0', "icase" },
			if (pathspec_magic[i].mnemonic == ch) {
		struct pathspec_item *s = &src->items[i];


		if (m->mnemonic)
static inline int get_noglob_global(void)
}
		init_pathspec_item(item + i, flags, prefix, prefixlen, entry);

			pathspec->has_wildcard = 1;
	}
			}
	int global_magic = 0;
			 unsigned flags, const char *prefix,
		die(_("Missing ')' at the end of pathspec magic in '%s'"),
		const struct pathspec_magic *m = pathspec_magic + i;
	if (get_noglob_global() && !(element_magic & PATHSPEC_GLOB))
}
			if (!hint_path)
	 * If everything is an exclude pattern, add one positive pattern
	git_check_attr(istate, name, item->attr_check);


	strbuf_getline_fn getline_fn = nul_term_line ? strbuf_getline_nul :
	int i;
	/*
{
	int i, j;
	}
	if ((global_magic & PATHSPEC_LITERAL) &&
			       const char *prefix, int prefixlen,
}
	if ((magic & PATHSPEC_LITERAL) && (magic & PATHSPEC_GLOB))
			else {
static void parse_pathspec_attr_match(struct pathspec_item *item, const char *value)
				strbuf_addch(sb, ',');
	const char *copyfrom = elt;
			item->nowildcard_len = prefixlen;

{
	}
	if (flags & PATHSPEC_LITERAL_PATH) {
		if (ATTR_TRUE(value))


	return seen;
	const char *pos;
	for (i = 0; i < ARRAY_SIZE(pathspec_magic); i++) {

{
static const char *parse_short_magic(unsigned *magic, const char *elem)
			if (attr[attr_len] != '=')

static inline int get_literal_global(void)
		if (ch == '^') {
}
					   &prefixlen, copyfrom);
{
		if (pos[len] == ',')
		BUG("error initializing pathspec_item");
		    item->match[item->nowildcard_len] == '*' &&
			die(_("pathspec '%s' is beyond a symbolic link"), entry);
void add_pathspec_matches_against_index(const struct pathspec *pathspec,
	if (literal < 0)
void copy_pathspec(struct pathspec *dst, const struct pathspec *src)
		}


			matched = (match_mode == MATCH_SET);


		if (magic & pathspec_magic[i].bit) {
	if (name[namelen])
} pathspec_magic[] = {
		/*

	b = (struct pathspec_item *)b_;
 * Perform the initialization of a pathspec_item based on a pathspec element.
static inline int get_glob_global(void)
		pathspec->nr = 1;
}
 * the existing entry.  As an optimization, matching is skipped
	/* No arguments, no prefix -> no pathspec */
	for_each_string_list_item(si, &list) {
	if (*pos != ')')
		enum attr_match_mode match_mode;

		}
