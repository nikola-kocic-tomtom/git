#else
		i = -1 - i;

int map_user(struct string_list *map,
		if (len && buffer[len - 1] == '\n')
const char *git_mailmap_file;
	char buffer[1024];
			break;
}
			/*
		return NULL;
		int abblen = sizeof(abbrev) - 1;
		struct mailmap_info *mi = xcalloc(1, sizeof(struct mailmap_info));
			return &map->items[i];
static void free_mailmap_entry(void *p, const char *s)
	}
{
}
		git_mailmap_blob = "HEAD:.mailmap";
			if (subitem)
		debug_mm("mailmap: adding (simple) entry for '%s'\n", old_email);

}
	} else {
		return NULL;
		int cmp = strncasecmp(map->items[i].string, string, len);

		add_mapping(map, name1, email1, name2, email2);
	}
	enum object_type type;
 * Look for an entry in map that match string[0:len]; string[len]
	while (nend > nstart && isspace(*nend))
		 s, me->namemap.nr);
			 */
	return err;
			return 0;
		 * keep trying.
			/* found it */
	while (0 <= --i && i < map->nr) {

	if (old_email == NULL) {
		}
	char *buf;
		 * otherwise, the string at "i" may be string[0:len]
			subitem = lookup_prefix(&me->namemap, *name, *namelen);
		 * that map entry matches exactly to the string, including
 * here as a workaround---do not assign strcasecmp directly to
}
		if (new_name) {
	return strcasecmp(a, b);

static char *parse_name_and_email(char *buffer, char **name,
 */
				; /* nothing */
static void free_mailmap_info(void *p, const char *s)
		if (!repo_abbrev)
			struct string_list_item *subitem;
	*right++ = '\0';
	char *left, *right, *nstart, *nend;

#define debug_str(X) ((X) ? (X) : "(none)")
		return 0;
	debug_mm("map_user: map '%.*s' <%.*s>\n",

	return 0;
			     char **repo_abbrev)
	read_mailmap_string(map, buf, repo_abbrev);
int read_mailmap(struct string_list *map, char **repo_abbrev)
static int namemap_cmp(const char *a, const char *b)

		 * matching entry can exist in the map.
			free(me->name);
	item = lookup_prefix(map, *email, *emaillen);
	}
			/*
	return (*right == '\0' ? NULL : right);

	struct string_list namemap;
	if (!f) {
const char *git_mailmap_blob;
	}
	if ((right = strchr(left+1, '>')) == NULL)
	if (!git_mailmap_blob && is_bare_repository())
	return NULL;
			 * "i" points at a key definitely below the prefix;
		err |= read_mailmap_blob(map, git_mailmap_blob, repo_abbrev);
#include "cache.h"
		 */
		old_email = new_email;

	if (startup_info->have_repository)
		 * asked with the whole string, and got nothing.  No
			 * simple entry.
}
		me = (struct mailmap_entry *)item->util;
		me = (struct mailmap_entry *)item->util;
		item->util = me;
}
			*repo_abbrev = xstrdup(cp);
	map->strdup_strings = 1;
	/* name and email for the simple mail-only case */
}
			     char **repo_abbrev)
		return NULL;
		}
	}
	FILE *f;
		/*
	     const char **email, size_t *emaillen,
		mi->name = xstrdup_or_null(new_name);
 * does not have to be NUL (but it could be).
	free(me->name);
{
		read_mailmap_line(map, buffer, repo_abbrev);
	debug_mm("mailmap: -- complex: '%s' -> '%s' <%s>\n",
	char *name;

}
		 debug_str(me->name), debug_str(me->email));
	debug_mm("mailmap: clearing %d entries...\n", map->nr);
 * On some systems (e.g. MinGW 4.0), string.h has _only_ inline
	free(mi->email);
		++nstart;
		 */
			return;
		char *end = strchrnul(buf, '\n');
	if ((name2 = parse_name_and_email(buffer, &name1, &email1, 0)) != NULL)
				*emaillen = strlen(*email);
			 (int)*namelen, debug_str(*name),
		/*
	 */
	debug_mm("mailmap: removing entries for <%s>, with %d sub-entries\n",
	err |= read_mailmap_file(map, git_mailmap_file, repo_abbrev);
		/* Replace current name and new email for simple entry */
	nstart = buffer;
			 (int)*emaillen, debug_str(*email));
{
		return error("mailmap is not a blob: %s", name);
			return &map->items[i];


			*end++ = '\0';
#include "mailmap.h"
	struct object_id oid;


{
	debug_mm("mailmap: - simple: '%s' <%s>\n",
			for (cp = buffer + abblen; isspace(*cp); cp++)
	struct mailmap_entry *me;
		/* exact match */

		 * the cruft at the end beyond "len".  That is not a match
}
	item = string_list_insert(map, old_email);
		 (int)*namelen, debug_str(*name),


struct mailmap_info {
	struct mailmap_entry *me = (struct mailmap_entry *)p;
	*name = *email = NULL;
		return;
		 * with string[0:len] that we are looking for.
}
	char *email;

			 * The item has multiple items, so we'll look up on
				*namelen = strlen(*name);
	*name = (nstart <= nend ? nstart : NULL);
	int err = 0;

		string_list_insert(&me->namemap, old_name)->util = mi;
{
		}
		new_email = NULL;
	}

 * definition of strcasecmp and no non-inline implementation is
	return 0;
	while (fgets(buffer, sizeof(buffer), f) != NULL)
	}
		/*

#include "string-list.h"
		 debug_str(old_name), old_email,
	buf = read_object_file(&oid, &type, &size);
		--nend;
		return 0;
		 s, debug_str(mi->name), debug_str(mi->email));
	f = fopen(filename, "r");
	*email = left+1;
				char **repo_abbrev)
		}
		debug_mm("map_user:  to '%.*s' <%.*s>\n",
{

		debug_mm("mailmap: adding (complex) entry for '%s'\n", old_email);
				*email = mi->email;
 * supplied anywhere, which is, eh, "unusual"; we cannot take an
		if (!strncmp(buffer, abbrev, abblen)) {
	if (email1)
	}
				*name = mi->name;
	if (item->util) {
	struct mailmap_info *mi = (struct mailmap_info *)p;
static struct string_list_item *lookup_prefix(struct string_list *map,
	     const char **name, size_t *namelen)
		read_mailmap_line(map, buf, repo_abbrev);
void clear_mailmap(struct string_list *map)
#endif
	nend = left-1;
 * "unusual" string.h.
			char *new_name, char *new_email,
	}
#include "object-store.h"
struct mailmap_entry {
	if (item != NULL) {
 * address of such a function to store it in namemap.cmp.  This is
	me->namemap.strdup_strings = 1;
			char *cp;
/*

	debug_mm("map_user:  --\n");
	debug_mm("mailmap: cleared\n");
			 * the map does not have string[0:len] in it.
			     const char *name,
	struct string_list_item *item;
	err |= read_mailmap_file(map, ".mailmap", repo_abbrev);
		me->namemap.strdup_strings = 1;
	*(nend+1) = '\0';
			return 0;
		}
	map->cmp = namemap_cmp;
		parse_name_and_email(name2, &name2, &email2, 1);
	if (!name)



#define debug_mm(...) fprintf(stderr, __VA_ARGS__)

{
	if ((left = strchr(buffer, '<')) == NULL)
			free(me->email);
		if (me->namemap.nr) {

	if (!allow_empty_email && (left+1 == right))
	if (get_oid(name, &oid) < 0)
	/* remove whitespace from beginning and end of name */
			 * name too. If the name is not found, we choose the
			      char **repo_abbrev)
		return NULL;
	unsigned long size;
		if (new_email) {
{
		 */


static void read_mailmap_line(struct string_list *map, char *buffer,
	if (buffer[0] == '#') {

			buffer[--len] = 0;

	debug_mm("mailmap:  '%s' <%s> -> '%s' <%s>\n",


	 * overlong key would be inserted, which must come after the
/*
		else if (!cmp && !map->items[i].string[len])
{
{
#if DEBUG_MAILMAP

		me = xcalloc(1, sizeof(struct mailmap_entry));

		mi->email = xstrdup_or_null(new_email);

	string_list_clear_func(map, free_mailmap_entry);

}

	 * i is at the exact match to an overlong key, or location the
}
static void add_mapping(struct string_list *map,
 * namemap.cmp until we know no systems that matter have such an
		if (!string[len])
	char *name;
		me->namemap.cmp = namemap_cmp;
{
	while (isspace(*nstart) && nstart < left)
		}
	if (old_name == NULL) {
	}

 */
		return error_errno("unable to open mailmap at %s", filename);
	/*
				  char **email, int allow_empty_email)
		 debug_str(new_name), debug_str(new_email));

		if (errno == ENOENT)
	} else {
	int i = string_list_find_insert_index(map, string, 1);
	} else if (!string[len]) {
	 * real location of the key if one exists.
		if (*end)
		int len = strlen(buffer);
		return 1;
	return 0;
{
		struct mailmap_info *mi = (struct mailmap_info *)item->util;
	struct mailmap_entry *me;
static int read_mailmap_blob(struct string_list *map,
	char *email;
		}

	if (item != NULL) {


#define DEBUG_MAILMAP 0
	/* name and email for the complex mail and name matching case */
					      const char *string, size_t len)
			free(*repo_abbrev);
	if (type != OBJ_BLOB)
		return error("unable to read mailmap object at %s", name);
	while (*buf) {
			me->name = xstrdup(new_name);
static inline const char *debug_str(const char *s) { return s; }
};

		if (mi->name) {
	struct string_list_item *item;
static int read_mailmap_file(struct string_list *map, const char *filename,
		if (mi->email) {
};
	if (!filename)
	char *name1 = NULL, *email1 = NULL, *name2 = NULL, *email2 = NULL;

{
	string_list_clear_func(&me->namemap, free_mailmap_info);
		 (int)*emaillen, debug_str(*email));
		return 0;
				item = subitem;
}
static void read_mailmap_string(struct string_list *map, char *buf,
		buf = end;
		if (mi->name == NULL && mi->email == NULL) {
		 * followed by a string that sorts later than string[len:];
	map->strdup_strings = 1;
			me->email = xstrdup(new_email);
			char *old_name, char *old_email)
			 */
	if (i < 0) {
	free(buf);


static inline void debug_mm(const char *format, ...) {}
		static const char abbrev[] = "# repo-abbrev:";
	free(me->email);
		if (cmp < 0)
	if (!buf)
	fclose(f);
			debug_mm("map_user:  -- (no simple mapping)\n");
	free(mi->name);
