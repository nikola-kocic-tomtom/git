	if (*p != '>')
	if (!options->msg_type) {
static int fsck_gitmodules_fn(const char *var, const char *value, void *vdata)

			result = options->walk(obj, OBJ_TREE, data, options);
	int i;
	FUNC(BAD_DATE, ERROR) \

				has_dup_entries = 1;
	FUNC(FULL_PATHNAME, WARN) \
	if (!skip_prefix(buffer, "type ", &buffer)) {
	}
			if (counter++)
	return 0;
			if (*p == '_')
	FUNC(MULTIPLE_AUTHORS, ERROR) \
	FUNC(GITMODULES_BLOB, ERROR) \
		has_empty_name |= !*name;
	p += 6;
		 * that an error.
	    starts_with(url, "ftp://") ||
		}
	FUNC(BAD_OBJECT_SHA1, ERROR) \
		const char *p = msg_id_info[i].id_string;
	parse_msg_type(msg_type);
	    !isdigit(p[4]) ||
{
		if (oidset_contains(&gitmodules_done, oid))
	if (parse_config_key(var, "submodule", &subsection, &subsection_len, &key) < 0 ||
		}
		return fsck_walk_commit((struct commit *)obj, data, options);
				    value);
		return report(options, oid, OBJ_COMMIT, FSCK_MSG_MISSING_COMMITTER, "invalid format - expected 'committer' line");
{

		}
	FOREACH_MSG_ID(MSG_ID)
		retval += report(options, oid, OBJ_TREE, FSCK_MSG_BAD_TREE, "cannot be parsed as a tree");
	}
static int verify_ordered(unsigned mode1, const char *name1, unsigned mode2, const char *name2)
	int i;
		if (parse_oid_hex(buffer, &parent_oid, &p) || *p != '\n') {
				fsck_put_object_name(options, oid, "%.*s~%d",
	default:
		if (S_ISGITLINK(entry.mode))
	if (!c1 && S_ISDIR(mode1))

	else if (author_count > 1)
#define TREE_HAS_DUPS  (-2)
		/*
				      "non-blob found at .gitmodules");
{
	if (memchr(buffer_begin, '\0', size)) {
		ret = report(options, oid, OBJ_TAG, FSCK_MSG_MISSING_TYPE_ENTRY, "invalid format - expected 'type' line");
	 * line.
	}
		if (S_ISDIR(entry.mode)) {
}
			goto done;
		p = msg_id_info[i].id_string;
	if (has_empty_name)
	if (name)
	FUNC(BAD_TYPE, ERROR) \
	if (skip_prefix(url, "http::", out) ||
	if (name)
	free(name);

		return NULL;

		return report(options, oid, type, FSCK_MSG_MISSING_EMAIL, "invalid author/committer line - missing email");
			int msg_type, const char *message)
	FUNC(GITMODULES_MISSING, ERROR) \
	FUNC(BAD_EMAIL, ERROR) \
static int object_on_skiplist(struct fsck_options *opts,
}

	pos = kh_put_oid_map(options->object_names, *oid, &hashret);
		case S_IFLNK:
#define STR(x) #x
				    value);
	if (!obj)
	else
		return 0;
	const char *curl_url;

		if (update_tree_entry_gently(&desc)) {
				    FSCK_MSG_GITMODULES_UPDATE,
	return 1;
	{ NULL, NULL, NULL, -1 }
	return result;
 *
	if (*p == '>')
		list_config_item(list, prefix, msg_id_info[i].camelcased);
	strbuf_vaddf(&buf, fmt, ap);
}
		 * URLs which escape their root via "../" can overwrite
}

	va_start(ap, fmt);
	oidset_insert(&gitmodules_done, oid);

		ret = report(options, oid, OBJ_TAG, FSCK_MSG_MISSING_TAG, "invalid format - unexpected end after 'type' line");
	if (pos >= kh_end(options->object_names))
	else if (msg_type == FSCK_INFO)
	int hashret;
		ret = report(options, oid, OBJ_TAG,

			if (!options->strict)
	p += strcspn(p, "<>\n");
		}
		options->object_names = kh_init_oid_map();
	FUNC(MISSING_AUTHOR, ERROR) \
			err = report(options, oid, OBJ_COMMIT, FSCK_MSG_BAD_PARENT_SHA1, "invalid 'parent' line format - bad sha1");
	khiter_t pos;
	name = fsck_get_object_name(options, &commit->object.oid);

		return fsck_tree(&obj->oid, data, size, options);
		for (i = 0; i < FSCK_MSG_MAX; i++)
int is_valid_msg_type(const char *msg_id, const char *msg_type)
		if (starts_with_dot_slash(url)) {
/*
	FUNC(MISSING_TAG, ERROR) \
{
 * In other words, this counts "../" components at the start of a
	if (!c1 && !c2)
		return -1;
	 */

		has_null_sha1 |= is_null_oid(oid);
	struct fsck_options *options)
				      oid, OBJ_BLOB,

	FUNC(NULL_SHA1, WARN) \
	while (tree_entry_gently(&desc, &entry)) {
	struct object_id tree_oid, parent_oid;
		retval += report(options, oid, OBJ_TREE, FSCK_MSG_HAS_DOT, "contains '.'");
		 * URLs like https::example.com/submodule.git and

		msg_id_info[i].downcased = q;
	if (err)
{
	}
	const char *name;
 * from the remote_url it is to be resolved against.
		}
	if (!strcmp(key, "update") && value &&


	return kh_value(options->object_names, pos);

			      const struct object_id *oid)
		return report(options, oid, type, FSCK_MSG_BAD_DATE, "invalid author/committer line - bad date");
}
#define MSG_ID(id, msg_type) { STR(id), NULL, NULL, FSCK_##msg_type },

	strbuf_addstr(buf, oid_to_hex(oid));
		}
		if (starts_with_dot_dot_slash(url)) {
		has_nl = !!strchr(decoded, '\n');
	if (parse_tree(tree))
				   FSCK_MSG_GITMODULES_PARSE,
		return fsck_blob(&obj->oid, data, size, options);
		     const char *buffer, unsigned long size,
		return report(options, oid, type, FSCK_MSG_BAD_NAME, "invalid author/committer line - bad name");
				return err;
		/*
		if (!strcmp(buf, "skiplist")) {

#include "tag.h"
	FUNC(TREE_NOT_SORTED, ERROR) \
		switch (buffer[i]) {

static int starts_with_dot_slash(const char *str)
			url += strlen("./");

		has_full_path |= !!strchr(name, '/');

		FSCK_MSG_UNTERMINATED_HEADER, "unterminated header");
				    data->oid, OBJ_BLOB,
	if (!strcmp(key, "path") && value &&
	strbuf_release(&sb);
 *
	else {
		has_zero_pad |= *(char *)desc.buffer == '0';
		/*

	if (starts_with(url, "http://") ||
			generation = 1;
					*q++ = *p++;

	FUNC(BAD_NAME, ERROR) \
		if (err)
	if (init_tree_desc_gently(&desc, buffer, size)) {
				    data->oid, OBJ_BLOB,
			buf += len + 1;
	struct strbuf sb = STRBUF_INIT;

	struct fsck_gitmodules_data *data = vdata;
				oidset_insert(&gitmodules_found, oid);
	return retval;
	 * a '\0' into a '/' for a directory entry.
	append_msg_id(&sb, msg_id_info[id].id_string);
	if (has_full_path)
		return;
		}
	p++;

	if (!hashret)
#include "credential.h"
	*ident = strchrnul(*ident, '\n');
{
				       fsck_describe_object(options, &tree->object.oid),
	buffer = p + 1;
 */
		       struct fsck_options *options)
	    !isdigit(p[3]) ||
		case S_IFREG | 0664:
	int ret;
			continue;
		return -1;
			      ".gitmodules too large to parse");
			while (backslash) {
	if (!oidset_contains(&gitmodules_found, oid))
	FUNC(MISSING_OBJECT, ERROR) \
	cmp = memcmp(name1, name2, len);
static int fsck_commit(const struct object_id *oid,



	/*
	if (type_from_string_gently(buffer, eol - buffer, 1) < 0)
	p += strcspn(p, "<>\n");
static int fsck_msg_type(enum fsck_msg_id msg_id,
		o_name = name;
		goto done;
	if (size && buffer[size - 1] == '\n')
	return options->walk(tag->tagged, OBJ_ANY, data, options);
	assert(msg_id >= 0 && msg_id < FSCK_MSG_MAX);
	if (obj->type == OBJ_TAG)
						     name, counter);
{
		retval += report(options, oid, OBJ_TREE, FSCK_MSG_FULL_PATHNAME, "contains full pathnames");
		o_mode = mode;
	FUNC(MISSING_TREE, ERROR) \
}
		for (equal = 0;

			const struct object_id *oid,
 * relative to the current directory on any platform, since \ is a
	if (!strcmp(key, "url") && value &&
		ret = report(options, oid, OBJ_TAG, FSCK_MSG_MISSING_TAGGER_ENTRY, "invalid format - expected 'tagger' line");

		ALLOC_ARRAY(msg_type, FSCK_MSG_MAX);
	    skip_prefix(url, "https::", out) ||
						retval += report(options, oid, OBJ_TREE,
	FUNC(HAS_DOT, WARN) \
				backslash++;
	if (author_count < 1)
{
		retval += report(options, oid, OBJ_TREE, FSCK_MSG_ZERO_PADDED_FILEMODE, "contains zero-padded file modes");
		return -1;
				generation += power * (name[--len] - '0');
		data.ret |= report(options, oid, OBJ_BLOB,
	 * on because in the default configuration, is_transport_allowed
#define MSG_ID(id, msg_type) FSCK_MSG_##id,
#include "utf8.h"
	int has_dotdot = 0;
#include "commit.h"
	static struct strbuf bufs[] = {


		return 0;
		     struct fsck_options *options)
		 */

	int len1 = strlen(name1);
		return 0;
	return 0;
				".gitmodules", buf, size, &data, &config_opts))

	if (looks_like_command_line_option(url))
{

	int ret = 0;
{
		retval += report(options, oid, OBJ_TREE, FSCK_MSG_NULL_SHA1, "contains entries pointing to null sha1");
	if (git_config_from_mem(fsck_gitmodules_fn, CONFIG_ORIGIN_BLOB,
		 */
	    !subsection)
		struct credential c = CREDENTIAL_INIT;
}
						     name, entry.path);
	va_end(ap);

		if (is_hfs_dotgitmodules(name) || is_ntfs_dotgitmodules(name)) {
	    starts_with(url, "https://") ||


static int fsck_walk_tree(struct tree *tree, void *data, struct fsck_options *options)
		     unsigned long size, struct fsck_options *options)

			/* fallthrough */
	return opts && oid && oidset_contains(&opts->skiplist, oid);
		      const struct object_id *oid, enum object_type type,
{

		}
	 * automatically.

				*(q)++ = tolower(*(p)++);
	FUNC(MISSING_TAGGER_ENTRY, INFO)
	FUNC(GITMODULES_URL, ERROR) \
{
	int has_dot = 0;
				break;
		return FSCK_IGNORE;
	char *buf = xstrdup(values), *to_free = buf;
	config_opts.error_action = CONFIG_ERROR_SILENT;
			buf++;
	FUNC(MISSING_COMMITTER, ERROR) \
	FUNC(UNKNOWN_TYPE, ERROR) \
	return report(options, &obj->oid, obj->type,
		goto done;
				continue;
			continue;
	}
static int report(struct fsck_options *options,

				    FSCK_MSG_GITMODULES_NAME,
	int subsection_len;
		}
		return report(options, oid, OBJ_COMMIT, FSCK_MSG_MISSING_TREE, "invalid format - expected 'tree' line");
				    FSCK_MSG_GITMODULES_URL,
 * Otherwise, returns 0 and leaves "out" untouched.
						     name, entry.path);
	while (skip_prefix(buffer, "author ", &buffer)) {

{
	if (ret)
	FUNC(BAD_DATE_OVERFLOW, ERROR) \
		const char *next;
			if (name && obj)

		return 0;
		data->ret |= report(data->options,

		return FSCK_WARN;
						     name_prefix_len, name,

	}
{
			case TREE_HAS_DUPS:

				"unterminated header: NUL at offset %ld", i);
		int len = strlen(p);
static void prepare_msg_ids(void)
	int retval = 0;

	int res;
	while ((oid = oidset_iter_next(&iter))) {
	else if (!strcmp(str, "ignore"))
	}
};
	if (!strcmp(str, "error"))

	return res;
	}
	}
}
	if (has_dotdot)
	int len2 = strlen(name2);
	}
	FUNC(MISSING_TAG_ENTRY, ERROR) \
		goto done;
{

	result = options->error_func(options, oid, object_type,
}
		}
	const char *downcased;
		return -1;
				 const struct object_id *oid)
		enum object_type type;
	struct name_entry entry;
	if (*p == '0' && p[1] != ' ')
				if (is_ntfs_dotgitmodules(backslash)) {
	while (desc.size) {
				break;
	else if (url_to_curl_url(url, &curl_url)) {
			default:
	const char *buffer_begin = buffer;
	FOREACH_MSG_ID(MSG_ID)
	}
	if (init_tree_desc_gently(&desc, tree->buffer, tree->size))
				    data->oid, OBJ_BLOB,
			if (!S_ISLNK(mode))
	int result;
		}

	char *name;
			}
__attribute__((format (printf, 5, 6)))


		if (equal == len)
	int has_null_sha1 = 0;
	struct fsck_options *options)
			     "invalid 'tag' name: %.*s",
	FSCK_MSG_MAX
		       const char *buffer, unsigned long size,
	FUNC(MISSING_NAME_BEFORE_EMAIL, ERROR) \
		char *buf;
	return msg_type;
		data->ret |= report(data->options,
	}
	FUNC(DUPLICATE_ENTRIES, ERROR) \
static int url_to_curl_url(const char *url, const char **out)
	buffer = eol + 1;
		*q = '\0';
			if (*p == '_') {
			return report(options, oid, type,
 *

}
	FUNC(MISSING_TREE_OBJECT, ERROR) \
const char *fsck_describe_object(struct fsck_options *options,
	va_list ap;
	if (!skip_prefix(buffer, "object ", &buffer)) {


/*
				return 0;
		return report(options, oid, type, FSCK_MSG_BAD_EMAIL, "invalid author/committer line - bad email");
			if (is_promisor_object(oid))

		      fsck_describe_object(options, &obj->oid));
	FUNC(GITMODULES_UPDATE, ERROR) \
			goto done;
	return 1;
{
		return -1;
	const char *name;
				    value);
			} else {
	FUNC(MISSING_SPACE_BEFORE_EMAIL, ERROR) \
	options->msg_type[id] = type;
enum fsck_msg_id {

	if (**ident == '\n')
	p++;

} msg_id_info[FSCK_MSG_MAX + 1] = {
			       OBJ_TREE, data, options);
	 */
 *   https://example.com/repo.git -> 1, https://example.com/repo.git
}
	return c1 < c2 ? 0 : TREE_UNORDERED;
#define FSCK_FATAL -1

		if (!len) {
	unsigned char c1, c2;

	oidset_clear(&gitmodules_done);
	while (skip_prefix(buffer, "parent ", &buffer)) {
	}
{
		 * susceptible to CVE-2020-11008.
/*
		if (!res)
		return report(options, oid, OBJ_BLOB,
	const char *subsection, *key;
		return result;
		ret = report(options, oid, OBJ_TAG, FSCK_MSG_MISSING_OBJECT, "invalid format - expected 'object' line");
	if (type != FSCK_ERROR && msg_id_info[id].msg_type == FSCK_FATAL)

			     FSCK_MSG_BAD_TAG_NAME,
	if (!eol) {
	struct commit_list *parents;
	FUNC(GITMODULES_LARGE, ERROR) \

	if (cmp > 0)
 * The entries in a tree are ordered in the _path_ order,
			ret = -1;
 */
		return err;
{
		retval += report(options, oid, OBJ_TREE, FSCK_MSG_DUPLICATE_ENTRIES, "contains duplicate file entries");
		buf = read_object_file(oid, &type, &size);
{
		return report(options, oid, type, FSCK_MSG_MISSING_SPACE_BEFORE_DATE, "invalid author/committer line - missing space before date");
	int has_dotgit = 0;
		parse_object(the_repository, &obj->oid);
	struct config_options config_opts = { 0 };
	}
		/* early tags do not contain 'tagger' lines; warn only */
	}
	if (has_bad_modes)
 * Count directory components that a relative submodule URL should chop
	va_end(ap);
			struct object_id *oid = &parents->item->object.oid;
void fsck_set_msg_types(struct fsck_options *options, const char *values)
static void append_msg_id(struct strbuf *sb, const char *msg_id)
				      oid, type,

	oidset_clear(&gitmodules_found);
	case OBJ_BLOB:
	prepare_msg_ids();

		if (credential_from_url_gently(&c, curl_url, 1) ||
			break;
	FUNC(BAD_PARENT_SHA1, ERROR) \

const char *fsck_get_object_name(struct fsck_options *options,
		int has_nl;
	case OBJ_COMMIT:
	case OBJ_TAG:
				retval += report(options,
		return report(options, oid, type, FSCK_MSG_BAD_DATE_OVERFLOW, "invalid author/committer line - date causes integer overflow");
		buf += len + 1;
		while (*p)
			if (i + 1 < size && buffer[i + 1] == '\n')
 * "../" components to out.
			for (generation = 0, power = 1;

	if (date_overflows(parse_timestamp(p, &end, 10)))
		    unsigned long size, struct fsck_options *options)
	if ((end == p || *end != ' '))
		die("Unknown fsck message type: '%s'", str);
#define FOREACH_MSG_ID(FUNC) \
	const char *name = fsck_get_object_name(options, oid);
	int not_properly_sorted = 0;
			if (equal == len)
	strbuf_vaddf(&sb, fmt, ap);
		err = report(options, oid, OBJ_COMMIT, FSCK_MSG_MULTIPLE_AUTHORS, "invalid format - multiple 'author' lines");
	if (not_properly_sorted)
int fsck_walk(struct object *obj, void *data, struct fsck_options *options)
	char *end;
			msg_type[i] = fsck_msg_type(i, options);

		fsck_set_msg_type(options, buf, buf + equal + 1);
			break;
	const char *p = *ident;
	if (obj->type == OBJ_TREE)
		strbuf_addf(buf, " (%s)", name);
		msg_type = FSCK_ERROR;


	}
		msg_type = options->msg_type[msg_id];
		if ((backslash = strchr(name, '\\'))) {
	FUNC(NUL_IN_HEADER, FATAL) \
			ret |= fsck_blob(oid, buf, size, options);
 */
	eol = strchr(buffer, '\n');
}
				backslash = strchr(backslash, '\\');
	if (!c2 && S_ISDIR(mode2))
}
		if (ret)

	static int b = 0;
			has_bad_modes = 1;
	if (!skip_prefix(buffer, "committer ", &buffer))

	if (msg_type == FSCK_FATAL)

	};
						 oid, OBJ_TREE,
			  const char *fmt, ...)
	return -1;
 * git-remote-curl to the "out" parameter.
static int check_submodule_url(const char *url)
}
			ret |= report(options,
	}
 *   git://example.com/repo.git -> 0

			die("Missing '=': '%s'", buf);
	for (i = 0; i < size; i++) {
		char *q = xmalloc(len);
	free(to_free);
				not_properly_sorted = 1;
	return report(options, oid, type,
		return fsck_commit(&obj->oid, data, size, options);
				    name);
			obj = (struct object *)lookup_blob(the_repository, &entry.oid);

void fsck_set_msg_type(struct fsck_options *options,
	b = (b + 1) % ARRAY_SIZE(bufs);


		goto done;


	type = parse_msg_type(msg_type);
	return buf->buf;
			return result;
	o_name = NULL;
		 */

		if (!buf) {
		const struct object_id *oid;


static struct {
				   "could not parse gitmodules blob");
				    "disallowed submodule path: %s",
}
			switch (verify_ordered(o_mode, o_name, mode, name)) {
	case OBJ_TREE:
		default:
		 * check for malicious characters.
	return 0;
	FUNC(MISSING_TYPE_ENTRY, ERROR) \
 * Check whether a transport is implemented by git-remote-curl.
		else { /* parse ~<generation> suffix */
		 */
		if (ret)
	    skip_prefix(url, "ftp::", out) ||
	/*
	    starts_with(url, "ftps://")) {
 * submodule URL.

	if (ret)
		    !*c.host)
	int has_zero_pad = 0;
		 * git-write-tree used to write out a nonsense tree that has
				       entry.path, entry.mode);
	if (obj->type == OBJ_NONE)
				break;
			url += strlen("../");
	FUNC(ZERO_PADDED_FILEMODE, WARN) \
#include "fsck.h"
		return 0;
	const char *p;
	if (*p == '<')
}
				fsck_put_object_name(options, oid, "%s^", name);
	 * Now we need to order the next one, but turn
	if (result < 0)
			obj = (struct object *)lookup_tree(the_repository, &entry.oid);
	return str[0] == '.' && (str[1] == '/' || str[1] == '\\');
			     (int)(eol - buffer), buffer);
	if (!options->object_names)
		return;
	for (i = 0; i < FSCK_MSG_MAX; i++) {
				fsck_put_object_name(options, &entry.oid, "%s%s/",
			continue;

		if (err)
static int verify_headers(const void *data, unsigned long size,
	if (submodule_url_is_relative(url)) {
	for (i = 0; i < FSCK_MSG_MAX; i++)
			assert(*msg_id);
		if (ret)
{
		return FSCK_ERROR;
			result = options->walk(obj, OBJ_BLOB, data, options);
{

	}
}
			res = result;
	int cmp;
		}

		msg_type = FSCK_WARN;
	if (has_zero_pad)
	FUNC(NUL_IN_COMMIT, WARN) \
}
	if (parse_tag(tag))
	if (object_on_skiplist(options, oid))
		return -1;
	prepare_msg_ids();
	int res = 0;
		return fsck_walk_tree((struct tree *)obj, data, options);
void fsck_put_object_name(struct fsck_options *options,
	buffer = p + 1;
			oidset_parse_file(&options->skiplist, buf + equal + 1);
	name = xmemdupz(subsection, subsection_len);
	int msg_type;
	oidset_iter_init(&gitmodules_found, &iter);
	else
static int fsck_tag(const struct object_id *oid, const char *buffer,
}
						     generation + 1);
		retval += report(options, oid, OBJ_TREE, FSCK_MSG_EMPTY_NAME, "contains empty pathname");
			strbuf_addch(sb, *(msg_id)++);
	unsigned author_count;
			else
	FUNC(HAS_DOTGIT, WARN) \
	struct tree_desc desc;
		c1 = '/';
		retval += report(options, oid, OBJ_TREE, FSCK_MSG_HAS_DOTDOT, "contains '..'");
	FUNC(BAD_TAG_NAME, INFO) \
		}
		     equal < len && buf[equal] != '=' && buf[equal] != ':';
	if (*p != ' ')
	if (!buf) {
{
		data->ret |= report(data->options,
}

};
 * This is for use in checking for previously exploitable bugs that
	 * we do want to see the terminating LF for the last header
	if (parse_msg_id(msg_id) < 0)
		buf[equal] = '\0';
	 */
	if (options->msg_type)
 *
	FUNC(BAD_TREE_SHA1, ERROR) \
	if (check_refname_format(sb.buf, 0)) {
	int result = 0;
}
		 * the host field and previous components, resolving to
void list_config_fsck_msg_ids(struct string_list *list, const char *prefix)
	struct strbuf sb = STRBUF_INIT;
int fsck_finish(struct fsck_options *options)
		return;
		has_dotdot |= !strcmp(name, "..");
	 * We did not find double-LF that separates the header

		if (name) {
			strbuf_addch(sb, tolower(c));
	data.ret = 0;
		data->ret |= report(data->options, data->oid, OBJ_BLOB,
#include "repository.h"

			return err;
{
{
		free(buf);
	FUNC(BAD_TIMEZONE, ERROR) \
 * a slash to the end of it.
				FSCK_MSG_NUL_IN_HEADER,
	if (msg_type == FSCK_WARN) {
int fsck_error_function(struct fsck_options *o,
		err = report(options, oid, OBJ_COMMIT, FSCK_MSG_NUL_IN_COMMIT,
		goto done;
		 * entries with the same name, one blob and one tree.  Make
		return 0;
	while (!done) {
	 * prevents URLs with those schemes from being cloned

	err = fsck_ident(&buffer, oid, OBJ_COMMIT, options);
			else if (generation > 0)
		oid = tree_entry_extract(&desc, &name, &mode);
		    (*next == ':' || *next == '/'))
		}
}
#include "submodule-config.h"
	o_mode = 0;
				*q++ = tolower(*p++);

			result = error("in tree %s: entry %s has bad mode %.6o",

int fsck_object(struct object *obj, void *data, unsigned long size,
 */
		int i;
		return report(options, oid, type, FSCK_MSG_BAD_TIMEZONE, "invalid author/committer line - bad time zone");
 */
		return result;
		return fsck_tag(&obj->oid, data, size, options);
	const char *id_string;
static struct oidset gitmodules_done = OIDSET_INIT;
#include "blob.h"
	if (!options->object_names)

struct fsck_gitmodules_data {
 * directory separator even on non-Windows platforms.
	struct strbuf buf = STRBUF_INIT;
			enum object_type object_type,
		else if (S_ISREG(entry.mode) || S_ISLNK(entry.mode)) {
		return TREE_UNORDERED;
	if (name)
	while (parents) {
static int submodule_url_is_relative(const char *url)
		if (result < 0)
		case S_IFGITLINK:
	khiter_t pos;
		err = report(options, oid, OBJ_COMMIT, FSCK_MSG_MISSING_AUTHOR, "invalid format - expected 'author' line");
		result = options->walk((struct object *)parents->item, OBJ_COMMIT, data, options);
	const char *camelcased;
	int err;
 * required a submodule URL to be passed to git-remote-curl.
}
}
{
	res = result;
		 * bits..
			  const struct object_id *oid,
{
 * called "a.c", because "a/" sorts after "a.c".
}
				     "%s:", name);
	int ret = 0;
	}
 * This is for use in checking whether a submodule URL is interpreted as
		has_dotgit |= is_hfs_dotgit(name) || is_ntfs_dotgit(name);
	FUNC(MISSING_SPACE_BEFORE_DATE, ERROR) \
static int parse_msg_type(const char *str)
	}
		return report(options, oid, type, FSCK_MSG_ZERO_PADDED_DATE, "invalid author/committer line - zero-padded date");
			  struct fsck_options *options)
	FUNC(HAS_DOTDOT, WARN) \
	}
}

		case '\n':
#include "object.h"
		ret = report(options, oid, OBJ_TAG, FSCK_MSG_MISSING_TYPE, "invalid format - unexpected end after 'type' line");
	if (verify_headers(buffer, size, oid, OBJ_COMMIT, options))
		return 0;
						 FSCK_MSG_GITMODULES_SYMLINK,
/*
	const char *name = fsck_get_object_name(options, &tag->object.oid);

}
	const struct object_id *oid;
	}
			result++;
	const char *o_name;
	if (object_on_skiplist(options, oid))
	    parse_submodule_update_type(value) == SM_UPDATE_COMMAND)

	const char *p;
		case S_IFDIR:
		die("Unhandled message id: %s", msg_id);
}
				 const struct object_id *oid)
	const struct object_id *oid;
 *   http::https://example.com/repo.git -> 1, https://example.com/repo.git
		if (c != '_')
	}
	FUNC(BAD_FILEMODE, WARN) \
			buf[equal] = tolower(buf[equal]);
		 * This could be appended to an http URL and url-decoded;
			continue;
	    !isdigit(p[2]) ||
 * Returns the number of directory components to chop and writes a
		 */
	return 0;
		STRBUF_INIT, STRBUF_INIT, STRBUF_INIT, STRBUF_INIT
		unsigned long size;
 * Examples:
{
		return retval;
				fsck_put_object_name(options, oid, "%s^%d",

		ret = report(options, oid, OBJ_TAG, FSCK_MSG_BAD_OBJECT_SHA1, "invalid 'object' line format - bad sha1");
static int fsck_ident(const char **ident,
		return 1;
			continue;
		if (!strcmp(text, msg_id_info[i].downcased))
	/* warnings */ \
		error("Unknown object type for %s",
		case S_IFREG | 0755:

			return err;
	    skip_prefix(url, "ftps::", out))
 *
{
		decoded = url_decode(url);

	struct fsck_gitmodules_data data;

		retval += report(options, oid, OBJ_TREE, FSCK_MSG_HAS_DOTGIT, "contains '.git'");
	strbuf_addf(&sb, "refs/tags/%.*s", (int)(eol - buffer), buffer);

	return starts_with_dot_slash(url) || starts_with_dot_dot_slash(url);
	return ret;

			else
	}
		else {
		return NULL;
						oidset_insert(&gitmodules_found, oid);
		char c = *(msg_id)++;
 * helper of the same name with the twist that it accepts backslash as a
static int fsck_walk_commit(struct commit *commit, void *data, struct fsck_options *options)
		fsck_put_object_name(options, &tag->tagged->oid, "%s", name);
		      obj->type);
	struct strbuf *buf;

	strbuf_release(&sb);
	return data.ret;
	strbuf_reset(buf);
		while (*p) {
		ret = report(options, oid, OBJ_TAG, FSCK_MSG_BAD_TYPE, "invalid 'type' value");
		 * https:///example.com/submodule.git that were
	error("object %s: %s", fsck_describe_object(o, oid), message);
 * So a directory called "a" is ordered _after_ a file
static int fsck_tree(const struct object_id *oid,
		const char *msg_id, const char *msg_type)
		if (result < 0)
#include "oidset.h"
	if (!skip_prefix(buffer, "tree ", &buffer))

	if (check_submodule_name(name) < 0)
	if (msg_id_info[0].downcased)
				      FSCK_MSG_GITMODULES_MISSING,
{

		return 1;
static struct oidset gitmodules_found = OIDSET_INIT;
 * Like builtin/submodule--helper.c's starts_with_dot_slash, but without

	kh_value(options->object_names, pos) = strbuf_detach(&buf, NULL);
				p++;
	 * We don't need to check for case-aliases, "http.exe", and so
			if (err)
	int i;
				    "disallowed submodule name: %s",
}
		done = !buf[len];
 * which means that a directory entry is ordered by adding
			name_prefix_len = len - 1;
		int len = strlen(name), power;
	if (has_dotgit)
	int len = len1 < len2 ? len1 : len2;
	eol = strchr(buffer, '\n');
	FUNC(ZERO_PADDED_DATE, ERROR) \
		has_dot |= !strcmp(name, ".");
	return 0;
			return -1;
								 FSCK_MSG_GITMODULES_SYMLINK,
		else
	/* fatal errors */ \
		  const struct object_id *oid, enum object_type object_type,
	}
 *
			return -1;
			     power *= 10)
		parents = parents->next;
}
#include "tree-walk.h"
			else
	buffer = eol + 1;
			  const struct object_id *oid, enum object_type type,
	data.options = options;
	struct object_id tagged_oid;
	/*
	int msg_type;
#define TREE_UNORDERED (-1)
#include "cache.h"

		if (has_nl)
	int id = parse_msg_id(msg_id), type;
				die("skiplist requires a path");

		return report(options, NULL, OBJ_NONE, FSCK_MSG_BAD_OBJECT_SHA1, "no valid object to fsck");
		goto done;
				     msg_type, sb.buf);
			retval += report(options, oid, OBJ_TREE, FSCK_MSG_BAD_TREE, "cannot be parsed as a tree");
				    "disallowed submodule update setting: %s",
	data.oid = oid;
			if (name && obj)
	int has_dup_entries = 0;
	else if (!strcmp(str, "warn"))
		      "unknown type '%d' (internal fsck error)",
		return fsck_walk_tag((struct tag *)obj, data, options);

		if (type == OBJ_BLOB)
	FUNC(UNTERMINATED_HEADER, FATAL) \
		options->msg_type = msg_type;
	}
	int done = 0;
			continue;
			return result;

		int ret = 0;
		buf[len] = '\0';
static int fsck_blob(const struct object_id *oid, const char *buf,
	p = end + 1;
	if (!options->object_names)
		unsigned short mode;
		 * blob too gigantic to load into memory. Let's just consider
		if (!c)
		      struct fsck_options *options)
			      FSCK_MSG_GITMODULES_LARGE,
	if (cmp < 0)
			ret |= report(options,
	if (name && parents) {
}
	for (i = 0; i < FSCK_MSG_MAX; i++)
		return TREE_HAS_DUPS;
			res = result;
	va_list ap;
	if (!eol) {
				}
		return err;
	FUNC(GITMODULES_SYMLINK, ERROR) \
	}

	FUNC(GITMODULES_NAME, ERROR) \
	if (!obj)

	for (;;) {
	struct oidset_iter iter;
#undef MSG_ID
	if (err)
	if ((*p != '+' && *p != '-') ||
	if (*p != '<')
		q = xmalloc(len);
		ret = fsck_ident(&buffer, oid, OBJ_TAG, options);
static int starts_with_dot_dot_slash(const char *str)
	return str[0] == '.' && starts_with_dot_slash(str + 1);
		      FSCK_MSG_UNKNOWN_TYPE,
	const char *buffer = (const char *)data;
static int fsck_walk_tag(struct tag *tag, void *data, struct fsck_options *options)


		char *decoded;
		}
{
#include "object-store.h"
	FUNC(GITMODULES_PATH, ERROR) \
	ret = verify_headers(buffer, size, oid, OBJ_TAG, options);
				      "unable to read .gitmodules blob");
	buf = bufs + b;
		 * early on when we honored the full set of mode
		if (count_leading_dotdots(url, &next) > 0 &&
		buffer = p + 1;
			msg_type = FSCK_ERROR;
		 * A missing buffer here is a sign that the caller found the
		retval += report(options, oid, OBJ_TREE, FSCK_MSG_BAD_FILEMODE, "contains bad file modes");
	return res;

 * pointer to the next character of url after all leading "./" and
	FUNC(EMPTY_NAME, WARN) \
		switch (mode) {
{
	    looks_like_command_line_option(value))

				      FSCK_MSG_GITMODULES_BLOB,
	FUNC(GITMODULES_PARSE, INFO) \


		 * sure we do not have duplicate entries.
		return report(options, oid, type, FSCK_MSG_MISSING_NAME_BEFORE_EMAIL, "invalid author/committer line - missing space before email");
		if (len && name[len - 1] == '^') {
#undef MSG_ID
		*out = url;
{
	int has_full_path = 0;
								 ".gitmodules is a symbolic link");
						 ".gitmodules is a symbolic link");
				    "disallowed submodule url: %s",
	if (parse_oid_hex(buffer, &tree_oid, &p) || *p != '\n') {
		warning("object %s: %s", fsck_describe_object(o, oid), message);
 * If it is, returns 1 and writes the URL that would be passed to
	if (obj->type == OBJ_COMMIT)

		}
{

#include "refs.h"
		 * This is nonstandard, but we had a few of these
	name = fsck_get_object_name(options, &tree->object.oid);
			case TREE_UNORDERED:
 * directory separator on Windows but not on other platforms.
	}
}

	return ret;


	if (parse_commit(commit))
		return ret;
		c2 = '/';
#include "packfile.h"
	if (has_dot)

		return -1;
		goto done;
	 * and the body.  Not having a body is not a crime but
	strbuf_addstr(sb, ": ");
	/* infos (reported as warnings, but ignored by default) */ \
done:
		else {
			if (power > 1 && len && name[len - 1] == '~')

	    check_submodule_url(value) < 0)
	unsigned o_mode;
				if (*p)
	if (has_null_sha1)
	p++;
			return i;
	c2 = name2[len];
}
		case '\0':
	if (obj->type == OBJ_BLOB)
	struct tree_desc desc;
		die("Cannot demote %s to %s", msg_id, msg_type);
		}
 * relying on the platform-dependent is_dir_sep helper.

void fsck_enable_object_names(struct fsck_options *options)
			return err;
		err = fsck_ident(&buffer, oid, OBJ_COMMIT, options);
		  enum fsck_msg_id id, const char *fmt, ...)

	}
		return -1;
			continue;
	while (1) {
	if (!skip_prefix(buffer, "tagger ", &buffer)) {
#include "tree.h"
static int parse_msg_id(const char *text)
		if (!res)

}
		*out = url;

 * Like starts_with_dot_slash, this is a variant of submodule--helper's
		return 0;
		if (options->strict && msg_type == FSCK_WARN)


	if (p[-1] != ' ')
	FUNC(BAD_TREE, ERROR) \
			     "NUL byte in the commit object body");
		int result;
		(*ident)++;
	FUNC(BAD_TAG_OBJECT, ERROR) \
				break;
 *
	int has_bad_modes = 0;
#include "url.h"
	va_start(ap, fmt);
		retval += report(options, oid, OBJ_TREE, FSCK_MSG_TREE_NOT_SORTED, "not properly sorted");
/*
	if (id < 0)
{


				has_dotgit |= is_ntfs_dotgit(backslash);
	int msg_type = fsck_msg_type(id, options), result;
	FUNC(MISSING_TYPE, ERROR) \
		}
	pos = kh_get_oid_map(options->object_names, *oid);
		return report(options, oid, type, FSCK_MSG_MISSING_SPACE_BEFORE_EMAIL, "invalid author/committer line - missing space before email");
				name_prefix_len = len - 1;
					else
		credential_clear(&c);
		int len = strcspn(buf, " ,|"), equal;
					if (!S_ISLNK(mode))
	if (msg_type == FSCK_IGNORE)
#include "config.h"
		}
	unsigned long i;
	    (p[5] != '\n'))
		 */

		const char *name, *backslash;
	if (has_dup_entries)
};
	}
	/* convert id_string to lower case, without underscores. */
{
	 * Ok, the first <len> characters are the same.
		msg_id_info[i].camelcased = q;
		msg_type = msg_id_info[msg_id].msg_type;
#include "help.h"
		fsck_put_object_name(options, get_commit_tree_oid(commit),
			break;
		/*
			     len && isdigit(name[len - 1]);
		err = report(options, oid, OBJ_COMMIT, FSCK_MSG_BAD_TREE_SHA1, "invalid 'tree' line format - bad sha1");
#include "decorate.h"
#define FSCK_INFO -2
	parents = commit->parents;
				    FSCK_MSG_GITMODULES_PATH,
		 * Standard modes..

		case S_IFREG | 0644:
	int has_empty_name = 0;
	if (parse_oid_hex(buffer, &tagged_oid, &p) || *p != '\n') {
	if (!skip_prefix(buffer, "tag ", &buffer)) {
		/*
				fsck_put_object_name(options, &entry.oid, "%s%s",

		/*
	}
		ret = report(options, oid, OBJ_TAG, FSCK_MSG_MISSING_TAG_ENTRY, "invalid format - expected 'tag' line");
	author_count = 0;
		*q = '\0';
		return 0;
		struct object *obj;
		int *msg_type;
	c1 = name1[len];
	    !isdigit(p[1]) ||
	switch (obj->type) {
		if (err)
{
		free(decoded);
			}
		     equal++)

}
		}

 *
		return 0;
}
	/* errors */ \
	int counter = 0, generation = 0, name_prefix_len = 0;
	struct fsck_options *options;
			}
		author_count++;
				p++;
		if (o_name) {
	FUNC(MISSING_EMAIL, ERROR) \
	char *eol;
static int count_leading_dotdots(const char *url, const char **out)
	result = options->walk((struct object *)get_commit_tree(commit),
			goto done;
