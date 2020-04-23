}
	const char *env = getenv(CONFIG_DATA_ENVIRONMENT);
					  const struct config_store_data *store)
		if (!cf || !cf->path)
	if (starts_with(var, "mailmap."))

		if (type == CONFIG_EVENT_COMMENT)
		strbuf_reset(&text);
	else
	if (!*dest)
		 * and the value.
{
	int multi_replace;

			store.value_regex = NULL;
				   store->seen_alloc);
			section_seen = 1;
			strbuf_reset(var);
	git_die_config_linenr(key, kv_info->filename, kv_info->linenr);
	return ret;

	struct strbuf sb = STRBUF_INIT;
		return v;

{
 * NULL, then we aren't parsing anything (and depending on the function looking
	/*
	else if (skip_prefix_mem(cond, cond_len, "onbranch:", &cond, &cond_len))
		break;
 * If we are about to unset the last key(s) in a section, and if there are

	 * First, ensure that this is the first key, and that there are no




static int write_error(const char *filename)
static int git_parse_int(const char *value, int *ret)
			return 0;
{
	if (!strcmp(var, "core.compression")) {
	}
	default:
		return 0;
	if (git_parse_int(value, &v))
						    value_regex, multi_replace))
}
			return -1;
#define MAX_INCLUDE_DEPTH 10
	if (!strcmp(var, "core.sparsecheckout")) {
		return error(_("bogus config parameter: %s"), text);
}
	if (0 <= v)
		else if (!strcmp(value, "tracking")) /* deprecated */
			return 0;
		precomposed_unicode = git_config_bool(var, value);
		return git_config_string(&askpass_program, var, value);
		/* Is this the section we were looking for? */
		fsync_object_files = git_config_bool(var, value);


					goto write_err_out;
const struct string_list *git_configset_get_value_multi(struct config_set *cs, const char *key)
		 * are in the desired section.
					    data);
	errno = EINVAL;
			      const struct object_id *oid,
		return c;
	if (starts_with(var, "advice.") || starts_with(var, "color.advice"))
	 */
		error_errno(_("could not lock config file %s"), config_filename);
				goto out_free;
			return config_error_nonbool(var);
}
		error_return = -1;


		if (store.seen_nr == 0) {
	if (store->value_regex != NULL &&
		return 0;
void git_die_config(const char *key, const char *err, ...)
	top.u.buf.buf = buf;
	if (!strcmp(var, "core.trustctime")) {


			continue;
/*
	}
	if (!strcmp(var, "core.hookspath"))
	/* Add other config variables here and to Documentation/config.txt. */
			goto out;
			goto out_free;
	    (cond && include_condition_is_true(inc->opts, cond, cond_len)) &&
		return 0;
	return !git_env_bool("GIT_CONFIG_NOSYSTEM", 0);
	if (!value)
	ret = 0 - git_config_parse_key(key, &store.key, &store.baselen);

					output += offset + i;
	}
	config_store_data_clear(&store);
		ret = do_config_from_file(fn, CONFIG_ORIGIN_FILE, filename,
	return do_git_config_sequence(opts, fn, data);
	 * for querying entries from the hashmap.
}

				break;

	if (git_parse_signed(expiry_string, &days, maximum_signed_value_of_type(int))) {
			error_errno(_("unable to mmap '%s'"), config_filename);
		struct config_buf {
			return val;
	ret = write_error(get_lock_file_path(&lock));
	if (baselen_)
	} else
	cs->hash_initialized = 1;
	const char *value;
	 * Validate the key and while at it, lower case it for matching.
	if (!strcmp(var, "core.ignorecase")) {
				return error(_("abbrev length out of range: %d"), abbrev);
	add_trailing_starstar_for_dir(&pattern);
		if (bomptr && *bomptr) {
	else
{
	git_config_check_init(repo);
	}
{
	}
		kv_info->origin_type = cf->origin_type;
{
		    factor * uval > max) {
	return 0;
			strbuf_add(&copystr, output, length);
}
	*ret = tmp;
	/* Add other config variables here and to Documentation/config.txt. */

	strbuf_release(&buf);
			check_stat = 0;
	int ret = -1;
}
	val = git_env_ulong("GIT_TEST_INDEX_THREADS", 0);
		strbuf_setlen(pair[0], pair[0]->len - 1);
		for (; space; space--)
static enum config_scope current_parsing_scope;
		int is_section = 0;
	 * the end offset of the event is the current file position, otherwise
	}

		*subsection_len = dot - *subsection;
	strbuf_release(&commondir);
				cf->do_ungetc(c, cf);
	 * and that there are no comments that are possibly about the current
	/* unknown conditionals are always false */
					 * We wrote out the new section, with
		if (!subsection)
	if (data->previous_type != CONFIG_EVENT_EOF &&
	}
	const char *error_type = (errno == ERANGE) ?
	cf->subsection_case_sensitive = 0;
		char *path = git_pathdup("config.worktree");
	 * We are really removing the last entry/entries from this section, and
		return include_by_branch(cond, cond_len);

		else if (!strcmp(value, "never"))
		if (git_config_from_file_with_options(store_aux,
	 * we will already have advanced to the next event.
{
	strbuf_release(&top->value);
	rollback_lock_file(&lock);

static void config_store_data_clear(struct config_store_data *store)
		type = cf->origin_type;
				       "upstream or current"));
int git_configset_get_string(struct config_set *cs, const char *key, char **dest)
	}
			contents = NULL;
	    !access_or_die(repo_config, R_OK, 0))
		store->seen[store->seen_nr] = store->parsed_nr;
	return v ? git_config_bool(k, v) : def;

						 */
		}
	offset = cf->do_ftell(cf);
	if (!*name)
static int do_config_from(struct config_source *top, config_fn_t fn, void *data,
		 * any wildcard character in it can't create side effects.
	store->parsed[store->parsed_nr].end = end;
		core_compression_level = level;
		for (i = dot - key + 1; i < store->baselen; i++) {
			comment = 1;
				     const char *key, const char *value,
	}
	/*
ssize_t git_config_ssize_t(const char *name, const char *value)

			c = tolower(c);
	if (!strcmp(var, "core.warnambiguousrefs")) {
{
						/*
	opts.respect_includes = 1;
}
	if (buf[i] == ']' && name[j] == 0) {

			    const struct config_options *opts)
		strbuf_addstr(&sb, "\"]\n");
	if (!git_parse_int64(value, &ret))
 * the current_config_kvi as above. During parsing, the current value can be
		uval = val < 0 ? -val : val;
	intmax_t tmp;
	} else if (store->is_keys_section) {
{
			goto out_free;
	}
		if (!icase && strncmp(pattern.buf, text.buf, prefix))
		}
	struct config_source *prev;
			break;
	if (store_key)
		return 1;


			/* We encountered no comment before the section. */
	}

			continue;

		enum config_event_t type = store->parsed[i].type;
	 * based on the including config file.
		return 0;
				/* No BOM at file beginning. Cool. */
	if (!strcmp(var, "include.path"))
}
		FREE_AND_NULL(*store_key);
		return git_config_from_stdin(fn, data);
	return 0;
			if (c == ';' || c == '#') {
				strbuf_reset(&copystr);
int git_configset_get_pathname(struct config_set *cs, const char *key, const char **dest)
			BUG("config_buf can only ungetc the same character");
	}
	return 1;
int git_config_copy_section_in_file(const char *config_filename,
static long config_file_ftell(struct config_source *conf)
	int ret;
				      void *data,
int repo_config_get_bool(struct repository *repo,
	}
static int git_parse_source(config_fn_t fn, void *data,

	if (f) {
 * entry (which all are to be removed).
				   data, NULL);
		die_bad_number(name, value);
	memset(&store, 0, sizeof(store));
		else if (level < 0 || level > Z_BEST_COMPRESSION)
	}
	}
	 * check is about not losing leading or trailing SP and strings that
	if (!strcmp(var, "core.protectntfs")) {
	store->parsed_nr++;
					}
	if (!strcmp(var, "push.default")) {
{
		return 0;
		strbuf_addstr(&buf, path);
				 * Swallow preceding white-space on the same
	ALLOC_GROW(store->parsed, store->parsed_nr + 1, store->parsed_alloc);
	if (!strcmp(var, "core.editor"))
	free(xdg_config);
		error_return = error("%s", error_msg);
	FILE *f;
	config_store_data_clear(&store);
{
			case 'n':
		default:
 * If value==NULL, unset in (remove from) config,
	/* Add other config variables here and to Documentation/config.txt. */


 */
	/*
				; /* do_nothing */
	if (starts_with(var, "branch."))
	char *expiry_string;
	e2 = container_of(entry_or_key, const struct config_set_element, ent);
{
	while (c == ' ' || c == '\t')
			if (get_base_var(var) < 0 || var->len < 1)
		return 0;

void read_early_config(config_fn_t cb, void *data)
	 * Note that problematic characters are always backslash-quoted; this
	case CONFIG_ERROR_ERROR:
		error_msg = xstrfmt(_("bad config line %d in command line %s"),
	/*
	/* This needs a better name */
 * The "cf" variable will be non-NULL only when we are actually parsing a real
		type = current_config_kvi->origin_type;

		break;
int repo_config_get_int(struct repository *repo,
}
	}
	if (!git_config_set_multivar_in_file_gently(config_filename, key, value,
		return git_default_advice_config(var, value);
		slash = find_last_dir_sep(path.buf);
const struct string_list *repo_config_get_value_multi(struct repository *repo,
	default:
		return git_config_pathname(&git_attributes_file, var, value);
		return 0;
		else if (!strcmp(value, "local"))
{
			if (offset > 0) {
	ret = git_configset_get_string_const(repo->config, key, dest);
}
			return 0;

/*
		 * perform literal matching on the prefix part so that
	struct config_options opts = { 0 };
			     const struct config_store_data *store)
	if (!git_parse_signed(value, &tmp, maximum_signed_value_of_type(ssize_t)))
{
{


			break;
		trust_ctime = git_config_bool(var, value);
	hashmap_for_each_entry(&cs->config_hash, &iter, entry,
	else if (config_source && config_source->file)
						      &store, &opts)) {
					  contents_sz - copy_begin) < 0)

{
		kv_info->linenr = cf->linenr;
int git_parse_ulong(const char *value, unsigned long *ret)

	value = NULL;
 * at the variables, it's either a bug for it to be called in the first place,
		int level = git_config_int(var, value);
				bomptr++;
static int config_set_callback(const char *key, const char *value, void *cb)

}

}
		int eol_rndtrp_die;
				ret = CONFIG_INVALID_PATTERN;
int git_config_expiry_date(timestamp_t *timestamp, const char *var, const char *value)

			BUG("how is this possible?");
 * The "current_config_kvi" variable will be non-NULL only when we are feeding
{
	}
				bomptr = NULL;
	struct key_value_info *kv_info;
	else if (cf)
				return;
		check_roundtrip_encoding = xstrdup(value);
	/*
		return 0;
	int baselen;
int git_configset_get_maybe_bool(struct config_set *cs, const char *key, int *dest)
	int eof;
	 * there are no enclosed or surrounding comments. Remove the entire,
			if (do_event(CONFIG_EVENT_COMMENT, &event_data) < 0)
				if (do_event(CONFIG_EVENT_EOF, &event_data) < 0)

		if (!cf || !cf->path)
	current_parsing_scope = prev_parsing_scope;
	current_parsing_scope = CONFIG_SCOPE_LOCAL;
			if (!store.section_seen) {
	 * regular lookup sequence.
{
	if (!git_config_get_bool_or_int("index.threads", &is_bool, &val)) {
	if (!(cf && cf->name))
	if (!strcmp(var, "core.checkstat")) {
	free(normalized_key);
		va_start(params, err);
			    !cf ? "<unknown>" :
	struct strbuf copystr = STRBUF_INIT;
{
				    void *data)
	return -1;

	cf->linenr--;
			}
		die_bad_number(name, value);
 *
{
	}
	if (!strcmp(var, "mailmap.file"))
		return 1;
	case CONFIG_ORIGIN_STDIN:
		die(_("unable to parse command-line config"));

				store.seen[0] = store.parsed_nr
		if (type == CONFIG_EVENT_COMMENT)
 *             lowercase section and variable name
				continue;
			  const struct config_store_data *store)
		git_configset_clear(repo->config);
				      const char *old_name, const char *new_name)
			if (copy_end > 0 && contents[copy_end-1] != '\n')

	return ret;
	uintmax_t tmp;
		    factor * val > max) {
{
			}
		free(store.key);
	out_fd = hold_lock_file_for_update(&lock, config_filename, 0);

	return git_configset_get_string_const(cs, key, (const char **)dest);
int git_config_get_value(const char *key, const char **value)
		return 1;
}
	 * If we have a specific filename, use it. Otherwise, follow the
	}
/* Functions use to read configuration from a repository */
				int *is_bool, int *dest)

			goto error_incomplete_line;
	if (out_fd < 0) {
		system_wide = system_path(ETC_GITCONFIG);
	}
						copy_end--;
	int64_t ret;
		ret = error(_("bogus format in %s"), CONFIG_DATA_ENVIRONMENT);
}
		ret = error_errno(_("chmod on %s failed"),
	const char *dot;
			*dest = val ? 0 : 1;
				if (!quiet)
#undef config_error_nonbool
		int c = get_next_char();


		if (!factor) {
		else if (!strcmp(value, "matching"))
	 * At EOF, the parser always "inserts" an extra '\n', therefore

	 */

	e1 = container_of(eptr, const struct config_set_element, ent);
}
{
		return 0;

		if (write_in_full(out_fd, output, length) < 0) {
	case CONFIG_SCOPE_WORKTREE:
	 * anything goes, so we can stop checking.
			/* fallthrough */
				ent /* member name */) {
				       "conditionals must come from files"));

		if (icase && strncasecmp(pattern.buf, text.buf, prefix))
	const char *git_dir;
	switch (cf->origin_type) {
	    || !strcasecmp(value, "on"))

 *     else all matching key/values (regardless how many) are removed,
	if (ret >= 0)
		/* DOS like systems */

{

	if (pat->buf[0] == '.' && is_dir_sep(pat->buf[1])) {
		if (write_in_full(out_fd, copystr.buf, copystr.len) < 0) {
			strbuf_addstr(&sb, "\\t");
 * extend begin/end to remove the entire section.
	}
			errno = EINVAL;
		else if (!strcmp(value, "remote"))
	}
		return "command";
	struct config_set *cs = cb;
}
	return ungetc(c, conf->u.file);
			autorebase = AUTOREBASE_REMOTE;
		if (!zlib_compression_seen)

 * - it locks the config file by creating ".git/config.lock"
		 * immediately.
int lookup_config(const char **mapping, int nr_mapping, const char *var)
	struct strbuf value;
	top.u.file = f;
			goto out_free_ret_1;
	errno = EINVAL;
			is_section = 1;
}
				value_regex++;
					break;
		return git_config_pathname(&git_mailmap_file, var, value);
	return repo_config_get_bool(the_repository, key, dest);
		goto out;
{
	case CONFIG_SCOPE_SUBMODULE:
			return -1;
	configset_iter(repo->config, fn, data);
	return ret;
	int cond_len;
	else
static uintmax_t get_unit_factor(const char *end)
		if (matches(key, value, store)) {
	if (conf->u.buf.pos < conf->u.buf.len)
				      cf->linenr, cf->name);
	if (!strcmp(var, "core.disambiguate"))
	 */
static void repo_config_clear(struct repository *repo)
 * can be accessed by parsing callbacks.
{
		if (level == -1)
	const char *bad_numeric = N_("bad numeric config value '%s' for '%s': %s");
				 */
		return 0;


#include "config.h"
	if (val) {

	free(repo_config);
static int git_default_branch_config(const char *var, const char *value)
		struct stat st;
			error_errno(_("chmod on %s failed"), get_lock_file_path(&lock));
					return -1;
	return 0;
		if (c == '#' || c == ';') {

}
	timestamp_t when;
#include "strbuf.h"
	} else {
		    value, name, cf->name, _(error_type));
	if (git_config_parse_key(pair[0]->buf, &canonical_name, NULL)) {
{
	case CONFIG_SCOPE_COMMAND:
	struct lock_file lock = LOCK_INIT;
		return v;
int git_config_color(char *dest, const char *var, const char *value)

int git_config_set_in_file_gently(const char *config_filename,
			   const char *key, char **dest)

			level = Z_DEFAULT_COMPRESSION;
		if (value == NULL) {
#include "dir.h"

	if (new_name && !section_name_is_ok(new_name)) {
	return 0;
	free(store->seen);
	 * configuration parser.
	strbuf_init(&top->var, 1024);
	if (!strcmp(var, "core.logallrefupdates")) {
			const char *buf;
		return 0;
				new_line = 1;
		packed_git_window_size /= pgsz_x2;
}
	return git_config_copy_or_rename_section_in_file(config_filename,
	/*
			strbuf_addch(&sb, value[i]);
			     value, var);
			push_default = PUSH_DEFAULT_CURRENT;
	 * are already normalized. So simply add them without any further munging.
	int already_tried_absolute = 0;

{
		}
	int ret;
						  opts->system_gently ?
	if (!strcasecmp(value, "true")
		return include_by_gitdir(opts, cond, cond_len, 0);


	return git_config_int(name, value);

}
{

		memset(&opts, 0, sizeof(opts));
	return 0;
	cs->list.items = NULL;
	do {
		if (chmod(get_lock_file_path(&lock), st.st_mode & 07777) < 0) {
						output[0] = '\t';
		if (buf[i] == '\\' && dot)
	 */
}


		else
	if (!path)
		}
		else if (value && !strcasecmp(value, "native"))
int git_config_copy_section(const char *old_name, const char *new_name)

			error(_("key does not contain a section: %s"), key);
	}
			if (!section_seen)

			return 0;
	struct strbuf sb = STRBUF_INIT;
{
		if (subsection) {

		}
}
		BUG("git_dir without commondir");
	if (git_config_get_pathname("core.fsmonitor", &core_fsmonitor))
		    value, name, cf->name, _(error_type));
		return 0;
 * Find all the stuff for git_config_set() below.
			      void *data)
	cs->list.alloc = 0;
	}
	return -1;
{
			goto done;
		return 0;
		if (text.len < prefix)
			return -1;
	 */
			/* Reject unknown escape sequences */
	if (!git_configset_get_value(cs, key, &value))
				    const char *name,
	}
		return git_config_from_file(fn, config_source->file, data);
				break;
			const struct config_options *opts)
		 */
 */

	repo_config_clear(the_repository);
		return "submodule";
out_no_rollback:
	cs->list.alloc = 0;
}
		return git_config_string(&editor_program, var, value);
		current_parsing_scope = config_source->scope;
				  get_lock_file_path(&lock));
	if (value && *value) {
		trust_executable_bit = git_config_bool(var, value);
{
	/* Does it start with "section." ? */
	top.path = NULL;
}
	else if (skip_prefix_mem(cond, cond_len, "gitdir/i:", &cond, &cond_len))
	const struct string_list *values = NULL;
			quote = 1-quote;
}
				while (copy_end > 0 ) {
			git_die_config_linenr(entry->key,
	 */

	}
			size_t pos;
{
	if (starts_with(var, "i18n."))
{
	char *repo_config;
{
{
	return git_config_parse_key_1(key, store_key, baselen, 0);
			autorebase = AUTOREBASE_LOCAL;
		int is_keys_section;
	 * it, too.
	/*
{
			return 0;
		is_bare_repository_cfg = git_config_bool(var, value);
	enum config_error_action default_error_action;
 *
		return;
	 * Before a dot, we must be alphanumeric or dash. After the first dot,

	strbuf_addch(name, '.');
static void add_trailing_starstar_for_dir(struct strbuf *pat)

{
	}
}
 * Omit any repo-local, worktree-local, or command-line settings.

	 * possible to query information on the includes themselves.
	 * If .git/config does not exist yet, write a minimal version.

error_incomplete_line:
	}
{
	    starts_with(var, "author.") ||
 * found in this variable. It's not part of "cf" because it transcends a single
		path = buf.buf;
static int git_default_push_config(const char *var, const char *value)
		char *output = buf;
			if (store->parsed[i].is_keys_section)
		}
static void die_bad_number(const char *name, const char *value)

	if (!store->value_regex)
				/* include '\n' when copying section header */
		inc->depth--;
		else if (value[0] && !value[1]) {
	for (i = 0; i < nr_mapping; i++) {
	if (!opts->ignore_worktree && repository_format_worktree_config) {
	return git_config_from_file(config_set_callback, filename, cs);
int git_config_bool_or_int(const char *name, const char *value, int *is_bool)
		fclose(config_file);
		value = pair[1] ? pair[1]->buf : "";
			baselen = var->len;
		return git_default_i18n_config(var, value);
			const char *name, const char *buf, size_t len,
 */
			return error(_("core.commentChar should only be one character"));
			return error(_("relative config include "
int git_config_parse_key(const char *key, char **store_key, int *baselen)
				      cf->linenr, cf->name);

		}
	int ret = 0;
	strbuf_release(&text);
	if (get_next_char() != ']')
	int ret;
		contents = xmmap_gently(NULL, contents_sz, PROT_READ,
			ALLOC_GROW(store->seen, store->seen_nr + 1,
	unsigned long size;

	}
			 * multiple [branch "$name"] sections.
	strbuf_realpath(&text, git_dir, 1);
		strbuf_addch(name, tolower(c));
		return error(_("unable to load config blob object '%s'"), name);
			push_default = PUSH_DEFAULT_MATCHING;
	for (;;) {
	if (user_config && !access_or_die(user_config, R_OK, ACCESS_EACCES_OK))
		BUG("current_config_name called outside config callback");
		 * which'll do the right thing
}
					MAP_PRIVATE, in_fd, 0);
				/* Do not tolerate partial BOM. */
	return 0;
}
		}
	ret = fn(name->buf, value, data);
		 * Do not increment matches yet: this may not be a match, but we
{
	/* For the parser event callback */
		die(_("bad numeric config value '%s' for '%s' in blob %s: %s"),
}
		if (fn(entry->key, values->items[value_index].string, data) < 0)
		}
	top.origin_type = origin_type;
		return 0;
}
{
			level = Z_DEFAULT_COMPRESSION;
	return conf->u.buf.pos;
	f = fopen_or_warn(filename, "r");
	enum config_origin_type origin_type;
	const char *value;
{
			store->seen[store->seen_nr] = store->parsed_nr;
 */
				if (new_name == NULL) {
	switch (cf->origin_type) {
			  const struct config_options *opts)
out:
				}
		values = &entry->value_list;
	*dest = expand_user_path(value, 0);
				error(_("invalid pattern: %s"), value_regex);

				; /* do nothing */
	const char *name;
			check_stat = 1;

}
		}
	ret = write_in_full(fd, sb.buf, sb.len);
	}
#include "branch.h"
	git_config_check_init(repo);
}
	if (!opts->ignore_cmdline && git_config_from_parameters(fn, data) < 0)
	char *expanded;
{
	ret = do_config_from(&top, fn, data, opts);
		if (0 <= val && val <= 100)
		strbuf_reset(pat);
				if (!value)
	}
	int (*do_ungetc)(int c, struct config_source *conf);
		has_symlinks = git_config_bool(var, value);
			cmpfn = strncmp;

	if (!strcmp(var, "core.quotepath")) {
		    value, name, _(error_type));
{
				space++;
	return ret;
		ret = -1;

 *           section + subsection part, can be NULL
					   const char *value_regex,
			 WM_PATHNAME | (icase ? WM_CASEFOLD : 0));
		if (errno == ERANGE)
		 * use_gettext_poison(). This is why marked up
		return error(_("reference '%s' does not point to a blob"), name);

		if (isspace(c))
	const char *value;
			 * coping and begin anew. There might be
		return "unknown";
 *
#include "repository.h"
	}
		return error(_("unable to resolve config blob '%s'"), name);

		if (type == CONFIG_EVENT_SECTION) {
static int do_event(enum config_event_t type, struct parse_event_data *data)
	return git_configset_get_bool(repo->config, key, dest);

}
	opts.respect_includes = 1;
		if (cf->var.len < 2 || cf->var.buf[cf->var.len - 1] != '.')
		regfree(store->value_regex);
			c = get_next_char();
		return git_config_string(&git_mailmap_blob, var, value);
	return ret;
 * Similar to the variables above, this gives access to the "scope" of the
}

	if (value && *value) {

static int do_config_from_file(config_fn_t fn,
		 * statements that are entered only when no error is
		error_msg = xstrfmt(_("bad config line %d in standard input"),
		store->section_seen = 1;
int git_config_get_max_percent_split_change(void)
	if (0 <= v) {
						output -= 1;
	if (!parse_config_key(var, "includeif", &cond, &cond_len, &key) &&
				break;
	const char *value;
	if (!pair[0]->len) {
			for (i++; isspace(buf[i]); i++)

#include "color.h"
		pager_use_color = git_config_bool(var,value);
{
int repo_config_get_value(struct repository *repo,
		/* write the rest of the config */
		}
			packed_git_window_size = 1;

	const char *last_dot = strrchr(key, '.');
					goto write_err_out;
					 * section's length
	if (!strcmp(var, "core.safecrlf")) {
			return -1;
	if (buf[i] != '[')
	return 0;
		else
	return 4;
	top.u.buf.len = len;
	int quote = 0, comment = 0, space = 0;
			size_t len;
	expanded = expand_user_path(pat->buf, 1);

	if (!strcmp(var, "core.prefersymlinkrefs")) {
	if (!strcmp(var, "branch.autosetuprebase")) {
	int ret;
				goto error_incomplete_line;
		break;
		if (!iskeychar(c))
	if (!cf)

			break;

	e = configset_find_element(cs, key);
}
	const char **argv = NULL;
int git_config_from_parameters(config_fn_t fn, void *data)
	int i, value_index;

#include "string-list.h"
					goto out;
			if (copy_end > copy_begin) {
		if (contents == MAP_FAILED) {
		string_list_clear(&entry->value_list, 1);

 * get a boolean value (i.e. "[my] var" means "true").
				     const char *cond, size_t cond_len)

	int val = -1;

	 * call).
		contents_sz = xsize_t(st.st_size);
		protect_ntfs = git_config_bool(var, value);
	if (config_file)
commit_and_out:
	case CONFIG_ORIGIN_BLOB:

		if (comment)

}
		if (comment)

			copy_begin = replace_end;

	*is_bool = 0;
			if (do_event(CONFIG_EVENT_WHITESPACE, &event_data) < 0)

			if (!store.key_seen) {
				errno = EISDIR;
 * Copyright (C) Johannes Schindelin, 2005
	/* Add other config variables here and to Documentation/config.txt. */

	struct config_include_data *inc = data;
	struct strbuf sb = store_create_section(key, store);
					if (write_section(out_fd, new_name, &store) < 0) {
	const char *value;
		if (approxidate(*output) >= now)
}
#include "quote.h"
		if (fstat(in_fd, &st) == -1) {
		 * strbuf_add_absolute_path() version of the path,
		store.parsed[0].end = 0;
	cs->hash_initialized = 0;
		const char *name = mapping[i];
	}
{
{
		 */
static int section_name_is_ok(const char *name)
	if (fstat(fileno(config_file), &st) == -1) {
	add_trailing_starstar_for_dir(pat);
int git_config_get_split_index(void)
	ret = 0;
static int prepare_include_condition_pattern(struct strbuf *pat)
			      const char *name,
int git_default_config(const char *var, const char *value, void *cb)
			if (errno == ENODEV && S_ISDIR(st.st_mode))
	if (!last_dot[1]) {


			*dest = val;
int git_env_bool(const char *k, int def)
	if (!strcmp(var, "core.packedgitwindowsize")) {
		return -1;
		return 1;
			break;
	struct strbuf path = STRBUF_INIT;
		int c;
	opts.git_dir = repo->gitdir;

	strbuf_release(&sb);
		BUG("unknown config origin type");
{

		}
				FREE_AND_NULL(store.value_regex);
			strbuf_addch(&sb, key[i]);
	for (;;) {
out:
	struct parse_event_data event_data = {
}
		     const char **key)
	cf = &source;
		case '\\':
static int git_config_from_stdin(config_fn_t fn, void *data)

			}
		return 0;
	}
	return !!git_config_bool_or_int(name, value, &discard);
{

	struct config_options opts = { 0 };

		die(_("bad numeric config value '%s' for '%s' in %s: %s"),
}
			int j = store.seen[i];
	}
		/*
int git_parse_ssize_t(const char *value, ssize_t *ret)
		return 1024;
		} else if (c == '\n') {
		return git_config_string(&git_log_output_encoding, var, value);
		char *end;
}
		strbuf_insertstr(pat, 0, "**/");
}
			return config_error_nonbool(var);
		/* if nothing to unset, error out */
		if (unsigned_mult_overflows(factor, val) ||
	funlockfile(f);
	free(store->parsed);
			if (quote) {
{
			if (!quiet)

				cf->linenr--;
int git_configset_add_file(struct config_set *cs, const char *filename)
	 * Since "key" actually contains the section name and the real
	/* parse-key returns negative; flip the sign to feed exit(3) */
		case '\t':
			    i == store->seen[seen])
};
					REG_EXTENDED)) {
{
	int i;

int git_configset_get_bool_or_int(struct config_set *cs, const char *key,
	int ret = git_config_get_string_const(key, output);
	top.default_error_action = CONFIG_ERROR_DIE;
		break;

	 * Pass along all values, including "include" directives; this makes it
{
		else if (value_regex == CONFIG_REGEX_NONE)
		 * non-fatal potential errors are guarded by "if"
		}
static ssize_t write_section(int fd, const char *key,
	if (store->key_seen) {
	if (!repo->config)
	FILE *config_file = NULL;
					 old_name, new_name, 1);

}
 */
		return 0;
	char *value;
static int git_config_from_blob_ref(config_fn_t fn,
	for (i = 0; i < list->nr; i++) {
}
			continue;
	 */
		return 0;

{
			return i;
		if (level == -1)
	if (!filename)
	}
						  copy_end - copy_begin) < 0)
}
		strbuf_addstr(pat, expanded);

				continue;

	return c;
}
		*is_bool = 1;
	 * the line we just parsed during the call to fn to get
	struct config_store_data *store = cb;
		factor = get_unit_factor(end);
	if (ret < 0)
			log_all_ref_updates = LOG_REFS_NONE;
	char *normalized_key;
		return error(_("'%s' for '%s' is not a valid timestamp"),

	}
		strbuf_addf(&sb, "[%.*s \"", (int)(dot - key), key);
	trace2_cmd_set_config(key, value);
	}

		}
const char *current_config_name(void)
	else if(cf)
}
}
	}
	int fd = -1, in_fd = -1;


		ret += git_config_from_file(fn, xdg_config, data);
			case 't':
	if (dot == var) {
void git_config_push_parameter(const char *text)
	if (!value)
		prefix = slash - path.buf + 1 /* slash */;

		*dest = git_config_ulong(key, value);
		BUG("current_config_origin_type called outside config callback");
{
		die(_("bad numeric config value '%s' for '%s' in submodule-blob %s: %s"),
	else
		    key, filename, linenr);

	if (c != '"')
		 */
		return 0;
		/* no config file means nothing to rename, no error */

	}
		repo_config = NULL;
		return set_disambiguate_hint_config(var, value);
					char c = contents[copy_end - 1];
static int section_name_match (const char *buf, const char *name)
			break;
		va_end(params);
{
		c = get_next_char();
			return -1;
	}
	return ret;
	else

			 * if present. Sane editors won't put this in on their
	return 0;
		die(_("unknown error occurred while reading the configuration files"));
		return 0;
		else {
}
			cmpfn = strncasecmp;
			if (!store.seen_alloc) {
	}


		quote = "\"";

 */
	git_config_check_init(repo);
		if (!strcasecmp(value, "default"))
static int config_set_element_cmp(const void *unused_cmp_data,


static int handle_path_include(const char *path, struct config_include_data *inc)
	/*
{
	struct strbuf text = STRBUF_INIT;
				if (new_line &&
	cf = top->prev;
	if (!strcmp(var, "core.packedgitlimit")) {
	data->previous_offset = offset;
	char *error_msg = NULL;
	if (!expanded)


	struct {
		errno = 0;
	if (store->value_regex == CONFIG_REGEX_NONE)
		return config_error_nonbool(var);

	if (core_fsmonitor)
		return 0;

		error_msg = xstrfmt(_("bad config line %d in file %s"),
				  data, NULL);
		already_tried_absolute = 1;
}
			auto_crlf = AUTO_CRLF_INPUT;
struct parse_event_data {
		unsigned char c = key[i];
	if (expanded) {
	if (i && value[i - 1] == ' ')

	store->parsed[store->parsed_nr].begin = begin;
static int git_default_mailmap_config(const char *var, const char *value)
		prefer_symlink_refs = git_config_bool(var, value);
}
	if (!strcasecmp(value, "false")
		strbuf_setlen(var, baselen);
						break;
{
	if (copystr.len > 0) {
 * baselen - pointer to int which will hold the length of the
}

int git_config_string(const char **dest, const char *var, const char *value)
		c = cf->do_fgetc(cf);
				continue;

{

	if (!git_parse_signed(value, &tmp, maximum_signed_value_of_type(int)))
	 */
		if (cf->eof)
			strbuf_addch(&cf->value, c);
			goto out_free;
	/*
		}
	} else {
		opts.commondir = commondir.buf;
		return 0;
		 */
 *
static struct config_set_element *configset_find_element(struct config_set *cs, const char *key)
	    data->opts->event_fn(data->previous_type, data->previous_offset,
{
	*seen_ptr = seen;

 * Call this to report error for your variable that should not
	return 0;
			continue;
	return 1;
					error(_("invalid key: %s"), key);
		return "global";
	int (*do_fgetc)(struct config_source *c);
			     const char *cond, size_t cond_len, int icase)
	if (ret < 0)

	 */
	path = expanded;
	 * section.

{
			    cf->name ? cf->name :
	struct string_list_item *si;

	if (!strcmp(var, "core.protecthfs")) {

	struct config_store_data *store = data;
			error(_("malformed value for %s: %s"), var, value);
}
	struct config_source source;
	if (!strcmp(var, "pager.color") || !strcmp(var, "color.pager")) {
	top.default_error_action = CONFIG_ERROR_ERROR;
	return -1;
	ret = git_configset_get_pathname(repo->config, key, dest);

	return e ? &e->value_list : NULL;
	if (have_git_dir()) {

		if (c == '\n') {
	ret = !wildmatch(pattern.buf, shortname, WM_PATHNAME);
			continue;
		return 0;
		error_msg = xstrfmt(_("bad config line %d in %s"),
		close(in_fd);
		vreportf("error: ", err, params);
			autorebase = AUTOREBASE_ALWAYS;
 * no comments surrounding (or included in) the section, we will want to
}
	/*
		if (value && !strcasecmp(value, "input")) {
			store.value_regex = CONFIG_REGEX_NONE;
		if ((store.seen_nr == 0 && value == NULL) ||
{
}
		*ret = val;
	if (!config_filename)
"exceeded maximum include depth (%d) while including\n"
{
int git_config_get_pathname(const char *key, const char **dest)
{
			} else {
static struct config_source *cf;
	return git_configset_get_int(repo->config, key, dest);
	return ret;
{
 * This function does this:



 */
		return git_config_from_blob_ref(fn, config_source->blob, data);
}
	/* Get the full name */

int parse_config_key(const char *var,
	if (config_with_options(config_set_callback, repo->config, NULL, &opts) < 0)
	if (!strcmp(var, "core.createobject")) {
		 */
	}
			}
	if (!strcmp(var, "branch.autosetupmerge")) {
static int git_config_copy_or_rename_section_in_file(const char *config_filename,
		goto done;
 *

	long (*do_ftell)(struct config_source *c);
		if (!is_section && copystr.len > 0) {
	case CONFIG_ORIGIN_STDIN:


{
{

	if (starts_with(var, "core."))


 * Returns 0 on success, -1 when there is an invalid character in the key and
		global_conv_flags_eol = eol_rndtrp_die ?
		pack_size_limit_cfg = git_config_ulong(var, value);
		 * Truncate the var name back to the section header
	if (!strcmp(var, "i18n.commitencoding"))
again:
 * These variables record the "current" config source, which
	}
	case CONFIG_ORIGIN_CMDLINE:
				return -1;

		if (!value)
	 * Follows "last one wins" semantic, i.e., if there are multiple matches for the
	}
	return git_config_set_multivar_in_file_gently(config_filename, key, value, NULL, 0);
			core_eol = EOL_NATIVE;
static int configset_add_value(struct config_set *cs, const char *key, const char *value)

		/*
{
{


		opts->error_action :
	return ret;
}
	} u;
					copystr = store_create_section(new_name, &store);
	strbuf_release(&pattern);
		return conf->u.buf.buf[conf->u.buf.pos++];
}
	if (i < store->parsed_nr)
		return 1;
		else {
}



	return repo_config_get_value(the_repository, key, value);
			}
					ret = write_error(get_lock_file_path(&lock));
{
int git_config_get_string(const char *key, char **dest)
		strbuf_addch(name, tolower(c));
	int ret;
int git_config_get_ulong(const char *key, unsigned long *dest)
			int offset;
			if (c == '\n')
int git_parse_maybe_bool(const char *value)
		return git_default_push_config(var, value);
	return repo_config_get_bool_or_int(the_repository, key, is_bool, dest);

			return cf->value.buf;
	}
				return NULL;
		if (!value)
				ret++;
		core_apply_sparse_checkout = git_config_bool(var, value);

 */
	ALLOC_GROW(cs->list.items, cs->list.nr + 1, cs->list.alloc);
}



			  const char *key, const char **value)
	if (!strcmp(name, "GIT_TEST_GETTEXT_POISON"))
static int config_buf_fgetc(struct config_source *conf)
		free(store->value_regex);
		*subsection = var + 1;

	}
	int error_return = 0;
{

	const struct config_options *opts;
		inc.fn = fn;
	return ret;
			} else {

void git_config_clear(void)
#include "lockfile.h"
	 * Use an absolute path as-is, but interpret relative paths

 * Copyright (C) Linus Torvalds, 2005
{
	if (v && !git_parse_ulong(v, &val))
	}

		else if (value && !strcasecmp(value, "crlf"))
static int config_file_fgetc(struct config_source *conf)
	}
	const char *cond, *key;
	return val;


		for (; buf[i] && isspace(buf[i]); i++)
void git_die_config_linenr(const char *key, const char *filename, int linenr)
		if (*dest == -1)
		break;
		ret = CONFIG_NO_LOCK;
 */
		return 1;
		die("%s", error_msg);
			store->parsed[store->parsed_nr].is_keys_section =
		}
	if (!data->opts || !data->opts->event_fn)
		else if (!strcasecmp(value, "minimal"))
			if (key[i] == '"' || key[i] == '\\')
	}
		return -1;
int git_config_from_blob_oid(config_fn_t fn,
			return error(_("must be one of nothing, matching, simple, "

{
		return include_by_gitdir(opts, cond, cond_len, 1);
 * Auxiliary function to sanity-check and split the key into the section
out_free_ret_1:
}
		 */
	return ret;

				      const struct config_options *opts)
	size_t previous_offset;
			if (abbrev < minimum_abbrev || abbrev > the_hash_algo->hexsz)
	top.do_fgetc = config_buf_fgetc;
	strbuf_release(&path);
	}
	}
			/* We are at the file beginning; skip UTF8-encoded BOM
					goto write_err_out;
static int git_default_i18n_config(const char *var, const char *value)
	cf->subsection_case_sensitive = 1;


	cs->list.nr = 0;





 * Parse environment variable 'k' as ulong with possibly a unit

		return current_parsing_scope;
	struct strbuf env = STRBUF_INIT;

	return store->do_not_match ^
	return 0;
		if (c == ']')
		 */
				continue;
		return -1;
	return platform_core_config(var, value, cb);
			strbuf_addch(&sb, '\\');
	switch (scope) {
	if (!parse_expiry_date(expiry_string, &when)) {
void git_configset_clear(struct config_set *cs)
		if (type == CONFIG_EVENT_ENTRY) {
	int ret;
	setenv(CONFIG_DATA_ENVIRONMENT, env.buf, 1);
			if (regcomp(store.value_regex, value_regex,

		strbuf_splice(pat, 0, 1, path.buf, slash - path.buf);
	if (ret)
		repo->config = xcalloc(1, sizeof(struct config_set));

		}

			log_all_ref_updates = LOG_REFS_ALWAYS;
		strbuf_addch(name, c);
static int git_parse_unsigned(const char *value, uintmax_t *ret, uintmax_t max)
{
	current_parsing_scope = CONFIG_SCOPE_SYSTEM;
	const char *v = getenv(k);
			ret = write_error(get_lock_file_path(&lock));
	opts.commondir = repo->commondir;

	while (fgets(buf, sizeof(buf), config_file)) {
	enum config_scope prev_parsing_scope = current_parsing_scope;
	return repo_config_get_pathname(the_repository, key, dest);
		return git_ident_config(var, value, cb);
			goto done;
/*
	current_parsing_scope = CONFIG_SCOPE_WORKTREE;


	sq_quote_buf(&env, text);
{
	const char *dot;
	union {
static struct strbuf store_create_section(const char *key,
		if (buf[i] != name[j++])
		FILE *file;

				/* This is not the section's first entry. */
		if (c == '\n')
{
		return "worktree";


		ret = warn_on_fopen_errors(config_filename);
void git_config_set(const char *key, const char *value)
		const char *name, const char *path, FILE *f,
	case CONFIG_ERROR_DIE:
	case CONFIG_SCOPE_GLOBAL:
 * Returns 0 on success.
}
	if (pat->len && is_dir_sep(pat->buf[pat->len - 1]))
		 *
					return -1;
		CONFIG_EVENT_EOF, 0, opts
	if (contents)
	memset(&store, 0, sizeof(store));
			int abbrev = git_config_int(var, value);
}
{
{
	git_config_set_multivar_in_file(NULL, key, value, value_regex,
		goto out_free;
	if (!(config_file = fopen(config_filename, "rb"))) {
		/*
			 const char *key, int *dest)
out_free:
}


	 * now-empty section.
	}

{
		return 0;
			ret = write_error(get_lock_file_path(&lock));
	strbuf_release(&env);
	} else if (!is_absolute_path(pat->buf))
}
}
	 * We already consumed the \n, but we need linenr to point to
	}
		return 0;
	if (c != '\n') {

		}
			if (cf->value.len)
	}
			/* write the first part of the config */
		if (!quiet)

		}
	if (starts_with(var, "user.") ||
			case 'b':
			for (i++; isspace(buf[i]); i++)
		if (!strcasecmp(value, "auto"))
}
		opts.event_fn_data = &store;
		return 1;
 * - it then parses the config using store_aux() as validator to find
			(*store_key)[i] = c;
	struct config_set_element *found_entry;
	si = string_list_append_nodup(&e->value_list, xstrdup_or_null(value));
	strbuf_addf(&sb, "\t%.*s = %s",

			/*
		}
			return 0;
	store->parsed[store->parsed_nr].type = type;
static char *parse_value(void)
			if (cf->eof) {
		NULL : resolve_ref_unsafe("HEAD", 0, NULL, &flags);
		}
			       const char *key, int *dest)


		factor = get_unit_factor(end);
				strbuf_addch(&sb, '\\');
	}
	int do_not_match;
{
		core_fsmonitor = getenv("GIT_TEST_FSMONITOR");
	case CONFIG_ORIGIN_BLOB:
	if (conf->u.buf.pos > 0) {
					 */
	const char *bomptr = utf8_bom;
	return git_config_set_multivar_in_file_gently(NULL, key, value, value_regex,
		protect_hfs = git_config_bool(var, value);
			return;
}
{
			if (store->seen_nr == 1 && store->multi_replace == 0) {
	    starts_with(var, "committer."))


	    || !strcasecmp(value, "yes")
done:
	opts.ignore_worktree = 1;
		die(_("bad numeric config value '%s' for '%s' in standard input: %s"),
int git_config_set_multivar_in_file_gently(const char *config_filename,
};
		else if (!strcasecmp(value, "auto"))
	struct strbuf gitdir = STRBUF_INIT;
				if (!copy) {
	const char *refname = !the_repository->gitdir ?
			}
	 * accurate line number in error messages.
	int ret;
}
				  const struct hashmap_entry *entry_or_key,
	 * value in the value list for that key.
int git_config_get_bool_or_int(const char *key, int *is_bool, int *dest)
		if (c != '\n') {
	struct config_source top;
		val *= factor;
	unsigned int parsed_nr, parsed_alloc, *seen, seen_nr, seen_alloc;
 * identifier and variable name.

	char *user_config = expand_user_path("~/.gitconfig", 0);
		value = parse_value();
{
			object_creation_mode = OBJECT_CREATION_USES_HARDLINKS;
		return config_error_nonbool(var);
		return 0;
	ret = git_config_from_mem(fn, CONFIG_ORIGIN_BLOB, name, buf, size,
	config_file = NULL;


		return 0;
		 * possible.
	source.prev = cf;


		core_sparse_checkout_cone = git_config_bool(var, value);
		munmap(contents, contents_sz);
}
{



			return config_error_nonbool(var);


	}
	int ret;
	if (!value)
		 * We match, now just find the right length offset by
{
	ret = inc->fn(var, value, inc->data);
			quote = "\"";
		    length, key + store->baselen + 1, quote);
}
			; /* do nothing */
		return 0;
static int zlib_compression_seen;
	int c = cf->do_fgetc(cf);
}
			const char *key, int *dest)
int repo_config_get_ulong(struct repository *repo,
	if (!env)
			if (write_in_full(fd, contents + copy_begin,
		return 0;
			if (write_pair(fd, key, value, &store) < 0)
			continue;
{
}
	struct strbuf *var = &cf->var;
	return do_config_from_file(fn, CONFIG_ORIGIN_STDIN, "", NULL, stdin,
 *
		if (value && !strcasecmp(value, "lf"))
	for (i = 0; key[i]; i++) {
			case '\\': case '"':
}
		ret = error_errno(_("fstat on %s failed"), config_filename);
		c = get_next_char();
			error(_("invalid config file %s"), config_filename);


		*end_offset = store->parsed[store->parsed_nr - 1].end;

}
				/*
{
		return 0;
	/* Invalidate the config cache */
	for (; *name && *name != '.'; name++)
	top.name = name;
		     const char **subsection, int *subsection_len,
}
		quote = "\"";
				if (write_in_full(fd, contents + copy_begin,
	source.origin_type = CONFIG_ORIGIN_CMDLINE;
	if (commit_lock_file(&lock) < 0)
{
		pack_compression_seen = 1;
		if (conf->u.buf.buf[conf->u.buf.pos] != c)

		goto out;
		cf->eof = 1;
	if (!buf)
		if (store_key)
static int include_by_gitdir(const struct config_options *opts,
		 *
	if (do_event(CONFIG_EVENT_ERROR, &event_data) < 0)
	if (!strcmp(var, "core.usereplacerefs")) {

			goto error_incomplete_line;
	return ret;
			goto done;

}
		return -1;
}
		return git_default_mailmap_config(var, value);
	 * Find the key; we don't know yet if we have a subsection, but we must
		return 0;

		return 1;
		ret = handle_path_include(value, inc);

			c = get_next_char();

		}
}
	if (!strcmp(var, "core.attributesfile"))
const char *git_etc_gitconfig(void)
	enum config_event_t previous_type;
		/* write the pair (value == NULL means unset) */

		kv_info->filename = strintern(cf->name);
	else
		ret += git_config_from_file(fn, git_etc_gitconfig(),

			continue;
		config_filename = filename_buf = git_pathdup("config");
	free(argv);
			return error(_("relative config includes must come from files"));
		/*
		if (!value)
		int c = get_next_char();
	opts.ignore_repo = 1;
 *     (only add a new one)
}

	if (!is_absolute_path(path)) {
void git_config_set_multivar(const char *key, const char *value,
		c = '\n';
}
	return error(_("missing value for '%s'"), var);
static int store_aux(const char *key, const char *value, void *cb)


}

			dot = 1;
			goto out_free;
}
	git_config_check_init(repo);
	struct strbuf buf = STRBUF_INIT;
				break;

		if (!access_or_die(path, R_OK, 0))
				      const char *old_name,
					return -1;
	git_config_clear();
	for (;;) {
{
	 * is any repository config we should use (but unlike
	 */
	default:
}
{
		read_replace_refs = git_config_bool(var, value);

"	%s\n"
		if (cf->subsection_case_sensitive)
		 * If we ever encounter a non-fatal error, it means
		char *end;
	if (pair[0]->len && pair[0]->buf[pair[0]->len - 1] == '=') {
	}
 * or it's a function which can be reused for non-config purposes, and should
	struct config_set_element *e = configset_find_element(cs, key);
	if (!values)
		}
	}

	kv_info = values->items[values->nr - 1].util;
	strbuf_add(&pattern, cond, cond_len);
		cf->linenr++;


		enum config_event_t type = store->parsed[i - 1].type;
	struct lock_file lock = LOCK_INIT;
}
				ALLOC_GROW(store.seen, 1, store.seen_alloc);
	l_item->e = e;
	    || !strcasecmp(value, "off"))

			c = '\r';
		struct config_options opts;

		notes_ref_name = xstrdup(value);

	unsigned long ret;
		return 0;
		strbuf_addstr(pat, "**");
		int level = git_config_int(var, value);
	return ret;
			return 0;
		 * existing config file.
static struct key_value_info *current_config_kvi;
	config_with_options(cb, data, NULL, &opts);

static int git_default_core_config(const char *var, const char *value, void *cb)
	}
		if (c == '\n') {
}
	int baselen = 0;
				 * line.
		   const struct config_store_data *store)

	if (!*value)
		if (!isalpha(c))
void git_configset_init(struct config_set *cs)
		 * zero, as most errors are fatal, and
	if (!git_config_get_maybe_bool("core.splitindex", &val))
	case CONFIG_ORIGIN_SUBMODULE_BLOB:
{
		return 0;
}
		if (!value)
	if (c == '\r') {
	memset(store, 0, sizeof(*store));
				     const char *value_regex, int multi_replace)
 * Note: the parameter `seen_ptr` points to the index into the store.seen
	if (git_config_system() && !access_or_die(git_etc_gitconfig(), R_OK,
	if (!strcmp(var, "core.sparsecheckoutcone")) {


	int discard;
						      multi_replace);

			core_eol = EOL_LF;
	if (!strcmp(var, "core.excludesfile"))
	if (!strcmp(var, "core.commentchar")) {

	if (config_source && config_source->use_stdin)
		else
				if (copy_end > 0 && copy_end < contents_sz &&
	top.name = name;
	cf->linenr--;
}

	else if (!strcasecmp(end, "m"))
	cs->list.nr = 0;
		strbuf_add_absolute_path(&text, git_dir);
			 * own, but e.g. Windows Notepad will do it happily. */
			return -1;
	int i;
		die(_("bad numeric config value '%s' for '%s' in file %s: %s"),
	if (!strcmp(var, "core.bare")) {
#include "utf8.h"
int git_config_get_expiry_in_days(const char *key, timestamp_t *expiry, timestamp_t now)
	if (!e) {
		strbuf_reset(&copystr);
	if (chmod(get_lock_file_path(&lock), st.st_mode & 07777) < 0) {
		 * strbuf_realpath() will expand it, so the rule won't

{
			    const char *key, const char *value)


	 * flushed by the usual "flush because we have a new section
	}

		case '"':
{

	}
	if (!skip_prefix(var, section, &var) || *var != '.')
int git_config_from_mem(config_fn_t fn,

	 * queried key in the files of the configset, the value returned will be the last
 * fall back to some sane behavior).
void git_config(config_fn_t fn, void *data)
	static const char *system_wide;

	int linenr;
			ret += git_config_from_file(fn, path, data);
	return -1; /* thing exists but cannot be parsed */
		}
			store->seen[store->seen_nr] = store->parsed_nr;
			if (value_regex[0] == '!') {
		git_branch_track = git_config_bool(var, value);
			ret = -1;
					return -1;
	/*
		/* if nothing to unset, or too many matches, error out */
				      const char *old_name, const char *new_name)
 *
				continue;
	if (last_dot == NULL || last_dot == key) {
	if (get_oid(name, &oid) < 0)
		name = cf->name;

				replace_end = copy_end;
}
static int include_by_branch(const char *cond, size_t cond_len)
		quote_path_fully = git_config_bool(var, value);
					   const char *key, const char *value,
}
			ret = CONFIG_INVALID_FILE;
{
	goto out_free;
		/* for values read from `git_config_from_parameters()` */
 * if multi_replace==0, nothing, or only one matching key/value is replaced,
	struct config_set_element *e;
		 * We've tried e.g. matching gitdir:~/work, but if

		hashmap_entry_init(&e->ent, strhash(key));
	else if (!strcasecmp(end, "g"))

		auto_crlf = git_config_bool(var, value);
	}
		ret = error(_("could not lock config file %s"), config_filename);

		}
		return 1; /* always matches */

		return cf->linenr;


		whitespace_rule_cfg = parse_whitespace_rule(value);
{
	if (prefix < 0)
		if (unsigned_mult_overflows(factor, uval) ||
		}
	if (!git_config_get_int("splitindex.maxpercentchange", &val)) {
	assert(values->nr > 0);

 * array.  * This index may be incremented if a section has more than one
	 * parse backwards from the end, since the subsection may have dots in
		if (c == '"') {
	if (!system_wide)
				warning(_("%s has multiple values"), key);

			if (copystr.len > 0) {
	current_parsing_scope = CONFIG_SCOPE_COMMAND;
		return "local";
			goto out;
	/*
	intmax_t days;
		if (*name != '-' && !isalnum(*name))
				if (bomptr != utf8_bom)
		cf->linenr++;
		*baselen_ = baselen;

	int ret = 0, remove = 0;

	free(buf);
{
		free(expanded);

}
	error(_("failed to write new configuration file %s"), filename);

int git_config_int(const char *name, const char *value)
	 * key name separated by a dot, we have to know where the dot is.
		if (get_value(fn, data, var) < 0)
	return 0;
				store.baselen = strlen(new_name);
	if (current_config_kvi)
{
int git_config_get_bool(const char *key, int *dest)
	struct hashmap_iter iter;
		return git_default_core_config(var, value, cb);
			/* it's a section */
		 * As a side effect, we make sure to transform only a valid
	strbuf_release(&top->var);
static int get_value(config_fn_t fn, void *data, struct strbuf *name)
		return 0;
	if (parse_expiry_date(value, timestamp))
static int git_parse_signed(const char *value, intmax_t *ret, intmax_t max)
		return git_config_pathname(dest, key, value);
		inc.data = data;
	else
int git_config_get_expiry(const char *key, const char **output)
		slash = find_last_dir_sep(cf->path);
	for (i = 0; i < nr; i++) {
		return "system";

static int git_parse_int64(const char *value, int64_t *ret)
	 * Next, make sure that we are removing he last key(s) in the section,
	flockfile(f);
	if (!strcmp(var, "pack.compression")) {
	if (!strcmp(var, "core.loosecompression")) {
			comment = 0;
		}
	else
		for (i = 0; buf[i] && isspace(buf[i]); i++)

	top.u.buf.pos = 0;
int repo_config_get_string_const(struct repository *repo,
		return 1;
	if (!strcmp(var, "core.symlinks")) {

		const char *slash;
/*
	}
	free(user_config);
int git_configset_get_string_const(struct config_set *cs, const char *key, const char **dest)
						 * next line; indent with a
{
}
	}
		if (level == -1)
	if (!strcmp(var, "i18n.logoutputencoding"))
}
	    store->value_regex != CONFIG_REGEX_NONE) {
	    data->previous_type == type)
}

			void *data, const struct config_options *opts)
	return git_config_set_multivar_gently(key, value, NULL, 0);
	kv_info->scope = current_parsing_scope;
	return 0;
	/* push config-file parsing state stack */
	int ret;
	struct configset_list_item *l_item;
{
	}
	return git_configset_get_value_multi(repo->config, key);
}
	top.do_ungetc = config_file_ungetc;
		strbuf_addch(&cf->value, c);
	if (type != OBJ_BLOB) {

			log_all_ref_updates = LOG_REFS_NORMAL;
{
	 * comments before the entry nor before the section header.


	if (!git_parse_unsigned(value, &tmp, maximum_unsigned_value_of_type(long)))
		}
		*expiry = now - days * scale;
int git_config_parse_parameter(const char *text,
	}
			if (do_event(CONFIG_EVENT_SECTION, &event_data) < 0)
	enum object_type type;
				c = '\t';
}
		return 0;
	if (git_config_get_string(key, &expiry_string))
		if (c == '\n')
		char *slash;
	return 0;
	if (!refname || !(flags & REF_ISSYMREF)	||
			return get_extended_base_var(name, c);
		    (store.seen_nr > 1 && multi_replace == 0)) {
		if (cf->eof)
		hashmap_add(&cs->config_hash, &e->ent);
			goto out;

	if (!config_filename)



int git_config_system(void)
	 */
{
			ALLOC_GROW(store->seen, store->seen_nr + 1,
	/*
		N_("out of range") : N_("invalid unit");
}
"	%s\n"
		if (is_bool)
					copy_end++;


	size_t offset;
		die(_("failed to expand user dir in: '%s'"), value);
		error_msg = xstrfmt(_("bad config line %d in submodule-blob %s"),
	return 1;
	top.do_ungetc = config_buf_ungetc;
	if (fd < 0) {
	}
		ret = error(_("invalid section name: %s"), new_name);

	return 0;
	/* Add other config variables here and to Documentation/config.txt. */
	const struct config_set_element *e1, *e2;
	return ret;
			ret = CONFIG_NOTHING_SET;
{
		return git_config_string(&git_commit_encoding, var, value);
{
		*dest = git_config_int(key, value);
	fd = hold_lock_file_for_update(&lock, config_filename, 0);
		break;
		opts.git_dir = get_git_dir();
	char *contents = NULL;
					if (strlen(output) > 0) {
		/*

	const char *quote = "";
}
	return 1;
	dot = strrchr(var, '.');
	else
	if (err) {
	int out_fd;
NORETURN
		if (packed_git_window_size < 1)
	struct config_store_data store;
							     &replace_end, &i);

	struct config_set_element *entry;

	repo_read_config(repo);
		uintmax_t factor;

					 old_name, new_name, 0);
		ALLOC_GROW(store.parsed, 1, store.parsed_alloc);
		packed_git_window_size *= pgsz_x2;
			return error(_("malformed value for %s"), var);
		die(_(bad_numeric), value, name, _(error_type));

 * cached config from a configset into a callback.
"This might be due to circular includes.");
		}
		inc.opts = opts;
	}
		core_fsmonitor = NULL;
		return;
		else if (buf[i] == '"' && dot) {
	if (current_config_kvi)
	/* Did we have a subsection at all? */
NORETURN __attribute__((format(printf, 2, 3)))
			if (c == (*bomptr & 0377)) {
	} else {
			strbuf_addstr(&sb, "\\n");

{
	return 0;
		warn_ambiguous_refs = git_config_bool(var, value);
		i++;

{
int git_config_from_file(config_fn_t fn, const char *filename, void *data)
	*ret = tmp;
		strbuf_list_free(pair);
static void maybe_remove_section(struct config_store_data *store,
			return 0;
int config_error_nonbool(const char *var)
	buf = read_object_file(oid, &type, &size);
			*subsection_len = 0;
						 * a declaration to put on the
	return !git_config_parse_key_1(key, NULL, NULL, 1);
	int nr = 0, alloc = 0;
{
		 * parsed elements, and store.seen will contain a list of
	char *xdg_config = xdg_config_home("config");
 * GIT - The information manager from hell
NORETURN
				  config_filename);
{
	else {
	k.key = normalized_key;
				   const char *value_regex, int multi_replace)
					else
 *
	if (!ret && !already_tried_absolute) {
		else {
	 * Copy a trailing section at the end of the config, won't be
		 * ~/work is a symlink to /mnt/storage/work

		goto again;

	}
	strbuf_trim(pair[0]);
		e->key = xstrdup(key);
		*expiry = when;

	return git_config_copy_or_rename_section_in_file(config_filename,
{
 * if value_regex!=NULL, disregard key/value pairs where value does not match.
		}
	}
				/* Did not see key nor section */

	/* Same error code as "failed to rename". */
	case CONFIG_ORIGIN_CMDLINE:

	return getc_unlocked(conf->u.file);
				store.do_not_match = 0;
	for (;;) {
		*ret = val;
}
	strbuf_add(&pattern, cond, cond_len);
			return -1;
		c = get_next_char();
{
int git_configset_get_ulong(struct config_set *cs, const char *key, unsigned long *dest)
	}
	char *canonical_name;

	return prefix;
	int ret = 0;
	} else

	else
	return git_config_copy_section_in_file(NULL, old_name, new_name);

int git_config_set_multivar_gently(const char *key, const char *value,
						goto out;
		return "blob";
	if (!strcmp(var, "core.fsyncobjectfiles")) {
				comment = 1;
			break;
 *
	} else

		va_list params;
	else
			core_eol = EOL_CRLF;

{
					maybe_remove_section(&store,

		return -1;
			die(_("bad pack compression level %d"), level);

int git_config_include(const char *var, const char *value, void *data)
		if (value && !strcasecmp(value, "always")) {
			return 0;
		 */
		kv_info->origin_type = CONFIG_ORIGIN_CMDLINE;
			return;
	char *envw;
		return 0;
	*key = dot + 1;
	cf = source.prev;
			    (i == baselen + 1 && !isalpha(c))) {

		(value && !regexec(store->value_regex, value, 0, NULL, 0));
		    write_pair(fd, key, value, &store) < 0)
		if (git_config_parse_parameter(argv[i], fn, data) < 0) {
		if (remove)
		core_compression_seen = 1;
static int get_extended_base_var(struct strbuf *name, int c)
	free(error_msg);
	else
}
}
					multi_replace);
	ret = write_in_full(fd, sb.buf, sb.len);


{
		die_bad_number(name, value);
{
				/* We want to remove this entry, too */

		else if (!strcmp(value, "always"))
	if (commit_lock_file(&lock) < 0) {

		*store_key = xmallocz(strlen(key));
 * suffix; if missing, use the default value 'val'.
	if (!git_configset_get_value(cs, key, &value)) {
		return 0;
	if (dot) {
int git_config_key_is_valid(const char *key)
	return found_entry;
	top.do_ftell = config_buf_ftell;
	struct config_store_data store;
			cf->var.len - 1 == store->baselen &&
	if (current_config_kvi)

			!cmpfn(cf->var.buf, store->key, store->baselen);

	int i, dot, baselen;
		conf->u.buf.pos--;
		goto commit_and_out;
}
		core_preload_index = git_config_bool(var, value);
			ret = CONFIG_NO_WRITE;
		if (value && !strcasecmp(value, "warn")) {
	return -1; /* default value */
}
	if (skip_prefix_mem(cond, cond_len, "gitdir:", &cond, &cond_len))
	git_config_check_init(repo);


		return 0;
			autorebase = AUTOREBASE_NEVER;
		}
	} else
		    value, name, cf->name, _(error_type));
		*dest = git_config_bool_or_int(key, value, is_bool);
 *

	unsigned subsection_case_sensitive : 1;
	return repo_config_get_string_const(the_repository, key, dest);
	if (strcmp(*output, "now")) {
			error_errno(_("opening %s"), config_filename);
		else
void git_config_set_in_file(const char *config_filename,
}
}
{
		kv_info->filename = NULL;
	return 0;
	if (!value)
			strbuf_add(&buf, cf->path, slash - cf->path + 1);
	if (prefix > 0) {
	 */
		opts.event_fn = store_aux_event;
 * - the config file is mmap()ed and the part before the match (if any) is
	struct strbuf pattern = STRBUF_INIT;
}
{
		size_t begin, end;
	}
	} while (isspace(c));
						      config_filename,
	for (i = 0; value[i]; i++)
	}
		return !!v;
 * this function.
	free(envw);
};
		return 0;
		if (!factor) {
		ignore_case = git_config_bool(var, value);
int git_config_bool(const char *name, const char *value)
		uintmax_t val;
		return NULL;
static int do_git_config_sequence(const struct config_options *opts,
struct config_source {
			if (name[j++] != '.')
	top->prev = cf;
			     const char *key, const char **dest)
		return 0;
			/* Some characters escape as themselves */
	int flags;
	int val;

			; /* do nothing */
{
	}

		 * config_with_options() normally returns only

static int git_parse_maybe_bool_text(const char *value)


		*dest = git_parse_maybe_bool(value);
					continue;
	}
int repo_config_get_maybe_bool(struct repository *repo,
	 * GIT_DIR, we ask discover_git_directory() to figure out whether there
	config_with_options(cb, data, NULL, &opts);
	case CONFIG_ORIGIN_SUBMODULE_BLOB:
		}
	fclose(config_file);
	case CONFIG_ORIGIN_SUBMODULE_BLOB:
/*
}
	}
		if (c == '"')
enum config_scope current_config_scope(void)
{

	size_t begin;
		strbuf_addch(&env, ' ');
		else if (level < 0 || level > Z_BEST_COMPRESSION)
		}
	if (!strcmp(var, "pack.packsizelimit")) {
		if ( ENOENT != errno ) {
			break;
	int length = strlen(key + store->baselen + 1);
{
		return val;
		return config_error_nonbool("include.path");
			ret = CONFIG_INVALID_FILE;
			continue;
	/*
			} else
		uintmax_t uval;
	 * `key` may come from the user, so normalize it before using it
				      const char *new_name, int copy)
			/* There is a comment before this entry or section */
}
unsigned long git_config_ulong(const char *name, const char *value)
		return error(_("bogus config parameter: %s"), text);
	return repo_config_get_string(the_repository, key, dest);
/*
		int (*cmpfn)(const char *, const char *, size_t);
			if (buf[i] != '"')
	/*
		else
		}
{
{
 * Parse environment variable 'k' as a boolean (in various
	return ret;
		}
	case CONFIG_ERROR_SILENT:
	 * notably, the current working directory is still the same after the
		    value, name, cf->name, _(error_type));
			return config_error_nonbool(var);
}
			goto out;
	if (sq_dequote_to_argv(envw, &argv, &nr, &alloc) < 0) {
		goto out_free;
int git_configset_get_bool(struct config_set *cs, const char *key, int *dest)
		free(canonical_name);
				}
	int comment = 0;
		pack_compression_level = level;
	 * contents of .git/config will be written into it.
		goto out;
					remove = 1;
int config_with_options(config_fn_t fn, void *data,

	hashmap_init(&cs->config_hash, config_set_element_cmp, NULL, 0);
	if (!git_parse_ssize_t(value, &ret))
			/* There is another entry in this section. */
		if (!quiet)
		if (write_section(fd, key, &store) < 0 ||
int git_config_get_fsmonitor(void)
					if (isspace(c) && c != '\n')
	return ret;
		value = NULL;
		/*

	case CONFIG_ORIGIN_BLOB:
			continue;
	found_entry = hashmap_get_entry(&cs->config_hash, &k, ent, NULL);
			break;

{
			return 0;
				break;
	top.origin_type = origin_type;
	return repo_config_get_value_multi(the_repository, key);
	if (!git_configset_get_value(cs, key, &value))
{
	return ret;
		}
	strbuf_addf(&sb, "%s\n", quote);

{
	if (c == EOF) {
		uintmax_t factor;
 *   the position on the key/value pair to replace. If it is to be unset,

{
{
int current_config_line(void)
	return repo_config_get_maybe_bool(the_repository, key, dest);
		return 0;
int git_config_pathname(const char **dest, const char *var, const char *value)
	}
	} else {
int repo_config_get_bool_or_int(struct repository *repo,
			}

{
	struct config_set_element k;
	return 1;


	case CONFIG_ORIGIN_CMDLINE:
	if (!git_parse_signed(value, &tmp, maximum_signed_value_of_type(int64_t)))
	for (;;) {
	return -1; /* default value */
int git_configset_get_value(struct config_set *cs, const char *key, const char **value)
		if (!value)

	return EOF;
int git_config_rename_section_in_file(const char *config_filename,
	if (!opts->ignore_repo && repo_config &&
		ret = CONFIG_NO_WRITE;
}
	}
{
static int matches(const char *key, const char *value,

	free(cs->list.items);
int git_config_rename_section(const char *old_name, const char *new_name)
			 */
}
		return "submodule-blob";
		return;
	struct config_include_data inc = CONFIG_INCLUDE_INIT;
		return 0;
	int v = git_parse_maybe_bool_text(value);
static inline int iskeychar(int c)
 *
	intmax_t tmp;
	/*
		return 0;
			die(_("bad zlib compression level %d"), level);
		name = current_config_kvi->filename;
		}
				copy_end = store.parsed[j].end;
	hashmap_free_entries(&cs->config_hash, struct config_set_element, ent);
	}
int git_config_get_string_const(const char *key, const char **dest)
		return -CONFIG_NO_SECTION_OR_NAME;
{
		/* Leave the extended basename untouched.. */


static void repo_read_config(struct repository *repo)
		return config_error_nonbool(var);
		error_msg = xstrfmt(_("bad config line %d in blob %s"),
						 * More content means there's
	if (!value)
				store.do_not_match = 1;
		     const char *section,
		kv_info->linenr = -1;
			switch (c) {
#include "refs.h"
unsigned long git_env_ulong(const char *k, unsigned long val)
	if (ret < 0)
			struct git_config_source *config_source,

		value_index = list->items[i].value_index;
		strbuf_addch(var, tolower(c));
{
	return ret;
		close(in_fd);
	int c;
	expanded = expand_user_path(path, 0);
{

	if (!cs->hash_initialized)
		if (!iskeychar(c) && c != '.')
		die(_("could not unset '%s'"), key);
						      const char *key)
		intmax_t val;

	return git_config_rename_section_in_file(NULL, old_name, new_name);
	 */
			    "the command line");
				break;
			goto out_free;
	if (!repo->config || !repo->config->hash_initialized)
}
			}
	return ret;
	return ret;

			default_abbrev = abbrev;
	/*
 */
	/*
	git_config_check_init(repo);
			store.seen_nr = 1;

			new_line = 0;
		int pgsz_x2 = getpagesize() * 2;
		size_t copy_begin, copy_end;
		die(bad_numeric, value, name, error_type);
		 * match. Let's match against a


	return do_config_from(&top, fn, data, opts);
	int ret;
}
	/* sq_dequote will write over it */
	}
	 * When setup_git_directory() was not yet asked to discover the
	*begin_offset = begin;
	hashmap_entry_init(&k.ent, strhash(normalized_key));
	git_config_check_init(repo);
			error(_("key does not contain variable name: %s"), key);

	if (!git_configset_get_value(cs, key, &value)) {
int repo_config_get_string(struct repository *repo,
int git_config_get_maybe_bool(const char *key, int *dest)
	}
	for (i = 0; value[i]; i++)
			strbuf_addch(&cf->value, ' ');
static int store_aux_event(enum config_event_t type,
{
	strbuf_reset(&cf->value);
	begin = store->parsed[i].begin;

	}
		munmap(contents, contents_sz);
	/* pop config-file parsing state stack */
{
{
				    contents[copy_end - 1] != '\n' &&
	ssize_t ret;
			ret = CONFIG_INVALID_FILE; /* same as "invalid config file" */
	if (type != CONFIG_EVENT_EOF)
	ssize_t ret;
void read_very_early_config(config_fn_t cb, void *data)
	if (!strcmp(var, "core.notesref")) {
		*end_offset = store->parsed[i].begin;
	if (!strcmp(var, "core.abbrev")) {

}
		return 0;
	}
			size_t replace_end;
		current_config_kvi = values->items[value_index].util;
					 * a newline, now skip the old

			global_conv_flags_eol = CONV_EOL_RNDTRP_WARN;

{
	}

	if (repo->config && repo->config->hash_initialized)
							     &copy_end,
		die(_("bad numeric config value '%s' for '%s' in command line %s: %s"),
 * All source specific fields in the union, die_on_error, name and the callbacks
	values = git_config_get_value_multi(key);
	int v = git_parse_maybe_bool_text(value);
	if (!strcmp(var, "core.filemode")) {

	/*
		if (buf[i] == '[') {
	top->eof = 0;
}
			if (!store->parsed[i - 1].is_keys_section)

	return 0;
	return ret;

	cf = top;
			die(_(include_depth_advice), MAX_INCLUDE_DEPTH, path,
		return 0;
		return "command line";
		if (ret)
	if (color_parse(value, dest) < 0)
			CONV_EOL_RNDTRP_DIE : 0;
}
	if (!access_or_die(path, R_OK, 0)) {

	 */
	}
	strbuf_list_free(pair);
		strbuf_addstr(&env, old);
/*
	if (!git_parse_int(value, &ret))
	if (!strcmp(var, "core.askpass"))
		return git_config_string(dest, key, value);
static int config_file_ungetc(int c, struct config_source *conf)
{
}
		val = strtoumax(value, &end, 0);
		strbuf_addf(&sb, "[%.*s]\n", store->baselen, key);
	if (!strcmp(var, "core.deltabasecachelimit")) {
		 * something went really wrong and we should stop
	}
					   int multi_replace)
		return 1;
"from\n"
		c = get_next_char();
			push_default = PUSH_DEFAULT_UPSTREAM;
	char *expanded;
	/*
		zlib_compression_seen = 1;
		die(_("unable to parse '%s' from command-line config"), key);
/* Functions used historically to read configuration from 'the_repository' */
		contents = NULL;
{
			if (do_event(CONFIG_EVENT_WHITESPACE, &event_data) < 0)
				  config_fn_t fn, void *data)
static int core_compression_seen;
	}
				if (write_in_full(out_fd, copystr.buf, copystr.len) < 0) {
			goto out_free;
		cf->default_error_action) {
{
		return current_config_kvi->linenr;
		die_bad_number(name, value);
	*value = values->items[values->nr - 1].string;
		zlib_compression_level = level;
	seen = *seen_ptr;
	git_config_check_init(repo);
	struct config_set_element *entry;
		data = &inc;
	envw = xstrdup(env);
	struct string_list *values;

	char *key;
	return error_return;
			return;
			*subsection = NULL;
	struct strbuf **pair;
			  const char *key, unsigned long *dest)
		return 0;

		if (c == '[') {
	switch (type) {
		break;
/*
	char *filename_buf = NULL;

}
				c = '\b';
{
 *   it must be found exactly once.
				    contents[copy_end] == '\n')

				       cf->linenr, cf->name);
			break;
		return config_error_nonbool(var);
				  const char *key, const char *value)
		}
			core_eol = EOL_UNSET;
	 * Check to see if the value needs to be surrounded with a dq pair.
	int i;
		return 0;
	cs->list.items = NULL;
			}
{
			dot = 1;
	*ret = tmp;
	strbuf_release(&pattern);
}
	if (c == '\n')
	return 0;
		return 0;
#include "cache.h"
}

/*

	opts.ignore_cmdline = 1;

			errno = ERANGE;
	int i, seen, section_seen = 0;
{
		else if (!strcmp(value, "nothing"))
	case CONFIG_ORIGIN_FILE:
	/* Add other config variables here and to Documentation/config.txt. */


			       config_fn_t fn, void *data)
			errno = ERANGE;
	case CONFIG_ORIGIN_FILE:
				 int *seen_ptr)
	return 0;
	}
		if (c == '\\') {
}
						ret = write_error(get_lock_file_path(&lock));
		return 0;
	default:
	return repo_config_get_int(the_repository, key, dest);
	if ( in_fd < 0 ) {
			default_abbrev = -1;
		}

	size_t contents_sz;
		BUG("config error action unset");
int git_configset_get_int(struct config_set *cs, const char *key, int *dest)
		else if (!strcmp(value, "upstream"))
}
	data->previous_type = type;
}
		if (errno == ERANGE)
	switch (opts && opts->error_action ?
				}
			       "should be between 0 and 100"), val);
	char buf[1024];
			zlib_compression_level = level;
	si->util = kv_info;
	 * The lock serves a purpose in addition to locking: the new
		free(entry->key);
	}


	}
			}
			error_errno(_("fstat on %s failed"), config_filename);
		BUG("configset_add_value has no source");
/* if new_name == NULL, the section is removed instead */
}
}
	opts.respect_includes = 1;
}
	}
		eol_rndtrp_die = git_config_bool(var, value);
			store->key_seen = 1;
	} *parsed;
	if (git_config_parse_key(key, &normalized_key, NULL))
	git_configset_init(repo->config);
	return 0;
	if (!value)
#include "hashmap.h"
		fn = git_config_include;

#include "exec-cmd.h"
		string_list_init(&e->value_list, 1);
	}
		return 0;
	}
		val *= factor;
	struct config_options opts = {0};
					}
	/* U+FEFF Byte Order Mark in UTF8 */
			const enum config_origin_type origin_type,
		enum config_event_t type;
		 * matches, as indices into store.parsed.
		/* This value must be multiple of (pagesize * 2) */

				      cf->linenr);
		else if (!strcmp(value, "current"))
		return 1024 * 1024;
			push_default = PUSH_DEFAULT_NOTHING;
write_err_out:
		}
	opts.system_gently = 1;
}
		}
	*dest = xstrdup(value);
		 * cause an infinite loop with _() needing to call

static ssize_t write_pair(int fd, const char *key, const char *value,
		if (c == '.')
				      cf->linenr, cf->name);
int git_config_get_int(const char *key, int *dest)
	if (opts->commondir)

		offset--;
		return;
		goto out_free;
		return 1;
	int ret = 0;
	}
	return strcmp(e1->key, e2->key);
	strbuf_release(&gitdir);
	const char *value;


	int prefix = 0;
struct config_store_data {
				 const char *key, const char **dest)
		return i;
int git_config_get_index_threads(int *dest)
			}
		if (!slash)

			die(_("bad zlib compression level %d"), level);
	git_config_check_init(repo);
	}
		free(path);
				goto write_err_out;
	git_config_set_multivar_in_file(config_filename, key, value, NULL, 0);
void git_config_set_multivar_in_file(const char *config_filename,

	}
	*ret = tmp;
		break;
				copy_end = store.parsed[j].begin;
{
			break;
		ALLOC_GROW(store->seen, store->seen_nr + 1, store->seen_alloc);
			break;
	 * logic in the loop above.
 * config source (file, blob, cmdline, etc).
		for (i = 0, copy_begin = 0; i < store.seen_nr; i++) {
		ret = (fn(canonical_name, value, data) < 0) ? -1 : 0;


		free(buf);

			store->seen_nr++;
	int i = 0, j = 0, dot = 0;
	case CONFIG_ORIGIN_FILE:
		return 0;
		if (!dot && isspace(buf[i])) {
				   store->seen_alloc);
	return -CONFIG_INVALID_KEY;
		return 0;
		opts.commondir = get_git_common_dir();
	if (starts_with(var, "push."))
 * store_key - pointer to char* which will hold a copy of the key with
	}

}
	struct key_value_info *kv_info = xmalloc(sizeof(*kv_info));
	/* We require the format to be '[base "extension"]' */



	return ret;
	}
		if (value[i] == ';' || value[i] == '#')
static int get_next_char(void)
		const int scale = 86400;
	} else {
			i++;

}
			return error(_("invalid section name '%s'"), cf->var.buf);
	for (i = store->seen[seen] + 1; i < store->parsed_nr; i++) {
			if (!iskeychar(c) ||
	 */

				  const struct hashmap_entry *eptr,
		if (slash)
		return 0; /* never matches */
	else if (config_source && config_source->blob)
	if (!strcmp(var, "mailmap.blob"))
		big_file_threshold = git_config_ulong(var, value);
	return system_wide;
}
		void *data, const struct config_options *opts)

				replace_end = store.parsed[j].end;
		if (copy_begin < contents_sz)
	 */
	}
	return git_configset_get_bool_or_int(repo->config, key, is_bool, dest);
	return -1;
	if (opts->respect_includes) {
		 * stem prior to grabbing the suffix part of the name
int64_t git_config_int64(const char *name, const char *value)
	return 0;
		else if (level < 0 || level > Z_BEST_COMPRESSION)
{

		if (!dot || i > baselen) {

	struct strbuf pattern = STRBUF_INIT;
			 * need to flush out any section we're already
		int i;
		else if (!strcmp(value, "link"))
		return 0;
		repo_config = mkpathdup("%s/config", opts->commondir);
		/*
	regex_t *value_regex;
	top->linenr = 1;
}


		}
		ret += git_config_from_file(fn, repo_config, data);


		if (!quote) {
		return "file";
 * -2 if there is no section name in the key.
static int include_condition_is_true(const struct config_options *opts,
		if (type == CONFIG_EVENT_SECTION) {
 * fgetc, ungetc, ftell of top need to be initialized before calling
			default:
		}
		else if (!strcmp(value, "simple"))
		config_filename = filename_buf = git_pathdup("config");

	if (!strcmp(var, "core.eol")) {
		value = "";
						  ACCESS_EACCES_OK : 0))


	free(filename_buf);
}

		int level = git_config_int(var, value);
	if (!strcmp(var, "core.precomposeunicode")) {
			store->seen_nr++;
		if (value && !strcasecmp(value, "always"))
	struct config_source top;
 * current value (repo, global, etc). For cached values, it can be found via
		return 0;
	const char *value;
	/* Final ']' */
			errno = EINVAL;
		/*
				       cf->linenr, cf->name);
			auto_comment_line_char = 1;
		ret = handle_path_include(value, inc);
/*
const char *config_scope_name(enum config_scope scope)
	case CONFIG_SCOPE_SYSTEM:
		int length;
const struct string_list *git_config_get_value_multi(const char *key)
		case '\n':
	in_fd = open(config_filename, O_RDONLY);
	strbuf_init(&top->value, 1024);
{
{
	return 0;

static long config_buf_ftell(struct config_source *conf)
static int git_config_parse_key_1(const char *key, char **store_key, int *baselen_, int quiet)
	dot = memchr(key, '.', store->baselen);


		in_fd = -1;
	return repo_config_get_string_const(repo, key, (const char **)dest);
		if (name && !strcasecmp(var, name))
	int is_bool, val;
{

		if (c != '=')
					      current_config_kvi->linenr);
	free(expanded);

	 */
	return 1;
		git_die_config(key, NULL);
		return 0;
		return ret;
		int i, new_line = 0;
			   size_t begin, size_t end, void *data)
	if (strcmp(key, store->key))
	const struct string_list *values;
}
	if (!pair[0])
	 * follow beginning-of-comment characters (i.e. ';' and '#') by the
		if (!value)
			level = Z_DEFAULT_COMPRESSION;

	git_config_set_multivar(key, value, NULL, 0);
	for (i = store->seen[seen]; i > 0; i--) {

 *
	baselen = last_dot - key;
	if (!git_parse_ulong(value, &ret))
			remove = 0;

					/*
			auto_comment_line_char = 0;

		opts.git_dir = gitdir.buf;
	return name ? name : "";

}


		}
		packed_git_limit = git_config_ulong(var, value);
static void git_config_check_init(struct repository *repo)
			/* Reset prior to determining a new stem */
			     const char *value_regex, int multi_replace)
	configset_add_value(cs, key, value);
		die(_("bad config variable '%s' in file '%s' at line %d"),
			git_die_config(key, _("Invalid %s: '%s'"), key, *output);
	git_configset_clear(repo->config);

				break;
static int config_buf_ungetc(int c, struct config_source *conf)
 *     before the new pair is written.
		git_die_config(key, NULL);
	int ret;
	else if (opts->git_dir)
		}


{
				}
			}
			ret = CONFIG_INVALID_FILE;
		packed_git_window_size = git_config_ulong(var, value);
		fclose(f);
	if (!strcmp(var, "core.ignorestat")) {
				 offset, data->opts->event_fn_data) < 0)
	return ret;
		error_errno(_("could not write config file %s"), config_filename);
	 */
}
			goto write_err_out;
		die(_("failed to parse %s"), k);
		    value, name, cf->name, _(error_type));
	char *filename_buf = NULL;
}
		if (++inc->depth > MAX_INCLUDE_DEPTH)

		if (!pack_compression_seen)

	if (!strcmp(var, "core.bigfilethreshold")) {
		val = strtoimax(value, &end, 0);
			}
				 size_t *begin_offset, size_t *end_offset,
		goto out_no_rollback;
 *
	return 0;
	if (!git_configset_get_value(cs, key, &value)) {
		return "standard input";
	current_parsing_scope = CONFIG_SCOPE_GLOBAL;
	ret = git_parse_source(fn, data, opts);
	}
{
{


		return git_config_pathname(&excludes_file, var, value);
		return ret;
	return git_configset_get_maybe_bool(repo->config, key, dest);
	return EOF;
	if (core_fsmonitor && !*core_fsmonitor)
{
		else
	int i;
	ssize_t ret;
	const char *v = getenv(k);
		return git_default_branch_config(var, value);
			goto out_free;
			case '\n':
{
		timestamp_t now = approxidate("now");
 * - the config file is removed and the lock file rename()d to it.
	struct strbuf commondir = STRBUF_INIT;
	git_config_check_init(repo);
	const char *value;
		if (isspace(c)) {

		}
			die(_("invalid mode for object creation: %s"), value);
}
	if (type == CONFIG_EVENT_WHITESPACE &&
		*dest = git_config_bool(key, value);

		errno = 0;
				break;

			store->section_seen = 1;
		store->is_keys_section =
	    || !strcasecmp(value, "no")
		return 1024 * 1024 * 1024;
{
	if (!strcmp(var, "core.preloadindex")) {
	return git_config_from_blob_oid(fn, name, &oid, data);
	struct object_id oid;
int git_config_from_file_with_options(config_fn_t fn, const char *filename,
	l_item->value_index = e->value_list.nr - 1;
				goto out_free_ret_1;
}
	return repo_config_get_ulong(the_repository, key, dest);
}

			strbuf_addch(var, '.');
	} else
	if (!strcmp(var, "core.whitespace")) {
	rollback_lock_file(&lock);

	if (store_key) {
	const char *shortname;
		entry = list->items[i].e;


		ret = git_config_from_file(git_config_include, path, inc);
static void configset_iter(struct config_set *cs, config_fn_t fn, void *data)
					  filename, f, data, opts);
		ret += git_config_from_file(fn, user_config, data);
	struct strbuf var;
	if (!git_configset_get_value(cs, key, &value)) {
		return -CONFIG_NO_SECTION_OR_NAME;
	return git_config_from_file_with_options(fn, filename, data, NULL);
}
			continue;
		return git_config_pathname(&git_hooks_path, var, value);
	}
		if (matches(key, value, store)) {
	}
#include "object-store.h"
	    !strcmp(key, "path"))
	if (type == CONFIG_EVENT_SECTION) {
	return isalnum(c) || c == '-';
}
}
		return 1;
		if (store->is_keys_section) {
static int pack_compression_seen;
		} buf;
void repo_config(struct repository *repo, config_fn_t fn, void *data)
		if (value_regex == NULL)
		return 0;

		if (!strcmp(value, "rename"))
		return error(_("splitIndex.maxPercentChange value '%d' "
}
 * if value_regex==CONFIG_REGEX_NONE, do not match any existing values
	git_config_check_init(repo);
}
}
 *   written to the lock file, then the changed part and the rest.

	for (i = 1; buf[i] && buf[i] != ']'; i++) {
	if (opts->git_dir)
{
 * possible spellings); if missing, use the default value 'def'.
			return 0;
	if (xdg_config && !access_or_die(xdg_config, R_OK, ACCESS_EACCES_OK))
	if (in_fd >= 0)
		current_config_kvi = NULL;
	free(filename_buf);
	}
	if (cf->name) {
				    write_str_in_full(fd, "\n") < 0)
		if (do_event(CONFIG_EVENT_ENTRY, &event_data) < 0)
		return 0; /* not ours */

		return 0;
		if (type == CONFIG_EVENT_ENTRY) {
			comment_line_char = value[0];
				if (write_section(fd, key, &store) < 0)
		return 1;
	if (!*end)
			continue;
		return 0;
	ret = !wildmatch(pattern.buf + prefix, text.buf + prefix,
	if (value)
		if (value != NULL) {
		}
		}

	prefix = prepare_include_condition_pattern(&pattern);
		 * translations with N_() above.
			 * When encountering a new section under -c we
				return NULL;
 */
	values = git_configset_get_value_multi(cs, key);
			push_default = PUSH_DEFAULT_SIMPLE;
	return 0;
	const char *old = getenv(CONFIG_DATA_ENVIRONMENT);
	case CONFIG_SCOPE_LOCAL:

		}
		 * After this, store.parsed will contain offsets of all the
			git_branch_track = BRANCH_TRACK_ALWAYS;
 * Read config but only enumerate system and global settings.
	return git_configset_get_value(repo->config, key, value);
 * They should generally never be non-NULL at the same time. If they are both




				} else {
			push_default = PUSH_DEFAULT_UPSTREAM;
	if (ret)
	repo_config(the_repository, fn, data);
	store.multi_replace = multi_replace;
	if (value[0] == ' ')
			offset = section_name_match(&buf[i], old_name);
			!skip_prefix(refname, "refs/heads/", &shortname))
	free(store->key);
		cf->linenr++;
	strbuf_release(&sb);
				  const void *unused_keydata)

	top.do_fgetc = config_file_fgetc;
		length = strlen(output);

int git_config_set_gently(const char *key, const char *value)
	char *buf;
	top.do_ftell = config_file_ftell;

	}
				c = '\n';
				return 0;
	if (!git_configset_get_value(cs, key, &value)) {
	struct configset_list *list = &cs->list;

		store.key = xstrdup(key);
		return error(_("could not expand include path '%s'"), path);
	 */
	unsigned int key_seen:1, section_seen:1, is_keys_section:1;
}
	}
	case CONFIG_ORIGIN_STDIN:

		return 0;
 *
}

}
		*dest = val;
		else if (git_config_bool(var, value))
	memset(&source, 0, sizeof(source));

		die(_("could not set '%s' to '%s'"), key, value);
	}
		git_dir = opts->git_dir;
	}
		goto done;
		ret = error_errno(_("could not write config file %s"),
		}
static int get_base_var(struct strbuf *name)

	 */
	if (config_source)
						 * tab
	if (old && *old) {
				goto write_err_out;
		return 1;
			if (c != EOF)
		if (isspace(c) && !quote) {
		goto out;


	return sb;
			object_creation_mode = OBJECT_CREATION_USES_RENAMES;
/*
			pack_compression_level = level;
		return 0;
		} else
	if (!strcmp(var, "core.autocrlf")) {
			break;
{
	else if (!strcasecmp(end, "k"))
}
			ret = CONFIG_NOTHING_SET;
	struct stat st;
static const char include_depth_advice[] = N_(
		if (c == '\\') {
		return -1;
 *
		return current_config_kvi->scope;
}
		strbuf_realpath(&path, cf->path, 1);
/*
	if (!strcmp(var, "core.checkroundtripencoding")) {
	dot = 0;
		return 0;
	int ret = 0, prefix;
	return ret;
		 * gobbling up any whitespace after it, as well
		delta_base_cache_limit = git_config_ulong(var, value);
		return 1; /* no such thing */
			store.value_regex = (regex_t*)xmalloc(sizeof(regex_t));
	int type;

		const enum config_origin_type origin_type,
	} else if (!discover_git_directory(&commondir, &gitdir)) {


	/* Empty section names are bogus. */

		switch (value[i]) {
	top.path = path;
{

}
 */
 * file (i.e., a file included from .git/config is still in "repo" scope).
	if (current_config_kvi)
			}
		e = xmalloc(sizeof(*e));
			if (++seen < store->seen_nr &&
					- !!store.parsed_nr;
	 * Since the keys are being fed by git_config*() callback mechanism, they
}
	intmax_t tmp;
}
	};
					      current_config_kvi->filename,
				error(_("invalid key (newline): %s"), key);

			return config_error_nonbool(var);
int repo_config_get_pathname(struct repository *repo,
	l_item = &cs->list.items[cs->list.nr++];
{
	pair = strbuf_split_str(text, '=', 2);
	return ftell(conf->u.file);
	 * setup_git_directory_gently(), no global state is changed, most
		 * We explicitly *don't* use _() here since it would
	}
const char *current_config_origin_type(void)
	case CONFIG_ERROR_UNSET:
{
		assume_unchanged = git_config_bool(var, value);
	const char *path;
				const char *key, int *is_bool, int *dest)
	return git_configset_get_ulong(repo->config, key, dest);
		int c = get_next_char();
{
	const char *name;
