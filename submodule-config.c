
		file = repo_worktree_path(repo, GITMODULES_FILE);
	if (fetchjobs < 0)
	if (!opt->value)
	int subsection_len, parse;
			config, config_size, &parameter, NULL);
		enum lookup_type lookup_type)

		} else if (looks_like_command_line_option(value)) {
	parameter.treeish_name = treeish_name;
	 * If any parameter except the cache is a NULL pointer just
					"ignore");
		struct submodule_entry *entry;

int parse_fetch_recurse_submodules_arg(const char *opt, const char *arg)
	default:
	int *max_children;
	parse = parse_config_key(var, "submodule", &subsection,
		const struct config_options opts = { 0 };
}
	unsigned int hash = hash_oid_string(gitmodules_oid, name);
}
	config = read_object_file(&oid, &type, &config_size);
	return ret;
			commit_string, name, option);
		struct git_config_source config_source = {
}

	 * their .gitmodules blob sha1 and submodule name.
	submodule = xmalloc(sizeof(*submodule));
 * for_path stores submodule entries with path as key
					    submodule->name);

			if (name[0] == '.' && name[1] == '.' &&

 * submodule cache lookup structure
	 * We iterate over the name hash here to be symmetric with the
	the_repository->submodule_cache->gitmodules_read = 1;
	return parse_push_recurse(opt, arg, 1);
			ret = config_error_nonbool(var);
	hashmap_init(&cache->for_name, config_name_cmp, NULL, 0);
{
		if (die_on_error)
	hashmap_entry_init(&key.ent, hash);
	free((void *) entry->config->branch);
					 &oid, the_repository);

		submodule = cache_lookup_name(cache, &oid, key);
 */
	struct submodule key_config;
	key.config = &key_config;
	submodule->ignore = NULL;

	ret = git_config_set_in_file_gently(GITMODULES_FILE, key, value);
	};

	cache->initialized = 0;
	case lookup_name:

	b = container_of(entry_or_key, const struct submodule_entry, ent);
					     "shallow");
/*
		else if (!strcmp(arg, "only"))
		} else {
			goto out;
		 * git-completion.bash when you add new options.
	submodule->branch = NULL;
					     me->gitmodules_oid,
	submodule_cache_clear(cache);
				ent /* member name */)
			   repo_get_oid(repo, GITMODULES_HEAD, &oid) >= 0) {

	if (repo->worktree) {
};
 * working directory.
	int ret = 0;
		return RECURSE_SUBMODULES_OFF;

		else {
const struct submodule *submodule_from_name(struct repository *r,
		/* Maybe the user already did that, don't error out here */
	submodule->url = NULL;
	 */
	entry = hashmap_get_entry(&cache->for_path, &key, ent, NULL);
void gitmodules_config_oid(const struct object_id *commit_oid)
	case 1:
	unsigned int hash = hash_oid_string(&submodule->gitmodules_oid,
	default:
		entry = hashmap_iter_first_entry(&cache->for_name, &iter,
	e->config = submodule;
	if (!strcmp(var, "submodule.fetchjobs"))
		else if (!me->overwrite && submodule->ignore)
					     name.buf);
}
struct parse_config_parameter {
	int *recurse_submodules;
	config_from_gitmodules(gitmodules_update_clone_config, the_repository, &max_jobs);
{
	/*
 * config store (.git/config, etc).  Callers are responsible for
								die_on_error);
}
{

 * not be used as a mechanism to retrieve arbitrary configuration stored in
	hashmap_for_each_entry(&cache->for_name, &iter, entry,

			 strcmp(value, "none"))
{
					"fetchrecursesubmodules");
		/*
	}
		return CONFIG_INVALID_KEY;

	} else if (!strcmp(item.buf, "ignore")) {
{
	hashmap_entry_init(&e->ent, hash);

				add_to_alternates_memory(repo->objects->odb->path);
		else
	const char *subsection, *key;

{
{
}
}
{
	key.config = &key_config;
	free(config);
{
		return -1;
{
		if (die_on_error)
		else if (!me->overwrite && submodule->path)
 */
	       !oideq(&a->config->gitmodules_oid, &b->config->gitmodules_oid);
			 strcmp(value, "dirty") &&
{
		if (!strcmp(arg, "on-demand"))
		int die_on_error = is_null_oid(me->gitmodules_oid);
static int gitmodules_fetch_config(const char *var, const char *value, void *cb)
{
		 * Please update $__git_fetch_recurse_submodules in
	int overwrite;
	int *v;
		warning(_("Could not update .gitmodules entry %s"), key);
			warning("Invalid parameter '%s' for config option "
		      struct submodule *submodule)

		else
	if (check_submodule_name(name->buf) < 0) {
		return RECURSE_SUBMODULES_ON;
		const char *path)
		goto out;
		warning(_("ignoring suspicious submodule name: %s"), name->buf);
			*v = RECURSE_SUBMODULES_ON;
			return RECURSE_SUBMODULES_ERROR;
	unsigned initialized:1;
		die(_("negative values not allowed for submodule.fetchjobs"));
	parameter.gitmodules_oid = &oid;

		if (file_exists(file)) {
				return -1;
	if (unset) {
	return memhash(oid->hash, the_hash_algo->rawsz) + strhash(string);
		};
			   const struct hashmap_entry *entry_or_key,
	struct strbuf rev = STRBUF_INIT;
	if (!strcmp(wanted_key, var))
		free(oidstr);
static int config_print_callback(const char *var, const char *value, void *cb_data)
	parameter.cache = cache;
 *
		return -1;
		return NULL;
static struct submodule *cache_lookup_name(struct submodule_cache *cache,
#include "submodule-config.h"
static void submodule_cache_check_init(struct repository *repo)
}
}
	v = opt->value;
			      struct submodule *submodule)
		/*

	unsigned int hash = hash_oid_string(gitmodules_oid, path);
	struct hashmap for_name;
	struct submodule_entry *entry;

	free(entry->config);
	switch (git_parse_maybe_bool(arg)) {
			free((void *) submodule->path);
	submodule = lookup_or_create_by_name(me->cache,
		else
					     "update");
	struct submodule_entry *entry;
void update_clone_config_from_gitmodules(int *max_jobs)
static int parse_update_recurse(const char *opt, const char *arg,
		return 1;

	struct submodule_cache *cache;
	hashmap_free_entries(&cache->for_name, struct submodule_entry, ent);
		if (!me->overwrite && submodule->branch)
{
}
		if (c == '/' || c == '\\') {
	oidcpy(&key_config.gitmodules_oid, gitmodules_oid);
};
	if (parse < 0 || !subsection)
	while (*name) {
		else if (strcmp(value, "untracked") &&
{
void submodule_cache_free(struct submodule_cache *cache)
		goto out;
	}

}
#include "submodule.h"
		return RECURSE_SUBMODULES_ON;
	free((void *) entry->config->path);
	lookup_name,
			die("bad %s argument: %s", opt, arg);
	/*
	struct submodule_entry *entry;

						struct submodule_entry,
		ret = 1;
		const struct object_id *gitmodules_oid, const char *name)
	if (!gitmodule_oid_from_commit(treeish_name, &oid, &rev))
	parameter.cache = repo->submodule_cache;

	 * there are any submodules parsed.
		 */
		else if (parse_submodule_update_strategy(value,
	unsigned gitmodules_read:1;

	strbuf_release(&rev);
	const struct object_id *treeish_name;
{
out:
static const struct submodule *cache_lookup_path(struct submodule_cache *cache,
			ret = config_error_nonbool(var);
			&subsection_len, &key);
	return 0;

	unsigned int hash = hash_oid_string(&submodule->gitmodules_oid,
}
	return strcmp(a->config->name, b->config->name) ||
static int parse_fetch_recurse(const char *opt, const char *arg,
	} else if (!strcmp(item.buf, "url")) {
	case 1:
		struct hashmap_iter iter;
		*(config->recurse_submodules) = parse_fetch_recurse_submodules_arg(var, value);
};

in_component:
		break;
			warn_multiple_config(me->treeish_name, submodule->name,
	hashmap_entry_init(&e->ent, hash);
			free((void *) submodule->url);
		}
#include "parse-options.h"


			die("bad %s argument: %s", opt, arg);
					"url");
#include "repository.h"
	hashmap_add(&cache->for_name, &e->ent);
{
void fetch_config_from_gitmodules(int *max_children, int *recurse_submodules)
	free(store_key);
	struct strbuf name = STRBUF_INIT, item = STRBUF_INIT;
	cache->gitmodules_read = 0;

		return 0;

enum lookup_type {
			   const struct hashmap_entry *eptr,
	 * return the first submodule. Can be used to check whether
					"path");

	if (!is_gitmodules_unmerged(repo->index))
	case lookup_name:

	return xcalloc(1, sizeof(struct submodule_cache));

 * Runs the provided config function on the '.gitmodules' file found in the
	case 0:
		char *oidstr = NULL;

	if (!strcmp(item.buf, "path")) {
		if (!value)
			       int die_on_error)
		else if (looks_like_command_line_option(value))
	parameter.overwrite = 0;
 * There is one shared set of 'struct submodule' entries which can be
	switch (lookup_type) {
}
		break;
	struct submodule *submodule;
static void warn_command_line_option(const char *var, const char *value)

}
					    submodule->path);
}

		git_config_from_blob_oid(gitmodules_cb, rev.buf,
			ret = config_error_nonbool(var);
	return 1;
}
	submodule->update_strategy.type = SM_UPDATE_UNSPECIFIED;

static int config_name_cmp(const void *unused_cmp_data,
	cache->initialized = 1;
			       int die_on_error)
	return config_from(r->submodule_cache, treeish_name, path, lookup_path);
	}
		if (!entry)
		    submodule->fetch_recurse != RECURSE_SUBMODULES_NONE)
{
	return ret;
		else if (!strcmp(arg, "check"))
	}
	hashmap_entry_init(&key.ent, hash);
}
	strbuf_addstr(item, key);
			free((void *) submodule->ignore);
	struct strbuf rev = STRBUF_INIT;
	parameter.overwrite = 1;
	switch (git_parse_maybe_bool(arg)) {
	submodule_cache_check_init(repo);
}
}
		return RECURSE_SUBMODULES_ERROR;
 */


	struct submodule_entry key;
}
			warn_multiple_config(me->treeish_name, submodule->name,
		if (!strcmp(arg, "on-demand"))
		.recurse_submodules = recurse_submodules

			submodule->ignore = xstrdup(value);
	} else if (!strcmp(var, "fetch.recursesubmodules")) {
			submodule->url = xstrdup(value);
	if (ret < 0)



					  void *cb)
	struct object_id oid;
static int gitmodules_update_clone_config(const char *var, const char *value,
	warning("%s:.gitmodules, multiple configurations found for "


	struct object_id oid;
			return RECURSE_SUBMODULES_ON_DEMAND;
	if (!strcmp(var, "submodule.fetchjobs")) {
	case 0:
	struct fetch_config *config = cb;
	strbuf_release(&item);
{
			"'submodule.%s.%s'. Skipping second one!",
		else
	struct hashmap for_path;
		.max_children = max_children,
{
	struct parse_config_parameter parameter;
}
int parse_push_recurse_submodules_arg(const char *opt, const char *arg)
			warn_command_line_option(var, value);
static struct submodule *lookup_or_create_by_name(struct submodule_cache *cache,
			config_source.file = file;
		free(file);
	e.config = submodule;
		return entry->config;
		if (!value)
	} else if (!strcmp(item.buf, "shallow")) {
}
static int gitmodules_cb(const char *var, const char *value, void *data)
void submodule_free(struct repository *r)
{
static void warn_multiple_config(const struct object_id *treeish_name,
	} else {
{
	if (submodule)
	struct fetch_config config = {
					    const struct object_id *treeish_name,
	cache_add(cache, submodule);
	hashmap_put(&cache->for_path, &e->ent);

	}
{
		return RECURSE_SUBMODULES_OFF;
	return parse_fetch_recurse(opt, arg, 1);

			   const struct hashmap_entry *entry_or_key,
		else {
}
	return config_from(r->submodule_cache, treeish_name, name, lookup_name);
	return 0;
	case 0:
	return 0;
static int name_and_item_from_var(const char *var, struct strbuf *name,
		return 0;
	repo_read_gitmodules(r, 1);
		repo->submodule_cache = submodule_cache_alloc();
	unsigned int hash = hash_oid_string(&submodule->gitmodules_oid,


{
			if (submodule->path)
		/* There's no simple "on" value when pushing */
int config_set_in_gitmodules_file_gently(const char *key, const char *value)
	int ret;
	strbuf_addf(rev, "%s:.gitmodules", oid_to_hex(treeish_name));

}
			 submodule->update_strategy.type != SM_UPDATE_UNSPECIFIED)
	if (treeish_name)
static const struct submodule *config_from(struct submodule_cache *cache,
	int fetchjobs = git_config_int(var, value);
#include "object-store.h"
		return 0;
static int parse_config(const char *var, const char *value, void *data)
	return ret;

	hashmap_free_entries(&cache->for_path, struct submodule_entry, ent);
		} else if (repo_get_oid(repo, GITMODULES_INDEX, &oid) >= 0 ||
		else {
#include "dir.h"
static struct submodule_cache *submodule_cache_alloc(void)
};
	config_from_gitmodules(config_print_callback, repo, store_key);
	/* this also ensures that we only parse submodule entries */
	return parse_config(var, value, &parameter);
int print_config_from_gitmodules(struct repository *repo, const char *key)
		}
 * looked up by their sha1 blob id of the .gitmodules file and either

	if (submodule)

 * the hashmap

}
				git_config_bool(var, value);
		return;
{

	return 0;
		char c = *name++;
	key_config.path = path;
			submodule->branch = xstrdup(value);
	unsigned long config_size;
			submodule->recommend_shallow =
		return cache_lookup_name(cache, &oid, key);
	} else if (!strcmp(item.buf, "fetchrecursesubmodules")) {
			    (!name[2] || name[2] == '/' || name[2] == '\\'))
 * for_name stores submodule entries with name as key

#include "config.h"
			return RECURSE_SUBMODULES_ONLY;



	strbuf_release(&rev);
	if (!config || type != OBJ_BLOB)
	entry = hashmap_get_entry(&cache->for_name, &key, ent, NULL);
			cache_put_path(me->cache, submodule);
{
	}
		} else if (!me->overwrite && submodule->url) {
		return cache_lookup_path(cache, &oid, key);
				  struct strbuf *item)
struct fetch_config {
		}

 * (key) with on-demand reading of the appropriate .gitmodules from
	int ret = 0;
 *
 * revisions.

/*
	const struct submodule_entry *a, *b;
		return;

{

	struct strbuf name_buf = STRBUF_INIT;
static int gitmodule_oid_from_commit(const struct object_id *treeish_name,
	submodule = cache_lookup_name(cache, gitmodules_oid, name);
	}
	repo_read_gitmodules(r, 1);
			warn_multiple_config(me->treeish_name, submodule->name,
		return 0;
/*


		if (!me->overwrite &&
			if (repo != the_repository)
	const struct object_id *gitmodules_oid;
	if (!treeish_name || !key) {

}
	struct submodule_entry e;
	if (entry)
static void free_one_config(struct submodule_entry *entry)
	free(config);
	if (!repo->submodule_cache)
			submodule->fetch_recurse = parse_fetch_recurse(
static void config_from_gitmodules(config_fn_t fn, struct repository *repo, void *data)
		if (!value)
		/* when parsing worktree configurations we can die early */

		else
{
int option_fetch_parse_recurse_submodules(const struct option *opt,
	}
		char *file;
	const struct submodule_entry *a, *b;
	lookup_path
	if (!name_and_item_from_var(var, &name, &item))
	return submodule;
		free_one_config(entry);

		else if (!me->overwrite &&
}
		 * git-completion.bash when you add new modes.
	return NULL;
	goto in_component; /* always start inside component */
					    const struct object_id *treeish_name,
	if (repo->submodule_cache && repo->submodule_cache->initialized)
		submodule_cache_clear(r->submodule_cache);
	return 0;
{
		strbuf_release(name);

	struct submodule_entry *e = xmalloc(sizeof(*e));
{
 * using path or name as key.

	removed = hashmap_remove_entry(&cache->for_path, &e, ent, NULL);
	 */

			warn_multiple_config(me->treeish_name, submodule->name,
			   const void *unused_keydata)
		return 0;
}
	if (gitmodule_oid_from_commit(commit_oid, &oid, &rev)) {
					"'submodule.%s.ignore'", value, name.buf);

};
	config_from_gitmodules(gitmodules_fetch_config, the_repository, &config);
			warn_multiple_config(me->treeish_name, submodule->name,
}
			0, .scope = CONFIG_SCOPE_SUBMODULE

			*v = parse_fetch_recurse_submodules_arg(opt->long_name, arg);
	if (repo_read_index(repo) < 0)
	}

	struct submodule key_config;
	/* Disallow empty names */
		const struct object_id *treeish_name, const char *key,
	key_config.name = name;
			return RECURSE_SUBMODULES_ERROR;
	return parse_update_recurse(opt, arg, 1);
	int ret;
				int die_on_error)

	 * separators rather than is_dir_sep(), because we want the name rules
 * checking for overrides in the main config store when appropriate.
int parse_submodule_fetchjobs(const char *var, const char *value)
	if (!*name)
	oidcpy(&submodule->gitmodules_oid, gitmodules_oid);
		*max_jobs = parse_submodule_fetchjobs(var, value);
	return 0;
	ret = git_config_parse_key(key, &store_key, NULL);
		return entry->config;
{
		printf("%s\n", value);
		}
static void cache_put_path(struct submodule_cache *cache,
	struct submodule *config;

int parse_update_recurse_submodules_arg(const char *opt, const char *arg)
		*(config->max_children) = parse_submodule_fetchjobs(var, value);
			   struct submodule *submodule)
			return RECURSE_SUBMODULES_ON_DEMAND;
 */
			   const void *unused_keydata)

	 */
	const char *commit_string = "WORKTREE";
{
}
}

	strbuf_addstr(&name_buf, name);
	b = container_of(entry_or_key, const struct submodule_entry, ent);
		}
		struct object_id oid;
	submodule->recommend_shallow = -1;
struct submodule_cache {
	if (!cache->initialized)

		if (!value) {
		goto out;
const struct submodule *submodule_from_path(struct repository *r,
			warn_multiple_config(me->treeish_name, submodule->name,
	hashmap_entry_init(&e.ent, hash);
	case lookup_path:
	git_config_from_mem(parse_config, CONFIG_ORIGIN_SUBMODULE_BLOB, rev.buf,
}

static int config_path_cmp(const void *unused_cmp_data,
	struct parse_config_parameter parameter;
#include "strbuf.h"
	}
int check_submodule_name(const char *name)
								var, value,
			free((void *)submodule->branch);
		const struct object_id *gitmodules_oid, const char *path)

	strbuf_release(&rev);
}
				     struct object_id *gitmodules_oid,
}
			ret = config_error_nonbool(var);
	/* fill the submodule config into the cache */
			 strcmp(value, "all") &&
	parameter.treeish_name = NULL;
			submodule->path = xstrdup(value);
static void submodule_cache_init(struct submodule_cache *cache)
		else if (die_on_error)
				     struct strbuf *rev)
static void cache_remove_path(struct submodule_cache *cache,

	free(cache);
		}
			 &submodule->update_strategy) < 0 ||
	submodule_cache_check_init(the_repository);
			   const struct hashmap_entry *eptr,
		 * Please update $__git_push_recurse_submodules in
			config_source.blob = oidstr = xstrdup(oid_to_hex(&oid));
	} else if (!strcmp(item.buf, "branch")) {
		oidclr(gitmodules_oid);
}

	submodule->name = strbuf_detach(&name_buf, NULL);
static int parse_push_recurse(const char *opt, const char *arg,
				cache_remove_path(me->cache, submodule);
				 const char *name, const char *option)

						ent /* member name */);
	default:

}
	}
	char *config = NULL;
}


	char *store_key;

		config_with_options(fn, data, &config_source, &opts);
{
					     "branch");
	struct submodule_entry key;
		return entry->config;
	case 1:
			warn_multiple_config(me->treeish_name, submodule->name,
		submodule = cache_lookup_path(cache, &oid, key);

{


	strbuf_add(name, subsection, subsection_len);

	repo->submodule_cache->gitmodules_read = 1;
			die("bad %s argument: %s", opt, arg);

	struct hashmap_iter iter;
 * Note: This function is private for a reason, the '.gitmodules' file should
	/*
 * the repository.
{
{
			return RECURSE_SUBMODULES_ERROR;
struct submodule_entry {
	} else if (!strcmp(item.buf, "update")) {
		const struct object_id *gitmodules_oid, const char *name)
static void submodule_cache_clear(struct submodule_cache *cache)
	submodule->fetch_recurse = RECURSE_SUBMODULES_NONE;
	free((void *) entry->config->update_strategy.command);
	strbuf_release(&name);
	}
{
/*
		 */
	oidcpy(&key_config.gitmodules_oid, gitmodules_oid);

	free((void *) entry->config->name);
	hashmap_init(&cache->for_path, config_path_cmp, NULL, 0);
}
{
		*v = RECURSE_SUBMODULES_OFF;

	}
	int *max_jobs = cb;
			warn_command_line_option(var, value);
	free(removed);
	struct hashmap_entry ent;

	submodule->path = NULL;
		return;
	const struct submodule *submodule = NULL;

	 * to be consistent across platforms.
	warning(_("ignoring '%s' which may be interpreted as"
			die("bad %s argument: %s", opt, arg);
		} else {
	struct repository *repo = data;
		if (arg)
}
	}
{
 * Parse a config item from .gitmodules.
	a = container_of(eptr, const struct submodule_entry, ent);

		config_from_gitmodules(gitmodules_cb, repo, repo);
	case lookup_path:
		return RECURSE_SUBMODULES_OFF;
	 * Look for '..' as a path component. Check both '/' and '\\' as

	if (entry)
	parameter.gitmodules_oid = &null_oid;
static void cache_add(struct submodule_cache *cache,
		if (die_on_error)
out:
	default:
	submodule_cache_init(repo->submodule_cache);
		return submodule;
		commit_string = oid_to_hex(treeish_name);


}
	char *wanted_key = cb_data;
	struct submodule *submodule;

void repo_read_gitmodules(struct repository *repo, int skip_if_read)
				    const char *string)
		if (!me->overwrite && submodule->recommend_shallow != -1)

}
					    submodule->path);
{
	struct submodule_entry *e = xmalloc(sizeof(*e));
	switch (git_parse_maybe_bool(arg)) {
static unsigned int hash_oid_string(const struct object_id *oid,

	enum object_type type;

}
					  const char *arg, int unset)
{
 * thin wrapper struct needed to insert 'struct submodule' entries to
	a = container_of(eptr, const struct submodule_entry, ent);
	 * allocation of struct submodule entries. Each is allocated by

{
{
			return RECURSE_SUBMODULES_CHECK;
	switch (lookup_type) {
			die(_("invalid value for %s"), var);
	return fetchjobs;

	if (get_oid(rev->buf, gitmodules_oid) >= 0)
		const char *name)
	return submodule;
#include "cache.h"
		  " a command-line option: %s"), var, value);
	submodule->update_strategy.command = NULL;
	return strcmp(a->config->path, b->config->path) ||

}
	struct parse_config_parameter *me = data;
 */

	       !oideq(&a->config->gitmodules_oid, &b->config->gitmodules_oid);
			return NULL;
			 submodule->update_strategy.type == SM_UPDATE_COMMAND)

/* This does a lookup of a submodule configuration by name or by path
}
	if (is_null_oid(treeish_name)) {
	return NULL;
		else
{

 * This does not handle submodule-related configuration from the main
{
	if (ret < 0)
		return;

	if (repo->submodule_cache->gitmodules_read && skip_if_read)
	struct submodule_entry *removed;
	if (r->submodule_cache)

	e->config = submodule;
