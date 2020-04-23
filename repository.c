	}
	read_repository_format(format, sb.buf);
		 * If initialization fails then it may be due to the submodule
	memset(repo, 0, sizeof(*repo));
	return ret;
{
			struct repository *superproject,
				     "modules/%s", sub->name);
int repo_init(struct repository *repo,
		goto error;
static int repo_init_gitdir(struct repository *repo, const char *gitdir)
	strbuf_release(&worktree);


	strbuf_release(&sb);
			       const char *commondir)
	      const char *worktree)
	struct strbuf sb = STRBUF_INIT;
#include "lockfile.h"
	if (repo_init_gitdir(repo, gitdir))
}
	if (commondir) {
		discard_index(repo->index);
 * declaration matches the definition in this file.
	}
		warning("%s", sb.buf);
	repo->hash_algo = &hash_algos[hash_algo];
	strbuf_repo_worktree_path(&worktree, superproject, "%s", sub->path);
	FREE_AND_NULL(repo->commondir);
		ret = -1;

}
void repo_set_gitdir(struct repository *repo,
	raw_object_store_clear(repo->objects);
	if (worktree)
		strbuf_reset(&gitdir);

}
	struct strbuf worktree = STRBUF_INIT;
}

		     const struct set_gitdir_args *o)
{
		repo->submodule_cache = NULL;
int repo_read_index(struct repository *repo)
}
	if (repo->index) {
 * Return 0 upon success and a non-zero value upon failure.
#include "object.h"
	if (!sub) {
	return read_index_from(repo->index, repo->index_file, repo->gitdir);

	strbuf_release(&gitdir);
					     const char *commondir)
	if (!repo->index)
out:
}
		if (repo_init(subrepo, gitdir.buf, NULL)) {
			   struct lock_file *lf,
			const struct submodule *sub)
 */

	 * that also points to repo->gitdir. We want to keep it alive
struct repository *the_repository;
	if (read_and_verify_repository_format(&format, repo->commondir))
static void repo_set_commondir(struct repository *repo,
{
	struct set_gitdir_args args = { NULL };
	clear_repository_format(&format);
	int ret = 0;
/* The main repository */
{

static struct repository the_repo;
	parsed_object_pool_clear(repo->parsed_objects);

	struct strbuf sb = STRBUF_INIT;
	repo->objects = raw_object_store_new();
	free(old_gitdir);
	return ret;
	char *old_gitdir = repo->gitdir;
	if (!resolved_gitdir) {
					    superproject->submodule_prefix ?
{
	if (repo->config) {
{
	trace2_def_repo(repo);
		strbuf_repo_git_path(&gitdir, superproject,
			repo->gitdir, "index");
		}
	repo->worktree = real_pathdup(path, 1);
	}
		/*
}
	free(repo->objects->alternate_db);
	if (hash_algo != GIT_HASH_SHA1)
		repo->objects->odb = xcalloc(1, sizeof(*repo->objects->odb));
	free(repo->commondir);

		ret = -1;


void repo_clear(struct repository *repo)
		repo->different_commondir = 1;
	repo->commondir = strbuf_detach(&sb, NULL);

	repo_set_gitdir(repo, resolved_gitdir, &args);
			repo->commondir, "info/grafts");
		 */
	}
 * Return 0 upon success and a non-zero value upon failure.
int repo_submodule_init(struct repository *subrepo,
}
	if (verify_repository_format(format, &sb) < 0) {
		git_configset_clear(repo->config);
	subrepo->submodule_prefix = xstrfmt("%s%s/",
	if (!repo->objects->odb) {
#endif
	if (!repo->index_file)
					    "", sub->path);

{
{
	else
	strbuf_reset(&sb);

		die(_("The hash algorithm %s is not supported in this build."), repo->hash_algo->name);
	repo_set_hash_algo(&the_repo, GIT_HASH_SHA1);
	repo->gitdir = xstrdup(gitfile ? gitfile : root);
		ret = -1;
	repo->parsed_objects = parsed_object_pool_new();
	repo_set_commondir(repo, o->commondir);
{
	struct repository_format format = REPOSITORY_FORMAT_INIT;
	free(*out);
 */
	if (repo->submodule_cache) {

	}
#include "repository.h"
		repo->commondir = xstrdup(commondir);

	 * repo->gitdir is saved because the caller could pass "root"
#include "config.h"

	free(abspath);
	 */

		FREE_AND_NULL(repo->config);
	}
	int ret = 0;
	/* 'gitdir' must reference the gitdir directly */
}
	strbuf_repo_worktree_path(&gitdir, superproject, "%s/.git", sub->path);

	the_repo.parsed_objects = parsed_object_pool_new();
	FREE_AND_NULL(repo->index_file);
		repo_set_worktree(repo, worktree);

	}
 */
		goto out;


	expand_base_dir(&repo->graft_file, o->graft_file,
			ret = -1;
	return 0;
		goto out;
	expand_base_dir(&repo->index_file, o->index_file,
/*
		repo->objects->odb_tail = &repo->objects->odb->next;
		 * submodule would not have a worktree.
	abspath = real_pathdup(gitdir, 0);
	repo->objects->alternate_db = xstrdup_or_null(o->alternate_db);
		BUG("the repo hasn't been setup");
 * not really _using_ the compat macros, just make sure the_index


	strbuf_addf(&sb, "%s/config", commondir);
{

}
		if (repo->index != &the_index)

		     const char *root,


			    const char *base_dir, const char *def_in)
void initialize_the_repository(void)
	resolved_gitdir = resolve_gitdir_gently(abspath, &error);

			FREE_AND_NULL(repo->index);
	char *abspath = NULL;
	the_repository = &the_repo;

void repo_set_hash_algo(struct repository *repo, int hash_algo)
void repo_set_worktree(struct repository *repo, const char *path)
/*



	the_repo.index = &the_index;
{
out:
struct index_state the_index;
}
#include "object-store.h"

			goto out;

	struct strbuf gitdir = STRBUF_INIT;
		*out = xstrfmt("%s/%s", base_dir, def_in);
		repo->index = xcalloc(1, sizeof(*repo->index));
	/*
		submodule_cache_free(repo->submodule_cache);
	return ret;
error:
#include "submodule-config.h"
		goto error;
	return hold_lock_file_for_update(lf, repo->index_file, flags);
		 * not being populated in the superproject's worktree.  Instead
	FREE_AND_NULL(repo->worktree);
	FREE_AND_NULL(repo->gitdir);
		 * we can try to initialize the submodule by finding it's gitdir

	if (!abspath) {


					    superproject->submodule_prefix :
#ifndef ENABLE_SHA256
int repo_hold_locked_index(struct repository *repo,
	FREE_AND_NULL(repo->parsed_objects);
#include "cache.h"
		ret = -1;


	}
		return;
#define USE_THE_INDEX_COMPATIBILITY_MACROS
	return -1;

	expand_base_dir(&repo->objects->odb->path, o->object_dir,

 * Initialize 'repo' based on the provided 'gitdir'.
	int ret = 0;
			repo->commondir, "objects");
static void expand_base_dir(char **out, const char *in,
	FREE_AND_NULL(repo->objects);
	repo_clear(repo);
{
static int read_and_verify_repository_format(struct repository_format *format,

	repo_set_hash_algo(repo, format.hash_algo);
}
			   int flags)
	FREE_AND_NULL(repo->submodule_prefix);

	the_repo.objects = raw_object_store_new();
		*out = xstrdup(in);
	if (repo_init(subrepo, gitdir.buf, worktree.buf)) {
{
	if (in)
	}
	}


	FREE_AND_NULL(repo->graft_file);
	const char *resolved_gitdir;
	      const char *gitdir,

}
		goto out;
	repo->different_commondir = get_common_dir_noenv(&sb, repo->gitdir);

		 * in the superproject's 'modules' directory.  In this case the
 * Attempt to resolve and set the provided 'gitdir' for repository 'repo'.
	 * until after xstrdup(root). Then we can free it.

	const char *gitfile = read_gitfile(root);
/*
	int error = 0;
