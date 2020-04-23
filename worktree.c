	if (ret)

		 * repository would make it impossible to know where
static void strbuf_addf_gently(struct strbuf *buf, const char *fmt, ...)
		return wt;
	return wt->lock_reason;
	DIR *dir;
	struct strbuf path = STRBUF_INIT;
		return git_common_path("worktrees/%s", wt->id);
	worktrees = get_worktrees(0);
				die_errno(_("failed to read '%s'"), path.buf);
	if (!wt->lock_reason_valid) {
				strbuf_addf(sb, "worktrees/%s/", wt->id);
		if (ret)

				existing = wt;
			else
	path = xstrdup_or_null(read_gitfile_gently(wt_path.buf, &err));
{
		break;
		struct strbuf path = STRBUF_INIT;
	struct strbuf worktree_path = STRBUF_INIT;
	found_rebase = wt_status_check_bisect(wt, &state) &&
	strbuf_vaddf(buf, fmt, params);
	strbuf_release(&err);
		 * For shared refs, don't prefix worktrees/ or
	int nr_found = 0, suffixlen;
	worktree->is_bare = (is_bare_repository_cfg == 1) ||

	worktree->path = strbuf_detach(&worktree_path, NULL);
	}


			if (is_worktree_being_bisected(wt, target)) {
}
	}
			   "%s/.git", path.buf);

			       const char *target)
			wt->lock_reason = strbuf_detach(&lock_reason, NULL);


int parse_worktree_ref(const char *worktree_ref, const char **name,

		strbuf_addf_gently(errmsg,


/* convenient wrapper to deal with NULL strbuf */

			found = *list;
		return 0;
			break;
		strbuf_release(&path);
		const char *slash = strchr(worktree_ref, '/');
		break;
static struct worktree *get_main_worktree(void)
		} else
		BUG("can't relocate main worktree");
{
	strbuf_release(&path);
	}
		refs = get_worktree_ref_store(wt);
		 * always be the first
		       int *name_length, const char **ref)
		return get_git_dir();
	/* Replace config by worktrees. */
		free(worktrees[i]->lock_reason);
			strbuf_trim(&lock_reason);
	struct repository_format format = REPOSITORY_FORMAT_INIT;
	strbuf_release(&realpath);
		strbuf_strip_suffix(&worktree_path, "/.");
		struct worktree *wt = worktrees[i];
	struct strbuf sb = STRBUF_INIT, err = STRBUF_INIT;
}
	int i = 0;
	worktree->id = xstrdup(id);
		goto done;
const struct worktree *find_shared_symref(const char *symref,
		ret = 0;
			if ((linked = get_linked_worktree(d->d_name))) {
{
			 struct strbuf *sb,
/*

				   _("'%s' at main working tree is not the repository directory"),
	}
}
int validate_worktree(const struct worktree *wt, struct strbuf *errmsg,
	strbuf_realpath(&realpath, git_common_path("worktrees/%s", wt->id), 1);
		free(worktrees[i]->id);
	}
	int found_rebase;
done:


	dir = opendir(sb.buf);
#include "refs.h"
		break;
		return 0;
		strbuf_addf_gently(errmsg,

		if (file_exists(path.buf)) {

		      unsigned flags)
			struct worktree *linked = NULL;
	worktree = xcalloc(1, sizeof(*worktree));
	free(git_dir);
	int counter = 0, alloc = 2;
		if (wt->is_bare)
		starts_with(target, "refs/heads/") &&

	strbuf_add_absolute_path(&worktree_path, get_git_common_dir());
 * HEAD is temporarily detached (e.g. in the middle of rebase or
	read_repository_format(&format, sb.buf);
	char *to_free = NULL;
		strbuf_addf_gently(errmsg, _("'%s' does not exist"), wt_path.buf);
	/* The env would be set for the superproject. */
		struct object_id oid;
	const struct worktree *const *a = a_;
}
	worktrees = get_worktrees(0);
	for (i = 0; worktrees[i]; i++) {
	strbuf_addstr(&sb, "worktrees");
	assert(!is_main_worktree(wt));

	for (i = 0; worktrees[i]; i++) {
	list[counter++] = get_main_worktree();

}
	return ret;
	int err, ret = -1;
		goto done;
		    symref_target && !strcmp(symref_target, target)) {
	if (is_main_worktree(wt))
	if (!wt)
	struct dirent *d;
	worktree->path = strbuf_detach(&worktree_path, NULL);
		 !strcmp(state.branch, target + strlen("refs/heads/")));
			break;
		int flag;
		closedir(dir);
			if (is_worktree_being_rebased(wt, target)) {
			*ref = slash + 1;

			      const char *target)

		 * Main worktree using .git file to point to the
	strbuf_rtrim(&worktree_path);
	if (flags & GWT_SORT_LINKED)
	DIR *dir;
	}
	int i;
{
	suffixlen = strlen(suffix);

		wt->path = strbuf_detach(&path, NULL);
			wt->lock_reason = NULL;
			       const char *prefix,
	return wt;
	struct strbuf wt_path = STRBUF_INIT;
{
				   wt->path, git_common_path("worktrees/%s", wt->id));
#include "strbuf.h"

	/*
	return *list;
			break;
int other_head_refs(each_ref_fn fn, void *cb_data)


		goto done;
				list[counter++] = linked;

		goto done;
#include "wt-status.h"
		if (!*worktree_ref)

	ALLOC_GROW(list, counter + 1, alloc);

				break;
		if (ref)

	return worktree;

	if (fspathcmp(wt->path, path.buf)) {
		if (is_dot_or_dotdot(d->d_name))


		strbuf_release(&sb);
		 */
		return;
	else
			}
	for (i = 0; worktrees[i]; i++) {
 */
	switch (ref_type(refname)) {
	for (; *list; list++) {
}
	char *git_dir = absolute_pathdup(get_git_dir());
{
				ALLOC_GROW(list, counter + 1, alloc);

}
	strbuf_release(&path);
		free(worktrees[i]);
		is_bare_repository();

	char *path = real_pathdup(p, 0);
	mark_current_worktree(list);
	if (!path) {
		if (name)
	if (strbuf_read_file(&worktree_path, path.buf, 0) <= 0)

	get_common_dir_noenv(&sb, submodule_gitdir);
		 * main-worktree/. It's not necessary and
	strbuf_release(&sb);

		if (wt->is_current)

	if ((wt = find_worktree_by_suffix(list, arg)))
int is_worktree_being_rebased(const struct worktree *wt,
{

 * Update head_sha1, head_ref and is_detached of the given worktree
	strbuf_setlen(&sb, sb.len - strlen("config"));
			goto done;
	clear_repository_format(&format);

{
			 const char *refname)
	return ret;
		struct worktree *wt = *p;


			if (strbuf_read_file(&lock_reason, path.buf, 0) < 0)
	struct worktree *worktree = NULL;
		free(worktrees[i]->path);
	case REF_TYPE_NORMAL:
	strbuf_git_common_path(&path, the_repository, "worktrees/%s/gitdir", id);
	return worktree;
		}
		int		 start	 = pathlen - suffixlen;
	for (; *list && nr_found < 2; list++) {
	if (!path)
		wt->lock_reason_valid = 1;
{

	free(state.onto);
		}

		strbuf_addf_gently(errmsg, _("'%s' is not a .git file, error code %d"),
		struct ref_store *refs;

	char *path = NULL;
				strbuf_addstr(sb, "main-worktree/");
	}
	}
					 &wt->head_oid, &flags);
		die("Missing linked worktree name");
	dir = opendir(path.buf);
	 * file points back here.
		free(worktrees[i]->head_ref);
	 * config.worktree is present, is_bare_repository_cfg will reflect the
	free(state.branch);
	if (!target)

}
}
}
	strbuf_release(&wt_path);

			ret = fn(worktree_ref(wt, "HEAD"), &oid, flag, cb_data);
		 * from another worktree. No .git file support for now.
		 */
			*name = worktree_ref;
	int ret = 0;
void strbuf_worktree_ref(const struct worktree *wt,
 * note: this function should be able to detect shared symref even if
			*name_length = slash - worktree_ref;
	}
 * get the main worktree
			continue;
			continue;
		 state.branch &&
				existing = wt;
int submodule_uses_worktrees(const char *path)
	int ret = 0;
	strbuf_release(&worktree_path);
#include "repository.h"
		return NULL;
		goto done;
{

	struct wt_status_state state;
}
	 */
const char *worktree_lock_reason(struct worktree *wt)
}
					RESOLVE_REF_READING,
	case REF_TYPE_OTHER_PSEUDOREF:
	}
	if (!strbuf_strip_suffix(&worktree_path, "/.git")) {

		symref_target = refs_resolve_ref_unsafe(refs, symref, 0,
			struct strbuf lock_reason = STRBUF_INIT;
		 starts_with(target, "refs/heads/") &&
	struct strbuf worktree_path = STRBUF_INIT;
}
		int flags;
			}
	if (!is_absolute_path(wt->path)) {
		const char	*path	 = (*list)->path;
		strbuf_strip_suffix(&worktree_path, "/.");
			continue;
	return list;
			return -1;
		/*
static void mark_current_worktree(struct worktree **worktrees)
{
	}
		return;
	strbuf_release(&path);
	int flags;
		}
	int found_rebase;

/**
		}
			if (is_dot_or_dotdot(d->d_name))
		if (ref)
	case REF_TYPE_PER_WORKTREE:
{
		QSORT(list + 1, counter - 1, compare_worktree);
		if (!strbuf_realpath(&wt_path, (*list)->path, 0))
	return sb.buf;
		const char *symref_target;
		strbuf_addf_gently(errmsg, _("'%s' does not point back to '%s'"),
	return -1;
	 * NEEDSWORK: If this function is called from a secondary worktree and
struct worktree *find_worktree(struct worktree **list,
static int compare_worktree(const void *a_, const void *b_)
	 * Make sure "gitdir" file points to a real .git file and that
		int		 pathlen = strlen(path);
					&oid, &flag))
		arg = to_free = prefix_filename(prefix, arg);
	static struct worktree **worktrees;

		return 1;
		goto done;
	const struct worktree *existing = NULL;

	target = refs_resolve_ref_unsafe(get_worktree_ref_store(wt),
		 * the actual worktree is if this function is executed

	if (worktrees)
			continue;
		}
	}
	int i = 0;
	return ret;
void update_worktree_location(struct worktree *wt, const char *path_)
				   wt_path.buf);

	return !wt->id;
			}
	if (prefix)
	/* See if there is any file inside the worktrees directory. */
		free(wt->path);
	add_head_info(worktree);
	va_list params;
	add_head_info(worktree);
	const char *target;
	if (!strbuf_strip_suffix(&worktree_path, "/.git"))
	}
	submodule_gitdir = git_pathdup_submodule(path, "%s", "");
		return get_git_common_dir();
	struct strbuf path = STRBUF_INIT;
{
	if (verify_repository_format(&format, &err)) {
{
	wt = find_worktree_by_path(list, arg);

	va_start(params, fmt);
	found_rebase = wt_status_check_rebase(wt, &state) &&

			return -1;
 */

const char *worktree_ref(const struct worktree *wt, const char *refname)
	struct wt_status_state state;
	free(state.branch);
}
	strbuf_addf(&wt_path, "%s/.git", wt->path);
	memset(&state, 0, sizeof(state));
		 */
			ret = 0;
			*name_length = 0;

		if (name)


	static struct strbuf sb = STRBUF_INIT;
		state.branch &&
		return NULL;
done:
}
	struct worktree *wt;
	char *submodule_gitdir;
	strbuf_reset(&path);
}
const char *get_worktree_git_dir(const struct worktree *wt)
	strbuf_addstr(sb, refname);
		free_worktrees(worktrees);
	closedir(dir);
		  state.rebase_interactive_in_progress) &&
void free_worktrees(struct worktree **worktrees)
		/*
{
		!strcmp(state.branch, target + strlen("refs/heads/"));
	strbuf_release(&worktree_path);
		strbuf_release(&err);
		while ((d = readdir(dir)) != NULL) {
					 "HEAD",
struct worktree **get_worktrees(unsigned flags)
		return 0;
			nr_found++;
		strbuf_reset(&worktree_path);
{
 */

	strbuf_reset(&sb);
#include "dir.h"


							NULL, &flags);
static struct worktree *get_linked_worktree(const char *id)
{

	}
	if (skip_prefix(worktree_ref, "main-worktree/", &worktree_ref)) {
}
				   _("'%s' file does not contain absolute path to the working tree location"),
			break;
	if (!submodule_gitdir)

	strbuf_addf(&path, "%s/worktrees/%s/HEAD", get_git_common_dir(), id);
		/*
	}

	memset(&state, 0, sizeof(state));
		strbuf_addstr(&path, worktree_git_path(wt, "locked"));
		clear_repository_format(&format);
					 0,
	return found_rebase;
	free_worktrees(worktrees);

		if ((flags & REF_ISSYMREF) &&

	return found_rebase;
	free(path);
				   wt_path.buf, err);
		}
			if (is_main_worktree(wt))
	struct worktree **list = NULL;
		break;
	worktree = xcalloc(1, sizeof(*worktree));

		}
			existing = wt;
		strbuf_add_absolute_path(&worktree_path, ".");

	strbuf_strip_suffix(&worktree_path, "/.");
{
	return fspathcmp((*a)->path, (*b)->path);
		ret = 1;
	 */
}
	strbuf_realpath(&path, path_, 1);
	if (dir) {

	if (skip_prefix(worktree_ref, "worktrees/", &worktree_ref)) {
	free(submodule_gitdir);
	}
	strbuf_worktree_ref(wt, &sb, refname);
{
	if (is_main_worktree(wt)) {
{
struct worktree *find_worktree_by_path(struct worktree **list, const char *p)
			*name = NULL;
	case REF_TYPE_MAIN_PSEUDOREF:
	struct dirent *d;
	free(path);
 * function as well.

	if (!suffixlen)

{
		 * files-backend.c can't handle it anyway.
/**
{

	/*
	return existing;
int is_main_worktree(const struct worktree *wt)

	free (worktrees);
	    !file_exists(wt->path)) {
	strbuf_addstr(&sb, "/config");
		write_file(git_common_path("worktrees/%s/gitdir", wt->id),
	free(to_free);
	struct worktree *worktree = NULL;
			wt->is_current = 1;
			*ref = worktree_ref;
		return 0;
	list[counter] = NULL;

}
		/* suffix must start at directory boundary */
int is_worktree_being_bisected(const struct worktree *wt,
	struct strbuf realpath = STRBUF_INIT;
	 * contents of config.worktree, not the contents of the main worktree.
					worktree_ref(wt, "HEAD"),
	}
	case REF_TYPE_PSEUDOREF:
		if (name_length)
		if (!fspathcmp(git_dir, absolute_path(wt_git_dir))) {
		if ((!start || (start > 0 && is_dir_sep(path[start - 1]))) &&
	else if (!wt->id)
	struct strbuf wt_path = STRBUF_INIT;

#include "cache.h"
}

		/* invalid gitdir file */
		wt->is_detached = 1;

	if (!file_exists(wt_path.buf)) {

}
	}

	return nr_found == 1 ? found : NULL;
	}
		struct worktree *wt = worktrees[i];
	else
	ret = fspathcmp(path, realpath.buf);
				continue;

	if (flags & WT_VALIDATE_WORKTREE_MISSING_OK &&
				break;
		if (wt->is_detached && !strcmp(symref, "HEAD")) {
		if (!refs_read_ref_full(get_main_ref_store(the_repository),
 * bisect). New commands that do similar things should update this
						const char *suffix)
	ALLOC_ARRAY(list, alloc);

	while ((d = readdir(dir)) != NULL) {
	const struct worktree *const *b = b_;
	if (!buf)

	strbuf_release(&wt_path);
}
}
	va_end(params);
		if (name_length)
		((state.rebase_in_progress ||
{
	strbuf_addf(&path, "%s/worktrees", get_git_common_dir());
		 * don't sort the first item (main worktree), which will
	struct strbuf path = STRBUF_INIT;
	struct worktree *found = NULL;
{
			       const char *arg)

		if (is_directory(wt_path.buf)) {

		const char *wt_git_dir = get_worktree_git_dir(wt);

#include "worktree.h"
	 * worktree is configured to be bare.
static struct worktree *find_worktree_by_suffix(struct worktree **list,
		if (!slash || slash == worktree_ref || !slash[1])
	if (!dir)
					  const char *target)
	if (!id)
	}
				   git_common_path("worktrees/%s/gitdir", wt->id));
	if (flags & REF_ISSYMREF)

	struct worktree **worktrees, **p;
static void add_head_info(struct worktree *wt)
		    !fspathcmp(suffix, path + start)) {
	 * This means that worktree->is_bare may be set to 0 even if the main
}
		if (wt && !wt->is_current) {
		wt->head_ref = xstrdup(target);
		if (!fspathcmp(path, wt_path.buf))

	for (p = worktrees; *p; p++) {
