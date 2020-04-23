const char **tmp_objdir_env(const struct tmp_objdir *t)
	char *path;
 * the midst of a sorting routine, but in practice it shouldn't matter.
		return -1;
{
#include "cache.h"
	free(path);

		strbuf_addf(src, "/%s", name);

	old = getenv(key);

	strbuf_addf(&t->path, "%s/incoming-XXXXXX", get_object_directory());
	if (!on_signal)
{

	if (ends_with(name, ".idx"))
		installed_handlers++;
{
	err = remove_dir_recursively(&t->path, 0);
	}
	strbuf_release(&src);
	struct dirent *de;
{
	 * This may use malloc via strbuf_grow(), but we should
	add_to_alternates_memory(t->path.buf);


	return ret;
		sigchain_push_common(remove_tmp_objdir_on_signal);
int tmp_objdir_migrate(struct tmp_objdir *t)
	return finalize_object_file(src->buf, dst->buf);
	if (ends_with(name, ".pack"))
struct tmp_objdir *tmp_objdir_create(void)
/*
		strbuf_addf(dst, "/%s", name);

static int setup_tmp_objdir(const char *root)
 * separated by PATH_SEP (which is what separate values in
}
static int read_dir_paths(struct string_list *out, const char *path)

	argv_array_clear(&t->env);
 * Allow only one tmp_objdir at a time in a running process, which simplifies
		val = quoted.buf;
	raise(signo);
	/*
}
static struct tmp_objdir *the_tmp_objdir;
	struct argv_array env;
{
	int ret = 0;
}
}
		return 3;
	if (!dh)
		the_tmp_objdir = NULL;
{
 * GIT_ALTERNATE_OBJECT_DIRECTORIES).

static void env_replace(struct argv_array *env, const char *key, const char *val)

#include "object-store.h"
{

		argv_array_pushf(env, "%s=%s", key, val);
	strbuf_release(&quoted);
	return 4;
		/* free, not destroy, as we never touched the filesystem */
		atexit(remove_tmp_objdir);

#include "sigchain.h"
 */
	 */
 * order. All of these ends_with checks are slightly expensive to do in
static int migrate_paths(struct strbuf *src, struct strbuf *dst)
		strbuf_setlen(dst, dst_len);

	ret = migrate_paths(&src, &dst);

}
	/*
/*
}
	if (!t)
	if (!t)
}
}

	 * If tmp_objdir_destroy() is called by a signal handler, then

static void remove_tmp_objdir(void)
	if (the_tmp_objdir)
		if (!mkdir(dst->buf, 0777)) {
	}
}
 * objects exit early in the first line.
	 * have pre-grown t->path sufficiently so that this
	tmp_objdir_destroy_1(the_tmp_objdir, 1);
		return 0;
		strbuf_addch(&quoted, '"');
	struct strbuf src = STRBUF_INIT, dst = STRBUF_INIT;

		ret |= migrate_one(src, dst);
	env_append(&t->env, ALTERNATE_DB_ENVIRONMENT,
}
		return NULL;
	}
	 */
	int i;
	struct tmp_objdir *t;
	}

	strbuf_init(&t->path, 0);
	return err;

	return tmp_objdir_destroy_1(t, 0);
}
	struct stat st;
	 * doesn't happen in practice.
}
	if (*val == '"' || strchr(val, PATH_SEP)) {
	 * with older parsers which don't understand the quoting.
		return 0;
{


{
	while ((de = readdir(dh)))


	env_replace(&t->env, DB_ENVIRONMENT, absolute_path(t->path.buf));
	 * we should be able to use the strbuf to remove files without
	return t;
	return pack_copy_priority(a) - pack_copy_priority(b);

		tmp_objdir_free(t);

 * more than one, and we can expand later if so.  You can have many such
/*
static int pack_copy_priority(const char *name)
	 * When we are cleaning up due to a signal, we won't bother
 */
 * These env_* functions are for setting up the child environment; the
	if (!old)
	paths.cmp = pack_copy_cmp;
static int migrate_one(struct strbuf *src, struct strbuf *dst)
	closedir(dh);

	tmp_objdir_destroy(the_tmp_objdir);

	strbuf_release(&dst);
	strbuf_addstr(&dst, get_object_directory());
		   absolute_path(get_object_directory()));
	if (!installed_handlers) {

	tmp_objdir_destroy(t);
	return ret;
		return NULL;
static void remove_tmp_objdir_on_signal(int signo)
int tmp_objdir_destroy(struct tmp_objdir *t)
	/*
}
	strbuf_release(&t->path);
	argv_array_init(&t->env);


{
};

	struct strbuf quoted = STRBUF_INIT;
		return 2;
	struct string_list paths = STRING_LIST_INIT_DUP;
		BUG("only one tmp_objdir can be used at a time");

	}
		return -1;
static int tmp_objdir_destroy_1(struct tmp_objdir *t, int on_signal)
		return 0;


	if (read_dir_paths(&paths, src->buf) < 0)
{
 * our signal/atexit cleanup routines.  It's doubtful callers will ever need
{

struct tmp_objdir {
{
		} else if (errno != EEXIST)
static int pack_copy_cmp(const char *a, const char *b)
	size_t src_len = src->len, dst_len = dst->len;
	 * arrived while libc's allocator lock is held.
		return -1;
	if (!mkdtemp(t->path.buf)) {
 */

 * tmp_objdirs simultaneously in many processes, of course.
		strbuf_setlen(src, src_len);
	}
}
		quote_c_style(val, &quoted, NULL, 1);
	int err;
	 * having to call malloc.
	path = xstrfmt("%s/pack", root);
 * We will have a relatively small number of packfiles to order, and loose
{
		strbuf_addch(&quoted, '"');
	for (i = 0; i < paths.nr; i++) {
	env_replace(&t->env, GIT_QUARANTINE_ENVIRONMENT,
	DIR *dh;
	if (t == the_tmp_objdir)

void tmp_objdir_add_as_alternate(const struct tmp_objdir *t)
}
	argv_array_pushf(env, "%s=%s", key, val);
	if (S_ISDIR(st.st_mode)) {
	struct strbuf path;
	/*
	 */
	 */
#include "argv-array.h"
		    absolute_path(t->path.buf));
		return migrate_paths(src, dst);
 * "key". The "append" variant puts our new value at the end of a list,
static void env_append(struct argv_array *env, const char *key, const char *val)
		if (de->d_name[0] != '.')

			return -1;

		const char *name = paths.items[i].string;


	else

	sigchain_pop(signo);
 * Make sure we copy packfiles and their associated metafiles in the correct
	 * Avoid quoting if it's not necessary, for maximum compatibility
	string_list_sort(&paths);
#include "string-list.h"

	if (!starts_with(name, "pack"))
	 * Grow the strbuf beyond any filename we expect to be placed in it.
	if (!t)
	strbuf_addbuf(&src, &t->path);
		return NULL;
	 * freeing memory; it may cause a deadlock if the signal
	the_tmp_objdir = t;
	if (setup_tmp_objdir(t->path.buf)) {
static int migrate_paths(struct strbuf *src, struct strbuf *dst);

}
#include "strbuf.h"
	return t->env.argv;

	strbuf_grow(&t->path, 1024);
{
	static int installed_handlers;



#include "dir.h"
	ret = mkdir(path, 0777);
#include "tmp-objdir.h"
}
	free(t);
		argv_array_pushf(env, "%s=%s%c%s", key, old, PATH_SEP, val);

static void tmp_objdir_free(struct tmp_objdir *t)
	int ret = 0;
#include "quote.h"

	string_list_clear(&paths, 0);
		tmp_objdir_free(t);
	int ret;

	t = xmalloc(sizeof(*t));
			string_list_append(out, de->d_name);
 * "replace" variant overrides the value of any existing variable with that
	return 0;
		return 1;
	const char *old;
	dh = opendir(path);
{
		tmp_objdir_destroy(t);
	return ret;
	if (ends_with(name, ".keep"))
				return -1;
			if (adjust_shared_perm(dst->buf))

{
	if (stat(src->buf, &st) < 0)

