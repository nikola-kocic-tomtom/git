	if (is_absolute_path(path))
		errno = saved_errno;
	char **path = data;
			 "setup: chdir from '%s' to '%s'",
#include "strbuf.h"
				 name, *path);
	chdir_notify_callback cb;
	const char *name;
			const char *old_cwd,
	ret = xstrdup(remove_leading_path(full, new_cwd));
}
		int saved_errno = errno;
		struct chdir_notify_entry *e =

}

void chdir_notify_reparent(const char *name, char **path)
char *reparent_relative_path(const char *old_cwd,
}
	e->data = data;

			void *data)
		return xstrdup(path);

{
		strbuf_release(&old_cwd);
	if (!tmp)
	}
	full = xstrfmt("%s/%s", old_cwd, path);

};

#include "list.h"
}
#include "cache.h"
{
	}

	list_add_tail(&e->list, &chdir_notify_entries);
	char *ret, *full;
		e->cb(e->name, old_cwd.buf, new_cwd, e->data);

		return -1;
	return 0;
{
	void *data;
	if (strbuf_getcwd(&old_cwd) < 0)
{
			list_entry(pos, struct chdir_notify_entry, list);

			const char *new_cwd,
	free(full);
#include "chdir-notify.h"
	struct list_head *pos;
			   void *data)
	struct chdir_notify_entry *e = xmalloc(sizeof(*e));
	if (chdir(new_cwd) < 0) {
		trace_printf_key(&trace_setup_key,
				 "setup: reparent %s to '%s'",

	e->name = name;
			   chdir_notify_callback cb,

	e->cb = cb;
	strbuf_release(&old_cwd);
	list_for_each(pos, &chdir_notify_entries) {
int chdir_notify(const char *new_cwd)

			     const char *new_cwd,
	struct strbuf old_cwd = STRBUF_INIT;
struct chdir_notify_entry {

}
	free(tmp);
		return;
			     const char *path)
	}
	struct list_head list;
static LIST_HEAD(chdir_notify_entries);
			 old_cwd.buf, new_cwd);
{
		return -1;
	if (name) {

	chdir_notify_register(name, reparent_cb, path);
	return ret;
	char *tmp = *path;
	trace_printf_key(&trace_setup_key,
static void reparent_cb(const char *name,
void chdir_notify_register(const char *name,


	*path = reparent_relative_path(old_cwd, new_cwd, tmp);
