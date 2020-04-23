void get_reflog_message(struct strbuf *sb,
	int recno = -1;
	info = &commit_reflog->reflogs->items[commit_reflog->recno+1];
	enum selector_type {
			}
	info = &commit_reflog->reflogs->items[commit_reflog->recno+1];
		if (reflogs->nr == 0) {
}

	if (reflog_info && reflog_info->last_commit_reflog) {
		if (timestamp >= array->items[i].timestamp)
}
{
		char *email;
				free(branch);
			if (!branch)
	return 0;
	item->email = xstrdup(email);

}
		struct commit_reflog *log = walk->logs[i];
	} else {
	if (!array)
		}
				branch = b;
{
	struct reflog_info *info;
#include "diff.h"


	char *branch, *at = strchr(name, '@');

		const char *name;
	struct commit_reflog *commit_reflog = reflog_info->last_commit_reflog;
}
	for (i = array->nr - 1; i >= 0; i--)
		if (!reflogs || reflogs->nr == 0) {
			 int shorten)
		printed_ref = commit_reflog->reflogs->ref;


		branch[at - name] = '\0';
	struct string_list complete_reflogs;
struct complete_reflogs {
}
	struct commit_reflog *commit_reflog = reflog_info->last_commit_reflog;
			else if (ret == 1) {
			for_each_reflog_ent(refname, read_one_reflog, reflogs);
		}
}
			return (struct commit *)obj;
	info = &commit_reflog->reflogs->items[commit_reflog->recno+1];
}
	return info->timestamp;
};
	if (!commit_reflog)
void init_reflog_walk(struct reflog_walk_info **info)
		void *name_to_free;
			continue;
	item->timestamp = timestamp;
{
		string_list_insert(&info->complete_reflogs, branch)->util

	struct reflog_info *item;
			selector = SELECTOR_INDEX;
	for (i = 0; i < array->nr; i++) {
{

	struct commit_reflog *best = NULL;
	struct commit_reflog *last_commit_reflog;
	strbuf_addf(sb, "%s@{", printed_ref);
	if (len > 0)
	array->nr++;
		return;
		char *message;
	commit_reflog->reflogs = reflogs;
}

	} else
		len--; /* strip away trailing newline */
		return;
		if (commit_reflog->recno < 0) {
		recno = 0;
		struct commit *commit, const char *name)

		if (!commit)

	const char *printed_ref;
	timestamp_t timestamp)
			free(refname);
	enum selector_type selector = SELECTOR_NONE;
	}
				free(b);
	} selector;
	struct complete_reflogs *reflogs;
	}

			       selector.buf, info->email, info->message);
		strbuf_addstr(sb, show_date(info->timestamp, info->tz, dmode));

static timestamp_t log_timestamp(struct commit_reflog *log)
		SELECTOR_DATE
	if (!commit_reflog)
	else {
};
const char *get_reflog_ident(struct reflog_walk_info *reflog_info)
		}
	struct commit *best_commit = NULL;
	ALLOC_GROW(array->items, array->nr + 1, array->alloc);
	branch = xstrdup(name);

{
	free(array->ref);
	if (!commit_reflog)
}
		timestamp_t timestamp;
		get_reflog_selector(&selector, reflog_info, dmode, force_date, 0);
	} else
		commit_reflog->recno = reflogs->nr - recno - 1;
	int recno;
	info->logs[info->nr++] = commit_reflog;
	item = array->items + array->nr;
		info = &commit_reflog->reflogs->items[commit_reflog->recno+1];
	} *items;
struct commit_reflog {
	return NULL;
		struct strbuf selector = STRBUF_INIT;
		const char *message, void *cb_data)
		if (*branch == '\0') {
		else {
		char *ep;
			free(name_to_free);

	}
	if (reflogs->nr == 0) {
	if (best) {
#include "commit.h"
		if (*ep != '}') {


		const char *email, timestamp_t timestamp, int tz,
	return reflogs;

			free(commit_reflog);
		if (!best || log_timestamp(log) > log_timestamp(best)) {
	size_t nr, alloc;
		for_each_reflog_ent(refname, read_one_reflog, reflogs);
			 const struct date_mode *dmode, int force_date,
#include "revision.h"
					   &oid, &b);
			    - 2 - commit_reflog->recno);
	if (recno < 0) {
	for (i = 0; i < walk->nr; i++) {
			 const struct date_mode *dmode, int force_date)
{
}
	return NULL;
	strbuf_add(sb, info->message, len);
	struct commit_reflog **logs;
		if (name) {
			return i;
{
	timestamp_t timestamp = 0;
	const char *short_ref;
	if (reflogs->nr == 0) {
	if (commit->object.flags & UNINTERESTING)
		return;
		int tz;
		name = name_to_free = resolve_refdup(ref, RESOLVE_REF_READING,
	*info = xcalloc(1, sizeof(struct reflog_walk_info));
	strbuf_addch(sb, '}');

			return -1;
	struct reflog_info *info;
	(*info)->complete_reflogs.strdup_strings = 1;
	struct reflog_info {
}
	ALLOC_GROW(info->logs, info->nr + 1, info->alloc);
		char *refname = xstrfmt("refs/%s", ref);
{
	struct commit_reflog *commit_reflog;
		}
	}

		struct object *obj = parse_object(the_repository,
{
			if (ret > 1)
		}

	size_t len;

		struct reflog_info *entry = &log->reflogs->items[log->recno];
		if (!commit_reflog->reflogs->short_ref)
		if (obj && obj->type == OBJ_COMMIT)


	if (shorten) {
	} else {

		}
			recno = -1;

{
	return log->reflogs->items[log->recno].timestamp;
		SELECTOR_NONE,

		reflogs = read_complete_reflog(branch);

	return !info || !info->nr;

	if (!commit_reflog)


static struct commit *next_reflog_commit(struct commit_reflog *log)
	char *ref;
	oidcpy(&item->ooid, ooid);
	item = string_list_lookup(&info->complete_reflogs, branch);
		commit_reflog->recno = get_reflog_recno_by_time(reflogs, timestamp);
	free(array);
			struct object_id oid;

{
		return best_commit;
			int ret = dwim_log(branch, strlen(branch),
	    (commit_reflog->selector == SELECTOR_NONE && force_date)) {
#include "reflog-walk.h"
			char *b;
			best_commit = commit;
		reflogs = item->util;
			timestamp = approxidate(at + 2);

		recno = strtoul(at + 2, &ep, 10);
struct commit *next_reflog_entry(struct reflog_walk_info *walk)
				reflogs = read_complete_reflog(branch);


	reflogs->ref = xstrdup(ref);
	struct complete_reflogs *reflogs;
	struct complete_reflogs *reflogs =
	item->tz = tz;
{
		printed_ref = commit_reflog->reflogs->short_ref;
	struct reflog_info *info;
		}
			free_complete_reflog(reflogs);
				die("no current branch");
			= reflogs;
	if (commit_reflog->selector == SELECTOR_DATE ||
			return -1;
	struct string_list_item *item;

		struct reflog_info *info;
		die("cannot walk reflogs for %s", name);
	}
	size_t i;
	item->message = xstrdup(message);
}
	free(array->items);
			branch = resolve_refdup("HEAD", 0, NULL, NULL);
	commit_reflog->selector = selector;
	oidcpy(&item->noid, noid);
static void free_complete_reflog(struct complete_reflogs *array)
	free(branch);

		walk->last_commit_reflog = best;
						  &entry->noid);
		if (!reflogs || reflogs->nr == 0) {
			for_each_reflog_ent(name, read_one_reflog, reflogs);

		info = &commit_reflog->reflogs->items[commit_reflog->recno+1];
	struct complete_reflogs *array = cb_data;

			selector = SELECTOR_DATE;

		free(refname);
		}
		xcalloc(1, sizeof(struct complete_reflogs));
		SELECTOR_INDEX,
static struct complete_reflogs *read_complete_reflog(const char *ref)
	return -1;
		struct commit_reflog *commit_reflog = reflog_info->last_commit_reflog;
#include "refs.h"
#include "string-list.h"
	}
		struct object_id ooid, noid;
};
int add_reflog_for_walk(struct reflog_walk_info *info,

	struct commit_reflog *commit_reflog = reflog_info->last_commit_reflog;
		return NULL;
	return info->email;
	if (at && at[1] == '{') {
struct reflog_walk_info {
			struct reflog_walk_info *reflog_info)
		free(array->items[i].email);
						     NULL, NULL);
				= shorten_unambiguous_ref(commit_reflog->reflogs->ref, 0);
		strbuf_release(&selector);
		strbuf_addf(sb, "%d", commit_reflog->reflogs->nr
	struct reflog_info *info;
	int nr, alloc;
	commit_reflog = xcalloc(1, sizeof(struct commit_reflog));

		else
			printf("Reflog: %s (%s)\nReflog message: %s",
timestamp_t get_reflog_timestamp(struct reflog_walk_info *reflog_info)
			refname = xstrfmt("refs/heads/%s", ref);
			printf("%s: %s", selector.buf, info->message);
}
			free(branch);
	struct commit_reflog *commit_reflog = reflog_info->last_commit_reflog;
		if (oneline) {
}
}
			free(branch);
	return 0;
		free(array->items[i].message);

{
	}
void get_reflog_selector(struct strbuf *sb,
int reflog_walk_empty(struct reflog_walk_info *info)
{
	}
		}
static int get_reflog_recno_by_time(struct complete_reflogs *array,
	int i;


	}
		best->recno--;
void show_reflog_message(struct reflog_walk_info *reflog_info, int oneline,
		return 0;
	len = strlen(info->message);
	if (item)
	int i;
	}
#include "cache.h"
	for_each_reflog_ent(ref, read_one_reflog, reflogs);
			best = log;
		struct commit *commit = next_reflog_commit(log);
static int read_one_reflog(struct object_id *ooid, struct object_id *noid,
		}
{
				free_complete_reflog(reflogs);
			 struct reflog_walk_info *reflog_info,
	for (; log->recno >= 0; log->recno--) {
			commit_reflog->reflogs->short_ref
