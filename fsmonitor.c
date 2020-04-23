		timestamp = get_be64(index);
			} else if (hook_version < 0) {
}
		break;

		istate->fsmonitor_last_update = strbuf_detach(&last_update, NULL);
			istate->untracked->use_fsmonitor = 1;

		BUG("fsmonitor_dirty has more entries than the index (%"PRIuMAX" >= %u)",
	strbuf_addstr(sb, istate->fsmonitor_last_update);
	/* Now that we've updated istate, save the last_update_token */
				/*
	ret = ewah_read_mmap(fsmonitor_dirty, index, ewah_size);
		return error("failed to parse ewah bitmap reading fsmonitor index extension");

				} else {
				istate->cache[i]->ce_flags &= ~CE_FSMONITOR_VALID;
		/* If we're going to check every file, ensure we save the results */
				BUG("fsmonitor_dirty has more entries than the index (%"PRIuMAX" > %u)",
	int fixup = 0;
	ewah_serialize_strbuf(istate->fsmonitor_dirty, sb);

	/*
				 * only the the chars up to the first NUL

}
		}
				continue;
	uint32_t hdr_version;
	} else {
	}
	ce->ce_flags &= ~CE_FSMONITOR_VALID;

	 */
}
			istate->cache_changed |= FSMONITOR_CHANGED;
			if (buf[i] != '\0')
					hook_version = HOOK_INTERFACE_VERSION2;

	if (!core_fsmonitor || istate->fsmonitor_has_run_once)
		/* reset the fsmonitor state */
				strbuf_addstr(&last_update_token, buf);

			fsmonitor_refresh_callback(istate, buf + bol);
	 * and check it all.
	unsigned long sz)
			core_fsmonitor, query_success ? "success" : "failure");
			/* Mark all entries valid */
	unsigned int i;

	if (pos >= istate->cache_nr)
		return error("bad fsmonitor version %d", hdr_version);
{
		}
		FREE_AND_NULL(istate->fsmonitor_last_update);
			skipped++;
					strbuf_addf(&last_update_token, "%"PRIu64"", last_update);
	index += sizeof(uint32_t);

	/*
	FREE_AND_NULL(istate->fsmonitor_last_update);
		strbuf_addf(&last_update, "%"PRIu64"", getnanotime());

	fsmonitor_dirty = ewah_new();
void remove_fsmonitor(struct index_state *istate)
{
			istate->untracked->use_fsmonitor = 1;
	int hook_version;
		break;
#include "run-command.h"

	uint32_t ewah_size = 0;
{
		}
	last_update = getnanotime();
	return 0;
	 */
	}
static int query_fsmonitor(int version, const char *last_update, struct strbuf *query_result)
			}
			if (istate->cache[i]->ce_flags & CE_FSMONITOR_VALID) {
	/* a fsmonitor process can return '/' to indicate all entries are invalid */
	uint64_t timestamp;
			refresh_fsmonitor(istate);
	trace_printf_key(&trace_fsmonitor, "refresh fsmonitor");
		/* Mark all entries invalid */
void write_fsmonitor_extension(struct strbuf *sb, struct index_state *istate)

#define INDEX_EXTENSION_VERSION1	(1)
int read_fsmonitor_extension(struct index_state *istate, const void *data,
static void fsmonitor_refresh_callback(struct index_state *istate, const char *name)

void tweak_fsmonitor(struct index_state *istate)
	uint32_t hdr_version;
		if (hook_version == HOOK_INTERFACE_VERSION1) {
#include "config.h"
}
		"Must be 1 or 2.", hook_version);
			ewah_set(istate->fsmonitor_dirty, i - skipped);
		}


		trace_printf_key(&trace_fsmonitor, "add fsmonitor");
		    (uintmax_t)istate->fsmonitor_dirty->bit_size, istate->cache_nr);
	unsigned int i;

	    istate->fsmonitor_dirty->bit_size > istate->cache_nr)
	    istate->fsmonitor_dirty->bit_size > istate->cache_nr)

	istate->fsmonitor_dirty = ewah_new();
	strbuf_add(sb, &ewah_size, sizeof(uint32_t)); /* we'll fix this up later */
	int pos = index_name_pos(istate, name, strlen(name));
	hook_version = fsmonitor_hook_version();
			if (query_success) {
	trace_printf_key(&trace_fsmonitor, "fsmonitor_refresh_callback '%s'", name);

	const char *index = data;
	case 1: /* true */
void refresh_fsmonitor(struct index_state *istate)
	if (pos >= 0) {
	untracked_cache_invalidate_path(istate, name, 0);
	if (git_config_get_int("core.fsmonitorhookversion", &hook_version))
				 */
}
		return;
struct trace_key trace_fsmonitor = TRACE_KEY_INIT(FSMONITOR);
				 * analysis was suggesting to use strbuf_addbuf
	/*
	} else {
	struct strbuf last_update_token = STRBUF_INIT;
		if (istate->cache[i]->ce_flags & CE_REMOVE)
{
	return capture_command(&cp, query_result, 1024);
	struct cache_entry *ce;
	if (!istate->split_index &&
{

			ewah_each_bit(istate->fsmonitor_dirty, fsmonitor_ewah_callback, istate);
		return -1;

/*
	strbuf_add(sb, &hdr_version, sizeof(uint32_t));
 */
			}
	if (istate->fsmonitor_last_update) {
	struct strbuf last_update = STRBUF_INIT;
	cp.use_shell = 1;
		break;
		refresh_fsmonitor(istate);
	uint32_t ewah_size;

		trace_printf_key(&trace_fsmonitor, "fsmonitor process '%s' returned %s",

	istate->fsmonitor_last_update = strbuf_detach(&last_update_token, NULL);

				    (uintmax_t)istate->fsmonitor_dirty->bit_size, istate->cache_nr);

#define HOOK_INTERFACE_VERSION1		(1)
	struct ewah_bitmap *fsmonitor_dirty;
	}

		/* We only want to run the post index changed hook if we've actually changed entries, so keep track
{
}

	 * changes since that token, else assume everything is possibly dirty
	 * This could be racy so save the date/time now and query_fsmonitor
}

		if (hook_version == -1 || hook_version == HOOK_INTERFACE_VERSION2) {
		if (is_cache_changed)

	if (query_success && query_result.buf[bol] != '/') {
		    (uintmax_t)pos, istate->cache_nr);
	int query_success = 0, hook_version = -1;
				}

	if (istate->fsmonitor_dirty) {
			}
				if (hook_version < 0)
		return -1;
{

	} else if (hdr_version == INDEX_EXTENSION_VERSION2) {
		 * if we actually changed entries or not */
	}
				istate->fsmonitor_last_update, &query_result);


		if (istate->untracked)

		ewah_free(fsmonitor_dirty);
	 * If we have a last update token, call query_fsmonitor for the set of

	default: /* unknown value: do nothing */
			for (i = 0; i < istate->cache_nr; i++) {
}
	ewah_start = sb->len;

	return -1;
			add_untracked_cache(istate);
		return hook_version;
			istate->cache[i]->ce_flags &= ~CE_FSMONITOR_VALID;
	ewah_free(istate->fsmonitor_dirty);

			/* Mark all previously saved entries as dirty */
{
	/* fix up size field */
	if (hdr_version == INDEX_EXTENSION_VERSION1) {
	switch (fsmonitor_enabled) {
		/* reset the untracked cache */
	char *buf;
	cp.dir = get_git_work_tree();
#define INDEX_EXTENSION_VERSION2	(2)
	if (istate->fsmonitor_last_update) {
			if (istate->fsmonitor_dirty->bit_size > istate->cache_nr)
		int is_cache_changed = 0;
	if (sz < sizeof(uint32_t) + 1 + sizeof(uint32_t))


	put_be32(&hdr_version, INDEX_EXTENSION_VERSION2);
	 * Mark the untracked cache dirty even if it wasn't found in the index

				 * but we don't want to copy the entire strbuf

	}


	}
				buf = query_result.buf;
	size_t bol = 0; /* beginning of line */
		for (i = bol; i < query_result.len; i++) {
	argv_array_push(&cp.args, core_fsmonitor);
	struct strbuf query_result = STRBUF_INIT;


					query_success = 0;
				if (!last_update_token.len) {
		ce->ce_flags &= ~CE_FSMONITOR_VALID;
	ce = istate->cache[pos];
				istate->cache[i]->ce_flags |= CE_FSMONITOR_VALID;
	index += sizeof(uint32_t);
		istate->cache_changed |= FSMONITOR_CHANGED;
{
	argv_array_pushf(&cp.args, "%d", version);
#include "ewah/ewok.h"
		for (i = 0; i < istate->cache_nr; i++) {
		buf = query_result.buf;
	if (!istate->split_index &&
	unsigned int i, skipped = 0;
	if (ret != ewah_size) {
		if (fsmonitor_enabled) {
	strbuf_addch(sb, 0); /* Want to keep a NUL */
	case -1: /* keep: do nothing */
		}

			bol = i + 1;
}
	struct strbuf last_update = STRBUF_INIT;
		for (i = 0; i < istate->cache_nr; i++)
}
		index += last_update.len + 1;


		remove_fsmonitor(istate);
		/* Update the fsmonitor state */
	if (!core_fsmonitor)
void add_fsmonitor(struct index_state *istate)
			query_success = !query_fsmonitor(HOOK_INTERFACE_VERSION2,
 * Call the query-fsmonitor hook passing the last update token of the saved results.

	hdr_version = get_be32(index);
	uint64_t last_update;
	istate->fsmonitor_dirty = NULL;

		BUG("fsmonitor_dirty has more entries than the index (%"PRIuMAX" > %u)",
	if (hook_version == HOOK_INTERFACE_VERSION1)

	uint32_t ewah_start;
				istate->fsmonitor_last_update, &query_result);

}
	ewah_size = get_be32(index);
	put_be32(&ewah_size, sb->len - ewah_start);
#include "strbuf.h"
		strbuf_addstr(&last_update, index);
		index += sizeof(uint64_t);
				if (!last_update_token.len)
#define HOOK_INTERFACE_VERSION2		(2)
	case 0: /* false */
	}
	}
			istate->untracked->use_fsmonitor = 0;
					bol = last_update_token.len + 1;
		trace_printf_key(&trace_fsmonitor, "remove fsmonitor");
	int ret;
		BUG("fsmonitor_dirty has more entries than the index (%"PRIuMAX" > %u)",
	}
	trace_printf_key(&trace_fsmonitor, "read fsmonitor extension successful");
	unsigned int i;

{
		if (bol < query_result.len)
	istate->fsmonitor_has_run_once = 1;
	istate->fsmonitor_last_update = strbuf_detach(&last_update, NULL);
		}
#include "cache.h"
	argv_array_pushf(&cp.args, "%s", last_update);

			query_success = !query_fsmonitor(HOOK_INTERFACE_VERSION1,
		strbuf_addf(&last_update, "%"PRIu64"", timestamp);
					warning("Empty last update token.");
#include "dir.h"
static int fsmonitor_hook_version(void)
void fill_fsmonitor_bitmap(struct index_state *istate)
	if (!istate->fsmonitor_last_update) {
	    hook_version == HOOK_INTERFACE_VERSION2)
		struct cache_entry *ce = istate->cache[pos];
{
		ewah_free(istate->fsmonitor_dirty);
		    (uintmax_t)istate->fsmonitor_dirty->bit_size, istate->cache_nr);
	for (i = 0; i < istate->cache_nr; i++) {
		istate->fsmonitor_dirty = NULL;
				 * Need to use a char * variable because static
		/* Now mark the untracked cache for fsmonitor usage */



	struct index_state *istate = (struct index_state *)is;

		if (istate->untracked) {
				is_cache_changed = 1;
	trace_printf_key(&trace_fsmonitor, "write fsmonitor extension successful");
		break;
		add_fsmonitor(istate);
	memcpy(sb->buf + fixup, &ewah_size, sizeof(uint32_t));
	 * as it could be a new untracked file.
	int fsmonitor_enabled = git_config_get_fsmonitor();
	istate->fsmonitor_dirty = fsmonitor_dirty;
#include "fsmonitor.h"
	fixup = sb->len;
	if (hook_version == HOOK_INTERFACE_VERSION1 ||
		else if (!(istate->cache[i]->ce_flags & CE_FSMONITOR_VALID))
		if (istate->untracked)
	 * should be inclusive to ensure we don't miss potential changes.
		istate->cache_changed |= FSMONITOR_CHANGED;
static void fsmonitor_ewah_callback(size_t pos, void *is)
	 */

	strbuf_release(&query_result);
				hook_version = HOOK_INTERFACE_VERSION1;
			fsmonitor_refresh_callback(istate, buf + bol);
		/* Mark all entries returned by the monitor as dirty */
	}
	warning("Invalid hook version '%i' in core.fsmonitorhookversion. "
		return error("corrupt fsmonitor extension (too short)");
		trace_performance_since(last_update, "fsmonitor process '%s'", core_fsmonitor);
	struct child_process cp = CHILD_PROCESS_INIT;
		strbuf_addf(&last_update_token, "%"PRIu64"", last_update);

				 * First entry will be the last update token

