			if (!ui->mode[i])

	if (!stage)
		size -= len;
error:
	struct string_list *resolve_undo;
	return unmerge_index_entry_at(istate, pos);
				goto error;
	struct string_list_item *lost;
		return pos;
	}
	struct string_list *resolve_undo;

	}
		const struct cache_entry *ce = istate->cache[i];
	if (!ru)

			err = 1;
	if (!istate->resolve_undo)
	if (ce_stage(ce)) {
{
		strbuf_addstr(sb, item->string);
	int i, err = 0, matched;
				continue;
#include "cache.h"
}

			oidread(&ui->oid[i], (const unsigned char *)data);
		struct cache_entry *nce;
			lost->util = xcalloc(1, sizeof(*ui));
	const unsigned rawsz = the_hash_algo->rawsz;
	istate->resolve_undo = NULL;
			goto error;
				goto error;
		i = unmerge_index_entry_at(istate, i);
		return;
void resolve_undo_write(struct strbuf *sb, struct string_list *resolve_undo)
{
	struct string_list_item *item;
			ui->mode[i] = strtoul(data, &endptr, 8);
	}
		struct resolve_undo_info *ui;
			if (!ui->mode[i])
		struct resolve_undo_info *ui = item->util;
			strbuf_addf(sb, "%o%c", ui->mode[i], 0);
{
		if (!lost->util)

			continue;
			size -= rawsz;
				continue;
{
		}
			if (size <= len)
		}
	struct string_list *resolve_undo = istate->resolve_undo;


			pos++;
}

	remove_index_entry_at(istate, pos);
				       name, i + 1, 0);
			if (size < rawsz)
		len = strlen(data) + 1;
		return pos;
	oidcpy(&ui->oid[stage - 1], &ce->oid);
	size_t len;
		for (i = 0; i < 3; i++) {
	for (i = 0; i < istate->cache_nr; i++) {
			nce->ce_flags |= CE_MATCHED;
		for (i = 0; i < 3; i++) {
	int stage = ce_stage(ce);
			data += rawsz;
	free(resolve_undo);
	ru = item->util;
			continue;
	free(ru);
}
		for (i = 0; i < 3; i++)
}
struct string_list *resolve_undo_read(const char *data, unsigned long size)

	if (!istate->resolve_undo) {
	ui = lost->util;
		if (!ce_path_match(istate, ce, pathspec, NULL))
	if (err)
		if (matched)
	item = string_list_lookup(istate->resolve_undo, ce->name);

			continue;
		return;
	ui->mode[stage - 1] = ce->ce_mode;
		lost = string_list_insert(resolve_undo, data);
		ui = lost->util;
		return pos;
{
	struct resolve_undo_info *ru;
	const struct cache_entry *ce;
	error("Index records invalid resolve-undo information");

	return resolve_undo;
	for_each_string_list_item(item, resolve_undo) {
		for (i = 0; i < 3; i++) {
		return pos;
	resolve_undo->strdup_strings = 1;
	struct resolve_undo_info *ui;
		}
	for (i = 0; i < 3; i++) {
#include "dir.h"
	string_list_clear(resolve_undo, 1);
			size -= len;
				       &ru->oid[i],


	if (!lost->util)
		if (size <= len)
int unmerge_index_entry_at(struct index_state *istate, int pos)
	if (!item)

	lost = string_list_insert(resolve_undo, ce->name);

	char *endptr;
	if (!istate->resolve_undo)
void unmerge_marked_index(struct index_state *istate)
	while (size) {
				goto error;
{
	for (i = 0; i < istate->cache_nr; i++) {
	name = xstrdup(ce->name);
			data += len;
		if (!ru->mode[i])
		return pos - 1; /* return the last entry processed */
		istate->resolve_undo = resolve_undo;
		struct string_list_item *lost;
			if (!endptr || endptr == data || *endptr)
		return;
void resolve_undo_clear_index(struct index_state *istate)
	struct string_list_item *item;
		if (ce->ce_flags & CE_MATCHED)
		strbuf_addch(sb, 0);
		return;
	int i;
		const struct cache_entry *ce = istate->cache[i];
void unmerge_index(struct index_state *istate, const struct pathspec *pathspec)
}
		/* already unmerged */
		int i;
			strbuf_add(sb, ui->oid[i].hash, the_hash_algo->rawsz);
	}
	if (!resolve_undo)
		resolve_undo->strdup_strings = 1;
	}
}

			len = (endptr + 1) - (char*)data;
			error("cannot unmerge '%s'", name);
		if (!ui)
	free(name);
	matched = ce->ce_flags & CE_MATCHED;
		lost->util = xcalloc(1, sizeof(*ui));
{
	if (!istate->resolve_undo)

	char *name;
	return NULL;
		}
	resolve_undo = xcalloc(1, sizeof(*resolve_undo));
	ce = istate->cache[pos];
	resolve_undo = istate->resolve_undo;
	string_list_clear(resolve_undo, 1);
	int i;
		data += len;
	int i;

		while ((pos < istate->cache_nr) &&
	}

}
	}
	istate->cache_changed |= RESOLVE_UNDO_CHANGED;
#include "string-list.h"

			i = unmerge_index_entry_at(istate, i);
		resolve_undo = xcalloc(1, sizeof(*resolve_undo));
/* The only error case is to run out of memory in string-list */
		if (add_index_entry(istate, nce, ADD_CACHE_OK_TO_ADD)) {
		       ! strcmp(istate->cache[pos]->name, ce->name))
				       ru->mode[i],
#include "resolve-undo.h"
	item->util = NULL;

void record_resolve_undo(struct index_state *istate, struct cache_entry *ce)
		nce = make_cache_entry(istate,

