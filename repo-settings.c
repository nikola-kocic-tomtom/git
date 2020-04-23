	UPDATE_DEFAULT_BOOL(r->settings.fetch_write_commit_graph, 0);
	}

		if (!strcasecmp(strval, "keep"))
#define UPDATE_DEFAULT_BOOL(s,v) do { if (s == -1) { s = v; } } while(0)
		UPDATE_DEFAULT_BOOL(r->settings.core_untracked_cache, UNTRACKED_CACHE_KEEP);
	if (!repo_config_get_int(r, "index.version", &value))
	UPDATE_DEFAULT_BOOL(r->settings.gc_write_commit_graph, 1);
	UPDATE_DEFAULT_BOOL(r->settings.core_commit_graph, 1);
	/* Hack for test programs like test-dump-untracked-cache */
	}

			r->settings.core_untracked_cache = UNTRACKED_CACHE_KEEP;
	int value;
	memset(&r->settings, -1, sizeof(r->settings));
		r->settings.index_version = value;

	UPDATE_DEFAULT_BOOL(r->settings.fetch_negotiation_algorithm, FETCH_NEGOTIATION_DEFAULT);
{
		r->settings.gc_write_commit_graph = value;

	if (!repo_config_get_bool(r, "core.commitgraph", &value))
		else

	if (!repo_config_get_bool(r, "feature.experimental", &value) && value) {
		r->settings.fetch_write_commit_graph = value;


	if (!repo_config_get_string(r, "fetch.negotiationalgorithm", &strval)) {
		free(strval);
	/* Defaults */
	if (!repo_config_get_bool(r, "fetch.writecommitgraph", &value))
	if (!repo_config_get_maybe_bool(r, "core.untrackedcache", &value)) {
			r->settings.core_untracked_cache = UNTRACKED_CACHE_WRITE;
}
		UPDATE_DEFAULT_BOOL(r->settings.core_untracked_cache, UNTRACKED_CACHE_WRITE);
		if (!strcasecmp(strval, "skipping"))
#include "repository.h"
			r->settings.fetch_negotiation_algorithm = FETCH_NEGOTIATION_SKIPPING;
	}
		r->settings.core_untracked_cache = UNTRACKED_CACHE_KEEP;
void prepare_repo_settings(struct repository *r)
		return;
		UPDATE_DEFAULT_BOOL(r->settings.index_version, 4);
	if (!repo_config_get_bool(r, "gc.writecommitgraph", &value))
		r->settings.pack_use_sparse = value;
	else
	} else if (!repo_config_get_string(r, "core.untrackedcache", &strval)) {
	if (r->settings.initialized)
	char *strval;
		UPDATE_DEFAULT_BOOL(r->settings.fetch_negotiation_algorithm, FETCH_NEGOTIATION_SKIPPING);

		if (value == 0)
#include "config.h"
	UPDATE_DEFAULT_BOOL(r->settings.pack_use_sparse, 1);
		UPDATE_DEFAULT_BOOL(r->settings.fetch_write_commit_graph, 1);
			r->settings.fetch_negotiation_algorithm = FETCH_NEGOTIATION_DEFAULT;
#include "cache.h"
			r->settings.core_untracked_cache = UNTRACKED_CACHE_REMOVE;


	if (!repo_config_get_bool(r, "feature.manyfiles", &value) && value) {
		r->settings.core_commit_graph = value;
	if (!repo_config_get_bool(r, "pack.usesparse", &value))
	if (ignore_untracked_cache_config)
		else

	}

