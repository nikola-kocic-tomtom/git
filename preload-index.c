	if (refresh_flags & REFRESH_PROGRESS && isatty(2)) {
 */
	struct thread_data data[MAX_PARALLEL];
	trace_performance_leave("preload index");
	struct index_state *index = p->index;
		if (ie_match_stat(index, ce, &st, CE_MATCH_RACY_IS_DIRTY|CE_MATCH_IGNORE_FSMONITOR))
			continue;
		ce_mark_uptodate(ce);
			continue;
	cache_def_clear(&cache);
/*
		display_progress(pd->progress, pd->n + last_nr);

		if (ce->ce_flags & CE_FSMONITOR_VALID)
	if (threads > MAX_PARALLEL)
	return NULL;
			    unsigned int refresh_flags)
	pthread_t pthread;
		if (pd.progress)
	struct cache_entry **cep = index->cache + p->offset;

	} while (--nr > 0);
};
			continue;
	int nr, last_nr;
	}
#define MAX_PARALLEL (20)
	if (threads < 2)
	struct index_state *index;
		if (lstat(ce->name, &st))
 * be worth starting a thread.
	}
 * Copyright (C) 2008 Linus Torvalds
	offset = 0;
	struct progress *progress;
		if (p->progress && !(nr & 31)) {

}
	unsigned long n;
	}
		if (ce_stage(ce))
			continue;
		if (ce_skip_worktree(ce))
			continue;
#include "progress.h"
	threads = index->cache_nr / THREAD_COST;
	do {
}
		if (pthread_join(p->pthread, NULL))
struct progress_data {

}
			continue;
			pd->n += last_nr - nr;
		pthread_mutex_lock(&pd->mutex);
{
{
		struct thread_data *p = data+i;
		offset += work;
int repo_read_index_preload(struct repository *repo,
			display_progress(pd->progress, pd->n);
		struct stat st;
			copy_pathspec(&p->pathspec, pathspec);


			die("unable to join threaded lstat");
		int err;
		if (pathspec)
{

		pthread_mutex_unlock(&pd->mutex);

	if (p->progress) {

};
		struct progress_data *pd = p->progress;
#include "dir.h"
	memset(&data, 0, sizeof(data));
	trace_performance_enter();
static void *preload_thread(void *_data)
void preload_index(struct index_state *index,
	int threads, i, work, offset;
 * cap the parallelism to 20 threads, and we want
			continue;
		return;
	for (i = 0; i < threads; i++) {

		   const struct pathspec *pathspec,
	pthread_mutex_t mutex;
	memset(&pd, 0, sizeof(pd));
	struct thread_data *p = _data;
			pthread_mutex_unlock(&pd->mutex);
		}
			continue;
	struct progress_data pd;
	nr = p->nr;
	last_nr = nr;
	stop_progress(&pd.progress);
		if (ce_uptodate(ce))
/*
			pthread_mutex_lock(&pd->mutex);
#include "cache.h"
		if (S_ISGITLINK(ce->ce_mode))
		mark_fsmonitor_valid(index, ce);
		pthread_mutex_init(&pd.mutex, NULL);
		nr = index->cache_nr - p->offset;
		err = pthread_create(&p->pthread, NULL, preload_thread, p);
 * Mostly randomly chosen maximum thread counts: we
		if (!ce_path_match(index, ce, &p->pathspec, NULL))
		p->index = index;
		p->nr = work;
		if (err)

#define THREAD_COST (500)
	if (nr + p->offset > index->cache_nr)
#include "repository.h"

	if ((index->cache_nr > 1) && (threads < 2) && git_env_bool("GIT_TEST_PRELOAD_INDEX", 0))
			die(_("unable to create threaded lstat: %s"), strerror(err));
			last_nr = nr;
#include "fsmonitor.h"

	struct cache_def cache = CACHE_DEF_INIT;

		pd.progress = start_delayed_progress(_("Refreshing index"), index->cache_nr);
 */

		struct thread_data *p = data+i;
#include "config.h"

#include "thread-utils.h"
	preload_index(repo->index, pathspec, refresh_flags);
 * to have at least 500 lstat's per thread for it to
struct thread_data {

		if (threaded_has_symlink_leading_path(&cache, ce->name, ce_namelen(ce)))
	struct progress_data *progress;
		return;
	int offset, nr;

		threads = 2;
	int retval = repo_read_index(repo);
	work = DIV_ROUND_UP(index->cache_nr, threads);
			struct progress_data *pd = p->progress;
		threads = MAX_PARALLEL;
	if (!HAVE_THREADS || !core_preload_index)
			continue;
#include "pathspec.h"
		struct cache_entry *ce = *cep++;
		   unsigned int refresh_flags)
	}
		p->offset = offset;

			    const struct pathspec *pathspec,
	for (i = 0; i < threads; i++) {
	struct pathspec pathspec;
			p->progress = &pd;
	return retval;
