		"test-tool lazy-init-name-hash (-s | -m) [-c c]",

	int i;
	int nr_threads_used;
		t2 = getnanotime();
		OPT_INTEGER('a', "analyze", &analyze, "analyze different multi sizes"),
				   ((double)(t2 - t1))/1000000000,
	uint64_t sum = 0;
		NULL
		printf("dir %08x %7d %s\n", dir->ent.hash, dir->nr, dir->name);
	read_cache();
		OPT_INTEGER('c', "count", &count, "number of passes"),
	int i;
			die("cannot combine dump, perf, or analyze");
	/* Stolen from name-hash.c */
				ent /* member name */)
		return 0;
	while (1) {
		return 0;
		OPT_BOOL('p', "perf", &perf, "compare single vs multi"),
				   ((double)(t2 - t1))/1000000000,
			analyze_step = analyze;
		time_runs(0);
	/*
	avg = sum / count;
{

				printf("avg [size %8d] [single %f] %c [multi %f %d]\n",
			   (try_threaded) ? "multi" : "single");
			read_cache();
		uint64_t sum_single = 0;
}
					   nr,
		read_cache();
		"test-tool lazy-init-name-hash -s -m [-c c]",
	struct hashmap_iter iter_cache;
			t2m = getnanotime();
	int cache_nr_limit;
 * mode and verify that both single and multi produce the same set.
		for (i = 0; i < count; i++) {
	struct dir_entry *dir;

			die("analyze must be at least 500");
					   nr, ((double)(t2s - t1s))/1000000000);
					   (double)avg_single/1000000000);
	}
	if (count > 1)

			die("cannot use single or multi with perf");
 * If you sort the result, you can compare it with the other type
	struct dir_entry {
		die("require either -s or -m or both");
 */
	if (multi)
			die("non-threaded code path used");
 * try to find a good value for the multi-threaded criteria.
{

	discard_cache();
			discard_cache();
		printf("avg %f %s\n",
	uint64_t avg;
		if (!nr_threads_used)
 */
		if (nr > cache_nr_limit)


		int nr;

int cmd__lazy_init_name_hash(int argc, const char **argv)
		if (analyze < 500)
		OPT_BOOL('m', "multi", &multi, "run multi-threaded code"),
	read_cache();
					   (((t2s - t1s) < (t2m - t1m)) ? '<' : '>'),
	 */
static int count = 1;
			die("multi is slower");
	const char *usage[] = {

		if (single || multi)



				   ((double)(t1 - t0))/1000000000,
			die("cannot use single or multi with analyze");
					   ((double)(t2m - t1m))/1000000000,
	uint64_t avg_single, avg_multi;
		"test-tool lazy-init-name-hash -a a [--step s] [-c c]",


				printf("avg [size %8d] [single %f]\n",
					   (avg_single < avg_multi ? '<' : '>'),
{

/*
		if (count > 1) {
	ignore_case = 1;

			die("count not valid with dump");
			t2s = getnanotime();
static int analyze;
 */

		if (try_threaded && !nr_threads_used)
		}
			printf("%f %f %d single\n",
		if (!single && !multi)

	}
		if (nr_threads_used)
		avg_single = time_runs(0);
		fflush(stdout);
}
		return 0;
			else
static void analyze_run(void)
		if (nr >= cache_nr_limit)
	struct option options[] = {
		OPT_INTEGER(0, "step", &analyze_step, "analyze step factor"),
	prefix = setup_git_directory();
#include "test-tool.h"
	return avg;
		struct dir_entry *parent;
/*
			fflush(stdout);
		uint64_t sum_multi = 0;

			nr = cache_nr_limit;
	int nr_threads_used = 0;

	}
		if (perf || analyze > 0)
		t0 = getnanotime();
static int dump;
	 * istate->dir_hash is only created when ignore_case is set.
	if (!single && !multi)
			t1s = getnanotime();
		printf("name %08x %s\n", ce->ent.hash, ce->name);
			sum_single += (t2s - t1s);
			else
					   (double)avg_single/1000000000,
{
			read_cache();
 * Dump the contents of the "dir" and "name" hash tables to stdout.

			printf("%f %f %d multi %d\n",
			t1m = getnanotime();
		"test-tool lazy-init-name-hash -d (-s | -m)",
	argc = parse_options(argc, argv, prefix, options, usage, 0);
static uint64_t time_runs(int try_threaded)
			the_index.cache_nr = cache_nr_limit;
	};
				   the_index.cache_nr);
	hashmap_for_each_entry(&the_index.dir_hash, &iter_dir, dir,
			return;
				printf("    [size %8d] [single %f] %c [multi %f %d]\n",
			   (double)avg/1000000000,
		if (!analyze_step)
		if (count > 1)
	if (perf) {
			die("cannot use both single and multi with dump");
static int multi;
		if (single || multi)


	};
	cache_nr_limit = the_index.cache_nr;
	}
			die("dump requires either single or multi");
	struct cache_entry *ce;
	if (analyze) {
		dump_run();
 * Run the single or multi threaded version "count" times and
		nr_threads_used = test_lazy_init_name_hash(&the_index, try_threaded);
		else
		avg_multi = time_runs(1);
				   the_index.cache_nr,
					   nr,
	for (i = 0; i < count; i++) {
		if (analyze > 0)

		analyze_run();
/*
			if (!nr_threads_used)
				   ((double)(t1 - t0))/1000000000,
	return 0;
				ent /* member name */)
			sum_multi += (t2m - t1m);
			avg_multi = sum_multi / count;
			the_index.cache_nr = nr; /* cheap truncate of index */
					   nr,
		test_lazy_init_name_hash(&the_index, 0);
		OPT_BOOL('s', "single", &single, "run single-threaded code"),

	hashmap_for_each_entry(&the_index.name_hash, &iter_cache, ce,
		if (avg_multi > avg_single)
		uint64_t avg_multi;
		sum += (t2 - t1);
}
	if (single)
			the_index.cache_nr = nr; /* cheap truncate of index */
		char name[FLEX_ARRAY];

			if (!nr_threads_used)
	int nr;

	const char *prefix;
	uint64_t t1s, t1m, t2s, t2m;
			the_index.cache_nr = cache_nr_limit;
	}
	};
					   (double)avg_multi/1000000000,
	}
					   ((double)(t2s - t1s))/1000000000,

	uint64_t t0, t1, t2;
}
		unsigned int namelen;
		discard_cache();
					   nr_threads_used);
			die("non-threaded code path used");
		OPT_END(),

	if (single) {
		OPT_BOOL('d', "dump", &dump, "dump hash tables"),
			die("cannot combine dump, perf, or analyze");

		time_runs(1);

			nr_threads_used = test_lazy_init_name_hash(&the_index, 1);
					   nr_threads_used);
	} else {
static void dump_run(void)
			test_lazy_init_name_hash(&the_index, 0);
static int perf;
	struct hashmap_iter iter_dir;
				   nr_threads_used);
			avg_single = sum_single / count;
static int analyze_step;
		uint64_t avg_single;
		int nr_threads_used = test_lazy_init_name_hash(&the_index, 1);
#include "cache.h"

				printf("    [size %8d] [single %f]   non-threaded code path used\n",

 * Try a series of runs varying the "istate->cache_nr" and
		struct hashmap_entry ent;
	if (dump) {
static int single;
		nr += analyze_step;
			fflush(stdout);
	discard_cache();

		if (single && multi)
		"test-tool lazy-init-name-hash -p [-c c]",
			discard_cache();
		}
		t1 = getnanotime();
	nr = analyze;
#include "parse-options.h"
 * report on the time taken.
