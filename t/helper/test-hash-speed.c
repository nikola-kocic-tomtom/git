{
	if (ac == 2) {
	for (i = 0; i < ARRAY_SIZE(bufsizes); i++) {
	git_hash_ctx ctx;
			 * dominating the runtime with system calls.
{
	exit(0);
}
				end = clock() - initial;
		for (j = 0; ((end - start) / CLOCKS_PER_SEC) < NUM_SECONDS; j++) {
	algo->init_fn(ctx);
		kb_per_sec = kb / (1024 * ((double)end - start) / CLOCKS_PER_SEC);
	unsigned char hash[GIT_MAX_RAWSZ];
	}

	/* Use this as an offset to make overflow less likely. */
	const struct git_hash_algo *algo = NULL;
		}
	unsigned bufsizes[] = { 64, 256, 1024, 8192, 16384 };

	algo->final_fn(final, ctx);
		printf("size %u: %lu iters; %lu KiB; %0.2f KiB/s\n", bufsizes[i], j, kb, kb_per_sec);

				algo = &hash_algos[i];
	void *p;
			compute_hash(algo, &ctx, hash, p, bufsizes[i]);
			}
static inline void compute_hash(const struct git_hash_algo *algo, git_hash_ctx *ctx, uint8_t *final, const void *p, size_t len)
		p = xcalloc(1, bufsizes[i]);
		for (i = 1; i < GIT_HASH_NALGOS; i++) {
		free(p);
				break;
int cmd__hash_speed(int ac, const char **av)
		kb = j * bufsizes[i];
		}
		unsigned long j, kb;
	printf("algo: %s\n", algo->name);
			 */
		start = end = clock() - initial;
			 * Only check elapsed time every 128 iterations to avoid
#include "cache.h"
#include "test-tool.h"
		double kb_per_sec;

	algo->update_fn(ctx, p, len);

}
#define NUM_SECONDS 3

	}
	clock_t initial, start, end;
			if (!strcmp(av[1], hash_algos[i].name)) {

	if (!algo)

	int i;
			if (!(j & 127))
			/*
		die("usage: test-tool hash-speed algo_name");

	initial = clock();
