{
			room -= sz;
	int binary = 0;
	if (!bufsz)
				break;
	while ((buffer = malloc(bufsz)) == NULL) {
			cp += sz;
}
	algop->final_fn(hash, &ctx);
	const struct git_hash_algo *algop = &hash_algos[algo];
			die("OOPS");
		unsigned room = bufsz;
		this_sz = 0;

		}
			if (sz == 0)
		ssize_t sz, this_sz;
	unsigned bufsz = 8192;
		if (this_sz == 0)
		char *cp = buffer;
		if (bufsz < 1024)
			binary = 1;
			this_sz += sz;
	algop->init_fn(&ctx);
		bufsz /= 2;

		algop->update_fn(&ctx, buffer, this_sz);
	git_hash_ctx ctx;
		fprintf(stderr, "bufsz %u is too big, halving...\n", bufsz);
	exit(0);
			break;
		puts(hash_to_hex_algop(hash, algop));
	}
	if (binary)
	}
			sz = xread(0, cp, room);
	}
			bufsz = strtoul(av[1], NULL, 10) * 1024 * 1024;
		else
	unsigned char hash[GIT_MAX_HEXSZ];
#include "test-tool.h"
	char *buffer;
int cmd_hash_impl(int ac, const char **av, int algo)

		if (!strcmp(av[1], "-b"))
	if (ac == 2) {

	else
		while (room) {
		bufsz = 8192;
#include "cache.h"

	while (1) {
			if (sz < 0)

				die_errno("test-hash");
		fwrite(hash, 1, algop->rawsz, stdout);

