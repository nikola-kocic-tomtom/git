			if (pos < 0)
	int i, cnt = 1;
				die("%s not in index", name);
	return 0;
	}
		argv++;
		}
	if (argc > 1 && skip_prefix(argv[1], "--print-and-refresh=", &name)) {
				      NULL, NULL, NULL);
	if (argc == 2)
	}
int cmd__read_cache(int argc, const char **argv)
			       ce_uptodate(the_index.cache[pos]) ? "" : " not");
	setup_git_directory();
			pos = index_name_pos(&the_index, name, strlen(name));

			write_file(name, "%d\n", i);
			refresh_index(&the_index, REFRESH_QUIET,
			int pos;

{
	for (i = 0; i < cnt; i++) {
		if (name) {

		discard_cache();
		read_cache();
	const char *name = NULL;
		argc--;
#include "test-tool.h"
	git_config(git_default_config, NULL);
#include "cache.h"
			printf("%s is%s up to date\n", name,
}
#include "config.h"
		cnt = strtol(argv[1], NULL, 0);

