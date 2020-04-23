static NORETURN void die_usage(void)
			trace2_cmd_name(cmds[i].name);
	for (i = 0; i < ARRAY_SIZE(cmds); i++)
	{ "dir-iterator", cmd__dir_iterator },
		if (!strcmp(cmds[i].name, argv[1])) {
			     PARSE_OPT_STOP_AT_NON_OPTION |
	argc = parse_options(argc, argv, NULL, options, test_tool_usage,
	{ "windows-named-pipe", cmd__windows_named_pipe },
	{ "delta", cmd__delta },
	{ "regex", cmd__regex },
static struct test_cmd cmds[] = {
	{ "repository", cmd__repository },
	struct option options[] = {
			return cmds[i].fn(argc, argv);
	{ "xml-encode", cmd__xml_encode },
#include "trace2.h"
	{ "read-cache", cmd__read_cache },
}
	{ "mktemp", cmd__mktemp },
	{ "sha1", cmd__sha1 },

	{ "genzeros", cmd__genzeros },
};
	{ "submodule-config", cmd__submodule_config },
	{ "oid-array", cmd__oid_array },
	{ "dump-fsmonitor", cmd__dump_fsmonitor },
	{ "prio-queue", cmd__prio_queue },
	{ "strcmp-offset", cmd__strcmp_offset },
	{ "ref-store", cmd__ref_store },
	{ "config", cmd__config },
	fprintf(stderr, "usage: test-tool <toolname> [args]\n");
	int (*fn)(int argc, const char **argv);
	const char *name;
int cmd_main(int argc, const char **argv)
	{ "progress", cmd__progress },

static const char * const test_tool_usage[] = {
	{ "trace2", cmd__trace2 },
	};
		OPT_END()
{
	{ "online-cpus", cmd__online_cpus },
			trace2_cmd_list_config();
#ifdef GIT_WINDOWS_NATIVE
	die_usage();
	{ "date", cmd__date },
	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
			argv++;
	const char *working_directory = NULL;
	size_t i;
	{ "dump-cache-tree", cmd__dump_cache_tree },
			   "change the working directory"),
	{ "write-cache", cmd__write_cache },
	int i;
	{ "dump-split-index", cmd__dump_split_index },
		die_usage();
	{ "sigchain", cmd__sigchain },
	{ "revision-walking", cmd__revision_walking },
	{ "ctype", cmd__ctype },
	{ "parse-options", cmd__parse_options },
};
	{ "urlmatch-normalization", cmd__urlmatch_normalization },
	BUG_exit_code = 99;
	{ "lazy-init-name-hash", cmd__lazy_init_name_hash },
	{ "mergesort", cmd__mergesort },
	"test-tool [-C <directory>] <command [<arguments>...]]",
	{ "path-utils", cmd__path_utils },
			trace2_cmd_list_env_vars();
	{ "reach", cmd__reach },

	{ "read-graph", cmd__read_graph },

}
struct test_cmd {

		}

	error("there is no tool named '%s'", argv[1]);
	{ "oidmap", cmd__oidmap },
			     PARSE_OPT_KEEP_ARGV0);
	{ "example-decorate", cmd__example_decorate },
	{ "match-trees", cmd__match_trees },
	{ "wildmatch", cmd__wildmatch },
			argc--;
	{ "parse-pathspec-file", cmd__parse_pathspec_file },
		OPT_STRING('C', NULL, &working_directory, "directory",

#include "parse-options.h"
	if (working_directory && chdir(working_directory) < 0)
		die("Could not cd to '%s'", working_directory);
	{ "hash-speed", cmd__hash_speed },
#endif
};
	{ "sha256", cmd__sha256 },
	exit(128);

	{ "advise", cmd__advise_if_enabled },
		fprintf(stderr, "  %s\n", cmds[i].name);
	{ "chmtime", cmd__chmtime },
	{ "drop-caches", cmd__drop_caches },
	if (argc < 2)
{
	NULL
	{ "submodule-nested-repo-config", cmd__submodule_nested_repo_config },
	{ "string-list", cmd__string_list },
	{ "json-writer", cmd__json_writer },
	{ "hashmap", cmd__hashmap },

	}
	{ "dump-untracked-cache", cmd__dump_untracked_cache },
	{ "read-midx", cmd__read_midx },
	{ "pkt-line", cmd__pkt_line },
	{ "run-command", cmd__run_command },

	{ "serve-v2", cmd__serve_v2 },
	{ "subprocess", cmd__subprocess },
	{ "index-version", cmd__index_version },
	{ "genrandom", cmd__genrandom },
	{ "scrap-cache-tree", cmd__scrap_cache_tree },
#include "test-tool.h"
#include "git-compat-util.h"
