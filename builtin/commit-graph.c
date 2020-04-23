		OPT_END(),
		if (opts.stdin_commits) {
			N_("The object directory to store the graph")),

};
	if (argc == 2 && !strcmp(argv[1], "-h"))

		usage_with_options(builtin_commit_graph_usage,
			string_list_append(&lines, strbuf_detach(&buf, NULL));
	UNLEAK(lines);

	NULL

		}
	if (!opts.obj_dir)
	return odb;
		flags |= COMMIT_GRAPH_WRITE_APPEND;

		OPT_BOOL(0, "append", &opts.append,
	if (write_commit_graph(odb,
	odb = find_odb(the_repository, opts.obj_dir);

	N_("git commit-graph write [--object-dir <objdir>] [--append|--split] [--reachable|--stdin-packs|--stdin-commits] [--[no-]progress] <split options>"),
	if (opts.stdin_packs || opts.stdin_commits) {

static int graph_verify(int argc, const char **argv)
	trace2_cmd_mode("write");
	strbuf_release(&odb_path_real);


			     builtin_commit_graph_verify_options,
	char *obj_dir_real = real_pathdup(obj_dir, 1);
	else
} opts;
			N_("scan pack-indexes listed by stdin for commits")),
static char const * const builtin_commit_graph_usage[] = {
	if (argc > 0) {
	int stdin_packs;
static int graph_write(int argc, const char **argv)
		OPT_BOOL(0, "stdin-packs", &opts.stdin_packs,
		if (!strcmp(argv[0], "verify"))
	if (!odb)

		OPT_INTEGER(0, "size-multiple", &split_opts.size_multiple,
		if (!strcmp(argv[0], "write"))
}
			N_("dir"),

			return 1;
#include "builtin.h"
	N_("git commit-graph write [--object-dir <objdir>] [--append|--split] [--reachable|--stdin-packs|--stdin-commits] [--[no-]progress] <split options>"),
	static struct option builtin_commit_graph_options[] = {
		return !!open_ok;
	opts.progress = isatty(2);
			N_("include all commits already in the commit-graph file")),
	trace2_cmd_mode("verify");
	if (opts.shallow)
};
		while (strbuf_getline(&buf, stdin) != EOF)
		graph = read_commit_graph_one(the_repository, odb);
	struct commit_graph *graph = NULL;
	UNLEAK(graph);

{
	git_config(git_default_config, NULL);
	int reachable;
#include "lockfile.h"
				   builtin_commit_graph_options);


		flags |= COMMIT_GRAPH_WRITE_PROGRESS;
			N_("maximum number of commits in a non-base split commit-graph")),
		OPT_STRING(0, "object-dir", &opts.obj_dir,
{
			     builtin_commit_graph_usage,
}
	int open_ok;
#include "config.h"
		return 0;
	if (opts.reachable + opts.stdin_packs + opts.stdin_commits > 1)
	prepare_alt_odb(r);
			N_("start walk at commits listed by stdin")),

	opts.progress = isatty(2);
	struct string_list *pack_indexes = NULL;
		flags |= COMMIT_GRAPH_WRITE_PROGRESS;
int cmd_commit_graph(int argc, const char **argv, const char *prefix)
	}
		opts.obj_dir = get_object_directory();
	struct object_directory *odb;
			N_("start walk at all refs")),
	int fd;

			   N_("The object directory to store the graph")),

			pack_indexes = &lines;
}
	split_opts.expire_time = 0;
			N_("maximum number of commits in a non-base split commit-graph")),
			commit_hex = &lines;
	return result;
	for (odb = r->objects->odb; odb; odb = odb->next) {
{
	argc = parse_options(argc, argv, NULL,
	struct string_list *commit_hex = NULL;

	const char *obj_dir;
			       commit_hex,
		OPT_BOOL(0, "shallow", &opts.shallow,
	struct stat st;
	int result = 0;
		strbuf_realpath(&odb_path_real, odb->path, 1);
	N_("git commit-graph verify [--object-dir <objdir>] [--shallow] [--[no-]progress]"),
		if (write_commit_graph_reachable(odb, flags, &split_opts))
	if (!graph)
			 N_("if the commit-graph is split, only verify the tip file")),
static const char * const builtin_commit_graph_write_usage[] = {
		result = 1;
#include "commit-graph.h"

	usage_with_options(builtin_commit_graph_usage,
		OPT_INTEGER(0, "max-commits", &split_opts.max_commits,
	if (opts.progress)
			N_("dir"),
	graph_name = get_commit_graph_filename(odb);
			   N_("dir"),

		OPT_END(),
	split_opts.max_commits = 0;
	static struct option builtin_commit_graph_verify_options[] = {

		struct strbuf buf = STRBUF_INIT;
		graph = load_commit_graph_one_fd_st(fd, &st, odb);

	int append;
extern int read_replace_refs;
		OPT_STRING(0, "object-dir", &opts.obj_dir,
			N_("maximum ratio between two levels of a split commit-graph")),
		die(_("use at most one of --reachable, --stdin-commits, or --stdin-packs"));
	FREE_AND_NULL(graph_name);



	}
	return verify_commit_graph(the_repository, graph, flags);

			     builtin_commit_graph_write_options,
	enum commit_graph_write_flags flags = 0;
		flags |= COMMIT_GRAPH_VERIFY_SHALLOW;
			     builtin_commit_graph_write_usage, 0);
		die(_("could not find object directory matching %s"), obj_dir);
};
		OPT_BOOL(0, "split", &opts.split,

	if (open_ok)
#include "parse-options.h"
	if (!opts.obj_dir)
static struct object_directory *find_odb(struct repository *r,

		if (!strcmp(obj_dir_real, odb_path_real.buf))
			return graph_write(argc, argv);
	}
	NULL
		OPT_BOOL(0, "progress", &opts.progress, N_("force progress reporting")),
	struct object_directory *odb = NULL;
			   builtin_commit_graph_options);
	if (!open_ok && errno != ENOENT)
			     builtin_commit_graph_verify_usage, 0);
			break;
		die_errno(_("Could not open commit-graph '%s'"), graph_name);
	open_ok = open_commit_graph(graph_name, &fd, &st);
	NULL
#include "dir.h"
			     PARSE_OPT_STOP_AT_NON_OPTION);
	static struct option builtin_commit_graph_write_options[] = {

		OPT_STRING(0, "object-dir", &opts.obj_dir,
		OPT_BOOL(0, "reachable", &opts.reachable,
	};
	save_commit_buffer = 0;
	struct string_list lines;
	int flags = 0;
					 const char *obj_dir)
	if (opts.append)

		OPT_BOOL(0, "progress", &opts.progress, N_("force progress reporting")),
	odb = find_odb(the_repository, opts.obj_dir);
		UNLEAK(buf);
			flags |= COMMIT_GRAPH_WRITE_CHECK_OIDS;
	int split;
	if (opts.reachable) {
			       pack_indexes,

	free(obj_dir_real);

	struct strbuf odb_path_real = STRBUF_INIT;
	split_opts.size_multiple = 2;
			return graph_verify(argc, argv);
{
		opts.obj_dir = get_object_directory();
	int stdin_commits;
	/* Return failure if open_ok predicted success */
		OPT_EXPIRY_DATE(0, "expire-time", &split_opts.expire_time,
	}

	if (opts.progress)
		OPT_END(),

static struct split_commit_graph_opts split_opts;
#include "object-store.h"
	argc = parse_options(argc, argv, prefix,
	};
			N_("The object directory to store the graph")),
		if (opts.stdin_packs)
		flags |= COMMIT_GRAPH_WRITE_SPLIT;


	};
	read_replace_refs = 0;

			       flags,
	int progress;
static struct opts_commit_graph {
	char *graph_name;
	int shallow;
		OPT_BOOL(0, "stdin-commits", &opts.stdin_commits,

	if (opts.split)

	string_list_init(&lines, 0);
	N_("git commit-graph verify [--object-dir <objdir>] [--shallow] [--[no-]progress]"),
	argc = parse_options(argc, argv, NULL,
#include "repository.h"
			       &split_opts))
	struct object_directory *odb = NULL;
			     builtin_commit_graph_options,
			N_("allow writing an incremental commit-graph file")),
static const char * const builtin_commit_graph_verify_usage[] = {
}
