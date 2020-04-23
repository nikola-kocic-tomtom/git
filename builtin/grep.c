	strbuf_add(&w->out, buf, size);

		if (match != all_entries_interesting) {
}

	while (todo_done != todo_end)

	}
				die(_("--no-index or --untracked cannot be used with revs"));

#include "grep.h"
			    N_("search in subdirectories (default)"), -1),
		obj_read_unlock();
	 * performance (this increases the number of pack files git has to pay
	argc = parse_options(argc, argv, prefix, options, grep_usage,
		hit |= grep_file(opt, dir.entries[i]->name);
}
	BUG_ON_OPT_NEG(unset);

			N_("show <n> context lines after matches")),
static int skip_first_line;
/* Signalled when a new work_item is added to todo. */


			/*
#include "userdiff.h"
}
}
			&opt.unmatch_name_only,
			verify_filename(prefix, argv[j], j == i && allow_revs);
	fill_directory(&dir, opt->repo->index, pathspec);
				GREP_PATTERN);
	/* Wait until all work is done. */

}
		free(oc.path);
			strbuf_addch(&base, ':');
		if (!w)
		real_obj = deref_tag(opt->repo, list->objects[i].item,
		OPT_BOOL(0, "heading", &opt.heading,
			hit |= grep_oid(opt, &entry.oid, base->buf, tn_len,
	struct work_item *ret;
		dir.flags |= DIR_NO_GITLINKS;

			if (match == entry_not_interesting)
		warning(_("no threads support, ignoring --threads"));
	struct grep_opt opt;
		if (fallback)
			N_("show only filenames instead of matching lines")),
/* In the range [todo_done, todo_start) in 'todo' we have work_items
	if (!use_index)
		/* ignore empty line like grep does */
	strbuf_release(&sb);

			 * If CE_VALID is on, we assume worktree file and its
		opt.output = append_path;
			if (seen_dashdash)

	 * "do what I mean" case, we verify and complain when that isn't true.
					      ce->name, cached);
	BUG_ON_OPT_ARG(arg);
	} else {
	};
		 */
#include "object-store.h"
				while (len) {
		     struct tree_desc *tree, struct strbuf *base, int tn_len,
		} else if (S_ISDIR(entry.mode)) {
{
			     PARSE_OPT_KEEP_DASHDASH |
		st = -1;
	if (!strcmp(var, "submodule.recurse"))
		pthread_cond_signal(&cond_write);
			break;
#include "packfile.h"
			strbuf_setlen(&name, name_base_len);
	threads = xcalloc(num_threads, sizeof(*threads));
}
	for(; todo[todo_done].done && todo_done != todo_start;
			do {
			i++;
 *
		/*
	todo[todo_end].source = *gs;
	 * separating revisions from pathnames if
			init_tree_desc(&sub, data, size);
static inline void grep_unlock(void)
			hit |= grep_tree(opt, pathspec, &sub, base, tn_len,
	strbuf_reset(&todo[todo_end].out);

		OPT_GROUP(""),
		struct object *real_obj;

		if (i)
			    int unset)


		if (opt.ignore_case && !strcmp("less", pager))
	grep_unlock();
		append_grep_pat(grep_opt, sb.buf, sb.len, arg, ++lno,

	allow_revs = use_index && !untracked;
		die(_("--cached or --untracked cannot be used with --no-index"));
static void *run(void *arg)
	obj_read_lock();
	struct work_item *w = opt->output_priv;
	sub = submodule_from_path(superproject, &null_oid, path);
			strbuf_addstr(&name, base->buf + tn_len);
	 */
		opt.null_following_name = 1;
static void run_pager(struct grep_opt *opt, const char *prefix)
					      1); /* ignored */
				list->objects[i].path)) {
					 check_attr);
		      const struct pathspec *pathspec, int cached);


			    int unset)
		compile_grep_patterns(&opt);
		OPT_BOOL('l', "files-with-matches", &opt.name_only,
		object = parse_object_or_die(oid, oid_to_hex(oid));
		grep_opt->pre_context = grep_opt->post_context = 0;
		return error(_("switch `%c' expects a numerical value"),
		}
	grep_source_init(&gs, GREP_SOURCE_FILE, buf.buf, filename, filename);

			   N_("allow calling of grep(1) (ignored by this build)"),

	} else {
static pthread_cond_t cond_result;
		return 0;
		       PATHSPEC_PREFER_CWD |
{
		int fallback = 0;
			N_("show only matches from files that match all patterns")),
		struct object_id oid;
	/*
{
			obj_read_unlock();
#include "blob.h"
			N_("show only the names of files without match")),

			break;
	if (show_in_pager) {
			    ce_skip_worktree(ce)) {
	if (repo->submodule_prefix) {
		num_threads = HAVE_THREADS ? online_cpus() : 1;
	pthread_mutex_init(&grep_attr_mutex, NULL);
		{ OPTION_CALLBACK, 0, "and", &opt, NULL,
	return 0;
			void *data;
		}
	}
		OPT_INTEGER(0, "threads", &num_threads,
	pthread_cond_destroy(&cond_add);
	struct string_list *path_list = opt->output_priv;
		     int check_attr)

}
 *
	struct grep_opt *opt = arg;
	return 0;
#define TODO_SIZE 128
		opt.only_matching = 0;
}
		len = name ? strlen(name) : 0;

	 * add_to_alternates_memory() via config_from_gitmodules(). This
	return 0;
{
			if (skip_first_line) {
			}
			die(_("both --cached and trees are given"));
int cmd_grep(int argc, const char **argv, const char *prefix)

		void *data;
			die(_("unable to read tree (%s)"), oid_to_hex(&object->oid));
		strbuf_insert(&pathbuf, 0, filename, tree_name_len);
					 &oid, &oc)) {
	BUG_ON_OPT_ARG(arg);
		OPT_SET_INT('a', "text", &opt.binary,


	 * Resolve any rev arguments. If we have a dashdash, then everything up
		int len = strlen(pager);
static int grep_tree(struct grep_opt *opt, const struct pathspec *pathspec,
			   N_("indicate hit with exit status without output")),
			if (opt->status_only)
	int hit = 0;
	}
		if (hit && opt->status_only)

{
			die(_("invalid number of threads specified (%d) for %s"),
			break;
		argv_array_push(&child.args, path_list->items[i].string);
	} else {
		for (j = i; j < argc; j++)
			   PARSE_OPT_NOCOMPLETE),
	for (i = 0; i < ARRAY_SIZE(todo); i++) {
		}
static int and_callback(const struct option *opt, const char *arg, int unset)
	/* --only-matching has no effect with --invert. */
	if (!use_index || untracked) {
			  const char *filename, const char *path, int cached)
{
	pthread_cond_signal(&cond_add);
	from_stdin = !strcmp(arg, "-");
	}
		if (S_ISREG(entry.mode)) {
		name_base_len = strlen(repo->submodule_prefix);

	value = strtol(arg, (char **)&endp, 10);
		 * for each thread.
		  PARSE_OPT_NOARG | PARSE_OPT_NONEG, not_callback },
	int i;
{
	const unsigned int nr = list->nr;
		if (!allow_revs) {

	grep_lock();
	 * operation causes a race condition with concurrent object readings
			o->debug = 0;
	grep_source_init(&gs, GREP_SOURCE_OID, pathbuf.buf, path, oid);
					len--;
	/* Wake up all the consumer threads so they can see that there
#include "string-list.h"
		} else {
static int grep_directory(struct grep_opt *opt, const struct pathspec *pathspec,
		die(_("--untracked not supported with --recurse-submodules"));
		OPT_BOOL('W', "function-context", &opt.funcbody,
	grep_lock();
		obj_read_lock();
		strbuf_setlen(&name, name_base_len);
		data = read_object_with_reference(opt->repo,

	die(_("unable to grep from object of type %s"), type_name(obj->type));
		OPT_BOOL_F(0, "ext-grep", &external_grep_allowed__ignored,
			if (cached || (ce->ce_flags & CE_VALID) ||
	grep_init(&opt, the_repository, prefix);
	if (show_in_pager && (cached || list.nr))
		if (cached)
		      const struct pathspec *pathspec, int cached)
		/* load the gitmodules file for this rev */
	 * If there is no -- then the paths must exist in the working
	 */
	return ret;

};
					 check_attr ? base->buf + tn_len : NULL);
			N_("match <pattern>"), PARSE_OPT_NONEG, pattern_callback },

			continue;
#include "commit.h"
		OPT__QUIET(&opt.status_only,
	pthread_cond_destroy(&cond_result);
	if (len == 1 && *(const char *)data == '\0')

			use_index = 0;
{
{
	append_grep_pattern(grep_opt, "--and", "command line", 0, GREP_AND);
	child.dir = prefix;
		     const char *path)

	 * here. It should be removed once it's no longer necessary to add the
	/* Ignore --recurse-submodules if --no-index is given or implied */
		const char *pager = path_list.items[0].string;
	 * pattern, but then what follows it must be zero or more

		if (num_threads > 1)
		pthread_cond_signal(&cond_result);
	} else if (num_threads < 0)
 * The ranges are modulo TODO_SIZE.
	for (i = 0; i < nr; i++) {
	while (tree_entry(tree, &entry)) {
		if (err)
#include "submodule-config.h"
	if (argc > 0 && !opt.pattern_list && !strcmp(argv[0], "--")) {

		OPT_BOOL(0, "textconv", &opt.allow_textconv,
	if (!patterns)
{
		OPT_BOOL(0, "name-only", &opt.name_only,
		 * reading/initialization once worker threads are started.
static int grep_cache(struct grep_opt *opt,
	 * NEEDSWORK: repo_read_gitmodules() might call
		OPT_INTEGER('B', "before-context", &opt.pre_context,

	int pattern_type_arg = GREP_PATTERN_TYPE_UNSPECIFIED;
	if (show_in_pager == default_pager)
{


 * consumers pick work items from the same array.
{
static int grep_cache(struct grep_opt *opt,

}
		init_tree_desc(&tree, data, size);
		hit = grep_cache(&subopt, pathspec, cached);

	if (!from_stdin)
 */
		num_threads = 1;
		int use_exclude = (opt_exclude < 0) ? use_index : !!opt_exclude;
			warning(_("no threads support, ignoring %s"), var);
	int i, status;
		OPT_BOOL('o', "only-matching", &opt.only_matching,
	pthread_mutex_init(&grep_mutex, NULL);
}
	free(arg);
			N_("show <n> context lines before and after matches"),
	/*
		strbuf_init(&todo[i].out, 0);
					   strbuf_detach(&buf, NULL));
		    && (opt.pre_context || opt.post_context ||
	}
		string_list_append(&path_list, show_in_pager);
		OPT_GROUP(""),
static pthread_cond_t cond_add;

		run_pager(&opt, prefix);
	char done;
}
	for (i = 0; i < num_threads; i++) {
static int context_callback(const struct option *opt, const char *arg,
		pthread_cond_wait(&cond_result, &grep_mutex);
		hit = grep_directory(&opt, &pathspec, use_exclude, use_index);
	const struct submodule *sub;
#include "quote.h"
		strbuf_addstr(&pathbuf, filename);
			context_callback),
	struct object_array list = OBJECT_ARRAY_INIT;
				nr++;
static int recurse_submodules;
		if (startup_info->have_repository)
	} else {

	 * skip a -- separator; we know it cannot be
	 * influences how we will parse arguments that come before it.

	 * store is no longer global and instead is a member of the repository
	struct grep_source source;

	 * -f, we take the first unrecognized non option to be the

	}

	unsigned int i;
	if (show_in_pager) {
#include "parse-options.h"
			(void)get_packed_git(the_repository);
			size_t len = w->out.len;

}
	struct strbuf name = STRBUF_INIT;
	else
		if (!cached)
			pager += len - 4;
{
	subopt.repo = &subrepo;
	/* First unrecognized non-option token */
}
static int grep_tree(struct grep_opt *opt, const struct pathspec *pathspec,
{
}


		struct object *object;
			      N_("show parse tree for grep expression"),
			N_("print empty line between matches from different files")),
	disable_obj_read_lock();
		hit = grep_cache(&opt, &pathspec, cached);
		return 0;
	todo[todo_end].done = 0;
	BUG_ON_OPT_NEG(unset);
}
			num_threads = 1;
	grep_use_locks = 0;
		OPT_CALLBACK('C', "context", &opt, N_("n"),
};
#include "config.h"
		argc--;
		void *data;
{

static int num_threads;
	int allow_revs;
			N_("show a line with the function name before matches")),
				 !strcmp(ce->name, repo->index->cache[nr]->name));
	else if (num_threads == 0)
static void append_path(struct grep_opt *opt, const void *data, size_t len)
		{ OPTION_CALLBACK, 0, "not", &opt, NULL, "",
		       struct object *obj, const char *name, const char *path)

		int err;
		opt.name_only = 1;

		OPT_BOOL(0, "all-match", &opt.all_match,
	}
	struct grep_opt *grep_opt = opt->value;
		OPT_SET_INT('P', "perl-regexp", &pattern_type_arg,
{
	 * Anything left over is presumed to be a path. But in the non-dashdash
	if (obj->type == OBJ_BLOB)
			 * grep.threads

	BUG_ON_OPT_NEG(unset);
			unsigned long size;
	struct grep_opt *grep_opt = opt->value;
		o->output = strbuf_out;
	int hit = 0;

		quote_path_relative(filename, opt->prefix, &buf);
		strbuf_addch(&base, '/');

			N_("search in index instead of in the work tree")),
		recurse_submodules = 0;
	child.use_shell = 1;
			N_("synonym for --files-with-matches")),

	struct name_entry entry;
	}
	 * tree.  If there is no explicit pattern specified with -e or
	}

}
 */
		if (!seen_dashdash)
{
	struct strbuf buf = STRBUF_INIT;
	free(threads);
	if (use_index && !startup_info->have_repository) {
			      1, PARSE_OPT_HIDDEN),
		}
	append_grep_pattern(grep_opt, arg, "-e option", 0, GREP_PATTERN);
			    N_("use basic POSIX regular expressions (default)"),
	}
	string_list_append(path_list, xstrndup(data, len));
		}
	struct repository *repo = opt->repo;
	append_grep_pattern(grep_opt, "--not", "command line", 0, GREP_NOT);
		 */
	return hit;
	 */

			    strerror(err));
		OPT_SET_INT('G', "basic-regexp", &pattern_type_arg,
	grep_unlock();
			  int exc_std, int use_index)
		OPT_GROUP(""),

		free(data);
				}
	int i;

		OPT_NEGBIT('h', NULL, &opt.pathname, N_("don't show filenames"), 1),
		     struct tree_desc *tree, struct strbuf *base, int tn_len,

	 * to it must resolve as a rev. If not, then we stop at the first

	grep_commit_pattern_type(pattern_type_arg, &opt);
		OPT_GROUP(""),
	all_work_added = 1;
	return hit;
		     const char *filename, int tree_name_len,
				     NULL, 0);
}
		struct strbuf base;
		if (!strcmp(argv[i], "--")) {
	/*
		grep_source_clear_data(&w->source);

	struct pathspec pathspec;
		ret = &todo[todo_start];
						       0, pathspec);
		 * initialization of packed_git to prevent racy lazy
		grep_source_clear(&w->source);
	}
		OPT_NUMBER_CALLBACK(&opt, N_("shortcut for -C NUM"),

		if (recurse_submodules) {
{
			 N_("recursively search in each submodule")),
			 N_("find in contents not managed by git"), 1),
			}
			PARSE_OPT_OPTARG | PARSE_OPT_NOCOMPLETE,
			N_("don't match patterns in binary files"),

		append_grep_pattern(&opt, argv[0], "command line", 0,
	}
				   S_ISDIR(ce->ce_mode) ||
		name_base_len = name.len;

	}
{
			 */
	memset(&dir, 0, sizeof(dir));
		 * add_work() copies gs and thus assumes ownership of
	struct child_process child = CHILD_PROCESS_INIT;

		die(_("index file corrupt"));
	struct option options[] = {
 */
	status = run_command(&child);
	pathspec.max_depth = opt.max_depth;
	int name_base_len = 0;
	}
	} else {
			context_callback),
			   submodule_path_match(repo->index, pathspec, name.buf, NULL)) {
	if (!strcmp(var, "grep.threads")) {
			write_or_die(1, p, len);
}

		OPT_BOOL(0, "break", &opt.file_break,
#include "tag.h"
	return hit;
	/*
}
		return hit;
	int hit = 0;
	 * NEEDSWORK: This adds the submodule's object directory to the list of

			obj_read_lock();
			if (!data)
static void start_threads(struct grep_opt *opt)
	struct string_list *path_list = opt->output_priv;
		}
	if (!show_in_pager && !opt.status_only)
						       &entry, &name,
		show_in_pager = git_pager(1);
		OPT_BOOL(0, "recurse-submodules", &recurse_submodules,
			 N_("process binary files with textconv filters")),
			N_("pager"), N_("show matching files in the pager"),
	 * valid refs up to the -- (if exists), and then existing
		 */
	enable_obj_read_lock();
	} else if (!list.nr) {
}
	if (opt->binary != GREP_BINARY_TEXT)
	struct dir_struct dir;
	 * consequences for memory (processed objects will never be freed) and

				hit |= grep_oid(opt, &ce->oid, name.buf,
	int lno = 0;
			N_("use <n> worker threads")),
static int file_callback(const struct option *opt, const char *arg, int unset)
		opt.color = 0;
	}
		if (!strcmp("less", pager) || !strcmp("vi", pager)) {
		}
		hit = grep_source(opt, &gs);
static int not_callback(const struct option *opt, const char *arg, int unset)

	if (!use_index)
	NULL
			setup_work_tree();
			    GREP_PATTERN_TYPE_FIXED),
	}
static void strbuf_out(struct grep_opt *opt, const void *buf, size_t size)

		free(data);
	}

			/* die the same way as if we did it at the beginning */

				   S_ISGITLINK(ce->ce_mode))) {
	if (show_in_pager && opt.pattern_list && !opt.pattern_list->next) {

			N_("show the surrounding function")),
			 */
			N_("show filename only once above matches from same file")),
 * up by a consumer thread.


			 * variable for tweaking threads, currently
			NULL, 1 },

			const char *p = w->out.buf;
{
		int hit;
		strbuf_addstr(&name, repo->submodule_prefix);
		{ OPTION_CALLBACK, ')', NULL, &opt, NULL, "",
		{ OPTION_STRING, 'O', "open-files-in-pager", &show_in_pager,

		 * add_work() copies gs and thus assumes ownership of
	for (i = 0; i < path_list->nr; i++)
	int seen_dashdash = 0;
		die(_("--open-files-in-pager only works on the worktree"));
		OPT_SET_INT('F', "fixed-strings", &pattern_type_arg,
	return hit;

			seen_dashdash = 1;

	while (todo_start == todo_end && !all_work_added) {
			hit |= grep_submodule(opt, pathspec, NULL, ce->name,

		strbuf_init(&base, PATH_MAX + len + 1);
			nr--; /* compensate for loop control */
	} else if (!HAVE_THREADS && num_threads > 1) {
			opt.file_break || opt.funcbody))
		struct tree_desc tree;
	init_grep_defaults(the_repository);
				break;
	pthread_mutex_destroy(&grep_attr_mutex);
	 * performed by the worker threads. That's why we need obj_read_lock()
#include "tree-walk.h"
		OPT_BOOL('w', "word-regexp", &opt.word_regexp,
		/*
			string_list_append(&path_list, "-I");

	 * paths.  If there is an explicit pattern, then the first
		argc--;
	int nr;
		compile_grep_patterns(o);
	int dummy;
			/*
			break;
			free(data);
	const char *show_in_pager = NULL, *default_pager = "dummy";
			break;
	w->done = 1;
		  close_callback },
	 * object.
		ret = NULL;
		exit(status);

			} else {
		if (!data)
	if (!use_index && (untracked || cached))
	pthread_mutex_unlock(&grep_mutex);
	int st = grep_config(var, value, cb);
		 */
	grep_opt->pre_context = grep_opt->post_context = value;
		fclose(patterns);
	/*
		} else if (recurse_submodules && S_ISGITLINK(entry.mode)) {
	 * We have to find "--" in a separate pass, because its presence
		if (hit && opt->status_only)
static struct work_item *get_work(void)
			gitmodules_config_oid(&real_obj->oid);
		BUG("Never call this function unless you have started threads");
	if (all_work_added && todo_done == todo_end)
		OPT_SET_INT('I', NULL, &opt.binary,
	int hit = 0;
	return 0;
		if (hit && opt->status_only)
	}
		const struct cache_entry *ce = repo->index->cache[nr];
	memcpy(&subopt, opt, sizeof(subopt));
	obj_read_unlock();
		} else if (recurse_submodules && S_ISGITLINK(ce->ce_mode) &&
	BUG_ON_OPT_NEG(unset);

	if (argc > 0 && !opt.pattern_list) {
	grep_destroy();
#define USE_THE_INDEX_COMPATIBILITY_MACROS
			string_list_append(&path_list,
	repo_read_gitmodules(&subrepo, 0);
		pthread_join(threads[i], &h);
		 * start_threads() above calls compile_grep_patterns()
struct work_item {
	}


	clear_pathspec(&pathspec);

			warning(_("invalid option combination, ignoring --threads"));
			/* Skip the leading hunk mark of the first file. */
/* This lock protects all the variables above. */
		OPT_BOOL(0, "untracked", &untracked,
		 * used when not using threading. Otherwise
	int external_grep_allowed__ignored;
	if (todo_start == todo_end && all_work_added) {
			 * been modified, so use cache version instead
	int i, hit = 0;
	for (i = 0; i < argc; i++) {
		struct tree_desc tree;
		{ OPTION_INTEGER, 0, "max-depth", &opt.max_depth, N_("depth"),
{
			data = read_object_file(&entry.oid, &type, &size);

		if (!HAVE_THREADS)
		}

 * threads. The producer adds struct work_items to 'todo' and the
		}
	if (repo->submodule_prefix) {
			const struct object_array *list)
	free_grep_patterns(&opt);
	for (nr = 0; nr < repo->index->cache_nr; nr++) {
						  &size, NULL);
	int cached = 0, untracked = 0, opt_exclude = -1;
			   N_("print NUL after filenames"),
		return 0;
		void *h;
		 * its fields, so do not call grep_source_clear()
		start_threads(&opt);
			struct strbuf buf = STRBUF_INIT;
		if (recurse_submodules)
		num_threads = git_config_int(var, value);
		  PARSE_OPT_NOARG | PARSE_OPT_NONEG | PARSE_OPT_NODASH,
			N_("read patterns from file"), file_callback),
	parse_pathspec(&pathspec, 0,
	repo_clear(&subrepo);
		strbuf_addstr(&name, repo->submodule_prefix);
				    GREP_PATTERN);
 */
	 * alternates for the single in-memory object store.  This has some bad
 * The work_items in [todo_start, todo_end) are waiting to be picked
	 * unrecognized non option is the beginning of the refs list
	} else {
static int grep_cmd_config(const char *var, const char *value, void *cb)
	grep_use_locks = 1;
			N_("case insensitive matching")),
}

			 * cache entry are identical, even if worktree file has
		obj_read_lock();
static int grep_objects(struct grep_opt *opt, const struct pathspec *pathspec,

		quote_path_relative(filename + tree_name_len, opt->prefix, &pathbuf);
	struct repository *repo = opt->repo;
			die(_("unable to read tree (%s)"), oid_to_hex(&obj->oid));
	} else {
static char const * const grep_usage[] = {
#include "cache.h"
	int old_baselen = base->len;

			    num_threads, var);
	strbuf_release(&name);
	if (status)

				die(_("unable to read tree (%s)"),
	if (git_color_default_config(var, value, cb) < 0)
				hit |= grep_file(opt, name.buf);
		if (!data)
static int todo_done;
		else if (!HAVE_THREADS && num_threads > 1) {
{
	if (num_threads > 1) {

		if (S_ISREG(ce->ce_mode) &&
		die(_("invalid number of threads specified (%d)"), num_threads);
		OPT_CALLBACK('f', NULL, &opt, N_("file"),
			} while (nr < repo->index->cache_nr &&
	const char *endp;
		OPT_BOOL(0, "column", &opt.columnnum, N_("show column number of first match")),
						break;
static void work_done(struct work_item *w)

	strbuf_release(&pathbuf);
	if (old_done != todo_done)
}
		OPT_BOOL('i', "ignore-case", &opt.ignore_case,
		opt.output_priv = &path_list;
#include "repository.h"
			hit = 1;
		struct object *object;
			N_("search in both tracked and untracked files")),
			N_("show filenames relative to top directory"), 1),

		if (num_threads < 0)
			N_("match patterns only at word boundaries")),
	FILE *patterns;
		hit = grep_tree(opt, pathspec, &tree, &base, base.len,
				    oid_to_hex(&entry.oid));


		setup_pager();
		argv++;
		init_tree_desc(&tree, data, size);
static int pattern_callback(const struct option *opt, const char *arg,
						  &object->oid, tree_type,


#include "dir.h"
static int todo_start;
	todo_end = (todo_end + 1) % ARRAY_SIZE(todo);
		OPT_INTEGER('A', "after-context", &opt.post_context,

		add_work(opt, &gs);
	strbuf_release(&name);
	if (num_threads > 1)
			die(_("grep: failed to create thread: %s"),

		w = &todo[todo_done];
		if (get_oid_with_context(the_repository, arg,
		 * The compiled patterns on the main path are only
	 * subrepo's odbs to the in-memory alternates list.
		  N_("combine patterns specified with -e"),
			verify_non_filename(prefix, arg);
static int open_callback(const struct option *opt, const char *arg, int unset)
		  PARSE_OPT_NOARG | PARSE_OPT_NONEG | PARSE_OPT_NODASH,
#include "pathspec.h"
		OPT_SET_INT('E', "extended-regexp", &pattern_type_arg,
	}

		add_work(opt, &gs);
}
static pthread_cond_t cond_write;
		OPT__COLOR(&opt.color, N_("highlight matches")),

static void add_work(struct grep_opt *opt, struct grep_source *gs)

			     PARSE_OPT_STOP_AT_NON_OPTION);
					      base->buf, base->buf + tn_len,
		hit = grep_objects(&opt, &pathspec, &list);
			N_("process binary files as text"), GREP_BINARY_TEXT),
		die(_("no pattern given"));
	enum interesting match = entry_not_interesting;
 * that have been or are processed by a consumer thread. We haven't
		OPT_END()

}
	struct strbuf name = STRBUF_INIT;
		}
			    GREP_PATTERN_TYPE_ERE),
			BUG("Somebody got num_threads calculation wrong!");
		}
	}
	struct repository *superproject = opt->repo;
			  const struct object_id *oid,
			strbuf_addf(&buf, "+/%s%s",
	strbuf_release(&buf);
		OPT_BOOL('c', "count", &opt.count,
	if (!opt.pattern_list)
	if (oid) {
}
}
				if (ce_stage(ce) || ce_intent_to_add(ce))

	int old_done;
/* Signalled when the result from one work_item is written to

			   PARSE_OPT_NOCOMPLETE),


	 */
	struct grep_opt *grep_opt = opt->value;
	struct grep_opt *grep_opt = opt->value;
			continue;
			    N_("use Perl-compatible regular expressions"),
	}
static int all_work_added;
		if (!(opt.name_only || opt.unmatch_name_only || opt.count)
		die_errno(_("cannot open '%s'"), arg);
					opt.pattern_list->pattern);
		}
			skip_first_line = 1;
		add_object_array_with_path(object, arg, &list, oc.mode, oc.path);
	return 0;

				break;
			     opt->short_name);

	if (*endp) {
#include "run-command.h"
		strbuf_addstr(&buf, filename);
	}
				continue;
			hit |= grep_submodule(opt, pathspec, &entry.oid,
			GREP_BINARY_NOMATCH),
	if (!is_submodule_active(superproject, path))
	pthread_cond_init(&cond_add, NULL);
	}

			N_("descend at most <depth> levels"), PARSE_OPT_NONEG,
 * written the result for these to stdout yet.

		strbuf_release(&base);
			 * TRANSLATORS: %s is the configuration
			repo_read_gitmodules(the_repository, 1);
	if (obj->type == OBJ_COMMIT || obj->type == OBJ_TREE) {
		struct object_context oc;
						  &obj->oid, tree_type,
		OPT_SET_INT('r', "recursive", &opt.max_depth,
	patterns = from_stdin ? stdin : fopen(arg, "r");

	while ((todo_end+1) % ARRAY_SIZE(todo) == todo_done) {

	if (num_threads > 1) {
static pthread_t *threads;
#include "submodule.h"
	 * non-rev and assume everything else is a path.
		hit = grep_source(opt, &gs);
	if (opt->relative && opt->prefix_length) {
		grep_source_clear(&gs);
	}
		     int check_attr);
		if (w->out.len) {
		{ OPTION_CALLBACK, 'e', NULL, &opt, N_("pattern"),
		OPT_BOOL('L', "files-without-match",

		OPT_NEGBIT(0, "full-name", &opt.relative,

	if (unset) {
					strcmp("less", pager) ? "" : "*",
						 0, name.buf);
		    match_pathspec(repo->index, pathspec, name.buf, name.len, 0, NULL,
		grep_source_clear(&gs);
		hit = grep_tree(&subopt, pathspec, &tree, &base, base.len,

static int todo_end;
	grep_lock();
		OPT_GROUP(""),
	struct grep_source gs;
	grep_unlock();
	int value;
static struct work_item todo[TODO_SIZE];
static int grep_file(struct grep_opt *opt, const char *filename)
#include "tree.h"
		OPT_NEGBIT(0, "no-index", &use_index,

			NULL, (intptr_t)default_pager },
		die(_("--[no-]exclude-standard cannot be used for tracked contents"));
	while (1) {
		 * Pre-read gitmodules (if not read already) and force eager
		struct work_item *w = get_work();
	while (strbuf_getline(&sb, patterns) == 0) {
	if (opt.invert)
		if (len) {
	struct strbuf out;
		recurse_submodules = git_config_bool(var, value);
		return grep_oid(opt, &obj->oid, name, 0, path);
		int j;
	 * attention to, to the sum of the number of pack files in all the
	pthread_cond_init(&cond_result, NULL);
		struct strbuf base = STRBUF_INIT;
		hit |= wait_all();
		if (sb.len == 0)
		object = parse_object_or_die(&oid, arg);
	int hit = 0;
		  PARSE_OPT_NOARG | PARSE_OPT_NONEG, and_callback },
static int grep_object(struct grep_opt *opt, const struct pathspec *pathspec,
{
		OPT_BOOL('n', "line-number", &opt.linenum, N_("show line numbers")),
	append_grep_pattern(grep_opt, "(", "command line", 0, GREP_OPEN_PAREN);
static pthread_mutex_t grep_mutex;
		err = pthread_create(&threads[i], NULL, run, o);
			N_("show non-matching lines")),
	return 0;
	int name_base_len = 0;
static int grep_oid(struct grep_opt *opt, const struct object_id *oid,
		pthread_cond_wait(&cond_write, &grep_mutex);
		if (grep_object(opt, pathspec, real_obj, list->objects[i].name,
		strbuf_addstr(&base, filename);

	 */
	int from_stdin;
		unsigned long size;
			struct tree_desc sub;
				obj->type == OBJ_COMMIT);
		obj_read_unlock();
	}
	if (repo_submodule_init(&subrepo, superproject, sub))
static int wait_all(void)
	BUG_ON_OPT_ARG(arg);
	add_to_alternates_memory(subrepo.objects->odb->path);
		if (!dir_path_match(opt->repo->index, dir.entries[i], pathspec, 0, NULL))

			N_("show only matching parts of a line")),
	 * that continues up to the -- (if exists), and then paths.
/* We use one producer thread and THREADS consumer
static int close_callback(const struct option *opt, const char *arg, int unset)
		if (ce_stage(ce)) {
	grep_lock();

		OPT_BOOL(0, "or", &dummy, ""),
	pthread_cond_destroy(&cond_write);
	append_grep_pattern(grep_opt, ")", "command line", 0, GREP_CLOSE_PAREN);
	pthread_mutex_destroy(&grep_mutex);
#include "builtin.h"
	}

{
		{ OPTION_CALLBACK, '(', NULL, &opt, NULL, "",
	return 0;
	struct grep_opt *grep_opt = opt->value;
	struct grep_opt *grep_opt = opt->value;
{
	return !hit;
	struct strbuf pathbuf = STRBUF_INIT;
	pathspec.recursive = 1;
	if (hit && show_in_pager)
	/*
			    GREP_PATTERN_TYPE_PCRE),
		 * its fields, so do not call grep_source_clear()

	BUG_ON_OPT_NEG(unset);
/* Has all work items been added? */
	pthread_cond_broadcast(&cond_add);
	if (num_threads > 1) {
		todo_start = (todo_start + 1) % ARRAY_SIZE(todo);
	struct repository subrepo;
	pathspec.recurse_submodules = !!recurse_submodules;
		OPT_SET_INT(0, "exclude-standard", &opt_exclude,
	}
		OPT_BOOL(0, "cached", &cached,
		opt->output_priv = w;
			strbuf_add(&base, name, len);
	struct grep_source gs;
		       (opt.max_depth != -1 ? PATHSPEC_MAXDEPTH_VALID : 0),
		argv++;
		OPT_BIT('H', NULL, &opt.pathname, N_("show filenames"), 1),
		  open_callback },
	free_grep_patterns(arg);
		strbuf_release(&base);
 * stdout.
	int use_index = 1;



		OPT_GROUP(""),

	/*
/*
	pthread_cond_init(&cond_write, NULL);
						  &size, NULL);
	grep_unlock();
			submodule_free(opt->repo);

		int hit, len;
{
	for (i = 0; i < dir.nr; i++) {

		return hit;
		strbuf_setlen(base, old_baselen);
		hit |= (int) (intptr_t) h;
		setup_standard_excludes(&dir);
		if (len > 4 && is_dir_sep(pager[len - 5]))
	}
	if (!HAVE_THREADS)
 * Copyright (c) 2006 Junio C Hamano

	if (repo_read_index(repo) < 0)
		unsigned long size;
{
	if (exc_std)

		return 0;
			setup_git_directory();
	BUG_ON_OPT_NEG(unset);

	struct grep_opt subopt;
	}
	return (void*) (intptr_t) hit;

		OPT_BOOL('p', "show-function", &opt.funcname,
		}

	 * repositories processed so far).  This can be removed once the object
	 * is no more work to do.
	return hit;
	return st;
	 */
}
			strbuf_addch(base, '/');
	N_("git grep [<options>] [-e] <pattern> [<rev>...] [[--] <path>...]"),

				skip_first_line = 0;
			    GREP_PATTERN_TYPE_BRE),
		return;

			match = tree_entry_interesting(repo->index,
		return 0;
	int hit = 0;
		OPT_SET_INT_F(0, "debug", &opt.debug,
		hit |= grep_source(opt, &w->source);
	struct strbuf sb = STRBUF_INIT;

			break;
	pthread_mutex_lock(&grep_mutex);
		/*
		OPT_BOOL('v', "invert-match", &opt.invert,
		strbuf_addstr(&name, ce->name);
	}

		OPT_BOOL_F('z', "null", &opt.null_following_name,
		if (!strcmp(arg, "--")) {
	struct string_list path_list = STRING_LIST_INIT_NODUP;
			    N_("use extended POSIX regular expressions"),
		int hit;

		       prefix, argv + i);
			break;
				die(_("unable to resolve revision: %s"), arg);


	if (opt->relative && opt->prefix_length)
			if (seen_dashdash)
		data = read_object_with_reference(&subrepo,

					if (*p++ == '\n')
		return hit;
		num_threads = 1;
	 */
	int i;
			N_("show <n> context lines before matches")),
	for (i = 0; i < num_threads; i++) {
			break;

 *
	} else if (0 <= opt_exclude) {
		/*

		}
	git_config(grep_cmd_config, NULL);
{

	if (recurse_submodules && untracked)
	    todo_done = (todo_done+1) % ARRAY_SIZE(todo)) {
		struct grep_opt *o = grep_opt_dup(opt);
	struct grep_opt *grep_opt = opt->value;
			N_("show the number of matches instead of matching lines")),
			  const struct pathspec *pathspec,
	BUG_ON_OPT_ARG(arg);
	if (!seen_dashdash) {
}
		work_done(w);
	 * we haven't even had any patterns yet
		else
		strbuf_add(base, entry.path, te_len);
		int te_len = tree_entry_len(&entry);
	for (i = 0; i < argc; i++) {
					continue;

	 */
			enum object_type type;
	}
		const char *arg = argv[i];
		pthread_cond_wait(&cond_add, &grep_mutex);
			if (match == all_entries_not_interesting)


	int hit;
		grep_source_load_driver(gs, opt->repo->index);


	return hit;
					 GET_OID_RECORD_PATH,
	old_done = todo_done;
			    N_("interpret patterns as fixed strings"),
	}
/* Signalled when we are finished with everything. */
			    N_("ignore files specified via '.gitignore'"), 1),
 * Builtin "git grep"
static int grep_submodule(struct grep_opt *opt,
static inline void grep_lock(void)
				object->type == OBJ_COMMIT);
			continue;
		git_config_get_bool("grep.fallbacktonoindex", &fallback);
