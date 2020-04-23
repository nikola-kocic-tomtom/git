
void register_archiver(struct archiver *ar)
		const char *colon = strchrnul(name, ':');
static void parse_treeish_arg(const char **argv,
	int list = 0;
	 */
	struct archiver_context *c = context;
	struct archiver_context *c = context;
	strbuf_release(&fmt);
				   stage, context);

		fprintf(stderr, "%.*s\n", (int)path.len, path.buf);
	NULL
	const struct commit *commit;
		OPT_GROUP(""),
	int baselen, len;
	if (!*ar || (is_remote && !((*ar)->flags & ARCHIVER_REMOTE)))
	struct directory *bottom;
	if (!check)

		opts.index_only = 1;
	hashcpy(d->oid.hash, sha1);
	return !strcmp(filename + prefixlen, ext);
	git_check_attr(istate, path, check);
static char const * const archive_usage[] = {

}
		return NULL;
		while (*pathspec) {
		if (!c)
	path += args->baselen;
}
		init_tree_desc(&t, args->tree->buffer, args->tree->size);
		strbuf_setlen(base, baselen);
static int match_extension(const char *filename, const char *ext)
	struct directory *d;
	const char *output = NULL;
				     prefix, &tree_oid,
		OPT_GROUP(""),
		b = memmem(src, len, "$Format:", 8);
	for (;;) {
	}
	d = xmalloc(st_add(sizeof(*d), len));
	if (write_directory(c))
	char path[FLEX_ARRAY];

static void queue_directory(const unsigned char *sha1,
static void format_subst(const struct commit *commit,
		format_commit_message(commit, fmt.buf, buf, &ctx);
				  len, 040777);
		die(_("Option --exec can only be used together with --remote"));
	while (context.bottom) {
}
	static struct strbuf path = STRBUF_INIT;
	err = read_tree_recursive(args->repo, args->tree, "",
static int check_attr_export_ignore(const struct attr_check *check)
				    &ctx->pathspec,
	if (!format && name_hint)
	git_config_get_bool("uploadarchive.allowunreachable", &remote_allow_unreachable);
	int i;
#define OPT__COMPR_HIDDEN(s, v, p) \

		die(_("not a tree object: %s"), oid_to_hex(&oid));
	}
		len -= c + 1 - src;
	init_checkout_metadata(&meta, args->refname,
			die(_("current working directory is untracked"));
		strbuf_add(&fmt, b + 8, c - b - 8);
				    d->stage, c) != READ_TREE_RECURSIVE;



	ar_args->commit_oid = commit_oid;
	d->path[d->len - 1] = '\0'; /* no trailing slash */
struct path_exists_context {
		OPT__VERBOSE(&verbose, N_("report archived files on stderr")),
}
	if (!startup_info->have_repository) {

	int i;

	unsigned mode;

			args->compression_level = compression_level;
		if (check_attr_export_ignore(check))
				  0, 0, &args->pathspec,
	const char *base = NULL;
		/* Borrow base, but restore its original value when done. */
	args->convert = 0;

		to_free = strbuf_detach(buf, NULL);
	N_("git archive --remote <repo> [--exec <cmd>] [<options>] <tree-ish> [<path>...]"),
	 * must be consistent with parse_pathspec in path_exists()
}
	 * Setup index and instruct attr to read index only
		if (!match_pathspec(ctx->args->repo->index,
	}

	if (remote)
	commit = lookup_commit_reference_gently(ar_args->repo, &oid, 1);
	int ret = -1;
{
	if (compression_level != -1) {
		return 0;
{
				  &context);
	return check && ATTR_TRUE(check->items[1].value);
{
	 * Also if pathspec patterns are dependent, we're in big
{
		die(_("Unexpected option --output"));
	d->mode	   = mode;
	if (prefix) {

static int nr_archivers;
			N_("write the archive to this file")),
static int write_directory(struct archiver_context *c)
static int write_archive_entry(const struct object_id *oid, const char *base,
	return ret;
			return err;

			     unsigned long *sizep)
		OPT_BOOL('l', "list", &list,
	struct object_id oid;
		const char *name_hint, int is_remote)
		strbuf_attach(&buf, buffer, *sizep, *sizep + 1);
	char *ref = NULL;
	struct object_id oid;
	}

static int queue_or_write_archive_entry(const struct object_id *oid,

		buffer = strbuf_detach(&buf, &size);
		strbuf_addstr(base, filename);
static const struct archiver *lookup_archiver(const char *name)
{
#define OPT__COMPR(s, v, h, p) \
		OPT__COMPR('9', &compression_level, N_("compress better"), 9),
		check = get_archive_attrs(args->repo->index, path_without_prefix);

	ctx.date_mode.type = DATE_NORMAL;
		OPT__COMPR_HIDDEN('7', &compression_level, 7),
		strbuf_addstr(&sb, filename);
		opts.dst_index = args->repo->index;

		dwim_ref(name, strlen(name), &oid, &ref);
}
	} else {
	struct archiver_args args;
	if (list) {

}
	int compression_level = -1;
	N_("git archive --remote <repo> [--exec <cmd>] --list"),
		return 0;
		strbuf_reset(&fmt);
	if (prefixlen < 2 || filename[prefixlen - 1] != '.')
		err = write_entry(args, &args->tree->object.oid, args->base,
		archive_time = time(NULL);
		OPT__COMPR_HIDDEN('5', &compression_level, 5),
	return NULL;
	argc = parse_archive_args(argc, argv, &ar, &args, name_hint, remote);
	}
	}
		OPT_END()
		  const char *name_hint, int remote)
		check = get_archive_attrs(c->args->repo->index, base->buf);

static void parse_pathspec_arg(const char **pathspec,

	 * trouble as we test each one separately
				die(_("pathspec '%s' did not match any files"), *pathspec);


				printf("%s\n", archivers[i]->name);
			die(_("no such ref: %.*s"), refnamelen, name);

}
	struct path_exists_context ctx;
	N_("git archive --list"),
			return archivers[i]->name;
				  queue_or_write_archive_entry,
	d->stage   = stage;
		size_t baselen = base->len;
}
	archivers[nr_archivers++] = ar;

	}
	}
	strbuf_reset(&path);
{
	free(to_free);
		}

		exit(0);


		commit_oid = NULL;
	for (i = 0; i < nr_archivers; i++) {
	void *buffer;

		struct strbuf *base, const char *filename,
	ar_args->refname = ref;
		  struct repository *repo,
struct archiver_context {
		strbuf_addbuf(&sb, base);
		if (!b)

	if (pathspec) {
		context.bottom = next;
	/* We need at least one parameter -- tree-ish */
	c->bottom  = d;
		OPT__COMPR('1', &compression_level, N_("compress faster"), 1),
	 * filename).
		c = memchr(b + 8, '$', (src + len) - b - 8);
			pathspec++;
	if (S_ISDIR(mode)) {

		if (!strcmp(name, archivers[i]->name))
	if (args->verbose)
	return write_archive_entry(oid, base->buf, base->len, filename, mode,
	write_archive_entry_fn_t write_entry = c->write_entry;
static int path_exists(struct archiver_args *args, const char *path)
		const struct archiver **ar, struct archiver_args *args,
	if (S_ISDIR(mode) || S_ISGITLINK(mode)) {
	return NULL;
			return 0;
	const char *remote = NULL;
	const struct commit *commit = args->convert ? args->commit : NULL;
void *object_file_to_archive(const struct archiver_args *args,
		if (args->verbose)
	struct path_exists_context *ctx = context;
		OPT_STRING(0, "exec", &exec, N_("command"),
static const struct archiver **archivers;

		if (check_attr_export_ignore(check))
	struct tree *tree;

		struct directory *next = c->bottom->up;
	}
}
{

static int parse_archive_args(int argc, const char **argv,
		if (!dwim_ref(name, refnamelen, &oid, &ref))
			break;
	for (i = 0; i < nr_archivers; i++)
						  const char *path)
	}
	static struct attr_check *check;
	git_config(git_default_config, NULL);
	ar_args->commit = commit;
		if (match_extension(filename, archivers[i]->name))
		 * than what we could write here.
	struct tree_desc t;
	/*
		args->convert = check_attr_export_subst(check);
static int remote_allow_unreachable;
		err = get_tree_entry(ar_args->repo,
	if (!args->worktree_attributes) {
		free(c->bottom);
}
		OPT_GROUP(""),
	if (S_ISDIR(mode)) {
		OPT__COMPR('0', &compression_level, N_("store only"), 0),
	args->worktree_attributes = worktree_attributes;
		unsigned short mode;


	return check;
	if (!name)
				     &tree->object.oid,
		struct strbuf *base, const char *filename,
	const struct archiver *ar = NULL;
		git_attr_set_direction(GIT_ATTR_INDEX);
}
		size_t len = args->baselen;

	if (remote && !remote_allow_unreachable) {

	}
	}
	int prefixlen = strlen(filename) - strlen(ext);
	char *to_free = NULL;
	}

		convert_to_working_tree(args->repo->index, path, buf.buf, buf.len, &buf, &meta);
};
#include "refs.h"
		       "", pathspec);
		check = attr_check_initl("export-ignore", "export-subst", NULL);
		die(_("Unexpected option --remote"));
		const char *b, *c;
		struct archiver_args *ar_args, const char *prefix,
		OPT__COMPR_HIDDEN('6', &compression_level, 6),
			if (**pathspec && !path_exists(ar_args, *pathspec))
	size_t len = st_add4(base->len, 1, strlen(filename), 1);
	struct archiver_args *args;
	ar_args->time = archive_time;
}

	OPT_SET_INT_F(s, NULL, v, h, p, PARSE_OPT_NONEG)
	args->base = base;
			N_("read .gitattributes in working directory")),
		struct directory *next = context.bottom->up;

}
			N_("list supported archive formats")),
	 * We need 1 character for the '.', and 1 character to ensure that the
}
	strbuf_add(&path, args->base, args->baselen);
		opts.head_idx = -1;
		 !strncmp(base->buf, c->bottom->path, c->bottom->len))) {
{
		int baselen, const char *filename, unsigned mode, int stage,

static const struct attr_check *get_archive_attrs(struct index_state *istate,
	struct pretty_print_context ctx = {0};
#include "commit.h"
#include "dir.h"
		int err;
		memset(&opts, 0, sizeof(opts));
	}
{
	ar_args->pathspec.recursive = 1;
		struct strbuf sb = STRBUF_INIT;
		err = 0;
		tree = parse_tree_indirect(&tree_oid);
	 */
		OPT_STRING('o', "output", &output, N_("file"),
static int check_attr_export_subst(const struct attr_check *check)
	while (c->bottom &&

			if (!is_remote || archivers[i]->flags & ARCHIVER_REMOTE)

	}
			len--;
{
	       !(base->len >= c->bottom->len &&
		*sizep = size;
	c->bottom = d->up;

	OPT_SET_INT_F(s, NULL, v, "", p, PARSE_OPT_NONEG | PARSE_OPT_HIDDEN)
	int verbose = 0;
	return argc;

			N_("prepend prefix to each pathname in the archive")),
	int worktree_attributes = 0;

{
	argc = parse_options(argc, argv, NULL, opts, archive_usage, 0);
			return err;

	strbuf_grow(&path, PATH_MAX);
{
		struct object_id tree_oid;
	write_archive_entry_fn_t write_entry;
	int err;
void init_archivers(void)
	d->up	   = c->bottom;
	context.args = args;

		die(_("Unknown archive format '%s'"), format);
	 */
		src  = c + 1;
		unsigned mode, int stage, struct archiver_context *c)
		err = write_entry(args, oid, path.buf, path.len, mode);
{
}
	free(d);
		OPT__COMPR_HIDDEN('3', &compression_level, 3),
	if (!format)
		int refnamelen = colon - name;

struct directory {
				    d->path + d->baselen, d->mode,
	}
		write_archive_entry(&d->oid, d->path, d->baselen,
		while (len > 1 && args->base[len - 2] == '/')
	parse_treeish_arg(argv, &args, prefix, remote);
	struct checkout_metadata meta;
		strbuf_addch(&path, '/');
		return -1;
static int reject_entry(const struct object_id *oid, struct strbuf *base,
	struct archiver_args *args;
	args.repo = repo;

	/*
			       args->commit_oid ? args->commit_oid :

	/*
	struct directory *d = c->bottom;
	args->baselen = strlen(base);

					format, compression_level);
		OPT_STRING(0, "format", &format, N_("fmt"), N_("archive format")),
		       PATHSPEC_PREFER_FULL,

	ctx.pathspec.recursive = 1;
			fprintf(stderr, "%.*s\n", (int)path.len, path.buf);
	ar_args->tree = tree;
		const struct attr_check *check;
		opts.src_index = args->repo->index;
	};
		format = "tar";
	ctx.args = args;


	N_("git archive [<options>] <tree-ish> [<path>...]"),
}
	if (exec)
	*ar = lookup_archiver(format);
	return buffer;
		unsigned mode, int stage, void *context)
	args->compression_level = Z_DEFAULT_COMPRESSION;
{
			const char *filename, unsigned mode,

	ctx.abbrev = DEFAULT_ABBREV;
	int ret;
	int ret;
			ret = READ_TREE_RECURSIVE;
			break;
		 * die ourselves; but its error message will be more specific
		queue_directory(oid->hash, base, filename,

	strbuf_add(&path, base, baselen);

int write_archive(int argc, const char **argv, const char *prefix,
	return ar->write_archive(ar, &args);
	const char *path_without_prefix;
		if ((*ar)->flags & ARCHIVER_WANT_COMPRESSION_LEVELS)
		OPT__COMPR_HIDDEN('2', &compression_level, 2),
			format_subst(commit, buf.buf, buf.len, &buf);
	strbuf_add(buf, src, len);
#include "tree-walk.h"
			die(_("Argument not supported for format '%s': -%d"),
#include "config.h"

{
}
	}
				    sb.buf, sb.len, 0, NULL, 1))
	init_tar_archiver();
	/* Remotes are only allowed to fetch actual refs */
	time_t archive_time;
}

	d->len = xsnprintf(d->path, len, "%.*s%s/", (int)base->len, base->buf, filename);
	if (err == READ_TREE_RECURSIVE)
	memset(&context, 0, sizeof(context));
			     const char *path, const struct object_id *oid,
	if (buffer && S_ISREG(mode)) {
		die(_("not a valid object name: %s"), name);
	struct archiver_args *args = c->args;
		if (err)
		OPT_STRING(0, "remote", &remote, N_("repo"),

		/*
	const char *exec = NULL;
int write_archive_entries(struct archiver_args *args,
		 */
	struct option opts[] = {
			fprintf(stderr, "%.*s\n", (int)len, args->base);
		OPT_BOOL(0, "worktree-attributes", &worktree_attributes,
	if (output)
		if (unpack_trees(1, &t, &opts))
	if (args->baselen > 0 && args->base[args->baselen - 1] == '/') {
		else {
	 * prefix is non-empty (k.e., we don't match .tar.gz with no actual
		write_directory(c) ||
#include "cache.h"
};
		OPT__COMPR_HIDDEN('4', &compression_level, 4),
{
	args->verbose = verbose;
			return 0;
		OPT__COMPR_HIDDEN('8', &compression_level, 8),
			return archivers[i];
}
	if (src == buf->buf)
	strbuf_addstr(&path, filename);
const char *archive_format_from_filename(const char *filename)
	struct pathspec pathspec;
				     &mode);
};
	return err;
		strbuf_addch(base, '/');
		if (err || !S_ISDIR(mode))
		return (S_ISDIR(mode) ? READ_TREE_RECURSIVE : 0);
	ALLOC_GROW(archivers, nr_archivers + 1, alloc_archivers);
	struct unpack_trees_options opts;

	if (argc < 1)

				  0, 0, &ctx.pathspec,
	d->baselen = base->len;
	if (S_ISDIR(mode) || S_ISGITLINK(mode))
	if (!d)
	ret = read_tree_recursive(args->repo, args->tree, "",
		const struct attr_check *check;
				  reject_entry, &ctx);
	if (!S_ISDIR(mode)) {
	parse_pathspec(&ctx.pathspec, 0, 0, "", paths);
#include "archive.h"
	const struct object_id *commit_oid;
		}
	int i;
	struct directory *up;
{
	return ret != 0;

{
		c->bottom = next;
static int alloc_archivers;
	parse_pathspec_arg(argv + 1, &args);
		void *context)
		OPT_STRING(0, "prefix", &base, N_("prefix"),
	const char *format = NULL;
	int err;
	int stage;
		write_archive_entry_fn_t write_entry)
		strbuf_release(&sb);
			 const char *src, size_t len,

		free(context.bottom);
	if (!base)
	init_zip_archiver();
		commit_oid = &commit->object.oid;
{
		if (commit)
		base = "";
	struct strbuf fmt = STRBUF_INIT;
		 * We know this will die() with an error, so we could just
{
		struct archiver_args *ar_args)

		archive_time = commit->date;
#include "parse-options.h"
{
		for (i = 0; i < nr_archivers; i++)
	if (tree == NULL)


				mode, stage, c);
	if (commit) {
#include "unpack-trees.h"
	}
	} else {
		size_t size = 0;

	path_without_prefix = path.buf + args->baselen;
	buffer = read_object_file(oid, type, sizep);

			 struct strbuf *buf)
	ret =
	struct archiver_context context;
		strbuf_add(buf, src, b - src);
	clear_pathspec(&ctx.pathspec);
		if (err)
			N_("path to the remote git-upload-archive command")),
	tree = parse_tree_indirect(&oid);
			     unsigned int mode, enum object_type *type,

			return -1;
};
	const char *name = argv[0];
		opts.fn = oneway_merge;
		struct strbuf buf = STRBUF_INIT;
		format = archive_format_from_filename(name_hint);
	if (get_oid(name, &oid))
#include "object-store.h"

	return ret ? -1 : 0;

	return check && ATTR_TRUE(check->items[0].value);
	return write_entry(args, oid, path.buf, path.len, mode);
	const char *paths[] = { path, NULL };
			int stage, void *context)
			N_("retrieve the archive from remote repository <repo>")),
	parse_pathspec(&ar_args->pathspec, 0,
#include "attr.h"
			       (args->tree ? &args->tree->object.oid : NULL), oid);
}
		if (args->verbose)
		setup_git_directory();
		usage_with_options(archive_usage, opts);
	context.write_entry = write_entry;
		int remote)
		return READ_TREE_RECURSIVE;
