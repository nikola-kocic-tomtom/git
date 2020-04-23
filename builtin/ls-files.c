
	int i;
			if (show_deleted && err)
#include "resolve-undo.h"
	/*
static const char *tag_removed = "";
			construct_fullname(&fullname, repo, ce);
	if ((dir.flags & DIR_SHOW_IGNORED) && !exc_given)
			show_other_files(repo->index, dir);
		setup_work_tree();
				/* If any of the leading directories in


			continue;
	if (get_oid(tree_name, &oid))
	 * Find common prefix for all pathspec's
			continue; /* uninterested */
		die("ls-files --ignored needs some exclude pattern");
 */
	prune_index(the_repository->index, max_prefix, max_prefix_len);

static void show_other_files(const struct index_state *istate,
	unsigned int first, last;

	if (!tree)

		{ OPTION_CALLBACK, 'x', "exclude", &exclude_list, N_("pattern"),
static void show_submodule(struct repository *superproject,
 * Read the tree specified with --with-tree option
	N_("git ls-files [<options>] [<file>...]"),
		switch (ce_stage(ce)) {
static void show_ru_info(const struct index_state *istate)
			       find_unique_abbrev(&ce->oid, abbrev),
		die("git ls-files: internal error - cache entry not superset of prefix");
static void show_killed_files(const struct index_state *istate,
				 * cache, it will be killed.
			/* fallthru */
	argc = parse_options(argc, argv, prefix, builtin_ls_files_options,
#include "config.h"
	parse_pathspec(&pathspec, 0,

					killed = 1;
				 * ent->name in the cache.  Does it expect
static struct pathspec pathspec;
static void write_eolinfo(const struct index_state *istate,
	MOVE_ARRAY(istate->cache, istate->cache + pos, last - pos);
static void show_ce(struct repository *repo, struct dir_struct *dir,

		/*
	setup_standard_excludes(dir);

static int prefix_len;
		if (show_killed)
	if (read_tree(the_repository, tree, 1, &pathspec, istate))
		show_dir_entry(istate, tag_other, ent);
	}
		tag_other = "? ";
		OPT_BOOL('m', "modified", &show_modified,
}
			continue; /* outside of the prefix */
static int show_stage;

			if (ce->ce_flags & CE_UPDATE)
	if (debug_mode) {
			continue;
static int show_valid_bit;


static const char *with_tree;
		add_pattern(exclude_list.items[i].string, "", 0, pl, --exclude_args);
		OPT_BOOL('k', "killed", &show_killed,
			N_("recurse through submodules")),
						ent->len, ent->name);
		 * There's no point in showing unmerged unless


				pos = index_name_pos(istate, ent->name, ent->len);
}
	string_list_append(exclude_list, arg);
		die("ls-files --recurse-submodules does not support "
}
			if (ce_skip_worktree(ce))
		pos = -pos-1;
			if ((dir->flags & DIR_SHOW_IGNORED) &&
static const char *get_tag(const struct cache_entry *ce, const char *tag)
	int i;
	} else
		}
			PARSE_OPT_NONEG, option_parse_exclude },
		int pos, len, killed = 0;
		printf("  size: %u\tflags: %x\n", sd->sd_size, ce->ce_flags);
	if (prefix)
		}
	for (i = 0; i < dir->nr; i++) {
		die("unable to read tree entries %s", tree_name);
		return;
}
			i_txt = get_cached_convert_stats_ascii(istate,
	return 0;
			N_("read additional per-directory exclude patterns in <file>")),
	 * submodule.
		OPT_BOOL('d', "deleted", &show_deleted,
				(ce_skip_worktree(ce) ? tag_skip_worktree :

				continue;
		OPT_BOOL(0, "debug", &debug_mode, N_("show debugging data")),
					pos++; /* skip unmerged */

	if (recurse_submodules)
	exc_given = 1;
	max_prefix_len = get_common_prefix_len(max_prefix);
	}
		OPT_BOOL('o', "others", &show_others,
	BUG_ON_OPT_NEG(unset);
	 */
 * This merges the file listing in the directory cache index
	if (recurse_submodules && error_unmatch)
	}

		OPT__ABBREV(&abbrev),
	if (common_prefix[common_prefix_len - 1] == '/')
{
		 * Basic sanity check; show-stages and show-unmerged

			       ce->ce_mode,
		int bad;
static int abbrev;

		const struct cache_entry *ce = istate->cache[next];
		tag_unmerged = "M ";
	 */
	if (show_unmerged)
	if (tag && *tag && ((show_valid_bit && (ce->ce_flags & CE_VALID)) ||
	int i;



static int show_eol;
		 */
#include "string-list.h"
	if (argc == 2 && !strcmp(argv[1], "-h"))
		struct resolve_undo_info *ui = item->util;
{
	 * be pruned from the index.
			fputs(tag, stdout);
			       find_unique_abbrev(&ui->oid[i], abbrev),

	int len = max_prefix_len;
static void show_files(struct repository *repo, struct dir_struct *dir)
				     const char *arg, int unset)
	pl = add_pattern_list(&dir, EXC_CMDL, "--exclude option");

				ce_stage(ce) ? tag_unmerged :
static void construct_fullname(struct strbuf *out, const struct repository *repo,
	 * be done when recursing into submodules because when a pathspec is
			}

		default:
				ce->ce_flags |= CE_UPDATE;
static int ce_excluded(struct dir_struct *dir, struct index_state *istate,
 *
			       ce_stage(ce));
	UNLEAK(dir);
			}
			if (ce->ce_flags & CE_UPDATE)
};
			 */
static void show_files(struct repository *repo, struct dir_struct *dir);
#include "submodule-config.h"
	 * an empty string in that case (a NULL is good for "").
			int err;
		(show_fsmonitor_bit && (ce->ce_flags & CE_FSMONITOR_VALID)))) {
	/* Treat unmatching pathspec elements as errors */

#include "cache.h"
	if (pos < 0)
	common_prefix_len = strlen(common_prefix);
{
static int show_unmerged;
		OPT_BOOL('f', NULL, &show_fsmonitor_bit,
				continue;
		bad = report_path_error(ps_matched, &pathspec);
static void prune_index(struct index_state *istate,
	struct dir_struct *dir = opt->value;
	return 0;
	while (last > first) {
			alttag[2] = ' ';
	struct option builtin_ls_files_options[] = {
				continue;
		/*
							       ce->name);
		if (isalpha(tag[0])) {
	strbuf_release(&fullname);
		for (i = 0; i < repo->index->cache_nr; i++) {
					break;
	return common_prefix_len;

			N_("exclude patterns are read from <file>"),
	if (show_cached || show_stage) {
	}
		die("index file corrupt");
		OPT_SET_INT('z', NULL, &line_terminator,
	if (!istate->resolve_undo)
	/*

				   stdout, line_terminator);
		return;
{

{
			alttag[3] = 0;
				 */
		die("index file corrupt");
		const char *w_txt = "";
static int show_modified;
	return 0;

		printf("  uid: %u\tgid: %u\n", sd->sd_uid, sd->sd_gid);
	if (repo_read_index(the_repository) < 0)
			 * If there is stage #0 entry for this, we do not
	pos = index_name_pos(istate, prefix, prefixlen);
			PARSE_OPT_NOARG | PARSE_OPT_NONEG,
		printf("i/%-5s w/%-5s attr/%-17s\t", i_txt, w_txt, a_txt);
	git_config(git_default_config, NULL);

		} else {
				  S_ISDIR(ce->ce_mode) ||
}
		memset(&pathspec, 0, sizeof(pathspec));
		last = next;
		       prefix, argv);
	/* Hoist the unmerged entries up to stage #3 to make room */
	if (recurse_submodules && S_ISGITLINK(ce->ce_mode) &&
	BUG_ON_OPT_ARG(arg);
{
	static char alttag[4];
		write_name(fullname);
	if (!(show_stage || show_deleted || show_others || show_unmerged ||
	tree = parse_tree_indirect(&oid);
					     ent->name, ent->len) &&
	else
	    (show_stage || show_deleted || show_others || show_unmerged ||

		}
		OPT_BOOL(0, "resolve-undo", &show_resolve_undo,
		 * would not make any sense with this option.
{
	int common_prefix_len;

	if (len > ent->len)
			write_name(path);
			show_ce(repo, dir, ce, fullname.buf,
 * Prune the index to only contain stuff starting with "prefix"
	struct tree *tree;
}
{
}
			PARSE_OPT_NONEG, option_parse_exclude_from },
	for (i = 0; i < istate->cache_nr; i++) {

	for_each_string_list_item(item, istate->resolve_undo) {
			N_("show other files in the output")),
	 * With "--full-name", prefix_len=0; this caller needs to pass

			       i + 1);
			/*
				if (0 <= pos)

	 * This is used as a performance optimization which unfortunately cannot
static void print_debug(const struct cache_entry *ce)
			show_dir_entry(istate, tag_killed, dir->entries[i]);

		static const char *(matchbuf[1]);
			if (!sp) {

 * that were given from the command line.  We are not
			err = lstat(fullname.buf, &st);
		show_stage = 1;
				    !strncmp(istate->cache[pos]->name,
	struct pattern_list *pl;
	show_files(&subrepo, dir);
		case 1:
		OPT_BOOL('t', NULL, &show_tag,

		tag = alttag;
			N_("show ignored files in the output"),
		require_work_tree = 1;
			const struct cache_entry *ce = repo->index->cache[i];
		    const char *tag)
			DIR_SHOW_IGNORED),
				 * ent->name is registered in the cache,
}
	strbuf_addstr(out, ce->name);
				    istate->cache[pos]->name[ent->len] == '/')

 * combinations of the two.
	prefix = cmd_prefix;

}
static int show_deleted;
	BUG_ON_OPT_NEG(unset);
			alttag[1] = tag[0];
		parse_pathspec(&pathspec, PATHSPEC_ALL_MAGIC,

		 */
	int i;

	const char *max_prefix;
		if (killed)
		matchbuf[0] = NULL;
{

static int show_fsmonitor_bit;
			fprintf(stderr, "Did you forget to 'git add'?\n");

	struct pathspec pathspec;
		OPT_BIT('i', "ignored", &dir.flags,
static void show_dir_entry(const struct index_state *istate,

	}
					BUG("killed-file %.*s not found",
}
		OPT_BOOL('v', NULL, &show_valid_bit,
static const char *tag_killed = "";
		show_cached = 1;
{
				if ((ent->len < len) &&
	if (with_tree) {
static int max_prefix_len;
	write_name(ent->name);
	     show_killed || show_modified || show_resolve_undo || with_tree))
	for (i = 0; i < dir->nr; i++) {
				 * ent->name will be killed.
		if (show_stage || show_unmerged)
{
static int option_parse_exclude_from(const struct option *opt,
		       const char *fullname, const struct cache_entry *ce)
			N_("show 'other' directories' names only"),
		ce->ce_flags |= CE_STAGEMASK;
		    const struct cache_entry *ce, const char *fullname,
{
				 tag_cached));
	struct string_list *exclude_list = opt->value;

		}
		tag_removed = "R ";
		/* Think twice before adding "--nul" synonym to this */
		tag_cached = "H ";
		OPT_BOOL(0, "error-unmatch", &error_unmatch,
}
	if (dir.exclude_per_dir)
	struct string_list exclude_list = STRING_LIST_INIT_NODUP;
				len = ce_namelen(istate->cache[pos]);
{
	NULL
		overlay_tree_on_index(the_repository->index, with_tree, max_prefix);

}
			N_("use lowercase letters for 'assume unchanged' files")),
		{ OPTION_CALLBACK, 0, "exclude-standard", &dir, NULL,
			N_("skip files matching pattern"),
		show_ru_info(the_repository->index);
			       const struct cache_entry *ce)
				show_ce(repo, dir, ce, fullname.buf, tag_removed);
static int line_terminator = '\n';
	}
		const char *path = item->string;

	write_eolinfo(istate, NULL, ent->name);
		die("tree-ish %s not found.", tree_name);
			const char *prefix, size_t prefixlen)
			N_("show files on the filesystem that need to be removed")),

			      const struct dir_struct *dir)

			if (show_modified && ie_modified(repo->index, ce, &st, 0))
		if (!match_pathspec(istate, &pathspec, path, len,
	 * given which spans repository boundaries you can't simply remove the

			last_stage0 = ce;
static int show_killed;
				const char *arg, int unset)
	if (repo_read_index(&subrepo) < 0)
		if (!show_others)
#include "parse-options.h"
		usage_with_options(ls_files_usage, builtin_ls_files_options);
	struct object_id oid;
		const char *a_txt = get_convert_attr_ascii(istate, path);
	int dtype = ce_to_dtype(ce);
			die("ls-files --with-tree is incompatible with -s or -u");
#include "repository.h"
			N_("show modified files in the output")),
					 const char *arg, int unset)
				/* pos points at a name immediately after
			N_("pretend that paths removed since <tree-ish> are still present")),
	}
			     const struct dir_struct *dir)
static int error_unmatch;
#include "dir.h"
void overlay_tree_on_index(struct index_state *istate,
		    "--error-unmatch");
	}
			construct_fullname(&fullname, repo, ce);
		tag_resolve_undo = "U ";
	for (i = 0; i < istate->cache_nr; i++) {
				  S_ISGITLINK(ce->ce_mode))) {
 * --error-unmatch to list and check the path patterns
			const struct cache_entry *ce = repo->index->cache[i];
	return is_excluded(dir, istate, fullname, &dtype);
				show_ce(repo, dir, ce, fullname.buf, tag_modified);
	strbuf_reset(out);
			 * need to show it.  We use CE_UPDATE bit to mark
			N_("identify the file status with tags")),
	}

	if (show_deleted || show_modified) {
				 */
			alttag[0] = '!';
}
	write_name_quoted_relative(name, prefix_len ? prefix : NULL,
		OPT_NEGBIT(0, "empty-directory", &dir.flags,

		struct stat st;
static const char *tag_unmerged = "";
		printf("  dev: %u\tino: %u\n", sd->sd_dev, sd->sd_ino);
			  const struct cache_entry *ce, const char *path)
{
		common_prefix_len--;

			if (0 <= index_name_pos(istate, ent->name, sp - ent->name)) {
			w_txt = get_wt_convert_stats_ascii(path);
			continue;
	add_patterns_from_file(dir, arg);
	exc_given = 1;
		char *cp, *sp;

		for (i = 0; i < 3; i++) {
			DIR_SHOW_OTHER_DIRECTORIES),
static const char *tag_skip_worktree = "";

 * Copyright (C) Linus Torvalds, 2005
			alttag[0] = tolower(tag[0]);
		} else {
/*
				continue;

				 * ent->name to be a directory?
		int i, len;

	 * If the prefix has a trailing slash, strip it so that submodules wont
	struct cache_entry *last_stage0 = NULL;
 * (typically, HEAD) into stage #1 and then
			continue;
		tag_skip_worktree = "S ";
			if ((dir->flags & DIR_SHOW_IGNORED) &&
static const char *tag_resolve_undo = "";
	/* For cached/deleted files we don't need to even do the readdir */
			N_("paths are separated with NUL character"), '\0'),
	if (prefix) {
}
	if (repo->submodule_prefix)
		if (bad)


 * squash them down to stage #0.  This is used for
		OPT_BOOL(0, "recurse-submodules", &recurse_submodules,

				killed = 1;
		prefix_len = strlen(prefix);
	if (show_resolve_undo)
	if (require_work_tree && !is_inside_work_tree())

		case 0:
static int debug_mode;

/*
 * with the actual working directory list, and shows different
			    !ce_excluded(dir, repo->index, fullname.buf, ce))
			N_("show deleted files in the output")),
			N_("don't show empty directories"),
{
			ls_files_usage, 0);
				continue;
			printf("%s%06o %s %d\t",
			    !ce_excluded(dir, repo->index, fullname.buf, ce))
#include "quote.h"
	struct repository subrepo;
		OPT_END()
}


	};
{
{
		max_prefix = NULL;
	return 0;
}
		if (!ce_stage(ce))

	const struct submodule *sub = submodule_from_path(superproject,

			   const char *tag, struct dir_entry *ent)
		fill_directory(dir, repo->index, &pathspec);
		OPT_BOOL('c', "cached", &show_cached,
static int option_parse_exclude(const struct option *opt,
			DIR_HIDE_EMPTY_DIRECTORIES),
	show_files(the_repository, &dir);
			if (!ui->mode[i])
		tag_modified = "C ";

	    is_submodule_active(repo, ce->name)) {
		tag_killed = "K ";
			N_("if any <file> is not in the index, treat this as an error")),

	} else if (match_pathspec(repo->index, &pathspec, fullname, strlen(fullname),
				    max_prefix_len, ps_matched, 0))
		OPT_BOOL('u', "unmerged", &show_unmerged,
		die("ls-files --recurse-submodules unsupported mode");
	if (recurse_submodules &&
		if (!strncmp(ce->name, prefix, prefixlen)) {
static char *ps_matched;
static int show_cached;
				break;
}
	if (max_prefix_len > strlen(fullname))
		memcpy(alttag, tag, 3);
				       ce_stage(istate->cache[pos]))
			N_("show cached files in the output (default)")),
		max_prefix = common_prefix(&pathspec);
	}
		if (len < max_prefix_len)
			 * such an entry.
		} else if (tag[0] == '?') {


static int exc_given;
		OPT_BOOL('s', "stage", &show_stage,
	int pos;

		die("bad tree-ish %s", tree_name);
	for (i = 0; i < exclude_list.nr; i++) {
	first = pos;
			   const char *tree_name, const char *prefix)
			      0, PARSE_OPT_NONEG),
			printf("%s%06o %s %d\t", tag_resolve_undo, ui->mode[i],
		for (i = 0; i < repo->index->cache_nr; i++) {
		struct cache_entry *ce = istate->cache[i];
		OPT_STRING(0, "exclude-per-directory", &dir.exclude_per_dir, N_("file"),

#include "tree.h"

		return;
#include "builtin.h"
		OPT_BIT(0, "directory", &dir.flags,
static const char *tag_modified = "";
 * going to write this index out.
	struct string_list_item *item;
	memset(&dir, 0, sizeof(dir));
static const char *tag_other = "";
		exc_given = 1;
	if (show_others || show_killed) {

	repo_clear(&subrepo);
		ps_matched = xcalloc(pathspec.nr, 1);
#include "run-command.h"
		const struct stat_data *sd = &ce->ce_stat_data;
		}
static int recurse_submodules;
	}
			alttag[0] = 'v';
	/* With no flags, we default to showing the cached files */
	BUG_ON_OPT_NEG(unset);
		 * you also show the stage information.
}

	struct strbuf fullname = STRBUF_INIT;
/*
static const char *prefix;
static void write_name(const char *name)
int cmd_ls_files(int argc, const char **argv, const char *cmd_prefix)
			       tag,
	if (show_eol) {
	if (show_tag || show_valid_bit || show_fsmonitor_bit) {
}
	}

	if (!prefix || !istate->cache_nr)
		if (!show_stage) {
		if (show_others)
		die("git ls-files: internal error - directory entry not superset of prefix");
			      N_("make the output relative to the project top directory"),
{
		tag = get_tag(ce, tag);
static int get_common_prefix_len(const char *common_prefix)
	last = istate->cache_nr;
	 */
		if (ce && S_ISREG(ce->ce_mode))

			N_("use lowercase letters for 'fsmonitor clean' files")),
		printf("  mtime: %u:%u\n", sd->sd_mtime.sec, sd->sd_mtime.nsec);
				 */
		for (cp = ent->name; cp - ent->name < ent->len; cp = sp + 1) {
			sp = strchr(cp, '/');

{
		struct dir_entry *ent = dir->entries[i];
		}

	if (show_modified || show_others || show_deleted || (dir.flags & DIR_SHOW_IGNORED) || show_killed)
			N_("add the standard git exclusions"),
			   struct dir_struct *dir, const char *path)
}

	return tag;
			show_killed_files(repo->index, dir);
		if (!index_name_is_other(istate, ent->name, ent->len))
#include "pathspec.h"
			if (last_stage0 &&
		strbuf_addstr(out, repo->submodule_prefix);
	if (!common_prefix)
	istate->cache_nr = last - pos;
		const char *i_txt = "";
			    !strcmp(last_stage0->name, ce->name))
			       PATHSPEC_PREFER_CWD, prefix, matchbuf);
static int exclude_args;
	if (repo_submodule_init(&subrepo, superproject, sub))
		if (!lstat(path, &st) && S_ISREG(st.st_mode))
{
		return 0;
	exc_given = 1;
			N_("show staged contents' object name in the output")),
	}
	if (!dir_path_match(istate, ent, &pathspec, len, ps_matched))
		{ OPTION_CALLBACK, 'X', "exclude-from", &dir, N_("file"),
			    N_("show resolve-undo information")),
		return bad ? 1 : 0;
		OPT_BOOL(0, "eol", &show_eol, N_("show line endings of files")),

			first = next+1;
				  max_prefix_len, ps_matched,
	if (pathspec.nr && error_unmatch)
	}
	struct dir_struct *dir = opt->value;
				while (pos < istate->cache_nr &&
#include "submodule.h"
		write_eolinfo(repo->index, ce, fullname);
		show_submodule(repo, dir, ce->name);
		}
		return;
	}
			option_parse_exclude_standard },
		printf("  ctime: %u:%u\n", sd->sd_ctime.sec, sd->sd_ctime.nsec);
		int next = first + ((last - first) >> 1);
	if (ps_matched) {
static const char * const ls_files_usage[] = {
	 * submodule entry because the pathspec may match something inside the
		OPT_STRING(0, "with-tree", &with_tree, N_("tree-ish"),
	/*
static int show_resolve_undo;
static int option_parse_exclude_standard(const struct option *opt,
		print_debug(ce);
 */
				continue;
				/* If ent->name is prefix of an entry in the

		len = strlen(path);
		struct dir_entry *ent = dir->entries[i];
	}
	struct dir_struct dir;

		OPT_SET_INT_F(0, "full-name", &prefix_len,
		       PATHSPEC_PREFER_CWD,
	}

			N_("show unmerged files in the output")),
				pos = -pos - 1;
static int show_others;
				continue;
static const char *tag_cached = "";
		}
	fputs(tag, stdout);

	      show_killed || show_modified || show_resolve_undo))
			dir->flags |= DIR_COLLECT_KILLED_ONLY;
		struct cache_entry *ce = istate->cache[i];
				break;
			struct stat st;
	int require_work_tree = 0, show_tag = 0, i;
			if (show_unmerged && !ce_stage(ce))
							  &null_oid, path);
				if (istate->cache_nr <= pos)
 */
