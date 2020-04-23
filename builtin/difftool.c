		if (!data)
static int parse_index_info(char *p, int *mode1, int *mode2,
			strbuf_reset(&buf);
					goto finish;
						ADD_CACHE_JUST_APPEND);
		goto finish;
 *
			 N_("make 'git-difftool' exit when an invoked diff "
		if (*entry->left) {
	update_index.no_stdout = 1;
			1, PARSE_OPT_NONEG | PARSE_OPT_HIDDEN),
	memset(&wtindex, 0, sizeof(wtindex));


		    const struct hashmap_entry *eptr,
	strbuf_release(&buf);
	};
	discard_cache_entry(ce);
	env[0] = index_env.buf;
		ret = error("error occurred running diff --raw");
	struct strbuf ldir = STRBUF_INIT, rdir = STRBUF_INIT;

	}
		hashmap_add(map, &e->entry);
		flags = 0;

	else if (difftool_cmd) {
	if (use_gui_tool)
				entry /* member name */) {
			 "--unmerged", NULL);
	if (!no_index && !startup_info->have_repository)

	return run_file_diff(prompt, prefix, argc, argv);
			add_path(&rdir, rdir_len, entry->path);
	 * should be copied back to the working tree.

static int difftool_config(const char *var, const char *value, void *cb)
#include "builtin.h"
}
						      st.st_mode)) {
	strbuf_addf(&rdir, "%s/right/", tmpdir);
#define USE_THE_INDEX_COMPATIBILITY_MACROS
	argv_array_pushl(&child.args, "diff", "--raw", "--no-abbrev", "-z",
		if (*extcmd)
		int fd = open(buf.buf, O_RDONLY);
	 * If the diff includes working copy files and those
		if (lmode && status != 'C') {
	existing = hashmap_get_entry(map, e, entry, NULL);
			}
{
	child.no_stdin = 1;
					ret = error("could not create "
						goto finish;
		return error("expected ':', got '%c'", *p);
	const char *helper_argv[] = { "difftool--helper", NULL, NULL, NULL };
	if (*p != ' ')
	struct strbuf info = STRBUF_INIT, lpath = STRBUF_INIT;
}
{
	strbuf_release(&index_env);
		    const struct hashmap_entry *entry_or_key,
	child.clean_on_exit = 1;
		return error("could not create '%s'", tmpdir);
			die(_("no <tool> given for --tool=<tool>"));
	char left[PATH_MAX], right[PATH_MAX];
		}
	if (*p != ':')

};
	b = container_of(entry_or_key, const struct working_tree_entry, entry);
			changed_files(&tmp_modified, buf.buf, rdir.buf);

			if (strbuf_getline_nul(&rpath, fp))
	 */
						    "directory for '%s'",
	for (i = 0; i < wtindex.cache_nr; i++) {
				warning_errno(_("could not copy '%s' to '%s'"),

			     PARSE_OPT_KEEP_DASHDASH);
	 * These hashes are loaded lazily since they aren't needed
		OPT_BOOL('g', "gui", &use_gui_tool,
	child.out = -1;
		    !index_fd(&the_index, &wt_oid, fd, &st, OBJ_BLOB, name, 0)) {
				oidcpy(oid, &wt_oid);
						goto finish;
			dst_path = src_path;
			 "--git-dir", git_dir, "--work-tree", workdir,
	struct hashmap working_tree_dups, submodules, symlinks2;
			continue;
		warning(_("failed: %d"), exit_code);
			strbuf_addf(&buf, "%s/wtindex", tmpdir);
	*status = *++p;
	hashmap_for_each_entry(&submodules, &iter, entry,
			struct working_tree_entry *entry;
{
static int trust_exit_code;

	}
		const char *src_path, *dst_path;
 * and a SHA-1 surrounded by brief text for submodules.
 * as the goal of the dir-diff mode is to produce an output that is logically
	struct child_process diff_files = CHILD_PROCESS_INIT;
	a = container_of(eptr, const struct path_entry, entry);
#include "strbuf.h"
	char *data;
	lstate.base_dir_len = ldir.len;
	/* Ignore any errors of update-index */
		const char *name = wtindex.cache[i]->name;
	if (err) {
	if (fp)
			} else if (unlink(wtdir.buf) ||

				add_index_entry(&wtindex, ce2,
			 NULL);
			setenv("GIT_DIFFTOOL_EXTCMD", extcmd, 1);
	b = container_of(entry_or_key, const struct pair_entry, entry);

	 * to compare the a / b directories. In file diff mode, 'git diff'
			hashmap_add(&working_tree_dups, &entry->entry);
			    "tool returns a non - zero exit code")),
static int run_file_diff(int prompt, const char *prefix,
	if (exit_code)
 * to compare the readlink(2) result as text, even on a filesystem that is
				die(_("could not read symlink %s"), path);
		struct object_id loid, roid;
	struct child_process child = CHILD_PROCESS_INIT;
			write_file(ldir.buf, "%s", entry->left);
	/*
	a = container_of(eptr, const struct working_tree_entry, entry);
		else
{
		OPT_STRING('x', "extcmd", &extcmd, N_("command"),
 * Any arguments that are unknown to this script are forwarded to 'git diff'.
	tmp = getenv("TMPDIR");
 * The `left` and `right` entries hold paths for the symlinks hashmap,
						    dst_path);
 * the symlink that gets written to a regular file to force the external tool
		"GIT_PAGER=", "GIT_EXTERNAL_DIFF=git-difftool--helper", NULL,
	 * Do not copy back files when symlinks are used and the
		if (*entry->right) {
	struct hashmap wt_modified, tmp_modified;
	ldir_len = ldir.len;
	strbuf_release(&buf);
	while (!strbuf_getline_nul(&buf, fp)) {
	return 0;
		}
		unsigned long size;
		/* The symlink is unknown to Git so read from the filesystem */
				continue;
	*mode2 = (int)strtol(p + 1, &p, 8);


	add_path(&buf, buf.len, name);
	int use = 0;
	strbuf_addstr(&wtdir, workdir);
	if (start_command(&child))
		OPT_SET_INT_F('y', "no-prompt", &prompt,
				if (symlinks) {

	strbuf_addstr(&buf, workdir);
	    tool_help = 0, no_index = 0;
	struct strbuf wtdir = STRBUF_INIT;
		fclose(fp);
static int working_tree_entry_cmp(const void *unused_cmp_data,
	/* Build index info for left and right sides of the diff */
#include "dir.h"
		}
static int checkout_path(unsigned mode, struct object_id *oid,
			if (oideq(&loid, &roid))
 */
/*
				err = 1;
	diff_files.env = env;
				ret = error("could not write %s", buf.buf);
			add_path(&rdir, rdir_len, name);
	for (i = 0; i < argc; i++)
{
	rstate.base_dir = rbase_dir = xstrdup(rdir.buf);
	mkdir(ldir.buf, 0700);
			add_left_or_right(&submodules, dst_path, buf.buf, 1);
	 */
				     &status))
			if (hashmap_get(&wt_modified, &dummy, name)) {
static void add_left_or_right(struct hashmap *map, const char *path,
 * before starting to avoid double slashes in symlink targets.
			break;
	for (i = 0; i < argc; i++)
	update_index.git_cmd = 1;
}
				ret = error("could not write '%s'", src_path);
		if (S_ISLNK(lmode)) {
						  &rstate)) {
				break;
		data = read_object_file(oid, &type, &size);
		struct hashmap_entry dummy;
				       "of '%s'"), path);
						ret = error_errno("could not symlink '%s' to '%s'", wtdir.buf, rdir.buf);
		return 0;
	const char path[FLEX_ARRAY];
					ret = error("could not write '%s'",
	hashmap_init(&symlinks2, pair_cmp, NULL, 0);
				entry /* member name */) {
	exit(ret);
		OPT_STRING('t', "tool", &difftool_cmd, N_("tool"),
	return strcmp(a->path, b->path);

		NULL
			if (hold_lock_file_for_update(&lock, buf.buf, 0) < 0 ||
				    oid_to_hex(&loid));
		i++;
			continue;
	struct option builtin_difftool_options[] = {
	*mode1 = (int)strtol(p + 1, &p, 8);
			ensure_leading_directories(rdir.buf);
	if (*p != ' ')
		return error("expected ' ', got '%c'", *p);
			write_file(rdir.buf, "%s", entry->right);
	int ret = 0, i;
 * Copyright (C) 2016 Johannes Schindelin
	const char *git_dir = absolute_path(get_git_dir()), *env[] = {
#include "argv-array.h"
		}
static int path_entry_cmp(const void *unused_cmp_data,

		return error("missing status");
		die(_("--gui, --tool and --extcmd are mutually exclusive"));

	workdir = get_git_work_tree();
		die("could not obtain raw diff");
static void changed_files(struct hashmap *result, const char *index_path,
 *
				goto finish;

	child.git_cmd = 1;
int cmd_difftool(int argc, const char **argv, const char *prefix)
	}


		free(e);

			write_file(ldir.buf, "%s", entry->left);
			 N_("use symlinks in dir-diff mode")),
				goto finish;
			return 0;
	rdir_len = rdir.len;
}
					}
		e->left[0] = e->right[0] = '\0';
	return run_command_v_opt(argv, RUN_GIT_CMD);
 * difference of the target of the symbolic link, which is not what we want,
	update_index.use_shell = 0;
	update_index.dir = workdir;
	 * files were modified during the diff, then the changes
		if (fd >= 0 &&
	strbuf_addf(&index_env, "GIT_INDEX_FILE=%s", index_path);
				warning(_("working tree file has been left."));
				oid_to_hex(oid), path);

			 "diff-files", "--name-only", "-z", NULL);
			}
		env[2] = "GIT_DIFFTOOL_NO_PROMPT=true";
 */
	/*
	} else {
			continue;
	char tmpdir[PATH_MAX];

				if (ensure_leading_directories(rdir.buf)) {
 * Remove any trailing slash from $workdir
						ret = error("could not copy '%s' to '%s'", wtdir.buf, rdir.buf);
{
		die("could not obtain raw diff");
	if (parse_oid_hex(++p, oid1, (const char **)&p))
			}

	else if (!prompt)
}

					struct stat st;
			    char *status)
			add_left_or_right(&symlinks2, dst_path, content, 1);
				struct cache_entry *ce2 =

			strbuf_addf(&buf, "Subproject commit %s",
#include "run-command.h"
	strbuf_release(&ldir);

	       trust_exit_code ? "true" : "false", 1);
	if (tool_help)
	git_config(difftool_config, NULL);
			return error(_("could not create leading directories "
	 * external tool did not replace the original link with a file.
 * Most importantly, we want to get textual comparison of the result of the
	strbuf_setlen(buf, base_len);
			} else if (oideq(oid, &wt_oid))
			int argc, const char **argv)
	if (extcmd) {
	argv_array_pushl(&diff_files.args,
				}
	fclose(fp);
			strbuf_setlen(&rdir, rdir_len);
#include "exec-cmd.h"



			 N_("use `diff.guitool` instead of `diff.tool`")),

static int pair_cmp(const void *unused_cmp_data,
				  const struct hashmap_entry *entry_or_key,
	struct strbuf buf = STRBUF_INIT;
	diff_files.out = -1;
	hashmap_init(&wt_modified, path_entry_cmp, NULL, wtindex.cache_nr);
static NORETURN void exit_cleanup(const char *tmpdir, int exit_code)
	mkdir(rdir.buf, 0700);
 * show a diff of two directories (e.g. "diff -r A B").
		struct path_entry *entry;
	strbuf_addstr(buf, path);
	strbuf_release(&buf);
			strbuf_reset(&buf);
	char path[FLEX_ARRAY];
	struct strbuf rpath = STRBUF_INIT, buf = STRBUF_INIT;
	return use;
	update_index.no_stderr = 1;
#include "object-store.h"



	child.dir = prefix;
};
			} else if (!is_null_oid(&roid)) {
				/*
				 * Changes in the working tree need special
	if (!lstat(buf.buf, &st) && !S_ISLNK(st.st_mode)) {
static int print_tool_help(void)
 * readlink(2).  get_symlink() provides that---it returns the contents of
	struct hashmap_entry entry;
	 *
{
		OPT_END()
	int use_gui_tool = 0, dir_diff = 0, prompt = -1, symlinks = 0,
			if (strbuf_readlink(&link, path, strlen(path)))
	a = container_of(eptr, const struct pair_entry, entry);
	int ret = 0, i;
			  const char *workdir)
	if (parse_oid_hex(++p, oid2, (const char **)&p))
#include "cache.h"
	} else

	struct cache_entry *ce;
	char *lbase_dir, *rbase_dir;
			dst_path = rpath.buf;
				    oid_to_hex(&roid));
	if (start_command(&diff_files))
	xsnprintf(tmpdir, sizeof(tmpdir), "%s/git-difftool.XXXXXX", tmp ? tmp : "/tmp");
		add_path(&rdir, rdir_len, name);
	strbuf_setlen(&ldir, ldir_len);
	struct hashmap_entry entry;
 * "git difftool" builtin command
				}
 * equivalent to what "git diff" produces.
			if (!use_wt_file(workdir, dst_path, &roid)) {

		warning(_("you may want to cleanup or recover these."));
	} else
		char status;
		struct strbuf link = STRBUF_INIT;
{
	 */

		return error("expected ' ', got '%c'", *p);
	if (!mkdtemp(tmpdir))
 * This is a wrapper around the GIT_EXTERNAL_DIFF-compatible
			FLEX_ALLOC_STR(entry, path, dst_path);
			 "update-index", "--really-refresh", "-q",


			      const char *content, int is_right)
			ensure_leading_directories(rdir.buf);
{
	struct hashmap_iter iter;
		argv_array_push(&child.args, argv[i]);
	const struct working_tree_entry *a, *b;
}

			/* Avoid duplicate working_tree entries */
			ensure_leading_directories(ldir.buf);
	diff_files.dir = workdir;
		setup_work_tree();


}
 *
		} else {
};
	switch (safe_create_leading_directories(path)) {
			die(_("no <cmd> given for --extcmd=<cmd>"));
 * "git difftool --dir-diff" wants to do for symlinks.  We are preparing two
			   N_("specify a custom command for viewing diffs")),
		}
	if (prompt > 0)
			add_left_or_right(&symlinks2, src_path, content, 0);
		NULL, NULL
	setenv("GIT_DIFFTOOL_TRUST_EXIT_CODE",
		if (S_ISGITLINK(lmode) || S_ISGITLINK(rmode)) {
					if (copy_file(rdir.buf, wtdir.buf,
	FILE *fp;
 * This script exports GIT_EXTERNAL_DIFF and GIT_PAGER for use by git.
					if (symlink(wtdir.buf, rdir.buf)) {
	if (buf->len && buf->buf[buf->len - 1] != '/')
			ensure_leading_directories(ldir.buf);
	return ret;
 *
			N_("do not prompt before launching a diff tool"),
			  const struct hashmap_entry *eptr,
}
 * these temporary directories, it will try to dereference and show the
	struct stat st;
	 * each file that changed.
	 * In directory diff mode, 'git-difftool--helper' is called once
	hashmap_init(&submodules, pair_cmp, NULL, 0);
	 * Symbolic links require special treatment.The standard "git diff"
						st.st_mode = 0644;
	} else {
	 * temporary file to both the left and right directories to show the
	strlcpy(is_right ? e->right : e->left, content, PATH_MAX);
	fp = NULL;
					make_cache_entry(&wtindex, rmode, &roid,


/*

		OPT_BOOL(0, "trust-exit-code", &trust_exit_code,
		OPT_BOOL(0, "tool-help", &tool_help,
struct pair_entry {
					}
		FLEX_ALLOC_STR(entry, path, buf.buf);
		} else if (strbuf_read_file(&link, path, 128))
					NULL)) {
	if (!*status)


	struct pair_entry *e, *existing;
 */
		if (*difftool_cmd)
		argv_array_push(&args, argv[i]);

	N_("git difftool [<options>] [<commit> [<commit>]] [--] [<path>...]"),


static void add_path(struct strbuf *buf, size_t base_len, const char *path)
	struct strbuf index_env = STRBUF_INIT, buf = STRBUF_INIT;
	const char *env[] = {
		strbuf_addch(&wtdir, '/');
			setenv("GIT_DIFF_TOOL", difftool_cmd, 1);

		if (strbuf_getline_nul(&lpath, fp))
 *

		case SCLD_EXISTS:
		OPT_SET_INT_F(0, "prompt", &prompt, NULL,
			free(content);

	wtdir_len = wtdir.len;
			if (is_null_oid(oid)) {
			break;
		exit_cleanup(tmpdir, rc);
	symlinks = has_symlinks;
	}
	struct pair_entry *entry;
		}
		case SCLD_OK:
	/*
			strbuf_reset(&buf);
static char *get_symlink(const struct object_id *oid, const char *path)

struct working_tree_entry {
				use = 1;
	remove_dir_recursively(&buf, 0);
		setenv("GIT_MERGETOOL_GUI", "true", 1);
				add_path(&wtdir, wtdir_len, dst_path);
	update_index.env = env;
		return error("expected object ID, got '%s'", p);

		return error("unexpected trailer: '%s'", p + 1);
		setenv(GIT_WORK_TREE_ENVIRONMENT, absolute_path(get_git_work_tree()), 1);
	free(lbase_dir);
	return git_default_config(var, value, cb);

		if (!indices_loaded) {
	strbuf_release(&rdir);
				use = 1;
	}

	strbuf_addstr(&buf, tmpdir);
}
	if (*p != ' ')
		if (*entry->left) {
	size_t ldir_len, rdir_len, wtdir_len;
	ret = checkout_entry(ce, state, NULL, NULL);
	helper_argv[2] = rdir.buf;
			 const char *path, const struct checkout *state)
					goto finish;
		if (hashmap_get(&tmp_modified, &dummy, name)) {
		if ((symlinks && S_ISLNK(st.st_mode)) || !S_ISREG(st.st_mode))
/*
					wtdir.buf, rdir.buf);
	diff_files.no_stdin = 1;
	int ret;
			add_path(&rdir, rdir_len, entry->path);
		setenv("GIT_DIFFTOOL_DIRDIFF", "true", 1);

	strbuf_setlen(&rdir, rdir_len);
	if (!strcmp(var, "difftool.trustexitcode")) {
	const char *argv[] = { "mergetool", "--tool-help=diff", NULL };
}
		default:

	if (!no_index){

		hashmap_entry_init(&entry->entry, strhash(buf.buf));
				  const void *unused_keydata)
	const struct pair_entry *a, *b;

{
}

	diff_files.clean_on_exit = 1;
	struct child_process update_index = CHILD_PROCESS_INIT;
		return run_dir_diff(extcmd, symlinks, prefix, argc, argv);
 *

 * git-difftool--helper script.
		if (rmode && !S_ISLNK(rmode)) {

	argv_array_push(&args, "diff");

	free(rbase_dir);
		OPT_BOOL('d', "dir-diff", &dir_diff,
	hashmap_init(&working_tree_dups, working_tree_entry_cmp, NULL, 0);
	 * change in the recorded SHA1 for the submodule.
		}
			0, PARSE_OPT_NONEG),
			char *content = get_symlink(&roid, dst_path);
	FILE *fp;
{
{
				free(entry);
#include "config.h"

	diff_files.git_cmd = 1;
 * temporary directories to be fed to a Git-unaware tool that knows how to
		hashmap_entry_init(&dummy, strhash(name));
				strbuf_addstr(&buf, "-dirty");
			if (hashmap_get(&working_tree_dups, &entry->entry,
	run_command(&update_index);
			char *content = get_symlink(&loid, src_path);
	 * files through the symlink.

		if (parse_index_info(info.buf, &lmode, &rmode, &loid, &roid,
			}
	hashmap_init(&tmp_modified, path_entry_cmp, NULL, wtindex.cache_nr);
		enum object_type type;

	i = 0;
}
			if (checkout_path(lmode, &loid, src_path, &lstate)) {
			struct lock_file lock = LOCK_INIT;
	ce = make_transient_cache_entry(mode, oid, path, 0);
				if (checkout_path(rmode, &roid, dst_path,
				 * treatment since they are not part of the
		struct object_id wt_oid;
	}
		struct stat st;
	}
	rstate.force = 1;
		trust_exit_code = git_config_bool(var, value);
				} else {
		die(_("difftool requires worktree or --no-index"));
						    dst_path);
#include "lockfile.h"
	if (existing) {
			hashmap_entry_init(&entry->entry, strhash(dst_path));
				   copy_file(wtdir.buf, rdir.buf, st.st_mode))
	rc = run_command_v_opt(helper_argv, flags);
		return error("expected object ID, got '%s'", p);
				 * index.

		exit(1);
 * capable of doing a symbolic link.
	NULL
	child.use_shell = 0;
	if (!i)

	}
		OPT_BOOL(0, "symlinks", &symlinks,
		}
	char path[FLEX_ARRAY];
	} else if (dir_diff)
		}
					      rdir.buf, wtdir.buf);
	struct index_state wtindex;
	}
 * Unconditional writing of a plain regular file is what
			       "directory diff mode('-d' and '--dir-diff')."));

	/* Setup temp directories */
	}
				}

	};
	return strcmp(a->path, key ? key : b->path);
			add_path(&ldir, ldir_len, entry->path);



	fclose(fp);
	if (use_gui_tool + !!difftool_cmd + !!extcmd > 1)
	update_index.no_stdin = 1;
	}
static int ensure_leading_directories(char *path)

		return error("expected ' ', got '%c'", *p);
	static char *difftool_cmd = NULL, *extcmd = NULL;
			 int argc, const char **argv)
{
static int run_dir_diff(const char *extcmd, int symlinks, const char *prefix,
		else
			write_file(rdir.buf, "%s", entry->right);
		setenv(GIT_DIR_ENVIRONMENT, absolute_path(get_git_dir()), 1);
		goto finish;
	argv_array_pushl(&update_index.args,
}
				warning(_("both files modified: '%s' and '%s'."),
{
			  const void *key)
		}
 * Because the tool is Git-unaware, if a symbolic link appears in either of
			die(_("could not read object %s for symlink %s"),
		if (S_ISLNK(rmode)) {
	struct checkout lstate, rstate;
}
	struct argv_array args = ARGV_ARRAY_INIT;
		}


	if (finish_command(&child)) {
		OPT_ARGUMENT("no-index", &no_index, N_("passed to `diff`")),
	helper_argv[1] = ldir.buf;
				 */
					if (stat(wtdir.buf, &st))
finish:
	hashmap_entry_init(&e->entry, strhash(path));
		}
		warning(_("temporary files exist in '%s'."), tmpdir);
	struct hashmap_entry entry;
			indices_loaded = 1;

		return error("expected ' ', got '%c'", *p);
			free(content);
	struct strbuf buf = STRBUF_INIT;
			add_left_or_right(&submodules, src_path, buf.buf, 0);

		strbuf_addch(buf, '/');
		helper_argv[0] = extcmd;
	return data;
			strbuf_addf(&buf, "Subproject commit %s",
 */
	int rc, flags = RUN_GIT_CMD, err = 0;
	 */
	strbuf_addf(&ldir, "%s/left/", tmpdir);

		die(_("--dir-diff is incompatible with --no-index"));
	if (*p != ' ')

	update_index.clean_on_exit = 1;
			 N_("perform a full-directory diff")),
	lstate.force = 1;
	 * This loop replicates that behavior.
	};
	if (extcmd) {
#include "parse-options.h"
		int lmode, rmode;
 * Determine whether we can simply reuse the file in the worktree.
		if (status != 'C' && status != 'R') {
{
	argc = parse_options(argc, argv, prefix, builtin_difftool_options,
		e = existing;
	while (!strbuf_getline_nul(&info, fp)) {
	 * in the common case of --symlinks and the difftool updating
	if (!wtdir.len || !is_dir_sep(wtdir.buf[wtdir.len - 1]))
				warning("%s", "");
		if (has_symlinks) {
	return ret;
	 * shows only the link itself, not the contents of the link target.
	strbuf_release(&buf);
			changed_files(&wt_modified, buf.buf, workdir);
			    struct object_id *oid1, struct object_id *oid2,
	memset(&rstate, 0, sizeof(rstate));
	int indices_loaded = 0;
	fp = xfdopen(diff_files.out, "r");
	if (is_null_oid(oid)) {
	b = container_of(entry_or_key, const struct path_entry, entry);
				add_path(&rdir, rdir_len, dst_path);
{
			add_path(&ldir, ldir_len, entry->path);
	 * will invoke a separate instance of 'git-difftool--helper' for

	}

	const struct path_entry *a, *b;
		data = strbuf_detach(&link, NULL);
	exit(exit_code);
{
/*
 * The GIT_DIFF* variables are exported for use by git-difftool--helper.

/*
		if (starts_with(info.buf, "::"))
		env[2] = "GIT_DIFFTOOL_PROMPT=true";
}
			     builtin_difftool_usage, PARSE_OPT_KEEP_UNKNOWN |
			  const struct hashmap_entry *entry_or_key,
		if (lstat(rdir.buf, &st))
	memset(&lstate, 0, sizeof(lstate));
};
	if (dir_diff)
}
		}
		hashmap_add(result, &entry->entry);
		if (*entry->right) {


	strbuf_release(&wtdir);
			die(N_("combined diff formats('-c' and '--cc') are "
	if (p[1] && !isdigit(p[1]))
static const char *const builtin_difftool_usage[] = {
		die("diff-files did not exit properly");
	 * Changes to submodules require special treatment.This loop writes a
	/*
		src_path = lpath.buf;
		return print_tool_help();
			       "not supported in\n"
	fp = xfdopen(child.out, "r");

	return strcmp(a->path, b->path);
	ret = run_command_v_opt_cd_env(args.argv, RUN_GIT_CMD, prefix, env);
	}
	const char *workdir, *tmp;
		       struct object_id *oid)


static int use_wt_file(const char *workdir, const char *name,
			   N_("use the specified diff tool")),
			add_path(&wtdir, wtdir_len, name);
}
			 "--git-dir", git_dir, "--work-tree", workdir,

			 N_("print a list of diff tools that may be used with "
struct path_entry {
							 dst_path, 0, 0);
			die(_("could not read symlink file %s"), path);
			    write_locked_index(&wtindex, &lock, COMMIT_LOCK)) {
			    "`--tool`")),
		    const void *unused_keydata)
	FLEX_ALLOC_STR(e, path, path);
	rstate.base_dir_len = rdir.len;
	diff_files.use_shell = 0;
	if (finish_command(&diff_files))
				  const struct hashmap_entry *eptr,
	hashmap_for_each_entry(&symlinks2, &iter, entry,
	lstate.base_dir = lbase_dir = xstrdup(ldir.buf);
 */
