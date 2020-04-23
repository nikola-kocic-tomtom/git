	init_db_template_dir = NULL; /* re-set in case it was set before */
	/*

#else
			src = git_link;
	struct stat st1;
	if (!git_dir)
	filemode = TEST_FILEMODE;
		  "%d", repo_version);
			set_git_work_tree(git_work_tree_cfg);
			char *rel = xstrndup(git_dir, git_dir_parent - git_dir);
		}
	adjust_shared_perm(git_path("refs"));
	 * is an attempt to reinitialize new repository with an old tool.
{
	if (get_shared_repository()) {
	size_t template_baselen = template_path->len;

	/*
				die_errno(_("cannot opendir '%s'"), template_path->buf);
		return 1;
		    GIT_WORK_TREE_ENVIRONMENT,
		strbuf_setlen(template_path, template_baselen);
			strbuf_release(&lnk);

		 * PERM_EVERYBODY.

			   N_("specify the hash algorithm to use")),
 * be the judge.  The default case is to have one DB per managed directory.
			error(_("ignoring template %s"), template_path->buf);
{
			N_("specify that the git repository is to be shared amongst several users"),
		else

	 * Create the default symlink from ".git/HEAD" to the "master"
		setenv(GIT_DIR_ENVIRONMENT, cwd, argc > 0);
	while ((de = readdir(dir)) != NULL) {
	if (hash_algo != GIT_HASH_SHA1)
	check_repository_format(&repo_fmt);
	NULL
	 * We need to create a "refs" dir in any case so that older
	}
			if (!subdir)
	 * config file, so this will not fail.  What we are catching
	strbuf_setlen(&path, baselen);

	 * with the way the namespace under .git/ is organized, should
				const struct repository_format *fmt)
	 * "GIT_DIR=.git or GIT_DIR=something/.git is usually not.
	if (!template_dir)
	}
	strbuf_release(&path);
	}
	 * Before reading that config, we also need to clear out any cached
	/* Just look for `core.hidedotfiles` */
#ifndef DEFAULT_GIT_TEMPLATE_DIR
	slash = strrchr(git_dir, '/');
	/*
{
 * find it by default, and we need to set the worktree explicitly.
}
static void validate_hash_algorithm(struct repository_format *repo_fmt, int hash)

	free(original_git_dir);
					die_errno(_("cannot mkdir %s"), argv[0]);

				N_("directory from which templates will be used")),

		if (lstat(path->buf, &st_git)) {
	if (!template_dir)
			xsnprintf(buf, sizeof(buf), "%d", OLD_PERM_GROUP);
				 */
	 * config file there, in which case we would want to read

{
	 * Otherwise, if the user has specified one on the command line, use it.

}
		    !unlink(path) &&
		git_dir = get_git_dir();
			       ? _("Reinitialized existing shared Git repository in %s%s\n")
	work_tree = xstrdup_or_null(getenv(GIT_WORK_TREE_ENVIRONMENT));
	 * "GIT_DIR=. git init" is always bare.
{
	if (!(flags & INIT_DB_QUIET)) {
}

		set_shared_repository(init_shared_repository);
			copy_templates_1(path, template_path, subdir);
		die(_("%s (or --work-tree=<directory>) not allowed without "
}
		else if (S_ISLNK(st_template.st_mode)) {
#ifdef NO_TRUSTABLE_FILEMODE

		}
				switch (safe_create_leading_directories_const(argv[0])) {


static void copy_templates_1(struct strbuf *path, struct strbuf *template_path,
 */
	 * shared-repository settings, we would need to fix them up.
	BUG_ON_OPT_NEG(unset);

	strbuf_complete(&path, '/');
		free(cwd);
		return git_config_pathname(&init_db_template_dir, k, v);

		}
	 * values we might have just re-read from the config.
		if (S_ISDIR(st_template.st_mode)) {
#endif
		git_config_set("core.sharedrepository", buf);
			die_errno(_("cannot chdir to %s"), argv[0]);
		return 0;
 * If the git_dir is not directly inside the working tree, then git will not
	DIR *dir;
	char junk[2];


static int guess_repository_type(const char *git_dir)
			set_git_work_tree(work_tree);
	return reinit;
	if (!strcmp(".", git_dir))
				die_errno(_("cannot copy '%s' to '%s'"),
	 */
				 * At this point we haven't read any configuration,
		is_bare_repository_cfg = guess_repository_type(git_dir);
	xsnprintf(repo_version_string, sizeof(repo_version_string),
		int len = strlen(git_dir);
	}
	 */
		OPT_STRING(0, "template", &template_dir, N_("template-directory"),
{
		if (chdir(argv[0]) < 0) {

	struct strbuf err = STRBUF_INIT;
	if (argc == 1) {

{
	 * we are just guessing.
					errno = EEXIST;


	if ((!git_dir || is_bare_repository_cfg == 1) && work_tree)

	else if (hash != GIT_HASH_UNKNOWN)
static void copy_templates(const char *template_dir)
	startup_info->have_repository = 1;
	char *cwd;
		git_dir = DEFAULT_GIT_DIR_ENVIRONMENT;
		 * and compatibility values for PERM_GROUP and
		if (get_shared_repository() < 0)
#ifndef ENABLE_SHA256
#include "exec-cmd.h"
		git_config_set("extensions.objectformat",
		real_git_dir = real_pathdup(real_git_dir, 1);
				case SCLD_PERMS:

		char buf[10];
			die_errno(_("cannot stat template '%s'"), template_path->buf);
	UNLEAK(real_git_dir);

	if (!strcmp(work_tree, "/") && !strcmp(git_dir, "/.git"))

	const char *slash;
	else {
 * GIT - The information manager from hell
	/*
 *
	/*
	const struct option init_db_options[] = {
	}
static int create_default_files(const char *template_path,
	strbuf_setlen(&template_path, template_len);
				die_errno(_("cannot readlink '%s'"), template_path->buf);


#include "config.h"
	}
	/*
		else if (get_shared_repository() == PERM_GROUP)
static const char *const init_db_usage[] = {

	int reinit;
}

		die(_("The hash algorithm %s is not supported in this build."), hash_algos[hash_algo].name);
		else
			git_work_tree_cfg = real_pathdup(rel, 1);
		template_dir = getenv(TEMPLATE_DIR_ENVIRONMENT);
	 * If we already have an initialized repo, don't allow the user to
		return 0;
		}
	const char *git_dir;
	/* Just look for `init.templatedir` */

	safe_create_dir(path.buf, 1);
		if (!exist_ok && !stat(real_git_dir, &st))
		usage(init_db_usage[0]);
	else {
		struct stat st2;

	 * re-initialized, /etc/core-git/templates/hooks/update would
	if (hash_algo != GIT_HASH_SHA1)
		    S_ISLNK(st1.st_mode))
	free(cwd);
	if (!stat(git_link, &st)) {
	}
		OPT_BIT('q', "quiet", &flags, N_("be quiet"), INIT_DB_QUIET),
	struct strbuf path = STRBUF_INIT;
	UNLEAK(git_dir);
#include "parse-options.h"
		strbuf_addstr(path, de->d_name);
	if (!reinit) {
static int shared_callback(const struct option *opt, const char *arg, int unset)
		int exists = 0;
{
	size_t path_baselen = path->len;
	else {
			DIR *subdir = opendir(template_path->buf);
	git_config(git_default_config, NULL);
			die(_("%s already exists"), git_dir);
	 * specify a different algorithm, as that could cause corruption.
	const char *env = getenv(GIT_DEFAULT_HASH_ENVIRONMENT);
				!chmod(path, st1.st_mode));
		OPT_SET_INT(0, "bare", &is_bare_repository_cfg,

	 * versions of git can tell that this is a repository.
	}
	clear_repository_format(&template_format);
	if (skip_prefix(git_dir, work_tree, &git_dir) &&

		filemode = (!chmod(path, st1.st_mode ^ S_IXUSR) &&
	 * First copy the templates -- we might have the default
	git_config_clear();
	 * without --bare.  Catch the error early.
	strbuf_setlen(&path, baselen);
	 */

			strbuf_addch(template_path, '/');

		git_config_set("core.bare", "true");
		if (git_dir_parent) {
	path = git_path_buf(&buf, "config");
	}
				case SCLD_EXISTS:
	strbuf_addstr(&path, get_object_directory());
			git_work_tree_cfg = xgetcwd();
	if (!strcmp(k, "init.templatedir"))
				if (mkdir(argv[0], 0777) < 0)
	 * it means that the set of templates we ship by default, along
	if (!reinit) {

int init_db(const char *git_dir, const char *real_git_dir,
			       : _("Initialized empty Git repository in %s%s\n"),
	const char *object_format = NULL;
		struct stat st;


	}
			closedir(subdir);
		warning(_("templates not found in %s"), template_dir);
	if (starts_with(k, "core."))
		    !symlink("testing", path) &&
	if (cwd_is_git_dir)
	}
	 */
	 * We must make sure command-line options continue to override any

		return 1;

 * If you want to, you can share the DB area with any number of branches.
		if (needs_work_tree_config(original_git_dir, work_tree))
		if (!exist_ok && !stat(git_dir, &st))
	if (object_format) {
			       hash_algos[hash_algo].name);
		else
		OPT_STRING(0, "object-format", &object_format, N_("hash"),
		if (filemode && !reinit && (st1.st_mode & S_IXUSR))
		warning(_("not copying templates from '%s': %s"),

		int mkdir_tried = 0;
		 * of git. Note, we use octal numbers for new share modes,
			       : _("Reinitialized existing Git repository in %s%s\n"),
	return 0;
			git_config_set("core.logallrefupdates", "true");
		set_git_dir(git_dir, 1);
	char *original_git_dir = real_pathdup(git_dir, 1);
	cwd = xgetcwd();
	strbuf_release(&template_path);
	strbuf_addstr(&path, "/pack");
	const char *work_tree;
	} else if (0 < argc) {
			       git_dir, len && git_dir[len-1] != '/' ? "/" : "");
		OPT_STRING(0, "separate-git-dir", &real_git_dir, N_("gitdir"),
		git_dir = get_git_dir();
	baselen = path.len;
				set_shared_repository(saved);

	is_bare_repository_cfg = init_is_bare_repository;
	dir = opendir(template_path.buf);


}

		die("failed to set up refs db: %s", err.buf);
					die_errno(_("cannot mkdir %s"), argv[0]);
	}
	}
		if (lstat(template_path->buf, &st_template))
		int env_algo = hash_algo_by_name(env);
}
	int exist_ok = flags & INIT_DB_EXIST_OK;
	if (hash_algo != GIT_HASH_SHA1)
static void create_object_directory(void)

		else
static int init_shared_repository = -1;
	create_object_directory();
			git_config_set("core.symlinks", "false");
		set_git_dir(real_git_dir, 1);
		const char *src;
 * Copyright (C) Linus Torvalds, 2005

		if (log_all_ref_updates == LOG_REFS_UNSET)
	unsigned int flags = 0;
	init_is_bare_repository = is_bare_repository();
	 * No mention of version at all is OK, but anything else should be
			if (strbuf_readlink(&lnk, template_path->buf,
		{ OPTION_CALLBACK, 0, "shared", &init_shared_repository,
static const char *init_db_template_dir;


	}
{
			if (errno != ENOENT)

			BUG("invalid value for shared_repository");
}
		/* Check if the filesystem is case-insensitive */
	int filemode;
	/* This forces creation of new config file */

		strbuf_setlen(path, path_baselen);
#include "refs.h"
	}
	if (is_bare_repository_cfg == 1) {
	};
	char repo_version_string[10];
	safe_create_dir(path.buf, 1);

		else
		path = git_path_buf(&buf, "CoNfIg");
			set_git_work_tree(work_tree);
			N_("permissions"),
		template_dir = init_db_template_dir;
static int init_is_bare_repository = 0;
#define GIT_DEFAULT_HASH_ENVIRONMENT "GIT_DEFAULT_HASH"
	char *path;
	if (refs_init_db(&err))
		goto close_free_return;
/*
			git_config_set("core.worktree", work_tree);
			xsnprintf(buf, sizeof(buf), "%d", OLD_PERM_EVERYBODY);

	validate_hash_algorithm(&repo_fmt, hash);

			       ? _("Initialized empty shared Git repository in %s%s\n")
				case SCLD_OK:


	/*
			     DIR *dir)

	 */
	safe_create_dir(git_path("refs"), 1);
		/* Check if symlink is supported in the work tree */
			filemode = 0;
	return 1;
close_free_return:
	strbuf_release(&path);
	    const char *template_dir, int hash, unsigned int flags)
}
	 * cause "git init" to fail here.  I think this is sane but
	git_config_set("core.filemode", filemode ? "true" : "false");
		if (env_algo == GIT_HASH_UNKNOWN)
	if (repo_fmt->version >= 0 && hash != GIT_HASH_UNKNOWN && hash != repo_fmt->hash_algo)
	 */
static int needs_work_tree_config(const char *git_dir, const char *work_tree)
}

	char *to_free = NULL;
}
	size_t baselen;
	}
	/* Check filemode trustability */
	}
	 * Set up the default .git directory contents
				const char *original_git_dir,
		repo_version = GIT_REPO_VERSION_READ;
					/* fallthru */
 */
	path = git_path_buf(&buf, "HEAD");
		return 0;
	git_dir = xstrdup_or_null(getenv(GIT_DIR_ENVIRONMENT));
	read_repository_format(&template_format, template_path.buf);
	git_config(git_init_db_config, NULL);
	 */
	template_len = template_path.len;


#define TEST_FILEMODE 0
		const char *work_tree = get_git_work_tree();
		if (rename(src, git_dir))
		strbuf_addstr(template_path, de->d_name);
	const char *real_git_dir = NULL;
	int repo_version = GIT_REPO_VERSION;
		if (!close(xmkstemp(path)) &&
		    !lstat(path, &st1) &&
	/*
	/*
		return 0;

				die_errno(_("cannot symlink '%s' '%s'"),
	 * Otherwise it is often bare.  At this point
	 * branch, if it does not exist yet.
		else if (exists)
{
		die(_("attempt to reinitialize repository with different hash"));

		else
		else if (get_shared_repository() == PERM_EVERYBODY)
	else if (env) {
	retry:
			  template_dir, err.buf);
	 * values (since we've just potentially changed what's available on
			printf(get_shared_repository()
				N_("create a bare repository"), 1),
	    !strcmp(git_dir, "/.git"))
	int cwd_is_git_dir;
	struct repository_format template_format = REPOSITORY_FORMAT_INIT;
		hash_algo = hash_algo_by_name(object_format);
				mkdir_tried = 1;
		set_shared_repository(init_shared_repository);
void initialize_repository_version(int hash_algo)
			continue;
	 */

#endif
	int reinit;
{
#define TEST_FILEMODE 1
		/* We do not spell "group" and such, so that
		if (!access(path, F_OK))
		template_dir = absolute_pathdup(template_dir);
	 * "GIT_DIR=`pwd` git init" too.

				default:
		if (de->d_name[0] == '.')
		probe_utf8_pathname_composition();
	size_t template_len;
	}
	return 1;
			/* force to the mode value */
			die_errno(_("unable to move %s to %s"), src, git_dir);
			  "specifying %s (or --git-dir=<directory>)"),
 */
	return init_db(git_dir, real_git_dir, template_dir, hash_algo, flags);
	 */
		else if (S_ISDIR(st.st_mode))
	 */

		repo_fmt->hash_algo = env_algo;
	 * Note that a newly created repository does not have
			git_config_set("core.ignorecase", "true");
		if (S_ISREG(st.st_mode))
	safe_create_dir(path.buf, 1);
		if (hash_algo == GIT_HASH_UNKNOWN)
	if (get_shared_repository()) {
	 * GIT_WORK_TREE makes sense only in conjunction with GIT_DIR
	strbuf_release(&buf);
	if (TEST_FILEMODE && !lstat(path, &st1)) {

	 *
	if (!is_bare_repository_cfg) {
		adjust_shared_perm(get_git_dir());
				set_shared_repository(0);
		 * the configuration can be read by older version
	if (real_git_dir && !is_absolute_path(real_git_dir))
			   N_("separate git dir from working tree")),

	/* Note: if ".git/hooks" file exists in the repository being
			die_errno (_("Cannot access work tree '%s'"),
#endif
	argc = parse_options(argc, argv, prefix, init_db_options, init_db_usage, 0);
	free(to_free);

		if (!git_work_tree_cfg)
	 * disk).
			}
	/*
	const char *template_dir = NULL;
	if (real_git_dir) {
				!lstat(path, &st2) &&
	if (is_bare_repository())
			die(_("unknown hash algorithm '%s'"), env);
		const char *git_dir_parent = strrchr(git_dir, '/');
	if (template_dir && *template_dir && !is_absolute_path(template_dir))
				 * and we know shared_repository should always be 0;
static int git_init_db_config(const char *k, const char *v, void *cb)
	*((int *) opt->value) = (arg) ? git_config_perm("arg", arg) : PERM_GROUP;
	 */
	 * be really carefully chosen.
		if (access(get_git_work_tree(), X_OK))
	}

	git_config_set("core.repositoryformatversion", repo_version_string);
			free(rel);
			if (copy_file(path->buf, template_path->buf, st_template.st_mode))
		if (work_tree)
		if (work_tree)
{
				/*

	 */

	    verify_repository_format(&template_format, &err) < 0) {
	safe_create_dir(git_dir, 0);
		repo_fmt->hash_algo = hash;
		strbuf_release(&err);
		separate_git_dir(git_dir, original_git_dir);
			strbuf_addch(path, '/');
	struct strbuf path = STRBUF_INIT;
			printf(get_shared_repository()

/*
			struct strbuf lnk = STRBUF_INIT;
	/* Make sure that template is from the correct vintage */
	struct stat st;
				st1.st_mode != st2.st_mode &&

		git_config_set("core.bare", "false");
	strbuf_complete(&template_path, '/');
		goto free_return;
		  || readlink(path, junk, sizeof(junk)-1) != -1);

		else if (S_ISREG(st_template.st_mode)) {
	strbuf_addstr(&path, get_git_common_dir());
	reinit = (!access(path, R_OK)

		}
				die_errno(_("cannot stat '%s'"), path->buf);
			unlink(path); /* good */
				 * but just in case we play safe.
		struct stat st_git, st_template;

	/* Check to see if the repository version is right.
static void separate_git_dir(const char *git_dir, const char *git_link)
		template_dir = to_free = system_path(DEFAULT_GIT_TEMPLATE_DIR);
	closedir(dir);
			continue;
	strbuf_addstr(&template_path, template_dir);

	/*
	git_config(git_init_db_config, NULL);
			PARSE_OPT_OPTARG | PARSE_OPT_NONEG, shared_callback, 0},
					break;

	struct strbuf err = STRBUF_INIT;
	struct strbuf template_path = STRBUF_INIT;
	 * from it after installing.
			die(_("unknown hash algorithm '%s'"), object_format);
 * On the other hand, it might just make lookup slower and messier. You

	reset_shared_repository();
	if (template_format.version >= 0 &&
			exists = 1;
		char *cwd = xgetcwd();
	copy_templates(template_path);
	if (!dir) {
	if (!template_dir)
		    GIT_DIR_ENVIRONMENT);

}
 * That has advantages: you can save space by sharing all the SHA1 objects.
	if (is_bare_repository_cfg < 0)
	initialize_repository_version(fmt->hash_algo);
			src = read_gitfile(git_link);
	if (init_shared_repository != -1)
					break;
		else
		}
	return 0;
	struct dirent *de;
	 * verified.
		return;
	if (init_shared_repository != -1)
	cwd_is_git_dir = !strcmp(git_dir, cwd);
	UNLEAK(work_tree);

	int hash_algo = GIT_HASH_UNKNOWN;
			die(_("unable to handle file type %d"), (int)st.st_mode);
}
			if (!mkdir_tried) {
	 */
					  lnk.buf, path->buf);
	struct strbuf buf = STRBUF_INIT;

#include "cache.h"
		git_config_set("receive.denyNonFastforwards", "true");
#define DEFAULT_GIT_TEMPLATE_DIR "/usr/share/git-core/templates"
		if (reinit)
			xsnprintf(buf, sizeof(buf), "0%o", -get_shared_repository());
				   get_git_work_tree());
		OPT_END()
		path = git_path_buf(&buf, "tXXXXXX");
	}
			if (symlink(lnk.buf, path->buf))
				goto retry;
			die(_("%s already exists"), real_git_dir);
free_return:
	copy_templates_1(&path, &template_path, dir);
	strbuf_addstr(&path, "/info");
		 */
				saved = get_shared_repository();
	 * We would have created the above under user's umask -- under
			       git_dir, len && git_dir[len-1] != '/' ? "/" : "");
int cmd_init_db(int argc, const char **argv, const char *prefix)

	N_("git init [-q | --quiet] [--bare] [--template=<template-directory>] [--shared[=<permissions>]] [<directory>]"),
				int saved;
	 */
			exit(1);
	flags |= INIT_DB_EXIST_OK;
#include "builtin.h"
	/*

	if (slash && !strcmp(slash, "/.git"))
};
	if (!strcmp(git_dir, ".git"))
	strbuf_addstr(&template_path, "config");
					  template_path->buf, path->buf);
{
	safe_create_dir(path->buf, 1);
					    st_template.st_size) < 0)
		if (create_symref("HEAD", "refs/heads/master", NULL) < 0)
		return platform_core_config(k, v, cb);
		/* allow template config file to override the default */
	reinit = create_default_files(template_dir, original_git_dir, &repo_fmt);
/*
	write_file(git_link, "gitdir: %s", git_dir);
				}
	return 0;
		free(to_free);
	struct repository_format repo_fmt = REPOSITORY_FORMAT_INIT;
	if (!template_dir[0]) {
