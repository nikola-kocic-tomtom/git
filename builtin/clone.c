		else
static void copy_or_link_directory(struct strbuf *src, struct strbuf *dest,
	return err;
	if (!option_bare) {
		while (start < end && is_dir_sep(end[-1]))
	if (real_git_dir) {
		 N_("use --reference only while cloning")),
	if (!head) {
	 * Read from the source objects/info/alternates file
				    option_branch, option_origin);
	int src_len, dest_len;
			expand_list_objects_filter_spec(&filter_options);
			strbuf_realpath(&realpath, src->buf, 1);
#include "packfile.h"
		get_common_dir(&dest, dest_repo);
 *
		transport_set_option(transport, TRANS_OPT_LIST_OBJECTS_FILTER,

	strbuf_release(&head);
	OPT_STRING_LIST(0, "server-option", &server_options,
	opts.fn = oneway_merge;
static const char junk_leave_repo_msg[] =
	return ref;
	free(alternates);
			argv_array_pushf(&args, "--jobs=%d", max_jobs);
				continue;
	if (option_since)
static void setup_reference(void)
	remove_junk();
		}
		 */
		die(_("could not create leading directories of '%s'"), git_dir);
#include "run-command.h"

		 N_("don't clone any tags, and make later fetches not to follow them")),

				     (const char *)&option_not);
		git_dir = real_git_dir;
static void write_followtags(const struct ref *refs, const char *msg)
				find_remote_branch(mapped_refs, option_branch);
static const char *junk_git_dir;

	if (option_shared) {
	len = end - start;
			builtin_clone_usage, builtin_clone_options);

static int option_progress = -1;
		error(_("failed to initialize sparse-checkout"));
	/* Returning -1 notes "end of list" to the caller. */
	struct unpack_trees_options opts;
	struct remote *remote;
	if (unpack_trees(1, &t, &opts) < 0)
		strbuf_setlen(src, src_len);
{
	OPT_BOOL('s', "shared", &option_shared,
			continue;
	while (start < ptr && !is_dir_sep(ptr[-1]) && ptr[-1] != ':')
	const char *src_ref_prefix = "refs/heads/";
	/*
			warning(_("Could not find remote branch %s to clone."),
	if (!t)
	NULL
		start = repo;
	const struct ref *r;
	case JUNK_LEAVE_ALL:
				option_branch);

	    !strncmp(end - 4, ".git", 4)) {
 *
			out[-1] = '\0';
	return local_refs;
		die(_("depth %s is not a positive number"), option_depth);
		if (option_verbosity < 0)
	OPT_BOOL(0, "remote-submodules", &option_remote_submodules,
	struct ref *ref = *rm;
	else if (arg)

		if (dest_exists)
	for (i = 0; i < config->nr; i++) {
		struct string_list_item *item;

	/*
	struct transport *transport = NULL;
static int iterate_ref_map(void *cb_data, struct object_id *oid)
		transport_set_option(transport, TRANS_OPT_FROM_PROMISOR, "1");
		if (real_git_dir)
		warning("%s", _(junk_leave_repo_msg));
	if (!strcmp(head, "HEAD")) {

		junk_git_dir = real_git_dir;
	 * We must apply the setting in the current process

	if (option_depth && atoi(option_depth) < 1)



	ref = find_ref_by_name(refs, head.buf);
	if (our && skip_prefix(our->name, "refs/heads/", &head)) {
			guess_remote_head(remote_head, mapped_refs, 0);

	}
static void dissociate_from_references(void)
		update_ref(msg, "HEAD", &remote->old_oid, NULL, REF_NO_DEREF,
static int add_one_reference(struct string_list_item *item, void *cb_data)
		junk_work_tree = work_tree;
	int err = 0;
	  PARSE_OPT_OPTARG, recurse_submodules_cb, (intptr_t)"." },
		struct strbuf sb = STRBUF_INIT;
		if (option_not.nr)

		end--;
			 * any remote-tracking branch, which is what
		mapped_refs = wanted_peer_refs(refs, &remote->fetch);

}
	OPT_BOOL(0, "dissociate", &option_dissociate,
	JUNK_LEAVE_REPO,
		dir = guess_dir_name(repo_name, is_bundle, option_bare);
			   UPDATE_REFS_DIE_ON_ERR);
							   &our->old_oid);

	}

		FREE_AND_NULL(head);
		}
		strbuf_setlen(dest, dest_len);
		 * Detach HEAD in all these cases.
		const struct ref *remote_head_points_at,
	if (is_local) {
			end--;
			return path->buf;
{
{
	}
			argv_array_push(&args, option_single_branch ?


	int err = 0, complete_refs_before_fetch = 1;
	opts.dst_index = &the_index;
	else {
	if (iter_status != ITER_DONE) {
			continue;
		if (run_command_v_opt(argv, RUN_GIT_CMD|RUN_COMMAND_NO_STDIN))
		if (start < ptr && ptr[-1] == ':')
	struct lock_file lock_file = LOCK_INIT;
		/* Configure the remote */
#include "fetch-pack.h"
		die(_("%s exists and is not a directory"), pathname);
		result = 1;
static char *option_template, *option_depth, *option_since;


		if (filter_options.choice)
		abs_path = mkpathdup("%s/objects/%s", src_repo, line.buf);
	} else {
		if (!normalize_path_copy(abs_path, abs_path))
					   0, NULL, &err))
 *
static void write_refspec_config(const char *src_ref_prefix,
	 * greedily, such that we strip up to the last '@' inside
	if (option_bare) {
		strbuf_reset(&key);
	static char *bundle_suffix[] = { ".bundle", "" };
			junk_work_tree_flags |= REMOVE_DIR_KEEP_TOPLEVEL;

	if (option_required_reference.nr || option_optional_reference.nr)
	}
	const struct ref *our_head_points_at;
			argv_array_push(&args, "--quiet");
	path = get_repo_path(repo_name, &is_bundle);
		repo = repo_name;

	for_each_string_list(&option_required_reference,
}
		end -= 5;
		free(abs_path);
			strbuf_reset(&key);

			add_to_alternates_file(line.buf);
		option_no_checkout = 1;
	if (is_local)

			get_fetch_map(refs, &refspec->items[i], &tail, 0);
	char *ref_git = compute_alternate_path(item->string, &err);
			N_("server-specific"), N_("option to transmit")),
			}
				     option_since);
	struct ref **tail = head ? &head->next : &local_refs;

		strbuf_addstr(&dest, "/objects");
	opts.clone = 1;
		write_remote_refs(mapped_refs);
	const struct ref *ref;
	if (!len || (len == 1 && *start == '/'))
				   UPDATE_REFS_DIE_ON_ERR);
		    N_("setup as shared repository")),
		 N_("don't create a checkout")),
	flags = DIR_ITERATOR_PEDANTIC | DIR_ITERATOR_FOLLOW_SYMLINKS;

		if (!starts_with(head, "refs/heads/"))
	*rm = ref->next;
		}
	struct strbuf err = STRBUF_INIT;

		 * comment). In that case we need fetch it early because
		 * remote_head code below relies on it.

			if (dst) {
					BUG("remote HEAD points at non-head?");
	} else if (remote) {
			   UPDATE_REFS_DIE_ON_ERR);
	OPT_BOOL('l', "local", &option_local,
			     builtin_clone_usage, 0);
		if (option_single_branch >= 0)
static struct list_objects_filter_options filter_options;
			builtin_clone_usage, builtin_clone_options);
		end--;
	OPT_PARSE_LIST_OBJECTS_FILTER(&filter_options),
			N_("create a bare repository")),
	canon = raw ? absolute_pathdup(raw) : NULL;
	OPT_STRING(0, "template", &option_template, N_("template-directory"),

		 * in mapped_refs (see struct transport->get_refs_list
		ref = ref->next;

						branch_top->buf, option_branch);
		} else if (S_ISREG(st.st_mode) && st.st_size > 8) {
	 * actually going to write a ref for.

			remote_head = guess_remote_head(head, refs, 0);
	}
	if (!ref)
			if (option_branch) {
	struct ref *local_refs = head;
				die(_("Remote branch %s not found in upstream %s"),
	}
{
		} else {
	struct ref *mapped_refs;
		if (submodule_progress)

	struct strbuf value = STRBUF_INIT;
			die(_("HEAD not found below refs/heads!"));
		if (path_exists(real_git_dir))
			TRANSPORT_FAMILY_IPV6),
			continue;
	if (run_command_v_opt(argv.argv, RUN_GIT_CMD)) {
			die("%s", err.buf);
		} else if (option_optional_reference.nr) {
		if (create_symref(head_ref.buf,
		if (dest_exists)

	argv_array_pushl(&argv, "-C", repo, "sparse-checkout", "init", NULL);
	if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK))
/*
		struct commit *c = lookup_commit_reference(the_repository,
	 * Instead of copying bit-for-bit from the original,
			   UPDATE_REFS_DIE_ON_ERR);
			const char *msg)
	}
static int option_local = -1, option_no_hardlinks, option_shared;
	}
	}
				*is_bundle = 0;
		if (unlink(alternates) && errno != ENOENT)
		strbuf_addstr(path, bundle_suffix[i]);
		if (option_remote_submodules) {
				   (const char *)opt->defval);
		}
		if (!remote_head && option_branch)
			N_("deepen history of shallow clone, excluding rev")),

		if (!option_bare) {
	 * Strip trailing port number if we've got only a
		return;
	int i;
	const struct ref *rm = mapped_refs;
static const char *get_repo_path_1(struct strbuf *path, int *is_bundle)

static void update_head(const struct ref *our, const struct ref *remote,
	OPT_STRING('o', "origin", &option_origin, N_("name"),
	transport_set_verbosity(transport, option_verbosity, option_progress);
			strbuf_addf(&value, "+%s*:%s*", src_ref_prefix, branch_top->buf);
		/*
		}

				"submodule.alternateLocation=superproject");
		git_dir = mkpathdup("%s/.git", dir);
		 * for normal clones, transport_get_remote_refs() should
	JUNK_LEAVE_ALL
		      "Please specify a directory on the command line"));
		strbuf_addstr(&sb, junk_git_dir);
	 * also regard colons as path separators, such that
	iter = dir_iterator_begin(src->buf, flags);
#include "sigchain.h"
			warning(_("--shallow-since is ignored in local clones; use file:// instead."));

		update_ref(msg, ref->name, &ref->old_oid, NULL, 0,
	const char *raw;
{
	strbuf_addstr(&head, branch);
static int write_one_config(const char *key, const char *value, void *data)
			argv_array_push(&args, "--remote");
	int submodule_progress;
			die(_("unable to write parameters to config file"));
		if (check_connected(iterate_ref_map, &rm, &opt))
{
		expand_ref_prefix(&ref_prefixes, option_branch);
				  msg) < 0)
		dir = xstrfmt("%.*s.git", (int)len, start);
		if (option_origin)
	OPT_STRING_LIST(0, "shallow-exclude", &option_not, N_("revision"),
}

{
	if (transport->smart_options && !deepen && !filter_options.choice)
	}
				 const char *arg, int unset)
	err = checkout(submodule_progress);
		strbuf_release(&sb);
		die(_("unable to checkout working tree"));

				strbuf_addf(&value, "+%s:%s%s", remote_head_points_at->name,
	if (unset)
			die_errno(_("failed to unlink '%s'"), dest->buf);
			N_("reference repository")),
	strbuf_release(&sb);

		N_("to clone from a local repository")),
			   !is_local);
		die_errno(_("failed to stat '%s'"), pathname);


	if (*dir) {
			remote_head = copy_ref(find_remote_branch(refs, option_branch));

		transport_set_option(transport, TRANS_OPT_FOLLOWTAGS, "1");
	if (junk_git_dir) {

	strbuf_release(&realpath);
	const struct ref *ref;
	strbuf_addstr(&head, "refs/heads/");
	core_apply_sparse_checkout = 1;
	struct ref *head = copy_ref(find_ref_by_name(refs, "HEAD"));


	/*
		 */
		 * return reliable ref set, we can delay cloning until after
		if (!is_local && !complete_refs_before_fetch)


		if (copy_file_with_time(dest->buf, src->buf, 0666))
static const char *junk_work_tree;
			strbuf_addf(&sb, "submodule.active=%s",
				_("info: Could not add alternate for '%s': %s\n"),
	junk_mode = JUNK_LEAVE_ALL;
	if (real_git_dir)
	return 0;
	 */
	transport->cloning = 1;
		if (option_single_branch && !option_no_tags)

		    N_("any cloned submodules will use their remote-tracking branch")),
	}
 * Implementation notes:
		if (option_bare)
	opts.update = 1;

		if (!r->peer_ref)
			       const char *msg,
		if (!access(mkpath("%s/shallow", path), F_OK)) {
	size_t baselen = path->len;
	struct argv_array argv = ARGV_ARRAY_INIT;
}
		update_ref(msg, "HEAD", &c->object.oid, NULL, REF_NO_DEREF,
		get_common_dir(&src, src_repo);
			git_config_set_multivar(key.buf, value.buf, "^$", 0);
	} else {
			mkdir_if_missing(dest->buf, 0777);
	N_("git clone [<options>] [--] <repo> [<dir>]"),
				continue;
	free(head);
	OPT_BOOL(0, "mirror", &option_mirror,
		warning(_("You appear to have cloned an empty repository."));
		}
						OBJECT_INFO_QUICK |
		*out = '\0';
	if (safe_create_leading_directories_const(git_dir) < 0)
{
			 * otherwise, the next "git fetch" will
	strbuf_release(&path);
		    option_optional_reference.nr)
	}
			 * we want.
		 N_("create a mirror repository (implies bare)")),
	strbuf_addstr(&path, repo);
		return 0;
		    N_("initialize sparse-checkout file to include only files at root")),
		else if (mkdir(work_tree, 0777))
		if (*required)
static struct option builtin_clone_options[] = {
	strbuf_release(&line);
		 N_("force progress reporting")),
		get_fetch_map(refs, tag_refspec, &tail, 0);
	required = 0;
	strbuf_addf(&key, "remote.%s.url", option_origin);
	sigchain_pop(signo);
{

			start = ptr + 1;
			die(_("cannot repack to clean up"));
static int option_remote_submodules;

			strbuf_addf(&key, "remote.%s.fetch", option_origin);
		if (unlink(dest->buf) && errno != ENOENT)
static int option_no_checkout, option_bare, option_mirror, option_single_branch = -1;
	} else {
static struct ref *find_remote_branch(const struct ref *refs, const char *branch)

		/*
	 * to turn entries with paths relative to the original
	oidcpy(oid, &ref->old_oid);
	struct stat st;

			if (option_mirror) {
		/* remove duplicates */
static int git_sparse_checkout_init(const char *repo)
		repo = absolute_pathdup(repo_name);
		mapped_refs = NULL;
	 */
			N_("set config inside the new repository")),
		git_config_set(key.buf, "--no-tags");
	char *dir;
		deepen = 1;
#include "parse-options.h"
	if (dest_exists && !is_empty_dir(dir))
	char *end = dir + strlen(dir);
	struct strbuf path = STRBUF_INIT;
		die(_("destination path '%s' already exists and is not "
		junk_git_dir = git_dir;
	if (start == NULL)
			 * simply fetch from HEAD without updating
				const char *head = remote_head_points_at->name;
			write_followtags(refs, msg);
			char ch = *end;

	raw = get_repo_path_1(&path, is_bundle);
		opt.transport = transport;

{
				  work_tree);

   "You can inspect what was checked out with 'git status'\n"
}
	while (start < end && (is_dir_sep(end[-1]) || isspace(end[-1])))
			*is_bundle = 1;
static struct string_list option_required_reference = STRING_LIST_INIT_NODUP;
	if (option_bare || work_tree)
{
#include "builtin.h"
 * Clone a repository into a different directory that does not yet exist.
}
			N_("repo"), N_("reference repository")),
	if (server_options.nr)
	}
	tree = parse_tree_indirect(&oid);
		strbuf_reset(&sb);
	if (junk_work_tree) {
static const char *real_git_dir;

	return git_config_set_multivar_gently(key,
	OPT_STRING(0, "shallow-since", &option_since, N_("time"),

		    branch_top.buf);
				if (prev_space)
		clone_local(path, git_dir);
	 * Strip trailing spaces, slashes and /.git
 */


		}
{

	strbuf_release(&reflog_msg);
 * Based on git-commit.sh by Junio C Hamano and Linus Torvalds

			die_errno(_("could not create leading directories of '%s'"),
{
 *  - dropping use-separate-remote and no-separate-remote compatibility
	if (refs) {
		if (option_required_reference.nr &&
	int iter_status;
		if (git_config_parse_parameter(config->items[i].string,
	}
			*out++ = ch;
	if (ref)
		work_tree = getenv("GIT_WORK_TREE");
		transport->smart_options->check_self_contained_and_connected = 1;
}

	 * We want to show progress for recursive submodule clones iff
		remote_head_points_at = NULL;
					   strbuf_detach(&sb, NULL));
	const char *end = repo + strlen(repo), *start, *ptr;
	strbuf_release(&default_refspec);

	else
		struct argv_array args = ARGV_ARRAY_INIT;


			die(_("--bare and --origin %s options are incompatible."),


static int option_sparse_checkout;

	fclose(in);
	} else {
		   N_("path to git-upload-pack on the remote")),
		remove_dir_recursively(&sb, junk_git_dir_flags);
	 * Strip .{bundle,git}.
static int junk_work_tree_flags;
	write_config(&option_config);

	 * created entry via "clone -s" is not lost, and also
	ptr = end;
			   branch_top.buf, reflog_msg.buf, transport,
	{ OPTION_CALLBACK, 0, "recurse-submodules", &option_recurse_submodules,
						our_head_points_at->name);
	case JUNK_LEAVE_REPO:
						OBJECT_INFO_SKIP_FETCH_OBJECT))
}
	remote = remote_get(option_origin);
		strbuf_addstr(src, iter->relative_path);
	if (errno != EEXIST)
				die_errno(_("failed to create link '%s'"), dest->buf);
	/*
	OPT_BOOL('n', "no-checkout", &option_no_checkout,
			if (option_local > 0)

		 *

		if (stat(path->buf, &st))
			transport_fetch_refs(transport, mapped_refs);
	 * compatibility.
			string_list_append(&option_config,
		 * NEEDSWORK: In a multi-working-tree world, this needs to be
		const struct ref *our_head_points_at,
		struct strbuf dest = STRBUF_INIT;
	parse_tree(tree);

	/*
			const char *dst;

		strbuf_addstr(&sb, junk_work_tree);
				     option_depth);
	char *head;

		char *out = dir;
	if (0 <= option_verbosity)
	for (ref = refs; ref; ref = ref->next) {

			warning(_("--shallow-exclude is ignored in local clones; use file:// instead."));
	OPT_STRING_LIST('c', "config", &option_config, N_("key=value"),
	strbuf_release(&key);
/*
}
			die_errno(_("failed to copy file to '%s'"), dest->buf);
				prev_space = 1;
static struct string_list option_optional_reference = STRING_LIST_INIT_NODUP;
			    option_origin);
			string_list_append(&option_config,
			warning(_("--depth is ignored in local clones; use file:// instead."));
	}
		usage_msg_opt(_("Too many arguments."),
	OPT_BOOL(0, "bare", &option_bare, N_("create a bare repository")),
		   N_("separate git dir from working tree")),
			end = ptr - 1;
			die_errno(_("could not create work tree dir '%s'"),
	OPT_INTEGER('j', "jobs", &max_jobs,
{
		strbuf_addstr(dest, iter->relative_path);
		strbuf_addstr(&alt, "/objects");
			remote_head_points_at, &branch_top);
		return;
{
			if (is_null_oid(&ref->old_oid)) {
	else
	else if (refs && complete_refs_before_fetch)
	}
	while (strbuf_getline(&line, in) != EOF) {
	switch (junk_mode) {
		option_origin = "origin";
	else {

					continue;
		if (option_branch)
	strbuf_addstr(&head, branch);
			string_list_append(&option_config,

			if (isspace(ch)) {
		}
	/*
				"submodule.alternateErrorStrategy=die");

	argv_array_push(&ref_prefixes, "HEAD");
	ref_transaction_free(t);
   "and retry with 'git restore --source=HEAD :/'\n");

 *
	/*
	if (check_connectivity) {

static int option_no_tags;
	 */
static char *option_branch = NULL;
		if (!fspathcmp(iter->relative_path, "info/alternates")) {
	}

	 */
	if (option_branch)
 * Overall FIXMEs:
		dir = xstrndup(start, len);
	}
		set_git_work_tree(work_tree);
	if (option_dissociate) {
	if (option_mirror || !option_bare) {
		struct check_connected_options opt = CHECK_CONNECTED_INIT;
	char *alternates = git_pathdup("objects/info/alternates");
	OPT_ALIAS(0, "recursive", "recurse-submodules"),


			       const struct ref *remote_head_points_at,
		close_object_store(the_repository->objects);
	for (ptr = start; ptr < end && !is_dir_sep(*ptr); ptr++) {
	FILE *in = xfopen(src->buf, "r");
	if (argc == 2)
			die(_("clone --recursive is not compatible with "
{
	 * cloning a repository 'foo:bar.git' would result in a
}
	}
}
	memset(&opts, 0, sizeof opts);
	 * Both src and dst have "$path/objects/info/alternates".
}
		work_tree = NULL;
		if (work_tree && path_exists(work_tree))

		/* --branch specifies a non-branch (i.e. tags), detach HEAD */
	 * Skip anything missing a peer_ref, which we are not
			die(_("--bare and --separate-git-dir are incompatible."));
	int required = 1;
	else

	}
	 * we need to append to existing one so that the already

			install_branch_config(0, "master", option_origin,
	head = resolve_refdup("HEAD", RESOLVE_REF_READING, &oid, NULL);
	struct tree_desc t;
	}
	JUNK_LEAVE_NONE,
		while (start < ptr && isdigit(ptr[-1]) && ptr[-1] != ':')
static void strip_trailing_slashes(char *dir)
}
	 * with one ascii space, remove leading and trailing spaces.
			/* if --branch=tag, pull the requested tag explicitly */

	init_tree_desc(&t, tree->buffer, tree->size);
	 * colon). This check is required such that we do not
		if (option_single_branch && !option_mirror) {
	return canon;
		work_tree = dir;
	OPT_BOOL(0, "no-tags", &option_no_tags,
	free(ref_git);
		strbuf_addf(&branch_top, "refs/remotes/%s/", option_origin);

				     spec);
			src_ref_prefix = "refs/";
		else

	else if (!strchr(repo_name, ':'))

		if (!line.len || line.buf[0] == '#')
		int prev_space = 1 /* strip leading whitespace */;
				get_fetch_map(remote_head, &refspec->items[i],
	strbuf_release(&value);

	OPT_BOOL(0, "shallow-submodules", &option_shallow_submodules,
	struct stat sb;

	/* no need to be strict, transport_set_option() will validate it again */

		if (ends_with(ref->name, "^{}"))
	refspec_append(&remote->fetch, default_refspec.buf);
	update_remote_refs(refs, mapped_refs, remote_head_points_at,
	 */
		string_list_append((struct string_list *)opt->value, arg);
		if (S_ISDIR(iter->st.st_mode)) {
		}
		remote_head = NULL;


static void mkdir_if_missing(const char *pathname, mode_t mode)
		for_each_string_list_item(item, &option_recurse_submodules) {
		strbuf_release(&dest);
	return err;
			argv_array_push(&args, "--progress");
		string_list_remove_duplicates(&option_recurse_submodules, 0);
		else {
		 * transport_get_remote_refs() may return refs with null sha-1
	write_refspec_config(src_ref_prefix, our_head_points_at,
#include "connected.h"
	struct strbuf line = STRBUF_INIT;
	struct strbuf key = STRBUF_INIT;
	/*
	if (option_not.nr)
	if (refs) {
		    N_("don't use local hardlinks, always copy")),

	update_head(our_head_points_at, remote_head, reflog_msg.buf);
		die_errno(_("failed to create directory '%s'"), pathname);
			  "unable to checkout.\n"));
			       int check_connectivity)
	for (i = 0; i < ARRAY_SIZE(suffix); i++) {
	else
{
			option_no_hardlinks = 1;
	src_len = src->len;
		strbuf_setlen(path, baselen);
		option_no_checkout = 1;
					      CONFIG_REGEX_NONE, 0);
			return path->buf;
		if (safe_create_leading_directories_const(work_tree) < 0)
	const struct ref *remote_head_points_at;
	transport_set_option(transport, TRANS_OPT_KEEP, "yes");
	setup_work_tree();
	}

		strbuf_addstr(&head_ref, branch_top);
		else
	path = get_repo_path(remote->url[0], &is_bundle);
		for (end = dir; *end; ++end) {
		remove_dir_recursively(&sb, junk_work_tree_flags);
	const struct ref *refs, *remote_head;

static int option_dissociate;
};
	struct ref_transaction *t;
	}
	const char *repo_name, *repo, *work_tree, *git_dir;


	 * Skip scheme.
	strbuf_reset(&key);

	}
{
		struct strbuf src = STRBUF_INIT;

	argv_array_clear(&ref_prefixes);
	if (!access(alternates, F_OK)) {

	strbuf_addch(src, '/');
	 */
	dest_exists = path_exists(dir);

	/*
		if (is_absolute_path(line.buf)) {

	}
			die("%s", err.buf);
		ptr--;

	struct argv_array ref_prefixes = ARGV_ARRAY_INIT;
#include "transport.h"
			       struct transport *transport,
	}
			/*
	}
	}
	}
	refspec_ref_prefixes(&remote->fetch, &ref_prefixes);
#include "tree.h"
	 * before we free the transport.
	struct strbuf sb = STRBUF_INIT;
			die(_("Remote branch %s not found in upstream %s"),

	struct strbuf default_refspec = STRBUF_INIT;
	transport_disconnect(transport);

		strbuf_release(&head_ref);
	 * strip URI's like '/foo/bar:2222.git', which should
		 * We know remote HEAD points to a non-branch, or
				  remote_head_points_at->peer_ref->name,
		warning(_("--local is ignored"));
	dest_len = dest->len;
		if (!starts_with(ref->name, "refs/tags/"))
	}
}

		}
}

	struct ref *ref;
	/* We need to be in the new work tree for the checkout */
	opts.merge = 1;
			die(_("remote did not send all necessary objects"));
	struct strbuf realpath = STRBUF_INIT;
	start = ptr;
	OPT_STRING('u', "upload-pack", &option_upload_pack, N_("path"),
		    N_("number of submodules cloned in parallel")),
			die(_("working tree '%s' already exists."), work_tree);
			int len, fd = open(path->buf, O_RDONLY);
			 */
		/*
	}
	int result = 0;
			if (len != 8 || strncmp(signature, "gitdir: ", 8))
{
				src_repo, line.buf);


static enum transport_family family;
{

	struct dir_iterator *iter;
	struct strbuf err = STRBUF_INIT;
			install_branch_config(0, head, option_origin, our->name);
	OPT_BOOL(0, "single-branch", &option_single_branch,
	if (0 <= option_verbosity) {
				if (!skip_prefix(head, "refs/heads/", &head))
	raise(signo);

	opts.src_index = &the_index;
		}
			       const struct ref *mapped_refs,
static void write_config(struct string_list *config)
	if (option_no_checkout)
			}
	struct strbuf key = STRBUF_INIT;
}
		die(_("unable to write new index file"));

#include "refspec.h"
} junk_mode = JUNK_LEAVE_NONE;
		strbuf_addstr(&src, "/objects");
	int is_bundle = 0, is_local;
		add_to_alternates_file(alt.buf);
				complete_refs_before_fetch = 0;
	struct strbuf head = STRBUF_INIT;
}
	OPT_STRING(0, "separate-git-dir", &real_git_dir, N_("gitdir"),
			copy_alternates(src, src_repo);
	 * result in a dir '2222' being guessed due to backwards
		}
	strbuf_addch(dest, '/');
 */
	else if (!S_ISDIR(st.st_mode))

			/* Is it a "gitfile"? */

	struct object_id oid;
	if (option_recurse_submodules.nr > 0) {
	 * hostname (that is, there is no dir separator but a
	git_config_set(key.buf, repo);
		option_single_branch = deepen ? 1 : 0;
	t = ref_transaction_begin(&err);
static char *option_origin = NULL;
		const char *spec =
#include "strbuf.h"
	while (dir < end - 1 && is_dir_sep(end[-1]))
	git_config(git_default_config, NULL);
		transport->server_options = &server_options;
		option_bare = 1;
	start = strstr(repo, "://");

		ptr = end;
		 */
	const char *head;
	OPT_SET_INT('4', "ipv4", &family, N_("use IPv4 addresses only"),

	if (filter_options.choice)
static int checkout(int submodule_progress)
		err = run_command_v_opt(args.argv, RUN_GIT_CMD);
	if (filter_options.choice) {
		transport_fetch_refs(transport, mapped_refs);

 *  - respect DB_ENVIRONMENT for .git/objects.
			if (!our_head_points_at)
	submodule_progress = transport->progress;

		copy_or_link_directory(&src, &dest, src_repo);
	if (is_bare)
			if (option_local > 0)
		   N_("directory from which templates will be used")),
			is_local = 0;
			} else if (remote_head_points_at) {
	}
		for (i = 0; i < refspec->nr; i++)
			continue;
				else
	if (end - start > 5 && is_dir_sep(end[-5]) &&
	size_t len;
	}
	strbuf_addf(&default_refspec, "+%s*:%s*", src_ref_prefix,
	}
static void update_remote_refs(const struct ref *refs,
			add_to_alternates_file(abs_path);
static int option_verbosity;

		else {
				warning(_("source repository is shallow, ignoring --local"));
static struct string_list option_config = STRING_LIST_INIT_NODUP;
}
				"submodule.alternateLocation=superproject");
	return !stat(path, &sb);

 *		 2008 Daniel Barkalow <barkalow@iabervon.org>

				item->string, err.buf);
	sigchain_push_common(remove_junk_on_signal);
					       "--no-single-branch");
		char *abs_path;
	}
	if (option_no_tags) {
		our_head_points_at = NULL;
		if (max_jobs != -1)
		strbuf_addstr(&head_ref, "HEAD");
	else
			   oid_to_hex(&oid), "1", NULL);
		get_common_dir(&alt, src_repo);
		if (S_ISDIR(st.st_mode) && is_git_directory(path->buf)) {
		}
static int option_shallow_submodules;
		    N_("any cloned submodules will be shallow")),
static struct string_list option_not = STRING_LIST_INIT_NODUP;
				return dst;
	} else {
				git_config_set(key.buf, "true");
	 * Replace sequences of 'control' characters and whitespace

			continue;
			string_list_append(&option_config,
		setup_reference();


	strbuf_release(&head);
	OPT_END()
		if (option_depth)

#include "unpack-trees.h"
		die("%s", err.buf);
			}
		strbuf_addf(&sb, "%s/objects", ref_git);
		struct ref *remote_head = NULL;

		else
		die(_("No directory name could be guessed.\n"
		    N_("create a shallow clone of that depth")),
{
		strbuf_addf(&key, "remote.%s.tagOpt", option_origin);
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		return -1;
	refs = transport_get_remote_refs(transport, &ref_prefixes);


	OPT_STRING_LIST(0, "reference-if-able", &option_optional_reference,
		   N_("use <name> instead of 'origin' to track upstream")),
}
	if (!err && (option_recurse_submodules.nr > 0)) {
		/* proceed to removal */
#include "dir-iterator.h"
	argc = parse_options(argc, argv, prefix, builtin_clone_options,
		struct strbuf alt = STRBUF_INIT;
			}
				strbuf_reset(&key);
	}

					strbuf_addf(&value, "+%s:%s", our_head_points_at->name,
	return result;
		 * remote HEAD check.
	}
		 * set in the per-worktree config.

		strbuf_release(&alt);

			continue;
		if (option_since)
	int dest_exists;

		return 0;
static char *get_repo_path(const char *repo, int *is_bundle)
	OPT__VERBOSITY(&option_verbosity),
		if (!has_object_file_with_flags(&ref->old_oid,
#include "remote.h"
	struct tree *tree;
{
}
	}
	if (path)
	atexit(remove_junk);
		}
static int junk_git_dir_flags;
	 * directory 'bar' being guessed.

static char *option_upload_pack = "git-upload-pack";
	char *path, *dir;
		argv_array_pushl(&args, "submodule", "update", "--require-init", "--recursive", NULL);
			continue;
					      "refs/heads/master");
	if (!option_origin)
	 */
	init_checkout_metadata(&opts.meta, head, &oid, NULL);

	if (option_upload_pack)
		    N_("create a shallow clone since a specific time")),

	 *
	while ((iter_status = dir_iterator_advance(iter)) == ITER_OK) {

	if (option_single_branch == -1)
	junk_mode = JUNK_LEAVE_REPO;
	packet_trace_identity("clone");
		if (option_branch) {
		remote_head = find_ref_by_name(refs, "HEAD");
		warning(_("remote HEAD refers to nonexistent ref, "
			     add_one_reference, &required);
	struct ref **rm = cb_data;
			for (i = 0; i < refspec->nr; i++)
		if (!option_bare)
		remote_head_points_at =
		argv_array_push(&ref_prefixes, "refs/tags/");
			dst = read_gitfile(path->buf);
	  N_("pathspec"), N_("initialize submodules in the clone"),
 * Copyright (c) 2007 Kristian Høgsberg <krh@redhat.com>,

#include "list-objects-filter-options.h"
		string_list_append((struct string_list *)opt->value,
static enum {
			*is_bundle = 0;
	OPT_BOOL(0, "progress", &option_progress,
	 * destination repository with add_to_alternates_file().
{
}

		for (ref = refs; ref; ref = ref->next)
			fprintf(stderr,
	 * the final decision for this flag, so we need to rescue the value
			warning("skipping invalid relative alternate: %s/%s",
				  work_tree);
}
static struct ref *wanted_peer_refs(const struct ref *refs,
static void remove_junk_on_signal(int signo)
			fprintf(stderr, _("Cloning into bare repository '%s'...\n"), dir);
				continue;
	struct stat st;
		dir = xstrdup(argv[1]);
		strbuf_addstr(path, suffix[i]);
		   N_("checkout <branch> instead of the remote's HEAD")),
	} else if (our) {
			fprintf(stderr, _("Cloning into '%s'...\n"), dir);
	strbuf_release(&branch_top);
}
		transport_set_option(transport, TRANS_OPT_DEEPEN_NOT,
		strbuf_setlen(src, src_len);
#include "dir.h"
			"an empty directory."), dir);
static int deepen;
	return dir;
	OPT_STRING('b', "branch", &option_branch, N_("branch"),
					      &tail, 0);
		}
				prev_space = 0;

	 * we did so for the main clone. But only the transport knows
			detach_advice(oid_to_hex(&oid));
{
		transport_set_option(transport, TRANS_OPT_UPLOADPACK,
	ref = find_ref_by_name(refs, head.buf);



			junk_git_dir_flags |= REMOVE_DIR_KEEP_TOPLEVEL;

		add_to_alternates_file(sb.buf);
	if (option_single_branch)
int cmd_clone(int argc, const char **argv, const char *prefix)

	else if (stat(pathname, &st))
				if (starts_with(our_head_points_at->name, "refs/tags/"))
		return ref;

	if (option_bare) {
			die(_("unable to update HEAD"));
	OPT_STRING(0, "depth", &option_depth, N_("depth"),
	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);
static int path_exists(const char *path)
	if (option_depth || option_since || option_not.nr)
	if (option_depth)
		if (ref_transaction_create(t, r->peer_ref->name, &r->old_oid,
			die(_("unable to update %s"), head_ref.buf);
		string_list_sort(&option_recurse_submodules);
	if (!mkdir(pathname, mode))
		strbuf_addstr(&branch_top, src_ref_prefix);

			     add_one_reference, &required);
	}
static struct string_list server_options = STRING_LIST_INIT_NODUP;

					option_branch, option_origin);
	 * for the later checkout to use the sparse-checkout file.
				strbuf_addf(&key, "remote.%s.mirror", option_origin);

						branch_top->buf, head);

			int i;
		if (advice_detached_head)
static void clone_local(const char *src_repo, const char *dest_repo)
	while (ref && !ref->peer_ref)


		if (out > dir && prev_space)
}
	strbuf_addf(&reflog_msg, "clone: from %s", repo);
	int i;
static void copy_alternates(struct strbuf *src, const char *src_repo)
		/* Local default branch link */
#include "lockfile.h"
	if (!ref_git) {
		 * HEAD points to a branch but we don't know which one.
	if (option_bare)
	    && memchr(start, ':', end - start) != NULL) {
		if (value.len) {
		if (*ptr == '@')
		/* Files that cannot be copied bit-for-bit... */
	return 0;
	opts.verbose_update = (option_verbosity >= 0);
		return 1;
		if (option_mirror)
	err |= run_hook_le(NULL, "post-checkout", oid_to_hex(&null_oid),
static char *guess_dir_name(const char *repo, int is_bundle, int is_bare)
	if (memchr(start, '/', end - start) == NULL
#include "iterator.h"
					      value ? value : "true",

	 * absolute, so that they can be used in the new repository.
	OPT_STRING_LIST(0, "reference", &option_required_reference, N_("repo"),
	strbuf_release(&err);
			our_head_points_at =
		struct strbuf head_ref = STRBUF_INIT;
	 * the host part.
	transport_unlock_pack(transport);
	default:
			} else
			local_refs = NULL;

		git_dir = xstrdup(dir);
	argv_array_clear(&argv);
			close(fd);
	if (remote_head_points_at && !option_bare) {
	init_db(git_dir, real_git_dir, option_template, GIT_HASH_UNKNOWN, INIT_DB_QUIET);
			      "both --reference and --reference-if-able"));
			tail = &local_refs;
			our_head_points_at = remote_head_points_at;
	else {
		transport_set_option(transport, TRANS_OPT_DEEPEN_SINCE,

		if (!stat(path->buf, &st) && S_ISREG(st.st_mode)) {
	*end = '\0';
	} else {
		if (!option_branch)

			argv_array_push(&args, "--depth=1");
	if (initial_ref_transaction_commit(t, &err))
			if ((unsigned char)ch < '\x20')
		struct refspec *refspec)
	strip_suffix_mem(start, &len, is_bundle ? ".bundle" : ".git");
		opt.progress = transport->progress;
{
		dissociate_from_references();
	 * Skip authentication data. The stripping does happen
		die(_("repository '%s' does not exist"), repo_name);
	strbuf_release(&err);
	if (argc > 2)
	for (r = local_refs; r; r = r->next) {
		strbuf_setlen(path, baselen);
	 * Find last component. To remain backwards compatible we

	if (argc == 0)
	char *canon;

			argv_array_push(&args, "--no-fetch");
	mkdir_if_missing(dest->buf, 0777);
}
#include "config.h"
	 * and copy the entries to corresponding file in the

		git_config_set("core.bare", "true");
	 */
				    item->string);
	repo_name = argv[0];
	strip_trailing_slashes(dir);
		string_list_clear((struct string_list *)opt->value, 0);
		if (create_symref("HEAD", our->name, NULL) < 0)
	if (option_single_branch) {
	/*
				     option_upload_pack);
static const char * const builtin_clone_usage[] = {
}
	OPT_BOOL(0, "no-hardlinks", &option_no_hardlinks,
static int recurse_submodules_cb(const struct option *opt,
	 */
		}
			TRANSPORT_FAMILY_IPV4),
};
		struct strbuf *branch_top)
#include "refs.h"
		die_errno(_("failed to start iterator over '%s'"), src->buf);
	if (!option_no_tags)

	unsigned int flags;

				break;
		if (option_shallow_submodules == 1)
{
		usage_msg_opt(_("You must specify a repository to clone."),
static int max_jobs = -1;
			get_fetch_map(remote_head, tag_refspec, &tail, 0);

static struct string_list option_recurse_submodules = STRING_LIST_INIT_NODUP;
		argv_array_clear(&args);
			junk_git_dir_flags |= REMOVE_DIR_KEEP_TOPLEVEL;
	strbuf_release(&key);
		partial_clone_register(option_origin, &filter_options);

	}
		transport_set_option(transport, TRANS_OPT_DEPTH,
	strbuf_addstr(&head, "refs/tags/");
	transport->family = family;
	struct strbuf branch_top = STRBUF_INIT, reflog_msg = STRBUF_INIT;
	if (option_mirror)
 * Builtin "git clone"
}
	/*

			string_list_append(&option_config,
				   const char *src_repo)

				ch = '\x20';
	static const char* argv[] = { "repack", "-a", "-d", NULL };
	OPT_SET_INT('6', "ipv6", &family, N_("use IPv6 addresses only"),

			char signature[8];
	OPT_HIDDEN_BOOL(0, "naked", &option_bare,
static void remove_junk(void)

	if (!iter)
	for (i = 0; i < ARRAY_SIZE(bundle_suffix); i++) {
	}
static void write_remote_refs(const struct ref *local_refs)
			update_ref(msg, "HEAD", &our->old_oid, NULL, 0,
			die_errno(_("cannot unlink temporary alternates file"));
{

	 */
}
	int *required = cb_data;
	OPT_BOOL(0, "sparse", &option_sparse_checkout,
	return 0;
	if (option_local > 0 && !is_local)
		die(_("failed to iterate over '%s'"), src->buf);
		int i;
#include "object-store.h"
					       write_one_config, NULL) < 0)
		if (!option_no_hardlinks) {
	 */
			warning(_("--filter is ignored in local clones; use file:// instead."));
			continue;
			continue;
		strbuf_release(&src);
			len = read_in_full(fd, signature, 8);
			if (fd < 0)
{
		/* fall-through */
#include "tree-walk.h"
	transport = transport_get(remote, remote->url[0]);
		    N_("clone only one branch, HEAD or --branch")),
	static char *suffix[] = { "/.git", "", ".git/.git", ".git" };

		fprintf(stderr, _("done.\n"));
#include "branch.h"
		struct strbuf sb = STRBUF_INIT;
	is_local = option_local != 0 && path && !is_bundle;
					       "--single-branch" :
		die("%s", err.buf);
		start += 3;
	if (!option_mirror && !option_single_branch && !option_no_tags)
	}

		else if (option_required_reference.nr) {
					strbuf_addf(&value, "+%s:%s%s", our_head_points_at->name,
			ptr--;
		break;
N_("Clone succeeded, but checkout failed.\n"
	for_each_string_list(&option_optional_reference,
		}

	if (option_sparse_checkout && git_sparse_checkout_init(dir))
				"submodule.alternateErrorStrategy=info");
	return NULL;

			if (!link(realpath.buf, dest->buf))
			       const char *branch_top,
