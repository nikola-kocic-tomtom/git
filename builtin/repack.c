			free(fname);
	int no_reuse_delta;
	if (args->threads)
		argv_array_push(&cmd.args, "--incremental");
		return;
	if (!(dir = opendir(packdir)))
	if (ret)
	xwrite(cmd->in, oid_to_hex(oid), the_hash_algo->hexsz);
/*
	fclose(out);
		 * packfile, but this would not preserve their contents. Maybe

				 const struct pack_objects_args *args)
	 * NEEDSWORK: Giving pack-objects only the OIDs without any ordering

		write_bitmaps = git_config_bool(var, value);
		}
#include "run-command.h"
			fname = mkpathdup("%s/old-%s%s",
	packdir = mkpathdup("%s/pack", get_object_directory());
		/* No packed objects; cmd was never started */
	 */
		OPT_STRING_LIST(0, "keep-pack", &keep_pack_list, N_("name"),
		delta_base_offset = git_config_bool(var, value);
	if (write_bitmaps < 0) {


{
	FILE *out;

	ret = start_command(&cmd);
		{".promisor", 1},
					packdir, item->string, exts[ext].name);
#define ALL_INTO_ONE 1

		}
	closedir(dir);
		const char *name;
static void get_non_kept_pack_filenames(struct string_list *fname_list,
static int delta_base_offset = 1;
	sigchain_push_common(remove_pack_on_signal);
	prepare_pack_objects(&cmd, args);
		if (!keep_unreachable &&

	for (i = 0; i < keep_pack_list.nr; i++)
};
	if (!strcmp(var, "repack.usedeltabaseoffset")) {

					packtmp, item->string, exts[ext].name);
	if (delta_base_offset)
	strbuf_release(&buf);
			       FOR_EACH_OBJECT_PROMISOR_ONLY);
				N_("pass --delta-islands to git-pack-objects")),

					  line.buf);
			free(fname);
		}
		OPT_STRING(0, "threads", &po_args.threads, N_("n"),
				break;

				argv_array_pushf(&cmd.args,
				N_("same as -a, and turn unreachable objects loose"),
	while (strbuf_getline_lf(&line, out) != EOF) {
#include "config.h"
						"--unpack-unreachable");


	};
				N_("maximum size of each packfile")),
	}
{
		argv_array_pushf(&cmd->args, "--window=%s", args->window);
				    struct string_list *names)
	}
		strbuf_setlen(&buf, dirlen);
		 * NEEDSWORK: fetch-pack sometimes generates non-empty
			}
				continue;
struct pack_objects_args {
			fname = mkpathdup("%s/%s", packdir, item->string);
	if (failed) {
		     unpack_unreachable) &&
	if (write_bitmaps && !(pack_everything & ALL_INTO_ONE))
		OPT_BOOL('k', "keep-unreachable", &keep_unreachable,
	};
	if (finish_command(&cmd))
	failed = 0;


		return ret;
		 * concatenate the contents of all .promisor files instead of


	if (args->window)
	struct child_process *cmd = data;
	git_config(repack_config, NULL);
	if (ret)
		for (ext = 0; ext < ARRAY_SIZE(exts); ext++) {

		strbuf_addstr(&buf, e->d_name);

			free(fname);
			continue;
			if (unpack_unreachable) {
				clear_midx_file(the_repository);
		argv_array_push(&cmd->args,  "--local");
 */

	}
	 * {type -> existing pack order} ordering when computing deltas instead
		argv_array_push(&cmd.args, "--unpacked");
		argv_array_pushf(&cmd->args, "--window-memory=%s", args->window_memory);
		unlink(buf.buf);
	const char *window_memory;
	struct dirent *e;
#define LOOSEN_UNREACHABLE 2
	for_each_string_list_item(item, &names) {
	/* Remove the "old-" files */
		argv_array_pushf(&cmd->args, "--max-pack-size=%s", args->max_pack_size);
				N_("with -A, do not loosen objects older than this")),
	strbuf_release(&line);
	if (args->quiet)

			} else if (keep_unreachable) {
			sha1 = item->string + len - hexsz;
	cmd->git_cmd = 1;
	struct strbuf line = STRBUF_INIT;
		fd = open(promisor_name, O_CREAT|O_EXCL|O_WRONLY, 0600);
	int i, ext, ret, failed;
#include "argv-array.h"
		if (failed)

	while ((e = readdir(dir))) {
				  "WARNING: replace them with the new version of the\n"
				N_("write bitmap index")),
static void repack_promisor_objects(const struct pack_objects_args *args,
				N_("do not repack this pack")),

	prefixlen = buf.len - dirlen;
		for (ext = 0; ext < ARRAY_SIZE(exts); ext++) {
			if (!string_list_has_string(&names, sha1))
	 * the OIDs can be sent with fake paths such that pack-objects can use a
				N_("do not run git-update-server-info")),
		pack_kept_objects = git_config_bool(var, value);
		argv_array_pushf(&cmd->args, "--no-reuse-object");
		if (!po_args.quiet && isatty(2))
	sigchain_pop(signo);
	if (has_promisor_remote())

	if (pack_everything & ALL_INTO_ONE) {
				free(fname_old);
	}
	struct string_list keep_pack_list = STRING_LIST_INIT_NODUP;
				break;
			} else {
	DIR *dir;
static void remove_redundant_pack(const char *dir_name, const char *base_name)

}
				argv_array_push(&cmd.args,
	struct dirent *e;
	int keep_unreachable = 0;
	} exts[] = {
		 * .promisor files containing the ref names and associated
		}
				N_("pack everything in a single pack"), ALL_INTO_ONE),
static void remove_pack_on_signal(int signo)
		    is_repository_shallow(the_repository))
		free(promisor_name);
			int i;
	for_each_string_list_item(item, &names) {

int cmd_repack(int argc, const char **argv, const char *prefix)
	if (write_bitmaps > 0)
	if (use_delta_islands)
{
	out = xfdopen(cmd.out, "r");
				N_("pass --local to git-pack-objects")),
			}
				argv_array_push(&cmd.args, "--keep-unreachable");
{
		argv_array_push(&cmd->args,  "--quiet");
	if (args->window_memory)
	cmd.in = -1;
}

		const int hexsz = the_hash_algo->hexsz;
	return 0;
				midx_cleared = 1;
		if (start_command(cmd))
			break;
#include "sigchain.h"
static int pack_kept_objects = -1;

		OPT_BOOL('n', NULL, &no_update_server_info,
	strbuf_addstr(&buf, packtmp);
		    !is_bare_repository())
		size_t len;

static void remove_temporary_files(void)
				statbuffer.st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);

	 * of a {type -> size} ordering, which may produce better deltas.
				N_("remove redundant packs, and run git-prune-packed")),
	argv_array_push(&cmd.args, "--reflog");
	if (!strcmp(var, "repack.writebitmaps") ||

	}
			for (i = 0; i < rollback_failure.nr; i++)
	NULL
#include "midx.h"
}
	const char *window;
		return;
		OPT__QUIET(&po_args.quiet, N_("be quiet")),
					rollback_failure.items[i].string);
				argv_array_push(&cmd.env_array, "GIT_REF_PARANOIA=1");
		OPT_BOOL('d', NULL, &delete_redundant,
	close(cmd.in);
	raise(signo);
	if (args->local)

	}
			} else {

		if (!strip_suffix(e->d_name, ".pack", &len))
static void prepare_pack_objects(struct child_process *cmd,
			char *fname, *fname_old;
		repack_promisor_objects(&po_args, &names);
	if (pack_kept_objects < 0)
		use_delta_islands = git_config_bool(var, value);
			die(_("repack: Expecting full hex object ID lines only from pack-objects."));
}
	struct child_process cmd = CHILD_PROCESS_INIT;

{
			}
	packtmp = mkpathdup("%s/.tmp-%d-pack", packdir, (int)getpid());
	if (!pack_kept_objects)
	dir = opendir(packdir);

		if (existing_packs.nr && delete_redundant) {
		 * hashes at the point of generation of the corresponding
				argv_array_push(&cmd.args, "--pack-loose-unreachable");
			die(_("could not start pack-objects to repack promisor objects"));

			fname = mkpathdup("%s/pack-%s%s", packdir,
		die(_("cannot delete packs in a precious-objects repo"));
		int i;
				chmod(fname_old, statbuffer.st_mode);
	int pack_everything = 0;


		return;
	int delete_redundant = 0;
	argv_array_push(&cmd.args, "--keep-true-parents");
	    !strcmp(var, "pack.writebitmaps")) {
		argv_array_push(&cmd.args, "--delta-islands");
	closedir(dir);
				N_("pass --no-reuse-object to git-pack-objects")),
 * have a corresponding .keep file. These packs are not to

		OPT_END()
		    (!(pack_everything & LOOSEN_UNREACHABLE) ||
		printf_ln(_("Nothing new to pack."));
				N_("limits the maximum delta depth")),
				failed = 1;
		OPT_STRING(0, "max-pack-size", &po_args.max_pack_size, N_("bytes"),
	const char *depth;
		OPT_BOOL('l', "local", &po_args.local,
				remove_redundant_pack(packdir, item->string);
				N_("size of the window used for delta compression")),
	if (args->depth)
		if (line.len != the_hash_algo->hexsz)

				warning(_("failed to remove '%s'"), fname);

				string_list_append(&rollback, fname);
{
	return 0;
				  "WARNING: file.  But the operation failed, and the\n"
	dirlen = strlen(packdir) + 1;
	struct child_process cmd = CHILD_PROCESS_INIT;
	if (!strcmp(var, "repack.packkeptobjects")) {

					  exts[ext].name);
	}
#include "promisor-remote.h"
		struct string_list rollback_failure = STRING_LIST_INIT_DUP;
		char *promisor_name;
				  "WARNING: prefixing old- to their name, in order to\n"
#include "cache.h"
	const char *unpack_unreachable = NULL;
		if (rollback_failure.nr) {
		argv_array_pushf(&cmd->args, "--depth=%s", args->depth);
		argv_array_push(&cmd.args, "--write-bitmap-index");
			} else if (pack_everything & LOOSEN_UNREACHABLE) {
		fname = xmemdupz(e->d_name, len);
				 keep_pack_list.items[i].string);
				string_list_append(&rollback_failure, fname);
		}
static const char *const git_repack_usage[] = {


		argv_array_push(&cmd.args, "--honor-pack-keep");
			fname_old = mkpathdup("%s-%s%s",
	struct string_list names = STRING_LIST_INIT_DUP;
		int opts = 0;
					failed = 1;
 * Adds all packs hex strings to the fname list, which do not

			if (!stat(fname_old, &statbuffer)) {
			if (len < hexsz)
		OPT_STRING(0, "depth", &po_args.depth, N_("n"),
}
	const char *max_pack_size;
 * Write oid to the given struct child_process's stdin, starting it first if
		update_server_info(0);
	struct pack_objects_args po_args = {NULL};
				N_("with -a, repack unreachable objects")),
				_("WARNING: Some packs in use have been renamed by\n"
				continue;
	}
		exit(1);
				   LOOSEN_UNREACHABLE | ALL_INTO_ONE),
				git_repack_usage, 0);
		return 0;

	}
		return ret;
					  item->string,
		if (strncmp(e->d_name, buf.buf + dirlen, prefixlen))
		return 0;
			opts |= PRUNE_PACKED_VERBOSE;
	/* Hold the length of  ".tmp-%d-pack-" */
static int write_bitmaps = -1;
	cmd->out = -1;

	while ((e = readdir(dir)) != NULL) {
	fclose(out);
		return 0;
			free(fname);
		argv_array_pushf(&cmd->args, "--no-reuse-delta");

		write_midx_file(get_object_directory(), 0);


				N_("same as the above, but limit memory size instead of entries count")),
					const struct string_list *extra_keep)
			if (!fspathcmp(e->d_name, extra_keep->items[i].string))
		OPT_BOOL('i', "delta-islands", &use_delta_islands,

					rollback_failure.items[i].string,
				if (unlink(fname_old))
	if (args->no_reuse_object)
			struct stat statbuffer;

			fname_old = mkpathdup("%s/old-%s%s", packdir,
}
 * necessary.
	ret = finish_command(&cmd);
{
	}
			die(_("repack: Expecting full hex object ID lines only from pack-objects."));
			if (!failed && rename(fname, fname_old)) {
	strbuf_addf(&buf, "%s/%s.pack", dir_name, base_name);
	if (delete_redundant && repository_format_precious_objects)

	 */
	 * First see if there are packs of the same name and if so
		string_list_append(&names, line.buf);
 */
				exists = 1;
	xwrite(cmd->in, "\n", 1);
 * Remove temporary $GIT_OBJECT_DIRECTORY/pack/.tmp-$$-pack-* files.
		OPT_BIT('A', NULL, &pack_everything,
		argv_array_push(&cmd.args, "--write-bitmap-index-quiet");
				argv_array_push(&cmd.env_array, "GIT_REF_PARANOIA=1");
/*
	    (unpack_unreachable || (pack_everything & LOOSEN_UNREACHABLE)))
		for (ext = 0; ext < ARRAY_SIZE(exts); ext++) {
	}
		string_list_append(names, line.buf);
{

		 * .promisor file. Create the .promisor file, which is empty.
	argv_array_push(&cmd.args, "--indexed-objects");
	}
				free(fname_old);
			continue;
		OPT_BIT('a', NULL, &pack_everything,
			char *fname, *fname_old;
	/* Point at the slash at the end of ".../objects/pack/" */
			fname = mkpathdup("%s/pack-%s%s",
	struct strbuf buf = STRBUF_INIT;
			char *fname;
			continue;
		}
	struct string_list rollback = STRING_LIST_INIT_NODUP;
		 * just creating a new empty file.
			int exists = 0;
		 *
	if (git_env_bool(GIT_TEST_MULTI_PACK_INDEX, 0))
					  packdir,
		{".bitmap", 1},
	size_t dirlen, prefixlen;
	unlink_pack_path(buf.buf, 1);
}
#include "builtin.h"
		for_each_string_list_item(item, &existing_packs) {
		{".idx"},
	remove_temporary_files();
};
	int quiet;
		}
			free(fname_old);
		if (fd < 0)
		promisor_name = mkpathdup("%s-%s.promisor", packtmp,
			fprintf(stderr,
		     uint32_t pos, void *data)
		OPT_STRING(0, "window", &po_args.window, N_("n"),
		if (!file_exists(mkpath("%s/%s.keep", packdir, fname)))
 * be kept if we are going to pack everything into one file.
				free(fname);
		for_each_string_list_item(item, &rollback) {
			free(fname_old);
		unsigned optional:1;
		if (extra_keep->nr > 0 && i < extra_keep->nr)

			if (exists || !exts[ext].optional) {
#include "parse-options.h"
	int no_reuse_object;
	for_each_string_list_item(item, &names) {
	/*
				  "WARNING: attempt to rename them back to their\n"
			char *fname, *fname_old;

	char *fname;
	string_list_clear(&names, 0);
	if (!dir)
				N_("pass --no-reuse-delta to git-pack-objects")),
		OPT_BOOL('b', "write-bitmap-index", &write_bitmaps,
		prune_packed_objects(opts);
	if (delete_redundant) {

	struct string_list_item *item;
		else
	if (keep_unreachable &&
	if (args->max_pack_size)
	string_list_clear(&existing_packs, 0);
	if (cmd->in == -1) {
				  "WARNING: original names also failed.\n"
			if (!midx_cleared) {
				free(fname);
	 * repacked immediately after packing fully.
	reprepare_packed_git(the_repository);
						item->string, exts[ext].name);
		OPT_BOOL(0, "pack-kept-objects", &pack_kept_objects,
			size_t len = strlen(item->string);
	}
				  "WARNING: Please rename them in %s manually:\n"), packdir);
	string_list_clear(&rollback, 0);
	return git_default_config(var, value, cb);
#include "dir.h"
						"--unpack-unreachable=%s",
}
	N_("git repack [<options>]"),
	out = xfdopen(cmd.out, "r");
				fprintf(stderr, "WARNING:   old-%s -> %s\n",
			fname_old = mkpathdup("%s/old-%s", packdir, item->string);
	struct strbuf line = STRBUF_INIT;
	 * if we can move them out of the way (this can happen if we
	cmd.no_stdin = 1;

				if (rename(fname_old, fname))
static const char incremental_bitmap_conflict_error[] = N_(
		if (!(pack_everything & ALL_INTO_ONE) ||
#include "object-store.h"
			char *sha1;
			}
		OPT_STRING(0, "unpack-unreachable", &unpack_unreachable, N_("approxidate"),
	/* Now the ones with the same name are out of the way... */
	if (args->no_reuse_delta)
	for_each_packed_object(write_oid, &cmd,
	while (strbuf_getline_lf(&line, out) != EOF) {
	if (!strcmp(var, "repack.usedeltaislands")) {

		close(fd);
static int use_delta_islands;
{
"Incremental repacks are incompatible with bitmap indexes.  Use\n"

	/* variables to be filled by option parsing */
		return 0;
			die_errno(_("unable to create '%s'"), promisor_name);
	argv_array_push(&cmd->args, packtmp);
		die(_(incremental_bitmap_conflict_error));
	int local;
/*
						item->string, exts[ext].name);

	struct string_list existing_packs = STRING_LIST_INIT_DUP;
		argv_array_push(&cmd.args, "--exclude-promisor-objects");
	struct strbuf buf = STRBUF_INIT;
		/*
	argv_array_push(&cmd->args, "pack-objects");
				N_("limits the maximum number of threads")),
		die(_("--keep-unreachable and -A are incompatible"));
static int write_oid(const struct object_id *oid, struct packed_git *pack,
	/*
}
			}
	 * hints may result in suboptimal deltas in the resulting pack. See if

 */
	}
	else if (write_bitmaps < 0)


				N_("repack objects in packs marked with .keep")),
	DIR *dir;
	} else {
		pack_kept_objects = write_bitmaps > 0;
		argv_array_push(&cmd->args,  "--delta-base-offset");
	struct {
		{".pack"},
	}
	struct option builtin_repack_options[] = {
	 * Ok we have prepared all new packfiles.
					die_errno(_("renaming '%s' failed"), fname_old);
		argv_array_pushf(&cmd->args, "--threads=%s", args->threads);
		die(_("could not finish pack-objects to repack promisor objects"));
		 * pack-objects creates the .pack and .idx files, but not the
	strbuf_release(&buf);
#include "strbuf.h"
	if (!names.nr && !po_args.quiet)
			}
						unpack_unreachable);


	prepare_pack_objects(&cmd, &po_args);
		argv_array_pushf(&cmd.args, "--keep-pack=%s",
		for (i = 0; i < extra_keep->nr; i++)
	/* End of pack replacement. */
		OPT_BOOL('f', NULL, &po_args.no_reuse_delta,
		OPT_BOOL('F', NULL, &po_args.no_reuse_object,
	const char *threads;
			if (remove_path(fname))
	int midx_cleared = 0;
			if (file_exists(fname_old))
#include "packfile.h"
	argc = parse_options(argc, argv, prefix, builtin_repack_options,
static int repack_config(const char *var, const char *value, void *cb)
	}
			if (!file_exists(fname)) {
	argv_array_push(&cmd.args, "--all");
	FILE *out;
		string_list_sort(&names);
		if (line.len != the_hash_algo->hexsz)
	if (!no_update_server_info)

			string_list_append_nodup(fname_list, fname);
	argv_array_push(&cmd.args, "--non-empty");
		OPT_STRING(0, "window-memory", &po_args.window_memory, N_("bytes"),
#include "string-list.h"
			if (rename(fname_old, fname))
);
static char *packdir, *packtmp;
		get_non_kept_pack_filenames(&existing_packs, &keep_pack_list);
	remove_temporary_files();
"--no-write-bitmap-index or disable the pack.writebitmaps configuration."
	int no_update_server_info = 0;
		int fd;
	close_object_store(the_repository->objects);
		 */

			write_bitmaps = 0;

			prune_shallow(PRUNE_QUICK);
	if (cmd.in == -1)
