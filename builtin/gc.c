	 * post-daemonized phases will call us, but running these
}
				die(FAILED_RUN, prune.argv[0]);
static struct packed_git *find_base_packs(struct string_list *packs,
static int too_many_packs(void)
		commit_lock_file(&log_lock);

		    name, (uintmax_t)pid);
				exit(128);
	struct sysinfo si;
/*
		sigchain_push_common(process_log_file_on_signal);
	 */
	argv_array_pushl(&pack_refs_cmd, "pack-refs", "--all", "--prune", NULL);
	else
	for (i = 0; i < pack_garbage.nr; i++)
			if (ret == 1)
#elif defined(HAVE_BSD_SYSCTL) && (defined(HW_MEMSIZE) || defined(HW_PHYSMEM))
	if (argc == 2 && !strcmp(argv[1], "-h"))
	 * the cache.
		if (auto_gc)
}
	 */
	/* revindex is used also */
	reprepare_packed_git(the_repository);
	 * distributed, we can check only one and get a reasonable
		should_exit =
			free(pidfile_path);
	git_config_get_int("gc.aggressivewindow", &aggressive_window);
	if (xgethostname(my_host, sizeof(my_host)))
	 * estimate.
	if (the_repository->settings.gc_write_commit_graph == 1)
				find_base_packs(&keep_pack, 0);

#define FAILED_RUN "failed to run %s"
	if (auto_gc && too_many_loose_objects())
		if (errno == ENOENT)
	dir = opendir(git_path("objects/17"));
	os_cache = pack->pack_size + pack->index_size;
		usage_with_options(builtin_gc_usage, builtin_gc_options);
	if (gc_config_is_timestamp_never("gc.reflogexpire") &&
			/*
		return 0;
			die(_("failed to parse '%s' value '%s'"), var, value);
	char my_host[HOST_NAME_MAX + 1];
			pack_refs = git_config_bool("gc.packrefs", value);

	mib[1] = HW_PHYSMEM;
		argv_array_push(&repack, "-a");
		return 0;

	return 0;
	} else {

	/* then pack-objects needs lots more for book keeping */
	 * and the other half is for trees (commits and tags are
		argv_array_push(&prune_worktrees, prune_worktrees_expire);
 *
	heap = sizeof(struct object_entry) * nr_objects;
	argv_array_pushl(&repack, "repack", "-d", "-l", NULL);
			!fstat(fileno(fp), &st) &&
			 * problem. --force can be used in manual gc
			PARSE_OPT_OPTARG, NULL, (intptr_t)prune_expire },
			argv_array_push(&prune, prune_expire);
 * Cleanup unreachable files and optimize the repository.
	} else {
static unsigned long max_delta_cache_size = DEFAULT_DELTA_CACHE_SIZE;
	/*
	}
	git_config_get_bool("gc.autodetach", &detach_auto);
		if (aggressive_depth > 0)

	struct option builtin_gc_options[] = {
{

static uint64_t total_ram(void)
	if (!sysinfo(&si))
	size_t os_cache, heap;
	/*

		return NULL;
		return si.totalram;
	name = lock_repo_for_gc(force, &pid);
{
		 * Auto-gc should be least intrusive as possible.

static void gc_config(void)
#include "commit.h"
		for_each_string_list(keep_pack, keep_one_pack, NULL);
	int cnt;
		argv_array_push(&repack, "-A");
#endif
	DIR *dir;
				big_pack_threshold = 0;
	if (stat(gc_log_path, &st)) {
		rollback_lock_file(&log_lock);
		argv_array_push(&repack, "-q");
		/*
		if (prune_expire)
		}

static void gc_before_repack(void)
static struct argv_array rerere = ARGV_ARRAY_INIT;
	if (len < 0)
{
static struct argv_array reflog = ARGV_ARRAY_INIT;
	}
static struct string_list pack_garbage = STRING_LIST_INIT_DUP;
			if (lock_repo_for_gc(force, &pid))
	if (aggressive) {
			fp != NULL &&
	if (fstat(get_lock_file_fd(&log_lock), &st)) {
}
	raise(signo);
			 * 12 hour limit is very generous as gc should
	}
	NULL
	} else if (st.st_size) {
	if (argc > 0)
{
			mem_have = total_ram();
	 * or we may accidentally evict data of other processes from
					     NULL);
		if (keep_base_pack != -1) {

	argv_array_pushl(&prune, "prune", "--expire", NULL);
	git_config_get_ulong("gc.bigpackthreshold", &big_pack_threshold);
{
			get_tempfile_path(log_lock.tempfile),
			if (run_command_v_opt(prune.argv, RUN_GIT_CMD))

int cmd_gc(int argc, const char **argv, const char *prefix)
	if (pack_refs < 0)
	if (is_tempfile_active(pidfile))
		die(_("gc is already running on machine '%s' pid %"PRIuMAX" (use --force if not)"),
static struct argv_array repack = ARGV_ARRAY_INIT;
		return 0;
				return 0;
	 * Setting gc.auto to 0 or negative can disable the
		    ent->d_name[hexsz_loose] != '\0')
	}
	N_("git gc [<options>]"),
			     builtin_gc_usage, 0);
	char *pidfile_path;
		static char locking_host[HOST_NAME_MAX + 1];

				string_list_clear(&keep_pack, 0);

		int should_exit;
			"run 'git prune' to remove them."));

				       LOCK_DIE_ON_ERROR);
				argv_array_push(&prune, "--no-progress");
				argv_array_push(&prune,

		add_repack_all_option(&keep_pack);

	argv_array_push(&repack, "--no-write-bitmap-index");

}
static void process_log_file_on_signal(int signo)
static const char *lock_repo_for_gc(int force, pid_t* ret_pid)
	mib[1] = HW_MEMSIZE;
	strbuf_addf(&sb, "%"PRIuMAX" %s",
static struct lock_file log_lock;

static uint64_t estimate_repack_memory(struct packed_git *pack)
}

	return gc_auto_pack_limit < cnt;
	uintmax_t pid;
			if (!mem_have || mem_want < mem_have / 2)
			N_("prune unreferenced objects"),

			uint64_t mem_have, mem_want;
	}
	/* and of course pack-objects has its own delta cache */
{
 *

}

	fd = hold_lock_file_for_update(&lock, pidfile_path,
 * Returns 0 if there was no previous error and gc can proceed, 1 if

	int daemonized = 0;
			int ret = report_last_gc_error();
			time(NULL) - st.st_mtime <= 12 * 3600 &&
}
}
{

				rollback_lock_file(&lock);
# else
#include "commit-graph.h"
			       "Automatic cleanup will not be performed "
	mib[0] = CTL_HW;
	/*
					     !quiet && !daemonized ? COMMIT_GRAPH_WRITE_PROGRESS : 0,
	if (name) {
#include "pack-objects.h"
		}
{
			break;
	if (base)
	closedir(dir);
static void process_log_file(void)
	if (!dir)
		if (big_pack_threshold) {
	 */
}

#include "blob.h"
		if (should_exit) {
#include "config.h"

 */
	if (!git_config_get_value(var, &value) && value) {
{
}
	}
	argv_array_pushl(&prune_worktrees, "worktree", "prune", "--expire", NULL);
		struct string_list keep_pack = STRING_LIST_INIT_NODUP;
{
static const char * const builtin_gc_usage[] = {
			die(FAILED_RUN, prune_worktrees.argv[0]);
		if (p->pack_keep)
static void clean_pack_garbage(void)
		if (prune_expire) {
			if (quiet)
			return 0; /* be quiet on --auto */
	/*
			continue;
	 * automatic gc.
			fclose(fp);
	 * let's say half of it is for blobs
	for (cnt = 0, p = get_all_packs(the_repository); p; p = p->next) {
	git_config_get_int("gc.aggressivedepth", &aggressive_depth);

		if (!need_to_gc())
	struct packed_git *p, *base = NULL;
static void add_repack_all_option(struct string_list *keep_pack)
#include "sigchain.h"
			if (p->pack_size >= limit)
			   PARSE_OPT_NOCOMPLETE),
}
		goto done;
			 */
		string_list_clear(&keep_pack, 0);
		warning(_("The last gc run reported the following. "

		/*
	else if (len > 0) {
			/*
			mem_want = estimate_repack_memory(p);
		die(_("failed to parse gc.logexpiry value %s"), gc_log_expire);

		string_list_clear(&keep_pack, 0);
		{ OPTION_STRING, 0, "prune", &prune_expire, N_("date"),
		if (detach_auto) {
	int force = 0;
	gc_config();

	if (run_command_v_opt(rerere.argv, RUN_GIT_CMD))

	if (prune_expire && parse_expiry_date(prune_expire, &dummy))
#include "argv-array.h"

	else {
			continue;
	/*
			 * after the user verifies that no gc is
 *
{
	if (prune_expire && !strcmp(prune_expire, "now"))
}
			fprintf(stderr, _("See \"git help gc\" for manual housekeeping.\n"));
			find_base_packs(&keep_pack, big_pack_threshold);
		 * unlikely situation.  Try to make a note of
	 * usually insignificant)

 *
		if (!p->pack_local)
			 * never take that long. On the other hand we
static int gc_config_is_timestamp_never(const char *var)

		} else if (!base || base->pack_size < p->pack_size) {
	if (!git_config_get_value("gc.packrefs", &value)) {
static int aggressive_depth = 50;
			*ret_pid = pid;
static unsigned long big_pack_threshold;
	}
	};
	char *gc_log_path = git_pathdup("gc.log");
}
{
		unlink(git_path("gc.log"));
	if (seen_bits == PACKDIR_FILE_IDX)

 * Copyright (c) 2007 James Bowes
	} else if (too_many_loose_objects())
		die(FAILED_RUN, reflog.argv[0]);
static int report_last_gc_error(void)
	git_config_get_ulong("pack.deltacachesize", &max_delta_cache_size);
	/* default expiry time, overwritten in gc_config */
		prune_reflogs = 0;
	const char *name;
	struct strbuf sb = STRBUF_INIT;
	strbuf_release(&sb);
			 * the rest for the OS and other processes in the
#include "pack.h"
		return expire == 0;
	git_config_get_expiry("gc.pruneexpire", &prune_expire);
	git_config(git_default_config, NULL);
	 * many loose objects there are.  Because SHA-1 is evenly
		if (!scan_fmt)
	git_config_get_expiry("gc.logexpiry", &gc_log_expire);
static struct argv_array prune_worktrees = ARGV_ARRAY_INIT;
}
	if (keep_pack)
static int keep_one_pack(struct string_list_item *item, void *data)
	return 0;

		return memInfo.ullTotalPhys;
		}

			continue;

static int too_many_loose_objects(void)
	if (gc_auto_threshold <= 0)
	 * we run "repack -A -d -l".  Otherwise we tell the caller
	heap += max_delta_cache_size;


#include "builtin.h"
	int i;


		/* No error, clean up any old gc.log */
		write_commit_graph_reachable(the_repository->objects->odb,
		OPT_BOOL_F(0, "force", &force,
	struct stat st;
static int pack_refs = 1;
		close_object_store(the_repository->objects);
#include "object-store.h"
		 */
	return 1;
		pack_refs = !is_bare_repository();
		}
 * Based on git-gc.sh, which is
			   N_("force running gc even if there may be another gc running"),

	}
		goto done;
	 */
	int mib[2];
	prepare_repo_settings(the_repository);
	 */
	if (run_hook_le(NULL, "pre-auto-gc", NULL))
	if (!repository_format_precious_objects) {
		cnt++;
static timestamp_t gc_log_expire_time;

	struct packed_git *p;
			argv_array_pushf(&repack, "--window=%d", aggressive_window);
static struct argv_array pack_refs_cmd = ARGV_ARRAY_INIT;
			daemonized = !daemonize();
			/* be gentle to concurrent "gc" on remote hosts */
			continue;
		if (run_command_v_opt(repack.argv, RUN_GIT_CMD))
		 * Perhaps check the size of the pack and count only
	struct stat st;

	write_in_full(fd, sb.buf, sb.len);
	    gc_config_is_timestamp_never("gc.reflogexpireunreachable"))
		OPT_END()
	 * read_sha1_file() (either at delta calculation phase, or
#include "tempfile.h"
 * gc should not proceed due to an error in the last run. Prints a
{
	 */
	int needed = 0;
			if (ret < 0)
			 * running.
		argv_array_push(&repack, "-f");
	const unsigned hexsz_loose = the_hash_algo->hexsz - 2;
#elif defined(GIT_WINDOWS_NATIVE)
static int gc_auto_threshold = 6700;


		}
			argv_array_pushf(&repack, "--depth=%d", aggressive_depth);
		 * to fail in the same way.
		fprintf(stderr, _("Failed to fstat %s: %s"),
	git_config_get_int("gc.autopacklimit", &gc_auto_pack_limit);

		fflush(stderr);
		return physical_memory;
		}

		/* already locked */

}
		 * A previous gc failed.  Report the error, and don't
			       "and remove %s.\n"
#include "tree.h"

	if (prune_reflogs && run_command_v_opt(reflog.argv, RUN_GIT_CMD))
	}

		/*
		unlink(git_path("gc.log"));
		if (!p->pack_local)
		commit_lock_file(&log_lock);

	if (!daemonized)
	string_list_clear(&pack_garbage, 0);

		die(FAILED_RUN, rerere.argv[0]);

		if (aggressive_window > 0)
			}
	pidfile = register_tempfile(pidfile_path);
static void add_repack_incremental_option(void)
		struct string_list keep_pack = STRING_LIST_INIT_NODUP;
		dup2(get_lock_file_fd(&log_lock), 2);
		} else {
	return os_cache + heap;

	len = strbuf_read_file(&sb, gc_log_path, 0);
			/*
	gc_before_repack();
	return ret;
	size_t length;
		return 0;
	 */
		return;
				fprintf(stderr, _("Auto packing the repository for optimum performance.\n"));
#include "promisor-remote.h"
	if (parse_expiry_date(gc_log_expire, &gc_log_expire_time))
#if defined(HAVE_SYSINFO)
		warning(_("There are too many unreachable loose objects; "
		string_list_append(&pack_garbage, path);
		 * bother with an automatic gc run since it is likely
			       "%s"),

		/* There was some error recorded in the lock file */
	if (pack_refs && run_command_v_opt(pack_refs_cmd.argv, RUN_GIT_CMD))
			       "until the file is removed.\n\n"

	if (auto_gc) {
				string_list_append(packs, p->pack_name);
{
		 * very small ones here?
		static char *scan_fmt;
		if (value && !strcmp(value, "notbare"))
		return 0;
{
	pidfile_path = git_pathdup("gc.pid");
			 * failure to daemonize is ok, we'll continue
	free(pidfile_path);
		if (!quiet) {
			 * Only allow 1/2 of memory for pack-objects, leave
			 * running gc --auto one day late is not a big
#include "parse-options.h"
	sigchain_pop(signo);

				/* Last gc --auto failed. Skip this one. */

		}
static const char *prune_expire = "2.weeks.ago";

		close_object_store(the_repository->objects);
	 * We may be called twice, as both the pre- and
 */
	auto_threshold = DIV_ROUND_UP(gc_auto_threshold, 256);
				return 0;
static struct tempfile *pidfile;

	int aggressive = 0;
 * message and returns -1 if an error occurred while reading gc.log
	 * Assume enough room in OS file cache to keep the entire pack
	const char *value;
}
static const char *gc_log_expire = "1.day.ago";
		 * Perhaps there was an i/o error or another
			    gc_log_path, sb.buf);

	length = sizeof(int64_t);

	git_config_get_int("gc.auto", &gc_auto_threshold);
		add_repack_incremental_option();
	int auto_gc = 0;
	if (prune_worktrees_expire) {
			argv_array_pushf(&repack, "--unpack-unreachable=%s", prune_expire);
		string_list_append(packs, base->pack_name);
	return needed;

};
		hold_lock_file_for_update(&log_lock,
				/* an I/O error occurred, already reported */
			return locking_host;

			die(FAILED_RUN, repack.argv[0]);
	return 0;
	struct lock_file lock = LOCK_INIT;
		 * messages.
	return base;

static int prune_reflogs = 1;

	argv_array_pushl(&rerere, "rerere", "gc", NULL);
	if (quiet)
	process_log_file();
# endif
			 N_("repack all other packs except the largest pack")),
			pack_refs = -1;
	argc = parse_options(argc, argv, prefix, builtin_gc_options,
	 * there is no need.
			 */
	git_config_get_expiry("gc.worktreepruneexpire", &prune_worktrees_expire);
		if (parse_expiry_date(value, &expire))
	timestamp_t dummy;
					  LOCK_DIE_ON_ERROR);
	/*
	}
	int fd;

	FILE *fp;
	if (!sysctl(mib, 2, &physical_memory, &length, NULL, 0))
	if (GlobalMemoryStatusEx(&memInfo))
		die(FAILED_RUN, pack_refs_cmd.argv[0]);
		 */

			 * in foreground
			 * don't really need a strict limit here,

	argv_array_pushl(&reflog, "reflog", "expire", "--all", NULL);
			if (keep_base_pack)
	if (!pack || !nr_objects)
	fflush(stderr);
	report_garbage = report_pack_garbage;
static int need_to_gc(void)
	 * Quickly check if a "gc" is needed, by estimating how
	int keep_base_pack = -1;

	process_log_file();
	struct stat st;
	}
	if (st.st_mtime < gc_log_expire_time)
		ret = error_errno(_("cannot stat '%s'"), gc_log_path);
{
		xsnprintf(my_host, sizeof(my_host), "unknown");
#include "repository.h"
				string_list_clear(&keep_pack, 0);
			goto done;
	heap += sizeof(struct revindex_entry) * nr_objects;
	heap += delta_base_cache_limit;
#include "packfile.h"
		if (strspn(ent->d_name, "0123456789abcdef") != hexsz_loose ||
	 * internal rev-list --all --objects takes up some memory too,
		unlink_or_warn(pack_garbage.items[i].string);
}
/* return NULL on success, else hostname running the gc */
					  unsigned long limit)
static void process_log_file_at_exit(void)
			 * system.
			scan_fmt = xstrfmt("%s %%%ds", "%"SCNuMAX, HOST_NAME_MAX);
	int num_loose = 0;
			if (fd >= 0)

	heap += sizeof(struct tree) * nr_objects / 2;
static struct argv_array prune = ARGV_ARRAY_INIT;
		OPT__QUIET(&quiet, N_("suppress progress reporting")),
		    (uintmax_t) getpid(), my_host);
#include "run-command.h"

		else
			find_base_packs(&keep_pack, big_pack_threshold);
			strerror(saved_errno));
{

			return 0;
	/* and then obj_hash[], underestimated in fact */
}


						"--exclude-promisor-objects");
		memset(locking_host, 0, sizeof(locking_host));
static const char *prune_worktrees_expire = "3.months.ago";
			   PARSE_OPT_NOCOMPLETE),
	if (too_many_packs()) {
	int64_t physical_memory;
		ret = 1;
					  git_path("gc.log"),
	 * packs, we run "repack -d -l".  If there are too many packs,
	for (p = get_all_packs(the_repository); p; p = p->next) {
			 */
		ret = error_errno(_("cannot read '%s'"), gc_log_path);
		if (limit) {
		if (++num_loose > auto_threshold) {
			gc_before_repack(); /* dies on failure */
	commit_lock_file(&lock);
	}
	/*
	if (gc_auto_pack_limit <= 0)

	timestamp_t expire;
#include "lockfile.h"
		if (fp != NULL)
		if (run_command_v_opt(prune_worktrees.argv, RUN_GIT_CMD))
			(strcmp(locking_host, my_host) || !kill(pid, 0) || errno == EPERM);
	}
		OPT_BOOL_F(0, "auto", &auto_gc, N_("enable auto-gc mode"),
		 */
	 * writing phase) also fills up the delta base cache
	ssize_t len;
	}
		} else if (big_pack_threshold) {
}
	MEMORYSTATUSEX memInfo;
{
	pid_t pid;
		atexit(process_log_file_at_exit);
				fprintf(stderr, _("Auto packing the repository in background for optimum performance.\n"));
	}
	const char *value;

		 */
	 */
			delete_tempfile(&pidfile);

	if (daemonized) {
		int saved_errno = errno;
		}
				find_base_packs(&keep_pack, 0);
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
			fscanf(fp, scan_fmt, &pid, locking_host) == 2 &&
	return NULL;
	heap += sizeof(struct blob) * nr_objects / 2;
		die(_("failed to parse prune expiry value %s"), prune_expire);
	static int done = 0;
		errno = saved_errno;
			if (has_promisor_remote())
	/*
	 * If there are too many loose objects, but not too many
# if defined(HW_MEMSIZE)
{
static int aggressive_window = 250;

			if (keep_pack.nr >= gc_auto_pack_limit) {
			struct packed_git *p = find_base_packs(&keep_pack, 0);
		fp = fopen(pidfile_path, "r");
		add_repack_all_option(&keep_pack);

	}
		OPT_BOOL(0, "aggressive", &aggressive, N_("be more thorough (increased runtime)")),

	strbuf_release(&sb);
	struct dirent *ent;
	int auto_threshold;
	while ((ent = readdir(dir)) != NULL) {
	 * First we have to scan through at least one pack.
		usage_with_options(builtin_gc_usage, builtin_gc_options);
/*
	int ret = 0;
static int gc_auto_pack_limit = 50;
	int quiet = 0;
	 * commands more than once is pointless and wasteful.

	heap += sizeof(struct object *) * nr_objects;
			if (detach_auto)
			needed = 1;
	return 0;
		return 0;
		OPT_BOOL(0, "keep-largest-pack", &keep_base_pack,
	free(gc_log_path);
	struct strbuf sb = STRBUF_INIT;
	if (!force) {
done:
}
 * git gc builtin command
static void report_pack_garbage(unsigned seen_bits, const char *path)
	unsigned long nr_objects = approximate_object_count();



	}

 * Copyright (c) 2006 Shawn O. Pearce
static int detach_auto = 1;
			       "Please correct the root cause\n"
	argv_array_pushf(&repack, "--keep-pack=%s", basename(item->string));
		/*
		clean_pack_garbage();
	if (done++)
			else
		 * this in gc.log along with any existing
	if (pack_garbage.nr > 0) {
			base = p;
{
