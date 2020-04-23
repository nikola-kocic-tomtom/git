#else
	trace_printf("trace: resolved executable dir: %s\n",
 */
		prefix = FALLBACK_RUNTIME_PREFIX;
	const char *slash;
	}
	mib[2] = KERN_PROC_PATHNAME;

		strbuf_release(&buf);
 * Resolves the executable path by examining a procfs symlink.
	}
	}

	argv_array_pushv(out, argv);
}
	 * selectively-available or non-authoritative methods.
static int git_get_exec_path_from_argv0(struct strbuf *buf, const char *argv0)

{
#if defined(RUNTIME_PREFIX)
 *
		return error(_("too many args to run %s"), cmd);
 * Returns 0 on success, -1 on failure.
		trace_printf(
		strbuf_addstr(&new_path, _PATH_DEFPATH);

static int git_get_exec_path_darwin(struct strbuf *buf)
	char path[MAXPATHLEN];
}
	return -1;

{
#include <sys/param.h>
	else
/*
	executable_dirname = resolved;
}
}

			break;
	return 0;
int execv_git_cmd(const char **argv)
	}


	/*
}
	}
#include <sys/sysctl.h>
				"but prefix computation failed.  "


		return 0;
 * This is called during initialization, but No work needs to be done here when
	    !(prefix = strip_path_suffix(executable_dirname, BINDIR)) &&



}
	return execv_git_cmd(argv);
	mib[3] = -1;
/*
#endif /* RUNTIME_PREFIX */

	prepare_git_cmd(&nargv, argv);


	size_t cb = sizeof(path);
 */
	if (!_NSGetExecutablePath(path, &size)) {
	 * preferring highly-available authoritative methods over
	slash = find_last_dir_sep(argv0);
			"trace: resolved executable path from sysctl: %s\n",
#if defined(HAVE_NS_GET_EXECUTABLE_PATH)
		else
}
 * 'git_resolve_executable_dir'.
		strbuf_addch(out, PATH_SEP);
	if (slash)
}
static int git_get_exec_path_bsd_sysctl(struct strbuf *buf)
{
void git_resolve_executable_dir(const char *argv0)
			path);
}
#if defined(HAVE_BSD_KERN_PROC_SYSCTL)
{
		trace_printf("RUNTIME_PREFIX requested, "

		return 0;
static const char *executable_dirname;
			"trace: resolved executable path from Darwin stack: %s\n",
const char **prepare_git_cmd(struct argv_array *out, const char **argv)
/*
		git_get_exec_path_wpgmptr(buf) &&
	static const char *prefix;
#include "argv-array.h"

 */
 *
	trace_argv_printf(nargv.argv, "trace: exec:");
	 * Propagate this setting to external programs.
	int len = wcslen(_wpgmptr) * 3 + 1;
	strbuf_grow(buf, len);
	if (
const char *git_exec_path(void)
			     argv0);
	/*
		trace_printf(

		resolved[slash - resolved] = '\0';
	if (slash) {
	git_set_exec_path(exec_path);
 */
 * executable.
	const char *arg;

#ifdef HAVE_WPGMPTR
static int git_get_exec_path_wpgmptr(struct strbuf *buf)


		return -1;
	assert(is_absolute_path(executable_dirname));
static const char *system_prefix(void);
{
		if (!arg)
int execl_git_cmd(const char *cmd, ...)
		return -1;
void setup_path(void)
{
{
#endif /* RUNTIME_PREFIX */
/*
char *system_path(const char *path)
			"trace: could not determine executable path from: %s\n",

	int argc;
	if (strbuf_realpath(buf, PROCFS_EXECUTABLE_PATH, 0)) {

 * When using a runtime prefix, Git dynamically resolves paths relative to its
		trace_printf("trace: could not normalize path: %s\n", buf->buf);
#endif /* HAVE_BSD_KERN_PROC_SYSCTL */

		     executable_dirname);
	 * Identifying the executable path is operating system specific.
	return 0;
	if (len < 0)
{
}
	 * after the first successful method.
	if (path && *path) {
		return;
	struct strbuf new_path = STRBUF_INIT;
#endif
		strbuf_addstr(&new_path, old_path);

	 * better functional method. However, note that argv[0] can be
		strbuf_addstr(buf, path);
		trace_printf(
	argv_array_clear(&nargv);

			path);
 */
#endif /* PROCFS_EXECUTABLE_PATH */
#endif /* HAVE_NS_GET_EXECUTABLE_PATH */
#include "cache.h"
 */
	buf->len += len;
	if (!exec_path_value) {
	if (git_get_exec_path(&buf, argv0)) {
		strbuf_addstr(buf, path);
	 */
	return -1;
static int git_get_exec_path(struct strbuf *buf, const char *argv0)
		git_get_exec_path_bsd_sysctl(buf) &&

}
#ifdef HAVE_BSD_KERN_PROC_SYSCTL
}
}

	va_start(param, cmd);
 * The method for determining the path of the executable is highly
#ifdef PROCFS_EXECUTABLE_PATH

	const char *old_path = getenv("PATH");
}
	return -1;
			exec_path_value = xstrdup(env);
{
}
}

 * runtime prefix is not being used.

#ifdef PROCFS_EXECUTABLE_PATH
#ifdef HAVE_NS_GET_EXECUTABLE_PATH
			"trace: resolved executable path from procfs: %s\n",
static const char *system_prefix(void)
 * Returns 0 on success, -1 on failure.
		trace_printf(
 * Path to the current Git executable. Resolved on startup by
	trace_printf("trace: exec failed: %s\n", strerror(errno));
 *
	add_path(&new_path, exec_path);
	argv_array_push(out, "git");
	if (!prefix &&

	uint32_t size = sizeof(path);
	char path[PATH_MAX];
void git_resolve_executable_dir(const char *argv0)
#ifdef HAVE_WPGMPTR
	strbuf_addf(&d, "%s/%s", system_prefix(), path);
		return 0;
	struct argv_array nargv = ARGV_ARRAY_INIT;
	    !(prefix = strip_path_suffix(executable_dirname, GIT_EXEC_PATH)) &&
	return FALLBACK_RUNTIME_PREFIX;

#endif
static const char *exec_path_value;
	return out->argv;
	    !(prefix = strip_path_suffix(executable_dirname, "git"))) {
#include <mach-o/dyld.h>
	argc = 1;

		return 0;
		arg = argv[argc++] = va_arg(param, char *);

{
{
	return prefix;
	}
	if (!argv0 || !*argv0)
	 *
	argv[0] = cmd;
		return -1;
 * Resolves the absolute path of the current executable.
		strbuf_add_absolute_path(buf, argv0);
#include "quote.h"
			argv0);
#define MAX_ARGS 32
	if (old_path)
	 * in those cases.
 *
 * Returns 0 on success, -1 on failure.
	}


	va_end(param);
	exec_path_value = exec_path;
 *
 *
	return -1;
#ifdef RUNTIME_PREFIX
	/* execvp() can only ever return if it fails */
		strbuf_add_absolute_path(out, path);
	 * All cases fall back on resolving against argv[0] if there isn't a

#endif /* PROCFS_EXECUTABLE_PATH */
				"Using static fallback '%s'.\n", prefix);
	 * Each of these functions returns 0 on success, so evaluation will stop
{
{
 */
#ifdef HAVE_NS_GET_EXECUTABLE_PATH
	const char *argv[MAX_ARGS + 1];
#ifdef HAVE_BSD_KERN_PROC_SYSCTL
/*
		const char *env = getenv(EXEC_PATH_ENVIRONMENT);
 *

	}
		return -1;
	const char *exec_path = git_exec_path();
{
	return strbuf_detach(&d, NULL);
	return exec_path_value;
/**
			buf->buf);
/*
		if (env && *env)



	}
#include "exec-cmd.h"
	argv[argc] = NULL;
static const char *system_prefix(void)
	mib[1] = KERN_PROC;
	strbuf_release(&new_path);
{
		git_get_exec_path_darwin(buf) &&
	trace2_cmd_path(buf->buf);
 */
	resolved = strbuf_detach(&buf, NULL);

 */
}


	if (MAX_ARGS <= argc)
	int mib[4];
		trace_printf("trace: resolved executable path from argv0: %s\n",
	}
	 *
 */
	char *resolved;
		return xstrdup(path);
	setenv(EXEC_PATH_ENVIRONMENT, exec_path, 1);
	mib[0] = CTL_KERN;

	if (is_absolute_path(path))
 * When not using a runtime prefix, Git uses a hard-coded path.



/*
	slash = find_last_dir_sep(resolved);
#include <sys/types.h>
#endif /* HAVE_BSD_KERN_PROC_SYSCTL */

{
 * Resolves the executable path from argv[0], only if it is absolute.
	 */
 * Returns 0 on success, -1 on failure.


/*
}
#endif /* HAVE_WPGMPTR */
 * Returns 0 on success, -1 on failure.
static int git_get_exec_path_procfs(struct strbuf *buf)
	const char *slash;
{
	while (argc < MAX_ARGS) {
 * Resolves the executable path by using the global variable _wpgmptr.
 * Resolves the executable path by querying Darwin application stack.
	setenv("PATH", new_path.buf, 1);
	assert(executable_dirname);
	len = xwcstoutf(buf->buf, _wpgmptr, len);
/* Returns the highest-priority location to look for git programs. */
	if (strbuf_normalize_path(buf)) {
/**
	struct strbuf buf = STRBUF_INIT;

	 * Selectively employ all available methods in order of preference,
 * Returns 0 on success, -1 on failure.
	}
void git_set_exec_path(const char *exec_path)
 * Resolves the executable path using KERN_PROC_PATHNAME BSD sysctl.
	if (!sysctl(mib, 4, path, &cb, NULL, 0)) {
 * platform-specific.
{

			exec_path_value = system_path(GIT_EXEC_PATH);
	return -1;
#endif /* HAVE_WPGMPTR */
	va_list param;
static void add_path(struct strbuf *out, const char *path)
#endif /* HAVE_NS_GET_EXECUTABLE_PATH */
		git_get_exec_path_procfs(buf) &&

	sane_execvp("git", (char **)nargv.argv);
	 * used-supplied on many operating systems, and is not authoritative
		git_get_exec_path_from_argv0(buf, argv0)) {
	struct strbuf d = STRBUF_INIT;

