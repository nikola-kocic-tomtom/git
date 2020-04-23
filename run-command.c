}

		}
	else if (cmd->out > 1)
	set_error_routine(fake_fatal);
	const char *const *p;
				close(cmd->out);
		git_atexit_installed = 1;
}
		/*
		void *data;
	xwrite(child_notifier, &buf, sizeof(buf));
	argv_array_clear(&nargv);
		struct {


			child_die(CHILD_ERR_ENOENT);
		close(fdout[1]);
	extern char **environ;

	for (i = 0; i < pp->max_processes; i++) {
#else
end_of_spawn:
	} *children;
		close(fhout);
 */
 * parent will make it look like the child spewed a fatal error and died

	 */

			break;
	if (sigprocmask(SIG_SETMASK, &as->old, NULL))
		error_errno("cannot spawn %s", cmd->argv[0]);
			break;

{
					 "You can disable this warning with "
	pid_t waiting;
	if (n < 1)

	 * Async-Signal-Safe functions are permitted in the child.
}
		pp_output(&pp);
			goto fail_pipe;
		    pp.nr_processes < pp.max_processes;
	case CHILD_ERR_CLOSE:
#else
	_exit(2);
{

		argv_array_push(out, "-c");
	pp->children[i].state = GIT_CP_WORKING;
	static struct strbuf path = STRBUF_INIT;
		} else if (cmd->err > 1) {
				 pp->data,
			strbuf_reset(&key);
	async->pid = fork();
	 * indicates whether it can be run as an executable, and Git
		null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		 * Attempt to exec using the command and arguments starting at

	pp_init(&pp, n, get_next_task, start_failure, task_finished, pp_cb);
			strbuf_reset(&pp->children[i].err);
{
	if (async->isolate_sigpipe) {
			kill(pp->children[i].process.pid, signo);
	}

			string_list_append(&env, key.buf)->util = (void *) *p;
	return !pthread_equal(main_thread, pthread_self());
			return -1;
	}
		close(fherr);
	fflush(NULL);
	if (proc_in >= 0)
int run_hook_le(const char *const *env, const char *name, ...)
		nr++;
	close(notify_pipe[1]);
{
	}
	kill_children(pp_for_signal, signo);
		else if (cmd->stdout_to_stderr)
				break;
		git_atexit_clear();
static void kill_children(struct parallel_processes *pp, int signo)
	int need_in, need_out, need_err;
	struct strbuf buffered_output; /* of finished children */
			die_errno(_("open /dev/null failed"));
		const char *val = envs.items[i].util;
			       (char *const *) childenv);
	if (!p)
	if (ends_with(name, ".exe"))

	 */

	ret = async->proc(async->proc_in, async->proc_out, async->data);
{
}

		}
		if (is_executable(buf.buf))
		}
		if (pthread_sigmask(SIG_BLOCK, &mask, NULL) < 0) {
			break;
			if (need_in)
	old_errfn = get_error_routine();
			str = "standard input";
		die_errno("poll failed");
			size_t len;
{

static void pp_cleanup(struct parallel_processes *pp)
	int output_owner;
		return code;
		BUG("bookkeeping is hard");
	close(fd[1]);

	 */
		&& cmd->out < 0;
		return -1;
	code = pp->get_next_task(&pp->children[i].process,
 * this is needed to prevent changes to t0061.
	int i, code;
			ssize_t len = strbuf_read_once(io->u.in.buf,
static pthread_key_t async_die_counter;
}

		n = read(fd, buf, 2);
 * execve() or after execvp() to diagnose why it failed.
			strbuf_reset(&pp->buffered_output);
static int pp_collect_finished(struct parallel_processes *pp)
			if (!code)
static void NORETURN async_exit(int code)

#else
		errno = exists_in_PATH(file) ? EACCES : ENOENT;
{

	trace2_child_exit(cmd, ret);
	return run_command(&hook);

	for (i = 0; i < nr; i++) {

	for (i = 0; i < pp->max_processes; i++)
	return 0;

	/*
			    cmd->argv[0], cmd->dir);
		if (errno == ENOEXEC)
	int i, code;
	strbuf_release(&pp->buffered_output);
		set_warn_routine(child_warn_fn);
		}
int run_command_v_opt_cd_env(const char **argv, int opt, const char *dir, const char *const *env)
		if (oldval && !strcmp(val, oldval))
		strbuf_reset(&pp->children[i].err);
	strbuf_reset(&path);

}
			failed_errno = errno;
{

		cmd->argv = cmd->args.argv;
			child_close(cmd->err);
	 * it quite expensive to open many files.
	if (code)
	 * care should be taken with the function calls made in between the
		} else {
#undef atexit
				);
		set_cloexec(notify_pipe[1]);
	int i = pp->output_owner;
}
	return run_command(&cmd);
	clear_child_for_cleanup(pid);


		struct child_process process;
	}
#define CHECK_BUG(err, msg) \
int start_async(struct async *async)


	xwrite(2, msg, sizeof(msg) - 1);
	int i, code;
				close(io->fd);
		close(null_fd);
			if (len < 0)
			if (!string_list_lookup(&advise_given, name)) {
	if (fd >= 0) {
			strbuf_reset(&key);
			BUG("%s: %s", msg, strerror(e)); \
			if (need_in)
};

	 */
	return ret;

		sigset_t mask;
		}
	return 0;
				pp->children[i].state = GIT_CP_WAIT_CLEANUP;
	return 0;
	struct io_pump io[3];
	free(r);

	else if (async->in)
	 * cp->env_array if needed. We only check one place.
			}
	if (async->pid < 0) {
	}
		int err = errno;
error:

	if (in) {
	 * (unless of course the execvp() fails).
		fherr = open("/dev/null", O_RDWR);
			error(_("cannot create async thread: %s"), strerror(err));
		proc_out = fdout[1];
	/*
{
static void NORETURN child_die_fn(const char *err, va_list params)
		proc_out = -1;
{
		 * we catch a signal right before execve below
static int exists_in_PATH(const char *file)
#ifdef NO_PTHREADS
	 * a path lookup and use the resolved path as the command to exec. If
static void git_atexit_dispatch(void)
		}
static void *run_thread(void *data)

	int spawn_cap = 4;
	} else if (waiting != pid) {
	for (i = 0; i < n; i++) {
	int notify_pipe[2];
}
	struct child_to_clean **pp;
{
	else if (cmd->stdout_to_stderr)
#ifndef NO_PTHREADS

	if (!argv[0])
		async->out = fdout[0];
			close_pair(fdin);
{
		return NULL;
		exit(!!async->proc(proc_in, proc_out, async->data));

		    void *data)
	}
	while (1) {
	if (access(path.buf, X_OK) < 0) {
	/* Construct a sorted string list consisting of the current environ */
	p = find_hook(name);
	while (1) {
		set_cloexec(proc_out);
	int null_fd = -1;
}
	pp->data = data;
			error("cannot create %s pipe for %s: %s",

		if (need_out)
{
		main_thread = pthread_self();
 * "foo.exe").

		die_errno("sigfillset");
	else if (cmd->in)
			goto error;
	pp->task_finished = task_finished ? task_finished : default_task_finished;
	if (cmd->no_stdin)
	}
		/* POSIX specifies an empty entry as the current directory. */
	if (need_out)
	}
	cmd.clean_on_exit = opt & RUN_CLEAN_ON_EXIT ? 1 : 0;
		 */
	pp_cleanup(&pp);

	}
{
};
int run_command(struct child_process *cmd)
		pp_cleanup(pp);
{
		children_to_clean = p->next;
		if (code != SIGINT && code != SIGQUIT && code != SIGPIPE)
	int status, code = -1;
}
			code = pp_start_one(&pp);
	 * fork() and exec() calls.  No calls should be made to functions which
						 pp->children[i].process.err, 0);
	}
	async->proc_in = proc_in;
	return 0;
		if (async->proc_out >= 0)

	CHECK_BUG(pthread_sigmask(SIG_SETMASK, &as->old, NULL),
{
	char *str;
	struct atfork_state as;
		break;
}
	int fdin[2], fdout[2];
			child_dup2(cmd->out, 1);
	int result;
			close(cmd->err);
		if (err == EACCES && advice_ignored_hook) {
			argv_array_clear(out);
		 * be used in the event exec failed with ENOEXEC at which point
	pthread_setspecific(async_die_counter, (void *)1);
	 *


		git_atexit_hdlrs.handlers[i-1]();
{
	result = run_processes_parallel(n, get_next_task, start_failure,

	char **childenv;
	for (i = 0; i < envs.nr; i++) {
		}

		return 0;

		set_die_is_recursing_routine(async_die_is_recursing);
			       const char *tr2_category, const char *tr2_label)
		close(cmd->in);
	pthread_exit((void *)(intptr_t)code);

	for (pp = &children_to_clean; *pp; pp = &(*pp)->next) {
	ALLOC_ARRAY(pfd, nr);
		fhout = dup(fherr);
	for (i=git_atexit_hdlrs.nr ; i ; i--)

		 */

				close(cmd->in);
	}

		&& !cmd->stdout_to_stderr
		int err = pthread_create(&async->tid, NULL, run_thread, async);
		strbuf_release(&key);
	string_list_clear(&envs, 0);
	 */
		}
		if (cmd->no_stderr)
	intptr_t ret;

					 pp->children[i].data);
		prepare_git_cmd(out, cmd->argv);

} git_atexit_hdlrs;
	else if (cmd->use_shell)
		return code;
};

	 * the command directly.
			if (need_out)
}

	/*
};
				close(cmd->in);
	childenv[env.nr] = NULL;
#include "quote.h"
	ALLOC_ARRAY(childenv, env.nr + 1);

		"restoring signal mask");
	if (cmd->out < 0 || cmd->err < 0)
	const char *p = getenv("PATH");
		} else {

	return found;
			if (cmd->out > 0)
	pp->output_owner = 0;
{
	return 0;
	 * Note that use of this infrastructure is completely advisory,
	 * has to emulate the execvp() call anyway.
		io[nr].type = POLLOUT;
	else if (need_in)
			}
		pp->children[i].state = GIT_CP_FREE;
	GIT_CP_WORKING,
		sigemptyset(&mask);
		/*
			strbuf_addstr(dst, " unset");

	string_list_clear(&env, 0);
	/* initialized by caller */
		error_errno("waitpid for %s failed", argv0);
	void *data;
			int n = strbuf_read_once(&pp->children[i].err,
		struct child_to_clean *p = children_to_clean;
		cmd->err = fderr[0];


 *
			errno = slots[i].error;


	union {
	struct argv_array argv = ARGV_ARRAY_INIT;
	CHECK_BUG(pthread_setcancelstate(as->cs, NULL),
	switch (cerr->err) {
			goto fail_pipe;
	if (in_signal)
		set_cloexec(proc_in);
#ifndef GIT_WINDOWS_NATIVE

	while ((p = va_arg(args, const char *)))
	return ret != NULL;

		close(async->in);


		nr++;
		error("waitpid is confused (%s)", argv0);


			close(fdout[0]);
			child_process_clear(cmd);
	/*
#include "strbuf.h"
static int child_notifier = -1;
	trace2_region_enter_printf(tr2_category, tr2_label, NULL, "max:%d",
			if (pp->children[i].state == GIT_CP_WAIT_CLEANUP)
	return -1;
	}
/* returns
			if (code < 0) {
	else

	trace_printf("run_processes_parallel: preparing to run up to %d tasks", n);
		error_errno("cannot run %s", cmd->argv[0]);
	sigchain_pop_common();

	int flags = fcntl(fd, F_GETFD);


	/*
		fhin = open("/dev/null", O_RDWR);

#else
}
		code = pp->task_finished(code,
}
	else
struct io_pump {
		/*

{
			child_close(cmd->in);

	xwrite(2, msg, sizeof(msg) - 1);
			return error_errno("cannot create pipe");
	}
		"re-enabling cancellation");

	}

	sigchain_pop(signo);
struct parallel_processes {
		n = online_cpus();

		error_errno("cannot fork() for %s", cmd->argv[0]);
#endif
	if (i == pp->max_processes)
			strbuf_write(&pp->buffered_output, stderr);
	 * never be released in the child process.  This means only
	else if (cmd->clean_on_exit)
		pp->pfd[i].events = POLLIN | POLLHUP;

			strbuf_reset(&pp->children[i].err);
{
	}
			if (len <= 0) {

	return childenv;
			errno = failed_errno;
enum child_errcode {
			strbuf_add(&key, *p, equals - *p);
	/*
		if (cmd->no_stdout)
		BUG("shell command is empty");


{
		 * At this point we know that fork() succeeded, but exec()
		}
	if (pump_io(io, nr) < 0) {
	int ret;
static int git_atexit_installed;
			/*
	return finish_command(cmd);
		code = WTERMSIG(status);

	 * Now that we know it does not have an executable extension,
	    !S_ISREG(st.st_mode))
	else if (cmd->in)

	return path.buf;
{

			if (n == 0) {
			child_dup2(fderr[1], 2);
{
	 * require acquiring a lock (e.g. malloc) as the lock could have been
}

#ifdef STRIP_EXTENSION


#endif
		proc_in = fdin[0];
			close(async->proc_out);
static void child_close_pair(int fd[2])
					"trace: run_command: running exit handler for pid %"
static NORETURN void die_async(const char *err, va_list params)
		return 0; /* cannot happen ;-) */
	}
{
		if (equals) {
			 * For now we pick it randomly by doing a round
	if (!git_atexit_installed) {
		const char *end = strchrnul(p, ':');
	argv_array_clear(&argv);



				string_list_insert(&advise_given, name);
{
		struct io_pump *io = &slots[i];
		process_is_async = 1;
	if (errno == EACCES && !strchr(file, '/'))
	if (!main_thread_set) {
/* this runs in the parent process */

	va_end(args);

	struct strbuf buf = STRBUF_INIT;
	{
		 * called, they can take stdio locks and malloc.
	const char *const *e;
	void *ret = (void *)(intptr_t)(-1);
			async_exit(141);
static void NORETURN async_exit(int code)

	}
				io->error = errno;
{
	cmd.git_cmd = opt & RUN_GIT_CMD ? 1 : 0;
		close(fderr[1]);
}

				advise(_("The '%s' hook was ignored because "
		code += 128;
		oldval = getenv(var);
		const char *equals = strchr(*p, '=');

	for (i = 0; i < nr; i++) {
{
		break;

			child_close(cmd->out);
	 */

	if (fhin != 0)
	exit(code);

			child_close_pair(fdin);
#else
	struct child_err buf;
		const char *var = envs.items[i].string;

		if (equals) {

	argv_array_clear(&child->env_array);
		cmd->err = -1;
			continue;
			strbuf_addbuf(&pp->buffered_output, &pp->children[i].err);
	free(childenv);
	/* Create an array of 'char *' to be used as the childenv */
		else if (cmd->in)
	int i, n = pp->max_processes;
			string_list_append(&env, *p)->util = (void *) *p;
	} else if (cmd->use_shell) {
		strbuf_addf(dst, " %s", var);

	 * lookups in that case.
}
	close(fd[0]);
	trace_run_command(cmd);

	GIT_CP_FREE,
	const char msg[] = "warn() should not be called in child\n";

	struct child_to_clean *p = xmalloc(sizeof(*p));
			if (!strcmp(buf, "#!"))
static int pp_start_one(struct parallel_processes *pp)
	if (need_in)
		struct child_to_clean *clean_me = *pp;
	if (sigfillset(&all))

		 struct strbuf *err, size_t err_hint)
			/* otherwise ('key') remove existing entry */
			 * the most output or the longest or shortest
		if (sigprocmask(SIG_SETMASK, &as.old, NULL) != 0)
	return wait_or_whine(async->pid, "child process", 0);
		if (errno == EINTR)

			close(cmd->out);
		 * This return value is chosen so that code & 0xff
	if (!cmd->pid) {

		close_pair(fdout);
		io[nr].fd = cmd->err;
	}
	return ret;

	for (p = (const char *const *) environ; p && *p; p++) {
			close_pair(fderr);
	if (cmd->pid < 0 && (!cmd->silent_exec_failure || errno != ENOENT))
	buf.syserr = errno;
		fherr = dup(cmd->err);
{
int async_with_fork(void)
 * can be used before fork() to prepare to run a command using
		close(fdout[1]);
	sigset_t all;

		pfd[pollsize].fd = io->fd;
	 * When get_next_task added messages to the buffer in its last
	 * peek into the file instead.

			strbuf_add(&key, *e, equals - *e);
	 * The caller is responsible for initializing cp->env from
	/*
		 * restore default signal handlers here, in case
		struct io_pump *io = &slots[i];

				 void *pp_cb,
	int cs;
	while (pp->nr_processes > 0) {
	CHILD_ERR_SILENT,
	strbuf_git_path(&path, "hooks/%s", name);

}
		io[nr].fd = cmd->in;
	failed_errno = errno;
		close(fd);
		child_process_clear(&pp->children[i].process);
static void child_error_fn(const char *err, va_list params)
	if (cmd->git_cmd)
		close(fhin);
	if (!cmd->env)
		error_errno("fork (async) failed");
	if (!code) {
		error_errno("exec '%s': cd to '%s' failed",
			child_dup2(cmd->in, 0);
		} in;
		sigaddset(&mask, SIGPIPE);
	}
			else if (cmd->in)
	if (!cmd->argv[0])
			child_die(CHILD_ERR_ERRNO);
	cmd.env = env;
			free((char *)out->argv[1]);
				 struct strbuf *out,
			struct strbuf *buf;
	if (!pollsize)
	}
	task_finished_fn task_finished;
{

		} else {
{
				kill_children(&pp, -code);
		pp->nr_processes--;
	do { \
		close(fdin[0]);
		if (!cmd->silent_exec_failure)
		code = pp_collect_finished(&pp);
	pid_t pid;
			str = "standard error";
			       task_finished_fn task_finished, void *pp_cb,

}
	child_close(fd[0]);
		child_notifier = notify_pipe[1];
	children_to_clean = p;
 * execvp would perform, without actually executing the command so it
			} else if (n < 0)

		error("pthread_join failed");
	CHILD_ERR_CLOSE,
			child_dup2(null_fd, 2);
	childenv = prep_childenv(cmd->env);
		}
	_exit(1);
	char **childenv;
	}
			continue;
	if (dup2(fd, to) < 0)
		while (waitpid(p->pid, NULL, 0) < 0 && errno == EINTR)
int finish_async(struct async *async)
enum child_state {
	if (stat(name, &st) || /* stat, not lstat */

	return -1;
}
		const char *var = envs.items[i].string;
	cmd->argv = sargv;
			return;
	struct {

	size_t alloc;
		close(fdin[0]);
		if (!pp.nr_processes)
 * used to store the resultant path.

		if (atexit(&git_atexit_dispatch))
static struct parallel_processes *pp_for_signal;
	if (close(fd))
 * Returns the path to the command, as found in $PATH or NULL if the
		strbuf_addstr(&buf, " git");
	pp->shutdown = 0;
		}
	git_atexit_installed = 0;
		}

	}
				 void *pp_task_cb)
		strbuf_addbuf(&pp->buffered_output, &pp->children[i].err);
int in_async(void)
			child_close_pair(fderr);
}
	 * intuitive.
		break;
		BUG("you need to specify a get_next_task function");
		execve(argv.argv[1], (char *const *) argv.argv + 1,
	}

		}
		pthread_key_create(&async_key, NULL);

	struct strbuf key = STRBUF_INIT;
		}
		strbuf_reset(&pp->children[i].err);
{
	st.st_mode &= ~S_IXUSR;
	close(notify_pipe[0]);
static struct {
{
	argv_array_push(&hook.args, p);
	struct child_process cmd = CHILD_PROCESS_INIT;
					PRIuMAX, (uintmax_t)p->pid
}
	return ret;
struct child_to_clean {
		else if (need_err) {

	int proc_in, proc_out;
static int default_task_finished(int result,
	int i;

	int ret = wait_or_whine(cmd->pid, cmd->argv[0], 1);
		return 0;
			if (code < 0)

{
		failed_errno = errno;
	p->pid = pid;
	 * that have been passed in via ->in and ->out.
	ALLOC_GROW(git_atexit_hdlrs.handlers, git_atexit_hdlrs.nr + 1, git_atexit_hdlrs.alloc);
#endif

				 void *pp_task_cb)
	buf.err = err;
				io->fd = -1;
		 * We assume that the first time that start_async is called

		error("waitpid is confused (%s)", argv0);

				free(p);
		set_cloexec(null_fd);
}
	CHILD_ERR_ERRNO
		}
	trace_printf("run_processes_parallel: done");
	code = start_command(cmd);
	cleanup_children(sig, 1);
		enum child_state state;
}
	}
	if (in_async()) {
	get_next_task_fn get_next_task;
	child_process_clear(cmd);
		error_errno("dup2() in child failed");
{
					 pp->data,
		pp->pfd[i].fd = -1;
static void atfork_parent(struct atfork_state *as)
	struct child_process hook = CHILD_PROCESS_INIT;
			close(async->proc_in);
{
	if (pp->children[i].state == GIT_CP_WORKING &&
/*
	else if (async->out)
		cmd->env = cmd->env_array.argv;

	return run_command_v_opt_cd_env(argv, opt, NULL, NULL);
		if (code)
	}
		finish_command(cmd); /* throw away exit code */
	return 0;
		if (equals) {
	struct child_err cerr;
			child_die(CHILD_ERR_SIGPROCMASK);
	int exec_id = trace2_exec(file, (const char **)argv);
	trace_printf("%s", buf.buf);
}
		BUG("command is empty");
	memset(&git_atexit_hdlrs, 0, sizeof(git_atexit_hdlrs));
static int default_start_failure(struct strbuf *out,
		if (need_err)
		if (end != p) {
				close_pair(fdout);

		if (need_in)
		} else {
		argv_array_push(&hook.args, p);
				close(io->fd);
static void cleanup_children_on_signal(int sig)
	for (p = deltaenv; p && *p; p++) {

	pp->nr_processes = 0;
	void *ret = pthread_getspecific(async_die_counter);
	struct pollfd *pfd;
			error_errno("cannot run %s", cmd->argv[0]);
	enum child_errcode err;
	 * but we need to protect against exists_in_PATH overwriting errno.
}
		fhin = dup(cmd->in);
int run_command_v_opt(const char **argv, int opt)
static void fake_fatal(const char *err, va_list params)
 */
		}
			   task_finished_fn task_finished,
		}
	if (need_in)

static void clear_child_for_cleanup(pid_t pid)

		if (!*end)

			failed_errno = errno;
		if (io->fd < 0)

	if (!async->pid) {
static pthread_t main_thread;
	struct stat st;
	for (i = 0; i < n; i++)
			for (i = 0; i < n; i++)
	if (!main_thread_set)
		if (i == pp->max_processes)
				io->error = errno;
}
	if (cmd->no_stdout)
int run_command_v_opt_cd_env_tr2(const char **argv, int opt, const char *dir,
}
static int pump_io(struct io_pump *slots, int nr)
		goto error;
	hook.stdout_to_stderr = 1;
	} else if (WIFSIGNALED(status)) {
	if (proc_out >= 0)
	argv_array_clear(&child->args);
{

{
		kill(p->pid, sig);


				}
		strbuf_addf(dst, " %s=", var);
	raise(sig);
	 * iteration, the buffered output is non empty.
static int pump_io_round(struct io_pump *slots, int nr, struct pollfd *pfd)

{
	 * what we are about to do and let it leave a hint in the log
			err = errno;
	if (xread(notify_pipe[0], &cerr, sizeof(cerr)) == sizeof(cerr)) {
			continue;
			else if (cmd->out)
	if (!p || !*p)
int pipe_command(struct child_process *cmd,
	const char msg[] = "error() should not be called in child\n";
			if (signal(sig, SIG_DFL) == SIG_IGN)
	}
{
int run_processes_parallel_tr2(int n, get_next_task_fn get_next_task,
			out->argv[1] = program;
			   get_next_task_fn get_next_task,
	}
	 */
			 * robin. Later we may want to pick the one with

	start_failure_fn start_failure;
				close(async->in);
			if (cmd->silent_exec_failure)
				signal(sig, SIG_IGN);

#endif
	if (cmd->git_cmd) {
	static void (*old_errfn)(const char *err, va_list params);
		if (code)
int start_command(struct child_process *cmd)

	} while(0)
			pp.shutdown = 1;
		strbuf_release(&pp->children[i].err);
	/* "unset X Y...;" */
{
{
		}

	free(pp->children);
	exit(128);

		strbuf_addstr(&path, STRIP_EXTENSION);
}
			 * running process time.
	cmd->pid = mingw_spawnvpe(cmd->argv[0], cmd->argv, (char**) cmd->env,
	int type; /* POLLOUT or POLLIN */

 * <0 no new job was started, user wishes to shutdown early. Use negative code
	if (poll(pfd, pollsize, -1) < 0) {
		struct strbuf err;
		if (pipe(fdin) < 0) {
	int fd = open(name, O_RDONLY);
		strbuf_addstr(&buf, file);

		 * we will try to interpret the command using 'sh'.
	cmd.argv = argv;

	}
		pp->pfd[i].fd = -1;
}
#define atexit git_atexit
static void child_err_spew(struct child_process *cmd, struct child_err *cerr)
			errno = ENOENT;
		set_error_routine(child_error_fn);
		strbuf_addbuf(&pp->buffered_output, &pp->children[i].err);
		 * argv.argv[1].  argv.argv[0] contains SHELL_PATH which will
{
	if (start_command(&pp->children[i].process)) {
#endif /* GIT_WINDOWS_NATIVE */
	if (cp->env)
		pthread_key_create(&async_die_counter, NULL);
		int ec = errno;
static struct child_to_clean *children_to_clean;
					task_finished, pp_cb);
		 * failed. Errors have been reported to our stderr.


	struct child_to_clean *children_to_wait_for = NULL;
		sigchain_push_common(cleanup_children_on_signal);
/*
		children_to_wait_for = p->next;
	if (!cmd->argv)
static char *locate_in_PATH(const char *file)

	 *

	 * held by another thread at the time of forking, causing the lock to
		wait_or_whine(cmd->pid, cmd->argv[0], 0);
	}
	if (pipe(notify_pipe))

		close(async->out);
	int ret = wait_or_whine(cmd->pid, cmd->argv[0], 0);
		cmd->out = -1;
}
				close_pair(fdin);
	int fdin[2], fdout[2], fderr[2];
		fhin = dup(fdin[0]);
	 * has special-handling to detect scripts and launch them

	}
	sigset_t old;
		if (pipe(fdout) < 0) {
	xwrite(2, msg, sizeof(msg) - 1);
	if (cmd->no_stdin || cmd->no_stdout || cmd->no_stderr) {
	 */
	fflush(NULL);
void check_pipe(int err)
			child_die(CHILD_ERR_CHDIR);
	 */
{
	 * The reassignment of EACCES to errno looks like a no-op below,
		 * If we have no extra arguments, we do not even need to
	atfork_prepare(&as);

	free(git_atexit_hdlrs.handlers);
			   void *pp_cb)


	}
		fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
		if (clean_me->pid == pid) {
	 * Add SHELL_PATH so in the event exec fails with ENOEXEC we can
	int syserr; /* errno */
		}
		/*
	}
	return 1;
		die_errno("sigprocmask");
		 * a program that died from this signal.
	pp->children[i].process.err = -1;
	if (err) {
		} else if (cmd->in) {
}

		}
				close(pp->children[i].process.err);

		struct async *async = pthread_getspecific(async_key);
}
		for (i = 0; i < pp->max_processes; i++)
	strbuf_release(&key);
		return 0;
	struct pollfd *pfd;
		else if (cmd->err)
}
			if (async->out > 0)
	need_out = !cmd->no_stdout
	int i;
	}
		if (p->process && !in_signal) {
#ifndef GIT_WINDOWS_NATIVE
		}

{
	if (need_in) {
	/* Merge in 'deltaenv' with the current environ */
 * separators.
	raise(signo);
				       path.buf);
static void atfork_prepare(struct atfork_state *as)
			if (len < 0) {
}
		break;

	cmd.stdout_to_stderr = opt & RUN_COMMAND_STDOUT_TO_STDERR ? 1 : 0;
#ifdef NO_PTHREADS
		if (null_fd < 0)
		code = WEXITSTATUS(status);
	 * In case of errors we must keep the promise to close FDs
	strbuf_write(&pp->buffered_output, stderr);
	}
		argv_array_pushv(out, cmd->argv);
		return NULL;
 * Search $PATH for a command.  This emulates the path search that
	pp->pfd = xcalloc(n, sizeof(*pp->pfd));
	case CHILD_ERR_ERRNO:
	case CHILD_ERR_SILENT:


static void child_dup2(int fd, int to)
	int code;
#ifdef NO_PTHREADS

static void pp_output(struct parallel_processes *pp)

#endif

		} else if (cmd->out > 1) {
#endif
#endif
		if (!(io->pfd->revents & (POLLOUT|POLLIN|POLLHUP|POLLERR|POLLNVAL)))
}
		"disabling cancellation");
static int installed_child_cleanup_handler;
			break;
}
{
		io[nr].u.in.hint = err_hint;
		p = end + 1;

	pp->children[i].process.stdout_to_stderr = 1;
		io[nr].type = POLLIN;
		io[nr].u.in.buf = err;
					 "it's not set as executable.\n"
	/*
#else
	if (in)
		if (code < 0)
	cmd.dir = dir;
	for (i = 0; i < env.nr; i++)
		return 0;
	int printed_unset = 0;
		} else {
		close(async->out);
	int i;
		/*
}
		strbuf_addstr(&buf, " cd ");
	pp->start_failure = start_failure ? start_failure : default_start_failure;
	pp->nr_processes++;

	 * careful usability testing (read: analysis of occasional bug

static void pp_buffer_stderr(struct parallel_processes *pp, int output_timeout)
			struct child_process *process = p->process;
	while (children_to_wait_for) {
		io[nr].u.out.len = in_len;
#ifdef NO_PTHREADS
				continue;
	 * The struct pollfd is logically part of *children,
	if (!installed_child_cleanup_handler) {
		argv_array_push(out, SHELL_PATH);
	GIT_CP_WAIT_CLEANUP,
#include "cache.h"
	p->process = process;
		if (errno == ENOENT) {
}
	int need_in, need_out;
	return run_command_v_opt_cd_env_tr2(argv, opt, NULL, NULL, tr2_class);
			argv_array_pushf(out, "%s \"$@\"", argv[0]);
		if (access(path.buf, X_OK) >= 0)
#endif

			execve(argv.argv[0], (char *const *) argv.argv,
	if (need_out) {
}

		for (i = 0;
	struct argv_array nargv = ARGV_ARRAY_INIT;
		 struct strbuf *out, size_t out_hint,
				child_die(CHILD_ERR_SILENT);
#endif
		    start_failure_fn start_failure,
}
{
	 * through the indicated script interpreter. We test for the
		code = finish_command(&pp->children[i].process);
 * are more complicated (e.g., a search for "foo" should find
		 * Ensure the default die/error/warn routines do not get
	cmd.use_shell = opt & RUN_USING_SHELL ? 1 : 0;
}
	for (i = 0; i < envs.nr; i++) {
	void (**handlers)(void);
		strbuf_addch(dst, ';');
					     io->u.out.buf, io->u.out.len);
		}
	/* Flush stdio before fork() to avoid cloning buffers */
		atexit(cleanup_children_on_exit);
	else if (cmd->err)
		const char *val = envs.items[i].util;
	int output_timeout = 100;
	/* ... followed by "A=B C=D ..." */
	return 1;
	/*
		else
			       start_failure_fn start_failure,
		return 0; /* no asyncs started yet */

		if (!printed_unset) {
	if (need_err) {
			/* ('key=value'), insert or replace entry */
			close_pair(fdout);
{
		BUG("run_command with a pipe can cause deadlock");
	if (need_in)
	if (fhout != 1)
		if (slots[i].error) {
	const char *p;
			/* ignored signals get reset to SIG_DFL on execve */
		fhout = dup(cmd->out);
	pp_for_signal = pp;
	git_atexit_hdlrs.handlers[git_atexit_hdlrs.nr++] = handler;

			p->next = children_to_wait_for;
	if (!get_next_task)

	case CHILD_ERR_ENOENT:

}
	while ((waiting = waitpid(pid, &status, 0)) < 0 && errno == EINTR)
			child_close_pair(fdout);
		if (err) {
	else if (errno == ENOTDIR && !strchr(file, '/'))
	cmd->pid = fork();
}
 * The caller should ensure that file contains no directory
	child_close(fd[1]);
			/* look for a she-bang */
}
			ssize_t len = xwrite(io->fd,
	}

	else if (cmd->err > 2)


	unsigned shutdown : 1;
static void trace_add_env(struct strbuf *dst, const char *const *deltaenv)
	if (cmd->no_stderr)
				if (errno != EAGAIN)

		} else {
		if (io->type == POLLOUT) {


static int prepare_cmd(struct argv_array *out, const struct child_process *cmd)


#endif

				 const char *const *env, const char *tr2_class)
}
#endif
				   ((n < 1) ? online_cpus() : n));
static void git_atexit_clear(void)
		errno = failed_errno;

				 &pp->children[i].err,
	else if (need_err)
{
};
	strbuf_init(&pp->buffered_output, 0);
	int fhin = 0, fhout = 1, fherr = 2;
		failed_errno = errno;
static void pp_init(struct parallel_processes *pp,

		if (need_in)


int run_command_v_opt_tr2(const char **argv, int opt, const char *tr2_class)
{
	return finish_command(cmd);
	else if (async->in)
static int process_is_async;
	int fd;
		cmd->pid = -1;
	return NULL;
		proc_in = -1;
	}
		break;
	case CHILD_ERR_SIGPROCMASK:
			break;
	trace2_child_exit(cmd, ret);
					 &pp->children[i].err, pp->data,
#endif
	pp->get_next_task = get_next_task;


		child_process_clear(cmd);
	}

				 void *pp_cb,
		}
	else if (cmd->out)
			; /* spin waiting for process exit or error */
		       (char *const *) childenv);
		 * it is from the main thread.
	CHILD_ERR_CHDIR,
		if (pp->children[i].state == GIT_CP_WORKING &&
	if (cmd->clean_on_exit && cmd->pid >= 0)


		}
}
	async->proc_out = proc_out;
		error_errno("cannot exec '%s'", cmd->argv[0]);
	vreportf("fatal: ", err, params);

		io[nr].type = POLLIN;
	while (pump_io_round(slots, nr, pfd))
}
		else if (cmd->out)
		if (!val)

	if (null_fd >= 0)
		trace_add_env(&buf, cp->env);
	int i;
		if (pipe(fderr) < 0) {
	if (need_in)

		io[nr].u.out.buf = in;
 *

{
	}

}
		const char *equals = strchr(*p, '=');

	struct child_process *process;
		trace2_exec_result(exec_id, ec);
	int failed_errno;
			str = "standard output";
		if (cmd->no_stdin)
		if (pipe(fdout) < 0) {

	set_error_routine(old_errfn);
		fhout = dup(fdout[1]);
	if (printed_unset)
				str, cmd->argv[0], strerror(failed_errno));
			string_list_insert(&envs, *e)->util = NULL;
	if (cmd->pid < 0) {
			error("%s died of signal %d", argv0, code);
		else if (need_in) {
		}
		prepare_shell_cmd(out, cmd->argv);
	pp->children = xcalloc(n, sizeof(*pp->children));
	}
	 * we skip this for Windows because the compat layer already
			return error_errno("cannot create pipe");

	CHECK_BUG(pthread_sigmask(SIG_SETMASK, &all, &as->old),
	return result;
			/* Output all other finished child processes */
{

{
			}
{
				pp.shutdown = 1;
	return (void *)ret;
struct child_err {
		strbuf_reset(&pp->children[i].err);
	else if (async->out)
static int async_die_is_recursing(void)
		return 1;
	if (out) {
	free(pp->pfd);
	 * file extension first because virus scanners may make
{

		    get_next_task_fn get_next_task,

	if (flags >= 0)
		if (async->proc_in >= 0)
	CHECK_BUG(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &as->cs),
		strbuf_init(&pp->children[i].err, 0);
		 const char *in, size_t in_len,

	int found = r != NULL;
		child_process_init(&pp->children[i].process);
	 */
		async->in = fdin[1];
			continue;
	}
		}
		 */
		raise(SIGPIPE);
{
			const char *buf;

		int e = (err); \
	const char **sargv = cmd->argv;
		 */
	} else if (WIFEXITED(status)) {
#include "thread-utils.h"
	 * failed), EOF is seen immediately by the parent. Otherwise, the
	int result = 0;
	argv_array_pushv(out, argv);
				close(async->out);
	atfork_parent(&as);
			} else {
		io[nr].fd = cmd->out;

{
	}
	 * therefore, we keep error checks minimal.
{
	strbuf_release(&buf);
	if (pthread_join(async->tid, &ret))
	}
			argv_array_push(out, argv[0]);
		notify_pipe[0] = notify_pipe[1] = -1;
	int pollsize = 0;
	if (need_out)
#include "string-list.h"

			printed_unset = 1;
{
}
		    int n,
		set_die_routine(die_async);
			return strbuf_detach(&buf, NULL);
	int nr_processes;
	for (e = deltaenv; e && *e; e++) {
	/* internal use */
 */
static inline void set_cloexec(int fd)
		pp_buffer_stderr(&pp, output_timeout);
}

	 * there are dir separator characters, we have exec attempt to invoke
	sq_quote_argv_pretty(&buf, cp->argv);
		die_errno("sigprocmask");
	else if (async->out)
	cmd.no_stdin = opt & RUN_COMMAND_NO_STDIN ? 1 : 0;


				if (!io->u.out.len) {
	if (fherr != 2)
			child_dup2(fdin[0], 0);
void child_process_init(struct child_process *child)
	if (need_out)

		child_process_init(&pp->children[i].process);

	 */
			cmd->dir, fhin, fhout, fherr);
		fhout = open("/dev/null", O_RDWR);
	vreportf("fatal: ", err, params);
	while (children_to_clean) {
			if (need_in)
	size_t nr;
		if (in_async())

#else

#include "run-command.h"
		; /* nothing */
{
		;	/* nothing */
static char **prep_childenv(const char *const *deltaenv)


	 * child process sends a child_err struct.
		if (cmd->dir && chdir(cmd->dir))
	int max_processes;
	free(pfd);
}
		close_pair(fdin);

		close(cmd->out);
			child_dup2(cmd->err, 2);
	failed_errno = errno;
	CHILD_ERR_DUP2,
		io->pfd = &pfd[pollsize++];
fail_pipe:

	int n;
	if (err)
		errno = ec;
static void child_die(enum child_errcode err)
	if (cp->git_cmd)
	/* There may be multiple errno values, so just pick the first. */
				io->u.out.buf += len;
}
	sigchain_pop(sig);
{
	return (int)(intptr_t)ret;
		close(cmd->err);
			string_list_insert(&env, key.buf)->util = (void *) *p;
	if (!has_dir_sep(out->argv[1])) {
	struct strbuf buf = STRBUF_INIT;
	 * On Windows there is no executable bit. The file extension
	struct string_list envs = STRING_LIST_INIT_DUP;
			static struct string_list advise_given = STRING_LIST_INIT_DUP;
{

	 * listed in $PATH is unsearchable, execvp reports EACCES, but
		failed_errno = errno;
			children_to_wait_for = p;
		set_die_routine(child_die_fn);
#ifndef GIT_WINDOWS_NATIVE
				process->clean_on_exit_handler(process);
}
	mark_child_for_cleanup(async->pid, NULL);
	if (err == EPIPE) {
		 * bother with the "$@" magic.
	if (start_command(cmd) < 0)

static void handle_children_on_signal(int signo)
		} else {
				kill_children(&pp, -code);
	/* write(2) on buf smaller than PIPE_BUF (min 512) is atomic: */
{
	hook.env = env;
		child_err_spew(cmd, &cerr);
		nr++;
		if (errno == EACCES)
		child_die(CHILD_ERR_DUP2);
	cleanup_children(SIGTERM, 0);
}
{
}
	struct parallel_processes pp;

	while ((i = poll(pp->pfd, pp->max_processes, output_timeout)) < 0) {
#endif

 * command could not be found.  The caller inherits ownership of the memory
	return process_is_async;
{
			}

	struct string_list env = STRING_LIST_INIT_DUP;

{
}
	}
			 */
	strbuf_release(&buf);
	if (strcspn(argv[0], "|&;<>()$`\\\"' \t\n*?[#~=%") != strlen(argv[0])) {
			continue;
	 * Wait for child's exec. If the exec succeeds (or if fork()
}
	if (!trace_want(&trace_default_key))
int finish_command_in_signal(struct child_process *cmd)
	return 0;
	ret = run_hook_ve(env, name, args);
	for (i = 0; i < nr; i++) {
	 * We avoid commands with "/", because execvp will not do $PATH
			result = code;
	return 0;
	}
			   start_failure_fn start_failure,
{

#ifndef GIT_WINDOWS_NATIVE
}
		if (n == 2)
	int failed_errno = 0;
			child_dup2(null_fd, 0);
 *    to signal the children.
				close_pair(fdin);
		code = pp->start_failure(&pp->children[i].err,
};
	need_err = !cmd->no_stderr && cmd->err < 0;
	string_list_sort(&env);
}
	argv_array_push(out, SHELL_PATH);
			pp->shutdown = 1;
		if (need_out)
			if (!in_signal)
	return code;
}
void child_process_clear(struct child_process *child)
		if (code) {



		else if (need_out) {
	size_t i;
			return (void *)ret;
	for (i = 0; i < pp->max_processes; i++) {
	const char msg[] = "die() should not be called in child\n";
		sq_quote_buf_pretty(dst, val);
	cmd.trace2_child_class = tr2_class;
	}
	else if (need_out)
		if (program) {
{
			strbuf_addch(&buf, '/');
					die_errno("read");


	/*

				io->u.out.len -= len;
	argv_array_init(&child->env_array);
		}
	if (cp->dir) {

			failed_errno = errno;
int run_hook_ve(const char *const *env, const char *name, va_list args)
static void cleanup_children(int sig, int in_signal)
	pp->pfd[i].fd = pp->children[i].process.err;

	if (need_in) {
static int main_thread_set;
	va_start(args, name);

	struct async *async = data;
#if defined(GIT_WINDOWS_NATIVE)
static void child_warn_fn(const char *err, va_list params)
	p->next = children_to_clean;
}
			 * Pick next process to output live.
		if (e) \
 *  1 if no new jobs was started (get_next_task ran out of work, non critical
	 * When a command can't be found because one of the directories
	CHILD_ERR_ENOENT,
}
			string_list_insert(&envs, key.buf)->util = equals + 1;
		signal(SIGPIPE, SIG_DFL);
		return S_IXUSR;
		if (pp->children[i].state == GIT_CP_FREE)
	 * attempt to interpret the command with 'sh'.
int in_async(void)
		goto end_of_spawn;
			free(p);
		struct {
	/* Last one wins, see run-command.c:prep_childenv() for context */

			break;

	int n = pp->max_processes;
			return -1;
}
	if (out)

	 */
		cmd->argv = prepare_git_cmd(&nargv, cmd->argv);
				 &pp->children[i].data);
		if (pipe(fdin) < 0) {
	/*
		mark_child_for_cleanup(cmd->pid, cmd);
	struct pollfd *pfd;

		return -1;
				close(cmd->out);
		struct child_to_clean *p = children_to_wait_for;
		strbuf_write(&pp->children[i].err, stderr);
	return 0;
static void cleanup_children_on_exit(void)
		if (!argv[1])
 *    problem with starting a new command)
			return 1;
			*pp = clean_me->next;
#else
{
	struct child_to_clean *next;

	need_out = async->out < 0;

		} out;
			strbuf_write(&pp->children[i].err, stderr);
			close(fdin[1]);
	int error; /* 0 for success, otherwise errno */
			continue;
		char *program = locate_in_PATH(out->argv[1]);
			return -1;
	if (prepare_cmd(&argv, cmd) < 0) {
		cmd->out = fdout[0];
	case CHILD_ERR_DUP2:
const char *find_hook(const char *name)
}

};
		cmd->argv = prepare_shell_cmd(&nargv, cmd->argv);
		    i++) {
int finish_command(struct child_process *cmd)

		cmd->in = fdin[1];
	char buf[3] = { 0 };
		if (io->fd < 0)
	if (need_err)

	/*
			else if (cmd->in)
		proc_out = async->out;
	pp->max_processes = n;
		/* Should never happen, but just in case... */
			}
		for (sig = 1; sig < NSIG; sig++) {

			ret = error("unable to block SIGPIPE in async thread");
		io[nr].u.in.buf = out;
		mark_child_for_cleanup(cmd->pid, cmd);
	int nr = 0;
		pfd[pollsize].events = io->type;
				st.st_mode |= S_IXUSR;
 *  0 if a new task was started.
static int wait_or_whine(pid_t pid, const char *argv0, int in_signal)
{
#include "argv-array.h"
			free(clean_me);
	if (need_out) {
{

	int i;
			 * NEEDSWORK:
#ifndef GIT_WINDOWS_NATIVE
	/* returned by pump_io */
	}
	case CHILD_ERR_CHDIR:

		return -1;
struct atfork_state {

int is_executable(const char *name)
	} else {
		close(notify_pipe[0]);
		proc_in = async->in;
	int i;
				if (pp->children[(pp->output_owner + i) % n].state == GIT_CP_WORKING)

	cmd.silent_exec_failure = opt & RUN_SILENT_EXEC_FAILURE ? 1 : 0;
	/* Buffer output from all pipes. */
#ifdef NO_PTHREADS
	if (sigprocmask(SIG_SETMASK, &all, &as->old))
		 */
			return path.buf;
	pp->children[i].process.no_stdin = 1;
		 */
	errno = failed_errno;

		}
static const char **prepare_shell_cmd(struct argv_array *out, const char **argv)
			strbuf_add(&key, *p, equals - *p);
	return st.st_mode & S_IXUSR;
						       io->fd, io->u.in.hint);
	argv_array_init(&child->args);
	if (cmd->pid < 0)
	{
#include "sigchain.h"
		exit(141);

	int i;
	if (waiting < 0) {
		fherr = dup(fderr[1]);
					 pp->children[i].data);
			string_list_remove(&env, *p, 0);
		if (p->process && p->process->wait_after_clean) {
				close_pair(fdin);
					break;
		/*
	trace2_region_leave(tr2_category, tr2_label, NULL);

}
					close(io->fd);
	} u;
	pthread_setspecific(async_key, async);

static void mark_child_for_cleanup(pid_t pid, struct child_process *process)
 *
		installed_child_cleanup_handler = 1;
}

	need_in = async->in < 0;

	 * execvp() doesn't return, so we all we can do is tell trace2
			close(cmd->in);
		pthread_exit((void *)128);
		error_errno("close() in child failed");
		errno = ENOENT;
int run_processes_parallel(int n,

{
	    pp->children[i].err.len) {
			child_dup2(null_fd, 1);
			continue;
	trace2_child_start(cmd);
		trace2_child_exit(cmd, -1);
static void trace_run_command(const struct child_process *cp)
	}
	}
		cmd->pid = -1;
		error_errno("sigprocmask failed restoring signals");
int git_atexit(void (*handler)(void))
	 * If there are no dir separator characters in the command then perform
	return out->argv;
			size_t hint;
	strbuf_addstr(&buf, "trace: run_command:");
	va_list args;

static inline void close_pair(int fd[2])
	hook.no_stdin = 1;
		childenv[i] = env.items[i].util;
		strbuf_addch(&buf, ';');
	else if (async->in)
	 * NOTE: In order to prevent deadlocking when using threads special
		if (errno == EINTR)
		cmd->in = -1;
		"blocking all signals");
}
		 */
		char *equals = strchr(*e, '=');


	return 0;


		/*
	if (need_out)
	sigchain_push_common(handle_children_on_signal);

	}
		sq_quote_buf_pretty(&buf, cp->dir);
}
	need_in = !cmd->no_stdin && cmd->in < 0;

		if (!in_signal)
			child_dup2(fdout[1], 1);
static pthread_key_t async_key;
	if (!execvp(file, argv))
		child_die(CHILD_ERR_CLOSE);
	char *r = locate_in_PATH(file);
		if (pp->children[i].state == GIT_CP_WORKING)
		const char *oldval;
			pp->output_owner = (pp->output_owner + i) % n;

		return;
		if (val || !getenv(var))

	return result;
	}
		argv_array_push(out, "sh");
	} else {
			if (process->clean_on_exit_handler) {
	}
		break;

			return -1;

		 * mimics the exit code that a POSIX shell would report for
		strbuf_reset(&buf);
		struct strbuf key = STRBUF_INIT;
#ifndef NO_PTHREADS
		die_errno("poll");
int sane_execvp(const char *file, char * const argv[])
	}
	 *
	return run_command_v_opt_cd_env_tr2(argv, opt, dir, env, NULL);
{
	hook.trace2_hook_name = name;


		if (io->type == POLLIN) {

#include "exec-cmd.h"
static void child_close(int fd)
			strbuf_add(&buf, p, end - p);
{
				io->fd = -1;
}
	 * but the system call expects it as its own array.
			else if (async->in)
		    task_finished_fn task_finished,
		io[nr].u.in.hint = out_hint;
 * This should not be used on Windows, where the $PATH search rules
	}
		break;
}
			child_dup2(2, 1);


	CHILD_ERR_SIGPROCMASK,
		main_thread_set = 1;
					 "`git config advice.ignoredHook false`."),
	errno = cerr->syserr;
	for (i = 0; i < nr; i++)
		int sig;

}
		close(async->in);
				trace_printf(
		if (i != pp->output_owner) {
		slots[i].error = 0;
					io->fd = -1;
	}
}
		    i < spawn_cap && !pp.shutdown &&
		}
	memset(child, 0, sizeof(*child));
	 * reports) reveals that "No such file or directory" is more
		    pp->pfd[i].revents & (POLLIN | POLLHUP)) {
