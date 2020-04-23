 * break this carefully orchestrated machinery.
	int result;

	attr_start();
	trace2_collect_process_info(TRACE2_PROCESS_INFO_STARTUP);
 * programs that ignore or block SIGPIPE for their own reason forget
	signal(SIGPIPE, SIG_DFL);


 *
	 * Always open file descriptors 0/1/2 to avoid clobbering files

	sigemptyset(&unblock);

	 * onto stdin/stdout/stderr in the child processes we spawn.
{
	 * in die().  It also avoids messing up when the pipes are dup'ed
/*
	return result;
	git_setup_gettext();
 * upstream of a pipe to die with SIGPIPE when the downstream of a
	result = cmd_main(argc, argv);
	restore_sigpipe_to_default();
 */
	initialize_the_repository();
}
 * pipe does not need to read all that is written.  Some third-party

#include "attr.h"
	git_resolve_executable_dir(argv[0]);
#include "exec-cmd.h"
static void restore_sigpipe_to_default(void)
	trace2_cmd_start(argv);
	 */
 * to restore SIGPIPE handling to the default before spawning Git and
	sigaddset(&unblock, SIGPIPE);
	trace2_initialize();
	/*
	sigprocmask(SIG_UNBLOCK, &unblock, NULL);

}
	sigset_t unblock;

 * Restore the way SIGPIPE is handled to default, which is what we
 * expect.

	trace2_initialize_clock();

 * Many parts of Git have subprograms communicate via pipe, expect the

	sanitize_stdfds();
int main(int argc, const char **argv)

#include "cache.h"
{

	trace2_cmd_exit(result);
