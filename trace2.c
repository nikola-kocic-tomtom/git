	int j;
		if (tgt_j->pfn_init())
			tgt_j->pfn_atexit(us_elapsed_absolute,
					      "thread-proc on main: %s",
						  us_elapsed_absolute,
		return;
	uint64_t us_elapsed_absolute;
			 const struct json_writer *value)
					   code);
	 * We expect each target function to treat 'ap' as constant
		if (tgt_j->pfn_child_start_fl)
 * Our atexit routine should run after everything has finished.
	cmd->trace2_child_us_start = us_now;

	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
	uint64_t us_now;
#include "trace2/tr2_cmd_name.h"
	int sum = 0;
	sigchain_push(SIGPIPE, tr2main_signal_handler);

				      const char *category, const char *label,

	int j;
					   exec_id, exe, argv);
}

static void tr2_tgt_disable_builtins(void)

		trace2_region_enter_printf_fl(file, line, NULL, NULL, NULL,
/*
int trace2_cmd_exit_fl(const char *file, int line, int code)

	 */
 * the TR2 and TLS machinery.
#include "trace2/tr2_sysenv.h"

	struct tr2_tgt *tgt_j;

	uint64_t us_now;

	 * the trace output if someone calls die(), for example.
	if (!trace2_enabled)
		if (tgt_j->pfn_printf_va_fl)


	for_each_builtin(j, tgt_j)                   \

static int tr2_tgt_want_builtins(void)
 * Return the number of builtin targets enabled.
	if (!trace2_enabled)

	 */
	tr2tls_pop_unwind_self();
				const struct repository *repo, const char *fmt,
	int j;
#endif
		 * are built with threading disabled), we need to allow it.
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
	for_each_wanted_builtin (j, tgt_j)
		if (tgt_j->pfn_exec_result_fl)

	for_each_wanted_builtin (j, tgt_j)

#include "version.h"

	uint64_t us_elapsed_absolute;
	tr2tls_start_process_clock();
			tgt_j->pfn_repo_fl(file, line, repo);
	/*
						 us_elapsed_absolute,
			tgt_j->pfn_version_fl(file, line);
	us_now = getnanotime() / 1000;
	struct tr2_tgt *tgt_j;
	strbuf_addf(&buf_string, "%" PRIdMAX, value);
	tr2_cmd_name_release();


		return;
	struct tr2_tgt *tgt_j;
void trace2_cmd_mode_fl(const char *file, int line, const char *mode)

		 * main thread also runs the thread-proc function (or when we


	cmd->trace2_child_id = tr2tls_locked_increment(&tr2_next_child_id);
	for_each_wanted_builtin (j, tgt_j)
void trace2_region_leave_printf_va_fl(const char *file, int line,

			tgt_j->pfn_alias_fl(file, line, alias, argv);

#define for_each_wanted_builtin(j, tgt_j)            \
}
#include "trace2/tr2_tgt.h"
	int j;

	uint64_t us_elapsed_region;

				   const char *fmt, ...)
			tgt_j->pfn_thread_start_fl(file, line,

	uint64_t us_elapsed_absolute;



int trace2_is_enabled(void)
			tgt_j->pfn_data_json_fl(file, line, us_elapsed_absolute,
}
{

	/*
	 * and use va_copy.
	if (!trace2_enabled)
		 * correct.
static int tr2_next_child_id; /* modify under lock */
 * actual TRACE2 event call) so we can see if we need to setup
	uint64_t us_elapsed_absolute;
void trace2_cmd_start_fl(const char *file, int line, const char **argv)
{
	 * We expect each target function to treat 'ap' as constant
void trace2_printf_fl(const char *file, int line, const char *fmt, ...)
	struct tr2_tgt *tgt_j;
}
					 ap);
void trace2_cmd_error_va_fl(const char *file, int line, const char *fmt,
{
		if (tgt_j->pfn_command_mode_fl)
	struct tr2_tgt *tgt_j;
		if (tgt_j->pfn_thread_start_fl)


}
		return;


{
	for_each_wanted_builtin (j, tgt_j)
			tgt_j->pfn_start_fl(file, line, us_elapsed_absolute,
				const struct repository *repo, const char *fmt,
	tr2tls_pop_unwind_self();
	tr2_cmd_name_append_hierarchy(name);
		if (tgt_j->pfn_repo_fl)

{
/*
	if (cmd->trace2_child_us_start)
		/*
}
void trace2_data_string_fl(const char *file, int line, const char *category,
				file, line, us_elapsed_absolute, exec_id, code);
 * the pipes).
		 * Convert this call to a region-enter so the nesting looks
	uint64_t us_elapsed_absolute;
		 * those cases where the main thread also runs the

	if (!trace2_enabled)
		if (tgt_j->pfn_command_name_fl)
			    const char *label, const struct repository *repo, ...)
	return trace2_enabled;
	tr2_cfg_set_fl(file, line, key, value);
{
	us_now = getnanotime() / 1000;

	va_end(ap);
		if (tgt_j->pfn_param_fl)
		if (tgt_j->pfn_thread_exit_fl)
		 *

void trace2_cmd_alias_fl(const char *file, int line, const char *alias,
void trace2_def_param_fl(const char *file, int line, const char *param,
	for_each_wanted_builtin (j, tgt_j)
		 * thread-proc, so this is technically a bug.  But in
		return;
{

void trace2_cmd_path_fl(const char *file, int line, const char *pathname)
	}
	if (!trace2_enabled)
			tgt_j->pfn_exec_result_fl(
			tgt_j->pfn_region_leave_printf_va_fl(

void trace2_printf(const char *fmt, ...)
	for_each_wanted_builtin (j, tgt_j)
{
	trace2_collect_process_info(TRACE2_PROCESS_INFO_EXIT);

						  us_elapsed_absolute, cmd);
	for_each_wanted_builtin (j, tgt_j)
	us_elapsed_region = tr2tls_region_elasped_self(us_now);
	for_each_wanted_builtin (j, tgt_j)
	 * Clear any unbalanced regions and then get the relative time
	for (j = 0, tgt_j = tr2_tgt_builtins[j];	\
	/*
#include "trace2/tr2_dst.h"
{
	for_each_wanted_builtin (j, tgt_j)

	&tr2_tgt_event,

		 * thread-proc function (or when we are built with
	for_each_wanted_builtin (j, tgt_j)
	if (!trace2_enabled)
	 */

	struct tr2_tgt *tgt_j;
				   const struct repository *repo,
	}
		return;
	va_end(ap);

		return;
	int j;
		return;
	 * (indentation) level and then push a new level.
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
	int j;

	va_end(ap);
 * enabled or disabled.  Each TRACE2 API method will try to write an event to


{
	tr2_sid_get();
/* clang-format off */

	uint64_t us_now;
	tr2tls_push_self(us_now);
	/*
{
	int j;
static void tr2main_atexit_handler(void)
	for_each_wanted_builtin (j, tgt_j)
 * builtin TRACE2 targets at startup (and before we've seen an
#include "trace2/tr2_sid.h"
{
	&tr2_tgt_normal,
}
				...)
#endif
	us_now = getnanotime() / 1000;
	&tr2_tgt_perf,
	if (trace2_enabled)
	return exec_id;
		trace2_region_leave_printf_fl(file, line, NULL, NULL, NULL,
/* clang-format off */

	for_each_wanted_builtin (j, tgt_j)
				file, line, us_elapsed_absolute, category,
void trace2_exec_result_fl(const char *file, int line, int exec_id, int code)
{
	tr2tls_release();

{
					   us_elapsed_region, category, repo,
void trace2_cmd_name_fl(const char *file, int line, const char *name)
		   const char **argv)
		return;
static int trace2_enabled;

	 * does not appear nested.  This improves the appearance of
void trace2_initialize_fl(const char *file, int line)

	uint64_t us_now;
{
/* clang-format on */
	raise(signo);
{
	for_each_wanted_builtin (j, tgt_j)
		return;

			tgt_j->pfn_command_path_fl(file, line, pathname);
}
	/*
				      const struct repository *repo,
	uint64_t us_elapsed_region;
{

}
		return code;
						us_elapsed_region, category,
 * and then close the fd.
	else

	code &= 0xff;


	NULL
	int j;
void trace2_printf_va_fl(const char *file, int line, const char *fmt,
		return;
	trace2_printf_va_fl(file, line, fmt, ap);

}


	struct tr2_tgt *tgt_j;
{
	if (!trace2_enabled)
void trace2_cmd_list_env_vars_fl(const char *file, int line)

	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
	uint64_t us_elapsed_absolute;

				   const struct repository *repo,
	uint64_t us_now;
#include "sigchain.h"
			   const struct repository *repo, const char *key,
	for_each_builtin (j, tgt_j)
	uint64_t us_now;
	tr2_sid_release();
void trace2_region_enter_printf(const char *category, const char *label,
	if (!trace2_enabled)

				file, line, us_elapsed_absolute,


	for_each_builtin (j, tgt_j)
	struct tr2_tgt *tgt_j;
		if (tgt_j->pfn_region_leave_printf_va_fl)
		return;
{
	return code;
	int j;
			tgt_j->pfn_command_mode_fl(file, line, mode);
void trace2_child_start_fl(const char *file, int line,
}
			sum++;
		if (tr2_dst_trace_want(tgt_j->pdst))
		us_elapsed_child = us_now - cmd->trace2_child_us_start;
		if (tgt_j->pfn_exit_fl)

				   const char *fmt, ...)
		 * Convert this call to a region-leave so the nesting
	int j;
	us_now = getnanotime() / 1000;


		 * threading disabled), we need to allow it.
				      const char *fmt, va_list ap)
{
	if (!trace2_enabled)
						 cmd->trace2_child_id, cmd->pid,
{
	uint64_t us_elapsed_region;
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
		return;
	hierarchy = tr2_cmd_name_get_hierarchy();
				...)
			 va_list ap)
	va_end(ap);
	uint64_t us_elapsed_thread;
{
	int j;
	us_elapsed_region = tr2tls_region_elasped_self(us_now);
}
	int j;
	tr2_list_env_vars_fl(file, line);

	if (!trace2_enabled)
	if (!tr2_tgt_want_builtins())
	 */
	us_now = getnanotime() / 1000;
	struct tr2_tgt *tgt_j;
	va_end(ap);
		if (tgt_j->pfn_data_json_fl)
	struct tr2_tgt *tgt_j;
	struct tr2_tgt *tgt_j;

		return;
{
	uint64_t us_elapsed_absolute;
{

void trace2_region_leave_printf(const char *category, const char *label,
void trace2_region_enter_printf_fl(const char *file, int line,
	 */
	us_now = getnanotime() / 1000;

				label, repo, fmt, ap);

	us_now = getnanotime() / 1000;

	tr2tls_create_self(thread_name, us_now);
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);

static void tr2main_signal_handler(int signo)

void trace2_thread_exit_fl(const char *file, int line)
		return;
{
	va_list ap;
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
	repo->trace2_repo_id = tr2tls_locked_increment(&tr2_next_repo_id);


	uint64_t us_now;
#include "trace2/tr2_tls.h"
 */
void trace2_data_intmax_fl(const char *file, int line, const char *category,
		if (tgt_j->pfn_region_enter_printf_va_fl)
		return;
}
{
 * we are writing to fd 1 or 2 and our atexit routine runs after
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
					 ap);
	us_now = getnanotime() / 1000;
}
		return;
	struct tr2_tgt *tgt_j;
static int tr2_next_repo_id = 1; /* modify under lock. zero is reserved */
		tgt_j->pfn_term();
				   const char *category, const char *label,
	struct tr2_tgt *tgt_j;
				   const char *category, const char *label,

			tgt_j->pfn_exit_fl(file, line, us_elapsed_absolute,
/*
			   const struct repository *repo, const char *key,
			   intmax_t value)
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
{

	tr2tls_pop_self();
{


			tgt_j->pfn_child_exit_fl(file, line,

#define for_each_builtin(j, tgt_j)			\
		return;

	for_each_wanted_builtin (j, tgt_j)
						fmt, ap);


#ifndef HAVE_VARIADIC_MACROS

			   const char *value)
	struct tr2_tgt *tgt_j;
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);

#endif
	tr2_cfg_list_config_fl(file, line);
	int j;
	us_elapsed_thread = tr2tls_region_elasped_self(us_now);
{
	if (!trace2_enabled)
	trace2_enabled = 1;
		if (tgt_j->pfn_signal)
	sigchain_pop(signo);
}
			tgt_j->pfn_exec_fl(file, line, us_elapsed_absolute,
	/*
}
	int j;

	struct tr2_tgt *tgt_j;

	struct tr2_tgt *tgt_j;
	trace2_enabled = 0;
			      const char *value)

#include "cache.h"
	tr2_sysenv_release();
{
	if (!trace2_enabled)
			    const char *label, const struct repository *repo, ...)
	for_each_wanted_builtin (j, tgt_j)
	int j;
	va_list ap;
	/*
					 ap);
	trace2_region_leave_printf_va_fl(file, line, category, label, repo, fmt,
void trace2_cmd_set_config_fl(const char *file, int line, const char *key,
	va_start(ap, fmt);
	struct strbuf buf_string = STRBUF_INIT;
	int j;
	tr2_cfg_free_patterns();
		 * so this is technically a bug.  But in those cases where the

	uint64_t us_elapsed_absolute;

{
				us_elapsed_region, category, label, repo, fmt,
 */
	va_list ap;
{
		if (tgt_j->pfn_command_path_fl)
			 const struct repository *repo, const char *key,
}
#include "config.h"
		if (tgt_j->pfn_atexit)
	uint64_t us_now;
	 */
			 const char **argv)
	us_now = getnanotime() / 1000;
	uint64_t us_now;


#ifndef HAVE_VARIADIC_MACROS
		 * We should only be called from the new thread's thread-proc,
	uint64_t us_elapsed_absolute;
 * Force (rather than lazily) initialize any of the requested
	 */
}
	if (!trace2_enabled)

}
	for_each_wanted_builtin (j, tgt_j)
}
 *
	struct tr2_tgt *tgt_j;

	tr2_sysenv_load();

void trace2_child_exit_fl(const char *file, int line, struct child_process *cmd,
 * the pager's atexit routine (since it closes them to shutdown
						repo, key, value);
#include "run-command.h"

{
	uint64_t us_now;
		return;
{
	int j;
}
			tgt_j->pfn_region_enter_printf_va_fl(
				ap);
		return;
 * *each* of the enabled targets.
	 * We expect each target function to treat 'ap' as constant

/* clang-format off */

		if (tgt_j->pfn_error_va_fl)
	uint64_t us_elapsed_absolute;
			    va_list ap)
}
	us_now = getnanotime() / 1000;
			   struct child_process *cmd)


	int j;
	 * and use va_copy.
		 * We should only be called from the exiting thread's
}
		return;

		 * looks correct.
	uint64_t us_elapsed_absolute;
	uint64_t us_now;
	for_each_wanted_builtin (j, tgt_j)
		return;

	va_start(ap, repo);

	va_list ap;
	struct tr2_tgt *tgt_j;

}


 */
	 *
	trace2_printf_va_fl(NULL, 0, fmt, ap);
{
			tgt_j->pfn_printf_va_fl(file, line, us_elapsed_absolute,
	     j++, tgt_j = tr2_tgt_builtins[j])
			  int child_exit_code)
		 *
			 const char *value)


}

	 * and use va_copy (because an 'ap' can only be walked once).
void trace2_thread_start_fl(const char *file, int line, const char *thread_name)
	     tgt_j;					\
			tgt_j->pfn_thread_exit_fl(file, line,
	uint64_t us_now;

	uint64_t us_elapsed_absolute;
	struct tr2_tgt *tgt_j;
	va_list ap;
		return;
	struct tr2_tgt *tgt_j;
	 * it lines up with the corresponding push/enter.
	strbuf_release(&buf_string);
}

	struct tr2_tgt *tgt_j;
	va_list ap;

	 * Get the elapsed time in the current region before we
	us_now = getnanotime() / 1000;
	atexit(tr2main_atexit_handler);
	us_now = getnanotime() / 1000;
		us_elapsed_child = 0;
	if (!trace2_enabled)
		return;
	 * Clear any unbalanced regions so that our atexit message
	va_end(ap);
		 */
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
	 * pop it off the stack.  Pop the stack.  And then print
{
					 ap);
	for_each_wanted_builtin (j, tgt_j)
	tr2tls_init();

	 * Emit 'version' message on each active builtin target.
	if (!trace2_enabled)
						 us_elapsed_child);
{
		if (tgt_j->pfn_start_fl)
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
	trace2_region_leave_printf_va_fl(file, line, category, label, repo,
	uint64_t us_now;


	if (!trace2_enabled)

						 child_exit_code,
}
static int tr2main_exit_code;
	struct tr2_tgt *tgt_j;
#include "trace2/tr2_cfg.h"
			tgt_j->pfn_error_va_fl(file, line, fmt, ap);
}
	if (!trace2_enabled)
		/*
	exec_id = tr2tls_locked_increment(&tr2_next_exec_id);
		if (tgt_j->pfn_alias_fl)
	us_now = getnanotime() / 1000;
	if (!trace2_enabled)
	for_each_wanted_builtin (j, tgt_j)
#include "json-writer.h"
void trace2_region_enter_fl(const char *file, int line, const char *category,

	if (!trace2_enabled)
	if (tr2tls_is_main_thread()) {
	us_elapsed_region = tr2tls_region_elasped_self(us_now);
		if (tgt_j->pfn_version_fl)



void trace2_initialize_clock(void)
			tgt_j->pfn_param_fl(file, line, param, value);
	uint64_t us_now;
}
 * a chance to write a summary event and/or flush if necessary
	va_start(ap, fmt);
	 * We expect each target function to treat 'ap' as constant
#include "thread-utils.h"

}
#ifndef HAVE_VARIADIC_MACROS

	if (!trace2_enabled)
		return;

	if (!trace2_enabled)

	if (!trace2_enabled)
void trace2_cmd_list_config_fl(const char *file, int line)
/*

	va_end(ap);
					      "thread-proc on main");
	va_end(ap);
#include "quote.h"
		if (tgt_j->pfn_exec_fl)
	 * started).  This gives us the run time of the thread.
	us_now = getnanotime() / 1000;
}
						   us_elapsed_absolute);
	if (tr2tls_is_main_thread()) {
}

	 * for the outer-most region (which we pushed when the thread
{
		 */
	 * Print the region-enter message at the current nesting
					   key, value);
	int j;

		return;
	trace2_region_enter_printf_va_fl(file, line, category, label, repo,
/* clang-format on */
	int j;

}
				      const char *category, const char *label,
	int j;

		if (tgt_j->pfn_data_fl)
	int j;

	/*
		if (tgt_j->pfn_child_exit_fl)
	 * the perf message at the new (shallower) level so that
}


	va_start(ap, fmt);
	struct tr2_tgt *tgt_j;
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
				      const struct repository *repo,
	if (repo->trace2_repo_id)
	return sum;
}
	va_list ap;
		return;
	for_each_wanted_builtin (j, tgt_j)
	trace2_region_leave_printf_va_fl(NULL, 0, category, label, repo, fmt,
	tr2_cfg_free_env_vars();
			tgt_j->pfn_child_start_fl(file, line,

int trace2_exec_fl(const char *file, int line, const char *exe,
}
						  us_elapsed_thread);

 * A table of the builtin TRACE2 targets.  Each of these may be independently
{
	va_start(ap, repo);
void trace2_region_enter_printf_va_fl(const char *file, int line,
	struct tr2_tgt *tgt_j;
			tgt_j->pfn_data_fl(file, line, us_elapsed_absolute,

		return -1;

 * Note that events generated here might not actually appear if
 * Properly terminate each builtin target.  Give each target
static int tr2_next_exec_id; /* modify under lock */
	struct tr2_tgt *tgt_j;
void trace2_def_repo_fl(const char *file, int line, struct repository *repo)
	int exec_id;

	 */
void trace2_region_leave_fl(const char *file, int line, const char *category,
};
}
	tr2main_exit_code = code;
	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);

}

	trace2_data_string_fl(file, line, category, repo, key, buf_string.buf);
	for_each_wanted_builtin (j, tgt_j)
{
	us_now = getnanotime() / 1000;

	va_start(ap, fmt);
	if (!trace2_enabled)
	int j;
	va_start(ap, fmt);
 */
	trace2_region_enter_printf_va_fl(file, line, category, label, repo, fmt,
void trace2_data_json_fl(const char *file, int line, const char *category,
	if (!trace2_enabled)
				      const char *fmt, va_list ap)
	int j;

	us_elapsed_absolute = tr2tls_absolute_elapsed(us_now);
void trace2_region_leave_printf_fl(const char *file, int line,
					      thread_name);
	uint64_t us_elapsed_child;
	uint64_t us_elapsed_absolute;
}
	 * and use va_copy.
			tgt_j->pfn_signal(us_elapsed_absolute, signo);
	for_each_wanted_builtin (j, tgt_j)
					  tr2main_exit_code);
	uint64_t us_elapsed_absolute;

	const char *hierarchy;
	uint64_t us_now;
static struct tr2_tgt *tr2_tgt_builtins[] =
	trace2_region_enter_printf_va_fl(NULL, 0, category, label, repo, fmt,
	uint64_t us_elapsed_absolute;
/* clang-format on */
	tr2tls_unset_self();
	va_start(ap, fmt);
			tgt_j->pfn_command_name_fl(file, line, name, hierarchy);
					 NULL, ap);

					 NULL, ap);
	for_each_wanted_builtin (j, tgt_j)
	va_list ap;
					    argv);
 *
	int j;
	tr2_tgt_disable_builtins();
		return;
