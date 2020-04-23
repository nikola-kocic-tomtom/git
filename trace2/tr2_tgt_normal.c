	struct strbuf buf_payload = STRBUF_INIT;
		tr2_tbuf_local_time(&tb_now);

	normal_io_write_fl(file, line, &buf_payload);

static int tr2env_normal_be_brief;
	strbuf_addf(&buf_payload, "exec_result[%d] code:%d", exec_id, code);
	fn_error_va_fl,
 *
	normal_fmt_prepare(file, line, &buf_line);
	strbuf_addstr(&buf_payload, "start ");
		if (file && *file)
	}
	 * See trace_add_env() in run-command.c as used by original trace.c
			      uint64_t us_elapsed_absolute, int exec_id,

	normal_io_write_fl(file, line, &buf_payload);
	strbuf_addch(&buf_payload, ' ');

	sq_append_quote_argv_pretty(&buf_payload, argv);
static void fn_alias_fl(const char *file, int line, const char *alias,
	normal_io_write_fl(file, line, &buf_payload);
{
	normal_io_write_fl(__FILE__, __LINE__, &buf_payload);
	fn_signal,

	normal_io_write_fl(file, line, &buf_payload);
}
static void fn_param_fl(const char *file, int line, const char *param,
{
static void fn_command_mode_fl(const char *file, int line, const char *mode)
}



static void normal_fmt_prepare(const char *file, int line, struct strbuf *buf)
	struct strbuf buf_payload = STRBUF_INIT;


#include "config.h"
static struct tr2_dst tr2dst_normal = { TR2_SYSENV_NORMAL, 0, 0, 0, 0 };
{

			const char *value)
	strbuf_addbuf(&buf_line, buf_payload);

	}
static void fn_exit_fl(const char *file, int line, uint64_t us_elapsed_absolute,
	normal_io_write_fl(file, line, &buf_payload);
static void fn_exec_fl(const char *file, int line, uint64_t us_elapsed_absolute,
	strbuf_release(&buf_payload);
		maybe_append_string_va(&buf_payload, fmt, ap);
	strbuf_release(&buf_payload);
		strbuf_addch(&buf_payload, ' ');
	normal_io_write_fl(file, line, &buf_payload);
}
}
	strbuf_addf(&buf_payload, "cmd_mode %s", mode);
static void fn_child_start_fl(const char *file, int line,
	sq_append_quote_argv_pretty(&buf_payload, cmd->argv);
}
	fn_alias_fl,
}
	struct strbuf buf_payload = STRBUF_INIT;
{
	strbuf_release(&buf_payload);
{
}
{
		strbuf_addf(&buf_payload, " (%s)", hierarchy);
	if (brief && *brief &&
	fn_atexit,
	normal_io_write_fl(file, line, &buf_payload);

	double elapsed = (double)us_elapsed_absolute / 1000000.0;
	fn_command_mode_fl,
	int want = tr2_dst_trace_want(&tr2dst_normal);
		strbuf_addstr(&buf_payload, " cd ");
	&tr2dst_normal,

	double elapsed = (double)us_elapsed_absolute / 1000000.0;


			   va_list ap)
	struct strbuf buf_payload = STRBUF_INIT;
{
	tr2_dst_trace_disable(&tr2dst_normal);
	struct strbuf buf_payload = STRBUF_INIT;
}
	normal_io_write_fl(file, line, &buf_payload);
		strbuf_addstr(&buf_payload, ";");
}

	fn_init,
	if (exe) {
static void fn_command_path_fl(const char *file, int line, const char *pathname)
	struct strbuf buf_payload = STRBUF_INIT;
	strbuf_addf(&buf_payload, "signal elapsed:%.6f code:%d", elapsed,
	if (cmd->git_cmd)
				   va_list ap)
	NULL, /* region_leave */
		sq_quote_buf_pretty(&buf_payload, cmd->dir);
		while (buf->len < TR2FMT_NORMAL_FL_WIDTH)
	fn_exit_fl,
	strbuf_addf(&buf_payload, "atexit elapsed:%.6f code:%d", elapsed, code);
static void fn_repo_fl(const char *file, int line,

{
	normal_io_write_fl(file, line, &buf_payload);
static int fn_init(void)
	strbuf_addf(&buf_payload, "exit elapsed:%.6f code:%d", elapsed, code);

	brief = tr2_sysenv_get(TR2_SYSENV_NORMAL_BRIEF);

}
	fn_exec_result_fl,

	/*
}
	NULL, /* thread_start */
	return want;
	NULL, /* data_json */
	strbuf_addf(&buf_payload, "cmd_path %s", pathname);
	struct strbuf buf_payload = STRBUF_INIT;
		    cid, pid, code, elapsed);
	maybe_append_string_va(&buf_payload, fmt, ap);
			       const struct strbuf *buf_payload)


 * fields from each line written to the builtin normal target.

	struct strbuf buf_line = STRBUF_INIT;
}
	strbuf_release(&buf_payload);

		    signo);
}
{
	fn_exec_fl,
	strbuf_release(&buf_payload);
#include "trace2/tr2_sysenv.h"

{
		return;
#include "trace2/tr2_tls.h"
	    ((want_brief = git_parse_maybe_bool(brief)) != -1))
	fn_command_path_fl,
		strbuf_vaddf(buf, fmt, copy_ap);
{
	fn_start_fl,
	fn_child_start_fl,

#include "quote.h"

 * Use the TR2_SYSENV_NORMAL_BRIEF setting to omit the "<time> <file>:<line>"

static void fn_command_name_fl(const char *file, int line, const char *name,
		       const struct repository *repo)

{
}
	fn_repo_fl,


#include "trace2/tr2_tbuf.h"
#define TR2FMT_NORMAL_FL_WIDTH (50)


}
			    uint64_t us_elapsed_absolute, const char *fmt,
	fn_param_fl,
	strbuf_release(&buf_payload);
	fn_command_name_fl,
	if (fmt && *fmt) {
	strbuf_release(&buf_payload);
		va_list copy_ap;

	normal_io_write_fl(file, line, &buf_payload);
#include "trace2/tr2_tgt.h"
{
	struct strbuf buf_payload = STRBUF_INIT;

		strbuf_addstr(buf, tb_now.buf);
static void fn_child_exit_fl(const char *file, int line,


static void fn_atexit(uint64_t us_elapsed_absolute, int code)
	double elapsed = (double)us_elapsed_absolute / 1000000.0;
}
	fn_version_fl,
	tr2_dst_write_line(&tr2dst_normal, &buf_line);
	normal_io_write_fl(file, line, &buf_payload);
		       int exec_id, const char *exe, const char **argv)
	if (cmd->dir) {
	 */
static void fn_version_fl(const char *file, int line)
 */
	NULL, /* thread_exit */
	struct strbuf buf_payload = STRBUF_INIT;
	struct strbuf buf_payload = STRBUF_INIT;
	NULL, /* data */
	struct strbuf buf_payload = STRBUF_INIT;
	sq_quote_buf_pretty(&buf_payload, repo->worktree);
			      int code)
		strbuf_addstr(&buf_payload, "git ");
}
};
static void normal_io_write_fl(const char *file, int line,
			    va_list ap)
	normal_io_write_fl(file, line, &buf_payload);
	NULL, /* region_enter */
	strbuf_release(&buf_payload);

	}

			uint64_t us_elapsed_absolute, const char **argv)
	}
	struct strbuf buf_payload = STRBUF_INIT;
#include "version.h"
			       const char *hierarchy)
struct tr2_tgt tr2_tgt_normal = {
	strbuf_release(&buf_payload);

			     int code, uint64_t us_elapsed_child)
}
	struct strbuf buf_payload = STRBUF_INIT;
}
		tr2env_normal_be_brief = want_brief;
{

{
	normal_io_write_fl(file, line, &buf_payload);
static void maybe_append_string_va(struct strbuf *buf, const char *fmt,
static void fn_signal(uint64_t us_elapsed_absolute, int signo)

		struct tr2_tbuf tb_now;
static void fn_error_va_fl(const char *file, int line, const char *fmt,

#include "trace2/tr2_dst.h"
	strbuf_release(&buf_payload);
}
	fn_term,
	sq_append_quote_argv_pretty(&buf_payload, argv);
static void fn_printf_va_fl(const char *file, int line,
		strbuf_addch(buf, ' ');

	if (fmt && *fmt) {
			const char **argv)
	if (!tr2env_normal_be_brief) {
	const char *brief;
{
#include "cache.h"

	if (!want)
	strbuf_addf(&buf_payload, "version %s", git_version_string);
	struct strbuf buf_payload = STRBUF_INIT;
	normal_io_write_fl(file, line, &buf_payload);
static void fn_start_fl(const char *file, int line,
	strbuf_addf(&buf_payload, "def_param %s=%s", param, value);
	normal_io_write_fl(__FILE__, __LINE__, &buf_payload);
	strbuf_addf(&buf_payload, "child_exit[%d] pid:%d code:%d elapsed:%.6f",
 * Unit tests may want to use this to help with testing.

	strbuf_addstr(&buf_payload, "error");

	strbuf_addf(&buf_payload, "exec[%d] ", exec_id);
			strbuf_addf(buf, "%s:%d ", file, line);
		return want;
	normal_io_write_fl(file, line, &buf_payload);
		strbuf_addf(&buf_payload, " err:%s", strerror(code));


	struct strbuf buf_payload = STRBUF_INIT;
}
	strbuf_release(&buf_payload);
/*
			      const struct child_process *cmd)
	strbuf_addf(&buf_payload, "child_start[%d]", cmd->trace2_child_id);
	strbuf_addstr(&buf_payload, "worktree ");
{
		va_copy(copy_ap, ap);
	struct strbuf buf_payload = STRBUF_INIT;

static void fn_exec_result_fl(const char *file, int line,
{
	fn_printf_va_fl,
	strbuf_release(&buf_payload);
{
	strbuf_release(&buf_payload);
{
	strbuf_release(&buf_line);
	strbuf_release(&buf_payload);
	sq_append_quote_argv_pretty(&buf_payload, argv);
static void fn_term(void)


	double elapsed = (double)us_elapsed_child / 1000000.0;
}
		strbuf_addstr(&buf_payload, exe);
{
	strbuf_setlen(buf, 0);
			      uint64_t us_elapsed_absolute,

	strbuf_addf(&buf_payload, "cmd_name %s", name);
		va_end(copy_ap);
	 * TODO if (cmd->env) { Consider dumping changes to environment. }
	}

			strbuf_addch(buf, ' ');
			     uint64_t us_elapsed_absolute, int cid, int pid,
	if (hierarchy && *hierarchy)
	strbuf_release(&buf_payload);
	struct strbuf buf_payload = STRBUF_INIT;
	int want_brief;
#include "run-command.h"
		strbuf_addch(&buf_payload, ' ');

	strbuf_release(&buf_payload);
	if (code > 0)
	strbuf_release(&buf_payload);
		       int code)
	fn_child_exit_fl,

{
	strbuf_addf(&buf_payload, "alias %s -> ", alias);
