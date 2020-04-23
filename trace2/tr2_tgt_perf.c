	fn_data_fl,
static void fn_command_path_fl(const char *file, int line, const char *pathname)
		strbuf_addf(buf, "%9s | ", " ");
		strbuf_addchars(buf, '.', TR2_INDENT_LENGTH(ctx));
	const char *event_name = "exec_result";
}
	fn_param_fl,

	const char *event_name = "def_param";

		strbuf_addf(&buf_payload, " (%s)", hierarchy);


			}
	}
	struct strbuf buf_payload = STRBUF_INIT;
	strbuf_addf(&buf_payload, "code:%d", code);
	const char *event_name = "thread_start";
			   va_list ap)
	sq_append_quote_argv_pretty(&buf_payload, argv);
			    uint64_t us_elapsed_absolute, const char *fmt,

	strbuf_addf(&buf_payload, "alias:%s argv:[", alias);

	struct strbuf buf_payload = STRBUF_INIT;

	}

			strbuf_addch(&buf_payload, ' ');
	struct strbuf buf_line = STRBUF_INIT;

	if (brief && *brief &&
{
{
 * the performance target:
	struct tr2tls_thread_ctx *ctx = tr2tls_get_self();
			 &buf_line);
}
 * Use TR2_SYSENV_PERF_BRIEF to omit the "<time> <file>:<line>"

{
	strbuf_addf(&buf_payload, "%s:%s", key, value->json.buf);
	const char *event_name = "alias";
	if (fmt && *fmt) {
	if (label)
		tr2env_perf_be_brief = want_brief;

		strbuf_addf(&buf_payload, " err:%s", strerror(code));


	strbuf_addstr(&buf_payload, git_version_string);
	if (!tr2env_perf_be_brief) {
}
	const char *event_name = "child_start";
			const char **argv)
	strbuf_addf(buf, "%-*.*s | ", TR2FMT_PERF_CATEGORY_WIDTH,
{
			 &buf_payload);

					 const char *fmt, va_list ap)
					   avail);
	if (cmd->git_cmd) {
	tr2_dst_write_line(&tr2dst_perf, &buf_line);
{
		strbuf_addstr(buf, " | ");
		strbuf_addf(&buf_payload, "label:%s", label);
	fn_version_fl,
			     uint64_t us_elapsed_absolute, int cid, int pid,

{
	const char *event_name = "cmd_mode";
		strbuf_addf(&buf_payload, "[ch%d] class:%s",
			strbuf_release(&buf_fl);
static void fn_param_fl(const char *file, int line, const char *param,
		       const struct repository *repo)
	fn_region_leave_printf_va_fl,
			else {

static void perf_fmt_prepare(const char *event_name,
		strbuf_addf(&buf_payload, "[ch%d] class:hook hook:%s",

{
	struct strbuf buf_payload = STRBUF_INIT;
	brief = tr2_sysenv_get(TR2_SYSENV_PERF_BRIEF);


			       uint64_t us_elapsed_absolute)
	strbuf_release(&buf_payload);

static void fn_term(void)
}
			 &buf_payload);
 *         [<category>] <bar> [<dots>] "
}
	strbuf_release(&buf_payload);
	if (fmt && *fmt) {
	strbuf_release(&buf_payload);
	struct strbuf buf_payload = STRBUF_INIT;
	perf_io_write_fl(file, line, event_name, NULL, NULL, NULL, NULL,

}
	if (p_us_elapsed_relative)


		strbuf_addch(&buf_payload, ' ');
	perf_io_write_fl(file, line, event_name, repo, &us_elapsed_absolute,
	uint64_t us_elapsed_region, const char *category, const char *label,
		if (argv[0])
	const char *event_name = "atexit";
			    uint64_t us_elapsed_region, const char *category,
 *     "[<time> [<file>:<line>] <bar>] <nr_parents> <bar>
	perf_io_write_fl(file, line, event_name, NULL, &us_elapsed_absolute,


	const char *event_name = "cmd_name";
	strbuf_addch(&buf_payload, ']');
}
	if (code > 0)
					 const char *category,

	strbuf_release(&buf_line);
	if (p_us_elapsed_absolute)
	struct strbuf buf_payload = STRBUF_INIT;
	perf_io_write_fl(file, line, event_name, NULL, &us_elapsed_absolute,
static void perf_io_write_fl(const char *file, int line, const char *event_name,
	strbuf_addstr(buf, " | ");
			      uint64_t us_elapsed_absolute, int exec_id,
	sq_append_quote_argv_pretty(&buf_payload, argv);
	fn_child_exit_fl,
	int len;

};
	const char *event_name = "cmd_path";
			    const struct json_writer *value)
{

			     const struct repository *repo,
	const char *event_name = "child_exit";
	perf_fmt_prepare(event_name, ctx, file, line, repo,
			 NULL, category, &buf_payload);
		       const struct repository *repo, const char *key,
	fn_command_mode_fl,
{


	len = buf->len + TR2FMT_PERF_REPO_WIDTH;
static void fn_exit_fl(const char *file, int line, uint64_t us_elapsed_absolute,
		strbuf_addf(buf, "%9.6f | ",
	fn_start_fl,
	perf_io_write_fl(file, line, event_name, NULL, NULL, NULL, NULL,
	strbuf_addstr(&buf_payload, "argv:[");
			 &us_elapsed_region, category, &buf_payload);
		if (file && *file) {
#include "run-command.h"
	strbuf_release(&buf_payload);
	if (repo)
	if (cmd->dir) {

{
			 &buf_payload);

	struct strbuf buf_payload = STRBUF_INIT;

#include "quote.h"
			 &buf_payload);
	tr2_dst_trace_disable(&tr2dst_perf);
		    TR2FMT_PERF_CATEGORY_WIDTH, (category ? category : ""));
	strbuf_release(&buf_payload);
}
	fn_alias_fl,
	struct strbuf buf_payload = STRBUF_INIT;
	fn_term,
	const char *event_name = "printf";
static void fn_data_fl(const char *file, int line, uint64_t us_elapsed_absolute,

	strbuf_release(&buf_payload);
					 const char *label,
/*

	fn_command_name_fl,
	strbuf_addf(&buf_payload, "id:%d code:%d", exec_id, code);
		fl_end_col = buf->len + TR2FMT_PERF_FL_WIDTH;
	struct strbuf buf_payload = STRBUF_INIT;

	strbuf_release(&buf_payload);

					   &buf_fl.buf[buf_fl.len - avail],
				strbuf_addbuf(buf, &buf_fl);
	struct strbuf buf_payload = STRBUF_INIT;
	const char *event_name = "def_repo";
	fn_atexit,

	fn_signal,

			struct strbuf buf_fl = STRBUF_INIT;
	if (ctx->nr_open_regions > 0)
	const char *event_name = "data";


			 &buf_payload);
	fn_error_va_fl,
}
#include "config.h"
	strbuf_release(&buf_payload);
			 NULL, NULL, &buf_payload);
	else
/*
}
		size_t fl_end_col;
 *
{
	perf_io_write_fl(file, line, event_name, NULL, &us_elapsed_absolute,
	} else {
				strbuf_addstr(buf, "...");
	strbuf_release(&buf_payload);
	struct strbuf buf_payload = STRBUF_INIT;
	strbuf_release(&buf_payload);
	fn_data_json_fl,
			 &us_elapsed_child, NULL, &buf_payload);
		       const char *value)
			 NULL, NULL, &buf_payload);


	struct strbuf buf_payload = STRBUF_INIT;
	strbuf_addf(&buf_payload, "id:%d ", exec_id);
	perf_io_write_fl(file, line, event_name, NULL, &us_elapsed_absolute,
	strbuf_addf(&buf_payload, "code:%d", code);
	if (!want)
	strbuf_release(&buf_payload);

}
#define TR2FMT_PERF_FL_WIDTH (28)
{
		strbuf_vaddf(buf, fmt, copy_ap);
		return;
			 NULL, NULL, &buf_payload);


	if (fmt && *fmt) {
static void fn_signal(uint64_t us_elapsed_absolute, int signo)
	sq_append_quote_argv_pretty(&buf_payload, argv);
	while (buf->len < len)
static int tr2env_perf_be_brief;
	int want_brief;
	perf_io_write_fl(file, line, event_name, NULL, NULL, NULL, NULL,
{
		strbuf_addch(buf, ' ');
{
		strbuf_addstr(buf, tb_now.buf);

		       int exec_id, const char *exe, const char **argv)
			 &us_elapsed_region, category, &buf_payload);

	strbuf_addf(&buf_payload, "%s:%s", param, value);
				size_t avail = TR2FMT_PERF_FL_WIDTH - 3;
	struct strbuf buf_payload = STRBUF_INIT;

}
 * Format trace line prefix in human-readable classic format for

#include "cache.h"
#define TR2FMT_PERF_MAX_EVENT_NAME (12)
	const char *event_name = "exit";

	strbuf_addbuf(&buf_line, buf_payload);
	perf_io_write_fl(__FILE__, __LINE__, event_name, NULL,
{
	strbuf_addstr(&buf_payload, name);
static void fn_version_fl(const char *file, int line)
	strbuf_addch(&buf_payload, ']');
static int fn_init(void)
	strbuf_addstr(&buf_payload, "worktree:");
			     struct tr2tls_thread_ctx *ctx, const char *file,
	fn_thread_exit_fl,

{
{
}

	fn_printf_va_fl,
 * Unit tests may want to use this to help with testing.
	strbuf_addf(buf, "d%d | ", tr2_sid_depth());

 *         [<elapsed_absolute>] [<elapsed_relative>] <bar>
			     uint64_t *p_us_elapsed_relative,
			 &buf_payload);
	strbuf_release(&buf_payload);
			     int code, uint64_t us_elapsed_child)
 * fields from each line written to the builtin performance target.
static void fn_command_name_fl(const char *file, int line, const char *name,
	strbuf_addstr(&buf_payload, " argv:[");

	strbuf_release(&buf_payload);

		maybe_append_string_va(&buf_payload, fmt, ap);
		if (cmd->argv[0])
	strbuf_release(&buf_payload);
	strbuf_setlen(buf, 0);
			      int code)

			      uint64_t us_elapsed_absolute,
					 const struct repository *repo,

	}
	const char *event_name = "exec";
			      uint64_t us_elapsed_thread)

static void fn_thread_exit_fl(const char *file, int line,
	fn_init,
	const char *event_name = "signal";
			 &buf_payload);
	struct strbuf buf_payload = STRBUF_INIT;
 */
{
			       const char *hierarchy)
#include "trace2/tr2_tls.h"
		strbuf_addstr(&buf_payload, " cd:");
	if (hierarchy && *hierarchy)
static void fn_printf_va_fl(const char *file, int line,

	struct strbuf buf_payload = STRBUF_INIT;
}
	perf_io_write_fl(file, line, event_name, NULL, NULL, NULL, NULL,
					 uint64_t us_elapsed_absolute,
struct tr2_tgt tr2_tgt_perf = {
}

	perf_io_write_fl(__FILE__, __LINE__, event_name, NULL,
			     const struct strbuf *buf_payload)
static void fn_error_va_fl(const char *file, int line, const char *fmt,
	perf_io_write_fl(file, line, event_name, NULL, &us_elapsed_absolute,
		       uint64_t us_elapsed_region, const char *category,
}
			     int line, const struct repository *repo,
			 NULL, NULL, &buf_payload);
}

	perf_io_write_fl(file, line, event_name, NULL, &us_elapsed_absolute,
	if (cmd->trace2_hook_name) {

#include "trace2/tr2_sid.h"

	strbuf_addstr(&buf_payload, pathname);
		}
	strbuf_release(&buf_payload);
#include "version.h"
		maybe_append_string_va(&buf_payload, fmt, ap);
		tr2_tbuf_local_time(&tb_now);
static void fn_thread_start_fl(const char *file, int line,


#include "trace2/tr2_tbuf.h"
}
#include "trace2/tr2_tgt.h"

	strbuf_release(&buf_payload);
		strbuf_addf(&buf_payload, "label:%s", label);
			      uint64_t us_elapsed_absolute,

	int want = tr2_dst_trace_want(&tr2dst_perf);
	strbuf_release(&buf_payload);
	else
{
	const char *file, int line, uint64_t us_elapsed_absolute,
	perf_io_write_fl(file, line, event_name, repo, &us_elapsed_absolute,
	}
	}
static void fn_region_enter_printf_va_fl(const char *file, int line,
			 p_us_elapsed_absolute, p_us_elapsed_relative, category,
static void fn_exec_fl(const char *file, int line, uint64_t us_elapsed_absolute,
		const char *child_class =
		va_copy(copy_ap, ap);
static void fn_start_fl(const char *file, int line,

#define TR2_INDENT (2)
static void maybe_append_string_va(struct strbuf *buf, const char *fmt,
{
				   va_list ap)
	perf_io_write_fl(file, line, event_name, NULL, NULL, NULL, NULL,
	    ((want_brief = git_parse_maybe_bool(brief)) != -1))
			    ((double)(*p_us_elapsed_relative)) / 1000000.0);
			 &us_elapsed_region, category, &buf_payload);
		va_end(copy_ap);
	fn_exec_result_fl,
	const char *event_name = "thread_exit";
{


static void fn_child_start_fl(const char *file, int line,
			 NULL, NULL, &buf_payload);

#define TR2FMT_PERF_REPO_WIDTH (3)


	&tr2dst_perf,
	struct strbuf buf_payload = STRBUF_INIT;
			     uint64_t *p_us_elapsed_relative,
}

}

	strbuf_release(&buf_payload);

{
	perf_io_write_fl(file, line, event_name, repo, &us_elapsed_absolute,
	const char *event_name = "region_enter";
		strbuf_addch(&buf_payload, ' ' );
	perf_io_write_fl(file, line, event_name, NULL, &us_elapsed_absolute,

}
			    cmd->trace2_child_id, cmd->trace2_hook_name);
			    cmd->trace2_child_id, child_class);

static void fn_alias_fl(const char *file, int line, const char *alias,
	strbuf_release(&buf_payload);
	}

			uint64_t us_elapsed_absolute, const char **argv)
 */
	if (exe) {
	const char *event_name = "data_json";
		strbuf_addstr(&buf_payload, "git");
	strbuf_release(&buf_payload);
	const char *brief;

}
#define TR2FMT_PERF_CATEGORY_WIDTH (12)
		strbuf_addf(buf, "r%d ", repo->trace2_repo_id);
		    event_name);
	if (label)
#include "json-writer.h"
	perf_io_write_fl(file, line, event_name, NULL, NULL, NULL, NULL,

	perf_io_write_fl(file, line, event_name, NULL, &us_elapsed_absolute,
	perf_io_write_fl(file, line, event_name, repo, &us_elapsed_absolute,

	const char *event_name = "start";

{
	struct strbuf buf_payload = STRBUF_INIT;
{
			strbuf_addf(&buf_fl, "%s:%d", file, line);
	maybe_append_string_va(&buf_payload, fmt, ap);
static void fn_child_exit_fl(const char *file, int line,
			    const struct repository *repo, const char *key,
#include "trace2/tr2_sysenv.h"
			cmd->trace2_child_class ? cmd->trace2_child_class : "?";
	fn_child_start_fl,


		va_list copy_ap;
}
	const char *event_name = "region_leave";
			if (buf_fl.len <= TR2FMT_PERF_FL_WIDTH)
			 &us_elapsed_absolute, NULL, NULL, &buf_payload);
	strbuf_addch(&buf_payload, ']');
	fn_thread_start_fl,
		       int code)

	struct strbuf buf_payload = STRBUF_INIT;
	strbuf_addf(&buf_payload, "signo:%d", signo);
static void fn_exec_result_fl(const char *file, int line,
	perf_io_write_fl(file, line, event_name, repo, NULL, NULL, NULL,
static void fn_command_mode_fl(const char *file, int line, const char *mode)
		return want;
			    uint64_t us_elapsed_absolute,


	struct strbuf buf_payload = STRBUF_INIT;

	fn_command_path_fl,
		    ctx->thread_name.buf, TR2FMT_PERF_MAX_EVENT_NAME,
			 NULL, NULL, &buf_payload);
	strbuf_release(&buf_payload);
			     const char *category, struct strbuf *buf)
			 &us_elapsed_thread, NULL, &buf_payload);
	}

	fn_exec_fl,
{
static void fn_repo_fl(const char *file, int line,
		strbuf_addstr(&buf_payload, exe);

	maybe_append_string_va(&buf_payload, fmt, ap);
{
 *         <thread_name> <bar> <event_name> <bar> [<repo>] <bar>
			 &us_elapsed_absolute, NULL, NULL, &buf_payload);
				strbuf_add(buf,

static void fn_region_leave_printf_va_fl(
{

	struct strbuf buf_payload = STRBUF_INIT;
			     const char *category,

}
			      const struct child_process *cmd)
	perf_io_write_fl(file, line, event_name, NULL, NULL, NULL, NULL,
	struct strbuf buf_payload = STRBUF_INIT;
	fn_region_enter_printf_va_fl,

	strbuf_release(&buf_payload);

#define TR2_INDENT_LENGTH(ctx) (((ctx)->nr_open_regions - 1) * TR2_INDENT)
			 &buf_payload);
static void fn_atexit(uint64_t us_elapsed_absolute, int code)
			     uint64_t *p_us_elapsed_absolute,

	strbuf_release(&buf_payload);
	}
	const char *event_name = "error";
	strbuf_addf(buf, "%-*s | %-*s | ", TR2_MAX_THREAD_NAME,
#include "trace2/tr2_dst.h"

	const struct repository *repo, const char *fmt, va_list ap)
			strbuf_addch(&buf_payload, ' ');
}
		strbuf_addf(buf, "%9s | ", " ");
	fn_repo_fl,
			const char *value)
			 NULL, NULL, &buf_payload);
static struct tr2_dst tr2dst_perf = { TR2_SYSENV_PERF, 0, 0, 0, 0 };
	perf_io_write_fl(file, line, event_name, NULL, &us_elapsed_absolute,
	strbuf_addf(&buf_payload, "%s:%s", key, value);
}
}

	const char *event_name = "version";
static void fn_data_json_fl(const char *file, int line,
			strbuf_addch(buf, ' ');
	strbuf_addf(&buf_payload, "[ch%d] pid:%d code:%d", cid, pid, code);
	struct strbuf buf_payload = STRBUF_INIT;

			     uint64_t *p_us_elapsed_absolute,
	struct strbuf buf_payload = STRBUF_INIT;
		strbuf_addf(buf, "%9.6f | ",
}
	sq_append_quote_argv_pretty(&buf_payload, cmd->argv);
	sq_quote_buf_pretty(&buf_payload, repo->worktree);
{
		sq_quote_buf_pretty(&buf_payload, cmd->dir);

	return want;
	struct strbuf buf_payload = STRBUF_INIT;
		strbuf_addch(buf, ' ');
	strbuf_addstr(&buf_payload, mode);
			    ((double)(*p_us_elapsed_absolute)) / 1000000.0);
			    va_list ap)
	fn_exit_fl,
		struct tr2_tbuf tb_now;
		while (buf->len < fl_end_col)
