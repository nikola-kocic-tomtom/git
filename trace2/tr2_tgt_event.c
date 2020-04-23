{

static void fn_thread_exit_fl(const char *file, int line,
static void fn_child_start_fl(const char *file, int line,
	if (repo)
	jw_object_intmax(&jw, "exec_id", exec_id);
	jw_release(&jw);
	jw_end(&jw);
		jw_end(&jw);
{
	jw_object_begin(&jw, 0);

	int max_nesting;
}
	if (!tr2env_event_be_brief && file && *file) {
{
			      uint64_t us_elapsed_absolute, int exec_id,
		       int code)

	tr2_dst_write_line(&tr2dst_event, &jw.json);
		maybe_add_string_va(&jw, "msg", fmt, ap);
	jw_end(&jw);
struct tr2_tgt tr2_tgt_event = {
		jw_object_intmax(&jw, "nesting", ctx->nr_open_regions);
{
	fn_child_start_fl,
static void fn_term(void)
	struct json_writer jw = JSON_WRITER_INIT;
	}
	jw_end(&jw);
static void fn_param_fl(const char *file, int line, const char *param,
	/*
	struct json_writer jw = JSON_WRITER_INIT;
		jw_object_string(jw, "time", tb_now.buf);
	fn_data_fl,
	tr2_dst_write_line(&tr2dst_event, &jw.json);
		tr2env_event_be_brief = want_brief;
		event_fmt_prepare(event_name, file, line, repo, &jw);
	jw_object_string(jw, "event", event_name);

		jw_object_string(&jw, "key", key);
{
{
{
	jw_object_intmax(&jw, "code", code);
#include "config.h"
		va_copy(copy_ap, ap);

	tr2_dst_trace_disable(&tr2dst_event);
			jw_object_string(&jw, "label", label);
	tr2_dst_write_line(&tr2dst_event, &jw.json);
static void fn_region_leave_printf_va_fl(

	fn_alias_fl,
}
}
	fn_param_fl,

static void fn_exec_fl(const char *file, int line, uint64_t us_elapsed_absolute,
/*

	jw_end(&jw);
	event_fmt_prepare(event_name, file, line, NULL, &jw);
	jw_end(&jw);
		jw_object_string(&jw, "hook_name", cmd->trace2_hook_name);
	jw_object_string(jw, "sid", tr2_sid_get());

}
}
/*
	jw_release(&jw);

{

	const char *event_name = "child_start";
		struct json_writer jw = JSON_WRITER_INIT;
	double t_abs = (double)us_elapsed_absolute / 1000000.0;

static int tr2env_event_max_nesting_levels = 2;
	jw_object_begin(&jw, 0);

	jw_object_string(&jw, "name", mode);
	int want_brief;
	jw_object_intmax(&jw, "code", code);

		double t_rel = (double)us_elapsed_region / 1000000.0;
}
	jw_array_argv(&jw, argv);
		event_fmt_prepare(event_name, file, line, repo, &jw);
	jw_object_string(&jw, "exe", git_version_string);
		event_fmt_prepare(event_name, file, line, repo, &jw);
	double t_abs = (double)us_elapsed_absolute / 1000000.0;
	jw_object_double(&jw, "t_abs", 6, t_abs);
			       uint64_t us_elapsed_absolute)
}
					 uint64_t us_elapsed_absolute,
{
 * are primarily intended for the performance target during debugging.
static void fn_data_json_fl(const char *file, int line,
}
	tr2_dst_write_line(&tr2dst_event, &jw.json);
/*
	jw_object_string(&jw, "param", param);
			     uint64_t us_elapsed_absolute, int cid, int pid,
	tr2_dst_write_line(&tr2dst_event, &jw.json);
		const char *child_class =
static int tr2env_event_be_brief;
	if (ctx->nr_open_regions <= tr2env_event_max_nesting_levels) {

{
	fn_region_enter_printf_va_fl,
static void fn_command_path_fl(const char *file, int line, const char *pathname)
	fn_signal,
	jw_object_double(&jw, "t_rel", 6, t_rel);
		jw_end(&jw);
				const char *fmt, va_list ap)
	fn_version_fl,
{
	jw_object_begin(&jw, 0);


	jw_end(&jw);
		jw_object_string(&jw, "hierarchy", hierarchy);
		va_list copy_ap;
	jw_end(&jw);
}
 * if existing fields are removed, or if there are significant changes in
	event_fmt_prepare(event_name, file, line, NULL, &jw);

		return;



	jw_object_intmax(&jw, "code", code);
	}
		jw_object_sub_jw(&jw, "value", value);
	jw_end(&jw);
		jw_object_begin(&jw, 0);
	jw_release(&jw);
	const char *event_name = "cmd_name";

			    uint64_t us_elapsed_region, const char *category,

			      struct json_writer *jw)

	event_fmt_prepare(event_name, file, line, NULL, &jw);
		jw_release(&jw);
	return want;

#include "cache.h"
		jw_object_intmax(jw, "line", line);
	struct json_writer jw = JSON_WRITER_INIT;
		       uint64_t us_elapsed_region, const char *category,
		return want;
	if (tr2dst_event.too_many_files)
 * messages such as those produced while diving the worktree or index)
#define TR2_EVENT_VERSION "2"
	fn_command_mode_fl,
	struct json_writer jw = JSON_WRITER_INIT;
	const char *event_name = "signal";
			      uint64_t us_elapsed_absolute,
		struct strbuf buf = STRBUF_INIT;
			jw_object_string(&jw, "category", category);
 * region details in the event target.
	}
{
		tr2_tbuf_utc_datetime_extended(&tb_now);
static void fn_data_fl(const char *file, int line, uint64_t us_elapsed_absolute,

/*
	event_fmt_prepare(event_name, __FILE__, __LINE__, NULL, &jw);
	struct json_writer jw = JSON_WRITER_INIT;
 * interpretation of existing events or fields. Smaller changes, such as adding
}
		jw_end(&jw);
		struct json_writer jw = JSON_WRITER_INIT;
	jw_release(&jw);


		jw_object_string(&jw, "key", key);
static void fn_thread_start_fl(const char *file, int line,
	jw_object_inline_begin_array(&jw, "argv");
		jw_object_intmax(&jw, "nesting", ctx->nr_open_regions);
	tr2_dst_write_line(&tr2dst_event, &jw.json);
	struct json_writer jw = JSON_WRITER_INIT;
 *   "thread":"<thread_name>"
{
	jw_end(&jw);
		strbuf_release(&buf);
	tr2_dst_write_line(&tr2dst_event, &jw.json);

}
static void fn_start_fl(const char *file, int line,
	maybe_add_string_va(&jw, "msg", fmt, ap);

	fn_thread_start_fl,
	jw_release(&jw);
	fn_repo_fl,
	struct tr2tls_thread_ctx *ctx = tr2tls_get_self();

		jw_object_double(&jw, "t_rel", 6, t_rel);

	const char *event_name = "region_enter";

	nesting = tr2_sysenv_get(TR2_SYSENV_EVENT_NESTING);
	struct json_writer jw = JSON_WRITER_INIT;
	jw_object_string(&jw, "alias", alias);
	event_fmt_prepare(event_name, file, line, NULL, &jw);
			      const struct child_process *cmd)
			     int code, uint64_t us_elapsed_child)
	if (cmd->git_cmd)
 * The version number of the JSON data generated by the EVENT target in this
	 * Also emit the format string as a field in case
	jw_object_begin(&jw, 0);
{
	 * messages by type without argument fields (such
	jw_object_begin(&jw, 0);
static void fn_signal(uint64_t us_elapsed_absolute, int signo)
 *     "time":"<time>"
		event_fmt_prepare(event_name, file, line, repo, &jw);
	jw_end(&jw);
 * source file. The version should be incremented if new event types are added,
					 const char *fmt, va_list ap)
		jw_release(&jw);
	jw_object_intmax(&jw, "child_id", cid);
	jw_object_string(&jw, "worktree", repo->worktree);
	} else {
	jw_object_double(&jw, "t_abs", 6, t_abs);
	jw_object_inline_begin_array(&jw, "argv");
	if (!want)
	jw_release(&jw);

	jw_release(&jw);
#include "json-writer.h"
	struct json_writer jw = JSON_WRITER_INIT;
	jw_object_string(&jw, "value", value);
	int want = tr2_dst_trace_want(&tr2dst_event);
}
	brief = tr2_sysenv_get(TR2_SYSENV_EVENT_BRIEF);
	if (hierarchy && *hierarchy)
#include "version.h"
 */
			       const char *hierarchy)
	const char *event_name = "def_param";
	jw_object_begin(&jw, 0);
	struct tr2tls_thread_ctx *ctx = tr2tls_get_self();
	tr2_dst_write_line(&tr2dst_event, &jw.json);
	jw_array_argv(&jw, cmd->argv);
}
		jw_object_string(jw, field_name, buf.buf);

	 * as pathnames or branch names) cluttering it up.
{
static void fn_alias_fl(const char *file, int line, const char *alias,
	fn_error_va_fl,
}
	const char *brief;


	if (fmt && *fmt) {
	jw_object_intmax(&jw, "pid", pid);
static void fn_child_exit_fl(const char *file, int line,
		tr2env_event_max_nesting_levels = max_nesting;

	jw_object_begin(&jw, 0);
	const char *event_name = "atexit";
	struct json_writer jw = JSON_WRITER_INIT;
	jw_object_begin(&jw, 0);
static void fn_version_fl(const char *file, int line)
{

	tr2_dst_write_line(&tr2dst_event, &jw.json);
	}
}
}
	struct json_writer jw = JSON_WRITER_INIT;
		double t_rel = (double)us_elapsed_region / 1000000.0;
	const char *event_name = "region_leave";
	fn_region_leave_printf_va_fl,

		jw_object_double(&jw, "t_rel", 6, t_rel);
 * The "region_enter" and "region_leave" messages (especially recursive
	jw_end(&jw);
 *     "file":"<filename>"
#include "trace2/tr2_sysenv.h"
		jw_release(&jw);
	event_fmt_prepare(event_name, file, line, repo, &jw);
	jw_release(&jw);

}
		jw_object_double(&jw, "t_abs", 6, t_abs);
	tr2_dst_write_line(&tr2dst_event, &jw.json);
	struct json_writer jw = JSON_WRITER_INIT;
	fn_command_path_fl,
	tr2_dst_write_line(&tr2dst_event, &jw.json);
		if (label)
			uint64_t us_elapsed_absolute, const char **argv)


 *     "line":<line_number>
	jw_object_begin(&jw, 0);
	jw_release(&jw);
	event_fmt_prepare(event_name, file, line, NULL, &jw);
 *
	struct tr2tls_thread_ctx *ctx = tr2tls_get_self();
		tr2_dst_write_line(&tr2dst_event, &jw.json);
}
	jw_release(&jw);

 * Some of the outer-most messages, however, may be of interest to the
			    const struct repository *repo, const char *key,
	jw_object_string(jw, "thread", ctx->thread_name.buf);
	jw_release(&jw);

					 const char *label,
			    uint64_t us_elapsed_absolute,

	event_fmt_prepare(event_name, file, line, NULL, &jw);
	jw_end(&jw);
		jw_end(&jw);
}
	jw_object_begin(&jw, 0);


	struct json_writer jw = JSON_WRITER_INIT;

					 const struct repository *repo,
	const char *event_name = "data";
{
 * Region nesting limit for messages written to the event target.
	const char *event_name = "exit";
	if (nesting && *nesting && ((max_nesting = atoi(nesting)) > 0))
	event_fmt_prepare(event_name, file, line, NULL, &jw);
			    const struct json_writer *value)
static void event_fmt_prepare(const char *event_name, const char *file,
		jw_object_begin(&jw, 0);

		jw_object_intmax(jw, "repo", repo->trace2_repo_id);
	fn_init,
		       const struct repository *repo, const char *key,
}
	if (cmd->dir)
	jw_array_argv(&jw, argv);
static void fn_command_mode_fl(const char *file, int line, const char *mode)
		jw_object_string(&jw, "exe", exe);

 * format version.
		double t_abs = (double)us_elapsed_absolute / 1000000.0;
	jw_release(&jw);
static void fn_exec_result_fl(const char *file, int line,
	jw_release(&jw);
#include "run-command.h"
		jw_object_string(&jw, "child_class", "hook");
 *     "event:"<event_name>"
	const char *event_name = "cmd_mode";
			      int line, const struct repository *repo,


		strbuf_vaddf(&buf, fmt, copy_ap);
	jw_release(&jw);
	jw_object_double(&jw, "t_abs", 6, t_abs);
	struct tr2_tbuf tb_now;
	event_fmt_prepare(event_name, __FILE__, __LINE__, NULL, &jw);
static int fn_init(void)
	jw_end(&jw);
	struct json_writer jw = JSON_WRITER_INIT;
	/*
		jw_object_double(&jw, "t_rel", 6, t_rel);
	const char *event_name = "error";
#include "trace2/tr2_dst.h"
	tr2_dst_write_line(&tr2dst_event, &jw.json);
	jw_object_inline_begin_array(&jw, "argv");


		tr2_dst_write_line(&tr2dst_event, &jw.json);
	jw_object_intmax(&jw, "signo", signo);

	struct json_writer jw = JSON_WRITER_INIT;
	jw_object_string(&jw, "path", pathname);
 *     "repo":<repo_id>
			   va_list ap)
	if (!tr2env_event_be_brief || !strcmp(event_name, "version") ||

	const char *nesting;
		if (category)
	event_fmt_prepare(event_name, file, line, NULL, &jw);
	    !strcmp(event_name, "atexit")) {
	double t_abs = (double)us_elapsed_absolute / 1000000.0;
}

	fn_exec_fl,
	const char *event_name = "alias";

		jw_object_string(&jw, "value", value);
		jw_release(&jw);
	jw_object_double(&jw, "t_abs", 6, t_abs);
{
 *      "sid":"<sid>"

	jw_object_begin(&jw, 0);
	jw_object_inline_begin_array(&jw, "argv");
	if (ctx->nr_open_regions <= tr2env_event_max_nesting_levels) {
	fn_term,
	 */

	const char *event_name = "child_exit";
static void maybe_add_string_va(struct json_writer *jw, const char *field_name,
	const struct repository *repo, const char *fmt, va_list ap)
	jw_object_intmax(&jw, "code", code);
	jw_release(&jw);

	fn_atexit,

static void fn_error_va_fl(const char *file, int line, const char *fmt,
		jw_object_double(&jw, "t_abs", 6, t_abs);
	event_fmt_prepare(event_name, file, line, NULL, &jw);

static void fn_region_enter_printf_va_fl(const char *file, int line,
static void fn_command_name_fl(const char *file, int line, const char *name,
	}
	jw_release(&jw);
			      uint64_t us_elapsed_thread)
		       const struct repository *repo)
	}
	tr2_dst_write_line(&tr2dst_event, &jw.json);

	const char *event_name = "def_repo";

	fn_exec_result_fl,
	event_fmt_prepare(event_name, file, line, NULL, &jw);
			      uint64_t us_elapsed_absolute,
	jw_object_intmax(&jw, "exec_id", exec_id);
#include "trace2/tr2_tbuf.h"
	struct json_writer jw = JSON_WRITER_INIT;
 * <line> fields from most events.

		struct json_writer jw = JSON_WRITER_INIT;
	jw_object_begin(&jw, 0);
{
	event_fmt_prepare(event_name, file, line, NULL, &jw);
	const char *event_name = "thread_exit";
{
	const char *event_name = "cmd_path";

			const char *value)
	const char *event_name = "version";
		double t_abs = (double)us_elapsed_absolute / 1000000.0;
	jw_end(&jw);
		tr2_dst_write_line(&tr2dst_event, &jw.json);

		if (label)

	jw_object_string(&jw, "evt", TR2_EVENT_VERSION);
	jw_object_begin(&jw, 0);
	fn_start_fl,
	const char *event_name = "exec_result";
			      int code)
#include "trace2/tr2_tls.h"
 */
	jw_end(&jw);
static void fn_repo_fl(const char *file, int line,

#include "trace2/tr2_tgt.h"

	fn_data_json_fl,
static void fn_too_many_files_fl(const char *file, int line)
	struct json_writer jw = JSON_WRITER_INIT;
	event_fmt_prepare(event_name, file, line, NULL, &jw);

	tr2_dst_write_line(&tr2dst_event, &jw.json);
		va_end(copy_ap);
	double t_rel = (double)us_elapsed_thread / 1000000.0;
	jw_end(&jw);
	const char *file, int line, uint64_t us_elapsed_absolute,
};

	if (brief && *brief &&
	    ((want_brief = git_parse_maybe_bool(brief)) != -1))
	fn_thread_exit_fl,
	jw_end(&jw);
	jw_end(&jw);
 */
	jw_array_argv(&jw, argv);
	struct tr2tls_thread_ctx *ctx = tr2tls_get_self();

#include "trace2/tr2_sid.h"
	if (ctx->nr_open_regions <= tr2env_event_max_nesting_levels) {
		jw_array_string(&jw, "git");
	const char *event_name = "too_many_files";

	jw_object_begin(&jw, 0);
	jw_object_bool(&jw, "use_shell", cmd->use_shell);
	if (cmd->trace2_hook_name) {

	 * post-processors want to aggregate common error
	 */

	event_fmt_prepare(event_name, file, line, NULL, &jw);
	jw_object_begin(&jw, 0);
		jw_object_string(&jw, "cd", cmd->dir);
	tr2_dst_write_line(&tr2dst_event, &jw.json);

	jw_end(&jw);
	struct json_writer jw = JSON_WRITER_INIT;
}
}
	jw_object_begin(&jw, 0);
	tr2_dst_write_line(&tr2dst_event, &jw.json);
		jw_object_string(&jw, "category", category);
			cmd->trace2_child_class ? cmd->trace2_child_class : "?";
	jw_object_begin(&jw, 0);


		maybe_add_string_va(&jw, "msg", fmt, ap);
	}
		fn_too_many_files_fl(file, line);
		struct json_writer jw = JSON_WRITER_INIT;
	struct json_writer jw = JSON_WRITER_INIT;
		jw_object_begin(&jw, 0);
	tr2_dst_write_line(&tr2dst_event, &jw.json);
 * a new field to an existing event, do not require an increment to the EVENT
		       int exec_id, const char *exe, const char **argv)
	jw_end(&jw);
		if (category)
	struct tr2tls_thread_ctx *ctx = tr2tls_get_self();
	struct json_writer jw = JSON_WRITER_INIT;
	jw_release(&jw);
	const char *event_name = "start";

	fn_command_name_fl,
	const char *event_name = "thread_start";
}
{
 * event target.  Use the TR2_SYSENV_EVENT_NESTING setting to increase

	jw_object_begin(&jw, 0);

static void fn_atexit(uint64_t us_elapsed_absolute, int code)
	jw_release(&jw);
	event_fmt_prepare(event_name, file, line, NULL, &jw);
 *

static struct tr2_dst tr2dst_event = { TR2_SYSENV_EVENT, 0, 0, 0, 0 };
		       const char *value)
	jw_object_double(&jw, "t_rel", 6, t_rel);
	jw_release(&jw);
		jw_object_string(&jw, "fmt", fmt);
	uint64_t us_elapsed_region, const char *category, const char *label,
	if (exe)
		jw_object_begin(&jw, 0);

	tr2_dst_write_line(&tr2dst_event, &jw.json);
	double t_rel = (double)us_elapsed_child / 1000000.0;

 * Use the TR2_SYSENV_EVENT_BRIEF to omit the <time>, <file>, and
	event_fmt_prepare(event_name, file, line, NULL, &jw);
	if (ctx->nr_open_regions <= tr2env_event_max_nesting_levels) {
	jw_end(&jw);
			jw_object_string(&jw, "category", category);
		jw_object_intmax(&jw, "nesting", ctx->nr_open_regions);
{
	jw_end(&jw);
	if (fmt && *fmt)
		jw_object_string(&jw, "category", category);

	jw_object_string(&jw, "name", name);
			const char **argv)
 */
{
	&tr2dst_event,
{

	jw_end(&jw);
		double t_rel = (double)us_elapsed_region / 1000000.0;
	const char *event_name = "exec";
	jw_object_intmax(&jw, "child_id", cmd->trace2_child_id);
static void fn_exit_fl(const char *file, int line, uint64_t us_elapsed_absolute,
		jw_object_string(&jw, "child_class", child_class);
		tr2_dst_write_line(&tr2dst_event, &jw.json);
	tr2_dst_write_line(&tr2dst_event, &jw.json);
 * Append common key-value pairs to the currently open JSON object.
		jw_object_intmax(&jw, "nesting", ctx->nr_open_regions);
	double t_abs = (double)us_elapsed_absolute / 1000000.0;
}

}
	 * In brief mode, only emit <time> on these 2 event types.
	jw_object_begin(&jw, 0);

	fn_exit_fl,
}
{
{
			jw_object_string(&jw, "label", label);
	event_fmt_prepare(event_name, file, line, NULL, &jw);

		jw_object_string(jw, "file", file);
	}
{
	NULL, /* printf */
	const char *event_name = "data_json";
					 const char *category,
	fn_child_exit_fl,
