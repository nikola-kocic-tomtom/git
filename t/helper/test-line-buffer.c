#include "vcs-svn/line_buffer.h"
		die("invalid count: %s", s);

			if (buffer_init(&file_buf, filename))
	struct line_buffer file_buf = LINE_BUFFER_INIT;

 * test-line-buffer.c: code to exercise the svn importer's input helper
	uintmax_t n = strtoumax(s, &end, 10);
}
		die("input error");
static uint32_t strtouint32(const char *s)
	if (*s == '\0' || *end != '\0')

	const char *arg = strchr(line, ' ');
{
		die("error reading from %s", filename);


		fwrite(sb.buf, 1, sb.len, stdout);
		die("output error");
		filename = argv[1];
		struct strbuf sb = STRBUF_INIT;
	} else {
				die_errno("error opening %s", filename);
	else if (argc == 2)
#include "strbuf.h"
		die("unrecognized command: %s", command);
		die("no argument in line: %s", line);
	char *end;
int cmd_main(int argc, const char **argv)
static void handle_command(const char *command, const char *arg, struct line_buffer *buf)
	return 0;
 */
	struct line_buffer *input = &stdin_buf;
}
static void handle_line(const char *line, struct line_buffer *stdin_buf)
	}
	} else if (starts_with(command, "skip ")) {
		filename = NULL;
		usage("test-line-buffer [file | &fd] < script");
	else
{

	if (buffer_init(&stdin_buf, NULL))
	if (filename && buffer_deinit(&file_buf))
		}

	struct line_buffer stdin_buf = LINE_BUFFER_INIT;
		if (*filename == '&') {
	return (uint32_t) n;
	if (filename) {
		buffer_copy_bytes(buf, strtouint32(arg));
	const char *filename;
{
		buffer_read_binary(buf, &sb, strtouint32(arg));
	while ((s = buffer_read_line(&stdin_buf)))
			if (buffer_fdinit(&file_buf, strtouint32(filename + 1)))
	if (!arg)
}
	handle_command(line, arg + 1, stdin_buf);
{
#include "git-compat-util.h"

	if (starts_with(command, "binary ")) {
		buffer_skip_bytes(buf, strtouint32(arg));
	if (argc == 1)
	}
	if (ferror(stdout))
	if (buffer_deinit(&stdin_buf))
		strbuf_release(&sb);
		die_errno("open error");
/*
		strbuf_addch(&sb, '>');

	} else if (starts_with(command, "copy ")) {
		} else {
		input = &file_buf;
		handle_line(s, input);
				die_errno("error opening fd %s", filename + 1);
	char *s;
}
