#include "builtin.h"
	if (mode == STRIP_DEFAULT || mode == STRIP_COMMENTS)
	write_or_die(1, buf.buf, buf.len);

static const char * const stripspace_usage[] = {
#include "cache.h"
			    STRIP_COMMENTS),
			    N_("skip and remove all lines starting with comment character"),
		OPT_CMDMODE('s', "strip-comments", &mode,
		git_config(git_default_config, NULL);
};
int cmd_stripspace(int argc, const char **argv, const char *prefix)

	};

static void comment_lines(struct strbuf *buf)
#include "config.h"
#include "parse-options.h"
	}
	strbuf_release(&buf);
	enum stripspace_mode mode = STRIP_DEFAULT;
	int nongit;
}

}


		OPT_END()
		setup_git_directory_gently(&nongit);

enum stripspace_mode {
};
		usage_with_options(stripspace_usage, options);
	NULL

	free(msg);
	if (argc)
		strbuf_stripspace(&buf, mode == STRIP_COMMENTS);
	size_t len;
	msg = strbuf_detach(buf, &len);
	const struct option options[] = {
	N_("git stripspace [-s | --strip-comments]"),
	else
			    COMMENT_LINES),
		die_errno("could not read the input");

	struct strbuf buf = STRBUF_INIT;
{

	return 0;
	if (mode == STRIP_COMMENTS || mode == COMMENT_LINES) {
	STRIP_DEFAULT = 0,
	STRIP_COMMENTS,

	char *msg;
			    N_("prepend comment character and space to each line"),
	strbuf_add_commented_lines(buf, msg, len);
	if (strbuf_read(&buf, 0, 1024) < 0)
	N_("git stripspace [-c | --comment-lines]"),
		OPT_CMDMODE('c', "comment-lines", &mode,
{
	argc = parse_options(argc, argv, prefix, options, stripspace_usage, 0);
		comment_lines(&buf);
	COMMENT_LINES
#include "strbuf.h"
