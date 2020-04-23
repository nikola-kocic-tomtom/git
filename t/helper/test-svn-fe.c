		svndump_reset();
}
	"test-svn-fe (<dumpfile> | [-d] <preimage> <delta> <len>)";
{
		return apply_delta(argc, argv);

	if (buffer_deinit(&preimage))
	if (argc != 5)
			return 1;

	if (buffer_deinit(&delta))
	if (svndiff0_apply(&delta, (off_t) strtoumax(argv[4], NULL, 0),
/*

		die_errno("cannot open preimage");
	usage(test_svnfe_usage);

		usage(test_svnfe_usage);
		svndump_deinit();
	struct line_buffer preimage = LINE_BUFFER_INIT;
	struct line_buffer delta = LINE_BUFFER_INIT;
{
}
					&preimage_view, stdout))
		die_errno("cannot open delta");
	strbuf_release(&preimage_view.buf);
	if (buffer_init(&delta, argv[3]))
		die_errno("cannot close preimage");
#include "vcs-svn/svndump.h"
		svndump_read(NULL, "refs/heads/master", "refs/notes/svn/revs");

		return 0;

	if (buffer_init(&preimage, argv[2]))
 */
	}
static int apply_delta(int argc, const char **argv)
#include "vcs-svn/sliding_window.h"
		if (svndump_init(argv[1]))
	if (argc >= 2 && !strcmp(argv[1], "-d"))
#include "git-compat-util.h"

		return 1;
static const char test_svnfe_usage[] =
		die_errno("cannot close delta");
#include "vcs-svn/svndiff.h"
	struct sliding_view preimage_view = SLIDING_VIEW_INIT(&preimage, -1);
 * test-svn-fe: Code to exercise the svn import lib
	return 0;
int cmd_main(int argc, const char **argv)
#include "vcs-svn/line_buffer.h"
	if (argc == 2) {
