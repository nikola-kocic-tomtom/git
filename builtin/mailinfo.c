}
	mi.metainfo_charset = def_charset;
#include "utf8.h"
	"git mailinfo [-k | -b] [-m | --message-id] [-u | --encoding=<encoding> | -n] [--scissors | --no-scissors] <msg> <patch> < mail >info";
			mi.keep_subject = 1;
	status = !!mailinfo(&mi, msgfile, patchfile);
	return status;
int cmd_mailinfo(int argc, const char **argv, const char *prefix)
		argc--; argv++;
			mi.use_scissors = 1;
#include "cache.h"
 * email to figure out authorship and subject
		else if (!strcmp(argv[1], "-b"))
		if (!strcmp(argv[1], "-k"))
			mi.metainfo_charset = argv[1] + 11;

static const char mailinfo_usage[] =
	if (argc != 3)
		usage(mailinfo_usage);
{
#include "builtin.h"
 */
	mi.input = stdin;
		else if (!strcmp(argv[1], "-u"))
		else if (!strcmp(argv[1], "-n"))

		else if (!strcmp(argv[1], "--scissors"))
/*
	free(patchfile);


#include "mailinfo.h"
	}
			mi.add_message_id = 1;
	const char *def_charset;
			usage(mailinfo_usage);
			mi.metainfo_charset = def_charset;
	def_charset = get_commit_output_encoding();
		else if (!strcmp(argv[1], "--no-scissors"))
	while (1 < argc && argv[1][0] == '-') {
	free(msgfile);
	int status;
			mi.use_scissors = 0;
#include "strbuf.h"
	clear_mailinfo(&mi);
			mi.metainfo_charset = NULL;
			mi.keep_non_patch_brackets_in_subject = 1;


		else if (starts_with(argv[1], "--encoding="))

	struct mailinfo mi;
	setup_mailinfo(&mi);
 * Another stupid program, this one parsing the headers of an
	msgfile = prefix_filename(prefix, argv[1]);
		else if (!strcmp(argv[1], "--no-inbody-headers"))
		else if (!strcmp(argv[1], "-m") || !strcmp(argv[1], "--message-id"))

		else

	char *msgfile, *patchfile;
	patchfile = prefix_filename(prefix, argv[2]);
	mi.output = stdout;

			mi.use_inbody_headers = 0;
