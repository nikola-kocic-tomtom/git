		fprintf(f, "%s%s", i > 0 ? " " : "", i > 0 ? argv[i] : "ssh:");
	return run_command_v_opt(child_argv, RUN_USING_SHELL);
	const char *trash_directory = getenv("TRASH_DIRECTORY");
	child_argv[0] = argv[argc - 1];
	int i;
	fprintf(f, "\n");

#include "run-command.h"
	FILE *f;


	/* First, print all parameters into $TRASH_DIRECTORY/ssh-output */
	/* Now, evaluate the *last* parameter */
int cmd_main(int argc, const char **argv)
	const char *child_argv[] = { NULL, NULL };
	if (!trash_directory)
		die("Need a TRASH_DIRECTORY!");
		die("Could not write to %s", buf.buf);
	strbuf_addf(&buf, "%s/ssh-output", trash_directory);
#include "git-compat-util.h"
		return 0;
	struct strbuf buf = STRBUF_INIT;
{
	fclose(f);
	if (!f)
	if (argc < 2)
#include "strbuf.h"
}
	for (i = 0; i < argc; i++)
	f = fopen(buf.buf, "w");
