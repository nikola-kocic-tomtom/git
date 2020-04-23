 * This code is free software; you can redistribute it and/or modify
	ctx.date_mode.type = DATE_NORMAL;
	return got_revision;
#include "test-tool.h"
int cmd__revision_walking(int argc, const char **argv)
}
	if (argc < 2)
	if (prepare_revision_walk(&rev))

	while ((commit = get_revision(&rev)) != NULL) {


	int argc = ARRAY_SIZE(argv) - 1;
 */
 *
 * (C) 2012 Heiko Voigt <hvoigt@hvoigt.net>
	}
	}
	printf("%s\n", sb.buf);
		return 0;
 *
	struct strbuf sb = STRBUF_INIT;
static void print_commit(struct commit *commit)
#include "revision.h"
{



static int run_revision_walk(void)
	strbuf_release(&sb);

		printf("1st\n");
#include "commit.h"
{
		if (!run_revision_walk())
		die("revision walk setup failed");
	format_commit_message(commit, " %m %s", &sb, &ctx);
}
	return 1;
}
	struct pretty_print_context ctx = {0};
	const char *argv[] = {NULL, "--all", NULL};
		return 1;
	struct commit *commit;
		if (!run_revision_walk())

	struct rev_info rev;
	reset_revision_walk();
#include "diff.h"
		got_revision = 1;
 * it under the terms of the GNU General Public License version 2 as
#include "cache.h"
	int got_revision = 0;
			return 1;
{
	setup_revisions(argc, argv, &rev, NULL);
 * published by the Free Software Foundation.
/*
		print_commit(commit);
	setup_git_directory();

	fprintf(stderr, "check usage\n");


		printf("2nd\n");
	if (!strcmp(argv[1], "run-twice")) {
	repo_init_revisions(the_repository, &rev, NULL);
 * test-revision-walking.c: test revision walking API.
			return 1;
