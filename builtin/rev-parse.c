		show_rev(symmetric ? NORMAL : REVERSED, &start_oid, start);
		"--parents",
					if (work_tree)
			continue;
					}
		return 0;
				}
				    strcmp(val, "input") &&
	}
	if (include_rev)
				struct commit *commit = pop_commit(&exclude);
		"--no-min-parents",
	static int keep_dashdash = 0, stop_at_non_option = 0;
		strbuf_addf(parsed, " -%c", o->short_name);
		if (dotdot[2])
	else
			switch (dwim_ref(name, strlen(name), &discard, &full)) {
	struct object_context unused;
			o->help = xstrdup(skipspaces(sb.buf));
}
		return 0;
			a = lookup_commit_reference(the_repository, &start_oid);
		} else
		    (str[len-1] == '=' && !strncmp(arg, str, len)))
			if (skip_prefix(arg, "--before=", &arg)) {
						strbuf_realpath(&realpath, gitdir, 1);
{
			}
				continue;
			if (!strcmp(arg, "--default")) {
/*
	return 0;

	}
			show(arg);
				/* Pass on the "--" if we show anything but files.. */
	show(buffer);
				filter &= ~DO_NOREV;
		NULL
				o->flags |= PARSE_OPT_OPTARG;

					if (pfx) {
 * Copyright (C) Linus Torvalds, 2005
					if (!prefix) {

				const char *gitdir = getenv(GIT_DIR_ENVIRONMENT);
			if (verify)

				filter &= ~(DO_FLAGS|DO_NOREV);
				handle_ref_opt(arg, "refs/remotes/");
			if (opt_with_value(arg, "--remotes", &arg)) {
	static const char head_by_default[] = "HEAD";
		git_config(git_default_config, NULL);
					pfx = strchr(pfx, '/');
			putchar(ch);
		"--pretty",
						puts(gitdir);
				show_datestring("--min-age=", arg);
						struct strbuf realpath = STRBUF_INIT;
	/* date handling requires both flags and revs */
		o->type = OPTION_CALLBACK;
				verify_filename(prefix, arg, 0);
			if (!gitdir)
			}
				continue;
		const char *str = *p++;
		if (*arg++ == '=') {
		"--remotes=",
				 * refs spelled in full, and they would
	start = arg;
			struct commit *a, *b;
		s = strpbrk(sb.buf, flag_chars);
	if (pattern)
			}
			show_rev(NORMAL, &oid, s);
					const char *path = git_path("sharedindex.%s", oid_to_hex(oid));
			struct object_id discard;
						printf("../");
			if (!strcmp(arg, "--all")) {

		while ((ch = *arg++)) {

			if ((filter & DO_FLAGS) && (filter & DO_REVS)) {

				printf("%s\n", is_inside_git_dir() ? "true"
static int abbrev_ref_strict;
				continue;
	if (get_oid_committish(arg, &oid) ||
	while (isspace(*s))
			puts(relative_path(git_path("%s", argv[i + 1]),
			git_config(git_default_config, NULL);
						is_repository_shallow(the_repository) ? "true"

				if (arg[2] == 'g') {	/* --git-dir */

			if (!strcmp(arg, "--no-revs")) {
	if (start == head_by_default && end == head_by_default &&
		}
			case '*':
				puts(the_hash_algo->name);
			continue;
	int i, as_is = 0, verify = 0, quiet = 0, revs_count = 0, type = 0;
				continue;
static int abbrev_ref;
				show_type ^= REVERSED;
	struct object_id end_oid;
static const char *def;
	for (i = 1; i < argc; i++) {
	if (argc < 1 || strcmp(argv[0], "--"))
			continue;
			has_dashdash = 1;
		}
		}

	int include_parents = 0;
	static struct option parseopt_opts[] = {
			}
			}
		if (try_parent_shorthands(arg))
				const char *pfx = prefix;
}
	if (quiet)
						continue;
				if (work_tree)
		o->help = xstrdup(skipspaces(help+1));
	}
	}
			continue;
{
}
		}
			if (skip_prefix(arg, "--after=", &arg)) {
		"--no-merges",

				as_is = 2;
	int has_dashdash = 0;
			continue;
				show_datestring("--max-age=", arg);
#define SHOW_SYMBOLIC_FULL 2



				die("-n requires an argument");
		}
		return 0;
	if ((symbolic || abbrev_ref) && name) {
			}
	if (!get_oid_committish(start, &start_oid) && !get_oid_committish(end, &end_oid)) {
				}
					  flags, &oid, &unused)) {
			if (!strcmp(arg, "--sq")) {
		/* Not a flag argument */

				show_datestring("--min-age=", arg);
					if (!gitdir && !prefix)
		putchar(' ');
{
	*dotdot = '.';
					   prefix, &buf));
						pfx++;
			continue;
	for (i = 1; i < argc; i++) {
static const char builtin_rev_parse_usage[] =
			o->long_name = xmemdupz(sb.buf + 2, s - sb.buf - 2);
				continue;
		*dotdot = '.';
		return 0;
				 * need to filter non-refs if we did so.
{
#include "refs.h"
	int exclude_parent = 0;
		/* name(s) */
	if ((filter & (DO_FLAGS | DO_REVS)) != (DO_FLAGS | DO_REVS))
					else if (!strcmp(arg, "loose"))
			strbuf_addch(parsed, '=');
			if (!strcmp(arg, "--symbolic")) {
		}
		if (!*arg) {
				continue;
		"--no-max-parents",
	if (argc == 1) {
		if (!strcmp(argv[i], "--")) {
	}
					puts(work_tree);
{
		"--date-order",
		return;
		def = NULL;
	char *buffer;
				continue;
	const char *start;
		"--header",
			return (char*)s;
		if (symmetric) {
}
		*dotdot = '^';
			if (!strcmp(arg, "--not")) {
		NULL
	if (output_sq) {
						: "false");
	if (unset)
						puts(realpath.buf);
				handle_ref_opt(arg, NULL);
		int len;
static void show(const char *arg)
			continue;
		}
		 */
				printf("%s\n", is_inside_work_tree() ? "true"
		if (symbolic)
	} else if ((dotdot = strstr(arg, "^-"))) {
	return 0;
				strbuf_release(&superproject);
	int parent_number;
				continue;
					}
	struct object_id oid;
	const int hexsz = the_hash_algo->hexsz;
			*value = NULL;

				die("--git-path requires an argument");
						: "false");
			}
			}
		putchar('^');
				continue;
				if (!def)
		"--ignore-missing",
		if (isspace(*s))
		show_rev(NORMAL, &oid, arg);
						gitdir = ".git";
				error("refname '%s' is ambiguous", name);
				filter &= ~DO_NONFLAGS;
					const char *work_tree =
			case '?':
				filter &= ~DO_FLAGS;
static int abbrev;
 * others are about output format or other details.

				abbrev_ref = 1;
		exit(1);
				continue;
				break;
static const char *skipspaces(const char *s)
				die("not a gitdir '%s'", argv[i]);
	strbuf_addstr(&parsed, " --");
}
static int is_rev_argument(const char *arg)
			if (!strcmp(arg, "--git-common-dir")) {
		}
				if (!prefix)
				continue;
		return 0;
static int try_parent_shorthands(const char *arg)
					}
			continue;
#include "quote.h"
				putchar('\n');
	struct commit *commit;
				printf("%s\n", local_repo_env[i]);
		if (!strcmp("--", sb.buf)) {
		if (s - sb.buf == 1) /* short option only */
		}

#define DO_FLAGS	4

			}
			char *end;
	else
			show_rev(type, &oid, name);
	if (exclude_parent &&
			*value = arg;
   "Run \"git rev-parse --parseopt -h\" for more information on the first usage.");
					}
				for_each_abbrev(arg, show_abbrev, NULL);
			free(fname);
	return 0;

	}
				continue;
		"--branches=",
		"--dense",

				break;
					die("--prefix requires an argument");
			if (++i >= argc)
			if (!strcmp(arg, "--revs-only")) {
	int symmetric;
	else
		if (s < help)
						   prefix, &buf));
	puts(parsed.buf);
static int output_sq;
static int try_difference(const char *arg)
		return 1;
{
			name = xstrfmt("%s^%d", arg, parent_number);
		if (!strcmp(arg,"-n")) {
		name = arg;
	};
			}
		for_each_glob_ref_in(show_reference, pattern, prefix, NULL);

{
				quiet = 1;
						abbrev_ref_strict);
{
	printf("%s\n", buf.buf);

					N_("output in stuck long form")),
			}
				continue;
 * Some arguments are relevant "revision" arguments,
			 &parents->item->object.oid, name);
				o->flags &= ~PARSE_OPT_NOARG;
		if (!get_oid_with_context(the_repository, name,
			break;
	}
	struct strbuf *parsed = o->value;
		show_with_type(type, oid_to_hex(oid));
	else if (o->short_name && (o->long_name == NULL || !stuck_long))
		OPT_BOOL(0, "stop-at-non-option", &stop_at_non_option,
		if (!get_oid(s, &oid)) {
	sq_quote_argv(&parsed, argv);

		puts(arg);
/*
static int cmd_sq_quote(int argc, const char **argv)
				o->flags |= PARSE_OPT_HIDDEN;
	                     PARSE_OPT_KEEP_DASHDASH);

		die("Needed a single revision");
			char *fname = prefix_filename(prefix, arg);
			break;
		if (!stuck_long)
	     parents;

	while (strbuf_getline(&sb, stdin) != EOF) {
				handle_ref_opt(arg, "refs/heads/");
					show_file(arg, 0);
 */
		}
			}
			show(fname);
	if ((filter & (DO_NONFLAGS|DO_NOREV)) == (DO_NONFLAGS|DO_NOREV)) {
	strbuf_release(&buf);
	} else

	    !symmetric) {
static int show_default(void)
			if (unb < 1)
		strbuf_addf(parsed, " --no-%s", o->long_name);
N_("git rev-parse --parseopt [<options>] -- [<args>...]\n"
			if (!strcmp(arg, "--verify")) {
	if (filter & (is_rev_argument(arg) ? DO_REVS : DO_NOREV)) {
		return 1;
	*dotdot = '^';
				 * Not found -- not a ref.  We could
			int i;

	int output_prefix = 0;
#include "cache.h"
	int include_rev = 0;
			case 0:
			}
	struct option *opts = NULL;
static void show_datestring(const char *flag, const char *datestr)
			}
				else if (hexsz <= abbrev)

				continue;
				return 0;
		show_rev(include_parents ? NORMAL : REVERSED,

#include "commit.h"
		"--max-count=",
			if (!strcmp(arg, "--symbolic-full-name")) {
			if (!strcmp(arg, "--quiet") || !strcmp(arg, "-q")) {
}
		show(arg);
					continue;
				*dotdot = '.';
	return 0;

				verify = 1;
				for_each_fullref_in("refs/bisect/good", anti_reference, NULL, 0);
	if (type != show_type)
			if (skip_prefix(arg, "--glob=", &arg)) {
				puts(relative_path(get_git_common_dir(),
		return 0;
			PARSE_OPT_SHELL_EVAL);
				die("--resolve-git-dir requires an argument");
		"--max-parents=",
			if (opt_with_value(arg, "--show-object-format", &arg)) {
		return;
					die("this operation must be run in a work tree");
	if (dotdot == arg)
				printf("%s\n",
				revs_count++;
		if (exclude_parent && parent_number != exclude_parent)
static int show_abbrev(const struct object_id *oid, void *cb_data)
			const char *prefix = startup_info->prefix;
		if (s == NULL)
				} else {		/* --absolute-git-dir */

			case '=':
	for (; *s; s++)
	if (!*end)
		memset(opts + onb, 0, sizeof(opts[onb]));
		"--unpacked",
	char *dotdot;
}
			}
#include "commit-reach.h"
				continue;


	if (!(filter & DO_REVS))
			b = lookup_commit_reference(the_repository, &end_oid);
		if (has_dashdash)
			while (exclude) {
		"--remotes",
	if (argc > 1 && !strcmp("--parseopt", argv[1]))
	} else if ((dotdot = strstr(arg, "^@"))) {
{
			return 0;
		}
				continue;
				continue;
				show_rev(type, &oid, name);
#include "diff.h"
	def = NULL;
	if (skip_prefix(arg, opt, &arg)) {
				continue;
	/* accept -<digit>, like traditional "head" */
				cwd = xgetcwd();
		help = findspace(sb.buf);
{
				int len;
					putchar('\n');
	return 0;
{
				show(arg);
					    arg);
			if (!strcmp(arg, "--is-shallow-repository")) {
			puts(gitdir);
		*dotdot = '.';
		die_no_single_rev(quiet);

 */

				add_ref_exclusion(&ref_excludes, arg);

	const char *name = NULL;
	else
			}
}
		}
				free(cwd);
		if (!show_file(arg, output_prefix))
				return 0;

		"--glob=",
		*help = '\0';

				abbrev = DEFAULT_ABBREV;
	end += symmetric;
		if (!sb.len)
			s = help;
			o->argh = xmemdupz(s, help - s);
#include "config.h"
			}
	if ((dotdot = strstr(arg, "^!"))) {
		}
	if (argc > 1 && !strcmp("-h", argv[1]))
	for (;;) {

				continue;
{
		o->value = &parsed;
					full = shorten_unambiguous_ref(full,
			o->long_name = xmemdupz(sb.buf, s - sb.buf);


			show_with_type(type, name);
static int symbolic;
				else
				continue;

				show_datestring("--max-age=", arg);
   "   or: git rev-parse [<options>] [<arg>...]\n"
					N_("keep the `--` passed as an arg")),
			strbuf_addch(parsed, ' ');
	show_rev(REVERSED, oid, refname);
				abbrev = strtoul(arg, NULL, 10);
	*dotdot = 0;
		} else if (revs_count == 0 && show_default())
			case 1: /* happy */
		type = NORMAL;
		if (!strcmp(arg, "--resolve-git-dir")) {
			if (!strcmp(arg, "--flags")) {
		}
			o->short_name = *sb.buf;
	show_default();
			if (opt_with_value(arg, "--tags", &arg)) {
				continue;
			if (!strcmp(arg, "--prefix")) {
				continue;
			if (show_flag(arg) && verify)

			}
	return 0;
					continue;
	int onb = 0, osz = 0, unb = 0, usz = 0;
				continue;
	if (ref_excluded(ref_excludes, refname))
	struct strbuf buf = STRBUF_INIT;
	int did_repo_setup = 0;
		start = head_by_default;
				continue;
		if (starts_with(arg, "-n")) {

		usage_with_options(parseopt_usage, parseopt_opts);
		"--bisect",
			prefix = setup_git_directory();
			}
			}
	if (argc)
		OPT_BOOL(0, "stuck-long", &stuck_long,
	show_rev(NORMAL, oid, refname);

static void show_rev(int type, const struct object_id *oid, const char *name)
static int filter = ~0;
		s++;
				else
			const char *gitdir = argv[++i];
	*dotdot = 0;
#define SHOW_SYMBOLIC_ASIS 1
		"--tags=",
			usage[unb] = NULL;
		return 0;
			return 1;

			continue;
		if (output_prefix) {
		show_rev(NORMAL, &end_oid, end);

	};
		o->callback = &parseopt_dump;
			if (skip_prefix(arg, "--until=", &arg)) {
						    arg);
				const char *work_tree = get_git_work_tree();
	const char **usage = NULL;
		const char *s;

			name++;
				if (filter & (DO_FLAGS | DO_REVS))
	if (!(dotdot = strstr(arg, "..")))
	static const char * const flag_chars = "*=?!";
	return 0;
				filter &= ~(DO_FLAGS|DO_NOREV);
			type = REVERSED;
			if (!strcmp(arg, "--shared-index-path")) {

{
		char *name = NULL;
				prefix = argv[++i];

	return NULL;
		"--all",
			if (!strcmp(arg, "--is-bare-repository")) {
			if (ch == sq)
	const char **p = rev_args;
{
		strbuf_addf(parsed, " --%s", o->long_name);
			else
		int sq = '\'', ch;
				fputs("'\\'", stdout);
	static const char *rev_args[] = {
#include "split-index.h"
#include "submodule.h"
	return 0;
			if (opt_with_value(arg, "--abbrev-ref", &arg)) {

			if (skip_prefix(arg, "--disambiguate=", &arg)) {
#define NORMAL 0
				show_with_type(type, full);
			if (!strcmp(arg, "--is-inside-git-dir")) {
				startup_info->prefix = prefix;
				continue;
			if (!strcmp(arg, "--show-cdup")) {
			if ((filter & DO_FLAGS) && (filter & DO_REVS))
			if (show_file(arg, output_prefix) && as_is < 2)
static int show_file(const char *arg, int output_prefix)
	argc = parse_options(argc, argv, prefix, opts, usage,
				o->flags |= PARSE_OPT_NONEG;
			if (!strcmp(arg, "--no-flags")) {
			switch (*s++) {
			char *full;
	if (arg) {
	}
			}
 */
	char *dotdot;
				def = argv[++i];
	struct strbuf buf = STRBUF_INIT;
	unsigned int flags = 0;
	for (parents = commit->parents, parent_number = 1;
	else if (abbrev)
			}
			    !strcmp(arg, "--absolute-git-dir")) {
		sq_quote_buf(parsed, arg);
				printf("%s%s.git\n", cwd, len && cwd[len-1] != '/' ? "/" : "");
					else
	}
					die(_("Could not read the index"));
				continue;
	return s;
					const struct object_id *oid = &the_index.split_index->base_oid;
				printf("%s\n", is_bare_repository() ? "true"
			i++;
}
}
	argc = parse_options(argc, argv, prefix, parseopt_opts, parseopt_usage,
			return 0;
		include_parents = 1;
	     parents = parents->next, parent_number++) {

		if (strbuf_getline(&sb, stdin) == EOF)
	const char *s = def;
		ALLOC_GROW(usage, unb + 1, usz);
}
			}
				output_prefix = 1;
	return 1;
		}
#include "builtin.h"
			die("premature end of input");
				continue;
#define DO_REVS		1
				continue;
		for_each_ref_in(prefix, show_reference, NULL);
static int show_type = NORMAL;
	show_rev(NORMAL, oid, NULL);
	end = dotdot + 2;
/* Like show(), but with a negation prefix according to type */
 * Parse "opt" or "opt=<value>", setting value respectively to either
			}
		include_rev = 1;
				show(arg);
			return 0;
			}
	for (;;) {

			if (!strcmp(arg, "--git-dir") ||
						die("unknown mode for --abbrev-ref: %s",
		*dotdot = '^';
   "\n"
					die("unknown mode for --show-object-format: %s",
			s--;
				flags |= GET_OID_QUIETLY;
				filter &= ~DO_REVS;
		"--tags",
{
			break;
		return cmd_parseopt(argc - 1, argv + 1, prefix);
					abbrev = MINIMUM_ABBREV;
				clear_ref_exclusion(&ref_excludes);
static int cmd_parseopt(int argc, const char **argv, const char *prefix)
static int show_flag(const char *arg)
		include_rev = 1;
}
			struct commit_list *exclude;
			continue;
 *
		if (!strcmp(arg, "--local-env-vars")) {
		if (!strcmp(arg, str) ||
				if (!is_inside_work_tree()) {
static int anti_reference(const char *refname, const struct object_id *oid, int flag, void *cb_data)
		setup_git_directory();
					   "first non-option argument")),
	struct object_id start_oid;
				len = strlen(cwd);

			exclude = get_merge_bases(a, b);
	return 0;
	} else
#include "revision.h"
		else if (o->long_name)
						strbuf_release(&realpath);
		 * pathspec for the parent directory.
		if (!did_repo_setup) {
			die("bad revision '%s'", arg);
			continue;
			if (!strcmp(arg, "--show-toplevel")) {
static char *findspace(const char *s)
		const char *arg = argv[i];
		"--max-age=",
				die("no usage string given before the `--' separator");
			return 0;
			}
					puts(prefix);
		}
		} else {

	return 0;
				output_sq = 1;
			return 1;
		if (!strcmp(arg, "--git-path")) {
				}
				continue;
		if (*arg == '-') {
	struct strbuf sb = STRBUF_INIT, parsed = STRBUF_INIT;
		sq_quote_argv(&buf, argv);
			for (i = 0; local_repo_env[i]; i++)
/* Output a revision, only if filter allows it */

		 * Just ".."?  That is not a range but the
				continue;
		usage[unb++] = strbuf_detach(&sb, NULL);
				verify = 1;
		N_("git rev-parse --parseopt [<options>] -- [<args>...]"),
			}
}
				break;
			}
				if (arg) {
		/* The rest of the options require a git repository. */
					if (gitdir) {
			}
	}

		}
		return 1;
	struct object_id oid;
	strbuf_release(&sb);
		if (*arg == '^') {
			}
{
	memset(opts + onb, 0, sizeof(opts[onb]));

		/* flags */
					if (!strcmp(arg, "strict"))
		verify_filename(prefix, arg, 1);
 * rev-parse.c
	/* parse: (<short>|<short>,<long>|<long>)[*=?!]*<arghint>? SP+ <help> */
	/* get the usage up to the first line with a -- on it */

		ALLOC_GROW(opts, onb + 1, osz);
			(keep_dashdash ? PARSE_OPT_KEEP_DASHDASH : 0) |
				if (abbrev_ref)
#define USE_THE_INDEX_COMPATIBILITY_MACROS
			}
}
		if (dotdot[2]) {
		OPT_END(),
					strbuf_reset(&buf);
				continue;
				die_no_single_rev(quiet);

				if (get_superproject_working_tree(&superproject))
				continue;
{
						: "false");
	/* No options; just report on whether we're in a git repo or not. */
				o->flags &= ~PARSE_OPT_NOARG;
static int parseopt_dump(const struct option *o, const char *arg, int unset)
	/* put an OPT_END() */

			gitdir = resolve_gitdir(gitdir);
			if (!strcmp(arg, "--show-superproject-working-tree")) {
		"--sparse",
	    exclude_parent > commit_list_count(commit->parents)) {
			if (!a || !b) {
}
			if (!strcmp(arg, "--show-prefix")) {
		"--branches",
			}
		exclude_parent = 1;
	    !(commit = lookup_commit_reference(the_repository, &oid))) {
				continue;
}
			if (opt_with_value(arg, "--short", &arg)) {
	else
		else if (sb.buf[1] != ',') /* long option only */
			}
				 * emit "name" here, but symbolic-full
		if (symbolic == SHOW_SYMBOLIC_FULL || abbrev_ref) {
		"--min-parents=",
	strbuf_release(&buf);
}
				continue;
		/*
			}
/* Output argument as a string, either SQ or normal */
   "   or: git rev-parse --sq-quote [<arg>...]\n"
				if (strcmp(val, "storage") &&
	clear_ref_exclusion(&ref_excludes);
static struct string_list *ref_excludes;

static void show_with_type(int type, const char *arg)
}
			}
			if (opt_with_value(arg, "--branches", &arg)) {
			if (skip_prefix(arg, "--since=", &arg)) {
		if (try_difference(arg))
						abbrev_ref_strict = 0;
	if (verify) {
				if (abbrev < MINIMUM_ABBREV)
	}
				for_each_ref(show_reference, NULL);
	free(buffer);
#define REVERSED 1
			}
			}
		"--min-age=",
				continue;
		putchar(sq);

		usage(builtin_rev_parse_usage);
			}
						abbrev_ref_strict = 1;
static int stuck_long;
						: "false");
			continue;
				char *cwd;
			if (!strcmp(arg, "--is-inside-work-tree")) {
						puts(".git");
		struct object_id oid;
					if (gitdir) {
					puts(superproject.buf);


		"--objects-edge",
		if (!help || sb.buf == help) {
			if (!gitdir)
	}
				const char *val = arg ? arg : "storage";
		while (s < help) {
		struct option *o;
		if (!str)
			exclude_parent = strtoul(dotdot + 2, &end, 10);
						continue;

			continue;
				struct strbuf superproject = STRBUF_INIT;
	}
			strbuf_reset(&buf);
	symmetric = (*end == '.');
				}
			return 1;
				for_each_fullref_in("refs/bisect/bad", show_reference, NULL, 0);
#define DO_NONFLAGS	8
		o = &opts[onb++];
						get_git_work_tree();
static int opt_with_value(const char *arg, const char *opt, const char **value)
				continue;
		if (dotdot[2])
					puts(relative_path(path, prefix, &buf));
		len = strlen(str);
/*
	strbuf_addstr(&parsed, "set --");
			case '!':
			if (*end != '\0' || !exclude_parent)
		"--objects",
			die_no_single_rev(quiet);
				continue;
		}
			}
			return 0;
				 */
static int show_reference(const char *refname, const struct object_id *oid, int flag, void *cb_data)
				if (!arg)
}
				strbuf_reset(&buf);
		else {
	ALLOC_GROW(opts, onb + 1, osz);
		if (revs_count == 1) {
			if (skip_prefix(arg, "--exclude=", &arg)) {
static void handle_ref_opt(const char *pattern, const char *prefix)
{
				continue;
				}
					abbrev = hexsz;
				    strcmp(val, "output"))
int cmd_rev_parse(int argc, const char **argv, const char *prefix)
				continue;
					die("--default requires an argument");
				abbrev_ref_strict = warn_ambiguous_refs;
				if (prefix)
		char *help;
				while (pfx) {
	buffer = xstrfmt("%s%"PRItime, flag, approxidate(datestr));
		as_is = 1;
	}
			return 1;
		if (verify)
}
			}

				continue;
	if (!(filter & DO_FLAGS))
		}
				/*
static void die_no_single_rev(int quiet)
		}
				continue;
			did_repo_setup = 1;
		}


			if (!strcmp(arg, "--bisect")) {
				symbolic = SHOW_SYMBOLIC_ASIS;
		OPT_BOOL(0, "keep-dashdash", &keep_dashdash,
		o->flags = PARSE_OPT_NOARG;
{
			o->type = OPTION_GROUP;
		show_with_type(type, find_unique_abbrev(oid, abbrev));
		end = head_by_default;
				continue;
			if (!argv[i + 1])
				symbolic = SHOW_SYMBOLIC_FULL;
			default: /* ambiguous */
		show_default();
			if (!strcmp(arg, "--")) {

	}
	}
	struct commit_list *parents;
	};
			(stop_at_non_option ? PARSE_OPT_STOP_AT_NON_OPTION : 0) |
	if ((*arg == '-') && isdigit(arg[1]))

{
			}
{

{
	const char *end;
	show(arg);
#include "parse-options.h"
 * NULL or the string after "=".
			free(full);

}
			o->short_name = *sb.buf;
 * This sorts it all out.
}
	return 0;
				show_rev(REVERSED, &commit->object.oid, NULL);
		putchar(sq);


			continue;
				handle_ref_opt(arg, "refs/tags/");
		}
						continue;
#define DO_NOREV	2
	}
	static char const * const parseopt_usage[] = {

	if (argc > 1 && !strcmp("--sq-quote", argv[1]))
	return 0;
				 * users are interested in finding the
			}
	}
		free(name);
		return 0;

			}
		if (as_is) {
			}
		"--topo-order",
		return cmd_sq_quote(argc - 2, argv + 2);
		return 1;
	if (s) {
				if (read_cache() < 0)
				if (the_index.split_index) {
						printf("%s\n", work_tree);
					N_("stop parsing after the "
				continue;
/* Output a flag, only if filter allows it. */
				show(argv[i]);
