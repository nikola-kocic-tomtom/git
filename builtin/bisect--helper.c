			res = -1;
	}
		} else {
static int is_expected_rev(const char *expected_hex)
	if (!commit) {
	/*
		res = -1;
				goto finish;
	}
		res = BISECT_OK;

#include "dir.h"
			 N_("update BISECT_HEAD instead of checking out the current commit")),
	return res;
		if (!is_expected_rev(revs[i])) {
	/*
		if (argc > 1)
	} cmdmode = 0;

			strbuf_release(&branch);
	free(bad_ref);
				return error(_("won't bisect on cg-seek'ed tree"));
			return error(_("--bisect-reset requires either no argument or a commit"));
		res = bisect_terms(&terms, argc == 1 ? argv[0] : NULL);
			has_double_dash = 1;
finish:
		}
			const char **argv, int argc)
}
		set_terms(&terms, argv[1], argv[0]);
		if (strbuf_read_file(&branch, git_path_bisect_start(), 0) < 1) {
		goto finish;
static const char vocab_good[] = "good|old";
	};
		if (starts_with(yesno, "N") || starts_with(yesno, "n"))
	return res;

static GIT_PATH_FUNC(git_path_bisect_names, "BISECT_NAMES")
	/*
	}
#include "cache.h"
#include "quote.h"
{
		struct argv_array argv = ARGV_ARRAY_INIT;
			terms->term_bad = xstrdup(arg);
	 * explicitly specify the terms, but we are already starting to
		res = -1;
{
		return -1;

			res = -1;
			     vocab_good, vocab_bad, vocab_good, vocab_bad);
		break;
					 "--", NULL);
}
			 N_("cleanup the bisection state"), BISECT_CLEAN_STATE),
				"%s/%s bisect"), terms->term_bad,
	strbuf_release(&tag);
		CHECK_AND_SET_TERMS,
			 N_("check whether bad or good terms exist"), BISECT_NEXT_CHECK),
	 * In theory, nothing prevents swapping completely good and bad,
	terms->term_bad = strbuf_detach(&str, NULL);
{
			}
}
	switch (cmdmode) {
	fprintf(fp, "# %s: [%s] %s\n", label, oid_to_hex(&commit->object.oid),
	N_("git bisect--helper --write-terms <bad_term> <good_term>"),
		OPT_CMDMODE(0, "bisect-write", &cmdmode,
	int res;
	pathspec_pos = i;
		res = bisect_next_all(the_repository, prefix, no_checkout);

{
static int check_and_set_terms(struct bisect_terms *terms, const char *cmd)
{
		      const char *good)
	char *term_bad;
			terms->term_good = xstrdup(argv[++i]);
			goto finish;

	FILE *fp = NULL;

	 */

#include "parse-options.h"
		CHECK_EXPECTED_REVS,
			 N_("check for expected revs"), CHECK_EXPECTED_REVS),
		warning(_("bisecting only with a %s commit"), terms->term_bad);
	 */


	FILE *fp = NULL;
	N_("git bisect--helper --bisect-check-and-set-terms <command> <good_term> <bad_term>"),
	 */

	int has_term_file = !is_empty_or_missing_file(git_path_bisect_terms());

	}
				terms->term_good);
	return res;
			     PARSE_OPT_KEEP_DASHDASH | PARSE_OPT_KEEP_UNKNOWN);
		return -1;
{
		must_write_terms = 1;
	}
			must_write_terms = 1;
	strbuf_release(&start_head);
		commit_msg.buf);
	res = fprintf(fp, "%s\n%s\n", bad, good);
		} else if (!get_oid(head, &head_oid) &&
}
		set_terms(&terms, argv[3], argv[2]);
		return !!bisect_reset(argc ? argv[0] : NULL);

		strbuf_addf(&tag, "refs/bisect/%s-%s", state, rev);
	return 1;
	int flags, pathspec_pos, res = 0;
	/*
	struct commit *commit;
	 */
		}
	}
					    terms->term_good)) {
	if (!has_term_file) {
	int res = 0;
	}

		return error(_("can't change the meaning of the term '%s'"), term);

		res = !strcmp(term, match);
static int decide_next(const struct bisect_terms *terms,
		res = check_and_set_terms(&terms, argv[0]);
		} else if (!strcmp(arg, "--term-bad") ||

	 * set references named with the default terms, and won't be able
			struct argv_array argv = ARGV_ARRAY_INIT;
		       terms->term_good, terms->term_bad);
		res = -1;
		argv_array_clear(&argv);
			return error(_("'%s' is not a valid commit"), commit);
			 "and %s for the new state.\n"),
		/* Get the rev from where we start. */
		strbuf_rtrim(&branch);
		}
{
			       "Supported options are: "
		OPT_CMDMODE(0, "write-terms", &cmdmode,
		OPT_BOOL(0, "no-checkout", &no_checkout,
		break;
		if (argc > 1)

	int i;
		usage_with_options(git_bisect_helper_usage, options);
		 * translation. The program will only accept English input
};
	free_terms(terms);
	N_("git bisect--helper --bisect-terms [--term-good | --term-old | --term-bad | --term-new]"),
		BISECT_RESET,
		NEXT_ALL = 1,
			must_write_terms = 1;
	struct string_list revs = STRING_LIST_INIT_DUP;
		if (run_command_v_opt(argv.argv, RUN_GIT_CMD)) {
		break;
		goto finish;

	}
	 * but this situation could be confusing and hasn't been tested

{

	}
			goto finish;
	 * enough. Forbid it for now.
			if (run_command_v_opt(argv.argv, RUN_GIT_CMD)) {
	va_list matches;
static const char * const git_bisect_helper_usage[] = {
}
		strbuf_trim(&actual_hex);

	if (fprintf(fp, "git bisect start") < 1) {
			string_list_append(&revs, oid_to_hex(&oid));


			/*
	if (fprintf(fp, "%s\n", orig_args.buf) < 1)
#include "argv-array.h"
{
			return error(_("--bisect-terms requires 0 or 1 argument"));
		       UPDATE_REFS_MSG_ON_ERR)) {
		strbuf_trim(&start_head);
	 * We have to trap this to be able to clean up using
	 * "bisect_auto_next" below may exit or misbehave.
	struct pretty_print_context pp = {0};

	/*

static int write_terms(const char *bad, const char *good)

				      "revision"), arg);
	if (one_of(term, "help", "start", "skip", "next", "reset",
	 */
			return write_terms(terms->term_bad, terms->term_good);
			error(_("could not check out original"
static GIT_PATH_FUNC(git_path_bisect_head, "BISECT_HEAD")
		if (bad_seen) {
	strbuf_release(&bisect_names);

			 N_("write the terms to .git/BISECT_TERMS"), WRITE_TERMS),


			   skip_prefix(arg, "--term-new=", &arg)) {
	for (i = 0; i < rev_nr; i++) {
			string_list_append(&states, terms->term_bad);
		} else if (skip_prefix(arg, "--term-bad=", &arg) ||
		res = bisect_write(argv[0], argv[1], &terms, nolog);
}
static void check_expected_revs(const char **revs, int rev_nr)
	}
	struct strbuf bisect_names = STRBUF_INIT;
	FREE_AND_NULL(terms->term_bad);

			strbuf_addstr(&start_head, head);
	N_("git bisect--helper --bisect-clean-state"),
#include "builtin.h"

	struct object_id oid;
		}
		strbuf_read_file(&start_head, git_path_bisect_start(), 0);
		if (get_oid(start_head.buf, &oid) < 0) {
			free((void *) terms->term_bad);
	case BISECT_NEXT_CHECK:
		res = -1;
	int res;
		goto finish;
	enum {
			return 0;
{
	N_("You need to give me at least one %s and %s revision.\n"
	case BISECT_CLEAN_STATE:
	/*
	char *term_good;
	fp = fopen(git_path_bisect_terms(), "r");


	int i, has_double_dash = 0, must_write_terms = 0, bad_seen = 0;
	if (res)
			     git_bisect_helper_usage,
			if (get_oid(commit_id, &oid) && has_double_dash)

	int no_checkout = 0, res = 0, nolog = 0;
		return error(_("can't use the builtin command '%s' as a term"), term);
	FILE *fp = NULL;

			string_list_append(&states, terms->term_good);

	strbuf_release(&str);
			terms->term_good = xstrdup(arg);
				 revs.items[i].string, terms, 1)) {
	free(new_term);

	}
{
	if (!head)
	default:
			 N_("no log for BISECT_WRITE")),
		printf("%s\n", terms->term_bad);
	struct bisect_terms terms = { .term_good = NULL, .term_bad = NULL };
			"visualize", "view", "replay", "log", "run", "terms", NULL))
			       UPDATE_REFS_MSG_ON_ERR)) {
	return abs(res);
	 */
		       int missing_bad)
 * included in the variable arguments.
		printf(_("Your current terms are %s for the old state\n"
	case WRITE_TERMS:
		if (!get_oid(head, &head_oid) &&
			return error(_("--check-and-set-terms requires 3 arguments"));
	sq_quote_argv(&orig_args, argv);
		WRITE_TERMS,
	char *good_glob = xstrfmt("%s-*", terms->term_good);
				" HEAD '%s'. Try 'git bisect"
			 N_("start the bisect session"), BISECT_START),
		if (!isatty(0))
				res = error(_("checking out '%s' failed."
		if (one_of(cmd, "bad", "good", NULL)) {
		if (bisect_write(states.items[i].string,
	if (!nolog)

	FREE_AND_NULL(terms->term_good);

	if (!strcmp(bad, good))
	if (!fp) {
}

	int res = 0;
		return error("BUG: unknown subcommand '%d'", cmdmode);
static int bisect_write(const char *state, const char *rev,

{
		char *yesno;
	/*
{
	if ((strcmp(orig_term, "bad") && one_of(term, "bad", "new", NULL)) ||
	}
		/*
	if (!cmdmode)
		}
			if (!is_empty_or_missing_file(git_path_head_name()))
		goto finish;
		OPT_END()
	if (no_checkout) {
	fp = fopen(git_path_bisect_log(), "a");

	struct strbuf orig_args = STRBUF_INIT;
		res = error(_("couldn't get the oid of the rev '%s'"), rev);
	struct object_id oid;
	const char *match;


	case CHECK_EXPECTED_REVS:
	if (!is_empty_or_missing_file(git_path_bisect_start())) {
}
	if (fp)
	struct option options[] = {
		fclose(fp);
	 * Check if we are bisecting
		return error(_("'%s' is not a valid term"), term);
	if (one_of(cmd, "skip", "start", "terms", NULL))
		missing_bad = 0;
		 */


			unlink_or_warn(git_path_bisect_expected_rev());
		    !starts_with(head, "refs/heads/")) {
					       start_head.buf);
	}
static GIT_PATH_FUNC(git_path_bisect_ancestors_ok, "BISECT_ANCESTORS_OK")
			set_terms(terms, "bad", "good");
		BISECT_CLEAN_STATE,
	}
		const char *arg = argv[i];
	else if (one_of(option, "--term-bad", "--term-new", NULL))
			return write_terms(terms->term_bad, terms->term_good);

	res = check_refname_format(new_term, 0);
		break;
		 */
						 "<valid-branch>'."),
			must_write_terms = 1;
		res = bisect_start(&terms, no_checkout, argv, argc);
		res = error_errno(_("couldn't open the file '%s'"), git_path_bisect_log());
	if (check_term_format(bad, "bad") || check_term_format(good, "good"))
static const char need_bad_and_good_revision_warning[] =
 */

	N_("git bisect--helper --bisect-reset [<commit>]"),
	strbuf_release(&actual_hex);
	commit = lookup_commit_reference(the_repository, &oid);
		strbuf_addf(&tag, "refs/bisect/%s", state);
	 */
static int one_of(const char *term, ...)
	free(good_glob);
	case CHECK_AND_SET_TERMS:

	if (revs.nr)
	return 0;
		if (argc != 2)
		/*
						 " Try 'git bisect start "
			return error(_("bad HEAD - I need a HEAD"));
		return error(_("please use two different terms"));
		BISECT_WRITE,
	 * to change afterwards.

		OPT_CMDMODE(0, "bisect-clean-state", &cmdmode,
	if (has_term_file && strcmp(cmd, terms->term_bad) &&
	if (!fp) {
	*m_good = 0;
 * Check whether the string `term` belongs to the set of strings
			 * cogito usage, and cogito users should understand
	if (must_write_terms && write_terms(terms->term_bad,
	if (!fp)
			return -1;
#include "refs.h"
}
	int res = 0;
			goto finish;
			 N_("print out the bisect terms"), BISECT_TERMS),
	if (!missing_good && !missing_bad)
		if (argc != 2 && argc != 3)
					     "[--no-checkout] [<bad> [<good>...]] [--] [<paths>...]"),
		 * although this is less optimum.
		fclose(fp);
	NULL
	N_("git bisect--helper --bisect-next-check <good_term> <bad_term> [<term>]"),
		OPT_CMDMODE(0, "bisect-start", &cmdmode,
	case NEXT_ALL:
		return 0;
		return error(_("no terms defined"));

	for_each_glob_ref_in(mark_good, good_glob, "refs/bisect/",
		}
	else
	write_file(git_path_bisect_names(), "%s\n", bisect_names.buf);
static int check_term_format(const char *term, const char *orig_term)
	if (res == BISECT_INTERNAL_SUCCESS_MERGE_BASE)
		if (one_of(cmd, "new", "old", NULL)) {


		} else if (skip_prefix(arg, "--term-good=", &arg) ||
		 (strcmp(orig_term, "good") && one_of(term, "good", "old", NULL)))
		       const char *current_term, int missing_good,
	if (!file_exists(git_path_bisect_head())) {
		}
		BISECT_START
{
	case BISECT_RESET:
	if (is_bare_repository())
};

				die(_("'%s' does not appear to be a valid "
		     int flag, void *cb_data)

#include "run-command.h"
			       "--term-good|--term-old and "
		if (argc != 0)
			free((void *) terms->term_bad);
		BISECT_TERMS,
	if (!strcmp(state, terms->term_bad)) {
	 * Get rid of any old bisect state.

	if (update_ref(NULL, tag.buf, &oid, NULL, 0,
		return error(_(need_bisect_start_warning),

		return error_errno(_("could not open the file BISECT_TERMS"));

	const char *head;
		if (argc != 4 && argc != 5)

	if (res)
			strbuf_reset(&start_head);
{
static const char need_bisect_start_warning[] =

		no_checkout = 1;
static int bisect_terms(struct bisect_terms *terms, const char *option)
finish:
			set_terms(terms, "new", "old");
static GIT_PATH_FUNC(git_path_bisect_terms, "BISECT_TERMS")
	if (!current_term)
	if (!fp)
			 * This error message should only be triggered by
		yesno = git_prompt(_("Are you sure [Y/n]? "), PROMPT_ECHO);
		}

	 * Verify HEAD
		if (!strcmp(argv[i], "--")) {

static int mark_good(const char *refname, const struct object_id *oid,
			res = error(_("invalid ref: '%s'"), start_head.buf);
		 * have bad (or new) but not good (or old). We could bisect
	char *new_term = xstrfmt("refs/bisect/%s", term);
static int bisect_append_log_quoted(const char **argv)
	int res = 0;
			 * it relates to cg-seek.
			 N_("perform 'git bisect next'"), NEXT_ALL),
}
			printf(_("We are not bisecting.\n"));
			 !strcmp(arg, "--term-new")) {
		}
			argv_array_pushl(&argv, "checkout", start_head.buf,

static const char vocab_bad[] = "bad|new";
	if (get_terms(terms))
	return bisect_clean_state();
				" reset <commit>'."), branch.buf);

			     vocab_bad, vocab_good, vocab_bad, vocab_good);
		       struct commit *commit)



	va_end(matches);
	for (i = 0; i < argc; i++) {
	}
		res = !strcmp(actual_hex.buf, expected_hex);
#include "prompt.h"
static int bisect_start(struct bisect_terms *terms, int no_checkout,

			 N_("reset the bisection state"), BISECT_RESET),
		if (update_ref(NULL, "BISECT_HEAD", &oid, NULL, 0,
		OPT_CMDMODE(0, "bisect-next-check", &cmdmode,
			return error(_("--bisect-next-check requires 2 or 3 arguments"));
		goto finish;
		if (argc != 3)
	} else {
			char *commit_id = xstrfmt("%s^{commit}", arg);
		OPT_CMDMODE(0, "next-all", &cmdmode,
	}
	string_list_clear(&revs, 0);
		OPT_CMDMODE(0, "bisect-reset", &cmdmode,
	/*
		if (get_oid_commit(commit, &oid))
static int get_terms(struct bisect_terms *terms)
		} else if (starts_with(arg, "--") &&
			argv_array_clear(&argv);
		 * TRANSLATORS: Make sure to include [Y] and [n] in your
}
static GIT_PATH_FUNC(git_path_bisect_log, "BISECT_LOG")
	fp = fopen(git_path_bisect_terms(), "w");

	if (ref_exists(bad_ref))
	log_commit(fp, "%s", state, commit);
		 * at this point.
		goto finish;
#include "bisect.h"

		return error(_(need_bad_and_good_revision_warning),
		}
			return error(_("--bisect-clean-state requires no arguments"));
	if (get_oid(rev, &oid)) {
	strbuf_getline_lf(&str, fp);
			 N_("write out the bisection state in BISECT_LOG"), BISECT_WRITE),
	if (!is_empty_or_missing_file(git_path_bisect_start()))
/*
	if (option == NULL) {
	} else {
	case BISECT_WRITE:
	return res;
	/*
		return write_terms(argv[0], argv[1]);
	for (i = 0; i < revs.nr; i++) {
}
	struct strbuf str = STRBUF_INIT;
}

{
		if (get_oid("HEAD", &head_oid))
	free((void *)terms->term_bad);
	}
	res |= fclose(fp);
			   skip_prefix(arg, "--term-old=", &arg)) {
	for (i = 0; i < states.nr; i++)
finish:
		return 0;
	 * In case of mistaken revs or checkout error, or signals received,
		} else if (!strcmp(arg, "--term-good") ||
}
	 * "bisect_clean_state".
			free((void *) terms->term_good);
	write_file(git_path_bisect_start(), "%s\n", start_head.buf);
	format_commit_message(commit, "%s", &commit_msg, &pp);

	return res;
		printf("%s\n", terms->term_good);
	struct strbuf start_head = STRBUF_INIT;
	return 0;
int cmd_bisect__helper(int argc, const char **argv, const char *prefix)
static void log_commit(FILE *fp, char *fmt, const char *state,
			return -1;
static int bisect_next_check(const struct bisect_terms *terms,
	if (pathspec_pos < argc - 1)
finish:
		struct object_id oid;
	FILE *fp = fopen(git_path_bisect_log(), "a");
{
		res = bisect_next_check(&terms, argc == 3 ? argv[2] : NULL);
		break;

	} else if (one_of(state, terms->term_good, "skip", NULL)) {
			strbuf_addstr(&start_head, oid_to_hex(&head_oid));
	   "You can use \"git bisect %s\" and \"git bisect %s\" for that.");

}
	strbuf_getline_lf(&str, fp);

	case BISECT_START:
			break;
	for (i = 0; i < argc; i++) {
		} else if (!strcmp(arg, "--no-checkout")) {
	 */
			return 0;
	struct strbuf commit_msg = STRBUF_INIT;
	if (fp)
	if (one_of(option, "--term-good", "--term-old", NULL))
	struct object_id head_oid;
	terms->term_good = strbuf_detach(&str, NULL);
	int missing_good = 1, missing_bad = 1;
		set_terms(&terms, "bad", "good");
	}
			free(commit_id);
			must_write_terms = 1;

		OPT_CMDMODE(0, "check-and-set-terms", &cmdmode,
	terms->term_good = xstrdup(good);
			   skip_prefix(head, "refs/heads/", &head)) {

		return 0;

	while (!res && (match = va_arg(matches, const char *)))
			return error(_("bad HEAD - strange symbolic ref"));
		argv_array_pushl(&argv, "checkout", branch.buf, "--", NULL);
			free((void *) terms->term_good);
			     const char *current_term)
		if (!strcmp(argv[i], "--")) {
}
			 */
	res = bisect_append_log_quoted(argv);
		return error(_("Invalid command: you're currently in a "

		OPT_CMDMODE(0, "bisect-terms", &cmdmode,
static GIT_PATH_FUNC(git_path_bisect_expected_rev, "BISECT_EXPECTED_REV")
	if (bisect_clean_state())

		return 0;
	strbuf_release(&commit_msg);
			 !one_of(arg, "--term-good", "--term-bad", NULL)) {
			terms->term_bad = xstrdup(argv[++i]);
	struct string_list states = STRING_LIST_INIT_DUP;
			return error(_("unrecognized option: '%s'"), arg);
		return 0;

			return error(_("--bisect-write requires either 4 or 5 arguments"));
		res = error(_("Bad bisect_write argument: %s"), state);
static GIT_PATH_FUNC(git_path_head_name, "head-name")
	N_("git bisect--helper --bisect-write [--no-log] <state> <revision> <good_term> <bad_term>"),
		strbuf_addstr(&branch, commit);


		}
struct bisect_terms {
	free_terms(&terms);
	return res;
			     (void *) &missing_good);
	if (strbuf_read_file(&actual_hex, git_path_bisect_expected_rev(), 0) >= 40) {
	   "You can use \"git bisect %s\" and \"git bisect %s\" for that.");

	terms->term_bad = xstrdup(bad);
	return decide_next(terms, current_term, missing_good, missing_bad);
	int res = 0;
	head = resolve_ref_unsafe("HEAD", 0, &head_oid, &flags);
	char *label = xstrfmt(fmt, state);

		sq_quote_argv(&bisect_names, argv + pathspec_pos);
			return error(_("--write-terms requires two arguments"));

	}
			       "--term-bad|--term-new."), option);
	 * Check for one bad and then some good revisions
		set_terms(&terms, argv[2], argv[1]);

		OPT_CMDMODE(0, "check-expected-revs", &cmdmode,
static void set_terms(struct bisect_terms *terms, const char *bad,

	N_("git bisect--helper --bisect-start [--term-{old,good}=<term> --term-{new,bad}=<term>]"

		}
		return -1;
	fclose(fp);
			unlink_or_warn(git_path_bisect_ancestors_ok());
	va_start(matches, term);
		res = -1;

		/* Reset to the rev from where we started */
		}
	 * Write new start state
		res = -1;
}
			break;
			bad_seen = 1;
		check_expected_revs(argv, argc);
	} else {
		OPT_BOOL(0, "no-log", &nolog,
		goto finish;
	struct strbuf actual_hex = STRBUF_INIT;
static GIT_PATH_FUNC(git_path_bisect_start, "BISECT_START")
		fprintf(fp, "git bisect %s %s\n", state, rev);
			 N_("check and set terms in a bisection state"), CHECK_AND_SET_TERMS),
	    strcmp(cmd, terms->term_good))
	struct strbuf branch = STRBUF_INIT;
	return (res < 0) ? -1 : 0;
	 * The user ran "git bisect start <sha1> <sha1>", hence did not
			const struct bisect_terms *terms, int nolog)
static void free_terms(struct bisect_terms *terms)
	strbuf_release(&orig_args);
}

	 */
		} else {
static int bisect_reset(const char *commit)
LAST_ARG_MUST_BE_NULL
	argc = parse_options(argc, argv, prefix, options,
	struct strbuf tag = STRBUF_INIT;
		BISECT_NEXT_CHECK,
	if (missing_good && !missing_bad &&
			 !strcmp(arg, "--term-old")) {
	return 0;
	free((void *)terms->term_good);
		return bisect_clean_state();
	char *bad_ref = xstrfmt("refs/bisect/%s", terms->term_bad);
	N_("git bisect--helper --next-all [--no-checkout]"),


	strbuf_release(&branch);
	int *m_good = (int *)cb_data;
			no_checkout = 1;
		if (!no_checkout) {
}
	case BISECT_TERMS:
	string_list_clear(&states, 0);
	   "You then need to give me at least one %s and %s revision.\n"

	 * From check_merge_bases > check_good_are_ancestors_of_bad > bisect_next_all
	free(label);
	    !strcmp(current_term, terms->term_good)) {
{
	 * Handle early success
	else
	N_("You need to start by \"git bisect start\".\n"
		} else {
		break;
		return error(_("invalid argument %s for 'git bisect terms'.\n"
		return -1;
	}
{
