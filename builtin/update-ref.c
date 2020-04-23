#include "parse-options.h"
	strbuf_release(&err);
	    "%s %s: unexpected end of input when reading <newvalue>",
	return next;
	die(flags & PARSE_SHA1_OLD ?
 */
		} else {
		(*next)++;
	if (*next != line_termination)

		else if (skip_prefix(next, "option ", &next))
	if (!refname)
	}

			next = parse_cmd_update(transaction, &input, next);
#include "refs.h"

 * return 0.  If there is no argument at all (not even the empty
		(*next)++;
	argc = parse_options(argc, argv, prefix, options, git_update_ref_usage,
	struct object_id old_oid;
				   have_old ? &old_oid : NULL,
			line_termination = '\0';
	int create_reflog = 0;
				  default_flags | create_reflog_flag,
		*next += ref.len;
};
			die("empty command in input");

#include "argv-array.h"
			die("badly quoted argument: %s", orig);
/*

		if (**next != ' ')
	update_flags = default_flags;
static const char *parse_cmd_create(struct ref_transaction *transaction,
 * If there is an argument, convert it to a SHA-1, write it to sha1,
		if (delete || argc > 0)
static const char *msg;
	} else {
	if (is_null_oid(&new_oid))
}
	char *refname;
		die("option unknown: %s", next);
}
		 * NULL_SHA1 as "don't care" here:

	return rest;
	int have_old;
	if (check_refname_format(ref.buf, REFNAME_ALLOW_ONELEVEL))



			die("delete %s: zero <oldvalue>", refname);
				  (oldval && !is_null_oid(&oldoid)) ? &oldoid : NULL,
				command, refname);
 * explanatory message if there are any parsing problems.  All of
		die("create %s: extra input: %s", refname, next);
	refname = parse_refname(input, &next);
			usage_with_options(git_update_ref_usage, options);
static char *parse_refname(struct strbuf *input, const char **next)
	have_old = !parse_next_oid(input, &next, &old_oid, "update", refname,
	refname = parse_refname(input, &next);
		else if (isspace(*next))
		die("create %s: missing <newvalue>", refname);
	N_("git update-ref [<options>] -d <refname> [<old-val>]"),
}

	} else {

	struct strbuf err = STRBUF_INIT;
	return strbuf_detach(&ref, NULL);
			oidclr(&oldoid);

	if (ref_transaction_delete(transaction, refname,
 * Parse the reference name immediately after "command SP".  If not
				   update_flags | create_reflog_flag,
static const char *parse_cmd_delete(struct ref_transaction *transaction,
	    "%s %s: invalid <newvalue>: %s",
		update_flags = default_flags;
	free(refname);
	char *refname;
			/* With -z, treat an empty value as all zeros: */
 */
static int parse_next_oid(struct strbuf *input, const char **next,
	if (*next != line_termination)
	if (no_deref) {
	struct strbuf ref = STRBUF_INIT;
 * an error.  Update *next to point at the character that terminates
	if (ref_transaction_create(transaction, refname, &new_oid,
		else
		/* With -z, read the next NUL-terminated line */

		OPT_BOOL('z', NULL, &end_null, N_("stdin has NUL-terminated arguments")),
		die("update %s: missing <newvalue>", refname);
	int ret = 0;
}
			if (get_oid(arg.buf, oid))

{

		} else {
static char line_termination = '\n';
	if (parse_next_oid(input, &next, &new_oid, "create", refname, 0))
		else if (skip_prefix(next, "update ", &next))
			return 1;
}
	    "%s %s: unexpected end of input when reading <oldvalue>" :
}
				   update_flags, &err))
		 * For purposes of backwards compatibility, we treat
static const char * const git_update_ref_usage[] = {

		} else if (flags & PARSE_SHA1_ALLOW_EMPTY) {
			die("%s", err.buf);

	free(refname);
	NULL
			 * unspecified:
	if (parse_next_oid(input, &next, &old_oid, "delete", refname,
			warning("%s %s: missing <newvalue>, treating as zero",
		OPT_END(),
				goto invalid;
			    command, refname, *next);
	strbuf_release(&err);
	next = input.buf;
	die(flags & PARSE_SHA1_OLD ?
		die("verify %s: extra input: %s", refname, next);
#include "config.h"
		strbuf_addstr(&arg, *next);
	refname = parse_refname(input, &next);
	if (*next == '"') {
		die("%s", err.buf);
		return NULL;
	struct object_id new_oid, old_oid;
			   PARSE_SHA1_OLD))
		*next = parse_arg(*next, &ref);
 * <newvalue> in binary mode to be equivalent to specifying zeros.
 */
 * depending on how line_termination is set.
			     0);
			  struct object_id *oid,
{
		*next += arg.len;
{
/*

			die("%s: not a valid old SHA1", oldval);
		die("%s", err.buf);

		goto eof;
		oidclr(&old_oid);
		*next = parse_arg(*next, &arg);
		transaction = ref_transaction_begin(&err);
				    struct strbuf *input, const char *next)
			next = parse_cmd_verify(transaction, &input, next);

	if (!refname)
	if (delete) {
			goto eof;
	if (ref_transaction_verify(transaction, refname, &old_oid,
		return update_ref(msg, refname, &oid, oldval ? &oldoid : NULL,
{
	    command, refname);
	if (*next == input->buf + input->len)
				  UPDATE_REFS_DIE_ON_ERR);
		if (unquote_c_style(arg, next, &next))
			/*
 * difference affects which error messages are generated):
 * Die if there is an error in how the argument is C-quoted.  This
	strbuf_release(&arg);
	update_flags = default_flags;
	struct strbuf err = STRBUF_INIT;
		OPT_BOOL( 0 , "stdin", &read_stdin, N_("read updates from stdin")),
			ret = 1;
				goto invalid;
#include "cache.h"
		strbuf_addstr(&ref, *next);
 */
				   PARSE_SHA1_OLD);
		if (argc < 2 || argc > 3)
 * and append the result to arg.  Return a pointer to the terminator.


static const char *parse_cmd_update(struct ref_transaction *transaction,
	} else {
		die("update: missing <ref>");
			    command, refname, *next);
 * these functions handle either text or binary format input,
		if (!*oldval)
	return next;
			   PARSE_SHA1_ALLOW_EMPTY))
		const char *value;
		die("invalid ref format: %s", ref.buf);
	if (!ref.len) {
{
	if (read_stdin) {
		refname = argv[0];
			die("%s %s: expected SP but got: %s",


			die("unexpected character after quoted argument: %s", orig);

			 */
	free(refname);
	update_flags = default_flags;
	strbuf_release(&input);

			next = parse_cmd_delete(transaction, &input, next);
		have_old = 0;
			usage_with_options(git_update_ref_usage, options);

	if (*next != line_termination)
		die("create %s: zero <newvalue>", refname);
}
#define PARSE_SHA1_ALLOW_EMPTY 0x02
 * Parse one whitespace- or NUL-terminated, possibly C-quoted argument
{
			usage_with_options(git_update_ref_usage, options);
{
		refname = argv[0];
			 * With -z, an empty non-required value means
		if (is_null_oid(&old_oid))
/*
		return 0;
#include "builtin.h"
 * The value being parsed is <oldvalue> (as opposed to <newvalue>; the
	if (end_null)

	return ret;
 * The following five parse_cmd_*() functions parse the corresponding

			  int flags)
			 * The empty string implies that the reference
	else
	return next;
	struct object_id new_oid;
	refname = parse_refname(input, &next);
 * to the character terminating the command, and die with an
				   &new_oid, have_old ? &old_oid : NULL,
		oldval = argv[2];
		die("delete: missing <ref>");
				    struct strbuf *input, const char *next)
			die("%s", err.buf);
	}
	}
		if (!transaction)

			/*
 */
	} else {
	if (delete)
	if (ref_transaction_update(transaction, refname,
int cmd_update_ref(int argc, const char **argv, const char *prefix)
		if (end_null)
			oidclr(oid);
	strbuf_release(&err);
		else if (skip_prefix(next, "create ", &next))
		die("create: missing <ref>");
		die("verify: missing <ref>");
	struct object_id old_oid;

		update_flags |= REF_NO_DEREF;
/*


		if (*next && !isspace(*next))
		/* Without -z, use the next argument */
		 */
	free(refname);
}
			oidclr(oid);
		default_flags = REF_NO_DEREF;
		die("update %s: extra input: %s", refname, next);
 */
	int delete = 0, no_deref = 0, read_stdin = 0, end_null = 0;
	N_("git update-ref [<options>] --stdin [-z]"),
		update_refs_stdin(transaction);

		if (argc < 1 || argc > 2)
	const char *next;
		OPT_BOOL( 0 , "no-deref", &no_deref,
static unsigned int default_flags;

			  const char *command, const char *refname,
static const char *parse_cmd_verify(struct ref_transaction *transaction,
 * For backwards compatibility, accept an empty string for update's

		if (ref_transaction_commit(transaction, &err))

 * include PARSE_SHA1_OLD and/or PARSE_SHA1_ALLOW_EMPTY.
	while (next < input.buf + input.len) {
	}
	struct strbuf input = STRBUF_INIT;

static const char *parse_cmd_option(struct strbuf *input, const char *next)



				   update_flags, msg, &err))

		strbuf_release(&ref);
		value = argv[1];
		else if (skip_prefix(next, "verify ", &next))
				    struct strbuf *input, const char *next)
		if (*next == input->buf + input->len)

/*
 * the argument.  Die if C-quoting is malformed or the reference name
static void update_refs_stdin(struct ref_transaction *transaction)
		if (*next == line_termination)
static const char *parse_arg(const char *next, struct strbuf *arg)
		have_old = 1;
		OPT_STRING( 'm', NULL, &msg, N_("reason"), N_("reason of the update")),
	return next;
 * string), return 1 and leave *next unchanged.  If the value is
}
	};
	return next;
 * string containing the name of the reference, or NULL if there was
	create_reflog_flag = create_reflog ? REF_FORCE_CREATE_REFLOG : 0;
				   msg, &err))
	if (skip_prefix(next, "no-deref", &rest) && *rest == line_termination)
			strbuf_addch(arg, *next++);
	int have_old;
 * -z, then handle C-quoting.  Return a pointer to a newly allocated
	char *refname;
	struct strbuf arg = STRBUF_INIT;
		return delete_ref(msg, refname,

	if (oldval) {
		struct ref_transaction *transaction;

				    struct strbuf *input, const char *next)
		ref_transaction_free(transaction);
	} else {
				   msg, &err))
	N_("git update-ref [<options>]    <refname> <new-val> [<old-val>]"),
#include "quote.h"
		strbuf_release(&err);
		die("%s", err.buf);
		/* With -z, use everything up to the next NUL */

	const char *refname, *oldval;
	struct option options[] = {
	git_config(git_default_config, NULL);
static unsigned int update_flags;
static unsigned create_reflog_flag;

	else
	if (msg && !*msg)



		while (*next && !isspace(*next))
		OPT_BOOL( 0 , "create-reflog", &create_reflog, N_("create a reflog")),

	/* Read each line dispatch its command */
	const char *rest;
	if (parse_next_oid(input, &next, &old_oid, "verify", refname,
	}

}
 * command.  In each case, next points at the character following the
 * command name and the following space.  They each return a pointer
		die("%s", err.buf);
		oldval = argv[1];
			die("%s: not a valid SHA1", value);
 * Parse an argument separator followed by the next argument, if any.

		if (arg.len) {
				  default_flags);

	}
		next++;
	}
	struct object_id oid, oldoid;
	    "%s %s: invalid <oldvalue>: %s" :
 * is invalid.
	if (strbuf_read(&input, 0, 1000) < 0)
	update_flags = default_flags;
		die("Refusing to perform update with empty message.");

		}
		if (get_oid(value, &oid))
		const char *orig = next;
		else if (skip_prefix(next, "delete ", &next))
			 */
	if (line_termination) {
			 * must not already exist:

 * provided but cannot be converted to a SHA-1, die.  flags can
			die("unknown command: %s", next);

/*
 * function is only used if not -z.
		if (**next)
				   update_flags | create_reflog_flag,

	}
 * set *next to point at the character terminating the argument, and
	    command, refname, arg.buf);

 eof:
			/* Without -z, an empty value means all zeros: */
	if (parse_next_oid(input, &next, &new_oid, "update", refname,
		die_errno("could not read from stdin");
	struct strbuf err = STRBUF_INIT;
			next = parse_cmd_option(&input, next);

	}
			if (get_oid(arg.buf, oid))

		else if (get_oid(oldval, &oldoid))
		usage_with_options(git_update_ref_usage, options);
		struct strbuf err = STRBUF_INIT;
	if (!refname)
	char *refname;
{
		if (!**next || **next == line_termination)
			die("whitespace before command: %s", next);
	struct strbuf err = STRBUF_INIT;
	}
	if (!refname)
	strbuf_release(&err);
			die("%s %s: expected NUL but got: %s",
 invalid:
		OPT_BOOL('d', NULL, &delete, N_("delete the reference")),

		/*
			   PARSE_SHA1_OLD)) {
					N_("update <refname> not the one it points to")),
#define PARSE_SHA1_OLD 0x01
{
	if (line_termination) {



	if (*next != line_termination)

		if (arg.len) {

		die("delete %s: extra input: %s", refname, next);
			next = parse_cmd_create(transaction, &input, next);
		/* Without -z, consume SP and use next argument */
		}
{
