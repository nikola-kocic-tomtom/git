	return 0;

	N_("\nWrite a message for tag:\n  %s\n"
	int status;
		return error(_("unable to write tag file"));
		die(_("tag '%s' already exists"), tag);
		       struct strbuf *buf, struct create_tag_options *opt,
}
	if (cmdmode == 'v') {
		return;

	}
		    git_committer_info(IDENT_STRICT));
		OPT_END()
				strbuf_commented_addf(&buf, _(tag_template), tag, comment_line_char);
	if (!strcmp(var, "tag.forcesignannotated")) {
			exit(1);
#include "run-command.h"
	"Lines starting with '%c' will be ignored.\n");
int cmd_tag(int argc, const char **argv, const char *prefix)
	struct msg_arg *msg = opt->value;

		int fd;
	if (format->format)
		die(_("unable to parse format string"));
 * Copyright (c) 2007 Kristian Høgsberg <krh@redhat.com>,

	if (filter.merge_commit)
{
			cmdmode = 'l';
	return check_refname_format(sb->buf, 0);
}

		return;
}
	git_config(git_tag_config, sorting_tail);
		OPT_STRING('u', "local-user", &keyid, N_("key-id"),
	if (!arg)
		return git_column_config(var, value, "tag", &colopts);
	if (status)
		{

	}
			run_column_filter(colopts, &copts);
	if (!transaction ||
static int strbuf_check_tag_ref(struct strbuf *sb, const char *name)
		return for_each_tag_name(argv, verify_tag, &format);
		OPT_CLEANUP(&cleanup_arg),
		} else if (!is_null_oid(prev)) {

		  N_("tag message"), PARSE_OPT_NONEG, parse_msg_arg },

		if (read_ref(ref.buf, &oid)) {

					die_errno(_("could not open or read '%s'"),
{
			strbuf_reset(buf);
			_("Please supply the message using either -m or -F option.\n"));
		OPT_CMDMODE('d', "delete", &cmdmode, N_("delete tags"), 'd'),
		colopts = 0;
	struct strbuf reflog_msg = STRBUF_INIT;
		if (launch_editor(path, buf, NULL)) {


		break;
		}
		else {

		strbuf_addstr(sb, "tree object");
	}
			stop_column_filter();
		if ((buf = read_object_file(oid, &type, &size)) != NULL) {
	if (filter.no_commit)
			fprintf(stderr, _("The tag message has been left in %s\n"),
	}
	status = git_gpg_config(var, value, cb);
	if (cmdmode == 'd')
		OPT_FILENAME('F', "file", &msgfile, N_("read message from file")),
	struct ref_format format = REF_FORMAT_INIT;
	}
	tag = argv[0];
	}
	char *rla = getenv("GIT_REFLOG_ACTION");
		die("%s", err.buf);
		if (filter->lines) {
	memset(&opt, 0, sizeof(opt));
	const struct ref_format *format = cb_data;
		break;
	if (msg->buf.len)
		    "tagger %s\n\n",
		strbuf_addstr(sb, "tag: tagging ");
{
		OPT_MERGED(&filter, N_("print only tags that are merged")),
	struct ref_array array;
		free(buf);
}
#include "column.h"
		advise_if_enabled(ADVICE_NESTED_TAG, _(message_advice_nested_tag),
	flags = GPG_VERIFY_VERBOSE;
		close(fd);
	int icase = 0;
				N_("print <n> lines of each tag message"),
		OPT_GROUP(N_("Tag listing options")),
{
		show_ref_array_item(array.items[i], format);

	unsigned long size;

						msgfile);
		die(_("'%s' is not a valid tag name."), tag);
		printf(_("Updated tag '%s' (was %s)\n"), tag,
	struct ref_sorting **sorting_tail = (struct ref_sorting **)cb;
	default:
		die(_("--no-contains option is only allowed in list mode"));
	struct strbuf buf;
	char *buf, *sp;
	   "\tgit tag -f %s %s^{}");
		usage_with_options(git_tag_usage, options);
	return 0;
	struct option options[] = {
static const char message_advice_nested_tag[] =
	opt.message_given = msg.given || msgfile;
		die(_("Invalid cleanup mode %s"), cleanup_arg);
		die(_("--contains option is only allowed in list mode"));
	strbuf_addstr(sb, " (");
	N_("git tag [-a | -s | -u <key-id>] [-f] [-m <msg> | -F <file>]\n"
#include "object-store.h"
		break;
	filter.lines = -1;
	if (keyid) {
	    ref_transaction_update(transaction, ref.buf, &object, &prev,
};
					  "%(align:15)%(refname:lstrip=2)%(end)",
		OPT__FORCE(&force, N_("replace the tag if exists"), 0),
			strbuf_addstr(sb, "commit object");
{
			subject_len = find_commit_subject(buf, &subject_start);
			if (!strcmp(msgfile, "-")) {
	}
		if (msg.given && msgfile)
				  tag, object_ref);
		strbuf_addstr(sb, "blob object");
{
	if (opt.sign == -1)

static const char * const git_tag_usage[] = {
		strbuf_addstr(sb, "other tag object");
	unsigned long size;
		    "type %s\n"
			die_errno(_("could not create file '%s'"), path);
	filter.ignore_case = icase;
		return -1;
		OPT_CMDMODE('v', "verify", &cmdmode, N_("verify tags"), 'v'),
		if ((c = lookup_commit_reference(the_repository, oid)) != NULL)

		opt.cleanup_mode = CLEANUP_ALL;
	unsigned int message_given:1;
	strbuf_addf(&header,
		}

	const char *subject_start;
struct msg_arg {
	if (create_tag_object) {
		int ret;
	strbuf_release(&header);
		free(buf);
	const char *object_ref, *tag;
	return 0;
		return ret;
static void create_reflog_msg(const struct object_id *oid, struct strbuf *sb)
	if (force && !is_null_oid(&prev) && !oideq(&prev, &object))
		"\t\t<tagname> [<head>]"),
	} cleanup_mode;

			format->format = "%(refname:lstrip=2)";
static void write_tag_body(int fd, const struct object_id *oid)
		return 0;
#include "parse-options.h"
		return for_each_tag_name(argv, delete_tag, NULL);
		strbuf_reset(&ref);
	sp += 2; /* skip the 2 LFs */

			     const void *cb_data)
		die(_("too many params"));

			format->format = to_free;
	if (get_oid(object_ref, &object))
			} else {
	int had_error = 0;
	    ref_transaction_commit(transaction, &err))
	if (gpg_verify_tag(oid, name, flags))
	if (write_object_file(buf->buf, buf->len, tag_type, result) < 0)

	if (!sorting)
	if (cmdmode == 'l') {
		strbuf_stripspace(buf, opt->cleanup_mode == CLEANUP_ALL);
		OPT_BOOL('s', "sign", &opt.sign, N_("annotated and GPG-signed tag")),
		CLEANUP_NONE,
	else if (!strcmp(cleanup_arg, "whitespace"))
	unsigned int use_editor:1;
		OPT_NO_CONTAINS(&filter.no_commit, N_("print only tags that don't contain the commit")),

		opt.sign = 1;
					N_("annotated tag, needs a message")),
	if (verify_ref_format(format))
			struct strbuf buf = STRBUF_INIT;


		OPT_CMDMODE('l', "list", &cmdmode, N_("list tag names"), 'l'),
	struct object_id object, prev;
	if (!format->format) {
		flags = GPG_VERIFY_OMIT_STATUS;
			fprintf(stderr,
	if (!cleanup_arg || !strcmp(cleanup_arg, "strip"))
	if (read_ref(ref.buf, &prev))
	NULL


	N_("You have created a nested tag. The object referred to by your new tag is\n"
	return had_error;
	if ((create_tag_object || force) && (cmdmode != 0))
	object_ref = argc == 2 ? argv[1] : "HEAD";
		strbuf_add_unique_abbrev(sb, oid, DEFAULT_ABBREV);
static const char tag_template_nocleanup[] =
			die(_("--column and -n are incompatible"));
	opt.sign = -1;


		OPT_WITH(&filter.with_commit, N_("print only tags that contain the commit")),
			strbuf_addbuf(&buf, &(msg.buf));
		return 1;
		{ OPTION_CALLBACK, 'm', "message", &msg, N_("message"),
	if (name[0] == '-')

	else
#include "revision.h"
		OPT_REF_SORT(sorting_tail),
		filter.name_patterns = argv;
			   N_("format to use for the output")),
	struct strbuf buf = STRBUF_INIT;
	return 0;

{
static int config_sign_tag = -1; /* unspecified */
			write_or_die(fd, buf.buf, buf.len);
		free(path);
	if (msg.given || msgfile) {
				path);
	}
	ref_array_clear(&array);
	strbuf_addch(sb, ')');

		if (argc == 0)
					N_("use another key to sign the tag")),
static int list_tags(struct ref_filter *filter, struct ref_sorting *sorting,
#include "ref-filter.h"
	UNLEAK(ref);
	strbuf_addstr(&(msg->buf), arg);
			return config_error_nonbool(var);
	opt.use_editor = edit_flag;
			had_error = 1;
	if (filter.with_commit)

		OPT_NO_MERGED(&filter, N_("print only tags that are not merged")),
		OPT_BOOL('a', "annotate", &annotate,
	return sign_buffer(buffer, buffer, get_signing_key());
static int do_sign(struct strbuf *buffer)
		/* write the template message before editing: */
#include "diff.h"
	int subject_len = 0;

		} else
	struct ref_transaction *transaction;
	return 0;



		}
		"\t\t[--format=<format>] [--[no-]merged [<commit>]] [<pattern>...]"),
{
	int cmdmode = 0, create_tag_object = 0;
}
	int given;
	}
	case OBJ_BLOB:


		OPT_WITHOUT(&filter.no_commit, N_("print only tags that don't contain the commit")),
		OPT_BOOL('i', "ignore-case", &icase, N_("sorting and filtering are case insensitive")),
			write_or_die(fd, buf->buf, buf->len);
	if (strbuf_check_tag_ref(&ref, tag))
	if (!opt->message_given || opt->use_editor) {
		CLEANUP_ALL
	if (filter.lines != -1)

		     struct ref_format *format)
			}


		fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);


	N_("git tag -l [-n[<num>]] [--contains <commit>] [--no-contains <commit>] [--points-at <object>]\n"
	struct commit *c;

				if (strbuf_read(&buf, 0, 1024) < 0)
		opt.cleanup_mode = CLEANUP_NONE;
	}
		force_sign_annotate = git_config_bool(var, value);

static const char tag_template[] =
		strbuf_addstr(sb, rla);
			 filter.lines != -1)
	if (opt->cleanup_mode != CLEANUP_NONE)

		return 0;
}
	"Lines starting with '%c' will be kept; you may remove them"
#include "oid-array.h"
			strbuf_insert(sb, sb->len, subject_start, subject_len);
	if (delete_ref(NULL, ref, oid, 0))
	}
}
		die(_("--points-at option is only allowed in list mode"));
static void create_tag(const struct object_id *object, const char *object_ref,
		path = git_pathdup("TAG_EDITMSG");
	return 0;
		       const char *tag,
		parse_ref_sorting(sorting_tail, value);
	unsigned int sign;
	}
	if (!buf)
{
	argc = parse_options(argc, argv, prefix, options, git_tag_usage, 0);
			else

	strbuf_reset(sb);
		unlink_or_warn(path);
	sorting->ignore_case = icase;
	case OBJ_TREE:
}
	filter_refs(&array, filter, FILTER_REFS_TAGS);
#include "config.h"
{

	" yourself if you want to.\n");
				strbuf_commented_addf(&buf, _(tag_template_nocleanup), tag, comment_line_char);

	if (sign && do_sign(buf) < 0)
static int git_tag_config(const char *var, const char *value, void *cb)
};

#include "gpg-interface.h"
	printf(_("Deleted tag '%s' (was %s)\n"), name,
				   reflog_msg.buf, &err) ||
		return -1;
		die(_("bad object type."));

		config_sign_tag = git_config_bool(var, value);
	write_or_die(fd, sp, parse_signature(sp, buf + size - sp));
		setup_auto_pager("tag", 1);
				const struct object_id *oid, const void *cb_data);
		if (force_sign_annotate && !annotate)
static int build_tag_object(struct strbuf *buf, int sign, struct object_id *result)
	else if (!force)
	case OBJ_COMMIT:
	}
	const char *msgfile = NULL, *keyid = NULL;
	struct strbuf ref = STRBUF_INIT;
	enum object_type type;
		       find_unique_abbrev(&prev, DEFAULT_ABBREV));
	/* skip header */
static int force_sign_annotate;
	}
		if (fn(*p, ref.buf, &oid, cb_data))

	if (path) {

	const char **p;
		OPT_GROUP(N_("Tag creation options")),
	   "already a tag. If you meant to tag the object that it points to, use:\n"
		} else {
		if (column_active(colopts))
	if (!strcmp(var, "tag.sort")) {
	if (!strcmp(var, "tag.gpgsign")) {
				   create_reflog ? REF_FORCE_CREATE_REFLOG : 0,
		if (fd < 0)
	case OBJ_TAG:
	char *cleanup_arg = NULL;
	if (format->format)
	memset(&array, 0, sizeof(array));
	if (cmdmode == 'l')
		    oid_to_hex(object),

	char *path = NULL;
	for (i = 0; i < array.nr; i++)
	int edit_flag = 0;
}
		OPT_STRING(  0 , "format", &format.format, N_("format"),
	int flags;
					  filter->lines);
		    type_name(type),
	N_("git tag -v [--format=<format>] <tagname>..."),

	struct msg_arg msg = { 0, STRBUF_INIT };
		if (explicitly_enable_column(colopts))
	if (cmdmode == 'l' && filter.lines != -1) {
	strbuf_addf(sb, "refs/tags/%s", name);
#include "refs.h"
		return error(_("unable to sign the tag"));
		sorting = ref_default_sorting();

		opt.sign = cmdmode ? 0 : config_sign_tag > 0;
		break;
	} else {

		CLEANUP_SPACE,
	UNLEAK(err);
	ref_array_sort(sorting, &array);



			if (opt->cleanup_mode == CLEANUP_ALL)
{
 *

			 filter.points_at.nr || filter.merge_commit ||
		}
	N_("\nWrite a message for tag:\n  %s\n"
			cmdmode = 'l';
		if (opt->message_given) {
	if (!sp || !size || type != OBJ_TAG) {
		die(_("--merged and --no-merged options are only allowed in list mode"));
		oidclr(&prev);
static int parse_msg_arg(const struct option *opt, const char *arg, int unset)
		strbuf_addstr(&(msg->buf), "\n\n");
 */
	enum {
			copts.padding = 2;
#include "builtin.h"


		OPT__COLOR(&format.use_color, N_("respect format colors")),
		die(_("Failed to resolve '%s' as a valid ref."), object_ref);
		    "object %s\n"
	if (argc > 2)
	}
		die(_("-n option is only allowed in list mode"));
	if (!cmdmode) {
			write_tag_body(fd, prev);
	int annotate = 0, force = 0;
static int for_each_tag_name(const char **argv, each_tag_name_fn fn,
	if (!opt->message_given && !buf->len)

{
	else if (!strcmp(cleanup_arg, "verbatim"))
			had_error = 1;

	if (build_tag_object(buf, opt->sign, result) < 0) {
	strbuf_insert(buf, 0, header.buf, header.len);
 * Based on git-tag.sh and mktag.c by Linus Torvalds.
	UNLEAK(msg);
	N_("git tag -d <tagname>..."),
		else if (filter.with_commit || filter.no_commit ||

	if (type == OBJ_TAG)
		break;
		OPT_BOOL(0, "create-reflog", &create_reflog, N_("create a reflog")),
			error(_("tag '%s' not found."), *p);
	for (p = argv; *p; p++) {
#include "tag.h"
			strbuf_addf(sb, ", %s", show_date(c->date, 0, DATE_MODE(SHORT)));
			struct column_options copts;
	switch (type) {
static unsigned int colopts;
	struct create_tag_options opt;
	sp = strstr(buf, "\n\n");
			parse_opt_object_name, (intptr_t) "HEAD"
	if (filter.points_at.nr)
			OPTION_CALLBACK, 0, "points-at", &filter.points_at, N_("object"),
static int delete_tag(const char *name, const char *ref,
	}

	struct strbuf err = STRBUF_INIT;
	char *to_free = NULL;
		if (format.format && verify_ref_format(&format))

	   "\n"
		} else {
	struct ref_filter filter;
}
		opt.cleanup_mode = CLEANUP_SPACE;
		create_tag(&object, object_ref, tag, &buf, &opt, &prev, &object);
		},
	struct strbuf header = STRBUF_INIT;
	int create_reflog = 0;
		    tag,
/*
		strbuf_addstr(sb, "object of unknown type");
			memset(&copts, 0, sizeof(copts));
	create_tag_object = (opt.sign || annotate || msg.given || msgfile);
	if (type <= OBJ_NONE)

	       find_unique_abbrev(oid, DEFAULT_ABBREV));


		OPT_CONTAINS(&filter.with_commit, N_("print only tags that contain the commit")),
	UNLEAK(reflog_msg);
	type = oid_object_info(the_repository, object, NULL);
}
	BUG_ON_OPT_NEG(unset);
 * Builtin "git tag"

	free(buf);

	char *buf;
		if (msg.given)
	}

	finalize_colopts(&colopts, -1);
	if (starts_with(var, "column."))
	transaction = ref_transaction_begin(&err);
		return -1;
	if (rla) {
	msg->given = 1;

			die(_("only one -F or -m option is allowed."));
static int verify_tag(const char *name, const char *ref,
typedef int (*each_tag_name_fn)(const char *name, const char *ref,
	type = oid_object_info(the_repository, oid, NULL);

	};

			continue;
	static struct ref_sorting *sorting = NULL, **sorting_tail = &sorting;
			N_("print only tags of the object"), PARSE_OPT_LASTARG_DEFAULT,
}
		      const struct object_id *oid, const void *cb_data)
		if (path)
			to_free = xstrfmt("%s %%(contents:lines=%d)",
	if (filter->lines == -1)
			usage_with_options(git_tag_usage, options);
			opt.sign = 1;
	filter->with_commit_tag_algo = 1;
					die_errno(_("cannot read '%s'"), msgfile);
		}
		exit(128);
		if (column_active(colopts)) {
	create_reflog_msg(&object, &reflog_msg);
		      const struct object_id *oid, const void *cb_data)
	UNLEAK(buf);
	buf = read_object_file(oid, &type, &size);
};
				if (strbuf_read_file(&buf, msgfile, 1024) < 0)
		filter->lines = 0;
		set_signing_key(keyid);
	}
	strbuf_release(&ref);
#include "cache.h"
		strbuf_addf(&ref, "refs/tags/%s", *p);
		       struct object_id *prev, struct object_id *result)
			strbuf_addch(&buf, '\n');
	struct strbuf ref = STRBUF_INIT;
		ret = list_tags(&filter, sorting, &format);

		{ OPTION_INTEGER, 'n', NULL, &filter.lines, N_("n"),
	setup_ref_filter_porcelain_msg();
	return git_color_default_config(var, value, cb);
		    "tag %s\n"
				PARSE_OPT_OPTARG, NULL, 1 },
		return status;

		OPT_BOOL('e', "edit", &edit_flag, N_("force edit of tag message")),

	int i;

	enum object_type type;
	enum object_type type;
		}
	struct object_id oid;
		if (!value)
	free(to_free);
		pretty_print_ref(name, oid, format);
		return 0;
		OPT_COLUMN(0, "column", &colopts, N_("show tag list in columns")),
 *                    Carlos Rica <jasampler@gmail.com>
			strbuf_release(&buf);
struct create_tag_options {

{
	memset(&filter, 0, sizeof(filter));
	ref_transaction_free(transaction);
		die(_("no tag message?"));
}
