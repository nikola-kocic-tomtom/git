			warning(_("graft for '%s' unnecessary"),
		struct strbuf result = STRBUF_INIT;
#include "config.h"
				      git_replace_usage, options);
	if (check_ref_valid(&old_oid, &prev, &ref, force)) {

		return error(_("new object is the same as the old one: '%s'"), oid_to_hex(&old_oid));
			       "valid formats are 'short', 'medium' and 'long'"),
		return error(_("not a valid object name: '%s'"), object_ref);
	return had_error;
		parent_end += hexsz + 8; /* "parent " + "hex sha1" + "\n" */
		}
			      git_replace_usage, options);
int cmd_replace(int argc, const char **argv, const char *prefix)


				oid_to_hex(&commit->object.oid));
		if (get_oid(mergetag_data->argv[i], &oid) < 0)
	else if (!force)
}

		MODE_EDIT,
			usage_msg_opt(_("-e needs exactly one argument"),
		strbuf_release(&buf);
	if (format && cmdmode != MODE_LIST)
			  int flag, void *cb_data)

		MODE_LIST,

			return error(_("unable to write object to database"));
	FILE *fp = fopen_or_warn(graft_file, "r");
	ref_transaction_free(transaction);
	return for_each_mergetag(check_one_mergetag, commit, &mergetag_data);
		return error(_("bad mergetag in commit '%s'"), ref);
	data.pattern = pattern;
	if (write_object_file(buf.buf, buf.len, commit_type, &new_oid)) {
			printf("%s -> %s\n", refname, oid_to_hex(oid));
	/*
				   0, NULL, &err) ||
	return 0;
			close(fd);
	const char *pattern;
	strbuf_add(&buf, buffer, size);
	}
	if (fd < 0)
			       struct commit_extra_header *extra,
	if (!fp)
		return error(_("could not parse %s"), old_ref);
	/*
		}
	switch (cmdmode) {
			     object_ref);

		OPT_STRING(0, "format", &format, N_("format"), N_("use this format")),


 * and Carlos Rica <jasampler@gmail.com> that was itself based on
			     replace_ref);


	fclose(fp);
		OPT_CMDMODE('l', "list", &cmdmode, N_("list replace refs"), MODE_LIST),
		}
	const char **p, *full_hex;
		return error(_("cat-file reported failure"));
		MODE_GRAFT,
	int had_error = 0;
	struct strbuf ref = STRBUF_INIT;
	}
	return res;
		return -1;
	enum {
		return for_each_replace_name(argv, delete_replace_ref);
	const char *buffer;
	argv_array_push(&cmd.args, "cat-file");
}
	 */
	}

			     oid_to_hex(&old_oid));
static int list_replace_refs(const char *pattern, const char *format)
		if (strbuf_read(&result, cmd.out, the_hash_algo->hexsz + 1) < 0) {
}
	if (delete_ref(NULL, ref, oid, 0))
	N_("git replace [-f] --convert-graft-file"),
	const char **argv;
			continue;
		/* index_fd close()s fd for us */
	unuse_commit_buffer(commit, buffer);
	else if (!strcmp(format, "medium"))
	if (!commit)
	if (!err.len)
	if (get_oid(replace_ref, &repl))
			     replace_ref, type_name(repl_type));
{
		if (fn(full_hex, ref.buf, &oid))
	const char *format = NULL;
		usage_msg_opt(_("--format cannot be used when not listing"),
{
	strbuf_release(&err);
			printf("%s\n", refname);
	N_("git replace [-f] --edit <object>"),
{
 * Based on builtin/tag.c by Kristian Høgsberg <krh@redhat.com>
}
	return replace_object_oid(object_ref, &old_oid, "replacement", &new_oid, force);
	struct object_id prev;
		warning(_("the signature will be removed in the replacement commit!"));
static int check_one_mergetag(struct commit *commit,
	case MODE_DELETE:

	struct check_mergetag_data *mergetag_data = (struct check_mergetag_data *)data;
	read_replace_refs = 0;
	for (i = 1; i < mergetag_data->argc; i++) {
	struct tag *tag;
	parent_end = parent_start;
#include "builtin.h"
static int export_object(const struct object_id *oid, enum object_type type,
{
};

#include "run-command.h"
		return -1;
	struct object_id old_oid, new_oid;
		return unlink_or_warn(graft_file);
static int convert_graft_file(int force)
	obj_type = oid_object_info(the_repository, object, NULL);
		int flags = HASH_FORMAT_CHECK | HASH_WRITE_OBJECT;

		return error(_("Objects must be of the same type.\n"
		cmd.in = fd;
		OPT_CMDMODE('d', "delete", &cmdmode, N_("delete replace refs"), MODE_DELETE),
	    ref_transaction_commit(transaction, &err))
			return error(_("could not parse %s as a commit"), argv[i]);
		cmdmode = argc ? MODE_REPLACE : MODE_LIST;
			  const struct object_id *oid,
			   PARSE_OPT_NOCOMPLETE),
			usage_msg_opt(_("-d needs at least one argument"),
 * git-tag.sh and mktag.c by Linus Torvalds.
		MODE_UNSPECIFIED = 0,
	git_config(git_default_config, NULL);
			if (get_oid(refname, &object))
	hash_object_file(the_hash_algo, extra->value, extra->len,
		else if (data->format == REPLACE_FORMAT_MEDIUM)
	return replace_object_oid(object_ref, &object, replace_ref, &repl, force);
	parent_start += hexsz + 6; /* "tree " + "hex sha1" + "\n" */
		if (argc > 1)

		     oid_to_hex(&tag_oid));


/*
		if (args.argc && create_graft(args.argc, args.argv, force, 1))
			return -1;

	}
#include "object-store.h"
		return -1;
			repl_type = oid_object_info(r, oid, NULL);
{
			  int raw, const char *filename)
			error_errno(_("unable to read from mktree"));
		free(tmpfile);
	if (get_oid(old_ref, &old_oid) < 0)
	int force = 0;

		return replace_object(argv[0], argv[1], force);

				    const struct object_id *oid);

			       "'%s' points to a replaced object of type '%s'\n"
	strbuf_splice(buf, parent_start - buf->buf, parent_end - parent_start,
			      git_replace_usage, options);
	if (raw && cmdmode != MODE_EDIT)
struct check_mergetag_data {
		usage_msg_opt(_("--raw only makes sense with --edit"),
 * interpreting it as "type", and writing the result to the object database.
	struct strbuf buf = STRBUF_INIT, err = STRBUF_INIT;
		if (argc < 1)
	}
	argv_array_push(&cmd.args, "--no-replace-objects");

	return 0;
 * The sha1 of the written object is returned via sha1.
		if (argc < 1)
		return error_errno(_("unable to open %s for writing"), filename);
		free(tmpfile);
	enum object_type obj_type, repl_type;
		return -1;
		if (start_command(&cmd)) {
	    cmdmode != MODE_CONVERT_GRAFT_FILE)
	if (get_oid(object_ref, &object))
	struct strbuf err = STRBUF_INIT;
		OPT_CMDMODE(0, "convert-graft-file", &cmdmode, N_("convert existing graft file"), MODE_CONVERT_GRAFT_FILE),
			struct object_id object;
	while (strbuf_getline(&buf, fp) != EOF) {
};
 *

		if (gentle) {

}
	tmpfile = git_pathdup("REPLACE_EDITOBJ");
	return 0;
		}
		const char *argv[] = { "mktree", NULL };
{
	return 0;
};
	if (check_ref_valid(object, &prev, &ref, force)) {
	if (fd < 0)
static int check_ref_valid(struct object_id *object,

	if (check_mergetags(commit, argc, argv)) {

	struct object_id old_oid, new_oid, prev;
		}
			return error(_("unable to spawn mktree"));
		if (index_fd(the_repository->index, oid, fd, &st, type, NULL, flags) < 0)
		data.format = REPLACE_FORMAT_SHORT;
#include "cache.h"
	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	unsigned long size;
			usage_msg_opt(_("-g needs at least one argument"),
	else
			       struct object_id *repl,
	strbuf_release(&ref);
	mergetag_data.argv = argv;
	REPLACE_FORMAT_LONG


	int fd;
	int i;
	REPLACE_FORMAT_MEDIUM,
			 type_name(OBJ_TAG), &tag_oid);
			enum object_type obj_type, repl_type;
	case MODE_CONVERT_GRAFT_FILE:
	if (export_object(&old_oid, type, raw, tmpfile)) {
	if (check_refname_format(ref->buf, 0))
	    cmdmode != MODE_REPLACE &&
		return 1;
static int edit_and_replace(const char *object_ref, int force, int raw)
	}
			had_error = 1;
			return 0; /* found */
}

	strbuf_release(&new_parents);
		return error(_("not a valid object name: '%s'"), old_ref);


		}

	if (!tag)
		if (!commit) {

	struct child_process cmd = CHILD_PROCESS_INIT;
		argv_array_push(&cmd.args, type_name(type));
#include "tag.h"
		strbuf_release(&ref);
static int show_reference(struct repository *r, const char *refname,

 */
	strbuf_reset(ref);
		strbuf_addf(&new_parents, "parent %s\n", oid_to_hex(&commit->object.oid));
			     oid_to_hex(&commit->object.oid));
		if (oideq(get_tagged_oid(tag), &oid))
		cmd.out = -1;

		}
	cmd.out = fd;
		cmd.argv = argv;
#include "refs.h"
	enum replace_format format;
	strbuf_release(&buf);
		return error(_("failed to resolve '%s' as a valid ref"),
		struct child_process cmd = CHILD_PROCESS_INIT;
{
		return -1;

	int i;

static int replace_object(const char *object_ref, const char *replace_ref, int force)
			close(cmd.out);
	struct strbuf ref = STRBUF_INIT;
			continue;
static int create_graft(int argc, const char **argv, int force, int gentle)
static int import_object(struct object_id *oid, enum object_type type,
	}
	struct object_id object, repl;

		strbuf_release(&ref);

	if (pattern == NULL)
	/* find existing parents */
		argv_array_push(&cmd.args, "-p");
/*

	free(tmpfile);

		oidclr(prev);
			    struct object_id *prev,
	struct strbuf buf = STRBUF_INIT;
{
		data.format = REPLACE_FORMAT_LONG;
	case MODE_REPLACE:
	 */
{
		OPT_BOOL_F('f', "force", &force, N_("replace the ref if it exists"),
		if (get_oid(argv[i], &oid) < 0) {
	warning(_("could not convert the following graft(s):\n%s"), err.buf);
{
	advice_graft_file_deprecated = 0;
{
typedef int (*each_replace_name_fn)(const char *name, const char *ref,
	}
	N_("git replace [--format=<format>] [-l [<pattern>]]"),
	enum object_type type;
	struct object_id tag_oid;

		return error(_("invalid replace format '%s'\n"
	cmd.git_cmd = 1;
		strbuf_addstr(&ref, oid_to_hex(&oid));
	const char *graft_file = get_graft_file(the_repository);
	if (oideq(&old_oid, &new_oid))
		}

			     old_ref);
	int fd;

		struct commit *commit;
		OPT_CMDMODE('e', "edit", &cmdmode, N_("edit existing object"), MODE_EDIT),
static int replace_object_oid(const char *object_ref,

	case MODE_EDIT:
		if (argc != 1)
			close(fd);
static const char * const git_replace_usage[] = {
			error("failed to resolve '%s' as a valid ref", *p);
	}
		OPT_BOOL(0, "raw", &raw, N_("do not pretty-print contents for --edit")),
	    ref_transaction_update(transaction, ref.buf, repl, &prev,


			had_error = 1;
		else { /* data->format == REPLACE_FORMAT_LONG */
	strbuf_release(&ref);
		BUG("invalid cmdmode %d", (int)cmdmode);
	struct argv_array args = ARGV_ARRAY_INIT;


		warning(_("the original commit '%s' has a gpg signature"), old_ref);
		strbuf_setlen(&ref, base_len);
		res = error("%s", err.buf);
		MODE_DELETE,
			strbuf_addf(&err, "\n\t%s", buf.buf);
		struct stat st;
		usage_msg_opt(_("-f only makes sense when writing a replacement"),
}
				      git_replace_usage, options);
	return replace_object_oid(old_ref, &commit->object.oid,

	if (remove_signature(&buf)) {
	}
	argv_array_push(&cmd.args, oid_to_hex(oid));
				  "replacement", &new_oid, force);
	struct strbuf new_parents = STRBUF_INIT;

}

		return -1;
}
		OPT_CMDMODE('g', "graft", &cmdmode, N_("change a commit's parents"), MODE_GRAFT),
	const char *parent_start, *parent_end;
/*
			       "type '%s'."),
#include "repository.h"
 * Write the contents of the object named by "sha1" to the file "filename".

	    cmdmode != MODE_EDIT &&
static int replace_parents(struct strbuf *buf, int argc, const char **argv)
			strbuf_release(&new_parents);
			return -1;

			  int raw, const char *filename)

{
	strbuf_addf(ref, "%s%s", git_replace_ref_base, oid_to_hex(object));
		struct object_id oid;

	if (!wildmatch(data->pattern, refname, 0)) {


	if (import_object(&new_oid, type, raw, tmpfile)) {

	/* replace existing parents with new ones */
			error(_("replace ref '%s' not found"), full_hex);
			printf("%s (%s) -> %s (%s)\n", refname, type_name(obj_type),
	}
	while (starts_with(parent_end, "parent "))
	mergetag_data.argc = argc;
			close(fd);
		return error_errno(_("unable to open %s for reading"), filename);

			     object_ref, type_name(obj_type),
	const char *ref = mergetag_data->argv[0];
		OPT_END()
		strbuf_release(&buf);
	if (parse_tag_buffer(the_repository, tag, extra->value, extra->len))
		if (finish_command(&cmd)) {



	}
	int res = 0;

			error_errno(_("unable to fstat %s"), filename);
			usage_msg_opt(_("--convert-graft-file takes no argument"),
			usage_msg_opt(_("only one pattern can be given with -l"),
	int argc;


		cmd.git_cmd = 1;
{
	base_len = ref.len;
	N_("git replace [-f] <object> <replacement>"),
 */
		close(cmd.out);
				      git_replace_usage, options);
		return -1;
	strbuf_release(&ref);

	if (format == NULL || *format == '\0' || !strcmp(format, "short"))
		strbuf_release(&result);
			return error(_("not a valid object name: '%s'"),
	const unsigned hexsz = the_hash_algo->hexsz;
			return error(_("mktree reported failure"));
			return 0;
			strbuf_release(&new_parents);
	case MODE_GRAFT:
	 * No need to close(fd) here; both run-command and index-fd
	struct check_mergetag_data mergetag_data;
	} cmdmode = MODE_UNSPECIFIED;
}
				      git_replace_usage, options);
	else
 */
	N_("git replace [-f] --graft <commit> [<parent>...]"),
			       struct object_id *object,
	if (raw)
		return error(_("unable to get object type for %s"),
		return error(_("replace ref '%s' already exists"), ref->buf);
	}
		if (argc != 0)
		MODE_CONVERT_GRAFT_FILE,

	if (!transaction ||
			      git_replace_usage, options);
	if (!cmdmode)

		if (*buf.buf == '#')
	 * you add new format
		}
	struct ref_transaction *transaction;
	if (read_ref(ref->buf, prev))
	tag = lookup_tag(the_repository, &tag_oid);
	if (!force && obj_type != repl_type)
static int for_each_replace_name(const char **argv, each_replace_name_fn fn)

			       int force)
		MODE_REPLACE
	/* iterate over new parents */
	strbuf_addstr(&ref, git_replace_ref_base);
				      git_replace_usage, options);
		if (argc != 2)
			return error(_("not a valid object name: '%s'"),
		pattern = "*";
		return error(_("failed to resolve '%s' as a valid ref"),

	/* prepare new parents */
			return error(_("mktree did not return an object name"));

			obj_type = oid_object_info(r, &object, NULL);
		struct object_id oid;
{

enum replace_format {
			strbuf_release(&result);
		if (get_oid(*p, &oid)) {
		argv_array_split(&args, buf.buf);
	const char *old_ref = argv[0];
			      const struct object_id *oid)
			       oid_to_hex(oid), type_name(repl_type));
#include "parse-options.h"
	if (oideq(&commit->object.oid, &new_oid)) {
	struct object_id oid;
	} else {
	argc = parse_options(argc, argv, prefix, options, git_replace_usage, 0);
	}
 * Read a previously-exported (and possibly edited) object back from "filename",

			strbuf_release(&result);
			    int force)
	char *tmpfile;
	int raw = 0;
}
		if (get_oid_hex(result.buf, oid) < 0) {
	}
	struct show_data *data = cb_data;
	transaction = ref_transaction_begin(&err);
				return error(_("failed to resolve '%s' as a valid ref"), refname);

static int delete_replace_ref(const char *name, const char *ref,


		       "discarded; use --edit instead of --graft"), ref,

	return 0;
	if (type < 0)
	    cmdmode != MODE_GRAFT &&
	case MODE_LIST:
 * Copyright (c) 2008 Christian Couder <chriscool@tuxfamily.org>
	if (launch_editor(tmpfile, NULL, NULL) < 0) {

	repl_type = oid_object_info(the_repository, repl, NULL);
	if (run_command(&cmd))
	}
	printf_ln(_("Deleted replace ref '%s'"), name);
	if (force &&
		return error(_("malformed mergetag in commit '%s'"), ref);

	if (!raw && type == OBJ_TREE) {
	}
			       void *data)
			    struct strbuf *ref,
 * If "raw" is true, then the object's raw contents are printed according to
	REPLACE_FORMAT_SHORT,


}
}
			had_error = 1;
}
	 * will have done it for us.


	for (p = argv; *p; p++) {
	return error(_("original commit '%s' contains mergetag '%s' that is "
		return edit_and_replace(argv[0], force, raw);
		return error(_("'%s' is not a valid ref name"), ref->buf);
};

	for_each_replace_ref(the_repository, show_reference, (void *)&data);
	size_t base_len;
		}
				     argv[i]);

	for (i = 0; i < argc; i++) {
		      new_parents.buf, new_parents.len);

{
	struct strbuf ref = STRBUF_INIT;
	return 0;


	type = oid_object_info(the_repository, &old_oid, NULL);
		if (fstat(fd, &st) < 0) {
				     mergetag_data->argv[i]);
	commit = lookup_commit_reference(the_repository, &old_oid);
		return create_graft(argc, argv, force, 0);

		return error(_("new commit is the same as the old one: '%s'"),
	N_("git replace -d <object>..."),

	 * Please update _git_replace() in git-completion.bash when
		free(tmpfile);
}
 * Builtin "git replace"
	default:
			       "while '%s' points to a replacement object of "
}

	parent_start = buf->buf;
		if (read_ref(ref.buf, &oid)) {
		strbuf_release(&buf);
{
	return -1;

			usage_msg_opt(_("bad number of arguments"),
	if (replace_parents(&buf, argc - 1, &argv[1]) < 0) {

				      git_replace_usage, options);

	struct commit *commit;
			       const char *replace_ref,
			continue;
	buffer = get_commit_buffer(commit, &size);
	if (get_oid(object_ref, &old_oid) < 0)
	struct show_data data;
		if (data->format == REPLACE_FORMAT_SHORT)
		commit = lookup_commit_reference(the_repository, &oid);
		full_hex = ref.buf + base_len;
	};

	fd = open(filename, O_RDONLY);

		data.format = REPLACE_FORMAT_MEDIUM;
		argv_array_clear(&args);
 *
		return list_replace_refs(argv[0], format);
	NULL
		return error(_("editing object file failed"));
		return error(_("could not write replacement commit for: '%s'"),
		return !!convert_graft_file(force);
	return 0;
		}
	struct option options[] = {
	else if (!strcmp(format, "long"))
static int check_mergetags(struct commit *commit, int argc, const char **argv)
 * "type". Otherwise, we pretty-print the contents for human editing.
	strbuf_release(&buf);
			     format);
struct show_data {

