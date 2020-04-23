			     "Notes removed by 'git notes add'");
	struct option options[] = {
	free_notes(t);
	};
			"Please use 'git notes add -f -m/-F/-c/-C' instead.\n"));
#include "notes.h"

	struct strbuf msg = STRBUF_INIT;
	free_notes(t);
static const char * const git_notes_list_usage[] = {

	t = init_notes_check("show", 0);
	struct note_data *d = opt->value;
			error(_("the note contents have been left in %s"),
	N_("git notes [--ref <notes-ref>] remove [<object>...]"),
			die(_("please supply the note contents using either -m or -F option"));
			    default_notes_ref(), wt->path);
	while (strbuf_getline_lf(&buf, stdin) != EOF) {
	const char * const *usage;
	unsigned long len;
}
	free_note_data(&d);

	N_("git notes [--ref <notes-ref>] edit [--allow-empty] [<object>]"),
	char *buf;

			die(_("failed to resolve '%s' as a valid ref."), split[1]->buf);
	if (!retval)
	};

		logmsg = xstrfmt("Notes added by 'git notes %s'", argv[0]);
				free_note_data(&d);
			 *
			     PARSE_OPT_KEEP_ARGV0);

	struct notes_tree *t;
	if (argc) {
	} else

		if (argc) {
	else {
	if (get_oid(object_ref, &object))
static void write_commented_object(int fd, const struct object_id *object)
	if (rewrite_cmd) {
			      "--stdin)")),
#include "repository.h"
	return parse_reuse_arg(opt, arg, unset);
	return 0;
	return result < 0; /* return non-zero on conflicts */
	if (from_stdin || rewrite_cmd) {
	else if (parse_commit(partial))

	if (d->edit_path) {
		if (add_note(t, &object, &new_note, combine_notes_overwrite))
	prepare_note_data(&object, &d, note);
	struct option options[] = {
		    oid_to_hex(object));

	t = init_notes_check("add", NOTES_INIT_WRITABLE);
		unlink_or_warn(d->edit_path);
	if (1 < argc) {
	free(buf);
static int list_each_note(const struct object_id *object_oid,
	free(local_ref_to_free);
	strbuf_stripspace(&d->buf, 0);
		strbuf_addch(&buf, '\n');
		free(buf);
	strbuf_grow(&d->buf, strlen(arg) + 2);
	else if (!strcmp(argv[0], "remove"))
		error(_("must specify a notes ref to merge"));
		OPT_GROUP(N_("Merge options")),
#include "exec-cmd.h"
	o.verbosity = verbosity + NOTES_MERGE_VERBOSITY_DEFAULT;
		commit_notes(the_repository, t,

	if (d->use_editor || !d->given) {
 *
	free_notes(t);
	else if (!strcmp(argv[0], "merge"))


	 */
	struct strbuf buf = STRBUF_INIT;
			     0);

		struct strbuf sb = STRBUF_INIT;
		strbuf_addch(&d->buf, '\n');
		{ OPTION_CALLBACK, 'c', "reedit-message", &d, N_("object"),
	return 0;
	int ret = 0;
		OPT_END()
	unsigned long size;
		ret += error(_("failed to delete ref NOTES_MERGE_PARTIAL"));
		oidcpy(&parent_oid, &partial->parents->item->object.oid);

#include "notes-utils.h"
}
	puts(default_notes_ref());
static const char * const git_notes_show_usage[] = {

		{ OPTION_CALLBACK, 'm', "message", &d, N_("message"),
		die(_("failed to resolve '%s' as a valid ref."), object_ref);
	strbuf_release(&msg);
			git_path(NOTES_MERGE_WORKTREE));
	if (d.buf.len || allow_empty) {
	const struct object_id *from_note, *note;
	strbuf_release(&remote_ref);
	strbuf_insertstr(&msg, 0, "notes: ");

	N_("git notes merge --abort [<options>]"),

			retval = error(_("Cannot copy notes. Found existing "
{
	N_("git notes [--ref <notes-ref>] get-ref"),
			     "Notes removed by 'git notes remove'");
	if (2 < argc) {
		usage_with_options(usage, options);
	} else {
			oid_to_hex(&object));
	struct notes_tree *t = NULL;

	strbuf_release(&buf);
		error(_("too many parameters"));
		init_notes(NULL, NULL, NULL, NOTES_INIT_WRITABLE);

{
	}
		error(_("unable to write note object"));
	}
		struct object_id from_obj, to_obj;
	if (buf) {
}
		OPT__VERBOSE(&verbose, N_("report pruned notes")),
	d->use_editor = 1;
	} else {
		OPT_SET_INT_F(0, "abort", &do_abort,
	N_("git notes [list [<object>]]"),
	NULL
	else if (!strcmp(argv[0], "show"))
		OPT_END()
	struct note_data *d = opt->value;
static int remove_one_note(struct notes_tree *t, const char *name, unsigned flag)


		strbuf_release(&buf);
	usage = edit ? git_notes_edit_usage : git_notes_append_usage;
		fprintf(stderr, _("Automatic notes merge failed. Fix conflicts in %s "
	BUG_ON_OPT_NEG(unset);
			N_("reuse specified note object"), PARSE_OPT_NONEG,
	if (d->buf.len)
		} else {
	if (argc) {
	struct note_data d = { 0, 0, NULL, STRBUF_INIT };
			argv[0] = "edit";
	from_note = get_note(t, &from_obj);


}
static void free_note_data(struct note_data *d)
		usage_with_options(git_notes_list_usage, options);
	if (note) {
		logmsg = xstrfmt("Notes removed by 'git notes %s'", argv[0]);
#include "notes-merge.h"
	N_("git notes add [<options>] [<object>]"),

		}
		exit(128);
	if (delete_ref(NULL, "NOTES_MERGE_PARTIAL", NULL, 0))
static int parse_reedit_arg(const struct option *opt, const char *arg, int unset)
	argc = parse_options(argc, argv, prefix, options,
		if (git_config_get_notes_strategy(merge_key.buf, &o.strategy))
				       "overwrite existing notes"),

	free_notes(t);

struct note_data {
	};
	N_("git notes merge [<options>] <notes-ref>"),
	strbuf_release(&cbuf);
			puts(oid_to_hex(note));
		usage_with_options(git_notes_merge_usage, options);
static int merge(int argc, const char **argv, const char *prefix)
		if (create_symref("NOTES_MERGE_REF", default_notes_ref(), NULL))
	object_ref = 1 < argc ? argv[1] : "HEAD";
		const char *short_ref = NULL;
#include "pretty.h"
	}
	if (d->buf.len)

	}
	if (!from_note) {
	memset(&pretty_ctx, 0, sizeof(pretty_ctx));
	unsigned flag = 0;

		}
	if (notes_merge_commit(o, t, partial, &oid))
	argc = parse_options(argc, argv, prefix, options, git_notes_add_usage,
	BUG_ON_OPT_NEG(unset);
	struct pretty_print_context pretty_ctx;
			oid_to_hex(&object));
		OPT__FORCE(&force, N_("replace existing notes"), PARSE_OPT_NOCOMPLETE),

		if (err) {

	if (get_oid("NOTES_MERGE_PARTIAL", &oid))
		OPT_STRING(0, "for-rewrite", &rewrite_cmd, N_("command"),
			   N_("load rewriting config for <command> (implies "
	commit_notes(the_repository, t,
	const char *msg = "Notes added by 'git notes copy'";

			    default_notes_ref());
	else
		strbuf_list_free(split);
			goto out;
	struct object_id object;
	N_("git notes [--ref <notes-ref>] [list [<object>]]"),
		    oid_to_hex(object));
		fprintf(stderr, _("Overwriting existing notes for object %s\n"),
static int git_config_get_notes_strategy(const char *key,
	int verbosity = 0, result;
	note = get_note(t, &object);

		OPT__VERBOSITY(&verbosity),
		OPT_END()
{
	}
	int do_merge = 0, do_commit = 0, do_abort = 0;

static void copy_obj_to_fd(int fd, const struct object_id *oid)
	struct option options[] = {
	o->local_ref = local_ref_to_free =
		/* Append buf to previous note contents */
		die(_("failed to read object '%s'."), arg);

		OPT_END()
	strbuf_addf(&msg, "notes: Merged notes from %s into %s",
	N_("git notes [--ref <notes-ref>] prune [-n] [-v]"),
	strbuf_trim(&msg);
static int list(int argc, const char **argv, const char *prefix)

			    N_("read object names from the standard input")),
}
			parse_reedit_arg},
	}
	free_notes(t);
			parse_reuse_arg},

	return 0;
			parse_msg_arg},
		 */
		error(_("too many parameters"));
		 * TRANSLATORS: the first %s will be replaced by a git
		/*
		die(_("failed to resolve '%s' as a valid ref."), object_ref);
#include "parse-options.h"
		if (d.buf.len && prev_buf && size)
		result = error(_("unknown subcommand: %s"), argv[0]);
static const char * const git_notes_copy_usage[] = {
}
	int ret;
		error(_("too many parameters"));
		strbuf_reset(&d->buf);
	NULL

	/* Reuse existing commit message in reflog message */
	strbuf_stripspace(&d->buf, 0);
		if (!force) {

		if (wt)
			     PARSE_OPT_STOP_AT_NON_OPTION);
	const char *object_ref;
	struct commit *partial;
		die(_("failed to resolve '%s' as a valid ref."), object_ref);
	if (notes_merge_abort(o))
};
	prune_notes(t, (verbose ? NOTES_PRUNE_VERBOSE : 0) |
	argc = parse_options(argc, argv, prefix, options,
		     "Notes added by 'git notes copy'");
		commit_notes(the_repository, t,
	d->given = 1;
		if (rewrite_cmd)
			retval = 0;
			BUG("combine_notes_overwrite failed");
		if (!force) {


		ret += error(_("failed to remove 'git notes merge' worktree"));

};
	return 0;
		split = strbuf_split(&buf, ' ');
		} else
	update_ref(msg.buf, o->local_ref, &oid,
	}

		strbuf_add_commented_lines(&buf, "\n", strlen("\n"));


{
	free_notes(t);
		write_note_data(&d, &new_note);
	N_("Write/edit the notes for the following object:");
static int notes_copy_from_stdin(int force, const char *rewrite_cmd)

		if (note) {
		error(_("too many parameters"));
		OPT__FORCE(&force, N_("replace existing notes"), PARSE_OPT_NOCOMPLETE),
};
		update_ref(msg.buf, default_notes_ref(), &result_oid, NULL, 0,
			     "Notes added by 'git notes add'");
		strbuf_add_commented_lines(&buf, _(note_template), strlen(_(note_template)));


	if (get_oid(argv[0], &from_obj))
			die(_("a notes merge into %s is already in-progress at %s"),

			"for the 'edit' subcommand.\n"

	}
	struct notes_tree *t;

	N_("git notes copy [<options>] <from-object> <to-object>"),
{

	if (argc) {
			    o.local_ref);
	 * Remove .git/NOTES_MERGE_PARTIAL and .git/NOTES_MERGE_REF, and call
		/* write the template message before editing: */
	}
			die(_("failed to resolve '%s' as a valid ref."), split[0]->buf);
	}
		{ OPTION_CALLBACK, 'C', "reuse-message", &d, N_("object"),
					 enum notes_merge_strategy *strategy)
out:
	if (d->buf.len)
	const char *ref;

		const struct object_id *note_oid, char *note_path,
	if (do_commit)
		retval = error(_("no note found for object %s."),
	int edit = !strcmp(argv[0], "edit");
	if (status)
	else { /* Merge has unresolved conflicts */
		OPT__DRY_RUN(&show_only, N_("do not remove, show only")),
		OPT_END()
	struct object_id oid;
	int use_editor;
			usage_with_options(git_notes_copy_usage, options);
		/* Store ref-to-be-updated into .git/NOTES_MERGE_REF */
					   int flags)
	result = notes_merge(&o, t, &result_oid);
	N_("git notes show [<object>]"),
		if (fd < 0)
		strbuf_release(&merge_key);
		argc = parse_options(argc, argv, prefix, options,

static const char * const git_notes_add_usage[] = {

		if (size)
	show.git_cmd = 1;
		/* Update default notes ref with new commit */
	}
	const char *rewrite_cmd = NULL;
	N_("git notes [--ref <notes-ref>] copy [-f] <from-object> <to-object>"),
	int retval = 0;
	t = init_notes_check("prune", NOTES_INIT_WRITABLE);
			       oid_to_hex(&object));
		wt = find_shared_symref("NOTES_MERGE_REF", default_notes_ref());
	init_notes(t, "NOTES_MERGE_PARTIAL", combine_notes_overwrite, 0);

}
	if (d.given && edit)
	struct option options[] = { OPT_END() };
			N_("attempt to remove non-existent note is not an error"),
static const char note_template[] =
			write_or_die(fd, buf, size);
	NULL
}
	}

				  "and commit the result with 'git notes merge --commit', "
			      1, PARSE_OPT_NONEG),
};

};
				d->edit_path);
static int parse_file_arg(const struct option *opt, const char *arg, int unset)
			error(_("failed to copy notes from '%s' to '%s'"),
static int remove_cmd(int argc, const char **argv, const char *prefix)
{
	} else {
		if (add_note(t, &object, &new_note, combine_notes_overwrite))

	N_("git notes merge --abort [-v | -q]"),
	if (!o->local_ref)
	int force = 0, allow_empty = 0;

		return merge_commit(&o);
int cmd_notes(int argc, const char **argv, const char *prefix)
	};
			die_errno(_("could not create file '%s'"), d->edit_path);
	}
}
static int merge_commit(struct notes_merge_options *o)

	format_commit_message(partial, "%s", &msg, &pretty_ctx);
{

		close(fd);
	t = init_notes_check("list", 0);
	struct note_data *d = opt->value;

		update_ref(msg.buf, "NOTES_MERGE_PARTIAL", &result_oid, NULL,
	if (!strcmp(arg, "-")) {
};
			err = copy_note_for_rewrite(c, &from_obj, &to_obj);
			return notes_copy_from_stdin(force, rewrite_cmd);
		free(d->edit_path);
	const char *object_ref;
			die(_("failed to store link to current notes ref (%s)"),
		result = append_edit(argc, argv, prefix);
	char *edit_path;
				       oid_to_hex(&object));
	}
	expand_loose_notes_ref(&remote_ref);
		die_errno(_("could not read 'show' output"));
	return 0;

	};
	const char *object_ref;

		const struct worktree *wt;
};
	};
		die(_("refusing to %s notes in %s (outside of refs/notes/)"),
		error(_("too many parameters"));
		OPT_END()
	write_or_die(fd, cbuf.buf, cbuf.len);
		   0, UPDATE_REFS_DIE_ON_ERR);
			error(_("too many parameters"));
		die(_("could not parse commit from NOTES_MERGE_PARTIAL."));
			     0);

	if (override_notes_ref) {
	strbuf_add(&(o.commit_msg), msg.buf + 7, msg.len - 7); /* skip "notes: " */
}
			      N_("abort notes merge"),
static const char * const git_notes_append_usage[] = {
{

	return ret;
	BUG_ON_OPT_NEG(unset);
	return retval;


	int show_only = 0, verbose = 0;
	free_note_data(&d);
		{ OPTION_CALLBACK, 'F', "file", &d, N_("file"),
	}

			BUG("local ref %s is outside of refs/notes/",
		struct strbuf buf = STRBUF_INIT;
	} else {

		note = get_note(t, &object);

	}
	N_("git notes [--ref <notes-ref>] show [<object>]"),
	struct object_id object, new_note;
	}
		if (launch_editor(d->edit_path, &d->buf, NULL)) {
		t = &default_notes_tree;

static int parse_reuse_arg(const struct option *opt, const char *arg, int unset)

	return 0;
			ret = 1;
			     PARSE_OPT_KEEP_ARGV0);
	if (note && !edit) {
	struct object_id result_oid;
	note = get_note(t, &object);
	NULL

		 * notes command: 'add', 'merge', 'remove', etc.
			usage_with_options(git_notes_merge_usage, options);
			   N_("resolve notes conflicts using the given strategy "
			N_("note contents as a string"), PARSE_OPT_NONEG,
			 */
	object_ref = 1 < argc ? argv[1] : "HEAD";

		usage_with_options(git_notes_add_usage, options);
	NULL
		/* Update .git/NOTES_MERGE_PARTIAL with partial merge result */


{
		resolve_refdup("NOTES_MERGE_REF", 0, &oid, NULL);
		const struct object_id *old_note)
			oid_to_hex(&object));
		fd = open(d->edit_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	int result;
		OPT_BIT(0, "ignore-missing", &flag,

	NULL
		if (!c)
		usage_with_options(git_notes_show_usage, options);
 */
	else if (!strcmp(argv[0], "append") || !strcmp(argv[0], "edit"))
	};
	ret = merge_abort(o);
		free(buf);
	if (do_abort)
			 * argv[0-1].
	show.no_stdin = 1;
	N_("git notes edit [<object>]"),
	t = init_notes_check("merge", NOTES_INIT_WRITABLE);
				     git_notes_list_usage, 0);
			parse_msg_arg},
	N_("git notes prune [<options>]"),
		int fd;
			error(_("unknown -s/--strategy: %s"), strategy);
}
	NULL
			     git_notes_remove_usage, 0);
			 * Redirect to "edit" subcommand.
}
	init_notes(NULL, NULL, NULL, flags);
		error(_("cannot mix --commit, --abort or -s/--strategy"));
 *
	argc = parse_options(argc, argv, prefix, options, git_notes_prune_usage,
	N_("git notes remove [<object>]"),
	argc = parse_options(argc, argv, prefix, options,
	struct strbuf buf;
	const char *show_args[5] =
		ret += error(_("failed to delete ref NOTES_MERGE_REF"));
{

	ref = (flags & NOTES_INIT_WRITABLE) ? t->update_ref : t->ref;
	struct strbuf cbuf = STRBUF_INIT;

			     0);

		usage_with_options(git_notes_copy_usage, options);

		result = get_ref(argc, argv, prefix);
	}
		if (strbuf_read(&d->buf, 0, 1024) < 0)

static int merge_abort(struct notes_merge_options *o)
		OPT_BOOL(0, "allow-empty", &allow_empty,

			strbuf_insert(&d.buf, 0, prev_buf, size);
			parse_reuse_arg},
#include "run-command.h"
	} else {
		write_commented_object(fd, object);
	if (parse_notes_merge_strategy(value, strategy))
		expand_notes_ref(&sb);
	const char *strategy = NULL;
	int status;


	struct option options[] = {
	if (do_merge && argc != 1) {
		strbuf_rtrim(split[1]);
			die_errno(_("cannot read '%s'"), arg);

		error(_("too many parameters"));
		if (prev_buf && size)
			return 0;
	if (delete_ref(NULL, "NOTES_MERGE_REF", NULL, REF_NO_DEREF))
	struct note_data d = { 0, 0, NULL, STRBUF_INIT };
	argc = parse_options(argc, argv, prefix, options, git_notes_show_usage,
{
		commit_notes(the_repository, t,
	free_notes(t);
	NULL
		write_note_data(&d, &new_note);
}
static struct notes_tree *init_notes_check(const char *subcommand,
	N_("git notes [--ref <notes-ref>] add [-f] [--allow-empty] [-m <msg> | -F <file> | (-c | -C) <object>] [<object>]"),
		}
}
};


		fprintf(stderr, _("Object %s has no note\n"), name);
	 * and target notes ref from .git/NOTES_MERGE_REF.
		{ OPTION_CALLBACK, 'm', "message", &d, N_("message"),
		usage_with_options(git_notes_merge_usage, options);


		strbuf_addf(&merge_key, "notes.%s.mergeStrategy", short_ref);
		commit_notes(the_repository, t,
	}
		usage_with_options(git_notes_get_ref_usage, options);
		strbuf_addch(&d->buf, '\n');
			N_("reuse and edit specified note object"), PARSE_OPT_NONEG,
	else {
			 * given. The original args are therefore still in
				       "notes for object %s. Use '-f' to "
					combine_notes_overwrite);
		OPT_BOOL(0, "stdin", &from_stdin,
		OPT_GROUP(N_("Committing unmerged notes")),
			 * We only end up here if none of -m/-F/-c/-C or -f are


				return error(_("Cannot add notes. "
		void *cb_data)
	struct note_data *d = opt->value;
	return (flag & IGNORE_MISSING) ? 0 : status;
	if (do_merge + do_commit + do_abort != 1) {
	struct notes_tree *t;
		else if (old_note)
	if (argc)
	commit_notes(the_repository, t, logmsg);
		while (*argv) {
			     "Notes removed by 'git notes prune'");
	N_("git notes get-ref"),
		{ OPTION_CALLBACK, 'c', "reedit-message", &d, N_("object"),
		c = init_copy_notes_for_rewrite(rewrite_cmd);

}

		if (!skip_prefix(o.local_ref, "refs/notes/", &short_ref))
	t = init_notes_check("copy", NOTES_INIT_WRITABLE);
static int show(int argc, const char **argv, const char *prefix)
		OPT_END()
static const char * const git_notes_get_ref_usage[] = {


		remove_note(t, object.hash);
	free_notes(t);
	if (!(buf = read_object_file(&object, &type, &len)))

		struct strbuf sb = STRBUF_INIT;
#include "object-store.h"
	if (!show_only)
		    remote_ref.buf, default_notes_ref());
#include "cache.h"
	else if (!strcmp(argv[0], "prune"))
	}
			argv++;
 * and builtin/tag.c by Kristian Høgsberg and Carlos Rica.
	};
		strbuf_addch(&d->buf, '\n');
	else if (!(partial = lookup_commit_reference(the_repository, &oid)))
		struct strbuf merge_key = STRBUF_INIT;

	int retval;
}
		finish_copy_notes_for_rewrite(the_repository, c, msg);
			   0, UPDATE_REFS_DIE_ON_ERR);
}
	const struct object_id *note;
	if (strbuf_read(&buf, show.out, 0) < 0)
	struct notes_tree *t;
		usage_with_options(git_notes_prune_usage, options);
		}
	strbuf_add_commented_lines(&cbuf, buf.buf, buf.len);
				       oid_to_hex(&object));
		    subcommand, ref);

		while (strbuf_getwholeline(&sb, stdin, '\n') != EOF) {
	int retval = -1;
}
		die(_("unable to start 'show' for object '%s'"),
	N_("git notes [--ref <notes-ref>] merge [-v | -q] [-s <strategy>] <notes-ref>"),
		fprintf(stderr, _("Overwriting existing notes for object %s\n"),

	return retval;
	struct object_id object;
{
			N_("note contents in a file"), PARSE_OPT_NONEG,
	};
	const struct object_id *note;
	int from_stdin = 0;
		strbuf_grow(&d.buf, size + 1);
		strbuf_release(&sb);
}
	object_ref = argc ? argv[0] : "HEAD";
	t = xcalloc(1, sizeof(struct notes_tree));
	if (1 < argc) {
	N_("git notes copy --stdin [<from-object> <to-object>]..."),
			return append_edit(argc, argv, prefix);

	struct object_id object, from_obj;
		(show_only ? NOTES_PRUNE_VERBOSE|NOTES_PRUNE_DRYRUN : 0) );
		die_errno(_("could not open or read '%s'"), arg);
	}
	}
	t = &default_notes_tree;
	const struct object_id *note;
		OPT_STRING('s', "strategy", &strategy, N_("strategy"),
		result = merge(argc, argv, prefix);
	return ret;
	if (strategy || do_commit + do_abort == 0)
		strbuf_release(&sb);

		OPT_SET_INT_F(0, "commit", &do_commit,
	N_("git notes merge --commit [<options>]"),
	}
	strbuf_add(&d->buf, buf, len);
					"Found existing notes for object %s. "
{
	if (!starts_with(ref, "refs/notes/"))
		if (!split[0] || !split[1])
			/*
	return 0;
	t = init_notes_check("remove", NOTES_INIT_WRITABLE);
		die(_("failed to resolve '%s' as a valid ref."), arg);

 * Builtin "git notes"
/*
static const char * const git_notes_usage[] = {
}
	return retval;
}
};
	} else if (strbuf_read_file(&d->buf, arg, 1024) < 0)
		return error(_("Failed to resolve '%s' as a valid ref."), name);
static const char * const git_notes_merge_usage[] = {
			       "copy."), oid_to_hex(&from_obj));
	free_notes(t);
	return t;
};

	if (argc < 1) {
	prepare_note_data(&object, &d, edit && note ? note : NULL);
		BUG("combine_notes_overwrite failed");
	if (!argc && !from_stdin) {
	object_ref = argc > 1 ? argv[1] : "HEAD";
	N_("git notes merge --commit [-v | -q]"),
			die(_("malformed input line: '%s'."), buf.buf);
		enum object_type type;
		write_or_die(fd, buf.buf, buf.len);
			copy_obj_to_fd(fd, old_note);

	strbuf_release(&msg);


		fprintf(stderr, _("The -m/-F/-c/-C options have been deprecated "

 * Based on git-notes.sh by Johannes Schindelin,
	free(logmsg);
	}
		goto out;
	int retval = 0, force = 0, from_stdin = 0;
	/*
			      N_("finalize notes merge by committing unmerged notes"),
					"Use '-f' to overwrite existing notes"),
		strbuf_stripspace(&d->buf, 1);
			strbuf_insertstr(&d.buf, 0, "\n");
		result = list(argc, argv, prefix);
		setenv("GIT_NOTES_REF", sb.buf, 1);

{
	d->given = 1;
	show.argv = show_args;

	return retval;
{
		OPT_BOOL(0, "stdin", &from_stdin, N_("read objects from stdin")),
{

	return 0;

		free(prev_buf);

		retval = error(_("missing notes on source object %s. Cannot "

			N_("note contents in a file"), PARSE_OPT_NONEG,
			N_("reuse specified note object"), PARSE_OPT_NONEG,
	int allow_empty = 0;
	BUG_ON_OPT_NEG(unset);
}
		die(_("failed to finalize notes merge"));
			N_("reuse and edit specified note object"), PARSE_OPT_NONEG,
	}

	o.local_ref = default_notes_ref();
			}
		retval = for_each_note(t, 0, list_each_note, NULL);

	N_("git notes append [<options>] [<object>]"),
		oidclr(&parent_oid);
	struct object_id oid, parent_oid;
{
			   N_("use notes from <notes-ref>")),
};
		}
{
	struct option options[] = {
			BUG("combine_notes_overwrite failed");

	struct strbuf remote_ref = STRBUF_INIT, msg = STRBUF_INIT;
	struct object_id object, new_note;
	else if (!strcmp(argv[0], "add"))
			N_("allow storing empty note")),
		result = add(argc, argv, prefix);
	if (get_oid(object_ref, &object))
	show.err = 0;
	argc = parse_options(argc, argv, prefix, options, git_notes_usage,
	if (get_oid(name, &oid))


	struct notes_tree *t;
		char *prev_buf = read_object_file(note, &type, &size);
static void write_note_data(struct note_data *d, struct object_id *oid)
}
			err = copy_note(t, &from_obj, &to_obj, force,
	}
	o.remote_ref = remote_ref.buf;
}
		const char *show_args[3] = {"show", oid_to_hex(note), NULL};
		do_merge = 1;
	argc = parse_options(argc, argv, prefix, options, git_notes_copy_usage,
	if (!note)
		result = show(argc, argv, prefix);
	free(value);
	return result ? 1 : 0;
	enum object_type type;


		if (get_oid(argv[0], &object))
	const struct object_id *note;
		commit_notes(the_repository, t, msg);


#include "worktree.h"

	else if (!strcmp(argv[0], "copy"))

		free_notes(t);
		fprintf(stderr, _("Removing note for object %s\n"),

{

	return 0;
		OPT_BOOL(0, "allow-empty", &allow_empty,
			N_("note contents as a string"), PARSE_OPT_NONEG,
		error(_("too few parameters"));
	 */
{
		{"show", "--stat", "--no-notes", oid_to_hex(object), NULL};
}
				  "or abort the merge with 'git notes merge --abort'.\n"),
		error(_("too many parameters"));

	int ret = 0;

	printf("%s %s\n", oid_to_hex(note_oid), oid_to_hex(object_oid));

{
	struct object_id object;

			      split[0]->buf, split[1]->buf);
 * Copyright (c) 2010 Johan Herland <johan@herland.net>
		remove_note(t, object.hash);
		strbuf_rtrim(split[0]);
			oid_to_hex(&object));
		unsigned long size;

		if (d->given)
	else
	 * notes_merge_abort() to remove .git/NOTES_MERGE_WORKTREE.
	if (get_oid(arg, &object))

			retval = error(_("no note found for object %s."),
			     git_notes_merge_usage, 0);
		OPT_END()
		fprintf(stderr, _("Removing note for object %s\n"), name);
			git_config_get_notes_strategy("notes.mergeStrategy", &o.strategy);
static int append_edit(int argc, const char **argv, const char *prefix)
		OPT_STRING(0, "ref", &override_notes_ref, N_("notes-ref"),
	struct notes_rewrite_cfg *c = NULL;
	char *buf = read_object_file(oid, &type, &size);
		die(_("failed to read ref NOTES_MERGE_PARTIAL"));
	if (2 < argc) {

static const char * const git_notes_remove_usage[] = {
	struct notes_tree *t;
	}
#include "refs.h"
			parse_file_arg},
		usage_with_options(git_notes_merge_usage, options);
	struct child_process show = CHILD_PROCESS_INIT;
		OPT_GROUP(N_("Aborting notes merge resolution")),
	}
			die(_("failed to resolve '%s' as a valid ref."), argv[0]);
	if (d.buf.len || allow_empty) {
		return 1;
	if (add_note(t, &object, from_note, combine_notes_overwrite))
		error(_("too many parameters"));
		usage_with_options(git_notes_copy_usage, options);
			retval |= remove_one_note(t, *argv, flag);
	if (get_oid(object_ref, &object))
			parse_reedit_arg},
	note = get_note(t, &object);
	N_("git notes [--ref <notes-ref>] append [--allow-empty] [-m <msg> | -F <file> | (-c | -C) <object>] [<object>]"),
		result = copy(argc, argv, prefix);
static const char * const git_notes_prune_usage[] = {
		else
	if (type != OBJ_BLOB) {
	}
	const char *object_ref;

static void prepare_note_data(const struct object_id *object, struct note_data *d,
	strbuf_addstr(&d->buf, arg);
		retval = remove_one_note(t, "HEAD", flag);

	strbuf_release(&d->buf);
	const char *override_notes_ref = NULL;
			retval |= remove_one_note(t, sb.buf, flag);
	struct notes_tree *t;
	if (2 < argc) {
#define IGNORE_MISSING 1
static const char * const git_notes_edit_usage[] = {
	NULL
		retval = execv_git_cmd(show_args);
			N_("allow storing empty note")),
}
static int parse_msg_arg(const struct option *opt, const char *arg, int unset)
	struct option options[] = {
		result = prune(argc, argv, prefix);
		die(_("could not find commit from NOTES_MERGE_PARTIAL."));


	note = get_note(t, &object);

	char *logmsg;
	t = init_notes_check(argv[0], NOTES_INIT_WRITABLE);
	if (!rewrite_cmd) {
		struct strbuf **split;
	struct option options[] = {
	struct option options[] = {
		}
			parse_file_arg},
	}
			IGNORE_MISSING),
		if (parse_notes_merge_strategy(strategy, &o.strategy)) {
#include "config.h"
	if (result >= 0) /* Merge resulted (trivially) in result_oid */
	else if (!strcmp(argv[0], "get-ref"))

	if (git_config_get_string(key, &value))
	struct strbuf buf = STRBUF_INIT;
	d->given = 1;
		{ OPTION_CALLBACK, 'F', "file", &d, N_("file"),
			if (d.given) {


		   is_null_oid(&parent_oid) ? NULL : &parent_oid,
	enum object_type type;
	if (get_oid(object_ref, &object))
	strbuf_addstr(&remote_ref, argv[0]);
#include "string-list.h"

		die(_("failed to finish 'show' for object '%s'"),
	show.out = -1;
};
	}
	if (argc < 1 || !strcmp(argv[0], "list"))
static int copy(int argc, const char **argv, const char *prefix)
		d->edit_path = git_pathdup("NOTES_EDITMSG");
{
		strbuf_addch(&buf, '\n');
static int prune(int argc, const char **argv, const char *prefix)
		die(_("failed to resolve '%s' as a valid ref."), object_ref);
		}

	struct notes_tree *t;
#include "blob.h"
	int given;
	git_config(git_default_config, NULL);
	/* Invoke "git show --stat --no-notes $object" */
			strbuf_rtrim(&sb);
{
		die(_("failed to resolve NOTES_MERGE_REF"));

		if (get_oid(split[0]->buf, &from_obj))
static int get_ref(int argc, const char **argv, const char *prefix)
	/*
	} else if (!do_merge && argc) {

	argc = parse_options(argc, argv, prefix, options, usage,
{
			     git_notes_get_ref_usage, 0);

	NULL
					oid_to_hex(&object));
{
	char *value;
		git_die_config(key, _("unknown notes merge strategy %s"), value);
#include "builtin.h"
			      1, PARSE_OPT_NONEG),
		return merge_abort(&o);
	struct notes_merge_options o;
	if (finish_command(&show))
	struct option options[] = {
static int add(int argc, const char **argv, const char *prefix)
		}
static int append_edit(int argc, const char **argv, const char *prefix);
	if (write_object_file(d->buf.buf, d->buf.len, blob_type, oid)) {
		OPT_END()
	void *local_ref_to_free;
	if (partial->parents)
			free_notes(t);
		int err;
	}
	if (start_command(&show))
		if (get_oid(split[1]->buf, &to_obj))
	struct notes_tree *t;
	} else {
	if (strategy) {
			write_or_die(fd, d->buf.buf, d->buf.len);
		usage_with_options(git_notes_usage, options);
{
		strbuf_addstr(&sb, override_notes_ref);
		die(_("cannot read note data from non-blob object '%s'."), arg);
			      "(manual/ours/theirs/union/cat_sort_uniq)")),

		fprintf(stderr, _("Removing note for object %s\n"),
	return ret;
		OPT_GROUP(N_("General options")),
		{ OPTION_CALLBACK, 'C', "reuse-message", &d, N_("object"),
	 * Read partial merge result from .git/NOTES_MERGE_PARTIAL,
	if (from_stdin) {
	if (note) {
	struct notes_tree *t;
			   UPDATE_REFS_DIE_ON_ERR);
		die(_("failed to resolve '%s' as a valid ref."), argv[0]);
	NULL

	strbuf_release(&buf);
	init_notes_merge_options(the_repository, &o);
	status = remove_note(t, oid.hash);
		if (d->edit_path)
		result = remove_cmd(argc, argv, prefix);
