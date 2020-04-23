			break; /* root commit */
	}
	}
		/*
{
		strbuf_addch(msgbuf, comment_line_char);
 * If the current series of squash/fixups has not yet included a squash
			git_config_bool_or_int(key, value, &error_flag);
	unpack_tree_opts.fn = oneway_merge;
				/* failed with merge conflicts */
 * commit is still the commit to be edited.  When any other rebase
				i2 = entry->i;
	}

		default:
		rollback_lock_file(&lock);

		next_label = msg.label;
			for (; i < the_hash_algo->hexsz; i++) {
		error(_("could not even attempt to merge '%.*s'"),
		entry = oidmap_get(&state.commit2label, &commit->object.oid);
					  NULL, 0, msg.buf, &err) < 0 ||
		todo_list->nr -= i;
	free(msg->subject);

		struct stat st;



				oid_to_hex(&parent->object.oid));
	FLEX_ALLOC_STR(string_entry, string, label);
	 * abbreviation of the commit name. This is slightly more complicated
	char **subjects;
		strbuf_addf(&buf, _("This is the commit message #%d:"),
	return NULL;
	eol = strchr(buf.buf, '\n');
		if (res < 0)
					     &check_todo);
	argv_array_pushf(env, "GIT_AUTHOR_NAME=%s", name);
		todo_list_release(&done);
					"options.gpg-sign", opts->gpg_sign);
		cmd = command_to_char(item->command);
		}
	struct argv_array argv = ARGV_ARRAY_INIT;

			   struct replay_opts *opts)
			return error(_("cannot amend non-existing commit"));
	enum replay_action action;
void append_signoff(struct strbuf *msgbuf, size_t ignore_footer, unsigned flag)
			 * fixup or a squash now, we have rearranged it.
		/*
		}
			  &buf, 0);


		unuse_commit_buffer(commit, commit_buffer);
	ret = run_command_v_opt(argv.argv, RUN_GIT_CMD);
	 * abbreviation for any uninteresting commit's names that does not
		return error_resolve_conflict(_(action_name(opts)));

};

	unsigned int advise_skip = file_exists(git_path_revert_head(r)) ||
			}
			const char *msg;
	}
		return -1;
		if (advice_sequencer_in_use)
				  s);
 * something that the user does not expect.
"    git config --global user.email you@example.com\n"
	if (command == TODO_SQUASH) {
	strbuf_release(&buf);

		MOVE_ARRAY(todo_list->items, todo_list->items + i, todo_list->nr - i);
			  NULL, 0,
		item->commit = NULL;
		       int allow_missing)
		return _(implicit_ident_advice_noconfig);
		struct string_list_item *item;

			rollback_lock_file(&lock);

	close(fd);
				    rebase_path_current_fixups(), 0);
		free_commit_list(list);
	int run_commit_flags = (flags & TODO_EDIT_MERGE_MSG) ?
 * --continue" is executed, if there are any staged changes then they
		/*
	if (index_fd >= 0) {
	if (opts->allow_empty)


						res, to_amend);
	    !file_exists(git_path_revert_head(r)))
	int root_with_onto = flags & TODO_LIST_ROOT_WITH_ONTO;
	if (!(flags & EDIT_MSG))
		strbuf_addf(&header, _("This is a combination of %d commits."),
			goto out;
	}
	if (onto)
	const char *sub_action, const char *fmt, ...)
			_("You can amend the commit now, with\n"
	return 0;
						entry);

			struct replay_opts *opts)
	va_start(ap, fmt);
			if (entry)
#include "commit-reach.h"
	struct replay_opts *opts = data;
		res |= git_config_set_in_file_gently(opts_file,
	const char *path, int skip_if_empty)
	res = todo_list_parse_insn_buffer(r, todo_list->buf.buf, todo_list);
	setup_unpack_trees_porcelain(&unpack_tree_opts, "reset");

		cp = sq_dequote(cp);
		ret = error(_("'prepare-commit-msg' hook failed"));
			if (read_oneliner(&buf, rebase_path_orig_head(), 0) &&
				 *commit_todo_item_at(&commit_todo, commit2))
		append_conflicts_hint(r->index, msgbuf,
		}
	{ 't', "reset" },
		if ((flags & TODO_LIST_ABBREVIATE_CMDS) && cmd)
			continue;
	struct trailer_info info;
			res = continue_single_pick(r);
static GIT_PATH_FUNC(rebase_path_reschedule_failed_exec, "rebase-merge/reschedule-failed-exec")
			break;
static int parse_insn_line(struct repository *r, struct todo_item *item,
		if (is_fixup(todo_list->items[i].command))
	    !(commit = lookup_commit(r, &head)) ||
	fprintf(stderr, _("Executing: %s\n"), command_line);
	if (skip_if_empty && buf->len == orig_len)
finish:
	o.buffer_output = 2;
		 */
			struct commit *commit2;
 */
	strbuf_release(&ref_name);
 */
		case REPLAY_REVERT:
	write_message(oid_to_hex(&merge_commit->object.oid), the_hash_algo->hexsz,
		unlink(rebase_path_fixup_msg());
	return 0;
			return -1;
 *     1: Allow empty commit

		struct commit_list *parent = iter->item->parents;
	struct strbuf msgbuf = STRBUF_INIT;
				FILE *f = fopen(rebase_path_msgnum(), "w");
		error(_("could not resolve '%s'"), buf->buf);
	if (strbuf_read_file(buf, path, 0) < 0) {
	f = fopen(git_path_head_file(), "r");
	if (cleanup_mode < ARRAY_SIZE(modes))
			break;

	if (repo_hold_locked_index(r, &index_lock, LOCK_REPORT_ON_ERROR) < 0)
 * Read a GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL AND GIT_AUTHOR_DATE from a
{
		if (write_message(body, strlen(body),
	return 0;

	commit = lookup_commit_reference_by_name(buf->buf);
		else
	unuse_commit_buffer(commit, message);
	}
			in_progress_advice =
 * For the post-rewrite hook, we make a list of rewritten commits and
	hashmap_init(&state.labels, labels_cmp, NULL, 0);
		ret = -1;
				    COMMIT_MSG_CLEANUP_SPACE;
		} else if (!strcmp(s, "strip")) {
	struct commit *head_commit;
		if (!strcmp(kv.items[i].string, "GIT_AUTHOR_NAME")) {
			if (!has_conforming_footer(&msgbuf, NULL, 0))
			}
	struct commit_message message;
			if (!starts_with(buf.buf, "-S"))
{
	o.branch1 = "HEAD";
}
}

		strbuf_release(&sb);
			if (i == info.trailer_nr - 1)

							   strihash(p), p))
	return 0;

				     (int) (np - buf), buf);
			ret = error(_("octopus merge cannot be executed on "
	/*
	return todo_list->items + todo_list->nr++;
	if (parse_commit(commit))
	 * command, appending it to "done" instead.
 */
/*
		return todo_command_info[command].c;
}
	    !get_oid("HEAD", &newoid) &&
		struct commit *first_parent = current_head;

}
		return 1;

		unlink(git_path_cherry_pick_head(r));
	}
			strbuf_addch(buf, cmd);
	if (status)
	} else {

				name_i = i;
		error("%s", in_progress_error);
		opts->allow_ff = git_config_bool_or_int(key, value, &error_flag);
			    const void *key)
				   &null_oid : from,
	if (to_amend) {
		return 0;
		if (parse_commit(parent))

		if (--buf->len > orig_len && buf->buf[buf->len - 1] == '\r')
	strbuf_release(&buf);
			todo_list->items[i].command =
		argv_array_push(&cmd.args, "--cleanup=verbatim");
		 * We may need to extend the abbreviated hash so that there is
	struct oidset interesting = OIDSET_INIT, child_seen = OIDSET_INIT,
		}
		unlink(rebase_path_fixup_msg());
			return error(_("unable to dequote value of '%s'"),
static int checkout_onto(struct repository *r, struct replay_opts *opts,
				   old_head ? &old_head->object.oid : &null_oid,
		write_file(rebase_path_reschedule_failed_exec(), "%s", "");
		discard_index(r->index);
{

	 */
		return error(_("nothing to do"));
			return todo_list->items[i].command;

	format_commit_message(commit, "%an <%ae>", &author_ident, &pctx);
	struct commit_list *tips = NULL, **tips_tail = &tips;
			break;
			    opts->current_fixups.len ? "\n" : "",
 * actions.
	char *p;
		if (opts->record_origin) {
		else if (*message != '\'')
	if (nl) {
		if (flags & AMEND_MSG) {
		strbuf_release(&stash_sha1);
		return error(_("malformed options sheet: '%s'"),
		item->arg_len = eol - bol;
		oidcpy(&oid, &opts->squash_onto);
		revs.max_parents = 1;
	}
}
static const char *label_oid(struct object_id *oid, const char *label,
{
	strbuf_release(&buf);
	free_commit_list(commits);
		if (!strcmp(s, "verbatim")) {
				return error_failed_squash(r, item->commit, opts,
		if (!to_merge) {
		rollback_lock_file(&lock);
 * The rebase command lines that have already been processed. A line
				    "onto" : "[new root]");

		return rebase_path_todo();
		strbuf_release(&ref_name);
					command_to_string(item->command), NULL),
		if (todo_list_write_to_file(r, todo_list, done_path, NULL, NULL, i, 0)) {
						       "'%s'"), path);
		} else {
static GIT_PATH_FUNC(rebase_path_strategy, "rebase-merge/strategy")
		size_t subject_len;
	} else {
}
					goto out;
		    struct string_list *commands, unsigned autosquash,
{
	return -1;
		strbuf_addstr(&buf, ": ");

					 &head, &msgbuf, opts);
		if (index_differs_from(r, unborn ? empty_tree_oid_hex() : "HEAD",
		if (file_exists(git_path_seq_dir()))
	if (is_rebase_i(opts)) {
		res |= write_message(subject, strlen(subject), buf.buf, 1);
};
	else if (opts->drop_redundant_commits)
	for (iter = commits; iter; iter = iter->next) {
			if (item->command == TODO_MERGE) {

 * their new sha1s.  The rewritten-pending list keeps the sha1s of
		}
				p[i] = '\0';
				cur = next[cur];
	struct process_trailer_options opts = PROCESS_TRAILER_OPTIONS_INIT;
{
				  "You can run \"git stash pop\" or"
		next_p = *eol ? eol + 1 /* skip LF */ : eol;
			  unsigned int flags)

	struct strbuf stash_sha1 = STRBUF_INIT;
		strbuf_addstr(&format, "\n Author: ");
fast_forward_edit:
{
int template_untouched(const struct strbuf *sb, const char *template_file,
 * A script to set the GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, and
		return make_script_with_merges(&pp, &revs, out, flags);
				strbuf_release(&buf);
	return &istate->cache_tree->oid;
	strbuf_addf(&buf, "%s/message", get_dir(opts));
			      &check_todo);
		strbuf_release(&buf);
	} else if (allow == 1) {
	 * want to avoid jumping back and forth between revisions. To
		} else
		if (item->command <= TODO_SQUASH) {
 */

	 * are pretty certain that it is syntactically correct.
	if (!is_directory(git_path_seq_dir()))
		fprintf(stderr, _("Stopped at HEAD\n"));
			tail[i2] = i;
	}
		has_footer = has_conforming_footer(msgbuf, &sob, ignore_footer);
/*
		if ((skip_prefix(subject, "fixup! ", &p) ||
 * in the todo list.
	struct commit *commit;
	if (opts->allow_ff)
{
			/* Missing 'author' line? */
	else
	} else
{
				 * chain, we only need to clean up the commit
			return error(_("git %s: failed to refresh the index"),
	abbrev = short_commit_name(commit);
	 */

		(!opts->strategy || !strcmp(opts->strategy, "recursive")) ?
		unlink(rebase_path_squash_msg());
	return ret;


	    ref_transaction_commit(transaction, &err)) {
				record_in_rewritten(&item->commit->object.oid,
			else if (!strchr(p, ' ') &&
	}
		    oideq(&rebase_head, &cherry_pick_head))
{
		       REF_NO_DEREF, UPDATE_REFS_MSG_ON_ERR))
 * When we stop at a given patch via the "edit" command, this file contains
			     git_path_merge_msg(r), 0666))
			     oid_to_hex(&commit->object.oid));
		    new_todo.buf.buf);
	return skip_prefix(*bol, str, bol) ||
		strbuf_addstr(&buf, "\n\n");
	if (item->command == TODO_NOOP || item->command == TODO_BREAK) {
}
			git_path_head_file());
static int parse_key_value_squoted(char *buf, struct string_list *list)
	allow = allow_empty(r, opts, commit);


	}
	bol += strspn(bol, " \t");
		const char *commit_buffer, *subject, *p;
 * interactive rebase: in that case, we will want to retain the
				break;
			return error(_("need a HEAD to fixup"));
	 * --keep-empty).  So, it is safe to insert an exec command
	return get_item_line_offset(todo_list, index + 1)
	todo_list_to_strbuf(r, &new_todo, &buf2, -1, 0);
		/* TRANSLATORS: The first %s will be a "todo" command like
	}
#include "wt-status.h"
							opts, res, 0);
 *
#include "quote.h"
			struct object_id *oid = &parent->item->object.oid;
	 * without further complaints in such a case.  Otherwise, if
				 struct string_list *commands)
static int get_message(struct commit *commit, struct commit_message *out)
			argv_array_push(&cmd.args, strategy);
	}
	 * "commit" is an existing commit.  We would want to apply
		tail = &commit_list_insert(merge_commit, tail)->next;
	}
		opts->current_fixup_count = 0;
		item->arg_len = item->arg_offset = item->flags = item->offset_in_buf = 0;
	bol = buf.buf + strspn(buf.buf, " \t\r\n");

	const char *base_label, *next_label;
	if ((flags & CLEANUP_MSG))
	if (cleanup != COMMIT_MSG_CLEANUP_NONE)
		strbuf_add_commented_lines(&buf, body, strlen(body));
#define AMEND_MSG   (1<<2)
static int walk_revs_populate_todo(struct todo_list *todo_list,

		} else {
			error_errno(_("could not write '%s'"),
		return -1;
	unsigned int final_fixup = 0, is_clean;

	if (!read_oneliner(&stash_sha1, rebase_path_autostash(), 1)) {
	}
		argv_array_push(&cmd.args, "-n");
		msg_file = NULL;
			append_newlines = "\n\n";

			}
{
	if (!committer_ident_sufficiently_given()) {
{
static const char *gpg_sign_opt_quoted(struct replay_opts *opts)
				email_i = error(_("'GIT_AUTHOR_EMAIL' already given"));
	strbuf_release(&buf);

		/* add command to the buffer */
	int ret = 0;
		 */
		goto fail;
static int reset_merge(const struct object_id *oid)
#define CLEANUP_MSG (1<<3)
	    parse_commit(commit) || get_message(commit, &message))
				     2048) < 0) {
	struct commit *commit;
			 * If a fixup/squash in a fixup/squash chain failed, the
	 */
			}
		 *
static int update_squash_messages(struct repository *r,
				       "verbatim",
	return comment_line_char;
	 * moved? In this case, it doesn't make sense to "reset the merge" and
	ref_transaction_free(transaction);
		fputs(o.obuf.buf, stdout);
static GIT_PATH_FUNC(rebase_path_verbose, "rebase-merge/verbose")
	return do_pick_commit(r, opts->action == REPLAY_PICK ?
		goto leave_merge;

		for (j = to_merge; j; j = j->next)

	if (autosquash && todo_list_rearrange_squash(todo_list))
	const char *message, *body;
			while ((p = strchr(p, '\n'))) {
			if (!oidset_contains(&interesting, oid)) {
		if (read_oneliner(&head_ref, rebase_path_head_name(), 0) &&
	int res;
			argv_array_push(&cmd.args,
	if (string_entry)
			   const char *buf, const char *bol, char *eol)
	    ((parent && oideq(&parent->object.oid, &head)) ||
 */
				if (!opts->verbose)
}

	if (opts->mainline) {

		if (errno == ENOENT) {
				todo_list->current = -1;
			      TODO_PICK : TODO_REVERT, cmit, opts, 0,
}
			opts->drop_redundant_commits = 1;

		sequencer_remove_state(opts);


 * previous commit and from the first squash/fixup commit are written
		free((char *)s);
	}
				res = error(_("could not update %s"),
			char *end_of_arg = (char *)(arg + item->arg_len);
	fast_forward_edit:
static int commit_staged_changes(struct repository *r,

	if (defmsg)
	if (!f)
		if (file_exists(rebase_path_verbose()))
	const char *insn = flags & TODO_LIST_ABBREVIATE_CMDS ? "p" : "pick";
		/* label the tips of merged branches */
				if (!opts->quiet)
		len = i;
				commit = NULL;
	}
	const char *str = todo_command_info[command].str;
	struct strbuf buf = STRBUF_INIT;
	struct object_id head_oid;
	 * are considered part of the pick, so we insert the commands *after*
				argv_array_push(&hook.args, post_rewrite_hook);
			 * Buffer ends with a single newline.  Add another
			else if (!strcmp(buf.buf, "--no-rerere-autoupdate"))
	if (verbose || /* Truncate the message just before the diff, if any. */
	}

	int i = todo_list->current;
	    ref_transaction_update(transaction, "HEAD",
	for (i = 0; i < todo_list->nr; i++)
		if (commit)
	char *strategy_opts_string = raw_opts;
		else
		to_merge = commit->parents ? commit->parents->next : NULL;
	va_end(ap);
	clean = merge_trees(&o,

		struct strbuf buf = STRBUF_INIT;
	 * - label all branch tips

		argv_array_push(&store.args, "-q");

	unsigned int flags = ALLOW_EMPTY | EDIT_MSG;
			strbuf_reset(&buf);
		todo_list->done_nr += i;
		const char *commit_buffer = logmsg_reencode(commit, NULL, encoding);
			    const char *shortonto, int num, unsigned flags)
	struct oidmap commit2todo = OIDMAP_INIT;
		if (nl)
			strbuf_addch(&format, '\n');
	struct object_id tree;
int read_author_script(const char *path, char **name, char **email, char **date,
			if (action != REPLAY_PICK)
	int rebase_merges = flags & TODO_LIST_REBASE_MERGES;
		opts->current_fixup_count = 0;
			else {
				oid_to_hex(&commit->object.oid), opts->mainline);
		 */
{
			} else if (match_stat_data(&todo_list->stat, &st)) {
	free_commit_list(bases);
	struct strbuf committer_ident = STRBUF_INIT;

			     struct replay_opts *opts)
			if (stat(get_todo_path(opts), &st)) {
N_("you have staged changes in your working tree\n"
			return res;
	int res;
		if (opts->no_commit)
	 * Start a new cherry-pick/ revert sequence; but
	if (!log_tree_commit(&rev, commit)) {
enum commit_msg_cleanup_mode get_cleanup_mode(const char *cleanup_arg,
		arg1 = "commit";
	reset_ident_date();
static GIT_PATH_FUNC(git_path_seq_dir, "sequencer")
						_(" (root-commit)") : "");
	if (clean < 0) {
	return opts->action == REPLAY_INTERACTIVE_REBASE;
		 * When the user tells us to "merge" something into a
static int save_head(const char *head)
	if (walk_revs_populate_todo(&todo_list, opts) ||
		} else if (!strcmp(kv.items[i].string, "GIT_AUTHOR_EMAIL")) {
 */
			    !get_oid("HEAD", &head)) {
	if (command < TODO_COMMENT)
			   &bases->item->object.oid)) {

			clear_commit_todo_item(&commit_todo);
static GIT_PATH_FUNC(rebase_path_quiet, "rebase-merge/quiet")
			len = buf.len;
		if (!msg) {

	ref_transaction_free(transaction);
			flags |= EDIT_MSG;
		p += k;

		      git_path_merge_head(r), 0);
		write_file(rebase_path_allow_rerere_autoupdate(), "--rerere-autoupdate\n");
			if (create_symref("HEAD", head_ref.buf, msg)) {
	 * we will want to reschedule the `merge` command).
		 * (typically rebase --interactive) wants to take care
	if (save_opts(opts))
	 * Second phase:
 * e.g. because they are waiting for a 'squash' command.
	else if (!strcmp(key, "options.mainline"))
	bol = end_of_object_name + strspn(end_of_object_name, " \t");
 * script cannot be trusted) in order to normalize the autosquash arrangement.
		struct todo_item *item = append_new_todo(todo_list);
			return res;
}

		if (file_exists(rebase_path_keep_redundant_commits()))
			  struct replay_opts *opts,
			if (is_rebase_i(opts))
	bol += padding;
 * the dummy commit used for `reset [new root]`.
		opts->xopts[opts->xopts_nr++] = xstrdup(value);
	unpack_tree_opts.head_idx = 1;


			oid_to_hex(&commit->object.oid), msg.subject);

	transaction = ref_transaction_begin(err);
				i2 = *commit_todo_item_at(&commit_todo, commit2)
	if (strbuf_read_file(&buf, todo_file, 0) < 0) {

				strbuf_addf(out, "%s %s # %s\n",
	struct lock_file lock = LOCK_INIT;
		strbuf_addstr(buf, commands->items[i].string);
		fputs(o.obuf.buf, stdout);

				    oid_to_hex(&commit->object.oid));
	va_list ap;
		item->commit = commit;
		if (get_oid_hex(sb.buf, &expected_head)) {
}
	}
	if (!padding)
}
		die_errno(_("could not read '%s'"), git_path_abort_safety_file());
				todo_list_release(todo_list);
	hashmap_free_entries(&state.labels, struct labels_entry, entry);
			unlink(git_path_merge_msg(r));
		if (!(head_message = logmsg_reencode(head_commit, NULL, encoding)))
				  get_item_line_length(todo_list, next - 1))

			const char *p = opts->current_fixups.buf;
		oidclr(&actual_head);
		if (is_rebase_i(opts))
		if (parse_commit(current_head))
		argv_array_push(&argv, oid_to_hex(oid));

		write_file(rebase_path_keep_redundant_commits(), "%s", "");
			struct child_process child = CHILD_PROCESS_INIT;
}
	if (repo_read_index_unmerged(r)) {


	char *label;

			unlink(rebase_path_amend());
		    hashmap_get_from_hash(&state->labels,
		else
	FREE_AND_NULL(todo_list->items);
				to = entry->string;
		strbuf_addf(&todo_list->buf, "%s %s %.*s\n", command_string,
static int is_original_commit_empty(struct commit *commit)
			ret = error_errno(_("could not write to '%s'"), done);
{
	if (!fill_tree_descriptor(r, &desc, &oid)) {
				  struct commit *commit,
	}
		/* Reverting or cherry-picking a merge commit */
		if (ret) {
	struct strbuf *msgbuf, enum commit_msg_cleanup_mode cleanup_mode)
		 * via the most significant bit). They should be all acceptable
				find_hook("post-rewrite");
	} else {
		else

		else
"    %.*s"
		 * "[new root]", let's simply fast-forward to the merge head.
		rollback_lock_file(&head_lock);
		parent_oid = &item->commit->parents->item->object.oid;
 */
 * Returns 0 for non-conforming footer
			    cmd_merge, oid_to_hex(&commit->object.oid));
		copy_note_for_rewrite(cfg, &old_head->object.oid, new_head);
	return rest_is_empty(sb, start - sb->buf);
	if (checkout_onto(r, opts, onto_name, &oid, orig_head))
	free_commit_extra_headers(extra);
}
	}
{
	if (fd < 0)
		const char *subject;
	strbuf_release(&msg);
static int read_populate_opts(struct replay_opts *opts)
	if (!commit) {
		return -1;
				goto cleanup_head_ref;
	strbuf_addf(&buf, "%s\n", head);
{
		struct strbuf buf = STRBUF_INIT;
	rollback_lock_file(&lock);
static int is_pick_or_similar(enum todo_command command)
/*
{
		warning(_("execution failed: %s\n%s"

{
		head = _("detached HEAD");
	int i, res = 0, fixup_okay = file_exists(rebase_path_done());
	struct todo_list new_todo = TODO_LIST_INIT;
			if (!isspace(sb->buf[i++]))
		strbuf_addf(&buf, "%d", opts->mainline);

			 const struct object_id *new_head)
					NULL, NULL))
	int merge_arg_len, oneline_offset, can_fast_forward, ret, k;
}
	discard_index(r->index);

				 * fast-forwarded already, or are about to
	res = stat(todo_file, &st);
	log_tree_opt.diffopt.file = fopen(buf.buf, "w");
		if (status)
	return key ? strcmp(a->label, key) : strcmp(a->label, b->label);
			strbuf_addf(&buf, "'\\%c'", *(message++));
	if (!index_unchanged)
	    (res == 0 || res == 1) &&

	}


static int is_fixup(enum todo_command command)
	FLEX_ALLOC_STR(labels_entry, label, label);

		if (res)
				       "'git rebase --edit-todo'."));

		-  get_item_line_offset(todo_list, index);


		 * If the number of merge heads differs from the original merge
	free_commit_list(tips);
	if (strbuf_cmp(&author_ident, &committer_ident)) {
		write_file(rebase_path_quiet(), "%s", "");
	struct rev_info revs;

	if (!file_exists(git_path_cherry_pick_head(r)) &&

		return -1;
		return error(_("git %s: failed to read the index"),
	if (cleanup_mode == COMMIT_MSG_CLEANUP_NONE && sb->len)
				if (opts->reschedule_failed_exec)
		strbuf_addch(msgbuf, '\n');
					term_clear_line();
	    oideq(&head_commit->object.oid, &opts->squash_onto)) {
			strbuf_addf(&buf, "'\\%c'", *(message++));
	if (action) {
	/*
			if ((res = do_merge(r, item->commit,
	/* If there is only one line then we are done */
			 * valid full OID, or the label is a '#' (which we use

				st.st_size > 0) {
	child_argv[0] = command_line;
		ptree_oid = get_commit_tree_oid(parent);
			append_newlines = "\n";
	char *msg = getenv("GIT_CHERRY_PICK_HELP");
			label = buf->buf;
		if (!*p)
	const struct subject2item_entry *a, *b;
			can_fast_forward = 0;
		is_empty = is_original_commit_empty(commit);

			entry = oidmap_get(&state.commit2label,
}
				strbuf_release(&head_ref);
	 */
#include "rerere.h"

	if (!is_rebase_i(opts)) {
	repo_read_index(r);
	const char *nl;
		goto finish;
	/*

	else if (!strcmp(cleanup_arg, "strip"))
		unlink(rebase_path_current_fixups());
 * commit-id fixup!/squash! msg" in it so that the latter is put immediately
		 * When skipping a failed fixup/squash, we need to edit the
					"options.allow-empty", "true");
	merge_commit = to_merge->item;
	strbuf_reset(&buf);
			_(action_name(opts)));
		flags |= ALLOW_EMPTY;
	struct lock_file index_lock = LOCK_INIT;
#include "cache-tree.h"
		}
	}
	if (file_exists(rebase_path_amend())) {
	*head = current_head;
	case REPLAY_REVERT:
	strbuf_release(&buf);
			/* we are in a fixup/squash chain */
		return 0; /* let "git commit" barf as necessary */
	int res;
			opts->signoff = 1;
			bol += strspn(bol, " \t");
			if (delete_ref("(rebase) cleanup", p, NULL, 0) < 0) {
		}

	free((void *)desc.buffer);

				run_command(&hook);

		}
/*
};

		error(_("missing 'GIT_AUTHOR_EMAIL'"));
	log_tree_opt.no_commit_id = 1;
		} else if (is_rebase_i(opts) && check_todo && !res) {
}

		return code;
		return 0;
		die(_("could not parse newly created commit"));
	if (!out)
	if (*strategy_opts_string == ' ')
	 * The return value of merge_recursive() is 1 on clean, and 0 on
	free(next);
	char *prev_reflog_action;

		     struct replay_opts *opts, unsigned int flags,
	} else
{
		write_file(rebase_path_drop_redundant_commits(), "%s", "");
		if (file_exists(rebase_path_signoff())) {
		const char *head_message, *body;
				describe_cleanup_mode(opts->default_msg_cleanup));
			else

	if (read_author_script(rebase_path_author_script(),

				if (!res) {
			res = error_errno(_("unable to read commit message "
int complete_action(struct repository *r, struct replay_opts *opts, unsigned flags,
		item->offset_in_buf = todo_list->buf.len;
{
			  const char *defmsg,
	}

				append_newlines, strlen(append_newlines));
	if (orig_head)
/*
				goto release_todo_list;
"\n"
	     (!parent && unborn))) {
	if (is_rebase_i(opts))
		 * A conflict has occurred but the porcelain
		strbuf_addstr(&msgbuf, "\"\n\nThis reverts commit ");
	return 0;


			goto leave;
	const char *child_argv[] = { NULL, NULL };
		if (*p == '#' && (!p[1] || isspace(p[1]))) {
int sequencer_pick_revisions(struct repository *r,
		const char *commit_buffer = logmsg_reencode(commit, NULL, encoding);
	rev.diff = 1;
			  "  git rebase --continue\n"
}
				p[i] = save;
static void free_message(struct commit *commit, struct commit_message *msg)
					"options.edit", "true");

	return 0;
			/*
	fclose(f);


static GIT_PATH_FUNC(rebase_path_drop_redundant_commits, "rebase-merge/drop_redundant_commits")
			strbuf_reset(&buf);
		const char *p1, *p2;
				    (oideq(&item->commit->object.oid, &oid) ||
fail:
 *     0: Halt on empty commit
	status = run_command_v_opt_cd_env(child_argv, RUN_USING_SHELL, NULL,
			if (!opts->verbose)
	{ 'l', "label" },
	strbuf_complete(&buf, '\n');
}
		return status;
	len = strbuf_read(sb, fd, 0);

				 * the latest commit message.
		strbuf_addch(out, '\n');
		const char *s;
	/* Note that 0 for 3rd parameter of setenv means set only if not set */
			continue;
			return error(_("\nYou have uncommitted changes in your "
	if (!head)
			 * as a separator between merge heads and oneline), we


	struct lock_file head_lock = LOCK_INIT;
			warning(_("cancelling a revert in progress"));
				break;

	strbuf_release(&stash_sha1);
	case REPLAY_REVERT:
	struct strbuf tmpl = STRBUF_INIT;
static int write_message(const void *buf, size_t len, const char *filename,
	todo_file = git_path_todo_file();
		}

				struct commit *commit = item->commit;
{

					    comment_line_char);
		}
		if (file_exists(git_path_cherry_pick_head(r)) ||

			 */
		ret = update_ref(reflog_message(opts, "reset", "'%.*s'",
	if (!template_file || strbuf_read_file(&tmpl, template_file, 0) <= 0)
	if (allow < 0) {
	if (opts->keep_redundant_commits)
static void read_strategy_opts(struct replay_opts *opts, struct strbuf *buf)
		      const struct hashmap_entry *entry_or_key, const void *key)
 * is seen, the file is created and the commit message from the
	}
		goto fail;
int todo_list_write_to_file(struct repository *r, struct todo_list *todo_list,
static int continue_single_pick(struct repository *r)
	run_rewrite_hook(&old_head->object.oid, new_head);
	}
		      struct commit *commit,
			return 0;
static enum todo_command peek_command(struct todo_list *todo_list, int offset)
			hex = oid_to_hex(&opts->squash_onto);
			*whence = FROM_CHERRY_PICK_MULTI;
static int stopped_at_head(struct repository *r)


	res = pick_commits(r, &new_todo, opts);
static struct object_id *get_cache_tree_oid(struct index_state *istate)
			opts->explicit_cleanup = 1;
		return 3;
		COPY_ARRAY(items + nr, base_items, commands->nr);
 */
	name = git_path_commit_editmsg();

			goto leave_merge;
}
		*cmd_reset = abbr ? "t" : "reset",
/*
{
	case TODO_EDIT:
			}
	return 0;
}
{
	pp.fmt = revs.commit_format;
	revs.reverse = 1;
				const char *path = rebase_path_squash_msg();
		return error(_("invalid key: %s"), key);
			FLEX_ALLOC_STR(entry, string, buf.buf);
		if (ret) {
	 */
		return error(_("could not copy '%s' to '%s'"),
	"rebase-merge/rewritten-pending")

	if (find_hook("prepare-commit-msg")) {
	for (i = 0; i < opts->xopts_nr; ++i)
			if (!eol)
		goto leave_merge;
	strbuf_release(&err);


			item->arg_len = (int)(eol - bol);
	argv_array_push(&child.args, stash_sha1.buf);
		msg = &commit_msg;
	argv_array_push(&cmd.args, "commit");
		}
	fd = hold_lock_file_for_update(&head_lock, git_path_head_file(), 0);
			goto leave_merge;
					    cmd_reset, to, oneline.buf);
	struct commit *current_head = NULL;
				unlink(rebase_path_squash_msg());
		ret = write_message(p, len, git_path_merge_msg(r), 0);
	}

struct label_state {
		FLEX_ALLOC_STR(onto_label_entry, label, "onto");



	return res;
/*
		strbuf_addstr(&sb, ": ");
	} else {
	git_config_get_string("rebase.instructionFormat", &format);
	free(base_items);
	ret = !ret;
	 * removing the .git/sequencer directory
	rev.show_root_diff = 1;
	argv_array_pushf(&child_env, "GIT_WORK_TREE=%s",

static int error_dirty_index(struct repository *repo, struct replay_opts *opts)
		struct object_id cherry_pick_head, rebase_head;
		    file_exists(git_path_revert_head(r))) {
	if (write_in_full(fd, buf.buf, buf.len) < 0) {
		return -1; /* the callee should have complained already */
			 struct object_id *oid)
			 * just print the line from the todo file.
static int is_noop(const enum todo_command command)
			if (res)
		int is_empty = is_original_commit_empty(commit);

		 */
			*end_of_arg = '\0';
		return error_errno(_("could not write to '%s'"), todo_path);

	get_commit_format(format, &revs);
		else if (*message != '\'')
			strbuf_addch(out, '\n');
	hashmap_init(&subject2item, subject2item_cmp, NULL, todo_list->nr);

			  "Commit or stash your changes, and then run\n"
int todo_list_parse_insn_buffer(struct repository *r, char *buf,

	free(opts->strategy);
		int i;
		res = error("%s", err.buf);
		error_flag = 0;
				if (!skip_prefix(p, "fixup! ", &p) &&

	fd = open(path, O_RDONLY);
		return -1;
}

	if (todo_list_write_to_file(r, &new_todo, todo_file, NULL, NULL, -1,

}
	return 0;
			for (i = 2; ; i++) {
			if (item->command == TODO_EDIT) {
		argv_array_push(&cmd.args, "--no-stat");
				file_exists(git_path_cherry_pick_head(r));
	/*
	static struct lock_file lock;
	else if (res == -2) {

		next = commit;
			    ++opts->current_fixup_count + 1);
				date_i = i;
	else
	}
 * The path of the file containing the OID of the "squash onto" commit, i.e.
				to = label_oid(&commit->object.oid, NULL,
 *     2: Drop empty commit

		nl = memchr(sb->buf + i, '\n', sb->len - i);

			return error(_("could not parse HEAD commit"));

			if (write_message(hex, strlen(hex),
"After doing this, you may fix the identity used for this commit with:\n"
	if (ret < 0) {
	 * the difference it introduces since its first parent "prev"
		strbuf_addstr(&sb, action);
	struct lock_file msg_file = LOCK_INIT;
	return update_ref(NULL, "ORIG_HEAD", &oid, NULL, 0, UPDATE_REFS_MSG_ON_ERR);
	int res, unborn = 0, reword = 0, allow, drop_commit;
	/*
	unpack_tree_opts.update = 1;
	encoding = get_log_output_encoding();
	while (*buf) {
		strbuf_addch(&sb, '\n');
					NULL, &opts->squash_onto,
		if (strbuf_read_file(&commit_msg, git_path_commit_editmsg(),
		finish_copy_notes_for_rewrite(r, cfg, "Notes added by 'git commit --amend'");
	}
				       get_item_line(todo_list,
{

				    git_path_merge_msg(r));
	transaction = ref_store_transaction_begin(refs, &err);

	write_file(rebase_path_strategy_opts(), "%s\n", buf.buf);
		strbuf_addf(&buf, " # %s", oneline.buf);
				if (res == 1)
	if (i >= TODO_COMMENT)
"In both cases, once you're done, continue with:\n"

	struct object_id commit_oid;
	strbuf_release(&author_ident);
		unlink(rebase_path_fixup_msg());
			opts->have_squash_onto = 1;
		}
				/*

			in_progress_error = _("revert is already in progress");
	if (msg_fd < 0)
			short_commit_name(commit), subject_len, subject);
		return 0;
void sequencer_init_config(struct replay_opts *opts)
			opts->explicit_cleanup = 1;
		fprintf(stderr, _("Applied autostash.\n"));
	/*
	/*
			  "  git commit --amend %s\n"
				unlink(rebase_path_current_fixups());
	struct commit *commit;
		res |= log_tree_commit(&log_tree_opt, commit);

		if (run_command(&store))
	}
		 */
		res = -1;
		} else if (msgbuf->buf[len - 2] != '\n') {
		if (skip_prefix(oneline.buf, "Merge ", &p1) &&
	 */
		 * edit it.
"edit the todo list first:\n"
	const char *sub_action, const char *fmt, ...);
	if (res == 1) {

			    struct commit *commit,
{

			  "\n"
	base_tree = base ? get_commit_tree(base) : empty_tree(r);
	struct commit *commit;
		return -1;


 * command, then this can be used as the commit message of the combined
	if (!eol || !eol[1])
{
int sequencer_skip(struct repository *r, struct replay_opts *opts)
	saved = *end_of_object_name;
	else if (!strcmp(key, "options.gpg-sign"))
		return error(_("could not update %s"), "REBASE_HEAD");
			if (item->commit)
	revs.sort_order = REV_SORT_IN_GRAPH_ORDER;
			}
		FREE_AND_NULL(todo_list->items);
	 * which item was moved directly after the i'th.

{
	struct child_process proc = CHILD_PROCESS_INIT;
		const char *arg = todo_item_get_arg(todo_list, item);
 */
 * where $author_name, $author_email and $author_date are quoted. We are strict
	 * However, if the merge did not even start, then we don't want to
			strbuf_complete_line(&msgbuf);
			flags |= CREATE_ROOT_COMMIT;
	return key ? strcmp(a->subject, key) : strcmp(a->subject, b->subject);
	argv_array_push(&cmd.args, "checkout");
#include "lockfile.h"
	if (setup_revisions(argc, argv, &revs, NULL) > 1)
		return error(_("empty commit set passed"));
static GIT_PATH_FUNC(rebase_path_rewritten_pending,
		struct child_process cmd = CHILD_PROCESS_INIT;

			 struct replay_opts *opts, unsigned int flags,
	}

	if (strbuf_read_file(&sb, git_path_abort_safety_file(), 0) >= 0) {
	struct strbuf buf = STRBUF_INIT;
	strbuf_swap(&new_todo.buf, &buf2);

		return -1;
static int parse_head(struct repository *r, struct commit **head)
					fprintf(stderr, _("Rebasing (%d/%d)%s"),
						      out_enc);
	if (write_in_full(fd, todo_list->buf.buf + offset,
			msg = reflog_message(opts, "finish", "returning to %s",
				    oneline.buf);
	if (!(message = logmsg_reencode(commit, NULL, encoding)))
			      struct object_id *head, struct strbuf *msgbuf,
	int index_fd = repo_hold_locked_index(r, &index_lock, 0);
			if (!oideq(&j->item->object.oid,
				pretty_print_commit(pp, commit, &oneline);
		else if (!oideq(&head, &to_amend) ||
				_(action_name(opts)));
		 (*bol = p));
	struct lock_file todo_lock = LOCK_INIT;
	case TODO_SQUASH:
	strbuf_release(&buf);
	int ret = 0;
		*np = '\0';
	return !clean;
		/*
			eol--; /* strip Carriage Return */
		argv_array_push(&store.args, "-m");
{
	if (opts->no_commit)
static char command_to_char(const enum todo_command command)
	if (read_populate_opts(opts))
	struct notes_rewrite_cfg *cfg;
	}
{
	enum commit_msg_cleanup_mode cleanup_mode, int verbose)
	}
	const char *shortonto, *todo_file = rebase_path_todo();
static int get_item_line_length(struct todo_list *todo_list, int index)
				"options.allow-rerere-auto",
{
{
	if (opts->xopts_nr > 0)
	/* Check if the rest is just whitespace and Signed-off-by's. */
		next[i] = tail[i] = -1;
		return config_error_nonbool(var);
		if (is_rebase_i(opts))
			strbuf_addf(out, "%s %s\n", cmd_reset,
	int i, eol;
		base_items[i].offset_in_buf = base_offset;
	if (opts->no_commit) {
static int write_author_script(const char *message)
			p = buf.buf;
	}
	if ((flags & AMEND_MSG))

			git_config_bool_or_int(key, value, &error_flag);
N_("Your name and email address were configured automatically based\n"
#include "exec-cmd.h"

	if (write_message(msg->buf, msg->len, name, 0))
 */
				  rebase_path_current_fixups(), 1)) {
		commit_list_insert(base, &common);
 * (e.g. for the prompt).
				next[i2] = i;


	free_commit_list(to_merge);
	struct todo_item *item;
		write_file(rebase_path_signoff(), "--signoff\n");
	todo_list->current = todo_list->nr = 0;
#include "object-store.h"


}
 * file with shell quoting into struct argv_array. Returns -1 on
				    rebase_cousins || root_with_onto ?
			if (item->command == TODO_BREAK) {
static int do_exec(struct repository *r, const char *command_line)
static int allow_empty(struct repository *r,
			 */


#include "object.h"
		goto fail;
	if (!is_rebase_i(opts)) {
		strbuf_splice(&buf, 0, eol - buf.buf, header.buf, header.len);
	if (index_unchanged < 0)
	res |= write_rebase_head(&commit->object.oid);
	struct commit_list *to_merge = NULL, **tail = &to_merge;
			if (!opts->verbose)
{
			/*
			  "\n"),
			oidmap_put(&commit2todo, entry);

		return error(_("nothing to do"));
}
		} else if (item->command == TODO_LABEL) {
		strbuf_release(&ref_name);
		if (author || command == TODO_REVERT || (flags & AMEND_MSG))
	int i, res;


		apply_autostash(opts);
		opts->allow_rerere_auto =
					fclose(f);
	for (i = 0; i < commands->nr; i++) {
	strbuf_release(&err);
				head_ref.buf);
		else
		goto cleanup;
			return error(_("could not remove CHERRY_PICK_HEAD"));
		      &head_commit->object.oid);
	struct lock_file index_lock = LOCK_INIT;
							   buf->buf))
				       get_item_line_length(todo_list,
 * commit to be edited is recorded in this file.  When "git rebase
		res |= git_config_set_in_file_gently(opts_file,
static int save_opts(struct replay_opts *opts)
		if (!merge_commit) {
		oidcpy(base_oid, &item->commit->object.oid);
		return 0;


		goto out;
		cmit = get_revision(opts->revs);

			if (is_fixup(command))

	if (write_locked_index(r->index, &index_lock,
	 * merged. The list is optionally followed by '#' and the oneline.
"  git commit %s\n"
			if ((res = do_label(r, arg, item->arg_len)))
			strbuf_addf(out, "\n%c Branch %s\n", comment_line_char, entry->string);
	if (!has_footer) {
			return 0;
		else if (!is_noop(item->command))
/**
		struct labels_entry *onto_label_entry;
		int cnt;
static int read_env_script(struct argv_array *env)
		todo_list_release(&new_todo);
		 * There is no multiple-cherry-pick in progress.
			ret = error(_("cannot store %s"), stash_sha1.buf);
}
	proc.argv = argv;

					res = -1; /* message was printed */
	if (strbuf_read_file(&buf, filename, 0) < 0 && errno != ENOENT) {
	 * without looking at the command following a comment.
	fprintf(out, "%s\n", oid_to_hex(oid));
		strbuf_splice(buf, 0, strlen("refs/rewritten/"), "", 0);
static GIT_PATH_FUNC(rebase_path_msgnum, "rebase-merge/msgnum")
}

	 * have been commented out because the user did not specify
	}
			FLEX_ALLOC_MEM(entry, subject, subject, subject_len);
/*
			  const char **argv, unsigned flags)
			const char *p = opts->current_fixups.buf;
		rollback_lock_file(&index_lock);
			strbuf_addch(&buf, ' ');
		while (*p) {
		argv_array_push(&cmd.args, "--no-log");
		else
	static const char *modes[] = { "whitespace",
		return -1;


	argv_array_push(&child.args, "apply");
	if (opts->keep_redundant_commits)
static int run_git_checkout(struct repository *r, struct replay_opts *opts,

}
			warning(_("cancelling a cherry picking in progress"));
/*
		res = error(_("failed to write commit object"));
	else
			if (commit_tree("", 0, the_hash_algo->empty_tree,
	offset = get_item_line_offset(todo_list, next);

			  unsigned int flags)
						     todo_list->current));
	}
	 *
				    todo_item_get_arg(todo_list, item));

		return error(_("could not skip unnecessary pick commands"));
			break;

				   struct rev_info *revs, struct strbuf *out,
			    struct replay_opts *opts,
	index_unchanged = is_index_unchanged(r);
			strbuf_addstr(&msgbuf, cherry_picked_prefix);
		opts->explicit_cleanup = 1;
	if ((flags & EDIT_MSG))
	return 0;
		for (; parent; parent = parent->next) {
	struct unpack_trees_options unpack_tree_opts;
			if (isspace(name[i]))
	init_checkout_metadata(&unpack_tree_opts.meta, name, &oid, NULL);
	if (!ret)
			break;
				 "and commit the result with 'git commit'"));
		if (write_locked_index(r->index, &index_lock,

	return 0;
#include "oidset.h"

		const char *arg = opts->xopts[i];
		const char *append_newlines = NULL;
}
		base_label = msg.label;
	todo_list_release(&todo_list);
			res = error(_("invalid line %d: %.*s"),

		} else if (len == 1) {
			const char *gpg_opt = gpg_sign_opt_quoted(opts);
		if (is_command(i, &bol)) {
	 * picking (but not reverting) ranges (but not individual revisions)
		strbuf_release(&ref_name);
	unuse_commit_buffer(commit, msg->message);
	if (!get_oid("HEAD", &head))
		strbuf_stripspace(msg, cleanup == COMMIT_MSG_CLEANUP_ALL);

				ret = -1;
	unpack_tree_opts.src_index = r->index;
		write_strategy_opts(opts);

 * The following files are written by git-rebase just after parsing the

		else if (file_exists(rebase_path_fixup_msg())) {
				items[nr++] = todo_list->items[cur];
	if (opts->drop_redundant_commits)

	res = write_message(buf.buf, buf.len, file, 0);
}
				char save = p[i];
/*


				next[tail[i2]] = i;
		strbuf_addbuf(&sb, msg);
			delete_ref(NULL, "REBASE_HEAD", NULL, REF_NO_DEREF);

		if (*message != '\'')
			fprintf(out, "%.*s %s\n", (int)(eol - bol),
			     shortonto, flags);
			for (k = 0; k < opts->xopts_nr; k++)
			return error(_("please fix this using "
void print_commit_summary(struct repository *r,
 * Signed-off-by lines.
		strbuf_addf(&buf, " (%s)", sub_action);
		if (oneline_offset < arg_len) {
						item->arg_len, arg);
		return error(_("revision walk setup failed"));
	}
		ret = write_message(body, len, git_path_merge_msg(r), 0);
			if (!oidset_contains(&interesting, oid))
					     "from '%s'"),
}
			if ((res = todo_list_check_against_backup(r, &todo_list)))
					"options.no-commit", "true");
		status = git_config_string(&s, k, v);
{
		return error_errno(_("cannot open '%s'"), git_path_head_file());
 *	GIT_AUTHOR_EMAIL='$author_email'
	size_t i;

					      "from '%s'"),

	 * This means it is possible to cherry-pick in the middle
					break;
					     VERIFY_MSG | AMEND_MSG |
		}
		extra = read_commit_extra_headers(current_head, exclude_gpgsig);
					p++;
		*cmd_label = abbr ? "l" : "label",
}
		}
	}
 */
		for (j = to_merge; j && p; j = j->next, p = p->next)

 */
	struct child_process cmd = CHILD_PROCESS_INIT;
	strbuf_addf(&sb, _("%s: fast-forward"), _(action_name(opts)));
	 * If any items need to be rearranged, the next[i] value will indicate

					     (flags & ALLOW_EMPTY));
		/* Append the commit log message to msgbuf. */
}
	return reset_merge(&head);
static const char *describe_cleanup_mode(int cleanup_mode)
	strbuf_addf(buf, "refs/rewritten/%.*s", len, label);


	int index_unchanged, originally_empty;
		}
}
	if (!is_fixup(next_command))
		merge_arg_len = p - arg;
}
				 "with 'git add <paths>' or 'git rm <paths>'\n"
		/* Verify that the conflict has been resolved */
static GIT_PATH_FUNC(rebase_path_keep_redundant_commits, "rebase-merge/keep_redundant_commits")
}
			error(_("unable to update cache tree"));
				opts->current_fixup_count++;

		item->arg_offset = bol - buf;
	if (opts->strategy)
				else
			}
static int intend_to_amend(void)
		if (read_oneliner(&opts->current_fixups,
				if (save_todo(todo_list, opts))
		res |= git_config_set_in_file_gently(opts_file,
	insert = 0;
		if (!item->commit || item->command == TODO_DROP) {
			return -1;
static GIT_PATH_FUNC(rebase_path_current_fixups, "rebase-merge/current-fixups")
	memset(&log_tree_opt, 0, sizeof(log_tree_opt));
	struct object_id newoid;
				return error(_("%s: can't cherry-pick a %s"),
	int i;
			if (!to || !strcmp(to, "onto"))
		if (parse_insn_line(r, item, buf, p, eol)) {

		strbuf_addf(out, "%s %s ", insn,
	 * Otherwise we check that the last instruction was related to the
	}
			strbuf_release(&sb);
{
			opts->default_msg_cleanup = COMMIT_MSG_CLEANUP_NONE;
				head_ref.buf);
		argv_array_push(&cmd.args, "--allow-empty-message");
		else if (is_fixup(item->command))
"  git rebase --continue\n");
			  "You can fix the problem, and then run\n"
	strbuf_addstr(&buf, "'\nGIT_AUTHOR_DATE='@");
		else
}
}



#include "trailer.h"
		item->commit = NULL;
				 const char *var, const char *value)
			else {

		return 1;
	    ref_transaction_commit(transaction, err)) {
	} else if (get_oid("HEAD", &head_oid)) {
		char *p = buf.buf;
		/* skip merging an ancestor of HEAD */
			strbuf_reset(&buf);
	struct label_state state = { OIDMAP_INIT, { NULL }, STRBUF_INIT };
 *   0 - success
static void flush_rewritten_pending(void)
	int subject_len;
	struct strbuf sb = STRBUF_INIT;
	struct object_id head_oid, *cache_tree_oid;
	}
	}
		unborn = get_oid("HEAD", &head);
		error(_("missing 'GIT_AUTHOR_NAME'"));
"\n"
	enum todo_command command = opts->action == REPLAY_PICK ?
				strbuf_addf(out, "%s %s\n",
		rollback_lock_file(&lock);
					fprintf(f, "%d\n", todo_list->done_nr);
static void write_strategy_opts(struct replay_opts *opts)
	rev.diffopt.output_format =
		cleanup = COMMIT_MSG_CLEANUP_ALL;

		if (!file_exists(git_path_revert_head(r))) {
	struct commit *commit;
		unuse_commit_buffer(current_head, message);
			if (post_rewrite_hook) {
		struct strbuf sb = STRBUF_INIT;
				setenv(GIT_REFLOG_ACTION, prev_reflog_action, 1);

	free(date);
		switch (action) {
				       NULL, 0))
int sequencer_make_script(struct repository *r, struct strbuf *out, int argc,


			  const char *prefix,

			    next_tree, base_tree);
		else
		ret = !!run_git_commit(r, git_path_merge_msg(r), opts,
	if (parse_commit(head_commit))
		strbuf_addstr(&buf, "\n\n");
	for (;;)
		if (is_empty && !keep_empty)
		ret = safe_append(rebase_path_refs_to_delete(),
	struct ref_transaction *transaction;
		while (*bol) {
				starts_with(subject, "fixup!") ?

		return rebase_path();
			const char *post_rewrite_hook =
	head_commit = lookup_commit(r, &head_oid);
	}
{
		struct object_id *oid = &revs->cmdline.rev[0].item->oid;
	else if (!(flags & EDIT_MSG))
	{ 0,   "revert" },
	if (originally_empty)
	*end_of_object_name = '\0';
	if (!clean)
		}

		} else if (!strcmp(s, "scissors")) {
static int single_pick(struct repository *r,
 * error, 0 otherwise.
	}
	struct todo_list todo_list = TODO_LIST_INIT;
		checkout_onto(r, opts, onto_name, &onto->object.oid, orig_head);
	 * reverse of it if we are revert.
	 * than calling find_unique_abbrev() because we also need to make
			return error(_("could not parse parent commit %s"),
			fprintf(stderr,
		if (!opts->have_squash_onto) {
		 *  non-merge commit
				can_fast_forward = 0;
		todo_list_write_total_nr(todo_list);
	int clean;
{
static ssize_t strbuf_read_file_or_whine(struct strbuf *sb, const char *path)
			 int append_eol)

			if (!rollback_is_safe())
	revs.verbose_header = 1;
	return git_diff_basic_config(k, v, NULL);
		struct commit_list *remotes = NULL;
#include "oidmap.h"
"  git commit --amend %s\n"

		argv_array_push(&cmd.args, "--no-ff");
}
	struct object_id oid;
static struct commit *lookup_label(const char *label, int len,
	const char *in_progress_error = NULL;
	int i;
	while (++i < todo_list->nr)

{



					reschedule = 1;
			for (;;) {


		argv_array_pushf(&cmd.args, "-S%s", opts->gpg_sign);
		parent = commit->parents->item;
	sequencer_remove_state(&opts);
{
		unlink(git_path_merge_msg(r));
static GIT_PATH_FUNC(rebase_path_signoff, "rebase-merge/signoff")
 * is moved here when it is first handled, before any associated user
	{ 'd', "drop" },
		}
	}
	tree = parse_tree_indirect(&oid);
		goto leave_merge;
	else
		char *eol;
		while (oidset_contains(&interesting, &commit->object.oid) &&
		if (is_empty && !keep_empty)
	unsigned int flags = opts->edit ? EDIT_MSG : 0;
		print_advice(r, res == 1, opts);


		if (index_differs_from(r, "HEAD", NULL, 0)) {
{
	return reset_merge(&head_oid);
		    (p2 = strchr(++p1, '\'')))
			return error(_("could not read HEAD"));
		argv_array_push(&cmd.args, "--cleanup=strip");
	if (!read_oneliner(buf, rebase_path_strategy(), 0))
			item->command = TODO_COMMENT + 1;

				for (i2 = 0; i2 < i; i2++)
			while (i < istate->cache_nr &&
		return error_errno(_("could not lock HEAD"));
		/* Stopped in the middle, as planned? */
			int cur = i;


	return 0;
			 absolute_path(get_git_work_tree()));
	int ret;
	if (rearranged) {
	int ret = 0;
		else
	if (status < 0)

				 shortrevisions, shortonto, &buf);
	return ret;
	if (!skip_prefix(sb->buf, tmpl.buf, &start))
	base_items = xcalloc(commands->nr, sizeof(struct todo_item));
	int i;

			p = arg + oneline_offset;
		opts->gpg_sign = git_config_bool(k, v) ? xstrdup("") : NULL;
		BUG("invalid todo list after expanding IDs:\n%s",
 * If we are cherry-pick, and if the merge did not result in
		/*
{
	if (!commit)

			insert = 1;
			return -1;
				  " \"git stash drop\" at any time.\n"));
				 (commit2 =
		/*
	{ 'b', "break" },
			if (update_ref(msg, head_ref.buf, &head, &orig,


	 * found a conforming footer with a matching sob
		    int flags, struct replay_opts *opts)
	if (!is_null_oid(oid))
	 * If the whole message buffer is equal to the sob, pretend that we
	} else if (exit_code) {
				     git_path_merge_msg(r), 0);
	argv[0] = find_hook("post-rewrite");
			     repo_read_index(r) < 0))
	head_tree = parse_tree_indirect(head);
	 */
	}
			int res;
			opts);
	/* force re-reading of the cache */
		return error(_("failed to finalize '%s'"), filename);
				print_commit_summary(r, NULL, &oid,
		argv_array_push(&store.args, "autostash");
	} else
	for (i = 0; i < opts->xopts_nr; i++) {
			opts->reschedule_failed_exec = 1;

	}
	todo_list_write_total_nr(&new_todo);
	if (opts->reschedule_failed_exec)
	struct commit *commit;
				unlink(rebase_path_fixup_msg());
#include "diff.h"
							opts, res, 0);
	}
						short_commit_name(commit),
	free(subjects);
	strbuf_release(&buf);
		return error(_("cannot read HEAD"));
	write_message("no-ff", 5, git_path_merge_mode(r), 0);
			child.in = open(rebase_path_rewritten_list(), O_RDONLY);
				      "top of a [new root]"));
		return error(_("%s: cannot parse parent commit %s"),


		ret = 0;
	const char *eol;

	if (command == TODO_REVERT && ((opts->no_commit && res == 0) || res == 1) &&
				/* found by title */
	rev.verbose_header = 1;
		repo_rerere(r, opts->allow_rerere_auto);

	out->subject = xmemdupz(subject, subject_len);
				    git_path_merge_msg(r));
			in_progress_advice =

	 *
			  "Once you are satisfied with your changes, run\n"
	if (fd < 0)
			argv_array_push(&cmd.args, "octopus");
	case REPLAY_PICK:
			 * message.
				   &p->item->object.oid)) {
						    todo_list->current),
							item->commit,
					if (subjects[i2] &&
static GIT_PATH_FUNC(rebase_path_refs_to_delete, "rebase-merge/refs-to-delete")
 */
 */
			}
			goto leave_merge;
			    arg1, arg2, NULL))
				res = error(_("could not read 'onto'"));
	res = pick_commits(r, &todo_list, opts);
	struct argv_array child_env = ARGV_ARRAY_INIT;

	return res;
		if (!opts->quiet) {
	if (append_eol && write(msg_fd, "\n", 1) < 0) {
		res |= error_errno(_("could not open '%s'"), buf.buf);
	return -1;
			struct todo_list *todo_list,
				enum object_type type = oid_object_info(r,
	if (strbuf_getline_lf(&buf, f)) {
		 !opts->signoff && !opts->record_origin &&
		if (!buf->len) {
	}

				unuse_commit_buffer(commit, p);
				term_clear_line();
	}
		for (; *label; label++)

{
			; /* do nothing */
 * Returns 1 if the file was read, 0 if it could not be read or does not exist.
	char *subject;
					strbuf_addstr(buf, " -c");
		struct subject2item_entry *entry;
			if (res) {
		if (!final_fixup)
		struct commit_list *p = commit->parents->next;
		} else if (!hashmap_get_from_hash(&subject2item,
							tips_tail)->next;
	} else {
				hook.trace2_hook_name = "post-rewrite";
	 * may die() in case of a syntactically incorrect file. We do not care
	free(email);
					      opts);
	const char *todo_file = get_todo_path(opts);
	 * - get onelines for all commits

				/* Reschedule */
		skip_prefix(arg, "--", &arg);
		strbuf_addstr(&buf, _("This is the 1st commit message:"));
	strbuf_addch(&sob, '\n');
	FREE_AND_NULL(todo_list->items);

			unuse_commit_buffer(head_commit, head_message);
	}

	argv_array_push(&child.args, "stash");
leave:
		strbuf_add(&sb, msg->buf, nl + 1 - msg->buf);

		       struct replay_opts *opts)
	if (!istate->cache_tree)
		apply_autostash(opts);
				continue;
		o.buffer_output = 2;
	unpack_tree_opts.merge = 1;
	string_entry = oidmap_get(&state->commit2label, oid);

	if (run_git_commit(r, final_fixup ? NULL : rebase_path_message(),
		for (i = 0; i < opts->xopts_nr; i++)


"\n"
	if (!transaction ||
			if (!strcmp(buf.buf, "--rerere-autoupdate"))
						todo_list->done_nr,
	free(opts->xopts);


			entry = hashmap_get_entry_from_hash(&subject2item,
	opts->strategy = strbuf_detach(buf, NULL);
	for (iter = tips; iter; iter = iter->next) {
	if (write_message(p, strlen(p), rebase_path_stopped_sha(), 1) < 0)
	strbuf_addf(&msg, "rebase (label) '%.*s'", len, name);

	}
 */
			unlink(git_path_merge_msg(r));
	{ 'f', "fixup" },
		strbuf_addf(&header, "%c ", comment_line_char);


	argv[2] = NULL;
		unlink(git_path_cherry_pick_head(r));

		sequencer_remove_state(opts);
	 *

		if (update_squash_messages(r, command, commit, opts))
const char *todo_item_get_arg(struct todo_list *todo_list,
	*dest = xstrdup(value);
	if (bases && oideq(&merge_commit->object.oid,
		error(_("stored pre-cherry-pick HEAD file '%s' is corrupt"),
		parse_merge_opt(&o, opts->xopts[i]);
	/*

		}
				continue;
		argv_array_pushl(&cmd.args, "-C", "HEAD", NULL);
		parents = copy_commit_list(current_head->parents);
	struct strbuf *buf = &todo_list->buf;
	item->arg_len = (int)(eol - bol);
				name_i = error(_("'GIT_AUTHOR_NAME' already given"));
{
		error_errno(_("could not write to '%s'"), filename);
		*action = REPLAY_PICK;
			entry = oidmap_get(&state.commit2label, oid);

					    cmd_label, entry->string);
		} else if (item->command == TODO_MERGE) {
static GIT_PATH_FUNC(git_path_todo_file, "sequencer/todo")
release_todo_list:
				}
	if (buf->len == 0) {
	if (!strcmp(k, "commit.cleanup")) {
		parse_commit(item->commit);
				free(opts->gpg_sign);
		return error(_("could not resolve HEAD commit"));
		return 0;
				struct commit *commit;
			argv_array_push(&child.args, "notes");

		return -1;
}
				break;

#include "notes-utils.h"
				       "--continue' again."));
	if (is_clean) {

static const char *implicit_ident_advice(void)
		return -1;
		 * the job of this function.
	FILE *out;
 * command-line.
static GIT_PATH_FUNC(rebase_path_orig_head, "rebase-merge/orig-head")

	const char *eol;
				 * If we are rewording and have either
	/*
	}
		enum todo_command next_command)
"\n"
		}
"\n"
	}
			       struct commit *commit,
}
	 */
	struct object_id oid;
		return error(_("failed to finalize '%s'"), filename);

	return index < todo_list->nr ?

		}

	struct todo_item *item;
	struct strbuf author_ident = STRBUF_INIT;
		return use_editor ? COMMIT_MSG_CLEANUP_ALL :
				       "working tree. Please, commit them\n"
	/*
				break;
	for (i = 1; *p; i++, p = next_p) {
			unlink(dest);

	for (i = 0; i < opts->revs->pending.nr; i++) {
static int subject2item_cmp(const void *fndata,
			eol = strchrnul(bol, '\n');
static int populate_opts_cb(const char *key, const char *value, void *data)
	strbuf_reset(&buf);
				return 0;
						_("Stopped at %s...  %.*s\n"),

		die(_("Invalid cleanup mode %s"), cleanup_arg);
		 * that represents the "current" state for merge-recursive
	    write_locked_index(r->index, &lock, COMMIT_LOCK)) {

		return -1;
	}
		enum todo_command command = todo_list->items[i].command;
{
	if (code)
		*commit_todo_item_at(&commit_todo, item->commit) = item;
			fixup_okay = 1;


			const char *orig_message = NULL;
	if (flags & SUMMARY_SHOW_AUTHOR_DATE) {

	if (opts->current_fixup_count > 0) {
	return ret;
				   struct strbuf *buf)
			if (res && is_fixup(item->command)) {
			strbuf_addstr(buf, command_to_string(item->command));
		max = num;
	if (strbuf_read_file_or_whine(&todo_list->buf, todo_file) < 0)
			 */
					flags = (flags & ~EDIT_MSG) | CLEANUP_MSG;
			 !file_exists(rebase_path_stopped_sha())) {

	struct strbuf buf = STRBUF_INIT;
{
	struct rev_info rev;
		if (entry)
		fputs(buf.buf, stderr);
	struct object_id oid;
		strbuf_addstr(&format, "\n Committer: ");
		}

			opts->have_squash_onto = 1;
			warning(_("invalid commit message cleanup mode '%s'"),

	enum replay_action action = -1;


 * need to be committed following a user interaction.

		return -1;
missing_author:
		if (file_exists(rebase_path()) &&
	strbuf_release(&o.obuf);
		res |= git_config_set_in_file_gently(opts_file,
			const char *hex;
				    opts->current_fixups.len,
	else if (!strcmp(key, "options.keep-redundant-commits"))
		hashmap_entry_init(&onto_label_entry->entry, strihash("onto"));
	 * clash with any other label.


			    !get_oid(buf.buf, &orig) &&
	 * particular subcommand we're trying to execute and barf if that's not

static int run_prepare_commit_msg_hook(struct repository *r,
	if (show_hint) {
	if (!run_command(&child))
	 * (3) we allow ones that were initially empty, but
	}
	switch (command) {
		return 2;
				/* copy can be a prefix of the commit subject */
	strbuf_vaddf(&buf, fmt, ap);
		/*
	error(_("your local changes would be overwritten by %s."),

		format = xstrdup("%s");
 * An exception is when run_git_commit() is called during an
	if (update_head_with_reflog(current_head, oid,
{

	 * The hashmap maps onelines to the respective todo list index.
	return 0;
	if (!f && errno == ENOENT) {
			strbuf_addf(out, " %c empty", comment_line_char);
			int len = opts->current_fixups.len;
			if (is_rebase_i(opts))
}
		buf = np + (*np == '\n');
		}
{
							   strihash(buf->buf),
	size_t len;
					"options.strategy", opts->strategy);
	 * sure the user can't have committed before.
		return error(_("failed to finalize '%s'"), git_path_head_file());
	struct oidmap commit2label;
	strbuf_release(&oneline);
			*end_of_arg = saved;
	if (is_rebase_i(opts) && clean <= 0)
#define CREATE_ROOT_COMMIT (1<<5)
					      &log_tree_opt.diffopt);
		append_signoff(&msgbuf, 0, 0);
}
		return -1;
	transaction = ref_transaction_begin(&err);
			git_config_bool_or_int(key, value, &error_flag);
	free(format);
	struct labels_entry *labels_entry;
					head_ref.buf);

	ALLOC_GROW(todo_list->items, todo_list->nr + 1, todo_list->alloc);
	}
{

		BUG("unexpected action in sequencer_skip");
		need_cleanup = 1;
}
	struct strbuf label = STRBUF_INIT;
		argv_array_push(&cmd.args, "-s");
	if (config_exists)
			/*
			opts->explicit_cleanup = 1;
struct commit_message {
			struct object_id head, orig;
	 * As we insert the exec commands immediately after rearranging
	}
	int reapply_cherry_picks = flags & TODO_LIST_REAPPLY_CHERRY_PICKS;
	case TODO_FIXUP:
	const struct object_id *ptree_oid;
			advise(_(rescheduled_advice),

	item->arg_offset = bol - buf;
		ret = error(_("could not write index"));
 * Rearrange the todo list that has both "pick commit-id msg" and "pick
}
	else if (!strcmp(key, "options.allow-empty"))
		reword = 1;
		struct object_id head;
		if (write_index_as_tree(&head, r->index, r->index_file, 0, NULL))
				const char *encoding = get_commit_output_encoding();
	strbuf_release(&buf);
				date_i = error(_("'GIT_AUTHOR_DATE' already given"));
N_("Could not execute the todo command\n"
					  child_env.argv);
	strbuf_addch(msgbuf, '\n');
			  "  git rebase --continue\n"
					break;
		flags |= AMEND_MSG;
					      &head_commit->object.oid, 0,
		strbuf_addstr(&msgbuf, msg.subject);
			     git_path_merge_msg(r));
void sequencer_post_commit_cleanup(struct repository *r, int verbose)
	trailer_info_get(&info, sb->buf, &opts);

	if (!value)
	default:
		base = parent;
	struct strbuf buf = STRBUF_INIT;
}
	if (flags & TODO_LIST_APPEND_TODO_HELP)
	if (parse_oid_hex(buf.buf, &oid, &p) || *p != '\0') {

		return -1;
		}
	}
			memset(&log_tree_opt, 0, sizeof(log_tree_opt));
		char cmd;

	if (ret <= 0)
	strbuf_release(&buf);

	 *
	else
#define VERIFY_MSG  (1<<4)
}
		res |= try_merge_command(r, opts->strategy,
	} else {

	/*
				 * opening the commit message in the editor.

	else if ((opts->signoff || opts->record_origin) &&
int sequencer_determine_whence(struct repository *r, enum commit_whence *whence)
	if (!cache_tree_fully_valid(istate->cache_tree))
			goto fast_forward_edit;
		item = append_new_todo(todo_list);
	if (!opts->allow_empty)

	 * lookup_commit, would have indicated that head_commit is not
			}
	struct strbuf *buf = &todo_list->buf, buf2 = STRBUF_INIT;
	}
			    oid_to_hex(&commit->object.oid));
						struct subject2item_entry,
			item->flags |= TODO_EDIT_MERGE_MSG;
"\n"

			opts->quiet = 1;
				continue;
		for (iter2 = list; iter2; iter2 = iter2->next) {
		    const char *shortrevisions, const char *onto_name,
		else
		return error(_("illegal label name: '%.*s'"), len, name);
			continue;
"\n"
		char *bol = buf.buf, *eol;
	todo_list_to_strbuf(r, todo_list, &buf, num, flags);
			tips_tail = &commit_list_insert(to_merge->item,
	if (final_fixup) {
				opts->current_fixup_count = 0;
			opts->current_fixup_count = 1;
	switch (opts->action) {


	res = write_message(buf.buf, buf.len, rebase_path_author_script(), 1);
	strbuf_addstr(&sob, sign_off_header);
{
	else
			 * Only if it is the final command in the fixup/squash
			item->arg_offset = bol - buf;

	}
		warning(_("You seem to have moved HEAD. "
		strbuf_reset(&oneline);
		       !oidset_contains(&shown, &commit->object.oid)) {
	else if (!strcmp(cleanup_arg, "scissors"))
 * If we are revert, or if our cherry-pick results in a hand merge,
}
	strbuf_release(&ref_name);
			}
	if (fd < 0)
	if (!todo_list->nr)



		res |= write_message(msgbuf.buf, msgbuf.len,

				       struct strbuf *msg,
	retval = 0;
		opts->record_origin = git_config_bool_or_int(key, value, &error_flag);

{
				"options.keep-redundant-commits", "true");

	format_commit_message(commit, "%cn <%ce>", &committer_ident, &pctx);
			else

 * NB using int rather than enum cleanup_mode to stop clang's
	drop_commit = 0;
}
		      merge_arg_len, arg);
	if (command < TODO_COMMENT)
	int orig_len = buf->len;
}
 *
			      struct replay_opts *opts)
		if (cache_tree_update(istate, 0)) {
int todo_list_rearrange_squash(struct todo_list *todo_list)
		FLEX_ALLOC_STR(entry, string, "onto");

					if (!opts->verbose)
			opts->default_msg_cleanup = COMMIT_MSG_CLEANUP_SPACE;
	if (bol == eol || *bol == '\r' || *bol == comment_line_char) {
			return 0;

	struct rev_info log_tree_opt;
				 */
			break;

	if (file_exists(git_path_cherry_pick_head(r))) {
	else if (!strcmp(cleanup_arg, "verbatim"))
					oid_to_hex(&j->item->object.oid));

		ret = error(_("nothing to merge: '%.*s'"), arg_len, arg);
	if ((flags & ALLOW_EMPTY))
	return find_unique_abbrev(&commit->object.oid, DEFAULT_ABBREV);
#include "sigchain.h"
	if (commit) {
		/* add commit id */
			*whence = FROM_CHERRY_PICK_SINGLE;


	if (is_rebase_i(opts) && write_author_script(msg.message) < 0)
}
	if (repo_hold_locked_index(r, &lock, LOCK_REPORT_ON_ERROR) < 0)
}
	/*
	 * If HEAD is not identical to the first parent of the original merge
						todo_list->total_nr,
		for (i = 0; i < todo_list->nr; i++)
			opts->default_msg_cleanup = COMMIT_MSG_CLEANUP_ALL;
 * Should empty commits be allowed?  Return status:
	 * For octopus merges, the arg starts with the list of revisions to be
		strbuf_release(&buf);
	return 0;
		struct strbuf buf = STRBUF_INIT;
		else
	merge_arg_len = oneline_offset = arg_len;

enum todo_item_flags {
		DIFF_FORMAT_SHORTSTAT | DIFF_FORMAT_SUMMARY;
			entry = oidmap_get(&commit2todo, oid);

	}
		for (cnt = 1, p = commit->parents;
			  "\n"), command_line);

}
	}
				res = error(_("could not read orig-head"));

		if (get_oid("HEAD", &head))
		error("%s", err.buf);
	if (is_rebase_i(opts))

	}
			 */
		strbuf_addf(&buf, "\n%c ", comment_line_char);
		      struct replay_opts *opts)

 * author metadata.
				DIFF_FORMAT_DIFFSTAT;
	if (prepare_revision_walk(&revs) < 0)
#include "unpack-trees.h"
			oid_to_hex_r(p, oid);
	int fd;

	int check_todo;

		} else {

	ssize_t written;
			    ++opts->current_fixup_count + 1);
			 * If the label already exists, or if the label is a
	 * Check whether the subcommand requested to skip the commit is actually
static int fast_forward_to(struct repository *r,
				opts->gpg_sign = xstrdup(buf.buf + 2);

					peek_command(todo_list, 1));
	if (!file_exists(buf.buf)) {
	 * We disallow "interesting" commits to be labeled by a string that
	strbuf_release(&sb);

	const char *p;
		/* add all the rest */
				/* found by commit name */
	return -1;
			/* command not found */
	return 0;
		const char *encoding = get_commit_output_encoding();
		char *np;
 * The author script is of the format:
	ALLOC_ARRAY(tail, todo_list->nr);
							arg, item->arg_len,
			git_path_opts_file());
"    git commit --amend --reset-author\n");
				  enum todo_command command,
				if (read_populate_todo(r, todo_list, opts))
		} else if (item->command == TODO_EXEC) {

		return -1;
		return -1;
	}

				    todo_item_get_arg(todo_list, item));

	if (status < 0)
		todo_list->current++;
{
		}
		}
	unsigned no_dup_sob = flag & APPEND_SIGNOFF_DEDUP;


				goto cleanup_head_ref;
				return res | error_with_patch(r, item->commit,
		return rollback_single_pick(r);
		}
		strbuf_addf(&buf, "author %s", git_author_info(0));
		 * Sanitize labels by replacing non-alpha-numeric characters
	}
			}
		if (!file_exists(git_path_cherry_pick_head(r))) {
	int code;
		next++;
	/*
		strbuf_vaddf(&buf, fmt, ap);
		/* Add the tips to be merged */

	*email = kv.items[email_i].util;
	nl = strchr(msg->buf, '\n');
"\n"
			   oid_to_hex(&onto->object.oid));
				strbuf_reset(&oneline);
		opts->edit = git_config_bool_or_int(key, value, &error_flag);
	va_end(ap);
	return todo_list->buf.buf + item->arg_offset;
	return 0;
			p += 1 + strspn(p + 1, " \t\n");
	if (get_oid(orig_head, &oid))
	for (i = 0; i < todo_list->nr; i++)

			else

		struct strbuf rev = STRBUF_INIT;
	} else if (file_exists(rebase_path_stopped_sha())) {
		} else if (!is_noop(item->command))
	int next = todo_list->current, offset, fd;
	}
	if (!cleanup_arg || !strcmp(cleanup_arg, "default"))
	return ret;
		res = write_message(opts->current_fixups.buf,
		      struct commit *onto, const char *orig_head)
	}
static int rest_is_empty(const struct strbuf *sb, int start)
	if (ret)
			i = eol;
		else if (skip_prefix(oneline.buf, "Merge pull request ",
		const char *done_path = rebase_path_done();
	{ 'r', "reword" },

{
			strbuf_addstr(&buf, label_oid(oid, label.buf, &state));
		if (is_fixup(peek_command(todo_list, 0)))
{
			gpg_sign_opt_quoted(opts));
		/* This happens when using --stdin. */
			return error(_("%s: bad revision"), name);
 *

			       &name, &email, &date, 0))
	setenv(GIT_REFLOG_ACTION, action_name(opts), 0);
			opts->explicit_cleanup = 1;
}
				strbuf_addf(&buf, " %c empty",

{

		if (!*message || starts_with(message, "\n")) {
		shown = OIDSET_INIT;
	int i;
			}
		} else {
	int i, max = todo_list->nr;
	strbuf_release(&sb);
	}
	free(opts->gpg_sign);
		rollback_lock_file(&msg_file);
	int i, saved, status, padding;
		todo_list_release(&new_todo);
					item->arg_len, arg);
	int fd = hold_lock_file_for_update(&lock, filename,
	struct strbuf sb = STRBUF_INIT;
			 *
				res = error(_("cannot read HEAD"));

	return -1;
		strbuf_addstr(&buf, body);
{

		strbuf_addbuf_percentquote(&format, &date);

	} else if (!file_exists(get_todo_path(opts)))
		if (!message) {
		skip_prefix(head, "refs/heads/", &head);
		return error(_("invalid value for %s: %s"), key, value);
	free(tail);
			    !is_fixup(peek_command(todo_list, 0))) {
	}
			else {
static int rollback_is_safe(void)
 * accumulated into message-fixup or message-squash so far.
			_("try \"git cherry-pick (--continue | %s--abort | --quit)\"");
	return git_path_seq_dir();
#include "run-command.h"

	if (opts->verbose)
#define GIT_REFLOG_ACTION "GIT_REFLOG_ACTION"
		free_commit_list(common);
	}

	if (repo_hold_locked_index(r, &lock, LOCK_REPORT_ON_ERROR) < 0) {
}
	hashmap_entry_init(&labels_entry->entry, strihash(label));
	repo_init_revisions(r, &revs, NULL);
{


	}



	if (opts->allow_rerere_auto == RERERE_AUTOUPDATE)
	int use_editor)
			  NULL, 0,
	 *
int sequencer_continue(struct repository *r, struct replay_opts *opts)
	status = get_oid(bol, &commit_oid);
		repo_rerere(r, opts->allow_rerere_auto);
	return res;

			msg_file = rebase_path_squash_msg();
		apply_autostash(opts);

	 * in progress and that it's safe to skip the commit.
 * command is processed, this file is deleted.
}
	if (opts->allow_ff && skip_unnecessary_picks(r, &new_todo, &oid)) {
		return error_errno(_("could not open '%s'"), path);
	 * be moved to appear after the i'th.
		goto leave;
static const char *reflog_message(struct replay_opts *opts,
			check_todo = 1;
		      : _("could not apply %s... %s"),
		if (read_oneliner(&buf, rebase_path_allow_rerere_autoupdate(), 1)) {
	const char *encoding;
}

	if (todo_list_parse_insn_buffer(r, new_todo.buf.buf, &new_todo) < 0)



static GIT_PATH_FUNC(rebase_path_fixup_msg, "rebase-merge/message-fixup")
		commit_list_insert(current_head, &parents);

				       (const char ***)&opts->xopts);
	code = start_command(&proc);
			  const struct object_id *oid,
{
	}
static const char sign_off_header[] = "Signed-off-by: ";
static struct {
static GIT_PATH_FUNC(rebase_path_amend, "rebase-merge/amend")
	}
	if (flags & AMEND_MSG) {
		if (is_pick_or_similar(command) && opts->have_squash_onto &&
		return error(_("unable to copy '%s' to '%s'"),
			return error(_("revision walk setup failed"));
		}
{

	}
		if (!final_fixup)
		strbuf_release(&buf);
		}
	if (parse_commit(commit))
	char string[FLEX_ARRAY];
	struct lock_file lock = LOCK_INIT;
	if (advice_resolve_conflict) {
		 * We do not intend to commit immediately.  We just want to
		struct todo_item *item = todo_list->items + i;
			strbuf_addf(buf, "%.*s\n", item->arg_len,
		item->command = TODO_NOOP;
				  lookup_commit_reference_by_name(p)) &&
	/*

		if (status == 127)
		if (!is_empty && (commit->object.flags & PATCHSAME))
	strbuf_addf(&sb, "%s %s\n", oid_to_hex(oldoid), oid_to_hex(newoid));

	int ret;
			    const struct object_id *new_head,
		strbuf_addf(&buf, "%s -C %s",
static const char *reflog_message(struct replay_opts *opts,

 * The file into which is accumulated the suggested commit message for


		return 0;
static GIT_PATH_FUNC(rebase_path_gpg_sign_opt, "rebase-merge/gpg_sign_opt")
			eol = sb->len;

				_("Applying autostash resulted in conflicts.\n"
			if (!is_fixup(peek_command(todo_list, 0))) {
	if (commit) {
		rollback_lock_file(&lock);
{
}
	}
 * with our parsing, as the file was meant to be eval'd in the now-removed
	if (fmt) {

		 * If CHERRY_PICK_HEAD or REVERT_HEAD indicates
				hook.in = open(rebase_path_rewritten_list(),

			buf.buf : strchrnul(buf.buf, '\n');
	if (strbuf_read_file(&buf, todo_path, 0) < 0) {

			       get_item_line_length(todo_list,

	 * Four cases:



		     struct object_id *oid)
			}
	p = short_commit_name(commit);
		    struct commit *commit,
		item->offset_in_buf = p - todo_list->buf.buf;
			msg_file = rebase_path_fixup_msg();
	 * opts->action tells us which subcommand requested to skip the commit.
		commit = iter->item;
		 */
static GIT_PATH_FUNC(rebase_path_head_name, "rebase-merge/head-name")
	else if (errno == ENOENT)


	if (written < 0) {
				      oideq(&opts->squash_onto, &oid))))
 * When an "edit" rebase command is being processed, the SHA1 of the
};
	struct object_id head;
	proc.stdout_to_stderr = 1;

		 !opts->explicit_cleanup)
			} else {
	} else {
	struct strbuf commit_msg = STRBUF_INIT;
	if (commit_tree_extended(msg->buf, msg->len, &tree, parents,

#include "commit.h"
				  struct replay_opts *opts)
	 * For "uninteresting" commits, i.e. commits that are not to be
		strbuf_addstr(&msgbuf, ".\n");
			/* only show if not already upstream */
static int error_failed_squash(struct repository *r,
			if (save_todo(todo_list, opts))
					to_amend = 1;
	strbuf_release(&ref_name);
		rollback_lock_file(&lock);

		}
	rollback_lock_file(&lock);
	 * Sequence of picks finished successfully; cleanup by

	struct pretty_print_context pctx = {0};
	else
		if (errno == ENOENT && allow_missing)
	if (found_sob)
			if (is_rebase_i(opts) && res < 0) {
	if (!log_tree_opt.diffopt.file)
		if (file_exists(rebase_path_reschedule_failed_exec()))

	while ((commit = get_revision(opts->revs))) {
			while (len && p[len - 1] != '\n')
	return res;
				todo_list->current--;

		if (bol != eol)
	}
 * is always true.
	case TODO_REVERT:
			dirty ? N_("and made changes to the index and/or the "
		 * illegal in file names (and hence in ref names).
		return;
 * finishes. This is used by the `label` command to record the need for cleanup.
				goto cleanup_head_ref;
	struct commit *head_commit, *merge_commit, *i;
		res = fast_forward_to(r, &commit->object.oid, &head, unborn,
		return N_("rebase");
static const char *get_dir(const struct replay_opts *opts)
	strbuf_addch(&buf, '\'');
	strbuf_trim(&stash_sha1);
		/* Octopus merge */
	}

	update_abort_safety_file();
		    struct commit *onto, const char *orig_head,
			 * body and the sob.
			break; /* merge commit */



	}
		write_file(rebase_path_strategy(), "%s\n", opts->strategy);
		find_commit_subject(message, &body);

		apply_autostash(opts);
		items[nr++] = todo_list->items[i];

		find_commit_subject(head_message, &body);
				goto give_advice;
		return N_("revert");
			goto out;
				"working tree\n") : "");
			if (write_rebase_head(oid))
	if (opts->verbose)

		return error_errno(_("could not create sequencer directory '%s'"),
	res = write_message(buf.buf, buf.len, rebase_path_squash_msg(), 0);
		       struct commit *cmit,

		res = try_to_commit(r, msg_file ? &sb : NULL,
	return 0;
	if (opts->gpg_sign)
			return error(_("cannot write '%s'"),
			}
				argv_array_pushf(&cmd.args,
	    strbuf_read_file(&buf, rebase_path_refs_to_delete(), 0) > 0) {
		if (skip_prefix(message, "> ", &message))
	const char *hook_commit = NULL;

GIT_PATH_FUNC(rebase_path_todo, "rebase-merge/git-rebase-todo")
		if (!get_oid(name, &oid)) {
				 * otherwise we do not.
}
}
	 * the case.

	}
			if (oidset_insert(&child_seen, oid))
	cmd.git_cmd = 1;

			strbuf_addch(&buf, *(message++));

		opts.action = REPLAY_REVERT;
		sq_quotef(&buf, "-S%s", opts->gpg_sign);
	}
	char *end_of_object_name;
	 * "skip the commit" as the user already handled this by committing. But
		write_file(git_path_abort_safety_file(), "%s", "");
				  struct object_id *base_oid)
		if (!is_fixup(command))
	}
	const char *strategy = !opts->xopts_nr &&
			return -1;

							      &state));
static int create_seq_dir(struct repository *r)
		goto fast_forward_edit;
	struct object_id dummy;
	strbuf_addf(out, "%s onto\n", cmd_label);

	 * (1) we do not allow empty at all and error out.
	 * REVERT_HEAD, and don't touch the sequencer state.
		return 1;
"on your username and hostname. Please check that they are accurate.\n"
			find_commit_subject(message, &orig_message);
#include "worktree.h"
	const char *head;
static GIT_PATH_FUNC(rebase_path, "rebase-merge")
			break;
{


		if (reschedule) {

 * file and written to the tail of 'done'.
		error_errno(_("could not write eol to '%s'"), filename);
				oid_to_hex(&item->commit->object.oid));

		NULL : opts->strategy;
		      short_commit_name(commit), msg.subject);


	 * If any merge head is different from the original one, we cannot
			 * Initially, all commands are 'pick's. If it is a
		strbuf_stripspace(msgbuf, cleanup_mode == COMMIT_MSG_CLEANUP_ALL);
{
			todo_list->current--;
				    !strstr(p, "\nsquash "))
				"options.allow-empty-message", "true");
			record_in_rewritten(&oid, peek_command(&todo_list, 0));

					opts->xopts[i], "^$", 0);
		/* force re-reading of the cache */
		goto leave;
{
		find_commit_subject(commit_buffer, &subject);
	}
		struct strbuf head_ref = STRBUF_INIT, buf = STRBUF_INIT;
			bol += strspn(bol, " \t");
/*
		}
	strbuf_release(&o.obuf);
	if (!file_exists(path))
		return error(_("could not commit staged changes."));
	    opts->revs->no_walk &&
	int ret = 0;
					  short_commit_name(item->commit) :
	}
 * This file contains the list fixup/squash commands that have been
}
			strbuf_addstr(&msgbuf, p);
	if (!file_exists(git_path_cherry_pick_head(r)) &&
					intend_to_amend();
			  "\n"
				 * message, no need to bother the user with
{
			strbuf_addf(&buf, "%s %s %s", cmd_pick,

}
	 *
			strbuf_addf(buf, " %s", oid);
	while (*message && *message != '\n' && *message != '\r')
	 * on top of the current HEAD if we are cherry-pick.  Or the
	for (i = 0; i < todo_list->nr; i++) {
static int do_commit(struct repository *r,
		} /* else, the buffer already ends with two newlines. */
			goto release_todo_list;
	int res;
}
	cmd->stdout_to_stderr = 1;
	strbuf_release(&sb);
	end_of_object_name = (char *) bol + strcspn(bol, " \t\n");
		}
		item = string_list_append(list, buf);
				if (parse_head(r, &commit) ||
"    git rebase --edit-todo\n"
		opts->default_msg_cleanup = get_cleanup_mode(value, 1);
				      opts->default_msg_cleanup);
	close(proc.in);
				 * create a new root commit, we want to amend,
		struct commit *parent = commit->parents->item;
	return retval;
	const char *in_progress_advice = NULL;

void todo_list_add_exec_commands(struct todo_list *todo_list,

	struct hashmap subject2item;
		fprintf(f, "%d\n", todo_list->total_nr);

	struct string_entry *string_entry;
		     cnt++)
		const char *out_enc = get_commit_output_encoding();

		unlink(rebase_path_current_fixups());
		}
				struct strbuf *buf, int num, unsigned flags)
		    const char *name, int len,
		int len;
				       "first and then run 'git rebase "
		eol = buf.buf[0] != comment_line_char ?
		 *  Non-first parent explicitly specified as mainline for
	todo_list->alloc = alloc;
			strbuf_reset(&buf);
	if (!rebase_merges)
}
		oidcpy(&entry->entry.oid, oid);
{
	struct commit_extra_header *extra = NULL;
					   msg_file);
				       "scissors",
	}
	oidmap_free(&commit2todo, 1);
			if (entry)

		log_tree_commit(&rev, commit);
	}
		ALLOC_GROW(items, nr + 1, alloc);
			fprintf(stderr,

		goto leave_merge;
					commit? &commit->object.oid : NULL);
				reschedule = 1;
{

		if (!strategy)
		strbuf_release(&ref_name);

	 * fast-forward.
		int i2 = -1;

		const char *name = opts->revs->pending.objects[i].name;
 *
					res = error(_("could not parse HEAD commit"));
	argv_array_pushf(env, "GIT_AUTHOR_DATE=%s", date);
	else
			return error_errno(_("unable to read commit message "
	 */
	    update_ref(NULL, "CHERRY_PICK_HEAD", &commit->object.oid, NULL,
			run_commit_flags |= AMEND_MSG;

		goto release_todo_list;
	a = container_of(eptr, const struct labels_entry, entry);
	}
		if ((buf->len == the_hash_algo->hexsz &&
				head_ref.buf, buf.buf);

	ret = merge_recursive(&o, head_commit, merge_commit, reversed, &i);
	if (get_oid("HEAD", &actual_head))
int sequencer_remove_state(struct replay_opts *opts)
}
	else {
		if (close(fd) < 0)
				advise(_(rescheduled_advice),
			res = run_git_commit(r, NULL, opts, EDIT_MSG |
	return buf.buf;
		error(_("failed to find tree of %s"), oid_to_hex(&oid));
	rev.always_show_header = 0;
{

	item->commit = lookup_commit_reference(r, &commit_oid);
	return res;
				strbuf_addf(out, "%s\n", entry->string);
		return 0;



			return error(_("no key present in '%.*s'"),
		opts->xopts[i] = xstrdup(arg);
		base_items[i].arg_len = command_len - strlen("exec ");
	 */
		commit_list_insert(next, &remotes);
		parent = NULL;
		return COMMIT_MSG_CLEANUP_ALL;
		commit_post_rewrite(r, current_head, oid);
{
		return -1;
				_("Successfully rebased and updated %s.\n"),
	struct strbuf buf = STRBUF_INIT;
	 */
	return 0;
			else if (item->commit)
	if (checkout_fast_forward(r, from, to, 1))
}

			unborn = 1;
}
		    oideq(&head, &opts->squash_onto)) {
				 NULL, 0, UPDATE_REFS_MSG_ON_ERR);

		const char *gpg_opt = gpg_sign_opt_quoted(opts);
		free(format);

}
	update_abort_safety_file();
static GIT_PATH_FUNC(rebase_path_squash_msg, "rebase-merge/message-squash")
			strbuf_addstr(&msgbuf, ", reversing\nchanges made to ");
	if (opts->revs->cmdline.nr == 1 &&
static int skip_unnecessary_picks(struct repository *r,
		if (skip_prefix(bol, "-C", &bol))
		if (!(head_commit = lookup_commit_reference(r, &head)))
	else


				/* we don't care if this hook failed */
		ALLOC_GROW(opts->xopts, opts->xopts_nr + 1, opts->xopts_alloc);

			return error_dirty_index(r, opts);
 * GIT_AUTHOR_DATE that will be used for the commit that is currently
		argv_array_push(&cmd.args, "-F");
		return single_pick(r, cmit, opts);
}
	 * (2) we allow ones that were initially empty, and
	if (has_footer != 3 && (!no_dup_sob || has_footer != 2))
			       !strcmp(ce->name, istate->cache[i]->name))
	todo_list->total_nr++;
	 * sure that the abbreviation does not conflict with any other
		size_t len = msgbuf->len - ignore_footer;

 *
	for (i = 0; i < kv.nr; i++) {

			int saved = *end_of_arg;

					bol, oid_to_hex(&newoid));
	struct object_id oid = onto->object.oid;
			strbuf_addstr(&label, p1 + strlen(" from "));
	next_tree = next ? get_commit_tree(next) : empty_tree(r);
	struct object_id head_oid;

"\n"
	strbuf_addf(&buf, "%s/patch", get_dir(opts));
		    !get_oid("REBASE_HEAD", &rebase_head) &&
static GIT_PATH_FUNC(git_path_abort_safety_file, "sequencer/abort-safety")
}
			}

	else {
		return error(_("could not stat '%s'"), todo_file);
	struct strbuf buf = STRBUF_INIT;
	repo_init_revisions(r, &rev, prefix);
				BUG("Incorrect current_fixups:\n%s", p);
			unlink(rebase_path_author_script());
static int do_reset(struct repository *r,
			else
	 * is a valid full-length hash, to ensure that we always can find an
			continue;
	 */
			 * We don't have the hash of the parent so
					     opts, is_final_fixup(todo_list),

#include "tag.h"
		}

static int labels_cmp(const void *fndata, const struct hashmap_entry *eptr,
	if (prepare_revision_walk(opts->revs))
		*cmd_merge = abbr ? "m" : "merge";
	rev.diffopt.break_opt = 0;
					  oid_to_hex(&item->commit->object.oid);
 * after the former, and change "pick" to "fixup"/"squash".
	if (parse_head(r, &current_head))
	init_commit_todo_item(&commit_todo);
			return 0;
	}
}
	const char *abbrev, *subject;
					     rebase_path_squash_msg(), dest);
	{ 0,   NULL }
		}
	}
		error(_("could not parse '%s'"), bol); /* return later */
	if (!file_exists(git_path_opts_file()))
	if (!ret)
			/* we don't care if this copying failed */
	 * any fixups and before the user edits the list, a fixup chain
		write_author_script(buf.buf);
static int make_patch(struct repository *r,
	const char *start;
	if (len == 10 && !strncmp("[new root]", name, len)) {
void parse_strategy_opts(struct replay_opts *opts, char *raw_opts)
	/*
		return error_errno(_("could not write '%s'"), todo_file);
	struct object_id head;
		}
	}

		if (save_todo(todo_list, opts))

			 struct strbuf *msg, const char *author,
"\n"
		commit_list_insert(j->item, &reversed);
static int safe_append(const char *filename, const char *fmt, ...)



			strbuf_addch(&buf, *(message++));
				      &head_commit->object.oid, 0, opts);

void append_conflicts_hint(struct index_state *istate,
	opts->xopts_nr = split_cmdline(strategy_opts_string,

		np = strchrnul(cp, '\n');
				if (repo_parse_commit(r, first_parent)) {
{
		return 0;
"    git config --global --edit\n"
				res = error(_("could not update HEAD to %s"),
		strbuf_release(&header);
define_commit_slab(commit_todo_item, struct todo_item *);
		strbuf_addbuf_percentquote(&format, &author_ident);
		/*
	 * First phase:
 * Take a series of KEY='VALUE' lines where VALUE part is
				       const char *commit)
	return 0;
		struct commit *head_commit;
			else if (valid == TODO_PICK)
		goto out;
	int msg_fd = hold_lock_file_for_update(&msg_file, filename, 0);
 * Try to commit without forking 'git commit'. In some cases we need
		ptree_oid = the_hash_algo->empty_tree; /* commit is root */

	if (res) {
#include "log-tree.h"
		}
		enum todo_command valid =

			else if (!rebase_cousins)
	}
{
			  "\n"
		return 0;
		die_errno(_("unable to resolve HEAD after creating commit"));
	    opts->revs->cmdline.rev->whence == REV_CMD_REV &&
		item->commit = NULL;

		error_errno(_("could not read '%s'"), filename);

 *   1 - run 'git commit'
	 */
}

 * commit without opening the editor.)
		if (get_revision(opts->revs))
	    (!is_rebase_i(opts) || !file_exists(rebase_path_done())))
		 * a single-cherry-pick in progress, abort that.
	struct strbuf format = STRBUF_INIT;
	if (!res && final_fixup) {
}
	}
		} else if (unborn)
} todo_command_info[] = {
			}
	 */
	if (command == TODO_REWORD)

	strbuf_release(&buf2);
				strbuf_addf(buf, "-%d", i);
				starts_with(head_ref.buf, "refs/")) {
		return 1;
			continue;
			eol = nl - sb->buf;
				 * If there was not a single "squash" in the
	/*
			unlink(rebase_path_dropped());
		pretty_print_commit(pp, commit, &oneline);
				i, (int)(eol - p), p);




	if (cfg) {
		return modes[cleanup_mode];
out:
	status = git_gpg_config(k, v, NULL);
 */
					     rebase_path_current_fixups());
				   short_commit_name(commit), subject_len, subject);
				opts->record_origin || opts->edit));
{
	 * (4) we allow both.
	const char *encoding = get_commit_output_encoding();
		 * to work on.


					unuse_commit_buffer(commit, p);
}
	/* left-trim */
		unuse_commit_buffer(item->commit, commit_buffer);
		strbuf_setlen(msgbuf, wt_status_locate_end(msgbuf->buf, msgbuf->len));
		argv_array_push(&store.args, stash_sha1.buf);
	int res;
		goto fail;
				strbuf_addch(buf, '-');
				final_fixup = 1;
 * hand-editing, we will hit this commit and inherit the original
	return finish_command(&proc);
			+ count_commands(todo_list);
		if (is_fixup(item->command)) {
	die(_("unknown command: %d"), command);
	int res;
		strbuf_reset(&opts->current_fixups);

			 * append a dash and a number to make it unique.
		return error(_("could not read index"));
static int read_and_refresh_cache(struct repository *r,
			child.git_cmd = 1;
	int found_sob = 0, found_sob_last = 0;
		 * Note that we retain non-ASCII UTF-8 characters (identified
	}
{
		item->arg_offset = 0;
		argv_array_push(&cmd.args, "--allow-empty");
			  int final_fixup, int *check_todo)
			err = error(_("unknown variable '%s'"),
static int prepare_revs(struct replay_opts *opts)
		int is_empty;

	}
}
#include "merge-recursive.h"
		return status;
				}
		current_head = lookup_commit_reference(r, &oid);
	if (get_oid("HEAD", &oid) && (opts->action == REPLAY_REVERT))
{
{

/*
	} else if (current_head &&


	string_list_clear(&kv, !!retval);
		arg1 = "message";
	}
		res |= git_config_set_in_file_gently(opts_file,


	if (strbuf_read_file(&buf, rebase_path_rewritten_pending(), (GIT_MAX_HEXSZ + 1) * 2) > 0 &&
		    < 0)
				"options.default-msg-cleanup",
	const char *name, *arg1 = NULL, *arg2 = NULL;
		if (read_oneliner(&buf, rebase_path_squash_onto(), 0)) {
	else
static GIT_PATH_FUNC(rebase_path_stopped_sha, "rebase-merge/stopped-sha")
	    update_ref(NULL, "REVERT_HEAD", &commit->object.oid, NULL,
			 action == REPLAY_REVERT ? "revert" : "cherry-pick");
		char *eol = strchrnul(p, '\n');
		git_config_string_dup(&opts->gpg_sign, key, value);
}
	for (i = 0; i < opts->xopts_nr; i++)
	o.branch2 = ref_name.buf;
					"options.signoff", "true");
						  get_todo_path(opts));
		fclose(out);
	const char *command_string = todo_command_info[command].str;
	strbuf_release(&buf);
	return 0;
	if (!transaction) {
{

		argv_array_push(&cmd.args, "merge");
	struct object_id head;
			continue;
	oidmap_put(&state->commit2label, string_entry);
		while (i < eol)
	 */


					- todo_list->items;

	}
	}
		struct strbuf *buf = &state->buf;
			       get_item_line(todo_list, todo_list->current));
		       struct commit *commit)
		return error(_("failed to finalize '%s'"), todo_path);
		ret = error(_("could not remove '%s'"), buf.buf);
		}
			git_config_bool_or_int(key, value, &error_flag) ?
				label_oid(oid, "branch-point", &state);
{
	if (!(cache_tree_oid = get_cache_tree_oid(istate)))
		int fd = open(done, O_CREAT | O_WRONLY | O_APPEND, 0666);
	if (run_commit_hook(0, r->index_file, "prepare-commit-msg", name,


	if (rc)
		goto leave_merge;
 * sq-quoted, and append <KEY, VALUE> at the end of the string list
		res = -1;

	struct strbuf buf = STRBUF_INIT;

	char *parent_label;
	if (advice_commit_before_merge)

		free(opts->xopts[i]);
		if (write_in_full(fd, get_item_line(todo_list, next - 1),
	unpack_tree_opts.dst_index = r->index;
				       REF_NO_DEREF, UPDATE_REFS_MSG_ON_ERR)) {
		return -1;
		((nick && **bol == nick) &&
					    arg, item->arg_len,
	char *amend_author = NULL;
/*
	}
			 * chain, and only if the chain is longer than a single

		write_file(git_path_abort_safety_file(), "%s", oid_to_hex(&head));
	struct object_id oid;
}
					common, oid_to_hex(&head), remotes);
			append_newlines = "\n";
				    author, opts, flags, &oid);
	struct hashmap_entry entry;
		sequencer_remove_state(opts);
	struct child_process cmd = CHILD_PROCESS_INIT;
			argv_array_push(&child.args, "--for-rewrite=rebase");
				   0, sb.buf, &err) ||
int write_basic_state(struct replay_opts *opts, const char *head_name,
	const char *message;
}
#include "utf8.h"
			 (p1 = strstr(p1, " from ")))
		}
		free(subjects[i]);
		ret = run_command(&cmd);
		return -1;
		if (!is_clean && !oideq(&head, &to_amend))
				if (!hashmap_get_from_hash(&state->labels,
		/*
	if (command == TODO_REVERT) {
	}
		if (read_env_script(&cmd.env_array)) {
	}
 */
		 * commit message, the current fixup list and count, and if it

}
"\n"
	if (commit_lock_file(&msg_file) < 0)
		for (; to_merge; to_merge = to_merge->next) {
		argv_array_pushl(&cmd.args, "-F", defmsg, NULL);
			oid_to_hex(&commit->object.oid));
			}
 * message will have to be retrieved from the commit (as the oneline in the

									NULL);
	if (date_i < 0 || email_i < 0 || date_i < 0 || err)
		ALLOC_GROW(items, nr + commands->nr, alloc);
			ret = error(_("unable to parse '%.*s'"), k, p);
	 * Let's reverse that, so that do_merge() returns 0 upon success and
			     struct label_state *state)
			if (opts->current_fixup_count > 0 &&
		       struct replay_opts *opts,
			msg = &commit_msg;
		 */
	}
							arg, item->arg_len,
		}
			    head_tree,
	return sequencer_remove_state(opts);
		 * no conflicting label.
}
			_("dropping %s %s -- patch contents already upstream\n"),
{
"\n"
 *
	    !opts->revs->cmdline.rev->flags) {

	if (strbuf_read_file(&buf, path, 256) <= 0) {
	die(_("unknown action: %d"), opts->action);

		const struct cache_entry *ce = istate->cache[i++];


	strbuf_release(&committer_ident);
		res |= git_config_set_in_file_gently(opts_file,
	strbuf_release(&buf);
 * Note that only the last end-of-line marker is stripped, consistent with the
				     (opts->have_squash_onto &&
	if (!(flags & VERIFY_MSG))
		error(_("could not read HEAD"));
{
			}
#include "cache.h"
		if (i2 >= 0) {
	originally_empty = is_original_commit_empty(commit);

			size_t len = buf->len;
		next = parent;
			    const char *commit, const char *action)
				return stopped_at_head(r);
		return index_unchanged;
		strbuf_addf(&buf, "%c ", comment_line_char);
	strbuf_addf(&ref_name, "refs/rewritten/%.*s", len, name);
	if (msgbuf->len - ignore_footer == sob.len &&

			oneline_offset = p - arg;
	if (commands->nr)
static GIT_PATH_FUNC(git_path_head_file, "sequencer/head")
		fprintf(stderr,
	if (count_commands(todo_list) == 0) {

				}
		return error(_("cannot rebase: You have unstaged changes."));
	if (get_oid("HEAD", &head) ||
static int rollback_single_pick(struct repository *r)
		tail = &commit_list_insert(commit, tail)->next;
			 * commit message is already correct, no need to commit
		res |= git_config_set_in_file_gently(opts_file,


				advise_skip ? "--skip | " : "");



		argv_array_push(&cmd.args, git_path_merge_msg(r));
			res = -1;
		struct object_id oid;
		oidset_insert(&interesting, &commit->object.oid);
{
	 *
		item->arg_offset = bol - buf;
		return error(_("could not detach HEAD"));
}
	can_fast_forward = opts->allow_ff && commit && commit->parents &&
	 * If the corresponding .git/<ACTION>_HEAD exists, we know that the
			fprintf_ln(stderr, _("Could not merge %.*s"),
		strbuf_splice(msgbuf, msgbuf->len - ignore_footer, 0,

	new_todo.total_nr -= new_todo.nr;
	return ret;
	struct strbuf err = STRBUF_INIT;
		res |= git_config_set_in_file_gently(opts_file,
	static struct strbuf buf = STRBUF_INIT;
		if (errno == ENOENT || errno == ENOTDIR)

	}
					strbuf_addstr(buf, " -C");

	 */
		return ret;

			return -1;

		break;
	o.branch1 = "HEAD";
				return error(_("writing fake root commit"));
		argv_array_push(&cmd.args, "--amend");
		strbuf_addf(&buf, _("This is a combination of %d commits."), 2);
		res = write_message(msgbuf.buf, msgbuf.len,
	va_list ap;
	else
			if (!lookup_commit_reference_gently(r, &oid, 1)) {
		goto finish;
{

 * Returns:
	for (p = arg; p - arg < arg_len; p += strspn(p, " \t\n")) {
			return error(_("the script was already rearranged."));
		    starts_with(sb->buf + i, sign_off_header)) {

		goto leave_merge;
			_(action_name(opts)));
		if (cnt != opts->mainline || !p)
	out->label = xstrfmt("%s... %s", abbrev, out->subject);
	} else if (dirty) {
		if (!len) {
				/* `current` will be incremented below */
		return run_git_commit(r, msg_file, opts, flags);
	 * In that case, last[i] will indicate the index of the latest item to

		goto leave_merge;
	strbuf_addstr(&format, "format:%h] %s");

 * author date and name.
				email_i = i;
			BUG("unexpected extra commit from walk");
			  struct commit *commit,
		item->commit = NULL;
					   LOCK_REPORT_ON_ERROR);

				     item->string);
		ret = -1;
			/* was a final fixup or squash done manually? */
		struct commit *cmit;
	if (i > 0) {
static const char cherry_picked_prefix[] = "(cherry picked from commit ";

		item->command = TODO_COMMENT;

			commit_list_insert(commit, &list);
		struct strbuf header = STRBUF_INIT;

						len, name), "HEAD", &oid,
{
	if (copy_file(rebase_path_message(), rebase_path_squash_msg(), 0666))
			      struct todo_item *item)

	int res = 0, reschedule = 0;
	argv_array_pushl(&argv, "reset", "--merge", NULL);
		/* if the item is not a command write it and continue */
		item->arg_len = 0;
static int make_script_with_merges(struct pretty_print_context *pp,

				 */
			commit = commit->parents->item;
	 */
		int check_todo = 0;
		opts.action = REPLAY_PICK;
	const char *argv[3];
{
	if (cleanup_mode != COMMIT_MSG_CLEANUP_NONE)
			strbuf_add(&label, p1, p2 - p1);
	if (head_name)
	return 1;
 * behavior of "$(cat path)" in a shell script.
		if (!author) {
}
	int i, name_i = -2, email_i = -2, date_i = -2, err = 0;
				first_parent = current_head->parents->item;
		res |= git_config_set_in_file_gently(opts_file,
		     const char *msg_file, const char *author,
			     rebase_path_message(),
	return TODO_NOOP <= command;
				struct child_process hook = CHILD_PROCESS_INIT;
	const char *msg_file = opts->edit ? NULL : git_path_merge_msg(r);
	int i;

		warning_errno(_("could not read '%s'"), path);
	int dirty, status;
		todo_list->items = items;
#include "alias.h"
	FILE *out = fopen_or_warn(rebase_path_rewritten_pending(), "a");
		 */
	if (flags & AMEND_MSG)
		if (item->command != TODO_PICK)
	rev.diffopt.detect_rename = DIFF_DETECT_RENAME;
	return buf.buf;
			oidset_insert(&shown, oid);
}
		need_cleanup = 1;
		return 0;
	for (i = todo_list->current + offset; i < todo_list->nr; i++)
		return;
#include "hashmap.h"
			continue;
	if (in_progress_error) {
			enum todo_command command = todo_list->items[i].command;
static void update_abort_safety_file(void)
	} /* else allow == 0 and there's nothing special to do */
					"options.allow-ff", "true");
	parse_strategy_opts(opts, buf->buf);

	 *
}
 *
	struct todo_item *items = NULL, *base_items = NULL;
static int save_todo(struct todo_list *todo_list, struct replay_opts *opts)

	if (get_oid("HEAD", &head))

	if (copy_file(git_path_merge_msg(r), rebase_path_message(), 0666))
		strbuf_reset(&opts->current_fixups);
static int run_git_commit(struct repository *r,
N_("Your name and email address were configured automatically based\n"
				i++;
	}
		/* Determine the length of the label */

	if (!read_oneliner(buf, rebase_path_strategy_opts(), 0))
	if (!commit->parents)
	return rc;
	clear_commit_todo_item(&commit_todo);
		    get_oid(ref_name.buf + strlen("refs/rewritten/"), &oid)) {
	} else if (allow == 2) {
		if (strbuf_read_file(&done.buf, rebase_path_done(), 0) > 0 &&
	size_t ignore_footer)
				first_parent = NULL;

					return -1;
}
static const char staged_changes_advice[] =
	p = oid_to_hex(&head);
		return run_command(&cmd);
	 *
	opts.no_divider = 1;
				if (item->command == TODO_REWORD &&
	if (r->index->cache_changed &&
		strbuf_addstr(&buf, body);
	free(amend_author);

		for (i = 0; i < todo_list->nr; i++) {
	if (!error_flag)
	argv[1] = "amend";
static int read_populate_todo(struct repository *r,
	int count = 0, i;
	free(user_config);
			ret = error(_("could not get commit message of '%s'"),
		}
	int res = 1;
	return ret;
	 */
	ALLOC_ARRAY(next, todo_list->nr);
			flags |= CLEANUP_MSG;

	argv_array_pushf(env, "GIT_AUTHOR_EMAIL=%s", email);


	if (revs->cmdline.nr && (revs->cmdline.rev[0].flags & BOTTOM)) {
			 * actually need to re-commit with a cleaned up commit
		/* Create a label */
			return error(_("commit %s is a merge but no -m option was given."),
		if (intend_to_amend())
		return error_errno(_("could not lock '%s'"), todo_path);
	oidmap_init(&state.commit2label, 0);
	}
		if (advice_implicit_identity) {
				return error(_("could not rename '%s' to '%s'"),
}
	return rest_is_empty(sb, 0);

	a = find_commit_header(message, "author", &len);

				record_in_rewritten(&item->commit->object.oid,
}
		has_footer = 3;

	 * those chains if there are any.
 *
	 * - add HEAD to the branch tips

 * is appended to the file as it is processed.
		if (opts->gpg_sign)
			create_seq_dir(r) < 0)
		}
		len = strlen(body);

		 !opts->explicit_cleanup)
	char *format = NULL;
	return commit;
		write_file(rebase_path_onto(), "%s\n",
			strbuf_addstr(&msgbuf, oid_to_hex(&parent->object.oid));
	struct oidmap_entry entry;
		ret = -1;
	return res;
		return 2;
{


			log_tree_opt.disable_stdin = 1;
		strbuf_addstr(&buf, "\n\n");

 * being rebased.
			opts->allow_ff = 0;

	struct todo_list todo_list = TODO_LIST_INIT;
	return 0;
		base_items[i].arg_offset = base_offset + strlen("exec ");
int sequencer_rollback(struct repository *r, struct replay_opts *opts)
	head_commit = lookup_commit_reference_by_name("HEAD");
			}
		if (file_exists(cherry_pick_head) && unlink(cherry_pick_head))
		if (file_exists(rebase_path_quiet()))
		struct commit_list *common = NULL;
}
	return git_path_todo_file();
{

	else if (!opts->strategy || !strcmp(opts->strategy, "recursive") || command == TODO_REVERT) {
/*

			if (current_head->parents) {
	else if (commit->parents->next) {
				return error(_("no revert in progress"));
		    struct todo_list *todo_list)
			item->flags |= TODO_EDIT_MERGE_MSG;
		 * message...
 * The commit message that is planned to be used for any changes that
				diff_tree_oid(&orig, &head, "",

		if (file_exists(rebase_path_dropped())) {
static const char implicit_ident_advice_noconfig[] =
			      struct replay_opts *opts)
				sob.buf, sob.len);

/*
	refresh_index(r->index, REFRESH_QUIET|REFRESH_UNMERGED, NULL, NULL, NULL);
		warning(_("execution succeeded: %s\nbut "
		argv_array_push(&cmd.args, "--no-gpg-sign");
		if (sob && !strncmp(info.trailers[i], sob->buf, sob->len)) {
	if (cleanup_mode == COMMIT_MSG_CLEANUP_NONE && sb->len)

		    struct replay_opts *opts)
	 */
	out->parent_label = xstrfmt("parent of %s", out->label);

static GIT_PATH_FUNC(rebase_path_rewritten_list, "rebase-merge/rewritten-list")
static int git_sequencer_config(const char *k, const char *v, void *cb)
		struct todo_item *item = append_new_todo(todo_list);
		if (oideq(first_parent
		/* Do not error, just do not rollback */
		} else {
	if (email_i == -2)
		return error(_("cannot get commit message for %s"),
			if (!rollback_is_safe())
			if (res > 0)
			if (name_i != -2)
		subject_len = find_commit_subject(commit_buffer, &subject);
				strbuf_addstr(&buf, label_oid(oid, NULL,


static struct tree *empty_tree(struct repository *r)
	return 0;

};
			strbuf_splice(msgbuf, msgbuf->len - ignore_footer, 0,
			todo_list->done_nr = 0;
static void todo_list_write_total_nr(struct todo_list *todo_list)
	 *     halt for the ones that become empty;
{
		return -1;
	/*
	/*
	if (is_rebase_i(opts)) {
	}
		}
	}
				 struct todo_list *todo_list)
	oidmap_init(&commit2todo, 0);
{
	is_clean = !has_uncommitted_changes(r, 0);
					arg, item->arg_len, opts, res, !res);

 * Returns 1 for conforming footer
				opts->allow_rerere_auto = RERERE_AUTOUPDATE;
	prime_cache_tree(r, r->index, tree);
			if (is_empty)
	repo_init_revisions(r, &log_tree_opt, NULL);
	log_tree_opt.disable_stdin = 1;
			   const struct object_id *to,
	strbuf_release(&commit_msg);
			run_command(&child);
		return error(_("no cherry-pick or revert in progress"));
	/* insert or append final <commands> */
		const char *encoding = get_commit_output_encoding();
			opts->verbose = 1;
	if (!(flags & EDIT_MSG) && !(flags & VERIFY_MSG)) {
	}
			return error(_("could not read '%s'"),
			return -1;
	int i, ret = 0;
		return 0;
		       enum commit_msg_cleanup_mode cleanup_mode)

	child.git_cmd = 1;
 * from what this function expects, it is better to bail out than to do
		if ((res = read_populate_todo(r, &todo_list, opts)))
{
	}

		return error(_("missing arguments for %s"),
	if (date_i == -2)
			if (is_fixup(command))
			      const char *base_label, const char *next_label,
				TODO_FIXUP : TODO_SQUASH;
	strbuf_release(&label);
	child.no_stderr = 1;
	if (strategy || to_merge->next) {
	struct strbuf buf = STRBUF_INIT;
		break;
		strbuf_release(&sb);
	if (opts->current_fixup_count > 0) {
	FILE *f = fopen_or_warn(rebase_path_msgtotal(), "w");
			    const char *action, const struct strbuf *msg,
		struct todo_list done = TODO_LIST_INIT;
		else
		}
			    return -1;
	return error_with_patch(r, commit, subject, subject_len, opts, 1, 0);
static int git_config_string_dup(char **dest,
 * squash/fixup commands. When the first of a series of squash/fixups
		parent = p->item;


	if (is_rebase_i(opts) && !(flags & EDIT_MSG))
		return error(_("can't revert as initial commit"));
		}
	revs.topo_order = 1;
	if (!res) {

	 * progress
		arg2 = commit;
}
				command_to_string(item->command));
	for (i = 0; i < TODO_COMMENT; i++)
		strbuf_addf(&buf, _("The commit message #%d will be skipped:"),
		cmd.git_cmd = 1;
			hashmap_entry_init(&entry->entry,
		if (read_oneliner(&buf, rebase_path_stopped_sha(), 1) &&
				return error(_("cannot cherry-pick during a revert."));
			goto missing_author;
	fclose(out);
		}
		if (make_patch(r, commit, opts))
 * Find out if the message in the strbuf contains only whitespace and
	char c;

		argv_array_push(&cmd.args, "--no-edit");
					   path);

			if (eol)

			unlink(rebase_path_stopped_sha());
"your configuration file:\n"
				  rebase_path_fixup_msg(), 0)) {
	return item->commit ? 0 : -1;

	setenv(GIT_REFLOG_ACTION, action_name(opts), 0);
		}
		strbuf_addstr(&format, "\n Date: ");
		/* Do we want to generate a root commit? */

/*
}

			 */
	dirty = require_clean_work_tree(r, "rebase", NULL, 1, 1);
	}
				    !skip_prefix(p, "squash! ", &p))
		}
	else if (!strcmp(key, "options.allow-ff"))


		if (read_oneliner(&buf, rebase_path_gpg_sign_opt(), 1)) {
	revs.cherry_mark = !reapply_cherry_picks;
	int res = 0;
			item->arg_offset = p - buf;
	struct string_entry *entry;
		}
		error(_("missing 'GIT_AUTHOR_DATE'"));
				       "strip" };
give_advice:
		unlink(git_path_cherry_pick_head(r));
	else if (!strcmp(key, "options.strategy"))
{

	if (!todo_list->nr &&
			}
#include "commit-slab.h"
		write_file(rebase_path_head_name(), "%s\n", head_name);
	int res = 0;

			opts->action == REPLAY_PICK ? TODO_PICK : TODO_REVERT;
	}
	struct commit *base, *next, *parent;

{
		error(_("cannot abort from a branch yet to be born"));
{
	if (fd < 0)
}
			goto out;
			if (entry)
		strbuf_addch(buf, '\n');
				if (f) {
	 * CHERRY_PICK_HEAD for the subsequent invocation of commit to use.
	while (*message && *message != '\n' && *message != '\r')
			ret = error(_(staged_changes_advice), gpg_opt, gpg_opt);
"You can suppress this message by setting them explicitly. Run the\n"
		opts->keep_redundant_commits =
			if (next[i2] < 0)

	sigchain_pop(SIGPIPE);
			strbuf_commented_addf(msgbuf, "\t%s\n", ce->name);
	if (!opts->no_commit && !drop_commit) {

	/*
			return error_errno(_("could not open '%s' for reading"),
		strbuf_release(&buf);

		die(_("couldn't look up newly created commit"));
		int ret = 0;
	out->message = logmsg_reencode(commit, NULL, get_commit_output_encoding());
	else if (is_fixup(command)) {
		todo_list->current = 0;
	write_in_full(proc.in, sb.buf, sb.len);
		    (buf->len == 1 && *label == '#') ||
	 *
		strbuf_addbuf_percentquote(&format, &committer_ident);
	else
	if (opts->allow_empty_message)
			strbuf_add_unique_abbrev(buf, oid, default_abbrev);

{

					return error(_("could not write file: "
	strbuf_reset(&todo_list->buf);
			break;

	if (read_and_refresh_cache(r, opts))

			strbuf_release(&ref_name);
		res = error(_("git write-tree failed to write a tree"));
	} else if (1 < opts->mainline)
		cleanup = COMMIT_MSG_CLEANUP_SPACE;
}
			char *eol = strchr(p, '\n');


	argv_array_pushf(&child_env, "GIT_DIR=%s", absolute_path(get_git_dir()));
			res = do_exec(r, arg);
	if (!to_merge) {
static int do_pick_commit(struct repository *r,
		/*
static int is_command(enum todo_command command, const char **bol)
	if (info.trailer_start == info.trailer_end)
	case TODO_PICK:
						    peek_command(todo_list, 1));
		int subject_len;
static int count_commands(struct todo_list *todo_list)
	if (!resolve_ref_unsafe("HEAD", RESOLVE_REF_READING, &head_oid, NULL))
		opts->signoff = git_config_bool_or_int(key, value, &error_flag);
	free(name);
{
	if (!head_commit) {
		todo_list->items[index].offset_in_buf : todo_list->buf.len;
			    const struct hashmap_entry *eptr,
	 * then outputting that list (labeling revisions as needed).
	char *xdg_config = xdg_config_home("config");
		return run_command_silent_on_success(&cmd);
		if (parse_commit(item->commit)) {
	 * should be done in reverse

}
				 * We need to update the squash message to skip
		oidclr(&expected_head);
	} else {
		}
				    getenv("GIT_REFLOG_ACTION"), msg, &err)) {
	error(_("there is nothing to skip"));
	if (file_exists(git_path_revert_head(r))) {

					  0) < 0)
	 * If head_commit is NULL, check_commit, called from
			log_tree_opt.diff = 1;
		const char *body;
						strhash(p), p,
	if (opts->gpg_sign)
	if (opts->keep_redundant_commits)
		}


		struct strbuf buf = STRBUF_INIT;
		return 0; /* we do not have to say --allow-empty */
	if (read_ref_full("HEAD", 0, &head, NULL))
				       run_commit_flags);

	free(msg->label);

	case REPLAY_PICK:
	return write_message(p, strlen(p), rebase_path_amend(), 1);
		commit_buffer = logmsg_reencode(item->commit, NULL, "UTF-8");
				RERERE_AUTOUPDATE : RERERE_NOAUTOUPDATE;
		return error_resolve_conflict(_(action_name(opts)));
		int i;
	char *p = buf, *next_p;
					    starts_with(subjects[i2], p))
	if (is_rebase_i(opts)) {
		else {
	char *name, *email, *date;
	else if (!strcmp(key, "options.no-commit"))
	return ret;

		base_offset += command_len + 1;
	find_commit_subject(message, &body);
		error(_("cannot read '%s': %s"), git_path_head_file(),
			return error(_("commit %s does not have parent %d"),
		return clean;
	if (read_and_refresh_cache(r, opts))

		return error(_(staged_changes_advice),
	else if (opts->allow_rerere_auto == RERERE_NOAUTOUPDATE)
static int apply_autostash(struct replay_opts *opts)
			goto release_todo_list;
		else
				return error_with_patch(r,
		}
 */
			status = 1;
	}
	if (cleanup_mode == COMMIT_MSG_CLEANUP_SCISSORS) {

static GIT_PATH_FUNC(rebase_path_squash_onto, "rebase-merge/squash-onto")

	log_tree_opt.abbrev = 0;
{
		    !get_oid("CHERRY_PICK_HEAD", &cherry_pick_head) &&
}
			struct rev_info log_tree_opt;
		if (!iter->next)
}
	    (out = fopen_or_warn(rebase_path_rewritten_list(), "a"))) {
	struct merge_options o;
	struct strbuf msg = STRBUF_INIT;
			 * The buffer is completely empty.  Leave foom for
	if (run_git_checkout(r, opts, oid_to_hex(onto), action)) {
	}
					O_RDONLY);
		}
	commit = lookup_commit(r, oid);
				"true" : "false");
	return 0;
	if (repo_read_index_unmerged(repo))

			fprintf_ln(stderr, _("Could not apply %s... %.*s"),

static char *get_author(const char *message)
	if (write_in_full(msg_fd, buf, len) < 0) {
		struct commit_list *list = NULL, *iter2;
	for (i = 0; i < info.trailer_nr; i++)
			struct object_id orig, head;
#include "dir.h"
	for (item = todo_list->items, i = 0; i < max; i++, item++) {
static void todo_list_to_strbuf(struct repository *r, struct todo_list *todo_list,
}
	else {

/*
			if (item->command != TODO_COMMENT) {
	 * - gather all branch tips (i.e. 2nd or later parents of merges)
		}
	log_tree_opt.diffopt.output_format = DIFF_FORMAT_PATCH;
	const char *p = *bol + 1;
	if (is_rebase_i(opts) && next > 0) {
	/* Do nothing on a single-pick */

				  "%s\n", ref_name.buf);

static GIT_PATH_FUNC(rebase_path_msgtotal, "rebase-merge/end")
	struct pretty_print_context pp = {0};

		if (commit_staged_changes(r, opts, &todo_list)) {
	if (discard_index(r->index) < 0 || repo_read_index(r) < 0)
}
			strbuf_addf(&buf, "Merge %s '%.*s'",
			goto release_todo_list;
	struct strbuf sob = STRBUF_INIT;
		if (!opts->mainline)

		} else {
	return command == TODO_FIXUP || command == TODO_SQUASH;
	printf("[%s%s ", head, (flags & SUMMARY_INITIAL_COMMIT) ?
static const char *command_to_string(const enum todo_command command)
		   ref_transaction_commit(transaction, &err)) {
	 * it gets removed when the user commits, so if it still exists we're
			record_in_rewritten(base_oid, peek_command(todo_list, 0));
				return res;
	if (commit_lock_file(&todo_lock) < 0)

		 (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || !*p) &&

		      ferror(f) ?  strerror(errno) : _("unexpected end of file"));
		return error(_("could not copy '%s' to '%s'"),
		if (!cp)
{
 * Returns 0 on success, -1 if the file could not be parsed.
			return error_errno("unable to open '%s'", todo_file);
static struct todo_item *append_new_todo(struct todo_list *todo_list)
	log_tree_opt.diffopt.use_color = GIT_COLOR_NEVER;
			strbuf_addbuf(&label, &oneline);
		subject = subjects[i] = strbuf_detach(&buf, &subject_len);
	struct strbuf ref_name = STRBUF_INIT, err = STRBUF_INIT;

		ret = run_command_silent_on_success(&cmd);
		struct commit_list *p;
		if (oidset_contains(&shown, &commit->object.oid))
 */
	if (commit_lock_file(&head_lock) < 0)
	struct todo_item *items = NULL;

{
 * the abbreviated commit name of the corresponding patch.
			/*
				len--;
	 * can never contain comments (any comments are empty picks that
			} else if (res && is_rebase_i(opts) && item->commit) {

		} else if (!strcmp(s, "whitespace")) {
		else
{

				     rebase_path_fixup_msg());
			error_errno(_("could not write to '%s'"), done_path);
	b = container_of(entry_or_key, const struct labels_entry, entry);
	cfg = init_copy_notes_for_rewrite("amend");
		argv_array_push(&store.args, "store");
	if (update_ref("rebase", "REBASE_HEAD", oid,
		/*
 * email and date accordingly.
		strbuf_addf(&buf, "\n%c ", comment_line_char);
	}
	repo_read_index(r);
	struct strbuf sb = STRBUF_INIT;
	strbuf_release(&buf);
	{ 0,   "noop" },
				while (isspace(*p))
	shortonto = find_unique_abbrev(&oid, DEFAULT_ABBREV);
		if (is_rebase_i(opts)) {

		return error(_("could not read commit message of %s"),
				strbuf_reset(&opts->current_fixups);
	{ 'p', "pick" },
			item->arg_len = (int)(eol - p);
			return error(_("unknown command %d"), item->command);
	if (name_i == -2)
		strbuf_complete_line(msgbuf);
{
		fclose(f);
				goto give_advice;

	const char *cmd_pick = abbr ? "p" : "pick",
	} else {
		if (find_commit_subject(msg.message, &p))
static void record_in_rewritten(struct object_id *oid,
		free_message(commit, &message);
{
	pp.output_encoding = get_log_output_encoding();
#include "refs.h"
	a = container_of(eptr, const struct subject2item_entry, entry);
	if (is_rebase_i(opts))
		strbuf_addf(&buf, "\n%c ", comment_line_char);
			      struct todo_list *todo_list,
	}

static GIT_PATH_FUNC(rebase_path_allow_rerere_autoupdate, "rebase-merge/allow_rerere_autoupdate")
	const char *subject, *p;
	} else {
		error(command == TODO_REVERT

	repo_read_index(r);
		pretty_print_commit(&pp, commit, out);
			continue;
			_("try \"git revert (--continue | %s--abort | --quit)\"");
	if (!ret)
	} else if (!strcmp(key, "options.allow-rerere-auto"))
	return oideq(&actual_head, &expected_head);
	init_merge_options(&o, r);
	}
	    cleanup_mode == COMMIT_MSG_CLEANUP_SCISSORS)
							tips_tail)->next;
		if (is_empty)
	if (opts->allow_ff)
	    item->command == TODO_RESET) {
				   git_path_seq_dir());
static GIT_PATH_FUNC(rebase_path_onto, "rebase-merge/onto")
				strbuf_addch(buf, *label);
		unuse_commit_buffer(commit, commit_buffer);
}
				  struct replay_opts *opts)
	}
	 *
		oidcpy(&entry->entry.oid, &commit->object.oid);
static GIT_PATH_FUNC(rebase_path_autostash, "rebase-merge/autostash")
	 * If the merge was clean or if it failed due to conflict, we write
	}
		       NULL, REF_NO_DEREF, UPDATE_REFS_MSG_ON_ERR))
	strbuf_addstr(&buf, reflog_action ? reflog_action : action_name(opts));
			  ? get_commit_tree_oid(first_parent)
	ssize_t len;
			--buf->len;
	return todo_list->buf.buf + get_item_line_offset(todo_list, index);
	 * Insert <commands> after every pick. Here, fixup/squash chains
 * The file to keep track of how many commands are to be processed in total
					  rebase_path_squash_onto(), 0))
/* Does this command create a (non-merge) commit? */
	if (!value)
			die(_("could not parse %s"), git_path_abort_safety_file());
/*
static const char rescheduled_advice[] =
	strbuf_reset(&buf);
/*
{
			 struct replay_opts *opts)
		}
		istate->cache_tree = cache_tree();
	get_commit_format(format.buf, &rev);


	strbuf_release(&sob);
}
	head = resolve_ref_unsafe("HEAD", 0, NULL, NULL);
				  struct todo_list *todo_list,
		if (item->commit->parents->next)
			log_tree_opt.diffopt.output_format =
		*cp++ = '\0';
	while ((commit = get_revision(revs))) {
		return string_entry->string;
 * end-of-line marker that needs to be stripped.


		return error(_("commit %s does not have parent %d"),

		}
		if (!oideq(&oid, &current_head->object.oid)) {
	strbuf_release(&buf);

			res |= git_config_set_multivar_in_file_gently(opts_file,
	return 1;
	if (is_rebase_i(opts) && read_env_script(&cmd.env_array)) {
	va_start(ap, fmt);
		fprintf(stderr,
	if (can_fast_forward) {

		drop_commit = 1;
		ret = error(_("merge: Unable to write new index file"));
			/* avoid leading dash and double-dashes */
}
		strbuf_reset(&buf);
{
			       int subject_len,

	if (prepare_revs(opts))

			ALLOC_GROW(items, nr + commands->nr, alloc);
			    struct strbuf *err)
		unuse_commit_buffer(head_commit, head_message);
	for (j = bases; j; j = j->next)
struct labels_entry {


		return error(_("make_script: error preparing revisions"));
					get_oid_hex(buf.buf, &orig)) {
static int write_rebase_head(struct object_id *oid)
		return originally_empty;
		return;
		struct commit_list *to_merge;
		TODO_PICK : TODO_REVERT;
		strategy_opts_string++;

		return continue_single_pick(r);

		 * In case of problems, we now want to return a positive
		k = strcspn(p, " \t\n");
	hashmap_free_entries(&subject2item, struct subject2item_entry, entry);
	if (reset_merge(&oid))
		item->arg_len = eol - bol;
		return;
	struct object_id *parent_oid;
	int keep_empty = flags & TODO_LIST_KEEP_EMPTY;
static int do_merge(struct repository *r,
	strbuf_release(&msgbuf);
	return ret;
cleanup:
		     skip_prefix(subject, "squash! ", &p))) {
	else if (!strcmp(key, "options.default-msg-cleanup")) {
		return;
 * Note that if the config has specified a custom instruction format, each log
			res = error(_("unable to parse commit author"));
cleanup_head_ref:
				    to_merge->next ? "branches" : "branch",
	}
			ret = error_errno(_("failed to finalize '%s'"), done);
 *  -1 - error unable to commit
			res = do_commit(r, msg_file, author, opts, flags,
{
				reschedule = 1;
	argv_array_clear(&child_env);
		return -1;
	int ret = 0;
			return status;
		}
	} else {
	     command == TODO_EDIT) && !opts->no_commit &&
		return -1;
	struct commit_list *bases, *j, *reversed = NULL;

		/* we are amending, so old_head is not NULL */
	strbuf_release(&opts->current_fixups);
			if (!*eol)
	}
		assert(!(opts->signoff || opts->no_commit ||
					 opts->xopts_nr, (const char **)opts->xopts,
			    const struct hashmap_entry *entry_or_key,
		else
		strbuf_release(&buf);

			goto out;
		if (strbuf_read_file(&buf, rebase_path_squash_msg(), 9) <= 0)
	int ret = 0;
		     cnt != opts->mainline && p;
						break;
			    int exit_code, int to_amend)
					"options.record-origin", "true");
		strbuf_reset(&buf);

"    git commit --amend --reset-author\n");
	int rebase_cousins = flags & TODO_LIST_REBASE_COUSINS;
			; /* this is not the final fixup */
			}
	free(msg->parent_label);
 * Reads and parses the state directory's "author-script" file, and sets name,
	return status;
		if (!stat(rebase_path_rewritten_list(), &st) &&
				}
		FLEX_ALLOC_STR(entry, string, buf.buf);
		if (get_oid(ref_name.buf, &oid) &&

			oid_to_hex(&parent->object.oid));
	else if ((res = read_populate_todo(r, &todo_list, opts)))
		goto leave_merge;

			in_progress_error = _("cherry-pick is already in progress");
		}
	 * Third phase: output the todo list. This is a bit tricky, as we
	case TODO_REWORD:
			msg = reflog_message(opts, "finish", "%s onto %s",
	if (!strcmp(k, "commit.gpgsign")) {
			}
		else
	struct commit_list *commits = NULL, **tail = &commits, *iter;
	if (require_clean_work_tree(r, "rebase", "", 1, 1))
			}
				   unsigned flags)
"\n"
		}
	 * cherry-pick/revert it, set CHERRY_PICK_HEAD /

			    command_to_string(command),
	else
		return 0;
		struct todo_item *item = todo_list->items + i;
			   const struct object_id *from,
	return ret;
		return error(_("no commits parsed."));
			res = do_pick_commit(r, item->command, item->commit,
		if (item->command >= TODO_COMMENT) {

			    const struct object_id *newoid)
	if (opts->explicit_cleanup)
		find_unique_abbrev_r(p, oid, default_abbrev);
	free_message(commit, &msg);
	/*
	unlink(git_path_merge_msg(r));
	while (*message && *message != '\n' && *message != '\r')
		ret = fast_forward_to(r, &commit->object.oid,
 * to it. The commit message for each subsequent squash/fixup commit
	proc.trace2_hook_name = "post-rewrite";
	if (write_locked_index(r->index, &lock, COMMIT_LOCK) < 0)
	else if (!strcmp(key, "options.allow-empty-message"))
			len = arg_len - oneline_offset;
{
	}
	struct strbuf buf = STRBUF_INIT;
#define ALLOW_EMPTY (1<<0)
	struct ref_transaction *transaction;
}

					fprintf(stderr,

				 "with 'git add <paths>' or 'git rm <paths>'"));
		}
	return exit_code;
		unlink(rebase_path_rewritten_pending());
	if (f) {
	    !strncmp(msgbuf->buf, sob.buf, sob.len))
			res = error_dirty_index(r, opts);
	strbuf_release(&format);
				oid_to_hex(&oid));
		free((void *)desc.buffer);
#include "argv-array.h"
}
	 * a commit object already.  parse_commit() will return failure
	struct strbuf buf = STRBUF_INIT, oneline = STRBUF_INIT;
			return 0;
			/*
static GIT_PATH_FUNC(rebase_path_done, "rebase-merge/done")
		if (commit->parents && commit->parents->next) {
	if (buf->len > orig_len && buf->buf[buf->len - 1] == '\n') {
				found_sob_last = 1;
/*
			insert = 0;
		todo_list.current++;
				setenv(GIT_REFLOG_ACTION, reflog_message(opts,
	}

		} else {

		return -1;
	strbuf_release(&buf);

		if (hashmap_get_from_hash(&state->labels, strihash(p), p)) {
	return 0;
			/*

	 * The function git_parse_source(), called from git_config_from_file(),


	TODO_EDIT_MERGE_MSG = 1
		return error(_("could not read '%s'."), path);
 */
	const char *action = reflog_message(opts, "start", "checkout %s", onto_name);
	for (i = 0; i < istate->cache_nr;) {

			BUG("unexpected action in create_seq_dir");
	proc.in = -1;
	if (flags & CLEANUP_MSG)
			}
 * The path of the file listing refs that need to be deleted after the rebase

		else
		format_commit_message(commit, "%ad", &date, &pctx);

			return error(_("could not read HEAD's commit message"));
		opts->no_commit = git_config_bool_or_int(key, value, &error_flag);
			    const char *subject, int subject_len,

		if (!is_noop(todo_list->items[i].command))
			strbuf_addstr(&msgbuf, ")\n");
 */
	}
static int is_index_unchanged(struct repository *r)
		struct strbuf date = STRBUF_INIT;
	/*
				    kv.items[i].string);
		const char *exclude_gpgsig[] = { "gpgsig", "gpgsig-sha256", NULL };
	fd = hold_lock_file_for_update(&todo_lock, todo_path, 0);
{
			count++;
{
				struct todo_list *todo_list)
				struct object_id oid;


	memset(&unpack_tree_opts, 0, sizeof(unpack_tree_opts));
		if (!cmit)
	 * there is nothing for us to say here.  Just return failure.
	trailer_info_release(&info);
	return res;
	const char *opts_file = git_path_opts_file();
			unlink(rebase_path_author_script());
			const char *to = NULL;
		 * value (a negative one would indicate that the `merge`
void cleanup_message(struct strbuf *msgbuf,
			   int unborn,
					    git_path_commit_editmsg());
#define EDIT_MSG    (1<<1)
					"options.mainline", buf.buf);
		return todo_command_info[command].str;
		return -1;
	if (opts->strategy)
			    opts->current_fixup_count + 2);
	if (opts->edit)


		oidmap_put(&state.commit2label, entry);
	}
		} else if (item->command == TODO_RESET) {
			continue;
	const char *p;
		error_errno(_("could not write to '%s'"), git_path_head_file());
	switch (opts->action) {
			unlink(git_path_cherry_pick_head(r));
	if (!strcmp(head, "HEAD"))
	sigchain_push(SIGPIPE, SIG_IGN);
			if (!read_oneliner(&buf, rebase_path_orig_head(), 0) ||
	if (is_rebase_i(opts))


						term_clear_line();



	strbuf_release(&buf);
		 * "rebase".
			    const char *file, const char *shortrevisions,
	if (git_config_from_file(populate_opts_cb, git_path_opts_file(), opts) < 0)
					break;
				/* Reread the todo file if it has changed. */
		free_commit_list(remotes);
			goto leave;
		if (todo_list->items[i].command != TODO_COMMENT)

 */
GIT_PATH_FUNC(rebase_path_dropped, "rebase-merge/dropped")

}
		strbuf_addstr(&msgbuf, oid_to_hex(&commit->object.oid));
{
	struct stat st;
				hook.stdout_to_stderr = 1;
	const char *todo_path = git_path_todo_file();
	struct strbuf buf = STRBUF_INIT;


	if (opts->signoff && !is_fixup(command))

	int rearranged = 0, *next, *tail, i, nr = 0, alloc = 0;
				 */
	strbuf_release(&tmpl);


		char *p;
 *    <0: Error in is_index_unchanged(r) or is_original_commit_empty(commit)
	return string_entry->string;
	res = edit_todo_list(r, todo_list, &new_todo, shortrevisions,
		find_commit_subject(commit_buffer, &subject);
		const char *message = logmsg_reencode(commit, NULL, encoding);
				rebase_path_squash_msg());
				break;


						strhash(subject), subject)) {
		cleanup = opts->default_msg_cleanup;

			tips_tail = &commit_list_insert(iter->item,
		case REPLAY_PICK:
			  "\n"
			strbuf_setlen(&opts->current_fixups, len);

	if (!transaction ||

	if (opts->gpg_sign)
	struct object_id expected_head, actual_head;
}
	oidmap_free(&state.commit2label, 1);
	const char *todo_path = get_todo_path(opts);
"You can suppress this message by setting them explicitly:\n"
		nr += commands->nr;
					    item->flags, opts)) < 0)
	 * - label branch points
		} else if (skip_prefix(message, "author ", &message))
			break;

		return 0;
		const char *cherry_pick_head = git_path_cherry_pick_head(r);
		base_label = msg.parent_label;
 *	GIT_AUTHOR_NAME='$author_name'
static int error_with_patch(struct repository *r,
 */
		res = do_recursive_merge(r, base, next, base_label, next_label,
			oidcpy(&entry->entry.oid, &commit->object.oid);
		/* fall back to non-rewritten ref or commit */
int message_is_empty(const struct strbuf *sb,
	for (i = 0; i < opts->xopts_nr; i++)
		status = 1;
 * Returns 2 when sob exists within conforming footer
	struct object_id head;
	if (save_head(oid_to_hex(&oid)))
 * This file is created by "git rebase -i" then edited by the user. As
	if (!have_finished_the_last_pick())
		goto out;

	argv_array_clear(&argv);
		strbuf_addf(&opts->current_fixups, "%s%s %s",
	enum commit_msg_cleanup_mode cleanup;
		unuse_commit_buffer(commit, message);
{
	 * 1 upon failed merge (keeping the return value -1 for the cases where

			return error(_("invalid contents: '%s'"),
/*
		buf->buf[buf->len] = '\0';
			}

	} else if (res == -4) {
	free(xdg_config);
		write_file(rebase_path_orig_head(), "%s\n", orig_head);
				ALLOC_GROW(items, nr + 1, alloc);
	int error_flag = 1;
	if (opts->record_origin)
		const char *p;
	if (len < 0)
		strbuf_reset(&label);
		size_t command_len = strlen(commands->items[i].string);

			  : the_hash_algo->empty_tree,
	strbuf_release(&err);
	 */
		advise(_("commit your changes or stash them to proceed."));

			const char *dest = git_path_squash_msg(r);
	*date = kv.items[date_i].util;
	FILE *f;
					strhash(entry->subject));
	 * unclean merge.
		git_config_string_dup(&opts->strategy, key, value);
	else if (!strcmp(cleanup_arg, "whitespace"))
"If these changes are meant to be squashed into the previous commit, run:\n"
	argv_array_pushf(&cmd.env_array, GIT_REFLOG_ACTION "=%s", action);
{
	strbuf_addstr(&buf, "'\nGIT_AUTHOR_EMAIL='");
{
	return 1;
		EDIT_MSG | VERIFY_MSG : 0;
/* skip picking commits whose parents are unchanged */
			 * so that there is an empty line between the message
 * The file containing rebase commands, comments, and empty lines.
"on your username and hostname. Please check that they are accurate.\n"

			command_to_string(command),
	int status;
		return 0;
	for (i = 0; i < todo_list->nr; i++) {
		strbuf_release(&buf);
		write_file(rebase_path_allow_rerere_autoupdate(), "--no-rerere-autoupdate\n");
		if (get_oid("HEAD", &head))
		fclose(f);
				strbuf_addf(out, "%s onto\n", cmd_reset);
		for (i = 0; i < len; i++)
		rollback_lock_file(&lock);
	run_commit_hook(0, r->index_file, "post-commit", NULL);
		argv_array_push(&cmd.args, "-e");
		if (!commit)
	 * only need to check that when .git/<ACTION>_HEAD doesn't exist because
	}

	strbuf_release(&todo_list->buf);
	return res;
		struct object_id head, to_amend;
		}
			todo_list->done_nr = count_commands(&done);
			}
	todo_list->items = items;
			strbuf_addstr(buf, "rev-");
		if (!read_oneliner(&rev, rebase_path_amend(), 0))
				res = error_errno(_("could not stat '%s'"),
			bol = eol + 1;
			return error(_("cannot '%s' without a previous commit"),
#include "rebase-interactive.h"
		return -1;

		error("%s", err.buf);
			if (is_rebase_i(opts) && !res)
	if (skip_single_pick())
			return -1;
		struct child_process store = CHILD_PROCESS_INIT;
	b = container_of(entry_or_key, const struct subject2item_entry, entry);
		strbuf_release(&buf);

		return error(_("no cherry-pick or revert in progress"));
	struct tree *next_tree, *base_tree, *head_tree;
}
	struct child_process child = CHILD_PROCESS_INIT;
	 * gathering commits not yet shown, reversing the list on the fly,

				/*
		 * in file names. We do not validate the UTF-8 here, that's not
	 * label.
}
		*action = REPLAY_REVERT;
		strbuf_release(&buf);
	struct replay_opts opts = REPLAY_OPTS_INIT;
		else if (!is_noop(todo_list->items[i].command))
	return res;

		base_items[i].command = TODO_EXEC;
	 */
		return _(implicit_ident_advice_config);
		return;
		ref_transaction_free(transaction);
			if (!is_rebase_i(opts))

				if (!hashmap_get_from_hash(&state->labels,
int update_head_with_reflog(const struct commit *old_head,
}
			else
	if (write_index_as_tree(&tree, r->index, r->index_file, 0, NULL)) {
			return 0;
		advise(_("have you committed already?\n"
	 * Finally we check that the rollback is "safe", i.e., has the HEAD
		res = run_prepare_commit_msg_hook(r, msg, hook_commit);
};
			command_line,
			COPY_ARRAY(items + nr, base_items, commands->nr);
	return oideq(cache_tree_oid, get_commit_tree_oid(head_commit));
			}
	if (parent && parse_commit(parent) < 0)
			/* non-merge commit: easy case */
	static struct strbuf buf = STRBUF_INIT;
		else {
			  struct replay_opts *opts,
	struct merge_options o;

	if (mkdir(git_path_seq_dir(), 0777) < 0)
		return error(_("unusable instruction sheet: '%s'"), todo_file);
	if (opts->have_squash_onto &&
		if (res)
			     oid_to_hex(&commit->object.oid), opts->mainline);
	int config_exists = file_exists(user_config) || file_exists(xdg_config);
	}
				    oid_to_hex(&commit->object.oid),
			}
	{ 's', "squash" },
				oid_to_hex(&commit->object.oid));
		 */
	if (!(flags & ALLOW_EMPTY)) {
{
		     !get_oid_hex(label, &dummy)) ||
		todo_list_release(&new_todo);
static void print_advice(struct repository *r, int show_hint,
		strbuf_addf(&ref_name, "refs/rewritten/%.*s", len, name);
		rev.always_show_header = 1;
		fclose(log_tree_opt.diffopt.file);
			  "left changes to the index and/or the working tree\n"
		if (strlen(sign_off_header) <= eol - i &&
{
					       &state);
	else if (is_command(TODO_REVERT, &bol) &&
 */
	return count;
	struct string_list kv = STRING_LIST_INIT_DUP;
	const char *argv[] = { "commit", NULL };
				int to_amend = 0;
			  enum todo_command command,
void todo_list_release(struct todo_list *todo_list)
/*
		write_file(rebase_path_verbose(), "%s", "");
		strbuf_release(&sb);
#include "sequencer.h"
	if (!ignore_footer)
{
	if (!is_fixup(todo_list->items[i].command))
	if (res) {

	todo_list->nr = todo_list->alloc = 0;

int sequencer_get_last_command(struct repository *r, enum replay_action *action)


		return -1;
	if (status) {
		 * was the last fixup/squash in the chain, we need to clean up
	case REPLAY_INTERACTIVE_REBASE:
		if (prepare_revision_walk(opts->revs))
		if (!current_head)
		if (!oideq(parent_oid, base_oid))
			warning(_("HEAD %s is not a commit!"),
			       const char *subject)
			 const char *orig_head)
	if (opts->signoff)
				    !(p = logmsg_reencode(commit, NULL, encoding)) ||
		       REF_NO_DEREF, UPDATE_REFS_MSG_ON_ERR))
			if (!len)
	}
				return error(_("cannot revert during a cherry-pick."));
			continue;
		flush_rewritten_pending();
		if (msg_file && strbuf_read_file(&sb, msg_file, 2048) < 0)
		return error_errno(_("could not lock '%s'"), filename);
	strbuf_release(&buf);
static int try_to_commit(struct repository *r,
	res = -1;

				if (i2 == i)
		 * of the commit itself so remove CHERRY_PICK_HEAD
	struct tree_desc desc;
				strbuf_addch(&msgbuf, '\n');
			return error(_("your index file is unmerged."));
{
		    !todo_list_parse_insn_buffer(r, done.buf.buf, &done))
		return xmemdupz(a, len);
"following command and follow the instructions in your editor to edit\n"
	 * first, make sure that an existing one isn't in
			  "  git rebase --continue\n"),
		return 0;
		if (res || command != TODO_REWORD)
		return 0;

			 "try \"git %s --continue\""),
{
"After doing this, you may fix the identity used for this commit with:\n"
			if (!commit->parents) {
	if (parse_key_value_squoted(buf.buf, &kv))
		item->arg_len = (int)(eol - bol);
		if (command == TODO_PICK || command == TODO_MERGE)
		 * commit, we cannot fast-forward.
		ret = run_command(&cmd);

	char *author = NULL;
		res = allow;
		}
	struct hashmap_entry entry;
			if (copy_file(dest, rebase_path_squash_msg(), 0666))
		if (is_rebase_i(opts) && oid)
	log_tree_opt.diff = 1;
 */

			goto leave_merge;
	} else if (res == -3) {
		res |= git_config_set_in_file_gently(opts_file,
	struct strbuf err = STRBUF_INIT;
		merge_commit = lookup_label(p, k, &ref_name);
	}
			*check_todo = 1;
		unlink(rebase_path_squash_msg());
			rebase_path_squash_msg(), rebase_path_message());
			}
			strbuf_addch(&buf, *(message++));
	struct commit *current_head;

		label = buf->buf;
		oidmap_put(&commit2todo, entry);
		struct todo_item *item = todo_list->items + todo_list->current;
	}
 * will be amended to the HEAD commit, but only provided the HEAD

	 * write it at all.
			if (date_i != -2)
	for (i = 0; i < todo_list->nr; i++) {
		int len;
	fill_stat_data(&todo_list->stat, &st);
		current_head = NULL;
					i2 = -1;
		} else if (!strcmp(kv.items[i].string, "GIT_AUTHOR_DATE")) {

						SUMMARY_SHOW_AUTHOR_DATE);
}
	return oideq(ptree_oid, get_commit_tree_oid(commit));
		if (item->commit) {
		if (!res && reword) {
			 * Buffer contains a single newline.  Add another


			continue;
	if (commit_lock_file(&lock) < 0) {
}

		strbuf_release(&date);
			 * it again.
};
	const char *todo_file, *bol;
	const char *a;

		author = amend_author = get_author(message);
	int need_cleanup = 0;
	if (num > 0 && num < max)
		store.git_cmd = 1;
	int abbr = flags & TODO_LIST_ABBREVIATE_CMDS;
	struct tree *tree;
{
			advise(_("after resolving the conflicts, mark the corrected paths\n"
			if (write_message(p, len, rebase_path_current_fixups(),
	strbuf_reset(buf);
	int i;
	if (insert || nr == todo_list->nr) {
	}
		res = 1; /* run 'git commit' to display error message */
			strbuf_addstr(msg, orig_message);
		rollback_lock_file(&msg_file);
		 * (including white-space ones) by dashes, as they might be
			 const char *onto_name, const struct object_id *onto,
				goto release_todo_list;
			unlink(rebase_path_message());
		 * merge the differences in, so let's compute the tree
	 *
		return error(_("%s: Unable to write new index file"),
			      struct commit *base, struct commit *next,
	}
"    git config --global user.name \"Your Name\"\n"
			strbuf_addf(&buf, "'\\%c'", *(message++));
	if (unpack_trees(1, &desc, &unpack_tree_opts)) {
		strbuf_addstr(&msgbuf, "Revert \"");
	return res;
				   subject_len, subject);
		strbuf_grow(&state->buf, GIT_MAX_HEXSZ);
	strbuf_commented_addf(msgbuf, "Conflicts:\n");
	*end_of_object_name = saved;

}
		rollback_lock_file(&lock);

	init_merge_options(&o, r);
	if (sub_action)
/*
}
}
			 */

				if (item->flags & TODO_EDIT_MERGE_MSG)
			np = strchrnul(buf, '\n');
		goto cleanup;

	subject_len = find_commit_subject(out->message, &subject);
		if (!k)
static const char implicit_ident_advice_config[] =


	strbuf_addstr(&buf, "GIT_AUTHOR_NAME='");
		rollback_lock_file(&lock);
		    const char *arg, int arg_len,
	int res = 0;

			break;
	return sequencer_remove_state(opts);

	if (opts->action == REPLAY_PICK && !opts->revs->no_walk)

	struct commit_list *parents = NULL;
			strbuf_addstr(&format, implicit_ident_advice());
	if (item->command == TODO_MERGE) {
		struct strbuf buf = STRBUF_INIT;
	return 0;

	else
		   "revert" or "pick", the second %s a SHA1. */
		if (fd < 0)
		char *cp = strchr(buf, '=');
			continue;
		      ? _("could not revert %s... %s")
		ret = -1;
	diff_setup_done(&rev.diffopt);
		}
			if (email_i != -2)
		/*
 * Add commands after pick and (series of) squash/fixup commands
			return 0;
	strbuf_addstr(&sob, fmt_name(WANT_COMMITTER_IDENT));

}
				return -1;
	int rc;
		if (insert && !is_fixup(command)) {
		if (!item->arg_len)
	return len;
		return 0;
	}
			     gpg_opt, gpg_opt);
				return error(_("no cherry-pick in progress"));
	if (!rollback_is_safe()) {
				reschedule = 1;
static int has_conforming_footer(struct strbuf *sb, struct strbuf *sob,
		}
}
{
		if (ce_stage(ce)) {
		}
						arg, item->arg_len, opts,
	struct strbuf ref_name = STRBUF_INIT;
		if (!unlink(git_path_revert_head(r)) && verbose)
		if (!item->commit->parents)
			rearranged = 1;

}
	res = pick_commits(r, &todo_list, opts);
	const char *str;
	if (is_null_oid(&head_oid))
	setup_revisions(0, NULL, &rev, NULL);

{
		strbuf_release(&head_ref);
		argv_array_push(&store.args, "stash");
		return error(_("could not parse commit %s"),
	for (i = start; i < sb->len; i++) {
		 */
	if (msg) {
			 const struct commit *old_head,
	ALLOC_ARRAY(subjects, todo_list->nr);
		return 0;
	free(*dest);
static const char *get_todo_path(const struct replay_opts *opts)

static GIT_PATH_FUNC(git_path_opts_file, "sequencer/opts")
	else if (!(flags & CLEANUP_MSG) &&
		ret = -1;
			argv_array_push(&cmd.args, opts->gpg_sign);
}
			strbuf_addf(buf, " %.*s\n", item->arg_len,
	struct ref_transaction *transaction;
			todo_list->buf.len - offset) < 0)
static int is_final_fixup(struct todo_list *todo_list)
		 */
			strbuf_addstr(&msgbuf, oid_to_hex(&commit->object.oid));
	strbuf_init(&state.buf, 32);
			struct object_id *oid = &iter2->item->object.oid;
		else if (skip_prefix(bol, "-c", &bol)) {
{
			strbuf_reset(&buf);
	strbuf_reset(&state->buf);
			if ((res = do_reset(r, arg, item->arg_len, opts)))
	if (is_null_oid(&oid)) {

}
	hashmap_add(&state->labels, &labels_entry->entry);
	struct replay_opts *opts = cb;
		return -1;
 * for the prompt).

		return -1;
void commit_post_rewrite(struct repository *r,
 *
	char *user_config = expand_user_path("~/.gitconfig", 0);
		fprintf(stderr, _("Stopped at %s\n"), message.label);
		return error(_("cannot abort from a branch yet to be born"));
				   to, unborn && !is_rebase_i(opts) ?
			*whence = FROM_REBASE_PICK;
				return error(_("could not write file: '%s'"),
		}

 */
	int fd;
/*
		     enum commit_msg_cleanup_mode cleanup_mode)
					   &commit->object.oid);
	}
			/*
 */
 * the lines are processed, they are removed from the front of this
		    !get_oid_committish(buf.buf, &oid))
		opts->mainline = git_config_int(key, value);
		if (append_newlines)
{
		if (!is_clean || !opts->current_fixup_count)
		return status;
	}

	 * the commit is invalid, parse_commit() will complain.  So

		}
	else if (!strcmp(key, "options.signoff"))
	return ret;
{
			return 0;
			 * so that we leave room for the title and body.

 * command, then this file exists and holds the commit message of the
{
			strbuf_addch(buf, '\n');
	rc = pipe_command(cmd,
					1);
	 * action is in progress and we can skip the commit.
	if (originally_empty < 0)
static int have_finished_the_last_pick(void)
}
	ref_transaction_free(transaction);
			}
	if (!argv[0])


			size_t i = strlen(p) + 1;
	    ref_transaction_update(transaction, "HEAD", new_head,
	unlink(rebase_path_amend());
			error(_("could not read '%s'"), ref_name.buf);
static GIT_PATH_FUNC(rebase_path_strategy_opts, "rebase-merge/strategy_opts")
	padding = strspn(bol, " \t");
		    (p1 = strchr(p1, '\'')) &&


static int do_label(struct repository *r, const char *name, int len)
	opts->default_msg_cleanup = COMMIT_MSG_CLEANUP_NONE;


static int pick_commits(struct repository *r,
	if (commit) {
		ret = 1;
	}
	cmd.git_cmd = 1;
	if (res)

	return lookup_tree(r, the_hash_algo->empty_tree);
		const char *done = rebase_path_done();
{
		item->util = xstrdup(cp);
			if (valid == todo_list->items[i].command)
	prev_reflog_action = xstrdup(getenv(GIT_REFLOG_ACTION));
				return error(_("cannot fixup root commit"));

	if (!commit)
		/* Add HEAD as implicit "tip of branch" */
			const char *oid = flags & TODO_LIST_SHORTEN_IDS ?
			oid = &to_merge->item->object.oid;
			found_sob = 1;
			oidcpy(&head, the_hash_algo->empty_tree);
		return;
		return -1;
 * original "pick" commit.  (If the series ends without a "squash"
				 oid, author, opts->gpg_sign, extra)) {
	return res;
	 * commit, we cannot fast-forward.

	unlink(git_path_merge_head(r));
static int run_command_silent_on_success(struct child_process *cmd)
	struct strbuf buf = STRBUF_INIT;
	} else if (copy_file(rebase_path_message(),
 *	GIT_AUTHOR_DATE='$author_date'
		oideq(&commit->parents->item->object.oid,
	todo_list_release(&new_todo);
}
	{ 'm', "merge" },
	return 1;
		if (!unlink(git_path_cherry_pick_head(r)) && verbose)
	} else if (command == TODO_FIXUP) {
		write_file(rebase_path_gpg_sign_opt(), "-S%s\n", opts->gpg_sign);
		apply_autostash(opts);
	struct object_id oid;
	while (todo_list->current < todo_list->nr) {
leave_merge:
		hashmap_add(&state.labels, &onto_label_entry->entry);
	{ 'x', "exec" },
	if (rebase_merges)
	return ret;

							    todo_list->current),
"It has been rescheduled; To edit the command before continuing, please\n"
	struct strbuf buf = STRBUF_INIT;
	if (repo_read_index(r) < 0) {
}
		todo_list->nr = nr;
		return COMMIT_MSG_CLEANUP_SPACE;
		res |= git_config_set_in_file_gently(opts_file,

			  &tree)) {

	strbuf_addstr(&buf, get_dir(opts));
			  "\n"
	if (is_rebase_i(opts)) {
			  "Not rewinding, check your HEAD!"));
		format_subject(&buf, subject, " ");
	if ((command == TODO_PICK || command == TODO_REWORD ||
			hashmap_put(&subject2item, &entry->entry);
	revs.pretty_given = 1;
	argv_array_push(&cmd.args, commit);

			if (get_oid("HEAD", &head)) {
	if (opts->quiet)
	if (opts->allow_rerere_auto)
/*
	update_abort_safety_file();
		}
		if (skip_prefix(message, " <", &message))
	if (!label) {
	/* Eat up extra spaces/ tabs before object name */
	{ 'e', "edit" },
	if (item->command == TODO_EXEC || item->command == TODO_LABEL ||
		if (j || p)
				rebase_path_amend());
GIT_PATH_FUNC(git_path_commit_editmsg, "COMMIT_EDITMSG")
"    git rebase --continue\n");
}
GIT_PATH_FUNC(rebase_path_todo_backup, "rebase-merge/git-rebase-todo.backup")
		if (todo_list->current < todo_list->nr)
	BUG("invalid cleanup_mode provided (%d)", cleanup_mode);
		}
			opts->current_fixup_count--;
		res = -1;
				return error_with_patch(r, item->commit,
 * Returns 3 when sob exists within conforming footer as last entry
		if (file_exists(rebase_path_drop_redundant_commits()))
	todo_list->nr = nr;
	struct strbuf buf;

static int read_oneliner(struct strbuf *buf,


		ret = -1;
		goto out;
		}
	todo_list_release(&todo_list);
				return error(_("unusable squash-onto"));
	struct commit_todo_item commit_todo;
		read_strategy_opts(opts, &buf);
			 * the title and body to be filled in by the user.
	if (a)
 * to run 'git commit' to display an error message
{

	if (can_fast_forward) {

struct subject2item_entry {
									&oid,

	int has_footer;
			item->commit = NULL;
			if (get_oid_hex(buf.buf, &opts->squash_onto) < 0)
			       COMMIT_LOCK | SKIP_IF_UNCHANGED))
		return error(_("%s: not a valid OID"), orig_head);
		label = p = state->buf.buf;
{
					head_ref.buf);

			error_errno(_("could not write '%s'"),

						opts->verbose ? "\n" : "\r");

				struct replay_opts *opts)
	const char *nl;
{
			item->command = i;
		res |= git_config_set_in_file_gently(opts_file,
		if (!strlen(name))
				continue;
		todo_list->total_nr = todo_list->done_nr

				    !get_oid("HEAD", &oid) &&
				     command_to_string(item->command), bol);
			return error(_("could not parse HEAD"));
		rollback_lock_file(&lock);


		todo_list->alloc = alloc;
			message = eol + 1;
static int get_item_line_offset(struct todo_list *todo_list, int index)
	}
{
"\n"
	 * rebased, and which can therefore not be labeled, we use a unique
		item->arg_offset = bol - buf;
			} else if (is_fixup(peek_command(todo_list, 0))) {
			ret = fast_forward_to(r, &to_merge->item->object.oid,
	}

	if (!format || !*format) {
		rollback_lock_file(&index_lock);
 */

{
	sequencer_get_last_command(r, &action);
static GIT_PATH_FUNC(rebase_path_message, "rebase-merge/message")
	item->flags = 0;
		return error(_("cannot resolve HEAD"));
	struct strbuf ref_name = STRBUF_INIT;
			p = p->next;
		struct object_id oid;
}
		commit = lookup_commit_reference_by_name(buf->buf);
 * was in the template intact
 * Reads a file that was presumably written by a shell script, i.e. with an
				strbuf_reset(&buf);
				goto cleanup_head_ref;
		error_errno(_("could not write to '%s'"), filename);
		rollback_lock_file(&lock);
		if (get_oid_hex(rev.buf, &to_amend))

"If they are meant to go into a new commit, run:\n"
		write_author_script(message);
		if (fixup_okay)

				       COMMIT_LOCK | SKIP_IF_UNCHANGED)) {
				return error(_("writing squash-onto"));
		 * command needs to be rescheduled).
		struct object_id oid;
			if (action != REPLAY_REVERT)
		strbuf_addf(&buf, " --%s", opts->xopts[i]);

	else if (!strcmp(key, "options.strategy-option")) {
				*eol = '\0';
	 * about this case, though, because we wrote that file ourselves, so we
	return 0;
			return error(_("invalid file: '%s'"), rebase_path_amend());
	} else if (ref_transaction_update(transaction, ref_name.buf, &head_oid,
				    git_path_merge_msg(r), 0);
	if (opts->allow_ff && !is_fixup(command) &&
	if (is_rebase_i(opts) &&
	}
	const struct labels_entry *a, *b;
	if (!sequencer_get_last_command(r, &action)) {
static GIT_PATH_FUNC(rebase_path_author_script, "rebase-merge/author-script")
			       struct replay_opts *opts,
/**
	free(author);
	int i;
			res = 1; /* run 'git commit' to display error message */
	}
		sequencer_remove_state(opts);
#include "revision.h"
	/* Expand the commit IDs */
	 * accomplish that goal, we walk backwards from the branch tips,
	struct index_state *istate = r->index;

	strbuf_stripspace(&tmpl, cleanup_mode == COMMIT_MSG_CLEANUP_ALL);


			if (!read_oneliner(&buf, rebase_path_onto(), 0)) {
		return use_editor ? COMMIT_MSG_CLEANUP_SCISSORS :
			    oid_to_hex(&commit->object.oid));
 * See if the user edited the message in the editor or left what
	int retval = -1; /* assume failure */
		}
			 */
		return error(_("failed to skip the commit"));
			}
	strbuf_reset(buf);
			item->commit = NULL;

	    !file_exists(git_path_revert_head(r)))
{
	int ret = 0;
	return run_command_v_opt(argv, RUN_GIT_CMD);
				argv_array_push(&hook.args, "rebase");
		todo_list_add_exec_commands(todo_list, commands);
		reword = 1;
				     &p1) &&
	}

		else if ((eol = strchr(message, '\n')))
		}

		*check_todo = !!(flags & EDIT_MSG);
		start = sb->buf;
	 *     just drop the ones that become empty
}
			return error(_("%s does not accept arguments: '%s'"),
static int run_rewrite_hook(const struct object_id *oldoid,
	written = write_in_full(fd, buf.buf, buf.len);
			else if (buf->len && buf->buf[buf->len - 1] != '-')
				opts->allow_rerere_auto = RERERE_NOAUTOUPDATE;
		rev.use_terminator = 1;
		if (flags & TODO_EDIT_MERGE_MSG) {
	return 0;
			author = get_author(msg.message);
		if (to_merge->next)
	 * If we were called as "git cherry-pick <commit>", just
{
		flush_rewritten_pending();
		_(action_name(opts)));
	const char nick = todo_command_info[command].c;
	if (opts->xopts) {
}
	if (file_exists(git_path_cherry_pick_head(r))) {
	if (read_and_refresh_cache(r, opts))
	if (remove_dir_recursively(&buf, 0))
/*
		ret = error(_("cannot merge without a current revision"));
	o.branch2 = next ? next_label : "(empty tree)";
		append_todo_help(count_commands(todo_list),
				if (!starts_with(p, "squash ") &&
					name, type_name(type));
		 * the commit message and if there was a squash, let the user
			   opts, flags))
				return error_with_patch(r, commit,
	/*
			opts->default_msg_cleanup = COMMIT_MSG_CLEANUP_SCISSORS;

		}
	strbuf_release(&state.buf);
				    flags & ~(TODO_LIST_SHORTEN_IDS))) {

				p++;
			break;
	}
	if (get_oid("HEAD", &oid)) {
	struct strbuf buf = STRBUF_INIT;
				warning(_("could not delete '%s'"), p);
			nr += commands->nr;
}
	if (opts->gpg_sign)
static const char *get_item_line(struct todo_list *todo_list, int index)
			return NULL;
		if (item->command >= TODO_NOOP)
			return 0;
	child.no_stdout = 1;

			     oid_to_hex(&commit->object.oid));
		}
		const char *message = logmsg_reencode(current_head, NULL,
	int keep_empty = flags & TODO_LIST_KEEP_EMPTY;
	char label[FLEX_ARRAY];
#include "config.h"

		 */
			advise(in_progress_advice,
	if ((flags & EDIT_MSG) && message_is_empty(msg, cleanup)) {

	}
				    COMMIT_MSG_CLEANUP_SPACE;
	oidcpy(&string_entry->entry.oid, oid);
	revs.limited = 1;
	struct strbuf sb = STRBUF_INIT;
	struct hashmap labels;
{
		return -1;
				/*
}
			res = error(_("unable to parse commit author"));
		if (!ret && (discard_index(r->index) < 0 ||
		return error(_("cannot resolve HEAD"));
	while ((commit = get_revision(&revs))) {
	return sequencer_continue(r, opts);
struct string_entry {
		 (*bol == ' ' || *bol == '\t'))
			error_errno("unable to open '%s'", todo_path);
}
				todo_list->done_nr++;
			while (cur >= 0) {
				  "Your changes are safe in the stash.\n"
				opts->allow_rerere_auto == RERERE_AUTOUPDATE ?
	int i, insert, nr = 0, alloc = 0;

			 * fixup/squash command (which was just skipped), do we

 * The file to keep track of how many commands were already processed (e.g.
	}
}

	default:
	struct object_id head;
			entry->i = i;
		return -1;
	else if (!strcmp(key, "options.record-origin"))
			p = eol + 1;
		opts->allow_empty_message =
	return res;

	 * rebase -i writes "git-rebase-todo" without the currently executing
static const char *action_name(const struct replay_opts *opts)
					"options.strategy-option",
				log_tree_diff_flush(&log_tree_opt);
		if (opts->verbose) {
		if (!res) {
				term_clear_line();
		strbuf_trim(&sb);
	revs.right_only = 1;
		return -1;
	 * of a cherry-pick sequence.
			struct stat st;
	if (get_message(commit, &msg) != 0)
		return 0;
				    merge_arg_len, arg);
	if (opts->signoff)
	if (res == -1)
			write_author_script(msg.message);
				strbuf_setlen(buf, len);
		 * TRANSLATORS: %s will be "revert", "cherry-pick" or

static inline int is_rebase_i(const struct replay_opts *opts)
static int do_recursive_merge(struct repository *r,
	assert(opts->revs);

		   (!(flags & CREATE_ROOT_COMMIT) || (flags & AMEND_MSG))) {
		item->command = command;
			hook_commit = "HEAD";
	}
			opts->keep_redundant_commits = 1;
		return COMMIT_MSG_CLEANUP_NONE;
	bases = get_merge_bases(head_commit, merge_commit);
			repo_init_revisions(r, &log_tree_opt, NULL);
		}
	size_t base_offset = buf->len;
		 * Whether final fixup or not, we just cleaned up the commit
		struct object_id *oid;

		return N_("cherry-pick");
		goto leave_merge;
		}
	if (len == 1 && *name == '#')
static const char *short_commit_name(struct commit *commit)

	if (!file_exists(git_path_seq_dir()))

			return error(_("empty commit set passed"));
	if (read_ref_full("HEAD", 0, &head_oid, NULL))
		flags |= AMEND_MSG;

		opts->allow_empty =
			unlink(git_path_merge_head(r));
		}
	if (has_unstaged_changes(r, 1))
			     git_path_merge_msg(r), rebase_path_message());
		if (!cp) {
	struct commit_message msg = { NULL, NULL, NULL, NULL };

	char *reflog_action = getenv(GIT_REFLOG_ACTION);
	strbuf_reset(&buf);
		if (!is_empty && (commit->object.flags & PATCHSAME))
		return error(_("unknown command: %d"), command);

	struct ref_store *refs = get_main_ref_store(r);
		opts->revs->reverse ^= 1;
		todo_list_release(&new_todo);
	if (found_sob_last)
		strbuf_release(&err);
				   0, sb.buf, err) ||
 * git-am.sh/git-rebase--interactive.sh scripts, and thus if the file differs

	*name = kv.items[name_i].util;
		free((void *)desc.buffer);
			advise(_("after resolving the conflicts, mark the corrected paths\n"
		strbuf_release(&rev);
			ret = error(_("could not read index"));

		if (p != eol && eol[-1] == '\r')
}
			argv_array_push(&child.args, "copy");


	o.ancestor = base ? base_label : "(empty tree)";
			return error(_("could not parse commit '%s'"),
static int skip_single_pick(void)
	o.show_rename_progress = 1;
	if (is_command(TODO_PICK, &bol) && (*bol == ' ' || *bol == '\t'))
	if (commit->parents) {
			msg_file = dest;
		}
	git_config(git_sequencer_config, opts);

					  strihash(label), label)) {
	 * we'd not want to barf here, instead give advice on how to proceed. We
	 */
			subjects[i] = NULL;
	}
	else if (!strcmp(key, "options.edit"))

		error("%s", err.buf);
	if (!need_cleanup)


		wt_status_append_cut_line(msgbuf);
			if (entry)
		int i;
 * -Wtautological-constant-out-of-range-compare complaining that the comparison
		fprintf(stderr, "%s\n", msg);
				    write_message(p, strlen(p), path, 0)) {
	struct strbuf buf = STRBUF_INIT;
		base = commit;
	char subject[FLEX_ARRAY];
		return error(_("make_script: unhandled options"));
 * commits that have been processed, but not committed yet,
						 "-X%s", opts->xopts[k]);

				 struct replay_opts *opts,
	int i;

		next_label = msg.parent_label;
			if ((*label & 0x80) || isalnum(*label))
{
		res |= git_config_set_in_file_gently(opts_file,
 * we had better say that the current user is responsible for that.
			goto leave_merge;
			     command_to_string(item->command));
