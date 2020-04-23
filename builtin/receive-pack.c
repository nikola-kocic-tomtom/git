		return;
		NULL, "--", NULL
		    !delayed_reachability_test(si, i))
	if (!boc)
	if (use_sideband)
{
static void rp_error(const char *err, ...) __attribute__((format (printf, 1, 2)));
	report_message("warning: ", err, params);
		k_opad[i] = key[i] ^ 0x5c;
{
	if (!use_sideband)
	if (do_update_worktree) {

}

static const char *service_dir;
	for (cmd = commands; cmd; cmd = cmd->next) {
		strbuf_addstr(&cap,
	}
	struct child_process proc = CHILD_PROCESS_INIT;
	if (is_bare_repository())
		if (!strcmp(reader->line, "push-cert")) {
		    old_object->type != OBJ_COMMIT ||
	*cmd_list = NULL;
		return 0;
		linelen = strlen(reader->line);
	strbuf_release(&refname_full);
	reject_updates_to_hidden(commands);
	/*
		return;

static off_t max_input_size;
	for (i = 0; i < extra.nr; i++)
	const char *line = msg;
}
enum deny_action {
				"gc", "--auto", "--quiet", NULL,

cleanup:
	if (!starts_with(name, "refs/") || check_refname_format(name + 5, 0)) {
		if (!strcasecmp(value, "refuse"))
static void show_ref(const char *path, const struct object_id *oid)
	 * Now we'll start writing out refs, which means the objects need
		return "denyCurrentBranch = updateInstead needs a worktree";
		return code;
		if (push_cert_nonce) {
	const char *read_tree[] = {
	return status;
			   PACKET_READ_CHOMP_NEWLINE |
	if (!checked_connectivity)
				      &push_cert_oid))

{
	}
						 "GIT_PUSH_CERT_NONCE_SLOP=%ld",
			argv_array_push(&child.args, "-q");
}

	ALLOC_ARRAY(ref_status, ref->nr);

	else

		struct string_list push_options = STRING_LIST_INIT_DUP;
	int flag;
			rp_error("%s", err.buf);
static int should_process_cmd(struct command *cmd)
#include "lockfile.h"
		if (!si->used_shallow[i])
		}
	   "its current branch; however, this is not recommended unless you\n"
	tmp_objdir = tmp_objdir_create();

			return "non-fast-forward";
	muxer.in = -1;
		 cmd->ref_name,
	struct check_connected_options opt = CHECK_CONNECTED_INIT;
{
	if (strcmp(var, "receive.fsckobjects") == 0) {
}
			retval = 0;
	if (tmp_objdir)
static int reject_thin;
		cmd->skip_update = 1;
static const char *cert_nonce_seed;
static void execute_commands(struct command *commands,
	the_hash_algo->init_fn(&ctx);
}
	int index;
		return -1; /* EOF */
		run_receive_hook(commands, "post-receive", 1,
		argv_array_pushf(&proc->env_array, "GIT_PUSH_CERT=%s",
	state.cmd = commands;
			pfd.fd = in;
	DENY_UNCONFIGURED,
		if (feed(feed_state, &buf, &n))
	}
			if (next_line)

			    const struct string_list *push_options)
}
	strbuf_addf(&buf, "%s%s", get_git_namespace(), cmd->ref_name);
			if (parse_feature_request(feature_list, "side-band-64k"))
 * robust. !get_sha1() based check used here and elsewhere would not
		prepare_shallow_update(si);
	   "to 'ignore' or 'warn' in the remote repository to allow pushing into\n"
		usage_msg_opt(_("Too many arguments."), receive_pack_usage, options);

static int use_push_options;
	if (strcmp(var, "receive.certnonceseed") == 0)
				rp_warning("deleting the current branch");
	struct async muxer;
			continue;
			strbuf_reset(&err);

			report(commands, unpack_status);
};

		run_update_post_hook(commands);
	struct command **cmd_list = cb_data;
	uint32_t mask = 1 << (cmd->index % 32);
			} /* else there is actual data to read */
			err_fd = muxer.in;
		 */
	va_end(params);

static const char *parse_pack_header(struct pack_header *hdr)
}
	si->shallow_ref = xcalloc(si->ref->nr, sizeof(*si->shallow_ref));
	oidcpy(&cmd->old_oid, &old_oid);
{

			int true_flush = 0;
	boc = strstr(push_cert->buf, "\n\n");
		/*
static void push_header_arg(struct argv_array *args, struct pack_header *hdr)
			const char *feature_list = reader->line + linelen + 1;
		if (report_status)
	struct object_id *old_oid = &cmd->old_oid;
		alt_shallow_file = setup_temporary_shallow(si->shallow);
	}
		if (!check_cert_push_options(&push_options)) {
	/* run_command() does not clean up completely; reinitialize */
		argv_array_pushf(&proc.env_array, "GIT_PUSH_OPTION_COUNT=%d",
	struct command *cmd;


	if (!hook)
	int status = parse_hide_refs_config(var, value, "receive");
	eoc = push_cert->buf + parse_signature(push_cert->buf, push_cert->len);

		transfer_fsck_objects = git_config_bool(var, value);
		memset(&sigcheck, '\0', sizeof(sigcheck));
static enum deny_action deny_current_branch = DENY_UNCONFIGURED;
					 cmd->ref_name, cmd->error_string);
	};
	head_name = head_name_to_free = resolve_refdup("HEAD", 0, NULL, NULL);
		deny_delete_current = parse_deny_action(var, value);
					 "GIT_PUSH_CERT_NONCE=%s",
	if (strcmp(var, "receive.advertiseatomic") == 0) {
	 * In addition, when a nonce issued by another instance has
	si->need_reachability_test =
	if (advertise_refs)
	struct child_process child = CHILD_PROCESS_INIT;
		free((void *)push_cert_nonce);
#include "pkt-line.h"
		return 0;

}
			return "shallow error";
struct receive_hook_feed_state {
int cmd_receive_pack(int argc, const char **argv, const char *prefix)
		return "unable to create temporary object directory";
		    && ref_transaction_commit(transaction, &err)) {
				quiet = 1;
	int err_fd = 0;
	proc.stdout_to_stderr = 1;
			finish_async(&muxer);

		retval = NONCE_BAD;
	if (use_atomic)
					 nonce_status);

	}
				 "--keep=receive-pack %"PRIuMAX" on %s",

		goto failure;
static void check_aliased_updates(struct command *commands)
#include "remote.h"
	check_aliased_update_internal(cmd, list, dst_name, flag);
		if (si->used_shallow[i] &&
		return 0;
					   0, "push",
			return 1;
	   "To squelch this message and still keep the default behaviour, set\n"
				      int linelen)
		boc += 2;

		return "protocol error (pack version unsupported)";
		return;
	child_process_init(&child);
		}
{
		die("protocol error: expected old/new/ref, got '%s'", line);
	}
		 * it yet; just pass along the data.
	oidcpy(oid, &cmd->new_oid);
{
	return 0;
		status = run_command(&child);
		return "Working directory has unstaged changes";
		if (!strcasecmp(value, "ignore"))
	}
		 find_unique_abbrev(&dst_cmd->old_oid, DEFAULT_ABBREV),
	if (unpacker_error) {
	}
}

	/*
	case PH_ERROR_EOF:
	struct command *cmd = state->cmd;
		if (status)
		keepalive_in_sec = git_config_int(var, value);
			struct command *cmd;
		if (!should_process_cmd(cmd))
static int receive_pack_config(const char *var, const char *value, void *cb)
		retval = NONCE_SLOP;
}
		muxer.proc = copy_to_sideband;

	argv[1] = NULL;
	char data[128];
		return 0;
		buf = next_line;
	struct strbuf buf = STRBUF_INIT;
		return;

static int show_ref_cb(const char *path_full, const struct object_id *oid,
			argv_array_push(&child.args, "--show-resolving-progress");
{
		return "hook declined";

		if (!proc.args.argc)



	};
	strbuf_release(&buf);
		bogs = parse_signature(push_cert.buf, push_cert.len);
			     const struct string_list *push_options)
	else
	}
		OPT_END()
}
		int i;
#include "oid-array.h"
	struct child_process child = CHILD_PROCESS_INIT;
		case DENY_UPDATE_INSTEAD:
		return "bad pack";
		 * push support for protocol v2 has not been implemented yet,
	if (argc == 0)
				 " (you should pull first)", name);
	struct command *cmd = *cmd_list;
	proc.trace2_hook_name = "update";
	if (!len)
	int status;
static void queue_commands_from_cert(struct command **tail,
	if (!is_null_oid(&push_cert_oid)) {

			case DENY_UNCONFIGURED:
	struct command *cmd;

		reported_error = "transaction failed to start";


		child.out = -1;
	const char *dst_name;
		return DENY_REFUSE;
				if (errno == EINTR)
		return NULL; /* good */
		struct string_list_item *item =
	if (worktree && worktree->path)
		transfer_unpack_limit = git_config_int(var, value);
	}
		return "protocol error (pack signature mismatch detected)";
	return !get_oid("HEAD", &oid);
	child.git_cmd = 1;
				struct shallow_info *si,

		muxer.in = -1;
{
	int i;
	sz += vsnprintf(msg + sz, sizeof(msg) - sz, err, params);

			case DENY_UPDATE_INSTEAD:
					refuse_unconfigured_deny_delete_current();
			if (parse_feature_request(feature_list, "report-status"))
	}
			     const char *unpacker_error,
	if (hdr_err) {
	/* RFC 2104 2. (1) */
		shallow_update = 0;
		      "but I can't find it!", oid_to_hex(new_oid));

	if (strcmp(var, "receive.unpacklimit") == 0) {

			struct child_process proc = CHILD_PROCESS_INIT;

	if (code)
		break;
#include "sigchain.h"
	strbuf_addf(&buf, "%"PRItime"-%.*s", stamp, (int)the_hash_algo->hexsz, hash_to_hex(hash));
	if (run_hook_le(env->argv, push_to_checkout_hook,

	if (bufp) {
		strbuf_release(&err);
	struct oid_array extra = OID_ARRAY_INIT;
	commit_lock_file(&shallow_lock);
			*cmd_list = cmd->next;

	child.stdout_to_stderr = 0;
	 * timestamp within receive.certnonceslop seconds, we pretend
		if (git_config_pathname(&path, var, value))
	if (run_receive_hook(commands, "pre-receive", 0, push_options)) {
				return "Invalid denyDeleteCurrent setting";
	proc.err = use_sideband ? -1 : 0;
				 * sure we send any other data we read along
			cmd->skip_update = 1;
	memset(key, '\0', GIT_MAX_BLKSZ);
	}

	}
{
		return;

leave:
	strbuf_addstr(&refname_full, get_git_namespace());
static void report_message(const char *prefix, const char *err, va_list params)
		for (cmd = commands; cmd; cmd = cmd->next)
		}
	}
	    *p++ != ' ')
		}
	}
	struct command *cmd = *cmd_list;
}
	check_aliased_updates(commands);
		advertise_push_options = git_config_bool(var, value);
		return "push-to-checkout hook declined";
	if (use_sideband)
		memcpy(key, key_in, key_len);
	strbuf_release(&buf);

				}

	struct shallow_info si;
			argv_array_pushf(&proc.env_array,
		if (max_input_size)
		}
	   "'receive.denyCurrentBranch' configuration variable to 'refuse'.");
	 * objects ourselves to set up shallow information.

	return DENY_IGNORE;
static void execute_commands_non_atomic(struct command *commands,
	if (nonce_stamp_slop_limit &&
	child.stdout_to_stderr = 1;
			     struct receive_hook_feed_state *feed_state)
		if (xgethostname(hostname, sizeof(hostname)))
	 */
		goto leave;
	struct lock_file shallow_lock = LOCK_INIT;

	int fsck_objects = (receive_fsck_objects >= 0
	if (run_command(&child))
	else if (0 <= receive_unpack_limit)

	child.git_cmd = 1;
		struct strbuf cap = STRBUF_INIT;
 * on an unborn branch?" test into one, and make the unified one more

	if (strcmp(expect, nonce)) {
				die("protocol error: expected shallow sha, got '%s'",
	KEEPALIVE_NEVER = 0,


	case protocol_v0:
static int quiet;
		OPT_HIDDEN_BOOL(0, "stateless-rpc", &stateless_rpc, NULL),

			argv_array_pushf(&child.args, "--max-input-size=%"PRIuMAX,
			rp_error("%s", err.buf);
	case protocol_v2:
	}
	hdr_err = parse_pack_header(&hdr);
			strbuf_release(&err);
	}
	/* RFC 2104 5. HMAC-SHA1-80 */
			packet_buf_write(&buf, "ng %s %s\n",
		if (!transaction) {
		 find_unique_abbrev(&dst_cmd->new_oid, DEFAULT_ABBREV));
	   "You can set the 'receive.denyCurrentBranch' configuration variable\n"
static char *refuse_unconfigured_deny_msg =
	hmac(hash, buf.buf, buf.len, cert_nonce_seed, strlen(cert_nonce_seed));
				(uintmax_t)max_input_size);
			return DENY_UPDATE_INSTEAD;
					struct shallow_info *si)
	child.no_stdin = 1;
	}
					   new_oid, old_oid,
	setenv(GIT_SHALLOW_FILE_ENVIRONMENT, alt_shallow_file, 1);
	else
{
	if (tmp_objdir_migrate(tmp_objdir) < 0) {
	const char *argv[5];

	struct strbuf err = STRBUF_INIT;
}


	DENY_IGNORE,
{
		tail = queue_command(tail, boc, eol ? eol - boc : eoc - boc);
	case protocol_v1:
				}
	child.stdout_to_stderr = 1;
	if (worktree)
				     &opt))
		return;
	close(proc.in);

			strbuf_addstr(&cap, " push-options");
		p = queue_command(p, reader->line, linelen);
				return "deletion of the current branch prohibited";
	if (!already_done) {
}
	}



		return 0;
	KEEPALIVE_AFTER_NUL,
		else
#include "fsck.h"
		old_commit = (struct commit *)old_object;
	int *ref_status;
		packet_flush(1);
{

	}
		if (shallow_update && si->shallow_ref[cmd->index] &&
		struct check_connected_options opt = CHECK_CONNECTED_INIT;
			}
				  struct argv_array *env,

	strbuf_release(&state.buf);
}
	data.cmds = commands;
	};
		goto leave;
			int ret;
static struct object_id push_cert_oid;
	for (i = 0; i < si->nr_ours; i++)
	if (!is_null_oid(new_oid) && !has_object_file(new_oid)) {

	int sz;
		return 1;
	for (cmd = commands; cmd; cmd = cmd->next) {
		die("malformed push certificate %.*s", 100, push_cert->buf);
			oidcpy(oid, &cmd->new_oid);
	child.argv = update_refresh;
static const char *push_to_checkout_hook = "push-to-checkout";
static int shallow_update;

				rp_warning("Allowing deletion of corrupt ref.");

	   "other way.\n"
#include "version.h"
static const char *update_worktree(unsigned char *sha1, const struct worktree *worktree)
			break;
	child.no_stdin = 1;
	 */
			rp_error("%s", err.buf);
			return "failed to delete";
		if (!cmd->error_string)
static int run_receive_hook(struct command *commands,

	setup_alternate_shallow(&shallow_lock, &opt.shallow_file, &extra);
	if (is_null_oid(new_oid)) {
		if (linelen < reader->pktlen) {
		if (pack_lockfile)
	child.dir = work_tree;
	if (!enter_repo(service_dir, 0))
			    const char *hook_name,
static const char *alt_shallow_file;
		if (is_null_oid(&cmd->new_oid))
		return 0;
	opt.env = tmp_objdir_env(tmp_objdir);
	int i, j, k, bitmap_size = DIV_ROUND_UP(si->ref->nr, 32);
				cmd->did_not_exist = 1;
			}
			return DENY_REFUSE;
			pfd.events = POLLIN;
	tmp_objdir_add_as_alternate(tmp_objdir);
	free((void *)push_cert_nonce);
			switch (deny_delete_current) {
					si->shallow_ref[j * 32 + k]++;
	strbuf_addf(&buf, "%s:%"PRItime, path, stamp);
static int stateless_rpc;

		send_sideband(1, 1, buf.buf, buf.len, use_sideband);
	int retval = 1;

	struct argv_array env = ARGV_ARRAY_INIT;

				 oid_to_hex(&push_cert_oid));
}
			proc.stdout_to_stderr = 1;
	packet_trace_identity("receive-pack");
		child.err = err_fd;
				packet_reader_read(reader);
	}
}
		if (shallow_update && data->si->shallow_ref[cmd->index])
static int head_has_history(void)

	/*
		if (fsck_objects)
	if (strcmp(var, "receive.maxinputsize") == 0) {
				cmd->error_string = "pre-receive hook declined";
		if (oidset_insert(seen, oid))
		close(child.out);

	if (!strcmp(var, "receive.denycurrentbranch")) {
		strbuf_release(&cap);


		}
			   PACKET_READ_DIE_ON_ERR_PACKET);
	if (shallow_update) {
		new_object = parse_object(the_repository, new_oid);
		push_cert_nonce = xstrdup(nonce);
		packet_write_fmt(1, "%s %s\n", oid_to_hex(oid), path);
		"inconsistent aliased update";
	proc.argv = argv;
	use_keepalive = KEEPALIVE_AFTER_NUL;
			unlink_or_warn(pack_lockfile);

	if (!transaction) {
static void check_aliased_update_internal(struct command *cmd,
	packet_reader_init(&reader, 0, NULL, 0,
		child.git_cmd = 1;
			case DENY_WARN:
			}

	report_message("error: ", err, params);

	if (strcmp(var, "receive.shallowupdate") == 0) {
	}
		    update_shallow_ref(cmd, si))
		argv_array_pushf(&proc->env_array, "GIT_PUSH_CERT_STATUS=%c",
			return "branch is currently checked out";
	namespaced_name = strbuf_detach(&namespaced_name_buf, NULL);

	if (!find_hook(push_to_checkout_hook))
static void run_update_post_hook(struct command *commands)
	   "\n"
static void report(struct command *commands, const char *unpack_status)
	show_ref(".have", oid);
	const char *ret;
			cmd->error_string = "deny deleting a hidden ref";
	const char *path = strip_namespace(path_full);
		register_shallow(the_repository, &extra.oid[i]);
	   "\n"
	argv_array_clear(&env);
	struct strbuf buf = STRBUF_INIT;
		/* fallthrough */

	if (si->nr_ours || si->nr_theirs) {

		oid_array_append(ref, &cmd->new_oid);
}
static const char *unpack(int err_fd, struct shallow_info *si)

	trace_printf_key(&trace_shallow,

			};
	expect = prepare_push_cert_nonce(service_dir, stamp);
	oid_array_clear(&ref);
				use_atomic = 1;
		return;

		si->need_reachability_test[i] =

	va_list params;
			if (p) {
		sz = xread(in, data, sizeof(data));
	}
	static char *namespaced_name;
			proc.argv = argv_gc_auto;
	git_hash_ctx ctx;
			return NULL;
		for (cmd = commands; cmd; cmd = cmd->next) {

			return ret;
		char hostname[HOST_NAME_MAX + 1];
	   "with what you pushed, and will require 'git reset --hard' to match\n"
		warn_if_skipped_connectivity_check(commands, si);
	sigchain_pop(SIGPIPE);

		push_header_arg(&child.args, &hdr);
		"update-index", "-q", "--ignore-submodules", "--refresh", NULL
		    !memcmp(line, key, key_len) && line[key_len] == ' ') {
static const char *push_to_checkout(unsigned char *hash,
			if (ref_exists(name)) {

		return 0;
			argv_array_pushf(&proc->env_array,
	int keepalive_active = 0;
	if (strcmp(var, "receive.denydeletecurrent") == 0) {
		return "unknown error in parse_pack_header";
		    cmd->ref_name);
static const char *update(struct command *cmd, struct shallow_info *si)
		if (!quiet && err_fd)

static int command_singleton_iterator(void *cb_data, struct object_id *oid);
					struct shallow_info *si)
				write_or_die(1, buf, sizeof(buf) - 1);
{
	child.env = env->argv;
					       struct shallow_info *si)
			     oid_to_hex(oid), path, 0, cap.buf);
			const char *argv_gc_auto[] = {
/*

		clear_shallow_info(&si);
				send_sideband(1, 2, p + 1, sz - (p - data + 1), use_sideband);
	the_hash_algo->update_fn(&ctx, k_opad, sizeof(k_opad));
{
			error("BUG: connectivity check has not been run on ref %s",

			if (parse_feature_request(feature_list, "quiet"))
			hash_to_hex(hash), NULL))
		if (max_input_size)
		if ((msg + len <= eol) || line == eol)
		prefer_ofs_delta = git_config_bool(var, value);
	state.cmd = commands;
	int do_update_worktree = 0;
		deny_current_branch = parse_deny_action(var, value);
		usage_msg_opt(_("You must specify a directory."), receive_pack_usage, options);


		    || strcmp(option,

	return 0;
		status = finish_command(&child);
				break;
	const char *error_string;
	show_ref(path, oid);
	*tail = cmd;
	unsigned char key[GIT_MAX_BLKSZ];
	strbuf_reset(&state->buf);
{
		 * so ignore the request to use v2 and fallback to using v0.
	argv_array_pushf(&env, "GIT_DIR=%s", absolute_path(git_dir));
		k_ipad[i] = key[i] ^ 0x36;
			return "index-pack fork failed";
	}
	    oideq(&cmd->new_oid, &dst_cmd->new_oid))
			close(err_fd);

	case 0:
	else
		if (!old_object || !new_object ||
		work_tree = git_work_tree_cfg;
		struct object *old_object, *new_object;

			return "failed to update ref";
	if (!si->nr_ours && !si->nr_theirs) {
#include "exec-cmd.h"

	argc = parse_options(argc, argv, prefix, options, receive_pack_usage, 0);
			const char *p = memchr(data, '\0', sz);
			continue;
	struct object_id oid;

				rp_warning("Deleting a non-existent ref.");
		return "Working directory has staged changes";
			      "report-status delete-refs side-band-64k quiet");
static int advertise_atomic_push = 1;
				send_sideband(1, 2, data, p - data, use_sideband);
		case DENY_IGNORE:
	for (cmd = commands; cmd; cmd = cmd->next) {
		if (!strcasecmp(value, "warn"))
				break;
			string_list_append(&ref_list, cmd->ref_name);
			    : 0);
			int saved_options = reader->options;
	}
			argv_array_pushf(&proc->env_array,
	if (*tail)

	while (1) {
	}
	struct strbuf err = STRBUF_INIT;

	}
		push_header_arg(&child.args, &hdr);
#include "protocol.h"
		goto leave;
	    !is_null_oid(old_oid) &&
static const char *NONCE_MISSING = "MISSING";
	}
	for (cmd = commands; cmd; cmd = cmd->next) {
			if (!si->used_shallow[i][j])
static void show_one_alternate_ref(const struct object_id *oid,

	if (strcmp(var, "receive.advertisepushoptions") == 0) {

	struct command **cmd_list = &data->cmds;
	if (git_config_bool(var, value))
static int check_cert_push_options(const struct string_list *push_options)
	struct packet_reader reader;
}
	return NULL;
	const char *update_refresh[] = {
				fsck_msg_types.buf);
static void write_head_info(void)
	    labs(nonce_stamp_slop) <= nonce_stamp_slop_limit) {
	}
		for (j = 0; j < bitmap_size; j++) {
	unsigned char k_ipad[GIT_MAX_BLKSZ];
			strbuf_addstr(&cap, " ofs-delta");

{

		return 0;

			goto failure;
				 sigcheck.key ? sigcheck.key : "");
		boc = eol ? eol + 1 : eoc;
	child.no_stdin = 1;
		if (use_push_options)

			packet_write_fmt(1, "version 1\n");
			return 0;
	 * Normally we just pass the tmp_objdir environment to the child
	struct command *cmd;
		return 0;
	 * transfer but will otherwise ignore them.
				continue;
	   "the work tree to HEAD.\n"

	static int already_done;
		*sizep = state->buf.len;
				continue;
}
		if (ref_status[cmd->index]) {
			argv_array_pushf(&child.args, "--strict%s",
		auto_update_server_info = git_config_bool(var, value);
	} else {
			close(err_fd);
	}
	switch (read_pack_header(0, hdr)) {

				if (!strcmp(reader->line, "push-cert-end\n"))
		retval = NONCE_BAD;


			if (deny_current_branch == DENY_UNCONFIGURED)
		if (is_null_oid(&cmd->new_oid))
		return "Could not update working tree to new HEAD";

	assign_shallow_commits_to_refs(si, si->used_shallow, NULL);
		push_cert_nonce = prepare_push_cert_nonce(service_dir, time(NULL));
static struct strbuf fsck_msg_types = STRBUF_INIT;
#include "commit.h"
			return 0;
	if (run_command(&child))
		work_tree = worktree->path;
				if (si->used_shallow[i][j] & (1U << k))
		shallow_update = git_config_bool(var, value);
	 * true .git/shallow though.

	struct iterate_data data;
	if (!start_command(&proc)) {
		return "funny refname";

	 */
			continue;
	struct oidset *seen = data;
static int transfer_unpack_limit = -1;
			ntohl(hdr->hdr_version), ntohl(hdr->hdr_entries));
	if (!cmd || is_null_oid(&cmd->new_oid))
		return;

			break;
	if (use_sideband) {
	} else {
					break;
	   "You can set 'receive.denyDeleteCurrent' configuration variable to\n"
				fsck_msg_types.buf);
	}
		/*
	opt.err_fd = err_fd;
	       state->skip_broken && (cmd->error_string || cmd->did_not_exist))
	struct command *cmd;
		const char *unpack_status = NULL;
	/* RFC 2104 2. (3) & (4) */
	if (!git_dir)
		/*
			continue;
{

	argv_array_pushf(env, "GIT_WORK_TREE=%s", absolute_path(work_tree));
		strbuf_addstr(&refname_full, cmd->ref_name);

static struct ref_transaction *transaction;
	 *
		retval = NONCE_OK;
	struct shallow_info *si;
		 */
		if (worktree || (head_name && !strcmp(namespaced_name, head_name))) {
#include "object.h"
	while (line && line < msg + len) {
#include "packfile.h"


			proc.err = use_sideband ? -1 : 0;
#include "connect.h"
	code = start_command(&proc);
		/* ...else, continue without relaying sideband */
	return 0;
{
		deny_non_fast_forwards = git_config_bool(var, value);
	if (value) {
			argv_array_pushf(&child.args, "--max-input-size=%"PRIuMAX,
			} else {
	}
					 "GIT_PUSH_CERT_NONCE_STATUS=%s",
static struct command **queue_command(struct command **tail,


{
	if (ref_is_hidden(path, path_full))
	char *option;
	argv[4] = NULL;
static void rp_warning(const char *err, ...) __attribute__((format (printf, 1, 2)));

}
		unpack_limit = transfer_unpack_limit;
		retval = NONCE_OK;
		return;
		/* Not what we would have signed earlier */

		if (ret)
		rp_error("%s", err.buf);

 * For the purpose of fixing "deploy-to-update does not work when
	argv[2] = oid_to_hex(&cmd->old_oid);
	}
			if (true_flush)

	if ((commands = read_head_info(&reader, &shallow)) != NULL) {
{
		}
	*cmd_list = NULL; /* this returns only one */
		if (use_sideband)
static void reject_updates_to_hidden(struct command *commands)
}
	if (oideq(&cmd->old_oid, &dst_cmd->old_oid) &&
		return 0;
		}

		const char *buf;
static const char *unpack_with_sideband(struct shallow_info *si)
	N_("By default, deleting the current branch is denied, because the next\n"
	if (feed_state->push_options) {
{
		return "Up-to-date check failed";
	service_dir = argv[0];
			/* to be checked in update_shallow_ref() */
static int copy_to_sideband(int in, int out, void *arg)
		return 0;
		use_keepalive = KEEPALIVE_NEVER;
	if ((item = string_list_lookup(list, dst_name)) == NULL)
{
		write_or_die(1, buf.buf, buf.len);
		if (!strcasecmp(value, "updateinstead"))
	return NULL;
	ostamp = parse_timestamp(push_cert_nonce, NULL, 10);
	}
				  const char *work_tree)
			cmd->error_string = "deny updating a hidden ref";
 */
	}
			continue;
		muxer.in = -1;
 */
		cmd->error_string = "broken symref";
				 &push_options);
	struct strbuf buf;
{
	child_process_init(&child);
	}
static void check_aliased_update(struct command *cmd, struct string_list *list)

			return "bad ref";
		return NULL;
		return;




		struct command *singleton = cmd;
static struct signature_check sigcheck;

{
	if (check_connected(iterate_receive_command_list, &data, &opt))
		deny_deletes = git_config_bool(var, value);
		transaction = ref_transaction_begin(&err);

	   "current branch, with or without a warning message.\n"
		return 0;
		receive_unpack_limit = git_config_int(var, value);
	}
	string_list_sort(&ref_list);
	transaction = ref_transaction_begin(&err);
	opt.env = tmp_objdir_env(tmp_objdir);
	child.argv = diff_index;
		return 0;
		if (ref_transaction_update(transaction,
	for (cmd = commands; cmd; cmd = cmd->next) {
	free(expect);
		reprepare_packed_git(the_repository);
			continue;
	oidcpy(&cmd->new_oid, &new_oid);
	struct strbuf buf = STRBUF_INIT;

		reported_error = "atomic transaction failed";
static const char *NONCE_BAD = "BAD";
#include "gpg-interface.h"
	close(in);
	}
static char *prepare_push_cert_nonce(const char *path, timestamp_t stamp)
			warning("Skipping unknown msg id '%s'", var);

{
			cmd->error_string = "shallow update not allowed";
	}
	const char *refname;
	 * report the time slop.
	if (parse_oid_hex(line, &old_oid, &p) ||
	va_list params;
			     struct shallow_info *si,
	}
		xcalloc(si->shallow->nr, sizeof(*si->reachable));



			continue;
static void set_connectivity_errors(struct command *commands,
	free(head_name_to_free);
		OPT_HIDDEN_BOOL(0, "advertise-refs", &advertise_refs, NULL),
						 nonce_stamp_slop);
			return DENY_WARN;
	}
	const char *argv[2];
		}

#include "argv-array.h"
	const char *diff_index[] = {
		return hdr_err;
static char *find_header(const char *msg, size_t len, const char *key,
		if (keepalive_active) {
		unpack_limit = receive_unpack_limit;
			continue;
				    struct argv_array *env,
	if (bohmac == nonce || bohmac[0] != '-') {
	dst_cmd->skip_update = 1;
				keepalive_active = 1;

	return ret;
	for (cmd = commands; cmd; cmd = cmd->next) {
leave:
			    int skip_broken,
		 " its target '%s' (%s..%s)",
	if (strcmp(var, "transfer.unpacklimit") == 0) {
		}
}

		       int flag, void *data)
	return &cmd->next;
		if (should_process_cmd(cmd) && si->shallow_ref[cmd->index]) {
}
 * pushing into an empty repository" issue, this should suffice for
	packet_buf_write(&buf, "unpack %s\n",

			reader->options &= ~PACKET_READ_CHOMP_NEWLINE;

			checked_connectivity = 0;
{
	const char *p;
	if (run_command(&child))
		send_sideband(1, 2, msg, sz, use_sideband);
			    && parse_feature_request(feature_list, "push-options"))
		argv_array_pushf(&child.args,
	return NULL;
{
	default:
	struct command *cmd;

					copy_to_sideband(proc.err, -1, NULL);
	setup_path();
		 * HMAC check, so it is not a forged by third-party)
	if (strcmp(var, "repack.usedeltabaseoffset") == 0) {
static const char *NONCE_OK = "OK";
			strbuf_addstr(&cap, " atomic");
	argv[0] = find_hook(hook_name);
				      struct oid_array *shallow)
	/* nonce is concat(<seconds-since-epoch>, "-", <hmac>) */
	 * processes that do the heavy lifting, but we may need to see these
	the_hash_algo->update_fn(&ctx, out, the_hash_algo->rawsz);
		strbuf_reset(&err);
			update_server_info(0);
			 const char **next_line)

		if (is_valid_msg_type(var, value))
static const char *NONCE_UNSOLICITED = "UNSOLICITED";
	int reflen;
	proc.no_stdin = 1;
static void update_shallow_info(struct command *commands,

		retval = NONCE_UNSOLICITED;
	 * nonce-seed and dir should match, so we can recompute and
		 * true for those associated with some refs and belong
};
		the_hash_algo->final_fn(key, &ctx);
	child.git_cmd = 1;
	} else if (!strcmp(push_cert_nonce, nonce)) {

	   "'warn' or 'ignore' in the remote repository to allow deleting the\n"


	/*
		if (status)
	hook = find_hook("post-update");
	}
		if (line + key_len < eol &&
				rp_error("refusing to delete the current branch: %s", name);
		len -= (next_line - buf);

	struct async muxer;
				 (uintmax_t)getpid(),
	/* RFC 2104 2. (6) & (7) */
	char msg[4096];
				 hostname);
	remove_nonexistent_theirs_shallow(si);
}
	dst_cmd = (struct command *) item->util;
	rp_error("%s", _(refuse_unconfigured_deny_msg));
	return finish_command(&proc);
		break;
	} else {
	for (cmd = commands; cmd; cmd = cmd->next) {
	argv[1] = cmd->ref_name;

	char *nonce = find_header(buf, len, "nonce", NULL);
	struct object_id new_oid;

	si->reachable =

	 * Advertise refs outside our current namespace as ".have"
	while (1) {
#include "repository.h"
		OPT__QUIET(&quiet, N_("quiet")),
			continue;
				use_push_options = 1;
	for (; cmd; cmd = cmd->next) {

	if (strcmp(var, "receive.updateserverinfo") == 0) {
				argv_array_pushf(&proc->env_array,

	child_process_init(&child);
	opt.progress = err_fd && !quiet;
				*next_line = *eol ? eol + 1 : eol;


	}
};

					  struct string_list *list,
	else
		retval = push_to_checkout(sha1, &env, work_tree);

		/*
			proc.no_stdin = 1;
			update_shallow_info(commands, &si, &ref);
		receive_fsck_objects = git_config_bool(var, value);
#include "sideband.h"
			case DENY_REFUSE:
	argv[3] = oid_to_hex(&cmd->new_oid);
				/*
				 sigcheck.signer ? sigcheck.signer : "");
	argv_array_pushf(args, "--pack_header=%"PRIu32",%"PRIu32,
			/* pass -- let other checks intervene first */
	}
	 * By how many seconds is this nonce stale?  Negative value
	    *p++ != ' ' ||
					   old_oid,
	}
		}
		if (!reject_thin)
	if (skip_prefix(var, "receive.fsck.", &var)) {
#include "object-store.h"
	proc.argv = argv;

					   namespaced_name,
	struct command *cmd;
}
	 * would mean it was issued by another server with its clock
}
	DENY_WARN,

	struct command *cmd;
}
		die("'%s' does not appear to be a git repository", service_dir);

		BUG("connectivity check skipped???");
		strbuf_release(&err);
	for (cmd = commands; cmd; cmd = cmd->next) {
		return 0;
	}
	oid_array_clear(&extra);
	}

		if (!cmd->error_string
			return DENY_IGNORE;
		options_seen++;
typedef int (*feed_fn)(void *, const char **, size_t *);
			if (get_oid_hex(reader->line + 8, &oid))


	free(option);
		if (is_null_oid(&cmd->new_oid))
		path = ".have";
		return git_config_string(&cert_nonce_seed, var, value);
		    (si->used_shallow[i][cmd->index / 32] & mask) &&
 */
	si->ref = ref;
	for (cmd = commands; cmd; cmd = cmd->next)
	child.no_stdin = 1;
	while (boc < eoc) {

		old_object = parse_object(the_repository, old_oid);
	}
	   "\n"
static void read_push_options(struct packet_reader *reader,
		if (advertise_atomic_push)
	}
		argv_array_pushv(&proc.env_array, tmp_objdir_env(tmp_objdir));

				"GIT_PUSH_OPTION_%d=%s", i,
		return -1;
			struct object_id oid;
		argv_array_push(&proc.args, cmd->ref_name);
		check_signature(push_cert.buf, bogs, push_cert.buf + bogs,
static void execute_commands_atomic(struct command *commands,
#include "config.h"
	 * keep hooks happy by forcing a temporary shallow file via
static void refuse_unconfigured_deny_delete_current(void)
	struct object_id old_oid;


		}
			xsnprintf(hostname, sizeof(hostname), "localhost");
	diff_index[4] = head_has_history() ? "HEAD" : empty_tree_oid_hex();
static const char * const receive_pack_usage[] = {
{
		if (!is_null_oid(&cmd->new_oid) && !cmd->skip_update) {
		 * v1 is just the original protocol with a version string,
	if (run_update_hook(cmd)) {
			proc.git_cmd = 1;
		if (sz <= 0)
		return 0;
	child.dir = work_tree;
static int use_sideband;
}
 * Return 1 if there is no push_cert or if the push options in push_cert are
		send_sideband(1, 2, data, sz, use_sideband);

	child.env = tmp_objdir_env(tmp_objdir);

#include "commit-reach.h"
	return 1;
	struct iterate_data *data = cb_data;
			strbuf_addf(&fsck_msg_types, "%c%s=%s",

					   &err)) {
	the_hash_algo->init_fn(&ctx);
	if (status)
	   "To squelch this message, you can set it to 'refuse'.");
	}
	if (!argv[0])
		      const char *text, size_t text_len)
	if (!push_cert.len)

				use_sideband = LARGE_PACKET_MAX;
		show_ref("capabilities^{}", &null_oid);
	}
				push_cert.len - bogs, &sigcheck);
				refuse_unconfigured_deny();
}
	the_hash_algo->final_fn(out, &ctx);
static int prefer_ofs_delta = 1;
			ret = poll(&pfd, 1, 1000 * keepalive_in_sec);
			break;
		string_list_clear(&push_options, 0);
		return 0;
			      struct string_list *options)
				if (reader->status == PACKET_READ_FLUSH) {
	DENY_REFUSE,
	struct strbuf namespaced_name_buf = STRBUF_INIT;
			struct pollfd pfd;
		}


};
	else {
#include "builtin.h"
	const struct worktree *worktree = is_bare_repository() ? NULL : find_shared_symref("HEAD", name);

	   "arranged to update its work tree to match what you pushed in some\n"
		const char *eol = strchrnul(line, '\n');
		}
}

	status = run_and_feed_hook(hook_name, feed_receive_hook, &state);

}
			argv_array_push(&child.args, "--report-end-of-input");
	}
	for_each_ref(show_ref_cb, &seen);
	the_hash_algo->final_fn(out, &ctx);
static int receive_fsck_objects = -1;
			if (!start_command(&proc)) {
		if (use_sideband)
		"read-tree", "-u", "-m", NULL, NULL
	cmd->error_string = dst_cmd->error_string =
	proc.trace2_hook_name = hook_name;
static int deny_non_fast_forwards;
			shallow_update = 0;
		}
	for (i = 0; i < si->shallow->nr; i++) {


	return retval;
			if (nonce_status == NONCE_SLOP)
static int advertise_push_options;
			break;
		if (!cmd->error_string)


static int auto_update_server_info;
	}
#include "string-list.h"
	if (deny_non_fast_forwards && !is_null_oid(new_oid) &&
			argv_array_push(&child.args, "--fix-thin");
	free(nonce);
	int len = push_cert.len;
		goto leave;
		int bogs /* beginning_of_gpg_sig */;
	if (!sent_capabilities)
					 push_cert_nonce);
		memset(&muxer, 0, sizeof(muxer));
}
				    struct shallow_info *si)
			    && parse_feature_request(feature_list, "atomic"))
			oidclr(&push_cert_oid);

	while (cmd &&
		}
					 cmd->ref_name);
		argv_array_pushf(&proc->env_array, "GIT_PUSH_CERT_KEY=%s",
	struct command *dst_cmd;
		strbuf_addf(&fsck_msg_types, "%cskiplist=%s",
		child.no_stdout = 1;

		git_dir = get_git_dir();
	the_hash_algo->update_fn(&ctx, text, text_len);
	/* RFC 2104 2. (2) & (5) */
	} else if (!push_cert_nonce) {
		already_done = 1;
				break;

	if (options_seen != push_options->nr)
	 * Make sure setup_alternate_shallow() for the next ref does
}
	unsigned char hash[GIT_MAX_RAWSZ];

		if (auto_gc) {

			strbuf_addf(&cap, " push-cert=%s", push_cert_nonce);

			copy_to_sideband(proc.err, -1, NULL);
	}

		*bufp = state->buf.buf;
{
	return finish_command(&proc);
		return 0;
			    ? transfer_fsck_objects
		else

	}
	strbuf_addf(&namespaced_name_buf, "%s%s", get_git_namespace(), name);
		rp_error("%s", err.buf);
				feed_state->push_options->items[i].string);
		}
				report_status = 1;


	argv[0] = find_hook("update");
}
			return code;
	child.argv = read_tree;
					break;
static const char *pack_lockfile;
	}
				else
					true_flush = 1;
static int command_singleton_iterator(void *cb_data, struct object_id *oid)
	struct string_list_item *item;
	if (use_sideband) {
	if (strcmp(var, "receive.keepalive") == 0) {
	N_("git receive-pack <git-dir>"),
static struct tmp_objdir *tmp_objdir;
	assign_shallow_commits_to_refs(si, NULL, ref_status);
static void warn_if_skipped_connectivity_check(struct command *commands,
				static const char buf[] = "0005\1";
		if (cmd->error_string)
		 */
	 */
		return 0;

	int i;
	packet_buf_flush(&buf);
				 &push_options);
	while ((option = find_header(buf, len, "push-option", &next_line))) {
static void rp_warning(const char *err, ...)

#include "tag.h"

	struct option options[] = {
	reflen = linelen - (p - line);
		if (!in_merge_bases(old_commit, new_commit)) {
static const char *push_cert_nonce;
			return 0;
	case protocol_unknown_version:
		pack_lockfile = index_pack_lockfile(child.out);
	refname = p;
		return 0;

static void rp_error(const char *err, ...)
		if (!check_connected(command_singleton_iterator, &singleton,
			si->need_reachability_test[i] > 1;
}
	the_hash_algo->update_fn(&ctx, k_ipad, sizeof(k_ipad));
		cmd->error_string = update(cmd, si);


			read_push_options(&reader, &push_options);
	va_end(params);
		xwrite(2, msg, sz);
		cmd->error_string = update(cmd, si);
				fsck_msg_types.len ? ',' : '=', var, value);
		if (options_seen > push_options->nr

		return unpack(0, si);

{
	 * In stateless mode, we may be receiving a nonce issued by
			check_aliased_update(cmd, &ref_list);
		 * so just fall through after writing the version string.

	struct command *cmd;
	}


			break;
			strbuf_reset(&err);
		execute_commands_non_atomic(commands, si);
	oid_array_clear(&shallow);

	if (!stateless_rpc) {
		finish_async(&muxer);

		return -1; /* end of list */


	/* diff-index with either HEAD or an empty tree */
		for (cmd = commands; cmd; cmd = cmd->next) {
	for (i = 0; i < si->shallow->nr; i++)
		 find_unique_abbrev(&cmd->new_oid, DEFAULT_ABBREV),
}
	if (ntohl(hdr.hdr_entries) < unpack_limit) {
{
	if (strcmp(var, "receive.certnonceslop") == 0) {
{
		      const char *key_in, size_t key_len,
	dst_name = strip_namespace(dst_name);

	return retval;
	return 0;

	}
	}
	if (use_sideband)
	ALLOC_ARRAY(si->used_shallow, si->shallow->nr);

	FLEX_ALLOC_MEM(cmd, ref_name, refname, reflen);
{
{
	return 0;
	packet_flush(1);
	 * skewed in the future.
	KEEPALIVE_ALWAYS
static const char *push_to_deploy(unsigned char *sha1,
		if (!parse_object(the_repository, old_oid)) {
	};
	switch (determine_protocol_version_server()) {
}

	if (feed_receive_hook(&state, NULL, NULL))
	if (push_cert.len)
}
	int options_seen = 0;

		memset(&muxer, 0, sizeof(muxer));
		retval = NONCE_MISSING;
	if (strcmp(var, "receive.denynonfastforwards") == 0) {
	if (!path) {
}
		return NULL;
	child.env = env->argv;
	advertise_shallow_grafts(1);
	 */
			reader->options = saved_options;
{
				(uintmax_t)max_input_size);
		nonce_stamp_slop_limit = git_config_ulong(var, value);
	struct command *commands = NULL;
	/*

	struct child_process proc = CHILD_PROCESS_INIT;
		if (write_in_full(proc.in, buf, n) < 0)
}

			fsck_msg_types.len ? ',' : '=', path);
		}
		 find_unique_abbrev(&cmd->old_oid, DEFAULT_ABBREV),

	const char *ret;
		keepalive_active = 1;


	struct command **p = &commands;
	}
		ret = update_worktree(new_oid->hash, find_shared_symref("HEAD", name));


	child.env = env->argv;
			      push_options->items[options_seen - 1].string)) {
};
			default:

		prepare_shallow_info(&si, &shallow);
{
	return retval;
#include "run-command.h"
	const char *reported_error = "atomic push failure";
		oid_array_clear(&extra);
			error("bad sha1 objects for %s", name);
	else
}
{
	}
			/* to be checked in update_shallow_ref() */
static struct command *read_head_info(struct packet_reader *reader,
	struct oidset *seen = data;
static void refuse_unconfigured_deny(void)
			continue;
	strbuf_release(&err);
		 */
			rp_error("refusing to update checked out branch: %s", name);
	if (!tmp_objdir) {
}
		const char *path;
static int receive_unpack_limit = -1;
	if (!proc.args.argc)
		if (code)

	proc.err = use_sideband ? -1 : 0;
		/*
			close_object_store(the_repository->objects);
		if (use_keepalive == KEEPALIVE_AFTER_NUL && !keepalive_active) {
			if (ret < 0) {
		ssize_t sz;
	proc.no_stdin = 1;
		goto leave;


		if (deny_deletes && starts_with(name, "refs/heads/")) {
		return status;
		advertise_atomic_push = git_config_bool(var, value);
	int advertise_refs = 0;
	sz = xsnprintf(msg, sizeof(msg), "%s", prefix);
			continue;
		child.git_cmd = 1;
 * now.
static int run_update_hook(struct command *cmd)
		code = start_async(&muxer);

}
	if (use_sideband)
			 unpack_status ? unpack_status : "ok");
			rp_error("denying ref deletion for %s", name);
	for_each_alternate_ref(show_one_alternate_ref, &seen);
	struct strbuf refname_full = STRBUF_INIT;
		 * in "ours" list aka "step 7 not done yet"
		free(option);
	if (!dst_name) {
		if (!is_null_oid(&cmd->new_oid))
			    : transfer_fsck_objects >= 0

		/* returned nonce MUST match what we gave out earlier */
	strbuf_release(&err);
		goto leave;
		}
	sigchain_push(SIGPIPE, SIG_IGN);
		si->need_reachability_test[si->ours[i]] = 1;
}
		return;

		xcalloc(si->shallow->nr, sizeof(*si->need_reachability_test));
	const char *hook;
			argv_array_pushf(&child.args, "--strict%s",
static int keepalive_in_sec = 5;
		if (reader->pktlen > 8 && starts_with(reader->line, "shallow ")) {
	git_config(receive_pack_config, NULL);
static int delete_only(struct command *commands)
	}
		 * Either we're not looking for a NUL signal, or we didn't see
	N_("By default, updating the current branch in a non-bare repository\n"
	char ref_name[FLEX_ARRAY]; /* more */
	}
	}
	child.argv = diff_files;
	for (cmd = commands; cmd; cmd = cmd->next) {
static int use_atomic;
		return code;
		nonce_status = check_nonce(push_cert.buf, bogs);


	if (use_sideband)
	struct object_id *new_oid = &cmd->new_oid;
	 * refs, so that the client can use them to minimize data
		}
	unsigned char k_opad[GIT_MAX_BLKSZ];


			if (advertise_atomic_push
/*
{
		proc.err = muxer.in;
	if (code) {
	int key_len = strlen(key);
		if (advertise_refs || !stateless_rpc)
	child.stdout_to_stderr = 0;
 * after dropping "_commit" from its name and possibly moving it out
	}
{
		argv_array_push(&child.args, "unpack-objects");
	}
				      const char *line,
	 * another instance of the server that serving the same
	if (argc > 1)


	proc.trace2_hook_name = "post-update";
	state.skip_broken = skip_broken;

	 * command. check_connected() will be done with
				struct oid_array *ref)
	nonce_stamp_slop = (long)ostamp - (long)stamp;

		cmd->error_string = "missing necessary objects";

				finish_command(&proc);
			break;
static void prepare_shallow_update(struct shallow_info *si)
		size_t n;
	}
			cmd->error_string = "failed to update ref";

			si->need_reachability_test[i]++;
		case DENY_REFUSE:
	child.git_cmd = 1;


		"diff-index", "--quiet", "--cached", "--ignore-submodules",
static int deny_deletes;
{
			for (k = 0; k < 32; k++)
static int auto_gc = 1;
	 */
{
#include "refs.h"
	}
	struct command *cmd;
		retval = push_to_deploy(sha1, &env, work_tree);
		}
			if (!cmd->error_string)
	/*
	int code;
		if (auto_update_server_info)
	string_list_clear(&ref_list, 0);
	rp_error("%s", _(refuse_unconfigured_deny_delete_current_msg));
	}
 * NEEDSWORK: reuse find_commit_header() from jk/commit-author-parsing
			}
		if (!si.nr_ours && !si.nr_theirs)
		return NULL; /* good */
		git_dir = get_worktree_git_dir(worktree);

		else
	}
	const char *name = cmd->ref_name;
			if (advertise_push_options
		if (use_sideband)
	state.push_options = push_options;
	struct command *cmd;
	const struct string_list *push_options;


		rp_error("refusing update to broken symref '%s'", cmd->ref_name);
		strbuf_addf(&cap, " agent=%s", git_user_agent_sanitized());
/*
				/* no data; send a keepalive packet */
		OPT_HIDDEN_BOOL(0, "reject-thin-pack-for-testing", &reject_thin, NULL),
failure:

			argv_array_push(&proc.args, hook);
				continue;
		}
static int iterate_receive_command_list(void *cb_data, struct object_id *oid)
	const char *buf = push_cert.buf;
		if (!cmd->error_string)
		retval = 0;
		return 0;
	tmp_objdir = NULL;
	}
		return NULL;
		set_connectivity_errors(commands, si);
		case DENY_UNCONFIGURED:
	struct receive_hook_feed_state state;

	state->cmd = cmd->next;
		item->util = (void *)cmd;
	if (sent_capabilities) {
	struct string_list ref_list = STRING_LIST_INIT_NODUP;
	code = start_command(&proc);
		status = start_command(&child);
	   "is denied, because it will make the index and work tree inconsistent\n"
			for (cmd = commands; cmd; cmd = cmd->next)
	case PH_ERROR_PROTOCOL:
static void hmac(unsigned char *out,

{
		use_keepalive = KEEPALIVE_ALWAYS;
	cmd->skip_update = 1;
	if (ref_transaction_commit(transaction, &err)) {
	}

			break;
	stamp = parse_timestamp(nonce, &bohmac, 10);
}
		finish_async(&muxer);
			for (;;) {
		"diff-files", "--quiet", "--ignore-submodules", "--", NULL
}
		retval = NONCE_BAD;

	}
	struct async muxer;

		BUG("unknown protocol version");

	else
		 dst_cmd->ref_name,
		     did_not_exist:1;
{



					continue;
	msg[sz++] = '\n';

	}
	rp_error("refusing inconsistent update between symref '%s' (%s..%s) and"
	while (1) {

		line = *eol ? eol + 1 : NULL;
		if (packet_reader_read(reader) != PACKET_READ_NORMAL)


		the_hash_algo->update_fn(&ctx, key_in, key_len);
		cmd->index = ref->nr - 1;

		execute_commands(commands, unpack_status, &si,
	if (cert_nonce_seed)
					   namespaced_name,
	if (advertise_refs || !stateless_rpc) {
	}
		max_input_size = git_config_int64(var, value);
		new_commit = (struct commit *)new_object;
		struct strbuf err = STRBUF_INIT;
	const char *next_line;
		packet_write_fmt(1, "%s %s%c%s\n",
	if (!is_null_oid(old_oid) && is_null_oid(new_oid)) {
	if (start_async(&muxer))
		if (!start_async(&muxer))
	if (strcmp(var, "receive.denydeletes") == 0) {
	if (run_command(&child))
			cmd->error_string = "unpacker error";
	data.si = si;
		sent_capabilities = 1;

	struct oid_array shallow = OID_ARRAY_INIT;
				 feed_state->push_options->nr);
	if (strcmp(var, "transfer.fsckobjects") == 0) {
		case DENY_WARN:
	return !cmd->error_string && !cmd->skip_update;
		}

	muxer.proc = copy_to_sideband;
					   0, "push", &err)) {

					  const char *dst_name, int flag)
	finish_async(&muxer);
static const char *check_nonce(const char *buf, size_t len)
	}
}
		auto_gc = git_config_bool(var, value);
static struct strbuf push_cert = STRBUF_INIT;
	 * as if we issued that nonce when reporting to the hook.
		rp_error("refusing to create funny ref '%s' remotely", name);
	ret = unpack(muxer.in, si);
		if (err_fd > 0)
			if (!cmd->error_string)
	proc.stdout_to_stderr = 1;
	}
			packet_buf_write(&buf, "ok %s\n",
	DENY_UPDATE_INSTEAD
	timestamp_t stamp, ostamp;
	goto cleanup;
}
	size_t prefix_len;

	    parse_oid_hex(p, &new_oid, &p) ||
		return 0;

	if (!cmd)
struct iterate_data {
	if (!argv[0])
	child.no_stdout = 1;
	if (oidset_insert(seen, oid))
		return 0;
	strbuf_addf(&state->buf, "%s %s %s\n",


		sz = sizeof(msg) - 1;
	va_start(params, err);
	read_tree[3] = hash_to_hex(sha1);
		return;
static timestamp_t nonce_stamp_slop_limit;
				if (use_sideband)
 * the same as those in the argument; 0 otherwise.
	struct command *cmd;
		int linelen;
	prepare_push_cert_sha1(&proc);
static int feed_receive_hook(void *state_, const char **bufp, size_t *sizep)
		if (shallow_update && si->shallow_ref[cmd->index])
{
	strbuf_release(&buf);
}
	if (strcmp(var, "receive.fsck.skiplist") == 0) {
	unsigned int skip_update:1,
#include "oidset.h"
	char *bohmac, *expect = NULL;
	 * to be in their final positions so that other processes can see them.
#include "worktree.h"
			oid_array_append(shallow, &oid);
static int transfer_fsck_objects = -1;
		strbuf_setlen(&refname_full, prefix_len);

		muxer.proc = copy_to_sideband;
		if (advertise_push_options)

	return 0;
				     struct strbuf *push_cert)
		    new_object->type != OBJ_COMMIT) {
		if (!delete_only(commands)) {

		return 0;
		    oid_to_hex(&cmd->old_oid), oid_to_hex(&cmd->new_oid),
	child.no_stdout = 1;
#include "pack.h"
{
{
	if (use_sideband)
		if (cmd->error_string || cmd->did_not_exist)
			case DENY_IGNORE:
		if (prefer_ofs_delta)
			    ? receive_fsck_objects
		}
	const char *diff_files[] = {
				 */
	struct command *commands;
static int sent_capabilities;
static int update_shallow_ref(struct command *cmd, struct shallow_info *si)
			rp_warning("updating the current branch");
			return "index-pack abnormal exit";
	}
		if (packet_reader_read(reader) != PACKET_READ_NORMAL)
					die("protocol error: got an unexpected packet");
	/* EOF */
	}

	NULL
static void prepare_push_cert_sha1(struct child_process *proc)
static const char *nonce_status;


}
				   void *data)
		struct commit *old_commit, *new_commit;
	oidset_clear(&seen);

	}
			rp_error("denying non-fast-forward %s"
	    starts_with(name, "refs/heads/")) {
		write_head_info();

				 * with it.
	prefix_len = refname_full.len;
	   "\n"

	child.dir = work_tree;
		return 0;
	}


				if (deny_delete_current == DENY_UNCONFIGURED)
		 */

				 sigcheck.result);
	/*
		if (write_object_file(push_cert.buf, push_cert.len, "blob",
		oidset_insert(seen, oid);
	if (*nonce <= '0' || '9' < *nonce) {
		struct strbuf err = STRBUF_INIT;
	for (i = 0; i < sizeof(key); i++) {
static const char *head_name;
			cmd->error_string = "transaction failed to start";
		the_hash_algo->init_fn(&ctx);
			do_update_worktree = 1;
		}
}
		finish_command(&proc);
	} else {
	for (;;) {

			return xmemdupz(line + offset, (eol - line) - offset);
#include "tmp-objdir.h"
		free((char *)path);
		argv_array_pushf(&proc->env_array, "GIT_PUSH_CERT_SIGNER=%s",
	const char *retval, *work_tree, *git_dir = NULL;
		return;
	int skip_broken;
	struct command *cmd;
	 */

 * of commit.c
		rollback_lock_file(&shallow_lock);
	}
	} else {
	};



		if (status)
		opt.env = tmp_objdir_env(tmp_objdir);

	if (shallow_update)


static char *refuse_unconfigured_deny_delete_current_msg =
	struct command *cmd;
	const char *retval = NONCE_BAD;

	 * env variable because we can't add --shallow-file to every
{

					break; /* end of cert */
static int report_status;

		error("unpack should have generated %s, "
			 "shallow: update_shallow_ref %s\n", cmd->ref_name);
{
		if (!should_process_cmd(cmd))
static void *head_name_to_free;
			break;
			strbuf_release(&err);
		if (quiet)
{
	if (worktree) {
		child.err = err_fd;
	dst_name = resolve_ref_unsafe(buf.buf, 0, NULL, &flag);
	/* only refs/... are allowed */
	proc.stdout_to_stderr = 1;
		retval = NONCE_BAD;

		}
			continue;
		goto leave;
				cmd->error_string = "unable to migrate objects to permanent storage";
}
	int checked_connectivity = 1;
	if (0 <= transfer_unpack_limit)
	for (cmd = commands; cmd; cmd = cmd->next) {
			int offset = key_len + 1;

	case PH_ERROR_PACK_SIGNATURE:
				 * The NUL tells us to start sending keepalives. Make
{
		argv_array_push(&child.args, alt_shallow_file);
	 * repository, and the timestamps may not match, but the
	struct receive_hook_feed_state *state = state_;
	int code;

	struct pack_header hdr;
{
	return strbuf_detach(&buf, NULL);
			return "deletion prohibited";
static enum deny_action parse_deny_action(const char *var, const char *value)
		rp_error("hook declined to update %s", name);
	memset(&muxer, 0, sizeof(muxer));
				cmd->error_string = "inconsistent push options";
	} else
			continue;

			rp_error("%s", err.buf);
	}
}
			return "unpack-objects abnormal exit";
static int unpack_limit = 100;
	si->shallow_ref[cmd->index] = 0;
	free(namespaced_name);
{
			}
	struct child_process proc = CHILD_PROCESS_INIT;
			continue;
			      cmd->ref_name);
	struct object_id old_oid, new_oid;
		argv_array_push(&child.args, "--shallow-file");
	if (!nonce) {
		argv_array_pushl(&child.args, "index-pack", "--stdin", NULL);
static int run_and_feed_hook(const char *hook_name, feed_fn feed,
		switch (deny_current_branch) {
			} else if (ret == 0) {

	const char *hdr_err;
		die("protocol error: got both push certificate and unsigned commands");

		copy_to_sideband(proc.err, -1, NULL);
	for (cmd = commands; cmd; cmd = cmd->next) {
		goto failure;
		if (ref_transaction_delete(transaction,
				strbuf_addstr(&push_cert, reader->line);
		 * Pretend as if the received nonce (which passes the
		argv_array_pushf(&proc.env_array, "GIT_PUSH_OPTION_COUNT");
	const char *boc, *eoc;
		}
} use_keepalive;
			cmd->error_string = reported_error;
		execute_commands_atomic(commands, si);
				    reader->line + 8);
			old_oid = NULL;
static const char *NONCE_SLOP = "SLOP";
static long nonce_stamp_slop;
	}
	for (cmd = commands; cmd; cmd = cmd->next) {
	struct check_connected_options opt = CHECK_CONNECTED_INIT;
	struct oid_array ref = OID_ARRAY_INIT;
		work_tree = "..";
	return commands;


	else if (git_work_tree_cfg)
	return git_default_config(var, value, cb);
 * NEEDSWORK: we should consolidate various implementions of "are we

	free(ref_status);
	if (check_connected(command_singleton_iterator, cmd, &opt)) {
		for (i = 0; i < feed_state->push_options->nr; i++)
		if (push_cert_nonce)

	strbuf_init(&state.buf, 0);
		return "eof before pack header was fully read";
				    const char *work_tree)
	va_start(params, err);
	if (!(flag & REF_ISSYMREF))
		if (fsck_objects)
		if (!ref_is_hidden(cmd->ref_name, refname_full.buf))
	 * not lose these new roots..
 * allow us to tell an unborn branch from corrupt ref, for example.
	ref_transaction_free(transaction);
	return -1; /* end of list */
		string_list_append(options, reader->line);

	if (sz > (sizeof(msg) - 1))

struct command {
	static struct oidset seen = OIDSET_INIT;
	if (the_hash_algo->blksz < key_len) {
		if (cmd->error_string)
				if (reader->status != PACKET_READ_NORMAL) {

	struct command *next;
			oid_array_append(&extra, &si->shallow->oid[i]);
		ref_transaction_free(transaction);
static enum deny_action deny_delete_current = DENY_UNCONFIGURED;
			goto leave;
		queue_commands_from_cert(p, &push_cert);


		if (err_fd > 0)
	proc.in = -1;
		const char *eol = memchr(boc, '\n', eoc - boc);
	if (keepalive_in_sec <= 0)
	int status;
		 * is what we issued.
	if (strcmp(var, "receive.autogc") == 0) {
	struct command *cmds;
static enum {
	if (use_keepalive == KEEPALIVE_ALWAYS)
{
		cmd = cmd->next;
#include "connected.h"
			unpack_status = unpack_with_sideband(&si);
	   "'git clone' won't result in any file checked out, causing confusion.\n"
	child.env = env->argv;
