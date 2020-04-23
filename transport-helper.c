static int tloop_spawnwait_tasks(struct bidirectional_transfer_state *s)
	if (push_update_refs_status(data, remote_refs, flags))

		if (flags & TRANSPORT_PUSH_DRY_RUN || !data->rs.nr || data->no_private_update)
	for (;;) {
	int v = t->verbose;
		return transport->vtable->fetch(transport, nr_heads, to_fetch);
	ret |= tloop_join(pid1, "Git to program copy");
					/* Follow symbolic refs (mainly for HEAD). */
					strbuf_addf(&buf, ":%s", ref->name);
	 */
			 !strcmp(buf.buf, "connectivity-ok"))
	struct strbuf buf = STRBUF_INIT;
		debug = 1;
	ssize_t bytes;
		refname = buf->buf + 3;

	if (!data->rs.nr)
	else {
	if (STATE_NEEDS_CLOSING(t->state) && !t->bufuse) {
			    posn->symref ? posn->symref : posn->name);
	free(data);
	 */

static int run_connect(struct transport *transport, struct strbuf *cmdbuf)


	fclose(input);
		if (debug)
	for (ref = remote_refs; ref; ref = ref->next) {
		return push_refs_with_export(transport, remote_refs, flags);
static int get_exporter(struct transport *transport,
	if (data->helper)
	/*
	FILE *out;
	}
	err = pthread_create(&gtp_thread, NULL, udt_copy_task_routine,
		int mandatory = 0;
		quote_c_style(value, &buf, NULL, 0);
	for (i = 0; i < ARRAY_SIZE(boolean_options); i++) {
		status = REF_STATUS_REMOTE_REJECT;
	}
	int src_is_sock;
			sigchain_pop(SIGPIPE);
	state.gtp.dest = output;
 * process (for error messages). Returns 0 on success, 1 on failure.
}
			if (ref->peer_ref)
{
	helper->git_cmd = 0;
	int err;
		break;
static int push_refs(struct transport *transport,
			t->src_name, (int)t->bufuse);
}
	pid_t pid1, pid2;
	} else if (!strcmp(cmdbuf->buf, "fallback")) {
		if (!buf.len)
	struct helper_data *data = transport->data;
static struct transport_vtable vtable = {
	if (data->helper) {
	if (t->bufuse == BUFFERSIZE)
	int state;
		else if (!strcmp(msg, "stale info")) {
		shutdown(t->dest, SHUT_WR);
		else
	int ret = 0;
	if (err) {
			continue;
		if (!*buf.buf)
		} else if (skip_prefix(capname, "export-marks ", &arg)) {
			 * since we're about to close the pipe anyway. And the

			warning(_("setting remote service path not supported by protocol"));
	int err;
	/* These go from remote name (as in "list") to private name */
/* Stream state: Transfer in this direction finished. */
	struct helper_data *data = transport->data;
{
{
 * identity filter.
	state.gtp.src_name = "stdin";
	if (bytes < 0) {

	return ret;
	struct ref *ret = NULL;
{
		 * do not break old remote helpers by setting "all" here

			}
	get_helper(transport);
		transfer_debug("Closed %s.", t->dest_name);


		return transport->vtable->get_refs_list(transport, for_push, ref_prefixes);

	state.ptg.dest = 1;
	if (flags & TRANSPORT_PUSH_FORCE) {
		if (set_helper_option(transport, TRANS_OPT_PUSH_CERT, "true") != 0)
	data = (struct helper_data *)transport->data;
static void *udt_copy_task_routine(void *udt)
	TRANS_OPT_KEEP,

		ret = 1;

			string_list_append_nodup(&revlist_args,
}
		return 1;
static int push_update_refs_status(struct helper_data *data,
	}
	strbuf_addf(&buf, "option %s ", name);
		private = apply_refspecs(&data->rs, ref->name);
	if (flags & TRANSPORT_PUSH_DRY_RUN) {

			continue;
			    int nr_heads, struct ref **to_fetch)
#include "run-command.h"
	} else {
	struct strbuf buf = STRBUF_INIT;
static int process_connect(struct transport *transport,
	for (i = 0; i < list->nr; i++) {
			continue;
#define STATE_NEEDS_WRITING(state) ((state) <= SSTATE_FLUSHING)
	}
	struct helper_data *data = transport->data;
	struct strbuf buf = STRBUF_INIT;
					 struct string_list *list)
	/* Destination */
	write_constant(data->helper->in, "\n");
 */
			capname = buf.buf;
	helper = get_helper(transport);
		return 1;
	struct helper_data *data = transport->data;
			warning(_("invalid remote service path"));
			 * to report an error itself.
	if (duped < 0)
	case TRANSPORT_FAMILY_IPV4:
		argv_array_pushf(&fastimport->args, "--cat-blob-fd=%d", cat_blob_fd);
		}

	}
		else if (!strcmp(msg, "fetch first")) {
	 *
}

static int tloop_join(pthread_t thread, const char *name)
		do_take_over(transport);

		return 0;
		warning("Ignoring --negotiation-tip because the protocol does not support it.");
	child_process_init(fastimport);
	}

	if (!strcmp(name, "deepen-not"))
	struct child_process *helper = get_helper(transport);
		status = REF_STATUS_OK;
	return 0;
			    capname);
		if (!eov)
{


	set_helper_option,


		warning(_("this remote helper should implement refspec capability"));
 * Tries to read data from source into buffer. If buffer is full,
					    int for_push)
		die(_("unable to find remote helper for '%s'"), data->name);
		}
		*msg++ = '\0';
	state.gtp.src = 0;
#include "sigchain.h"
	strbuf_release(&buf);

		return 0;	/* Nothing to write. */
static int tloop_join(pid_t pid, const char *name)
/*
	if (write_in_full(fd, str, strlen(str)) < 0)
};
 */
	 * on it.
#include "string-list.h"
		if (status == REF_STATUS_NONE)
}
		}
	if (data->check_connectivity &&
	if (!attrs)
		case REF_STATUS_REJECT_STALE:
		    cmdbuf->buf);
		 * Earlier, the ref was marked not to be pushed, so ignore the ref
			transport->stateless_rpc = 1;
		die(_("operation not supported by protocol"));
	/*
	if (data->bidi_import) {
		return 1;
{

	for (i = 0; i < nr_heads; i++) {
 * Spawn the transfer tasks and then wait for them. Returns 0 on success,
	child_process_init(fastexport);

		const char *name;
	}
				strbuf_release(&buf);
				    struct strbuf *buf)
	 */

	struct helper_data *data = transport->data;
}
		t->state = SSTATE_FINISHED;
{
	/* Fork thread #2: program to git. */
			data->transport_options.self_contained_and_connected = 1;
	/* Buffer used. */
	/* Direction from git to program. */
	for (i = 0; i < nr_heads; i++) {
					name = resolve_ref_unsafe(ref->peer_ref->name,
			if (ref->force)
	for (;;) {
	 */
	 * remote-helpers that advertise the bidi-import capability are required to
	pid1 = fork();
	 * functions can be used.
{

	(*ref)->status = status;
	if (process_connect(transport, 0)) {
						 strbuf_detach(&cas, NULL));

		if (!strcmp(name, unsupported_options[i]))
				(*tail)->status |= REF_STATUS_UPTODATE;
}
	t->state = SSTATE_FINISHED;
		const char *end;
		else if (!buf.len)
			status = REF_STATUS_REJECT_ALREADY_EXISTS;
{

		transfer_debug("%s EOF (with %i bytes in buffer)",
	if (data->import)
 */
		if (STATE_NEEDS_CLOSING(t->state))

	va_start(args, fmt);
		if (STATE_NEEDS_READING(t->state))
		/* Check for statuses set by set_ref_status_for_push() */
	} else if (bytes > 0) {
		set_helper_option(transport, "update-shallow", "true");
			shutdown(t->dest, SHUT_WR);
				string_list_append(&revlist_args, "--refspec");
		return 1;

{
		}
		else if (!strcmp(msg, "up to date")) {

 * Additionally filtering through given filter. If filter is NULL, uses
	}
static int get_importer(struct transport *transport, struct child_process *fastimport)


				return NULL;
#include "diff.h"
	if (debug)
	struct helper_data *data = transport->data;
	return !(status == REF_STATUS_OK);
	}
		}
	int res = 0;
	if (process_connect(transport, for_push)) {
		if (!unquote_c_style(&msg_buf, msg, &end))
static int has_attribute(const char *attrs, const char *attr)
		if (colon && colon[1] == ':')

		die(_("error while running fast-export"));
	TRANS_OPT_FOLLOWTAGS,
		fclose(data->out);
	/*
#include "remote.h"
			&data->transport_options.filter_options);
		string_list_clear(&cas_options, 0);
/* Tries to write data from buffer into destination. If buffer is empty,
 */

	struct helper_data *data;
	else if (pid1 == 0) {
static int connect_helper(struct transport *transport, const char *name,
	get_helper(transport);

			data->option = 1;
	struct helper_data *data = transport->data;
		strbuf_addf(&buf, "import %s\n",
#define STATE_NEEDS_CLOSING(state) ((state) == SSTATE_FLUSHING)

	}

	int i;
		import : 1,
		eon = strchr(eov + 1, ' ');
			     int nr_heads, struct ref **to_fetch)
	 * support connect or stateless_connect, we need to invoke
			exit(128);
	 * Do this with duped fd because fclose() will close the fd,
}
		if (ref->expect_old_sha1) {
	helper = get_helper(transport);
	ret |= tloop_join(ptg_thread, "Program to git copy");
			struct strbuf cas = STRBUF_INIT;
		else if (skip_prefix(capname, "refspec ", &arg)) {
	return ret;
	code = start_command(fastimport);
		die(_("can't start thread for copying data: %s"), strerror(err));
	connect_helper,
		} else
	helper->out = -1;
	return recvline_fh(helper->out, buffer);
		}
		}
	return udt;	/* Just some non-NULL value. */
		return 1;
#else
				continue;
	/* we need to duplicate helper->in because we want to use it after
		if (recvline(data, &buf))
	}

		if (!strcmp(capname, "fetch"))
	ssize_t bytes;
{
	return code;
	char *export_marks;

}
			die(_("malformed response in ref list: %s"), buf.buf);

	 * stream buffering only can be changed before first I/O operation
		char *eov, *eon;
	return 0;
static int udt_do_read(struct unidirectional_transfer *t)
	data->out = xfdopen(duped, "r");
		for_each_string_list_item(item, transport->push_options)
	 */
			warning(_("%s unexpectedly said: '%s'"), data->name, buf.buf);
	count = 0;
	}
	 * terminal, populate FETCH_HEAD, and determine what new value
	 * be mixed with import commands, otherwise.
		 * the ref->old_oid_expect[] field; we can ignore
			is_bool = 1;
		if (STATE_NEEDS_WRITING(t->state))
	struct child_process *helper;
{
				     int for_push)
			break;
		private = apply_refspecs(&data->rs, ref->name);

		FREE_AND_NULL(data->helper);
}
			return 1;
		error(_("%s thread failed to join: %s"), name, strerror(err));

	if (debug)
	write_constant(helper->in, "export\n");
			struct child_process *fastexport,
	}

						name = ref->peer_ref->name;
		return 0;
	xsnprintf(buf, sizeof(buf), "%d", v + 1);
		   const char *exec, int fd[2])
		error_errno(_("%s process failed to wait"), name);
	else if (starts_with(buf->buf, "error"))
	return get_refs_list_using_list(transport, for_push);
	transport->smart_options = &(data->transport_options);
	TRANS_OPT_THIN,
			status = REF_STATUS_UPTODATE;
			fprintf(stderr, "Debug: Smart transport connection "
}
	return ret;
	if (err)
	int i;
int bidirectional_transfer_loop(int input, int output)
	if (data->transport_options.update_shallow)

		 * status reported by the remote helper if the latter is 'no match'.
	FILE *input;
/* This should be enough to hold debugging message. */
/*
		resolve_remote_symref(posn, ret);
	int ret = 0;
	argv_array_push(&helper->args, transport->remote->name);

	return ret;


			FREE_AND_NULL(msg);
};
	}
{
				string_list_append(&revlist_args, buf.buf);
};


			exit(128);
	struct unidirectional_transfer gtp;
	refspec_init(&data->rs, REFSPEC_FETCH);
	/* Transport options for fetch-pack/send-pack (should one of
	set_helper_option(t, "verbosity", buf);
	 * have SHUT_RD)...
								  RESOLVE_REF_READING,

				die(_("could not read ref %s"), private);
	if (data->transport_options.negotiation_tips)
static void standard_options(struct transport *t)
	else
		strbuf_addf(&buf, "option %s ", name);
		}
		die(_("remote-helper doesn't support push; refspec needed"));
		no_disconnect_req : 1,
	}
		if ((ret = strbuf_set_helper_option(data, &buf)))
			data->export = 1;
	/* Name of destination. */

	int i, ret, is_bool = 0;
	set_helper_option(t, "progress", t->progress ? "true" : "false");
	else if (!strcmp(buf->buf, "unsupported"))
	} else if (flags & TRANSPORT_PUSH_CERT_IF_ASKED) {
	return data->helper;
			count++;
		die(_("can't connect to subservice %s"), name);
	}
int transport_helper_init(struct transport *transport, const char *name)

		do_take_over(transport);
		if (!data->no_disconnect_req) {
		strbuf_release(&buf);
	return res;
	 * of input pipe as FILE*. fclose() closes the underlying fd and
	state.ptg.state = SSTATE_TRANSFERRING;
		die(_("unknown response to connect: %s"),
	return -1;
		t->state = SSTATE_FLUSHING;
	} else if (bytes > 0) {
	code = start_command(helper);



	else
		if (len == space - attrs && !strncmp(attrs, attr, len))
	(*ref)->remote_status = msg;
			string_list_append_nodup(&cas_options,
		strbuf_addstr(&buf, "push ");
			memmove(t->buf, t->buf + bytes, t->bufuse);

			/*
			fprintf(stderr, "Debug: Remote helper quit.\n");
	if (data->fetch)
		error(_("%s process failed"), name);
	else if (code != 0)
	if (flags & TRANSPORT_PUSH_OPTIONS) {
	refspec_clear(&data->rs);
		update_ref("update by helper", private, &ref->new_oid, NULL,
		write_str_in_full(helper->in, "list\n");
	/* Direction from program to git. */

	 * the "refspec" capability writes to the refs named after the
			struct string_list *revlist_args)
		fprintf(stderr,
	if (!t->src_is_sock)
	if (err)
	strbuf_addch(&buf, '\n');
			data->import = 1;
		return transport->vtable->push_refs(transport, remote_refs, flags);
		if (ret)
	if (bytes < 0) {
static int recvline(struct helper_data *helper, struct strbuf *buffer)

	ret = strbuf_set_helper_option(data, &buf);
	set_common_push_options(transport, data->name, flags);
	case TRANSPORT_FAMILY_ALL:
	TRANS_OPT_DEEPEN_RELATIVE
	else
}
			 */

	strbuf_release(&cmdbuf);

	int dest_is_sock;

				} else
					int flag;
	}
				transport->pack_lockfile = xstrdup(name);
	fastexport->git_cmd = 1;
	fclose(data->out);
	helper->silent_exec_failure = 1;
		else
			fprintf(stderr, "Debug: Got cap %s\n", capname);
			return colon + 2;
	}
 */
	 * (If no "refspec" capability was specified, for historical
	size_t bufuse;
		get_refs_list_using_list(transport, 0);
		signed_tags : 1,
 */
	}
	/*


		 */
	return ret;
	/* Transfer state (TRANSFERRING/FLUSHING/FINISHED) */
		if (t->bufuse)
static const char *unsupported_options[] = {
		fprintf(stderr, "Debug: Read ref listing.\n");
	} else if (bytes == 0) {
	if (get_importer(transport, &fastimport))
#include "refs.h"

		struct ref *remote_refs, int flags)
	return start_command(fastexport);

 */
		die_errno(_("can't dup helper output fd"));
		   !strcmp("git-upload-pack", name)) {
			oidcpy(&ref->old_oid, &oid);
/* Unidirectional transfer. */

		/*
static void do_take_over(struct transport *transport)
		return 0;	/* No space for more. */
		set_helper_option(t, "family", "ipv4");
	 * get_refs_list ourselves if we haven't already done so. Keep track of
	int mirror = flags & TRANSPORT_PUSH_MIRROR;
}
	return 0;
	if (for_push)
		close(t->dest);
		if (push_update_ref_status(&buf, &ref, remote_refs))
	struct helper_data *data = xcalloc(1, sizeof(*data));
		udt_kill_transfer(&s->gtp);
			 * Ignore write errors; there's nothing we can do,
	return 0;

		strbuf_addf(&cmdbuf, "connect %s\n", name);
{

	while (1) {
	struct child_process *helper, exporter;
		*eov = '\0';
	 * Store the result in to_fetch[i].old_sha1.  Callers such

			data->connect = 1;
	if (msg) {
	return ret;
		 * can enumerate them from the refs.
	struct ref *ref = remote_refs;
		quote_c_style(list->items[i].string, &buf, NULL, 0);
	 */

				return 0;
static int fetch_with_fetch(struct transport *transport,
	 */
		export : 1,

}
		case REF_STATUS_REJECT_NONFASTFORWARD:
	(*ref)->forced_update |= forced;
{
	data->get_refs_list_called = 1;
	sendline(data, cmdbuf);
			free(private);
	unsigned get_refs_list_called : 1;
	int i, count;
		/* propagate back the update to the remote namespace */
	if (url) {

}
	if (starts_with(buf->buf, "ok ")) {
	if (recvline(data, buf))
static int disconnect_helper(struct transport *transport)
		refname = buf->buf + 6;
		struct string_list_item *item;
static int udt_do_write(struct unidirectional_transfer *t)
	if (finish_command(&fastimport))
		/*
		if (posn->status & REF_STATUS_UPTODATE)
		return 1;
}
	}
				string_list_append(&revlist_args, ref->peer_ref->name);
			break;

	char buf[16];

}

static void udt_close_if_finished(struct unidirectional_transfer *t)
{
		return push_refs_with_push(transport, remote_refs, flags);
/* Print bidirectional transfer loop debug message. */
{
	 * task would first close the socket it sends data to
	struct strbuf buf = STRBUF_INIT;
	 * Socket read end left open isn't a disaster if nobody
static int recvline_fh(FILE *helper, struct strbuf *buffer)
			data->import_marks = xstrdup(arg);
	argv_array_push(&fastexport->args, "--use-done-feature");
	struct ref **tail = &ret;
		return 1;
		if (skip_prefix(buf.buf, "lock ", &name)) {
}
			} else
		strbuf_addch(&buf, ':');
	/* Fork thread #1: git to program. */
				   const char *name, int flags)
#define PBUFFERSIZE 8192

		else if (!strcmp(msg, "forced update")) {

	state.gtp.state = SSTATE_TRANSFERRING;

			status = REF_STATUS_REJECT_STALE;
	ret |= tloop_join(gtp_thread, "Git to program copy");
		if (set_helper_option(transport, "dry-run", "true") != 0)
		strbuf_addstr(&buf, ref->name);
		exit(code);
			return 1;
		 * The "--force-with-lease" options without explicit


	/*
		return 0;
				"ready.\n");
	struct helper_data *data = transport->data;
	 * while closing the ptg file descriptors.
	int force_all = flags & TRANSPORT_PUSH_FORCE;
		ret = -1;
			mandatory = 1;

		}
 * data.

	 * just warn if it fails.
	if (!data->rs.nr && (data->import || data->bidi_import || data->export)) {
		t->bufuse -= bytes;
	if (!count)
		return 1;

	strbuf_release(&buf);
	 * and stuff like taking over will require the fd to remain.
 */
		return fetch_with_import(transport, nr_heads, to_fetch);


		if (set_helper_option(transport, TRANS_OPT_PUSH_CERT, "if-asked") != 0)
			 * most likely error is EPIPE due to the helper dying
		strbuf_addf(&cmdbuf, "stateless-connect %s\n", name);
	case TRANSPORT_FAMILY_IPV6:
#include "thread-utils.h"
	};

		fprintf(stderr, "Debug: Remote helper: Waiting...\n");
		data->no_disconnect_req = 1;
static int process_connect_service(struct transport *transport,
	pthread_t gtp_thread;
		strbuf_addch(&buf, '\n');
#include "transport-internal.h"
	};
}
	 */
		if (!strcmp(name, boolean_options[i])) {
	const char *name;
	msg = strchr(refname, ' ');
			      "helper probably needs newer version of Git"),
	if (finish_command(&exporter))
	if (!remote_refs) {
	/*
				   struct ref **ref,
		error_errno(_("read(%s) failed"), t->src_name);
			strbuf_addf(&cas, "%s:%s",
	struct string_list_item *cas_option;
			(*tail)->symref = xstrdup(buf.buf + 1);
#define STATE_NEEDS_READING(state) ((state) <= SSTATE_TRANSFERRING)
				    struct ref *remote_refs,
		if (recvline(data, &buf))
	if (!*ref) {
		"--signed-tags=verbatim" : "--signed-tags=warn-strip");
	return 0;
			  "Perhaps you should specify a branch such as 'master'.\n"));
		*ref = find_ref_by_name(*ref, refname);
				strbuf_addstr(&buf, ref->peer_ref->name);

	data->name = name;
}
	for (posn = ret; posn; posn = posn->next)
		*tail = alloc_ref(eov + 1);
	if (recvline_fh(input, cmdbuf))
		if (buf.buf[0] == '@')

	int ret;
			die(_("helper %s does not support --signed"), name);
 * Join thread, with appropriate errors on failure. Name is name for the

			data->check_connectivity = 1;
	static int debug_enabled = -1;
		rename(buf.buf, data->export_marks);
		&s->gtp);
			}
	return url;
	return ret;
		fprintf(stderr, "Debug: Remote helper: <- %s\n", buffer->buf);
	pid2 = fork();
		debug_enabled = getenv("GIT_TRANSLOOP_DEBUG") ? 1 : 0;

		}
			if (udt_do_write(t))
		struct ref *remote_refs, int flags)
/*
			die(_("helper %s does not support dry-run"), name);
	struct strbuf buf = STRBUF_INIT;
	struct helper_data *data = transport->data;
	}
		option : 1,

		strbuf_release(&msg_buf);
static int strbuf_set_helper_option(struct helper_data *data,
		exit(udt_copy_task_routine(&s->ptg) ? 0 : 1);
			; /* do nothing */
	fd[1] = data->helper->in;

	bytes = xread(t->src, t->buf + t->bufuse, BUFFERSIZE - t->bufuse);

		const char *space = strchrnul(attrs, ' ');
			capname = buf.buf + 1;
	setvbuf(input, NULL, _IONBF, 0);
{
		free(private);
	}
#endif
		bidi_import : 1,
		set_helper_option(transport, "cas", cas_option->string);
		die_errno(_("full write to remote helper failed"));
	}


#include "argv-array.h"
	}
		if (private && !get_oid(private, &oid)) {
	len = strlen(attr);
		const char *capname, *arg;
		set_helper_option(transport, "check-connectivity", "true");
	if (!tret) {
					 const char *name,
		else

	}

		}
			xwrite(data->helper->in, "\n", 1);
			FREE_AND_NULL(msg);
			break;
	err = pthread_create(&ptg_thread, NULL, udt_copy_task_routine,
		if (posn->status & REF_STATUS_UPTODATE)
			FREE_AND_NULL(msg);
	if (debug)
static void set_common_push_options(struct transport *transport,
	 * fast-forward or this is a forced update.

	udt_kill_transfer(&s->gtp);
{
		}
	if (debug)
	fastexport->out = dup(helper->in);
	void *tret;
	/* Buffer. */
{
		no_private_update : 1;
static struct ref *get_refs_list_using_list(struct transport *transport,
	 * as "git fetch" can use the value to write feedback to the
		const char *spec = expand_list_objects_filter_spec(
		return -1;
	if (debug)

 * thread (for error messages). Returns 0 on success, 1 on failure.
	struct string_list revlist_args = STRING_LIST_INIT_DUP;
}

			if (udt_do_read(t))
	state.gtp.src_is_sock = 0;
	char msgbuf[PBUFFERSIZE];
		const struct ref *posn = to_fetch[i];
	for (i = 0; i < nr_heads; i++) {
	 *
		close(data->helper->out);
{
			die(_("helper %s does not support --atomic"), name);
	if (get_exporter(transport, &exporter, &revlist_args))
}
					if (!name || !(flag & REF_ISSYMREF))
		}
	 * These helpers read back data from fast-import on their stdin, which could
		die_errno(_("full write to remote helper failed"));
static void sendline(struct helper_data *helper, struct strbuf *buffer)
			if (atomic) {
	fastimport->git_cmd = 1;
static const char *boolean_options[] = {
	struct helper_data *data = transport->data;
		if (!private)
		if (!strcmp(msg, "no match")) {
#ifndef NO_PTHREADS
		if (!ref->peer_ref && !mirror)

	/* Fill the state fields. */
	struct strbuf cmdbuf = STRBUF_INIT;
	if (data->export)
	 * were fetching.
		posn = to_fetch[i];
/* Closes the target (for writing) if transfer has finished. */
		} else if (!strcmp(capname, "signed-tags")) {
			       struct ref *remote_refs, int flags)
			break;
	 * attempts to read from it (mingw compat headers do not
		if (set_helper_option(transport, "force", "true") != 0)
}
	state.ptg.bufuse = 0;
		if (recvline(data, &buf))
	if (waitpid(pid, &tret, 0) < 0) {
		if (posn->status & REF_STATUS_UPTODATE)
	/* Is destination socket? */
		fprintf(stderr, "Debug: Remote helper: -> %s", str);
	strbuf_release(&buf);
 * Linux pipes can buffer 65536 bytes at once (and most platforms can
		close(t->src);
		return 1;
	struct ref *posn;
	struct ref *ref;
	struct strbuf buf = STRBUF_INIT;
	fd[0] = data->helper->out;
		} else if (mandatory) {

			 data->transport_options.check_self_contained_and_connected &&

			break;
	for (i = 0; i < ARRAY_SIZE(unsupported_options); i++) {
		udt_kill_transfer(&s->ptg);
			if (strcmp(ref->name, ref->peer_ref->name)) {
	 * get_refs_list. If this happens, and if the transport helper doesn't
			refspec_append(&data->rs, arg);
 * Stream state: No more data coming in this direction, flushing rest of
			if (!ref->deletion)
	ret |= tloop_join(pid2, "Program to git copy");
	if (process_connect(transport, 1)) {
			_("No refs in common and none specified; doing nothing.\n"
	 * is listed in .tsan-suppressions for the time being.
			if (set_helper_option(transport, "push-option", item->string) != 0)
	struct child_process *helper = get_helper(transport);
	if (data->connect) {
			FREE_AND_NULL(msg);
	unsigned fetch : 1,
#define BUFFERSIZE 65536
	return push_update_refs_status(data, remote_refs, flags);
	data->helper = helper;
	 * fastexport is done with it. */
	struct strbuf buf = STRBUF_INIT;

}
	push_refs,
			    oid_to_hex(&posn->old_oid),
static struct ref *get_refs_list(struct transport *transport, int for_push,
			udt_close_if_finished(t);
		stateless_connect : 1,
/*
	 *
		break;
 * no data is read. Returns 0 on success, -1 on error.
	state.ptg.dest_is_sock = 0;
#include "protocol.h"
								  &oid, &flag);

	}
	int ret = 0;

		 * transport->smart_options->cas altogether and instead
	if (duped < 0)

#include "transport.h"
#include "refspec.h"
	string_list_clear(&revlist_args, 1);
}
static int fetch(struct transport *transport,
		exit(128);
{
		else if (data->check_connectivity &&
	for (ref = remote_refs; ref; ref = ref->next) {
		strbuf_addf(&buf, "%s.tmp", data->export_marks);
		 */
		connect : 1,
	int atomic = flags & TRANSPORT_PUSH_ATOMIC;
		else if (!strcmp(capname, "check-connectivity"))
		argv_array_pushf(&fastexport->args, "--import-marks=%s", data->import_marks);
	}

			status = REF_STATUS_NONE;
	struct helper_data *data = transport->data;
		if (debug)
static int push_refs_with_push(struct transport *transport,
		error(_("%s thread failed"), name);


		else if (!strcmp(capname, "bidi-import"))
			die(_("helper %s does not support --signed=if-asked"), name);
		 * values to expect have already been expanded into

	/*
{
			strbuf_addf(&buf, "^%s", private);
			if (has_attribute(eon + 1, "unchanged")) {
						     (struct string_list *)value);

	standard_options(transport);
				strbuf_addstr(&buf, oid_to_hex(&ref->new_oid));
	state.gtp.bufuse = 0;

	TRANS_OPT_THIN,
}
	const char *src_name;

			private = apply_refspecs(&data->rs, name);
			private = xstrdup(name);
	}
	int code;
{
		posn = to_fetch[i];

		die(_("expected ok/error, helper said '%s'"), buf->buf);

	struct child_process *helper;

	if (flags & TRANSPORT_PUSH_ATOMIC)
	 * We can't fully close the socket since otherwise gtp
	transport_check_allowed(name);
	 */
		warning(_("helper reported unexpected status of %s"), refname);

	 * Close both streams in parent as to not interfere with
	strbuf_release(&buf);
		}
		} else if (!strcmp(capname, "stateless-connect")) {
	/* Get_helper so connect is inited. */
	strbuf_addch(&buf, '\n');
		ret = 1;
		*ref = find_ref_by_name(remote_refs, refname);
	if (!*ref)
		argv_array_push(&fastexport->args, revlist_args->items[i].string);
		return 0;
static void udt_kill_transfer(struct unidirectional_transfer *t)
			FREE_AND_NULL(msg);
		if (!ref->deletion) {

	if (debug)

			ref->force = 1;
	if (!strcmp(buf->buf, "ok"))
	err = pthread_join(thread, &tret);
	helper = get_helper(transport);
}
	return 0;
	free(transport->data);

				if (!ref->deletion) {
 * -1 on failure.
		strbuf_reset(&buf);

{

	}
		if (private) {
		set_helper_option(transport, "filter", spec);
	for (i = 0; i < nr_heads; i++)
 * buffer less), so attempt reads and writes with up to that size.
	int duped;

	struct child_process *helper;

	return 0;
}

				return NULL;


			exit(128);
 * Join process, with appropriate errors on failure. Name is name for the
	udt_kill_transfer(&s->ptg);
	if (data->export_marks)
	if (pid1 < 0)

	state.ptg.src_is_sock = (input == output);
	if (data->transport_options.filter_options.choice) {
		if (eon) {
/*
		die_errno(_("can't start thread for copying data"));
		else if (!strcmp(capname, "import"))
/* Close the source and target (for writing) for transfer. */
	char buf[BUFFERSIZE];
	}
	 * As an optimization, the transport code may invoke fetch before
			msg = xstrdup(msg);
		 * this is already the default,

	else
	sendline(data, &buf);
				    int flags)
		free(private);
		else if (!strcmp(capname, "option"))

			status = REF_STATUS_REJECT_NONFASTFORWARD;
	struct string_list cas_options = STRING_LIST_INIT_DUP;
			(int)bytes, t->src_name, (int)t->bufuse);
 * Spawn the transfer tasks and then wait for them. Returns 0 on success,
		sendline(data, &buf);
	return res;
	return 0;
	TRANS_OPT_RECEIVEPACK,
	transport->vtable = &vtable;
	struct helper_data *data = transport->data;
	strbuf_release(&buf);
	int status, forced = 0;

	 * buffer the complete batch of import commands until this newline before
	struct helper_data *data = transport->data;
}
	 * NEEDSWORK: This function is sometimes used from multiple threads, and

			msg = strbuf_detach(&msg_buf, NULL);
		} else if (starts_with(capname, "no-private-update")) {
			if (transport->pack_lockfile)
		}
	TRANS_OPT_KEEP

		if (t->dest_is_sock)
	 * The fast-import stream of a remote helper that advertises



		if (*buf.buf == '*') {
		transfer_debug("Read %i bytes from %s (buffer now at %i)",
{
{

	duped = dup(helper->out);

		if (eon)
	int ret = 0;
		strbuf_addstr(&buf, value ? "true" : "false");
	 * end of file detection and wait for both tasks to finish.
	name = for_push ? "git-receive-pack" : "git-upload-pack";
/* State of bidirectional transfer loop. */
		if (recvline(data, &buf)) {
			if (read_ref(private, &posn->old_oid) < 0)
{
	if (!data->option)
	release_helper
		&s->ptg);

__attribute__((format (printf, 1, 2)))

		die(_("error while running fast-import"));

	argv_array_push(&fastexport->args, data->signed_tags ?

			forced = 1;

		const char *colon = strchr(url, ':');
#define SSTATE_FINISHED 2
	helper->trace2_child_class = helper->args.argv[0]; /* "remote-<name>" */
	get_refs_list,
		argv_array_pushf(&helper->env_array, "%s=%s",
		else if (!strcmp(capname, "push"))
		exec = data->transport_options.uploadpack;
				strbuf_addch(&buf, '+');
}
	sendline(data, buf);
					const char *name;
	int src;
static int release_helper(struct transport *transport)
		} else if (!strcmp(capname, "connect")) {
		error_errno(_("write(%s) failed"), t->dest_name);
	strbuf_release(&buf);

		}

			status = REF_STATUS_REJECT_FETCH_FIRST;
		tail = &((*tail)->next);
	 * we always write the same value, but it's still wrong. This function
struct helper_data {
			(int)bytes, t->dest_name, (int)t->bufuse);
	for_each_string_list_item(cas_option, &cas_options)
		if (!*buf.buf)
		ret = 1;
		if (!(to_fetch[i]->status & REF_STATUS_UPTODATE))

{
 * Copies data from stdin to output and from input to stdout simultaneously.
	vsnprintf(msgbuf, PBUFFERSIZE, fmt, args);
{
static void transfer_debug(const char *fmt, ...)
	    data->transport_options.check_self_contained_and_connected)
		else
	}
{
	strbuf_release(&buf);
	if (transport->cloning)
	}

	const char *dest_name;

					    (*tail)->name);
	while (t->state != SSTATE_FINISHED) {
		if (set_helper_option(transport, TRANS_OPT_ATOMIC, "true") != 0)
	if (!data->push)
}
	state.gtp.dest_name = "remote output";


	argv_array_push(&helper->args, remove_ext_force(transport->url));
	if (strcmp(name, exec)) {
			continue;
	/* Is source socket? */
}
static int push_update_ref_status(struct strbuf *buf,
	}
	TRANS_OPT_UPLOADPACK,
			data->signed_tags = 1;

		fprintf(stderr, "Debug: Capabilities complete.\n");
	return -1;
			continue;

		if (force_all)
		push : 1,
	}
	}
	int ret = 0;

	 * Yes, dup the pipe another time, as we need unbuffered version
}
 * -1 on failure.
	int dest;
 */
		die_errno(_("can't start thread for copying data"));
	}
	} else if (flags & TRANSPORT_PUSH_CERT_ALWAYS) {
		char *private;
	}

/* Stream state: More data may be coming in this direction. */
	 * right hand side of the first refspec matching each ref we
	/* Source */
		strbuf_addch(&buf, '\n');

		if (!*space)
	if (have_git_dir())

}


	struct helper_data *data = transport->data;
};
		strbuf_reset(&buf);
						 strbuf_detach(&buf, NULL));

	if (*ref)
}
	 * whether we have invoked get_refs_list.
			FREE_AND_NULL(msg);
		else if (buf.buf[0] != '?')
	int i, ret = 0;

struct unidirectional_transfer {
		if (debug)
	argv_array_push(&fastimport->args, "fast-import");
		struct strbuf msg_buf = STRBUF_INIT;
	helper = xmalloc(sizeof(*helper));
		}
			sigchain_push(SIGPIPE, SIG_IGN);
	if (!data->get_refs_list_called)
}
			return 1;
	if (buf.len == 0) {
static int set_helper_option(struct transport *transport,


static int string_list_set_helper_option(struct helper_data *data,
	int res = 0;
	get_helper(transport);
	}
	if (write_in_full(helper->helper->in, buffer->buf, buffer->len) < 0)
	}
		return fetch_with_fetch(transport, nr_heads, to_fetch);
	transport->data = data;
	struct unidirectional_transfer *t = (struct unidirectional_transfer *)udt;
	} else if (data->stateless_connect &&
#define SSTATE_FLUSHING 1


}
			fprintf(stderr, "Debug: Disconnecting.\n");
	int len;
			FREE_AND_NULL(msg);
	return 0;
	helper->in = -1;
	va_end(args);

	if ((*ref)->status != REF_STATUS_NONE) {
	duped = dup(helper->out);
	if (getenv("GIT_TRANSPORT_HELPER_DEBUG"))
{
#include "cache.h"
			data->bidi_import = 1;
	 * we end up using debug_enabled racily. That "should not matter" since
		if (r > 0)
		default:
	char *import_marks;
}
}
static struct ref *get_refs_list_using_list(struct transport *transport,
			get_oid_hex(buf.buf, &(*tail)->old_oid);
			*eon = '\0';
	if (strbuf_getline(buffer, helper) == EOF) {
				warning(_("%s also locked %s"), data->name, name);
		exit(128);


					strbuf_addf(&buf, "%s:%s", name, ref->name);

		struct object_id oid;
	 * reasons we default to the equivalent of *:*.)
		do_take_over(transport);
	res = disconnect_helper(transport);
	struct helper_data *data = transport->data;
{
	 * Open the output as FILE* so strbuf_getline_*() family of
	}

		int r = set_helper_option(transport, "servpath", exec);
	struct child_process *helper;
		die(_("couldn't run fast-export"));
		return -1;
		set_helper_option(t, "family", "ipv6");

	const char *exec;
		else if (!strcmp(msg, "already exists")) {
#define SSTATE_TRANSFERRING 0
	 * sending data to fast-import.

	transfer_debug("%s is writable", t->dest_name);
}
	} else if (starts_with(buf->buf, "error ")) {
		   (get_protocol_version_config() == protocol_v2) &&
	while (1) {
	transport_take_over(transport, data->helper);
			fprintf(stderr, "Debug: Falling back to dumb "
	return 0;
	if (data->export_marks) {
			FREE_AND_NULL(msg);
	switch (t->family) {
		if (debug)
	if (data->push)
	int cat_blob_fd, code;
static int debug;
	struct unidirectional_transfer ptg;
		if (debug)
	}
/*
		char *private, *name;
	} else

	struct strbuf buf = STRBUF_INIT;
{
static int fetch_with_import(struct transport *transport,
				   const char *name, const char *exec)
			data->stateless_connect = 1;
	if (data->push && for_push)
static void standard_options(struct transport *t);
#include "revision.h"

	/* Name of source. */
			die(_("unknown mandatory capability %s; this remote "
struct bidirectional_transfer_state {

	return ret;
static const char *remove_ext_force(const char *url)
{
	struct ref *posn;
		transfer_debug("Wrote %i bytes to %s (buffer now at %i)",
	argv_array_pushf(&helper->args, "git-remote-%s", data->name);

			data->no_private_update = 1;
/*
	va_list args;
	struct git_transport_options transport_options;
{

 * no data is written. Returns 0 on success, -1 on error.
		set_helper_option(transport, "cloning", "true");
{
		return;
{
		else if (!strcmp(msg, "non-fast forward")) {
				 GIT_DIR_ENVIRONMENT, get_git_dir());
{

		t->bufuse += bytes;
			break;
		char *private;
		ret = run_connect(transport, &cmdbuf);

}
	if (pid2 < 0)
	string_list_clear(&cas_options, 0);
static int push_refs_with_export(struct transport *transport,
					    int for_push);

		name = posn->symref ? posn->symref : posn->name;
	helper->err = 0;
	transfer_debug("%s is readable", t->src_name);
	if (code < 0 && errno == ENOENT)
	char *refname, *msg;
	argv_array_push(&fastimport->args, debug ? "--stats" : "--quiet");
				   struct ref *remote_refs)
	state.ptg.dest_name = "stdout";
	struct helper_data *data = transport->data;
				die(_("helper %s does not support 'push-option'"), name);
	if (!debug_enabled)
		case REF_STATUS_REJECT_ALREADY_EXISTS:

	struct child_process fastimport;
		 int nr_heads, struct ref **to_fetch)
	struct helper_data *data = transport->data;
	return ret;
			continue;
			   0, 0);
	data->no_disconnect_req = 0;
	/*
		}
	if (!strcmp(cmdbuf->buf, "")) {
	struct refspec rs;
		attrs = space + 1;
				string_list_clear(&cas_options, 0);
		if (ref->peer_ref) {
			continue;
	strbuf_release(&buf);
	return tloop_spawnwait_tasks(&state);
		warning(_("%s unexpectedly said: '%s'"), data->name, buf->buf);
/*

	if (data->import_marks)
	argv_array_push(&fastexport->args, "fast-export");

	argv_array_push(&fastimport->args, "--allow-unsafe-features");
		ret = run_connect(transport, &cmdbuf);
	if (!WIFEXITED(tret) || WEXITSTATUS(tret)) {

	}
			warning(_("helper %s does not support 'force'"), data->name);
		return data->helper;
		case REF_STATUS_UPTODATE:
		 */
	 */
			else
{
	 * Handle --upload-pack and friends. This is fire and forget...
	struct ref *ref;
		}

	while (1) {
	get_helper(transport);
		switch (ref->status) {
	if (t->dest_is_sock)
	/*
		}

	for (i = 0; i < revlist_args->nr; i++)
			data->export_marks = xstrdup(arg);
	get_helper(transport);
		check_connectivity : 1,

	state.ptg.src = input;
				 const struct argv_array *ref_prefixes)

		die(_("couldn't run fast-import"));

				    ref->name, oid_to_hex(&ref->old_oid_expect));
		exit(udt_copy_task_routine(&s->gtp) ? 0 : 1);
	if (!process_connect_service(transport, name, exec))
	bytes = xwrite(t->dest, t->buf, t->bufuse);
	int i;
static struct child_process *get_helper(struct transport *transport)

	if (debug_enabled < 0)
		die_errno(_("can't dup helper output fd"));
	if (is_bool)

		return string_list_set_helper_option(data, name,
	strbuf_addch(&buf, '\n');
	input = xfdopen(duped, "r");
		break;
			status = REF_STATUS_REJECT_NEEDS_FORCE;
	state.ptg.src_name = "remote input";

	struct strbuf buf = STRBUF_INIT;
			ret = 1;
	fastimport->in = xdup(helper->out);
		argv_array_pushf(&fastexport->args, "--export-marks=%s.tmp", data->export_marks);
		cat_blob_fd = xdup(helper->in);

		die(_("can't start thread for copying data: %s"), strerror(err));
		else if (!strcmp(msg, "needs force")) {
	sendline(data, &buf);
			data->fetch = 1;
	set_common_push_options(transport, data->name, flags);
			continue;
	return process_connect_service(transport, name, exec);
	fprintf(stderr, "Transfer loop debugging: %s\n", msgbuf);
			else

	const char *name;


	 * should be written to peer_ref if the update is a
	}
				"transport.\n");
	child_process_init(helper);
	}
			close(t->dest);
{
{
		} else if (skip_prefix(capname, "import-marks ", &arg)) {
	if (!data->connect)
	fetch,
	write_constant(helper->in, "capabilities\n");
		else if (r < 0)
#include "quote.h"


			    posn->symref ? posn->symref : posn->name);
			  const char *name, const char *value)
					die(_("could not read ref %s"),
	}
}
		fprintf(stderr, "Debug: Remote helper: -> %s", buffer->buf);
		exec = data->transport_options.receivepack;
	int duped;
}
	if (t->bufuse == 0)
#include "commit.h"
		close(data->helper->in);

			break;
	state.gtp.dest_is_sock = (input == output);
	get_helper(transport);
	struct bidirectional_transfer_state state;
static void write_constant(int fd, const char *str)
		write_str_in_full(helper->in, "list for-push\n");
			return 0;
	int tret;
static int tloop_spawnwait_tasks(struct bidirectional_transfer_state *s)


	else if (pid2 == 0) {
		if (data->rs.nr)
			data->push = 1;

		else if (!strcmp(capname, "export"))
	}
				if (read_ref((*tail)->name, &(*tail)->old_oid) < 0)
		ret = 0;
		eov = strchr(buf.buf, ' ');
	strbuf_reset(buffer);
	pthread_t ptg_thread;
		strbuf_addf(&buf, "fetch %s %s\n",
		res = finish_command(data->helper);
		/*
{
	 * those be invoked).
