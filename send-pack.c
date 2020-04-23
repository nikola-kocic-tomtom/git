		default:
	close(out);
#include "config.h"
		return 0;
		case REF_STATUS_EXPECTING_REPORT:
			ret = -1;
		update_seen = 1;
		if (check_to_send_update(ref, args) < 0)
	if (args->stateless_rpc && cmds_sent)
{
		fprintf(stderr, "No refs in common and none specified; doing nothing.\n"
{
	if (args->progress)
				shutdown(fd[0], SHUT_WR);

}
static void reject_invalid_nonce(const char *nonce, int len)
		ret = receive_status(&reader, remote_refs);
			break;

		free(anon_url);
			continue;

	struct string_list_item *item;
	}
		free(buf);
	case REF_STATUS_REJECT_NONFASTFORWARD:
	int status_report = 0;
	rc = finish_command(&po);
				close(demux.out);

	while (refs) {
			return -1;
		atomic_supported = 1;
	if (args->url && *args->url) {
	}
		/* start our next search from the next ref */
			fd[1] = -1;
	if (sign_buffer(&cert, &cert, signing_key))
	if (args->push_options)
	use_push_options = push_options_supported && args->push_options;
		if (!hint) {
	switch (ref->status) {
	struct strbuf cap_buf = STRBUF_INIT;
		 * (141), because that's a normal occurrence if the remote end

	return error("atomic push failed for ref %s. status: %d\n",
		np = next_line(cp, cert.buf + cert.len - cp);
	for (i = 0; i < extra->nr; i++)

	}
		while (1) {
		     failing_ref->name, failing_ref->status);
	if (use_atomic)
			 * When we know the server would reject a ref update if
	if (strcmp(reader->line, "ok"))

		strbuf_addf(&cert, "pushee %s\n", anon_url);
		feed_object(&extra->oid[i], po_in, 1);
					refname);
			error("error in sideband demultiplexer");
	struct strbuf req_buf = STRBUF_INIT;
	if (server_supports("report-status"))
		return ret;
	}
	strbuf_addstr(&cert, "\n");
			packet_buf_write(&req_buf, "%s %s %s",
				 "%.*s", (int)(np - cp), cp);
{

	struct async demux;
	if (quiet_supported && (args->quiet || !args->progress))
		demux.isolate_sigpipe = 1;
{
		strbuf_addstr(&cap_buf, " side-band-64k");
	 * set this bit for us???
	if (need_pack_data && cmds_sent) {
	}
	int quiet_supported = 0;
	/* Mark other refs as failed */

	if (args->atomic && !atomic_supported)
}
			 * we get one).
#include "gpg-interface.h"
		}
	if (args->stateless_rpc)
		strbuf_addstr(&cap_buf, " report-status");
			continue;
	if (!skip_prefix(reader->line, "unpack ", &reader->line))
static int advertise_shallow_grafts_cb(const struct commit_graft *graft, void *cb)
			push_cert_nonce = xmemdupz(push_cert_nonce, len);
			hint->status = REF_STATUS_OK;
	int in = fd[0];
	ret = receive_unpack_status(reader);
	      struct ref *remote_refs,
	struct ref *ref;
#include "sideband.h"

		packet_buf_flush(&req_buf);
		packet_flush(out);
				strbuf_release(&cap_buf);
		packet_flush(out);

			/* Closed by pack_objects() via start_command() */
	}
#include "builtin.h"
	case 0:
	packet_buf_write(req_buf, "push-cert-end\n");
			       struct ref *remote_refs,

#include "connect.h"
#define CHECK_REF_STATUS_REJECTED -2
				  " push"));
	int i = 0;
	if (server_supports("atomic"))
	 * let its stdout go back to the other end.

		new_hex = oid_to_hex(&ref->new_oid);
	for (ref = remote_refs; ref; ref = ref->next) {
static const char *next_line(const char *line, size_t len)
		if (msg)
			error("pack-objects died of signal %d", rc - 128);
		char *anon_url = transport_anonymize_url(args->url);
	free(signing_key);
	else
	if (args->stateless_rpc) {
		    ch == '=' || ch == '_')
	}

		die_errno("error writing to pack-objects");

		if (!starts_with(reader->line, "ok ") && !starts_with(reader->line, "ng ")) {
		if (start_async(&demux))
	}
	 * The child becomes pack-objects --revs; we feed
	if (packet_reader_read(reader) != PACKET_READ_NORMAL)
			ssize_t n = xread(po.out, buf, LARGE_PACKET_MAX);
	use_atomic = atomic_supported && args->atomic;
		*(int *)(opt->value) = SEND_PACK_PUSH_CERT_ALWAYS;
	const char *cp, *np;
	if (use_sideband && cmds_sent) {

	unsigned cmds_sent = 0;
		return;
		for_each_string_list_item(item, args->push_options)
	if (!is_repository_shallow(the_repository))
	 */
	if (args->porcelain)

		 * For a normal non-zero exit, we assume pack-objects wrote
static int pack_objects(int fd, struct ref *refs, struct oid_array *extra, struct send_pack_args *args)
	switch (git_parse_maybe_bool(arg)) {
	fputs(oid_to_hex(oid), fh);
	po.out = args->stateless_rpc ? -1 : fd;
			*msg++ = '\0';
}
		if (!hint)
		close(demux.out);
 */
			reject_invalid_nonce(push_cert_nonce, len);
#include "remote.h"
		return 0;
		demux.data = fd;
	/*
			   PACKET_READ_DIE_ON_ERR_PACKET);
	 * We feed the pack-objects we just spawned with revision
		if (!args->dry_run && (cmds_sent || is_repository_shallow(the_repository))) {
	for (cp = cert.buf; cp < cert.buf + cert.len; cp = np) {
		}
	strbuf_release(&cert);
	po.in = -1;
	if (server_supports("side-band-64k"))
	strbuf_release(&cap_buf);
			send_sideband(fd, -1, buf, n, LARGE_PACKET_MAX);
int send_pack(struct send_pack_args *args,

			    oid_to_hex(&ref->new_oid),

					 old_hex, new_hex, ref->name);
		case REF_STATUS_UPTODATE:
	/*
	 * parameters by writing to the pipe.
	}
	datestamp(&cert);
			packet_buf_write(&req_buf,
		else {
		case 0: /* no error */
#include "commit.h"
	for_each_commit_graft(advertise_shallow_grafts_cb, sb);
		die("the receiving end asked to sign an invalid nonce <%.*s>",
	struct ref *ref;
			strbuf_addf(&cert, "push-option %s\n", item->string);
	/* Check for statuses set by set_ref_status_for_push() */

	/*
			continue;
	for (ref = remote_refs; ref; ref = ref->next)
	if (args->push_options && !push_options_supported)
		strbuf_addstr(&cap_buf, " quiet");
	 * NEEDSWORK: why does delete-refs have to be so specific to

	const char *nl = memchr(line, '\n', len);
		}
static int check_to_send_update(const struct ref *ref, const struct send_pack_args *args)
			break;
			if (status_report)
{
	argv_array_push(&po.args, "--stdout");

	for (ref = remote_refs; ref; ref = ref->next) {

		}
		int ch = nonce[i] & 0xFF;
	 * send-pack machinery that set_ref_status_for_push() cannot
	if (server_supports("push-options"))
	die("bad %s argument: %s", opt->long_name, arg);
			/*
			hint->status = REF_STATUS_REMOTE_REJECT;
			 * as well as marking refs with their remote status (if
/*
	case REF_STATUS_REJECT_NEEDS_FORCE:
	}
	strbuf_addf(&cert, "pusher %s ", signing_key);
		else

	if (!update_seen)
#include "quote.h"
 * NEEDSWORK: perhaps move this to git-compat-util.h or somewhere and

	int *fd = data, ret;
	if (use_sideband)
		 * we should mention it to the user. The exception is SIGPIPE
		die("the receiving end asked to sign an invalid nonce <%.*s>",
				strbuf_release(&req_buf);

		case CHECK_REF_STATUS_REJECTED:

		argv_array_push(&po.args, "-q");
	return 0;
		}
		default:
		if (check_to_send_update(ref, args) < 0)
		/*

	return update_seen;
			       struct ref *failing_ref)
		quiet_supported = 1;
		return 0;
		}
		char *old_hex, *new_hex;
			if (args->stateless_rpc)
			 * Do not even bother with the return value; we know we
		hint->remote_status = xstrdup_or_null(msg);
	 */
	int use_atomic = 0;
		strbuf_addstr(&cap_buf, " atomic");
		} else if (args->push_cert == SEND_PACK_PUSH_CERT_IF_ASKED) {
	if (server_supports("ofs-delta"))
#define CHECK_REF_NO_PUSH -1
	if (!remote_refs) {
		close(fd[1]);
int option_parse_push_signed(const struct option *opt,
	for (ref = remote_refs; ref; ref = ref->next) {
		packet_flush(out);
	if (use_push_options) {
			"Perhaps you should specify a branch such as 'master'.\n");
	ret = recv_sideband("send-pack", fd[0], out);
	strbuf_addstr(&cert, "certificate version 0.1\n");
			return -1;
	int rc;
	}
	int use_push_options = 0;
		struct string_list_item *item;
	return 0;
	if (async_with_fork())
			      const char *cap_string,
		old_hex = oid_to_hex(&ref->old_oid);
	}
		agent_supported = 1;
 *
	if (negative &&
			ret = -1;
					 cap_buf.buf);
		argv_array_push(&po.args, "--progress");
		}
			warning("remote reported status on unknown ref: %s",
		/* first try searching at our hint, falling back to all refs */
			    oid_to_hex(&ref->old_oid),
	}
		refname = reader->line + 3;
		} else {
		status_report = 1;
			break;
{
		argv_array_push(&po.args, "--delta-base-offset");
			hint = find_ref_by_name(hint, refname);
#include "cache.h"
		if (!is_null_oid(&refs->old_oid))
		in = demux.out;
static void advertise_shallow_grafts_buf(struct strbuf *sb)
 * convert many similar uses found by "git grep -A4 memchr".
	int ret;
		if (isalnum(ch) ||
			continue;
		if (pack_objects(out, remote_refs, extra_have, args) < 0) {
{
			      struct send_pack_args *args,
	 * Clear the status for each ref and see if we need to send
				break;
		case REF_STATUS_OK:
			}
static int generate_push_cert(struct strbuf *req_buf,
{
		packet_buf_write(req_buf,
	}
		strbuf_addf(&cert, "%s %s %s\n",
	hint = NULL;
			die(_("the receiving end does not support --signed push"));
		memset(&demux, 0, sizeof(demux));
		return CHECK_REF_UPTODATE;
			      const char *push_cert_nonce)
		hint = hint->next;
		if (push_cert_nonce) {
		char *msg;
		} else if (args->push_cert == SEND_PACK_PUSH_CERT_ALWAYS) {
	/* Does the other end support the reporting? */
	}
}
		die_errno("git pack-objects failed");
			ret = -1;

			ref->status = REF_STATUS_REJECT_NODELETE;
	fclose(po_in);
	 */
		    len, nonce);
	if (server_supports("delete-refs"))
					OBJECT_INFO_SKIP_FETCH_OBJECT |
	case REF_STATUS_REJECT_NODELETE:
		return error(_("unexpected flush packet while reading remote unpack status"));
		allow_deleting_refs = 1;
		strbuf_addf(&cap_buf, " agent=%s", git_user_agent_sanitized());
		return error(_("unable to parse remote unpack status: %s"), reader->line);
	}
	char *signing_key = xstrdup(get_signing_key());

				  " receiving end does not support --signed"
		po.out = -1;
		}
			warning("remote reported status on unexpected ref: %s",


	if (unset) {

	int atomic_supported = 0;
		 * hangs up (and we'll report that by trying to read the unpack
	case REF_STATUS_UPTODATE:
#include "object-store.h"

	if (ferror(po_in))
}
	} else {
		if (args->dry_run || !status_report)
static void feed_object(const struct object_id *oid, FILE *fh, int negative)
	for (ref = remote_refs; ref; ref = ref->next) {
			break; /* do nothing */
	if (server_supports("agent"))

			feed_object(&refs->old_oid, po_in, 1);

	return 0;
			continue;
			 * are failing, and just want the error() side effects,
#include "transport.h"
			packet_buf_flush(&req_buf);
		write_or_die(out, req_buf.buf, req_buf.len);

	strbuf_release(&req_buf);
 */
#include "version.h"
	    !has_object_file_with_flags(oid,
			 * we were to send it and we're trying to send the refs
			packet_buf_write(&req_buf, "%s", item->string);
			die("send-pack: unable to fork off sideband demultiplexer");
		char *buf = xmalloc(LARGE_PACKET_MAX);
		case REF_STATUS_NONE:
		return line + len; /* incomplete line */
		    ch == '/' || ch == '+' ||
}
			send_sideband(out, -1, req_buf.buf, req_buf.len, LARGE_PACKET_MAX);
		if (args->dry_run || push_cert_nonce)
	while (1) {
		refs = refs->next;

#include "pkt-line.h"
		    ch == '-' || ch == '.' ||
			cmds_sent = 1;
			ref->status = REF_STATUS_OK;
		return;
}
			/*
			need_pack_data = 1;
	/*
		argv_array_push(&po.args, "--shallow");
	argv_array_push(&po.args, "--all-progress-implied");
		if (hint)
	argv_array_push(&po.args, "--revs");

	 */
	if (NONCE_LEN_LIMIT <= len)
		if (packet_reader_read(reader) != PACKET_READ_NORMAL)
					 old_hex, new_hex, ref->name, 0,

		die(_("the receiving end does not support --atomic push"));
static int receive_unpack_status(struct packet_reader *reader)
		demux.out = -1;
#define CHECK_REF_UPTODATE -3
		switch (ref->status) {
				receive_status(&reader, remote_refs);
	if (args->use_thin_pack)
		return 0;
		close(po.out);
		if (!ref->peer_ref && !args->send_mirror)
		default:
	if (negative)
			warning(_("not sending a push certificate since the"
	      int fd[], struct child_process *conn,

		if (!args->stateless_rpc)
					       cap_buf.buf, push_cert_nonce);
		if (finish_async(&demux)) {
		strbuf_addf(&cert, "nonce %s\n", push_cert_nonce);
		}

}
		if (rc > 128 && rc != 141)
		 * something useful to stderr. For death by signal, though,
			 */
	case REF_STATUS_REJECT_FETCH_FIRST:
	if (!args->dry_run && push_cert_nonce)
static int receive_status(struct packet_reader *reader, struct ref *refs)
		}
free_return:
		if (!is_null_oid(&refs->new_oid))
	if (!ref->peer_ref && !args->send_mirror)
	po.git_cmd = 1;
	case REF_STATUS_REJECT_STALE:
	po_in = xfdopen(po.in, "w");
			fd[1] = -1;
	default:
}
	if (is_repository_shallow(the_repository))
		if (hint->status != REF_STATUS_EXPECTING_REPORT) {
	if (args->push_cert != SEND_PACK_PUSH_CERT_NEVER) {
	for (i = 0; i < len; i++) {

}
	int need_pack_data = 0;
		if (ref->deletion && !allow_deleting_refs)
				finish_async(&demux);
	}
#include "oid-array.h"
			continue;
static int atomic_push_failure(struct send_pack_args *args,
		const char *refname;
					OBJECT_INFO_QUICK))
			    ref->name);
	const char *push_cert_nonce = NULL;
	if (rc) {
static int sideband_demux(int in, int out, void *data)
		msg = strchr(refname, ' ');
	if (!strcasecmp("if-asked", arg)) {
	if (push_cert_nonce[0])
{
		advertise_shallow_grafts_buf(&req_buf);
	if (server_supports("no-thin"))
				close(out);
	if (args->quiet || !args->progress)
	if (server_supports("quiet"))
			break;
	fflush(po_in);
		*(int *)(opt->value) = SEND_PACK_PUSH_CERT_NEVER;
			error("invalid ref status from remote: %s", reader->line);
		die(_("the receiving end does not support push options"));
	if (status_report && cmds_sent)
		args->use_thin_pack = 0;
	int agent_supported = 0;
}
{
					 "%s %s %s%c%s",
		if (reader->line[0] == 'o' && reader->line[1] == 'k')
	 * the revision parameters to it via its stdin and
		strbuf_addstr(&cap_buf, " push-options");

	}
		return 0;
			 */
	return ret;
}
	int use_sideband = 0;
		args->use_ofs_delta = 1;
			ref->status = REF_STATUS_EXPECTING_REPORT;
		    len, nonce);
	struct strbuf *sb = cb;


	if (use_push_options)
	case REF_STATUS_REJECT_ALREADY_EXISTS:
	struct strbuf cert = STRBUF_INIT;
		return 0;
		}
	argv_array_push(&po.args, "pack-objects");
		int len;
	if (!args->dry_run)

		*(int *)(opt->value) = SEND_PACK_PUSH_CERT_IF_ASKED;

	int i;
			feed_object(&refs->new_oid, po_in, 0);
{

}
			if (use_sideband) {

{
	int ret;
 * the beginning of the next line, or the end of buffer.
			if (use_atomic) {
/*
		return 0;
{
#include "run-command.h"
	for (ref = remote_refs; ref; ref = ref->next) {
}
	FILE *po_in;
		putc('^', fh);
	return ret;
	if (status_report)
#include "refs.h"

	if (ret < 0)
	if (use_sideband && cmds_sent) {
		push_options_supported = 1;
		}
		cmds_sent = generate_push_cert(&req_buf, remote_refs, args,
	 */
			continue;
			   PACKET_READ_CHOMP_NEWLINE |
		goto free_return;
	struct packet_reader reader;
		use_sideband = 1;
		argv_array_push(&po.args, "--thin");
		}
	struct ref *hint;
	if (!nl)
		 */
				return atomic_push_failure(args, remote_refs, ref);
	}
	const struct ref *ref;
	int allow_deleting_refs = 0;
#define NONCE_LEN_LIMIT 256
		ret = 0;
	/*
	}
	if (graft->nr_parent == -1)
			      const struct ref *remote_refs,
			hint = find_ref_by_name(refs, refname);
		for_each_string_list_item(item, args->push_options)


		return error(_("remote unpack failed: %s"), reader->line);
	case 1:
			/* else fallthrough */
	}
		 * status).



			continue;

{
		packet_buf_write(sb, "shallow %s\n", oid_to_hex(&graft->oid));
		push_cert_nonce = server_feature_value("push-cert", &len);


	}
			if (git_connection_is_socket(conn))
	      struct oid_array *extra_have)
			continue;
	return nl + 1;
		demux.proc = sideband_demux;

			     const char *arg, int unset)

		return -1;
	putc('\n', fh);
		*(int *)(opt->value) = SEND_PACK_PUSH_CERT_NEVER;
	 * the pack data.
		die(_("failed to sign the push certificate"));
	int update_seen = 0;
	int push_options_supported = 0;
		if (!cmds_sent) {
	if (start_command(&po))

	packet_buf_write(req_buf, "push-cert%c%s", 0, cap_string);
		return CHECK_REF_NO_PUSH;

	packet_reader_init(&reader, in, NULL, 0,
		switch (ref->status) {
	if (agent_supported)

		switch (check_to_send_update(ref, args)) {
 * Make a pack stream and spit it out into file descriptor fd
#include "send-pack.h"
			}
	int out = fd[1];
	}
		return CHECK_REF_STATUS_REJECTED;
			if (n <= 0)
	strbuf_addch(&cert, '\n');
			 * atomically, abort the whole operation.
	if (args->use_ofs_delta)
		if (!ref->deletion)
	 * Finally, tell the other end!
			ref->status = REF_STATUS_ATOMIC_PUSH_FAILED;
	if (args->stateless_rpc) {

	struct child_process po = CHILD_PROCESS_INIT;
	return 0;
					refname);
