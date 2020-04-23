		case REF_STATUS_UPTODATE:
	args.send_mirror = send_mirror;
		OPT__VERBOSITY(&verbose),
	if (argc > 0) {
#include "oid-array.h"
		OPT_BOOL(0, "atomic", &atomic, N_("request atomic transaction on remote side")),
		OPT_BOOL(0, "mirror", &send_mirror, N_("mirror all refs")),
	return ret;
#include "run-command.h"

int cmd_send_pack(int argc, const char **argv, const char *prefix)
			break;
			continue;
		get_remote_heads(&reader, &remote_refs, REF_NORMAL,
	for (; ref; ref = ref->next) {
	int fd[2];
	int ret;
					args.push_cert = SEND_PACK_PUSH_CERT_IF_ASKED;
	if (!helper_status)
static void print_helper_status(struct ref *ref)
	struct oid_array extra_have = OID_ARRAY_INIT;
#include "sideband.h"
		transport_print_push_status(dest, remote_refs, args.verbose, 0, &reject_reasons);

	if (helper_status)
		fd[1] = 1;
				args.push_cert = SEND_PACK_PUSH_CERT_ALWAYS;
	args.force_update = force_update;
		}
				 &extra_have, &shallow);
	args.progress = progress;

	flags = MATCH_REFS_NONE;

		apply_push_cas(&cas, remote, remote_refs);
#include "send-pack.h"
				N_("option to transmit")),
	if (send_all)
	if (remote_name) {

		OPT_STRING(0, "receive-pack", &receivepack, "receive-pack", N_("receive pack program")),
		fd[0] = 0;

		OPT_BOOL('f', "force", &force_update, N_("force updates")),
			msg = "fetch first";
			msg = "non-fast forward";
	} else {

		usage_with_options(send_pack_usage, options);
	unsigned send_mirror = 0;
	if (!args.dry_run && remote) {
		case REF_STATUS_REJECT_NEEDS_FORCE:
				if (value && !strcasecmp(value, "if-asked"))
#include "quote.h"
			default:

		  PARSE_OPT_OPTARG, option_parse_push_signed },
	}

}
	const char *remote_name = NULL;
		case REF_STATUS_REJECT_ALREADY_EXISTS:
		OPT_BOOL(0, "thin", &use_thin_pack, N_("use thin pack")),

			die("Destination %s is not a uri for %s",
		case REF_STATUS_REJECT_FETCH_FIRST:
	args.use_thin_pack = use_thin_pack;
			break;
			msg = "already exists";
	ret = send_pack(&args, fd, conn, remote_refs, &extra_have);
		case REF_STATUS_NONE:
	close(fd[1]);
				N_("server-specific"),
	unsigned int reject_reasons;
{
		struct ref *ref;
			msg = ref->remote_status;
			res = "ok";
	  "[<host>:]<directory> [<ref>...]\n"
	struct refspec rs = REFSPEC_INIT_PUSH;
	set_ref_status_for_push(remote_refs, args.send_mirror,
		break;
	struct string_list push_options = STRING_LIST_INIT_NODUP;
		refspec_appendn(&rs, argv + 1, argc - 1);
			msg = "stale info";
			   PACKET_READ_GENTLE_ON_EOF |
}
	switch (discover_version(&reader)) {
				break;
		OPT_BOOL('n' , "dry-run", &dry_run, N_("dry run")),
		flags |= MATCH_REFS_ALL;
	args.push_cert = push_cert;
#include "refs.h"
		{ OPTION_CALLBACK,

		args.force_update);
	int helper_status = 0;

		for (ref = remote_refs; ref; ref = ref->next)

		switch(ref->status) {

		strbuf_addf(&buf, "%s %s", res, ref->name);
		OPT_STRING(0, "exec", &receivepack, "receive-pack", N_("receive pack program")),
	struct oid_array shallow = OID_ARRAY_INIT;

		print_helper_status(remote_refs);
			res = "error";
		dest = argv[0];

};
			res = "error";

		OPT_STRING_LIST(0, "push-option", &push_options,
	local_refs = get_local_heads();
	strbuf_release(&buf);
	if (!dest)
		}
		} else {
		case REF_STATUS_REMOTE_REJECT:
	}
			res = "ok";
	args.verbose = verbose;
			break;

	struct ref *remote_refs, *local_refs;
			msg = "no match";
		remote = remote_get(remote_name);
		conn = NULL;
		flags |= MATCH_REFS_MIRROR;
{

		OPT_BOOL(0, "progress", &progress, N_("force progress reporting")),

	argc = parse_options(argc, argv, prefix, options, send_pack_usage, 0);
			break;
	ret |= finish_connect(conn);
	/* match them up */


#include "version.h"
#include "transport.h"
		case REF_STATUS_OK:
	args.push_options = push_options.nr ? &push_options : NULL;
		case REF_STATUS_REJECT_STALE:
	case protocol_v0:
#include "pkt-line.h"
		OPT_BOOL(0, "stdin", &from_stdin, N_("read refs from stdin")),
	args.progress = progress;
#include "protocol.h"
			while (strbuf_getline(&line, stdin) != EOF)

		fprintf(stderr, "Everything up-to-date\n");
		conn = git_connect(fd, dest, receivepack,
	int verbose = 0;
		OPT_BOOL(0, "all", &send_all, N_("push all refs")),
			   PACKET_READ_DIE_ON_ERR_PACKET);
				args.push_cert = SEND_PACK_PUSH_CERT_NEVER;
		default:
				refspec_append(&rs, buf);
		break;
		  0, "signed", &push_cert, "(yes|no|if-asked)", N_("GPG sign the push"),
	unsigned quiet = 0;

	close(fd[0]);
	int progress = -1;
			transport_update_tracking_ref(remote, ref, args.verbose);
	unsigned force_update = 0;
		if (msg) {
	NULL,
		{ OPTION_CALLBACK,
			struct strbuf line = STRBUF_INIT;
		const char *res;
		die("support for protocol v2 not implemented yet");
	}
	}
#include "remote.h"
			res = "error";
			}
		OPT_END()

	}
		const char *msg = NULL;
		  N_("require old value of ref to be at this value"),
}
			const char *buf;

			break;
			case 0:
	git_gpg_config(k, v, NULL);
	  "  --all and explicit <ref> specification are mutually exclusive."),
	/*
			switch (git_parse_maybe_bool(value)) {
			args.verbose ? CONNECT_VERBOSE : 0);

			break;
	if (!strcmp(k, "push.gpgsign")) {
		write_or_die(1, buf.buf, buf.len);
			    dest, remote_name);
			while ((buf = packet_read_line(0, NULL)))
			res = "error";
		case REF_STATUS_REJECT_NONFASTFORWARD:
			break;
static const char * const send_pack_usage[] = {
		  PARSE_OPT_OPTARG, parseopt_push_cas_option },
		if (!git_config_get_value("push.gpgsign", &value)) {
			msg = "up to date";
	struct packet_reader reader;
		strbuf_addch(&buf, '\n');
			case 1:
	args.dry_run = dry_run;
			msg = "needs force";
				break;
	args.stateless_rpc = stateless_rpc;
		}
	const char *receivepack = "git-receive-pack";
	unsigned dry_run = 0;


	if (from_stdin) {
	N_("git send-pack [--all | --mirror] [--dry-run] [--force] "

#include "config.h"

	}

	const char *dest = NULL;
#include "connect.h"
	if (args.stateless_rpc) {
	case protocol_v2:
		BUG("unknown protocol version");
		}
{
	if ((rs.nr > 0 && (send_all || args.send_mirror)) ||
	 */
			break;
				else
	    (send_all && args.send_mirror))
	git_config(send_pack_config, NULL);
	unsigned stateless_rpc = 0;

	if (!ret && !transport_refs_pushed(remote_refs))
	};
#include "builtin.h"
	if (args.send_mirror)
		case REF_STATUS_EXPECTING_REPORT:
	struct option options[] = {
	int send_all = 0;
	int flags;
	case protocol_v1:

		}

	struct remote *remote = NULL;
#include "gettext.h"
		progress = !args.quiet && isatty(2);
		OPT_BOOL(0, "helper-status", &helper_status, N_("print status from remote helper")),
		usage_with_options(send_pack_usage, options);
					return error("Invalid value for '%s'", k);
		return -1;

	packet_reader_init(&reader, fd[0], NULL, 0,
	  "[--receive-pack=<git-receive-pack>] [--verbose] [--thin] [--atomic] "
	if (progress == -1)
	struct strbuf buf = STRBUF_INIT;
			strbuf_release(&line);



		case REF_STATUS_REJECT_NODELETE:

static struct send_pack_args args;

			res = "error";
static int send_pack_config(const char *k, const char *v, void *cb)
	unsigned atomic = 0;
				refspec_append(&rs, line.buf);
	case protocol_unknown_version:
	 * with any refspecs.
#include "commit.h"
#include "gpg-interface.h"
	}


			res = "error";
	args.atomic = atomic;
		const char *value;
		if (!remote_has_url(remote, dest)) {
	struct push_cas_option cas = {0};
		strbuf_reset(&buf);
			res = "error";
		if (args.stateless_rpc) {
			quote_two_c_style(&buf, "", msg, 0);
		OPT_STRING(0, "remote", &remote_name, "remote", N_("remote name")),
	int push_cert = 0;
	if (match_push_refs(local_refs, &remote_refs, &rs, flags))
			break;
	if (!is_empty_cas(&cas))
	return git_default_config(k, v, cb);
		if (ref->remote_status)
	int from_stdin = 0;
		  0, CAS_OPT_NAME, &cas, N_("<refname>:<expect>"),
	unsigned use_thin_pack = 0;
			strbuf_addch(&buf, ' ');
		OPT_BOOL(0, "stateless-rpc", &stateless_rpc, N_("use stateless RPC protocol")),
	struct child_process *conn;
	}
	 * --all and --mirror are incompatible; neither makes sense
	args.quiet = quiet;
			   PACKET_READ_CHOMP_NEWLINE |

