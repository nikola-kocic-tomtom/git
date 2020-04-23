		if (!strcmp("--thin", arg)) {
	case protocol_v0:
"git fetch-pack [--all] [--stdin] [--quiet | -q] [--keep | -k] [--thin] "
	struct object_id oid;

	}
	}
		usage(fetch_pack_usage);
		get_remote_refs(fd[1], &reader, &ref, 0, NULL, NULL);
	case protocol_unknown_version:
			continue;
			list_objects_filter_set_no_filter(&args.filter_options);
		}
			while (strbuf_getline_lf(&line, stdin) != EOF)
			/* in stateless RPC mode we use pkt-line to read
#include "fetch-pack.h"
			continue;
		}
		if (!strcmp("--cloning", arg)) {
	} else {
		} else if (*p == '\0') {
			     const char *name)

		else {
#include "protocol.h"
	version = discover_version(&reader);
	if (args.stdin_refs) {
		if (!strcmp("--include-tag", arg)) {
	args.uploadpack = "git-upload-pack";
			 * from stdin, until we get a flush packet

	packet_reader_init(&reader, fd[0], NULL, 0,
	oidcpy(&ref->old_oid, &oid);
					break;
			continue;
		if (!strcmp("-v", arg)) {
			parse_list_objects_filter(&args.filter_options, arg);
	if (args.check_self_contained_and_connected &&
	}
	(*sought)[*nr - 1] = ref;
			args.cloning = 1;
		if (!strcmp("--all", arg)) {
	enum protocol_version version;
	 * all of them by matching the remote.  Otherwise, 'git fetch
		}
			continue;
}

	    args.self_contained_and_connected) {
			args.verbose = 1;
			args.uploadpack = arg;
		if (!strcmp("--from-promisor", arg)) {
			continue;
			args.quiet = 1;

				if (!line)
		oidclr(&oid);
			; /* <oid>, leave oid as name */
	 * refs from the standard input:
			args.stdin_refs = 1;
	for (i = 1; i < argc && *argv[i] == '-'; i++) {
			args.lock_pack = 1;
			string_list_append(&deepen_not, arg);
		fflush(stdout);

	}
		if (!conn)
		if (skip_prefix(arg, "--exec=", &arg)) {
		if (skip_prefix(arg, "--depth=", &arg)) {
			args.use_thin_pack = 1;
	 * remote no-such-ref' would silently succeed without issuing
	packet_trace_identity("fetch-pack");
		add_sought_entry(&sought, &nr_sought, &alloc_sought, argv[i]);

		if (*p == ' ') {
		const char *arg = argv[i];
		break;
	for (; i < argc; i++)
		}
			args.update_shallow = 1;
#include "oid-array.h"
		}
			continue;
static void add_sought_entry(struct ref ***sought, int *nr, int *alloc,
	if (deepen_not.nr)
			 */
		}
		}
			continue;
				char *line = packet_read_line(0, NULL);
			continue;
		}
	if (finish_connect(conn))
			continue;
		}
			   PACKET_READ_DIE_ON_ERR_PACKET);
	ALLOC_GROW(*sought, *nr, *alloc);
static const char fetch_pack_usage[] =

		break;
			args.keep_pack = 1;
#include "remote.h"
		if (!strcmp("--stateless-rpc", arg)) {
		}
		}
		conn = git_connect(fd, dest, args.uploadpack,
	}
#include "pkt-line.h"
			args.check_self_contained_and_connected = 1;
		if (!strcmp("--check-self-contained-and-connected", arg)) {
			continue;
			}
		fd[0] = 0;

	if (!parse_oid_hex(name, &oid, &p)) {
	int fd[2];
		} else {
			args.lock_pack = args.keep_pack;
		}
		return 1;
			continue;
	 * an error.
	} else {
		args.deepen_not = &deepen_not;
	else
			continue;
}
	fetch_if_missing = 0;

			strbuf_release(&line);
	/*
		}
		}
	int i, ret;
{
	char **pack_lockfile_ptr = NULL;
	}
			continue;
		}
	ref = alloc_ref(name);

	ref = fetch_pack(&args, fd, ref, sought, nr_sought,
			args.include_tag = 1;
	if (args.stateless_rpc) {
	}
#include "connect.h"
		fd[1] = 1;
	struct packet_reader reader;
		}
				   flags);

			oidclr(&oid);
	}
	char *pack_lockfile = NULL;
		if (!strcmp("--quiet", arg) || !strcmp("-q", arg)) {
		if (!strcmp("--stdin", arg)) {
		}
	struct fetch_pack_args args;
	struct ref *ref = NULL;
	close(fd[1]);

		ref = ref->next;
		if (!strcmp(arg, ("--no-" CL_ARG__FILTER))) {
		}
			name = p + 1;
		if (!strcmp(arg, "--deepen-relative")) {
			args.deepen_relative = 1;
		if (args.diag_url)
	return ret;
		printf("lock %s\n", pack_lockfile);
		       oid_to_hex(&ref->old_oid), ref->name);
			return args.diag_url ? 0 : 1;
	switch (version) {
		/* <ref>, clear cruft from get_oid_hex */
			continue;
	int nr_sought = 0, alloc_sought = 0;
			flags |= CONNECT_DIAG_URL;
		if (skip_prefix(arg, "--upload-pack=", &arg)) {
	const char *p;
			continue;

	 * If the heads to pull were given, we should have consumed
#include "builtin.h"
		usage(fetch_pack_usage);
	case protocol_v2:
		if (skip_prefix(arg, "--shallow-since=", &arg)) {
"[--no-progress] [--diag-url] [-v] [<host>:]<directory> [<refs>...]";
			args.deepen_since = xstrdup(arg);
		if (skip_prefix(arg, "--shallow-exclude=", &arg)) {

	ret |= report_unmatched_refs(sought, nr_sought);
	struct ref *ref;
		BUG("unknown protocol version");
			continue;
	struct child_process *conn;
			for (;;) {

		}
			args.stateless_rpc = 1;
		if (!strcmp("--update-shallow", arg)) {
	const char *dest = NULL;
		conn = NULL;
			continue;
	close(fd[0]);
	if (i < argc)
	 * Copy refs from cmdline to growable list, then append any
	ret = !ref;

	/*
		}
	struct ref **sought = NULL;
		if (args.stateless_rpc) {
			continue;
	 */
	(*nr)++;
			 &shallow, pack_lockfile_ptr, version);
		}
			continue;
		if (!strcmp("--no-dependents", arg)) {
			struct strbuf line = STRBUF_INIT;
		get_remote_heads(&reader, &ref, 0, NULL, &shallow);
			continue;
				add_sought_entry(&sought, &nr_sought, &alloc_sought, line.buf);

	 */
	memset(&args, 0, sizeof(args));
		if (!strcmp("--diag-url", arg)) {
		}
			args.no_dependents = 1;
		int flags = args.verbose ? CONNECT_VERBOSE : 0;
			continue;
	case protocol_v1:
			args.fetch_all = 1;
		if (!strcmp("--lock-pack", arg)) {
			continue;
			args.from_promisor = 1;

			pack_lockfile_ptr = &pack_lockfile;
		}
		}
			args.diag_url = 1;
			   PACKET_READ_GENTLE_ON_EOF |
		}
"[--include-tag] [--upload-pack=<git-upload-pack>] [--depth=<n>] "
	struct string_list deepen_not = STRING_LIST_INIT_DUP;
		}
		if (skip_prefix(arg, ("--" CL_ARG__FILTER "="), &arg)) {
		printf("connectivity-ok\n");
			/* read from stdin one ref per line, until EOF */
{
		fflush(stdout);
			continue;
	if (pack_lockfile) {
		if (!strcmp("--keep", arg) || !strcmp("-k", arg)) {
			args.depth = strtol(arg, NULL, 0);
	struct oid_array shallow = OID_ARRAY_INIT;
			continue;
		if (!strcmp("--no-progress", arg)) {
			/* <oid> <ref>, find refname */
		dest = argv[i++];
			args.uploadpack = arg;

	while (ref) {
			   PACKET_READ_CHOMP_NEWLINE |
int cmd_fetch_pack(int argc, const char **argv, const char *prefix)
			/* <ref>, clear cruft from oid */
			args.no_progress = 1;
		}
		printf("%s %s\n",
				add_sought_entry(&sought, &nr_sought,  &alloc_sought, line);
