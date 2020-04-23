		/*
	case protocol_unknown_version:
#include "serve.h"
		serve_opts.stateless_rpc = opts.stateless_rpc;
	N_("git upload-pack [<options>] <dir>"),
		break;
#include "upload-pack.h"
	};
			packet_write_fmt(1, "version 1\n");
		OPT_INTEGER(0, "timeout", &opts.timeout,
	packet_trace_identity("upload-pack");
			 N_("do not try <directory>/.git/ if <directory> is no Git directory")),

		 */
}
	case protocol_v0:

int cmd_upload_pack(int argc, const char **argv, const char *prefix)
	argc = parse_options(argc, argv, prefix, options, upload_pack_usage, 0);
#include "exec-cmd.h"

	setup_path();
	struct option options[] = {
	return 0;
		BUG("unknown protocol version");
	int strict = 0;
	struct serve_options serve_opts = SERVE_OPTIONS_INIT;
			    N_("interrupt transfer after <n> seconds of inactivity")),
		/* fallthrough */
	}

	if (!enter_repo(dir, strict))

			 N_("quit after a single request/response exchange")),



	if (argc != 1)
#include "parse-options.h"
#include "pkt-line.h"
		die("'%s' does not appear to be a git repository", dir);
		OPT_BOOL(0, "strict", &strict,
	struct upload_pack_options opts = { 0 };
		serve_opts.advertise_capabilities = opts.advertise_refs;
};

			 N_("exit immediately after initial ref advertisement")),
		OPT_END()
	case protocol_v2:
		OPT_BOOL(0, "advertise-refs", &opts.advertise_refs,
#include "builtin.h"
	read_replace_refs = 0;
		OPT_BOOL(0, "stateless-rpc", &opts.stateless_rpc,

	dir = argv[0];
		break;
	NULL
		if (opts.advertise_refs || !opts.stateless_rpc)
		upload_pack(&opts);
		serve(&serve_opts);
#include "protocol.h"
	case protocol_v1:
		usage_with_options(upload_pack_usage, options);
	const char *dir;

#include "cache.h"
		 * so just fall through after writing the version string.
static const char * const upload_pack_usage[] = {
		opts.daemon_mode = 1;
	switch (determine_protocol_version_server()) {
	if (opts.timeout)
{
		 * v1 is just the original protocol with a version string,

