int cmd__serve_v2(int argc, const char **argv)
};
#include "parse-options.h"
	serve(&opts);
	struct serve_options opts = SERVE_OPTIONS_INIT;
static char const * const serve_usage[] = {


		OPT_END()
	/* ignore all unknown cmdline switches for now */
	struct option options[] = {

#include "cache.h"
	};
		OPT_BOOL(0, "stateless-rpc", &opts.stateless_rpc,
			 N_("quit after a single request/response exchange")),
			 N_("exit immediately after advertising capabilities")),
#include "serve.h"
		OPT_BOOL(0, "advertise-capabilities", &opts.advertise_capabilities,

	const char *prefix = setup_git_directory();
#include "test-tool.h"
			     PARSE_OPT_KEEP_DASHDASH |
	N_("test-tool serve-v2 [<options>]"),
	NULL
			     PARSE_OPT_KEEP_UNKNOWN);

	argc = parse_options(argc, argv, prefix, options, serve_usage,
{
	return 0;
}
