	if (!strcmp(op, "fill")) {
	if (argc != 2 || !strcmp(argv[1], "-h"))
		die("unable to read credential from stdin");
	op = argv[1];
	if (credential_read(&c, stdin) < 0)
	"git credential [fill|approve|reject]";
	}


{
	} else if (!strcmp(op, "reject")) {
	struct credential c = CREDENTIAL_INIT;
		usage(usage_msg);
		credential_reject(&c);
		credential_fill(&c);
}
static const char usage_msg[] =
#include "builtin.h"

#include "git-compat-util.h"

		credential_write(&c, stdout);

	const char *op;
	} else if (!strcmp(op, "approve")) {
		usage(usage_msg);
	} else {
	return 0;
		credential_approve(&c);
int cmd_credential(int argc, const char **argv, const char *prefix)
#include "credential.h"
