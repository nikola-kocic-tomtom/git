	return agent;
{


		strbuf_addstr(&buf, git_user_agent());
		for (i = 0; i < buf.len; i++) {
const char *git_user_agent_sanitized(void)
				buf.buf[i] = '.';

#include "git-compat-util.h"

}
		int i;
	}
{

}


			if (buf.buf[i] <= 32 || buf.buf[i] >= 127)
		strbuf_trim(&buf);
	if (!agent) {
		agent = buf.buf;
		agent = getenv("GIT_USER_AGENT");
const char *git_user_agent(void)
const char git_version_string[] = GIT_VERSION;
	if (!agent) {

#include "strbuf.h"
			agent = GIT_USER_AGENT;
		if (!agent)
#include "version.h"
	static const char *agent = NULL;
	static const char *agent = NULL;
		struct strbuf buf = STRBUF_INIT;
	}
	return agent;
const char git_built_from_commit_string[] = GIT_BUILT_FROM_COMMIT;
		}
