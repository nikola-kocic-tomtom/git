}
}

{
	setenv(TR2_ENVVAR_PARENT_NAME, tr2cmdname_hierarchy.buf, 1);
	if (parent_name && *parent_name) {
	const char *parent_name = getenv(TR2_ENVVAR_PARENT_NAME);
#define TR2_ENVVAR_PARENT_NAME "GIT_TRACE2_PARENT_NAME"
#include "trace2/tr2_cmd_name.h"

#include "cache.h"
	return tr2cmdname_hierarchy.buf;

static struct strbuf tr2cmdname_hierarchy = STRBUF_INIT;
{
		strbuf_addstr(&tr2cmdname_hierarchy, parent_name);
	strbuf_release(&tr2cmdname_hierarchy);
	}
		strbuf_addch(&tr2cmdname_hierarchy, '/');
	strbuf_reset(&tr2cmdname_hierarchy);
{
void tr2_cmd_name_append_hierarchy(const char *name)
const char *tr2_cmd_name_get_hierarchy(void)

void tr2_cmd_name_release(void)

}
	strbuf_addstr(&tr2cmdname_hierarchy, name);


