
static HANDLE ms_eventlog;
			free(oldstr);
		}
			warning_errno("realloc failed");
		break;
	}
	va_start(ap, fmt);
void openlog(const char *ident, int logopt, int facility)
		str = realloc(str, st_add(++str_len, 1));
	switch (priority) {
		break;
#include "../../git-compat-util.h"
	default:
		break;
	vsnprintf(str, str_len + 1, fmt, ap);
	ReportEventA(ms_eventlog, logtype, 0, 0, NULL, 1, 0,
{

	ms_eventlog = RegisterEventSourceA(NULL, ident);
	int str_len;

			return;
	}
	if (!ms_eventlog)
		memmove(pos + 2, pos + 1, strlen(pos));
		return;
	va_start(ap, fmt);

	free(str);
	if (!ms_eventlog)

		if (!str) {
	case LOG_ALERT:
	va_end(ap);
		return;
	if (ms_eventlog)
		return;
	str_len = vsnprintf(NULL, 0, fmt, ap);
	    (const char **)&str, NULL);
		char *oldstr = str;
	WORD logtype;
		logtype = EVENTLOG_INFORMATION_TYPE;
{
	while ((pos = strstr(str, "%1")) != NULL) {
	str = malloc(st_add(str_len, 1));
		logtype = EVENTLOG_WARNING_TYPE;

		warning_errno("vsnprintf failed");
}
	case LOG_DEBUG:

		return;
	case LOG_WARNING:
	case LOG_NOTICE:
		pos[1] = ' ';



		warning_errno("malloc failed");
	case LOG_CRIT:

void syslog(int priority, const char *fmt, ...)

	case LOG_ERR:
	}
	if (!str) {

	char *str, *pos;
	case LOG_INFO:
	case LOG_EMERG:

		warning("RegisterEventSource() failed: %lu", GetLastError());
	if (str_len < 0) {
	va_end(ap);

}
	}
		logtype = EVENTLOG_ERROR_TYPE;
	va_list ap;
