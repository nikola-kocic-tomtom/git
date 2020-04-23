	ret = gmtime_r(timep, result);
	return ret;
#include "../git-compat-util.h"
	}
	 * be zero, we can test this very quickly.
{

#undef gmtime
	 */

		errno = EOVERFLOW;
		ret = NULL;
	struct tm *ret;

	return git_gmtime_r(timep, &result);
#undef gmtime_r
{
}
	/*
}
	memset(result, 0, sizeof(*result));
struct tm *git_gmtime(const time_t *timep)
	 * untouched when it encounters overflow. Since "mday" cannot otherwise
	static struct tm result;

struct tm *git_gmtime_r(const time_t *timep, struct tm *result)

	if (ret && !ret->tm_mday) {
	 * Rather than NULL, FreeBSD gmtime simply leaves the "struct tm"
