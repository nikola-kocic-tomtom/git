
		errno = EINVAL;
	namelen = strlen(name);
		char *oldval = NULL;
	out = putenv(envstr);
	valuelen = strlen(value);
	if (!replace) {
	return out;
		return -1;
	if (!name || strchr(name, '=') || !value) {
		errno = ENOMEM;
int gitsetenv(const char *name, const char *value, int replace)
		return -1;
	 * means we do not own that storage anymore.  Do not free

	}
	}
	envstr[namelen + valuelen + 1] = 0;
	 * envstr.
	int out;
	}
	 */
	 * and changing that string modifies the environment --- which

	memcpy(envstr + namelen + 1, value, valuelen);
	if (!envstr) {

	envstr[namelen] = '=';
	/* putenv(3) makes the argument string part of the environment,
#include "../git-compat-util.h"
	memcpy(envstr, name, namelen);
	char *envstr;

		if (oldval) return 0;

	envstr = malloc(st_add3(namelen, valuelen, 2));
}
{
	size_t namelen, valuelen;
		oldval = getenv(name);
