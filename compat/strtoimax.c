}
#if defined(NO_STRTOULL)
#endif
	return strtol(nptr, endptr, base);

#else
	return strtoll(nptr, endptr, base);
intmax_t gitstrtoimax (const char *nptr, char **endptr, int base)
#include "../git-compat-util.h"
{
