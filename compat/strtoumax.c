#else
uintmax_t gitstrtoumax (const char *nptr, char **endptr, int base)
{
#if defined(NO_STRTOULL)
}
#include "../git-compat-util.h"
#endif
	return strtoul(nptr, endptr, base);
	return strtoull(nptr, endptr, base);

