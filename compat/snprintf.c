	va_list ap;

 * the trailing NUL byte; but Windows's vsnprintf uses the entire
		maxsize = 128;
 */
 * always have room for a trailing NUL byte.
			ret = -1;
	char *s;
		if (ret == maxsize-1)
#define SNPRINTF_SIZE_CORR 1
 * therefore remove 1 byte from the reported buffer size, so we
	return ret;
 * The size parameter specifies the available space, i.e. includes
#endif
		str[maxsize-1] = 0;
#else

	va_end(ap);
		if (ret == maxsize-1)
	if (maxsize > 0) {

		va_copy(cp, ap);

	s = NULL;

	va_list cp;

		str = realloc(s, maxsize);
			ret = -1;
#if defined(WIN32) && (!defined(__GNUC__) || __GNUC__ < 4) && (!defined(_MSC_VER) || _MSC_VER < 1900)

#undef vsnprintf
		/* Windows does not NUL-terminate if result fills buffer */
/*
	free(s);
		maxsize *= 4;
	ret = git_vsnprintf(str, maxsize, format, ap);

#define SNPRINTF_SIZE_CORR 0
int git_vsnprintf(char *str, size_t maxsize, const char *format, va_list ap)
{
	}
}
		if (! str)
	while (ret == -1) {
	int ret = -1;
#endif
		ret = vsnprintf(str, maxsize-SNPRINTF_SIZE_CORR, format, cp);
		return ret;
	}
#ifndef SNPRINTF_SIZE_CORR
 * buffer and avoids the trailing NUL, should the buffer be exactly
		va_end(cp);
	if (ret != -1)
		va_end(cp);
	if (maxsize < 128)
		s = str;
}
int git_snprintf(char *str, size_t maxsize, const char *format, ...)
#include "../git-compat-util.h"
		ret = vsnprintf(str, maxsize-SNPRINTF_SIZE_CORR, format, cp);
	int ret;

	va_start(ap, format);
	return ret;
 * big enough for the result. Defining SNPRINTF_SIZE_CORR to 1 will
		va_copy(cp, ap);
{
			break;
