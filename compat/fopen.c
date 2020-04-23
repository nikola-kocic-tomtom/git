
 *  necessary since fopen is a macro on some platforms which may be set
#include "../git-compat-util.h"
}


		fclose(fp);
 *  based on compiler options. For example, on AIX fopen is set to fopen64
 *  The order of the following two lines is important.

	struct stat st;

	return fp;
 */
		return fopen(path, mode);
	if (S_ISDIR(st.st_mode)) {

FILE *git_fopen(const char *path, const char *mode)
 *  SUPPRESS_FOPEN_REDEFINITION is defined before including git-compat-util.h
		fclose(fp);
	}
#define SUPPRESS_FOPEN_REDEFINITION
	FILE *fp;
		return NULL;
 *  when _LARGE_FILES is defined. The previous technique of merely undefining
		return NULL;
		errno = EISDIR;
/*
	}
{
 *  to avoid the redefinition of fopen within git-compat-util.h. This is
	if (fstat(fileno(fp), &st)) {
 *
		return NULL;
	if (!(fp = fopen(path, mode)))
 *  fopen after including git-compat-util.h is inadequate in this case.
	if (mode[0] == 'w' || mode[0] == 'a')
