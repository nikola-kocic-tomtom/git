	 * bits set.
		return access(path, mode);

	 */
	/* Root can read or write any file. */

		return -1;
/* Do the same thing access(2) does, but use the effective uid,
	if (geteuid())
	return -1;

}
	errno = EACCES;
		return 0;
#include "../git-compat-util.h"
int git_access(const char *path, int mode)
	struct stat st;
	if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
 * and don't make the mistake of telling root that any file is
	if (stat(path, &st) < 0)
 */
 * executable.  This version uses stat(2).
	if (!(mode & X_OK))
#define COMPAT_CODE_ACCESS

		return 0;


{
	/* Root can execute any file that has any one of the execute
	/* do not interfere a normal user */
