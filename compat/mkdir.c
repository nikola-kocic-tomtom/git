	}
{

#include "../git-compat-util.h"
		tmp_dir = (char *)dir;
#undef mkdir
/* for platforms that can't deal with a trailing '/' */
int compat_mkdir_wo_trailing_slash(const char *dir, mode_t mode)
	int retval;
	return retval;
	retval = mkdir(tmp_dir, mode);
	else

	char *tmp_dir = NULL;
	size_t len = strlen(dir);
		free(tmp_dir);
}
			return -1;
	if (tmp_dir != dir)
		tmp_dir[len-1] = '\0';

		if ((tmp_dir = strdup(dir)) == NULL)
	if (len && dir[len-1] == '/') {

