	if (S_ISCHR(native_mode))
		return 0140000 | perm_bits;
}
	if (rc == 0)
#define _POSIX_C_SOURCE 200112L
}
		return 0020000 | perm_bits;
	mode_t perm_bits = native_mode & 07777;
		return 0100000 | perm_bits;
{
	int rc = stat(path, buf);

	if (S_ISSOCK(native_mode))
int git_stat(const char *path, struct stat *buf)
	int rc = fstat(fd, buf);
int git_lstat(const char *path, struct stat *buf)
	int rc = lstat(path, buf);
	if (rc == 0)
{
	if (S_ISBLK(native_mode))
static inline mode_t mode_native_to_git(mode_t native_mode)
#include <sys/stat.h>  /* *stat, S_IS* */
		return 0010000 | perm_bits;
	if (S_ISDIR(native_mode))


		return 0120000 | perm_bits;
	/* Non-standard type bits were given. */
{
	return rc;

}
		buf->st_mode = mode_native_to_git(buf->st_mode);
}
		return 0040000 | perm_bits;
	if (S_ISREG(native_mode))
{
int git_fstat(int fd, struct stat *buf)
		buf->st_mode = mode_native_to_git(buf->st_mode);
	if (S_ISLNK(native_mode))
	return rc;
#include <sys/types.h> /* mode_t       */
	return perm_bits;
	if (S_ISFIFO(native_mode))
		return 0060000 | perm_bits;
		buf->st_mode = mode_native_to_git(buf->st_mode);
	return rc;
	if (rc == 0)
