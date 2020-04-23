	int status = copy_file(dst, src, mode);
{

		return -1;
	}
	while (1) {
	times.actime = st.st_atime;

	status = copy_fd(fdi, fdo);
	if (close(fdo) != 0)

	}
		return copy_times(dst, src);
	struct stat st;
		return error_errno("%s: close error", dst);
		if (!len)
	close(fdi);
	int fdi, fdo, status;
		return -1;
			return COPY_READ_ERROR;
int copy_file(const char *dst, const char *src, int mode)
static int copy_times(const char *dst, const char *src)
	if ((fdo = open(dst, O_WRONLY | O_CREAT | O_EXCL, mode)) < 0) {

	if ((fdi = open(src, O_RDONLY)) < 0)
int copy_fd(int ifd, int ofd)
	times.modtime = st.st_mtime;
		ssize_t len = xread(ifd, buffer, sizeof(buffer));
		return fdi;
		error_errno("copy-fd: read returned");
		close(fdi);
}
	switch (status) {
#include "cache.h"
{
	if (utime(dst, &times) < 0)
		return -1;
}
	mode = (mode & 0111) ? 0777 : 0666;

{
int copy_file_with_time(const char *dst, const char *src, int mode)
	return status;

}
		if (write_in_full(ofd, buffer, len) < 0)
	case COPY_WRITE_ERROR:
		break;
		break;
			return COPY_WRITE_ERROR;
	}
}
		return fdo;
	return status;
	if (!status)
		if (len < 0)
	return 0;
	struct utimbuf times;
	case COPY_READ_ERROR:
	if (!status && adjust_shared_perm(dst))

		char buffer[8192];
		error_errno("copy-fd: write returned");
	return 0;
{
	if (stat(src, &st) < 0)
			break;
