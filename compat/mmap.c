}
	return 0;
		die("Invalid usage of mmap when built with NO_MMAP");
		if (count < 0) {
void *git_mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset)
			memset((char *)start+n, 0, length-n);


	free(start);
{
	while (n < length) {
int git_munmap(void *start, size_t length)
			return MAP_FAILED;
	return start;

	if (start != NULL || flags != MAP_PRIVATE || prot != PROT_READ)
		}

{

	if (start == NULL) {
			free(start);
		return MAP_FAILED;
			break;


}
	size_t n = 0;
	}
		ssize_t count = xpread(fd, (char *)start + n, length - n, offset + n);
		errno = ENOMEM;
	start = xmalloc(length);
	}
		if (count == 0) {
		n += count;
#include "../git-compat-util.h"
		}


			errno = EACCES;
