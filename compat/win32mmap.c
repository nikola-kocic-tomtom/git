{
}


	uint32_t l = o & 0xFFFFFFFF;
	temp = MapViewOfFileEx(hmap, prot == PROT_READ ?




	LARGE_INTEGER len;

		return MAP_FAILED;
	}
	return !UnmapViewOfFile(start);
	hmap = CreateFileMapping(osfhandle, NULL,
	if (temp)
			FILE_MAP_READ : FILE_MAP_COPY, h, l, length, start);
	uint32_t h = (o >> 32) & 0xFFFFFFFF;
		length = xsize_t(len.QuadPart - offset);
		die("mmap: could not determine filesize");
int git_munmap(void *start, size_t length)

}

	return MAP_FAILED;
	if ((length + offset) > len.QuadPart)
	if (!(flags & MAP_PRIVATE))
void *git_mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset)
	HANDLE osfhandle, hmap;
		return temp;
		die("Invalid usage of mmap when built with USE_WIN32_MMAP");
	if (!hmap) {
{
	if (!GetFileSizeEx(osfhandle, &len))


	uint64_t o = offset;
		errno = EINVAL;
#include "../git-compat-util.h"
	errno = GetLastError() == ERROR_COMMITMENT_LIMIT ? EFBIG : EINVAL;
		prot == PROT_READ ? PAGE_READONLY : PAGE_WRITECOPY, 0, 0, NULL);
	if (!CloseHandle(hmap))
	osfhandle = (HANDLE)_get_osfhandle(fd);
	void *temp;
		warning("unable to close file mapping handle");
