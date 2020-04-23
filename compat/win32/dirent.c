{
}
	if (len && !is_dir_sep(pattern[len - 1]))
struct dirent *readdir(DIR *dir)
	free(dir);
	dir = xmalloc(sizeof(DIR));
				errno = err_win_to_posix(lasterr);

	/* convert UTF-16 name to UTF-8 */
			return NULL;
	xwcstoutf(ent->d_name, fdata->cFileName, sizeof(ent->d_name));
	HANDLE h;

			   find any more files; so, if another error we leave it set. */
	if ((len = xutftowcs_path(pattern, name)) < 0)
	DIR *dir;
	pattern[len] = 0;
{
	dir->dd_stat = 0;
	int len;
		}
	h = FindFirstFileW(pattern, &fdata);
		return NULL;
		return NULL;
	return dir;

			finddata2dirent(&dir->dd_dir, &fdata);
	if (h == INVALID_HANDLE_VALUE) {
	/* convert name to UTF-16 and check length < MAX_PATH */
		WIN32_FIND_DATAW fdata;
struct DIR {
{
};

		errno = EBADF;

	dir->dd_handle = h;
}
	/* append optional '/' and wildcard '*' */
	return 0;
	if (dir->dd_stat) {
	pattern[len++] = '*';
	if (!dir) {
	finddata2dirent(&dir->dd_dir, &fdata);
	/* Set file type, based on WIN32_FIND_DATA */
	int dd_stat;          /* 0-based index */
	WIN32_FIND_DATAW fdata;
		if (FindNextFileW(dir->dd_handle, &fdata)) {
int closedir(DIR *dir)
	/* initialize DIR structure and copy first dir entry */
	else
		} else {

			if (lasterr != ERROR_NO_MORE_FILES)
	struct dirent dd_dir; /* includes d_type */
}
	/* open find handle */
		errno = EBADF; /* No set_errno for mingw */
	if (!dir) {
		ent->d_type = DT_REG;
		return -1;

}
	}
		DWORD err = GetLastError();
	}
	FindClose(dir->dd_handle);
static inline void finddata2dirent(struct dirent *ent, WIN32_FIND_DATAW *fdata)
	}
	++dir->dd_stat;
		ent->d_type = DT_DIR;
{
	}
#include "../../git-compat-util.h"
	if (fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		return NULL;
	wchar_t pattern[MAX_PATH + 2]; /* + 2 for '/' '*' */
DIR *opendir(const char *name)
			DWORD lasterr = GetLastError();

	/* if first entry, dirent has already been set up by opendir */
		errno = (err == ERROR_DIRECTORY) ? ENOTDIR : err_win_to_posix(err);
		/* get next entry and convert from WIN32_FIND_DATA to dirent */



	HANDLE dd_handle;     /* FindFirstFile handle */

	return &dir->dd_dir;
			/* POSIX says you shouldn't set errno when readdir can't
		pattern[len++] = '/';

