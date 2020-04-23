	return path[i] == ':' ? i + 1 : 0;
}

	 */
	*path += ret;
	return ret;
}
	 * Does it start with an ASCII letter (i.e. highest bit not set),
		; /* skip first UTF-8 character */
	/*
	 * While drive letters must be letters of the English alphabet, it is

	/* unc paths */
	 * a drive letter to "virtual drives". Even `1`, or `ä`. Or fun stuff
	if (!(0x80 & (unsigned char)*path))
		if (!pos)
	for (i = 1; i < 4 && (0x80 & (unsigned char)path[i]); i++)
	 *
	 */
	 * followed by a colon?
int win32_has_dos_drive_prefix(const char *path)
#include "../../git-compat-util.h"


	return pos + is_dir_sep(*pos) - path;
	int i;
		do {
}
{

			pos++;

int win32_offset_1st_component(const char *path)
	}
		} while (*pos && !is_dir_sep(*pos));
	int ret = has_dos_drive_prefix(*path);
	 * like this:
			return 0; /* Error: malformed unc path */
	if (!skip_dos_drive_prefix(&pos) &&
		/* skip server name */
	 * possible to assign virtually _any_ Unicode character via `subst` as
	 *      subst ֍: %USERPROFILE%\Desktop
		return *path && path[1] == ':' ? 2 : 0;
{
	char *pos = (char *)path;
		pos = strpbrk(pos + 2, "\\/");
			is_dir_sep(pos[0]) && is_dir_sep(pos[1])) {
int win32_skip_dos_drive_prefix(char **path)

	/*

{
