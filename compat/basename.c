
/* Adapted from libiberty's basename.c.  */


#include "../strbuf.h"
dot:
			while (--path != base && is_dir_sep(*path))
	static struct strbuf buf = STRBUF_INIT;
	strbuf_addf(&buf, "%.*s.", dos_drive_prefix, path);
		if (*path)
	/*

	if (is_dir_sep(*p)) {
				slash = tentative;
	if (slash) {
	return buf.buf;
	 * POSIX.1-2001 says dirname("/") should return "/", and dirname("//")
char *gitbasename (char *path)
			/* POSIX.1-2001 says to ignore trailing slashes */
	while ((c = *(p++)))
{
	 * should return "//", but dirname("///") should return "/" again.
		} while (is_dir_sep(*path));
	if (path)
	const char *base;
	}


	char *p = path, *slash = NULL, c;
}
			char *tentative = p - 1;
			if (*p)
			path++;
	if (!p)
			while (is_dir_sep(*p))
	 */
		do {
			base = path;

	if ((dos_drive_prefix = skip_dos_drive_prefix(&p)) && !*p)
		if (is_dir_sep(c)) {

}
	return (char *)base;
		return ".";
char *gitdirname(char *path)
			continue;
				p++;
		if (!p[1] || (is_dir_sep(p[1]) && !p[2]))
	int dos_drive_prefix;
	strbuf_reset(&buf);

	if (!path || !*path)
		goto dot;
		*slash = '\0';
#include "../git-compat-util.h"
		slash = ++p;
		}
	}
	}
		if (!is_dir_sep(*path))
	for (base = path; *path; path++) {
		else
		return ".";
{
		return path;

		skip_dos_drive_prefix(&path);
			return path;
				*path = '\0';

