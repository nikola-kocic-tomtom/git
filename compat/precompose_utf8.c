				char *outpos = &prec_dir->dirent_nfc->d_name[0];
				if (errno || inleft) {
					 * die() for that, but rather let the user see the original name
}
				iconv_ibp	cp = (iconv_ibp)res->d_name;
	struct strbuf path = STRBUF_INIT;
#define PRECOMPOSE_UNICODE_C
{
		*strlen_c = strlen_chars;
void probe_utf8_pathname_composition(void)
		size_t new_maxlen = namelenz;
}
	while (i < argc) {


#include "precompose_utf8.h"
	while (*ptr && maxlen) {
			if (prec_dir->ic_precompose == (iconv_t)-1) {
	int ret_errno;

			newarg = reencode_string_iconv(oldarg, namelen, ic_precompose, 0, NULL);
	strbuf_release(&path);

	if (output_fd >= 0) {
	ic_precompose = iconv_open(repo_encoding, path_encoding);



	return ret_value;
		if (*ptr & 0x80)
	int ret_value;
				size_t inleft = namelenz;

		i++;
					 * If they occur on a mounted drive (e.g. NFS) it is not worth to
	prec_dir->dirp = opendir(dirname);
						"    \"git config core.precomposeunicode false\"\n",
	ret_value = closedir(prec_dir->dirp);

	PREC_DIR *prec_dir = xmalloc(sizeof(PREC_DIR));

		return;
		return;
		int ret_errno = errno;
			namelenz = 0;
			prec_dir->dirent_nfc = xrealloc(prec_dir->dirent_nfc, new_len);
	size_t ret = 0;
			size_t new_len = sizeof(dirent_prec_psx) + new_maxlen -
	static const char *auml_nfc = "\xc3\xa4";
		}
static const char *path_encoding = "UTF-8-MAC";
	} else {
#include "config.h"
	}
void precompose_argv(int argc, const char **argv)
	}
	return NULL;
		/* if iconv_open() fails, die() in readdir() if needed */
					namelenz = 0; /* trigger strlcpy */

					 * iconv() failed and errno could be E2BIG, EILSEQ, EINVAL, EBADF
/*

		return; /* We found it defined in the global config, respect it */
	if (ic_precompose == (iconv_t) -1)
		if (new_maxlen > prec_dir->dirent_nfc->max_name_len) {
	}
		int ret_errno = errno;
			if (newarg)
	return ret;
		}
 * Converts filenames from decomposed unicode into precomposed unicode.
			die_errno(_("failed to unlink '%s'"), path.buf);
		iconv_close(prec_dir->ic_precompose);
	prec_dir->dirent_nfc->max_name_len = sizeof(prec_dir->dirent_nfc->d_name);
	res = readdir(prec_dir->dirp);
		if (has_non_ascii(oldarg, (size_t)-1, &namelen)) {
	return prec_dir;
		free(prec_dir);
	}
		maxlen--;

 * Used on MacOS X.

					*/

		if (!namelenz)
static const char *repo_encoding = "UTF-8";
		return 0;

#include "cache.h"
	ret_errno = errno;
		prec_dir->dirent_nfc->d_type = res->d_type;

			       precomposed_unicode ? "true" : "false");
				}
{
		free(prec_dir->dirent_nfc);
			prec_dir->dirent_nfc->max_name_len = new_maxlen;
	if (strlen_c)
	if (res) {
{
	if (precomposed_unicode != 1)
		if (unlink(path.buf))
						"    precomposed unicode is not supported.\n"
				sizeof(prec_dir->dirent_nfc->d_name);
		strlen_chars++;
						repo_encoding, path_encoding);
	int output_fd;
	iconv_close(ic_precompose);
		} else
	struct dirent *res;
}

		prec_dir->dirent_nfc->d_ino  = res->d_ino;
				argv[i] = newarg;
				die("iconv_open(%s,%s) failed, but needed:\n"
		ptr++;
	if (!prec_dir->dirp) {

	const uint8_t *ptr = (const uint8_t *)s;
	errno = ret_errno;
#include "utf8.h"
		return prec_dir->dirent_nfc;
	char *newarg;
				errno = 0;
typedef char *iconv_ibp;

	const char *oldarg;
{
			} else {
		git_config_set("core.precomposeunicode",
		errno = ret_errno;
}
PREC_DIR *precompose_utf8_opendir(const char *dirname)
		precomposed_unicode = access(path.buf, R_OK) ? 0 : 1;
				size_t outsz = prec_dir->dirent_nfc->max_name_len;
	if (prec_dir->ic_precompose != (iconv_t)-1)
		oldarg = argv[i];
					/*
				iconv(prec_dir->ic_precompose, &cp, &inleft, &outpos, &outsz);

			ret++;

		if ((precomposed_unicode == 1) && has_non_ascii(res->d_name, (size_t)-1, NULL)) {
 */
	static const char *auml_nfd = "\x61\xcc\x88";
		return NULL;
static size_t has_non_ascii(const char *s, size_t maxlen, size_t *strlen_c)
	if (precomposed_unicode != -1)
					 * MacOS X avoids illegal byte sequences.
	iconv_t ic_precompose;
		errno = ret_errno;
}
	git_path_buf(&path, "%s", auml_nfc);
						"    If you want to use decomposed unicode, run\n"
struct dirent_prec_psx *precompose_utf8_readdir(PREC_DIR *prec_dir)
	}
	free(prec_dir);
	int i = 0;
		close(output_fd);
{
	size_t strlen_chars = 0;

							prec_dir->dirent_nfc->max_name_len);
			}
		git_path_buf(&path, "%s", auml_nfc);
}
		size_t namelenz = strlen(res->d_name) + 1; /* \0 */
	output_fd = open(path.buf, O_CREAT|O_EXCL|O_RDWR, 0600);
		prec_dir->ic_precompose = iconv_open(repo_encoding, path_encoding);
int precompose_utf8_closedir(PREC_DIR *prec_dir)

	free(prec_dir->dirent_nfc);

			strlcpy(prec_dir->dirent_nfc->d_name, res->d_name,
		size_t namelen;

{

	prec_dir->dirent_nfc = xmalloc(sizeof(dirent_prec_psx));
		git_path_buf(&path, "%s", auml_nfd);

	if (!ptr || !*ptr)
