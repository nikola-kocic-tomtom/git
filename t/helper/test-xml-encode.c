			tmp2 = tmp + 1;
				fputs("&gt;", stdout);

				fwrite(tmp, tmp2 - tmp, 1, stdout);
		if (!(ch & 0x80)) {
			else if (ch >= 0x20)
	unsigned char buf[1024], tmp[4], *tmp2 = NULL;
				fputs("&lt;", stdout);

	for (;;) {
 * Encodes (possibly incorrect) UTF-8 on <stdin> to <stdout>, to be embedded
		} else if ((ch & 0xf8) == 0xf0) {
	}
			else if (ch == '"')
				fputs(utf8_replace_character, stdout);
			len = xread(0, buf, sizeof(buf));
		if (++cur == len) {


static const char *utf8_replace_character = "&#xfffd;";
			if (len < 0)
				cur--;
				fputs("&amp;", stdout);
		} else if ((ch & 0xf0) == 0xe0) {
	unsigned char ch;
			else if (ch == '<')
				fprintf(stdout, "&#x%02x;", ch);

			remaining = 2;
			/* 1110XXXX 10Xxxxxx 10xxxxxx */
	ssize_t cur = 0, len = 1, remaining = 0;
			else if (ch == '\'')
#include "test-tool.h"
{
			tmp2++;
			else if (ch == '>')
			tmp[0] = ch;
				fputs("&quot;", stdout);
			}
			*tmp2 = ch;
			if ((ch & 0xc0) != 0x80) {
int cmd__xml_encode(int argc, const char **argv)
			continue;
		if (tmp2) {
			}
			tmp2 = tmp + 1;
				fputs(utf8_replace_character, stdout);
			/* 11110XXX 10XXxxxx 10xxxxxx 10xxxxxx */
			tmp[0] = ch;
			else
			fputs(utf8_replace_character, stdout);
		}
				continue;
			remaining = 1;
			if (ch == '&')
/*
	return 0;
				fputs("&apos;", stdout);
				tmp2 = NULL;
 */
				tmp2 = NULL;
}
				return 0;
 * in an XML file.
			/* 0xxxxxxx */
			cur = 0;
			/* 110XXXXx 10xxxxxx */
			remaining = 3;
		}
				die_errno("Could not read <stdin>");
			tmp[0] = ch;
			else if (ch == 0x09 || ch == 0x0a || ch == 0x0d)
		} else if ((ch & 0xe0) == 0xc0) {
		} else
				fputc(ch, stdout);
			if (--remaining == 0) {

		ch = buf[cur];
			if (!len)
			tmp2 = tmp + 1;
