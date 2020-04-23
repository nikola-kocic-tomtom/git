		unsigned acc = 0;
#define say(a) fprintf(stderr, a)
	say("encode 85");
#else
			if (--de < 0)
		int cnt;
	}
		de85[ch] = i + 1;
		unsigned acc = 0;
			unsigned ch = *data++;

			*dst++ = acc;
			return error("invalid base85 sequence %.5s", buffer-5);
#define say1(a,b) fprintf(stderr, a, b)

				return error("invalid base85 alphabet %c", ch);

			int val = acc % 85;
		for (cnt = 4; cnt >= 0; cnt--) {
static char de85[256];
			acc /= 85;
		int ch = en85[i];
		de = de85[ch];
		if (len <= 26) len = len + 'A' - 1;
};
#endif
int decode_85(char *dst, const char *buffer, int len)
int main(int ac, char **av)
	'u', 'v', 'w', 'x', 'y', 'z',
		else len = len + 'a' - 26 - 1;
}

	while (len) {
			if (--bytes == 0)
		buf += 5;
	'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
			ch = *buffer++;
		decode_85(buf, av[2]+1, len);
		}
		say1(" %08x", acc);
	}
	}
		int len = *av[2];
		say1(" %08x", acc);
	';', '<', '=', '>', '?', '@', '^', '_',	'`', '{',
#define say1(a,b) do { /* nothing */ } while (0)
}
		do {
	prep_base85();
				break;
		unsigned char ch;
			de = de85[ch];
	'!', '#', '$', '%', '&', '(', ')', '*', '+', '-',
#endif
		} while (--cnt);
void encode_85(char *buf, const unsigned char *data, int bytes)
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',

	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
#ifdef DEBUG_85
{
		if (0xffffffff / 85 < acc ||
{
		char t[4] = { -1,-1,-1,-1 };
#include "cache.h"

#undef DEBUG_85
			acc = (acc << 8) | (acc >> 24);
	if (!strcmp(av[1], "-d")) {

		/* Detect overflow. */
	if (de85['Z'])

}
#define say2(a,b,c) fprintf(stderr, a, b, c)

		} while (--cnt);
		ch = *buffer++;
			buf[cnt] = en85[val];
	}
		printf("encoded: D%s\n", buf);
	return 0;
		do {
	char buf[1024];
		if ('A' <= len && len <= 'Z') len = len - 'A' + 1;
			return error("invalid base85 alphabet %c", ch);
{
	while (bytes) {
		}
	'|', '}', '~'
#ifdef DEBUG_85
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
#define say2(a,b,c) do { /* nothing */ } while (0)
		cnt = (len < 4) ? len : 4;
	}
	}
static void prep_base85(void)
		return 0;
{
	int i;
	say("\n");
			acc |= ch << cnt;
	if (!strcmp(av[1], "-t")) {

		for (cnt = 24; cnt >= 0; cnt -= 8) {
	for (i = 0; i < ARRAY_SIZE(en85); i++) {
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
		len -= cnt;
		printf("encoded: %c%s\n", len, buf);
			acc = acc * 85 + de;
	*buf = 0;
		printf("decoded: %.*s\n", len, buf);
		int de, cnt = 4;
		else len = len - 'a' + 26 + 1;
#define say(a) do { /* nothing */ } while (0)
	say2("decode 85 <%.*s>", len / 4 * 5, buffer);
		return 0;

}
		encode_85(buf, av[2], len);
	'U', 'V', 'W', 'X', 'Y', 'Z',
		if (--de < 0)

		acc += de;
static const char en85[] = {
		    0xffffffff - de < (acc *= 85))
		int len = strlen(av[2]);
		return;
		encode_85(buf, t, 4);
		return 0;
	say("\n");
	if (!strcmp(av[1], "-e")) {
