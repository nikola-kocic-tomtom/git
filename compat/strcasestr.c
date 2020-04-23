			if (toupper(c1) != toupper(c2))
	}
	int hlen = strlen(haystack) - nlen + 1;
		}

	int i;
	int nlen = strlen(needle);
#include "../git-compat-util.h"
	return NULL;
char *gitstrcasestr(const char *haystack, const char *needle)
			unsigned char c2 = needle[j];
	next:
}
				goto next;
		for (j = 0; j < nlen; j++) {
			unsigned char c1 = haystack[i+j];
	for (i = 0; i < hlen; i++) {
		;
		return (char *) haystack + i;

		int j;
{
