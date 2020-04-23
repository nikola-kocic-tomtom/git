}
	rc = 1;
	TEST_CLASS(isdigit, DIGIT);


int cmd__ctype(int argc, const char **argv)
	TEST_CLASS(is_regex_special, "$()*+.?[\\^{|");
			report_error(#t, i);	\
	for (i = 0; i < 256; i++) {		\
	TEST_CLASS(is_pathspec_magic, "!\"#%&',-/:;<=>@_`~");

		if (is_in(s, i) != t(i))	\
#define UPPER "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

{

static int rc;
}

{
#define DIGIT "0123456789"
	TEST_CLASS(isalpha, LOWER UPPER);

	int i;					\
#define TEST_CLASS(t,s) {			\
	}					\
	TEST_CLASS(isalnum, LOWER UPPER DIGIT);
	/* We can't find NUL using strchr.  It's classless anyway. */
#include "cache.h"
static void report_error(const char *class, int ch)
	printf("%s classifies char %d (0x%02x) wrongly\n", class, ch, ch);
	TEST_CLASS(isspace, " \n\r\t");
static int is_in(const char *s, int ch)
	return !!strchr(s, ch);
}
	TEST_CLASS(is_glob_special, "*?[\\");
#define LOWER "abcdefghijklmnopqrstuvwxyz"
{
	return rc;
#include "test-tool.h"
	if (ch == '\0')
}
		return 0;
