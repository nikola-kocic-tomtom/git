	if (retval && *retval)
		return "UTF-8";
	/*
#		define locale_charset() nl_langinfo(CODESET)

#	include <locale.h>
		return retval;
/*
	if (!podir)
		env = getenv("LANG");
	   Then we could simply set LC_CTYPE from the environment, which would
	va_start(ap, fmt);
static void init_gettext_charset(const char *domain)
#	elif defined HAVE_LIBCHARSET_H
	   This primarily done to avoid a bug in vsnprintf in the GNU C
		env = getenv("LC_CTYPE");
 */
#ifndef NO_GETTEXT
	   characters get encoded to question marks.
	   requested encoding, but avoids setting LC_CTYPE from the
	if (!env)
		poison_requested = git_env_bool("GIT_TEST_GETTEXT_POISON", 0);

	   functions whose semantics are modified by LC_CTYPE.
#ifndef NO_GETTEXT
}
		   setlocale(LC_MESSAGES, "");
static const char *locale_charset(void)

#include "config.h"
	   bind_textdomain_codeset. That suffices to tell gettext what
	   drawbacks (changed semantics for C functions we rely on).
		if (!env || !*env)
	if (!charset) {
	if (!is_directory(podir)) {
	   without LC_CTYPE it'll emit something like this on 'git init'
#	ifdef GIT_WINDOWS_NATIVE
/*
	   this point, because it'd require auditing all the code that uses C
 * The result can be a colon-separated list like "ko:ja:en".
#	include <libintl.h>
	   #include <errno.h>
			env = strchr(env, '.') + 1;
#include "exec-cmd.h"
	free(p);
}

	if (retval && *retval &&

 *
}
	bindtextdomain("git", podir);
}
			env = getenv("LANG");
{

const char *get_preferred_languages(void)
	   Gettext knows about the encoding of our PO file, but we haven't
		if (!env || !*env)
	ret = vsnprintf(buf, sizeof(buf), fmt, ap);


	static int poison_requested = -1;
#endif
		strcmp(retval, "POSIX"))
	return is_utf8 ? utf8_strwidth(s) : strlen(s);
	dot = strchr(env, '.');
}
		   errno = ENODEV;
	static int is_utf8 = -1;
	char *p = NULL;
	init_gettext_charset("git");
#ifndef NO_GETTEXT
 * variable and LC_MESSAGES locale category if NO_GETTEXT is not defined.
	   environment for the whole program.

	if (!env || !*env)

	   we declare the encoding of our PO files[2] the gettext
		setlocale(LC_CTYPE, "C");

	   argument, due to mismatch between the data encoding and the

		free(p);

		return retval;
	   And the equivalent ISO-8859-1 string will be emitted under a




	const char *podir = getenv(GIT_TEXT_DOMAIN_DIR_ENVIRONMENT);
/* return the number of columns of string 's' in current locale */
		return;
}
	   implementation will try to recode it to the user's locale, but

#ifdef NO_GETTEXT
	return poison_requested;
	const char *retval;
	va_list ap;

		   return 0;
int is_utf8_locale(void)

	}
	const char *env = getenv("LC_ALL"), *dot;
		const char *env = getenv("LC_ALL");

	if (test_vsnprintf("%.*s", 13, "David_K\345gedal") < 0)
void git_setup_gettext(void)
	if (is_utf8 == -1)

	   #include <locale.h>
	setlocale(LC_MESSAGES, "");
 * Guess the user's preferred languages from the value in LANGUAGE environment
		strcmp(retval, "C") &&
	   #include <stdio.h>
{
 * Copyright (c) 2010 Ævar Arnfjörð Bjarmason
	va_end(ap);
	retval = setlocale(LC_MESSAGES, NULL);
#		include <libcharset.h>
	   told it about the user's encoding, so all the non-US-ASCII
#endif
	setlocale(LC_TIME, "");
	   That commit contains a ISO-8859-1 encoded author name, which
	   Running that will give you a message with question marks:

int gettext_width(const char *s)
{
 */
		charset = xstrdup(env);

	   1. http://sourceware.org/bugzilla/show_bug.cgi?id=6530
	use_gettext_poison(); /* getenv() reentrancy paranoia */

	   ISO-8859-1 locale.

{
	   encoding it should emit in, so it'll now say:
	/* the string is taken from v0.99.6~1 */
		is_utf8 = is_utf8_locale();

static const char *charset;
	return !dot ? env : dot + 1;
	   $ LANGUAGE= LANG=de_DE.utf8 ./test

#endif
		if (strchr(env, '.'))

	   However foreign functions using other message catalogs that
	   2. E.g. "Content-Type: text/plain; charset=UTF-8\n" in po/is.po
	   the locale aware vsnprintf(3) won't interpolate in the format
#include "gettext.h"
	   Even if it wasn't for that bug we wouldn't want to use LC_CTYPE at
		if (!env)

{
		   perror("test");
	}


	   regression tests.
	textdomain("git");
{


}
	bind_textdomain_codeset(domain, charset);
{

	   But we're in luck! We can set LC_CTYPE from the environment
			env = getenv("LC_CTYPE");
	charset = locale_charset();
	return is_encoding_utf8(charset);
#include "cache.h"

	   locale.
	int ret;
	       Bj? til t?ma Git lind ? /hlagh/.git/
	return ret;
	       Bjó til tóma Git lind í /hlagh/.git/
	   }
	   {
	   int main(void)
	   Library [1]. which triggered a "your vsnprintf is broken" error
#endif
	   (talk to the user in his language/encoding), without the major
	   This trick arranges for messages to be emitted in the user's
		podir = p = system_path(GIT_LOCALE_PATH);
	   on Git's own repository when inspecting v0.99.6~1 under a UTF-8
	   under the Icelandic locale:
	   only while we call nl_langinfo and

	   test: Kein passendes Ger?t gefunden
int use_gettext_poison(void)
	   See t/t0203-gettext-setlocale-sanity.sh's "gettext.c" tests for
	retval = getenv("LANGUAGE");
			env = "";
#		include <langinfo.h>

	   locale.
	setlocale(LC_CTYPE, "");
	   But only setting LC_MESSAGES as we do creates a problem, since

#	else
	return NULL;
	   The vsnprintf bug has been fixed since glibc 2.17.
	*/

	   we have to call perror(3):
	if (poison_requested == -1)
{
	   aren't using our neat trick will still have a problem, e.g. if
}
#	endif

	   make things like the external perror(3) messages work.
#include "utf8.h"

	   With this change way we get the advantages of setting LC_CTYPE

#include "strbuf.h"
static int test_vsnprintf(const char *fmt, ...)
	if (!env || !*env)
	char buf[26];
		   setlocale(LC_CTYPE, "C");
