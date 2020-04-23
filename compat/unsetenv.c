     size_t nmln;
	  environ[dst] = environ[src];
	  }
#endif
     environ[dst] = NULL;
	       if (0 == strncmp (environ[src], name, nmln)
     }
		    continue;

     nmln = strlen(name);
     for (src = dst = 0; environ[src]; ++src) {

	  if (enln > nmln) {
void gitunsetenv (const char *name)
#include "../git-compat-util.h"
		    /* matches, so skip */
	  ++dst;
		   && '=' == environ[src][nmln])
	  size_t enln;
     int src, dst;
}

#if !defined(__MINGW32__)
	  enln = strlen(environ[src]);
               /* might match, and can test for '=' safely */
{
     extern char **environ;
