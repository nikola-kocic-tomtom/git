		}
	    j1 = j + 1;
#include "git-compat-util.h"

print_variable (const char *var_ptr, size_t var_len)
	      else
{
string_list_append (string_list_ty *slp, const char *s)

   ${VARIABLE} construct is seen, where VARIABLE is a nonempty sequence
  exit (EXIT_SUCCESS);
	  /* echo '$foo and $bar' | git sh-i18n--envsubst --variables '$foo and $bar' */
    {
   Copyright (C) 2003-2007 Free Software Foundation, Inc.
 * This is a modified version of
   implemented using a dynamic array.  */
		  if (buflen >= bufmax)
    {
		    putchar ('{');
 * 8dac033df0:gnulib-local/lib/closeout.c. The copyright notices for
		  buffer[buflen++] = c;
	      }
  if (c == EOF)
		  {
   encoding, it doesn't look like one in the BIG5, BIG5-HKSCS, GBK, GB18030,
	  else if (result == 0)
	  break;
	      while ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	case 2:
cmd_main (int argc, const char *argv[])
	      buflen = 0;
		{

	  if (c == '{')
      if (ferror (stdin))
		  if (opening_brace)
  if (c != EOF)
		}
}
   We allow only ASCII characters, to avoid dependencies w.r.t. the current
{
   GNU General Public License for more details.
 * 67d0871a8c:gettext-runtime/src/envsubst.c from the gettext.git
/* Print a variable to stdout, followed by a newline.  */

/* Substitution of environment variables in shell format strings.

  string_list_sort (&variables_set);
	      callback (variable_start, variable_end - variable_start);
 *
note_variables (const char *string)
	    {



      print_variables (argv[2]);

string_list_sort (string_list_ty *slp)
	  int result = strcmp (slp->item[j], s);

}
 *
	error ("error while reading standard input");
	    variable_end = string;
typedef struct string_list_ty string_list_ty;

		    }
		  if (c == '}')
      /* Binary search.  */
	putchar (c);
{
      subst_from_stdin ();
   This program is distributed in the hope that it will be useful,
		{

{
struct string_list_ty
  size_t j1, j2;

/* Initialize an empty list of strings.  */
		  /* Perform no substitution at all.  Since the buffered input
		      buffer = xrealloc (buffer, bufmax);

   You should have received a copy of the GNU General Public License
	if (strcmp (slp->item[j1], s) == 0)
		putchar ('{');
	unsigned short int valid;

	    if (valid)
	break;

/* Print the variables contained in STRING to stdout, each one followed by a
cmp_string (const void *pstr1, const void *pstr2)
do_getc (void)
   This program is free software; you can redistribute it and/or modify
    {
		  if (!all_variables

	const char *variable_start;
  static size_t buflen;
		      && !sorted_string_list_member (&variables_set, buffer))
static void
		      closing_brace = 1;
}
	      opening_brace = 1;
 * both files are reproduced immediately below.
}
}

/* Append a single string to the end of a list of strings.  */
	      {
   GNU General Public License for more details.
		      bufmax = 2 * bufmax + 10;
int
  slp->nitems = 0;
		     output all the buffered contents.  */
  size_t nitems_max;
	  else
  if (fclose (stderr) && errno != EBADF)
/* Test whether a sorted string list contains a given string.  */
	      if (valid)
{

  string_list_init (&variables_set);
		    {
  char *string = xmemdupz (var_ptr, var_len);
  j1 = 0;
  string_list_append (&variables_set, string);
find_variables (const char *string,
		  c = do_getc ();
{
string_list_init (string_list_ty *slp)
static int
		    valid = 1;
note_variable (const char *var_ptr, size_t var_len)
#include "trace2.h"
   along with this program; if not, see <http://www.gnu.org/licenses/>.  */
  for (;;)
{
  QSORT(slp->item, slp->nitems, cmp_string);
   but WITHOUT ANY WARRANTY; without even the implied warranty of
		  buffer[buflen] = '\0';

		  putchar ('$');
  slp->nitems_max = 0;
  slp->item[slp->nitems++] = s;
	  /* Here we know that if s is in the list, it is at an index j
/* If true, substitution shall be performed on all variables.  */
	  unsigned short int closing_brace = 0;
   alphabetic/underscore character.
   This program is free software; you can redistribute it and/or modify

	  string++;
	if (*string == '{')
		    {
  errno = 0;
	  {
    {
static void
	{
  /* Default values for command line options.  */

		  /* Test whether the variable shall be substituted.  */


/* Copies stdin to stdout, performing substitutions.  */
		     || (c >= '0' && c <= '9') || c == '_');
  putchar ('\n');
   Written by Bruno Haible <bruno@clisp.org>, 2003.
{
     upon failure we don't need an errno - all we can do at this point is to
	  break;
	      c = *++string;

   encodings.  */
static inline void
	  if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_')
	  /*
  j2 = slp->nitems;
		}
		    }

	      do_ungetc (c);
   of ASCII alphanumeric/underscore characters, starting with an ASCII
	{
{
	    }
  return strcmp (str1, str2);
}
 * The "Close standard error" part in main() is from
	variable_start = string;
static void print_variables (const char *string);
  /* Add the string to the end of the list.  */
#include <string.h>
subst_from_stdin (void)
		      buffer = xrealloc (buffer, bufmax);
		     contains no other '$' than at the start, we can just

	  */
	      if (valid)

#include <stdlib.h>
	  all_variables = 0;
		   || (c >= '0' && c <= '9') || c == '_');
		  valid = 1;
  int c;
/* closeout.c - close standard output and standard error
   any later version.
}
      c = do_getc ();
		  if (env_value != NULL)

  return c;
  /* Grow the list.  */
print_variables (const char *string)
{
}

  return 0;
	case 1:
		}
}
   along with this program; if not, see <http://www.gnu.org/licenses/>.  */
  const char **item;



	  unsigned short int opening_brace = 0;
{
	  size_t j = j1 + ((j2 - j1) >> 1);
	  else
	  if (strcmp(argv[1], "--variables"))
static void note_variables (const char *string);
/* Adds a variable to variables_set.  */
do_ungetc (int c)
   the Free Software Foundation; either version 2, or (at your option)
static int
}

 *
static void subst_from_stdin (void);
	    return 1;
		    valid = 0;
  for (; *string != '\0';)
static string_list_ty variables_set;
  slp->item = NULL;
/* Type describing list of immutable strings,
	    while ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
/* Stores the variables occurring in the string in variables_set.  */
 * Copyright (C) 2010 Ævar Arnfjörð Bjarmason
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  fwrite (var_ptr, var_len, 1, stdout);
      fclose (stderr);
		    {
      REALLOC_ARRAY(slp->item, slp->nitems_max);

	      c = do_getc ();
		  /* Terminate the variable in the buffer.  */
	}
	    if (variable_start[-1] == '{')

    exit (EXIT_FAILURE);
static inline void
		  /* Substitute the variable's value from the environment.  */
	    else
   This program is distributed in the hope that it will be useful,
		{
/* Forward declaration of local functions.  */
  switch (argc)
}
	}
  /* Close standard error.  This is simpler than fwriteerror_no_ebadf, because
	      if (opening_brace)
		    fputs (env_value, stdout);
      }
#include <stdio.h>
		  valid = 0;
  find_variables (string, &print_variable);
    {
   SHIFT_JIS, JOHAB encodings, because \xe0\x7d is a single character in these

   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * sh-i18n--envsubst.c - a stripped-down version of gettext's envsubst(1)
   any later version.
      {
		  }
sorted_string_list_member (const string_list_ty *slp, const char *s)
	      putchar ('$');
	    {
	  c = do_getc ();
/*
 */
		  do_ungetc (c);

  static char *buffer;
		  fwrite (buffer, buflen, 1, stdout);
  /* unsigned short int show_variables = 0; */

		void (*callback) (const char *var_ptr, size_t var_len))
/* Sort a list of strings.  */
		    }
   it under the terms of the GNU General Public License as published by
	     with j1 <= j < j2.  */
   encoding: While "${\xe0}" looks like a variable access in ISO-8859-1
static inline void

{
      exit (EXIT_FAILURE);
	    do
	    }

		    {
	if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_')
  find_variables (string, &note_variable);
	      do
static void


   Used only if !all_variables.  */
		}
      else
	      else
      if (c == '$')
      if (c == EOF)
      if (j2 > j1)
    }
	  break;
		    putchar ('}');
/* Set of variables on which to perform substitution.
		      valid = 0;
{
    ungetc (c, stdin);
static unsigned short int all_variables;


		      valid = 1;
      while (j2 - j1 > 1)
static void
  if (slp->nitems >= slp->nitems_max)
    if (*string++ == '$')

};
	default:
		else
		error ("first argument must be --variables when two are given");
		  else
 * envsubst(1) features that we need in the git-sh-i18n fallbacks.

	case 3:
      subst_from_stdin ();
	  error ("too many arguments");
static inline void
	  if (result > 0)
	char c;
   newline.  */
	    {

	  break;
   You should have received a copy of the GNU General Public License
   Copyright (C) 1998-2007 Free Software Foundation, Inc.
	c = *string;

    }
/* Parse the string and invoke the callback each time a $VARIABLE or
  const char *str1 = *(const char **)pstr1;
	  all_variables = 1;
  const char *str2 = *(const char **)pstr2;
  static size_t bufmax;
	}

		{
	      /* Accumulate the VARIABLE in buffer.  */
	  note_variables (argv[1]);
#include <errno.h>
	  error ("we won't substitute all variables on stdin for you");
		  const char *env_value = getenv (buffer);

		{
	      unsigned short int valid;
  trace2_cmd_name("sh-i18n--envsubst");
    }
      slp->nitems_max = slp->nitems_max * 2 + 4;
}
		  if (buflen >= bufmax)

		    }

   it under the terms of the GNU General Public License as published by
		      bufmax = 2 * bufmax + 10;
     set an exit status.  */
		{
    }
static void
		      do_ungetc (c);
    }
		  if (closing_brace)
static void
{
	{

}
	const char *variable_end;
  if (ferror (stderr) || fflush (stderr))
		if (*string == '}')
	    }
	  /* show_variables = 1; */
		}
}

	      valid = 1;
	  return 1;
{
	  /* git sh-i18n--envsubst --variables '$foo and $bar' */
		    string++;
   but WITHOUT ANY WARRANTY; without even the implied warranty of
/* Compare two strings given by reference.  */
	    j2 = j;
	      if (opening_brace)
static int
      /* Look for $VARIABLE or ${VARIABLE}.  */
 * repository. It has been stripped down to only implement the
  if (j2 > 0)
  int c = getc (stdin);
	  }
   the Free Software Foundation; either version 2, or (at your option)

  size_t nitems;
