  register struct _obstack_chunk *new_chunk;
  register struct _obstack_chunk *lp;	/* below addr of any objects in this chunk */
}
    DEFAULT_ALIGNMENT = offsetof (struct fooalign, u),
    }

      size = 4096 - extra;
#   define __attribute__(Spec) /* empty */
  if (!new_chunk)
      plp = lp->prev;
_obstack_memory_used (struct obstack *h)
int _obstack_allocated_p (struct obstack *h, void *obj);
		  void *arg)
  chunk->prev = NULL;
   do not allow (expr) ? void : void.  */
  /* The initial chunk now contains no empty object.  */
    (*obstack_alloc_failed_handler) ();
   License as published by the Free Software Foundation; either
int
		   & ~(DEFAULT_ROUNDING - 1));

#include "obstack.h"
      CALL_FREEFUN (h, lp);
		    + 4 + DEFAULT_ROUNDING - 1)
   This is here for debugging.

    /* Default size is what GNU malloc can fit in a 4096-byte block.  */
# ifdef _LIBC

# endif
  return lp != NULL;
   called by non-GCC compilers.  */

  lp = h->chunk;
  long double d;

	   i >= 0; i--)

void (*obstack_alloc_failed_handler) (void) = print_and_abort;
#  include <stdint.h>


   modify it under the terms of the GNU Lesser General Public
  new_chunk->prev = old_chunk;
    /* Default size is what GNU malloc can fit in a 4096-byte block.  */
  for (i = already; i < obj_size; i++)
	 allocated.
# endif
}
# if HAVE_INTTYPES_H
   Objects start on multiples of ALIGNMENT (0 means use default).
# ifndef COPYING_UNIT
  h->alloc_failed = 0;
      already = obj_size / sizeof (COPYING_UNIT) * sizeof (COPYING_UNIT);

   variable by default points to the internal function
  do { \
      && (h->object_base

#endif
   This file is part of the GNU C Library.
    alignment = DEFAULT_ALIGNMENT;

  };

	 and we used a larger request, a whole extra 4096 bytes would be
      /* 12 is sizeof (mhead) and 4 is EXTRA from GNU malloc.

#define OBSTACK_INTERFACE_VERSION 1
  void *p;
   On some machines, copying successive ints does not work;
   (that adds an extra first argument), based on the state of use_extra_arg.
      CALL_FREEFUN (h, old_chunk);
  h->object_base = object_base;
# ifdef _LIBC
      /* We used to copy the odd few remaining bytes as one extra COPYING_UNIT,
    }
   Copyright (C) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1996, 1997, 1998,
  h->use_extra_arg = 0;
enum
    (*obstack_alloc_failed_handler) ();
    }
/* If malloc were really smart, it would round addresses to DEFAULT_ALIGNMENT.
      plp = lp->prev;
	  == __PTR_ALIGN ((char *) old_chunk, old_chunk->contents,
	 which does not do strict alignment for COPYING_UNITS.  */
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU

	((COPYING_UNIT *)object_base)[i]
   DEFAULT_ROUNDING.  So we prepare for it to do that.  */
#  if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
  h->maybe_empty_object = 0;

      /* 12 is sizeof (mhead) and 4 is EXTRA from GNU malloc.

  h->next_free = h->object_base + obj_size;
  h->freefun.extra = (void (*) (void *, struct _obstack_chunk *)) freefun;

      h->chunk = lp;
}
    {

	 Use the values for range checking, because if range checking is off,

   Copies any partial object from the end of the old chunk
strong_alias (obstack_free, _obstack_free)
# endif
    if ((h) -> use_extra_arg) \
   and linking in this code is a waste when using the GNU C library
   library still exports it because somebody might use it.  */
      lp = plp;
  if (size == 0)
  /* The new chunk certainly contains no empty object yet.  */
  register struct _obstack_chunk *plp;	/* point to previous chunk if any */
  /* Compute size for new chunk.  */
/* Older versions of libc used a function _obstack_free intended to be

libc_hidden_def (_obstack_newchunk)
   files, it is simpler to just do this in the source for each such file.  */
/* A looong time ago (before 1994, anyway; we're not sure) this global variable
    = (char *) chunk + h->chunk_size;
      for (i = obj_size / sizeof (COPYING_UNIT) - 1;
   C Library, but also included in many other GNU distributions.  Compiling
      h->chunk_limit = lp->limit;
{
  new_chunk = CALL_CHUNKFUN (h, new_size);
   was used by non-GNU-C macros to avoid multiple evaluation.  The GNU C
# include <gnu-versions.h>
  while (lp != NULL && ((void *) lp >= obj || (void *) (lp)->limit < obj))
      /* If we switch chunks, we can't tell whether the new current
  if (new_size < h->chunk_size)
	 the extra bytes won't be missed terribly, but if range checking is on
compat_symbol (libc, _obstack_compat, _obstack, GLIBC_2_0);

_obstack_begin_1 (struct obstack *h, int size, int alignment,
   You should have received a copy of the GNU Lesser General Public
  h->chunkfun.extra = (struct _obstack_chunk * (*)(void *,long)) chunkfun;
struct fooalign
int
   ? (*(h)->chunkfun.extra) ((h)->extra_arg, (size)) \
  /* Move the existing object to the new chunk.

#  include <libio/iolibio.h>
  chunk = h->chunk = CALL_CHUNKFUN (h, h -> chunk_size);
  h->alignment_mask = alignment - 1;
    DEFAULT_ROUNDING = sizeof (union fooround)
  h->chunkfun.plain = chunkfun;

# endif
#  if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_3_4)
    {
#include "git-compat-util.h"
      new_chunk->prev = old_chunk->prev;
  register struct _obstack_chunk *lp;	/* below addr of any objects in this chunk */
#include <gettext.h>
#  define COPYING_UNIT int
    {
    object_base[i] = h->object_base[i];

	  = ((COPYING_UNIT *)h->object_base)[i];
/* Allocate a new current chunk for the obstack *H

  (void) __fxprintf (NULL, "%s\n", _("memory exhausted"));
		    + 4 + DEFAULT_ROUNDING - 1)
      int extra = ((((12 + DEFAULT_ROUNDING - 1) & ~(DEFAULT_ROUNDING - 1))
  object_base =

  h->use_extra_arg = 1;
# endif

  register long i;
   If you use it in a program, you are probably losing.  */
{

}
# if _GNU_OBSTACK_INTERFACE_VERSION == OBSTACK_INTERFACE_VERSION
  for (lp = h->chunk; lp != NULL; lp = lp->prev)
  /* We use >= because there cannot be an object at the beginning of a chunk.

_obstack_begin (struct obstack *h,
  h->chunk_size = size;
  register struct _obstack_chunk *chunk; /* points to new chunk */
   Return nonzero if successful, calls obstack_alloc_failed_handler if
    else \
  (((h) -> use_extra_arg) \
{
# ifndef __attribute__
  /* We use >= rather than > since the object cannot be exactly at
   Lesser General Public License for more details.
   But in fact it might be less smart and round addresses to as much as
{
  register struct _obstack_chunk *chunk; /* points to new chunk */
   allocation fails.  */
  register long	new_size;

void
}
    (*obstack_alloc_failed_handler) ();
     at the end of an adjacent chunk.  */
    alignment = DEFAULT_ALIGNMENT;
union fooround
      h->object_base = h->next_free = (char *) (obj);
  return 1;
     is sufficiently aligned.  */
# else
# endif
#  define ELIDE_CODE
# ifdef _LIBC

void
					       alignment - 1);
}
   The GNU C Library is distributed in the hope that it will be useful,
# endif
  h->maybe_empty_object = 0;
  h->chunk_size = size;
  uintmax_t i;
  chunk->prev = NULL;
   obstack.h because it is just for debugging.  */
     free that chunk and remove it from the chain.
	 less sensitive to the size of the request.  */

   and FREEFUN the function to free them.
   longer properly call the functions in this obstack.c.  */
   version 2.1 of the License, or (at your option) any later version.
   : (*(h)->chunkfun.plain) ((size)))
     But there can be an empty object at that address
_obstack_newchunk (struct obstack *h, int length)
static void print_and_abort (void);
	 and we used a larger request, a whole extra 4096 bytes would be
  h->next_free = h->object_base = __PTR_ALIGN ((char *) chunk, chunk->contents,
  /* If the object just copied was the only data in OLD_CHUNK,
	 These number are irrelevant to the new GNU malloc.  I suspect it is

#  endif
/* This feature is available in gcc versions 2.5 and later.  */
};
    }
  if (!chunk)
  h->chunk_limit = chunk->limit
    {
/* NOTE BEFORE MODIFYING THIS FILE: This version number must be
    already = 0;
					       alignment - 1);
     the beginning of the chunk but might be an empty object exactly
	 allocated.
/* obstack.c - subroutines used implicitly by object stack macros
    {
int


   to the current object, or a new object of length LENGTH allocated.
  h->chunk = new_chunk;

/* Suppress -Wmissing-prototypes warning.  We don't want to declare this in
  if (alignment == 0)
	 These number are irrelevant to the new GNU malloc.  I suspect it is
   For free, do not use ?:, since some compilers, like the MIPS compilers,
/* When we copy a long block of data, this is the unit to do it with.
   program understand `configure --with-gnu-libc' and omit the object
   supports the same library interface we do.  This code is part of the GNU
#if !defined _LIBC && defined __GNU_LIBRARY__ && __GNU_LIBRARY__ > 1
  /* Don't change any of these strings.  Yes, it would be possible to add
# endif
# endif
{
#include <stdio.h>		/* Random thing to get __GNU_LIBRARY__.  */
  {
  return 1;
# endif
   incremented whenever callers compiled using an old obstack.h can no
# ifdef _LIBC
    {
  register struct _obstack_chunk *plp;	/* point to previous chunk if any */
  fprintf (stderr, "%s\n", _("memory exhausted"));
# ifdef _LIBC
      nbytes += lp->limit - (char *) lp;
    }
    new_size = h->chunk_size;
   1999, 2000, 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.
		void (*freefun) (void *))
  h->chunk_limit = chunk->limit
   `print_and_abort'.  */
  char *object_base;
	 but that can cross a page boundary on a machine
      h->maybe_empty_object = 1;
  h->next_free = h->object_base = __PTR_ALIGN ((char *) chunk, chunk->contents,
  union fooround u;
  else
   jump to the handler pointed to by `obstack_alloc_failed_handler'.
   This can be set to a user defined function which should either


obstack_free (struct obstack *h, void *obj)
  h->alignment_mask = alignment - 1;
   more recently than OBJ.  If OBJ is zero, free everything in H.  */
int
    }
  /* Compute an aligned object_base in the new chunk */
  if (! h->maybe_empty_object
	 the extra bytes won't be missed terribly, but if range checking is on
    __PTR_ALIGN ((char *) new_chunk, new_chunk->contents, h->alignment_mask);
     the newline to the string and use fputs or so.  But this must not

{

# define CALL_FREEFUN(h, old_chunk) \
  h->extra_arg = arg;
   to the beginning of the new one.  */
     But not if that chunk might contain an empty object.  */
  /* Copy remaining bytes one by one.  */
		void *(*chunkfun) (long),

      int extra = ((((12 + DEFAULT_ROUNDING - 1) & ~(DEFAULT_ROUNDING - 1))
/* The functions allocating more room by calling `obstack_chunk_alloc'

  else if (obj != NULL)
  register struct _obstack_chunk* lp;
   on the assumption that LENGTH bytes need to be added
      (*(h)->freefun.plain) ((old_chunk)); \
			  h->alignment_mask)))
	 Use the values for range checking, because if range checking is off,

_obstack_allocated_p (struct obstack *h, void *obj)
		int size, int alignment,

  if (lp)
	 less sensitive to the size of the request.  */
      lp = plp;
   (especially if it is a shared library).  Rather than having every GNU
  if (!chunk)
     Word at a time is fast and is safe if the object
   calling interface, or calls functions with the mmalloc/mfree interface
/* Initialize an obstack H for use.  Specify chunk size SIZE (0 means default).
     at the end of another chunk.  */
		   & ~(DEFAULT_ROUNDING - 1));
{
  lp = (h)->chunk;
  long already;
{
/* Determine default alignment.  */
     a very similar string which requires a separate translation.  */
  if (alignment == 0)
#  include <inttypes.h>
  register int nbytes = 0;
  if (size == 0)
     like this and the translation should be reused instead of creating
    abort ();

    /* obj is not in any of the chunks! */
# define CALL_CHUNKFUN(h, size) \
};
  register long obj_size = h->next_free - h->object_base;
  exit (1);
{
   abort gracefully or use longjump - but shouldn't return.  This
#include <stddef.h>
/* Comment out all this code if we are using the GNU C Library, and are not

    {
		  void *(*chunkfun) (void *, long),

  while (lp != NULL && ((void *) lp >= obj || (void *) (lp)->limit < obj))
     happen because the "memory exhausted" message appears in other places
}
   but WITHOUT ANY WARRANTY; without even the implied warranty of
  chunk = h->chunk = CALL_CHUNKFUN (h, h -> chunk_size);
  h->alloc_failed = 0;

		  void (*freefun) (void *, void *),
  h->maybe_empty_object = 0;
# if HAVE_STDINT_H || defined _LIBC

  new_chunk->limit = h->chunk_limit = (char *) new_chunk + new_size;
print_and_abort (void)
    = (char *) chunk + h->chunk_size;
/* Return nonzero if object OBJ has been allocated from obstack H.
   CHUNKFUN is the function to use to allocate chunks,
  /* Allocate and initialize the new chunk.  */
   actually compiling the library itself, and the installed library
  /* The initial chunk now contains no empty object.  */

  return nbytes;
  char c;
struct obstack *_obstack_compat;
    }
  h->freefun.plain = freefun;
#endif	/* !ELIDE_CODE */
# undef obstack_free
      (*(h)->freefun.extra) ((h)->extra_arg, (old_chunk)); \
   <http://www.gnu.org/licenses/>.  */
    }
  if (h->alignment_mask + 1 >= DEFAULT_ALIGNMENT)

  new_size = (obj_size + length) + (obj_size >> 3) + h->alignment_mask + 100;
   The GNU C Library is free software; you can redistribute it and/or
/* Define a macro that either calls functions with the traditional malloc/free
   or `char' as a last resort.  */
static void
  } while (0)
   License along with the GNU C Library; if not, see
/* Free objects in obstack H, including OBJ and everything allocate

   in such a case, redefine COPYING_UNIT to `long' (if that works)

      size = 4096 - extra;

  register struct _obstack_chunk *old_chunk = h->chunk;
#  endif

#ifndef ELIDE_CODE
	 chunk contains an empty object, so assume that it may.  */
    {
