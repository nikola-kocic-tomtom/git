   The GNU C Library is distributed in the hope that it will be useful,
#ifdef HAVE_CONFIG_H
   version 2.1 of the License, or (at your option) any later version.
# define re_compile_fastmap(bufp) __re_compile_fastmap (bufp)
#endif
	__re_match_2 (bufp, string1, size1, string2, size2, pos, regs, stop)


   License as published by the Free Software Foundation; either
/* Binary backward compatibility.  */
#if _LIBC
	__re_search (bufp, string, size, startpos, range, regs)
#include "regex_internal.h"
# define regfree(preg) __regfree (preg)
   This file is part of the GNU C Library.
int re_max_failures = 2000;
   Contributed by Isamu Hasegawa <isamu@yamato.ibm.com>.
#endif
   License along with the GNU C Library; if not, see
#include <limits.h>
#include "regex_internal.c"
   modify it under the terms of the GNU Lesser General Public
#define false (0)
#include <regex.h>
/* Extended regular expression matching and search library.
   You should have received a copy of the GNU Lesser General Public
# if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_3)
   The GNU C Library is free software; you can redistribute it and/or
#endif
# define re_set_registers(bu, re, nu, st, en) \

#ifdef GAWK

   GNU regex allows.  Include it before <regex.h>, which correctly
	__re_match (bufp, string, size, pos, regs)
#ifdef __cplusplus
# define re_search(bufp, string, size, startpos, range, regs) \
#ifdef _LIBC
#include <stdint.h>
#define alloca alloca_is_bad_you_should_never_use_it


#include "regcomp.c"
# define re_compile_pattern(pattern, length, bufp) \
   but WITHOUT ANY WARRANTY; without even the implied warranty of

   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	__re_compile_pattern (pattern, length, bufp)
	__re_search_2 (bufp, st1, s1, st2, s2, startpos, range, regs, stop)
# define re_search_2(bufp, st1, s1, st2, s2, startpos, range, regs, stop) \
# include <shlib-compat.h>
# define re_match_2(bufp, string1, size1, string2, size2, pos, regs, stop) \
   Lesser General Public License for more details.
#define true (1)
/* On some systems, limits.h sets RE_DUP_MAX to a lower value than
# include "../locale/localeinfo.h"
#define bool int

/* We have to keep the namespace clean.  */

#ifdef GAWK
   Copyright (C) 2002, 2003, 2005 Free Software Foundation, Inc.
# define re_set_syntax(syntax) __re_set_syntax (syntax)
#include "config.h"
#if defined (_MSC_VER)
# define regexec(pr, st, nm, pm, ef) __regexec (pr, st, nm, pm, ef)
	__re_set_registers (bu, re, nu, st, en)
# error "This is C code, use a C compiler"
   <http://www.gnu.org/licenses/>.  */
# define regerror(errcode, preg, errbuf, errbuf_size) \
#undef alloca

#endif
#include "regexec.c"
#include <stdio.h> /* for size_t */
# define re_match(bufp, string, size, pos, regs) \
#endif
# endif
/* Make sure no one compiles this code with a C++ compiler.  */
link_warning (re_max_failures, "the 're_max_failures' variable is obsolete and will go away.")
#endif
# define regcomp(preg, pattern, cflags) __regcomp (preg, pattern, cflags)

#endif
	__regerror(errcode, preg, errbuf, errbuf_size)
   #undefs RE_DUP_MAX and sets it to the right value.  */

