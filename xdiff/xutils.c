	nb += 2;
	nb += xdl_num_out(buf + nb, c1 ? s1: s1 - 1);
int xdl_emit_hunk_hdr(long s1, long c1, long s2, long c2,
static int xdl_format_hunk_hdr(long s1, long c1, long s2, long c2,
 *
 *


	/*
		if (cr_at_eol_only) {

		ha ^= (unsigned long) *ptr;
	long nl = 0, size, tsize = 0;
}
		return xdl_hash_record_with_whitespace(data, top, flags);
	} else if (flags & XDF_IGNORE_CR_AT_EOL) {

		mb[2].ptr = (char *) "\n\\ No newline at end of file\n";
		for (top = data + size; nl < sample && cur < top; ) {
	}
		}

		while (i1 < s1 && i2 < s2) {
}
	}
		;

	int i1, i2;
		diff_env->xdf2.recs[line2 + count2 - 2]->size - subfile2.ptr;

 * CR at the very end?

				}

	char const *data, *cur, *top;
 *  modify it under the terms of the GNU Lesser General Public
		cur = cur->next;
				return 0;
	mb[1].ptr = (char *) rec;
				continue;
	int i = 2;
	chanode_t *cur, *tmp;
			continue;
			       const char *func, long funclen,
		return -1;
long xdl_bogosqrt(long n) {
	 * which in turn matches everything that matches with --ignore-cr-at-eol.
	return data;
		ha ^= (unsigned long) *ptr;
	return nl + 1;
	return i;
	}

	*size = mmf->size;

			else

}
	if (s1 == s2 && !memcmp(l1, l2, s1))
}
	return 0;
			cha->tail->next = ancur;
			if (XDL_ISSPACE(l1[i1]) && XDL_ISSPACE(l2[i2])) {

int xdl_cha_init(chastore_t *cha, long isize, long icount) {
		ha += (ha << 5);
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
}
	return ha;
		tsize += (long) (cur - data);


void *xdl_cha_alloc(chastore_t *cha) {

	buf[nb++] = '\n';
	 * This probably does not work outside Git, since
 *
	 * nothing but whitespace for the lines to match.  Note that
			/* do not ignore CR at the end of an incomplete line */
	if (i1 < s1) {
		ha += (ha << 5);


	char const *ptr = *data;
				ha += (ha << 5);

{

	return 1;
void xdl_cha_free(chastore_t *cha) {

	}
		nb += funclen;
		memcpy(buf + nb, func, funclen);
	for (; ptr < top && *ptr != '\n'; ptr++) {
	void *data;

void *xdl_mmfile_first(mmfile_t *mmf, long *size)
	/*
		goto skip_ws;
	 * ignore-whitespace-at-eol case may break out of the loop
		return (ends_with_optional_cr(l1, s1, i1) &&
			while (ptr + 1 < top && XDL_ISSPACE(ptr[1])
			*str = *ptr;

			i1++;
	 * Classical integer square root approximation using shifts.
				while (i1 < s1 && XDL_ISSPACE(l1[i1]))

	if (c1 != 1) {


	for (cur = cha->head; (tmp = cur) != NULL;) {
			if (!(cur = memchr(cur, '\n', top - cur)))
		if (!cha->head)
	 */

				i1++;
			i1++;

	 * Note: ideally, we would reuse the prepared environment, but
	ancur->icurr += cha->isize;


 *  LibXDiff by Davide Libenzi ( File Differential Library )

	}
	}
	memcpy(buf, "@@ -", 4);
}
		buf[nb++] = ' ';
	if (size > 0 && rec[size - 1] != '\n') {
	return (i == size);
	} else if (flags & XDF_IGNORE_WHITESPACE_CHANGE) {
	return 0;
	if (ecb->out_hunk(ecb->priv,
	}
{
	memcpy(diff_env->xdf1.rchg + line1 - 1, env.xdf1.rchg, count1);
	 * ranges of lines instead of the whole files.
	char buf[32];
	mb[0].ptr = (char *) pre;
	if (xdl_do_diff(&subfile1, &subfile2, xpp, &env) < 0)
		while (i1 < s1 && i2 < s2 && l1[i1] == l2[i2]) {
	 */
/*
	subfile2.ptr = (char *)diff_env->xdf2.recs[line2 - 1]->ptr;
			else if (flags & XDF_IGNORE_WHITESPACE_AT_EOL
	cha->isize = isize;
		memcpy(buf + nb, ",", 1);
			ends_with_optional_cr(l2, s2, i2));
					ha ^= (unsigned long) *ptr2;
}
			i2++;
	if (nl && tsize)
		for (; *ptr; ptr++, str++)
	unsigned long ha = 5381;

	 *
}
				 && !at_eol) {
				; /* already handled */
		skip_ws:
	/*
}
	xdl_free_env(&env);
	memcpy(diff_env->xdf2.rchg + line2 - 1, env.xdf2.rchg, count2);
			}
	}

		nl = xdl_mmfile_size(mf) / (tsize / nl);
		return (size <= 1);
		while (i2 < s2 && XDL_ISSPACE(l2[i2]))
		if (funclen > sizeof(buf) - nb - 1)
	if (*ptr)
	subfile1.size = diff_env->xdf1.recs[line1 + count1 - 2]->ptr +
		return xdl_format_hunk_hdr(s1, c1, s2, c2, func, funclen, ecb);
		return 1;
		while (i1 < s1 && XDL_ISSPACE(l1[i1]))
}
		char const *top, long flags) {
	memcpy(buf + nb, " @@", 3);
					ptr2++;
	if (!ecb->out_hunk)
	/* do not ignore CR at the end of an incomplete line */
	mmbuffer_t mb;

	return 0;
			at_eol = (top <= ptr + 1 || ptr[1] == '\n');
	}
	char *ptr, *str = out;
	long i;
		ancur->icurr = 0;

		nb += xdl_num_out(buf + nb, c2);

}
		*--ptr = "0123456789"[val % 10];
 *  Davide Libenzi <davidel@xmailserver.org>
}
			while (i1 < s1 && XDL_ISSPACE(l1[i1]))
	char const *ptr = *data;
	nb += xdl_num_out(buf + nb, c2 ? s2: s2 - 1);

	i1 = 0;
	return str - out;
			const char *ptr2 = ptr;
		cha->ancur = ancur;
	char buf[128];
 */


			i2++;
				ptr++;
	if (func && funclen) {
 *  This library is free software; you can redistribute it and/or





		else if (XDL_ISSPACE(*ptr)) {
 *  Lesser General Public License for more details.
			if (flags & XDF_IGNORE_WHITESPACE)

	mb.ptr = buf;
{
	mb[0].size = psize;
int xdl_recmatch(const char *l1, long s1, const char *l2, long s2, long flags)
		}
	if (complete)
			i1++;
		return 0;
			funclen = sizeof(buf) - nb - 1;
	for (; val && ptr > buf; val /= 10)
	 * -w matches everything that matches with -b, and -b in turn
		ancur->next = NULL;
		xdl_free(tmp);
unsigned long xdl_hash_record(char const **data, char const *top, long flags) {
			if (*ptr == '\r' &&
}
	*data = ptr < top ? ptr + 1: ptr;
	 * matches everything that matches with --ignore-space-at-eol,
				continue;
	if (!(ancur = cha->ancur) || ancur->icurr == cha->nsize) {
		return 1;
		}

				i2++;
	for (; ptr < top && *ptr != '\n'; ptr++) {
 *  You should have received a copy of the GNU Lesser General Public
	if (flags & XDF_WHITESPACE_FLAGS)

	if (ecb->out_line(ecb->priv, &mb, 1) < 0)
					&& ptr[1] != '\n')
	 * Each flavor of ignoring needs different logic to skip whitespaces
		}
			i2++;
		*str++ = '0';
	nb += 3;
long xdl_mmfile_size(mmfile_t *mmf)
	if (val < 0) {
				/* Skip matching spaces and try again */
 *  License as published by the Free Software Foundation; either
	}
	unsigned int val = 1, bits = 0;
unsigned int xdl_hashbits(unsigned int size) {
	if (ecb->out_line(ecb->priv, mb, i) < 0) {
	if (flags & XDF_IGNORE_WHITESPACE) {

}
	mmbuffer_t mb[3];
	unsigned long ha = 5381;
	return 0;
		s--;
}
		      xdemitcb_t *ecb) {
	data = (char *) ancur + sizeof(chanode_t) + ancur->icurr;
	return 0;
			       xdemitcb_t *ecb) {
		while (i1 < s1 && i2 < s2 && l1[i1] == l2[i2]) {

long xdl_guess_lines(mmfile_t *mf, long sample) {
			}
	}
		while (i1 < s1 && i2 < s2) {
		/* Find the first difference and see how the line ends */
	mb[1].size = size;
		return 1;
			    (ptr + 1 < top && ptr[1] == '\n'))

		if (s1 != i1)

		nb += 1;

				cur++;
 *  Copyright (C) 2003	Davide Libenzi

				while (ptr2 != ptr + 1) {
		*--ptr = '-';
int xdl_num_out(char *out, long val) {
	if (complete && s == i + 1 && l[i] == '\r')
			  c1 ? s1 : s1 - 1, c1,

		i++;
int xdl_blankline(const char *line, long size, long flags)
			if (l1[i1++] != l2[i2++])
{
	return bits ? bits: 1;
		if (cha->tail)
	cha->scurr = 0;
	if ((cur = data = xdl_mmfile_first(mf, &size)) != NULL) {
	nb += 4;
				while (i2 < s2 && XDL_ISSPACE(l2[i2]))
 *  License along with this library; if not, see
			  func, funclen) < 0)
	else
		return -1;
#include "xinclude.h"
	for (; val < size && bits < CHAR_BIT * sizeof(unsigned int); val <<= 1, bits++);
		diff_env->xdf1.recs[line1 + count1 - 2]->size - subfile1.ptr;

	return ha;
		cha->tail = ancur;

		      const char *func, long funclen,
 *  This library is distributed in the hope that it will be useful,

	chanode_t *ancur;
	} else if (flags & XDF_IGNORE_WHITESPACE_AT_EOL) {
	mb.size = nb;
					i1++;
	int cr_at_eol_only = (flags & XDF_WHITESPACE_FLAGS) == XDF_IGNORE_CR_AT_EOL;
		i <<= 1;
/*
}
			while (i2 < s2 && XDL_ISSPACE(l2[i2]))


			}
	int nb = 0;
	}


}
	mmfile_t subfile1, subfile2;
	 * After running out of one side, the remaining side must have
	if (c2 != 1) {

	return mmf->size;
			if (l1[i1++] != l2[i2++])
static unsigned long xdl_hash_record_with_whitespace(char const **data,
			cha->head = ancur;
	 */
	ptr = buf + sizeof(buf) - 1;
 *
	 * we have a very simple mmfile structure.
	subfile2.size = diff_env->xdf2.recs[line2 + count2 - 2]->ptr +
{
	xdfenv_t env;
		val = -val;
				 && !at_eol) {
	}
 *  <http://www.gnu.org/licenses/>.
int xdl_emit_diffrec(char const *rec, long size, char const *pre, long psize,
	return mmf->ptr;
int xdl_fall_back_diff(xdfenv_t *diff_env, xpparam_t const *xpp,

		}
		mb[2].size = strlen(mb[2].ptr);

	return 0;
		}
	*ptr = '\0';
			  c2 ? s2 : s2 - 1, c2,
 *
	 * while we have both sides to compare.
		int line1, int count1, int line2, int count2)
					ha += (ha << 5);

		return -1;
 *  version 2.1 of the License, or (at your option) any later version.
static int ends_with_optional_cr(const char *l, long s, long i)
			return NULL;
		nb += 1;
		return (s2 == i2);
		return -1;

	if (!(flags & XDF_WHITESPACE_FLAGS))
	if (s == i)
	}
			int at_eol;
	cha->head = cha->tail = NULL;
			else if (flags & XDF_IGNORE_WHITESPACE_CHANGE
	cha->nsize = icount * isize;
	 *

			return 0;

	subfile1.ptr = (char *)diff_env->xdf1.recs[line1 - 1]->ptr;
		}
				return 0;
		}
 */

		memcpy(buf + nb, ",", 1);

	 */
				cur = top;
				ha ^= (unsigned long) ' ';
	for (i = 1; n > 0; n >>= 2)
	cha->ancur = cha->sncur = NULL;
					i2++;
	for (i = 0; i < size && XDL_ISSPACE(line[i]); i++)
	*data = ptr < top ? ptr + 1: ptr;
		nb += xdl_num_out(buf + nb, c1);

	*str = '\0';
	i2 = 0;
	/*
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
	long i;
	 * the libxdiff interface does not (yet) allow for diffing only
	 * while there still are characters remaining on both lines.
}
	memcpy(buf + nb, " +", 2);
			nl++;
		if (!(ancur = (chanode_t *) xdl_malloc(sizeof(chanode_t) + cha->nsize))) {
 * Have we eaten everything on the line, except for an optional
	if (!(flags & XDF_WHITESPACE_FLAGS))
{
	int complete = s && l[s-1] == '\n';
		     xdemitcb_t *ecb) {
	if (i2 < s2) {
