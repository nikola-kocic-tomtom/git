			    cp_off + cp_size > src_size ||
			if (cmd > size || cmd > top - data)

		return NULL;
	out = dst_buf;
			 */
			if (cmd & (bit)) { \
	/* make sure the orig file size matches what we expect */
	/* now the result size */
	}
			memcpy(out, data, cmd);
			} } while (0)
			if (cp_size == 0) cp_size = 0x10000;
			 * cmd == 0 is reserved for future encoding
 *
	data = delta_buf;
			if (unsigned_add_overflows(cp_off, cp_size) ||
			error("unexpected delta opcode 0");
		  const void *delta_buf, unsigned long delta_size,
/*
{
			PARSE_CP_PARAM(0x20, cp_size, 8);
		bad_length:
 * it under the terms of the GNU General Public License version 2 as

#undef PARSE_CP_PARAM
 * This code is free software; you can redistribute it and/or modify
			PARSE_CP_PARAM(0x10, cp_size, 0);
	return dst_buf;

				goto bad_length;
				if (data >= top) \
		} else if (cmd) {
			    cp_size > size)
	while (data < top) {
	size = get_delta_hdr_size(&data, top);
		return NULL;
	*dst_size = out - dst_buf;
void *patch_delta(const void *src_buf, unsigned long src_size,

 * recreate a buffer from a source and the delta produced by diff-delta.c
 * patch-delta.c:
			out += cp_size;
			PARSE_CP_PARAM(0x08, cp_off, 24);
		cmd = *data++;
			PARSE_CP_PARAM(0x01, cp_off, 0);
		error("delta replay has gone wild");
#define PARSE_CP_PARAM(bit, var, shift) do { \
 * (C) 2005 Nicolas Pitre <nico@fluxnic.net>
#include "delta.h"
					goto bad_length; \
			out += cmd;
			goto bad;


 *
			/*
	const unsigned char *data, *top;
			unsigned long cp_off = 0, cp_size = 0;
 */
	top = (const unsigned char *) delta_buf + delta_size;
		return NULL;
			 * encountering them (might be data corruption).
		if (cmd & 0x80) {
	if (size != src_size)
		  unsigned long *dst_size)
	if (delta_size < DELTA_SIZE_MIN)
			size -= cp_size;
#include "git-compat-util.h"
		bad:
	dst_buf = xmallocz(size);
}
		free(dst_buf);
			PARSE_CP_PARAM(0x02, cp_off, 8);
 * published by the Free Software Foundation.
	size = get_delta_hdr_size(&data, top);

	unsigned long size;
	if (data != top || size != 0) {
	unsigned char *dst_buf, *out, cmd;
			PARSE_CP_PARAM(0x04, cp_off, 16);

	/* sanity check */
			PARSE_CP_PARAM(0x40, cp_size, 16);
				goto bad_length;
			data += cmd;
				var |= ((unsigned) *data++ << (shift)); \

		} else {
			memcpy(out, (char *) src_buf + cp_off, cp_size);
	}
			size -= cmd;
			 * extensions. In the mean time we must fail when
		}
