	if (write_fun(data, &bitsize, 4) != 4)
	/** 32 bit -- position for the RLW */
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
static int write_strbuf(void *user_data, const void *data, size_t len)

	self->bit_size = get_be32(ptr);
	/** 64 bit x N -- compressed words */
 *
		words_left -= words_per_dump;
	ptr += sizeof(uint32_t);
 * This program is free software; you can redistribute it and/or
	strbuf_add(sb, data, len);
	words_left = self->buffer_size;
			dump[i] = htonll(*buffer);
		return error("corrupt ewah bitmap: eof before bit size");
	if (len < data_len)
	 * if we're in a little-endian platform, we'll perform
{
 *
	 * the endianness conversion in a separate pass to ensure
	const eword_t *buffer;
 * as published by the Free Software Foundation; either version 2
			dump[i] = htonll(*buffer);
 * You should have received a copy of the GNU General Public License
#include "git-compat-util.h"
int ewah_serialize_strbuf(struct ewah_bitmap *self, struct strbuf *sb)
	size_t words_left;

		for (i = 0; i < words_per_dump; ++i, ++buffer)
		for (i = 0; i < words_left; ++i, ++buffer)
ssize_t ewah_read_mmap(struct ewah_bitmap *self, const void *map, size_t len)
	word_count =  htonl((uint32_t)self->buffer_size);

	len -= sizeof(uint32_t);
	/** 32 bit -- number of compressed 64-bit words */
	while (words_left >= words_per_dump) {
			     "(%"PRIuMAX" bytes short)",
	ptr += data_len;
 */
	memcpy(self->buffer, ptr, data_len);
	 * Copy the raw data for the bitmap as a whole chunk;
	self->buffer_size = self->alloc_size = get_be32(ptr);
int ewah_serialize_to(struct ewah_bitmap *self,
		return -1;


 *	David McIntosh, Robert Becho, Google Inc. and Veronika Zenz
 * GNU General Public License for more details.
	if (write_fun(data, &word_count, 4) != 4)
		return error("corrupt ewah bitmap: eof before length");

}

		if (write_fun(data, dump, sizeof(dump)) != sizeof(dump))
	len -= sizeof(uint32_t);
	if (write_fun(data, &rlw_pos, 4) != 4)

	/*
	len -= sizeof(uint32_t);
	rlw_pos = (uint8_t*)self->rlw - (uint8_t *)self->buffer;
		return error("corrupt ewah bitmap: eof in data "
	REALLOC_ARRAY(self->buffer, self->alloc_size);
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	size_t i;
	buffer = self->buffer;
{
	uint32_t bitsize, word_count, rlw_pos;
	bitsize =  htonl((uint32_t)self->bit_size);
#include "ewok.h"
 * Copyright 2009-2013, Daniel Lemire, Cliff Moon,
		self->buffer[i] = ntohll(self->buffer[i]);
	const size_t words_per_dump = sizeof(dump) / sizeof(eword_t);
}
/**
	size_t data_len;
	eword_t dump[2048];
	return (3 * 4) + (self->buffer_size * 8);
	if (len < sizeof(uint32_t))
 * of the License, or (at your option) any later version.
	ptr += sizeof(uint32_t);
{
{
	self->rlw = self->buffer + get_be32(ptr);
}

	return ewah_serialize_to(self, write_strbuf, sb);

			     (uintmax_t)(data_len - len));

	 */
		return -1;
	const uint8_t *ptr = map;


}
	}
	if (len < sizeof(uint32_t))
	data_len = st_mult(self->buffer_size, sizeof(eword_t));
	rlw_pos = htonl(rlw_pos / sizeof(eword_t));
	for (i = 0; i < self->buffer_size; ++i)

	/* 32 bit -- bit size for the map */
	return ptr - (const uint8_t *)map;
 *


		if (write_fun(data, dump, words_left * 8) != words_left * 8)

	return len;

		      void *data)
	size_t i;
	len -= data_len;
		return error("corrupt ewah bitmap: eof before rlw");

	ptr += sizeof(uint32_t);
	if (words_left) {
	 * we're loading 8-byte aligned words.
		return -1;
	}
		      int (*write_fun)(void *, const void *, size_t),
 * Copyright 2013, GitHub, Inc
	struct strbuf *sb = user_data;


			return -1;
 * modify it under the terms of the GNU General Public License
	if (len < sizeof(uint32_t))
#include "strbuf.h"


			return -1;
