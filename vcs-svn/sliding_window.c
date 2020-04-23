	assert(view);
	assert(view->width <= view->buf.len);
		return error("delta preimage ends early");
 * See LICENSE for details.
	if (buffer_skip_bytes(file, gap) != gap)

static int input_error(struct line_buffer *file)
	}
	if (off < view->off || off + width < view->off + view->width)
				(uintmax_t) offset, len);
		return -1;
	if (buf->len != width)
		strbuf_setlen(&view->buf, 0);
		; /* Already read. */
		return input_error(file);
	else if (read_to_fill_or_whine(view->file, &view->buf, width))
#include "line_buffer.h"
		return error("unrepresentable length in delta: "
		/* Seek ahead to skip the gap. */
#include "git-compat-util.h"
				"%"PRIuMAX" > OFF_MAX", len);
}

	if (!buffer_ferror(file))

		return error("unrepresentable offset in delta: "
	if (check_offset_overflow(off, width))

	assert(!check_offset_overflow(view->off, view->buf.len));
	buffer_read_binary(file, buf, width - buf->len);
				struct strbuf *buf, size_t width)
	view->width = width;
	return 0;
	} else {
	return 0;
		strbuf_remove(&view->buf, 0, off - view->off);
 * Licensed under a two-clause BSD-style license.
				"%"PRIuMAX" + %"PRIuMAX" > OFF_MAX",
		return input_error(file);
{
		/* Move the overlapping region into place. */
}
	view->off = off;


}
static int skip_or_whine(struct line_buffer *file, off_t gap)
	return error_errno("cannot read delta preimage");
/*
		return error("delta preimage ends early");
	if (view->buf.len > width)
{
	return 0;
{
static int check_offset_overflow(off_t offset, uintmax_t len)
 */
{
	if (signed_add_overflows(offset, (off_t) len))
	if (len > maximum_signed_value_of_type(off_t))
	file_offset = view->off + view->buf.len;
	off_t file_offset;
	return 0;
	if (view->max_off >= 0 && view->max_off < off + (off_t) width)

}
		if (skip_or_whine(view->file, off - file_offset))
		return error("invalid delta: window slides left");
#include "sliding_window.h"
int move_window(struct sliding_view *view, off_t off, size_t width)
#include "strbuf.h"
		return -1;
}

			return -1;


static int read_to_fill_or_whine(struct line_buffer *file,
	if (off < file_offset) {
{
