

static int packet_length(const char *linelen)


			   writer->use_sideband ? "\003" : "ERR ", fmt, args);
	while (1) {
			      packet_buffer, sizeof(packet_buffer),
	strbuf_reset(&buf);
	if (src_buf && *src_buf) {
	int len = packet_read(fd, NULL, NULL,
}
			continue;
 */
int packet_flush_gently(int fd)
		die_errno(_("packet write failed"));
}

		return error(_("packet write failed"));

	memcpy(packet_write_buffer + 4, buf, size);

		else
	}
		trace_verbatim(&trace_pack, buf + 1, len - 1);

static char *packet_read_line_generic(int fd,
		*src_buf += ret;
	buf[0] = hex(size >> 12);
		sb_out->len += packet_len;
		*pktlen = -1;
}
	int i;

	buf[1] = hex(size >> 8);
	packet_write_fmt_1(fd, 0, "", fmt, args);
							 &reader->src_len,
	size_t orig_len, n;
	size_t orig_alloc = sb_out->alloc;
	if (dst_len)
	return packet_read_line_generic(-1, src, src_len, dst_len);


int packet_write_fmt_gently(int fd, const char *fmt, ...)
		die(_("the remote end hung up unexpectedly"));
static int packet_write_fmt_1(int fd, int gently, const char *prefix,
	if (packet_write_gently(fd_out, buf, size))
void packet_writer_delim(struct packet_writer *writer)
			bytes_to_write = LARGE_PACKET_DATA_MAX;
	return err;
}
		return reader->status;

	}

{
					 &sideband_type))
	struct strbuf scratch = STRBUF_INIT;

	strbuf_add(buf, "0001", 4);
/* Packet Reader Functions */
		return;
{
		if (!reader->use_sideband)

	if (write_in_full(fd_out, packet_write_buffer, packet_size) < 0)
{
	len -= 4;
	packet_trace("0001", 4, 1);
	}
		in_pack = 1;
		default: /* errors: message already written */
	packet_trace(buf, size, 1);
		return;
		if (bytes_to_write == 0)

		reader->line = reader->use_sideband ?

	strbuf_addstr(buf, "0000");
	n = out->len - orig_len;
	orig_len = buf->len;
			  const char *fmt, va_list args)
}
static void format_packet(struct strbuf *out, const char *prefix,
	strbuf_addstr(out, prefix);
	if (write_in_full(fd, "0001", 4) < 0)

		die(_("protocol error: impossibly long line"));
	}
			strbuf_setlen(sb_out, orig_len);
	packet_reader_read(reader);
	enum sideband_type sideband_type;
	if (reader->status == PACKET_READ_NORMAL)
{
		if (packet_trace_pack(buf, len, sideband))

		return packet_len;
			return sideband_type;
}
{
	else

		return error(_("packet write with format failed"));
void packet_write_fmt(int fd, const char *fmt, ...)
			int options)
static struct trace_key trace_packet = TRACE_KEY_INIT(PACKET);
					  &sideband_type))
{

		if (ret < 0)
		ret = read_in_full(fd, dst, size);
	}

		if (buf[i] == '\n')
	return 0;
	strbuf_addf(&out, "packet: %12s%c ",

{
	size_t bytes_written = 0;
	if (len < 0) {
							 reader->buffer_size,
}
	char buf[LARGE_PACKET_MAX + 1];
{
			die_errno(_("packet write with format failed"));
		err = packet_flush_gently(fd_out);
		ret = size < *src_size ? size : *src_size;
	/*
		if (demultiplex_sideband(reader->me, reader->buffer,
}
	strbuf_addch(&out, '\n');
	va_start(args, fmt);
		 * started.
	if ((options & PACKET_READ_DIE_ON_ERR_PACKET) &&

	set_packet_header(&out->buf[orig_len], n);
	packet_read_with_status(fd, src_buffer, src_len, buffer, size,
{
	va_end(args);
		*dst_line = (len > 0) ? packet_buffer : NULL;
		if (bytes_to_write < 0)
	} else {
			break;
	orig_len = out->len;
{
}
{
	return PACKET_READ_NORMAL;
	}
	int val = hex2chr(linelen);
	struct strbuf scratch = STRBUF_INIT;
		return error(_("packet write failed - data exceeds max packet size"));
	len = packet_length(linelen);
	reader->me = "git";

static int packet_write_gently(const int fd_out, const char *buf, size_t size)
	    starts_with(buffer, "ERR "))
	va_start(args, fmt);
enum packet_read_status packet_reader_read(struct packet_reader *reader)
		if (!gently) {
	*pktlen = len;
	if (fd >= 0 && src_buf && *src_buf)

	/* Read up to "size" bytes from our source, whatever it is. */
char *packet_read_line(int fd, int *len_p)
	va_list args;
		 */
}
			break;

	if (n > LARGE_PACKET_MAX)
	if (packet_len < 0) {

{
	if (!err)
}
/*

	packet_trace("0000", 4, 1);
	return err;
		char *buffer, unsigned size, int options)
		return 1;
	return in_async() ? "sideband" : packet_trace_prefix;

		memcpy(dst, *src_buf, ret);
	size_t orig_len = sb_out->len;
void packet_writer_flush(struct packet_writer *writer)
	int len;
	char linelen[4];
	if (get_packet_data(fd, src_buffer, src_len, linelen, 4, options) < 0) {
		strbuf_grow(sb_out, LARGE_PACKET_DATA_MAX);

	}
	if (dst_len)
#include "pkt-line.h"

							 reader->buffer,
	buf[3] = hex(size);
	while (1) {
static const char *packet_trace_prefix = "git";
	while (!err) {
}
	/* Peek a line by reading it and setting peeked flag */
		return PACKET_READ_DELIM;
		if ((len - bytes_written) > LARGE_PACKET_DATA_MAX)


{

	if ((unsigned)len >= size)
{
		die(_("remote error: %s"), buffer + 4);

		reader->line_peeked = 0;
#include "run-command.h"
	reader->src_buffer = src_buffer;
	strbuf_addstr(out, "0000");

	packet_flush(writer->dest_fd);
	return reader->status;
}
	ssize_t bytes_to_write;
{
			break;

	va_end(args);
	/* +32 is just a guess for header + quoting */
			break;
		return PACKET_READ_EOF;
			   writer->use_sideband ? "\001" : "", fmt, args);
{
		/*
}
		packet_trace("0001", 4, 0);
void packet_writer_write(struct packet_writer *writer, const char *fmt, ...)
		if (!demultiplex_sideband(me, buf, len, 0, &scratch,
	for (i = 0; i < len; i++) {
static const char *get_trace_prefix(void)
}
	return (val < 0) ? val : (val << 8) | hex2chr(linelen + 2);
	status = packet_write_fmt_1(fd, 1, "", fmt, args);
			return -1;

	return 0;



		err = packet_write_gently(fd_out, buf, bytes_to_write);
}
	 */
	strbuf_add(buf, data, len);
	format_packet(buf, "", fmt, args);
		else
}
		else
}

}
	if (reader->line_peeked)

		return error(_("flush packet write failed"));
{
	n = buf->len - orig_len;
			write_or_die(out, buf + 1, len - 1);
{
{
	return reader->status;
	return len;
	} else if (starts_with(buf, "PACK") || starts_with(buf, "\1PACK")) {
#include "cache.h"
	if ((options & PACKET_READ_CHOMP_NEWLINE) &&
			strbuf_addch(&out, buf[i]);
{
	buf[2] = hex(size >> 4);
	struct strbuf out;
		*pktlen = 0;
	if (in_pack) {
		*pktlen = -1;


	va_list args;


			   void *dst, unsigned size, int options)

	strbuf_release(&out);
	return packet_read_line_generic(fd, NULL, NULL, len_p);

	} else if (len && *buf == '\1') {
}
			 * store a '\0' at the end of the string. packet_read()
	int err = 0;
	if (write_in_full(fd, "0000", 4) < 0)
	}
void packet_buf_write_len(struct strbuf *buf, const char *data, size_t len)
	}
		reader->status = packet_read_with_status(reader->fd,
}
	int err = 0;
		enum sideband_type sideband_type;
char *packet_read_line_buf(char **src, size_t *src_len, int *dst_len)

		if (buf[i] >= 0x20 && buf[i] <= 0x7e)

	} else if (!len) {
					 reader->pktlen, 1, &scratch,
	reader->fd = fd;
		die(_("protocol error: impossibly long line"));
	strbuf_init(&out, len+32);
	}
			return;
							 reader->options);
		/* it's another non-pack sideband */
			char *src_buffer, size_t src_len,
}
		err = packet_write_gently(fd_out, src_in + bytes_written, bytes_to_write);
{
		err = packet_flush_gently(fd_out);
void packet_writer_error(struct packet_writer *writer, const char *fmt, ...)
{
	}
	packet_size = size + 4;
static int get_packet_data(int fd, char **src_buf, size_t *src_size,
	reader->line_peeked = 1;

		packet_len = packet_read(fd_in, NULL, NULL,
	size_t bytes_to_write;
void set_packet_header(char *buf, int size)
	int len;
			 * that there is already room for the extra byte.

				      int *dst_len)
{
}
	 * Consume all progress packets until a primary payload packet is
	if (!err)
	static int in_pack, sideband;

{


{
		if (bytes_to_write == 0)
int packet_read(int fd, char **src_buffer, size_t *src_len,
							 &reader->pktlen,
		/* suppress newlines */
	packet_write_fmt_1(writer->dest_fd, 0,

		die(_("protocol error: bad line length character: %.4s"), linelen);
int recv_sideband(const char *me, int in_stream, int out)
{

	return (len > 0) ? packet_buffer : NULL;
	return sb_out->len - orig_len;

void packet_flush(int fd)
	if (reader->line_peeked) {
	if (ret != size) {
	buffer[len] = 0;
		return 1;
		if (options & PACKET_READ_GENTLE_ON_EOF)
	} else {
	packet_trace("0001", 4, 1);
}
}

		bytes_written += bytes_to_write;
	/* XXX we should really handle printable utf8 */
		len = packet_read(in_stream, NULL, NULL, buf, LARGE_PACKET_MAX,
		BUG("multiple sources given to packet_read");

	reader->options = options;
	packet_write_fmt_1(writer->dest_fd, 0,
			reader->buffer + 1 : reader->buffer;

		return reader->status;
	}
		/* Skip the sideband designator if sideband is used */

	return pktlen;
			      PACKET_READ_CHOMP_NEWLINE);
						unsigned size, int *pktlen,
		return PACKET_READ_EOF;
	if (!trace_want(&trace_packet) && !trace_want(&trace_pack))
enum packet_read_status packet_reader_peek(struct packet_reader *reader)
	packet_trace(out->buf + orig_len + 4, n - 4, 1);
						int options)
	/* Only allow peeking a single line */
	writer->dest_fd = dest_fd;
	if (size > sizeof(packet_write_buffer) - 4)
}
	    len && buffer[len-1] == '\n')
 * we'd flush it here
void packet_writer_init(struct packet_writer *writer, int dest_fd)
{
	}
void packet_buf_delim(struct strbuf *buf)

				      char **src, size_t *src_len,
		packet_trace_pack(buf, len, sideband);
	ssize_t ret;


	va_end(args);
		return 0;
	writer->use_sideband = 0;
	packet_trace(buffer, len, 0);
						size_t *src_len, char *buffer,
{
	if (!sideband) {
			sb_out->buf + sb_out->len, LARGE_PACKET_DATA_MAX+1,



	return status;
int write_packetized_from_fd(int fd_in, int fd_out)
	set_packet_header(&buf->buf[orig_len], n);
		if (packet_len <= 0)
		buf = "PACK ...";
			PACKET_READ_GENTLE_ON_EOF);
	size_t orig_len, n;
	set_packet_header(packet_write_buffer, packet_size);
	 * received
void packet_delim(int fd)
		reader->line = NULL;
		die(_("protocol error: bad line length %d"), len);
{

{
{
			      PACKET_READ_CHOMP_NEWLINE|PACKET_READ_GENTLE_ON_EOF);
}
char packet_buffer[LARGE_PACKET_MAX];
int packet_read_line_gently(int fd, int *dst_len, char **dst_line)
			 */
	if (get_packet_data(fd, src_buffer, src_len, buffer, len, options) < 0) {
		bytes_to_write = xread(fd_in, buf, sizeof(buf));
}
		packet_trace("0000", 4, 0);
ssize_t read_packetized_to_strbuf(int fd_in, struct strbuf *sb_out)

void packet_reader_init(struct packet_reader *reader, int fd,
		die_errno(_("unable to write flush packet"));
		die_errno(_("unable to write delim packet"));

{
{
{
	va_end(args);

	va_start(args, fmt);
	size_t packet_size;
	}
			break;

			      const char *fmt, va_list args)
void packet_buf_write(struct strbuf *buf, const char *fmt, ...)
	strbuf_vaddf(out, fmt, args);
	for (;;) {
			 * writes a '\0' extra byte at the end, too. Let it know
void packet_buf_flush(struct strbuf *buf)
void packet_write(int fd_out, const char *buf, size_t size)
	packet_trace("0000", 4, 1);
		*src_size -= ret;
	if (write_in_full(fd, buf.buf, buf.len) < 0) {
	return 0;
		len--;
	int pktlen = -1;
			strbuf_release(sb_out);

		trace_verbatim(&trace_pack, buf, len);
	reader->buffer = packet_buffer;
			/* strbuf_grow() above always allocates one extra byte to
		len = strlen(buf);
	while (!err) {

			strbuf_addf(&out, "\\%o", buf[i]);
	va_list args;
	if (n > LARGE_PACKET_MAX)
	int len = packet_read(fd, src, src_len,
		case SIDEBAND_PRIMARY:
	memset(reader, 0, sizeof(*reader));
	format_packet(&buf, prefix, fmt, args);
	va_end(args);
	va_list args;
			break;
	packet_trace(data, len, 1);
}
	#undef hex
	va_start(args, fmt);

}
}
			bytes_to_write = len - bytes_written;
	return ret;
		}
		return PACKET_READ_FLUSH;
	packet_delim(writer->dest_fd);
		sideband = *buf == '\1';
	reader->src_len = src_len;
							 &reader->src_buffer,
		*dst_len = len;
}
}
		if (orig_alloc == 0)

			check_pipe(errno);
	va_start(args, fmt);

	int status;
void packet_trace_identity(const char *prog)
		*pktlen = 0;

	reader->buffer_size = sizeof(packet_buffer);
				  0);
{


	#define hex(a) (hexchar[(a) & 15])
			      packet_buffer, sizeof(packet_buffer),
static int packet_trace_pack(const char *buf, unsigned int len, int sideband)
	}
	}
	static char buf[LARGE_PACKET_DATA_MAX];
		switch (sideband_type) {
	strbuf_add(buf, "0000", 4);
{
	/* And complain if we didn't get enough bytes to satisfy the read. */
	int packet_len;
	packet_trace_prefix = xstrdup(prog);
}

}
	static struct strbuf buf = STRBUF_INIT;
	if (dst_line)
	if (!trace_want(&trace_packet))

	static char hexchar[] = "0123456789abcdef";
}
		}
		die(_("protocol error: bad line length %d"), len);
	} else if (len < 4) {
static struct trace_key trace_pack = TRACE_KEY_INIT(PACKFILE);
		*dst_len = len;
{
}
	} else if (len == 1) {
		    get_trace_prefix(), write ? '>' : '<');

		 * Make a note in the human-readable trace that the pack data

 * If we buffered things up above (we don't, but we should),
	if (write_in_full(fd, "0000", 4) < 0)

	va_list args;
}

	packet_trace("0000", 4, 1);
	static char packet_write_buffer[LARGE_PACKET_MAX];

	trace_strbuf(&trace_packet, &out);
			return COPY_READ_ERROR;
				&pktlen, options);

static void packet_trace(const char *buf, unsigned int len, int write)
			die_errno(_("read error"));
			continue;
enum packet_read_status packet_read_with_status(int fd, char **src_buffer,
{
int write_packetized_from_buf(const char *src_in, size_t len, int fd_out)
