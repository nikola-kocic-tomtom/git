 * Licensed under a two-clause BSD-style license.
}
		return NULL;
	return err;

		return -1;
		 * There is probably a saner way to deal with this,

		return ferror(buf->infile);
	off_t done = 0;


#define COPY_BUFFER_LEN 4096
int buffer_tmpfile_init(struct line_buffer *buf)

	buf->infile = filename ? fopen(filename, "r") : stdin;
off_t buffer_skip_bytes(struct line_buffer *buf, off_t nbytes)
		/* Error or data exhausted. */
off_t buffer_copy_bytes(struct line_buffer *buf, off_t nbytes)
size_t buffer_read_binary(struct line_buffer *buf,
}
/* Read a line without trailing newline. */
	return buf->infile;
	else if (feof(buf->infile))
	char byte_buffer[COPY_BUFFER_LEN];
{
		/*
	while (done < nbytes && !feof(buf->infile) && !ferror(buf->infile)) {
		end[-1] = '\0';
	if (end[-1] == '\n')
		if (ferror(stdout))
}
	end = buf->line_buffer + strlen(buf->line_buffer);
	char *end;
		; /* No newline at end of file.  That's fine. */
		size_t in = len < COPY_BUFFER_LEN ? len : COPY_BUFFER_LEN;
{
		return NULL;
		size_t in = len < COPY_BUFFER_LEN ? len : COPY_BUFFER_LEN;
char *buffer_read_line(struct line_buffer *buf)
{
	return done;

#include "git-compat-util.h"

int buffer_deinit(struct line_buffer *buf)
		in = fread(byte_buffer, 1, in, buf->infile);
	}
{
}
	err = ferror(buf->infile);

	return 0;
		off_t len = nbytes - done;
{
}
		 * but for now let's return an error.
{
}
/*
	return strbuf_fread(sb, size, buf->infile);
	return 0;
	if (pos < 0)
{

	rewind(buf->infile);
		return error_errno("ftell error");
		 * Line was too long.
	long pos = ftell(buf->infile);
	return 0;
	return pos;
long buffer_tmpfile_prepare_to_read(struct line_buffer *buf)
	return buf->line_buffer;
	if (!buf->infile)
	int err;
	else
#include "line_buffer.h"
		return -1;
	return ferror(buf->infile);
	if (buf->infile == stdin)
	if (!buf->infile)
FILE *buffer_tmpfile_rewind(struct line_buffer *buf)
 */

	if (fseek(buf->infile, 0, SEEK_SET))
		 */
 * See LICENSE for details.
	err |= fclose(buf->infile);

int buffer_read_char(struct line_buffer *buf)
{
}
		done += in;
{
}


}
{

		return error_errno("seek error");
	char byte_buffer[COPY_BUFFER_LEN];
		fwrite(byte_buffer, 1, in, stdout);
			return done + buffer_skip_bytes(buf, nbytes - done);
	if (!buf->infile)
		off_t len = nbytes - done;
	buf->infile = fdopen(fd, "r");
	return done;
	buf->infile = tmpfile();
int buffer_init(struct line_buffer *buf, const char *filename)
}
{
	if (!fgets(buf->line_buffer, sizeof(buf->line_buffer), buf->infile))
int buffer_ferror(struct line_buffer *buf)
int buffer_fdinit(struct line_buffer *buf, int fd)
}
{
#include "strbuf.h"
	}
		return -1;
	while (done < nbytes && !feof(buf->infile) && !ferror(buf->infile)) {
		done += fread(byte_buffer, 1, in, buf->infile);
}
	return fgetc(buf->infile);
				struct strbuf *sb, size_t size)
	off_t done = 0;
