		const void *data;
struct hashfile *hashfd(int fd, const char *name)
	return f->crc32;


	if (0 <= f->check_fd && count)  {
			count -= ret;
	f->offset = 0; /* hashflush() was called in checkpoint */
	return 0;
	} else
		die_errno("unable to open '%s'", name);
#include "cache.h"

}
		} else {
	f->fd = fd;
	f->ctx = checkpoint->ctx;

void hashfile_checkpoint(struct hashfile *f, struct hashfile_checkpoint *checkpoint)
}
			die("sha1 file '%s' write error. Out of diskspace", f->name);
		fd = f->fd;
	return hashfd_throughput(fd, name, NULL);
		int cnt = read_in_full(f->check_fd, &discard, 1);
		the_hash_algo->update_fn(&f->ctx, f->buffer, offset);
	return fd;

	f->name = name;
{
	}
{

	for (;;) {
	f->check_fd = -1;
static void flush(struct hashfile *f, const void *buf, unsigned int count)

	    lseek(f->fd, offset, SEEK_SET) != offset)
}
	}
	if (result)
{
		if (ret != count)


			the_hash_algo->update_fn(&f->ctx, data, offset);
		if (!ret)

	if (flags & CSUM_FSYNC)
	if (0 <= f->check_fd) {
	int fd;
		if (memcmp(buf, check_buffer, count))
		if (ret > 0) {
	f->total = 0;
}
	f->do_crc = 1;
			offset = 0;
	struct hashfile *f = xmalloc(sizeof(*f));
	f->do_crc = 0;
void hashwrite(struct hashfile *f, const void *buf, unsigned int count)
			die_errno("%s: sha1 file error on close", f->name);
	f->crc32 = crc32(0, NULL, 0);
}
	f->offset = 0;
		if (!left) {
 * able to verify hasn't been messed with afterwards.
{
}
	the_hash_algo->clone_fn(&checkpoint->ctx, &f->ctx);
			/* process full buffer directly without copy */
	struct hashfile *f;
	checkpoint->offset = f->total;
		if (close(f->fd))
		}


	if (offset) {
		flush(f, f->buffer, the_hash_algo->rawsz);
	return f;
void crc32_begin(struct hashfile *f)
			die("%s: sha1 file truncated", f->name);
}
	f->total = offset;
	f->tp = tp;
{
			buf = (char *) buf + ret;
	f = hashfd(sink, name);
	}
			if (count)
				continue;

 * Copyright (C) 2005 Linus Torvalds
		flush(f, f->buffer, offset);
		if (ret < 0)
		count -= nr;
}
		char discard;
#include "csum-file.h"
{
				  f->name);
{
		f->offset = 0;
 *
}
		fsync_or_die(f->fd, f->name);
	if (check < 0)
			flush(f, data, offset);
	hashflush(f);
	if (ftruncate(f->fd, offset) ||
		}
{
 * csum-file.c
{
			display_throughput(f->tp, f->total);
	if (flags & CSUM_HASH_IN_STREAM)

		unsigned nr = count > left ? left : count;
			f->crc32 = crc32(f->crc32, buf, nr);
int finalize_hashfile(struct hashfile *f, unsigned char *result, unsigned int flags)
struct hashfile *hashfd_throughput(int fd, const char *name, struct progress *tp)
		if (cnt)
		f->offset = offset;
		return -1;
			die_errno("%s: sha1 file error on close", f->name);
		die_errno("unable to open /dev/null");
			die("%s: sha1 file has trailing garbage", f->name);

 * Simple file write infrastructure for writing SHA1-summed
	if (sink < 0)
#include "progress.h"
	f->check_fd = check;
	int sink, check;
	sink = open("/dev/null", O_WRONLY);
	if (flags & CSUM_CLOSE) {
		ssize_t ret = read_in_full(f->check_fd, check_buffer, count);
		if (cnt < 0)
	the_hash_algo->init_fn(&f->ctx);
	while (count) {
	off_t offset = checkpoint->offset;
		buf = (char *) buf + nr;
			memcpy(f->buffer + offset, buf, nr);
{
struct hashfile *hashfd_check(const char *name)
		hashcpy(result, f->buffer);
			die_errno("%s: sha1 file read error", f->name);
			data = buf;
		offset += nr;
		unsigned left = sizeof(f->buffer) - offset;
 */
		unsigned offset = f->offset;
uint32_t crc32_end(struct hashfile *f)
			return;
 *
	}
/*

		int ret = xwrite(f->fd, buf, count);
	unsigned offset = f->offset;
			f->total += ret;
	free(f);

			die_errno("%s: error when reading the tail of sha1 file",
		}
}
		die_errno("sha1 file '%s' write error", f->name);
		if (close(f->check_fd))
			die("sha1 file '%s' validation error", f->name);

}
	}
	the_hash_algo->final_fn(f->buffer, &f->ctx);
{
		if (nr == sizeof(f->buffer)) {
		unsigned char check_buffer[8192];

int hashfile_truncate(struct hashfile *f, struct hashfile_checkpoint *checkpoint)
		left -= nr;
	f->do_crc = 0;
		if (f->do_crc)

	hashflush(f);
	return f;
			data = f->buffer;
	check = open(name, O_RDONLY);
void hashflush(struct hashfile *f)
 * files. Useful when you write a file that you want to be
		fd = 0;
