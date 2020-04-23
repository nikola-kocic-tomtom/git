
}

			crc = crc32(crc, buf, readlen);
	copy_le64(trailer64.record_size, ZIP64_DIR_TRAILER_RECORD_SIZE);
	unsigned char entries_on_this_disk[2];
	dest[3] = 0xff & (n >> 030);
	if (size > 0xffffffff || compressed_size > 0xffffffff)
	copy_le32(header->crc32, crc);
static int zip_date;
	unsigned char magic[2];
		header_extra_size += ZIP64_EXTRA_SIZE;
	dest[2] = 0xff & (n >> 020);
	dest[0] = 0xff & n;
/* We only care about the "buf" part here. */
			return 0;
	stream.next_in = data;

			zip64_dir_extra_payload_size += 8;
			   const void *buffer, size_t size)
	unsigned long maxsize;
	unsigned char size[8];
	unsigned char compressed_size[8];
};


	copy_le64(trailer64.offset, zip_offset);
	unsigned char crc32[4];
	copy_le16(dest, clamp_max(n, 0xffff, clamped));
	size_t zip64_dir_extra_payload_size = 0;
	void *deflated = NULL;
	copy_le32(header->compressed_size, compressed_size);
	dest[4] = 0xff & (n >> 040);
#define ZIP_UTF8	(1 << 11)
	copy_le32(trailer.size, zip_dir.len);
static uint64_t zip_dir_entries;

	if (compressed_size > 0xffffffff || size > 0xffffffff ||
					     oid_to_hex(oid));
{
		method = ZIP_METHOD_STORE;
			out = buffer;
}
				zstream.next_out = compressed;

			strbuf_add_le(&zip_dir, 8, offset);

	}
	copy_le32(extra.mtime, args->time);
		return NULL;
	void *buffer;
						    buffer, size);

	copy_le64(trailer64.entries_on_this_disk, zip_dir_entries);
{
	*timestamp = time;

		copy_le16(extra64.magic, 0x0001);
struct zip_local_header {
	git_config(archive_zip_config, NULL);
#define ZIP_STREAM	(1 <<  3)
	unsigned char size[4];
	copy_le32(dest, clamp_max(n, 0xffffffff, clamped));

			result = git_deflate(&zstream, 0);
	} else {
	} else if (compressed_size > 0) {
	struct zip_local_header header;
	unsigned char disk[2];
	copy_le64(locator64.offset, zip_offset + zip_dir.len);

	"zip",
	if (size >= 0xffffffff || compressed_size >= 0xffffffff) {
		return error(_("path too long (%d chars, SHA1: %s): %s"),
	unsigned char magic[4];
	if (!has_only_ascii(path)) {
};
		for (;;) {
		zstream.next_in = buf;
		if (S_ISREG(mode) && args->compression_level != 0 && size > 0)

	struct userdiff_driver *driver = userdiff_find_by_path(istate, path);
	unsigned char directory_start_disk[2];
	return buffer_is_binary(buffer, size);

	copy_le32(locator64.number_of_disks, 1);
		unsigned char buf[STREAM_BUFFER_SIZE];
	unsigned char _end[1];
	unsigned long crc;
	if (zip64_dir_extra_payload_size) {
static int strbuf_add_le(struct strbuf *sb, size_t size, uintmax_t n)
#include "streaming.h"
{
	unsigned char size[8];
	copy_le16(header.version, version_needed);
	unsigned char magic[4];
	*dos_time = tm.tm_sec / 2 + tm.tm_min * 32 + tm.tm_hour * 2048;


	unsigned char _end[1];
		copy_le32(trailer.magic, 0x08074b50);
	write_or_die(1, &header, ZIP_LOCAL_HEADER_SIZE);
			   const struct object_id *oid,
	if (driver->binary != -1)
	strbuf_add(&zip_dir, &extra, ZIP_EXTRA_MTIME_SIZE);

	unsigned char magic[2];
	unsigned char offset[8];


}
		copy_le32(trailer.size, size);
	unsigned char magic[4];
		strbuf_addch(sb, n & 0xff);
							    path_without_prefix,
		attr2 = 16;
	strbuf_add_le(&zip_dir, 2, zip_time);
	maxsize = git_deflate_bound(&stream, size);
					     oid_to_hex(oid));
		if (c == '\0')

		set_zip_header_data_desc(&header, size, compressed_size, crc);
	strbuf_add_le(&zip_dir, 2, version_needed);
static struct archiver zip_archiver = {
static int zip_time;
		for (;;) {
static int has_only_ascii(const char *s)
static void *zlib_deflate_raw(void *data, unsigned long size,
static uintmax_t zip_offset;
static int write_zip_entry(struct archiver_args *args,
		zip_dir_extra_size += 2 + 2 + zip64_dir_extra_payload_size;
		set_zip_header_data_desc(&header, 0xffffffff, 0xffffffff, crc);
		need_zip64_extra = 1;
static void set_zip_header_data_desc(struct zip_local_header *header,
static void copy_le64(unsigned char *dest, uint64_t n)

}
		git_deflate_end(&zstream);
		buffer = NULL;
		if (size >= 0xffffffff)
	zip_offset += ZIP_LOCAL_HEADER_SIZE;
};
	size_t header_extra_size = ZIP_EXTRA_MTIME_SIZE;
	if (need_zip64_extra) {
	unsigned char compressed_size[4];
	time = (time_t)*timestamp;
	if (oid)

}
			out = buffer = NULL;
 * On ARM, padding is added at the end of the struct, so a simple
			zip64_dir_extra_payload_size += 8;
		if (!out || compressed_size >= size) {
	unsigned char directory_start_disk[4];
{
		ssize_t readlen;
				die(_("deflate error (%d)"), result);
		out_len = zstream.next_out - compressed;
	dest[1] = 0xff & (n >> 010);
		attr2 = S_ISLNK(mode) ? ((mode | 0777) << 16) :
static void write_zip_data_desc(unsigned long size,
	while (size-- > 0) {
static uint32_t clamp32(uintmax_t n)
static void write_zip_trailer(const struct object_id *oid)
	 offsetof(struct zip64_dir_trailer, creator_version))
	register_archiver(&zip_archiver);
	git_deflate_end(&stream);
	free(buffer);
	} else {
	unsigned char magic[4];
#define STREAM_BUFFER_SIZE (1024 * 16)
}

		compressed_size = size;
	write_or_die(1, &extra, ZIP_EXTRA_MTIME_SIZE);
#define ZIP64_EXTRA_SIZE	offsetof(struct zip64_extra, _end)

	strbuf_init(&zip_dir, 0);

{
	free(deflated);
	copy_le16(extra.magic, 0x5455);
		unsigned char buf[STREAM_BUFFER_SIZE];
		}

#define ZIP64_DIR_TRAILER_LOCATOR_SIZE \
	return err;

{
struct zip64_data_desc {
		}
	dest[0] = 0xff & n;
			is_binary = entry_is_binary(args->repo->index,
#define ZIP64_DATA_DESC_SIZE	offsetof(struct zip64_data_desc, _end)
	if (!err)
{
	int err;
	}

		zstream.avail_in = 0;
		compressed_size = 0;
			if (is_binary == -1)
	dest[7] = 0xff & (n >> 070);
		write_or_die(1, &trailer, ZIP_DATA_DESC_SIZE);
		return driver->binary;
	ZIP_METHOD_STORE = 0,
	strbuf_release(&zip_dir);
	unsigned char version[2];
	offsetof(struct zip64_dir_trailer_locator, _end)
}

				return error(_("cannot stream blob %s"),

			method = ZIP_METHOD_STORE;
			method = ZIP_METHOD_DEFLATE;
		die(_("timestamp too large for this system: %"PRItime),
}
	unsigned char extra_size[2];
#define ZIP64_DIR_TRAILER_RECORD_SIZE \
	size_t zip_dir_extra_size = ZIP_EXTRA_MTIME_SIZE;
		write_or_die(1, &extra64, ZIP64_EXTRA_SIZE);
	int is_binary = -1;
	ZIP_METHOD_DEFLATE = 8

	}
struct zip64_extra {

			}
		if (S_ISLNK(mode) || (mode & 0111))
	unsigned long flags = 0;
		if (compressed_size >= 0xffffffff)
}
		zstream.next_out = compressed;
	(ZIP_EXTRA_MTIME_SIZE - offsetof(struct zip_extra_mtime, flags))
static void copy_le32_clamp(unsigned char *dest, uint64_t n, int *clamped)
static int write_zip_archive(const struct archiver *ar,
			      unsigned long *compressed_size)
							&size);
	write_or_die(1, &trailer, ZIP_DIR_TRAILER_SIZE);
	unsigned char entries[2];

	copy_le16(trailer64.creator_version, max_creator_version);
	unsigned char entries[8];
	unsigned char compressed_size[8];
	strbuf_add_le(&zip_dir, 2, method);


	dest[5] = 0xff & (n >> 050);
			return 1;
	int need_zip64_extra = 0;
	zip_offset += pathlen;
	copy_le32(header.magic, 0x04034b50);
	copy_le32_clamp(trailer.offset, zip_offset, &clamped);
		max_creator_version = creator_version;
	buffer = xmalloc(maxsize);
		write_zip_trailer(args->commit_oid);
	unsigned char mtime[2];

static void copy_le16_clamp(unsigned char *dest, uint64_t n, int *clamped)
	unsigned char record_size[8];
			out = buffer;
	const char *path_without_prefix = path + args->baselen;
		if (compressed_size >= 0xffffffff)
	if (S_ISDIR(mode) || S_ISGITLINK(mode)) {

			out_len = zstream.next_out - compressed;

	ARCHIVER_WANT_COMPRESSION_LEVELS|ARCHIVER_REMOTE
		if (is_utf8(path))
		strbuf_add_le(&zip_dir, 2, zip64_dir_extra_payload_size);
		copy_le64(extra64.size, size);
	strbuf_add_le(&zip_dir, 2, creator_version);
#define ZIP_EXTRA_MTIME_PAYLOAD_SIZE \
	write_or_die(1, &trailer64, ZIP64_DIR_TRAILER_SIZE);
				zstream.avail_out = sizeof(compressed);
	copy_le64(trailer64.size, zip_dir.len);
	unsigned char disk[4];
				write_or_die(1, compressed, out_len);
	unsigned char size[8];

		zip_offset += ZIP64_DATA_DESC_SIZE;
}

		int c = *s++;
#include "archive.h"

	int clamped = 0;
	return max;
		zstream.avail_out = sizeof(compressed);
			(mode & 0111) ? ((mode) << 16) : 0;
	copy_le32(trailer.magic, 0x06054b50);
	strbuf_add_le(&zip_dir, 2, 0);		/* comment length */
	if (pathlen > 0xffff) {

	strbuf_add_le(&zip_dir, 4, 0x02014b50);	/* magic */

struct zip_data_desc {
	unsigned char version[2];
				compressed_size += out_len;
#define ZIP64_EXTRA_PAYLOAD_SIZE \
				     unsigned long compressed_size,
	unsigned char magic[4];

	extra.flags[0] = 1;	/* just mtime */

static struct strbuf zip_dir;
{
		method = ZIP_METHOD_STORE;
	if (need_zip64_extra) {
	crc = crc32(0, NULL, 0);
void init_zip_archiver(void)
			return readlen;
{
	unsigned char _end[1];
							    buf, readlen);
	copy_le16(trailer64.version, 45);
{
		write_zip64_trailer();
{
	*dos_date = tm.tm_mday + (tm.tm_mon + 1) * 32 +
 * Copyright (c) 2006 Rene Scharfe
	void *buffer;
			warning(_("path is not valid UTF-8: %s"), path);
	copy_le16(header.extra_length, header_extra_size);
	copy_le16(header.mdate, zip_date);
		close_istream(stream);
};
enum zip_method {

}
		result = git_deflate(&zstream, Z_FINISH);
	unsigned char mtime[4];
	copy_le16(trailer.comment_length, oid ? the_hash_algo->hexsz : 0);

};
	dest[6] = 0xff & (n >> 060);
	copy_le16(header.mtime, zip_time);
	} else if (stream && method == ZIP_METHOD_DEFLATE) {
	unsigned char _end[1];

			readlen = read_istream(stream, buf, sizeof(buf));
	(ZIP64_DIR_TRAILER_SIZE - \
	unsigned int version_needed = 10;
		return n;
{
		write_zip_data_desc(size, compressed_size, crc);

	copy_le16_clamp(trailer.entries, zip_dir_entries, &clamped);
	strbuf_add_le(&zip_dir, 2, 0);		/* disk */
		if (readlen)
	for (;;) {
	} else {
static int entry_is_binary(struct index_state *istate, const char *path,
	strbuf_add_le(&zip_dir, 2, zip_date);
				     unsigned long size,
}
			buffer = object_file_to_archive(args, path, oid, mode,
		return error(_("unsupported file mode: 0%o (SHA1: %s)"), mode,
	copy_le64(trailer64.entries, zip_dir_entries);
	unsigned char mdate[2];
	}
{
	}
	copy_le16(extra.extra_size, ZIP_EXTRA_MTIME_PAYLOAD_SIZE);
#include "object-store.h"
		close_istream(stream);
	strbuf_add_le(&zip_dir, 2, pathlen);
			creator_version = 0x0317;
				return error(_("cannot read %s"),
static void copy_le16(unsigned char *dest, unsigned int n)
	struct zip64_dir_trailer_locator locator64;
	unsigned char extra_length[2];
			if (is_binary == -1)
#define ZIP_DIR_HEADER_SIZE	offsetof(struct zip_dir_header, _end)
			   const char *path, size_t pathlen,
		copy_le16(extra64.extra_size, ZIP64_EXTRA_PAYLOAD_SIZE);
			return readlen;
		if (readlen)
	if (need_zip64_extra)
struct zip_dir_trailer {
				     unsigned long crc)

		if (offset >= 0xffffffff)
#include "cache.h"
	if (creator_version > max_creator_version)
		write_or_die(1, compressed, out_len);
	} else if (S_ISREG(mode) || S_ISLNK(mode)) {

		copy_le64(extra64.compressed_size, compressed_size);
}
	if (stream && method == ZIP_METHOD_STORE) {
				is_binary = entry_is_binary(args->repo->index,
		zip_offset += compressed_size;

	strbuf_add_le(&zip_dir, 4, attr2);
		}
};
 * we're interested in.
	unsigned char compressed_size[4];
static void write_zip64_trailer(void)


	}
	unsigned char crc32[4];
	unsigned char _end[1];
	return 0;
	do {


	}
	}
{
						  args->compression_level,
}
				is_binary = entry_is_binary(args->repo->index,
struct zip_extra_mtime {

	stream.avail_out = maxsize;

		copy_le32(trailer.crc32, crc);
	strbuf_add(&zip_dir, path, pathlen);
				unsigned long crc)
	int result;
		struct zip_data_desc trailer;
	strbuf_add_le(&zip_dir, 4, clamp32(offset));
#include "userdiff.h"
	unsigned char number_of_disks[4];
}
	copy_le32(trailer64.disk, 0);
	write_zip_archive,
 * sizeof(struct ...) reports two bytes more than the payload size
struct zip64_dir_trailer {
	copy_le32(trailer64.magic, 0x06064b50);
	strbuf_add_le(&zip_dir, 2, !is_binary);
	unsigned char crc32[4];
						    path_without_prefix,
	}
	copy_le16(header.flags, flags);
	strbuf_add_le(&zip_dir, 4, clamp32(compressed_size));
	dest[3] = 0xff & (n >> 030);
			strbuf_add_le(&zip_dir, 8, size);
#include "utf8.h"
			      int compression_level,
	dest[1] = 0xff & (n >> 010);
}
	if (buffer && method == ZIP_METHOD_DEFLATE) {

		out = NULL;
		ssize_t readlen;
		out = deflated = zlib_deflate_raw(buffer, size,

		copy_le32(trailer.compressed_size, compressed_size);
	    offset > 0xffffffff) {
	struct zip64_dir_trailer trailer64;
			crc = crc32(crc, buffer, size);
		} else {
	copy_le32(locator64.magic, 0x07064b50);

static uint64_t clamp_max(uint64_t n, uint64_t max, int *clamped)
	zip_offset += ZIP_EXTRA_MTIME_SIZE;
	unsigned char entries_on_this_disk[8];
{
	git_deflate_init_raw(&stream, compression_level);
					      NULL);
	}
							&type, &size);
			compressed_size = size;

	stream.avail_in = size;
	const uintmax_t max = 0xffffffff;
		compressed_size = 0;
	unsigned char compression_method[2];
		    (tm.tm_year + 1900 - 1980) * 512;
	*compressed_size = stream.total_out;

	time_t time;
			if (!stream)

		int result;
#define ZIP_LOCAL_HEADER_SIZE	offsetof(struct zip_local_header, _end)
		need_zip64_extra = 1;
		    size > big_file_threshold) {
		write_or_die(1, oid_to_hex(oid), the_hash_algo->hexsz);
	struct git_istream *stream = NULL;
	if (n <= max)
		write_or_die(1, &trailer, ZIP64_DATA_DESC_SIZE);

			if (readlen <= 0)
 */
			zip64_dir_extra_payload_size += 8;
	dos_time(&args->time, &zip_date, &zip_time);
		copy_le32(trailer.crc32, crc);
		if (S_ISREG(mode) && type == OBJ_BLOB && !args->convert &&
	unsigned char flags[2];
		compressed_size = (method == ZIP_METHOD_STORE) ? size : 0;
	copy_le32(trailer64.directory_start_disk, 0);
			if (result != Z_OK)
		    *timestamp);
{
			readlen = read_istream(stream, buf, sizeof(buf));
	stream.next_out = buffer;
};
	if (!driver)

				oid_to_hex(oid));
							    path_without_prefix,
{
	if (clamped)

	unsigned long compressed_size;
	unsigned char size[4];
		zip_offset += ZIP64_EXTRA_SIZE;
	return buffer;
	copy_le16(trailer.disk, 0);
};
	if (date_overflows(*timestamp))
static void dos_time(timestamp_t *timestamp, int *dos_date, int *dos_time)
	dest[0] = 0xff & n;
	git_zstream stream;
	if (result != Z_STREAM_END) {
			zstream.next_in = buf;
	strbuf_add_le(&zip_dir, 4, clamp32(size));
	write_or_die(1, path, pathlen);

struct zip64_dir_trailer_locator {
		size_t out_len;
		result = git_deflate(&stream, Z_FINISH);
	unsigned long attr2;

}
	strbuf_add_le(&zip_dir, 4, crc);
	unsigned char magic[4];
	dest[1] = 0xff & (n >> 010);

	unsigned char filename_length[2];
	dest[2] = 0xff & (n >> 020);
	write_or_die(1, zip_dir.buf, zip_dir.len);
			crc = crc32(crc, buf, readlen);


};
		git_zstream zstream;
		if (offset >= 0xffffffff)
		size = 0;
	struct tm tm;
	copy_le16_clamp(trailer.entries_on_this_disk, zip_dir_entries,

			zstream.avail_in = readlen;
		write_zip_data_desc(size, compressed_size, crc);
			strbuf_add_le(&zip_dir, 8, compressed_size);
	struct zip_dir_trailer trailer;
	copy_le16(header.filename_length, pathlen);
};

		unsigned char compressed[STREAM_BUFFER_SIZE * 2];
		enum object_type type = oid_object_info(args->repo, oid,
				break;
}
		copy_le64(trailer.size, size);
	unsigned char offset[8];
	unsigned char _end[1];

	unsigned long size;
		compressed_size += out_len;
			flags |= ZIP_STREAM;
			     struct archiver_args *args)
		copy_le32(trailer.magic, 0x08074b50);
	}
		if (size >= 0xffffffff)
		if (result != Z_STREAM_END)
	}
#include "config.h"
	enum zip_method method;
	*clamped = 1;
		else
{
			die("deflate error (%d)", result);

	unsigned char *out;
		zip_offset += compressed_size;
#include "xdiff-interface.h"
/*
	unsigned char disk[4];
			if (!buffer)
						  &compressed_size);
{
		version_needed = 45;
	unsigned char creator_version[2];
		strbuf_add_le(&zip_dir, 2, 0x0001);	/* magic */
			stream = open_istream(args->repo, oid, &type, &size,
			write_or_die(1, buf, readlen);
				(int)pathlen, oid_to_hex(oid), path);

#define ZIP_DIR_TRAILER_SIZE	offsetof(struct zip_dir_trailer, _end)
		write_or_die(1, out, compressed_size);
				unsigned long compressed_size,
	unsigned char flags[1];

	return (n < max) ? n : max;
	return userdiff_config(var, value);
	unsigned char offset[4];

	uintmax_t offset = zip_offset;
				break;
			if (readlen <= 0)
	copy_le16(header.compression_method, method);
		struct zip64_data_desc trailer;
	(ZIP64_EXTRA_SIZE - offsetof(struct zip64_extra, size))
	if (stream && size > 0x7fffffff)
							    buf, readlen);
	copy_le16(trailer.directory_start_disk, 0);

	unsigned char size[4];
			&clamped);

/*
		}
	unsigned char _end[1];

#define ZIP_DATA_DESC_SIZE	offsetof(struct zip_data_desc, _end)
	write_or_die(1, &locator64, ZIP64_DIR_TRAILER_LOCATOR_SIZE);
	unsigned char _end[1];
	localtime_r(&time, &tm);
}
	struct zip_extra_mtime extra;

		zip_offset += compressed_size;
	copy_le32(header->size, size);
 */

	strbuf_add_le(&zip_dir, 2, zip_dir_extra_size);
		if (!isascii(c))
	unsigned char extra_size[2];
	unsigned char comment_length[2];
	err = write_archive_entries(args, write_zip_entry);
	strbuf_add_le(&zip_dir, 2, flags);
			   unsigned int mode)
		n >>= 8;
		zip_offset += ZIP_DATA_DESC_SIZE;
static void copy_le32(unsigned char *dest, unsigned int n)
	zip_dir_entries++;
		driver = userdiff_find_by_name("default");
#define ZIP_EXTRA_MTIME_SIZE	offsetof(struct zip_extra_mtime, _end)
	} while (result == Z_OK);
	struct zip64_extra extra64;
		git_deflate_init_raw(&zstream, args->compression_level);
	copy_le32(locator64.disk, 0);
			if (out_len > 0) {
}

{
		copy_le64(trailer.compressed_size, compressed_size);
		free(buffer);
	}
			flags |= ZIP_UTF8;
	unsigned int creator_version = 0;
	return -!!n;
static unsigned int max_creator_version;
static int archive_zip_config(const char *var, const char *value, void *data)
#define ZIP64_DIR_TRAILER_SIZE	offsetof(struct zip64_dir_trailer, _end)
