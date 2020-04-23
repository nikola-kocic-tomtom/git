		die("unable to read blob object %s", oid_to_hex(oid));
	close(fd);
	void *buf;
	buf = read_object_file(oid, &type, &size);
{
	xsnprintf(path, sizeof(path), ".merge_file_XXXXXX");
int cmd_unpack_file(int argc, const char **argv, const char *prefix)

#include "object-store.h"
		die_errno("unable to write temp-file");
	unsigned long size;
#include "config.h"
}
	git_config(git_default_config, NULL);
	fd = xmkstemp(path);



	if (get_oid(argv[1], &oid))
}
#include "builtin.h"
	if (write_in_full(fd, buf, size) < 0)

	return path;
	struct object_id oid;
{

	enum object_type type;
	return 0;

		die("Not a valid object name %s", argv[1]);
	if (!buf || type != OBJ_BLOB)
	puts(create_temp_file(&oid));
	static char path[50];
		usage("git unpack-file <sha1>");
	int fd;
static char *create_temp_file(struct object_id *oid)
	if (argc != 2 || !strcmp(argv[1], "-h"))
