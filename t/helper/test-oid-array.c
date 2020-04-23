#include "oid-array.h"
			oid_array_append(&array, &oid);
			die("unknown command: %s", line.buf);
}
				die("not a hexadecimal oid: %s", arg);
		if (skip_prefix(line.buf, "append ", &arg)) {
				die("not a hexadecimal oid: %s", arg);
	struct oid_array array = OID_ARRAY_INIT;
	struct strbuf line = STRBUF_INIT;
		} else if (skip_prefix(line.buf, "lookup ", &arg)) {
}
		const char *arg;
			oid_array_for_each_unique(&array, print_oid, NULL);
static int print_oid(const struct object_id *oid, void *data)
		} else if (!strcmp(line.buf, "clear"))
{
	return 0;
#include "test-tool.h"
	}

			printf("%d\n", oid_array_lookup(&array, &oid));
	puts(oid_to_hex(oid));
			if (get_oid_hex(arg, &oid))

		else if (!strcmp(line.buf, "for_each_unique"))
			oid_array_clear(&array);
			if (get_oid_hex(arg, &oid))
{
int cmd__oid_array(int argc, const char **argv)

	return 0;
		struct object_id oid;
#include "cache.h"
		else

	while (strbuf_getline(&line, stdin) != EOF) {
