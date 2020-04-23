			/* add / replace entry */
#include "cache.h"
 *
		}
			entry = oidmap_get(&map, &oid);

			}
			struct oidmap_iter iter;

			if (get_oid(p1, &oid)) {

			/* lookup entry in oidmap */
	return 0;
 * iterate -> oidkey1 namevalue1\noidkey2 namevalue2\n...



				printf("Unknown oid: %s\n", p1);
/* key is an oid and value is a name (could be a refname for example) */
			puts(entry ? entry->name : "NULL");
			if (get_oid(p1, &oid)) {
}

		} else if (!strcmp("iterate", cmd)) {
	/* init oidmap */
 * hash oidkey -> sha1hash(oidkey)
	struct oidmap_entry entry;
			if (get_oid(p1, &oid)) {
 */
				printf("Unknown oid: %s\n", p1);
#include "oidmap.h"
		} else if (!strcmp("get", cmd) && p1) {
			continue;

		char *cmd, *p1 = NULL, *p2 = NULL;

	setup_git_directory();
#include "strbuf.h"

			puts(entry ? entry->name : "NULL");


{
 * Read stdin line by line and print result of commands to stdout:
		if (!strcmp("put", cmd) && p1 && p2) {
		} else if (!strcmp("remove", cmd) && p1) {
			printf("Unknown command %s\n", cmd);
 * put oidkey namevalue -> NULL / old namevalue
		cmd = strtok(line.buf, DELIM);
			free(entry);
			free(entry);
	struct strbuf line = STRBUF_INIT;
		p1 = strtok(NULL, DELIM);
	/* process commands from stdin */
		if (p1)

		struct test_entry *entry;
			while ((entry = oidmap_iter_next(&iter)))
	char name[FLEX_ARRAY];

			puts(entry ? entry->name : "NULL");

	}


			p2 = strtok(NULL, DELIM);
#include "test-tool.h"
				printf("Unknown oid: %s\n", p1);
	strbuf_release(&line);
#define DELIM " \t\r\n"
 *
				continue;

		} else {
			entry = oidmap_put(&map, entry);
 * get oidkey -> NULL / namevalue
				continue;
	struct oidmap map = OIDMAP_INIT;
				printf("%s %s\n", oid_to_hex(&entry->entry.oid), entry->name);
			}

				continue;
int cmd__oidmap(int argc, const char **argv)
			/* print result and free entry*/

	oidmap_init(&map, 0);
		if (!cmd || *cmd == '#')
			FLEX_ALLOC_STR(entry, name, p2);

			/* remove entry from oidmap */
	while (strbuf_getline(&line, stdin) != EOF) {
 * remove oidkey -> NULL / old namevalue
	oidmap_free(&map, 1);
struct test_entry {
			/* create entry with oid_key = p1, name_value = p2 */
			/* print result */



};
		/* ignore empty lines */

/*
			oidcpy(&entry->entry.oid, &oid);
			}


		/* break line into command and up to two parameters */
			oidmap_iter_init(&map, &iter);
		struct object_id oid;
			/* print and free replaced entry, if any */
			entry = oidmap_remove(&map, &oid);
