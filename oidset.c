
	int added;
	}

	strbuf_release(&sb);
	if (!fp)
void oidset_clear(struct oidset *set)
{
#include "oidset.h"
{
	return pos != kh_end(&set->set);

	if (pos == kh_end(&set->set))
		if (!sb.len)
	return !added;
	khiter_t pos = kh_get_oid_set(&set->set, *oid);
}
			continue;
	if (initial_size)
	kh_del_oid_set(&set->set, pos);
		 */

#include "cache.h"
}
}
			strbuf_setlen(&sb, name - sb.buf);
int oidset_insert(struct oidset *set, const struct object_id *oid)
	struct strbuf sb = STRBUF_INIT;
int oidset_remove(struct oidset *set, const struct object_id *oid)
	return 1;
		return 0;
}
		name = strchr(sb.buf, '#');
			die("invalid object name: %s", sb.buf);

{
		 * Allow trailing comments, leading whitespace
	kh_put_oid_set(&set->set, *oid, &added);
}


	fclose(fp);
void oidset_init(struct oidset *set, size_t initial_size)
void oidset_parse_file(struct oidset *set, const char *path)
		 * (including before commits), and empty or whitespace
int oidset_contains(const struct oidset *set, const struct object_id *oid)
		oidset_insert(set, &oid);
	while (!strbuf_getline(&sb, fp)) {
		if (name)
	kh_release_oid_set(&set->set);
{
		die_errno("Could not read '%s'", path);
		die("could not open object name list: %s", path);
	FILE *fp;
	khiter_t pos = kh_get_oid_set(&set->set, *oid);
	struct object_id oid;
		const char *p;
	oidset_init(set, 0);
		 * only lines.
		if (parse_oid_hex(sb.buf, &oid, &p) || *p != '\0')
		const char *name;
		/*
{
	memset(&set->set, 0, sizeof(set->set));
}
		kh_resize_oid_set(&set->set, initial_size);
		strbuf_trim(&sb);
	fp = fopen(path, "r");


	if (ferror(fp))
{
