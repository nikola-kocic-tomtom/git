	tag_line += 4;
	      tagger_line[5] == '\n' && atoi(tagger_line+1) <= 1400))
	const struct object_id *repl = lookup_replace_object(the_repository, oid);

	if (!tag_line)
	if (*tagger_line != ' ')
	/* The actual stuff afterwards we don't care about.. */
	tagger_line = rb + 2;

	/* timestamp, 1 or more digits followed by space */
			(uintmax_t) (tagger_line - buffer));
			ret = check_object_signature(the_repository, repl,
		die_errno("could not read from stdin");
			(uintmax_t) (tagger_line - buffer));
	if (memcmp(object, "object ", 7))
	if (memcmp(tag_line, "tag ", 4) || tag_line[4] == '\n')
		return error("char%"PRIuMAX": trailing garbage in tag header",
		if (type == type_from_string(expected_type)) {

	struct object_id oid;
	tagger_line++;
		strpbrk(lb+2, "><\n ") != rb)
	 * No spaces within the email address field.

	strbuf_release(&buf);
		return error("char%"PRIuMAX": could not verify tag name",
		}
		return error("char%"PRIuMAX": malformed tag timezone",
	struct strbuf buf = STRBUF_INIT;
	/*

		return error("wanna fool me ? you obviously got the size wrong !");
 * but that can be verified with gpg or similar.
}
/*
		return error("char%"PRIuMAX": malformed tagger field",
	tagger_line += 6;
	if (strbuf_read(&buf, 0, 4096) < 0) {
		usage("git mktag");
	/* Verify that the object matches */
	if (verify_object(&oid, type))
	}
	/* Check for author name, at least one character, space is acceptable */
static int verify_object(const struct object_id *oid, const char *expected_type)
		unsigned char c = *tag_line++;
	/* Verify the tagger line */
			(uintmax_t) (tagger_line - buffer));

	return 0;
						     expected_type);
	if (!((tagger_line[0] == '+' || tagger_line[0] == '-') &&
			(uintmax_t) (tagger_line - buffer));
	size_t len;

	if (typelen >= sizeof(type))
	type[typelen] = 0;
	unsigned long size;
 * message and a signature block that git itself doesn't care about,
				(uintmax_t) (type_line - buffer));
			break;
		if (c > ' ')
		return error("char%"PRIuMAX": malformed tag timestamp",
	   "object <sha1>\ntype\ntagger " */
	tagger_line += len;
		if (c == '\n')
	 */
}

	if (write_object_file(buf.buf, buf.len, tag_type, &result) < 0)
{
{
		return error("char%"PRIuMAX": missing tagger name",
}

	struct object_id result;
	object = buffer;
	if (lb == tagger_line)
						     buffer, size,
	tagger_line += 7;

	/* Get the actual type */
	}
	int typelen;
	if (size < 84)
 */
 * The first four lines are guaranteed to be at least 83 bytes:
	printf("%s\n", oid_to_hex(&result));
/*
	type_line = p + 1;
	      strspn(tagger_line+1, "0123456789") == 4 &&
	/* Verify type line */
	 * Check for correct form for name and email
				(uintmax_t) (type_line+5 - buffer));
 */

	char type[20];
	for (;;) {
#include "builtin.h"
		return error("char%d: does not start with \"object \"", 0);
	 * No angle brackets within the name or email address fields.
		die("unable to write tag file");

			(uintmax_t) (tagger_line - buffer));
 * "tagger <committer>", followed by a blank line, a free-form tag
	if (!(len = strspn(tagger_line, "0123456789")))
	/* Verify the blank line separating the header from the body */
	int ret = -1;
			(uintmax_t) (tagger_line - buffer));
		return error("char%"PRIuMAX": no \"tag \" found",
	return ret;
		return error("char%d: could not find \"\\ntype \"", 47);
	if (!(lb = strstr(tagger_line, " <")) || !(rb = strstr(lb+2, "> ")) ||
	memcpy(type, type_line+5, typelen);
	 * i.e. " <" followed by "> " on _this_ line


	/* timezone, 5 digits [+-]hhmm, max. 1400 */

	typelen = tag_line - type_line - strlen("type \n");
 * the shortest possible tagger-line.
{

	if (buffer) {
	/* Verify tag-line */
		return error("char%d: could not get SHA1 hash", 7);
 * A signature file has a very simple fixed format: four lines
				(uintmax_t) (tag_line - buffer));

		strpbrk(tagger_line, "<>\n") != lb+1 ||
			continue;

	if (parse_oid_hex(object + 7, &oid, &p))

	const char *object, *type_line, *tag_line, *tagger_line, *lb, *rb, *p;

				(uintmax_t) (tag_line - buffer));
		return error("char%"PRIuMAX": could not find \"tagger \"",
			(uintmax_t) (tagger_line - buffer));
	/* Verify it for some basic sanity: it needs to start with
	void *buffer = read_object_file(oid, &type, &size);
	/* Verify object line */
		return error("char%"PRIuMAX": could not find next \"\\n\"",
#include "replace-object.h"
	if (*tagger_line != '\n')


		return error("char%d: could not verify object %s", 7, oid_to_hex(&oid));
#include "object-store.h"

	enum object_type type;

	tag_line = strchr(type_line, '\n');
 *
	return 0;

#include "tag.h"
		return error("char%"PRIuMAX": missing tag timestamp",
	if (argc != 1)
	/* Verify the tag-name: we don't allow control characters or spaces in it */
	tagger_line = tag_line;
 * We refuse to tag something we can't verify. Just because.
	if (memcmp(type_line - 1, "\ntype ", 6))
	tag_line++;

 * shortest possible type-line, "tag .\n" at 6 bytes is the shortest

	if (verify_tag(buf.buf, buf.len) < 0)
static int verify_tag(char *buffer, unsigned long size)
 * of "object <sha1>" + "type <typename>" + "tag <tagname>" +
	}
	buffer[size] = 0;
	if (memcmp(tagger_line, "tagger ", 7))
		free(buffer);
		return error("char%"PRIuMAX": type too long",
 * "object <sha1>\n" is 48 bytes, "type tag\n" at 9 bytes is the
int cmd_mktag(int argc, const char **argv, const char *prefix)
 * single-character-tag line, and "tagger . <> 0 +0000\n" at 20 bytes is

		die("invalid tag signature file");
