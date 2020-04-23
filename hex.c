	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 10-17 */
	return GIT_HASH_UNKNOWN;
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* d0-d7 */
		*end = hex + algop->hexsz;
 * length to longest length.
char *hash_to_hex_algop_r(char *buffer, const unsigned char *hash,
}
	}
{

	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 28-2f */
	 -1, 10, 11, 12, 13, 14, 15, -1,		/* 60-67 */
{
			return -1;
}
	static int bufno;
int parse_oid_hex_any(const char *hex, struct object_id *oid, const char **end)
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 08-0f */
	return hash_to_hex_algop_r(hexbuffer[bufno], hash, algop);
			      const struct git_hash_algo *algop)

	 -1, -1, -1, -1, -1, -1, -1, -1,		/* c0-c7 */
	bufno = (bufno + 1) % ARRAY_SIZE(hexbuffer);
char *hash_to_hex_algop(const unsigned char *hash, const struct git_hash_algo *algop)
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 70-77 */
{

		*binary++ = val;
		if (!get_hash_hex_algop(hex, oid->hash, &hash_algos[i]))
	  0,  1,  2,  3,  4,  5,  6,  7,		/* 30-37 */

	int ret = get_oid_hex_any(hex, oid);
	return ret;
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* d8-df */
	return 0;
	}
	int i;
	return ret;
	}
 */
}

	*buf = '\0';
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 50-57 */
};

{
		unsigned int val = *hash++;
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* f8-ff */
{
#include "cache.h"
}

char *oid_to_hex_r(char *buffer, const struct object_id *oid)
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 78-7f */
			return i;
 * NOTE: This function relies on hash algorithms being in order from shortest
static int get_hash_hex_algop(const char *hex, unsigned char *hash,

		if (val < 0)
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 68-67 */
		if (val & ~0xff)
			  const struct git_hash_algo *algop)
int hex_to_bytes(unsigned char *binary, const char *hex, size_t len)
int parse_oid_hex_algop(const char *hex, struct object_id *oid,
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* b8-bf */
	for (i = 0; i < algop->rawsz; i++) {
	 -1, 10, 11, 12, 13, 14, 15, -1,		/* 40-47 */
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 48-4f */

	char *buf = buffer;
			const char **end,
int get_sha1_hex(const char *hex, unsigned char *sha1)
	return 0;

		int val = hex2chr(hex);
{

}
	for (; len; len--, hex += 2) {
		*end = hex + hash_algos[ret].hexsz;
	return get_oid_hex_algop(hex, oid, the_hash_algo);
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 20-27 */
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* c8-cf */
{
	return get_hash_hex_algop(hex, sha1, the_hash_algo);
	return buffer;
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* a8-af */
	int ret = get_hash_hex_algop(hex, oid->hash, algop);
{
{
	int i;

{

int get_oid_hex_algop(const char *hex, struct object_id *oid,
	return hash_to_hex_algop_r(buffer, oid->hash, the_hash_algo);
}
	}
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 80-87 */

const signed char hexval_table[256] = {
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 88-8f */
	return get_hash_hex_algop(hex, oid->hash, algop);
	if (ret)
	return hash_to_hex_algop(oid->hash, the_hash_algo);
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* f0-f7 */
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* a0-a7 */
char *oid_to_hex(const struct object_id *oid)
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 18-1f */
		*hash++ = val;
int get_oid_hex_any(const char *hex, struct object_id *oid)
	return hash_to_hex_algop(hash, the_hash_algo);
	for (i = GIT_HASH_NALGOS - 1; i > 0; i--) {
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* e8-ef */
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 98-9f */
/*
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 00-07 */
	static const char hex[] = "0123456789abcdef";
			return -1;
			const struct git_hash_algo *algop)
	if (!ret)
}
}

int parse_oid_hex(const char *hex, struct object_id *oid, const char **end)
		*buf++ = hex[val & 0xf];
{
	int i;
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* e0-e7 */
}
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 58-5f */
}
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* b0-b7 */
}
		*buf++ = hex[val >> 4];
{
		hex += 2;

}
}
{
		      const struct git_hash_algo *algop)
	return parse_oid_hex_algop(hex, oid, end, the_hash_algo);
{

	  8,  9, -1, -1, -1, -1, -1, -1,		/* 38-3f */
		unsigned int val = (hexval(hex[0]) << 4) | hexval(hex[1]);

int get_oid_hex(const char *hex, struct object_id *oid)
	 -1, -1, -1, -1, -1, -1, -1, -1,		/* 90-97 */
char *hash_to_hex(const unsigned char *hash)
}
	static char hexbuffer[4][GIT_MAX_HEXSZ + 1];
	for (i = 0; i < algop->rawsz; i++) {
