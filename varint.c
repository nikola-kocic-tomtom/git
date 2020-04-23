	unsigned char c = *buf++;
}
	*bufp = buf;
{
	if (buf)

#include "varint.h"
		memcpy(buf, varint + pos, sizeof(varint) - pos);
		val = (val << 7) + (c & 127);
	while (c & 128) {
	unsigned char varint[16];
}
			return 0; /* overflow */

		val += 1;
	const unsigned char *buf = *bufp;
{
	return sizeof(varint) - pos;
		c = *buf++;
	unsigned pos = sizeof(varint) - 1;
	}
	varint[pos] = value & 127;
	while (value >>= 7)
uintmax_t decode_varint(const unsigned char **bufp)
		varint[--pos] = 128 | (--value & 127);
int encode_varint(uintmax_t value, unsigned char *buf)
		if (!val || MSB(val, 7))
	return val;
	uintmax_t val = c & 127;
#include "git-compat-util.h"
