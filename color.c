		ptr++;
	unsigned char value;
	return -1;
		return 0;
 */
	if (strncasecmp(name, "bright", 6) == 0) {
}
		fprintf(fp, "%s", GIT_COLOR_RESET);
{
	COLOR_FOREGROUND_256 = 38,

			attr |= (1 << val);
	GIT_COLOR_CYAN,
			out->type = COLOR_ANSI;
	OUT(0);


		color_offset = COLOR_FOREGROUND_BRIGHT_ANSI;
	}
	r += vfprintf(fp, fmt, args);
	return GIT_COLOR_AUTO;
		dst[0] = '\0';

			out->value = val;
		/*
	GIT_COLOR_BOLD_MAGENTA,
	return 0;
			out->value = val + COLOR_FOREGROUND_ANSI;
	if (len == 7 && name[0] == '#') {

		}
				continue;
		break;
/*
{
	va_list args;
			attr &= ~bit;
	static const char * const color_names[] = {
static int match_word(const char *word, int len, const char *match)
 * already have the ANSI escape code in it. "out" should have enough
 */
{
	return out;
{
		COLOR_256,
	GIT_COLOR_BLUE,
{
		OUT('[');
{
		break;
{

	GIT_COLOR_BOLD_RED,

		COLOR_UNSPECIFIED = 0,
	 * NEEDSWORK: This function is sometimes used from multiple threads, and
		}
 * If an ANSI color is recognized in "name", fill "out" and return 0.


}
	/* Try a 24-bit RGB value */
#include "config.h"


		 * numbers are bogus.
		COLOR_ANSI, /* basic 0-7 ANSI colors */
		while (len > 0 && !isspace(word[wordlen])) {
			out->type = COLOR_ANSI;
	int i;
	int r;
	*dst++ = (x); \
	static int color_stderr_is_tty = -1;
		ATTR("bold",      1, 22),
			out->type = COLOR_NORMAL;

			return 0;
 * The list of available column colors.
		if (!strcasecmp(value, "never"))
			return 0;
			goto bad;
	}
int color_stdout_is_tty = -1;
	 */
	if (match_word(name, len, "normal")) {
		return 0;
			want_auto[fd] = check_auto_color(fd);


	 * we always write the same value, but it's still wrong. This function
		    !get_hex_color(name + 3, &out->green) &&
		int i;
	case COLOR_RGB:
	}
	GIT_COLOR_MAGENTA,
{
	return error(_("invalid color value: %.*s"), value_len, value);

	*out = val;
	}

	}
		}
	};
	COLOR_FOREGROUND_ANSI = 30,
	}
	if (background)
	if (var < 0)

		COLOR_NORMAL,
		skip_prefix_mem(name, len, "-", &name, &len);
		return 0;

 */
		out += xsnprintf(out, len, "%d;5;%d", COLOR_FOREGROUND_256 + offset,
	}
	if (attr || !color_empty(&fg) || !color_empty(&bg)) {
			return 0;
			return 0;
	case COLOR_NORMAL:
	if (parse_ansi_color(out, name, len) == 0) {
			if (fg.type == COLOR_UNSPECIFIED) {
			return 1;
		var = git_use_color_default;
static int parse_attr(const char *name, size_t len)
	static int want_auto[3] = { -1, -1, -1 };

	if (!strcmp(var, "color.ui")) {
	if (var == GIT_COLOR_AUTO) {
/*
			len--;
	return r;
	for (i = 0; i < ARRAY_SIZE(attrs); i++) {
		for (i = 0; attr; i++) {
	char *end = dst + COLOR_MAXLEN;

bad:
	/* The numeric value for ANSI and 256-color modes */
int want_color_fd(int fd, int var)
	return 0;
}
static int git_use_color_default = GIT_COLOR_AUTO;

	fprintf(fp, "%s", sb->buf);
	va_end(args);
	int i;
		val = parse_attr(word, wordlen);

	return c->type <= COLOR_NORMAL;

#define OUT(x) do { \
		}
		    !get_hex_color(name + 5, &out->blue)) {
	return r;
		name += 6;
		git_use_color_default = git_config_colorbool(var, value);
			dst = color_output(dst, end - dst, &bg, 1);
	int color_offset = COLOR_FOREGROUND_ANSI;
			if (sep++)

#define ATTR(x, val, neg) { (x), sizeof(x)-1, (val), (neg) }
	/* 24-bit RGB color values */
		out->type = COLOR_NORMAL;
			}
	if (git_color_config(var, value, cb) < 0)
		} else if (val < 16) {
				OUT(';');
		size_t len;
		break;
	long val;
	};
			if (bg.type == COLOR_UNSPECIFIED) {
			return GIT_COLOR_AUTO;
		OUT('m');
	if (*is_tty_p || (fd == 1 && pager_in_use() && pager_use_color)) {
{
				continue;
	}
		COLOR_RGB
	struct color fg = { COLOR_UNSPECIFIED };
		xsnprintf(dst, end - dst, GIT_COLOR_RESET);
		ATTR("blink",     5, 25),
		return 0;

		return 0;
	/* [fg [bg]] [attr]... */
}
{
			return 0;
		return want_auto[fd];
/* Ignore the RESET at the end when giving the size */
 * Write the ANSI color codes for "c" to "out"; the string should
/*
	va_end(args);
		fprintf(fp, "%s", color);
int color_parse(const char *value, char *dst)
	val = strtol(name, &end, 10);
static int color_vfprintf(FILE *fp, const char *color, const char *fmt,
		if (val < -1)
static int color_empty(const struct color *c)
			if (sep++)
			wordlen++;

		/* Rewrite 8-15 as more-portable aixterm colors. */

		return 0;
static int parse_color(struct color *out, const char *name, int len)
}
			if (sep++)
	GIT_COLOR_GREEN,
	if (*color)
				OUT(';');
 * "match" exactly?
}

	return -1;
static int parse_ansi_color(struct color *out, const char *name, int len)
		break;
	if (value) {
	GIT_COLOR_RESET,
		} else if (val < 8) {
/* An individual foreground or background color. */
		len -= 6;
}
		/* Rewrite 0-7 as more-portable standard colors. */
				fg = c;

	if (*is_tty_p < 0)
	case COLOR_ANSI:

int color_parse_mem(const char *value, int value_len, char *dst)
		out += xsnprintf(out, len, "%d;2;%d;%d;%d",
		if (0 <= val)
	return color_parse_mem(value, strlen(value), dst);
	return var;
			out->value = i + color_offset;
	GIT_COLOR_RED,
		BUG("file descriptor out of range: %d", fd);
	if (*color)
		if (!strcasecmp(value, "auto"))
	if (*color)
	if (skip_prefix_mem(name, len, "no", &name, &len)) {
		 */
}
	}
		}
};
struct color {
static int get_hex_color(const char *in, unsigned char *out)
#undef ATTR
	struct color bg = { COLOR_UNSPECIFIED };
			return 0;
	COLOR_BACKGROUND_OFFSET = 10,

		return -1;
 * Otherwise, leave out unchanged and return -1.
}
	}

	if (!strncasecmp(ptr, "reset", len)) {
	unsigned char red, green, blue;
			return negate ? attrs[i].neg : attrs[i].val;
		else
	}
			; /* fall through to error */
{
}
	/*
	return !strcmp(c, "NIL");


		if (!is_terminal_dumb())
			return 1;
	}
		"blue", "magenta", "cyan", "white"
	switch (c->type) {
	 * we end up using want_auto racily. That "should not matter" since
}
int color_fprintf_ln(FILE *fp, const char *color, const char *fmt, ...)
		if (!get_hex_color(name + 1, &out->red) &&


			}
static char *color_output(char *out, int len, const struct color *c, int background)
#include "color.h"
	/* Missing or explicit false to turn off colorization */

	case COLOR_UNSPECIFIED:
	if (val & ~0xff)
};
	val = (hexval(in[0]) << 4) | hexval(in[1]);
		}
		return -1;

			dst = color_output(dst, end - dst, &fg, 0);
	GIT_COLOR_YELLOW,
	if (trail)

			out->type = COLOR_RGB;
	return -1;
int color_fprintf(FILE *fp, const char *color, const char *fmt, ...)
		const char *name;
	/* And finally try a literal 256-color-mode number */
		ATTR("strike",    9, 29)
		int val, wordlen = 0;
#undef OUT
	/* Positions in array must match ANSI color codes */
	va_start(args, fmt);
	GIT_COLOR_BOLD_GREEN,
{
	int negate = 0;
		}
		ATTR("reverse",   7, 27),
		BUG("color parsing ran out of space"); \
	int len = value_len;
	return !strncasecmp(word, match, len) && !match[len];

				 COLOR_FOREGROUND_RGB + offset,
		if (match_word(name, len, color_names[i])) {
} while(0)
			ptr++;
	GIT_COLOR_BOLD_BLUE,
	/* First try the special word "normal"... */

 * "word" is a buffer of length "len"; does it match the NUL-terminated

		if (want_auto[fd] < 0)
		}
			len--;
}
		const char *word = ptr;
const int column_colors_ansi_max = ARRAY_SIZE(column_colors_ansi) - 1;
{
const char *column_colors_ansi[] = {
		negate = 1;
	/* any normal truth value defaults to 'auto' */
	va_list args;
			if (!(attr & bit))
			dst += xsnprintf(dst, end - dst, "%d", i);
 * space in it to fit any color.
	}
	}
		while (len > 0 && isspace(*ptr)) {
	} attrs[] = {
		ATTR("ul",        4, 24),
		 * Allow "-1" as an alias for "normal", but other negative
{
{
};
int git_color_config(const char *var, const char *value, void *cb)
			unsigned bit = (1 << i);
				OUT(';');
		if (attrs[i].len == len && !memcmp(attrs[i].name, name, len))
	unsigned int val;

		offset = COLOR_BACKGROUND_OFFSET;

	return git_default_config(var, value, cb);
			goto bad;
	if (fd < 1 || fd >= ARRAY_SIZE(want_auto))
	}
	return r;
int git_color_default_config(const char *var, const char *value, void *cb)
		if (!color_empty(&fg)) {
enum {
{
int color_is_nil(const char *c)
	}
		ptr = word + wordlen;
}
			out->type = COLOR_ANSI;
{

		} else if (val < 256) {
		va_list args, const char *trail)
		if (!parse_color(&c, word, wordlen)) {
		int sep = 0;
		r += fprintf(fp, "%s", trail);
}
	if (*color)
#undef OUT
}

	if (end - name == len) {
	int *is_tty_p = fd == 1 ? &color_stdout_is_tty : &color_stderr_is_tty;
	return 0;
	if (!git_config_bool(var, value))
	COLOR_FOREGROUND_BRIGHT_ANSI = 90,
}
		if (!color_empty(&bg)) {
			out->value = val - 8 + COLOR_FOREGROUND_BRIGHT_ANSI;
{
	for (i = 0; i < ARRAY_SIZE(color_names); i++) {
 */
	return 0;
		r += fprintf(fp, "%s", color);
		"black", "red", "green", "yellow",
				 c->value);
		ATTR("dim",       2, 22),
#include "cache.h"
	int offset = 0;
	r = color_vfprintf(fp, color, fmt, args, "\n");
{
		return -1;
	/* Then pick from our human-readable color names... */

	unsigned int attr = 0;
				 c->red, c->green, c->blue);
		}
	if (!var)

	case COLOR_256:

	enum {

	while (len > 0) {
}
/*
				bg = c;
	va_start(args, fmt);

		OUT('\033');
		if (!strcasecmp(value, "always"))
}
		out += xsnprintf(out, len, "%d", c->value + offset);
	COLOR_FOREGROUND_RGB = 38,
		else if (val < 0) {

	 * is listed in .tsan-suppressions for the time being.
	int r;
	while (len > 0 && isspace(*ptr)) {
void color_print_strbuf(FILE *fp, const char *color, const struct strbuf *sb)
		r += fprintf(fp, "%s", GIT_COLOR_RESET);
	static const struct {

	int r = 0;
			out->type = COLOR_256;
				continue;
	}
	if (dst == end) \
	r = color_vfprintf(fp, color, fmt, args, NULL);
		ATTR("italic",    3, 23),
	}

	if (!len) {
int git_config_colorbool(const char *var, const char *value)
	GIT_COLOR_BOLD_CYAN,
		len--;
	GIT_COLOR_BOLD_YELLOW,
static int check_auto_color(int fd)
	const char *ptr = value;
			return 0;
	} type;
}
		*is_tty_p = isatty(fd);
		int val, neg;
		struct color c = { COLOR_UNSPECIFIED };
	char *end;
