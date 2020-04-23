		sb->buf[sb->len] = '\0';
			return 1;
		ssize_t got = read_in_full(fd, sb->buf + sb->len, want);
	strbuf_setlen(sb, sb->len + dlen - len);

	return ret;
	    unsigned_add_overflows(sb->len, extra + 1))
		result[i] = toupper(string[i]);
	for_each_string_list_item(item, slist) {
}
		sb->len--;
{
	errno = 0;
		strbuf_release(sb);
	}
	}
{
	return result;

		strbuf_addch(&munged_fmt, ' ');
	for (i = j = 0; i < sb->len; i += len, j += newlen) {
}
{
}
		return cmp;
}
			sb->buf[newlen + j++] = '\n';
	ret = xstrvfmt(fmt, ap);
		return -1;
	if (len < 0) {
	}
			len = strftime(sb->buf + sb->len, sb->alloc - sb->len,
	size_t nr = 0, alloc = 0;
	save = sb->buf[pos + len];

{
		 * to the same restrictions as the fallback.
		if (*format == '%') {
	size_t len;
	va_copy(cp, ap);

		s += len;
			const char *end = memchr(str, terminator, slen);
		return 0;

	}
		else
			break;
	return strbuf_detach(&buf, NULL);

			if (end)
}
		sb->buf[sb->len++] = ch;
char strbuf_slopbuf[1];
	return 0;
	switch (placeholder[0]) {
{
}

{
		case '!': case '*': case '\'': case '(': case ')': case ';':
		if (getcwd(sb->buf, sb->alloc)) {

}
int strbuf_getwholeline_fd(struct strbuf *sb, int fd, int term)
			const char *prefix2,
	int r;
		if (newlen) {
}
		}
	const char *p;
		return;
			strbuf_setlen(sb, sb->len - 1);
		}
}
#else
size_t strbuf_expand_literal_cb(struct strbuf *sb,
 * If the input has only empty lines and spaces,
	}
void strbuf_add_commented_lines(struct strbuf *out, const char *buf, size_t size)
					/* TRANSLATORS: IEC 80000-13:2008 mebibyte/second */
{
			strbuf_grow(sb, hint);
void strbuf_add_percentencode(struct strbuf *dst, const char *src)
	size_t oldalloc = sb->alloc;
		const char *next = memchr(buf, '\n', size);

{
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);

{
	size_t res;
		return 1;
		BUG("your vsnprintf is broken (returned %d)", len);
		/* Not just an empty line? */
			if (e->value)
}
}

	size_t len;
		strbuf_addch(sb, ch);
	strbuf_grow(sb, hint ? hint : 8192);
{
int fprintf_ln(FILE *fp, const char *fmt, ...)
			break;

		xsnprintf(prefix2, sizeof(prefix2), "%c", comment_line_char);
			if (errno != ERANGE)
			const char *prefix1,

	size_t i, j, len, newlen;
		ch = hex2chr(placeholder + 1);
			fmt++;
{
	if (sb->len) {
	int ret;

		}
			strbuf_addch(dst, ch);
	strbuf_grow(sb, len);
			return 0;
		sb->buf = NULL;
		die("Out of memory, getdelim failed");

	}
		}
{
#endif
		len--; /* drop munged space */

		return 3;
	 * Normally we would have called xrealloc, which will try to free
			  ? prefix2 : prefix1);
{

 */

void strbuf_ltrim(struct strbuf *sb)
}
		if (sb->len && sb->buf[sb->len - 1] == '\r')
		strbuf_grow(sb, 64);
size_t strbuf_expand_dict_cb(struct strbuf *sb, const char *placeholder,

	va_end(ap);
}
			break;
				 const char **arg, const char *def)
	strbuf_release(sb);
void strbuf_add_separated_string_list(struct strbuf *str,
				strbuf_setlen(sb, oldlen);
ssize_t strbuf_read_once(struct strbuf *sb, int fd, size_t hint)
		BUG("your vsnprintf is broken (returns inconsistent lengths)");
		return 1;
		strbuf_release(sb);
}
	struct strbuf **ret = NULL;
	strbuf_humanise(buf, bytes, 1);
	ssize_t r;
		if (src->buf[i] == '%')
int is_rfc3986_reserved_or_unreserved(char ch)
			break;
		prefix = ((prefix2 && (buf[0] == '\n' || buf[0] == '\t'))
			return;
	struct strbuf buf = STRBUF_INIT;
	cnt = xread(fd, sb->buf + sb->len, sb->alloc - sb->len - 1);
	}
	strbuf_grow(sb, len);
			/* FALLTHROUGH */
			strbuf_setlen(sb, strlen(sb->buf));
	}
ssize_t strbuf_write(struct strbuf *sb, FILE *f)
	return 0;
	res = sb->buf;
	}

	if (new_buf)
}
		return 1;
			strbuf_addf(&munged_fmt, "%+05d", tz_offset);
			strbuf_grow(sb, 1);
#include "string-list.h"

}
	strbuf_complete_line(out);
void strbuf_addchars(struct strbuf *sb, int c, size_t n)
	strbuf_setlen(sb, sb->len + n);
	va_list ap;
			BUG("your vsnprintf is broken (insatiable)");
	static char prefix1[3];
	va_start(ap, fmt);
	/* We may have to add a newline. */
			break;


	strbuf_splice(sb, pos, 0, data, len);
	size_t len = a->len < b->len ? a->len: b->len;
		strbuf_reset(sb);
{
	struct strbuf buf = STRBUF_INIT;
 *
 * initialized strbuf.
		return; /* nothing to do */
		case 0:
	if (!argc)
		}


	va_list params;
	if (cnt > 0)
	else if (oldalloc == 0)
		}
	r = getdelim(&sb->buf, &sb->alloc, term, fp);

		strbuf_addf(buf,
		ALLOC_GROW(ret, nr + 2, alloc);
 * character.
	while (--argc) {
	if (errno == ENOMEM)

	va_list ap;
	return strbuf_getdelim(sb, fp, '\n');
int strbuf_getwholeline(struct strbuf *sb, FILE *fp, int term)
		 */
	 * catastrophic memory failure. We skip the opportunity to free pack
			sb->buf + pos + len,
		strbuf_addbuf(sb, &resolved);
{
			break;
	while (1) {
			    (unsigned)(bytes >> 30),
{
		return EOF;
{
		if (ch == term)

	char save;
		 * we may be able to avoid EACCES by providing enough
		die("you want to use way too much memory");

			     int argc, const char **argv, char delim)
{
			continue;

	return 0;
	if (ret < 0 || putc('\n', fp) == EOF)
}

void strbuf_addstr_urlencode(struct strbuf *sb, const char *s,
			return 0;
		fmt = percent + 1;
	strbuf_grow(sb, sb2->len);
	if (feof(fp))
		die("you want to use way too much memory");
{
		die("`pos + len' is too far after the end of the buffer");
				len = end - str + 1;
			fmt++;
	/*
			    x >> 20, ((x & ((1 << 20) - 1)) * 100) >> 20);

int istarts_with(const char *str, const char *prefix)
	result = xmallocz(len);
static void add_lines(struct strbuf *out,
		strbuf_release(sb);
static void strbuf_humanise(struct strbuf *buf, off_t bytes,
			strbuf_addstr(str, sep);
	 * enough to hold a single line of input, anyway.
	 * normalize_path does not tell us the new length, so we have to
	int ch;
	if (sz)
			strbuf_addstr(buf, "&amp;");
{
		*p = tolower(*p);
}
{
	struct strbuf *t;
	return sb->len - oldlen;
}
				strbuf_release(sb);
		if (max <= 0 || nr + 1 < max) {
 * Turn multiple consecutive empty lines between paragraphs
					/* TRANSLATORS: IEC 80000-13:2008 gibibyte/second */
	else if (oldalloc == 0)
	if (dlen >= len)
		die("`pos' is too far after the end of the buffer");
	while (slen) {
	for (; ; str++, prefix++)
{
	va_start(ap, fmt);
	return 0;
	while (sb->len > 0 && isspace((unsigned char)sb->buf[sb->len - 1]))

	}
{
				break;
		if (got < want)
}
			strbuf_addch(sb, ch);
			    x >> 10, ((x & ((1 << 10) - 1)) * 100) >> 10);
}
		strbuf_init(sb, 0);
int strbuf_getline_lf(struct strbuf *sb, FILE *fp)
	sb->buf[sb->len] = '\0';
	 * Restore strbuf invariants; if getdelim left us with a NULL pointer,
 * buf is non NULL and ->buf is NUL terminated even for a freshly
		if (got < 0) {

	va_end(cp);
{
}
					_("%u.%2.2u KiB") :

	va_list ap;

		len = vsnprintf(sb->buf + sb->len, sb->alloc - sb->len, fmt, ap);
		len = eol ? eol - (sb->buf + i) + 1 : sb->len - i;
{
}
		case ',': case '/': case '?': case '#': case '[': case ']':
		strbuf_addstr(out, prefix);
	add_lines(out, prefix1, prefix2, buf, size);
void strbuf_init(struct strbuf *sb, size_t hint)
	}


int strbuf_normalize_path(struct strbuf *src)
int starts_with(const char *str, const char *prefix)

	int incomplete_line = sb->len && sb->buf[sb->len - 1] != '\n';
	va_end(params);
		slen -= len;
	if (hint < 32)
	close(fd);

	sb->len   = len;

		case '&':
	if (!is_absolute_path(path)) {
		 * strftime reports "0" if it could not fit the result in the buffer.
		strbuf_addf(buf,
		strbuf_add(t, str, len);
	strbuf_vaddf(&buf, fmt, params);
	strbuf_add_commented_lines(sb, buf.buf, buf.len);
	int len, len2;
	return isalnum(ch) ||
	r = find_unique_abbrev_r(sb->buf + sb->len, oid, abbrev_len);
		case 'z':
	int len;
	char *res;
	int fd;
	if (!skip_prefix(str, prefix, &p))
			      int abbrev_len)
}
	 */
	return ret + 1;
		/* .. the buffer was too small - try again */
	else {
static void strbuf_add_urlencode(struct strbuf *sb, const char *s, size_t len,
	return EOF;
	while (*s) {

	size_t i, len = strlen(src);
		const char *percent;
	char *path2 = NULL;
	for (;;) {
		}
			      const char *const *env)
	 */
		struct strbuf resolved = STRBUF_INIT;
{
	while ((ch = getc_unlocked(fp)) != EOF) {
		unlink(path);

					/* TRANSLATORS: IEC 80000-13:2008 kibibyte/second */
 *
	static char prefix2[2];
		 * Unfortunately, it also reports "0" if the requested time string
		unsigned x = bytes + 5;  /* for rounding */
					Q_("%u byte", "%u bytes", (unsigned)bytes) :
					/* TRANSLATORS: IEC 80000-13:2008 gibibyte */

}
		} else if (len < hint) {
	int ret;
{
	if (feof(fp))
		if (errno != ERANGE)

}
	char *p = sb->buf, *end = sb->buf + sb->len;
	for (i = 0; i < len; i++) {
	if (cmp)
		 */
	 */
	for (; ; str++, prefix++)
	memmove(sb->buf + pos + len, sb->buf + pos, sb->len - pos);
		if (ch <= 0x1F || ch >= 0x7F || strchr(URL_UNSAFE_CHARS, ch))
	if (fd < 0)
		    pwd_stat.st_ino == cwd_stat.st_ino)
{
		sb->buf = NULL;
		strbuf_add(out, buf, next - buf);
 *
		BUG("your vsnprintf is broken (returned %d)", len);
}
{
	int new_buf = !sb->alloc;
	size_t len, i;
	}
			     char_predicate allow_unencoded_fn)
void strbuf_trim(struct strbuf *sb)
		     int tz_offset, int suppress_tz_name)
{
	strbuf_setlen(sb, sb->len + len);

		strbuf_setlen(sb, sb->len - 1);

	if (len > strbuf_avail(sb)) {
 * Remove empty lines from the beginning and end
void strbuf_remove(struct strbuf *sb, size_t pos, size_t len)
			break;
	ALLOC_GROW(sb->buf, sb->len + extra + 1, sb->alloc);

	for (; p < end; p++)
	if (!*p) {
	else
				humanise_rate == 0 ?
		sb->buf[0] = '\0';
	}
		return -1;
	}
void strbuf_trim_trailing_dir_sep(struct strbuf *sb)

					_("%u.%2.2u MiB/s"),
int strbuf_reencode(struct strbuf *sb, const char *from, const char *to)

	va_end(ap);
	ssize_t len;
		/* %x00 == NUL, %x0a == LF, etc. */
}
	 * Dying here is reasonable. It mirrors what xrealloc would do on
	while (len--) {
		ch == '-' || ch == '_' || ch == '.' || ch == '~';
	strbuf_grow(sb, hint ? hint : 8192);


		if (len <= 0)
		}
{
		unsigned char c = line[len - 1];
void strbuf_splice(struct strbuf *sb, size_t pos, size_t len,
	len = strlen(string);
	return len;
	return a->len < b->len ? -1: a->len != b->len;



	if (res > 0)

	if (!out)
		return -1;
	char *ret;
}
					/* TRANSLATORS: IEC 80000-13:2008 byte/second */
		char ch;
		return EOF;
		next = next ? (next + 1) : (buf + size);
	va_start(ap, fmt);
	if (!*path)
		if (ch == term)
	size_t hint = 128;
		default:
{
}
	}
			break;
		case 'Z':
}
	if (ret < 0 || putchar('\n') == EOF)
void strbuf_addbuf(struct strbuf *sb, const struct strbuf *sb2)
		ssize_t len = xread(fd, &ch, 1);

		return 0;
		percent = strchrnul(format, '%');

			if (oldalloc == 0)
		if (skip_comments && len && sb->buf[i] == comment_line_char) {
	strbuf_vinsertf(sb, pos, fmt, ap);
	}
	}
		void *context)

	}
	size_t empties = 0;
				strbuf_addstr(sb, e->value);
{
{
		die("you want to use way too much memory");
				   const void *data, size_t dlen)
			}
void strbuf_add_unique_abbrev(struct strbuf *sb, const struct object_id *oid,
	va_end(ap);
			strbuf_addch(sb, '%');
	strbuf_setlen(sb, sb->len + len);
	len = strbuf_read(sb, fd, hint);
			strbuf_addstr(buf, "&lt;");
		b++;
	while (hint < STRBUF_MAXLINK) {
		return -1;
	if (strbuf_getwholeline(sb, fp, term))
		strbuf_release(sb);
}
		const char *prefix;
	}
			break;
	va_list cp;
		size_t orig_len = sb->len;

static int strbuf_getdelim(struct strbuf *sb, FILE *fp, int term)
	} else if (close(fd) < 0)
	strbuf_init(sb, 0);
				break;
	struct strbuf dst = STRBUF_INIT;
}
}
					_("%u.%2.2u GiB") :
	return 0;
#include "cache.h"
		    (cwd_stat.st_dev || cwd_stat.st_ino) &&
 * and also trailing spaces from every line.
					/* TRANSLATORS: IEC 80000-13:2008 byte */
void strbuf_vaddf(struct strbuf *sb, const char *fmt, va_list ap)
}
void strbuf_addbuf_percentquote(struct strbuf *dst, const struct strbuf *src)
		free(*s++);
	memcpy(sb->buf + sb->len, sb2->buf, sb2->len);

	if (len2 != len)
		return buf->buf;
 *

	while (sb->len > 0 && isspace(*b)) {

	fd = open(path, O_RDONLY);
}
		size -= next - buf;

	assert(r == -1);
			sb->len - pos - len);
static size_t cleanup(char *line, size_t len)
void strbuf_expand(struct strbuf *sb, const char *format, expand_fn_t fn,
			strbuf_addstr(buf, "&quot;");
	/* Translate slopbuf to NULL, as we cannot call realloc on it */
}
		sb->buf[--sb->len] = '\0';
	return ret;
{
{
{
			strbuf_addch(&munged_fmt, '%');
		strbuf_add(buf, s, len);
	memmove(sb->buf + pos + dlen,
	struct strbuf_expand_dict_entry *e = context;
}
	if (r > 0) {
	strbuf_attach(sb, out, len, len);
 * Used as the default ->buf value, so that people can always assume
	size_t oldalloc = sb->alloc;
		else
	strbuf_grow(sb, n);
	char *eol;
		    pwd_stat.st_dev == cwd_stat.st_dev &&
/*
	if (bytes > 1 << 30) {
		ssize_t want = sb->alloc - sb->len - 1;
		if (!strbuf_avail(sb))
}
	strbuf_ltrim(sb);
	return 1;
				humanise_rate == 0 ?
	strbuf_grow(sb, GIT_MAX_HEXSZ + 1);
	sb->buf[pos + len] = save;
char *xstrfmt(const char *fmt, ...)
		strbuf_add(&munged_fmt, fmt, percent - fmt);
}
		else
			continue;
}
		res = error_errno(_("could not write to '%s'"), path);

			    (unsigned)(bytes & ((1 << 30) - 1)) / 10737419);
	int cmp = memcmp(a->buf, b->buf, len);
{
	sb->buf[sb->len] = '\0';
	va_start(ap, fmt);
			hint *= 2;

	 */

		if (--sb->len > 0 && sb->buf[sb->len - 1] == '\r')
int strbuf_getwholeline(struct strbuf *sb, FILE *fp, int term)
	if (is_rfc3986_unreserved(ch))
			empties++;
	result = xmallocz(len);
	while (size) {

	/*
		strbuf_grow(sb, hint);
			else
}
#include "refs.h"
	ret = vfprintf(fp, fmt, ap);
			break;
			strbuf_addch(sb, '/');
	va_end(ap);
void strbuf_addstr_xml_quoted(struct strbuf *buf, const char *s)

	/*
		sb->len--;
	return -1;
	if (!strbuf_avail(sb))
			format += consumed;
		return -1;
void strbuf_commented_addf(struct strbuf *sb, const char *fmt, ...)
	sb->buf[sb->len] = '\0';

void strbuf_addftime(struct strbuf *sb, const char *fmt, const struct tm *tm,
		strbuf_reset(sb);
	strbuf_setlen(sb, sb->len + len);
	va_list cp;
		xsnprintf(prefix1, sizeof(prefix1), "%c ", comment_line_char);

struct strbuf **strbuf_split_buf(const char *str, size_t slen,
		len = readlink(path, sb->buf, hint);
		strbuf_grow(sb, len);
}
	strbuf_setlen(&dst, strlen(dst.buf));
		strbuf_realpath(sb, path, 1);
					_("%u.%2.2u KiB/s"),
	len2 = vsnprintf(sb->buf + pos, len + 1, fmt, ap);
		}
		else

	strbuf_reset(sb);
	if (pos > sb->len)
}
}
{
char *strbuf_detach(struct strbuf *sb, size_t *sz)
	if (sb->alloc) {
	len = strftime(sb->buf + sb->len, sb->alloc - sb->len, fmt, tm);
		return EOF;
	strbuf_grow(sb, 0);
		sb->len = r;
			res = error_errno(_("could not edit '%s'"), path);
	memcpy(sb->buf + sb->len, data, len);

		consumed = fn(sb, format, context);
	return 0;
{
}
		if (sb->len > orig_len && !is_dir_sep(sb->buf[sb->len - 1]))
}
		if (!isspace(c))

	} else {
		struct stat cwd_stat, pwd_stat;
	while (len) {
	memcpy(sb->buf + pos, data, dlen);
	}

	va_start(ap, fmt);
 * into just one empty line.
		s++;
	return 0;
		close(fd);



}
		if (sep_needed)
{
		strbuf_addf(buf,
	else
		die("The empty string is not a valid path");
	}

		strbuf_reset(buffer);


 * If the line ends with newline, it will be removed too.
		strbuf_setlen(sb, sb->len + res);
		die("`pos' is too far after the end of the buffer");
	for (i = 0; i < len; i++)
			return 0;
	case 'x':
	va_end(cp);
ssize_t strbuf_read_file(struct strbuf *sb, const char *path, size_t hint)
}
			const char *buf, size_t size)
	}
		len--;
}
	strbuf_release(&buf);
}
	if (sb->buf[sb->len - 1] == '\n') {
		strbuf_add(sb, format, percent - format);


	for (;; guessed_len *= 2) {
	out = reencode_string_len(sb->buf, sb->len, to, from, &len);
 * If last line does not have a newline at the end, one is added.
	 *
	struct string_list_item *item;
	strbuf_release(&dst);
 */
{
	va_end(ap);
			*arg = def;
	while (sb->len > 0 && is_dir_sep((unsigned char)sb->buf[sb->len - 1]))
	strbuf_add_urlencode(sb, s, strlen(s), allow_unencoded_fn);

int is_rfc3986_unreserved(char ch)
}
			strbuf_addch(dst, '%');
		const char *percent = strchrnul(fmt, '%');
		else if (*str != *prefix)
	struct strbuf munged_fmt = STRBUF_INIT;
		while (!len) {
int strbuf_getcwd(struct strbuf *sb)
		newlen = cleanup(sb->buf + i, len);
					_("%u.%2.2u GiB/s"),
	char *result;
	if (incomplete_line)
{
char *xstrdup_toupper(const char *string)
		if (ch < 0)
		if (allow_unencoded_fn(ch))

	strbuf_vaddf(sb, fmt, ap);
		*arg = p + 1;
	strbuf_grow(sb, 0);
 */
{
			newlen = 0;

	return 0;
		}
}

{
	ret[nr] = NULL;
	res = fread(sb->buf + sb->len, 1, size, f);
	sb->alloc = alloc;
		int len = slen;

{
	size_t oldalloc = sb->alloc;

	if (fd < 0)
void strbuf_vinsertf(struct strbuf *sb, size_t pos, const char *fmt, va_list ap)
		strbuf_init(sb, 0);
void strbuf_insertf(struct strbuf *sb, size_t pos, const char *fmt, ...)
		if (!*percent)


	if (normalize_path_copy(dst.buf, src->buf) < 0) {
	fmt = munged_fmt.buf;
	else if (write_in_full(fd, buffer->buf, buffer->len) < 0) {
		strbuf_grow(sb, guessed_len);
	} else
	if (!sb->buf)
		errno = saved_errno;
}
			--sb->len;
					/* TRANSLATORS: IEC 80000-13:2008 mebibyte */
	 * compute it by looking for the new NUL it placed
	sb->buf[sb->len] = '\0';
{
			strbuf_addstr(&munged_fmt, "%%");

	if (len < 0)
			format++;
	}
	strbuf_grow(sb, hint);
	}
{
		strbuf_addch(buf, delim);

}
{
	/*
		t = xmalloc(sizeof(struct strbuf));
void strbuf_add_absolute_path(struct strbuf *sb, const char *path)
		if (launch_editor(path, buffer, env) < 0)
	for (; e->placeholder && (len = strlen(e->placeholder)); e++) {

		strbuf_setlen(sb, sb->len + cnt);
	strbuf_splice(sb, pos, len, "", 0);
			return EOF;
			if (empties > 0 && j > 0)

{
					_("%u.%2.2u MiB") :
void strbuf_add_lines(struct strbuf *out, const char *prefix,
}
}
			break;
	int sep_needed = 0;
{
int strbuf_readlink(struct strbuf *sb, const char *path, size_t hint)
void strbuf_add_real_path(struct strbuf *sb, const char *path)
{
		 * space to the syscall as it's not necessarily bound
	if (prefix1[0] != comment_line_char) {
}
		unsigned char ch = src[i];


		sb->len--;
		case ':': case '@': case '&': case '=': case '+': case '$':

	 * strftime, so we handle %z and %Z here.
	 * There is no portable way to pass timezone information to
		if (!*percent)
	strbuf_reset(sb);

	return sb->len ? fwrite(sb->buf, 1, sb->len, f) : 0;
	return res;
		path = path2 = xstrdup(git_path("%s", path));
		else if (tolower(*str) != tolower(*prefix))
		strbuf_realpath(&resolved, path, 1);
	strbuf_grow(sb, size);
		    !stat(pwd, &pwd_stat) &&
	for (i = 0; i < len; i++)
		char *pwd = getenv("PWD");
	}
	 * memory and retry, but that's unlikely to help for a malloc small
	if (strbuf_getwholeline(sb, fp, '\n'))
		strbuf_setlen(sb, sb->len - 1);
	size_t oldalloc = sb->alloc;
		if (len > strbuf_avail(sb))
		strbuf_addch(sb, ch);
		strbuf_grow(sb, dlen - len);
{
void strbuf_tolower(struct strbuf *sb)
	}
#include "utf8.h"
		str += len;
	strbuf_setlen(sb, sb->len + r);
void strbuf_humanise_bytes(struct strbuf *buf, off_t bytes)
 *
		 * character before returning.

		char *cwd = xgetcwd();
	va_list ap;
#define STRBUF_MAXLINK (2*PATH_MAX)
	len = strlen(string);
	return res;
		strbuf_addch(sb, '\n');
{
	strbuf_grow(&dst, src->len);
}

		if (pwd && strcmp(pwd, cwd) &&

int skip_to_optional_arg_default(const char *str, const char *prefix,
	 * memory and recover. But we have no way to tell getdelim() to do so.
			strbuf_addf(sb, "%%%02x", (unsigned char)ch);
				      struct string_list *slist)
	if (sb->buf[sb->len - 1] == term)
void strbuf_stripspace(struct strbuf *sb, int skip_comments)
		case '>':
	size_t len, i;
	struct strbuf **s = sbs;
	funlockfile(fp);
		size_t consumed;
{
	return ret + 1;
	if (unsigned_add_overflows(extra, 1) ||
	if (hint)

{

	memmove(sb->buf, b, sb->len);
	 * we can just re-init, but otherwise we should make sure that our
	strbuf_reset(sb);
			strbuf_addstr(sb, pwd);
			break;
void strbuf_rtrim(struct strbuf *sb)
		if (len < 0) {
		return EOF;
		hint = 32;
void strbuf_humanise_rate(struct strbuf *buf, off_t bytes)
	strbuf_vaddf(&buf, fmt, ap);
#ifdef HAVE_GETDELIM
	char *b = sb->buf;
	/* vsnprintf() will append a NUL, overwriting one of our characters */
	 * Worse, we cannot try to recover ENOMEM ourselves, because we have

	strbuf_swap(src, &dst);


		    !stat(cwd, &cwd_stat) &&


		if (errno == EACCES && guessed_len < PATH_MAX)
 * Returns the length of a line, without trailing spaces.
		format = percent + 1;
	size_t guessed_len = 128;
char *xstrvfmt(const char *fmt, va_list ap)
		result[i] = tolower(string[i]);
	if (*p != '=')
		strbuf_release(&dst);
	case 'n':		/* newline */
	} else if (bytes > 1 << 20) {
		strbuf_grow(sb, hint);
		strbuf_addf(buf,
		return -1;
		switch (*fmt) {
		switch (*s) {
	return len;
		if (!*prefix)
	if (pos + len > sb->len)
	sb->buf[sb->len] = '\0';
	strbuf_grow(sb, 1);
{
}
	}
		      const char *buf, size_t size)
			return len;


{

				humanise_rate == 0 ?
}
void strbuf_attach(struct strbuf *sb, void *buf, size_t len, size_t alloc)
	return buf->buf;
		free(sb->buf);
int printf_ln(const char *fmt, ...)
int strbuf_edit_interactively(struct strbuf *buffer, const char *path,
{
		case '<':
	for (i = 0; i < len; i++) {
		hint *= 2;
}
	int ch;
		eol = memchr(sb->buf + i, '\n', sb->len - i);
}
/*
	while (*s) {
	strbuf_addstr(buf, *argv);
	if (arg)
	return result;
				       munged_fmt.buf, tm);
		return EOF;
	}
			empties = 0;
	strbuf_release(&munged_fmt);
	if (!sb->alloc)
void strbuf_release(struct strbuf *sb)
	if (oldalloc == 0)
			return -1;
	if (ch == EOF && sb->len == 0)
		if (!strncmp(placeholder, e->placeholder, len)) {
			if (suppress_tz_name) {
	sb->buf   = buf;

	ALLOC_GROW(ret, nr + 1, alloc); /* In case string was empty */
	}
		sep_needed = 1;
{
				 int terminator, int max)
	sb->alloc = sb->len = 0;

}
	 * length is empty, and that the result is NUL-terminated.
	switch (ch) {

			strbuf_addstr(sb, cwd);
int strbuf_cmp(const struct strbuf *a, const struct strbuf *b)

{

				sb->buf[j++] = '\n';
	return 0;
	}
int strbuf_getline(struct strbuf *sb, FILE *fp)
 * Enable skip_comments to skip every line starting with comment
				humanise_rate == 0 ?


		strbuf_addstr(buf, *(++argv));
void strbuf_grow(struct strbuf *sb, size_t extra)
void strbuf_addf(struct strbuf *sb, const char *fmt, ...)

		return 0;
			strbuf_addch(sb, '%');
				 int humanise_rate)
		/*
#define URL_UNSAFE_CHARS " <>\"%{}|\\^`:/?#[]@!$&'()*+,;="
	if (sb->len > 0 && sb->buf[sb->len - 1] == '\n') {
	 * no idea how many bytes were read by getdelim.
			continue;
	}
char *xstrdup_tolower(const char *string)
}
void strbuf_add(struct strbuf *sb, const void *data, size_t len)
		buf = next;
	if (!len)

	strbuf_addstr(sb, path);
		   void *context)
		char ch = *s++;
	size_t oldlen = sb->len;
		*sz = sb->len;
}

		size_t len = strcspn(s, "\"<>&");
{
		 * If getcwd(3) is implemented as a syscall that falls
	int saved_errno;


const char *strbuf_join_argv(struct strbuf *buf,
	strbuf_rtrim(sb);
	size_t i, len = src->len;
	free(sbs);
}
	strbuf_setlen(sb, j);
	size_t oldalloc = sb->alloc;
ssize_t strbuf_read(struct strbuf *sb, int fd, size_t hint)
	for (;;) {
	}
	saved_errno = errno;
{

			return 0;
	flockfile(fp);
int strbuf_getline_nul(struct strbuf *sb, FILE *fp)

	return strbuf_getdelim(sb, fp, '\0');
 * no output will be produced.
				(unsigned)bytes);
	if (!is_absolute_path(path))
				const char *placeholder,
				      const char *sep,
{
{
		res = error_errno(_("could not close '%s'"), path);
		if (consumed)
		strbuf_addstr(str, item->string);
}
		sb->len += got;
			return 0;
			return 1;
{
	len = vsnprintf(sb->buf + sb->len, sb->alloc - sb->len, fmt, cp);
		return 0;

	}

	if (!len) {
	if (pos > sb->len)


		if (arg)
	strbuf_setlen(sb, sb->len + len);
{
	size_t len;

	int fd, res = 0;
	for (;;) {
{
					/* TRANSLATORS: IEC 80000-13:2008 kibibyte */
	add_lines(out, prefix, NULL, buf, size);
		 * takes 0 bytes. So our strategy is to munge the format so that the
			strbuf_addf(dst, "%%%02X", (unsigned char)ch);


				fmt++;
	sb->buf[sb->len] = '\0';
void strbuf_insert(struct strbuf *sb, size_t pos, const void *data, size_t len)
/*
	ssize_t cnt;
		case '%':
}
{
		 * output contains at least one character, and then drop the extra
		unsigned x = bytes + 5243;  /* for rounding */
	if (oldalloc == 0)
{
	return -1;
	va_list ap;
	strbuf_grow(sb, len);

size_t strbuf_fread(struct strbuf *sb, size_t size, FILE *f)
		strbuf_init(t, len);
		 * back to a regular lookup using readdir(3) etc. then
		ret[nr++] = t;
		if (!*prefix)
}
	}

{
			strbuf_addstr(buf, "&gt;");
	char *result;
			memmove(sb->buf + j, sb->buf + i, newlen);
}
	free(path2);
}
			break;
{
void strbuf_list_free(struct strbuf **sbs)
		} else {

				 char_predicate allow_unencoded_fn)
{
	} else if (bytes > 1 << 10) {
	char *out;
{
	if (same_encoding(from, to))

		}
	if (!*fmt)

	strbuf_setlen(sb, sb->len + sb2->len);
{
	len = vsnprintf(sb->buf + sb->len, 0, fmt, cp);
		res = error_errno(_("could not open '%s' for writing"), path);
		strbuf_release(*s);
}
		case '"':
		free(cwd);

			return 1;
	ret = vprintf(fmt, ap);
	memset(sb->buf + sb->len, c, n);
	if (unsigned_add_overflows(pos, len))
	va_start(params, fmt);
		strbuf_grow(sb, 8192);





		strbuf_addch(dst, src->buf[i]);
	}
	va_copy(cp, ap);
					Q_("%u byte/s", "%u bytes/s", (unsigned)bytes),

				void *context)
		strbuf_release(&resolved);
		ssize_t len;
	if (unsigned_add_overflows(sb->len, len))

}
			strbuf_setlen(sb, len);
	if (new_buf)
	if (len < 0)
		/*
	strbuf_humanise(buf, bytes, 0);
	return res;
	return cnt;
}
void strbuf_trim_trailing_newline(struct strbuf *sb)

	sb->buf = strbuf_slopbuf;

