	return url_decode_internal(&url, len, NULL, &out, 0);
	*dest = strbuf_detach(&buf, NULL);
{
	const char *colon = memchr(url, ':', len);
		else
	struct strbuf out = STRBUF_INIT;
	if (!url || !is_urlschemechar(1, *url++))
}
	return url_decode_internal(query, -1, "&", &out, 1);
{
}

			}
	return alphanumeric || (!first_flag && special);
		}
	/*
int is_url(const char *url)

int is_urlschemechar(int first_flag, int ch)
			strbuf_addch(out, c);
{
	return (url[0] == ':' && url[1] == '/' && url[2] == '/');
	 * helpers.
	 * of '[A-Za-z0-9][A-Za-z0-9+.-]*' because earlier version
{
void str_end_url_with_slash(const char *url, char **dest)
	}

	while (*url && *url != ':') {
		len--;
	struct strbuf out = STRBUF_INIT;
				continue;
				q += 3;
{

}
	alphanumeric = ch > 0 && isalnum(ch);
{
		}
char *url_decode_parameter_value(const char **query)
	special = ch == '+' || ch == '-' || ch == '.';
#include "url.h"
void end_url_with_slash(struct strbuf *buf, const char *url)
		if (!c)
	return strbuf_detach(out, NULL);
			break;
{
char *url_percent_decode(const char *encoded)
char *url_decode(const char *url)
			return 0;
	end_url_with_slash(&buf, url);

	return url_decode_mem(url, strlen(url));
			break;


	struct strbuf out = STRBUF_INIT;
	return url_decode_internal(&encoded, strlen(encoded), NULL, &out, 0);
			len--;
	}
		len -= colon - url;
	 * of check used '[A-Za-z0-9]+' so not to break any remote
			q++;
}
	return url_decode_internal(query, -1, "&=", &out, 1);
			if (0 < val) {
		unsigned char c = *q;
		if (c == '%' && (len < 0 || len >= 3)) {
	struct strbuf buf = STRBUF_INIT;
			int val = hex2chr(q + 1);
	int alphanumeric, special;
}
		strbuf_add(&out, url, colon - url);
	free(*dest);
}
	/* We've seen "scheme"; we want colon-slash-slash */
	strbuf_complete(buf, '/');
	if (colon && url < colon) {
	}


	 * The set of valid URL schemes, as per STD66 (RFC3986) is
{
}

	/* Is "scheme" part reasonable? */
		return 0;
				 const char *stop_at, struct strbuf *out,
	/* Skip protocol part if present */
	while (len) {
static char *url_decode_internal(const char **query, int len,
#include "cache.h"

	struct strbuf out = STRBUF_INIT;
	*query = q;
				strbuf_addch(out, val);
}
				len -= 3;
	strbuf_addstr(buf, url);
char *url_decode_parameter_name(const char **query)
{

}

	 * '[A-Za-z][A-Za-z0-9+.-]*'. But use slightly looser check
		q++;
		url = colon;

{
		if (!is_urlschemechar(0, *url++))
	 */
	const char *q = *query;
		if (decode_plus && c == '+')
}
				 int decode_plus)
char *url_decode_mem(const char *url, int len)

		if (stop_at && strchr(stop_at, c)) {
			strbuf_addch(out, ' ');
