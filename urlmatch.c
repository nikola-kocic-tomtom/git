		return 0;
	slash_ptr = url + strcspn(url, "/?#");
		pat = pat_next;
static char *url_normalize_1(const char *url, struct url_info *out_info, char allow_globs)
			}
				strbuf_release(&norm);
	 * will be detected (including a missing host for non file: URLs).
	while (from_len) {
	while (url < colon_ptr) {
		strbuf_release(&norm);
	if (allow_globs)
		/* Otherwise, replace it with this one. */
	if (!match_host(url, url_prefix))
	if (at_ptr && at_ptr < slash_ptr) {
#define URL_DIGIT "0123456789"
	 *
		int was_esc = 0;

					out_info->url = NULL;
			}
			url--;
			if (colon_ptr) {
			}

			 */
				user_len = norm.len - (scheme_len + 3);
		strbuf_addch(&norm, tolower(*url++));
	 * Copy lowercased scheme and :// suffix, %-escapes are not allowed
	 * followed by 2 hexadecimal digits, the sequence is invalid and
	 * 5. Leading 0s are removed from port numbers
	 * be escaped.  If 'esc_ok' is not NULL, those characters will be left
			if (seg_start == path_start + 1) {

			strbuf_addch(&norm, '/');
			       const char *url_prefix,
	 *
		free(norm_url);
	const char *key, *dot;
	return next;
	    strncmp(url->url, url_prefix->url, url->scheme_len))
		url_prefix->url + url_prefix->path_off,
	 * is the same as the path portion of url or it is a prefix that
		free(config_url);
	const char *pat = pattern_info->url + pattern_info->host_off;
	 * escaped if found that way, but will not be unescaped otherwise (used
		out_info->url = result;
	strbuf_addch(&synthkey, '.');
	/*
			while (*--prev_slash != '/') {}
			if (out_info) {
	if (!url_len || strchr(":/?#", *url)) {

	if (a->pathmatch_len != b->pathmatch_len)
			strbuf_addch(&norm, ':');
{
	if (host_off)
		if (out_info) {
	const char *slash_ptr, *at_ptr, *colon_ptr, *path_start;
		}
int urlmatch_config_entry(const char *var, const char *value, void *cb)
	/*
	    strncmp(url->url + url->port_off,
	 */
		url_prefix->url_len - url_prefix->path_off);
			}
		}
	struct urlmatch_item matched = {0};
		out_info->port_len = port_len;
			if (pnum == 0 || pnum > 65535) {
		/* skip the ':' and leading 0s but not the last one if all 0s */
	 * 6. If the default port for the scheme is given it will be removed
	 * url must be NUL terminated.  url_prefix_len is the length of

static int match_host(const struct url_info *url_info,
			}
	if (match) {
			/* ignore a . segment; be careful not to remove initial '/' */

			/* wildcard matches anything */
	return result;
		return (!*url || *url == '/') ? 1 : 0;
			/* Skip ":" port with no number, it's same as default */
			  * we cannot use it.
		if (!strcmp(seg_start, ".")) {
			 * 0 is not allowed because that means "next available"
	/*
#include "cache.h"
	} else if (!host_off && colon_ptr < slash_ptr && colon_ptr + 1 != slash_ptr) {
}
char *url_normalize(const char *url, struct url_info *out_info)
	return 0;
			} else {
			if (!append_normalized_escapes(&norm, url, at_ptr - url,
		if (!skip_add_slash)
	size_t host_off=0, host_len=0, port_off=0, port_len=0, path_off, path_len, result_len;

	int pat_len = pattern_info->host_len;

		next = s + n;
	/* check the user name if url_prefix has one */
	dot = strrchr(key, '.');
		return NULL;
	item = string_list_insert(&collect->vars, key);
			/*
	 * Now copy the path resolving any . and .. segments being careful not

		url_len -= next_slash - url;
	 * to corrupt the URL by unescaping any delimiters, but do add an
	 * value is the length of the path match including any implicit
	}
			pat_next++;

	 */
	/*
					       URL_RESERVED)) {
}
			out_info->err = _("invalid URL scheme name or missing '://' suffix");
		}
		if (collect->cascade_fn)

			if (ch < 0)
					out_info->url = NULL;
	}
	return 1;
				out_info->err = _("missing host and scheme is not 'file:'");
			return 0;
	if (!url_prefix_len || (url_prefix_len == 1 && *url_prefix == '/'))
		usermatched = 1;
		url_prefix_len--;
		int ch = *from++;
				strbuf_release(&norm);
	/*
				strbuf_setlen(&norm, prev_slash - norm.buf);
				out_info->err = _("invalid %XX escape sequence");
			}
		}
			out_info->err = _("a 'file:' URL may not have a port number");
			port_off = norm.len;
			from_len -= 2;
				return NULL;
			break;
	 * user name.  If there is no match *exactusermatch is left untouched.
		const char *next_slash = url + strcspn(url, "/?#");
		url_len -= (++at_ptr - url);
	 * 1. Case-insensitive parts of url will be converted to lower case
	if (out_info) {
				/* port number not in range 1..65535 */
	struct url_info *url = &collect->url;
			return 0;
{

			if (spanned < slash_ptr - url) {
	 * 'esc_extra' is not NULL, those additional characters will also always
	 * and host part (except for file: URLs which may have an empty host).
{
	/*

		}
		return url_prefix_len + 1;
		if (out_info) {
	/*


			return NULL;
			   !strncmp(norm.buf, "https:", 6) &&
	 *
		url = at_ptr;
			 * ignore a .. segment and remove the previous segment;
		out_info->path_len = path_len;
		return 0;
	 * the final '/' even if it's implicit) or 0 for no match.
		return b->user_matched ? -1 : 1;
	char *result;
	path_len = norm.len - path_off;
			unsigned long pnum = 0;
		if (!append_normalized_escapes(&norm, url, next_slash - url, "",

	retval = collect->collect_fn(synthkey.buf, value, collect->cb);
	if (collect->key && strcmp(key, collect->key))
	return url_normalize_1(url, out_info, 0);
	return 0;
	struct urlmatch_config *collect = cb;
}
		url = next_slash;
	url_len -= spanned;
				}
	if (*url) {
		url_len--;
		 * RFC 3689 indicates that any . or .. segments should be
	}
	 *
			if (out_info) {
			strbuf_release(&norm);
		}
	colon_ptr = slash_ptr - 1;
	 * as indicated in RFC 3986.  Unless included in esc_extra or esc_ok
	 * undetected.  However, most all other problems that make a URL invalid
		    strchr(URL_UNSAFE_CHARS, ch) ||
		} else if (slash_ptr - url == 2 &&
				return 0;
				}

			port_len = slash_ptr - url;
	 * for delimiters).  If a %-escape sequence is encountered that is not
		url = slash_ptr;
		out_info->path_off = path_off;
		    strncmp(url->url + url->user_off,
	if (*url == '/') {
	size_t scheme_len, user_off=0, user_len=0, passwd_off=0, passwd_len=0;
		return a->pathmatch_len < b->pathmatch_len ? -1 : 1;
		    (was_esc && strchr(esc_ok, ch)))
	memcpy(item->util, &matched, sizeof(matched));
	 * 7. A path part (including empty) not starting with '/' has one added

		return 0; /* paths do not match */
		if (!norm_url)
}
	}
		if (!url->user_off || url->user_len != url_prefix->user_len ||
		url++;
}
		else
	result = strbuf_detach(&norm, &result_len);
	}
	size_t pathmatchlen;
		return 0; /* host names do not match */
				     const char *esc_ok)
		return 0; /* schemes do not match */
		key = dot + 1;
				skip_add_slash = 1;
	}
}
	 * The rules are based on information in RFC 3986.
	}
	}
	while (url_len && pat_len) {
					out_info->err = _("invalid '..' path segment");
	return 1;
	if (url_prefix->port_len != url->port_len ||
		return 0; /* not interested */
			 * be careful not to remove initial '/' from path

	 * 2. %-encoded characters that do not need to be will be unencoded
	 * Both url and url_prefix are considered to have an implicit '/' on the
	 *
	 * leading 0s); no %-escapes allowed

		       const struct urlmatch_item *b)
			   !strncmp(url, "80", 2)) {

				strbuf_release(&norm);
			if (prev_slash == path_start) {
	}
				strbuf_release(&norm);
			strbuf_release(&norm);
		return NULL;
	 * First character of scheme must be URL_ALPHA
#define URL_RESERVED URL_GEN_RESERVED URL_SUB_RESERVED /* only allowed delims */
	 * performed.  Some invalid host names are passed through this function
				strbuf_setlen(&norm, norm.len - 2);
			}
	 * will be set to a brief, translated, error message, but no other
	 * final '/'.  For example, "http://me@example.com/path" is matched by
		const char *url_next = end_of_token(url, '.', url_len);
		}
			 * and since all the protocols we deal with have a 16-bit
			url_next++;
{

		if (url_next < url + url_len)
		/* Host name has invalid characters */
			   !strncmp(norm.buf, "http:", 5) &&
	}
	path_off = norm.len;
		return a->hostmatch_len < b->hostmatch_len ? -1 : 1;
	int retval;
				return NULL;

	if (*colon_ptr != ':') {
			 * Port number must be all digits with leading 0s removed
	 * Append to strbuf 'buf' characters from string 'from' with length
			strbuf_add(&norm, url, slash_ptr - url);
		retval = match_urls(url, &norm_info, &matched);
#define URL_UNSAFE_CHARS " <>\"%{}|\\^`" /* plus 0x00-0x1F,0x7F-0xFF */
	if (a->user_matched != b->user_matched)
	 * is a prefix of url and the match ends on a path component boundary.
			  */
	}
	 * url_prefix matches url if the scheme, host and port of url_prefix
	struct string_list_item *item;

	 * The return value is the length of the match in characters (including
}
			}
	if (!item->util) {
		url++;

			const char *prev_slash = norm.buf + norm.len - 3;
					out_info->err = _("invalid port number");
	strbuf_addch(&norm, '/');
		if (pat_next == pat + 1 && pat[0] == '*')
}
		spanned = strspn(url, URL_HOST_CHARS "*");
			    url->user_len))
			if (prev_slash == path_start) {
			out_info->url = NULL;
	if (!skip_prefix(var, collect->section, &key) || *(key++) != '.') {
		out_info->port_off = port_off;
		out_info->passwd_off = passwd_off;
	const char *url = url_info->url + url_info->host_off;
	char usermatched = 0;
		host_off = norm.len;
			    url_prefix->url + url_prefix->user_off,
			   !strncmp(url, "443", 3)) {
	/*
	} else {
	return (!url_len && !pat_len);
	 * 'from_len' while unescaping characters that do not need to be escaped
	spanned += 3;
			} else {
			from += 2;
		collect->select_fn ? collect->select_fn : cmp_matches;
				out_info->url = NULL;
		url_len -= url_next - url;

		pat_len -= pat_next - pat;
		const char *pat_next = end_of_token(pat, '.', pat_len);
					out_info->err = _("invalid %XX escape sequence");

				     size_t from_len,
#define URL_HOST_CHARS URL_ALPHADIGIT ".-[:]" /* IPv6 literals need [:] */
	 * contained a user name or false if url_prefix did not have a
	/* check the scheme */
		return 0;
			ch = hex2chr(from);
#define URL_SUB_RESERVED "!$&'()*+,;="
	while (spanned--)
static size_t url_match_prefix(const char *url,
	 * Normalize NUL-terminated url using the following rules:
		if (select_fn(&matched, item->util) < 0)
	 *
			strbuf_addch(buf, ch);
	 * fields will be filled in.
		out_info->err = NULL;
				if (out_info) {
	 * Passing NULL as url and/or url_prefix will always cause 0 to be
				if (out_info) {
			return 0; /* url_prefix has a user but it's not a match */
			spanned = strspn(url, URL_DIGIT);
			}
				out_info->url = NULL;


	 */
	if (a->hostmatch_len != b->hostmatch_len)
	}
	 * "http://example.com" with a path length of 1.
			;
	 *
		out_info->passwd_len = passwd_len;
	/* check the path */
	const char *next = memchr(s, c, n);
		if (ch == '%') {
#define URL_GEN_RESERVED ":/?#[]@"
			  * Our match is worse than the old one,

			return 0; /* found an unmatch */

	/* check the host */
			return collect->cascade_fn(var, value, cb);
		user_off = norm.len;
	if (!spanned || !isalpha(url[0]) || spanned + 3 > url_len ||
		char *config_url, *norm_url;
	 * that must also exactly match the user name in url.
	 * The return value is a newly allocated string that must be freed
				return NULL;
	strbuf_release(&synthkey);
		colon_ptr--;
	 * initial '/' if it's missing and do normalize any %-escape sequences.
				passwd_off = (colon_ptr + 1) - norm.buf;

	 * alphanumerics and "-._~" will always be unescaped as per RFC 3986.
static int append_normalized_escapes(struct strbuf *buf,
	at_ptr = strchr(url, '@');
	 * If the user, host, port and path match in this fashion, the returned
				}

	 * is returned, NULL will be stored in out_info->url and out_info->err
	 * being careful not to corrupt the URL by unescaping any delimiters.
static int cmp_matches(const struct urlmatch_item *a,

		if (url == slash_ptr) {
		out_info->user_off = user_off;

	 * be set.  If a non-NULL value is returned, it will be stored in
	 * false (0) will be returned.  Otherwise true (1) will be returned for
		url = url_next;
{
		    (esc_extra && strchr(esc_extra, ch)) ||
		if (url == slash_ptr && url[-1] == '0')
	size_t spanned;
		struct url_info norm_info;

{
#define URL_SCHEME_CHARS URL_ALPHADIGIT "+.-"
		spanned = strspn(url, URL_HOST_CHARS);
		size_t seg_start_off = norm.len;
	}
		strbuf_addch(&norm, '@');
			out_info->url = NULL;
		return 0;
		out_info->url_len = result_len;
	strbuf_addstr(&synthkey, key);
	if ((strlen(url) == url_prefix_len) || (url[url_prefix_len] == '/'))
	 * *exactusermatch will be set to true if both url and url_prefix
	return retval;
	 * are the same as those of url and the path portion of url_prefix

				return 0;
	 * Check the port part and copy if not the default (after removing any
{
	 *
	 * and escaping characters that do.  The set of characters to escape
			was_esc = 1;
		strbuf_addch(&norm, tolower(*url++));
	 * 8. Any dot segments (. or ..) in the path are resolved and removed
			return NULL;
		item->util = xcalloc(1, sizeof(matched));
						       "", URL_RESERVED)) {

	if (spanned < colon_ptr - url) {
	 * unsafe characters (0x00-0x1F,0x7F-0xFF," <>\"#%{}|\\^`").  If
	if (url_prefix[url_prefix_len - 1] == '/')
	 * This is NOT a URL validation function.  Full URL validation is NOT
	if (strncmp(url, url_prefix, url_prefix_len))
#include "urlmatch.h"
		host_len = norm.len - host_off - (port_len ? port_len + 1 : 0);
	 * (the complement of which is unescaped) starts out as the RFC 3986
		seg_start = norm.buf + seg_start_off;
	 */
		return 0; /* ports do not match */
		      const struct url_info *pattern_info)
		url++;
		colon_ptr = slash_ptr;
	 * end for matching purposes if they do not already.
	for (;;) {
	 * Now simply copy the rest, if any, only normalizing %-escapes and
			 !memcmp(url, pat, url_next - url))
		if (!retval)
	/*
		url_len -= slash_ptr - colon_ptr;
				return NULL;
			return NULL;
		/*
		} else {
#define URL_ALPHA "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	} else {
			/* Skip https :443 as it's the default */

	struct strbuf norm;
		}

	    url[spanned] != ':' || url[spanned+1] != '/' || url[spanned+2] != '/') {
					out_info->url = NULL;
		if (*url != '/')
		/* Missing host invalid for all URL schemes except file */
			strbuf_addf(buf, "%%%02X", (unsigned char)ch);
		match->user_matched = usermatched;
		int skip_add_slash = 0;
		} else if (slash_ptr - url == 3 &&
			if (out_info) {
			;
#define URL_ALPHADIGIT URL_ALPHA URL_DIGIT
	 */
		if (at_ptr > url) {
				     const char *esc_extra,
	 * If there is a match and exactusermatch is not NULL, then
	 * If out_info is non-NULL, the url and err fields therein will always
		      const struct url_info *url_prefix,
	else
		url_len--;
			out_info->err = _("invalid characters in host name");
	/*
	 */
	 */
			 * port number it must also be in the range 1..65535
	 * Copy the host part excluding any port part, no %-escapes allowed
				pnum = strtoul(url, NULL, 10);
	 */
	 * success.
				passwd_len = norm.len - passwd_off;
	 * out_info->url as well, out_info->err will be set to NULL and the
				     const char *from,
	}
	strbuf_addstr(&synthkey, collect->section);

			/* Skip http :80 as it's the default */
		} else if (!strcmp(seg_start, "..")) {
	 * other fields of *out_info will also be filled in.  If a NULL value
	size_t url_len = strlen(url);

	 */
	spanned = strspn(url, URL_SCHEME_CHARS);
	if (url_prefix->user_off) {
		else if ((pat_next - pat) == (url_next - url) &&
				skip_add_slash = 1;
		const char *seg_start;
				out_info->url = NULL;
			 /*
	if (url_prefix->scheme_len != url->scheme_len ||
		match->hostmatch_len = url_prefix->host_len;
		}
}
		if (out_info) {
			return 0;
					out_info->err = _("invalid port number");
	int (*select_fn)(const struct urlmatch_item *a, const struct urlmatch_item *b) =
		}
	}
			       size_t url_prefix_len)

	/* check the port */
	struct strbuf synthkey = STRBUF_INIT;
		out_info->host_off = host_off;
	}

			}
	}
			if (from_len < 2)
		if (!append_normalized_escapes(&norm, url, url_len, "", URL_RESERVED)) {
			 */
				strbuf_setlen(&norm, norm.len - 1);
	 * 3. Characters that are not %-encoded and must be will be encoded
		    url_prefix->url + url_prefix->port_off, url->port_len))
	while (colon_ptr > url && *colon_ptr != ':' && *colon_ptr != ']')

		url_len--;
	if (!next)
	 * or NULL if the url is not valid.
		norm_url = url_normalize_1(config_url, &norm_info, 1);
		from_len--;
				if (out_info) {
	 *
		 * unescaped before being checked for.
				}
	 * Copy any username:password if present normalizing %-escapes
static const char *end_of_token(const char *s, int c, size_t n)
				out_info->err = _("invalid %XX escape sequence");
	 * url_prefix matches url if url_prefix is an exact match for url or it
		return NULL; /* Bad scheme and/or missing "://" part */
				if (out_info) {
	path_start = norm.buf + path_off;

	 * url_prefix which need not be NUL terminated.
		out_info->user_len = user_len;
	}
	if (!pathmatchlen)
	int url_len = url_info->host_len;
			if (slash_ptr - url <= 5)
	scheme_len = spanned;
		url += strspn(url, "0");
{
	 */
		      struct urlmatch_item *match)
			out_info->url = NULL;
	 * 4. All %-encodings will be converted to upper case hexadecimal
	 * 9. IPv6 host literals are allowed (but not normalized or validated)
	 *

					out_info->url = NULL;
	 * returned without causing any faults.
		out_info->scheme_len = scheme_len;
	 *
static int match_urls(const struct url_info *url,
	strbuf_init(&norm, url_len);
		if (strncmp(norm.buf, "file:", 5)) {
		/* file: URLs may not have a port number */
			colon_ptr = strchr(norm.buf + scheme_len + 3, ':');
	if (dot) {
		strbuf_release(&norm);
		config_url = xmemdupz(key, dot - key);
				strbuf_setlen(&norm, prev_slash - norm.buf + 1);
	 * Note that all %-escape sequences will be normalized to UPPERCASE
				/* invalid .. because no previous segment to remove */
		else
		/* if the next char is not '/' done with the path */
	if (!url || !url_prefix)
			} else {
{
	if (colon_ptr < slash_ptr) {
	if (!url || !url_prefix || !url->url || !url_prefix->url)
		if ((unsigned char)ch <= 0x1F || (unsigned char)ch >= 0x7F ||
	 * matches at a '/' boundary.  If url_prefix contains a user name,
			strbuf_release(&norm);

	pathmatchlen = url_match_prefix(
	 * Please note this function requires a full URL including a scheme
		 */
		url->url + url->path_off,
				user_len = (passwd_off - 1) - (scheme_len + 3);
	 *
				/* port number has invalid characters */
			 * on just about every system and therefore cannot be used
		out_info->host_len = host_len;

			/* the components are the same */
		if (pat_next < pat + pat_len)
		match->pathmatch_len = pathmatchlen;
			/*
