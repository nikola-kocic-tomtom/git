	 */
			credential_reject(&proxy_auth);
	if (http_ssl_backend) {
	release_http_object_request(freq);
}
{

			process_curl_messages();
	loose_object_path(the_repository, &filename, oid);
	if (prev_read == -1) {
	string_list_clear(&extra_http_headers, 0);
	strbuf_addf(&buf, "objects/pack/pack-%s.pack",
	struct fill_chain **linkp = &fill_cfg;

		slot->callback_func(slot->callback_data);
		}
#if LIBCURL_VERSION_NUM >= 0x072c00
}
};
	}
	{ "digest", CURLAUTH_DIGEST },
	return size / eltsize;
		else
static struct string_list extra_http_headers = STRING_LIST_INIT_DUP;
	if (!strcmp("http.sslversion", var))
		break;
	curl_easy_setopt(slot->curl, CURLOPT_FAILONERROR, 0);
	ip.git_cmd = 1;
		curl_easy_setopt(result, CURLOPT_PROXY, proxy_auth.host);
			|| ((ch >= 'a') && (ch <= 'z'))


			if (!strcmp(curl_deleg, curl_deleg_levels[i].name)) {
	if (ssl_cert != NULL)
		slot = newslot;

	}
			 * to read.  See commit message for more details.

#if LIBCURL_VERSION_NUM >= 0x070908
 *

			} else {
	 * here, too
{
	 * language_tags array.
		fprintf(stderr, "Getting index for pack %s\n", hash_to_hex(hash));
 *
	if (ssl_cert == NULL || ssl_cert_password_required != 1)
{
/*

	{ "basic", CURLAUTH_BASIC },
	if (!preq->packfile) {
abort:
	}
#ifdef USE_CURL_MULTI
}
		ssl_cipherlist = getenv("GIT_SSL_CIPHER_LIST");
	long curl_deleg_param;
	}
		FREE_AND_NULL(cert_auth.password);
		else if (starts_with(curl_http_proxy, "https")) {

		return git_config_string(&curl_deleg, var, value);
static void var_override(const char **var, char *value)
			min_curl_sessions = 1;
		break;
#include "http.h"
	curl_easy_setopt(result, CURLOPT_PROTOCOLS,
		if (http_post_buffer < LARGE_PACKET_MAX)
		    skip_prefix(data, ".pack", &data) &&
			  http_code);
#if LIBCURL_VERSION_NUM >= 0x073400
		} else {

				select_timeout.tv_sec  = 0;
	url = strbuf_detach(&buf, NULL);
static void closedown_active_slot(struct active_request_slot *slot)
	struct strbuf *buffer = buffer_;
			strbuf_addch(&buf, *cp);
			redact_sensitive_header(*header);
		}
}

 * The "got" parameter is the URL that curl reported to us as where we ended

		language_tags[num_langs++] = "*"; /* it's OK; this won't be freed */
struct curl_slist *http_copy_default_headers(void)
			char *semicolon = strstr(cookie, "; ");
	if (rc < 0)
			int curl_result = curl_message->data.result;
	curl_easy_setopt(result, CURLOPT_PASSWORD, http_auth.password);
		cert_auth.username = xstrdup("");
static const char *ssl_cipherlist;
					is_rfc3986_unreserved);
#if LIBCURL_VERSION_NUM >= 0x070903
	case CURLIOCMD_NOP:
		{ "HTTP/1.1", CURL_HTTP_VERSION_1_1 },
	case CURLINFO_SSL_DATA_OUT:
		strbuf_setlen(header,  sensitive_header - header->buf);
				goto abort;
				ssl_version);
			if (fill->fill(fill->data))

	char *tmp_idx = NULL;
};
			active_queue_head = newslot;
#endif
	curl_easy_setopt(slot->curl, CURLOPT_ERRORBUFFER, curl_errorstr);
static void process_curl_messages(void)
#ifndef LIBCURL_CAN_HANDLE_AUTH_ANY


			if (http_proxy_ssl_key)
	strbuf_release(&out);
	the_hash_algo->final_fn(freq->real_oid.hash, &freq->c);
		 * to worry about updating this buffer, only setting its


	/*
	}
	freq->http_code = freq->slot->http_code;
/* Helpers for modifying and creating URLs */
	int rc;
	if (curl_low_speed_limit > 0 && curl_low_speed_time > 0) {
static int fetch_and_setup_pack_index(struct packed_git **packs_head,

long int git_curl_ipresolve;
			http_follow_config = HTTP_FOLLOW_ALWAYS;
{
/*
	while (*p) {
		memset(&freq->stream, 0, sizeof(freq->stream));
	} while (*s++);
	the_hash_algo->init_fn(&freq->c);
	curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDS, NULL);
	if (http_auth.password || curl_empty_auth_enabled())
		curl_dump_header(text, (unsigned char *)data, size, NO_FILTER);
	unsigned char *sha1, const char *base_url)
	headers = strbuf_split_max(&out, '\n', 0);
			ssl_cert_password_required = 1;
	int ret;
size_t fwrite_buffer(char *ptr, size_t eltsize, size_t nmemb, void *buffer_)
	freq->url = get_remote_object_url(base_url, hex, 0);
	while (*lst != p)
}
		slot = slot->next;
		strbuf_addstr(&buf, " no-cache");
static struct credential proxy_cert_auth = CREDENTIAL_INIT;
	curl_global_cleanup();
	int num_messages;
	char buf[128];
	}
	struct fill_chain *next;
		else if (starts_with(curl_http_proxy, "socks"))
		slot = next;
		return git_config_pathname(&curl_cookie_file, var, value);
		if (target == HTTP_REQUEST_FILE) {
				 curl_low_speed_time);
		if (http_is_verbose)

	tmp_idx = fetch_pack_index(sha1, base_url);
	}
			if (curl_timeout == 0) {
static int curl_trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
		    getenv("GIT_SSL_CERT_PASSWORD_PROTECTED") &&
				 */
 * with "https://other.example.com/foo.git/info/refs". We would want the

		return git_config_string(&http_proxy_ssl_cert, var, value);

	char *url, *tmp;
		}
	 */
	struct timeval select_timeout;
	}
		return 0;
	curl_easy_setopt(result, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
	if (curl_empty_auth >= 0)
	return 1;
		strbuf_addch(&s, ':');

			curl_dump_data(text, (unsigned char *)data, size);
		return 0;
#if LIBCURL_VERSION_NUM >= 0x073400
{
}
	append_remote_object_url(&buf, url, hex, only_two_digit_prefix);
#elif LIBCURL_VERSION_NUM >= 0x071000
	 * only uppercase variants, which was later corrected to take both - with
		slot->results->http_code = slot->http_code;

#endif
		if (trace_curl_data) {
	}
		}
			p++;
			&& curl_session_count > min_curl_sessions) {
	{ "anyauth", CURLAUTH_ANY },
		}
			while (slot != NULL &&
	}
	normalized_url = url_normalize(url, &config.url);
	strbuf_reset(buf);
	end_url_with_slash(&buf, base_url);
		curl_easy_setopt(result, CURLOPT_FTP_USE_EPSV, 0);
		buffer->posn = 0;
	if (!s)
	if (num_langs) {
			}
#endif
		new_pack = parse_pack_index(sha1, sha1_pack_index_name(sha1));
			curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION,
		text = "=> Send header";
	}
}
			    http_ssl_backend);
		fclose(preq->packfile);
		return -1;
{
	struct active_request_slot *slot = active_queue_head;
		break;
		curl_easy_getinfo(slot->curl, CURLINFO_HTTP_CONNECTCODE,
}
		finish_active_slot(slot);
	size_t len;
static char *fetch_pack_index(unsigned char *hash, const char *base_url)
void normalize_curl_result(CURLcode *result, long http_code,
	}
#define CURLOPT_KEYPASSWD CURLOPT_SSLCERTPASSWD
	}
 *   "TEXT/PLAIN; charset=utf-8" -> "text/plain", "utf-8"
static char *http_ssl_backend;
	}
		}

	struct strbuf out = STRBUF_INIT;
	 *
			prev_posn = 0;
	git_config(urlmatch_config_entry, &config);
		curl_easy_setopt(result, CURLOPT_SSL_VERIFYHOST, 0);
void process_http_object_request(struct http_object_request *freq)
	}
}
			    http_ssl_backend);
	char *ptr;
			BUG("curl_easy_getinfo for HTTP code failed: %s",
			if (st.st_size == 0)
		BUG("pack tmpfile does not end in .pack.temp?");
		curl_easy_setopt(slot->curl, CURLOPT_FILE, result);

#endif
				     options->charset);
{
}
	const char *name;
	 * something.
			    (select_timeout.tv_sec > 0 ||
		release_active_slot(freq->slot);
	config.cb = NULL;
		no_pragma_header);
		return git_config_string(&curl_http_proxy, var, value);
		}
			text = "=> Send data";
 * or parameters.
	return http_request(url, result, target, options);
static int curl_ssl_try;

	freq->localfile = -1;
	}

static struct trace_key trace_curl = TRACE_KEY_INIT(CURL);
		if (retval < 0)
	if (slot) {
	} while (curlm_result == CURLM_CALL_MULTI_PERFORM);
	curl_proxyuserpwd = NULL;
	} else if (cookies_to_redact.nr &&

		size_t w;


 * the Certificate Store in cURL v7.60.0 and later, which is not what we want
#endif
#endif
				 curl_low_speed_limit);
{
		return CURLIOE_UNKNOWNCMD;
		if (slot->curl != NULL) {
		return git_config_string(&curl_http_version, var, value);

	const int MAX_DECIMAL_PLACES = 3;
	struct http_object_request *freq = data;
	return 0;
	/* Wait for a slot to open up if the queue is full */
	const char *text;
 *
				strbuf_addstr(&redacted_header, cookie);
	 * The previous request may have put cruft into our output stream; we
	    !http_schannel_use_ssl_cainfo) {
	if (http_get_file(url, tmp, NULL) != HTTP_OK) {
#ifdef LIBCURL_CAN_HANDLE_AUTH_ANY
		return git_config_pathname(&ssl_key, var, value);
	if (!http_auth.username || !*http_auth.username) {
	if (!strcmp("http.proxysslcertpasswordprotected", var)) {
			}
				break;
	do {
		return 0;
static const char *curl_proxyuserpwd;
	 * HTTP specification allows. See
			    int only_two_digit_prefix)

			return HTTP_START_FAILED;

void http_cleanup(void)
static const char *http_proxy_authmethod;
			var_override(&curl_http_proxy, getenv("https_proxy"));
	int ret;
		user_agent ? user_agent : git_user_agent());

		int i;
			slot = active_queue_head;
			}
		strbuf_addstr(buf, hex + 2);

			}
		const curl_ssl_backend **backends;
		strbuf_release(&raw);
			for (i = 0; backends[i]; i++)
		newslot->next = NULL;
			return posn / eltsize;
	if (http_auth_methods_restricted &&
	slot->finished = &finished;
	if (!strcmp("http.emptyauth", var)) {
	credential_fill(&http_auth);
		} else {
	/*
			*dir = '/';
				options->effective_url);

	if (options && options->effective_url)
#ifdef USE_CURL_MULTI
		return 0;
#endif
	slot->finished = NULL;
		curl_low_speed_limit = strtol(low_speed_limit, NULL, 10);
		if (!proxy_auth.host)
	unlink_or_warn(freq->tmpfile.buf);
		close_pack_index(new_pack);
	}
		free(tmp_idx);
				       ? ch : '.');
		curl_low_speed_time = strtol(low_speed_time, NULL, 10);
	if (!strcmp("http.postbuffer", var)) {
	{ "tlsv1.3", CURL_SSLVERSION_TLSv1_3 },
			if (num_langs >= MAX_LANGUAGE_TAGS - 1) /* -1 for '*' */
#ifdef USE_CURL_MULTI

		return -1;
	struct buffer *buffer = clientp;
	if (slot->results != NULL) {
	 * Unlike many other common environment variables, these are historically
	 * should clear it out before making our next request.
	struct http_get_options options = {0};


	{ "none", CURLGSSAPI_DELEGATION_NONE },
		if (hide_sensitive_header)
			}
		slot->in_use = 0;
	/*

	}


		xsnprintf(errorstr, errorlen,
{
	end_url_with_slash(&buf, base_url);

{
		break;
void step_active_slots(void)
	preq->slot = get_active_slot();
	git_inflate_end(&freq->stream);
	}
		BUG("update_url_from_redirect: %s is not a superset of %s",
}

	http_is_verbose = 0;
{
#ifdef CURLPROTO_HTTP
	 * methods are available.
 * should be positioned at the start of the potential
	} choice[] = {

}
		http_schannel_check_revoke = git_config_bool(var, value);
	close(freq->localfile);
	}
static const char *http_proxy_ssl_key;
		strbuf_insertstr((*header), 0, text);
}
	freq->localfile = -1;
{
		ssl_cert_password_required = git_config_bool(var, value);
	| CURLAUTH_DIGEST;
			return 0;
		curlinfo_strbuf(slot->curl, CURLINFO_EFFECTIVE_URL,

	closedown_active_slot(slot);


	if (!strip_suffix_mem(got->buf, &new_len, tail))
			select_timeout.tv_sec  = 0;
	curl_easy_cleanup(curl_default);
	struct strbuf **headers, **header;
	if (strncasecmp(raw, name, len))

			http_post_buffer = LARGE_PACKET_MAX;
{
	}
		freq->stream.next_out = expn;
			       void *data)
static int update_url_from_redirect(struct strbuf *base,
	process_http_object_request(freq);


	struct strbuf buf = STRBUF_INIT;
	curl_easy_setopt(result, CURLOPT_HTTPAUTH, CURLAUTH_ANY);


		switch (curl_global_sslset(-1, http_ssl_backend, &backends)) {
	void *data;
		/* collect language tag */
	if (!result) {
	else
			max_fd = -1;
	CURLAUTH_BASIC
	curl_easy_setopt(slot->curl, CURLOPT_IPRESOLVE, git_curl_ipresolve);
		} else {

#endif
					http_proxy_authmethod);
		ssl_version = getenv("GIT_SSL_VERSION");
	new_len = got->len;
	}
		curl_easy_setopt(result, CURLOPT_SSL_VERIFYHOST, 2);
	}

			string_list_clear(&extra_http_headers, 0);
			}
				slot = slot->next;
#endif
	if (freq->localfile < 0 && errno == ENOENT) {
	 */
	curl_easy_setopt(freq->slot->curl, CURLOPT_FAILONERROR, 0);
		free((void *)*var);
static size_t fwrite_sha1_file(char *ptr, size_t eltsize, size_t nmemb,
			      "cURL was built without SSL backends"),
			return HTTP_NOAUTH;
 * new base. So for example, if our base is "http://example.com/foo.git",
					 fwrite);
			}
	free((void *)http_proxy_authmethod);
		close(freq->localfile);
		goto abort;
			var_override(&curl_http_proxy, getenv("ALL_PROXY"));
		*var = val;
	slot->in_use = 1;


static struct {


		free(slot);

int finish_http_object_request(struct http_object_request *freq)
			headers = curl_slist_append(headers, item->string);

void run_active_slot(struct active_request_slot *slot)
	}
int active_requests;
#else
	url = strbuf_detach(&buf, NULL);
	if (freq->localfile != -1) {
/* http_request() targets */
#define PREV_BUF_SIZE 4096

 * With the backend being set to `schannel`, setting sslCAinfo would override
			/* Set request use http version */
#ifdef CURLAUTH_DIGEST_IE
	curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
	CURLMcode curlm_result;
struct fill_chain {
}
		return 0;
	freq->stream.next_in = (void *)ptr;

		http_opt_request_remainder(freq->slot->curl, prev_posn);
			string_list_append(&extra_http_headers, value);
		max_requests = DEFAULT_MAX_REQUESTS;
		curl_http_proxy = xstrdup(remote->http_proxy);
	if (!charset)
#else
struct http_object_request *new_http_object_request(const char *base_url,
	active_requests--;
	const char *cp;


		ret = finalize_object_file(tmp_idx, sha1_pack_index_name(sha1));
			http_auth_methods &= ~CURLAUTH_GSSNEGOTIATE;

		static struct strbuf up = STRBUF_INIT;
			data = strchrnul(data, '\n');
	if (!strcmp("http.maxrequests", var)) {
static const char *get_accept_language(void)
		warning(_("CURLSSLOPT_NO_REVOKE not supported with cURL < 7.44.0"));
		strbuf_addstr_urlencode(&s, proxy_auth.username,
	curl_easy_setopt(preq->slot->curl, CURLOPT_FILE, preq->packfile);
		return git_config_string(&user_agent, var, value);
	}
			if (results->auth_avail) {
#endif
static int handle_curl_result(struct slot_results *results)
				CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5_HOSTNAME);
#ifdef USE_CURL_MULTI
#if LIBCURL_VERSION_NUM >= 0x072200
	struct strbuf buf = STRBUF_INIT;
			ret = get_oid_hex(buffer.buf, &ref->old_oid);
				"Resuming fetch of object %s at byte %"PRIuMAX"\n",
			*dir = 0;
		unlink(tmp_idx);
/*
	 * Reset inflate/SHA1 if there was an error reading the previous temp
static const char *ssl_capath;
	return NULL;
#ifdef CURLGSSAPI_DELEGATION_FLAG
	/*
	return preq;
 *
		     decimal_places++, max_q *= 10)
 * scheme is unlikely to represent a real git repository, and failing to
	/*
		return -1;
			die(_("Could not set SSL backend to '%s': "

	ssl_cert_password_required = 0;
				continue;
				(uintmax_t)prev_posn);
static void set_from_env(const char **var, const char *envname)
		fill_active_slots();
		curl_ssl_verify = 0;
		goto cleanup;
void abort_http_object_request(struct http_object_request *freq)
#endif

}
		    asked, got->buf);

		}

	var_override(&http_proxy_authmethod, getenv("GIT_HTTP_PROXY_AUTHMETHOD"));
	if (cert_auth.password != NULL) {
/* Helpers for fetching packs */



static struct credential proxy_auth = CREDENTIAL_INIT;

 * redirects seen when requesting a URL starting with "url".
		curl_easy_setopt(result, CURLOPT_SSLKEY, ssl_key);
		else
	return 0;
{
					 fwrite_buffer);
	proxy_ssl_cert_password_required = 0;
			curl_easy_setopt(result, CURLOPT_PROXY_CAINFO, http_proxy_ssl_ca_info);

			text = "<= Recv data";
	}
	const struct string_list_item *item;

		}
		case CURLSSLSET_TOO_LATE:
	FILE *result;
	struct strbuf tag = STRBUF_INIT;
	}
	int max_fd;
				  getenv("GIT_REDACT_COOKIES"), ',', -1);

	curl_easy_setopt(result, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
	int num_transfers;
	if (!strcmp("http.lowspeedtime", var)) {
			ret = 0;
	{ "tlsv1.2", CURL_SSLVERSION_TLSv1_2 },
		return 0;
		/* compute decimal_places */
		return 0;
			      int only_two_digit_prefix)
		struct strbuf redacted_header = STRBUF_INIT;
		case CURLSSLSET_UNKNOWN_BACKEND:
						curl_deleg_levels[i].curl_deleg_param);
{
	struct curl_slist *headers = NULL;

	curl_default = get_curl_handle();
void add_fill_function(void *data, int (*fill)(void *))
	do {
		unlink(tmp_idx);
	struct fill_chain *new_fill = xmalloc(sizeof(*new_fill));

#endif
{
	if (ret)
		if (trace_curl_data) {
		return;
	if (ret != HTTP_OK && ret != HTTP_REAUTH)
		FREE_AND_NULL(proxy_cert_auth.password);
	buffer->posn += size;
	free(preq->url);
{
			curl_easy_setopt(result,
	fill_active_slots();
		if (*p == ';') {
 *   LANGUAGE=ko_KR.UTF-8:sr@latin -> "Accept-Language: ko-KR, sr; q=0.9, *; q=0.1"
		the_hash_algo->update_fn(&freq->c, expn,
	 * them here in order to decide whether to prompt for missing password (cf.
	return ret;

		} else {
	/*

#if LIBCURL_VERSION_NUM >= 0x071301
	size_t len = strlen(name);
	/* write Accept-Language header into buf */
static void init_curl_proxy_auth(CURL *result)
	}
			strbuf_addch(&out,
	return 0;
	if (is_transport_allowed("http", from_user))
				curl_easy_setopt(result, CURLOPT_PROXY_SSLKEY, http_proxy_ssl_key);
		for_each_string_list_item(item, options->extra_headers) {

			credential_from_url(&proxy_auth, curl_http_proxy);
static int http_options(const char *var, const char *value, void *cb)
} curl_deleg_levels[] = {
		for (i = 0; i < ARRAY_SIZE(proxy_authmethods); i++) {

		curl_easy_setopt(result, CURLOPT_USE_SSL, CURLUSESSL_TRY);
		newslot->in_use = 0;
			lseek(freq->localfile, 0, SEEK_SET);
	| CURLAUTH_DIGEST_IE
	    !http_schannel_check_revoke) {
					 sizeof(expn) - freq->stream.avail_out);

				http_auth_methods &= results->auth_avail;
	struct stat st;
 *   "text / plain" -> "text/plain"
#endif
				break;
#endif
{
		curl_easy_setopt(result, CURLOPT_SSL_VERIFYPEER, 0);
		if (dir) {
	 * CURL also examines these variables as a fallback; but we need to query

			|| (ch == '-')
	const int MAX_ACCEPT_LANGUAGE_HEADER_SIZE = 4000;
	}
		}
			if (http_proxy_ssl_cert)
	if (prev_posn>0) {
static CURL *get_curl_handle(void)
	const int MAX_LANGUAGE_TAGS = 1000;
	return 1;
	free(url);
#ifdef CURLGSSAPI_DELEGATION_FLAG

	/*
				fprintf(stderr, "Received DONE message for unknown request!\n");
		free(http_ssl_backend);
#ifdef USE_CURL_MULTI
	setup_curl_trace(result);

 * Get an Accept-Language header which indicates user's preferred languages.
	slot->callback_data = NULL;
	normalize_curl_result(&results->curl_result, results->http_code,
{
	struct packed_git *new_pack;
#endif

static void curl_dump_header(const char *text, unsigned char *ptr, size_t size, int hide_sensitive_header)
	size_t i;
			} else {
			return config_error_nonbool(var);
	if (!strcmp("http.sslcapath", var))
}
	if (curlm_result != CURLM_OK &&
	curl_easy_setopt(slot->curl, CURLOPT_HTTPGET, 1);


	if (!ret) {
		process_curl_messages();
	new_pack->next = *packs_head;
	if (prev_posn>0) {
#include "urlmatch.h"
	http_proactive_auth = proactive_auth;
		strbuf_addstr(header, " <redacted>");
 *   LANGUAGE=ko:en -> "Accept-Language: ko, en; q=0.9, *; q=0.1"
#endif
	}
		long opt_token;
{
	}
{
			curl_easy_cleanup(slot->curl);

static struct active_request_slot *active_queue_head;
	if (getenv("GIT_PROXY_SSL_CERT_PASSWORD_PROTECTED"))
 * up.
	default:
	fclose(result);
	if (http_ssl_backend && !strcmp("schannel", http_ssl_backend) &&
			strbuf_release(&url);
static unsigned long http_auth_methods = CURLAUTH_ANY;
		credential_from_url(&http_auth, url);
		return 0;
		strbuf_addf(&out, "%s: ", text);

	if (!strcmp("http.proxysslcainfo", var))
			if (semicolon) {
}

					is_rfc3986_unreserved);
		 */
#ifdef USE_CURL_MULTI
	if (http_is_verbose)
	freq->curl_result = freq->slot->curl_result;
	if (!skip_prefix(asked, base->buf, &tail))
	set_curl_keepalive(result);
	curl_easy_setopt(handle, CURLOPT_DEBUGFUNCTION, curl_trace);
	}
	struct object_id oid;
			FD_ZERO(&excfds);
			if (has_proxy_cert_password())
#if LIBCURL_VERSION_NUM >= 0x070908

		if (ssl_cainfo != NULL)
	}
		curl_ssl_verify = git_config_bool(var, value);
	strbuf_addf(&buf, "%s.temp", sha1_pack_index_name(hash));
#if LIBCURL_VERSION_NUM >= 0x070903

		/* The first token is the type, which is OK to log */
	const char *sensitive_header;
	}
		}
			       slot->curl != curl_message->easy_handle)
	if (curl_http_proxy && curl_http_proxy[0] == '\0') {
{

				strbuf_addstr(&redacted_header, "; ");
		    asked, base->buf);
		curl_low_speed_time = (long)git_config_int(var, value);
			strbuf_addf(&buf, _("Unsupported SSL backend '%s'. "
	case CURLINFO_TEXT:
static struct {
}

		else if (starts_with(curl_http_proxy, "socks5"))
 *

		if (!curl_errorstr[0])
		/*
		curl_easy_setopt(result, CURLOPT_PINNEDPUBLICKEY, ssl_pinnedkey);
		BUG("Unknown http_request target");
			|| (ch == '/')


			       void *result, int target,
enum http_follow_config http_follow_config = HTTP_FOLLOW_INITIAL;
		} else {
/* Use CURLOPT_KEYPASSWD as is */
}


		return git_config_pathname(&ssl_cert, var, value);

				    const struct strbuf *got)

	strbuf_addf(&preq->tmpfile, "%s.temp", sha1_pack_name(target->hash));
	if (!curl_ssl_verify) {
}
		char *http_max_requests = getenv("GIT_HTTP_MAX_REQUESTS");
	curl_easy_setopt(slot->curl, CURLOPT_URL, url);
#endif
 * spaces suppressed, all letters lowercased, and no trailing ";"
		    (*data == '\n' || *data == '\0')) {
			curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION,
				break;
	no_pragma_header = NULL;
#endif

	if (!only_two_digit_prefix)
		unlink(preq->tmpfile.buf);
		var_override(&curl_no_proxy, getenv("no_proxy"));
#endif

		strbuf_addstr(buf, "Accept-Language: ");
static const char *ssl_pinnedkey;
	size_t size = eltsize * nmemb;

	curl_easy_setopt(result, CURLOPT_USERAGENT,
		newslot->curl = NULL;
		return -1;

static void extract_content_type(struct strbuf *raw, struct strbuf *type,
		/* Verify authenticity of the peer's certificate */
static struct {

	for_each_string_list_item(item, &extra_http_headers)
	/* free language tags -- last one is a static '*' */
	ret = http_get_strbuf(url, &buf, &options);
		proxy_cert_auth.host = xstrdup("");
				error_errno("Couldn't truncate temporary file %s",
	return headers;
static const char *curl_cookie_file;
	 * http://tools.ietf.org/html/rfc7231#section-5.3.1 for q-value.
			FD_ZERO(&writefds);
				http_opt_request_remainder(slot->curl, posn);
			die("Invalid proxy URL '%s'", curl_http_proxy);
 * Note that we will silently remove even invalid whitespace. For
	if (proxy_auth.password) {
}
			return nmemb;
				curl_easy_setopt(result, CURLOPT_GSSAPI_DELEGATION,
static const char *http_proxy_ssl_ca_info;
	return allowed_protocols;
} sslversions[] = {
	if (slot->finished != NULL)
/*
	if (val)
#ifdef USE_CURL_MULTI
	if (ssl_key != NULL)
	switch (cmd) {
	if (has_cert_password())
	curl_slist_free_all(pragma_header);
	new_fill->fill = fill;
{
		 * common code clean.
	if (http_proxy_ssl_cert == NULL || proxy_ssl_cert_password_required != 1)
{
	}


			if (i > 0)
		}
	set_from_env(&ssl_key, "GIT_SSL_KEY");
}
ssize_t http_post_buffer = 16 * LARGE_PACKET_MAX;
#if LIBCURL_VERSION_NUM >= 0x072c00
static int http_schannel_check_revoke = 1;
	} else if (ssl_cainfo != NULL || http_proxy_ssl_ca_info != NULL) {
		if (prev_posn>0) {
	struct strbuf buffer = STRBUF_INIT;
	}
			strbuf_addf(&buf, "%%%02x", ch);
static int curl_ssl_verify = -1;
	if (options && options->effective_url && options->base_url) {
		strbuf_setlen(header, sensitive_header - header->buf);
	 || finalize_object_file(tmp_idx, sha1_pack_index_name(p->hash))) {
static const char *http_proxy_ssl_cert;
static struct fill_chain *fill_cfg;
		strbuf_rtrim(&buffer);
				/*
int http_is_verbose;

 *
	slot->in_use = 0;
	int i;
{
		set_proxyauth_name_password(result);

		if (results->http_connectcode == 407)

#include "git-compat-util.h"
		headers = curl_slist_append(headers, accept_language);
static int ssl_cert_password_required;
	while (slot != NULL)
	/*
	else if (results->http_code == 401) {


			fprintf(stderr, "Unknown CURL message received: %d\n",

		while (*p && !isspace(*p))
static struct curl_slist *no_pragma_header;

			var_override(&curl_http_proxy, getenv("http_proxy"));

		for (w = 0; (w < width) && (i + w < size); w++) {
		      "  asked for: %s\n"
 * Returns 1 if we updated the base url, 0 otherwise.
		for (i = 0; i < ARRAY_SIZE(sslversions); i++) {
	if (getenv("GIT_SSL_VERSION"))
			text = "<= Recv SSL data";
		if (!curl_http_proxy) {
}
			s++;
		 * NB: empty option disables proxying at all.
static unsigned long empty_auth_useless =
			}
		/* skip .codeset, @modifier and any other unnecessary parts */
	if (ssl_capath != NULL)
		}
		return 0;
		break;

		int decimal_places;
	fd_set writefds;

	while (slot->in_use) {

}
	strbuf_list_free(headers);
	strbuf_addstr(&buf, "objects/info/packs");
			 */

	return strbuf_detach(&buf, NULL);
 * with "base".
{

				strbuf_addstr(&redacted_header, "=<redacted>");
	}
	struct strbuf buf = STRBUF_INIT;
	return nmemb;
#endif
		return 0;
	if (low_speed_time != NULL)
	 * the exception of http_proxy, which is lowercase only also in CURL. As
				break;
#endif
static void set_curl_keepalive(CURL *c)
#endif
				select_timeout.tv_usec = 50000;
	strbuf_release(&buf);
		http_post_buffer = git_config_ssize_t(var, value);
		return 1;
	} else if (missing_target(results))
#endif
		if (i == ARRAY_SIZE(sslversions))
				hex, (uintmax_t)prev_posn);
	for (i = 0; i < size; i += width) {

 * Check for and extract a content-type parameter. "raw"
			return HTTP_START_FAILED;
		int max_q;
		return -1;
 *
			credential_reject(&http_auth);
			char *equals;


static struct curl_slist *pragma_header;
	{ "negotiate", CURLAUTH_GSSNEGOTIATE },
	free(preq);
}

		}
#include "pkt-line.h"

	case CURLINFO_DATA_OUT:
}
	 *
		if (strstr(curl_http_proxy, "://"))
		if (slot->in_use) {
	FREE_AND_NULL(cached_accept_language);
	if (!result)
		if (slot->in_use) {
	if (slot->curl == NULL) {
		proxy_ssl_cert_password_required = 1;
			REALLOC_ARRAY(language_tags, num_langs);
		}
#include "string-list.h"
	off_t prev_posn = 0;
	};
		if (!strcmp(version_string, choice[i].name)) {
		/*
	curl_easy_setopt(freq->slot->curl, CURLOPT_FILE, freq);
	default:		/* we ignore unknown types by default */
	int i;
	if (skip_prefix(header->buf, "Authorization:", &sensitive_header) ||
	return tmp;
	if (slot->callback_func != NULL)
		return;
		return 0;
		while (isspace(*sensitive_header))
}
}


	if (!strcmp("http.sslcertpasswordprotected", var)) {
	    skip_prefix(header->buf, "Proxy-Authorization:", &sensitive_header)) {
	if (!strcmp("http.proxyauthmethod", var))
	 * HTTP_FOLLOW_* cases themselves.
	preq->packfile = NULL;
}
	return slot;
			fetch_and_setup_pack_index(packs_head, oid.hash, base_url);

	}

		preq->packfile = NULL;
	socklen_t len = (socklen_t)sizeof(ka);
	for (header = headers; *header; header++) {
	active_requests++;
		/* Everything else is opaque and possibly sensitive */
#if LIBCURL_VERSION_NUM >= 0x071800
	strbuf_addf(&buf, "objects/pack/pack-%s.idx", hash_to_hex(hash));
	config.section = "http";
	low_speed_limit = getenv("GIT_HTTP_LOW_SPEED_LIMIT");
#endif
			break;
			select(max_fd+1, &readfds, &writefds, &excfds, &select_timeout);
	size_t new_len;
	strbuf_release(&preq->tmpfile);
}

#define CURLOPT_KEYPASSWD CURLOPT_SSLKEYPASSWD
			  "failed to start HTTP request");
	struct strbuf prevfile = STRBUF_INIT;
	strbuf_reset(base);
		freq->slot->callback_data = NULL;
	struct buffer *buffer = buffer_;
	struct child_process ip = CHILD_PROCESS_INIT;
		if (curl_session_count > min_curl_sessions) {
	curl_easy_setopt(preq->slot->curl, CURLOPT_WRITEFUNCTION, fwrite);
#elif LIBCURL_VERSION_NUM >= 0x071101
	}
	if (!strcmp("http.schannelusesslcainfo", var)) {
	*linkp = new_fill;
		die("curl_multi_init failed");
			if (semicolon)
#endif
static int http_get_file(const char *url, const char *filename,
    }

	free(freq->url);

		if (update_url_from_redirect(options->base_url,
}
		for (max_q = 1, decimal_places = 0;
	struct strbuf filename = STRBUF_INIT;
	return ret;

#endif
	ret = verify_pack_index(new_pack);
				strbuf_addstr(&redacted_header, cookie);
	prev_posn = ftello(preq->packfile);
			slot->curl = NULL;
#endif
int http_get_strbuf(const char *url,

static int has_cert_password(void)
	}
			 struct strbuf *out)
	if (has_pack_index(sha1)) {
	if (!cert_auth.password) {
 * but "text/plain" is the only reasonable output, and this keeps
	}
	if (getenv("GIT_SSL_NO_VERIFY"))
	if (result == NULL) {
		allowed_protocols |= CURLPROTO_HTTP;
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, pragma_header);
		curl_easy_setopt(result, CURLOPT_NOPROXY, curl_no_proxy);
		if (curl_message->msg == CURLMSG_DONE) {
			 * long timeout when curl_multi_fdset returns no file descriptors
			return HTTP_REAUTH;
		return -1;
/*
					    freq->tmpfile.buf);
	const char *data;
#if LIBCURL_VERSION_NUM >= 0x070908
#endif
		if (slot->http_code >= 300)
	}
{

	struct strbuf buf = STRBUF_INIT;
#endif
				 struct strbuf *charset)
#endif
			curl_easy_cleanup(slot->curl);
	while (active_requests >= max_requests) {
			curl_dump_data(text, (unsigned char *)data, size);
		while (*sensitive_header && !isspace(*sensitive_header))
			error_errno("unable to flush a file");
	if (finalize_object_file(preq->tmpfile.buf, sha1_pack_name(p->hash))
			return;
		credential_fill(&cert_auth);
	freq->localfile = open(freq->tmpfile.buf,
		while (cookie) {
	if (curl_ssl_verify == -1)
	char **language_tags = NULL;

		 * subsequently be overridden, so it is fine to mutate this
	return 0;
	}
		strbuf_reset(result);
	case HTTP_REQUEST_FILE:
	CURL *result = curl_easy_init();
			error_errno("unable to truncate a file");
	}
			if (prev_read>0) {
		ret = HTTP_ERROR;
	}
		curl_http_proxy = NULL;

		}
		} else
				finish_active_slot(slot);
	int num_transfers;
		break;
#endif
	curl_easy_setopt(freq->slot->curl, CURLOPT_ERRORBUFFER, freq->errorstr);
	while (slot != NULL && slot->in_use)
		curl_easy_setopt(result, CURLOPT_LOW_SPEED_TIME,
	    curlm_result != CURLM_CALL_MULTI_PERFORM) {
			fprintf(stderr,
		      preq->tmpfile.buf);
	}
	/* Fall back on the default ones */
#endif
static int http_auth_methods_restricted;
		struct strbuf raw = STRBUF_INIT;

		 * from the server into curl_errorstr; unfortunately without
	set_from_env(&ssl_capath, "GIT_SSL_CAPATH");
		http_ssl_backend = xstrdup_or_null(value);
 * example, "text / plain" is specifically forbidden by RFC 2616,
		*var = xstrdup(value);
		allowed_protocols |= CURLPROTO_HTTPS;
	{ "tlsv1.0", CURL_SSLVERSION_TLSv1_0 },
{

		return -1;
		cert_auth.host = xstrdup("");
{
static int trace_curl_data = 1;
	free(url);
static int get_curl_http_version_opt(const char *version_string, long *opt)
	}
}
	struct active_request_slot *slot = active_queue_head;
	/* Don't add Accept-Language header if no language is preferred. */
	strbuf_release(&filename);
	const char *accept_language;
 *
	}
static int curl_session_count;
	if (!strcmp("http.pinnedpubkey", var)) {
	}
#if LIBCURL_VERSION_NUM >= 0x071301
	argv_array_push(&ip.args, "index-pack");
	strbuf_addf(&out, "%s, %10.10ld bytes (0x%8.8lx)\n",
}
	 */
	return http_request_reauth(url, result, HTTP_REQUEST_STRBUF, options);
		text = "<= Recv header";
	if (!strcmp("http.lowspeedlimit", var)) {
		slot->results->auth_avail = 0;
		slot->curl = get_curl_handle();

		 * FAILONERROR it is lost, so we can give only the numeric
	trace_strbuf(&trace_curl, &out);

			strbuf_addch(&tag, *s == '_' ? '-' : *s);

	struct strbuf buf = STRBUF_INIT;
	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK)
	if (low_speed_limit != NULL)
#if LIBCURL_VERSION_NUM >= 0x072c00

{
				strbuf_addstr(&redacted_header, cookie);
#include "protocol.h"
			FD_ZERO(&readfds);
	if (getenv("GIT_CURL_VERBOSE"))
		return 0;
	if (*result == CURLE_OK && http_code >= 300) {
		struct fill_chain *fill;
		 */

	struct curl_slist *headers = http_copy_default_headers();
		error("Unable to get pack index %s", url);
	git_inflate_init(&freq->stream);
#include "run-command.h"
#ifdef CURLPROTO_HTTP

#if LIBCURL_VERSION_NUM >= 0x072c00
		free((void *)curl_http_proxy);

void http_init(struct remote *remote, const char *url, int proactive_auth)

		struct strbuf buf = STRBUF_INIT;
				 * reason, the input string ends in "; ".)
			data++; /* skip past newline */
		curl_save_cookies = git_config_bool(var, value);
		warning(_("Public key pinning not supported with cURL < 7.44.0"));
 * in the example above to end up at a URL that does not even end in
cleanup:
#ifdef USE_CURL_MULTI
 * Example:
	const char *val = getenv(envname);
		}
	strbuf_addstr(&buf, "Pragma:");
						     1,
	if (options && options->content_type) {
	config.cascade_fn = git_default_config;

				http_auth_methods_restricted = 1;
 * The "asked" parameter is a URL that we asked curl to access, and must begin
	if (curl_deleg) {
	 * subsequent request, as by then we know what
}
		curl_easy_setopt(result, CURLOPT_KEYPASSWD, cert_auth.password);
			}


		memset(cert_auth.password, 0, strlen(cert_auth.password));
static const char *curl_deleg;
	 */
		}
static int curl_empty_auth = -1;
			    freq->tmpfile.buf);
				strbuf_addf(buf, q_format, max_q - i);
	 * init_curl_proxy_auth()).
	lst = preq->lst;
struct active_request_slot *get_active_slot(void)
	curl_easy_setopt(slot->curl, CURLOPT_HTTPAUTH, http_auth_methods);
{


						     freq) == prev_read) {
	}
{
	if (getenv("GIT_CURL_FTP_NO_EPSV"))
	strbuf_release(&prevfile);
				CURLOPT_PROXYTYPE, CURLPROXY_SOCKS4);
		curl_dump_header(text, (unsigned char *)data, size, DO_FILTER);
}
	while (active_requests < max_requests) {
	if (!strcmp("http.sslcipherlist", var))
	}
#endif
				break;
			strbuf_addf(&up, "%s:%s",
{
	 */
	if (!strcmp("http.followredirects", var)) {
} proxy_authmethods[] = {

		return;
{
#endif
	if (!strcmp("http.sslcert", var))
	set_from_env(&ssl_cert, "GIT_SSL_CERT");
struct http_pack_request *new_http_pack_request(
 * "name" is the name of the parameter. The value is appended
	 * lowercase only. It appears that CURL did not know this and implemented
	/*
	strbuf_reset(type);
	raw++;
	free(tmp_idx);
	if (curl_ftp_no_epsv)
		 * status code.
			curl_easy_setopt(result,

#endif

		free(language_tags[i]);
		cert_auth.protocol = xstrdup("cert");
 * to "out".
	case CURLINFO_DATA_IN:


	trace_strbuf(&trace_curl, &out);


#endif
		warning_errno("unable to set SO_KEEPALIVE on socket");
		free(tmp_idx);
	}
#if LIBCURL_VERSION_NUM >= 0x070a06
	strbuf_add(buffer, ptr, size);

	/*
			if (string_list_lookup(&cookies_to_redact, cookie)) {
#ifdef USE_CURL_MULTI

#if LIBCURL_VERSION_NUM >= 0x070903
	enum { NO_FILTER = 0, DO_FILTER = 1 };

			credential_from_url(&http_auth, options->base_url->buf);
		}
	ip.no_stdout = 1;
static void http_opt_request_remainder(CURL *curl, off_t pos)
	const char *p;
{
#ifdef LIBCURL_CAN_HANDLE_AUTH_ANY
			return -1; /* parse_pack_index() already issued error message */
		curl_session_count++;
	for (p = raw->buf; *p; p++) {

	 * try to mkdir the last path component.
				CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
		allowed_protocols |= CURLPROTO_FTP;
			       O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (run_command(&ip)) {
#else
 * Note that this assumes a sane redirect scheme. It's entirely possible

	curl_easy_setopt(result, CURLOPT_USERNAME, http_auth.username);
#endif
#endif
	}
			slot->curl = NULL;
}
			credential_fill(&proxy_auth);
#endif
int http_get_info_packs(const char *base_url, struct packed_git **packs_head)

		}

		}


						 sslversions[i].ssl_version);
	if (!strcmp("http.ssltry", var)) {

	case CURLINFO_HEADER_OUT:
		    !parse_oid_hex(data, &oid, &data) &&
	 * Default following to off unless "ALWAYS" is configured; this gives
	if (!trace_want(&trace_curl))
	curl_easy_setopt(c, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
	unsigned int width = 60;
	return 1;
				hash_to_hex(target->hash),
		lst = &((*lst)->next);
#if LIBCURL_VERSION_NUM >= 0x073400
	if (ret == HTTP_OK && finalize_object_file(tmpfile.buf, filename))

#endif
		curl_easy_setopt(result, CURLOPT_PROXYPASSWORD,
		curl_easy_getinfo(slot->curl, CURLINFO_HTTPAUTH_AVAIL,
	new_pack = parse_pack_index(sha1, tmp_idx);

		if (num_transfers < active_requests)
{
#ifdef USE_CURL_MULTI
		return 0;
						proxy_authmethods[i].curlauth_param);
	 */
		curl_message = curl_multi_info_read(curlm, &num_messages);
 * specific to our request. We then strip those bits off of "got" to yield the
void release_http_object_request(struct http_object_request *freq)
	/* Store slot results so they can be read after the slot is reused */
		while (isspace(*sensitive_header))

		trace_printf_key(&trace_curl, "== Info: %s", data);
	const char *name;
	 * precedence here, as in CURL.

		if (skip_prefix(data, "P pack-", &data) &&
{

		var_override(&curl_no_proxy, getenv("NO_PROXY"));
static void set_proxyauth_name_password(CURL *result)
int run_one_slot(struct active_request_slot *slot,
	strbuf_release(&buffer);
	if (slot->curl) {


	 */
char curl_errorstr[CURL_ERROR_SIZE];
	return result;
#endif
	struct active_request_slot *slot;

#include "sideband.h"
	while (!finished) {
	return freq;
			http_follow_config = HTTP_FOLLOW_NONE;
void release_http_pack_request(struct http_pack_request *preq)
			} else if (curl_timeout == -1) {
#define HTTP_REQUEST_STRBUF	0
	strbuf_release(&preq->tmpfile);

		int i;
	curl_multi_remove_handle(curlm, slot->curl);
		slot = slot->next;
static int http_proactive_auth;
	 * translate the code into failure here.
	unlink_or_warn(prevfile.buf);
#else
	struct urlmatch_config config = { STRING_LIST_INIT_DUP };
	/*
	 * CURLAUTH_DIGEST_IE has no corresponding command-line option in
	{ "always", CURLGSSAPI_DELEGATION_FLAG },

	if (!strcmp(asked, got->buf))
				if (fwrite_sha1_file(prev_buf,

	struct http_get_options options = {0};
	accept_language = get_accept_language();

				    const char *asked,
#if LIBCURL_VERSION_NUM >= 0x070907

	char *normalized_url;
		}
	}
		 * The contents of header starting from sensitive_header will
			prev_read = xread(prevlocal, prev_buf, PREV_BUF_SIZE);
void setup_curl_trace(CURL *handle)
		return git_config_string(&http_proxy_authmethod, var, value);
		return 0;
#if LIBCURL_VERSION_NUM >= 0x070903
	tmp = strbuf_detach(&buf, NULL);
	curlm = curl_multi_init();
				select_timeout.tv_usec = (curl_timeout % 1000) * 1000;
/*

	if (url) {
		error("Unable to open local file %s for pack",

			mkdir(freq->tmpfile.buf, 0777);
			if (!equals) {
	}
#ifndef NO_CURL_EASY_DUPHANDLE
 */
static int min_curl_sessions = 1;
			warning(_("negative value for http.postbuffer; defaulting to %d"), LARGE_PACKET_MAX);
	closedown_active_slot(slot);
		text, (long)size, (long)size);
		return 0;
		slot = active_queue_head;

	curl_multi_cleanup(curlm);
		 struct slot_results *results)
	switch (target) {
	return NULL;
	struct packed_git *p = preq->target;
	curl_multi_perform(curlm, &num_transfers);
		return -1;
	curl_easy_setopt(slot->curl, CURLOPT_COOKIEFILE, curl_cookie_file);
			language_tags[num_langs - 1] = strbuf_detach(&tag, NULL);

			die(_("Could not set SSL backend to '%s': already set"),
	char prev_buf[PREV_BUF_SIZE];
				http_auth.username, http_auth.password);

	unsigned char expn[4096];
	 */
	{ "ntlm", CURLAUTH_NTLM },
			sensitive_header++;
				}
		write_accept_language(&buf);
{

 */
	}
		credential_approve(&http_auth);
	if (options && options->initial_request &&
		proxy_ssl_cert_password_required = git_config_bool(var, value);

		return 0;

{



		unlink_or_warn(freq->tmpfile.buf);

	const char *s = get_preferred_languages();
				*equals = '=';

#if LIBCURL_VERSION_NUM >= 0x071900
		if (isspace(*p))
		freq->slot = NULL;
	if (!strcmp("http.noepsv", var)) {
	char *tmp_idx;
{



	free(url);

	    http_follow_config == HTTP_FOLLOW_INITIAL)
{
	 * hack as long as we would potentially try some
	free(language_tags);

		curl_low_speed_limit = (long)git_config_int(var, value);
				cookie = semicolon + strlen("; ");
	}
		return;


		http_opt_request_remainder(preq->slot->curl, prev_posn);
/* *var must be free-able */
				continue;
		strbuf_addstr(buf, ptr);
	if (getenv("GIT_REDACT_COOKIES")) {
	if (http_proxy_authmethod) {

	struct http_pack_request *preq;
{
		proxy_cert_auth.protocol = xstrdup("cert");

static struct string_list cookies_to_redact = STRING_LIST_INIT_DUP;
	data = buf.buf;
	{
			curl_empty_auth = git_config_bool(var, value);
			if (!strcmp(ssl_version, sslversions[i].name)) {
			const struct http_get_options *options)


#if LIBCURL_VERSION_NUM >= 0x073400
}
	unlink_or_warn(prevfile.buf);
}

#include "version.h"
			*equals = 0; /* temporarily set to NUL for lookup */
		if (starts_with(curl_http_proxy, "socks5h"))
	long allowed_protocols = 0;

		unlink_or_warn(freq->tmpfile.buf);
	curl_easy_setopt(preq->slot->curl, CURLOPT_HTTPHEADER,
	url = quote_ref_url(base, ref->name);
}
	result = fopen(tmpfile.buf, "a");
	}
		if (http_post_buffer < 0)
		warning(_("Delegation control is not supported with cURL < 7.22.0"));
char *get_remote_object_url(const char *url, const char *hex,
	set_from_env(&http_proxy_ssl_ca_info, "GIT_PROXY_SSL_CAINFO");
	rename(freq->tmpfile.buf, prevfile.buf);
	switch (type) {
	}
	}
		if (!ssl_cert_password_required &&

	return handle_curl_result(results);
{
		free(tmp_idx);
	while (*raw && !isspace(*raw) && *raw != ';')
		freq->stream.avail_out = sizeof(expn);
		if (!value) {
{

	rc = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&ka, len);
	strbuf_init(&freq->tmpfile, 0);
	}
#include "credential.h"
static long curl_low_speed_limit = -1;
	 */
	char *url;
	unlink_or_warn(freq->tmpfile.buf);
	 * FAILONERROR (to keep the server's custom error response), and should
		} while (prev_read > 0);
	if (remote)
					(char *) ptr + posn, size - posn);
static int sockopt_callback(void *client, curl_socket_t fd, curlsocktype type)
static void redact_sensitive_header(struct strbuf *header)
#endif
	if (ssl_cipherlist != NULL && *ssl_cipherlist)
	if (!oideq(&freq->oid, &freq->real_oid)) {
	return nmemb;
		CURLcode c = curl_easy_getinfo(slot->curl, CURLINFO_HTTP_CODE,
	return nmemb;
	 * Our libcurl is too old to do AUTH_ANY in the first place;
	return ret;
		    struct http_get_options *options)
		if (slot == NULL) {
	}

		the_hash_algo->init_fn(&freq->c);
		slot->results->curl_result = slot->curl_result;
curlioerr ioctl_buffer(CURL *handle, int cmd, void *clientp)
	http_proxy_authmethod = NULL;
		curlinfo_strbuf(slot->curl, CURLINFO_CONTENT_TYPE, &raw);
	if (options && options->no_cache)

	if (!strip_suffix(preq->tmpfile.buf, ".pack.temp", &len))
		}
		if (*data)

	if (!strcmp("http.cookiefile", var))
		struct strbuf buf = STRBUF_INIT;
		for (fill = fill_cfg; fill; fill = fill->next)
{
		char *dir = strrchr(freq->tmpfile.buf, '/');
	if (curl_ssl_try)
	} else if (curl_http_proxy) {
		return 0;
	}
	end_url_with_slash(&buf, base_url);
	if (ssl_version && *ssl_version) {

		freq->zret = git_inflate(&freq->stream, Z_SYNC_FLUSH);

#if LIBCURL_VERSION_NUM >= 0x072f00 // 7.47.0
					     url, options->effective_url)) {
			die("%s", buf.buf);
	strbuf_addf(&prevfile, "%s.prev", filename.buf);
			if (!strcmp(http_proxy_authmethod, proxy_authmethods[i].name)) {
			warning("unsupported ssl version %s: using default",
	if (!strcmp("http.savecookies", var)) {
	if (!tmp_idx)
			} else {
			warning("unsupported proxy authentication method %s: using anyauth",

{
	if (!curlm)

{

		else if (starts_with(curl_http_proxy, "socks4a"))
	if (!strcmp("http.version", var)) {
	 */

	if (ret != HTTP_REAUTH)
	while (curl_message != NULL) {

			 get_curl_allowed_protocols(-1));

	off_t prev_posn = 0;
	config.collect_fn = http_options;
	 * curl(1) and is not included in CURLAUTH_ANY, so we leave it out
	curl_easy_setopt(slot->curl, CURLOPT_READFUNCTION, NULL);

	while (*linkp)
 * Downloads a URL and stores the result in the given file.
}

}
static CURL *curl_default;
	int num_langs = 0;
	if (!curl_http_proxy) {
	warning(_("Protocol restrictions not supported with cURL < 7.19.4"));
		posn += retval;
    if (curl_http_version) {

	if (!strcmp("http.proxy", var))
}
static const char *ssl_cainfo;
			ref->symref = xstrdup(buffer.buf + 5);
	options.no_cache = 1;
#else
	if (http_get_strbuf(url, &buffer, &options) == HTTP_OK) {
	set_from_env(&user_agent, "GIT_HTTP_USER_AGENT");
 * file is still around) the download is resumed.
	if (ssl_pinnedkey != NULL)
		}
#if LIBCURL_VERSION_NUM >= 0x071700
 */
 * Examples:
}
	}
#else
		if (buf.len > 0)

	const char *name;
int start_active_slot(struct active_request_slot *slot)
static int curl_ftp_no_epsv;
		goto abort;
		else if (git_config_bool(var, value))
	strbuf_release(&filename);
			 get_curl_allowed_protocols(0));
	int ret = http_request(url, result, target, options);
	if (proxy_cert_auth.password != NULL) {

	free(normalized_url);
		if (!extract_param(p, "charset", charset))
	strbuf_reset(charset);
		curl_easy_setopt(result, CURLOPT_CAPATH, ssl_capath);
{
		else
static int proxy_ssl_cert_password_required;
	strbuf_add(base, got->buf, new_len);
static const char *ssl_key;
	{ "policy", CURLGSSAPI_DELEGATION_POLICY_FLAG },
	if (proxy_auth.username) {
}
		return curl_empty_auth;
size_t fwrite_null(char *ptr, size_t eltsize, size_t nmemb, void *strbuf)
	default:
#endif
	curl_session_count = 0;
				break;
		 * credentials in a given program run, so we do not have
	curl_easy_setopt(handle, CURLOPT_DEBUGDATA, NULL);
	set_from_env(&http_proxy_ssl_cert, "GIT_PROXY_SSL_CERT");
#define HTTP_REQUEST_FILE	1
static long curl_low_speed_time = -1;
			http_follow_config = HTTP_FOLLOW_INITIAL;
	 * resume where it left off
	curl_easy_setopt(result, CURLOPT_MAXREDIRS, 20);
	argv_array_push(&ip.args, preq->tmpfile.buf);
		slot->curl = curl_easy_duphandle(curl_default);
		curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 1);
	curl_slist_free_all(no_pragma_header);
		die(_("unable to update url base from redirection:\n"
	if (preq->packfile != NULL) {
					    http_ssl_backend);
	freq = xcalloc(1, sizeof(*freq));
static void finish_active_slot(struct active_request_slot *slot)
#include "config.h"
	 * callers a sane starting point, and they can tweak for individual
		}



	FREE_AND_NULL(freq->url);
	long curlauth_param;
	{ "tlsv1.1", CURL_SSLVERSION_TLSv1_1 },
			curl_easy_setopt(result,
}
	if (http_follow_config == HTTP_FOLLOW_ALWAYS)


	struct active_request_slot *slot = active_queue_head;
	new_fill->next = NULL;


 *   LANGUAGE= LANG=en_US.UTF-8 -> "Accept-Language: en-US, *; q=0.1"
	if (!strcmp("http.sslverify", var)) {

	}
	if (ret != HTTP_OK)
	preq->packfile = fopen(preq->tmpfile.buf, "a");
	tmp_idx = xstrfmt("%.*s.idx.temp", (int)len, preq->tmpfile.buf);
		if (i == ARRAY_SIZE(curl_deleg_levels))
		if (http_auth.protocol && !strcmp(http_auth.protocol, "https")) {
		if (!up.len)
			curl_multi_timeout(curlm, &curl_timeout);
}
	case CURLINFO_SSL_DATA_IN:
		strbuf_addch((*header), '\n');

	free((void *)curl_proxyuserpwd);
{
			*opt = choice[i].opt_token;


	}
	if (!strcmp("http.sslcainfo", var))
	return cached_accept_language;
				(int)curl_message->msg);
		die("curl_global_init failed");
#ifdef USE_CURL_MULTI
		return git_config_pathname(&ssl_pinnedkey, var, value);
				curl_easy_strerror(results->curl_result),
		curl_easy_setopt(result, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_REVOKE);
	ret = run_one_slot(slot, &results);
	pragma_header = NULL;
	if (!strcmp("http.sslkey", var))
		"Pragma: no-cache");
static int max_requests = -1;
	if (freq->http_code == 416) {
	}

#endif
		text, (long)size, (long)size);
		trace_curl_data = 0;
		var_override(&http_proxy_authmethod, remote->http_proxy_authmethod);
		http_schannel_use_ssl_cainfo = git_config_bool(var, value);
				unlink_or_warn(freq->tmpfile.buf);
}
			|| ((ch >= '0') && (ch <= '9'))
{
static inline int needs_quote(int ch)
	if (is_transport_allowed("https", from_user))
	else
}

			select_timeout.tv_usec = 50000;
	}

	} else {
			break;
			if (buf->len > MAX_ACCEPT_LANGUAGE_HEADER_SIZE) {
	} else {
		curl_easy_setopt(result, CURLOPT_SSLCERT, ssl_cert);
		goto cleanup;
		warning("requested range invalid; we may already have all the data.");
	curl_slist_free_all(headers);
		xmulti_remove_handle(slot);
			if (max_fd < 0 &&
			warning("Unknown delegation method '%s': using default",
	}
	if (!strcmp("http.schannelcheckrevoke", var)) {

	freq->slot = NULL;
int http_fetch_ref(const char *base, struct ref *ref)
	/*
	}
	slot = get_active_slot();
}
	do {
	argv_array_pushl(&ip.args, "-o", tmp_idx, NULL);
	 * fetched.

		error("Unable to open local file %s", tmpfile.buf);
cleanup:
	if (!new_pack) {
 * Our basic strategy is to compare "base" and "asked" to find the bits
		 * Handle case with the empty http.proxy value here to keep
			curl_easy_setopt(result, CURLOPT_USERPWD, ":");
 * and we ask for "http://example.com/foo.git/info/refs", we might end up
		 */
	slot->results = results;
}
			   char *errorstr, size_t errorlen)
	do {
	if (size > buffer->buf.len - buffer->posn)
	char *low_speed_time;
			 struct http_get_options *options)
 *

	while (slot != NULL) {
#endif
			     select_timeout.tv_usec > 50000)) {

	string_list_clear(&config.vars, 1);
#if LIBCURL_VERSION_NUM >= 0x073400
	low_speed_time = getenv("GIT_HTTP_LOW_SPEED_TIME");
			      const char *hex,
	fd_set excfds;

		} else {
		curl_easy_setopt(slot->curl, CURLOPT_FOLLOWLOCATION, 1);
}
static CURLM *curlm;
				       (ch >= 0x20) && (ch < 0x80)
			|| (ch == '.'))
		proxy_cert_auth.path = xstrdup(http_proxy_ssl_cert);
#include "transport.h"

static long get_curl_allowed_protocols(int from_user)
	slot->callback_func = NULL;
{

		string_list_split(&cookies_to_redact,
#ifndef NO_CURL_EASY_DUPHANDLE
		goto add_pack;

			strbuf_addf(&url, "http://%s", curl_http_proxy);
 * If the "charset" argument is not NULL, store the value of any
		return 0;
	int ka = 1;
}
#else
			curl_session_count--;
		int i;

		FREE_AND_NULL(proxy_auth.password);
 * Update the "base" url to a more appropriate value, as deduced by

	for (i = 0; i < ARRAY_SIZE(choice); i++) {
			      curl_errorstr, sizeof(curl_errorstr));
				slot->curl_result = curl_result;
}
			curl_easy_setopt(result, CURLOPT_PROXYTYPE, CURLPROXY_HTTPS);
	}
		    struct strbuf *result,
{
		curl_easy_setopt(result, CURLOPT_VERBOSE, 1L);
#endif
	new_fill->data = data;
			&slot->results->http_connectcode);
 */
		}
	preq->url = strbuf_detach(&buf, NULL);
			url = options->effective_url->buf;
 * parameter, with any whitespace already removed.
	strbuf_release(&tmpfile);
		error_errno("Couldn't create temporary file %s",
	if (!strcmp("http.delegation", var)) {
		curl_ssl_verify = 1;

		} else if (!*value) {
}
	 * MAX_DECIMAL_PLACES must not be larger than 3. If it is larger than
		trace_strbuf(&trace_curl, (*header));
	if (curl_http_proxy) {
		char q_format[32];

			curl_easy_setopt(result, CURLOPT_CAINFO, ssl_cainfo);

	curl_easy_setopt(freq->slot->curl, CURLOPT_URL, freq->url);
#if LIBCURL_VERSION_NUM >= 0x071304
	}
#include "gettext.h"
static void release_active_slot(struct active_request_slot *slot)
static int curl_save_cookies;
			slot->next = newslot;
{
		min_curl_sessions = git_config_int(var, value);


#ifdef USE_CURL_MULTI
		curl_easy_setopt(slot->curl, CURLOPT_COOKIEJAR, curl_cookie_file);
#endif
	if (getenv("GIT_SSL_CIPHER_LIST"))
		(*slot->finished) = 1;
	}
		curl_easy_setopt(result, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
		return ret;
	strbuf_release(&prevfile);
#if LIBCURL_VERSION_NUM >= 0x070a08
	credential_fill(&http_auth);
{
#if LIBCURL_VERSION_NUM >=0x072f00
	}
{
	if (*raw != '=')
	}

			sensitive_header++;
#endif

 */
	if (!strcmp("http.minsessions", var)) {
static const char *ssl_version;
	int ret = 0;
	while (slot != NULL) {
	}
		return 0;

#endif
#if LIBCURL_VERSION_NUM >= 0x073800
	char *hex = oid_to_hex(oid);
		freq->localfile = open(freq->tmpfile.buf,
	CURLMcode curlm_result = curl_multi_add_handle(curlm, slot->curl);
		return 0;
		close(prevlocal);
static const char *user_agent;
				/* invalid cookie, just append and continue */
/* Helpers for fetching objects (loose) */

		return HTTP_START_FAILED;
#include "object-store.h"
		}
			       struct http_get_options *options)
	if (!ret && ptr)
	active_queue_head = NULL;
	return ret;
		break;
		curlm_result = curl_multi_perform(curlm, &num_transfers);
	*packs_head = new_pack;
	char *low_speed_limit;
	memcpy(ptr, buffer->buf.buf + buffer->posn, size);
				curl_easy_setopt(result, CURLOPT_PROXY_SSLCERT, http_proxy_ssl_cert);
		string_list_sort(&cookies_to_redact);
		   skip_prefix(header->buf, "Cookie:", &sensitive_header)) {
				 * There are more cookies. (Or, for some
	/*
#ifdef CURLOPT_USE_SSL
static char *quote_ref_url(const char *base, const char *ref)
	}
	 * This could have failed due to the "lazy directory creation";
		/*
		return HTTP_MISSING_TARGET;
		xsnprintf(q_format, sizeof(q_format), ";q=0.%%0%dd", decimal_places);


	 */
{
#if LIBCURL_VERSION_NUM >= 0x070a08
		curl_easy_setopt(slot->curl, CURLOPT_FOLLOWLOCATION, 1);
	strbuf_reset(&out);
	}
			proxy_auth.username);
		}
	case CURLIOCMD_RESTARTREAD:

			curl_multi_strerror(curlm_result));
#include "pack.h"
				  &slot->results->auth_avail);
		case CURLSSLSET_NO_BACKENDS:
	preq = xcalloc(1, sizeof(*preq));
	ip.no_stdin = 1;
 */


#include "packfile.h"
			 * It can happen that curl_multi_timeout returns a pathologically

	/* Add additional headers here */
		git_inflate_init(&freq->stream);
	end_url_with_slash(buf, url);
		if (trace_curl_data) {
	int posn = 0;
		}
#else
#else

{
static int has_proxy_cert_password(void)
		long opt;
	}
			curl_dump_data(text, (unsigned char *)data, size);
#ifdef LIBCURL_CAN_HANDLE_AUTH_ANY
	if (!strcmp("http.useragent", var))
add_pack:
	curl_easy_setopt(c, CURLOPT_TCP_KEEPALIVE, 1);
	int ch;
			}
				} else {

		 * string (hence the assignment to "char *").
		freq->slot->callback_func = NULL;
 *

				slot = slot->next;

		return git_config_string(&ssl_cipherlist, var, value);

	int (*fill)(void *);
			max_requests = atoi(http_max_requests);
			var_override(&curl_http_proxy, getenv("all_proxy"));
		hash_to_hex(target->hash));
size_t fread_buffer(char *ptr, size_t eltsize, size_t nmemb, void *buffer_)
		extract_content_type(&raw, options->content_type,
static const char *curl_http_version = NULL;
		return -1;
 *   LANGUAGE=ko LANG=en_US.UTF-8 -> "Accept-Language: ko, *; q=0.1"
static int http_request_reauth(const char *url,

		active_requests--;
		if (buffer.len == the_hash_algo->hexsz)
	int ret;
static void write_accept_language(struct strbuf *buf)
	if (http_proactive_auth)
#ifdef LIBCURL_CAN_HANDLE_AUTH_ANY
	for (i = 0; i < num_langs - 1; i++)
		linkp = &(*linkp)->next;
	if (!charset->len && starts_with(type->buf, "text/"))
		if (!fill)
			/*

static const char *ssl_cert;


static CURLcode curlinfo_strbuf(CURL *curl, CURLINFO info, struct strbuf *buf)
		memset(proxy_cert_auth.password, 0, strlen(proxy_cert_auth.password));
	 * attempt, only fetch the data we don't already have.
#endif

#else
		      "   redirect: %s"),
#endif
		proxy_cert_auth.username = xstrdup("");
		return CURLIOE_OK;
	if (freq->slot != NULL) {
{
	if (value) {
	{ "sslv2", CURL_SSLVERSION_SSLv2 },
		struct active_request_slot *next = slot->next;
	if (freq->localfile < 0) {
	const char *tail;
		return git_config_string(&ssl_version, var, value);
			text = "=> Send SSL data";
			off_t posn = ftello(result);
	}
				curl_deleg);
	if (results->curl_result == CURLE_OK) {


		for (i = 0; i < num_langs; i++) {
			slot = slot->next;
			curl_easy_setopt(result,
	curl_easy_setopt(slot->curl, CURLOPT_UPLOAD, 0);
	if (remote && remote->http_proxy)
	 * In the automatic case, kick in the empty-auth
	} else {
#endif
	 * But only do this when this is our second or
	strbuf_release(&freq->tmpfile);
#endif
	strbuf_addf(&out, "%s, %10.10ld bytes (0x%8.8lx)\n",
		while (*s && *s != ':')
	unlink(sha1_pack_index_name(p->hash));
#endif
				*semicolon = 0;

			continue;
	free(tmp_idx);
	warning("unknown value given to http.version: '%s'", version_string);
	}
			proxy_auth.password);
					    "Supported SSL backends:"),
struct credential http_auth = CREDENTIAL_INIT;
	return 1;
	}
static void xmulti_remove_handle(struct active_request_slot *slot)
static const char *curl_http_proxy;
	return -1; /* not found */
	close_pack_index(p);
		if (!slot->in_use && slot->curl != NULL
{

	 * Likewise, if we see a redirect (30x code), that means we turned off
		curl_easy_setopt(result, CURLOPT_PROXY, "");
	{ "tlsv1", CURL_SSLVERSION_TLSv1 },
	strbuf_addf(&freq->tmpfile, "%s.temp", filename.buf);
			curl_session_count--;
		return HTTP_ERROR;

		curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 0);
#ifdef LIBCURL_CAN_HANDLE_AUTH_ANY
			strbuf_addstr(buf, language_tags[i]);
#define LIBCURL_CAN_HANDLE_AUTH_ANY
		memset(proxy_auth.password, 0, strlen(proxy_auth.password));
		if (value && !strcmp(value, "initial"))

		return 0;
	struct slot_results results;
}
		}
}
#else
		credential_fill(&proxy_cert_auth);
		curl_multi_perform(curlm, &num_transfers);
			if (posn > 0)
		int i;
		FREE_AND_NULL(tmp);
		/* add '*' */
	headers = curl_slist_append(headers, buf.buf);
	for (cp = ref; (ch = *cp) != 0; cp++)

	}
#ifndef NO_CURL_IOCTL
#if LIBCURL_VERSION_NUM >= 0x070908
	init_curl_proxy_auth(result);
			if (slot != NULL) {
	strbuf_grow(type, raw->len);
	struct packed_git *target, const char *base_url)
		strbuf_reset(&out);
		else if (starts_with(buffer.buf, "ref: ")) {
	ret = http_request_reauth(url, result, HTTP_REQUEST_FILE, options);
{
		return git_config_pathname(&ssl_cainfo, var, value);
		{ "HTTP/2", CURL_HTTP_VERSION_2 }

#endif

void append_remote_object_url(struct strbuf *buf, const char *url,
	if (!start_active_slot(slot)) {
		do {

		}
	curl_easy_setopt(curl, CURLOPT_RANGE, buf);
{

#endif
		for (; *s && (isalnum(*s) || *s == '_'); s++)
	curl_easy_setopt(preq->slot->curl, CURLOPT_URL, preq->url);
		strbuf_addch(out, *raw++);
		curl_easy_setopt(slot->curl, CURLOPT_FOLLOWLOCATION, 0);


	size_t size = eltsize * nmemb;
	 * that, q-value will be smaller than 0.001, the minimum q-value the
		strbuf_addstr(charset, "ISO-8859-1");
		strbuf_insertstr((*header), strlen(text), ": ");
abort:
		case CURLSSLSET_OK:
	} else if (freq->curl_result != CURLE_OK) {
	}
}
				select_timeout.tv_sec  =  curl_timeout / 1000;
	 *
		curl_easy_setopt(result, CURLOPT_SSL_VERIFYPEER, 1);

#ifndef NO_CURL_EASY_DUPHANDLE
		strbuf_addch(&out, '\n');
		die("curl_easy_init failed");
		return git_config_pathname(&ssl_capath, var, value);
				ssl_cipherlist);
	{ "sslv3", CURL_SSLVERSION_SSLv3 },
	freq->slot = get_active_slot();
#if LIBCURL_VERSION_NUM >= 0x070a07 /* CURLOPT_PROXYAUTH and CURLAUTH_ANY */
 * Extract a normalized version of the content type, with any
#endif
	if (is_transport_allowed("ftps", from_user))

				curl_easy_strerror(c));
		const struct string_list_item *item;
	if (curl_save_cookies)
			curl_empty_auth = -1;
	prevlocal = open(prevfile.buf, O_RDONLY);

	 * Split the colon-separated string of preferred languages into
		if (stat(freq->tmpfile.buf, &st) == 0)

	static struct {
	options.no_cache = 1;
		/*
	if (type != CURLSOCKTYPE_IPCXN)
	}
#if LIBCURL_VERSION_NUM >= 0x070a08
	return ret;
			xmulti_remove_handle(slot);
	}
		init_curl_http_auth(result);
#if LIBCURL_VERSION_NUM >= 0x070c00
		ssize_t retval = xwrite(freq->localfile,

{
		trace_strbuf(&trace_curl, &out);
	config.key = NULL;
	end_url_with_slash(&buf, base);
	slot->results = NULL;
		 * initial value.
			struct strbuf url = STRBUF_INIT;
		return git_config_string(&http_proxy_ssl_key, var, value);
	}
		    starts_with(url, "https://"))
	    (http_auth_methods & ~empty_auth_useless))

 *   LANGUAGE= -> ""
	set_from_env(&ssl_cainfo, "GIT_SSL_CAINFO");
}
 *

			}

			cached_accept_language = strbuf_detach(&buf, NULL);
	run_active_slot(slot);
		if (http_auth.username && http_auth.password) {
	if (freq->slot == NULL)


	if (!strcmp("http.extraheader", var)) {
			if (ftruncate(freq->localfile, 0) < 0) {

{
static struct credential cert_auth = CREDENTIAL_INIT;
	if (freq->localfile != -1)
		 * Note that we assume we only ever have a single set of
		if (ftruncate(fileno(result), 0) < 0) {

	}


		if (tag.len) {

	strbuf_add(&out, ptr, size);
				strbuf_addf(&buf, "\n\t%s", backends[i]->name);
	pragma_header = curl_slist_append(http_copy_default_headers(),
static const char *curl_no_proxy;
	/* not supported on older curl versions */
		return git_config_string(&http_proxy_ssl_ca_info, var, value);
{
	if (getenv("GIT_TRACE_CURL_NO_DATA"))
			last_buf_len = buf->len;
void fill_active_slots(void)
 * by default.
void finish_all_active_slots(void)
	freq->rename = finalize_object_file(freq->tmpfile.buf, filename.buf);

		rewind(result);
	struct active_request_slot *slot = freq->slot;
	 * file; also rewind to the beginning of the local file.
{
		int last_buf_len = 0;
#else
	curl_easy_setopt(slot->curl, CURLOPT_ENCODING, "");
{
	{
		newslot = xmalloc(sizeof(*newslot));
	 * the lowercase versions are the historical quasi-standard, they take
};

 * rewrite the base opens options for malicious redirects to do funny things.
		 * Normally curl will already have put the "reason phrase"

	curl_easy_setopt(result, CURLOPT_REDIR_PROTOCOLS,
				cookie = NULL;
			credential_approve(&proxy_auth);
		if (fflush(result)) {
	struct active_request_slot *newslot;
			fprintf(stderr,
	loose_object_path(the_repository, &filename, &freq->oid);
	struct strbuf out = STRBUF_INIT;
 * "info/refs".  In such a case we die. There's not much we can do, such a
		if (http_proxy_ssl_ca_info != NULL)
			;
	fd_set readfds;

		return;
		size = buffer->buf.len - buffer->posn;
	 */
	int num_transfers;
	if (!proxy_cert_auth.password) {
	int finished = 0;
				sizeof(curl_errorstr));
	freq->stream.avail_in = size;
			curl_easy_cleanup(slot->curl);
	 * redirect-following, and we should treat the result as an error.
				curl_easy_setopt(result, CURLOPT_SSLVERSION,
		return 0;

	}
}
	return 0;
	free(preq->url);
	curl_easy_setopt(slot->curl, CURLOPT_FAILONERROR, 1);
			curl_easy_setopt(result, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
#endif
	}


 * charset parameter there.

		return 0;
	free(preq);
				xmulti_remove_handle(slot);
	 * If we have successfully processed data from a previous fetch
			curl_easy_setopt(result, CURLOPT_HTTP_VERSION, opt);
						     prev_read,
	ssize_t prev_read = 0;
		cert_auth.path = xstrdup(ssl_cert);
	if (prevlocal != -1) {

		ret = HTTP_ERROR;
				curl_easy_setopt(result, CURLOPT_PROXYAUTH,
			run_active_slot(slot);
	}
#ifdef NO_CURL_EASY_DUPHANDLE
		if (value && !strcmp("auto", value))
	curl_easy_setopt(slot->curl, CURLOPT_HTTPGET, 1);
			break; /* Okay! */
		curl_easy_setopt(result, CURLOPT_PROXYUSERPWD, curl_proxyuserpwd);
		init_curl_http_auth(slot->curl);
			void *result, int target,
		curl_easy_setopt(result, CURLOPT_USERPWD, up.buf);
	} while (freq->stream.avail_in && freq->zret == Z_OK);
	}
		     max_q < num_langs && decimal_places <= MAX_DECIMAL_PLACES;
				strbuf_remove(buf, last_buf_len, buf->len - last_buf_len);
static int curl_empty_auth_enabled(void)
{
		else {
				       O_WRONLY | O_CREAT | O_EXCL, 0666);



		strbuf_addbuf(header, &redacted_header);
				CURLOPT_PROXYTYPE, CURLPROXY_SOCKS4A);
	 * If a previous temp file is present, process what was already
		strbuf_addch(type, tolower(*p));
#elif LIBCURL_VERSION_NUM >= 0x070903
	return 1;
				select_timeout.tv_sec  = 0;
		REALLOC_ARRAY(language_tags, num_langs + 1);
	strbuf_addf(buf, "objects/%.*s/", 2, hex);
		}

static char *cached_accept_language;
	strbuf_addf(&tmpfile, "%s.temp", filename);
}
 *   LANGUAGE= LANG=C -> ""
	char *url;

	}
			} else {

			strlcpy(curl_errorstr,
long int git_curl_ipresolve = CURL_IPRESOLVE_WHATEVER;
	curl_easy_setopt(freq->slot->curl, CURLOPT_WRITEFUNCTION, fwrite_sha1_file);
	set_from_env(&http_proxy_ssl_key, "GIT_PROXY_SSL_KEY");
#endif
		curl_easy_setopt(result, CURLOPT_LOW_SPEED_LIMIT,
/* Modes for which empty_auth cannot actually help us. */
	if (!strcmp("http.proxysslkey", var))
	free(freq);
		 */


	if (!strcmp("http.proxysslcert", var))
		strbuf_rtrim((*header));
		if (trace_curl_data) {

		char *cookie;
{
	if (!strcmp("http.sslbackend", var)) {
	fclose(preq->packfile);
	 */
}
		max_requests = git_config_int(var, value);
	/* Run callback if appropriate */
		curl_easy_setopt(result, CURLOPT_PROXY_CAINFO, NULL);
	return strbuf_detach(&buf, NULL);
		}
#if LIBCURL_VERSION_NUM >= 0x071301
		error("fd leakage in start: %d", freq->localfile);
#endif
		xsnprintf(curl_errorstr, sizeof(curl_errorstr),
	oidcpy(&freq->oid, oid);
			long curl_timeout;
	curl_easy_setopt(slot->curl, CURLOPT_RANGE, NULL);


	size_t size = eltsize * nmemb;
	 * We know there must be something to do, since we just added
		return 0;
		if (curl_empty_auth_enabled())
		if (http_is_verbose)
			var_override(&curl_http_proxy, getenv("HTTPS_PROXY"));
			}
int finish_http_pack_request(struct http_pack_request *preq)
	/*
		for (i = 0; i < ARRAY_SIZE(curl_deleg_levels); i++) {
	 * method more exotic than "Basic" or "Digest".
	}

	struct http_object_request *freq;
#endif
			p++;
static void curl_dump_data(const char *text, unsigned char *ptr, size_t size)
 * If a previous interrupted download is detected (i.e. a previous temporary

			if (i > 0)
static void set_curl_keepalive(CURL *c)
		allowed_protocols |= CURLPROTO_FTPS;
				strbuf_addstr(buf, ", ");
	 * just default to turning the feature off.
		*result = CURLE_HTTP_RETURNED_ERROR;
}
	if (accept_language)
			num_langs++;
		break;
}
		curl_ssl_try = git_config_bool(var, value);

		curl_easy_setopt(result, CURLOPT_SSL_CIPHER_LIST,
		if (min_curl_sessions > 1)
static void init_curl_http_auth(CURL *result)
					prev_read = -1;
{
	raw += len;
		strbuf_addstr_urlencode(&s, proxy_auth.password,
	xsnprintf(buf, sizeof(buf), "%"PRIuMAX"-", (uintmax_t)pos);
		if (i == ARRAY_SIZE(proxy_authmethods)) {
}
						&slot->http_code);
			curl_multi_fdset(curlm, &readfds, &writefds, &excfds, &max_fd);
		}
	strbuf_release(&out);
			sensitive_header++;
#include "url.h"
	struct active_request_slot *slot;
 * our code simple.

}


static int http_schannel_use_ssl_cainfo;
}
	 */
	struct packed_git **lst;
		cookie = (char *) sensitive_header;

			credential_from_url(&proxy_auth, url.buf);
	*lst = (*lst)->next;

 * new URL to become "https://other.example.com/foo.git".
	}
				select_timeout.tv_usec = 50000;
			equals = strchrnul(cookie, '=');
static void set_curl_keepalive(CURL *c)
	 * If we see a failing http code with CURLE_OK, we have turned off
	return 0; /* CURL_SOCKOPT_OK only exists since curl 7.21.5 */
		freq->localfile = -1;
	if (!cached_accept_language) {
		return -1; /* parse_pack_index() already issued error message */
	struct strbuf filename = STRBUF_INIT;
	preq->slot = NULL;
	CURLMsg *curl_message = curl_multi_info_read(curlm, &num_messages);
		if (c != CURLE_OK)

	if (((ch >= 'A') && (ch <= 'Z'))
	return freq->rename;
	return git_default_config(var, value, cb);
}
			slot = active_queue_head;
		return CURLIOE_OK;
		if (!new_pack)
	if (slot == NULL) {
	case CURLINFO_HEADER_IN:
	int ret = -1;
		} else {
						    const struct object_id *oid)
				"Resuming fetch of pack %s at byte %"PRIuMAX"\n",
			p++;
#endif
static int extract_param(const char *raw, const char *name,
#if LIBCURL_VERSION_NUM >= 0x070f04
	strbuf_init(&preq->tmpfile, 0);
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, NULL);
	curl_easy_setopt(freq->slot->curl, CURLOPT_HTTPHEADER, no_pragma_header);
			unsigned char ch = ptr[i + w];
	curl_easy_setopt(slot->curl, CURLOPT_CUSTOMREQUEST, NULL);
			while (slot->next != NULL)
	long ssl_version;

		}
#endif
{

}
			}
	int prevlocal;
	if (max_requests < 1)

			curl_dump_data(text, (unsigned char *)data, size);

		curl_ftp_no_epsv = git_config_bool(var, value);
		const char *name;
#endif
		curl_proxyuserpwd = strbuf_detach(&s, NULL);
	if (options && options->extra_headers) {
	no_pragma_header = curl_slist_append(http_copy_default_headers(),
		/* The name in the cert must match whom we tried to connect */
static int http_request(const char *url,
#ifdef CURLGSSAPI_DELEGATION_FLAG
		if (http_max_requests != NULL)
	struct strbuf tmpfile = STRBUF_INIT;
	curl_easy_setopt(result, CURLOPT_POST301, 1);
#endif
		"Pragma:");
		headers = curl_slist_append(headers, item->string);
#if LIBCURL_VERSION_NUM >= 0x071304
	} while (posn < size);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, headers);
	if (http_ssl_backend && !strcmp("schannel", http_ssl_backend) &&
}
			  "The requested URL returned error: %ld",
#ifndef USE_CURL_MULTI
		break;
#endif

				curl_easy_setopt(result, CURLOPT_PROXY_KEYPASSWD, proxy_cert_auth.password);
		curl_ftp_no_epsv = 1;
		}
	if (freq->zret != Z_STREAM_END) {
	while (*data) {
		curl_easy_setopt(result, CURLOPT_CAINFO, NULL);
		curl_easy_setopt(result, CURLOPT_PROXYUSERNAME,
#else
	CURLcode ret;
}
		return HTTP_OK;
	if (is_transport_allowed("ftp", from_user))
	if (num_transfers < active_requests) {
	preq->target = target;
	 * If there is data present from a previous transfer attempt,
#endif
	curl_easy_getinfo(slot->curl, CURLINFO_HTTP_CODE, &slot->http_code);
					prev_posn += prev_read;
	install_packed_git(the_repository, p);
	case HTTP_REQUEST_STRBUF:


#endif
		while (isspace(*p) || *p == ';')
	}
		if (needs_quote(ch))
		step_active_slots();
	/*

	struct active_request_slot *slot = active_queue_head;
{
		if (!get_curl_http_version_opt(curl_http_version, &opt)) {
}
		warning("curl_multi_add_handle failed: %s",
		}
		struct strbuf s = STRBUF_INIT;

		return ret;
#else

		return 0;
	ret = curl_easy_getinfo(curl, info, &ptr);
		if (proxy_auth.password)
		return 0;
	struct strbuf buf = STRBUF_INIT;
		slot->curl_result = curl_easy_perform(slot->curl);
	}
};

		if (!proxy_auth.password)
