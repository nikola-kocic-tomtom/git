		 * and let them request the refs themselves.
		do {
		 * and we just need to send it.
			options.followtags = 1;
		unsigned long v = strtoul(value, &end, 10);
	free(to_fetch);
	return refs;
	 */
		return 0;
	headers = curl_slist_append(headers, rpc->hdr_accept);
		rpc->protocol_header = strbuf_detach(&buf, NULL);
 * from ptr.
		return 0;
	free_discovery(last);
		if (options.verbosity > 1) {
	fflush(stdout);
		argv_array_push(&args, "--atomic");
	return err;

		free_refs(d->refs);

}
		return 0;
			     enum packet_read_status *status) {
		} while (err == HTTP_REAUTH);
	walker->get_progress = options.progress;
		return 0;
			return -1;
		free(u);
			if (!result)
	argv_array_push(&args, options.progress ? "--progress" : "--no-progress");
	struct curl_slist *headers = http_copy_default_headers();

		/* The client backend isn't giving us compressed data so
	int in;
	argv_array_push(&child.args, "http-push");
	walker_free(walker);
				value = "true";
{
	char *hdr_content_type;
		heads = discover_refs("git-upload-pack", for_push);
			options.update_shallow = 1;
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, headers);
	/*
		strbuf_addf(&refs_url, "service=%s", service);
	if (!http_fetch_ref(url.buf, ref) &&
			BUG("The entire rpc->buf should be larger than LARGE_PACKET_MAX");
		if (!strcmp(value, "true"))
		targets[i] = xstrdup(oid_to_hex(&to_fetch[i]->old_oid));
	int i, err;
	struct http_get_options http_options;
		buf = rpc->buf + rpc->len;
	if (maybe_smart)

	struct string_list extra_headers = STRING_LIST_INIT_DUP;

	}
{
			if (nongit)
#include "oid-array.h"
		 * capability advertisement.  Client would have run

	struct walker *walker;
		 */
	struct active_request_slot *slot;
		if (rpc->initial_buffer) {

			fprintf(stderr, "POST %s (%lu bytes)\n",
	 * If we don't see x-$service-advertisement, then it's not smart-http.
		else if (!strcmp(value, "false"))

			else
	if (options.depth || options.deepen_since)
	headers = curl_slist_append(headers, needs_100_continue ?

			if (status == PACKET_READ_FLUSH)
	curl_easy_setopt(slot->curl, CURLOPT_FAILONERROR, 0);
	rpc->service_url = strbuf_detach(&buf, NULL);

	}
	if (rpc_result.len)

				break;
			oidcpy(&ref->old_oid, &old_oid);
			get_oid_hex(start, &ref->old_oid);

		 * run will have set up the headers and gzip buffer already,
	}
		options.filter = xstrdup(value);
	close(client.in);
		free(d->buf_alloc);
		}
	}
			printf("check-connectivity\n");
		else
		else if (!strcmp(value, "false"))
	if (large_request) {
		buf = rpc->buf + rpc->len + 4;
		"Expect: 100-continue" : "Expect:");

		else if (!strcmp(value, "false"))
		 * full request but have not fully sent it + EOF, which is why
		 * v2 smart http; do not consume version packet, which will
	free(rpc.protocol_header);
static void parse_fetch(struct strbuf *buf)
			    version);
			if (reader.pktlen <= 0) {
		if (!strcmp(value, "true"))
#include "cache.h"
		for (;;) {
	http_ret = http_get_strbuf(refs_url.buf, &buffer, &http_options);

/*
		data->rpc->any_written = 1;
		git_zstream stream;
static int rpc_read_from_out(struct rpc_state *rpc, int options,
	client.in = -1;
		 */
	}
	struct strbuf protocol_header = STRBUF_INIT;
	else if (!strcmp(name, "cas")) {
	while (i < heads->len) {

	int err;
	case protocol_v1:

			fprintf(stderr, "POST %s (chunked)\n", rpc->service_name);
static int push(int nr_spec, const char **specs)
	strbuf_release(&preamble);
	strbuf_release(&type);
	rpc.flush_read_but_not_sent = 0;
	struct strbuf effective_url = STRBUF_INIT;

	if (for_push)
				name = q + 1;
			      &response_code) != CURLE_OK)
			options.push_cert = SEND_PACK_PUSH_CERT_NEVER;
		    transport_anonymize_url(url.buf));
	if (argc < 2) {

	strbuf_trim(msg);

	 * v2.  If and only if the server supports v2 can we successfully
		error(_("RPC failed; %s"), msg.buf);
	rpc->hdr_accept = strbuf_detach(&buf, NULL);
		 * We must use chunked encoding to send it.
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, headers);
	int out;
		return 0;

	/*
	struct strbuf buffer = STRBUF_INIT;
			result = set_option(arg, value);
		argv_array_push(&args, cas_option->string);
	struct discovery *discover;
{
		/* One of the SEND_PACK_PUSH_CERT_* constants. */
	strbuf_release(&rpc_result);
	return err;
	rpc->buf = xmalloc(rpc->alloc);
	mid = data;

#endif
	case protocol_v2:
	rpc.hdr_accept = xstrfmt("Accept: application/x-%s-result", rpc.service_name);
		enum packet_read_status status;
		rpc->initial_buffer = 1;
		die(_("dumb http transport does not support shallow capabilities"));

static int show_http_message(struct strbuf *type, struct strbuf *charset,
				rpc->service_name, (unsigned long)rpc->len);
	rpc.service_name = "git-receive-pack",
			size_t n;
{
			printf("stateless-connect\n");
	options.thin = 1;
			string_list_append_nodup(&options.push_options,
	if (options.filter)

	 */
		 */
			return 0;
{
			options.dry_run = 1;
		*appended = pktlen_raw + (rpc->write_line_lengths ? 4 : 0);
		if (results.auth_avail & CURLAUTH_GSSNEGOTIATE)
		push_cert : 2,
			     size_t *appended,
		no_dependents : 1,
	argv_array_clear(&args);
	struct strbuf rpc_result = STRBUF_INIT;
	err = run_slot(slot, NULL);
				strbuf_addch(&msg, ' ');
	write_or_die(rpc.in, discover->buf, discover->len);

	 * the end of a request, each flush must be completely sent before any
	char *protocol_header;

	size_t size = eltsize * nmemb;

	struct strbuf rpc_result = STRBUF_INIT;



		argv_array_push(&child.args, "--verbose");
		if (post_rpc(&rpc, status == PACKET_READ_FLUSH))
		fprintf(stderr, "remote: %.*s\n", (int)(eol - p), p);
	if (options.atomic)

	for (i = 0; i < nr_heads; i++) {
#include "run-command.h"
	rpc->alloc = http_post_buffer;

				 NULL, &heads->shallow);

		} else if (!strcmp(buf.buf, "list") || starts_with(buf.buf, "list ")) {
		d->proto_git = 1;
		char buf[4096];
		strbuf_release(&val);
	} else if (use_gzip && 1024 < rpc->len) {
		ret = push_git(heads, nr_spec, specs);
	ref = alloc_ref("HEAD");


	/* Until we see EOF keep sending POSTs */
		left = rpc->alloc - rpc->len;
		end_url_with_slash(&url, argv[2]);
/*
		get_remote_heads(&reader, &list, for_push ? REF_NORMAL : 0,
	/* Add the extra Git-Protocol header */
	const char *service_name;
	}
static size_t rpc_out(void *ptr, size_t eltsize,
	else if (options.push_cert == SEND_PACK_PUSH_CERT_IF_ASKED)
		string_list_append(&options.deepen_not, value);
{
		maybe_smart = 1;
		argv_array_push(&args, "--deepen-relative");
			packet_reader_read(&reader);


		}
		else
	free(rpc.hdr_accept);
		argv_array_pushl(&args, "-v", "-v", NULL);
			fflush(stderr);
		argv_array_push(&args, "--signed=yes");
		strbuf_addf(header, GIT_PROTOCOL_HEADER ": version=%d",

			break;
		argv_array_push(&args, "--from-promisor");
	curl_slist_free_all(headers);
			strbuf_addch(&refs_url, '?');
		if (!strcmp(value, "ipv4"))
		rpc.protocol_header = strbuf_detach(&buf, NULL);
				break;

	} else if (!strcmp(name, "family")) {
		struct strbuf msg = STRBUF_INIT;
				die(_("invalid quoting in push-option value: '%s'"), value);
	if (start_command(&client))
static struct ref *get_refs(int for_push)
	long response_code;
		else
	slot = get_active_slot();

				    transport_anonymize_url(url.buf));
		case PACKET_READ_DELIM:
		eol = strchrnul(p, '\n');
		printf("\n");
			die(_("http transport does not support %s"), buf->buf);
	 * client to fallback to using other transport helper functions to
	struct active_request_slot *slot;

	int ret;
			if (!rpc_read_from_out(rpc, 0, &n, &status)) {
	 */
{
	heads->version = discover_version(&reader);
	int pktlen_raw;
		check_self_contained_and_connected : 1,
	struct strbuf type = STRBUF_INIT;
		options.deepen_since = xstrdup(value);
	size_t max = eltsize * nmemb;
		else
		return 0;
	client.argv = client_argv;
		 */
	int nongit;
static int get_protocol_http_header(enum protocol_version version,
static struct discovery *discover_refs(const char *service, int for_push)
		/*
		else
		argv_array_push(&args, "--signed=if-asked");
	free(targets);
		if (strbuf_getline_lf(buf, stdin) == EOF)
	size_t i;
		from_promisor : 1,
			return -1;

	} else if (!strcmp(reader.line, "version 2")) {

	http_options.charset = &charset;
	if (rpc->write_line_lengths) {
	/* Add the extra Git-Protocol header */
		if (!start) {
			ref = alloc_ref(ref_name);
			strbuf_addf(&msg, "curl %d", results->curl_result);
		 * If flush_read_but_not_sent is true, we have already read one
	case protocol_v0:
	options.verbosity = 1;

		die(_("invalid server response; got '%s'"), reader.line);
		else if (!strcmp(value, "false"))
	struct ref *posn;
	    !resolve_remote_symref(ref, refs)) {
	size_t len;

	 * Dump the capability listing that we got from the server earlier
}

		argv_array_push(&args, "--quiet");
	for (posn = refs; posn; posn = posn->next) {
	rpc.service_url = xstrfmt("%s%s", url.buf, rpc.service_name);
			argv_array_push(&specs, arg);

		rpc->initial_buffer = 0;
		return -1;
	return list;
#include "argv-array.h"
	argv_array_clear(&specs);
	}
	else
		 */
		write_or_die(1, rpc_result.buf, rpc_result.len);
static int run_slot(struct active_request_slot *slot,
};
static void output_refs(struct ref *refs)
	rpc.any_written = 0;
		 * The header can include additional metadata lines, up
		argv_array_push(&args, "--update-shallow");
		options.no_dependents = 1;
		else


		 * the transfer time.
		if (skip_prefix(buf->buf, "fetch ", &p)) {
			}
		warning(_("redirecting to %s"), u);
		if (!strcmp(value, "true"))
	if (large_request) {
	/*
static int set_option(const char *name, const char *value)
	size_t alloc;
	case HTTP_MISSING_TARGET:
	http_options.base_url = &url;
			const char *name;
			else
			return 1;
		}
		results = &results_buf;
		}
			const char *q;
		strbuf_reencode(msg, charset->buf, get_log_output_encoding());
	}
		BUG("unknown protocol version");

			fprintf(stderr, "POST %s (gzip %lu to %lu bytes)\n",
	err |= finish_command(&client);
			int result;
		die(_("unable to access '%s': %s"),
	memcpy(ptr, rpc->buf + rpc->pos, avail);

			break;
		gzip_body = xmalloc(gzip_size);

	}
		else if (!strcmp(value, "false"))
	*status = packet_read_with_status(rpc->out, NULL, NULL, buf,
			set_packet_header(buf - 4, *appended);
		struct strbuf val = STRBUF_INIT;
		argv_array_push(&args, "--thin");

#include "string-list.h"
	rpc->out = client.out;
		string_list_append(&cas_options, val.buf);
{
	case CURLIOCMD_RESTARTREAD:
}
			 */
	 * during the info/refs request.
	} else if (gzip_body) {
	}
	http_options.no_cache = 1;

		strbuf_release(&buf);
	if (!flush_received) {
		strbuf_read(rpc_result, client.out, 0);
			memcpy(buf - 4, "0001", 4);
	 * true) and EOF have not been sent to libcurl. Since each flush marks
	if (options.followtags)
	struct rpc_state *rpc;
		if (strbuf_getline_lf(buf, stdin) == EOF)
		else {
	struct argv_array args;


		headers = curl_slist_append(headers, "Transfer-Encoding: chunked");
		if (status == PACKET_READ_EOF)
		ref->next = refs;
		else if (!strcmp(value, "false"))
 */
		argv_array_push(&args, "--include-tag");
{
			parse_push(&buf);
	}
		/*

	if (ret)
	if (options.deepen_since)
	if (last && !strcmp(service, last->service))
}
	rpc.len = 0;
			 * The line length either does not need to be sent at
		else
				error(_("remote-curl: error reading command stream from git"));
		curl_easy_setopt(slot->curl, CURLOPT_READFUNCTION, rpc_out);
}

	struct ref *refs = NULL;
		 * until a packet flush marker.  Ignore these now, but
		 * hasn't been fully sent. Proceed with sending the line
	if (get_protocol_http_header(heads->version, &buf))
		argv_array_push(&child.args, specs[i]);
	curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDS, "0000");
{


		} else if (skip_prefix(buf.buf, "stateless-connect ", &arg)) {
			return -1;
	struct slot_results results_buf;
	default:
	struct string_list deepen_not;
				    struct strbuf *header)
	} else if (!strcmp(name, "atomic")) {
		headers = curl_slist_append(headers, "Content-Encoding: gzip");
	if (options.check_self_contained_and_connected)

		else
	do {
		last->refs = parse_info_refs(last);
	err = rpc_service(&rpc, heads, args.argv, &preamble, &rpc_result);
	curl_easy_setopt(slot->curl, CURLOPT_URL, rpc->service_url);
		rpc.protocol_header = NULL;
	size_t left;
		}
			fflush(stderr);
			if (curl_errorstr[0]) {
	} else {
		argv_array_push(&args, "--check-self-contained-and-connected");
	ALLOC_ARRAY(targets, nr_heads);
	}


	if (size)
			ALLOC_GROW(to_fetch, nr_heads + 1, alloc_heads);
	for (i = 0; i < options.deepen_not.nr; i++)
	curl_easy_setopt(slot->curl, CURLOPT_POST, 1);
			list = &ref->next;
		rpc->len = n;
		case PACKET_READ_EOF:
	if (!strcmp(name, "verbosity")) {
	else
		write_or_die(1, rpc_result.buf, rpc_result.len);
		gzip_size = stream.total_out;
	} else {
			memcpy(buf - 4, "0000", 4);
	 */
			break;
		if (options.verbosity > 1) {
	struct ref *ref = NULL;
		ret = git_deflate(&stream, Z_FINISH);
	}

		struct ref *ref = to_fetch[i];
	}
struct options {
	rpc.service_name = service_name;
			return 1;
	unsigned gzip_request : 1;


			printf("\n");
			   PACKET_READ_CHOMP_NEWLINE |
struct discovery {
#include "remote.h"
	free(rpc->protocol_header);
		left = rpc->alloc - rpc->len - 4;
			last_discovery = NULL;
	char *buf;
	} else if (!strcmp(name, "cloning")) {
	char *service_url;
	}
		 * Do nothing.  This isn't a list of refs but rather a
	for (i = 0; i < nr_heads; i++)
		rpc->pos = 0;
			options.deepen_relative = 1;
		if (options.verbosity > 1) {
	struct string_list push_options;
	struct strbuf buf = STRBUF_INIT;
struct rpc_state {
				break;
 * hexadecimal string before appending the result described above.
		break;
				rpc->flush_read_but_not_sent = 1;

		if (value == end || *end)
		if (!strcmp(value, "true"))
		curl_easy_setopt(slot->curl, CURLOPT_INFILE, rpc);
			options.push_cert = SEND_PACK_PUSH_CERT_IF_ASKED;
		printf("fallback\n");
	if (options.deepen_relative && options.depth)
		 * more normal Content-Length approach.
			char *value = strchr(arg, ' ');
}
			int for_push = !!strstr(buf.buf + 4, "for-push");
	 * are all just copies of the same actual executable.
	char *buf;
			if (err == HTTP_REAUTH)
	size_t gzip_size = 0;
	packet_buf_flush(&preamble);
		/* The request body is large and the size cannot be predicted.
	printf("\n");
	child.git_cmd = 1;
		error(_("unable to rewind rpc post data - try increasing http.postBuffer"));
	struct discovery *d = discover_refs("git-upload-pack", 0);
	options.progress = !!isatty(2);
		char *end;
		if (!strcmp(value, "true"))
			output_refs(get_refs(for_push));
	err = rpc_service(&rpc, heads, args.argv, &preamble, &rpc_result);
		if (!strcmp(value, "true"))
	client.in = -1;
				printf("unsupported\n");
#endif /* LIBCURL_VERSION_NUM >= 0x070a08 */
		 * in the future we might start to scan them.
}
	argv_array_push(&child.args, "--helper-status");
	int use_gzip = rpc->gzip_request;
	rpc.buf = xmalloc(http_post_buffer);
	} else {

	char *service;

		credential_fill(&http_auth);
		ret = push_dav(nr_spec, specs);
	unsigned proto_git : 1;
}
	if (rpc->protocol_header)
	memset(&http_options, 0, sizeof(http_options));
			mid = &data[i];
		 * v0 smart http; callers expect us to soak up the
	int ret, i;
		return 0;
		/*
	rpc.alloc = http_post_buffer;

	struct strbuf buf = STRBUF_INIT;

		       struct strbuf *rpc_result)

			struct strbuf unquoted = STRBUF_INIT;

			 NULL);
	struct child_process child = CHILD_PROCESS_INIT;
						 strbuf_detach(&unquoted, NULL));


	 * allocated buffer space we can use HTTP/1.0 and avoid the
	char *deepen_since;
}
	rpc->in = client.in;
			   PACKET_READ_DIE_ON_ERR_PACKET);
	rpc.service_name = "git-upload-pack",
		       const char **client_argv, const struct strbuf *preamble,
	free(rpc->hdr_accept);

	enum packet_read_status status;
		}
		last->refs = parse_git_refs(last, for_push);
		curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDS, gzip_body);
	} else {
	return 1;
	 * We only show text/plain parts, as other types are likely
				die(_("shouldn't have EOF when not gentle on EOF"));
			break;
	strbuf_release(&effective_url);
		d->buf = reader.src_buffer;

	free(rpc.hdr_content_type);
		curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDSIZE_LARGE, xcurl_off_t(gzip_size));
		}
	trace2_cmd_name("remote-curl");
	if (!err) {
	struct rpc_in_data rpc_in_data;
	if (!rpc->any_written)

	if (rpc->flush_read_but_not_sent) {
	strbuf_release(&rpc_result);
		if (starts_with(buf.buf, "fetch ")) {
	http_init(remote, url.buf, 0);
		const char *p;
		else if (!strcmp(value, "false"))
 * enough space, 0 otherwise.
		}
	if (options.dry_run)
		show_http_message(&type, &charset, &buffer);
#include "protocol.h"
};
		return 0;
};
		if (strbuf_getline_lf(&buf, stdin) == EOF) {
	else if (!strcmp(name, "check-connectivity")) {
	 * NEEDSWORK: If we are trying to use protocol v2 and we are planning
		argv_array_push(&args, "--no-dependents");
			goto free_specs;
		curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDSIZE_LARGE, xcurl_off_t(gzip_size));
#include "send-pack.h"

	struct strbuf buf = STRBUF_INIT;
		return last;
	return (curl_off_t)size;
	return err;
		die(_("repository '%s' not found"),

	else if (!strcmp(name, "dry-run")) {


	}
			else if (result < 0)

{
				use_gzip = 0;
			if (!stateless_connect(arg))
	last->service = xstrdup(service);
	char **targets;

static struct remote *remote;

			struct ref *ref;
			if (value)

	p = msg->buf;
		die(_("cannot handle pushes this big"));
	argv_array_push(&args, url.buf);
	argv_array_init(&args);
		return CURLIOE_FAILRESTART;
		if (data[i] == '\n') {
				rpc->service_name,
#include "config.h"
		return fetch_dumb(nr_heads, to_fetch);
			if (xread(client.out, buf, sizeof(buf)) <= 0)
	return last;
			if (msg.len)
	return 0;
		return 1;
				credential_fill(&http_auth);
		strbuf_reset(buf);
			fflush(stdout);
			parse_fetch(&buf);
		argv_array_pushf(&args, "--push-option=%s",
			die(_("cannot deflate request; zlib end error %d"), ret);
	return ret ? error(_("fetch failed.")) : 0;
		size_t nmemb, void *buffer_)

	char *data, *start, *mid;

		stream.next_out = (unsigned char *)gzip_body;

		return 0;
	unsigned progress : 1,
	return heads->refs;
	if (options.verbosity && !starts_with(refs_url.buf, url.buf)) {
		break;
}
		exit(128); /* error already reported */
	client.out = -1;
 * A callback for CURLOPT_WRITEFUNCTION. The return value is the bytes consumed
{
	curl_easy_setopt(slot->curl, CURLOPT_URL, rpc->service_url);

	http_options.extra_headers = &extra_headers;
		free(ref);

	headers = curl_slist_append(headers, rpc->hdr_accept);
	}

		argv_array_push(&args, "--cloning");
		 * be handled elsewhere.
	printf("\n");
	size_t avail = rpc->len - rpc->pos;
		if (skip_prefix(buf->buf, "push ", &arg))
	strbuf_release(&buf);
	for (i = 0; i < nr_heads; i++)
	struct rpc_state rpc;

	struct argv_array args = ARGV_ARRAY_INIT;
}
		curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDS, rpc->buf);
		free(d);

		}
			printf("option\n");
	for (i = 0; i < options.push_options.nr; i++)
	enum protocol_version version;
static struct options options;
		string_list_append(&extra_headers, protocol_header.buf);
	int needs_100_continue = 0;

	slot = get_active_slot();
		argv_array_pushf(&args, "--shallow-since=%s", options.deepen_since);
			else if (!*q)
	if (options.push_cert == SEND_PACK_PUSH_CERT_ALWAYS)
static int rpc_service(struct rpc_state *rpc, struct discovery *heads,
struct rpc_in_data {
	if (options.verbosity > 1)
		return 0;
	/*
		else
		else if (!strcmp(value, "if-asked"))

	} else {
#if LIBCURL_VERSION_NUM >= 0x070a08

 */
	last= xcalloc(1, sizeof(*last_discovery));
	const char *p;
	} while (1);
	int err, large_request = 0;
		return -1;
				strbuf_addstr(&msg, curl_errorstr);

			break;
static int push_git(struct discovery *heads, int nr_spec, const char **specs)
	size_t len;
		atomic : 1;
				BUG("The entire rpc->buf should be larger than LARGE_PACKET_MAX");
	return 0;
	if (heads)
			options.cloning = 1;
	if (d) {

		else
		const char *arg;
	return ret;
	rpc->pos += avail;
	char *ref_name;
			if (last_ref)
#include "strbuf.h"
			break;
}
		packet_buf_write(&preamble, "%s\n", specs[i]);
	return 0;
	} else if (!strcmp(name, "filter")) {

		fflush(stdout);
	memset(&rpc, 0, sizeof(rpc));
	rpc_in_data.rpc = rpc;
	switch (heads->version) {
	struct packet_reader reader;
	unsigned long depth;
	strbuf_addf(&buf, "Accept: application/x-%s-result", svc);
	}
	struct ref *refs;
}
		stream.avail_in = rpc->len;
			   PACKET_READ_GENTLE_ON_EOF |



	} else {
			strbuf_addf(&msg, "HTTP %ld", results->http_code);
		if (!strcmp(value, "true"))
}
		show_http_message(&type, &charset, &buffer);
		argv_array_pushf(&args, "--shallow-exclude=%s",
static int push_dav(int nr_spec, const char **specs)
		return 0;
	rpc.out = 0;
			needs_100_continue = 1;
	struct child_process client = CHILD_PROCESS_INIT;
	struct ref *list = NULL;
}
	}
	/*
			printf("@%s %s\n", posn->symref, posn->name);
		die(_("Authentication failed for '%s'"),
	if (options.update_shallow)
				die(_("remote-curl: fetch attempted without a local repo"));
{
			options.progress = 0;
				 options.push_options.items[i].string);

	if (!skip_prefix(type->buf, "application/x-", &p) ||
	 * to perform a push, then fallback to v0 since the client doesn't know
			fflush(stdout);
	     git_env_bool("GIT_SMART_HTTP", 1)) {
	strbuf_release(&refs_url);
			return -1;
			if (!(options & PACKET_READ_GENTLE_ON_EOF))
	for (i = 0; i < nr_spec; i++)
			return -1;
			if (unquote_c_style(&unquoted, value, NULL) < 0)
 free_specs:
		return 0;

{
			}
	while (1) {
	strbuf_addf(&buf, "%s%s", url.buf, svc);
	int alloc_heads = 0, nr_heads = 0;
		if (!rpc->flush_read_but_not_sent) {
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &rpc_in_data);
{
		error(_("remote-curl: usage: git remote-curl <remote> [<url>]"));
		strbuf_reset(&buf);
{
	return size;
{
	struct active_request_slot *slot;
	}
			options.followtags = 0;
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &buf);
			     struct strbuf *msg)
	argv_array_pushl(&args, "send-pack", "--stateless-rpc", "--helper-status",
}

	if (strcmp(type->buf, "text/plain"))
			data[i] = 0;
	curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDSIZE, 4);
}
	packet_buf_flush(&preamble);
	unsigned initial_buffer : 1;

static curl_off_t xcurl_off_t(size_t len)
		if (!avail) {
static struct discovery *last_discovery;
		return 0;

		err |= post_rpc(rpc, 0);
	curl_easy_setopt(slot->curl, CURLOPT_POST, 1);
 */
	memset(&rpc, 0, sizeof(rpc));
	if (!msg->len)
	rpc.gzip_request = 1;
		}
#include "connect.h"

	client.out = -1;
 * If flush_received is true, do not attempt to read any more; just use what's

		if (posn->symref)
		return 1 /* unsupported */;
	argv_array_push(&child.args, url.buf);
	rpc->hdr_content_type = strbuf_detach(&buf, NULL);

	} else {
}
	if (discover->version != protocol_v2) {
		argv_array_push(&args, "--thin");
	int verbosity;
			   PACKET_READ_CHOMP_NEWLINE |

				 oid_to_hex(&ref->old_oid), ref->name);
		else if (!strcmp(value, "ipv6"))
	/*
	if (size > maximum_signed_value_of_type(curl_off_t))
	if (options.thin)

		cloning : 1,
#include "http.h"
		else if (!strcmp(value, "false"))
			return -1;


		 * length.
		gzip_size = git_deflate_bound(&stream, rpc->len);
	}
		return size;
		argv_array_pushf(&args, "--filter=%s", options.filter);
				(unsigned long)rpc->len, (unsigned long)gzip_size);
 * in rpc->buf.
	ret = walker_fetch(walker, nr_heads, targets, NULL, NULL);
		else if (!strcmp(value, "all"))
}
}
			options.push_cert = SEND_PACK_PUSH_CERT_ALWAYS;
		write_or_die(client.in, heads->buf, heads->len);
			return;
			     struct strbuf *type)
};
			options.atomic = 1;
	if (options.no_dependents)
	printf("\n");
		/* We know the complete request size in advance, use the
			if (parse_oid_hex(p, &old_oid, &q))

		strbuf_reset(buf);
		if (!rpc_read_from_out(&rpc, PACKET_READ_GENTLE_ON_EOF, &avail,
	free(rpc->service_url);
	case HTTP_NOAUTH:
	last_discovery = last;
			err = probe_rpc(rpc, &results);

		avail = max;


		char *u = transport_anonymize_url(url.buf);
		} else if (skip_prefix(buf.buf, "option ", &arg)) {
	close(client.out);
	if (max < avail)
	struct discovery *heads;
 * Writes the total number of bytes appended into appended.
	if (last->proto_git)
			to_fetch[nr_heads++] = ref;
		return;
	struct ref *list_head = NULL;
	data = heads->buf;
	if (err == HTTP_REAUTH && !large_request) {

	}
}
/* always ends with a trailing slash */
		if (value == end || *end)
			struct object_id old_oid;
	}
#include "credential.h"
	}
				printf("error invalid value\n");
	int err = 0;
		} else {
			start = &data[i];
		rpc->len = 0;
	}
		/* Stateless Connection established */
{
		/*
		}
	do {


	http_options.content_type = &type;
	fflush(stdout);
	curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 0);
		char *end;
	struct ref **to_fetch = NULL;
	write_or_die(data->rpc->in, ptr, size);
	else
	struct strbuf charset = STRBUF_INIT;


	if (rpc_result.len)
				die(_("%sinfo/refs not valid: is this a git repository?"),
	return 0;
	struct discovery *last = last_discovery;
		    struct slot_results *results)
		refs = ref;
			left, &pktlen_raw, options);
	int any_written;
		size_t avail;
		return 0;

	} while (1);
		 */
		/*
	 * Used by rpc_out; initialize to 0. This is true if a flush has been

{
	struct packet_reader reader;
retry:
		curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDSIZE_LARGE, xcurl_off_t(rpc->len));
			die(_("cannot deflate request; zlib deflate error %d"), ret);
	else
		return 0;
}
			if (!rpc_read_from_out(rpc, 0, &avail, &status))
	int nr_heads, struct ref **to_fetch)
	struct curl_slist *headers = http_copy_default_headers();

		 * 'stateless-connect' so we'll dump this capability listing
	char *buf_alloc;
	rpc.pos = 0;
	}
	} else if (!strcmp(name, "push-option")) {
	strbuf_release(&buffer);
		die(_("git-http-push failed"));
	do {
static int probe_rpc(struct rpc_state *rpc, struct slot_results *results)
			return -1;
			error(_("remote-curl: unknown command '%s' from git"), buf.buf);
	rpc.gzip_request = 1;
		argv_array_push(&child.args, "--dry-run");
			options.deepen_relative = 0;

		free(targets[i]);

	struct ref *last_ref = NULL;
 * If rpc->write_line_lengths is true, appends the line length as a 4-byte
	else if (!strcmp(name, "depth")) {
	if (d->proto_git)
	argv_array_pushl(&args, "fetch-pack", "--stateless-rpc",
	 * denoting its length before appending the payload.
	 * Run the info/refs request and see if the server supports protocol
	if (options.verbosity == 0)
	strbuf_release(&buf);
	return err;
{
			break;
	http_options.effective_url = &effective_url;
		rpc->len += *appended;
	err = run_slot(slot, results);
		rpc->pos = 0;
		if (ret != Z_STREAM_END)
	/*

		 * service and header packets
	struct strbuf buf = STRBUF_INIT;
		return CURLIOE_OK;
			break;
		return size;
		 * If avail is non-zerp, the line length for the flush still
			 "--stdin", "--lock-pack", NULL);
		case PACKET_READ_NORMAL:
		else
		}
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_buffer);
		argv_array_pushf(&args, "--depth=%lu", options.depth);
#ifndef NO_CURL_IOCTL
	argv_array_push(&args, url.buf);
		if (!n)
		exit(128); /* error already reported */
	else if (!strcmp(name, "deepen-relative")) {
	struct rpc_in_data *data = buffer_;
	if (get_protocol_http_header(discover->version, &buf)) {
			options.progress = 1;
		strbuf_release(&msg);
	if (response_code >= 300)
	char *filter;
		stream.next_in = (unsigned char *)rpc->buf;
	strbuf_addf(&buf, "Content-Type: application/x-%s-request", svc);

	curl_easy_setopt(slot->curl, CURLOPT_ENCODING, "");
		if (!*buf->buf)
				last_ref->next = ref;

	if (options.from_promisor)

	rpc_in_data.slot = slot;
		case PACKET_READ_FLUSH:
	else
{
	switch (cmd) {
	} while (1);
		int ret;
 * rpc->buf and rpc->len if there is enough space. Returns 1 if there was
static size_t rpc_in(char *ptr, size_t eltsize,
	const char *svc = rpc->service_name;
		return -1;

			die(_("cannot fetch by sha1 over smart http"));
{
			die(_("http transport does not support %s"), buf->buf);
			return -1;
	if (err != HTTP_OK && err != HTTP_REAUTH) {
	err = run_one_slot(slot, results);
	 */
			*list = ref;
		else
	char *buf;
		packet_buf_write(&preamble, "%s %s\n",
	} while(*eol);

	last->buf = last->buf_alloc;
		curl_easy_setopt(slot->curl, CURLOPT_IOCTLDATA, rpc);
			printf("fetch\n");

	 * to be ugly to look at on the user's terminal.
}
		if (*value != '"')
#include "pkt-line.h"
			fflush(stderr);
		/*
		update_shallow : 1,
	if (options.verbosity >= 3)
	if (rpc->write_line_lengths) {
		err = -1;
				 options.deepen_not.items[i].string);
		return 0;
	return err;
static void parse_push(struct strbuf *buf)

	char *hdr_accept;
		err = -1;
	if (options.cloning)
				name = "";
		if (err != HTTP_OK)
			break;
			options.cloning = 0;
		argv_array_push(&args, "--dry-run");
{


		fflush(stdout);
	default:
{
		show_http_message(&type, &charset, &buffer);

			ref_name = mid + 1;
	 * chunked encoding mess.
#endif
			rpc->flush_read_but_not_sent = 0;
		 * we can try to deflate it ourselves, this may save on
		version = protocol_v0;
	 */
	argv_array_push(&args, "--stdin");
	}
		if (results->http_code && results->http_code != 200)
		else
#include "sideband.h"
	free(gzip_body);
		size_t nmemb, void *buffer_)
	    strcmp(p, "-advertisement"))
	if (options.depth)
	struct argv_array specs = ARGV_ARRAY_INIT;
	} else {
	strbuf_release(&preamble);

				*value++ = '\0';

	free_discovery(heads);
		break;
#include "transport.h"
	 */
	struct strbuf refs_url = STRBUF_INIT;
		if (buf.len == 0)
		d->proto_git = 1;
			if (status == PACKET_READ_FLUSH)
	strbuf_release(&buf);
	if (version == protocol_v2 && !strcmp("git-receive-pack", service))
		deepen_relative : 1,
		free(d->shallow.oid);

	start = NULL;
	strbuf_release(&charset);
	discover = discover_refs(service_name, 0);
		return 0;
	free(rpc->buf);

static void check_smart_http(struct discovery *d, const char *service,
		stream.avail_out = gzip_size;
			options.atomic = 0;
		followtags : 1,

		options.depth = v;

	else if (!strcmp(name, "deepen-not")) {
	 * But once we do, we commit to it and assume any other protocol
	setup_git_directory_gently(&nongit);
		return 0;
	if (charset->len)
	string_list_clear(&extra_headers, 0);
	}
static int fetch_git(struct discovery *heads,
		}
	/*

	argv_array_clear(&args);
static struct ref *parse_info_refs(struct discovery *heads)
	struct rpc_state rpc;


			 * return 0, indicating EOF, meaning that the flush has
			return CURLIOE_OK;
		curl_easy_setopt(slot->curl, CURLOPT_POSTFIELDS, gzip_body);
		end_url_with_slash(&url, remote->url[0]);
		return CURLIOE_UNKNOWNCMD;
	curl_slist_free_all(headers);
	struct strbuf preamble = STRBUF_INIT;
		 * we need to refrain from reading.
	while (!err) {
	case CURLIOCMD_NOP:
	else if (!strcmp(name, "deepen-since")) {
	 */
			else
			 * been fully sent.
		} else if (starts_with(buf.buf, "push ")) {
		while (1) {
static struct string_list cas_options = STRING_LIST_INIT_DUP;
 *
			printf("push\n");

	char *gzip_body = NULL;
		return 1;
	 * ("git-remote-http", "git-remote-https", and etc.) here since they
	if (!avail) {
static curlioerr rpc_ioctl(CURL *handle, int cmd, void *clientp)
		exit(1);
		}
	curl_easy_setopt(slot->curl, CURLOPT_ENCODING, NULL);
	 * Just report "remote-curl" here (folding all the various aliases

	write_or_die(client.in, preamble->buf, preamble->len);
	}
	packet_reader_init(&reader, -1, d->buf, d->len,
		if (results->curl_result != CURLE_OK) {
		else if (!strcmp(value, "false"))
	if (!options.progress)
			if (*q == ' ')
	case protocol_unknown_version:
 * Appends the result of reading from rpc->out to the string represented by
	} else if (!strcmp(name, "pushcert")) {
			/*
	 * establish a stateless connection, otherwise we need to tell the
	}
	}
	if (options.thin)
	unsigned write_line_lengths : 1;
	if (argc > 2) {
			return -1;
		/* Reset the buffer for next request */
	}
			git_curl_ipresolve = CURL_IPRESOLVE_WHATEVER;
		int v = strtol(value, &end, 10);
		 */
/*
			if (!refs)
		/*
		const char *arg;
	headers = curl_slist_append(headers, rpc->hdr_content_type);
	if (fetch(nr_heads, to_fetch))

static int fetch(int nr_heads, struct ref **to_fetch)
			strbuf_addch(&refs_url, '&');
		 */
	return 0;
	int i = 0;
static int post_rpc(struct rpc_state *rpc, int flush_received)
				refs = ref;
			return -1;
	if (err != HTTP_OK)

	for (i = 0; i < nr_spec; i++)
	if (run_command(&child))


		 * If we are looping to retry authentication, then the previous
	walker->get_verbosely = options.verbosity >= 3;
	walker = get_http_walker(url.buf);
		die(_("invalid server response; expected service, got flush packet"));
	return avail;
}

	size_t pos;
			options.check_self_contained_and_connected = 0;
	http_options.initial_request = 1;
#include "exec-cmd.h"
#include "quote.h"
	else if (!strcmp(name, "progress")) {
			last_ref = ref;
		return 0;
		strbuf_addf(&val, "--" CAS_OPT_NAME "=%s", value);
			string_list_append(&options.push_options, value);
	if (heads->proto_git)
		heads = discover_refs("git-receive-pack", for_push);
	case HTTP_OK:
	else if (!strcmp(name, "followtags")) {
	 * how to push yet using v2.

	free_refs(list_head);
	 */
		if (ret != Z_OK)
	enum protocol_version version = get_protocol_version_config();
	struct rpc_state rpc;
	if (curl_easy_getinfo(data->slot->curl, CURLINFO_RESPONSE_CODE,
	rpc->any_written = 0;

				die(_("protocol error: expected sha/ref, got '%s'"), p);
	}
	rpc.initial_buffer = 0;
				break;
		rpc.len = 0;
	int i, err;
	int ret;
	uintmax_t size = len;
	if (get_protocol_http_header(version, &protocol_header))
}
	packet_reader_init(&reader, -1, heads->buf, heads->len,
	struct rpc_state *rpc = clientp;
		if (d == last_discovery)
			options.update_shallow = 0;
static struct strbuf url = STRBUF_INIT;
			options.check_self_contained_and_connected = 1;
static int stateless_connect(const char *service_name)
		if (!*buf->buf)
		i++;


	}
static int fetch_dumb(int nr_heads, struct ref **to_fetch)
			break;
			   PACKET_READ_DIE_ON_ERR_PACKET);
		dry_run : 1,

	strbuf_reset(buf);
	ret = push(specs.argc, specs.argv);
	int err;
	    !skip_prefix(p, service, &p) ||
	struct string_list_item *cas_option;
	struct strbuf preamble = STRBUF_INIT;
	rpc.write_line_lengths = 1;

	 * violations are hard errors.
		for (;;)
				break;
static void free_discovery(struct discovery *d)
		curl_easy_setopt(slot->curl, CURLOPT_IOCTLFUNCTION, rpc_ioctl);
	struct oid_array shallow;
		int n = packet_read(rpc->out, NULL, NULL, rpc->buf, rpc->alloc, 0);
	string_list_init(&options.push_options, 1);
	strbuf_addf(&refs_url, "%sinfo/refs", url.buf);
	free(rpc->hdr_content_type);
			return -1;
		if (!strcmp(value, "true"))
	headers = curl_slist_append(headers, rpc->hdr_content_type);
		thin : 1,

		if (!strcmp(value, "true"))
#include "walker.h"
		argv_array_push(&args, "--verbose");
	if (!results)
			return -1;
	}
static struct ref *parse_git_refs(struct discovery *heads, int for_push)
			 * all or has already been completely sent. Now we can
	 * complete their request.
	walker->get_recover = 0;
{
				printf("ok\n");
	client.git_cmd = 1;
	int http_ret, maybe_smart = 0;
	curl_easy_setopt(slot->curl, CURLOPT_NOBODY, 0);
	}
	if (skip_prefix(reader.line, "# service=", &p) && !strcmp(p, service)) {

	}
	do {
int cmd_main(int argc, const char **argv)
	if (options.dry_run)
	free(rpc.buf);

	fflush(stdout);

		if (data[i] == '\t')
		    transport_anonymize_url(url.buf), curl_errorstr);
		check_smart_http(last, service, &type);
	return err;
	if (packet_reader_read(&reader) != PACKET_READ_NORMAL)


		}
		goto retry;
		else
	switch (http_ret) {
	} else if (!strcmp(name, "update-shallow")) {
		p = eol + 1;
		options.verbosity = v;
		free(d->service);
	strbuf_release(&protocol_header);

			/* We would have an err here */
			printf("%s %s\n", oid_to_hex(&posn->old_oid), posn->name);
		return 0;
}

	unsigned flush_read_but_not_sent : 1;
	else if (options.verbosity > 1)
			rpc->pos = 0;

	 * Whenever a pkt-line is read into buf, append the 4 characters

		 */
	const char *p, *eol;
{
}
	} else {
		d->len = reader.src_len;
			options.dry_run = 0;
}
	if (*status != PACKET_READ_EOF) {
	/* Try to load the entire request, if we can fit it into the
	if (left < LARGE_PACKET_MAX)
				large_request = 1;
		struct slot_results results;
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, rpc_in);
		ret = git_deflate_end_gently(&stream);
			git_curl_ipresolve = CURL_IPRESOLVE_V4;
	} else if (!strcmp(name, "no-dependents")) {
			if (mid - start != the_hash_algo->hexsz)
{
		switch (*status) {
	struct discovery *heads = discover_refs("git-receive-pack", 1);
#ifndef NO_CURL_IOCTL
		return fetch_git(d, nr_heads, to_fetch);
		    transport_anonymize_url(url.buf));
	} else if (!strcmp(name, "from-promisor")) {
	last->buf_alloc = strbuf_detach(&buffer, &last->len);
		argv_array_push(&args, "--no-progress");
		if (!*ref->name)
			if (ferror(stdin))
{
	if (version > 0) {
		} else if (!strcmp(buf.buf, "capabilities")) {
	rpc.hdr_content_type = xstrfmt("Content-Type: application/x-%s-request", rpc.service_name);
		}
		options.from_promisor = 1;
				       &status))

	struct rpc_state *rpc = buffer_;
	free(rpc.service_url);
		rpc->protocol_header = NULL;
		git_deflate_init_gzip(&stream, Z_BEST_COMPRESSION);
		headers = curl_slist_append(headers, rpc->protocol_header);
	 * further reading occurs.
	for_each_string_list_item(cas_option, &cas_options)
	remote = remote_get(argv[1]);
				strbuf_addch(&msg, ' ');
	if ((starts_with(url.buf, "http://") || starts_with(url.buf, "https://")) &&
	string_list_init(&options.deepen_not, 1);

	http_cleanup();
 *
	rpc.in = 1;
	 * read, but the corresponding line length (if write_line_lengths is
			enum packet_read_status status;
		 */
				die(_("protocol error: expected sha/ref, got '%s'"), p);
			git_curl_ipresolve = CURL_IPRESOLVE_V6;
}
			return -1;
	}
			start = NULL;
		if (!strchr(url.buf, '?'))
	}
			ref = alloc_ref(name);
			}
	struct ref **list = &list_head;

