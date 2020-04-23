	strbuf_release(&buf);

	const char *pattern;
	struct strbuf buf = STRBUF_INIT;
		hdr_str(hdr, "Allow",
		method = "GET";
				 "GIT_COMMITTER_EMAIL=%s@http.%s", user, host);
		forbidden(hdr, "Unsupported service: '%s'", name);
	hdr_nocache(hdr);
	if (!enter_repo(dir, 0))
			if (full_request)


		}

	if (err && *err)

	if (dead <= 1) {
		if (buffer_input) {
			ret = git_inflate(&stream, Z_NO_FLUSH);
{
		struct service_cmd *c = &services[i];
	size_t objdirlen = strlen(get_object_directory());
static void pipe_fixed_length(const char *prog_name, int out, size_t req_len)
static void write_to_child(int out, const unsigned char *buf, ssize_t len, const char *prog_name)
		if (!regexec(&re, dir, 1, out, 0)) {
	send_strbuf(hdr, "text/plain; charset=utf-8", &buf);
	}

	if (!getenv("GIT_COMMITTER_NAME"))

		die_errno("error reading request body");
	buf = xmalloc(req_len);
static ssize_t read_request_eof(int fd, unsigned char **out)
	hdr_str(hdr, "Cache-Control", "public, max-age=31536000");
	http_status(hdr, 404, "Not Found");

	write_to_child(out, buf, n, prog_name);
}
		}
{
	{"GET", "/objects/[0-9a-f]{2}/[0-9a-f]{62}$", get_loose_object},

			    " try setting GIT_HTTP_MAX_REQUEST_BUFFER",
	for (p = get_all_packs(the_repository); p; p = p->next) {
static void select_getanyfile(struct strbuf *hdr)
	return svc;
	end_headers(hdr);
	{ "receive-pack", "receivepack", 0, -1 },
	close(out);
}
	http_status(hdr, 403, "Forbidden");
	va_list params;
		struct strbuf hdr = STRBUF_INIT;
		query_params = xcalloc(1, sizeof(*query_params));
	send_local_file(hdr, "text/plain", name);
	signed enabled : 2;
		if (cnt < 0) {
	send_local_file(hdr, "application/x-git-packed-objects", name);
static void hdr_nocache(struct strbuf *hdr)

} services[] = {
static void get_info_refs(struct strbuf *hdr, char *arg)

		http_status(&hdr, 500, "Internal Server Error");
	if (proto && !strcmp(proto, "HTTP/1.1")) {
__attribute__((format (printf, 2, 3)))
{
		strbuf_addf(&buf, "application/x-git-%s-advertisement",
{
{
	write_or_die(1, hdr->buf, hdr->len);
	struct packed_git *p;
		free(buf);

{
		end_url_with_slash(&buf, root);
	}

	if (n >= sizeof(buffer))
}
#include "url.h"
	if (err && *err)
				n = 0; /* nothing left to read */
		const char *argv[] = {NULL /* service name */,
__attribute__((format (printf, 2, 3)))
{
	while (remaining_len > 0) {
	free(buf);
{
}
		die("request was larger than our maximum size (%lu): "
		pipe_fixed_length(argv[0], cld.in, req_len);

		if (n < 0)

			if (req_len_defined && n > 0)
		return xstrdup(path);
			ssize_t buffer_len;
	if (!getanyfile)
			else
{
	n = vsnprintf(buffer, sizeof(buffer), fmt, args);
		svc->enabled = (user && *user) ? 1 : 0;
	hdr_str(hdr, content_type, buf.buf);
			strbuf_addf(buf, "ref: %s\n", strip_namespace(target));
	for (i = 0; i < ARRAY_SIZE(rpc_service); i++) {
		write_to_child(out, buf, n, prog_name);


	}

		const char *user = getenv("REMOTE_USER");
			stream.avail_out = sizeof(out_buf);

static unsigned long max_request_buffer = 10 * 1024 * 1024;
{
	if (!getenv("GIT_COMMITTER_EMAIL"))
 */
	va_start(args, fmt);
	strbuf_addf(&buf, "application/x-git-%s-request", svc->name);
		if (alloc == max_request_buffer)
		}
{
{
		max_request_buffer = alloc;
	va_list args;
	strbuf_release(&buf);
			    name_nons);
static void get_head(struct strbuf *hdr, char *arg)
	ssize_t req_len = get_content_length();
	if (!skip_prefix(name, "git-", &svc_name))
	const char *config_name;
static int getanyfile = 1;
};
	if (encoding && !strcmp(encoding, "gzip"))
		return read_request_eof(fd, out);
				buffer_len = req_remaining_len;

static int show_head_ref(const char *refname, const struct object_id *oid,
	strbuf_addf(hdr, "%s: %s\r\n", name, value);

	send_strbuf(hdr, "text/plain", &buf);
		regmatch_t out[1];

	git_config_get_ulong("http.maxrequestbuffer", &max_request_buffer);
	write_or_die(fd, buffer, n);
static const char content_type[] = "Content-Type";

		actual_type = "";
		/* partial read from read_in_full means we hit EOF */
		    "%" PRIuMAX "; try setting GIT_HTTP_MAX_REQUEST_BUFFER",
	}
		forbidden(hdr, "Unsupported service: getanyfile");
		copy_request(argv[0], cld.in, req_len);
				n = read_request(0, &full_request, req_len);
#include "pkt-line.h"
			return len;
			stream.next_in = full_request;
}
		} else {
			n = xread(0, in_buf, buffer_len);
	{"GET", "/objects/info/http-alternates$", get_text_file},
}
		for_each_namespaced_ref(show_text_ref, &buf);
{
	hdr_str(hdr, "Pragma", "no-cache");
{
}
}
			i->util = value;
	git_inflate_init_gzip_only(&stream);
	if (o->type == OBJ_TAG) {
	const char *name;
				free(i->util);
}
			struct string_list_item *i;
	int i;
	hdr_cache_forever(hdr);
}


static struct service_cmd {
	hdr_nocache(hdr);

}

static void get_idx_file(struct strbuf *hdr, char *name)
	if (write_in_full(out, buf, len) < 0)
			svc = s;
	{"GET", "/objects/info/alternates$", get_text_file},
{
		return 0;

		argv_array_pushf(&cld.env_array,
}

			svc->enabled = value;

};

		hdr_nocache(hdr);
		while (query && *query) {
	struct strbuf hdr = STRBUF_INIT;
	if (flag & REF_ISSYMREF) {
	if (root && *root) {

							NULL, NULL);
			dir[out[0].rm_so] = 0;
	dir = getdir();

	unsigned char *buf = xmalloc(alloc);


		}
		}
}
		if (daemon_avoid_alias(pathinfo))
}
	setup_path();
				const char *name)
}


static int show_text_ref(const char *name, const struct object_id *oid,
#include "protocol.h"

		const char *target = resolve_ref_unsafe(refname,
	const char *svc_name;

		argv_array_pushf(&cld.env_array, "GIT_COMMITTER_NAME=%s", user);
		strbuf_addf(buf, "%s\t%s^{}\n", oid_to_hex(&o->oid),
		exit(0);
	free(buf);
}
	hdr_int(hdr, content_length, sb.st_size);
		if (target)
	if (start_command(&cld))
	select_getanyfile(hdr);
}
	unsigned char buf[8192];
			return -1;
			die("request was larger than our maximum size (%lu);"
			else
		ssize_t cnt;
			die_errno("Reading request failed");
	select_getanyfile(hdr);
			const char *type, struct strbuf *buf)
			packet_flush(1);
	return i ? i->util : NULL;
#include "refs.h"
	if (!getenv("GIT_HTTP_EXPORT_ALL") &&
}

	if (!svc->enabled)
			!strcmp(c->method, "GET") ? "GET, HEAD" : c->method);

	set_die_routine(die_webcgi);
{

{


static struct rpc_service *select_service(struct strbuf *hdr, const char *name)
		remaining_len -= n;
		if (determine_protocol_version_server() != protocol_v2) {
	cld.argv = argv;
		o = deref_tag(the_repository, o, name, 0);

		ssize_t n = xread(0, buf, chunk_length);
		if (len < alloc) {
		struct rpc_service *svc = select_service(hdr, service_name);

		if (p->pack_local)
			write_to_child(out, out_buf, stream.total_out - cnt, prog_name);
	while (1) {
			stream.next_in = in_buf;
	char *buf = xmalloc(buf_alloc);
	int gzipped_request = 0;
	{"GET", "/objects/pack/pack-[0-9a-f]{64}\\.pack$", get_pack_file},
	unsigned char out_buf[8192];
	if (service_name) {
	}
	close(1);
			cnt++;
	close(out);


	exit(0); /* we successfully reported a failure ;-) */
}
	hdr_nocache(hdr);
	hdr_nocache(hdr);
		http_status(hdr, 415, "Unsupported Media Type");
/*
	return 0;
		host = "(none)";


#include "packfile.h"
	end_headers(hdr);
	struct service_cmd *cmd = NULL;
	fd = open(p, O_RDONLY);
	while (1) {
		if (!strcmp(s->name, svc_name)) {
	end_headers(hdr);
			n = stream.total_out - cnt;
		forbidden(hdr, "Service not enabled: '%s'", svc->name);
	strbuf_release(&buf);
		run_service(argv, 0);
	if (!actual_type)
static void end_headers(struct strbuf *hdr)
static void copy_request(const char *prog_name, int out, ssize_t req_len)
	strbuf_reset(&buf);
			die_errno("Cannot read '%s'", p);
			    max_request_buffer);
			cmd_arg = xmemdupz(dir + out[0].rm_so + 1, n - 1);
}
		return read_request_fixed_len(fd, req_len, out);

		cld.in = -1;
	select_getanyfile(hdr);
	struct strbuf buf = STRBUF_INIT;
}
	}
	for (i = 0; i < ARRAY_SIZE(services); i++) {
static void hdr_date(struct strbuf *hdr, const char *name, timestamp_t when)
{
	struct object *o = parse_object(the_repository, oid);

	hdr_nocache(hdr);
	}
static void hdr_str(struct strbuf *hdr, const char *name, const char *value)
		die("protocol error: impossibly long line");
	if (!strcmp(method, "HEAD"))

		die("unable to write to '%s'", prog_name);
		if (!n)
			else
	unsigned char *full_request = NULL;
	size_t len = 0, alloc = 8192;

	else
#include "run-command.h"
		struct rpc_service *s = &rpc_service[i];
	}
	strbuf_grow(&buf, cnt * 53 + 2);
		vreportf("fatal: ", err, params);
			if (strcmp(method, c->method))

			svc->name);
	if (!o)
{
}
	unsigned long cnt = 0;
static void service_rpc(struct strbuf *hdr, char *service_name)
}
	exit(0);
	}
{

			char *value = url_decode_parameter_value(&query);
static const char *get_parameter(const char *name)

	} else if (path && *path) {
	{ "upload-pack", "uploadpack", 1, 1 },
	hdr_date(hdr, last_modified, sb.st_mtime);
	}
	if (cnt < 0) {
		strbuf_addf(&var, "http.%s", svc->config_name);
	if (!cmd)
				i = string_list_insert(query_params, name);
	}
		/* otherwise, grow and try again (if we can) */
	if (buffer_input || gzipped_request || req_len >= 0)
	exit(0);
			*out = buf;
{
	struct strbuf buf = STRBUF_INIT;
	if (!query_params) {
static ssize_t get_content_length(void)

	if (gzipped_request)
		}
			"--stateless-rpc", "--advertise-refs",

		vfprintf(stderr, err, params);
#include "cache.h"
		argv[0] = svc->name;
static void run_service(const char **argv, int buffer_input)
	const char *value = show_date(when, 0, DATE_MODE(RFC2822));
	close(fd);
		die("No GIT_PROJECT_ROOT or PATH_TRANSLATED from server");
{
		not_found(&hdr, "Repository not exported: '%s'", dir);
		user = "anonymous";

		end_headers(hdr);
		http_status(hdr, 405, "Method Not Allowed");
	char *cmd_arg = NULL;

static void hdr_int(struct strbuf *hdr, const char *name, uintmax_t value)
	{"GET", "/objects/pack/pack-[0-9a-f]{40}\\.pack$", get_pack_file},

				goto done;
{
static void http_status(struct strbuf *hdr, unsigned code, const char *msg)
{
}
	{"POST", "/git-upload-pack$", service_rpc},
	git_zstream stream;

	cld.clean_on_exit = 1;
	if (!user || !*user)
	char *dir;
		http_status(hdr, 400, "Bad Request");
	char *path = getenv("PATH_TRANSLATED");
	}
			die("Bogus regex in service table: %s", c->pattern);
	va_list params;
	static char buffer[1024];
 * maliciously large request than chew up infinite memory).
}
	const char *encoding = getenv("HTTP_CONTENT_ENCODING");
	hdr_date(hdr, "Date", now);
	}
	timestamp_t now = time(NULL);
	va_end(params);
#include "object-store.h"
}
	http_config();
	char *method = getenv("REQUEST_METHOD");
	*out = buf;
			char *name = url_decode_parameter_name(&query);
	if (n < 0)
	void (*imp)(struct strbuf *, char *);

			if (ret == Z_STREAM_END)
		while (0 < stream.avail_in) {

		die_errno("Cannot stat '%s'", p);
			return 0;
			if (ret != Z_OK && ret != Z_STREAM_END)

	int i;


	send_local_file(hdr, "application/x-git-packed-objects-toc", name);
	if (max_request_buffer < alloc)
static void inflate_request(const char *prog_name, int out, int buffer_input, ssize_t req_len)
	set_die_is_recursing_routine(die_webcgi_recursing);
				die("zlib error inflating request, result %d", ret);
	if (max_request_buffer < req_len) {
		not_found(&hdr, "Not a git repository: '%s'", dir);
	char *pathinfo = getenv("PATH_INFO");
		struct rpc_service *svc = &rpc_service[i];
	struct strbuf *buf = cb_data;

	strbuf_addf(hdr, "Status: %u %s\r\n", code, msg);

static void get_info_packs(struct strbuf *hdr, char *arg)

	unsigned buffer_input : 1;
static void get_text_file(struct strbuf *hdr, char *name)
static void get_loose_object(struct strbuf *hdr, char *name)
	end_headers(hdr);
#include "repository.h"
	if (finish_command(&cld))
		if (pathinfo[0] == '/')
			strbuf_addf(&buf, "P %s\n", p->pack_name + objdirlen + 6);
		select_getanyfile(hdr);
}
	git_inflate_end(&stream);
{
static NORETURN void forbidden(struct strbuf *hdr, const char *err, ...)
__attribute__((format (printf, 2, 3)))
}
		}
}
			break;
	if (strcmp(actual_type, accepted_type)) {
	free(full_request);

			" but received '%s' instead.\n",
		cnt = read_in_full(fd, buf + len, alloc - len);
	ssize_t val = -1;
	int i, value = 0;
	if (fd < 0)
	max_request_buffer = git_env_ulong("GIT_HTTP_MAX_REQUEST_BUFFER",
	struct strbuf buf = STRBUF_INIT;
		REALLOC_ARRAY(buf, alloc);
	} else
static void check_content_type(struct strbuf *hdr, const char *accepted_type)
		gzipped_request = 1;
	size_t remaining_len = req_len;
			die("'%s': aliased", pathinfo);
}
		hdr_nocache(&hdr);

static void get_pack_file(struct strbuf *hdr, char *name)

				req_remaining_len -= n;
}
{

		if (!git_config_get_bool(var.buf, &value))
	va_start(params, err);
		hdr_str(hdr, content_type, buf.buf);
		if (n <= 0)
static const char content_length[] = "Content-Length";
	struct strbuf buf = STRBUF_INIT;
		die("No REQUEST_METHOD from server");
		not_found(hdr, "Cannot open '%s': %s", p, strerror(errno));
	select_getanyfile(hdr);
	if (svc->enabled < 0) {

	} else {
static struct string_list *query_params;
	}
		if (!o)
#include "string-list.h"
	size_t cnt = 0;

{

	hdr_cache_forever(hdr);
		write_or_die(1, buf, n);
}

		close(0);
		regfree(&re);


	git_config_get_bool("http.getanyfile", &getanyfile);
	return query_params;
	run_service(argv, svc->buffer_input);
	if (fstat(fd, &sb) < 0)
		strbuf_addstr(&buf, pathinfo);
	{"GET", "/objects/[0-9a-f]{2}/[0-9a-f]{38}$", get_loose_object},
	const char *service_name = get_parameter("service");
static struct rpc_service rpc_service[] = {

	{"POST", "/git-receive-pack$", service_rpc}
			 int flag, void *cb_data)
			stream.next_out = out_buf;
	return val;

	struct stat sb;
static int die_webcgi_recursing(void)
		len += cnt;
#include "tag.h"

{

}


		ssize_t n;
	struct rpc_service *svc = NULL;

			die("GIT_PROJECT_ROOT is set but PATH_INFO is not");
		if (p->pack_local)
	unsigned char in_buf[8192];
}
		format_write(1,
	for (p = get_all_packs(the_repository); p; p = p->next) {
			packet_write_fmt(1, "# service=git-%s\n", svc->name);
{
	cld.wait_after_clean = 1;
	argv[0] = svc->name;
	const char *method;
	unsigned char *buf;
	{"GET", "/objects/pack/pack-[0-9a-f]{64}\\.idx$", get_idx_file},
	close(out);



	int req_len_defined = req_len >= 0;
			break;
			n = out[0].rm_eo - out[0].rm_so;
	if (!host || !*host)

	hdr_nocache(hdr);
{
	va_start(params, err);
{
			die("request ended in the middle of the gzip stream");
		if (n < 0)
	select_getanyfile(hdr);
{
#include "config.h"
 * This is basically strbuf_read(), except that if we
		    max_request_buffer, (uintmax_t)req_len);
		if (regcomp(&re, c->pattern, REG_EXTENDED))
	const char *argv[] = {NULL, "--stateless-rpc", ".", NULL};
	strbuf_release(&var);


		end_headers(&hdr);

}


			free(buf);
				return bad_request(&hdr, c);
			alloc = max_request_buffer;


		end_headers(hdr);

	struct strbuf *buf = cb_data;
		send_strbuf(hdr, "text/plain", &buf);


	    access("git-daemon-export-ok", F_OK) )
		if (!pathinfo || !*pathinfo)
	end_headers(hdr);
			".", NULL};

			if (!i)
	strbuf_addf(buf, "%s\t%s\n", oid_to_hex(oid), name_nons);
	hdr_str(hdr, name, value);
static const char last_modified[] = "Last-Modified";
	unsigned n;
	}
	{"GET", "/info/refs$", get_info_refs},
	hdr_str(hdr, "Cache-Control", "no-cache, max-age=0, must-revalidate");
	{"GET", "/objects/info/packs$", get_info_packs},
	}
	memset(&stream, 0, sizeof(stream));
	write_or_die(1, buf->buf, buf->len);
	hdr_str(hdr, "Expires", "Fri, 01 Jan 1980 00:00:00 GMT");
	strbuf_addf(&buf, "application/x-git-%s-result", svc->name);

		strbuf_addf(buf, "%s\n", oid_to_hex(oid));
	free(p);
				buffer_len = sizeof(in_buf);
{

		strbuf_reset(&var);
			if (req_len_defined && req_remaining_len <= sizeof(in_buf))
	struct string_list_item *i;
int cmd_main(int argc, const char **argv)
}
	if (str && *str && !git_parse_ssize_t(str, &val))


			pathinfo++;
static NORETURN void not_found(struct strbuf *hdr, const char *err, ...)
	return dead++ > 1;
	}
static ssize_t read_request_fixed_len(int fd, ssize_t req_len, unsigned char **out)
	hdr_cache_forever(hdr);
	else if (buffer_input)
	hdr_str(hdr, content_type, type);
	struct rpc_service *svc = select_service(hdr, service_name);
	hdr_nocache(hdr);
	cnt = read_in_full(fd, buf, req_len);
	send_local_file(hdr, "application/x-git-loose-object", name);
	va_end(args);

static void send_local_file(struct strbuf *hdr, const char *the_type,
{
	ssize_t cnt = 0;
}
		inflate_request(argv[0], cld.in, buffer_input, req_len);
static void format_write(int fd, const char *fmt, ...)
		}
			cnt = stream.total_out;

	if (req_len < 0)

	{"GET", "/objects/pack/pack-[0-9a-f]{40}\\.idx$", get_idx_file},
		forbidden(hdr, "Unsupported service: '%s'", name);
static struct string_list *get_parameters(void)
	i = string_list_lookup(get_parameters(), name);

			"Expected POST with Content-Type '%s',"


	hdr_date(hdr, "Expires", now + 31536000);
}
#include "exec-cmd.h"
}
	if (!method)
			size_t n;

	return 0;
static void send_strbuf(struct strbuf *hdr,
struct rpc_service {

	const char *proto = getenv("SERVER_PROTOCOL");
static void http_config(void)
	const char *actual_type = getenv("CONTENT_TYPE");

{
	int fd;
	struct child_process cld = CHILD_PROCESS_INIT;
		return -1;
	if (!svc)
					   max_request_buffer);

}
	unsigned char *buf = NULL;
	return cnt;
{
			accepted_type, actual_type);
	strbuf_add(hdr, "\r\n", 2);

{
{
#include "argv-array.h"
		exit(1);
	cld.git_cmd = 1;
	ssize_t n = read_request(0, &buf, req_len);
static int dead;
		return strbuf_detach(&buf, NULL);
	strbuf_addf(hdr, "%s: %" PRIuMAX "\r\n", name, value);
	const char *user = getenv("REMOTE_USER");
							RESOLVE_REF_READING,

}

		if (alloc > max_request_buffer)
	strbuf_reset(&buf);

	}
 * hit max_request_buffer we die (we'd rather reject a
		die("failed to parse CONTENT_LENGTH: %s", str);
	const char *host = getenv("REMOTE_ADDR");
	for (i = 0; i < ARRAY_SIZE(rpc_service); i++) {
	size_t req_remaining_len = req_len;

		regex_t re;
	char *p = git_pathdup("%s", name);
static NORETURN void die_webcgi(const char *err, va_list params)
	hdr_str(hdr, content_type, the_type);
			break;
	} else {
	va_end(params);

{
	hdr_int(hdr, content_length, buf->len);
	cmd->imp(&hdr, cmd_arg);
		ssize_t n = xread(fd, buf, buf_alloc);
		exit(1);
	return NULL;
}
		size_t chunk_length = remaining_len > sizeof(buf) ? sizeof(buf) : remaining_len;
			i = string_list_lookup(query_params, name);
		vfprintf(stderr, err, params);
		stream.avail_in = n;
	select_getanyfile(hdr);

		const char *query = getenv("QUERY_STRING");
static char* getdir(void)
done:
};
			int ret;
	const char *str = getenv("CONTENT_LENGTH");

		gzipped_request = 1;
static int bad_request(struct strbuf *hdr, const struct service_cmd *c)
	head_ref_namespaced(show_head_ref, &buf);
	size_t buf_alloc = 8192;

static void hdr_cache_forever(struct strbuf *hdr)

	return 0;
			cmd = c;
	struct strbuf var = STRBUF_INIT;

{
	char *root = getenv("GIT_PROJECT_ROOT");
	return 0;
	strbuf_addch(&buf, '\n');
#include "object.h"
{
	end_headers(hdr);
	else if (req_len >= 0)
	check_content_type(hdr, buf.buf);

	{"GET", "/HEAD$", get_head},
			 int flag, void *cb_data)
	strbuf_release(hdr);
	else
static ssize_t read_request(int fd, unsigned char **out, ssize_t req_len)
	} else
	for (;;) {
		alloc = alloc_nr(alloc);
	strbuf_release(&buf);
{

		not_found(&hdr, "Request not supported: '%s'", dir);
	else if (encoding && !strcmp(encoding, "x-gzip"))
	const char *name_nons = strip_namespace(name);
