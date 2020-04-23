#include "commit.h"
				/*
};
{
	walker->fetch = fetch;
	if (obj_req->req !=NULL && obj_req->req->localfile != -1)
	struct strbuf *buffer;
	slot = req->slot;
	}
	if (obj_req->state == ABORTED) {
				okay = strchr(base, ':') - base + 3 <
		}
	/* Nothing to do if they've already been fetched */

				serverlen = strlen(base);
		     data->alt->base);
		struct strbuf buf = STRBUF_INIT;
	};

				 * neighbour.
	obj_req->req = req;
	newreq = xmalloc(sizeof(*newreq));
			int serverlen = 0;
	enum object_request_state state;
	list_for_each_safe(pos, tmp, head) {
			}
		return 0;
					okay = 1;
	struct slot_results results;
				const char *colon_ss = strstr(base,"://");
	} else if (!oideq(&obj_req->oid, &req->real_oid)) {
	preq->lst = &repo->packs;

	/* Try to get the request started, abort the request on error */
				}
			slot->in_use = 1;

}
	cdata->got_alternates = 1;
	struct active_request_slot *slot = alt_req->slot;
		return 0;
				/*
	struct strbuf url = STRBUF_INIT;

}
static void fetch_alternates(struct walker *walker, const char *base)
	release_object_request(obj_req);
				}

	/*
		ret = error("File %s has bad hash", hex);
	strbuf_release(&buffer);
#endif
		}
			return;
	ret = finish_http_pack_request(preq);
	}
	data->alt->got_indices = 0;
static int fetch_ref(struct walker *walker, struct ref *ref)

	newreq->walker = walker;

struct object_request {
	if (repo->got_indices)
}
struct alternates_request {
			cdata->got_alternates = -1;
	WAITING,
			obj_req->repo =
static void cleanup(struct walker *walker)
#include "walker.h"
	} else if (req->rename < 0) {
					serverlen = (strchr(colon_ss + 3, '/')
	data->alt->next = NULL;
	struct packed_git *target;

static void prefetch(struct walker *walker, unsigned char *sha1)

		fetch_alternates(walker, alt->base);

	} else if (req->zret != Z_STREAM_END) {
	release_http_object_request(req);
		ret = -1;
		warning("ignoring alternate with unknown protocol: %s", url);

			if (slot->finished != NULL)
	while (obj_req->state == WAITING)
}
	normalize_curl_result(&obj_req->req->curl_result,
};
	if (finish_http_object_request(obj_req->req))

	struct walker_data *data = walker->data;
			curl_easy_setopt(slot->curl, CURLOPT_URL,
	struct active_request_slot *slot;
	 * obj_req->req might change when fetching alternates in the callback
	struct strbuf *url;
	fwrite_buffer((char *)&null_byte, 1, 1, alt_req->buffer);
	default:
						 base[serverlen - 1] != '/');
				 struct object_request *obj_req)
	 * may fail and need to have alternates loaded before continuing
{
					warning("ignoring alternate that does"

				 *
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &buffer);
	struct object_request *obj_req;
	obj_req->state = ACTIVE;
	 * Use a callback to process the result, since another request

		}

					newalt->next = NULL;
{
	alt_req.walker = walker;


static int fill_active_slot(struct walker *walker)
	/* Use alternates if necessary */
abort:
		step_active_slots();

			struct alt_base *newalt;
	preq->slot->results = &results;
			posn++;
			active_requests++;
		if (obj_req->req != NULL)
#include "packfile.h"

				 *     http://git.host/pub/scm/linux.git/
	data = alt_req->buffer->buf;
	alt_req.base = base;

	fill_active_slots();
	int i = 0;
			hash_to_hex(sha1));
{


	 * wait for them to arrive and return to processing this request's
	walker->fetch_ref = fetch_ref;

			abort_http_object_request(obj_req->req);
#endif
{
	struct walker *walker = obj_req->walker;
	const char *base;
		obj_req = list_entry(pos, struct object_request, node);
	list_add_tail(&newreq->node, &object_queue_head);

			      curl_errorstr, sizeof(curl_errorstr));
		if (!http_fetch_pack(walker, altbase, hash))
	 */
		*s = 0;
	if (walker->get_verbosely)
					do {
		fetch_alternates(walker, data->alt->base);
		    !alt_req->buffer->len) {
			/* Try reusing the slot to get non-http alternates */


						tail = tail->next;
	struct walker_data *cdata = walker->data;
{
			int okay = 0;
	if (missing_target(obj_req->req)) {
	struct alt_base *alt;
		i = posn + 1;

	}
			      obj_req->req->http_code,


	release_http_pack_request(preq);
};
	struct alt_base *altbase = data->alt;
		abort_object_request(obj_req);
		(struct object_request *)callback_data;
				cdata->got_alternates = -1;
	}
};
					} while (serverlen &&
	struct alternates_request alt_req;
				 * -----------here^
		ret = 0;
					(*slot->finished) = 1;
struct walker_data {
		if (hasheq(obj_req->oid.hash, hash))
}
	}
		return 0;
#ifdef USE_CURL_MULTI
	struct active_request_slot *slot;
	struct alt_base *alt = data->alt;
	process_http_object_request(obj_req->req);
	const char *base = alt_req->base;
	if (ret)
				if (colon && slash && colon < data + posn &&
		}
	struct walker *walker = alt_req->walker;
	alt_req.http_specific = 1;
	if (has_object_file(&obj_req->oid)) {
				 * Relative URL; chop the corresponding

enum object_request_state {
{
		return;
#else
		return;
					newalt->packs = NULL;
		ret = error("Request for %s aborted", hex);
	return ret;
}
				 * from data), and concatenate the result.
#endif
				}
				} else if (is_alternate_allowed(target.buf)) {
		warning("ignoring alternate with restricted protocol: %s", url);
	 * process_object_response; therefore, the "shortcut" variable, req,
{
					strbuf_release(&target);
	struct walker *walker;
		walker_say(obj_req->walker, "got %s\n", oid_to_hex(&obj_req->oid));
	obj_req->state = COMPLETE;
		return 0;

#include "object-store.h"
	if (walker->get_verbosely)
	return walker;
			release_http_object_request(obj_req->req);
		   req->http_code != 416) {
	 * If another request has already started fetching alternates,
				if (!strbuf_strip_suffix(&target, "objects")) {
	struct alternates_request *alt_req =
			alt_req->http_specific = 0;
	return -1;
				 * The code first drops ../ from data, and
		repo->got_indices = 0;
			}
	struct object_id oid;
	free(obj_req);
					tail->next = newalt;
				 *     http://git.host/pub/scm/linus.git/

				 * so memcpy(dst, base, serverlen) will
	if (walker->get_verbosely) {
				return 1;
static void fetch_alternates(struct walker *walker, const char *base);
	return 0;
			return;

						     - base);
	}
						serverlen--;
#endif
						target.buf);
{

		if (missing_target(req))
	return 1;
			if (has_object_file(&obj_req->oid))
	char *data;
				if (colon_ss) {

				char *colon = strchr(data + i, ':');
		goto abort;
				obj_req->repo->next;
		if (obj_req->state == WAITING) {
		step_active_slots();
	ACTIVE,
		run_active_slot(obj_req->req->slot);

#ifdef USE_CURL_MULTI
		}
}
	preq = new_http_pack_request(target, repo->base);
		run_active_slot(slot);
				}
			else {
				strbuf_add(&target, base, serverlen);

{
		return 0;
static int is_alternate_allowed(const char *url)
	case HTTP_MISSING_TARGET:
		strbuf_release(&buf);
		break;
		return;
				char *slash = strchr(data + i, '/');
	data->alt->base = xstrdup(url);
					while (tail->next != NULL)
		altbase = altbase->next;

	target = find_sha1_pack(sha1, repo->packs);
	}
		while (posn < alt_req->buffer->len && data[posn] != '\n')

		obj_req->state = ABORTED;
	normalize_curl_result(&req->curl_result, req->http_code,
			ret = error("%s (curl_result = %d, http_code = %ld, sha1 = %s)",
	int ret;
#include "cache.h"
	struct object_request *obj_req =
		release_http_object_request(req);
{
	alt_req.url = &url;
struct walker *get_http_walker(const char *url)

	const char *protocols[] = {
	ABORTED,

			      sizeof(obj_req->req->errorstr));
			hash_to_hex(target->hash));
				 * number of subpath from base (and ../

		return -1;
{
				 * This counts
	/*
		obj_req = list_entry(pos, struct object_request, node);
struct alt_base {
	walker->corrupt_object_found = 0;
static LIST_HEAD(object_queue_head);
	slot->callback_data = obj_req;
	hashcpy(newreq->oid.hash, sha1);
				 * then drops one ../ from data and one path
	start_object_request(walker, obj_req);
			break;
#include "transport.h"
				/* If the server got removed, give up. */
		else
	const char null_byte = '\0';
			free(alt->base);
	newreq->repo = data->alt;
				 * to borrow from
					strbuf_release(&target);
				 * This is not wrong.  The alternate in
	while (altbase) {


	data->alt->packs = NULL;

	struct walker *walker = xmalloc(sizeof(struct walker));
}
				start_object_request(walker, obj_req);
	} else if (slot->curl_result != CURLE_OK) {
	struct alt_base *next;
				    slash < data + posn && colon < slash) {
static int http_fetch_pack(struct walker *walker, struct alt_base *repo, unsigned char *sha1)
	slot->callback_func = process_object_response;
{
		error("Unable to start request");
		alt = data->alt;
	else
			strbuf_addf(alt_req->url, "%s/objects/info/alternates",

	struct http_pack_request *preq;
				 *

#include "repository.h"
	if (start_active_slot(preq->slot)) {

	}

	}

	alt_req->buffer->len--;
static void finish_object_request(struct object_request *obj_req)
	}
			strbuf_reset(alt_req->url);
	}
	struct active_request_slot *slot;
		fprintf(stderr, "Getting alternates list for %s\n", base);
	return 0;
	case HTTP_OK:
	int http_specific;
		error("fd leakage in release: %d", obj_req->req->localfile);
		free(data);
	COMPLETE
	struct list_head *pos, *head = &object_queue_head;
static void release_object_request(struct object_request *obj_req)
			start_object_request(walker, obj_req);

	for (s = data->alt->base + strlen(data->alt->base) - 1; *s == '/'; --s)
		}
		obj_req->state = ABORTED;
	walker->cleanup = cleanup;
	char *base;

	struct list_head node;
	}
	if (start_active_slot(slot))
			}
	struct http_object_request *req;
static int fetch_object(struct walker *walker, unsigned char *hash)
	release_object_request(obj_req);
		walker->data = NULL;
		if (data[posn] == '\n') {
	}

	list_for_each(pos, head) {

			free(alt);
		if (obj_req->repo->next != NULL) {
	}


	}
	return http_fetch_ref(data->alt->base, ref);
				strbuf_add(&target, data + i, posn - i);
	char *s;
	struct object_request *obj_req = NULL;
	 */
				i += 3;
	step_active_slots();
		}
	http_is_verbose = walker->get_verbosely;
				 */
	req = obj_req->req;
	switch (http_get_info_packs(repo->base, &repo->packs)) {
}
	if (obj_req->req->rename == 0)
	walker->prefetch = prefetch;
	curl_easy_setopt(slot->curl, CURLOPT_WRITEFUNCTION, fwrite_buffer);
		const char *end;
	struct alt_base *tail = cdata->alt;

	struct strbuf buffer = STRBUF_INIT;
	if (data) {
}

		while (alt) {
	}
					 alt_req->url->buf);
				    req->errorstr, req->curl_result,
	} else {

		fprintf(stderr, " which contains %s\n",
}
		fprintf(stderr, "Getting pack %s\n",
		goto abort;
				struct strbuf target = STRBUF_INIT;
	 */
	list_del(&obj_req->node);
static void process_alternates_response(void *callback_data)
	while (i < alt_req->buffer->len) {

				       serverlen;
	req = new_http_object_request(obj_req->repo->base, &obj_req->oid);
					newalt->base = strbuf_detach(&target, NULL);
					newalt = xmalloc(sizeof(*newalt));
	newreq->req = NULL;
			      req->errorstr, sizeof(req->errorstr));
	if (cdata->got_alternates == 1)
	walker->data = data;
		    starts_with(end, "://"))
	add_fill_function(walker, (int (*)(void *)) fill_active_slot);
			alt_next = alt->next;
	if (!is_transport_allowed(protocols[i], 0)) {
			if (okay) {
			      curl_errorstr);

	if (alt_req->http_specific) {
}
				obj_req->state = COMPLETE;
		if (results.curl_result != CURLE_OK) {
	if (!start_active_slot(slot)) {
	} else if (req->curl_result != CURLE_OK &&

	if (req->localfile != -1) {
	if (req == NULL) {
}
}
		ret = error("unable to write sha1 filename %s", buf.buf);
		warning("alternate disabled by http.followRedirects: %s", url);
		close(req->localfile);
			if (data[i] == '/') {

		int posn = i;
	 * is used only after we're done with slots.
	}
			ret = -1; /* Be silent, it is probably in a pack. */

	normalize_curl_result(&slot->curl_result, slot->http_code,
	curl_easy_setopt(slot->curl, CURLOPT_URL, url.buf);
				 * two ../../ to borrow from your direct
			}

}
				 * copy up to "...git.host".
					okay = 1;
		fprintf(stderr, "Getting pack list for %s\n", repo->base);
	slot->callback_func = process_alternates_response;
	int ret = 0;
		loose_object_path(the_repository, &buf, &req->oid);
					i += 3;
	struct list_head *pos, *tmp, *head = &object_queue_head;
	return error("Unable to find %s under %s", hash_to_hex(hash),
	if (obj_req == NULL)

		"http", "https", "ftp", "ftps"
				 * http://git.host/pub/scm/linux.git/
				    base);
static void abort_object_request(struct object_request *obj_req)
			if (!start_active_slot(slot)) {
static void process_object_response(void *callback_data);
#ifdef USE_CURL_MULTI
	struct http_object_request *req;
		walker->corrupt_object_found++;

#include "http.h"
#endif
	data->alt = xmalloc(sizeof(*data->alt));
		return;
		run_active_slot(preq->slot);
	while (cdata->got_alternates == 0) {
	struct walker_data *cdata = walker->data;


	alt_req.buffer = &buffer;
	struct walker_data *data = walker->data;

				if (slot->finished != NULL)
	struct walker_data *data = walker->data;
	int got_indices;
	strbuf_addf(&url, "%s/objects/info/http-alternates", base);

			      obj_req->req->errorstr,
			return 0;
	if (i >= ARRAY_SIZE(protocols)) {
	if (fetch_indices(walker, repo))
				while (i + 2 < posn &&
				} else {

	 * curl message
	int i;
	struct walker_data *data = walker->data;
	struct object_request *newreq;
	if (!fetch_object(walker, hash))
	}
		req->localfile = -1;
					warning("adding alternate object store: %s",
				 * is ../../linus.git/objects/.  You need
#include "list.h"
		return error("Couldn't find request for %s in the queue", hex);
				    req->http_code, hex);
		(struct alternates_request *)callback_data;
		repo->got_indices = 1;
	if (!target)
			return;
	data->got_alternates = -1;

		return -1;

}
#ifdef USE_CURL_MULTI
	alt_req.slot = slot;

	slot->callback_data = &alt_req;
			error("Unable to get pack file %s\n%s", preq->url,
	struct packed_git *packs;

static int fetch_indices(struct walker *walker, struct alt_base *repo)
		if (slot->curl_result != CURLE_OK ||
	int got_alternates;
static void start_object_request(struct walker *walker,
						target.buf);
	struct walker_data *data = xmalloc(sizeof(struct walker_data));
				(*slot->finished) = 0;
	/*
{
}
						" not end in 'objects': %s",
	cdata->got_alternates = 0;
#ifdef USE_CURL_MULTI
	while (obj_req->state == ACTIVE)
	struct alt_base *repo;
	}
static void process_object_response(void *callback_data)
{
			alt = alt_next;
	if (http_follow_config != HTTP_FOLLOW_ALWAYS) {

	struct alt_base *alt, *alt_next;
			goto abort;
		return ret;
	strbuf_release(&url);
		cdata->got_alternates = -1;
				       !memcmp(data + i, "../", 3)) {
				 * from base.  IOW, one extra ../ is dropped
	finish_object_request(obj_req);
	char *hex = hash_to_hex(hash);
	/* Start the fetch */

					newalt->got_indices = 0;
				 */
};
			break;
static int fetch(struct walker *walker, unsigned char *hash)


	const char *url;
			} else if (!memcmp(data + i, "../", 3)) {
	struct http_object_request *req;


		return 0;

				 * from data than path is dropped from base.
		if (skip_prefix(url, protocols[i], &end) &&
	return ret;

	slot = get_active_slot();

	struct walker_data *data = walker->data;
	struct walker *walker;
				slot->in_use = 0;
{
	}

		ret = error("File %s (%s) corrupt", hex, req->url);

	if (preq == NULL)
	newreq->state = WAITING;
	for (i = 0; i < ARRAY_SIZE(protocols); i++) {
		if (!missing_target(slot)) {
{
	int ret;
			} else if (alt_req->http_specific) {
