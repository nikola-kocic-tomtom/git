			XML_SetCharacterDataHandler(parser, xml_cdata);

	    get_oid_hex_from_objpath(path, &oid))
	/*
					path = strchr(path+2, '/');
		dav_headers = get_dav_token_headers(lock, DAV_HEADER_IF);
	struct curl_slist *dav_headers = http_copy_default_headers();
		objects_to_send = get_delta(&revs, ref_lock);
					ls->dentry_name = xstrdup(path);


		c = name;
			ls->dentry_flags |= IS_DIR;

	curl_slist_free_all(dav_headers);
			result = XML_Parse(parser, in_buffer.buf,

	strbuf_rtrim(&buffer);
	struct transfer_request *request;
	struct ref *ref;
}

		return;
		*symref = xmemdupz(name, buffer.len - (name - buffer.buf));
	if (!strcmp(ls->path, ls->dentry_name) && (ls->flags & IS_DIR)) {
}

			current_time;
	}
#ifdef USE_CURL_MULTI
	fprintf(stderr, "Removing remote locks...\n");
		if (prepare_revision_walk(&revs))
	struct active_request_slot *slot;
		return 0;
	request->lock = NULL;
			free(ctx.name);
			if (path) {
	curl_easy_setopt(curl, CURLOPT_URL, url);
static int delete_remote_branch(const char *pattern, int force)

		} else if (!strcmp(ctx->name, DAV_PROPFIND_COLLECTION)) {
}
		/* fallthrough */
	/* Verify DAV compliance/lock support */
	else
#include "blob.h"

				http_is_verbose = 1;
			}
	free(ls.path);
}

	if (delete_branch) {
static int fetch_indices(void)

			ctx.userFunc = handle_remote_ls_ctx;
			    results.http_code != 405) {

#endif
		fprintf(stderr,

	ref = alloc_ref(ls->dentry_name);
		pushing = 0;

	time_t current_time = time(NULL);
				"error: curl result=%d, HTTP code=%ld\n",

				     remote_ref->name);

		}
	free(escaped);
static void get_remote_object_list(unsigned char parent);
	NEED_PUSH,
	struct active_request_slot *slot;
}
		ls->dentry_flags = 0;
			ctx.userData = &ls;
			fprintf(stderr,
#include "list-objects.h"
				if (path) {
#include "remote.h"


		return;
		return error("More than one remote branch matches %s",
		release_request(request);
	fprintf(stderr, "Fetching remote heads...\n");
		argv_array_push(&commit_argv, ""); /* ignored */
	}
		die("You must specify only one branch name when deleting a remote branch");
			printf("error null no match\n");
	int len;
/*
				      "local '%s'.\n"



}
	for (i = 1; i < argc; i++, argv++) {


	struct ref *ref, *local_refs;
					XML_ErrorString(
	return add_one_object(obj, p);
		object_list_insert(obj, &objects);
	init_tree_desc(&desc, tree->buffer, tree->size);
			if (remote_dir_exists[request->obj->oid.hash[0]] == 1) {
				if (finish_http_pack_request(preq) == 0)
static void curl_setup_http(CURL *curl, const char *url,
	case HTTP_OK:
	remote_refs = ref;
	request->buffer.buf.len = stream.total_out;

				     remote_ref->name);
		}
	}
	curl_setup_http(slot->curl, url, DAV_LOCK, &out_buffer, fwrite_buffer);
				force_all = 1;
static void start_move(struct transfer_request *request)
			XML_SetElementHandler(parser, xml_start_tag,
	sigchain_push_common(remove_locks_on_signal);
#endif
			oid_to_hex(&ref->old_oid), refname);
	if (new_len > ctx->len) {
				lock->timeout = -1;
	free(url);
		repo->can_update_info_refs = 0;
	if (!aborted) {
		    oid_to_hex(&ref->old_oid), ls->dentry_name);

			fprintf(stderr, "LOCK HTTP error %ld\n",
	obj = lookup_object(the_repository, oid);
		slot = get_active_slot();

{
	} else {
			XML_Parser parser = XML_ParserCreate(NULL);
		request->slot = slot;

		if (info_ref_lock && repo->can_update_info_refs) {
			}
			p = process_tree(lookup_tree(the_repository, &entry.oid),

	char *escaped;
#endif
#endif

		if (results.curl_result == CURLE_OK) {
	/* URL is reused for MOVE after PUT and used during FETCH */
	struct transfer_request *next;
		}
			rc = 1;
	char *url;
		case OBJ_TREE:
			return error("Remote branch %s is the current HEAD",
	while (lock) {
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
			release_request(request);

	char *ep;

		const char *name = entry->name;
enum XML_Status {
	int i;
	struct ref *refs = remote_refs;
	if (!start_active_slot(slot)) {
				fprintf(stderr, "'%s': up-to-date\n", ref->name);
		if (request->curl_result == CURLE_OK ||
/* DAV methods */


	is_running_queue = 0;
	if (target) {
	 * symlink to a symref will look like a symref)
		return error("Remote HEAD is not a symref");
				lock->timeout = strtol(arg, NULL, 10);
		FREE_AND_NULL(request->url);
					path += repo->path_len;
		return;
#include "commit-reach.h"
	curl_setup_http_get(slot->curl, url, DAV_DELETE);
		struct remote_lock *next = lock->next;
#include "object-store.h"
			fprintf(stderr, " using '%s'", ref->peer_ref->name);
			}
#define DAV_ACTIVELOCK_TOKEN ".prop.lockdiscovery.activelock.locktoken.href"
			count += add_send_request(objects->item, lock);
	ssize_t size;
{
	slot->callback_func = process_response;
/* DAV lock flags */
	}
			const char *arg;
			char *path = strstr(arg, "//");
}
		lock->url = url;
		break;
		strbuf_reset(&buf);

		curl_setup_http(slot->curl, lock->url, DAV_PUT,
	path += 2;

		request->state = ABORTED;
					      xml_end_tag);
			rc = 1;
xml_cdata(void *userData, const XML_Char *s, int len)

		p = process_tree(get_commit_tree(commit), p);
		}
		case OBJ_BLOB:
	void *userData;
}
					 p);
	die("git-push is not available for http/https repository when not compiled with USE_CURL_MULTI");
	if (!target) {
	} else {
	 * Don't push the object if it's known to exist on the remote
	curl_easy_setopt(curl, CURLOPT_INFILESIZE, buffer->buf.len);
	/* Get a list of all local and remote heads to validate refspecs */
	if (c == NULL)

	for (match = 0; refs; refs = refs->next) {
			if (delete_remote_branch(ref->name, 1) == -1) {
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);

	struct ref *remote_ref = NULL;
			continue;

	strbuf_add(&buf, request->lock->tmpfile_suffix, the_hash_algo->hexsz + 1);
	/* First header.. */
	}
#define XML_STATUS_OK    1
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);


	 */
	int ret;
	case HTTP_ERROR:
	curl_easy_setopt(curl, CURLOPT_INFILE, buffer);
				if (repo->path)
	dav_headers = curl_slist_append(dav_headers, timeout_header);
						  ls->flags,
	curl_easy_setopt(curl, CURLOPT_URL, url);
	int dentry_flags;
static void finish_request(struct transfer_request *request);

			the_hash_algo->update_fn(&hash_ctx, lock->token, strlen(lock->token));
	 * Remote HEAD must be a symref (not exactly foolproof; a remote
	unpacked = read_object_file(&request->obj->oid, &type, &len);
		  process_ls_object, &val);
	request->obj = obj;
			if (!strcmp(arg, "-D")) {
	/* Compress it */
	void (*userFunc)(struct remote_ls_ctx *ls);
static struct ref *remote_refs;
	free(lock->owner);


				    ls->flags & RECURSIVE) {

	request->dest = strbuf_detach(&buf, NULL);
	slot = get_active_slot();
	if (obj->flags & (UNINTERESTING | SEEN))
#ifndef XML_STATUS_OK
	http_cleanup();
	}
	fill_active_slots();
	 * or is already in the request queue
	struct object *obj = &tree->object;
		if (helper_status)

		run_active_slot(slot);
	} else if (request->state == RUN_PUT) {
	append_remote_object_url(&buf, repo->url, hex, 0);
		rc = -1;
		}

	if (start_active_slot(slot)) {
		if (!strcmp(ctx->name, DAV_ACTIVELOCK_OWNER)) {

			if (skip_prefix(ctx->cdata, "Second-", &arg))
	unsigned int val = parent;
{
				continue;
#define DAV_PUT "PUT"
			run_active_slot(slot);
			&out_buffer, fwrite_null);
		} else {
		} else
	/* Send delete request */

		/* Remote branch must be an ancestor of remote HEAD */
	obj->flags |= SEEN;
	path[8] = hex[val >> 4];

#define DAV_ACTIVELOCK_OWNER ".prop.lockdiscovery.activelock.owner.href"
				printf("error %s cannot remove\n", branch);
		/* Lock remote branch ref */

	lock->refreshing = 0;
	obj->flags |= LOCAL;
{
	case HTTP_OK:
					   in_buffer.len, 1);
			repo->can_update_info_refs = 0;
			return 1;
	}
	struct tree_desc desc;
				     "of your current HEAD.\n"
}
			else if (helper_status)
		info_ref_lock = lock_remote("info/refs", LOCK_TIME);
	char tmpfile_suffix[GIT_MAX_HEXSZ + 1];
			fprintf(stderr, "Unable to update server info\n");
	slot = get_active_slot();
	FREE_AND_NULL(*symref);
}
		return;
			str_end_url_with_slash(arg, &repo->url);

		}
	}
		repo->locks = lock;
	return ret;
	} else {
		if (request->state == NEED_FETCH) {
static int pushing;
}
		/* Try fetching packed if necessary */
			p = process_tree((struct tree *)obj, p);
	int i;
	add_fill_function(NULL, fill_active_slot);
	/* Then the data itself.. */
		unlock_remote(info_ref_lock);

	dav_headers = get_dav_token_headers(lock, DAV_HEADER_IF | DAV_HEADER_TIMEOUT);
	struct object_id head_oid;
			ctx.name = xcalloc(10, 1);
	struct remote_ls_ctx *parent;
		if (!lock->refreshing && time_remaining < LOCK_REFRESH) {
				if (repo->path)
{
		die("bad tree object %s", oid_to_hex(&obj->oid));
			if (result != XML_STATUS_OK) {
	struct xml_ctx *ctx = (struct xml_ctx *)userData;
	int has_info_refs;
static int unlock_remote(struct remote_lock *lock)
	}
				request->curl_result, request->http_code);
	} else {
					"PUT error: curl result=%d, HTTP code=%ld\n",
		fprintf(stderr, "Unable to start LOCK request\n");
				continue;
			if (!dry_run)
	}
			rc = 1;
	return 0;
		fill_active_slots();
		}
	curl_setup_http(slot->curl, repo->url, DAV_PROPFIND,
	/*
}
{
	struct remote_lock *info_ref_lock = NULL;
}
	struct active_request_slot *slot;
	new_len = old_namelen + strlen(c) + 2;
	dav_headers = get_dav_token_headers(lock, DAV_HEADER_IF);
	int can_update_info_refs;
#define PROCESS_DIRS  (1u << 1)
			"Unable to parse object %s for remote ref %s\n",
	preq->slot->callback_data = request;
}

	}
{
	}

			XML_Parser parser = XML_ParserCreate(NULL);
	if (info_ref_lock)

		fprintf(stderr, "Unable to start UNLOCK request\n");
		get_remote_object_list(obj->oid.hash[0]);
	}
	int objects_to_send;
	curl_slist_free_all(dav_headers);

		if (*arg == '-') {
static void start_mkcol(struct transfer_request *request)
	struct commit *commit;
		ref_lock = lock_remote(ref->name, LOCK_TIME);
	struct xml_ctx *ctx = (struct xml_ctx *)userData;
		request_queue_head = request->next;
	int force_delete = 0;
	ref = alloc_ref(refname);
			ctx.name = xcalloc(10, 1);
	request = request_queue_head;
			fprintf(stderr, "MKCOL %s failed, aborting (%d/%ld)\n",

	p = add_one_object(obj, p);

				request->curl_result, request->http_code);
			continue;
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &in_buffer);
	} else {
	if (!obj)
		break;
					      path, url);
	curl_slist_free_all(dav_headers);


	 */
			break;
	struct active_request_slot *slot;
	/* Check whether the remote has server info files */
	struct slot_results results;
	struct remote_ls_ctx *ls = (struct remote_ls_ctx *)ctx->userData;
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
				request->obj->flags |= (LOCAL | REMOTE);
			ctx.cdata = NULL;
	}

	git_hash_ctx hash_ctx;
				 */
		release_request(request);

		  add_remote_info_ref, &buffer.buf);
		fprintf(stderr, "No refs in common and none specified; doing nothing.\n");
					remote_ls(ls->dentry_name,
		if (obj->type == OBJ_TREE) {

			XML_SetUserData(parser, &ctx);
	char timeout_header[25];
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
#ifndef NO_CURL_IOCTL

			continue;
	free(lock->url);
			if (!strcmp(arg, "--dry-run")) {
static void one_remote_object(const struct object_id *oid)
	repo = xcalloc(1, sizeof(*repo));
		} else {
	struct transfer_request *request;
			if (obj_req->rename == 0)
	if (start_active_slot(slot)) {
#define DAV_CTX_LOCKTYPE_EXCLUSIVE ".multistatus.response.propstat.prop.supportedlock.lockentry.lockscope.exclusive"
	ep = strchr(url + strlen(repo->url) + 1, '/');
		if (results.curl_result == CURLE_OK) {
		}
	 * Fetch a copy of the object if it doesn't exist locally - it
}
		curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
	finish_request(request);
	if (remote_dir_exists[obj->oid.hash[0]] == -1)
static int remote_exists(const char *path)
				if (helper_status)
	char *token;
	fprintf(stderr,	"Fetching pack %s\n",
			aborted = 1;
#endif
	struct transfer_request *request;
		if (o)
}
		slot->results = &results;
			if (!strcmp(arg, "--force")) {
	}
			}
		} else if (!strcmp(ctx->name, DAV_ACTIVELOCK_TIMEOUT)) {
				if (ls->flags & PROCESS_DIRS) {
			return error("Unable to resolve remote branch %s",
			if (preq) {

{
/* We allow "recursive" symbolic refs. Only within reason, though */
	if (c == NULL)

	slot->results = &results;

	}
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, custom_req);
				/* ensure collection names end with slash */
		FREE_AND_NULL(lock);
		return;
		ret = -1;
			run_active_slot(slot);
	char *path;
	struct object *obj = &blob->object;
	struct http_object_request *obj_req;
	int rc = 0;
		char *name = refs->name;
	struct active_request_slot *slot;
static struct curl_slist *get_dav_token_headers(struct remote_lock *lock, enum dav_header_flag options)
	if (start_active_slot(slot)) {
			if ((*lock_flags & DAV_PROP_LOCKEX) &&
}
				objects_to_send);
struct repo {
		time_remaining = lock->start_time + lock->timeout -
static void finish_request(struct transfer_request *request)
			release_request(request);


			error("Cannot access URL %s, return code %d",
		else {
					 struct object_list **p)

static void get_remote_object_list(unsigned char parent)
				      "Maybe you are not up-to-date and "
	slot->callback_data = request;
	if (obj->flags & (UNINTERESTING | SEEN))
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
			oid_to_hex(&ref->old_oid), ls->dentry_name);
	slot->results = &results;
				results.curl_result, results.http_code);
	dav_headers = curl_slist_append(dav_headers, "Overwrite: T");

			continue;
	obj->flags |= PUSHING;
		unlock_remote(ref_lock);
  XML_STATUS_OK = 1,
	if (!remote_refs) {
static void release_request(struct transfer_request *request);
static void start_put(struct transfer_request *request)
					 struct object_list **p)
		argv_array_push(&commit_argv, "--objects");
 * determine the refs from the remote file system (badly: it does not even
				}
	xsnprintf(ctx->name + old_namelen, ctx->len - old_namelen, ".%s", c);
	const char *name;
	if (http_fetch_ref(repo->url, ref) != 0) {
	/* Set it up */
		}
	char *path;
		repo->can_update_info_refs = 0;
		ep = strchr(ep + 1, '/');

	ls.userData = userData;

/* Flags that control remote_ls processing */
	if (!symref)
		ret = -1;
		run_active_slot(slot);

	is_running_queue = 0;

}
	stream.next_in = unpacked;
	int time_remaining;
	const char *path = ls->dentry_name;
	strbuf_release(&buf);
}


		if (request->curl_result != CURLE_OK) {
#include "commit.h"
		release_http_object_request(obj_req);
			return error("DELETE request failed (%d/%ld)",
	struct object *obj;
	struct slot_results results;
enum dav_header_flag {
		repo->can_update_info_refs = 0;
		if (dry_run) {
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &in_buffer);
	}
			return 1;
	const char *c = strchr(name, ':');
		die("Couldn't get %s for remote symref\n%s", url,
#define PROCESS_FILES (1u << 0)
#define PROPFIND_SUPPORTEDLOCK_REQUEST "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:propfind xmlns:D=\"DAV:\">\n<D:prop xmlns:R=\"%s\">\n<D:supportedlock/>\n</D:prop>\n</D:propfind>"
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
			ctx.name = xcalloc(10, 1);
	strbuf_release(&out_buffer.buf);
#endif
	run_request_queue();



	} else {
	if (buffer.len == 0)
						     remote->name);
{
#define LOCK_TIME 600
	}
	return &entry->next;
	struct strbuf buf = STRBUF_INIT;
#define DAV_PROPFIND_COLLECTION ".multistatus.response.propstat.prop.resourcetype.collection"
				      ref->name,
	int patlen = strlen(pattern);

				delete_branch = 1;
		if (check_request->state == RUN_FETCH_PACKED &&
			release_http_object_request(obj_req);
	struct buffer out_buffer = { STRBUF_INIT, 0 };
				fprintf(stderr, "    sent %s\n",
	struct remote_ls_ctx ls;
	request->slot = NULL;
		fprintf(stderr, "Unable to start PUT request\n");
	/*
#define DAV_PROP_LOCKEX (1u << 1)
				return NULL;
static struct object_list **process_tree(struct tree *tree,
	struct slot_results results;
	free_tree_buffer(tree);
				oid_to_hex(&request->obj->oid),
			*lock_flags |= DAV_PROP_LOCKEX;
	int lock_flags = 0;
		return -1;
	if (strlen(path) != the_hash_algo->hexsz + 1)
		if (!strcmp(ctx->name, DAV_CTX_LOCKENTRY)) {
}
		}

	if (delete_branch && rs.nr != 1)
static void one_remote_ref(const char *refname)
#define MAXDEPTH 5

	switch (http_get_info_packs(repo->url, &repo->packs)) {

	struct curl_slist *dav_headers = http_copy_default_headers();
			}
}
			XML_SetElementHandler(parser, xml_start_tag,
	char *hex = oid_to_hex(&request->obj->oid);
		return;
	free(ctx->cdata);
	obj->flags |= FETCHING;
	slot = obj_req->slot;
	/* If it's a symref, set the refname; otherwise try for a sha1 */
struct remote_lock {
	git_zstream stream;
			free(ctx.name);

			if (helper_status)
		slot->results = &results;
}
				     results.curl_result, results.http_code);
		/* Set up revision info for this refspec */
			repo->path_len = strlen(repo->url);
			request->state = ABORTED;
			}




			if (results.curl_result != CURLE_OK &&
	strbuf_addf(&out_buffer.buf, LOCK_REQUEST, escaped);
		if (request->obj->flags & LOCAL) {
#include "argv-array.h"
	request->next = request_queue_head;
#endif
	return lock_flags;
		add_fetch_request(obj);
static signed char remote_dir_exists[256];
	obj->flags |= SEEN;
	if (!(ls->dentry_flags & IS_DIR))
			remote_dir_exists[request->obj->oid.hash[0]] = 1;
		request->state = RUN_MOVE;
	}

#define XML_STATUS_ERROR 0

		} else {
		/* Update the remote branch if all went well */
	struct remote_lock *prev = repo->locks;
	COMPLETE

	struct active_request_slot *slot;

				}
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite_null);
		setup_revisions(commit_argv.argc, commit_argv.argv, &revs, NULL);
{
		strbuf_reset(&buf);

				/*

{
					      xml_end_tag);
	}
}
		lock->start_time = time(NULL);
	} else if (!strcmp(ctx->name, DAV_PROPFIND_RESP)) {
		slot = get_active_slot();

		int namelen = strlen(name);
			ctx.cdata = NULL;
	if (!o) {
	char *ep;
			continue;
				branch);
				error("remote '%s' is not an ancestor of\n"
static int aborted;
	}

}
				fprintf(stderr, "XML error: %s\n",
	obj->flags |= REMOTE;

	char *url;
			continue;
int cmd_main(int argc, const char **argv)
		if (request->curl_result == CURLE_OK) {
#define IS_DIR (1u << 0)
	struct strbuf buf = STRBUF_INIT;
	enum transfer_state state;
		release_http_pack_request(preq);
			aborted = 1;
	struct strbuf in_buffer = STRBUF_INIT;
	strbuf_addstr(&buf, "Destination: ");
				     "If you are sure you want to delete it,"
			"Unable to fetch ref %s from %s\n",

{
		} else if (pushing && request->state == NEED_PUSH) {
	return rc;
	escaped = xml_entities(repo->url);

	slot = get_active_slot();
}
			if (!lock_flags)
		free(url);
{
	struct transfer_request *request =
	}
		finish_all_active_slots();
		if (is_null_oid(&head_oid))
			if (helper_status)
{
	/*
			}
	is_running_queue = 1;
	strbuf_addf(&out_buffer.buf, "%s\n", oid_to_hex(oid));
		if (is_null_oid(&remote_ref->old_oid))
	int delete_branch = 0;

	dav_headers = curl_slist_append(dav_headers, "Depth: 0");
	lock->timeout = -1;
	if (!strcmp(ls->path, ls->dentry_name) && (ls->dentry_flags & IS_DIR)) {
	struct active_request_slot *slot;
	}
#define DAV_PROP_LOCKWR (1u << 0)
				continue;
			preq = (struct http_pack_request *)request->userData;
	}
		request->state = RUN_PUT;


	struct refspec rs = REFSPEC_INIT_PUSH;
			XML_ParserFree(parser);
{
	case HTTP_MISSING_TARGET:
	char *url = xstrfmt("%s%s", repo->url, path);
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);

	/* Ignore remote objects that don't exist locally */

	return lock;
	curl_setup_http_get(slot->curl, request->url, DAV_MKCOL);
	/* match them up */
#ifdef USE_CURL_MULTI

		}
	request->state = NEED_PUSH;
static int helper_status;
/* DAV XML properties */
}
			continue;
		return p;
}
			oid_to_hex(&ref->old_oid), oid_to_hex(&ref->new_oid));

	slot->callback_func = process_response;


	new_refs = 0;

	int rc = 0;
		}
	dav_headers = curl_slist_append(dav_headers, "Content-Type: text/xml");
{
	RUN_FETCH_LOOSE,

	raise(signo);
	preq->lst = &repo->packs;

			}
		} else {
{
 * should _only_ heed the information from that file, instead of trying to
						XML_GetErrorCode(parser)));

static int add_send_request(struct object *obj, struct remote_lock *lock)
			ctx.userData = lock;
	if (remote_dir_exists[obj->oid.hash[0]] == -1)
		commit->object.flags |= LOCAL;
#define LOCK_REFRESH 30
				 * commits at the remote end and likely
	stream.avail_in = len;
			if (helper_status)
static int push_verbosely;
	char *hex = oid_to_hex(&request->obj->oid);
			fprintf(stderr, "Unable to lock remote branch %s\n",
#include <xmlparse.h>
			prev = prev->next;
static int get_oid_hex_from_objpath(const char *path, struct object_id *oid)
#define DAV_LOCK_OK (1u << 2)

				if (strcmp(ls->dentry_name, ls->path) &&
			continue;
	one_remote_object(&oid);
	fprintf(stderr, " which contains %s\n", oid_to_hex(&request->obj->oid));
static void release_request(struct transfer_request *request)
		c++;
			memcpy(lock->tmpfile_suffix + 1, hash_to_hex(lock_token_hash), the_hash_algo->hexsz);
		if (start_active_slot(slot)) {
		    !ref->force) {
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, fread_buffer);
			fprintf(stderr, "    sending %d objects\n",
		if (results.curl_result != CURLE_OK) {
		one_remote_ref(ls->dentry_name);
	char *escaped;

#define DAV_CTX_LOCKENTRY ".multistatus.response.propstat.prop.supportedlock.lockentry"
		return 0;
{
	while ((commit = get_revision(revs)) != NULL) {

			if (path) {
				if (strncmp(path, url, repo->path_len))
		fprintf(stderr, "Getting pack list\n");
	int rc = 0;
		curl_write_callback write_fn)


	struct packed_git *target;
{
	const char *c = strchr(name, ':');
/* extract hex from sharded "xx/x{38}" filename */
/* Remember to update object flag allocation in object.h */
			if (!refresh_lock(lock)) {
{
{
	/* Find the remote branch(es) matching the specified branch name */
	if (!start_active_slot(preq->slot)) {
#define DAV_LOCK "LOCK"
		ctx->name = xrealloc(ctx->name, new_len);
	stream.avail_in = hdrlen;
	dav_headers = curl_slist_append(dav_headers, request->dest);

				force_delete = 1;

	if (!force) {
				free(url);
		struct object *obj = entry->item;
	struct remote_lock *ref_lock = NULL;
		} else if (!strcmp(ctx->name, DAV_CTX_LOCKTYPE_EXCLUSIVE)) {
		goto cleanup;

	}
static void start_fetch_packed(struct transfer_request *request)

			ctx.cdata = NULL;
}

	} while (request_queue_head && !aborted);
struct remote_ls_ctx {
		if (results.curl_result == CURLE_OK) {
}
		strbuf_release(&out_buffer.buf);
					results.curl_result, results.http_code);

	char *url;
		new_refs++;

static char *xml_entities(const char *s)
		}
	curl_easy_setopt(slot->curl, CURLOPT_ERRORBUFFER, request->errorstr);
		    !is_null_oid(&ref->old_oid) &&
};
	long http_code;
static int refresh_lock(struct remote_lock *lock)
			lock->owner = xstrdup(ctx->cdata);
		return;
			start_fetch_loose(request);
static struct transfer_request *request_queue_head;
			XML_SetElementHandler(parser, xml_start_tag,
	char *name;

			XML_SetCharacterDataHandler(parser, xml_cdata);
		struct argv_array commit_argv = ARGV_ARRAY_INIT;
		request = next_request;
	struct curl_slist *dav_headers;
	if (request->headers != NULL)

	} else {
	request->http_code = request->slot->http_code;
			}
		return;
		struct object_array_entry *entry = revs->pending.objects + i;
	free(escaped);

#define DAV_MOVE "MOVE"
		}

{
				start_mkcol(request);
		return 0;
		lock->next = repo->locks;
static struct repo *repo;
{
	strbuf_addstr(&out_buffer.buf, PROPFIND_ALL_REQUEST);
		if (!rc)
			}
{
		int fail = 1;
		}
	}
		    !strcmp(check_request->url, preq->url)) {
	while (request != NULL) {
		if (!(commit->object.flags & UNINTERESTING))

{
	url = xstrfmt("%s%s", repo->url, path);
			}
#ifndef USE_CURL_MULTI
static void curl_setup_http_get(CURL *curl, const char *url,
			count += add_send_request(&commit->object, lock);
		if (!has_object_file(&head_oid))
	slot->callback_data = request;

{
			enum XML_Status result;
		}

		if (symref)
			fprintf(stderr, "UNLOCK HTTP error %ld\n",

	int old_namelen, new_len;
#define DAV_MKCOL "MKCOL"
static int get_delta(struct rev_info *revs, struct remote_lock *lock)

	}
	struct remote_lock *next;
		strbuf_reset(&buf);
				fprintf(stderr, "XML error: %s\n",
			result = XML_Parse(parser, in_buffer.buf,
				start_put(request);
	}

	request->buffer.posn = 0;
	struct packed_git *target;

static void get_dav_remote_heads(void)

		FREE_AND_NULL(ls->dentry_name);
		if (results.curl_result == CURLE_OK)


		return error("Unable to start DELETE request");
					   in_buffer.len, 1);

			    !ref_newer(&ref->peer_ref->new_oid,
	curl_setup_http(slot->curl, url, DAV_PROPFIND,
		obj_req = (struct http_object_request *)request->userData;
	struct transfer_request *next_request;
			if (!strcmp(arg, "-h"))
{
		fprintf(stderr,
		unlock_remote(lock);
		return;

{


 * NEEDSWORK: remote_ls() ignores info/refs on the remote side.  But it
	void (*userFunc)(struct xml_ctx *ctx, int tag_closed);
{

		fprintf(stderr, "Unable to start PROPFIND request\n");
static void check_locks(void)
		if (!force_all &&

					 p);

	if (!locking_available()) {
	append_remote_object_url(&buf, repo->url, hex, 0);
			fprintf(stderr,	"PUT %s failed, aborting (%d/%ld)\n",
			return error("Remote HEAD symrefs too deep");

					"Unable to create branch path %s\n",

		}
			ctx.len = 0;
		finish_all_active_slots();
	preq = new_http_pack_request(target, repo->url);
}
/* get_dav_token_headers options */
		if (!strcmp(ctx->name, DAV_PROPFIND_RESP) && ls->dentry_name) {
	struct transfer_request *request;
	FREE_AND_NULL(ctx->cdata);
	strbuf_release(&in_buffer);
	dav_headers = get_dav_token_headers(lock, DAV_HEADER_LOCK);
	struct commit *head = lookup_commit_or_die(head_oid, "HEAD");
		fprintf(stderr, "Unable to start GET request\n");
	struct xml_ctx ctx;
	entry->item = obj;
	struct curl_slist *dav_headers = http_copy_default_headers();
	}

		if (obj->flags & (UNINTERESTING | SEEN))
{
	curl_setup_http_get(slot->curl, lock->url, DAV_UNLOCK);
		}
		while (prev && prev->next != lock)

	slot = get_active_slot();
	time_t start_time;
	struct strbuf buffer = STRBUF_INIT;
				 * we know that the remote ref is not

	target = find_sha1_pack(request->obj->oid.hash, repo->packs);
	request->headers = NULL;

	int *lock_flags = (int *)ctx->userData;
						XML_GetErrorCode(parser)));
	}
	request->url = strbuf_detach(&buf, NULL);
		goto cleanup;

	if (tag_closed && ctx->cdata) {
			fprintf(stderr, "Unable to delete remote branch %s\n",
		ret = 1;


		free(ref);
	request->state = NEED_FETCH;
	struct name_entry entry;
				error("Could not remove %s", ref->name);
}
		}

	slot = get_active_slot();
		if (obj->type == OBJ_BLOB) {
						  ls->userData);

	if (start_active_slot(slot)) {
static int push_all = MATCH_REFS_NONE;
	struct http_pack_request *preq;
	return 0;
		if (aborted || !update_remote(&ref->new_oid, ref_lock))

static void add_fetch_request(struct object *obj)
		dav_headers = curl_slist_append(dav_headers, buf.buf);
				const char *url = repo->url;
	slot = get_active_slot();
static struct object_list **add_one_object(struct object *obj, struct object_list **p)
	step_active_slots();
			}
	slot->results = &results;
	/* Try to get the request started, abort the request on error */
	if (obj->flags & (LOCAL | FETCHING))
	curl_setup_http(slot->curl, lock->url, DAV_PUT,

	struct active_request_slot *slot;
	ep = ctx->name + strlen(ctx->name) - strlen(c) - 1;
xml_start_tag(void *userData, const char *name, const char **atts)
	while (tree_entry(&desc, &entry))

			if (result != XML_STATUS_OK) {
	} else {
		/* Generate a list of objects that need to be pushed */
		(struct transfer_request *)callback_data;
			"Unable to fetch ref %s from %s\n",


		if (helper_status)
	static const char hex[] = "0123456789abcdef";

};
static void handle_lockprop_ctx(struct xml_ctx *ctx, int tag_closed)
			rc = 1;
		if (!verify_merge_base(&head_oid, remote_ref)) {

		remote_dir_exists[*parent] = 1;
#define REMOTE   (1u<<17)
		break;
}
			}

				}

	free(url);
		die("unknown pending object %s (%s)", oid_to_hex(&obj->oid), name);

	free(request);
		release_request(request);
	}
		repo->locks = lock->next;
	if (dry_run)
	struct curl_slist *dav_headers;
			entry = entry->next;

	void *unpacked;
		free(lock->owner);
	/* Make sure leading directories exist for the remote ref */

	sigchain_pop(signo);
	switch (http_get_strbuf(url, NULL, NULL)) {
		const char *branch = rs.items[i].src;
{
	/* Update remote server info if appropriate */
	struct http_pack_request *preq;
}
	if (o->type == OBJ_TAG) {
	struct ref *ref;
static int verify_merge_base(struct object_id *head_oid, struct ref *remote)
	request->url = NULL;
	git_deflate_end(&stream);
	stream.next_in = (void *)hdr;
static struct object_list **process_blob(struct blob *blob,
	if (lock->token == NULL || lock->timeout <= 0) {
		}
	return rc;
};
	void *userData;
static int force_all;
			prev->next = lock->next;
			fprintf(stderr, "Updating remote server info\n");
			lock->start_time = time(NULL);
	free(url);
	if (obj->flags & (REMOTE | PUSHING))
		goto cleanup;
				else {
		if (namelen != patlen && name[namelen - patlen - 1] != '/')
			new_refs++;
	repo->has_info_packs = remote_exists("objects/info/packs");
		usage(http_push_usage);
	CURLcode curl_result;
			}
	strbuf_release(&out_buffer.buf);
	struct strbuf in_buffer = STRBUF_INIT;
#endif
	if (start_active_slot(slot)) {

			if (helper_status)
#ifdef USE_CURL_MULTI
		request->slot = slot;

			fprintf(stderr,
	}
	struct curl_slist *dav_headers = http_copy_default_headers();
		remote_ref = refs;
		request->state = ABORTED;
	lock->refreshing = 1;
			}

		release_request(request);

			lock->tmpfile_suffix[0] = '_';
}

		    memcmp(name + namelen - patlen, pattern, patlen))

	if (!repo->url)
	struct slot_results results;
	struct curl_slist *dav_headers;
		fprintf(stderr,
	char *url;
	case HTTP_MISSING_TARGET:
#define DAV_CTX_LOCKTYPE_WRITE ".multistatus.response.propstat.prop.supportedlock.lockentry.locktype.write"
	}
		default:
	/* Try to get the request started, abort the request on error */
#ifdef EXPAT_NEEDS_XMLPARSE_H
		strbuf_addf(&buf, "Timeout: Second-%ld", lock->timeout);
static struct object_list *objects;
				}
};
	ctx->userFunc(ctx, 1);
	if (repo->has_info_refs) {

	struct xml_ctx ctx;
		ret = 0;
				     remote_ref->name, repo->url, pattern);
		switch (object_type(entry.mode)) {
		run_active_slot(slot);
		} else if (!strcmp(ctx->name, DAV_PROPFIND_NAME) && ctx->cdata) {

	stream.avail_out = size;
				       &ref->old_oid)) {

			     pattern);
				*lock_flags |= DAV_LOCK_OK;
			refname, repo->url);
	struct active_request_slot *slot;
			XML_ParserFree(parser);
			/* Subproject commit - not in this repository */
				printf("error %s lock error\n", ref->name);



			      repo->url, results.curl_result);
	ref->next = remote_refs;
		oidcpy(&ref->new_oid, &ref->peer_ref->new_oid);
	stream.next_out = (unsigned char *)request->buffer.buf.buf;
	}
			}

			&out_buffer, fwrite_buffer);
	unsigned int *parent = (unsigned int *)ls->userData;
		/* Remote HEAD must resolve to a known object */
	if (repo->locks == lock) {
	}
		check_locks();
	slot->results = &results;
		o = deref_tag(the_repository, o, ls->dentry_name, 0);
	}
	int hdrlen;
	}

	if (start_active_slot(slot)) {
}
	while (git_deflate(&stream, 0) == Z_OK)
	curl_setup_http(slot->curl, request->url, DAV_PUT,
		FREE_AND_NULL(request->url);

static void process_response(void *callback_data)
	long timeout;
		const char *custom_req, struct buffer *buffer,
	char path[] = "objects/XX/";
				if (helper_status)
		next_request = request->next;
		match++;

		if (request->curl_result == CURLE_OK) {

		check_request = check_request->next;

			continue;
	struct remote_lock *lock = NULL;

		      void (*userFunc)(struct remote_ls_ctx *ls),
	request->slot = preq->slot;


#include "cache.h"


#define DAV_UNLOCK "UNLOCK"
	entry->next = *p;
					XML_ErrorString(
	if (push_verbosely)
#define DAV_DELETE "DELETE"
	DAV_HEADER_LOCK = (1u << 1),
	 * may be required for updating server info later.
		/* Push missing objects to remote, this would be a
	struct remote_lock *lock = repo->locks;
			request->state = ABORTED;
		ep[1] = '\0';

		fprintf(stderr, "Unable to fetch %s, will not be able to update server info refs\n", oid_to_hex(&request->obj->oid));
#define DAV_PROPFIND_RESP ".multistatus.response"
		request->state = RUN_MKCOL;
	return dav_headers;
		      void *userData);
			p = process_blob(lookup_blob(the_repository, &entry.oid),
				"PUT error: curl result=%d, HTTP code=%ld\n",
	}
	slot->callback_data = request;
#else
		run_active_slot(slot);

		run_active_slot(slot);
			if (push_verbosely)
	struct active_request_slot *slot;
		ret = 0;
	struct remote_lock *locks;

		hash_to_hex(target->hash));

				usage(http_push_usage);

		run_active_slot(slot);
		while (entry && entry->next != request)
		refspec_appendn(&rs, argv, argc - i);
	request->headers = NULL;
	 */
			return error("The branch '%s' is not an ancestor "
		lock = next;


		char saved_character = ep[1];
};
	} else if (request->state == RUN_FETCH_PACKED) {
	curl_setup_http_get(slot->curl, request->url, DAV_MOVE);
	char *url;
#define DAV_ACTIVELOCK_TIMEOUT ".prop.lockdiscovery.activelock.timeout"
	if (preq == NULL) {
	RUN_PUT,
static void process_ls_object(struct remote_ls_ctx *ls)
	if (options & DAV_HEADER_TIMEOUT) {
	 * or is already in the request queue

	fill_active_slots();

		fetch_symref(symref, &symref, &head_oid);
		    request->http_code == 405) {
		/* Remote branch must resolve to a known object */
			fprintf(stderr, "Unable to get pack file %s\n%s",
	char hdr[50];
		obj = lookup_unknown_object(&ref->old_oid);
static void fetch_symref(const char *path, char **symref, struct object_id *oid)

};
			if (results.curl_result != CURLE_OK) {
	struct rev_info revs;
			fprintf(stderr, "MOVE %s failed, aborting (%d/%ld)\n",


	/* Remote branch must not be the remote HEAD */
	if (request->state != RUN_PUT && request->state != RUN_FETCH_PACKED) {
			continue;

			ctx.len = 0;
static void
	char *dentry_name;
	slot->callback_data = request;

				fprintf(stderr,
	int refreshing;
		strbuf_addf(&buf, "Lock-Token: <%s>", lock->token);
				request->url, curl_errorstr);
	struct transfer_request *check_request = request_queue_head;
	local_refs = get_local_heads();
	if (request->state == RUN_MKCOL) {
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	int flags;
			if (!strcmp(arg, "-d")) {
				results.curl_result, results.http_code);
		free(url);
		request->slot = slot;

			break;
	for (ref = remote_refs; ref; ref = ref->next) {
}
	int match;
	obj_req = new_http_object_request(repo->url, &request->obj->oid);
			if (!strcmp(arg, "--helper-status")) {
		ep[1] = saved_character;
		free(ref);
static void remove_locks_on_signal(int signo)
{
			continue;
#define DAV_PROPFIND_NAME ".multistatus.response.href"
{
		c = name;
				release_http_pack_request(preq);
		return;
				dry_run = 1;
	fill_active_slots();
					 oid_to_hex(&ref->old_oid));
				      repo->url);

			free(ctx.name);
	if (obj_req == NULL) {
	}
		aborted = 1;
			request->obj->flags |= REMOTE;
static int fill_active_slot(void *unused)
	curl_easy_setopt(curl, CURLOPT_IOCTLDATA, buffer);
{
		      void (*userFunc)(struct remote_ls_ctx *ls),

		if (prev)

	if (start_active_slot(slot)) {
		curl_setup_http_get(slot->curl, url, DAV_MKCOL);
	struct transfer_request *entry = request_queue_head;
	request_queue_head = request;
		      void *userData)
			start_fetch_packed(request);
}
	/* Make sure there isn't another open request for this pack */
	curl_easy_setopt(slot->curl, CURLOPT_HTTPHEADER, dav_headers);
			XML_SetUserData(parser, &ctx);
			}
	} else {
static void
			repo->can_update_info_refs = 1;
	curl_slist_free_all(dav_headers);
	if (http_get_strbuf(url, &buffer, NULL) != HTTP_OK)
				request->curl_result, request->http_code);
	/* Cut off trailing newline. */
	dav_headers = curl_slist_append(dav_headers, "Content-Type: text/xml");
			} else {
	int new_refs;
			if (!has_object_file(&ref->old_oid) ||

	struct remote_lock *lock;
	}
				error("no DAV locking support on %s",
		request->state = ABORTED;
}
				results.http_code);
	request = xmalloc(sizeof(*request));
	char *owner;
{
	strbuf_addf(&out_buffer.buf, PROPFIND_SUPPORTEDLOCK_REQUEST, escaped);
	if (start_active_slot(slot)) {
static void start_fetch_loose(struct transfer_request *request)
static int dry_run;
	char *dest;
static void handle_new_lock_ctx(struct xml_ctx *ctx, int tag_closed)
			ls->dentry_name, repo->url);
	if (match == 0)

				rc = -4;
		; /* nothing */
			return 0;
	strbuf_addf(buf, "%s\t%s\n",

				 * We do not have the remote ref, or

	 * Don't fetch the object if it's known to exist locally

	/* Run extra sanity checks if delete is not forced */
	remote_ls(path, (PROCESS_FILES | PROCESS_DIRS),
		goto cleanup;
			if (push_verbosely)
			return error("Remote branch %s resolves to object %s\nwhich does not exist locally, perhaps you need to fetch?", remote_ref->name, oid_to_hex(&remote_ref->old_oid));
			if (!strcmp(arg, "--verbose")) {
}
		if (fail)
	struct xml_ctx *ctx = (struct xml_ctx *)userData;

		c++;
#define PROPFIND_ALL_REQUEST "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:propfind xmlns:D=\"DAV:\">\n<D:allprop/>\n</D:propfind>"
				    oid_to_hex(&o->oid), ls->dentry_name);
			request->state = ABORTED;
			result = XML_Parse(parser, in_buffer.buf,
	slot = get_active_slot();
	/* Keep locks active */
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, custom_req);
		} else if (!strcmp(ctx->name, DAV_ACTIVELOCK_TOKEN)) {

#include "refs.h"

	return 1;
	struct active_request_slot *slot;
		else
				results.http_code);

{
	if (match != 1)
		const char *arg = *argv;
	default:
struct xml_ctx {
	}
		return error("No remote branch matches %s", pattern);
{
#define LOCAL    (1u<<16)
	setup_git_directory();
			/* We should attempt recovery? */
	url = xstrfmt("%s%s", repo->url, remote_ref->name);
	struct curl_slist *headers;
}
 * know about packed-refs).
static struct remote_lock *lock_remote(const char *path, long timeout)
static const char http_push_usage[] =
	if (repo->can_update_info_refs && !has_object_file(&ref->old_oid)) {
	ls.dentry_flags = 0;

				push_all = MATCH_REFS_ALL;
			lock_flags = 0;
	request->obj = obj;


		    curl_errorstr);
		if (results.curl_result != CURLE_OK) {
}

		}

	request->userData = obj_req;

	fprintf(stderr, "Removing remote branch '%s'\n", remote_ref->name);
		FREE_AND_NULL(request->url);
{
#endif
			*lock_flags &= DAV_LOCK_OK;

		if (results.curl_result != CURLE_OK)
	argv++;
		fetch_indices();
	struct slot_results results;
	if (aborted || !is_running_queue)
		}
				ls->userFunc(ls);
			}

		repo_init_revisions(the_repository, &revs, setup_git_directory());
	strbuf_release(&in_buffer);
static void process_ls_ref(struct remote_ls_ctx *ls)
		strbuf_addf(&buf, "If: (<%s>)", lock->token);

			obj->flags |= SEEN;
				continue;
	target = find_sha1_pack(obj->oid.hash, repo->packs);
	ls.dentry_name = NULL;
	struct slot_results results;
	char *url = xstrfmt("%s%s", repo->url, path);
				&buffer, fwrite_null);
		mark_edges_uninteresting(&revs, NULL, 0);
		}
	if (tag_closed) {
		fprintf(stderr, "  %s\n", ls->dentry_name);
		obj->flags |= REMOTE;
	curl_easy_setopt(slot->curl, CURLOPT_FILE, &in_buffer);
	NEED_FETCH,
	}
	if (match_push_refs(local_refs, &remote_refs, &rs, push_all)) {
	}
		if (!repo->url) {
			if (result != XML_STATUS_OK) {
		if (!push_all && !is_null_oid(&ref->old_oid))
	while (check_request) {
				update_remote_info_refs(info_ref_lock);
#endif
	strbuf_release(&in_buffer);
	void *userData;


				printf("ok %s\n", ref->name);
	slot->callback_func = process_response;

			enum XML_Status result;
			p = add_one_object(obj, p);
	remote_ls("refs/", (PROCESS_FILES | PROCESS_DIRS | RECURSIVE), process_ls_ref, NULL);
	for (i = 0; symref && i < MAXDEPTH; i++) {
	check_locks();
	ls.userFunc = userFunc;
		if (finish_http_object_request(obj_req) == 0)
			rc = 1;
	request->state = RUN_FETCH_PACKED;
	}
				continue;
	struct object_list *entry = xmalloc(sizeof(struct object_list));
	}
	} else if (request->state == RUN_FETCH_LOOSE) {
	int i;

 cleanup:

		} else if (!strcmp(ctx->name, DAV_CTX_LOCKTYPE_WRITE)) {
	}

	request_queue_head = request;
	} else {
			entry->next = request->next;
	if (parse_tree(tree) < 0)
					XML_ErrorString(
	free(ref);
					url = repo->path;
	size = git_deflate_bound(&stream, len + hdrlen);
			}
	} else {

"git http-push [--all] [--dry-run] [--force] [--verbose] <remote> [<head>...]\n";

	preq->slot->callback_func = process_response;
	request->slot = slot;
	}

				aborted = 1;
			release_http_pack_request(preq);
	RUN_MKCOL,
		free(ref);
	while (objects) {
					repo->path_len = strlen(repo->path);
					error("Parsed path '%s' does not match url: '%s'",
					printf("error %s cannot remove\n", ref->name);
					fail = 0;
#ifdef USE_CURL_MULTI

}
		if (oideq(&ref->old_oid, &ref->peer_ref->new_oid)) {
	curl_easy_setopt(curl, CURLOPT_NOBODY, 0);
		}
	}
#include "diff.h"

{
	curl_slist_free_all(dav_headers);
		error("Unable to start PROPFIND request on %s", repo->url);
			}
	}

	lock = xcalloc(1, sizeof(*lock));
	}
	slot->results = &results;

			error("cannot lock existing info/refs");
static void handle_remote_ls_ctx(struct xml_ctx *ctx, int tag_closed)
			release_request(request);
 */
	strbuf_addstr_xml_quoted(&buf, s);
				push_verbosely = 1;
#define FETCHING (1u<<18)
		objects = objects->next;
	if (repo->has_info_packs)
	int ret;
	default:
				continue;
	return strbuf_detach(&buf, NULL);
		} else {
#include "revision.h"
	do {
	struct remote_lock *lock = (struct remote_lock *)ctx->userData;
	int count = 0;
				 * an ancestor of what we are trying to
}
			p = process_blob((struct blob *)obj, p);
			} else if (ls->flags & PROCESS_FILES) {
		error("unable to access '%s': %s", url, curl_errorstr);
	http_init(NULL, repo->url, 1);
#endif
	path[9] = hex[val & 0xf];
static void add_remote_info_ref(struct remote_ls_ctx *ls)
}
	struct object *obj;
	char *cdata;
			continue;
	}
#include "tag.h"
		return 0;
static void remote_ls(const char *path, int flags,
	DAV_HEADER_IF = (1u << 0),
		if (ref_lock == NULL) {
		if (!ref->peer_ref)
	request->next = request_queue_head;
			return;
	repo->can_update_info_refs = 0;
		} else {
					"Unable to refresh lock for %s\n",
		lock = lock->next;
/* DAV request body templates */
		; /* nothing */

				printf("ok %s\n", ref->name);
	return rc;
	request->url = get_remote_object_url(repo->url, hex, 1);
	RUN_FETCH_PACKED,
	}
	git_deflate_init(&stream, zlib_compression_level);
	return ret;
			enum XML_Status result;
		curl_slist_free_all(request->headers);
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	}
		return p;
				lock_flags = 0;
				rc = -2;

	free(lock->token);
	if (options & DAV_HEADER_LOCK) {
		return 0;
	return 1;
					ls->userFunc(ls);
		revs.edge_hint = 0; /* just in case */
	if (!object_list_contains(objects, obj))
	return hex_to_bytes(oid->hash + 1, path, the_hash_algo->rawsz - 1);
				helper_status = 1;
	struct curl_slist *dav_headers = http_copy_default_headers();
	struct slot_results results;

					lock->url);
	} else {
}
		fprintf(stderr, "\n  from %s\n  to   %s\n",
#define LOCK_REQUEST "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:lockinfo xmlns:D=\"DAV:\">\n<D:lockscope><D:exclusive/></D:lockscope>\n<D:locktype><D:write/></D:locktype>\n<D:owner>\n<D:href>mailto:%s</D:href>\n</D:owner>\n</D:lockinfo>"
	dav_headers = curl_slist_append(dav_headers, "Depth: 1");
	ctx->cdata = xmemdupz(s, len);
	struct strbuf in_buffer = STRBUF_INIT;
	curl_setup_http_get(slot->curl, lock->url, DAV_LOCK);
		}
			ctx.len = 0;
	strbuf_release(&buffer.buf);

		}
		if (info_ref_lock)

				return;
	int path_len;

				fprintf(stderr,
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_fn);
		request->state = ABORTED;
		rc = 0;
	get_dav_remote_heads();
#include "exec-cmd.h"
	xsnprintf(timeout_header, sizeof(timeout_header), "Timeout: Second-%ld", timeout);
	struct buffer out_buffer = { STRBUF_INIT, 0 };
	struct strbuf buf = STRBUF_INIT;

{
				 * push.  Either way this can be losing
				printf("ok %s up to date\n", ref->name);
		if (obj->type == OBJ_TAG) {
{
{
		}
		if (is_null_oid(&ref->peer_ref->new_oid)) {
	escaped = xml_entities(ident_default_email());
	slot->callback_func = process_response;
					printf("error %s non-fast forward\n", ref->name);
#include "http.h"


}
		free(lock->token);
			printf("%s %s\n", !rc ? "ok" : "error", ref->name);
};
static int locking_available(void)
enum transfer_state {
			fprintf(stderr, "Unable to start MKCOL request\n");
/* Flags that remote_ls passes to callback functions */
static void remote_ls(const char *path, int flags,
	}
		run_request_queue();
		fprintf(stderr, "Unable to start GET request\n");
	curl_easy_setopt(curl, CURLOPT_PUT, 1);
	free(unpacked);

static void one_remote_ref(const char *refname);
					   in_buffer.len, 1);
{
			return error("Unable to resolve remote HEAD");
};

	strbuf_release(&buffer);
#include <expat.h>
	struct active_request_slot *slot;
			the_hash_algo->final_fn(lock_token_hash, &hash_ctx);
			XML_Parser parser = XML_ParserCreate(NULL);
	old_namelen = strlen(ctx->name);
	}
		const char *custom_req)
			return NULL;

		ctx->len = new_len;
		if (namelen < patlen ||
{
		}
	struct active_request_slot *slot;
	char *symref = NULL;
		FREE_AND_NULL(request->url);
			free(url);
				continue;
static int is_running_queue;
	slot = get_active_slot();
	if (skip_prefix(buffer.buf, "ref: ", &name)) {
	slot = get_active_slot();
	} else {
	struct buffer buffer;
		release_request(request);
{
	o = parse_object(the_repository, &ref->old_oid);
			goto cleanup;
	struct object *o;
	if (!skip_prefix(path, "objects/", &path) ||
	struct http_object_request *obj_req;

#define PUSHING  (1u<<19)

#include "packfile.h"
	if (tag_closed) {
			return error("Remote HEAD resolves to object %s\nwhich does not exist locally, perhaps you need to fetch?", oid_to_hex(&head_oid));
	request->url = NULL;
				continue;

					      xml_end_tag);
		dav_headers = curl_slist_append(dav_headers, buf.buf);
		}
		if (delete_remote_branch(branch, force_delete) == -1) {
		repo->can_update_info_refs = 0;
			start_move(request);
	while (ep) {


#ifdef USE_CURL_MULTI
					oid_to_hex(&request->obj->oid));
	request->userData = preq;
		}
		} else {

	while (git_deflate(&stream, Z_FINISH) == Z_OK)
#define RECURSIVE     (1u << 2)
	}
			XML_ParserFree(parser);
	struct slot_results results;
	return p;
			aborted = 1;
	hdrlen = xsnprintf(hdr, sizeof(hdr), "%s %"PRIuMAX , type_name(type), (uintmax_t)len) + 1;

	memset(remote_dir_exists, -1, 256);
				str_end_url_with_slash(ls->dentry_name, &ls->dentry_name);
			char *path = ctx->cdata;
		} else {

struct transfer_request {
		rc = 1;
{
				 * we were not up to date to begin with.
	request = xmalloc(sizeof(*request));
	ctx->userFunc(ctx, 0);
	slot->results = &results;
{

				repo->path = strchr(path+2, '/');
}
		return;
static int update_remote(const struct object_id *oid, struct remote_lock *lock)
	step_active_slots();
			&request->buffer, fwrite_null);
	if (repo->has_info_refs && new_refs) {
  XML_STATUS_ERROR = 0
static void run_request_queue(void)
#ifdef USE_CURL_MULTI
	int has_info_packs;
{
				path = strstr(path, "//");

	request->lock = lock;
			ctx.userFunc = handle_lockprop_ctx;
	struct curl_slist *dav_headers;
#ifdef USE_CURL_MULTI
			strbuf_addf(buf, "%s\t%s^{}\n",
		run_active_slot(slot);
			the_hash_algo->init_fn(&hash_ctx);
	if (request == request_queue_head) {
				oid_to_hex(&request->obj->oid),
		   convenient time to pack them first if appropriate. */
				fprintf(stderr, "XML error: %s\n",
		get_oid_hex(buffer.buf, oid);
}


	free(repo);
	strbuf_init(&request->buffer.buf, size);
		break;

static void update_remote_info_refs(struct remote_lock *lock)
			ctx.userData = &lock_flags;
			}
			ctx.userFunc = handle_new_lock_ctx;
			XML_SetUserData(parser, &ctx);
						  ls->userFunc,
		if (!has_object_file(&remote_ref->old_oid))
	struct object_list **p = &objects;
	struct buffer buffer = { STRBUF_INIT, 0 };
		if (strcmp(ref->name, ref->peer_ref->name))
			if (ls->dentry_flags & IS_DIR) {
}
	slot = get_active_slot();
	return in_merge_bases(branch, head);

		fprintf(stderr, "updating '%s'", ref->name);
#include "repository.h"
		free(url);
	enum object_type type;
			}
#define PREV_BUF_SIZE 4096

	for (i = 0; i < revs->pending.nr; i++) {
	repo->has_info_refs = remote_exists("info/refs");
	if (!obj)
	ABORTED,
	struct strbuf *buf = (struct strbuf *)ls->userData;

		return;
static void remove_locks(void)
	struct object_id oid;
	free(lock);
	if (http_fetch_ref(repo->url, ref) != 0) {
		aborted = 1;
#endif
	check_locks();

}

#include "sigchain.h"

	if (start_active_slot(slot)) {
		}
		if (objects_to_send)
	path++; /* skip '/' */
		pushing = 1;
	DAV_HEADER_TIMEOUT = (1u << 2)
	remote_dir_exists[val] = 0;
				fprintf(stderr,
		get_remote_object_list(obj->oid.hash[0]);
		if (!(objects->item->flags & UNINTERESTING))
		return -1;
#define DAV_PROPFIND "PROPFIND"
	char errorstr[CURL_ERROR_SIZE];
	strbuf_release(&out_buffer.buf);
	char *url = xstrfmt("%s%s", repo->url, path);
		strbuf_release(&out_buffer.buf);
	request->curl_result = request->slot->curl_result;
			if (*ctx->cdata == 'h') {
	while (lock) {
{
				     " run:\n\t'git http-push -D %s %s'",
			*lock_flags |= DAV_PROP_LOCKWR;
	ls.path = xstrdup(path);
{
	return count;
				ref->name);
	} else if (request->state == RUN_MOVE) {
	if (hex_to_bytes(oid->hash, path, 1))
				      ref->peer_ref->name);
		}
			&out_buffer, fwrite_buffer);
	RUN_MOVE,
	struct remote_lock *lock = repo->locks;
	 */
	for (request = request_queue_head; request; request = request->next) {
#ifdef USE_CURL_MULTI
static void
			start_put(request);
	/* Keep locks active */
						XML_GetErrorCode(parser)));
	unsigned char lock_token_hash[GIT_MAX_RAWSZ];
	remote_ls("refs/", (PROCESS_FILES | RECURSIVE),
			die("revision walk setup failed");
		argv_array_clear(&commit_argv);
				      "need to pull first?",

	remove_locks();

	free(request->url);
				oid_to_hex(&request->obj->oid),
			lock->token = xstrdup(ctx->cdata);
		dav_headers = curl_slist_append(dav_headers, buf.buf);
	/* Remove a remote branch if -d or -D was specified */
	struct object *obj;
			if (!strcmp(arg, "--all")) {
	unsigned long len;
		fprintf(stderr,	"  fetch %s for %s\n",
		} else {
	check_locks();
			argv_array_pushf(&commit_argv, "^%s",
	if (start_active_slot(slot)) {
	}
	}

		if (!strcmp(remote_ref->name, symref))

	struct packed_git *packs;
	curl_easy_setopt(curl, CURLOPT_IOCTLFUNCTION, ioctl_buffer);
		if (start_active_slot(slot)) {
				delete_branch = 1;
		obj = parse_object(the_repository, oid);
	else
	slot->results = &results;
	fetch_symref("HEAD", &symref, &head_oid);

			    (*lock_flags & DAV_PROP_LOCKWR)) {
	*ep = 0;
	struct commit *branch = lookup_commit_or_die(&remote->old_oid,
	oidclr(oid);
		if (entry)
	*p = entry;
	dav_headers = curl_slist_append(dav_headers, "Content-Type: text/xml");
		argv_array_push(&commit_argv, oid_to_hex(&ref->new_oid));

	request->state = RUN_FETCH_LOOSE;
	}
	struct xml_ctx ctx;
xml_end_tag(void *userData, const char *name)

			fprintf(stderr, "    done\n");
					url);
	if (options & DAV_HEADER_IF) {

	obj->flags |= LOCAL;
			break;
	ls.flags = flags;

