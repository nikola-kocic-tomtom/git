	trace2_region_enter("fetch-pack", "parse_remote_refs_and_find_cutoff", NULL);
}
		if (extra.nr) {
		packet_buf_write(&req_buf, "have %s\n", oid_to_hex(oid));
static int cmp_ref_by_name(const void *a_, const void *b_)
static int rev_list_insert_ref(struct fetch_negotiator *negotiator,
			if (args->deepen_relative) strbuf_addstr(&c, " deepen-relative");
		}
}
		}
}
		die(_("--stateless-rpc requires multi_ack_detailed"));
		     int *haves_to_send, int *in_vain)

		if (!args->keep_pack)
					    the_repository);
			if (got_ready)
			if (strstr(p, "common"))
		item = string_list_insert(&names, ref[src]->name);
	if (!peek) {
	packet_reader_init(&reader, fd[0], NULL, 0,
		packet_buf_write(req_buf, "deepen-since %"PRItime, max_age);
		if (!sought[i])
	strbuf_release(&promisor_name);
			process_section_header(&reader, "packfile", 0);
		o = parse_object(the_repository, &t->tagged->oid);
	for ( ; refs ; refs = refs->next) {
					&extra);
		 */
 * The cutoff time for recency is determined by this heuristic: it is the
				 const struct ref *orig_ref,
		 */

		for (i = 0; i < si->nr_theirs; i++)
{
	if (args->deepen)
		write_promisor_file(*pack_lockfile, sought, nr_sought);
				continue;
	if (version == protocol_v2) {
	}
{
			      oid_to_hex(&complete->item->object.oid));
 * not consumed); if 0, the line will be consumed and the function will die if
		       struct oid_array *shallow,
		 */
		return 0;
			ref->match_status = REF_MATCHED;
				int cmp = strcmp(ref->name, sought[i]->name);
	 */
			/* When cloning, it is not unusual to have
			strbuf_setlen(&req_buf, state_len);
			alternate_shallow_file = NULL;
	va_start(params, fmt);
		if (server_supports("no-done")) {
			commit_lock_file(&shallow_lock);

		else
					retval = 0;
	save_commit_buffer = 0;
				if (!parse_object(the_repository, &oid))

}
		}
#include "sideband.h"
			expand_list_objects_filter_spec(&args->filter_options);
			/*
			if (deepen_since_ok)    strbuf_addstr(&c, " deepen-since");
					 struct ref **refs)
	int len;
		case REF_MATCHED:

	static int initialized;
		free((char *)path);
			 * no common commit.
			/* Check for shallow-info section */
		if (!found)
		print_verbose(args, _("Server supports %s"), "side-band");
		/*
static void send_request(struct fetch_pack_args *args,
		die(_("Server does not support --deepen"));
	len = reader->pktlen;

		warning("filtering not recognized by server, ignoring");
	if (!args->deepen) {
static void receive_wanted_refs(struct packet_reader *reader,
		close(cmd.out);
		else
	}
			die(_("unexpected wanted-ref: '%s'"), reader->line);
				break;
static int no_done;
			switch (process_acks(negotiator, &reader, &common)) {
				die(_("no shallow found: %s"), reader->line);
 * the commit time of.

{
static void mark_tips(struct fetch_negotiator *negotiator,
}
	oid_array_clear(&ref);

					die(_("no shallow found: %s"), reader.line);
{
			BUG("Protocol V2 does not provide shallows at this point in the fetch");
	}
			use_sideband = 2;

	struct object *o = parse_object(the_repository, oid);
	}
		consume_shallow_list(args, &reader);
		     struct strbuf *req_buf,
		add_common(&req_buf, common);
	return ret;
					die(_("error in object: %s"), reader.line);
 all_done:
			      int *haves_to_send, int *in_vain,
			if (args->use_thin_pack) strbuf_addstr(&c, " thin-pack");
	 */
			      int sideband_all)
{
	if (skip_prefix(reader->line, "ACK ", &arg)) {
		args->use_thin_pack = 0;

	int suffix_stripped;
		}
		/*
			if (get_pack(args, fd, pack_lockfile, sought, nr_sought))
		if (!no_dependents &&
	int i;
		cb(negotiator, cache.items[i]);
	struct ref *ref = copy_ref_list(orig_ref);

		 * through demux->out.
	git_config_get_bool("transfer.fsckobjects", &transfer_fsck_objects);
			warning(_("no common commits"));
				if (get_oid_hex(arg, &oid))
 */
		ref = sought[i];
};
		case REF_NOT_MATCHED:
		} else
	int src, dst;
				register_shallow(the_repository, &oid);
	NAK = 0,
		if (do_keep && (args->lock_pack || unpack_limit)) {
		die(_("error in sideband demultiplexer"));
	va_end(params);
				continue;
		 */
}
	}
 */
		if (!t->tagged)
	}


		/* If we aren't using the stateless-rpc interface
		 */
	for (src = dst = 0; src < nr; src++) {
			count = count * 11 / 10;
		if (pack_lockfile)
		warning("filtering not recognized by server, ignoring");
{
		struct ref **found;
	/* Send request */
		reader.use_sideband = 1;
			/* make sure that it is parsed as shallow */
					     NULL, 0);
#include "refs.h"
					 (struct commit *)o);

				state = FETCH_GET_PACK;
		const char *spec =
			/* Process ACKs/NAKs */
{
	if (server_supports("no-progress"))
		int keep = 0;
	if (server_supports("shallow"))
		server_supports_filtering = 1;
	}

		/*
#include "version.h"
		if (!o)
				state = FETCH_SEND_REQUEST;
		alternate_shallow_file = NULL;
				case ACK_ready:
							OBJECT_INFO_SKIP_FETCH_OBJECT))

static void filter_refs(struct fetch_pack_args *args,
	}
	static struct alternate_object_cache cache;
	}
	}
	} else if (args->deepen_not)
	struct ref *ref_cpy;
{
		for_each_cached_alternate(negotiator, insert_one_alternate_object);

			alternate_shallow_file =
	}

	if (server_supports("multi_ack_detailed")) {
			packet_buf_write(req_buf, "deepen-not %s", s->string);
						in_vain = 0;
{
	if (!args->verbose)
			/*
				return ACK_ready;
	}

		args->connectivity_checked = 1;
	else
static int unpack_limit = 100;
	int unshallow_received = 0;
				if (!lookup_object(the_repository, &oid))
			break;
}
static int find_common(struct fetch_negotiator *negotiator,
#include "config.h"
						 * seen.
				break;
		 * same.
			if (got_continue && MAX_IN_VAIN < in_vain) {
	for (i = 0; i < nr_sought; i++) {
				state = FETCH_PROCESS_ACKS;
			if (starts_with(reader->line, "unshallow "))
	else if (server_supports("side-band")) {
	if (server_supports("filter")) {
	}
		 * The protocol does not support requesting that only the
		if (args->use_thin_pack)
	timestamp_t cutoff = 0;
				break;
			continue;
	struct oidset_iter iter;
			continue; /* already have it */

	return dst;
	}
			continue;

		fprintf(output, "%s %s\n", oid_to_hex(&sought[i]->old_oid),
		assign_shallow_commits_to_refs(si, NULL, NULL);
		}
static int process_section_header(struct packet_reader *reader,

	int agent_len;
		    ((o = lookup_object(the_repository, remote)) != NULL) &&
						 struct object *))
{
			oid_array_append(shallows, &oid);
	process_section_header(reader, "wanted-refs", 0);
	struct oid_array ref = OID_ARRAY_INIT;
			commit_list_insert(commit, &complete);
{
		if (!is_unmatched_ref(ref))
	}
		demux.proc = sideband_demux;
		case FETCH_CHECK_LOCAL:
		    int xd[2], char **pack_lockfile,
			unshallow_received = 1;
	cmd.in = demux.out;
		write_shallow_commits(req_buf, 1, NULL);
	if (find_common(negotiator, args, fd, &oid, ref) < 0)
}
			error(_("Server does not allow request for unadvertised object %s"),

		return 0;
		args->self_contained_and_connected =
 * give up traversing our history.

		print_verbose(args, _("Server supports %s"), "filter");
					NULL);
		send_sideband(fd, -1, buf->buf, buf->len, LARGE_PACKET_MAX);
		next = ref->next;

		negotiator->add_tip(negotiator, (struct commit *)o);

			      struct fetch_pack_args *args,
	i = 0;
					int was_common;
	}
		print_verbose(args, _("Server supports filter"));
		for (i = 0; i < si->shallow->nr; i++)
	strbuf_release(&req_buf);
}
		return;

		args->deepen = 1;
		    keep_name);
			consume_shallow_list(args, &reader);
				die(_("git fetch-pack: fetch failed."));
static void fetch_pack_setup(void)
	*refs = newlist;
			continue;
	if (!use_sideband)

	return 0;
				oid_array_append(&extra, &oid[i]);
	clear_shallow_info(&si);
/* Remember to update object flag allocation in object.h */
	FETCH_DONE,
	const char *arg;

 * Mark recent commits available locally and reachable from a local ref as
		die(_("expected packfile to be sent after 'ready'"));
			struct object_id oid;
	}
			ref->next = NULL;

				args->deepen = 1;
	}

		       struct ref **sought, int nr_sought,
			if (status[i])
				continue;

			count <<= 1;
static struct strbuf fsck_msg_types = STRBUF_INIT;
	int ret;
	struct async demux;
		       int fd[],
					if (args->stateless_rpc
	if (reader->status != PACKET_READ_FLUSH &&
	}

		else
		}
		 * local ref), we tell them we have it but do not have to

		if (is_valid_msg_type(var, value))
	int count = 0, flushes = 0, flush_at = INITIAL_FLUSH, retval;
			if (args->include_tag)   strbuf_addstr(&c, " include-tag");
{
}
	}
		found = bsearch(end, sought, nr_sought, sizeof(*sought),


	}
		int ack = get_ack(&reader, result_oid);
				if (negotiator)
	add_wants(args->no_dependents, wants, &req_buf);
				    struct shallow_info *si,
	*haves_to_send = next_flush(1, *haves_to_send);
		/*
		packet_buf_write(&req_buf, "include-tag");
			sought[i]->name);
}
						 * Reset in_vain because an ack
		use_sideband = 1;

			goto cleanup;
	if (args->deepen_not) {
			flush_at = next_flush(args->stateless_rpc, count);
						state_len = req_buf.len;
					 args->server_options->items[i].string);
	} else {
	if (server_supports("allow-tip-sha1-in-want")) {
	}
					got_continue = 1;
					keep = 1; /* definitely have it */
cleanup:
#include "run-command.h"
	if (args->depth > 0 || args->deepen_since || args->deepen_not)

				cmp_name_ref);
	oidset_clear(&tip_oids);
	else
	} else {
	unsigned in_vain = 0;
static int cmp_name_ref(const void *name, const void *ref)

		       enum protocol_version version)
	}
	/* Increase haves to send on next round */
		}
		return;
			if (has_object_file(&oid[i]))

		if (!si->nr_ours && !si->nr_theirs) {
	struct oidset *loose_object_set;
					state = FETCH_SEND_REQUEST;

		 * we cannot trust the object flags).

struct ref *fetch_pack(struct fetch_pack_args *args,
		 * remote is also shallow, .git/shallow may be updated
			ref->match_status = REF_UNADVERTISED_NOT_ALLOWED;
#include "packfile.h"


	}
static int deepen_since_ok;
		state_len = 0;

		strbuf_addf(&fsck_msg_types, "%cskiplist=%s",
		packet_flush(fd[1]);
		 * sent because they are directly specified as a "want".
	if (is_repository_shallow(the_repository))
		packet_buf_write(req_buf, "done\n");
		agent_supported = 1;
			struct ref **refs,
		 * we don't need to retain the headers.
		}

		 */
};
	}
						   || ack != ACK_common)
	packet_reader_init(&reader, fd[0], NULL, 0,
			print_verbose(args, _("Server version is %.*s"),
	struct packet_reader reader;
	return strcmp(a->name, b->name);
	if (nr_sought)
			   struct shallow_info *si)
{
		parse_list_objects_filter(&args->filter_options, "blob:none");
	git_config_get_bool("repack.usedeltabaseoffset", &prefer_ofs_delta);
	oidset_clear(&common);
#include "transport.h"
		}
			packet_flush(fd[1]);

				    char **pack_lockfile)
	fetching = 0;
		else
		packet_buf_write(&req_buf, "agent=%s", git_user_agent_sanitized());
	return 0;
				}
	else {
		print_verbose(args, _("Server supports %s"), "thin-pack");
	if (server_supports_feature("fetch", "filter", 0) &&
static int server_supports_filtering;
			if (xgethostname(hostname, sizeof(hostname)))
		}
			add_refs_to_oidset(&tip_oids, newlist);

			       const char *refname,
	/*
	/*
		} else {
				struct ref **sought, int nr_sought)
				case ACK_common:
		switch (state) {
			struct packet_reader *reader,
			if (use_sideband == 1)  strbuf_addstr(&c, " side-band");
	struct oid_array shallows_scratch = OID_ARRAY_INIT;
		if (args->check_self_contained_and_connected)
	struct shallow_info si;
		const struct object_id *remote = &ref->old_oid;
					 && !was_common) {

		cmd_name = "unpack-objects";
	int fetching;
		/* Send Done */
	struct ref *unmatched = NULL;
			sort_ref_list(&ref, ref_compare_name);

						/*

	int haves_to_send = INITIAL_FLUSH;
		case REF_UNADVERTISED_NOT_ALLOWED:
		packet_buf_write(&req_buf, "done");
			/* v2 supports these by default */
				(o->flags & COMPLETE)) {
		struct object *o;
		fetch_negotiator_init(r, negotiator);
		print_verbose(args, _("Server supports %s"), "allow-tip-sha1-in-want");
		print_verbose(args, _("Server supports %s"), "allow-reachable-sha1-in-want");
					 timestamp_t cutoff)
	}
			if (!args->stateless_rpc && count == INITIAL_FLUSH)
	packet_buf_flush(&req_buf);
		o->flags |= COMPLETE;
		return;
		die(_("error processing shallow info: %d"), reader->status);
			oid_array_append(&extra, &oid[si->theirs[i]]);
	if (reader->status != PACKET_READ_DELIM)
	while ((oid = oidset_iter_next(&iter))) {
				in_vain = 0;
			continue;
		*p == '\0' &&

			struct string_list_item *s = args->deepen_not->items + i;
		if (!args->no_dependents &&
				      void (*cb)(struct fetch_negotiator *,
		 * we cannot trust the object flags).
				case ACK:

		filter_refs(args, &ref, sought, nr_sought);
			unmatched = ref;
		args->no_progress = 0;
		 * In v0, these lines cannot cause refs to be rejected; do the
	git_config(fetch_pack_config_cb, NULL);
		opt.shallow_file = alternate_shallow_file;
		packet_flush(fd[1]);
	struct ref *ref, *next;
	}
		packet_buf_write(req_buf, "have %s\n", oid_to_hex(oid));
	git_config_get_int("transfer.unpacklimit", &transfer_unpack_limit);
		}
	/* return 0 if no common, 1 if there are common, or 2 if ready */
	while (state != FETCH_DONE) {

	} else {
			if (!args->no_dependents) {
			die(_("git fetch-pack: expected shallow list"));
static struct ref *do_fetch_pack(struct fetch_pack_args *args,
{
			print_verbose(args, "want %s (%s)", oid_to_hex(remote),
	}
			packet_buf_write(&req_buf, "server-option=%s",
			else
		die(_("expected shallow/unshallow, got %s"), reader->line);
	if (server_supports("thin-pack"))
 */
	FETCH_GET_PACK,
	}
	if (do_keep || args->from_promisor) {
	int ret = 0;
					   &shallows_scratch, &si,
	}
		 * shallow points that exist in the pack (iow in repo
		multi_ack = 0;
	ACK_ready
	    args->filter_options.choice) {
		struct check_connected_options opt = CHECK_CONNECTED_INIT;
		multi_ack = 2;
				/* fallthrough */
				if (everything_local(args, &ref))
#define MAX_IN_VAIN 256
	FETCH_SEND_REQUEST,
}
enum fetch_state {
							      result_oid);
	 * only if "ready" was sent in this section. The other sections
		die(_("expected no other sections to be sent after no 'ready'"));
	free(status);
		negotiator->known_common(negotiator,
			struct ref **sought, int nr_sought)
		} else
	if (git_env_bool("GIT_TEST_SIDEBAND_ALL", 1) &&
 * Returns 1 if every object pointed to by the given remote refs is available
}
		 * "blob:none" filter if no filter is already set. This works
		die(_("error processing wanted refs: %d"), reader->status);

		allow_unadvertised_object_request |= ALLOW_TIP_SHA1;
			if (multi_ack == 2)     strbuf_addstr(&c, " multi_ack_detailed");
		if (!use_ref_in_want || wants->exact_oid)
{
			continue;

			count <<= 1;
		die(_("Server does not support --shallow-since"));
			setup_alternate_shallow(&shallow_lock,
	 * This block marks all local refs as COMPLETE, and then recursively marks all
			   PACKET_READ_CHOMP_NEWLINE |
#include "remote.h"
	}
	} else {

	if (sideband_all)
					"--keep=fetch-pack %"PRIuMAX " on %s",
	const struct ref *b = *((const struct ref **)b_);
	int i, ret = 0;
	}
				 const struct fetch_pack_args *args)
			      ref->name);
	int pass_header = 0;
		print_verbose(args, _("Server supports %s"), "deepen-relative");
		print_verbose(args, _("Server supports %s"), "include-tag");
	if (pass_header)
		 * shallow and unshallow commands every time there
	if (si->nr_ours || si->nr_theirs) {

	struct repository *r = the_repository;
static void receive_shallow_info(struct fetch_pack_args *args,
	return mark_complete(oid);

	if (!si->shallow || !si->shallow->nr)
		else
{
		}
	ACK,
	return count ? retval : 0;
		die(_("Server does not support shallow requests"));
	if (fetch_fsck_objects >= 0

	sort_ref_list(&ref, ref_compare_name);
	/* add wants */
	if (version != protocol_v2 && !ref) {
{


	if (args->update_shallow) {
		struct oid_array extra = OID_ARRAY_INIT;

}
				if (unregister_shallow(&oid))
		packet_buf_write(&req_buf, "filter %s", spec);
		demux.data = xd;
		 * If that object is complete (i.e. it is an ancestor of a
			       const struct object_id *oid)
			goto all_done;
		if (skip_prefix(reader->line, "shallow ", &arg)) {
	retval = -1;
			int ack;
		setup_alternate_shallow(&shallow_lock, &alternate_shallow_file,
{
	if (server_supports("ofs-delta"))
 * COMPLETE. If args->no_dependents is false, also mark COMPLETE remote refs as
	if (!suffix_stripped)
			argv_array_push(&cmd.args, "--fsck-objects");
	struct pack_header header;
			continue;
{
			continue;
	return ref_cpy;
	/*
		packet_flush(fd[1]);
	if (!fetching) {
		/* xd[] is talking with upload-pack; subprocess reads from
			if (multi_ack == 1)     strbuf_addstr(&c, " multi_ack");
	}
		 * Do this only if args->no_dependents is false (if it is true,
	free_refs(unmatched);
					die(_("invalid unshallow line: %s"), reader.line);
	struct object_id oid;
		struct object_id *remote = &refs->old_oid;
			if (!get_oid_hex(arg, &oid)) {
			ref = sought[i];
#define INITIAL_FLUSH 16

		*pack_lockfile = index_pack_lockfile(cmd.out);


	struct child_process cmd = CHILD_PROCESS_INIT;
}
	if (packet_reader_peek(reader) != PACKET_READ_NORMAL)
		}
	 * Mark all complete remote refs as common refs.

		args->include_tag = 0;
	return 0;
				state = FETCH_SEND_REQUEST;
#define ALTERNATE	(1U << 1)
		for_each_alternate_ref(cache_one_alternate, &cache);
}
			if (strstr(p, "continue"))
{
					       &haves_to_send, &in_vain,
	struct ref **rm = cb_data;
				strbuf_addstr(&c, " filter");
			if (strstr(p, "ready"))
				return ACK;
	} else {
	FETCH_CHECK_LOCAL = 0,
		!parse_oid_hex(ref->name, &oid, &p) &&
	QSORT(sought, nr_sought, cmp_ref_by_name);
		       struct ref *refs)
				      agent_len, agent_feature);
	}
		goto done;
		print_verbose(args, _("Marking %s as complete"),
		struct commit *commit = (struct commit *)o;

		flushes--;

static inline void print_verbose(const struct fetch_pack_args *args,
					       reader.use_sideband))
	if (use_sideband) {

	}
		o = parse_object(the_repository, &ref->old_oid);
		if (src != dst)
			if (process_section_header(&reader, "wanted-refs", 1))
	struct ref **newtail = &newlist;
	mark_complete(&obj->oid);

			}
	 * obtained .keep filename if necessary
	struct packet_reader reader;
{
			mark_recent_complete_commits(args, cutoff);
	fetch_pack_config();
		    ((o = lookup_object(the_repository, remote)) != NULL) &&
		 */
						 * on the next RPC request so the peer knows
	output = xfopen(promisor_name.buf, "w");
	if (!obj || (obj->flags & ALTERNATE))
	return ref;
	if (args->depth > 0)
		if (agent_len)
				struct ref **sought, int nr_sought)
	si->ref = &ref;


 */
{
			continue;
	}

		oidset_insert(oids, &refs->old_oid);
	}
		const char *end;
	}
}
		 * rejected (unless --update-shallow is set); do the same.
	size_t state_len = 0;
{
		 * information below. If not, we need index-pack to do it for
#include "oidset.h"
			}
	reprepare_packed_git(the_repository);
		case FETCH_GET_PACK:
				continue;
						 */
		if (ntohl(header.hdr_entries) < unpack_limit)
	return ref;
		unpack_limit = transfer_unpack_limit;
	const struct object_id *oid;
		       int fd[2], struct object_id *result_oid,
	process_section_header(reader, "shallow-info", 0);
	if (server_supports_filtering && args->filter_options.choice) {
				 ntohl(header.hdr_version),
	/* it is no error to fetch into a completely empty repo */
				receive_wanted_refs(&reader, sought, nr_sought);
	}
	 * remote is also shallow, check what ref is safe to update
 * `section`.  If the value of `peek` is 1, the header line will be peeked (and
	}
			return;

		filter_refs(args, &ref, sought, nr_sought);
		struct object_id oid;

	if (args->no_progress)

	if (!si->nr_ours && !si->nr_theirs)
		deepen_since_ok = 1;
		const char *spec =
	else
{
struct loose_object_iter {
		ref_cpy = do_fetch_pack(args, fd, ref, sought, nr_sought,
	struct object *obj = parse_object(the_repository, oid);
			flushes--;

static struct ref *do_fetch_pack_v2(struct fetch_pack_args *args,
		allow_unadvertised_object_request |= ALLOW_REACHABLE_SHA1;

			if (no_done)            strbuf_addstr(&c, " no-done");
	if (args->no_dependents) {
}
static void add_refs_to_oidset(struct oidset *oids, struct ref *refs)
}

		oid_array_clear(&extra);
	    server_supports_v2("server-option", 1)) {
	return 0;
	else
		}
			/* Filter 'ref' by 'sought' and those that aren't local */
			rollback_lock_file(&shallow_lock);
static int remove_duplicates_in_refs(struct ref **ref, int nr)
static int fetch_unpack_limit = -1;
		for_each_ref(mark_complete_oid, NULL);
	return ret;
	}
				continue;
	strbuf_addstr(&promisor_name, ".promisor");
	obj->flags |= ALTERNATE;
	if (received_ready && reader->status != PACKET_READ_DELIM)
	if (packet_reader_read(reader) != PACKET_READ_NORMAL)
			}
			error(_("remote did not send all necessary objects"));
	if (!got_ready || !no_done) {
			add_refs_to_oidset(&tip_oids, unmatched);
{
}
		return;
		 * We use lookup_object here because we are only
	int received_ready = 0;
				state = FETCH_GET_PACK;
		const char *arg;

	/* Add shallow-info and deepen request */
					print_verbose(args, _("got %s %d %s"), "ack",
};
						 */
		send_request(args, fd[1], &req_buf);
					retval = 0;

	struct object **items;
						 * it is in common with us.
	die(_("git fetch-pack: expected ACK/NAK, got '%s'"), reader->line);
				filter_refs(args, &ref, sought, nr_sought);
					state = FETCH_DONE;
		packet_buf_write(&req_buf, "deepen-since %"PRItime, max_age);
	}
	return count;
			if (!is_unmatched_ref(ref))
	} else {

			case 1:
	    ? transfer_fsck_objects
		if (item->util)
	const struct object_id *oid;
				struct commit *commit;
	} else if (!args->stateless_rpc)
				mark_complete_and_common_ref(negotiator, args, &ref);
			 * trash or a peeled value; do not even add it to
static int mark_complete(const struct object_id *oid)
			struct string_list_item *s = args->deepen_not->items + i;
	if (negotiator)
enum ack_type {
			continue;
		    check_refname_format(ref->name, 0)) {

	ACK_common,
	if (!haves_added || *in_vain >= MAX_IN_VAIN) {
		/*

				ack = get_ack(&reader, result_oid);
	if (is_repository_shallow(the_repository))
	if (alternate_shallow_file) {
	    reader->status != PACKET_READ_DELIM)
	}
		return 1;
}

					if (!commit)

		if (ack) {
			 */
					}
			free_refs(ref_cpy);
		die(_("error reading section header '%s'"), section);
	}
		 * after get_pack() and reprepare_packed_git())
	if (args->deepen || unshallow_received) {
					was_common = negotiator->ack(negotiator, commit);
			retval = 0;
		print_verbose(args, _("Server supports %s"), "deepen-not");
			case 2:
#include "repository.h"
	struct ref *refs;
			if (!parse_object(the_repository, &oid))
		for (i = 0; i < si->nr_ours; i++)
{
		if (si->nr_ours || si->nr_theirs)
		/* Closed by start_command() */
			/*
		/* Add initial haves */

			newtail = &ref->next;
						OBJECT_INFO_QUICK |
	struct alternate_object_cache *cache = vcache;
	flushes = 0;

	if (args->deepen_since) {
		die(_("fetch-pack: unable to fork off %s"), cmd_name);
				fsck_msg_types.len ? ',' : '=', var, value);
	for (i = 0; i < nr_sought; i++)
	while (flushes || multi_ack) {
		int i;
	if (0 <= transfer_unpack_limit)
		alternate_shallow_file = NULL;

		if (!strict || oidset_contains(&tip_oids, &ref->old_oid)) {
	    ? fetch_fsck_objects
{
		/*
		print_verbose(args, "have %s", oid_to_hex(oid));
		if (read_pack_header(demux.out, &header))
	}
	else
			argv_array_pushf(&cmd.args,

						packet_buf_write(&req_buf, "have %s\n", hex);
		}

		packet_buf_write(req_buf, "deepen %d", args->depth);
		print_verbose(args, _("Server supports %s"), "side-band-64k");
	else if (si->nr_ours || si->nr_theirs)
			die(_("expected shallow/unshallow, got %s"), reader.line);

			 * We keep one window "ahead" of the other side, and
		if (parse_oid_hex(reader->line, &oid, &end) || *end++ != ' ')
					multi_ack = 0;
	 */
						    "negotiation_v2",
	}

	trace2_region_leave("fetch-pack", "parse_remote_refs_and_find_cutoff", NULL);
					} else if (!args->stateless_rpc
			 */
						/* We need to replay the have for this object
			break;
				 char **pack_lockfile)
		case FETCH_PROCESS_ACKS:
		die(_("%s failed"), cmd_name);

	if (server_supports("include-tag"))
static void update_shallow(struct fetch_pack_args *args,
		}
				else if (cmp == 0) {
		mark_complete_and_common_ref(negotiator, args, &ref);
		struct ref *iterator = ref_cpy;
}
		 * no objects in repo to worry about. Accept any
				switch (ack) {
			} else {
		 */
	for (i = 0; i < cache.nr; i++)
static int sideband_demux(int in, int out, void *data)
		print_verbose(args, _("Server supports %s"), "ofs-delta");
		       const struct ref *ref,
	int ret;
		if (flush_at <= ++count) {
			print_verbose(args, _("got %s (%d) %s"), "ack",
	if (server_supports("deepen-relative"))
	fclose(output);
static struct lock_file shallow_lock;
	if (!args->cloning && args->deepen) {
		 * for all object types: note that wanted blobs will still be
	return strcmp(name, (*(struct ref **)ref)->name);
			state = FETCH_DONE;
static void fetch_pack_config(void)
	return;
	if (args->deepen) {
			die(_("protocol error: bad pack header"));
	return	ref->match_status == REF_NOT_MATCHED &&
		if (!strcmp(reader->line, "NAK"))
				xsnprintf(hostname, sizeof(hostname), "localhost");
	int ret;
	rev_list_insert_ref(negotiator, NULL, &obj->oid);
		if (!o || o->type != OBJ_COMMIT || !(o->flags & COMPLETE))
			ret == 0;
	struct oidset common = OIDSET_INIT;
			die_errno(_("unable to write to remote"));
		struct object_id oid;
	 * ("shallow-info" and "wanted-refs") are sent only if a packfile is
				 struct packet_reader *reader)
					die(_("invalid shallow line: %s"), reader.line);
				    int fd[2],
	const struct ref *a = *((const struct ref **)a_);
		return NAK;
	if (o && o->type == OBJ_COMMIT)
	for (i = 0; i < nr_sought; i++) {
				 struct shallow_info *si,
{
	int got_continue = 0;
		print_verbose(args, _("Server supports %s"), "deepen-since");
				continue;

	git_config_get_int("fetch.unpacklimit", &fetch_unpack_limit);
	return ret;
		mark_tips(negotiator, args->negotiation_tips);
{
}
			continue;

		timestamp_t max_age = approxidate(args->deepen_since);
	if (!got_ready || !no_done)
					break;
		}
		 */
	}
}
			if (use_sideband == 2)  strbuf_addstr(&c, " side-band-64k");
		}
			if (unregister_shallow(&oid))
		packet_buf_write(&req_buf, "sideband-all");
	if (get_pack(args, fd, pack_lockfile, sought, nr_sought))
{
#define LARGE_FLUSH 16384
	while (packet_reader_read(reader) == PACKET_READ_NORMAL) {
	else if (is_repository_shallow(the_repository) || args->deepen)

			}
	struct ref *ref = *rm;
#include "object-store.h"
		if (!has_object_file_with_flags(&ref->old_oid,
			 * checks both broken objects and links, but we only

static int fetch_pack_config_cb(const char *var, const char *value, void *cb)
		switch (sought[i]->match_status) {
		} else {
		 *
	if (do_keep && pack_lockfile) {
		 * Treat these as shallow lines caused by the remote being
		oideq(&oid, &ref->old_oid);
			error(_("no such remote ref %s"), sought[i]->name);
			    section, reader->line);
			/* get the pack */
		xd[0] = -1;
			packet_buf_write(&req_buf, "want %s%s\n", remote_hex, c.buf);

}
			warning("Skipping unknown msg id '%s'", var);
		print_verbose(args, _("already have %s (%s)"), oid_to_hex(remote),
		/*
		       (ALLOW_TIP_SHA1 | ALLOW_REACHABLE_SHA1));
		/*
				i++;
		negotiator->release(negotiator);
		 * local ref), we tell them we have it but do not have to
						got_ready = 1;
	}
			trace2_region_leave("fetch-pack",
		const char *arg;
					die(_("object not found: %s"), reader.line);
				void *vcache)
	int retval;
		 * so all refs can be accepted. Make sure we only add
	}
	    : 0) {
		struct oid_array extra = OID_ARRAY_INIT;
	string_list_clear(&names, 0);
		rev_list_insert_ref(negotiator, NULL,
			 int fd, struct strbuf *buf)
static int get_pack(struct fetch_pack_args *args,
				     parse_object(the_repository, oid),
		 * only the wanted objects be sent, and implement it.
	FETCH_PROCESS_ACKS,
		 * interested in the case we *know* the object is
	if (args->no_dependents)
		print_verbose(args, _("Server supports %s"), "multi_ack_detailed");


	    : transfer_fsck_objects >= 0
		 *
				    struct ref **sought, int nr_sought,
		if (!strcmp(reader->line, "ready")) {
		if (starts_with(ref->name, "refs/") &&

		fetch_negotiator_init(r, negotiator);
}


		if (++haves_added >= *haves_to_send)
			}
			die(_("expected wanted-ref, got '%s'"), reader->line);
				return ACK_continue;
			do_keep = 1;
{
		if (keep) {

			} while (ack);
static int prefer_ofs_delta = 1;
			 * unmatched list
}
					&alternate_shallow_file,
	if (args->deepen && alternate_shallow_file) {
static void mark_recent_complete_commits(struct fetch_pack_args *args,
			   PACKET_READ_CHOMP_NEWLINE |
	}
	if (reader->status != PACKET_READ_FLUSH &&
			if (agent_supported)    strbuf_addf(&c, " agent=%s",
				}
		while (packet_reader_read(reader) == PACKET_READ_NORMAL) {
		/*
	va_list params;
		 * We use lookup_object here because we are only

static int process_acks(struct fetch_negotiator *negotiator,

	strbuf_release(&req_buf);
			break;

		flushes++;
			len -= p - reader->line;
	struct ref *ref = copy_ref_list(orig_ref);
	for (ref = *refs; ref; ref = ref->next) {
		remote_hex = oid_to_hex(remote);
		}
	for ( ; wants ; wants = wants->next) {
{
	if (negotiator)
			count += PIPESAFE_FLUSH;
			commit_lock_file(&shallow_lock);
	else if (server_supports("multi_ack")) {

	if (prefer_ofs_delta)
					   pack_lockfile);
#include "exec-cmd.h"
			break;

		packet_buf_write(&req_buf, "done\n");
	if (!args->stateless_rpc) {
		alternate_shallow_file = NULL;
/*
		 *
	trace2_region_enter("fetch-pack", "mark_complete_local_refs", NULL);
	cmd.git_cmd = 1;
	}
		 * If that object is complete (i.e. it is an ancestor of a
#include "cache.h"
	*in_vain += haves_added;
		 * shallow. In v0, remote refs that reach these objects are
	state_len = req_buf.len;
	if (args->stateless_rpc && multi_ack == 1)
	oidcpy(oid, &ref->old_oid);
			if (!cutoff || cutoff < commit->date)

{
		commit_lock_file(&shallow_lock);
		struct object *o;
	}
		if (check_connected(iterate_ref_map, &iterator, &opt)) {
			break;
	FILE *output;

		return;
		if (cutoff)
	while ((oid = negotiator->next(negotiator))) {
	enum fetch_state state = FETCH_CHECK_LOCAL;
				no_done = 1;
		packet_buf_write(&req_buf, "no-progress");
	} else if (args->filter_options.choice) {
}
/* Allow request of a sha1 if it is reachable from a ref (possibly hidden ref). */
	if (!initialized) {
		for (i = 0; i < args->server_options->nr; i++)
				if (ack)
	for (retval = 1, ref = *refs; ref ; ref = ref->next) {
{
			die(_("git fetch-pack: expected a flush packet after shallow list"));
			continue;
				die(_("error in object: %s"), reader->line);
			argv_array_pushf(&cmd.args, "--strict%s",
	 * Don't mark them common yet; the server has to be told so first.

		write_shallow_commits(&req_buf, 1, NULL);
				     refname, 0);
		 * interested in the case we *know* the object is
		send_request(args, fd[1], &req_buf);
		if (!ret)
	did_setup = 1;
	if (server_supports("deepen-since")) {
	int use_ref_in_want = server_supports_feature("fetch", "ref-in-want", 0);
				   int flag, void *cb_data)
 * the section header doesn't match what was expected.
#define ALLOW_TIP_SHA1	01

}
	} else if (args->filter_options.choice) {
	if (args->stateless_rpc && args->deepen) {

	struct fetch_negotiator negotiator_alloc;
	int i;

	 * otherwise.
	if (server_supports("deepen-not")) {
/*
	struct oidset tip_oids = OIDSET_INIT;
static int agent_supported;
	if (skip_prefix(var, "fetch.fsck.", &var)) {
 * Processes a section header in a server's response and checks if it matches
						&alternate_shallow_file,
	return ret;
						in_vain = 0;
				trace2_region_enter("fetch-pack",
				 struct ref **sought, int nr_sought,
}
		int i;
 *

			continue;
static void mark_alternate_complete(struct fetch_negotiator *unused,
		ret = 1;
						&extra);
	size_t nr, alloc;

	struct strbuf req_buf = STRBUF_INIT;
			strbuf_release(&c);
				die(_("invalid shallow line: %s"), reader->line);
		 */
		}
	/* Append unmatched requests to the list */
	} else {
static int mark_complete_oid(const char *refname, const struct object_id *oid,
				receive_shallow_info(args, &reader, shallows, si);
	const char *agent_feature;
		struct object *o;
		 * us.
static void cache_one_alternate(const struct object_id *oid,
		send_request(args, fd[1], &req_buf);
			do_keep = 0;
		for_each_cached_alternate(NULL, mark_alternate_complete);
			argv_array_push(&cmd.args, "-q");
struct alternate_object_cache {
		}
			packet_buf_write(&req_buf, "want %s\n", remote_hex);
			cmd.out = -1;
			packet_buf_write(&req_buf, "deepen-not %s", s->string);
			alternate_shallow_file = NULL;
	if (args->include_tag)
static int everything_local(struct fetch_pack_args *args,
				    struct object *obj)
		if (!parse_oid_hex(arg, result_oid, &p)) {
			QSORT(sought, nr_sought, cmp_ref_by_name);
	} else {
static int send_fetch_request(struct fetch_negotiator *negotiator, int fd_out,
			return ACK;
}
				 struct shallow_info *si)
		const char *path;
			do {


	vfprintf(stderr, fmt, params);
	struct ref *ref;
	if (retval != 0) {
	while (packet_reader_read(reader) == PACKET_READ_NORMAL) {
	int in_vain = 0, negotiation_started = 0;
				keep = 1;
	if (start_command(&cmd))
			continue;
/*

	}
		struct object *o;

	int haves_added = 0;
		}
	ACK_continue,
			newtail = &(*newtail)->next;
	/*
	struct fetch_negotiator *negotiator;
			    (!args->deepen || !starts_with(ref->name, "refs/tags/")))
}
			argv_array_push(&cmd.args, "-v");
			      const struct ref *wants, struct oidset *common,
int report_unmatched_refs(struct ref **sought, int nr_sought)
		while (packet_reader_read(&reader) == PACKET_READ_NORMAL) {
	if (args->deepen_not) {
		demux.isolate_sigpipe = 1;
		ret = 1;
		 * tell them about its ancestors, which they already know
		 * shallow roots that are actually reachable from new
	}
	}
	int strict = !(allow_unadvertised_object_request &
		die(_("no matching remote head"));
		}
		return;
			if (args->filter_options.choice)

	ALLOC_GROW(cache->items, cache->nr + 1, cache->alloc);
			strbuf_addf(&fsck_msg_types, "%c%s=%s",
	struct string_list names = STRING_LIST_INIT_NODUP;
		oidcpy(&(*found)->old_oid, &oid);
	if (server_supports_feature("fetch", "shallow", 0))
				      ack, oid_to_hex(result_oid));
					sought[i]->match_status = REF_MATCHED;

	/*
					 fsck_msg_types.buf);
#include "fetch-negotiator.h"
	if (args->no_dependents) {
	if (stateless_rpc) {


		use_sideband = 2;
				/* make sure that it is parsed as shallow */
}
		packet_buf_write(req_buf, "have %s\n", oid_to_hex(oid));
	ret = !strcmp(reader->line, section);
#include "commit.h"
		 * Do this only if args->no_dependents is false (if it is true,
	struct fetch_negotiator *negotiator;
	else if (0 <= fetch_unpack_limit)
	}
{
#define PIPESAFE_FLUSH 32
			expand_list_objects_filter_spec(&args->filter_options);
				commit = lookup_commit(the_repository, &oid);
		o = lookup_object(the_repository, remote);
		multi_ack = 1;
done:

	if ((agent_feature = server_feature_value("agent", &agent_len))) {
		struct object_id *oid = si->shallow->oid;
	int *status;
		 * Treat these as shallow lines caused by our depth settings.
				    &negotiation_tips->oid[i]);
	for (ref = *refs; ref; ref = next) {
	} else if (args->deepen_since)
			 * will wait for an ACK only on the next one
 * thus do not need COMMON_REF marks).
	return ret;
	process_section_header(reader, "acknowledgments", 0);
		 * If we're obtaining the filename of a lockfile, we'll use

				die(_("invalid unshallow line: %s"), reader->line);
		if (start_async(&demux))

	while (packet_reader_read(reader) == PACKET_READ_NORMAL) {
	strbuf_addstr(&promisor_name, keep_name);
	int got_ready = 0;
		case FETCH_SEND_REQUEST:
			break;
			oid_array_clear(&ref);
		if (args->from_promisor)
			struct commit *commit = (struct commit *)o;

					break; /* definitely do not have it */
static const char *alternate_shallow_file;
		prefer_ofs_delta = 0;
		return;
		struct tag *t = (struct tag *) o;
			if (send_fetch_request(negotiator, fd[1], args, ref,


		packet_buf_write(&req_buf, "filter %s", spec);
			if (process_section_header(&reader, "shallow-info", 1))
						lookup_commit(the_repository,
				filter_refs(args, &ref, sought, nr_sought);
						const char *hex = oid_to_hex(result_oid);
		ref[src] = NULL;
		 * that filename to write a .promisor file with more
		pass_header = 1;
	for (; refs; refs = refs->next)
			if (get_oid_hex(arg, &oid))

	if (strcmp(var, "fetch.fsck.skiplist") == 0) {
static int next_flush(int stateless_rpc, int count)
{
	if (args->depth > 0)
static int iterate_ref_map(void *cb_data, struct object_id *oid)
		argv_array_push(&cmd.args, "--stdin");
			ref->next = unmatched;
			packet_buf_write(req_buf, "want-ref %s\n", wants->name);
	 * without updating .git/shallow

				 const char *fmt, ...)
	else if (args->deepen_relative)
		BUG("name of pack lockfile should end with .keep (was '%s')",

#define ALLOW_REACHABLE_SHA1	02


	trace2_region_leave("fetch-pack", "mark_common_remote_refs", NULL);
			 */
			*newtail = ref;
			 */
		 * reachable and we have already scanned it.
#include "connect.h"

			if (ack == ACK)
static int deepen_not_ok;
					       &common,
	}
			die(_("fetch-pack: unable to fork off sideband demultiplexer"));
		 * in sync with the other side at some time after
						 * for this commit has not been
	fetch_pack_setup();
 * COMMON_REF (otherwise, we are not planning to participate in negotiation, and

}

static int transfer_fsck_objects = -1;
			if (deepen_not_ok)      strbuf_addstr(&c, " deepen-not");
#include "fsck.h"
		print_verbose(args, _("Server supports %s"), "shallow");
				cutoff = commit->date;
	struct object_id oid;
		int i;
			struct strbuf c = STRBUF_INIT;
		negotiator = NULL;

static int multi_ack, use_sideband;
			if (args->depth > 0 || args->deepen_since || args->deepen_not)
	trace2_region_leave("fetch-pack", "mark_complete_local_refs", NULL);
				if (cmp < 0)
		 * about.
	if (!si->nr_ours && !si->nr_theirs)

		}
static void add_wants(int no_dependents, const struct ref *wants, struct strbuf *req_buf)
	 * parents of those refs as COMPLETE.
		       struct fetch_pack_args *args,
}
}
			     struct object_id *result_oid)
	struct strbuf req_buf = STRBUF_INIT;

		if (!(commit->object.flags & COMPLETE)) {
{
		struct object_id oid;
	 * If an "acknowledgments" section is sent, a packfile is sent if and
			allow_unadvertised_object_request |= ALLOW_REACHABLE_SHA1;
		      const struct oid_array *negotiation_tips)
			if (skip_prefix(reader.line, "shallow ", &arg)) {
		for (i = 0; i < nr_sought; i++)

		const char *remote_hex;
				break; /* give up */
					flushes = 0;
	if (args->deepen_relative)
		dst++;
	else
			args->check_self_contained_and_connected &&

	}
			if (args->no_progress)   strbuf_addstr(&c, " no-progress");
		prepare_shallow_info(&si, shallow);
		ref_cpy = do_fetch_pack_v2(args, fd, ref, sought, nr_sought,
	remove_nonexistent_theirs_shallow(si);
{
				 ntohl(header.hdr_entries));
	ret = recv_sideband("fetch-pack", xd[0], out);
	if (args->no_dependents) {
					if (ack == ACK_ready)
	/* Add filter */
			*newtail = copy_ref(ref);
	packet_buf_flush(&req_buf);
	    server_supports_feature("fetch", "sideband-all", 0)) {
		return;
		fetching++;
#define COMPLETE	(1U << 0)
static unsigned int allow_unadvertised_object_request;
			break;
	if (!negotiation_tips) {


	 * sent. Therefore, a DELIM is expected if "ready" is sent, and a FLUSH
 * After sending this many "have"s if we do not get any new ACK , we

			    struct ref **refs)
{

	memset(&demux, 0, sizeof(demux));
		timestamp_t max_age = approxidate(args->deepen_since);

			die(_("expected '%s', received '%s'"),
	}


		 * xd[0], spits out band#2 to stderr, and feeds us band#1
		ret = add_haves(negotiator, &req_buf, haves_to_send, in_vain);
#include "pack.h"
	oidset_iter_init(common, &iter);
			continue;
		setup_alternate_shallow(&shallow_lock, &alternate_shallow_file,

		if (reader->status != PACKET_READ_FLUSH)
	if (args->use_thin_pack)
				case ACK_continue: {
	}
		 * We already have it -- which may mean that we were
		 */
		argv_array_push(&cmd.args, cmd_name);
				die(_("object not found: %s"), reader->line);
	git_config_get_bool("fetch.fsckobjects", &fetch_fsck_objects);
{
					     &ref->old_oid),

						      ack, oid_to_hex(result_oid));
	if (server_supports_v2("fetch", 1))
		negotiator = NULL;
		packet_buf_write(req_buf, "deepen-relative\n");
			continue;
	if (args->stateless_rpc) {
		}
		if (write_in_full(fd, buf->buf, buf->len) < 0)
 * earliest commit time of the objects in refs that are commits and that we know
		die_errno(_("unable to write request to remote"));
	}
/*
		const char *arg;
	int ret = 0;
			multi_ack = 1;

	 */
{
}

			while (i < nr_sought) {
		argv_array_push(&cmd.args, "--shallow-file");
	if (!args->no_dependents) {
		 * NEEDSWORK: Add an option in the protocol to request that
	}
				print_verbose(args, _("giving up"));
	return retval;
		 *
			 * want to check for broken objects.
		struct object_id *oid = si->shallow->oid;
		die(_("Server does not support --shallow-exclude"));
		}
	}
	int old_save_commit_buffer = save_commit_buffer;
			register_shallow(the_repository, &shallows->oid[i]);
	struct ref *ref;
		in_vain++;

		die(_("git fetch-pack: fetch failed."));
		unpack_limit = fetch_unpack_limit;
	if (do_keep && pack_lockfile && args->from_promisor)
	if (args->deepen_since) {
		print_verbose(args, _("Server supports %s"), "multi_ack");

	return received_ready ? 2 : (received_ack ? 1 : 0);

static int add_haves(struct fetch_negotiator *negotiator,
			received_ready = 1;

			ref[dst] = ref[src];
__attribute__((format (printf, 2, 3)))
		return;
static int fetch_fsck_objects = -1;
			unlink_or_warn(git_path_shallow(the_repository));
	if (strict) {
		if (args->quiet || args->no_progress)

		else
							  insert_one_alternate_object);
	int do_keep = args->keep_pack;
			packet_buf_write(req_buf, "want %s\n", oid_to_hex(remote));
	for (i = 0; i < negotiation_tips->nr; i++)
	if (args->stateless_rpc)
}
	save_commit_buffer = old_save_commit_buffer;
						die(_("invalid commit %s"), oid_to_hex(result_oid));
				if (get_oid_hex(arg, &oid))
	packet_buf_delim(&req_buf);
		packet_buf_write(&req_buf, "ofs-delta");
	struct strbuf promisor_name = STRBUF_INIT;
{
					negotiator->ack(negotiator, commit);
	const char *cmd_name;
		memset(&si, 0, sizeof(si));
	suffix_stripped = strbuf_strip_suffix(&promisor_name, ".keep");
			oid_array_append(&extra, &oid[si->ours[i]]);
			char hostname[HOST_NAME_MAX + 1];
			print_verbose(args, _("Server supports %s"), "no-done");
			opt.is_deepening_fetch = 1;
	struct fetch_negotiator negotiator_alloc;
	return rev_list_insert_ref(cb_data, refname, oid);
		 * refs.
static void add_shallow_requests(struct strbuf *req_buf,

				    struct oid_array *shallows,
		 * that (it is OK if we guess wrong here).
			return 1;

		oid_array_append(&ref, &sought[i]->old_oid);
	while ((oid = negotiator->next(negotiator))) {
		negotiator->release(negotiator);

				 struct packet_reader *reader,
	if (server_supports_v2("agent", 0))
	return git_default_config(var, value, cb);

			}

				return ACK_common;
		case FETCH_DONE:
	if (o && o->type == OBJ_COMMIT) {
			if (len < 1)
	while (complete && cutoff <= complete->item->date) {
		oid_array_clear(&extra);
					struct commit *commit =

	while (o && o->type == OBJ_TAG) {

				  const char *section, int peek)
	    reader->status != PACKET_READ_DELIM)
			default:
				negotiation_started = 1;
		cmd_name = "index-pack";
		packet_buf_write(&req_buf, "thin-pack");
/* Allow specifying sha1 if it is a ref tip. */
}
			argv_array_push(&cmd.args, "--promisor");
	if (args->cloning) {
		 * tell them about its ancestors, which they already know

		argv_array_push(&cmd.args, alternate_shallow_file);
			break;
	if (!received_ready && reader->status != PACKET_READ_FLUSH)

			   PACKET_READ_DIE_ON_ERR_PACKET);
		for_each_ref(rev_list_insert_ref_oid, negotiator);
{

	assign_shallow_commits_to_refs(si, NULL, status);
	cache->items[cache->nr++] = obj;
		}
				 struct oid_array *shallows,
			if (args->stateless_rpc)
		packet_reader_read(reader);
	if (!args->keep_pack && unpack_limit) {
		if (!fetching) {

			rollback_lock_file(&shallow_lock);
#include "lockfile.h"
			if (!keep && args->fetch_all &&
	}
			commit->object.flags |= COMPLETE;
	} else if (shallows->nr) {
	struct repository *r = the_repository;
		pop_most_recent_commit(&complete, COMPLETE);
							    git_user_agent_sanitized());
					NULL);
		return;
		ret = 1;
		argv_array_push(&cmd.args, cmd_name);
				 int fd[2],
static void add_common(struct strbuf *req_buf, struct oidset *common)

		args->check_self_contained_and_connected = 0;
		if (shallow->nr)
	struct object *o = deref_tag(the_repository,
	close(out);
	oid_array_clear(&shallows_scratch);
	}
			if (!negotiation_started) {
	ret = finish_command(&cmd);
						    the_repository);
		setup_alternate_shallow(&shallow_lock,
				oidset_insert(common, &oid);

			continue;

		 */
		if (args->deepen)
			      sought[i]->name);
};
		deepen_not_ok = 1;
	if (use_sideband && finish_async(&demux))
	if (server_supports("allow-reachable-sha1-in-want")) {
		if (count < LARGE_FLUSH)
					     lookup_object(the_repository,
		    struct ref **sought, int nr_sought)

					struct object *obj)
	trace2_region_enter("fetch-pack", "negotiation_v0_v1", the_repository);
			}
		/* Add all of the common commits we've found in previous rounds */
	}
			fsck_msg_types.len ? ',' : '=', path);
static enum ack_type get_ack(struct packet_reader *reader,
			 * We cannot use --strict in index-pack because it
		if (skip_prefix(reader->line, "unshallow ", &arg)) {
	}
	if (!args->no_dependents) {

		oid_array_clear(&ref);
			if (skip_prefix(reader.line, "unshallow ", &arg)) {
 * locally and reachable from a local ref, and 0 otherwise.
	for (src = dst; src < nr; src++)

}
		packet_flush(fd);
	if (!strcmp(reader->line, "NAK"))
		args->deepen = 1;
			if (prefer_ofs_delta)   strbuf_addstr(&c, " ofs-delta");
	trace2_region_enter("fetch-pack", "mark_common_remote_refs", NULL);
		negotiator = &negotiator_alloc;
			packet_buf_flush(&req_buf);
			break; /* broken repository */
		 * wanted objects be sent, so approximate this by setting a
	print_verbose(args, _("done"));
		if (o->type == OBJ_COMMIT) {
		packet_buf_write(&req_buf, "deepen %d", args->depth);
	else if (args->depth > 0 || is_repository_shallow(r))
		print_verbose(args, _("Server supports %s"), "no-progress");
	status = xcalloc(nr_sought, sizeof(*status));
		 * is a block of have lines exchanged.
	 * Now that index-pack has succeeded, write the promisor file using the
				else
		die(_("unexpected acknowledgment line: '%s'"), reader->line);
		       char **pack_lockfile,
	}
	}
	}
		die(_("error processing acks: %d"), reader->status);
			ref_cpy = NULL;

	}
#include "tag.h"
	const char *p;

		alternate_shallow_file = setup_temporary_shallow(si->shallow);
#include "fetch-pack.h"
			struct oidset *common)
					    "negotiation_v2",
		else

		 * reachable and we have already scanned it.
	const struct object_id *oid;
		if (!(do_keep && pack_lockfile) && args->from_promisor)
		if (git_config_pathname(&path, var, value))
		int i;
	if (!ref)
		return -1; /* end of the list */
	*rm = ref->next;
			continue;
	fputc('\n', stderr);
	}
			send_request(args, fd[1], &req_buf);
		/* If we sent a depth we will get back "duplicate"
	int received_ack = 0;
		die(_("git fetch-pack: expected ACK/NAK, got a flush packet"));
		 *
	int *xd = data;

	struct ref *newlist = NULL;

	for (i = 0; i < nr_sought; i++)
	int i;
{

		demux.out = xd[0];
			if (!lookup_object(the_repository, &oid))
	for (ref = *refs; ref; ref = ref->next) {
	}
					(uintmax_t)getpid(), hostname);
	 */
	if (args->no_dependents && !args->filter_options.choice) {
				    const struct ref *orig_ref,
	update_shallow(args, sought, nr_sought, &si);
#include "connected.h"
				for_each_cached_alternate(negotiator,
		prepare_shallow_info(si, shallows);
		if (everything_local(args, &ref)) {


					&si, pack_lockfile);
		demux.out = -1;
		struct object *o = deref_tag(the_repository,
		die(_("Server does not support shallow clients"));
static int transfer_unpack_limit = -1;
	/* received */
			argv_array_push(&cmd.args, "--check-self-contained-and-connected");
			if (get_oid_hex(arg, &oid))
				return 0;
		}
		nr_sought = remove_duplicates_in_refs(sought, nr_sought);
				      ref->name);
		for (i = 0; i < args->deepen_not->nr; i++) {
}
		struct string_list_item *item;
		negotiator = &negotiator_alloc;
		const struct object_id *remote = &wants->old_oid;
		} else {
			argv_array_push(&cmd.args, "--fix-thin");
		strbuf_setlen(&req_buf, 0);
		    (o->flags & COMPLETE)) {
		reader.me = "fetch-pack";
			     int flag, void *cb_data)
		alternate_shallow_file = NULL;
		add_shallow_requests(&req_buf, args);
	if (!ret || (args->check_self_contained_and_connected && ret == 1))
static void write_promisor_file(const char *keep_name,
		for (i = 0; i < args->deepen_not->nr; i++) {
		const char *p;
	else
#include "pkt-line.h"
				mark_tips(negotiator, args->negotiation_tips);
		strbuf_release(&req_buf);
		for (i = 0; i < shallows->nr; i++)
		initialized = 1;
			   PACKET_READ_DIE_ON_ERR_PACKET);
	static int did_setup;
					 struct fetch_pack_args *args,
		argv_array_pushf(&cmd.args, "--pack_header=%"PRIu32",%"PRIu32,
	if (args->server_options && args->server_options->nr &&

}
	if (did_setup)
		 * about.
		packet_buf_write(&req_buf, "command=fetch");
static void for_each_cached_alternate(struct fetch_negotiator *negotiator,
			   struct ref **sought, int nr_sought,
static struct commit_list *complete;
		 * remote is shallow, but this is a clone, there are
	size_t i;

#include "oid-array.h"
	if (write_in_full(fd_out, req_buf.buf, req_buf.len) < 0)
}
				sought[i]->status = REF_STATUS_REJECT_SHALLOW;
		if (skip_prefix(reader->line, "ACK ", &arg)) {
static void mark_complete_and_common_ref(struct fetch_negotiator *negotiator,
		if (!args->quiet && !args->no_progress)
				setup_temporary_shallow(si->shallow);

					 && ack == ACK_common

		if (count < PIPESAFE_FLUSH)
static int rev_list_insert_ref_oid(const char *refname, const struct object_id *oid,
{

		if (!o || !(o->flags & COMPLETE)) {
}


static void consume_shallow_list(struct fetch_pack_args *args,
	if (server_supports("side-band-64k")) {
	trace2_region_leave("fetch-pack", "negotiation_v0_v1", the_repository);
	int i;
			flushes++;
			}
			if (starts_with(reader->line, "shallow "))

static void insert_one_alternate_object(struct fetch_negotiator *negotiator,
					goto done;
			free_one_ref(ref);
		commit_list_sort_by_date(&complete);
}

		item->util = ref[src];

		if (*alternate_shallow_file == '\0') { /* --unshallow */
static int is_unmatched_ref(const struct ref *ref)
		for (i = 0; i < nr_sought; i++) {
