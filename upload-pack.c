		}
		"rev-list", "--stdin", NULL,
	if (!send_shallow_list(&data->writer, data->depth,


			die("Invalid deepen-since: %s", line);
		if (!keepalive)
		if (!(o->flags & WANTED)) {
			if (no_done && sent_ready) {
	int buffered = -1;
	if (finish_command(&pack_objects)) {

			packet_writer_error(writer, "unknown ref %s", arg);
#include "revision.h"
			     parents = parents->next)
	for_each_string_list_item(item, &data->wanted_refs) {

		 * an empty message on the data sideband just to let the other

	if (skip_prefix(line, "want-ref ", &arg)) {
	struct oid_array haves;

		if (process_shallow(reader->line, &shallows))
		if (!(o->flags & WANTED)) {
			 */
		o = get_indexed_object(i - 1);
			continue;
	data->shallows = shallows;
static int process_deepen_not(const char *line, struct string_list *deepen_not, int *deepen_rev_list)
	 * even when it showed no commit.
		case FETCH_DONE:
		    (!repo_config_get_bool(the_repository,
			 * pack data is not good enough to signal
		struct object_id oid;
	if (!we_knew_they_have) {
}
		object_array_clear(&reachable_shallows);
			/* Data ready; we keep the last byte to ourselves
}
/* return non-zero if the ref is hidden, otherwise 0 */
	}
{
			     timestamp_t deepen_since,
	if (capabilities) {
					    "upload-pack: not our ref %s",
			argv_array_pushf(&pack_objects.args, "--filter=%s", buf.buf);
		if (reachable && o->type == OBJ_COMMIT)
 */
			/* give priority to status messages */
			continue;
			else if (sz == 0) {
			     oid_to_hex(oid), refname_nons,
	const char *arg;
		ret = 1;
	head_ref_namespaced(find_symref, &symref);
		struct object_array reachable_shallows = OBJECT_ARRAY_INIT;
	}
			if (have_obj->nr > 0) {
		"corruption on the remote side.";
}

		data[0] = buffered;
#include "list-objects-filter-options.h"
	send_shallow(writer, result);
			continue;

		if (o && o->type == OBJ_COMMIT) {
			got_common = 0;
	}
	int ret = 0;
	if (skip_prefix(line, "deepen-since ", &arg)) {

{
			 struct object_array *have_obj)
			die("git upload-pack: not our ref %s",
			case -1: /* they have what we do not */
		/*
				struct object_array *reachable)
{
{
		 * marked with OUR_REF.
			     stateless_rpc ? " no-done" : "",
			 */
			argv_array_pushf(&pack_objects.args, "--filter=%s",
	packet_reader_init(&reader, 0, NULL, 0,
		struct object_id oid;
	return 0;
	return 0;
#include "version.h"
	int deepen_relative = 0;
		/* ignore unknown lines maybe? */
	current_config_scope() != CONFIG_SCOPE_WORKTREE) {
		o = parse_object_or_die(&oid, arg);

			continue;

	/* All the non-tip ones are ancestors of what we advertised */
			if (!oldest_have || (commit->date < oldest_have))
		if (get_oid_hex(arg, &oid))
			 * in case we detect broken rev-list, so that we
static void upload_pack_data_init(struct upload_pack_data *data)
static void process_args(struct packet_reader *request,
	return 0;
			     const struct object_array *want_obj)

				packet_write_fmt(1, "ACK %s ready\n", last_hex);
	struct object_array wants;
			while (parents) {

	}
					if (multi_ack == 2) {
					    oid_to_hex(&object->oid));
	struct string_list_item *item;
		if (process_deepen(reader->line, &depth))
	int i;
	}
	const struct string_list_item *item;
			strbuf_release(&buf);
	shallow_nr = 0;
		const char *spec =
#include "upload-pack.h"
		register_shallow(the_repository, &object->oid);
		oid_array_append(haves, &oid);
			continue;
			continue;
			argv_array_pushf(&av, "--max-age=%"PRItime, deepen_since);
		fprintf(pipe_fd, "%s\n",
		struct commit_list *parents;
static int is_our_ref(struct object *o)

			break;
			continue;

		struct object *o;
			create_pack_file(&have_obj, &want_obj);
	/* We read from pack_objects.err to capture stderr output for
		}
static timestamp_t oldest_have;
		return 1;
}
#include "sigchain.h"
		     parents = parents->next)
		result = get_shallow_commits(&reachable_shallows,
			 struct object_array *want_obj)
			keepalive < 0 ? -1 : 1000 * keepalive);
		keepalive = git_config_int(var, value);

{

		argv_array_push(&pack_objects.args, "--thin");
	oid_array_clear(&data->haves);
	cmd->no_stderr = 1;
	struct string_list_item *item;
		if (!strcmp(arg, "ofs-delta")) {
}

		die("git upload-pack: expected SHA1 list, got '%s'", reader->line);
	if (skip_prefix(line, "deepen-not ", &arg)) {
		object = parse_object(the_repository, &oid);
			 * breakage to downstream.
	struct object *o;
	}
		}
			die("oops (%s)", oid_to_hex(oid));
	memset(data, 0, sizeof(*data));
	pack_objects.out = -1;
	if (shallow_nr) {
 * on successful case, it's up to the caller to close cmd->out
				/*
		packet_write_fmt(1, "%s %s%c%s%s%s%s%s%s agent=%s\n",
{
	for (i = get_max_object_index(); 0 < i; i--) {

#define OUR_REF		(1u << 12)
#define WANTED		(1u << 13)
				argv_array_push(&av, s->string);
#include "string-list.h"
	if (!symref_target || (flag & REF_ISSYMREF) == 0)

{
					     SHALLOW, NOT_SHALLOW);
	write_or_die(fd, data, sz);
	}
static void send_shallow_info(struct upload_pack_data *data,
	oid_array_clear(&data->haves);
static void send_shallow(struct packet_writer *writer,
		if (o && o->type == OBJ_COMMIT &&
		const struct object_id *oid = &haves->oid[i];
static unsigned int timeout;
		struct object_id oid;
	FETCH_PROCESS_ARGS = 0,
			data->writer.use_sideband = 1;
		if (!repo_config_get_bool(the_repository,
	send_unshallow(writer, shallows, want_obj);
		*deepen_rev_list = 1;
static int use_sideband;
		result = result->next;
	return 1;
 * otherwise maximum packet size (up to 65520 bytes).
		const char *p;

	if (skip_prefix(line, "deepen ", &arg)) {
		die("oops (%s)", oid_to_hex(oid));
	} else {
	struct packet_writer writer;
	if (!symref->nr)

		struct object_id oid_buf;
		if ((git_env_bool("GIT_TEST_SIDEBAND_ALL", 0) ||
}
		}
			parents->item->object.flags |= THEY_HAVE;
	send_unshallow(writer, shallows, want_obj);
	if (!acks->nr)
	} else if (send_acks(&data->writer, &common, have_obj, want_obj)) {
		else
	struct oid_array common = OID_ARRAY_INIT;
		if (!strcmp(arg, "include-tag")) {
}
	const unsigned hexsz = the_hash_algo->hexsz;

	return 0;
static int no_progress, daemon_mode;
	int deepen_rev_list;
		packet_flush(1);
	if (!strcmp("uploadpack.allowtipsha1inwant", var)) {
			filter_capability_requested = 1;
		for (parents = commit->parents;
		const char *arg;


	clear_object_flags(ALL_FLAGS);
	}
static void check_non_tip(struct object_array *want_obj,
#define HIDDEN_REF	(1u << 19)

	unsigned use_include_tag : 1;
				buffered = -1;
						packet_write_fmt(1, "ACK %s ready\n", hex);
{
	close(cmd.out);
#include "prio-queue.h"
			continue;
					    oid_to_hex(&object->oid));
				send_client_data(2, progress, sz);
		return 1;
	if (0 <= buffered) {
			return -1;
			state = FETCH_DONE;
	while (packet_reader_read(request) == PACKET_READ_NORMAL) {
		free_commit_list(result);
{


		int i;
#include "cache.h"
		return -1;
			use_ofs_delta = 1;
}
		 * We hit the keepalive timeout without saying anything; send
			parse_commit_or_die((struct commit *)object);
	if (value) {
	char last_hex[GIT_MAX_HEXSZ + 1];

	struct commit_list *result;
	if (filter_options.choice) {
	return 0;
		if (skip_prefix(reader->line, "filter ", &arg)) {
				pack_objects.err = -1;
	}
		allow_filter = git_config_bool(var, value);
		if (!we_knew_they_have)
			pfd[pollsize].events = POLLIN;
		       int flag, void *cb_data)

	return -1;
static int process_shallow(const char *line, struct object_array *shallows)
	}
		}
	string_list_clear(&data->wanted_refs, 1);
	if (use_include_tag)
	}
			     symref_info.buf,
	if (finish_command(&cmd))
				die("git upload-pack: filtering capability not negotiated");
			 * re-register it.
		     allow_sideband_all_value))
static int send_shallow_list(struct packet_writer *writer,
	return 0;
		} else {
static void send_unshallow(struct packet_writer *writer,
#include "tag.h"
		if (shallows->nr > 0) {
	char namebuf[GIT_MAX_HEXSZ + 2]; /* ^ + hash + LF */
	timeout = options->timeout;
			/*
	int deepen_relative;
	if (cmd->in >= 0)
			else
		    parse_want_ref(&data->writer, arg, &data->wanted_refs,
			list_objects_filter_die_if_populated(&filter_options);
static int use_thin_pack, use_ofs_delta, use_include_tag;
	packet_writer_init(&data->writer, 1);
	 * progress bar, and pack_objects.out to capture the pack data.
{
				  sizeof(data) - outsz);
static int has_unreachable(struct object_array *src)

	struct object_array have_obj = OBJECT_ARRAY_INIT;
		xwrite(fd, data, sz);
	 * uploadpack.allowReachableSHA1InWant,
	 * If the next rev-list --stdin encounters an unknown commit,
	return 0;
			 struct upload_pack_data *data,
	data->haves = haves;
		o = parse_object(the_repository, &oid);

	struct string_list deepen_not;
	 */
	} else {
			pollsize++;


	send_client_data(3, abort_msg, sizeof(abort_msg));
 */
	while (1) {
{
		struct object_id oid;
		     parents;
			goto error;
		if (!o)
		if (!strcmp("uploadpack.packobjectshook", var))
	oid_array_clear(&common);
	if (current_config_scope() != CONFIG_SCOPE_LOCAL &&
			return git_config_string(&pack_objects_hook, var, value);
	return 1;
	namebuf[hexsz] = '\n';
	/* Process haves */
		       &data->shallows, want_obj);
		o->flags |= HIDDEN_REF;
	timestamp_t deepen_since = 0;
				return 0;
	const char *arg;
		    allow_filter_value)
			continue;

		if (packet_reader_read(reader) != PACKET_READ_NORMAL) {
					    "upload-pack: not our ref %s",
}
	if (!have_obj->nr)
		if (o->flags & THEY_HAVE)
			packet_writer_write(writer, "shallow %s",

	argv_array_push(&pack_objects.args, "--stdout");
	if (!pack_objects_hook)
	struct child_process cmd = CHILD_PROCESS_INIT;
		if (!strcmp(arg, "thin-pack")) {


	 */
			       struct object_array *shallows,
		const char *p;
		pe = pu = -1;
	struct object_array shallows = OBJECT_ARRAY_INIT;

	receive_needs(&reader, &want_obj);
				close(pack_objects.out);
		return 0;
				*cp++ = buffered;

		     int flag, void *cb_data);
{
		allow_ref_in_want = git_config_bool(var, value);

			add_object_array(o, NULL, want_obj);
		if (!is_our_ref(o)) {
			break;
	if (!o)
	data->wanted_refs = wanted_refs;
			if (multi_ack == 2 && got_common
	if (ref_is_hidden(refname, refname_full)) {
		if (parse_feature_request(features, "ofs-delta"))
	}

				  sizeof(progress));
		packet_writer_write(writer, "NAK\n");
	if (ok_to_give_up(have_obj, want_obj)) {
	for (i = 0; i < have_obj->nr; i++)
			continue;
			    "expected to get object ID, not '%s'", reader->line);

				   want_obj))
		}
					    "upload-pack: not our ref %s",
			object->flags |= CLIENT_SHALLOW;
		/* Shallow related arguments */
		int allow_sideband_all_value;
	} else if (deepen_rev_list) {
		    *deepen_since == -1)
		if (!strcmp(reader->line, "done")) {
			continue;
		if (git_env_bool("GIT_TEST_SIDEBAND_ALL", 0) ||
	if (!has_unreachable(want_obj))
		    (o->flags & TMP_MARK)) {


}
		if (get_oid_hex(arg, &oid))
	}

static void deepen(struct packet_writer *writer, int depth, int deepen_relative,
			if (!((allow_unadvertised_object_request & ALLOW_ANY_SHA1) == ALLOW_ANY_SHA1
		if (0 <= pu && (pfd[pu].revents & (POLLIN|POLLHUP))) {
	/*
		if (!strcmp(arg, "done")) {
	if (skip_prefix(line, "have ", &arg)) {

	}
		goto fail;
		if (process_deepen(arg, &data->depth))
			o->flags |= THEY_HAVE;
	 * In the normal in-process case without
				parents = parents->next;
				add_object_array(&parents->item->object,
		    /* revisions.c's max_age -1 is special */
	}
#include "list-objects-filter.h"
	sigchain_pop(SIGPIPE);
static const char *pack_objects_hook;
			struct commit_list *parents;

		/* Send Ready */

#include "run-command.h"
		}
		die("git upload-pack: deepen and deepen-since (or deepen-not) cannot be used together");
			die("unknown ref %s", arg);
	return parse_hide_refs_config(var, value, "uploadpack");
		}
	return 0;
			packet_writer_write(writer, "unshallow %s",
	}
		if (parse_have(arg, &data->haves))
			     int deepen_relative,
static void send_wanted_ref_info(struct upload_pack_data *data)
	if (depth == INFINITE_DEPTH && !is_repository_shallow(the_repository)) {
#include "serve.h"
					packet_write_fmt(1, "ACK %s\n", last_hex);
					 &data->deepen_rev_list))
static int ok_to_give_up(const struct object_array *have_obj,
		strbuf_addstr(value, "shallow");
			struct commit *commit = (struct commit *)o;
				o->flags &= ~TMP_MARK;
		int allow_ref_in_want;
	struct string_list deepen_not = STRING_LIST_INIT_DUP;
			      struct object_array *reachable)
}
			      struct object_array *want_obj)

		if (0 <= pe && (pfd[pe].revents & (POLLIN|POLLHUP))) {
			die("git upload-pack: not our ref %s",
	/*
		if (parse_feature_request(features, "no-done"))
			continue;

	}

		if (!o) {
			parse_list_objects_filter(&filter_options, arg);

			     struct object_array *shallows,
}
		}
					    oid_to_hex(&o->oid));
			add_object_array(object, NULL, shallows);
		" side-band-64k ofs-delta shallow deepen-since deepen-not"
		return;
				close(pack_objects.err);
			}
}
			die("git upload-pack: expected SHA1 object, got '%s'", arg);

			argv_array_push(&av, "--not");
	for (i = 0; i < acks->nr; i++) {

		head_ref_namespaced(check_ref, NULL);
			use_include_tag = 1;

	}
		struct strbuf symref_info = STRBUF_INIT;
		else if (parse_feature_request(features, "multi_ack"))
		if (deepen_not->nr) {
	struct object_id peeled;
		return;
	/*
	git_config(upload_pack_config, NULL);
	} else if (!strcmp("uploadpack.allowrefinwant", var)) {
#define ALLOW_ANY_SHA1	07
		}
			no_progress = 1;
	return 0;
			int i;
			else
		packet_flush(1);
		/* process want */
			    "expected to get oid, not '%s'", line);
	if (cmd->out >= 0)
				state = FETCH_SEND_PACK;
		}
	if (o->type == OBJ_COMMIT) {
		if (!(object->flags & (CLIENT_SHALLOW|NOT_SHALLOW))) {
		argv_array_push(&pack_objects.args, "--shallow-file");
	} else if (!strcmp("core.precomposeunicode", var)) {
#define ALLOW_TIP_SHA1	01
	 */
	argv_array_push(&pack_objects.args, "--revs");
		send_sideband(1, fd, data, sz, use_sideband);
					 spec);


					    min_generation);
			continue;
		 * Checking for reachable shallows requires that our refs be
	/* Pick one of them (we know there at least is one) */
		if (git_config_bool(var, value))
			if (0 <= buffered) {
		case FETCH_SEND_ACKS:
			multi_ack = 2;
	packet_delim(1);
			strbuf_addstr(value, " ref-in-want");

		return;
			  struct string_list *wanted_refs,
	alarm(timeout);
			add_object_array(o, NULL, reachable);
	struct object *o;
		for (i = 0; i < shallows->nr; i++) {
			die("invalid shallow line: %s", line);
		send_shallow(writer, result);
	for (i = 0; i < want_obj->nr; i++) {
	return 0;
	}
			packet_writer_error(writer,



	struct string_list wanted_refs = STRING_LIST_INIT_DUP;
	pipe_fd = xfdopen(pack_objects.in, "w");
			continue;
			struct object *o = want_obj->objects[i].item;
			if (!want_obj.nr) {
			else
		if (!(object->flags & CLIENT_SHALLOW)) {
	if (get_oid_hex(hex, oid))
		}
		struct string_list_item *item;

	if (use_ofs_delta)
		return 0;
			allow_unadvertised_object_request &= ~ALLOW_ANY_SHA1;
	string_list_clear(&symref, 1);

			send_client_data(1, data, sz);
		free(ref);


			 * parse and add the parents to the want list, then
{

		if (ret < 0) {
					 &allow_ref_in_want) &&
#include "object-store.h"


			if (1 < sz) {
		/* Add Flush */
				pack_objects.out = -1;
		}

{
				outsz++;
		if (!has_object_file(oid))
	}
			shallow_nr++;
{

}
	int i;

			     parents;
static int get_common_commits(struct packet_reader *reader,
				if (multi_ack)
		o = parse_object(the_repository, &oid_buf);
	fflush(pipe_fd);

	FETCH_SEND_PACK,
		   struct packet_reader *request)
			continue;
		argv_array_push(&pack_objects.args, "--shallow");
	object_array_clear(&have_obj);
	int i;
					const char *hex = oid_to_hex(&oid);
		}
		if (parse_feature_request(features, "no-progress"))
		if (!(o->flags & WANTED)) {
		    allow_ref_in_want)
	packet_writer_write(writer, "acknowledgments\n");
	static const char *argv[] = {
		char *end = NULL;
	shallow_nr += shallows->nr;
				 */
#include "quote.h"
			     allow_filter ? " filter" : "",
	FILE *pipe_fd;
		packet_writer_write(&data->writer, "%s %s\n",
	close(cmd->in);
					     SHALLOW, NOT_SHALLOW);
	cmd->argv = argv;
		*deepen_since = parse_timestamp(arg, &end, 0);

{
			 */
	daemon_mode = options->daemon_mode;
		 * luck.
		if (parse_want(&data->writer, arg, want_obj))

	}
					    COMMON_KNOWN, oldest_have,
}
		struct object_id oid;
		const char *features;

};
{
#define COMMON_KNOWN	(1u << 14)
			struct strbuf buf = STRBUF_INIT;
		o = lookup_object(the_repository, &oid);
	sigchain_pop(SIGPIPE);
		oid_array_append(common, oid);
	cmd.out = -1;
static void upload_pack_data_clear(struct upload_pack_data *data)
					 "uploadpack.allowfilter",

		if (packet_reader_read(reader) != PACKET_READ_NORMAL)
	int we_knew_they_have = 0;
struct upload_pack_data {
	int i;
	object_array_clear(&data->wants);
			register_shallow(the_repository, &object->oid);
				sleep(1);
		fprintf(pipe_fd, "%s\n",
	unsigned stateless_rpc : 1;
				 * Request didn't contain any 'want' lines,

	disable_commit_graph(the_repository);

	sigchain_pop(SIGPIPE);
						packet_write_fmt(1, "ACK %s continue\n", hex);
	int i;
	} else {

	if (mark_our_ref(refname_nons, refname, oid))
static int parse_want(struct packet_writer *writer, const char *line,
			}

			}
/* Allow request of a sha1 if it is reachable from a ref (possibly hidden ref). */
	} else {
		deepen_by_rev_list(writer, av.argc, av.argv, shallows, want_obj);
static int keepalive = 5;
		if (!end || *end || *depth <= 0)
			sq_quote_buf(&buf, spec);
};
	int depth;

		case FETCH_PROCESS_ARGS:


}
			else
		else
		pack_objects.git_cmd = 1;
			got_other = 0;
		}
				       struct object_array *have_obj,
{
			continue;
	 * rev-list may have died by encountering a bad commit
	struct string_list deepen_not = STRING_LIST_INIT_DUP;

	struct packet_reader reader;
				if (multi_ack == 2)
	return can_all_from_reach_with_flag(want_obj, THEY_HAVE,
		return 1;
			die("git upload-pack: protocol error, "
				packet_write_fmt(1, "ACK %s\n", last_hex);
				;
			oid_to_hex(&extra_edge_obj.objects[i].item->oid));
			allow_unadvertised_object_request |= ALLOW_ANY_SHA1;

	/* Send Acks */
				error_errno("poll failed, resuming");
#include "repository.h"
							&want_obj))
			    oid_to_hex(&oid));
			/* Status ready; we ship that in the side-band
				we_knew_they_have = 1;

static int mark_our_ref(const char *refname, const char *refname_full,


		if (!ret && use_sideband) {
	if (!peel_ref(refname, &peeled))
	struct object_array want_obj = OBJECT_ARRAY_INIT;
				packet_write_fmt(1, "NAK\n");
				state = FETCH_SEND_ACKS;
		send_shallow(writer, result);

			packet_writer_error(writer,
static void reset_timeout(void)
int upload_pack_advertise(struct repository *r,
		memcpy(namebuf, oid_to_hex(&o->oid), hexsz);
			switch (got_oid(arg, &oid, have_obj)) {
	struct string_list wanted_refs;
		if (parse_feature_request(features, "multi_ack_detailed"))
static int process_haves_and_send_acks(struct upload_pack_data *data,
			   const struct object_array *shallows,
	argv_array_push(&pack_objects.args, "pack-objects");
	packet_writer_write(&data->writer, "wanted-refs\n");
{
			 * can leave the stream corrupted.  This is
	return ret;
static int parse_want_ref(struct packet_writer *writer, const char *line,
					   "uploadpack.allowsidebandall",
	int i;
#include "object.h"

		if (!skip_prefix(reader->line, "want ", &arg) ||
		if (parse_feature_request(features, "thin-pack"))
		return;
	else {
		}
	struct upload_pack_data data;
	int ret = 0;
				got_other = 1;
	if (request->status != PACKET_READ_FLUSH)
			use_thin_pack = 1;
		 * If we don't have a sideband channel, there's no room in the
		for_each_namespaced_ref(check_ref, NULL);
		}
static int allow_filter;
/* Allow request of any sha1. Implies ALLOW_TIP_SHA1 and ALLOW_REACHABLE_SHA1. */
}
		char *ref = NULL;
			oldest_have = commit->date;
				add_object_array(o, NULL, reachable);
		return 0;
	FILE *fp = cb_data;
				     " allow-reachable-sha1-in-want" : "",
			      struct object_array *have_obj,
		for_each_namespaced_ref(check_ref, NULL);
					    oid_to_hex(&oid_buf));
			} else if (data.haves.nr) {
			sz = xread(pack_objects.err, progress,


	const char *refname = strip_namespace(refname_full);

	char abort_msg[] = "aborting due to possible repository "
			continue;
		return 1;
			     git_user_agent_sanitized());
		struct object_id oid;
		get_common_commits(&reader, &have_obj, &want_obj);
	}
			   struct object_array *want_obj)
{
	cmd->in = -1;
		else
		strbuf_release(&symref_info);
				state = FETCH_DONE;
	if (!no_progress)
		argv_array_push(&pack_objects.args, "git");
	sigchain_push(SIGPIPE, SIG_IGN);
		struct commit *commit = (struct commit *)o;
			    oid_to_hex(&o->oid));


			 struct commit_list *result)
	if (fd == 2) {
		reset_timeout();
#include "argv-array.h"
static int find_symref(const char *refname, const struct object_id *oid,
		free_commit_list(result);
	    is_repository_shallow(the_repository))
		if (reachable && o->type == OBJ_COMMIT)
				parents->item->object.flags |= THEY_HAVE;
			o->flags |= WANTED;
			continue;
			o->flags |= TMP_MARK;
}
			packet_writer_write(&data.writer, "packfile\n");
		o = src->objects[i].item;
		if (o->type == OBJ_COMMIT) {
	return 0;

			}
	object_array_clear(&want_obj);
	unsigned done : 1;
			     (allow_unadvertised_object_request & ALLOW_REACHABLE_SHA1) ?
				 * Request had 'have' lines, so lets ACK them.
			die("Invalid deepen: %s", line);
enum fetch_state {
	for_each_string_list_item(item, symref)
void upload_pack(struct upload_pack_options *options)


{



		struct object *o = want_obj->objects[i].item;
			keepalive = -1;
			data->deepen_relative = 1;
	if (do_reachable_revlist(&cmd, src, NULL) < 0)

			       data->deepen_rev_list,
	if (send_shallow_list(&writer, depth, deepen_rev_list, deepen_since,
}
	const char *arg;
}
		if (git_config_bool(var, value))
	}
		int ret;
	if (use_sideband)
	unsigned no_progress : 1;
	capabilities = NULL;

		pack_objects.use_shell = 1;

}
						 &shallows->objects[i].item->oid);

}
	 * below.
				if (multi_ack && ok_to_give_up(have_obj, want_obj)) {


	 * in the history, in which case we do want to bail out
			continue;
	ssize_t sz;
		if (!is_our_ref(o))
				goto fail;
	while ((i = read_in_full(cmd.out, namebuf, hexsz + 1)) == hexsz + 1) {
			if (0 < sz)
		 */
		if (!pollsize)

	const char *arg;

				}
				    oid_to_hex(item->util),
static int allow_sideband_all;
	return 0;

			no_progress = 1;
		argv_array_push(&pack_objects.args, "--progress");
		close(cmd->out);

	const char *symref_target;

		if (write_in_full(cmd->in, namebuf, hexsz + 2) < 0)
	return 0;
			struct commit_list *parents;
	 * it terminates, which will cause SIGPIPE in the write loop
				 * immedietly go to construct and send a pack.
		}
#define THEY_HAVE	(1u << 11)
			object->flags &= ~CLIENT_SHALLOW;
	object_array_clear(&data->shallows);

			for (i = 0; i < deepen_not->nr; i++) {
			allow_unadvertised_object_request &= ~ALLOW_REACHABLE_SHA1;
		if (skip_prefix(reader->line, "have ", &arg)) {
static int upload_pack_config(const char *var, const char *value, void *unused)
		reset_timeout();
	/*
		/* All the non-tip ones are ancestors of what we advertised */
}
	return ret;
		 * side know we're still working on it, but don't have any data

static void receive_needs(struct packet_reader *reader, struct object_array *want_obj)
	if (!stateless_rpc && !(allow_unadvertised_object_request & ALLOW_REACHABLE_SHA1))
	char buf[1];
		argv_array_push(&pack_objects.args, pack_objects_hook);
	struct child_process pack_objects = CHILD_PROCESS_INIT;
		return 1;
		if (deepen_since)
			       data->deepen_relative,
	if (cmd.out >= 0)
		if (process_shallow(arg, &data->shallows))
}
		if (write_in_full(cmd->in, namebuf, hexsz + 1) < 0)
{
		return -1;
#include "pkt-line.h"
	int got_common = 0;
		head_ref_namespaced(check_ref, NULL);
#define CLIENT_SHALLOW	(1u << 18)
{
				sent_ready = 1;
		argv_array_push(&pack_objects.args, "");
		strbuf_addf(buf, " symref=%s:%s", item->string, (char *)item->util);
			oid_to_hex(&have_obj->objects[i].item->oid));
			break;
	packet_writer_init(&writer, 1);
		      struct object_array *want_obj)
		send_client_data(1, data, 1);
			use_ofs_delta = 1;
	if (skip_prefix(line, "want ", &arg)) {
	return 0;

		int pe, pu, pollsize;
		return 1;
			for (parents = commit->parents;
			send_wanted_ref_info(&data);
#define NOT_SHALLOW	(1u << 17)
	cmd->out = -1;
	int allow_hidden_ref = (allow_unadvertised_object_request &
			allow_unadvertised_object_request |= ALLOW_REACHABLE_SHA1;
		   struct object_array *shallows, struct object_array *want_obj)
			       struct object_array *want_obj)
		}
					    oid_to_hex(&oid));
						sent_ready = 1;
			 struct object_array *want_obj)
			continue;
static int check_ref(const char *refname_full, const struct object_id *oid,


			sz += outsz;
	if (!data->depth && !data->deepen_rev_list && !data->shallows.nr &&
		deepen(writer, depth, deepen_relative, shallows, want_obj);

			pfd[pollsize].fd = pack_objects.err;
	int got_other = 0;
{
					 &allow_filter_value) &&

		     int flag, void *cb_data)
		 * protocol to say anything, so those clients are just out of
			}
	if (use_thin_pack)
static int check_ref(const char *refname_full, const struct object_id *oid,

			const struct object_id *oid)

static int multi_ack;
		argv_array_clear(&av);
			      struct object_array *want_obj)
		if (!o) {
		goto error;
{

	static const char *capabilities = "multi_ack thin-pack side-band"
	}
			pe = pollsize;
		/* XXX: are we happy to lose stuff here? */
}
		advertise_shallow_grafts(1);
	int deepen_rev_list = 0;
	if (depth > 0 && deepen_rev_list)
			   PACKET_READ_DIE_ON_ERR_PACKET);
	int has_non_tip = 0;
		fd = 2;
		if (is_our_ref(o)) {
		if (!object)

	/* flush the data */

		fprintf(fp, "--shallow %s\n", oid_to_hex(&graft->oid));
		die("git upload-pack: expected SHA1 object, got '%s'", hex);
		}
#define SHALLOW		(1u << 16)
		    int flag, void *cb_data)
int upload_pack_v2(struct repository *r, struct argv_array *keys,
			       const char **av,
	}
		struct object *object;

			     int depth, int deepen_rev_list,
	 */
			pu = pollsize;
			      || is_our_ref(o)))
		}
		struct pollfd pfd[2];
			if (errno != EINTR) {
		}
error:
		return 1;
	die("git upload-pack: %s", abort_msg);

			use_sideband = DEFAULT_PACKET_MAX;
			struct object *object = shallows->objects[i].item;
		}
		for_each_namespaced_ref(send_ref, &symref);
			add_object_array(object, NULL, &extra_edge_obj);
	 * non-tip requests can never happen.
				 */

		}
		return;
	unsigned use_ofs_delta : 1;
	const char *refname_nons = strip_namespace(refname);
error:

		die("git upload-pack: unable to fork git-pack-objects");

		struct object_array have_obj = OBJECT_ARRAY_INIT;
	 * by another process that handled the initial request.
		if (object->type != OBJ_COMMIT)
#define ALLOW_REACHABLE_SHA1	02
	char namebuf[GIT_MAX_HEXSZ + 2]; /* ^ + hash + LF */
	if (skip_prefix(line, "shallow ", &arg)) {
				register_shallow(the_repository,

	int sent_ready = 0;
		allow_sideband_all = git_config_bool(var, value);
static struct object_array extra_edge_obj;

	}
				exit(0);
			} else {
				break;
		if (git_config_bool(var, value))
			pfd[pollsize].fd = pack_objects.out;

		if (allow_filter && parse_feature_request(features, "filter"))
		ret = 1;
		struct commit_list *result;
	git_config(upload_pack_config, NULL);
		result = get_shallow_commits(want_obj, depth,
		return;

	stateless_rpc = options->stateless_rpc;
			continue;
	for (i = 0; i < haves->nr; i++) {
	upload_pack_data_init(&data);
		}
				has_non_tip = 1;
				state = FETCH_SEND_PACK;

			add_object_array(o, NULL, want_obj);
		if (0 <= pack_objects.out) {
static int get_reachable_list(struct object_array *src,
	if (data->done) {
			packet_write_fmt(1, "NAK\n");
	process_haves(&data->haves, &common, have_obj);
		packet_writer_delim(&data->writer);
			allow_unadvertised_object_request |= ALLOW_TIP_SHA1;
		ret = 1;
#include "commit-graph.h"
	};
			else if (sz == 0) {
			(ALLOW_TIP_SHA1 | ALLOW_REACHABLE_SHA1));

		 * yet.
			 * We want to _register_ "object" as shallow, but we
	struct object *o = lookup_unknown_object(oid);
		     struct object_array *want_obj)
	data->wants = wants;
static int no_done;
		goto error;
	for (i = 0; i < src->nr; i++) {

			multi_ack = 1;
	}
	if (i)
		if (process_deepen_not(arg, &data->deepen_not,
{

		argv_array_push(&av, "rev-list");
			o->flags &= ~TMP_MARK;
		}
/* 0 for no sideband,
	if (options->advertise_refs)
			if (0 < sz)
		if (0 <= pack_objects.err) {
		struct object *o;
{

		*depth = (int)strtol(arg, &end, 0);
static unsigned int allow_unadvertised_object_request;
	}
			 * unfortunate -- unpack-objects would happily
			list_objects_filter_die_if_populated(&filter_options);

		item->util = oiddup(&oid);

		memcpy(namebuf + 1, oid_to_hex(&o->oid), hexsz);
				buffered = data[sz-1] & 0xFF;
			data->done = 1;
					packet_write_fmt(1, "ACK %s\n", last_hex);
			process_args(request, &data, &want_obj);
	return 0;
		packet_writer_write(writer, "ACK %s\n",
		int we_knew_they_have = 0;
	/*
			  struct packet_writer *writer)

#define ALL_FLAGS (THEY_HAVE | OUR_REF | WANTED | COMMON_KNOWN | SHALLOW | \
		return 1;
#include "config.h"
	if (options->advertise_refs || !stateless_rpc) {
	if (depth > 0) {
		if (pack_objects.use_shell) {

		}
			     0, capabilities,

	for (i = 0; i < extra_edge_obj.nr; i++)
		struct commit_list *result;
	}

			static const char buf[] = "0005\1";
	o = parse_object(the_repository, oid);
		}
	}
static int got_oid(const char *hex, struct object_id *oid,
}
			send_shallow_info(&data, &want_obj);
	for (i = 0; i < shallows->nr; i++) {
			add_object_array(o, NULL, have_obj);
		return;
	struct object_array want_obj = OBJECT_ARRAY_INIT;
			break;
	if (fd == 3)
			die("git upload-pack: ambiguous deepen-not: %s", line);
			}

static int do_reachable_revlist(struct child_process *cmd,
			continue;
			parse_list_objects_filter(&filter_options, p);
		    !strcmp(arg, "sideband-all")) {
	if (shallow_nr)
}
	if (start_command(cmd))
			continue;
			unregister_shallow(&object->oid);
	for (i = get_max_object_index(); 0 < i; ) {


{
	 * have been based on the set of older refs advertised
			oid_to_hex(&want_obj->objects[i].item->oid));
			break;
	return 0;
			strbuf_addstr(value, " sideband-all");

			}
			o->flags |= WANTED;
				else if (have_obj->nr == 1)
/* Allow specifying sha1 if it is a ref tip. */
		if (!end || *end || !deepen_since ||
	upload_pack_data_clear(&data);
			add_object_array(o, NULL, want_obj);
{
			continue;
			ssize_t outsz = 0;
	if (has_non_tip)
		create_pack_file(&have_obj, &want_obj);
					 "uploadpack.allowrefinwant",

	unsigned use_thin_pack : 1;
	int i;
	char data[8193], progress[128];
	 * our ref.
}
	return;
			  struct object_array *want_obj)
	if (want_obj.nr) {
	}

			    oid_to_hex(&oid_buf));

#include "protocol.h"
	return 0;
	const unsigned hexsz = the_hash_algo->hexsz;
		ret = poll(pfd, pollsize,
	} else if (!strcmp("uploadpack.allowfilter", var)) {
static int send_acks(struct packet_writer *writer, struct oid_array *acks,
		add_object_array(o, NULL, have_obj);

		return;
	close(cmd.out);
					packet_write_fmt(1, "ACK %s common\n", last_hex);
		}

	FETCH_SEND_ACKS,
	pack_objects.err = -1;
	struct object_array shallows;
	timestamp_t deepen_since;
				struct object_array *src,
}
		}
	return 0;
	pack_objects.in = -1;
static int process_deepen(const char *line, int *depth)
#include "connect.h"
	int i;
		}
		string_list_append(deepen_not, ref);
	}
			char *cp = data;
{
static int shallow_nr;
	const char *arg;
static int parse_have(const char *line, struct oid_array *haves)
	struct oid_array haves = OID_ARRAY_INIT;
			if (stateless_rpc)

		packet_writer_write(writer, "ready\n");
	}
			o->flags &= ~TMP_MARK;
static int allow_ref_in_want;
	} else if (!strcmp("uploadpack.allowanysha1inwant", var)) {
			parents = ((struct commit *)object)->parents;
		packet_writer_flush(&data->writer);
			write_or_die(1, buf, 5);

	data->deepen_not = deepen_not;
		if (!repo_config_get_bool(the_repository,

		check_non_tip(want_obj, &writer);


{
	o->flags |= OUR_REF;
			if (have_obj->nr == 0 || multi_ack)
/*
			continue;
	}
	} else if (deepen_relative) {
		return 1;
		}
		}
		 *
		die(_("expected flush after fetch arguments"));
}
	}
			 * shallow clone. Unregister it for now so we can
{
			argv_array_push(&av, "--not");
	item->util = xstrdup(strip_namespace(symref_target));
	if (finish_command(&cmd))
			die("git upload-pack: not our ref %s",
#include "commit-reach.h"
			no_done = 1;

		     allow_sideband_all) &&
				/*
static int send_ref(const char *refname, const struct object_id *oid,
				 * guess they didn't want anything.
	struct object_id oid;
		if (process_deepen_not(reader->line, &deepen_not, &deepen_rev_list))
				    oid_to_hex(&acks->oid[i]));
		item = string_list_append(wanted_refs, arg);
					} else
			goto error;
				       &data->deepen_rev_list))

}
{
		}
	 */
error:

	mark_our_ref(refname, refname_full, oid);
			 * also need to traverse object's parents to deepen a
static void format_symref_info(struct strbuf *buf, struct string_list *symref)
		/* emergency quit */
			use_sideband = LARGE_PACKET_MAX;
{
	}
		goto error;
			 * accept a valid packdata with trailing garbage,
}
static int process_deepen_since(const char *line, timestamp_t *deepen_since, int *deepen_rev_list)
	namebuf[hexsz + 1] = '\n';
}
			pollsize++;
/* Returns 1 if a shallow list is sent or 0 otherwise */
	if (!data->wanted_refs.nr)
		}
		}
		packet_flush(1);
	for (;;) {
				return 0;
static int filter_capability_requested;
static void create_pack_file(const struct object_array *have_obj,
{
			if (!filter_capability_requested)
}
			we_knew_they_have = 1;
			die("invalid shallow object %s", oid_to_hex(&oid));
			default:
		if (object->flags & NOT_SHALLOW) {
	    !is_repository_shallow(the_repository))
			     (allow_unadvertised_object_request & ALLOW_TIP_SHA1) ?
				oid_to_hex_r(last_hex, &oid);
		}
		if (parse_feature_request(features, "side-band-64k"))

				break;
			die("git upload-pack: protocol error, "
		   struct object_array *have_obj)
	fprintf(pipe_fd, "--not\n");
			argv_array_push(&av, oid_to_hex(&o->oid));
	const char *arg;
		ret = 0;
			}
		no_progress = 1;
		deepen(&data->writer, INFINITE_DEPTH, data->deepen_relative,
		}

		if (expand_ref(the_repository, arg, strlen(arg), &oid, &ref) != 1)
		/* make sure commit traversal conforms to client */
		close(cmd->in);
			if (process_haves_and_send_acks(&data, &have_obj,
	if (do_reachable_revlist(&cmd, src, reachable) < 0)

}

	uint32_t min_generation = GENERATION_NUMBER_ZERO;
			      want_obj))
				o->flags |= THEY_HAVE;
		int allow_filter_value;
		return 1;

				    item->string);
				sz--;
	 * in the stateless RPC mode, however, their choice may
			    && !got_other && ok_to_give_up(have_obj, want_obj)) {
					     depth + 1,
		if (!o)
		close(cmd.out);
		*deepen_rev_list = 1;
			  struct strbuf *value)

	 */
				got_common = 1;

	struct object_array shallows = OBJECT_ARRAY_INIT;
	while (result) {
			return 1;
			 * or dump to the standard error.
				goto fail;
		if (process_deepen_since(arg, &data->deepen_since,
	if ((flag & REF_ISSYMREF) == 0)
	}
	const char *arg;
			}
	item = string_list_append(cb_data, strip_namespace(refname));
		o = get_indexed_object(--i);
				 */
static void deepen_by_rev_list(struct packet_writer *writer, int ac,
	} else {
			object->parsed = 0;
		if (!strcmp(arg, "deepen-relative")) {
	if (graft->nr_parent == -1)
		NOT_SHALLOW | CLIENT_SHALLOW | HIDDEN_REF)
	}
		if (parse_feature_request(features, "deepen-relative"))
#include "refs.h"
			     struct object_array *want_obj)
}
{
	if (!has_object_file(oid))
	while (state != FETCH_DONE) {
		switch (state) {
	 * should have chosen out of them. When we are operating

			   PACKET_READ_CHOMP_NEWLINE |
		for (i = 0; i < want_obj->nr; i++) {
		goto error;
	save_commit_buffer = 0;
	fclose(pipe_fd);
			continue;

						 NULL, want_obj);
		/* process have line */
				else if (multi_ack)

		else
			       data->deepen_since, &data->deepen_not,
	symref_target = resolve_ref_unsafe(refname, 0, NULL, &flag);
				     " allow-tip-sha1-in-want" : "",

		o = parse_object(the_repository, oid);
				/*
		argv_array_push(&pack_objects.args, "--include-tag");

		head_ref_namespaced(send_ref, &symref);
	use_sideband = LARGE_PACKET_MAX;
	 * The commits out of the rev-list are not ancestors of
		if (read_ref(arg, &oid)) {

	if (!use_sideband && daemon_mode)
	for (i = 0; i < want_obj->nr; i++)
			packet_writer_error(&writer,
 fail:
#include "sideband.h"
		if (!strcmp(arg, "no-progress")) {
			if (o->flags & THEY_HAVE)
		reset_timeout();
		reset_timeout();
	enum fetch_state state = FETCH_PROCESS_ARGS;
	if (shallow_nr)

			       &data->shallows, want_obj) &&

		    parse_oid_hex(arg, &oid_buf, &features))
	packet_writer_write(&data->writer, "shallow-info\n");
	cmd->git_cmd = 1;
			expand_list_objects_filter_spec(&filter_options);
		error("git upload-pack: git-pack-objects died with error.");
#include "diff.h"
			continue;
			object->flags |= NOT_SHALLOW;
static int stateless_rpc;
		die("unexpected line: '%s'", arg);
		die("'%s' is a symref but it is not?", refname);
		return -1;

		fprintf(stderr, "flushed.\n");
		 */
static struct list_objects_filter_options filter_options;
			}
			o->flags |= WANTED;

		" deepen-relative no-progress include-tag multi_ack_detailed";
				state = FETCH_DONE;
		const char *arg;

		char *end = NULL;
	string_list_clear(&data->deepen_not, 0);
	for (;;) {
static void send_client_data(int fd, const char *data, ssize_t sz)

	object_array_clear(&shallows);
		case FETCH_SEND_PACK:
		ret = 1;
			strbuf_addstr(value, " filter");
		fprintf(pipe_fd, "%s\n",
			else
	free_commit_list(result);
			}

	i = read_in_full(cmd.out, buf, 1);
}
			if (reachable)
		/*
			continue;
		/* process args like thin-pack */
				oldest_have = commit->date;
static int write_one_shallow(const struct commit_graft *graft, void *cb_data)
		else if (parse_feature_request(features, "side-band"))
			use_thin_pack = 1;
	packet_writer_delim(&data->writer);
}
	struct packet_writer writer;
	return 0;
}

			deepen_relative = 1;
		argv_array_push(&pack_objects.args, "--delta-base-offset");
				struct string_list_item *s = deepen_not->items + i;
	struct child_process cmd = CHILD_PROCESS_INIT;
		packet_write_fmt(1, "%s %s\n", oid_to_hex(oid), refname_nons);
			 * so appending garbage after we pass all the
		if (parse_feature_request(features, "include-tag"))
		packet_write_fmt(1, "%s %s^{}\n", oid_to_hex(&peeled), refname_nons);
			use_include_tag = 1;
{
		for_each_commit_graft(write_one_shallow, pipe_fd);
		format_symref_info(&symref_info, cb_data);

		struct object *o;
/* Remember to update object flag allocation in object.h */
			     struct string_list *deepen_not,
			for (i = 0; i < shallows->nr; i++)
		if (allow_filter && skip_prefix(arg, "filter ", &p)) {
			      &deepen_not, deepen_relative, &shallows,
		struct object *object = &result->item->object;
	namebuf[0] = '^';
					   &allow_sideband_all_value) &&
	result = get_shallow_commits_by_rev_list(ac, av, SHALLOW, NOT_SHALLOW);
			continue;
	/* No shallow info needs to be sent */

			pfd[pollsize].events = POLLIN;
		if (!oldest_have || (commit->date < oldest_have))
	FETCH_DONE,
		struct argv_array av = ARGV_ARRAY_INIT;
	} else if (!strcmp("uploadpack.allowsidebandall", var)) {
	struct object *o;
	if (start_command(&pack_objects))
		get_reachable_list(shallows, &reachable_shallows);
		     const struct object_array *have_obj,

			}
#include "commit.h"
	}
	}
{
}
{

	} else if (!strcmp("uploadpack.allowreachablesha1inwant", var)) {
static int process_haves(struct oid_array *haves, struct oid_array *common,
{
	struct object_array wants = OBJECT_ARRAY_INIT;
			allow_unadvertised_object_request &= ~ALLOW_TIP_SHA1;
	 * We have sent all our refs already, and the other end
		precomposed_unicode = git_config_bool(var, value);
		struct object *object = shallows->objects[i].item;
	fprintf(pipe_fd, "\n");
		if (get_oid_hex(arg, &oid))
		const char *arg = request->line;
					packet_write_fmt(1, "ACK %s continue\n", last_hex);

			sz = xread(pack_objects.out, cp,
		pollsize = 0;
				       struct object_array *want_obj)
}
		int i;
	}
		if (allow_ref_in_want &&

	int depth = 0;
}
		struct object *o;
		if (process_deepen_since(reader->line, &deepen_since, &deepen_rev_list))

#include "list-objects.h"
	if (depth == 0 && !deepen_rev_list && shallows.nr == 0)
{
	return o->flags & ((allow_hidden_ref ? HIDDEN_REF : 0) | OUR_REF);
	} else if (!strcmp("uploadpack.keepalive", var)) {

			break;

	cmd->in = -1;
	struct string_list symref = STRING_LIST_INIT_DUP;
	}
				 * Request had 'want's but no 'have's so we can
		if (parse_oid_hex(namebuf, &oid, &p) || *p != '\n')
		return 1;
	if (use_sideband) {

{
