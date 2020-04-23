
			opts->depth = strtol(value, &end, 0);
		default:
{
			summary, reset);
	if (!remote)
	GIT_COLOR_RED		/* REJECTED */
	if (!data->got_remote_heads)


			else
	} else if (!strcmp(name, TRANS_OPT_DEEPEN_RELATIVE)) {
			match_flags |= MATCH_REFS_PRUNE;
		 * (see builtin/fetch.c:quickfetch()).
					 NULL, &flag);
		result = ref;

 * remote refs.

	args.stateless_rpc = transport->stateless_rpc;
	fetch_refs_from_bundle,
		 */
			"[new branch]"),

	struct packet_reader reader;

}
		    transport->smart_options->cas &&
	TRANSPORT_COLOR_RESET = 0,
					oid_array_append(&commits,

		 * When deepening of a shallow repository is requested,

void transport_take_over(struct transport *transport,
	char *value;
			     struct ref *to, struct ref *from, const char *msg,
				       transport->remote, remote_refs);
}
	} else if (!strcmp(name, TRANS_OPT_DEEPEN_NOT)) {
}
				 for_push ? REF_NORMAL : 0,
#include "connect.h"
		opts->no_dependents = !!value;
					transport->server_options);
			 r->name, oid_to_hex(&r->old_oid));
}
		 */
	if (start_command(&proc)) {
			     const struct argv_array *ref_prefixes,
		if (from_user < 0)
	return ret;

				 int porcelain, int summary_width)
	struct oid_array shallow;
			fprintf(stdout, "%s (%s)\n", summary, msg);
		break;
#include "pkt-line.h"
		ret->smart_options->receivepack = "git-receive-pack";
					it->status = REF_STATUS_ATOMIC_PUSH_FAILED;

		transport->got_remote_refs = 1;
	args.atomic = !!(flags & TRANSPORT_PUSH_ATOMIC);
{
	else if (!strcasecmp(value, "user"))

	struct stat buf;

				  int verbose, int porcelain, unsigned int *reject_reasons)
	fprintf(stderr, _("The following submodule paths contain changes that can\n"
}
	static int initialized;
	return strchr(url, ':') - url;
				 "non-fast-forward", porcelain, summary_width);
	fd[1] = data->fd[1];
	data->got_remote_heads = 0;
	fetch_refs_via_pack,
	if (!transport->got_remote_refs) {
		if (!r->peer_ref) continue;

			if (find_unpushed_submodules(r,
		localname = ref->peer_ref->name;
	struct refspec_item rs;



}
	}


	} else if (!strcmp(name, TRANS_OPT_UPDATE_SHALLOW)) {
	struct ref *r;
		err = push_had_errors(remote_refs);
	data->conn = NULL;
		BUG("No remote provided to transport_get()");
			case '+': case '.': case '-':
	case REF_STATUS_NONE:
			     struct ref *remote_refs)
		return 0;

		strbuf_addf( &buf, "%s %s %s %s\n",
const struct ref *transport_get_remote_refs(struct transport *transport,
		finish_connect(data->conn);
	}
static int measure_abbrev(const struct object_id *oid, int sofar)
		 */
	args.progress = transport->progress;

 */

};
				trace2_region_leave("transport_push", "push_submodules", r);
	/* maybe it is a foreign URL? */
	} else if (!strcmp(name, TRANS_OPT_LIST_OBJECTS_FILTER)) {

}
	argv[3] = NULL;
	if (!nr_heads) {
		else {
		}
		print_ref_status('!', "[remote rejected]", ref,
	NULL,
	int force_progress)

				die(_("failed to push all needed submodules"));
}
		if ((flags & TRANSPORT_PUSH_ATOMIC) && err) {
			continue;
	if (!strcmp(type, "http") ||
			fprintf(stdout, "%s\n", summary);
	} else if (!strcmp(name, TRANS_OPT_FROM_PROMISOR)) {
{
	rs.dst = NULL;
#include "remote.h"
		struct argv_array ref_prefixes = ARGV_ARRAY_INIT;
		    "smart_options field.");

	args.deepen_since = data->options.deepen_since;
	if (enabled < 0) {
}
	return 0;
		return 0;

			transport_print_push_status(transport->url, remote_refs,
	case protocol_v2:
	if (!count) {
int is_transport_allowed(const char *type, int from_user)
	data->conn = NULL;
	int pretend)
	case protocol_v1:

			 const char *name, const char *value)
			continue;

	int git_reports = 1, protocol_reports = 1;
void transport_print_push_status(const char *dest, struct ref *refs,
		fputc('\n', stderr);
		      const char *exec, int fd[2])
{

	}
				die_with_unpushed_submodules(&needs_pushing);


				 porcelain, summary_width);
		      !pretend)) && !is_bare_repository()) {

			update_ref("update by push", rs.dst, &ref->new_oid,
	free_refs(refs);
			n += print_one_push_status(ref, dest, n,
				n += print_one_push_status(ref, dest, n,

				 porcelain, summary_width);
		 * will be checked individually in git_connect.

			match_flags |= MATCH_REFS_FOLLOW_TAGS;
	data->fd[1] = data->conn->in;
	if (reader.line_peeked)
	if (!url && remote->url)
};
		trace2_region_enter("transport_push", "get_refs_list", r);
	GIT_COLOR_RESET,
							       &ref_prefixes);
	} else if (!strcmp(name, TRANS_OPT_KEEP)) {
	return (w < sofar) ? sofar : w;
		finish_command(&proc);
				 "atomic push failed", porcelain, summary_width);
static int fetch_refs_via_pack(struct transport *transport,
	struct git_transport_data *data = transport->data;
		return 0;
		opts->deepen_not = (const struct string_list *)value;
	case protocol_v0:
		opts->uploadpack = value;
		if (push_had_errors(to)) {
		if (flags & TRANSPORT_PUSH_SET_UPSTREAM)
}
		transport->remote_refs =
	data->got_remote_heads = 1;
			continue;
	struct fetch_pack_args args;
	data->got_remote_heads = 0;
		print_ref_status('!', "[rejected]", ref, NULL,

		}
	case protocol_v2:
}
	if (!transport->smart_options)
		if (starts_with(p, "::"))
{
		get_refs_via_connect(transport, 1, NULL);
static struct transport_vtable bundle_vtable = {

	case protocol_unknown_version:
		if (!quiet || err)
	TRANSPORT_COLOR_REJECTED = 1
		case REF_STATUS_OK:
	for (i = 0; i < needs_pushing->nr; i++)



	if (refs == NULL)
		print_ref_status('X', "[no match]", ref, NULL, NULL,
}


	struct bundle_transport_data *data = transport->data;
}
#include "cache.h"
	fetch_refs_via_pack,
				oid_array_clear(&commits);
		strbuf_add_unique_abbrev(&quickref, &ref->old_oid,
	get_refs_via_connect,

			  "	git push --recurse-submodules=on-demand\n\n"

				 &data->extra_have,
 * this function returns NULL. Otherwise, this function returns the list of
{
					break;
		return 0;

static int print_one_push_status(struct ref *ref, const char *dest, int count,
{
		if (!git_config_get_string(keys[i], &value)) {

char *transport_anonymize_url(const char *url)
			transport->progress ? BUNDLE_VERBOSE : 0);
			n += print_one_push_status(ref, dest, n,
			  "	git push\n\n"
{

		ret = x;
	/* if defined, fallback to user-defined default for unknown protocols */
static int run_pre_push_hook(struct transport *transport,
				 porcelain, summary_width);
		return 0;

		print_ok_ref_status(ref, porcelain, summary_width);
					ref_prefixes,
		 * Just feed them all to the fetch method in that case.
		break;
		url = remote->url[0];
		    ref->status != REF_STATUS_UPTODATE &&


		return PROTOCOL_ALLOW_USER_ONLY;

		break;
	switch(ref->status) {
			fputs(msg, stderr);
{

		if (r->status == REF_STATUS_REJECT_NONFASTFORWARD) continue;
		break;
		return 0;
	const char *helper;

		return 0;
				transport_update_tracking_ref(transport->remote, ref, verbose);
	proc.in = -1;


	}
	struct ref *result = NULL;
	}
		break;
#include "send-pack.h"
		return 0;
	initialized = 1;
};
			for (; ref; ref = ref->next)
	const char *argv[4];
	int i;
{
	free(head);
	char *value;
			struct oid_array commits = OID_ARRAY_INIT;
}
		die(_("could not read bundle '%s'"), transport->url);
#include "color.h"
	case REF_STATUS_REJECT_NODELETE:
	data->options = *transport->smart_options;
	int n = 0;

	 *   . Don't report progress, if verbosity < 0 (ie. -q/--quiet ).
		opts->followtags = !!value;
		const char *red = "", *reset = "";
}
		int flag = 0;
		break;

	scheme_prefix = strstr(url, "://");
	args.use_thin_pack = data->options.thin;
}

		print_ref_status('!', "[rejected]", ref, ref->peer_ref,

	data->conn = git_connect(data->fd, transport->url,
	return ret;
		data->options.check_self_contained_and_connected;
			parse_protocol_config("protocol.allow", value);
	return xstrdup(url);
	struct ref **heads = NULL;


				 &data->shallow);
		return 0;
	if (!remote_find_tracking(remote, &rs)) {
			ret->smart_options->receivepack = remote->receivepack;
		const char *p = url;
		return;
		 * These are builtin smart transports; "allowed" transports
	if (ref->deletion)
		int must_list_refs = 0;
	packet_reader_init(&reader, data->fd[0], NULL, 0,
	}
	data->options.connectivity_checked = args.connectivity_checked;
	args.negotiation_tips = data->options.negotiation_tips;

	char hex[GIT_MAX_HEXSZ + 1];

			puts("Done");
	BUG("invalid protocol_allow_config type");
			break;
		free(rs.dst);


			struct ref *it;

	close(data->fd[0]);
		if (((flags & TRANSPORT_RECURSE_SUBMODULES_CHECK) ||
		print_ref_status('-', "[deleted]", ref, NULL, NULL,
};
	return unbundle(the_repository, &data->header, data->fd,
	if (porcelain) {
				default:
		if (ref->deletion) {
	close(data->fd[0]);
	int maxw = -1;
static int push_had_errors(struct ref *ref)
				goto literal_copy;
static int is_file(const char *url)

		print_ref_status('!', "[rejected]", ref, ref->peer_ref,
		ret->vtable = &builtin_smart_vtable;
	} else if (!strcmp(name, TRANS_OPT_THIN)) {
	}
	return refs;
		case REF_STATUS_UPTODATE:
			parse_protocol_config(key, value);
	int nr_heads = 0, nr_alloc = 0, nr_refs = 0;
	disconnect_git
				if (!is_null_oid(&ref->new_oid))
		const char *tmp;
int transport_disconnect(struct transport *transport)
		}
	struct bundle_header header;
	args.uploadpack = data->options.uploadpack;
			fputc(')', stderr);
			localname = tmp;
	memset(&args, 0, sizeof(args));
		return 0;
		break;
	for (; ref; ref = ref->next) {
static int connect_git(struct transport *transport, const char *name,

			switch (*cp) {

			delete_ref(NULL, rs.dst, NULL, 0);
		args.push_cert = SEND_PACK_PUSH_CERT_NEVER;
	} else if (!strcmp(name, TRANS_OPT_FOLLOWTAGS)) {
		refs = fetch_pack(&args, data->fd,
	if (!ret)
		opts->thin = !!value;
		else
	int fd;
	if (data->fd < 0)
		if (!ref->peer_ref)
struct transport *transport_get(struct remote *remote, const char *url)
	sigchain_pop(SIGPIPE);
		enum protocol_allow_config ret =
			if (!push_unpushed_submodules(r,
	if (initialized)
	struct git_transport_data *data = transport->data;
	if (data->conn)
	}
	/* Otherwise if both report unknown, report unknown. */

		/*
{
		if (ref->forced_update) {
	data->fd[0] = data->conn->out;


	connect_setup(transport, for_push);
{
		if (tmp && flag & REF_ISSYMREF &&
int transport_connect(struct transport *transport, const char *name,
{
	for (ref = refs; ref; ref = ref->next) {
{
	return 0;
			goto literal_copy;

	args.no_dependents = data->options.no_dependents;


}
	}
	enum protocol_version version;
			if (run_pre_push_hook(transport, remote_refs))
				 porcelain, summary_width);
	int w = find_unique_abbrev_r(hex, oid, DEFAULT_ABBREV);
	case protocol_v1:

	rc = transport->vtable->fetch(transport, nr_heads, heads);
static int transport_color_config(void)
	if (verbosity < 0)
	int flags = transport->verbose > 0 ? CONNECT_VERBOSE : 0;
{
			msg = NULL;
}
				 porcelain, summary_width);
		struct bundle_transport_data *data = xcalloc(1, sizeof(*data));
			*reject_reasons |= REJECT_FETCH_FIRST;
	}
	/* fallback to built-in defaults */
		print_ref_status('!', "[rejected]", ref, ref->peer_ref,
		 * already up-to-date ref create/modify (not delete).
			       int nr_heads, struct ref **to_fetch)
}
#include "url.h"
}
		cp = strchr(scheme_prefix + 3, '/');
		if (msg)
	    !strcmp(type, "https") ||
					int for_push,
			reset = transport_get_color(TRANSPORT_COLOR_RESET);
		transport_helper_init(ret, handler);
						     transport->remote->name,
	x = finish_command(&proc);
{
	int i;
		nr_refs++;
				trace2_region_leave("transport_push", "check_submodules", r);
	/* known scary; err on the side of caution */
	}
	ret |= finish_connect(data->conn);
{
		}
		strbuf_reset(&buf);
		opts->receivepack = value;
				 "needs force", porcelain, summary_width);
static int connect_setup(struct transport *transport, int for_push)
	fd[0] = data->fd[0];
	}
	struct git_transport_options options;
		return PROTOCOL_ALLOW_NEVER;
						      pretend)) {


	return 1;
		die(_("git-over-rsync is no longer supported"));
			struct ref *ref = remote_refs;

};
	data->fd = read_bundle_header(transport->url, &data->header);

	unsigned got_remote_heads : 1;
	if (transport->vtable->push_refs) {
	fprintf(stderr, _("\nPlease try\n\n"
	int rc;
			strbuf_addstr(&quickref, "...");
	return 0;
	if (verbosity >= 1)
		opts->deepen_relative = !!value;
{
			ret->smart_options->uploadpack = remote->uploadpack;
		fprintf(porcelain ? stdout : stderr, "To %s\n", url);
		} else
			strbuf_addstr(&quickref, "..");
void transport_set_verbosity(struct transport *transport, int verbosity,
		}
#include "run-command.h"
					     name, value);
		set_ref_status_for_push(remote_refs,
			}
				transport->remote->name);
#include "sigchain.h"
		close(data->fd);
	case REF_STATUS_OK:
	else
			struct string_list needs_pushing = STRING_LIST_INIT_DUP;
	if (stat(url, &buf))
	int ret = 0, x;
			  const char *name, const char *value)
		print_ref_status(type, quickref.buf, ref, ref->peer_ref, msg,
	NULL,
	git_transport_push,
				break; /* ok */
	data->get_refs_from_bundle_called = 1;
/*
#include "dir.h"
#include "object-store.h"
	case TRANSPORT_FAMILY_IPV6: flags |= CONNECT_IPV6; break;
{
		if (!remotename || !starts_with(remotename, "refs/heads/"))
		die(_("transport '%s' not allowed"), type);
		remote_refs = transport->vtable->get_refs_list(transport, 1,
		for (i = 0; i < nr_heads; i++) {
		if (is_null_oid(&ref->new_oid))
			helper = xstrndup(url, p - url);
	data->conn = git_connect(data->fd, transport->url,
				TRANSPORT_RECURSE_SUBMODULES_ONLY)) &&
	for (; refs; refs = refs->next) {
			trace2_region_leave("transport_push", "push_refs", r);
					oid_array_append(&commits,
		if (transport->smart_options &&
		ret->data = data;

	return ret;
				 "remote does not support deleting refs",
						      rs,

				localname + 11, remotename + 11,
		ret->data = data;
				 flags);
		warning(_("could not parse transport.color.* config"));
		die(_("support for protocol v2 not implemented yet"));
		tmp = resolve_ref_unsafe(localname, RESOLVE_REF_READING,
					 DEFAULT_ABBREV);
}
		return 0;
			trace2_region_enter("transport_push", "check_submodules", r);
#include "string-list.h"
				 "fetch first", porcelain, summary_width);
		struct ref_list_entry *e = data->header.references.list + i;
	PROTOCOL_ALLOW_USER_ONLY,
		}

	argv[2] = transport->url;
}
			packet_flush(data->fd[1]);
void transport_check_allowed(const char *type)
{
}
	char *key = xstrfmt("protocol.%s.allow", type);
			push_ret = transport->vtable->push_refs(transport, remote_refs, flags);
		get_remote_heads(&reader, &refs,


		die(_("operation not supported by protocol"));
		transport->verbose = -1;

		ret->vtable = &bundle_vtable;
	free(key);
		transport->progress = verbosity >= 0 && isatty(2);
		goto literal_copy;
	for (; ref; ref = ref->next) {
}

						      transport->push_options,
		break;
		opts->deepen_since = value;
	anon_len = strlen(++anon_part);
		argv_array_clear(&ref_prefixes);
		else
	if (url) {
	args.no_progress = !transport->progress;
		if (!value)
		for (rm = refs; rm; rm = rm->next)

	return PROTOCOL_ALLOW_USER_ONLY;
#include "fetch-pack.h"
			install_branch_config(BRANCH_CONFIG_VERBOSE,

	if (!scheme_prefix) {
{
		break;
}
	case REF_STATUS_UPTODATE:
static int transport_use_color = -1;
	free(heads);

			/* cannot be "me@there:/path/name" */
		enum protocol_allow_config ret =
			for (; ref; ref = ref->next)

	struct git_transport_data *data = transport->data;

		break;
	return 0;
				 executable, 0);
		|| starts_with(url, "ssh+git://") /* deprecated - do not use */
		if ((flags & (TRANSPORT_RECURSE_SUBMODULES_ON_DEMAND |
			fputs(" (", stderr);
		break;
	proc.argv = argv;
	if (transport->pack_lockfile) {
		switch(ref->status) {



	args.check_self_contained_and_connected =


			     int porcelain, int summary_width)
	if (whitelist)
		 * then local and remote refs are likely to still be equal.
				 porcelain, summary_width);

			if (head != NULL && !strcmp(head, ref->name))
	switch (data->version) {
			return 1;

	if (!git_config_get_string(key, &value)) {
		/* make sure scheme is reasonable */
	 * Rules used to determine whether to report progress (processing aborts
{
			if (ref->status == REF_STATUS_UPTODATE)

	return 0;
		}
	get_refs_via_connect,
	else if (flags & TRANSPORT_PUSH_CERT_IF_ASKED)
	if (data->fd > 0)
	if (data->fd > 0)
						   porcelain, summary_width);
		if (cp && cp < anon_part)
	}

	struct git_transport_data *data = transport->data;
				 ref->peer_ref, NULL, porcelain, summary_width);
 * refs, and must_list_refs is 0, the listing of remote refs is skipped and
		"color.transport.rejected"

			trace2_region_leave("transport_push", "check_submodules", r);
				*reject_reasons |= REJECT_NON_FF_OTHER;
					break;
	else
static struct ref *handshake(struct transport *transport, int for_push,
	struct git_transport_data *data = transport->data;
			flags & TRANSPORT_PUSH_FORCE);
		    !is_null_oid(&rm->old_oid) &&
	for (ref = refs; ref; ref = ref->next)
		if (!(flags & (TRANSPORT_PUSH_DRY_RUN |

		    !is_empty_cas(transport->smart_options->cas))
		break;
							const char *value)
		ref->next = result;
				 ref->deletion ? NULL : ref->peer_ref,
	args.update_shallow = data->options.update_shallow;
			ref->status != REF_STATUS_UPTODATE)
void transport_unlock_pack(struct transport *transport)
		switch (ref->status) {
					const struct argv_array *ref_prefixes)
	}
	case REF_STATUS_REJECT_NONFASTFORWARD:
	/* first check the per-protocol config */
		    ref->status != REF_STATUS_OK)
		|| starts_with(url, "file://")
	if (!git_reports || !protocol_reports)
	 *   . Report progress, if force_progress is 1 (ie. --progress).
static char transport_colors[][COLOR_MAXLEN] = {
	args.send_mirror = !!(flags & TRANSPORT_PUSH_MIRROR);
	struct oid_array extra_have;
	}
	if (!transport->server_options || !transport->server_options->nr)
	}
		struct strbuf quickref = STRBUF_INIT;
 */
		if (remote->receivepack)
		close(data->fd[1]);
static int git_transport_push(struct transport *transport, struct ref *remote_refs, int flags)
			apply_push_cas(transport->smart_options->cas,
static void die_with_unpushed_submodules(struct string_list *needs_pushing)
	if (transport->vtable->set_option)

	} else if (!strcmp(name, TRANS_OPT_NO_DEPENDENTS)) {
	memset(&args, 0, sizeof(args));
				 "already exists", porcelain, summary_width);
		ret = push_ret | err;
		parse_list_objects_filter(&opts->filter_options, value);
						     &needs_pushing)) {
		print_ref_status('!', "[rejected]", ref, ref->peer_ref,


			struct ref *ref;
		} else {

		maxw = measure_abbrev(&refs->old_oid, maxw);
		print_ref_status('!', "[rejected]", ref, ref->peer_ref,
			}
		int verbose = (transport->verbose > 0);


	args.include_tag = data->options.followtags;
			fprintf(stderr, "updating local tracking ref '%s'\n", rs.dst);
	close(data->fd[1]);
	}, *key = "color.transport";

		return 0;
{
			return 1;
	data->options.self_contained_and_connected =
	return 0;
	 *   . Report progress if isatty(2) is 1.


 * Obtains the protocol version from the transport and writes it to
			trace2_region_leave("transport_push", "push_submodules", r);
	if (url_is_local_not_ssh(url) || !anon_part)
		return ret;
{
		args.self_contained_and_connected;
		struct ref *local_refs = get_local_heads();
static struct transport_vtable builtin_smart_vtable = {
	case protocol_unknown_version:
		else
	case REF_STATUS_ATOMIC_PUSH_FAILED:
#include "refspec.h"
		char *url = transport_anonymize_url(dest);
		} else
		opts->update_shallow = !!value;
		}
{

void transport_update_tracking_ref(struct remote *remote, struct ref *ref, int verbose)
struct bundle_transport_data {
		break;
{
	if (helper) {
		       const char *executable, int fd[2])
			fprintf(stdout, "%c\t:%s\t", flag, to->name);
					reject_reasons);
	ret->progress = isatty(2);


			     int must_list_refs)
		ret = -1;
			struct oid_array commits = OID_ARRAY_INIT;
 * Strip username (and password) from a URL and return
{
}
	switch (data->version) {
	case PROTOCOL_ALLOW_USER_ONLY:


		if (from)
		if (ref->status != REF_STATUS_NONE &&
		if (ref->status != REF_STATUS_OK &&
		return 0;

				case REF_STATUS_OK:
	/**
#include "submodule.h"
};

					const struct argv_array *ref_prefixes)
{

		print_ref_status('*',
};

		if (ref->status == REF_STATUS_REJECT_NONFASTFORWARD) {
		   struct refspec *rs, int flags,

	advise(_("see protocol.version in 'git help config' for more details"));
	string_list_clear(needs_pushing, 0);
		}
			from_user = git_env_bool("GIT_PROTOCOL_FROM_USER", 1);
		break;
			 r->peer_ref->name, oid_to_hex(&r->new_oid),

		args.push_cert = SEND_PACK_PUSH_CERT_IF_ASKED;
	args.server_options = transport->server_options;
			enabled = 0;

		break;
	struct git_transport_data *data;
		return 0;
		return string_list_has_string(whitelist, type);
		BUG("buffer must be empty at the end of handshake()");
	args.from_promisor = data->options.from_promisor;
	static struct string_list allowed = STRING_LIST_INIT_DUP;
				 data->options.uploadpack,
	if (transport_color_config() < 0)
	head = resolve_refdup("HEAD", RESOLVE_REF_READING, NULL, NULL);
			fprintf(stderr, "%s -> %s", prettify_refname(from->name), prettify_refname(to->name));
	return transport->remote_refs;
		case REF_STATUS_NONE:
	if (finish_connect(data->conn))
#include "branch.h"
}
	 *   . Don't report progress, if force_progress is 0 (ie. --no-progress).
	case REF_STATUS_EXPECTING_REPORT:
static struct ref *get_refs_via_connect(struct transport *transport, int for_push,
		if (check_push_refs(local_refs, rs) < 0)
	if (!strcmp(type, "ext"))
	/* known safe */
		strbuf_release(&quickref);
	} else {
		const char *cp;
		data->conn = NULL;
		if (match_push_refs(local_refs, &remote_refs, rs, match_flags))
{
{
		ret = -1;
		       (int)anon_len, anon_part);
		opts->keep = !!value;
	struct transport *ret = xcalloc(1, sizeof(*ret));
int transport_push(struct repository *r,
		transport_check_allowed("file");
	proc.trace2_hook_name = "pre-push";
	}

		int len = external_specification_len(url);
		/*
	case protocol_v0:
	args.verbose = (transport->verbose > 0);
	}
		BUG("unknown protocol version");
			*reject_reasons |= REJECT_ALREADY_EXISTS;
{
	}
				must_list_refs = 1;
}
		print_ref_status('!', "[rejected]", ref, ref->peer_ref,
		if (flags & TRANSPORT_PUSH_FOLLOW_TAGS)
		ret = -1;
	case protocol_v2:


}
	if (!git_config_get_string(key, &value))
			(starts_with(ref->name, "refs/tags/") ? "[new tag]" :
		/* Both source and destination must be local branches. */

		transport->verbose = verbosity <= 3 ? verbosity : 3;
		int match_flags = MATCH_REFS_NONE;
		return 0;
/*

						      transport->remote,
	return 1;
		free(url);
		if (!strchr(anon_part, ':'))
			ref, ref->peer_ref, NULL, porcelain, summary_width);
		free(value);
	args.cloning = transport->cloning;
	if (data->conn) {
	anon_part = strchr(url, '@');

				*reject_reasons |= REJECT_NON_FF_HEAD;
			default:
	if (transport->smart_options)
	if (transport_color_config() < 0)
		return 0;
		transport_helper_init(ret, helper);
static int close_bundle(struct transport *transport)
}
				break;
}
		if (porcelain && !push_ret)
	return 0;
	}
		if (data->got_remote_heads && !transport->stateless_rpc)
		}
static enum protocol_allow_config parse_protocol_config(const char *key,
			      TRANSPORT_RECURSE_SUBMODULES_ONLY)) &&
	if ((git_reports == -1) || (protocol_reports == -1))
	else
#include "protocol.h"
		break;
		close(data->fd);
			   PACKET_READ_CHOMP_NEWLINE |
	connect_git,
							  &ref->new_oid);
				 "remote failed to report status",
		/* Follow symbolic refs (mainly for HEAD). */
				localname + 11, transport->remote->name,
		ret = transport->vtable->disconnect(transport);
		return -1;
			   PACKET_READ_GENTLE_ON_EOF |
#include "transport.h"
	args.porcelain = !!(flags & TRANSPORT_PUSH_PORCELAIN);
	args.filter_options = data->options.filter_options;
	struct ref *rm;
		int porcelain = flags & TRANSPORT_PUSH_PORCELAIN;
		close(data->fd[0]);
		if (!(flags & TRANSPORT_PUSH_NO_HOOK))
	case protocol_v0:
	free(data);

	if (ref->status != REF_STATUS_OK && ref->status != REF_STATUS_UPTODATE)

		BUG("unknown protocol version");
#include "walker.h"
	 * when a rule is satisfied):
}
 * If the protocol version is one that allows skipping the listing of remote

	int ret = 0;
		}
		list_objects_filter_die_if_populated(&opts->filter_options);

{
		oidcpy(&ref->old_oid, &e->oid);
		struct git_transport_data *data = xcalloc(1, sizeof(*data));
	}
	for (ref = refs; ref; ref = ref->next) {
	if (!want_color_stderr(transport_use_color))
static const char *transport_get_color(enum color_transport ix)

	struct git_transport_data *data = transport->data;
				  refs_tmp ? refs_tmp : transport->remote_refs,
		if (verbose)
		fprintf(stderr, "  %s\n", needs_pushing->items[i].string);
	NULL,
			goto literal_copy;


		free(value);
static struct transport_vtable taken_over_vtable = {
		maxw = measure_abbrev(&refs->new_oid, maxw);
int transport_set_option(struct transport *transport,
		    !is_bare_repository()) {
			*reject_reasons |= REJECT_NEEDS_FORCE;
static void set_upstreams(struct transport *transport, struct ref *refs,

			   PACKET_READ_DIE_ON_ERR_PACKET);
	die(_("server options require protocol version 2 or later"));
{
			for (ref = remote_refs; ref; ref = ref->next)
			for (it = remote_refs; it; it = it->next)

}
							  &ref->new_oid);
			enabled = 1;
		case REF_STATUS_NONE:
{

		unlink_or_warn(transport->pack_lockfile);
								 name, value);
		if (from)

		maxw = FALLBACK_DEFAULT_ABBREV;
	args.force_update = !!(flags & TRANSPORT_PUSH_FORCE);
}
		|| starts_with(url, "ssh://")
		}
	}
				 ref->remote_status, porcelain, summary_width);
		char type;
		return from_user;
			match_flags |= MATCH_REFS_MIRROR;

		return NULL;
static void print_ref_status(char flag, const char *summary,
				return -1;
	if (transport_color_config() < 0)
	}
				   NULL, 0, 0);
	close(data->fd[1]);
		 * Check suitability for tracking. Must be successful /
static enum protocol_allow_config get_protocol_config(const char *type)
		if (msg) {
		free(key);
	struct ref *refs = NULL;
	strbuf_release(&buf);
			opts->depth = 0;

		if (flags & TRANSPORT_PUSH_PRUNE)
			type = ' ';
		}
	char *scheme_prefix, *anon_part;
				if (isalnum(*cp))
	struct bundle_transport_data *data = transport->data;
static int fetch_refs_from_bundle(struct transport *transport,
		protocol_reports = transport->vtable->set_option(transport,
	for (rm = refs; rm; rm = rm->next) {
}
	if (verbose) {
	NULL,
	*reject_reasons = 0;
			p++;
	const char *keys[] = {
		strbuf_add_unique_abbrev(&quickref, &ref->new_oid,
	struct bundle_transport_data *data = transport->data;
	/* If either reports -1 (invalid value), report -1. */
{
 * it in a newly allocated string.
static int set_git_option(struct git_transport_options *opts,
enum color_transport {
							 ref_prefixes);
		return ret;
			starts_with(tmp, "refs/heads/"))
			set_upstreams(transport, remote_refs, pretend);
			heads[nr_heads++] = rm;
	char *head;

				/* RFC 1738 2.1 */
		heads[nr_heads++] = rm;
static struct ref *get_refs_from_bundle(struct transport *transport,
		BUG("taking over transport requires non-NULL "
	static int enabled = -1;
	strbuf_init(&buf, 256);
		/* @ past the first slash does not count */
	if (!strcmp(name, TRANS_OPT_UPLOADPACK)) {
				 "new shallow roots not allowed",
		|| starts_with(url, "git://")

		if (!pretend)
{
	case REF_STATUS_REJECT_FETCH_FIRST:
	struct child_process proc = CHILD_PROCESS_INIT;
#include "bundle.h"
#include "config.h"
		ret->smart_options = NULL;
		return;
		die_if_server_options(transport);
				return config_error_nonbool(keys[i]);
	die(_("Aborting."));
	free(transport);
	*reject_reasons = 0;
		remotename = ref->name;
	if (!data->got_remote_heads) {

	/* If either report is 0, report 0 (success). */

			trace2_region_enter("transport_push", "push_refs", r);
		get_refs_from_bundle(transport, 0, NULL);
		ret = send_pack(&args, data->fd, data->conn, remote_refs,
	case REF_STATUS_REJECT_SHALLOW:
	if (transport->vtable->connect)
			}
			oid_array_clear(&commits);
	ret->got_remote_refs = 0;
	if (!data->get_refs_from_bundle_called)
		else if (!quiet && !ret && !transport_refs_pushed(remote_refs))
	    !strcmp(type, "file"))
	PROTOCOL_ALLOW_NEVER = 0,
		   unsigned int *reject_reasons)
				  &transport->pack_lockfile, data->version);
				remotename);
			oid_array_clear(&commits);
				  to_fetch, nr_heads, &data->shallow,
	else {
		opts->from_promisor = !!value;
		const char *v = getenv("GIT_ALLOW_PROTOCOL");
		}
		if (rm->peer_ref &&
		BUG("unknown protocol version");
};

	case REF_STATUS_REJECT_NEEDS_FORCE:
}
{
			"not be found on any remote:\n"));
			/* We do not mind if a hook does not read all refs. */

	} else if (!strcmp(name, TRANS_OPT_DEEPEN_SINCE)) {
		} else if (ref->status == REF_STATUS_REJECT_FETCH_FIRST) {

	int summary_width = transport_summary_width(refs);
	args.deepen_not = data->options.deepen_not;
{
		else
		return transport_colors[ix];
	if (!is_transport_allowed(type, -1))

			  "to push them to a remote.\n\n"));
}
		args.push_cert = SEND_PACK_PUSH_CERT_ALWAYS;
{
		if (ref->status == REF_STATUS_OK)
	if (flags & TRANSPORT_PUSH_CERT_ALWAYS)
		ALLOC_ARRAY(heads, nr_refs);
			return -1;
int transport_summary_width(const struct ref *refs)
	data = xcalloc(1, sizeof(*data));
			if (errno != EPIPE)

		return 0;
		/* Unknown protocol in URL. Pass to external handler. */
	}
			continue;
		transport->progress = !!force_progress;

	case protocol_v1:

	data->version = discover_version(&reader);

	}
				/* it isn't */
			  "or cd to the path and use\n\n"


}
			}
				ret = -1;
	} else if (!strcmp(name, TRANS_OPT_DEPTH)) {
{
	switch (data->version) {
			string_list_sort(&allowed);
	if (force_progress >= 0)
			continue;
	return ret;
	rs.src = ref->name;
		if (remote->uploadpack)
						     &commits,
	args.verbose = (transport->verbose > 1);
literal_copy:
	transport->data = data;
	NULL,
	return ret;
	/* unknown; by default let them be used only directly by the user */
	if (ret->smart_options) {
						   porcelain, summary_width);

{
	} else if (!is_url(url)
				oid_array_clear(&commits);
			printf(_("Would set upstream of '%s' to '%s' of '%s'\n"),
		ret = x;
	} else {
		while (is_urlschemechar(p == url, *p))
		default:
	struct ref *refs_tmp = NULL;
	unsigned get_refs_from_bundle_called : 1;
	free_refs(refs_tmp);
	helper = remote->foreign_vcs;
	return handshake(transport, for_push, ref_prefixes, 1);
		     ((flags & (TRANSPORT_RECURSE_SUBMODULES_ON_DEMAND |

			get_remote_refs(data->fd[1], &reader, &refs, for_push,
	sigchain_push(SIGPIPE, SIG_IGN);
		return 0;
		) {
	 **/
	args.use_thin_pack = data->options.thin;
#include "refs.h"
			string_list_split(&allowed, v, ':', -1);

	return result;
			match_flags |= MATCH_REFS_ALL;
		return -1;
	if (!strcasecmp(value, "always"))
			 struct child_process *child)
	int ret = 0;
static int external_specification_len(const char *url)
	return xstrfmt("%.*s%.*s", (int)prefix_len, url,
	for (i = 0; i < ARRAY_SIZE(keys); i++)
int transport_refs_pushed(struct ref *ref)
		if (flags & TRANSPORT_PUSH_ALL)
		refs = fetch_pack(&args, data->fd,
}
		print_ref_status('!', "[rejected]", ref, ref->peer_ref,
	case TRANSPORT_FAMILY_IPV4: flags |= CONNECT_IPV4; break;
	if (maxw < 0)
		if (r->status == REF_STATUS_REJECT_STALE) continue;
		int push_ret, ret, err;
		 * This condition shouldn't be met in a non-deepening fetch
				switch (it->status) {
							   porcelain, summary_width);
				  &transport->pack_lockfile, data->version);
}
	struct strbuf buf;
	int fd[2];
	} else if (!strcmp(name, TRANS_OPT_RECEIVEPACK)) {
	args.quiet = (transport->verbose < 0);
	case PROTOCOL_ALLOW_ALWAYS:
		if (v) {
	if (want_color_stderr(transport_use_color))
	if (for_push)
		data->got_remote_heads = 0;
		return PROTOCOL_ALLOW_ALWAYS;
	if (transport->vtable->disconnect)
	}
	else if (!strcasecmp(value, "never"))
		print_ref_status('!', "[remote failure]", ref,
			red = transport_get_color(TRANSPORT_COLOR_REJECTED);
		case REF_STATUS_UPTODATE:
 *
			transport->vtable->get_refs_list(transport, 0,
		   struct transport *transport,
	if (report_unmatched_refs(to_fetch, nr_heads))
	for (r = remote_refs; r; r = r->next) {
		transport_use_color = git_config_colorbool(key, value);
		int pretend = flags & TRANSPORT_PUSH_DRY_RUN;
	switch (transport->family) {
		int quiet = (transport->verbose < 0);
	}
static void die_if_server_options(struct transport *transport)
			if (!value)
		struct ref *remote_refs;

		int i;

	args.url = transport->url;
				case REF_STATUS_UPTODATE:
			char *end;

			fprintf(stdout, "%c\t%s:%s\t", flag, from->name, to->name);

		return 0;
		} else if (ref->status == REF_STATUS_REJECT_ALREADY_EXISTS) {
static const struct string_list *protocol_whitelist(void)
	transport->vtable = &taken_over_vtable;
	if (!ret)
	case TRANSPORT_FAMILY_ALL: break;
		return PROTOCOL_ALLOW_ALWAYS;
	}
				&data->extra_have);
	    !strcmp(type, "git") ||
struct git_transport_data {
	const struct string_list *whitelist = protocol_whitelist();
		break;
		"color.transport.reset",

	struct child_process *conn;
		ret->smart_options->thin = 1;
	die(_("unknown value for config '%s': %s"), key, value);
		char *handler = xmemdupz(url, len);
			if (color_parse(value, transport_colors[i]) < 0)
	struct ref *ref;
enum protocol_allow_config {

		return -1;
	int ret = 0;
			push_ret = 0;
	} else if (starts_with(url, "rsync:")) {
	}
		ret->smart_options->uploadpack = "git-upload-pack";
			if (!to_fetch[i]->exact_oid) {

		refspec_ref_prefixes(rs, &ref_prefixes);
}
		FREE_AND_NULL(transport->pack_lockfile);
				 ref->deletion ? NULL : ref->peer_ref,
		die_if_server_options(transport);
		git_reports = set_git_option(transport->smart_options,
		ret->smart_options = &(data->options);
						      &commits,
	transport->smart_options = &(data->options);
				if (!is_null_oid(&ref->new_oid))
#include "oid-array.h"
	return enabled ? &allowed : NULL;
		break;
	args.keep_pack = data->options.keep;
					    const struct argv_array *ref_prefixes)
		if (must_list_refs)
		if (r->status == REF_STATUS_UPTODATE) continue;
	args.quiet = (transport->verbose < 0);
		return -1;
	close_bundle
				die(_("transport: invalid depth option '%s'"), value);
		}
	args.push_options = transport->push_options;
	size_t anon_len, prefix_len = 0;
		print_ref_status('=', "[up to date]", ref,

			string_list_clear(&needs_pushing, 0);
	x = close(proc.in);
	if (!(argv[0] = find_hook("pre-push")))
					verbose | porcelain, porcelain,
	argv[1] = transport->remote->name;
	} else if (url_is_local_not_ssh(url) && is_file(url) && is_bundle(url, 1)) {
	}

	data->got_remote_heads = 0;
				}
	get_refs_from_bundle,
		|| starts_with(url, "git+ssh://") /* deprecated - do not use */
	case REF_STATUS_REMOTE_REJECT:
			       int nr_heads, struct ref **to_fetch)
	data->conn = child;
		const char *localname;
	ret->remote = remote;
 * transport->data->version, first connecting if not already connected.
	}
	case protocol_unknown_version:
static void print_ok_ref_status(struct ref *ref, int porcelain, int summary_width)
	    !strcmp(type, "ssh") ||
		return PROTOCOL_ALLOW_NEVER;
	git_transport_push,
		if (write_in_full(proc.in, buf.buf, buf.len) < 0) {
		return 1;
	struct ref *ref;
	return S_ISREG(buf.st_mode);

		return transport->vtable->connect(transport, name, exec, fd);
{
	return 1;


	int i;
			type = '+';
			fputs(prettify_refname(to->name), stderr);
	}
			struct ref *ref = remote_refs;

	else if (is_null_oid(&ref->old_oid))
	case REF_STATUS_REJECT_STALE:
		if (!(flags & TRANSPORT_RECURSE_SUBMODULES_ONLY)) {
	return "";
				 "stale info", porcelain, summary_width);
		const char *remotename;
			break;
	free(data);
	ret->url = url;
		struct ref *ref = alloc_ref(e->name);
					 DEFAULT_ABBREV);
			continue;
	return (2 * maxw + 3);
}
	transport->cannot_reuse = 1;
		} else {
static int disconnect_git(struct transport *transport)
	case REF_STATUS_REJECT_ALREADY_EXISTS:
	args.deepen_relative = data->options.deepen_relative;
	struct ref *refs = NULL;
				 for_push ? data->options.receivepack :
			msg = "forced update";
	args.dry_run = !!(flags & TRANSPORT_PUSH_DRY_RUN);
		trace2_region_leave("transport_push", "get_refs_list", r);
		refs_tmp = handshake(transport, 0, NULL, must_list_refs);
				return -1;
int transport_fetch_refs(struct transport *transport, struct ref *refs)
		prefix_len = scheme_prefix - url + 3;
	switch (get_protocol_config(type)) {
}

	disconnect_git
	if (!git_config_get_string("protocol.allow", &value)) {
}
		for (ref = refs; ref; ref = ref->next)
	args.depth = data->options.depth;
	args.lock_pack = 1;
		if (!localname || !starts_with(localname, "refs/heads/"))
	struct send_pack_args args;
	PROTOCOL_ALLOW_ALWAYS
			if (*end)
		const char *msg;
{
				  to_fetch, nr_heads, &data->shallow,
	return rc;
		}
		} else if (ref->status == REF_STATUS_REJECT_NEEDS_FORCE) {
		break;
	} else {
		return 0;
				case REF_STATUS_NONE:

	NULL,
#include "transport-internal.h"
		ALLOC_GROW(heads, nr_heads + 1, nr_alloc);
	for (i = 0; i < data->header.references.nr; i++) {
	return 1;
	}
		fprintf(stderr, " %s%c %-*s%s ", red, flag, summary_width,
{
			break;
		for (cp = url; cp < scheme_prefix; cp++) {

				  refs_tmp ? refs_tmp : transport->remote_refs,
		    oideq(&rm->peer_ref->old_oid, &rm->old_oid))

					break;

			       TRANSPORT_RECURSE_SUBMODULES_ONLY))) {
			return -1;
		return ret;
			flags & TRANSPORT_PUSH_MIRROR,
	 *
		/*
			fprintf(stderr, "Everything up-to-date\n");
			trace2_region_enter("transport_push", "push_submodules", r);
	case PROTOCOL_ALLOW_NEVER:
	}
		if (flags & TRANSPORT_PUSH_MIRROR)
