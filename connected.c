	sigchain_pop(SIGPIPE);
		struct strbuf idx_file = STRBUF_INIT;

				error_errno(_("failed write to rev-list"));

	struct check_connected_options defaults = CHECK_CONNECTED_INIT;
	sigchain_push(SIGPIPE, SIG_IGN);
				 _("Checking connectivity"));
		 * For partial clones, we don't want to have to do a regular
			err = -1;

#include "packfile.h"
		/*
 * If we feed all the commits we want to verify to this command
					goto promisor_pack_found;
		/*
 *
}
		} while (!fn(cb_data, &oid));
	commit[hexsz] = '\n';
		 */
		 * each wanted ref.
		 * are sure the ref is good and not sending it to
no_promisor_pack_found:
		return err;
	argv_array_push(&rev_list.args, "--objects");
		strbuf_add(&idx_file, transport->pack_lockfile, base_len);
#include "connected.h"
		 * itself becomes a no-op because in a partial clone every
	if (start_command(&rev_list))
		argv_array_pushf(&rev_list.args, "--progress=%s",
		rev_list.no_stderr = opt->quiet;
	if (!opt)
	if (opt->progress)
		 * received, in a promisor packfile, the objects pointed to by
		if (new_pack && find_pack_entry_one(oid.hash, new_pack))
	argv_array_push(&rev_list.args, "--alternate-refs");
		reprepare_packed_git(the_repository);
		 *
 *
	argv_array_push(&rev_list.args,"rev-list");
#include "cache.h"
	if (has_promisor_remote()) {
promisor_pack_found:
		argv_array_push(&rev_list.args, "--not");
	size_t base_len;
		argv_array_push(&rev_list.args, "--all");
			close(opt->err_fd);
 * Returns 0 if everything is connected, non-zero otherwise.

	if (!opt->is_deepening_fetch) {
		 */
			goto no_promisor_pack_found;
		 * - the pack is self contained
		if (write_in_full(rev_list.in, commit, hexsz + 1) < 0) {
	struct transport *transport;
	if (fn(cb_data, &oid)) {
		do {
		argv_array_push(&rev_list.args, opt->shallow_file);
 *  $ git rev-list --objects --stdin --not --all


			break;
			}
	struct child_process rev_list = CHILD_PROCESS_INIT;
		strbuf_addstr(&idx_file, ".idx");
 *
		if (opt->err_fd)
		return 0;
		 * Before checking for promisor packs, be sure we have the
			if (errno != EPIPE && errno != EINVAL)
 */
	rev_list.env = opt->env;
	transport = opt->transport;
 * these commits locally exists and is connected to our existing refs.
	char commit[GIT_MAX_HEXSZ + 1];
#include "sigchain.h"
		rev_list.err = opt->err_fd;

	}

	    transport->smart_options->self_contained_and_connected &&
	struct object_id oid;
	return finish_command(&rev_list) || err;
		 * connectivity check because we have to enumerate and exclude
	}
	    strip_suffix(transport->pack_lockfile, ".keep", &base_len)) {
#include "transport.h"
#include "run-command.h"
		 * - there are no dangling pointers in the new pack
		 * rev-list for verification.
		new_pack = add_packed_git(idx_file.buf, idx_file.len, 1);
	if (close(rev_list.in))
	if (transport && transport->smart_options &&
		 * Then if the updated ref is in the new pack, then we

			/*
	} while (!fn(cb_data, &oid));
	rev_list.no_stdout = 1;
		strbuf_release(&idx_file);
		argv_array_push(&rev_list.args, "--shallow-file");
	if (has_promisor_remote())

	    transport->pack_lockfile &&
				if (!p->pack_promisor)
		}
/*
				if (find_pack_entry_one(oid.hash, p))
int check_connected(oid_iterate_fn fn, void *cb_data,
	}
	if (opt->err_fd)
			 */

#include "promisor-remote.h"
	}
	rev_list.git_cmd = 1;
	argv_array_push(&rev_list.args, "--quiet");
		err = error_errno(_("failed to close rev-list's stdin"));
	}
	rev_list.in = -1;
	argv_array_push(&rev_list.args, "--stdin");

	const unsigned hexsz = the_hash_algo->hexsz;
			 * object IDs provided by fn.
		opt = &defaults;
			;
 * Note that this does _not_ validate the individual objects.
{
		 * all promisor objects (slow), and then the connectivity check
	int err = 0;
 * and if it does not error out, that means everything reachable from
	if (opt->shallow_file) {
	else
		return error(_("Could not run 'git rev-list'"));
		    struct check_connected_options *opt)
		memcpy(commit, oid_to_hex(&oid), hexsz);
	do {
		 * latest pack-files loaded into memory.
		 * object is a promisor object. Instead, just make sure we
					continue;
		argv_array_push(&rev_list.args, "--exclude-promisor-objects");
		 * If index-pack already checked that:
			struct packed_git *p;


			 * Fallback to rev-list with oid and the rest of the
			continue;
#include "object-store.h"
	struct packed_git *new_pack = NULL;
			for (p = get_all_packs(the_repository); p; p = p->next) {
