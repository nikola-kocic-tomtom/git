		strbuf_addf(&refline, " symref-target:%s",
#include "cache.h"
	if (!ref_match(&data->prefixes, refname_nons))
}
			data.peel = 1;
		return 0;
	}

							       &flag);
	unsigned symrefs;
 * If no prefixes were provided, all refs match.
#include "ls-refs.h"
}

	struct argv_array prefixes;
static int send_ref(const char *refname, const struct object_id *oid,
	return 0;
	const char *refname_nons = strip_namespace(refname);
 */
	return parse_hide_refs_config(var, value, "uploadpack");
}
	head_ref_namespaced(send_ref, &data);
/*
	struct ls_refs_data *data = cb_data;
	/*
	}


	strbuf_release(&refline);
	if (!prefixes->argc)
	    struct packet_reader *request)
		const char *prefix = prefixes->argv[i];

		const char *symref_target = resolve_ref_unsafe(refname, 0,
		else if (skip_prefix(arg, "ref-prefix ", &out))
	while (packet_reader_read(request) == PACKET_READ_NORMAL) {
		if (!symref_target)
	struct ls_refs_data data;
	struct strbuf refline = STRBUF_INIT;
	if (request->status != PACKET_READ_FLUSH)
			    strip_namespace(symref_target));
{
{

		const char *out;
		struct object_id unused;
	for (i = 0; i < prefixes->argc; i++) {

struct ls_refs_data {
		if (!strcmp("peel", arg))
							       &unused,
	packet_flush(1);
	packet_write(1, refline.buf, refline.len);
#include "config.h"
	strbuf_addch(&refline, '\n');
		if (!peel_ref(refname, &peeled))


	 * don't yet know how that information will be passed to ls-refs.
			die("'%s' is a symref but it is not?", refname);
	}
}
};
	if (data->symrefs && flag & REF_ISSYMREF) {

{
	git_config(ls_refs_config, NULL);
	for_each_namespaced_ref(send_ref, &data);
		else if (!strcmp("symrefs", arg))
		return 0;
	 */
		if (starts_with(refname, prefix))

	 * We only serve fetches over v2 for now, so respect only "uploadpack"


	if (data->peel) {
#include "repository.h"

	}
			argv_array_push(&data.prefixes, out);
		return 1; /* no restriction */

		const char *arg = request->line;
#include "pkt-line.h"
	 * config. This may need to eventually be expanded to "receive", but we
{
			data.symrefs = 1;
int ls_refs(struct repository *r, struct argv_array *keys,
	memset(&data, 0, sizeof(data));
			return 1;
	return 0;
		die(_("expected flush after ls-refs arguments"));

	int i;

	argv_array_clear(&data.prefixes);
#include "refs.h"
static int ls_refs_config(const char *var, const char *value, void *data)
	return 0;

	unsigned peel;

static int ref_match(const struct argv_array *prefixes, const char *refname)

 * Check if one of the prefixes is a prefix of the ref.
	strbuf_addf(&refline, "%s %s", oid_to_hex(oid), refname_nons);
			strbuf_addf(&refline, " peeled:%s", oid_to_hex(&peeled));


	if (ref_is_hidden(refname_nons, refname))
#include "argv-array.h"
#include "remote.h"
		struct object_id peeled;
		    int flag, void *cb_data)

