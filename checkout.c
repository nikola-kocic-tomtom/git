	cb_data.src_ref = xstrfmt("refs/heads/%s", name);
	    get_oid(query.dst, cb->dst_oid)) {

		free(cb_data.default_dst_oid);
	return 0;
	const char *default_remote = NULL;
#include "refspec.h"
	char *dst_ref;
		return 0;
}
				 int *dwim_remotes_matched)
#include "cache.h"
		free(query.dst);
		return cb_data.dst_ref;
	query.src = cb->src_ref;
	/* const */ char *src_ref;
	cb->dst_ref = query.dst;
	cb->num_matches++;
	if (remote_find_tracking(remote, &query) ||
		free(query.dst);
	struct object_id *default_dst_oid;
	}
	}
};
	struct tracking_name_data *cb = cb_data;
	if (!git_config_get_string_const("checkout.defaultremote", &default_remote))
	if (cb->default_remote && !strcmp(remote->name, cb->default_remote)) {
}
	cb_data.dst_oid = oid;

	if (cb_data.default_dst_ref) {
static int check_tracking_name(struct remote *remote, void *cb_data)
		free(cb_data.default_dst_ref);
{
	struct object_id *dst_oid;
		oidcpy(oid, cb_data.default_dst_oid);
	for_each_remote(check_tracking_name, &cb_data);
	return NULL;
	struct refspec_item query;
		cb->default_dst_oid = dst;
		struct object_id *dst = xmalloc(sizeof(*cb->default_dst_oid));
	}
		*dwim_remotes_matched = cb_data.num_matches;
{
		oidcpy(dst, cb->dst_oid);

	char *default_dst_ref;
	free((char *)default_remote);
	}
		return cb_data.default_dst_ref;
#define TRACKING_NAME_DATA_INIT { NULL, NULL, NULL, 0, NULL, NULL, NULL }
		cb->default_dst_ref = xstrdup(query.dst);
	memset(&query, 0, sizeof(struct refspec_item));
	free(cb_data.dst_ref);
const char *unique_tracking_name(const char *name, struct object_id *oid,
	}
#include "config.h"
#include "checkout.h"
	if (dwim_remotes_matched)
struct tracking_name_data {
	free(cb_data.src_ref);
		return 0;
	int num_matches;
		free(cb_data.default_dst_oid);
	struct tracking_name_data cb_data = TRACKING_NAME_DATA_INIT;

#include "remote.h"
	if (cb_data.num_matches == 1) {
	if (cb->dst_ref) {
	const char *default_remote;
		cb_data.default_remote = default_remote;
