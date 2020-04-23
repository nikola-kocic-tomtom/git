			    oid_to_hex(&ctx->commits.list[i]->object.oid));
	if (!(flags & COMMIT_GRAPH_VERIFY_SHALLOW) && g->base_graph)
		error(_("commit-graph hash version %X does not match version %X"),
	int num_chunks = 3;
	}
		last_chunk_offset = chunk_offset;
	strbuf_addch(&path, '/');

	o->commit_graph = NULL;
	}
	if (commit_hex) {
	struct commit_graph *g = ctx->r->objects->commit_graph;
			graph_report(_("commit-graph has incorrect fanout value: fanout[%d] = %u != %u"),

	if (num != ctx->num_commit_graphs_after - 1) {

{
		if (parse_commit_no_graph(*list))
	graph->num_chunks = *(unsigned char*)(data + 6);
		if (result) {
	}
		     parent = parent->next)
	uint32_t current_graph_number = ctx->num_commit_graphs_before;
}
			odb_parents = odb_parents->next;
		error(_("commit-graph version %X does not match version %X"),
		num_commits += g->num_commits;
			if (!strcmp(ctx->commit_graph_filenames_after[i],
		parse_commit_no_graph(ctx->commits.list[ctx->commits.nr]);
#define GRAPH_VERSION_1 0x1
static void write_graph_chunk_extra_edges(struct hashfile *f,
		hold_lock_file_for_update(&lk, lock_name, LOCK_DIE_ON_ERROR);
{
		return NULL;
	unsigned char graph_version, hash_version;
}
}
		num_chunks++;
		return 0;
	 */

{
 */
	uint32_t i, count_distinct = 1;

	if (ctx->split)
		 split:1,
	if (ret)
				     graph_commit->date,
		/*
static void merge_commit_graphs(struct write_commit_graph_context *ctx)
	ctx->oids.alloc = ctx->approx_nr_objects / 32;
	uint32_t i;
#define GRAPH_MIN_SIZE (GRAPH_HEADER_SIZE + 4 * GRAPH_CHUNKLOOKUP_WIDTH \
	if (!fp ||
		pptr = insert_parent_or_die(r, g,

	if (safe_create_leading_directories(ctx->graph_name)) {
		if (ctx->r->objects->commit_graph)
	uint32_t offset = g->num_commits_in_base;

	local_error = verify_commit_graph_error;
	/*


	if (r->objects->commit_graph)
	dirlen = packname.len;
		return 0;

		strbuf_addf(&progress_title,
	edge_value = get_be32(commit_data + g->hash_len);
				    oid_to_hex(&(*list)->object.oid));


			struct commit_graph *g = load_commit_graph_one(graph_name, odb);
	} else {
			unlink(graph_name);
	load_oid_from_graph(g, pos, &oid);
	int fd;

	return oidcmp(a, b);
	string_list_append(list, oid_to_hex(oid));
		if (g->num_commits != fanout_value)
	chunk_ids[2] = GRAPH_CHUNKID_DATA;
		return 1;
	if (!prepare_commit_graph(r))
		 * so that commit graph loading is not attempted again for this
				struct commit *item,
			else
}
			ctx->commits.nr++;

	} else {
	struct object_id *list;
				} else if (parent->item->generation > max_generation) {
	}
	uint32_t lex_index;
		strbuf_addf(&progress_title,
}
		close(*fd);
							 ctx->new_base_graph,
		display_progress(ctx->progress, ++ctx->progress_cnt);
			graph_report(_("failed to parse commit %s from object database for commit-graph"),
	size_t graph_size;
	}
		stop_progress(&ctx->progress);
	for (i = 0; i < graph->num_chunks; i++) {
	while (list < last) {
	if (!g)
		return NULL;
	for (count = 0; count < ctx->commits.nr; count++, list++) {
							 ctx->new_base_graph,
			continue;
{
			       "Finding commits for commit graph in %d packs",
		g = g->base_graph;
}
			continue;
	if (!open_ok)
			graph_report(_("commit-graph parent list for commit %s terminates early"),
		if (fd < 0) {
struct commit_graph *parse_commit_graph(void *graph_map, int fd,
	size_t dirnamelen;
	if (pos >= g->num_commits + g->num_commits_in_base)
		}
	prepare_repo_settings(r);
	lex_index = pos - g->num_commits_in_base;
extern int read_replace_refs;
		strbuf_setlen(&path, dirnamelen);
				if (result) {
	if (find_commit_in_graph(item, r->objects->commit_graph, &pos))
	int num_commit_graphs_after;

	stop_progress(&ctx->progress);
				      const char *oid_hex)
						 struct commit_list **pptr)
	if (ctx->append) {
					      ctx->commits.nr,
		hashwrite(f, packedDate, 8);

			goto cleanup;
	item->generation = get_be32(commit_data + g->hash_len + 8) >> 2;

		if (!oideq(&ctx->oids.list[i - 1], &ctx->oids.list[i])) {
		pptr = insert_parent_or_die(r, g, edge_value, pptr);



	struct commit **list = ctx->commits.list;

static struct commit_graph *load_commit_graph_chain(struct repository *r,
{
			hashcpy(ctx->oids.list[ctx->oids.nr++].hash, hash);
struct tree *get_commit_tree_in_graph(struct repository *r, const struct commit *c)
	}
	set_commit_tree(item, NULL);
		return 0;
		graph_report("no commit-graph file loaded");
	close_commit_graph_one(g->base_graph);

			ctx->oids.nr++;

	ALLOC_ARRAY(ctx->oids.list, ctx->oids.alloc);


			unlink(path.buf);
	if (n && !g->chunk_base_graphs) {
			list++;
#include "refs.h"

					return -1;
		return 0;
	timestamp_t expire_time = time(NULL);

		die(_("invalid commit position. commit-graph is likely corrupt"));
#include "config.h"
		error(_("the commit graph format cannot write %d commits"), count_distinct);
		      graph_signature, GRAPH_SIGNATURE);
		}
	if (ctx->split) {
}

	pptr = &item->parents;
			if (g) {


	chunk_offsets[2] = chunk_offsets[1] + hashsz * ctx->commits.nr;

		}

		ctx->progress_done = 0;

					_("Clearing commit marks in commit graph"),
			    commit_hex->nr);
	lex_index = pos - g->num_commits_in_base;
		ctx->commit_graph_hash_after[ctx->num_commit_graphs_after - 2] = new_base_hash;
	} else
	uint32_t lex_index;
			      struct commit_graph *chain,
		munmap(graph_map, graph_size);
	struct commit **last = ctx->commits.list + ctx->commits.nr;
	time_t now = time(NULL);

		return 1;
	}

	int i, count = 0;

}
	struct commit_graph *g;
		ctx->oids.alloc = 1024;
			_("Finding commits for commit graph among packed objects"),
		mark_commit_graphs(ctx);
		num_chunks++;
				graph->chunk_oid_lookup = data + chunk_offset;
	if (chain)
		return -1;
	const struct object_id *b = (const struct object_id *)_b;
		strbuf_addstr(&path, de->d_name);

static int commit_graph_compatible(struct repository *r)
					continue;
		uint32_t chunk_id;
	char *graph_name;
	}
	if (verify_commit_graph_error)
	}

		      graph_version, GRAPH_VERSION);
	return !!r->objects->commit_graph;

#define GRAPH_LAST_EDGE 0x80000000
			if (edge_value >= 0)

				if (parent->item->generation == GENERATION_NUMBER_INFINITY ||
	return c->maybe_tree;
		    g->odb != ctx->odb) {
	if (ctx->num_commit_graphs_after > 1 &&
	chunk_ids[1] = GRAPH_CHUNKID_OIDLOOKUP;

	strbuf_release(&packname);
	ctx->r = the_repository;
static int write_commit_graph_file(struct write_commit_graph_context *ctx)
}
{
int parse_commit_in_graph(struct repository *r, struct commit *item)
		char *chain_file_name = get_chain_filename(ctx->odb);
	int num_extra_edges;
			progress_title.buf,



 * Return 1 if commit_graph is non-NULL, and 0 otherwise.
	struct commit_graph *g;
		while (g) {
{
	struct object_id prev_oid, cur_oid, checksum;
	return result;
		cur_fanout_pos++;


	struct stat st;
	return ret;

		if (!oideq(&get_commit_tree_in_graph_one(r, g, graph_commit)->object.oid,
static int commit_compare(const void *_a, const void *_b)
			} while (parent);
		}
		list++;
		if (ctx->report_progress)


		return 0;
		}
int generation_numbers_enabled(struct repository *r)
}
{
}
			if (all_parents_computed) {
		ret->odb = odb;
	prepare_commit_graft(r);
		last_chunk_id = chunk_id;
	hashwrite(f, g->oid.hash, the_hash_algo->rawsz);
				break;

			char *graph_name = get_commit_graph_filename(ctx->odb);

	const struct commit *b = *(const struct commit **)_b;
	set_commit_tree(c, lookup_tree(r, &oid));

}
	hash_version = *(unsigned char*)(data + 5);
					      ctx->commits.list,
		fill_commit_graph_info(item, r->objects->commit_graph, pos);
	void *graph_map;
	/*
			ctx->progress = start_delayed_progress(_("Merging commit-graph"), 0);
	compute_generation_numbers(ctx);
	return xstrfmt("%s/info/commit-graphs/graph-%s.graph", odb->path,
		       struct string_list *commit_hex,
		} else {
		int result;
		error(_("unable to create leading directories of %s"),

			    Q_("Writing out commit graph in %d pass",
			    commit_hex->items[i].string);

		verify_commit_graph_error = VERIFY_COMMIT_GRAPH_ERROR_HASH;

						ctx->num_commit_graphs_after - 2];
			GRAPH_DATA_WIDTH * (c->graph_pos - g->num_commits_in_base);

	int num = 0;
		free(ctx->commit_graph_filenames_after[ctx->num_commit_graphs_after - 2]);

	int devnull;
		prepare_commit_graph_one(ctx->r, ctx->odb);
{
			continue;
	struct commit **last = ctx->commits.list + ctx->commits.nr;
	uint32_t i;
			error(_("invalid commit object id: %s"),
					     oid_to_hex(&cur_oid));
		if (!(parent->item->object.flags & REACHABLE)) {

			else
		struct commit_list *parent;
cleanup:
	commit_data = g->chunk_commit_data +
			return -1;
#include "dir.h"
	ctx->num_extra_edges = 0;
}
		return fill_commit_in_graph(r, item, g, pos);

		    !oideq(&oids[n], &cur_g->oid) ||
		die("invalid parent position %"PRIu32, pos);
	    stat_res ||
	struct commit_graph *graph_chain = NULL;
						 struct object_directory *odb)
	struct stat st;
 * On the first invocation, this function attempts to load the commit

	return !!first_generation;
	struct object_info oi = OBJECT_INFO_INIT;
	free(graph_name);
	ALLOC_GROW(ctx->commits.list, ctx->commits.nr + g->num_commits, ctx->commits.alloc);

							 &pos))
void disable_commit_graph(struct repository *r)
		else {
		f = hashfd(lk.tempfile->fd, lk.tempfile->filename.buf);
static struct commit_graph *alloc_commit_graph(void)
			       "Writing out commit graph in %d passes",
			ctx->commits.list[ctx->commits.nr] = result;
						  commit_to_sha1);
			uint32_t max_generation = 0;

	return graph_chain;
				   struct write_commit_graph_context *ctx)


			else
	if (ctx->num_extra_edges)
	strbuf_release(&progress_title);
#include "lockfile.h"
	parent_data_ptr = (uint32_t*)(g->chunk_extra_edges +
	const struct commit *a = *(const struct commit **)_a;

			break;
	if (ctx->split) {

		odb_commit = (struct commit *)create_object(r, &cur_oid, alloc_commit_node(r));
			+ GRAPH_FANOUT_SIZE + the_hash_algo->rawsz)
			ctx->new_base_graph = NULL;

{
	}
{
		die(_("unable to get type of object %s"), oid_to_hex(oid));
static void write_graph_chunk_data(struct hashfile *f, int hash_len,
			}

					current->generation = GENERATION_NUMBER_MAX;
	close_reachable(ctx);
	if (!graph_map)


	char **commit_graph_hash_after;
				if (find_commit_in_graph(parent->item,
	while (g && pos < g->num_commits_in_base)
}


	for (i = ctx->num_commit_graphs_after - 1; i < ctx->num_commit_graphs_before; i++) {
{
		return 1;
static void split_graph_merge_strategy(struct write_commit_graph_context *ctx)

#define VERIFY_COMMIT_GRAPH_ERROR_HASH 2
			break;
		if (commit)
	int i;
	struct strbuf line = STRBUF_INIT;
			warning(_("commit-graph chain does not match"));
	}
	chunk_ids[0] = GRAPH_CHUNKID_OIDFANOUT;
		updated_time.modtime = now;
				edge_value += ctx->new_num_commits_in_base;
}
				chunk_repeated = 1;

			int edge_value = sha1_pos(parent->item->object.oid.hash,
static void merge_commit_graph(struct write_commit_graph_context *ctx,
	 */

static void mark_commit_graphs(struct write_commit_graph_context *ctx)
				   struct write_commit_graph_context *ctx)
			generation_zero = GENERATION_ZERO_EXISTS;
}
		return 1;
	strbuf_release(&progress_title);
			commit->object.flags &= ~REACHABLE;

		free(ctx->commit_graph_hash_after);
		ctx->progress = start_delayed_progress(
}
			graph_parents = graph_parents->next;

		}
		chunk_write[1] = htonl(chunk_offsets[i] >> 32);


		odb_parents = odb_commit->parents;

		ctx->progress = start_delayed_progress(
			else
	graph->data = graph_map;
		case GRAPH_CHUNKID_BASE:

		if (odb_parents != NULL)
	graph->graph_fd = fd;

	}
static uint8_t oid_version(void)
	commit_data = g->chunk_commit_data + GRAPH_DATA_WIDTH * lex_index;
		    ctx->commits.list[ctx->commits.nr]->graph_pos != COMMIT_NOT_FROM_GRAPH)
		hashwrite_be32(f, edge_value);
		i--;

	uint64_t last_chunk_offset;
			valid = 0;
				chunk_repeated = 1;
			if (edge_value >= 0)
		display_progress(ctx->progress, i + 1);
	string_list_clear(&list, 0);

		error(_("failed to write correct number of base graph ids"));
			ctx->oids.nr++;
	const unsigned char *commit_data;
	for (i = 0; i < ctx->oids.nr; i++) {
		close(fd);

	date_low = get_be32(commit_data + g->hash_len + 12);
			continue;
	free(oids);
	last_chunk_id = 0;

{

		num_chunks++;
	return res;

		} else if (generation_zero == GENERATION_ZERO_EXISTS)

	return 0;
	int size_mult = 2;

#include "pack.h"

#include "git-compat-util.h"
	}


			return -1;
		list++;
int write_commit_graph_reachable(struct object_directory *odb,



	int dirlen;
#define GRAPH_DATA_WIDTH (the_hash_algo->rawsz + 16)
		die(_("could not find commit %s"), oid_to_hex(&oid));

		    GRAPH_CHUNKLOOKUP_WIDTH) {
	close_commit_graph_one(o->commit_graph);
	uint32_t *parent_data_ptr;
	}

	fp = fopen(chain_name, "r");
						    struct object_directory *odb)


static void expire_commit_graphs(struct write_commit_graph_context *ctx)
							 ctx->new_base_graph,

			       struct commit_graph *g)


{
		struct commit_graph *cur_g = g;
		UNLEAK(ctx->graph_name);
				if (find_commit_in_graph(parent->item,
			_("Finding extra edges in commit graph"),
		g = ctx->r->objects->commit_graph;

	if (pos >= g->num_commits + g->num_commits_in_base)
	commit_lock_file(&lk);
}
					    edge_value & GRAPH_EDGE_LAST_MASK,
		commit = lookup_commit(ctx->r, &ctx->oids.list[i]);
					FOR_EACH_OBJECT_PACK_ORDER);
		if (num_parents <= 2) {
	 */
	struct strbuf packname = STRBUF_INIT;
		if (!parent)
{

}
	}

	uint32_t i;
}
	if (ctx->report_progress)
		ctx->graph_name = strbuf_detach(&tmp_file, NULL);
	if (g) {


	struct commit **commits = table;
			       commit_hex->nr),

	}
	if (ctx->num_commit_graphs_after == 2) {
{

	return 1;
static struct commit_graph *load_commit_graph_v1(struct repository *r,

		}
		}



	if (!ctx->split) {
	int max_commits = 0;
	return num + 1;
	for (i = 0; i < ctx->commits.nr; i++) {
		return 0;

						 struct commit_graph *g,

		} else if (!parse_commit_no_graph(commit))
static int find_commit_in_graph(struct commit *item, struct commit_graph *g, uint32_t *pos)
		       const struct split_commit_graph_opts *split_opts)
	char **commit_graph_filenames_before;
				graph->chunk_base_graphs = data + chunk_offset;
		if (!found)
	DIR *dir;
		if (graph_commit->date != odb_commit->date)
	return &commit_list_insert(c, pptr)->next;
		if (ctx->split) {
	char *graph_name = get_commit_graph_filename(odb);

	}
		g->filename = xstrdup(graph_file);
		if ((res = fill_oids_from_packs(ctx, pack_indexes)))
	}
	return commits[index]->object.oid.hash;
						  struct object_directory *odb)
	stop_progress(&ctx->progress);
			oidcpy(&ctx->oids.list[ctx->oids.nr], &(result->object.oid));


		error("commit-graph is missing the Commit Data chunk");
	}
			free(ctx->commit_graph_filenames_after[i]);
			if (edge_value >= 0)
{
		ctx->commits.list[ctx->commits.nr] = lookup_commit(ctx->r, &ctx->oids.list[i]);
{
static int fill_oids_from_packs(struct write_commit_graph_context *ctx,
		valid = 0;
{
		}
		display_progress(ctx->progress, i + 1);
	if (ctx->report_progress)
				     oid_to_hex(&cur_oid));

				chunk_repeated = 1;

	}
		ctx->progress = start_delayed_progress(progress_title.buf, 0);

	uint32_t pos;
	}
	int res = 0;
		hashwrite(f, chunk_write, 12);
		BUG("NULL commit-graph");
#define GRAPH_EDGE_LAST_MASK 0x7fffffff
		/* only add commits if they still exist in the repo */
	if (!pack_indexes && !commit_hex)
		goto cleanup;
	 * Write the first-level table (the list is sorted,
		return 1;
	int generation_zero = 0;
	for (i = 0; i <= num_chunks; i++) {
		struct commit_graph *g = ctx->r->objects->commit_graph;

	 * which'll be called every time the graph is used, and the
static int write_graph_chunk_base(struct hashfile *f,
	if (ctx->split_opts) {
	while (list < last) {
	if (r->objects->commit_graph_attempted)

			graph_report(_("root tree OID for commit %s in commit-graph is %s != %s"),
	}
static void add_missing_parents(struct write_commit_graph_context *ctx, struct commit *commit)
	if (item->graph_pos != COMMIT_NOT_FROM_GRAPH) {
		return !!r->objects->commit_graph;
			   get_commit_tree_oid(odb_commit)))
		expire_time -= ctx->split_opts->expire_time;

		chunk_ids[num_chunks] = GRAPH_CHUNKID_EXTRAEDGES;
				}
	}

		if (sizeof((*list)->date) > 4)
	graph = alloc_commit_graph();

		struct commit *result;
		struct stat st;
	r->objects->commit_graph_attempted = 1;
	num_chunks = 3;
		if (!chainf) {
	uint32_t i, count_distinct = 0;
		chunk_lookup += GRAPH_CHUNKLOOKUP_WIDTH;
		if (edge_value & GRAPH_EXTRA_EDGES_NEEDED) {

			free(graph);
struct write_commit_graph_context {
	if (ctx->split_opts && ctx->split_opts->expire_time)
	if (ctx->num_extra_edges) {
	for (i = 0; i < pack_indexes->nr; i++) {
			}


{
		case GRAPH_CHUNKID_EXTRAEDGES:

		}
{
				graph_report(_("commit-graph has generation number zero for commit %s, but non-zero elsewhere"),

		updated_time.actime = st.st_atime;
		load_oid_from_graph(g, i + offset, &oid);
		parent = (*list)->parents;
{
	display_progress(ctx->progress, 0); /* TODO: Measure QSORT() progress */
			while (g) {

		graph_commit = lookup_commit(r, &cur_oid);
					ctx->oids.nr);
		ctx->progress = start_delayed_progress(
	stop_progress(&ctx->progress);
		display_progress(ctx->progress, ctx->approx_nr_objects);
	if (!g->chunk_oid_fanout) {

	}
			break;
			graph->num_commits = (chunk_offset - last_chunk_offset)

	     !r->objects->commit_graph && odb;

		uint32_t max_generation = 0;
			struct commit *current = list->item;
	 * Basic validation shared between parse_commit_graph()
	strbuf_addf(&packname, "%s/pack/", ctx->odb->path);
	if (ctx->new_base_graph)
struct packed_oid_list {
		hashwrite_be32(f, count);
	uint32_t lex_index;
	int i = 0, valid = 1, count;

		if (!cur_g ||
				     oid_to_hex(get_commit_tree_oid(graph_commit)),
	const unsigned char *commit_data;
			    pack_indexes->nr);
	finalize_hashfile(f, checksum.hash, CSUM_CLOSE);
				struct commit_graph *g, uint32_t pos)
	if (item->object.parsed)
		num_chunks++;
};

static int add_packed_commits(const struct object_id *oid,
				     struct commit_graph *g,
	free_commit_graph(g);
{
	if (r->commit_graph_disabled)
}
	va_list ap;
	prepare_alt_odb(r);
					commit_list_insert(parent->item, &list);

	}
static int write_graph_chunk_base_1(struct hashfile *f,
{


	int num = write_graph_chunk_base_1(f, ctx->new_base_graph);
		split_graph_merge_strategy(ctx);
			free(graph);

			const unsigned char *hash = g->chunk_oid_lookup + g->hash_len * i;
		return 0;
	g->graph_fd = -1;
	uint32_t i;
				 const struct split_commit_graph_opts *split_opts)
		for (i = 0; i < ctx->num_commit_graphs_before; i++)
	ctx->odb = odb;
		ctx->commit_graph_filenames_after[ctx->num_commit_graphs_after - 1] = final_graph_name;
	uint64_t progress_cnt;
				edge_value |= GRAPH_LAST_EDGE;
		ctx->graph_name = get_commit_graph_filename(ctx->odb);
	struct commit_graph *new_base_graph;
				    oid_to_hex(&parent->item->object.oid),
	}
		return;
		 * do not load one. (But report commit_graph_attempted anyway

			ctx->oids.nr);
			if (!parse_commit(commit) &&
	 * we don't e.g. segfault in fill_commit_in_graph(), but

		}
		goto cleanup;
	struct commit *commit;
			error(_("commit-graph chunk lookup table entry missing; file may be incomplete"));
#define GENERATION_NUMBER_EXISTS 2

	}
		}
			if (graph->chunk_oid_lookup)



	struct string_list *list = (struct string_list *)cb_data;

		case GRAPH_CHUNKID_DATA:
					all_parents_computed = 0;
				oid_to_hex(&(*list)->object.oid));
	char **commit_graph_filenames_after;
	FILE *fp;
	 * much more expensive verify_commit_graph() used by

		char *final_graph_name;
	free(g->filename);
			else {
				chunk_repeated = 1;
static int fill_commit_in_graph(struct repository *r,
			cur_g = cur_g->base_graph;
int verify_commit_graph(struct repository *r, struct commit_graph *g, int flags)
	if (ctx->split) {
			ctx->approx_nr_objects);
		write_graph_chunk_extra_edges(f, ctx);
		 * extra logic in the following condition.
		return 1;

	if (graph_size < GRAPH_MIN_SIZE) {
			return NULL;
			continue;
	if (ctx->num_commit_graphs_after > 1) {

		uint32_t chunk_write[3];
	g = r->objects->commit_graph;
	stop_progress(&ctx->progress);
	finalize_hashfile(f, file_hash.hash, CSUM_HASH_IN_STREAM | CSUM_FSYNC);
			count++;
	enum object_type type;
		char *lock_name = get_chain_filename(ctx->odb);


			graph_report(_("commit-graph generation for commit %s is %u != %u"),
	if (!g)



		close(fd);
	uint64_t date_low, date_high;
		return 0;
	count = st.st_size / (the_hash_algo->hexsz + 1);
			packedDate[0] = htonl(((*list)->date >> 32) & 0x3);
		strbuf_setlen(&packname, dirlen);
	int alloc;
static void close_commit_graph_one(struct commit_graph *g)

					_("Scanning merged commits"),


	}
{
	graph_signature = get_be32(data);
						  ctx->commits.nr,
		res = -1;
			edge_value = sha1_pos(parent->item->object.oid.hash,
		display_progress(ctx->progress, i + 1);
}

	item->date = (timestamp_t)((date_high << 32) | date_low);
					_("Computing commit graph generation numbers"),
	struct object_directory *odb;
			    commit->graph_pos == COMMIT_NOT_FROM_GRAPH)
	struct object_id oid;
		    i < ctx->num_commit_graphs_before; i++)

			add_missing_parents(ctx, commit);
	expire_commit_graphs(ctx);
			edge_value = GRAPH_PARENT_NONE;
			error(_("failed to rename temporary commit-graph file"));
}
		return 0;
				     max_generation + 1);

	return g;

	return g;
		g = g->base_graph;
		result = lookup_commit_reference_gently(ctx->r, &oid, 1);
static int prepare_commit_graph(struct repository *r)
	int count;
				    oid_to_hex(&(*list)->object.oid));
		display_progress(ctx->progress, ++ctx->progress_done);
	if (fstat(*fd, st)) {
	struct object_id oid;
	free(ctx->commits.list);
			parent = parent->next;
	struct commit_graph *g;
	ctx->split_opts = split_opts;
}
				break;

	struct commit *c;
				ctx->commit_graph_filenames_before[--i] = xstrdup(g->filename);

	 * There should only be very basic checks here to ensure that
			edge_value = GRAPH_PARENT_NONE;
		struct commit *graph_commit;
	f = hashfd(devnull, NULL);
			continue;
		fd = git_mkstemp_mode(ctx->graph_name, 0444);
static int bsearch_graph(struct commit_graph *g, struct object_id *oid, uint32_t *pos)
		stat(path.buf, &st);
	const unsigned char *commit_data;
	}
{

	}
					    pptr);

		struct commit *graph_commit, *odb_commit;
	 * over g->num_commits, or runs a checksum on the commit-graph

		return NULL;
	stop_progress(&ctx->progress);
}
	if (pos >= g->num_commits + g->num_commits_in_base)
	}
		packedDate[1] = htonl((*list)->date);
	return 0;
{
}
		ctx->new_base_graph = g;
	}
	 * having to do eight extra binary search iterations).
{
			      struct object_id *oids,

	for (i = 0; i < ctx->oids.nr; i++) {
		error("commit-graph is missing the OID Fanout chunk");
	oidcpy(&(ctx->oids.list[ctx->oids.nr]), oid);
				uint32_t pos;
					     oid_to_hex(&odb_parents->item->object.oid));
			}
	strbuf_addstr(&path, "/info/commit-graphs");
				     oid_to_hex(&prev_oid),
	for (i = 0; i < 256; i++) {
			else if (!parent->next)
	int alloc;
				if (!c || c->graph_pos != COMMIT_NOT_FROM_GRAPH)
}
	struct progress *progress = NULL;

				BUG("missing parent %s for commit %s",

			cur_fanout_pos++;


	if (c->maybe_tree)
{
{
	}

				if (current->generation > GENERATION_NUMBER_MAX)


			return 0;
static int oid_compare(const void *_a, const void *_b)



{
				     struct write_commit_graph_context *ctx)

	ctx = xcalloc(1, sizeof(struct write_commit_graph_context));
		if (ctx->split &&
			free(ctx->commit_graph_filenames_before[i]);

			if (generation_zero == GENERATION_NUMBER_EXISTS)
			   int flags, void *cb_data)
	}
	return 1;

	ctx->report_progress = flags & COMMIT_GRAPH_WRITE_PROGRESS ? 1 : 0;
		return -1;
}

				graph->chunk_extra_edges = data + chunk_offset;

	 * "local" position for the rest of the calculation.
	off_t offset = nth_packed_object_offset(pack, pos);
	struct commit **list;
		int num_parents = 0;
					edge_value = pos;
					  struct write_commit_graph_context *ctx)
	if (!g)
		uint32_t fanout_value = get_be32(g->chunk_oid_fanout + cur_fanout_pos);
}
	for (i = 0; i < g->num_commits; i++) {
	int result;
#define GRAPH_CHUNKLOOKUP_WIDTH 12
				graph_report(_("commit-graph parent for %s is %s != %s"),
	}
}
			count_distinct++;
	hashwrite_u8(f, ctx->num_commit_graphs_after - 1);
#include "object-store.h"
	strbuf_release(&progress_title);

	if (verify_commit_graph_error & ~VERIFY_COMMIT_GRAPH_ERROR_HASH)
{
	item->generation = get_be32(commit_data + g->hash_len + 8) >> 2;
			error(_("commit-graph improper chunk offset %08x%08x"), (uint32_t)(chunk_offset >> 32),
}
	if (ctx->report_progress) {
#define GRAPH_HEADER_SIZE 8
}
		return -1;
		if (!graph_commit->generation) {

	hashwrite_u8(f, oid_version());

	}
			if (graph->chunk_oid_fanout)
	g = load_commit_graph_one_fd_st(fd, &st, odb);
		free(chain_file_name);

	uint32_t new_num_commits_in_base;
	}
static struct commit_list **insert_parent_or_die(struct repository *r,
		struct commit *result;

	if (ctx->report_progress)
			}
		display_progress(ctx->progress, ++ctx->progress_cnt);
	if (type != OBJ_COMMIT)
	if (edge_value == GRAPH_PARENT_NONE)
				g = g->base_graph;
	g = ctx->r->objects->commit_graph;
{
			graph_report(_("commit-graph has incorrect OID order: %s then %s"),

	uint32_t first_generation;
	struct progress *progress;
					edge_value = pos;
		max_commits = ctx->split_opts->max_commits;
		if (num_parents > 2)
	for (i = 0; i < g->num_commits; i++) {
	for (i = 0; i < count; i++) {
	verify_commit_graph_error = verify_commit_graph_lite(g);
	}
					      ctx->commits.nr,

	chunk_ids[num_chunks] = 0;
	chunk_offsets[0] = 8 + (num_chunks + 1) * GRAPH_CHUNKLOOKUP_WIDTH;
	if (ctx->split && split_opts && ctx->oids.alloc > split_opts->max_commits)
		display_progress(ctx->progress, i + 1);
	struct object_directory *odb;


		if (!strcmp(g->filename, old_graph_name) &&
				struct commit *c = lookup_commit(ctx->r, &ctx->oids.list[i]);
	uint32_t i;
	while (c->graph_pos < g->num_commits_in_base)
{


	for (i = 0; i < g->num_commits; i++) {
				    oid_to_hex(&(*list)->object.oid));
				     oid_to_hex(&cur_oid));
	graph->hash_len = the_hash_algo->rawsz;
	fclose(fp);
					     oid_to_hex(&graph_parents->item->object.oid),
		if (!parse_commit_in_graph_one(r, g, graph_commit))

	uint32_t i;
static char *get_split_graph_filename(struct object_directory *odb,
	if (!g) {

			goto cleanup;
{
#define GRAPH_CHUNKID_EXTRAEDGES 0x45444745 /* "EDGE" */
#define GENERATION_ZERO_EXISTS 1
static void compute_generation_numbers(struct write_commit_graph_context *ctx)
		} else if (ctx->check_oids) {


			ctx->commit_graph_hash_after[i] = xstrdup(oid_to_hex(&g->oid));
						 uint32_t pos,
}
	struct strbuf progress_title = STRBUF_INIT;
		hashcpy(cur_oid.hash, g->chunk_oid_lookup + g->hash_len * i);
		return NULL;
		hashwrite_be32(f, edge_value);
			continue;
	return 0;

	ctx->commits.alloc = count_distinct;
		return verify_commit_graph_error;
		       struct string_list *pack_indexes,
					ctx->oids.nr);

}
				     graph_commit->generation,

	res = write_commit_graph_file(ctx);

					   struct object_directory *odb)


		if (st.st_mtime > expire_time)
			ctx->num_commit_graphs_after = 1;



	r->commit_graph_disabled = 1;
	}
			break;

	devnull = open("/dev/null", O_WRONLY);
	int fd;
		fd = lk.tempfile->fd;
	while (g && current_graph_number >= ctx->num_commit_graphs_after) {
	struct commit_list *list = NULL;

	ALLOC_ARRAY(ctx->commit_graph_filenames_after, ctx->num_commit_graphs_after);

		if (ctx->base_graph_name) {
				  struct write_commit_graph_context *ctx)
			return 1;
		close_pack(p);
	hashcpy(graph->oid.hash, graph->data + graph->data_len - graph->hash_len);
{
		prepare_commit_graph_one(r, odb);
							 &pos))
	}
	else {
	if (ctx->commits.nr >= GRAPH_EDGE_LAST_MASK) {
{
					      commit_to_sha1);
						 struct object_directory *odb)
			ALLOC_GROW(ctx->oids.list, ctx->oids.nr + 1, ctx->oids.alloc);
				if (add_graph_to_chain(g, graph_chain, oids, i)) {

	*fd = git_open(graph_file);
}
{
					graph_chain = g;
				     cur_fanout_pos, fanout_value, i);
		utime(ctx->commit_graph_filenames_before[i], &updated_time);
{
		    (max_commits && num_commits > max_commits))) {
	}
		close(g->graph_fd);

				    g->hash_len + 8) >> 2;
	return xstrfmt("%s/info/commit-graphs/commit-graph-chain", odb->path);
		uint32_t packedDate[2];
static void graph_report(const char *fmt, ...)
		if (!p) {
}
		if (!parse_oid_hex(commit_hex->items[i].string, &oid, &end) &&
static void fill_commit_graph_info(struct commit *item, struct commit_graph *g, uint32_t pos)

	struct commit_graph *g = load_commit_graph_v1(r, odb);
		if (i > 0 && oideq(&ctx->oids.list[i - 1], &ctx->oids.list[i]))

	hashwrite_u8(f, num_chunks);
		unsigned int num_parents;
	}
		 */
					 struct commit_graph *g,
static uint32_t count_distinct_commits(struct write_commit_graph_context *ctx)
out:
		progress = start_progress(_("Verifying commits in commit graph"),
		}
				BUG("missing parent %s for commit %s",
	uint32_t pos;



				line.buf);
 * graph if the_repository is configured to have one.
		if (i && oideq(&ctx->commits.list[i - 1]->object.oid,
					valid = 1;
	while (cur_fanout_pos < 256) {
		ctx->commit_graph_filenames_after[ctx->num_commit_graphs_after - 2] = new_base_name;
	data = (const unsigned char *)graph_map;

	uint32_t num_extra_edges = 0;
			error(_("unable to open commit-graph chain file"));
		error("commit-graph is missing the OID Lookup chunk");
};
				     oid_to_hex(get_commit_tree_oid(odb_commit)));
	for_each_packed_object(add_packed_commits, ctx,
		uint32_t i, found = 0;
		return 0;
			fprintf(lk.tempfile->fp, "%s\n", ctx->commit_graph_hash_after[i]);
			  4 * (uint64_t)(edge_value & GRAPH_EDGE_LAST_MASK));
	if (!commit_graph_compatible(r))

		while (graph_parents) {
{
				BUG("missing parent %s for commit %s",

}
		merge_commit_graphs(ctx);

	if (graph_signature != GRAPH_SIGNATURE) {
	graph_version = *(unsigned char*)(data + 4);
		display_progress(progress, i + 1);

	hashcpy(oid.hash, commit_data);

		ctx->commit_graph_hash_after[ctx->num_commit_graphs_after - 1] = xstrdup(oid_to_hex(&file_hash));
			      void *data)

	char *base_graph_name;
		display_progress(ctx->progress, i);
}

	if (ctx->append && ctx->r->objects->commit_graph) {
{
		packedDate[0] |= htonl((*list)->generation << 2);
		}
	chunk_lookup = data + 8;
		struct object_id oid;
			max_generation--;
	if (ctx->report_progress) {
		error(_("commit-graph signature %X does not match signature %X"),
			free(graph_name);
struct packed_commit_list {
				struct string_list *pack_indexes)
}

	}
		final_graph_name = get_split_graph_filename(ctx->odb,
{
		ctx->progress = start_delayed_progress(
		free(ctx->commit_graph_filenames_before);
			continue;
			      struct packed_git *pack,
			/* parse parent in case it is in a base graph */
	ctx->new_base_graph = g;
	item->graph_pos = pos;
						hashsz * (ctx->num_commit_graphs_after - 1);
#include "replace-object.h"
		graph_commit = lookup_commit(r, &cur_oid);

	struct commit_graph *ret;

		commit = lookup_commit(ctx->r, &ctx->oids.list[i]);
		g = g->base_graph;

		       oid_hex);
	for (i = 0; i < ctx->oids.nr; i++) {
		ctx->progress = start_delayed_progress(

	stop_progress(&ctx->progress);
}



	uint32_t graph_signature;
void load_commit_graph_info(struct repository *r, struct commit *item)
		strbuf_addstr(&packname, pack_indexes->items[i].string);
}
	ALLOC_ARRAY(ctx->commits.list, ctx->commits.alloc);
		const char *end;

}
{
		}

static void sort_and_scan_merged_commits(struct write_commit_graph_context *ctx)
	dirnamelen = path.len;
		if (open_pack_index(p)) {


	 * but we use a 256-entry lookup to be able to avoid
			_("Counting distinct commits in commit graph"),
			num_chunks * ctx->commits.nr);

				 enum commit_graph_write_flags flags,

		struct strbuf tmp_file = STRBUF_INIT;
		display_progress(ctx->progress, i + 1);
}

		tree = get_commit_tree_oid(*list);


		return 0;



			if (edge_value < 0)

#define GRAPH_CHUNKID_OIDFANOUT 0x4f494446 /* "OIDF" */
{
		}
	return xstrfmt("%s/info/commit-graph", odb->path);
	struct commit_graph *g = load_commit_graph_one(graph_name, odb);
			else
				chunk_repeated = 1;
	struct hashfile *f;
	if (!g->chunk_commit_data) {
		uint64_t chunk_offset;
		free(p);
static void load_oid_from_graph(struct commit_graph *g,
	}
	return oidcmp(&a->object.oid, &b->object.oid);

		ctx->new_num_commits_in_base = g->num_commits + g->num_commits_in_base;
	 * we want to disable even an already-loaded graph file.
	item->graph_pos = pos;
}
	struct lock_file lk = LOCK_INIT;
	int progress_done;


{
			warning(_("invalid commit-graph chain: line '%s' not a hash"),
	graph->data_len = graph_size;
	if (ctx->split) {
	strbuf_addstr(&path, ctx->odb->path);
{
		}

	if (ctx->report_progress)

	return count_distinct;

		/*

		strbuf_addf(&tmp_file,

			free(ctx->commit_graph_hash_after[i]);
					g->num_commits);

			if (i != fanout_value)
		ctx->progress = start_delayed_progress(
		if (ctx->commits.list[i]->generation != GENERATION_NUMBER_INFINITY &&
	if (flags & COMMIT_GRAPH_WRITE_PROGRESS)
	edge_value = get_be32(commit_data + g->hash_len + 4);
{
		}

			if (num_parents > 2)
		return NULL;
	for (i = 0; i < commit_hex->nr; i++) {
	while (n) {
{
	unsigned append:1,
		}
	oi.typep = &type;
	for (i = 0; i < ctx->oids.nr; i++) {
}
					size_t graph_size)

		g = load_commit_graph_chain(r, odb);
{

	close_commit_graph(ctx->r->objects);


				current->generation = max_generation + 1;
		chunk_offset = get_be64(chunk_lookup + 4);
	item->object.parsed = 1;
	uint32_t last_chunk_id;
		struct stat st;

	if (git_env_bool(GIT_TEST_COMMIT_GRAPH_DIE_ON_LOAD, 0))
			parent->item->object.flags |= REACHABLE;

	if (!g)
		 * If one of our parents has generation GENERATION_NUMBER_MAX, then

	return 0;
		return 1;

		ctx->num_commit_graphs_after = 0;
			edge_value = sha1_pos(parent->item->object.oid.hash,
	for (odb = r->objects->odb;
				    flags, split_opts);
static struct commit_graph *load_commit_graph_one(const char *graph_file,
				graph->chunk_oid_fanout = (uint32_t*)(data + chunk_offset);
		goto out;
struct commit_graph *read_commit_graph_one(struct repository *r,
{
			continue;
	QSORT(ctx->oids.list, ctx->oids.nr, oid_compare);
					      commit_to_sha1);
		}

}
};
	uint32_t num_commits;
			if (strcmp(ctx->base_graph_name, dest)) {
						  ctx->commits.list,
	}
	return 1;
			return NULL;
			if (graph->chunk_base_graphs)
	free(ctx);
		for (odb = r->objects->odb; odb; odb = odb->next) {
	    st.st_size <= the_hash_algo->hexsz)
		char *new_base_hash = xstrdup(oid_to_hex(&ctx->new_base_graph->oid));
	if (find_commit_in_graph(item, g, &pos))
		ctx->num_commit_graphs_after = 1;
	write_graph_chunk_oids(f, hashsz, ctx);
	date_high = get_be32(commit_data + g->hash_len + 8) & 0x3;
	char *chain_name = get_chain_filename(odb);



		else {
					break;
	free(ctx->oids.list);
			ctx->graph_name);
	ctx->num_commit_graphs_after = ctx->num_commit_graphs_before + 1;
			if (edge_value < 0)

		}
	struct commit **list = ctx->commits.list;
			}
			unsigned int num_parents;
	if (verify_commit_graph_lite(graph)) {
	 * This must come before the "already attempted?" check below, because



				     struct commit *item)


{
	 * than the number of missing commits in the reachable
#include "packfile.h"
	stop_progress(&ctx->progress);

	struct commit_graph *graph;
		error(_("too many commits to write graph"));
		while (cur_g && !bsearch_graph(cur_g, &(item->object.oid), &lex_index))
			error(_("error opening index for %s"), packname.buf);
				    struct commit_graph *g)

	if (count_distinct >= GRAPH_EDGE_LAST_MASK) {
			if (ctx->split) {
			error(_("commit-graph chunk id %08x appears multiple times"), chunk_id);
		chunk_offsets[num_chunks + 1] = chunk_offsets[num_chunks] +
		return;
			list++;
#include "sha1-lookup.h"
	write_graph_chunk_data(f, hashsz, ctx);
		if (hashmap_get_size(&r->objects->replace_map->map))
	num_commits = ctx->commits.nr;
	first_generation = get_be32(g->chunk_commit_data +
				     struct object_directory *odb)
			if (graph->chunk_extra_edges)
	result = write_commit_graph(odb, NULL, &list,
					     oid_to_hex(&cur_oid));
		display_progress(ctx->progress, ++ctx->progress_cnt);

		if (generation_zero == GENERATION_ZERO_EXISTS)

	c->maybe_tree = t;
	i = ctx->num_commit_graphs_before - 1;


{

			parse_commit_in_graph_one(r, g, graph_parents->item);
	ctx->append = flags & COMMIT_GRAPH_WRITE_APPEND ? 1 : 0;

	}
	}
	struct commit_list *parent;

#define GRAPH_EXTRA_EDGES_NEEDED 0x80000000
			size_mult = ctx->split_opts->size_multiple;
		hashcpy(cur_oid.hash, g->chunk_oid_lookup + g->hash_len * i);
	 *

				graph_report(_("commit-graph parent list for commit %s is too long"),
		if (i < ctx->num_commit_graphs_after)

	free(chain_name);
			else {
		    !hasheq(oids[n].hash, g->chunk_base_graphs + g->hash_len * n)) {
	while (g) {
			num_parents++;
			break;
	struct hashfile *f;

	hashcpy(oid->hash, g->chunk_oid_lookup + g->hash_len * lex_index);
		return;

	}


	}
}
			num_parents = commit_list_count(ctx->commits.list[i]->parents);
	struct object_id *oids;
					edge_value = pos;
	ctx->oids.nr++;
			error(_("unable to create '%s'"), ctx->graph_name);
				uint32_t pos;
	free(ctx->graph_name);
					     cur_fanout_pos, fanout_value, i);
	 * closure.
	if (ctx->commit_graph_filenames_after) {
		if (ctx->num_commit_graphs_before) {
		if (!parent)
		chunk_write[0] = htonl(chunk_ids[i]);

		}

			struct commit_list *parent;
	}
{
struct commit_graph *load_commit_graph_one_fd_st(int fd, struct stat *st,
	g->base_graph = chain;
			warning(_("unable to find all commit-graph files"));
				     oid_to_hex(&cur_oid),
		return verify_commit_graph_error;
			       "Finding commits for commit graph from %d refs",

		edge_value = get_be32(parent_data_ptr);

		commit_list_insert(ctx->commits.list[i], &list);
		free(graph);

static int add_ref_to_list(const char *refname,
			}
		if (chunk_repeated) {



	int num_commit_graphs_before;
			    "%s/info/commit-graphs/tmp_graph_XXXXXX",
	for (i = 1; i < ctx->oids.nr; i++) {
	copy_oids_to_commits(ctx);
				    path.buf)) {

}

	}
	return bsearch_hash(oid->hash, g->chunk_oid_fanout,
	if (pack_indexes) {
			graph_report(_("commit-graph has non-zero generation number for commit %s, but zero elsewhere"),

	}
	     odb = odb->next)

	if (!dir)
		if ((res = fill_oids_from_commit_hex(ctx, commit_hex)))
				graph->chunk_commit_data = data + chunk_offset;
#include "cache.h"
		for (parent = (*list)->parents->next; parent; parent = parent->next) {
static struct tree *get_commit_tree_in_graph_one(struct repository *r,
			free(graph);
				    oid_to_hex(&parent->item->object.oid),
	stop_progress(&ctx->progress);
			return -1;
			packedDate[0] = 0;
	if (ctx->oids.alloc < 1024)
					ctx->commits.nr);
		g = g->base_graph;
#include "hashmap.h"
	return parse_commit_in_graph_one(r, r->objects->commit_graph, item);
	 * "commit-graph verify".
	uint32_t i;
	g = ctx->r->objects->commit_graph;

	int nr;
}
	if (read_replace_refs) {
		 * our generation is also GENERATION_NUMBER_MAX. Decrement to avoid
		if (i && oidcmp(&prev_oid, &cur_oid) >= 0)
	struct commit **list = ctx->commits.list;

			hashwrite_be32(f, edge_value);
	last_chunk_offset = 8;
		case GRAPH_CHUNKID_OIDLOOKUP:

		case GRAPH_CHUNKID_OIDFANOUT:

		}

			g = g->base_graph;
	if (!prepare_commit_graph(r))
	for (parent = commit->parents; parent; parent = parent->next) {


		}
		if (get_oid_hex(line.buf, &oids[i])) {
	if (!g->num_commits)
	if (!ctx->commits.nr)
{


}

			if (graph->chunk_commit_data)
	if (!prepare_commit_graph(r))
#define REACHABLE       (1u<<15)
	}
	if (ctx->report_progress)

		die("dying as requested by the '%s' variable on commit-graph load!",
	if (graph_version != GRAPH_VERSION) {
	uint32_t chunk_ids[6];
		}
	if (c->graph_pos == COMMIT_NOT_FROM_GRAPH)
		local_error |= verify_commit_graph(r, g->base_graph, flags);
		cur_g = cur_g->base_graph;
			    num_chunks);
			do {
						 struct commit_graph *g,
		struct commit_list *graph_parents, *odb_parents;
		for (i = 0; i < ctx->num_commit_graphs_after; i++) {
		if (chunk_offset > graph_size - the_hash_algo->rawsz) {
void free_commit_graph(struct commit_graph *g)
	va_start(ap, fmt);
		g->num_commits_in_base = chain->num_commits + chain->num_commits_in_base;
}
	if (g)
					0);
	return local_error;
	struct packed_oid_list oids;
 *
		ALLOC_GROW(ctx->commits.list, ctx->commits.nr + 1, ctx->commits.alloc);

		ctx->progress = start_delayed_progress(
	if (!(edge_value & GRAPH_EXTRA_EDGES_NEEDED)) {
	for (i = 0; i < ctx->commits.nr; i++) {
	/*
	    write_graph_chunk_base(f, ctx)) {
	if (r->parsed_objects && r->parsed_objects->grafts_nr)

static void prepare_commit_graph_one(struct repository *r,

	do {

		close(fd);
	const struct object_id *a = (const struct object_id *)_a;
	}
			}
}

	while (pos < g->num_commits_in_base)
	const unsigned char *data, *chunk_lookup;
		goto cleanup;
		struct object_directory *odb;
		else if (parent->next)
			if (edge_value < 0)
{
	}
	}
		}
			die(_("unable to parse commit %s"),

#define GRAPH_CHUNKID_BASE 0x42415345 /* "BASE" */
		 * repository.)
	int i;
		ctx->progress = start_delayed_progress(
				found = 1;
			return -1;
		FILE *chainf = fdopen_lock_file(&lk, "w");
}


	ctx->num_extra_edges = 0;

	if (ctx->num_extra_edges) {
		chunk_id = get_be32(chunk_lookup + 0);

	stop_progress(&ctx->progress);
		if (path.len < 6 || strcmp(path.buf + path.len - 6, ".graph"))

			oidcpy(&ctx->oids.list[ctx->oids.nr], &(parent->item->object.oid));
			    g->chunk_oid_lookup, g->hash_len, pos);
	ALLOC_ARRAY(ctx->commit_graph_hash_after, ctx->num_commit_graphs_after);
	graph_size = xsize_t(st->st_size);
static void copy_oids_to_commits(struct write_commit_graph_context *ctx)
	ctx->approx_nr_objects = approximate_object_count();

		free(ctx->commit_graph_filenames_after);
	if (!commit_graph_compatible(the_repository))
		for_each_object_in_pack(p, add_packed_commits, ctx,
	 */
int open_commit_graph(const char *graph_file, int *fd, struct stat *st)
#include "object.h"
	struct strbuf progress_title = STRBUF_INIT;
					     / graph->hash_len;
	if (!c)
			ctx->num_extra_edges += num_parents - 1;
			break;
	int stat_res;
						4 * ctx->num_extra_edges;
	struct packed_commit_list commits;
			       num_chunks),
		ctx->progress = start_delayed_progress(
/*
		    ctx->commits.list[i]->generation != GENERATION_NUMBER_ZERO)
	if (!g)
		ctx->num_commit_graphs_after--;
		g = g->base_graph;

		p = add_packed_git(packname.buf, packname.len, 1);
		oidcpy(&prev_oid, &cur_oid);
static int fill_oids_from_commit_hex(struct write_commit_graph_context *ctx,
	return load_tree_for_commit(r, g, (struct commit *)c);
{
	uint32_t i;
		switch (chunk_id) {
			error(_("error adding pack %s"), packname.buf);
		g = g->base_graph;

	r->objects->commit_graph = read_commit_graph_one(r, odb);

				pop_commit(&list);

		fill_oids_from_all_packs(ctx);
		struct object_id oid;
	struct commit_list **pptr;
		uint32_t lex_index;

	if (ctx->progress_done < ctx->approx_nr_objects)
		while (count < ctx->commits.nr) {
		prepare_commit_graph(ctx->r);
	if (graph_size < GRAPH_MIN_SIZE)
	free(g);
		char *old_graph_name = get_commit_graph_filename(g->odb);

}
		    (result = lookup_commit_reference_gently(ctx->r, &oid, 1))) {
				uint32_t pos;
	struct commit_graph *g = xcalloc(1, sizeof(*g));
		res = -1;
	stop_progress(&ctx->progress);
	} while (!(edge_value & GRAPH_LAST_EDGE));
	oids = xcalloc(count, sizeof(struct object_id));
					error(_("failed to rename base commit-graph file"));
	struct write_commit_graph_context *ctx;
			if ((*list)->object.oid.hash[0] != i)
		die(_("invalid commit position. commit-graph is likely corrupt"));
			    Q_("Finding commits for commit graph from %d ref",
		*pos = item->graph_pos;
		return NULL;
	struct write_commit_graph_context *ctx = (struct write_commit_graph_context*)data;
			    Q_("Finding commits for commit graph in %d pack",
}
	struct string_list list = STRING_LIST_INIT_DUP;
			return -1;
		num_parents = commit_list_count(ctx->commits.list[ctx->commits.nr]->parents);

			}
static inline void set_commit_tree(struct commit *c, struct tree *t)
		return 1;
	for_each_ref(add_ref_to_list, &list);

		for (i = 0; i < ctx->num_commit_graphs_after; i++) {
	ctx->check_oids = flags & COMMIT_GRAPH_WRITE_CHECK_OIDS ? 1 : 0;
	hashwrite(f, g->data, g->data_len - g->hash_len);
	return 1;
						 const struct commit *c)

		result = rename(ctx->graph_name, final_graph_name);
					commit_hex->nr);
		struct object_id *tree;
				     struct string_list *commit_hex)
		ctx->commits.nr++;
	}
}
	int local_error = 0;
		g->data = NULL;
		if (data + graph_size - chunk_lookup <
		if (parse_commit_internal(odb_commit, 0, 0)) {
		return 0;
void close_commit_graph(struct raw_object_store *o)
		free(ctx->commit_graph_hash_after[ctx->num_commit_graphs_after - 2]);
		struct commit_graph *g;
#define GRAPH_FANOUT_SIZE (4 * 256)
		if (parent)
	if (edge_value == GRAPH_PARENT_NONE)
			for (parent = current->parents; parent; parent = parent->next) {
			return -1;

	graph_map = xmmap(NULL, graph_size, PROT_READ, MAP_PRIVATE, fd, 0);
	/*
	stop_progress(&ctx->progress);
		chunk_write[2] = htonl(chunk_offsets[i] & 0xffffffff);

#include "commit.h"


	write_graph_chunk_fanout(f, ctx);
	const unsigned hashsz = the_hash_algo->rawsz;
					_("Loading known commits in commit graph"),


{
			i = ctx->num_commit_graphs_before;

		 * This repository is not configured to use commit graphs, so
		error(_("commit-graph file is too small"));
static void write_graph_chunk_oids(struct hashfile *f, int hash_len,
		}


	if (is_repository_shallow(r))
	if (ctx->split) {
	}

		}
		commit = lookup_commit(ctx->r, &ctx->oids.list[i]);
		else
static void write_graph_chunk_fanout(struct hashfile *f,
		g = g->base_graph;

	 * because this is a very hot codepath nothing that e.g. loops
	}
	count_distinct = count_distinct_commits(ctx);
	hashwrite_be32(f, GRAPH_SIGNATURE);
					     oid_to_hex(&cur_oid),
	uint64_t chunk_offsets[6];


#define GRAPH_CHUNKID_DATA 0x43444154 /* "CDAT" */
	 */
		free(old_graph_name);
		return 0;
	return g;
			else {
/* Remember to update object flag allocation in object.h */
			break;
		    GIT_TEST_COMMIT_GRAPH_DIE_ON_LOAD);
	uint32_t edge_value;
	for (i = 0; i < ctx->num_commit_graphs_after &&
	stat_res = stat(chain_name, &st);
		if (last_chunk_id == GRAPH_CHUNKID_OIDLOOKUP)
		}
	}
			char *graph_name = get_split_graph_filename(odb, line.buf);
	while (g && (g->num_commits <= size_mult * num_commits ||
				    parent->item->generation == GENERATION_NUMBER_ZERO) {
	if (*fd < 0)
		struct utimbuf updated_time;
	if (ctx->report_progress)
	c->graph_pos = pos;
	struct commit_list *parent;
		merge_commit_graph(ctx, g);
		return 0;
	}
		return 0;
		}
static struct tree *load_tree_for_commit(struct repository *r,
		}


	const struct split_commit_graph_opts *split_opts;
	 * Store the "full" position, but then use the

	}
			ctx->num_commit_graphs_before++;
	uint32_t i, cur_fanout_pos = 0;
		f = hashfd(fd, ctx->graph_name);
}
		warning(_("commit-graph has no base graphs chunk"));
			graph_report(_("commit date for commit %s in commit-graph is %"PRItime" != %"PRItime),

	struct object_id file_hash;
	if (ctx->report_progress)


		if (commit)

				num_extra_edges++;

				     oid_to_hex(&cur_oid));

				parent = parent->next;
			if (!oideq(&graph_parents->item->object.oid, &odb_parents->item->object.oid))
	prepare_alt_odb(r);
				add_missing_parents(ctx, commit);
{
		chunk_offsets[num_chunks + 1] = chunk_offsets[num_chunks] +
		       enum commit_graph_write_flags flags,
		graph_parents = graph_commit->parents;
static const unsigned char *commit_to_sha1(size_t index, void *table)
	struct repository *r;
			ctx->oids.alloc += ctx->r->objects->commit_graph->num_commits;
	    r->settings.core_commit_graph != 1)
		while (list) {
			ctx->oids.nr);

	chunk_offsets[3] = chunk_offsets[2] + (hashsz + 16) * ctx->commits.nr;

static int parse_commit_in_graph_one(struct repository *r,

			return 0;

	if (ctx->progress)
			      int n)
	pptr = insert_parent_or_die(r, g, edge_value, pptr);
	lex_index = pos - g->num_commits_in_base;
	/*
		strbuf_addf(&progress_title,
				uint32_t pos,
		}
			die(_("unexpected duplicate commit id %s"),
static void close_reachable(struct write_commit_graph_context *ctx)

	return 0;
		BUG("get_commit_tree_in_graph_one called from non-commit-graph commit");
#define GRAPH_VERSION GRAPH_VERSION_1
		}
	fprintf(stderr, "\n");
			break;
		for (i = 0; i < g->num_commits; i++) {
		for (parent = (*list)->parents; num_parents < 3 && parent;

	       return 0;

int write_commit_graph(struct object_directory *odb,
					ctx->commit_graph_hash_after[ctx->num_commit_graphs_after - 1]);
	if (!r->gitdir)
			       pack_indexes->nr),

	verify_commit_graph_error = 1;

		ctx->commit_graph_filenames_after[i] = xstrdup(ctx->commit_graph_filenames_before[i]);
			if (graph_parents->item->generation > max_generation)
		return NULL;


		 check_oids:1;
		parent_data_ptr++;
		hold_lock_file_for_update(&lk, ctx->graph_name, LOCK_DIE_ON_ERROR);
				struct object_id *oid)
		if (max_generation == GENERATION_NUMBER_MAX)
	stop_progress(&progress);
	if (ctx->report_progress) {

				}
		}
	if (packed_object_info(ctx->r, pack, offset, &oi) < 0)
	return 0;
	ctx->split = flags & COMMIT_GRAPH_WRITE_SPLIT ? 1 : 0;
			    ctx->odb->path);
char *get_commit_graph_filename(struct object_directory *odb)
		return 1;

#include "progress.h"
		}
	 * As this loop runs, ctx->oids.nr may grow, but not more
static char *get_chain_filename(struct object_directory *odb)
{
	strbuf_release(&line);
		chunk_ids[num_chunks] = GRAPH_CHUNKID_BASE;
		int edge_value;
			if (odb_parents == NULL) {
		munmap((void *)g->data, g->data_len);

		if (graph_commit->generation != max_generation + 1)

				     oid_to_hex(&cur_oid));
{
}

	QSORT(ctx->commits.list, ctx->commits.nr, commit_compare);
		      hash_version, oid_version());
					max_generation = parent->item->generation;
	}
	uint32_t i;
				     oid_to_hex(&cur_oid),
							 &pos))
	struct commit **list = ctx->commits.list;
			return NULL;
		} else {
#define GRAPH_SIGNATURE 0x43475048 /* "CGPH" */
{

}

	strbuf_release(&path);
	}
			  &ctx->commits.list[i]->object.oid)) {
	return 1;
		current_graph_number--;


			commit->object.flags |= REACHABLE;

	num = write_graph_chunk_base_1(f, g->base_graph);
				break;
				break;

	}
				     oid_to_hex(&cur_oid),
		unlink(chain_file_name);



	return get_commit_tree_in_graph_one(r, r->objects->commit_graph, c);
	unsigned long approx_nr_objects;
#include "alloc.h"
	if (ctx->num_commit_graphs_after > 1) {
	struct strbuf progress_title = STRBUF_INIT;
			      uint32_t pos,
		return NULL;


	int nr;
		ctx->base_graph_name = xstrdup(ctx->new_base_graph->filename);
static int add_graph_to_chain(struct commit_graph *g,
					_("Expanding reachable commits in commit graph"),
		display_progress(ctx->progress, i + 1);
#define GRAPH_CHUNKID_OIDLOOKUP 0x4f49444c /* "OIDL" */
			      (uint32_t)chunk_offset);
		stat(ctx->commit_graph_filenames_before[i], &st);

	if (!hasheq(checksum.hash, g->data + g->data_len - g->hash_len)) {
		if (g->odb != ctx->odb)
		if (ctx->split_opts->size_multiple)
	while (pos < g->num_commits_in_base)
	hashwrite_u8(f, GRAPH_VERSION);
	}

		if (strbuf_getline_lf(&line, fp) == EOF)
				}
			edge_value = GRAPH_EXTRA_EDGES_NEEDED | num_extra_edges;
			       FOR_EACH_OBJECT_PACK_ORDER);
		n--;
		prepare_replace_object(r);
	vfprintf(stderr, fmt, ap);
	sort_and_scan_merged_commits(ctx);
	return 0;
	ALLOC_GROW(ctx->oids.list, ctx->oids.nr + 1, ctx->oids.alloc);
	 * itself.

					progress_title.buf,
}
	struct dirent *de;
					      ctx->commits.list,
		if (result) {
		while (cur_oid.hash[0] > cur_fanout_pos) {
		int chunk_repeated = 0;
				     oid_to_hex(&cur_oid));
		}
	if (g->graph_fd >= 0) {



			ALLOC_ARRAY(ctx->commit_graph_filenames_before, ctx->num_commit_graphs_before);
				max_generation = graph_parents->item->generation;
		 report_progress:1,
				edge_value += ctx->new_num_commits_in_base;
			   const struct object_id *oid,
		return;
		display_progress(ctx->progress, i + 1);
		hashwrite(f, (*list)->object.oid.hash, (int)hash_len);
#define GRAPH_PARENT_NONE 0x70000000
}
}
			int all_parents_computed = 1;
			ALLOC_GROW(ctx->oids.list, ctx->oids.nr + 1, ctx->oids.alloc);
	if (ctx->split && ctx->base_graph_name && ctx->num_commit_graphs_after > 1) {
static int verify_commit_graph_lite(struct commit_graph *g)
	} else {
	while ((de = readdir(dir)) != NULL) {
					ctx->commits.nr);
			g = ctx->r->objects->commit_graph;


	}
				edge_value += ctx->new_num_commits_in_base;
		graph_report(_("the commit-graph file has incorrect checksum and is likely corrupt"));
{
		return NULL;
}

	}
		}

				result = rename(ctx->base_graph_name, dest);
{
				graph_report(_("commit-graph has incorrect fanout value: fanout[%d] = %u != %u"),
				ctx->num_extra_edges += num_parents - 1;
	}
			}
		display_progress(ctx->progress, i + 1);

			const char *dest = ctx->commit_graph_filenames_after[
				if (find_commit_in_graph(parent->item,
					 struct commit *c)
		struct packed_git *p;
			uint32_t fanout_value = get_be32(g->chunk_oid_fanout + cur_fanout_pos);
		return c->maybe_tree;

		if (cur_g) {
	chunk_offsets[1] = chunk_offsets[0] + GRAPH_FANOUT_SIZE;
	return 0;
{
	va_end(ap);
	struct commit_graph *cur_g = chain;
		char *new_base_name = get_split_graph_filename(ctx->new_base_graph->odb, new_base_hash);

	ret = parse_commit_graph(graph_map, fd, graph_size);
		{
	return graph;
		ctx->oids.alloc = split_opts->max_commits;
		 */

	if (!g->chunk_oid_lookup) {
		/* Since num_parents > 2, this initializer is safe. */
#include "revision.h"
	if (!git_env_bool(GIT_TEST_COMMIT_GRAPH, 0) &&
	if (ctx->report_progress)
	struct strbuf path = STRBUF_INIT;
		if (!commit)



}
	int open_ok = open_commit_graph(graph_file, &fd, &st);
				     odb_commit->date);

	commit_data = g->chunk_commit_data + (g->hash_len + 16) * lex_index;
}

{
		ctx->progress = start_delayed_progress(
	return g;
		hashwrite(f, tree->hash, hash_len);
static int verify_commit_graph_error;

	if (hash_version != oid_version()) {
	dir = opendir(path.buf);
			display_progress(ctx->progress, ++ctx->progress_cnt);
		for (i = 0; i < ctx->num_commit_graphs_after; i++)
				    oid_to_hex(&parent->item->object.oid),

	c = lookup_commit(r, &oid);
			}
static void fill_oids_from_all_packs(struct write_commit_graph_context *ctx)
			graph_report(_("failed to parse commit %s from commit-graph"),
#include "commit-graph.h"
		if (!valid) {
			*pos = lex_index + cur_g->num_commits_in_base;
			}

	}
