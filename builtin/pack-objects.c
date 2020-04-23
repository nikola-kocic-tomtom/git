
static unsigned *done_pbase_paths;

		pack_size_limit = 1024*1024;
	if (used == 0)

	else
			if (p[i].remaining > 2*window &&
		{ OPTION_CALLBACK, 0, "index-version", NULL, N_("<version>[,<offset>]"),
			 N_("similar to --all-progress when progress meter is shown")),
			if (st)

	 * The actual depth of each object we will write is stored as an int,

		eword_t word = reuse_packfile_bitmap->words[i];
		; /* nothing */
			line[--len] = 0;

		}
}
			count--;
		do_check_packed_object_crc = 1;
				}
			stream.next_out = obuf;
	 * Mark objects that are at the tip of tags.
		 * going to pack.

		trg->data = read_object_file(&trg_entry->idx.oid, &type, &sz);
		return;
	    !src_entry->preferred_base &&
			zret = git_deflate(&stream, readlen ? 0 : Z_FINISH);
	return stream.total_out;
		nent->temporary = (available_ix < 0);
	    check_pack_inflate(p, &w_curs, offset, datalen, entry_size)) {

		}
{
		return;
	return 0;
				 * and we do not need to deltify it.

		hashwrite(f, header, hdrlen);
 * limit.
			hashwrite(out, base_oid.hash, the_hash_algo->rawsz);
	return hdrlen + datalen;
		p[i].depth = depth;
			}
			       buf, size, &delta_size, 0);
 *
}
	}
}
			uint32_t other_idx = idx + j;
{
	for (i = 0; i < to_pack.nr_objects; i++) {
		if (objects[i].tagged)


static int use_delta_islands;
		max_delta_cache_size = git_config_int(k, v);
		/*
		hashwrite(f, DELTA(entry)->idx.oid.hash, hashsz);
	struct object_entry *root;
		OPT_STRING_LIST(0, "keep-pack", &keep_pack_list, N_("name"),
			 N_("use the sparse reachability algorithm")),

		max_size = trg_size/2 - the_hash_algo->rawsz;
		int mi = lo + ((hi - lo) / 2);
			nr_result--;
/*

				close_istream(st);

		resolve_tree_islands(the_repository, progress, &to_pack);
		if (type < 0)

		progress_unlock();


		  N_("handling for missing objects"), PARSE_OPT_NONEG,

			bitmap_git,
 * progress_state
				break;
		if (want != -1)
 */
static void pbase_tree_put(struct pbase_tree_cache *cache)

			return;
		if (cur->dfs_state == DFS_DONE)
			continue;
				     record_recent_object, NULL);
	int flags = 0;
{

		if (!entry->type_valid ||
	if (!DELTA(entry))
	packing_data_lock(&to_pack);
	 */
		 * + 1) entries, the final depth of an entry will be its

			pthread_join(target->thread, NULL);
		}

	} else {
				 * exact half in that case.
	if (!to_reuse)
		}
{
	if (!has_object_file(&obj->oid) && is_promisor_object(&obj->oid))
		SET_DELTA_SIBLING(&objects[i], NULL);
	p = xcalloc(delta_search_threads, sizeof(*p));
		if (!p->pack_local || p->pack_keep || p->pack_keep_in_core)
/*
			depth++;
			i = sizeof(ofs_header) - 1;

		packing_data_unlock(&to_pack);
static int add_object_entry_from_bitmap(const struct object_id *oid,
static void show_object__ma_allow_any(struct object *obj, const char *name, void *data)
}
		pbase_tree_cache[my_ix] = nent;
		return write_no_reuse_object(f, entry, limit, usable_delta);
		char *pack_tmp_name = NULL;
		 * Did we write the wrong # entries in the header?
	return 1;
	recursing = (e->idx.offset == 1);

		revs.ignore_missing_links = 1;
	/* Did not find one.  Either we got a bogus request or
		if (prepare_revision_walk(&revs))

 */
			add_to_order = 1;
				continue;
		if (ret)
				flags ^= UNINTERESTING;
		to_write = reuse_packfile->revindex[written].offset

		;
		}
		find_deltas(me->list, &me->remaining,
		src->index = create_delta_index(src->data, src_size);
/*
		OPT_SET_INT_F(0, "reflog", &rev_list_reflog,
		n->entry = entry;
		else {
		usable_delta = 0;	/* base was written to another pack */
 * We search for deltas in a list sorted by type, by filename hash, and then
		if (arg)
{
		return write_no_reuse_object(f, entry, limit, usable_delta);
	enum object_type type;
		packing_data_unlock(&to_pack);
	if (progress)
	} else {
}
	return wo;

			    cur->dfs_state);
	if (!pack_size_limit || !nr_written)
	}
			if (oe_type(entry) < 0)
	QSORT(sorted_by_offset, to_pack.nr_objects, pack_offset_sort);
	enum object_type type;
		progress_unlock();
	 */
	if (0 <= pos)
		return 1;
	p = (last_found != (void *)1) ? last_found :
 * never consider reused delta as the base object to
	const char *p;
			add_to_write_order(wo, endp, e);
	int my_ix = pbase_tree_cache_ix(oid);
static off_t find_reused_offset(off_t where)
		return 1;
 */
}
		int have_base = 0;
	packing_data_unlock(&to_pack);
			break;
	if (!rev_list_all || !rev_list_reflog || !rev_list_index)
			pthread_cond_wait(&progress_cond, &progress_mutex);
	return 0;
	if (keep_unreachable && unpack_unreachable)

	if (*c == ',' && c[1])
		return 0;
			 N_("ignore packed objects")),
	}

static void cleanup_preferred_base(void)
			oe_set_tree_depth(&to_pack, ent, depth);
			    N_("use threads when searching for best delta matches")),
		fn_show_object = show_object__ma_allow_promisor;
}

	die(_("invalid value for --missing"));
			pthread_cond_destroy(&target->cond);
			len = encode_in_pack_object_header(header, sizeof(header),
	reused++;
	struct option pack_objects_options[] = {
		OPT_SET_INT_F(0, "indexed-objects", &rev_list_index,
		while (window_memory_limit &&

	sizediff = src_size < trg_size ? trg_size - src_size : 0;

				break;
		unsigned depth;
#include "oid-array.h"
		return;
	trg_size = SIZE(trg_entry);

	 * Quietly ignore EXPECTED missing objects.  This avoids problems with
	}
		entry->tagged = 1;
	return (ix+1) % ARRAY_SIZE(pbase_tree_cache);
	ALLOC_ARRAY(written_list, to_pack.nr_objects);
		return 1;

	if (recursing) {
static struct packing_data to_pack;
	if (!use_internal_rev_list || (!pack_to_stdout && write_bitmap_index) || is_repository_shallow(the_repository))
	if (packed_object_info(the_repository, IN_PACK(entry), entry->in_pack_offset, &oi) < 0) {
						 NULL));
	/* The offset of the first object of this chunk in the original
					      type, size);
	unsigned n;
	    (!local || !have_non_local_packs))

		unsigned long used, used_0;
	free(write_order);
	if (in_pack.nr) {
		return 0;

	obj->flags |= OBJECT_ADDED;
	uint32_t i;
	const struct packed_git *a_in_pack = IN_PACK(a);
		/*

	 * slots after that slot if it is cached.
	struct thread_params *me = arg;
		if (handle_revision_arg(line, &revs, flags, REVARG_CANNOT_BE_FILENAME))
		}
 * packfile.
		 * done to save time on future traversals.

	char line[1000];
		unsigned long expect)
			if (!exclude && want > 0)
				/*
	}
	       !incremental;
	else if (!pack_size_limit)
	 * Now let's wait for work completion.  Each time a thread is done
	if (type == OBJ_OFS_DELTA) {
		target->list_size = sub_size;
				break;
static void add_preferred_base_object(const char *name)
	if (!want_object_in_pack(oid, exclude, &found_pack, &found_offset)) {
	}
			p = p->next;
		(*list_size)--;


	return i;

		struct object_entry *e = &objects[--i];
	assert(!unset);
	 * We catch duplicates already in add_object_entry(), but we'd

static void add_tag_chain(const struct object_id *oid)
				if (write_bitmap_index != WRITE_BITMAP_QUIET)
 * Protect object list partitioning (e.g. struct thread_param) and
	setup_revisions(ac, av, &revs, &s_r_opt);
{
			free(buf);
		/* mark written objects as written to previous pack */
				      unsigned int *endp,
		SET_DELTA_CHILD(DELTA(e), e);
	size_t pos = 0;
	unsigned list_size;
				SET_DELTA_EXT(entry, &base_ref);
	return 0;
	 * away when NO_PTHREADS is defined.

		while (ofs >>= 7)
	MA_ALLOW_PROMISOR, /* silently allow all missing PROMISOR objects */
		    written, nr_result);

	 */
		    (st = open_istream(the_repository, &entry->idx.oid, &type,
/*
		return 0;
			struct object *o = in_pack.array[i].object;
	 * staging them now and getting an odd error later.
		return 1;

	struct hashfile *f;

		off_t to_write;
			finalize_hashfile(f, oid.hash, CSUM_HASH_IN_STREAM | CSUM_FSYNC | CSUM_CLOSE);
	/*
static uint32_t written, written_delta;
			if (write_bitmap_index) {
		*mem_usage += sz;
	e->filled = 1;


}
		p[i].window = window;
		warning(_("pack.deltaCacheLimit is too high, forcing %d"),
		}
	 * as it cannot exceed our int "depth" limit. But before we break
static struct list_objects_filter_options filter_options;
		if (!entry->preferred_base) {
/* Remember to update object flag allocation in object.h */
	if (progress && all_progress_implied)
	else {
{
	}
	for (neigh = 0; neigh < 8; neigh++) {
 * Check whether we want the object in the pack (e.g., we do not want
			add_object_entry(&o->oid, o->type, "", 0);


			unuse_pack(&w_curs);
	}
	done_pbase_paths[pos] = hash;
			unsigned i, ofs_len;

	if (a_in_pack < b_in_pack)
	}
			lo = mi + 1;

	maxsize = git_deflate_bound(&stream, size);
	} while (st == Z_OK || st == Z_BUF_ERROR);
		struct pack_window *w_curs = NULL;
		if (!src->index) {
			total_depth += cur->depth;
		int j, max_depth, best_base = -1;
			if (!buf)
static void init_threaded_search(void)
		 * error is always one less than the size of the cycle we
	if (!strcmp(k, "pack.usebitmaps")) {
		struct packed_git *p = list_entry(pos, struct packed_git, mru);
		}
			    oid_to_hex(&trg_entry->idx.oid), (uintmax_t)sz,
	free(delta_list);
		warning(_("loose object at %s could not be examined"), path);
	do {
		sparse = the_repository->settings.pack_use_sparse;
		if (ent && oideq(&ent->oid, oid)) {
		OPT_SET_INT_F(0, "all", &rev_list_all,
	 * memory reasons. Something is very wrong if this time we
	reused_chunks[reused_chunks_nr].original = where;
{
				return;
	if (progress)
			if (want != -1)
static int allow_ofs_delta;
		pthread_mutex_lock(&me->mutex);
			      &write_bitmap_index,
	add_object_entry(&commit->object.oid, OBJ_COMMIT, NULL, 0);
			used_0 = 0;
static int add_object_entry(const struct object_id *oid, enum object_type type,
static const char *pack_usage[] = {
				}

/* Return 0 if we will bust the pack-size limit */

	else if (a->offset > b->offset)
	if (!ent) {
	 * to be worth splitting anymore.
		}
	}
		stream.total_out == expect &&
		struct object_entry *base_entry;

	 * And then all remaining commits and tags.

		 */
		}
		 */
		 * base from this object's position in the pack.
			continue;
		use_internal_rev_list = 1;
			/*
			e = DELTA(e);
			die(_("unable to pack objects reachable from tag %s"),
	}
		 * entry what its final depth will be after all of the
 * The main thread waits on the condition that (at least) one of the workers
static timestamp_t unpack_unreachable_expiration;
			 */
			sub_size++;
	free(trg_entry->delta_data);
	if (progress)

		free(ent->tree_data);
			list = victim->list + victim->list_size - sub_size;
		add_to_write_order(wo, wo_end, &objects[i]);
			     " reused %"PRIu32" (delta %"PRIu32"),"
static void get_object_list(int ac, const char **av)

			 &all_progress_implied,
		warning(_("delta chain depth %d is too deep, forcing %d"),
		struct packed_git *p,
		usable_delta = 0;	/* base could end up in another pack */
	if (!pack_to_stdout && p->index_version > 1 &&
			    oid_object_info(the_repository, &entry->idx.oid, &size));
	unsigned char *in;
	while (git_deflate(&stream, Z_FINISH) == Z_OK)
		}
		unpack_unreachable_expiration = 0;
		child = DELTA_SIBLING(child);
}
			cur->dfs_state = DFS_DONE;
static void record_reused_object(off_t where, off_t offset)
	if (src->depth >= max_depth)

		if (cmp < 0)

			break;
	struct object_id peeled;
	pthread_mutex_t mutex;
			      WRITE_BITMAP_QUIET, PARSE_OPT_HIDDEN),
			if (reuse_delta && !entry->preferred_base) {
	unsigned hdrlen;
	 * Then fill all the tagged tips.
{
			ofs_len = sizeof(ofs_header) - i;
		assert(base_offset != 0);
		die(_("bad index version '%s'"), val);
 * Indexed commits
				die(_("deflate error (%d)"), zret);
			write_bitmap_index = 0;

#define IN_PACK(obj) oe_in_pack(&to_pack, obj)
			       struct object_entry *e)
			add_object_entry(&it->pcache.oid, OBJ_TREE, NULL, 1);
		pthread_mutex_unlock(&me->mutex);
			struct stat st;
		argv_array_push(&rp, "--objects");
		 * instead, as we can afford spending more time compressing

				list -= sub_size;
					warning_errno(_("failed utime() on %s"), pack_tmp_name);
		window_memory_limit = git_config_ulong(k, v);
	get_object_details();
	 * are present we will determine the answer right now.
		for (p = strchr(name, '/'); p; p = strchr(p + 1, '/'))
		if (!fgets(line, sizeof(line), stdin)) {
	stream.avail_out = maxsize;
	oi.typep = &type;
					die(_("unable to force loose object"));
{
};
			OBJ_OFS_DELTA : OBJ_REF_DELTA;
		.allow_exclude_promisor_objects = 1,
				p->pack_keep_in_core) &&
	if (!strcmp(k, "pack.indexversion")) {
				 * don't have to include it anyway.
	 * if they do not matter we know we want the object in generated pack.

				 * resulting pack.  Be resilient and ignore
			}
				int src = (dst + 1) % window;
		progress_unlock();
static void add_preferred_base(struct object_id *oid)
		die(_("ordered %u objects, expected %"PRIu32),
	}
static enum write_one_status write_one(struct hashfile *f,
		nent = xmalloc(sizeof(*nent));

		/*

#include "diff.h"
		return 1;
	} while (nr_remaining && i < to_pack.nr_objects);
	if (obj_is_packed(oid))

		off_t offset,
{
			       int exclude,
 * a portion of the main object list. Just don't access object entries
	 */
	else if (!IN_PACK(entry))
		    oe_size_greater_than(&to_pack, entry, big_file_threshold))
		progress_state = start_progress(_("Enumerating objects"), 0);
			free(pack_tmp_name);
		if (fixup) {
	int neigh;
	if (pack_compression_level == -1)
/*
		if (!DELTA(cur)) {
	if (a->preferred_base > b->preferred_base)
			nth_packed_object_id(&base_oid, reuse_packfile,
			/* pass it off to sibling at this level */
			struct unpacked swap = array[best_base];
static enum {
	struct pack_window *w_curs = NULL;
		stream.next_in = in;
#define DELTA(obj) oe_delta(&to_pack, obj)
	out = xmalloc(maxsize);
 */
	FREE_AND_NULL(done_pbase_paths);
	int st;
		return 0;
	 */
		if (*line == '-') {
			int ret;
	}
		unpack_unreachable = 0;
		}
				bitmap_writer_show_progress(progress);
			    N_("do not show progress meter"), 0),
			 N_("do not create an empty pack output")),
		if (!objects[i].filled && oe_layer(&to_pack, &objects[i]) == write_layer)
			progress_unlock();
	for (i = 0; name[i] && name[i] != '\n' && name[i] != '/'; i++)
			const char *down = name+cmplen+1;

		propagate_island_marks(commit);
static struct object_entry **compute_write_order(void)
	return 1;
 * progress_mutex for protection.
		*mem_usage += sz;
	}

			unuse_pack(&w_curs);

		datalen = do_compress(&buf, size);
	if (!delta_buf)
	pthread_mutex_init(&progress_mutex, NULL);
			offset = find_pack_entry_one(oid->hash, p);
			die(_("bad pack.indexversion=%"PRIu32),
			pbase_tree_put(tree);
			continue;
	if (incremental)
			write_bitmap_options |= BITMAP_OPT_HASH_CACHE;
	const unsigned hashsz = the_hash_algo->rawsz;
		use_internal_rev_list = 1;
	return 0;


	struct revindex_entry *revidx;

		use_bitmap_index_default = 0;
	if (type == OBJ_OFS_DELTA) {
	if (!len)
				die(_("unable to read %s"),
			 */
		 * the maximum depth. Most of the resulting chains will contain
			if (!ferror(stdin))
		 * at this point...
		assert(reuse_packfile_objects);
}
	 * that matches the criteria is sufficient for us to decide to omit it.
	reused_chunks[reused_chunks_nr].difference = offset;
		pthread_mutex_init(&p[i].mutex, NULL);
}

 * sure it is not corrupt.
			/*
		indexed_commits_alloc = (indexed_commits_alloc + 32) * 2;
	unsigned long maxsize;
		}
	if (thin) {
		return 0;
		if (oid_object_info(the_repository, &e->idx.oid, &size) < 0)
	 */
		if (DELTA(entry)) {
	MA_ERROR = 0,      /* fail if any missing objects are encountered */
		 * Deltas with a base reference contain
	}


			 N_("do not pack objects in promisor packfiles")),
 * with some extra book-keeping:
			&reuse_packfile_objects,

	int hi = done_pbase_paths_num;
	else
	write_order = compute_write_order();
		oe_set_type(entry, type);
			if ((word >> offset) == 0)
			unsigned long size;
		reuse_delta = 0;
			}
}
		if (cur->dfs_state == DFS_DONE) {
		return 0;
	if (!to_pack.nr_objects || !window || !depth)
			      N_("include objects referred by reflog entries"),
	done_pbase_paths_num++;
			die(_("expected object ID, got garbage:\n %s"), line);
	return freed_mem;
	free(in);

		cache_unlock();
		if (DELTA_CHILD(entry)) {
		if (entry->no_try_delta)
	/*
			clearerr(stdin);

		delta_cache_size += delta_size;
	struct argv_array rp = ARGV_ARRAY_INIT;
	sorted_by_offset = xcalloc(to_pack.nr_objects, sizeof(struct object_entry *));
		/*
	 * delta, we need to keep going to look for more depth cuts. So we need
		if (!entry->preferred_base) {

		 * should evict it first.
		nr_written = 0;
		fprintf_ln(stderr,
		to_reuse = 0;	/* we want to pack afresh */
		return 0;
				    the_repository);
		}
		if ((!p->pack_local || p->pack_keep ||
			      1, PARSE_OPT_NONEG),
	 * tag at all if we already know that it's being packed (e.g., if
	if (!nent->temporary)
		OPT_BOOL(0, "keep-unreachable", &keep_unreachable,
{
	return WRITE_ONE_WRITTEN;

			unpack_unreachable_expiration = approxidate(arg);
		if (!ent)
 * reader of the pack might not understand, and which would therefore prevent
}
		argv_array_clear(&rp);
	unsigned long size;
			oe_set_type(entry, entry->in_pack_type);
		 */
	unsigned long size;
	 */
		read_object_list_from_stdin();
		 * call.
	}

}
static int add_ref_tag(const char *path, const struct object_id *oid, int flag, void *cb_data)
		use_internal_rev_list = 1;
		else
 * literally as a delta against the base in "base_sha1". If
		       list[sub_size]->hash == list[sub_size-1]->hash)
			entry->in_pack_header_size = used + used_0;
static int option_parse_missing_action(const struct option *opt,
{
				goto next;
		if (done_pbase_paths[mi] < hash)
		const char *name = basename(p->pack_name);

		stream.total_in == len) ? 0 : -1;

					enum object_type type,
	}
		struct thread_params *victim = NULL;

static void ll_find_deltas(struct object_entry **list, unsigned list_size,
				enum object_type type,
		readlen = read_istream(st, ibuf, sizeof(ibuf));
	else if (DELTA(entry)->idx.offset == (off_t)-1)
	stop_progress(&progress_state);

		if (limit && hdrlen + sizeof(dheader) - pos + datalen + hashsz >= limit) {
static int ofscmp(const void *a_, const void *b_)
		me->working = 0;

	}
	}
		return oidcmp(&a->object->oid, &b->object->oid);
				bitmap_writer_build_type_index(
		}
	trace2_data_intmax("pack-objects", the_repository,
		 * original depth modulo (depth + 1). Any time we encounter an
			hashwrite(f, obuf, stream.next_out - obuf);
			    const char *name, int exclude)

	struct object_entry **list;
	return 1;
		OPT_BOOL(0, "reuse-delta", &reuse_delta,

static void copy_pack_data(struct hashfile *f,
{
			    N_("limit pack window by objects")),
	for (i = last_untagged; i < to_pack.nr_objects; i++) {
			unuse_pack(&w_curs);
	stream.avail_in = size;
		OPT_SET_INT_F(0, "write-bitmap-index-quiet",
static int type_size_sort(const void *_a, const void *_b)

	SET_DELTA(entry, NULL);
	warn_on_object_refname_ambiguity = 0;
					&to_pack, written_list, nr_written);
		return 0;
					  tree_type, &size, &tree_oid);
		if (p == *found_pack)
		}

	}
		struct pbase_tree *tmp = it;
		entry->preferred_base = 1;
	if (IN_PACK(entry)) {

		return 0;

			goto next;
	static struct packed_git *last_found = (void *)1;
{
static const char *base_name;
}
static void add_extra_kept_packs(const struct string_list *names)
			array[dst] = swap;
		SET_DELTA_CHILD(&objects[i], NULL);
		if (oe_type(entry) == OBJ_BLOB &&
			    WRITE_BITMAP_TRUE),
		hdrlen += sizeof(dheader) - pos;
			entry->no_try_delta = 1;
{
 *

	}
		/* try to split chunks on "path" boundaries */
			return;
		buf = get_delta(entry);
		return 0;
		fn_show_object = show_object;
		fprintf_ln(stderr, _("Delta compression using up to %d threads"),
 * reachable from another object that was.

		 * If the current object is at pack edge, take the depth the
		 * reuse it or not.  Otherwise let's find out as cheaply as
			hashwrite(out, header, len);
		free(tmp);
		    wo_end, to_pack.nr_objects);
			return 0;
static void add_family_to_write_order(struct object_entry **wo,

		       list[sub_size]->hash &&
				goto give_up;
	pbase_tree = NULL;

		 */
		struct pack_entry e;
				if (!nth_packed_object_id(&base_ref, p, revidx->nr))
			buf = read_object_file(&entry->idx.oid, &type, &size);
{
		type = (allow_ofs_delta && DELTA(entry)->idx.offset) ?
	WRITE_BITMAP_TRUE,
				break;

}


			return mi;
}
	 * it to that newly idle thread.  This ensure good load balancing
		 * We must not set ->data_ready before we wait on the
		/*
}

			}
	if (exclude_promisor_objects) {
	}
	WRITE_BITMAP_FALSE = 0,
			unuse_pack(&w_curs);
	} else if (e->idx.offset || e->preferred_base) {

		 * was initialized to 0 before this thread was spawned
		if (line[0] == '-') {
			OBJ_OFS_DELTA : OBJ_REF_DELTA;
			return 0;
		 */
static int can_reuse_delta(const struct object_id *base_oid,
}
		nr_result += reuse_packfile_objects;
			}



	if (oid_array_lookup(&recent_objects, oid) >= 0)
		entry->delta_data = NULL;
			break;

#include "progress.h"
	 * packfile. */
		 * a final DONE. We can quit after the DONE, because either it
		use_internal_rev_list = 1;
	struct pack_window *w_curs;
	datalen = revidx[1].offset - offset;
static int done_pbase_path_pos(unsigned hash)
		for (i = 0; i < delta_search_threads; i++)
			 * to preserve this property.
	if (!src->index) {
	       !ignore_packed_keep_on_disk &&
 * We also detect too-long reused chains that would violate our --depth
		int i;
}
		      dheader[MAX_PACK_OBJECT_HEADER];
	if (non_empty && !nr_result)
	for (i = 0; i < to_pack.nr_objects; i++)
		  PARSE_OPT_OPTARG, option_parse_unpack_unreachable },
}
	for (i = last_untagged; i < to_pack.nr_objects; i++) {

		if (len && line[len - 1] == '\n')
			return 0;
		off_t len)
				error(_("delta base offset out of bound for %s"),
						   &in_pack_size);
	 * changes based no that limit, we may potentially go as deep as the
		break_delta_chains(&to_pack.objects[i]);
	SET_DELTA_SIZE(trg_entry, delta_size);
	 * - to use more robust pack-generation codepath (avoiding possible
		if (fill_midx_entry(the_repository, oid, &e, m)) {
			/* go back to our parent node */
		max_size = DELTA_SIZE(trg_entry);

		 */
 */
	/*
		crc32_begin(f);
	}
	return 0;
		case WRITE_ONE_BREAK:
	 *   packed in suboptimal order).
	unsigned long trg_size, src_size, delta_size, sizediff, max_size, sz;

int cmd_pack_objects(int argc, const char **argv, const char *prefix)
		arg_missing_action = MA_ERROR;
	free(in_pack.array);
			if (offset) {
	for (root = e; DELTA(root); root = DELTA(root))
		progress_state = start_progress(_("Counting objects"),
				return;
			return 0;
{
	it = xcalloc(1, sizeof(*it));
		hashwrite(f, header, hdrlen);
			avail = (unsigned long)len;
			if (st)
			break;
	free(array);
			 * This must be a delta and we already know what the
static void add_descendants_to_write_order(struct object_entry **wo,
	return 1;
	if (use_bitmap_index && !get_object_list_from_bitmap(&revs))
{

		if (entry->preferred_base)
		record_reused_object(sizeof(struct pack_header), 0);
	off_t len;
	}
/*
			   int window, int depth, unsigned *processed)
		add_preferred_base_object(p + 1);

							   OBJ_REF_DELTA, size);
	const enum object_type a_type = oe_type(a);
			len = encode_in_pack_object_header(header, sizeof(header),
static int ignore_packed_keep_in_core;
			die(_("unable to add recent objects"));
}
		return oidcmp(&a->idx.oid, &b->idx.oid);
{
	return 0;
	 * staging them now and getting an odd error later.
		return 0;
		progress_lock();
{
{
		nr_result++;
	cmplen = name_cmp_len(name);
			cur->dfs_state = DFS_DONE;
	struct object_entry **delta_list;
	if (window <= num_preferred_base++)
	for (i = to_pack.nr_objects; i > 0;) {
	const struct packed_git *b_in_pack = IN_PACK(b);
{
		}
	}
	struct object_entry **wo;
		/*
 * deltify other objects against, in order to avoid
		if (island_cmp)
 * signals the main thread and waits on the condition that .data_ready
		if (i < names->nr) {
		OPT_MAGNITUDE(0, "max-pack-size", &pack_size_limit,
		list += sub_size;
	return 0;
		return 0;
			    N_("show progress meter"), 1),
	 * appropriate. Unlike the loop above, which can quit when it drops a
	if (a->preferred_base < b->preferred_base)
		check = attr_check_initl("delta", NULL);
		}
	commit->object.flags |= OBJECT_ADDED;
	if (pack_options_allow_reuse() &&
	       usable_delta = 1;	/* unlimited packfile */

#include "csum-file.h"
			 N_("ignore borrowed objects from alternate object store")),
	} else {
	 * it was included via bitmaps, we would not have parsed it
	 * information for the whole list being completed.
		offset += avail;

static unsigned int indexed_commits_alloc;
/*
{
				struct utimbuf utb;
		if (cmp > 0)
			   unsigned long delta_size)
	uint32_t offset;
	if (!peel_ref(path, &peeled)) {
static void cleanup_threaded_search(void)
enum write_one_status {

	for (i = 0; i < to_pack.nr_objects; i++) {
	return 1;
	if (!delta_search_threads)	/* --threads=0 means autodetect */
			   struct object_entry **base_out)
		if (!pack_to_stdout)
#include "attr.h"
{
	/*
		sorted_by_offset[i] = to_pack.objects + i;
	git_config(git_pack_config, NULL);
		       (zret == Z_OK || zret == Z_BUF_ERROR)) {
	if (local && !p->pack_local)
		    oe_size_less_than(&to_pack, entry, 50))
			      N_("maximum size of each output pack file")),
	}
				    &base_size);
		/*
static void write_reused_pack_one(size_t pos, struct hashfile *out,
		return -1;
	if (!strcmp(arg, "allow-any")) {
}
			finish_tmp_packfile(&tmpname, pack_tmp_name,

				       &size, NULL)) != NULL)
	 * until the remaining object list segments are simply too short
	 * the fact that this object is involved in "write its base
	char *c;
				break;
	trg->depth = src->depth + 1;
			}
				break;
			if (p == *found_pack)
	}
	if (*found_pack) {
		return -1;
static unsigned long do_compress(void **pptr, unsigned long size)

	 */
			entry->in_pack_header_size = used + the_hash_algo->rawsz;
static uint32_t reused, reused_delta;
		entry = packlist_find(&to_pack, &peeled);
		 * mistaking this with unlimited (i.e. limit = 0).
			free(delta_buf);
				    the_repository);
		argv_array_push(&rp, "--reflog");
	} else {
	}

	if (!cache->temporary) {
	for (it = pbase_tree; it; it = it->next) {
		packing_data_lock(&to_pack);
static void mark_in_pack_object(struct object *object, struct packed_git *p, struct in_pack *in_pack)
	entry = packlist_alloc(&to_pack, oid);
	return hdrlen + datalen;
			free(buf);
}
			struct object_entry *s;
static int pack_offset_sort(const void *_a, const void *_b)
"disabling bitmap writing, packs are split due to pack.packSizeLimit"
	/* we don't know yet; keep looking for more packs */

			if (!fspathcmp(name, names->items[i].string))
	if (starts_with(path, "refs/tags/") && /* is a tag? */
	display_progress(progress_state, ++nr_seen);
		free(pbase_tree_cache[i]->tree_data);
			nth_packed_object_id(&oid, p, i);
			return 0;
	 * Finally all the rest in really tight order

		else
 * "git rev-list --objects" output that produced the pack originally.
	if (!reuse_object)
	while (me->remaining) {
		unpack_unreachable = 1;
	/*
		if (ent && depth > oe_tree_depth(&to_pack, ent))

	nent->tree_data = data;
	 * Fully connect delta_child/delta_sibling network.
		}
	off_t datalen;
		return WRITE_ONE_RECURSIVE;

			}
	}
				struct object_id oid;
			return reused_chunks[mi].difference;
		dheader[pos] = ofs & 127;
#include "streaming.h"
			return want;

		unsigned char *buf, c;


			puts(oid_to_hex(&oid));
	/*
	else
	git_deflate_end(&stream);
	 * Quietly ignore ALL missing objects.  This avoids problems with
	 * propagated to the new pack.  Clients receiving streamed packs
	N_("git pack-objects --stdout [<options>...] [< <ref-list> | < <object-list>]"),
					      oid_to_hex(&entry->idx.oid));
		 * from its delta base, thereby making it so.
	return olen;
{

			die(_("unable to create thread: %s"), strerror(ret));
		OPT_INTEGER(0, "window", &window,
			die(_("cannot open pack index"));

				    line);
		unpack_unreachable_expiration = 0;
	unsigned *idx = &to_pack.objects[entry->delta_idx - 1].delta_child_idx;
		delta_search_threads = git_config_int(k, v);
				if (!ofs || MSB(ofs, 7)) {
		if (progress)
	nent->tree_size = size;
		 */
		unuse_pack(&w_curs);
			if (zret != Z_STREAM_END)
static uint16_t write_bitmap_options = BITMAP_OPT_HASH_CACHE;
		error(_("corrupt packed object for %s"),
	BUG_ON_OPT_NEG(unset);
			oid_to_hex(&e->idx.oid));
		struct object *o;
	pbase_tree = it;
	n->index = NULL;

					warning(_(no_split_warning));
	off_t offset;
			if (errno != EINTR)
			SET_SIZE(entry, in_pack_size); /* delta size */

			   _("Total %"PRIu32" (delta %"PRIu32"),"

		die(_("--max-pack-size cannot be used to build a pack for transfer"));
{
	nr_deltas = n = 0;
 * stats
		buf = entry->delta_data;

		return;
			   delta_search_threads);
}

			continue;
			olen += stream.next_out - obuf;

	/* make sure shallows are read */
	if (use_delta_islands)
		if (DELTA(entry))
	}
static enum missing_action arg_missing_action;


			struct pbase_tree_cache *tree;
		if (offset) {

	return 0;
				bitmap_writer_build(&to_pack);
					goto give_up;
				 const char *name,
		return 0;
 * Follow the chain of deltas from this entry onward, throwing away any links
		  option_parse_missing_action },

		case OBJ_REF_DELTA:
			return;
				goto give_up;
		stream.next_in = ibuf;
		BUG("when e->type is a delta, it must belong to a pack");
			   written, written_delta, reused, reused_delta,

	unsigned long used, avail, size;
	struct pbase_tree *it;
		 */
		}

}
	ALLOC_GROW(done_pbase_paths,
	if (!entry)
		      dheader[MAX_PACK_OBJECT_HEADER];
		}
	}
				stop_progress(&progress_state);

	progress = isatty(2);
	pthread_mutex_init(&cache_mutex, NULL);
	struct string_list keep_pack_list = STRING_LIST_INIT_NODUP;
			continue;

	int data_ready;
	}
 */
		 * and therefore it is best to go to the write phase ASAP
 *      (type) when check_object() decided to reuse the delta.

	/* pbase-tree-cache acts as a limited hashtable.
		return 0;
	 * accounting lock.  Compiler will optimize the strangeness
 * It contains an array (dynamically expanded) of the object data, and a map
	/*
 * This tracks any options which pack-reuse code expects to be on, or which a
	if (reused_chunks_nr && reused_chunks[reused_chunks_nr-1].difference == offset)
			BUG("invalid type %d", type);
			}
		/*
	if (DELTA(entry))
	void *tree_data;

{
				 * them if they can't be read, in case the
		}
	while (e) {
			 N_("reuse existing deltas")),
			if (!in_same_island(&delta->idx.oid, base_oid))
	for (p = get_all_packs(the_repository); p; p = p->next) {
			if (!p->pack_local) {
	const enum object_type b_type = oe_type(b);
	 * going to evict it or find it through _get()
		return NULL;
				unsigned long limit, int usable_delta)
		my_ix = pbase_tree_cache_ix_incr(my_ix);

		unsigned char header[MAX_PACK_OBJECT_HEADER];
		if (tag->tagged->type != OBJ_TAG)
		OPT_BOOL(0, "stdout", &pack_to_stdout,
		}
		int len = strlen(line);
		/* ...otherwise we have no fixup, and can write it verbatim */
}
		if (!p->pack_local || p->pack_keep || p->pack_keep_in_core)
		if (where == reused_chunks[mi].original)

{
		depth = git_config_int(k, v);
			for (s = DELTA_SIBLING(e); s; s = DELTA_SIBLING(s)) {
 * that we're not looking for an exact match, just the first
		if (!DELTA(e))
	static struct attr_check *check;
			    (uintmax_t)src_size);
 *
		if (readlen == -1)
		progress_state = start_progress(_("Writing objects"), nr_result);
	oe_set_type(entry, type);
		OPT_BOOL(0, "exclude-promisor-objects", &exclude_promisor_objects,
}
		p[i].data_ready = 0;
#include "packfile.h"
		pthread_mutex_lock(&target->mutex);
	    trg_entry->in_pack_type != OBJ_REF_DELTA &&
	if (rev_list_unpacked) {

		 * Now we know this is the first time we've seen the object. If

		 */
	assert(arg);
static void index_commit_for_bitmap(struct commit *commit)
static show_object_fn fn_show_object;
		off_t fixup;
	git_zstream stream;
}
		hashflush(out);

#include "refs.h"
static int exclude_promisor_objects;
	if (a->hash < b->hash)
	const struct object_entry *b = *(struct object_entry **)_b;
			init_tree_desc(&tree, it->pcache.tree_data, it->pcache.tree_size);
		return 0;
	if (DFS_NUM_STATES > (1 << OE_DFS_STATE_BITS))
	if (unpack_unreachable_expiration) {
			ret = try_delta(n, m, max_depth, &mem_usage);
			pthread_cond_wait(&me->cond, &me->mutex);
/*
		cur->depth = (total_depth--) % (depth + 1);
		/* Mark me as the first child */
	nent->ref = 1;
	wo[(*endp)++] = e;
			if (!warned++)
		OPT_END(),
			    pack_idx_opts.version);
 * As an optimization, we pass out the index position where we would have
			if (!strcmp(line, "--not")) {
				SET_DELTA(entry, base_entry);
		OPT_MAGNITUDE(0, "window-memory", &window_memory_limit,
	hdrlen = encode_in_pack_object_header(header, sizeof(header),
	 * We can however first check whether these options can possible matter;
	progress_unlock();
{

 * more importantly, the bigger file is likely the more recent


				      add_loose_object,
	for (p = get_all_packs(the_repository); p; p = p->next) {
		die(_("unsupported index version %s"), val);
	       !ignore_packed_keep_in_core &&
		warning(_("recursive delta detected for object %s"),
static int try_delta(struct unpacked *trg, struct unpacked *src,
			free(buf);
				/* check_object() decided it for us ... */
			ofs = entry->in_pack_offset - ofs;
{
		if (sz != trg_size)
				sub_size--;
		reused_delta++;
			}

	 * would almost always change with any commit.
		if (entry->type_valid &&
	int lo = 0;
	git_zstream stream;
	 * we need to read and perhaps cache.
		if (p == last_found)
		if (count + 1 < window)
			die(_("object %s inconsistent object length (%"PRIuMAX" vs %"PRIuMAX")"),
	 * recompute and create a different delta.
	if (max_size == 0)
	else
			canonical_size = get_size_from_delta(p, &w_curs, delta_pos);
	if (sparse < 0)
	       (!local || !have_non_local_packs) &&
		for (i = 0; i < p->num_objects; i++) {
		unuse_pack(&w_curs);
			while (dist--) {


			add_family_to_write_order(wo, wo_end, &objects[i]);
	    bitmap_walk_contains(bitmap_git, reuse_packfile_bitmap, oid))
	}
 * The main thread steals half of the work from the worker that has
	SET_DELTA(trg_entry, src_entry);
				 void *data)
		else
			drop_reused_delta(cur);
		to_reuse = usable_delta;
		struct packed_git *p;
	 */


	/* cache delta, if objects are large enough compared to delta size */

		usage_with_options(pack_usage, pack_objects_options);
	/*
	unsigned long mem_usage = 0;
	unsigned int i, wo_end;
	in_pack->array[in_pack->nr].offset = find_pack_entry_one(object->oid.hash, p);
				if (get_oid_hex(line + 10, &oid))
unsigned long oe_get_size_slow(struct packing_data *pack,
			struct strbuf tmpname = STRBUF_INIT;
#define SET_DELTA_EXT(obj, oid) oe_set_delta_ext(&to_pack, obj, oid)
		pthread_cond_signal(&target->cond);
	 * mechanism -- this is for the toplevel node that
	if (written != nr_result)
				    &add_object_entry_from_bitmap);
			ofs_header[i] = ofs & 127;
		      memcmp(name, entry.path, cmplen);
			static int warned = 0;
		e->idx.offset = 1; /* now recurse */
					*found_offset = offset;

#include "pack-bitmap.h"
static int delta_search_threads;
	for (;;) {
		ll_find_deltas(delta_list, n, window+1, depth, &nr_done);
			hashwrite(out, ofs_header + sizeof(ofs_header) - ofs_len, ofs_len);
 *   3. Resetting our delta depth, as we are now a base object.
		 */
		if (reuse_packfile) {
{
	w_curs = NULL;
			die(_("object %s cannot be read"),


	 * We successfully computed this delta once but dropped it for
		return -1;
		}
#include "commit.h"
static pthread_mutex_t cache_mutex;
		src->data = read_object_file(&src_entry->idx.oid, &type, &sz);
		 * to compress it right away.  First because we have to do
			   in_pack.alloc);
	stream.next_in = in;
			     " pack-reused %"PRIu32),
}
						     tmpname.buf, write_bitmap_options);
		if (S_ISDIR(entry.mode)) {
		if (victim) {
	} else if (entry->delta_data) {
	int i, ret, active_threads = 0;
		objects[i].filled = 0;
			 N_("create thin packs")),

	size = write_object(f, e, *offset);
			continue;
			while (ofs >>= 7)
		if (!trg->data)
	if (trg_entry->delta_data) {
		hashwrite(f, header, hdrlen);
		 */
			progress_state = start_progress(_("Compressing objects"),
				 * might be found.  Let's just steal the
			}
	unuse_pack(&w_curs);
		 * otherwise they would become too deep.
	for_each_tag_ref(mark_tagged, NULL);
	 * packing list.
			add_to_order = 0;
				victim = &p[i];

	struct object_entry *src_entry = src->entry;
{
		/* don't use too small segments or no deltas will be found */
		FREE_AND_NULL(n->data);
		unsigned long in_pack_size;
 * just involve blanking out the "delta" field, but we have to deal
 * loose object we find.
	}
#define SET_DELTA(obj, val) oe_set_delta(&to_pack, obj, val)
		    oid_to_hex(&DELTA(entry)->idx.oid));
	buf = use_pack(p, &w_curs, e->in_pack_offset, &avail);
		/* Convert to REF_DELTA if we must... */
		next = DELTA(cur);
		 oe_type(entry) == OBJ_OFS_DELTA)
		 */
	 * more bytes of length.
					die("not an SHA-1 '%s'", line + 10);
		OPT_BOOL(0, "shallow", &shallow,
		ent = NULL;
		len = write_reuse_object(f, entry, limit, usable_delta);
	 */
	if (cache_max_small_delta_size >= (1U << OE_Z_DELTA_BITS)) {
		 * save a lot of time in the non threaded write phase,
	else if (DELTA(entry)->idx.offset)
		tag = (struct tag *)tag->tagged;
		unuse_pack(&w_curs);
	if (sizediff >= max_size)
				/*
				if (want != -1)
	e->idx.offset = *offset;
	uint32_t i;
				continue;
		}
		pthread_mutex_unlock(&target->mutex);
		buf = use_pack(p, &w_curs, entry->in_pack_offset, &avail);
	struct object_info oi = OBJECT_INFO_INIT;
			size = do_compress(&entry->delta_data, DELTA_SIZE(entry));
 * becomes 1.


		cur->dfs_state = DFS_ACTIVE;
	while (pos < reuse_packfile_bitmap->word_alloc &&
#include "delta.h"
	 * it, we will still save the transfer cost, as we already know
	it->next = pbase_tree;
	add_extra_kept_packs(&keep_pack_list);
		OPT_SET_INT('q', "quiet", &progress,
	}
{
		nent = ent;
{
			*idx = oe->delta_sibling_idx;

			 N_("include tag objects that refer to objects to be packed")),
		hashwrite(f, dheader + pos, sizeof(dheader) - pos);
					error(_("delta base offset overflow in pack for %s"),
	max_size = (uint64_t)max_size * (max_depth - src->depth) /

	offset = entry->in_pack_offset;
	if (!pack_to_stdout)
static void add_pbase_object(struct tree_desc *tree,
	cleanup_threaded_search();
		if (add_unseen_recent_objects_to_traversal(&revs,
	    obj_is_packed(&peeled)) /* object packed? */
		/*
		 * Move the best delta base up in the window, after the
{
				      const char *arg, int unset)
							   OBJ_OFS_DELTA, size);
static void prepare_pack(int window, int depth)
		if (entry)
	if (!a_in_pack && !b_in_pack)
}
			dheader[--pos] = 128 | (--ofs & 127);
		if (pack_idx_opts.version > 2)
		return 0;
	return a->in_pack_offset < b->in_pack_offset ? -1 :
}

		traverse_commit_list(&revs, record_recent_commit,

		if (DELTA_CHILD(e)) {
	 */
		datalen = write_large_blob_data(st, f, &entry->idx.oid);
		in = use_pack(p, w_curs, offset, &stream.avail_in);
	datalen -= entry->in_pack_header_size;
	unsigned char fakebuf[4096], *in;
	free(sorted_by_offset);
 * we are going to reuse the existing object data as is.  make

static int window = 10;
};
	for (m = get_multi_pack_index(the_repository); m; m = m->next) {
{
 */
		 */
	 * When asked to do --local (do not include an object that appears in a
	 * our "excluded" list).
	struct pbase_tree *next;
		struct object_id oid;
		 * the last chain (i.e., the one containing entry) will contain
	if (allow_ofs_delta)
	}
 * to our packing list. If so, we can skip. However, if we are
	unsigned *processed;
		active_threads++;
				return want;
	oi.sizep = &size;
		unsigned nr_done = 0;

	}
	unsigned long size, base_size, delta_size;

	}
	int rev_list_index = 0;
		entry->in_pack_offset = found_offset;

			    the_repository);
static int incremental;
				bitmap_writer_finish(written_list, nr_written,
	return len;
/*
	}
		free(array[i].data);
					warning(_("object %s cannot be read"),
		max_layers = compute_pack_layers(&to_pack);
	written_list[nr_written++] = &e->idx;
static unsigned long max_delta_cache_size = DEFAULT_DELTA_CACHE_SIZE;
	cleanup_preferred_base();

					 object_type(entry.mode),
		 * E.g., We may see a partial loop like:
					    written_list, nr_written,
		 * condition because the main thread may have set it to 1
/*
	base_buf = read_object_file(&DELTA(entry)->idx.oid, &type,
			int window, int depth, unsigned *processed)
		if (delta_size == DELTA_SIZE(trg_entry) &&
	write_pack_file();
		hashwrite(f, header, hdrlen);
{
	entry->hash = hash;
				if (!revidx)
		die(_("revision walk setup failed"));
		written_delta++;
	git_zstream stream;
	}
			e = DELTA_SIBLING(e);
			 * to our count.

			int downlen = name_cmp_len(down);
	/* Partition the work amongst work threads. */
	 * an extra "next" pointer to keep going after we reset cur->delta.
	for (i = 0; i < ARRAY_SIZE(pbase_tree_cache); i++) {
	memset(&in_pack, 0, sizeof(in_pack));
			for (i = 0; !target && i < delta_search_threads; i++)

	}
		struct pack_window **w_curs,
	prepare_packing_data(the_repository, &to_pack);
	 * The first chunk starts at zero, so we can't have gone below
	}
		OPT_BOOL(0, "thin", &thin,
			      N_("include objects reachable from any reference"),
 * blind reuse of what we have on disk.
				 * so many objects that no hash boundary
		return 0;

		struct object_entry *entry = to_pack.objects + i;
			write_bitmap_options &= ~BITMAP_OPT_HASH_CACHE;
			if (oe_type(entry) < 0) {
		 * unlike ignore_packed_keep_on_disk above, we do not
}
			if (!(o->flags & OBJECT_ADDED))

				c = buf[used_0++];
	pthread_t thread;

					  get_packed_git_mru(the_repository));
	while (child) {
				cache_lock();
static void record_recent_commit(struct commit *commit, void *data)
	}
		dheader[pos] = ofs & 127;

	if (pack_size_limit && pack_size_limit < 1024*1024) {
				    oid_to_hex(&entry->idx.oid));
		return 0;
			 ((0 <= available_ix) &&
		die(_("pack too large for current definition of off_t"));

			last_found = p;
	assert(lo);
	if (nr_result) {
	if (!check)
		/*
	}
	return 0;
		    oe_type(&objects[i]) != OBJ_TAG)
		 * Mark ourselves as active and see if the next step causes

	uint32_t i = 0, j;
		OPT_BOOL(0, "honor-pack-keep", &ignore_packed_keep_on_disk,
	struct delta_index *index;
	return 1;
			      1, PARSE_OPT_NONEG),
		usable_delta = 1;	/* base already exists in this pack */
	add_object_entry(oid, type, "", 0);

	off_t offset, next, cur;
);
			o->flags |= OBJECT_ADDED;
		 * with oid_object_info() to find about the object type
 * circular deltas.
 */
		}
		if (avail > len)
	/*
		unsigned len;
			const uint32_t tail = (idx + window - count) % window;
			SET_DELTA(e, NULL);
	struct object_id oid;
		compute_layer_order(wo, &wo_end);
 * chunk that contains it (which implicitly ends at the start
}
	 */
			}
	struct object *object;
	}
		return;
	else if (oe_type(entry) != entry->in_pack_type)
		hashwrite(f, dheader + pos, sizeof(dheader) - pos);

	if (!strcmp(arg, "error")) {
		 * this _before_ we loop, because it impacts where we make the

{
static int sparse;
	return -lo-1;

	if (use_delta_islands) {
	 */
		list_size -= sub_size;
					int flags, uint32_t name_hash,
	in_pack->array[in_pack->nr].object = object;
			    oid_to_hex(&trg_entry->idx.oid));
		pthread_cond_init(&p[i].cond, NULL);
	type = unpack_object_header(reuse_packfile, w_curs, &cur, &size);

		ref_depth = trg->depth;
	}
}
	revidx = find_pack_revindex(p, offset);
		progress_unlock();
	} else {
			add_pbase_object(&sub, down, downlen, fullname);
 * Return 1 iff the object specified by "delta" can be sent
}
	uint32_t i;
		stream.avail_in = readlen;
			die(_("object %s inconsistent object length (%"PRIuMAX" vs %"PRIuMAX")"),
	void *data;
}
 * by size, so that we see progressively smaller and smaller files.

		unsigned sub_size = 0;
			   reuse_packfile_objects);
		       void *cb_data)
	reset_pack_idx_option(&pack_idx_opts);
			find_reused_offset(base_offset);
				bitmap_writer_reuse_bitmaps(&to_pack);
			SET_DELTA_SIZE(entry, in_pack_size);
static int thin;
		OPT_BOOL(0, "include-tag", &include_tag,
		return 0;
			entry->in_pack_header_size = used;
}


	if (delta_search_threads <= 1) {
		if (readlen == 0) {
		arg_missing_action = MA_ALLOW_PROMISOR;
		if (oe_type(&objects[i]) != OBJ_TREE)
 * few lines later when we want to add the new entry.
				/* done- we hit our original root node */
	if (delta_size < cache_max_small_delta_size)
	memset(&stream, 0, sizeof(stream));
				die("BUG: fgets returned NULL, not EOF, not error!");
		return 1;

	struct thread_params *p;
			} else {
	offset = reuse_packfile->revindex[pos].offset;
		OPT_INTEGER(0, "compression", &pack_compression_level,
#include "pack.h"
	}
	for (it = pbase_tree; it; it = it->next) {
	for (i = last_untagged; i < to_pack.nr_objects; i++) {
		 */
			(a->in_pack_offset > b->in_pack_offset);
		hashwrite(f, buf, datalen);
		return;
static int keep_unreachable, unpack_unreachable, include_tag;
			assert(pack_to_stdout);
	 * The object header is a byte of 'type' followed by zero or
	else if (DELTA(entry))
				      struct object_entry *e)
					return want;
			victim->list_size -= sub_size;

		 */
		if (limit && hdrlen + hashsz + datalen + hashsz >= limit) {

	}
	unsigned int m = n;
}


			    delta_search_threads);
	return m;
		while ((stream.avail_in || readlen == 0) &&
		display_progress(progress_state, written);
	/* avoid filesystem trashing with loose objects */
		struct object_entry *entry;
	for (; write_layer < max_layers; ++write_layer)
	read_replace_refs = 0;
					*found_pack = p;
	    !peel_ref(path, &peeled)    && /* peelable? */

 * that can resolve SHA1s to their position in the array.
		add_tag_chain(oid);
static unsigned int check_delta_limit(struct object_entry *me, unsigned int n)
		OPT_INTEGER(0, "threads", &delta_search_threads,
		if (!src->data) {
				write_bitmap_index = 0;
static off_t write_reuse_object(struct hashfile *f, struct object_entry *entry,
		{ OPTION_CALLBACK, 0, "unpack-unreachable", NULL, N_("time"),
		OPT_BOOL(0, "sparse", &sparse,
			}
	if (local) {
}
static struct oid_array recent_objects;
 * Objects we are going to pack are collected in the `to_pack` structure.
			    (uintmax_t)trg_size);


/* Return 0 if we will bust the pack-size limit */
}
			continue;
		return 1;
			available_ix = my_ix;
	 * If we're locally repacking then we need to be doubly careful

		 * Since we are iterating towards decreasing depth, we need to
}
static int pbase_tree_cache_ix(const struct object_id *oid)
			(1U << OE_Z_DELTA_BITS) - 1);
			if (!tree)
				 */
	struct in_pack_object *b = (struct in_pack_object *)b_;
/*
		return 0;
					 struct pack_window **w_curs)
struct in_pack {

			 * younger objects.  So if we are creating multiple
	off_t difference;
/*
	while (*idx) {
		 * and dealt with in prepare_pack().
		error(_("bad packed object CRC for %s"),
		}
	struct object_entry *objects = to_pack.objects;
	/* This is a phony "cache" entry; we are not
		OPT_BOOL(0, "delta-islands", &use_delta_islands,
				       const char *arg, int unset)
		ent = packlist_find(&to_pack, &obj->oid);
	}
}


		 * want to unset "local" based on looking at packs, as
		return 0;
		OPT_BOOL(0, "local", &local,
			BUG("confusing delta dfs state in second pass: %d",
	}
				list_move(&p->mru,
		if (oe_type(entry)) {
			while (c & 128) {

				off_t found_offset)
						to_pack.nr_objects);
	src_size = SIZE(src_entry);
		       mem_usage > window_memory_limit &&
	}
	oid_array_append(&recent_objects, &commit->object.oid);
	if (type == OBJ_OFS_DELTA) {
	if (ATTR_FALSE(check->items[0].value))
		    oid_to_hex(&e->idx.oid));
	if (progress > pack_to_stdout)
	/* Load data if not already done */
		if (entry->delta_data && !pack_to_stdout) {
	 * pack we borrow from elsewhere) or --honor-pack-keep (do not include
		to_reuse = 0;	/* can't reuse what we don't have */
			else if (ret > 0)


	 * packfile minus "original". */
			if (!sub_size) {
	const struct object_entry *b = *(struct object_entry **)_b;
	}
 * Compare the objects in the offset order, in order to emulate the
			      1, PARSE_OPT_NONEG),
		use_bitmap_index = 0;
		 *
 */
			display_progress(progress_state, *processed);
				struct packed_git *found_pack,

	 * And then all the trees.
		OPT_BOOL(0, "delta-base-offset", &allow_ofs_delta,
	}
	 */
	cache_lock();
		die(_("unable to read %s"), oid_to_hex(&entry->idx.oid));
		find_deltas(list, &list_size, window, depth, processed);
	return 0;


	}
	 * need to clear the active flags and set the depth fields as

			sub_size = victim->remaining / 2;
					if (!is_pack_valid(p))
	unsigned int i, last_untagged;
	array = xcalloc(window, sizeof(struct unpacked));
static struct packed_git *reuse_packfile;
		else

	struct object_entry **sorted_by_offset;
	struct object_id oid;

		add_objects_in_unpacked_packs();


static struct pbase_tree {
		}
{
				use_bitmap_index = 0;
		 * objects that depend on the current object into account
}
		add_object_entry(&tag->object.oid, OBJ_TAG, NULL, 0);
			depth, (1 << OE_DEPTH_BITS) - 1);
	return 0;
static uint32_t reuse_packfile_objects;
		 * pack file, but the transfer will still take place.
		delta_search_threads = online_cpus();
			if (write_bitmap_index) {
		delta_list[n++] = entry;
	 * there.
		add_to_write_order(wo, wo_end, &objects[i]);
		if (have_base &&
	if (pos < done_pbase_paths_num)
	if (a_size < b_size)
	int rev_list_unpacked = 0, rev_list_all = 0, rev_list_reflog = 0;
	if (use_delta_islands)
	if (nr_deltas && n > 1) {
			stream.avail_out = sizeof(obuf);
		  N_("unpack unreachable objects newer than <time>"),
static unsigned long write_large_blob_data(struct git_istream *st, struct hashfile *f,
		off_t base_offset;

				int no_try_delta,
	 */
						   &type,
	if (type < 0) {
		/*
		cmp = tree_entry_len(&entry) != cmplen ? 1 :
		for (p = get_all_packs(the_repository); p; p = p->next) {
}
struct pbase_tree_cache {
{
 * The main object list is split into smaller lists, each is handed to
	     cur = DELTA(cur), total_depth++) {
			if (reuse_delta && !entry->preferred_base) {
	return oid->hash[0] % ARRAY_SIZE(pbase_tree_cache);
		return 0;
		return -1;
	}
	WRITE_ONE_RECURSIVE = 2 /* already scheduled to be written */
static int have_duplicate_entry(const struct object_id *oid,
			int dst = best_base;
			    !loosened_object_can_be_discarded(&oid, p->mtime))
	void *buf;

	/* apply size limit if limited packsize and not first object */
	/*
		off_t offset,
	add_object_entry(&obj->oid, obj->type, name, 0);
	if (!size) {

}
			    me->window, me->depth, me->processed);
	unsigned depth;
	struct setup_revision_opt s_r_opt = {
	base = packlist_find(&to_pack, base_oid);
		} else {
				if (!*found_pack) {

static uint32_t write_layer;
static struct progress *progress_state;
			sizeof(struct pack_header), to_write);

				if (!warned++)
				uint32_t hash,
		cache_max_small_delta_size = (1U << OE_Z_DELTA_BITS) - 1;
	/* Let's not bust the allowed depth. */
		/* if we made n a delta, and if n is already at max
		trg_entry->delta_data = xrealloc(delta_buf, delta_size);
	do {
			} else if (!last_mtime) {

}
	if (DELTA(e)) {
	while (lo < hi) {
			if (write_bitmap_index != WRITE_BITMAP_QUIET)
		die(_("wrote %"PRIu32" objects while expecting %"PRIu32),
 * Drop an on-disk delta we were planning to reuse. Naively, this would
	int i;
	if (DELTA(trg_entry)) {
		   done_pbase_paths_alloc);
 */
		if (!sub_size) {
	unsigned long size, datalen;
			    N_("maximum length of delta chain allowed in the resulting pack")),
			 */
static void show_commit(struct commit *commit, void *data)
		if (limit && hdrlen + datalen + hashsz >= limit) {
	 */
			warning(_("no threads support, ignoring %s"), k);
			struct tree_desc tree;
			die(_("bad revision '%s'"), line);
			  off_t write_offset)
		}
				e = DELTA(e);
		}
		const int island_cmp = island_delta_cmp(&a->idx.oid, &b->idx.oid);
	int ref;

		}

		}
			tree = pbase_tree_get(&entry.oid);
	if ((src_size >> 20) + (trg_size >> 21) > (delta_size >> 10))
	}
			      N_("limit pack window by memory in addition to object limit")),
		 * Bad object type is checked in prepare_pack().  This is
	pthread_mutex_destroy(&progress_mutex);
	void *delta_buf;
static int num_preferred_base;
		use_internal_rev_list = 1;
			find_pack_entry_one(oid->hash, p)) {
	it->pcache.tree_data = data;
	if (pack_to_stdout || !rev_list_all)
	}
		return 0;
				       struct object_entry *e,
	int usable_delta, to_reuse;
}
		 * encoding of the relative offset for the delta
	if (!reuse_object)
}
	struct object_entry **write_order;
		argv_array_push(&rp, "--unpacked");

	/* We need to either cache or return a throwaway copy */
		cache->ref--;
	 * your object will be found at your index or within a few
				break;

		warning(_("minimum pack size limit is 1 MiB"));
			write_reused_pack(f);
		/* offset is non zero if object is written already. */
 * being asked to excludei t, but the previous mention was to include
{
				warning(_("suboptimal pack - out of memory"));
	N_("git pack-objects [<options>...] <base-name> [< <ref-list> | < <object-list>]"),

		argc--;
		if (!HAVE_THREADS && delta_search_threads != 1) {
				 */
				delta_cache_size += entry->z_delta_size;

		 bitmap_walk_contains(bitmap_git, reuse_packfile_bitmap, oid));
			die(_("inconsistency with delta count"));

struct in_pack_object {
		cur->dfs_state = DFS_DONE;
static void write_reused_pack(struct hashfile *f)
		packing_data_unlock(&to_pack);
	int use_internal_rev_list = 0;
			drop_reused_delta(cur);
	while (fgets(line, sizeof(line), stdin) != NULL) {
	struct pbase_tree_cache *ent, *nent;
	for_each_loose_file_in_objdir(get_object_directory(),

			int base_pos = find_revindex_position(reuse_packfile, base_offset);
		p[i].remaining = sub_size;

		struct object_entry *entry = sorted_by_offset[i];
	off_t offset;
	if (filter_options.choice) {

	struct packed_git *p;

static int pbase_tree_cache_ix_incr(int ix)
		    oid_object_info(the_repository, &entry->idx.oid, &canonical_size));
		to_reuse = 0;	/* pack has delta which is unusable */
 * return the size of the delta data).
static int depth = 50;
		else
			BUG("confusing delta dfs state in first pass: %d",
 * relative position in the original packfile and the generated
		QSORT(delta_list, n, type_size_sort);

		 * (depth + 1) entries (i.e., depth deltas plus one base), and
static pthread_mutex_t progress_mutex;
	}
			if (stat(pack_tmp_name, &st) < 0) {
	if (exclude) {
				 * Those objects are not included in the
	return packlist_find(&to_pack, oid) ||
				ofs_header[--i] = 128 | (--ofs & 127);
	cur = offset;
{
	}
	int available_ix = -1;
	 * the other side has it and we won't send src_entry at all.
			dheader[--pos] = 128 | (--ofs & 127);
 */
			add_object_entry(&entry.oid,
 */
	}
	 * with its work, we steal half of the remaining work from the
	if (unpack_unreachable)
				/* we're on the right side of a subtree, keep
#include "list-objects.h"
	return delta_buf;
	argc = parse_options(argc, argv, prefix, pack_objects_options,


		else if (((available_ix < 0) && (!ent || !ent->ref)) ||
		 * We should have a chain of zero or more ACTIVE states down to

		return 0;
	if (!strcmp(k, "pack.windowmemory")) {
	int cmp;

				break;
	 */
		OPT_SET_INT(0, "progress", &progress,
		      oid_to_hex(&entry->idx.oid));
#include "object.h"
			die(_("cannot use --filter without --stdout"));

		}
static void write_pack_file(void)
		delta_cache_size -= DELTA_SIZE(trg_entry);
					have_base = 1;
			continue;
	for (cur = entry, total_depth = 0;
			continue;
	 * However, even if this pack does not satisfy the criteria, we need to
	/*
	} else {
		return 0;

			    the_repository);
				bitmap_writer_set_checksum(oid.hash);
static int mark_tagged(const char *path, const struct object_id *oid, int flag,
	struct object_entry *entry;
			      N_("include objects referred to by the index"),

#include "tree.h"
		hashwrite(f, header, hdrlen);
	if (!data)
		ent = pbase_tree_cache[available_ix];
 * that cause us to hit a cycle (as determined by the DFS state flags in
#define SIZE(obj) oe_size(&to_pack, obj)
	}

		packing_data_lock(&to_pack);
		hashwrite(f, DELTA(entry)->idx.oid.hash, hashsz);
			 N_("reuse existing objects")),
				*found_pack = p;
			display_progress(progress_state, ++written);
		struct packed_git *p = IN_PACK(entry);
	}
					    timestamp_t mtime)
	 */
			fixup_pack_header_footer(fd, oid.hash, pack_tmp_name,

	record_reused_object(offset, offset - hashfile_total(out));
		/*
	else
			    void *data)
		return WRITE_ONE_BREAK;
	 */
static struct bitmap *reuse_packfile_bitmap;
	struct packed_git *p;
	};
	free(written_list);
			if (ret < 0)
	in_pack->nr++;
static uint32_t nr_result, nr_written, nr_seen;
		for (offset = 0; offset < BITS_IN_EWORD; ++offset) {
{
	int temporary;
	if (!strcmp(k, "pack.threads")) {
#include "config.h"
#define DELTA_SIZE(obj) oe_delta_size(&to_pack, obj)
 * most work left to hand it to the idle worker.
		want = want_found_object(exclude, *found_pack);
					   const struct object_id *oid)
				register_shallow(the_repository, &oid);

	}
		REALLOC_ARRAY(indexed_commits, indexed_commits_alloc);
	int save_warning;
	}
	struct object_id peeled;
		for (;;) {
		off_t ofs = entry->idx.offset - DELTA(entry)->idx.offset;
		add_unreachable_loose_objects();
		}
			e->idx.offset = recursing;

			if (oe_type(entry) < OBJ_COMMIT || oe_type(entry) > OBJ_BLOB)
	if (unpack_unreachable || keep_unreachable || pack_loose_unreachable)

		it = tmp->next;
		else
	}
			offset = *found_offset;
	 */
		return;

			if (size < (1U << OE_Z_DELTA_BITS)) {
			add_pbase_object(&tree, name, cmplen, name);
 * less susceptible to be accessed often.
}
		ssize_t readlen;
			}
					struct packed_git *pack, off_t offset)
	 * first before writing a deltified object" recursion.
		argv_array_push(&rp, "--all");
	delta_buf = create_delta(src->index, trg->data, trg_size, &delta_size, max_size);
 * Access to struct object_entry is unprotected since each thread owns
		if (!in_same_island(&delta->idx.oid, &base->idx.oid))

 * A reused set of objects. All objects in a chunk have the same
static int option_parse_index_version(const struct option *opt,
	off_t original;
		*base_out = NULL;
 *
{
	enum object_type type = oe_type(entry);
			      N_("write a bitmap index if possible"),

}
			break;
	struct pbase_tree_cache pcache;
 * and its offset in these variables.
#define progress_unlock()	pthread_mutex_unlock(&progress_mutex)
 * so, then *base_out will point to the entry in our packing

		die(_("--keep-unreachable and --unpack-unreachable are incompatible"));
		 * But only if not writing to stdout, since in that case

	free(buf);
	n->depth = 0;
			if (st)
			finalize_hashfile(f, oid.hash, CSUM_HASH_IN_STREAM | CSUM_CLOSE);
	if (!pack_to_stdout)
 * That's because we prefer deltas to be from the bigger file

			continue;
			(*processed)++;
	WRITE_BITMAP_QUIET,
	add_descendants_to_write_order(wo, endp, root);
	return allow_pack_reuse &&
		  PARSE_OPT_NONEG, option_parse_index_version },

	while (lo < hi) {
				offset = *found_offset;



		if (!tag || parse_tag(tag) || !tag->tagged)
static int want_object_in_pack(const struct object_id *oid,

		entry->preferred_base = 1;

			nr_deltas++;
	 */
		if (open_pack_index(p))
			if (DELTA_SIBLING(e)) {
			die(_("unable to get size of %s"),
	show_object(obj, name, data);
	struct packed_git *p = IN_PACK(entry);

	}
	free_delta_index(n->index);
	 * src_entry that is marked as the preferred_base should always
	}
			     pack_usage, 0);
		progress_lock();
		/*
	if (have_duplicate_entry(oid, 0))
		to_reuse = 0;	/* explicit */
#include "list.h"
		if (!allow_ofs_delta) {
		hashwrite(f, header, hdrlen);
		p[i].working = 1;
			return ent;
	if (!want_object_in_pack(oid, 0, &pack, &offset))
	if (!unpack_unreachable_expiration)
			entry->tagged = 1;
		} else {
	 * from now on in order to make sure no stealth corruption gets
		size = DELTA_SIZE(entry);
static int obj_is_packed(const struct object_id *oid)

	const unsigned long a_size = SIZE(a);
	add_preferred_base(&commit->object.oid);
	it->pcache.tree_size = size;
}
		/*
{
			idx = &oe->delta_sibling_idx;
		}
	ALLOC_ARRAY(delta_list, to_pack.nr_objects);
	else if (pack_size_limit <= write_offset)
	unsigned int alloc;
		limit = 1;
{
		if (pack_to_stdout) {
	    !reuse_partial_packfile_from_bitmap(
{
		return 1;
static int pack_options_allow_reuse(void)
	if (reuse_delta && IN_PACK(trg_entry) &&
		progress_lock();


			delta_pos = entry->in_pack_offset + entry->in_pack_header_size;
	}
				return 0;
		write_bitmap_index = 0;
};
	repo_init_revisions(the_repository, &revs, NULL);
static struct pack_idx_entry **written_list;

	/* make sure off_t is sufficiently large not to wrap */
	wo_end = 0;
	stop_progress(&progress_state);
		return -1;
	 * If we already know the pack object lives in, start checks from that
		if (!pbase_tree_cache[i])
		 * is a bug.
	oidcpy(&it->pcache.oid, &tree_oid);
	unsigned long size;
		struct object_entry *ent;

#include "midx.h"
			die(_("cannot open pack index"));
			    (!victim || victim->remaining < p[i].remaining))
	add_preferred_base_object(name);
		cache_unlock();
	     (ignore_packed_keep_in_core && p->pack_keep_in_core)))
		}
 * Mutex and conditional variable can't be statically-initialized on Windows.
			while (sub_size && list[0]->hash &&
				/*
			die(_("not a rev '%s'"), line);
			if (other_idx >= window)
	int pos = done_pbase_path_pos(hash);
		return WRITE_ONE_SKIP;

 * from, that is passed in *found_pack and *found_offset; otherwise this

		if (limit && hdrlen + sizeof(dheader) - pos + datalen + hashsz >= limit) {
		target->remaining = sub_size;

			}
	struct packed_git *found_pack = NULL;
	unsigned char header[MAX_PACK_OBJECT_HEADER],
	     cur;
	if (pack_to_stdout && pack_size_limit)

		limit = 0;
	git_deflate_init(&stream, pack_compression_level);
/*
	if (!exclude && local && has_loose_object_nonlocal(oid))
	struct object_entry *trg_entry = trg->entry;
}
			    oid_to_hex(oid));
			hi = mi;
	delta_buf = diff_delta(base_buf, base_size,
static struct bitmap_index *bitmap_git;
	if (!names->nr)
		entry->idx.crc32 = crc32_end(f);
			return;
		case WRITE_ONE_RECURSIVE:
	data = read_object_file(oid, &type, &size);
#include "pack-revindex.h"
		    oe_size_greater_than(&to_pack, entry, big_file_threshold) &&
	if (!buf)
		 * the chain into two or more smaller chains that don't exceed
			init_tree_desc(&sub, tree->tree_data, tree->tree_size);
		default:
	while (1) {
	}
				     threaded_find_deltas, &p[i]);
	trace2_region_leave("pack-objects", "enumerate-objects",
#define cache_unlock()		pthread_mutex_unlock(&cache_mutex)
{



	struct list_head *pos;
 * Binary search to find the chunk that "where" is in. Note
		}
		 * whatever entries are left over, namely
{
		reused_delta++;
	if (available_ix < 0)
			unsigned char ofs_header[10];

}
	NULL
			struct object_entry *e = write_order[i];
			if (!e) {

		check_object(entry);
	unsigned char *buf;
			if (ofs <= 0 || ofs >= entry->in_pack_offset) {
			}
			if (write_one(f, e, &offset) == WRITE_ONE_BREAK)
	if (oe_type(trg_entry) != oe_type(src_entry))
		}

	else

		if (!p[i].list_size)
	return pos;

				if (!is_pack_valid(p))
	 * recency order.
			if (!packlist_find(&to_pack, &oid) &&
	 * And now that we've gone all the way to the bottom of the chain, we

	trace2_region_enter("pack-objects", "write-pack-file", the_repository);
	if (!strcmp(k, "pack.window")) {
	}
		if (limit && hdrlen + hashsz + datalen + hashsz >= limit) {
		 *
	if (!p)
			continue;
	if (argc) {
			die(_("deflate error (%d)"), zret);
	while (tree_entry(tree,&entry)) {
	int depth;

	done_pbase_paths_num = done_pbase_paths_alloc = 0;
	 * Otherwise, reachability bitmaps may tell us if the receiver has it,
		   reused_chunks_alloc);
static void loosen_unused_packed_objects(void)
	 * an object that appears in a pack marked with .keep), finding a pack
		add_to_write_order(wo, wo_end, &objects[i]);
	struct object_entry *entry;
static int get_object_list_from_bitmap(struct rev_info *revs)
		/* The pack is missing an object, so it will not have closure */
	 * should validate everything they get anyway so no need to incur
static int progress = 1;


		pack_size_limit = pack_size_limit_cfg;
	unsigned remaining;
 *
{
			reuse_packfile_bitmap->words[pos] == (eword_t)~0)
static void compute_layer_order(struct object_entry **wo, unsigned int *wo_end)
			p->pack_keep_in_core = 1;
	if (type != OBJ_TREE) {
	}
			die(_("invalid number of threads specified (%d)"),


	WRITE_ONE_WRITTEN = 1, /* normal */
		entry->z_delta_size = 0;
			if (p->pack_local && p->pack_keep)
static void show_object(struct object *obj, const char *name, void *data)
	struct in_pack_object *a = (struct in_pack_object *)a_;
			/* add this node... */
	SET_SIZE(entry, size);
	int cmplen;
				goto give_up;
	p = oe_in_pack(pack, e);
		 */
			    N_("write a bitmap index together with the pack index"),
	}
#include "trace2.h"
		OPT_BOOL(0, "all-progress-implied",
		return -1;


		 * If we decided to cache the delta data, then it is best
{
		for (j = 0; j < nr_written; j++) {
static void show_edge(struct commit *commit)
			return;
				       off_t *offset)
			sub_size = 0;
			 * final object type is.  Let's extract the actual

	if (!has_object_file(&obj->oid))
 * add_object_entry will weed out duplicates, so we just add every
		/*
/*
 * objects found in non-local stores if the "--local" option was used).
	entry = packlist_find(&to_pack, oid);
}
	 * even if it was buried too deep in history to make it into the
	unuse_pack(&w_curs);
		pack_idx_opts.version = git_config_int(k, v);
				close_istream(st);
 * one.  The deepest deltas are therefore the oldest objects which are
				delta_cache_size -= DELTA_SIZE(entry);
	if (!strcmp(k, "pack.allowpackreuse")) {
		if (DELTA(cur)->dfs_state == DFS_ACTIVE) {
	if (have_duplicate_entry(oid, exclude))
	struct object_entry *entry;
	copy_pack_data(f, p, &w_curs, offset, datalen);
	if (st) {

		 * us to cycle to another active object. It's important to do
static inline void add_to_write_order(struct object_entry **wo,

				continue;

	uint32_t total_depth;
			if (get_oid_hex(line+1, &oid))
		}
 * When a work thread has completed its work, it sets .working to 0 and
struct thread_params {
static void *get_delta(struct object_entry *entry)
#include "list-objects-filter-options.h"
	for (; i < to_pack.nr_objects; i++) {
	argv_array_push(&rp, "pack-objects");


		cache_max_small_delta_size = git_config_int(k, v);
	 */
		return 1;
		depth = *name ? 1 : 0;
			struct object_id base_oid;
	if (prepare_revision_walk(&revs))
	oid_array_clear(&recent_objects);
static int done_pbase_paths_num;
		return 1;
	git_inflate_end(&stream);
{
#define progress_lock()		pthread_mutex_lock(&progress_mutex)
		if (oe == entry)
	const struct object_entry *a = *(struct object_entry **)_a;
		FREE_AND_NULL(pbase_tree_cache[i]);
		 * possible what the actual type and size for this object is.
			 * order since newer packs are more likely to contain

	stream.next_out = out;
		return 1;
		p[i].list_size = sub_size;
	struct in_pack in_pack;
		return 0;
 *
		p[i].processed = processed;

	int recursing;
			}
{
static void read_object_list_from_stdin(void)
	return 0;
			copy_pack_data(out, reuse_packfile, w_curs, cur, next - cur);
	}
 * Depth value does not matter - find_deltas() will
	enum object_type type;
static size_t write_reused_pack_verbatim(struct hashfile *out,
			}
		enum object_type type;
		 * If so, rewrite it like in fast-import

#define SET_DELTA_SIBLING(obj, val) oe_set_delta_sibling(&to_pack, obj, val)
					goto give_up;
static int check_pbase_path(unsigned hash)
		die(_("bad pack compression level %d"), pack_compression_level);



		warning(_("no threads support, ignoring --threads"));
	}
	void *in, *out;
			} else {
	}
		}
	if (!base_buf)
			OBJ_OFS_DELTA : OBJ_REF_DELTA;
		struct thread_params *target = NULL;
				utb.modtime = --last_mtime;
	if (!pack_to_stdout && thin)
		 */
				 * pack could be created nevertheless.
		copy_pack_data(out, reuse_packfile, w_curs,
			     int cmplen,
		}
		if (git_config_bool(k, v))
	unsigned long size;

	}
	}
		if (open_pack_index(p))
	const struct object_entry *a = *(struct object_entry **)_a;

	/* Start work threads. */
				offset = find_pack_entry_one(oid->hash, p);
	WRITE_ONE_SKIP = -1, /* already written */
			c = buf[used_0++];
			continue;
 */
		}

	if (!strcmp(k, "pack.deltacachelimit")) {

		/*
static int non_empty;
static struct pbase_tree_cache *(pbase_tree_cache[256]);
		/* We do not compute delta to *create* objects we are not
	unsigned long avail;
			die(_("object %s cannot be read"),
			 */
	 * prefer to do this extra check to avoid having to parse the
					      type, entry_size);
/*
	oe_set_type(entry,
		}
	unsigned i;
	}
enum missing_action {
		 * broke. Commits C and D were "lost" from A's chain.
	if (thin && bitmap_has_oid_in_uninteresting(bitmap_git, base_oid)) {
		free(data);
	 * First see if we're already sending the base (or it's explicitly in
	used = unpack_object_header_buffer(buf, avail, &type, &size);
		return 0;
	 *
{
			/* Not a delta hence we've already got all we need. */
	while (active_threads) {
}
		}
	unsigned int nr;
		/* We're recording one chunk, not one object. */
		return 0;
{
			ignore_packed_keep_in_core = 1;
		get_object_list(rp.argc, rp.argv);
static int use_bitmap_index = -1;
	enum object_type type;
}
	enum object_type type;
	unuse_pack(&w_curs);
		int mi = lo + (hi - lo) / 2;
static int allow_pack_reuse = 1;
	if (!trg->data) {
		for (i = 0; i < names->nr; i++)
static int no_try_delta(const char *path)
		return;
 *      either not recorded initially (size) or overwritten with the delta type
		OPT_BOOL(0, "incremental", &incremental,
static unsigned long free_unpacked(struct unpacked *n)
	next = reuse_packfile->revindex[pos + 1].offset;
			 N_("create packs suitable for shallow fetches")),
	if (!num_preferred_base || check_pbase_path(hash))
		fetch_if_missing = 0;
			     const char *name,
	else {


	ALLOC_ARRAY(wo, to_pack.nr_objects);
		return NULL;
		if (S_ISGITLINK(entry.mode))
			   done_pbase_paths_num - pos - 1);
		die(_("unable to parse object header of %s"),
			ignore_packed_keep_on_disk = 0;
		 * as a preferred base.  Doing so can result in a larger
						continue;
		 * make sure no cached delta data remains from a
		hdrlen += hashsz;
	    IN_PACK(trg_entry) == IN_PACK(src_entry) &&
		ret = pthread_create(&p[i].thread, NULL,
			   struct object_entry *delta,
	    !ignore_packed_keep_in_core &&
	struct object_entry *objects = to_pack.objects;
				int exclude,
		fixup = find_reused_offset(offset) -
				strbuf_addf(&tmpname, "%s.bitmap", oid_to_hex(&oid));

 * it, make sure to adjust its flags and tweak our numbers accordingly.
		 */
#include "thread-utils.h"
 * This is filled by get_object_list.
				warning(_(no_closure_warning));

 * If the caller already knows an existing pack it wants to take the object
	if (a_type > b_type)
		 * the network is most likely throttling writes anyway,
 *
	/*
	}

		 * snipping. Since we're snipping into chains of length (depth
	return (st == Z_STREAM_END &&
	unsigned ref_depth;
	off_t offset;
	if (e->type_ != OBJ_OFS_DELTA && e->type_ != OBJ_REF_DELTA) {
 * has stopped working (which is indicated in the .working member of
	/*
	if (a_type < b_type)
	uint32_t i, idx = 0, count = 0;
static int ignore_packed_keep_on_disk;
	if (pack_idx_opts.version > 2)
				die_errno("fgets");
{
	else {
 * because they are either written too recently, or are
				FREE_AND_NULL(entry->delta_data);
				e = DELTA_SIBLING(e);
			return;

static unsigned long cache_max_small_delta_size = 1000;
				other_idx -= window;
				struct revindex_entry *revidx;
		 * If we instead cut D->B, then the depth of A is correct at 3.
		 */
{
		switch (write_one(f, DELTA(e), offset)) {
			} else {
			die(_("unable to read %s"), oid_to_hex(oid));
			pthread_mutex_destroy(&target->mutex);
		argv_array_push(&rp, "--topo-order");
	}
	traverse_bitmap_commit_list(bitmap_git, revs,
			active_threads--;
		/* Otherwise see if we need to rewrite the offset... */
		return 0;
		freed_mem += SIZE(n->entry);
		 * it anyway, and doing it here while we're threaded will
		}
		if (nr_done != nr_deltas)
			/*
		return 1;
#include "dir.h"
	traverse_commit_list_filtered(&filter_options, &revs,
			if (target)

		type = (allow_ofs_delta && DELTA(entry)->idx.offset) ?
			SET_SIZE(entry, canonical_size);
	while (it) {
		 *
	 *
}

				return 0;
		while (!me->data_ready)
				warning_errno(_("failed to stat %s"), pack_tmp_name);
	}
		 * as well as allow for caching more deltas within
	enum object_type type;
	if (!strcmp(k, "pack.deltacachesize")) {


		else
	return NULL;

		use_internal_rev_list = 1;
	struct tag *tag;
			return 1;
	enum object_type type = oid_object_info(the_repository, oid, NULL);

		st = git_inflate(&stream, Z_FINISH);
			unuse_pack(&w_curs);
		 * be the first base object to be attempted next.
	while (len) {

	/*
		/* evict and reuse */
#define cache_lock()		pthread_mutex_lock(&cache_mutex)
	free(p);
		 * the same cache size limit.
		for (i = 0; i < in_pack.nr; i++) {
 */

		while (--j > 0) {
			 N_("use a bitmap index if available to speed up counting objects")),
		if (used == 0)
			copy_pack_data(out, reuse_packfile, w_curs, cur, next - cur);
static void *threaded_find_deltas(void *arg)
	if (progress > pack_to_stdout)

			offset = hashfile_total(f);
			die(_("revision walk setup failed"));
			     const char *fullname)
	if (!pack_to_stdout)
	struct object_id tree_oid;
	if (rev_list_all) {
		trg_entry->delta_data = NULL;
			display_progress(progress_state, written);
						 nr_written, oid.hash, offset);
			if (max_depth <= 0)
	 */
	if (!(bitmap_git = prepare_bitmap_walk(revs, &filter_options)))
	 * Otherwise, we signal "-1" at the end to tell the caller that we do
 *

{

	assert(arg_missing_action == MA_ALLOW_PROMISOR);
				SET_DELTA_CHILD(base_entry, entry);
	return reused_chunks[lo-1].difference;
				/* ... but pack split may override that */

			off_t offset;
		progress_lock();
			ent->ref++;
	if (!usable_delta) {
{

		OPT_INTEGER(0, "depth", &depth,
	/*
	for (i = 0; i < window; ++i) {
			strbuf_addf(&tmpname, "%s-", base_name);
static unsigned int indexed_commits_nr;
			written_list[j]->offset = (off_t)-1;
 */
	}
		struct object_entry *oe = &to_pack.objects[*idx - 1];
				    oid_to_hex(&entry->idx.oid));
		ALLOC_GROW(in_pack.array,
	if (a_size > b_size)
#include "repository.h"

				die(_("unable to get type of object %s"),
	}
} *pbase_tree;
		if (where < reused_chunks[mi].original)
}

 */

		 * only 1, and our total_depth counter is at 3. The size of the
		       count > 1) {
	const char *val = arg;
 * ahead in the list because they can be stolen and would need
			ofs = c & 127;
	written++;
	else


		*mem_usage += sizeof_delta_index(src->index);
	last_untagged = i;
	if (delta_cacheable(src_size, trg_size, delta_size)) {
	 * be considered, as even if we produce a suboptimal delta against
		 * cut, and thus how our total_depth counter works.
	size_t i = 0;
	/*
	 * This must happen in a second pass, since we rely on the delta
				last_mtime = st.st_mtime;
	else if (pack_compression_level < 0 || pack_compression_level > Z_BEST_COMPRESSION)
		window = git_config_int(k, v);

		if (p == last_found)
}
	if (ignore_packed_keep_on_disk) {
	tag = lookup_tag(the_repository, oid);

			off_t ofs = offset - base_offset - fixup;
				*found_offset = offset;
		{ OPTION_CALLBACK, 0, "missing", NULL, N_("action"),
		} else if (nr_written == nr_remaining) {
			o = lookup_unknown_object(&oid);

	struct pbase_tree *it;
			if (starts_with(line, "--shallow ")) {
	} else if (type == OBJ_REF_DELTA) {
static void find_deltas(struct object_entry **list, unsigned *list_size,
	show_object(obj, name, data);
	 *

		default:
	int working;
	/*
	if (base) {
		unsigned sub_size = list_size / (delta_search_threads - i);



{
	if (pos) {
		 * Determine if this is a delta and if so whether we can
		entry = *list++;
			hi = mi;

		unsigned long avail;
		free_delta_index(array[i].index);


		use_bitmap_index = use_bitmap_index_default;
	}
	if (!delta_buf || delta_size != DELTA_SIZE(entry))

	if (use_delta_islands)
static int name_cmp_len(const char *name)
			    found_pack, found_offset);
 *

	struct object_entry *base;
	for (;;) {
		trace2_region_leave("pack-objects", "prepare-pack",
				       entry->in_pack_offset + used, NULL);
				list++;
 * of the next chunk.
};
	};
			buf = NULL;
		in = use_pack(p, w_curs, offset, &avail);
			break;
	off_t size;
				add_to_write_order(wo, endp, s);
		target->working = 1;
	const unsigned long b_size = SIZE(b);
#define SET_DELTA_SIZE(obj, val) oe_set_delta_size(&to_pack, obj, val)
	if (entry)
	 */
		fetch_if_missing = 0;
	/* if we are deltified, write out base object first. */

		int zret = Z_OK;
	display_progress(progress_state, ++nr_seen);
		 * No choice but to fall back to the recursive delta walk
	if (signed_add_overflows(*offset, size))
#include "list-objects-filter.h"
	if (use_delta_islands)
	pthread_mutex_destroy(&cache_mutex);
			break;
				write_bitmap_index = 0;
			add_preferred_base(&oid);
		 * We break cycles before looping, so an ACTIVE state (or any
	 */
	unsigned char header[MAX_PACK_OBJECT_HEADER],
#define DELTA_SIBLING(obj) oe_delta_sibling(&to_pack, obj)
		pack_idx_opts.off32_limit = strtoul(c+1, &c, 0);
	}
	/* "hard" reasons not to use bitmaps; these just won't work at all */

	    check_pack_crc(p, &w_curs, offset, datalen, revidx->nr)) {
	if (!src->data) {
		}
			continue;
	if (indexed_commits_nr >= indexed_commits_alloc) {
		OPT_SET_INT(0, "all-progress", &progress,
	return git_default_config(k, v, cb);
		 * Cutting B->C breaks the cycle. But now the depth of A is
			target->list = list;
}
		case OBJ_OFS_DELTA:
 */
		while (sub_size && sub_size < list_size &&
			return;
}
	if (include_tag && nr_result)
	}
);
				entry->z_delta_size = size;
		 *
		e->idx.offset = recursing;
	assert(type >= 0);
	unsigned long entry_size = SIZE(entry);
				continue;
	}
	if (n->data) {
				      NULL, NULL, NULL);
		return 0;

			struct packed_git *p = e.p;
	} else {
	if (keep_unreachable)
}
		index_commit_for_bitmap(commit);
			 * We've already seen this object and know it isn't
	 * Make sure delta_sibling is sorted in the original
			want = want_found_object(exclude, p);
	free(base_buf);
		const unsigned int c = check_delta_limit(child, n + 1);
			e = DELTA_CHILD(e);
	int want;
			if (base_entry) {
static void break_delta_chains(struct object_entry *entry)
	}


	 * thread with the largest number of unprocessed objects and give

			break;
	pack_idx_opts.version = strtoul(val, &c, 10);

		 * to permit a missing preferred base object to be ignored
			 N_("read revision arguments from standard input")),
		hdrlen += hashsz;
/*
		if (parse_oid_hex(line, &oid, &p))
			&reuse_packfile_bitmap)) {
		return;
		pos++;
	if (unset) {

		offset = write_pack_header(f, nr_remaining);
		unsigned pos = sizeof(dheader) - 1;
	 * the additional cost here in that case.
	trace2_region_leave("pack-objects", "write-pack-file", the_repository);
				dst = src;
	uint32_t i, nr_deltas;


{
static struct pbase_tree_cache *pbase_tree_get(const struct object_id *oid)
	for (i = 0; i < delta_search_threads; i++) {
		free(delta_buf);
#include "cache.h"
		return -1;
	time_t last_mtime = 0;

		nr_remaining -= nr_written;
	/*
		 * it also covers non-local objects
		      oid_to_hex(&entry->idx.oid));
	if (use_delta_islands) {
		ref_depth = 1;
	if (a->hash > b->hash)
	return size;
		pack_compression_level = Z_DEFAULT_COMPRESSION;
	/*
static int check_pack_inflate(struct packed_git *p,
	it = pbase_tree;
		OPT_BOOL(0, "non-empty", &non_empty,
					 fullname, 1);

		oe_set_type(entry,

	if (found_pack) {
	}
		/*
		return 1;
static void show_object__ma_allow_promisor(struct object *obj, const char *name, void *data)
			return island_cmp;
		/*
			while (e && !DELTA_SIBLING(e)) {
/*
	void *data;
			count++;
		if (!entry->preferred_base)
			 * delta from a pack.  "reuse_delta &&" is implied.
}
	save_commit_buffer = 0;

			max_depth -= check_delta_limit(entry, 0);
				entry->delta_sibling_idx = base_entry->delta_child_idx;
}
 * We actually don't even have to worry about reachability here.
	for (p = get_all_packs(the_repository); p; p = p->next) {

 */
	struct multi_pack_index *m;
	assert(arg_missing_action == MA_ALLOW_ANY);
				      oid_to_hex(&entry->idx.oid));
		add_object_entry(&oid, OBJ_NONE, p + 1, 0);
	else if (entry->z_delta_size)
		return;
		}
static int local;

	pthread_cond_t cond;
#include "tag.h"
	}
	is_repository_shallow(the_repository);
	git_deflate_init(&stream, pack_compression_level);
static const char no_split_warning[] = N_(
#include "reachable.h"
 */
			       unsigned int *endp,
{
	struct packed_git *p;
	 * to omit the object, so we need to check all the packs.

		OPT_PARSE_LIST_OBJECTS_FILTER(&filter_options),

		}
		free(buf);
		if (sub_size < 2*window && i+1 < delta_search_threads)
		}
			      1, PARSE_OPT_NONEG),
	if (!strcmp(k, "pack.writebitmaphashcache")) {

					get_all_packs(the_repository);
	git_inflate_init(&stream);
		use_bitmap_index_default = git_config_bool(k, v);
			hashwrite(out, header, len);
	int window;
				      show_commit, fn_show_object, NULL,

		    src->depth + 1 >= trg->depth) {
		}
	struct object_entry *child = DELTA_CHILD(me);
		/*
	off_t found_offset = 0;
	in = *pptr;
	struct packed_git *p;
		if (sz != src_size)
	uint32_t max_layers = 1;
	data = read_object_with_reference(the_repository, oid,
		struct packed_git *p;
		OPT_SET_INT(0, "keep-true-parents", &grafts_replace_parents,

				cache_unlock();
}
		return 1;
		size = DELTA_SIZE(entry);

static int pack_to_stdout;
	free(cache->tree_data);
	else if (oe_type(entry) == OBJ_REF_DELTA ||
static struct commit **indexed_commits;
static unsigned long write_no_reuse_object(struct hashfile *f, struct object_entry *entry,
	mark_edges_uninteresting(&revs, show_edge, sparse);
	if (write_bitmap_index)

		 */
		return 1;
			int dist = (window + idx - best_base) % window;
	for (i = 0; i < to_pack.nr_objects; i++) {
			mem_usage -= free_unpacked(array + tail);
		for (i = 0; i < p->num_objects; i++) {
	}
		OPT_BOOL(0, "use-bitmap-index", &use_bitmap_index,
	if (entry->type_valid) {
			struct unpacked *m;
		target->data_ready = 1;
						(max_depth - ref_depth + 1);
			    oid_to_hex(&e->idx.oid));
static int have_non_local_packs;

		 */
}
				ofs += 1;
		pthread_cond_signal(&progress_cond);
} write_bitmap_index;
	for (i = 0; i < delta_search_threads; i++) {

	if (trg_size < src_size / 32)
			 N_("output pack to stdout")),
	 * Handle memory allocation outside of the cache
{
			 N_("keep unreachable objects")),

				static int warned = 0;
				mark_in_pack_object(o, p, &in_pack);
	struct rev_info revs;
			offset += ewah_bit_ctz64(word >> offset);
		if (limit && hdrlen + datalen + hashsz >= limit) {
	}
static struct reused_chunk {

{
			continue;
	/* leave ->working 1 so that this doesn't get more work assigned */

		ent = pbase_tree_cache[my_ix];
}
	/*
	return 0;
	}
				revidx = find_pack_revindex(p, ofs);
 * the entries).

 * Store a list of sha1s that are should not be discarded
	for (; i < reuse_packfile_bitmap->word_alloc; ++i) {
			SET_SIZE(entry, in_pack_size);

	const unsigned hashsz = the_hash_algo->rawsz;

		len = write_no_reuse_object(f, entry, limit, usable_delta);
			       const struct object_entry *e)

	if (rev_list_reflog) {
		to_reuse = 1;	/* we have it in-pack undeltified,
		 * fall back to oid_object_info, which may find another copy.
	}
 * function finds if there is any pack that has the object and returns the pack
	 * previously).
	} else {
	if (e->filled || oe_layer(&to_pack, e) != write_layer)
	struct in_pack_object *array;
	MA_ALLOW_ANY,      /* silently allow ALL missing objects */
				oidread(&base_ref,
	int add_to_order = 1;
		}
			return 0;
#include "argv-array.h"
			&reuse_packfile,
			m = c;
		/* the empty string is a root tree, which is depth 0 */
		return;
				      NULL);
			/* all its siblings... */
		struct object_id oid;
			struct tree_desc sub;
			f = hashfd_throughput(1, "<stdout>", progress_state);
							nr_deltas);
/* Protect delta_cache_size */
{
					   unsigned long limit, int usable_delta)
			}
		for_each_ref(add_ref_tag, NULL);
		}
	if (!fn_show_object)
	 * - to produce good pack (with bitmap index not-yet-packed objects are
	int all_progress_implied = 0;
		}
		OPT_SET_INT_F(0, "unpacked", &rev_list_unpacked,


} *reused_chunks;
		 * since non-delta representations could still be reused.
 *   2. Updating our size/type to the non-delta representation. These were
		max_depth = depth;
			continue;
	/*
		}
		datalen = entry->z_delta_size;
		 * And if that fails, the error will be recorded in oe_type(entry)
	if (!ignore_packed_keep_on_disk &&
/*
		display_progress(progress_state, nr_result);
			if (!*found_pack) {
	}
				if (!p[i].working)
			m = array + other_idx;
			    N_("pack compression level")),
static void drop_reused_delta(struct object_entry *entry)
				 * This object is not found, but we

		else {

		me->data_ready = 0;
}
{
		if (idx >= window)
	hdrlen = encode_in_pack_object_header(header, sizeof(header),
				break;
		if (add_to_order) {
	}
	}
	stop_progress(&progress_state);
	entry->no_try_delta = no_try_delta;
 * one worker.
	 * pack - in the usual case when neither --local was given nor .keep files
	struct object_entry *entry = packlist_find(&to_pack, oid);

		SET_SIZE(entry, canonical_size);
}
static void check_object(struct object_entry *entry)
			return 0;
		for (p = get_all_packs(the_repository); p; p = p->next)
		BUG("delta size changed");
	init_threaded_search();
		stream.avail_out = sizeof(fakebuf);
			break;
};
			int fd = finalize_hashfile(f, oid.hash, 0);
	struct git_istream *st = NULL;
			}
	sparse = git_env_bool("GIT_TEST_PACK_SPARSE", -1);
		}
	warn_on_object_refname_ambiguity = save_warning;
				bitmap_writer_select_commits(indexed_commits, indexed_commits_nr, -1);
/*
 */
	return -1;
	}
		if (!len)
	if (exclude)
	reused_chunks_nr++;

	git_deflate_end(&stream);
	for (i = 0; i < to_pack.nr_objects; i++) {
				have_base = 1;
	}
		else if (cur->dfs_state != DFS_ACTIVE)
		stream.next_out = fakebuf;
			 N_("respect islands during delta compression")),
		if (cur->dfs_state != DFS_NONE)
static int reuse_delta = 1, reuse_object = 1;
	}
{

	 * We do not bother to try a delta that we discarded on an
		i = write_reused_pack_verbatim(f, &w_curs);

		datalen = size;
 *   1. Removing ourselves from the delta_sibling linked list.
	if (a->offset < b->offset)

};
	struct pbase_tree *it;
static int reused_chunks_alloc;
		} else {
			p = p->next;
		offset += stream.next_in - in;
};

					   const char *arg, int unset)
			continue;
}
static int add_loose_object(const struct object_id *oid, const char *path,
static void record_recent_object(struct object *obj,

		 * decrement total_depth as we go, and we need to write to the
}
			   "write_pack_file/wrote", nr_result);
				? "--objects-edge-aggressive"
			oe_set_type(entry, entry->in_pack_type);
					continue;
	if (mtime > unpack_unreachable_expiration)
		 * the earlier object did not fit the limit; avoid
			 N_("use OFS_DELTA objects")),


		struct object_id base_ref;
}
		struct pack_window **w_curs,
		used = unpack_object_header_buffer(buf, avail,
	if (!use_internal_rev_list)
		my_ix = available_ix;
		cleanup_threaded_search();
		base_name = argv[0];
		struct unpacked *n = array + idx;
		return -1;
			    cur->dfs_state);
}

static int has_sha1_pack_kept_or_nonlocal(const struct object_id *oid)

	if (st)	/* large blob case, just assume we don't compress well */
	}
static int loosened_object_can_be_discarded(const struct object_id *oid,
 * When adding an object, check whether we have already added it
				 * It is possible for some "paths" to have
			if (!m->entry)
static const char no_closure_warning[] = N_(
		fn_show_object = show_object__ma_allow_any;


static int delta_cacheable(unsigned long src_size, unsigned long trg_size,

			return 0;
		OPT_BOOL(0, "pack-loose-unreachable", &pack_loose_unreachable,
		 * has no bases, or we've already handled them in a previous
				array[dst] = array[src];
	free(cache);
			p = get_all_packs(the_repository);
	/*
		usable_delta = 0;	/* no delta */
	/* The offset of the first object of this chunk in the generated
 *
	for (i = 0; i < to_pack.nr_objects; i++)
		off_t offset;
			 * Packs are runtime accessed in their mtime
				best_base = other_idx;
		return 0;
	unsigned long olen = 0;
static void create_object_entry(const struct object_id *oid,
			nth_packed_object_id(&oid, p, i);
}

			       struct packed_git **found_pack,
	entry->depth = 0;
		}
	create_object_entry(oid, type, pack_name_hash(name),
	if (pack_loose_unreachable)
	save_warning = warn_on_object_refname_ambiguity;

 * found the item, since that saves us from having to look it up again a
		OPT_BOOL(0, "reuse-object", &reuse_object,
	int lo = 0, hi = reused_chunks_nr;
			/* we cannot depend on this one */


				sub_size = victim->remaining / 2;
			idx = 0;
				entry->z_delta_size = 0;
				have_non_local_packs = 1;
		trace2_region_enter("pack-objects", "prepare-pack",
static unsigned long delta_cache_size = 0;

	/* Don't bother doing diffs between different types */
	uint32_t nr_remaining = nr_result;

		     unsigned max_depth, unsigned long *mem_usage)
 *
static void add_objects_in_unpacked_packs(void)
	} else if (type == OBJ_REF_DELTA) {
		unsigned pos = sizeof(dheader) - 1;

	git_check_attr(the_repository->index, path, check);
{

	unsigned char ibuf[1024 * 16];
 * reconstruction (so non-deltas are true object sizes, but deltas
			    oid_to_hex(&src_entry->idx.oid));
		size_t pos = (i * BITS_IN_EWORD);
		 * Deltas with relative base contain an additional
		if (pack_to_stdout)
	struct object_entry *cur, *next;

			unuse_pack(&w_curs);
			goto give_up;
	list_for_each(pos, get_packed_git_mru(the_repository)) {
		/* drop down a level to add left subtree nodes if possible */
	unsigned long tree_size;
#include "builtin.h"
	if (use_bitmap_index < 0)

			}
		if (done_pbase_paths[mi] == hash)

		if (!cur->depth)
	 * "soft" reasons not to use bitmaps - for on-disk repack by default we want

{
	};
		MOVE_ARRAY(done_pbase_paths + pos + 1, done_pbase_paths + pos,
		 * before we get here. In order to be sure that new
		 * If the total_depth is more than depth, then we need to snip
	    trg_entry->in_pack_type != OBJ_OFS_DELTA)
		   done_pbase_paths_num + 1,
		 * other cruft which made its way into the state variable)
		fetch_if_missing = 0;
	}

	pthread_cond_init(&progress_cond, NULL);
			    oid_to_hex(&src_entry->idx.oid), (uintmax_t)sz,
static int want_found_object(int exclude, struct packed_git *p)
			 * part of a cycle. We do need to append its depth
	struct packed_git *p;
		}
			- sizeof(struct pack_header);
	buf = read_object_file(&entry->idx.oid, &type, &size);
			delta_search_threads = 0;
	}
		 * additional bytes for the base object ID.
{
			 N_("ignore packs that have companion .keep file")),
			return 0;


	if (wo_end != to_pack.nr_objects)
					target = &p[i];
			/* This happens if we decided to reuse existing
		if (objects[i].tagged)
	if (a_in_pack > b_in_pack)
}
				 */


	void *buf, *base_buf, *delta_buf;
		next:
		if (oe_type(&objects[i]) != OBJ_COMMIT &&
	create_object_entry(oid, type, name_hash, 0, 0, pack, offset);
		die(_("--thin cannot be used to build an indexable pack"));
		 * and we reset it to 0 right away.
		}
		*base_out = base;
		use_internal_rev_list = 1;
{
		OPT_BOOL(0, "revs", &use_internal_rev_list,
			break;
	if (!pack_to_stdout)
			close(fd);
	oid_array_append(&recent_objects, &obj->oid);
	/* Now some size filtering heuristics. */
		 *   A -> B -> C -> D -> B
				int exclude)
		if (!*list_size) {
{
	if (!strcmp(arg, "allow-promisor")) {
	unsigned hdrlen;
{
	if (!HAVE_THREADS && delta_search_threads != 1)

 * Return the size of the object without doing any delta
static struct pack_idx_option pack_idx_opts;
				if (force_object_loose(&oid, p->mtime))
			}
	}
}
		argv_array_push(&rp, shallow
		return 0;
	}
#define SET_SIZE(obj,size) oe_set_size(&to_pack, obj, size)
		 * entry whose final depth is supposed to be zero, we snip it
			if (write_bitmap_index) {
		BUG("too many dfs states, increase OE_DFS_STATE_BITS");
	else {
			add_to_write_order(wo, wo_end, &objects[i]);

			break;
		argv_array_push(&rp, "--exclude-promisor-objects");
	unsigned long canonical_size;
	WRITE_ONE_BREAK = 0, /* writing this will bust the limit; not written */
	if (depth >= (1 << OE_DEPTH_BITS)) {
static int done_pbase_paths_alloc;
	    ((ignore_packed_keep_on_disk && p->pack_keep) ||
{
#include "blob.h"
		hashwrite(f, in, avail);
	void *data;
		idx++;
}
}

static int pack_loose_unreachable;
			    !has_sha1_pack_kept_or_nonlocal(&oid) &&
	if (p->pack_local &&
		entry->in_pack_type = type;
			f = create_tmp_packfile(&pack_tmp_name);
			return;
		if (delta_search_threads < 0)
		len -= avail;
		oe_set_in_pack(&to_pack, entry, found_pack);
 * list, or NULL if we must use the external-base list.
	/*
		display_progress(progress_state, i + 1);
			}
		switch (entry->in_pack_type) {

					use_pack(p, &w_curs,
		 * We failed to get the info from this pack for some reason;
		fn_show_object = show_object;
{
		if (use_delta_islands) {
		return 0;
{
{
	offset += entry->in_pack_header_size;
		OPT_SET_INT(0, "write-bitmap-index", &write_bitmap_index,
	if (exclude)
	if (!in_same_island(&trg->entry->idx.oid, &src->entry->idx.oid))
		close_istream(st);
		e->delta_sibling_idx = DELTA(e)->delta_child_idx;
					   unsigned int *endp,
static void add_unreachable_loose_objects(void)
				: "--objects-edge");
	}


struct unpacked {
			}

	 * not know either way, and it needs to check more packs.
		limit = pack_size_limit - write_offset;
		off_t ofs = entry->idx.offset - DELTA(entry)->idx.offset;
		 * currently deltified object, to keep it longer.  It will
			lo = mi + 1;
	copy_pack_data(out, reuse_packfile, w_curs, offset, next - offset);

		p[i].list = list;
#define DELTA_CHILD(obj) oe_delta_child(&to_pack, obj)
						 entry->in_pack_offset + used,

	 *   bugs in bitmap code and possible bitmap index corruption).
		argv_array_push(&rp, "--indexed-objects");
		 * previous attempt before a pack split occurred.
			/* our sibling might have some children, it is next */
		for (; i < to_pack.nr_objects; i++) {
	}
					    &pack_idx_opts, oid.hash);
	if (!data)
				unpack_unreachable_expiration))

	 */
{
	oidcpy(&nent->oid, oid);
	ALLOC_GROW(reused_chunks, reused_chunks_nr + 1,
			  (!ent && pbase_tree_cache[available_ix])))
	 * we set offset to 1 (which is an impossible value) to mark

#define OBJECT_ADDED (1u<<20)

	if (max_delta_cache_size && delta_cache_size + delta_size > max_delta_cache_size)
			break;
	 */

	 * number of objects, which is elsewhere bounded to a uint32_t.


 */
	} else
		(reuse_packfile_bitmap &&
 * to the smaller -- deletes are potentially cheaper, but perhaps
			continue;
"disabling bitmap writing, as some objects are not being packed"
	progress_lock();
	unsigned hash = pack_name_hash(name);
{
		 * depth, leaving it in the window is pointless.  we
static unsigned long pack_size_limit;
				want = want_found_object(exclude, p);
		 * work is available if we see 1 in ->data_ready, it
			  struct object_entry *entry,
		loosen_unused_packed_objects();
						oid_to_hex(&src_entry->idx.oid));
#include "pack-objects.h"
	if (usable_delta)
	int shallow = 0;
			       list[0]->hash == list[-1]->hash) {

	unsigned long limit;
	enum object_type type;

				write_bitmap_index = 0;
	return nent;
static pthread_cond_t progress_cond;
		 * it's not a delta, we're done traversing, but we'll mark it
		off_t len,

				 */
		const char *p;
	if (!pack_to_stdout && !pack_size_limit)
	for (;;) {
	*pptr = out;
			   in_pack.nr + p->num_objects,
		type = (allow_ofs_delta && DELTA(entry)->idx.offset) ?
			strbuf_release(&tmpname);
	if (!strcmp(k, "pack.depth")) {

		depth = (1 << OE_DEPTH_BITS) - 1;
		return;
		return;
}
		allow_pack_reuse = git_config_bool(k, v);

	struct name_entry entry;
static int git_pack_config(const char *k, const char *v, void *cb)
		hdrlen += sizeof(dheader) - pos;

				close_istream(st);
		mem_usage -= free_unpacked(n);
static int use_bitmap_index_default = 1;
		/*
{
		free(tmp->pcache.tree_data);
		give_up:

{
	 */
	if (*c || pack_idx_opts.off32_limit & 0x80000000)
		load_delta_islands(the_repository, progress);
	return a < b ? -1 : (a > b);  /* newest first */

	trace2_region_enter("pack-objects", "enumerate-objects",
				 * going up until we can go right again */
static int option_parse_unpack_unreachable(const struct option *opt,
	for (cur = entry; cur; cur = next) {
		if (write_bitmap_index) {
		if (name[cmplen] != '/') {
		 * We keep all commits in the chain that we examined.
	if (!DELTA(trg_entry)) {
};
	n->entry = NULL;
			return;
			write_reused_pack_one(pos + offset, f, &w_curs);
		off_t ofs;
#define SET_DELTA_CHILD(obj, val) oe_set_delta_child(&to_pack, obj, val)
 * struct thread_params).
	/*
		 * ...
				utb.actime = st.st_atime;

		}
		base_offset = get_delta_base(reuse_packfile, w_curs, &cur, type, offset);
	}
	struct pack_window *w_curs = NULL;
	/*

			if (src_entry->preferred_base) {

#include "object-store.h"
}
	if (reuse_packfile_bitmap &&
			    N_("show progress meter during object writing phase"), 2),
			 * object size from the delta header.

	if (rev_list_index) {
	 * make sure no copy of this object appears in _any_ pack that makes us
#include "delta-islands.h"
		if (cmplen == 0) {
}

{

		progress = 2;
}
				N_("ignore this pack")),
			      N_("limit the objects to those that are not yet packed"),
		; /* nothing */
#include "revision.h"
	*offset += size;
				die(_("expected edge object ID, got garbage:\n %s"),
			victim->remaining -= sub_size;
		}
			break;
			    N_("do not hide commits by grafts"), 0),


	pthread_cond_destroy(&progress_cond);
		arg_missing_action = MA_ALLOW_ANY;
	if (!pack_to_stdout && p->index_version == 1 &&
			 * packs then we should modify the mtime of later ones
	}
	struct unpacked *array;
		  N_("write the pack index file in the specified idx format version"),
					     reuse_packfile->revindex[base_pos].nr);
		return size;
			else
				if (utime(pack_tmp_name, &utb) < 0)
	 * earlier try, but only when reusing delta data.  Note that
			if (canonical_size == 0)
static off_t write_object(struct hashfile *f,
}
		 */

				ofs = (ofs << 7) + (c & 127);
	struct object_id oid;
		return 0;
		j = window;
			buf = use_pack(p, &w_curs,
static void get_object_details(void)
		if (!p) /* no keep-able packs found */
				  struct pack_window **w_curs)
	unsigned char obuf[1024 * 16];
		objects[i].tagged = 0;
		if (DELTA(entry) && max_depth <= n->depth)
	if (pack_to_stdout != !base_name || argc)
			free(data);


		prepare_pack(window, depth);
}
		FREE_AND_NULL(entry->delta_data);
					   struct object_entry *e)
			off_t delta_pos;
static int reused_chunks_nr;
		die("unable to read %s",
/*
		QSORT(in_pack.array, in_pack.nr, ofscmp);
{
	indexed_commits[indexed_commits_nr++] = commit;
	}
		 * We want in_pack_type even if we do not reuse delta

	unsigned long freed_mem = sizeof_delta_index(n->index);
	prepare_repo_settings(the_repository);


	char line[GIT_MAX_HEXSZ + 1 + PATH_MAX + 2];
		 * (total_depth % (depth + 1)) of them.
		packing_data_lock(&to_pack);
	pos = -pos - 1;
		while (ofs >>= 7)
	if (use_delta_islands)
		return 0;
		if (stream.avail_in)
}
static unsigned long window_memory_limit = 0;
	}
		stop_progress(&progress_state);
/* Return 0 if we will bust the pack-size limit */
		if (oideq(&it->pcache.oid, &tree_oid)) {

	}
{

/*
		written = (pos * BITS_IN_EWORD);
			 N_("pack loose unreachable objects")),
		/* Prefer only shallower same-sized deltas. */
		if (!pack_to_stdout) {
			return WRITE_ONE_BREAK;

{
			if (feof(stdin))
			}
		if (!p->pack_local)
	while (p) {

		if (m < c)
		 * between writes at that moment.
			       off_t *found_offset)
	       pack_to_stdout &&
		    can_reuse_delta(&base_ref, entry, &base_entry)) {
#include "tree-walk.h"
			    exclude, name && no_try_delta(name),
