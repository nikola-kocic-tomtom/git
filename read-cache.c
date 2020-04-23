}
			changed |= TYPE_CHANGED;
	struct split_index *si = istate->split_index;
			write_index_ext_header(&c, &eoie_c, newfd, CACHE_EXT_LINK,
			return -1;
	uint64_t start = getnanotime();
	 * that is associated with the given "istate".
		break;
		}
				     const struct object_id *oid,
	unsigned int size = ce_size(ce);
	return changed;
 * index; the caller is responsible to clear out the extra entries
 */

	} else {
	free_name_hash(istate);
		}
		 * valid again, under "assume unchanged" mode.
		ret = commit_locked_index(lock);
			if (ce_write_flush(context, fd))
	 * we can avoid searching for it.
static struct cache_entry *refresh_cache_ent(struct index_state *istate,
			BUG("cache entry is not allocated from expected memory pool");
 * for some time.
	return unmerged;
}
	strbuf_add(sb, hash, the_hash_algo->rawsz);
		}
				 * to the loop below to disect the entry's path
static void tweak_split_index(struct index_state *istate)
static void show_file(const char * fmt, const char * name, int in_porcelain,
 *
				strbuf_addch(sb, ' ');

	return updated;
 */
static size_t read_eoie_extension(const char *mmap, size_t mmap_size)
			}
 * one before we accept it as
 * This is used by routines that want to traverse the git namespace
	move_cache_to_base_index(istate);
{
	struct cache_entry **cache = istate->cache;
	struct cache_entry *ce;

	return shared_index_expire_date;

		write_ieot_extension(&sb, ieot);
		error(_("cannot fix permission bits on '%s'"), get_tempfile_path(*temp));
			if (ce_stage(ce) > ce_stage(next_ce))
/*
		struct strbuf sb = STRBUF_INIT;

	flags = ce->ce_flags & ~CE_NAMEMASK;
}
			ce_array[j++] = ce_array[i];
	if (!index)
}
	mode_t st_mode = st->st_mode;
	switch (flip) {
		}

			else if (changed & TYPE_CHANGED)

		struct cache_entry *ce = cache[i];
	/* Make sure the array is big enough .. */
	/*

	unsigned int version = INDEX_FORMAT_DEFAULT;
			err = -1;
	for (;;) {
	int ieot_blocks;	/* count of ieot entries to process */
			      ce->name + common, ce_namelen(ce) - common);
	/* Add it in.. */
	/* Append the hash signature at the end */
		    unlink(shared_index_path))
	record_resolve_undo(istate, ce);
			c = *path++;
	istate->cache_alloc = 0;
		if (ieot && i && (i % ieot_entries == 0)) {
	size = offsetof(struct ondisk_cache_entry,data) + ondisk_data_size(ce->ce_flags, 0);
}
}
		remove_index_entry_at(istate, --pos);
		len = strlen(name);
	cmp = memcmp(name1, name2, len);
		if (is_racy_timestamp(istate, ce))
	int val;
	case CACHE_EXT_UNTRACKED:
#include "fsmonitor.h"
	/*
	p.istate = istate;
		 * we're ok, and we can exit.
	for (i = 0; i < istate->cache_nr; i++) {
	sz = htonl(sz);
	}
		write_buffer_len = 0;

				continue;
 * or as an unmerged entry.

{
		return NULL;
			   istate->cache_nr - pos - 1);
		if (err)
	 * Validate the offset we're going to look for the first extension
struct cache_entry *make_cache_entry(struct index_state *istate,
				return 0;
	 */

	int ret;
	case 0: /* false */
		write_locked_index(repo->index, lockfile, COMMIT_LOCK);
struct index_entry_offset_table
{
	if (stripped_name) {
			ieot->nr++;
		if (!istate) {
		/* else fallthrough */

{
 */
			break;
		ce->ce_stat_data.sd_size = 0;
 * Copyright (C) Linus Torvalds, 2005
	int retval;
	istate->cache_nr = ntohl(hdr->hdr_entries);

	}
		consumed += p->consumed;
}
 * This way, shared index can be removed if they have not been used
	 * to multi-thread the reading of the cache entries.
	if (ignore_case && alias && different_name(ce, alias))
				/*
		if (!ce_stage(ce))
}
	uint32_t buffer;
}
		struct cache_entry *ent;
	istate->timestamp.nsec = ST_MTIME_NSEC(st);
		if (p->ce_flags & CE_REMOVE)
	if (!(option & ADD_CACHE_KEEP_CACHE_TREE))
 * the output of read_directory can be used as-is.
		}
	}
	 * subproject.  If ie_match_stat() already said it is different,
/* Mask for the name length in ce_flags in the on-disk index */
		nr = 0;
		} else {
	istate->timestamp.sec = 0;
				    struct index_state *istate)
}
			write_buffer_len = buffered;


		disk_ce = (struct ondisk_cache_entry *)(mmap + src_offset);
			return ce;
		ret = add_index_entry_with_check(istate, ce, option);
		name = (const char *)(flagsp + 1);
		if (cmp_last > 0) {
 *
			oidclr(&si->base_oid);

	unsigned long consumed = 0;
	}
	 * Compare the entry's full path with the last path in the index.
	if (!ignore_fsmonitor && (ce->ce_flags & CE_FSMONITOR_VALID))
		 * $ echo filfre >nitfol

	else
		 */
static int index_name_pos_also_unmerged(struct index_state *istate,
	ce->ce_flags |= CE_UPDATE_IN_BASE;
}
	struct cache_entry *old = istate->cache[nr];
	void *buffer;
	version = strtoul(envversion, &endp, 10);
		stripped_name = 1;

		error(_("could not close '%s'"), tempfile->filename.buf);

	if (pos >= istate->cache_nr ||
}
{
int add_index_entry(struct index_state *istate, struct cache_entry *ce, int option)


			 * index, but because of multiple stage and CE_REMOVE
{
		errno = saved_errno;

				   the_repository, "%s", (*temp)->filename.buf);
	struct object_id oid;
		 * found that the entry is unmodified.  If the entry
{

					return 0;
	ret = rename_tempfile(temp,
	int offset, nr;
	 * there is a high probability that this entry will eventually

	int add_option = (ADD_CACHE_OK_TO_ADD|ADD_CACHE_OK_TO_REPLACE|
		return changed | changed_fs;
				 * means the index is not valid anymore.

	if (ce_flush(&c, newfd, istate->oid.hash))
			   istate->cache_nr);
			ieot = xcalloc(1, sizeof(struct index_entry_offset_table)
static int repo_verify_index(struct repository *repo)
	ce->index = 0;
	case 1: /* true */
		 * is a tricky code.  At first glance, it may appear
		 * $ sleep 3
		break;
	switch (CACHE_EXT(ext)) {
	trace_performance_leave("read cache %s", path);
{
	struct stat st;
		write_fsmonitor_extension(&sb, istate);

	pos = -pos-1;

		changed |= CTIME_CHANGED;
void stat_validity_clear(struct stat_validity *sv)


	if (istate->version == 3 || istate->version == 2)
		cpus = online_cpus();

#else
			istate->cache_changed |= SPLIT_INDEX_ORDERED;

			 * We do not mark the index itself "modified"
		int name_compare = strcmp(ce->name, next_ce->name);
	 */
	return -first-1;
	 * carefully than others.
	 */
		if (cache[i]->ce_flags & CE_EXTENDED_FLAGS) {
{
	 *
	if (len1 < len2)
		 * valid bit, then we did the actual stat check and
	struct index_entry_offset entries[FLEX_ARRAY];


{
static int check_file_directory_conflict(struct index_state *istate,
	int unmerged = 0;
		/* reduce extended entries if possible */
			; /* still matching */
		if (ce_stage(p) != stage)

			return 0;
			&len_eq_last);
#define CACHE_ENTRY_PATH_LENGTH 80
	 *	 "REUC" + <binary representation of M>)
			 * This is a possible collision. Fall through and
				if (is_ntfs_dotgitmodules(path))
	if (!strip_extensions && istate->untracked) {
		return changed;
		strbuf_release(&sb);

		 /* nanosecond timestamped files can also be racy! */
	}
}
{
}
	 */
		write_buffer_len = 0;



	}
{
		updated->ce_flags &= ~CE_VALID;
			       struct lock_file *lockfile)
 */
	else
	ALLOC_GROW(istate->cache, istate->cache_nr + 1, istate->cache_alloc);
	if (istate->cache_nr > 0 &&
	closedir(dir);
			drop_cache_tree = 1;
			if ((ce_namelen(p) <= len) ||
static int ce_write(git_hash_ctx *context, int fd, void *data, unsigned int len)
		/*
	if (fd < 0)
	}
	 * the filesystem is on
		return error(_("bad index version %d"), hdr_version);
			ce_write(&c, newfd, sb.buf, sb.len) < 0;
				 * level or anything shorter.
		/* We do not yet understand any bit out of CE_EXTENDED_FLAGS */
	c1 = name1[len];
		mark_fsmonitor_valid(istate, ce);
	if (trust_ctime && check_stat &&
	ret = write_split_index(istate, lock, flags);
		if (resolve_gitlink_ref(path, "HEAD", &oid) < 0)

	if (flags & COMMIT_LOCK)
	if (tree || !get_oid_tree("HEAD", &cmp)) {

	alternate_index_output = name;
			return 0; /* Yup, this one exists unmerged */
		if (expand_name_field)
	int i;
	struct split_index *si = istate->split_index;
	char *envversion = getenv("GIT_INDEX_VERSION");
	struct load_index_extensions *p = _data;
	int result;
	}
	while (len) {
				 */
{
	}
				 * EQ: last: xxx/A
	if (offset < 0) {
}
		if (rest[2] != 't' && rest[2] != 'T')
 * name that we already have - but we don't want to update the same
	int nr, nr_threads;
	base_path = xstrfmt("%s/sharedindex.%s", gitdir, base_oid_hex);

	memcpy(ce->name, path, namelen);
/*

	return validate_index_cache_entries;
	 * We don't actually require that the .git directory

			discard_cache_entry(ce);
		changed |= !S_ISREG(st->st_mode) ? TYPE_CHANGED : 0;
	unsigned int changed;

			if (istate->cache_nr > 0 &&
		MOVE_ARRAY(istate->cache + pos + 1, istate->cache + pos,
#define INDEX_FORMAT_DEFAULT 3
			!mem_pool_contains(istate->ce_mem_pool, istate->cache[i])) {
 * cap the parallelism to online_cpus() threads, and we want
	 */
		if (err)
	if (pos < istate->cache_nr) {

			goto out;
			}
	int ok_to_add = option & ADD_CACHE_OK_TO_ADD;
	return changed;
		clean_shared_index_files(oid_to_hex(&si->base->oid));
	 * so that it can be found and processed before all the index entries are
	 */
		return 1;
			 const struct cache_entry *ce, int pos, int ok_to_replace)
	return *pool_ptr;
 */
		}
	/* When core.ignorecase=true, determine if a directory of the same name but differing
	return 0;
			replace_index_entry(istate, pos, ce);
	 * If this entry's path sorts after the last entry in the index,
	/* ensure we have an index big enough to contain an EOIE extension */
				mark_fsmonitor_invalid(istate, ce);

	}
 * If the initial amount of memory set aside is not sufficient, the
	if (istate->version == 4) {
			if (is_ntfs_dotgit(path))
				 *     this: xxxB/file
	if (!ignore_skip_worktree && ce_skip_worktree(ce)) {
		data = (char *) data + partial;
	if (len1 == len2)
		die_errno(_("%s: cannot stat the open index"), path);
	int pos;
struct cache_entry *make_empty_cache_entry(struct index_state *istate, size_t len)
int write_locked_index(struct index_state *istate, struct lock_file *lock,
		pool_ptr = &istate->ce_mem_pool;
	sd->sd_ctime.sec = (unsigned int)st->st_ctime;
			 * the longest directory prefix; subsequent
	 * TODO trace2: replace "the_repository" with the actual repo instance
		return 0; /* 100% means never write a new shared index */
		int common, to_remove, prefix_size;
				ce->ce_flags &= ~CE_VALID;
	size_t copy_len = 0;
static int write_shared_index(struct index_state *istate,
}
		return;
		unmerged = 1;
			const struct cache_entry *ce, int pos, int ok_to_replace)
	int pos, len;
	 *
	}
	uint32_t extsize;
		set_index_entry(istate, i, ce);
	case CACHE_EXT_LINK:
	/*
			continue;
		nr_threads = 1;
	return verify_index_from(repo->index, repo->index_file);
	static unsigned char padding[8] = { 0x00 };
			if (skip_iprefix(rest, "modules", &rest) &&
	add_name_hash(istate, ce);
static void check_ce_order(struct index_state *istate)
		const struct cache_entry *ce,
		    (has_symlinks || !S_ISREG(st->st_mode)))
	goto inside;
	}
	    version < INDEX_FORMAT_LB || INDEX_FORMAT_UB < version) {
		struct cache_entry *ce = istate->cache[i - 1];
	struct cache_entry *new_entry = make_empty_cache_entry(istate, ce_namelen(ce));
		}
	}

}
		return -1;
		istate->timestamp.sec <= sd->sd_mtime.sec
			cpus = online_cpus();
				break;
	/*
	 * associated split_index. There is no need to free individual
		const char *sha1_hex;
	if (check_stat && sd->sd_dev != (unsigned int) st->st_dev)
	if (git_env_bool("GIT_TEST_CHECK_CACHE_TREE", 0))
	if (ret) {
		return NULL;
		 *
			copy_len = previous_len - strip_len;
	if (!HAVE_THREADS || git_config_get_index_threads(&nr_threads))
	int i, not_shared = 0;
		return 0;
		return;
		if (!temp) {

				     ext);
		return MODE_CHANGED | DATA_CHANGED | TYPE_CHANGED;
				if (!ok_to_replace)
		  const struct cache_entry *ce, struct stat *st,


	if (!data || type != OBJ_BLOB) {
	if (ce->ce_flags & CE_REMOVE)
	 * see if the contents match, and if so, should answer "unchanged".
				   "%s", path);
 * order to correctly interpret the index file, pick character that
				untracked_cache_remove_from_index(istate,
		int changed = 0;
	dst->cache_tree = src->cache_tree;
		return -1;
	uint32_t extsize, ext_version;
{
	while (src_offset <= p->mmap_size - the_hash_algo->rawsz - 8) {
			discard_cache_entry(ce);
		/* This is "racily clean"; smudge it.  Note that this
	return !oideq(&oid, &ce->oid);
		if (flags & COMMIT_LOCK)
/*
	ce = mem_pool_alloc(mem_pool, cache_entry_size(len));
				die(_("unable to create load_index_extensions thread: %s"), strerror(err));
	}
 */
	struct cache_header hdr;
		struct cache_entry *ce = istate->cache[next];
		if (pos >= 0) {
		remove_split_index(istate);
	changed = ie_match_stat(istate, ce, &st, options);

/*
 * That is, is there another file in the index with a path
#include "diffcore.h"
		BUG("unsupported ce_mode: %o", ce->ce_mode);
}
{
	memcpy(ce->name, name, len);
{
		break;
	save_or_free_index_entry(istate, ce);
		goto out;
	while (pos < istate->cache_nr) {
	 * If so, we consider it always to match.
		*first = 0;
	int namelen = strlen(new_name);
	 * unsigned char hash[hashsz];
	if (lstat(ce->name, &st) < 0)
	return 0;
	unsigned char hash[GIT_MAX_RAWSZ];
				+ (ieot_blocks * sizeof(struct index_entry_offset)));


	struct index_entry_offset_table *ieot = NULL;
		if (!result)
		if (!ok_to_replace)
	if (ce && ce->mem_pool_allocated)
	die(_("index file corrupt"));
	}
}

	return (!S_ISGITLINK(ce->ce_mode) &&
		return ret;
	for (i = 0; i < istate->cache_nr; i++) {
#define ondisk_data_size_max(len) (ondisk_data_size(CE_EXTENDED, len))
	int ieot_entries = 1;
			istate->updated_workdir ? "1" : "0",
	case '.':

				 * strcmp said the whole path was greater).
	/*
		struct strbuf sb = STRBUF_INIT;
}
	ce->ce_mode = create_ce_mode(mode);
	the_hash_algo->final_fn(hash, &c);
	istate->untracked = NULL;
	}
		return NULL;
		strbuf_release(&sb);
			 * last: xxx
	if (trust_ctime && check_stat &&
#include "resolve-undo.h"
	int verbose = flags & (ADD_CACHE_VERBOSE | ADD_CACHE_PRETEND);
			pos++;
 *
	int in_porcelain = (flags & REFRESH_IN_PORCELAIN);
	if (trust_executable_bit && has_symlinks) {
	if (cmp)
{
		if (err)
		    base_oid_hex, base_path,
static void write_ieot_extension(struct strbuf *sb, struct index_entry_offset_table *ieot);
	nr = 0;
	ieot_blocks = DIV_ROUND_UP(ieot->nr, nr_threads);
		err = write_link_extension(&sb, istate) < 0 ||
		die(_("will not add file alias '%s' ('%s' already exists in index)"),
	the_hash_algo->init_fn(&eoie_c);
	if (!c1 && S_ISDIR(mode1))
				 *     this: xxx/file_B


		break; /* just use the configured value */
	 * ce_stat_data.sd_mtime match the index file mtime.
	}
			return DATA_CHANGED;
		if (!is_empty_blob_sha1(ce->oid.hash))
}
			ieot_blocks = istate->cache_nr / THREAD_COST;

	consumed = load_cache_entry_block(istate, istate->ce_mem_pool,

	int i, offset, ieot_blocks, ieot_start, err;
		strcmp(ce->name, istate->cache[istate->cache_nr - 1]->name) > 0)
			 * we are not going to write this change out.
}
	}
	prepare_to_write_split_index(istate);
	istate->cache_changed |= CE_ENTRY_ADDED;



	} else {
		struct strbuf sb = STRBUF_INIT;
	free(base_path);
			return -1;
			ieot->entries[ieot->nr].offset = offset;
	ce->ce_namelen = len;
/* Copy miscellaneous fields but not the name */
	return ret;

{
	 */
		oidcpy(&si->base_oid, &si->base->oid);
				 * slash) also appears as a prefix in the last
			if (previous_len < strip_len)

		      !strcmp(istate->cache[i]->name, path));
			 * character to ensure there is nothing common with the previous
 * from the memory mapped file and add them to the given index.
static void set_index_entry(struct index_state *istate, int nr, struct cache_entry *ce)
	if (c2 == '/' && !c1)
	 * by definition never matches what is in the work tree until it
	return refresh_cache_ent(istate, ce, options, NULL, NULL);

		split_index->base = xcalloc(1, sizeof(*split_index->base));
		if (ignore_submodules && S_ISGITLINK(ce->ce_mode))
		memcpy(&extsize, mmap + src_offset + 4, 4);
#include "blob.h"
	/*
	if (!nr) {
	if (!hasheq(istate->oid.hash, hash))
{
	dst->untracked = src->untracked;
	/* istate->initialized covers both .git/index and .git/sharedindex.xxx */
}
	unsigned char hash[GIT_MAX_RAWSZ];
		cmp_last = strcmp_offset(name,
	    check_file_directory_conflict(istate, ce, pos, ok_to_replace)) {
	trace_performance_leave("refresh index");


	char c = 0;
		version = INDEX_FORMAT_DEFAULT;
{
	}
	fd = open(path, O_RDONLY);
		p.src_offset = src_offset;
	if (!ok_to_add)
		ce = create_from_disk(ce_mem_pool, istate->version, disk_ce, &consumed, previous_ce);
	struct stat st;


		pos = index_name_stage_pos(istate, ce->name, ce_namelen(ce), ce_stage(ce));
		/* increment by the number of cache entries in the ieot block being processed */
			 * path.

	istate->cache_nr--;

	 * since there's really no good reason to allow it.
	}
			break;
	ce->ce_flags &= ~CE_HASHED;
	trace_performance_enter();
	if (*endp ||
	mark_fsmonitor_invalid(istate, ce);
	if (flags & ADD_CACHE_RENORMALIZE)
			has_errors = 1;
	 * already has checked the actual HEAD from the filesystem in the


}
	if ((repo->index->cache_changed ||
		 * $ echo xyzzy >frotz
		if (write_in_full(fd, write_buffer, left) < 0)
					  &first, header_msg);
		error("invalid IEOT version %d", ext_version);
	 *	uint16_t flags2;
	ondisk->mtime.sec = htonl(ce->ce_stat_data.sd_mtime.sec);
	offset = lseek(newfd, 0, SEEK_CUR);
			ce_smudge_racily_clean_entry(istate, ce);
	struct cache_time mtime;

		c1 = '/';
	unsigned int flags;
	case 'g':
	/* Check timestamp */
	extsize = get_be32(index);
 * For example, you'd want to do this after doing a "git-read-tree",

	if (ieot) {
	 * then the hash would be:
}
	 */
	 */
		break;
				return retval;
static size_t read_eoie_extension(const char *mmap, size_t mmap_size);
	size_t mmap_size;
				 * and see where the difference is.

static void ce_smudge_racily_clean_entry(struct index_state *istate,
	struct object_id oid;
	ext = htonl(ext);
	sd->sd_ctime.nsec = ST_CTIME_NSEC(*st);
}
		break;
	}
	for (i = 0; i < nr_threads; i++) {
	ondisk->uid  = htonl(ce->ce_stat_data.sd_uid);
	if (lstat(path, &st))
		error(_("invalid path '%s'"), path);
	int i;

	}
		    oideq(&alias->oid, &ce->oid) &&
	if (cmp)
			   struct stat *st)
int name_compare(const char *name1, size_t len1, const char *name2, size_t len2)
	 * CACHE_EXT_ENDOFINDEXENTRIES must be written as the last entry before the SHA1
#define CACHE_EXT_LINK 0x6c696e6b	  /* "link" */
	    sd->sd_ctime.nsec != ST_CTIME_NSEC(*st))
	switch (st->st_mode & S_IFMT) {

		if (err)
static int read_index_extension(struct index_state *istate,
	int len = len1 < len2 ? len1 : len2;
				/*

	const char *name = ce->name;
	}
				fmt = modified_fmt;
				estimate_cache_size_from_compressed(istate->cache_nr));
 * mem pool will allocate extra memory.
		}
			changed |= DATA_CHANGED;
static int add_index_entry_with_check(struct index_state *istate, struct cache_entry *ce, int option)
};
 * Chmod an index entry with either +x or -x.

}
		die_errno(_("unable to stat '%s'"), path);

{
		left = 0;
		return 1; /* 0% means always write a new shared index */

			 * iterations consider parent directories.
	struct stat st;
	 * automatically, which is not really what we want.
		return -1;
		for (i = -pos - 1;
 * in memory because of pathname deltafication.  This is not required
		 * that it can break with this sequence:
	len = ce_namelen(alias);
	else
	if (!changed) {
	data = xcalloc(nr_threads, sizeof(*data));
			break;
		return 0;
	 * As a convenience, the end of index entries extension
	repo_read_index(repo);
	}
		discard_index(split_index->base);
		} else {
	 */
	buffer = read_object_file(&ce->oid, &type, &size);
static unsigned long load_all_cache_entries(struct index_state *istate,
		return -1;

	}
}
	}
	case S_IFLNK:
			result = ce_write(c, fd, padding, 1);
	}
	if (flags & COMMIT_LOCK)
	}
		return cmp;

		return error(_("unable to add '%s' to index"), path);
{
	new_entry->mem_pool_allocated = mem_pool_allocated;
	trace2_data_intmax("index", the_repository, "write/version",
	cmp = name_compare(name1, len1, name2, len2);
		if (memcmp(name, p->name, len))
	if (!si || alternate_index_output ||
	if (fstat(fd, &st))
				return 0;
		/* We ignore most of the st_xxx fields for gitlinks */
	/* extension size - version bytes / bytes per entry */
		struct strbuf sb = STRBUF_INIT;
				 * is a subdirectory of what we are looking
	int len = ce_namelen(a);
			continue;
	untracked_cache_remove_from_index(istate, path);
		/* create a mem_pool for each thread */
	 * under GITLINK directory be a valid git directory. It
	}
{
				 * a longer file or directory name, but sorts
	sd->sd_gid = st->st_gid;
#include "lockfile.h"
		goto out;

	ce->ce_stat_data.sd_ino   = get_be32(&ondisk->ino);
	if (!istate->version) {
	for (i = 0; i < nr_threads; i++) {

#define CACHE_EXT_FSMONITOR 0x46534D4E	  /* "FSMN" */
}
		while (namelen && path[namelen-1] == '/')
}

		if (!index_fd(istate, &oid, fd, st, OBJ_BLOB, ce->name, 0))
				 * The directory prefix lines up with part of
			changed |= ce_modified_check_fs(istate, ce, st);
}
		ce->ce_namelen = saved_namelen;

}
		}
		if (ieot_blocks > 1) {
	return 0;
			if (i)
				 * this: xxx/yy/abc
		if (err)
};
{
 *

				 * The entry sorts AFTER the last one in the

#define align_flex_name(STRUCT,len) ((offsetof(struct STRUCT,data) + (len) + 8) & ~7)
{

			}
		       + (nr * sizeof(struct index_entry_offset)));
{

					struct cache_entry *ce,
				 * LT: last: xxx/file_A
	 * TODO trace2: replace "the_repository" with the actual repo instance

	case S_IFDIR:

	}
	if (hdr_version < INDEX_FORMAT_LB || INDEX_FORMAT_UB < hdr_version)
		/* If there is an existing entry, pick the mode bits and type
		adjust_dirname_case(istate, ce->name);
		err = pthread_create(&p->pthread, NULL, load_cache_entries_thread, p);
	int len;
	/*
			die(_("unable to join load_index_extensions thread: %s"), strerror(ret));
 * Returns 1 if the path is an "other" path with respect to
			changed |= MODE_CHANGED;


	cache_tree_invalidate_path(istate, ce->name);
}

	int first = 1;
	struct load_index_extensions p;

		 * is not marked VALID, this is the place to mark it


		do_diff_cache(&cmp, &opt);
	if (left + the_hash_algo->rawsz > WRITE_BUFFER_SIZE) {
			die(_("unable to join load_cache_entries thread: %s"), strerror(err));
	}
	hdr.hdr_version = htonl(hdr_version);

		return -2;
#define ondisk_data_size(flags, len) (the_hash_algo->rawsz + \
			ieot->entries[ieot->nr].nr = nr;
	len = strlen(path);
	cmp = memcmp(name1, name2, len);
	if (fd >= 0) {
}
					       const char *path, int stage)
	/*
	 * We check if the path is a sub-path of a subsequent pathname

	left += the_hash_algo->rawsz;
	int ignore_valid = options & CE_MATCH_IGNORE_VALID;
		return val;

	hashcpy(ce->oid.hash, ondisk->data);
				    ce->name);
	 * If we can confirm that, we can avoid binary searches on the
#endif
			match = memcmp(buffer, sb.buf, size);
struct cache_entry *dup_cache_entry(const struct cache_entry *ce,
				return retval;
		rollback_lock_file(lockfile);

 */

	for (i = offset; i < offset + nr; i++) {
	modified_fmt   = in_porcelain ? "M\t%s\n" : "%s: needs update\n";
	const char *index, *eoie;
static int verify_hdr(const struct cache_header *hdr, unsigned long size)
		struct load_cache_entries_thread_data *p = &data[i];
		ieot->nr++;

		 * this function, notices that the cached size is 6
			ieot_entries = DIV_ROUND_UP(entries, ieot_blocks);
	if (!git_config_get_bool("index.recordendofindexentries", &val))
		if (index_path(istate, &ce->oid, path, st, hash_flags)) {

int remove_index_entry_at(struct index_state *istate, int pos)
	}

		return NULL;
		new_ce->ce_mode = ce->ce_mode;

		mem_pool_init(&istate->ce_mem_pool,
	return 1;
	if (r->settings.core_untracked_cache == UNTRACKED_CACHE_WRITE)
		cache_tree_verify(the_repository, istate);
			nr_threads = cpus;
		int extended_flags;
		struct stat *st, unsigned int options)
	}
}
	for (i = 1; i < istate->cache_nr; i++) {
		mem_pool_combine(istate->ce_mem_pool, p->ce_mem_pool);
		free(ieot);
 * either as a file, a directory with some files in the index,
	case -1:

		return ce;
		the_hash_algo->update_fn(context, write_buffer, buffered);
		/* index_fd() closed the file descriptor already */
	nr = (extsize - sizeof(uint32_t)) / (sizeof(uint32_t) + sizeof(uint32_t));
				remove_index_entry_at(istate, pos);
	/* Validate that the extension offsets returned us back to the eoie extension. */
	    !(ce->ce_flags & CE_VALID))
		/*
	case 0:
		    !(ce->ce_flags & CE_VALID))
{
		ce_mark_uptodate(ce);
	new_entry->ce_flags &= ~CE_HASHED;

	close(fd);

	munmap((void *)mmap, mmap_size);
	if (src_offset != mmap_size - the_hash_algo->rawsz - EOIE_SIZE_WITH_HEADER)
	sd->sd_mtime.sec = (unsigned int)st->st_mtime;

{
{
		  istate->timestamp.nsec <= sd->sd_mtime.nsec))
}
	p.mmap = mmap;
	char *base_path;
	ondisk->gid  = htonl(ce->ce_stat_data.sd_gid);
				pos = i;
	if (j == istate->cache_nr)
		if (si)

static void freshen_shared_index(const char *shared_index, int warn)
 * calling remove_index_entry_at() for each entry to be removed.
	if (pos < 0) {
#ifdef USE_NSEC
		 * in 4-byte network byte order.

	} else {

	return 0;
		break;

	if (fd < 0) {
static struct mem_pool *find_mem_pool(struct index_state *istate)
	offset = get_be32(index);
	int pos = index_name_pos(istate, path, namelen);

	}
			else
	if (st.st_size < sizeof(struct cache_header) + the_hash_algo->rawsz)
			namelen--;
		if (err)
		return val;
{
	ssize_t n;
		if (cache[i]->ce_flags & CE_REMOVE)

	int i;
	updated = make_empty_cache_entry(istate, ce_namelen(ce));

	 * When ce is an "I am going away" entry, we allow it to be added
	if (alternate_index_output)
 * different files with aliasing names!
			display_progress(progress, i);
			return DATA_CHANGED;
int df_name_compare(const char *name1, int len1, int mode1,

		else
			ieot_blocks = ieot->nr - ieot_start;
		if (!cmp)
	if (changed & (MODE_CHANGED | TYPE_CHANGED))
	}
		err = write_index_ext_header(&c, NULL, newfd, CACHE_EXT_ENDOFINDEXENTRIES, sb.len) < 0
		if (getenv("GIT_TEST_VALIDATE_INDEX_CACHE_ENTRIES"))
			if (allow)
		p->ieot_start = ieot_start;

{

				 const struct pathspec *pathspec,
	 * We are frequently called during an iteration on a sorted
		return 0;
	struct cache_entry * ce;
	int ignore_missing = options & CE_MATCH_IGNORE_MISSING;
				/* If we are doing --really-refresh that

				!istate->split_index->base->ce_mem_pool ||
	/* maybe unmerged? */

			 * entry
	return match_stat_data(sd, st);
	int ieot_start;		/* starting index into the ieot array */
	return (c1 < c2) ? -1 : (c1 > c2) ? 1 : 0;
	 * This outlaws ".GIT" everywhere out of an abundance of caution,
			result = ce_write(c, fd, ce->name, len);
	ondisk->ctime.sec = htonl(ce->ce_stat_data.sd_ctime.sec);


	}
struct load_index_extensions
	if (!dir)
{
		break;
		if ((v & 15) < 6)

				 */
{
		return commit_lock_file(lk);
	hdr_version = ntohl(hdr->hdr_version);
		return error(_("invalid path '%s'"), ce->name);
			     const struct cache_entry *ce)

				(really ? CE_MATCH_IGNORE_VALID : 0) |
		}
 * Again - this is just a (very strong in practice) heuristic that

out:
			*err = EINVAL;
/*

	if (changed_fs)
			result = ce_write(c, fd, to_remove_vi, prefix_size);
{

		p->istate = istate;
		 * bytes and what is on the filesystem is an empty
	}

	run_hook_le(NULL, "post-index-change",
				break; /* not our subdirectory */
	 * can minimize the number of extensions we have to scan through to
	if (lstat(ce->name, &st) < 0) {

	hdr.hdr_signature = htonl(CACHE_SIGNATURE);
	 * everything else as they are.  We are called for entries whose
	return 0;
				return retval;
#include "cache-tree.h"
	if (!strip_extensions && !drop_cache_tree && istate->cache_tree) {
		new_ce->ce_flags = create_ce_flags(0) | CE_CONFLICTED;
	copy_cache_entry(new_entry, ce);
		 */
		die(_("broken index, expect %s in %s, got %s"),
static unsigned long load_cache_entry_block(struct index_state *istate,
		strbuf_release(&sb);
	 * st_dev breaks on network filesystems where different
					 extsize) < 0) {
	memcpy(updated->name, ce->name, ce->ce_namelen + 1);
	/* On-disk flags are just 16 bits */
	for (i = 0; i < entries; i++) {
	/* existing match? Just replace it. */
		src_offset += load_all_cache_entries(istate, mmap, mmap_size, src_offset);
	int namelen, was_same;
}
		struct strbuf sb = STRBUF_INIT;
	int expand_name_field = version == 4;
#include "thread-utils.h"
		strbuf_release(&sb);
			continue;
		 * sections, each of which is prefixed with

	ce->name[len] = '\0';

	int len = ce_namelen(ce);

	else
	int cmp_last = 0;

	int i;
	struct index_entry_offset_table *ieot;
 *
								  ce_array[i]->name);
		error("invalid number of IEOT entries %d", nr);

	memcpy(new_entry->name, alias->name, len);
	return result;
	if (pretend)
	if (0 <= fd && write_locked_index(repo->index, &lock_file, COMMIT_LOCK | write_flags))

}
		if (ce_compare_link(ce, xsize_t(st->st_size)))

 * to link up the stat cache details with the proper files.
				     ((flags & CE_EXTENDED) ? 2 : 1) * sizeof(uint16_t) + len)

	size_t offset, src_offset;
		    !ce_stage(alias) &&
		nr_threads = istate->cache_nr / THREAD_COST;
	}
			if (allow < 0)
/*

				       struct cache_entry *ce)


	return !git_config_get_index_threads(&val) && val != 1;
	return consumed;
#include "strbuf.h"
		return error(_("%s: can only add regular files, symbolic links or git-directories"), path);
			warning(_("index.version set, but the value is invalid.\n"
			return ce_compare_gitlink(ce) ? DATA_CHANGED : 0;
		flagsp[1] = htons((ce->ce_flags & CE_EXTENDED_FLAGS) >> 16);
			 */
		src_offset += 8;
{
}
	tweak_split_index(istate);
	}
	 * the length field is zero, as we have never even read the
	struct stat st;
		pos = -pos-1;
	 *
	memcpy(ce->name, path, len);
		struct cache_entry *ce = istate->cache[i];
{
		const char *shared_index_path;
			continue;
		}
	istate->timestamp.sec = 0;
		if (is_dir_sep(c)) {
	 * us not to worry.
/* Index extensions.
static int too_many_not_shared_entries(struct index_state *istate)
	if (expand_name_field) {

		strip_len = decode_varint(&cp);
	return 1;
	int ret;
			 *
	/*
	 * contents.  The caller checks with is_racy_timestamp() which
	cache_tree_invalidate_path(istate, old_entry->name);
static int ce_modified_check_fs(struct index_state *istate,
		return 0;
			/*
#define align_padding_size(size, len) ((size + (len) + 8) & ~7) - (size + len)
	struct cache_time ctime;
	if (!verify_ce_order)
 * added.  Either one would result in a nonsense tree that has path
	trace_performance_since(start, "write index, changed mask = %x", istate->cache_changed);
		if (err)

		struct cache_entry *ce = istate->cache[pos];
int index_name_is_other(const struct index_state *istate, const char *name,
				if (S_ISLNK(mode)) {
		    oid_to_hex(&split_index->base->oid));
				 * p is at the same stage as our entry, and

		nr_threads = ieot->nr;
	size_t len;
					 struct cache_entry *ce)
/*
static void tweak_untracked_cache(struct index_state *istate)
	save_or_free_index_entry(istate, ce);
		}
		}
		ent = (0 <= pos) ? istate->cache[pos] : NULL;
	if (c1 == '/' && !c2)

{
 *
			else
	ondisk->ctime.nsec = htonl(ce->ce_stat_data.sd_ctime.nsec);
	}
	istate->cache_changed = 0;
		ret = -1;
int match_stat_data_racy(const struct index_state *istate,
{
 * state can call this and check its return value, instead of calling
static void *load_index_extensions(void *_data)
		BUG("the name hash isn't thread safe");

	if (pos >= 0)

		the_hash_algo->update_fn(&c, mmap + src_offset, 8);
 */
}
static int ce_flush(git_hash_ctx *context, int fd, unsigned char *hash)
		return 0;
	/* validate the version is IEOT_VERSION */
			while ((i < istate->cache_nr) &&
#include "diff.h"
	 */
	return ret;
	int cmp;
}
		ieot_start += ieot_blocks;
}
struct cache_entry *refresh_cache_entry(struct index_state *istate,
				ce_mark_uptodate(alias);
{

				 * collide with a file.
	 */
}
		struct cache_entry *ce, *new_entry;
	unsigned int options = (CE_MATCH_REFRESH |
	 * length match the cache, and other stat fields do not change.
		 */
		int next = first + ((last - first) >> 1);
	last = istate->cache_nr;
			 * items, we fall through and let the regular search
		 */

void fill_stat_cache_info(struct index_state *istate, struct cache_entry *ce, struct stat *st)
	return version;
			if (ieot_blocks > istate->cache_nr)
	return (write_in_full(fd, write_buffer, left) < 0) ? -1 : 0;

	git_hash_ctx c;


		memcpy(ce->name, name, len + 1);
	return pos;



			die(_("unknown index entry format 0x%08x"), extended_flags);
	unsigned long consumed;	/* return # of bytes in index file processed */
	tweak_fsmonitor(istate);
	if (write_object_file("", 0, blob_type, &oid))
	ce->ce_mode  = get_be32(&ondisk->mode);
	 * used for threading is written by default if the user

		struct cache_entry *ce = istate->cache[i];
		strbuf_splice(previous_name, common, to_remove,
 *
#endif
		 * obtain from the filesystem next time we stat("frotz").
	if (ce->ce_flags & CE_EXTENDED) {
}
}

	return ondisk_size + entries * per_entry;
	int hash_flags = HASH_WRITE_OBJECT;
				ieot_blocks = istate->cache_nr;
			compare_name((ce = istate->cache[pos]), path, namelen))
	return xcalloc(1, cache_entry_size(len));
			sv->sd = xcalloc(1, sizeof(struct stat_data));

 */
static void write_eoie_extension(struct strbuf *sb, git_hash_ctx *eoie_context, size_t offset);
	if (!intent_only) {
			match = !oideq(&oid, &ce->oid);
		 * The path is unchanged.  If we were told to ignore
	if (!(flags & ADD_CACHE_RENORMALIZE)) {

			if (*--slash == '/')

		if (extension_offset) {
	mmap = xmmap_gently(NULL, mmap_size, PROT_READ, MAP_PRIVATE, fd, 0);
/*
	if (istate->cache_nr > 0) {
	}
		for (j = p->ieot_start; j < p->ieot_start + p->ieot_blocks; j++)
	 * The logic does not apply to gitlinks, as ce_match_stat_basic()
		for (;;) {
		/* Same initial permissions as the main .git/index file */
	}
		git_config_get_expiry("splitindex.sharedindexexpire",
	close(fd);
		free(data);
	 *
		if (assume_racy_is_modified)
			changed |= DATA_CHANGED;
	}
	 * always says "no" for gitlinks, so we are not called for them ;-)
	int ok_to_replace = option & ADD_CACHE_OK_TO_REPLACE;
	 * Intent-to-add entries have not been added, so the index entry

	if (!ignore_fsmonitor)
		struct cache_entry *p = istate->cache[pos++];
	istate->cache_nr = j;
	if (!S_ISREG(st_mode) && !S_ISLNK(st_mode) && !S_ISDIR(st_mode))
			nr += p->ieot->entries[j].nr;

	return 0;
	int i;
	uint32_t ino;
	struct ondisk_cache_entry ondisk;
		int filtered = 0;
	 * so that it can be found by scanning backwards from the EOF.

		}
			if (!remove_index_entry_at(istate, pos))
			/*
 * alias twice, because that implies that there were actually two
		if (ignore_missing)

	const char *path, int namelen)
		 * have enough blocks to utilize multi-threading
			}
	}
					    struct ondisk_cache_entry *ondisk,
{
	}
		break;
	return entries * (sizeof(struct cache_entry) + CACHE_ENTRY_PATH_LENGTH);
		if (new_entry == ce)
	ret = do_write_index(istate, lock->tempfile, 0);
	struct load_cache_entries_thread_data *data;
	if (tree)
	    (S_ISGITLINK(ce->ce_mode) || ce->ce_stat_data.sd_size != 0))

		mem_pool_init(&istate->ce_mem_pool,
	if (ce->ce_flags & CE_STRIP_NAME) {
				allow = git_env_bool("GIT_ALLOW_NULL_SHA1", 0);
		uint32_t extsize;

	 *
	return (!istate->cache_nr && !istate->timestamp.sec);

		      const char *name2, int len2, int mode2)
				die(_("multiple stage entries for merged file '%s'"),
		if (CACHE_EXT((mmap + offset)) == CACHE_EXT_INDEXENTRYOFFSETTABLE) {
	if (!verify_path(path, mode)) {
		if (S_ISLNK(mode)) {
	if (!shared_index_expire_date_prepared) {
			/*
		mem_pool_init(pool_ptr, 0);
	 * which ce_match_stat_basic() always goes to the actual


		break;
	else {
		}

	}

		 * becomes zero --- which would then match what we would

static const int default_max_percent_split_change = 20;
		return NULL;
			|| ce_write(&c, newfd, sb.buf, sb.len) < 0;
	int entries = istate->cache_nr;
	int cmp = memcmp(name1, name2, min_len);
			}
	if (flags & REFRESH_PROGRESS && isatty(2))
	if (size)
	index += sizeof(uint32_t);

				return retval;
		pos = index_name_stage_pos(istate, name, len, stage);
		ce_mark_uptodate(ce);
 * should have been allocated by the memory pool
	if (!check_and_freshen_file(shared_index, 1) && warn)
 * df_name_compare() is identical to base_name_compare(), except it
		break;
			}
	if (!hasheq(hash, (unsigned char *)hdr + size - the_hash_algo->rawsz))
	}
	 * index.
	struct cache_entry *ce;
 * out of date.
	 * then we know it is.
			return 1;
		memcpy(ce->name + copy_len, name, len + 1 - copy_len);

			if (err)
#include "tempfile.h"
}
		return error(_("bad index file sha1 signature"));
				 *
	 * would give a falsely clean cache entry.  The mtime and
		break;

				fmt = typechange_fmt;
{
#include "object-store.h"
static int index_name_stage_pos(const struct index_state *istate, const char *name, int namelen, int stage)
}
{
		}

			}
		istate->version = get_index_format_default(the_repository);
void stat_validity_update(struct stat_validity *sv, int fd)
{
	if (buffer) {
	int ignore_valid = options & CE_MATCH_IGNORE_VALID;

{
		 * extension name (4-byte) and section length

			!compare_name(ce, path, namelen))
 * the inode hasn't changed.

		pos = ret - 1;
				break;
}

	    !is_null_oid(&istate->split_index->base_oid)) {

		/*
#include "cache.h"
	struct index_state *istate;
 * This function verifies if index_state has the correct sha1 of the
int cache_name_stage_compare(const char *name1, int len1, int stage1, const char *name2, int len2, int stage2)
		ieot->entries[i].offset = get_be32(index);
	}
	/* validate the extension signature */
 * be worth starting a thread.
		struct object_id oid;
			if (allow_unmerged)
					break;
static unsigned long load_cache_entries_threaded(struct index_state *istate, const char *mmap, size_t mmap_size,
				return 0;
{

	 * Once we've seen ".git", we can also find ".gitmodules", etc (also
	oidcpy(&ce->oid, &oid);
 *
		validate_cache_entries(istate->split_index->base);
}
	int changed;
	/* Ok, create the new entry using the name of the existing alias */
{
		/* not or badly configured: use the default value */
	unsigned long src_offset;
		set_object_name_for_intent_to_add_entry(ce);
	}
		offset += extsize;
	if (istate->initialized)
	 * valid whatever the checked-out copy says.
 * compares conflicting directory/file entries as equal. Note that
		ce->ce_flags |= CE_VALID;
	}
		err = write_index_ext_header(&c, &eoie_c, newfd, CACHE_EXT_UNTRACKED,
int remove_file_from_index(struct index_state *istate, const char *path)

	resolve_undo_clear_index(istate);
	int hdr_version;
		ce_mark_uptodate(ce);

 * This only updates the "non-critical" parts of the directory
		ce = istate->cache[i];
	 * Use the multi-threaded preload_index() to refresh most of the
}
	int i;
		saved_namelen = ce_namelen(ce);


	if (ieot) {
		} else if (c == '\\' && protect_ntfs) {
	const unsigned hashsz = the_hash_algo->rawsz;
	 * that is associated with the given "istate".
	return ce_namelen(alias) != len || memcmp(ce->name, alias->name, len);

static int commit_locked_index(struct lock_file *lk)
			const struct stat_data *sd)

				ce->ce_flags |= CE_UPDATE_IN_BASE;
	int really = (flags & REFRESH_REALLY) != 0;
#define THREAD_COST		(10000)
};
/*
			strbuf_addstr(sb, istate->cache[i]->name);
	 * effectively mean we can make at most one commit per second,
			return -1;
}
			 * (len + 1) is a directory boundary (including
		break;
	for (;;) {
{


				warning(msg, ce->name);
		goto out;

		istate->cache_changed |= SPLIT_INDEX_ORDERED;
		if (!result)
	deleted_fmt    = in_porcelain ? "D\t%s\n" : "%s: needs update\n";
		 */
		if (istate->version == 4) {


	}

	 * being registered/updated records the same time as "now")
		if (is_null_oid(&ce->oid)) {

{
				fmt = added_fmt; /* must be before other checks */
	 * The end of index entries (EOIE) extension is guaranteed to be last
				  "Using version %i"), INDEX_FORMAT_DEFAULT);
	unmerged_fmt   = in_porcelain ? "U\t%s\n" : "%s: needs merge\n";

void fill_stat_data(struct stat_data *sd, struct stat *st)
		/* After an array of active_nr index entries,
{
	ce->ce_stat_data.sd_gid   = get_be32(&ondisk->gid);
/*
				 unsigned int refresh_flags,
			   const struct cache_entry *ce,
		/* offset */
	if (!git_config_get_bool("index.recordoffsettable", &val))
	unsigned int i, j;
		free(ieot);
	the_hash_algo->final_fn(write_buffer + left, context);
	for (i = j = 0; i < istate->cache_nr; i++) {
static struct index_entry_offset_table *read_ieot_extension(const char *mmap, size_t mmap_size, size_t offset)
		}
		return error_errno(_("could not stat '%s'"), shared_index_path);
		if (previous_ce) {
	istate->timestamp.nsec = 0;
{
	 * number of bytes to be stripped from the end of the previous name,
 * proper superset of the name we're trying to add?
	/* Write extension data here */
			if ((c == '.' && !verify_dotfile(path, mode)) ||
	/*
					     struct cache_entry *ce,
		return ce;
{
	if (cmp)
		changed |= DATA_CHANGED;
	/*
 */
		diffcore_std(&opt);
#define CACHE_EXT_UNTRACKED 0x554E5452	  /* "UNTR" */
 * for V2/V3 index formats because their pathnames are not compressed.
 */
	new_entry->ce_namelen = namelen;
	if (ce_modified_check_fs(istate, ce, &st)) {
	}
	}
	oidcpy(&ce->oid, oid);
{
	free_untracked_cache(istate->untracked);
 */
	if (extension_offset) {
 * unmerged.  Callers who want to refuse to work from an unmerged
 * index file.  Don't die if we have any other failure, just return 0.

		unsigned long consumed;
		else {
}
	}
		return 0;
	case S_IFREG:
		 * already matches the sub-directory, then we know
#include "run-command.h"
	return 0;
	int skip_df_check = option & ADD_CACHE_SKIP_DFCHECK;
 *****************************************************************/
}
{
	len = strlen(path);
	if (!hasheq(hash, (const unsigned char *)index))
			has_errors = 1;
#define IEOT_VERSION	(1)
	new_entry->index = 0;
	return namelen != ce_namelen(ce) || memcmp(path, ce->name, namelen);
		if (!must_exist && errno == ENOENT)
#define ondisk_ce_size(ce) (ondisk_cache_entry_size(ondisk_data_size((ce)->ce_flags, ce_namelen(ce))))

	char name[FLEX_ARRAY];
	mem_pool_init(&istate->ce_mem_pool, 0);
				 * GT: last: xxxA
	the_hash_algo->final_fn(hash, eoie_context);
	 */
			return 1;
				 */
	unsigned ce_option = CE_MATCH_IGNORE_VALID|CE_MATCH_IGNORE_SKIP_WORKTREE|CE_MATCH_RACY_IS_DIRTY;
 * Do we have another file with a pathname that is a proper
 * a dot after the basename (because '\0' < '.' < '/').
			unsigned long start_offset, const struct cache_entry *previous_ce)
		int pos = index_name_pos_also_unmerged(istate, path, namelen);
		alias = index_file_exists(istate, ce->name,
		} else if (!istate->ce_mem_pool ||
	/* a little sanity checking */
struct cache_entry *make_transient_cache_entry(unsigned int mode, const struct object_id *oid,
			filtered = 1;
			changed |= TYPE_CHANGED;
		break;
			offset = lseek(newfd, 0, SEEK_CUR);
/*
			result = ce_write(c, fd, padding, align_padding_size(size, len));
	ret = do_write_index(si->base, *temp, 1);
		return 0;

	} else {
	/* ensure we have no more threads than we have blocks to process */
	if (new_shared_index) {

}
	trace2_region_leave_printf("index", "shared/do_write_index",


#ifdef USE_STDEV
	ce = mem_pool_calloc(mem_pool, 1, cache_entry_size(len));
			die(_("unable to create load_cache_entries thread: %s"), strerror(err));
		ce = create_alias_ce(istate, ce, alias);

		index += sizeof(uint32_t);
 * If we add a filename that aliases in the cache, we will use the
		name = (const char *)cp;
int verify_path(const char *path, unsigned mode)
	if (!ce->ce_stat_data.sd_size) {
	/*
static void *load_cache_entries_thread(void *_data)

	istate = repo->index;
	int mem_pool_allocated;

	int ignore_skip_worktree = options & CE_MATCH_IGNORE_SKIP_WORKTREE;
	if (split_index->base)
 * _does_ do is to "re-match" the stat information of a file
{
		while (ce_same_name(istate->cache[pos], ce)) {
	remove_name_hash(istate, ce);
				     unsigned int refresh_options)
				free(ieot);
	return 1;
	    (istate->cache_changed & ~EXTMASK)) {
 * detail of lockfiles, callers of `do_write_index()` should not
}
		if (cmp < 0) {
	index += sizeof(uint32_t);
		resolve_undo_write(&sb, istate->resolve_undo);
	if (offset < 0) {

 */
	}
	index += sizeof(uint32_t);
	if (strbuf_readlink(&sb, ce->name, expected_size))
	default:
		int len = ce_namelen(ce);
/*
	unsigned long expiration;
	if (!skip_df_check &&
	 * Cache entries in istate->cache[] should have been allocated
		 * for "frotz" stays 6 which does not match the filesystem.
		    !memcmp(ce->name, name, namelen))
				if (S_ISLNK(mode)) {
 * GIT - The information manager from hell
	if (!S_ISREG(ce->ce_mode))
		for (i = 0; sb && i < diff_queued_diff.nr; i++) {
	unsigned int saved_namelen;
	istate->timestamp.nsec = ST_MTIME_NSEC(st);
	case 100:
			offset += write_buffer_len;
			buffered = 0;

		return 0;

		break;
	split_index = istate->split_index;

		saved_errno = errno;
					     sb.len) < 0 ||
	switch (max_split) {
	hashcpy(ondisk->data, ce->oid.hash);
	base_oid_hex = oid_to_hex(&split_index->base_oid);
	struct stat st;
 * to validate the cache.
			mem_pool_init(&p->ce_mem_pool,




	} else
	}


		if (ce_stage(istate->cache[i]))
	 * that is associated with the given "istate".
	int i;
int verify_index_checksum;
}
}
		uint32_t extsize = get_be32(p->mmap + src_offset + 4);
	/*
		       unsigned flags)
		}
	ce->ce_flags |= CE_ADDED;
	/* ieot */
			}
		return 0;
 *
			munmap((void *)p->mmap, p->mmap_size);
		for (j = 0; j < ieot_blocks; j++)
		copy_cache_entry_to_ondisk(ondisk, ce);
			extended++;
		prepare_repo_settings(r);
	data = read_object_file(&istate->cache[pos]->oid, &type, &sz);
 * When this happens, we return non-zero.
}
	struct stat st;
			static const char msg[] = "cache entry has null sha1: %s";

	}
{
				previous_name->buf[0] = 0;
	 * ".git" followed by NUL or slash is bad. Note that we match
		return 0;
}
		if (should_delete_shared_index(shared_index_path) > 0 &&

		 * from it, otherwise assume unexecutable regular file.
		istate->resolve_undo = resolve_undo_read(data, sz);
	untracked_cache_remove_from_index(istate, old_entry->name);
static inline struct cache_entry *mem_pool__ce_alloc(struct mem_pool *mem_pool, size_t len)
	ce->ce_namelen = namelen;
	int quiet = (flags & REFRESH_QUIET) != 0;
int refresh_index(struct index_state *istate, unsigned int flags,
	new_entry = make_empty_cache_entry(istate, namelen);
}
	if (st.st_mtime > expiration)
			return error(_("'%s' does not have a commit checked out"), path);
		cache[i]->ce_flags &= ~CE_EXTENDED;
}
		return cmp;

		extsize = get_be32(mmap + offset + 4);
	changed_fs = ce_modified_check_fs(istate, ce, st);
		}
	trace2_region_enter_printf("index", "shared/do_read_index",
 * is outside the range, to cause the reader to abort.
		extension_offset = read_eoie_extension(mmap, mmap_size);
	while (pos < istate->cache_nr && !strcmp(istate->cache[pos]->name, path))
	return src_offset - start_offset;
	return c1 - c2;
		break;

int verify_ce_order;
 */
	previous_name = (hdr_version == 4) ? &previous_name_buf : NULL;

			 * the trailing slash).  And since the loop is
		      ce->name[common] == previous_name->buf[common]);
	free(ce);
		fprintf_ln(stderr, _("ignoring %.4s extension"), ext);
	/*

		repo_diff_setup(repo, &opt);
	}
{
	return match;
		}
		return 0;
{
	strbuf_add(sb, &buffer, sizeof(uint32_t));
				 */
#include "tree.h"
	if (changed_ret)
		break;
struct ondisk_cache_entry {
			}

				   "%s", lock->tempfile->filename.buf);
	ce->ce_stat_data.sd_ctime.nsec = get_be32(&ondisk->ctime.nsec);
	unsigned long sz;
	unsigned char data[GIT_MAX_RAWSZ + 2 * sizeof(uint16_t)];
	struct cache_entry *new_entry;
	FREE_AND_NULL(sv->sd);
		return 0;



	ieot = xmalloc(sizeof(struct index_entry_offset_table)
		write_untracked_extension(&sb, istate->untracked);
			 * this: xxx/file
				 * The entry sorts AFTER the last one in the
	}
			  struct strbuf *previous_name, struct ondisk_cache_entry *ondisk)
}
		if (size == sb.len)
			 * Found one, but not so fast.  This could
	if (!ignore_skip_worktree && ce_skip_worktree(ce))


	/*
/* We may be in a situation where we already have path/file and path
	return 1;
			partial = len;
/* changes that can be kept in $GIT_DIR/index (basically all extensions) */
{
				 *
	/*
{
		*changed_ret = changed;
				      &shared_index_expire);
	 */
	return !git_config_get_index_threads(&val) && val != 1;
	 * assertion does not hold.
				 *
	}
int repo_refresh_and_write_index(struct repository *repo,
	len = flags & CE_NAMEMASK;
	for (i = 0; i < ieot->nr; i++) {
static int verify_index_from(const struct index_state *istate, const char *path)

			die(_("unordered stage entries in index"));
	hashcpy(istate->oid.hash, (const unsigned char *)hdr + mmap_size - the_hash_algo->rawsz);
	 * has already been discarded, we now test

					if (is_ntfs_dotgitmodules(path))
			 * be a marker that says "I was here, but
		istate->cache_tree = cache_tree_read(data, sz);
		 * $ git-update-index --add nitfol
	add_index_entry(istate, new_entry, ADD_CACHE_OK_TO_ADD|ADD_CACHE_OK_TO_REPLACE);


	 * If ignore_valid is not set, we should leave CE_VALID bit

	/* Racily smudged entry? */

	struct stat st;
		prefix_size = encode_varint(to_remove, to_remove_vi);
		 * sections, each of which is prefixed with
	trace_performance_enter();
	if (progress) {
			continue;
	pthread_t pthread;
}
			rest += 3;
			changed |= DATA_CHANGED;
	/*
	/*
	struct dirent *de;
	}
				     int stage,
		struct tempfile *temp;

			const char *mmap, size_t mmap_size, unsigned long src_offset)

		return NULL;
	free(data);
	 * actually gets added.
out:

int do_read_index(struct index_state *istate, const char *path, int must_exist)
	if (pos < istate->cache_nr && ce_stage(ce) == 0) {
	 */
					0, istate->cache_nr, mmap, src_offset, NULL);
	struct cache_entry *ce;
 * read_cache().
	}
{
 * end that can make pathnames ambiguous.
	}
			return ce;
				if (c == '\\')
	istate->cache_changed |= CE_ENTRY_REMOVED;
	c2 = name2[len];
static unsigned int get_index_format_default(struct repository *r)
}
	    sd->sd_ctime.sec != (unsigned int)st->st_ctime)
/*
		return 0;

	 * cache entries quickly then in the single threaded loop below,
#ifdef USE_NSEC
	long per_entry = sizeof(struct cache_entry) - sizeof(struct ondisk_cache_entry);

			ce_stage((ce = istate->cache[pos + 1])) == 2 &&
	struct index_state *istate = repo->index;
	const unsigned hashsz = the_hash_algo->rawsz;
	}
		int cache_errno = 0;
/*
		if (ignore_missing && errno == ENOENT)
	 * uint16_t flags;

}
	istate->cache[nr] = ce;
	uint32_t gid;
	if (r->settings.core_untracked_cache  == UNTRACKED_CACHE_REMOVE) {
static unsigned char write_buffer[WRITE_BUFFER_SIZE];
	 * and delay the return from git-update-index, but that would
	 * read.  Write it out regardless of the strip_extensions parameter as we need it
		goto out;
		return NULL;
			}

	else
	return S_ISREG(st.st_mode) && !match_stat_data(sv->sd, &st);
	while (offset <= mmap_size - the_hash_algo->rawsz - 8) {
	istate->cache_changed |= CE_ENTRY_CHANGED;
		 * file, and never calls us, so the cached size information
		 * However, the second update-index, before calling
		break;
	/*
				   the_repository, "%s", base_path);
	return (istate->timestamp.sec &&

		if (partial > len)
	}
 * this for V4 index files to guess the un-deltafied size of the index
		pool_ptr = &istate->split_index->base->ce_mem_pool;
	/* Directories and files compare equal (same length, same name) */
	int i, nr;
	 */
	n = pread_in_full(fd, hash, the_hash_algo->rawsz, st.st_size - the_hash_algo->rawsz);
	if (too_many_not_shared_entries(istate))
	int changed = 0;
	unsigned long src_offset = p->src_offset;
		return ret;
	ce->ce_stat_data.sd_mtime.nsec = get_be32(&ondisk->mtime.nsec);

	struct repository *r = the_repository;
				 * after it, so this sub-directory cannot
			return error(_("%s: cannot drop to stage #0"),
	if (assume_unchanged)
		return 0;
	pos = -pos - 1;
			warning_errno(_("unable to unlink: %s"), shared_index_path);
			/*

		if (!new_only)

 * with the cache, so that you can refresh the cache for a
	src->cache_tree = NULL;
			 */

		put_be32(&buffer, ieot->entries[i].nr);
		 */
	}
		*ent_size = ondisk_ce_size(ce);
			i--;
	switch (*rest) {

			return -1;

	case S_IFGITLINK:
				(not_new ? CE_MATCH_IGNORE_MISSING : 0));
}
	if (ret)
		if (rest[1] == '\0' || is_dir_sep(rest[1]))

		struct cache_entry *ce = istate->cache[i];
		c2 = '/';

		return ce;
	off_t offset;

		 * case we would read stage #2 (ours).
		  char *seen, const char *header_msg)
		      char flip)
		if (ce_namelen(ce) == namelen &&
	 * find it during load.  Write it out regardless of the
		struct strbuf sb = STRBUF_INIT;
		return 0;
		 (istate->timestamp.sec == sd->sd_mtime.sec &&
	if (S_ISDIR(st_mode)) {
	/*
	 */
	istate->cache_nr = 0;
			if (!filtered)
 */
	return 0;
			}


	added_fmt      = in_porcelain ? "A\t%s\n" : "%s: needs update\n";

}
	 * from the memory pool associated with this index, or from an
	 * Immediately after read-tree or update-index --cacheinfo,
				ce_namelen(istate->cache[istate->cache_nr - 1]) > len) {
	if (option & ADD_CACHE_JUST_APPEND)

	else {
	if (istate->ce_mem_pool) {
	offset += write_buffer_len;
	if (!ret) {
		refresh_fsmonitor(istate);
	return consumed;
		if (read_index_extension(p->istate,

			if (invalidate) {
	 * We could detect this at update-index time (the cache entry
}
		return 0;	/* exact match */
/*
		nr_threads = 1;

	const char *mmap;
		}
	if (!expiration)
{


	return retval;
	}
			|| ce_write(&c, newfd, sb.buf, sb.len) < 0;

	 * SHA-1("TREE" + <binary representation of N> +

		if (ce->ce_flags & CE_REMOVE)
}
		ret = 1;
	ondisk->ino  = htonl(ce->ce_stat_data.sd_ino);
	}
	retval = has_file_name(istate, ce, pos, ok_to_replace);
void set_object_name_for_intent_to_add_entry(struct cache_entry *ce)
				!istate->split_index->base ||
		len = ce_namelen(ce);
			return INDEX_FORMAT_DEFAULT;
}
		strbuf_add(sb, &buffer, sizeof(uint32_t));
	if (git_config_get_index_threads(&nr_threads))
{
					return 0;
}
	namelen = strlen(path);
 * twice when git-write-tree tries to write it out.  Prevent it.
			strbuf_addstr(sb, diff_queued_diff.queue[i]->two->path);
			 * not a part of the resulting tree, and

		return commit_lock_file_to(lk, alternate_index_output);
	struct strbuf sb = STRBUF_INIT;
		fill_stat_cache_info(istate, ce, st);

	}
	sd->sd_ino = st->st_ino;
#define EXTMASK (RESOLVE_UNDO_CHANGED | CACHE_TREE_CHANGED | \
	/* version */
void repo_update_index_if_able(struct repository *repo,
	struct mem_pool *ce_mem_pool;
	/*
		if (!ok_to_replace)
	ce = make_empty_transient_cache_entry(len);
}
	if (!first_change)
	trace2_region_enter_printf("index", "do_read_index", the_repository,
		c1 = '/';
	if (alias->ce_flags & CE_ADDED)
		for (common = 0;
	return changed;
#endif
		if (filtered)
	 * and the bytes to append to the result, to come up with its name.
	if (pos < 0)
				  int fd, unsigned int ext, unsigned int sz)

		return -1;
		stat_validity_clear(sv);
			 * The entry exactly matches the last one in the
	if (offset && record_eoie()) {
	const char *added_fmt;
static const char *shared_index_expire = "2.weeks.ago";
		if (git_env_bool("GIT_TEST_SPLIT_INDEX", 0))
		buffered += partial;
int repo_index_has_changes(struct repository *repo,
	 * (i.e. things to be edited) will reacquire CE_VALID bit
			changed |= INODE_CHANGED;
		free(buffer);
 * dot or dot-dot anywhere, and for obvious reasons don't
			goto out;

			return error(_("unable to index file '%s'"), path);
static size_t estimate_cache_size_from_compressed(unsigned int entries)
		int cmp = cache_name_stage_compare(name, namelen, stage, ce->name, ce_namelen(ce), ce_stage(ce));
	MOVE_ARRAY(istate->cache + pos, istate->cache + pos + 1,
		max_split = default_max_percent_split_change;
		/*
{
		return -1;
	return 0;
	int i;
				estimate_cache_size_from_compressed(nr));

	 * on-disk format of the index, each on-disk cache entry stores the
	flags |= (ce_namelen(ce) >= CE_NAMEMASK ? CE_NAMEMASK : ce_namelen(ce));
{
	ce->ce_stat_data.sd_mtime.sec = get_be32(&ondisk->mtime.sec);

static int verify_dotfile(const char *rest, unsigned mode)
 *
	if (istate->name_hash_initialized)


	 * components of the pathname.
		/* If we're at the beginning of a block, ignore the previous name */
	case CACHE_EXT_ENDOFINDEXENTRIES:
						return 0;

		return;
	const char *mmap;
static struct cache_entry *create_alias_ce(struct index_state *istate,
static int has_file_name(struct index_state *istate,
{
	if (!changed && is_racy_timestamp(istate, ce)) {
#define CACHE_EXT_RESOLVE_UNDO 0x52455543 /* "REUC" */
		}
void set_alternate_index_output(const char *name)
		mem_pool_discard(istate->ce_mem_pool, should_validate_cache_entries());
		return error_errno(_("unable to open git dir: %s"), get_git_dir());
	} else {
static int do_write_locked_index(struct index_state *istate, struct lock_file *lock,
	flagsp[0] = htons(flags);
				continue;
		 * it notices that the entry "frotz" has the same timestamp

	if (has_dos_drive_prefix(path))
			   istate->cache_nr);
	}
				fmt = deleted_fmt;
			oidclr(&si->base_oid);
					previous_ce->name);
	return 1;
		if (extended_flags & ~CE_EXTENDED_FLAGS)
	sd->sd_mtime.nsec = ST_MTIME_NSEC(*st);
	ondisk->mtime.nsec = htonl(ce->ce_stat_data.sd_mtime.nsec);
		opt.flags.exit_with_status = 1;
	if (n != the_hash_algo->rawsz)
	if (mmap + offset >= eoie)
	/*
				 unsigned flags)
		if (r->settings.index_version >= 0)
	tweak_untracked_cache(istate);
	if (!istate->initialized)
					 int pos, int ok_to_replace)
		 *
 * Validate the cache entries of this index.
	 */
 * across multiple background threads.
	 *
	ext_version = get_be32(index);
			 * because CE_UPTODATE flag is in-core only;
				estimate_cache_size(mmap_size, istate->cache_nr));
/*
		changed |= MTIME_CHANGED;
	size_t extension_offset = 0;
			 */
 * When new extensions are added that _needs_ to be understood in
			    memcmp(p->name, name, len))
	const char *typechange_fmt;
	memcpy(new_entry->name, new_name, namelen + 1);

	int changed, changed_fs;


static unsigned long get_shared_index_expire_date(void)
	if (ignore_case) {
 * index file over NFS transparently.
	first = 0;
int ie_match_stat(struct index_state *istate,

	 */
 */
	pos = index_name_pos(istate, name, namelen);
			break;
		p->consumed += load_cache_entry_block(p->istate, p->ce_mem_pool,
	/* if we created a thread, join it otherwise load the extensions on the primary thread */
		pos = -pos-1;
	}

	pthread_t pthread;
	if (CACHE_EXT(index) != CACHE_EXT_ENDOFINDEXENTRIES)
	 * <4-byte offset>
	if (istate->cache_nr > pos + 1)
	/* find the IEOT extension */
		return 0;

		return -1;
int repo_read_index_unmerged(struct repository *repo)
		the_hash_algo->update_fn(eoie_context, &ext, 4);
		int saved_errno;
int add_to_index(struct index_state *istate, const char *path, struct stat *st, int flags)
				if (is_hfs_dotgit(path))
	ce->ce_stat_data.sd_dev   = get_be32(&ondisk->dev);
	}

	sd->sd_size = st->st_size;
		 * but it does not.  When the second update-index runs,

 * We fundamentally don't like some paths: we don't want

	changed = ce_match_stat_basic(ce, st);
{
	if (git_env_bool("GIT_TEST_SPLIT_INDEX", 0)) {
	short flags;
	return ((ce_write(context, fd, &ext, 4) < 0) ||
	istate->timestamp.nsec = 0;
	 * If it's marked as always valid in the index, it's
		goto out;
	int pos;

#define EOIE_SIZE_WITH_HEADER (4 + 4 + EOIE_SIZE) /* <4-byte signature> + <4-byte length> + EOIE_SIZE */

		cache_tree_invalidate_path(istate, ce->name);
	put_be32(&buffer, offset);
			validate_index_cache_entries = 0;


			else if (ce_intent_to_add(ce))
	if (flags & CE_EXTENDED) {
	enum object_type type;

	 *
 * split index.
		*ent_size = (name - ((char *)ondisk)) + len + 1 - copy_len;
			if (ce_stage(p) == stage && !(p->ce_flags & CE_REMOVE))
}
	 * ce_match_stat_basic() to signal that the filesize of the
			return -1;
{
	return 0;
static int clean_shared_index_files(const char *current_hex)

	case '-':
	if (buffered) {
			return next;
			  (intent_only ? ADD_CACHE_NEW_ONLY : 0));
	}
		 * extension name (4-byte) and section length
			return -1;
	int new_only = option & ADD_CACHE_NEW_ONLY;
	if (!envversion) {
		/*
		 * We might be in the middle of a merge, in which
 */
		return 0;
	 * which is not acceptable.  Instead, we check cache entries
	if (fstat(fd, &st))
		err = write_index_ext_header(&c, &eoie_c, newfd, CACHE_EXT_FSMONITOR, sb.len) < 0
		if (err)
{
static size_t estimate_cache_size(size_t ondisk_size, unsigned int entries)
int read_index_from(struct index_state *istate, const char *path,
		if (ieot_start + ieot_blocks > ieot->nr)
	/* TODO: does creating more threads than cores help? */
{
						  istate->cache_nr);
}
	/* Flush first if not enough space for hash signature */
int stat_validity_check(struct stat_validity *sv, const char *path)
	if (S_ISREG(st->st_mode)) {
		if (rest[1] != 'i' && rest[1] != 'I')
	 * falsely clean entry due to touch-update-touch race, so we leave
{
		size_t strip_len, previous_len;
		discard_cache_entry(ce);
	ce->mem_pool_allocated = 1;
						return 0;
	if (ce->ce_flags & CE_REMOVE)
			ok_to_add = 1;
	 * As a convenience, the offset table used for threading is

struct load_cache_entries_thread_data
	return NULL;

	int max_split = git_config_get_max_percent_split_change();

	struct cache_entry *ce;
	int val;
			not_shared++;
				continue;
	ce->ce_flags = create_ce_flags(stage);
	return ce;
	istate->timestamp.sec = st.st_mtime;
#define EOIE_SIZE (4 + GIT_SHA1_RAWSZ) /* <4-byte offset> + <20-byte hash> */
	unsigned int left = write_buffer_len;
		namelen--;
	trace2_region_leave_printf("index", "do_read_index", the_repository,
	src_offset = offset;
	istate->cache_alloc = alloc_nr(istate->cache_nr);
{
		}
		printf("%s\n", header_msg);

{
	ce->ce_flags = flags & ~CE_NAMEMASK;
	if (!verify_path(ce->name, ce->ce_mode))
	if (nr_threads > ieot->nr)
	if (stage1 > stage2)

		read_fsmonitor_extension(istate, data, sz);
{
		if (len >= ce_namelen(p))
	ce->ce_namelen = len;
int ie_modified(struct index_state *istate,



		    !ce_stage(alias) &&
			changed |= OWNER_CHANGED;

		if (progress)
	memcpy(new_entry, ce, size);
		if (ce_stage(ce)) {
	 * when loading the shared index.
	for (i = 0; i < nr; i++) {
		the_hash_algo->update_fn(context, write_buffer, left);
		return NULL;
	if (check_stat) {
		free(ieot);
		 SPLIT_INDEX_ORDERED | UNTRACKED_CHANGED | FSMONITOR_CHANGED)
		return TYPE_CHANGED;
				 int gentle,

			continue;

	if (!offset)
int base_name_compare(const char *name1, int len1, int mode1,
			err = pthread_create(&p.pthread, NULL, load_index_extensions, &p);
	return has_errors;

		remove_untracked_cache(istate);

	int ignore_skip_worktree = options & CE_MATCH_IGNORE_SKIP_WORKTREE;
	copy_cache_entry(updated, ce);
unmap:
		src_offset += 8;
}
		p->mmap = mmap;
		return -1;
{
	}
		shared_index_expire_date_prepared = 1;
	 * lstat(2) information once, and we cannot trust DATA_CHANGED
	if (err) {
	uint32_t dev;
	const char *name = ce->name;
	if (istate->split_index && istate->split_index->base)
		    !ie_match_stat(istate, alias, st, ce_option)) {
/*
	unsigned char c1, c2;

			const char *fmt;
	if (!oideq(&split_index->base_oid, &split_index->base->oid))
	return index_name_stage_pos(istate, name, namelen, 0);
		else
		    const char *gitdir)
	unsigned int changed = 0;
		int namelen)
		return error(_("bad signature 0x%08x"), hdr->hdr_signature);

	 * alone.  Otherwise, paths marked with --no-assume-unchanged

{

		p->ieot = ieot;
 * cache, ie the parts that aren't tracked by GIT, and only used
		     common++)

		untracked_cache_add_to_index(istate, ce->name);

			 */
		}
 * the index; that is, the path is not mentioned in the index at all,
		ce->ce_flags |= CE_INTENT_TO_ADD;
	/* offset */
}
	/*
static int ce_compare_data(struct index_state *istate,
	for (i = 0; i < istate->cache_nr; i++) {
		offset += 8;
};

	if (expand_name_field) {
	DIR *dir = opendir(get_git_dir());
	istate->timestamp.sec = (unsigned int)st.st_mtime;
}
				strbuf_addch(sb, ' ');
	int nr;
static int different_name(struct cache_entry *ce, struct cache_entry *alias)
{
	 * might even be missing (in case nobody populated that
};
	}
static const char *alternate_index_output;
			      git_path("sharedindex.%s", oid_to_hex(&si->base->oid)));
	sd->sd_uid = st->st_uid;
				     ce->name);
		strbuf_release(&sb);
	return NULL;
	static int shared_index_expire_date_prepared;
			; /* mark this one VALID again */

	const char *modified_fmt;
		if (ret)
{
		struct load_cache_entries_thread_data *p = &data[i];
		ret = write_shared_index(istate, &temp);
	if ((changed & DATA_CHANGED) &&
#define CACHE_EXT_INDEXENTRYOFFSETTABLE 0x49454F54 /* "IEOT" */
	if (!verify_index_checksum)

	static int validate_index_cache_entries = -1;
	struct strbuf previous_name_buf = STRBUF_INIT, *previous_name;
		    ce->ce_mode == alias->ce_mode);

}

		 */

	if (!nr_threads) {
			return error(_("index uses %.4s extension, which we do not understand"),

				/*

struct cache_entry *make_empty_transient_cache_entry(size_t len)
		return;
	ret = do_read_index(split_index->base, base_path, 1);
	return pos + 1;
 * If strings are equal, return the length.
			 * decrementing "slash", the first iteration is
		if (write_in_full(fd, write_buffer, buffered) < 0)
	/*
	if (!is_valid_path(path))
	 */
	strbuf_release(&sb);
			|| ce_write(&c, newfd, sb.buf, sb.len) < 0;
				   "%s", path);
	expiration = get_shared_index_expire_date();
				 */
	ce = make_empty_cache_entry(istate, namelen);
	case S_IFREG:
{
	struct object_id oid;
 * before writing the index to a tree).  Returns true if the index is
	cache_tree_free(&(istate->cache_tree));
		p->ieot_blocks = ieot_blocks;
{
	}
	 * Then check if the path might have a clashing sub-directory
	 * to refresh the entry - it's not going to match
}
 * "refresh" does not calculate a new sha1 file or bring the
				 * so there cannot be a F/D conflict.
	istate->updated_workdir = 0;
		if (!ce_uptodate(ce) && is_racy_timestamp(istate, ce))
		return cmp;
		return strcmp(s1, s2);


	new_shared_index = istate->cache_changed & SPLIT_INDEX_ORDERED;

	int stripped_name = 0;
		}

		len = slash - name;
		while (pos < istate->cache_nr) {

	 * case of the file being added to the repository matches (is folded into) the existing

	enum object_type type;
				 *
	new_entry = make_empty_cache_entry(istate, len);
	int offset;
					   struct cache_entry *alias)
		if (s1[k] == '\0')
struct index_entry_offset
}
	if (!split_index || is_null_oid(&split_index->base_oid)) {

	post_read_index_from(istate);
	}
	if (verbose && !was_same)
	}
}

		free(ieot);
	struct lock_file lock_file = LOCK_INIT;
			p->offset, p->ieot->entries[i].nr, p->mmap, p->ieot->entries[i].offset, NULL);
	return 0;
		c2 = '/';
	default:
	/* demote version 3 to version 2 when the latter suffices */
	return (int64_t)istate->cache_nr * max_split < (int64_t)not_shared * 100;
	struct cache_entry *ce, *ret;
					 p->mmap + src_offset + 8,
 * Like strcmp(), but also return the offset of the first change.
				 * collide with a file.
	index = eoie = mmap + mmap_size - EOIE_SIZE_WITH_HEADER - the_hash_algo->rawsz;

		if (!result)
	if (!intent_only)
		int ret = pthread_join(p.pthread, NULL);
{
 * file that hasn't been changed but where the stat entry is
		new_ce = make_empty_cache_entry(istate, len);
		return 0;
static int ce_match_stat_basic(const struct cache_entry *ce, struct stat *st)
		rollback_lock_file(lock);
		 * "mode changes"
		die(_("cannot create an empty blob in the object database"));
				}
		is_racy_stat(istate, &ce->ce_stat_data));
	trace2_region_enter_printf("index", "do_write_index", the_repository,
		return 0;
	 * signature is after the index header and before the eoie extension.
		int nr, j;
	char *base_oid_hex;
	if (check_stat && sd->sd_mtime.nsec != ST_MTIME_NSEC(*st))
	switch (git_config_get_split_index()) {
				   the_repository, "%s", base_path);
		if (read_link_extension(istate, data, sz))
			ret = do_write_locked_index(istate, lock, flags);
			      struct tempfile **temp)
	return new_entry;
	ce->ce_stat_data.sd_ctime.sec = get_be32(&ondisk->ctime.sec);
	} else {
int chmod_index_entry(struct index_state *istate, struct cache_entry *ce,
		hash_flags |= HASH_RENORMALIZE;

				/*

	int assume_racy_is_modified = options & CE_MATCH_RACY_IS_DIRTY;
		return;
	const char *slash = name + ce_namelen(ce);
	 */
	/* It was suspected to be racily clean, but it turns out to be Ok */
{

	offset += write_buffer_len;
		 * ensure default number of ieot blocks maps evenly to the
	discard_cache_entry(old);
	FREE_AND_NULL(istate->cache);
static int ce_compare_link(const struct cache_entry *ce, size_t expected_size)
			 * If we have a V4 index, set the first byte to an invalid
	return istate->cache_nr;
		return 0;
 */
		if (!S_ISDIR(st->st_mode))
	return add_to_index(istate, path, &st, flags);
		add_split_index(istate);
	trace2_data_intmax("index", the_repository, "read/cache_nr",
	int first, last;
	struct cache_entry **ce_array = istate->cache;
	int entries = istate->cache_nr;
	int len;
		return DATA_CHANGED | TYPE_CHANGED | MODE_CHANGED;
		src_offset += consumed;
/* remember to discard_cache() before reading a different cache! */
		progress = start_delayed_progress(_("Refresh index"),
	 */
	}
		struct strbuf sb = STRBUF_INIT;
				const char *ext, const char *data, unsigned long sz)
	int pos = index_name_pos(istate, path, strlen(path));

	struct cache_entry *old_entry = istate->cache[nr], *new_entry;
	return offset;
#define ondisk_cache_entry_size(len) align_flex_name(ondisk_cache_entry,len)
	}
	 * explicitly requested threaded index reads.
 * A thread proc to run the load_cache_entries() computation
	}
{
 * Index File I/O

	istate->initialized = 0;
		if (err)

	munmap((void *)mmap, mmap_size);
	oidcpy(&ce->oid, oid);
}

		ce->ce_mode = create_ce_mode(st_mode);
	if (is_racy_stat(istate, sd))
		return 0;
			if (offset < 0) {
	case CACHE_EXT_RESOLVE_UNDO:
		 * in index is the 6-byte file but the cached stat information
	the_hash_algo->init_fn(&c);
			}
	int cmp;
}


				    ce->name);
				retval = -1;
		replace_index_entry(istate, i, new_entry);
			save_or_free_index_entry(istate, ce_array[i]);
{
		return NULL;
	int newfd = tempfile->fd;
	if (!HAVE_THREADS)
	close(fd);
 */
static int do_write_index(struct index_state *istate, struct tempfile *tempfile,


		changed |= MTIME_CHANGED;
		 * as index, and if we were to smudge it by resetting its
	if (ext_version != IEOT_VERSION) {
		/* After an array of active_nr index entries,
	unsigned char hash[GIT_MAX_RAWSZ];

	if (!ignore_valid && (ce->ce_flags & CE_VALID)) {
	if (!verify_path(path, mode)) {
	case CACHE_EXT_TREE:

			if (len + 1 <= len_eq_last) {
 * So we use the CE_ADDED flag to verify that the alias was an old
static struct index_entry_offset_table *read_ieot_extension(const char *mmap, size_t mmap_size, size_t offset);
	trace2_data_intmax("index", the_repository, "write/cache_nr",


		goto unmap;
	ce = mem_pool__ce_alloc(ce_mem_pool, len);

static void replace_index_entry(struct index_state *istate, int nr, struct cache_entry *ce)
}
		     (ce->name[common] &&
		return !!istate->cache_nr;
		unsigned int partial = WRITE_BUFFER_SIZE - buffered;
	int ret;
/* These are only used for v3 or lower */
				 * equal portions, so this sub-directory cannot
 *
		if (sd->sd_ino != (unsigned int) st->st_ino)
				return -1;
		memcpy(new_ce->name, ce->name, len);
	trace2_data_intmax("index", the_repository, "read/version",
	return 0;
					    const struct cache_entry *previous_ce)
	if (close_tempfile_gently(tempfile)) {
			nr_threads--;
	}
}
			  "Using version %i"), INDEX_FORMAT_DEFAULT);
	static unsigned long shared_index_expire_date;
				return -1;
 * The first letter should be 'A'..'Z' for extensions that are not
		if (nr_threads > cpus)
		name = (const char *)(flagsp + 2);
	if (!gentle && fd < 0)
	uint32_t size;
	was_same = (alias &&
			changed |= INODE_CHANGED;
		return 0;
 * If ok-to-replace is specified, we remove the conflicting entries
	}
	}
				const struct cache_entry *ce,

#include "config.h"
		return sv->sd == NULL;
					 const struct cache_entry *ce,
		size_t len;
		memcpy(write_buffer + buffered, data, partial);
			    is_dir_sep(c) || c == '\0')
				ce_mark_uptodate(ce);

	replace_index_entry_in_base(istate, old, ce);

			return ret;
		len -= partial;
	if (!ignore_valid && (ce->ce_flags & CE_VALID))
			     struct lock_file *lock,

 * We save the fields in big-endian order to allow using the
			/* Nothing changed, really */
	while (last > first) {

	void *data;
			memcpy(ce->name, previous_ce->name, copy_len);
}
{

		return 1;

		 *
		write_eoie_extension(&sb, &eoie_c, offset);


	istate->cache_changed |= CE_ENTRY_REMOVED;
	struct index_entry_offset_table *ieot = NULL;
	 * written by default if the user explicitly requested
			  int strip_extensions)
		return 0;
	/*
			validate_index_cache_entries = 1;
	/*
		p->offset = offset;
		istate->ce_mem_pool = NULL;
	ondisk->mode = htonl(ce->ce_mode);
			break;
	 * Note that this actually does not do much for gitlinks, for
}
	struct index_state *istate;

		int ret;
	char *endp;
	case S_IFLNK:
	hdr_version = istate->version;
		if (ce_compare_data(istate, ce, st))

	 * the rest.
		return -1;

		pos = index_name_stage_pos(istate, ce->name, ce_namelen(ce), ce_stage(ce));

		struct cache_entry *next_ce = istate->cache[i];

				 *     this: xxx/B
	istate->cache = xcalloc(istate->cache_alloc, sizeof(*istate->cache));
		ieot->entries[ieot->nr].nr = nr;
			} else {
	if (verify_hdr(hdr, mmap_size) < 0)
	}

	ret = do_read_index(istate, path, 0);
	if (!ignore_fsmonitor)
	}

inside:
		if (!sb)
	const char *unmerged_fmt;
			*err = ENOENT;
}
	hdr.hdr_entries = htonl(entries - removed);

		if (!result)
	return 0;
	else
	int size;
	}
				 unsigned int write_flags,
	git_hash_ctx c, eoie_c;
#define CE_NAMEMASK  (0x0fff)
		struct diff_options opt;

	while (src_offset < mmap_size - the_hash_algo->rawsz - EOIE_SIZE_WITH_HEADER) {
	/*
		diff_flush(&opt);
static void copy_cache_entry_to_ondisk(struct ondisk_cache_entry *ondisk,
			 const struct stat_data *sd, struct stat *st)
	if (extension_offset && nr_threads > 1)
	int fd;
		return istate->cache_nr;
	struct cache_entry *updated;
{
 * not a regular file), -2 if an invalid flip argument is passed in, 0

		int i;


		if (!name_compare) {
 * A helper function that will load the specified range of cache entries

		if (src_offset + 8 + extsize < src_offset)
}



	 * we only have to do the special cases that are left.
	if (nr_threads > 1) {
	/* Count not shared entries */
			    (p->name[len] != '/') ||
	 * TODO trace2: replace "the_repository" with the actual repo instance
		  unsigned int options)
		result = ce_write(c, fd, ondisk, size);

#include "varint.h"
	case 'G':
	}
		src_offset += load_cache_entries_threaded(istate, mmap, mmap_size, nr_threads, ieot);
	struct mem_pool **pool_ptr;
	int pretend = flags & ADD_CACHE_PRETEND;
			if (!(istate->cache[pos]->ce_flags & CE_REMOVE)) {
	case -1: /* unset: do nothing */

	copy_cache_entry(new_entry, old_entry);

				struct stat *st)
#define CACHE_EXT_ENDOFINDEXENTRIES 0x454F4945	/* "EOIE" */
 */
}
	return data;


		shared_index_expire_date = approxidate(shared_index_expire);
	pos = -1 - pos;
		else if (ce_compare_gitlink(ce))

			if (!S_ISGITLINK(alias->ce_mode))
	p.mmap_size = mmap_size;
	/*
 * All cache entries associated with this index
			ieot_blocks = nr_threads;
int strcmp_offset(const char *s1, const char *s2, size_t *first_change)
				err = error(msg, ce->name);
		/* already handled in do_read_index() */
}
	for (i = 0; i < istate->cache_nr; i++) {
	return new_entry;
	case '+':
	if (len1 > len2)
		ce->ce_mode &= ~0111;
	size_t k;
			struct mem_pool *ce_mem_pool, int offset, int nr, const char *mmap,
			/*
		ce_mark_uptodate(ce);
		return NULL;
				estimate_cache_size(mmap_size, nr));

}

		flags |= extended_flags;
		shared_index_path = git_path("%s", de->d_name);
	if (ce && should_validate_cache_entries())
			break;
		unsigned char to_remove_vi[16];
				 */
	if (ce_match_stat_basic(ce, &st))
		(istate->timestamp.sec < sd->sd_mtime.sec ||
		if (copy_len)
{
	unsigned long src_offset;
{
		ce->ce_namelen = 0;
			if (!istate->split_index ||
		nr++;
static int write_index_ext_header(git_hash_ctx *context, git_hash_ctx *eoie_context,
	default: /* unknown value: do nothing */
		remove_index_entry_at(istate, pos);
	}
				/*
	int drop_cache_tree = istate->drop_cache_tree;

	int match = -1;
}

	/*
		} else if (cmp_last == 0) {
 * cache up-to-date for mode/content changes. But what it
		if (!strcmp(sha1_hex, current_hex))
	/*
	if (namelen && name[namelen - 1] == '/')
	 * their contents).  E.g. if we have "TREE" extension that is N-bytes
		cache_tree_write(&sb, istate->cache_tree);
			 * it is Ok to have a directory at the same
		break;
{
	default:
	 * running this command:
		unsigned int buffered = write_buffer_len;
			if (really && cache_errno == EINVAL) {
 * We helpfully remove a trailing "/" from directories so that
			if (len > len_eq_last) {
}

	 * 	echo frotz >file
			remove_name_hash(istate, ce_array[i]);
			*err = errno;
	if (istate->split_index)
			break;
	if (ret != ce)
					     sb.len) < 0

		return -1;
	 * "EOIE"
	}
	istate->version = ntohl(hdr->hdr_version);
{
				  ce->name, in_porcelain, &first, header_msg);
	if (!strip_extensions && istate->resolve_undo) {
					    unsigned int version,
			    (*rest == '\0' || is_dir_sep(*rest)))
					return 0;
int unmerged_index(const struct index_state *istate)
	istate->fsmonitor_has_run_once = 0;
	mmap_size = xsize_t(st.st_size);
	 * threaded index reads.

static inline struct cache_entry *mem_pool__ce_calloc(struct mem_pool *mem_pool, size_t len)

	return 0;
	struct index_state *istate;
		return;
				   the_repository, "%s", (*temp)->filename.buf);
				mark_fsmonitor_valid(istate, ce);
		load_index_extensions(&p);
	return ce;
	the_hash_algo->init_fn(&c);
			delete_tempfile(&temp);
			result = ce_write(c, fd, ce->name + common, ce_namelen(ce) - common);
		if (is_tempfile_active(temp))
	}
		/* count */
	 * TODO trace2: replace "the_repository" with the actual repo instance
		return MTIME_CHANGED;

		ret = do_write_locked_index(istate, lock, flags);
 * a 'close_lock_file_gently()`. Since that is an implementation
	if (extsize != EOIE_SIZE)

	else if (add_index_entry(istate, ce, add_option)) {
	changed = ie_match_stat(istate, ce, st, options);

 * Also, we don't want double slashes or slashes at the
	 * The hash is computed over extension types and their sizes (but not
	return ret;
void move_index_extensions(struct index_state *dst, struct index_state *src)
		 * $ : >frotz
	if (mmap_size < sizeof(struct cache_header) + EOIE_SIZE_WITH_HEADER + the_hash_algo->rawsz)
int ce_same_name(const struct cache_entry *a, const struct cache_entry *b)

}
			return 0;

		if (ret <= 0)

		(ce_write(context, fd, &sz, 4) < 0)) ? -1 : 0;
	}
		index += sizeof(uint32_t);
	}
		if (add_index_entry(istate, new_ce, ADD_CACHE_SKIP_DFCHECK))
}
	if (mmap == MAP_FAILED)
		     (pos < 0 && i < istate->cache_nr &&
		pos = index_pos_to_insert_pos(istate->cache_nr);
		if (ce_array[i]->ce_flags & CE_REMOVE) {
	if (istate->fsmonitor_last_update)
	put_be32(&buffer, IEOT_VERSION);
	case CACHE_EXT_FSMONITOR:
		 * default number of threads that will process them leaving
}
static void write_ieot_extension(struct strbuf *sb, struct index_entry_offset_table *ieot)
	/* starting byte offset into index file, count of index entries in this block */

		err = write_index_ext_header(&c, &eoie_c, newfd, CACHE_EXT_RESOLVE_UNDO,
			return ce;
		if (*ext < 'A' || 'Z' < *ext)
	hdr = (const struct cache_header *)mmap;
	if (!changed)
		discard_cache_entry(ce);
	 * that the change to the work tree does not matter and told
	uint32_t mode;
{
{
static int record_eoie(void)
	if (cmp)
	int intent_only = flags & ADD_CACHE_INTENT;
	 */

		if (version < INDEX_FORMAT_LB || INDEX_FORMAT_UB < version) {
		return changed;
{
		}
			static int allow = -1;
	 * <4-byte length>
#include "refs.h"
		src_offset += extsize;
					unsigned int options)
 */

		if (buffered == WRITE_BUFFER_SIZE) {
/* Allow fsck to force verification of the cache entry order. */
	finish_writing_split_index(istate);
		pos++;
			if (slash <= ce->name)
		);

	struct object_id cmp;
{
 * otherwise.
	 * sub-project).
	set_index_entry(istate, nr, ce);
	unsigned char c1, c2;
		return ret;
	if (in_porcelain && *first && header_msg) {

	remove_index_entry_at(istate, nr);
	int stage = ce_stage(ce);
static void write_eoie_extension(struct strbuf *sb, git_hash_ctx *eoie_context, size_t offset)
	}
	if (hdr->hdr_signature != htonl(CACHE_SIGNATURE))
		if (!skip_prefix(de->d_name, "sharedindex.", &sha1_hex))
			istate->updated_skipworktree ? "1" : "0", NULL);
		temp = mks_tempfile_sm(git_path("sharedindex_XXXXXX"), 0, 0666);
	 */
				 * entry, so the remainder cannot collide (because
			if (ce_stage(istate->cache[i]) == 2)
		  const struct pathspec *pathspec,
	return retval;
			die(_("index file corrupt"));
	 * Within 1 second of this sequence:
	int i, err = 0, removed, extended, hdr_version;
		extended_flags = get_be16(flagsp + 1) << 16;
		}
			nr = 0;
		return opt.flags.has_changes != 0;
		if (!S_ISLNK(st->st_mode) &&
	check_ce_order(istate);
 * index_state, dropping any unmerged entries to stage #0 (potentially
	ret = refresh_cache_entry(istate, ce, refresh_options);
		return -1;
	if (pos >= istate->cache_nr)
				die(_("unordered stage entries for '%s'"),
			return 1;
			/*
	uint32_t uid;
			if (S_ISLNK(mode)) {
	if (!ignore_fsmonitor && (ce->ce_flags & CE_FSMONITOR_VALID)) {
}

	*first_change = k;
	int has_errors = 0;
		if (trust_executable_bit &&
					 p->mmap + src_offset,
 * to have at least 10000 cache entries per thread for it to
		memset(ce, 0xCD, cache_entry_size(ce->ce_namelen));
		ce->ce_mode = ce_mode_from_stat(ent, st_mode);
{
	 * If the mode or type has changed, there's no point in trying
	ce->ce_mode = create_ce_mode(mode);
	 * long, "REUC" extension that is M-bytes long, followed by "EOIE",
		/* We consider only the owner x bit to be relevant for
		int v = si->base_oid.hash[0];
	validate_cache_entries(istate);
{
		if (rest[3] == '\0' || is_dir_sep(rest[3]))
 * subset of the name we're trying to add?
		if (!sv->sd)
		printf("add '%s'\n", path);

{
	 * that is associated with the given "istate".
 * Do we have another file that has the beginning components being a
	uint16_t *flagsp = (uint16_t *)(ondisk->data + hashsz);
	if (!c1 && S_ISDIR(mode1))
}

			if (!S_ISGITLINK(ce->ce_mode)) {

int is_index_unborn(struct index_state *istate)
		if (p->name[len] != '/')
	if (*rest == '\0' || is_dir_sep(*rest))
			return -1;
#ifdef GIT_WINDOWS_NATIVE
	int ignore_fsmonitor = options & CE_MATCH_IGNORE_FSMONITOR;
			cache[i]->ce_flags |= CE_EXTENDED;
		struct cache_entry *new_ce;

	istate->updated_skipworktree = 0;
				istate->cache_changed |= CE_ENTRY_CHANGED;
		strbuf_release(&sb);
		c = *path++;
		 CE_ENTRY_ADDED | CE_ENTRY_REMOVED | CE_ENTRY_CHANGED | \
	the_hash_algo->update_fn(&c, hdr, size - the_hash_algo->rawsz);
				cache_tree_invalidate_path(istate,
		/* verify the extension size isn't so large it will wrap around */
	for (k = 0; s1[k] == s2[k]; k++)

	/* validate the extension size */
	if (ce_intent_to_add(ce))
		return 0;

	 * case already exists within the Git repository.  If it does, ensure the directory


			istate->cache[istate->cache_nr - 1]->name,
static int ce_write_entry(git_hash_ctx *c, int fd, struct cache_entry *ce,
		const unsigned char *cp = (const unsigned char *)name;
		 * there can be arbitrary number of extended
		return err;
		if (err)
	/* istate->cache_changed is updated in the caller */
 * Read the index file that is potentially unmerged into given

	if (eoie_context) {
{
	for (i = p->ieot_start; i < p->ieot_start + p->ieot_blocks; i++) {
/*
	hashcpy(hash, write_buffer + left);
		free(ieot);
	c2 = name2[len];
	if (ce_stage(ce) == 1 && pos + 1 < istate->cache_nr &&
	if (pos >= 0) {

			return 0;
 * Returns -1 if the chmod for the particular cache entry failed (if it's
	offset = lseek(newfd, 0, SEEK_CUR);
 * that matches a sub-directory in the given entry?
				     unsigned int mode,
 */
{
				     const char *path,
	 * case-insensitively here, even if ignore_case is not set.

	mark_fsmonitor_invalid(istate, ce);

	}
	 * clients will have different views of what "device"
		 */

		const char *shared_index = git_path("sharedindex.%s",
	 * Locate and read the index entry offset table so that we can use it
	 * before it.
	if (left) {
		die_errno(_("%s: unable to map index file"), path);
	index += sizeof(uint32_t);
			if (quiet)
	return ce;
		istate->untracked = read_untracked_extension(data, sz);
	 */
	 * in the array.
}

	 * Adjacent cache entries tend to share the leading paths, so it makes
	 */
	if (sd->sd_mtime.sec != (unsigned int)st->st_mtime)

	 * CE_VALID or CE_SKIP_WORKTREE means the user promised us
	const char *index = NULL;
				const char *path, unsigned long *size)

static void post_read_index_from(struct index_state *istate)
	return ret;
	}
#include "utf8.h"
	fd = repo_hold_locked_index(repo, &lock_file, 0);
		      common < previous_name->len &&

		return 0;

		int len;
	int len = ce_namelen(ce);
	int stage = ce_stage(ce);
{

	 * 	echo xyzzy >file && git-update-index --add file
			previous_len = previous_ce->ce_namelen;
				 * last: xxx/yy-file (because '-' sorts before '/')
	mem_pool_allocated = new_entry->mem_pool_allocated;

		struct ondisk_cache_entry *disk_ce;
		if (err)
		 * in 4-byte network byte order.

					     int *changed_ret)
	if (nr_threads != 1 && record_ieot()) {
		int ieot_blocks, cpus;
	preload_index(istate, pathspec, 0);
			sd->sd_gid != (unsigned int) st->st_gid)

static int is_racy_stat(const struct index_state *istate,
			return -1;
		if (pathspec && !ce_path_match(istate, ce, pathspec, seen))
	return ret;
 * rely on it.
{

	}
		break;
	/*
	 * Account for potential alignment differences.
	 */
			ce_write(&c, newfd, sb.buf, sb.len) < 0;
	if ((flags & SKIP_IF_UNCHANGED) && !istate->cache_changed) {
	struct progress *progress = NULL;
	 * returned by ie_match_stat() which in turn was returned by
		    ce->name, alias->name);
	ondisk->dev  = htonl(ce->ce_stat_data.sd_dev);
}
	}
}
	fill_stat_cache_info(istate, updated, &st);
		return ret;
 * CE_REMOVE is set in ce_flags.  This is much more effective than
	int nr_threads, cpus;



					if (is_hfs_dotgitmodules(path))
	src_offset = sizeof(*hdr);
	struct index_entry_offset_table *ieot;
void rename_index_entry_at(struct index_state *istate, int nr, const char *new_name)
	}
					   struct cache_entry *ce,

	 * entry's directory case.
			continue;

	int not_new = (flags & REFRESH_IGNORE_MISSING) != 0;
		if (alias &&
		}

#define CACHE_EXT_TREE 0x54524545	/* "TREE" */
 * resulting in a path appearing as both a file and a directory in the
	if (!ignore_valid && assume_unchanged &&
		freshen_shared_index(shared_index, 1);
		if (!result)
			index = mmap + offset + 4 + 4;
	ce = make_empty_cache_entry(istate, len);
	return 0;
			 * I am being removed".  Such an entry is

	size_t len_eq_last;
	trace2_region_leave_printf("index", "shared/do_read_index",
	if (validate_index_cache_entries < 0) {
			alias->ce_flags |= CE_ADDED;
		first = next+1;
		return 0;
	if (ret)
		return -1;
				 char *seen, const char *header_msg)
		p->offset += p->ieot->entries[i].nr;
		return ce;
	int fd, ret = 0;
			if (len_eq_last == 0) {
	flags = get_be16(flagsp);
			 * code handle it.
	int ignore_fsmonitor = options & CE_MATCH_IGNORE_FSMONITOR;
 * while a directory name compares as equal to a regular file, they
void remove_marked_cache_entries(struct index_state *istate, int invalidate)
			 */
		put_be32(&buffer, ieot->entries[i].offset);
		extsize = ntohl(extsize);
		if (!c)
		previous_ce = ce;
	strbuf_add(sb, &buffer, sizeof(uint32_t));
			continue;
	int match = -1;
	 * The only thing we care about in this function is to smudge the
	struct cache_entry *ce = istate->cache[pos];
		post_read_index_from(istate);
		fill_fsmonitor_bitmap(istate);

 * is being added, or we already have path and path/file is being
		return -1;
				return retval;
					     unsigned int options, int *err,

				 * at, so we cannot have conflicts at our
}
				/*
	return (unsigned char)s1[k] - (unsigned char)s2[k];
			show_file(fmt,
	while ((de = readdir(dir)) != NULL) {
}
	unsigned int i;

	int ret;
		if (ret)
}
}
				 * index, but has a common prefix.  Fall through
		nr_threads = 1;
			removed++;
	if (!c2 && S_ISDIR(mode2))
	int retval = 0;
			opt.flags.quick = 1;
		to_remove = previous_name->len - common;
}
	int ignore_submodules = (flags & REFRESH_IGNORE_SUBMODULES) != 0;
				 * the trailing slash) is longer than the known
			return 0;
{
		ret = close_lock_file_gently(lock);
int should_validate_cache_entries(void)
			init_split_index(istate);
			rollback_lock_file(lock);
{
		err = write_index_ext_header(&c, &eoie_c, newfd, CACHE_EXT_INDEXENTRYOFFSETTABLE, sb.len) < 0
		new_entry = refresh_cache_ent(istate, ce, options, &cache_errno, &changed);
	 * skip-worktree has the same effect with higher precedence
			if (protect_hfs) {
	trace_performance_enter();
	if (!previous_name) {
	 * case-insensitively).
	per_entry += align_padding_size(per_entry, 0);
	ce->ce_stat_data.sd_uid   = get_be32(&ondisk->uid);
	pos = index_name_pos(istate, path, len);
			len += copy_len;
	/*
			if (previous_name)
	 */
		 * there can be arbitrary number of extended
				     new_ce->name);
	}

		 * $ git-update-index --add frotz
	}
			if (cache_errno == ENOENT)
			last = next;
	/* hash */

	 *

{
	if (len == CE_NAMEMASK) {
		struct cache_entry *ce;
							   ce_array[i]->name);
				i++;
 * On success, `tempfile` is closed. If it is the temporary file
	 */
 * Mostly randomly chosen maximum thread counts: we
		if (ignore_valid && assume_unchanged &&
 */
	int refresh = options & CE_MATCH_REFRESH;
/* Allow fsck to force verification of the index checksum. */
	/* iterate across all ieot blocks assigned to this thread */
	 */
	if (stage1 < stage2)
	/*
	}
			       ! strcmp(istate->cache[i]->name, ce->name))
 * associated with this index, or by a referenced
	 * cache entries. validate_cache_entries can detect when this
	default:
static int record_ieot(void)
#include "dir.h"
					    unsigned long *ent_size,
	freshen_shared_index(base_path, 0);
		      int * first, const char *header_msg)
	if (!strip_extensions && istate->split_index &&
						    oid_to_hex(&si->base_oid));
		ce->ce_mode |= 0111;
void discard_cache_entry(struct cache_entry *ce)


/*
	memcpy(ce->name, path, len);
	switch (ce->ce_mode & S_IFMT) {
		 * no reason to write out the IEOT extension if we don't
	ret = adjust_shared_perm(get_tempfile_path(*temp));
	 * whose mtime are the same as the index file timestamp more
	int new_shared_index, ret;
			version = r->settings.index_version;
		new_ce->ce_namelen = len;
						 int nr_threads, struct index_entry_offset_table *ieot)

	size_t mmap_size;
	ce->ce_flags = create_ce_flags(stage);
		if (!nr_threads) {
	return ce_namelen(b) == len && !memcmp(a->name, b->name, len);
	if (istate->initialized)
	}
	changed |= match_stat_data(&ce->ce_stat_data, st);
			|| ce_write(&c, newfd, sb.buf, sb.len) < 0;
	 */
		 */
	if (!refresh || ce_uptodate(ce))
 *
{
 * This is an estimate of the pathname length in the index.  We use
				die(_("malformed name field in the index, near path '%s'"),
	return ieot;
		changed |= CTIME_CHANGED;
	return 0;
static int should_delete_shared_index(const char *shared_index_path)
				}
				!mem_pool_contains(istate->split_index->base->ce_mem_pool, istate->cache[i])) {
int discard_index(struct index_state *istate)

}
static int compare_name(struct cache_entry *ce, const char *path, int namelen)
	cache_tree_invalidate_path(istate, path);
	if (0 <= pos)
 * of a `struct lock_file`, we will therefore effectively perform
		if (S_ISGITLINK(ce->ce_mode))
 * then individually compare _differently_ to a filename that has
	istate->cache_changed |= CE_ENTRY_CHANGED;
#define CACHE_EXT(s) ( (s[0]<<24)|(s[1]<<16)|(s[2]<<8)|(s[3]) )
			struct cache_entry *p = istate->cache[pos];
static struct cache_entry *create_from_disk(struct mem_pool *ce_mem_pool,
}
{

	return ret;
	istate->initialized = 1;
			return -1;
		error(_("invalid path '%s'"), path);
/*
	 * if (flags & CE_EXTENDED)
	 * <20-byte hash>
				return retval;
		     i++)
		 * room for the thread to load the index extensions.
	if (!*pool_ptr)
	for (i = removed = extended = 0; i < entries; i++) {
	prepare_repo_settings(r);
	int len;
	ce->ce_flags |= CE_UPDATE_IN_BASE;
	default:
	printf(fmt, name);
				show_file(unmerged_fmt, ce->name, in_porcelain,
static int ce_write_flush(git_hash_ctx *context, int fd)
 * want to recurse into ".git" either.
		if (!new_entry) {
	strbuf_release(&previous_name_buf);

	 */
	struct load_cache_entries_thread_data *p = _data;
	 * will always replace all non-merged entries..
	 * The first character was '.', but that
		ieot->entries[i].nr = get_be32(index);
	size_t min_len = (len1 < len2) ? len1 : len2;
}
	return ret;
		retval = -1;
				BUG("cache entry is not allocated from expected memory pool");
		}
	if (!c2 && S_ISDIR(mode2))
		display_progress(progress, istate->cache_nr);
		}

{
			int err;
	fill_stat_data(&ce->ce_stat_data, st);
	     has_racy_timestamp(repo->index)) &&
	return 0;
	return retval + has_dir_name(istate, ce, pos, ok_to_replace);
	 * Lets write out CACHE_EXT_INDEXENTRYOFFSETTABLE first so that we
static int ce_compare_gitlink(const struct cache_entry *ce)
		return NULL;
int match_stat_data(const struct stat_data *sd, struct stat *st)
			continue;
	 * blob changed.  We have to actually go to the filesystem to

 * necessary for a correct operation (i.e. optimization data).
	/*
	}
	const char *deleted_fmt;
		    const char *name2, int len2, int mode2)
		if (err)
	int len = len1 < len2 ? len1 : len2, cmp;
}
{
	}
		for (i = 0; sb && i < istate->cache_nr; i++) {
}

	 */
		istate->version = extended ? 3 : 2;
			if (!ce_stage(ce))
			}

	sd->sd_dev = st->st_dev;
static int has_dir_name(struct index_state *istate,
int add_file_to_index(struct index_state *istate, const char *path, int flags)
	if (!should_validate_cache_entries() ||!istate || !istate->initialized)
	if (ieot && nr) {

	istate->cache_nr++;
		write_buffer_len = buffered;
	trace2_region_enter_printf("index", "shared/do_write_index",
	/* order of preference: stage 2, 1, 3 */
	if (ie_modified(istate, ce, &st, options)) {
		    (0100 & (ce->ce_mode ^ st->st_mode)))
{
}
	fd = open(path, O_RDONLY);
	len = strlen(path);
			continue;
			p.src_offset = extension_offset;
	int allow_unmerged = (flags & REFRESH_UNMERGED) != 0;
			   istate->version);
	if (sd->sd_size != (unsigned int) st->st_size)

		result = ce_write(c, fd, ondisk, size);
	 * sense to only store the differences in later entries.  In the v4
			   struct strbuf *sb)
{
		pos = istate->cache_nr;
		ieot->entries[ieot->nr].offset = offset;

		else
	}
	int pos;
	}
		else
			 */
	 * be appended to the index, rather than inserted in the middle.
				   "%s", lock->tempfile->filename.buf);
static int has_racy_timestamp(struct index_state *istate)
		refresh_fsmonitor(istate);
 * Signal that the shared index is used by updating its mtime.
				 * The directory prefix (including the trailing
	 */
			pos = -pos-1;
		ieot = read_ieot_extension(mmap, mmap_size, extension_offset);
		if (ce_write_entry(&c, newfd, ce, previous_name, (struct ondisk_cache_entry *)&ondisk) < 0)
			if (protect_ntfs) {

	}
	struct cache_entry *ce, *alias = NULL;

	ret = do_write_locked_index(istate, lock, flags);
	git_hash_ctx c;

	if (!strip_extensions && istate->fsmonitor_last_update) {
		fill_stat_data(sv->sd, &st);
		if (sd->sd_uid != (unsigned int) st->st_uid ||
			if (i)
{
	if (mmap_size < sizeof(struct cache_header) + the_hash_algo->rawsz)
		discard_cache_entry(ce);
}
	discard_split_index(istate);
	 * list of pathnames and while building a new index.  Therefore,
	int i;
					       sb.len) < 0 ||
	/* Freshen the shared index only if the split-index was written */
		warning(_("could not freshen shared index '%s'"), shared_index);
		die_errno(_("%s: index file open failed"), path);
		strbuf_release(&sb);
	 */
	the_hash_algo->init_fn(&c);
#include "commit.h"
	ondisk->size = htonl(ce->ce_stat_data.sd_size);
			offset += ieot->entries[ieot_start + j].nr;
{
{
	if (refresh_index(repo->index, refresh_flags, pathspec, seen, header_msg))
#define WRITE_BUFFER_SIZE 8192
 * dev/ino/uid/gid/size are also just tracked to the low 32 bits
		return cmp;
		die(_("%s: index file smaller than expected"), path);
	    repo_verify_index(repo))
#include "split-index.h"
				 * index and their paths have no common prefix,
	if (stat(path, &st) < 0)
	 * first, since removing those will not change the position

	return match;
	int fd = git_open_cloexec(ce->name, O_RDONLY);
		stop_progress(&progress);

	trace_performance_leave("read cache %s", base_path);
	unsigned int buffered = write_buffer_len;

		ce->ce_flags &= ~CE_STRIP_NAME;
		return changed;
	ieot->nr = nr;
	const char *name;
	uint32_t buffer;
			continue;
				if (is_ntfs_dotgit(path))
	if (pos < 0)

	if (!(option & ADD_CACHE_KEEP_CACHE_TREE))
static unsigned long write_buffer_len;
					return 0;

void validate_cache_entries(const struct index_state *istate)
			if (ieot_blocks > cpus - 1)
	ce->ce_namelen = len;
	unsigned long consumed;
	return mem_pool__ce_calloc(find_mem_pool(istate), len);
		add_untracked_cache(istate);
	}
	for (i = 0; i < istate->cache_nr; i++) {
		if (0 < name_compare)
	for (i = 0; i < entries; i++) {
	if (!sv->sd)
{
				ieot_blocks = cpus - 1;
 * Remove all cache entries marked for removal, that is where
	const struct cache_header *hdr;
			return 0;
/*****************************************************************
	int fd;
			     unsigned flags)
			return error(_("'%s' appears as both a file and as a directory"),

				 * This part of the directory prefix (excluding
	offset = ieot_start = 0;
{
{
		return 0;

		if (err)
		err = write_index_ext_header(&c, &eoie_c, newfd, CACHE_EXT_TREE, sb.len) < 0
	struct stat st;
	}
		return 0;
		if (!ce->index)
		copy_cache_entry_to_ondisk(ondisk, ce);
	} else {
		return;
	if (stat(tempfile->filename.buf, &st))
	if (stat(shared_index_path, &st))
		}

	struct stat st;

	 * strip_extensions parameter as we need it when loading the shared
		if (cmp_last > 0) {
	}


}
		return istate->cache_nr;
			mem_pool_init(&p->ce_mem_pool,
{
	case CACHE_EXT_INDEXENTRYOFFSETTABLE:
		warning(_("GIT_INDEX_VERSION set, but the value is invalid.\n"
		}
		err = pthread_join(p->pthread, NULL);
				 */
	 */
	else
	const uint16_t *flagsp = (const uint16_t *)(ondisk->data + hashsz);
	set_index_entry(istate, pos, ce);
 * but then handle conflicting entries together when possible.
	unsigned char hash[GIT_MAX_RAWSZ];
		return pos;
	unsigned long src_offset = start_offset;
#include "progress.h"
static int write_split_index(struct index_state *istate,
			return -1;
		 * Trivial optimization: if we find an entry that
	const char *mmap;
		the_hash_algo->update_fn(eoie_context, &sz, 4);
	src->untracked = NULL;
	remove_name_hash(istate, old);
	else
{
		   istate->cache_nr - pos);
	}
	return ce;
		return version;
	if (mmap + offset < mmap + sizeof(struct cache_header))
					  ce_namelen(ce), ignore_case);
#endif
	}
	if (ce_write(&c, newfd, &hdr, sizeof(hdr)) < 0)
	/* "." is not allowed */
	 *
{
			   struct tree *tree,
	return 0;
			break;
	typechange_fmt = in_porcelain ? "T\t%s\n" : "%s: needs update\n";
/*
/*
	unsigned long size;
			 * let the regular search code handle it.
	struct split_index *split_index;
		cmp = tree->object.oid;
 * from the cache so the caller should recompute the insert position.

	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode))
{
int is_racy_timestamp(const struct index_state *istate,
	if (resolve_gitlink_ref(ce->name, "HEAD", &oid) < 0)
	trace2_region_leave_printf("index", "do_write_index", the_repository,
		 * size to zero here, then the object name recorded
	/*
		 */

			|| ce_write(&c, newfd, sb.buf, sb.len) < 0;

	c1 = name1[len];
	int retval = 0;
	if (has_symlink_leading_path(ce->name, ce_namelen(ce))) {
void *read_blob_data_from_index(const struct index_state *istate,
	ce->mem_pool_allocated = 1;
	ce->ce_stat_data.sd_size  = get_be32(&ondisk->size);
		src_offset += extsize;
int index_name_pos(const struct index_state *istate, const char *name, int namelen)
			continue;
	if (!ret && !new_shared_index && !is_null_oid(&si->base_oid)) {
			continue;
		strbuf_add(sb, &buffer, sizeof(uint32_t));
		*size = sz;
	merge_base_index(istate);
	 * Inserting a merged entry ("stage 0") into the index
 */
	the_hash_algo->final_fn(hash, &c);
			   istate->version);
