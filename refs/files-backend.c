

}
			goto error_return;
			       struct ref_dir *dir, const char *dirname)
}

			 */
	}
		goto rollbacklog;

		struct ref_lock *lock = update->backend_data;
 * update to HEAD.
						    "error reading reference",
		return 0;
	for (i = 0; i < transaction->nr; i++) {
	 * Perform deletes now that updates are safely completed.
}
			rollback_lock_file(&reflog_lock);
{
						    original_update_refname(update));
	iter->dir_iterator = diter;
					    struct ref_transaction *transaction,
		fprintf(stderr, "no symlink - falling back to symbolic ref\n");
			files_ref_path(refs, &path, newrefname);
	} else {
		 * reason to expect this error to be transitory.
	    (message[1] != '+' && message[1] != '-') ||
out:
		ref_transaction_free(packed_transaction);
		 * a reference if there are no remaining reflog
		else
					    refname);
		error("unable to restore logfile %s from %s: %s",
			 * write_ref_to_lockfile():
	struct strbuf ref_file = STRBUF_INIT;
}
}
	/* Follow "normalized" - ie "refs/.." symlinks by hand */
	if (!sb->len || sb->buf[sb->len - 1] != '\n' ||
/* make sure nobody touched the ref, and unlink */
	struct files_ref_store *refs =
	struct strbuf err = STRBUF_INIT;
			}
	cb.flags = flags;
		if (starts_with(sb_contents.buf, "refs/") &&
	iter->iter0 = overlay_iter;
	if (fseek(logfp, 0, SEEK_END) < 0)
		 */
	update_symref_reflog(refs, lock, refname, target, logmsg);
{
	struct stat loginfo;
			}
	strbuf_release(&sb);
 * necessary error messages.
		return -1;
	if (!(update->flags & REF_NEEDS_COMMIT)) {
						 REFNAME_ALLOW_ONELEVEL)) {
			char *write_err = strbuf_detach(err, NULL);
	struct files_ref_store *refs =
	if (ref_iterator_abort(ref_iterator) == ITER_ERROR)
static int files_init_db(struct ref_store *ref_store, struct strbuf *err)
			if (ret)
 */
			 * the transaction, so we have to read it here
				ret = TRANSACTION_GENERIC_ERROR;
		child_entry = create_dir_entry(dir->cache, prefix, prefix_len, 1);
	/* Do not pack broken refs: */
	ret = 0;
		if (ret)
		 * hold references:
	const char *prefixes[] = { "refs/bisect/", "refs/worktree/", "refs/rewritten/" };
	cb.tmp_renamed_log = tmp.buf;
static int files_transaction_abort(struct ref_store *ref_store,
	strbuf_addstr(&buf, refname);
		/*
	struct files_ref_store *refs =
};
		break;
		files_downcast(ref_store, REF_STORE_READ, "fill_ref_dir");
	for (i = 0; i < refnames->nr; i++) {
	strbuf_release(&sb_newref);
		}
		const char *prefix = prefixes[ip];
		BUG("operation %s requires abilities 0x%x, but only have 0x%x",
 */
	FILE *logfp;

				flag |= REF_ISBROKEN;
		int flag;
					packed_transaction;
 * been deleted.

	/*
		break;
 * are consistent with oid, which is the reference's current value. If
			      struct strbuf *referent, unsigned int *type)
}
	for (i = 0; i < transaction->nr; i++) {
 */
				strbuf_splice(&sb, 0, 0, bp + 1, endp - (bp + 1));
		resolve_flags |= RESOLVE_REF_ALLOW_BAD_NAME;
	log_file = strbuf_detach(&log_file_sb, NULL);
static const char *original_update_refname(struct ref_update *update)
					    "%s", logfile, strerror(errno));
		if (refs_read_ref_full(iter->ref_store,
		copy_reflog_msg(&sb, msg);
		strbuf_release(&err);
#define REF_DELETED_LOOSE (1 << 9)
	 *
		/*
{
			 * lockfile into place later.
					packed_transaction, update->refname,
	strbuf_reset(&sb);
		refs->loose = NULL;
		while (*p == '/')
	/*
	strbuf_release(&err);
		if (!(iter->flags & DO_FOR_EACH_INCLUDE_BROKEN) &&
		goto error_return;
			BUG("initial ref transaction with old_sha1 set");

					 create_dir_entry(dir->cache, refname.buf,

 * the iteration gets to it.
			bp = find_beginning_of_line(buf, scanp);
		return error("unable to write symref for %s: %s", refname,
		struct ref_store *ref_store,
	if (log && rename_tmp_log(refs, newrefname))
			reflog_iterator_begin(ref_store, refs->gitdir),
	}
};
		}
{
				     each_reflog_ent_fn fn, void *cb_data)
	case REF_TYPE_OTHER_PSEUDOREF:
			ret = error("cannot read %d bytes from reflog for %s: %s",

	files_assert_main_repository(refs, "commit_ref_update");
			    update->refname);

		return 0;
}

	if (parse_oid_hex(buf, oid, &p) ||
	 * (If they've already been read, that's OK; we only need to
			 */
		 * symref update, record the old OID in the parent
		if (refs_verify_refname_available(

	 * points to it (may happen on the remote side of a push

	/* Jump to the end */
}
	}
	if (fd >= 0)
			BUG("REF_IS_PRUNING set without REF_NO_DEREF");

	void *cb_data)
				if (!refname_is_safe(refname.buf))
	if (!lock) {
	}
}
			lk, path, LOCK_NO_DEREF,
 * at a newly-allocated lock object. Fill in lock->old_oid, referent,
			error("unable to copy '%s' to '%s': %s", oldrefname, newrefname, err.buf);
			}
	strbuf_release(&sb);
	files_reflog_path(refs, &sb_newref, newrefname);
			ret = TRANSACTION_GENERIC_ERROR;
	struct files_ref_iterator *iter =
		char *reason;
	 * mildly invalid repository state):
		 * ref is supposed to be, there could still be a
	if (!ref_resolves_to_object(refname, oid, ref_flags))

			/*
						 err)) {

				  &type, &err);

		}

	return hold_lock_file_for_update_timeout(
			ret = 0;
				if (!packed_transaction) {
}
{
			 * we don't require that the reference already
		 * Add a reference creation for this reference to the
	if (write_in_full(fd, oid_to_hex(oid), the_hash_algo->hexsz) < 0 ||
	struct ref_iterator *iter;
				strbuf_addf(err, "couldn't set '%s'", lock->ref_name);
	/*
			}
	base_ref_iterator_init(ref_iterator, &files_ref_iterator_vtable,
			       const char *refname)
	struct strbuf tmp = STRBUF_INIT;
		size_t nread;
			if (!refs_verify_refname_available(
 * Read the loose references from the namespace dirname into dir
	logfp = fopen(sb.buf, "r");
		 * If this fails, commit_lock_file() will also fail
	 */
	int ret = 0;

		return -1;
	return ok;
						lock->ref_name,
					strbuf_addf(err, "there is a non-empty directory '%s' "
			scanp--;
	return 0;
				 * just means we are at the exact end of the
	*type = 0;
	 * unsafe to try to remove loose refs, because doing so might

{

	if ((update->flags & REF_HAVE_NEW) && is_null_oid(&update->new_oid))
						     refname.buf,
					      prefix, 1);
		/*
			else if (errno == EISDIR)
		strbuf_reset(&sb);
	 * try again starting with the lstat().
		 * itself needs to be split.
	if (ref_transaction_commit(transaction, &err))

		}
				    "cannot update ref '%s': %s",
		 * Add a reference creation for this reference to the
	/*
		/* An entry already exists */
		BUG("ref_store is type \"%s\" not \"files\" in %s",
	 * *how much* before.) After that, we call

		 * It doesn't make sense to adjust a reference pointed
	if (!lock) {
	struct files_ref_iterator *iter =
	 * ones in files_ref_iterator_advance(), after we have merged
			/*
	return ret;
		strbuf_release(&err);
				 * the data from the next read.
	return 0;
		files_reflog_path(refs, &sb, refname);
};

	files_reflog_path(refs, &sb, refname);
		strbuf_addf(err,
			errno = save_errno;
{
		goto out;
	while ((ok = ref_iterator_advance(iter)) == ITER_OK) {
	struct object_id ooid, noid;
 *   avoided, namely if we were successfully able to read the ref
	}
			error("unable to delete existing %s", newrefname);
		goto out;
	 * accessing the packed-refs file; this avoids a race
		strbuf_addf(err, "unable to create directory for %s",
	struct ref_cache *loose;
		/*
static int write_ref_to_lockfile(struct ref_lock *lock,
		/*
			try_remove_empty_parents(refs, update->refname,
			struct ref_to_prune *n;
				     const char *refname,
}
	if (logmoved && rename(sb_newref.buf, sb_oldref.buf))
{
			continue;
	return 0;
 * conflict with REF_NO_DEREF, REF_FORCE_CREATE_REFLOG, REF_HAVE_NEW,
	refs_for_each_reflog_ent(ref_store, refname, expire_reflog_ent, &cb);
		BUG("unknown ref type %d of ref %s",
		log_all_ref_updates = is_bare_repository() ? LOG_REFS_NONE : LOG_REFS_NORMAL;
static int files_create_reflog(struct ref_store *ref_store,
	log_all_ref_updates = LOG_REFS_NONE;
		}
		BUG("reverse reflog parser had leftover data");
		    !(update->flags & REF_IS_PRUNING)) {
 */
			    "couldn't write '%s'", get_lock_file_path(&lock->lk));
			ref_transaction_add_update(
	switch (ref_type(refname)) {
 *
	*type = 0;
			printf("would prune %s", message);
	return ok;
	clear_loose_ref_cache(refs);
	/* First lock the file so it can't change out from under us. */
	}
			    oldrefname, strerror(errno));
				strbuf_addf(err, "unable to resolve reference '%s'",
out:
				strbuf_addf(err, "cannot update the ref '%s': %s",
/*
				if (refs_verify_refname_available(
	if (log_ref_setup(refs, refname, force_create, &fd, err))
	files_ref_path(refs, &sb, "refs/heads");
		 * update:
		}
		/*

	int fd;
		struct ref_entry *child_entry;
				    oldrefname);
		*refs_to_prune = r->next;
	}
/*
	if (!fdopen_lock_file(&lock->lk, "w"))
{
						    "blocking reference '%s'",
{
				/*
	char *logfile;
	 */
	 * so here we really only check that none of the references
	    !message || message[0] != ' ' ||


			    oid_to_hex(&update->old_oid));
				/*
		strbuf_addf(err,

	transaction->backend_data = backend_data;

 * `ref_update::flags`.
		return error("unable to fdopen %s: %s",
	/*
		}
}
				oid_to_hex(&cb.last_kept_oid), the_hash_algo->hexsz) < 0 ||
	ref_iterator = &iter->base;
		transaction->backend_data;
			 * and verify old_oid for this update as part
			    "via symref '%s') are not allowed",

		 * free up the file descriptor:
	int ok;
		if (hold_lock_file_for_update(&reflog_lock, log_file, 0) < 0) {
			}
				 * (supposing that we are trying to lock
	iter->iter0 = NULL;


	 * size, but it happens at most once per symref in a
		/*
		goto cleanup;
	    email_end[1] != ' ' ||
	if (write_ref_to_lockfile(lock, &orig_oid, &err) ||
	 * this case. So ask the packed_ref_store for all of its

		goto out;
	struct lock_file reflog_lock = LOCK_INIT;
 * Die if refs is not the main ref store. caller is used in any
	int dirnamelen = strlen(dirname);
{

	flag = log_all_ref_updates;
	 * First, we call start the loose refs iteration with its
			    const char *logmsg)
			transaction, referent, new_flags,
	 * The packed-refs file might contain broken references, for
	if (hold_lock_file_for_update_timeout(
		if (nread != 1) {
	struct strbuf log_file_sb = STRBUF_INIT;
	struct ref_store *ref_store;
			continue;
				 * line, and we have everything for this one.
	struct strbuf sb = STRBUF_INIT;
				 * may get here even if *bp was a newline; that
				 * middle.
	int ret = 0;
		die("unable to write new packed-refs: %s", err.buf);
		unlock_ref(lock);
	strbuf_release(&sb);
	files_ref_path(refs, &ref_file, refname);
						  const char *gitdir)
			continue;
		}
}
{
	strbuf_release(&buf);
{
	struct strbuf ref_file = STRBUF_INIT;
				   struct object_id *peeled)
				  NULL, NULL, REF_NO_DEREF, NULL,
static int create_symref_locked(struct files_ref_store *refs,
}
		int save_errno = errno;
			       "for_each_reflog_ent");

 * - Deal with possible races with other processes
			      const char *refname, struct object_id *oid,
	}
	return ret;
	files_reflog_path(refs, &sb, refname);
		goto out;

		strbuf_addf(sb, "%s/worktrees/%.*s/logs/%s", refs->gitcommondir,
					      unsigned int required_flags,
		while (q > p && *(q-1) == '/')
{
			       mustexist ? RESOLVE_REF_READING : 0,
static struct ref_iterator *reflog_iterator_begin(struct ref_store *ref_store,

	if (!logfp)
		}
				 * start of the file; there is no previous
			    original_update_refname(update),
	errno = save_errno;
	if (worktree_name)
 * Used as a flag in ref_update::flags when a loose ref is being

}
	    commit_ref_update(refs, lock, &orig_oid, NULL, &err)) {

 * necessary, using the specified lockmsg (which can be NULL).
			}
}
			errno = ENOENT;
	while ((ok = dir_iterator_advance(diter)) == ITER_OK) {
			    "multiple updates for '%s' (including one "
		    !(update->flags & REF_LOG_ONLY) &&
			       unsigned int flags,
			    oid_to_hex(oid),
		return;
		strbuf_addf(sb, "%s/logs/%s", refs->gitcommondir,
		/*
	 * Special hack: If a branch is updated directly and HEAD
		free(old_msg);
			goto stat_ref;
				try_remove_empty_parents(refs, update->refname,
				if (unlink_or_msg(sb.buf, err)) {

				/*
			error("bad ref for %s", diter->path.buf);
		}
		files_downcast(ref_store, REF_STORE_WRITE, "create_reflog");
			}
	files_delete_refs,
static int files_reflog_iterator_advance(struct ref_iterator *ref_iterator)
				strbuf_reset(&sb);
				 */
			struct strbuf *referent,

		strbuf_addstr(&path, de->d_name);
		} else if (errno == EISDIR) {
			 * The file that is in the way isn't a loose
			error("cannot fdopen %s (%s)",
			if (!unlink_or_warn(sb.buf))
};
		return ITER_OK;
		ret = -1;
		 * treating it like a non-symlink, and reading whatever it

			       overlay_iter->ordered);
	 * overrides it, and we don't want to emit an error message in
			 * itself, but not free. Do that now, and disconnect
				oid_to_hex(ooid), oid_to_hex(noid),
				ret = show_one_reflog_ent(&sb, fn, cb_data);
	}
				goto error_return;
	lock = xcalloc(1, sizeof(struct ref_lock));
 * everything is OK, return 0; otherwise, write an error message to
				flag |= REF_ISBROKEN;
	}
	return files_copy_or_rename_ref(ref_store, oldrefname,
				unlock_ref(lock);
	struct ref_iterator *ref_iterator;
	return ret;

#include "refs-internal.h"
	/*
			       struct strbuf *err)
		if (diter->basename[0] == '.')
		cb.newlog = fdopen_lock_file(&reflog_lock, "w");
 * - If it is a symref update without REF_NO_DEREF, split it up into a
		goto rollback;
			REF_NO_DEREF | REF_HAVE_NEW | REF_HAVE_OLD | REF_IS_PRUNING,

	struct dirent *de;
 * Prune the loose versions of the references in the linked list
		free(reason);

	 * "HEAD" and "master" branches before calling this function,
				      oid, referent, type)) {
	if (files_log_ref_write(refs, lock->ref_name,
					 * The error message set by
	lock = lock_ref_oid_basic(refs, oldrefname, NULL, NULL, NULL,
			    NULL, REF_NO_DEREF)) {
			    "via its referent '%s') are not allowed",
	clear_loose_ref_cache(refs);
			struct ref_lock **lock_p,
	if (commit_ref(lock) < 0)

					ret = TRANSACTION_NAME_CONFLICT;
		 * because there was a non-directory in the way. This
		      refnames->items[0].string, err.buf);
		struct ref_update *update = transaction->updates[i];
	closedir(d);
	int ret;
 * Used as a flag in ref_update::flags when we want to log a ref
	for (i = 0; i < 2; i++) { /* refs/{heads,tags,...}/ */
	case REF_TYPE_PSEUDOREF:

		goto error_return;
	BUG("operation %s only allowed for main ref store", caller);
	if (!transaction)
	item = string_list_insert(affected_refnames, new_update->refname);
	    refs_verify_refname_available(refs->packed_ref_store, refname,
	 * updated too.
 * set *logfd to -1. On failure, fill in *err, set *logfd to -1, and
			if (!refs_resolve_ref_unsafe(&refs->base,
					strbuf_addf(err, "cannot lock ref '%s': "
	"files",

	struct strbuf sb_contents = STRBUF_INIT;
			       struct strbuf *err)
		 */
	files_reflog_expire
		ret = error("unable to move logfile logs/%s to logs/"TMP_RENAMED_LOG": %s",
		goto cleanup;
		    ref_type(refname), refname);
			    close_ref_gently(lock) < 0)) {
			break;
		ok = ITER_ERROR;
		strbuf_setlen(&refname, dirnamelen);
		    update->flags & REF_LOG_ONLY) {

	if (!logmoved && log &&
		char *endp, *scanp;
				strbuf_addf(err, "there are still logs under '%s'",
 * - A new, separate update for the referent reference
	if ((update->flags & REF_HAVE_NEW) &&
			 */
	files_reflog_iterator_advance,
			!(type & REF_ISSYMREF) &&
			strbuf_addf(err, "unable to resolve reference '%s': "
		struct strbuf sb = STRBUF_INIT;
 out:
		strbuf_reset(referent);
			}
	 * Now that updates are safely completed, we can perform
	 */
		/*
				strbuf_addf(err, "unable to resolve reference '%s'",
		 * have foo/bar which now does not exist;
			printf("keep %s", message);


	logfile = strbuf_detach(&logfile_sb, NULL);

				 * know that there is not a conflict with
			 * terminating LF of the previous line, or the beginning
	}
/*

#include "../dir-iterator.h"
	while (flags & (REMOVE_EMPTY_PARENTS_REF | REMOVE_EMPTY_PARENTS_REFLOG)) {
			struct strbuf err = STRBUF_INIT;

	 * that we are creating already exists.
{
	if (backend_data->packed_transaction &&
	base_ref_iterator_free(ref_iterator);


				 * we are in the middle of a line. Note that we
		int save_errno = errno;
	 * repository or when there are existing references: we are
static char *find_beginning_of_line(char *bob, char *scan)
	} else {
		else if (cb->flags & EXPIRE_REFLOGS_VERBOSE)

	if (prefer_symlink_refs && !create_ref_symlink(lock, target)) {
		refs->loose->root->flag &= ~REF_INCOMPLETE;

			   &update->type, err);
#include "ref-cache.h"
					 * references that it should
			FLEX_ALLOC_STR(n, name, iter->refname);
		 * to add another reflog update for HEAD. Note that

	if (is_null_oid(&update->old_oid))
static int lock_raw_ref(struct files_ref_store *refs,
	files_reflog_path(refs, &sb_oldref, oldrefname);

		strbuf_attach(&sb_path, path, len, len);
	 * Create .git/refs/{heads,tags}
	return 0;
	files_reflog_path(refs, &tmp_renamed_log, TMP_RENAMED_LOG);
		 * but finding all symrefs pointing to the given branch
	strbuf_release(&sb_contents);

{

				      oid, referent, type)) {
	return 0;
}

	if (iter->dir_iterator)
/*
		strbuf_addf(sb, "%s/logs/%s", refs->gitcommondir, refname);
			      &refs->gitcommondir);
	if (refs->loose) {
			status |= error("unable to write reflog '%s' (%s)",
		BUG("unknown ref type %d of ref %s",
	}
		unlock_ref(lock);
					die("loose refname is dangerous: %s", refname.buf);
		files_downcast(ref_store, 0, "ref_transaction_finish");
			continue;

			    iter->refname, err.buf);
		} else {
	 */
	if (ref_update_reject_duplicates(&affected_refnames, err)) {
static int rename_tmp_log(struct files_ref_store *refs, const char *newrefname)
{
	}
	ref_iterator = &iter->base;

		 * in the packed ref cache. If the reference should be
					   update->flags & ~REF_HAVE_OLD,
	struct ref_transaction *packed_transaction = NULL;

			    get_files_ref_lock_timeout_ms()) < 0) {
	if (strcmp(new_update->refname, "HEAD"))
			 */
		new_flags |= REF_UPDATE_VIA_HEAD;
					      const char *caller)
struct expire_reflog_cb {
	struct files_ref_store *refs =
 * pruned. This flag must only be used when REF_NO_DEREF is set.
{
			       const char *refname, const char *target,

}
	if (strbuf_read(&sb_contents, fd, 256) < 0) {
		cnt = (sizeof(buf) < pos) ? sizeof(buf) : pos;
				    ref_file.buf);
static struct files_ref_store *files_downcast(struct ref_store *ref_store,
static struct ref_cache *get_loose_ref_cache(struct files_ref_store *refs)
		/* Fill next block from the end */
			     struct strbuf *err)
			     const char *message, void *cb_data)
				strbuf_addf(err, "unable to append to '%s': %s",
	if (!resolved && errno == EISDIR) {
{
				 * OK.
	    !(update->flags & REF_LOG_ONLY)) {
		strbuf_release(&sb_path);
	 * any confusing situation sending us into an infinite loop.
		return 0;
		/* Schedule the loose reference for pruning if requested. */
	files_for_each_reflog_ent,
			       reflog_expiry_should_prune_fn should_prune_fn,
			get_files_ref_lock_timeout_ms()) < 0 ? -1 : 0;
		} else if (update && commit_ref(lock)) {
		 * machinery here anyway because it does a lot of the
	ref_transaction_free(transaction);

	if (item->util)
		    caller, required_flags, refs->store_flags);
		}
		backend_data->packed_refs_locked = 1;
	o = parse_object(the_repository, oid);
			    sb.buf, strerror(save_errno));
			goto cleanup;

	int ret = 0;
	}
	strbuf_release(&err);
					goto cleanup;
				 * We are at the start of the buffer, and there
			refs_to_prune = n;
#define TMP_RENAMED_LOG  "refs/.tmp-renamed-log"
	 */
	int resolved;
 * message to err, set errno, and return a negative value.
				/* Garden variety missing reference. */
			if (files_log_ref_write(refs,
		*type |= REF_ISBROKEN;
}

	int ok = ITER_DONE;


	}
 * Manually add refs/bisect, refs/rewritten and refs/worktree, which, being
	packed_refs_unlock(refs->packed_ref_store);
		 */
	 */
		int prefix_len = strlen(prefix);
						 REMOVE_EMPTY_PARENTS_REF);
				 *   named "refs/foo".
			    oldrefname, strerror(errno));
		}
			     const char *email, timestamp_t timestamp, int tz,
	if (strcmp(update->refname, head_ref))
	if (!lstat(path, &st) && S_ISDIR(st.st_mode)) {
			    write_str_in_full(get_lock_file_fd(&lock->lk), "\n") < 0 ||
		break;
				 * missing:
	if (parse_worktree_ref(refname, &worktree_name, &length, &real_ref))
	 * referent, which might soon be freed by our caller.
			    refname, strerror(errno));
		goto error_return;
{
	files_copy_ref,

		if ((flags & PACK_REFS_PRUNE)) {
		 */
	struct ref_iterator base;
		goto out;
	 * split_symref_update() or split_head_update(), those
			continue;
			       const char *refname)

			    original_update_refname(update), reason);

			    length, worktree_name, real_ref);

	return refs;
		return -1;
}
	 * If we failed to rewrite the packed-refs file, then it is
	return 0;
	 * only locking and changing packed-refs, so (1) any
		while (buf < scanp) {
	return ret;
	if (close_lock_file_gently(&lock->lk))
		/*
				&new_oid, logmsg, 0, &err)) {
		goto cleanup;
			   affected_refnames, NULL,

	}
		return result;
	 * <-> symlink) between the lstat() and reading, then
	iter->ref_store = ref_store;
	struct files_transaction_backend_data *backend_data;
static int files_delete_refs(struct ref_store *ref_store, const char *msg,
				 *   know that there cannot be a loose
		iter->base.flags = iter->iter0->flags;
		add_entry_to_dir(dir, child_entry);
			if (ref_transaction_abort(packed_transaction, err)) {
	    close_ref_gently(lock) < 0) {
	    parse_oid_hex(p, &noid, &p) || *p++ != ' ' ||
}
static int log_ref_write_fd(int fd, const struct object_id *old_oid,
	head_ref = refs_resolve_refdup(ref_store, "HEAD",
		ret = 0;
		strbuf_addf(err, "cannot lock ref '%s': "
		die("error while iterating over references");
			      &refs->gitdir);
				 *   the lockfile refs/foo/bar.lock, so we
				  REF_NO_DEREF, NULL, &err);

		 */
 * This backend uses the following flags in `ref_update::flags` for
		return 0;
	struct strbuf sb = STRBUF_INIT;
	if (mustexist)
	NULL,
			goto out;
	*fd = open(path, O_APPEND | O_WRONLY | O_CREAT, 0666);
static int files_ref_iterator_peel(struct ref_iterator *ref_iterator,

		}
			printf("prune %s", message);
	struct ref_iterator *iter_worktree,
	struct strbuf sb_newref = STRBUF_INIT;
}
						 packed_transaction)) {
		} else {
	if (cb->flags & EXPIRE_REFLOGS_REWRITE)
	refs->packed_ref_store = packed_ref_store_create(sb.buf, flags);
		goto rollback;
						     &oid, &flag)) {
			 * can only work because we have already
/*
 * live into logs/refs.
	 * that new values are valid, and write new values to the

	files_pack_refs,
		(struct files_ref_iterator *)ref_iterator;
			strbuf_swap(&sb_contents, referent);

 * return TRANSACTION_NAME_CONFLICT or TRANSACTION_GENERIC_ERROR.

		error("unable to write current sha1 into %s: %s", oldrefname, err.buf);

		resolve_flags |= RESOLVE_REF_READING;
	oidcpy(&lock->old_oid, &orig_oid);
	BUG("ref_iterator_peel() called for reflog_iterator");
			error("%s", err.buf);
	memset(&cb, 0, sizeof(cb));

				ret = TRANSACTION_GENERIC_ERROR;
		files_transaction_cleanup(refs, transaction);
	/* Do not pack symbolic refs: */

			/*
		char buf[BUFSIZ];
	int fd;
	struct ref_to_prune *refs_to_prune = NULL;
				     struct ref_transaction *transaction,
		 * make sure there is no existing packed ref that
		 * lazily):
		error("%s", err.buf);
	struct strbuf sb = STRBUF_INIT;

			       struct ref_transaction *transaction,
	lock = lock_ref_oid_basic(refs, refname, NULL,
				 *   know there cannot be a loose reference

				  REF_NO_DEREF, NULL, &err);
	new_update = ref_transaction_add_update(
			; /* silently ignore */

static int files_copy_ref(struct ref_store *ref_store,
		}
				    update->refname);
				email, timestamp, tz, message);

		       struct strbuf *err)
	struct files_ref_store *refs;
			strbuf_reset(&sb);
				    refs->packed_ref_store, refname,
}
	struct strbuf buf = STRBUF_INIT;
			 * empty parent directories. (Note that this
				     unsigned int flags)
	}
	 * disk, and re-reads it if not.

	int ret;
	if (!(flags & DO_FOR_EACH_INCLUDE_BROKEN))
	struct lock_file *lk = cb;
 * err and return -1.
/*
{
	}
			if (bp == buf) {

					goto error_return;
#include "../lockfile.h"
				strbuf_addf(err, "unable to resolve reference '%s'",
/*
	}
	struct string_list affected_refnames = STRING_LIST_INIT_NODUP;
 *   writing the reflog.
	if (!refs_reflog_exists(ref_store, refname)) {
	}
	const char *tmp_renamed_log;


 * `*refs_to_prune`, freeing the entries in the list as we go.
	struct strbuf refname;
#define REF_LOG_ONLY (1 << 7)
 * Unlock any references in `transaction` that are still locked, and
{

#include "packed-backend.h"

	if (refs_for_each_rawref(&refs->base, ref_present,
/*
	    refs_delete_ref(&refs->base, NULL, newrefname,
	struct files_ref_store *refs =
	for (ip = 0; ip < ARRAY_SIZE(prefixes); ip++) {
	struct files_ref_iterator *iter;
	iter = xcalloc(1, sizeof(*iter));
	 * whether the packed-ref cache is up to date with what is on
	if (!copy && refs_delete_ref(&refs->base, logmsg, oldrefname,
	 * We'll keep a count of the retries, though, just to avoid
#define REF_IS_PRUNING (1 << 4)
 * - Lock the reference referred to by update.
 * files_ref_store. required_flags is compared with ref_store's
		struct ref_update *update = transaction->updates[i];
	unlock_ref(lock);
	 * packed_ref_iterator_begin(), which internally checks
			       "initial_ref_transaction_commit");
{
			if (mustexist) {
	 * Please note that FETCH_HEAD has additional
		pos -= cnt;
#include "../cache.h"
				    struct strbuf *err)
		return -1;
		free(r);
 */
{
	}
	struct ref_update *new_update;
		/*
 */
		strbuf_addf(err, "cannot lock ref '%s': %s",
		for (parent_update = update->parent_update;
		}
	strbuf_release(&ref_file);
	 * retaining the packed-refs lock:
		if (ends_with(diter->basename, ".lock"))
		    oideq(&lock->old_oid, &update->new_oid)) {
						err)) {
		last_errno = errno;
	prune_refs(refs, &refs_to_prune);
	if (!o) {
{
				unlock_ref(lock);

	buf = sb_contents.buf;
	strbuf_release(&sb);
			strbuf_release(&err);
		}
		if (copy)
			strbuf_addf(err, "couldn't close '%s.lock'",

	return remove_dir_recursively(path, REMOVE_DIR_EMPTY_ONLY);
cleanup:
		strbuf_release(&err);
}
	 */
	}
		return 0;
		 * Sheesh. Record the true errno for error reporting,
			!is_null_oid(&cb.last_kept_oid);
	struct ref_transaction *packed_transaction;
				if (ret)
				char *old_msg = strbuf_detach(err, NULL);
		errno = EBUSY;
	int true_errno;
					 const char *caller)
static void files_reflog_path(struct files_ref_store *refs,
		if (!skip_prefix(refname, "main-worktree/", &refname))
		 * packed-refs transaction:
				 */
	string_list_sort(&affected_refnames);
			ret = TRANSACTION_GENERIC_ERROR;
}
	return ret;
		packed_transaction = NULL;
		strbuf_addf(err, "ref '%s' is at %s but expected %s",
		else
	if (o->type != OBJ_COMMIT && is_branch(lock->ref_name)) {
		 */

struct files_ref_iterator {
	diter = dir_iterator_begin(sb.buf, 0);
		files_ref_path(refs, &sb, buf.buf);
			       const char *head_ref,
	    !(timestamp = parse_timestamp(email_end + 2, &message, 10)) ||
		 */
	if (refs_delete_refs(refs->packed_ref_store, msg, refnames, flags)) {

		     parent_update;
			}
	goto out;
			oidclr(&lock->old_oid);
		unlock_ref(lock);
	    rename(tmp_renamed_log.buf, sb_oldref.buf))
	for (i = 0; i < transaction->nr; i++) {
	strbuf_release(&sb);
	 * changes the type of the file (file <-> directory
	strbuf_addch(&sb, '\n');
}

		goto error_return;
	if (write_ref_to_lockfile(lock, &orig_oid, &err) ||
{
		if (!cb->newlog)
			continue;
	 */
	 * We might have to loop back here to avoid a race
	struct strbuf err = STRBUF_INIT;
			goto error;
	case REF_TYPE_MAIN_PSEUDOREF:
				   struct object_id *peeled)

	unlock_ref(lock);
 * On failure errno is set to something meaningful.
	cb.policy_cb = policy_cb_data;
			ret = TRANSACTION_GENERIC_ERROR;
		 */
			   (write_in_full(get_lock_file_fd(&lock->lk),
				    extras, skip, err))
#include "../refs.h"
	}
}
	 * the references that we are setting would have precedence
	refs->store_flags = flags;
	int flag = 0, logmoved = 0;
	timestamp_t timestamp;
	struct files_ref_store *refs =
	 */
		 * work we need, including cleaning up if the program
				 * - We got ENOENT and not EISDIR, so we
	case REF_TYPE_PER_WORKTREE:
	int head_type;
		/* fall through */

		/*
	struct object_id new_oid;


		iter->base.flags = flags;
					 create_ref_entry(refname.buf, &oid, flag));
#include "../dir.h"
			error("unable to rename '%s' to '%s': %s", oldrefname, newrefname, err.buf);
	int ret = 0, at_tail = 1;
	/*

	}
		if (fseek(logfp, pos - cnt, SEEK_SET)) {
 *
		ret = 0;
		 */
	}
	 */
	}
		} else {
 * ref update is split up.

				 * appearance in a loose reference
				files_ref_path(refs, &sb, lock->ref_name);
		ok = dir_iterator_abort(iter->dir_iterator);
	}
	lock = lock_ref_oid_basic(refs, refname, oid,

			q--;
				strbuf_reset(err);
			if (errno == ENOENT || errno == EINVAL)
	if (!refs_rename_ref_available(&refs->base, oldrefname, newrefname)) {
 * Flag passed to lock_ref_sha1_basic() telling it to tolerate broken
				error("Directory not empty: %s", newrefname);

				 * It is so astronomically unlikely
	strbuf_release(&err);
			if (commit_ref(lock)) {
 failure:

	if (iter_worktree) {
			ret = TRANSACTION_GENERIC_ERROR;
static enum iterator_selection reflog_iterator_select(
	struct strbuf logfile_sb = STRBUF_INIT;
static int ref_present(const char *refname,
			goto cleanup;
	if (raceproof_create_file(ref_file.buf, create_reflock, &lock->lk)) {
					   const char *refname,
static void files_transaction_cleanup(struct files_ref_store *refs,
	}
	if (verify_lock(&refs->base, lock, old_oid, mustexist, err)) {
		iter->base.refname = diter->relative_path;
	 * we don't want to report that as an error but rather
			if (check_refname_format(refname.buf,
	struct strbuf sb_oldref = STRBUF_INIT;
	return ret;
		return ITER_OK;
		 * to result in ISDIR, but Solaris 5.8 gives ENOTDIR.

error:
{
		 * common refs if they are accidentally added as
			break;
						    &refs->base, refname,
		 * Even though there is a directory where the loose
 *

		return 0;
				ret = TRANSACTION_GENERIC_ERROR;
	return 0;

			if (!(update->type & REF_ISPACKED) ||
		int pos;
			}
		goto out;
static struct ref_lock *lock_ref_oid_basic(struct files_ref_store *refs,
					    refname);
			}

		ret = TRANSACTION_GENERIC_ERROR;

}
	}
	struct expire_reflog_cb *cb = cb_data;
		if ((flags & REMOVE_EMPTY_PARENTS_REF) && rmdir(sb.buf))
	struct ref_transaction *transaction;

	if (refnames->nr == 1)

static int files_reflog_iterator_abort(struct ref_iterator *ref_iterator)
	if (!copy && !refs_read_ref_full(&refs->base, newrefname,
	struct dir_iterator *dir_iterator;
			} else {
		files_downcast(ref_store, 0, "ref_transaction_abort");
			files_reflog_path(refs, &sb, update->refname);

		*type |= REF_ISSYMREF;
					      const char *refname)

		message += 6;

	 * correct value to pass to delete_ref as old_oid. But that
		strbuf_release(&path);
struct files_transaction_backend_data {
			       const char *referent,
		}
	files_ref_store_create,
	for (i = 0; i < transaction->nr; i++) {
	if (!transaction)
					REF_HAVE_NEW | REF_NO_DEREF,
	struct files_ref_store *refs =
	 * Change the symbolic ref update to log only. Also, it
	assert(err);
						    extras, skip, err)) {
	struct strbuf err = STRBUF_INIT;
		strbuf_addf(err, "unable to append to '%s': %s",
		 * when we process it, split_head_update() doesn't try
 */
				 *   reference named "refs/foo/bar/baz".
	 * only, which should cover 99% of all usage scenarios (even
			 int *logfd, struct strbuf *err)
	if (packed_transaction)
		 */
						    ref_file.buf, refname);
	if ((refs->store_flags & required_flags) != required_flags)
{
				 * The newline is the end of the previous line,
	}
	int save_errno;
		if (errno == ENOENT) {
				goto error_return;
			goto failure;
				       RESOLVE_REF_NO_RECURSE,

		; /* keep scanning backwards */
	if (ret) {
	struct strbuf err = STRBUF_INIT;
		int flags;
		} else if (errno == EINVAL && (*type & REF_ISBROKEN)) {
		if (update->flags & REF_DELETED_LOOSE) {
	return ret;
	struct files_reflog_iterator *iter =
		 * We didn't call write_ref_to_lockfile(), so

		 * We're a bit loose here. We probably should ignore
static int should_pack_ref(const char *refname,
	struct strbuf sb = STRBUF_INIT;
				free(old_msg);
		BUG("refname %s is not a other-worktree ref", refname);
			 * A failure during the prepare step will abort

			    update->type & REF_ISSYMREF) {

		at_tail = 0;
	int log, ret;

			error("unable to move logfile %s to %s: %s",
	}

{
		goto out;
 error_return:
		if (ret)
			strbuf_addf(err, "unable to create lock file %s.lock; "
				       NULL, &head_type);
	 * from before the migration. We ensure this as follows:

		close(fd);
					goto error_return;
 * Used as a flag in ref_update::flags when the lockfile needs to be
		}
	struct files_ref_store *refs =
	const char *path;

		files_downcast(ref_store, REF_STORE_READ,
	struct ref_iterator *ref_iterator;
}
	char *ref_name;
			 * from the files_transaction so it does not try to
	}
			} else if (is_null_oid(&oid)) {
 * - Avoid calling refs_verify_refname_available() when it can be
			*type |= REF_ISSYMREF;


				    refname, strerror(last_errno));
			 */
	struct ref_iterator *iter0;
	files_create_reflog,
	strbuf_release(&sb);

	const char *buf;
	}
			update->flags | REF_LOG_ONLY | REF_NO_DEREF,
		 * packed-refs transaction:
	if (iter->iter0)
	    !(email_end = strchr(p, '>')) ||
	return ok;
	} else if (iter_common) {
			 * Maybe somebody just deleted one of the
	}
		packed_refs_unlock(refs->packed_ref_store);
		 * If the loose reference can be packed, add an entry
		 * delete it.
	} else {


	if (commit_lock_file(&lock->lk))
	/*
			 * that we are trying to delete.
 */
	/*
			       void *policy_cb_data)

	files_init_db,

{
			update->backend_data = NULL;
			       const struct object_id *new_oid, const char *msg,
	files_reflog_path(refs, &log_file_sb, refname);
	while (*refs_to_prune) {
	struct strbuf err = STRBUF_INIT;
			   const struct object_id *oid, unsigned int ref_flags,
		strbuf_addstr(referent, buf);
						  extras, skip, err)) {
			   struct strbuf *sb,
	 * We must make sure that all loose refs are read before

static int files_transaction_prepare(struct ref_store *ref_store,
	int i;
		struct ref_lock *lock = update->backend_data;
{
	struct files_reflog_iterator *iter =
			 * removed the lockfile.)


	 */
	iter = cache_ref_iterator_begin(get_loose_ref_cache(refs), NULL, 0);
		return ITER_DONE;

#define REF_DELETING (1 << 5)
	return files_copy_or_rename_ref(ref_store, oldrefname,
			rollback_lock_file(&reflog_lock);

		strbuf_addf(sb, "%s/%s", refs->gitcommondir, refname);
		 */
			string_list_append(&affected_refnames, update->refname);
	 * doesn't matter, because an old_oid check wouldn't add to

	files_ref_path(refs, &sb_path, refname);
	assert(err);
 rollbacklog:
	if (ref_iterator_abort(ref_iterator) != ITER_DONE)
				}
	int logfd, result;
			       "pack_refs");
	struct object *o;

	 * Now we hold the lock and can read the reference without
	}
		 * per-worktree refs.
 * (without recursing).  dirname must end with '/'.  dir must be the
		}
			goto out;
				 * reference "refs/foo/bar"):
static struct ref_iterator *files_ref_iterator_begin(
				RESOLVE_REF_READING, &new_oid, NULL) &&
			     struct ref_lock *lock,

	free(lock->ref_name);
	/*
					    iter->iter0->flags))
	return 0;
			}
	if (commit_ref(lock)) {

			    original_update_refname(update),
		ret = 1;
	strbuf_addf(&sb, "%s/packed-refs", refs->gitcommondir);
		 */
				/*
		    ref_type(refname), refname);
	 * example an old version of a reference that points at an
	return ref_iterator;
 * mustexist is set. Return 0 on success. On error, write an error
			else

#ifndef NO_SYMLINK_HEAD
		if (packed_refs_lock(refs->packed_ref_store, 0, err)) {

	/* Do not pack per-worktree refs: */
	return ret;
	 * to read it as a link or as a file.  But if somebody
	int tz;
			}
		 * A generic solution implies reverse symref information,
				     flags))

						unsigned int flags)
}
 *   REF_LOG_ONLY update of the symref and add a separate update for
cleanup:

	packed_refs_unlock(refs->packed_ref_store);
	size_t i;
	struct string_list affected_refnames = STRING_LIST_INIT_NODUP;
	REMOVE_EMPTY_PARENTS_REFLOG = 0x02
	files_transaction_abort,
			    "reference already exists",
}
 * REMOVE_EMPTY_PARENTS_REFLOG.
		   oideq(oid, &update->old_oid))

			continue;
	new_update->parent_update = update;
 * set of caches.
	if (is_null_oid(&lock->old_oid) &&



error_return:
			strbuf_addf(err, "unable to resolve reference '%s': %s",
		goto out;
	 * Add "HEAD". This insertion is O(N) in the transaction
		}
	files_reflog_path(refs, &logfile_sb, refname);
	if (packed_refs_lock(refs->packed_ref_store, 0, err)) {
	 * updates use REF_IS_PRUNING without REF_NO_DEREF.
	/* Perform updates first so live commits remain referenced */
static int open_or_create_logfile(const char *path, void *cb)
	else

		 * conflicts with refname:
			const struct string_list *skip,
		/* fallthrough */
		return ITER_SKIP_1;
	int remaining_retries = 3;
			goto out;
				goto cleanup;
 *
	 * the safety anyway; we want to delete the reference whatever
		/*
	return ref_store;
		if (--attempts_remaining > 0)

	struct strbuf sb = STRBUF_INIT;
	unsigned int new_flags;
				goto stat_ref;
	 * `prime_ref` argument set to true. This causes the loose
	files_assert_main_repository(refs, "lock_raw_ref");
		 * If this update is happening indirectly because of a

{
 */
	struct files_reflog_iterator *iter;
	struct strbuf err = STRBUF_INIT;
{
static int files_rename_ref(struct ref_store *ref_store,
				 * that the "mustexist" reference is

}


	ret = lock_raw_ref(refs, update->refname, mustexist,
	 *
static int show_one_reflog_ent(struct strbuf *sb, each_reflog_ent_fn fn, void *cb_data)
static int files_reflog_expire(struct ref_store *ref_store,
		}
		 * There is a directory at the path we want to rename
	files_assert_main_repository(refs, "lock_ref_for_update");
/*
		error(_("could not delete references: %s"), err.buf);
		strbuf_addf(err, "cannot lock ref '%s': "
			free(write_err);
	item->util = new_update;
static struct ref_iterator_vtable files_ref_iterator_vtable = {

			ret = ref_transaction_prepare(packed_transaction, err);
			fprintf(cb->newlog, "%s %s %s %"PRItime" %+05d\t%s",
	}
						update->msg, update->flags,
	return ret;
					NULL);
			      struct strbuf *sb,

		/*
			strbuf_addf(err, "can't verify ref '%s'", lock->ref_name);
	if (strcmp(lock->ref_name, "HEAD") != 0) {

 * directory entry corresponding to dirname.
	struct dir_iterator *diter = iter->dir_iterator;
				goto cleanup;
	files_reflog_exists,
		(struct files_ref_iterator *)ref_iterator;
			 */
	    !(update->flags & REF_DELETING) &&
	packed_transaction = backend_data->packed_transaction;
	}
		if (update->flags & REF_NEEDS_COMMIT) {
	 * branch) to be worth it. So let's cheat and check with HEAD
 * have a D/F conflict with any existing references. extras and skip
			     lock->lk.tempfile->filename.buf, strerror(errno));
	if (update->type & REF_ISSYMREF) {
	case REF_TYPE_NORMAL:
			unsigned int *type,

	 * First make sure that referent is not already in the
	unlock_ref(lock);
		if (de->d_name[0] == '.')
	base_ref_iterator_init(ref_iterator, &files_reflog_iterator_vtable, 0);
 * per-worktree, might not appear in the directory listing for
		goto cleanup;
	while ((de = readdir(d)) != NULL) {
#define REF_UPDATE_VIA_HEAD (1 << 8)
				}
		update_symref_reflog(refs, lock, refname, target, logmsg);
	return ref_iterator;
		 * points to it (may happen on the remote side of a push
		 * per-worktree refs, which should be ignored
				update->backend_data = NULL;
				strbuf_release(&log_err);
				    refname, strerror(errno));
	}
	 * reference if --updateref was specified:
				   message, policy_cb)) {
{

	 * we want to create a file but there is a directory there;
				scanp = bp;
			/*
	if (!d) {
	strbuf_addf(&sb, "%s %s %s", oid_to_hex(old_oid), oid_to_hex(new_oid), committer);
static int commit_ref_update(struct files_ref_store *refs,
		(struct files_reflog_iterator *)ref_iterator;
		return -1;
	return -1;

		 * the moment we never use the value of this field
			struct strbuf *err)
	files_reflog_iterator_abort
	}
			    "trying to write ref '%s' with nonexistent object %s",


error:
 */
		/*
		update = update->parent_update;
		ret = error("reflog for %s is a symlink", oldrefname);
		strbuf_reset(&sb_contents);
					affected_refnames, err);
	if (close(logfd)) {
			goto failure;
		strbuf_release(&sb);

}
	return fn(&ooid, &noid, p, timestamp, tz, message, cb_data);
		ret = error("cannot seek back reflog for %s: %s",
			       reflog_expiry_prepare_fn prepare_fn,
			strbuf_addch(&refname, '/');
/*
		strbuf_addf(err, "cannot lock ref '%s': "

	if (S_ISLNK(st.st_mode)) {
		return merge_ref_iterator_begin(
				/*
	 *
		 */

	unlock_ref(lock);
				    "non-directory in the way",
		}
			     struct ref_lock *lock,
			} else {
static int check_old_oid(struct ref_update *update, struct object_id *oid,
					ret = TRANSACTION_GENERIC_ERROR;
		pos = search_ref_dir(dir, prefix, prefix_len);
{
		if (update->flags & REF_DELETING &&
static int files_read_raw_ref(struct ref_store *ref_store,
	if (!refnames->nr)
		    !refs_verify_refname_available(&refs->base, refname,
static int files_initial_transaction_commit(struct ref_store *ref_store,

	/* Now delete the loose versions of the references: */


	 * size, but it happens at most once per symref in a
	return result;

		update->flags |= REF_DELETING;

			goto out;
		return -1;

	 * Fail if a refname appears more than once in the

};
			&null_oid, &r->oid, NULL);
					     refname, resolve_flags,
			goto error_return;
			if (mustexist) {

	 */
				ref_transaction_free(packed_transaction);
	strbuf_release(&path);
			 * not) will free it.
			status |= error("couldn't write %s",

	 * Add the referent. This insertion is O(N) in the transaction

		 */
{
		strbuf_release(&err);

	backend_data = transaction->backend_data;
	return update->refname;
	files_ref_path(refs, &sb, "refs/tags");
	struct strbuf sb = STRBUF_INIT;

		 * that it knows to retry.
	strbuf_release(&sb);
			 * file. But we do need to leave it locked, so
				 * we collected for the line and process it.
		free_ref_cache(refs->loose);
		unlock_ref(lock);

{
		files_downcast(ref_store, REF_STORE_WRITE, "delete_refs");
}
			/* inconsistent with lstat; retry */
	struct strbuf sb = STRBUF_INIT;
 *
		if (!should_pack_ref(iter->refname, iter->oid, iter->flags,
			clear_loose_ref_cache(refs);
	/*

		last_errno = ENOTDIR;
	ret = 0;
	for (i = 0; i < transaction->nr; i++) {
		struct stat st;
	transaction = ref_store_transaction_begin(refs->packed_ref_store, &err);

	safe_create_dir(sb.buf, 1);
		if (errno == ENOTDIR)
 *
		struct strbuf sb = STRBUF_INIT;
	fd = open(path, O_RDONLY);
	int attempts_remaining = 3;
/*
	return 0;
			buf++;
 * If the reference doesn't already exist, verify that refname doesn't
	struct ref_lock *lock;
			}
	return refs->loose;
			     const struct object_id *oid, const char *logmsg,
		BUG("initial ref transaction called with existing refs");
		    new_update->refname);
	strbuf_addf(&sb, "%s/logs", gitdir);
		    !(update->flags & REF_IS_PRUNING)) {

	}
		return -1;
						&lock->old_oid, oid,
	int ret = -1;
	struct files_ref_store *refs =


			/*
	char *ref_path = get_locked_file_path(&lock->lk);
	default:
}
			 * This reference has to be deleted from
				backend_data->packed_transaction = NULL;
	strbuf_release(&referent);
}
		ret = 0;
 * Note that the new update will itself be subject to splitting when
}
 * Create a reflog for a ref. If force_create = 0, only create the

		files_reflog_path(refs, &sb, buf.buf);
	strbuf_rtrim(&sb_contents);
	struct expire_reflog_cb cb;
	}
		goto error;
		} else {
	return string_list_has_string(affected_refnames, refname);
		else
		ok = ref_iterator_abort(iter->iter0);
		/*

	    (*p != '\0' && !isspace(*p))) {
 * mark the transaction closed.
		files_downcast(ref_store, REF_STORE_WRITE, "init_db");
					    refname);
	    !isdigit(message[2]) || !isdigit(message[3]) ||
			       "ref_transaction_prepare");

	}
	 * only empty directories), remove them.

 * and type similarly to read_raw_ref().
	while ((ok = ref_iterator_advance(iter->iter0)) == ITER_OK) {
{
	struct dir_iterator *diter;
	if (!refs_resolve_ref_unsafe(&refs->base, oldrefname,
		adjust_shared_perm(logfile);
	free(ref_path);
	return ret;

	size_t path_baselen;
	if (ref_update_reject_duplicates(&affected_refnames, err)) {
					  extras, skip, err)) {
	static char term = '\n';
		} else if (update &&
	if (ret)

				   struct strbuf *err)
			goto out;
 * name. If the logfile already existed or was created, return 0 and
				 * To the user the relevant error is
	int ok;
 * Downcast ref_store to files_ref_store. Die if ref_store is not a
				 * but that is not an error; it only
 * update but not actually perform it.  This is used when a symbolic
			add_entry_to_dir(dir,
		BUG("%s unexpectedly found in affected_refnames",
	 * the packed and loose references.
	 * long as there is a corresponding loose reference that
 * - The original update, but with REF_LOG_ONLY and REF_NO_DEREF set
	fprintf(lock->lk.tempfile->fp, "ref: %s\n", target);
	goto out;
			struct strbuf log_err = STRBUF_INIT;
				    cnt, refname, strerror(errno));
	close(fd);
		goto error_return;
}
				  git_committer_info(0), msg);
		error("%s", err.buf);
				goto out;
				 *
	/*
	else
	 * error) leaving a reference without a reflog is less bad
 */
			 * We won't be reading the referent as part of
		 * Add an incomplete entry for "refs/" (to be filled
		 * no locking implications, we use the lock_file

	lock = NULL;
		 * If the ref did not exist and we are creating it,
			 */
	}
	struct strbuf sb = STRBUF_INIT;

	if (!lock) {

					      struct strbuf *sb,
				 */
			&update->new_oid, &update->old_oid,

		struct object_id oid;
		errno = save_errno;
			       reflog_expiry_cleanup_fn cleanup_fn,


	unlock_ref(lock);

	struct ref_iterator *loose_iter, *packed_iter, *overlay_iter;
					   &update->new_oid, &update->old_oid,
		 * Even though holding $GIT_DIR/logs/$reflog.lock has
		goto rollback;
	    ref_transaction_abort(backend_data->packed_transaction, &err)) {
			goto error_return;
	}
		while (isspace(*buf))

		} else if (S_ISDIR(st.st_mode)) {
		return empty_ref_iterator_begin();
	if (head_ref && !(head_type & REF_ISSYMREF)) {
	d = opendir(path.buf);
	q = buf.buf + buf.len;
	for (i = 0; i < transaction->nr; i++) {
			errno = EISDIR;
		if (cb->flags & EXPIRE_REFLOGS_VERBOSE)
		strbuf_addf(err, "unable to append to '%s': %s",
			goto out;
 * - Generate informative error messages in the case of failure
		 * The main ref store may contain main worktree's
			oldrefname, strerror(errno));

			continue;
	else
		struct ref_update *update = transaction->updates[i];

	char *path = get_locked_file_path(&lock->lk);
	else
						   NULL, &head_flag);
}

		return 0;
			    referent, update->refname);
					   REF_NO_DEREF, NULL, &err))
			      const char *refname)
 * - Read the reference under lock.
			ret = TRANSACTION_NAME_CONFLICT;
			    const char *oldrefname, const char *newrefname,
			 * packed-refs if it exists there.
			update->backend_data = NULL;
		goto out;
 * reference and/or its reflog, but spare [logs/]refs/ and immediate
/*
{
		if (!cb.newlog) {

	if (packed_transaction) {
			error("directory not empty: %s", path.buf);
			       "reflog_iterator_begin");
			p++;
{
}

	strbuf_release(&sb_oldref);

#include "../iterator.h"

		const char *refname = refnames->items[i].string;
					   iter->oid, NULL,
	assert(err);
				   transaction->updates[i]->refname);
	if (packed_transaction) {
		files_downcast(ref_store, REF_STORE_READ,
		} else if (commit_lock_file(&reflog_lock)) {
		 * to remain.
		ret = TRANSACTION_GENERIC_ERROR;
	if (skip_prefix(buf, "ref:", &buf)) {
				 * entries to it.
		goto error;
		break; /* success */
	add_per_worktree_entries_to_dir(dir, dirname);
			char *bp;
		if (refs_read_raw_ref(refs->packed_ref_store, refname,
	return (*fd < 0) ? -1 : 0;
}
		return;
	} else
 *     lock reference
		if (iter->flags & DO_FOR_EACH_PER_WORKTREE_ONLY &&
			else
				update->flags |= REF_DELETED_LOOSE;
	struct object_id oid;
	}
			 * value, so we don't need to write it.
	files_transaction_cleanup(refs, transaction);
 */

			return ITER_SELECT_1;
	 * Anything else, just open it and try to use it as

	else if (is_null_oid(oid))
		strbuf_release(&err);
	return ret;
 *
		 * check with HEAD only which should cover 99% of all usage
		return -1;

	log_all_ref_updates = flag;
	if (logfd < 0)
		error("unable to lock %s for rollback: %s", oldrefname, err.buf);

	ret = !lstat(sb.buf, &st) && S_ISREG(st.st_mode);
	return 0;
		 */
		if (refs_verify_refname_available(&refs->base, refname,
	unlink(ref_path);
				 *


			 * exists, try to remove the directory so that it
			    sb.buf, strerror(save_errno));
	new_flags = update->flags;
	log = !lstat(sb_oldref.buf, &loginfo);
		if (raceproof_create_file(logfile, open_or_create_logfile, logfd)) {
	int ret = TRANSACTION_GENERIC_ERROR;
};
 * If mustexist is not set and the reference is not found or is
}
			    lock->ref_name,


	 * will be deleted, since (in the unexpected event of an
	int resolve_flags = RESOLVE_REF_NO_RECURSE;
		ret = split_head_update(update, transaction, head_ref,
		 * it is normal for the empty directory 'foo'

static void clear_loose_ref_cache(struct files_ref_store *refs)
	fclose(logfp);
	ret = 1;
		/* tolerate duplicate slashes; see check_refname_format() */

		backend_data->packed_transaction = NULL;
	}
		if (ref_type(iter_common->refname) == REF_TYPE_NORMAL)
	 * transaction. (If we end up splitting up any updates using
	 * The reflog file is locked by holding the lock on the
		struct ref_to_prune *r = *refs_to_prune;
	}
/*
			if (result) {
		files_downcast(ref_store, REF_STORE_WRITE, "reflog_expire");
				} else {
	    write_in_full(fd, &term, 1) < 0 ||
	char name[FLEX_ARRAY];
	}
		strbuf_release(&err);
	 * references, and (if needed) do our own check for broken
		    ref_store->be->name, caller);
		strbuf_addf(err,
		if (close_lock_file_gently(&reflog_lock)) {
	struct ref_update *new_update;

		 * packed ref:
	const char *p = sb->buf;

static void unlock_ref(struct ref_lock *lock)
{
			    "multiple updates for 'HEAD' (including one "
	string_list_clear(&affected_refnames, 0);
	}

			       const char *refname, int force_create,
				const char *target, const char *logmsg)
	return ref_iterator_peel(iter->iter0, peeled);
			    lock->ref_name, oid_to_hex(oid));
{
		 * and will report the problem.
static int log_ref_setup(struct files_ref_store *refs,
	}
 * returns non-zero). Otherwise, create it regardless of the reference
	struct string_list_item *item;
	 *
				 * that null_oid is the OID of an
			    const struct object_id *new_oid,
				 *
					    &refs->base,

	unsigned int required_flags = REF_STORE_READ;
	int mustexist = (update->flags & REF_HAVE_OLD) &&
	 */
static void prune_ref(struct files_ref_store *refs, struct ref_to_prune *r)
	if (!(pack_flags & PACK_REFS_ALL) && !starts_with(refname, "refs/tags/"))
	int fd;
		goto cleanup;
	 * the previous line.
						&lock->old_oid,

	if (refs_read_ref_full(ref_store, lock->ref_name,
			return 0;
		error("unable to delete old %s", oldrefname);
};


				backend_data->packed_transaction =
	assert(err);
	if (flags & REF_DELETING)
	chdir_notify_reparent("files-backend $GIT_DIR",
	files_ref_path(refs, &ref_file, refname);
		 * but report EISDIR to raceproof_create_file() so
	if (files_read_raw_ref(&refs->base, refname,
/*
	size_t i;

	return 0;
{
		return 0;

	default:

			strbuf_release(&path);

	strbuf_reset(&sb_path);
				 * refs_verify_refname_available() is
				 * actual object that we consider its
				struct ref_lock *lock, const char *refname,
		 * another reference such as "refs/foo". There is no
	 * data after the sha.
 * Write oid into the open lockfile, then close the lockfile. On
		ret = TRANSACTION_GENERIC_ERROR;
					break;
	struct stat st;
	struct strbuf referent = STRBUF_INIT;
static void try_remove_empty_parents(struct files_ref_store *refs,
	int status = 0;
	return ret;
	return 0;
	resolved = !!refs_resolve_ref_unsafe(&refs->base,
				 */

	strbuf_add(&refname, dirname, dirnamelen);
{
		struct ref_update *update = transaction->updates[i];
struct ref_lock {
	 * if that is an empty directory (or a directory that contains
	 */
		resolved = !!refs_resolve_ref_unsafe(&refs->base,
	int *fd = cb;
	update->backend_data = lock;
	return ret;
	return status;
	strbuf_release(&sb_path);
	struct ref_store *ref_store = (struct ref_store *)refs;
	struct object_id old_oid;
		message += 7;
		goto out;
		goto out;
	files_reflog_path(refs, &sb, refname);
	}

				 * The logfile doesn't already exist,
	/*
				oidclr(&oid);
					goto cleanup;
	/*
	    parse_oid_hex(p, &ooid, &p) || *p++ != ' ' ||
	case SCLD_EXISTS:
	for (i = 0; i < transaction->nr; i++) {
						     &lock->old_oid, type);
	struct ref_lock *lock;
{
		return -1;
	refs->gitcommondir = strbuf_detach(&sb, NULL);

		goto rollback;

			strbuf_addf(err, "unable to resolve reference '%s': %s",


	if (transaction->state != REF_TRANSACTION_OPEN)
		return reflog_iterator_begin(ref_store, refs->gitcommondir);
					 * verify_refname_available() is OK.
 * The caller must verify that refname is a "safe" reference name (in
				flag |= REF_BAD_NAME | REF_ISBROKEN;
}
			 * that somebody else doesn't pack a reference
	if (ok != ITER_DONE)
	return -1;
 */
	}

			 struct strbuf *err)
		ret = lock_ref_for_update(refs, update, transaction,
	int ok;
 * subdirs. flags is a combination of REMOVE_EMPTY_PARENTS_REF and/or
	FILE *logfp;
	int ret = -1;
 * update is for a symref that points at referent and doesn't have

	backend_data = xcalloc(1, sizeof(*backend_data));
			 * of the buffer.
static int remove_empty_directories(struct strbuf *path)
	}
}
		 * Special hack: If a branch is updated directly and HEAD
	free(head_ref);
 * errors, rollback the lockfile, fill in *err and return -1.
	if (backend_data->packed_refs_locked)
			} else if (!pos) {

			if (errno == ENOENT || errno == EISDIR) {
			if (files_log_ref_write(refs, "HEAD",
			 * The reference already has the desired
	}
				 */
				 * Save away what we have to be combined with
	while (!ret && !strbuf_getwholeline(&sb, logfp, '\n'))
		ret = TRANSACTION_GENERIC_ERROR;
		if (ref_transaction_update(transaction, iter->refname,


	if (log_all_ref_updates == LOG_REFS_UNSET)
	path = sb_path.buf;
static int close_ref_gently(struct ref_lock *lock)
			       "for_each_reflog_ent_reverse");
	}

 */
}
			goto cleanup;

		files_downcast(ref_store, REF_STORE_WRITE, "delete_reflog");
	 * our refname.
		if ((update->flags & REF_HAVE_OLD) &&
	lock->ref_name = xstrdup(refname);
	rollback_lock_file(&lock->lk);
 * Return true if the specified reference should be packed.
		 * Suppose refname is "refs/foo/bar". We just failed
			goto rollback;
	new_update = ref_transaction_add_update(

	case SCLD_OK:
			     struct strbuf *err);
			DO_FOR_EACH_INCLUDE_BROKEN);
	goto out;
				 * means that we won't write log
{
	struct ref_to_prune *next;
 * refs (i.e., because the reference is about to be deleted anyway).
	 */
		/*

	if (message[6] != '\t')
					    iter->iter0->oid,
	assert(err);
	if (flag & REF_ISSYMREF) {
		ret = show_one_reflog_ent(&sb, fn, cb_data);
stat_ref:

/*
	files_for_each_reflog_ent_reverse,
static int files_create_symref(struct ref_store *ref_store,
	}

		if (errno == EISDIR)
		return 0;
				 */
{

	struct strbuf sb = STRBUF_INIT;
				    "reference broken", refname);
	 * over our values. But some remote helpers create the remote
	iter->dir_iterator = NULL;
	 * its current value.
				if (update->flags & REF_HAVE_OLD) {
 */
}
	overlay_iter = overlay_ref_iterator_begin(loose_iter, packed_iter);
	item->util = new_update;

				/*
	char *p, *q;
	 * the same time we do, and (2) any existing loose versions of


	if (!copy && log && rename(sb_oldref.buf, tmp_renamed_log.buf)) {
	if (!packed_transaction) {
	files_create_symref,
		} else if (write_ref_to_lockfile(lock, &update->new_oid,
				 create_dir_entry(refs->loose, "refs/", 5, 1));
 * internal bookkeeping purposes. Their numerical values must not
struct ref_storage_be refs_be_files = {
			oidcpy(&n->oid, iter->oid);
				 * previous line, rather than some spot in the

		string_list_append(&affected_refnames,
	chdir_notify_reparent("files-backend $GIT_COMMONDIR",
	return ok;
		 * indicates a D/F conflict, probably because of
	item = string_list_insert(affected_refnames, new_update->refname);
			result = remove_empty_directories(&path);

 */
	reflog_expiry_should_prune_fn *should_prune_fn;
		goto error_return;
 * the sense of refname_is_safe()) before calling this function.
 * but it includes a lot more code to
		/* An entry already existed */
		strbuf_setlen(&buf, q - buf.buf);
		struct ref_update *update = transaction->updates[i];
	struct string_list_item *item;
	int mustexist = (old_oid && !is_null_oid(old_oid));
	path_baselen = path.len;

			unable_to_lock_message(log_file, errno, &err);
	if ((update->flags & REF_LOG_ONLY) ||
			    lock->ref_name, old_msg);
			 * abort us when we hit the cleanup code below.

		strbuf_addf(sb, "%s/%s", refs->gitdir, refname);
	char *gitcommondir;

		files_downcast(ref_store, REF_STORE_READ,
			       flags & REF_FORCE_CREATE_REFLOG,

}

		if (refs_delete_ref(&refs->base, msg, refname, NULL, flags))
	strbuf_release(&err);
 */
		 */
	if (log && S_ISLNK(loginfo.st_mode)) {
	case REF_TYPE_MAIN_PSEUDOREF:
						refs->packed_ref_store, err);
				 * Reference is missing, but that's OK. We
	case REF_TYPE_PER_WORKTREE:

	packed_refs_lock(refs->packed_ref_store, LOCK_DIE_ON_ERROR, &err);
#endif
		/* We're going to fill the top level ourselves: */
	files_transaction_prepare,
	    (update->flags & REF_UPDATE_VIA_HEAD))

	if (copy && log && copy_file(tmp_renamed_log.buf, sb_oldref.buf, 0644)) {
	}
 */
}
	REMOVE_EMPTY_PARENTS_REF = 0x01,
	loose_iter = cache_ref_iterator_begin(get_loose_ref_cache(refs),
}
			   unsigned int pack_flags)
			goto retry;
			backend_data->packed_transaction = NULL;
static int files_delete_reflog(struct ref_store *ref_store,
		(struct files_ref_iterator *)ref_iterator;
				strbuf_splice(&sb, 0, 0, buf, endp - buf);
	files_initial_transaction_commit,

	files_reflog_iterator_peel,

		error("cannot lock ref '%s': %s", refname, err.buf);
			add_entry_to_dir(dir,
		files_downcast(ref_store, REF_STORE_READ, "reflog_exists");
static void files_ref_path(struct files_ref_store *refs,
			     struct ref_transaction *transaction,
	 * transaction.
	} else {
			   &lock, &referent,
	}
				goto cleanup;
	}
	return ret;
		 * entries.
	if (initial_ref_transaction_commit(packed_transaction, err)) {
				       diter->relative_path, 0,

	}
	 * transaction. This check is O(lg N) in the transaction
				 * another loose reference because
	return 1;
	}
		    !(update->flags & REF_LOG_ONLY) &&
				&orig_oid, &flag)) {
	struct rename_cb *cb = cb_data;
			transaction, "HEAD",
		ret = error("refname %s not found", oldrefname);
	struct ref_transaction *packed_transaction;
	strbuf_release(&sb);
	 * done when new_update is processed.
out:
	    !refs_read_ref_full(&refs->base, target,


	}
			 * backend_data, since the abort (whether successful or
		files_downcast(ref_store, REF_STORE_READ, "read_raw_ref");

			 * don't have to do it here.
	strbuf_release(&sb);
			} else {
			       struct ref_update *update,
				 */
			n->next = refs_to_prune;
				RESOLVE_REF_READING | RESOLVE_REF_NO_RECURSE,
			update->msg);
		 * It doesn't look like a refname; fall through to just
		 */
		 */
 *   the referent to transaction.
			&update->new_oid, &update->old_oid,
	files_ref_iterator_begin,

	}
{
	ret = 0;
			oldrefname, newrefname, strerror(errno));
		strbuf_addstr(&refname, de->d_name);
	struct files_ref_store *refs =
	 * reference itself, plus we might need to update the
				  &err);
			const char *refname, int mustexist,
				 const struct object_id *oid, struct strbuf *err)
{
			 */
			refs->packed_ref_store, prefix, 0,
 * reflog for certain refs (those for which should_autocreate_reflog
 * return -1.
				     RESOLVE_REF_READING | RESOLVE_REF_NO_RECURSE,
			/*

		} else {
		if (lock) {
	struct ref_lock *lock;
				/* It is a loose reference. */
}
	if (!transaction->nr)
	strbuf_release(&path);
{
	 * references in the subtree to be pre-read into the cache.
				    update->refname, write_err);
		ref_transaction_add_update(packed_transaction, update->refname,
		 * for example) then logically the HEAD reflog should be
		ref_transaction_free(packed_transaction);
		 * pruned, also add it to refs_to_prune.
	 */
	lock = lock_ref_oid_basic(refs, newrefname, NULL, NULL, NULL,
		if (pos >= 0)
	 * Return either beginning of the buffer, or LF at the end of
/*
{
			/*
	}
	 * guarantee that they're read before the packed refs, not
}
					    refname, extras, skip, err))
		    !(update->flags & REF_LOG_ONLY)) {
			    oid_to_hex(&lock->old_oid),

	transaction->state = REF_TRANSACTION_CLOSED;
static void loose_fill_ref_dir(struct ref_store *ref_store,

	tz = strtol(message + 1, NULL, 10);
	struct files_ref_store *refs =
		files_downcast(ref_store, REF_STORE_WRITE, "rename_ref");
	for (i = 0; i < transaction->nr; i++)
		}
		if (update->flags & REF_DELETING &&
{
	if (S_ISDIR(st.st_mode)) {

				break;
	files_reflog_iterator_begin,
 * If update is a direct update of head_ref (the reference pointed to
struct rename_cb {
				error("%s", log_err.buf);
		strbuf_addf(err,


	 * refname, nor a packed ref whose name is a proper prefix of
	struct files_ref_store *refs =
	struct files_ref_iterator *iter =
		goto out;
		if (last_errno != ENOTDIR ||
 * refs/ in the main repo.
/*
		strbuf_addf(sb, "%s/logs/%s", refs->gitdir, refname);
	int last_errno = 0;
			    const char *committer, const char *msg)
				    refname, strerror(errno));
			unlock_ref(lock);
	refs = (struct files_ref_store *)ref_store;
	/* old SP new SP name <email> SP time TAB msg LF */
	}

		strbuf_release(&err);
		struct ref_update *update = transaction->updates[i];
}
static int files_pack_refs(struct ref_store *ref_store, unsigned int flags)
		       const struct object_id *old_oid, int mustexist,
			    ref_file.buf);
		last_errno = errno;
{
	assert(err);
		 * Mark the top-level directory complete because we
	transaction = ref_store_transaction_begin(&refs->base, &err);

	struct files_transaction_backend_data *backend_data =
	}
	safe_create_dir(sb.buf, 1);
	struct files_ref_store *refs =
	free(log_file);
			 * The loose reference was deleted. Delete any
		}
	(*cleanup_fn)(cb.policy_cb);
static int split_symref_update(struct ref_update *update,
		unlock_ref(lock);
#include "../object.h"
 * Return 0 on success. On failure, write an error message to err and
};
			if (!packed_transaction) {
 * Locks a ref returning the lock on success and NULL on failure.

/*
					/*
	/*
 */
 * Return the refname under which update was originally requested.
	free(log_file);
			    const char *logmsg, int copy)
enum {
	 * condition if loose refs are migrated to the packed-refs
			struct strbuf path = STRBUF_INIT;
	struct strbuf err = STRBUF_INIT;

			} else if (remove_dir_recursively(&ref_file,
	string_list_sort(&affected_refnames);
static int split_head_update(struct ref_update *update,
	 * So if HEAD is a symbolic reference, then record the name of
		while (q > p && *q != '/')
}
}

	 */
			    oid_to_hex(old_oid));
		 * exits unexpectedly.
}
				;
		goto cleanup;
			continue;
			/*
static int files_ref_iterator_advance(struct ref_iterator *ref_iterator)
				/* Garden variety missing reference. */
	 * Since we are doing a shallow lookup, oid is not the
{
		 * the symbolic reference's reflog. Nor can we update
	}
		} else {
		return 0;
	files_ref_iterator_advance,
	struct ref_store base;
		}
		return TRANSACTION_NAME_CONFLICT;
			continue;
				strbuf_addf(err, "there are still refs under '%s'",
}
	    commit_ref_update(refs, lock, &orig_oid, logmsg, &err)) {
	 * open at a time to avoid running out of file descriptors.


			reflog_iterator_begin(ref_store, refs->gitcommondir),
	const char *real_ref;
static struct ref_iterator_vtable files_reflog_iterator_vtable = {
{
			 * Create a new update for the reference this
	if (result) {
}
	return 0;
{
	struct strbuf path = STRBUF_INIT;
	}
			update->flags |= REF_NEEDS_COMMIT;
	int ok = ITER_DONE;
		return -1;
		goto out;
			errno = EISDIR;
	FILE *newlog;
	    !isdigit(message[4]) || !isdigit(message[5]))
				NULL, NULL) &&
			update->msg);
	(*prepare_fn)(refname, oid, cb.policy_cb);

		struct ref_update *parent_update;
		cb->true_errno = errno;
 */
static int expire_reflog_ent(struct object_id *ooid, struct object_id *noid,

			       struct strbuf *err)
				 * is more file to read backwards. Which means
/*
	return scan;

						   RESOLVE_REF_READING,
		}
	 * condition: first we lstat() the file, then we try
	if (write_in_full(fd, sb.buf, sb.len) < 0)
	refs->gitdir = xstrdup(gitdir);
				 * (probably due to a software bug).
			     const char *head_ref,
	 * First make sure that HEAD is not already in the
	ret = remove_path(sb.buf);
			}
{
 * - Check that its old OID value (if specified) is correct, and in
		 * are about to read the only subdirectory that can
	struct ref_lock *lock;
					     void *cb_data)
	struct ref_transaction *packed_transaction = NULL;
			       &logfd, err);
	if (msg && *msg)
	lock->ref_name = xstrdup(refname);
	 * deletes. First delete the reflogs of any references that
	struct files_ref_store *refs;
	logfp = fopen(sb.buf, "r");
	 * rather costly for this rare event (the direct update of a



	/*
	if (check_refname_format(r->name, 0))
static int create_reflock(const char *path, void *cb)
{
 * - If it is an update of head_ref, add a corresponding REF_LOG_ONLY
		item->util = update;
		     parent_update = parent_update->parent_update) {
	struct strbuf path = STRBUF_INIT;
		strbuf_addf(err, "cannot update the ref '%s': %s",
			    oid_to_hex(oid), lock->ref_name);
#include "../config.h"

	struct rename_cb cb;
	struct strbuf sb = STRBUF_INIT;
	struct files_ref_store *refs =
	}
	}

				strbuf_addf(err, "unable to append to '%s': %s",
			       &lock->old_oid, referent, type)) {
	struct expire_reflog_policy_cb *policy_cb = cb->policy_cb;

	if (head_ref) {
	unsigned int flags;
}
	return 0;
				endp = bp + 1;

	transaction->state = REF_TRANSACTION_CLOSED;
		}
			/* Looking at the final LF at the end of the file */
}
		head_ref = refs_resolve_ref_unsafe(&refs->base, "HEAD",
		if (update->flags & REF_NEEDS_COMMIT ||
			flags &= ~REMOVE_EMPTY_PARENTS_REFLOG;
	 */
static void update_symref_reflog(struct files_ref_store *refs,
	 * transaction. Make sure to add new_update->refname, which will
	struct ref_store *packed_ref_store;
	    files_log_ref_write(refs, refname, &lock->old_oid,
		ret = TRANSACTION_GENERIC_ERROR;

			       struct string_list *affected_refnames,
 * Commit a change to a loose reference that has already been written
	packed_transaction = ref_store_transaction_begin(refs->packed_ref_store, err);
	int length;
}
					    logfile, strerror(errno));
	/*
	struct ref_lock *lock;
	}
	fd = get_lock_file_fd(&lock->lk);
	 * expose an obsolete packed value for a reference that might

	char *email_end, *message;
	int ret = 0;
			oidcpy(&cb->last_kept_oid, noid);
			 *
		 * updated too.
	 * size, but it happens at most once per transaction.
	files_transaction_finish,
#include "worktree.h"
			    "reference is missing but expected %s",
	if (logmsg &&

	files_read_raw_ref,
	 * even point at an object that has been garbage collected.
	 * a ref
	files_assert_main_repository(refs, "lock_ref_oid_basic");
			status |= error("couldn't write %s: %s", log_file,
	files_reflog_path(refs, &path, newrefname);
	if (!(update->flags & REF_HAVE_OLD) ||
		return 0; /* corrupt? */
			    real_ref);
		return;

	struct ref_lock *lock;
	struct strbuf sb_path = STRBUF_INIT;
		if (refs_verify_refname_available(&refs->base, update->refname,
							  refname.len, 1));
		FREE_AND_NULL(head_ref);

static int files_copy_or_rename_ref(struct ref_store *ref_store,
			 * to record and possibly check old_oid:
struct ref_to_prune {
			       const char *refname, const struct object_id *old_oid,
			if (mustexist) {
	}
			 * We can skip rewriting the `packed-refs`
		reason = strbuf_detach(err, NULL);
	ref_transaction_free(transaction);
				goto rollback;
		int save_errno = errno;
	strbuf_release(&tmp_renamed_log);
			last_errno = errno;
/*
	 * same refname as any existing ones.) Also fail if any of the
	if (!(flags & EXPIRE_REFLOGS_DRY_RUN)) {
		close(logfd);
			 */
}
	fclose(logfp);

					   const struct object_id *old_oid,
	/*
		if (strbuf_readlink(&sb_contents, path, st.st_size) < 0) {

 * Create a new submodule ref cache and add it to the internal

	} else {
	if (!resolved) {

				      struct ref_transaction *transaction)

			    const char *oldrefname, const char *newrefname,
 */
	struct stat st;
		transaction->state = REF_TRANSACTION_PREPARED;
static int create_ref_symlink(struct ref_lock *lock, const char *target)
		error("error aborting transaction: %s", err.buf);
		const char *head_ref;
	 */
	if (rename(cb->tmp_renamed_log, path)) {
				ret = TRANSACTION_GENERIC_ERROR;
/*
	}
	if (ret) {
		BUG("%s unexpectedly not 'HEAD'", new_update->refname);
static int files_reflog_iterator_peel(struct ref_iterator *ref_iterator,
				 * - We were successfully able to create
	char *head_ref = NULL;
					   NULL);
	/* Is it a directory? */
 */
	int ret;
	 * Acquire all locks, verify old values if provided, check
		files_downcast(ref_store, REF_STORE_WRITE,
			if (errno == ENOENT)
	 */
		}

			q--;
	ret = raceproof_create_file(path.buf, rename_tmp_log_callback, &cb);
			unable_to_lock_message(ref_file.buf, errno, err);
	case SCLD_VANISHED:
						  &affected_refnames, NULL,
	}
	}

	}
		}
{
	 * A generic solution would require reverse symref lookups,

			       struct string_list *affected_refnames,
 * Remove empty parent directories associated with the specified
	result = log_ref_setup(refs, refname,
	return lock;
	ret = symlink(target, ref_path);
					       &lock->old_oid, NULL)) {
{
		if (at_tail && scanp[-1] == '\n')
			break;
		ok = ITER_ERROR;
		while (*p && *p != '/')
	cb.should_prune_fn = should_prune_fn;
			 * We need to disconnect our transaction from

					get_lock_file_path(&lock->lk));
		if (errno == ENOENT && !S_ISLNK(st.st_mode))
					    lock->ref_name, old_msg);
		errno = EINVAL;
};
	struct ref_iterator *iter_common,
	if (ref_flags & REF_ISSYMREF)
	case REF_TYPE_PSEUDOREF:
{

		int cnt;
}
		*logfd = open(logfile, O_APPEND | O_WRONLY, 0666);
{
			/*
				     struct strbuf *err)

		 * scenarios (even 100% of the default ones).
 * Used as a flag in ref_update::flags when the ref_update was via an
				logmsg, 0, err)) {

		iter->base.oid = iter->iter0->oid;
		ret = ref_transaction_commit(packed_transaction, err);
	while (bob < scan && *(--scan) != '\n')
					    logfile);
 * Check whether the REF_HAVE_OLD and old_oid values stored in update
			 const char *refname, int force_create,

		 * rename(a, b) when b is an existing directory ought
		}
	if (lstat(path, &st) < 0) {
 * IOW, to avoid cross device rename errors, the temporary renamed log must
	case REF_TYPE_OTHER_PSEUDOREF:
	update->flags |= REF_LOG_ONLY | REF_NO_DEREF;
		char *old_msg = strbuf_detach(err, NULL);
		struct ref_lock *lock = update->backend_data;
		close(fd);
		unable_to_lock_message(ref_file.buf, errno, err);
	/* no error check; commit_ref will check ferror */
	const char *worktree_name;
			 * reference. Report it as a low-level
			 */
			    "is at %s but expected %s",

		/*
static int commit_ref(struct ref_lock *lock)
				strbuf_reset(&sb);
		if (update->flags & REF_NO_DEREF) {
{
						  err)) {
		strbuf_addf(err, "couldn't set '%s'", lock->ref_name);
			goto cleanup;
	 * Note that lock_ref_for_update() might append more updates
			     const struct object_id *oid, const char *logmsg,
	strbuf_release(&sb);
			      strerror(cb.true_errno));


	ref_transaction_add_update(
	return 0;
	packed_iter = refs_ref_iterator_begin(
		}
			if (ret) {
			result |= error(_("could not remove reference %s"), refname);
		return -1;
	string_list_clear(&affected_refnames, 0);

				packed_transaction = ref_store_transaction_begin(
		       const struct object_id *oid, int flags, void *cb_data)


static int lock_ref_for_update(struct files_ref_store *refs,
			}
	 * arranges for the reflog of HEAD to be updated, too.
		 */
static int files_reflog_exists(struct ref_store *ref_store,
		files_reflog_path_other_worktrees(refs, sb, refname);
			ret = error("cannot seek back reflog for %s: %s",
#include "../chdir-notify.h"
	 * the reference that it points to. If we see an update of
		}
 * are passed to refs_verify_refname_available() for this check.
				update->backend_data = NULL;
static int files_for_each_reflog_ent(struct ref_store *ref_store,
		refs->loose = create_ref_cache(&refs->base, loose_fill_ref_dir);
 * store_flags to ensure the ref_store has all required capabilities.
	files_ref_iterator_peel,
	if ((*cb->should_prune_fn)(ooid, noid, email, timestamp, tz,
		return -1;
	unsigned int flags;
		required_flags |= REF_STORE_ODB;

#define REF_NEEDS_COMMIT (1 << 6)
		ooid = &cb->last_kept_oid;
		prune_ref(refs, r);
	 * there is no existing packed ref whose name begins with our
	else

	struct stat st;
static void add_per_worktree_entries_to_dir(struct ref_dir *dir, const char *dirname)
	if (!diter) {

	struct strbuf err = STRBUF_INIT;
	char *gitdir;
					 * contain.
						     RESOLVE_REF_READING,
 * /some/other/path/.git/logs/refs, and that may live on another device.
	base_ref_iterator_free(ref_iterator);
	struct files_ref_store *refs =
	}
				   struct ref_transaction *transaction,
		 */
 */

		scanp = endp = buf + cnt;

	}

			reflog_iterator_select, refs);
 * Lock refname, without following symrefs, and set *lock_p to point
			int save_errno = errno;
			     struct string_list *refnames, unsigned int flags)
				}
	 * be valid as long as affected_refnames is in use, and NOT
		if (errno == EISDIR) {
	char *log_file;
				 * We are at the start of the buffer, and the
	}
			 * again:
	DIR *d;

		if ((update->flags & REF_IS_PRUNING) &&
			} else if (check_old_oid(update, &lock->old_oid, err)) {
			/*
		return -1;
		ret = error("unable to copy logfile logs/%s to logs/"TMP_RENAMED_LOG": %s",
			transaction, r->name,
	int type;
							 REMOVE_EMPTY_PARENTS_REFLOG);
	errno = last_errno;
 *     read_raw_ref()
		} else {
	 * If the ref did not exist and we are creating it, make sure
		 * to create the containing directory, "refs/foo",
}
					   const struct string_list *extras,
	unsigned int store_flags;
			 * directories leading to ref_file.  Try
			goto out;
		if (head_ref && (head_flag & REF_ISSYMREF) &&
}
	struct object_id last_kept_oid;
			/*
	files_delete_reflog,
	if (force_create || should_autocreate_reflog(refname)) {
				 const char *target, const char *logmsg)
cleanup:
					 */

/*

	free(lock);

		    ref_type(iter->iter0->refname) != REF_TYPE_PER_WORKTREE)
	iter->flags = flags;
};
				strbuf_addf(err, "unable to create directory for '%s': "
	void *policy_cb;
			goto error_return;
			return -1;
		return TRANSACTION_NAME_CONFLICT;
		return ITER_SELECT_0;
		if (old_oid) {
		 * would be rather costly for this rare event (the direct
}
	int packed_refs_locked;
	case REF_TYPE_NORMAL:

	/*
	} else {
				goto out;
	/*
	save_errno = errno;
{
			 * doesn't cause trouble when we want to rename the
	if (!ret && sb.len)
			oidcpy(&parent_lock->old_oid, &lock->old_oid);

	while (!ret && 0 < pos) {
			    &orig_oid, REF_NO_DEREF)) {
	const char *p;
		 * to by a symbolic ref based on expiring entries in
		files_downcast(ref_store, REF_STORE_WRITE,
 * REF_NO_DEREF set. Split it into two updates:
	if (!(flags & EXPIRE_REFLOGS_DRY_RUN)) {
	strbuf_release(&tmp);
		} else {
 * broken, lock the reference anyway but clear old_oid.
		return -1;
	 */
/*
		if (errno == ENOENT && --attempts_remaining > 0) {
	if (result)
	if (!refs->loose) {
					     const char *refname,

	 */

		struct ref_update *update = transaction->updates[i];
	}
	if (remaining_retries-- <= 0)
			     strerror(errno));
					&update->new_oid, NULL,
	int ret = 0;
		(struct files_reflog_iterator *)ref_iterator;
	p = buf.buf;
		free(path);
			BUG("ref %s is not a main pseudoref", refname);
	 * size, but it happens at most once per transaction.
					       referent.buf, 0,
	ret = create_symref_locked(refs, lock, refname, target, logmsg);

				ret = TRANSACTION_NAME_CONFLICT;
			 * failure.
			       &lock->old_oid, NULL)) {
 * People using contrib's git-new-workdir have .git/logs/refs ->
						   extras, skip, err))
	files_ref_path(refs, &path, dirname);
				 * Process it, and we can end the loop.
			       struct ref_transaction *transaction,
			    original_update_refname(update));
	 * but finding all symrefs pointing to a given branch would be
 * REF_HAVE_OLD, or REF_IS_PRUNING, which are also stored in
					   unsigned int flags, int *type,
	struct object_id oid;
				 newrefname, logmsg, 1);
static int files_transaction_finish(struct ref_store *ref_store,
	 * lockfiles, ready to be activated. Only keep one lockfile
			0,

		error("%s", err.buf);
		strbuf_release(&sb);
		if (remove_empty_directories(&ref_file)) {
	size_t i;
};
	 * doesn't need to check its old OID value, as that will be
{
				break;
			       int flags, struct strbuf *err)
}
		}


 */
	strbuf_release(&sb);
};
	free(backend_data);
		const char *prefix, unsigned int flags)
	rollback_lock_file(&reflog_lock);
		error("unable to restore logfile %s from logs/"TMP_RENAMED_LOG": %s",
			/*
		goto cleanup;
	if (old_oid && !oideq(&lock->old_oid, old_oid)) {

		files_downcast(ref_store, REF_STORE_WRITE | REF_STORE_ODB,
		 */
}
		if (ends_with(de->d_name, ".lock"))
					 * We can't delete the directory,
			    const char *logmsg)
				/*
	}
	/*
					ret = TRANSACTION_GENERIC_ERROR;
	return -1;
			    const char *oldrefname, const char *newrefname,
		/*
		transaction->state = REF_TRANSACTION_CLOSED;
		 * update of a branch) to be worth it.  So let's cheat and

	base_ref_store_init(ref_store, &refs_be_files);
					ret = TRANSACTION_GENERIC_ERROR;
	packed_refs_unlock(refs->packed_ref_store);
		return 0;
		strbuf_addf(err,
	struct files_transaction_backend_data *backend_data;

				strbuf_reset(&sb);
	struct files_ref_store *refs =
		    !strcmp(head_ref, lock->ref_name)) {
	int ret = -1;
				strbuf_splice(&sb, 0, 0, buf, endp - buf);
		return 0;
		 * points to.
		files_downcast(ref_store, REF_STORE_WRITE, "create_symref");
		 * the lockfile to. Hopefully it is empty; try to
			if (*bp == '\n') {
		int update = (flags & EXPIRE_REFLOGS_UPDATE_REF) &&
	 */
	int i, result = 0;
	*lock_p = NULL;


	}
	 * file by a simultaneous process, but our in-memory view is
		strbuf_release(&sb);
static void prune_refs(struct files_ref_store *refs, struct ref_to_prune **refs_to_prune)
retry:
		/* Maybe another process was tidying up. Try again. */
		!is_null_oid(&update->old_oid);
					    logfile, strerror(errno));
 * committed.
static int commit_ref_update(struct files_ref_store *refs,
				/* inconsistent with lstat; retry */
 out:
	if (packed_refs_lock(refs->packed_ref_store, 0, &err))
	 * 100% of the default ones).
	struct ref_transaction *transaction;
					     each_reflog_ent_fn fn,
 * Implementation note: This function is basically
			goto out;
	}
			goto retry;
			struct ref_lock *parent_lock = parent_update->backend_data;
					 * but we also don't know of any

			 * of processing the split-off update, so we
	if (!transaction->nr) {
				&lock->old_oid, oid,


		/*
	files_ref_iterator_abort
		if (is_packed_transaction_needed(refs->packed_ref_store,
		/*
				  NULL, NULL, REF_NO_DEREF,
static int files_ref_iterator_abort(struct ref_iterator *ref_iterator)
	/* Do not pack non-tags unless PACK_REFS_ALL is set: */
			ret = split_symref_update(update,
		if (*logfd < 0) {
 * "caller" is used in any necessary error messages.
		    !(update->flags & REF_NO_DEREF))
					     &lock->old_oid, type);
	email_end[1] = '\0';

	}
	int ip;
	files_transaction_cleanup(refs, transaction);
			     struct string_list *affected_refnames,
					 */
		} else {
	if (string_list_has_string(affected_refnames, "HEAD")) {
	/*
			int result;

	 * to the transaction.
 * If no logfile exists and we decided not to create one, return 0 and
			 * contained references that have been deleted. If

static int write_ref_to_lockfile(struct ref_lock *lock,
	if (ref_transaction_commit(transaction, &err))
	struct strbuf tmp_renamed_log = STRBUF_INIT;
	/*
}
	}
 * set *logfd to the file descriptor opened for appending to the file.

	if (ref_store->be != &refs_be_files)
			    "trying to write non-commit object %s to branch '%s'",
	 * Add new_update->refname instead of a literal "HEAD".
	}
	struct files_ref_store *refs =
		BUG("commit called for transaction that is not open");
	iter = xcalloc(1, sizeof(*iter));
			status |= error("couldn't set %s", lock->ref_name);



			   const char *refname)
 */
				goto out;
	}
			      tmp.buf, path.buf,


			ret = error("refname %s is a symbolic ref, copying it is not supported",
	/* Fail if a refname appears more than once in the transaction: */
		if ((flags & REMOVE_EMPTY_PARENTS_REFLOG) && rmdir(sb.buf))
}



				    oldrefname);
				    struct ref_transaction *transaction,
		int head_flag;

	if (!logfp)
 */
		if (!(update->type & REF_ISSYMREF) &&
		}

 * Used as a flag in ref_update::flags when the loose reference has
					log_file, strerror(errno));
 * to the loose reference lockfile. Also update the reflogs if
	logmoved = log;
		return 0;
				goto error;
	    (update->flags & REF_IS_PRUNING) ||
				 * at (bp + 1). Prefix it onto any prior data
	 * simultaneous processes might try to change a reference at

			flags &= ~REMOVE_EMPTY_PARENTS_REF;
	int ret = 0;
		return -1;
/*
					    refname);

		iter->base.oid = &iter->oid;
	if (ret)
		struct strbuf sb_path = STRBUF_INIT;
 *   update of HEAD.

			      get_lock_file_path(&reflog_lock), strerror(errno));
			       const char *logmsg)
	 * fear that its value will change.

	}
	 * than leaving a reflog without a reference (the latter is a
		remove_empty_directories(&sb_path);
			die("failure preparing to create packed reference %s: %s",
		}

			ret = error("refname %s is a symbolic ref, renaming it is not supported",
static void files_reflog_path_other_worktrees(struct files_ref_store *refs,
	}
static struct ref_iterator *files_reflog_iterator_begin(struct ref_store *ref_store)
				       &iter->oid, &flags)) {
 * by HEAD), then add an extra REF_LOG_ONLY update for HEAD.
{
			goto error_return;
	free(logfile);
				/*

	result = log_ref_write_fd(logfd, old_oid, new_oid,
	if (!strcmp(update->refname, "HEAD")) {
				 * so we know we have complete line starting
	ret = 0;
	return;
				oidclr(&oid);

	 * head_ref within the transaction, then split_head_update()
		nread = fread(buf, cnt, 1, logfp);
static int rename_tmp_log_callback(const char *path, void *cb_data)
	/*
/*
			p++;
static int files_for_each_reflog_ent_reverse(struct ref_store *ref_store,
		if (refs_read_raw_ref(refs->packed_ref_store, refname,
		    !check_refname_format(sb_contents.buf, 0)) {
	 * It's really undefined to call this function in an active
		error(_("could not delete reference %s: %s"),
			}
		if (cb->newlog) {
		 * We store a pointer to update in item->util, but at
	strbuf_release(&refname);
				 * The error message set by
					   struct strbuf *err)
cleanup:
		if (q == p)
	int ret;

		if (!S_ISREG(diter->st.st_mode))
						&update->new_oid,
	 * functions will check that the new updates don't have the

		return;
	if (!strcmp(refs->gitdir, refs->gitcommondir)) {
				 struct ref_lock *lock, const char *refname,
			 */
	refs = files_downcast(ref_store, required_flags, "ref_iterator_begin");
		 * Record that the new update came via HEAD, so that
	strbuf_reset(&sb_contents);
					strerror(errno));
		packed_refs_unlock(refs->packed_ref_store);
	struct object_id orig_oid;
		last_errno = errno;


	if (ret)
		if (update->flags & REF_DELETING &&
	size_t i;
	switch (safe_create_leading_directories(ref_file.buf)) {
	strbuf_release(&ref_file);
				ret = show_one_reflog_ent(&sb, fn, cb_data);
		if (stat(path.buf, &st) < 0) {
struct files_reflog_iterator {
static void files_assert_main_repository(struct files_ref_store *refs,
	if (refs->store_flags & REF_STORE_MAIN)
			 * There is a directory in the way. It might have
{
	files_rename_ref,
		files_reflog_path(refs, &sb, refname);
		struct ref_update *update = transaction->updates[i];

static int files_log_ref_write(struct files_ref_store *refs,
	default:
			    &lock->lk, ref_file.buf, LOCK_NO_DEREF,
 * Verify that the reference locked by lock has the value old_oid
 * Prepare for carrying out update:
	struct lock_file lk;
		if (errno != ENOENT)
		if (ret)
	struct string_list *affected_refnames = cb_data;
		}

	 * First delete any packed versions of the references, while
{
		 * we are trying to lock foo but we used to
		struct string_list_item *item =
	if (fd < 0) {

	return ret;
			       const char *refname, const struct object_id *oid,
		add_entry_to_dir(get_ref_dir(refs->loose->root),
				 newrefname, logmsg, 0);

				 const struct object_id *oid, struct strbuf *err);

		iter->base.refname = iter->iter0->refname;

		    !ref_resolves_to_object(iter->iter0->refname,
		break;
			    oid_to_hex(&update->old_oid));
			strbuf_addf(err,
	 * for example) then logically the HEAD reflog should be
							  REMOVE_DIR_EMPTY_ONLY)) {
						logmsg, 0, &log_err)) {
		if (copy)
{
	}
				}
		if (check_old_oid(update, &lock->old_oid, err)) {
			     struct strbuf *err)


	*lock_p = lock = xcalloc(1, sizeof(*lock));
	pos = ftell(logfp);
	strbuf_init(&refname, dirnamelen + 257);
	switch (ref_type(refname)) {
		strbuf_reset(&sb);
	files_reflog_path(refs, &sb, refname);
	 */
{

					   const struct string_list *skip,
/*
		return -1;
	struct ref_iterator base;
			 * symref is pointing at. Also, we will record
	long pos;
					goto out;
	unlock_ref(lock);
struct files_ref_store {
 *
		 * this bit will be propagated if the new_update

					/*
				 */
/*
			 * The lock was freed upon failure of

		 * except to check whether it is non-NULL.
				 &affected_refnames))
	}
			if (refs_read_ref_full(&refs->base,
		/*
 rollback:
		    !is_null_oid(&update->old_oid))
						  affected_refnames, err);
	if (*logfd >= 0)
		if (close_ref_gently(lock)) {
	get_common_dir_noenv(&sb, gitdir);
		break;
		error("unable to write current sha1 into %s: %s", newrefname, err.buf);
	}
static struct ref_store *files_ref_store_create(const char *gitdir,
	files_reflog_path(refs, &tmp, TMP_RENAMED_LOG);
			goto out;
						     refname, resolve_flags,
	free(logfile);
	update->flags &= ~REF_HAVE_OLD;
 *   any case record it in update->lock->old_oid for later use when



		size_t len = strlen(path);

		return -1;
						  referent.buf, transaction,


	struct files_ref_store *refs =

			const struct string_list *extras,
		strbuf_setlen(&path, path_baselen);
					    struct strbuf *err)
{
	return -1;
}
	}
		}
	if (ref_type(refname) != REF_TYPE_NORMAL)
	for (i = 0; i < transaction->nr; i++) {
static int verify_lock(struct ref_store *ref_store, struct ref_lock *lock,
		strbuf_release(&err);
 */

				     const char *refname,
			 */
	if (strcmp(dirname, "refs/"))
 * (unless it is NULL).  Fail if the reference doesn't exist and
		}
		 * the lockfile is still open. Close it to

	if (!lock) {
	while (update->parent_update)
	struct files_ref_store *refs = xcalloc(1, sizeof(*refs));
}
		unlock_ref(lock);
					  head_ref, &affected_refnames, err);
	 * object that has since been garbage-collected. This is OK as
		 */
	strbuf_release(&sb);
	 * transaction. This check is O(lg N) in the transaction
/*
	if (string_list_has_string(affected_refnames, referent)) {

		else
 */
				 * file to be repo corruption
