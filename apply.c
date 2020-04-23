			state->linenr++;
		first_name = find_name_traditional(&state->root, first, NULL, state->p_value);
	 * @@ -0,0 +N,M @@
	name = find_name_traditional(&state->root, nameline, NULL, 0);
			    !strncmp(np, name, len) &&
	 * delete are not necessarily deletion.
		if (!patch->def_name) {
	return 0;
	if (!strcmp(option, "nowarn")) {
		 * at the index; the target file may not have been added to
	const char *timestamp = NULL, *cp, *colon;
		else if (p->is_delete)
	line += len;
			state->patch_input_file, linenr, err, len, line);

		/*
		default:
static int path_is_beyond_symlink_1(struct apply_state *state, struct strbuf *name)
	if (!patch->is_delete && !newlines && context && state->apply_verbosity > verbosity_silent)
	 */
	return 0;
	if (was_deleted(previous))
				   struct patch *patch)
	struct stat st;
	memset(&preimage, 0, sizeof(preimage));
		int r = check_patch_list(state, list);
	}
		return 0;
		origlen = strtoul(buffer + 6, NULL, 10);
	free(image->line_allocated);
	parse_hdr_state.p_value = p_value;
		return 1;
			return error(_("make_cache_entry failed for path '%s'"),
}
	int phase;
	ce->ce_namelen = namelen;
			N_("apply a patch without touching the working tree")),
		len = parse_fragment(state, line, size, patch, fragment);
		if (ch == '/' && --nslash <= 0)
								size, patch);

	/* No point falling back to 3-way merge in these cases */

				name, patch->new_oid_prefix, oid_to_hex(&oid));

	}
			     patch->old_name);
			/* the symlink at patch->old_name is removed */
			if (!isspace(*buf))
		BUG("patch to %s is not a creation", patch->old_name);
	/*
		if (!memcmp("@@ -", line, 4)) {
 * their names against any previous information, just
		/* Note: with --reject, apply_fragments() returns 0 */

		return EXISTS_IN_WORKTREE;
		OPT_BOOL(0, "check", &state->check,
		fprintf(stderr, _("Falling back to three-way merge...\n"));
	strbuf_add(&fixed, img->buf + current, imgoff);
	if (len < strlen(" 07:01:32") || line[len-strlen(":32")] != ':')
			printf(" mode change %06o => %06o\n",
			break;
static void git_apply_config(void)
			continue;

		if (!fuzzy_matchlines(img->buf + current + imgoff, imglen,
		return 0;

	 * has whitespace breakages unfixed, and fixing them makes the
	}
}
		if (parse_traditional_patch(state, line, line+len, patch))
	}
			fprintf(stderr,
 * This is to extract the same name that appears on "diff --git"
}

			    ws_blank_line(patch + 1, plen, ws_rule))
		result = read_object_file(&oid, &type, &size);
}
static int apply_binary(struct apply_state *state,
	/*
			  int match_beginning, int match_end)
		if (state->apply_verbosity > verbosity_normal)
	 */
			break;
 * whitespace difference. Returns 1 if they match, 0 otherwise
		return 0;
		static const struct opentry {
{
static void clear_image(struct image *image)
	 * An attempt to read from or delete a path that is beyond a
		return NULL;
	fixed = preimage->buf;
		 * a version before our tree fixed whitespace breakage,
	int i, ctx, reduced;

	 * scale the add/delete
	state->update_index = (state->check_index || state->ita_only) && state->apply;
		{ OPTION_CALLBACK, 0, "exclude", state, N_("path"),
	const char *name = patch->old_name ? patch->old_name : patch->new_name;
static void show_mode_change(struct patch *p, int show_name)
static int apply_fragments(struct apply_state *state, struct image *img, struct patch *patch)
			new_blank_lines_at_end++;
		if (strcmp(oid_to_hex(&oid), patch->old_oid_prefix))
		return 0;

		 * a corrupt reverse hunk is.
	return NULL;
		return 0;


static void remove_first_line(struct image *img)
	return squash_slash(xmemdupz(start, len));
	/* post_oid is theirs */
					const char *arg, int unset)
		if (0 <= p && p == q) {
	int size = frag->size;
	return 0;
 * new file we should try to match whatever "patch" does. I have no idea.
 * to store the type of the binary hunk, either deflated "delta"
			cnt - 1, patch->new_name);
		if (res) {

			      int nth_fragment)
	}
			return error(_("the patch applies to an empty "
static size_t date_len(const char *line, size_t len)
		return -128;
			int squelched =
	 */
	*mode = strtoul(line, &end, 8);
	}
		patch->def_name = s;
	else if (patch->new_name)
		}

			fprintf_ln(stderr, _("Rejected hunk #%d."), cnt);
			     unsigned ws_rule)
 * form "@@ -a,b +c,d @@"
	if (!old_name)
		if (preimage->line[i].flag & LINE_COMMON)
	if (res < 0)
		int len = linelen(patch, size);
	const char *old_name = patch->old_name;
	return line + len - tz;
/* remove double slashes to make --index work with such filenames */
			if (second[len] == '\n' && !strncmp(name, second, len))
			np = skip_tree_prefix(p_value, sp.buf, sp.len);

	if (st_mode != patch->old_mode)
			state->p_value_known = 1;
	free(patch->new_name);

				    const char *line,
	 * https://lore.kernel.org/git/7vll0wvb2a.fsf@assigned-by-dhcp.cox.net/
static int apply_option_parse_space_change(const struct option *opt,

	p = tz + 2;
		zoneoffset = (zoneoffset / 100) * 60 + (zoneoffset % 100);

	 * and we would limit the patch line to 66 characters,
			if (git_hdr_len <= len)

	postimage->len = new_buf - postimage->buf;

			      parse_hdr_state.p_value, *linenr);
	if (preimage->nr + current_lno <= img->nr) {
		cp = strchr(cp, '/');
}
	 */
				   struct image *postimage,
			break;

		if (size < len + 6)
	    !ok_if_exists)
			N_("ignore additions made by the patch")),
	if (patch->old_name && patch->new_name &&
	return ret;
		/* otherwise we already gave an error message */

	 * it might with whitespace fuzz. We weren't asked to
			break;
	patch->old_oid_prefix[len] = 0;
		    !memcmp(img->buf + current, preimage->buf, preimage->len))
	int st;
			     struct patch *patch)
	line += offset;
	/* Adjust the contents */
	 * In other words, a hunk that is (frag->oldpos <= 1) with or

	 * GNU: 2010-07-05 19:41:17.620000023 -0500
		OPT_BOOL(0, "allow-overlap", &state->allow_overlap,
				goto unmatch_exit;
			return error(_("binary patch to '%s' creates incorrect result (expecting %s, got %s)"),
{

	free(their_file.ptr);
 * Use the patch-hunk text in "frag" to prepare two images (preimage and
				if (!rename(newpath, path))
			 */
				   " fixing whitespace errors.",
	fragment->newlines = newlines;
	}
			return error(_("%s: does not exist in index"), old_name);
	if (offset < 0 || offset >= len)
static unsigned long linelen(const char *buffer, unsigned long size)
		files++;
				int phase)
	return 0;
	char *img;
		/* Think twice before adding "--nul" synonym to this */
}
	}

	patch->old_mode = patch->new_mode = 0;
 * Copyright (C) Linus Torvalds, 2005
			if (patch->is_new < 0)
	struct patch *previous;
		if ((leading != frag->leading ||

	for (;;) {
		warning(_("truncating .rej filename to %.*s.rej"),
		return 0;

		switch (name[len]) {
			else
		struct stat st;
		return error(_("--index outside a repository"));
	patchsize = parse_single_patch(state,
	if (state->whitespace_error && (state->ws_error_action == die_on_ws_error))
	if (!date_len)
	prepare_image(&tmp_image, img, len, 1);

	 * A usable gitlink patch has only one fragment (hunk) that looks like:
	if (end == line || !isspace(*end))
		}
		return 0;
		size_t start;
static int parse_whitespace_option(struct apply_state *state, const char *option)
	free(preimage.line_allocated);

					 const char *arg, int unset)
	}
					patchsize = llen;
{
		/*
			; /* scan backwards */
	}
	     cnt++, frag = frag->next) {
 * Returns:
}

	}
	state->has_include = 1;
			    (patch->old_name &&
static const char *skip_tree_prefix(int p_value,
		patch->ws_rule = whitespace_rule(state->repo->index,
	for (i = 0; i < state->limit_by_name.nr; i++) {
	forward->next = reverse;
	}
		ws_fix_copy(&tgtfix, target, tgtlen, ws_rule, NULL);
			{ "@@ -", gitdiff_hdrend },
{
			hold_lock_file_for_update(&state->lock_file,
		return 0;
			  const char *path,
			unsigned long size,
	strbuf_addstr(&name, name_);
			l = l->next;
				check_whitespace(state, line, len, patch->ws_rule);

				   size_t len, size_t postlen)

	 * Yes, the preimage is based on an older version that still
	 */
	if (postlen
	const char *tz, *p;
	postlen = 0;
		 */
				return -1;
	unsigned long backwards, forwards, current;
	struct patch *previous = NULL;
		if (!result)
	int match_beginning, match_end;
		line = img->nr - preimage->nr;
	free_and_fail1:

{
			strbuf_release(&sp);
	if (!state->allow_overlap)
	namelen = strlen(patch->new_name);
	patch->result = image.buf;

	previous = previous_patch(state, patch, &status);
	      state->linenr-1, llen-1, buffer);
			     struct strbuf *buf,

static int gitdiff_dissimilarity(struct gitdiff_data *state,

	int hdrsize, patchsize;
		state->ws_ignore_action = ignore_ws_change;
}
}
		stat_patch_list(state, list);

			   struct patch *patch)
		preoff += prelen;
	struct patch *patch;
	/*
			if (name_terminate(c, terminate))
	 * empty or only contain whitespace (if WS_BLANK_AT_EOL is
				   const char *line,
	if (new_name &&
			if (!state->apply_with_reject)
	size_t len;
		if (*buffer++ == '\n')
		old_name = patch->old_name;

 * item->util in the filename table records the status of the path.
/*
}
					patch->old_mode);
			continue;
		return error(_("deleted file still has contents"));
	return res;
	int linenr;
		 * That's a sign that we didn't find a header, and that a
/*
				/* Good */
			      struct patch *patch)
		offset += linelen(line, size);
	return 0;
			  struct patch *patch,

/*
	int status;
#include "dir.h"

		return error_errno(_("closing file '%s'"), path);
		postimage.line_allocated[postimage.nr - 1].len--;
			   path, mode);
	return out;
		return -1;

		return status;
		if (res == -128)
	}
			if (first == '+' && state->no_add)
	assert(patch->is_new <= 0);
	free_fragment_list(patch->fragments);
			{ "+++ ", gitdiff_newname },
}

	return squash_slash(strbuf_detach(&name, NULL));

	return 0;
		struct fragment *fragment;
		} else
	return name;
	struct strbuf name = STRBUF_INIT;

			return -1;
	if (applied_pos >= 0) {
	/*

			show_file_mode_name("delete", p->old_mode, p->old_name);
			struct stat *st,
		OPT_BOOL('3', "3way", &state->threeway,
static int load_patch_target(struct apply_state *state,
 */
	if (len >= 2 && line[len-1] == '\n' && line[len-2] == '\r') {
		}
	parse_hdr_state.root = root;
static int is_dev_null(const char *str)
	len = ptr - line;
			     const char *name,
	unsigned long offset, len;
	}
			if (plen < 0)
static int remove_file(struct apply_state *state, struct patch *patch, int rmdir_empty)
		fprintf(rej, "%.*s", frag->size, frag->patch);
	 * which may become longer when their whitespace errors are
	 * patches that only add are not necessarily creation even

}
			}
{
				discard_cache_entry(ce);
		char *buf_end;
	unsigned long leading, trailing;
		}
	size_t nr;
				patch->new_mode = S_IFREG | 0644;
{
{
	strbuf_release(&nbuf);
			return -1;
			/* with --3way, we still need to write the index out */

	regmatch_t m[10];
		return;

{
	/*
	/*
	} else {
	 * hunk in the same format, starting with patch method (either
	    /* is its preimage one line? */
		if ((llen < 7) || (llen-2) % 5)
			goto free_and_fail1;
		 */
		return 0;

	static regex_t *stamp;
}
static size_t trailing_spaces_len(const char *line, size_t len)
#define SLOP (16)
	/*
			if (state->ws_error_action == die_on_ws_error)
}
	}
 */
			    (ws_rule & WS_BLANK_AT_EOF) &&
	 * line also has this pattern.
	int res;
static int try_create_file(struct apply_state *state, const char *path,


		return 0;
			res = apply_patch(state, 0, "<stdin>", options);
 *   the length of the parsed binary patch otherwise
	if (read_stdin) {
				     patch->new_name);
 * for the caller to write it out to the final destination.
	size -= len;
			  struct patch *patch)
	char *fixed_buf, *buf, *orig, *target;
		/* Add the length if this is common with the postimage */
			else if (first == '+')
	    !strcmp(option, "false") || !strcmp(option, "never") ||
			    ws_blank_line(patch + 1, plen, ws_rule))

	 * but some codepaths store an allocated buffer.
	*p2 = 1;
	preimage.buf = oldlines;
			byte_length = byte_length - 'a' + 27;
		 * should never look at the index when explicit crlf option
		if (*second == '"') {
		 * the index yet, and we may not even be in any Git repository.
		return error(_("%s: does not match index"), name);
	strbuf_release(&buf);
				 &pre_oid, &our_oid, &post_oid);
			   N_("accept a patch that touches outside the working area"),
	prepare_image(image, img, len, !patch->is_binary);
	strbuf_complete(&state->root, '/');
	stream.avail_in = size;
{
	for (offset = 0; size > 0; offset += len, size -= len, line += len, state->linenr++) {
		if (len > state->max_len)
	offset += digits;
		patch->conflicted_threeway = 1;
	    !isdigit(*p++) || !isdigit(*p++))	/* Not a time. */
			return error(_("cannot read the current contents of '%s'"),
	if (*line == '"') {
		/*
	return (uintptr_t)ent->util;
		error_errno(_("failed to write to '%s'"), path);
	assert(postlen

	struct object_id oid;
		       p->old_name, p->new_name, p->score);
		 */
	if (status)
			   const char *line,
			continue;
 */
		 */

			patch->new_name = name;
 * of length postlen
	 * use the whitespace from the preimage.
					     " to apply fragment at %d"),
	 * A hunk to change lines at the beginning would begin with
			return 0;
	if (!state->p_value_known) {
{
	if (state->whitespace_error) {
 *
			else {
{
{
		ptr = eol;
	 * @@ -1,L +N,M @@
		if (size < nextlen + 14 || memcmp("@@ -", line + len + nextlen, 4))
	patch->is_rename = 1;
			if (state->apply_verbosity > verbosity_normal)

			  unsigned mode,
#include "delta.h"
	struct patch *list = NULL, **listp = &list;
		return 0;
	 * for a removal patch.
		cnt = ARRAY_SIZE(namebuf) - 5;
		n = fractional_time_len(line, end - line);
		buf  = nbuf.buf;
static char *find_name_common(struct strbuf *root,
/*
			/* fall through */
	if (state->allow_overlap && match_beginning && match_end &&
	if (qname.len > max) {
			/* an added line -- no counterparts in preimage */
}
	 */
	/* Figure out the number of lines in a fragment */
		state->ws_error_action = (state->apply ? warn_on_ws_error : nowarn_ws_error);
	return parse_options(argc, argv, state->prefix, builtin_apply_options, apply_usage, 0);
	 */
	if (state->check_index)
			  state->repo->index,

	if (!frag->patch)

static int fuzzy_matchlines(const char *s1, size_t n1,
	if (!p_value)
	void *out;

/*
	 * here.
						current, current_lno, preimage_limit);
	int added, deleted;
		return error(_("affected file '%s' is beyond a symbolic link"),
			remove_last_line(&preimage);
		break;
	return 0;
			cp++;
		OPT__VERBOSE(&state->apply_verbosity, N_("be verbose")),
		return -1;

	if (to_be_deleted(previous))
	}
			applied_pos = -1;
	if (state->prefix && *state->prefix) {
	FILE *rej;
	switch (st->st_mode & S_IFMT) {
		 * "plen" is how much of the line we should use for
	 */
	}
		 * Do we have an exact match?  If we were told to match
		if (res < 0)
	struct strbuf *root;
static char *squash_slash(char *name)
			   struct patch *patch)
	} else {
			 * as an error???
}
		ce = make_empty_cache_entry(state->repo->index, namelen);
		while (ctx < preimage->nr &&
{
	for (phase = 0; phase < 2; phase++) {
		}
	return 0;
		int len = linelen(line, size);
	if (!patch->is_new)
		preimage_limit = img->nr - current_lno;
			res = -128;
	return gitdiff_oldmode(state, line, patch);
		/* Try fixing the line in the preimage */
	const char *tz, *p;
	unsigned mode;
	result = xmalloc(st_add3(st_sub(img->len, remove_count), insert_count, 1));
		size_t prelen = preimage->line[i].len;
	ALLOC_GROW(img->line_allocated, img->nr + 1, img->alloc);
	return patch == PATH_TO_BE_DELETED;

}
			remove_first_line(&postimage);
		}
	/*
static int apply_option_parse_exclude(const struct option *opt,
	print_stat_summary(stdout, files, adds, dels);
		} else if (has_epoch_timestamp(second)) {
	/* Adjust the line table */
	end -= n;
		} else if (!patch->lines_added && !patch->lines_deleted) {
 * Returns:
{
static void check_old_for_crlf(struct patch *patch, const char *line, int len)
	 */
				squelched);
	}
	if (preimage_limit != postimage->nr)
	    (preimage = memchr(hunk->patch, '\n', hunk->size)) != NULL &&
		const char *next;
		 * so we might as well take the fix together with their
			 (patch->is_rename == 1) + (patch->is_copy == 1);
	 * within the boundaries.
		if (state->apply_verbosity > verbosity_silent)
		if (ret) {
		if (preimage->nr <= ctx) {
 *   1 if the patch did not apply but user might fix it
{
		ce = make_cache_entry(&result, patch->old_mode, &oid, name, 0, 0);
		/* unquoted second */
				       "'%s' but it is not empty"), name);
	}
 */
	 * B; ask to_be_deleted() about the later rename.  Removal of

			free(to_free);
			APPLY_OPT_RECOUNT),

	for (i = reduced = ctx = 0; i < postimage->nr; i++) {
				      const char *arg, int unset)
	}
{
		 * removing blank lines at the end of the file.  This
			res = -128;
	/* Fractional seconds. */
		if (phase == 0)

	return (applied_pos < 0);
	char *name;
	return 0;
		errs |= res;

						errs = 1;
	 * done in-place when we are shrinking it with whitespace
				 struct image *img,
			if (starts_with(cp, state->prefix))
					       LOCK_DIE_ON_ERROR);
	return read_blob_object(buf, &ce->oid, ce->ce_mode);
		hunk_size = newsize;
	return 0;
	free(patch->old_name);
	if (!patch->old_mode)
{
			    int len,

	patch->lines_deleted += deleted;
}
		 * in the patch->fragments->{patch,size}.
		int added_blank_line = 0;
			goto corrupt;
	/* Hours, minutes, and whole seconds. */

	if (!ptr || eol < ptr)
	/*
			 * There is no way to apply subproject
	end -= trailing_spaces_len(line, end - line);
	default:
}
	if (!len)
	return 0;
	char *preimage_eof;
	return offset;
	memcpy(patch->old_oid_prefix, line, len);
		 * apply the patch data to it, which is stored
	/* See if it matches any of exclude/include rule */

	}
				struct patch *patch)
	 * if the preimage extends beyond the end of the file),
	struct patch *tpatch;
/*
	if (size < 1) {
		strbuf_setlen(&newlines, newlines.len - 1);
	int status;
	else
	}
			  struct image *img,
	/* our_oid is ours */
		if (len <= 0) {

			break;
			 * from taking place in apply_patch() that follows
/*
	       : fixed_preimage.nr <= preimage->nr);
 * moving A to B should not be prevented due to presence of B as we
static void recount_diff(const char *line, int size, struct fragment *fragment)
		       const char *line,

	 * If we had any include, a path that does not match any rule is
		 * the actual patch data. Normally we just remove the
	 * B and rename from A to B is handled the same way by asking
	}
{
 *  -128 if a bad error happened (like patch unreadable)
	if (state->apply_verbosity > verbosity_silent)
	return 1;
			free_fragment_list(patch->fragments);
	const char *old_name = patch->old_name;
		return 0;
	end -= n;
			next++;
}
		} else

		 * first character on the line, but if the line is

		if (add_index_entry(state->repo->index, ce, ADD_CACHE_OK_TO_ADD) < 0) {

		fixed_preimage.line[i].flag = preimage->line[i].flag;
	/* All spaces! */
			return error(_("unable to create backing store "
			N_("also apply the patch (use with --stat/--summary/--check)")),
{
	int found_new_blank_lines_at_end = 0;
	len = ptr - line;
		return 0;

static void update_pre_post_images(struct image *preimage,
{
	/*

	struct cache_entry *ce = NULL;
	}
		 * at the end, size must be exactly at current+fragsize,
		orig += oldlen;
int init_apply_state(struct apply_state *state,
		 */
{
	 */
	 * lines to use the same whitespace as the target.
	if (previous) {
		 * The preimage extends beyond the end of img, so

				return 1;
			0, apply_option_parse_directory },
		    (patch->is_rename || patch->is_delete))
		if (leading >= trailing) {
	int digits, ex;
				if (write_out_one_result(state, l, phase)) {
		    byte_length <= max_byte_length - 4)
			return -1;
}
						 const char *option)
			state->apply_verbosity = verbosity_verbose;
	line = ptr + 2;
			if (nr == -128) {
	else if (status)
				     patch->old_name);
	if (patch->def_name && root->len) {
		zoneoffset = -zoneoffset;
	memcpy(namebuf, patch->new_name, cnt);
	 * any context line by definition, so we cannot safely tell it
		return 0;
			 !memcmp(tgtfix.buf, fixed.buf + fixstart,
	read_mmblob(&base_file, base);
		ce->ce_mode = create_ce_mode(mode);

		case '\t': case ' ':
	char *img;
		if (state->ws_error_action == die_on_ws_error) {

	fragment->oldlines = oldlines;
	for (offset = len;
		}
}
			continue;

	}
				       _("Applied patch %s cleanly."), patch);
	 * Unfortunately, a real creation/deletion patch do _not_ have
	if (!patch->old_name && !patch->new_name) {
}
 * Parse a unified diff. Note that this really needs to parse each
		}

}
			continue;
	}
		/*
			    state->ws_error_action == correct_ws_error)
			fprintf_ln(stderr, _("Context reduced to (%ld/%ld)"
		return 0;


	char *old_name = *name;
	    (oldlines || (patch->fragments && patch->fragments->next)))

		if (line + llen <= second)

	fprintf(output, fmt, sb.buf);

			  int *linenr,
	newlines = fragment->newlines;
	while (size > 4 && !memcmp(line, "@@ -", 4)) {


		 * is given.

/*

		return 0;
{
			free_patch(patch);
	 */
			PARSE_OPT_NONEG, apply_option_parse_include },
}
		if (state->apply_verbosity > verbosity_normal)
				goto end;
	return line + len - p + n;
	int len;
			leading--;
				    int preimage_limit)
		     : (current + preimage->len <= img->len)) &&
	struct fragment *reverse;
				   leading, trailing, applied_pos+1);
	strbuf_addf(&sb, Q_("Applying patch %%s with %d reject...",
			if (!state->apply_in_reverse)
	 */
		case '\\':
		 * real change.
				   char *def,
			error(_("can't open patch '%s': %s"), arg, strerror(errno));
		return error(_("invalid path '%s'"), new_name);
				       "(%s)."), name);
		if (!remove_or_warn(patch->old_mode, patch->old_name) && rmdir_empty) {
	*p = strtoul(line, &ptr, 10);
static int apply_option_parse_whitespace(const struct option *opt,
	case BINARY_DELTA_DEFLATED:
			      int p_value,
		return offset;
	 */
			   struct cache_entry *ce, struct stat *st)

	    !isdigit(*p++) || !isdigit(*p++) || *p++ != ':' ||
			say_patch_name(stderr,
				return error(_("failed to read %s"), name);
	while (s1 < end1 && s2 < end2) {
{
		}
	n = short_time_len(line, end - line);
{
			struct string_list_item *item;
			 struct image *img,
	if (patch->is_binary)
				goto free_and_fail2;
				     state->linenr, (int)len-1, line);
	old_name = patch->old_name;
	struct apply_state *state = opt->value;
	target = img->buf + current;
	unsigned long origlen;
		switch (*line) {
		patch->new_name = name;
			   const char *name,

			 * the callchain led us here, which is:
		return -1;
			    int linenr)

	/*
	 * imgoff now holds the true length of the target that
	}
			oldlines++;

	free(image->buf);
		 * See if the old one matches what the patch
		if (patch->is_binary)
	if (lines > state->max_change)
 * Given the string after "--- " or "+++ ", guess the appropriate
		struct patch *next = list->next;
	img = strbuf_detach(&buf, &len);
	 * worth showing the new sha1 prefix, but until then...
	if (preimage_limit == preimage->nr) {
			return;
			size--;
static int path_is_beyond_symlink(struct apply_state *state, const char *name_)
	max = state->max_len;
			/*
	/*
		return 0;
				     name);
			   unsigned long size)
		char *first_name;
 * When directly falling back to add/add three-way merge, we read from
	strbuf_init(&newlines, size);

}
			  struct image *preimage,
	case S_IFLNK:
		 */
	if (timestamp[m[3].rm_so] == '-')
	else if (status) {
{
		clear_image(img);
/* fmt must contain _one_ %s and no other substitution */
}
/*
		if (p < 0) p = q;
			if (!res) {
		return 0;
		if (r < 0 && !state->apply_with_reject) {
		 * just reduce the larger context.
			if (res < 0)
	patch->new_name = find_name(state->root, line, NULL, state->p_value ? state->p_value - 1 : 0, 0);
#include "apply.h"
		patch->new_name, patch->new_name);
	struct strbuf newlines;
static size_t tz_with_colon_len(const char *line, size_t len)
			return error(_("failed to read %s"), patch->old_name);
	int errs = 0;
	/* Normal git tools never deal with .rej, so do not pretend
				if (len < size - hd &&
					show_mode_change(p, 1);
{
		free(another);
		name->buf[name->len] = '\0';
	}

static int load_preimage(struct apply_state *state,
	 * errors in both fixed, we count how large the corresponding
		if (r == -128) {
	return ie_match_stat(state->repo->index, ce, st,
				   match_beginning, match_end))
					  uintptr_t what)
	if (status < 0 || !result.ptr) {

	if (!state->prefix || p->is_toplevel_relative)
 * Does the ---/+++ line have the POSIX timestamp after the last HT?
			N_("don't expect at least one line of context")),
		img->buf = result;

			break;
				int unset)
#include "diff.h"
			if (first == '-')
		return 0;

			struct cache_entry *ce;
		zoneoffset = zoneoffset * 60 + strtol(colon + 1, NULL, 10);
		return status;
 * Returns:
			if (!lstat(name->buf, &st) && S_ISLNK(st.st_mode))
		state->linenr += 2;
		state->ws_ignore_action = ignore_ws_none;
						     "created file '%s'"),
	}
{
		return;
	unsigned st_mode = 0;
}
			printf("-\t-\t");

	if (ARRAY_SIZE(namebuf) <= cnt + 5) {
	    !isdigit(*p++) || !isdigit(*p++) || *p++ != ':' ||
		/*
		}
	int flush_attributes = 0;
 */
					patch->is_binary = 1;
	if (patch->is_new) {
		struct fragment *next = list->next;
		orig += oldlen;
		       char *def,
		return NULL;

			struct patch *patch)

	patch->new_name = find_name(state->root, line, NULL, state->p_value ? state->p_value - 1 : 0, 0);
		new_buf = postimage->buf = xmalloc(postlen);
	for (i = 0; i < line; i++)

	if (patch->old_name) {
			{ "", gitdiff_unrecognized },
	state->p_value = atoi(arg);
static int gitdiff_newfile(struct gitdiff_data *state,
			char newpath[PATH_MAX];
			if ((patch->new_name &&
{
	}


	prefix_one(state, &p->old_name);
			if (p->is_rename || p->is_copy)
		const char *s;
/*
	 * ignore whitespace, we were asked to correct whitespace
		 * has whitespace breakage, the preimage doesn't).
		free_patch(list);
	int pos, applied_pos;
{
#define TERM_TAB	2
	}

}
}

		/*
			   _("** warning: "
		    preimage.nr + applied_pos >= img->nr &&
	prepare_fn_table(state, patch);
		img->len = len;
			return 0;

			break;
	free(image.line_allocated);
		st_mode = previous->new_mode;
static void add_line_info(struct image *img, const char *bol, size_t len, unsigned flag)
			break;

 * or deflated "literal".
			{ "similarity index ", gitdiff_similarity },
 */
	img->line_allocated[img->nr].flag = flag;
		len++;
	BUG_ON_OPT_NEG(unset);
		if (isnull)
}
	size_t postlen = postimage->len;

		if ((img->line[current_lno + i].flag & LINE_PATCHED) ||
	 * the preimage.
		another = find_name(state->root, line, NULL, state->p_value, TERM_TAB);
		if (new_blank_lines_at_end &&
			  struct cache_entry **ce,
		/* Try fixing the line in the preimage */
	return 0;
	if (offset < 0)
/*
	*gone = 0;
			break;
{
}
	if (patch->old_name) {
		}
	} else if (name) {
	struct fragment *hunk = p->fragments;
/*
			patch->old_name = name;
		return -1;

		 * exactly.
	minute = strtol(timestamp + m[1].rm_so, NULL, 10);
}
		     const char *prefix)
		list = next;
			 * We would want to prevent write_out_results()
			trailing--;
	 * Always add new_name unless patch is a deletion
		return 0;
				patchsize = 0;
	if (add_index_entry(state->repo->index, ce, ADD_CACHE_OK_TO_ADD) < 0) {
		/* Empty patch cannot be applied if it is a text patch

	 * free "oldlines".
	const char *pathname = p->new_name ? p->new_name : p->old_name;
		/* otherwise, check the preimage */
	if (0 < patch->is_delete && newlines)
	 */
 * it is marked as "->free_patch = 1".

static int apply_one_fragment(struct apply_state *state,
{

	if (preimage_limit < postimage->nr) {

			backwards_lno--;


		strbuf_release(&first);
{
	char *end;
	return (res == -1 ? 1 : 128);
{
	memset(&stream, 0, sizeof(stream));
end:
		}
			return error_errno("%s", old_name);

			cp = qname.buf + qname.len + 3 - max;


					       "useless for submodule %s"), name);
}
			len = sp.buf + sp.len - np;
		{ OPTION_CALLBACK, 'p', NULL, state, N_("num"),
			  unsigned ws_rule,
	FREE_AND_NULL(patch->old_name);
static void show_file_mode_name(const char *newdelete, unsigned int mode, const char *name)

			if (first == '-')
		{ OPTION_CALLBACK, 0, "include", state, N_("path"),
	struct image image;
				       size - offset - hdrsize,

	name = skip_tree_prefix(p_value, line, llen);
	}
	preimage.line = preimage.line_allocated;
			current = forwards;
		oidcpy(&patch->threeway_stage[2], &post_oid);
		if (fd < 0) {
{
}

	rollback_lock_file(&state->lock_file);
		while (l) {
	const char *date, *p;
				return NULL;
			   char *path,
}
	if (state->apply_in_reverse) {
}

 * We need to reliably find name only when it is mode-change only,
	 * And a hunk to add to an empty file would begin with

	return 0;

	if (status)

		warning(_("%s has type %o, expected %o"),

	    strcmp(patch->old_name, patch->new_name)) {
	/*
	 *
	size_t preoff = 0;
	if (!res)
	if (old_name && !verify_path(old_name, patch->old_mode))
			break;
	 * We have read "GIT binary patch\n"; what follows is a line
{
}
	mode = patch->new_mode ? patch->new_mode : (S_IFREG | 0644);

	 * lines already, but the common lines were propagated as-is,
 *     so that the caller can call us again for the next patch.
			start = newlines.len;
	int status;
		epoch_hour = 0;
int apply_all_patches(struct apply_state *state,
		patch->is_new = 0;
			patch->new_mode = patch->old_mode;
		 * there cannot be an exact match.
	line += digits;
	if (!strcmp(option, "error")) {
		free(first_name);
 * The (fragment->patch, fragment->size) pair points into the memory given
		*name = find_name(state->root, line, NULL, state->p_value, TERM_TAB);
			/* mode-only change: update the current */
			res = p->fn(&parse_hdr_state, line + oplen, patch);
		 * A leading component of new_name might be a symlink

 * We're anal about diff header consistency, to make
	 * to 52 bytes max.  The length byte 'A'-'Z' corresponds
	const char *time, *p;
#include "quote.h"
{
#define SUBMODULE_PATCH_WITHOUT_INDEX 1
			if (l->rejected)
	strbuf_release(&qname);
		free(result.ptr);


		return error(_("inconsistent header lines %d and %d"),
			free((char *)list->patch);
	free(oldlines);
			return error(_("could not add %s to temporary index"),
			return -1;
 */
	struct image tmp_image;
		     ? (current + preimage->len == img->len)
	strbuf_release(&name);
{

			patch->is_new = 0;
			patch->is_delete = 0;
				val = count_slashes(state->prefix) + 1;
		strbuf_release(&tgtfix);
		state->apply = 0;
	}
		patch += len;
	 * so one line can fit up to 13 groups that would decode

	 * Update the preimage and the common postimage context
		else
}
			{ "rename from ", gitdiff_renamesrc },
		OPT_NOOP_NOARG(0, "allow-binary-replacement"),
	    !strcmp(option, "none")) {
		return !!mkdir(path, 0777);
		return error_errno("%s", old_name);
		    cnt);
 * p_value for the given patch.

			continue;
	 * Adjust the common context lines in postimage. This can be
			if (read_old_data(st, patch, name, buf))
{
		name = find_name_traditional(&state->root, second, first_name, state->p_value);

	st = git_inflate(&stream, Z_FINISH);
	if (old_name != p->old_name)
	/*

}
 * we would want it not to lose any local modification we have, either
	if (!mode)
 * This also decides if a non-git patch is a creation patch or a
		switch (*line) {

				break;
	if (patch->is_binary) {
	preimage.len = old - oldlines;
		byte_length = *buffer;
	if (!ent) {
		state->unsafe_paths = 0;
		int write_res = write_out_results(state, list);

		return;
	char namebuf[PATH_MAX];
		}
{
		match_beginning = 0;
#include "ll-merge.h"
		summary_patch_list(list);



	case BINARY_LITERAL_DEFLATED:
		 * Not having reverse hunk is not an error, but having
		else
			val = count_slashes(state->prefix);
 * We optimistically assume that the directories exist,
	char *buf;
	state->p_value_known = 1;
			break;
}

	size_t imgoff = 0;

{
		if (S_ISGITLINK(expected_mode)) {
	if (state->apply) {
		line += len;
		return 0;
		int len = quote_c_style(patch->new_name, NULL, NULL, 0);
	 * that to the smart and beautiful people. I'm simple and stupid.
				 "%d leading pathname component (line %d)",
/* phase zero is to remove, phase one is to create */
		    int line,
{
	status = load_patch_target(state, &buf, ce, &st, patch, name, mode);
{
			if (!second)
						string_list_append(&cpath, l->new_name);
	int fd, res;
	 */
		    (preimage->line[i].hash != img->line[current_lno + i].hash))
		}
			*hdrsize = git_hdr_len;

	return 0;
		buffer += llen;
			     const char *line,

								state->p_value, line, len,

	 *
		return NULL;
		    struct image *img,
		 * minimum ("@@ -0,0 +1 @@\n" is the shortest).

	struct strbuf nbuf = STRBUF_INIT;
	/* &state->fn_table is cleared at the end of apply_patch() */
	 */
	if (extensions > 1)
	memset(image, 0, sizeof(*image));
	}
					patch->new_mode, new_name,
		 read_blob_object(&buf, &pre_oid, patch->old_mode))
			{ "copy from ", gitdiff_copysrc },
			ce = index_file_exists(state->repo->index, name->buf,
		OPT_BIT(0, "inaccurate-eof", options,
			goto end;
{
		static const char git_binary[] = "GIT binary patch\n";
/*
{
	state->line_termination = '\n';
			struct fragment dummy;
	if (state->fake_ancestor &&
}
		return error(_("unrecognized binary patch at line %d"), state->linenr-1);
	return 1;
		return 0;
#define BINARY_DELTA_DEFLATED	1
	if (patchsize < 0)
	}
		int fd;
			for_each_string_list_item(item, &cpath)
		char c = *line;
			error(_("Unable to write new index file"));
	add_name_limit(state, arg, 1);
			N_("paths are separated with NUL character"), '\0'),
		applied_pos = find_pos(state, img, &preimage, &postimage, pos,
			else {
			if (!state->apply_in_reverse &&
 * As a result, gitdiff_{old|new}name() will check
			return NULL;
	 * @@ -1 +0,0 @@
}
static char *git_header_name(int p_value,
	if (!previous)
		if ((name[j++] = name[i++]) == '/')
	memcpy(result, img->buf, applied_at);
			strbuf_addch(&newlines, '\n');
		reset_parsed_attributes();
 * Check and apply the patch in-core; leave the result in patch->result
{
static int check_patch(struct apply_state *state, struct patch *patch)
		SWAP(p->lines_added, p->lines_deleted);
	state->linenr++;
			}
			struct patch *patch)

			    cnt),
				     *name, state->linenr);
				first = '+';
	 */
	struct fragment *frag;
			       const char *line,
	if (*line == '"') {

					  char **buf_p,
	for (cp = name.buf; p_value; p_value--) {
 * When dealing with a binary patch, we reuse "leading" field
	int i;
					       name->len, ignore_case);
	if (preimage_limit > img->nr - applied_pos)
	/* Apply the patch to get the post image */

	extra_chars = preimage_end - preimage_eof;
	BUG_ON_OPT_ARG(arg);
	 * If a fragment ends with an incomplete line, we failed to include
	char *path = patch->new_name;
	if (is_null_oid(&oid)) {
			struct patch *patch)
			if (state->apply_verbosity > verbosity_silent)
		/*
	for ( ; buf < preimage_end; buf++)
		 */
}

		else
	return NULL;
			{ "dissimilarity index ", gitdiff_dissimilarity },
			oidcpy(&patch->threeway_stage[0], &pre_oid);
	forwards = current;

		if (state->cached)
	 * though they do not have any old lines, and ones that only
		ent = string_list_insert(&state->symlink_changes, path);
	} else {
			warning(Q_("%d line adds whitespace errors.",
	else if (!patch->is_new && !patch->is_copy)
	}
		 */

	}
		 * should reject the hunk at this position.
#include "xdiff-interface.h"
		if (!len || line[len-1] != '\n')
	if (!n)
	added = deleted = 0;
		slash_old = strchr(old_name, '/');
	}
			  const char *line,
				patch->new_mode = patch->old_mode;
			   const char *line,
			 */
		case EXISTS_IN_INDEX:
		if (!S_ISDIR(st->st_mode))
			 */
	state->linenr++;
			      const char *line,
			   const char *buf,
		else if (!memcmp(" differ\n", buffer + hd + llen - 8, 8)) {
			{ "index ", gitdiff_index },
		fragment->size = len;
			    unsigned result,
		state->squelch_whitespace_errors = 0;
			while (s1 < end1 && isspace(*s1))
		MOVE_ARRAY(img->line + applied_pos + postimage->nr,
		 * far as git is concerned.
	return line + len - end;
					patch->old_mode, old_name);
		clear_image(img);
	 * "delta") and the length of data before deflating; a
{
	 * If whitespace is missing in the target (i.e.

 * PATH_TO_BE_DELETED for a path that a later patch would remove.
		SWAP(p->new_name, p->old_name);
		       int p_value,
				 struct patch *patch)
	 * if the other one is just a variation of that with
				state->applied_after_fixing_ws);
	return 0;
	 */
	if (is_dev_null(first)) {

	if (status < 0) {
				      offset),
		    get_oid_hex(s, &ce->oid)) {
static int add_index_file(struct apply_state *state,
	for (i = 0; ; i++) {
{
		/* there has to be one hunk (forward hunk) */
	patch->old_name = find_name(state->root, line, NULL, state->p_value ? state->p_value - 1 : 0, 0);
	img->nr = nr;
				   state->applied_after_fixing_ws),
	if (0 < patch->is_delete && patch->resultsize)
			       int side)

	read_mmblob(&their_file, theirs);
	if (root->len)
		 patch->old_mode != patch->new_mode);
	/* First count added lines in postimage */
	struct image preimage;
	}
	int offset = find_header(state, buffer, size, &hdrsize, patch);
	}
		}
#define BINARY_LITERAL_DEFLATED 2
{
			int res;
	if ((size_t) line > img->nr)
	struct apply_state *state = opt->value;
			  struct patch *patch)
		state->ws_error_action = die_on_ws_error;
	img->len -= img->line[0].len;
	int stage, namelen;
	postimage->nr -= reduced;
	}
	p = line + len - 1;
				    struct image *postimage,
	*name = prefix_filename(state->prefix, *name);
			   struct image *image,
	memcpy(result + applied_at + postimage->len,
			    state->ws_error_action != nowarn_ws_error)
				const char *line,
	if (*colon == ':')
}
			printf(" mode change %06o => %06o %s\n",

	insert_count = postimage->len;
}
				i++;
	nr = img->nr + postimage->nr - preimage_limit;
}

		 * match with img, and the remainder of the preimage
	 * the preimage may extend beyond the end.

				 &oid);
		struct stat st;
	char *old, *oldlines;
		case '\n':
		fragment = fragment->next;
	return res ? -1 : 0;
#define DIFF_NEW_NAME 1
		if (!state->cached && verify_index_match(state, *ce, st))
		return -1;
			   unsigned long size)
 */

}
	if (patch->is_copy || patch->is_rename)
static uintptr_t check_symlink_changes(struct apply_state *state, const char *path)
static int gitdiff_verify_name(struct gitdiff_data *state,
	if (!cp)
		state->ws_ignore_action = ignore_ws_change;
static int was_deleted(struct patch *patch)
end:
			 * Skip whitespace. We check on both buffers
		return error(_("could not write temporary index to %s"),
	 * A patch to swap-rename between A and B would first rename A
			while (s2 < end2 && isspace(*s2))
						errs = 1;
			   const char *line,
	}
			;
	if (S_ISGITLINK(mode)) {
		    (ws_rule & WS_BLANK_AT_EOF) &&
	struct strbuf buf = STRBUF_INIT;
	 * Make sure that we have some slop in the buffer
		origlen = strtoul(buffer + 8, NULL, 10);
	 * it in the above loop because we hit oldlines == newlines == 0
		strbuf_add(&buf, previous->result, previous->resultsize);
	strbuf_remove(&name, 0, cp - name.buf);
	struct fragment *frag = patch->fragments;
	/* Preimage the patch was prepared for */
	/* Binary patch is irreversible without the optional second hunk */
		/*
		int deflen = strlen(def);
		 * must be blank.

		return NULL; /* "git" patches do not depend on the order */
static int gitdiff_renamedst(struct gitdiff_data *state,
			new_blank_lines_at_end = 0;

		OPT_SET_INT('z', NULL, &state->line_termination,
{
		used += used_1;
	 */

	    preimage[sizeof(heading) + the_hash_algo->hexsz - 1] == '\n' &&
	if (!n)
	 * and optional space with octal mode.
			goto out;
static void show_rename_copy(struct patch *p)
			 struct image *image,

		if ((match_end
				       buffer + offset + hdrsize,
						  LOCK_DIE_ON_ERROR);
{
		unsigned long sz;
			show_file_mode_name("create", p->new_mode, p->new_name);
		 * "git apply" without "--index/--cached" should never look
	free(old_name);
static int find_header(struct apply_state *state,
			return error(_("binary patch does not apply to '%s'"),
 *
		 * l10n of "\ No newline..." is at least that long.
					   const char *arg, int unset)
	oldlines = xmalloc(size);
{
	img->buf += img->line[0].len;
}
	for (;;) {
		free(patch->def_name);
		       old_name, new_name, p->score);
	struct string_list cpath = STRING_LIST_INIT_DUP;

{
		 */
				 &oid);
	BUG_ON_OPT_NEG(unset);
			return 0;
		if (load_preimage(state, &tmp_image, patch, st, ce))
		size -= len;
}
	git_inflate_end(&stream);
		for (j = fixstart; j < fixed.len; j++)
		if (!strcmp(arg, "-")) {
	}
			if (res > 0)

	result[img->len] = '\0';
	state->repo = repo;
	struct string_list_item *ent;
			if (unquote_c_style(&sp, second, NULL))

		 * of context lines.
			second = skip_tree_prefix(p_value, name + len + 1,
		struct strbuf first = STRBUF_INIT;
		int plen;
}
	} else if (state->ws_error_action == correct_ws_error &&
	if (!patch->is_delete && path_is_beyond_symlink(state, patch->new_name))

{
/*

		size = nbuf.len;
				       "'%s' cannot be read"),
			state->p_value = p;
				_("Failed to fall back on three-way merge...\n"));

	/*

	unsigned long oldlines = 0, newlines = 0, context = 0;
	}
{
static int find_pos(struct apply_state *state,
 */
		}
 */
		return 0;

	free(data);
	if (patch->direct_to_threeway ||

		 */
			fprintf(stderr,
			   patch->new_name);
static int use_patch(struct apply_state *state, struct patch *p)
	 */
		memcpy(new_buf, fixed, l_len);
	for (stage = 1; stage < 4; stage++) {

		return -1;
		if ((leading <= state->p_context) && (trailing <= state->p_context))
	return 0;
		rejected:1;
		return NULL; /* the deletion hasn't happened yet */
		quote_c_style(patch->new_name, &sb, NULL, 0);

					       p->new_name, p->score);
	if (p_value == 0)
		return error(_("%s: wrong type"), old_name);

 */
 */
		strbuf_release(&name);
			continue;
	char *data = NULL;
	 * with unidiff without any context.
	 *
		if (!n)
	match_beginning = (!frag->oldpos ||
	 *
		} else {
				check_whitespace(state, line, len, patch->ws_rule);
		 * last one (which is the newline, of course).
			/*
	} else {
	 * follows.
		patch->ws_rule = whitespace_rule(state->repo->index,
	old_name = p->old_name;
		 */
	strbuf_init(&fixed, preimage->len + 1);
						  state->index_file,
	if (skip_prefix(timestamp, "1969-12-31 ", &timestamp))
{
	if (state->apply_with_reject && state->threeway)
	patch->new_name = xstrdup_or_null(patch->def_name);
 */

 *
		    struct image *preimage,
	 * expanding leading tabs to spaces.
			   struct patch *patch)
		if (!cp)
 * we read from the result of a previous diff.
		patch->old_mode = st_mode;
	}
{

	return used;
				goto free_and_fail1;
	}
		patch->new_mode = st_mode;
			if (used)
			 * found) exactly match?
		if (res < 0)
	if (!isdigit(*p++) || !isdigit(*p++) || *p++ != ':' ||
		int j;
			N_("show number of added and deleted lines in decimal notation")),
		OPT_BOOL(0, "numstat", &state->numstat,
	ep = image->buf + image->len;
static void reverse_patches(struct patch *p)
	unsigned mode = patch->new_mode;
}
			/* the symlink at patch->new_name is created or remains */
static int gitdiff_copysrc(struct gitdiff_data *state,
			goto free_and_fail1;
	fixed_buf = strbuf_detach(&fixed, &fixed_len);
		free(to_free);
			      const char *line,
	free(img->buf);
"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";
		if (read_file_or_gitlink(ce, buf))
			return offset;
		if (state->applied_after_fixing_ws && state->apply)

		unsigned int nr = getpid();
	return 1;

	llen = linelen(buffer, size);
		patch = patch->next;
			return -128;
			error(_("while searching for:\n%.*s"),
	if (apply_data(state, patch, &st, ce) < 0)
		return error(_("unable to add cache entry for %s"), path);

	if (!use_patch(state, patch))

	} while (1);
		int len;
{
		/* and copy it in, while fixing the line length */
 * Replace "img" with the result of applying the binary patch.
	if (state->cached && state->threeway)

			   int p_value)
		 * exceed 3 bytes
{
	char *buffer = *buf_p;
		string_list_sort(&cpath);
			break;
	}
/*
{
	 * beyond the end of the file and make sure that all of them

	if (max > 50)

	}

		} else if (*s1++ != *s2++)
			}
	if (state->update_index && !is_lock_file_locked(&state->lock_file)) {
}
			   struct patch *patch)
			goto free_and_fail1;
		patch->inaccurate_eof = !!(options & APPLY_OPT_INACCURATE_EOF);
			 * patch without looking at the index.
	int cnt = 0;

 *   -128 on another error,
	const char stamp_regexp[] =
	 * Because the comparison is unsigned, the following test
	 * is not deposited to a path that is beyond a symbolic link
		if (!end && isspace(c)) {
	 * fraction cannot be one, hence "(\.0+)?" in the regexp below.
	printf(" %-*s |", max, qname.buf);
			res = -128;
			ret = size < 3 || !starts_with(line, "@@ ");
 * sure that we don't end up having strange ambiguous

	if (*line == ',') {
	oldlines = fragment->oldlines;
 * postimage) for the hunk.  Find lines that match "preimage" in "img" and
			oidclr(&patch->threeway_stage[0]);

	struct option builtin_apply_options[] = {
	}
	memset(&postimage, 0, sizeof(postimage));
	struct string_list_item *item;
	return 0;
			while (name[i] == '/')
	}
	/*
}
		return;
	 * We trust the caller to tell us if the update can be done
	/* Paths outside are not touched regardless of "--include" */
	if (!len || !isdigit(line[len - 1]))
		if (!len)
	 * be creation, and if something was added it cannot be
	}
	ret = path_is_beyond_symlink_1(state, &name);
			if (state->apply_in_reverse &&
				continue;
 * Update the preimage, and the common lines in postimage,
			newlines--;
	} else {
		if (patch->is_new)

{

{
		ok_if_exists = 0;
	if (!list && !skipped_patch) {
		strbuf_release(&qname);
	return 0;
		offset += digits+1;
	free(data);
}
				     new_name);
			 struct image *postimage)
	for (patch = list; patch; patch = patch->next) {
				strbuf_add(&newlines, patch + 1, plen);
	ce = state->repo->index->cache[pos];
			if (!isspace(*s2))
	mmbuffer_t result = { NULL };
		       int terminate)
				return -1;
			return 0;


		if (!lstat(path, &st) && (!S_ISDIR(st.st_mode) || !rmdir(path)))
}
static void show_stats(struct apply_state *state, struct patch *patch)
	 * remove the copy of preimage at offset in img
 *   -1 if no header was found or parse_binary() failed,
int parse_git_diff_header(struct strbuf *root,
	    build_fake_ancestor(state, list)) {
{
static int gitdiff_newmode(struct gitdiff_data *state,
	struct patch *previous;
			       fixed_buf, fixed_len, postlen);
			if (ce && S_ISLNK(ce->ce_mode))
	char *ptr;
	BUG_ON_OPT_NEG(unset);
		return NULL;
	backwards_lno = line;
{
		if (S_ISDIR(nst.st_mode) || ok_if_exists)
	if (verify_index_match(state, ce, &st))
		if (!dst)
	pos = index_name_pos(state->repo->index, path, strlen(path));
			frag->rejected = 1;
			   struct patch *patch)
	 * but in this loop we will only handle the part of the
{
	pos = frag->newpos ? (frag->newpos - 1) : 0;
	 * seen that pretends to start at the beginning (but no longer does),
		 * on locale settings when the patch was produced we
	}
			state->max_len = len;
		 * applies to.
}
		 * Make sure we don't find any unconnected patch fragments.
				 "%d leading pathname components (line %d)",

				goto end;
	else
		 * Minimum line is "A00000\n" which is 7-byte long,
			/*
 *
		return -1;
		line += digits+1;
 *
		 * that is going to be removed with this patch, but
	patch->is_copy = 1;
	patch->is_delete = 0;
 * include/exclude
		 * thing we do know is that it begins with "\ ".
		name = find_name_traditional(&state->root, second, NULL, state->p_value);
			strbuf_release(&name);
}
		if (write_res > 0) {
 * both sides are the same name under a/ and b/ respectively.

	free(patch);
 * the patch wants to remove lines with CRLF.
 *  -1 if patch did not apply and user cannot deal with it
	return 0;
		if (next < ep)
		if (!digits)
};
		if (!patch->new_mode)
			len = strlen(patch->new_name);
	struct apply_state *state = opt->value;
	free(preimage->line_allocated);
	strbuf_addstr(&state->root, arg);
	return	patch->is_rename > 0 ||
	}

				   patch->is_new, &patch->old_name,

		cp = skip_tree_prefix(p_value, second, line + llen - second);
{
static int verify_index_match(struct apply_state *state,
	int new_blank_lines_at_end = 0;
}
}
	return previous;

			oldlines--;
	 *


		item = string_list_insert(&state->fn_table, patch->old_name);

			for (i = 0; binhdr[i]; i++) {

		*gone = 1;
			timestamp = cp + 1;
			if (!state->apply_in_reverse &&
				break;
 * path that a previously applied patch has already removed, or
			 * only interested in the case where there is
		 * we are not removing blanks at the end, so we
			}
			old += plen;
		if (name)

}
	if (date - line >= strlen("19") &&
	state->p_value = 1;


{
			{ "old mode ", gitdiff_oldmode },
		return error(_("cannot apply binary patch to '%s' "

		img->len = size;
		/*
	int res = 0;

}
static char *find_name(struct strbuf *root,
	if (!prepare_linetable)
		del = total - add;
				return 0;
	    S_ISGITLINK(patch->old_mode) || S_ISGITLINK(patch->new_mode))
 * modification to an existing empty file.  We do not check the state

		int nr;
	if (phase == 1)
 * This applies patches on top of some (arbitrary) version of the SCM.
		res = -128;
		for (i = 0; i < postimage->nr; i++)
		patch->is_delete = 0;
	status = ll_merge(&result, path,
			     patch->new_name ?
		return 0;

		 * Warn if it was necessary to reduce the number
		default:
	return 0;
{
	int preimage_limit;
	size_t len;
	return 0;
	int ret;
 * this function will be called.
	const char *second = NULL;
	}
		if (change & APPLY_SYMLINK_IN_RESULT)

						   path);
			      (int)(old - oldlines), oldlines);
		goto end;
	ent = string_list_lookup(&state->symlink_changes, path);
			start = line;
		return error_errno(_("cannot open %s"), namebuf);
				patch->new_name);
	patch->is_new = 1;
	if (state->check_index &&
	 * +Subproject commit <new sha1>
	fputc('\n', output);
	if (errno == EEXIST) {
/* This function tries to read the object name from the current index */

		return status;
				N_("ensure at least <n> lines of context match")),
		if (state->apply_verbosity > verbosity_silent)
	if (!option || !strcmp(option, "no") ||
	}

}
		state->ws_error_action = warn_on_ws_error;
	*preimage = fixed_preimage;
		case '-':
	if (!state->whitespace_option && !apply_default_whitespace)
			      const char *line,
static int check_unsafe_path(struct patch *patch)
{

	if (!strcmp(option, "strip") || !strcmp(option, "fix")) {
}
	if (S_ISGITLINK(mode)) {
		struct string_list_item *it = &state->limit_by_name.items[i];
		return remove_file(state, patch, patch->is_rename);
	size_t extra_chars;
static int write_out_one_result(struct apply_state *state,
static int parse_binary(struct apply_state *state,
	while (1) {
 * by the caller, not a copy, when we return.
		strbuf_remove(&first, 0, cp - first.buf);
			   struct patch *patch)
{
 *
		size_t l_len = postimage->line[i].len;
/*
static int gitdiff_oldname(struct gitdiff_data *state,
	else if (state->update_index)
	const char *start = NULL;
	if (state->update_index && !state->ita_only) {
static int try_threeway(struct apply_state *state,
	if (has_object_file(&oid)) {
 * of context lines.
};
	free(patch->result);
}
		"^[0-2][0-9]:([0-5][0-9]):00(\\.0+)?"
static int guess_p_value(struct apply_state *state, const char *nameline)
				while (new_blank_lines_at_end--)
	struct line *line_allocated;
{
		if (i & 1) {
				    !memcmp(binhdr[i], buffer + hd, len)) {
		return error(_("missing binary patch data for '%s'"),
	}
			newlines--;
			fprintf(stderr,
			else {
		return line_by_line_fuzzy_match(img, preimage, postimage,
		read_stdin = 0;
		return error(_("path %s has been renamed/deleted"),
			int offset = applied_pos - pos;
	else
		return error(_("new file %s depends on old contents"), patch->new_name);

	}
 *
}
	return offset;
	    !get_oid_hex(preimage + sizeof(heading) - 1, oid) &&
	if ((!patch->new_name && !patch->is_delete) ||
	struct apply_state *state = opt->value;
		cnt++;
	for (cnt = 0, frag = patch->fragments; frag; frag = frag->next) {
		 * preimage is expected to run out, if the caller
		patch->score = val;
		OPT_END()
	patch->is_rename = patch->is_copy = 0;
			discard_cache_entry(ce);
				       patch);
	strbuf_reset(&state->root);
 * them to the given patch structure.
	if (state->apply_verbosity > verbosity_silent)
		if (state->apply_verbosity > verbosity_normal)
			      int inaccurate_eof, unsigned ws_rule,
			     patch->extension_linenr, linenr);
	patch->resultsize = image.len;
	 * or
		if (state->index_file)
		OPT_INTEGER('C', NULL, &state->p_context,
	}
	write_object_file(tmp_image.buf, tmp_image.len, blob_type, &our_oid);
		slash_new = strchr(new_name, '/');
	else {
		if (!len || line[len-1] != '\n')
			 * see a new one created at a higher level.
		return NULL;
		       unsigned long *p1, unsigned long *p2)
				       get_git_dir());
			goto corrupt;

			 * and the postimage pathname?  Again, we are
 *   1 if the patch did not apply cleanly
		}

 *
	}
		return 0;
		if (state->apply_verbosity == verbosity_normal)
	struct cache_entry *ce;
{
 * the next patch is to look at the line counts..
	int len = linelen(line, size), offset;
			  const char *line,

	if (patch->new_name != NULL) {
{
	/*
	if (has_symlinks && S_ISLNK(mode))
		 * or we are lacking a whitespace-fix patch the tree
		offset += len;
				   Q_("Hunk #%d succeeded at %d (offset %d line).",
		nextlen = linelen(line + len, size - len);

	    index_name_pos(state->repo->index, new_name, strlen(new_name)) >= 0 &&
	if (!patch->recount && !deleted && !added)
static uintptr_t register_symlink_changes(struct apply_state *state,
	mmfile_t base_file, our_file, their_file;
			if (git_hdr_len < 0)
	if (len < strlen("72-02-05") || line[len-strlen("-05")] != '-')
		if (!slash_old ||
 corrupt:

	return parse_mode_line(line, state->linenr, &patch->old_mode);
}
{
	}
	if (!ce)
		if (!ce)
				break;
		}
	struct index_state result = { NULL };
		if (patch->is_new < 0)
		case EXISTS_IN_WORKTREE:
		case '-':
	/* This should not happen, because a removal patch that leaves
			say_patch_name(stderr,
		if (unquote_c_style(&first, line, &second))
				goto again;
 */
			const char *str;

		char *name = find_name_gnu(root, line, p_value);
		 * There must be one non-blank context line that match
	    img->nr - preimage->nr != 0)
	return line + len - time;
int check_apply_state(struct apply_state *state, int force_apply)
/*

		size_t fixstart = fixed.len; /* start of the fixed preimage */

			return create_file(state, patch);
		return squash_slash(ret);
			 const struct cache_entry *ce)
/*
	if (tz[1] != '+' && tz[1] != '-')
				}
			printf("%d\t%d\t", patch->lines_added, patch->lines_deleted);
		item->util = PATH_WAS_DELETED;
	if (postlen)
	strbuf_add(&fixed, preimage_eof, extra_chars);
			int (*fn)(struct gitdiff_data *, const char *, struct patch *);
	    (newlines || (patch->fragments && patch->fragments->next)))
			   const char *line,
			/* fallthrough */
	 */
			 * NEEDSWORK: shouldn't this be flagged

	    hunk && !hunk->next &&
}
			    _("git apply: bad git-diff - inconsistent new filename on line %d") :
	frag->size = origlen;
	if (!digits)

		error(_("unable to read index file"));
		 * still pointing at somewhere that has the path.
			N_("instead of applying the patch, output a summary for the input")),
 * Create fragments (i.e. patch hunks) and hang them to the given patch.
{
		strbuf_addf(buf, "Subproject commit %s\n", oid_to_hex(oid));
		write_name_quoted(name, stdout, state->line_termination);
	if (errno == ENOENT) {
					printf(" rewrite %s (%d%%)\n",

	const char *cp, *ep;
	if (offset > 0 && patch->recount)
	       img->len - (applied_at + remove_count));
		p = guess_p_value(state, first);
		res = check_patch(state, patch);
			return name;
	 * preimage that falls within the file.
	free(patch->new_name);
 */
		if (strcmp(oid_to_hex(&oid), patch->new_oid_prefix))
			  struct stat *st)
		 *
			return -1;
	patch->is_rename = 1;
	}
static void add_to_fn_table(struct apply_state *state, struct patch *patch)
			SWAP(frag->newlines, frag->oldlines);
	if (status)
	if (!state->cached && !previous)
			return error(_("%s: does not match index"), old_name);
	const char *new_name = patch->new_name;
		strbuf_release(&sp);
	if (val <= 100)
		       (int)(old_name - p->old_name), p->old_name,
		const char *name;
	 * more than one hunk it is not creation or deletion.
	for (i = 0; i < postimage->nr; i++) {
		       struct patch *patch)
			struct stat st;
	}
	/* ignore line endings */
	if (!state->cached) {
	/*
{
		patch->old_name = name;
	 * and such a path is used.
	unsigned long size = *sz_p;
static int parse_chunk(struct apply_state *state, char *buffer, unsigned long size, struct patch *patch)
 * Update "img" to remove "preimage" and replace it with "postimage".
				    struct patch *patch,
			   int ok_if_exists)
	struct line *line;
		patch->is_new > 0 ||
		/*
		if (!oldlines && !newlines)
}
		fragment->linenr = state->linenr;
#define PATH_TO_BE_DELETED ((struct patch *) -2)

	leading = frag->leading;
	if (state->check_index && read_apply_cache(state) < 0) {
		state->apply = 0;
		{ OPTION_CALLBACK, 0, "ignore-whitespace", state, NULL,
					patch->new_mode, new_name,
			warning(Q_("%d line applied after"

		*ce = state->repo->index->cache[pos];
				   patch->is_delete, &patch->new_name,
	return 0;
			continue;
		if (remove_file_from_index(state->repo->index, patch->old_name) < 0)
static int gitdiff_unrecognized(struct gitdiff_data *state,
 * header).  Read hunks that belong to this patch into fragments and hang
		return error(_("--reject and --3way cannot be used together."));
	eol = strchrnul(line, '\n');
		show_stats(state, patch);
		 * don't know what this line looks like. The only
		int hd = hdrsize + offset;
	else if (skip_prefix(timestamp, "1970-01-01 ", &timestamp))
	if (state->check_index && !previous) {
{
		       int *hdrsize,
	if (!name)
				int len = strlen(binhdr[i]);
		update_image(state, img, applied_pos, &preimage, &postimage);
	int files, adds, dels;
	trailing = 0;
		switch (first) {
			if (plen && (ws_rule & WS_BLANK_AT_EOF) &&
		size -= len;
	record_ws_error(state, result, line + 1, len - 2, state->linenr);
	while (line != end) {

	size_t i;
#define LINE_PATCHED	2
			old_name, st_mode, patch->old_mode);
			*old++ = '\n';
		patch->extension_linenr = linenr;
}
static int write_out_one_reject(struct apply_state *state, struct patch *patch)
		OPT_BOOL('R', "reverse", &state->apply_in_reverse,
 is_new:
	state->ws_ignore_action = ignore_ws_none;
	/*
static int parse_ignorewhitespace_option(struct apply_state *state,
	 * than `match_beginning`.
		while (--name->len && name->buf[name->len] != '/')
	size -= len;
	forward = parse_binary_hunk(state, &buffer, &size, &status, &used);
		}

				    struct image *preimage,
			const struct cache_entry *ce)
			item->util = PATH_TO_BE_DELETED;
		size -= len;
{
		}
	if (read_apply_cache(state) < 0)
			{ "copy to ", gitdiff_copydst },
	else
			break;
static struct patch *in_fn_table(struct apply_state *state, const char *name)
 *   1 if a recoverable error happened
	int hunk_linenr = frag->linenr;
		if (status < 0)
	quote_c_style(cp, &qname, NULL, 0);
		 * terminated.
			postlen += imglen - prelen;
	}
		/* --- followed by +++ ? */
	if (state->apply_with_reject) {
		}
		l_len = preimage->line[ctx].len;
		printf(" %s %.*s{%s => %s} (%d%%)\n", renamecopy,
static int read_blob_object(struct strbuf *buf, const struct object_id *oid, unsigned mode)
	int preimage_limit;
		if (match_fragment(state, img, preimage, postimage,
	return error(_("unrecognized whitespace ignore option '%s'"), option);
	int pos;
	return h;
				    int llen)
			       fixed_buf, fixed_len, postlen);
 */

			if (state->apply_verbosity > verbosity_normal)
struct gitdiff_data {
			 const char *path, struct strbuf *buf)

				 parse_hdr_state.p_value),
				      (first == '+' ? 0 : LINE_COMMON));
		state->apply = 1;
	if (tz[0] != ' ' || (tz[1] != '+' && tz[1] != '-'))

		buf_end = buf;
	 * index line is N hexadecimal, "..", N hexadecimal,

	img->buf = result;
			      const char *def,
		strbuf_init(&tgtfix, tgtlen);
	 * "literal" or "delta") with the length of data, and a sequence
			0, apply_option_parse_p },
	while (s1 < end1 && (end1[-1] == '\r' || end1[-1] == '\n'))

			return error(_("%s: already exists in index"), new_name);
			if (len < oplen || memcmp(p->str, line, oplen))
			patch->fragments = NULL;
	 * 'patch' is usually borrowed from buf in apply_patch(),
	clear_image(&tmp_image);
	/* Once we start supporting the reverse patch, it may be
	costate.refresh_cache = 1;
		return read_index_from(state->repo->index, state->index_file,

 * this such a timestamp?
		case '@':
	size_t offset;
	 * fixing, but needs a new buffer when ignoring whitespace or

		       int fd,
		}
			 * because we don't want "a b" to match "ab".
		if (!(postimage->line[i].flag & LINE_COMMON))
		return error(_("--cached and --3way cannot be used together."));
		return error(_("removal patch leaves file contents"));
			newlines++;
			if (used < 0)
			    const char *line,
			 struct patch *patch)
	for (; p; p = p->next) {
		set_default_whitespace_mode(state);
			N_("make sure the patch is applicable to the current index")),
	it = string_list_append(&state->limit_by_name, name);
	if (match_beginning)
			  struct fragment *fragment)
			       p->old_mode, p->new_mode);
		free_and_fail2:
		 */
	 * here.  We however need to make sure that the patch result
	if ((patch->new_name == NULL) || (patch->is_rename)) {

	return -1;
			  &base_file, "base",
	strbuf_release(&state->root);
			error(Q_("%d line adds whitespace errors.",
			return 0;
/*

		patch->new_name = xstrdup(patch->def_name);
		plen = len - 1;
	img->nr++;
		if (*p != ' ')
	}
/*

	if (patch->is_delete > 0) {

		return squash_slash(xstrdup_or_null(def));
	     0 < size;
	return errs;
	const char *renamecopy = p->is_rename ? "rename" : "copy";
}
		return -1;
		} else {
	hold_lock_file_for_update(&lock, state->fake_ancestor, LOCK_DIE_ON_ERROR);
	 * symbolic link will be prevented by load_patch_target() that
		 * find the second name.
	oidcpy(oid, &state->repo->index->cache[pos]->oid);
		return 0;
		else if (status == SUBMODULE_PATCH_WITHOUT_INDEX) {
		 * at least have "@@ -a,b +c,d @@\n", which is 14 chars
		int pos = index_name_pos(state->repo->index, old_name,
	char *buf = patch->result;
		new_buf = old_buf;
				say_patch_name(stderr, _("Skipped patch '%s'."), patch);
	*sz_p = size;
	 */
		if (use_patch(state, patch)) {
				       _("Checking patch %s..."), patch);
	}
	int is_not_gitdir = !startup_info->have_repository;
	size_t n;
	 * -Subproject commit <old sha1>

	 * fuzzy matching. We collect all the line length information because
		if (checkout_target(state->repo->index, ce, &st))
 * depending on the situation e.g. --cached/--index.  If we are
	if (load_preimage(state, &image, patch, st, ce) < 0)
			  unsigned long size)
	return 0;
	return 0;

	else if (starts_with(buffer, "literal ")) {
static int get_current_oid(struct apply_state *state, const char *path,
 * from buffer buf of length len. If postlen is 0 the postimage
	size_t len;
	}
			error(_("patch fragment without header at line %d: %.*s"),
			return -128;

	previous = in_fn_table(state, patch->old_name);
	 */
		    struct image *postimage,

	cp = strchr(name, '/');
	 * The hunk does not apply byte-by-byte, but the hash says
	 * later chunks shouldn't patch old names
 * are swapped by first renaming A to B and then renaming B to A;
		 * NOTE: this knows that we never call remove_first_line()
		default:
}
	memcpy(namebuf + cnt, ".rej", 5);
			   const struct object_id *base,
			trailing = 0;
			if (!isspace(fixed.buf[j]))

	return 0;
	 * Ok, the preimage matches with whitespace fuzz.
	buf = preimage_eof = preimage->buf + preoff;
{
	if (p->old_mode && p->new_mode && p->old_mode != p->new_mode) {
		patch_method = BINARY_DELTA_DEFLATED;
	struct patch *l;

	parse_hdr_state.linenr = *linenr;

		if (add_index_entry(&result, ce, ADD_CACHE_OK_TO_ADD)) {
			     const struct cache_entry *ce,

		char *s = xstrfmt("%s%s", root->buf, patch->def_name);
	if (!stamp) {
	 */
	img->len -= img->line[--img->nr].len;

	 * hunk match.  Update the context lines in the postimage.
	 */
		die(_("internal error"));
		int total = ((add + del) * max + state->max_change / 2) / state->max_change;
	return gitdiff_verify_name(state, line,
}
	    /* does preimage begin with the heading? */
		if (strbuf_readlink(buf, path, st->st_size) < 0)
	for (i = 0; i < preimage_limit; i++) {
{
	patch->rejected = 1; /* we will drop this after we succeed */
	int conv_flags = patch->crlf_in_old ?
#define PATH_WAS_DELETED ((struct patch *) -1)

	struct image fixed_preimage;
	int i;
	if (!forward && !status)
	ptr = strchr(line, '.');
			   (frag->oldpos == 1 && !state->unidiff_zero));
		res = -128;
	if (!ent)
	if (patch->is_new < 0)


}
			/* consume the blank line */
	if (ex > len)
	return 0;
			  int current_lno,
		ok_if_exists = 1;
	if (*p != '.')
	state->linenr = 1;
		if (c == '/' && !--p_value)

			record_ws_error(state, WS_BLANK_AT_EOF, "+", 1,
	    starts_with(preimage + sizeof(heading) - 1, p->old_oid_prefix))
	prefix_patch(state, patch);
	for (files = adds = dels = 0 ; patch ; patch = patch->next) {
			/* fallthrough */
 * Compare lines s1 of length n1 and s2 of length n2, ignoring

{
	 *
static int parse_fragment(struct apply_state *state,
		if (stat_ret && errno != ENOENT)
		res = write_locked_index(state->repo->index, &state->lock_file, COMMIT_LOCK);
	 * and replace it with postimage
		if (load_current(state, &tmp_image, patch))


	int linenr;
static int gitdiff_index(struct gitdiff_data *state,
		}
			break;
	 * new_name through the end of names are renames
		for (next = cp; next < ep && *next != '\n'; next++)
	}
			   PARSE_OPT_NOCOMPLETE),
	}
 * If "patch" that we are looking at modifies or deletes what we have,
				     ? patch->new_name : patch->old_name);
	ce->ce_flags = create_ce_flags(0);
		if (errno != ENOENT)
	struct string_list_item *it;
			  const char *line,
		const char *name;
			     state->fake_ancestor);
	leading = 0;
			;
	prepare_image(&fixed_preimage, buf, len, 1);
	len -= date_len;
		if (preimage->line[i].flag & LINE_COMMON)
	patch->is_toplevel_relative = 1;
		 */
	offset = 0;
			 * This cannot be "return 0", because we may
static int gitdiff_oldmode(struct gitdiff_data *state,

	if (previous) {
		if (applied_pos >= 0)
	}
	if (patch->is_delete ||
 * Skip p_value leading components from "line"; as we do not accept
	struct strbuf qname = STRBUF_INIT;
		size_t oldlen = preimage->line[i].len;
	return get_oid_hex(p->old_oid_prefix, oid);
		BUG("caller miscounted postlen: asked %d, orig = %d, used = %d",
			add_line_info(&preimage, old, plen,
	free(err);
			/* Newer GNU diff, empty context line */

			N_("remove <num> leading slashes from traditional diff paths"),

		/*
			plen--;
		return error(_("invalid mode on line %d: %s"), linenr, line);

		if (!frag->rejected) {
	add = patch->lines_added;
	previous = previous_patch(state, patch, &status);
	tz = line + len - strlen(" +0500");
		enum object_type type;
	image->line = image->line_allocated;
		state->max_change = lines;
	/*
		if (len < 6)
	/*
			 * apply_patch->check_patch_list->check_patch->
	int stat_ret = 0, status;
		if ((patch->new_name == NULL) || (patch->is_rename)) {
}
		clear_image(img);
	git_apply_config();
	if (!n)
 *
	 * in place (postlen==0) or not.
	image->len = len;
		int err = check_to_create(state, new_name, ok_if_exists);
		return NULL;


	strbuf_release(&newlines);
	struct stat st;
		}
	 * are whitespace characters. (This can only happen if
	}
				flush_attributes = 1;
	}
 */
	 */
		end2--;
		case '\\':

	unsigned long leading, trailing;
		if (res < 0)


	return 0;


	const char *ptr, *eol;
 * Try to apply a patch.
		else
 * Parse a unified diff fragment header of the
}
	unsigned long offset;
	struct strbuf fixed;

		set_error_routine(state->saved_error_routine);
 * we create them and try again.
	}
			buffer++;
		if (state->apply_verbosity > verbosity_silent)
	 * we are removing blank lines at the end of the file.)
				}
			if (len < 12 || memcmp(line, "\\ ", 2))
			return squash_slash(xstrdup(def));
	int patch_method;
		unsigned int change;
	return 1;
		discard_cache_entry(ce);
			break;
			}
	add_name_limit(state, arg, 0);
		for (; frag; frag = frag->next) {

		return 0;
	 * Accept a name only if it shows up twice, exactly the same
				   char *buf,
			error(_("patch failed: %s:%ld"), name, frag->oldpos);

					       "match old mode (%o)"),
				     name);
	if (!strcmp(option, "error-all")) {
			goto corrupt;
	free(patch->new_name);
	} else {
		free(list);
			error(Q_("git diff header lacks filename information when removing "
{

	}
		if (patch->new_name && S_ISLNK(patch->new_mode))
			continue;
		}
		 * many lines from the beginning of the preimage must


	 * store information about incoming file deletion
	return 0;
	patch->old_name = find_name(state->root, line, NULL, state->p_value ? state->p_value - 1 : 0, 0);
	 */
			continue;
			goto free_and_fail1;
	struct stat nst;
		 * a line before the end of img.
int apply_parse_options(int argc, const char **argv,
	 * the beginning of the second name.
		}
			return error((side == DIFF_NEW_NAME) ?
	}
	patch->is_binary = 1;


	res = write_locked_index(&result, &lock, COMMIT_LOCK);
}

	for (i = 0; i < applied_pos; i++)
}
		return gitdiff_oldmode(state, ptr + 1, patch);
	struct apply_state *state = opt->value;
	if (state->squelch_whitespace_errors &&

					 strlen(old_name));
					found_new_blank_lines_at_end);

	} else if (S_ISGITLINK(mode)) {
		int ch = line[i];
	struct cache_entry *ce;
	/*
		int p, q;

			0, apply_option_parse_whitespace },
	for ( ; i < preimage->nr; i++)
	struct stat st;
		printf(" %s %s\n", newdelete, name);
		cp = next;
			return error(_("unable to read symlink %s"), path);
	strbuf_release(&sb);
static void prefix_patch(struct apply_state *state, struct patch *p)
	n = short_time_len(line, p - line);
		int res;
			{ "rename new ", gitdiff_renamedst },

				state->apply = 0;
	char *buf;
 */
		 * otherwise current+fragsize must be still within the preimage,
		char first;
	int status, pos;

	}
		/*
		return 0;


	 * of length-byte + base-85 encoded data, terminated with another
	} else if (!state->cached) {
			*listp = patch;
	    state->squelch_whitespace_errors < state->whitespace_error)
	if (!isdigit(end[-1]))
	}
static int read_patch_file(struct strbuf *sb, int fd)
				   state->whitespace_error),
	return (uintptr_t)ent->util;
	/* Whitespace damage. */
}

	second = strchr(name, '\n');
		}
	    isdigit(date[-1]) && isdigit(date[-2]))	/* 4-digit year */
		return 0;

static void summary_patch_list(struct patch *patch)
			if (checkout_target(state->repo->index, *ce, st))
	return 0;
	for (second = name; second < line + llen; second++) {

{
			       p->old_mode, p->new_mode, p->new_name);

	img->line_allocated[img->nr].hash = hash_line(bol, len);
	 */

	show_mode_change(p, 0);
static size_t sane_tz_len(const char *line, size_t len)
				return error(_("new mode (%o) of %s does not "
				   DIFF_OLD_NAME);
		 * very likely to apply to our directory.
		    int match_beginning, int match_end)
		newlines += fragment->newlines;
		if ('A' <= byte_length && byte_length <= 'Z')
		state->saved_error_routine = get_error_routine();
			 * no rename, as this is only to set def_name
			N_("instead of applying the patch, see if the patch is applicable")),
static void update_image(struct apply_state *state,
	unsigned inaccurate_eof = patch->inaccurate_eof;

	p = time = line + len - strlen(" 07:01:32");
	if (item != NULL)

		if ((state->apply || state->check) &&
			     CE_MATCH_IGNORE_VALID | CE_MATCH_IGNORE_SKIP_WORKTREE);
		len = linelen(line, size);


 * fragment separately, since the only way to know the difference
				added_blank_line = 1;
static int gitdiff_newname(struct gitdiff_data *state,
	for (i = 0; i < preimage_limit; i++) {
		}
static int check_patch_list(struct apply_state *state, struct patch *patch)
	return 0;
out:
	size_t fixed_len;
		if (!isspace(cp[i])) {
		/*
		target += tgtlen;
		if (is_not_gitdir)
		cp++;
	git_config_get_string_const("apply.whitespace", &apply_default_whitespace);
		epoch_hour = 24;
 * This represents one "hunk" from a patch, starting with
				res = -128;
		}
	}
	if (!strcmp(option, "change")) {
	image->len = result.size;
		preoff += preimage->line[i].len;
	    !isdigit(*p++) || !isdigit(*p++))
		if (added_blank_line) {
			error(_("patch with only garbage at line %d"), state->linenr);
	/* do nothing */
 */
	fragment->trailing = trailing;
			return -1;
				error(_("invalid start of line: '%c'"), first);
	frag->free_patch = 1;
				else
			PARSE_OPT_NOARG, apply_option_parse_space_change },
	unsigned long oldpos, oldlines;
		    memcmp(old_name, new_name, slash_new - new_name))

	return line + len - date;
			patch_stats(state, patch);
	}

	 */
		int match;
}

		patch->crlf_in_old = 1;
		if (starts_with(name, state->prefix))
	string_list_init(&state->symlink_changes, 0);
	return 0;
	img->len += insert_count - remove_count;
			st_mode = (*ce)->ce_mode;
	if (flush_attributes)
					remove_last_line(&postimage);
	else
	if (patch->is_new)
	 * If match_beginning or match_end is specified, there is no
			if (state->apply_in_reverse)

	 * When a binary patch is reversible, there is another binary
				i++;
			return error(_("sha1 information is lacking or useless "
	 * Please update $__git_whitespacelist in git-completion.bash
			mksnpath(newpath, sizeof(newpath), "%s~%u", path, nr);
		return 0;
		return -128;
	if (parse_whitespace_option(state, arg))
	git_inflate_init(&stream);
	return offset + ex;
		 * This hunk extends beyond the end of img, and we are
		size -= llen;

		if (*second == '"') {
static int apply_data(struct apply_state *state, struct patch *patch,
			return error(_("the patch applies to '%s' (%s), "
	return find_name_common(root, line, def, p_value, NULL, terminate);
		 * Git patch? It might not have a real patch, just a rename

		return -128;
	if (state->apply_verbosity <= verbosity_silent) {
 * Returns:
			break;
	if (!force_apply && (state->diffstat || state->numstat || state->summary || state->check || state->fake_ancestor))
			return error(_("git apply: bad git-diff - expected /dev/null, got %s on line %d"),
	}
}
static int gitdiff_renamesrc(struct gitdiff_data *state,
	memset(state, 0, sizeof(*state));
		return NULL;
	if (create_one_file(state, path, mode, buf, size))

			 * Does len bytes starting at "name" and "second"
	 * that says the patch method (currently, either "literal" or
	if (status) {
	free(patch->new_name);

	int nslash;
			 N_( "attempt three-way merge if a patch does not apply")),
	patch->fragments = forward;
	    !isdigit(*p++) || !isdigit(*p++) || *p++ != '-' ||
		}
	 * or removing or adding empty files), so we get


static int check_header_line(int linenr, struct patch *patch)
			  const char *line,
 */
				   "squelched %d whitespace errors",
			struct apply_state *state,
		preimage_limit = img->nr - applied_pos;
	 * see to it that it is NUL-filled.


	*status_p = 0;
	for (cp = nameline; *cp != '\n'; cp++) {
			       "without full index line"), name);
	offset = parse_range(line, len, 4, " +", &fragment->oldpos, &fragment->oldlines);
	 */
					     fixed.len - fixstart));
			N_("leave the rejected hunks in corresponding *.rej files")),
	 * No exact match. If we are ignoring whitespace, run a line-by-line
	if (patch->is_new < 0 &&
 * to make sure..
			return -1;
	unsigned hash : 24;
			  unsigned long size,
		enum object_type type;
				    unsigned long current,
		goto end;

		fprintf(stderr, "%s:%d: %s.\n%.*s\n",
static struct patch *previous_patch(struct apply_state *state,
}
			     ends_with_path_components(patch->new_name,
		if (!(postimage->line[i].flag & LINE_COMMON)) {
		    !slash_new ||
	 */
		    memcmp(first.buf, cp, first.len))
				s2++;
		return -1;
	 * wander around and wait for a match at the specified end.
		printf(" %-*s |  Bin\n", max, qname.buf);
	/*

		return 0;
	if (match_beginning && current_lno)
		return repo_read_index(state->repo);
			return error(_("the necessary postimage %s for "
	patch->is_delete = 0;
		const char *n = patch->new_name;
			discard_cache_entry(ce);
		context += fragment->leading + fragment->trailing;
 * applying a non-git patch that incrementally updates the tree,
}
		return 0;
		if (!cp) {
	 * without leading context must match at the beginning.
				check_old_for_crlf(patch, line, len);
	struct object_id pre_oid, post_oid, our_oid;
		unsigned long size;
		*fragp = fragment;

	return error(_("unrecognized whitespace option '%s'"), option);
			   unsigned int mode, const char *buf,
	state->ws_error_action = warn_on_ws_error;
/*
	struct strbuf sb = STRBUF_INIT;
	}
	if (c == '\t' && !(terminate & TERM_TAB))
		if (llen == sizeof(git_binary) - 1 &&
	return offset;
			break;
	add_to_fn_table(state, patch);
{
			      unsigned long size,
		list = next;
	for (i = 0; i < argc; i++) {

			}
static const char pluses[] =
{
		numstat_patch_list(state, list);
			reduced++;
		clear_image(&tmp_image);
	if (new_name && old_name) {
		frag = frag->next;
static int name_terminate(int c, int terminate)
			patch->is_new = 1;
		len = linelen(line, size);
{


		{ OPTION_CALLBACK, 0, "ignore-space-change", state, NULL,
			add_line_info(&postimage, newlines.buf + start, newlines.len - start,
		patch->ws_rule |= WS_CR_AT_EOL;
{
			static const char *binhdr[] = {
				check_whitespace(state, line, len, patch->ws_rule);
 * GNU diff puts epoch there to signal a creation/deletion event.  Is

			int *force_apply, int *options,
	for ( ; i < preimage->nr; i++) {

				goto free_and_fail1;
	const char *end2 = s2 + n2;

}
	}

	strbuf_release(&fixed);
}
				goto free_and_fail1;
			goto is_new;
			return error(_("corrupt patch for submodule %s"), path);
	if (res)
			old_buf += l_len;
		adds += patch->lines_added;
			return -1;
	update_pre_post_images(preimage, postimage,

		/*
}
	int err = 0;
	unsigned long len = 0;
			h = h * 3 + (cp[i] & 0xff);
	}

			postlen += tgtfix.len;
	git_config_get_string_const("apply.ignorewhitespace", &apply_default_ignorewhitespace);
}
	COPY_ARRAY(img->line + applied_pos, postimage->line, postimage->nr);
static int checkout_target(struct index_state *istate,
					   patch->old_name, patch->old_mode);
	ent = string_list_lookup(&state->symlink_changes, path);
		convert_to_git(NULL, path, buf->buf, buf->len, buf, conv_flags);
		printf(" %s %s => %s (%d%%)\n", renamecopy,
	if (res > -1)
		recount_diff(line + offset, size - offset, fragment);

	buffer += llen;


	/*
	struct cache_entry *ce;

	offset = parse_range(line, len, offset, " @@", &fragment->newpos, &fragment->newlines);

				/* ... followed by '\No newline'; nothing */
			free(another);
	img->line++;
		 * on anything other than pre/post image.
	 * to the number of lines in the preimage that falls
	else if (state->prefix) {
	}
			const struct opentry *p = optable + i;
		if (match_end && (preimage->nr + current_lno != img->nr))
	return val;
	set_default_whitespace_mode(state);
			if (unquote_c_style(&sp, second, NULL))
		return create_file(state, patch);
		if (!len)


				(int)linelen(line, size), line);
	if (strbuf_read(sb, fd, 0) < 0)
	memset(image, 0, sizeof(*image));

			repo_hold_locked_index(state->repo, &state->lock_file,

			N_("detect new or modified lines that have whitespace errors"),
			if (!preimage_oid_in_gitlink_patch(patch, &oid))

					return -1;

	return 0;
			     patch->old_name);
			ret = -1;
		if (err && state->threeway) {
		 * Checking for 12 is just for sanity check -- any
			goto end;
			return error(_("cannot read the current contents of '%s'"),
	if (state->diffstat && state->apply_verbosity > verbosity_silent)
		OPT_BOOL('N', "intent-to-add", &state->ita_only,
		ctx++;
	state->apply = 1;
	int lines = patch->lines_added + patch->lines_deleted;
	free(patch->old_name);
		if (!state->cached) {
	*status_p = -1;
				if (p->score) {
	res = try_create_file(state, path, mode, buf, size);
	 * A type-change diff is always split into a patch to delete
	if (state->cached)
		if (!name->len)
	char *cp = patch->new_name ? patch->new_name : patch->old_name;
{
	}
		/* XXX read_sha1_file NUL-terminates */
		}
{
		}
		}
		set_error_routine(mute_routine);
		if (!is_dev_null(line))

		for (i = 0; i < ARRAY_SIZE(optable); i++) {

	postimage.line = postimage.line_allocated;
			state->max_len = len;
		end--;
 * Returns:
		}
{
	}

	 * false).

	return gitdiff_newmode(state, line, patch);
		line += len;
 * "@@ -oldpos,oldlines +newpos,newlines @@" marker.  The


	while (size--) {


static int read_apply_cache(struct apply_state *state)
		/* strip the a/b prefix including trailing slash */
 */
		old_name = patch->old_name;
	 */

		}
		 */
	int i = 0, j = 0;
	/* Parse the thing.. */
		st_mode = ce_mode_from_stat(*ce, st->st_mode);
		patch->score = val;
		 * We only accept unified patches, so we want it to

		return error_errno("git apply: failed to read");
			break;
		if (state->apply_in_reverse) {
	return 0;
		}
	 * diff.c::run_diff()); in such a case it is Ok that the entry
{


		if (img->len)
}
 *
	/*

		CONV_EOL_KEEP_CRLF : CONV_EOL_RENORMALIZE;
	postimage.buf = newlines.buf;
				  fragment->size, &len);
	 */
	if (state->apply_verbosity <= verbosity_silent) {
		case '+':

	    get_oid_hex(patch->old_oid_prefix, &oid) ||
			}
		/*
	if (0 < patch->is_new && oldlines)
	free(name);
	 * A hunk without trailing lines must match at the end.
				   DIFF_NEW_NAME);
	if (state->numstat && state->apply_verbosity > verbosity_silent)
	if (status) {
				   squelched),
	if (postlen < postimage->len)
	return 0;
		strbuf_grow(buf, 100);
	new_name = p->new_name;
	 * was_deleted().
	static const char heading[] = "-Subproject commit ";
 * replace the part of "img" with "postimage" text.
}
			return 0;

		free(forward);
	if (hexsz < len)
	clear_image(&tmp_image);
		};
 * "buf" has the file contents to be patched (read from various sources).
			warning(Q_("squelched %d whitespace error",
		SWAP(p->new_mode, p->old_mode);
		if (is_not_gitdir)
	 * errors, so let's try matching after whitespace correction.
	struct fragment *fragment = patch->fragments;
#define EXISTS_IN_WORKTREE 2
	memcpy(patch->new_oid_prefix, line, len);
			  void *buf,
 * line.  We do not find and return anything if it is a rename
		if (match_beginning || match_end) {
	while (list) {
	return !state->has_include;
				return error(_("new mode (%o) of %s does not "
		if (phase == 1)
	unsigned long leading, trailing;
	assert(*name_ != '\0');
}
		state->ws_ignore_action = ignore_ws_none;
	first += 4;	/* skip "--- " */
	if (!isdigit(*p++) || !isdigit(*p++) || *p++ != '-' ||
 *   0 if the patch applied cleanly
		 * without metadata change.  A binary patch appears

		char *result;
 */
			goto end;
				     name);
	 * (west of GMT) or 1970-01-01 (east of GMT)

	int used, used_1;
		goto corrupt;
	return 0;
		ent->util = (void *)0;
	git_config(git_xmerge_config, NULL);
		state->ws_error_action = warn_on_ws_error;
			remove_first_line(&preimage);

		return 0;
	while (cp < ep) {
			free_patch(patch);
	len = strchrnul(line, '\n') - line;
		len -= digits+1;
	while (size > 0) {
	}
{
		line = 0;

	for (i = 0, h = 0; i < len; i++) {
	const char *patch;
		status = load_patch_target(state, &buf, ce, st, patch,
	 */
	return 0;
 *   -1 in case of error,
	return frag;
 */
		struct strbuf sp = STRBUF_INIT;
		}
	if (!len || line[len-1] != '\n')
					if (write_out_one_reject(state, l))
			}
		oldlines += fragment->oldlines;

			   unsigned mode,
	int errs = 0;
	BUG_ON_OPT_NEG(unset);
	if (patch->is_delete < 0 &&
	 * However, we simply cannot tell if a hunk must match end

			     "file %s becomes empty but is not deleted"),
static int to_be_deleted(struct patch *patch)
				struct patch *patch,
		return 0;
			return NULL;
			N_("build a temporary index based on embedded index information")),

			break;
			    !state->whitespace_error ||
}
		errs |= res;
 * of the current tree for a creation patch in this function; the caller
	for (offset = len ; size > 0 ; offset += len, size -= len, line += len, (*linenr)++) {
		}
			pos--;
	    !isdigit(*p++) || !isdigit(*p++))	/* Not a date. */
	remove_count = 0;

			return current_lno;

	struct patch *p;
		if (size < 1)
		strbuf_insert(&name, 0, root->buf, root->len);
	if (apply_fragments(state, &tmp_image, patch) < 0) {
static char *find_name_gnu(struct strbuf *root,

	int oldlines = 0, newlines = 0, ret = 0;
	 */
	max = max + state->max_change > 70 ? 70 - max : state->max_change;
	int offset;
	struct fragment *frag;
		}
			else
}
 * "image" now owns the "buf".
		return error(_("new file depends on old contents"));
						  line_len - (len + 1));
{
}
		SWAP(p->is_new, p->is_delete);
		   (ws_rule & WS_BLANK_AT_EOF)) {
	if (!patchsize) {
		 * The hunk falls within the boundaries of img.
		}
		/* Otherwise, the old one must be empty. */

	if (reverse)
{
			struct image *image,
		else if ('a' <= byte_length && byte_length <= 'z')
			continue;
			byte_length = byte_length - 'A' + 1;
			if (0 < patch->is_new)

		if (llen == 1) {
}
	patch->rejected = 0;
	discard_index(&result);
		if (!isspace(*buf))
		}
		if (p->is_new)

		return 0;
	}
		    (!patch->is_binary && !metadata_changes(patch))) {
	 * point starting from a wrong line that will never match and
	int status;
			   const char *line,
	if (res)
		/* Testing this early allows us to take a few shortcuts.. */

				leading++;
			{ "new mode ", gitdiff_newmode },
 * which is true 99% of the time anyway. If they don't,
			goto end;
		return 0;
		case '@': case '\\':
				   current, current_lno, ws_rule,
static int add_conflicted_stages_file(struct apply_state *state,
	}
	if (mode)
	if (state->ws_error_action != correct_ws_error)
	date_len = diff_timestamp_len(line, len);

/*
	if (len < strlen(" +08:00") || line[len - strlen(":00")] != ':')
			return 0;
static const char minuses[]=

		int i;
				return strbuf_detach(&sp, NULL);
	if (apply_default_ignorewhitespace && parse_ignorewhitespace_option(state, apply_default_ignorewhitespace))
}

	for (i = 0; i < fixed_preimage.nr; i++)
			  struct image *postimage,
	BUG_ON_OPT_NEG(unset);
		 */

			return error(_("reading from '%s' beyond a symbolic link"), name);
}
		quote_c_style(patch->old_name, &sb, NULL, 0);
	 * to B and then rename B to A.  While applying the first one,
			 struct image *preimage,

		state->ws_error_action = nowarn_ws_error;

{
	orig = preimage->buf;
	if (c == ' ' && !(terminate & TERM_SPACE))
	if (unquote_c_style(&name, line, NULL)) {
		if (!frag->rejected)
	int res;
			     patch->new_name);
				return error_errno(_("unable to stat newly "
 * points at an allocated memory that the caller must free, so
		    unsigned ws_rule,

 * Read a binary hunk and return a new fragment; fragment->patch
					return 0;
				found_new_blank_lines_at_end = hunk_linenr;


	unsigned long size = patch->resultsize;
			return error(_("%s: already exists in working directory"),
			second++;
	const char *end = line + len;

		write_object_file("", 0, blob_type, &pre_oid);
static int apply_binary_fragment(struct apply_state *state,
	if ((st != Z_STREAM_END) || stream.total_out != inflated_size) {

				return error(_("mode change for %s, which is not "
	}
		    !memcmp(git_binary, buffer + hd, llen)) {
 *
 *  -1 if an unrecoverable error happened
				NULL,
		oidcpy(&ce->oid, &patch->threeway_stage[stage - 1]);
{
				; /* ok, the textual part looks sane */
	int zoneoffset, epoch_hour, hour, minute;
		 */
{
	struct strbuf sb = STRBUF_INIT;
	struct strbuf buf = STRBUF_INIT;
			res = -128;
}
			      int terminate)
{
	digits = parse_num(line, p1);
	ent->util = (void *)(what | ((uintptr_t)ent->util));
static int create_one_file(struct apply_state *state,
			N_("prepend <root> to all filenames"),
		return (llen && line[0] == '/') ? NULL : line;
	string_list_init(&state->limit_by_name, 0);

		add = (add * max + state->max_change / 2) / state->max_change;
		postlen = 0;
		char *ret = xstrfmt("%s%.*s", root->buf, len, start);
	ce = make_empty_cache_entry(state->repo->index, namelen);
		stat_ret = lstat(old_name, st);

{
		if (state->apply_verbosity > verbosity_silent)
		       unsigned long size,
			/*
static void prepare_image(struct image *image, char *buf, size_t len,
			"(line %d)"), *linenr);
	return 0;
			trailing = 0;

			}
					show_mode_change(p, 0);
}
	 * should follow, terminated by a newline.
		    state->ws_error_action != nowarn_ws_error) {
	 * not used.  Otherwise, we saw bunch of exclude rules (or none)
		if (!wildmatch(it->string, pathname, 0))
	/*
	 * This should cover the cases for normal diffs,
	rej = fopen(namebuf, "w");
		}
				return read_file_or_gitlink(ce, buf);

		const char *arg = argv[i];
		return strbuf_detach(&first, NULL);

		for (i = 0; i < preimage_limit; i++)

{
	 * apply_one_fragment() has whitespace errors fixed on added
	return 0;
	img = strbuf_detach(&buf, &len);
	if (end[-1] == '\t') {	/* Success! */
			 struct patch *patch, struct stat *st,
		unsigned long llen = linelen(buffer + hd, size - hd);
	uint32_t h;
		old_name = slash_old + 1;
			continue;
			/* They must match, otherwise ignore */
		return -1;
			  struct patch *patch)
		preimage.line_allocated[preimage.nr - 1].len--;
	strbuf_init(&state->root, 0);
			return 0;
}
	if (!len || line[len - 1] != ' ')
		"([-+][0-2][0-9]:?[0-5][0-9])\n";
 */
	} else if (stat_ret < 0) {
			if (first != '+' ||
	del = patch->lines_deleted;

	}
		state->check_index = 1;
 * the path the patch creates does not exist in the current tree.
		if (!another || strcmp(another, *name)) {
				break;
	 * There's probably some smart way to do this, but I'll leave
		warning("recount: ignore empty hunk");
	}
		/*
struct image {
	if (0 < patch->is_new && oldlines)
	else
		}
		 */
	item = string_list_lookup(&state->fn_table, name);
			   img->line + applied_pos + preimage_limit,
		else if (state->whitespace_error)
	return len;
		first = *patch;
		if (has_symlink_leading_path(new_name, strlen(new_name)))
		state->linenr++;
			{ "deleted file mode ", gitdiff_delete },

			}
		return !!symlink(buf, path);
	*buf_p = buffer;
	}
 */
		if (frag->patch[frag->size-1] != '\n')
			/* Ignore it, we already handled it */
		line++;
	 */
	res = write_in_full(fd, buf, size) < 0;
			goto end;
			is_blank_context = 1;
		free((void*) forward->patch);
		say_patch_name(stderr, sb.buf, patch);
 */
		return error(_("%s: patch does not apply"), name);
				strbuf_remove(&sp, 0, np - sp.buf);
static void stat_patch_list(struct apply_state *state, struct patch *patch)
		}
	patch->old_name = xstrdup_or_null(patch->def_name);
	 * The preimage may extend beyond the end of the file,
		 */
}
		if ((patch->old_name && S_ISLNK(patch->old_mode)) &&
 *  -128 in case of error
		OPT_BOOL(0, "index", &state->check_index,
			    _("git apply: bad git-diff - inconsistent old filename on line %d"), state->linenr);


				ws_fix_copy(&newlines, patch + 1, plen, ws_rule, &state->applied_after_fixing_ws);
		SWAP(p->old_oid_prefix, p->new_oid_prefix);
		{ OPTION_CALLBACK, 0, "directory", state, N_("root"),
		int byte_length, max_byte_length, newsize;

		fprintf_ln(stderr,
		case '+':
	return err;


		if (!len)
		remove_count += img->line[applied_pos + i].len;
static int read_old_data(struct stat *st, struct patch *patch,
		patch->is_new = 1;
	int skipped_patch = 0;
		patch->is_copy > 0 ||
	 */
			N_("mark new files with `git add --intent-to-add`")),
		return -128;
	 * result when match_end and preimage is larger than the target.
	tz = line + len - strlen(" +08:00");
				i++;
 * This is normal for a diff that doesn't change anything: we'll fall through
	name[j] = '\0';
			errs |= res;
			oldlines--;
static void prepare_symlink_changes(struct apply_state *state, struct patch *patch)
	if (!lstat(new_name, &nst)) {
	}

		data = xrealloc(data, newsize);
	 * postimage needs to be.  The postimage prepared by
/*
	} else {
	state->squelch_whitespace_errors = 5;
		if (len > state->max_len)
	fd = open(path, O_CREAT | O_EXCL | O_WRONLY, (mode & 0100) ? 0777 : 0666);
 * apply.c
	/* Fix the length of the whole thing */
		     trailing != frag->trailing) && state->apply_verbosity > verbosity_silent)
			res = -128;
	 * from the lack of trailing lines if the patch was generated

}
		return error(_("deleted file %s still has contents"), patch->old_name);
		if ((patch->old_mode ^ patch->new_mode) & S_IFMT) {


	    /* does the abbreviated name on the index line agree with it? */
	if (phase == 0)
{
{
#define TERM_SPACE	1
		struct string_list_item *item;
	 * something else tacked on to the end (ie "file.orig"
	frag->binary_patch_method = patch_method;
		size_t fixstart = fixed.len;

	size_t len;
				      const char *arg, int unset)
		 */
	 * to 1-26 bytes, and 'a'-'z' corresponds to 27-52 bytes.
		result = read_object_file(oid, &type, &sz);

		       const char *line,
		free(out);
		char *to_free = NULL;
 * except for an incomplete line at the end if the file ends with
		 * have filler at the end but the filler should never


				 "%d lines add whitespace errors.",
					state->linenr++;
	if (pos < 0)
}
			break;
	postimage.len = newlines.len;
	int status;

			break; /* happy */
				 struct patch *patch)
		patch = xcalloc(1, sizeof(*patch));

	 * sequence of 'length-byte' followed by base-85 encoded data
	return 0;
			    state->ws_error_action != nowarn_ws_error)
	p = line + len;
			goto end;
{
				show_rename_copy(p);
		}
	if (!option) {
 */
	struct checkout costate = CHECKOUT_INIT;
	while (name[i]) {
static void say_patch_name(FILE *output, const char *fmt, struct patch *patch)
		if (write_res < 0) {
		item = string_list_insert(&state->fn_table, patch->new_name);
	/* Say this even without --verbose */
 *
		struct fragment *frag = p->fragments;
		case '\n': /* newer GNU diff, an empty context line */
			return NULL;
	if (end[-1] != ' ')	/* No space before date. */
		return error(_("cannot checkout %s"), ce->name);
	switch (fragment->binary_patch_method) {
			goto corrupt;
}

	state->patch_input_file = filename;
					if (l->conflicted_threeway) {
	 * before seeing it.
			       char **name,
 *   -1 on error

		if (!patch->new_mode) {
	} else {
 * but the preimage prepared by the caller in "img" is freed here
		strbuf_addstr(&sb, " => ");
{
#include "cache.h"
	for (p = patch; p; p = p->next) {

	line += strlen("diff --git ");
				return NULL; /* no postimage name */
				return -1;
	 * deletion.  However, the reverse is not true; --unified=0
	for (p = tz + 2; p != line + len; p++)
			newlines++;

	if (!patch->new_mode && !patch->is_delete)
"----------------------------------------------------------------------";
			return error(_("git apply: bad git-diff - expected /dev/null on line %d"), state->linenr);
	const char *p;
	}
}
	remove_file_from_index(state->repo->index, patch->new_name);
			skipped_patch++;
		if (0 < patch->is_new)
	 * the presence of B should not stop A from getting renamed to
		}
		return 0;
{
static int three_way_merge(struct apply_state *state,

			      const char *end,
			char *buffer,
			   const struct object_id *ours,
			register_symlink_changes(state, patch->new_name, APPLY_SYMLINK_IN_RESULT);
{
		for (;;) {
}
	/*

	stream.next_out = out = xmalloc(inflated_size);
			}
				break;
		case '+':
/*
			forwards_lno++;
	if (offset < 0)

			free(fragment);
	if (is_dev_null(nameline))
		struct strbuf tgtfix;
	}
	return patch == PATH_WAS_DELETED;
	/*
			 */


			/*
	if (starts_with(buffer, "delta ")) {
	if (!fragment)
	}

			int i;
		 */

}
	status = three_way_merge(state, image, patch->new_name,
static int gitdiff_copydst(struct gitdiff_data *state,
			if (get_current_oid(state, patch->old_name, &oid))
	 * YYYY-MM-DD hh:mm:ss must be from either 1969-12-31
}
}
				       "without the reverse hunk to '%s'"),
		} else {
		size_t imglen = img->line[current_lno+i].len;
{
	}
		/* a common context -- skip it in the original postimage */
	const char *name = patch->old_name ? patch->old_name : patch->new_name;
	 * Posix: 2010-07-05 19:41:17

			     struct stat *st,
static int line_by_line_fuzzy_match(struct image *img,
	unsigned long oldlines, newlines;
		struct patch *patch;
						 patch->old_name);
 * Read the patch text in "buffer" that extends for "size" bytes; stop
	old_buf = postimage->buf;
	line_len = second - name;

	}
	if (val <= 100)
}
	}
/*
		if (!fragment->next)
	 * We are only interested in epoch timestamp; any non-zero
				       "current contents."),
			discard_cache_entry(ce);
	 * headers.  While at it, maybe please "kompare" that wants
			return line + len - (p + 1);
	 * old, immediately followed by a patch to create new (see
{
		patch_method = BINARY_LITERAL_DEFLATED;
			return strbuf_detach(&first, NULL);
		return 0;
	/* p->old_name through old_name is the common prefix, and old_name and
		if (!isdigit(*p))



	size_t len;
	}
		}

	struct gitdiff_data parse_hdr_state;
			   int exclude)
	if (!old_name)
	/* Permit 1-digit hours? */
	image->buf = buf;
	char *preimage;
	const char *end1 = s1 + n1;
static int apply_option_parse_p(const struct option *opt,
		state->ws_error_action = die_on_ws_error;
			register_symlink_changes(state, patch->old_name, APPLY_SYMLINK_GOES_AWAY);
static int check_to_create(struct apply_state *state,
	fclose(rej);
static int write_out_results(struct apply_state *state, struct patch *list)
	 * If that is the case, we must be careful only to
	patch->is_copy = 1;
		return error(_("unable to find filename in patch at line %d"), state->linenr);
static void set_default_whitespace_mode(struct apply_state *state)
			struct patch *patch,
	res = !!errs;
		date -= strlen("19");
	}
	 * the boundaries of img. Initialize preimage_limit
		 */
	while (offset < buf.len) {
		 * leading and trailing if they are equal otherwise
	} else {
		new_name = slash_new + 1;
			     patch->new_name :
			deleted++;
			return (it->util != NULL);

		patch->recount =  !!(options & APPLY_OPT_RECOUNT);
		postimage->line[i].len = l_len;
 */

		stamp = xmalloc(sizeof(*stamp));
			const char *np;

		 * used to be.
		img->buf = xmemdupz(fragment->patch, img->len);
	struct lock_file lock = LOCK_INIT;
	 * remove the part of the preimage that falls within

		size_t tgtlen = img->line[current_lno + i].len;

	 * the trailing TAB and some garbage at the end of line ;-).
 * will remove it in a later patch.
			if (forwards_lno == img->nr) {
			unsigned long inflated_size)
	 * this is a git patch by saying --git or giving extended
		return 0;

				unlink_or_warn(newpath);
	if (!ptr || ptr[1] != '.' || hexsz < ptr - line)
	int nth = 0;
	/* we may have full object name on the index line */
				s1++;
	    (was_deleted(tpatch) || to_be_deleted(tpatch)))
	    get_oid_hex(patch->new_oid_prefix, &oid))
		for ( ; buf < buf_end; buf++)
#define EXISTS_IN_INDEX 1
	size_t alloc;
	stream.next_in = (unsigned char *)data;
				status, timestamp);
static void check_whitespace(struct apply_state *state,
			   img->nr - (applied_pos + preimage_limit));
	 * Update the preimage with whitespace fixes.  Note that we
		}
		max = 50;
		 */
static size_t fractional_time_len(const char *line, size_t len)
	if (patch->is_delete)

		if (strbuf_read_file(buf, path, st->st_size) != st->st_size)
}
	} else if (is_dev_null(second)) {
		quote_c_style(n, &sb, NULL, 0);
			if (len < second - name &&
		return 0;
	}
{

			if (backwards_lno == 0) {
		preimage_limit = preimage->nr;
	 * store a failure on rename/deletion cases because

				is_blank_context = 1;
	return offset + hdrsize + patchsize;
		clear_image(img);
	int i;
	 * "scale" the filename

	strbuf_init(&fixed, imgoff + extra_chars);
				patchsize = used + llen;
	frag->patch = inflate_it(data, hunk_size, origlen);
				state->whitespace_error);
	 * fixed.
/*
	 * have to worry about a patch marked with "is_delete" bit
	while (frag) {
			if (!np)
				return 1;
		}

	 */
	return skip_prefix(str, "/dev/null", &str) && isspace(*str);
 * Get the name etc info from the ---/+++ lines of a traditional patch header
			res = -1;
	int ok_if_exists;

		return status;
		return add_index_file(state, path, mode, buf, size);
	if (errno == EEXIST || errno == EACCES) {
	 * is called at the beginning of apply_data() so we do not
			patch->direct_to_threeway = 1;
	while (p != line) {
		dels += patch->lines_deleted;
		     struct repository *repo,
	offset = parse_fragment_header(line, len, fragment);
			     struct patch *patch)
	for (i = 0; i < llen; i++) {
	 * but we need to be careful.  -U0 that inserts before the second
static int apply_patch(struct apply_state *state,
{
	if (state->update_index) {
		return -1;
		else {
		llen = linelen(buffer, size);
			new_buf += l_len;
	for (i = 0; i < preimage_limit; i++)
				     patch->new_oid_prefix, name);
				}
	}

		img->buf = dst;
	}
			continue;
			N_("ignore changes in whitespace when finding context"),
		const char *slash_old, *slash_new;
	const unsigned hexsz = the_hash_algo->hexsz;
			   struct patch *patch)
		       const char *filename,
	if (*p++ != ' ' ||
		if (decode_85(data + hunk_size, buffer + 1, byte_length))
 * Returns:
			if (parse_fragment_header(line, len, &dummy) < 0)
	 * since the first name is unquoted, a dq if exists must be
static int apply_option_parse_directory(const struct option *opt,

static int read_file_or_gitlink(const struct cache_entry *ce, struct strbuf *buf)

	 * While checking the preimage against the target, whitespace
	char *fixed_buf;
}
#include "rerere.h"
			cp = skip_tree_prefix(p_value, sp.buf, sp.len);
	return find_name_common(root, line, def, p_value, line + len, 0);
			fputc('\n', rej);
		return res;
}
		    state->squelch_whitespace_errors < state->whitespace_error) {
	string_list_clear(&state->limit_by_name, 0);
			if (!new_blank_lines_at_end)
		error(_("git diff header lacks filename information "
			 * (that are separated by one HT or SP we just

}
				"Binary files ",
	ce->ce_mode = create_ce_mode(mode);
				   " fixing whitespace errors.",
{
		fd = open(arg, O_RDONLY);
	return -1;
		used += llen;
	};
	return s1 == end1 && s2 == end2;
	current = 0;
	 * tree and in the index.
	return parse_mode_line(line, state->linenr, &patch->new_mode);
				       "for newly created file %s"), path);
		ws_fix_copy(&fixed, orig, oldlen, ws_rule, NULL);
	if (S_ISGITLINK(ce->ce_mode)) {
		if (nr < 0) {
				fprintf_ln(stderr, _("Hunk #%d applied cleanly."), cnt);
			return error(_("--3way outside a repository"));
}

	 * Count the number of characters in the preimage that fall
	if (!state->unsafe_paths && check_unsafe_path(patch))
	fprintf(rej, "diff a/%s b/%s\t(rejected hunks)\n",

/* Build an index that contains just the files needed for a 3way merge */
	 * Generally we prefer the shorter name, especially
 * one), and its contents hashes to 'hash'.
		}
{
				return -128;
	 * apart with --unified=0 insanity.  At least if the patch has
		 * The hunk extends beyond the end of the img and

		OPT_NOOP_NOARG(0, "binary"),
static int apply_option_parse_include(const struct option *opt,
			continue;
 * We have seen "diff --git a/... b/..." header (or a traditional patch

	if (!rej)
			 * in an unambiguous form.
	match_end = !state->unidiff_zero && !trailing;
	memcpy(result + applied_at, postimage->buf, postimage->len);
	} else {
}
			fill_stat_cache_info(state->repo->index, ce, &st);
			  NULL);
		char *name = find_name_gnu(root, line, p_value);
		name = patch->new_name ? patch->new_name : patch->old_name;
			goto free_and_fail1;
				errs = 1;
				state->whitespace_error - state->squelch_whitespace_errors;
	unsigned long val = strtoul(line, NULL, 10);
			memmove(new_buf, old_buf, l_len);
	 * the default name from the header.
	n = sane_tz_len(line, end - line);
}
	if (!result)
		if (buf == buf_end)
	}
	else
				 state->whitespace_error),
		else {
			     ends_with_path_components(patch->old_name,
	 * file creations and copies
static int gitdiff_delete(struct gitdiff_data *state,
			discard_cache_entry(ce);

		if (has_epoch_timestamp(first)) {
#include "parse-options.h"
 *   -1 in case of error,
		return error_errno("%s", new_name);
static uint32_t hash_line(const char *cp, size_t len)
	unsigned long len;

		old_buf += l_len;
{
 * of it after applying it), but it could be PATH_WAS_DELETED for a

		if (state->apply_in_reverse)
	       img->buf + (applied_at + remove_count),

	if (len < strlen(" +0500") || line[len-strlen(" +0500")] != ' ')
	return status;
 */
	int status;
			      struct image *img, struct fragment *frag,
		struct object_id oid;

	return line + len - tz;
				goto free_and_fail2;


	 */
	llen -= strlen("diff --git ");
	if (!cnt) {
	free_patch_list(list);
 * The change from "preimage" and "postimage" has been found to
static void numstat_patch_list(struct apply_state *state,
			break;
		if (change & APPLY_SYMLINK_GOES_AWAY)
struct line {
		return 0;
	if (state->threeway) {

	char *name = patch->new_name;
		return 0;
static void add_name_limit(struct apply_state *state,
	if (0 < patch->is_delete && newlines)
			N_("do not trust the line counts in the hunk headers"),
		printf(" %s mode %06o %s\n", newdelete, mode, name);
			add_line_info(&postimage, "\n", 1, LINE_COMMON);
	stream.avail_out = inflated_size;
			return 0;

	/* Expected format: 19:41:17.620000023 */
			   char *path,
 * The binary patch data itself in patch->fragment is still kept
		    (int)postlen, (int) postimage->len, (int)(new_buf - postimage->buf));
		/* We already have the postimage */
}
			     struct patch *patch,
	forwards_lno = line;
		old--;
	len -= digits;
				return -1;
		ce->ce_flags |= CE_INTENT_TO_ADD;
		/* We may be trying to create a file where a directory
	    : postimage->len < new_buf - postimage->buf)
	state->whitespace_option = arg;
		}
			forwards += img->line[forwards_lno].len;
		case 0:
	p = date = line + len - strlen("72-02-05");
 * apply at applied_pos (counts in line numbers) in "img".
	 *
					}
	/*
			ctx++;

		item->util = patch;
	status = regexec(stamp, timestamp, ARRAY_SIZE(m), m, 0);
static int check_preimage(struct apply_state *state,
		digits = parse_num(line+1, p2);
	struct apply_state *state = opt->value;

		patch = patch->next;
	case S_IFREG:
		mode = S_IFREG | 0644;
				      "Hunk #%d succeeded at %d (offset %d lines).",


			continue;

						       GITATTRIBUTES_FILE)) ||
		if (status != REG_NOMATCH)
	}
	 * are not losing preimage->buf -- apply_one_fragment() will

				   nth_fragment, applied_pos + 1, offset);
		 * fixed addition of trailing blank lines.
					       "in current HEAD"), name);
		if (regcomp(stamp, stamp_regexp, REG_EXTENDED)) {
static void free_patch_list(struct patch *list)
		/*
{
	state->whitespace_error++;
		return -1;
/*
			 */
		current += img->line[i].len;
			break;
		l = list;
		nr = parse_chunk(state, buf.buf + offset, buf.len - offset, patch);
	strbuf_release(&sb);
	 */
	/* If we reached the end on one side only, lines don't match. */
			reverse_patches(patch);
			/*
	 * Rename or modification boils down to the same
	prepare_image(image, img, len, !patch->is_binary);
			else
		fragment->patch = line;
	int i;
	/* unquoted first name */
static struct fragment *parse_binary_hunk(struct apply_state *state,
			  int p_value,
	 * Expect a line that begins with binary patch method ("literal"
	state->p_context = UINT_MAX;

		/*
			trailing++;
		/* We have a patched copy in memory; use that. */
			return -128;
		res = try_create_file(state, path, mode, buf, size);
		} else {
	 * empty line.  This data, when applied to the postimage, produces
			postlen += postimage->line[i].len;
/*
		OPT_BOOL_F(0, "unsafe-paths", &state->unsafe_paths,
			     const char *line,
		} optable[] = {
	    ? postlen < new_buf - postimage->buf
			return status;

	len -= offset;
{
		OPT_BOOL(0, "unidiff-zero", &state->unidiff_zero,

	patch->def_name = git_header_name(p_value, line, len);
		else {
{

			return -128;
				break;
{
			      struct patch *patch)
{
		       !(preimage->line[ctx].flag & LINE_COMMON)) {
	/*
	memcpy(ce->name, path, namelen);
static char *inflate_it(const void *data, unsigned long size,
	}
#define binary_patch_method leading
	/* A git diff has explicit new/delete information, so we don't guess */
		return line + len - end;
			   const char *line,


}
	char *err;
		/* if the input length was not multiple of 4, we would
static int match_fragment(struct apply_state *state,
};
		if (state->check_index) {

		if (!len)
			      struct stat *st)
struct fragment {
				stamp_regexp);
		fragp = &fragment->next;
static int parse_fragment_header(const char *line, int len, struct fragment *fragment)
			{ "rename to ", gitdiff_renamedst },
		patch->is_new = 0;
	read_mmblob(&our_file, ours);
				   const char *second,
				       struct patch *patch)
		val = 0;
		/*
	patch->is_new = patch->is_delete = -1;
 *   0 if the patch applied
			N_("tolerate incorrectly detected missing new-line at the end of file"),
	/* in-core three-way merge between post and our using pre as base */

	while (patch) {
 unmatch_exit:
	free(our_file.ptr);
		case ' ': case '\n':
		while ((second < line + llen) && isspace(*second))
	size_t n;
	else
		match = (tgtfix.len == fixed.len - fixstart &&
		cp = skip_tree_prefix(p_value, first.buf, first.len);
		res = apply_patch(state, 0, "<stdin>", options);
	else if (match_end)
		return error(_("repository lacks the necessary blob to fall back on 3-way merge."));
	if (12 < size && !memcmp(line, "\\ ", 2))
static void free_patch(struct patch *patch)
		return NULL;
		patch->old_name = xstrdup(patch->def_name);
	if (root->len) {
	while (s2 < end2 && (end2[-1] == '\r' || end2[-1] == '\n'))
static void record_ws_error(struct apply_state *state,
 * Returns:

			used = parse_binary(state, buffer + hd + llen,
	}
	if (status)


	while (patch) {
	     frag;
	}
				offset = 0 - offset;
		ce->ce_flags = create_ce_flags(stage);
	if (unset)
	if (!name)
			remove_path(patch->old_name);
	struct string_list_item *item;
			      state->whitespace_error);


		size_t oldlen = preimage->line[i].len;
		return 0;
 * between a "---" that is part of a patch, and a "---" that starts
			     int len,
	img->line_allocated[img->nr].len = len;
{
 *  -1 if an error happened
 * current version we have, from the working tree or from the index,
	 */
	}
		const char *cp;



		if (isspace(*s1)) {
	/*
		 * If they match, either the preimage was based on
			goto end;
			if (lstat(path, &st) < 0) {
}
	if (/* does the patch have only one hunk? */

			     const char *line,
	if (state->summary && state->apply_verbosity > verbosity_silent)
		repo_rerere(state->repo, 0);
			N_("allow overlapping hunks")),
	again:
		if (state->apply_verbosity > verbosity_silent) {
	if (state->ita_only) {
		 * patch has become corrupted/broken up.

	do {
		if (!lstat(path, &st) && S_ISDIR(st.st_mode))
			  unsigned long current,
		else
	ex = strlen(expect);
	preimage_limit = preimage->nr;
 */
		return squash_slash(xstrdup_or_null(def));
	patch->is_toplevel_relative = 0;

}
{
			patch->is_delete = 1;

			break;

/*
	if (!strcmp(option, "warn")) {
	return hour * 60 + minute - zoneoffset == epoch_hour * 60;
		if (len < size && patch[len] == '\\')
	/*
	if ((st_mode ^ patch->old_mode) & S_IFMT)
	 * matches the preimage before the end of the file.
	if (oldlines || newlines)
	char *img;
					  int *status_p,
		return -1;
					       "match old mode (%o) of %s"),
}
		dst = patch_delta(img->buf, img->len, fragment->patch,
}
	preimage_end = preimage->buf + preoff;
	if (!patch->new_name)
		}
		char *another;

		OPT_BOOL(0, "stat", &state->diffstat,
			goto end;
		return error(_("invalid path '%s'"), old_name);
 * patches floating around.
		return offset;
		newsize = hunk_size + byte_length;
 * Check if the patch has context lines with CRLF or
	return 1;
		if (is_null_oid(&patch->threeway_stage[stage - 1]))
			added++;
	}
			check_old_for_crlf(patch, line, len);

	    (!patch->old_name && !patch->is_new)) {
		(patch->old_mode && patch->new_mode &&
	const char *patch = frag->patch;
				break;
	free(patch->def_name);
	 */
	return len;

			     int llen)
	 * If something was removed (i.e. we have old-lines) it cannot

			remove_last_line(&postimage);
{
				check_old_for_crlf(patch, line, len);
		n = tz_with_colon_len(line, end - line);
	if (!*name && !isnull) {
static int parse_range(const char *line, int len, int offset, const char *expect,
	}
 */

{
		return -1;
	if (state->ws_ignore_action == ignore_ws_change)
	char *preimage_end;
		return add_conflicted_stages_file(state, patch);
{
		}

	if (strlen(patch->old_oid_prefix) != hexsz ||
	}
				if (phase == 1) {
		if (trailing > leading) {
	void *dst;
			int git_hdr_len = parse_git_diff_header(&state->root, &state->linenr,
			return error(_("corrupt patch at line %d"), state->linenr);
	 * when you add new options.
/*

 * creation or deletion of an empty file.  In any of these cases,
	patch->is_new = 0;
			APPLY_OPT_INACCURATE_EOF),
		if (backwards_lno == 0 && forwards_lno == img->nr)
	clear_image(image);

	const unsigned hexsz = the_hash_algo->hexsz;
			if (c == '\n')
		patch->is_delete = 1;
		new_buf += l_len;

	return gitdiff_verify_name(state, line,
	patch->is_delete = 1;
	reverse = parse_binary_hunk(state, &buffer, &size, &status, &used_1);

		else
		patch->ws_rule = 0;
			goto unmatch_exit;
	const char *old_name, *new_name;
		ws_fix_copy(&fixed, orig, oldlen, ws_rule, NULL);
	 */
		/*

	end -= n;
	 * a sequence of 'length-byte' followed by base-85 encoded data

		return 0; /* deletion patch */

			/* --no-add does not add new lines */
			  &their_file, "theirs",
		state->ws_error_action = correct_ws_error;
}
			current_lno = forwards_lno;
			    const char *s2, size_t n2)
	return offset;
		    slash_old - old_name != slash_new - new_name ||
}
		if (name)
 * reading after seeing a single patch (i.e. changes to a single file).
	}
	/*
		int is_blank_context = 0;
		}
	state->prefix = prefix;
		/* Although buf:size is counted string, it also is NUL
	 * For safety, we require patch index line to contain

		goto end;
	struct strbuf buf = STRBUF_INIT; /* owns the patch text */
	zoneoffset = strtol(timestamp + m[3].rm_so + 1, (char **) &colon, 10);

	while (list) {
			if (same)
				     patch->new_name
		return -1;
		OPT_BOOL(0, "apply", force_apply,
	/*
		state->check_index = 1;
{
		 * Pass NULL to convert_to_git() to stress this; the function
		return find_name_common(root, line, def, p_value, NULL, TERM_TAB);
			patch->new_name = xstrdup_or_null(name);
	} else if (!is_missing_file_error(errno)) {
 *   0 if everything went well
	if (pos < 0)
		} else if (status) {
			return error_errno("%s", name);

			return -128;
}
	}
				      preimage->buf + preoff, prelen))
	frag = xcalloc(1, sizeof(*frag));
 * A line in a file, len-bytes long (includes the terminating LF,
		if (pos < 0) {
		p--;
	if (patch->new_name) {
					break;
				fprintf(stderr, "U %s\n", item->string);
		hash_object_file(the_hash_algo, img->buf, img->len, blob_type,
		add, pluses, del, minuses);


		res = -128;
			   struct object_id *oid)
	if (!timestamp)
	struct strbuf name = STRBUF_INIT;
			++nr;
static int has_epoch_timestamp(const char *nameline)
		if (state->squelch_whitespace_errors &&
		if (safe_create_leading_directories(path))
			n = patch->old_name;
 * Find file diff header
			  struct patch *patch,
				return -1;
	int i;
	patch->old_name = patch->new_name = NULL;
	return 0;
	       ? fixed_preimage.nr == preimage->nr
	unsigned result = ws_check(line + 1, len - 1, ws_rule);
			res = try_create_file(state, newpath, mode, buf, size);
		}
		 * Does it begin with "a/$our-prefix" and such?  Then this is
 *
		return status;
		strbuf_attach(buf, result, sz, sz + 1);
						       GITATTRIBUTES_FILE)))
				      (first == ' ' ? LINE_COMMON : 0));
		return;
				return xmemdupz(name, len);
			ret = size < 5 || !starts_with(line, "diff ");
		if (!skip_prefix(pathname, state->prefix, &rest) || !*rest)
	unsigned mode = patch->new_mode;
	image->buf = result.ptr;
 * We are about to apply "patch"; populate the "image" with the
		 * the preimage was based on already had (i.e. target
				_("Applied patch to '%s' with conflicts.\n"),
#include "object-store.h"
		patch->is_delete = 0;
		case '\n':
}
			break;
	if (inaccurate_eof &&
	if (checkout_entry(ce, &costate, NULL, NULL) ||
	/*

				"Files ",
			if (!deleted && !added)
	patch->new_oid_prefix[len] = 0;
 *   the number of bytes consumed otherwise,
	    newlines.len > 0 && newlines.buf[newlines.len - 1] == '\n') {
{
	free(patch->old_name);
	if (!state->update_index)
		 * followed by "\ No newline", then we also remove the
	nslash = p_value;
 * the current contents of the new_name.  In no cases other than that
		fixed += l_len;
		img->len = fragment->size;
	if (patch->conflicted_threeway)

	const char *p;

				   "%d lines applied after"
 * is stored in size.  leading and trailing are the number
		OPT_BOOL(0, "summary", &state->summary,
					string_list_clear(&cpath, 0);
			current = backwards;
	 * form.

		return 0;
			if (!name[len + 1])
	     offset += len, size -= len, line += len, state->linenr++) {
{
/*
		 */
	    /* does it record full SHA-1? */
		if (!cp)

	memset(sb->buf + sb->len, 0, SLOP);
/*
	cp = image->buf;
	/*
		name = patch->old_name ? patch->old_name : patch->new_name;
	 *
			len = strlen(patch->old_name);
		if (!cp)
		 * empty to us here.
		 * and either case, the old piece should match the preimage
			if (res < 0)
	current_lno = line;
	if (def) {
	if (state->check || state->apply) {
static int create_file(struct apply_state *state, struct patch *patch)
	size_t len;
			strbuf_release(&sp);
 * Returns:
	}
	for (i = 0; i < preimage_limit; i++)

		 * and the line length must be multiple of 5 plus 2.
	return 0;
			return error(_("--cached outside a repository"));

	/*
			 * apply_data->apply_fragments->apply_one_fragment
		return 0;
	int max, add, del;
	(*linenr)++;

		return -1;
		if (!match)

			{ "rename old ", gitdiff_renamesrc },
#include "blob.h"
	unsigned long val = strtoul(line, NULL, 10);
		change = check_symlink_changes(state, name->buf);
	 * When running with --allow-overlap, it is possible that a hunk is


		}

		return -1;
{
	while (1) {
	char *name, *cp;
		default:
	if (cpath.nr) {
	}
		struct cache_entry *ce;
		OPT_BIT(0, "recount", options,
		int same = !strcmp(old_name, new_name);
}
	pos = index_name_pos(state->repo->index, name, strlen(name));
	return 0;
		/* and find the corresponding one in the fixed preimage */

	if (state->max_change > 0) {
			fprintf_ln(stderr,
		len = linelen(line, size);
{
	printf("%5d %.*s%.*s\n", patch->lines_added + patch->lines_deleted,
			if (strcmp(cp, first.buf))
static void prepare_fn_table(struct apply_state *state, struct patch *patch)
	char *new_buf, *old_buf, *fixed;
{
	return -1;
					  int *used_p)
	 * to be deleted by the previous patch is still in the working

		 * We allow "\ No newline at end of file". Depending
	/*
	free(patch->old_name);
	/* Expected format: ' ' x (1 or more)  */

		}
			else

	if (extensions && !patch->extension_linenr)
	int p_value;
	 * If we are removing blank lines at the end of img,
	write_object_file(tmp_image.buf, tmp_image.len, blob_type, &post_oid);
static int parse_num(const char *line, unsigned long *p)
	int len;
	while (p > line && isdigit(*p))
 * in the working tree or in the index.
 */
	unsigned ws_rule = patch->ws_rule;
	if (!start)
	trailing = frag->trailing;
	for ( ; patch; patch = patch->next) {
	if (!isdigit(*line))
	old = oldlines;

			  &our_file, "ours",
		if (line + llen - cp != first.len ||
		REALLOC_ARRAY(img->line, nr);
		return 0;
	 * Each 5-byte sequence of base-85 encodes up to 4 bytes,
		} else if (has_symlink_leading_path(name, strlen(name))) {
	 */
	const char *new_name = NULL;
	if (!patch->is_delete)
	/* Quick hash check */
static void patch_stats(struct apply_state *state, struct patch *patch)
{
		cp = strchr(qname.buf + qname.len + 3 - max, '/');
		p--;
		default:

	int read_stdin = 1;
	costate.istate = istate;
	if (!name)
	    apply_fragments(state, &image, patch) < 0) {
	int hunk_size = 0;
			if (state->apply_in_reverse)
		patch->is_new = 0;
		if (!state->threeway || try_threeway(state, &image, patch, st, ce) < 0)
	} else {

		/* Am I at my context limits? */
static char *find_name_traditional(struct strbuf *root,
	/*
}
}
done:
/*
			struct image *img,
 * patch text is pointed at by patch, and its byte length
}
#define LINE_COMMON     1
	if (close(fd) < 0 && !res)
		int len = quote_c_style(patch->old_name, NULL, NULL, 0);
	if (lstat(name, &st)) {
		const char *rest;
			errno = EEXIST;
		state->ita_only = 0;
	update_pre_post_images(preimage, postimage,
	int res;
		return;

	used = llen;
}
 * absolute paths, return NULL in that case.
		memcpy(ce->name, patch->new_name, namelen);
	 * Some things may not have the old name in the
	unsigned long newpos, newlines;

		OPT_BOOL(0, "no-add", &state->no_add,

		case 'd':
			if (ce)
					  unsigned long *sz_p,
static int parse_single_patch(struct apply_state *state,
}
			 */
			match_beginning = match_end = 0;
	struct strbuf fixed;

						 patch->new_name);
	}
	int extensions = (patch->is_delete == 1) + (patch->is_new == 1) +
		      const char **argv,
static int gitdiff_similarity(struct gitdiff_data *state,
	 * so that we can do speculative "memcmp" etc, and
	struct string_list_item *ent;
{
	if (read_patch_file(&buf, fd) < 0)
	}
				 "git diff header lacks filename information when removing "
			N_("apply the patch in reverse")),
	int i;
	 * full hex textual object ID for old and new, at least for now.
			warning(_("Cannot prepare timestamp regexp %s"),
			patch->old_name = name;
	}
	 * will also take care of a negative line number that can
		new_name = patch->new_name;
		}
}

			 int applied_pos,
			return error(_("failed to read %s"), name);
};
			       struct patch *patch)
			   const char *new_name,
		err |= res;
		return apply_binary(state, img, patch);
}
	 */
			return 0;
		max_byte_length = (llen - 2) / 5 * 4;
		 */
			return (i == 0) ? NULL : &line[i + 1];
			memcpy(old, patch + 1, plen);
	}
	if (*line == '"') {
			return err;
static size_t diff_timestamp_len(const char *line, size_t len)
			{ "new file mode ", gitdiff_newfile },
		return 0;
static int build_fake_ancestor(struct apply_state *state, struct patch *list)
			    state->ws_error_action != correct_ws_error) {
				const char *arg,
	struct fragment *forward;
	free(base_file.ptr);
 * attach it to "image" and add line-based index to it.
		add_line_info(image, cp, next - cp, 0);
		if (!res)
	/*
	if (fd < 0)
{
			   const char *line,
			return 0;
	}
	/*


			return 0;
		return -1;
	    starts_with(++preimage, heading) &&
	struct image postimage;
	if (*ptr == ' ')
		 * In such a case, path "new_name" does not exist as
				     patch->new_name);
		set_object_name_for_intent_to_add_entry(ce);
	if (convert_to_working_tree(state->repo->index, path, buf, size, &nbuf, NULL)) {
		return -1;
			item = string_list_insert(&state->fn_table, patch->old_name);
			return name;
	n = date_len(line, end - line);
	else
	 * or "delta"), followed by the length of data before deflating.
	unsigned flag : 8;
 * This represents a "file", which is an array of "lines".
	int llen, used;
	if (apply_default_whitespace && parse_whitespace_option(state, apply_default_whitespace))

		if (!skip_prefix(buf, "Subproject commit ", &s) ||
	img->nr--;
		if (apply_one_fragment(state, img, frag, inaccurate_eof, ws_rule, nth)) {
	cnt = strlen(patch->new_name);
 * or in the helper function apply_binary_fragment() this calls.
	 * For the same reason, the date must be either 1969-12-31 or
			       int isnull,
		if (memcmp("--- ", line,  4) || memcmp("+++ ", line + len, 4))
		 * or mode change, so we handle that specially
			warning(_("regexec returned %d for input: %s"),
			if (!cp)
		return NULL;
		}
		} else switch (err) {
			return 0;
 * files, we can happily check the index for a match, but for creating a
	    lstat(ce->name, st))
		{ OPTION_CALLBACK, 0, "whitespace", state, N_("action"),
			      const struct cache_entry *ce,
		 * We have verified buf matches the preimage;
					  const char *path,
 * The latter is needed to deal with a case where two paths A and B
				   int p_value)
	if (!second)
				goto again;
}


		applied_at += img->line[i].len;
			N_("ignore changes in whitespace when finding context"),
	prepare_symlink_changes(state, patch);

static int parse_mode_line(const char *line, int linenr, unsigned int *mode)
 * FIXME! The end-of-filename heuristics are kind of screwy. For existing
		      int argc,
 * into the next diff. Tell the parser to break out.
			backwards -= img->line[backwards_lno].len;
		/*
		close(fd);
		return 0;
	 * and that *still* needs to match the end. So trust `match_end` more
			N_("don't apply changes matching the given path"),
	int i, nr;
		}
static void prefix_one(struct apply_state *state, char **name)
		if (write_object_file(buf, size, blob_type, &ce->oid) < 0) {
		string_list_clear(&cpath, 0);
	for ( ; patch; patch = patch->next) {
		return 0;
			    isspace(name[len])) {

	 *
	}
	if (state->check_index && is_not_gitdir)
				return error(_("sha1 information is lacking or "

			img->line[applied_pos + i].flag |= LINE_PATCHED;
 *   0 otherwise
		if (deflen < len && !strncmp(start, def, deflen))

/*
				 const char *line,
		fragment = xcalloc(1, sizeof(*fragment));
	 */
			SWAP(frag->newpos, frag->oldpos);
{
			 * and a rename patch has the names elsewhere
}
		if (list->free_patch)
		return -1;
	struct strbuf buf = STRBUF_INIT;
static int parse_traditional_patch(struct apply_state *state,
			return error(_("cannot reverse-apply a binary patch "
	    hunk->oldpos == 1 && hunk->oldlines == 1 &&
	    old > oldlines && old[-1] == '\n' &&
	unsigned free_patch:1,
		/*
			return error(_("unable to add cache entry for %s"),
	}

		if (*cp == '\t')

	}
	if (name == NULL)
	 * Proposed "new-style" GNU patch/diff format; see
		char *result;
	if (patch->is_new > 0 || patch->is_copy) {
			  int prepare_linetable)
		set_warn_routine(state->saved_warn_routine);

	struct fragment **fragp = &patch->fragments;
	for (cnt = 1, frag = patch->fragments;
	if (state->ita_only && (state->check_index || is_not_gitdir))
			res = state->apply_with_reject ? -1 : 1;
		else if (is_blank_context)
		 * second points at one past closing dq of name.

				return -1;
static int preimage_oid_in_gitlink_patch(struct patch *p, struct object_id *oid)

	}
	second += 4;	/* skip "+++ " */
		}
			N_("apply changes matching the given path"),
			    "Applying patch %%s with %d rejects...",
	ptr = strchr(line, ' ');
	}
	 * @@ -1 +1 @@
			listp = &patch->next;
	 * or "file~").
	img = strbuf_detach(&buf, &len);
}
				   "%d lines add whitespace errors.",

	string_list_clear(&state->fn_table, 0);
		offset += nr;
	int size;
	 *
		return error(_("path %s has been renamed/deleted"), old_name);
				       "which does not match the "
#include "config.h"
static void free_fragment_list(struct fragment *list)
{
		*hdrsize = len + nextlen;

	}
 *   the size of the header in bytes (called "offset") otherwise
	hour = strtol(timestamp, NULL, 10);
		} else if (!get_oid_blob(patch->old_oid_prefix, &oid)) {
		return (struct patch *)item->util;

	status = check_preimage(state, patch, &ce, &st);
{
		}
			if (errno != EEXIST)

		if (state->apply_verbosity > verbosity_normal && applied_pos != pos) {
		oidcpy(&patch->threeway_stage[1], &our_oid);
	if (!n)	/* No date.  Too bad. */
		return EXISTS_IN_INDEX;
		ce->ce_namelen = namelen;
				     name, oid_to_hex(&oid));
				return SUBMODULE_PATCH_WITHOUT_INDEX;
{
	it->util = exclude ? NULL : (void *) 1;
	prefix_one(state, &p->new_name);
			add_line_info(&preimage, "\n", 1, LINE_COMMON);

	}
			const char * const *apply_usage)
 * Usually it points at a patch (whose result records the contents

			continue;
	    strlen(patch->new_oid_prefix) != hexsz ||
		 * In either case, we are fixing the whitespace breakages
		OPT_BOOL(0, "reject", &state->apply_with_reject,
		q = guess_p_value(state, second);
				continue;


static inline int metadata_changes(struct patch *patch)
	if (state->index_file)
	}
		state->saved_warn_routine = get_warn_routine();
				_("Applied patch to '%s' cleanly.\n"),
	}
		buf = preimage->buf;
	int namelen = strlen(path);
	}
	/*

{
		}
			{ "--- ", gitdiff_oldname },
 * is updated in place, otherwise it's updated on a new buffer
			  unsigned int size,
	}
		return 0;
	}
			if (check_header_line(*linenr, patch))
		strbuf_splice(&qname, 0, cp - qname.buf, "...", 3);

			; /* ok */

		return 0;
			     const char *line,
	 */
		 */
				break;
 */
	}
			PARSE_OPT_NONEG, apply_option_parse_exclude },
	return error_errno(_("unable to write file '%s' mode %o"),
		/*
		if (!memcmp("diff --git ", line, 11)) {
}
		return error(_("%s: does not exist in index"), name);
		 */
/*
			 * Is this the separator between the preimage
				patch->new_name);
				goto done;

		unsigned long nextlen;
			if (state->ws_error_action == correct_ws_error) {
		end1--;

	return NULL;
	int backwards_lno, forwards_lno, current_lno;
			if (first == '+' &&
		if (max_byte_length < byte_length ||
		/* verify that the result matches */
{
	if (end == line)	/* No space before date. */

		      struct stat *st, const struct cache_entry *ce)
	if (state->cached)
		img->line_allocated = img->line;
		if (show_name)
		 * Reduce the number of context lines; reduce both
		case ' ':
}
			return remove_file(state, patch, 1);
			goto end;
	if (state->cached || state->check_index) {
	error(_("corrupt binary patch at line %d: %.*s"),
	/*

	 * thing: remove the old, write the new
	 * we need it to adjust whitespace if we match.
			}
			   const struct object_id *theirs)
	struct fragment *next;
		}
	 * Now handle the lines in the preimage that falls beyond the
	const char *name = old_name ? old_name : new_name;
			 const char *line,
	}
		 */
	free(postimage.line_allocated);

				continue;

		hash_object_file(the_hash_algo, img->buf, img->len, blob_type,
			arg = to_free = prefix_filename(state->prefix, arg);

			return error(_("unable to open or read %s"), path);
	fixed_buf = strbuf_detach(&fixed, &fixed_len);
	for (len = 0 ; ; len++) {
/*
				       ws_rule, match_beginning, match_end);

			return error(_("unable to remove %s from index"), patch->old_name);
		return -1;
	}
			int used;
	if (!name)
		start = line;
		      int options)
}
	else if (get_oid(patch->old_oid_prefix, &pre_oid) ||
		}

	fragment->leading = leading;
				goto is_new;
			warning(_("recount: unexpected line: %.*s"),
			};
	if (status < 0)
	line += len;
			N_("instead of applying the patch, output diffstat for the input")),
 * patch, and it is OK because we will find the name elsewhere.
				}

#define DIFF_OLD_NAME 0
			struct image *image,
		/* Ok, we'll consider it a patch */
		error(_("unrecognized input"));
			read_stdin = 0;
			PARSE_OPT_NOARG, apply_option_parse_space_change },
	}

	if (new_name && !verify_path(new_name, patch->new_mode))
	 * -Subproject commit <old sha1>
		if (S_ISGITLINK(patch->old_mode)) {

					    size - hd - llen, patch);
		line = img->nr;
		OPT_BOOL(0, "cached", &state->cached,
	    ((0 < patch->is_new) || patch->is_rename || patch->is_copy)) {
 *   the number of bytes in the patch otherwise.
			     unsigned expected_mode)
		name = find_name_traditional(&state->root, first, NULL, state->p_value);
			return 1;
}
	strbuf_grow(sb, SLOP);
		nth++;
 */
	if (*name) {
	if ((tpatch = in_fn_table(state, new_name)) &&
	/* Find common prefix */
{

		}
		imgoff += imglen;
	string_list_clear(&state->symlink_changes, 0);
{
			if (res < 0)
	}

	size_t remove_count, insert_count, applied_at = 0;
	}
		/* Try fixing the line in the target */
	return ptr - line;
}
		if (stat_ret < 0) {
				first = '-';
 * check_patch() separately makes sure (and errors out otherwise) that
		return -1;
	} else {

			  int len,
	get_oid_hex(patch->new_oid_prefix, &oid);
{
static int load_current(struct apply_state *state,

}
	git_zstream stream;
 */
			int oplen = strlen(p->str);
	const char *name;
void clear_apply_state(struct apply_state *state)
	*used_p = used;
			struct strbuf sp = STRBUF_INIT;
	size_t date_len;
	patch->lines_added += added;
static void mute_routine(const char *msg, va_list params)
	 * contents are marked "rejected" at the patch level.


{



	size_t len, line_len;
			return -1;

		return 0; /* it all looks fine */
	return 0;
		return;
	 */
	}

	patch->is_new = 1;
 */
			break;
}
	}
	const char *old_name = NULL;
		case ' ':
	err = whitespace_error_string(result);
static size_t short_time_len(const char *line, size_t len)
	if (memcmp(line, expect, ex))
		" "
	 * rest of the headers anywhere (pure mode changes,
			current_lno = backwards_lno;
	}
	size_t fixed_len, postlen;
		}
	 * 1970-01-01, and the seconds part must be "00".
	/*
			return 1;
			buf_end += preimage->line[i].len;
	 * end of the file (if any). They will only match if they are
{
static void remove_last_line(struct image *img)
	char *cp;
	}
			return 0;
	int val = -1;
		return -1;
			   const char *line,
	return -1;
	backwards = current;
static int gitdiff_hdrend(struct gitdiff_data *state,
		set_warn_routine(mute_routine);
{
		}
 *  -1 if no header was found
#include "lockfile.h"
				    int current_lno,
			else
	else
	if (state->apply_verbosity > verbosity_silent)
		patch->is_delete ||
			fixed += preimage->line[ctx].len;
		if (apply_binary_fragment(state, img, patch))
	char *result;
				    int *gone)
				return -1;
	string_list_init(&state->fn_table, 0);
	unsigned long offset = 0;
				   const char *first,

		res = apply_patch(state, fd, arg, options);
		hunk_linenr++;

		       int options)
	len = line - start;
		case '-':
}
			break;
		if (!result)
		OPT_FILENAME(0, "build-fake-ancestor", &state->fake_ancestor,
		return 0;
	}

	if (state->cached) {
{


