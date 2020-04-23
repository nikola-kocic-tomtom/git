		case IDENT_DRAINING:

	strbuf_grow(buf, len + stats.lonelf);
				die(error_msg, path, enc);
	if (stats->nul)
	reset_merge_attributes();
	 */

			 * repository, we cope with that by stripping the expansion out.
/*

	 * Otherwise, just emit it to the output stream.
		/* step 3: skip over Id$ or Id:xxxxx$ */
	case CRLF_AUTO_INPUT:
		return 1;
static const char *gather_convert_stats_ascii(const char *data, unsigned long size)

	} else {
		ident->state = 0;

		return git_config_string(&drv->smudge, var, value);
static struct attr_check *check;
		return git_config_string(&drv->clean, var, value);
{
		return 0;
		src  = dollar + 1;
int would_convert_to_git_filter_fd(const struct index_state *istate, const char *path)
	}
	}
				  &dst_len);
		if (input) {
		return NULL;
		len = dst->len;
			if (stream_filter(cas->two,
{
	if (blob)
typedef void (*free_fn)(struct stream_filter *);
		return 0;
				/* incomplete keyword, no more '$', so just quit the loop */
	if (status)
	data = read_blob_data_from_index(istate, path, &sz);
			ca->crlf_action = CRLF_TEXT_INPUT;

		src = dst->buf;
			 * Skipping until '$' or LF, but keeping them
	/*
struct stream_filter {
		/* step 4: substitute */

			 */
	convert_attrs(istate, &ca, path);
};
	if (!buf && !src)
	strbuf_addf(&trace, "%s (%s, considered %s):\n", context, path, encoding);
		return "text=auto eol=crlf";
		/*
	return 0;
	} else {
		strbuf_remove(&ident->left, 0, to_drain);
{
		entry->supported_capabilities = 0;
		if (err)
}



			stats->lonelf++;

	case CRLF_BINARY:
};
	encode_to_git(path, dst->buf, dst->len, dst, ca.working_tree_encoding, conv_flags);
	size_t to_drain = ident->left.len;
static int start_multi_file_filter_fn(struct subprocess_entry *subprocess)
		const char *path;
		err = packet_write_fmt_gently(process->in, "treeish=%s\n", oid_to_hex(&meta->treeish));

	convert_attrs(istate, &ca, path);
	process = &entry->subprocess.process;
			&trace, "| \033[2m%2i:\033[0m %2x \033[2m%c\033[0m%c",

	int state;
	if ((stats->printable >> 7) < stats->nonprintable)
{
		meta->refname = refname;
	struct cascade_filter *cas = (struct cascade_filter *)filter;



			 * that it is suffixed with a space or comma
		memcpy(*output_p, ident->left.buf, to_drain);

	return !err;

		goto done;
	 * support smudge).  The filters might expect CRLFs.
	char buf[FILTER_BUFFER];
	case CRLF_TEXT_CRLF:
	while (filled < sz) {
	case CRLF_UNDEFINED:
			die(_("CRLF would be replaced by LF in %s"), path);
{
			strbuf_add(buf, src, nl - src);
			goto done;
	child_process.in = -1;
				   struct delayed_checkout *dco)
		{ "smudge", CAP_SMUDGE },
				die(error_msg, path, enc);
	 * filter.<name>.smudge and filter.<name>.clean specifies
			return -1;
	case CRLF_AUTO_CRLF:
	strbuf_setlen(buf, dst - buf->buf);

			} else
	fflush(NULL);

			else {

	}
		src = dst->buf;
				  "The file will have its original line"
}
			}
	if (finish_async(&async)) {
{
 * more interesting conversions (automatic gzip/unzip, general format
};
{
	struct cascade_filter *cascade;
			   const char *encoding, const char *buf, size_t len)
			return 0;
	CRLF_AUTO,
				lf_to_crlf->held = ch;
		if (die_on_error)


}
	/* NUL, CR, LF and CRLF counts */
	next = found + strlen(enc_name);
		return NULL;
		  ": %s $", oid_to_hex(oid));
		} while (--len);
static const char *default_encoding = "UTF-8";
		}
		skip_prefix(stripped, "-", &stripped);
			} else if (was_cr) {

				ident->state = IDENT_SKIPPING;
		return 0;
}
	return ret;
	const char *value = check->value;
		src = dst->buf;
	if (!drv)
		err = write_packetized_from_fd(fd, process->in);
			advise(advise_msg, path, stripped_len, stripped);

		/* If we have any CR or CRLF line endings, we do not touch it */

	return 0;
		}
	else
struct cmd2process {
	case CONVERT_STAT_BITS_TXT_LF | CONVERT_STAT_BITS_TXT_CRLF:
	struct strbuf filter_status = STRBUF_INIT;
			unsigned char c = *src++;
				 * Previous round saw CR and it is not followed
		*osize_p -= to_drain;
	}

	struct text_stat stats;
				cnt++;
		 * unless we want to renormalize in a merge or

		if (c == '\n') {
				stats->nul++;
	ret |= apply_filter(path, src, len, -1, dst, ca.drv, CAP_CLEAN, NULL, NULL);
	 * Create a pipeline to have the command filter the buffer's
			}
				  &dst_len);
		 entry->supported_capabilities &= ~wanted_capability;
		 * Force shutdown and restart if another blob requires filtering.
		return 1;
	struct strbuf nbuf = STRBUF_INIT;
 * the contents cannot be filtered without reading the whole thing
			    struct text_stat *old_stats, struct text_stat *new_stats,
	case CRLF_UNDEFINED:
			  const char *input, size_t *isize_p,
		else
	struct convert_driver *next;
void reset_parsed_attributes(void)
		    memcmp(src, re_src, src_len)) {
		strbuf_addstr(buf, " $");
	if (count) {

		return 0;
static const char *git_path_check_encoding(struct attr_check_item *check)

	unsigned has_held:1;
					    size_t len, struct strbuf *dst,
	 * contents.
	if (!cnt)
	}
	if (ATTR_TRUE(value))
		      path, default_encoding, enc);

	return 1;
	}
	 * would convert. If we are in dry-run mode, we can give an answer.
	if (ATTR_TRUE(value) || ATTR_FALSE(value)) {
	; /* nothing -- null instances are shared */
	}

	cascade_filter_fn,
}
	params.size = len;

	CRLF_TEXT_INPUT,
{
	if (!entry) {
	const char *key, *name;

			lf_to_crlf->has_held = 0;
		memmove(dst, src, dollar + 1 - src);
	if (ca.crlf_action == CRLF_AUTO || ca.crlf_action == CRLF_AUTO_CRLF)
		err = strcmp(filter_status.buf, "success");
	if (ca.ident)
	int ret = 0;
	}
			was_cr = 1;
	if (!ident)

	cascade->one = one;
	if (params->src) {
		if (ch != ':')
	struct cmd2process *entry;
	if (crlf_action == CRLF_AUTO || crlf_action == CRLF_AUTO_INPUT || crlf_action == CRLF_AUTO_CRLF) {
			}
				   enum crlf_action crlf_action)
			ca->crlf_action = CRLF_TEXT_CRLF;
				   const struct checkout_metadata *meta,

			"not all paths have been filtered"), cmd);
	if (!dst) {


		return git_config_string(&drv->process, var, value);
		ch = *cp++;
}
		return NULL;
				strbuf_addstr(&ident->left, ident->ident);
			    const struct object_id *treeish,
	if (crlf_action == CRLF_AUTO || crlf_action == CRLF_AUTO_INPUT || crlf_action == CRLF_AUTO_CRLF) {
			filled = sz - remaining;
		const char *nl = memchr(src, '\n', len);
	else
			if (!dollar) {

					    "back is not the same");
			src  = dollar + 1;
static int apply_multi_file_filter(const char *path, const char *src, size_t len,
		strbuf_addstr(buf, oid_to_hex(&oid));
	sigchain_pop(SIGPIPE);
			     char *output, size_t *osize_p)
}

			    size_t len, struct strbuf *dst,
				stats->printable++;
	return NULL;
};
		if (convert_is_binary(&stats))
{
static void handle_filter_error(const struct strbuf *filter_status,
#define CONVERT_STAT_BITS_TXT_LF    0x1
{
	/*
	trace_encoding("source", path, enc, src, src_len);
static int lf_to_crlf_filter_fn(struct stream_filter *filter,

		    (ret_stats & CONVERT_STAT_BITS_TXT_CRLF))
		/*
		string_list_insert(&dco->paths, path);
	}
		if (!nl)
				  output + filled, &remaining))
	 * "$Id: 0000000000000000000000000000000000000000 $" <=> "$Id$"

 *
	int err;
	enum crlf_action crlf_action; /* When no attr is set, use core.autocrlf */
	 *
		goto done;
	if (strbuf_avail(buf) + buf->len < len)

			   char *output, size_t *osize_p)
			default:
	default:
		*output_p += to_drain;
static int count_ident(const char *cp, unsigned long size)
				"(depending on the byte order) as "
	 * This ensures that no information is lost during conversion to/from
		goto done;
	struct strbuf trace = STRBUF_INIT;
	async.data = &params;
		strbuf_addch(&ident->left, ch);
	struct attr_check_item *ccheck = NULL;
	err = packet_flush_gently(process->in);
		const char* msg = _("failed to encode '%s' from %s to %s");
	if (refname)
		*osize_p -= count;

	gather_stats(src, len, &stats);
	case CRLF_BINARY:
	const char *ret = "";
	strbuf_attach(buf, dst, dst_len, dst_len + 1);
	if (ret && dst) {

{
			; /* ignore unknown keys */
		 * If we guessed, we already know we rejected a file with
				strbuf_addch(&ident->left, ch);

	}
 * Streaming conversion support
			spc = memchr(src + 4, ' ', dollar - src - 4);
	int err = 0;
		die(_("%s: clean filter '%s' failed"), path, ca.drv->name);

	return ret;
		/*
		/*
		/*
	if (src == buf->buf)
		return 0;
	 * Tell the caller that the content was not modified.
	if (crlf_action == CRLF_AUTO || crlf_action == CRLF_AUTO_INPUT || crlf_action == CRLF_AUTO_CRLF) {
	 */
	err = packet_write_fmt_gently(process->in, "pathname=%s\n", path);
	size_t dst_len;
const char *get_convert_attr_ascii(const struct index_state *istate, const char *path)
done:
	}
			src = dst->buf;
		return CRLF_AUTO;
	CRLF_BINARY,
}
{

#include "pkt-line.h"
		return apply_single_file_filter(path, src, len, fd, dst, cmd);
		return 0;
	}
}
	convert_attrs(istate, &ca, path);
{
		}
#define IDENT_DRAINING (-1)
	 * filtering is not available.
	int err;

	/* Optimization: No CRLF? Nothing to convert, regardless. */

	while (*isize_p || (ident->state == IDENT_DRAINING)) {

		free(drv);
	return ret | ret_filter;
}

				/*

	else if (auto_crlf == AUTO_CRLF_INPUT)
	int fd;
}
	}
		if ((!(conv_flags & CONV_EOL_RENORMALIZE)) &&
	sigchain_pop(SIGPIPE);
	struct stream_filter filter;
	if (!strcmp(filter_status->buf, "error"))
static struct convert_driver {
		err = packet_write_fmt_gently(process->in, "can-delay=1\n");
		return 0;
			new_stats.lonelf += new_stats.crlf;
	else
}
		{ "f", NULL, },
	char ch;
	else if (wanted_capability & CAP_SMUDGE)
		/* feed one from upstream and have it emit into our buffer */
struct ident_filter {
		free(re_src);

				struct cmd2process *entry,

	/* apply % substitution to cmd */
		   const char *path, const char *src, size_t len,
{
		err = error(_("read from external filter '%s' failed"), cmd);
			 * This advice is shown for UTF-??BE and UTF-??LE encodings.
	if (!ident || (src && !count_ident(src, len)))
			(buf[i] > 32 && buf[i] < 127 ? buf[i] : ' '),
		{ "clean",  CAP_CLEAN  },
{
	char *dst, *dollar;
	return cnt;
			struct strbuf *buf, int ident)
	void *data;
}
	}

{
	if (ret) {

	return 0;
		hashmap_init(&subprocess_map, cmd2process_cmp, NULL, 0);
	if (parse_config_key(var, "filter", &name, &namelen, &key) < 0 || !name)
		return 0;
				  NULL, &to_feed,
	count = *isize_p;
	int namelen;
	return apply_filter(path, NULL, 0, -1, NULL, ca.drv, CAP_CLEAN, NULL, NULL);
	int ret = convert_to_working_tree_internal(istate, path, src, len, dst, 1, NULL, NULL);
	if (err)
			next == check_roundtrip_encoding + len || (
{
		error(_("external filter '%s' failed"), entry->subprocess.cmd);
			new_stats.crlf += new_stats.lonelf;
	for (;;) {
	 * However, certain encodings (e.g. SHIFT-JIS) are known to have round
			continue;

	 * trip issues [2]. Check the round trip conversion for all encodings
			goto done;
			else {
} *user_convert, **user_convert_tail;

	dst = buf->buf;
		return CRLF_TEXT;
			cas->ptr += (cas->end - cas->ptr) - to_feed;
	 * listed in core.checkRoundtripEncoding.
				continue;
	int ident;
 * in-core.

	 * Tell the caller that the content was not modified.
	/*
		free((void *)drv->name);
		 * If the file in the index has any CR in it, do not


 * The same heuristics as diff.c::mmfile_is_binary()
	if (skip_iprefix(enc, "UTF", &stripped)) {
		 */
		ca->crlf_action = git_path_check_crlf(ccheck + 0);
	int die_on_error = conv_flags & CONV_WRITE_OBJECT;


static int will_convert_lf_to_crlf(struct text_stat *stats,
				 * current character.
	ca->crlf_action = git_path_check_crlf(ccheck + 4);
				i++;
	return !err;
	sigchain_push(SIGPIPE, SIG_IGN);
struct cascade_filter {
		}
			ident->state++;
	    dco && dco->state == CE_CAN_DELAY) {
{
	if (!strcmp("required", key)) {



};
static struct stream_filter_vtbl cascade_vtbl = {

			/*
			)
{
		}
	}
}
			}
	if (output_eol(crlf_action) != EOL_CRLF)
		return 0;
		else if (c < 32) {
	trace_encoding("destination", path, default_encoding, dst, dst_len);
		/* step 1: run to the next '$' */
			lf_to_crlf->held = '\r';
		else if (ca->crlf_action == CRLF_AUTO && eol_attr == EOL_CRLF)
	 * We may be holding onto the CR to see if it is followed by a

		return 0;
	if (!apply_filter(path, NULL, 0, fd, dst, ca.drv, CAP_CLEAN, NULL, NULL))
		}
	case CRLF_TEXT_INPUT:
		return 0; /* we do not keep any states */
 */
			     struct strbuf *buf, int ident)
	/* No "naked" LF? Nothing to convert, regardless. */
		return EOL_CRLF;
{
	/*
		}
		/* simulate "git add" */
	 *
			was_cr = 0;
	 * CRLF conversion can be skipped if normalizing, unless there

{
				continue;
}

	/* are we "faking" in place editing ? */
			len = dst->len;
	char *dst;
		}
		dst += dollar + 1 - src;
	int write_err, status;
			len -= dollar + 1 - src;
		 * "$Id: ... "; scan up to the closing dollar sign and discard.
				"mark (BOM). Please use UTF-%sBE or UTF-%sLE "
			if (memchr(src + 3, '\n', dollar - src - 3)) {
const char *get_wt_convert_stats_ascii(const char *path)
		       struct strbuf *buf,
	if (!stats->lonelf)
		char *re_src;
	}
			output[o++] = ch;
		err = error(_("external filter '%s' failed"), cmd);
	 *	command-line
					    struct delayed_checkout *dco)
		if (ch == '$')
	struct conv_attrs ca;


			if (ch == '$') {

	case CRLF_AUTO:
					    int normalizing,
{
 */
{
	struct cmd2process *entry;
		if (errno == EPIPE)
		stats->nonprintable--;

	if (strbuf_read(&nbuf, async.out, 0) < 0) {
	convert_attrs(istate, &ca, path);

static int encode_to_worktree(const char *path, const char *src, size_t src_len,
	struct cascade_filter *cas = (struct cascade_filter *) filter;
			len -= 3;
			    int conv_flags)
static void lf_to_crlf_free_fn(struct stream_filter *filter)
				(isspace(next[0]) || next[0] == ',')


		error(_("failed to encode '%s' from %s to %s"),
	/* expand all %f with the quoted path */
		filter = ident_filter(oid);
	struct conv_attrs ca;
	if (close(child_process.in))
	/* We are told to drain */
			case 0:
	 */
static int ident_filter_fn(struct stream_filter *filter,
			if (memchr(src + 3, '\n', dollar - src - 3)) {
		return error(_("cannot fork to run external filter '%s'"),
	struct strbuf sb = STRBUF_INIT;
			char ch = input[i];
}
		} else {
#include "run-command.h"
	/* If file ends with EOF then don't count this EOF as non-printable. */
			}
				const char *input, size_t *isize_p,

		 */
				break;
		return 0;

				  cas->buf, &remaining))
		to_feed = input ? *isize_p : 0;
		else if (eol_attr == EOL_LF)
			if (! (c == '\r' && (1 < len && *src == '\n')))
/*
		if (ca->crlf_action == CRLF_AUTO && eol_attr == EOL_LF)
			if (ch == '$' && !is_foreign_ident(ident->left.buf)) {
	 *

		if (src[2] == '$') {
{
		do {
		else if (eol_attr == EOL_CRLF)
		if (err)

	else if (!strcmp(value, "crlf"))
	const char *crp;
}

static int subprocess_map_initialized;
				"The file '%s' is missing a byte order "
					const char *path,

	}

	dst = reencode_string_len(src, src_len, default_encoding, enc,
				const unsigned int wanted_capability)
	static const char head[] = "$Id";
			die(msg, path, enc, default_encoding);

		ca->crlf_action = text_eol_is_crlf() ? CRLF_TEXT_CRLF : CRLF_TEXT_INPUT;
			int fd, struct strbuf *dst, struct convert_driver *drv,
	struct strbuf cmd = STRBUF_INIT;
	}
		return 0;

		if (nl > src && nl[-1] == '\r') {
	/* These are just approximations! */
			return 0;
}
		));
			 * This is probably not a good idea, since it will cause changes
 *
		len -= dollar + 1 - src;
	unsigned printable, nonprintable;

		remaining = sizeof(cas->buf);
	free(filter);
		return 1;
	if (start_async(&async))
		/* The filter got the blob and wants to send us a response. */
		}
		 * working tree. Let's try to avoid this by screaming loud.
	strbuf_release(&ident->left);

	return CRLF_UNDEFINED;
{
	if (same_encoding(value, default_encoding))

		 */

#include "cache.h"
	 * Unicode aims to be a superset of all other character encodings.
		filter = cascade_filter(filter, &null_filter_singleton);
	user_convert = NULL;
				/* fall through */
	 *
	if (old_stats->crlf && !new_stats->crlf ) {
	if (ATTR_TRUE(value) || ATTR_FALSE(value) || ATTR_UNSET(value))
	if (ATTR_UNSET(value))
				break;

	struct stream_filter *filter = NULL;
int renormalize_buffer(const struct index_state *istate, const char *path,
	if (meta && meta->refname) {
	null_filter_fn,
				stats->crlf++;
#define CONVERT_STAT_BITS_TXT_CRLF  0x2
		    head[ident->state] == ch) {
 *
					     &re_src_len);
	if (ret) {
		;
			continue;
		 * The filter signaled a permanent problem. Don't try to filter
			 */
				ident->state = IDENT_DRAINING;
		if (skip_prefix(line, "pathname=", &path))
	}
	 * the internal UTF-8 representation.
	ret |= encode_to_git(path, src, len, dst, ca.working_tree_encoding, conv_flags);
	if (!strcmp("process", key))
	unsigned long sz;
	if (!input)
	gather_stats(data, size, &stats);
		return text_eol_is_crlf() ? EOL_CRLF : EOL_LF;
		filled = sz - remaining;
			break;
	return (struct stream_filter *)cascade;
		if (will_convert_lf_to_crlf(&new_stats, crlf_action)) {

};
		}
	char *dst;
}
		return two;
			 * in case it is a foreign ident.
			const char *advise_msg = _(
		 * Git process.
		ident->state = IDENT_DRAINING;
static int read_convert_config(const char *var, const char *value, void *cb)
}

	free(filter);
			ca->crlf_action = CRLF_AUTO_INPUT;

		cas->end = sizeof(cas->buf) - remaining;

	}

		size_t i;
static int null_filter_fn(struct stream_filter *filter,
}
	if (err)
	free(to_free);
}
	struct cmd2process *entry = (struct cmd2process *)subprocess;
	if (err)
	else if (!strcmp(value, "auto"))
	}
	}
	if ((entry->supported_capabilities & CAP_DELAY) &&
	if (ca.working_tree_encoding)
			error(msg, path, enc, default_encoding);
			 * returning.
{
			    struct strbuf *buf, enum crlf_action crlf_action)
	err = subprocess_read_status(process->out, &filter_status);
			 * end of check_roundtrip_encoding or
	}
	 */
		src = dst->buf;
 * This should use the pathname to decide on whether it wants to do some
			if (!*osize_p)
			/* fallthrough */
	return has_crlf;
		write_err = 1;
{
 * convert.c - convert a file when checking it out and checking it in.
static int apply_filter(const char *path, const char *src, size_t len,
	 * [1] http://unicode.org/faq/utf_bom.html#gen2
			      int conv_flags)
	return 0;
	for (drv = user_convert; drv; drv = drv->next)
			     const struct checkout_metadata *src,
			}


		for (i = 0; o < *osize_p && i < count; i++) {
		ca->crlf_action = CRLF_AUTO_CRLF;
		strbuf_grow(buf, len - buf->len);
		default:
		dollar = memchr(src, '$', len);
}

			int stripped_len = strlen(stripped) - strlen("BE");
	return convert_to_working_tree_internal(istate, path, src, len, dst, 0, meta, NULL);
	return (found && (

	char *dst;
	struct async async;
		check = attr_check_initl("crlf", "ident", "filter",
		return EOL_CRLF;
		  const char *input, size_t *isize_p,
static void cascade_free_fn(struct stream_filter *filter)
			      struct strbuf *buf, const char *enc)
			die(_("LF would be replaced by CRLF in %s"), path);
{
		cmd = drv->clean;

	struct subprocess_entry subprocess; /* must be the first member! */
		cmd = drv->smudge;
			     const struct object_id *blob)
			goto done;
	for (i = 0; i < len && buf; ++i) {
		 * cherry-pick.
		*isize_p -= i;

		return "-text";

void clone_checkout_metadata(struct checkout_metadata *dst,
		handle_filter_error(&filter_status, entry, 0);
	fflush(NULL);
}
		if (len > 3 && !memcmp(src, "Id:", 3)) {
				continue;
			    const struct object_id *blob)
			new_stats.crlf = 0;
	if (lf_to_crlf->has_held && (lf_to_crlf->held != '\r' || !input)) {
static int cascade_filter_fn(struct stream_filter *filter,
		if (err)
	if (!enc || (src && !src_len))
	const char *filter_type;

		/*
	return "";
	ca->drv = git_path_check_convert(ccheck + 2);
	}

				ident->state = 0;
		}

		if (has_prohibited_utf_bom(enc, data, len)) {

		goto done;
		} else {

static struct stream_filter null_filter_singleton = {
					     enc, default_encoding,
		return "mixed";
		return "lf";
	}
	cascade = xmalloc(sizeof(*cascade));

	else if (drv->process && *drv->process)
			 * in which case we need to break out of this
		return NULL;
			free(entry);
	err = subprocess_read_status(process->out, &filter_status);

	}
	struct child_process child_process = CHILD_PROCESS_INIT;
		goto done;
		error(_("external filter '%s' is not available anymore although "
					    const struct checkout_metadata *meta,
{
	 */

	 * generate a faulty round trip without an iconv error. Iconv errors
		err = packet_write_fmt_gently(process->in, "ref=%s\n", meta->refname);
	if (!check) {

		; /* The filter signaled a problem with the file. */
		unsigned char c = buf[i];
		}
static int ident_to_worktree(const char *src, size_t len,
			     params->cmd);
			 * beginning of check_roundtrip_encoding or
		 * We could add the blob "as-is" to Git. However, on checkout
static struct stream_filter_vtbl null_vtbl = {
}
		if (err)
	const char *value = check->value;
	unsigned long i;
		return apply_multi_file_filter(path, src, len, fd, dst,
	return 0;
		if (stream_filter(cas->one,
			/*
static int convert_is_binary(const struct text_stat *stats)
{
		return 0;
		return "crlf";
	};

	}
			 * on checkout, which won't go away by stash, but let's keep it
		next = drv->next;
	if (!strcmp("smudge", key))
		string_list_insert(&dco->filters, cmd);
	/* are we "faking" in place editing ? */
			len -= dollar + 1 - src;
}
		error(_("cannot feed the input to external filter '%s'"),
		return EOL_LF;
#include "config.h"
	if (!skip_prefix(str, "$Id: ", &str))
{
	 */
	if (!subprocess_map_initialized) {
	if (ca->crlf_action == CRLF_UNDEFINED && auto_crlf == AUTO_CRLF_FALSE)

	if (!input) {
	const char *argv[] = { NULL, NULL };
		return 1;
		return 1;
	case CRLF_AUTO:


		err = error(_("read from external filter '%s' failed"), cmd);
	assert(strlen(filter_type) < LARGE_PACKET_DATA_MAX - strlen("command=\n"));
				  "The file will have its original line"
};
		oidcpy(&meta->treeish, treeish);
/*****************************************************************
				continue;

		if (subprocess_start(&subprocess_map, &entry->subprocess, cmd, start_multi_file_filter_fn)) {
}
		err = write_packetized_from_buf(src, len, process->in);
		ret |= CONVERT_STAT_BITS_BIN;
	/*
	warning(_("illegal crlf_action %d"), (int)crlf_action);
		if (!(ret_stats & CONVERT_STAT_BITS_BIN) &&
{
	sigchain_pop(SIGPIPE);
 * We treat files with bare CR as binary
		return 0;
				  input, &to_feed,
		if (!strncmp(drv->name, name, namelen) && !drv->name[namelen])
	hash_object_file(the_hash_algo, src, len, "blob", &oid);
	/* Don't encode to the default encoding */
	*osize_p -= filled;
	filter_fn filter;
		return EOL_CRLF;
	if ((wanted_capability & CAP_CLEAN) && !drv->process && drv->clean)
			      const char *path, int fd, struct strbuf *dst,
			src += 3;
	if (meta && !is_null_oid(&meta->blob)) {
	if (!err) {
	return filter->vtbl->filter(filter, input, isize_p, output, osize_p);
	params.cmd = cmd;

		strbuf_release(&cmd);
	sq_quote_buf(&path, params->path);
			goto done;
	else if ((wanted_capability & CAP_SMUDGE) && !drv->process && drv->smudge)
	if (!buf && !src)
	case CRLF_TEXT:

			warning(_("LF will be replaced by CRLF in %s.\n"
		process->in, "command=list_available_blobs\n");

	if (start_command(&child_process)) {
	 * the content. Let's answer with "yes", since an encoding was
	return 0;
			ident->state = IDENT_DRAINING;
 */
{
{
				"mark (BOM). Please use UTF-%.*s as "
	if (err)
	for (;;) {
{
		return "text eol=crlf";
		{ NULL, NULL, },
}

				(isspace(found[-1]) || found[-1] == ',')
	if (crlf_action == CRLF_BINARY ||
	struct ident_filter *ident = (struct ident_filter *)filter;
	 * Please note, the code below is not tested because I was not able to
	 */
				    capabilities,

		while (size) {
	convert_attrs(istate, &ca, path);
}

static int ident_to_git(const char *src, size_t len,
			return drv;
	int len;
			write_err = 0;
			continue;
	/*

				  const char *path, const char *src,

		 * Check for detectable errors in UTF encodings
		if (len < 3 || memcmp("Id", src, 2))
		ret |=  CONVERT_STAT_BITS_TXT_LF;
	struct strbuf_expand_dict_entry dict[] = {

	if (core_eol == EOL_UNSET && EOL_NATIVE == EOL_CRLF)
			strbuf_addch(&ident->left, ch);
	if (!data)
	 * nothing to analyze; we must assume we would convert.
	const char *value = check->value;

struct lf_to_crlf_filter {
	}

	git_check_attr(istate, path, check);
		die(_("%s: clean filter '%s' failed"), path, ca.drv->name);
		ret |= crlf_to_worktree(src, len, dst, ca.crlf_action);
	/*
			/* fallthrough */

	for (drv = user_convert; drv; drv = drv->next)
typedef int (*filter_fn)(struct stream_filter *,
		can_delay = 1;
		 */
	for (;;) {
		if (ch != '$')

	if (!buf)
int convert_to_git(const struct index_state *istate,
		 */

	/*
	}



	unsigned int supported_capabilities;
				continue;
			if (*osize_p <= o) {
			}
			dollar = memchr(src + 3, '$', len - 3);
{

			continue;
	 *
		to_drain = *osize_p;
			 * It's possible that an expanded Id has crept its way into the
	memset(meta, 0, sizeof(*meta));
static int validate_encoding(const char *path, const char *enc,
	if (close(async.out)) {
	 */
	/* We only check for UTF here as UTF?? can be an alias for UTF-?? */
		return "-text";
		 * we would try to re-encode to the original encoding. This
			size_t fed = *isize_p - to_feed;
{
	int i;

	struct text_stat stats;
	 * This means Git wants to know if it would encode (= modify!)
#define CONVERT_STAT_BITS_BIN       0x4
			break;
	if (convert_stats & CONVERT_STAT_BITS_BIN)
	 * LF, in which case we would need to go to the main loop.

	return (struct stream_filter *)lf_to_crlf;

}
	if (count || lf_to_crlf->has_held) {
{
				stats->nonprintable++;

			 * We may have consumed the last output slot,
				was_cr = 1;
static int apply_single_file_filter(const char *path, const char *src, size_t len, int fd,
	 */
				  void *dco)
		return "text";
	ca->working_tree_encoding = git_path_check_encoding(ccheck + 5);
	return value;
	if ((ca.drv && (ca.drv->smudge || ca.drv->process)) || !normalizing) {
			ca->crlf_action = CRLF_AUTO_CRLF;
};

{
/*
		else
		       const char *path, const char *src, size_t len,
		error(_("path name too long for external filter"));
		unsigned int ret_stats;
			continue;
static void null_free_fn(struct stream_filter *filter)
 */
		len = dst->len;
}
			continue;
	async.proc = filter_buffer_or_fd;
		err = packet_write_fmt_gently(process->in, "blob=%s\n", oid_to_hex(&meta->blob));
	if (err)
	const char *smudge;
		goto done;

	struct strbuf nbuf = STRBUF_INIT;
 */
{
		handle_filter_error(&filter_status, entry, wanted_capability);
void init_checkout_metadata(struct checkout_metadata *meta, const char *refname,

	lf_to_crlf_filter_fn,
	 */
				strbuf_addch(&ident->left, ch);
	strbuf_addchars(&trace, '\n', 1);
	}

		ret_stats = gather_convert_stats(data, sz);
		do {

		return 0;
			}

}
		if (c == '\r') {

/*
{
}
	if (can_delay && !strcmp(filter_status.buf, "delayed")) {
	struct lf_to_crlf_filter *lf_to_crlf = xcalloc(1, sizeof(*lf_to_crlf));
	}
	gather_stats(src, len, &stats);

				    struct strbuf *dst, const char *cmd)
		return 0;
	if (!entry) {
	}
		trace_encoding("reencoded source", path, enc,
static int filter_buffer_or_fd(int in, int out, void *data)
		 * follow it.
	struct stream_filter filter;
	for (i = 0; i < size; i++) {
		if (cas->ptr < cas->end) {
}
			strbuf_add(&ident->left, head, ident->state);
	return (write_err || status);


			advise(advise_msg, path, stripped, stripped);
	if (stats->lonecr)
	case CONVERT_STAT_BITS_TXT_LF:
	argv[0] = cmd.buf;
		if (ret) {
			     const char *input, size_t *isize_p,
				 */
	convert_crlf_into_lf = !!stats.crlf;
		size_t re_src_len;
	free_stream_filter(cas->two);
{
	if (!drv) {
}

/* Stat bits: When BIN is set, the txt bits are unset */
		size -= 3;
	else if (ATTR_FALSE(value))
		}
	cascade->filter.vtbl = &cascade_vtbl;
	if (convert_is_binary(&stats))
			unsigned char c = *src++;
static struct stream_filter *ident_filter(const struct object_id *oid)
			 * We cut off the last two characters of the encoding name
	return 0;
	cascade->end = cascade->ptr = 0;
	 * If we are doing a dry-run and have no source buffer, there is
		count = *osize_p;
	struct conv_attrs ca;
	const char *cmd;
{
	 * "filter.<name>.variable".
			if (die_on_error)
	if (stats.lonelf)
					  cas->buf + cas->ptr, &to_feed,
		write_err = (write_in_full(child_process.in,
	if (err)
	if (err)
	 * Spawn cmd and feed the buffer contents through its stdin.
		len -= nl + 1 - src;
			if (!dollar)
		return 0;

		strbuf_addf(
	const char *clean;
	struct stream_filter *two;
			return -1;
	} else {
		if (ident->state == IDENT_SKIPPING) {
				  " endings in your working directory"), path);
	case CRLF_TEXT_CRLF:
		memmove(output, input, count);

		return 0;
	if (!two || is_null_stream_filter(two))
		*osize_p -= o;
	 * No encoding is specified or there is nothing to encode.

	const char *name;
	if (err)
		return 1;
		*isize_p -= count;
		return 1;
	}
		int ch;
#define FILTER_BUFFER 1024
			if (i+1 < size && buf[i+1] == '\n') {
	crlf_to_git(istate, path, dst->buf, dst->len, dst, ca.crlf_action, conv_flags);

				 * This is probably an id from some other
		/* simulate "git checkout" */

		if (convert_crlf_into_lf) {
int convert_to_working_tree(const struct index_state *istate,
		ret = gather_convert_stats_ascii(sb.buf, sb.len);

	struct ident_filter *ident = xmalloc(sizeof(*ident));
	if (die_on_error && check_roundtrip(enc)) {
			const struct checkout_metadata *meta,
			 const char *input, size_t *isize_p,
		return "text=auto eol=lf";

			drv->process, wanted_capability, meta, dco);
		ch = *(input++);
	if (crp) {
	if (!ret_filter && ca.drv && ca.drv->required)
		strbuf_grow(buf, len - buf->len);
	while ((line = packet_read_line(process->out, NULL))) {
	char *to_free = NULL;
	if (write_err)
	size_t to_feed, remaining;
#include "sigchain.h"
void convert_to_git_filter_fd(const struct index_state *istate,
	 * the command line:

	 */
			/*
	err = strcmp(filter_status.buf, "success");
		user_convert_tail = &(drv->next);
 * conversions etc etc), but by default it just does automatic CRLF<->LF
}
		 */
				"BOM is prohibited in '%s' if encoded as %s");
		 * would fail and we would leave the user with a messed-up
			  char *output, size_t *osize_p)
				"The file '%s' contains a byte order "
	if (output_eol(ca.crlf_action) == EOL_CRLF)
	const char *ret;
 * LF-to-CRLF filter

				"working-tree-encoding.");
		{ NULL, 0 }

				  " endings in your working directory"), path);
		 */
			const char *error_msg = _(
		*user_convert_tail = drv;
	}
	dict[0].value = path.buf;

					   const char *path)
	 * External conversion drivers are configured using
	strbuf_release(&path);
			lf_to_crlf->has_held = 1;
		}
			continue;
	}
			}
			}
	struct conv_attrs ca;
			if (ch == ':') {
 *
			new_stats.lonelf = 0;
		drv->required = git_config_bool(var, value);
		}
		}
	const char *working_tree_encoding; /* Supported encoding or default encoding if NULL */
	lf_to_crlf->filter.vtbl = &lf_to_crlf_vtbl;
	cascade_free_fn,
	 * The command-line will not be interpolated in any way.
			const char *advise_msg = _(
			/*
{

		}

	crp = memchr(data, '\r', sz);
	if (auto_crlf == AUTO_CRLF_TRUE)
	free(data);
{
				continue; /* break but increment i */
}
}
		);
				stats->lonecr++;
		}
		to_free = strbuf_detach(buf, NULL);
	}
	 * UTF supports lossless conversion round tripping [1] and conversions
	strbuf_init(&ident->left, 0);
	}
			len = dst->len;
		if (ident->state == sizeof(head) - 1) {
			continue;
		*osize_p -= o;
static struct hashmap subprocess_map;
	if (!ident->left.len)
	free(data);
		return 0;
	 * Search for the given encoding in that string.
				lf_to_crlf->has_held = 1;
static void gather_stats(const char *buf, unsigned long size, struct text_stat *stats)
			src = dst->buf;

	free_fn free;
		       enum crlf_action crlf_action, int conv_flags)
		(*isize_p)--;
	}
	else if (!strcmp(value, "lf"))
		}
	struct child_process *process;

static int crlf_to_worktree(const char *src, size_t len,
	if (cmd && *cmd)
	strbuf_release(&nbuf);
	ident->filter.vtbl = &ident_vtbl;
}
	strbuf_setlen(buf, dst + len - buf->buf);

			} else {
			if (ch != '\n' && ch != '$')

	/*
	     ((conv_flags & CONV_EOL_RNDTRP_DIE) && len))) {

			size--;

	size_t count, o = 0;
			input += fed;
	for (i = 0; str[i]; i++) {

	 * check_roundtrip_encoding contains a string of comma and/or
{
	return !err;

	int end, ptr;

	} else {

static unsigned int gather_convert_stats(const char *data, unsigned long size)
	ca->ident = git_path_check_ident(ccheck + 1);
	char *line;
	char ident[GIT_MAX_HEXSZ + 5]; /* ": x40 $" */
	count = *isize_p;
	assert(subprocess_map_initialized);

			    const char *path, const char *src,
	int required;

		int was_cr = 0;
	 * is a smudge or process filter (even if the process filter doesn't
	sigchain_push(SIGPIPE, SIG_IGN);
	switch (ca.attr_action) {
	return 1;
	dst = reencode_string_len(src, src_len, enc, default_encoding,

	cnt = count_ident(src, len);
	int cnt;
			continue;

		return EOL_LF;
	int has_crlf = 0;
				   int fd, struct strbuf *dst, const char *cmd,
{
	}
	 * No encoding is specified or there is nothing to encode.
			 * check that the found encoding is at the
				break;
		}
		return 0;
		return 0;
{
		if (!re_src || src_len != re_src_len ||
			strbuf_add(buf, src, nl + 1 - src);
	if (err)
	ca->attr_action = ca->crlf_action;
	&null_vtbl,
		return 0;
	size_t dst_len;
/*
	if (src == buf->buf)
	 * Looks like we got called from "would_convert_to_git()".
	child_process.use_shell = 1;

/*
	return 1;
	 */

	static struct trace_key coe = TRACE_KEY_INIT(WORKING_TREE_ENCODING);
		 * convert.  This is the new safer autocrlf handling,


static int encode_to_git(const char *path, const char *src, size_t src_len,
		filter_type = "clean";
	CRLF_TEXT_CRLF,

	case CONVERT_STAT_BITS_TXT_CRLF:

		struct text_stat new_stats;
		}
		if (err)
		check_global_conv_flags_eol(path, crlf_action, &stats, &new_stats, conv_flags);

};
		user_convert_tail = &user_convert;
	 * (child --> cmd) --> us
				 * by a LF; emit the CR before processing the
		return "text=auto";
	int convert_crlf_into_lf;
		err = read_packetized_to_strbuf(process->out, &nbuf) < 0;
	return (struct stream_filter *)ident;
		}
	 * Apply a filter to an fd only if the filter is required to succeed.
	CRLF_TEXT,

			if (c != '\r')
			stats->printable++;
	const char *stripped;
}
	if (!(conv_flags & CONV_EOL_KEEP_CRLF)) {

		return 1;
			string_list_insert(available_paths, xstrdup(path));

	assert(ca.drv->clean || ca.drv->process);

	}


					   params->src, params->size) < 0);
		die(_("%s: smudge filter %s failed"), path, ca.drv->name);
		filter = cascade_filter(filter, lf_to_crlf_filter());
	if (((conv_flags & CONV_EOL_RNDTRP_WARN) ||
{

				"working-tree-encoding.");
		write_err = copy_fd(params->fd, child_process.in);
	free(to_free);
	ccheck = check->items;
	struct child_process *process;
		oidcpy(&meta->blob, blob);
			dst += 3;
}

			 */
	 */
	struct convert_driver *drv, *next;
		drv = xcalloc(1, sizeof(struct convert_driver));

	if (size >= 1 && buf[size-1] == '\032')
			/*
	/*
enum crlf_action {
	return ret;
	static int versions[] = {2, 0};
 *****************************************************************/
	} else if (old_stats->lonelf && !new_stats->lonelf ) {
	/*
	if (*osize_p < to_drain)
	const char *path;

		strbuf_swap(dst, &nbuf);
struct text_stat {
		if (ident->state == IDENT_DRAINING) {
	status = finish_command(&child_process);
		if (!dollar)
			*isize_p -= fed;

		return 0;	/* error was already reported */

 * Note that you would be crazy to set CRLF, smudge/clean or ident to a
			 * check that the found encoding is at the

		subprocess_map_initialized = 1;
	 * space separated encodings (eg. "UTF-16, ASCII, CP1125").
				  const struct checkout_metadata *meta,
	xsnprintf(ident->ident, sizeof(ident->ident),
		src  = nl + 1;
			continue;
		/* tell two to drain; we have nothing more to give it */
	return EOL_UNSET;
		drv->name = xmemdupz(name, namelen);
			       re_src, re_src_len);
	return !!ATTR_TRUE(value);
	struct filter_params params;
	err = packet_write_fmt_gently(
	}
}
		filter_type = "smudge";
	/*
static void check_global_conv_flags_eol(const char *path, enum crlf_action crlf_action,
	const char *cmd = NULL;

		err = subprocess_read_status(process->out, &filter_status);
	}
		if (!lf_to_crlf->has_held && was_cr) {
{
				return error(error_msg, path, enc);
		size--;
		} else if (src[2] == ':') {
static void trace_encoding(const char *context, const char *path,
			break;

			if (die_on_error)

		else if (conv_flags & CONV_EOL_RNDTRP_WARN)

	if (wanted_capability & CAP_CLEAN)
{



	}
			 */
	}
	unsigned long size;
		if (!dollar)
	return convert_to_working_tree_internal(istate, path, src, len, dst, 0, meta, dco);
	async.out = -1;
		to_free = strbuf_detach(buf, NULL);
	ret_filter = apply_filter(
		error(_("external filter '%s' failed %d"), params->cmd, status);
	size_t filled = 0;
	len = strlen(check_roundtrip_encoding);
				/* Line break before the next dollar. */
			  struct conv_attrs *ca, const char *path)
			src  = dollar + 1;
			return 0;
	/*
		if (convert_is_binary(stats))
			ch = *cp++;
	if (ca->crlf_action == CRLF_TEXT)
	return 1;

			   const char *input, size_t *isize_p,

	ident_to_git(dst->buf, dst->len, dst, ca.ident);
			continue;
					 "eol", "text", "working-tree-encoding",

		if (size < 3)
	strbuf_release(&trace);
}
	}
	}
			goto done;
				"BOM is required in '%s' if encoded as %s");
			(unsigned char) buf[i],
struct stream_filter_vtbl {

	if (strbuf_avail(buf) + buf->len < len)
			goto done;
{
				strbuf_setlen(&ident->left, sizeof(head) - 1);
					 NULL);

	if (core_eol == EOL_CRLF)
	struct convert_driver *drv;
			has_crlf = 1;
	case CRLF_TEXT:

	struct lf_to_crlf_filter *lf_to_crlf = (struct lf_to_crlf_filter *)filter;
}

		case IDENT_SKIPPING:
		lf_to_crlf->has_held = 0;
		return 1;
	if (!dst)
		return "none";
		return 0;
	struct convert_driver *drv;
		) && (
		return EOL_UNSET;
		 */


	return ret | ident_to_git(src, len, dst, ca.ident);
			 struct strbuf *buf, const char *enc, int conv_flags)
		cp += 3;
struct conv_attrs {
	return ret | convert_to_git(istate, path, src, len, dst, CONV_EOL_RENORMALIZE);
	int cnt = 0;
			if (ch == '\n')
			 * to generate the encoding name suitable for BOMs.
			return 1;
static struct stream_filter_vtbl ident_vtbl = {
			const char* msg = _("encoding '%s' from %s to %s and "
	 */
		if (!strcmp(value, drv->name))
		else if (conv_flags & CONV_EOL_RNDTRP_WARN)
				/* BS, HT, ESC and FF */
			if (ch != ':' && ch != '$') {
		src = dst->buf;
		strbuf_swap(dst, &nbuf);
	child_process.argv = argv;

			warning(_("CRLF will be replaced by LF in %s.\n"
			}
	memmove(dst, src, len);
			return 0;

	}
		return "text eol=lf";
{
#include "ll-merge.h"
			continue;
		if (stats->lonecr || stats->crlf)

	if (ATTR_UNSET(value) || !strlen(value))

			if (ch == '\r') {
		 * lone CR, and we can strip a CR without looking at what
}
	else if (!strcmp(filter_status->buf, "abort") && wanted_capability) {
	CRLF_UNDEFINED,
		goto done;
	 * specified.

			/* DEL */
static struct stream_filter *lf_to_crlf_filter(void)
		enum eol eol_attr = git_path_check_eol(ccheck + 3);
				next < check_roundtrip_encoding + len &&

	return core_eol;
	memset(&async, 0, sizeof(async));
			break;

	params.fd = fd;
		/* fall through */
#include "quote.h"
	strbuf_release(&sb);
int async_convert_to_working_tree(const struct index_state *istate,
	process = &entry->subprocess.process;
		len = dst->len;

{
	lf_to_crlf_free_fn,
				char *output, size_t *osize_p)
		return CRLF_BINARY;
			const unsigned int wanted_capability,
	if (ca->crlf_action == CRLF_UNDEFINED && auto_crlf == AUTO_CRLF_TRUE)
static void ident_drain(struct ident_filter *ident, char **output_p, size_t *osize_p)
	if (!enc || (src && !src_len))

	if (fd >= 0)
	/*

		}
}
	struct conv_attrs ca;
static enum crlf_action git_path_check_crlf(struct attr_check_item *check)
	struct stream_filter filter;
static int convert_to_working_tree_internal(const struct index_state *istate,
static void convert_attrs(const struct index_state *istate,
}
				output[o++] = '\r';
		if (input || cas->end)
};
static int text_eol_is_crlf(void)
		if (stream_filter(cas->two,
	if (validate_encoding(path, enc, src, src_len, die_on_error))
#include "attr.h"
		ca->crlf_action = CRLF_AUTO_INPUT;
	free(filter);
	ret |= encode_to_worktree(path, src, len, dst, ca.working_tree_encoding);
		remaining = sz - filled;
		ret |= crlf_to_git(istate, path, src, len, dst, ca.crlf_action, conv_flags);


		else {
	strbuf_expand(&cmd, params->cmd, strbuf_expand_dict_cb, &dict);
			/* it wasn't a "Id$" or "Id:xxxx$" */
		if (input && !to_feed)
	/* Save attr and make a decision for action */
	}
done:
	/*
int is_null_stream_filter(struct stream_filter *filter)
			struct delayed_checkout *dco)
#define CAP_DELAY    (1u<<2)
{
	struct convert_driver *drv;
			break;
	struct strbuf left;
	params.src = src;
			break; /* completely drained two */
	err = packet_flush_gently(process->in);
		return EOL_LF;

	return 1;
	int ret = 0, ret_filter = 0;
}
	filter->vtbl->free(filter);
	int ret = 0;
		ca->crlf_action = CRLF_BINARY;
		len = dst->len;
				 */
			ident_drain(ident, &output, osize_p);
		 */
	ret |= ident_to_worktree(src, len, dst, ca.ident);

}
		if (remaining == (sz - filled))

		output[o++] = lf_to_crlf->held;
}
	const char *value = check->value;
			goto done;
{
	struct ident_filter *ident = (struct ident_filter *)filter;
	/*
{
static int git_path_check_ident(struct attr_check_item *check)
	return filter;
{
	 */
		;
		free(entry);
		if (conv_flags & CONV_EOL_RNDTRP_DIE)
	if (!(entry->supported_capabilities & wanted_capability))
};
}
				 * versioning system. Keep it for now.
	user_convert_tail = NULL;

					    const char *path, const char *src,
	params.path = path;
struct stream_filter *get_stream_filter(const struct index_state *istate,

		} while (--len);

		if (memcmp("Id", cp, 2))
	if (strbuf_read_file(&sb, path, 0) >= 0)
				/* There are spaces in unexpected places.
	 * At this point all of our source analysis is done, and we are sure we

		oidcpy(&dst->blob, blob);
		die(_("unexpected filter type"));
		git_config(read_convert_config, NULL);
static int crlf_to_git(const struct index_state *istate,
	for (drv = user_convert; drv; drv = next) {
}
	struct text_stat stats;
			const char *error_msg = _(
		      const char *data, size_t len, int die_on_error)


			 char *output, size_t *osize_p);
int async_query_available_blobs(const char *cmd, struct string_list *available_paths)
	 * The round trip check is only performed if content is written to Git.
			i,
	 * We must die if the filter fails, because the original data before
		strbuf_addstr(buf, "Id: ");
				return error(error_msg, path, enc);
	int i;
	if (ca->crlf_action == CRLF_UNDEFINED)
				/* Line break before the next dollar. */


	if (!data || !size)
};
		/*
const char *get_cached_convert_stats_ascii(const struct index_state *istate,
	}
	strbuf_add(buf, src, len);
	switch (crlf_action) {
	}
		return 1;
				*dst++ = c;

	}
		return 0;
	unsigned long sz;

	 * are already caught above.
	/* quote the path to preserve spaces, etc. */
}
	static struct subprocess_capability capabilities[] = {
			 * loop; hold the current character before
			dollar = memchr(src + 3, '$', len - 3);

			ident_drain(ident, &output, osize_p);
			cnt++; /* $Id$ */
}
	strbuf_add(buf, src, len);
	}
static enum eol git_path_check_eol(struct attr_check_item *check)
				break;
		die(_("true/false are no valid working-tree-encodings"));
#define CAP_SMUDGE   (1u<<1)
		switch (ident->state) {
		trace_printf("Checking roundtrip encoding for %s...\n", enc);
			/*
				  size_t len, struct strbuf *dst,
	sigchain_push(SIGPIPE, SIG_IGN);
				break;
		err = strcmp(filter_status.buf, "success");
static struct convert_driver *git_path_check_convert(struct attr_check_item *check)
	attr_check_free(check);
			memcpy(dst, "Id$", 3);
#define IDENT_SKIPPING (-2)

	const char *found = strcasestr(check_roundtrip_encoding, enc_name);
	 *

static int is_foreign_ident(const char *str)
	struct object_id oid;
		strbuf_add(buf, src, dollar + 1 - src);
	case CRLF_AUTO_CRLF:
	char *to_free = NULL, *dollar, *spc;
		/*
	if (!one || is_null_stream_filter(one))
		return 1;
		src  = dollar + 1;
		return 0;
};
	if (!strcmp("clean", key))
		if (ident->state < sizeof(head) &&

		}
 * large binary blob you would want us not to slurp into the memory!
static struct stream_filter *cascade_filter(struct stream_filter *one,
	if (ca->crlf_action == CRLF_UNDEFINED && auto_crlf == AUTO_CRLF_INPUT)
#include "utf8.h"
};
	unsigned int convert_stats = gather_convert_stats(data, size);
		len = dst->len;

	struct stream_filter_vtbl *vtbl;
{
	struct strbuf path = STRBUF_INIT;
}
			 */
	return 0;
		return NULL;
}

struct filter_params {
	switch (convert_stats) {

			convert_crlf_into_lf = 0;
	}

	if (to_drain) {
	    (src && !len))
	if (!dst) {
					const struct object_id *oid)
	 * input -- (one) --> buf -- (two) --> output
static void ident_free_fn(struct stream_filter *filter)
				   const unsigned int wanted_capability,
		ret |= CONVERT_STAT_BITS_TXT_CRLF;
}
	if (!convert_crlf_into_lf)

			die(msg, path, enc, default_encoding);
	ident_filter_fn,
 */
	if (!ca.drv)
 * translation when the "text" attribute or "auto_crlf" option is set.
			)

	CRLF_AUTO_INPUT,

			if (spc && spc < dollar-1) {
	assert(ca.drv);
	if (err) {
		return 0;
	const char *next;
	if (treeish)

		path, src, len, -1, dst, ca.drv, CAP_SMUDGE, meta, dco);
				return -1;
	}
	}
			if (ch == '\n') {
	return subprocess_handshake(subprocess, "git-filter", versions, NULL,
	err = strlen(path) > LARGE_PACKET_DATA_MAX - strlen("pathname=\n");
		goto done;
	 */
		} else if (is_missing_required_utf_bom(enc, data, len)) {

		memcpy(&new_stats, &stats, sizeof(new_stats));

	const char *value = check->value;
			((i+1) % 8 && (i+1) < len ? ' ' : '\n')
	ret = gather_convert_stats_ascii(data, sz);
	if (blob)
		/* do we know that we drained one completely? */
		return CRLF_TEXT_INPUT;
		if (ret && dst) {
	null_free_fn,
		{ "delay",  CAP_DELAY  },
}
		entry = NULL;
void free_stream_filter(struct stream_filter *filter)
		return "";
	if (!ca.drv->required)
				strbuf_addstr(&ident->left, ident->ident);
		return one;
}

#define CAP_CLEAN    (1u<<0)
	struct strbuf filter_status = STRBUF_INIT;
	return 1;

		return 0;
	if (!ret && ca.drv && ca.drv->required)
#include "object-store.h"
		re_src = reencode_string_len(dst, dst_len,
{
		/* do we already have something to feed two with? */
	if (meta && !is_null_oid(&meta->treeish)) {
			 */
	else if (!strcmp(value, "input"))
	if (stats.crlf)
		entry = (struct cmd2process *)subprocess_find_entry(&subprocess_map, cmd);
			break;
			}
	return 0;
		 * CRLFs would not be restored by checkout
	strbuf_release(&nbuf);
	if (ca.drv && (ca.drv->process || ca.drv->smudge || ca.drv->clean))
	/* only grow if not in place */

				    &entry->supported_capabilities);
		dollar = memchr(src, '$', len);
	if (!len || output_eol(crlf_action) != EOL_CRLF)
			return 0;
	strbuf_attach(buf, dst, dst_len, dst_len + 1);
	strbuf_grow(buf, len + cnt * (the_hash_algo->hexsz + 3));
	 * [2] https://support.microsoft.com/en-us/help/170559/prb-conversion-problem-between-shift-jis-and-unicode
	if (!found)
{
		   struct strbuf *dst, int conv_flags)
	struct conv_attrs ca;
	size_t sz = *osize_p;
	free_stream_filter(cas->one);
			strbuf_addstr(buf, "\r\n");
	/* only grow if not in place */
 * Cascade filter

	if (!will_convert_lf_to_crlf(&stats, crlf_action))
		ch = cp[2];
				output[o++] = '\r';
	memcpy(dst, src, sizeof(*dst));
	if (ret && dst) {

				*dst++ = c;
		/* step 2: does it looks like a bit like Id:xxx$ or Id$ ? */
	case CRLF_AUTO_INPUT:
	if (!buf)
			 * that it is prefixed with a space or comma
	 * between UTF and other encodings are mostly round trip safe as
	strbuf_release(&cmd);
			strbuf_add(&ident->left, head, ident->state);
		entry = xmalloc(sizeof(*entry));
	if (ca->crlf_action != CRLF_BINARY) {
		}

		/*
	convert_attrs(istate, &ca, path);
		return NULL;
	if (!input) {
				break;

		if (ident->state)
}
		/* drain upon eof */
	CRLF_AUTO_CRLF
}
static int has_crlf_in_index(const struct index_state *istate, const char *path)

		if (conv_flags & CONV_EOL_RNDTRP_DIE)
			    const struct checkout_metadata *meta)
			stats->nonprintable++;

{
{
	}
	trace_strbuf(&coe, &trace);
	if (err)
static enum eol output_eol(enum crlf_action crlf_action)
			write_err = 0;
		cas->ptr = 0;

	} else {
		goto done;
	ident->state = 0;
 * ident filter
	err = packet_write_fmt_gently(process->in, "command=%s\n", filter_type);
	dst = buf->buf;
	while (size) {
	case CRLF_TEXT_INPUT:
		if (c == 127)
					  output + filled, &remaining))
			}
		      params->cmd);
	if (ret) {

 * Return an appropriately constructed filter for the path, or NULL if
static int check_roundtrip(const char *enc_name)
static struct stream_filter_vtbl lf_to_crlf_vtbl = {
}

int stream_filter(struct stream_filter *filter,
#include "sub-process.h"
	struct stream_filter *one;
		/* This is the new safer autocrlf-handling */
		       const char *src, size_t len, struct strbuf *dst)
};


			 * for git-style ids.
		len -= dollar + 1 - src;
		if (write_err == COPY_WRITE_ERROR && errno == EPIPE)
	if (*osize_p < count)
	unsigned nul, lonecr, lonelf, crlf;
	return 1;
			case '\b': case '\t': case '\033': case '\014':

		 * Something went wrong with the protocol filter.
			found == check_roundtrip_encoding || (
}
	return filter == &null_filter_singleton;
	else if (ATTR_UNSET(value))
	}
			}
		to_feed = 0;
	cascade->two = two;
	char held;

	return 0;
				continue;

	entry = (struct cmd2process *)subprocess_find_entry(&subprocess_map, cmd);

	check = NULL;

		remaining = sz - filled;
	const char *process;
	child_process.out = out;
			to_feed = cas->end - cas->ptr;
		    has_crlf_in_index(istate, path))
		if (err)
	const char *src;
	size_t count;

			switch (c) {

	struct filter_params *params = (struct filter_params *)data;
		if (isspace(str[i]) && str[i+1] != '$')
	memset(stats, 0, sizeof(*stats));
	void *data = read_blob_data_from_index(istate, path, &sz);
	int can_delay = 0;
		 * CRLFs would be added by checkout
		if (lf_to_crlf->has_held) {
		subprocess_stop(&subprocess_map, &entry->subprocess);
	ident_free_fn,
	}


	else
		  char *output, size_t *osize_p)
					    struct stream_filter *two)
			continue;
		if (err)
	};
	enum crlf_action attr_action; /* What attr says */
		 * files with the same command for the lifetime of the current
