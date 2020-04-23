				struct strbuf *gpg_output,
{
void print_signature_buffer(const struct signature_check *sigc, unsigned flags)
	if (!temp)
{
{

	if (ret)
					 * GPG v1 and v2 differs in how the
	  .verify_args = openpgp_verify_args,
	return 0;
	const char *program;
	"-----BEGIN SIGNED MESSAGE-----",
	{ 'R', "REVKEYSIG ", GPG_STATUS_STDSIG },
				 */
	FREE_AND_NULL(sigc->signer);
	FREE_AND_NULL(sigc->gpg_status);

			return error("unsupported value for %s: %s",
	strbuf_setlen(signature, j);
					 */
	argv_array_push(&gpg.args, fmt->program);
			 "-bsau", signing_key,
}
		*field = xmemdupz(line, next - line);
					replace_cstring(&sigc->fingerprint, line, next);
	}
};
		len += eol ? eol - (buf + len) + 1 : size - len;
error:
	ret |= !strstr(gpg_status->buf, "\n[GNUPG:] GOODSIG ");
	else
	int ret;
		BUG("bad signature '%s'", signature);
	struct child_process gpg = CHILD_PROCESS_INIT;

	{ "ULTIMATE", TRUST_ULTIMATE },
	sigc->gpg_status = strbuf_detach(&gpg_status, NULL);
	if (line && next)
				signature->buf[j] = signature->buf[i];
	if (!strcmp(var, "gpg.x509.program"))
	NULL
	temp = mks_tempfile_t(".git_vtag_tmpXXXXXX");
		return git_config_string(&fmt->program, var, value);

	if (!fmt)

						replace_cstring(&sigc->signer, line, next);

				return gpg_format + i;
#include "tempfile.h"
int sign_buffer(struct strbuf *buffer, struct strbuf *signature, const char *signing_key)
size_t parse_signature(const char *buf, size_t size)
		return 0;
				if (sigcheck_gpg_status[i].flags & GPG_STATUS_EXCLUSIVE) {

						goto error;
	for (i = 0; i < ARRAY_SIZE(sigcheck_gpg_trust_level); i++) {
	delete_tempfile(&temp);
	}
				 * signatures.  We don't support them
#define GPG_STATUS_TRUST_LEVEL	(1<<4)
static const char *openpgp_sigs[] = {
	  .sigs = x509_sigs


		return error(_("gpg failed to sign the data"));
				 * GOODSIG, BADSIG etc. can occur only once for

	}
				if (sigcheck_gpg_status[i].result)

	/* Iterate over all lines */
	int i, j;
					/* Do we have signer information? */
					char **field;
			return config_error_nonbool(var);


	sigchain_pop(SIGPIPE);
	if (!strcmp(var, "gpg.program") || !strcmp(var, "gpg.openpgp.program"))
	enum signature_trust_level value;

	/*

};
		set_signing_key(value);


			return config_error_nonbool(var);
} sigcheck_gpg_status[] = {
	NULL
						if (!*next || limit <= next)
	size_t match = size;
	const char **verify_args;
		if (signature->buf[i] != '\r') {
	struct child_process gpg = CHILD_PROCESS_INIT;
	struct tempfile *temp;
						next = strchrnul(line, '\n');
	return 1;
	}
	/* Strip CR from the line endings, in case we are on Windows. */

 out:
					 * space-separated information for v1.
	while (len < size) {

	ret = pipe_command(&gpg, buffer->buf, buffer->len,
	if (status && !gpg_output.len)
	"-----BEGIN PGP SIGNATURE-----",
			 "--status-fd=2",

	}
					 * Skip interim fields.  The search is
	 */
};
			 NULL);
}
	const char *name;

	return git_committer_info(IDENT_STRICT|IDENT_NO_DATE);
	return NULL;
					if (parse_gpg_trust_level(trust, &sigc->trust_level)) {

static struct gpg_format *get_format_by_name(const char *str)
		/* Iterate over all search strings */
{
	const char *output = flags & GPG_VERIFY_RAW ?
						next = strchrnul(line, '\n');
			return 0;
					}

		while (*line == '\n')
struct gpg_format {
				 * create, so something is likely fishy and we

		ret = parse_gpg_trust_level(trust, &configured_min_trust_level);
			match = len;
{
		if (!value)
					char *trust = xmemdupz(line, trust_size);
					replace_cstring(&sigc->key, line, next);
	}
#include "run-command.h"
static struct {
	sigc->result = 'E';
	NULL

	int i, j;
#include "gpg-interface.h"
				}
			j++;
					 * TRUST_ lines are written.  Some
		fputs(output, stderr);
	for (line = buf; *line; line = strchrnul(line+1, '\n')) {
	configured_signing_key = xstrdup(key);
	FREE_AND_NULL(sigc->gpg_output);
};
					}
const char *get_signing_key(void)
					/*
			break;
static const char *x509_verify_args[] = {

	FREE_AND_NULL(sigc->signer);
					size_t trust_size = strcspn(line, " \n");
						line = next + 1;
	}
}


							break;
			return gpg_format + i;
				}

}
		trust = xstrdup_toupper(value);
					 * OpenPGP signatures has a field with
/* The status includes key fingerprints */
		if (!skip_prefix(line, "[GNUPG:] ", &line))
			}
		if (!value)

	free(*field);
					for (j = 9; j > 0; j--) {
			if (i != j)
{
					}
	const char *key;
		}
			 "--status-fd=1",


	struct strbuf gpg_status = STRBUF_INIT;
	if (flags & GPG_VERIFY_VERBOSE && sigc->payload)
{
	sigc->payload = xmemdupz(payload, plen);
						replace_cstring(field, line, next);
	size_t slen, struct signature_check *sigc)
	  .sigs = openpgp_sigs
}
				}
	{ .name = "x509", .program = "gpgsm",
	int status;

		gpg_status = &buf;
	sigchain_push(SIGPIPE, SIG_IGN);
}
		if (!*line)
			 "--verify", temp->filename.buf, "-",
	},
#define GPG_STATUS_UID		(1<<2)
	strbuf_release(&gpg_status);
	free(configured_signing_key);


		if (!strcmp(sigcheck_gpg_trust_level[i].key, level)) {
					} else {
#define GPG_STATUS_EXCLUSIVE	(1<<0)
		return configured_signing_key;
					free(trust);
/* The status includes user identifier */
	  .verify_args = x509_verify_args,
	FREE_AND_NULL(sigc->fingerprint);
		for (i = 0; i < ARRAY_SIZE(sigcheck_gpg_status); i++) {
/* The status includes key identifier */
		error_errno(_("failed writing detached signature to '%s'"),
	FREE_AND_NULL(sigc->primary_key_fingerprint);
	status |= sigc->result != 'G';
				/*
	int seen_exclusive_status = 0;
	const char *line, *next;

					 * limited to the same line since only
				 * than one then we're dealing with multiple
				/* Do we have trust level? */
static const char *x509_sigs[] = {

#define GPG_STATUS_KEYID	(1<<1)
			line++;
			 NULL);
		eol = memchr(buf + len, '\n', size - len);

void set_signing_key(const char *key)

#include "cache.h"
	if (configured_signing_key)
	sigc->trust_level = -1;
#define GPG_STATUS_FINGERPRINT	(1<<3)
	ret = pipe_command(&gpg, payload, payload_size,
		goto out;
	FREE_AND_NULL(sigc->key);
	char *trust;
	/* Clear partial data to avoid confusion */
		if (!strcmp(gpg_format[i].name, str))
static int parse_gpg_trust_level(const char *level,
	status = verify_signed_buffer(payload, plen, signature, slen,
	struct strbuf gpg_status = STRBUF_INIT;
		fmt = get_format_by_name(fmtname);
}
				     value);
		return 0;
				break;
	return;
			*res = sigcheck_gpg_trust_level[i].value;

				if (sigcheck_gpg_status[i].flags & GPG_STATUS_FINGERPRINT) {
				 * each signature.  Therefore, if we had more

					if (seen_exclusive_status++)
					 */
			if (starts_with(sig, gpg_format[i].sigs[j]))
	 * because gpg exits without reading and then write gets SIGPIPE.
static struct {
	{ "NEVER", TRUST_NEVER },
			return error("unsupported value for %s: %s", var,
static struct gpg_format gpg_format[] = {
{
	parse_gpg_output(sigc);
						free(trust);
};
					 * trust lines contain no additional

			 use_format->program,
				const char *signature, size_t signature_size,
				if (sigcheck_gpg_status[i].flags & GPG_STATUS_TRUST_LEVEL) {
	sigc->result = 'N';

#define GPG_STATUS_STDSIG	(GPG_STATUS_EXCLUSIVE|GPG_STATUS_KEYID|GPG_STATUS_UID)
	return NULL;
	strbuf_release(&buf); /* no matter it was used or not */

	FREE_AND_NULL(sigc->payload);
static struct gpg_format *get_format_by_sig(const char *sig)
{
				/* Do we have key information? */

		return -1;
	int ret;
	sigchain_pop(SIGPIPE);
	return ret;
	if (!strcmp(var, "user.signingkey")) {
						line = next + 1;
	argv_array_pushl(&gpg.args,
	for (i = 0; i < ARRAY_SIZE(gpg_format); i++)
static void replace_cstring(char **field, const char *line, const char *next)
{

	char result;
	sigchain_push(SIGPIPE, SIG_IGN);
	{ 'X', "EXPSIG ", GPG_STATUS_STDSIG },
};
			    temp->filename.buf);
}
int check_signature(const char *payload, size_t plen, const char *signature,
		fputs(sigc->payload, stdout);
						replace_cstring(field, NULL, NULL);

		sigc->gpg_status : sigc->gpg_output;
static void parse_gpg_output(struct signature_check *sigc)
static int verify_signed_buffer(const char *payload, size_t payload_size,
	size_t len = 0;
					if (!j) {

#include "strbuf.h"
					next = strchrnul(line, ' ');
						next = strchrnul(line, ' ');
		fmt = get_format_by_name(value);
void signature_check_clear(struct signature_check *sigc)
				 * currently, and they're rather hard to
		if (ret)
	const char *check;

static char *configured_signing_key;
#include "sigchain.h"

	struct gpg_format *fmt = NULL;
				     var, value);
	struct strbuf buf = STRBUF_INIT;
			   gpg_status, 0, gpg_output, 0);
		if (!fmt)
	strbuf_release(&gpg_status);
#include "config.h"
	argv_array_pushl(&gpg.args,
	}


	size_t i;
				/* Do we have fingerprint? */
	char *fmtname = NULL;
};
	},
int git_gpg_config(const char *var, const char *value, void *cb)
	{ "MARGINAL", TRUST_MARGINAL },
				struct strbuf *gpg_status)
{
		return 0;
				 * should reject them altogether.
		if (!value)
	argv_array_pushv(&gpg.args, fmt->verify_args);
			continue;
				      &gpg_output, &gpg_status);

	{ 'E', "ERRSIG ", GPG_STATUS_EXCLUSIVE|GPG_STATUS_KEYID },

	if (write_in_full(temp->fd, signature, signature_size) < 0 ||
/* The status includes trust level */
	if (!strcmp(var, "gpg.mintrustlevel")) {
	if (output)
	for (i = j = bottom; i < signature->len; i++)
			if (skip_prefix(line, sigcheck_gpg_status[i].check, &line)) {

					sigc->result = sigcheck_gpg_status[i].result;
}
{
	if (!gpg_status)

				}
		use_format = fmt;

/* An exclusive status -- only one of them can appear in output */
	{ 'G', "GOODSIG ", GPG_STATUS_STDSIG },
	sigc->gpg_output = strbuf_detach(&gpg_output, NULL);
		fmtname = "x509";
{
					next = strchrnul(line, ' ');
	struct gpg_format *fmt;
/* Short-hand for standard exclusive *SIG status with keyid & UID */
	bottom = signature->len;
	struct strbuf gpg_output = STRBUF_INIT;

	{ 'B', "BADSIG ", GPG_STATUS_STDSIG },

	fmt = get_format_by_sig(signature);
	{ 0, "TRUST_", GPG_STATUS_TRUST_LEVEL },
}
static struct gpg_format *use_format = &gpg_format[0];
	    close_tempfile_gently(temp) < 0) {

	if (!strcmp(var, "gpg.format")) {
static enum signature_trust_level configured_min_trust_level = TRUST_UNDEFINED;
		delete_tempfile(&temp);
		}
	return !!status;
		const char *eol;
}
}
	 * When the username signingkey is bad, program could be terminated
	if (fmtname) {
} sigcheck_gpg_trust_level[] = {
	return match;
		}
		*field = NULL;
	const char *buf = sigc->gpg_status;
		for (j = 0; gpg_format[i].sigs[j]; j++)
{
}
	ret |= !strstr(gpg_status.buf, "\n[GNUPG:] SIG_CREATED ");
			return config_error_nonbool(var);
	strbuf_release(&gpg_output);
		free(trust);
	for (i = 0; i < ARRAY_SIZE(gpg_format); i++)

	"--keyid-format=long",
	{ .name = "openpgp", .program = "gpg",
			   signature, 1024, &gpg_status, 0);
	FREE_AND_NULL(sigc->key);
	status |= sigc->trust_level < configured_min_trust_level;

	{ "FULLY", TRUST_FULLY },
					}
	NULL

static const char *openpgp_verify_args[] = {
	int i;
	unsigned int flags;

	FREE_AND_NULL(sigc->fingerprint);
	const char **sigs;

	FREE_AND_NULL(sigc->primary_key_fingerprint);

	return 0;
					field = &sigc->primary_key_fingerprint;
					limit = strchrnul(line, '\n');
	{ "UNDEFINED", TRUST_UNDEFINED },
				 enum signature_trust_level *res)
}
				if (sigcheck_gpg_status[i].flags & GPG_STATUS_KEYID) {
	int ret;

	size_t i, j, bottom;
					if (*next && (sigcheck_gpg_status[i].flags & GPG_STATUS_UID)) {
	"-----BEGIN PGP MESSAGE-----",
	{ 0, "VALIDSIG ", GPG_STATUS_FINGERPRINT },

		/* Skip lines that don't start with GNUPG status */
	{ 'Y', "EXPKEYSIG ", GPG_STATUS_STDSIG },
		if (get_format_by_sig(buf + len))
		fmtname = "openpgp";
		return error_errno(_("could not create temporary file"));

					/*

					 * the primary fingerprint.
					const char *limit;

};
						goto error;
