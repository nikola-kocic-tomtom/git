		break;
	 */
			strbuf_release(&sb);
		{ OPTION_CALLBACK, 0, "batch-check", &batch, "format",

	struct object_info oi = OBJECT_INFO_INIT;
			    N_("for blob objects, run textconv on object's content"), 'c'),

	/*
	/*
					       FOR_EACH_OBJECT_PACK_ORDER);
			       result);
		path = obj_context.path;

			die("--batch-all-objects cannot be combined with "
		break;
				  void *data)
		error("--path=<path> needs --textconv or --filters");
{
			struct oid_array sa = OID_ARRAY_INIT;
static int collect_loose_object(const struct object_id *oid,
		die("git cat-file: unknown option: %s", exp_type);
	 * object_info to be handed to oid_object_info_extended for each
}
			 */

		if (data->mark_query)
		write_or_die(1, data, len);
	int all_objects;
	unsigned skip_object_info : 1;


	int cmdmode; /* may be 'w' or 'c' for --filters or --textconv */
			die("git cat-file: could not get object info");

	const struct object_id *oid = &data->oid;
	data.mark_query = 0;
	} else if (is_atom("objectsize", atom, len)) {
{
	}
			usage_with_options(cat_file_usage, options);
		return 0;
				oidcpy(&blob_oid, &oid);
			batch_option_callback },
	return git_default_config(var, value, cb);
	result = get_oid_with_context(the_repository, obj_name,
			break;

		fflush(stdout);
			die("object %s disappeared", oid_to_hex(oid));

		OPT_CMDMODE('p', NULL, &opt, N_("pretty-print object's content"), 'p'),
		if (fwrite(data, 1, len, stdout) != len)

						 &oid, exp_type, &size, NULL);
		else
	}
			stream_blob(oid);
{
		return !has_object_file(&oid);
	case 't':
	return 0;
		oi.sizep = &size;
		OPT_END()
	oid_array_append(data, oid);
		if (oid_object_info_extended(the_repository, &oid, &oi, flags) < 0)
static const char * const cat_file_usage[] = {
		usage_with_options(cat_file_usage, options);

		OPT_CMDMODE(0, "textconv", &opt,

				 GET_OID_RECORD_PATH,
}
		if (!memcmp(&data.info, &empty, sizeof(empty)))
		batch_write(opt, contents, size);
	expand_atom(sb, start + 1, end - start - 1, data);
		die("Not a valid object name %s", obj_name);
	int buffer_output;
			return stream_blob(&oid);
	strbuf_reset(scratch);
	batch_object_write(obj_name, scratch, opt, data);
	 * warn) ends up dwarfing the actual cost of the object lookups
		case SYMLINK_LOOP:
	bo->enabled = 1;
		if (data->mark_query)
	const char *format;
static int is_atom(const char *atom, const char *s, int slen)
	struct object_cb_data *data = vdata;
			 * and failed; there may be new dereference
		return 0;
		if (type == OBJ_BLOB)
static int cat_one_file(int opt, const char *exp_type, const char *obj_name,
			if (oid_object_info(the_repository, &blob_oid, NULL) == OBJ_BLOB)
			break;
		if (type_from_string(exp_type) == OBJ_BLOB) {
	*buf = read_object_file(oid, &type, size);
	strbuf_release(&output);
	struct object_cb_data *data = vdata;
		if (textconv_object(the_repository, path, obj_context.mode,
	free(obj_context.path);
			cb.seen = &seen;
static int batch_object_cb(const struct object_id *oid, void *vdata)
	return 0;
	warn_on_object_refname_ambiguity = 0;
				BUG("invalid cmdmode: %c", opt->cmdmode);
	batch_write(opt, scratch->buf, scratch->len);
			       (uintmax_t)strlen(obj_name), obj_name);
	int retval = 0;
		batch.buffer_output = batch.all_objects;
	 */
			*size = strbuf.len;
		struct strbuf strbuf = STRBUF_INIT;
		/* custom pretty-print here */
	end = strchr(start + 1, ')');
		printf("%s missing\n",

		if (data->mark_query)
		struct object_cb_data cb;
			N_("show info about objects fed from the standard input"),
			}
		if (has_promisor_remote())
static void batch_one_object(const char *obj_name,
	int unknown_type = 0;
	if (opt) {
		OPT_BOOL(0, "follow-symlinks", &batch.follow_symlinks,



				while (*p && strchr(" \t", *p))
{

		/* else fallthrough */
			printf("%s ambiguous\n", obj_name);

			exp_type = argv[0];

	return batch_unordered_object(oid, data);


			die("object %s changed size!?", oid_to_hex(oid));
static int stream_blob(const struct object_id *oid)
	enum get_oid_result result;
			free(contents);
			 * fall-back to the usual case.
			die("Cannot read object %s", obj_name);
	if (!*buf)
		}


		if (data->mark_query)
}
			 * we attempted to dereference a tag to a blob
	}
			return cmd_ls_tree(2, ls_args, NULL);
		if (filter_object(path, obj_context.mode,
		if (opt->cmdmode) {
	struct object_id delta_base_oid;
	const char *exp_type = NULL, *obj_name = NULL;


	}
{
			     struct expand_data *data)

static void batch_write(struct batch_options *opt, const void *data, int len)
	strbuf_expand(scratch, opt->format, expand_format, data);
			BUG("unknown get_sha1_with_context result %d\n",
			strbuf_addstr(sb, type_name(data->type));
	case 'c':
			data.rest = p;
		if (data->info.sizep && size != data->size)
			 */

			char *contents;
					contents = read_object_file(oid,
			strbuf_addstr(sb,
				char *buffer = read_object_file(&oid, &type,
#include "streaming.h"
		die("unknown format element: %.*s", len, atom);
	return batch_object_cb(oid, data);

	if (batch.enabled)
			*buf = strbuf_detach(&strbuf, NULL);
				if (filter_object(data->rest, 0100644, oid,
					die("could not convert '%s' %s",
			warning("This repository uses promisor remotes. Some objects may not be loaded.");

			break;
				  &oid, &buf, &size))
	unsigned long size;
	struct strbuf sb = STRBUF_INIT;
	} else if (is_atom("deltabase", atom, len)) {

			if (p) {
				     OBJECT_INFO_LOOKUP_REPLACE) < 0) {
		case SHORT_NAME_AMBIGUOUS:
	/*
			 char **buf, unsigned long *size)
			for_each_packed_object(batch_unordered_packed, &cb,
			 N_("do not order --batch-all-objects output")),

		if (argc == 2) {
	struct expand_data *data = vdata;
		       (uintmax_t)ctx.symlink_path.len,
static int git_cat_file_config(const char *var, const char *value, void *cb)
	if (*start != '(')
#include "userdiff.h"
				  struct packed_git *pack,
			break;
	return cat_one_file(opt, exp_type, obj_name, unknown_type);
		if (type == OBJ_TREE) {
	 * just mark the object_info with items we wish to query.


	if ((batch.follow_symlinks || batch.all_objects) && !batch.enabled) {
	 * Expand once with our special mark_query flag, which will prime the
	strbuf_release(&output);

		OPT_BOOL(0, "buffer", &batch.buffer_output, N_("buffer --batch output")),

	const char *rest;
		if (!path)
	unsigned flags = OBJECT_INFO_LOOKUP_REPLACE;
}
	/*
		return;
			for_each_loose_object(batch_unordered_loose, &cb, 0);
	return batch_unordered_object(oid, data);
			obj_name = argv[0];
			N_("show info and content of objects fed from the standard input"),
}
			batch_write(opt, contents, size);
		die("format element '%s' does not end in ')'", start);
	if (!data->skip_object_info &&

	char *buf;
{

	 * get_sha1; this is decided during the mark_query phase based on
#include "config.h"
			 const struct object_id *oid,
				      oid_to_hex(&data->delta_base_oid));
		type = oid_object_info(the_repository, &oid, NULL);
{

	enum object_type type;

}
		       obj_name ? obj_name : oid_to_hex(&data->oid));
	}
		}
		cb.opt = opt;
#include "packfile.h"
	 * elements above, so you can retrieve the response from there.
	write_or_die(1, buf, size);
		void *contents;
			printf("loop %"PRIuMAX"\n%s\n",
			     struct batch_options *opt,

	if (opt->buffer_output) {

		print_object_or_die(opt, data);
				 const char *arg,
			printf("notdir %"PRIuMAX"\n%s\n",
		return;

	if (!opt && !batch.enabled) {
				if (!textconv_object(the_repository,
	if (!end)
				return stream_blob(&blob_oid);
		OPT_CMDMODE('t', NULL, &opt, N_("show object type"), 't'),
};
		oi.type_name = &sb;
	case 's':
static int batch_unordered_loose(const struct object_id *oid,

	struct expand_data data;
 */
	enum object_type type;
			die("git cat-file --filters %s: <object> must be "

#include "tree-walk.h"

	}
	int flags = opt->follow_symlinks ? GET_OID_FOLLOW_SYMLINKS : 0;
		die("git cat-file --allow-unknown-type: use with -s or -t");
			} else
		if (batch.enabled && (opt == 'c' || opt == 'w'))
		if (!data->mark_query)
			unsigned long size;
			const char *ls_args[3] = { NULL };
		OPT_STRING(0, "path", &force_path, N_("blob"),
	}
			     struct strbuf *scratch,
static void print_object_or_die(struct batch_options *opt, struct expand_data *data)
			return 0;
	if (obj_context.mode == S_IFINVALID)
	struct strbuf output = STRBUF_INIT;
		return -1;
			batch_option_callback },
	case 0:

{
#include "object-store.h"

				void *data)
	oid_array_append(data, oid);
			printf("%s missing\n", obj_name);
	if (opt->print_contents) {
	}
	argc = parse_options(argc, argv, prefix, options, cat_file_usage, 0);
	strbuf_expand(&output, opt->format, expand_format, &data);
	return 0;
	 * If we are printing out the object, then always fill in the type,
#include "cache.h"
			strbuf_addstr(sb, data->rest);
			break;
		printf("symlink %"PRIuMAX"\n%s\n",
	 * don't require us to call oid_object_info, which can then be


	struct object_context ctx;

	const struct option options[] = {

		printf("%"PRIuMAX"\n", (uintmax_t)size);

		switch (result) {
		if (batch.cmdmode != opt || argc)
}
	/*
		struct checkout_metadata meta;
					die("%s not a valid tag", oid_to_hex(&oid));
};

	struct batch_options *bo = opt->value;
	if ((type == OBJ_BLOB) && S_ISREG(mode)) {
			    N_("for blob objects, run filters on object's content"), 'w'),
		} else {

		OPT_CMDMODE('s', NULL, &opt, N_("show object size"), 's'),
		OPT_GROUP(N_("<type> can be one of: blob, tree, commit, tag")),
		die("git cat-file %s: bad file", obj_name);
		if (!buf)
			printf("dangling %"PRIuMAX"\n%s\n",
	unsigned long size;
			data->info.typep = &data->type;

			for_each_packed_object(collect_packed_object, &sa, 0);
#define USE_THE_INDEX_COMPATIBILITY_MACROS
			usage_with_options(cat_file_usage, options);
	    oid_object_info_extended(the_repository, &data->oid, &data->info,

			die("object %s changed type!?", oid_to_hex(oid));
	case 'e':
		else
		cb.expand = &data;
		data.split_on_whitespace = 1;
	return alen == slen && !memcmp(atom, s, alen);
	}
				 struct packed_git *pack,
			data->info.disk_sizep = &data->disk_size;
		batch_write(opt, "\n", 1);

			die("Not a valid object name %s", obj_name);
		return error(_("cannot read object %s '%s'"),

	else {
int cmd_cat_file(int argc, const char **argv, const char *prefix)
		flags |= OBJECT_INFO_ALLOW_UNKNOWN_TYPE;
{

}
	/*
	bo->format = arg;
			} else
	struct batch_options batch = {0};
					    oid_to_hex(oid), data->rest);
		{ OPTION_CALLBACK, 0, "batch", &batch, "format",
	git_config(git_cat_file_config, NULL);
	}
			struct oidset seen = OIDSET_INIT;
			       struct batch_options *opt,
		usage_with_options(cat_file_usage, options);

					    oid_to_hex(oid), data->rest);
	int mark_query;
	}
	 * passed to oid_object_info_extended. It will point to the data
		return 0;


{
		return error(_("only one batch option may be specified"));

			oid_array_clear(&sa);
			    N_("exit with zero when there's no error"), 'e'),
{
		if (batch.cmdmode && batch.all_objects)
	if (unknown_type)
	 * This flag will be true if the requested batch format and options
						     data->rest, 0100644, oid,

}

			die_errno("unable to write to stdout");
}
}
static int batch_objects(struct batch_options *opt)
			} else if (opt->cmdmode == 'c') {
		return 0;
			char *p = strpbrk(input.buf, " \t");
{
			 N_("show all objects with --batch or --batch-check")),
			 * of the string and saving the remainder (or NULL) in
	}
	 */

		else if (data->rest)
		unsigned long size;
#include "diff.h"

	batch.buffer_output = -1;
	 */
		buf = read_object_file(&oid, &type, &size);
	if (data->type == OBJ_BLOB) {

	int alen = strlen(atom);
	 */
	 * whether we have a %(rest) token in our format.
			 * mechanisms this code is not aware of.
	case 'p':
	 * themselves. We can work around it by just turning off the warning.
				    get_oid_hex(target, &blob_oid))
static int batch_option_callback(const struct option *opt,
								    &type,
{
			    obj_name);
	}
		fflush(stdout);
			   N_("use a specific path for --textconv/--filters")),

	if (result != FOUND) {
			       (uintmax_t)strlen(obj_name), obj_name);
			strbuf_addstr(sb, oid_to_hex(&data->oid));
	struct object_id oid;
}
			batch.cmdmode = opt;
		contents = read_object_file(oid, &type, &size);
			  N_("allow -s and -t to work with broken/corrupt objects")),
		case MISSING_OBJECT:
	};
		if (opt->buffer_output)
	warn_on_object_refname_ambiguity = save_warning;
		default:
		OPT_BOOL(0, "batch-all-objects", &batch.all_objects,
			data->split_on_whitespace = 1;
	} else
		/* otherwise just spit out the data */
	batch_object_write(NULL, data->scratch, data->opt, data->expand);
		if (data.split_on_whitespace) {
			return -1;
};

			die("git cat-file --textconv %s: <object> must be <sha1:path>",

	int save_warning;
	default:
			data->info.sizep = &data->size;
					die("could not convert '%s' %s",
	switch (opt) {
	if (!path)
		init_checkout_metadata(&meta, NULL, NULL, oid);
		strbuf_release(&output);
		opt->format = "%(objectname) %(objecttype) %(objectsize)";
		buf = read_object_with_reference(the_repository,
		else

		} else {

#include "builtin.h"
{
	if (batch.enabled) {
		if (!path)
	buf = NULL;
		}
	struct expand_data *expand;
	 * cost to double-check that each one is not also a ref (just so we can

	if (stream_blob_to_fd(1, oid, NULL, 0))
	}
				if (!skip_prefix(buffer, "object ", &target) ||
	if (force_path && opt != 'c' && opt != 'w') {
	return 0;
	save_warning = warn_on_object_refname_ambiguity;
			fflush(stdout);
	strbuf_addch(scratch, '\n');
	N_("git cat-file (-t [--allow-unknown-type] | -s [--allow-unknown-type] | -e | -p | <type> | --textconv | --filters) [--path=<path>] <object>"),
	 * If mark_query is true, we do not expand anything, but rather
	return 0;


		usage_with_options(cat_file_usage, options);

		free(contents);
				 int unset)
			 * Split at first whitespace, tying off the beginning
								    &size);
	const char *path = force_path;
		OPT_BOOL(0, "allow-unknown-type", &unknown_type,
		fflush(stdout);
						  &contents, &size))
	return 0;
 *
			void *vdata)
	struct strbuf *scratch;
			if (oid_object_info(the_repository, &oid, NULL) == OBJ_TAG) {
	}
	off_t disk_size;
	 * object.
				 &oid, &obj_context))

static int batch_unordered_packed(const struct object_id *oid,
	 * Whether to split the input on whitespace before feeding it to
			strbuf_addf(sb, "%"PRIuMAX, (uintmax_t)data->disk_size);

	assert(data->info.typep);
	case 'w':
		if (convert_to_working_tree(&the_index, path, *buf, *size, &strbuf, &meta)) {
	if (oidset_insert(data->seen, oid))
		else
	int print_contents;
			       (uintmax_t)strlen(obj_name), obj_name);
/*
	int follow_symlinks;
 * Copyright (C) Linus Torvalds, 2005
	if (force_path && batch.enabled) {
			oid_array_for_each_unique(&sa, batch_object_cb, &cb);

static void batch_object_write(const char *obj_name,
			break;
#include "parse-options.h"

	} else
				    &oid, 1, &buf, &size))
#include "promisor-remote.h"

		OPT_BOOL(0, "unordered", &batch.unordered,
			     oid_to_hex(oid), path);
	struct strbuf input = STRBUF_INIT;
	if (opt->all_objects) {
	return end - start + 1;
		enum object_type type;
				      flags, &data->oid, &ctx);
	if (!opt->format)
	int split_on_whitespace;
		return;
	oidcpy(&data->expand->oid, oid);
		case DANGLING_SYMLINK:
	 * After a mark_query run, this object_info is set up to be
		OPT_CMDMODE(0, "filters", &opt,
		if (type != data->type)
			usage_with_options(cat_file_usage, options);
{
			    "<sha1:path>", obj_name);
								&size);
		cb.scratch = &output;
			data.skip_object_info = 1;
	int enabled;
struct object_cb_data {

	memset(&data, 0, sizeof(data));


	int opt = 0;
	struct object_info info;
		else if (argc == 1)
				die("missing path for '%s'", oid_to_hex(oid));
			obj_name = argv[1];
	 * since we will want to decide whether or not to stream.
	} else if (is_atom("rest", atom, len)) {

{
			ls_args[0] =  "ls-tree";
				if (!contents)
			data->info.delta_base_oid = &data->delta_base_oid;
}
		return batch_objects(&batch);
				 void *data)
		if (oid_object_info_extended(the_repository, &oid, &oi, flags) < 0)
static int filter_object(const char *path, unsigned mode,
	while (strbuf_getline(&input, stdin) != EOF) {

static void expand_atom(struct strbuf *sb, const char *atom, int len,
static int batch_unordered_object(const struct object_id *oid, void *vdata)
					*p++ = '\0';

			 * data.rest.
	const char *end;
			printf("%s\n", sb.buf);
	if (batch.buffer_output < 0)
	data.mark_query = 1;
	if (opt->cmdmode)
	}
		}

		OPT_CMDMODE('e', NULL, &opt,
}

				 uint32_t pos,
	return 0;

		if (type < 0)
			/*
{
				free(buffer);
			ls_args[1] =  obj_name;
		if (sb.len) {

				const char *path,
		}
				enum object_type type;
	if (is_atom("objectname", atom, len)) {

struct batch_options {
		error("--path=<path> incompatible with --batch");
{
	N_("git cat-file (--batch | --batch-check) [--follow-symlinks] [--textconv | --filters]"),
		break;
		} else

	strbuf_release(&input);
	if (opt->print_contents)
			for_each_loose_object(collect_loose_object, &sa, 0);

}
	if (userdiff_config(var, value) < 0)
			struct object_id blob_oid;
	return retval;
{
		obj_context.mode = 0100644;
	enum object_type type;
	}
		}
		struct object_info empty = OBJECT_INFO_INIT;
}
	if (get_oid_with_context(the_repository, obj_name,
			int unknown_type)
			if (!data->rest)
			/*

		if (data->mark_query)
}
			strbuf_addf(sb, "%"PRIuMAX , (uintmax_t)data->size);
		case NOT_DIR:
	/*
	 * optimized out.
{
}
				  uint32_t pos,
		if (opt->unordered) {
		       ctx.symlink_path.buf);
	if (unknown_type && opt != 't' && opt != 's')
			    "--textconv nor with --filters");

	BUG_ON_OPT_NEG(unset);
	int unordered;

	 */
			 N_("follow in-tree symlinks (used with --batch or --batch-check)")),
			if (opt->cmdmode == 'w') {
	} else if (is_atom("objectsize:disk", atom, len)) {
		}
	bo->print_contents = !strcmp(opt->long_name, "batch");
		data.info.typep = &data.type;
	}
		}
		die("unable to stream %s to stdout", oid_to_hex(oid));
			die("git cat-file: could not get object info");
			       struct strbuf *scratch,
	free(buf);


	if (opt->all_objects) {
	 * We are going to call get_sha1 on a potentially very large number of
			oidset_clear(&seen);
			free(*buf);
			       struct expand_data *data)
struct expand_data {
			PARSE_OPT_OPTARG | PARSE_OPT_NONEG,
	} else if (is_atom("objecttype", atom, len)) {
}
static size_t expand_format(struct strbuf *sb, const char *start, void *data)
 * GIT - The information manager from hell
			break;
			PARSE_OPT_OPTARG | PARSE_OPT_NONEG,
						     1, &contents, &size))
		if (!contents)
#include "oid-array.h"

	struct batch_options *opt;
		batch_one_object(input.buf, &output, opt, &data);
		break;
		else
	if (!buf)
static const char *force_path;
				const char *target;
				 void *data)
static int collect_packed_object(const struct object_id *oid,
	struct object_id oid;
	struct object_context obj_context;
	if (bo->enabled) {
	if (ctx.mode == 0) {

};
	NULL
	struct oidset *seen;
	 */
				 const char *path,
}
	 * objects. In most large cases, these will be actual object sha1s. The
