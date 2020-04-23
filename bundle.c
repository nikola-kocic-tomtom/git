	else
#include "cache.h"

			error("%s", message);
	if (flags & BUNDLE_VERBOSE)
		if (*buf.buf == '-') {
		if (dwim_ref(e->name, strlen(e->name), &oid, &ref) != 1)
			     r->nr),
	}
	if (!r || !r->objects || !r->objects->odb)
	int result = 1;
	FILE *rls_fout;
	return fd;

	       buf.len && buf.buf[0] != '\n') {
	ip.git_cmd = 1;
	/* Clean up objects used, as they will be reused. */
	}
}
			 * "v1.0..v2.0")?

		 */
		} else {
		 * constraints.
	return 0;

static int parse_bundle_header(int fd, struct bundle_header *header,
	argv_array_pushl(&pack_objects.args,
	if (run_command(&ip))
		goto err;
	 */
static int list_refs(struct ref_list *r, int argc, const char **argv)
	/*
	int i;
				!is_tag_in_date_range(e->item, revs)) {
			if (is_prereq)
	repo_init_revisions(r, &revs, NULL);
#include "list-objects.h"
	return parse_bundle_header(fd, header, path);

int list_bundle_refs(struct bundle_header *header, int argc, const char **argv)
int unbundle(struct repository *r, struct bundle_header *header,
			continue;
	date = parse_timestamp(line, NULL, 10);
	if (verbose) {
		if (parse_oid_hex(buf.buf, &oid, &p) ||
		    (*p && !isspace(*p)) ||
static int is_tag_in_date_range(struct object *tag, struct rev_info *revs)
			struct object *obj;
	if (revs.pending.nr != p->nr)

		if (commit->object.flags & PREREQ_MARK)
	return 0;
	int fd = open(path, O_RDONLY);
	if (pack_objects.out > 1) {
		if (++ret == 1)
	int bundle_to_stdout;
#include "bundle.h"
static const char bundle_signature[] = "# v2 git bundle\n";
				r->list[i].name);

	    strcmp(buf.buf, bundle_signature)) {
	line = memmem(buf, size, "\ntagger ", 8);
		 */
}
			 * in terms of a tag (e.g. v2.0 from the range
			 "pack-objects",

		bundle_fd = 1;

		write_or_die(bundle_fd, "\n", 1);

		struct ref_list *r;
	for (i = 0; i < p->nr; i++) {
#include "run-command.h"
	struct ref_list *p = &header->prerequisites;
			clear_commit_marks(commit, ALL_REV_FLAGS);

	free(buf);
	req_nr = revs.pending.nr;
		goto out;
	struct bundle_header header;
				error(_("unrecognized header: %s%s (%d)"),
	if (finish_command(&rls))
	struct child_process rls = CHILD_PROCESS_INIT;
		close(fd);
	argv_array_pushl(&rls.args,
		}
	if (!buf)
		bundle_fd = hold_lock_file_for_update(&lock, path,
		return error(_("need a repository to verify a bundle"));
			 * Is this the positive end of a range expressed
				add_to_ref_list(&oid, p + 1, &header->references);
		struct ref_list_entry *e = p->list + i;
	/* The bundle header ends with an empty line */
}

		struct object *object = revs->pending.objects[i].item;
		write_or_die(bundle_fd, display_ref, strlen(display_ref));
	argv_array_pushv(&pack_objects.args, pack_options->argv);
			struct object *object = parse_object_or_die(&oid,
		goto err;
			object->flags |= SHOWN;
		r = &header->prerequisites;

	for (i = 0; i < r->nr; i++) {
		struct object *o = parse_object(r, &e->oid);
		}
		if (e->item->flags & UNINTERESTING)
	if (!ref_count)
			goto skip_write_ref;
	save_commit_buffer = 0;
			break;
		return error(_("rev-list died"));
		die(_("Refusing to create empty bundle."));
				obj->flags |= SHOWN;
		goto out;
		(revs->min_age == -1 || revs->min_age > date);
				 * in the output; otherwise we would
		if (!oideq(&oid, &e->item->oid)) {
			  r->nr);
		 * followed by SP and subject line.
		if (report_path)
		int is_prereq = 0;

		}
{
		status = -1;
				add_to_ref_list(&oid, "", &header->prerequisites);
		char *ref;
		 * itself.
out:
			if (e->item == &(one->object)) {
			i--;
#define PREREQ_MARK (1u<<16)
	repo_init_revisions(r, &revs, NULL);
	int ref_count = 0;
err:
			if (j == argc)
	for (i = 0; i < revs->pending.nr; i++) {
		}
	int bundle_fd = -1;
				add_pending_object(revs, obj, e->name);
		struct object *o = parse_object(r, &e->oid);
				     "The bundle requires these %d refs:",
		 * Tip lines have object name, SP, and refname.
	return ret;
			/*
{
				object->flags |= UNINTERESTING;

		const char *display_ref;
		struct ref_list_entry *e = p->list + i;
	int i, ret = 0, req_nr;
		if (argc > 1) {

			error("%s", message);
		return error(_("could not open '%s'"), path);
		}
		goto out;
		}
		if (commit)

	pack_objects.out = bundle_fd;
	int status = 0;
int verify_bundle(struct repository *r,
}
}

	write_or_die(bundle_fd, bundle_signature, strlen(bundle_signature));
		if (commit_lock_file(&lock))

	pack_objects.git_cmd = 1;
 * Write out bundle refs based on the tips already
				 * input, so that the tag is included
	timestamp_t date;

	strbuf_release(&buf);
		}

	     int bundle_fd, int flags)
	for (i = 0; i < p->nr; i++) {
	const char *argv_index_pack[] = {"index-pack",
	 */
		free(ref);
	int fd = open(path, O_RDONLY);
	}




	list->nr++;
		write_or_die(pack_objects.in, "\n", 1);
	if (status) {
 */
static int write_bundle_refs(int bundle_fd, struct rev_info *revs)
	fclose(rls_fout);
}
 * Returns the number of refs written, or negative
	if (write_pack_data(bundle_fd, &revs, pack_options))
static int write_pack_data(int bundle_fd, struct rev_info *revs, struct argv_array *pack_options)
	/*
		struct object_id oid;
	 * to be verbose about the errors
			if (report_path)
		return error(_("Could not spawn pack-objects"));
	unsigned long size;
	bundle_to_stdout = !strcmp(path, "-");
		 * this issue as they are not affected by those extra
			goto skip_write_ref;
		if (object->flags & UNINTERESTING)

	return (fd >= 0);
	/* end header */
		return ret;
			       const char *report_path)
		}
	/* write prerequisites */
				 */
									    buf.buf);
			 "--stdout", "--thin", "--delta-base-offset",
			continue;
		if (!(e->item->flags & SHOWN) && e->item->type == OBJ_COMMIT) {
		strbuf_rtrim(&buf);
#include "diff.h"

	if (fd < 0)
		printf("%s %s\n", oid_to_hex(&r->list[i].oid),
		 * from getting output.
		commit = lookup_commit_reference_gently(r, &e->oid, 1);
	rls.git_cmd = 1;

	return ref_count;
		return 0;
		 * Prerequisites have object name that is optionally
 * parsed into revs.pending. As a side effect, may

{
#include "repository.h"

					 "--fix-thin", "--stdin", NULL, NULL};
			warning(_("ref '%s' is excluded by the rev-list options"),

				 * error.
 *
		    (!is_prereq && !*p)) {
{
			struct commit *one = lookup_commit_reference(revs->repo, &oid);
			child_process_clear(&pack_objects);
		return -1;
	struct lock_file lock = LOCK_INIT;
		fd = -1;
		 *
		return -1;
	const char *argv[] = {NULL, "--all", NULL};
	}

		struct object_id oid;
		goto abort;
	char *buf = NULL, *line, *lineend;
	line = memchr(line, '>', lineend ? lineend - line : buf + size - line);
	ip.no_stdout = 1;
	int i;

		write_or_die(bundle_fd, " ", 1);
	struct child_process pack_objects = CHILD_PROCESS_INIT;
	const char *message = _("Repository lacks these prerequisite commits:");
	}
		  struct bundle_header *header,
		if (pack_objects.out < 0) {
int create_bundle(struct repository *r, const char *path,
		struct object_array_entry *e = revs->pending.objects + i;
			return -1;
	/* The bundle header begins with the signature */
	return 0;
		struct object_id oid;
	write_or_die(bundle_fd, "\n", 1);
			list_refs(r, 0, NULL);

{
	if (revs->max_age == -1 && revs->min_age == -1)
	return list_refs(&header->references, argc, argv);
	if (prepare_revision_walk(&revs))
}
					   struct rev_info *revs,
		return error(_("pack-objects died"));
		if (read_ref_full(e->name, RESOLVE_REF_READING, &oid, &flag))
			add_pending_object(&revs, o, e->name);
	if (start_command(&pack_objects))
{
			goto skip_write_ref;
		goto err;
			flag = 0;

	close(pack_objects.in);
	if (verify_bundle(r, header, 0))
	struct strbuf buf = STRBUF_INIT;
	}
			printf_ln(Q_("The bundle requires this ref:",
				      (is_prereq ? "-" : ""), buf.buf, (int)buf.len);


		 * commit that is referenced by the tag, and not the tag
		error(_("unrecognized argument: %s"), argv[1]);


/* Remember to update object flag allocation in object.h */
}
		write_or_die(pack_objects.in, oid_to_hex(&object->oid), the_hash_algo->hexsz);

	if (finish_command(&pack_objects))

	}
	if (!line++)
			if (!get_oid_hex(buf.buf + 1, &oid)) {
 * on error.
			is_prereq = 1;
				/*
	}
 abort:
	return -1;
		/*
	rls_fout = xfdopen(rls.out, "r");
	ip.argv = argv_index_pack;
	rls.out = -1;
				 * Need to include e->name as an
	object_array_remove_duplicates(&revs.pending);
			 NULL);
						      LOCK_DIE_ON_ERROR);
				add_pending_object(revs, object, buf.buf);
 * necessary objects (like tags).
{
		assert(o); /* otherwise we'd have returned early */
int is_bundle(const char *path, int quiet)
static void add_to_ref_list(const struct object_id *oid, const char *name,
#include "object.h"
 * manipulate revs.pending to include additional
		display_ref = (flag & REF_ISSYMREF) ? e->name : ref;
		  int verbose)

	}
		pack_objects.out = dup(pack_objects.out);
		list_refs(r, 0, NULL);

	lineend = memchr(line, '\n', buf + size - line);
	while (strbuf_getwholeline(&buf, rls_fout, '\n') != EOF) {


	if (!bundle_to_stdout) {
	ip.in = bundle_fd;
				 * independent ref to the pack-objects
#include "commit.h"
	return 0;
{

		if (++ret == 1)
		struct ref_list *list)
				  r->nr);
static int compute_and_write_prerequisites(int bundle_fd,
			goto skip_write_ref;
				struct object *object = parse_object_or_die(&oid,
}
	/* write signature */
		/*
	ref_count = write_bundle_refs(bundle_fd, &revs);
	buf = read_object_file(&tag->oid, &type, &size);
		ref_count++;
		die(_("revision walk setup failed"));
	result = (revs->max_age == -1 || revs->max_age < date) &&
	return 0;
	if (strbuf_getwholeline_fd(&buf, fd, '\n') ||
#include "lockfile.h"
		}
		 * name of the positive ref is "v2.0" but that is the

				e->name);
	oidcpy(&list->list[list->nr].oid, oid);
								    buf.buf);
	if (compute_and_write_prerequisites(bundle_fd, &revs, argc, argv))
	}
 skip_write_ref:
		goto out;
			printf_ln(_("The bundle records a complete history."));
	if (fd >= 0)
int read_bundle_header(const char *path, struct bundle_header *header)
	for (i = 1; i < argc; i++)
	struct commit *commit;
			e->item->flags |= UNINTERESTING;
			     "The bundle contains these %d refs:",
	}
	argc = setup_revisions(argc, argv, &revs, NULL);

{
		int flag;

		error("%s %s", oid_to_hex(&e->oid), e->name);
	else if (ref_count < 0)
			int j;
			error_errno(_("unable to dup bundle descriptor"));
		return error(_("index-pack died"));
					break;
	while (!strbuf_getwholeline_fd(&buf, fd, '\n') &&
	rollback_lock_file(&lock);
			else
					   int argc, const char **argv)
				obj = parse_object_or_die(&oid, e->name);
	i = req_nr;
			status = -1;
		argv_index_pack[3] = "-v";
		 * Non commit objects such as tags and blobs do not have
		error("%s %s", oid_to_hex(&e->oid), e->name);
		} else {
}
		  int argc, const char **argv, struct argv_array *pack_options)
			 "rev-list", "--boundary", "--pretty=oneline",
			strbuf_remove(&buf, 0, 1);
			 */
{

			}
	/* write pack */
		if (e->item->type == OBJ_TAG &&
				if (!strcmp(r->list[i].name, argv[j]))
			die_errno(_("cannot create '%s'"), path);
	if (!line++)
			error(_("'%s' does not look like a v2 bundle file"),

	struct strbuf buf = STRBUF_INIT;

		if (!r->nr) {
		const char *p;
	int i;
}

#include "argv-array.h"
		 * If you run "git bundle create bndl v1.0..v2.0", the
{

	struct rev_info revs;
#include "revision.h"
				continue;
		if (o->flags & SHOWN)
			o->flags |= PREREQ_MARK;
	while (i && (commit = get_revision(&revs)))

			      report_path);
			write_or_die(bundle_fd, buf.buf, buf.len);
			continue;
/*
	enum object_type type;
	for (i = 0; i < revs->pending.nr; i++) {
		 * Make sure the refs we wrote out is correct; --max-count and
			 NULL);
		printf_ln(Q_("The bundle contains this ref:",
	struct child_process ip = CHILD_PROCESS_INIT;
			}
	 * start_command() will close our descriptor if it's >1. Duplicate it
	setup_revisions(2, argv, &revs, NULL);
	for (i = 0; i < p->nr; i++) {
		if (buf.len > 0 && buf.buf[0] == '-') {
	return result;
				     r->nr),
}
	}
{
	strbuf_release(&buf);
/* Write the pack data to bundle_fd */
	}
	if (argc > 1) {
		argv_array_push(&rls.args, argv[i]);
	ALLOC_GROW(list->list, list->nr + 1, list->alloc);
		 */
		} else if (!get_oid_hex(buf.buf, &oid)) {
	if (fd < 0)
			write_or_die(pack_objects.in, "^", 1);
		/*
	memset(&header, 0, sizeof(header));
				 * end up triggering "empty bundle"
#include "refs.h"
	pack_objects.in = -1;
	list->list[list->nr].name = xstrdup(name);
	/* init revs to list objects for pack-objects later */
			for (j = 1; j < argc; j++)
		write_or_die(bundle_fd, oid_to_hex(&e->item->oid), the_hash_algo->hexsz);
		close(fd);
		 * other limiting options could have prevented all the tips
#include "object-store.h"

	}
	 * Do fast check, then if any prereqs are missing then go line by line
	if (bundle_to_stdout)
		if (o) {
{
	if (start_command(&rls))
}
		struct ref_list_entry *e = p->list + i;
		r = &header->references;
	struct rev_info revs;
	int i;
	int ref_count = 0;
	 * to avoid surprising the caller.
		}
		goto err;


	fd = parse_bundle_header(fd, &header, quiet ? NULL : path);
