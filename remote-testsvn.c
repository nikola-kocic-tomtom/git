
	if (!marksfile) {
}
		void *cb_data)
		end = strchrnul(msg, '\n');
		url = url_decode(url_in + sizeof("file://")-1);
		regenerate_marks();
		while (strbuf_getline_lf(&line, marksfile) != EOF) {
	}
	init_notes(NULL, notes_ref, NULL, 0);
	else if (!msglen || type != OBJ_BLOB) {
}
	if (read_ref(private_ref, &head_oid))
		} else {

	} else {
	const char *command = "svnrdump";
	if (!(msg = read_object_file(note_oid, &type, &msglen)) ||
	if (batch_cmd) {
	struct object_id head_oid;

			"feature export-marks=%s\n", marksfilename, marksfilename);
			}

				return 0;

/* NOTE: 'ref' refers to a git reference, while 'rev' refers to a svn revision. */
}
{
	strbuf_release(&line);
	fclose(marksfile);
static int note2mark_cb(const struct object_id *object_oid,
		return 1;
				batch_cmd = p;
			i = strtol(value, &end, 0);
static int cmd_capabilities(const char *line)
{
		return 0;
static int parse_rev_note(const char *msg, struct rev_note *res)
static int cmd_list(const char *line);
	}


			die_errno("Couldn't open svn dump file %s.", url);
{
	struct child_process svndump_proc = CHILD_PROCESS_INIT;
static int cmd_import(const char *line);
		argv_array_push(&svndump_proc.args, url);
	}

	}
	 * Batches are ended by \n. If no batch is active the program ends.

				die("Unexpected end of command stream");

	struct strbuf line = STRBUF_INIT;
	FILE *marksfile = xfopen(marksfilename, "w+");
	strbuf_release(&marksfilename_sb);
	int found = 0;
static void check_or_regenerate_marks(int latestrev)
	unsigned long msglen;
}


	int ret;
	/* setup marks file import/export */
static int cmd_list(const char *line)
			return 0;	/* end of the batch, continue reading other commands. */

	remote = remote_get(argv[1]);

		const struct object_id *note_oid, char *note_path,
			die("Unable to start %s, code %d", command, code);
		if (starts_with(line->buf, p->name) && (strlen(p->name) == line->len ||
	return msg;
			startrev = 0;
	struct strbuf sb = STRBUF_INIT;
		if (batch_cmd) {
	if (!dump_from_file) {
	static struct remote *remote;
#include "refs.h"
}
#include "strbuf.h"
	/* didn't find it */
	{ NULL, NULL }
	strbuf_addf(&private_ref_sb, "refs/svn/%s/master", remote->name);
	strbuf_addf(&marksfilename_sb, "%s/info/fast-import/remote-svn/%s.marks",
		if(note_msg == NULL) {

	static struct string_list batchlines = STRING_LIST_INIT_DUP;
	printf("import\n");
		}
		strbuf_addf(&sb, ":%d ", latestrev);
				die("Error reading command stream");
	char *msg = NULL;
static char *read_ref_note(const struct object_id *oid)
	} else {
			if (starts_with(line.buf, sb.buf)) {
		}

	if (!(note_oid = get_note(NULL, oid)))
				break;
		/* buffer batch lines */
		fclose(marksfile);
	/* terminate a current batch's fast-import stream */
				string_list_append(&batchlines, line->buf);
			value = msg + strlen(key);
				die("Revision number couldn't be parsed from note.");
	printf("done\n");
			if (end == value || i < 0 || i > UINT32_MAX)
		code = finish_command(&svndump_proc);
		startrev = 0;
};
	return 0;
	close(dumpin_fd);
			long i;
		FREE_AND_NULL(msg);
	fflush(stdout);
#include "cache.h"
			!msglen || type != OBJ_BLOB) {
	}
	 */
		return 1;	/* end of command stream, quit */
	/*
		dump_from_file = 1;
	else {
struct rev_note { unsigned int rev_nr; };
		key = "Revision-number: ";
static const char *url;
		return;
		svndump_proc.out = -1;
		argv_array_push(&svndump_proc.args, "dump");
	svndump_init_fd(dumpin_fd, STDIN_FILENO);
}


static void terminate_batch(void)
	if (argc < 2 || argc > 3) {
	svndump_deinit();
		die("Regeneration of marks failed, returned %d.", ret);

	return 0;
		if (starts_with(msg, key)) {
	if (!(msg = read_object_file(note_oid, &type, &msglen)))
	svndump_reset();
typedef int (*input_command_handler)(const char *);
#include "vcs-svn/svndump.h"
		argv_array_push(&svndump_proc.args, command);
			warning("%s, returned %d", command, code);
			startrev = note.rev_nr + 1;
		free(msg);
	url_in = (argc == 3) ? argv[2] : remote->url[0];
		argv_array_pushf(&svndump_proc.args, "-r%u:HEAD", startrev);
	fflush(stdout);
		return NULL;	/* note tree not found */
			private_ref_sb = STRBUF_INIT, marksfilename_sb = STRBUF_INIT,
}
			die("Active %s batch interrupted by %s", batch_cmd->name, line->buf);
	unsigned char batchable;	/* whether the command starts or is part of a batch */
		error("Note contains unusable content. "
	const struct object_id *note_oid;
	die("Unknown command '%s'\n", line->buf);
		}
#include "run-command.h"

			if (ferror(stdin))

	if (parse_rev_note(msg, &note))

	static const struct input_command_entry *batch_cmd;
#include "object-store.h"
			break;
		dump_from_file = 0;
	 * commands can be grouped together in a batch.
	return 0;
	marksfile = fopen(marksfilename, "r");
struct input_command_entry {
		if(dumpin_fd < 0)
	strbuf_addf(&notes_ref_sb, "refs/notes/%s/revs", remote->name);
		if (do_command(&buf))

#include "exec-cmd.h"
	}
			"Is something else using this notes tree? %s", notes_ref);
		}
	}
			if (p->batchable) {
{

		dumpin_fd = svndump_proc.out;
{
	strbuf_release(&sb);
#include "url.h"
	notes_ref = notes_ref_sb.buf;
			struct string_list_item *item;
	const struct input_command_entry *p = input_command_list;
			warning("No note found for %s.", private_ref);
}
		return 3;
	int code;
		strbuf_reset(&buf);
	}
			struct rev_note note = { 0 };
		code = start_command(&svndump_proc);
		if (!found)
static const struct input_command_entry input_command_list[] = {
	printf("feature import-marks-if-exists=%s\n"
		fclose(marksfile);
		if (strbuf_getline_lf(&buf, stdin) == EOF) {
	enum object_type type;
		get_git_dir(), remote->name);
	if (line->len == 0) {
};
		note_msg = read_ref_note(&head_oid);
	free_notes(NULL);
	{ "capabilities", cmd_capabilities, 0 },
	if (fprintf(file, ":%d %s\n", note.rev_nr, oid_to_hex(object_oid)) < 1)
	return -1;

#include "notes.h"
static const char *remote_ref = "refs/heads/master";
	printf("refspec %s:%s\n\n", remote_ref, private_ref);
			char *end;
	strbuf_release(&buf);
				found++;
	{ "import", cmd_import, 1 },
static int dump_from_file;
{
	}
		string_list_append(&batchlines, line->buf);
			batch_cmd = NULL;
		return 1;
		marksfile = xfopen(marksfilename, "r");
static void regenerate_marks(void)
#include "remote.h"
				return -1;
			}
			notes_ref_sb = STRBUF_INIT;
	size_t len;
static const char *marksfilename, *notes_ref;
			if (parse_rev_note(note_msg, &note))
{
		usage("git-remote-svn <remote-name> [<url>]");

	init_notes(NULL, notes_ref, NULL, 0);
}
	return 0;
	struct rev_note note;

	}
	enum object_type type;
int cmd_main(int argc, const char **argv)
			return p->fn(line->buf);
		}
	strbuf_release(&url_sb);
	return 0;

	free_notes(NULL);
	svndump_read(url, private_ref, notes_ref);
	ret = for_each_note(NULL, 0, note2mark_cb, marksfile);
		if (!starts_with(batch_cmd->name, line->buf))
	private_ref = private_ref_sb.buf;
	FILE *file = (FILE *)cb_data;
	{ "list", cmd_list, 0 },
	for (p = input_command_list; p->name; p++) {
		}
		url = url_sb.buf;
static int do_command(struct strbuf *line)
	marksfilename = marksfilename_sb.buf;
	setup_git_directory();
	fflush(stdout);
static int cmd_import(const char *line)
	printf("? %s\n\n", remote_ref);
#include "argv-array.h"

	 * During a batch all lines are buffered and passed to the handler function
	FILE *marksfile;
	while (1) {
	struct strbuf buf = STRBUF_INIT, url_sb = STRBUF_INIT,
{
	input_command_handler fn;
	 * when the batch is terminated.

		error("Empty notes tree. %s", notes_ref);
		if (code)
	unsigned long msglen;
			regenerate_marks();
	const char *key, *value, *end;
		len = end - msg;
	char *msg;
	while (*msg) {

{
	check_or_regenerate_marks(startrev - 1);
	if (latestrev < 1)
		msg += len + 1;
			terminate_batch();
		return 2;

			for_each_string_list_item(item, &batchlines)
	if (ret)
	unsigned int startrev;

	} else {
	if (starts_with(url_in, "file://")) {
	const char *url_in;
	printf("bidi-import\n");
	}
	return 0;

			string_list_clear(&batchlines, 0);

{
		if (code)
static const char *private_ref;
			else

		dumpin_fd = open(url, O_RDONLY);
				batch_cmd->fn(item->string);
	if (dump_from_file) {
{
	strbuf_release(&notes_ref_sb);
}

	}
	char *note_msg;
static int cmd_capabilities(const char *line);
		end_url_with_slash(&url_sb, url_in);
	const char *name;
			return 0;
	int dumpin_fd;
			res->rev_nr = i;
}
	strbuf_release(&private_ref_sb);
				line->buf[strlen(p->name)] == ' ')) {
			free(note_msg);
	}
