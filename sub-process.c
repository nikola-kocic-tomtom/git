	int len;
 * Generic implementation of background process infrastructure.
	sigchain_pop(SIGPIPE);

	struct child_process *process = &entry->process;
		}
	process->clean_on_exit_handler = subprocess_exit_handler;
			     const char *welcome_prefix, int *versions,
}

	if (err) {
{
{
		return err;
		} else {
			break;
	process->use_shell = 1;


		 handshake_capabilities(process, capabilities,
	e2 = container_of(entry_or_key, const struct subprocess_entry, ent);
	sigchain_push(SIGPIPE, SIG_IGN);
	if (err) {

		len = packet_read_line_gently(fd, NULL, &line);
			 int *versions,
		return error("Unexpected line '%s', expected version",
			return error("Could not write requested capability");
	return strcmp(e1->cmd, e2->cmd);

	close(process->out);
/*
			     line ? line : "<flush packet>");

				  unsigned int *supported_capabilities)

}
			/* the last "status=<foo>" line wins */
	const char *p;
	int version_scratch;
			 const char *welcome_prefix,
	char *line;

	entry->process.clean_on_exit = 0;
	const struct subprocess_entry *e1, *e2;
	return 0;
}
	for (i = 0; capabilities[i].name; i++) {
 */
		const char *p;
	if (!(line = packet_read_line(process->out, NULL)) ||
	    !skip_prefix(line, welcome_prefix, &p) ||
	if (!versions[i])
struct subprocess_entry *subprocess_find_entry(struct hashmap *hashmap, const char *cmd)
	if (!entry)
		if ((len < 0) || !line)
			 int *chosen_version,
		subprocess_stop(hashmap, entry);
	return (len < 0) ? len : 0;

			}
		error("cannot fork to run subprocess '%s'", cmd);
	}
		    const struct hashmap_entry *eptr,
	hashmap_entry_init(&key.ent, strhash(cmd));

int cmd2process_cmp(const void *unused_cmp_data,
{
	process->clean_on_exit = 1;

				  struct subprocess_capability *capabilities,
		if (packet_write_fmt_gently(process->in, "version=%d\n",

	child_process_init(process);
	    !skip_prefix(line, "version=", &p) ||
	}
	/* Check to make sure that the version received is supported */
	return retval;
	subprocess_start_fn startfn)

			 struct subprocess_capability *capabilities,
		     i++)
	finish_command(&entry->process);
	close(process->in);
	if (packet_flush_gently(process->in))
int subprocess_read_status(int fd, struct strbuf *status)
			 unsigned int *supported_capabilities)
		return error("Could not write client identification");
	int err;
	retval = handshake_version(process, welcome_prefix, versions,
static int handshake_capabilities(struct child_process *process,
	/* Finish command will wait until the shutdown is complete. */
}
	process->trace2_child_class = "subprocess";
			if (!strcmp(pair[0]->buf, "status=")) {


				   chosen_version) ||
		    const struct hashmap_entry *entry_or_key,
{

			     int *chosen_version)
		for (i = 0;
			continue;
#include "sub-process.h"
		chosen_version = &version_scratch;
int subprocess_start(struct hashmap *hashmap, struct subprocess_entry *entry, const char *cmd,
		strbuf_list_free(pair);
static void subprocess_exit_handler(struct child_process *process)
	err = startfn(entry);
#include "sigchain.h"


		return error("Unexpected line '%s', expected flush", line);
{
	}
}
		return error("Could not write flush packet");



	process->in = -1;
{
	char *line;
}
	e1 = container_of(eptr, const struct subprocess_entry, ent);
		return err;
				strbuf_reset(status);
	sigchain_pop(SIGPIPE);
	int retval;
				    welcome_prefix))
		error("initialization for subprocess '%s' failed", cmd);
		if (capabilities[i].name) {
		}

					supported_capabilities);
	    strtol_i(p, 10, chosen_version))
	sigchain_push(SIGPIPE, SIG_IGN);
}
	while ((line = packet_read_line(process->out, NULL))) {
	struct child_process *process;
	if (packet_flush_gently(process->in))
	    strcmp(p, "-server"))
					    capabilities[i].name))
	if (packet_write_fmt_gently(process->in, "%s-client\n",

		if (versions[i] == *chosen_version)
	return 0;
	}
	int i;
		return error("Version %d not supported", *chosen_version);
			     line ? line : "<flush packet>", welcome_prefix);
		if (!skip_prefix(line, "capability=", &p))
				strbuf_addbuf(status, pair[1]);
	kill(entry->process.pid, SIGTERM);
	if ((line = packet_read_line(process->out, NULL)))
	/* Closing the pipe signals the subprocess to initiate a shutdown. */
	hashmap_add(hashmap, &entry->ent);
}
			if (supported_capabilities)
	process->out = -1;
			die("subprocess '%s' requested unsupported capability '%s'",

		     capabilities[i].name && strcmp(p, capabilities[i].name);
			;
	}
		pair = strbuf_split_str(line, '=', 2);
	if (!(line = packet_read_line(process->out, NULL)) ||
			break;

	for (i = 0; versions[i]; i++) {
	argv_array_push(&process->args, cmd);
	for (;;) {
	return 0;
		if (packet_write_fmt_gently(process->in, "capability=%s\n",
	char *line;
int subprocess_handshake(struct subprocess_entry *entry,

	if (!chosen_version)
	entry->cmd = cmd;
	struct subprocess_entry key;
		if (pair[0] && pair[0]->len && pair[1]) {
{
		return;
	key.cmd = cmd;
	return hashmap_get_entry(hashmap, &key, ent, NULL);
		return error("Unexpected line '%s', expected %s-server",

	err = start_command(process);
{
	}
static int handshake_version(struct child_process *process,
			return error("Could not write requested version");
	int i;

#include "pkt-line.h"

		return error("Could not write flush packet");
				*supported_capabilities |= capabilities[i].flag;
}
		    const void *unused_keydata)
			    process->argv[0], p);
	finish_command(process);
	}
	struct strbuf **pair;



	for (i = 0; versions[i]; i++) {
					    versions[i]))
{
	hashmap_entry_init(&entry->ent, strhash(cmd));
	hashmap_remove(hashmap, &entry->ent, NULL);
	process = &entry->process;

void subprocess_stop(struct hashmap *hashmap, struct subprocess_entry *entry)
