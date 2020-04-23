		if (!r) {
	if (strbuf_read(&buffer, pass.out, 20) < 0)
			die("could not read %s%s", prompt, err);

	struct child_process pass = CHILD_PROCESS_INIT;
#include "compat/terminal.h"
		error("unable to read askpass response from '%s'", cmd);


	const char *args[3];
	strbuf_reset(&buffer);
	if (err) {
	return buffer.buf;
			r = git_terminal_prompt(prompt, flags & PROMPT_ECHO);
	if (start_command(&pass))


			/* prompts already contain ": " at the end */
			err = "terminal prompts disabled";
		if (askpass && *askpass)
char *git_prompt(const char *prompt, int flags)

{
	return ret;

		const char *askpass;

	strbuf_setlen(&buffer, strcspn(buffer.buf, "\r\n"));
			r = do_askpass(askpass, prompt);
			askpass = getenv("SSH_ASKPASS");

	args[1]	= prompt;
	}
int git_read_line_interactively(struct strbuf *line)
	pass.argv = args;


		return NULL;
	return r;
{

#include "run-command.h"
		err = 1;

			err = strerror(errno);
		return NULL;
#include "cache.h"
	args[2] = NULL;
	int err = 0;
		strbuf_trim_trailing_newline(line);
		const char *err;
}
			askpass = askpass_program;
	int ret;

{
	fflush(stdout);
}

		askpass = getenv("GIT_ASKPASS");
	if (finish_command(&pass))
#include "config.h"
	if (!r) {
static char *do_askpass(const char *cmd, const char *prompt)
	static struct strbuf buffer = STRBUF_INIT;
	char *r = NULL;
#include "strbuf.h"
	args[0] = cmd;

	if (ret != EOF)
	pass.out = -1;
		}
#include "prompt.h"


	}
	close(pass.out);
		strbuf_release(&buffer);
		if (!askpass)
		}
	ret = strbuf_getline_lf(line, stdin);
		err = 1;
		if (!askpass)
}
		} else {
	}
		if (git_env_bool("GIT_TERMINAL_PROMPT", 1)) {
	if (flags & PROMPT_ASKPASS) {
