
	int n;
	check_signum(sig);
	if (s->old[s->n] == SIG_ERR)
	if (s->n < 1)
{
};
}
	sigchain_pop(SIGINT);
{
struct sigchain_signal {
}
{
	sigchain_push(SIGHUP, f);

	sigchain_push(SIGQUIT, f);
	s->old[s->n] = signal(sig, f);
}
static void check_signum(int sig)
#include "sigchain.h"
		return -1;
	sigchain_push(SIGPIPE, f);
	sigchain_pop(SIGPIPE);
	sigchain_pop(SIGQUIT);
		BUG("signal out of range: %d", sig);
}
	s->n++;
		return -1;
#include "cache.h"

	sigchain_pop(SIGTERM);
	return 0;
{

int sigchain_pop(int sig)
{
	int alloc;
		return 0;
static struct sigchain_signal signals[SIGCHAIN_MAX_SIGNALS];

	sigchain_push(SIGINT, f);
#define SIGCHAIN_MAX_SIGNALS 32

}
	if (sig < 1 || sig >= SIGCHAIN_MAX_SIGNALS)
	ALLOC_GROW(s->old, s->n + 1, s->alloc);
	sigchain_fun *old;



	sigchain_push(SIGTERM, f);
void sigchain_pop_common(void)
	s->n--;
	sigchain_pop(SIGHUP);
	struct sigchain_signal *s = signals + sig;
	return 0;
	check_signum(sig);
void sigchain_push_common(sigchain_fun f)
	struct sigchain_signal *s = signals + sig;
int sigchain_push(int sig, sigchain_fun f)
	if (signal(sig, s->old[s->n - 1]) == SIG_ERR)
