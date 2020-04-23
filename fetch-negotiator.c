#include "negotiator/skipping.h"
void fetch_negotiator_init(struct repository *r,
#include "git-compat-util.h"
		return;
		skipping_negotiator_init(negotiator);
{

			   struct fetch_negotiator *negotiator)
	case FETCH_NEGOTIATION_SKIPPING:
#include "repository.h"
}
		return;
	}

	switch(r->settings.fetch_negotiation_algorithm) {
	case FETCH_NEGOTIATION_DEFAULT:
#include "fetch-negotiator.h"
#include "negotiator/default.h"
	default:
		default_negotiator_init(negotiator);
	prepare_repo_settings(r);
