		printf(" oid_fanout");
		*(unsigned char*)(graph->data + 4),
	printf("num_commits: %u\n", graph->num_commits);

#include "cache.h"
	int fd;
		printf(" oid_lookup");
	graph_name = get_commit_graph_filename(odb);
	graph = load_commit_graph_one_fd_st(fd, &st, odb);
	open_ok = open_commit_graph(graph_name, &fd, &st);
		return 1;
#include "test-tool.h"
#include "object-store.h"
	odb = the_repository->objects->odb;
		*(unsigned char*)(graph->data + 7));

	char *graph_name;
	return 0;
	setup_git_directory();
	if (graph->chunk_extra_edges)

int cmd__read_graph(int argc, const char **argv)

	if (graph->chunk_oid_fanout)
	if (graph->chunk_oid_lookup)
	if (!open_ok)
	printf("header: %08x %d %d %d %d\n",
#include "repository.h"
		*(unsigned char*)(graph->data + 5),

	printf("\n");
	int open_ok;
		printf(" commit_metadata");
		printf(" extra_edges");
}
	struct stat st;
{
	struct commit_graph *graph = NULL;

	struct object_directory *odb;
#include "commit-graph.h"
	UNLEAK(graph);
	FREE_AND_NULL(graph_name);



	if (!graph)

		die_errno(_("Could not open commit-graph '%s'"), graph_name);
		*(unsigned char*)(graph->data + 6),
		ntohl(*(uint32_t*)graph->data),
	printf("chunks:");
	if (graph->chunk_commit_data)
