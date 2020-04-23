		jw_end(&jw);

				   "windows/debugger_present", 1);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
 *       stops when an ancestor process is not found in the snapshot
 *
			}
	}
		get_is_being_debugged();
 *
 *
			if (pid == pid_list[k]) {

		return;
				return;
 */
 *       refers to the PID of an exited parent and that PID has been
	DECLARE_PROC_ADDR(psapi.dll, BOOL, GetProcessMemoryInfo, HANDLE,
		struct json_writer jw = JSON_WRITER_INIT;
		get_ancestry();
		if (nr_pids == NR_PIDS_LIMIT) {

}
static void get_peak_memory_info(void)
	pid = GetCurrentProcessId();
{
	if (INIT_PROC_ADDR(GetProcessMemoryInfo)) {
}
 *
/*
		do {
			return;
 * it will not report instances where a debugger is attached dynamically
	case TRACE2_PROCESS_INFO_EXIT:
			  PPROCESS_MEMORY_COUNTERS, DWORD);
		jw_array_begin(&jw, 0);
/*
 * array built in git_processes().
{
 *


 * We use a fixed-size array rather than ALLOC_GROW to keep things
/*
#include "../../cache.h"
			jw_object_intmax(&jw, KV(PeakWorkingSetSize));
		pid = pe32.th32ParentProcessID;
	}
 * Emit JSON data with the peak memory usage of the current process.
 *       PID recycling, it might be possible to get a PPID link value
}
			struct json_writer jw = JSON_WRITER_INIT;
 *       This search may compute an incorrect result if the PPID link
					 "windows/memory", &jw);
 *       of 0.  This too would cause an infinite loop.
		trace2_data_json("process", the_repository, "windows/ancestry",
 */
	while (find_pid(pid, hSnapshot, &pe32)) {
				jw_array_string(jw, "(cycle)");
void trace2_collect_process_info(enum trace2_process_info_reason reason)

static void get_processes(struct json_writer *jw, HANDLE hSnapshot)
/*
				 &jw);
 *
			trace2_data_json("process", the_repository,
/*
 * Find the process data for the given PID in the given snapshot
 *       Git to be a descendant of the idle process, but because of
 * Emit JSON data for the current and parent processes.  Individual
	int k, nr_pids = 0;
 */
	}

 *       process exited).
 * trace2 targets can decide how to actually print it.
		/* Check for cycle in snapshot. (Yes, it happened.) */
 * truncate the search and return a partial answer.

#include <Psapi.h>
 *       recycled and given to a new unrelated process.
 *         ...
 * An arbitrarily chosen value to limit the size of the ancestor
 *       current process to be given the recycled PID and cause a
		get_peak_memory_info();
#include <tlHelp32.h>
{
#include "lazyload.h"
#include "../../json-writer.h"
 *       link in each visited PROCESSENTRY32 record.  This search
	DWORD pid_list[NR_PIDS_LIMIT];

		return;


 *       and that seems rather expensive (on top of the cost of
		jw_release(&jw);

{

#define NR_PIDS_LIMIT 10
static void get_is_being_debugged(void)
 *         exe-name-grand-parent,
			if (pe32->th32ProcessID == pid)
 *     [
	}
		return;
/*
			jw_object_intmax(&jw, KV(PageFaultCount));
{
 */

	return 0;
	case TRACE2_PROCESS_INFO_STARTUP:

}
 *     ]

 */
 * Is a debugger attached to the current process?
			jw_object_intmax(&jw, KV(PeakPagefileUsage));
 * simple and avoid the alloc/realloc overhead.  It is OK if we
	if (IsDebuggerPresent())

#define KV(kv) #kv, (intmax_t)pmc.kv
 * and update the PROCESSENTRY32 data.
		CloseHandle(hSnapshot);

static void get_ancestry(void)
	PROCESSENTRY32 pe32;
		PROCESS_MEMORY_COUNTERS pmc;
 * to a running git process, but that is relatively rare.
 *
	DWORD pid;
			jw_array_string(jw, "(truncated)");

 *         exe-name-parent,
 * Accumulate JSON array of our parent processes:

 */

				return 1;

		get_processes(&jw, hSnapshot);
 * Therefore, we keep an array of the visited PPIDs to guard against
}
			jw_array_string(jw, pe32.szExeFile);
 *       (because it exited before the current or intermediate parent
 *
		BUG("trace2_collect_process_info: unknown reason '%d'", reason);
	default:
 * Note: we only report the filename of the process executable; the
		pid_list[nr_pids++] = pid;
	}
	pe32->dwSize = sizeof(PROCESSENTRY32);

			jw_object_begin(&jw, 0);
	if (!trace2_is_enabled())
 * This is the normal case.  Since this code is called during our startup,
		/* Only report parents. Omit self from the JSON output. */
 * Note: we compute the set of parent processes by walking the PPID
 *       PPID=0 and could cause another PPID-cycle.  We don't expect


			jw_end(&jw);
 *       and GetModuleFileNameEx() or QueryfullProcessImageName()
	if (Process32First(hSnapshot, pe32)) {
 *       Worse, it is possible for a child or descendant of the
 * This will catch debug runs (where the debugger started the process).
 *       parent process array.
					 sizeof(pmc))) {
		}

		if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc,
	switch (reason) {
		trace2_data_intmax("process", the_repository,
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
 * cycles.
			jw_release(&jw);
		if (nr_pids)

 * Note: for completeness, the "System Idle" process has PID=0 and
		}
 *       getting the snapshot).
}
		} while (Process32Next(hSnapshot, pe32));
static int find_pid(DWORD pid, HANDLE hSnapshot, PROCESSENTRY32 *pe32)
 *       only way to get its full pathname is to use OpenProcess()
 *       PPID-cycle.  This would cause an infinite loop building our
		for (k = 0; k < nr_pids; k++)
{
