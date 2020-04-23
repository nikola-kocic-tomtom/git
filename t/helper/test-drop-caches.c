
	int status;
		return error("Unable to open volume for writing, need admin access");

	char szVolumeAccessPath[] = "\\\\.\\XXXX:";

	HANDLE hProcess = GetCurrentProcess();

		}
{
	return bResult;
}
	return system("sudo purge");

	MemoryEmptyWorkingSets,


		error("Unable to flush volume");
		SystemMemoryListInformation,
	if ((0 == dwRet) || (dwRet > MAX_PATH))

{
	if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))

			&tpPreviousState, &dwBufferLength);
	CloseHandle(hToken);
	szVolumeAccessPath[dos_drive_prefix] = '\0';
typedef enum _SYSTEM_MEMORY_LIST_COMMAND {
		return error("Could not find NtSetSystemInformation() function");
{
	if (bResult) {
		tpNewState.Privileges[0].Luid = luid;
	HANDLE hToken;
#include "test-tool.h"
	if (!GetPrivilege(hToken, "SeProfileSingleProcessPrivilege", 1))
	);
	SystemMemoryListInformation = 80,
{
			tpPreviousState.Privileges[0].Luid = luid;
			(DWORD)((LPBYTE)&(tpNewState.Privileges[1]) - (LPBYTE)&tpNewState),
		&command,
	char Buffer[MAX_PATH];
		if (bResult) {
		return error("Can't get SeProfileSingleProcessPrivilege");
	DWORD dwRet;
	if (INVALID_HANDLE_VALUE == hVolWrite)

	if (status == STATUS_PRIVILEGE_NOT_HELD)
{
	return status;
}
			tpPreviousState.PrivilegeCount = 1;
	success = FlushFileBuffers(hVolWrite);
	return system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
}
static int cmd_sync(void)
		tpNewState.PrivilegeCount = 1;
			tpPreviousState.Privileges[0].Attributes = flags != 0 ? 2 : 0;
int cmd__drop_caches(int argc, const char **argv)
}
	MemoryCaptureAccessedBits,
#else

	return system("sync");
#define STATUS_PRIVILEGE_NOT_HELD	(0xC0000061L)
} SYSTEM_MEMORY_LIST_COMMAND;
		error("Insufficient privileges to purge the standby list, need admin access");
	dos_drive_prefix = has_dos_drive_prefix(Buffer);
	TOKEN_PRIVILEGES tpNewState;

static int cmd_dropcaches(void)
}
	MemoryPurgeLowPriorityStandbyList,
	CloseHandle(hVolWrite);
	status = NtSetSystemInformation(
		error("Unable to execute the memory list command %d", status);
	return system("sync");
#elif defined(__linux__)
	if (!success)

	}
	LUID luid;
	return cmd_dropcaches();


	SYSTEM_MEMORY_LIST_COMMAND command;
	MemoryPurgeStandbyList,
	hVolWrite = CreateFile(szVolumeAccessPath, GENERIC_READ | GENERIC_WRITE,
		sizeof(SYSTEM_MEMORY_LIST_COMMAND)
	int success = 0, dos_drive_prefix;
}
#define STATUS_SUCCESS			(0x00000000L)
	memcpy(szVolumeAccessPath, Buffer, dos_drive_prefix);
{
	dwBufferLength = 16;
	DWORD dwBufferLength;
	dwRet = GetCurrentDirectory(MAX_PATH, Buffer);
		return error("Can't open current process token");
}
	else if (status != STATUS_SUCCESS)
	bResult = LookupPrivilegeValueA(0, lpName, &luid);

#if defined(GIT_WINDOWS_NATIVE)
	TOKEN_PRIVILEGES tpPreviousState;
static int cmd_sync(void)
#include "lazyload.h"

}
static int cmd_dropcaches(void)
	return 0;
	MemoryFlushModifiedList,
	cmd_sync();

#endif

} SYSTEM_INFORMATION_CLASS;

	BOOL bResult;
	return error("drop caches not implemented on this platform");

		return error("'%s': invalid drive letter", Buffer);

static int cmd_sync(void)
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE hVolWrite;
static BOOL GetPrivilege(HANDLE TokenHandle, LPCSTR lpName, int flags)
	if (!dos_drive_prefix)
{
	MemoryCommandMax
	MemoryCaptureAndResetAccessedBits,

			bResult = AdjustTokenPrivileges(TokenHandle, 0, &tpPreviousState,
{
				dwBufferLength, 0, 0);
#include "git-compat-util.h"


{
static int cmd_dropcaches(void)

}

	DECLARE_PROC_ADDR(ntdll.dll, DWORD, NtSetSystemInformation, INT, PVOID, ULONG);

		return error("Error getting current directory");
		tpNewState.Privileges[0].Attributes = 0;
	command = MemoryPurgeStandbyList;
}

static int cmd_dropcaches(void)
	if (!INIT_PROC_ADDR(NtSetSystemInformation))
static int cmd_sync(void)

{

#elif defined(__APPLE__)

typedef enum _SYSTEM_INFORMATION_CLASS {
	return !success;
		bResult = AdjustTokenPrivileges(TokenHandle, 0, &tpNewState,
