/*
    Includes functions for querying systeminfo and injection.

	TODO - Clean up in future and resolve a bunch of native functions (maybe peb walk)
*/

#include "Xenon.h"
#include "Spawn.h"


#define ProcessWow64Information 26

int osMajorVersion;

// Get Major Version
BOOL SelfIsWindowsVistaOrLater()
{
#define MAX_INFO 256
#define MAX_COMPUTER_NAME 256
#define MAX_USER_NAME 256
#define MAX_FILE_NAME 256

	// PPARSER parser = BeaconDataAlloc(sizeof(OSVERSIONINFOA));
	PPARSER parser = ParserAlloc(sizeof(OSVERSIONINFOA));

    // OSVERSIONINFOA* osVersionInfo = BeaconDataPtr(parser, sizeof(OSVERSIONINFOA));
    OSVERSIONINFOA* osVersionInfo = ParserGetDataPtr(parser, sizeof(OSVERSIONINFOA));

	osVersionInfo->dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
	GetVersionExA(osVersionInfo);
	osMajorVersion = osVersionInfo->dwMajorVersion;


	BOOL isWindowsVistaOrLater = osMajorVersion >= (_WIN32_WINNT_VISTA >> 8);

    ParserDestroy(parser);

    return isWindowsVistaOrLater;
}

typedef WINBASEAPI BOOL(WINAPI* FN_KERNEL32_ISWOW64PROCESS)(_In_ HANDLE hProcess, _Out_ PBOOL Wow64Process);

BOOL IsWow64ProcessEx(HANDLE hProcess)
{
	HMODULE hModule = GetModuleHandleA("kernel32");
	FN_KERNEL32_ISWOW64PROCESS _IsWow64Process = (FN_KERNEL32_ISWOW64PROCESS)GetProcAddress(hModule, "IsWow64Process");
	if (_IsWow64Process == NULL)
	{
		_err("kernel32$IsWow64Process: IsWow64Process is NULL");
        return FALSE;
	}

	BOOL bStatus 		= FALSE;	
	BOOL Wow64Process 	= FALSE;

	// bStatus = _IsWow64Process(hProcess, &Wow64Process);
	bStatus = _IsWow64Process(hProcess, &Wow64Process);
	if (!bStatus)
	{
		_err("_IsWow64Process failed with status code : %d", GetLastError());
		return FALSE;
	}

	return Wow64Process;		// TODO bug ! - returns 0 (x86) for current process?
}
