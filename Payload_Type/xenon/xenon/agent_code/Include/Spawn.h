#pragma once

#ifndef NATIVE_H
#define NATIVE_H


#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

BOOL IsWow64ProcessEx(HANDLE hProcess);

extern int osMajorVersion;


#endif