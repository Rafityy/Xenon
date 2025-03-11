#pragma once
#ifndef DOWNLOAD_H
#define DOWNLOAD_H

#include <windows.h>
#include "Parser.h"
#include "Config.h"

#ifdef INCLUDE_CMD_DOWNLOAD
#define MAX_PATH 0x2000

typedef struct _FILE_DOWNLOAD {
    HANDLE hFile;               // File handle
    CHAR fileUuid[37];          // File UUID (36 + 1 for null terminator)
    PCHAR filepath[MAX_PATH];   // Path to the file
    DWORD totalChunks;          // Total number of chunks
    UINT32 currentChunk;        // Current chunk number
    LARGE_INTEGER fileSize;     // Size of the file
} FILE_DOWNLOAD, *PFILE_DOWNLOAD;


VOID Download(_In_ PCHAR taskUuid, _In_ PPARSER arguments);

DWORD WINAPI DownloadThread(_In_ LPVOID lpTaskParamter);

#endif //INCLUDE_CMD_DOWNLOAD

#endif  //DOWNLOAD_H