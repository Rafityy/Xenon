#pragma once
#ifndef MICROPHONE_H
#define MICROPHONE_H

#include <windows.h>
#include "Parser.h"
#include "Config.h"

#ifdef INCLUDE_CMD_MICROPHONE
#define MAX_PATH 0x2000

typedef struct _MICROPHONE_DOWNLOAD {
    unsigned char* microphone_data;
    DWORD microphone_size;
    CHAR fileUuid[37];          // File UUID (36 + 1 for null terminator)
    PCHAR filepath[MAX_PATH];   // Path to the file
    DWORD totalChunks;          // Total number of chunks
    UINT32 currentChunk;        // Current chunk number
    LARGE_INTEGER fileSize;     // Size of the file
} MICROPHONE_DOWNLOAD, *PMICROPHONE_DOWNLOAD;


VOID Microphone(_In_ PCHAR taskUuid, _In_ PPARSER arguments);

DWORD WINAPI MicrophoneThread(_In_ LPVOID lpTaskParamter);

#endif //INCLUDE_CMD_MICROPHONE

#endif  //MICROPHONE_H
