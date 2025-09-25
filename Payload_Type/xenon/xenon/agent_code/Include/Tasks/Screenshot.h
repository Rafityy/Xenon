#pragma once
#ifndef SCREENSHOT_H
#define SCREENSHOT_H

#include <windows.h>
#include "Parser.h"
#include "Config.h"

#ifdef INCLUDE_CMD_SCREENSHOT
#define MAX_PATH 0x2000

typedef struct _SCREENSHOT_DOWNLOAD {
    unsigned char* screenshot_data;
    DWORD screenshot_size;
    CHAR fileUuid[37];          // File UUID (36 + 1 for null terminator)
    PCHAR filepath[MAX_PATH];   // Path to the file
    DWORD totalChunks;          // Total number of chunks
    UINT32 currentChunk;        // Current chunk number
    LARGE_INTEGER fileSize;     // Size of the file
} SCREENSHOT_DOWNLOAD, *PSCREENSHOT_DOWNLOAD;


VOID Screenshot(_In_ PCHAR taskUuid, _In_ PPARSER arguments);

DWORD WINAPI ScreenshotThread(_In_ LPVOID lpTaskParamter);

#endif //INCLUDE_CMD_SCREENSHOT

#endif  //SCREENSHOT_H
