#pragma once

#ifndef NETWORK_H
#define NETWORK_H

#include "Package.h"
#include "Parser.h"


VOID NetworkInitMutex();

BOOL NetworkRequest(PPackage package, PBYTE* ppOutData, SIZE_T* pOutLen);


#endif