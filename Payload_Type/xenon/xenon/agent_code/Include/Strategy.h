#pragma once

#ifndef STRATEGY_H
#define STRATEGY_H

#include <windows.h>

VOID StrategyRotate(_In_ BOOL isConnectionSuccess, _Inout_ int* attempts);

#endif