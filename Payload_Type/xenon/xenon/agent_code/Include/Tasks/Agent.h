#pragma once
#ifndef AGENT_H
#define AGENT_H

#include <windows.h>
#include "Parser.h"

VOID AgentSleep(_In_ PCHAR taskUuid, _In_ PPARSER arguments);

#endif  //AGENT_H
