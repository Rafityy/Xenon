#pragma once
#ifndef SHELL_H
#define SHELL_H

#include <windows.h>
#include "Parser.h"
#include "Config.h"

#ifdef INCLUDE_CMD_SHELL
VOID ShellCmd(PCHAR taskUuid, PPARSER arguments);
#endif

#endif //SHELL_H