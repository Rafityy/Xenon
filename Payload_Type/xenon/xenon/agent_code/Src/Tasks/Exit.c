#include "Tasks/Exit.h"

#include "Parser.h"
#include <processthreadsapi.h>

VOID Exit(PCHAR taskUuid, PPARSER arguments)
{
    PackageComplete(taskUuid, NULL);
    ExitProcess(0);
}