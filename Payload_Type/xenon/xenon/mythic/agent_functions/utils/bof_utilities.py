'''
Ref: https://github.com/MythicAgents/Athena/blob/main/Payload_Type/athena/athena/mythic/agent_functions/athena_utils/bof_utilities.py
'''
import struct
import subprocess
import os
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

from .mythicrpc_utilities import *


# This function merge the output of the subtasks and mark the parent task as completed.
async def default_coff_completion_callback(completionMsg: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    out = ""
    response = PTTaskCompletionFunctionMessageResponse(Success=True, TaskStatus="success", Completed=True)
    responses = await SendMythicRPCResponseSearch(MythicRPCResponseSearchMessage(TaskID=completionMsg.SubtaskData.Task.ID))
    for output in responses.Responses:
        out += str(output.Response)
            
    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
        TaskID=completionMsg.TaskData.Task.ID,
        Response=f"{out}"
    ))
    return response

class CoffCommandBase(CommandBase):
    completion_functions = {"coff_completion_callback": default_coff_completion_callback}

