from mythic_container.MythicCommandBase import *
import json


class ScreenshotArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise Exception("hostinfo command takes no parameters.")


class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "screenshot"
    description = "Perform a screenshot"
    version = 1
    supported_ui_features = []
    author = "@hegusung"
    argument_class = ScreenshotArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[ SupportedOS.Windows ],
        suggested_command=False
    )
    attackmapping = []

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
