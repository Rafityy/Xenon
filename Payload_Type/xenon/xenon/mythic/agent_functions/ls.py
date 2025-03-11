from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import re
import string, json

import logging

logging.basicConfig(level=logging.INFO)

class LsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="filepath", 
                type=ParameterType.String, 
                description="Path of file or folder on the current system to list",
                parameter_group_info=[ParameterGroupInfo(
                    required=False
                )]
            ),
        ]

    async def parse_arguments(self):
        logging.info("Parse Aguments")
        pass

    async def parse_dictionary(self, dictionary):
        logging.info("Parse Dictionary")
        if "host" in dictionary: 
            # Then this came from File Browser UI
            logging.info(f"Command came from File Browser UI - {dictionary}")
            self.add_arg("filepath", dictionary["path"] + "\\" + dictionary["file"])
            # self.add_arg("file_browser", type=ParameterType.Boolean, value=True)
        else:
            # Arguments came from command line
            logging.info(f"Command came from CMDLINE - {dictionary}")
            
            arg_path = dictionary.get("filepath")
            if arg_path:
                self.add_arg("filepath", arg_path)
            else:
                self.add_arg("filepath", ".\\*")    # List current directory if no args
           
        self.add_arg("file_browser", "true")

        self.load_args_from_dictionary(dictionary)

class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls [directory]"
    description = "List directory information for <directory>"
    version = 1
    supported_ui_features = ["file_browser:list"]
    author = "@c0rnbread"
    attackmapping = ["T1106", "T1083"]
    argument_class = LsArguments
    browser_script = BrowserScript(
        script_name="ls_new", author="@c0rnbread", for_new_ui=True
    )
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[ SupportedOS.Windows ],
        suggested_command=True
    )

    # async def create_tasking(self, task: MythicTask) -> MythicTask:
    #     task.display_params = task.args.get_arg("command")
    #     return task
    
    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        path = taskData.args.get_arg("filepath")
        logging.info(f"create_go_tasking - path : {path}")
        response.DisplayParams = path
        
        # 
        if uncmatch := re.match(r"^\\\\(?P<host>[^\\]+)\\(?P<path>.*)$", path):
            taskData.args.add_arg("host", uncmatch.group("host"))
            taskData.args.set_arg("path", uncmatch.group("path"))
        else:
            # Set the host argument to an empty string if it does not exist
            taskData.args.add_arg("host", "")
        if host := taskData.args.get_arg("host"):
            host = host.upper()

            # Resolve 'localhost' and '127.0.0.1' aliases
            if host == "127.0.0.1" or host.lower() == "localhost":
                host = taskData.Callback.Host

            taskData.args.set_arg("host", host)

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp