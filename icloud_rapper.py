import json

from icloud import PyiCloudService
from os import path

class IcloudWrapper:

    def __init__(self, config_file_path='my-app.json'):
        self.__username = None
        self.__password = None
        self.config_file_path = config_file_path

    def __get_pass_from_config(self):
        if not (path.exists(self.config_file_path)):
            print("LOG, config file: %s does not exists" % self.config_file_path)
            raise Exception("Config file does not exists!")

        with open(self.config_file_path) as f:
            config_data = json.load(f)

            try:
                self.__username = config_data['username']
                self.__password = config_data['password']
            except KeyError:
                print("Config file is incorrectly formatted.")
                raise Exception("Config file is incorrectly formatted")

    def start_icloud_session(self):
        pass



