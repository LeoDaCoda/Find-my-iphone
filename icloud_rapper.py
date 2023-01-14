import json

from icloud import PyiCloudService
from os import path
from icloud_exceptions import PyiCloudException


class IcloudWrapper:

    def __init__(self, config_file_path='my-app.json'):
        self.__username = None
        self.__password = None
        self.favorite = None
        self.api = None
        self.config_file_path = config_file_path
        self.__start_icloud_session()

    def __get_pass_from_config(self):
        if not (path.exists(self.config_file_path)):
            print("LOG, config file: %s does not exists" % self.config_file_path)
            raise Exception("Config file does not exists!")

        with open(self.config_file_path) as f:
            config_data = json.load(f)

            try:
                self.__username = config_data['username']
                self.__password = config_data['password']
                self.favorite = config_data['favorite']
            except KeyError:
                print("Config file is incorrectly formatted.")
                raise Exception("Config file is incorrectly formatted")

    def __start_icloud_session(self):
        self.__get_pass_from_config()
        try:
            api = PyiCloudService(self.__username, self.__password)
        except PyiCloudException:
            print("Could not authenticate with server")
            raise Exception("Could not authenticate with server")
        self.api = api

    @property
    def devices(self):
        return self.api.devices






