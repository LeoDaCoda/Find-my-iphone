import json
from icloud_rapper import IcloudWrapper

config_file_path = "my-app.json"
config_data = None
if __name__ == '__main__':
    # with open(config_file_path) as config_file:
    #     config_data = json.load(config_file)
    # username = config_data["username"]
    # password = config_data["password"]
    #
    # api = Icloud(username, password)
    # devices = api.devices
    api = IcloudWrapper(config_file_path)



