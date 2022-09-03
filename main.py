import json
# from icloud_rapper import IcloudWrapper
from flask import Flask
from flask_ask import Ask, statement, question, session

config_file_path = "my-app.json"
config_data = None

app = Flask(__name__)
ask = Ask(app, '/fmi')

@app.route("/fmi")
def hello_world():
    return "Hello World! This page is for debugging purposes."

@ask.launch
def find_phone_manager():
    return statement("Hello, finding phone")


if __name__ == '__main__':

    app.run(debug=True)
    # api = IcloudWrapper(config_file_path)
    # print(api.devices)
    # phone = api.devices[1]
    # print(phone.status())
    # print(phone.location())
    # phone.play_sound()



