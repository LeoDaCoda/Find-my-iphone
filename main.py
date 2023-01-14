import json
from icloud_rapper import IcloudWrapper
from flask import Flask
from flask_ask import Ask, statement, question, session, request

config_file_path = "my-app.json"
config_data = None

app = Flask(__name__)
ask = Ask(app, '/fmi')

@app.route("/fmi")
def hello_world():
    return "Hello World! This page is for debugging purposes."

@ask.launch
def find_phone_manager():
    try:
        api = IcloudWrapper(config_file_path)
    except:
        return statement("Error please contact backend for support!")

    devices = api.devices
    msg = ""
    if not api.favorite:
        msg = 'Select device to ping?  '
        for i, device in enumerate(devices):
            msg += f"{i}: {device}, "

    return question(msg)


@ask.intent("AMAZON.SelectIntent")
def select():
    try:
        selection = int(request.intent.slots.ListPosition.value)
        return statement(f"You selected {selection}")
    except:
        return statement("Debug 2")

if __name__ == '__main__':

    app.run(debug=True)
    api = IcloudWrapper(config_file_path)
    print(api.devices)
    phone = api.devices[3]
    print(phone.status())
    print(phone.location())
    phone.play_sound()



