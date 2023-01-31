import json
from icloud_rapper import IcloudWrapper
from flask import Flask
from flask_ask import Ask, statement, question, session, request

config_file_path = "my-app.json"
config_data = None


# credit https://stackoverflow.com/a/14903399
# allows icloud wrapper api to only have to be initialized once and
# be used throughout the various program states
def run_app(icloud_api):
    app = Flask(__name__)
    ask = Ask(app, '/fmi')
    app.config["icloud_api"] = icloud_api

    return app, ask


api = IcloudWrapper(config_file_path)
app, ask = run_app(api)


@app.route("/fmi")
def hello_world():
    return "Hello World! This page is for debugging purposes."


@ask.launch
def find_phone_manager():
    # Cookies
    app.config["phone"] = None
    app.config["selection"] = None
    # Navigation cookies help the backend keep track of the programs current state
    # by appending the previous state seperated by a "." delimiter
    app.config["navigation_cookie"] = "launchState"

    try:
        api = app.config["icloud_api"]

    except:
        return statement("Error please contact backend for support!")

    devices = api.devices
    msg = ""
    if not api.favorite:
        msg = 'Select device to ping?  '
        for i, device in enumerate(devices):
            msg += f"{i+1}: {device}, "

        return question(msg)
    else:
        pass
        confirm_favorite()


@ask.intent("AMAZON.SelectIntent")
def select():
    app.config["navigation_cookie"] += ".selectState"
    try:
        selection = int(request.intent.slots.ListPosition.value)
        # return statement(f"You selected {selection}")
        api = app.config['icloud_api']
        devices = api.devices
        phone = devices[selection-1]
        app.config["selection"] = selection
        app.config["phone"] = phone

        if 1 <= selection <= api.num_devices:
            msg = f"Would you like to make {phone} your favorite?"
            return question(msg)
        else:
            raise Exception("Out of Range")
    except:
        return statement("Debug 2")


def confirm_favorite():
    return question("Would you like to ping your favorite device?")


def ping(phone):
    phone.play_sound()

@ask.intent("NoMakeFavorite")
def no_make_favorite():
    app.config["navigation_cookie"] += ".noMakeFavoriteState"

    phone = app.config["phone"]
    ping(phone)
    return statement("Here")


@ask.intent("YesMakeFavorite")
def yes_make_favorite():
    app.config["navigation_cookie"] += ".yesMakeFavoriteState"

    phone = app.config["phone"]
    selection = app.config["selection"]
    api = app.config["icloud_api"]
    api.make_favorite(selection)
    ping(phone)
    return statement("Here")



if __name__ == '__main__':
    # # app.run(debug=True)
    # api = IcloudWrapper(config_file_path)
    # print(api.devices)
    # phone = api.devices[3]
    # print(phone.status())
    # print(phone.location())
    # #phone.play_sound()

    app.run(debug=True)
