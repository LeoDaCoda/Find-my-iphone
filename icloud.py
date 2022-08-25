# Author LeoDaCoda Github: https://github.com/LeoDaCoda
# All rights reserved

# credit to https://github.com/picklepete/pyicloud
# This repo contains a comprehensive python API to access icloud services (eg photos, drive, etc)
# I used several classes from this repo to authenticate ith the icloud server and to ping the find my icloud feature



import json
from re import match
from uuid import uuid1
from os import path
from tempfile import  gettempdir
from requests import Session
import http.cookiejar as cookielib
import getpass
from icloud_exceptions import *


HEADER_DATA = {
    "X-Apple-ID-Account-Country": "account_country",
    "X-Apple-ID-Session-Id": "session_id",
    "X-Apple-Session-Token": "session_token",
    "X-Apple-TwoSV-Trust-Token": "trust_token",
    "scnt": "scnt",
}


class PyiCloudSession(Session):
    """iCloud session."""

    def __init__(self, service):
        self.service = service
        super().__init__()

    def request(self, method, url, **kwargs):  # pylint: disable=arguments-differ

        # # Charge logging to the right service endpoint
        # callee = inspect.stack()[2]
        # module = inspect.getmodule(callee[0])
        # request_logger = logging.getLogger(module.__name__).getChild("http")
        # if self.service.password_filter not in request_logger.filters:
        #     request_logger.addFilter(self.service.password_filter)
        #
        # request_logger.debug("%s %s %s", method, url, kwargs.get("data", ""))

        has_retried = kwargs.get("retried")
        kwargs.pop("retried", None)
        response = super().request(method, url, **kwargs)

        content_type = response.headers.get("Content-Type", "").split(";")[0]
        json_mimetypes = ["application/json", "text/json"]


        # Saves header into session_data
        for header, value in HEADER_DATA.items():
            if response.headers.get(header):
                session_arg = value
                self.service.session_data.update(
                    {session_arg: response.headers.get(header)}
                )

        # Save session_data to file
        with open(self.service.session_path, "w", encoding="utf-8") as outfile:
            json.dump(self.service.session_data, outfile)
            # LOGGER.debug("Saved session data to file")

        # Save cookies to file
        self.cookies.save(ignore_discard=True, ignore_expires=True)
        # LOGGER.debug("Cookies saved to %s", self.service.cookiejar_path)

        if not response.ok and (
            content_type not in json_mimetypes
            or response.status_code in [421, 450, 500]
        ):
            try:
                # pylint: disable=protected-access
                fmip_url = self.service._get_webservice_url("findme")
                if (
                    has_retried is None
                    and response.status_code in [421, 450, 500]
                    and fmip_url in url
                ):
                    # Handle re-authentication for Find My iPhone
                    # LOGGER.debug("Re-authenticating Find My iPhone service")
                    try:
                        # If 450, authentication requires a full sign in to the account
                        service = None if response.status_code == 450 else "find"
                        self.service.authenticate(True, service)

                    except PyiCloudAPIResponseException:
                        # LOGGER.debug("Re-authentication failed")
                        print("Re-authentication failed")
                    kwargs["retried"] = True
                    return self.request(method, url, **kwargs)
            except Exception:
                pass

            if has_retried is None and response.status_code in [421, 450, 500]:
                api_error = PyiCloudAPIResponseException(
                    response.reason, response.status_code, retry=True
                )
                # request_logger.debug(api_error)
                kwargs["retried"] = True
                return self.request(method, url, **kwargs)

            self._raise_error(response.status_code, response.reason)

        if content_type not in json_mimetypes:
            return response

        try:
            data = response.json()
        except:  # pylint: disable=bare-except
            # request_logger.warning("Failed to parse response with JSON mimetype")
            return response

        # request_logger.debug(data)

        if isinstance(data, dict):
            reason = data.get("errorMessage")
            reason = reason or data.get("reason")
            reason = reason or data.get("errorReason")
            if not reason and isinstance(data.get("error"), str):
                reason = data.get("error")
            if not reason and data.get("error"):
                reason = "Unknown reason"

            code = data.get("errorCode")
            if not code and data.get("serverErrorCode"):
                code = data.get("serverErrorCode")

            if reason:
                self._raise_error(code, reason)

        return response

    def _raise_error(self, code, reason):
        if (
            self.service.requires_2sa
            and reason == "Missing X-APPLE-WEBAUTH-TOKEN cookie"
        ):
            raise PyiCloud2SARequiredException(self.service.user["apple_id"])
        if code in ("ZONE_NOT_FOUND", "AUTHENTICATION_FAILED"):
            reason = (
                "Please log into https://icloud.com/ to manually "
                "finish setting up your iCloud service"
            )
            api_error = PyiCloudServiceNotActivatedException(reason, code)
            # LOGGER.error(api_error)

            raise (api_error)
        if code == "ACCESS_DENIED":
            reason = (
                reason + ".  Please wait a few minutes then try again."
                "The remote servers might be trying to throttle requests."
            )
        if code in [421, 450, 500]:
            reason = "Authentication required for Account."

        api_error = PyiCloudAPIResponseException(reason, code)
        # LOGGER.error(api_error)
        raise api_error


class PyiCloudService:
    """
    A base authentication class for the iCloud service. Handles the
    authentication required to access iCloud services.

    Usage:
        from pyicloud import PyiCloudService
        pyicloud = PyiCloudService('username@apple.com', 'password')
        pyicloud.iphone.location()
    """

    AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth"
    HOME_ENDPOINT = "https://www.icloud.com"
    SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"

    def __init__(
        self,
        apple_id,
        password=None,
        cookie_directory=None,
        verify=True,
        client_id=None,
        with_family=True,
    ):
        # if password is None:
        #     password = get_password_from_keyring(apple_id)

        self.user = {"accountName": apple_id, "password": password}
        self.data = {}
        self.params = {}
        self.client_id = client_id or ("auth-%s" % str(uuid1()).lower())
        self.with_family = with_family

        # self.password_filter = PyiCloudPasswordFilter(password)
        # LOGGER.addFilter(self.password_filter)

        if cookie_directory:
            self._cookie_directory = path.expanduser(path.normpath(cookie_directory))
            # if not path.exists(self._cookie_directory):
            #     mkdir(self._cookie_directory, 0o700)
        else:
            topdir = path.join(gettempdir(), "pyicloud")
            self._cookie_directory = path.join(topdir, getpass.getuser())
            # if not path.exists(topdir):
            #     mkdir(topdir, 0o777)
            # if not path.exists(self._cookie_directory):
            #     mkdir(self._cookie_directory, 0o700)

        # LOGGER.debug("Using session file %s", self.session_path)

        self.session_data = {}
        try:
            with open(self.session_path, encoding="utf-8") as session_f:
                self.session_data = json.load(session_f)
        except:  # pylint: disable=bare-except
            # LOGGER.info("Session file does not exist")
            print("Session file does not exist")
        if self.session_data.get("client_id"):
            self.client_id = self.session_data.get("client_id")
        else:
            self.session_data.update({"client_id": self.client_id})

        self.session = PyiCloudSession(self)
        self.session.verify = verify
        self.session.headers.update(
            {"Origin": self.HOME_ENDPOINT, "Referer": "%s/" % self.HOME_ENDPOINT}
        )

        cookiejar_path = self.cookiejar_path
        self.session.cookies = cookielib.LWPCookieJar(filename=cookiejar_path)
        if path.exists(cookiejar_path):
            try:
                self.session.cookies.load(ignore_discard=True, ignore_expires=True)
                # LOGGER.debug("Read cookies from %s", cookiejar_path)
            except:  # pylint: disable=bare-except
                # Most likely a pickled cookiejar from earlier versions.
                # The cookiejar will get replaced with a valid one after
                # successful authentication.
                # LOGGER.warning("Failed to read cookiejar %s", cookiejar_path)
                print("Failed to read cookiejar %s", cookiejar_path)

        self.authenticate()

        self._drive = None
        self._files = None
        self._photos = None

    def authenticate(self, force_refresh=False, service=None):
        """
        Handles authentication, and persists cookies so that
        subsequent logins will not cause additional e-mails from Apple.
        """

        login_successful = False
        if self.session_data.get("session_token") and not force_refresh:
            # LOGGER.debug("Checking session token validity")
            try:
                self.data = self._validate_token()
                login_successful = True
            except PyiCloudAPIResponseException:
                # LOGGER.debug("Invalid authentication token, will log in from scratch.")
                print("Invalid authentication token, will log in from scratch.")

        if not login_successful and service is not None:
            app = self.data["apps"][service]
            if "canLaunchWithOneFactor" in app and app["canLaunchWithOneFactor"]:
                # LOGGER.debug(
                #     "Authenticating as %s for %s", self.user["accountName"], service
                # )
                try:
                    self._authenticate_with_credentials_service(service)
                    login_successful = True
                except Exception:
                    # LOGGER.debug(
                    #     "Could not log into service. Attempting brand new login."
                    # )
                    print("Could not log into service. Attempting brand new login.")

        if not login_successful:
            # LOGGER.debug("Authenticating as %s", self.user["accountName"])

            data = dict(self.user)

            data["rememberMe"] = True
            data["trustTokens"] = []
            if self.session_data.get("trust_token"):
                data["trustTokens"] = [self.session_data.get("trust_token")]

            headers = self._get_auth_headers()

            if self.session_data.get("scnt"):
                headers["scnt"] = self.session_data.get("scnt")

            if self.session_data.get("session_id"):
                headers["X-Apple-ID-Session-Id"] = self.session_data.get("session_id")

            try:
                self.session.post(
                    "%s/signin" % self.AUTH_ENDPOINT,
                    params={"isRememberMeEnabled": "true"},
                    data=json.dumps(data),
                    headers=headers,
                )
            except PyiCloudAPIResponseException as error:
                msg = "Invalid email/password combination."
                raise PyiCloudFailedLoginException(msg, error) from error

            self._authenticate_with_token()

        self._webservices = self.data["webservices"]

        # LOGGER.debug("Authentication completed successfully")

    def _authenticate_with_token(self):
        """Authenticate using session token."""
        data = {
            "accountCountryCode": self.session_data.get("account_country"),
            "dsWebAuthToken": self.session_data.get("session_token"),
            "extended_login": True,
            "trustToken": self.session_data.get("trust_token", ""),
        }

        try:
            req = self.session.post(
                "%s/accountLogin" % self.SETUP_ENDPOINT, data=json.dumps(data)
            )
            self.data = req.json()
        except PyiCloudAPIResponseException as error:
            msg = "Invalid authentication token."
            raise PyiCloudFailedLoginException(msg, error) from error

    # def _authenticate_with_credentials_service(self, service):
    #     """Authenticate to a specific service using credentials."""
    #     data = {
    #         "appName": service,
    #         "apple_id": self.user["accountName"],
    #         "password": self.user["password"],
    #     }
    #
    #     try:
    #         self.session.post(
    #             "%s/accountLogin" % self.SETUP_ENDPOINT, data=json.dumps(data)
    #         )
    #
    #         self.data = self._validate_token()
    #     except PyiCloudAPIResponseException as error:
    #         msg = "Invalid email/password combination."
    #         raise PyiCloudFailedLoginException(msg, error) from error

    def _validate_token(self):
        """Checks if the current access token is still valid."""
        # LOGGER.debug("Checking session token validity")
        try:
            req = self.session.post("%s/validate" % self.SETUP_ENDPOINT, data="null")
            # LOGGER.debug("Session token is still valid")
            return req.json()
        except PyiCloudAPIResponseException as err:
            # LOGGER.debug("Invalid authentication token")
            raise err

    def _get_auth_headers(self, overrides=None):
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "X-Apple-OAuth-Client-Id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
            "X-Apple-OAuth-Client-Type": "firstPartyAuth",
            "X-Apple-OAuth-Redirect-URI": "https://www.icloud.com",
            "X-Apple-OAuth-Require-Grant-Code": "true",
            "X-Apple-OAuth-Response-Mode": "web_message",
            "X-Apple-OAuth-Response-Type": "code",
            "X-Apple-OAuth-State": self.client_id,
            "X-Apple-Widget-Key": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
        }
        if overrides:
            headers.update(overrides)
        return headers

    @property
    def cookiejar_path(self):
        """Get path for cookiejar file."""
        return path.join(
            self._cookie_directory,
            "".join([c for c in self.user.get("accountName") if match(r"\w", c)]),
        )

    @property
    def session_path(self):
        """Get path for session data file."""
        return path.join(
            self._cookie_directory,
            "".join([c for c in self.user.get("accountName") if match(r"\w", c)])
            + ".session",
        )

    @property
    def requires_2sa(self):
        """Returns True if two-step authentication is required."""
        return self.data.get("dsInfo", {}).get("hsaVersion", 0) >= 1 and (
            self.data.get("hsaChallengeRequired", False) or not self.is_trusted_session
        )

    @property
    def requires_2fa(self):
        """Returns True if two-factor authentication is required."""
        return self.data["dsInfo"].get("hsaVersion", 0) == 2 and (
            self.data.get("hsaChallengeRequired", False) or not self.is_trusted_session
        )

    @property
    def is_trusted_session(self):
        """Returns True if the session is trusted."""
        return self.data.get("hsaTrustedBrowser", False)

    @property
    def trusted_devices(self):
        """Returns devices trusted for two-step authentication."""
        request = self.session.get(
            "%s/listDevices" % self.SETUP_ENDPOINT, params=self.params
        )
        return request.json().get("devices")

    def send_verification_code(self, device):
        """Requests that a verification code is sent to the given device."""
        data = json.dumps(device)
        request = self.session.post(
            "%s/sendVerificationCode" % self.SETUP_ENDPOINT,
            params=self.params,
            data=data,
        )
        return request.json().get("success", False)

    # def validate_verification_code(self, device, code):
    #     """Verifies a verification code received on a trusted device."""
    #     device.update({"verificationCode": code, "trustBrowser": True})
    #     data = json.dumps(device)
    #
    #     try:
    #         self.session.post(
    #             "%s/validateVerificationCode" % self.SETUP_ENDPOINT,
    #             params=self.params,
    #             data=data,
    #         )
    #     except PyiCloudAPIResponseException as error:
    #         if error.code == -21669:
    #             # Wrong verification code
    #             return False
    #         raise
    #
    #     self.trust_session()
    #
    #     return not self.requires_2sa

    # def validate_2fa_code(self, code):
    #     """Verifies a verification code received via Apple's 2FA system (HSA2)."""
    #     data = {"securityCode": {"code": code}}
    #
    #     headers = self._get_auth_headers({"Accept": "application/json"})
    #
    #     if self.session_data.get("scnt"):
    #         headers["scnt"] = self.session_data.get("scnt")
    #
    #     if self.session_data.get("session_id"):
    #         headers["X-Apple-ID-Session-Id"] = self.session_data.get("session_id")
    #
    #     try:
    #         self.session.post(
    #             "%s/verify/trusteddevice/securitycode" % self.AUTH_ENDPOINT,
    #             data=json.dumps(data),
    #             headers=headers,
    #         )
    #     except PyiCloudAPIResponseException as error:
    #         if error.code == -21669:
    #             # Wrong verification code
    #             # LOGGER.error("Code verification failed.")
    #             return False
    #         raise
    #
    #     # LOGGER.debug("Code verification successful.")
    #
    #     self.trust_session()
    #     return not self.requires_2sa

    def trust_session(self):
        """Request session trust to avoid user log in going forward."""
        headers = self._get_auth_headers()

        if self.session_data.get("scnt"):
            headers["scnt"] = self.session_data.get("scnt")

        if self.session_data.get("session_id"):
            headers["X-Apple-ID-Session-Id"] = self.session_data.get("session_id")

        try:
            self.session.get(
                f"{self.AUTH_ENDPOINT}/2sv/trust",
                headers=headers,
            )
            self._authenticate_with_token()
            return True
        except PyiCloudAPIResponseException:
            # LOGGER.error("Session trust failed.")
            return False

    def _get_webservice_url(self, ws_key):
        """Get webservice URL, raise an exception if not exists."""
        if self._webservices.get(ws_key) is None:
            raise PyiCloudServiceNotActivatedException(
                "Webservice not available", ws_key
            )
        return self._webservices[ws_key]["url"]

    @property
    def devices(self):
        """Returns all devices."""
        service_root = self._get_webservice_url("findme")
        return FindMyiPhoneServiceManager(
            service_root, self.session, self.params, self.with_family
        )

    @property
    def iphone(self):
        """Returns the iPhone."""
        return self.devices[0]

    # @property
    # def account(self):
    #     """Gets the 'Account' service."""
    #     service_root = self._get_webservice_url("account")
    #     return AccountService(service_root, self.session, self.params)

    # @property
    # def files(self):
    #     """Gets the 'File' service."""
    #     if not self._files:
    #         service_root = self._get_webservice_url("ubiquity")
    #         self._files = UbiquityService(service_root, self.session, self.params)
    #     return self._files

    # @property
    # def photos(self):
    #     """Gets the 'Photo' service."""
    #     if not self._photos:
    #         service_root = self._get_webservice_url("ckdatabasews")
    #         self._photos = PhotosService(service_root, self.session, self.params)
    #     return self._photos

    # @property
    # def calendar(self):
    #     """Gets the 'Calendar' service."""
    #     service_root = self._get_webservice_url("calendar")
    #     return CalendarService(service_root, self.session, self.params)

    # @property
    # def contacts(self):
    #     """Gets the 'Contacts' service."""
    #     service_root = self._get_webservice_url("contacts")
    #     return ContactsService(service_root, self.session, self.params)

    # @property
    # def reminders(self):
    #     """Gets the 'Reminders' service."""
    #     service_root = self._get_webservice_url("reminders")
    #     return RemindersService(service_root, self.session, self.params)

    # @property
    # def drive(self):
    #     """Gets the 'Drive' service."""
    #     if not self._drive:
    #         self._drive = DriveService(
    #             service_root=self._get_webservice_url("drivews"),
    #             document_root=self._get_webservice_url("docws"),
    #             session=self.session,
    #             params=self.params,
    #         )
    #     return self._drive

    def __str__(self):
        return f"iCloud API: {self.user.get('apple_id')}"

    def __repr__(self):
        return f"<{self}>"


class FindMyiPhoneServiceManager:
    """The 'Find my iPhone' iCloud service

    This connects to iCloud and return phone data including the near-realtime
    latitude and longitude.
    """

    def __init__(self, service_root, session, params, with_family=False):
        self.session = session
        self.params = params
        self.with_family = with_family

        fmip_endpoint = "%s/fmipservice/client/web" % service_root
        self._fmip_refresh_url = "%s/refreshClient" % fmip_endpoint
        self._fmip_sound_url = "%s/playSound" % fmip_endpoint
        self._fmip_message_url = "%s/sendMessage" % fmip_endpoint
        self._fmip_lost_url = "%s/lostDevice" % fmip_endpoint

        self._devices = {}
        self.refresh_client()

    def refresh_client(self):
        """Refreshes the FindMyiPhoneService endpoint,

        This ensures that the location data is up-to-date.

        """
        req = self.session.post(
            self._fmip_refresh_url,
            params=self.params,
            data=json.dumps(
                {
                    "clientContext": {
                        "fmly": self.with_family,
                        "shouldLocate": True,
                        "selectedDevice": "all",
                        "deviceListVersion": 1,
                    }
                }
            ),
        )
        self.response = req.json()

        for device_info in self.response["content"]:
            device_id = device_info["id"]
            if device_id not in self._devices:
                self._devices[device_id] = AppleDevice(
                    device_info,
                    self.session,
                    self.params,
                    manager=self,
                    sound_url=self._fmip_sound_url,
                    lost_url=self._fmip_lost_url,
                    message_url=self._fmip_message_url,
                )
            else:
                self._devices[device_id].update(device_info)

        if not self._devices:
            raise PyiCloudNoDevicesException()

    def __getitem__(self, key):
        if isinstance(key, int):
            key = list(self.keys())[key]
        return self._devices[key]

    def __getattr__(self, attr):
        return getattr(self._devices, attr)

    def __str__(self):
        return f"{self._devices}"

    def __repr__(self):
        return f"{self}"



class AppleDevice:
    """Apple device."""

    def __init__(
        self,
        content,
        session,
        params,
        manager,
        sound_url=None,
        lost_url=None,
        message_url=None,
    ):
        self.content = content
        self.manager = manager
        self.session = session
        self.params = params

        self.sound_url = sound_url
        self.lost_url = lost_url
        self.message_url = message_url

    def update(self, data):
        """Updates the device data."""
        self.content = data

    def location(self):
        """Updates the device location."""
        self.manager.refresh_client()
        return self.content["location"]

    def status(self, additional=[]):  # pylint: disable=dangerous-default-value
        """Returns status information for device.

        This returns only a subset of possible properties.
        """
        self.manager.refresh_client()
        fields = ["batteryLevel", "deviceDisplayName", "deviceStatus", "name"]
        fields += additional
        properties = {}
        for field in fields:
            properties[field] = self.content.get(field)
        return properties

    def play_sound(self, subject="Find My iPhone Alert"):
        """Send a request to the device to play a sound.

        It's possible to pass a custom message by changing the `subject`.
        """
        data = json.dumps(
            {
                "device": self.content["id"],
                "subject": subject,
                "clientContext": {"fmly": True},
            }
        )
        self.session.post(self.sound_url, params=self.params, data=data)

    def display_message(
        self, subject="Find My iPhone Alert", message="This is a note", sounds=False
    ):
        """Send a request to the device to play a sound.

        It's possible to pass a custom message by changing the `subject`.
        """
        data = json.dumps(
            {
                "device": self.content["id"],
                "subject": subject,
                "sound": sounds,
                "userText": True,
                "text": message,
            }
        )
        self.session.post(self.message_url, params=self.params, data=data)

    def lost_device(
        self, number, text="This iPhone has been lost. Please call me.", newpasscode=""
    ):
        """Send a request to the device to trigger 'lost mode'.

        The device will show the message in `text`, and if a number has
        been passed, then the person holding the device can call
        the number without entering the passcode.
        """
        data = json.dumps(
            {
                "text": text,
                "userText": True,
                "ownerNbr": number,
                "lostModeEnabled": True,
                "trackingEnabled": True,
                "device": self.content["id"],
                "passcode": newpasscode,
            }
        )
        self.session.post(self.lost_url, params=self.params, data=data)

    @property
    def data(self):
        """Gets the device data."""
        return self.content

    def __getitem__(self, key):
        return self.content[key]

    def __getattr__(self, attr):
        return getattr(self.content, attr)

    def __str__(self):
        return f"{self['deviceDisplayName']}: {self['name']}"

    def __repr__(self):
        return f"<AppleDevice({self})>"