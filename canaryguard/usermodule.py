"""Custom OpenCanary usermodule: a fake "CCTV-NVR admin API" service.

Installed via the `canary.usermodule` entry point. It emulates a small
network camera controller: prompts for credentials, then emulates a shell.
Every input is logged so CanaryGuard can triage it.

Config keys (opencanary.conf):
  "fakeapi.port": 8443
  "fakeapi.banner": "NVR-9200 Web Manager"
"""

from opencanary.modules import CanaryService

from twisted.internet.protocol import Factory, Protocol

LOG_FAKEAPI_AUTH_ATTEMPT = 21001
LOG_FAKEAPI_COMMAND = 21002


class FakeAPIProtocol(Protocol):
    def __init__(self):
        self.state = "user"
        self.username = ""
        self.logged_in = False

    def connectionMade(self):
        banner = self.factory.banner
        self.transport.write(f"{banner}\r\nlogin: ".encode("utf8"))

    def dataReceived(self, data):
        try:
            text = data.decode("utf8", errors="replace").strip("\r\n")
        except Exception:
            text = ""
        if not text:
            return

        if self.state == "user":
            self.username = text
            self.state = "pass"
            self.transport.write(b"password: ")
        elif self.state == "pass":
            password = text
            logdata = {"USERNAME": self.username, "PASSWORD": password}
            self.factory.logtype = LOG_FAKEAPI_AUTH_ATTEMPT
            self.factory.log(logdata, transport=self.transport)
            self.logged_in = True
            self.state = "cmd"
            self.transport.write(b"\r\n$ ")
        else:
            logdata = {"COMMAND": text, "USERNAME": self.username}
            self.factory.logtype = LOG_FAKEAPI_COMMAND
            self.factory.log(logdata, transport=self.transport)
            self.transport.write(b"sh: command not found\r\n$ ")


class CanaryFakeAPI(Factory, CanaryService):
    NAME = "fakeapi"
    protocol = FakeAPIProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("fakeapi.port", default=8443))
        self.banner = config.getVal("fakeapi.banner", default="NVR-9200 Web Manager")
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


CanaryServiceFactory = CanaryFakeAPI