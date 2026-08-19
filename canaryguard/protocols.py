"""Custom OpenCanary usermodules: 15 extra fake protocols.

Each emulates a service attackers commonly scan for, at the banner/auth
level, and logs every interaction for CanaryGuard.

Logtypes:
  22001 SMTP, 22002 POP3, 22003 IMAP, 22004 PostgreSQL, 22005 Elasticsearch,
  22006 Docker API, 22007 Kubernetes, 22008 RTSP, 22009 Modbus, 22010 Memcached,
  22011 DNS (UDP), 22012 MQTT, 22013 TeamViewer, 22014 LDAP, 22015 Java RMI.
"""

import base64
import struct

from opencanary.modules import CanaryService

from twisted.internet.protocol import DatagramProtocol, Factory, Protocol

LOG_SMTP = 22001
LOG_POP3 = 22002
LOG_IMAP = 22003
LOG_PGSQL = 22004
LOG_ES = 22005
LOG_DOCKER = 22006
LOG_K8S = 22007
LOG_RTSP = 22008
LOG_MODBUS = 22009
LOG_MEMCACHED = 22010
LOG_DNS = 22011
LOG_MQTT = 22012
LOG_TEAMVIEWER = 22013
LOG_LDAP = 22014
LOG_RMI = 22015


class _BaseProtocol(Protocol):
    def __init__(self):
        self.buffer = b""

    def log(self, logdata, logtype):
        self.factory.log(logdata, transport=self.transport, logtype=logtype)

    def _lines(self):
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            yield line.strip(b"\r")


class _LineServer(_BaseProtocol):
    banner = b""

    def connectionMade(self):
        if self.banner:
            self.transport.write(self.banner)

    def dataReceived(self, data):
        self.buffer += data
        for line in self._lines():
            if not self.on_line(line):
                break

    def on_line(self, line):
        return True


class _HTTPServer(_BaseProtocol):
    def connectionMade(self):
        pass

    def dataReceived(self, data):
        self.buffer += data
        if b"\r\n\r\n" in self.buffer:
            head, self.buffer = self.buffer.split(b"\r\n\r\n", 1)
            self.on_http(head)
            self.transport.loseConnection()

    def on_http(self, head):
        pass

    def respond(self, code, reason, body, extra=None):
        resp = f"HTTP/1.1 {code} {reason}\r\n".encode()
        if extra:
            resp += extra + b"\r\n"
        resp += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        self.transport.write(resp + body)


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------
class FakeSMTPProtocol(_LineServer):
    banner = b"220 mail.example.com ESMTP Postfix\r\n"

    def __init__(self):
        super().__init__()
        self.in_data = False
        self.auth_user = None
        self.mail_from = ""
        self._auth_state = None  # None | "plain" | "login-user" | "login-pass"

    def on_line(self, line):
        if self.in_data:
            if line == b".":
                self.in_data = False
                self.transport.write(b"250 Ok: queued as 4F7B2C1A\r\n")
            return True
        cmd = line.split(b" ")[0].upper().decode("ascii", "replace")
        rest = line.split(b" ", 1)[1] if b" " in line else b""

        # AUTH LOGIN second step (base64 username) / third step (base64 password)
        if self._auth_state in ("login-user", "login-pass"):
            try:
                decoded = base64.b64decode(line).decode("utf8", "replace")
            except Exception:
                decoded = line.decode("utf8", "replace")
            if self._auth_state == "login-user":
                self.auth_user = decoded
                self._auth_state = "login-pass"
                self.transport.write(b"334 UGFzc3dvcmQ6\r\n")  # Password:
            else:
                self.log({"USERNAME": self.auth_user or "", "PASSWORD": decoded, "COMMAND": "AUTH-LOGIN"}, LOG_SMTP)
                self._auth_state = None
                self.transport.write(b"235 2.7.0 Authentication successful\r\n")
            return True

        if cmd == "EHLO" or cmd == "HELO":
            self.log({"COMMAND": cmd, "HOST": rest.decode("utf8", "replace")}, LOG_SMTP)
            self.transport.write(b"250-mail.example.com\r\n250-PIPELINING\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
        elif cmd == "MAIL" or cmd == "RCPT":
            self.log({"COMMAND": cmd, "ARG": rest.decode("utf8", "replace")}, LOG_SMTP)
            self.transport.write(b"250 Ok\r\n")
            if cmd == "MAIL":
                self.mail_from = rest.decode("utf8", "replace")
        elif cmd == "AUTH":
            arg = rest.decode("utf8", "replace")
            self.log({"COMMAND": "AUTH", "ARG": arg}, LOG_SMTP)
            if arg.upper().startswith("PLAIN"):
                try:
                    b64 = arg.split(None, 1)[1] if " " in arg else ""
                    creds = base64.b64decode(b64).decode("utf8", "replace").strip("\x00")
                    parts = creds.split("\x00")
                    user = parts[-2] if len(parts) >= 2 else ""
                    pwd = parts[-1] if parts else ""
                    self.log({"USERNAME": user, "PASSWORD": pwd, "COMMAND": "AUTH-PLAIN"}, LOG_SMTP)
                    self.transport.write(b"235 2.7.0 Authentication successful\r\n")
                except Exception:
                    self.transport.write(b"535 5.7.8 Authentication credentials invalid\r\n")
            else:
                self._auth_state = "login-user"
                self.transport.write(b"334 VXNlcm5hbWU6\r\n")
        elif cmd == "DATA":
            self.in_data = True
            self.transport.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        elif cmd == "QUIT":
            self.log({"COMMAND": "QUIT"}, LOG_SMTP)
            self.transport.write(b"221 Bye\r\n")
            self.transport.loseConnection()
        else:
            self.transport.write(b"502 5.5.2 Error: command not recognized\r\n")
        return True


class CanarySMTP(Factory, CanaryService):
    NAME = "smtp"
    protocol = FakeSMTPProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("smtp.port", default=25))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# POP3
# ---------------------------------------------------------------------------
class FakePOP3Protocol(_LineServer):
    banner = b"+OK POP3 server ready\r\n"

    def __init__(self):
        super().__init__()
        self.user = ""

    def on_line(self, line):
        cmd = line.split(b" ")[0].upper().decode("ascii", "replace")
        rest = line.split(b" ", 1)[1] if b" " in line else b""
        if cmd == "USER":
            self.user = rest.decode("utf8", "replace")
            self.log({"USERNAME": self.user, "COMMAND": "USER"}, LOG_POP3)
            self.transport.write(b"+OK\r\n")
        elif cmd == "PASS":
            pwd = rest.decode("utf8", "replace")
            self.log({"USERNAME": self.user, "PASSWORD": pwd, "COMMAND": "PASS"}, LOG_POP3)
            self.transport.write(b"-ERR [AUTH] Authentication failed.\r\n")
        elif cmd == "STAT":
            self.transport.write(b"+OK 0 0\r\n")
        elif cmd == "QUIT":
            self.transport.write(b"+OK bye\r\n")
            self.transport.loseConnection()
        else:
            self.log({"COMMAND": cmd, "ARG": rest.decode("utf8", "replace")}, LOG_POP3)
            self.transport.write(b"+OK\r\n")
        return True


class CanaryPOP3(Factory, CanaryService):
    NAME = "pop3"
    protocol = FakePOP3Protocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("pop3.port", default=110))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------
class FakeIMAPProtocol(_LineServer):
    banner = b"* OK IMAP4rev1 server ready\r\n"

    def on_line(self, line):
        parts = line.split(b" ")
        tag = parts[0].decode("ascii", "replace")
        cmd = (parts[1] if len(parts) > 1 else b"").upper().decode("ascii", "replace")
        if cmd == "LOGIN":
            if len(parts) >= 4:
                user = parts[2].decode("utf8", "replace").strip('"')
                pwd = parts[3].decode("utf8", "replace").strip('"')
                self.log({"USERNAME": user, "PASSWORD": pwd, "COMMAND": "LOGIN"}, LOG_IMAP)
            self.transport.write(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n".encode())
        elif cmd == "CAPABILITY":
            self.transport.write(b"* CAPABILITY IMAP4rev1 IDLE\r\n" + f"{tag} OK\r\n".encode())
        elif cmd == "LOGOUT":
            self.transport.write(b"* BYE Logging out\r\n" + f"{tag} OK\r\n".encode())
            self.transport.loseConnection()
        elif cmd in ("AUTHENTICATE", "ID", "NOOP", "SELECT", "LIST"):
            self.log({"COMMAND": cmd, "ARG": b" ".join(parts[2:]).decode("utf8", "replace")}, LOG_IMAP)
            self.transport.write(f"{tag} OK\r\n".encode())
        else:
            self.log({"COMMAND": cmd, "ARG": b" ".join(parts[2:]).decode("utf8", "replace")}, LOG_IMAP)
            self.transport.write(f"{tag} NO Unknown command\r\n".encode())
        return True


class CanaryIMAP(Factory, CanaryService):
    NAME = "imap"
    protocol = FakeIMAPProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("imap.port", default=143))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------
class FakePostgreSQLProtocol(_BaseProtocol):
    def __init__(self):
        super().__init__()
        self._awaiting_query = False

    def connectionMade(self):
        pass

    def dataReceived(self, data):
        self.buffer += data
        if self._awaiting_query and len(self.buffer) >= 5:
            mtype = self.buffer[0:1]
            length = struct.unpack("!I", self.buffer[1:5])[0]
            if len(self.buffer) >= length:
                payload = self.buffer[5:length]
                if mtype in (b"Q", b"P"):  # simple query / extended parse
                    self.log({"QUERY": payload.split(b"\x00")[0].decode("utf8", "replace"), "COMMAND": "QUERY"}, LOG_PGSQL)
                    self.buffer = self.buffer[length:]
                    self._awaiting_query = False
                    # ReadyForQuery after error
                    self.transport.write(b"E\x00\x00\x00\x2aSERROR\x00VERROR\x00C42725\x00Mfunction does not exist\x00\x00")
                    self.transport.write(b"Z\x00\x00\x00\x05I")
                    self.transport.loseConnection()
                    return
                self.buffer = self.buffer[length:]
        if len(self.buffer) < 8:
            return
        length, code = struct.unpack("!II", self.buffer[:8])
        if code == 80877103:  # SSLRequest
            self.transport.write(b"N")
            self.buffer = self.buffer[8:]
            if len(self.buffer) < 8:
                return
            length, code = struct.unpack("!II", self.buffer[:8])
        if length < 8 or len(self.buffer) < length:
            return
        payload = self.buffer[8:length]
        fields = dict(
            f.decode("utf8", "replace").split("=", 1)
            for f in payload.split(b"\x00") if b"=" in f
        )
        self.log({"USERNAME": fields.get("user", ""), "DATABASE": fields.get("database", ""),
                  "APPLICATION": fields.get("application_name", ""), "CLIENT_ENCODING": fields.get("client_encoding", ""),
                  "COMMAND": "STARTUP"}, LOG_PGSQL)
        self.transport.write(b"R\x00\x00\x00\x08\x00\x00\x00\x03")  # AuthenticationCleartextPassword
        self._awaiting_query = True


class CanaryPostgreSQL(Factory, CanaryService):
    NAME = "postgresql"
    protocol = FakePostgreSQLProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("postgresql.port", default=5432))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# Elasticsearch
# ---------------------------------------------------------------------------
class FakeElasticsearchProtocol(_HTTPServer):
    def on_http(self, head):
        lines = head.split(b"\r\n")
        method, path, _ = lines[0].split(b" ", 2)
        self.log({"METHOD": method.decode(), "PATH": path.decode(), "COMMAND": "HTTP"}, LOG_ES)
        if path.startswith(b"/_search") or path.startswith(b"/search"):
            body = b'{"took":3,"hits":{"total":{"value":0},"hits":[]}}'
            self.respond(200, "OK", body)
        elif path.startswith(b"/_cat") or path.startswith(b"/_nodes") or path.startswith(b"/_cluster"):
            body = b'{"cluster_name":"elasticsearch","status":"green"}'
            self.respond(200, "OK", body)
        elif path == b"/":
            body = b'{"name":"es-node-1","cluster_name":"elasticsearch","version":{"number":"7.17.0"}}'
            self.respond(200, "OK", body)
        else:
            body = b'{"error":{"type":"index_not_found_exception"}}'
            self.respond(404, "Not Found", body)


class CanaryElasticsearch(Factory, CanaryService):
    NAME = "elasticsearch"
    protocol = FakeElasticsearchProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("elasticsearch.port", default=9200))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# Docker API
# ---------------------------------------------------------------------------
class FakeDockerProtocol(_HTTPServer):
    def on_http(self, head):
        lines = head.split(b"\r\n")
        method, path, _ = lines[0].split(b" ", 2)
        self.log({"METHOD": method.decode(), "PATH": path.decode(), "COMMAND": "HTTP"}, LOG_DOCKER)
        if path.startswith(b"/v1."):
            path = b"/" + path.split(b"/", 2)[2]
        if path == b"/version" or path == b"/_ping":
            body = b'{"ApiVersion":"1.41","MinAPIVersion":"1.12","Os":"linux","Arch":"amd64","Version":"20.10.12","KernelVersion":"5.15.0-100-generic","GoVersion":"go1.17.6"}'
            self.respond(200, "OK", body)
        elif path.startswith(b"/containers"):
            body = b'[]'
            self.respond(200, "OK", body)
        elif path.startswith(b"/images") or path.startswith(b"/info"):
            body = b'{"Containers":2,"Images":14,"MemTotal":16715268096}'
            self.respond(200, "OK", body)
        else:
            body = b'{"message":"page not found"}'
            self.respond(404, "Not Found", body)


class CanaryDocker(Factory, CanaryService):
    NAME = "docker"
    protocol = FakeDockerProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("docker.port", default=2375))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------------
class FakeKubernetesProtocol(_HTTPServer):
    def on_http(self, head):
        lines = head.split(b"\r\n")
        method, path, _ = lines[0].split(b" ", 2)
        self.log({"METHOD": method.decode(), "PATH": path.decode(), "COMMAND": "HTTP"}, LOG_K8S)
        if path.startswith(b"/version"):
            body = b'{"major":"1","minor":"24","gitVersion":"v1.24.3","platform":"linux/amd64"}'
            self.respond(200, "OK", body)
        elif path == b"/api" or path.startswith(b"/api/"):
            body = b'{"kind":"APIVersions","versions":["v1"]}'
            self.respond(200, "OK", body)
        elif path.startswith(b"/apis"):
            body = b'{"kind":"APIGroupList","apiVersion":"v1","groups":[]}'
            self.respond(200, "OK", body)
        else:
            body = b'{"kind":"Status","status":"Failure","reason":"NotFound"}'
            self.respond(404, "Not Found", body)


class CanaryKubernetes(Factory, CanaryService):
    NAME = "kubernetes"
    protocol = FakeKubernetesProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("kubernetes.port", default=6443))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# RTSP (IP cameras)
# ---------------------------------------------------------------------------
class FakeRTSPProtocol(_LineServer):
    def connectionMade(self):
        pass

    def on_line(self, line):
        parts = line.split(b" ")
        if len(parts) >= 3 and parts[1].startswith(b"rtsp:"):
            method = parts[0].decode("ascii", "replace")
            uri = parts[1].decode("utf8", "replace")
            self.log({"METHOD": method, "URI": uri}, LOG_RTSP)
            if method == "OPTIONS":
                self.transport.write(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, PAUSE, GET_PARAMETER\r\n\r\n")
            elif method == "DESCRIBE":
                self.transport.write(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: 172\r\n\r\nv=0\r\no=- 0 0 IN IP4 10.0.0.5\r\ns=Stream 1\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n")
            elif method == "SETUP":
                self.transport.write(b"RTSP/1.0 200 OK\r\nCSeq: 3\r\nTransport: RTP/AVP;unicast;client_port=5000-5001;server_port=6000-6001\r\n\r\n")
            else:
                self.transport.write(b"RTSP/1.0 200 OK\r\nCSeq: 4\r\n\r\n")
        return True


class CanaryRTSP(Factory, CanaryService):
    NAME = "rtsp"
    protocol = FakeRTSPProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("rtsp.port", default=554))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# Modbus/TCP (SCADA/ICS)
# ---------------------------------------------------------------------------
class FakeModbusProtocol(_BaseProtocol):
    def dataReceived(self, data):
        self.buffer += data
        if len(self.buffer) >= 12:
            tid = self.buffer[:2]
            pid = self.buffer[2:4]
            length = self.buffer[4:6]
            unit = self.buffer[6]
            fn = self.buffer[7]
            args = self.buffer[8:12]
            fn_name = {
                1: "READ_COILS", 2: "READ_DISCRETE_INPUTS", 3: "READ_HOLDING_REGS",
                4: "READ_INPUT_REGS", 5: "WRITE_SINGLE_COIL", 6: "WRITE_SINGLE_REG",
                15: "WRITE_MULTI_COILS", 16: "WRITE_MULTI_REGS", 43: "READ_DEVICE_ID",
            }.get(fn, f"UNKNOWN(0x{fn:02x})")
            self.log({"UNIT_ID": unit, "FUNCTION": fn_name, "ARGS": args.hex(), "COMMAND": "MBAP"}, LOG_MODBUS)
            if fn in (1, 2, 3, 4):
                # read response: quantity of bytes 2, values 0x0000
                resp = tid + pid + b"\x00\x00\x00\x05" + bytes([unit, fn, 0x02, 0x00, 0x00])
            elif fn in (5, 6):
                resp = tid + pid + b"\x00\x00\x00\x06" + bytes([unit, fn]) + args
            elif fn in (15, 16):
                resp = tid + pid + b"\x00\x00\x00\x06" + bytes([unit, fn]) + args[:4]
            else:
                resp = tid + pid + b"\x00\x00\x00\x03" + bytes([unit, fn | 0x80, 0x02])
            self.transport.write(resp)
            self.transport.loseConnection()


class CanaryModbus(Factory, CanaryService):
    NAME = "modbus"
    protocol = FakeModbusProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("modbus.port", default=502))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# Memcached
# ---------------------------------------------------------------------------
class FakeMemcachedProtocol(_LineServer):
    def connectionMade(self):
        pass

    def on_line(self, line):
        parts = line.split(b" ")
        cmd = parts[0].upper().decode("ascii", "replace")
        logdata = {"COMMAND": cmd, "ARG": line.decode("utf8", "replace")}
        if cmd in ("set", "add", "replace", "append", "prepend"):
            if len(parts) >= 5:
                logdata["KEY"] = parts[1].decode("utf8", "replace")
                logdata["FLAGS"] = parts[2].decode("utf8", "replace")
                logdata["EXPTIME"] = parts[3].decode("utf8", "replace")
                logdata["SIZE"] = parts[4].decode("utf8", "replace")
        self.log(logdata, LOG_MEMCACHED)
        if cmd == "version":
            self.transport.write(b"VERSION 1.6.9\r\n")
        elif cmd == "stats":
            self.transport.write(b"STAT version 1.6.9\r\nSTAT curr_connections 1\r\nSTAT total_items 42\r\nEND\r\n")
        elif cmd == "get" or cmd == "gets":
            self.transport.write(b"END\r\n")
        elif cmd == "quit":
            self.transport.write(b"OK\r\n")
            self.transport.loseConnection()
        elif cmd in ("set", "add", "replace"):
            self.transport.write(b"STORED\r\n")
        elif cmd == "flush_all":
            self.transport.write(b"OK\r\n")
        elif cmd == "slabs":
            self.transport.write(b"END\r\n")
        else:
            self.transport.write(b"ERROR\r\n")
        return True


class CanaryMemcached(Factory, CanaryService):
    NAME = "memcached"
    protocol = FakeMemcachedProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("memcached.port", default=11211))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# DNS (UDP)
# ---------------------------------------------------------------------------
class FakeDNS(DatagramProtocol, CanaryService):
    NAME = "dns"

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("dns.port", default=53))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE

    def datagramReceived(self, data, addr):
        if len(data) < 12:
            return
        ident = data[:2]
        qdcount = struct.unpack("!H", data[4:6])[0]
        qtype_names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
                       16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 99: "SPF", 255: "ANY"}
        queries = []
        i = 12
        for _ in range(max(1, qdcount)):
            qname_parts = []
            while i < len(data) and data[i] != 0:
                ln = data[i]
                i += 1
                if ln & 0xC0:  # compression pointer
                    i += 1
                    break
                if i + ln > len(data):
                    break
                qname_parts.append(data[i:i + ln].decode("utf8", "replace"))
                i += ln
            i += 1  # null terminator
            if i + 4 <= len(data):
                qtype = struct.unpack("!H", data[i:i + 2])[0]
                qclass = struct.unpack("!H", data[i + 2:i + 4])[0]
            else:
                qtype, qclass = 0, 0
            i += 4
            queries.append({
                "QNAME": ".".join(qname_parts),
                "QTYPE": qtype_names.get(qtype, qtype),
                "QCLASS": qclass,
            })
        self.log({"QUERIES": queries, "COMMAND": "QUERY"}, logtype=LOG_DNS)
        flags = struct.pack("!H", 0x8180)
        ancount = struct.pack("!H", 1)
        nscount = struct.pack("!H", 0)
        arcount = struct.pack("!H", 0)
        question = data[12:i]
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([203, 0, 113, 42])
        self.transport.write(ident + flags + struct.pack("!H", qdcount) + ancount + nscount + arcount + question + answer, addr)


# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------
class FakeMQTTProtocol(_BaseProtocol):
    def dataReceived(self, data):
        self.buffer += data
        if len(self.buffer) < 2:
            return
        first = self.buffer[0]
        ptype = first >> 4
        if ptype == 1:  # CONNECT
            pos = 1
            mult = 1
            rl = 0
            while True:
                b = self.buffer[pos]
                rl += (b & 0x7F) * mult
                mult *= 128
                pos += 1
                if not (b & 0x80):
                    break
            if len(self.buffer) >= pos + rl:
                packet = self.buffer[pos:pos + rl]
                client_id = ""
                username = ""
                password = ""
                will = ""
                # protocol name + level
                pn = struct.unpack("!H", packet[0:2])[0] if len(packet) >= 2 else 0
                if len(packet) >= pn + 4:
                    flags = packet[pn + 2]
                    off = pn + 4
                    cid_len = struct.unpack("!H", packet[off:off + 2])[0]
                    client_id = packet[off + 2:off + 2 + cid_len].decode("utf8", "replace")
                    off += 2 + cid_len
                    if flags & 0x04:  # will
                        wlen = struct.unpack("!H", packet[off:off + 2])[0]
                        will = packet[off + 2:off + 2 + wlen].decode("utf8", "replace")
                        off += 2 + wlen
                    if flags & 0x80:  # username
                        ulen = struct.unpack("!H", packet[off:off + 2])[0]
                        username = packet[off + 2:off + 2 + ulen].decode("utf8", "replace")
                        off += 2 + ulen
                    if flags & 0x40:  # password
                        plen = struct.unpack("!H", packet[off:off + 2])[0]
                        password = packet[off + 2:off + 2 + plen].decode("utf8", "replace")
                        off += 2 + plen
                logdata = {"CLIENT_ID": client_id, "WILL_TOPIC": will, "COMMAND": "CONNECT"}
                if username:
                    logdata["USERNAME"] = username
                if password:
                    logdata["PASSWORD"] = password
                self.log(logdata, LOG_MQTT)
                self.transport.write(b"\x20\x02\x00\x00")  # CONNACK accepted
        elif ptype == 8:  # SUBSCRIBE
            pos = 2
            mult = 1
            rl = 0
            while True:
                b = self.buffer[pos]
                rl += (b & 0x7F) * mult
                mult *= 128
                pos += 1
                if not (b & 0x80):
                    break
            if len(self.buffer) >= pos + rl:
                packet = self.buffer[pos:pos + rl]
                tlen = struct.unpack("!H", packet[2:4])[0]
                topic = packet[4:4 + tlen].decode("utf8", "replace")
                self.log({"COMMAND": "SUBSCRIBE", "TOPIC": topic}, LOG_MQTT)
        elif ptype == 3:  # PUBLISH
            pos = 2
            mult = 1
            rl = 0
            while True:
                b = self.buffer[pos]
                rl += (b & 0x7F) * mult
                mult *= 128
                pos += 1
                if not (b & 0x80):
                    break
            if len(self.buffer) >= pos + rl:
                packet = self.buffer[pos:pos + rl]
                tlen = struct.unpack("!H", packet[0:2])[0]
                topic = packet[2:2 + tlen].decode("utf8", "replace")
                payload = packet[2 + tlen:2 + tlen + min(128, len(packet) - 2 - tlen)].decode("utf8", "replace")
                self.log({"COMMAND": "PUBLISH", "TOPIC": topic, "PAYLOAD": payload}, LOG_MQTT)
        else:
            self.log({"COMMAND": f"TYPE:{ptype}", "RAW": self.buffer[:32].hex()}, LOG_MQTT)


class CanaryMQTT(Factory, CanaryService):
    NAME = "mqtt"
    protocol = FakeMQTTProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("mqtt.port", default=1883))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# TeamViewer / AnyDesk
# ---------------------------------------------------------------------------
class FakeTeamViewerProtocol(_BaseProtocol):
    def connectionMade(self):
        self.log({"COMMAND": "CONNECT", "PROTO": "teamviewer"}, LOG_TEAMVIEWER)
        self.transport.write(b"TV-7\r\n")

    def dataReceived(self, data):
        self.log({"COMMAND": "DATA", "RAW": data[:64].hex()}, LOG_TEAMVIEWER)
        self.transport.loseConnection()


class CanaryTeamViewer(Factory, CanaryService):
    NAME = "teamviewer"
    protocol = FakeTeamViewerProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("teamviewer.port", default=5938))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------
class FakeLDAPProtocol(_BaseProtocol):
    BIND_OK = bytes([0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00])

    def connectionMade(self):
        self.log({"COMMAND": "CONNECT", "PROTO": "ldap"}, LOG_LDAP)

    @staticmethod
    def _ber_tlvs(data):
        """Recursively yield (tag, value) for BER TLVs (one-byte lengths + long form)."""
        def walk(blob):
            out = []
            i = 0
            while i < len(blob):
                tag = blob[i]
                ln = blob[i + 1] if i + 1 < len(blob) else 0
                if ln & 0x80:
                    n = ln & 0x7F
                    ln = int.from_bytes(blob[i + 2:i + 2 + n], "big")
                    i += 2 + n
                else:
                    i += 2
                val = blob[i:i + ln]
                out.append((tag, val))
                i += ln
            return out

        def flatten(tlvs):
            found = []
            for tag, val in tlvs:
                found.append((tag, val))
                # recurse into constructed types (0x20..0x3F, 0x60..)
                if tag in (0x30, 0x31, 0x60, 0x61, 0x63, 0xa0, 0xa1, 0xa3):
                    found.extend(flatten(walk(val)))
            return found

        return flatten(walk(data))

    def _parse_bind(self, data):
        """Best-effort parse of a simple BindRequest to grab user/password."""
        try:
            for tag, val in self._ber_tlvs(data):
                if tag == 0x60:  # BindRequest (Application 0)
                    fields = {}
                    for t, v in self._ber_tlvs(val):
                        if t == 0x04:  # user DN
                            fields["USERNAME"] = v.decode("utf8", "replace")
                        elif t == 0x80:  # simple password
                            fields["PASSWORD"] = v.decode("utf8", "replace")
                        elif t == 0x02:  # version / message ids
                            fields.setdefault("VERSION", int.from_bytes(v, "big"))
                    if "PASSWORD" in fields or "USERNAME" in fields:
                        return fields
        except Exception:
            pass
        return None

    def dataReceived(self, data):
        self.buffer += data
        bind = self._parse_bind(self.buffer)
        if bind:
            bind["COMMAND"] = "BIND"
            self.log(bind, LOG_LDAP)
        else:
            self.log({"COMMAND": "BIND", "RAW": self.buffer[:64].hex()}, LOG_LDAP)
        self.transport.write(self.BIND_OK)
        self.transport.loseConnection()


class CanaryLDAP(Factory, CanaryService):
    NAME = "ldap"
    protocol = FakeLDAPProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("ldap.port", default=389))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


# ---------------------------------------------------------------------------
# Java RMI
# ---------------------------------------------------------------------------
class FakeRMIProtocol(_BaseProtocol):
    def connectionMade(self):
        self.log({"COMMAND": "CONNECT", "PROTO": "java-rmi"}, LOG_RMI)

    def dataReceived(self, data):
        self.buffer += data
        self.log({"COMMAND": "HANDSHAKE", "RAW": self.buffer[:32].hex()}, LOG_RMI)
        if self.buffer[:4] == b"JRMI":
            self.transport.write(b"\x4e\x00\x0d")
        else:
            self.transport.write(b"\x4e\x00\x0d")
        self.transport.loseConnection()


class CanaryRMI(Factory, CanaryService):
    NAME = "rmi"
    protocol = FakeRMIProtocol

    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal("rmi.port", default=1099))
        self.listen_addr = config.getVal("device.listen_addr", default="")
        self.logtype = logger.LOG_BASE_EXAMPLE


CanaryServiceFactory = CanarySMTP