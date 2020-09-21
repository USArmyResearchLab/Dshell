"""
Looks for SSL alert messages
"""

# handy reference:
# http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session

import dshell.core
from dshell.output.alertout import AlertOutput

import hashlib
import io
import struct
from pprint import pprint

# SSLv3/TLS version
SSL3_VERSION = 0x0300
TLS1_VERSION = 0x0301
TLS1_1_VERSION = 0x0302
TLS1_2_VERSION = 0x0303

# Record type
SSL3_RT_CHANGE_CIPHER_SPEC = 20
SSL3_RT_ALERT             = 21
SSL3_RT_HANDSHAKE         = 22
SSL3_RT_APPLICATION_DATA  = 23

# Handshake message type
SSL3_MT_HELLO_REQUEST           = 0
SSL3_MT_CLIENT_HELLO            = 1
SSL3_MT_SERVER_HELLO            = 2
SSL3_MT_CERTIFICATE             = 11
SSL3_MT_SERVER_KEY_EXCHANGE     = 12
SSL3_MT_CERTIFICATE_REQUEST     = 13
SSL3_MT_SERVER_DONE             = 14
SSL3_MT_CERTIFICATE_VERIFY      = 15
SSL3_MT_CLIENT_KEY_EXCHANGE     = 16
SSL3_MT_FINISHED                = 20

alert_types = {
    0x00: "CLOSE_NOTIFY",
    0x0a: "UNEXPECTED_MESSAGE",
    0x14: "BAD_RECORD_MAC",
    0x15: "DECRYPTION_FAILED",
    0x16: "RECORD_OVERFLOW",
    0x1e: "DECOMPRESSION_FAILURE",
    0x28: "HANDSHAKE_FAILURE",
    0x29: "NO_CERTIFICATE",
    0x2a: "BAD_CERTIFICATE",
    0x2b: "UNSUPPORTED_CERTIFICATE",
    0x2c: "CERTIFICATE_REVOKED",
    0x2d: "CERTIFICATE_EXPIRED",
    0x2e: "CERTIFICATE_UNKNOWN",
    0x2f: "ILLEGAL_PARAMETER",
    0x30: "UNKNOWN_CA",
    0x31: "ACCESS_DENIED",
    0x32: "DECODE_ERROR",
    0x33: "DECRYPT_ERROR",
    0x3c: "EXPORT_RESTRICTION",
    0x46: "PROTOCOL_VERSION",
    0x47: "INSUFFICIENT_SECURITY",
    0x50: "INTERNAL_ERROR",
    0x5a: "USER_CANCELLED",
    0x64: "NO_RENEGOTIATION",
}

alert_severities = {
    0x01: "warning",
    0x02: "fatal",
}

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name="sslalerts",
            author="dev195",
            bpf="tcp and (port 443 or port 993 or port 1443 or port 8531)",
            description="Looks for SSL alert messages",
            output=AlertOutput(label=__name__),
        )

    def blob_handler(self, conn, blob):
        data = io.BytesIO(blob.data)
        alert_seen = False
        # Iterate over each layer of the connection, paying special attention to the certificate
        while True:
            try:
                content_type, proto_version, record_len = struct.unpack("!BHH", data.read(5))
            except struct.error:
                break
            if proto_version not in (SSL3_VERSION, TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION):
                return None
            if content_type == SSL3_RT_ALERT:
                handshake_len = struct.unpack("!I", data.read(4))[0]
#                assert handshake_len == 2  # TODO remove when live
                severity = struct.unpack("!B", data.read(1))[0]
                if severity not in alert_severities:
                    continue
                severity_msg = alert_severities.get(severity, severity)
                alert_type = struct.unpack("!B", data.read(1))[0]
                alert_msg = alert_types.get(alert_type, str(alert_type))
                self.write("SSL alert: ({}) {}".format(severity_msg, alert_msg), **conn.info())
                alert_seen = True

        if alert_seen:
            return conn, blob
