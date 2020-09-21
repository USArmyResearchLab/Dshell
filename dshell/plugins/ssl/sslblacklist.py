"""
Looks for certificates in SSL/TLS traffic and tries to find any hashes that
match those in the abuse.ch blacklist.
(https://sslbl.abuse.ch/blacklist/)
"""

# handy reference:
# http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session

import dshell.core
from dshell.output.alertout import AlertOutput

import hashlib
import io
import struct

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


class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name="sslblacklist",
            author="dev195",
            bpf="tcp and (port 443 or port 993 or port 1443 or port 8531)",
            description="Looks for certificate SHA1 matches in the abuse.ch blacklist",
            longdescription="""
    Looks for certificates in SSL/TLS traffic and tries to find any hashes that
    match those in the abuse.ch blacklist.

    Requires downloading the blacklist CSV from abuse.ch:
    https://sslbl.abuse.ch/blacklist/

    If the CSV is not in the current directory, use the --sslblacklist_csv
    argument to provide a file path.
""",
            output=AlertOutput(label=__name__),
            optiondict={
                "csv": {
                    "help": "filepath to the sslblacklist.csv file",
                    "default": "./sslblacklist.csv",
                    "metavar": "FILEPATH"
                },
            }
        )

    def premodule(self):
        self.parse_blacklist_csv(self.csv)

    def parse_blacklist_csv(self, filepath):
        "parses the SSL blacklist CSV, given the 'filepath'"
        # Python's standard csv module doesn't seem to handle it properly
        self.hashes = {}
        with open(filepath, 'r') as csv:
            for line in csv:
                line = line.split('#')[0]  # ignore comments
                line = line.strip()
                try:
                    timestamp, sha1, reason = line.split(',', 3)
                    self.hashes[sha1] = reason
                except ValueError:
                    continue

    def blob_handler(self, conn, blob):
        if blob.direction == 'cs':
            return None

        data = io.BytesIO(blob.data)

        # Iterate over each layer of the connection, paying special attention to the certificate
        while True:
            try:
                content_type, proto_version, record_len = struct.unpack("!BHH", data.read(5))
            except struct.error:
                break
            if proto_version not in (SSL3_VERSION, TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION):
                return None
            if content_type == SSL3_RT_HANDSHAKE:
                handshake_type = struct.unpack("!B", data.read(1))[0]
                handshake_len = struct.unpack("!I", b"\x00"+data.read(3))[0]
                if handshake_type == SSL3_MT_CERTIFICATE:
                    # Process the certificate itself
                    cert_chain_len = struct.unpack("!I", b"\x00"+data.read(3))[0]
                    bytes_processed = 0
                    while (bytes_processed < cert_chain_len):
                        try:
                            cert_data_len = struct.unpack("!I", b"\x00"+data.read(3))[0]
                            cert_data = data.read(cert_data_len)
                            bytes_processed = 3 + cert_data_len
                            sha1 = hashlib.sha1(cert_data).hexdigest()
                            if sha1 in self.hashes:
                                bad_guy = self.hashes[sha1]
                                self.write("Certificate hash match: {}".format(bad_guy), **conn.info())
                        except struct.error as e:
                            break
                else:
                    # Ignore any layers that are not a certificate
                    data.read(handshake_len)
                    continue

        return conn, blob
