"""
XOR the data in every packet with a user-provided key. Multiple keys can be used
for different data directions.
"""

import struct

import dshell.core
import dshell.util
from dshell.output.output import Output

class DshellPlugin(dshell.core.ConnectionPlugin):
    def __init__(self):
        super().__init__(
            name="xor",
            description="XOR every packet with a given key",
            output=Output(label=__name__),
            bpf="tcp",
            author="twp,dev195",
            optiondict={
                "key": {
                    "type": str,
                    "default": "0xff",
                    "help": "xor key in hex format (default: 0xff)",
                    "metavar": "0xHH"
                },
                "cskey": {
                    "type": str,
                    "default": None,
                    "help": "xor key to use for client-to-server data (default: None)",
                    "metavar": "0xHH"
                },
                "sckey": {
                    "type": str,
                    "default": None,
                    "help": "xor key to use for server-to-client data (default: None)",
                    "metavar": "0xHH"
                },
                "resync": {
                    "action": "store_true",
                    "help": "resync the key index if the key is seen in the data"
                }
            }
        )

    def __make_key(self, key):
        "Convert a user-provided key into a standard format plugin can use."
        if key.startswith("0x") or key.startswith("\\x"):
            # Convert a hex key
            oldkey = key[2:]
            newkey = b''
            for i in range(0, len(oldkey), 2):
                try:
                    newkey += struct.pack('B', int(oldkey[i:i + 2], 16))
                except ValueError as e:
                    self.logger.warning("Error converting hex. Will treat as raw string. - {!s}".format(e))
                    newkey = key.encode('ascii')
                    break
        else:
            try:
                # See if it's a numeric key
                newkey = int(key)
                newkey = struct.pack('I', newkey)
            except ValueError:
                # otherwise, convert string key to bytes as it is
                newkey = key.encode('ascii')
        self.logger.debug("__make_key: {!r} -> {!r}".format(key, newkey))
        return newkey

    def premodule(self):
        self.key = self.__make_key(self.key)
        if self.cskey:
            self.cskey = self.__make_key(self.cskey)
        if self.sckey:
            self.sckey = self.__make_key(self.sckey)

    def connection_handler(self, conn):
        for blob in conn.blobs:
            key_index = 0
            if self.sckey and blob.direction == 'sc':
                key = self.sckey
            elif self.cskey and blob.direction == 'cs':
                key = self.cskey
            else:
                key = self.key
            for pkt in blob.packets:
                # grab the data from the TCP layer and down
                data = pkt.data
                # data = pkt.pkt.upper_layer.upper_layer.body_bytes
                self.logger.debug("Original:\n{}".format(dshell.util.hex_plus_ascii(data)))
                # XOR the data and store it in new_data
                new_data = b''
                for i in range(len(data)):
                    if self.resync and data[i:i + len(key)] == key:
                        key_index = 0
                    x = data[i] ^ key[key_index]
                    new_data += struct.pack('B', x)
                    key_index = (key_index + 1) % len(key)
                pkt.data = new_data
                # # rebuild the packet by adding together each of the layers
                # pkt.rawpkt = pkt.pkt.header_bytes + pkt.pkt.upper_layer.header_bytes + pkt.pkt.upper_layer.upper_layer.header_bytes + new_data
                self.logger.debug("New:\n{}".format(dshell.util.hex_plus_ascii(new_data)))
        return conn
