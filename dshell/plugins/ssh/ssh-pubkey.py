"""
Extract server ssh public key from key exchange
"""

import dshell.core
from dshell.output.alertout import AlertOutput
import struct
import base64
import hashlib


class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name="ssh-pubkey",
            author="amm",
            description="Extract server ssh public key from key exchange",
            bpf="tcp port 22",
            output=AlertOutput(label=__name__)
        )

    def connection_handler(self, conn):

        server_banner = ''
        sc_blob_count = 0
        cs_blob_count = 0

        info = {}

        for blob in conn.blobs:

            #
            # CS Blobs: Only interest is a client banner
            #
            if blob.direction == 'cs':
                cs_blob_count += 1
                if cs_blob_count > 1:
                    continue
                else:
                    blob.reassemble(allow_overlap=True, allow_padding=True)
                    if not blob.data:
                        continue
                    info['clientbanner'] = blob.data.split(b'\x0d')[0].rstrip()
                    if not info['clientbanner'].startswith(b'SSH'):
                        return conn  # NOT AN SSH CONNECTION
                    try:
                        info['clientbanner'] = info['clientbanner'].decode(
                            'utf-8')
                    except UnicodeDecodeError:
                        return conn
                    continue

            #
            # SC Blobs: Banner and public key
            #
            sc_blob_count += 1
            blob.reassemble(allow_overlap=True, allow_padding=True)
            if not blob.data:
                continue
            d = blob.data

            # Server Banner
            if sc_blob_count == 1:
                info['serverbanner'] = d.split(b'\x0d')[0].rstrip()
                if not info['serverbanner'].startswith(b'SSH'):
                    return conn  # NOT AN SSH CONNECTION
                try:
                    info['serverbanner'] = info['serverbanner'].decode('utf-8')
                except UnicodeDecodeError:
                    pass
                continue

            # Key Exchange Packet/Messages
            mlist = messagefactory(d)
            stop_blobs = False
            for m in mlist:
                if m.message_code == 31 or m.message_code == 33:
                    info['host_pubkey'] = m.host_pub_key
                    stop_blobs = True
                    break
            if stop_blobs:
                break

        #print(repr(info))

        if 'host_pubkey' in info:
            # Calculate key fingerprints
            info['host_fingerprints'] = {}
            for hash_scheme in ("md5", "sha1", "sha256"):
                hashfunction = eval("hashlib."+hash_scheme)
                thisfp = key_fingerprint(info['host_pubkey'], hashfunction)
                info['host_fingerprints'][hash_scheme] = ':'.join(
                    ['%02x' % b for b in thisfp])

            msg = "%s" % (info['host_pubkey'])
            self.write(msg, **info, **conn.info())
            return conn


def messagefactory(data):

    datalen = len(data)
    offset = 0
    msglist = []
    while offset < datalen:
        try:
            msg = sshmessage(data[offset:])
        except ValueError:
            return msglist
        msglist.append(msg)
        offset += msg.packet_len + 4

    return msglist


class sshmessage:

    def __init__(self, rawdata):
        self.__parse_raw(rawdata)

    def __parse_raw(self, data):
        datalen = len(data)
        if datalen < 6:
            raise ValueError

        (self.packet_len, self.padding_len,
         self.message_code) = struct.unpack(">IBB", data[0:6])
        if datalen < self.packet_len + 4:
            raise ValueError
        self.body = data[6:4+self.packet_len]

        # ECDH Kex Reply
        if self.message_code == 31 or self.message_code == 33:
            host_key_len = struct.unpack(">I", self.body[0:4])[0]
            full_key_net = self.body[4:4+host_key_len]
            key_type_name_len = struct.unpack(">I", full_key_net[0:4])[0]
            key_type_name = full_key_net[4:4+key_type_name_len]
            key_data = full_key_net[4+key_type_name_len:]
            if key_type_name_len > 50:
                # something went wrong
                # this probably isn't a code 31
                self.message_code = 0
            else:
                self.host_pub_key = "%s %s" % (key_type_name.decode(
                    'utf-8'), base64.b64encode(full_key_net).decode('utf-8'))


def key_fingerprint(ssh_pubkey, hashfunction=hashlib.sha256):

    # Treat as bytes, not string
    if type(ssh_pubkey) == str:
        ssh_pubkey = ssh_pubkey.encode('utf-8')

    # Strip space from end
    ssh_pubkey = ssh_pubkey.rstrip(b"\r\n\0 ")

    # Only look at first line
    ssh_pubkey = ssh_pubkey.split(b"\n")[0]
    # If two spaces, look at middle segment
    if ssh_pubkey.count(b" ") >= 1:
        ssh_pubkey = ssh_pubkey.split(b" ")[1]

    # Try to decode key as base64
    try:
        keybin = base64.b64decode(ssh_pubkey)
    except:
        sys.stderr.write("Invalid key value:\n")
        sys.stderr.write("  \"%s\":\n" % ssh_pubkey)
        return None

    # Fingerprint
    return hashfunction(keybin).digest()


if __name__ == "__main__":
    print(DshellPlugin())
