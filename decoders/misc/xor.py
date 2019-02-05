import dshell
import util
import struct


class DshellDecoder(dshell.TCPDecoder):

    def __init__(self):
        self.xorconn = {}  # required to track each individual connection
        dshell.TCPDecoder.__init__(self,
                                   name='xor',
                                   description='XOR an entire stream with a given single byte key',
                                   filter="tcp",
                                   author='twp',
                                   optiondict={
                                       'key': {'type': 'str', 'default': '0xff', 'help': 'xor key [default 255]'},
                                       'cskey': {'type': 'str', 'default': None, 'help': 'c->s xor key [default None]'},
                                       'sckey': {'type': 'str', 'default': None, 'help': 's->c xor key [default None]'},
                                       'resync': {'action': 'store_true', 'help': 'resync if the key is seen in the stream'},
                                   }
                                   )
        # sets chainable to true and requires connectionInitHandler() and
        # connectionCloseHandler()
        self.chainable = True

    def preModule(self, *args, **kwargs):
        dshell.TCPDecoder.preModule(self, *args, **kwargs)
        # twp handle hex keys
        self.key = self.makeKey(self.key)
        if self.cskey:
            self.cskey = self.makeKey(self.cskey)
        if self.sckey:
            self.sckey = self.makeKey(self.sckey)

    def makeKey(self, key):
        if key.startswith('"'):
            return key[1:-1]
        if key.startswith('0x'):
            k, key = '', key[2:]
            for i in xrange(0, len(key), 2):
                k += chr(int(key[i:i + 2], 16))
            return k
        else:
            return struct.pack('I', int(key))

    #
    # connectionInitHandler is required as this module (and all other chainable modules)  will have to track all
    # each connection independently of dshell.TCPDecoder
    #
    def connectionInitHandler(self, conn):
        # need to set up a custom connection tracker to handle
        self.xorconn[conn.addr] = dshell.Connection(self, conn.addr, conn.ts)
        self.xorconn[conn.addr].nextoffset = conn.nextoffset
        self.xorconn[conn.addr].proto = conn.proto
        self.xorconn[conn.addr].info(proto=conn.proto)

    #
    # Each blob will be xor'ed and the "newblob" data will be added to the connection
    # we are individually tracking
    #
    def blobHandler(self, conn, blob):
        k = 0  # key index
        # create new data (ie. pkt data)
        # with appropriate key
        data, newdata = blob.data(), ''
        self.debug('IN ' + util.hexPlusAscii(blob.data()))
        if self.cskey != None and blob.direction == 'cs':
            key = self.cskey
        elif self.sckey != None and blob.direction == 'sc':
            key = self.sckey
        else:
            key = self.key
        for i in xrange(len(data)):
            if self.resync and data[i:i + len(key)] == key:
                k = 0  # resync if the key is seen
            # xor this byte with the aligned byte from the key
            newdata += chr(ord(data[i]) ^ ord(key[k]))
            k = (k + 1) % len(key)  # move key position
        # update our connection object with the new data
        newblob = self.xorconn[conn.addr].update(
            conn.endtime, blob.direction, newdata)
        self.debug('OUT ' + repr(self.key) + ' ' + util.hexPlusAscii(newdata))
        # if there is another decoder we want to pass this data too
        if newblob and 'blobHandler' in dir(self.subDecoder):
            # pass to the subDecoder's blobHandler()
            self.subDecoder.blobHandler(self.xorconn[conn.addr], newblob)

    #
    # The connection has finished without errors, then we pass the entire connection to the subDecoder's
    # connectionHandler()
    #
    def connectionHandler(self, conn):
        if conn.addr in self.xorconn:
            self.xorconn[conn.addr].proto = conn.proto
            if 'connectionHandler' in dir(self.subDecoder):
                self.subDecoder.connectionHandler(self.xorconn[conn.addr])
            else:
                self.write(self.xorconn[conn.addr])

    #
    # connectionCloseHandler is called when:
    # - a connection finishes w/o errors (no data loss)
    # - a connection finishes w errors
    #
    # If the connection exists in our custom connection tracker (self.xorconn),
    # we will have to pass it to the subDecoder's connectionCloseHandler
    #
    #
    def connectionCloseHandler(self, conn):
        if conn.addr in self.xorconn:
            if 'connectionCloseHandler' in dir(self.subDecoder):
                self.subDecoder.connectionCloseHandler(self.xorconn[conn.addr])
            del self.xorconn[conn.addr]


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
