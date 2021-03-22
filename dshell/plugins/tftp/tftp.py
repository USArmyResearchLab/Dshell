"""
TFTP Plugin
In short:
 Goes through UDP traffic, packet by packet, and ties together TFTP file
 streams. If the command line argument is set (--tftp_rip), it will dump the
 files to a directory (--tftp_outdir=<DIR>)

In long:
 Goes through each UDP packet and parses out the TFTP opcode. For read or
 write requests, it sets a placeholder in unset_read_streams or unset_write_streams,
 respectively. These placeholders are moved to open_streams when we first see
 data for the read request or an ACK code for a write request. The reason for
 these placeholders is to allow the server to set the ephemeral port during
 data transfer.

 When it sees a DATA packet, it stores the data under the IP-port-IP-port
 openStream key as 'filedata'. Each of these data packets has an ordered block
 number, and the file data is stored under that block number. It is reassembled
 later. When we consider a stream finished (either the DATA packet is too short
 or there are no more packets), we rebuild the file data, print information
 about the stream, dump the file (optional), and move the information from
 open_streams to closed_streams.

Example:
 Running on sample pcap available here: https://wiki.wireshark.org/TFTP
 With default values, it will display transfers performed
   Dshell> decode -d tftp ~/pcap/tftp_*.pcap
    tftp 2013-05-01 08:24:11    192.168.0.253:50618 --     192.168.0.10:3445  ** read rfc1350.txt (24599 bytes)  **
    tftp 2013-04-27 05:07:59      192.168.0.1:57509 --     192.168.0.13:2087  ** write rfc1350.txt (24599 bytes)  **
 With the --tftp_rip flag, it will generate the same output while reassembling
 the files and saving them in a defined directory (./tftp_out by default)
   Dshell> decode -d tftp --tftp_rip --tftp_outdir=./MyTFTP ~/pcap/tftp_*.pcap
    tftp 2013-05-01 08:24:11    192.168.0.253:50618 --     192.168.0.10:3445  ** read rfc1350.txt (24599 bytes)  **
    tftp 2013-04-27 05:07:59      192.168.0.1:57509 --     192.168.0.13:2087  ** write rfc1350.txt (24599 bytes)  **
   Dshell> ls ./MyTFTP/
    rfc1350.txt  rfc1350.txt_01
 Note: The two files have the same name in the traffic, but have incremented
 filenames when saved
"""

import os
import struct

from pypacker.layer4 import udp

import dshell.core
import dshell.util
from dshell.output.alertout import AlertOutput

class DshellPlugin(dshell.core.PacketPlugin):
    "Primary plugin class"
    # packet opcodes (http://www.networksorcery.com/enp/default1101.htm)
    RRQ = 1  # read request
    WRQ = 2  # write request
    DATA = 3
    ACK = 4
    ERROR = 5
    OACK = 6  # option acknowledgment

    def __init__(self, **kwargs):
        super().__init__(
            name="tftp",
            bpf="udp",
            description="Find TFTP streams and, optionally, extract the files",
            author="dev195",
            output=AlertOutput(label=__name__),
            optiondict={
                "rip": {
                    "action": "store_true",
                    "help": "Rip files from traffic (default: off)",
                    "default": False},
                "outdir": {
                    "help": "Directory to place files when using --rip (default: tftp_out)",
                    "default": "./tftp_out",
                    "metavar": "DIRECTORY"}
            }
        )

        # default information for streams we didn't see the start for
        self.default_stream = {
            'filename': '',
            'mode': '',
            'readwrite': '',
            'closed_connection': False,
            'filedata': {},
            'timestamp': 0
        }

        # containers for various states of streams
        self.open_streams = {}
        self.closed_streams = []
        # These two are holders while waiting for the server to decide on which
        # ephemeral port to use
        self.unset_write_streams = {}
        self.unset_read_streams = {}

    def premodule(self):
        "if needed, create the directory for file output"
        if self.rip and not os.path.exists(self.outdir):
            try:
                os.makedirs(self.outdir)
            except OSError:
                self.error("Could not create directory {!r}. Files will not be dumped.".format(self.outdir))
                self.rip = False

    def postmodule(self):
        "cleanup any unfinished streams"
        self.logger.debug("Unset Read Streams: {!s}".format(self.unset_read_streams))
        self.logger.debug("Unset Write Streams: {!s}".format(self.unset_write_streams))
        while(len(self.open_streams) > 0):
            k = list(self.open_streams)[0]
            self.__closeStream(k, "POSSIBLY INCOMPLETE")

    def packet_handler(self, pkt):
        """
        Handles each UDP packet. It checks the TFTP opcode and parses
        accordingly.
        """
        udpp = pkt.pkt.upper_layer
        while not isinstance(udpp, udp.UDP):
            try:
                udpp = udpp.upper_layer
            except AttributeError:
                # There doesn't appear to be a UDP layer, for some reason
                return

        data = udpp.body_bytes

        try:
            flag = struct.unpack("!H", data[:2])[0]
        except struct.error:
            return   # awful small packet
        data = data[2:]
        if flag == self.RRQ:
            # this packet is requesting to read a file from the server
            try:
                filename, mode = data.split(b"\x00")[0:2]
            except ValueError:
                return  # probably not TFTP
            clientIP, clientPort, serverIP, serverPort = pkt.sip, udpp.sport, pkt.dip, udpp.dport
            self.unset_read_streams[(clientIP, clientPort, serverIP)] = {
                'filename': filename,
                'mode': mode,
                'readwrite': 'read',
                'closed_connection': False,
                'filedata': {},
                'timestamp': pkt.ts
            }

        elif flag == self.WRQ:
            # this packet is requesting to write a file to the server
            try:
                filename, mode = data.split(b"\x00")[0:2]
            except ValueError:
                return  # probably not TFTP
            # in this case, we are writing to the "server"
            clientIP, clientPort, serverIP, serverPort = pkt.sip, udpp.sport, pkt.dip, udpp.dport
            self.unset_write_streams[(clientIP, clientPort, serverIP)] = {
                'filename': filename,
                'mode': mode,
                'readwrite': 'write',
                'closed_connection': False,
                'filedata': {},
                'timestamp': pkt.ts
            }

        elif flag == self.DATA:
            # this packet is sending a chunk of data
            clientIP, clientPort, serverIP, serverPort = pkt.sip, udpp.sport, pkt.dip, udpp.dport
            key = (clientIP, clientPort, serverIP, serverPort)
            if key not in self.open_streams:
                # this is probably an unset read stream; there is no
                # acknowledgement, it just starts sending data
                if (serverIP, serverPort, clientIP) in self.unset_read_streams:
                    self.open_streams[key] = self.unset_read_streams[
                        (serverIP, serverPort, clientIP)]
                    del(self.unset_read_streams[
                        (serverIP, serverPort, clientIP)])
                else:
                    self.open_streams[key] = self.default_stream
            blockNum = struct.unpack("!H", data[:2])[0]
            data = data[2:]
            if len(data) < 512:
                # TFTP uses fixed length data chunks. If it's smaller than the
                # length, then the stream is finished
                closedConn = True
            else:
                closedConn = False
            self.open_streams[key]['filedata'][blockNum] = data
            self.open_streams[key]['closed_connection'] = closedConn

        elif flag == self.ACK:
            # this packet has acknowledged the receipt of a data chunk or
            # allows a write process to begin
            blockNum = struct.unpack("!H", data[:2])[0]
            clientIP, clientPort, serverIP, serverPort = pkt.sip, udpp.sport, pkt.dip, udpp.dport

            # special case: this is acknowledging a write operation and sets
            # the port for receiving
            if blockNum == 0:
                clientIP, clientPort, serverIP, serverPort = pkt.dip, udpp.dport, pkt.sip, udpp.sport
                i = (clientIP, clientPort, serverIP)
                if i in self.unset_write_streams:
                    self.open_streams[
                        (clientIP, clientPort, serverIP, serverPort)] = self.unset_write_streams[i]
                    del(self.unset_write_streams[i])
            # otherwise, check if this is the confirmation for the end of a
            # connection
            elif (clientIP, clientPort, serverIP, serverPort) in self.open_streams and self.open_streams[(clientIP, clientPort, serverIP, serverPort)]['closed_connection']:
                self.__closeStream(
                    (clientIP, clientPort, serverIP, serverPort))
            elif (serverIP, serverPort, clientIP, clientPort) in self.open_streams and self.open_streams[(serverIP, serverPort, clientIP, clientPort)]['closed_connection']:
                self.__closeStream(
                    (serverIP, serverPort, clientIP, clientPort))

        elif flag == self.ERROR:
            # this package is sending an error message
            # TODO handle more of these properly
            errCode = struct.unpack("!H", data[:2])[0]
            errMessage = data[2:].strip()
            if errCode == 1:   # File not found
                clientIP, clientPort, serverIP, serverPort = pkt.dip, udpp.dport, pkt.sip, udpp.sport
                i = (clientIP, clientPort, serverIP)
                if i in self.unset_read_streams:
                    self.open_streams[
                        (serverIP, serverPort, clientIP, clientPort)] = self.unset_read_streams[i]
                    del(self.unset_read_streams[i])
                self.__closeStream(
                    (serverIP, serverPort, clientIP, clientPort), errMessage)

        elif flag == self.OACK:
            pass  # TODO handle options

        return pkt

    def __closeStream(self, key, message=''):
        """
        Called when a stream is finished. It moves the stream from
        open_streams to closed_streams, prints output, and dumps the file
        """
        theStream = self.open_streams[key]
        if not theStream['filename']:
            message = "INCOMPLETE -- missing filename"
        else:
            theStream['filename'] = theStream['filename'].decode('utf-8', "backslashreplace")

        # Rebuild the file from the individual blocks
        rebuiltFile = b''
        for i in sorted(theStream['filedata'].keys()):
            rebuiltFile += theStream['filedata'][i]

        # if we're reading, swap the client and server IP so the output better
        # shows who requested the connection
        if theStream['readwrite'] == 'read':
            ipsNports = (key[2], key[3], key[0], key[1])
        else:
            ipsNports = key

        # print out information about the stream
        msg = "{:5} {} ({} bytes) {}".format(
            theStream['readwrite'],
            theStream['filename'],
            len(rebuiltFile),
            message)
        self.write(msg, ts=theStream['timestamp'], sip=ipsNports[0],
            sport=ipsNports[1], dip=ipsNports[2], dport=ipsNports[3],
            readwrite=theStream['readwrite'], filename=theStream['filename'])

        # dump the file, if that's what the user wants
        if self.rip and len(rebuiltFile) > 0:
            outpath = dshell.util.gen_local_filename(self.outdir, theStream['filename'])
            outfile = open(outpath, 'wb')
            outfile.write(rebuiltFile)
            outfile.close()

        # remove the stream from the list of open streams
        self.closed_streams.append((
            key,
            self.open_streams[key]['closed_connection']
        ))
        del(self.open_streams[key])

