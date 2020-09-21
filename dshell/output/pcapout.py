"""
This output module generates pcap output when given very specific arguments.
"""

from dshell.output.output import Output
import struct
import sys

# TODO get this module to work with ConnectionPlugins

class PCAPOutput(Output):
    "Writes data to a pcap file."
    _DESCRIPTION = "Writes data to a pcap file (does not work with connection-based plugins)"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, mode='wb', **kwargs)
        if self.fh == sys.stdout:
            # Switch to a stdout that can handle byte output
            self.fh = sys.stdout.buffer
        # Since we have to wait until the link-layer type is set, we wait
        # until the first write() operation before writing the pcap header
        self.header_written = False

    def write(self, *args, **kwargs):
        """
        Write a packet to the pcap file.

        Arguments:
            pktlen  : raw packet length
            rawpkt  : raw packet data string
            ts      : timestamp
            link_layer_type :   link-layer type (optional) (default: 1)
                                (e.g. 1 for Ethernet, 105 for 802.11, etc.)
        """
        # The first time write() is called, the pcap header is written.
        # This is to allow the plugin enough time to figure out what the
        # link-layer type is for the data.
        if not self.header_written:
            link_layer_type = kwargs.get('link_layer_type', 1)
            # write the header:
            # magic_number, version_major, version_minor, thiszone, sigfigs,
            # snaplen, link-layer type
            self.fh.write(
                struct.pack('IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_layer_type))
            self.header_written = True

        # Attempt to fetch the required fields
        pktlen = kwargs.get('pktlen', None)
        rawpkt = kwargs.get('rawpkt', None)
        ts = kwargs.get('ts', None)
        if pktlen is None or rawpkt is None or ts is None:
            raise TypeError("PCAPOutput.write() requires at least these arguments to write packet data: pktlen, rawpkt, and ts.\n\tIt is possible this plugin is not configured to handle pcap output.")

        self.fh.write(
            struct.pack('II', int(ts), int((ts - int(ts)) * 1000000)))
        self.fh.write(struct.pack('II', len(rawpkt), pktlen))
        self.fh.write(rawpkt)

    def close(self):
        if self.fh == sys.stdout.buffer:
            self.fh = sys.stdout
        super().close()

obj = PCAPOutput
