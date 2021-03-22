"""
Generates pcap output

Can be used alone or chained at the end of plugins for a kind of filter.

Use --pcapwriter_outfile to separate its output from that of other plugins.

Example uses include:
 - merging multiple pcap files into one
   (decode -d pcapwriter ~/pcap/* >merged.pcap)
 - saving relevant traffic by chaining with another plugin
   (decode -d track+pcapwriter --track_source=192.168.1.1 --pcapwriter_outfile=merged.pcap ~/pcap/*)
 - getting pcap output from plugins that can't use pcapout
   (decode -d web+pcapwriter ~/pcap/*)
"""

import struct

import dshell.core

class DshellPlugin(dshell.core.PacketPlugin):

    def __init__(self, *args, **kwargs):
        super().__init__(
            name="pcap writer",
            description="Used to generate pcap output for plugins that can't use -o pcapout",
            longdescription="""Generates pcap output

Can be used alone or chained at the end of plugins for a kind of filter.

Use --pcapwriter_outfile to separate its output from that of other plugins.

Example uses include:
 - merging multiple pcap files into one (decode -d pcapwriter ~/pcap/* --pcapwriter_outfile=merged.pcap)
 - saving relevant traffic by chaining with another plugin (decode -d track+pcapwriter --track_source=192.168.1.1 --pcapwriter_outfile=merged.pcap ~/pcap/*)
 - getting pcap output from plugins that can't use pcapout (decode -d web+pcapwriter ~/pcap/*)
""",
            author="dev195",
            optiondict={
                "outfile": {
                    "type": str,
                    "help": "Write to FILE instead of stdout",
                    "metavar": "FILE",
                }
            }
        )
        self.outfile = None  # Filled in with constructor
        self.pcap_fh = None

    def prefile(self, infile=None):
        # Default to setting pcap output filename based on first input file.
        if not self.outfile:
            self.outfile = (infile or self.current_pcap_file) + ".pcap"

    def packet_handler(self, packet: dshell.Packet):
        # If we don't have a pcap file handle, this is our first packet.
        # Create the output pcap file handle.
        # NOTE: We want to create the file on the first packet instead of premodule so we
        #   have a chance to use the input file as part of our output filename.
        if not self.pcap_fh:
            self.pcap_fh = open(self.outfile, mode="wb")
            link_layer_type = self.link_layer_type or 1
            # write the header:
            # magic_number, version_major, version_minor, thiszone, sigfigs,
            # snaplen, link-layer type
            self.pcap_fh.write(
                struct.pack('IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_layer_type))

        ts = packet.ts
        rawpkt = packet.rawpkt
        pktlen = packet.pktlen
        self.pcap_fh.write(struct.pack('II', int(ts), int((ts - int(ts)) * 1000000)))
        self.pcap_fh.write(struct.pack('II', len(rawpkt), pktlen))
        self.pcap_fh.write(rawpkt)

        return packet

    def postmodule(self):
        if self.pcap_fh:
            self.pcap_fh.close()


if __name__ == "__main__":
    print(DshellPlugin())
