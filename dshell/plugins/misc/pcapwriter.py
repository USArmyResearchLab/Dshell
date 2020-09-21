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

import dshell.core
from dshell.output.pcapout import PCAPOutput

import sys

class DshellPlugin(dshell.core.PacketPlugin):

    def __init__(self, *args, **kwargs):
        super().__init__(
            name="pcap writer",
            description="Used to generate pcap output for plugins that can't use -o pcapout",
            longdescription="""Generates pcap output

Can be used alone or chained at the end of plugins for a kind of filter.

Use --pcapwriter_outfile to separate its output from that of other plugins.

Example uses include:
 - merging multiple pcap files into one (decode -d pcapwriter ~/pcap/* >merged.pcap)
 - saving relevant traffic by chaining with another plugin (decode -d track+pcapwriter --track_source=192.168.1.1 --pcapwriter_outfile=merged.pcap ~/pcap/*)
 - getting pcap output from plugins that can't use pcapout (decode -d web+pcapwriter ~/pcap/*)
""",
            author="dev195",
            output=PCAPOutput(label=__name__),
            optiondict={
                "outfile": {
                    "type": str,
                    "help": "Write to FILE instead of stdout",
                    "metavar": "FILE",
                }
            }
        )

    def premodule(self):
        if self.outfile:
            try:
               self.out.reset_fh(filename=self.outfile, mode='wb')
            except OSError as e:
                self.error(str(e))
                sys.exit(1)

    def raw_handler(self, pktlen, pkt, ts):
        rawpkt = pkt.header_bytes + pkt.body_bytes
        self.write(pktlen=pktlen, rawpkt=rawpkt, ts=ts, link_layer_type=self.link_layer_type)
        return pktlen, pkt, ts

if __name__ == "__main__":
    print(DshellPlugin())
