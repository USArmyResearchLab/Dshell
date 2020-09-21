"""
Detects failed attempts to connect (SYN followed by RST/ACK)
"""

import dshell.core
from dshell.output.alertout import AlertOutput

from pypacker.layer4 import tcp

class DshellPlugin(dshell.core.PacketPlugin):

    def __init__(self):
        super().__init__(
            name="SYN/RST",
            description="Detects failed attempts to connect (SYN followed by RST/ACK)",
            author="bg",
            bpf="(ip and (tcp[13]=2 or tcp[13]=20)) or (ip6 and tcp)",
            output=AlertOutput(label=__name__)
        )

    def premodule(self):
        # Cache to hold SYNs waiting to pair with RST/ACKs
        self.tracker = {}

    def packet_handler(self, pkt):
        # Check if SYN or RST/ACK. Discard non-matches.
        if pkt.tcp_flags not in (tcp.TH_SYN, tcp.TH_RST|tcp.TH_ACK):
            return

        # Try to find the TCP layer
        tcpp = pkt.pkt.upper_layer
        while not isinstance(tcpp, tcp.TCP):
            try:
                tcpp = tcpp.upper_layer
            except AttributeError:
                # There doesn't appear to be a TCP layer, for some reason
                return

        if tcpp.flags == tcp.TH_SYN:
            seqnum = tcpp.seq
            key = "{}|{}|{}|{}|{}".format(
                pkt.sip, pkt.sport, seqnum, pkt.dip, pkt.dport)
            self.tracker[key] = pkt
        elif tcpp.flags == tcp.TH_RST|tcp.TH_ACK:
            acknum = tcpp.ack - 1
            tmpkey = "{}|{}|{}|{}|{}".format(
                pkt.dip, pkt.dport, acknum, pkt.sip, pkt.sport)
            if tmpkey in self.tracker:
                msg = "Failed connection [initiated by {}]".format(pkt.dip)
                self.write(msg, **pkt.info())
                oldpkt = self.tracker[tmpkey]
                del self.tracker[tmpkey]
                return [oldpkt, pkt]
