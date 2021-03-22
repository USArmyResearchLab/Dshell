"""
Outputs all IPv4/IPv6 traffic, and hex plus ascii with verbose flag
"""

import dshell.core
import dshell.util
from dshell.output.alertout import AlertOutput

class DshellPlugin(dshell.core.PacketPlugin):

    def __init__(self):
        super().__init__(
            name='ip',
            description='IPv4/IPv6 plugin',
            bpf='ip or ip6',
            author='twp',
            output=AlertOutput(label=__name__),
        )

    def packet_handler(self, packet):
        self.write(**packet.info(), dir_arrow='->')
        # If verbose flag set, outputs packet contents in hex and ascii alongside packet info
        self.logger.info("\n" + dshell.util.hex_plus_ascii(packet.rawpkt))
        return packet
