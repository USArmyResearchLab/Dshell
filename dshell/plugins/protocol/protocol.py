'''
Tries to find traffic that does not belong to the following protocols:
TCP, UDP, or ICMP
'''

import dshell.core
from dshell.output.alertout import AlertOutput

class DshellPlugin(dshell.core.PacketPlugin):

    def __init__(self):
        super().__init__(
            name='Uncommon Protocols',
            description='Finds uncommon (i.e. not tcp, udp, or icmp) protocols in IP traffic',
            bpf='(ip or ip6) and not tcp and not udp and not icmp and not icmp6',
            author='bg',
            output=AlertOutput(label=__name__),
        )

    def packet_handler(self, packet):
        self.write(f'PROTOCOL: {packet.protocol} ({packet.protocol_num})', **packet.info(), dir_arrow='->')
        return packet
