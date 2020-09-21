"""
DHCP Plugin
"""

import dshell.core
import dshell.util
from dshell.output.alertout import AlertOutput

from pypacker.layer4 import udp
from pypacker.layer567 import dhcp

from struct import unpack

class DshellPlugin(dshell.core.PacketPlugin):
    def __init__(self, **kwargs):
        super().__init__(name='dhcp',
                         description='extract client information from DHCP messages',
                         longdescription="""
The dhcp plugin will extract the Transaction ID, Hostname, and
Client ID (MAC address) from every UDP DHCP packet found in the given pcap
using port 67.  DHCP uses BOOTP as its transport protocol.
BOOTP assigns port 67 for the 'BOOTP server' and port 68 for the 'BOOTP client'.
This filter pulls DHCP Inform packets.

Examples:

    General usage:

        decode -d dhcp <pcap>

            This will display the connection info including the timestamp,
            the source IP : source port, destination IP : destination port,
            Transaction ID, Client Hostname, and the Client MAC address
            in a tabular format.


    Malware Traffic Analysis Exercise Traffic from 2015-03-03 where a user was hit with an Angler exploit kit:
        <http://www.malware-traffic-analysis.net/2015/03/03/2015-03-03-traffic-analysis-exercise.pcap>
    We want to find out more about the infected machine, and some of this information can be pulled from DHCP traffic

        decode -d dhcp 2015-03-03-traffic-analysis-exercise.pcap

            OUTPUT:
[dhcp] 2015-03-03 14:05:10   172.16.101.196:68    ->     172.16.101.1:67    ** Transaction ID: 0xba5a2cfe   Client ID (MAC): 38:2C:4A:3D:EF:01    Hostname: Gregory-PC **
[dhcp] 2015-03-03 14:08:40   172.16.101.196:68    ->  255.255.255.255:67    ** Transaction ID: 0x6a482406   Client ID (MAC): 38:2C:4A:3D:EF:01    Hostname: Gregory-PC **
[dhcp] 2015-03-03 14:10:11   172.16.101.196:68    ->     172.16.101.1:67    ** Transaction ID: 0xe74b17fe   Client ID (MAC): 38:2C:4A:3D:EF:01    Hostname: Gregory-PC **
[dhcp] 2015-03-03 14:12:50   172.16.101.196:68    ->  255.255.255.255:67    ** Transaction ID: 0xd62614a0   Client ID (MAC): 38:2C:4A:3D:EF:01    Hostname: Gregory-PC **
""",
                            bpf='(udp and port 67)',
                            output=AlertOutput(label=__name__),
                            author='dek',
                        )
        self.mac_address = None
        self.client_hostname = None
        self.xid = None

    # A packetHandler is used to ensure that every DHCP packet in the traffic is parsed
    def packet_handler(self, pkt):

        # iterate through the layers and find the DHCP layer
        dhcp_packet = pkt.pkt.upper_layer
        while not isinstance(dhcp_packet, dhcp.DHCP):
            try:
                dhcp_packet = dhcp_packet.upper_layer
            except AttributeError:
                # There doesn't appear to be a DHCP layer
                return

        # Pull the transaction ID from the packet
        self.xid = hex(dhcp_packet.xid)

        # if we have a DHCP INFORM PACKET
        if dhcp_packet.op == dhcp.DHCP_OP_REQUEST:
            for opt in list(dhcp_packet.opts):
                try:
                    option_code = opt.type
                    msg_value = opt.body_bytes
                except AttributeError:
                    continue

                # if opt is CLIENT_ID (61)
                # unpack the msg_value and reformat the MAC address
                if option_code == dhcp.DHCP_OPT_CLIENT_ID:
                    hardware_type, mac = unpack('B6s', msg_value)
                    mac = mac.hex().upper()
                    self.mac_address = ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])

                # if opt is HOSTNAME (12)
                elif option_code == dhcp.DHCP_OPT_HOSTNAME:
                    self.client_hostname = msg_value.decode('utf-8')

        # Allow for unknown hostnames
        if not self.client_hostname:
            self.client_hostname = ""

        if self.xid and self.mac_address:
            self.write('Transaction ID: {0:<12} Client ID (MAC): {1:<20} Hostname: {2:<}'.format(
                       self.xid, self.mac_address, self.client_hostname), **pkt.info(), dir_arrow='->')
            return pkt

if __name__ == "__main__":
    print(DshellPlugin())
