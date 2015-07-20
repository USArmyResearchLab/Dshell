import dpkt
import dshell
import util
from struct import unpack
import binascii 

class DshellDecoder(dshell.UDPDecoder):

    def __init__(self):
        dshell.UDPDecoder.__init__(self,
                            name='dhcp',
                            description='extract client information from DHCP messages',
                            longdescription="""
The dhcp decoder will extract the Transaction ID, Client Hostname, and 
Client MAC address from every UDP DHCP packet found in the given pcap
using port 67.  DHCP uses BOOTP as its transport protocol.  
BOOTP traffic generally uses ports 67 and 68 for outgoing and incoming traffic.
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

        decode -d dhcp /2015-03-03-traffic-analysis-exercise.pcap

            OUTPUT:
            dhcp 2015-03-03 14:05:10   172.16.101.196:68    --     172.16.101.1:67    ** Transaction ID: 0xba5a2cfe   Client Hostname: Gregory-PC      Client MAC: 38:2c:4a:3d:ef:01    **
            dhcp 2015-03-03 14:08:40   172.16.101.196:68    --  255.255.255.255:67    ** Transaction ID: 0x6a482406   Client Hostname: Gregory-PC      Client MAC: 38:2c:4a:3d:ef:01    **
            dhcp 2015-03-03 14:10:11   172.16.101.196:68    --     172.16.101.1:67    ** Transaction ID: 0xe74b17fe   Client Hostname: Gregory-PC      Client MAC: 38:2c:4a:3d:ef:01    **
            dhcp 2015-03-03 14:12:50   172.16.101.196:68    --  255.255.255.255:67    ** Transaction ID: 0xd62614a0   Client Hostname: Gregory-PC      Client MAC: 38:2c:4a:3d:ef:01    **
""",
                            filter='(udp and port 67)',
                            author='dek',
                            )
        self.mac_address = None
        self.client_hostname = None
        self.xid = None

  
    # A packetHandler is used to ensure that every DHCP packet in the traffic is parsed
    def packetHandler(self, udp, data):
        try:
            dhcp_packet = dpkt.dhcp.DHCP(data)
        except dpkt.NeedData as e:
            self.warn('{} dpkt could not parse session data (DHCP packet not found)'.format(str(e)))
            return

        # Pull the transaction ID from the packet
        self.xid = hex(dhcp_packet.xid)

        # if we have a DHCP INFORM PACKET
        if dhcp_packet.op == dpkt.dhcp.DHCP_OP_REQUEST:
            self.debug(dhcp_packet.op)
            for option_code, msg_value in dhcp_packet.opts:

                # if opt is CLIENT_ID (61)
                # unpack the msg_value and reformat the MAC address
                if option_code == dpkt.dhcp.DHCP_OPT_CLIENT_ID:
                    hardware_type, mac = unpack('B6s', msg_value)
                    mac = binascii.hexlify(mac)
                    self.mac_address = ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])

                # if opt is HOSTNAME (12)
                elif option_code == dpkt.dhcp.DHCP_OPT_HOSTNAME:
                    self.client_hostname = msg_value
      
  
        if self.xid and self.client_hostname and self.mac_address:
            self.alert('Transaction ID: {0:<12} Client Hostname: {1:<15} Client MAC: {2:<20}'.format(
                       self.xid, self.client_hostname,  self.mac_address), **udp.info())


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
