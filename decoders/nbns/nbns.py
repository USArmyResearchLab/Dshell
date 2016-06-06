import dpkt
import dshell
from struct import unpack


# A few common NBNS Protocol Info Opcodes
# Due to a typo in RFC 1002, 0x9 is also acceptable, but rarely used 
#   for 'NetBios Refresh'
# 'NetBios Multi-Homed Name Regsitration' (0xf) was added after the RFC
nbns_op = { 0: 'NB_NAME_QUERY', 
            5: 'NB_REGISTRATION',
            6: 'NB_RELEASE', 
            7: 'NB_WACK',
            8: 'NB_REFRESH',
            9: 'NB_REFRESH', 
            15: 'NB_MULTI_HOME_REG' }


class DshellDecoder(dshell.UDPDecoder):

    def __init__(self):
        dshell.UDPDecoder.__init__(self,
                            name='nbns',
                            description='Extract client information from NBNS traffic',
                            longdescription="""
The nbns (NetBIOS Name Service) decoder will extract the Transaction ID, Protocol Info, 
Client Hostname, and Client MAC address from every UDP NBNS packet found in the given 
pcap using port 137.  UDP is the standard transport protocol for NBNS traffic.
This filter pulls pertinent information from NBNS packets.

Examples:

    General usage:

        decode -d nbns <pcap>

            This will display the connection info including the timestamp,
            the source IP, destination IP, Transaction ID, Protocol Info,
            Client Hostname, and the Client MAC address in a tabular format.


    Malware Traffic Analysis Exercise Traffic from 2014-12-08 where a user was hit with a Fiesta exploit kit:
        <http://www.malware-traffic-analysis.net/2014/12/08/2014-12-08-traffic-analysis-exercise.pcap>
    We want to find out more about the infected machine, and some of this information can be pulled from NBNS traffic

        decode -d nbns /2014-12-08-traffic-analysis-exercise.pcap

          OUTPUT (first few packets):
            nbns 2014-12-08 18:19:13  192.168.204.137:137   --    192.168.204.2:137   ** 
	            Transaction ID:	0xb480   
	            Info:		NB_NAME_QUERY    
	            Client Hostname:	WPAD             
	            Client MAC:		00:0c:29:9d:b8:6d 
            **
            nbns 2014-12-08 18:19:14  192.168.204.137:137   --    192.168.204.2:137   ** 
	            Transaction ID:	0xb480   
	            Info:		NB_NAME_QUERY    
	            Client Hostname:	WPAD             
	            Client MAC:		00:0c:29:9d:b8:6d 
            **
            nbns 2014-12-08 18:19:16  192.168.204.137:137   --    192.168.204.2:137   ** 
	            Transaction ID:	0xb480   
	            Info:		NB_NAME_QUERY    
	            Client Hostname:	WPAD             
	            Client MAC:		00:0c:29:9d:b8:6d 
            **
            nbns 2014-12-08 18:19:17  192.168.204.137:137   --  192.168.204.255:137   ** 
	            Transaction ID:	0xb480   
	            Info:		NB_NAME_QUERY    
	            Client Hostname:	WPAD             
	            Client MAC:		00:0c:29:9d:b8:6d 
  """,
                            filter='udp and port 137',
                            author='dek',
                            )
        self.mac_address = None
        self.client_hostname = None
        self.xid = None
        self.prot_info = None
        

    def packetHandler(self, udp, data):
        try:
            nbns_packet = dpkt.netbios.NS(data)
        except (dpkt.dpkt.UnpackError, IndexError) as e:
            self.warn('{}: dpkt could not parse session data \
                      (NBNS packet not found)'.format(str(e)))
            return


        # Extract the Client hostname from the connection data
        # It is represented as 32-bytes half-ASCII
        try:
            nbns_name = unpack('32s', data[13:45])[0]
        except error as e:
            self.warn('{}: (NBNS packet not found)'.format(str(e)))
            return

        
        # Decode the 32-byte half-ASCII name to its 16 byte NetBIOS name
        try:
            self.client_hostname = dpkt.netbios.decode_name(nbns_name)

            # For uniformity, strip excess byte
            self.client_hostname = self.client_hostname[0:-1]
        except ValueError as e:
            self.warn('{}: Hostname in improper format \
                      (NBNS packet not found)'.format(str(e)))
            return


        # Extract the Transaction ID from the NBNS packet
        self.xid = hex(nbns_packet.id)

        # Extract the opcode info from the NBNS Packet
        op = nbns_packet.op
        # Remove excess bits
        op = (op >> 11) & 15

        # Extract protocol info if present in the payload
        if nbns_op[op]:
            self.prot_info = nbns_op[op]
        else:
            self.prot_info = hex(nbns_packet.op)

        # Extract the MAC address from the ethernet layer of the packet
        self.mac_address = udp.smac 
       

        if self.xid and self.prot_info and self.client_hostname and self.mac_address:
            self.alert('\n\tTransaction ID:\t\t{:<8} \n\tInfo:\t\t\t{:<16} \n\tClient Hostname:\t{:<16} \n\tClient MAC:\t\t{:<18}\n'.format(
                        self.xid, self.prot_info, self.client_hostname, self.mac_address), **udp.info())


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
