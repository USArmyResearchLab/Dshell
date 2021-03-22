"""
NBNS plugin
"""

from struct import unpack

import dshell.core
from dshell.output.alertout import AlertOutput

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


class DshellPlugin(dshell.core.PacketPlugin):
    def __init__(self):
        super().__init__(   name='nbns',
                            description='Extract client information from NBNS traffic',
                            longdescription="""
The nbns (NetBIOS Name Service) plugin will extract the Transaction ID, Protocol Info, 
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

        decode -d nbns 2014-12-08-traffic-analysis-exercise.pcap

          OUTPUT (first few packets):
            [nbns] 2014-12-08 18:19:13  192.168.204.137:137   ->    192.168.204.2:137   ** 
                    Transaction ID:         0xb480   
                    Info:                   NB_NAME_QUERY    
                    Client Hostname:        WPAD             
                    Client MAC:             00:0C:29:9D:B8:6D 
             **
            [nbns] 2014-12-08 18:19:14  192.168.204.137:137   ->    192.168.204.2:137   ** 
                    Transaction ID:         0xb480   
                    Info:                   NB_NAME_QUERY    
                    Client Hostname:        WPAD             
                    Client MAC:             00:0C:29:9D:B8:6D 
             **
            [nbns] 2014-12-08 18:19:16  192.168.204.137:137   ->    192.168.204.2:137   ** 
                    Transaction ID:         0xb480   
                    Info:                   NB_NAME_QUERY    
                    Client Hostname:        WPAD             
                    Client MAC:             00:0C:29:9D:B8:6D 
             **
            [nbns] 2014-12-08 18:19:17  192.168.204.137:137   ->  192.168.204.255:137   ** 
                    Transaction ID:         0xb480   
                    Info:                   NB_NAME_QUERY    
                    Client Hostname:        WPAD             
                    Client MAC:             00:0C:29:9D:B8:6D 
             **
  """,
                            bpf='(udp and port 137)',
                            output=AlertOutput(label=__name__),
                            author='dek',
                            )
        self.mac_address = None
        self.client_hostname = None
        self.xid = None
        self.prot_info = None
        

    def packet_handler(self, pkt):
        
        # iterate through the layers and find the NBNS layer
        nbns_packet = pkt.pkt.upper_layer
        try:
            nbns_packet = nbns_packet.upper_layer
        except IndexError as e:
            self.logger.error('{}: could not parse session data \
                      (NBNS packet not found)'.format(str(e)))
            # pypacker may throw an Exception here; could use 
            #   further testing
            return


        # Extract the Client hostname from the connection data
        # It is represented as 32-bytes half-ASCII
        try:
            nbns_name = unpack('32s', pkt.data[13:45])[0]
        except Exception as e:
            self.logger.error('{}: (NBNS packet not found)'.format(str(e)))
            return


        # Decode the 32-byte half-ASCII name to its 16 byte NetBIOS name
        try:
            if len(nbns_name) == 32:
                decoded = []
                for i in range(0,32,2):
                    nibl = hex(ord(chr(nbns_name[i])) - ord('A'))[2:]
                    nibh = hex(ord(chr(nbns_name[i+1])) - ord('A'))[2:]
                    decoded.append(chr(int(''.join((nibl, nibh)), 16)))

                # For uniformity, strip excess byte and space chars
                self.client_hostname = ''.join(decoded)[0:-1].strip()
            else:
                self.client_hostname = str(nbns_name)

        except ValueError as e:
            self.logger.error('{}: Hostname in improper format \
                      (NBNS packet not found)'.format(str(e)))
            return


        # Extract the Transaction ID from the NBNS packet
        xid = unpack('2s', pkt.data[0:2])[0]
        self.xid = "0x{}".format(xid.hex())

        # Extract the opcode info from the NBNS Packet
        op = unpack('2s', pkt.data[2:4])[0]
        op_hex = op.hex()
        op = int(op_hex, 16)
        # Remove excess bits
        op = (op >> 11) & 15

        # Decode protocol info if it was present in the payload
        try: 
            self.prot_info = nbns_op[op]
        except:
            self.prot_info = "0x{}".format(op_hex)

        # Extract the MAC address from the ethernet layer of the packet
        self.mac_address = pkt.smac 

        # Allow for unknown hostnames
        if not self.client_hostname:
            self.client_hostname = "" 

        if self.xid and self.prot_info and self.client_hostname and self.mac_address:
            self.write('\n\tTransaction ID:\t\t{:<8} \n\tInfo:\t\t\t{:<16} \n\tClient Hostname:\t{:<16} \n\tClient MAC:\t\t{:<18}\n'.format(
                        self.xid, self.prot_info, self.client_hostname, self.mac_address), **pkt.info(), dir_arrow='->')
            return pkt


if __name__ == "__main__":
    print(DshellPlugin())
