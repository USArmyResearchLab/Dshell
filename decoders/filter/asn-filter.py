import dshell
import util
import netflowout


class DshellDecoder(dshell.TCPDecoder):

    def __init__(self, **kwargs):
        self.sessions = {}
        self.alerts = False
        self.file = None
        dshell.TCPDecoder.__init__(self,
                                   name='asn-filter',
                                   description='filter connections on autonomous system number (ASN)',
                                   longdescription="""
This decoder filters connections by autonomous system numbers/names (ASN).

Chainable decoder used to filter TCP/UDP streams by ASNs. If no 
downstream (+) decoder is used the netflow data will be printed to 
the screen (when using --asn-filter_alerts). If used without specifying
a asn string, the asn-filter will filter nothing out and pass 
everything onto the next decoder or print it.

Examples:
    
    decode -d asn-filter <pcap> --asn-filter_asn AS8075 --asn-filter_alerts

        This will print the connection info for all connections where 
        AS8075 is the ASN for either the server of client.

    decode -d asn-filter <pcap> --asn-filter_asn Google --asn-filter_alerts
        
        This will print the connection info for all connections where
        "Google" appeared in the ASN information.

    decode -d asn-filter+followstream <pcap> --asn-filter_asn AS8075
        
        This will filter the streams by ASN and feed them into the 
        followstream decoder.
""",
                                   filter="ip or ip6",
                                   author='twp/nl',
                                   optiondict={
                                        'asn': {'type': 'string', 'help': 'asn for client or server'},
                                        'alerts': {'action': 'store_true'}})
        '''instantiate an decoder that will call back to us once the IP decoding is done'''
        self.__decoder = dshell.IPDecoder()
        self.out = netflowout.NetflowOutput()
        self.chainable = True

    def decode(self, *args):
        if len(args) is 3:
            pktlen, pktdata, ts = args  # orig_len,packet,ts format (pylibpcap)
        else:  # ts,pktdata (pypcap)
            ts, pktdata = args
            pktlen = len(pktdata)
        '''do normal decoder stack to track session '''
        dshell.TCPDecoder.decode(self, pktlen, pktdata, ts)
        '''our hook to decode the ip/ip6 addrs, then dump the addrs and raw packet to our callback'''
        self.__decoder.IPHandler = self.__callback  # set private decoder to our callback
        self.__decoder.decode(pktlen, pktdata, ts, raw=pktdata)

    def __callback(self, addr, pkt, ts, raw=None, **kw):
        '''substitute IPhandler for forwarding packets to subdecoders'''
        if addr in self.sessions or (addr[1], addr[0]) in self.sessions:  # if we are not passing this session, drop the packet
            if self.subDecoder:
                # make it look like a capture
                self.subDecoder.decode(len(raw), str(raw), ts)
            else:
                self.dump(raw, ts)

    def connectionInitHandler(self, conn):
        '''see if we have an ASN match and if so, flag this session for forwarding or dumping'''
        m = self.__asnTest(conn)
        if m:
            self.sessions[conn.addr] = m

    def __asnTest(self, conn):
        # If no ASN specified, pass all traffic through
        if not self.asn:
            return True
        # check criteria
        if self.asn.lower() in conn.clientasn.lower():
            return u'client {0}'.format(conn.clientasn)
        if self.asn.lower() in conn.serverasn.lower():
            return u'server {0}'.format(conn.serverasn)
        # no match
        return None

    def connectionHandler(self, conn):
        if conn.addr in self.sessions and self.alerts:
            self.alert(self.sessions[conn.addr], **conn.info())

    def connectionCloseHandler(self, conn):
        if conn.addr in self.sessions:
            del self.sessions[conn.addr]

dObj = DshellDecoder()
if __name__ == "__main__":
  print dObj
