'''
@author: tparker
'''

import dshell
import netflowout


class DshellDecoder(dshell.TCPDecoder):

    '''activity tracker '''

    def __init__(self, **kwargs):
        '''
        Constructor
        '''
        self.sessions = {}
        self.alerts = False
        self.file = None
        dshell.TCPDecoder.__init__(self,
            name='country',
            description='filter connections on geolocation (country code)',
            longdescription="""
country: filter connections on geolocation (country code)

Chainable decoder to filter TCP/UDP streams on geolocation data.  If no
downstream (+) decoders are specified, netflow data will be printed to
the screen.

Mandatory option:

  --country_code: specify (2 character) country code to filter on

Default behavior:

  If either the client or server IP address matches the specified country,
  the stream will be included.

Modifier options:

  --country_neither: Include only streams where neither the client nor the
                     server IP address matches the specified country.

  --country_both:    Include only streams where both the client AND the server
                     IP addresses match the specified country.

  --country_notboth: Include streams where the specified country is NOT BOTH
                     the client and server IP.  Streams where it is one or
                     the other may be included.


Example:

  decode -d country traffic.pcap -W USonly.pcap --country_code US
  decode -d country+followstream traffic.pcap --country_code US --country_notboth
""",
            filter="ip or ip6",
            author='twp',
            optiondict={
                'code': {'type': 'string', 'help': 'two-char country code'},
                'neither': {'action': 'store_true', 'help': 'neither (client/server) is in specified country'},
                'both': {'action': 'store_true', 'help': 'both (client/server) ARE in specified country'},
                'notboth': {'action': 'store_true', 'help': 'specified country is not both client and server'},
                'alerts': {'action': 'store_true'}
            }
        )
        # instantiate a decoder that will call back to us once the IP decoding is done
        self.__decoder = dshell.IPDecoder()
        self.out = netflowout.NetflowOutput()
        self.chainable = True

    def decode(self, *args):
        if len(args) is 3:
            pktlen, pktdata, ts = args
        else:
            ts, pktdata = args
            pktlen = len(pktdata)
        # do normal decoder stack to track session
        dshell.TCPDecoder.decode(self, pktlen, pktdata, ts)
        # our hook to decode the ip/ip6 addrs, then dump the addrs and raw packet to our callback
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
        '''see if we have a country match and if so, flag this session for forwarding or dumping'''
        m = self.__countryTest(conn)
        if m:
            self.sessions[conn.addr] = m

    def __countryTest(self, conn):
        # If no country code specified, pass all traffic through
        if not self.code:
            return True
        # check criteria
        if self.neither and conn.clientcountrycode != self.code and conn.servercountrycode != self.code:
            return 'neither ' + self.code
        if self.both and conn.clientcountrycode == self.code and conn.servercountrycode == self.code:
            return 'both ' + self.code
        if self.notboth and ((conn.clientcountrycode == self.code) ^ (conn.servercountrycode == self.code)):
            return 'not both ' + self.code
        if not self.both and conn.clientcountrycode == self.code:
            return 'client ' + self.code
        if not self.both and conn.servercountrycode == self.code:
            return 'server ' + self.code
        # no match
        return None

    def connectionHandler(self, conn):
        if conn.addr in self.sessions and self.alerts:
            self.alert(self.sessions[conn.addr], **conn.info())

    def connectionCloseHandler(self, conn):
        if conn.addr in self.sessions:
            del self.sessions[conn.addr]

dObj = DshellDecoder()
