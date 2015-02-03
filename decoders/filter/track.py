'''
@author: tparker
'''

import dshell
import util


class DshellDecoder(dshell.TCPDecoder):

    '''activity tracker '''

    def __init__(self, **kwargs):
        '''
        Constructor
        '''
        self.sources = []
        self.targets = []
        self.sessions = {}
        self.alerts = False
        self.file = None
        dshell.TCPDecoder.__init__(self,
                                   name='track',
                                   description='tracked activity recorder',
                                   longdescription='''captures all traffic to/from target while a specific connection to the target is up
                                specify target(s) ip and/or port as --track_target=ip:port,ip...
                                --track_source=ip,ip.. can be used to limit to specified sources
                                --track_alerts will turn on alerts for session start/end''',
                                   filter="ip",
                                   author='twp',
                                   optiondict={'target': {'action': 'append'},
                                               'source': {'action': 'append'},
                                               'alerts': {'action': 'store_true'}})
        self.chainable = True

        '''instantiate an IPDecoder and replace the IPHandler
         to decode the ip/ip6 addr and then pass the packet
         to _IPHandler, which will write the packet if in addr is in session'''
        self.__decoder = dshell.IPDecoder()

    def preModule(self):
        '''parse the source and target lists'''
        if self.target:
            for tstr in self.target:
                targets = util.strtok(tstr, as_list=True)[0]
                for t in targets:
                    try:
                        parts = t.split(':')
                        if len(parts) == 2:
                            ip, port = parts  # IP:port
                        else:
                            ip, port = t, None  # IPv6 addr
                    except:
                        ip, port = t, None  # IP
                    if ip == '':
                        ip = None  # :port
                    self.targets.append((ip, port))
        if self.source:
            for sstr in self.source:
                sources = util.strtok(sstr, as_list=True)[0]
                for ip in sources:
                    self.sources.append(ip)
        dshell.TCPDecoder.preModule(self)

    def decode(self, *args):
        if len(args) is 3:
            pktlen, pktdata, ts = args  # orig_len,packet,ts format (pylibpcap)
        else:  # ts,pktdata (pypcap)
            ts, pktdata = args
            pktlen = len(pktdata)
        '''do normal decoder stack to track session '''
        dshell.TCPDecoder.decode(self, pktlen, pktdata, ts)
        '''our hook to decode the ip/ip6 addrs, then dump the addrs and raw packet
           to our session check routine'''
        self.__decoder.IPHandler = self.__callback  # set private decoder to our callback
        self.__decoder.decode(pktlen, pktdata, ts, raw=pktdata)

    def __callback(self, addr, pkt, ts, raw=None, **kw):
        '''check to see if this packet is to/from an IP in a session,
        if so write it. the packet will be passed in the 'raw' kwarg'''
        if addr[0][0] in self.sessions:
            ip = addr[0][0]  # source ip
        elif addr[1][0] in self.sessions:
            ip = addr[1][0]  # dest ip
        else:
            return  # not tracked
        for s in self.sessions[ip].values():
            s.sessionpackets += 1
            s.sessionbytes += len(raw)  # actual captured data len
        # dump the packet or sub-decode it
        if self.subDecoder:
            # make it look like a capture
            self.subDecoder.decode(len(raw), str(raw), ts)
        else:
            self.dump(raw, ts)

    def connectionInitHandler(self, conn):
        '''see if dest ip and/or port is in target list and (if a source list)
            source ip is in source list
            if so, put the connection in the tracked-session list by dest ip
            if a new connection to the target comes in from an allowed source,
            the existing connection will still be tracked'''
        ((sip, sport), (dip, dport)) = conn.addr
        sport, dport = str(sport), str(dport)
        if ((dip, dport) in self.targets) or ((dip, None) in self.targets) or ((None, dport) in self.targets):
            if not self.sources or (sip in self.sources):
                s = self.sessions.setdefault(dip, {})
                s[conn.addr] = conn
                if self.alerts:
                    self.alert('session started', **conn.info())
                conn.info(sessionpackets=0, sessionbytes=0)

    def connectionHandler(self, conn):
        '''if a connection to a tracked-session host, alert and write if no subdecoder'''
        if self.alerts:
            if conn.serverip in self.sessions:
                self.alert('inbound', **conn.info())
            if conn.clientip in self.sessions:
                self.alert('outbound', **conn.info())
        if conn.serverip in self.sessions or conn.clientip in self.sessions:
            if not self.subDecoder:
                self.write(conn)

    def connectionCloseHandler(self, conn):
        '''close the tracked session if the initiating connection is closing
            make sure the conn in the session list matches,
            as we may have had more incoming connections to the same ip during the session'''
        if conn.serverip in self.sessions and conn.addr in self.sessions[conn.serverip]:
            if self.alerts:
                self.alert('session ended', **conn.info())
            del self.sessions[conn.serverip][conn.addr]
            if not self.sessions[conn.serverip]:
                del self.sessions[conn.serverip]

dObj = DshellDecoder()
