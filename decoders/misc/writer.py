'''
Created on Jan 13, 2012

@author: tparker
'''

import dshell
import dpkt
from output import PCAPWriter


class DshellDecoder(dshell.Decoder):

    '''
    session writer - chain to a decoder to end the chain if the decoder does not output session or packets on its own
    if chained to a packet-based decoder, writes all packets to pcap file, can be used to convert or concatenate files
    if chained to a connection-based decoder, writes selected streams to session file
    '''

    def __init__(self, **kwargs):
        '''
        Constructor
        '''
        self.file = None
        dshell.Decoder.__init__(self,
            name='writer',
            description='pcap/session writer',
            author='twp',
            raw=True,
            optiondict=dict(
                filename=dict(
                    default='%(clientip)s:%(clientport)s-%(serverip)s:%(serverport)s-%(direction)s.txt'
                ),
            )
        )

    def rawHandler(self, pktlen, pkt, ts, **kwargs):
        self.decodedbytes += pktlen
        self.count += 1
        self.dump(pktlen, pkt, ts)  # pktlen may be wrong if we stripped vlan

    def IPHandler(self, addr, ip, ts, pkttype=None, **kw):
        self.decodedbytes += len(ip.data)
        self.count += 1
        # if we are passed in IP data vs layer-2 frames, we need to encapsulate
        # them
        self.dump(dpkt.ethernet.Ethernet(data=str(ip), pkttype=type), ts=ts)

    def connectionHandler(self, conn):
        self.write(conn)

dObj = DshellDecoder()
