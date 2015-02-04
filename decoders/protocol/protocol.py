import dshell
import dpkt

# Build a list of known IP protocols from dpkt
try:
    PROTOCOL_MAP = dict((v, k[9:]) for k, v in dpkt.ip.__dict__.iteritems() if type(
        v) == int and k.startswith('IP_PROTO_') and k != 'IP_PROTO_HOPOPTS')
except:
    PROTOCOL_MAP = {}


class DshellDecoder(dshell.IPDecoder):

    """
    protocol.py

    Identifies non-standard protocols (not tcp, udp or icmp)

    References:
            http://www.networksorcery.com/enp/protocol/ip.htm
    """

    def __init__(self):
        dshell.IPDecoder.__init__(self,
                                  name='protocol',
                                  description='Identifies non-standard protocols (not tcp, udp or icmp)',
                                  filter='(ip and not tcp and not udp and not icmp)',
                                  author='bg',
                                  )

    def packetHandler(self, ip):
        p = PROTOCOL_MAP.get(ip.proto, ip.proto)
        self.alert('PROTOCOL: %s (%d)' %
                   (p, ip.proto), sip=ip.sip, dip=ip.dip, ts=ip.ts)

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
