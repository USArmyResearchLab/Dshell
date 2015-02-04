import dshell
import util
import dpkt
import traceback


class DshellDecoder(dshell.IP6Decoder):

    _PROTO_MAP = {dpkt.ip.IP_PROTO_TCP: 'TCP', 17: 'UDP'}

    def __init__(self):
        dshell.IP6Decoder.__init__(self,
                                   name='ip',
                                   description='IPv4/IPv6 decoder',
                                   filter='ip or ip6',
                                   author='twp',
                                   )

    def packetHandler(self, ip=None, proto=None):
        if self.verbose:
            self.out.log(util.hexPlusAscii(ip.pkt))
        self.alert(**ip.info())
        if self.out.sessionwriter:
            self.write(ip)

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
