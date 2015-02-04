import dshell
import dpkt


class DshellDecoder(dshell.IPDecoder):

    """
    Simple TCP syn/rst filter (ipv4) only
    """

    def __init__(self):
        dshell.IPDecoder.__init__(self,
                                  name='synrst',
                                  description='detect failed attempts to connect (SYN followed by a RST/ACK)',
                                  filter="tcp[13]=2 or tcp[13]=20",
                                  author='bg'
                                  )
        self.tracker = {}       # key = (srcip,srcport,seqnum,dstip,dstport)

    def packetHandler(self, ip=None):
        tcp = dpkt.ip.IP(ip.pkt).data

        if tcp.flags & 2:  # check for SYN flag
            seqnum = tcp.seq
            key = '%s:%s:%d:%s:%s' % (
                ip.sip, ip.sport, seqnum, ip.dip, ip.dport)
            self.tracker[key] = ''
        elif tcp.flags & 20:  # check for RST/ACK flags
            acknum = tcp.ack - 1
            tmpkey = '%s:%s:%d:%s:%s' % (
                ip.dip, ip.dport, acknum, ip.sip, ip.sport)
            if self.tracker.__contains__(tmpkey):
                self.alert('Failed connection', **ip.info())
                del self.tracker[tmpkey]


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
