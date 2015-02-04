import dshell
import dpkt


class DshellDecoder(dshell.Decoder):

    """
    merge.py - merge all pcap in to a single file

    Example: decode -d merge *.pcap -W merged.pcap
    """

    def __init__(self):
        dshell.Decoder.__init__(self,
                                name='merge',
                                description='dump all packets to single file',
                                longdescription="""Example: decode -d merge *.pcap -W merged.pcap""",
                                author='bg/twp'
                                )
        self.chainable = True

    def rawHandler(self, pktlen, pkt, ts, **kw):
        if self.subDecoder:
            return self.subDecoder.rawHandler(pktlen, str(pkt), ts, **kw)
        else:
            return self.dump(pktlen, pkt, ts)


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
