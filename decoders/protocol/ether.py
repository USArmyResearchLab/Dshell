import dshell
import util
import dpkt
import datetime
import binascii


class DshellDecoder(dshell.Decoder):

    def __init__(self):
        dshell.Decoder.__init__(self,
                                name='ether',
                                description='raw ethernet capture decoder',
                                filter='',
                                author='twp', asdatetime=True
                                )

    def rawHandler(self, dlen, data, ts, **kw):
        if self.verbose:
            self.log("%.06f %d\n%s" % (ts, dlen, util.hexPlusAscii(str(data))))
        eth = dpkt.ethernet.Ethernet(str(data))
        src = binascii.hexlify(eth.src)
        dst = binascii.hexlify(eth.dst)
        self.alert('%6x->%6x %4x len %d' % (long(src, 16), long(dst, 16), eth.type,
                                            len(eth.data)), type=eth.type, bytes=len(eth.data), src=src, dst=dst, ts=ts)

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
