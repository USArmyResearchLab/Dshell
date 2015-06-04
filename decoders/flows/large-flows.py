import dshell
import netflowout


class DshellDecoder(dshell.TCPDecoder):

    def __init__(self):
        dshell.TCPDecoder.__init__(self,
                                   name='large-flows',
                                   description='display netflows that have at least 1MB transferred',
                                   filter='tcp',
                                   author='bg',
                                   optiondict={'size': {
                                       'type': 'float', 'default': 1, 'help': 'number of megabytes transferred'}}
                                   )
        self.out = netflowout.NetflowOutput()
        self.min = 1048576      # 1MB

    def preModule(self):
        if self.size <= 0:
            self.warn(
                "Cannot have a size that's less than or equal to zero. (size: %s)" % (self.size))
            self.size = 1
        self.min = 1048576 * self.size
        self.debug("Input: %s,  Final size: %s bytes" % (self.size, self.min))

    def connectionHandler(self, conn):
        if (conn.clientbytes + conn.serverbytes) >= self.min:
            self.alert(**conn.info())


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
