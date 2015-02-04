import dshell
import netflowout


class DshellDecoder(dshell.TCPDecoder):

    def __init__(self):
        self.len = 5
        dshell.TCPDecoder.__init__(self,
                                   name='long-flows',
                                   description='display netflows that have a duration of at least 5mins',
                                   filter='(tcp or udp)',
                                   author='bg',
                                   optiondict={
                                       'len': {'type': 'int', 'default': 5, 'help': 'set minimum connection time to alert on, in minutes [default: 5 mins]'},
                                   }
                                   )
        self.out = netflowout.NetflowOutput()

    def connectionHandler(self, conn):
        if (conn.endtime - conn.starttime) >= (60 * self.len):
            self.alert(**conn.info())


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
