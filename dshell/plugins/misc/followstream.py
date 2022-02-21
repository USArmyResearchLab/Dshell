'''
Generates color-coded Screen/HTML output similar to Wireshark Follow Stream
'''

import dshell.core
from dshell.output.colorout import ColorOutput

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name='Followstream',
            author='amm/dev195',
            description='Generates color-coded Screen/HTML output similar to Wireshark Follow Stream. Empty connections will be skipped.',
            bpf='tcp',
            output=ColorOutput(label=__name__),
        )

    def connection_handler(self, conn):
        if (conn.clientbytes + conn.serverbytes > 0):
            self.write(conn, **conn.info())
            return conn

if __name__ == '__main__':
    print(DshellPlugin())
