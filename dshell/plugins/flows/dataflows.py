'''
Displays netflows that have at least 1 byte transferred, by default.
Bytes threshold can be updated by the user.
'''

import dshell.core
from dshell.output.netflowout import NetflowOutput

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name='dataflows',
            description='Display netflows that have at least 1 byte transferred',
            author='amm',
            output=NetflowOutput(label=__name__),
            optiondict={
                'size': {
                    'type': int,
                    'default': 1,
                    'metavar': 'SIZE',
                    'help': 'number of bytes transferred (default: 1)'}
            }
        )

    def premodule(self):
        if self.size <= 0:
            self.warn('Cannot have a size that\'s less than or equal to zero (size: {self.size}). Setting to 1.')
            self.size = 1

    def connection_handler(self, conn):
        if conn.clientbytes + conn.serverbytes >= self.size:
            self.write(**conn.info())
            return conn


