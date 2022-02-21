'''
Displays netflows that have at least 1MB transferred, by default.
Megabyte threshold can be updated by the user.
'''

import dshell.core
from dshell.output.netflowout import NetflowOutput

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name='large-flows',
            description='Display netflows that have at least 1MB transferred',
            author='bg',
            output=NetflowOutput(label=__name__),
            optiondict={
                'size': {
                    'type': float,
                    'default': 1,
                    'metavar': 'SIZE',
                    'help': 'number of megabytes transferred (default: 1)'}
            }
        )

    def premodule(self):
        if self.size <= 0:
            self.logger.warning(f'Cannot have a size that\'s less than or equal to zero (size: {self.size}). Setting to 1.')
            self.size = 1
        self.min = 1048576 * self.size
        self.logger.debug(f'Input: {self.size}, Final size: {self.min} bytes')

    def connection_handler(self, conn):
        if conn.clientbytes + conn.serverbytes >= self.min:
            self.write(**conn.info())
            return conn


