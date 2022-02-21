'''
Finds the top-talkers in a file or on an interface based on byte count.
'''

import dshell.core
from dshell.output.alertout import AlertOutput
from dshell.util import human_readable_filesize

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self, *args, **kwargs):
        super().__init__(
            name='Top Talkers',
            description='Find top-talkers based on byte count',
            author='dev195',
            bpf='tcp or udp',
            output=AlertOutput(label=__name__),
            optiondict={
                'top_x': {
                    'type': int,
                    'default': 20,
                    'help': 'Only display the top X results (default: 20)',
                    'metavar': 'X'
                },
                'total': {
                    'action': 'store_true',
                    'help': 'Sum byte counts from both directions instead of separate entries for individual directions'
                },
                'h': {
                    'action': 'store_true',
                    'help': 'Print byte counts in human-readable format'
                }
            },
            longdescription='''
Finds top 20 connections with largest transferred byte count.

Can be configured to display an arbitrary Top X list with arguments.

Does not pass connections down plugin chain.
'''
        )

    def premodule(self):
        '''
        Initialize a list to hold the top X talkers
        Format of each entry:
            (bytes, direction, Connection object)
        '''
        self.top_talkers = [(0, '---', None)]

    def connection_handler(self, conn):
        if self.total:
            # total up the client and server bytes
            self.__process_bytes(conn.clientbytes + conn.serverbytes, '<->', conn)
        else:
            # otherwise, treat client and server bytes separately
            self.__process_bytes(conn.clientbytes, '-->', conn)
            self.__process_bytes(conn.serverbytes, '<--', conn)

    def postmodule(self):
        'Iterate over the entries in top_talkers list and print them'
        for bytecount, direction, conn in self.top_talkers:
            if conn is None:
                break
            if self.h:
                byte_display = human_readable_filesize(bytecount)
            else:
                byte_display = f'{bytecount} B'
            msg = f'client {direction} server {byte_display}'
            self.write(msg, **conn.info(), dir_arrow='->')

    def __process_bytes(self, bytecount, direction, conn):
        '''
        Check if the bytecount for a connection belongs in top_talkers
        If so, insert it into the list and pop off the lowest entry
        '''
        for i, oldbytecount in enumerate(self.top_talkers):
            if bytecount >= oldbytecount[0]:
                self.top_talkers.insert(i, (bytecount, direction, conn))
                break

        while len(self.top_talkers) > self.top_x:
            self.top_talkers.pop(-1)
