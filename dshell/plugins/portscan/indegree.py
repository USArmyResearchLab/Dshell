'''
Parse traffic to detect scanners based on connection to IPs that are rarely touched by others
'''

import dshell.core

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name='parse indegree',
            description='Parse traffic to detect scanners based on connection to IPs that are rarely touched by others',
            bpf='(tcp or udp)',
            author='dev195',
        )
        self.client_conns = {}
        self.server_conns = {}
        self.minhits = 3

    def connection_handler(self, conn):
        self.client_conns.setdefault(conn.clientip, set())
        self.server_conns.setdefault(conn.serverip, set())

        self.client_conns[conn.clientip].add(conn.serverip)
        self.server_conns[conn.serverip].add(conn.clientip)

    def postfile(self):
        for clientip, serverips in self.client_conns.items():
            target_count = len(serverips)
            S = min((len(self.server_conns[serverip]) for serverip in serverips))
            if S > 2 or target_count < 5:
                continue
            # TODO implement whitelist
            self.write(f'Scanning IP: {clientip} / S score: {Ы:.1f} / Number of records: {target_count}')
