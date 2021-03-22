"""
Generate an alert when a client transmits more data than the server.

Additionally, the user can specify a threshold. This means that an alert
will be generated if the client transmits more than three times as much data
as the server.

The default threshold value is 3.0, meaning that any client transmits
more than three times as much data as the server will generate an alert.

Examples:
1) decode -d reverse-flow <pcap>
    Generates an alert for client transmissions that are three times
    greater than the server transmission.

2) decode -d reverse-flow <pcap> --reverse-flow_threshold 61
    Generates an alert for all client transmissions that are 61 times
    greater than the server transmission

3) decode -d reverse-flow <pcap> --reverse-flow_threshold 61  --reverse-flow_zero
    Generates an alert for all client transmissions that are 61 times greater
    than the server transmission.
"""

import dshell.core
from dshell.output.alertout import AlertOutput

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name="reverse-flows",
            description="Generate an alert if the client transmits more data than the server",
            author="me",
            bpf="tcp or udp",
            output=AlertOutput(label=__name__),
            optiondict={
               'threshold': {'type':float, 'default':3.0,
                             'help':'Alerts if client transmits more than threshold times the data of the server'},
               'minimum': {'type':int, 'default':0,
                           'help':'alert on client transmissions larger than min bytes [default: 0]'},
               'zero': {'action':'store_true', 'default':False,
                        'help':'alert if the server transmits zero bytes [default: false]'},
            },
            longdescription="""
Generate an alert when a client transmits more data than the server.

Additionally, the user can specify a threshold. This means that an alert
will be generated if the client transmits more than three times as much data
as the server.

The default threshold value is 3.0, meaning that any client transmits
more than three times as much data as the server will generate an alert.

Examples:
1) decode -d reverse-flow <pcap>
    Generates an alert for client transmissions that are three times
    greater than the server transmission.

2) decode -d reverse-flow <pcap> --reverse-flow_threshold 61
    Generates an alert for all client transmissions that are 61 times
    greater than the server transmission

3) decode -d reverse-flow <pcap> --reverse-flow_threshold 61  --reverse-flow_zero
    Generates an alert for all client transmissions that are 61 times greater
    than the server transmission.
            """,
        )

    def premodule(self):
        if self.threshold < 0:
            self.logger.warning("Cannot have a negative threshold. Defaulting to 3.0. (threshold: {0})".format(self.threshold))
            self.threshold = 3.0
        elif not self.threshold:
            self.logger.warning("Threshold not set. Displaying all client-server transmissions (threshold: {0})".format(self.threshold))

    def connection_handler(self, conn):
        if conn.clientbytes < self.minimum:
            return

        if self.zero or (conn.serverbytes and float(conn.clientbytes)/conn.serverbytes > self.threshold):
            self.write('client sent {:>6.2f} more than the server'.format(conn.clientbytes/float(conn.serverbytes)), **conn.info(), dir_arrow="->")
            return conn

