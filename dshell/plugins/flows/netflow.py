"""
Collects and displays statistics about connections (a.k.a. flow data)
"""

import dshell.core
from dshell.output.netflowout import NetflowOutput

class DshellPlugin(dshell.core.ConnectionPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(
            name="Netflow",
            description="Collects and displays flow statistics about connections",
            author="dev195",
            bpf="ip or ip6",
            output=NetflowOutput(label=__name__),
            longdescription="""
Collect and display flow statistics about connections.

It will reassemble connections and print one row for each flow keyed by
address four-tuple. Each row, by default, will have the following fields:

- Start Time : the timestamp of the first packet for a connection
- Client IP  : the IP address of the host that initiated the connection
- Server IP  : the IP address of the host that receives the connection
  (note: client/server designation is based on first packet seen for a connection)
- Client Country : the country code for the client IP address
- Server Country : the country code for the server IP address
- Protocol   : the layer-3 protocol of the connection
- Client Port: port number used by client
- Server Port: port number used by server
- Client Packets : number of data-carrying packets from the client
- Server Packets : number of data-carrying packets from the server
  (note: packet counts ignore packets without data, e.g. handshakes, ACKs, etc.)
- Client Bytes   : total bytes sent by the client
- Server Bytes   : total bytes sent by the server
- Duration   : time between the first packet and final packet of a connection
- Message Data: extra field not used by this plugin
"""
        )

    def connection_handler(self, conn):
        self.write(**conn.info())
        return conn
