"""
Collects and displays statistics about connections (a.k.a. flow data)
"""

import dshell.core
from dshell.output.netflowout import NetflowOutput

class DshellPlugin(dshell.core.ConnectionPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(
            name="Netflow",
            description="Collects and displays statistics about connections",
            author="dev195",
            bpf="ip or ip6",
            output=NetflowOutput(label=__name__),
        )

    def connection_handler(self, conn):
        self.write(**conn.info())
        return conn
