"""
Displays netflows that have a duration of at least 5 minutes.
Minute threshold can be updated by the user.
"""

import dshell.core
from dshell.output.netflowout import NetflowOutput

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name="long-flows",
            description="Display netflows that have a duration of at least 5 minutes",
            author="bg",
            output=NetflowOutput(label=__name__),
            optiondict={
                "len": {
                    "type": float,
                    "default": 5,
                    "help": "set minimum connection time to MIN minutes (default: 5)",
                    "metavar": "MIN",
                }
            }
        )

    def premodule(self):
        if self.len <= 0:
            self.logger.warning("Cannot have a time that's less than or equal to zero (size: {}). Setting to 5.".format(self.len))
            self.len = 5
        self.secs = 60 * self.len

    def connection_handler(self, conn):
        tdelta = (conn.endtime - conn.starttime).total_seconds()
        if tdelta >= self.secs:
            self.write(**conn.info())
            return conn

