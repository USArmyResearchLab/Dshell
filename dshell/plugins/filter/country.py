"""
A filter for connections by IP address country code. Will generally be chained
with other plugins.
"""

import dshell.core
from dshell.output.netflowout import NetflowOutput

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self, *args, **kwargs):
        super().__init__(
            name="Country Filter",
            bpf='ip or ip6',
            description="filter connections by IP address country code",
            longdescription="""
country: filter connections on geolocation (country code)

Mandatory option:

  --country_code: specify (2 character) country code to filter on

Default behavior:

  If either the client or server IP address matches the specified country,
  the stream will be included.

Modifier options:

  --country_neither: Include only streams where neither the client nor the
                     server IP address matches the specified country.

  --country_both:    Include only streams where both the client AND the server
                     IP addresses match the specified country.

  --country_notboth: Include streams where the specified country is NOT BOTH
                     the client and server IP.  Streams where it is one or
                     the other may be included.

  --country_alerts:  Show alerts for this plugin (default: false)


Example:

  decode -d country+pcapwriter traffic.pcap --pcapwriter_outfile=USonly.pcap --country_code US
  decode -d country+followstream traffic.pcap --country_code US --country_notboth
""",
            author="tp",
            output=NetflowOutput(label=__name__),
            optiondict={
                'code': {'type': str, 'help': 'two-char country code', 'metavar':'CC'},
                'neither': {'action': 'store_true', 'help': 'neither (client/server) is in specified country'},
                'both': {'action': 'store_true', 'help': 'both (client/server) ARE in specified country'},
                'notboth': {'action': 'store_true', 'help': 'specified country is not both client and server'},
                'alerts': {'action': 'store_true', 'default':False, 'help':'have this filter show alerts for matches'}
            },
        )

    def premodule(self):
        # Several of the args are mutually exclusive
        # Check if more than one is set, and print a warning if so
        if (self.neither + self.both + self.notboth) > 1:
            self.logger.warning("Can only use one of these args at a time: 'neither', 'both', or 'notboth'")

    def connection_handler(self, conn):
        # If no country code specified, pass all traffic through
        if not self.code:
            return conn

        if self.neither:
            if conn.clientcc != self.code and conn.servercc != self.code:
                if self.alerts: self.write('neither', **conn.info())
                return conn
            else:
                return

        elif self.both:
            if conn.clientcc == self.code and conn.servercc == self.code:
                if self.alerts: self.write('both', **conn.info())
                return conn
            else:
                return

        elif self.notboth:
            if ((conn.clientcc != self.code and conn.servercc == self.code)
                or
                (conn.clientcc == self.code and conn.servercc != self.code)):
                    if self.alerts: self.write('notboth', **conn.info())
                    return conn
            else:
                return

        else:
            if conn.clientcc == self.code or conn.servercc == self.code:
                if self.alerts: self.write('match', **conn.info())
                return conn

        # no match
        return None


if __name__ == "__main__":
    print(DshellPlugin())
