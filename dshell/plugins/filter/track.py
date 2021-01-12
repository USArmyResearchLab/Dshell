"""
Only follows connections that match user-provided IP addresses and ports. Is
generally chained with other plugins.
"""

import ipaddress
import sys

import dshell.core
from dshell.output.alertout import AlertOutput

class DshellPlugin(dshell.core.ConnectionPlugin):
    def __init__(self, **kwargs):
        super().__init__(
            name="track",
            author="twp,dev195",
            description="Only follow connections that match user-provided IP addresses and ports",
            longdescription="""Only follow connections that match user-provided IP addresses

IP addresses can be specified with --track_source and --track_target.
Multiple IPs can be used with commas (e.g. --track_source=192.168.1.1,127.0.0.1).
Ports can be included with IP addresses by joining them with a 'p' (e.g. --track_target=192.168.1.1p80,127.0.0.1).
Ports can be used alone with just a 'p' (e.g. --track_target=p53).
CIDR notation is okay (e.g. --track_source=196.168.0.0/16).

--track_source : used to limit connections by the IP that initiated the connection (usually the client)
--trace_target : used to limit connections by the IP that received the connection (usually the server)
--track_alerts : used to display optional alerts indicating when a connection starts/ends""",
            bpf="ip or ip6",
            output=AlertOutput(label=__name__),
            optiondict={
                "target": {
                    "default": [],
                    "action": "append",
                    "metavar": "IPpPORT"},
                "source": {
                    "default": [],
                    "action": "append",
                    "metavar": "IPpPORT"},
                "alerts": {
                    "action": "store_true"}
                }
            )
        self.sources = []
        self.targets = []

    def __split_ips(self, input):
        """
        Used to split --track_target and --track_source arguments into
        list-of-lists used in the connection handler
        """
        return_val = []
        for piece in input.split(','):
            if 'p' in piece:
                ip, port = piece.split('p', 1)
                try:
                    port = int(port)
                except ValueError as e:
                    self.error("Could not parse port number in {!r} - {!s}".format(piece, e))
                    sys.exit(1)
                if 0 < port > 65535:
                    self.error("Could not parse port number in {!r} - must be in valid port range".format(piece))
                    sys.exit(1)
            else:
                ip, port = piece, None
            if '/' in ip:
                try:
                    ip = ipaddress.ip_network(ip)
                except ValueError as e:
                    self.error("Could not parse CIDR netrange - {!s}".format(e))
                    sys.exit(1)
            elif ip:
                try:
                    ip = ipaddress.ip_address(ip)
                except ValueError as e:
                    self.error("Could not parse IP address - {!s}".format(e))
                    sys.exit(1)
            else:
                ip = None
            return_val.append((ip, port))
        return return_val

    def __check_ips(self, masterip, masterport, checkip, checkport):
        "Checks IPs and ports for matches against the user-selected values"
        # masterip, masterport are the values selected by the user
        # checkip, checkport are the values to be checked against masters
        ip_okay = False
        port_okay = False

        if masterip is None:
            ip_okay = True
        elif (isinstance(masterip, (ipaddress.IPv4Network, ipaddress.IPv6Network))
            and checkip in masterip):
                ip_okay = True
        elif (isinstance(masterip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            and masterip == checkip):
                ip_okay = True

        if masterport is None:
            port_okay = True
        elif masterport == checkport:
            port_okay = True

        if port_okay and ip_okay:
            return True
        else:
            return False


    def premodule(self):
        if self.target:
            for tstr in self.target:
                self.targets.extend(self.__split_ips(tstr))
        if self.source:
            for sstr in self.source:
                self.sources.extend(self.__split_ips(sstr))
        self.logger.debug("targets: {!s}".format(self.targets))
        self.logger.debug("sources: {!s}".format(self.sources))

    def connection_handler(self, conn):
        if self.targets:
            conn_okay = False
            for target in self.targets:
                targetip = target[0]
                targetport = target[1]
                serverip = ipaddress.ip_address(conn.serverip)
                serverport = conn.serverport
                if self.__check_ips(targetip, targetport, serverip, serverport):
                    conn_okay = True
                    break
            if not conn_okay:
                return

        if self.sources:
            conn_okay = False
            for source in self.sources:
                sourceip = source[0]
                sourceport = source[1]
                clientip = ipaddress.ip_address(conn.clientip)
                clientport = conn.clientport
                if self.__check_ips(sourceip, sourceport, clientip, clientport):
                    conn_okay = True
                    break
            if not conn_okay:
                return

        if self.alerts:
            self.write("matching connection", **conn.info())

        return conn

if __name__ == "__main__":
    print(DshellPlugin())
