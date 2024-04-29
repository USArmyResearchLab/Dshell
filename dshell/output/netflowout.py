"""
This output module is used for generating flow-format output
"""

from dshell.output.output import Output
from datetime import datetime

class NetflowOutput(Output):
    """
    A class for printing connection information for pcap

    Output can be grouped by setting the group flag to a field or fields
    separated by a forward-slash
    For example:
      --output=netflowout --oarg="group=clientip/serverip"
    Note: Output when grouping is only generated at the end of analysis

    A header row can be printed before output using --oarg header
    """

    _DESCRIPTION = "Flow (connection overview) format output"
    # Define two types of formats:
    # Those for plugins handling individual packets (not really helpful)
    _PACKET_FORMAT = "%(ts)s  %(sip)16s -> %(dip)16s  (%(sipcc)s -> %(dipcc)s) %(protocol)5s  %(sport)6s  %(dport)6s %(bytes)7s %(data)s\n"
    _PACKET6_FORMAT = "%(ts)s  %(sip)40s -> %(dip)40s  (%(sipcc)s -> %(dipcc)s) %(protocol)5s  %(sport)6s  %(dport)6s %(bytes)7s %(data)s\n"
    _PACKET_PRETTY_HEADER = "[start timestamp] [source IP] -> [destination IP] ([source country] -> [destination country]) [protocol] [source port] [destination port] [bytes] [message data]\n"
    # And those plugins handling full connections (more useful and common)
    _CONNECTION_FORMAT = "%(starttime)s  %(clientip)16s -> %(serverip)16s  (%(clientcc)s -> %(servercc)s) %(protocol)5s  %(clientport)6s  %(serverport)6s %(clientpackets)5s  %(serverpackets)5s  %(clientbytes)7s  %(serverbytes)7s  %(duration)-.4fs %(data)s\n"
    _CONNECTION6_FORMAT = "%(starttime)s  %(clientip)40s -> %(serverip)40s  (%(clientcc)s -> %(servercc)s) %(protocol)5s  %(clientport)6s  %(serverport)6s %(clientpackets)5s  %(serverpackets)5s  %(clientbytes)7s  %(serverbytes)7s  %(duration)-.4fs %(data)s\n"
    _CONNECTION_PRETTY_HEADER = "[start timestamp] [client IP] -> [server IP] ([client country] -> [server country]) [protocol] [client port] [server port] [client packets] [server packets] [client bytes] [server bytes] [duration] [message data]\n"
    # TODO decide if IPv6 formats are necessary, and how to switch between them
    #      and IPv4 formats
    # Default to packets since those fields are in both types of object
    _DEFAULT_FORMAT = _PACKET_FORMAT

    def __init__(self, *args, **kwargs):
        self.group = False
        self.group_cache = {}  # results will be stored here, if grouping
        self.format_is_set = False
        self.use_header = False
        Output.__init__(self, *args, **kwargs)

    def set_format(self, fmt, pretty_header=_PACKET_PRETTY_HEADER):
        if self.use_header:
            self.fh.write(str(pretty_header))
        return super().set_format(fmt)

    def set_oargs(self, **kwargs):
        # Are we printing the format string as a file header?
        self.use_header = kwargs.pop("header", False)
        # Are we grouping the results, and by what fields?
        if 'group' in kwargs:
            self.group = True
            groupfields = kwargs.pop('group', '')
            self.group_fields = groupfields.split('/')
        else:
            self.group = False
        super().set_oargs(**kwargs)

    def write(self, *args, **kwargs):
        # Change output format depending on if we're handling a connection or
        # a single packet
        if not self.format_is_set:
            if "clientip" in kwargs:
                self.set_format(self._CONNECTION_FORMAT, self._CONNECTION_PRETTY_HEADER)
            else:
                self.set_format(self._PACKET_FORMAT, self._PACKET_PRETTY_HEADER)
            self.format_is_set = True

        if self.group:
            # If grouping, check if the IP tuple is in the cache already.
            # If not, check the reverse of the tuple (i.e. opposite direction)
            try:
                key = tuple([kwargs[g] for g in self.group_fields])
            except KeyError as e:
                Output.write(self, *args, **kwargs)
                return
            if key not in self.group_cache:
                rkey = key[::-1]
                if rkey in self.group_cache:
                    key = rkey
                else:
                    self.group_cache[key] = []
            self.group_cache[key].append(kwargs)
        else:
            # If not grouping, just write out the connection immediately
            Output.write(self, *args, **kwargs)

    def close(self):
        if self.group:
            self.group = False # we're done grouping, so turn it off
            for key in self.group_cache.keys():
                # write header by mapping key index with user's group list
                self.fh.write(' '.join([
                    '%s=%s' % (self.group_fields[i], key[i]) for i in range(len(self.group_fields))])
                    + "\n")
                for kw in self.group_cache[key]:
                    self.fh.write("\t")
                    Output.write(self, **kw)
                self.fh.write("\n")
        Output.close(self)

obj = NetflowOutput