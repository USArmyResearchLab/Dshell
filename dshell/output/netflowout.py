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
    """

    _DESCRIPTION = "Flow (connection overview) format output"
    # Define two types of formats:
    # Those for plugins handling individual packets (not really helpful)
    _PACKET_FORMAT = "%(ts)s  %(sip)16s -> %(dip)16s  (%(sipcc)s -> %(dipcc)s) %(protocol)5s  %(sport)6s  %(dport)6s %(bytes)7s %(data)s\n"
    _PACKET6_FORMAT = "%(ts)s  %(sip)40s -> %(dip)40s  (%(sipcc)s -> %(dipcc)s) %(protocol)5s  %(sport)6s  %(dport)6s %(bytes)7s %(data)s\n"
    # And those plugins handling full connections (more useful and common)
    _CONNECTION_FORMAT = "%(starttime)s  %(clientip)16s -> %(serverip)16s  (%(clientcc)s -> %(servercc)s) %(protocol)5s  %(clientport)6s  %(serverport)6s %(clientpackets)5s  %(serverpackets)5s  %(clientbytes)7s  %(serverbytes)7s  %(duration)-.4fs %(data)s\n"
    _CONNECTION6_FORMAT = "%(starttime)s  %(clientip)40s -> %(serverip)40s  (%(clientcc)s -> %(servercc)s) %(protocol)5s  %(clientport)6s  %(serverport)6s %(clientpackets)5s  %(serverpackets)5s  %(clientbytes)7s  %(serverbytes)7s  %(duration)-.4fs %(data)s\n"
    # TODO decide if IPv6 formats are necessary, and how to switch between them
    #      and IPv4 formats
    # Default to packets since those fields are in both types of object
    _DEFAULT_FORMAT = _PACKET_FORMAT

    def __init__(self, *args, **kwargs):
        # Are we grouping the results, and by what fields?
        if 'group' in kwargs:
            self.group = True
            self.group_fields = kwargs['group'].split('/')
        else:
            self.group = False
        self.group_cache = {}  # results will be stored here, if grouping
        self.format_is_set = False
        Output.__init__(self, *args, **kwargs)

    def write(self, *args, **kwargs):
        # Change output format depending on if we're handling a connection or
        # a single packet
        if not self.format_is_set:
            if "clientip" in kwargs:
                self.set_format(self._CONNECTION_FORMAT)
            else:
                self.set_format(self._PACKET_FORMAT)
            self.format_is_set = True

        if self.group:
            # If grouping, check if the IP tuple is in the cache already.
            # If not, check the reverse of the tuple (i.e. opposite direction)
            try:
                key = tuple([kwargs[g] for g in self.group_fields])
            except KeyError as e:
                self.logger.error("Could not group by key %s" % str(e))
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
            for key in sorted(self.group_cache.keys()):
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
