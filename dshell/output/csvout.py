"""
This output module converts plugin output into a CSV format
"""

import csv
from dshell.output.output import Output

class CSVOutput(Output):
    """
    Takes specified fields provided to the write function and print them in
    a CSV format.

    Delimiter can be set with --oarg delimiter=<char>

    A header row can be printed with --oarg header

    Additional fields can be included with --oarg fields=field1,field2,field3
    For example, MAC address can be included with --oarg fields=smac,dmac
    Note: Field names must match the variable names in the plugin

    Additional flow fields for connection can be included with --oarg flows
    """

    # TODO refine plugin to do things like wrap quotes around long strings

    _DEFAULT_FIELDS = ['plugin', 'ts', 'sip', 'sport', 'dip', 'dport', 'data']
    _DEFAULT_FLOW_FIELDS = ['plugin', 'starttime', 'clientip', 'serverip', 'clientcc', 'servercc', 'protocol', 'clientport', 'serverport', 'clientpackets', 'serverpackets', 'clientbytes', 'serverbytes', 'duration', 'data']
    _DEFAULT_DELIM = ','
    _DESCRIPTION = "CSV format output"

    def __init__(self, *args, **kwargs):
        self.use_header = False
        self.fields = list(self._DEFAULT_FIELDS)
        super().__init__(**kwargs)

    def set_format(self, _=None):
        "Set the format to a CSV list of fields"
        columns = []
        for f in self.fields:
            if f:
                columns.append(f)
        if self.extra:
            columns.append("extra")
        fmt = self.delimiter.join('%%(%s)r' % f for f in columns)
        fmt += "\n"
        super().set_format(fmt)

    def set_oargs(self, **kwargs):
        self.use_header = kwargs.pop("header", False)
        if kwargs.pop("flows", False):
            self.fields = list(self._DEFAULT_FLOW_FIELDS)
        if exfields := kwargs.pop("fields", None):
            for field in exfields.split(','):
                self.fields.append(field)
        super().set_oargs(**kwargs)
        self.set_format()

    def setup(self):
        if self.use_header:
            self.fh.write(self.delimiter.join([f for f in self.fields]) + "\n")


obj = CSVOutput