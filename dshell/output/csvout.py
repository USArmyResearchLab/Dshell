"""
This output module converts plugin output into a CSV format
"""

import csv
from collections import defaultdict
from datetime import datetime
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

    def convert(self, *args, **kwargs):
        """
        Build the CSV row as a list of field values.

        Values are taken from the plugin's kwargs (with the same timestamp
        normalization and None->'' handling the base class applies) so that
        csv.writer can quote them correctly. The previous implementation used
        Python's repr() (%%(field)r), which single-quotes values and therefore
        does NOT escape the delimiter -- a value containing the delimiter split
        the row (CSV field injection) and a leading '=' survived into
        spreadsheets (formula injection).
        """
        outdict = defaultdict(str, **kwargs)

        if 'ts' in outdict:
            try:
                outdict['ts'] = datetime.fromtimestamp(float(outdict['ts'])).strftime(self.timeformat)
            except (TypeError, KeyError, ValueError):
                pass
        for key in ('starttime', 'endtime', 'dt'):
            if key in outdict and isinstance(outdict[key], datetime):
                outdict[key] = outdict[key].strftime(self.timeformat)

        for key, val in list(outdict.items()):
            if val is None:
                outdict[key] = ''

        outdict['data'] = self.delimiter.join(map(str, args))

        columns = [f for f in self.fields if f]
        if self.extra:
            extras = ["%s=%s" % (k, outdict[k]) for k in sorted(outdict) if k not in self.format_fields]
            outdict['extra'] = ', '.join(extras)
            columns.append('extra')

        return [self._csv_safe(outdict.get(f, '')) for f in columns]

    @staticmethod
    def _csv_safe(value):
        """
        Neutralize CSV formula injection: prefix a single quote to string
        values that begin with a formula-triggering character (=, +, -, @,
        tab, CR). csv.writer handles delimiter/quote escaping, but it does not
        neutralize values that spreadsheets evaluate as formulas, so the two
        protections are complementary.
        """
        v = value if isinstance(value, str) else str(value)
        if v[:1] in ('=', '+', '-', '@', '\t', '\r'):
            v = "'" + v
        return v

    def write(self, *args, **kwargs):
        """Write one row using the csv module for RFC-4180 quoting."""
        row = self.convert(*args, **kwargs)
        try:
            writer = csv.writer(self.fh, delimiter=self.delimiter, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(row)
            if self.nobuffer:
                self.fh.flush()
        except BrokenPipeError:
            pass


obj = CSVOutput
