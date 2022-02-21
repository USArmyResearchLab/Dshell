'''
This output module converts plugin output into a CSV format
'''

import csv
from dshell.output.output import Output

class CSVOutput(Output):
    '''
    Takes specified fields provided to the write function and print them in
    a CSV format.

    Delimiter can be set with --oarg delimiter=<char>

    A header row can be printed with --oarg header

    Additional fields can be included with --oarg fields=field1,field2,field3

    Note: Field names much match the variable names in the plugin
    '''

    # TODO refine plugin to do things like wrap quotes around long strings

    _DEFAULT_FIELDS = ['plugin', 'ts', 'sip', 'sport', 'dip', 'dport', 'data']
    _DEFAULT_DELIM = ','
    _DESCRIPTION = 'CSV format output'

    def __init__(self, *args, **kwargs):
        self.delimiter = kwargs.get('delimiter', self._DEFAULT_DELIM)
        if self.delimiter == 'tab':
            self.delimiter = '\t'

        self.use_header = kwargs.get('header', False)

        self.fields = list(self._DEFAULT_FIELDS)
        exfields = kwargs.get('fields', '')
        for field in exfields.split(','):
            self.fields.append(field)

        super().__init__(**kwargs)

        self.set_format()

    def set_format(self, _=None):
        'Set the format to a CSV list of fields'
        columns = []
        for f in self.fields:
            if f:
                columns.append(f)
        if self.extra:
            columns.append('extra')
        fmt = self.delimiter.join('%%(%s)r' % f for f in columns)
        fmt += '\n'
        super().set_format(fmt)

    def set_oargs(self, **kwargs):
        super().set_oargs(**kwargs)
        self.set_format()

    def setup(self):
        if self.use_header:
            self.fh.write(self.delimiter.join([f for f in self.fields]) + '\n')


obj = CSVOutput
