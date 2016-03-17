'''
@author: tparker
'''

import output
import util


class CSVOutput(output.TextOutput):

    '''
    CSV Output module
    use with --output=csvout,[,data,customfield[:type],...] (a list of field:types to append to end of default format)
    add [,file=...[,mode=...]] to write to outfile (or use -w arg on cmdline)
    add format=... to replace the default fields or use a format string
    add delim= to change delimeter from comma
    '''

    _NULL = ''

    _DEFAULT_DELIM = ','

    _DEFAULT_FIELDS = [('decoder', 's'), ('datetime', 's'),
                       ('sip', 's'), ('sport', 's'), ('dip', 's'), ('dport', 's')]

    def __init__(self, *args, **kwargs):
        '''
        sets up an output module, be sure to call Output.__init__ first or last
        args will have the name of the module as args[0], anything else after
        '''
        # start with a set of default fields
        self.fields = self._DEFAULT_FIELDS

        if 'format' in kwargs:
            self.fields = []
            fmtstr = kwargs['format']
            del kwargs['format']  # don't let base class process this
        else:
            fmtstr = ''

        # set delimiter
        if 'delim' in kwargs:
            self.delim = kwargs['delim']
            if self.delim.lower() == 'tab':
                self.delim = "\t"
        else:
            self.delim = self._DEFAULT_DELIM

        self.noheader = 'noheader' in kwargs

        # parse args as fields
        if len(args):
            for a in args:
                try:
                    f, t = a.split(':')  # split on field:type
                except:
                    f, t = a, 's'  # default to string type
                self.fields.append((f, t))

        # build format string to pass to textoutput
        if fmtstr:
            fmtstr += self.delim
        fmtstr += self.delim.join(['%%(%s)%s' % (f, t) for f, t in self.fields])

        # everything else is exactly like the text output module
        output.TextOutput.__init__(self, format=fmtstr, **kwargs)


    def setup(self):
        # print header if not suppressed
        if self.fh and not self.noheader:
            self.fh.write('#' + self.delim.join([f[0] for f in self.fields]) + "\n")

'''NOTE: output modules return obj=reference to the CLASS
    instead of a dObj=instance so we can init with args'''
obj = CSVOutput
