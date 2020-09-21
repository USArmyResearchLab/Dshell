"""
Generic Dshell output class(es)

Contains the base-level Output class that other modules inherit from.
"""

import logging
import os
import re
import sys
from collections import defaultdict
from datetime import datetime

class Output():
    """
    Base-level output class

    Arguments:
        label : name to use for logging.getLogger(label)
        format : 'format string' to override default formatstring for output class
        timeformat : 'format string' for datetime representation
        delim : set a delimiter for CSV or similar output
        nobuffer : true/false to run flush() after every relevant write
        noclobber : set to true to avoid overwriting existing files
        fh : existing open file handle
        file : filename to write to, assuming fh is not defined
        mode : mode to open file, assuming fh is not defined (default 'w')
    """
    _DEFAULT_FORMAT = "%(data)s\n"
    _DEFAULT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
    _DEFAULT_DELIM = ','
    _DESCRIPTION = "Base output class"

    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger(kwargs.get("label", "dshell"))

        self.format_fields = []
        self.timeformat = kwargs.get('timeformat', self._DEFAULT_TIME_FORMAT)
        self.delim = kwargs.get('delim', self._DEFAULT_DELIM)
        self.nobuffer = kwargs.get('nobuffer', False)
        self.noclobber = kwargs.get('noclobber', False)
        self.mode = kwargs.get('mode', 'w')
        self.extra = kwargs.get('extra', False)

        self.set_format( kwargs.get('format', self._DEFAULT_FORMAT) )

        # Set the filehandle for any output
        f = None
        if 'fh' in kwargs:
            self.fh = kwargs['fh']
            return
        elif 'file' in kwargs:
            f = kwargs['file']
        elif len(args) > 0:
            f = args[0]
        if f:
            if self.noclobber:
                f = self.__incrementFilename(f)
            self.fh = open(f, self.mode)
        else:
            self.fh = sys.stdout


    def reset_fh(self, filename=None, fh=None, mode=None):
        """
        Alter the module's open file handle without changing any of the other
        settings. Must supply at least a filename or a filehandle (fh).
        reset_fh(filename=None, fh=None, mode=None)
        """
        if fh:
            self.fh = fh
        elif filename:
            if self.noclobber:
                filename = self.__incrementFilename(filename)
            if mode:
                self.mode = mode
                self.fh = open(filename, mode)
            else:
                self.fh = open(filename, self.mode)

    def set_level(self, lvl):
        "Set the logging level. Just a wrapper around logging.setLevel(lvl)."
        self.logger.setLevel(lvl)

    def set_format(self, fmt):
        "Set the output format to a new format string"
        # Use a regular expression to identify all fields that the format will
        # populate, based on limited printf-style formatting.
        # https://docs.python.org/3/library/stdtypes.html#old-string-formatting
        regexmatch = "%\((?P<field>.*?)\)[diouxXeEfFgGcrs]"
        self.format_fields = re.findall(regexmatch, fmt)

        self.format = fmt

    def __incrementFilename(self, filename):
        """
        Used with the noclobber argument.
        Creates a distinct filename by appending a sequence number.
        """
        try:
            while os.stat(filename):
                p = filename.rsplit('-', 1)
                try:
                    p, n = p[0], int(p[1])
                except ValueError:
                    n = 0
                filename = '-'.join(p + ['%04d' % (int(n) + 1)])
        except OSError:
            pass  # file not found
        return filename

    def setup(self):
        """
        Perform any additional setup outside of the standard __init__.
        For example, printing header data to the outfile.
        """
        pass

    def close(self):
        "Close output file, assuming it's not stdout"
        if self.fh not in (sys.stdout, sys.stdout.buffer):
            self.fh.close()

    def log(self, msg, level=logging.INFO, *args, **kwargs):
        """
        Write a message to the log
        Passes all args and kwargs thru to logging, except for 'level'
        """
        self.logger.log(level, msg, *args, **kwargs)

    def convert(self, *args, **kwargs):
        """
        Attempts to convert the args/kwargs into the format defined in
        self.format and self.timeformat
        """
        # Have the keyword arguments default to empty strings, in the event
        # of missing keys for string formatting
        outdict = defaultdict(str, **kwargs)
        outformat = self.format
        extras = []

        # Convert raw timestamps into a datetime object
        if 'ts' in outdict:
            try:
                outdict['ts'] = datetime.fromtimestamp(float(outdict['ts']))
                outdict['ts'] = outdict['ts'].strftime(self.timeformat)
                outdict['starttime'] = datetime.fromtimestamp(float(outdict['starttime']))
                outdict['starttime'] = outdict['starttime'].strftime(self.timeformat)
                outdict['endtime'] = datetime.fromtimestamp(float(outdict['endtime']))
                outdict['endtime'] = outdict['endtime'].strftime(self.timeformat)
            except TypeError:
                pass
            except KeyError:
                pass
            except ValueError:
                pass

        # Create directional arrows
        if 'dir_arrow' not in outdict:
            if outdict.get('direction') == 'cs':
                outdict['dir_arrow'] = '->'
            elif outdict.get('direction') == 'sc':
                outdict['dir_arrow'] = '<-'
            else:
                outdict['dir_arrow'] = '--'

        # Convert Nones into empty strings.
        # If --extra flag used, generate string representing otherwise hidden
        # fields.
        for key, val in sorted(outdict.items()):
            if val is None:
                val = ''
                outdict[key] = val
            if self.extra:
                if key not in self.format_fields:
                    extras.append("%s=%s" % (key, val))

        # Dump the args into a 'data' field
        outdict['data'] = self.delim.join(map(str, args))

        # Create an optional 'extra' field
        if self.extra:
            if 'extra' not in self.format_fields:
                outformat = outformat[:-1] + " [ %(extra)s ]\n"
            outdict['extra'] = ', '.join(extras)

        # Convert the output dictionary into a string that is dumped to the
        # output location.
        output = outformat % outdict
        return output

    def write(self, *args, **kwargs):
        "Primary output function. Should be overwritten by subclasses."
        line = self.convert(*args, **kwargs)
        try:
            self.fh.write(line)
            if self.nobuffer:
                self.fh.flush()
        except BrokenPipeError:
            pass

    def alert(self, *args, **kwargs):
        """
        DEPRECATED
        Use the write function of the AlertOutput class
        """
        self.write(*args, **kwargs)

    def dump(self, *args, **kwargs):
        """
        DEPRECATED
        Use the write function of the PCAPOutput class
        """
        self.write(*args, **kwargs)



class QueueOutputWrapper(object):
    """
    Wraps an instance of any other Output-like object to make its
    write function more thread safe.
    """

    def __init__(self, oobject, oqueue):
        self.__oobject = oobject
        self.__owrite = oobject.write
        self.queue = oqueue
        self.id = str(self.__oobject)

    def true_write(self, *args, **kwargs):
        "Calls the wrapped class's write function. Called from decode.py."
        self.__owrite(*args, **kwargs)

    def write(self, *args, **kwargs):
        """
        Adds a message to the queue indicating that this wrapper is ready to
        run its write function
        """
        self.queue.put((self.id, args, kwargs))


###############################################################################

# The "obj" variable is used in decode.py as a standard name for each output
# module's primary class. It technically imports this variable and uses it to
# construct an instance.
obj = Output
