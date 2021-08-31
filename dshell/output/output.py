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
import warnings


logger = logging.getLogger(__name__)


class Output:
    """
    Base-level output class

    Arguments:
        format : 'format string' to override default formatstring for output class
        timeformat : 'format string' for datetime representation
        delimiter : set a delimiter for CSV or similar output
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

    def __init__(
            self, file=None, fh=None, mode='w', format=None, timeformat=None, delimiter=None, nobuffer=False,
            noclobber=False, extra=None, **unused_kwargs
    ):
        self.format_fields = []
        self.timeformat = timeformat or self._DEFAULT_TIME_FORMAT
        self.delimiter = delimiter or self._DEFAULT_DELIM
        self.nobuffer = nobuffer
        self.noclobber = noclobber
        self.extra = extra
        self.mode = mode

        # Must define attributes even if they are setup in different function.
        self.format_fields = None
        self.format = None
        self.set_format(format or self._DEFAULT_FORMAT)

        # Set the filehandle for any output
        if fh:
            self.fh = fh
            return

        f = file
        if f:
            if self.noclobber:
                f = self._increment_filename(f)
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
                filename = self._increment_filename(filename)
            if mode:
                self.mode = mode
                self.fh = open(filename, mode)
            else:
                self.fh = open(filename, self.mode)

    def set_oargs(self, format=None, noclobber=None, delimiter=None, timeformat=None, hex=None, **unused_kwargs):
        """
        Process the standard oargs from the command line.
        """
        if delimiter:
            self.delimiter = delimiter
        if timeformat:
            self.timeformat = timeformat
        if noclobber:
            self.noclobber = noclobber
        if hex:
            self.hexmode = hex
        if format:
            self.set_format(format)

    def set_format(self, fmt):
        """Set the output format to a new format string"""
        # Use a regular expression to identify all fields that the format will
        # populate, based on limited printf-style formatting.
        # https://docs.python.org/3/library/stdtypes.html#old-string-formatting
        regexmatch = "%\((?P<field>.*?)\)[diouxXeEfFgGcrs]"
        self.format_fields = re.findall(regexmatch, fmt)
        self.format = fmt

    def _increment_filename(self, filename):
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
        """
        Close output file, assuming it's not stdout
        """
        if self.fh not in (sys.stdout, sys.stdout.buffer):
            self.fh.close()

    # NOTE: Output modules no longer handles logging. Logging should be done by creating a logger
    # at the top of each of the modules.
    # If we want to change the destination of the log messages we can create a log handler.
    def log(self, msg, level=logging.INFO, *args, **kwargs):
        """
        Write a message to the log
        Passes all args and kwargs thru to logging, except for 'level'
        """
        warnings.warn("Please create and use a logger using the logging module instead", DeprecationWarning)
        logger.log(level, msg, *args, **kwargs)

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
            except TypeError:
                pass
            except KeyError:
                pass
            except ValueError:
                pass

        if "starttime" in outdict and isinstance(outdict["starttime"], datetime):
            outdict['starttime'] = outdict['starttime'].strftime(self.timeformat)
        if "endtime" in outdict and isinstance(outdict["endtime"], datetime):
            outdict['endtime'] = outdict['endtime'].strftime(self.timeformat)
        if 'dt' in outdict and isinstance(outdict["dt"], datetime):
            outdict['dt'] = outdict['dt'].strftime(self.timeformat)

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
        outdict['data'] = self.delimiter.join(map(str, args))

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
        """
        Primary output function. Should be overwritten by subclasses.
        """
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
        warnings.warn("Use the write function of the AlertOutput class", DeprecationWarning)
        self.write(*args, **kwargs)

    def dump(self, *args, **kwargs):
        """
        DEPRECATED
        Use the write function of the PCAPOutput class
        """
        warnings.warn("Use the write function of the PCAPOutput class", DeprecationWarning)
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
