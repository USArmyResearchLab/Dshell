"""
This output module is used to display single-line alerts

It inherits nearly everything from the base Output class, and only resets the
_DEFAULT_FORMAT to a more expressive format.
"""

from dshell.output.output import Output

class AlertOutput(Output):
    "A class that provides a default format for printing a single-line alert"
    _DESCRIPTION = "Default format for printing a single-line alert"
    _DEFAULT_FORMAT = "[%(plugin)s] %(ts)s %(sip)16s:%(sport)-5s %(dir_arrow)s %(dip)16s:%(dport)-5s ** %(data)s **\n"

obj = AlertOutput
