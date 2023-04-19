"""
Generates packet or reconstructed stream output with ANSI color codes.

Based on output module originally written by amm
"""

from dshell.output.output import Output
import dshell.core
import dshell.util

class ColorOutput(Output):
    _DESCRIPTION = "Reconstructed output with ANSI color codes"
    _PACKET_FORMAT = """Packet %(counter)s (%(proto)s)
Start: %(ts)s
%(sip)16s:%(sport)6s -> %(dip)16s:%(dport)6s (%(bytes)s bytes)

%(data)s

"""
    _CONNECTION_FORMAT = """Connection %(counter)s (%(protocol)s)
Start: %(starttime)s
End:   %(endtime)s
%(clientip)16s:%(clientport)6s -> %(serverip)16s:%(serverport)6s (%(clientbytes)s bytes)
%(serverip)16s:%(serverport)6s -> %(clientip)16s:%(clientport)6s (%(serverbytes)s bytes)

%(data)s

"""
    _DEFAULT_FORMAT = _PACKET_FORMAT
    _DEFAULT_DELIM = "\n\n"


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.counter = 1
        self.colors = {
            'cs': '31',   # client-to-server is red
            'sc': '32',   # server-to-client is green
            '--': '34',   # everything else is blue
        }
        self.hexmode = kwargs.get('hex', False)
        self.format_is_set = False

    def setup(self):
        # activate color blind friendly mode
        if self.cbf:
            self.colors['cs'] = '33'   #client-to-server is yellow
    
    def write(self, *args, **kwargs):
        if not self.format_is_set:
            if 'clientip' in kwargs:
                self.set_format(self._CONNECTION_FORMAT)
            else:
                self.set_format(self._PACKET_FORMAT)
            self.format_is_set = True

        # a template string for data output
        colorformat = "\x1b[%sm%s\x1b[0m"

        # Iterate over the args and try to parse out any raw data strings
        rawdata = []
        for arg in args:
            if type(arg) == dshell.core.Blob:
                if arg.data:
                    rawdata.append((arg.data, arg.direction))
            elif type(arg) == dshell.core.Connection:
                for blob in arg.blobs:
                    if blob.data:
                        rawdata.append((blob.data, blob.direction))
            elif type(arg) == dshell.core.Packet:
                rawdata.append((arg.pkt.body_bytes, kwargs.get('direction', '--')))
            elif type(arg) == tuple:
                rawdata.append(arg)
            else:
                rawdata.append((arg, kwargs.get('direction', '--')))

        # Clean up the rawdata into something more presentable
        if self.hexmode:
            cleanup_func = dshell.util.hex_plus_ascii
        else:
            cleanup_func = dshell.util.printable_text
        for k, v in enumerate(rawdata):
            newdata = cleanup_func(v[0])
            rawdata[k] = (newdata, v[1])

        # Convert the raw data strings into color-coded output
        data = []
        for arg in rawdata:
            datastring = colorformat % (self.colors.get(arg[1], '0'), arg[0])
            data.append(datastring)

        super().write(counter=self.counter, *data, **kwargs)
        self.counter += 1

obj = ColorOutput
