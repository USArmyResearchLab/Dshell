"""
Generates packet or reconstructed stream output as a HTML page.

Based on colorout module originally written by amm
"""

from dshell.output.output import Output
import dshell.util
import dshell.core
from xml.sax.saxutils import escape

class HTMLOutput(Output):
    _DESCRIPTION = "HTML format output"
    _PACKET_FORMAT = """<h1>Packet %(counter)s (%(protocol)s)</h1><h2>Start: %(ts)s
%(sip)s:%(sport)s -> %(dip)s:%(dport)s (%(bytes)s bytes)
</h2>
%(data)s
"""
    _CONNECTION_FORMAT = """<h1>Connection %(counter)s (%(protocol)s)</h1><h2>Start: %(starttime)s
End: %(endtime)s
%(clientip)s:%(clientport)s -> %(serverip)s:%(serverport)s (%(clientbytes)s bytes)
%(serverip)s:%(serverport)s -> %(clientip)s:%(clientport)s (%(serverbytes)s bytes)
</h2>
%(data)s
"""
    _DEFAULT_FORMAT = _PACKET_FORMAT
    _DEFAULT_DELIM = "<br />"

    _HTML_HEADER = """
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Dshell Output</title>
    <style>
        body {
            font-family: monospace;
            font-size: 10pt;
            white-space: pre;
        }
        h1 {
            font-family: helvetica;
            font-size: 13pt;
            font-weight: bolder;
            white-space: pre;
        }
        h2 {
            font-family: helvetica;
            font-size: 12pt;
            font-weight: bolder;
            margin: 0 0;
            white-space: pre;
        }
    </style>
</head>
<body>
"""

    _HTML_FOOTER = """
</body>
</html>
"""

    def __init__(self, *args, **kwargs):
        "Can be called with an optional 'hex' argument to display output in hex"
        super().__init__(*args, **kwargs)
        self.counter = 1
        self.colors = {
            'cs': 'red',   # client-to-server is red
            'sc': 'green',   # server-to-client is green
            '--': 'blue',   # everything else is blue
        }
        self.hexmode = kwargs.get('hex', False)
        self.format_is_set = False

    def setup(self):
        # activate color blind friendly mode
        if self.cbf:
            self.colors['cs'] = 'gold'   # client-to-server is gold (darker yellow)
            self.colors['sc'] = 'seagreen'   # server-to-client is sea green (lighter green)
        self.fh.write(self._HTML_HEADER)

    def write(self, *args, **kwargs):
        if not self.format_is_set:
            if 'clientip' in kwargs:
                self.set_format(self._CONNECTION_FORMAT)
            else:
                self.set_format(self._PACKET_FORMAT)
            self.format_is_set = True

        # a template string for data output
        colorformat = '<span style="color:%s;">%s</span>'

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
            newdata = escape(newdata)
            rawdata[k] = (newdata, v[1])

        # Convert the raw data strings into color-coded output
        data = []
        for arg in rawdata:
            datastring = colorformat % (self.colors.get(arg[1], ''), arg[0])
            data.append(datastring)

        super().write(counter=self.counter, *data, **kwargs)
        self.counter += 1

    def close(self):
        self.fh.write(self._HTML_FOOTER)
        Output.close(self)

obj = HTMLOutput
