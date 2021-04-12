"""
This output module converts plugin output into JSON
"""

from datetime import datetime
import json
from dshell.output.output import Output
from dshell.core import Packet, Blob, Connection

class JSONOutput(Output):
    """
    Converts arguments for every write into JSON
    Can be called with ensure_ascii=True to pass flag on to the json module.
    """
    _DEFAULT_FORMAT = "%(jsondata)s\n"
    _DESCRIPTION = "JSON format output"

    def __init__(self, *args, **kwargs):
        self.ensure_ascii = kwargs.get('ensure_ascii', False)
        super().__init__(*args, **kwargs)

    def write(self, *args, **kwargs):
        if self.extra:
            # JSONOutput does not make use of the --extra flag, so disable it
            # before printing output
            self.extra = False
        if args and 'data' not in kwargs:
            kwargs['data'] = self.delim.join(map(str, args))
        jsondata = json.dumps(kwargs, ensure_ascii=self.ensure_ascii, default=self.json_default)
        super().write(jsondata=jsondata)

    def json_default(self, obj):
        """
        JSON serializer for objects not serializable by default json code
        https://stackoverflow.com/a/22238613
        """
        if isinstance(obj, datetime):
            serial = obj.strftime(self.timeformat)
            return serial
        if isinstance(obj, bytes):
            serial = repr(obj)
            return serial
        if isinstance(obj, (Connection, Blob, Packet)):
            serial = obj.info()
            return serial
        raise TypeError ("Type not serializable ({})".format(str(type(obj))))

obj = JSONOutput
