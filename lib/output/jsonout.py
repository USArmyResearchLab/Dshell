'''
@author: amm
'''

import output
import datetime
import json


class JSONOutput(output.TextOutput):

    '''
    JSON Output module
    use with --output=jsonout

            usage: as with csvout, you can pass a list of field names that will be included in the JSON output

            options
            -------
            geoip:        If set to Y, output module won't discard geoip tags
            notrim:       If set to Y, do not trim any fields from the output
            ensure_ascii: Enable this option in json library

    '''

    _TIMESTAMP_FIELDS = (
        'ts', 'starttime', 'endtime', 'request_time', 'response_time')

    def __init__(self, *args, **kwargs):

        # Options
        self.options = {}
        for o in ('geoip', 'notrim', 'ensure_ascii'):
            self.options[o] = False
            if o in kwargs:
                if kwargs[o] == True or kwargs[o].upper() in ('Y', 'T', '1', 'YES', 'ON', 'TRUE'):
                    self.options[o] = True
                del kwargs[o]

        # Args as fields
        self.jsonfields = None
        if len(args):
            self.jsonfields = []
            for a in args:
                self.jsonfields.append(a)

        # Call parent init
        output.TextOutput.__init__(self, **kwargs)

    def alert(self, *args, **kw):

        # User specified field list??
        if self.jsonfields != None:
            for f in kw.keys():
                if f not in self.jsonfields:
                    del kw[f]
        elif not self.options['notrim']:
            # Remove Common Redundant Fields
            for name in ('addr', 'direction', 'clientport', 'serverport', 'clientip', 'serverip', 'sipint', 'dipint'):
                if name in kw:
                    del kw[name]
            # Time Fields
            # Rename 'ts' to 'starttime' if 'starttime' not present
            if 'ts' in kw:
                if 'starttime' not in kw:
                    kw['starttime'] = kw['ts']
                del kw['ts']
            # Convert known timestamp fields to string format
            for name in self._TIMESTAMP_FIELDS:
                try:
                    kw[name] = datetime.datetime.fromtimestamp(
                        float(kw[name])).strftime(self.timeformat)
                except:
                    pass
            # Remove GEOIP Fields
            if not self.options['geoip']:
                for name in ('servercountrycode', 'clientcountrycode', 'sipcc', 'dipcc', 'clientasn', 'serverasn', 'dipasn', 'sipasn'):
                    if name in kw:
                        del kw[name]
        self.fh.write(
            json.dumps(kw, ensure_ascii=self.options['ensure_ascii']) + "\n")
        if self.nobuffer:
            self.fh.flush()

obj = JSONOutput
