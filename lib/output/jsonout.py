'''
@author: amm
'''

import dshell
import dfile
import output
import datetime
import json
import base64


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
        self.fh.write(
            json.dumps(self._filter_data(kw), ensure_ascii=self.options['ensure_ascii']) + "\n")
        if self.nobuffer:
            self.fh.flush()


    # Reusable function to filter data in alerts and writes
    def _filter_data(self, kw):

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

        outdata = {}
        for n,v in kw.iteritems():
            if not isinstance(v, dfile.dfile):
              outdata[n] = v

        return outdata


    def write(self,*args,**kw):
  
      # Iterate *args
      for a in args:
        if type(a) == dshell.Blob:
          self.fh.write(json.dumps(self._blob_to_dict(blob), ensure_ascii=self.options['ensure_ascii']) + "\n")
        elif type(a) == dshell.Connection:
          outdata = self._filter_data(a.info())
          outdata['type'] = 'conn'
          outdata['data'] = []
          for blob in a:
            #self._write_blob(blob, kw)
            outdata['data'].append(self._blob_to_dict(blob))
          self.fh.write(json.dumps(outdata, ensure_ascii=self.options['ensure_ascii']) + "\n")
        else:
          d = self._filter_data(kw)
          d['type'] = 'raw'
          if type(a) == unicode:
            d['data'] = base64.b64encode(a.encode('utf-8'))
          else:
            d['data'] = base64.b64encode(a)
          self.fh.write(json.dumps(d, ensure_ascii=self.options['ensure_ascii']) + "\n")
  
    # Custom error handler for data reassembly --- ignores all errors
    def errorH(self, **x):
      return True
  
    def _blob_to_dict(self, blob):
      d = self._filter_data(blob.info())
      d['type'] = 'blob'
      d['data'] = base64.b64encode(blob.data(errorHandler=self.errorH))
      return d



obj = JSONOutput
