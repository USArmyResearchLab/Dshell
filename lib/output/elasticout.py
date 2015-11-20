'''
Created on May 6, 2015

@author: amm
'''

import sys
import output
import dshell
import dfile
import logging
import datetime
import elasticsearch


class elasticout(output.TextOutput):
    '''
    ElasticSearch Output module
    use with --output=elasticout

    e.g.  decode -d web *pcap --output elasticout,host=192.168.10.10,index=dshell

            options
            -------
            host:         <host>:<ip> of an Elasticsearch search node  (REQUIRED)
            index:        Elasticsearch index  (REQUIRED)
            doc_type:     Elasticsearch document type for indexed documents
            geoip:        If set to Y, output module won't discard geoip tags
            notrim:       If set to Y, do not trim any fields from the output
            message:      If set to Y, add the decoder output message (args[0])
                             as a "message" field in elasticsearch
    '''

    ELASTIC_HOST_LIST = []
    ELASTIC_INDEX = None
    _DOC_TYPE = None

    # Fields to format as timestamp string
    _TIMESTAMP_FIELDS = (
        'ts', 'starttime', 'endtime', 'request_time', 'response_time')
    # Fields to delete (redundant or unnecessary)
    _DELETE_FIELDS = ('addr', 'direction', 'clientport', 'serverport',
                      'clientip', 'serverip', 'sipint', 'dipint', 'pkttype')
    # Dshell geolocation fields
    _GEO_FIELDS = ('servercountrycode', 'clientcountrycode',
                   'sipcc', 'dipcc', 'clientasn', 'serverasn', 'dipasn', 'sipasn')

    def __init__(self, *args, **kwargs):

        #
        # Specified host - prepend to any list hard coded into the module
        #
        if 'host' in kwargs:
            self.ELASTIC_HOST_LIST.insert(0, kwargs['host'])

        #
        # Instantiate Elasticsearch client
        #
        if len(self.ELASTIC_HOST_LIST):
            self.es = elasticsearch.Elasticsearch(self.ELASTIC_HOST_LIST)
        else:
            self.es = elasticsearch.Elasticsearch()

        #
        # Index
        #
        if 'index' in kwargs:
            self.ELASTIC_INDEX = kwargs['index']

        #
        # Document Type
        #
        if 'doc_type' in kwargs:
        	self._DOC_TYPE = kwargs['doc_type']

        #
        # Handle boolean options
        #
        self.options = {}
        for o in ('geoip', 'notrim', 'message'):
            self.options[o] = False
            if o in kwargs:
                if kwargs[o].upper() in ('Y', 'T', '1', 'YES', 'ON', 'TRUE'):
                    self.options[o] = True
                del kwargs[o]

        #
        # Check for existence of preInsert function
        #  this function allows child classes to have one last access
        #  to the data -- as will be inserted to Elasticsearch -- before
        #  the actual insert
        #
        #  Function should return boolean value
        #    True to proceed with insert
        #    False to skip
        #
        #
        if 'preInsert' in dir(self):
            self.hasPreInsert = True
        else:
            self.hasPreInsert = False

        # Call parent init
        output.TextOutput.__init__(self, **kwargs)

    def alert(self, *args, **kw):

        #
        # DocType
        #
        if self._DOC_TYPE:
        	doc_type = self._DOC_TYPE
        elif 'decoder' in kw:
          doc_type = kw['decoder']
          del kw['decoder']
        else:
        	doc_type = 'dshell'

        #
        # Remove Common Redundant Fields
        #
        if not self.options['notrim']:
            for name in self._DELETE_FIELDS:
                if name in kw:
                    del kw[name]

        #
        # Time Fields
        #
        # Rename 'ts' to 'starttime' if 'starttime' not present
        if 'ts' in kw:
            if 'starttime' not in kw:
                kw['starttime'] = kw['ts']
            del kw['ts']

        #
        # Remove GEOIP Fields
        #
        if not self.options['geoip']:
            for name in self._GEO_FIELDS:
                if name in kw:
                    del kw[name]

        #
        # Perform multiple tasks, iterating across the kw dict
        #
        for k in kw.keys():
            #
            # Convert known timestamp fields to datetime format
            #  Remove empty fields
            #
            if k.lower() in self._TIMESTAMP_FIELDS:
                if type(kw[k]) == datetime:
                    continue
                elif type(kw[k]) == str:
                    if len(kw[k]) == 0:
                        del kw[k]
                        continue
                    else:
                        # dshell has a different default date/time string format than elastic,
                        # so let's try to parse that into a datetime object
                        try:
                            kw[k] = datetime.datetime.strptime(
                                kw[k], '%Y-%m-%d %H:%M:%S')
                        except:
                            pass  # if fail, pass it through and let elastic try to parse it
                else:
                    # if not a string, try to
                    try:
                        kw[k] = datetime.datetime.fromtimestamp(float(kw[k]))
                    except:
                        pass
            #
            # Get Rid of Dfiles.  Must be handled elsewhere.
            #
            if isinstance(kw[k], dfile.dfile):
                del kw[k]

        #
        # Message
        #
        if self.options['message']:
            if 'message' not in kw:
                kw['message'] = args[0].rstrip()

        #
        # Allow child classes to access the data one last time before the insert
        #
        if self.hasPreInsert:
            if not self.preInsert(kw):
                return (False, None)

        #
        # Insert into elastic
        #
        if '_id' in kw:
            docid = kw['_id']
            del kw['_id']
            es_response = self.es.index(
                index=self.ELASTIC_INDEX, id=docid, doc_type=doc_type, body=kw)
        else:
            es_response = self.es.index(
                index=self.ELASTIC_INDEX, doc_type=doc_type, body=kw)
        if es_response['created']:
            return (True, es_response)
        else:
            if es_response['_version'] > 1:
                self.log("Possible key collision: %s" %
                         (str(es_response)), logging.WARN)
                # sys.stderr.write(repr(kw))
            else:
                self.log("Elasticsearch error: %s" %
                         (str(es_response)), logging.WARN)
            return (False, es_response)

    def write(self, *args, **kwargs):
        print "WRITE CALLED (Not implemented in output decoder)"

obj = elasticout
