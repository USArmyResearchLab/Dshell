"""
This output module converts plugin output into JSON and indexes it into
an Elasticsearch datastore

NOTE: This module requires the third-party 'elasticsearch' Python module
"""

import ipaddress
import json

from elasticsearch import Elasticsearch

import dshell.output.jsonout

class ElasticOutput(dshell.output.jsonout.JSONOutput):
    """
    Elasticsearch output module
    Use with --output=elasticsearchout

    It is recommended that it be run with some options set:
        host:       server hosting the database (localhost)
        port:       HTTP port listening (9200)
        index:      name of index storing results ("dshell")
        type:       the type for each alert ("alerts")

    Example use:
        decode --output=elasticout --oargs="index=dshellalerts" --oargs="type=netflowout" -d netflow ~/pcap/example.pcap
    """

    _DESCRIPTION = "Automatically insert data into an elasticsearch instance"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs.copy())

        self.options = {}
        self.options['host'] = kwargs.get('host', 'localhost')
        self.options['port'] = int(kwargs.get('port', 9200))
        self.options['index'] = kwargs.get('index', 'dshell')
        self.options['type'] = kwargs.get('type', 'alerts')

        self.es = Elasticsearch([self.options['host']], port=self.options['port'])

    def write(self, *args, **kwargs):
        "Converts alert's keyword args to JSON and indexes it into Elasticsearch datastore."
        if args and 'data' not in kwargs:
            kwargs['data'] = self.delimiter.join(map(str, args))

        # Elasticsearch can't handle IPv6 (at time of writing)
        # Just delete the ints and expand the string notation.
        # Hopefully, it will be possible to perform range searches on this
        # consistent IP string format.
        try:
            del kwargs['dipint']
        except KeyError:
            pass
        try:
            del kwargs['sipint']
        except KeyError:
            pass
        try:
            kwargs['dip'] = ipaddress.ip_address(kwargs['dip']).exploded
        except KeyError:
            pass
        try:
            kwargs['sip'] = ipaddress.ip_address(kwargs['sip']).exploded
        except KeyError:
            pass

        jsondata = json.dumps(kwargs, ensure_ascii=self.ensure_ascii, default=self.json_default)
#        from pprint import pprint
#        pprint(jsondata)
        self.es.index(index=self.options['index'], doc_type=self.options['type'], body=jsondata)

obj = ElasticOutput
