'''
@author: tparker
'''

import output
import util
import dshell
from xml.etree import ElementTree as ET


class XMLOutput(output.FileOutput):

    '''XMLOutput Module'''

    def __init__(self, *args, **kwargs):
        '''init the underlying file output to get the file handle'''
        output.FileOutput.__init__(
            self, *args, **kwargs)  # pass all to fileoutput
        self.root = ET.Element('dshell')
        self.element = self.root

    def alert(self, *args, **kwargs):
        '''we will assume we get alerts before we get the matching session data'''
        self.element = ET.SubElement(
            self.root, 'alert', self._filter_attr(kwargs))
        self.element.text = self._filter_text(' '.join(args))

    def write(self, obj, parent=None, **kwargs):
        '''write the object data under the last alert element (or the root if no alert)
                if a conn object recurse in by iterating
                else write the string output of the object'''
        if not parent:
            parent = self.element
        kw = dict(**kwargs)
        # turns "<xxxx 'yyyy'>" into "yyyy"
        tag = str(type(obj)).split("'", 2)[1]
        if tag.startswith('dshell.'):  # is a dshell object
            kw.update(**obj.info())  # get attribs
            # turns "dshell.Connection" into "Connection"
            tag = tag.split('dshell.')[1]
        e = ET.SubElement(parent, tag, self._filter_attr(kw))
        if tag == 'Connection':  # recurse on blobs in conn
            for blob in obj:
                self.write(blob, parent=e)
            return  # subobjects will have the data
        # leave this up to the object to handle
        e.text = self._filter_text(str(obj))

    def _filter_attr(self, d): return dict((k, str(v))
                                           for (k, v) in d.iteritems())

    def _filter_text(self, t): return ''.join(c for c in t if ord(c) < 128)

    def close(self):
        '''write the ElementTree to the file'''
        ET.ElementTree(self.root).write(self.fh)

'''NOTE: output modules return obj=reference to the CLASS
    instead of a dObj=instance so we can init with args'''
obj = XMLOutput
