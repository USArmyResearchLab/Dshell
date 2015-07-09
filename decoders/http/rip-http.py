import dshell
import re
import datetime
import sys
import string

# import any other modules here
import re
import os
import hashlib
import util

# we extend this
from httpdecoder import HTTPDecoder


class DshellDecoder(HTTPDecoder):

    def __init__(self):
        HTTPDecoder.__init__(self,
                             name='rip-http',
                             description='rip files from HTTP traffic',
                             filter='tcp and port 80',
                             author='bg/twp',
                             optiondict={'append_conn': {'action': 'store_true', 'help': 'append sourceip-destip to filename'},
                                         'append_ts': {'action': 'store_true', 'help': 'append timestamp to filename'},
                                         'direction': {'help': 'cs=only capture client POST, sc=only capture server GET response'},
                                         'outdir': {'help': 'directory to write output files (Default: current directory)', 'metavar': 'DIRECTORY', 'default': '.'},
                                         'content_filter': {'help': 'regex MIME type filter for files to save'},
                                         'name_filter': {'help': 'regex filename filter for files to save'}}
                             )

    def preModule(self):
        if self.content_filter:
            self.content_filter = re.compile(self.content_filter)
        if self.name_filter:
            self.name_filter = re.compile(self.name_filter)
        HTTPDecoder.preModule(self)

        self.openfiles = {}  # dict of httpfile objects, indexed by url

        # Create output directory, if necessary
        if not os.path.exists(self.outdir):
            try:
                os.makedirs(self.outdir)
            except (IOError, OSError) as e:
                self.error("Could not create directory '%s': %s" %
                           (self.outdir, e))
                sys.exit(1)

    def splitstrip(self, data, sep, strip=' '):
        return [lpart.strip(strip) for lpart in data.split(sep)]

    def HTTPHandler(self, conn, request, response, requesttime, responsetime):
        payload = None
        self.debug('%s %s' % (repr(request), repr(response)))
        if (not self.direction or self.direction == 'cs') and request and request.method == 'POST' and request.body:
                payload = request
        elif (not self.direction or self.direction == 'sc') and response and response.status[0] == '2':
                payload = response 
        if payload:
            if not (not self.content_filter or self.content_filter.search(payload.headers['content-type'])):
                payload = None
        if payload:        
            # Calculate URL
            host = util.getHeader(request, 'host')
            if host == '':
                host = conn.serverip
            url = host + request.uri
            # File already open
            if url in self.openfiles:
                self.debug("Adding response section to %s" % url)
                (s, e) = self.openfiles[url].handleresponse(response)
                self.write(" --> Range: %d - %d\n" % (s, e))
            # New file
            else:
                filename = request.uri.split('?')[0].split('/')[-1]
                if 'content-disposition' in payload.headers:
                    cdparts = self.splitstrip(payload.headers['content-disposition'], ';')
                    for cdpart in cdparts:
                        try:
                            k, v = self.splitstrip(cdpart, '=')
                            if k == 'filename':
                                filename = v
                        except:
                            pass
                self.debug("New file with URL: %s" % url)
                if not self.name_filter or self.name_filter.search(filename):
                    if self.append_conn:
                        filename += '_%s-%s' % (conn.serverip,
                                                conn.clientip)
                    if self.append_ts:
                        filename += '_%d' % (conn.ts)
                    if not len(filename):
                        filename = '%s-%s_index.html' % (
                            conn.serverip, conn.clientip)
                    while os.path.exists(os.path.join(self.outdir, filename)):
                        filename += '_'
                    self.alert("New file: %s (%s)" %
                               (filename, url), conn.info())
                    self.openfiles[url] = httpfile(
                        os.path.join(self.outdir, filename), self)
                    (s, e) = self.openfiles[url].handleresponse(payload)
                    self.write(" --> Range: %d - %d\n" % (s, e))
            if self.openfiles[url].done():
                self.alert("File done: %s (%s)" %
                           (self.openfiles[url].filename, url), conn.info())
                del self.openfiles[url]


class httpfile:

    def __init__(self, filename, decoder_instance):
        self.complete = False
        # Expected size in bytes of full file transfer
        self.size = 0
        # List of tuples indicating byte chunks already received and written to
        # disk
        self.ranges = []
        self.decoder = decoder_instance
        self.filename = filename
        try:
            self.fh = open(filename, 'w')
        except IOError as e:
            self.decoder.error(
                "Could not create file '%s': %s" % (filename, e))
            self.fh = None

    def __del__(self):
        if self.fh is None:
            return
        self.fh.close()
        if not self.done():
            print "Incomplete file: %s" % self.filename
            try:
                os.rename(self.filename, self.filename + "_INCOMPLETE")
            except:
                pass
            ls = 0
            le = 0
            for s, e in self.ranges:
                if s > le + 1:
                    print "Missing bytes between %d and %d" % (le, s)
                ls, le = s, e

    def handleresponse(self, response):
        # Check for Content Range
        range_start = 0
        range_end = len(response.body) - 1
        if 'content-range' in response.headers:
            m = re.search(
                'bytes (\d+)-(\d+)/(\d+|\*)', response.headers['content-range'])
            if m:
                range_start = int(m.group(1))
                range_end = int(m.group(2))
                if len(response.body) < (range_end - range_start + 1):
                    range_end = range_start + len(response.body) - 1
                try:
                    if int(m.group(3)) > self.size:
                        self.size = int(m.group(3))
                except:
                    pass
        elif 'content-length' in response.headers:
            try:
                if int(response.headers['content-length']) > self.size:
                    self.size = int(response.headers['content-length'])
            except:
                pass
        # Update range tracking
        self.ranges.append((range_start, range_end))
        # Write part of file
        if self.fh is not None:
            self.fh.seek(range_start)
            self.fh.write(response.body)
        return (range_start, range_end)

    def done(self):
        self.checkranges()
        return self.complete

    def checkranges(self):
        self.ranges.sort()
        current_start = 0
        current_end = 0
        foundgap = False
        # print self.ranges
        for s, e in self.ranges:
            if s <= current_end + 1:
                current_end = e
            else:
                foundgap = True
                current_start = s
                current_end = e
        if not foundgap:
            if (current_end + 1) >= self.size:
                self.complete = True
        return foundgap

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
