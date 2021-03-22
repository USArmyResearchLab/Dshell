"""
Identifies HTTP traffic and reassembles file transfers before writing them to
files.
"""

import os
import re
import sys

from dshell.plugins.httpplugin import HTTPPlugin
from dshell.output.alertout import AlertOutput

class DshellPlugin(HTTPPlugin):
    def __init__(self):
        super().__init__(
            name="rip-http",
            author="bg,twp",
            bpf="tcp and (port 80 or port 8080 or port 8000)",
            description="Rips files from HTTP traffic",
            output=AlertOutput(label=__name__),
            optiondict={'append_conn':
                            {'action': 'store_true',
                             'help': 'append sourceip-destip to filename'},
                        'append_ts':
                            {'action': 'store_true',
                             'help': 'append timestamp to filename'},
                        'direction':
                            {'help': 'cs=only capture client POST, sc=only capture server GET response',
                             'metavar': '"cs" OR "sc"',
                             'default': None},
                        'outdir':
                            {'help': 'directory to write output files (Default: current directory)',
                             'metavar': 'DIRECTORY',
                             'default': '.'},
                        'content_filter':
                            {'help': 'regex MIME type filter for files to save',
                             'metavar': 'REGEX'},
                        'name_filter':
                            {'help': 'regex filename filter for files to save',
                             'metavar': 'REGEX'}
            }
        )

    def premodule(self):
        if self.direction not in ('cs', 'sc', None):
            self.logger.warning("Invalid value for direction: {!r}. Argument must be either 'sc' for server-to-client or 'cs' for client-to-server.".format(self.direction))
            sys.exit(1)

        if self.content_filter:
            self.content_filter = re.compile(self.content_filter)
        if self.name_filter:
            self.name_filter = re.compile(self.name_filter)

        self.openfiles = {}

        if not os.path.exists(self.outdir):
            try:
                os.makedirs(self.outdir)
            except (IOError, OSError) as e:
                self.error("Could not create output directory: {!r}: {!s}"
                           .format(self.outdir, e))
                sys.exit(1)

    def http_handler(self, conn, request, response):
        if (not self.direction or self.direction == 'cs') and request and request.method == "POST" and request.body:
            if not self.content_filter or self.content_filter.search(request.headers.get('content-type', '')):
                payload = request
        elif (not self.direction or self.direction == 'sc') and response and response.status[0] == '2':
            if not self.content_filter or self.content_filter.search(response.headers.get('content-type', '')):
                payload = response
        else:
            payload = None

        if not payload:
            # Connection did not match any filters, so get rid of it
            return

        host = request.headers.get('host', conn.serverip)
        url = host + request.uri

        if url in self.openfiles:
            # File is already open, so just insert the new data
            s, e = self.openfiles[url].handleresponse(response)
            self.logger.debug("{0!r} --> Range: {1} - {2}".format(url, s, e))
        else:
            # A new file!
            filename = request.uri.split('?', 1)[0].split('/')[-1]
            if self.name_filter and self.name_filter.search(filename):
                # Filename did not match filter, so get rid of it
                return
            if not filename:
                # Assume index.html if there is no filename
                filename = "index.html"
            if self.append_conn:
                filename += "_{0}-{1}".format(conn.serverip, conn.clientip)
            if self.append_ts:
                filename += "_{}".format(conn.ts)
            while os.path.exists(os.path.join(self.outdir, filename)):
                filename += "_"
            self.write("New file {} ({})".format(filename, url), **conn.info(), dir_arrow="<-")
            self.openfiles[url] = HTTPFile(os.path.join(self.outdir, filename), self)
            s, e = self.openfiles[url].handleresponse(payload)
            self.logger.debug("{0!r} --> Range: {1} - {2}".format(url, s, e))
        if self.openfiles[url].done():
            self.write("File done {} ({})".format(filename, url), **conn.info(), dir_arrow="<-")
            del self.openfiles[url]

        return conn, request, response


class HTTPFile(object):
    """
    An internal class used to hold metadata for open HTTP files.
    Used mostly to reassemble fragmented transfers.
    """

    def __init__(self, filename, plugin_instance):
        self.complete = False
        # Expected size in bytes of full file transfer
        self.size = 0
        # List of tuples indicating byte chunks already received and written to
        # disk
        self.ranges = []
        self.plugin = plugin_instance
        self.filename = filename
        try:
            self.fh = open(filename, 'wb')
        except IOError as e:
            self.plugin.error(
                "Could not create file {!r}: {!s}".format(filename, e))
            self.fh = None

    def __del__(self):
        if self.fh is None:
            return
        self.fh.close()
        if not self.done():
            self.plugin.warning("Incomplete file: {!r}".format(self.filename))
            try:
                os.rename(self.filename, self.filename + "_INCOMPLETE")
            except:
                pass
            ls = 0
            le = 0
            for s, e in self.ranges:
                if s > le + 1:
                    self.plugin.warning(
                        "Missing bytes between {0} and {1}".format(le, s))
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


if __name__ == "__main__":
    print(DshellPlugin())
