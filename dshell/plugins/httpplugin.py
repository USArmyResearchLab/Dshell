"""
This is a base-level plugin inteded to handle HTTP connections.

It inherits from the base ConnectionPlugin and provides a new handler
function: http_handler(conn, request, response).

It automatically pairs requests/responses, parses headers, reassembles bodies,
and collects them into HTTPRequest and HTTPResponse objects that are passed
to the http_handler.
"""

import logging

import dshell.core

from pypacker.layer567 import http

import gzip
import io


logger = logging.getLogger(__name__)


def parse_headers(obj, f):
    """Return dict of HTTP headers parsed from a file object."""
    # Logic lifted mostly from dpkt's http module
    d = {}
    while 1:
        line = f.readline()
        line = line.decode('utf-8')
        line = line.strip()
        if not line:
            break
        l = line.split(None, 1)
        if not l[0].endswith(':'):
            raise dshell.core.DataError("Invalid header {!r}".format(line))
        k = l[0][:-1].lower()
        v = len(l) != 1 and l[1] or ''
        if k in d:
            if not type(d[k]) is list:
                d[k] = [d[k]]
            d[k].append(v)
        else:
            d[k] = v
    return d


def parse_body(obj, f, headers):
    """Return HTTP body parsed from a file object, given HTTP header dict."""
    # Logic lifted mostly from dpkt's http module
    if headers.get('transfer-encoding', '').lower() == 'chunked':
        l = []
        found_end = False
        while 1:
            try:
                sz = f.readline().split(None, 1)[0]
            except IndexError:
                obj.errors.append(dshell.core.DataError('missing chunk size'))
                # FIXME: If this error occurs sz is not available to continue parsing!
                #   The appropriate exception should be thrown.
                raise
            n = int(sz, 16)
            if n == 0:
                found_end = True
            buf = f.read(n)
            if f.readline().strip():
                break
            if n and len(buf) == n:
                l.append(buf)
            else:
                break
        if not found_end:
            raise dshell.core.DataError('premature end of chunked body')
        body = b''.join(l)
    elif 'content-length' in headers:
        n = int(headers['content-length'])
        body = f.read(n)
        if len(body) != n:
            obj.errors.append(dshell.core.DataError('short body (missing {} bytes)'.format(n - len(body))))
    elif 'content-type' in headers:
        body = f.read()
    else:
        # XXX - need to handle HTTP/0.9
        body = b''
    return body


class HTTPRequest(object):
    """
    A class for HTTP requests

    Attributes:
        blob    : the Blob instance of the request
        errors  : a list of caught exceptions from parsing
        method  : the method of the request (e.g. GET, PUT, POST, etc.)
        uri     : the URI being requested (host not included)
        version : the HTTP version (e.g. "1.1" for "HTTP/1.1")
        headers : a dictionary containing the headers and values
        body    : bytestring of the reassembled body, after the headers
    """
    _methods = (
        'GET', 'PUT', 'ICY',
        'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
        'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE',
        'DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY',
        'BDELETE', 'CONNECT', 'OPTIONS', 'CHECKIN',
        'PROPFIND', 'CHECKOUT', 'CCM_POST',
        'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND',
        'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
        'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
        'VERSION-CONTROL',
        'BASELINE-CONTROL'
        )

    def __init__(self, blob):
        self.errors = []
        self.headers = {}
        self.body = b''
        self.blob = blob
        data = io.BytesIO(blob.data)
        rawline = data.readline()
        try:
            line = rawline.decode('utf-8')
        except UnicodeDecodeError:
            line = ''
        l = line.strip().split()
        if len(l) != 3 or l[0] not in self._methods or not l[2].startswith('HTTP'):
            self.errors.append(dshell.core.DataError('invalid HTTP request: {!r}'.format(rawline)))
            self.method = ''
            self.uri = ''
            self.version = ''
            return
        else:
            self.method = l[0]
            self.uri = l[1]
            self.version = l[2][5:]
        self.headers = parse_headers(self, data)
        self.body = parse_body(self, data, self.headers)


class HTTPResponse(object):
    """
    A class for HTTP responses

    Attributes:
        blob    : the Blob instance of the request
        errors  : a list of caught exceptions from parsing
        version : the HTTP version (e.g. "1.1" for "HTTP/1.1")
        status  : the status code of the response (e.g. "200" or "304")
        reason  : the status text of the response (e.g. "OK" or "Not Modified")
        headers : a dictionary containing the headers and values
        body    : bytestring of the reassembled body, after the headers
    """
    def __init__(self, blob):
        self.errors = []
        self.headers = {}
        self.body = b''
        self.blob = blob
        data = io.BytesIO(blob.data)
        rawline = data.readline()
        try:
            line = rawline.decode('utf-8')
        except UnicodeDecodeError:
            line = ''
        l = line.strip().split(None, 2)
        if len(l) < 2 or not l[0].startswith("HTTP") or not l[1].isdigit():
            self.errors.append(dshell.core.DataError('invalid HTTP response: {!r}'.format(rawline)))
            self.version = ''
            self.status = ''
            self.reason = ''
            return
        else:
            self.version = l[0][5:]
            self.status = l[1]
            self.reason = l[2]
        self.headers = parse_headers(self, data)
        self.body = parse_body(self, data, self.headers)

    def decompress_gzip_content(self):
        """
        If this response has Content-Encoding set to something with "gzip",
        this function will decompress it and store it in the body.
        """
        if "gzip" in self.headers.get("content-encoding", ""):
            try:
                iobody = io.BytesIO(self.body)
            except TypeError as e:
                # TODO: Why would body ever not be bytes? If it's not bytes, then that means
                #   we have a bug somewhere in the code and therefore should just allow the
                #   original exception to be raised.
                self.errors.append(dshell.core.DataError("Body was not a byte string ({!s}). Could not decompress.".format(type(self.body))))
                return
            try:
                self.body = gzip.GzipFile(fileobj=iobody).read()
            except OSError as e:
                self.errors.append(OSError("Could not gunzip body. {!s}".format(e)))
                return


class HTTPPlugin(dshell.core.ConnectionPlugin):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Use "gunzip" argument to automatically decompress gzipped responses
        self.gunzip = kwargs.get("gunzip", False)

    def connection_handler(self, conn):
        """
        Goes through each Blob in a Connection, assuming they appear in pairs
        of requests and responses, and builds HTTPRequest and HTTPResponse
        objects.

        After a response (or only a request at the end of a connection),
        http_handler is called. If it returns nothing, the respective blobs
        are marked as hidden so they won't be passed to additional plugins.
        """
        request = None
        response = None
        for blob in conn.blobs:
            # blob.reassemble(allow_overlap=True, allow_padding=True)
            if not blob.data:
                continue
            if blob.direction == 'cs':
                # client-to-server request
                request = HTTPRequest(blob)
                for req_error in request.errors:
                    self.debug("Request Error: {!r}".format(req_error))
            elif blob.direction == 'sc':
                # server-to-client response
                response = HTTPResponse(blob)
                for rep_error in response.errors:
                    self.debug("Response Error: {!r}".format(rep_error))
                if self.gunzip:
                    response.decompress_gzip_content()
                http_handler_out = self.http_handler(conn=conn, request=request, response=response)
                if not http_handler_out:
                    if request:
                        request.blob.hidden = True
                    if response:
                        response.blob.hidden = True
                request = None
                response = None
        if request and not response:
            http_handler_out = self.http_handler(conn=conn, request=request, response=None)
            if not http_handler_out:
                blob.hidden = True
        return conn

    def http_handler(self, conn, request, response):
        """
        A placeholder.

        Plugins will be able to overwrite this to perform custom activites
        on HTTP data.

        It SHOULD return a list containing the sames types of values that came
        in as arguments (i.e. return (conn, request, response)) or None. This
        is mostly a consistency thing. Realistically, it only needs to return
        some value that evaluates to True to pass the Blobs along to additional
        plugins.

        Arguments:
            conn:       a Connection object
            request:    a HTTPRequest object
            response:   a HTTPResponse object
        """
        return conn, request, response

DshellPlugin = None
