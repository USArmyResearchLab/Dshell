#!/usr/bin/env python
import dshell
import util
import dpkt

# for HTTPDecoder gzip decompression
import gzip
import cStringIO


class HTTPDecoder(dshell.TCPDecoder):

    '''extend HTTPDecoder to handle HTTP request/responses
            will call HTTPHandler(
                                                            conn=Connection(),
                                                            request=dpkt.http.Request,
                                                            response=dpkt.http.Response,
                                                            requesttime=timestamp, responsetime=timestamp
                                                    )
            after each response.

            config: noresponse: if True and connection closes w/o response, will call with response,responsetime=None,None (True)
                    gunzip: if True will decompress gzip encoded response bodies (default True)

    '''

    def __init__(self, **kwargs):
        self.noresponse = True
        self.gunzip = True
        dshell.TCPDecoder.__init__(self, **kwargs)
        self.requests = {}

    # Custom error handler for data reassembly --- ignores errors, keep data
    def errorH(self, **x):
        return True

    def blobHandler(self, conn, blob):
        '''buffer the request blob and call the handler once we have the response blob'''
        if conn not in self.requests:
            try:
                self.requests[conn] = (
                    blob.starttime, dpkt.http.Request(blob.data(self.errorH)))
            except Exception, e:
                self.UnpackError(e)
        else:
            try:
                if 'HTTPHandler' in dir(self):
                    response = dpkt.http.Response(blob.data(self.errorH))
                    if self.gunzip and 'gzip' in util.getHeader(response, 'content-encoding'):
                        bodyUnzip = self.decompressGzipContent(response.body)
                        if bodyUnzip != None:
                            response.body = bodyUnzip
                    self.HTTPHandler(conn=conn,
                                     request=self.requests[conn][1],
                                     response=response,
                                     requesttime=self.requests[conn][0],
                                     responsetime=blob.starttime)
                del self.requests[conn]
            except Exception, e:
                self.UnpackError(e)
                self.HTTPHandler(conn=conn, request=self.requests[conn][
                                 1], response=None, requesttime=self.requests[conn][0], responsetime=blob.starttime)
                del self.requests[conn]

    def connectionHandler(self, conn):
        '''when the connection closes, flush out any request blobs that did not have a response'''
        if conn in self.requests:
            if self.noresponse and 'HTTPHandler' in dir(self):
                self.HTTPHandler(conn=conn,
                                 request=self.requests[conn][1],
                                 response=None,
                                 requesttime=self.requests[conn][0],
                                 responsetime=self.requests[conn][0])
            del self.requests[conn]

    def decompressGzipContent(self, httpcontent):
        '''utility function to decompress gzip compressed content'''
        cstr = cStringIO.StringIO(httpcontent)
        try:
            return gzip.GzipFile(fileobj=cstr).read()
        except:
            return None

    def UnpackError(self, error):
        self._exc(error)


class displaystub(dshell.Decoder):

    def __init__(self):
        dshell.Decoder.__init__(self,
                                name='httpdecoder',
                                description='Intermediate class to support HTTP based decoders.',
                                longdescription="See source code or pydoc for details on use."
                                )

if __name__ == '__main__':
    dObj = displaystub()
    print dObj
else:
    dObj = displaystub()
