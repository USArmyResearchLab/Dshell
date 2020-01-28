import dshell
import dfile
import util
import hashlib

from httpdecoder import HTTPDecoder


class DshellDecoder(HTTPDecoder):

    def __init__(self):
        HTTPDecoder.__init__(self,
                             name='web',
                             description='Improved version of web that tracks server response',
                             filter='tcp and (port 80 or port 8080 or port 8000)',
                             filterfn=lambda ((sip, sp), (dip, dp)): sp in (
                                 80, 8000, 8080) or dp in (80, 8000, 8080),
                             author='bg,twp',
                             optiondict={
                                 'maxurilen': {'type': 'int', 'default': 30, 'help': 'Truncate URLs longer than max len.  Set to 0 for no truncating. (default: 30)'},
                                 'md5': {'action': 'store_true', 'help': 'calculate MD5 for each response. Available in CSV output.'}
                             },
                             )
        self.gunzip = False  # Not interested in response body

    def HTTPHandler(self, conn, request, response, requesttime, responsetime):

        #
        # Establish kw_items dictionary for extracted details from tcp/ip layer and request/response
        #
        kw_items = conn.info()
        
        #
        # Extract useful information from HTTP *request*
        #
        for h in request.headers.keys():
          kw_items[h] = util.getHeader(request, h)
        # Rename user-agent for backward compatability
        if 'user-agent' in kw_items:
          kw_items['useragent'] = kw_items.pop('user-agent')
        
        # Override non-existent host header with server IP address
        if kw_items['host'] == '':
            kw_items['host'] = conn.serverip

        # request info string for standard output
        requestInfo = '%s %s%s HTTP/%s' % (request.method,
                                           kw_items['host'] if kw_items['host'] != request.uri else '',  # With CONNECT method, the URI is or contains the host, making this redudant
                                           request.uri[:self.maxurilen] + '[truncated]' if self.maxurilen > 0 and len(
                                               request.uri) > self.maxurilen else request.uri,
                                           request.version)

        #
        # Extract useful information from HTTP *response* (if available)
        #
        status = ''
        reason = ''
        responsesize = 0
        loc = ''
        lastmodified = ''
        md5 = ''
        if response!=None:

            try:
                responsesize = len(response.body.rstrip('\0'))
            except:
                responsesize = 0

            if self.md5:
                md5 = self._bodyMD5(response)
            else:
                md5 = ''

            try:
                status = response.status
            except:
                status = ''
            try:
                reason = response.reason
            except:
                reason = ''

            for h in response.headers.keys():
              if not h in kw_items:
                  kw_items[h] = util.getHeader(response, h)
              else:
                  kw_items['server_'+h] = util.getHeader(response, h)
            if 'content-type' in kw_items:
              kw_items['contenttype'] = kw_items.pop('content-type')

            loc = ''
            if status[:2] == '30':
                loc = util.getHeader(response, 'location')
                if len(loc):
                    loc = '-> ' + loc
    
            lastmodified = util.HTTPlastmodified(response)
            
            # response info string for standard output
            responseInfo = '%s %s %s %s' % (status, reason, loc, lastmodified)

        else:
            responseInfo = ''

        #
        # File objects
        #
        try:
            if len(response.body) > 0:
                responsefile = dfile.dfile(
                    name=request.uri, data=response.body)
            else:
                responsefile = ''
        except:
            responsefile = ''
        if request.method == 'POST' and len(request.body):
            ulcontenttype, ulfilename, uldata = self.POSTHandler(request.body)
            uploadfile = dfile.dfile(name=ulfilename, data=uldata)
        else:
            uploadfile = None

				#
				# Call alert with text info and kw values
				#
        self.alert("%-80s // %s" % (requestInfo, responseInfo), request=requestInfo, response=responseInfo,
        					 request_time=requesttime, response_time=responsetime, request_method=request.method,
                   uri=request.uri, status=status, reason=reason, lastmodified=lastmodified,
                   md5=md5, responsesize=responsesize, responsefile=responsefile, uploadfile=uploadfile, **kw_items)

        if self.out.sessionwriter:
            self.write(request.data, direction='cs')
            if response:
                self.write(response.body, direction='sc')

    # MD5sum(hex) of the body portion of the response
    def _bodyMD5(self, response):
        try:
            if len(response.body) > 0:
                return hashlib.md5(response.body.rstrip('\0')).hexdigest()
            else:
                return ''
        except:
            return ''

    def POSTHandler(self, postdata):
        next_line_is_data = False
        contenttype = ''
        filename = ''
        for l in postdata.split("\r\n"):
            if next_line_is_data:
                break
            if l == '':
                next_line_is_data = True  # \r\n\r\n before data
                continue
            try:
                k, v = self.splitstrip(l, ':')
                if k == 'Content-Type':
                    contenttype = v
                if k == 'Content-Disposition':
                    cdparts = self.splitstrip(v, ';')
                    for cdpart in cdparts:
                        try:
                            k, v = self.splitstrip(cdpart, '=', '"')
                            if k == 'filename':
                                filename = v
                        except:
                            pass
            except:
                pass
        return contenttype, filename, l

    def splitstrip(self, data, sep, strip=' '):
        return [lpart.strip(strip) for lpart in data.split(sep)]


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
