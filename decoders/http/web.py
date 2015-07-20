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
                             author='bg,twp,mrl',
                             optiondict={
                                 'maxurilen': {'type': 'int', 'default': 30, 'help': 'Truncate URLs longer than max len.  Set to 0 for no truncating. (default: 30)'},
                                 'md5': {'action': 'store_true', 'help': 'calculate MD5 for each response. Available in CSV output.'},
                                 'color': {'action': 'store_true', 'help': 'display colored output for various traffic types'}
                             },
                             )
        self.gunzip = False  # Not interested in response body

    def set_color(self, content_type):
        if (content_type in ("application/zip", 
            "application/x-rar-compressed", 
            "application/vnd.ms-cab-compressed")): 

            # For zip file downloads, color output yellow
            color_code = '\x1b[33m' 
        
        elif(content_type in ('application/x-shockwave-flash',
            'application/octet-stream',
            'application/octet-stream', 
            'application/x-www-form-urlencoded')):

            # For flash file downloads, color output cyan
            color_code = '\x1b[36m'

        elif(content_type == 'application/x-msdownload'):
            # For executable file downloads, color output red
            color_code = '\x1b[31m'

        else:
            # White output for all other traffic
            color_code = '\x1b[37m'
        return color_code

    def generate_alert(self, conn, color_code, request_info, response_info, **kwargs):
        print '%s\r' % color_code,
        self.alert("%-80s // %s" % (request_info, response_info), kwargs, **conn.info())
        print '\x1b[37m',

    def HTTPHandler(self, conn, request, response, requesttime, responsetime):
        host = ''
        loc = ''
        lastmodified = ''
        
        # extract method,uri,host from response
        host = util.getHeader(request, 'host')
        if host == '':
            host = conn.serverip
        try:
            status = response.status
        except:
            status = ''
        try:
            reason = response.reason
        except:
            reason = ''

        loc = ''
        if status[:2] == '30':
            loc = util.getHeader(response, 'location')
            if len(loc):
                loc = '-> ' + loc

        lastmodified = util.HTTPlastmodified(response)
        referer = util.getHeader(request, 'referer')
        useragent = util.getHeader(request, 'user-agent')
        via = util.getHeader(request, 'via')
        content_type = util.getHeader(response, 'content-type')

        if self.color:
            color_code = self.set_color(content_type)
        else:
            color_code = '\x1b[37m'
        print color_code,

        try:
            responsesize = len(response.body.rstrip('\0'))
        except:
            responsesize = 0

        if self.md5:
            md5 = self._bodyMD5(response)
        else:
            md5 = ''

        # File objects
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

        requestInfo = '%s %s%s HTTP/%s' % (request.method,
                                           host,
                                           request.uri[:self.maxurilen] + '[truncated]' if self.maxurilen > 0 and len(
                                               request.uri) > self.maxurilen else request.uri,
                                           request.version)
        if response:
            responseInfo = '%s %s %s %s' % (status, reason, loc, lastmodified)
        else:
            responseInfo = ''

        self.generate_alert(conn, color_code, requestInfo, responseInfo, referer=referer, useragent=useragent, request=requestInfo, response=responseInfo, request_time=requesttime, response_time=responsetime, request_method=request.method, host=host, uri=request.uri, status=status, reason=reason, lastmodified=lastmodified, md5=md5, responsesize=responsesize, contenttype=util.getHeader(response, 'content-type'), responsefile=responsefile, uploadfile=uploadfile, via=via)

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
