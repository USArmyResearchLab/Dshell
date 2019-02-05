import dshell
import util
import hashlib
import urllib
import re
import colorout

from httpdecoder import HTTPDecoder


class DshellDecoder(HTTPDecoder):

    def __init__(self):
        HTTPDecoder.__init__(self,
                             name='httpdump',
                             description='Dump useful information about HTTP sessions',
                             filter='tcp and (port 80 or port 8080 or port 8000)',
                             filterfn=lambda ((sip, sp), (dip, dp)): sp in (
                                 80, 8000, 8080) or dp in (80, 8000, 8080),
                             author='amm',
                             optiondict={
                                 'maxurilen': {'type': 'int', 'default': 30, 'help': 'Truncate URLs longer than max len.  Set to 0 for no truncating. (default: 30)'},
                                 'maxpost': {'type': 'int', 'default': 1000, 'help': 'Truncate POST body longer than max chars.  Set to 0 for no truncating. (default: 1000)'},
                                 'showcontent': {'action': 'store_true', 'help': 'Display response BODY.'},
                                 'showhtml': {'action': 'store_true', 'help': 'Display response BODY only if HTML.'},
                                 'urlfilter': {'type': 'string', 'default': None, 'help': 'Filter to URLs matching this regex'},
                             },
                             )
        self.out = colorout.ColorOutput()
        # Disable auto-gunzip as we want to indicate content that was
        # compressed in the output
        self.gunzip = False

    def HTTPHandler(self, conn, request, response, requesttime, responsetime):
        host = ''
        loc = ''
        uri = ''
        lastmodified = ''

        #request_time, request, response = self.httpDict[conn.addr]

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

        if self.urlfilter:
            if not re.search(self.urlfilter, host + request.uri):
                return

        if '?' in request.uri:
            [uri_location, uri_data] = request.uri.split('?', 1)
        else:
            uri_location = request.uri
            uri_data = ''

        if self.maxurilen > 0 and len(uri_location) > self.maxurilen:
            uri_location = uri_location[:self.maxurilen] + '[truncated]'
        else:
            uri_location = uri_location

        if response == None:
            response_message = "%s (%s) %s%s" % (
                request.method, 'NO RESPONSE', host, uri_location)
        else:
            response_message = "%s (%s) %s%s (%s)" % (
                request.method, response.status, host, uri_location, util.getHeader(response, 'content-type'))
        urlParams = util.URLDataToParameterDict(uri_data)
        postParams = util.URLDataToParameterDict(request.body)

        clientCookies = self._parseCookies(util.getHeader(request, 'cookie'))
        serverCookies = self._parseCookies(
            util.getHeader(response, 'set-cookie'))

        self.alert(response_message,
                   urlParams=urlParams, postParams=postParams, clientCookies=clientCookies, serverCookies=serverCookies,
                   **conn.info()
                   )

        referer = util.getHeader(request, 'referer')
        if len(referer):
            self.out.write('  Referer: %s\n' % referer)

        if clientCookies:
            self.out.write('  Client Transmitted Cookies:\n', direction='cs')
            for key in clientCookies:
                self.out.write('          %s -> %s\n' % (util.printableUnicode(key),
                                                         util.printableUnicode(clientCookies[key])), direction='cs')
        if serverCookies:
            self.out.write('  Server Set Cookies:\n', direction='sc')
            for key in serverCookies:
                self.out.write('          %s -> %s\n' % (util.printableUnicode(key),
                                                         util.printableUnicode(serverCookies[key])), direction='sc')

        if urlParams:
            self.out.write('  URLParameters:\n', direction='cs')
            for key in urlParams:
                self.out.write('          %s -> %s\n' % (util.printableUnicode(key),
                                                         util.printableUnicode(urlParams[key])), direction='cs')
        if postParams:
            self.out.write(' POSTParameters:\n', direction='cs')
            for key in postParams:
                self.out.write('          %s -> %s\n' % (util.printableUnicode(key),
                                                         util.printableUnicode(postParams[key])), direction='cs')
        elif len(request.body):
            self.out.write(' POST Body:\n', direction='cs')
            if len(request.body) > self.maxpost and self.maxpost > 0:
                self.out.write('%s[truncated]\n' % util.printableUnicode(
                    request.body[:self.maxpost]), direction='cs')
            else:
                self.out.write(
                    util.printableUnicode(request.body) + u"\n", direction='cs')

        if self.showcontent or self.showhtml:

            if self.showhtml and 'html' not in util.getHeader(response, 'content-type'):
                return

            if 'gzip' in util.getHeader(response, 'content-encoding'):
                content = self.decompressGzipContent(response.body)
                if content == None:
                    content = '(gunzip failed)\n' + response.body
                else:
                    content = '(gzip encoded)\n' + content
            else:
                content = response.body

            self.out.write("Body Content:\n", direction='sc')
            self.out.write(
                util.printableUnicode(content) + u"\n", direction='sc')

    def _parseCookies(self, data):
        p, kwp = util.strtok(data, sep='; ')
        return dict((urllib.unquote(k), urllib.unquote(kwp[k]))for k in kwp.keys())


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
