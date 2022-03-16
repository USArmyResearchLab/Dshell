"""
Presents useful information points for HTTP sessions
"""

import dshell.core
import dshell.util
from dshell.plugins.httpplugin import HTTPPlugin
from dshell.output.colorout import ColorOutput

from urllib.parse import parse_qs
from http import cookies

class DshellPlugin(HTTPPlugin):
    def __init__(self):
        super().__init__(
            name="httpdump",
            description="Dump useful information about HTTP sessions",
            bpf="tcp and (port 80 or port 8080 or port 8000)",
            author="amm",
            output=ColorOutput(label=__name__),
            optiondict={
                "maxurilen": {
                    "type": int,
                    "default": 30,
                    "metavar": "LENGTH",
                    "help": "Truncate URLs longer than LENGTH (default: 30). Set to 0 for no truncating."},
                "maxpost": {
                    "type": int,
                    "default": 1000,
                    "metavar": "LENGTH",
                    "help": "Truncate POST bodies longer than LENGTH characters (default: 1000). Set to 0 for no truncating."},
                "maxcontent": {
                    "type": int,
                    "default": 0,
                    "metavar": "LENGTH",
                    "help": "Truncate response bodies longer than LENGTH characters (default: no truncating). Set to 0 for no truncating."},
                "showcontent": {
                    "action": "store_true",
                    "help": "Display response body"},
                "showhtml": {
                    "action": "store_true",
                    "help": "Display only HTML results"},
                "urlfilter": {
                    "type": str,
                    "default": None,
                    "metavar": "REGEX",
                    "help": "Filter to URLs matching this regular expression"}
                }
            )

    def premodule(self):
        if self.urlfilter:
            import re
            self.urlfilter = re.compile(self.urlfilter)

    def http_handler(self, conn, request, response):
        host = request.headers.get('host', conn.serverip)
        url = host + request.uri
        pretty_url = url

        # separate URL-encoded data from the location
        if '?' in request.uri:
            uri_location, uri_data = request.uri.split('?', 1)
            pretty_url = host + uri_location
        else:
            uri_location, uri_data = request.uri, ""

        # Check if the URL matches a user-defined filter
        if self.urlfilter and not self.urlfilter.search(pretty_url):
            return

        if self.maxurilen > 0 and len(uri_location) > self.maxurilen:
            uri_location = "{}[truncated]".format(uri_location[:self.maxurilen])
            pretty_url = host + uri_location

        # Set the first line of the alert to show some basic metadata
        if response == None:
            msg = ["{} (NO RESPONSE) {}".format(request.method, pretty_url)]
        else:
            msg = ["{} ({}) {} ({})".format(request.method, response.status, pretty_url, response.headers.get("content-type", "[no content-type]"))]

        # Determine if there is any POST data from the client and parse
        if request and request.method == "POST":
            try:
                post_params = parse_qs(request.body.decode("utf-8"), keep_blank_values=True)
                # If parse_qs only returns a single element with a null
                # value, it's probably an eroneous evaluation. Most likely
                # base64 encoded payload ending in an '=' character.
                if len(post_params) == 1 and list(post_params.values()) == [["\x00"]]:
                    post_params = request.body
            except UnicodeDecodeError:
                post_params = request.body
        else:
            post_params = {}

        # Get some additional useful data
        url_params = parse_qs(uri_data, keep_blank_values=True)
        referer = request.headers.get("referer", None)
        client_cookie = cookies.SimpleCookie(request.headers.get("cookie", ""))
        server_cookie = cookies.SimpleCookie(response.headers.get("cookie", ""))

        # Piece together the alert message
        if referer:
            msg.append("Referer: {}".format(referer))

        if client_cookie:
            msg.append("Client Transmitted Cookies:")
            for k, v in client_cookie.items():
                msg.append("\t{} -> {}".format(k, v.value))

        if server_cookie:
            msg.append("Server Set Cookies:")
            for k, v in server_cookie.items():
                msg.append("\t{} -> {}".format(k, v.value))

        if url_params:
            msg.append("URL Parameters:")
            for k, v in url_params.items():
                msg.append("\t{} -> {}".format(k, v))

        if post_params:
            if isinstance(post_params, dict):
                msg.append("POST Parameters:")
                for k, v in post_params.items():
                    msg.append("\t{} -> {}".format(k, v))
            else:
                msg.append("POST Data:")
                msg.append(dshell.util.printable_text(str(post_params)))
        elif request.body:
            msg.append("POST Body:")
            request_body = dshell.util.printable_text(request.body)
            if self.maxpost > 0 and len(request.body) > self.maxpost:
                msg.append("{}[truncated]".format(request_body[:self.maxpost]))
            else:
                msg.append(request_body)

        if self.showcontent or self.showhtml:
            if self.showhtml and 'html' not in response.headers.get('content-type', ''):
                return
            if 'gzip' in response.headers.get('content-encoding', ''):
                # TODO gunzipping
                content = '(gzip encoded)\n{}'.format(response.body)
            else:
                content = response.body
            content = dshell.util.printable_text(content)
            if self.maxcontent and len(content) > self.maxcontent:
                content = "{}[truncated]".format(content[:self.maxcontent])
            msg.append("Body Content:")
            msg.append(content)

        # Display the start and end times based on Blob instead of Connection
        kwargs = conn.info()
        if request:
            kwargs['starttime'] = request.blob.starttime
            kwargs['clientbytes'] = len(request.blob.data)
        else:
            kwargs['starttime'] = None
            kwargs['clientbytes'] = 0
        if response:
            kwargs['endtime'] = response.blob.endtime
            kwargs['serverbytes'] = len(response.blob.data)
        else:
            kwargs['endtime'] = None
            kwargs['serverbytes'] = 0

        if post_params:
            kwargs['post_params'] = post_params
        if url_params:
            kwargs['url_params'] = url_params
        if client_cookie:
            kwargs['client_cookie'] = client_cookie
        if server_cookie:
            kwargs['server_cookie'] = server_cookie

        self.write('\n'.join(msg), **kwargs)

        return conn, request, response
