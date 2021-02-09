"""
Displays basic information for web requests/responses in a connection.
"""

from dshell.plugins.httpplugin import HTTPPlugin
from dshell.output.alertout import AlertOutput

from hashlib import md5

class DshellPlugin(HTTPPlugin):
    def __init__(self):
        super().__init__(
            name="web",
            author="bg,twp",
            description="Displays basic information for web requests/responses in a connection",
            bpf="tcp and (port 80 or port 8080 or port 8000)",
            output=AlertOutput(label=__name__),
            optiondict={
                "md5": {"action": "store_true",
                        "help": "Calculate MD5 for each response."}
            },
        )

    def http_handler(self, conn, request, response):
     
        if request:
            if request.method=="":
                # It's impossible to have a properly formed HTTP request without a method
                # indicating, the httpplugin is calling http_handler without a full object
                return None
            # Collect basics about the request, if available
            method = request.method
            host = request.headers.get("host", "")
            uri = request.uri
#            useragent = request.headers.get("user-agent", None)
#            referer = request.headers.get("referer", None)
            version = request.version
        else:
            method = "(no request)"
            host = ""
            uri = ""
            version = ""

        if response:
            if response.status == "" and response.reason == "":
                # Another indication of improperly parsed HTTP object in httpplugin
                return None
            # Collect basics about the response, if available
            status = response.status
            reason = response.reason
            if self.md5:
                hash = "(md5: {})".format(md5(response.body).hexdigest())
            else:
                hash = ""
        else:
            status = "(no response)"
            reason = ""
            hash = ""

        data = "{} {}{} HTTP/{} {} {} {}".format(method,
                                                 host,
                                                 uri,
                                                 version,
                                                 status,
                                                 reason,
                                                 hash)
        if not request:
            self.write(data, method=method, host=host, uri=uri, version=version, status=status, reason=reason, hash=hash, **response.blob.info())
        elif not response:
            self.write(data, method=method, uri=uri, version=version, status=status, reason=reason, hash=hash, **request.headers, **request.blob.info())
        else:
        	self.write(data, method=method, uri=uri, version=version, status=status, reason=reason, hash=hash, request_headers=request.headers, response_headers=response.headers, **request.blob.info())
        return conn, request, response

if __name__ == "__main__":
    print(DshellPlugin())
