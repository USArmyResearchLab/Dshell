"""
2015 Feb 13

Sometimes, attackers will try to obfuscate links to the Sweet Orange exploit
kit. This plugin is an attempt to decode that sort of traffic.

It will use a regular expression to try and detect certain variable names that
can be contained in JavaScript code. It will then take the value assigned to
it and decode the domain address hidden inside the value.

Samples:
http://malware-traffic-analysis.net/2014/10/27/index2.html
http://malware-traffic-analysis.net/2014/10/03/index.html
http://malware-traffic-analysis.net/2014/09/25/index.html
"""

import re

from dshell.output.alertout import AlertOutput
from dshell.plugins.httpplugin import HTTPPlugin

class DshellPlugin(HTTPPlugin):

    def __init__(self):
        super().__init__(
            name="sweetorange",
            longdescription="Used to decode certain variants of the Sweet Orange exploit kit redirect traffic. Looks for telltale Javascript variable names (e.g. 'ajax_data_source' and 'main_request_data_content') and automatically decodes the exploit landing page contained.",
            description="Used to decode certain variants of the Sweet Orange exploit kit redirect traffic",
            bpf="tcp and (port 80 or port 8080 or port 8000)",
            output=AlertOutput(label=__name__),
            author="dev195",
            gunzip=True,
            optiondict={
                "variable": {
                    "type": str,
                    "action": "append",
                    "help": 'Variable names to search for. Default ("ajax_data_source", "main_request_data_content")',
                    "default": ["ajax_data_source", "main_request_data_content"]
                },
                "color": {
                    "action": "store_true",
                    "help": "Display encoded/decoded lines in different TTY colors.",
                    "default": False
                },
            }
        )


    def premodule(self):
        self.sig_regex = re.compile(
            r"var (" + '|'.join(map(re.escape, self.variable)) + ")='(.*?)';")
        self.hexregex = re.compile(r'[^a-fA-F0-9]')
        self.logger.debug('Variable regex: "%s"' % self.sig_regex.pattern)

    def http_handler(self, conn, request, response):
        try:
            response_body = response.body.decode("ascii")
        except UnicodeError:
            return
        except AttributeError:
            return

        if response and any([v in response_body for v in self.variable]):
            # Take the variable's value, extract the hex characters, and
            # convert to ASCII
            matches = self.sig_regex.search(response_body)
            try:
                hidden = matches.groups()[1]
                match = bytes.fromhex(self.hexregex.sub('', hidden))
                match = match.decode('utf-8')
            except:
                return
            if self.color:
                # If desired, add TTY colors to the alerts for differentiation
                # between encoded/decoded strings
                hidden = "\x1b[37;2m%s\x1b[0m" % hidden
                match = "\x1b[32m%s\x1b[0m" % match

            self.logger.info(hidden)
            self.write(match, **conn.info())
            return (conn, request, response)

