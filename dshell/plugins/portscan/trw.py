"""
Uses the Threshold Random Walk algorithm described in this paper:

Limitations to threshold random walk scan detection and mitigating enhancements
Written by: Mell, P.; Harang, R.
http://ieeexplore.ieee.org/xpls/icp.jsp?arnumber=6682723
"""

import dshell.core
from dshell.output.output import Output

from pypacker.layer4 import tcp

from collections import defaultdict

o0 = 0.8  # probability IP is benign given successful connection
o1 = 0.2  # probability IP is a scanner given successful connection
is_success = o0/o1
is_failure = o1/o0

max_fp_prob = 0.01
min_detect_prob = 0.99
hi_threshold = min_detect_prob / max_fp_prob
lo_threshold = max_fp_prob / min_detect_prob

OUTPUT_FORMAT = "(%(plugin)s) %(data)s\n"

class DshellPlugin(dshell.core.PacketPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(
            name="trw",
            author="dev195",
            bpf="tcp",
            output=Output(label=__name__, format=OUTPUT_FORMAT),
            description="Uses Threshold Random Walk to detect network scanners",
            optiondict={
                "mark_benigns": {
                    "action": "store_true",
                    "help": "Use an upper threshold to mark IPs as benign, thus removing them from consideration as scanners"
                }
            }
        )
        self.synners = set()
        self.ip_scores = defaultdict(lambda: 1)
        self.classified_ips = set()

    def check_score(self, ip, score):
        if self.mark_benigns and score >= hi_threshold:
            self.write("IP {} is benign (score: {})".format(ip, score))
            self.classified_ips.add(ip)
        elif score <= lo_threshold:
            self.write("IP {} IS A SCANNER! (score: {})".format(ip, score))
            self.classified_ips.add(ip)

    def packet_handler(self, pkt):
        if not pkt.tcp_flags:
            return

        # If we have a SYN, store it in a set and wait for some kind of
        # response or the end of pcap
        if pkt.tcp_flags == tcp.TH_SYN and pkt.sip not in self.classified_ips:
            self.synners.add(pkt.addr)
            return pkt

        # If we get the SYN/ACK, score the destination IP with a success
        elif pkt.tcp_flags == (tcp.TH_SYN | tcp.TH_ACK) and pkt.dip not in self.classified_ips:
            alt_addr = ((pkt.dip, pkt.dport), (pkt.sip, pkt.sport))
            if alt_addr in self.synners:
                self.ip_scores[pkt.dip] *= is_success
                self.check_score(pkt.dip, self.ip_scores[pkt.dip])
                self.synners.remove(alt_addr)
            return pkt

        # If we get a RST, assume the connection was refused and score the
        # destination IP with a failure
        elif pkt.tcp_flags & tcp.TH_RST and pkt.dip not in self.classified_ips:
            alt_addr = ((pkt.dip, pkt.dport), (pkt.sip, pkt.sport))
            if alt_addr in self.synners:
                self.ip_scores[pkt.dip] *= is_failure
                self.check_score(pkt.dip, self.ip_scores[pkt.dip])
                self.synners.remove(alt_addr)
            return pkt


    def postfile(self):
        # Go through any SYNs that didn't get a response and assume they failed
        for addr in self.synners:
            ip = addr[0][0]
            if ip in self.classified_ips:
                continue
            self.ip_scores[ip] *= is_failure
            self.check_score(ip, self.ip_scores[ip])

