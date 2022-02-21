'''
Shows 802.11 wireless beacons and related information
'''

from collections import defaultdict
from datetime import datetime

import dshell.core
from dshell.output.output import Output

class DshellPlugin(dshell.core.PacketPlugin):

    OUTPUT_FORMAT = '[%(plugin)s]\t%(dt)s\tInterval: %(interval)s TU,\tSSID: %(ssid)s\t%(count)s\n'

    def __init__(self, *args, **kwargs):
        super().__init__(
            name='Wi-fi Beacons',
            description='Show SSIDs of 802.11 wireless beacons',
            author='dev195',
            bpf='wlan type mgt subtype beacon',
            output=Output(label=__name__, format=self.OUTPUT_FORMAT),
            optiondict={
                'group': {'action': 'store_true', 'help': 'Group beacons together with counts'},
            }
        )
        self.group_counts = defaultdict(int)
        self.group_times  = defaultdict(datetime.now)

    def packet_handler(self, pkt):
        # Extract 802.11 frame from packet
        try:
            frame = pkt.pkt.ieee80211
        except AttributeError:
            frame = pkt.pkt

        # Confirm that packet is, in fact, a beacon
        if not frame.is_beacon():
            return

        # Extract SSID from frame
        beacon = frame.beacon
        ssid = ''
        try:
            for param in beacon.params:
                # Find the SSID parameter
                if param.id == 0:
                    ssid = param.body_bytes.decode('utf-8')
                    break
        except IndexError:
            # Sometimes pypacker fails to parse a packet
            return

        if self.group:
            self.group_counts[(ssid, beacon.interval)] += 1
            self.group_times[(ssid, beacon.interval)]  = pkt.ts
        else:
            self.write(ssid=ssid, interval=beacon.interval, **pkt.info())

        return pkt

    def postfile(self):
        if self.group:
            for key, val in self.group_counts.items():
                ssid, interval = key
                dt = self.group_times[key]
                self.write(ssid=ssid, interval=interval, plugin=self.name, dt=dt, count=val)
