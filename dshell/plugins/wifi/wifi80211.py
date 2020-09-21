"""
Shows 802.11 information for individual packets.
"""

import dshell.core
from dshell.output.output import Output

from pypacker.layer12 import ieee80211

# Create a dictionary of string representations of frame types
TYPE_KEYS = {
    ieee80211.MGMT_TYPE: "MGMT",
    ieee80211.CTL_TYPE: "CTRL",
    ieee80211.DATA_TYPE: "DATA"
}

# Create a dictionary of subtype keys from constants defined in ieee80211
# Its keys will be tuple pairs of (TYPE, SUBTYPE)
SUBTYPE_KEYS = dict()
# Management frame subtypes
SUBTYPE_KEYS.update(dict(((ieee80211.MGMT_TYPE, v), k[2:]) for k, v in ieee80211.__dict__.items() if type(v) == int and k.startswith("M_")))
# Control frame subtypes
SUBTYPE_KEYS.update(dict(((ieee80211.CTL_TYPE, v), k[2:]) for k, v in ieee80211.__dict__.items() if type(v) == int and k.startswith("C_")))
# Data frame subtypes
SUBTYPE_KEYS.update(dict(((ieee80211.DATA_TYPE, v), k[2:]) for k, v in ieee80211.__dict__.items() if type(v) == int and k.startswith("D_")))

class DshellPlugin(dshell.core.PacketPlugin):

    OUTPUT_FORMAT = "[%(plugin)s] %(dt)s [%(ftype)s] [%(encrypted)s] [%(fsubtype)s] %(bodybytes)r %(retry)s\n"

    def __init__(self, *args, **kwargs):
        super().__init__(
            name="802.11",
            description="Show 802.11 packet information",
            author="dev195",
            bpf="wlan type mgt or wlan type ctl or wlan type data",
            output=Output(label=__name__, format=self.OUTPUT_FORMAT),
            optiondict={
                "ignore_mgt": {"action": "store_true", "help": "Ignore management frames"},
                "ignore_ctl": {"action": "store_true", "help": "Ignore control frames"},
                "ignore_data": {"action": "store_true", "help": "Ignore data frames"},
                "ignore_beacon": {"action": "store_true", "help": "Ignore beacons"},
            },
            longdescription="""
Shows basic information for 802.11 packets, including:
 - Frame type
 - Encryption
 - Frame subtype
 - Data sample
"""
        )

    def handle_plugin_options(self):
        "Update the BPF based on 'ignore' flags"
        # NOTE: This function is naturally called in decode.py
        bpf_pieces = []
        if not self.ignore_mgt:
            if self.ignore_beacon:
                bpf_pieces.append("(wlan type mgt and not wlan type mgt subtype beacon)")
            else:
                bpf_pieces.append("wlan type mgt")
        if not self.ignore_ctl:
            bpf_pieces.append("wlan type ctl")
        if not self.ignore_data:
            bpf_pieces.append("wlan type data")
        self.bpf = " or ".join(bpf_pieces)

    def packet_handler(self, pkt):
        try:
            frame = pkt.pkt.ieee80211
        except AttributeError:
            frame = pkt.pkt
        encrypted = "encrypted" if frame.protected else "         "
        frame_type = TYPE_KEYS.get(frame.type, '----')
        frame_subtype = SUBTYPE_KEYS.get((frame.type, frame.subtype), "")
        retry = "[resent]" if frame.retry else ""
        bodybytes = frame.body_bytes[:50]

        self.write(
            encrypted=encrypted,
            ftype=frame_type,
            fsubtype=frame_subtype,
            retry=retry,
            bodybytes=bodybytes,
            **pkt.info()
        )

        return pkt
