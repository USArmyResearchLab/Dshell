"""
Shows MAC address information and optionally filters by it. It is highly
recommended that oui.txt be included in the share/ directory (see README).
"""

import logging
import os

import dshell.core
from dshell.output.output import Output
from dshell.util import get_data_path

logger = logging.getLogger(__name__)


class DshellPlugin(dshell.core.PacketPlugin):
    OUTPUT_FORMAT = "[%(plugin)s] %(dt)s   %(sip)-15s %(smac)-18s %(smac_org)-35s ->  %(dip)-15s %(dmac)-18s %(dmac_org)-35s %(byte_count)d\n"

    def __init__(self, *args, **kwargs):
        super().__init__(
            name="Ethernet",
            description="Show MAC address information and optionally filter by it",
            author="dev195",
            output=Output(label=__name__, format=self.OUTPUT_FORMAT),
            optiondict={
                "org": {"default":[], "action":"append", "metavar":"ORGANIZATION", "help":"Organizations owning MAC address to inclusively filter on (exact match only). Can be used multiple times to look for multiple organizations."},
                "org_exclusive": {"default":False, "action":"store_true", "help":"Set organization filter to be exclusive"},
                'quiet': {'action': 'store_true', 'default':False, 'help':'disable alerts for this plugin'}
            }
        )
        self.oui_map = {}

    def premodule(self):
        # Create a mapping of MAC address prefix to organization
        # http://standards-oui.ieee.org/oui.txt
        ouifilepath = os.path.join(get_data_path(), 'oui.txt')
        try:
            with open(ouifilepath, encoding="utf-8") as ouifile:
                for line in ouifile:
                    if "(hex)" not in line:
                        continue
                    line = line.strip().split(None, 2)
                    prefix = line[0].replace('-', ':')
                    org = line[2]
                    self.oui_map[prefix] = org
        except FileNotFoundError:
            # user probably did not download it
            # print warning and continue
            logger.warning("Could not find {} (see README). Will not be able to determine MAC organizations.".format(ouifilepath))

    def packet_handler(self, pkt):
        if not pkt.smac or not pkt.dmac:
            return
        smac_prefix = pkt.smac[:8].upper()
        smac_org = self.oui_map.get(smac_prefix, '???')
        dmac_prefix = pkt.dmac[:8].upper()
        dmac_org = self.oui_map.get(dmac_prefix, '???')

        # Filter out any packets that do not match organization filter
        if self.org:
            if self.org_exclusive and (smac_org in self.org or dmac_org in self.org):
                return
            elif not self.org_exclusive and not (smac_org in self.org or dmac_org in self.org):
                return

        if not self.quiet:
            self.write("", smac_org=smac_org, dmac_org=dmac_org, **pkt.info())
        return pkt


if __name__ == "__main__":
    print(DshellPlugin())
