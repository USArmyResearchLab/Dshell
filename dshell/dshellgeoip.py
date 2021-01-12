# -*- coding: utf-8 -*-
"""
A wrapper around GeoIP2 that provides convenience functions for querying and
collecting GeoIP data
"""

import datetime
import logging
import os
from collections import OrderedDict

import geoip2.database
import geoip2.errors

from dshell.util import get_data_path


logger = logging.getLogger(__name__)


class DshellGeoIP(object):
    MAX_CACHE_SIZE = 5000

    def __init__(self, acc=False):
        self.geodir = os.path.join(get_data_path(), 'GeoIP')
        self.geoccfile = os.path.join(self.geodir, 'GeoLite2-City.mmdb')
        self.geoasnfile = os.path.join(self.geodir, 'GeoLite2-ASN.mmdb')
        self.geoccdb = geoip2.database.Reader(self.geoccfile)
        self.geoasndb = geoip2.database.Reader(self.geoasnfile)
        self.geo_asn_cache = DshellGeoIPCache(max_cache_size=self.MAX_CACHE_SIZE)
        self.geo_loc_cache = DshellGeoIPCache(max_cache_size=self.MAX_CACHE_SIZE)
        self.acc = acc

    def check_file_dates(self):
        """
        Check the data file age, and log a warning if it's over a year old.
        """
        cc_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(self.geoccfile))
        asn_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(self.geoasnfile))
        n = datetime.datetime.now()
        year = datetime.timedelta(days=365)
        if (n - cc_mtime) > year or (n - asn_mtime) > year:
            logger.debug("GeoIP data file(s) over a year old, and possibly outdated.")

    def geoip_country_lookup(self, ip):
        """
        Looks up the IP and returns the two-character country code.
        """
        location = self.geoip_location_lookup(ip)
        return location[0]

    def geoip_asn_lookup(self, ip):
        """
        Looks up the IP and returns an ASN string.
        Example:
            print geoip_asn_lookup("74.125.26.103")
            "AS15169 Google LLC"
        """
        try:
            return self.geo_asn_cache[ip]
        except KeyError:
            try:
                template = "AS{0.autonomous_system_number} {0.autonomous_system_organization}"
                asn = template.format(self.geoasndb.asn(ip))
                self.geo_asn_cache[ip] = asn
                return asn
            except geoip2.errors.AddressNotFoundError:
                return None

    def geoip_location_lookup(self, ip):
        """
        Looks up the IP and returns a tuple containing country code, latitude,
        and longitude.
        """
        try:
            return self.geo_loc_cache[ip]
        except KeyError:
            try:
                location = self.geoccdb.city(ip)
                # Get country code based on order of importance
                # 1st: Country that owns an IP address registered in another
                #      location (e.g. military bases in foreign countries)
                # 2nd: Country in which the IP address is registered
                # 3rd: Physical country where IP address is located
                # https://dev.maxmind.com/geoip/geoip2/whats-new-in-geoip2/#Country_Registered_Country_and_Represented_Country
                # Handle flag from plugin optional args to enable all 3 country codes
                if self.acc:
                    try:
                        cc = "{}/{}/{}".format(location.represented_country.iso_code,
                                               location.registered_country.iso_code,
                                               location.country.iso_code)
                        cc = cc.replace("None", "--")

                    except KeyError:
                        pass
                else:
                    cc = (location.represented_country.iso_code or
                          location.registered_country.iso_code or
                          location.country.iso_code or
                          '--')

                location = (
                    cc,
                    location.location.latitude,
                    location.location.longitude
                )
                self.geo_loc_cache[ip] = location
                return location
            except geoip2.errors.AddressNotFoundError:
                # Handle flag from plugin optional args to enable all 3 country codes
                if self.acc:
                    location = ("--/--/--", None, None)
                else:
                    location = ("--", None, None)
                self.geo_loc_cache[ip] = location
                return location


class DshellFailedGeoIP(object):
    """
    Class used in place of DshellGeoIP if GeoIP database files are not found.
    """

    def __init__(self):
        self.geodir = os.path.join(get_data_path(), 'GeoIP')
        self.geoccdb = None
        self.geoasndb = None

    def check_file_dates(self):
        pass

    def geoip_country_lookup(self, ip):
        return "??"

    def geoip_asn_lookup(self, ip):
        return None

    def geoip_location_lookup(self, ip):
        return ("??", None, None)


class DshellGeoIPCache(OrderedDict):
    """
    A cache for storing recent IP lookups to improve performance.
    """

    def __init__(self, *args, **kwargs):
        self.max_cache_size = kwargs.pop("max_cache_size", 500)
        OrderedDict.__init__(self, *args, **kwargs)

    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        self.check_max_size()

    def check_max_size(self):
        while len(self) > self.max_cache_size:
            self.popitem(last=False)
