"""
Extract interesting metadata from TLS connection setup
"""

import dshell.core
from dshell.output.alertout import AlertOutput
import sys
import struct
import binascii
import hashlib
import OpenSSL
import time
import ja3.ja3

##################################################################################################
#
# Reference RFC 2246 (TLS Protocol Version 1.0)
#       and RFC 3546 (TLS Extensions)
#
# http://www.ietf.org/rfc/rfc2246.txt
# http://www.ietf.org/rfc/rfc3546.txt
# http://www.ietf.org/rfc/rfc3280.txt
#
##################################################################################################

#####################
# Custom Exceptions #
#####################
class Error(Exception): pass
class InsufficientData(Exception): pass
class UnsupportedOption(Exception): pass
	
####################################
# Constants borrowed from dpkt.ssl #
####################################

# SSLv3/TLS version
SSL3_VERSION = 0x0300
TLS1_VERSION = 0x0301
TLS1_2_VERSION = 0x0303

# Record type
SSL3_RT_CHANGE_CIPHER_SPEC = 20
SSL3_RT_ALERT             = 21
SSL3_RT_HANDSHAKE         = 22
SSL3_RT_APPLICATION_DATA  = 23

# Handshake message type
SSL3_MT_HELLO_REQUEST           = 0
SSL3_MT_CLIENT_HELLO            = 1
SSL3_MT_SERVER_HELLO            = 2
SSL3_MT_CERTIFICATE             = 11
SSL3_MT_SERVER_KEY_EXCHANGE     = 12
SSL3_MT_CERTIFICATE_REQUEST     = 13
SSL3_MT_SERVER_DONE             = 14
SSL3_MT_CERTIFICATE_VERIFY      = 15
SSL3_MT_CLIENT_KEY_EXCHANGE     = 16
SSL3_MT_FINISHED                = 20

# Cipher Suit Text Strings
ciphersuit_text = {
	0x0000 : 'TLS_NULL_WITH_NULL_NULL',
	0x0001 : 'TLS_RSA_WITH_NULL_MD5',
	0x0002 : 'TLS_RSA_WITH_NULL_SHA',
	0x0003 : 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
	0x0004 : 'TLS_RSA_WITH_RC4_128_MD5',
	0x0005 : 'TLS_RSA_WITH_RC4_128_SHA',
	0x0006 : 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
	0x0007 : 'TLS_RSA_WITH_IDEA_CBC_SHA',
	0x0008 : 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
	0x0009 : 'TLS_RSA_WITH_DES_CBC_SHA',
	0x000A : 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
	0x000B : 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
	0x000C : 'TLS_DH_DSS_WITH_DES_CBC_SHA',
	0x000D : 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
	0x000E : 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
	0x000F : 'TLS_DH_RSA_WITH_DES_CBC_SHA',
	0x0010 : 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
	0x0011 : 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
	0x0012 : 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
	0x0013 : 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
	0x0014 : 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
	0x0015 : 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
	0x0016 : 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
	0x0017 : 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
	0x0018 : 'TLS_DH_anon_WITH_RC4_128_MD5',
	0x0019 : 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
	0x001A : 'TLS_DH_anon_WITH_DES_CBC_SHA',
	0x001B : 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
	0x001E : 'TLS_KRB5_WITH_DES_CBC_SHA',
	0x001F : 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
	0x0020 : 'TLS_KRB5_WITH_RC4_128_SHA',
	0x0021 : 'TLS_KRB5_WITH_IDEA_CBC_SHA',
	0x0022 : 'TLS_KRB5_WITH_DES_CBC_MD5',
	0x0023 : 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
	0x0024 : 'TLS_KRB5_WITH_RC4_128_MD5',
	0x0025 : 'TLS_KRB5_WITH_IDEA_CBC_MD5',
	0x0026 : 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
	0x0027 : 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
	0x0028 : 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
	0x0029 : 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
	0x002A : 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
	0x002B : 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
	0x002C : 'TLS_PSK_WITH_NULL_SHA',
	0x002D : 'TLS_DHE_PSK_WITH_NULL_SHA',
	0x002E : 'TLS_RSA_PSK_WITH_NULL_SHA',
	0x002F : 'TLS_RSA_WITH_AES_128_CBC_SHA',
	0x0030 : 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
	0x0031 : 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
	0x0032 : 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
	0x0033 : 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
	0x0034 : 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
	0x0035 : 'TLS_RSA_WITH_AES_256_CBC_SHA',
	0x0036 : 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
	0x0037 : 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
	0x0038 : 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
	0x0039 : 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
	0x003A : 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
	0x003B : 'TLS_RSA_WITH_NULL_SHA256',
	0x003C : 'TLS_RSA_WITH_AES_128_CBC_SHA256',
	0x003D : 'TLS_RSA_WITH_AES_256_CBC_SHA256',
	0x003E : 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
	0x003F : 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
	0x0040 : 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
	0x0041 : 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
	0x0042 : 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
	0x0043 : 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
	0x0044 : 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
	0x0045 : 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
	0x0046 : 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
	0x0067 : 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
	0x0068 : 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
	0x0069 : 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
	0x006A : 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
	0x006B : 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
	0x006C : 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
	0x006D : 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
	0x0084 : 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
	0x0085 : 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
	0x0086 : 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
	0x0087 : 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
	0x0088 : 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
	0x0089 : 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',
	0x008A : 'TLS_PSK_WITH_RC4_128_SHA',
	0x008B : 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
	0x008C : 'TLS_PSK_WITH_AES_128_CBC_SHA',
	0x008D : 'TLS_PSK_WITH_AES_256_CBC_SHA',
	0x008E : 'TLS_DHE_PSK_WITH_RC4_128_SHA',
	0x008F : 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
	0x0090 : 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
	0x0091 : 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
	0x0092 : 'TLS_RSA_PSK_WITH_RC4_128_SHA',
	0x0093 : 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
	0x0094 : 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
	0x0095 : 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
	0x0096 : 'TLS_RSA_WITH_SEED_CBC_SHA',
	0x0097 : 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
	0x0098 : 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
	0x0099 : 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
	0x009A : 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
	0x009B : 'TLS_DH_anon_WITH_SEED_CBC_SHA',
	0x009C : 'TLS_RSA_WITH_AES_128_GCM_SHA256',
	0x009D : 'TLS_RSA_WITH_AES_256_GCM_SHA384',
	0x009E : 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
	0x009F : 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
	0x00A0 : 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
	0x00A1 : 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
	0x00A2 : 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
	0x00A3 : 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
	0x00A4 : 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
	0x00A5 : 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
	0x00A6 : 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
	0x00A7 : 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
	0x00A8 : 'TLS_PSK_WITH_AES_128_GCM_SHA256',
	0x00A9 : 'TLS_PSK_WITH_AES_256_GCM_SHA384',
	0x00AA : 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
	0x00AB : 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
	0x00AC : 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
	0x00AD : 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
	0x00AE : 'TLS_PSK_WITH_AES_128_CBC_SHA256',
	0x00AF : 'TLS_PSK_WITH_AES_256_CBC_SHA384',
	0x00B0 : 'TLS_PSK_WITH_NULL_SHA256',
	0x00B1 : 'TLS_PSK_WITH_NULL_SHA384',
	0x00B2 : 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
	0x00B3 : 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
	0x00B4 : 'TLS_DHE_PSK_WITH_NULL_SHA256',
	0x00B5 : 'TLS_DHE_PSK_WITH_NULL_SHA384',
	0x00B6 : 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
	0x00B7 : 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
	0x00B8 : 'TLS_RSA_PSK_WITH_NULL_SHA256',
	0x00B9 : 'TLS_RSA_PSK_WITH_NULL_SHA384',
	0x00BA : 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256',
	0x00BB : 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
	0x00BC : 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
	0x00BD : 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
	0x00BE : 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
	0x00BF : 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
	0x00C0 : 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256',
	0x00C1 : 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
	0x00C2 : 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
	0x00C3 : 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
	0x00C4 : 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
	0x00C5 : 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
	0x00FF : 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
	0xC001 : 'TLS_ECDH_ECDSA_WITH_NULL_SHA',
	0xC002 : 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
	0xC003 : 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
	0xC004 : 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
	0xC005 : 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
	0xC006 : 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
	0xC007 : 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
	0xC008 : 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
	0xC009 : 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
	0xC00A : 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
	0xC00B : 'TLS_ECDH_RSA_WITH_NULL_SHA',
	0xC00C : 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
	0xC00D : 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
	0xC00E : 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
	0xC00F : 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
	0xC010 : 'TLS_ECDHE_RSA_WITH_NULL_SHA',
	0xC011 : 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
	0xC012 : 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
	0xC013 : 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
	0xC014 : 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
	0xC015 : 'TLS_ECDH_anon_WITH_NULL_SHA',
	0xC016 : 'TLS_ECDH_anon_WITH_RC4_128_SHA',
	0xC017 : 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
	0xC018 : 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
	0xC019 : 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
	0xC01A : 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
	0xC01B : 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
	0xC01C : 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
	0xC01D : 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
	0xC01E : 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
	0xC01F : 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
	0xC020 : 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
	0xC021 : 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
	0xC022 : 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
	0xC023 : 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
	0xC024 : 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
	0xC025 : 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
	0xC026 : 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
	0xC027 : 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
	0xC028 : 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
	0xC029 : 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
	0xC02A : 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
	0xC02B : 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
	0xC02C : 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
	0xC02D : 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
	0xC02E : 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
	0xC02F : 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
	0xC030 : 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
	0xC031 : 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
	0xC032 : 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
	0xC033 : 'TLS_ECDHE_PSK_WITH_RC4_128_SHA',
	0xC034 : 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
	0xC035 : 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
	0xC036 : 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
	0xC037 : 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
	0xC038 : 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
	0xC039 : 'TLS_ECDHE_PSK_WITH_NULL_SHA',
	0xC03A : 'TLS_ECDHE_PSK_WITH_NULL_SHA256',
	0xC03B : 'TLS_ECDHE_PSK_WITH_NULL_SHA384',
	0xC03C : 'TLS_RSA_WITH_ARIA_128_CBC_SHA256',
	0xC03D : 'TLS_RSA_WITH_ARIA_256_CBC_SHA384',
	0xC03E : 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256',
	0xC03F : 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384',
	0xC040 : 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256',
	0xC041 : 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384',
	0xC042 : 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256',
	0xC043 : 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384',
	0xC044 : 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256',
	0xC045 : 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384',
	0xC046 : 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256',
	0xC047 : 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384',
	0xC048 : 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
	0xC049 : 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
	0xC04A : 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256',
	0xC04B : 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384',
	0xC04C : 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
	0xC04D : 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
	0xC04E : 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256',
	0xC04F : 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384',
	0xC050 : 'TLS_RSA_WITH_ARIA_128_GCM_SHA256',
	0xC051 : 'TLS_RSA_WITH_ARIA_256_GCM_SHA384',
	0xC052 : 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256',
	0xC053 : 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384',
	0xC054 : 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256',
	0xC055 : 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384',
	0xC056 : 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256',
	0xC057 : 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384',
	0xC058 : 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256',
	0xC059 : 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384',
	0xC05A : 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256',
	0xC05B : 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384',
	0xC05C : 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
	0xC05D : 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
	0xC05E : 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256',
	0xC05F : 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384',
	0xC060 : 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
	0xC061 : 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
	0xC062 : 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256',
	0xC063 : 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384',
	0xC064 : 'TLS_PSK_WITH_ARIA_128_CBC_SHA256',
	0xC065 : 'TLS_PSK_WITH_ARIA_256_CBC_SHA384',
	0xC066 : 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256',
	0xC067 : 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384',
	0xC068 : 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256',
	0xC069 : 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384',
	0xC06A : 'TLS_PSK_WITH_ARIA_128_GCM_SHA256',
	0xC06B : 'TLS_PSK_WITH_ARIA_256_GCM_SHA384',
	0xC06C : 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256',
	0xC06D : 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384',
	0xC06E : 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256',
	0xC06F : 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384',
	0xC070 : 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256',
	0xC071 : 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384',
	0xC072 : 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
	0xC073 : 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
	0xC074 : 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
	0xC075 : 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
	0xC076 : 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
	0xC077 : 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
	0xC078 : 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
	0xC079 : 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
	0xC07A : 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256',
	0xC07B : 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384',
	0xC07C : 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
	0xC07D : 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
	0xC07E : 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
	0xC07F : 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
	0xC080 : 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
	0xC081 : 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
	0xC082 : 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
	0xC083 : 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
	0xC084 : 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
	0xC085 : 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
	0xC086 : 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
	0xC087 : 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
	0xC088 : 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
	0xC089 : 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
	0xC08A : 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
	0xC08B : 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
	0xC08C : 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
	0xC08D : 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
	0xC08E : 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256',
	0xC08F : 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384',
	0xC090 : 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
	0xC091 : 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
	0xC092 : 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
	0xC093 : 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
	0xC094 : 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256',
	0xC095 : 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384',
	0xC096 : 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
	0xC097 : 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
	0xC098 : 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
	0xC099 : 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
	0xC09A : 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
	0xC09B : 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
	0xC09C : 'TLS_RSA_WITH_AES_128_CCM',
	0xC09D : 'TLS_RSA_WITH_AES_256_CCM',
	0xC09E : 'TLS_DHE_RSA_WITH_AES_128_CCM',
	0xC09F : 'TLS_DHE_RSA_WITH_AES_256_CCM',
	0xC0A0 : 'TLS_RSA_WITH_AES_128_CCM_8',
	0xC0A1 : 'TLS_RSA_WITH_AES_256_CCM_8',
	0xC0A2 : 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
	0xC0A3 : 'TLS_DHE_RSA_WITH_AES_256_CCM_8',
	0xC0A4 : 'TLS_PSK_WITH_AES_128_CCM',
	0xC0A5 : 'TLS_PSK_WITH_AES_256_CCM',
	0xC0A6 : 'TLS_DHE_PSK_WITH_AES_128_CCM',
	0xC0A7 : 'TLS_DHE_PSK_WITH_AES_256_CCM',
	0xC0A8 : 'TLS_PSK_WITH_AES_128_CCM_8',
	0xC0A9 : 'TLS_PSK_WITH_AES_256_CCM_8',
	0xC0AA : 'TLS_PSK_DHE_WITH_AES_128_CCM_8',
	0xC0AB : 'TLS_PSK_DHE_WITH_AES_256_CCM_8',
}

keytypes = {
 OpenSSL.crypto.TYPE_RSA : 'RSA',
 OpenSSL.crypto.TYPE_DSA : 'DSA',
}


#####################################################################
# TLS - TLS message object, initialized from TCP segment
#
#   Status:  Currently only supports TLS 1.0 Handshake messages
#
#####################################################################
class TLS(object):

	def __init__(self, data):

		data_length = len(data)
		offset = 0

		#########################
		# Unpack TLSPlaintext   #
		#########################
		if data_length >= offset+5:
			(self.ContentType, self.ProtocolVersion, self.TLSRecordLength) = struct.unpack('!BHH', data[offset:offset+5])
			offset += 5
		else:
			raise InsufficientData('%d bytes received by TLS' % data_length)

		#
		# For now, only interested in TLS 1.0.
		# Reason: SSL2.0 records do not support the server_name extension, which is the primary
		#         motivation for creating this library.  Needs to be updated/extended eventually.
		#
		if self.ProtocolVersion != TLS1_VERSION and self.ProtocolVersion != SSL3_VERSION and self.ProtocolVersion != TLS1_2_VERSION:
			raise UnsupportedOption('Protocol version 0x%x not supported' % self.ProtocolVersion)

		#################
		# Check Size    #
		#################
		self.recordbytes = self.TLSRecordLength + 5
		if data_length < self.recordbytes:
			raise InsufficientData('%d bytes received by TLS' % data_length)

		#########################################################################
		# Content Types - Only Handshake supported for now
		#########################################################################
		self.Handshakes = []
		if self.ContentType == SSL3_RT_HANDSHAKE:

			###############################
			# Loop Through Handshakes     #
			###############################
			while self.recordbytes >= offset + 4:  # Need minimum four bytes for the rest to contain another Handshake
	
				HandshakeType = data[offset]
				offset += 1
		
				#
				# Handshake Record length
				#
				HandshakeLength = struct.unpack('!I', b'\x00' + data[offset:offset+3])[0]
				offset += 3
			
				#
				# Parse Handshake SubType
				#
				if HandshakeType == SSL3_MT_CLIENT_HELLO:
					try:
						self.Handshakes.append( TLSClientHello(HandshakeType, HandshakeLength, data[offset:offset+HandshakeLength]) )
					except:
						raise
				elif HandshakeType == SSL3_MT_SERVER_HELLO:
					try:
						self.Handshakes.append( TLSServerHello(HandshakeType, HandshakeLength, data[offset:offset+HandshakeLength]) )
					except:
						raise
				elif HandshakeType == SSL3_MT_CERTIFICATE:
					try:
						self.Handshakes.append( TLSCertificate(HandshakeType, HandshakeLength, data[offset:offset+HandshakeLength]) )
					except:
						raise				
	
				offset += HandshakeLength
			###############################
			# End Handshakes Loop         #
			###############################




#####################################################################
# TLSHandshake
#####################################################################
class TLSHandshake(object):

	def __init__(self, HandshakeType, HandshakeLength):
		self.HandshakeType = HandshakeType
		self.HandshakeLength = HandshakeLength

#####################################################################
# TLSCertificate - Certificate Handshake type
#####################################################################
class TLSCertificate(TLSHandshake):

	def __init__(self, HandshakeType, HandshakeLength, data):

		TLSHandshake.__init__(self, HandshakeType, HandshakeLength)
		data_length = len(data)
		offset = 0

		# length of all certificates
		if data_length >= offset+3:
			certificates_length = struct.unpack('!I', b'\x00' + data[offset:offset+3])[0]
			offset += 3
		else:
			raise InsufficientData('%d bytes received by TLSCertificate, expected %d for client_version' % (data_length, offset + 2))
			
		if data_length >= offset + certificates_length:
			try:
				self.Certificates = self.__parse_certs(data[offset:offset+certificates_length])
				offset += certificates_length
			except:
				offset += certificates_length
				raise
		else:
			raise InsufficientData('%d bytes received by TLSCertificate, expected %d for client_version' % (data_length, offset + certificates_length))
		
	# Returns array of x509 objects (defined below)
	def __parse_certs(self, data):

		certs = []	
		while data:
			try:
				clen,data=self.l24(data)
				if len(data) < clen: raise InsufficientData('%d bytes in buffer, need %d' % (len(data), clen))
				try:
					cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, data[:clen])
				except:
					return certs
				certs.append(cert)
				data = data[clen:]
			except:
				raise
		return certs

	def l24(self,data):
		'''24-bit length decoder'''
		(lh,ll),data=struct.unpack('!BH',data[0:3]),data[3:]
		return lh<<16|ll,data


#####################################################################
# TLSClientHello - ClientHello Handshake type
#####################################################################
class TLSClientHello(TLSHandshake):

	def __init__(self, HandshakeType, HandshakeLength, data):
		TLSHandshake.__init__(self, HandshakeType, HandshakeLength)
		data_length = len(data)
		offset = 0
		self.ja3_data = []

		# self.client_version
		if data_length >= offset+2:
			self.client_version = struct.unpack('!H', data[offset:offset+2])[0]
			self.ja3_data.append(self.client_version)
			offset += 2
		else:
			raise InsufficientData('%d bytes received by TLSClientHello, expected %d for client_version' % (data_length, offset + 2))

		# self.random
		if data_length >= offset+32:
			self.random = data[offset:offset+32]
			offset += 32
		else:
			raise InsufficientData('%d bytes received by TLSClientHello, expected %d for random block' % (data_length, offset + 32))

		# self.session_id_length
		if data_length >= offset+1:
			self.session_id_length = struct.unpack('!B', data[offset:offset+1])[0]
			offset += 1
		else:
			raise InsufficientData('%d bytes received by TLSClientHello, expected %d for session_id_length' % (data_length, offset + 1))

		# self.session_id
		if self.session_id_length > 0:
			if data_length >= offset+self.session_id_length:
				self.session_id = data[offset:offset+self.session_id_length]
				offset += self.session_id_length
			else:
				raise InsufficientData('%d bytes received by TLSClientHello, expected %d for session_id' % (data_length, offset + self.session_id_length))
		else:
			self.session_id = None

		# self.cipher_suites_length
		if data_length >= offset+2:
			self.cipher_suites_length = struct.unpack('!H', data[offset:offset+2])[0]
			offset += 2
		else:
			raise InsufficientData('%d bytes received by TLSClientHello, expected %d for cipher_suites_length' % (data_length, offset + 2))

		# self.cipher_suites (array, two bytes each)
		self.cipher_suites = []
		if self.cipher_suites_length > 0:
			self.ja3_data.append( ja3.ja3.convert_to_ja3_segment(data[offset:offset+self.cipher_suites_length], 2) )
			if data_length >= offset + self.cipher_suites_length:
				for j in range(0, self.cipher_suites_length, 2):
					self.cipher_suites.append(data[offset+j:offset+j+2])
				offset += self.cipher_suites_length
			else:
				raise InsufficientData('%d bytes received by TLSClientHello, expected %d for cipher_suites' % (data_length, offset + self.cipher_suites_length))

		# self.compression_methods_length
		if data_length >= offset+1:
			self.compression_methods_length = data[offset]
			offset += 1
		else:
			raise InsufficientData('%d bytes received by TLSClientHello, expected %d for compression_methods_length' % (data_length, offset + 1))

		# self.compression_methods (array, one bytes each)
		self.compression_methods = []
		if self.compression_methods_length > 0:
			if data_length >= offset + self.compression_methods_length:
				for j in range(0, self.compression_methods_length):
					self.compression_methods.append(data[offset+j])
				offset += self.compression_methods_length
			else:
				raise InsufficientData('%d bytes received by TLSClientHello, expected %d for compression_methods' % (data_length, offset + self.compression_methods_length))

		################################
		# Slice Off the Extensions
		################################
		self.ja3_data.extend(ja3.ja3.process_extensions(ja3.ja3.dpkt.ssl.TLSClientHello(data)))
		self.extensions = {}
		self.raw_extensions = []  # ordered list of tuples (ex_type, ex_data)
		# self.extensions_length
		if data_length >= offset+2:
			self.extensions_length = struct.unpack('!H', data[offset:offset+2])[0]
			offset += 2
		else:
			# No extensions
			return

		# Copy Extension Blob into a new working variable
		try:
			extensions_data = data[offset:offset+self.extensions_length]
		except:
			raise InsufficientData('%d bytes received by TLSClientHello, expected %d for extensions' % (data_length, offset + self.extensions_length))

		###########################
		# Iterate the Extensions
		###########################
		extension_server_name_list = []
		while len(extensions_data) >= 4:

			(ex_type, length) = struct.unpack('!HH', extensions_data[:4])
			if len(extensions_data) > length+4:
				this_extension_data = extensions_data[4:4+length]
				extensions_data = extensions_data[4+length:]
			else:
				this_extension_data = extensions_data[4:]
				extensions_data = ''

			self.raw_extensions.append((ex_type, this_extension_data))

			# server_name extension
			# this_extension_data is defined on page 8 of RFC 3546
			# It is essentially a list of hostnames
			if ex_type == 0:
				server_name_list_length = struct.unpack('!H', this_extension_data[:2])[0]
				if server_name_list_length > len(this_extension_data) - 2:
					raise Error("Malformed ServerNameList")
				server_name_list = this_extension_data[2:]
				# Iterate the list
				while len(server_name_list) > 0:
					(name_type, name_length) = struct.unpack('!BH', server_name_list[0:3])
					name_data = server_name_list[3:name_length + 3]
					if len(server_name_list) > name_length + 3:
						server_name_list = server_name_list[name_length + 3:]
					else:
						server_name_list = ''
					if name_type == 0:
						extension_server_name_list.append(name_data)
					else:
						raise UnsupportedOption("Unknown NameType")
		# After Loop
		# add extension information to dictionary
		self.extensions['server_name'] = extension_server_name_list

	def ja3(self):
		return ','.join([str(x) for x in self.ja3_data])

	def ja3_digest(self):
		h = hashlib.md5(self.ja3().encode('utf-8'))
		return h.hexdigest()


#####################################################################
# TLSServerHello - ServerHello Handshake type
#####################################################################
class TLSServerHello(TLSHandshake):

	def __init__(self, HandshakeType, HandshakeLength, data):
		TLSHandshake.__init__(self, HandshakeType, HandshakeLength)
		data_length = len(data)
		offset = 0

		# self.server_version
		if data_length >= offset+2:
			self.server_version = struct.unpack('!H', data[offset:offset+2])[0]
			offset += 2
		else:
			raise InsufficientData('%d bytes received by TLSServerHello, expected %d for server_version' % (data_length, offset + 2))

		# self.random
		if data_length >= offset+32:
			self.random = data[offset:offset+32]
			offset += 32
		else:
			raise InsufficientData('%d bytes received by TLSServerHello, expected %d for random block' % (data_length, offset + 32))

		# self.session_id_length
		if data_length >= offset+1:
			self.session_id_length = struct.unpack('!B', data[offset:offset+1])[0]
			offset += 1
		else:
			raise InsufficientData('%d bytes received by TLSServerHello, expected %d for session_id_length' % (data_length, offset + 1))

		# self.session_id
		if self.session_id_length > 0:
			if data_length >= offset+self.session_id_length:
				self.session_id = data[offset:offset+self.session_id_length]
				offset += self.session_id_length
			else:
				raise InsufficientData('%d bytes received by TLSServerHello, expected %d for session_id' % (data_length, offset + self.session_id_length))
		else:
			self.session_id = None

		# self.cipher_suite (single value, two bytes)
		if data_length >= offset + 2:
			self.cipher_suite = data[offset:offset+2]
			offset += 2
		else:
			self.cipher_suite = None
			raise InsufficientData('%d bytes received by TLSServerHello, expected %d for cipher_suite' % (data_length, offset + 2))

		# self.compression_method (single value, one byte)
		if data_length >= offset + 1:
			self.compression_method = data[offset]
			offset += 1
		else:
			raise InsufficientData('%d bytes received by TLSServerHello, expected %d for compression_method' % (data_length, offset + 1))



##############################################################################
# Some Utility Functions
##############################################################################
def keyTypeToString(kt):
	global keytypes
	if kt in keytypes:
		return keytypes[kt]
	else:
		try:
			return "UNKNOWN(%s)"%str(kt)
		except:
			return "UNKNOWN(%s)"%repr(kt)

def parse_x509_dtm(dtm):
	if type(dtm) == bytes:
		dtm = dtm.decode('utf-8')
	# Fmt: YYYYMMDDhhmmssZ
	t = time.strptime(dtm, '%Y%m%d%H%M%SZ')
	return time.strftime('%Y-%m-%d %H:%M:%S', t)

def render_x509_object(n):
	output = b''
	for component in n.get_components():
		output += b"%s=%s "%component
	return output.rstrip().decode('utf-8')

def openSSL_cert_to_info_dictionary(c):
	d = {'fingerprints':{}}
	for h in ('md5', 'sha1', 'sha256'):
		d['fingerprints'][h] = c.digest(h).decode('utf-8')
	
	d['subject'] = render_x509_object(c.get_subject())
	d['subject_cn'] = c.get_subject().CN
	d['issuer'] = render_x509_object(c.get_issuer())
	d['notAfter'] = parse_x509_dtm(c.get_notAfter())
	d['notBefore'] = parse_x509_dtm(c.get_notBefore())
	#
	# Look for subjectAltName
	#
	for i in range(0,c.get_extension_count()):
		ext = c.get_extension(i)
		if ext.get_short_name() == b'subjectAltName':
			d['subjectAltName'] = str(ext)
	public_key = c.get_pubkey()		
	d['pubkey_bits'] = public_key.bits()
	d['pubkey_type'] = keyTypeToString(public_key.type())
	d['pubkey_sha1'] = hashlib.sha1(OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, public_key)).hexdigest()
	return d


def split_subjectAltName_string(subjectAltName):
	l = []
	for an in subjectAltName.split(', '):
		if an.startswith('DNS:'):
			an = an[4:]
		l.append(an)
	return l

class DshellPlugin(dshell.core.ConnectionPlugin):

	def	__init__(self):
		super().__init__(
			name="tls",
			author="amm",
			description="Extract interesting metadata from TLS connection setup",
			bpf="tcp and (port 443 or port 993 or port 25 or port 587 or port 465 or port 5269 or port 995 or port 3389)",
			output=AlertOutput(label=__name__)
		)

	def	connection_handler(self, conn):

		inverted_ssl = False
		info = conn.info()
		client_names = set()  # Agregate list of names specified by client
		server_names = set()  # Agregate list of names specified by server
		certs_cs = []
		certs_sc = []

		for blob in conn.blobs:

			blob.reassemble(allow_overlap=True, allow_padding=True)
			data = blob.data
			offset = 0

			while offset < len(data):

				tlsrecord = None
				try:
					tlsrecord = TLS(data[offset:])
					offset += tlsrecord.recordbytes
					
					if tlsrecord.ContentType == SSL3_RT_HANDSHAKE:
						for hs in tlsrecord.Handshakes:
							#
							# Client hello.  Looking for inversion.
							#
							if hs.HandshakeType == SSL3_MT_CLIENT_HELLO:
								if blob.direction != 'cs':
									inverted_ssl = True
								if 'server_name' in hs.extensions:
									for server in hs.extensions['server_name']:
										client_names.add(server.decode('utf-8'))
								info['ja3'] = hs.ja3()
								info['ja3_digest'] = hs.ja3_digest()
								client_cipher_list = hs.cipher_suites

							elif hs.HandshakeType == SSL3_MT_SERVER_HELLO:
								server_cipher = hs.cipher_suite

							#
							# Certificate.  Looking for first server cert.
							#
							elif hs.HandshakeType == SSL3_MT_CERTIFICATE:
								for cert in hs.Certificates:
									cert_info = openSSL_cert_to_info_dictionary(cert)
									if blob.direction == 'cs':
										certs_cs.append(cert_info)
									else:
										certs_sc.append(cert_info)

				except InsufficientData:
					self.log('Skipping small blob: %s\n' % (sys.exc_info()[1]))
					offset += len(data)
				except UnsupportedOption:
					self.log('Unsupported type: %s\n' % (sys.exc_info()[1]))
					offset += len(data)
				except:
					offset += len(data)
					self.log('Unknown error in connectionHandler: %s' % sys.exc_info()[1])
					break

		# Post processing
		if inverted_ssl:
			info['inverted_ssl'] = True
			info['client_certs'] = certs_sc
			info['server_certs'] = certs_cs
		else:
			info['client_certs'] = certs_cs
			info['server_certs'] = certs_sc
		if len(info['client_certs']):
			client_names.add(info['client_certs'][0]['subject_cn'])
		if len(info['server_certs']):
			server_names.add(info['server_certs'][0]['subject_cn'])
			try:
				server_names.update(split_subjectAltName_string(info['server_certs'][0]['subjectAltName']))
			except KeyError:
				pass
		info['client_names'] = list(client_names)
		info['server_names'] = list(server_names)
		# Cipher Lists
		if server_cipher in client_cipher_list:
			cipher_index = client_cipher_list.index(server_cipher)
		else:
			cipher_index = None
		info['cipher_index'] = cipher_index
		try:
			info['cipher_text'] = ciphersuit_text[struct.unpack('!H',server_cipher)[0]]
		except:
			info['cipher_text'] = 'UNKNOWN'

		#
		# Determine output message
		#
		if len(client_names) + len(server_names) == 0:
			return
		client_name = ','.join(info['client_names'])
		server_name = ','.join(info['server_names'])
		if len(client_name) and client_name != server_name:
			msg = "%s / %s" % (client_name, server_name)
		else:
			msg = server_name
		self.write(msg, **info)

		


if __name__	== "__main__":
	print(DshellPlugin())
