#!/usr/bin/env python
## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

## Copyright (c) 2011 Jochen Bartl <jochen.bartl gmail com>

"""
LLDP (Link Layer Discovery Protocol)
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IP6Field

_LLDP_tlv_cls = {0: "LLDPDUEnd",
                 1: "LLDPChassisId",
                 2: "LLDPPortId",
                 3: "LLDPTTL",
                 4: "LLDPPortDescription",
                 5: "LLDPSystemName",
                 6: "LLDPSystemDescription",
                 7: "LLDPSystemCapabilities",
                 8: "LLDPManagementAddress",
                 127: "LLDPOrganizationalSpecific"}

_LLDP_tlv_types = {0: "End of LLDPDU",
                   1: "Chassis Id",
                   2: "Port Id",
                   3: "Time to Live",
                   4: "Port Description",
                   5: "System Name",
                   6: "System Description",
                   7: "System Capabilities",
                   8: "Management Address",
                   127: "Organization Specific"}


# (oui, subtype)
# 0x0080c2 - IEEE 802.1
# 0x00120f - IEEE 802.3
_LLDPOrgSpec_tlv_cls = {(0x0080c2, 0x01): "LLDPDot1PortVlanId",
                       }
class ByteField(Field):
  def __init__(self, name, default):
    Field.__init__(self, name, default, "B")
        
class SignedByteField(Field):
  def __init__(self, name, default):
    Field.__init__(self, name, default, "b")
  def randval(self):
    return RandSByte()

class XByteField(ByteField):
  def i2repr(self, pkt, x):
    return lhex(self.i2h(pkt, x))

class OByteField(ByteField):
  def i2repr(self, pkt, x):
    return "%03o"%self.i2h(pkt, x)

class ThreeBytesField(ByteField):
  def __init__(self, name, default):
    Field.__init__(self, name, default, "!I")
    self.sz = 3
  def addfield(self, pkt, s, val):
    return s+struct.pack(self.fmt, self.i2m(pkt,val))[1:4]
  def getfield(self, pkt, s):
    return  s[3:], self.m2i(pkt, struct.unpack(self.fmt, "\x00"+s[:3])[0])

class XThreeBytesField(ThreeBytesField,XByteField):
  def i2repr(self, pkt, x):
    return XByteField.i2repr(self, pkt, x)


def _LLDPGuessPacketClass(p=None, **kargs):
    if p is None:
        return LLDPGeneric(**kargs)
    cls = Raw
    if len(p) >= 2:
        try:
            t = struct.unpack("!B", p[0:1])[0]
        except Exception as e:
            print("ERROR")
            print(e)
        t = (0xfe & t) >> 1
        if t != 127:
            clsname = _LLDP_tlv_cls.get(t, "LLDPGeneric")
        else:
            oui = struct.unpack("!I", "\x00" + p[2:5])[0]
            subtype = struct.unpack("!B", p[5])[0]
            clsname = _LLDPOrgSpec_tlv_cls.get((oui, subtype), "LLDPOrgSpecGeneric")
        cls = globals()[clsname]

    return cls(p, **kargs)


class LLDPGeneric(Packet):
    name = "LLDP Generic TLV"
    fields_desc = [BitField("type", 1, 7),
                   BitFieldLenField("length", None, 9, length_of="value"),
                   StrLenField("value", "", length_from=lambda x: x.length)]

    def guess_payload_class(self, p):
        return Padding

    def post_build(self, p, pay):
        if self.length is None:
            l = len(p) - 2
            p = chr((self.type << 1) ^ (l >> 8)) + chr(l & 0xff) + p[2:]

        return p+pay


class LLDPOrgSpecGeneric(LLDPGeneric):
    name = "LLDP Org Spec Generic TLV"
    fields_desc = [BitField("type", 127, 7),
                   BitFieldLenField("length", None, 9, length_of="value"),
                   XThreeBytesField("oui", 0),
                   ByteField("subtype", 0), 
                   StrLenField("value", "", length_from=lambda x: x.length - 4)]


class LLDPDUEnd(LLDPGeneric):
    name = "End of LLDPDU"
    fields_desc = [BitField("type", 0, 7),
                   BitField("length", 0, 9)]


_LLDPChassisId_Subtypes = {0: "Reserved",
                           1: "Chassis component",
                           2: "Interface alias",
                           3: "Port component",
                           4: "MAC address",
                           5: "Network address",
                           6: "Interface name",
                           7: "Locally assigned"}


class LLDPChassisId(LLDPGeneric):
    name = "LLDP Chassis"
    fields_desc = [BitField("type", 1, 7),
                   BitField("length", None, 9),
                   ByteEnumField("subtype", 4, _LLDPChassisId_Subtypes),
                   ConditionalField(MACField("macaddr", "00:11:22:33:44:55"), lambda pkt: pkt.subtype == 4),
                   # TODO Subtype 5, IPv4 / IPv6
                   # Catch-all field for undefined subtypes
                   ConditionalField(StrLenField("value", "", length_from=lambda x: x.length - 1),
                                    lambda pkt: pkt.subtype not in [4])]


_LLDPPortId_Subtypes = {0: "Reserved",
                        1: "Interface alias",
                        2: "Port component",
                        3: "MAC address",
                        4: "Network address",
                        5: "Interface name",
                        6: "Agent circuit ID",
                        7: "Locally assigned"}


class LLDPPortId(LLDPGeneric):
    name = "LLDP PortId"
    fields_desc = [BitField("type", 2, 7),
                   BitField("length", None, 9),
                   ByteEnumField("subtype", 3, _LLDPPortId_Subtypes),
                   ConditionalField(MACField("macaddr", "00:11:22:33:44:55"), lambda pkt: pkt.subtype == 3),
                   # TODO Subtype 4, IPv4 / IPv6
                   # Catch-all field for undefined subtypes
                   ConditionalField(StrLenField("value", "", length_from=lambda x: x.length - 1),
                                    lambda pkt: pkt.subtype not in [3])]


class LLDPTTL(LLDPGeneric):
    name = "LLDP TTL"
    fields_desc = [BitField("type", 3, 7),
                   BitField("length", None, 9),
                   ShortField("seconds", 120)]


class LLDPPortDescription(LLDPGeneric):
    name = "LLDP Port Description"
    type = 4
    value = "FastEthernet0/1"


class LLDPSystemName(LLDPGeneric):
    name = "LLDP System Name"
    type = 5
    value = "Scapy"


class LLDPSystemDescription(LLDPGeneric):
    name = "LLDP System Description"
    type = 6
    value = "Scapy"


_LLDPSystemCapabilities = ["other", "repeater", "bridge", "wlanap", "router", "telephone", "docsiscable", "stationonly"]


class LLDPSystemCapabilities(LLDPGeneric):
    name = "LLDP System Capabilities"
    fields_desc = [BitField("type", 7, 7),
                   BitField("length", None, 9),
                   # Available capabilities
                   FlagsField("capabilities", 0, 16, _LLDPSystemCapabilities),
                   # Enabled capabilities
                   FlagsField("enabled", 0, 16, _LLDPSystemCapabilities)]


_LLDPManagementAddress_Subtype = {1: "IPv4",
                                  2: "IPv6",
                                  6: "802"
                                 }

_LLDPManagementAddress_IfSubtype = {1: "Unknown",
                                    2: "ifIndex",
                                    3: "System Port Number"
                                   }


class LLDPManagementAddress(LLDPGeneric):
    name = "LLDP Management Address"
    fields_desc = [BitField("type", 8, 7),
                   BitField("length", None, 9),
                   ByteField("addrlen", None),
                   ByteEnumField("addrsubtype", 1, _LLDPManagementAddress_Subtype),
                   ConditionalField(IPField("ipaddr", "192.168.0.1"), lambda pkt: pkt.addrsubtype == 1),
                   ConditionalField(IP6Field("ip6addr", "2001:db8::1"), lambda pkt: pkt.addrsubtype == 2),
                   ConditionalField(MACField("macaddr", "00:11:22:33:44:55"), lambda pkt: pkt.addrsubtype == 6),
                   ConditionalField(StrLenField("addrval", "", length_from=lambda x: x.addrlen - 1),
                                    lambda pkt: pkt.addrsubtype not in [1, 2, 6]),
                   ByteEnumField("ifsubtype", 2, _LLDPManagementAddress_IfSubtype),
                   IntField("ifnumber", 0),
                   FieldLenField("oidlen", None, length_of="oid", fmt="B"),
                   StrLenField("oid", "", length_from=lambda x: x.oidlen)]

    def post_build(self, p, pay):
        # TODO Remove redundant code. LLDPGeneric.post_build()
        if self.length is None:
            l = len(p) - 2
            p = chr((self.type << 1) ^ (l >> 8)) + chr(l & 0xff) + p[2:]

        if self.addrlen is None:
            addrlen = len(p) - 2 - 8 - len(self.oid) + 1
            p = p[:2] + struct.pack("B", addrlen) + p[3:]

        return p+pay


_LLDPDot1Subtype = {1: "Port VLAN Id"}


class LLDPDot1PortVlanId(LLDPOrgSpecGeneric):
    name = "LLDP IEEE 802.1 Port VLAN Id"
    fields_desc = [BitField("type", 127, 7),
                   BitField("length", None, 9),
                   # TODO: XThreeBytesEnumField
                   XThreeBytesField("oui", 0x0080c2),
                   ByteEnumField("subtype", 0x01, _LLDPDot1Subtype),
                   ShortField("vlan", 1)]


class LLDP(Packet):
    name ="LLDP"
    fields_desc = [PacketListField("tlvlist", [], _LLDPGuessPacketClass)]


bind_layers(Ether, LLDP, type=0x88cc)

