

from pyof.v0x01.controller2switch.common import FlowStats
from pyof.v0x01.common.action import ActionType as ActionType
from pyof.v0x01.common.action import ActionHeader as ActionHeader
from pyof.v0x01.common.phy_port import PhyPort, PortConfig, PortState, Port

from random import randint
import socket
from struct import pack, unpack

'''

Classes that define Openflow Flows

'''

# Openflow 1.0 Flow
class Flow():
  match = None
  cookie = None
  command = None
  idle_timeout = None
  hard_timeout = None
  priority = None
  buffer_id = None
  out_port = None
  flags = None
  actions = None

  length = None
  duration_sec = None
  duration_nsec = None
  packet_count = None
  byte_count = None

  table_id = None


  def __init__(self, match=None, cookie=0,
                 idle_timeout=0, hard_timeout=0, priority=0,
                 buffer_id=0, out_port=Port.OFPP_NONE,
                 flags=0, actions=None
               ):
    self.match = match
    self.cookie = cookie
    self.idle_timeout = idle_timeout
    self.hard_timeout = hard_timeout
    self.priority = priority
    self.buffer_id = buffer_id
    self.out_port = out_port
    self.flags = flags
    self.actions = [] if actions is None else actions

    self.length = 0
    self.duration_sec = 0
    self.duration_nsec = 0
    self.packet_count = 0
    self.byte_count = 0

    self.table_id = 1

  def getFlowStats(self):
    stats = FlowStats(self.length, self.table_id, self.match,
                      self.duration_sec, self.duration_nsec, self.priority,
                      self.idle_timeout, self.hard_timeout, self.cookie,
                      self.packet_count, self.byte_count, self.actions)

    return stats

  def toString(self):
    return ("{\"cookie\": \"" + (str(self.cookie) if self.cookie != 0 else "*") + "\", "
            "\"idle_timeout\": \"" + str(self.idle_timeout) + "\", "
            "\"hard_timeout\": \"" + str(self.hard_timeout) + "\", "
            "\"priority\": \"" + str(self.priority) + "\", "
            "\"buffer_id\": \"" + str(self.buffer_id) + "\", "
            "\"out_port\": \"" + self.portToString(self.out_port) + "\", "
            "\"flags\": \"" + str(self.flags) + "\", "
            "\"actions\": {" + self.actionsToString(self.actions) + "}, "
            "\"match\": {" + self.matchToString(self.match) + "}"
            "}"
           )

  def portToString(self, port_no):
    try:
      port = {
             '0xff00': "OFPP_MAX",
             '0xfff8': "OFPP_IN_PORT",
             '0xfff9': "OFPP_TABLE",
             '0xfffa': "OFPP_NORMAL",
             '0xfffb': "OFPP_FLOOD",
             '0xfffc': "OFPP_ALL",
             '0xfffd': "OFPP_CONTROLLER",
             '0xfffe': "OFPP_LOCAL",
             '0xffff': "OFPP_NONE"
      }[str(hex(int(port_no)))]
    except:
      return str(port_no)
    return port

  def actionsToString(self, actions):
    actionHeaders = ""
    if(isinstance(actions, list)):
      for a in actions:
        actionHeaders += (self.getActionHeaderDetails(a))(a)  + ","
    else:
      actionHeaders += (self.getActionHeaderDetails(actions))(actions)
      actionHeaders += ","

    return "" + actionHeaders[:-1] + ""

  def getActionHeaderDetails(self, action):
    return {
             ActionType.OFPAT_OUTPUT: (lambda action: ("\"OFPAT_OUTPUT\": \"" + self.portToString(action.port) + "\"")),
             ActionType.OFPAT_SET_VLAN_VID: (lambda action: ("\"OFPAT_SET_VLAN_VID\": \"Vlan ID " + str(action.vlan_id) + "\"")),
             ActionType.OFPAT_SET_VLAN_PCP: (lambda action: ("\"OFPAT_SET_VLAN_PCP\": \"Vlan PCP" + str(action.vlan_pcp) + "\"")),
             ActionType.OFPAT_STRIP_VLAN: (lambda action: ("\"OFPAT_STRIP_VLAN\": \"" + str(action.port) + "\"")),
             ActionType.OFPAT_SET_DL_SRC: (lambda action: ("\"OFPAT_SET_DL_SRC\": \"MAC " + str(action.dl_addr) + "\"")),
             ActionType.OFPAT_SET_DL_DST: (lambda action: ("\"OFPAT_SET_DL_DST\": \"MAC " + str(action.dl_addr) + "\"")),
             ActionType.OFPAT_SET_NW_SRC: (lambda action: ("\"OFPAT_SET_NW_SRC\": \"IP " + str(action.nw_addr) + "\"")),
             ActionType.OFPAT_SET_NW_DST: (lambda action: ("\"OFPAT_SET_NW_DST\": \"IP " + str(action.nw_addr) + "\"")),
             ActionType.OFPAT_SET_NW_TOS: (lambda action: ("\"OFPAT_SET_NW_TOS\": \"Service " + str(action.nw_tos) + "\"")),
             ActionType.OFPAT_SET_TP_SRC: (lambda action: ("\"OFPAT_SET_TP_SRC\": \"Layer 4 Port " + str(action.tp_port) + "\"")),
             ActionType.OFPAT_SET_TP_DST: (lambda action: ("\"OFPAT_SET_TP_DST\": \"Layer 4 Port " + str(action.tp_port) + "\"")),
             ActionType.OFPAT_ENQUEUE: (lambda action: ("\"OFPAT_ENQUEUE\": \"Port " + self.portToString(action.port) + ", Queue ID " + str(action.queue_id) + "\"")),
             ActionType.OFPAT_VENDOR: (lambda action: ("\"OFPAT_VENDOR\": \"Vendor action " + str(action.vendor) + "\"")),
           }[int(str(action.action_type))]

  def matchToString(self, match):
    return ("" +
           "\"in_port\": \"" + (str(match.in_port) if match.in_port != 0 else "*") + "\", " +
           "\"dl_src\": \"" + (str(match.dl_src) if match.dl_src != "00:00:00:00:00:00" else "*") + "\", " +
           "\"dl_dst\": \"" + (str(match.dl_dst) if match.dl_dst != "00:00:00:00:00:00" else "*") + "\", " +
           "\"dl_vlan\": \"" + (str(match.dl_vlan) if match.dl_vlan != 0 else "*") + "\", " +
           "\"dl_vlan_pcp\": \"" + (str(match.dl_vlan_pcp) if match.dl_vlan_pcp != 0 else "*") + "\", " +
           "\"dl_type\": \"" + ("0x" + str(match.dl_type.pack())[2:-1].replace("\\x", "") if match.dl_type != 0 else "*") + "\", " +
           "\"nw_tos\": \"" + ("0x" + str(match.dl_type.pack())[2:-1].replace("\\x", "") if match.dl_type != 0 else "*") + "\", " +
           "\"nw_proto\": \"" + ("0x" + str(match.nw_proto.pack())[2:-1].replace("\\x", "") if match.nw_proto != 0 else "*") + "\", " +
           "\"nw_src\": \"" + (str(match.nw_src) + "/" + str(match.nw_src.max_prefix) if match.nw_src != "0.0.0.0" else "*") + "\", " +
           "\"nw_dst\": \"" + (str(match.nw_dst) + "/" + str(match.nw_dst.max_prefix) if match.nw_dst != "0.0.0.0" else "*") + "\", " +
           "\"tp_src\": \"" + (str(match.tp_src) if match.tp_src != 0 else "*") + "\", " +
           "\"tp_dst\": \"" + (str(match.tp_dst) if match.tp_dst != 0 else "*") + "\"" +
           "")
