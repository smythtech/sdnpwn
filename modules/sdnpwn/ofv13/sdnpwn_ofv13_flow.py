

from pyof.v0x01.controller2switch.common import FlowStats
from pyof.v0x04.common.flow_instructions import *
from pyof.v0x04.common.flow_match import OxmOfbMatchField, Match, MatchType
from pyof.v0x04.controller2switch.group_mod import Group
from pyof.v0x04.common.action import ActionType as ActionType
from pyof.v0x04.common.action import ActionHeader as ActionHeader
from pyof.v0x04.common.port import PortConfig, PortState, Port, PortNo
from pyof.v0x04.common.flow_instructions import ListOfInstruction

from random import randint
import socket
from struct import pack, unpack

'''

Classes that define Openflow Flows

'''

# Openflow 1.3 Flow
class Flow():
  match = None
  cookie = None
  command = None
  idle_timeout = None
  hard_timeout = None
  priority = None
  buffer_id = None
  out_port = None
  out_group = None
  flags = None
  instructions = None
  actions = None

  length = None
  duration_sec = None
  duration_nsec = None
  packet_count = None
  byte_count = None

  table_id = None


  def __init__(self, match=None, cookie=0,
                 idle_timeout=0, hard_timeout=0, priority=0,
                 buffer_id=0, out_port=PortNo.OFPP_MAX,
                 out_group=Group.OFPG_ANY, flags=0, instructions=None
               ):
    self.match = match
    self.cookie = cookie
    self.idle_timeout = idle_timeout
    self.hard_timeout = hard_timeout
    self.priority = priority
    self.buffer_id = buffer_id
    self.out_port = out_port
    self.flags = flags
    self.instructions = ListOfInstruction() if instructions is None else instructions

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
    return ("{\"cookie\": " + (str(self.cookie) if self.cookie != 0 else "*") + ", "
            "\"idle_timeout\": " + str(self.idle_timeout) + ", "
            "\"hard_timeout\": " + str(self.hard_timeout) + ", "
            "\"priority\": " + str(self.priority) + ", "
            "\"buffer_id\": " + str(self.buffer_id) + ", "
            "\"out_port\": \"" + self.portToString(self.out_port) + "\", "
            "\"flags\": " + str(self.flags) + ", "
            "\"instructions\": " + self.instructionsToString(self.instructions) + ", "
            "\"match_type\": " + self.matchTypeToString(self.match) + ", "
            "\"match\": " + self.matchToStringWrapper(self.match) + "}"
           )

  def portToString(self, port_no):
    try:
      port = {
             '0xffffff00': "OFPP_MAX",
             '0xfffffff8': "OFPP_IN_PORT",
             '0xfffffff9': "OFPP_TABLE",
             '0xfffffffa': "OFPP_NORMAL",
             '0xfffffffb': "OFPP_FLOOD",
             '0xfffffffc': "OFPP_ALL",
             '0xfffffffd': "OFPP_CONTROLLER",
             '0xfffffffe': "OFPP_LOCAL",
             '0xffffffff': "OFPP_ANY"
      }[str(hex(int(port_no)))]
    except:
      return str(port_no)
    return port


  def matchTypeToString(self, match):
    return {
             MatchType.OFPMT_STANDARD: "\"Standard\"",
             MatchType.OFPMT_OXM: "\"OpenFlow Extensible Match\""
           }[int(match.match_type)]

  def matchToStringWrapper(self, match):
    if(self.matchTypeToString(self.match) == "Standard"):
      return "\"Unsupported for this OF version\""
    match_instances = match.oxm_match_fields
    matches = "{"
    for m in match_instances:
      match_str = self.matchToString(m)
      matches += match_str
      matches += ","
    matches = matches[:-1] + "}"
    return matches

  def instructionsToString(self, instructions):
    instrs = "["
    for instr in instructions:
      instr_type = self.instructionTypeToString(instr)
      instr_detail = self.instructionDetailToString(instr.instruction_type, instr)
      instrs += "{\"Type\": " + str(instr_type) + ", \"Instruction\": " + instr_detail + "},"
    instrs = instrs[:-1] + "]"
    return instrs

  def instructionTypeToString(self, instructions):
    return {
             InstructionType.OFPIT_GOTO_TABLE: "\"GOTO Table\"",
             InstructionType.OFPIT_WRITE_METADATA: "\"Write Metadata\"",
             InstructionType.OFPIT_WRITE_ACTIONS: "\"Write Actions\"",
             InstructionType.OFPIT_APPLY_ACTIONS: "\"Apply Actions\"",
             InstructionType.OFPIT_CLEAR_ACTIONS: "\"Clear Actions\"",
             InstructionType.OFPIT_METER: "\"Apply Meter\"",
             InstructionType.OFPIT_EXPERIMENTER: "\"Experimenter\"",
           }[int(instructions.instruction_type)]

  def instructionDetailToString(self, type, instruction):
    instr_detail = {
             InstructionType.OFPIT_GOTO_TABLE: (lambda instr: ("{\"GOTO Table\": \"" + str(instr.table_id) + "\"}")),
             InstructionType.OFPIT_WRITE_METADATA: (lambda instr: ("{\"Metadata\": \"" + str(instr.metadata) + ", \"Metadata Mask\": " + str(instr.metadata_mask) + "\"}")),
             InstructionType.OFPIT_WRITE_ACTIONS: (lambda instr: ("{\"Actions\": " + self.actionsToString(instr.actions) + "}")),
             InstructionType.OFPIT_APPLY_ACTIONS: (lambda instr: ("{\"Actions\": " + self.actionsToString(instr.actions) + "}")),
             InstructionType.OFPIT_CLEAR_ACTIONS: (lambda instr: ("{\"Actions\": " + self.actionsToString(instr.actions) + "}")),
             InstructionType.OFPIT_METER: (lambda instr: ("{\"Meter\": \"" + str(instr.meter_id) + "\"}")),
             InstructionType.OFPIT_EXPERIMENTER: "{\"Experimenter\": \"none\"}",
            }[int(type)](instruction)

    return instr_detail

  def actionsToString(self, actions):
    actionHeaders = ""
    if(isinstance(actions, list)):
      for a in actions:
        actionHeaders += (self.getActionHeaderDetails(a))(a)  + ","
    else:
      actionHeaders += (self.getActionHeaderDetails(actions))(actions)

    return "{" + actionHeaders[:-1] + "}"

  def getActionHeaderDetails(self, action):
    return {
             ActionType.OFPAT_OUTPUT: (lambda action: ("\"OFPAT_OUTPUT\": \"" + self.portToString(action.port) + ", Max Length " + str(action.max_length) + "\"")),
             ActionType.OFPAT_COPY_TTL_OUT: (lambda action: ("\"OFPAT_COPY_TTL_OUT\"")),
             ActionType.OFPAT_COPY_TTL_IN: (lambda action: ("\"OFPAT_COPY_TTL_IN\"")),
             ActionType.OFPAT_SET_MPLS_TTL: (lambda action: ("\"OFPAT_SET_MPLS_TTL\": \"" + str(action.mpls_ttl) + "\"")),
             ActionType.OFPAT_DEC_MPLS_TTL: (lambda action: ("\"OFPAT_DEC_MPLS_TTL\"")),
             ActionType.OFPAT_PUSH_VLAN: (lambda action: ("\"OFPAT_PUSH_VLAN\": \"Ethertype " + str(action.ethertype) + "\"")),
             ActionType.OFPAT_POP_VLAN: (lambda action: ("\"OFPAT_POP_VLAN\"")),
             ActionType.OFPAT_PUSH_MPLS: (lambda action: ("\"OFPAT_PUSH_MPLS\": \"Ethertype " + str(action.ethertype) + "\"")),
             ActionType.OFPAT_POP_MPLS: (lambda action: ("\"OFPAT_POP_MPLS\"")),
             ActionType.OFPAT_SET_QUEUE: (lambda action: ("\"OFPAT_SET_QUEUE\": \"Queue ID " + str(action.queue_id) + "\"")),
             ActionType.OFPAT_GROUP: (lambda action: ("\"OFPAT_GROUP\": \"Group ID " + str(action.group_id) + "\"")),
             ActionType.OFPAT_SET_NW_TTL: (lambda action: ("\"OFPAT_SET_NW_TTL\": \"TTL " + str(action.nw_ttl) + "\"")),
             ActionType.OFPAT_DEC_NW_TTL: (lambda action: ("\"OFPAT_DEC_NW_TTL\"")),
             ActionType.OFPAT_SET_FIELD: (lambda action: ("\"OFPAT_SET_FIELD\": \"Field " + str(action.field) + "\"")),
             ActionType.OFPAT_PUSH_PBB: (lambda action: ("\"OFPAT_PUSH_PBB\": \"Ethertype " + str(action.ethertype) + "\"")),
             ActionType.OFPAT_POP_PBB: (lambda action: ("\"OFPAT_POP_PBB\"")),
             ActionType.OFPAT_EXPERIMENTER: (lambda action: ("\"OFPAT_EXPERIMENTER\": \"Experimenter " + str(action.experimenter) + "\"")),
           }[int(action.action_type)]


  def matchToString(self, matchTLV):
    return {
             OxmOfbMatchField.OFPXMT_OFB_IN_PORT: "\"OFPXMT_OFB_IN_PORT\": \"Port " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IN_PHY_PORT: "\"OFPXMT_OFB_IN_PHY_PORT\": \"Phy Port " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_METADATA: "\"OFPXMT_OFB_METADATA\": \"Metadata " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ETH_DST: "\"OFPXMT_OFB_ETH_DST\": \"ETH dst " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ETH_SRC: "\"OFPXMT_OFB_ETH_SRC\": \"ETH src " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE: "\"OFPXMT_OFB_ETH_TYPE\": \"ETH type " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_VLAN_VID: "\"OFPXMT_OFB_VLAN_VID\": \"VLAN Id " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_VLAN_PCP: "\"OFPXMT_OFB_VLAN_PCP\": \"VLAN PCP " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IP_DSCP: "\"OFPXMT_OFB_IP_DSCP\": \"IP DSCP " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IP_ECN: "\"OFPXMT_OFB_IP_ECN\": \"IP ECN " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IP_PROTO: "\"OFPXMT_OFB_IP_PROTO\": \"IP Proto " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IPV4_SRC: "\"OFPXMT_OFB_IPV4_SRC\": \"IP src " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IPV4_DST: "\"OFPXMT_OFB_IPV4_DST\": \"IP dst " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_TCP_SRC: "\"OFPXMT_OFB_TCP_SRC\": \"TCP src " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_TCP_DST: "\"OFPXMT_OFB_TCP_DST\": \"TCP dst " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_UDP_SRC: "\"OFPXMT_OFB_UDP_SRC\": \"UDP src " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_UDP_DST: "\"OFPXMT_OFB_UDP_DST\": \"UDP dst " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_SCTP_SRC: "\"OFPXMT_OFB_SCTP_SRC\": \"SCTP src " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_SCTP_DST: "\"OFPXMT_OFB_SCTP_DST\": \"SCTP dst " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ICMPV4_TYPE: "\"OFPXMT_OFB_ICMPV4_TYPE\": \"ICMPv4 Type " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ICMPV4_CODE: "\"OFPXMT_OFB_ICMPV4_CODE\": \"ICMPv4 Code " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ARP_OP: "\"OFPXMT_OFB_ARP_OP\": \"ARP OP Code " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ARP_SPA: "\"OFPXMT_OFB_ARP_SPA\": \"ARP Src IP " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ARP_TPA: "\"OFPXMT_OFB_ARP_TPA\": \"ARP Target IP " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ARP_SHA: "\"OFPXMT_OFB_ARP_SHA\": \"ARP Src MAC " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ARP_THA: "\"OFPXMT_OFB_ARP_THA\": \"ARP Target MAC " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IPV6_SRC: "\"OFPXMT_OFB_IPV6_SRC\": \"IPv6 src " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IPV6_DST: "\"OFPXMT_OFB_IPV6_DST\": \"IPv6 dst " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IPV6_FLABEL: "\"OFPXMT_OFB_IPV6_FLABEL\": \"IPv6 FLABEL " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ICMPV6_TYPE: "\"OFPXMT_OFB_ICMPV6_TYPE\": \"ICMPv6 Type " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ICMPV6_CODE: "\"OFPXMT_OFB_ICMPV6_CODE\": \"ICMPv6 Code " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IPV6_ND_TARGET: "\"OFPXMT_OFB_IPV6_ND_TARGET\": \"IPv6 ND Target " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IPV6_ND_SLL: "\"OFPXMT_OFB_IPV6_ND_SLL\": \"IPv6 ND SLL " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IPV6_ND_TLL: "\"OFPXMT_OFB_IPV6_ND_TLL\": \"IPv6 ND TLL " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_MPLS_LABEL: "\"OFPXMT_OFB_MPLS_LABEL\": \"MPLS Label " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_MPLS_TC: "\"OFPXMT_OFB_MPLS_TC\": \"MPLS TC " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFP_MPLS_BOS: "\"OFPXMT_OFP_MPLS_BOS\": \"MPLS BOS " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_PBB_ISID: "\"OFPXMT_OFB_PBB_ISID\": \"PBB ISID " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_TUNNEL_ID: "\"OFPXMT_OFB_TUNNEL_ID\": \"Tunnel ID " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_IPV6_EXTHDR: "\"OFPXMT_OFB_IPV6_EXTHDR\": \"IPv6 EXTHDR " + self.cleanBytes(str(matchTLV.oxm_value)) + "\"",
             OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE: "\"OFPXMT_OFB_ETH_TYPE\": \"Ethertype " + self.cleanBytes(str(matchTLV.oxm_value)) + "\""
           }[matchTLV.oxm_field]

  def cleanBytes(self, s):
    # Will figure out the proper decoding method for the value later.
    if("\\x" in s):
      s = "0x" + s
    s = s.replace("b", "")
    s = s.replace("'", "")
    s = s.replace("\\x", "")
    return s


'''
  def matchToString(self, match):
    return ("[ " +
           "in_port: " + (str(match.OFPXMT_OFB_IN_PORT) if match.OFPXMT_OFB_IN_PORT != 0 else "*") + ", " +
           "dl_src: " + (str(match.dl_src) if match.dl_src != "00:00:00:00:00:00" else "*") + ", " +
           "dl_dst: " + (str(match.dl_dst) if match.dl_dst != "00:00:00:00:00:00" else "*") + ", " +
           "dl_vlan: " + (str(match.dl_vlan) if match.dl_vlan != 0 else "*") + ", " +
           "dl_vlan_pcp: " + (str(match.dl_vlan_pcp) if match.dl_vlan_pcp != 0 else "*") + ", " +
           "dl_type: " + ("0x" + str(match.dl_type.pack())[2:-1].replace("\\x", "") if match.dl_type != 0 else "*") + ", " +
           "nw_tos: " + ("0x" + str(match.dl_type.pack())[2:-1].replace("\\x", "") if match.dl_type != 0 else "*") + ", " +
           "nw_proto: " + ("0x" + str(match.nw_proto.pack())[2:-1].replace("\\x", "") if match.nw_proto != 0 else "*") + ", " +
           "nw_src: " + (str(match.nw_src) + "/" + str(match.nw_src.max_prefix) if match.nw_src != "0.0.0.0" else "*") + ", " +
           "nw_dst: " + (str(match.nw_dst) + "/" + str(match.nw_dst.max_prefix) if match.nw_dst != "0.0.0.0" else "*") + ", " +
           "tp_src: " + (str(match.tp_src) if match.tp_src != 0 else "*") + ", " +
           "tp_dst: " + (str(match.tp_dst) if match.tp_dst != 0 else "*") + "" +
           "]")
'''
