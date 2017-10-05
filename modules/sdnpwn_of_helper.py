#!/usr/bin/python3

import modules.sdnpwn_common as sdnpwn

from scapy.all import *

from pyof.foundation.basic_types import DPID, UBInt8, UBInt16, UBInt32, UBInt64, Pad, HWAddress

#v0x01 is openflow version
from pyof.v0x01.symmetric.hello import Hello
from pyof.v0x01.controller2switch.features_reply import FeaturesReply
from pyof.v0x01.controller2switch.barrier_reply import BarrierReply
from pyof.v0x01.controller2switch.packet_out import PacketOut
from pyof.v0x01.controller2switch.flow_mod import *
from pyof.v0x01.controller2switch.common import *
from pyof.v0x01.symmetric.echo_reply import EchoReply
from pyof.v0x01.symmetric.vendor_header import VendorHeader
from pyof.v0x01.controller2switch.stats_request import StatsRequest
from pyof.v0x01.controller2switch.stats_reply import StatsReply
from pyof.v0x01.controller2switch.get_config_reply import GetConfigReply
from pyof.v0x01.common.phy_port import PhyPort, PortConfig, PortState, Port
from pyof.v0x01.common.header import Header, Type
from pyof.v0x01.common.flow_match import *
from pyof.v0x01.common.action import ActionType, ActionHeader
from pyof.foundation.base import GenericMessage

from random import randint
import socket
from struct import pack, unpack

from modules.sdnpwn_lldp import *

class OpenFlowSwitch():
  switch_config = None
  switch_vendor_id = None
  switch_desc = None
  switch_features = None
  switch_ports = None
  switch_vendor_ouid = None
  comm_sock = None
  autohandleMessages = True
  switch_stats = None
  switch_flows = None
  enable_output = None
  forward_packet_out_payload = None
  forward_packet_out_iface = None
  forward_packet_out_port_filter = None
  
  def __init__(self):
    self.switch_config = {}
    self.switch_vendor_id = 0
    self.switch_vendor_ouid = "5C:16:C7:" #Big switch networks
    self.switch_desc = {}
    self.switch_features = {}
    self.switch_ports = []
    self.switch_stats = {}
    self.switch_flows = {}
    
    self.comm_sock = None
    self.auto_handle_Messages = True
    self.enable_output = False
    self.forward_packet_out_payload = False
    self.forward_packet_out_iface = None
    self.forward_packet_out_port_filter = None
    
    self.__initDefaults__()

  def __initDefaults__(self):
    '''
      Called on initialisation. Will set default values for statistics.
    '''
    self.switch_stats["aggregate"] = {}
    self.switch_stats["aggregate"]["packet_count"] = 0
    self.switch_stats["aggregate"]["byte_count"] = 0
    self.switch_stats["aggregate"]["flow_count"] = 0
    
    self.switch_stats["port"] = {}
    
    self.switch_stats["flow"] = {}
    
    self.switch_stats["queue"] = {}
    
  def setVendorID(self, vid):
    self.switch_vendor_id = vid
    
  def setVendorOUID(self, ouid):
    self.switch_vendor_ouid = ouid
    
  def setDescription(self, mfr_desc="", hw_desc="", sw_desc="", serial_num="", dp_desc=""):
    self.switch_desc["switch_mfr_desc"] = mfr_desc
    self.switch_desc["switch_hw_desc"] = hw_desc
    self.switch_desc["switch_sw_desc"] = sw_desc
    self.switch_desc["switch_serial_num"] = serial_num
    self.switch_desc["switch_dp_desc"] = dp_desc

  def setConfig(self, flags="", miss_send_len=""):
    self.switch_config["flags"] = flags
    self.switch_config["miss_send_len"] = miss_send_len
  
  def setFeatures(self, dpid="", no_of_buffers=1, no_of_tables=1, capabilities=0x00000000, actions=0, ports=[]):
    self.switch_features["dpid"] = dpid
    self.switch_features["no_of_buffers"] = no_of_buffers
    self.switch_features["no_of_tables"] = no_of_tables
    self.switch_features["capabilities"] = capabilities
    self.switch_features["actions"] = actions
    self.switch_features["ports"] = ports
    
  def loadConfiguration(self, config):
    self.switch_vendor_id = config["vendor_id"]
    self.switch_desc["switch_mfr_desc"] = config["description"]["manufacturer_description"]
    self.switch_desc["switch_hw_desc"] = config["description"]["hardware_description"]
    self.switch_desc["switch_sw_desc"] = config["description"]["software_description"]
    self.switch_desc["switch_serial_num"] = config["description"]["serial_number"]
    self.switch_desc["switch_dp_desc"] = config["description"]["dataplane_description"]
    self.switch_features["dpid"] = config["features"]["dataplane_id"]
    self.switch_features["no_of_buffers"] = config["features"]["number_of_buffers"]
    self.switch_features["no_of_tables"] = config["features"]["number_of_tables"]
    self.switch_features["capabilities"] = config["features"]["capabilities"]
    self.switch_features["actions"] = config["features"]["actions"]
    self.switch_features["ports"] = []
    if(isinstance(config["ports"], list)):
      for port in config["ports"]:
        self.addPort(port["port_no"], port["hardware_address"], port["port_name"], port["port_config"], port["port_state"], port["port_curr"], port["port_advertised"], port["port_supported"], port["port_peer"]) #Need to add config options here
    elif(isinstance(config["ports"], int)):
      for i in range(config["ports"]):
        self.addPort()
    else:
      sdnpwn.message("Could not load port config. Switch will have no ports.", sdnpwn.WARNING)

    self.switch_stats["flow"] = config["stats"]["flow_stats"] 
    #print(self.switch_stats["flow"])
    
  def addPort(self, port_no=0, hw_addr="", port_name="", port_config=0, port_state=PortState.OFPPS_STP_LISTEN, port_curr=0, port_advertised=0, port_supported=0, port_peer=0):
    if(port_no == 0):
      port_no = randint(30000,65534)
    if(hw_addr == ""):
      hw_addr = sdnpwn.generateRandomMacAddress(self.switch_vendor_ouid)
    if(port_name == ""):
      port_name = "OF Port " + str(randint(1,10000))
    
    initQueueID = randint(30000,65534)
                      
    port = PhyPort(port_no=port_no,
                   hw_addr=HWAddress(hw_addr),
                   name=port_name,
                   #config=PortConfig.OFPC_PORT_DOWN,
                   #state=PortState.OFPPS_LINK_DOWN,
                   config=port_config,
                   state=port_state,
                   curr=port_curr,
                   advertised=port_advertised,
                   supported=port_supported,
                   peer=port_peer)
    self.switch_ports.append(port)
    self.switch_features["ports"] = self.switch_ports
    self.switch_stats["port"][str(port_no)] = PortStats(port_no=port_no, rx_packets=0, tx_packets=0, rx_bytes=0, tx_bytes=0,
                                                     rx_dropped=0, tx_dropped=0, rx_errors=0, tx_errors=0, rx_frame_err=0, 
                                                     rx_over_err=0, rx_crc_err=0, collisions=0)
    
    self.switch_stats["queue"][str(port_no) + ":" + str(initQueueID)] = QueueStats(port_no=port_no, queue_id=initQueueID, tx_bytes=0, tx_packets=0, tx_errors=0)
    
  def connect(self, controllerIP, port):
    try:
      self.comm_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.comm_sock.connect((controllerIP, port))
    except Exception as e: 
      sdnpwn.message("Problem connecting to " + controllerIP + ":" + str(port), sdnpwn.ERROR)
      print
      return
      
    sdnpwn.message("Socket connected. Sending OF Hello...", sdnpwn.SUCCESS)
    ofHello = Hello(xid=0)
    header = Header()
    self.comm_sock.send(ofHello.pack()) #Send Hello
    replyHeader = self.comm_sock.recv(8)
    
    #Get hello response header & body 
    header.unpack(replyHeader)
    sdnpwn.message("Got " + str(header.message_type), sdnpwn.NORMAL)
    #sdnpwn.message("Controller base OF version: " + str(header.version), sdnpwn.VERBOSE)
    replyBody = self.comm_sock.recv(header.length-8) #Get body but ignore
    
    sdnpwn.message("Connected to controller", sdnpwn.SUCCESS)
    
    if(self.auto_handle_Messages == True):
      run = True
      sdnpwn.message("Handling OpenFlow messages automatically", sdnpwn.NORMAL)
      while(run):
        #try:
        #Get feature request
        reply = self.comm_sock.recv(8)
        header.unpack(reply)
        if(header.length == None):
          sdnpwn.message("Got bad OF message. Closing.", sdnpwn.WARNING)
          run = False
          self.comm_sock.close()
        else:
          replyBody = self.comm_sock.recv(header.length-8)
          try:
            autohandleOFMessage(self, header, replyBody, self.enable_output)
          except:
            sdnpwn.message("Error handling OF message", sdnpwn.WARNING)
        #except Exception as e:
          #sdnpwn.message("Socket disconnected", sdnpwn.ERROR)
          #print(e)
          #self.comm_sock.close()
          #break 
    else:
      return True

class Flow(GenericMessage):
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
    return ("cookie: " + (str(self.cookie) if self.cookie != 0 else "*") + ", "
            "idle_timeout: " + str(self.idle_timeout) + ", "
            "hard_timeout: " + str(self.hard_timeout) + ", "
            "priority: " + str(self.priority) + ", "
            "buffer_id: " + str(self.buffer_id) + ", "
            "out_port: " + str(self.out_port) + ", "
            "flags: " + str(self.flags) + ", "
            "actions: " + self.actionsToString(self.actions) + ", "
            "match: " + self.matchToString(self.match) + ""
           )
  
  def actionsToString(self, actions):
    actionHeaders = ""
    if(isinstance(actions, list)):
      for a in actions:
        actionHeaders += (self.getActionHeaderDetails(a))(a)  + ","
    else:
      actionHeaders += (self.getActionHeaderDetails(actions))(actions)
      
    return "[" + actionHeaders[:-1] + "]"
  
  def getActionHeaderDetails(self, action):
    return {
             ActionType.OFPAT_OUTPUT: (lambda action: ("[OFPAT_OUTPUT: Port " + str(action.port) + "]")),
             ActionType.OFPAT_SET_VLAN_VID: (lambda action: ("[OFPAT_SET_VLAN_VID: Vlan ID " + str(action.vlan_id) + "]")),
             ActionType.OFPAT_SET_VLAN_PCP: (lambda action: ("[OFPAT_SET_VLAN_PCP: Vlan PCP" + str(action.vlan_pcp) + "]")),
             ActionType.OFPAT_STRIP_VLAN: (lambda action: ("[OFPAT_STRIP_VLAN: " + str(action.port) + "]")),
             ActionType.OFPAT_SET_DL_SRC: (lambda action: ("[OFPAT_SET_DL_SRC: MAC " + str(action.dl_addr) + "]")),
             ActionType.OFPAT_SET_DL_DST: (lambda action: ("[OFPAT_SET_DL_DST: MAC " + str(action.dl_addr) + "]")),
             ActionType.OFPAT_SET_NW_SRC: (lambda action: ("[OFPAT_SET_NW_SRC: IP " + str(action.nw_addr) + "]")),
             ActionType.OFPAT_SET_NW_DST: (lambda action: ("[OFPAT_SET_NW_DST: IP " + str(action.nw_addr) + "]")),
             ActionType.OFPAT_SET_NW_TOS: (lambda action: ("[OFPAT_SET_NW_TOS: Service " + str(action.nw_tos) + "]")),
             ActionType.OFPAT_SET_TP_SRC: (lambda action: ("[OFPAT_SET_TP_SRC: Layer 4 Port " + str(action.tp_port) + "]")),
             ActionType.OFPAT_SET_TP_DST: (lambda action: ("[OFPAT_SET_TP_DST: Layer 4 Port " + str(action.tp_port) + "]")),
             ActionType.OFPAT_ENQUEUE: (lambda action: ("[OFPAT_ENQUEUE: Port " + str(action.port) + ", Queue ID " + str(action.queue_id) + "]")),
             ActionType.OFPAT_VENDOR: (lambda action: ("[OFPAT_VENDOR: Vendor action " + str(action.vendor) + "]")),
             
           }[int(str(action.action_type))]
    
  def matchToString(self, match):
    return ("[ " +
           "in_port: " + (str(match.in_port) if match.in_port != 0 else "*") + ", " +
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

#
#
# Receiving OF messages
#
#

def getResponse(sock):
  try:
    ofHeader = Header()
    replyHeader = sock.recv(8)
    ofHeader.unpack(replyHeader)
    replyBody = sock.recv(ofHeader.length-8)
    return (ofHeader, replyBody)
  except Exception as e:
    if(verbose == True):
      print("Error: " + str(e))
    return None
  
def autohandleOFMessage(device, header, body, verbose=False):
  
  if(header.message_type == None):
    device.comm_sock.close()
    
  action = {
            0: handleHello,
            1: handleError,
            2: handleEchoRequest,
            3: handleEchoResponse,
            4: handleVendorMessage,
            5: handleFeatureRequest,
            6: handleFeatureResponse,
            7: handleConfigRequest,
            8: handleConfigResponse,
            9: handleSetConfig,
            10: handlePacketIn,
            11: handleFlowRemoved,
            12: handlePortStatus,
            13: handlePacketOut,
            14: handleFlowMod,
            15: handlePortMod,
            16: handleStatsRequest,
            17: handleStatsResponse,
            18: handleBarrierRequest,
            19: handleBarrierResponse,
            20: handleQueueConfigRequest,
            21: handleQueueConfigResponse
    
           }[(header.message_type & 0xFF)]
  
  if(callable(action)):
    action(device, header, body, verbose)
    
def handleHello(device, header, body, verbose):
  if(verbose):
    print("Got Hello")
  
def handleError(device, header, body, verbose):
  if(verbose):
    print("Got Error")

def handleEchoRequest(device, header, body, verbose):
  if(verbose):
    print("Got EchoReq")
    
  ofEchoReply = EchoReply(xid=header.xid)
  device.comm_sock.send(ofEchoReply.pack())
  if(verbose):
    print("Sent EchoRes")
    
def handleEchoResponse(device, header, body, verbose):
  if(verbose):
    print("Got EchoRes")
    
def handleVendorMessage(device, header, body, verbose):
  if(verbose):
    print("Got Vendor Message")
  ofVendor = VendorHeader(xid=header.xid, vendor=device.switch_vendor_id)
  ofVendor.header.length = 20
  vendorBytes = bytearray(ofVendor.pack())
  vendorBytes[3] += 8
  vendorBytes += b'\x00\x00\x00\x0b\x00\x00\x00\x01' #\x00\x00\x23\x20
  device.comm_sock.send(vendorBytes)
  if(verbose):
    print("Sent Vendor Message")
    
def handleFeatureRequest(device, header, body, verbose):
  if(verbose):
    print("Got FeatureReq")
  ofFeaturesReply = FeaturesReply(xid=header.xid, datapath_id=DPID(device.switch_features["dpid"]),  n_buffers=UBInt32(device.switch_features["no_of_buffers"]), n_tables=UBInt32(device.switch_features["no_of_tables"]), capabilities=UBInt32(device.switch_features["capabilities"]), actions=UBInt32(device.switch_features["actions"]), ports=device.switch_features["ports"])
  device.comm_sock.send(ofFeaturesReply.pack())
  if(verbose):
    print("Sent FeatureRes")
    
def handleFeatureResponse(device, header, body, verbose):
  if(verbose):
    print("Got FeatureRes")
    
def handleConfigRequest(device, header, body, verbose):
  if(verbose):
    print("Got ConfigReq")
  ofConfigRes = GetConfigReply(xid=header.xid, flags=UBInt16(int.from_bytes(device.switch_config["flags"], byteorder='big', signed=False)), miss_send_len=UBInt16(int.from_bytes(device.switch_config["miss_send_len"], byteorder='big', signed=False)))
  ofConfigRes.header.message_type = 8
  device.comm_sock.send(ofConfigRes.pack())
  if(verbose):
    print("Sent ConfigRes")
    
def handleConfigResponse(device, header, body, verbose):
  if(verbose):
    print("Got ConfigRes")
    
def handleSetConfig(device, header, body, verbose):
  if(verbose):
    print("Got SetConfig")
  device.setConfig(flags=bytearray(body)[0:2], miss_send_len=bytearray(body)[2:4])
  
def handlePacketIn(device, header, body, verbose):
  if(verbose):
    print("Got PacketIn")
    
def handleFlowRemoved(device, header, body, verbose):
  if(verbose):
    print("Got FlowRemoved")
    
def handlePortStatus(device, header, body, verbose):
  if(verbose):
    print("Got PortStatus")
    
def handlePacketOut(device, header, body, verbose):
  if(verbose):
    print("Got PacketOut")
  packetOut = PacketOut()
  packetOut.unpack(body)
  tempFlow = Flow()
  try:
    pkt = Ether(packetOut.data.pack())
    if(verbose):
      print(Flow.actionsToString(actions))
      pkt.show()
    if(device.forward_packet_out_payload == True):
      if(device.forward_packet_out_port_filter is not None):
        if(("Port " + str(device.forward_packet_out_port_filter)) in tempFlow.actionsToString(packetOut.actions)):
          sendp(pkt, iface=device.forward_packet_out_iface)
      else:
        sendp(pkt, iface=device.forward_packet_out_iface)
      
  except Exception as e:
    sdnpwn.message("Got error handling packet out.", sdnpwn.WARNING)
    sdnpwn.message(str(e), sdnpwn.VERBOSE)
  
def handleFlowMod(device, header, body, verbose):
  if(verbose):
    print("Got FlowMod")
  flowMod = FlowMod()
  flowMod.unpack(body)
  flow = Flow(match=flowMod.match, cookie=flowMod.cookie, 
                idle_timeout=flowMod.idle_timeout, hard_timeout=flowMod.hard_timeout, 
                priority=flowMod.priority, buffer_id=flowMod.buffer_id, out_port=flowMod.out_port,
                flags=flowMod.flags, actions=flowMod.actions
               )
   
  if(flowMod.command == FlowModCommand.OFPFC_ADD):
    sdnpwn.message("Adding New Flow ", sdnpwn.NORMAL)
    device.switch_flows[str(flow.cookie)] = flow
  elif(flowMod.command == FlowModCommand.OFPFC_MODIFY):
    sdnpwn.message("Modifying Flow ", sdnpwn.NORMAL)
    device.switch_flows[str(flow.cookie)] = flow
  elif(flowMod.command == FlowModCommand.OFPFC_MODIFY_STRICT):
    sdnpwn.message("Modifying Flow (Strict) ", sdnpwn.NORMAL)
    device.switch_flows[str(flow.cookie)] = flow
  elif(flowMod.command == FlowModCommand.OFPFC_DELETE):
    sdnpwn.message("Deleting Flow ", sdnpwn.NORMAL)
    if(flow.cookie == 0):
      device.switch_flows = {}
    else:
      del device.switch_flows[str(flow.cookie)]
  elif(flowMod.command == FlowModCommand.OFPFC_DELETE_STRICT):
    sdnpwn.message("Deleting Flow (Strict) ", sdnpwn.NORMAL)
    if(flow.cookie == 0):
      device.switch_flows = {}
    else:
      del device.switch_flows[str(flow.cookie)]
  print(flow.toString())
  
def handlePortMod(device, header, body, verbose):
  if(verbose):
    print("Got PortMod")
    
def handleStatsRequest(device, header, body, verbose):
  if(verbose):
    print("Got StatsReq")
  ofStatsReq = StatsRequest()
  ofStatsReq.unpack(body)
  if(verbose):
    print(ofStatsReq.body_type)
  if(ofStatsReq.body_type == 0): #Description flag      
    descReply = DescStats(mfr_desc=device.switch_desc["switch_mfr_desc"], 
                          hw_desc=device.switch_desc["switch_hw_desc"], 
                          sw_desc=device.switch_desc["switch_sw_desc"],
                          serial_num=device.switch_desc["switch_serial_num"],
                          dp_desc=device.switch_desc["switch_dp_desc"]
                          )
    statsReplyBody = descReply.pack()
    ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
    device.comm_sock.send(ofStatsReply.pack())
      
  elif(ofStatsReq.body_type == 1): #Flow flag
    if(verbose):
      print("Got flow stats req")
    #There may be an issue with the library here. Getting "Pack error: UBInt16 could not pack NoneType = None.". Must investigate further
    #ofFlowStatsReq = FlowStatsRequest()
    #ofFlowStatsReq.unpack(body)
     
    #for f in device.switch_flows:
      #flowStats = FlowStats(length=device.switch_flows[f].length, 
                            #table_id=device.switch_flows[f].table_id, 
                            #match=ofFlowStatsReq.match,
                            #duration_sec=device.switch_stats["flow"]["duration_sec"], 
                            #duration_nsec=device.switch_stats["flow"]["duration_nsec"], 
                            #priority=device.switch_flows[f].priority,
                            #idle_timeout=device.switch_flows[f].idle_timeout, 
                            #hard_timeout=device.switch_flows[f].hard_timeout, 
                            #cookie=device.switch_flows[f].cookie,
                            #packet_count=device.switch_stats["flow"]["packet_count"], 
                            #byte_count=device.switch_stats["flow"]["byte_count"], 
                            #actions=device.switch_flows[f].actions
                            #)
      #statsReplyBody = flowStats.pack()
      #ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
      #device.comm_sock.send(ofStatsReply.pack())  
      
      
  elif(ofStatsReq.body_type == 2): #Aggregate flag
    aggReply = AggregateStatsReply(packet_count=device.switch_stats["aggregate"]["packet_count"], byte_count=device.switch_stats["aggregate"]["byte_count"], flow_count=device.switch_stats["aggregate"]["flow_count"])
    statsReplyBody = aggReply.pack()
    ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
    device.comm_sock.send(ofStatsReply.pack())
      
  elif(ofStatsReq.body_type == 3): #Table flag
    if(verbose):
      print("Got table")
      
  elif(ofStatsReq.body_type == 4): #Port flag
    if(verbose):
      print("Got port")
    ofStatsReqBody = PortStatsRequest()
    ofStatsReqBody.unpack(body)
    if(ofStatsReqBody.port_no == ofStatsReq.body_type):
      #It wants stats from all ports
      statsReplyBody = b''
      for p in device.switch_stats["port"]:
        portStats = device.switch_stats["port"][p]
        statsReplyBody += portStats.pack()
      ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
      device.comm_sock.send(ofStatsReply.pack())
    else:
      #Just one port
      portStats = device.switch_stats["port"][str(ofStatsReqBody.port_no)]
      statsReplyBody = portStats.pack()
      ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
      device.comm_sock.send(ofStatsReply.pack())
   
  elif(ofStatsReq.body_type == 5): #Queue flag
    if(verbose):
      print("Got Queue")
    ofStatsReqBody = QueueStatsRequest()
    ofStatsReqBody.unpack(body)
    if(ofStatsReqBody.port_no == ofStatsReq.body_type):
      #Wants stats for all ports
      statsReplyBody = b''
      for q in device.switch_stats["queue"]:
        if(verbose):
          print(statsReplyBody)
        queueStats = device.switch_stats["queue"][q]
        statsReplyBody += queueStats.pack()
      ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
      device.comm_sock.send(ofStatsReply.pack())
    else:
      #Just one port
      queueStats = device.switch_stats["queue"][str(ofStatsReqBody.port_no) + ":" + str(ofStatsReqBody.queue_id)]
      statsReplyBody = queueStats.pack()
      ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
      device.comm_sock.send(ofStatsReply.pack())
      
  if(verbose):
    print("Sent StatsRes")
  
def handleStatsResponse(device, header, body, verbose):
  if(verbose):
    print("Got StatsRes")
  
def handleBarrierRequest(device, header, body, verbose):
  if(verbose):
    print("Got BarrierReq")
  ofBarrierReply = BarrierReply(xid=header.xid)
  device.comm_sock.send(ofBarrierReply.pack())
  if(verbose):
    print("Sent BarrierRes")
  
def handleBarrierResponse(device, header, body, verbose):
  if(verbose):
    print("Got BarrierRes")
  
def handleQueueConfigRequest(device, header, body, verbose):
  if(verbose):
    print("Got QueueGetConfigReq")
  
def handleQueueConfigResponse(device, header, body, verbose):
  if(verbose):
      print("Got QueueGetConfigRes")
      
#
#
# Sending OF messages
#
#

def sendHello(sock):
  pass

def sendEchoRequest(sock):
  pass

def sendEchoResponse(sock):
  pass

def sendFeatureRequest(sock):
  pass

def sendFeatureResponse(sock):
  pass


  

def paddedMessage(message, size):
  padded = b''
  paddingNeeded = size-len(message)
  padded += message
  for i in range(0, paddingNeeded):
    padded += b'\x00'
  return padded
  
def printFeatureReplyDetails(ofFeatureReply):
  sdnpwn.message("Device Datapath ID: " + str(ofFeatureReply.datapath_id), sdnpwn.NORMAL)
  sdnpwn.message("Number of Buffers: " + str(ofFeatureReply.n_buffers), sdnpwn.NORMAL)
  sdnpwn.message("Number of Tables: " + str(ofFeatureReply.n_tables), sdnpwn.NORMAL)
  sdnpwn.message("Capabilities: " + bin(int(str(ofFeatureReply.capabilities))), sdnpwn.NORMAL) 
  sdnpwn.message("Actions: " + bin(int(str(ofFeatureReply.actions))), sdnpwn.NORMAL) 
  sdnpwn.message("Ports: ", sdnpwn.NORMAL)   
  for p in ofFeatureReply.ports:
    print("\tNumber: " + str(p.port_no))
    print("\tHardware Address: " + str(p.hw_addr))
    print("\tName: " + str(p.name))
    if(str(p.curr) != "0"):
      print("\tCurrent Features:")
      print("\t\t" + getPortFeaturesAsString(p.curr))
    if(str(p.advertised) != "0"):
      print("\tAdvertised Features:")
      print("\t\t" + getPortFeaturesAsString(p.advertised))
    if(str(p.supported) != "0"):
      print("\tSupported Features:")
      print("\t\t" + getPortFeaturesAsString(p.supported))
    if(str(p.peer) != "0"):
      print("\tPeer Features:")
      print("\t\t" + getPortFeaturesAsString(p.peer))
    if(str(p.config) != "0"):
      print("Configuration: ")
      print("\t" + getPortConfigAsString(p.config))
    if(str(p.state) != "0"):
      print("State: ")
      print("\t" + getPortStateAsString(p.state))

def getPortFeaturesAsString(p):
  features = ""
  if(p & PortFeatures.OFPPF_10MB_HD):
    features += "10 Mb half-duplex rate support.\n"
  if(p & PortFeatures.OFPPF_10MB_FD):
    features += "10 Mb full-duplex rate support.\n"
  if(p & PortFeatures.OFPPF_100MB_HD):
    features += "100 Mb half-duplex rate support.\n"
  if(p & PortFeatures.OFPPF_100MB_FD):
    features += "100 Mb full-duplex rate support.\n"
  if(p & PortFeatures.OFPPF_1GB_HD):
    features += "1 Gb half-duplex rate support.\n"
  if(p & PortFeatures.OFPPF_1GB_FD):
    features += "1 Gb full-duplex rate support.\n"
  if(p & PortFeatures.OFPPF_COPPER):
    features += "Copper medium.\n"
  if(p & PortFeatures.OFPPF_FIBER):
    features += "Fiber medium.\n"
  if(p & PortFeatures.OFPPF_AUTONEG):
    features += "Auto-negotiation.\n"
  if(p & PortFeatures.OFPPF_PAUSE):
    features += "Pause.\n"
  if(p & PortFeatures.OFPPF_PAUSE_ASYM):
    features += "Asymmetric pause.\n"
  return features

def getPortConfigAsString(p):
  config = ""
  if(p & PortState.OFPC_PORT_DOWN):
    features += "Port is administratively down.\n"
  if(p & PortState.OFPPC_NO_STP):
    features += "Disable 802.1D spanning tree on port.\n"
  if(p & PortState.OFPPC_NO_RECV):
    features += "Drop all packets except 802.1D spanning tree.\n"
  if(p & PortState.OFPPC_NO_RECV_STP):
    features += "Drop received 802.1D STP packets.\n"
  if(p & PortState.OFPPC_FLOOD):
    features += "Do not include this port when flooding.\n"
  if(p & PortState.OFPPC_NO_FWD):
    features += "Drop packets forwarded to port.\n"
  if(p & PortState.OFPPC_NO_PACKET_IN):
    features += "Do not send packet-in msgs for port.\n"
  return config

def getPortStateAsString(p):
  state = ""
  if(p & PortState.OFPPS_LINK_DOWN):
    features += "Link down. Not learning or relaying frames.\n"
  if(p & PortState.OFPPS_STP_LISTEN):
    features += "STP listen. Not learning or relaying frames.\n"
  if(p & PortState.OFPPS_STP_LEARN):
    features += "STP learn. Learning but not relaying frames.\n"
  if(p & PortState.OFPPS_STP_FORWARD):
    features += "STP forward. Learning and relaying frames.\n"
  if(p & PortState.OFPPS_STP_BLOCK):
    features += "Not part of spanning tree.\n"
  return state
