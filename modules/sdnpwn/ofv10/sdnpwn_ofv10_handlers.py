
import modules.sdnpwn.sdnpwn_common as sdnpwn

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

from modules.sdnpwn.sdnpwn_lldp import *
from modules.sdnpwn.ofv10.sdnpwn_ofv10_flow import *

'''

Class to define and implement Openflow v1.0 message handlers

'''

class OFv10MessageHandler():

  version = 1.0
  save_connection_data = False

  def __init__(self):
    self.version = 1.0
    self.save_connection_data = False

  def get_response(self, sock):
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

  def autohandle_messages(self, device, header, body, verbose=False):
    if(header.message_type == None):
      device.comm_sock.close()

    action = {
            0: self.handle_hello,
            1: self.handle_error,
            2: self.handle_echo_request,
            3: self.handle_echo_response,
            4: self.handle_vendor_message,
            5: self.handle_feature_request,
            6: self.handle_feature_response,
            7: self.handle_config_request,
            8: self.handle_config_response,
            9: self.handle_set_config,
            10: self.handle_packet_in,
            11: self.handle_flow_removed,
            12: self.handle_port_status,
            13: self.handle_packet_out,
            14: self.handle_flow_mod,
            15: self.handle_port_mod,
            16: self.handle_stats_request,
            17: self.handle_stats_response,
            18: self.handle_barrier_request,
            19: self.handle_barrier_response,
            20: self.handle_queue_config_request,
            21: self.handle_queue_config_response
    }[(header.message_type & 0xFF)]

    if(callable(action)):
      action(device, header, body, verbose)

  def handle_hello(self, device, header, body, verbose):
    if(verbose):
      print("Got Hello")

  def handle_error(self, device, header, body, verbose):
    if(verbose):
      print("Got Error")

  def handle_echo_request(self, device, header, body, verbose):
    if(verbose):
      print("Got EchoReq")

    ofEchoReply = EchoReply(xid=header.xid)
    device.comm_sock.send(ofEchoReply.pack())
    if(verbose):
      print("Sent EchoRes")

  def handle_echo_response(self, device, header, body, verbose):
    if(verbose):
      print("Got EchoRes")

  def handle_vendor_message(self, device, header, body, verbose):
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

  def handle_feature_request(self, device, header, body, verbose):
    if(verbose):
      print("Got FeatureReq")
    ofFeaturesReply = FeaturesReply(xid=header.xid, datapath_id=DPID(device.switch_features["dpid"]),  n_buffers=UBInt32(device.switch_features["no_of_buffers"]), n_tables=UBInt32(device.switch_features["no_of_tables"]), capabilities=UBInt32(device.switch_features["capabilities"]), actions=UBInt32(device.switch_features["actions"]), ports=device.switch_features["ports"])
    device.comm_sock.send(ofFeaturesReply.pack())
    if(verbose):
      print("Sent FeatureRes")

  def handle_feature_response(self, device, header, body, verbose):
    if(verbose):
      print("Got FeatureRes")

  def handle_config_request(self, device, header, body, verbose):
    if(verbose):
      print("Got ConfigReq")
    ofConfigRes = GetConfigReply(xid=header.xid, flags=UBInt16(int.from_bytes(device.switch_config["flags"], byteorder='big', signed=False)), miss_send_len=UBInt16(int.from_bytes(device.switch_config["miss_send_len"], byteorder='big', signed=False)))
    ofConfigRes.header.message_type = 8
    device.comm_sock.send(ofConfigRes.pack())
    if(verbose):
      print("Sent ConfigRes")

  def handle_config_response(self, device, header, body, verbose):
    if(verbose):
      print("Got ConfigRes")

  def handle_set_config(self, device, header, body, verbose):
    if(verbose):
      print("Got SetConfig")
    device.setConfig(flags=bytearray(body)[0:2], miss_send_len=bytearray(body)[2:4])

  def handle_packet_in(self, device, header, body, verbose):
    if(verbose):
      print("Got PacketIn")

  def handle_flow_removed(self, device, header, body, verbose):
    if(verbose):
      print("Got FlowRemoved")

  def handle_port_status(self, device, header, body, verbose):
    if(verbose):
      print("Got PortStatus")

  def handle_packet_out(self, device, header, body, verbose):
    if(verbose):
      print("Got PacketOut")
    packetOut = PacketOut()
    packetOut.unpack(body)
    tempFlow = Flow()
    try:
      pkt = Ether(packetOut.data.pack())
      if(verbose):
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

  def handle_flow_mod(self, device, header, body, verbose):
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
    flow_string = flow.toString()
    print(flow_string)
    if(self.save_connection_data):
      with open("flows", 'a') as f:
        f.write(flow_string + "\n")


  def handle_port_mod(self, device, header, body, verbose):
    if(verbose):
      print("Got PortMod")

  def handle_stats_request(self, device, header, body, verbose):
    if(verbose):
      print("Got StatsReq")
    ofStatsReq = StatsRequest()
    ofStatsReq.unpack(body)
    if(verbose):
      print(ofStatsReq.body_type)
    if(ofStatsReq.body_type == 0): # Description flag
      descReply = DescStats(mfr_desc=device.switch_desc["switch_mfr_desc"],
                            hw_desc=device.switch_desc["switch_hw_desc"],
                            sw_desc=device.switch_desc["switch_sw_desc"],
                            serial_num=device.switch_desc["switch_serial_num"],
                            dp_desc=device.switch_desc["switch_dp_desc"]
                            )
      statsReplyBody = descReply.pack()
      ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
      device.comm_sock.send(ofStatsReply.pack())

    elif(ofStatsReq.body_type == 1): # Flow flag
      if(verbose):
        print("Got flow stats req")
      # There may be an issue with the library here. Getting "Pack error: UBInt16 could not pack NoneType = None.". Must investigate further
      '''
      ofFlowStatsReq = FlowStatsRequest()
      ofFlowStatsReq.unpack(body)

      for f in device.switch_flows:
        flowStats = FlowStats(length=device.switch_flows[f].length,
                              table_id=device.switch_flows[f].table_id,
                              match=ofFlowStatsReq.match,
                              duration_sec=device.switch_stats["flow"]["duration_sec"],
                              duration_nsec=device.switch_stats["flow"]["duration_nsec"],
                              priority=device.switch_flows[f].priority,
                              idle_timeout=device.switch_flows[f].idle_timeout,
                              hard_timeout=device.switch_flows[f].hard_timeout,
                              cookie=device.switch_flows[f].cookie,
                              packet_count=device.switch_stats["flow"]["packet_count"],
                              byte_count=device.switch_stats["flow"]["byte_count"],
                              actions=device.switch_flows[f].actions
                              )
        statsReplyBody = flowStats.pack()
        ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
        device.comm_sock.send(ofStatsReply.pack())
        '''

    elif(ofStatsReq.body_type == 2): # Aggregate flag
      aggReply = AggregateStatsReply(packet_count=device.switch_stats["aggregate"]["packet_count"], byte_count=device.switch_stats["aggregate"]["byte_count"], flow_count=device.switch_stats["aggregate"]["flow_count"])
      statsReplyBody = aggReply.pack()
      ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
      device.comm_sock.send(ofStatsReply.pack())

    elif(ofStatsReq.body_type == 3): # Table flag
      if(verbose):
        print("Got table")

    elif(ofStatsReq.body_type == 4): # Port flag
      if(verbose):
        print("Got port")
      ofStatsReqBody = PortStatsRequest()
      ofStatsReqBody.unpack(body)
      if(ofStatsReqBody.port_no == ofStatsReq.body_type):
        # It wants stats from all ports
        statsReplyBody = b''
        for p in device.switch_stats["port"]:
          portStats = device.switch_stats["port"][p]
          statsReplyBody += portStats.pack()
        ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
        device.comm_sock.send(ofStatsReply.pack())
      else:
        # Just one port
        portStats = device.switch_stats["port"][str(ofStatsReqBody.port_no)]
        statsReplyBody = portStats.pack()
        ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
        device.comm_sock.send(ofStatsReply.pack())

    elif(ofStatsReq.body_type == 5): # Queue flag
      if(verbose):
        print("Got Queue")
      ofStatsReqBody = QueueStatsRequest()
      ofStatsReqBody.unpack(body)
      if(ofStatsReqBody.port_no == ofStatsReq.body_type):
        # Wants stats for all ports
        statsReplyBody = b''
        for q in device.switch_stats["queue"]:
          if(verbose):
            print(statsReplyBody)
          queueStats = device.switch_stats["queue"][q]
          statsReplyBody += queueStats.pack()
        ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
        device.comm_sock.send(ofStatsReply.pack())
      else:
        # Just one port
        queueStats = device.switch_stats["queue"][str(ofStatsReqBody.port_no) + ":" + str(ofStatsReqBody.queue_id)]
        statsReplyBody = queueStats.pack()
        ofStatsReply = StatsReply(xid=header.xid, body_type=ofStatsReq.body_type, flags=UBInt16(0x00000000), body=statsReplyBody)
        device.comm_sock.send(ofStatsReply.pack())

    if(verbose):
      print("Sent StatsRes")

  def handle_stats_response(self, device, header, body, verbose):
    if(verbose):
      print("Got StatsRes")

  def handle_barrier_request(self, device, header, body, verbose):
    if(verbose):
      print("Got BarrierReq")
    ofBarrierReply = BarrierReply(xid=header.xid)
    device.comm_sock.send(ofBarrierReply.pack())
    if(verbose):
      print("Sent BarrierRes")

  def handle_barrier_response(self, device, header, body, verbose):
    if(verbose):
      print("Got BarrierRes")

  def handle_queue_config_request(self, device, header, body, verbose):
    if(verbose):
      print("Got QueueGetConfigReq")

  def handle_queue_config_response(self, device, header, body, verbose):
    if(verbose):
      print("Got QueueGetConfigRes")
