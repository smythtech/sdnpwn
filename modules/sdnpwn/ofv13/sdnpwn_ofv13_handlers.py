
import modules.sdnpwn.sdnpwn_common as sdnpwn

from scapy.all import *

from pyof.foundation.basic_types import DPID, UBInt8, UBInt16, UBInt32, UBInt64, Pad, HWAddress

#v0x01 is openflow version
from pyof.v0x04.symmetric.hello import Hello
from pyof.v0x04.controller2switch.features_reply import FeaturesReply
from pyof.v0x04.controller2switch.barrier_reply import BarrierReply
from pyof.v0x04.controller2switch.packet_out import PacketOut
from pyof.v0x04.controller2switch.flow_mod import *
from pyof.v0x04.controller2switch.common import *
from pyof.v0x04.symmetric.echo_reply import EchoReply
from pyof.v0x04.symmetric.experimenter import ExperimenterHeader
from pyof.v0x04.controller2switch.multipart_request import *
from pyof.v0x04.controller2switch.multipart_reply import *
from pyof.v0x04.controller2switch.role_request import RoleRequest
from pyof.v0x04.controller2switch.role_reply import RoleReply
from pyof.v0x04.controller2switch.get_config_reply import GetConfigReply
from pyof.v0x04.common.port import PortConfig, PortState, Port, PortNo
from pyof.v0x04.common.header import Header, Type
from pyof.v0x04.common.flow_match import *
from pyof.v0x04.common.action import ActionType, ActionHeader
from pyof.foundation.base import GenericMessage

from random import randint
import socket
from struct import pack, unpack

from modules.sdnpwn.sdnpwn_lldp import *
from modules.sdnpwn.ofv13.sdnpwn_ofv13_flow import *

'''

Class to define and implement Openflow v1.3 message handlers

'''

class OFv13MessageHandler():

  version = 1.3
  save_connection_data = False

  def __init__(self):
    self.version = 1.3
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
            4: self.handle_experimenter,
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
            15: self.handle_group_mod,
            16: self.handle_port_mod,
            17: self.handle_table_mod,
            18: self.handle_multipart_request,
            19: self.handle_multipart_response,
            20: self.handle_barrier_request,
            21: self.handle_barrier_response,
            22: self.handle_queue_config_request,
            23: self.handle_queue_config_response,
            24: self.handle_role_request,
            25: self.handle_role_response,
            26: self.handle_get_async_request,
            27: self.handle_get_async_response,
            28: self.handle_set_async,
            29: self.handle_meter_mod
    }[(header.message_type & 0xFF)]

    if(callable(action)):
      action(device, header, body, verbose)

  '''

  Openflow message handlers

  '''

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

  def handle_experimenter(self, device, header, body, verbose):
    if(verbose):
      print("Got Experimenter")
    ofExperimenter = ExperimenterHeader(xid=header.xid, experimenter=device.switch_vendor_id, exp_type=device.switch_vendor_ouid_bytes)
    ofExperimenter.header.length = 20
    experimenterBytes = bytearray(ofExperimenter.pack())
    experimenterBytes[3] += 8
    experimenterBytes += b'\x00\x00\x00\x00\x00\x00\x00\x00' #\x00\x00\x23\x20
    device.comm_sock.send(experimenterBytes)
    if(verbose):
      print("Sent Experimenter Message")

  def handle_feature_request(self, device, header, body, verbose):
    if(verbose):
      print("Got FeatureReq")
    ofFeaturesReply = FeaturesReply(xid=header.xid, auxiliary_id=0, reserved=0, datapath_id=DPID(device.switch_features["dpid"]),  n_buffers=UBInt32(device.switch_features["no_of_buffers"]), n_tables=UBInt32(device.switch_features["no_of_tables"]), capabilities=UBInt32(device.switch_features["capabilities"]))
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
        print(tempFlow.actionsToString(packetOut.actions))
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
                  out_group=flowMod.out_group, instructions=flowMod.instructions, flags=flowMod.flags)

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

  def handle_group_mod(self, device, header, body, verbose):
    if(verbose):
      print("Got GroupMod")

  def handle_port_mod(self, device, header, body, verbose):
    if(verbose):
      print("Got PortMod")

  def handle_table_mod(self, device, header, body, verbose):
    if(verbose):
      print("Got TableMod")

  def handle_multipart_request(self, device, header, body, verbose):
    if(verbose):
      print("Got MultipartRequest")
    ofMultipartReq = MultipartRequest()
    ofMultipartReq.unpack(body)
    if(verbose):
      print("MultipartReq type is " + str(ofMultipartReq.multipart_type))

    action = {
      0: self.handle_mp_desc,
      1: self.handle_mp_flow,
      2: self.handle_mp_aggregate,
      3: self.handle_mp_table,
      4: self.handle_mp_port_stats,
      5: self.handle_mp_queue,
      6: self.handle_mp_group,
      7: self.handle_mp_group_desc,
      8: self.handle_mp_group_features,
      9: self.handle_mp_meter,
      10: self.handle_mp_meter_config,
      11: self.handle_mp_meter_features,
      12: self.handle_mp_table_features,
      13: self.handle_mp_port_desc,
      14: self.handle_mp_experimenter
    }[ofMultipartReq.multipart_type & 0xFF]

    if(callable(action)):
      try:
        action(device, header, body, verbose)
      except Exception as e:
        ex_type, ex_value, ex_traceback = sys.exc_info()
        print(ex_type)
        print(ex_value)
        for t in traceback.extract_tb(ex_traceback):
          print("\t%s", t)

  def handle_multipart_response(self, device, header, body, verbose):
    if(verbose):
      print("Got MultipartResponse")

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

  def handle_role_request(self, device, header, body, verbose):
    if(verbose):
      print("Got RoleReq")

    ofRoleReq = RoleRequest()
    ofRoleReq.unpack(body)

    ofRoleResp = RoleReply(xid=header.xid, role=ofRoleReq.role, generation_id=ofRoleReq.generation_id)
    device.comm_sock.send(ofRoleResp.pack())

  def handle_role_response(self, device, header, body, verbose):
    if(verbose):
      print("Got RoleRes")

  def handle_get_async_request(self, device, header, body, verbose):
    if(verbose):
      print("Got GetAsyncReq")

  def handle_get_async_response(self, device, header, body, verbose):
    if(verbose):
      print("Got GetAsyncRes")

  def handle_set_async(self, device, header, body, verbose):
    if(verbose):
      print("Got SetAsync")

  def handle_meter_mod(self, device, header, body, verbose):
    if(verbose):
      print("Got MeterMod")

  '''

  Handlers for the various types of Multipart Messages

  '''

  def handle_mp_desc(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart Desc")

    ofMultipartReq = MultipartRequest()
    ofMultipartReq.unpack(body)

    ofDescRespBody = Desc(mfr_desc=device.switch_desc["switch_mfr_desc"],
                     hw_desc=device.switch_desc["switch_hw_desc"],
                     sw_desc=device.switch_desc["switch_sw_desc"],
                     serial_num=device.switch_desc["switch_serial_num"],
                     dp_desc=device.switch_desc["switch_dp_desc"]
                     )
    ofMultipartResp = MultipartReply(xid=header.xid, multipart_type=ofMultipartReq.multipart_type, flags=UBInt16(0x00000000), body=ofDescRespBody)
    device.comm_sock.send(ofMultipartResp.pack())


  def handle_mp_flow(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart Flow")

  def handle_mp_aggregate(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart Aggregate")

  def handle_mp_table(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart Table")

  def handle_mp_port_stats(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart PortStats")

  def handle_mp_queue(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart Queue")

  def handle_mp_group(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart Group")

  def handle_mp_group_desc(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart GroupDesc")

  def handle_mp_group_features(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart GroupFeatures")

  def handle_mp_meter(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart Meter")

  def handle_mp_meter_config(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart MeterConfig")

  def handle_mp_meter_features(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart MeterFeatures")

    ofMultipartReq = MultipartRequest()
    ofMultipartReq.unpack(body)

    max_meter = device.switch_features["meters"]["max_meter"]
    band_types = device.switch_features["meters"]["band_types"]
    capabilities = device.switch_features["meters"]["capabilities"]
    max_bands = device.switch_features["meters"]["max_bands"]
    max_color = device.switch_features["meters"]["max_color"]

    ofMeterFeaturesRespBody = MeterFeatures(max_meter=max_meter, band_types=band_types, capabilities=capabilities, max_bands=max_bands, max_color=max_color)
    ofMultipartResp = MultipartReply(xid=header.xid, multipart_type=ofMultipartReq.multipart_type, flags=UBInt16(0x00000000), body=ofMeterFeaturesRespBody)
    device.comm_sock.send(ofMultipartResp.pack())


  def handle_mp_table_features(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart TableFeatures")

  def handle_mp_port_desc(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart PortDesc")

    ofMultipartReq = MultipartRequest()
    ofMultipartReq.unpack(body)

    statsReplyBody = []
    for p in device.switch_features["ports"]:
      portDesc = p
      statsReplyBody.append(portDesc)

    ofMultipartResp = MultipartReply(xid=header.xid, multipart_type=ofMultipartReq.multipart_type, flags=UBInt16(0x00000000), body=statsReplyBody)
    device.comm_sock.send(ofMultipartResp.pack())

  def handle_mp_experimenter(self, device, header, body, verbose):
    if(verbose):
      print("Got Multipart Experimenter")
