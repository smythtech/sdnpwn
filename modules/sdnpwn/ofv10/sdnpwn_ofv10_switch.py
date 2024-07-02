
import modules.sdnpwn.sdnpwn_common as sdnpwn

from pyof.foundation.basic_types import DPID, UBInt8, UBInt16, UBInt32, UBInt64, Pad, HWAddress
from pyof.v0x01.common.header import Header, Type
from pyof.v0x01.symmetric.hello import Hello
from pyof.v0x01.controller2switch.common import *
from pyof.v0x01.common.phy_port import PhyPort, PortConfig, PortState, Port

from modules.sdnpwn.ofv10.sdnpwn_ofv10_handlers import OFv10MessageHandler

from random import randint
import socket
from struct import pack, unpack


'''

Class to define and implement a partially functioning Openflow switch

'''


class OpenFlowV10Switch():
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
  save_connection_data = None
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
    self.save_connection_data = False
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
      port_no = randint(30000,60000)
    if(hw_addr == ""):
      hw_addr = sdnpwn.generateRandomMacAddress(self.switch_vendor_ouid)
    if(port_name == ""):
      port_name = "OF Port " + str(port_no)

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
      if(self.save_connection_data):
        with open("connection_status", 'w') as f:
          f.write("{\"status\": \"connection failed\", \"error\": \"" + str(e) + "\"}\n")
      print
      return

    sdnpwn.message("Socket connected. Sending OF Hello...", sdnpwn.SUCCESS)

    ofHello = Hello(xid=5)
    ofHello.header.xid = 5
    self.comm_sock.send(ofHello.pack()) # Send Hello
    header = Header()
    replyHeader = self.comm_sock.recv(8)

    # Get hello response header & body
    header.unpack(replyHeader)
    sdnpwn.message("Got " + str(header.message_type), sdnpwn.NORMAL)
    sdnpwn.message("Controller base OF version: " + str(header.version), sdnpwn.VERBOSE)
    try:
      replyBody = self.comm_sock.recv(header.length-8) #Get body but ignore
    except:
      pass

    sdnpwn.message("Connected to controller", sdnpwn.SUCCESS)

    if(self.save_connection_data):
      with open("connection_status", 'w') as f:
        f.write("{\"status\": \"connected\", \"of_version\": \"1.0\"}\n")

    if(self.auto_handle_Messages == True):
      run = True
      of_msg_handler = OFv10MessageHandler()
      of_msg_handler.save_connection_data = self.save_connection_data
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
            of_msg_handler.autohandle_messages(self, header, replyBody, self.enable_output)
          except Exception as e:
            sdnpwn.message("Error handling OF message", sdnpwn.WARNING)
            print(e)
        #except Exception as e:
          #sdnpwn.message("Socket disconnected", sdnpwn.ERROR)
          #print(e)
          #self.comm_sock.close()
          #break
    else:
      return True

  def activateRelaySocket(self, port):
    hostname = socket.gethostbyname(socket.gethostname())
    listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenSock.bind(("0.0.0.0", port))
    listenSock.listen(1)
    data = b''
    sdnpwn.message("[Relay Socket] Relay port open on port " + str(port) + "", sdnpwn.NORMAL)
    while 1:
      try:
        conn, addr = listenSock.accept()
        msgHeader = conn.recv(8)
        header = Header()
        header.unpack(msgHeader)
        sdnpwn.message("[Relay Socket] Got " + str(header.message_type) + " from " + str(addr), sdnpwn.NORMAL)
        msgBody = conn.recv(header.length-8)
        msgFull = header.pack() + msgBody
        print(msgFull)
        self.comm_sock.send(msgFull)
      except Exception as e:
        sdnpwn.message("[Relay socket] Error handling message", sdnpwn.WARNING)
        print(e)
    listenSock.close()
