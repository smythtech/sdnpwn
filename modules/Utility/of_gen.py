
from pyof.foundation.basic_types import DPID, UBInt8, UBInt16, UBInt32, UBInt64, Pad, HWAddress, BinaryData

#v0x01 is openflow version
from pyof.v0x01.symmetric.hello import Hello
from pyof.v0x01.controller2switch.features_reply import FeaturesReply
from pyof.v0x01.controller2switch.features_request import FeaturesRequest
from pyof.v0x01.controller2switch.barrier_reply import BarrierReply
from pyof.v0x01.symmetric.echo_reply import EchoReply
from pyof.v0x01.symmetric.echo_request import EchoRequest
from pyof.v0x01.controller2switch.stats_request import StatsRequest
from pyof.v0x01.controller2switch.stats_reply import StatsReply
from pyof.v0x01.controller2switch.get_config_reply import GetConfigReply
from pyof.v0x01.common.phy_port import PhyPort, PortConfig, PortState, PortFeatures
from pyof.v0x01.common.header import Header
from pyof.v0x01.asynchronous.packet_in import PacketIn, PacketInReason
      
from ipaddress import ip_network
import socket
import signal
import base64
import codecs
from time import sleep

import modules.sdnpwn.sdnpwn_common as sdnpwn
from modules.sdnpwn.sdnpwn_of_helper import * 

def info():
  return "Generate OpenFlow messages. Currently supports OpenFlow V1.0 only."
  
def usage():
  
  sdnpwn.addUsage("-t | --target", "Network or host address (i.e. 192.168.1.0/24)", True)
  sdnpwn.addUsage("-p | --port", "Ports to connect to (Default is 6633,6634,6653)")
  sdnpwn.addUsage("-v | --verbose", "Enable verbose output")
  sdnpwn.addUsage("-s | --socket-timeout", "Timeout for connection in seconds (Default is 2)")
  sdnpwn.addUsage("-c | --count", "Number of messages to send")
  sdnpwn.addUsage("-d | --delay", "Delay between messages")
  
  sdnpwn.addUsage("--hold-open", "Keep socket open after sending message")
  
  sdnpwn.addUsage("--hello", "Send OF Hello message")
  sdnpwn.addUsage("--echo-request", "Send an OF Echo Request")
  
  sdnpwn.addUsage("--packet-in", "Send an OF packet-in")
  sdnpwn.addUsage(" --xid", "XID for OF header")
  sdnpwn.addUsage(" --buffer-id", "Buffer ID for packet-in")
  sdnpwn.addUsage(" --total-length", "Length of data in packet-in (Calculated by default)")
  sdnpwn.addUsage(" --in-port", "Port packet was received on")
  sdnpwn.addUsage(" --reason", "Reason for packet-in. Can be 'match' or 'action'")
  sdnpwn.addUsage(" --data-raw", "Packet-in data as hex")
  sdnpwn.addUsage(" --data-scapy", "Packet-in data as scapy object (i.e. Ether()/IP()/TCP())")
  
  return sdnpwn.getUsage()

def signal_handler(signal, frame):
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)
  
def run(params):
  
  targets = None #Full list of targets
  
  verbose = False
  
  signal.signal(signal.SIGINT, signal_handler)  
  
  target = sdnpwn.getArg(["--target", "-t"], params)
  port = sdnpwn.getArg(["--port", "-p"], params)
  sockTimeout = sdnpwn.getArg(["--socket-timeout", "-s"], params, 2)
  count = int(sdnpwn.getArg(["--count", "-c"], params, 1))
  delay = float(sdnpwn.getArg(["--delay", "-d"], params, 1))
  verbose = sdnpwn.checkArg(["--verbose", "-v"], params)
    
  if(target == None):
    print(info())
    print(usage())
    return
  else:
    startIndex = 0
    endIndex = 1
    if("/" in target):
      targets = ip_network(target)
      startIndex = 1
      endIndex = targets.num_addresses-2
    else:
      targets = ip_network(str(target) + "/32")
  
  if(port == None):
    sdnpwn.message("No ports given, using 6633,6634, and 6653.", sdnpwn.NORMAL)
    port = "6633,6634,6653"
  
  for host in range(startIndex, endIndex):
    targetHost = targets[host].exploded
    for p in port.split(","):
      for c in range(count):
        sleep(delay)
        sock = getSocket(targetHost, p, float(sockTimeout))
        if(sock != None):
          targetLabel = str(targetHost) + ":" + str(p)
          if(verbose == True):
            sdnpwn.message("Connected to " + str(targetHost) + ":" + str(p), sdnpwn.NORMAL)
          #print(params)
          
          #for msg in params:
            #action = {
                      #"--hello":sendHello,
                      #"echo-req":sendEchoRequest
                    #}[msg]
            #action(sock)
            
          #TODO: Remove following items in favour of above
          if("--hello" in params):
            sdnpwn.message("Sending OF Hello to " + str(targetHost), sdnpwn.NORMAL)
            ofHello = Hello(xid=5)
            sock.send(ofHello.pack())
              
          if("--echo-request" in params):
            sdnpwn.message("Sending OF Echo Request to " + str(targetHost), sdnpwn.NORMAL)
            echoReq = EchoRequest(xid=5)
            sock.send(echoReq.pack())
              
              
          if("--packet-in" in params):
            xid = 13
            bufferId = 0
            totalLength = -1
            inPort = 0
            reason = ""
            data = b''
            try:
              xid = params[params.index("--xid")+1] # int
              bufferId = params[params.index("--buffer-id")+1] # int
              if("--total-length" in params):
                totalLength = params[params.index("--total-length")+1] # int Full length of frame
              inPort = params[params.index("--in-port")+1] # int
              reason = params[params.index("--reason")+1] #match or action
              if(reason == "match"):
                reason = 0 #PacketInReason.OFPR_MATCH
              elif(reason == "action"):
                reason = 1 #PacketInReason.OFPR_ACTION
              else:
                sdnpwn.message("Invalid 'reason' argument given! Should be 'match' or 'action'", sdnpwn.ERROR)
                exit(0)
              
              dataBin = b''
              if("--data-raw" in params):
                data = params[params.index("--data-raw")+1] #Data in bytes
                dataBin = codecs.decode(data, 'hex_codec')
              elif("--data-scapy" in params):
                try:
                  cmd = params[params.index("--data-scapy")+1] #Data as scapy code
                  pkt = eval(cmd) #Get packet from scapy objects
                  dataBin = codecs.decode(scapy_packet_to_string(pkt), 'hex_codec')
                  dataBin = bytes(pkt)
                except Exception as e:
                  sdnpwn.message("Error building Scapy packet", sdnpwn.ERROR)
                  print(e)

            except Exception as e:
              sdnpwn.message("Missing paramerters for OF Packet In!", sdnpwn.ERROR)
              print(e)
              
            if(totalLength == -1):
              totalLength = len(dataBin)
            pktIn = PacketIn(xid=int(xid), buffer_id=int(bufferId), total_len=int(totalLength), in_port=int(inPort), reason=int(reason), data=dataBin)
            sdnpwn.message("Sending OF Packet In to " + str(targetHost), sdnpwn.NORMAL)
            sock.send(pktIn.pack())
              
          if("--hold-open" not in params):    
            sock.close()
          else:
            sdnpwn.message("Holding socket open", sdnpwn.NORMAL)
          
        else:
          sdnpwn.message("Could not connect to " + targetHost + " on socket " + str(p), sdnpwn.WARNING)   
        
    if("--hold-open" in params):    
      sdnpwn.message("Keeping sockets open. Use CTRL+C to stop...", sdnpwn.NORMAL)
      while(1):
        sleep(2)
          
def getSocket(ip, port, timeout=2):
  try:
    comm_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    comm_sock.settimeout(timeout)
    comm_sock.connect((ip, int(port)))
    return comm_sock
  except Exception as e:
    #print(e)
    return None

def scapy_packet_to_string(pkt):
  pktSplit = str(pkt).split("\\x")
  pktSplit.pop(0)
  for i in range(len(pktSplit)):
    pktSplit[i] = pktSplit[i][:2]
  return ''.join(pktSplit)
  
  
  
